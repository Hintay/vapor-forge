use core::ffi::c_void;

use std::sync::OnceLock;

use tracing::{debug, info, warn};
use vapor_forge_config::DepotId;
use vapor_forge_features::depot_key::DEPOT_KEY_SIZE;
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_patterns::depot_key_loader::{KeyBufferCalls, KEY_CAPACITY, SEEK_HEAD};

use vapor_forge_hook_engine::original::detour_or_return;

use super::install::script_state;
use crate::pattern_resolver::CodeRegion;

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type BuildDepotDependencyFn = unsafe extern "C" fn(
    *mut c_void,
    u32,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut u32,
    *mut bool,
) -> bool;

/// `LoadDepotDecryptionKey(_, depot_id, CUtlBuffer *out) -> bool`. The first
/// argument is not used by Steam's implementation.
pub(crate) type LoadDepotDecryptionKeyFn =
    unsafe extern "C" fn(*mut c_void, u32, *mut c_void) -> bool;
type EnsureCapacityFn = unsafe extern "C" fn(*mut c_void, i32);
type SeekPutFn = unsafe extern "C" fn(*mut c_void, i32, i32);

// ---------------------------------------------------------------------------
// Static detour slots
// ---------------------------------------------------------------------------

pub(crate) static mut BUILD_DEPOT_DETOUR: Option<Detour<BuildDepotDependencyFn>> = None;
pub(crate) static mut DEPOT_KEY_DETOUR: Option<Detour<LoadDepotDecryptionKeyFn>> = None;
/// The loader's own `CUtlBuffer` calls, decoded from its body at install.
static KEY_BUFFER_CALLS: OnceLock<KeyBufferCalls> = OnceLock::new();

// ---------------------------------------------------------------------------
// Hook replacement functions: BuildDepotDependency (manifest injection)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_build_depot_dependency(
    this: *mut c_void,
    app_id: u32,
    user_config: *mut c_void,
    p_depot_info: *mut c_void,
    p_shared_depot_info: *mut c_void,
    p_steam_app: *mut c_void,
    p_build_id: *mut u32,
    pb_beta_fallback: *mut bool,
) -> bool {
    let original = detour_or_return!("BuildDepotDependency", BUILD_DEPOT_DETOUR, false);
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(
        this,
        app_id,
        user_config,
        p_depot_info,
        p_shared_depot_info,
        p_steam_app,
        p_build_id,
        pb_beta_fallback,
    ) };
    // SAFETY: p_depot_info is the vector Steam just filled for this call.
    unsafe { note_depot_selection(app_id, result, p_depot_info) };

    if !crate::capability::is_ready(crate::capability::Capability::DepotInjection) {
        return result;
    }

    if !p_depot_info.is_null() {
        let ss = script_state();
        if !ss.manifests.is_empty() {
            // SAFETY: p_depot_info is a CUtlVector<DepotEntry>* filled by Steam.
            let vec = p_depot_info
                as *mut vapor_forge_steam_native_abi::CUtlVector<
                    vapor_forge_steam_native_abi::DepotEntry,
                >;
            // SAFETY: vec is valid after BuildDepotDependency returned.
            let size = unsafe { (*vec).len() };
            // SAFETY: vec is the same Steam-owned vector validated above.
            if size > 0 && size <= unsafe { (*vec).capacity() } {
                // Collect depot IDs for safe lookup (convert raw u32 to DepotId).
                let mut depot_ids: Vec<DepotId> = Vec::with_capacity(size);
                for i in 0..size {
                    // SAFETY: i < size.
                    depot_ids.push(DepotId(unsafe { (*vec).get(i) }.depot_id));
                }
                let patches = vapor_forge_features::manifest::find_patches(&depot_ids, &ss);
                for patch in &patches {
                    for i in 0..size {
                        // SAFETY: i < size.
                        let entry = unsafe { (*vec).get_mut(i) };
                        if entry.depot_id == patch.depot_id.0 {
                            info!(
                                depot_id = patch.depot_id.0,
                                old_gid = entry.manifest_gid,
                                new_gid = patch.new_gid.0,
                                "manifest: pinned"
                            );
                            entry.manifest_gid = patch.new_gid.0;
                            if let Some(new_size) = patch.new_size {
                                if new_size > 0 {
                                    entry.manifest_size = new_size;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result
}

/// Record what Steam selected for a controlled app. An empty selection makes
/// Steam finish an install with no depots (0 B), so it is reported with the
/// ownership state that feeds the selection, once per app and outcome; other
/// selections only at debug level.
///
/// # Safety
/// `p_depot_info` must be null or the `CUtlVector<DepotEntry>` Steam filled
/// for this `BuildDepotDependency` call.
unsafe fn note_depot_selection(app_id: u32, result: bool, p_depot_info: *mut c_void) {
    use std::collections::HashSet;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use vapor_forge_config::AppId;

    let app = AppId(app_id);
    if !super::install::config().is_controlled_app(app) {
        return;
    }
    let depots = (!p_depot_info.is_null())
        .then(|| {
            let vec = p_depot_info
                as *const vapor_forge_steam_native_abi::CUtlVector<
                    vapor_forge_steam_native_abi::DepotEntry,
                >;
            // SAFETY: the caller passes the vector Steam just filled.
            let (len, capacity) = unsafe { ((*vec).len(), (*vec).capacity()) };
            (len <= capacity).then_some(len)
        })
        .flatten();
    if result && depots.is_some_and(|count| count > 0) {
        debug!(app_id, depots = ?depots, "depot: selection");
        return;
    }

    /// (app id, BuildDepotDependency result, selected depot count).
    type Outcome = (u32, bool, Option<usize>);
    static REPORTED: Mutex<Option<HashSet<Outcome>>> = Mutex::new(None);
    let first = REPORTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(HashSet::new)
        .insert((app_id, result, depots));
    if !first {
        return;
    }
    warn!(
        app_id,
        result,
        depots = ?depots,
        license_sync_complete = vapor_forge_features::apps::license_sync_complete(),
        actual_ownership = ?vapor_forge_features::apps::actual_ownership(app),
        pkg0_injected = super::install::PKG0_INJECTED.load(Ordering::Acquire),
        depot_injection_ready =
            crate::capability::is_ready(crate::capability::Capability::DepotInjection),
        "depot: controlled app has no depots selected"
    );
}

// ---------------------------------------------------------------------------
// Hook replacement functions: LoadDepotDecryptionKey (depot key injection)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_load_depot_decryption_key(
    unused: *mut c_void,
    depot_id: u32,
    out: *mut c_void,
) -> bool {
    let original = detour_or_return!("LoadDepotDecryptionKey", DEPOT_KEY_DETOUR, false);
    if !crate::capability::is_ready(crate::capability::Capability::DepotInjection) || out.is_null()
    {
        // SAFETY: forwards Steam's untouched key request.
        return unsafe { original(unused, depot_id, out) };
    }
    let served = {
        let ss = script_state();
        let served =
            vapor_forge_features::depot_key::provide_key(DepotId(depot_id), &ss.depot_keys);
        log_depot_key_request(depot_id, served.is_some(), ss.depot_keys.len());
        served
    };
    if let (Some(key), Some(calls)) = (served, KEY_BUFFER_CALLS.get()) {
        // SAFETY: `out` is the loader's live CUtlBuffer argument, and both
        // calls are the ones the loader itself makes on it.
        if unsafe { write_key(out, calls, &key) } {
            return true;
        }
    }
    // SAFETY: forwards Steam's untouched key request.
    unsafe { original(unused, depot_id, out) }
}

/// Fill `out` the way the loader does after a successful config-store read:
/// reserve the key capacity, copy into the buffer's memory, set the put
/// position to the key length.
///
/// # Safety
/// `out` must be a live `CUtlBuffer` and `calls` must be decoded from the
/// loader running in this process.
unsafe fn write_key(out: *mut c_void, calls: &KeyBufferCalls, key: &[u8; DEPOT_KEY_SIZE]) -> bool {
    // SAFETY: the decoded targets are the loader's own buffer helpers.
    let (ensure_capacity, seek_put) = unsafe {
        (
            std::mem::transmute::<usize, EnsureCapacityFn>(calls.ensure_capacity),
            std::mem::transmute::<usize, SeekPutFn>(calls.seek_put),
        )
    };
    // SAFETY: same call and argument the loader makes before reading.
    unsafe { ensure_capacity(out, KEY_CAPACITY as i32) };
    // SAFETY: CUtlBuffer's memory pointer is its first member; the loader
    // reads it the same way to hand the config store its destination.
    let base = unsafe { *out.cast::<*mut u8>() };
    if base.is_null() {
        return false;
    }
    // SAFETY: EnsureCapacity reserved KEY_CAPACITY >= DEPOT_KEY_SIZE bytes.
    unsafe { std::ptr::copy_nonoverlapping(key.as_ptr(), base, DEPOT_KEY_SIZE) };
    // SAFETY: same call the loader makes with the length it read.
    unsafe { seek_put(out, SEEK_HEAD, DEPOT_KEY_SIZE as i32) };
    true
}

/// Decode the loader's buffer calls; without them the key cannot be served,
/// so the caller does not install the hook.
pub(crate) fn resolve_key_buffer_calls(code: &CodeRegion, loader: usize) -> bool {
    match vapor_forge_patterns::depot_key_loader::decode(usize::BITS, code.base, code.bytes, loader)
    {
        Ok(calls) => {
            info!(
                ensure_capacity = format_args!("0x{:x}", calls.ensure_capacity),
                seek_put = format_args!("0x{:x}", calls.seek_put),
                "depot: key loader buffer calls resolved"
            );
            let _ = KEY_BUFFER_CALLS.set(calls);
            true
        }
        Err(error) => {
            warn!(error, "depot: key loader buffer calls did not decode");
            false
        }
    }
}

/// Report each depot key Steam asks for and whether the scripts could answer,
/// once per depot.
fn log_depot_key_request(depot_id: u32, served: bool, configured: usize) {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static SEEN: Mutex<Option<HashSet<u32>>> = Mutex::new(None);
    let first = SEEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(HashSet::new)
        .insert(depot_id);
    if first {
        info!(depot_id, served, configured, "depot: key request");
    }
}
