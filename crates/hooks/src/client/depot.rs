use core::ffi::c_void;

use tracing::info;
use vapor_forge_config::DepotId;
use vapor_forge_hook_engine::detour::Detour;

use vapor_forge_hook_engine::original::detour_or_return;

use super::install::script_state;

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

pub(crate) type LoadDepotDecryptionKeyFn =
    unsafe extern "C" fn(*mut c_void, u32, *const i8, *mut u8, u32) -> i32;

// ---------------------------------------------------------------------------
// Static detour slots
// ---------------------------------------------------------------------------

pub(crate) static mut BUILD_DEPOT_DETOUR: Option<Detour<BuildDepotDependencyFn>> = None;
pub(crate) static mut DEPOT_KEY_DETOUR: Option<Detour<LoadDepotDecryptionKeyFn>> = None;

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

// ---------------------------------------------------------------------------
// Hook replacement functions: LoadDepotDecryptionKey (depot key injection)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_load_depot_decryption_key(
    this: *mut c_void,
    unknown: u32,
    key_name: *const i8,
    key_buf: *mut u8,
    key_size: u32,
) -> i32 {
    let original = detour_or_return!("LoadDepotDecryptionKey", DEPOT_KEY_DETOUR, 0);
    if !crate::capability::is_ready(crate::capability::Capability::DepotInjection) {
        // SAFETY: forwards Steam's untouched key query.
        return unsafe { original(this, unknown, key_name, key_buf, key_size) };
    }
    if !key_name.is_null() && key_size >= 32 && !key_buf.is_null() {
        if let Some(depot_id_raw) =
            /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
            unsafe { extract_depot_id_from_raw(key_name) }
        {
            let ss = script_state();
            let served =
                vapor_forge_features::depot_key::provide_key(DepotId(depot_id_raw), &ss.depot_keys);
            #[cfg(debug_assertions)]
            log_depot_key_request(depot_id_raw, served.is_some(), ss.depot_keys.len());
            if let Some(key) = served {
                // SAFETY: key_buf has key_size capacity >= 32, we write 32 bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(key.as_ptr(), key_buf, 32);
                }
                return 32;
            }
        } else {
            #[cfg(debug_assertions)]
            log_depot_key_unparsed(key_name);
        }
    }

    // SAFETY: forwards Steam's untouched key query.
    unsafe { original(this, unknown, key_name, key_buf, key_size) }
}

/// # Safety
/// `key_name` must point to a readable NUL-terminated string of at most
/// `MAX_SCAN` bytes.
pub(crate) unsafe fn extract_depot_id_from_raw(key_name: *const i8) -> Option<u32> {
    // Bounded scan for "\DecryptionKey" in the C string.
    const MAX_SCAN: usize = 512;
    const TAG: &[u8] = b"\\DecryptionKey";

    // SAFETY: bounded read of key_name up to MAX_SCAN bytes or NUL.
    let mut len = 0;
    while len < MAX_SCAN {
        // SAFETY: caller supplied key_name and this scan is bounded to MAX_SCAN.
        let byte = unsafe { *key_name.add(len) } as u8;
        if byte == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return None;
    }

    // SAFETY: we just verified [0..len) are readable non-NUL bytes.
    let bytes = unsafe { std::slice::from_raw_parts(key_name as *const u8, len) };

    // Find "\DecryptionKey" tag
    let tag_pos = bytes.windows(TAG.len()).position(|w| w == TAG)?;

    // Extract depot ID: digits between the last '\' before tag and tag_pos
    let before_tag = &bytes[..tag_pos];
    let id_start = before_tag.iter().rposition(|&b| b == b'\\')? + 1;
    let id_bytes = &before_tag[id_start..];
    let id_str = std::str::from_utf8(id_bytes).ok()?;
    id_str.parse().ok()
}

/// Report each depot key Steam asks for and whether the scripts could answer,
/// once per depot. Nothing on this path logged before, so an unanswered request
/// was indistinguishable from the hook never being reached at all.
#[cfg(debug_assertions)]
fn log_depot_key_request(depot_id: u32, served: bool, configured: usize) {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static SEEN: Mutex<Option<HashSet<u32>>> = Mutex::new(None);
    let first = SEEN
        .lock()
        .unwrap()
        .get_or_insert_with(HashSet::new)
        .insert(depot_id);
    if first {
        info!(depot_id, served, configured, "depot: key request");
    }
}

/// A key name whose depot id could not be parsed never reaches the script
/// lookup, so it is worth seeing verbatim.
#[cfg(debug_assertions)]
fn log_depot_key_unparsed(key_name: *const i8) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if LOGGED.swap(true, Ordering::AcqRel) {
        return;
    }
    // SAFETY: the caller checked the pointer is non-null, and Steam passes a
    // NUL-terminated key name.
    let name = unsafe { core::ffi::CStr::from_ptr(key_name) };
    info!(
        name = %name.to_string_lossy(),
        "depot: key name did not yield a depot id"
    );
}
