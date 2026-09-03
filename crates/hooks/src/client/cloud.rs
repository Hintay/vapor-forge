use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use tracing::{debug, info};
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_hook_engine::detour::Detour;

use vapor_forge_hook_engine::original::detour_or_return;

use super::install::config;

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) const IS_CLOUD_ENABLED_NAME: &str = "IClientRemoteStorage::IsCloudEnabledForApp";
pub(crate) const IS_CLOUD_ENABLED_FOR_ACCOUNT_NAME: &str =
    "IClientRemoteStorage::IsCloudEnabledForAccount";
pub(crate) type IsCloudEnabledForAppFn = unsafe extern "C" fn(*mut c_void, u32) -> bool;
pub(crate) type IsCloudEnabledForAccountFn = unsafe extern "C" fn(*mut c_void) -> bool;
pub(crate) type SetCloudEnabledForAppFn = unsafe extern "C" fn(*mut c_void, u32, bool);
pub(crate) type WriteVdfFileFn =
    unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void, *const u8, u32) -> u32;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut IS_CLOUD_ENABLED_DETOUR: Option<Detour<IsCloudEnabledForAppFn>> = None;
pub(crate) static mut IS_CLOUD_ENABLED_FOR_ACCOUNT_DETOUR: Option<
    Detour<IsCloudEnabledForAccountFn>,
> = None;
pub(crate) static mut WRITE_VDF_DETOUR: Option<Detour<WriteVdfFileFn>> = None;
pub(crate) static mut SET_CLOUD_FN: Option<SetCloudEnabledForAppFn> = None;

// The IClientRemoteStorage receiver Steam last used, the runtime and
// ownership generations the controlled apps were last swept for, and a
// re-entrancy latch for the sweep itself (SetCloudEnabledForApp may consult
// IsCloudEnabledForApp).
static REMOTE_STORAGE: AtomicUsize = AtomicUsize::new(0);
static SWEPT_GENERATION: AtomicU64 = AtomicU64::new(u64::MAX);
static SWEPT_OWNERSHIP_GENERATION: AtomicU64 = AtomicU64::new(u64::MAX);
static SWEEP_ACTIVE: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientRemoteStorage cloud gate
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_is_cloud_enabled_for_app(
    this: *mut c_void,
    app_id: u32,
) -> bool {
    // SAFETY: installation initializes the detour before enabling it.
    let original = detour_or_return!(IS_CLOUD_ENABLED_NAME, IS_CLOUD_ENABLED_DETOUR, true);
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, app_id) };

    if !crate::capability::is_ready(crate::capability::Capability::CloudControl) {
        return result;
    }

    let cfg = config();
    // Steam's logon sync walks every app with cloud still switched on before
    // it asks this gate about each of them, so the first sight of the receiver
    // is the earliest point at which every controlled app can be switched off.
    // SAFETY: `this` is the live receiver Steam is calling through right now.
    unsafe { sweep_controlled_apps(this, &cfg, app_id) };

    let should_disable = vapor_forge_features::apps::classify_app(&cfg, AppId(app_id))
        .requires_injected_ownership()
        && !cfg.cloud_enabled_for_controlled_apps();

    // SAFETY: captured from this object's VMT before the hook is enabled.
    let set_fn = unsafe { *std::ptr::addr_of!(SET_CLOUD_FN) };
    if should_disable {
        // Write cloudenabled=false into Steam's in-memory config store. This
        // prevents the "out of date" cloud badge after hot-reload; the VDF
        // write filter strips it before disk flush. Steam answering true for
        // an app already written means its roaming store was reloaded, so the
        // value is applied again.
        let first = vapor_forge_features::cloud::mark_cloud_wrote(AppId(app_id));
        if first || result {
            if let Some(set_fn) = set_fn {
                /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                unsafe { set_fn(this, app_id, false) };
                if first {
                    info!(
                        app_id,
                        "cloud: SetCloudEnabledForApp(false) — badge suppressed"
                    );
                } else {
                    debug!(app_id, "cloud: SetCloudEnabledForApp(false) re-applied");
                }
            }
        }
    } else if vapor_forge_features::cloud::is_forced_off(AppId(app_id)) {
        // The app no longer qualifies (script removed, backend configured,
        // genuine ownership learned): hand its cloud back to Steam.
        let result = if result {
            true
        } else if let Some(set_fn) = set_fn {
            /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
            unsafe { set_fn(this, app_id, true) };
            true
        } else {
            result
        };
        vapor_forge_features::cloud::mark_cloud_restored(AppId(app_id));
        info!(app_id, "cloud: SetCloudEnabledForApp(true) — restored");
        return vapor_forge_features::cloud::on_is_cloud_enabled(&cfg, AppId(app_id), result);
    }

    vapor_forge_features::cloud::on_is_cloud_enabled(&cfg, AppId(app_id), result)
}

/// Account-level gate, hooked only to see the receiver before Steam's logon
/// sync enumerates per-app jobs; the answer is passed through untouched.
pub(crate) unsafe extern "C" fn hk_is_cloud_enabled_for_account(this: *mut c_void) -> bool {
    // SAFETY: installation initializes the detour before enabling it.
    let original = detour_or_return!(
        IS_CLOUD_ENABLED_FOR_ACCOUNT_NAME,
        IS_CLOUD_ENABLED_FOR_ACCOUNT_DETOUR,
        true
    );
    // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
    let result = unsafe { original(this) };
    if crate::capability::is_ready(crate::capability::Capability::CloudControl) {
        let cfg = config();
        // SAFETY: `this` is the live receiver Steam is calling through right now.
        unsafe { sweep_controlled_apps(this, &cfg, 0) };
    }
    result
}

/// Reconcile Steam's per-app cloud switches with the configuration as soon as
/// a receiver is known, and again whenever the runtime generation (script or
/// config reload) or the ownership generation (genuine ownership learned)
/// changes. Controlled apps without genuine ownership are switched off; apps
/// we switched off that no longer qualify get their cloud back.
/// `trigger_app` is 0 when the account-level gate supplied the receiver.
///
/// # Safety
/// `this` must be the live IClientRemoteStorage receiver of the current call.
unsafe fn sweep_controlled_apps(this: *mut c_void, cfg: &RuntimeConfig, trigger_app: u32) {
    let generation = crate::client::install::runtime_generation();
    let ownership_generation = vapor_forge_features::apps::ownership_generation();
    let receiver = this as usize;
    let receiver_changed = REMOTE_STORAGE.swap(receiver, Ordering::AcqRel) != receiver;
    if !receiver_changed
        && SWEPT_GENERATION.load(Ordering::Acquire) == generation
        && SWEPT_OWNERSHIP_GENERATION.load(Ordering::Acquire) == ownership_generation
    {
        return;
    }
    if SWEEP_ACTIVE.swap(true, Ordering::AcqRel) {
        return;
    }
    // SAFETY: installation publishes the slot before the hook is enabled.
    let set_fn = unsafe { *std::ptr::addr_of!(SET_CLOUD_FN) };
    let mut plan = vapor_forge_features::cloud::cloud_plan(cfg);
    // Each write is an IPC message that Steam applies while its logon sync is
    // already walking the installed apps, so those go first.
    let installed = crate::client::install::steam_install_root()
        .map(|root| vapor_forge_features::cloud::installed_app_ids(&root))
        .unwrap_or_default();
    vapor_forge_features::cloud::order_installed_first(&mut plan.disable, &installed);
    let installed_targets = plan
        .disable
        .iter()
        .filter(|app_id| installed.contains(app_id))
        .count();
    let mut disabled = 0usize;
    let mut restored = 0usize;
    if let Some(set_fn) = set_fn {
        for app_id in &plan.disable {
            if vapor_forge_features::cloud::mark_cloud_wrote(*app_id) {
                // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
                unsafe { set_fn(this, app_id.0, false) };
                disabled += 1;
            }
        }
        for app_id in &plan.enable {
            if vapor_forge_features::cloud::mark_cloud_restored(*app_id) {
                // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
                unsafe { set_fn(this, app_id.0, true) };
                restored += 1;
                info!(
                    app_id = app_id.0,
                    "cloud: SetCloudEnabledForApp(true) — restored"
                );
            }
        }
    }
    SWEPT_GENERATION.store(generation, Ordering::Release);
    SWEPT_OWNERSHIP_GENERATION.store(ownership_generation, Ordering::Release);
    SWEEP_ACTIVE.store(false, Ordering::Release);
    if disabled == 0 && restored == 0 && !receiver_changed {
        return;
    }
    info!(
        receiver = format_args!("0x{receiver:x}"),
        generation,
        ownership_generation,
        trigger_app,
        controlled = plan.disable.len(),
        installed = installed_targets,
        disabled,
        restored,
        "cloud: controlled apps swept"
    );
}

pub(crate) fn set_set_cloud_function(address: usize) {
    // SAFETY: the address was decoded from the validated interface vtable.
    let function: SetCloudEnabledForAppFn = unsafe { std::mem::transmute(address) };
    // SAFETY: hook installation is the only writer and completes before use.
    unsafe { std::ptr::addr_of_mut!(SET_CLOUD_FN).write(Some(function)) };
    debug!(
        address = format_args!("0x{address:x}"),
        "SetCloudEnabledForApp resolved from interface vtable"
    );
}

pub(crate) fn set_cloud_function_ready() -> bool {
    // SAFETY: installation is the only writer and publishes the slot before this read.
    unsafe { (*std::ptr::addr_of!(SET_CLOUD_FN)).is_some() }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: CConfigStore::WriteVdfFile (VDF cloud filter)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_write_vdf_file(
    a0: *mut c_void,
    a1: u32,
    a2: u32,
    a3: *mut c_void,
    buffer: *const u8,
    size: u32,
) -> u32 {
    // SAFETY: WRITE_VDF_DETOUR is initialized before this replacement is enabled.
    let original = detour_or_return!("WriteVdfFile", WRITE_VDF_DETOUR, 0);
    if !crate::capability::is_ready(crate::capability::Capability::CloudControl) {
        // SAFETY: forwards Steam's untouched serialization buffer.
        return unsafe { original(a0, a1, a2, a3, buffer, size) };
    }
    if !buffer.is_null() && size > 0 {
        // SAFETY: buffer/size from Steam's serialized VDF.
        let data = unsafe { std::slice::from_raw_parts(buffer, size as usize) };
        if let Some(filtered) = vapor_forge_features::cloud::strip_cloud_from_vdf(data) {
            debug!(
                original = size,
                filtered = filtered.len(),
                "cloud: VDF write filtered"
            );
            // SAFETY: calling original with filtered buffer.
            return unsafe { original(a0, a1, a2, a3, filtered.as_ptr(), filtered.len() as u32) };
        }
    }

    // SAFETY: forwards Steam's untouched serialization buffer.
    unsafe { original(a0, a1, a2, a3, buffer, size) }
}
