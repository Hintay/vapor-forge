use core::ffi::c_void;
use tracing::{debug, info};
use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;

use vapor_forge_hook_engine::original::detour_or_return;

use super::install::config;

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) const IS_CLOUD_ENABLED_NAME: &str = "IClientRemoteStorage::IsCloudEnabledForApp";
pub(crate) type IsCloudEnabledForAppFn = unsafe extern "C" fn(*mut c_void, u32) -> bool;
pub(crate) type SetCloudEnabledForAppFn = unsafe extern "C" fn(*mut c_void, u32, bool);
pub(crate) type WriteVdfFileFn =
    unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void, *const u8, u32) -> u32;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut IS_CLOUD_ENABLED_DETOUR: Option<Detour<IsCloudEnabledForAppFn>> = None;
pub(crate) static mut WRITE_VDF_DETOUR: Option<Detour<WriteVdfFileFn>> = None;
pub(crate) static mut SET_CLOUD_FN: Option<SetCloudEnabledForAppFn> = None;

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
    let should_disable = vapor_forge_features::apps::classify_app(&cfg, AppId(app_id))
        .requires_injected_ownership()
        && !cfg.cloud_enabled_for_controlled_apps();

    if should_disable {
        // Write cloudenabled=false into Steam's in-memory config store (once per app).
        // This prevents the "out of date" cloud badge after hot-reload.
        // The VDF write filter strips it before disk flush.
        if vapor_forge_features::cloud::mark_cloud_wrote(AppId(app_id)) {
            // SAFETY: captured from this object's VMT before the hook is enabled.
            if let Some(set_fn) = unsafe { *std::ptr::addr_of!(SET_CLOUD_FN) } {
                /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                unsafe { set_fn(this, app_id, false) };
                info!(
                    app_id,
                    "cloud: SetCloudEnabledForApp(false) — badge suppressed"
                );
            }
        }
    }

    vapor_forge_features::cloud::on_is_cloud_enabled(&cfg, AppId(app_id), result)
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
