use core::ffi::c_void;
use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;

use vapor_forge_hook_engine::original::detour_or_return;

use super::install::config;

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type IsAppDlcInstalledFn = unsafe extern "C" fn(*mut c_void, u32, u32) -> bool;
pub(crate) type BIsDlcEnabledFn = unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void) -> bool;

pub(crate) const IS_APP_DLC_INSTALLED_NAME: &str = "IClientAppManager::IsAppDlcInstalled";
pub(crate) const B_IS_DLC_ENABLED_NAME: &str = "IClientAppManager::BIsDlcEnabled";

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut IS_APP_DLC_INSTALLED_DETOUR: Option<Detour<IsAppDlcInstalledFn>> = None;
pub(crate) static mut B_IS_DLC_ENABLED_DETOUR: Option<Detour<BIsDlcEnabledFn>> = None;

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientAppManager DLC gates
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_is_app_dlc_installed(
    this: *mut c_void,
    app_id: u32,
    dlc_id: u32,
) -> bool {
    // SAFETY: installation initializes the detour before enabling it.
    let original = detour_or_return!(
        IS_APP_DLC_INSTALLED_NAME,
        IS_APP_DLC_INSTALLED_DETOUR,
        false
    );
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, app_id, dlc_id) };

    if !crate::capability::is_ready(crate::capability::Capability::DlcOverrides) {
        return result;
    }

    let cfg = config();
    vapor_forge_features::dlc::on_is_dlc_installed(&cfg, AppId(app_id), AppId(dlc_id), result)
}

pub(crate) unsafe extern "C" fn hk_b_is_dlc_enabled(
    this: *mut c_void,
    app_id: u32,
    dlc_id: u32,
    unknown: *mut c_void,
) -> bool {
    // SAFETY: installation initializes the detour before enabling it.
    let original = detour_or_return!(B_IS_DLC_ENABLED_NAME, B_IS_DLC_ENABLED_DETOUR, false);
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, app_id, dlc_id, unknown) };

    if !crate::capability::is_ready(crate::capability::Capability::DlcOverrides) {
        return result;
    }

    let cfg = config();
    vapor_forge_features::dlc::on_is_dlc_enabled(&cfg, AppId(app_id), AppId(dlc_id), result)
}

// DLC enumeration (GetDLCCount / BGetDLCDataByIndex) is NOT hooked.
// DLC app IDs go into pkg0 alongside main app IDs, so Steam downloads
// their appinfo and handles enumeration natively.
