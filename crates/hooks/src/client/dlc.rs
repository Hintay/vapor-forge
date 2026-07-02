use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use retour::GenericDetour;
use tracing::{debug, warn};
use vapor_forge_config::AppId;

use crate::original::{detour_or_return, vmt_or_return};
use crate::vmt;

use super::install::{config, validate_vmt_hook_eligibility, read_vtable_slot};

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type IsAppDlcInstalledFn = extern "C" fn(*mut c_void, u32, u32) -> bool;
pub(crate) type BIsDlcEnabledFn = extern "C" fn(*mut c_void, u32, u32, *mut c_void) -> bool;
pub(crate) type LaunchAppFn =
    extern "C" fn(*mut c_void, *mut u32, *mut c_void, *mut c_void, *mut c_void) -> *mut c_void;

// Re-use RunIPCFrameFn from cloud module
use super::cloud::RunIPCFrameFn;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut APP_MANAGER_DETOUR: Option<GenericDetour<RunIPCFrameFn>> = None;
pub(crate) static mut CLIENT_APPS_DETOUR: Option<GenericDetour<RunIPCFrameFn>> = None;
pub(crate) static mut ORIG_IS_APP_DLC_INSTALLED: Option<IsAppDlcInstalledFn> = None;
pub(crate) static mut ORIG_B_IS_DLC_ENABLED: Option<BIsDlcEnabledFn> = None;
pub(crate) static mut ORIG_LAUNCH_APP: Option<LaunchAppFn> = None;
pub(crate) static APP_MANAGER_VMT_DONE: AtomicBool = AtomicBool::new(false);
pub(crate) static CLIENT_APPS_VMT_DONE: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientAppManager::RunIPCFrame (DLC VMT)
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_app_manager_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !APP_MANAGER_VMT_DONE.load(Ordering::Acquire) {
        install_app_manager_vmt(this);
    }

    // SAFETY: APP_MANAGER_DETOUR set before enabled.
    let original = detour_or_return!("IClientAppManager::RunIPCFrame", APP_MANAGER_DETOUR, ());
    original.call(this, a1, a2, a3);
}

extern "C" fn hk_is_app_dlc_installed(this: *mut c_void, app_id: u32, dlc_id: u32) -> bool {
    // SAFETY: original function pointer set before VMT swap.
    let original = vmt_or_return!("IsAppDlcInstalled", ORIG_IS_APP_DLC_INSTALLED, false);
    let result = original(this, app_id, dlc_id);

    let cfg = config();
    vapor_forge_features::dlc::on_is_dlc_installed(&*cfg, AppId(app_id), AppId(dlc_id), result)
}

extern "C" fn hk_b_is_dlc_enabled(
    this: *mut c_void,
    app_id: u32,
    dlc_id: u32,
    unknown: *mut c_void,
) -> bool {
    // SAFETY: original function pointer set before VMT swap.
    let original = vmt_or_return!("BIsDlcEnabled", ORIG_B_IS_DLC_ENABLED, false);
    let result = original(this, app_id, dlc_id, unknown);

    let cfg = config();
    vapor_forge_features::dlc::on_is_dlc_enabled(&*cfg, AppId(app_id), AppId(dlc_id), result)
}

extern "C" fn hk_launch_app(
    this: *mut c_void,
    p_app_id: *mut u32,
    a2: *mut c_void,
    a3: *mut c_void,
    a4: *mut c_void,
) -> *mut c_void {
    if !p_app_id.is_null() {
        let app_id = unsafe { *p_app_id };
        debug!(app_id, "LaunchApp");
    }
    // Flag evaluation moved to SpawnProcess hook (has pCommandLine directly).
    let original = vmt_or_return!("LaunchApp", ORIG_LAUNCH_APP, std::ptr::null_mut());
    original(this, p_app_id, a2, a3, a4)
}

fn install_app_manager_vmt(this: *mut c_void) {
    if APP_MANAGER_VMT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }

    let slot_installed = crate::vtable_scan::slot_of("IClientAppManager", "IsAppDlcInstalled");
    let slot_enabled = crate::vtable_scan::slot_of("IClientAppManager", "BIsDlcEnabled");
    let slot_launch = crate::vtable_scan::slot_of("IClientAppManager", "LaunchApp");

    if let Some(slot) = slot_installed {
        if let Some(addr) = unsafe { read_vtable_slot(this, slot) } {
            let repl = hk_is_app_dlc_installed as *const () as usize;
            if validate_vmt_hook_eligibility("IsAppDlcInstalled", addr, repl) {
                unsafe {
                    std::ptr::addr_of_mut!(ORIG_IS_APP_DLC_INSTALLED)
                        .write(Some(std::mem::transmute(addr)));
                    vmt::swap_vtable_slot("IsAppDlcInstalled", this, slot, repl);
                }
            }
        }
    } else {
        warn!("hook-install: IsAppDlcInstalled slot not found");
    }

    if let Some(slot) = slot_enabled {
        if let Some(addr) = unsafe { read_vtable_slot(this, slot) } {
            let repl = hk_b_is_dlc_enabled as *const () as usize;
            if validate_vmt_hook_eligibility("BIsDlcEnabled", addr, repl) {
                unsafe {
                    std::ptr::addr_of_mut!(ORIG_B_IS_DLC_ENABLED)
                        .write(Some(std::mem::transmute(addr)));
                    vmt::swap_vtable_slot("BIsDlcEnabled", this, slot, repl);
                }
            }
        }
    } else {
        warn!("hook-install: BIsDlcEnabled slot not found");
    }

    // LaunchApp: intercept to evaluate AppAvatar flag rules at game-launch time.
    if let Some(slot) = slot_launch {
        if let Some(addr) = unsafe { read_vtable_slot(this, slot) } {
            let repl = hk_launch_app as *const () as usize;
            if validate_vmt_hook_eligibility("LaunchApp", addr, repl) {
                // SAFETY: original stored before VMT slot is replaced.
                unsafe {
                    std::ptr::addr_of_mut!(ORIG_LAUNCH_APP).write(Some(std::mem::transmute(addr)));
                    vmt::swap_vtable_slot("LaunchApp", this, slot, repl);
                }
            }
        }
    } else {
        debug!("hook-install: LaunchApp slot not found (app-avatar flag rules inactive)");
    }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientApps::RunIPCFrame (DLC count/data VMT)
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_client_apps_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !CLIENT_APPS_VMT_DONE.load(Ordering::Acquire) {
        install_client_apps_vmt(this);
    }

    // SAFETY: CLIENT_APPS_DETOUR set before enabled.
    let original = detour_or_return!("IClientApps::RunIPCFrame", CLIENT_APPS_DETOUR, ());
    original.call(this, a1, a2, a3);
}

// DLC enumeration (GetDLCCount / BGetDLCDataByIndex) is NOT hooked.
// DLC app IDs go into pkg0 alongside main app IDs, so Steam downloads
// their appinfo and handles enumeration natively.

fn install_client_apps_vmt(_this: *mut c_void) {
    if CLIENT_APPS_VMT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }
    // IClientApps VMT hooks removed. DLC handled via pkg0 injection.
}
