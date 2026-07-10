use core::ffi::c_void;
use retour::GenericDetour;
use tracing::{debug, warn};
use vapor_forge_config::AppId;

use crate::original::{detour_or_return, vmt_or_return};
use crate::vmt;

use super::install::{config, read_vtable_slot, validate_vmt_hook_eligibility};

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
static IS_APP_DLC_INSTALLED_GATE: vmt::InstallGate = vmt::InstallGate::new();
static B_IS_DLC_ENABLED_GATE: vmt::InstallGate = vmt::InstallGate::new();
static LAUNCH_APP_GATE: vmt::InstallGate = vmt::InstallGate::new();

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientAppManager::RunIPCFrame (DLC VMT)
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_app_manager_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !app_manager_vmt_settled() {
        install_app_manager_vmt(this);
    }

    // SAFETY: APP_MANAGER_DETOUR set before enabled.
    let original = detour_or_return!("IClientAppManager::RunIPCFrame", APP_MANAGER_DETOUR);
    original.call(this, a1, a2, a3);
}

extern "C" fn hk_is_app_dlc_installed(this: *mut c_void, app_id: u32, dlc_id: u32) -> bool {
    // SAFETY: original function pointer set before VMT swap.
    let original = vmt_or_return!("IsAppDlcInstalled", ORIG_IS_APP_DLC_INSTALLED, false);
    let result = original(this, app_id, dlc_id);

    let cfg = config();
    vapor_forge_features::dlc::on_is_dlc_installed(&cfg, AppId(app_id), AppId(dlc_id), result)
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
    vapor_forge_features::dlc::on_is_dlc_enabled(&cfg, AppId(app_id), AppId(dlc_id), result)
}

extern "C" fn hk_launch_app(
    this: *mut c_void,
    p_app_id: *mut u32,
    a2: *mut c_void,
    a3: *mut c_void,
    a4: *mut c_void,
) -> *mut c_void {
    if !p_app_id.is_null() {
        // SAFETY: p_app_id is a non-null pointer supplied by Steam.
        let app_id = unsafe { *p_app_id };
        debug!(app_id, "LaunchApp");
    }
    // Flag evaluation moved to SpawnProcess hook (has pCommandLine directly).
    let original = vmt_or_return!("LaunchApp", ORIG_LAUNCH_APP, std::ptr::null_mut());
    original(this, p_app_id, a2, a3, a4)
}

fn install_app_manager_vmt(this: *mut c_void) {
    if let Some(attempt) = IS_APP_DLC_INSTALLED_GATE.begin() {
        if let Some(slot) = crate::vtable_scan::slot_of("IClientAppManager", "IsAppDlcInstalled") {
            // SAFETY: this is the live IClientAppManager object passed by Steam.
            if let Some(addr) = unsafe { read_vtable_slot(this, slot) } {
                let repl = hk_is_app_dlc_installed as *const () as usize;
                if validate_vmt_hook_eligibility("IsAppDlcInstalled", addr, repl) {
                    // SAFETY: original is stored before replacing the validated slot.
                    unsafe {
                        std::ptr::addr_of_mut!(ORIG_IS_APP_DLC_INSTALLED).write(Some(
                            std::mem::transmute::<usize, IsAppDlcInstalledFn>(addr),
                        ));
                        if vmt::swap_vtable_slot("IsAppDlcInstalled", this, slot, repl).is_some() {
                            attempt.commit();
                        }
                    }
                } else {
                    attempt.disable();
                }
            }
        } else {
            warn!("hook-install: IsAppDlcInstalled slot not found");
            attempt.disable();
        }
    }

    if let Some(attempt) = B_IS_DLC_ENABLED_GATE.begin() {
        if let Some(slot) = crate::vtable_scan::slot_of("IClientAppManager", "BIsDlcEnabled") {
            // SAFETY: this is the live IClientAppManager object passed by Steam.
            if let Some(addr) = unsafe { read_vtable_slot(this, slot) } {
                let repl = hk_b_is_dlc_enabled as *const () as usize;
                if validate_vmt_hook_eligibility("BIsDlcEnabled", addr, repl) {
                    // SAFETY: original is stored before replacing the validated slot.
                    unsafe {
                        std::ptr::addr_of_mut!(ORIG_B_IS_DLC_ENABLED)
                            .write(Some(std::mem::transmute::<usize, BIsDlcEnabledFn>(addr)));
                        if vmt::swap_vtable_slot("BIsDlcEnabled", this, slot, repl).is_some() {
                            attempt.commit();
                        }
                    }
                } else {
                    attempt.disable();
                }
            }
        } else {
            warn!("hook-install: BIsDlcEnabled slot not found");
            attempt.disable();
        }
    }

    // LaunchApp: intercept to evaluate AppAvatar flag rules at game-launch time.
    if let Some(attempt) = LAUNCH_APP_GATE.begin() {
        if let Some(slot) = crate::vtable_scan::slot_of("IClientAppManager", "LaunchApp") {
            // SAFETY: this is the live IClientAppManager object passed by Steam.
            if let Some(addr) = unsafe { read_vtable_slot(this, slot) } {
                let repl = hk_launch_app as *const () as usize;
                if validate_vmt_hook_eligibility("LaunchApp", addr, repl) {
                    // SAFETY: original is stored before replacing the validated slot.
                    unsafe {
                        std::ptr::addr_of_mut!(ORIG_LAUNCH_APP).write(Some(std::mem::transmute::<
                            usize,
                            LaunchAppFn,
                        >(
                            addr
                        )));
                        if vmt::swap_vtable_slot("LaunchApp", this, slot, repl).is_some() {
                            attempt.commit();
                        }
                    }
                } else {
                    attempt.disable();
                }
            }
        } else {
            debug!("hook-install: LaunchApp slot not found (app-avatar flag rules inactive)");
            attempt.disable();
        }
    }
}

fn app_manager_vmt_settled() -> bool {
    IS_APP_DLC_INSTALLED_GATE.is_settled()
        && B_IS_DLC_ENABLED_GATE.is_settled()
        && LAUNCH_APP_GATE.is_settled()
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
    // SAFETY: CLIENT_APPS_DETOUR set before enabled.
    let original = detour_or_return!("IClientApps::RunIPCFrame", CLIENT_APPS_DETOUR);
    original.call(this, a1, a2, a3);
}

// DLC enumeration (GetDLCCount / BGetDLCDataByIndex) is NOT hooked.
// DLC app IDs go into pkg0 alongside main app IDs, so Steam downloads
// their appinfo and handles enumeration natively.
