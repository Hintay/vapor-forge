use core::ffi::c_void;
use std::sync::atomic::Ordering;

use retour::GenericDetour;
use tracing::debug;
use vapor_forge_abi::CAppOwnershipInfo;
use vapor_forge_config::AppId;

use crate::original::detour_or_return;

use super::install::{config, package_state, runtime_snapshot, PKG0_INJECTED};

// ---------------------------------------------------------------------------
// Function type alias
// ---------------------------------------------------------------------------

pub(crate) type CheckAppOwnershipFn =
    extern "C" fn(*mut c_void, u32, *mut CAppOwnershipInfo) -> u32;
pub(crate) type GetSubscribedAppsFn = extern "C" fn(*mut c_void, *mut u32, u32, u8) -> u32;

// ---------------------------------------------------------------------------
// Static detour slots
// ---------------------------------------------------------------------------

pub(crate) static mut OWNERSHIP_DETOUR: Option<GenericDetour<CheckAppOwnershipFn>> = None;
pub(crate) static mut SUBSCRIBED_DETOUR: Option<GenericDetour<GetSubscribedAppsFn>> = None;

// ---------------------------------------------------------------------------
// Hook replacement functions: CheckAppOwnership
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_check_app_ownership(
    this: *mut c_void,
    app_id: u32,
    out: *mut CAppOwnershipInfo,
) -> u32 {
    // SAFETY: OWNERSHIP_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("CheckAppOwnership", OWNERSHIP_DETOUR, 0);
    let result = original.call(this, app_id, out);

    if out.is_null() {
        return result;
    }

    // Store CUser pointer for MarkLicenseAsChanged / ProcessPendingLicenseUpdates
    if super::package::CUSER_PTR.load(Ordering::Acquire) == 0 {
        super::package::CUSER_PTR.store(this as usize, Ordering::Release);
        debug!("package: captured CUser at 0x{:x}", this as usize);
    }

    // CUser also implements IClientUser; install the GetSteamID VMT hook once
    // we have a live instance, so ticket-delegate mode can spoof it.
    if !super::ticket::steamid_vmt_settled() {
        super::ticket::install_steamid_vmt(this);
    }

    // pkg0 injection: triggered after GetPackageInfo hook captures CPackageInfo* + pkg0
    if super::package::PKG0_PTR.load(Ordering::Acquire) != 0
        && !PKG0_INJECTED.swap(true, Ordering::AcqRel)
    {
        let runtime = runtime_snapshot();
        let controlled = vapor_forge_features::package::controlled_app_ids(
            &runtime.config,
            &runtime.script_state.apps,
        );
        let pkg_state = package_state();
        let plan = pkg_state.compute_injection(&controlled);

        // SAFETY: pkg0 and cuser captured, function pointers resolved.
        let injected = unsafe { super::package::try_inject_once(&plan.app_ids) };
        pkg_state.record_injected(&injected);
        pkg_state.set_active();
    }

    super::package::pump_reload();

    let cfg = config();
    // SAFETY: out is a valid pointer provided by Steam's caller, filled by original.
    let info = unsafe { &mut *out };

    // If pkg0 injection is active, Steam's original already sees ownership
    // from pkg0. Still run the spoof as fallback for edge cases.
    vapor_forge_features::apps::on_check_ownership(&cfg, AppId(app_id), result, info)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: GetSubscribedApps
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_get_subscribed_apps(
    this: *mut c_void,
    app_list: *mut u32,
    size: u32,
    a3: u8,
) -> u32 {
    // SAFETY: SUBSCRIBED_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("GetSubscribedApps", SUBSCRIBED_DETOUR, 0);
    let count = original.call(this, app_list, size, a3);

    let cfg = config();

    if app_list.is_null() || size == 0 {
        return count + vapor_forge_features::apps::get_subscribed_count_adjustment(&cfg);
    }

    // SAFETY: app_list buffer has `size` u32 slots, provided by Steam's caller.
    let slice = unsafe { std::slice::from_raw_parts_mut(app_list, size as usize) };
    vapor_forge_features::apps::on_get_subscribed_apps(&cfg, slice, count)
}
