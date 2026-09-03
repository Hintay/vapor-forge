use core::ffi::c_void;
use std::sync::atomic::Ordering;

use vapor_forge_config::AppId;
use vapor_forge_features::apps::{OwnershipDecision, OwnershipObservation};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::original_detour;
use vapor_forge_steam_native_abi::CAppOwnershipInfo;

use vapor_forge_hook_engine::original::detour_or_return;

use super::install::{config, runtime_snapshot, PKG0_INJECTED};

// ---------------------------------------------------------------------------
// Function type alias
// ---------------------------------------------------------------------------

pub(crate) type CheckAppOwnershipFn =
    unsafe extern "C" fn(*mut c_void, u32, *mut CAppOwnershipInfo) -> bool;
pub(crate) type GetSubscribedAppsFn = unsafe extern "C" fn(*mut c_void, *mut u32, u32, u8) -> u32;

// ---------------------------------------------------------------------------
// Static detour slots
// ---------------------------------------------------------------------------

pub(crate) static mut OWNERSHIP_DETOUR: Option<Detour<CheckAppOwnershipFn>> = None;
pub(crate) static mut SUBSCRIBED_DETOUR: Option<Detour<GetSubscribedAppsFn>> = None;

// ---------------------------------------------------------------------------
// Hook replacement functions: CheckAppOwnership
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_check_app_ownership(
    this: *mut c_void,
    app_id: u32,
    out: *mut CAppOwnershipInfo,
) -> bool {
    // SAFETY: OWNERSHIP_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("CheckAppOwnership", OWNERSHIP_DETOUR, false);
    let pkg0_was_injected = PKG0_INJECTED.load(Ordering::Acquire);
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, app_id, out) };

    if !crate::capability::is_ready(crate::capability::Capability::Ownership) {
        return result;
    }

    // SAFETY: `this` is the live CUser receiver for this hook callback.
    unsafe { super::package::capture_cuser(this) };

    // This is the first stable post-login CUser boundary. Starting the Steam-owned
    // worker here avoids creating a thread from inside the audit loader callback.
    if crate::capability::is_ready(crate::capability::Capability::CallbackEvents) {
        super::user_stats::ensure_worker_started();
    }

    if !pkg0_was_injected && !out.is_null() {
        // SAFETY: the original call populated `out` and it remains valid for this callback.
        let genuine = vapor_forge_features::apps::original_result_is_genuinely_owned(
            ownership_observation(result, unsafe { &*out }),
        );
        vapor_forge_features::apps::record_actual_ownership(AppId(app_id), genuine);
    }

    if out.is_null() {
        return result;
    }

    let runtime = runtime_snapshot();
    let cfg = &runtime.config;
    let app_id = AppId(app_id);
    // SAFETY: out is a valid pointer provided by Steam's caller, filled by original.
    let info = unsafe { &mut *out };

    // A pkg0 lookup can succeed without setting the native owns-license bit.
    // Normalize the returned ownership record before Steam composes app flags.
    let decision = vapor_forge_features::apps::decide_check_ownership(
        cfg,
        app_id,
        ownership_observation(result, info),
    );
    let result = apply_ownership_decision(info, decision);
    if vapor_forge_features::apps::classify_app(cfg, app_id).requires_injected_ownership() {
        let purchase_time = runtime.purchase_time(app_id);
        if purchase_time != 0 {
            info.purchase_time = purchase_time;
        }
    }
    result
}

fn ownership_observation(result: bool, info: &CAppOwnershipInfo) -> OwnershipObservation {
    OwnershipObservation {
        original_result: result,
        owns_license: info.owns_license() != 0,
        family_shared: info.is_family_shared(),
    }
}

fn apply_ownership_decision(info: &mut CAppOwnershipInfo, decision: OwnershipDecision) -> bool {
    if decision.grant_spoofed_ownership {
        info.grant_spoofed_ownership();
    }
    if decision.clear_family_shared {
        info.clear_family_shared();
    }
    decision.result
}

fn snapshot_with_original(original: CheckAppOwnershipFn, this: *mut c_void, app_ids: &[AppId]) {
    for &app_id in app_ids {
        let mut info = CAppOwnershipInfo::zeroed();
        let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, app_id.0, &mut info) };
        let genuine = vapor_forge_features::apps::original_result_is_genuinely_owned(
            ownership_observation(result, &info),
        );
        vapor_forge_features::apps::record_actual_ownership(app_id, genuine);
    }
}

pub(crate) fn snapshot_actual_ownership(this: *mut c_void, app_ids: &[AppId]) -> bool {
    // SAFETY: installation initializes the process-lifetime detour before any
    // package work item can be posted.
    let Some(original) =
        (unsafe { original_detour("CheckAppOwnership", std::ptr::addr_of!(OWNERSHIP_DETOUR)) })
    else {
        return false;
    };
    snapshot_with_original(original, this, app_ids);
    true
}

// ---------------------------------------------------------------------------
// Hook replacement functions: GetSubscribedApps
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_get_subscribed_apps(
    this: *mut c_void,
    app_list: *mut u32,
    size: u32,
    a3: u8,
) -> u32 {
    // SAFETY: SUBSCRIBED_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("GetSubscribedApps", SUBSCRIBED_DETOUR, 0);
    let count = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, app_list, size, a3) };

    if !crate::capability::is_ready(crate::capability::Capability::Ownership) {
        return count;
    }

    let cfg = config();
    // Steam enumerates subscriptions right after it processed a license change,
    // so this is where a pending license list gets turned into ownership.
    super::package::run_pending_ownership_refresh(&cfg);
    let pkg0_injected = PKG0_INJECTED.load(Ordering::Acquire);

    // Steam calls this twice: once with (NULL, 0) to size a CUtlVector, then
    // with the buffer, ignoring the second return value and consuming every
    // sized slot. Both answers must therefore describe the same list, and the
    // fill path must never leave slots unwritten.
    if app_list.is_null() || size == 0 || count > size {
        return count
            + vapor_forge_features::apps::get_subscribed_count_adjustment(&cfg, pkg0_injected);
    }

    // SAFETY: app_list buffer has `size` u32 slots, provided by Steam's caller.
    let slice = unsafe { std::slice::from_raw_parts_mut(app_list, size as usize) };
    vapor_forge_features::apps::on_get_subscribed_apps(&cfg, slice, count)
}
