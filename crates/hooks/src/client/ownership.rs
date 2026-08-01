use core::ffi::c_void;
use std::sync::atomic::Ordering;

use vapor_forge_config::AppId;
use vapor_forge_features::apps::{OwnershipDecision, OwnershipObservation};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_steam_native_abi::CAppOwnershipInfo;

use vapor_forge_hook_engine::original::detour_or_return;

use super::install::{config, package_state, runtime_snapshot, PKG0_INJECTED};

// ---------------------------------------------------------------------------
// Function type alias
// ---------------------------------------------------------------------------

pub(crate) type CheckAppOwnershipFn =
    unsafe extern "C" fn(*mut c_void, u32, *mut CAppOwnershipInfo) -> u32;
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
) -> u32 {
    // SAFETY: OWNERSHIP_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("CheckAppOwnership", OWNERSHIP_DETOUR, 0);
    let pkg0_was_injected = PKG0_INJECTED.load(Ordering::Acquire);
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, app_id, out) };

    // SAFETY: `this` is the live CUser receiver for this hook callback.
    unsafe { super::package::capture_cuser(this) };

    // This is the first stable post-login CUser boundary. Starting the Steam-owned
    // worker here avoids creating a thread from inside the audit loader callback.
    super::user_stats::ensure_worker_started();

    if !pkg0_was_injected && !out.is_null() {
        // SAFETY: the original call populated `out` and it remains valid for this callback.
        // SAFETY: the original call populated `out` and it remains valid for this callback.
        let genuine = vapor_forge_features::apps::original_result_is_genuinely_owned(
            ownership_observation(result, unsafe { &*out }),
        );
        vapor_forge_features::apps::record_actual_ownership(AppId(app_id), genuine);
    }

    if out.is_null() {
        return result;
    }

    // SAFETY: this scope exists only for the dynamic extent of this callback.
    let mut package_scope = unsafe { super::package::SteamPackageHookScope::enter() };
    let mut package_access = super::package::SteamPackageAccess::from_hook(&mut package_scope);

    // pkg0 injection: triggered after GetPackageInfo hook captures CPackageInfo* + pkg0
    if let Some(access) = package_access.as_mut() {
        if !PKG0_INJECTED.swap(true, Ordering::AcqRel) {
            let runtime = runtime_snapshot();
            let controlled = vapor_forge_features::package::controlled_app_ids(
                &runtime.config,
                &runtime.script_state.apps,
            );
            let pkg_state = package_state();
            let plan = pkg_state.compute_injection(&controlled);

            snapshot_with_original(original, this, &plan.app_ids);

            let injected = access.inject(&plan.app_ids);
            pkg_state.record_injected(&injected);
            pkg_state.set_active();
        }
    }

    if let Some(access) = package_access.as_mut() {
        super::package::pump_reload(access, |app_ids| {
            snapshot_with_original(original, this, app_ids)
        });
    }

    let cfg = config();
    // SAFETY: out is a valid pointer provided by Steam's caller, filled by original.
    let info = unsafe { &mut *out };

    // If pkg0 injection is active, Steam's original already sees ownership
    // from pkg0. Still run the spoof as fallback for edge cases.
    let decision = vapor_forge_features::apps::decide_check_ownership(
        &cfg,
        AppId(app_id),
        ownership_observation(result, info),
    );
    apply_ownership_decision(info, decision)
}

fn ownership_observation(result: u32, info: &CAppOwnershipInfo) -> OwnershipObservation {
    OwnershipObservation {
        original_result: result,
        package_associations: info.exist_in_package_nums,
        family_shared: info.is_family_shared(),
    }
}

fn apply_ownership_decision(info: &mut CAppOwnershipInfo, decision: OwnershipDecision) -> u32 {
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

    let cfg = config();

    if app_list.is_null() || size == 0 {
        return count + vapor_forge_features::apps::get_subscribed_count_adjustment(&cfg);
    }

    // SAFETY: app_list buffer has `size` u32 slots, provided by Steam's caller.
    let slice = unsafe { std::slice::from_raw_parts_mut(app_list, size as usize) };
    vapor_forge_features::apps::on_get_subscribed_apps(&cfg, slice, count)
}
