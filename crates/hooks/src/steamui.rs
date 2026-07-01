// SteamUI library management: refresh the Steam library UI after
// pkg0 injection (add/remove apps, stamp purchase time).
//
// Two functions in steamui.so are hooked to capture their `this` pointers:
// - CSteamUIAppController::GetAppByID(controller, appId, bCreate) -> CSteamApp*
// - CUpdateManager::MarkAppChange(source, appId, flags)
//
// After capture, we can call them directly via trampoline to manipulate
// the library UI without restarting Steam.

use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use retour::GenericDetour;
use steam_runtime_abi::steamui::{CAppOverviewChange, CSteamApp};
use steam_runtime_config::AppId;
use tracing::{debug, error, info, warn};

use crate::hook_report::{log_drift_summary, log_hook_details, HookResult};
use crate::original::detour_or_return;

const EAPP_OWNERSHIP_FLAGS_NONE: u32 = 0;
const EAPP_STATE_UNINSTALLED: u32 = 0;
const EAPPCHANGE_ADDED_OR_CREATED: u32 = 1;

type RunFrameFn = extern "C" fn(*mut c_void);
type FillInAppOverviewFn = extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
type BuildCompleteChangeFn = extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
type GetAppByIdFn = extern "C" fn(*mut c_void, u32, bool) -> *mut c_void;
type MarkAppChangeFn = extern "C" fn(*mut c_void, u32, u32);
type RepeatedFieldAddFn = extern "C" fn(*mut c_void, *const u32);

static mut REPEATED_FIELD_ADD: Option<RepeatedFieldAddFn> = None;
static mut RUN_FRAME_DETOUR: Option<GenericDetour<RunFrameFn>> = None;
static mut FILL_IN_OVERVIEW_DETOUR: Option<GenericDetour<FillInAppOverviewFn>> = None;
static mut BUILD_COMPLETE_DETOUR: Option<GenericDetour<BuildCompleteChangeFn>> = None;
static mut GET_APP_BY_ID_DETOUR: Option<GenericDetour<GetAppByIdFn>> = None;
static mut MARK_APP_CHANGE_DETOUR: Option<GenericDetour<MarkAppChangeFn>> = None;

static CONTROLLER: AtomicUsize = AtomicUsize::new(0);
static APP_CHANGE_SOURCE: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);

// Pending removals queued from the FileWatcher thread, drained on the
// UI thread inside hk_run_frame.
static PENDING_REMOVALS: Mutex<Vec<AppId>> = Mutex::new(Vec::new());
static HAS_PENDING: AtomicBool = AtomicBool::new(false);

// Apps confirmed removed. Appended to CAppOverview_Change.removed_appid
// during full rebuilds to prevent removed apps from reappearing.
static REMOVED_APP_IDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static HAS_REMOVED: AtomicBool = AtomicBool::new(false);

extern "C" fn hk_run_frame(controller: *mut c_void) {
    if CONTROLLER.load(Ordering::Relaxed) == 0 {
        CONTROLLER.store(controller as usize, Ordering::Release);
    }
    if HAS_PENDING.load(Ordering::Acquire) {
        drain_pending_removals(controller);
    }
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!("CSteamUIAppController::RunFrame", RUN_FRAME_DETOUR, ());
    original.call(controller);
}

extern "C" fn hk_fill_in_app_overview(
    this: *mut c_void,
    app_overview: *mut c_void,
    app: *mut c_void,
) -> *mut c_void {
    if !app.is_null() {
        // SAFETY: app is a CSteamApp* passed by SteamUI.
        let app_id_raw = unsafe { CSteamApp::app_id(app) };
        let cfg = crate::install::config();
        if cfg.app_category(AppId(app_id_raw)).is_some() {
            // Use configured purchase time, or fall back to current time.
            let mut t = cfg.purchase_time(AppId(app_id_raw));
            if t == 0 {
                t = unsafe { libc::time(std::ptr::null_mut()) } as u32;
            }
            // Stamp BEFORE the original copies the field into the overview.
            // SAFETY: app is a CSteamApp* passed by SteamUI.
            unsafe { CSteamApp::set_purchased_time(app, t) };
        }
    }
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!(
        "CSteamUIAppController::FillInAppOverview",
        FILL_IN_OVERVIEW_DETOUR,
        std::ptr::null_mut()
    );
    original.call(this, app_overview, app)
}

extern "C" fn hk_build_complete_change(
    controller: *mut c_void,
    change: *mut c_void,
    callback_slot: *mut c_void,
) {
    // Call original first so the full snapshot is built.
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!(
        "CSteamUIAppController::BuildCompleteAppOverviewChange",
        BUILD_COMPLETE_DETOUR,
        ()
    );
    original.call(controller, change, callback_slot);

    if change.is_null() || !HAS_REMOVED.load(Ordering::Acquire) {
        return;
    }
    let Ok(removed) = REMOVED_APP_IDS.lock() else {
        error!("steamui: removed app set lock poisoned");
        return;
    };
    if removed.is_empty() {
        return;
    }

    // SAFETY: REPEATED_FIELD_ADD resolved once at install time.
    let add_fn = match unsafe { *std::ptr::addr_of!(REPEATED_FIELD_ADD) } {
        Some(f) => f,
        None => return,
    };

    // Append removed app IDs to CAppOverview_Change.removed_appid so
    // full rebuilds don't restore apps we've hidden.
    // SAFETY: change is a valid CAppOverview_Change* from SteamUI.
    let field = unsafe { CAppOverviewChange::mutable_removed_appid(change) };
    for &app_id in removed.iter() {
        add_fn(field, &app_id);
    }
    debug!(
        count = removed.len(),
        "steamui: BuildComplete — appended removed_appid entries"
    );
}

extern "C" fn hk_get_app_by_id(
    controller: *mut c_void,
    app_id: u32,
    b_create: bool,
) -> *mut c_void {
    if CONTROLLER.load(Ordering::Relaxed) == 0 {
        CONTROLLER.store(controller as usize, Ordering::Release);
    }
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!(
        "CSteamUIAppController::GetAppByID",
        GET_APP_BY_ID_DETOUR,
        std::ptr::null_mut()
    );
    original.call(controller, app_id, b_create)
}

extern "C" fn hk_mark_app_change(source: *mut c_void, app_id: u32, flags: u32) {
    if APP_CHANGE_SOURCE.load(Ordering::Relaxed) == 0 {
        APP_CHANGE_SOURCE.store(source as usize, Ordering::Release);
    }
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR, ());
    original.call(source, app_id, flags);
}

/// Install the steamui.so hooks after the loader reaches a consistent state.
pub fn install(
    steamui_code: &crate::detour::CodeRegion,
    registry: &steam_runtime_patterns::registry::PatternRegistry,
) -> bool {
    use crate::detour;

    let names = [
        "CSteamUIAppController::RunFrame",
        "CSteamUIAppController::FillInAppOverview",
        "CSteamUIAppController::BuildCompleteAppOverviewChange",
        "CSteamUIAppController::GetAppByID",
        "CUpdateManager::MarkAppChange",
        "google::protobuf::RepeatedField<uint32>::Add",
    ];
    let mut addrs = [0usize; 6];
    let mut all_found = true;
    for (i, name) in names[..5].iter().enumerate() {
        let entry = match registry.get(name) {
            Some(e) => e,
            None => {
                warn!(name, "steamui: pattern not in registry");
                all_found = false;
                continue;
            }
        };
        let short = name.rsplit("::").next().unwrap_or(name);
        match detour::resolve_pattern_entry(steamui_code, short, &entry) {
            Some(a) => addrs[i] = a,
            None => {
                warn!(name, "steamui: pattern not found in steamui.so");
                all_found = false;
            }
        };
    }

    macro_rules! try_detour {
        ($name:expr, $addr:expr, $fn:expr, $ty:ty, $slot:ident) => {{
            let mut installed = false;
            if $addr != 0 {
                // SAFETY: $addr was resolved from steamui.so code for this function signature.
                let target: $ty = unsafe { std::mem::transmute($addr) };
                // SAFETY: target and replacement use the same function pointer type.
                let pending = unsafe { detour::create_detour::<$ty>($name, target, $addr, $fn) };
                // SAFETY: single-threaded init writes each detour slot once.
                installed = unsafe {
                    detour::store_and_finalize($name, std::ptr::addr_of_mut!($slot), pending)
                };
            }
            installed
        }};
    }

    let mut hook_results = vec![
        HookResult {
            name: names[0],
            installed: false,
            addr: addrs[0],
        },
        HookResult {
            name: names[1],
            installed: false,
            addr: addrs[1],
        },
        HookResult {
            name: names[2],
            installed: false,
            addr: addrs[2],
        },
        HookResult {
            name: names[3],
            installed: false,
            addr: addrs[3],
        },
        HookResult {
            name: names[4],
            installed: false,
            addr: addrs[4],
        },
        HookResult {
            name: names[5],
            installed: false,
            addr: addrs[5],
        },
    ];

    // GetAppByID and MarkAppChange are required capture hooks.
    if addrs[3] == 0 || addrs[4] == 0 {
        warn!("steamui: required capture hooks not found, aborting");
        log_drift_summary("steamui.so", &hook_results);
        if crate::install::config().runtime.diagnostics {
            log_hook_details("steamui.so", &hook_results);
        }
        return false;
    }

    hook_results[0].installed = try_detour!(
        "RunFrame",
        addrs[0],
        hk_run_frame as RunFrameFn,
        RunFrameFn,
        RUN_FRAME_DETOUR
    );
    hook_results[1].installed = try_detour!(
        "FillInAppOverview",
        addrs[1],
        hk_fill_in_app_overview as FillInAppOverviewFn,
        FillInAppOverviewFn,
        FILL_IN_OVERVIEW_DETOUR
    );
    hook_results[2].installed = try_detour!(
        "BuildComplete",
        addrs[2],
        hk_build_complete_change as BuildCompleteChangeFn,
        BuildCompleteChangeFn,
        BUILD_COMPLETE_DETOUR
    );
    hook_results[3].installed = try_detour!(
        "GetAppByID",
        addrs[3],
        hk_get_app_by_id as GetAppByIdFn,
        GetAppByIdFn,
        GET_APP_BY_ID_DETOUR
    );
    hook_results[4].installed = try_detour!(
        "MarkAppChange",
        addrs[4],
        hk_mark_app_change as MarkAppChangeFn,
        MarkAppChangeFn,
        MARK_APP_CHANGE_DETOUR
    );

    // Resolve RepeatedField<uint32>::Add for BuildComplete protobuf mutation.
    // The body pattern matches both int32 and uint32 instantiations (isomorphic).
    // Take the second (higher-address) match which is the uint32 version.
    if let Some(addr) = resolve_repeated_field_add(steamui_code, registry) {
        addrs[5] = addr;
        hook_results[5].addr = addr;
        hook_results[5].installed = true;
    }

    INSTALLED.store(true, Ordering::Release);

    if !all_found {
        warn!("steamui: some optional hooks missing, partial UI management");
    }
    log_drift_summary("steamui.so", &hook_results);
    if crate::install::config().runtime.diagnostics {
        log_hook_details("steamui.so", &hook_results);
    }

    // SAFETY: single-threaded init reads the resolver slot after install attempt.
    let rfa = unsafe { (*std::ptr::addr_of!(REPEATED_FIELD_ADD)).is_some() };
    info!(
        run_frame = format_args!("{:#x}", addrs[0]),
        fill_in = format_args!("{:#x}", addrs[1]),
        build_complete = format_args!("{:#x}", addrs[2]),
        get_app = format_args!("{:#x}", addrs[3]),
        mark = format_args!("{:#x}", addrs[4]),
        repeated_field_add = rfa,
        "steamui: hooks installed"
    );
    true
}

/// Resolve RepeatedField<uint32>::Add from steamui.so.
/// Uses follow=call: pattern matches one or more callsites, scan forward
/// for the last E8 CALL before RET to reach the target function.
fn resolve_repeated_field_add(
    steamui_code: &crate::detour::CodeRegion,
    registry: &steam_runtime_patterns::registry::PatternRegistry,
) -> Option<usize> {
    let entry = match registry.get("google::protobuf::RepeatedField<uint32>::Add") {
        Some(e) => e,
        None => return None,
    };
    let addr = match crate::detour::resolve_pattern_entry(
        steamui_code,
        "google::protobuf::RepeatedField<uint32>::Add",
        &entry,
    ) {
        Some(a) => a,
        None => return None,
    };

    // SAFETY: addr is a validated function address in steamui.so .text.
    let f: RepeatedFieldAddFn = unsafe { std::mem::transmute(addr) };
    // SAFETY: single-threaded init writes the resolver slot once.
    unsafe { std::ptr::addr_of_mut!(REPEATED_FIELD_ADD).write(Some(f)) };
    info!(
        addr = format_args!("{:#x}", addr),
        "steamui: RepeatedField<uint32>::Add resolved"
    );
    Some(addr)
}

/// Queue an app for removal from the library UI. The actual removal
/// happens on the UI thread when GetAppByID is next called by Steam.
pub fn queue_removal(app_id: AppId) {
    if !INSTALLED.load(Ordering::Acquire) {
        return;
    }
    let Ok(mut pending) = PENDING_REMOVALS.lock() else {
        error!("steamui: pending removal lock poisoned");
        return;
    };
    pending.push(app_id);
    HAS_PENDING.store(true, Ordering::Release);
    debug!(app = app_id.0, "steamui: removal queued");
}

/// Cancel a pending removal (e.g. when an app is re-added during hot-reload).
pub fn cancel_removal(app_id: AppId) {
    if let Ok(mut pending) = PENDING_REMOVALS.lock() {
        pending.retain(|&id| id != app_id);
    } else {
        error!("steamui: pending removal lock poisoned");
    }
    if let Ok(mut removed) = REMOVED_APP_IDS.lock() {
        removed.retain(|&id| id != app_id.0);
    } else {
        error!("steamui: removed app set lock poisoned");
    }
}

fn drain_pending_removals(controller: *mut c_void) {
    let src = APP_CHANGE_SOURCE.load(Ordering::Acquire);
    if src == 0 {
        return;
    }

    let draining: Vec<AppId> = {
        let Ok(mut pending) = PENDING_REMOVALS.lock() else {
            error!("steamui: pending removal lock poisoned");
            return;
        };
        let v = std::mem::take(&mut *pending);
        if v.is_empty() {
            HAS_PENDING.store(false, Ordering::Release);
            return;
        }
        v
    };
    HAS_PENDING.store(false, Ordering::Release);

    for app_id in draining {
        do_remove_app(controller, src, app_id);
    }
}

fn do_remove_app(controller: *mut c_void, src: usize, app_id: AppId) {
    // Skip if the app was re-added to config (hot-reload: unload then load).
    let cfg = crate::install::config();
    if cfg.app_category(app_id).is_some() {
        debug!(app = app_id.0, "steamui: app re-owned, skipping removal");
        return;
    }

    // SAFETY: calling through the trampoline with captured this pointers.
    let get_app_by_id = detour_or_return!(
        "CSteamUIAppController::GetAppByID",
        GET_APP_BY_ID_DETOUR,
        ()
    );
    let app_ptr = get_app_by_id.call(controller, app_id.0, false);
    if app_ptr.is_null() {
        return;
    }

    // SAFETY: app_ptr is a CSteamApp* returned by GetAppByID.
    unsafe {
        CSteamApp::set_ownership_flags(app_ptr, EAPP_OWNERSHIP_FLAGS_NONE);

        // Only track in removed set if already uninstalled (matches OST).
        let state = CSteamApp::app_state_flags(app_ptr);
        if state == EAPP_STATE_UNINSTALLED {
            if let Ok(mut removed) = REMOVED_APP_IDS.lock() {
                removed.push(app_id.0);
                HAS_REMOVED.store(true, Ordering::Release);
            } else {
                error!("steamui: removed app set lock poisoned");
            }
        }
    }

    // Notify UI
    // SAFETY: calling through the trampoline.
    let mark_app_change =
        detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR, ());
    mark_app_change.call(src as *mut c_void, app_id.0, EAPPCHANGE_ADDED_OR_CREATED);
    info!(app = app_id.0, "steamui: app removed from library");
}

/// Clear ownership + trigger UI refresh for a removed app.
/// Direct call variant (use queue_removal for cross-thread safety).
pub fn remove_app_and_send_change(app_id: AppId) {
    if !INSTALLED.load(Ordering::Acquire) {
        return;
    }
    let ctrl = CONTROLLER.load(Ordering::Acquire);
    let src = APP_CHANGE_SOURCE.load(Ordering::Acquire);
    if ctrl == 0 || src == 0 {
        debug!(app = app_id.0, "steamui: this pointers not captured yet");
        return;
    }

    // SAFETY: calling through the trampoline with captured this pointers.
    let get_app_by_id = detour_or_return!(
        "CSteamUIAppController::GetAppByID",
        GET_APP_BY_ID_DETOUR,
        ()
    );
    let app_ptr = get_app_by_id.call(ctrl as *mut c_void, app_id.0, false);
    if app_ptr.is_null() {
        return;
    }

    // SAFETY: app_ptr is a CSteamApp* returned by GetAppByID.
    unsafe { CSteamApp::set_ownership_flags(app_ptr, EAPP_OWNERSHIP_FLAGS_NONE) };

    // Notify UI
    // SAFETY: calling through the trampoline.
    let mark_app_change =
        detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR, ());
    mark_app_change.call(src as *mut c_void, app_id.0, EAPPCHANGE_ADDED_OR_CREATED);
    info!(app = app_id.0, "steamui: app removed from library");
}

/// Stamp purchase time on a CSteamApp and refresh the UI.
pub fn stamp_purchase_time(app_id: AppId, time: u32) {
    if !INSTALLED.load(Ordering::Acquire) || time == 0 {
        return;
    }
    let ctrl = CONTROLLER.load(Ordering::Acquire);
    let src = APP_CHANGE_SOURCE.load(Ordering::Acquire);
    if ctrl == 0 || src == 0 {
        return;
    }

    // SAFETY: calling through the trampoline.
    let get_app_by_id = detour_or_return!(
        "CSteamUIAppController::GetAppByID",
        GET_APP_BY_ID_DETOUR,
        ()
    );
    let app_ptr = get_app_by_id.call(ctrl as *mut c_void, app_id.0, false);
    if app_ptr.is_null() {
        return;
    }

    // SAFETY: app_ptr is a CSteamApp* returned by GetAppByID.
    unsafe { CSteamApp::set_purchased_time(app_ptr, time) };

    // Notify UI
    // SAFETY: calling through the trampoline.
    let mark_app_change =
        detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR, ());
    mark_app_change.call(src as *mut c_void, app_id.0, EAPPCHANGE_ADDED_OR_CREATED);
    debug!(app = app_id.0, time, "steamui: purchase time stamped");
}

/// Resolve steamui.so code region from /proc/self/maps.
pub fn get_steamui_code() -> Option<crate::detour::CodeRegion> {
    use steam_runtime_memory::find_proc_self_maps_targets;

    let entries = find_proc_self_maps_targets(64).ok()?;
    let exec_entry = entries
        .iter()
        .find(|e| e.permissions.starts_with("r-xp") && e.path.ends_with("/steamui.so"))?;

    let base = exec_entry.range.base.0;
    let size = exec_entry.range.size;
    // SAFETY: reading the executable mapping of steamui.so.
    let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    Some(crate::detour::CodeRegion { base, bytes })
}
