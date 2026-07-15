use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tracing::{debug, error, info};
use vapor_forge_abi::steamui::{CAppOverviewChange, CSteamApp};
use vapor_forge_config::AppId;

use crate::original::detour_or_return;

use super::state::{
    RepeatedFieldAddFn, APP_CHANGE_SOURCE, CONTROLLER, EAPPCHANGE_ADDED_OR_CREATED,
    EAPP_OWNERSHIP_FLAGS_NONE, EAPP_STATE_UNINSTALLED, GET_APP_BY_ID_DETOUR, INSTALLED,
    MARK_APP_CHANGE_DETOUR,
};

// Pending removals queued from the FileWatcher thread, drained on the
// UI thread inside hk_run_frame.
static PENDING_REMOVALS: Mutex<Vec<AppId>> = Mutex::new(Vec::new());
pub(crate) static HAS_PENDING: AtomicBool = AtomicBool::new(false);

// Apps confirmed removed. Appended to CAppOverview_Change.removed_appid
// during full rebuilds to prevent removed apps from reappearing.
static REMOVED_APP_IDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static HAS_REMOVED: AtomicBool = AtomicBool::new(false);

pub(crate) fn append_removed_appids(change: *mut c_void, add_fn: Option<RepeatedFieldAddFn>) {
    if change.is_null() || !HAS_REMOVED.load(Ordering::Acquire) {
        return;
    }
    let Some(add_fn) = add_fn else {
        error!("steamui: RepeatedField<uint32>::Add unavailable");
        return;
    };
    let Ok(removed) = REMOVED_APP_IDS.lock() else {
        error!("steamui: removed app set lock poisoned");
        return;
    };
    if removed.is_empty() {
        return;
    }

    // Append removed app IDs to CAppOverview_Change.removed_appid so
    // full rebuilds don't restore apps we've hidden.
    // SAFETY: change is a valid CAppOverview_Change* from SteamUI.
    let field = unsafe { CAppOverviewChange::mutable_removed_appid(change) };
    for &app_id in removed.iter() {
        add_fn(field, &app_id);
    }
    debug!(
        count = removed.len(),
        "steamui: BuildComplete appended removed_appid entries"
    );
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

pub(crate) fn drain_pending_removals(controller: *mut c_void) {
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
    let cfg = crate::client::install::config();
    if cfg.is_controlled_app(app_id) {
        debug!(app = app_id.0, "steamui: app re-owned, skipping removal");
        return;
    }

    // SAFETY: calling through the trampoline with captured this pointers.
    let get_app_by_id =
        detour_or_return!("CSteamUIAppController::GetAppByID", GET_APP_BY_ID_DETOUR);
    let app_ptr = get_app_by_id.call(controller, app_id.0, false);
    if app_ptr.is_null() {
        return;
    }

    // SAFETY: app_ptr is a CSteamApp* returned by GetAppByID.
    unsafe {
        let app = app_ptr.cast::<CSteamApp>();
        (*app).ownership_flags = EAPP_OWNERSHIP_FLAGS_NONE;

        // Only track in removed set if already uninstalled.
        let state = (*app).app_state_flags;
        if state == EAPP_STATE_UNINSTALLED {
            if let Ok(mut removed) = REMOVED_APP_IDS.lock() {
                removed.push(app_id.0);
                HAS_REMOVED.store(true, Ordering::Release);
            } else {
                error!("steamui: removed app set lock poisoned");
            }
        }
    }

    // Notify UI.
    // SAFETY: calling through the trampoline.
    let mark_app_change =
        detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR);
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
    let get_app_by_id =
        detour_or_return!("CSteamUIAppController::GetAppByID", GET_APP_BY_ID_DETOUR);
    let app_ptr = get_app_by_id.call(ctrl as *mut c_void, app_id.0, false);
    if app_ptr.is_null() {
        return;
    }

    // SAFETY: app_ptr is a CSteamApp* returned by GetAppByID.
    unsafe {
        (*app_ptr.cast::<CSteamApp>()).ownership_flags = EAPP_OWNERSHIP_FLAGS_NONE;
    }

    // Notify UI.
    // SAFETY: calling through the trampoline.
    let mark_app_change =
        detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR);
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
    let get_app_by_id =
        detour_or_return!("CSteamUIAppController::GetAppByID", GET_APP_BY_ID_DETOUR);
    let app_ptr = get_app_by_id.call(ctrl as *mut c_void, app_id.0, false);
    if app_ptr.is_null() {
        return;
    }

    // SAFETY: app_ptr is a CSteamApp* returned by GetAppByID.
    unsafe {
        (*app_ptr.cast::<CSteamApp>()).purchased_time = time;
    }

    // Notify UI.
    // SAFETY: calling through the trampoline.
    let mark_app_change =
        detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR);
    mark_app_change.call(src as *mut c_void, app_id.0, EAPPCHANGE_ADDED_OR_CREATED);
    debug!(app = app_id.0, time, "steamui: purchase time stamped");
}
