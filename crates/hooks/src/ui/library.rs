use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tracing::{debug, error, info};
use vapor_forge_config::AppId;
use vapor_forge_steam_native_abi::steamui::{CAppOverviewChange, CSteamApp};

use vapor_forge_hook_engine::original::detour_or_return;

use super::state::{
    RepeatedFieldAddFn, APP_CHANGE_SOURCE, EAPPCHANGE_ADDED_OR_CREATED, EAPP_OWNERSHIP_FLAGS_NONE,
    EAPP_STATE_UNINSTALLED, GET_APP_BY_ID_DETOUR, MARK_APP_CHANGE_DETOUR,
};

// Pending removals queued from the FileWatcher thread, drained on the
// UI thread inside hk_run_frame.
static PENDING_REMOVALS: Mutex<Vec<AppId>> = Mutex::new(Vec::new());

// App metadata changes queued outside the SteamUI thread.
static PENDING_METADATA_REFRESHES: Mutex<Vec<AppId>> = Mutex::new(Vec::new());
const MAX_METADATA_REFRESHES_PER_DRAIN: usize = 64;

// Apps confirmed removed. Appended to CAppOverview_Change.removed_appid
// during full rebuilds to prevent removed apps from reappearing.
static REMOVED_APP_IDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static HAS_REMOVED: AtomicBool = AtomicBool::new(false);

pub(crate) fn append_removed_appids(change: *mut c_void, add_fn: Option<RepeatedFieldAddFn>) {
    if !crate::capability::is_ready(crate::capability::Capability::LibrarySnapshot)
        || change.is_null()
        || !HAS_REMOVED.load(Ordering::Acquire)
    {
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
        /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
        unsafe { add_fn(field, &app_id) };
    }
    debug!(
        count = removed.len(),
        "steamui: BuildComplete appended removed_appid entries"
    );
}

/// Queue an app for removal from the library UI.
///
/// The next UI work drain applies it on Steam's UI thread.
pub fn queue_removal(app_id: AppId) {
    if !crate::capability::is_ready(crate::capability::Capability::LibraryUi) {
        return;
    }
    let Ok(mut pending) = PENDING_REMOVALS.lock() else {
        error!("steamui: pending removal lock poisoned");
        return;
    };
    pending.push(app_id);
    drop(pending);
    vapor_forge_features::toast::request_ui_work();
    debug!(app = app_id.0, "steamui: removal queued");
}

pub(crate) fn queue_metadata_refreshes(app_ids: impl IntoIterator<Item = AppId>) {
    if !crate::capability::is_ready(crate::capability::Capability::LibraryUi) {
        return;
    }
    let Ok(mut pending) = PENDING_METADATA_REFRESHES.lock() else {
        error!("steamui: pending metadata refresh lock poisoned");
        return;
    };
    for app_id in app_ids {
        if !pending.contains(&app_id) {
            pending.push(app_id);
        }
    }
    if pending.is_empty() {
        return;
    }
    drop(pending);
    vapor_forge_features::toast::request_ui_work();
}

pub(crate) fn drain_pending_metadata_refreshes(controller: *mut c_void) {
    if !crate::capability::is_ready(crate::capability::Capability::LibraryUi) {
        return;
    }
    let src = APP_CHANGE_SOURCE.load(Ordering::Acquire);
    if src == 0 {
        return;
    }

    let (draining, has_more): (Vec<AppId>, bool) = {
        let Ok(mut pending) = PENDING_METADATA_REFRESHES.lock() else {
            error!("steamui: pending metadata refresh lock poisoned");
            return;
        };
        let count = pending.len().min(MAX_METADATA_REFRESHES_PER_DRAIN);
        let batch = pending.drain(..count).collect();
        (batch, !pending.is_empty())
    };

    for app_id in draining {
        do_refresh_metadata(controller, src, app_id);
    }
    if has_more {
        vapor_forge_features::toast::request_ui_work();
    }
}

fn do_refresh_metadata(controller: *mut c_void, src: usize, app_id: AppId) {
    let runtime = crate::client::install::runtime_snapshot();
    if !vapor_forge_features::apps::classify_app(&runtime.config, app_id)
        .requires_injected_ownership()
        || runtime.purchase_time(app_id) == 0
    {
        return;
    }
    drop(runtime);

    let get_app_by_id =
        detour_or_return!("CSteamUIAppController::GetAppByID", GET_APP_BY_ID_DETOUR);
    // SAFETY: controller is the live UI receiver and the trampoline preserves Steam's ABI.
    let app_ptr = unsafe { get_app_by_id(controller, app_id.0, false) };
    if app_ptr.is_null() {
        return;
    }
    // SAFETY: app_ptr is a live CSteamApp returned by GetAppByID.
    unsafe { super::install::stamp_purchase_time(app_ptr) };

    let mark_app_change =
        detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR);
    // SAFETY: src is captured from Steam's live update manager callback.
    unsafe { mark_app_change(src as *mut c_void, app_id.0, EAPPCHANGE_ADDED_OR_CREATED) };
}

pub(crate) fn drain_pending_removals(controller: *mut c_void) {
    if !crate::capability::is_ready(crate::capability::Capability::LibraryUi) {
        return;
    }
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
            return;
        }
        v
    };

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
    let app_ptr = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { get_app_by_id(controller, app_id.0, false) };
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
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { mark_app_change(src as *mut c_void, app_id.0, EAPPCHANGE_ADDED_OR_CREATED) };
    info!(app = app_id.0, "steamui: app removed from library");
}
