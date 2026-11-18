use core::ffi::c_void;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use tracing::{debug, error, info};
use vapor_forge_config::AppId;
use vapor_forge_steam_native_abi::steamui::{CAppOverviewChange, CSteamApp};

use vapor_forge_hook_engine::original::detour_or_return;

use super::state::{
    RepeatedFieldAddFn, RepeatedFieldReserveFn, APP_CHANGE_SOURCE, EAPPCHANGE_ADDED_OR_CREATED,
    EAPP_OWNERSHIP_FLAGS_NONE, EAPP_STATE_UNINSTALLED, GET_APP_BY_ID_DETOUR,
    MARK_APP_CHANGE_DETOUR,
};

struct Removals {
    generation: u64,
    pending: Vec<AppId>,
    removed: Vec<u32>,
}

impl Removals {
    fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.pending.clear();
        self.removed.clear();
    }

    fn apply(
        &mut self,
        generation: u64,
        app_id: AppId,
        clear_ownership: impl FnOnce() -> bool,
    ) -> bool {
        if self.generation != generation {
            return false;
        }
        if clear_ownership() {
            self.removed.push(app_id.0);
        }
        true
    }
}

static REMOVALS: Mutex<Removals> = Mutex::new(Removals {
    generation: 0,
    pending: Vec::new(),
    removed: Vec::new(),
});

// App metadata changes queued outside the SteamUI thread.
static PENDING_METADATA_REFRESHES: Mutex<Vec<AppId>> = Mutex::new(Vec::new());
const MAX_METADATA_REFRESHES_PER_DRAIN: usize = 64;

pub(crate) fn append_removed_appids(
    change: *mut c_void,
    add_fn: Option<RepeatedFieldAddFn>,
    reserve_fn: Option<RepeatedFieldReserveFn>,
) {
    if !crate::capability::is_ready(crate::capability::Capability::LibrarySnapshot)
        || change.is_null()
    {
        return;
    }
    let Ok(state) = REMOVALS.lock() else {
        error!("steamui: removal state lock poisoned");
        return;
    };
    let removed = &state.removed;
    if removed.is_empty() {
        return;
    }
    let Some(add_fn) = add_fn else {
        error!("steamui: RepeatedField<uint32>::Add unavailable");
        return;
    };

    // Append removed app IDs to CAppOverview_Change.removed_appid so
    // full rebuilds don't restore apps we've hidden.
    // SAFETY: change is a valid CAppOverview_Change* from SteamUI.
    let field = unsafe { CAppOverviewChange::mutable_removed_appid(change) };
    let Some(reserve_fn) = reserve_fn else {
        error!("steamui: RepeatedField<uint32>::Reserve unavailable");
        return;
    };
    // The x86_64 Add only appends into reserved capacity, so the capacity
    // for every removed ID is reserved first.
    // SAFETY: the field's first member is its current size.
    let size = unsafe { field.cast::<i32>().read() };
    let Some(needed) = i32::try_from(removed.len())
        .ok()
        .and_then(|count| size.checked_add(count))
    else {
        return;
    };
    // SAFETY: Steam's RepeatedField<uint32> and its matching Reserve.
    unsafe { reserve_fn(field, needed) };
    for &app_id in removed.iter() {
        /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
        unsafe { add_fn(field, &app_id) };
    }
    debug!(
        count = removed.len(),
        "steamui: BuildComplete appended removed_appid entries"
    );
}

/// Forget every removal; the hidden apps belonged to the previous account.
pub(crate) fn reset_account_state() {
    if let Ok(mut state) = REMOVALS.lock() {
        state.reset();
    }
}

/// Stop hiding an app that is controlled again.
pub fn forget_removal(app_id: AppId) {
    if let Ok(mut state) = REMOVALS.lock() {
        state.pending.retain(|&pending| pending != app_id);
        state.removed.retain(|&removed| removed != app_id.0);
    }
}

/// Queue an app for removal from the library UI.
///
/// The next UI work drain applies it on Steam's UI thread.
pub fn queue_removal(app_id: AppId) {
    if !crate::capability::is_ready(crate::capability::Capability::LibraryUi) {
        return;
    }
    let Ok(mut state) = REMOVALS.lock() else {
        error!("steamui: pending removal lock poisoned");
        return;
    };
    state.pending.push(app_id);
    drop(state);
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

    let (generation, draining) = {
        let Ok(mut state) = REMOVALS.lock() else {
            error!("steamui: pending removal lock poisoned");
            return;
        };
        let v = std::mem::take(&mut state.pending);
        if v.is_empty() {
            return;
        }
        (state.generation, v)
    };

    for app_id in draining {
        do_remove_app(controller, src, app_id, generation);
    }
}

fn do_remove_app(controller: *mut c_void, src: usize, app_id: AppId, generation: u64) {
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

    {
        let Ok(mut state) = REMOVALS.lock() else {
            error!("steamui: removal state lock poisoned");
            return;
        };
        if !state.apply(generation, app_id, || {
            // SAFETY: GetAppByID returned the live UI-thread app.
            unsafe {
                let app = app_ptr.cast::<CSteamApp>();
                (*app).ownership_flags = EAPP_OWNERSHIP_FLAGS_NONE;
                (*app).app_state_flags == EAPP_STATE_UNINSTALLED
            }
        }) {
            return;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_invalidates_a_drained_removal_before_touching_the_app() {
        let mut state = Removals {
            generation: 0,
            pending: Vec::new(),
            removed: Vec::new(),
        };
        state.pending.push(AppId(42));
        let generation = state.generation;
        let app = state.pending.pop().unwrap();
        state.reset();
        assert!(!state.apply(generation, app, || panic!("stale app write")));
        assert!(state.removed.is_empty());
        assert!(state.apply(state.generation, app, || true));
        assert_eq!(state.removed, [42]);
    }
}
