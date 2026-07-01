use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use steam_runtime_config::{AppId, RuntimeConfig};
use tracing::debug;

/// Safe business logic for pkg0 injection.
///
/// This module does NOT touch Steam memory. It produces "what to do"
/// decisions that the unsafe hooks layer executes.
pub struct PackageState {
    active: AtomicBool,
    /// Track what we've injected so hot-reload can diff.
    injected_apps: Mutex<HashSet<AppId>>,
}

/// What to inject on first pkg0 capture.
pub struct InjectionPlan {
    pub app_ids: Vec<AppId>,
}

/// What changed on hot-reload (config or Lua scripts changed).
pub struct ReloadDiff {
    pub additions: Vec<AppId>,
    pub removals: Vec<AppId>,
}

impl PackageState {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            injected_apps: Mutex::new(HashSet::new()),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub fn set_active(&self) {
        self.active.store(true, Ordering::Release);
    }

    /// Compute what app IDs to inject into pkg0 on first capture.
    ///
    /// `controlled_ids` = union of config inject IDs + script addappid IDs.
    pub fn compute_injection(&self, controlled_ids: &[AppId]) -> InjectionPlan {
        let ids: Vec<AppId> = controlled_ids.to_vec();
        debug!(count = ids.len(), "package: injection plan computed");
        InjectionPlan { app_ids: ids }
    }

    /// Record what we injected so hot-reload can diff later.
    pub fn record_injected(&self, ids: &[AppId]) {
        let mut guard = self.injected_apps.lock().unwrap();
        guard.extend(ids.iter().copied());
    }

    /// Compute the diff between current controlled set and what was previously injected.
    ///
    /// `controlled_ids` = union of config inject IDs + script addappid IDs.
    pub fn compute_hot_reload_diff(&self, controlled_ids: &[AppId]) -> ReloadDiff {
        let new_set: HashSet<AppId> = controlled_ids.iter().copied().collect();
        let guard = self.injected_apps.lock().unwrap();

        let additions: Vec<AppId> = new_set.difference(&guard).copied().collect();
        let removals: Vec<AppId> = guard.difference(&new_set).copied().collect();

        debug!(
            additions = additions.len(),
            removals = removals.len(),
            "package: reload diff computed"
        );

        ReloadDiff {
            additions,
            removals,
        }
    }

    /// Update the injected set after a hot-reload diff is applied.
    pub fn apply_diff(&self, diff: &ReloadDiff) {
        let mut guard = self.injected_apps.lock().unwrap();
        for &id in &diff.removals {
            guard.remove(&id);
        }
        for &id in &diff.additions {
            guard.insert(id);
        }
    }
}

impl Default for PackageState {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the combined controlled-app-IDs list from config + script state.
/// Includes both main app IDs and their DLC IDs (DLC goes into pkg0 so
/// Steam downloads appinfo and handles DLC enumeration natively).
pub fn controlled_app_ids(config: &RuntimeConfig, script_apps: &[AppId]) -> Vec<AppId> {
    let mut ids: Vec<AppId> = Vec::new();
    for app in &config.apps.inject {
        if !ids.contains(&app.id) {
            ids.push(app.id);
        }
        for &dlc in &app.dlc {
            if !ids.contains(&dlc) {
                ids.push(dlc);
            }
        }
    }
    for &id in script_apps {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(ids: &[u32]) -> RuntimeConfig {
        let inject = ids
            .iter()
            .map(|&id| steam_runtime_config::InjectApp {
                id: AppId(id),
                dlc: Vec::new(),
                ticket: Default::default(), purchase_time: 0,
            })
            .collect();
        RuntimeConfig {
            apps: steam_runtime_config::AppsSection {
                inject,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn diff_additions_only() {
        let state = PackageState::new();
        state.record_injected(&[AppId(100), AppId(200)]);
        let diff = state.compute_hot_reload_diff(&[AppId(100), AppId(200), AppId(300)]);
        assert_eq!(diff.additions, vec![AppId(300)]);
        assert!(diff.removals.is_empty());
    }

    #[test]
    fn diff_removals_only() {
        let state = PackageState::new();
        state.record_injected(&[AppId(100), AppId(200), AppId(300)]);
        let diff = state.compute_hot_reload_diff(&[AppId(100)]);
        assert!(diff.additions.is_empty());
        assert!(diff.removals.contains(&AppId(200)));
        assert!(diff.removals.contains(&AppId(300)));
    }

    #[test]
    fn diff_additions_and_removals() {
        let state = PackageState::new();
        state.record_injected(&[AppId(100), AppId(200)]);
        let diff = state.compute_hot_reload_diff(&[AppId(200), AppId(300)]);
        assert_eq!(diff.additions, vec![AppId(300)]);
        assert_eq!(diff.removals, vec![AppId(100)]);
    }

    #[test]
    fn diff_no_change() {
        let state = PackageState::new();
        state.record_injected(&[AppId(100), AppId(200)]);
        let diff = state.compute_hot_reload_diff(&[AppId(100), AppId(200)]);
        assert!(diff.additions.is_empty());
        assert!(diff.removals.is_empty());
    }

    #[test]
    fn apply_diff_updates_state() {
        let state = PackageState::new();
        state.record_injected(&[AppId(100), AppId(200)]);

        let diff = ReloadDiff {
            additions: vec![AppId(300)],
            removals: vec![AppId(100)],
        };
        state.apply_diff(&diff);

        let diff2 = state.compute_hot_reload_diff(&[AppId(200), AppId(300)]);
        assert!(diff2.additions.is_empty());
        assert!(diff2.removals.is_empty());
    }

    #[test]
    fn controlled_app_ids_dedup_script_apps() {
        let config = make_config(&[100, 200]);
        let ids = controlled_app_ids(&config, &[AppId(200), AppId(300)]);
        assert_eq!(ids, vec![AppId(100), AppId(200), AppId(300)]);
    }
}
