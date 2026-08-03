use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tracing::debug;
use vapor_forge_config::{AppId, RuntimeConfig};

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

    pub fn reset_account_state(&self) {
        self.active.store(false, Ordering::Release);
        self.injected_apps.lock().unwrap().clear();
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

    /// Returns whether this AppId has actually been written into pkg0.
    ///
    /// This is runtime diagnostics state, not an ownership or network-policy
    /// signal. `RuntimeConfig::is_controlled_app` is authoritative for policy.
    pub fn is_injected_into_pkg0(&self, app_id: AppId) -> bool {
        self.injected_apps.lock().unwrap().contains(&app_id)
    }

    pub fn injected_count(&self) -> usize {
        self.injected_apps.lock().unwrap().len()
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
pub fn controlled_app_ids(config: &RuntimeConfig, script_apps: &HashSet<AppId>) -> Vec<AppId> {
    let mut seen: HashSet<AppId> = HashSet::new();
    let mut ids: Vec<AppId> = Vec::new();
    for app in &config.apps.inject {
        if seen.insert(app.id) {
            ids.push(app.id);
        }
        for &dlc in &app.dlc {
            if seen.insert(dlc) {
                ids.push(dlc);
            }
        }
    }
    for &id in script_apps {
        if seen.insert(id) {
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
            .map(|&id| vapor_forge_config::InjectApp {
                id: AppId(id),
                dlc: Vec::new(),
                ticket: Default::default(),
                purchase_time: 0,
            })
            .collect();
        RuntimeConfig {
            apps: vapor_forge_config::AppsSection {
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
    fn reports_actual_pkg0_injection_state() {
        let state = PackageState::new();
        assert!(!state.is_injected_into_pkg0(AppId(100)));
        state.record_injected(&[AppId(100)]);
        assert!(state.is_injected_into_pkg0(AppId(100)));
        assert!(!state.is_injected_into_pkg0(AppId(200)));
    }

    #[test]
    fn account_reset_clears_runtime_package_state() {
        let state = PackageState::new();
        state.set_active();
        state.record_injected(&[AppId(100), AppId(200)]);

        state.reset_account_state();

        assert!(!state.is_active());
        assert_eq!(state.injected_count(), 0);
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
        let script_apps: HashSet<AppId> = [AppId(200), AppId(300)].into_iter().collect();
        let ids = controlled_app_ids(&config, &script_apps);
        // Config-order entries come first, then any script-only extras. Script
        // apps that duplicate config entries are dropped.
        assert_eq!(&ids[..2], &[AppId(100), AppId(200)]);
        assert!(ids.contains(&AppId(300)));
        assert_eq!(ids.len(), 3);
    }
}
