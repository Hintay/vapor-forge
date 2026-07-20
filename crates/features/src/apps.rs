use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tracing::info;
use vapor_forge_config::{AppCategory, AppId, RuntimeConfig};

static ACTUAL_OWNERSHIP: Mutex<Option<HashMap<AppId, bool>>> = Mutex::new(None);

/// Set to true after Steam has completed its initial license sync (the first
/// `GetSubscribedApps` response). Until then, `on_check_ownership` refuses to
/// spoof so we don't poison `ACTUAL_OWNERSHIP` with a fake positive before
/// Steam has had a chance to report the genuine ownership.
static LICENSE_SYNC_COMPLETE: AtomicBool = AtomicBool::new(false);

pub fn mark_license_sync_complete() {
    LICENSE_SYNC_COMPLETE.store(true, Ordering::Release);
}

pub fn license_sync_complete() -> bool {
    LICENSE_SYNC_COMPLETE.load(Ordering::Acquire)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipState {
    Unknown,
    Unowned,
    Owned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipObservation {
    pub original_result: u32,
    pub package_associations: i32,
    pub family_shared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipDecision {
    pub result: u32,
    pub grant_spoofed_ownership: bool,
    pub clear_family_shared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppAuthority {
    Uncontrolled,
    Controlled {
        category: AppCategory,
        ownership: OwnershipState,
    },
}

impl AppAuthority {
    /// Controlled apps need injected behavior until genuine ownership is confirmed.
    pub fn requires_injected_ownership(self) -> bool {
        matches!(
            self,
            Self::Controlled {
                ownership: OwnershipState::Unknown | OwnershipState::Unowned,
                ..
            }
        )
    }

    /// Some request paths intentionally wait for an explicit unowned sample.
    pub fn is_confirmed_unowned(self) -> bool {
        matches!(
            self,
            Self::Controlled {
                ownership: OwnershipState::Unowned,
                ..
            }
        )
    }
}

/// Return the genuine ownership result captured before pkg0 could affect it.
pub fn actual_ownership(app_id: AppId) -> OwnershipState {
    match ACTUAL_OWNERSHIP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|ownership| ownership.get(&app_id).copied())
    {
        Some(true) => OwnershipState::Owned,
        Some(false) => OwnershipState::Unowned,
        None => OwnershipState::Unknown,
    }
}

pub fn classify_app(config: &RuntimeConfig, app_id: AppId) -> AppAuthority {
    classify_app_with_ownership(config, app_id, actual_ownership)
}

/// Classify an app using an explicit ownership source.
///
/// The resolver is only queried for controlled apps. This keeps protocol
/// decisions pure and lets diagnostics report missing runtime state instead of
/// silently treating it as a particular ownership result.
pub fn classify_app_with_ownership(
    config: &RuntimeConfig,
    app_id: AppId,
    ownership: impl FnOnce(AppId) -> OwnershipState,
) -> AppAuthority {
    match config.app_category(app_id) {
        Some(category) => AppAuthority::Controlled {
            category,
            ownership: ownership(app_id),
        },
        None => AppAuthority::Uncontrolled,
    }
}

/// Interpret a result returned by Steam's original ownership path.
///
/// A non-zero return alone is insufficient after package injection. Genuine
/// ownership also has more than the injected package association.
pub fn original_result_is_genuinely_owned(observation: OwnershipObservation) -> bool {
    observation.original_result != 0 && observation.package_associations > 1
}

/// Record an ownership result obtained before the app is added to pkg0.
pub fn record_actual_ownership(app_id: AppId, owned: bool) {
    ACTUAL_OWNERSHIP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(app_id, owned);
}

pub fn decide_check_ownership(
    config: &RuntimeConfig,
    app_id: AppId,
    observation: OwnershipObservation,
) -> OwnershipDecision {
    if config.is_controlled_app(app_id) && observation.original_result == 0 {
        // Don't grant spoofed ownership until Steam has finished its initial
        // license sync — otherwise a DRM racing us to `CheckAppOwnership`
        // during startup latches a fake positive into `ACTUAL_OWNERSHIP`
        // before Steam has said anything, and later real ownership can't
        // demote it back.
        if !license_sync_complete() {
            info!(
                app_id = app_id.0,
                "feat: ownership spoof deferred (license sync pending)"
            );
            return OwnershipDecision {
                result: observation.original_result,
                grant_spoofed_ownership: false,
                clear_family_shared: false,
            };
        }
        info!(app_id = app_id.0, "feat: ownership granted");
        return OwnershipDecision {
            result: 1,
            grant_spoofed_ownership: true,
            clear_family_shared: false,
        };
    }

    let clear_family_shared = config.should_bypass_sharing(app_id)
        && observation.original_result != 0
        && observation.family_shared;
    if clear_family_shared {
        info!(app_id = app_id.0, "feat: sharing unlocked");
    }

    OwnershipDecision {
        result: observation.original_result,
        grant_spoofed_ownership: false,
        clear_family_shared,
    }
}

pub fn on_get_subscribed_apps(
    config: &RuntimeConfig,
    app_list: &mut [u32],
    original_count: u32,
) -> u32 {
    // The first successful call latches Steam's license sync as complete so
    // deferred ownership spoofing can start.
    mark_license_sync_complete();

    let inject_ids: Vec<AppId> = config.apps.inject.iter().map(|a| a.id).collect();
    if inject_ids.is_empty() {
        return original_count;
    }

    let mut count = original_count as usize;
    for &app_id in &inject_ids {
        if app_list[..count].contains(&app_id.0) {
            continue;
        }
        if count < app_list.len() {
            app_list[count] = app_id.0;
            count += 1;
        }
    }
    count as u32
}

pub fn get_subscribed_count_adjustment(config: &RuntimeConfig) -> u32 {
    config.apps.inject.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use vapor_forge_config::InjectApp;

    fn config_with_inject(ids: &[u32]) -> RuntimeConfig {
        RuntimeConfig {
            apps: vapor_forge_config::AppsSection {
                inject: ids
                    .iter()
                    .map(|&id| InjectApp {
                        id: AppId(id),
                        dlc: Vec::new(),
                        ticket: Default::default(),
                        purchase_time: 0,
                    })
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn observation(original_result: u32) -> OwnershipObservation {
        OwnershipObservation {
            original_result,
            package_associations: 0,
            family_shared: false,
        }
    }

    // `LICENSE_SYNC_COMPLETE` is process-global; tests that touch it must
    // serialize through this guard so they don't observe each other's mutations.
    static SYNC_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn inject_sets_ownership_when_original_is_zero() {
        let _guard = SYNC_TEST_LOCK.lock().unwrap();
        mark_license_sync_complete();
        let config = config_with_inject(&[480]);
        let decision = decide_check_ownership(&config, AppId(480), observation(0));
        assert_eq!(decision.result, 1);
        assert!(decision.grant_spoofed_ownership);
        assert!(!decision.clear_family_shared);
    }

    #[test]
    fn spoof_deferred_until_license_sync_completes() {
        let _guard = SYNC_TEST_LOCK.lock().unwrap();
        LICENSE_SYNC_COMPLETE.store(false, Ordering::Release);
        let config = config_with_inject(&[912_345]);
        let decision = decide_check_ownership(&config, AppId(912_345), observation(0));
        // No spoof while license sync is pending.
        assert_eq!(decision.result, 0);
        assert!(!decision.grant_spoofed_ownership);

        // Simulate Steam returning the first subscribed-apps list.
        let mut list = [0u32; 4];
        on_get_subscribed_apps(&config, &mut list, 0);
        assert!(license_sync_complete());

        assert!(
            decide_check_ownership(&config, AppId(912_345), observation(0)).grant_spoofed_ownership
        );
    }

    #[test]
    fn no_inject_when_already_owned() {
        let config = config_with_inject(&[480]);
        let decision = decide_check_ownership(&config, AppId(480), observation(1));
        assert_eq!(decision.result, 1);
        assert!(!decision.grant_spoofed_ownership);
    }

    #[test]
    fn spoofed_followup_result_does_not_poison_actual_ownership() {
        let app_id = AppId(246_813_581);
        let config = config_with_inject(&[app_id.0]);
        record_actual_ownership(app_id, false);

        assert_eq!(
            decide_check_ownership(&config, app_id, observation(1)).result,
            1
        );
        assert_eq!(actual_ownership(app_id), OwnershipState::Unowned);
        assert!(classify_app(&config, app_id).requires_injected_ownership());

        record_actual_ownership(app_id, true);
        assert_eq!(actual_ownership(app_id), OwnershipState::Owned);
        assert!(!classify_app(&config, app_id).requires_injected_ownership());
    }

    #[test]
    fn package_association_alone_is_not_genuine_ownership() {
        let mut observed = observation(1);
        observed.package_associations = 1;
        assert!(!original_result_is_genuinely_owned(observed));

        observed.package_associations = 2;
        assert!(original_result_is_genuinely_owned(observed));
        observed.original_result = 0;
        assert!(!original_result_is_genuinely_owned(observed));
    }

    #[test]
    fn app_authority_preserves_unknown_ownership() {
        let app_id = AppId(246_813_582);
        let config = config_with_inject(&[app_id.0]);

        assert_eq!(actual_ownership(app_id), OwnershipState::Unknown);
        assert_eq!(
            classify_app(&config, app_id),
            AppAuthority::Controlled {
                category: AppCategory::Inject,
                ownership: OwnershipState::Unknown,
            }
        );
        assert!(classify_app(&config, app_id).requires_injected_ownership());
        assert!(!classify_app(&config, app_id).is_confirmed_unowned());
    }

    #[test]
    fn non_controlled_app_passes_through() {
        let config = config_with_inject(&[480]);
        let decision = decide_check_ownership(&config, AppId(999), observation(0));
        assert_eq!(decision.result, 0);
        assert!(!decision.grant_spoofed_ownership);
    }

    #[test]
    fn sharing_bypass_clears_family_shared() {
        let config = RuntimeConfig::default(); // shared.enabled = true by default
        let mut observed = observation(1);
        observed.family_shared = true;
        let decision = decide_check_ownership(&config, AppId(570), observed);
        assert_eq!(decision.result, 1);
        assert!(decision.clear_family_shared);
    }

    #[test]
    fn sharing_bypass_noop_when_not_shared() {
        let config = RuntimeConfig::default();
        let decision = decide_check_ownership(&config, AppId(570), observation(1));
        assert_eq!(decision.result, 1);
        assert!(!decision.clear_family_shared);
    }

    #[test]
    fn subscribed_apps_appends_inject_ids() {
        let config = config_with_inject(&[480, 730]);
        let mut buf = [0u32; 10];
        buf[0] = 100;
        let count = on_get_subscribed_apps(&config, &mut buf, 1);
        assert_eq!(count, 3);
        assert_eq!(buf[1], 480);
        assert_eq!(buf[2], 730);
    }

    #[test]
    fn subscribed_apps_stops_at_buffer_limit() {
        let config = config_with_inject(&[480, 730, 440]);
        let mut buf = [0u32; 2];
        let count = on_get_subscribed_apps(&config, &mut buf, 1);
        assert_eq!(count, 2);
        assert_eq!(buf[1], 480);
    }
}
