use std::collections::HashMap;
use std::sync::Mutex;

use tracing::{debug, info};
use vapor_forge_config::{AppCategory, AppId, RuntimeConfig};

struct AccountState {
    actual_ownership: Option<HashMap<AppId, bool>>,
    license_sync_complete: bool,
}

impl AccountState {
    const fn new() -> Self {
        Self {
            actual_ownership: None,
            license_sync_complete: false,
        }
    }

    fn reset(&mut self) {
        self.actual_ownership = None;
        self.license_sync_complete = false;
    }
}

static ACCOUNT_STATE: Mutex<AccountState> = Mutex::new(AccountState::new());

pub fn mark_license_sync_complete() {
    ACCOUNT_STATE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .license_sync_complete = true;
}

pub fn license_sync_complete() -> bool {
    ACCOUNT_STATE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .license_sync_complete
}

/// Discard state learned from the previous Steam account.
///
/// Ownership and license synchronization are account-scoped even though this
/// crate lives for the lifetime of the Steam process.
pub fn reset_account_state() {
    ACCOUNT_STATE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .reset();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipState {
    Unknown,
    Unowned,
    Owned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipObservation {
    pub original_result: bool,
    pub owns_license: bool,
    pub family_shared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipDecision {
    pub result: bool,
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

    /// Injected top-level apps need the library visibility exception until
    /// genuine ownership is confirmed. DLC keeps Steam's native filtering.
    pub fn requires_injected_library_visibility(self) -> bool {
        matches!(
            self,
            Self::Controlled {
                category: AppCategory::Inject,
                ownership: OwnershipState::Unknown | OwnershipState::Unowned,
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
    match ACCOUNT_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .actual_ownership
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
/// A successful lookup alone is insufficient because pkg0 also produces a
/// successful result. Steam's license bit distinguishes a real entitlement.
pub fn original_result_is_genuinely_owned(observation: OwnershipObservation) -> bool {
    observation.original_result && observation.owns_license
}

/// Record an ownership result obtained before the app is added to pkg0.
pub fn record_actual_ownership(app_id: AppId, owned: bool) {
    ACCOUNT_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .actual_ownership
        .get_or_insert_with(HashMap::new)
        .insert(app_id, owned);
}

pub fn decide_check_ownership(
    config: &RuntimeConfig,
    app_id: AppId,
    observation: OwnershipObservation,
) -> OwnershipDecision {
    if config.is_controlled_app(app_id)
        && (!observation.original_result || !observation.owns_license)
    {
        // Don't grant spoofed ownership until Steam has finished its initial
        // license sync — otherwise a DRM racing us to `CheckAppOwnership`
        // during startup latches a fake positive into the ownership cache
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
        debug!(app_id = app_id.0, "feat: ownership granted");
        return OwnershipDecision {
            result: true,
            grant_spoofed_ownership: true,
            clear_family_shared: false,
        };
    }

    let clear_family_shared = config.should_bypass_sharing(app_id)
        && observation.original_result
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

    let inject_ids: Vec<AppId> = config.apps.inject().iter().map(|a| a.id).collect();
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
    config.apps.inject().len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use vapor_forge_config::InjectApp;

    fn config_with_inject(ids: &[u32]) -> RuntimeConfig {
        RuntimeConfig {
            apps: vapor_forge_config::AppsSection::with_inject(
                ids.iter()
                    .map(|&id| InjectApp {
                        id: AppId(id),
                        dlc: Vec::new(),
                        ticket: Default::default(),
                        purchase_time: 0,
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    fn observation(original_result: bool) -> OwnershipObservation {
        OwnershipObservation {
            original_result,
            owns_license: original_result,
            family_shared: false,
        }
    }

    // The license-sync latch is process-global; tests that touch it must
    // serialize through this guard so they don't observe each other's mutations.
    static SYNC_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn inject_sets_ownership_when_original_is_zero() {
        let _guard = SYNC_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        mark_license_sync_complete();
        let config = config_with_inject(&[480]);
        let decision = decide_check_ownership(&config, AppId(480), observation(false));
        assert!(decision.result);
        assert!(decision.grant_spoofed_ownership);
        assert!(!decision.clear_family_shared);
    }

    #[test]
    fn spoof_deferred_until_license_sync_completes() {
        let _guard = SYNC_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        ACCOUNT_STATE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .license_sync_complete = false;
        let config = config_with_inject(&[912_345]);
        let decision = decide_check_ownership(&config, AppId(912_345), observation(false));
        // No spoof while license sync is pending.
        assert!(!decision.result);
        assert!(!decision.grant_spoofed_ownership);

        // Simulate Steam returning the first subscribed-apps list.
        let mut list = [0u32; 4];
        on_get_subscribed_apps(&config, &mut list, 0);
        assert!(license_sync_complete());

        assert!(
            decide_check_ownership(&config, AppId(912_345), observation(false))
                .grant_spoofed_ownership
        );
    }

    #[test]
    fn no_inject_when_already_owned() {
        let config = config_with_inject(&[480]);
        let decision = decide_check_ownership(&config, AppId(480), observation(true));
        assert!(decision.result);
        assert!(!decision.grant_spoofed_ownership);
    }

    #[test]
    fn pkg0_result_without_license_is_normalized() {
        let _guard = SYNC_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        mark_license_sync_complete();
        let config = config_with_inject(&[480]);
        let mut observed = observation(true);
        observed.owns_license = false;

        let decision = decide_check_ownership(&config, AppId(480), observed);

        assert!(decision.result);
        assert!(decision.grant_spoofed_ownership);
    }

    #[test]
    fn spoofed_followup_result_does_not_poison_actual_ownership() {
        let app_id = AppId(246_813_581);
        let config = config_with_inject(&[app_id.0]);
        record_actual_ownership(app_id, false);

        assert!(decide_check_ownership(&config, app_id, observation(true)).result);
        assert_eq!(actual_ownership(app_id), OwnershipState::Unowned);
        assert!(classify_app(&config, app_id).requires_injected_ownership());

        record_actual_ownership(app_id, true);
        assert_eq!(actual_ownership(app_id), OwnershipState::Owned);
        assert!(!classify_app(&config, app_id).requires_injected_ownership());
    }

    #[test]
    fn successful_lookup_without_license_is_not_genuine_ownership() {
        let mut observed = observation(true);
        observed.owns_license = false;
        assert!(!original_result_is_genuinely_owned(observed));

        observed.owns_license = true;
        assert!(original_result_is_genuinely_owned(observed));
        observed.original_result = false;
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
        assert!(classify_app(&config, app_id).requires_injected_library_visibility());
        assert!(!classify_app(&config, app_id).is_confirmed_unowned());
    }

    #[test]
    fn dlc_does_not_receive_library_visibility_exception() {
        let app_id = AppId(246_813_585);
        let dlc_id = AppId(246_813_586);
        let config = RuntimeConfig {
            apps: vapor_forge_config::AppsSection::with_inject(vec![InjectApp {
                id: app_id,
                dlc: vec![dlc_id],
                ticket: Default::default(),
                purchase_time: 0,
            }]),
            ..Default::default()
        };

        assert!(classify_app(&config, app_id).requires_injected_library_visibility());
        assert!(!classify_app(&config, dlc_id).requires_injected_library_visibility());
    }

    #[test]
    fn account_reset_clears_ownership_and_license_latch() {
        let app_id = AppId(246_813_584);
        let mut state = AccountState::new();

        state
            .actual_ownership
            .get_or_insert_with(HashMap::new)
            .insert(app_id, true);
        state.license_sync_complete = true;

        state.reset();

        assert!(state.actual_ownership.is_none());
        assert!(!state.license_sync_complete);
    }

    #[test]
    fn non_controlled_app_passes_through() {
        let config = config_with_inject(&[480]);
        let decision = decide_check_ownership(&config, AppId(999), observation(false));
        assert!(!decision.result);
        assert!(!decision.grant_spoofed_ownership);
    }

    #[test]
    fn sharing_bypass_clears_family_shared() {
        let config = RuntimeConfig::default(); // shared.enabled = true by default
        let mut observed = observation(true);
        observed.family_shared = true;
        let decision = decide_check_ownership(&config, AppId(570), observed);
        assert!(decision.result);
        assert!(decision.clear_family_shared);
    }

    #[test]
    fn sharing_bypass_noop_when_not_shared() {
        let config = RuntimeConfig::default();
        let decision = decide_check_ownership(&config, AppId(570), observation(true));
        assert!(decision.result);
        assert!(!decision.clear_family_shared);
    }

    #[test]
    fn subscribed_apps_appends_inject_ids() {
        let _guard = SYNC_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
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
        let _guard = SYNC_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let config = config_with_inject(&[480, 730, 440]);
        let mut buf = [0u32; 2];
        let count = on_get_subscribed_apps(&config, &mut buf, 1);
        assert_eq!(count, 2);
        assert_eq!(buf[1], 480);
    }
}
