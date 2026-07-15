use std::collections::HashMap;
use std::sync::Mutex;

use tracing::info;
use vapor_forge_abi::CAppOwnershipInfo;
use vapor_forge_config::{AppCategory, AppId, RuntimeConfig};

static ACTUAL_OWNERSHIP: Mutex<Option<HashMap<AppId, bool>>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipState {
    Unknown,
    Unowned,
    Owned,
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
    match config.app_category(app_id) {
        Some(category) => AppAuthority::Controlled {
            category,
            ownership: actual_ownership(app_id),
        },
        None => AppAuthority::Uncontrolled,
    }
}

/// Interpret a result returned by Steam's original ownership path.
///
/// A non-zero return alone is insufficient after package injection. Genuine
/// ownership also has more than the injected package association.
pub fn original_result_is_genuinely_owned(original_result: u32, info: &CAppOwnershipInfo) -> bool {
    original_result != 0 && info.exist_in_package_nums > 1
}

/// Record an ownership result obtained before the app is added to pkg0.
pub fn record_actual_ownership(app_id: AppId, owned: bool) {
    ACTUAL_OWNERSHIP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(app_id, owned);
}

pub fn on_check_ownership(
    config: &RuntimeConfig,
    app_id: AppId,
    original_result: u32,
    info: &mut CAppOwnershipInfo,
) -> u32 {
    if config.is_controlled_app(app_id) && original_result == 0 {
        info.grant_spoofed_ownership(1_600_000_000);
        info!(app_id = app_id.0, "feat: ownership granted");
        return 1;
    }

    if config.should_bypass_sharing(app_id) && original_result != 0 && info.is_family_shared() {
        info.clear_family_shared();
        info!(app_id = app_id.0, "feat: sharing unlocked");
    }

    original_result
}

pub fn on_get_subscribed_apps(
    config: &RuntimeConfig,
    app_list: &mut [u32],
    original_count: u32,
) -> u32 {
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

    fn zeroed_info() -> CAppOwnershipInfo {
        CAppOwnershipInfo::zeroed()
    }

    #[test]
    fn inject_sets_ownership_when_original_is_zero() {
        let config = config_with_inject(&[480]);
        let mut info = zeroed_info();
        let result = on_check_ownership(&config, AppId(480), 0, &mut info);
        assert_eq!(result, 1);
        assert_eq!(info.owner(), 1);
        assert_eq!(info.owns_license(), 1);
        assert_eq!(info.license_permanent(), 1);
        assert!(!info.is_family_shared());
    }

    #[test]
    fn no_inject_when_already_owned() {
        let config = config_with_inject(&[480]);
        let mut info = zeroed_info();
        info.set_owner(99);
        let result = on_check_ownership(&config, AppId(480), 1, &mut info);
        assert_eq!(result, 1);
        assert_eq!(info.owner(), 99);
    }

    #[test]
    fn spoofed_followup_result_does_not_poison_actual_ownership() {
        let app_id = AppId(246_813_581);
        let config = config_with_inject(&[app_id.0]);
        record_actual_ownership(app_id, false);

        let mut info = zeroed_info();
        assert_eq!(on_check_ownership(&config, app_id, 1, &mut info), 1);
        assert_eq!(actual_ownership(app_id), OwnershipState::Unowned);
        assert!(classify_app(&config, app_id).requires_injected_ownership());

        record_actual_ownership(app_id, true);
        assert_eq!(actual_ownership(app_id), OwnershipState::Owned);
        assert!(!classify_app(&config, app_id).requires_injected_ownership());
    }

    #[test]
    fn package_association_alone_is_not_genuine_ownership() {
        let mut info = zeroed_info();
        info.exist_in_package_nums = 1;
        assert!(!original_result_is_genuinely_owned(1, &info));

        info.exist_in_package_nums = 2;
        assert!(original_result_is_genuinely_owned(1, &info));
        assert!(!original_result_is_genuinely_owned(0, &info));
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
        let mut info = zeroed_info();
        let result = on_check_ownership(&config, AppId(999), 0, &mut info);
        assert_eq!(result, 0);
        assert_eq!(info.owner(), 0);
    }

    #[test]
    fn sharing_bypass_clears_family_shared() {
        let config = RuntimeConfig::default(); // shared.enabled = true by default
        let mut info = zeroed_info();
        info.set_family_shared(true);
        let result = on_check_ownership(&config, AppId(570), 1, &mut info);
        assert_eq!(result, 1);
        assert!(!info.is_family_shared());
    }

    #[test]
    fn sharing_bypass_noop_when_not_shared() {
        let config = RuntimeConfig::default();
        let mut info = zeroed_info();
        info.set_family_shared(false);
        let original_owner = info.owner();
        let result = on_check_ownership(&config, AppId(570), 1, &mut info);
        assert_eq!(result, 1);
        assert_eq!(info.owner(), original_owner);
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
