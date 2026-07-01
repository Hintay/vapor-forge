use steam_runtime_abi::CAppOwnershipInfo;
use steam_runtime_config::{AppCategory, AppId, RuntimeConfig};
use tracing::info;

pub fn on_check_ownership(
    config: &RuntimeConfig,
    app_id: AppId,
    original_result: u32,
    info: &mut CAppOwnershipInfo,
) -> u32 {
    let category = config.app_category(app_id);

    if let Some(AppCategory::Inject | AppCategory::InjectDlc { .. }) = category {
        if original_result == 0 {
            info.release_state = 2;
            info.owner = 1;
            info.exist_in_package_nums = 2;
            info.purchase_time = 1_600_000_000;
            info.owns_license = 1;
            info.license_expired = 0;
            info.license_permanent = 1;
            info.free_license = 0;
            info.family_shared = 0;
            info!(app_id = app_id.0, "feat: ownership injected");
            return 1;
        }
    }

    if config.should_bypass_sharing(app_id) && original_result != 0 && info.family_shared != 0 {
        info.family_shared = 0;
        info!(app_id = app_id.0, "feat: sharing bypass");
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
        if count < app_list.len() {
            // FFI buffer expects raw u32
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
    use steam_runtime_config::InjectApp;

    fn config_with_inject(ids: &[u32]) -> RuntimeConfig {
        RuntimeConfig {
            apps: steam_runtime_config::AppsSection {
                inject: ids
                    .iter()
                    .map(|&id| InjectApp {
                        id: AppId(id),
                        dlc: Vec::new(),
                    })
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn zeroed_info() -> CAppOwnershipInfo {
        CAppOwnershipInfo {
            sub_id: 0,
            release_state: 0,
            owner: 0,
            master_subscription_app_id: 0,
            trial_time: 0,
            exist_in_package_nums: 0,
            region: [0; 2],
            _pad_1a: [0; 2],
            purchase_time: 0,
            real_owner: 0,
            owns_license: 0,
            license_expired: 0,
            _field_26: 0,
            low_violence: 0,
            free_license: 0,
            region_restricted: 0,
            from_free_weekend: 0,
            license_locked: 0,
            license_pending: 0,
            retail_license: 0,
            auto_grant: 0,
            license_permanent: 0,
            _field_30: 0,
            _field_31: 0,
            site_license: 0,
            _field_33: 0,
            _field_34: 0,
            family_shared: 0,
            _field_36: 0,
            _field_37: 0,
        }
    }

    #[test]
    fn inject_sets_ownership_when_original_is_zero() {
        let config = config_with_inject(&[480]);
        let mut info = zeroed_info();
        let result = on_check_ownership(&config, AppId(480), 0, &mut info);
        assert_eq!(result, 1);
        assert_eq!(info.owner, 1);
        assert_eq!(info.owns_license, 1);
        assert_eq!(info.license_permanent, 1);
        assert_eq!(info.family_shared, 0);
    }

    #[test]
    fn no_inject_when_already_owned() {
        let config = config_with_inject(&[480]);
        let mut info = zeroed_info();
        info.owner = 99;
        let result = on_check_ownership(&config, AppId(480), 1, &mut info);
        assert_eq!(result, 1);
        assert_eq!(info.owner, 99);
    }

    #[test]
    fn non_controlled_app_passes_through() {
        let config = config_with_inject(&[480]);
        let mut info = zeroed_info();
        let result = on_check_ownership(&config, AppId(999), 0, &mut info);
        assert_eq!(result, 0);
        assert_eq!(info.owner, 0);
    }

    #[test]
    fn sharing_bypass_clears_family_shared() {
        let config = RuntimeConfig::default(); // shared.enabled = true by default
        let mut info = zeroed_info();
        info.family_shared = 1;
        let result = on_check_ownership(&config, AppId(570), 1, &mut info);
        assert_eq!(result, 1);
        assert_eq!(info.family_shared, 0);
    }

    #[test]
    fn sharing_bypass_noop_when_not_shared() {
        let config = RuntimeConfig::default();
        let mut info = zeroed_info();
        info.family_shared = 0;
        let original_owner = info.owner;
        let result = on_check_ownership(&config, AppId(570), 1, &mut info);
        assert_eq!(result, 1);
        assert_eq!(info.owner, original_owner);
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
