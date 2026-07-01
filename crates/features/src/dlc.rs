use steam_runtime_config::{AppId, RuntimeConfig};
use tracing::info;

pub fn on_is_dlc_installed(
    config: &RuntimeConfig,
    app_id: AppId,
    dlc_id: AppId,
    original: bool,
) -> bool {
    if !original && is_controlled_dlc(config, app_id, dlc_id) {
        info!(
            app_id = app_id.0,
            dlc_id = dlc_id.0,
            "feat: DLC installed spoofed"
        );
        return true;
    }
    original
}

pub fn on_is_dlc_enabled(
    config: &RuntimeConfig,
    app_id: AppId,
    dlc_id: AppId,
    original: bool,
) -> bool {
    if !original && is_controlled_dlc(config, app_id, dlc_id) {
        info!(
            app_id = app_id.0,
            dlc_id = dlc_id.0,
            "feat: DLC enabled spoofed"
        );
        return true;
    }
    original
}

pub fn dlc_count_adjustment(config: &RuntimeConfig, app_id: AppId) -> u32 {
    controlled_dlcs_for(config, app_id).len() as u32
}

pub struct InjectedDlc {
    pub dlc_id: AppId,
    pub name: String,
}

pub fn get_injected_dlc_at(
    config: &RuntimeConfig,
    app_id: AppId,
    inject_index: usize,
) -> Option<InjectedDlc> {
    let dlcs = controlled_dlcs_for(config, app_id);
    dlcs.get(inject_index).map(|&dlc_id| {
        info!(
            app_id = app_id.0,
            dlc_id = dlc_id.0,
            "feat: DLC data injected"
        );
        InjectedDlc {
            dlc_id,
            name: format!("DLC {}", dlc_id),
        }
    })
}

fn is_controlled_dlc(config: &RuntimeConfig, app_id: AppId, dlc_id: AppId) -> bool {
    config
        .apps
        .inject
        .iter()
        .any(|a| a.id == app_id && a.dlc.contains(&dlc_id))
}

fn controlled_dlcs_for(config: &RuntimeConfig, app_id: AppId) -> Vec<AppId> {
    config
        .apps
        .inject
        .iter()
        .find(|a| a.id == app_id)
        .map(|a| a.dlc.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use steam_runtime_config::InjectApp;

    fn config_with_dlc() -> RuntimeConfig {
        RuntimeConfig {
            apps: steam_runtime_config::AppsSection {
                inject: vec![InjectApp {
                    id: AppId(480),
                    dlc: vec![AppId(505730), AppId(505740)],
                    ticket: Default::default(),
                    purchase_time: 0,
                }],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn dlc_installed_spoofed_for_controlled() {
        let config = config_with_dlc();
        assert!(on_is_dlc_installed(
            &config,
            AppId(480),
            AppId(505730),
            false
        ));
    }

    #[test]
    fn dlc_installed_passthrough_when_already_true() {
        let config = config_with_dlc();
        assert!(on_is_dlc_installed(
            &config,
            AppId(480),
            AppId(505730),
            true
        ));
    }

    #[test]
    fn dlc_installed_passthrough_for_unknown() {
        let config = config_with_dlc();
        assert!(!on_is_dlc_installed(
            &config,
            AppId(480),
            AppId(999999),
            false
        ));
    }

    #[test]
    fn dlc_count_matches_config() {
        let config = config_with_dlc();
        assert_eq!(dlc_count_adjustment(&config, AppId(480)), 2);
        assert_eq!(dlc_count_adjustment(&config, AppId(999)), 0);
    }

    #[test]
    fn get_injected_dlc_returns_correct_id() {
        let config = config_with_dlc();
        let dlc = get_injected_dlc_at(&config, AppId(480), 0).unwrap();
        assert_eq!(dlc.dlc_id, AppId(505730));
        let dlc = get_injected_dlc_at(&config, AppId(480), 1).unwrap();
        assert_eq!(dlc.dlc_id, AppId(505740));
        assert!(get_injected_dlc_at(&config, AppId(480), 2).is_none());
    }
}
