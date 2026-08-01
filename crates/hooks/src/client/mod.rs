pub mod install;
pub mod package;

pub(crate) mod achievement;
pub(crate) mod callback_dispatch;
pub(crate) mod callback_notify;
pub(crate) mod client_id;
pub(crate) mod cloud;
pub(crate) mod cloud_http;
pub(crate) mod current_app;
pub(crate) mod depot;
pub(crate) mod dlc;
pub(crate) mod env;
pub(crate) mod eticket;
pub(crate) mod internal_callbacks;
pub(crate) mod network;
pub(crate) mod ownership;
pub(crate) mod playtime_downlink;
pub(crate) mod steam_context;
pub(crate) mod steam_session;
pub(crate) mod ticket;
pub(crate) mod user;
pub(crate) mod user_stats;

pub(crate) fn reset_account_state() {
    network::invalidate_injection_context();
    steam_context::invalidate_identity();
    package::reset_account_state();
    vapor_forge_features::apps::reset_account_state();
    playtime_downlink::reset_account_state();
    vapor_forge_features::rich_presence::reset_account_state();
    crate::achievement_worker::notify_context_changed();
    crate::playtime_worker::notify_context_changed();
    crate::playtime_downlink_worker::notify_context_changed();
    crate::stats_wakeup_worker::notify_context_changed();
    user_stats::notify_context_changed();
    crate::netpacket::notify_stats_context_changed();
}

pub(crate) fn set_authoritative_steam_id(steam_id: u64) -> bool {
    let changed = vapor_forge_features::identity::set_authoritative_steam_id(steam_id);
    if changed {
        reset_account_state();
    }
    if steam_id != 0 && vapor_forge_features::identity::steam_id() == steam_id {
        steam_context::observe_packet_identity(steam_id);
    }
    changed
}

pub(crate) fn observe_steam_id(steam_id: u64) -> bool {
    let changed = vapor_forge_features::identity::observe_steam_id(steam_id);
    if changed {
        reset_account_state();
    }
    if steam_id != 0 && vapor_forge_features::identity::steam_id() == steam_id {
        steam_context::observe_packet_identity(steam_id);
    }
    changed
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use vapor_forge_config::AppId;
    use vapor_forge_features::apps::{self, OwnershipState};

    use super::set_authoritative_steam_id;

    static ACCOUNT_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct AccountStateCleanup;

    impl Drop for AccountStateCleanup {
        fn drop(&mut self) {
            let _ = set_authoritative_steam_id(0);
            super::reset_account_state();
        }
    }

    #[test]
    fn account_switch_discards_previous_ownership_and_license_sync() {
        let _guard = ACCOUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _cleanup = AccountStateCleanup;
        let account_a = 76_561_198_000_000_001;
        let account_b = 76_561_198_000_000_002;
        let app_id = AppId(246_813_584);

        assert!(set_authoritative_steam_id(account_a));
        let generation_a = vapor_forge_features::identity::generation();
        apps::record_actual_ownership(app_id, true);
        apps::mark_license_sync_complete();
        assert_eq!(apps::actual_ownership(app_id), OwnershipState::Owned);
        assert!(apps::license_sync_complete());

        assert!(set_authoritative_steam_id(account_b));

        assert_eq!(vapor_forge_features::identity::steam_id(), account_b);
        assert!(vapor_forge_features::identity::generation() > generation_a);
        assert_eq!(apps::actual_ownership(app_id), OwnershipState::Unknown);
        assert!(!apps::license_sync_complete());
    }
}
