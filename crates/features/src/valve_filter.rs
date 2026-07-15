//! Privacy filtering for controlled apps on Steam's CM transport.
//!
//! This module only contains protocol decisions and packet construction. The
//! hooks crate owns the send/receive ABI and queues fabricated responses.

use prost::Message;
use std::collections::HashMap;
use vapor_forge_abi::{
    assemble_raw, CMsgClientGamesPlayed, CMsgProtoBufHeader, ClientStatsUpdated,
    ClientStoreUserStats2Request, ClientStoreUserStatsRequest, ClientStoreUserStatsResponse,
    EMSG_SERVICE_METHOD_RESPONSE, EMSG_STATS_UPDATED, EMSG_STORE_USERSTATS, EMSG_STORE_USERSTATS2,
    EMSG_STORE_USERSTATS_RESPONSE, ERESULT_OK, K_MSG_HDR_PROTO_FLAG,
};
use vapor_forge_config::{AppId, RuntimeConfig};

pub const APP_INTERFACE_METRICS: &str = "ClientMetrics.ClientAppInterfaceStatsReport#1";
pub const CLOUD_SYNC_METRICS: &str = "ClientMetrics.ClientCloudAppSyncStats#1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivacyAction {
    Pass,
    Drop { app_id: u32 },
    Respond { app_id: u32, packet: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GamesPlayedFilter {
    pub body: Option<Vec<u8>>,
    pub blocked_rich_presence_app: Option<AppId>,
}

#[derive(Clone, prost::Message)]
struct AppIdField1 {
    #[prost(uint32, optional, tag = "1")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct GameIdField1 {
    #[prost(uint64, optional, tag = "1")]
    game_id: Option<u64>,
}

fn protected(config: &RuntimeConfig, app_id: u32) -> bool {
    app_id != 0 && crate::apps::classify_app(config, AppId(app_id)).requires_injected_ownership()
}

/// Rewrite AppAvatar entries and remove protected apps without an avatar.
pub fn filter_games_played(
    body: &[u8],
    config: &RuntimeConfig,
    avatar_map: &HashMap<AppId, AppId>,
) -> Option<GamesPlayedFilter> {
    let mut message = CMsgClientGamesPlayed::decode(body).ok()?;
    let mut changed = false;
    let mut blocked_rich_presence_app = None;
    let mut filtered = Vec::with_capacity(message.games_played.len());

    for mut game in message.games_played.drain(..) {
        let Some(game_id) = game.game_id else {
            filtered.push(game);
            continue;
        };
        let app_id = AppId(game_id as u32);
        if let Some(avatar) = crate::app_avatar::get_avatar(app_id, avatar_map) {
            game.game_id = Some(avatar.0 as u64);
            changed = true;
            filtered.push(game);
            continue;
        }
        if protected(config, app_id.0) {
            blocked_rich_presence_app.get_or_insert(app_id);
            changed = true;
            continue;
        }
        filtered.push(game);
    }

    message.games_played = filtered;
    Some(GamesPlayedFilter {
        body: changed.then(|| message.encode_to_vec()),
        blocked_rich_presence_app,
    })
}

/// Keep the two known per-app telemetry uploads local.
pub fn service_method_action(
    header: &CMsgProtoBufHeader,
    _header_bytes: &[u8],
    body: &[u8],
    config: &RuntimeConfig,
) -> PrivacyAction {
    let Some(method) = header.target_job_name.as_deref() else {
        return PrivacyAction::Pass;
    };

    let app_id = match method {
        APP_INTERFACE_METRICS => {
            let Some(app_id) = GameIdField1::decode(body).ok().and_then(|msg| msg.game_id) else {
                return PrivacyAction::Pass;
            };
            app_id as u32
        }
        CLOUD_SYNC_METRICS => {
            let Some(app_id) = AppIdField1::decode(body).ok().and_then(|msg| msg.app_id) else {
                return PrivacyAction::Pass;
            };
            app_id
        }
        _ => return PrivacyAction::Pass,
    };

    if !protected(config, app_id) {
        return PrivacyAction::Pass;
    }
    PrivacyAction::Drop { app_id }
}

/// Return a local success packet for StoreStats when its AppID is protected.
pub fn store_stats_action(
    emsg: u32,
    header_bytes: &[u8],
    body: &[u8],
    config: &RuntimeConfig,
) -> PrivacyAction {
    match emsg {
        EMSG_STORE_USERSTATS => {
            let Ok(request) = ClientStoreUserStatsRequest::decode(body) else {
                return PrivacyAction::Pass;
            };
            let Some(game_id) = request.game_id else {
                return PrivacyAction::Pass;
            };
            let app_id = game_id as u32;
            if !protected(config, app_id) {
                return PrivacyAction::Pass;
            }
            let response = ClientStoreUserStatsResponse {
                game_id: Some(game_id),
                eresult: Some(ERESULT_OK),
                crc_stats: None,
                stats_out_of_date: Some(false),
            };
            PrivacyAction::Respond {
                app_id,
                packet: emsg_response(
                    EMSG_STORE_USERSTATS_RESPONSE,
                    header_bytes,
                    response.encode_to_vec(),
                ),
            }
        }
        EMSG_STORE_USERSTATS2 => {
            let Ok(request) = ClientStoreUserStats2Request::decode(body) else {
                return PrivacyAction::Pass;
            };
            let Some(game_id) = request.game_id else {
                return PrivacyAction::Pass;
            };
            let app_id = game_id as u32;
            if !protected(config, app_id) {
                return PrivacyAction::Pass;
            }
            let response = ClientStatsUpdated {
                steam_id: request.settee_steam_id.or(request.settor_steam_id),
                game_id: Some(game_id),
                crc_stats: request.crc_stats,
                updated_stats: request.stats,
            };
            PrivacyAction::Respond {
                app_id,
                packet: emsg_response(EMSG_STATS_UPDATED, header_bytes, response.encode_to_vec()),
            }
        }
        _ => PrivacyAction::Pass,
    }
}

pub fn service_response(header_bytes: &[u8], body: Vec<u8>, eresult: i32) -> Vec<u8> {
    let request = CMsgProtoBufHeader::decode(header_bytes).unwrap_or_default();
    let response = CMsgProtoBufHeader {
        steamid: request.steamid,
        jobid_source: None,
        jobid_target: request.jobid_source,
        target_job_name: request.target_job_name,
        eresult: Some(eresult),
        transport_error: None,
        seq_num: None,
    };
    assemble_raw(
        EMSG_SERVICE_METHOD_RESPONSE | K_MSG_HDR_PROTO_FLAG,
        &response.encode_to_vec(),
        &body,
    )
}

pub fn emsg_response(emsg: u32, header_bytes: &[u8], body: Vec<u8>) -> Vec<u8> {
    let request = CMsgProtoBufHeader::decode(header_bytes).unwrap_or_default();
    let response = CMsgProtoBufHeader {
        steamid: request.steamid,
        jobid_source: None,
        jobid_target: request.jobid_source,
        target_job_name: request.target_job_name,
        eresult: Some(ERESULT_OK),
        transport_error: None,
        seq_num: None,
    };
    assemble_raw(
        emsg | K_MSG_HDR_PROTO_FLAG,
        &response.encode_to_vec(),
        &body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vapor_forge_config::{AppsSection, InjectApp};

    fn config(app_id: u32) -> RuntimeConfig {
        RuntimeConfig {
            apps: AppsSection {
                inject: vec![InjectApp {
                    id: AppId(app_id),
                    dlc: Vec::new(),
                    ticket: Default::default(),
                    purchase_time: 0,
                }],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn header(method: &str) -> CMsgProtoBufHeader {
        CMsgProtoBufHeader {
            jobid_source: Some(42),
            target_job_name: Some(method.into()),
            ..Default::default()
        }
    }

    #[test]
    fn metrics_for_unknown_controlled_app_are_dropped() {
        let header = header(APP_INTERFACE_METRICS);
        let body = GameIdField1 {
            game_id: Some(736_260),
        }
        .encode_to_vec();
        assert_eq!(
            service_method_action(&header, &header.encode_to_vec(), &body, &config(736_260)),
            PrivacyAction::Drop { app_id: 736_260 }
        );
    }

    #[test]
    fn read_only_app_queries_pass_through() {
        let body = AppIdField1 {
            app_id: Some(736_261),
        }
        .encode_to_vec();
        for method in [
            "Player.GetGameBadgeLevels#1",
            "PublishedFile.GetUserFiles#1",
            "UserNews.GetUserNews#1",
            "UserGameActivity.GetActivity#1",
            "Store.ShouldPromptForCompatibilityFeedback#1",
        ] {
            let header = header(method);
            assert_eq!(
                service_method_action(&header, &header.encode_to_vec(), &body, &config(736_261)),
                PrivacyAction::Pass,
                "{method} should pass through"
            );
        }
    }

    #[test]
    fn store_stats_is_acknowledged_without_valve() {
        let header = header("store-stats").encode_to_vec();
        let request = ClientStoreUserStatsRequest {
            game_id: Some(736_262),
            explicit_reset: Some(false),
            stats_to_store: vec![vapor_forge_abi::StoreUserStatsEntry {
                stat_id: Some(1),
                stat_value: Some(2),
            }],
        };
        let PrivacyAction::Respond { packet, .. } = store_stats_action(
            EMSG_STORE_USERSTATS,
            &header,
            &request.encode_to_vec(),
            &config(736_262),
        ) else {
            panic!("expected a local response");
        };
        let (emsg, _, body) = vapor_forge_abi::unpack_raw(&packet).unwrap();
        assert_eq!(emsg, EMSG_STORE_USERSTATS_RESPONSE | K_MSG_HDR_PROTO_FLAG);
        assert_eq!(
            ClientStoreUserStatsResponse::decode(body).unwrap().eresult,
            Some(ERESULT_OK)
        );
    }

    #[test]
    fn games_played_removes_protected_app_without_avatar() {
        let body = CMsgClientGamesPlayed {
            games_played: vec![vapor_forge_abi::GamePlayed {
                game_id: Some(736_263),
                ..Default::default()
            }],
        }
        .encode_to_vec();
        let result = filter_games_played(&body, &config(736_263), &HashMap::new()).unwrap();
        assert_eq!(result.blocked_rich_presence_app, Some(AppId(736_263)));
        let filtered = result.body.unwrap();
        assert!(CMsgClientGamesPlayed::decode(filtered.as_slice())
            .unwrap()
            .games_played
            .is_empty());
    }

    #[test]
    fn games_played_rewrites_avatar_instead_of_removing_app() {
        let body = CMsgClientGamesPlayed {
            games_played: vec![vapor_forge_abi::GamePlayed {
                game_id: Some(736_264),
                ..Default::default()
            }],
        }
        .encode_to_vec();
        let avatars = HashMap::from([(AppId(736_264), AppId(480))]);
        let result = filter_games_played(&body, &config(736_264), &avatars).unwrap();
        assert_eq!(result.blocked_rich_presence_app, None);
        assert_eq!(
            CMsgClientGamesPlayed::decode(result.body.unwrap().as_slice())
                .unwrap()
                .games_played[0]
                .game_id,
            Some(480)
        );
    }
}
