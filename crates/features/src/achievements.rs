//! Achievement/stats schema interception.
//!
//! For controlled apps, outgoing stats requests are redirected to a donor
//! account only to fetch Valve's authoritative schema. The hooks crate then
//! drops the donor response, combines that schema with backend-authoritative
//! stats when available, and injects a response for Steam's original job.
//!
//! Schema retrieval supports both ServiceMethod (EMsg 151/147) and legacy
//! EMsg 818/819. Donor requests clear cached schema/stats tokens so Valve sends
//! full schema data; donor stat values must never be passed through as the
//! controlled account's state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use prost::Message;
use tracing::{debug, info};
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_steam_protocol::*;

pub const STATS_JOB_NAME: &str = vapor_forge_steam_protocol::PLAYER_GET_USER_STATS_JOB_NAME;
const DEFAULT_REF_STEAMID: u64 = 76561198028121353;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedAchievementSchema {
    pub app_id: u32,
    pub schema_version: Option<String>,
    pub content: Vec<u8>,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}

// ---------------------------------------------------------------------------
// Donor SteamID registry
// ---------------------------------------------------------------------------

fn get_ref_steamid(stat_steam_ids: &HashMap<AppId, u64>, app_id: AppId) -> u64 {
    stat_steam_ids
        .get(&app_id)
        .copied()
        .unwrap_or(DEFAULT_REF_STEAMID)
}

// ---------------------------------------------------------------------------
// Pending request tracking (ServiceMethod path)
// ---------------------------------------------------------------------------

static PENDING: Mutex<Option<HashMap<u64, AppId>>> = Mutex::new(None);
static PENDING_COUNT: AtomicUsize = AtomicUsize::new(0);

fn add_pending(job_id: u64, app_id: AppId) {
    let mut guard = PENDING.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(job_id, app_id);
    PENDING_COUNT.store(map.len(), Ordering::Release);
}

fn take_pending(job_id: u64) -> Option<AppId> {
    let mut guard = PENDING.lock().unwrap();
    let map = guard.as_mut()?;
    let app_id = map.remove(&job_id)?;
    PENDING_COUNT.store(map.len(), Ordering::Release);
    Some(app_id)
}

pub fn has_pending() -> bool {
    PENDING_COUNT.load(Ordering::Acquire) > 0
}

// ---------------------------------------------------------------------------
// Pending request tracking (Legacy 818/819 path)
// ---------------------------------------------------------------------------

static LEGACY_PENDING: Mutex<Option<HashMap<AppId, usize>>> = Mutex::new(None);
static LEGACY_PENDING_COUNT: AtomicUsize = AtomicUsize::new(0);

fn add_legacy_pending(app_id: AppId) {
    let mut guard = LEGACY_PENDING.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    *map.entry(app_id).or_insert(0) += 1;
    LEGACY_PENDING_COUNT.store(map.values().sum(), Ordering::Release);
}

fn take_legacy_pending(app_id: AppId) -> bool {
    let mut guard = LEGACY_PENDING.lock().unwrap();
    let Some(map) = guard.as_mut() else {
        return false;
    };
    let Some(count) = map.get_mut(&app_id) else {
        return false;
    };
    *count -= 1;
    if *count == 0 {
        map.remove(&app_id);
    }
    LEGACY_PENDING_COUNT.store(map.values().sum(), Ordering::Release);
    true
}

pub fn has_legacy_pending() -> bool {
    LEGACY_PENDING_COUNT.load(Ordering::Acquire) > 0
}

// ---------------------------------------------------------------------------
// Offline response queue
// ---------------------------------------------------------------------------

pub struct OfflineResponse {
    pub packet: Vec<u8>,
    pub generation: u64,
}

static OFFLINE_QUEUE: Mutex<Option<Vec<OfflineResponse>>> = Mutex::new(None);

fn queue_offline_response(app_id: AppId, job_id: u64, req_hdr: &CMsgProtoBufHeader) -> bool {
    let resp_hdr = CMsgProtoBufHeader {
        steamid: req_hdr.steamid,
        jobid_source: None,
        jobid_target: Some(job_id),
        target_job_name: req_hdr.target_job_name.clone(),
        eresult: Some(ERESULT_NO_CONNECTION),
        transport_error: None,
        seq_num: None,
        ..Default::default()
    };
    let resp_body = PlayerGetUserStatsResponse::default();

    let hdr_bytes = resp_hdr.encode_to_vec();
    let body_bytes = resp_body.encode_to_vec();
    let emsg = EMSG_SERVICE_METHOD_RESPONSE | K_MSG_HDR_PROTO_FLAG;
    let packet = assemble_raw(emsg, &hdr_bytes, &body_bytes);

    {
        let mut guard = OFFLINE_QUEUE.lock().unwrap();
        let queue = guard.get_or_insert_with(Vec::new);
        queue.push(OfflineResponse {
            packet,
            generation: crate::inject_wake::injection_generation(),
        });
    }
    debug!(
        app_id = app_id.0,
        "achievements: queued offline NO_CONNECTION response"
    );
    // Dispatch now instead of waiting for the next inbound packet.
    crate::inject_wake::wake(crate::inject_wake::InjectionSource::Achievements);
    true
}

pub fn drain_offline_responses() -> Vec<OfflineResponse> {
    let mut guard = OFFLINE_QUEUE.lock().unwrap();
    let queue = match guard.as_mut() {
        Some(q) => q,
        None => return Vec::new(),
    };
    std::mem::take(queue)
}

// ---------------------------------------------------------------------------
// Outgoing request processing (called from send hook)
// ---------------------------------------------------------------------------

fn should_redirect_with_ownership(
    app_id: AppId,
    config: &RuntimeConfig,
    ownership: impl FnOnce(AppId) -> crate::apps::OwnershipState,
) -> bool {
    crate::apps::classify_app_with_ownership(config, app_id, ownership)
        .requires_injected_ownership()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatsSendPlan {
    Pass,
    DropOffline {
        app_id: AppId,
        job_id: Option<u64>,
    },
    Rewrite {
        app_id: AppId,
        body: Vec<u8>,
        donor_steam_id: u64,
        job_id: Option<u64>,
        was_probe: bool,
    },
}

pub fn plan_send_service_stats(
    hdr: &CMsgProtoBufHeader,
    body_bytes: &[u8],
    config: &RuntimeConfig,
    stat_steam_ids: &HashMap<AppId, u64>,
    ownership: impl FnOnce(AppId) -> crate::apps::OwnershipState,
) -> StatsSendPlan {
    let Ok(mut req) = PlayerGetUserStatsRequest::decode(body_bytes) else {
        return StatsSendPlan::Pass;
    };
    let Some(app_id) = req.appid.map(AppId) else {
        return StatsSendPlan::Pass;
    };
    if !should_redirect_with_ownership(app_id, config, ownership) {
        return StatsSendPlan::Pass;
    }

    let Some(job_id) = hdr.jobid_source.filter(|job_id| *job_id != 0) else {
        return StatsSendPlan::Pass;
    };
    if config.achievements.offline_schema {
        return StatsSendPlan::DropOffline {
            app_id,
            job_id: Some(job_id),
        };
    }

    let had_sha_schema = req.sha_schema.take().is_some();
    let had_crc_schema = req.crc_schema.take().is_some();
    let was_probe = had_sha_schema || had_crc_schema;
    let donor_steam_id = get_ref_steamid(stat_steam_ids, app_id);
    req.steamid = Some(donor_steam_id);
    StatsSendPlan::Rewrite {
        app_id,
        body: req.encode_to_vec(),
        donor_steam_id,
        job_id: Some(job_id),
        was_probe,
    }
}

pub fn plan_send_legacy_stats(
    body_bytes: &[u8],
    config: &RuntimeConfig,
    stat_steam_ids: &HashMap<AppId, u64>,
    ownership: impl FnOnce(AppId) -> crate::apps::OwnershipState,
) -> StatsSendPlan {
    let Ok(mut req) = ClientGetUserStatsRequest::decode(body_bytes) else {
        return StatsSendPlan::Pass;
    };
    let Some(app_id) = req.game_id.and_then(app_id_from_game_id).map(AppId) else {
        return StatsSendPlan::Pass;
    };
    if !should_redirect_with_ownership(app_id, config, ownership) {
        return StatsSendPlan::Pass;
    }
    if config.achievements.offline_schema {
        return StatsSendPlan::DropOffline {
            app_id,
            job_id: None,
        };
    }

    let was_probe = req.crc_stats.take().is_some() || req.schema_local_version != Some(-1);
    req.schema_local_version = Some(-1);
    let donor_steam_id = get_ref_steamid(stat_steam_ids, app_id);
    req.steam_id_for_user = Some(donor_steam_id);
    StatsSendPlan::Rewrite {
        app_id,
        body: req.encode_to_vec(),
        donor_steam_id,
        job_id: None,
        was_probe,
    }
}

/// Process an outgoing ServiceMethod (EMsg 151) Player.GetUserStats#1 request.
/// Returns `Some(modified_body_bytes)` if the request was rewritten, `None` to pass through.
pub fn on_send_service_stats(
    hdr: &CMsgProtoBufHeader,
    body_bytes: &[u8],
    config: &RuntimeConfig,
    stat_steam_ids: &HashMap<AppId, u64>,
) -> Option<Vec<u8>> {
    match plan_send_service_stats(
        hdr,
        body_bytes,
        config,
        stat_steam_ids,
        crate::apps::actual_ownership,
    ) {
        StatsSendPlan::Pass => None,
        StatsSendPlan::DropOffline {
            app_id,
            job_id: Some(job_id),
        } => {
            queue_offline_response(app_id, job_id, hdr);
            Some(Vec::new())
        }
        StatsSendPlan::Rewrite {
            app_id,
            body,
            donor_steam_id,
            job_id: Some(job_id),
            was_probe,
        } => {
            add_pending(job_id, app_id);
            info!(
                app_id = app_id.0,
                ref_id = donor_steam_id,
                probe = was_probe,
                "achievements: redirected stats request"
            );
            Some(body)
        }
        StatsSendPlan::DropOffline { job_id: None, .. }
        | StatsSendPlan::Rewrite { job_id: None, .. } => unreachable!("service plan has a job id"),
    }
}

/// Process an outgoing Legacy (EMsg 818) CMsgClientGetUserStats request.
/// Returns `Some(modified_body_bytes)` if rewritten, `None` to pass through.
pub fn on_send_legacy_stats(
    body_bytes: &[u8],
    config: &RuntimeConfig,
    stat_steam_ids: &HashMap<AppId, u64>,
) -> Option<Vec<u8>> {
    match plan_send_legacy_stats(
        body_bytes,
        config,
        stat_steam_ids,
        crate::apps::actual_ownership,
    ) {
        StatsSendPlan::Pass => None,
        StatsSendPlan::DropOffline {
            app_id: _,
            job_id: None,
        } => Some(Vec::new()),
        StatsSendPlan::Rewrite {
            app_id,
            body,
            donor_steam_id,
            job_id: None,
            was_probe,
        } => {
            add_legacy_pending(app_id);
            debug!(
                app_id = app_id.0,
                ref_id = donor_steam_id,
                probe = was_probe,
                "achievements: redirected legacy full-schema request"
            );
            Some(body)
        }
        StatsSendPlan::DropOffline {
            job_id: Some(_), ..
        }
        | StatsSendPlan::Rewrite {
            job_id: Some(_), ..
        } => unreachable!("legacy plan has no job id"),
    }
}

// ---------------------------------------------------------------------------
// Incoming response processing (called from recv hook)
// ---------------------------------------------------------------------------

/// Process an incoming ServiceMethod response (EMsg 147) for stats.
/// Returns `Some(new_body_bytes)` if response was stripped, `None` to pass through.
pub fn on_recv_service_stats(
    hdr: &CMsgProtoBufHeader,
    body_bytes: &[u8],
) -> Option<(Vec<u8>, Vec<u8>, Option<CapturedAchievementSchema>)> {
    let job_id = hdr.jobid_target?;
    let app_id = take_pending(job_id)?;

    let mut resp = PlayerGetUserStatsResponse::decode(body_bytes).ok()?;
    let captured = resp
        .schema
        .as_ref()
        .filter(|schema| !schema.is_empty())
        .map(|schema| CapturedAchievementSchema {
            app_id: app_id.0,
            schema_version: resp.sha_schema.as_deref().map(hex),
            content: schema.clone(),
        });
    resp.stats.clear();

    let mut new_hdr = hdr.clone();
    new_hdr.eresult = Some(ERESULT_OK);

    info!(
        app_id = app_id.0,
        "achievements: cleared stats from response"
    );
    Some((new_hdr.encode_to_vec(), resp.encode_to_vec(), captured))
}

/// Remove reference-account values from a controlled App's EMsg 819 response.
pub fn on_recv_legacy_stats(
    body_bytes: &[u8],
    config: &RuntimeConfig,
) -> Option<(Vec<u8>, Option<CapturedAchievementSchema>)> {
    let mut response = ClientGetUserStatsResponse::decode(body_bytes).ok()?;
    let app_id = AppId(app_id_from_game_id(response.game_id?)?);
    if !should_redirect_with_ownership(app_id, config, crate::apps::actual_ownership) {
        return None;
    }

    let matched = has_legacy_pending() && take_legacy_pending(app_id);
    let captured = matched
        .then_some(response.schema.as_ref())
        .flatten()
        .filter(|schema| !schema.is_empty())
        .map(|schema| CapturedAchievementSchema {
            app_id: app_id.0,
            schema_version: None,
            content: schema.clone(),
        });
    response.stats.clear();
    response.achievement_blocks.clear();
    response.eresult = Some(ERESULT_OK);
    debug!(
        app_id = app_id.0,
        matched_pending = matched,
        "achievements: cleared legacy stats response"
    );
    Some((response.encode_to_vec(), captured))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controlled_config(app_id: u32) -> RuntimeConfig {
        RuntimeConfig {
            apps: vapor_forge_config::AppsSection::with_inject(vec![
                vapor_forge_config::InjectApp {
                    id: AppId(app_id),
                    dlc: Vec::new(),
                    ticket: Default::default(),
                    purchase_time: 0,
                },
            ]),
            ..Default::default()
        }
    }

    #[test]
    fn service_response_captures_schema_before_stats_are_cleared() {
        let app_id = 3_456_781;
        let job_id = 9_001_001;
        let config = controlled_config(app_id);
        let request_header = CMsgProtoBufHeader {
            jobid_source: Some(job_id),
            ..Default::default()
        };
        let request = PlayerGetUserStatsRequest {
            steamid: Some(76561198000000001),
            appid: Some(app_id),
            sha_schema: Some(vec![0xaa]),
            ..Default::default()
        };

        let rewritten = on_send_service_stats(
            &request_header,
            &request.encode_to_vec(),
            &config,
            &HashMap::new(),
        )
        .expect("controlled request should be redirected");
        let rewritten = PlayerGetUserStatsRequest::decode(rewritten.as_slice()).unwrap();
        assert_eq!(rewritten.steamid, Some(DEFAULT_REF_STEAMID));
        assert_eq!(rewritten.sha_schema, None);

        let response_header = CMsgProtoBufHeader {
            jobid_target: Some(job_id),
            eresult: Some(2),
            routing_app_id: Some(480),
            debug_source: Some("cm".into()),
            forward_to_system_id: vec![7, 8],
            ip_addr: Some(MsgProtoBufHeaderIpAddress::V6(vec![0; 16])),
            ..Default::default()
        };
        let response = PlayerGetUserStatsResponse {
            sha_schema: Some(vec![0x12, 0xab, 0x00]),
            schema: Some(vec![0x00, 0x01, 0x02, 0x08]),
            stats: vec![PlayerStatsEntry {
                stat_id: Some(7),
                stat_value: Some(42),
                unlock_times: Vec::new(),
            }],
            ..Default::default()
        };

        let (header, body, captured) =
            on_recv_service_stats(&response_header, &response.encode_to_vec()).unwrap();
        let captured = captured.expect("schema should be captured");
        assert_eq!(captured.app_id, app_id);
        assert_eq!(captured.schema_version.as_deref(), Some("12ab00"));
        assert_eq!(captured.content, vec![0x00, 0x01, 0x02, 0x08]);

        let header = CMsgProtoBufHeader::decode(header.as_slice()).unwrap();
        let body = PlayerGetUserStatsResponse::decode(body.as_slice()).unwrap();
        assert_eq!(header.eresult, Some(ERESULT_OK));
        assert_eq!(header.routing_app_id, Some(480));
        assert_eq!(header.debug_source.as_deref(), Some("cm"));
        assert_eq!(header.forward_to_system_id, vec![7, 8]);
        assert!(matches!(
            header.ip_addr,
            Some(MsgProtoBufHeaderIpAddress::V6(ref value)) if value == &[0; 16]
        ));
        assert!(body.stats.is_empty());
        assert_eq!(body.schema, response.schema);
    }

    #[test]
    fn legacy_request_is_redirected_and_response_values_are_cleared() {
        let app_id = 3_456_782;
        let config = controlled_config(app_id);
        let request = ClientGetUserStatsRequest {
            game_id: Some(u64::from(app_id)),
            schema_local_version: Some(-1),
            steam_id_for_user: Some(76561198000000001),
            ..Default::default()
        };

        let rewritten = on_send_legacy_stats(&request.encode_to_vec(), &config, &HashMap::new())
            .expect("controlled request should be handled");
        let rewritten = ClientGetUserStatsRequest::decode(rewritten.as_slice()).unwrap();
        assert_eq!(rewritten.steam_id_for_user, Some(DEFAULT_REF_STEAMID));

        let response = ClientGetUserStatsResponse {
            game_id: Some(u64::from(app_id)),
            eresult: Some(2),
            crc_stats: Some(0x12ab34cd),
            schema: Some(vec![1, 2, 3]),
            stats: vec![LegacyStatsEntry {
                stat_id: Some(7),
                stat_value: Some(42),
            }],
            achievement_blocks: vec![AchievementBlock {
                achievement_id: Some(9),
                unlock_time: vec![1_700_000_000],
            }],
        };
        let (body, captured) = on_recv_legacy_stats(&response.encode_to_vec(), &config).unwrap();
        let body = ClientGetUserStatsResponse::decode(body.as_slice()).unwrap();
        assert_eq!(body.eresult, Some(ERESULT_OK));
        assert!(body.stats.is_empty());
        assert!(body.achievement_blocks.is_empty());
        assert_eq!(captured.unwrap().content, vec![1, 2, 3]);
    }

    #[test]
    fn legacy_crc_probe_is_forced_to_full_schema() {
        let app_id = 3_456_783;
        let request = ClientGetUserStatsRequest {
            game_id: Some(u64::from(app_id)),
            crc_stats: Some(0x12345678),
            schema_local_version: Some(7),
            steam_id_for_user: Some(76561198000000001),
        };
        let rewritten = on_send_legacy_stats(
            &request.encode_to_vec(),
            &controlled_config(app_id),
            &HashMap::new(),
        )
        .unwrap();
        let rewritten = ClientGetUserStatsRequest::decode(rewritten.as_slice()).unwrap();
        assert_eq!(rewritten.crc_stats, None);
        assert_eq!(rewritten.schema_local_version, Some(-1));
        assert_eq!(rewritten.steam_id_for_user, Some(DEFAULT_REF_STEAMID));
    }

    #[test]
    fn service_plan_uses_explicit_ownership_and_lua_donor() {
        let app_id = AppId(3_456_784);
        let donor = 76561199000000001;
        let header = CMsgProtoBufHeader {
            jobid_source: Some(91),
            ..Default::default()
        };
        let request = PlayerGetUserStatsRequest {
            appid: Some(app_id.0),
            steamid: Some(76561198000000001),
            sha_schema: Some(vec![1, 2, 3]),
            crc_schema: Some(0x1234_5678),
            ..Default::default()
        };
        let donors = HashMap::from([(app_id, donor)]);

        let StatsSendPlan::Rewrite {
            body,
            donor_steam_id,
            job_id,
            ..
        } = plan_send_service_stats(
            &header,
            &request.encode_to_vec(),
            &controlled_config(app_id.0),
            &donors,
            |_| crate::apps::OwnershipState::Unowned,
        )
        else {
            panic!("expected a rewrite plan");
        };
        let rewritten = PlayerGetUserStatsRequest::decode(body.as_slice()).unwrap();
        assert_eq!(donor_steam_id, donor);
        assert_eq!(job_id, Some(91));
        assert_eq!(rewritten.steamid, Some(donor));
        assert_eq!(rewritten.sha_schema, None);
        assert_eq!(rewritten.crc_schema, None);
    }

    #[test]
    fn stats_plans_pass_genuinely_owned_apps() {
        let app_id = AppId(3_456_785);
        let header = CMsgProtoBufHeader {
            jobid_source: Some(92),
            ..Default::default()
        };
        let request = PlayerGetUserStatsRequest {
            appid: Some(app_id.0),
            ..Default::default()
        };
        assert_eq!(
            plan_send_service_stats(
                &header,
                &request.encode_to_vec(),
                &controlled_config(app_id.0),
                &HashMap::new(),
                |_| crate::apps::OwnershipState::Owned,
            ),
            StatsSendPlan::Pass
        );
    }
}
