//! Achievement/stats schema interception.
//!
//! For controlled apps, outgoing stats requests have their SteamID rewritten
//! to a reference account so the server returns a valid schema. Incoming
//! responses have stat values cleared (schema is preserved) so Steam keeps
//! metadata but falls back to local cache for actual stats.
//!
//! Schema retrieval supports both ServiceMethod (EMsg 151/147) and legacy
//! EMsg 818/819. Both paths replace the requested SteamID with a reference
//! account and clear the cached schema hash/CRC to request a full schema, then
//! remove that account's actual stats from the response.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use prost::Message;
use tracing::{debug, info};
use vapor_forge_abi::*;
use vapor_forge_config::{AppId, RuntimeConfig};

pub use vapor_forge_packet_inspect::STATS_JOB_NAME;
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
}

static OFFLINE_QUEUE: Mutex<Option<Vec<OfflineResponse>>> = Mutex::new(None);
static OFFLINE_QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);

fn queue_offline_response(app_id: AppId, job_id: u64, req_hdr: &CMsgProtoBufHeader) -> bool {
    let resp_hdr = CMsgProtoBufHeader {
        steamid: req_hdr.steamid,
        jobid_source: None,
        jobid_target: Some(job_id),
        target_job_name: req_hdr.target_job_name.clone(),
        eresult: Some(ERESULT_NO_CONNECTION),
        transport_error: None,
        seq_num: None,
    };
    let resp_body = PlayerGetUserStatsResponse::default();

    let hdr_bytes = resp_hdr.encode_to_vec();
    let body_bytes = resp_body.encode_to_vec();
    let emsg = EMSG_SERVICE_METHOD_RESPONSE | K_MSG_HDR_PROTO_FLAG;
    let packet = assemble_raw(emsg, &hdr_bytes, &body_bytes);

    let mut guard = OFFLINE_QUEUE.lock().unwrap();
    let queue = guard.get_or_insert_with(Vec::new);
    queue.push(OfflineResponse { packet });
    OFFLINE_QUEUE_COUNT.store(queue.len(), Ordering::Release);
    debug!(
        app_id = app_id.0,
        "achievements: queued offline NO_CONNECTION response"
    );
    true
}

pub fn has_offline_responses() -> bool {
    OFFLINE_QUEUE_COUNT.load(Ordering::Acquire) > 0
}

pub fn drain_offline_responses() -> Vec<OfflineResponse> {
    let mut guard = OFFLINE_QUEUE.lock().unwrap();
    let queue = match guard.as_mut() {
        Some(q) => q,
        None => return Vec::new(),
    };
    let drained = std::mem::take(queue);
    OFFLINE_QUEUE_COUNT.store(0, Ordering::Release);
    drained
}

// ---------------------------------------------------------------------------
// Outgoing request processing (called from send hook)
// ---------------------------------------------------------------------------

fn should_redirect(app_id: u32, config: &RuntimeConfig) -> bool {
    crate::apps::classify_app(config, AppId(app_id)).requires_injected_ownership()
}

/// Process an outgoing ServiceMethod (EMsg 151) Player.GetUserStats#1 request.
/// Returns `Some(modified_body_bytes)` if the request was rewritten, `None` to pass through.
pub fn on_send_service_stats(
    hdr: &CMsgProtoBufHeader,
    body_bytes: &[u8],
    config: &RuntimeConfig,
    stat_steam_ids: &HashMap<AppId, u64>,
) -> Option<Vec<u8>> {
    let mut req = PlayerGetUserStatsRequest::decode(body_bytes).ok()?;
    let app_id = req.appid?;
    if !should_redirect(app_id, config) {
        return None;
    }

    let job_id = hdr.jobid_source?;
    if job_id == 0 {
        return None;
    }

    if config.achievements.offline_schema {
        queue_offline_response(AppId(app_id), job_id, hdr);
        return Some(Vec::new()); // empty = drop frame
    }

    let is_probe = req.sha_schema.is_some();
    if is_probe {
        req.sha_schema = None;
    }

    let ref_id = get_ref_steamid(stat_steam_ids, AppId(app_id));
    req.steamid = Some(ref_id);

    add_pending(job_id, AppId(app_id));
    info!(
        app_id,
        ref_id,
        probe = is_probe,
        "achievements: redirected stats request"
    );

    Some(req.encode_to_vec())
}

/// Process an outgoing Legacy (EMsg 818) CMsgClientGetUserStats request.
/// Returns `Some(modified_body_bytes)` if rewritten, `None` to pass through.
pub fn on_send_legacy_stats(
    body_bytes: &[u8],
    config: &RuntimeConfig,
    stat_steam_ids: &HashMap<AppId, u64>,
) -> Option<Vec<u8>> {
    let mut req = ClientGetUserStatsRequest::decode(body_bytes).ok()?;
    let game_id = req.game_id?;
    let app_id = game_id as u32;

    if !should_redirect(app_id, config) {
        return None;
    }

    if config.achievements.offline_schema {
        return Some(Vec::new());
    }

    let is_probe = req.crc_stats.is_some() || req.schema_local_version != Some(-1);
    req.crc_stats = None;
    req.schema_local_version = Some(-1);

    let ref_id = get_ref_steamid(stat_steam_ids, AppId(app_id));
    req.steam_id_for_user = Some(ref_id);
    add_legacy_pending(AppId(app_id));
    debug!(
        app_id,
        ref_id,
        probe = is_probe,
        "achievements: redirected legacy full-schema request"
    );
    Some(req.encode_to_vec())
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
    let app_id = AppId(response.game_id? as u32);
    if !should_redirect(app_id.0, config) {
        return None;
    }

    let matched = has_legacy_pending() && take_legacy_pending(app_id);
    let captured = matched
        .then_some(response.schema.as_ref())
        .flatten()
        .filter(|schema| !schema.is_empty())
        .map(|schema| CapturedAchievementSchema {
            app_id: app_id.0,
            schema_version: response.crc_stats.map(|crc| format!("crc32:{crc:08x}")),
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
            apps: vapor_forge_config::AppsSection {
                inject: vec![vapor_forge_config::InjectApp {
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
            ..Default::default()
        };
        let response = PlayerGetUserStatsResponse {
            sha_schema: Some(vec![0x12, 0xab, 0x00]),
            schema: Some(vec![0x00, 0x01, 0x02, 0x08]),
            stats: vec![PlayerStatsEntry {
                stat_id: Some(7),
                stat_value: Some(42),
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
}
