//! Achievement/stats schema interception.
//!
//! For controlled apps, outgoing stats requests have their SteamID rewritten
//! to a reference account so the server returns a valid schema. Incoming
//! responses have stat values cleared (schema is preserved) so Steam keeps
//! metadata but falls back to local cache for actual stats.
//!
//! Two message paths are supported:
//! - ServiceMethod (EMsg 151/147): Player.GetUserStats#1
//! - Legacy (EMsg 818/819): CMsgClientGetUserStats

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use prost::Message;
use tracing::{debug, info};
use vapor_forge_abi::*;
use vapor_forge_config::{AppId, RuntimeConfig};

pub const STATS_JOB_NAME: &str = "Player.GetUserStats#1";
const DEFAULT_REF_STEAMID: u64 = 76561198028121353;

// ---------------------------------------------------------------------------
// Donor SteamID registry
// ---------------------------------------------------------------------------

static STAT_STEAM_IDS: Mutex<Option<HashMap<AppId, u64>>> = Mutex::new(None);

pub fn set_stat_steamid(app_id: AppId, steamid: u64) {
    let mut guard = STAT_STEAM_IDS.lock().unwrap();
    guard
        .get_or_insert_with(HashMap::new)
        .insert(app_id, steamid);
}

pub fn load_stat_steam_ids(ids: &HashMap<AppId, u64>) {
    if ids.is_empty() {
        return;
    }
    let mut guard = STAT_STEAM_IDS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    map.extend(ids.iter().map(|(&k, &v)| (k, v)));
}

fn get_ref_steamid(app_id: AppId) -> u64 {
    STAT_STEAM_IDS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&app_id).copied())
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
    let total: usize = map.values().sum();
    LEGACY_PENDING_COUNT.store(total, Ordering::Release);
}

fn take_legacy_pending(app_id: AppId) -> bool {
    let mut guard = LEGACY_PENDING.lock().unwrap();
    let map = match guard.as_mut() {
        Some(m) => m,
        None => return false,
    };
    let count = match map.get_mut(&app_id) {
        Some(c) if *c > 0 => c,
        _ => return false,
    };
    *count -= 1;
    if *count == 0 {
        map.remove(&app_id);
    }
    let total: usize = map.values().sum();
    LEGACY_PENDING_COUNT.store(total, Ordering::Release);
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
    config.app_category(AppId(app_id)).is_some() && !crate::apps::is_actually_owned(AppId(app_id))
}

/// Process an outgoing ServiceMethod (EMsg 151) Player.GetUserStats#1 request.
/// Returns `Some(modified_body_bytes)` if the request was rewritten, `None` to pass through.
pub fn on_send_service_stats(
    hdr: &CMsgProtoBufHeader,
    body_bytes: &[u8],
    config: &RuntimeConfig,
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

    let ref_id = get_ref_steamid(AppId(app_id));
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
pub fn on_send_legacy_stats(body_bytes: &[u8], config: &RuntimeConfig) -> Option<Vec<u8>> {
    let mut req = ClientGetUserStatsRequest::decode(body_bytes).ok()?;
    let game_id = req.game_id?;
    let app_id = game_id as u32;

    if req.schema_local_version != Some(-1) {
        return None;
    }
    if !should_redirect(app_id, config) {
        return None;
    }

    if config.achievements.offline_schema {
        return Some(Vec::new()); // drop frame
    }

    let ref_id = get_ref_steamid(AppId(app_id));
    req.steam_id_for_user = Some(ref_id);

    add_legacy_pending(AppId(app_id));
    debug!(app_id, "achievements: redirected legacy stats request");

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
) -> Option<(Vec<u8>, Vec<u8>)> {
    let job_id = hdr.jobid_target?;
    let app_id = take_pending(job_id)?;

    let mut resp = PlayerGetUserStatsResponse::decode(body_bytes).ok()?;
    resp.stats.clear();

    let mut new_hdr = hdr.clone();
    new_hdr.eresult = Some(ERESULT_OK);

    info!(
        app_id = app_id.0,
        "achievements: cleared stats from response"
    );
    Some((new_hdr.encode_to_vec(), resp.encode_to_vec()))
}

/// Process an incoming Legacy response (EMsg 819) for stats.
/// Returns `Some(new_body_bytes)` if response was stripped, `None` to pass through.
pub fn on_recv_legacy_stats(body_bytes: &[u8], config: &RuntimeConfig) -> Option<Vec<u8>> {
    let mut resp = ClientGetUserStatsResponse::decode(body_bytes).ok()?;
    let game_id = resp.game_id?;
    let app_id = game_id as u32;

    if !should_redirect(app_id, config) {
        return None;
    }

    let matched = has_legacy_pending() && take_legacy_pending(AppId(app_id));

    resp.stats.clear();
    resp.achievement_blocks.clear();
    resp.eresult = Some(ERESULT_OK);

    debug!(
        app_id,
        matched_pending = matched,
        "achievements: cleared legacy stats response"
    );
    Some(resp.encode_to_vec())
}
