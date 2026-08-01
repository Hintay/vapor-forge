#![forbid(unsafe_code)]

//! Proxying of Steam's user-stats requests.
//!
//! Controlled apps have no stats of their own on Valve's servers, so a request
//! is redirected to a donor account that owns the app. The donor answer carries
//! the authoritative schema; the values are then replaced with whatever the
//! configured cloud backend holds before the merged response is injected back
//! into Steam. Backend reads run on a worker thread so Steam's network thread
//! never blocks on HTTP.

use prost::Message;
use std::collections::VecDeque;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use vapor_forge_cloud_core::{AppStatsQuery, AppStatsResult};
use vapor_forge_features::achievements;
use vapor_forge_features::identity;
use vapor_forge_features::valve_filter;
use vapor_forge_packet_capture::{PacketChange, PacketDirection};
use vapor_forge_steam_protocol::{
    app_id_from_game_id, CMsgProtoBufHeader, ClientGetUserStatsRequest, ClientGetUserStatsResponse,
    PlayerGetUserStatsRequest, PlayerGetUserStatsResponse, EMSG_REQUEST_USERSTATS_RESPONSE,
    ERESULT_NO_CONNECTION, ERESULT_OK,
};

use vapor_forge_config::AppId;

use super::router::{
    capture_dropped, queue_local_response, queue_local_response_for_generation, RecvFrameDecision,
    SendFrameDecision,
};

const MAX_BACKEND_STATS_REQUESTS: usize = 64;
const PENDING_STATS_LIFETIME: Duration = Duration::from_secs(120);

static PENDING_BACKEND_STATS: once_cell::sync::Lazy<Mutex<VecDeque<PendingStatsRequest>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(VecDeque::new()));
static BACKEND_STATS_WORKER: once_cell::sync::Lazy<Option<SyncSender<BackendStatsRequest>>> =
    once_cell::sync::Lazy::new(start_backend_stats_worker);

pub(super) fn handle_proxy_service_stats(
    emsg_raw: u32,
    header_bytes: &[u8],
    body: &[u8],
    original_packet: &[u8],
    config: &vapor_forge_config::RuntimeConfig,
    stat_steam_ids: &std::collections::HashMap<AppId, u64>,
) -> Option<SendFrameDecision> {
    let hdr = CMsgProtoBufHeader::decode(header_bytes).ok()?;
    let request = PlayerGetUserStatsRequest::decode(body).ok()?;
    match achievements::plan_send_service_stats(
        &hdr,
        body,
        config,
        stat_steam_ids,
        vapor_forge_features::apps::actual_ownership,
    ) {
        achievements::StatsSendPlan::Pass => None,
        achievements::StatsSendPlan::DropOffline { app_id, .. } => {
            queue_local_response(service_stats_failure(header_bytes));
            info!(app_id = app_id.0, "netpacket: answered stats offline");
            capture_dropped(original_packet);
            Some(SendFrameDecision::Drop)
        }
        achievements::StatsSendPlan::Rewrite {
            app_id,
            body,
            donor_steam_id,
            job_id: Some(job_id),
            was_probe,
        } => {
            let pending = PendingStatsRequest {
                app_id: app_id.0,
                queued_at: Instant::now(),
                guard: stats_request_guard(),
                context: backend_stats_context(),
                kind: PendingStatsRequestKind::Service {
                    header_bytes: header_bytes.to_vec(),
                    request,
                },
            };
            if !push_pending_service_stats(job_id, pending) {
                warn!(app_id = app_id.0, "netpacket: stats proxy queue full");
                queue_local_response(service_stats_failure(header_bytes));
                capture_dropped(original_packet);
                return Some(SendFrameDecision::Drop);
            }
            let replacement =
                vapor_forge_steam_protocol::assemble_raw(emsg_raw, header_bytes, &body);
            info!(
                app_id = app_id.0,
                ref_id = donor_steam_id,
                probe = was_probe,
                "netpacket: redirected stats request for Valve schema"
            );
            crate::packet_capture::capture(
                PacketDirection::Send,
                original_packet,
                PacketChange::Rewritten,
                Some(replacement.len()),
            );
            Some(SendFrameDecision::Rewrite(replacement))
        }
        achievements::StatsSendPlan::Rewrite { job_id: None, .. } => {
            unreachable!("service stats proxy requires a job id")
        }
    }
}

pub(super) fn handle_proxy_legacy_stats(
    emsg_raw: u32,
    header_bytes: &[u8],
    body: &[u8],
    original_packet: &[u8],
    config: &vapor_forge_config::RuntimeConfig,
    stat_steam_ids: &std::collections::HashMap<AppId, u64>,
) -> Option<SendFrameDecision> {
    let request = ClientGetUserStatsRequest::decode(body).ok()?;
    match achievements::plan_send_legacy_stats(
        body,
        config,
        stat_steam_ids,
        vapor_forge_features::apps::actual_ownership,
    ) {
        achievements::StatsSendPlan::Pass => None,
        achievements::StatsSendPlan::DropOffline { app_id, .. } => {
            queue_local_response(legacy_stats_failure(header_bytes, request.game_id));
            info!(
                app_id = app_id.0,
                "netpacket: answered legacy stats offline"
            );
            capture_dropped(original_packet);
            Some(SendFrameDecision::Drop)
        }
        achievements::StatsSendPlan::Rewrite {
            app_id,
            body,
            donor_steam_id,
            job_id: None,
            was_probe,
        } => {
            let game_id = request.game_id;
            let pending = PendingStatsRequest {
                app_id: app_id.0,
                queued_at: Instant::now(),
                guard: stats_request_guard(),
                context: backend_stats_context(),
                kind: PendingStatsRequestKind::Legacy {
                    header_bytes: header_bytes.to_vec(),
                    request,
                },
            };
            if !push_pending_legacy_stats(app_id.0, pending) {
                warn!(
                    app_id = app_id.0,
                    "netpacket: legacy stats proxy queue full"
                );
                queue_local_response(legacy_stats_failure(header_bytes, game_id));
                capture_dropped(original_packet);
                return Some(SendFrameDecision::Drop);
            }
            let replacement =
                vapor_forge_steam_protocol::assemble_raw(emsg_raw, header_bytes, &body);
            debug!(
                app_id = app_id.0,
                ref_id = donor_steam_id,
                probe = was_probe,
                "netpacket: redirected legacy stats request for Valve schema"
            );
            crate::packet_capture::capture(
                PacketDirection::Send,
                original_packet,
                PacketChange::Rewritten,
                Some(replacement.len()),
            );
            Some(SendFrameDecision::Rewrite(replacement))
        }
        achievements::StatsSendPlan::Rewrite {
            job_id: Some(_), ..
        } => unreachable!("legacy stats proxy does not use a job id"),
    }
}

struct BackendStatsRequest {
    app_id: u32,
    context: BackendStatsContext,
    kind: PendingStatsRequestKind,
    donor: DonorStatsResponse,
    full_schema: Vec<u8>,
    schema_version: String,
    response_generation: u64,
}

struct PendingStatsRequest {
    app_id: u32,
    queued_at: Instant,
    guard: StatsRequestGuard,
    context: Option<BackendStatsContext>,
    kind: PendingStatsRequestKind,
}

enum PendingStatsRequestKind {
    Service {
        header_bytes: Vec<u8>,
        request: PlayerGetUserStatsRequest,
    },
    Legacy {
        header_bytes: Vec<u8>,
        request: ClientGetUserStatsRequest,
    },
}

enum DonorStatsResponse {
    Service(PlayerGetUserStatsResponse),
    Legacy(ClientGetUserStatsResponse),
}

fn start_backend_stats_worker() -> Option<SyncSender<BackendStatsRequest>> {
    let (sender, receiver) = mpsc::sync_channel(MAX_BACKEND_STATS_REQUESTS);
    if std::thread::Builder::new()
        .name("stats-request".into())
        .spawn(move || {
            while let Ok(request) = receiver.recv() {
                process_backend_stats_request(request);
            }
        })
        .is_err()
    {
        warn!("netpacket: failed to start backend stats worker");
        return None;
    }
    Some(sender)
}

fn try_send_bounded<T>(sender: Option<&SyncSender<T>>, request: T) -> Result<(), T> {
    let Some(sender) = sender else {
        return Err(request);
    };
    match sender.try_send(request) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(request)) | Err(TrySendError::Disconnected(request)) => Err(request),
    }
}

fn process_backend_stats_request(request: BackendStatsRequest) {
    let app_id = request.app_id;
    let context = &request.context;
    let steam_id64 = context.steam_id64.to_string();
    if !backend_stats_context_still_current(context) {
        debug!(
            app_id,
            "netpacket: completing stale backend stats request from donor schema"
        );
        inject_schema_only_stats_response(
            request.kind,
            request.donor,
            &request.full_schema,
            app_id,
            request.response_generation,
        );
        return;
    }
    let backend = if backend_query_blocked_by_pending_stats(context, &steam_id64, app_id) {
        None
    } else {
        let query = AppStatsQuery {
            app_id,
            client_crc_stats: request.kind.client_crc_stats(),
            schema_version: request.schema_version.clone(),
        };
        match context
            .backend
            .pull_app_stats(context.client_id, &steam_id64, &query)
        {
            Ok(result) => Some(result),
            Err(error) => {
                warn!(%error, app_id, "netpacket: backend app stats pull failed");
                None
            }
        }
    };
    if !backend_stats_context_still_current(context) {
        debug!(
            app_id,
            "netpacket: completing stale backend stats response from donor schema"
        );
        inject_schema_only_stats_response(
            request.kind,
            request.donor,
            &request.full_schema,
            app_id,
            request.response_generation,
        );
        return;
    }
    inject_merged_stats_response(
        request.kind,
        request.donor,
        &request.full_schema,
        backend.as_ref(),
        app_id,
        request.response_generation,
    );
}

fn backend_query_blocked_by_pending_stats(
    context: &BackendStatsContext,
    steam_id64: &str,
    app_id: u32,
) -> bool {
    let owner_scope = match crate::sync_journal::principal_scope(context.backend.as_ref()) {
        Ok(scope) => scope,
        Err(error) => {
            warn!(%error, app_id, "netpacket: backend principal unavailable for stats pull");
            return true;
        }
    };
    crate::achievement_worker::has_pending_stats(&owner_scope, steam_id64, app_id)
}

fn inject_merged_stats_response(
    kind: PendingStatsRequestKind,
    donor: DonorStatsResponse,
    full_schema: &[u8],
    backend: Option<&AppStatsResult>,
    app_id: u32,
    response_generation: u64,
) {
    let packet = match (kind, donor) {
        (
            PendingStatsRequestKind::Service {
                header_bytes,
                request,
            },
            DonorStatsResponse::Service(donor),
        ) => {
            let body = crate::stats_merge::merge_service_stats_response(
                &request,
                donor.clone(),
                full_schema,
                backend,
            )
            .or_else(|| {
                crate::stats_merge::merge_service_stats_response(&request, donor, full_schema, None)
            });
            let Some(body) = body else {
                queue_local_response_for_generation(
                    service_stats_failure(&header_bytes),
                    response_generation,
                );
                return;
            };
            valve_filter::service_response(&header_bytes, body, ERESULT_OK)
        }
        (
            PendingStatsRequestKind::Legacy {
                header_bytes,
                request,
            },
            DonorStatsResponse::Legacy(donor),
        ) => {
            let body = crate::stats_merge::merge_legacy_stats_response(
                &request,
                donor.clone(),
                full_schema,
                backend,
            )
            .or_else(|| {
                crate::stats_merge::merge_legacy_stats_response(&request, donor, full_schema, None)
            });
            let Some(body) = body else {
                queue_local_response_for_generation(
                    legacy_stats_failure(&header_bytes, request.game_id),
                    response_generation,
                );
                return;
            };
            valve_filter::emsg_response(EMSG_REQUEST_USERSTATS_RESPONSE, &header_bytes, body)
        }
        (PendingStatsRequestKind::Service { header_bytes, .. }, DonorStatsResponse::Legacy(_)) => {
            queue_local_response_for_generation(
                service_stats_failure(&header_bytes),
                response_generation,
            );
            return;
        }
        (
            PendingStatsRequestKind::Legacy {
                header_bytes,
                request,
            },
            DonorStatsResponse::Service(_),
        ) => {
            queue_local_response_for_generation(
                legacy_stats_failure(&header_bytes, request.game_id),
                response_generation,
            );
            return;
        }
    };
    info!(
        app_id,
        "netpacket: answered stats through Valve schema and backend state"
    );
    queue_local_response_for_generation(packet, response_generation);
}

fn inject_schema_only_stats_response(
    kind: PendingStatsRequestKind,
    donor: DonorStatsResponse,
    full_schema: &[u8],
    app_id: u32,
    response_generation: u64,
) {
    inject_merged_stats_response(kind, donor, full_schema, None, app_id, response_generation);
}

fn service_stats_failure(header_bytes: &[u8]) -> Vec<u8> {
    valve_filter::service_response(
        header_bytes,
        PlayerGetUserStatsResponse::default().encode_to_vec(),
        ERESULT_NO_CONNECTION,
    )
}

fn legacy_stats_failure(header_bytes: &[u8], game_id: Option<u64>) -> Vec<u8> {
    valve_filter::emsg_response(
        EMSG_REQUEST_USERSTATS_RESPONSE,
        header_bytes,
        ClientGetUserStatsResponse {
            game_id,
            eresult: Some(ERESULT_NO_CONNECTION),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

impl PendingStatsRequestKind {
    fn client_crc_stats(&self) -> Option<u32> {
        match self {
            Self::Service { request, .. } => request.crc_stats,
            Self::Legacy { request, .. } => request.crc_stats,
        }
    }
}

fn push_pending_service_stats(job_id: u64, pending: PendingStatsRequest) -> bool {
    prune_pending_stats();
    let mut queue = PENDING_BACKEND_STATS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    queue.retain(|entry| {
        !matches!(&entry.kind, PendingStatsRequestKind::Service { header_bytes, .. }
        if CMsgProtoBufHeader::decode(header_bytes.as_slice())
            .ok()
            .and_then(|header| header.jobid_source)
            == Some(job_id))
    });
    if queue.len() >= MAX_BACKEND_STATS_REQUESTS {
        return false;
    }
    queue.push_back(pending);
    true
}

fn push_pending_legacy_stats(app_id: u32, pending: PendingStatsRequest) -> bool {
    prune_pending_stats();
    let mut queue = PENDING_BACKEND_STATS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    queue.retain(|entry| {
        !matches!(&entry.kind, PendingStatsRequestKind::Legacy { .. }) || entry.app_id != app_id
    });
    if queue.len() >= MAX_BACKEND_STATS_REQUESTS {
        return false;
    }
    queue.push_back(pending);
    true
}

fn take_pending_service_stats(job_id: u64) -> Option<PendingStatsRequest> {
    prune_pending_stats();
    let mut queue = PENDING_BACKEND_STATS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let position = queue.iter().position(|entry| {
        matches!(&entry.kind, PendingStatsRequestKind::Service { header_bytes, .. }
            if CMsgProtoBufHeader::decode(header_bytes.as_slice())
                .ok()
                .and_then(|header| header.jobid_source)
                == Some(job_id))
    })?;
    queue.remove(position)
}

fn take_pending_legacy_stats(app_id: u32) -> Option<PendingStatsRequest> {
    prune_pending_stats();
    let mut queue = PENDING_BACKEND_STATS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let position = queue.iter().position(|entry| {
        entry.app_id == app_id && matches!(&entry.kind, PendingStatsRequestKind::Legacy { .. })
    })?;
    queue.remove(position)
}

fn prune_pending_stats() {
    let now = Instant::now();
    let expired = {
        let mut queue = PENDING_BACKEND_STATS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut expired = Vec::new();
        let mut retained = VecDeque::with_capacity(queue.len());
        while let Some(entry) = queue.pop_front() {
            if now.saturating_duration_since(entry.queued_at) >= PENDING_STATS_LIFETIME {
                expired.push(entry);
            } else {
                retained.push_back(entry);
            }
        }
        *queue = retained;
        expired
    };
    for entry in expired {
        complete_pending_stats_failure(entry);
    }
}

pub(crate) fn notify_context_changed() {
    let pending = {
        let mut queue = PENDING_BACKEND_STATS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queue.drain(..).collect::<Vec<_>>()
    };
    for entry in pending {
        complete_pending_stats_failure(entry);
    }
}

fn complete_pending_stats_failure(entry: PendingStatsRequest) {
    let generation = entry.guard.injection_generation;
    let packet = match entry.kind {
        PendingStatsRequestKind::Service { header_bytes, .. } => {
            service_stats_failure(&header_bytes)
        }
        PendingStatsRequestKind::Legacy {
            header_bytes,
            request,
        } => legacy_stats_failure(&header_bytes, request.game_id),
    };
    queue_local_response_for_generation(packet, generation);
}

fn stats_schema_version(response: &PlayerGetUserStatsResponse) -> Option<String> {
    response
        .sha_schema
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(lower_hex)
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}

#[derive(Clone)]
struct StatsRequestGuard {
    credential_fingerprint: Option<String>,
    config: Arc<vapor_forge_config::RuntimeConfig>,
    client_id: Option<u64>,
    steam_id64: u64,
    identity_generation: u64,
    injection_generation: u64,
}

fn stats_request_guard() -> StatsRequestGuard {
    StatsRequestGuard {
        credential_fingerprint: crate::cloud_backend::backend_context()
            .map(|backend| backend.credential_fingerprint()),
        config: crate::client::install::config(),
        client_id: vapor_forge_cloud_core::device_descriptor()
            .map(|descriptor| descriptor.client_id),
        steam_id64: identity::steam_id(),
        identity_generation: identity::generation(),
        injection_generation: crate::client::network::injection_generation(),
    }
}

fn stats_request_guard_still_current(guard: &StatsRequestGuard) -> bool {
    identity::steam_id() == guard.steam_id64
        && identity::generation() == guard.identity_generation
        && vapor_forge_cloud_core::device_descriptor().map(|descriptor| descriptor.client_id)
            == guard.client_id
        && crate::cloud_backend::backend_context().map(|backend| backend.credential_fingerprint())
            == guard.credential_fingerprint
        && Arc::ptr_eq(&crate::client::install::config(), &guard.config)
        && crate::client::network::injection_generation() == guard.injection_generation
}
struct BackendStatsContext {
    backend: Arc<dyn vapor_forge_cloud_core::CloudBackend>,
    credential_fingerprint: String,
    config: Arc<vapor_forge_config::RuntimeConfig>,
    client_id: u64,
    steam_id64: u64,
    identity_generation: u64,
}

fn backend_stats_context() -> Option<BackendStatsContext> {
    let backend = crate::cloud_backend::backend_context()?;
    let credential_fingerprint = backend.credential_fingerprint();
    let descriptor = vapor_forge_cloud_core::device_descriptor()?;
    let steam_id64 = identity::steam_id();
    if steam_id64 == 0 {
        return None;
    }
    Some(BackendStatsContext {
        backend,
        credential_fingerprint,
        config: crate::client::install::config(),
        client_id: descriptor.client_id,
        steam_id64,
        identity_generation: identity::generation(),
    })
}

fn backend_stats_context_still_current(context: &BackendStatsContext) -> bool {
    identity::steam_id() == context.steam_id64
        && identity::generation() == context.identity_generation
        && vapor_forge_cloud_core::device_descriptor()
            .is_some_and(|descriptor| descriptor.client_id == context.client_id)
        && crate::cloud_backend::backend_context().is_some_and(|backend| {
            backend.credential_fingerprint() == context.credential_fingerprint
        })
        && Arc::ptr_eq(&crate::client::install::config(), &context.config)
}

fn register_stats_schema(app_id: u32, schema_version: Option<String>, schema: Vec<u8>) {
    if let Some(version) = schema_version.clone() {
        remember_schema_version(app_id, version);
    }
    crate::client::achievement::register_packet_schema(app_id, &schema);
    crate::achievement_worker::queue_schema(app_id, schema_version, schema);
}

/// Schema versions Valve supplied, kept per app for the life of the process.
///
/// Only the service response carries one. The legacy response has no field for it at
/// all, so a legacy request has to reuse whichever version was last seen for that
/// app, or name the schema by its own bytes when none ever was. Using one scheme per
/// app matters because a backend compares the version it stored against the one it
/// is given, and two schemes for one app would read as a permanent mismatch.
static SCHEMA_VERSIONS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<u32, String>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn remember_schema_version(app_id: u32, version: String) {
    if let Ok(mut versions) = SCHEMA_VERSIONS.lock() {
        versions.insert(app_id, version);
    }
}

/// The version to query a backend with for an app whose response carries none.
fn schema_version_for(app_id: u32, schema: &[u8]) -> String {
    if let Some(version) = SCHEMA_VERSIONS
        .lock()
        .ok()
        .and_then(|versions| versions.get(&app_id).cloned())
    {
        return version;
    }
    // Naming the schema by its own content is deterministic and always available.
    // It will not equal Valve's own hash, so an app first seen on the legacy path
    // and later on the service path presents two different names for one schema.
    // See SCHEMA_VERSIONS.
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(schema))
}

pub(super) fn handle_proxy_service_stats_response(
    hdr: &CMsgProtoBufHeader,
    body: &[u8],
) -> Option<RecvFrameDecision> {
    let job_id = hdr.jobid_target.filter(|job_id| *job_id != 0)?;
    let pending = take_pending_service_stats(job_id)?;
    let PendingStatsRequest {
        app_id,
        queued_at: _,
        guard,
        context,
        kind,
    } = pending;
    let response_generation = guard.injection_generation;
    let donor = match PlayerGetUserStatsResponse::decode(body) {
        Ok(donor) => donor,
        Err(error) => {
            warn!(%error, app_id, "netpacket: failed to decode donor stats response");
            inject_merged_stats_response(
                kind,
                DonorStatsResponse::Service(PlayerGetUserStatsResponse::default()),
                &[],
                None,
                app_id,
                response_generation,
            );
            return Some(RecvFrameDecision::Drop);
        }
    };
    if !stats_request_guard_still_current(&guard) {
        debug!(
            app_id,
            "netpacket: completing stale donor stats response from its schema"
        );
        let full_schema = donor.schema.as_deref().unwrap_or_default().to_vec();
        inject_schema_only_stats_response(
            kind,
            DonorStatsResponse::Service(donor),
            &full_schema,
            app_id,
            response_generation,
        );
        return Some(RecvFrameDecision::Drop);
    }
    let Some(full_schema) = donor
        .schema
        .as_ref()
        .filter(|schema| !schema.is_empty())
        .cloned()
    else {
        // Tokens were cleared on the way out, so Valve had no reason to omit the
        // schema other than there being none. Record that before answering, so a
        // baseline snapshot does not poll an empty stats map.
        crate::client::achievement::note_schema_unavailable(app_id);
        warn!(app_id, "netpacket: donor stats response omitted schema");
        inject_merged_stats_response(
            kind,
            DonorStatsResponse::Service(donor),
            &[],
            None,
            app_id,
            response_generation,
        );
        return Some(RecvFrameDecision::Drop);
    };
    let schema_version = stats_schema_version(&donor);
    register_stats_schema(app_id, schema_version.clone(), full_schema.clone());
    let donor = DonorStatsResponse::Service(donor);
    let Some(context) = context else {
        inject_schema_only_stats_response(kind, donor, &full_schema, app_id, response_generation);
        return Some(RecvFrameDecision::Drop);
    };
    let Some(schema_version) = schema_version else {
        inject_schema_only_stats_response(kind, donor, &full_schema, app_id, response_generation);
        return Some(RecvFrameDecision::Drop);
    };
    if !backend_stats_context_still_current(&context) {
        debug!(app_id, "netpacket: discarded stale backend stats context");
        return Some(RecvFrameDecision::Drop);
    }
    let backend_request = BackendStatsRequest {
        app_id,
        context,
        kind,
        donor,
        full_schema,
        schema_version,
        response_generation,
    };
    if let Err(request) = try_send_bounded(BACKEND_STATS_WORKER.as_ref(), backend_request) {
        warn!(app_id, "netpacket: backend stats worker queue full");
        let BackendStatsRequest {
            kind,
            donor,
            full_schema,
            response_generation,
            ..
        } = request;
        inject_schema_only_stats_response(kind, donor, &full_schema, app_id, response_generation);
    }
    Some(RecvFrameDecision::Drop)
}

pub(super) fn handle_proxy_legacy_stats_response(body: &[u8]) -> Option<RecvFrameDecision> {
    let donor = ClientGetUserStatsResponse::decode(body).ok()?;
    let app_id = donor.game_id.and_then(app_id_from_game_id)?;
    let pending = take_pending_legacy_stats(app_id)?;
    let PendingStatsRequest {
        app_id,
        queued_at: _,
        guard,
        context,
        kind,
    } = pending;
    let response_generation = guard.injection_generation;
    if !stats_request_guard_still_current(&guard) {
        debug!(
            app_id,
            "netpacket: completing stale legacy donor stats response from its schema"
        );
        let full_schema = donor.schema.as_deref().unwrap_or_default().to_vec();
        inject_schema_only_stats_response(
            kind,
            DonorStatsResponse::Legacy(donor),
            &full_schema,
            app_id,
            response_generation,
        );
        return Some(RecvFrameDecision::Drop);
    }
    let Some(full_schema) = donor
        .schema
        .as_ref()
        .filter(|schema| !schema.is_empty())
        .cloned()
    else {
        // See the service path above.
        crate::client::achievement::note_schema_unavailable(app_id);
        warn!(
            app_id,
            "netpacket: legacy donor stats response omitted schema"
        );
        inject_schema_only_stats_response(
            kind,
            DonorStatsResponse::Legacy(donor),
            &[],
            app_id,
            response_generation,
        );
        return Some(RecvFrameDecision::Drop);
    };
    register_stats_schema(app_id, None, full_schema.clone());
    // The backend context was captured with the request and then discarded here, so a
    // legacy request only ever received Valve's schema and none of the state this
    // runtime exists to serve. Route it through the same worker the service path
    // uses; `inject_merged_stats_response` already handles both response shapes.
    let Some(context) = context else {
        inject_schema_only_stats_response(
            kind,
            DonorStatsResponse::Legacy(donor),
            &full_schema,
            app_id,
            response_generation,
        );
        return Some(RecvFrameDecision::Drop);
    };
    if !backend_stats_context_still_current(&context) {
        debug!(app_id, "netpacket: discarded stale backend stats context");
        return Some(RecvFrameDecision::Drop);
    }
    let schema_version = schema_version_for(app_id, &full_schema);
    let backend_request = BackendStatsRequest {
        app_id,
        context,
        kind,
        donor: DonorStatsResponse::Legacy(donor),
        full_schema,
        schema_version,
        response_generation,
    };
    if let Err(request) = try_send_bounded(BACKEND_STATS_WORKER.as_ref(), backend_request) {
        warn!(app_id, "netpacket: backend stats worker queue full");
        let BackendStatsRequest {
            kind,
            donor,
            full_schema,
            response_generation,
            ..
        } = request;
        inject_schema_only_stats_response(kind, donor, &full_schema, app_id, response_generation);
    }
    Some(RecvFrameDecision::Drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_request_queue_is_bounded() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        assert!(try_send_bounded(Some(&sender), 1).is_ok());
        assert_eq!(try_send_bounded(Some(&sender), 2).unwrap_err(), 2);
        assert_eq!(try_send_bounded::<u32>(None, 3).unwrap_err(), 3);
    }
}
