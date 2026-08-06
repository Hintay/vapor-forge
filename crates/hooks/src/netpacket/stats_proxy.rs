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
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
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
    capture_dropped, queue_local_response_for_generation, RecvFrameDecision, SendFrameDecision,
};

const MAX_BACKEND_STATS_REQUESTS: usize = 64;
const PENDING_STATS_LIFETIME: Duration = Duration::from_secs(120);

static PENDING_BACKEND_STATS: once_cell::sync::Lazy<PendingStatsQueue> =
    once_cell::sync::Lazy::new(PendingStatsQueue::new);
static PENDING_STATS_DEADLINE_WORKER: once_cell::sync::Lazy<bool> =
    once_cell::sync::Lazy::new(start_pending_stats_deadline_worker);
static BACKEND_STATS_WORKER: once_cell::sync::Lazy<Option<SyncSender<BackendStatsRequest>>> =
    once_cell::sync::Lazy::new(start_backend_stats_worker);

pub(super) struct StatsProxyContext<'a> {
    runtime_generation: u64,
    injection_generation: u64,
    config: &'a Arc<vapor_forge_config::RuntimeConfig>,
    stat_steam_ids: &'a std::collections::HashMap<AppId, u64>,
}

impl<'a> StatsProxyContext<'a> {
    pub(super) fn new(
        runtime_generation: u64,
        injection_generation: u64,
        config: &'a Arc<vapor_forge_config::RuntimeConfig>,
        stat_steam_ids: &'a std::collections::HashMap<AppId, u64>,
    ) -> Self {
        Self {
            runtime_generation,
            injection_generation,
            config,
            stat_steam_ids,
        }
    }
}

pub(super) fn handle_proxy_service_stats(
    emsg_raw: u32,
    header_bytes: &[u8],
    body: &[u8],
    original_packet: &[u8],
    context: StatsProxyContext<'_>,
) -> Option<SendFrameDecision> {
    let StatsProxyContext {
        runtime_generation,
        injection_generation,
        config,
        stat_steam_ids,
    } = context;
    let hdr = CMsgProtoBufHeader::decode(header_bytes).ok()?;
    let request = PlayerGetUserStatsRequest::decode(body).ok()?;
    match achievements::plan_send_service_stats(
        &hdr,
        body,
        config.as_ref(),
        stat_steam_ids,
        vapor_forge_features::apps::actual_ownership,
    ) {
        achievements::StatsSendPlan::Pass => None,
        achievements::StatsSendPlan::DropOffline { app_id, .. } => {
            if !registration_context_still_current(runtime_generation, injection_generation, config)
            {
                return Some(SendFrameDecision::Retry);
            }
            if !crate::client::network::response_delivery_ready() {
                return Some(SendFrameDecision::Retry);
            }
            queue_local_response_for_generation(
                service_stats_failure(header_bytes),
                injection_generation,
            );
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
            if !crate::client::network::response_delivery_ready() {
                return Some(SendFrameDecision::Retry);
            }
            let (guard, context) =
                stats_request_state(runtime_generation, injection_generation, Arc::clone(config));
            let response_generation = guard.injection_generation;
            let pending = PendingStatsRequest {
                app_id: app_id.0,
                queued_at: Instant::now(),
                request_job_id: Some(job_id),
                terminal_response_sent: false,
                guard,
                context,
                kind: PendingStatsRequestKind::Service {
                    header_bytes: header_bytes.to_vec(),
                    request,
                },
            };
            match push_pending_stats(pending) {
                Ok(PushPendingStatsOutcome::Inserted | PushPendingStatsOutcome::Merged) => {}
                Ok(PushPendingStatsOutcome::Terminal) => {
                    debug!(
                        app_id = app_id.0,
                        job_id, "netpacket: dropped retry for terminal stats request"
                    );
                    capture_dropped(original_packet);
                    return Some(SendFrameDecision::Drop);
                }
                Err(PushPendingStatsError::Stale) => {
                    return Some(SendFrameDecision::Retry);
                }
                Err(PushPendingStatsError::Full | PushPendingStatsError::WorkerUnavailable) => {
                    warn!(
                        app_id = app_id.0,
                        "netpacket: stats proxy queue unavailable"
                    );
                    queue_local_response_for_generation(
                        service_stats_failure(header_bytes),
                        response_generation,
                    );
                    capture_dropped(original_packet);
                    return Some(SendFrameDecision::Drop);
                }
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
    context: StatsProxyContext<'_>,
) -> Option<SendFrameDecision> {
    let StatsProxyContext {
        runtime_generation,
        injection_generation,
        config,
        stat_steam_ids,
    } = context;
    let request_header = CMsgProtoBufHeader::decode(header_bytes).ok();
    let request_job_id = request_header
        .and_then(|header| header.jobid_source)
        .filter(|job_id| *job_id != 0);
    let request = ClientGetUserStatsRequest::decode(body).ok()?;
    match achievements::plan_send_legacy_stats(
        body,
        config.as_ref(),
        stat_steam_ids,
        vapor_forge_features::apps::actual_ownership,
    ) {
        achievements::StatsSendPlan::Pass => None,
        achievements::StatsSendPlan::DropOffline { app_id, .. } => {
            if !registration_context_still_current(runtime_generation, injection_generation, config)
            {
                return Some(SendFrameDecision::Retry);
            }
            if !crate::client::network::response_delivery_ready() {
                return Some(SendFrameDecision::Retry);
            }
            queue_local_response_for_generation(
                legacy_stats_failure(header_bytes, request.game_id),
                injection_generation,
            );
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
            if !crate::client::network::response_delivery_ready() {
                return Some(SendFrameDecision::Retry);
            }
            let game_id = request.game_id;
            let (guard, context) =
                stats_request_state(runtime_generation, injection_generation, Arc::clone(config));
            let response_generation = guard.injection_generation;
            let pending = PendingStatsRequest {
                app_id: app_id.0,
                queued_at: Instant::now(),
                request_job_id,
                terminal_response_sent: false,
                guard,
                context,
                kind: PendingStatsRequestKind::Legacy {
                    header_bytes: header_bytes.to_vec(),
                    request,
                },
            };
            match push_pending_stats(pending) {
                Ok(PushPendingStatsOutcome::Inserted | PushPendingStatsOutcome::Merged) => {}
                Ok(PushPendingStatsOutcome::Terminal) => {
                    debug!(
                        app_id = app_id.0,
                        request_job_id,
                        "netpacket: dropped retry for terminal legacy stats request"
                    );
                    capture_dropped(original_packet);
                    return Some(SendFrameDecision::Drop);
                }
                Err(PushPendingStatsError::Stale) => {
                    return Some(SendFrameDecision::Retry);
                }
                Err(PushPendingStatsError::Full | PushPendingStatsError::WorkerUnavailable) => {
                    warn!(
                        app_id = app_id.0,
                        "netpacket: legacy stats proxy queue unavailable"
                    );
                    queue_local_response_for_generation(
                        legacy_stats_failure(header_bytes, game_id),
                        response_generation,
                    );
                    capture_dropped(original_packet);
                    return Some(SendFrameDecision::Drop);
                }
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
    request_job_id: Option<u64>,
    terminal_response_sent: bool,
    guard: StatsRequestGuard,
    context: Option<BackendStatsContext>,
    kind: PendingStatsRequestKind,
}

struct PendingStatsFailure {
    packet: Vec<u8>,
    response_generation: u64,
}

struct PendingStatsQueue {
    entries: Mutex<VecDeque<PendingStatsRequest>>,
    changed: Condvar,
}

impl PendingStatsQueue {
    fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<PendingStatsRequest>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PushPendingStatsError {
    Full,
    Stale,
    WorkerUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PushPendingStatsOutcome {
    Inserted,
    Merged,
    Terminal,
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
    let blocked = backend_query_blocked_by_pending_stats(context, &steam_id64, app_id);
    if !backend_stats_context_still_current(context) {
        debug!(
            app_id,
            "netpacket: completing stale stats request after principal resolution"
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
    let backend = if blocked {
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

fn push_pending_stats(
    pending: PendingStatsRequest,
) -> Result<PushPendingStatsOutcome, PushPendingStatsError> {
    let pending_stats = &*PENDING_BACKEND_STATS;
    if !*PENDING_STATS_DEADLINE_WORKER {
        return Err(PushPendingStatsError::WorkerUnavailable);
    }
    let mut queue = pending_stats.lock();
    if !stats_request_guard_still_current(&pending.guard) {
        return Err(PushPendingStatsError::Stale);
    }
    let Some(outcome) = merge_pending_stats(&mut queue, pending) else {
        return Err(PushPendingStatsError::Full);
    };
    drop(queue);
    pending_stats.changed.notify_one();
    Ok(outcome)
}

fn merge_pending_stats(
    queue: &mut VecDeque<PendingStatsRequest>,
    pending: PendingStatsRequest,
) -> Option<PushPendingStatsOutcome> {
    if let Some(position) = queue
        .iter()
        .position(|entry| same_pending_stats_correlation(entry, &pending))
    {
        if queue[position].terminal_response_sent {
            return Some(PushPendingStatsOutcome::Terminal);
        }
        // A false send result makes Steam submit the frame again. The deadline
        // follows the latest forwarding attempt.
        queue[position] = pending;
        return Some(PushPendingStatsOutcome::Merged);
    }
    if queue.len() >= MAX_BACKEND_STATS_REQUESTS {
        return None;
    }
    queue.push_back(pending);
    Some(PushPendingStatsOutcome::Inserted)
}

fn same_pending_stats_correlation(left: &PendingStatsRequest, right: &PendingStatsRequest) -> bool {
    if left.guard.injection_generation != right.guard.injection_generation {
        return false;
    }
    match (&left.kind, &right.kind) {
        (PendingStatsRequestKind::Service { .. }, PendingStatsRequestKind::Service { .. }) => {
            matches!(
                (left.request_job_id, right.request_job_id),
                (Some(left), Some(right)) if left == right
            )
        }
        (PendingStatsRequestKind::Legacy { .. }, PendingStatsRequestKind::Legacy { .. }) => {
            match (left.request_job_id, right.request_job_id) {
                (Some(left), Some(right)) => left == right,
                (None, None) => left.app_id == right.app_id,
                _ => false,
            }
        }
        _ => false,
    }
}

fn take_pending_service_stats(job_id: u64) -> Option<PendingStatsRequest> {
    take_pending_stats(|queue| pending_service_position(queue, job_id))
}

fn take_pending_legacy_stats(
    response_job_id: Option<u64>,
    app_id: Option<u32>,
) -> Option<PendingStatsRequest> {
    take_pending_stats(|queue| pending_legacy_position(queue, response_job_id, app_id))
}

fn take_pending_stats(
    position: impl FnOnce(&VecDeque<PendingStatsRequest>) -> Option<usize>,
) -> Option<PendingStatsRequest> {
    let pending_stats = &*PENDING_BACKEND_STATS;
    let mut queue = pending_stats.lock();
    let position = position(&queue)?;
    let pending = queue.remove(position);
    drop(queue);
    pending_stats.changed.notify_one();
    pending
}

fn pending_service_position(queue: &VecDeque<PendingStatsRequest>, job_id: u64) -> Option<usize> {
    queue.iter().position(|entry| {
        matches!(&entry.kind, PendingStatsRequestKind::Service { .. })
            && entry.request_job_id == Some(job_id)
    })
}

fn pending_legacy_position(
    queue: &VecDeque<PendingStatsRequest>,
    response_job_id: Option<u64>,
    app_id: Option<u32>,
) -> Option<usize> {
    match response_job_id {
        Some(job_id) => queue.iter().position(|entry| {
            matches!(&entry.kind, PendingStatsRequestKind::Legacy { .. })
                && entry.request_job_id == Some(job_id)
        }),
        None => {
            let app_id = app_id?;
            queue.iter().position(|entry| {
                entry.app_id == app_id
                    && matches!(&entry.kind, PendingStatsRequestKind::Legacy { .. })
            })
        }
    }
}

fn start_pending_stats_deadline_worker() -> bool {
    std::thread::Builder::new()
        .name("stats-deadline".into())
        .spawn(|| pending_stats_deadline_loop(&PENDING_BACKEND_STATS, PENDING_STATS_LIFETIME))
        .map(|_| true)
        .unwrap_or_else(|error| {
            warn!(%error, "netpacket: failed to start stats deadline worker");
            false
        })
}

fn pending_stats_deadline_loop(pending_stats: &'static PendingStatsQueue, lifetime: Duration) {
    loop {
        for failure in wait_for_expired_pending_stats(pending_stats, lifetime) {
            complete_pending_stats_failure(failure);
        }
    }
}

fn wait_for_expired_pending_stats(
    pending_stats: &PendingStatsQueue,
    lifetime: Duration,
) -> Vec<PendingStatsFailure> {
    let mut queue = pending_stats.lock();
    loop {
        let now = Instant::now();
        let expired = take_expired_pending_stats(&mut queue, now, lifetime);
        if !expired.is_empty() {
            return expired;
        }

        let Some(deadline) = earliest_pending_stats_deadline(&queue, lifetime) else {
            queue = pending_stats
                .changed
                .wait(queue)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            continue;
        };
        let wait = deadline.saturating_duration_since(now);
        let (next, _) = pending_stats
            .changed
            .wait_timeout(queue, wait)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queue = next;
    }
}

fn earliest_pending_stats_deadline(
    queue: &VecDeque<PendingStatsRequest>,
    lifetime: Duration,
) -> Option<Instant> {
    queue
        .iter()
        .filter(|entry| !entry.terminal_response_sent)
        .map(|entry| entry.queued_at + lifetime)
        .min()
}

fn take_expired_pending_stats(
    queue: &mut VecDeque<PendingStatsRequest>,
    now: Instant,
    lifetime: Duration,
) -> Vec<PendingStatsFailure> {
    let mut expired = Vec::new();
    let mut retained = VecDeque::with_capacity(queue.len());
    while let Some(mut entry) = queue.pop_front() {
        if entry.terminal_response_sent || now.saturating_duration_since(entry.queued_at) < lifetime
        {
            retained.push_back(entry);
            continue;
        }

        expired.push(pending_stats_failure(&entry));
        entry.terminal_response_sent = true;
        retained.push_back(entry);
    }
    *queue = retained;
    expired
}

pub(crate) fn notify_context_changed() {
    let pending_stats = &*PENDING_BACKEND_STATS;
    let current_generation = crate::client::network::injection_generation();
    let failures = terminalize_pending_stats(&mut pending_stats.lock(), current_generation);
    pending_stats.changed.notify_one();
    for failure in failures {
        complete_pending_stats_failure(failure);
    }
}

fn terminalize_pending_stats(
    queue: &mut VecDeque<PendingStatsRequest>,
    current_generation: u64,
) -> Vec<PendingStatsFailure> {
    let mut failures = Vec::new();
    let mut retained = VecDeque::with_capacity(queue.len());
    while let Some(mut entry) = queue.pop_front() {
        if entry.guard.injection_generation != current_generation {
            continue;
        }
        if !entry.terminal_response_sent {
            failures.push(pending_stats_failure(&entry));
            entry.terminal_response_sent = true;
        }
        retained.push_back(entry);
    }
    *queue = retained;
    failures
}

fn pending_stats_failure(entry: &PendingStatsRequest) -> PendingStatsFailure {
    let packet = match &entry.kind {
        PendingStatsRequestKind::Service { header_bytes, .. } => {
            service_stats_failure(header_bytes)
        }
        PendingStatsRequestKind::Legacy {
            header_bytes,
            request,
        } => legacy_stats_failure(header_bytes, request.game_id),
    };
    PendingStatsFailure {
        packet,
        response_generation: entry.guard.injection_generation,
    }
}

fn complete_pending_stats_failure(failure: PendingStatsFailure) {
    queue_local_response_for_generation(failure.packet, failure.response_generation);
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
    runtime_generation: u64,
    client_id: Option<u64>,
    steam_id64: u64,
    identity_generation: u64,
    injection_generation: u64,
}

fn stats_request_state(
    runtime_generation: u64,
    injection_generation: u64,
    config: Arc<vapor_forge_config::RuntimeConfig>,
) -> (StatsRequestGuard, Option<BackendStatsContext>) {
    let backend = crate::cloud_backend::backend_context();
    let credential_fingerprint = backend
        .as_ref()
        .map(|backend| backend.credential_fingerprint());
    let client_id =
        vapor_forge_cloud_core::device_descriptor().map(|descriptor| descriptor.client_id);
    let steam_id64 = identity::steam_id();
    let identity_generation = identity::generation();
    let guard = StatsRequestGuard {
        credential_fingerprint: credential_fingerprint.clone(),
        config: Arc::clone(&config),
        runtime_generation,
        client_id,
        steam_id64,
        identity_generation,
        injection_generation,
    };
    let context = match (backend, credential_fingerprint, client_id) {
        (Some(backend), Some(credential_fingerprint), Some(client_id)) if steam_id64 != 0 => {
            Some(BackendStatsContext {
                backend,
                credential_fingerprint,
                config,
                runtime_generation,
                client_id,
                steam_id64,
                identity_generation,
            })
        }
        _ => None,
    };
    (guard, context)
}

fn stats_request_guard_still_current(guard: &StatsRequestGuard) -> bool {
    identity::steam_id() == guard.steam_id64
        && identity::generation() == guard.identity_generation
        && vapor_forge_cloud_core::device_descriptor().map(|descriptor| descriptor.client_id)
            == guard.client_id
        && crate::cloud_backend::backend_context().map(|backend| backend.credential_fingerprint())
            == guard.credential_fingerprint
        && crate::client::install::runtime_generation() == guard.runtime_generation
        && Arc::ptr_eq(&crate::client::install::config(), &guard.config)
        && crate::client::network::injection_generation() == guard.injection_generation
}

fn registration_context_still_current(
    runtime_generation: u64,
    injection_generation: u64,
    config: &Arc<vapor_forge_config::RuntimeConfig>,
) -> bool {
    let current = crate::client::install::runtime_snapshot();
    current.generation == runtime_generation
        && Arc::ptr_eq(&current.config, config)
        && crate::client::network::injection_generation() == injection_generation
}

struct BackendStatsContext {
    backend: Arc<dyn vapor_forge_cloud_core::CloudBackend>,
    credential_fingerprint: String,
    config: Arc<vapor_forge_config::RuntimeConfig>,
    runtime_generation: u64,
    client_id: u64,
    steam_id64: u64,
    identity_generation: u64,
}

fn backend_stats_context_still_current(context: &BackendStatsContext) -> bool {
    identity::steam_id() == context.steam_id64
        && identity::generation() == context.identity_generation
        && vapor_forge_cloud_core::device_descriptor()
            .is_some_and(|descriptor| descriptor.client_id == context.client_id)
        && crate::cloud_backend::backend_context().is_some_and(|backend| {
            backend.credential_fingerprint() == context.credential_fingerprint
        })
        && crate::client::install::runtime_generation() == context.runtime_generation
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
        request_job_id: _,
        terminal_response_sent,
        guard,
        context,
        kind,
    } = pending;
    if terminal_response_sent {
        debug!(
            app_id,
            job_id, "netpacket: discarded donor stats response after terminal reply"
        );
        return Some(RecvFrameDecision::Drop);
    }
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
        inject_schema_only_stats_response(kind, donor, &full_schema, app_id, response_generation);
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

pub(super) fn handle_proxy_legacy_stats_response(
    hdr: &CMsgProtoBufHeader,
    body: &[u8],
) -> Option<RecvFrameDecision> {
    let donor = ClientGetUserStatsResponse::decode(body).ok()?;
    let response_job_id = hdr.jobid_target.filter(|job_id| *job_id != 0);
    let response_app_id = donor.game_id.and_then(app_id_from_game_id);
    let pending = take_pending_legacy_stats(response_job_id, response_app_id)?;
    let PendingStatsRequest {
        app_id,
        queued_at: _,
        request_job_id: _,
        terminal_response_sent,
        guard,
        context,
        kind,
    } = pending;
    if terminal_response_sent {
        debug!(
            app_id,
            response_job_id,
            "netpacket: discarded legacy donor stats response after terminal reply"
        );
        return Some(RecvFrameDecision::Drop);
    }
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
    // Both response shapes use the same backend merge worker.
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
        inject_schema_only_stats_response(
            kind,
            DonorStatsResponse::Legacy(donor),
            &full_schema,
            app_id,
            response_generation,
        );
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

    fn pending_legacy(
        app_id: u32,
        request_job_id: Option<u64>,
        queued_at: Instant,
    ) -> PendingStatsRequest {
        PendingStatsRequest {
            app_id,
            queued_at,
            request_job_id,
            terminal_response_sent: false,
            guard: StatsRequestGuard {
                credential_fingerprint: None,
                config: Arc::new(vapor_forge_config::RuntimeConfig::default()),
                runtime_generation: 0,
                client_id: None,
                steam_id64: 0,
                identity_generation: 0,
                injection_generation: 0,
            },
            context: None,
            kind: PendingStatsRequestKind::Legacy {
                header_bytes: Vec::new(),
                request: ClientGetUserStatsRequest {
                    game_id: Some(app_id as u64),
                    ..Default::default()
                },
            },
        }
    }

    fn pending_service(app_id: u32, job_id: u64, queued_at: Instant) -> PendingStatsRequest {
        let mut pending = pending_legacy(app_id, Some(job_id), queued_at);
        pending.kind = PendingStatsRequestKind::Service {
            header_bytes: CMsgProtoBufHeader {
                jobid_source: Some(job_id),
                ..Default::default()
            }
            .encode_to_vec(),
            request: PlayerGetUserStatsRequest::default(),
        };
        pending
    }

    #[test]
    fn stats_request_queue_is_bounded() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        assert!(try_send_bounded(Some(&sender), 1).is_ok());
        assert_eq!(try_send_bounded(Some(&sender), 2).unwrap_err(), 2);
        assert_eq!(try_send_bounded::<u32>(None, 3).unwrap_err(), 3);
    }

    #[test]
    fn service_retry_merges_only_the_same_connection_and_job() {
        let now = Instant::now();
        let mut queue = VecDeque::from([pending_service(10, 41, now)]);

        assert_eq!(
            merge_pending_stats(
                &mut queue,
                pending_service(10, 41, now + Duration::from_secs(1)),
            ),
            Some(PushPendingStatsOutcome::Merged)
        );
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].queued_at, now + Duration::from_secs(1));

        let mut next_generation = pending_service(10, 41, now);
        next_generation.guard.injection_generation = 1;
        assert_eq!(
            merge_pending_stats(&mut queue, next_generation),
            Some(PushPendingStatsOutcome::Inserted)
        );
        assert_eq!(
            merge_pending_stats(&mut queue, pending_legacy(10, Some(41), now)),
            Some(PushPendingStatsOutcome::Inserted)
        );
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn legacy_retry_prefers_job_id_and_falls_back_to_app_without_one() {
        let now = Instant::now();
        let mut queue = VecDeque::from([pending_legacy(10, Some(41), now)]);

        assert_eq!(
            merge_pending_stats(&mut queue, pending_legacy(10, Some(42), now)),
            Some(PushPendingStatsOutcome::Inserted)
        );
        assert_eq!(
            merge_pending_stats(&mut queue, pending_legacy(11, Some(41), now)),
            Some(PushPendingStatsOutcome::Merged)
        );
        assert_eq!(queue.len(), 2);
        assert_eq!(queue[0].app_id, 11);

        assert_eq!(
            merge_pending_stats(&mut queue, pending_legacy(10, None, now)),
            Some(PushPendingStatsOutcome::Inserted)
        );
        assert_eq!(
            merge_pending_stats(
                &mut queue,
                pending_legacy(10, None, now + Duration::from_secs(1)),
            ),
            Some(PushPendingStatsOutcome::Merged)
        );
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn terminal_correlation_is_not_replaced_or_excluded_from_capacity() {
        let now = Instant::now();
        let mut terminal = pending_service(10, 41, now);
        terminal.terminal_response_sent = true;
        let mut queue = VecDeque::from([terminal]);
        for job_id in 42..(42 + MAX_BACKEND_STATS_REQUESTS as u64 - 1) {
            queue.push_back(pending_service(10, job_id, now));
        }
        assert_eq!(queue.len(), MAX_BACKEND_STATS_REQUESTS);

        assert_eq!(
            merge_pending_stats(
                &mut queue,
                pending_service(10, 41, now + Duration::from_secs(1)),
            ),
            Some(PushPendingStatsOutcome::Terminal)
        );
        assert!(queue[0].terminal_response_sent);
        assert_eq!(queue[0].queued_at, now);
        assert_eq!(
            merge_pending_stats(&mut queue, pending_service(10, 500, now)),
            None
        );
        assert_eq!(queue.len(), MAX_BACKEND_STATS_REQUESTS);
    }

    #[test]
    fn pending_deadline_retains_the_response_correlation() {
        let pending_stats = Arc::new(PendingStatsQueue::new());
        pending_stats
            .lock()
            .push_back(pending_legacy(10, None, Instant::now()));

        let worker_queue = Arc::clone(&pending_stats);
        let expired = std::thread::spawn(move || {
            wait_for_expired_pending_stats(&worker_queue, Duration::from_millis(20))
        })
        .join()
        .unwrap();

        assert_eq!(expired.len(), 1);
        let queue = pending_stats.lock();
        assert_eq!(queue.len(), 1);
        assert!(queue[0].terminal_response_sent);
        assert_eq!(pending_legacy_position(&queue, None, Some(10)), Some(0));
        assert_eq!(
            earliest_pending_stats_deadline(&queue, Duration::from_millis(20)),
            None
        );
    }

    #[test]
    fn service_deadline_keeps_one_terminal_correlation_until_the_response_arrives() {
        let now = Instant::now();
        let lifetime = Duration::from_secs(1);
        let queued_at = now.checked_sub(lifetime).unwrap();
        let mut queue = VecDeque::from([pending_service(10, 41, queued_at)]);

        let failures = take_expired_pending_stats(&mut queue, now, lifetime);

        assert_eq!(failures.len(), 1);
        assert_eq!(queue.len(), 1);
        assert!(queue[0].terminal_response_sent);
        assert_eq!(pending_service_position(&queue, 41), Some(0));
        assert_eq!(earliest_pending_stats_deadline(&queue, lifetime), None);
        assert!(take_expired_pending_stats(&mut queue, now, lifetime).is_empty());
    }

    #[test]
    fn context_change_retains_current_connection_correlations() {
        let now = Instant::now();
        let lifetime = Duration::from_secs(1);
        let queued_at = now.checked_sub(lifetime).unwrap();
        let mut queue = VecDeque::from([
            pending_service(10, 41, queued_at),
            pending_legacy(11, Some(42), now),
        ]);
        assert_eq!(
            take_expired_pending_stats(&mut queue, now, lifetime).len(),
            1
        );

        let failures = terminalize_pending_stats(&mut queue, 0);

        assert_eq!(failures.len(), 1);
        assert_eq!(queue.len(), 2);
        assert!(queue.iter().all(|entry| entry.terminal_response_sent));
        assert!(terminalize_pending_stats(&mut queue, 0).is_empty());

        let failures = terminalize_pending_stats(&mut queue, 1);

        assert!(failures.is_empty());
        assert!(queue.is_empty());
    }

    #[test]
    fn legacy_response_prefers_job_id_then_uses_app_fifo() {
        let now = Instant::now();
        let mut queue = VecDeque::from([
            pending_legacy(10, Some(41), now),
            pending_legacy(10, Some(42), now),
            pending_legacy(11, None, now),
        ]);

        assert_eq!(pending_legacy_position(&queue, Some(42), Some(10)), Some(1));
        assert_eq!(pending_legacy_position(&queue, Some(99), Some(10)), None);
        assert_eq!(queue.len(), 3);

        queue.remove(1);
        assert_eq!(pending_legacy_position(&queue, None, Some(10)), Some(0));
        assert_eq!(pending_legacy_position(&queue, None, Some(11)), Some(1));
    }

    #[test]
    fn stale_runtime_generation_is_not_registered() {
        let runtime = crate::client::install::runtime_snapshot();
        let mut pending = pending_legacy(10, None, Instant::now());
        pending.guard = StatsRequestGuard {
            credential_fingerprint: crate::cloud_backend::backend_context()
                .map(|backend| backend.credential_fingerprint()),
            config: Arc::clone(&runtime.config),
            runtime_generation: runtime.generation.wrapping_add(1),
            client_id: vapor_forge_cloud_core::device_descriptor()
                .map(|descriptor| descriptor.client_id),
            steam_id64: identity::steam_id(),
            identity_generation: identity::generation(),
            injection_generation: crate::client::network::injection_generation(),
        };
        drop(runtime);

        let before = PENDING_BACKEND_STATS.lock().len();
        assert_eq!(
            push_pending_stats(pending),
            Err(PushPendingStatsError::Stale)
        );
        assert_eq!(PENDING_BACKEND_STATS.lock().len(), before);
    }
}
