#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(debug_assertions, test))]
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(any(debug_assertions, test))]
use std::time::Duration;

use tracing::{debug, warn};
use vapor_forge_config::AppId;
use vapor_forge_steam_protocol::{parse_achievement_bit_mappings, parse_stat_mappings};

use super::callback_dispatch::{
    ApiCallResultEvent, AppMinutesPlayedDataNotice, CallbackEvent, UserStatsReceived,
    APP_MINUTES_PLAYED_DATA_NOTICE,
};
use super::callback_notify;
use super::internal_callbacks;
#[cfg(any(debug_assertions, test))]
use super::steam_session::UserStatsProbe;
use super::steam_session::{
    spawn_user_stats_worker, SteamUserStatsSession, ERESULT_OK, MAX_DRAIN_PER_TICK,
};

/// Maximum concurrent stats requests.
const MAX_IN_FLIGHT: usize = 8;
/// Playtime getters are synchronous, so bound one service pass.
const MAX_PLAYTIME_PER_PASS: usize = 8;
/// Callback ids kept for the debug socket, so an id shift stays diagnosable.
const MAX_TRACKED_IDS: usize = 64;
#[cfg(any(debug_assertions, test))]
const MAX_PENDING_QUERIES: usize = 4;
#[cfg(any(debug_assertions, test))]
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

static WORKER: OnceLock<Mutex<Option<StatsWorker>>> = OnceLock::new();
static SNAPSHOT_LAYOUTS: OnceLock<Mutex<HashMap<u32, Arc<SnapshotLayout>>>> = OnceLock::new();
static COMPLETION: Mutex<CompletionCounters> = Mutex::new(CompletionCounters::new());
static CALLBACKS: Mutex<CallbackCounters> = Mutex::new(CallbackCounters::new());

/// Outcome of consuming a completed stats request.
struct CompletionCounters {
    issued: u64,
    by_handle: u64,
    handle_not_ok: u64,
    handle_contract: u64,
    drained: u64,
    ids: Vec<(i32, u64)>,
}

struct CallbackCounters {
    delivered: u64,
    notices_seen: u64,
    rejected: u64,
    filtered: u64,
    merged: u64,
    queued: u64,
    completed: u64,
    failed: u64,
    router_triggers: u64,
}

impl CallbackCounters {
    const fn new() -> Self {
        Self {
            delivered: 0,
            notices_seen: 0,
            rejected: 0,
            filtered: 0,
            merged: 0,
            queued: 0,
            completed: 0,
            failed: 0,
            router_triggers: 0,
        }
    }
}

impl CompletionCounters {
    const fn new() -> Self {
        Self {
            issued: 0,
            by_handle: 0,
            handle_not_ok: 0,
            handle_contract: 0,
            drained: 0,
            ids: Vec::new(),
        }
    }
}

fn completion() -> std::sync::MutexGuard<'static, CompletionCounters> {
    COMPLETION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn callbacks() -> std::sync::MutexGuard<'static, CallbackCounters> {
    CALLBACKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(any(debug_assertions, test))]
pub(crate) fn callback_status() -> String {
    let counters = callbacks();
    format!(
        "delivered={} notices={} rejected={} filtered={} merged={} queued={} completed={} failed={} router={} {} {} {}",
        counters.delivered,
        counters.notices_seen,
        counters.rejected,
        counters.filtered,
        counters.merged,
        counters.queued,
        counters.completed,
        counters.failed,
        counters.router_triggers,
        callback_notify::diagnostic_status(),
        internal_callbacks::diagnostic_status(),
        super::steam_context::diagnostic_status(),
    )
}

/// API-call completion counters exposed through the debug socket.
#[cfg(any(debug_assertions, test))]
pub(crate) fn completion_status() -> String {
    let counters = completion();
    format!(
        "issued={} by_handle={} handle_not_ok={} handle_contract={} drained={}",
        counters.issued,
        counters.by_handle,
        counters.handle_not_ok,
        counters.handle_contract,
        counters.drained
    )
}

/// Steam event ids consumed by the worker, most frequent first.
#[cfg(any(debug_assertions, test))]
pub(crate) fn observed_ids(limit: usize) -> String {
    let mut ids = completion().ids.clone();
    ids.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    ids.truncate(limit);
    ids.iter()
        .map(|(id, count)| format!("{id}:{count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug)]
pub(crate) struct AchievementSnapshot {
    pub app_id: u32,
    pub achievements: Vec<AchievementState>,
    pub stats: Vec<StatState>,
}

#[derive(Debug)]
pub(crate) struct AchievementState {
    pub key: String,
    pub unlocked: bool,
    pub unlock_time: u32,
}

#[derive(Debug)]
pub(crate) struct StatState {
    pub key: String,
    pub value_type: String,
    pub value: String,
}

#[derive(Debug)]
pub(super) struct SnapshotLayout {
    pub(super) achievements: Vec<SnapshotKey>,
    pub(super) stats: Vec<SnapshotStat>,
}

#[derive(Debug)]
pub(super) struct SnapshotKey {
    pub(super) key: String,
    pub(super) c_key: CString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotStatKind {
    Int,
    Float,
    AverageRate,
    Dynamic,
}

#[derive(Debug)]
pub(super) struct SnapshotStat {
    pub(super) key: SnapshotKey,
    pub(super) kind: SnapshotStatKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StatsRefreshGuard {
    pub credential_fingerprint: String,
    pub steam_id64: u64,
    pub identity_generation: u64,
    pub client_id: u64,
}

/// Cache the names and types already present in Steam's schema response.
///
/// Snapshot reads can then call only the value getters. The strings are owned by
/// this cache because the packet containing the schema is released after routing.
pub(crate) fn register_snapshot_schema(app_id: u32, content: &[u8]) -> bool {
    if app_id == 0 || content.is_empty() {
        return false;
    }
    let achievements = match parse_achievement_bit_mappings(content) {
        Ok(mappings) => mappings,
        Err(error) => {
            remove_snapshot_schema(app_id);
            warn!(
                app_id,
                ?error,
                "user-stats schema achievement mapping failed"
            );
            return false;
        }
    };
    let stats = match parse_stat_mappings(content) {
        Ok(mappings) => mappings,
        Err(error) => {
            remove_snapshot_schema(app_id);
            warn!(app_id, ?error, "user-stats schema stat mapping failed");
            return false;
        }
    };

    let mut seen_achievements = HashSet::new();
    let achievements = achievements
        .into_iter()
        .filter_map(|mapping| {
            if !seen_achievements.insert(mapping.key.clone()) {
                return None;
            }
            snapshot_key(mapping.key)
        })
        .collect::<Vec<_>>();
    let mut seen_stats = HashSet::new();
    let stats = stats
        .into_iter()
        .filter_map(|mapping| {
            if !seen_stats.insert(mapping.key.clone()) {
                return None;
            }
            let kind = match mapping.value_type {
                Some(1) => SnapshotStatKind::Int,
                Some(2) => SnapshotStatKind::Float,
                Some(3) => SnapshotStatKind::AverageRate,
                _ => SnapshotStatKind::Dynamic,
            };
            Some(SnapshotStat {
                key: snapshot_key(mapping.key)?,
                kind,
            })
        })
        .collect::<Vec<_>>();
    let achievement_count = achievements.len();
    let stat_count = stats.len();
    snapshot_layouts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            app_id,
            Arc::new(SnapshotLayout {
                achievements,
                stats,
            }),
        );
    debug!(
        app_id,
        achievement_count, stat_count, "user-stats snapshot layout cached"
    );
    true
}

fn snapshot_key(key: String) -> Option<SnapshotKey> {
    let c_key = CString::new(key.as_bytes()).ok()?;
    Some(SnapshotKey { key, c_key })
}

fn snapshot_layouts() -> &'static Mutex<HashMap<u32, Arc<SnapshotLayout>>> {
    SNAPSHOT_LAYOUTS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn remove_snapshot_schema(app_id: u32) {
    let Some(layouts) = SNAPSHOT_LAYOUTS.get() else {
        return;
    };
    layouts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&app_id);
}

fn snapshot_layout(app_id: u32) -> Option<Arc<SnapshotLayout>> {
    snapshot_layouts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&app_id)
        .cloned()
}

/// Read the stats map Steam has already loaded for this app.
pub(crate) fn queue_snapshot_read(app_id: u32) {
    if !worker().is_some_and(|worker| worker.queue_read(app_id)) {
        warn!(app_id, "user-stats snapshot-read worker is unavailable");
    }
}

/// Signal that Steam's native playtime value for an app should be sampled.
///
/// All producers converge on the same AppID set. Repeated
/// signals merge into one ready entry.
pub(crate) fn signal_playtime(app_id: u32) -> bool {
    signal_playtime_for_generation(app_id, vapor_forge_features::identity::generation())
}

/// Sample cumulative playtime after a disconnected-playtime report.
pub(crate) fn signal_router_playtime(app_id: u32) -> bool {
    if app_id != 0 {
        callbacks().router_triggers += 1;
    }
    signal_playtime(app_id)
}

fn signal_playtime_for_generation(app_id: u32, generation: u64) -> bool {
    if app_id == 0 || vapor_forge_features::identity::steam_id() == 0 {
        return false;
    }
    if !super::install::config().is_controlled_app(AppId(app_id)) {
        return false;
    }
    let Some(worker) = worker() else {
        return false;
    };
    worker.signal_playtime(app_id, generation);
    true
}

/// Re-enter Steam's native refresh path from the local debug socket. Unlike
/// backend-driven requests, this has no backend credential to validate.
#[cfg(any(debug_assertions, test))]
pub(crate) fn queue_debug_stats_refresh(app_id: u32) -> bool {
    worker().is_some_and(|worker| worker.queue_refresh(app_id, None))
}

pub(crate) fn queue_backend_stats_refresh(app_id: u32, guard: StatsRefreshGuard) -> bool {
    worker().is_some_and(|worker| worker.queue_refresh(app_id, Some(guard)))
}

pub(crate) fn current_backend_refresh_guard() -> Option<StatsRefreshGuard> {
    let backend = crate::cloud_backend::backend_context()?;
    let descriptor = vapor_forge_cloud_core::device_descriptor()?;
    let steam_id64 = vapor_forge_features::identity::steam_id();
    if steam_id64 == 0 {
        return None;
    }
    Some(StatsRefreshGuard {
        credential_fingerprint: backend.credential_fingerprint(),
        steam_id64,
        identity_generation: vapor_forge_features::identity::generation(),
        client_id: descriptor.client_id,
    })
}

/// Diagnostic entry point for one stats request and its completion event.
#[cfg(any(debug_assertions, test))]
pub(crate) fn request_user_stats(app_id: u32) -> Result<UserStatsProbe, String> {
    let steam_id64 = vapor_forge_features::identity::steam_id();
    if steam_id64 == 0 {
        return Err("SteamID is unavailable".to_owned());
    }
    let worker = worker().ok_or_else(|| "user-stats worker is unavailable".to_owned())?;
    let (reply, result) = mpsc::sync_channel(1);
    if !worker.queue_query(WorkerQuery::UserStats {
        app_id,
        steam_id64,
        reply,
    }) {
        return Err("user-stats query queue is full".to_owned());
    }
    result
        .recv_timeout(QUERY_TIMEOUT)
        .map_err(|error| format!("Steam user-stats request did not complete: {error}"))?
}

pub(crate) fn ensure_worker_started() {
    let _ = worker();
}

pub(crate) fn notify_context_changed() {
    if let Some(slot) = WORKER.get() {
        let shared = slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|worker| Arc::clone(&worker.shared));
        if let Some(shared) = shared {
            shared.context_epoch.fetch_add(1, Ordering::AcqRel);
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.pending_reads.clear();
            state.queued_reads.clear();
            state.active_reads.clear();
            state.read_recovery_attempted.clear();
            state.reads_after_refresh.clear();
            state.pending_refresh_order.clear();
            state.pending_refreshes.clear();
            state.active_refreshes.clear();
            state.pending_playtime.clear();
            #[cfg(any(debug_assertions, test))]
            state.queries.clear();
        }
    }
    callback_notify::notify();
}

fn worker() -> Option<StatsWorker> {
    let slot = WORKER.get_or_init(|| Mutex::new(None));
    let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = StatsWorker::start();
    }
    guard.clone()
}

#[derive(Clone)]
struct StatsWorker {
    shared: Arc<WorkerShared>,
}

impl StatsWorker {
    fn start() -> Option<Self> {
        if !callback_notify::hooks_ready() {
            debug!("user-stats: callback hooks are not ready");
            return None;
        }
        let shared = Arc::new(WorkerShared::default());
        if !spawn_user_stats_worker(Arc::clone(&shared)) {
            warn!("failed to start user-stats SteamThreadTools worker");
            return None;
        }
        Some(Self { shared })
    }

    fn queue_read(&self, app_id: u32) -> bool {
        if app_id == 0 {
            return false;
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.read_recovery_attempted.remove(&app_id);
        queue_read_locked(&mut state, app_id);
        callback_notify::notify();
        true
    }

    fn queue_refresh(&self, app_id: u32, guard: Option<StatsRefreshGuard>) -> bool {
        if app_id == 0 {
            return false;
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queue_refresh_locked(&mut state, app_id, guard);
        callback_notify::notify();
        true
    }

    fn signal_playtime(&self, app_id: u32, identity_generation: u64) -> PlaytimeSignal {
        let outcome = signal_pending_playtime(
            &mut self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            app_id,
            identity_generation,
        );
        callback_notify::notify();
        outcome
    }

    #[cfg(any(debug_assertions, test))]
    fn queue_query(&self, query: WorkerQuery) -> bool {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.queries.len() >= MAX_PENDING_QUERIES {
            return false;
        }
        state.queries.push_back(query);
        callback_notify::notify();
        true
    }
}

#[derive(Default)]
pub(super) struct WorkerShared {
    state: Mutex<WorkerState>,
    context_epoch: AtomicU64,
}

/// A read-only question answered through the worker's captured Steam interfaces.
#[cfg(any(debug_assertions, test))]
enum WorkerQuery {
    /// Diagnostic: issue `RequestUserStats` for one app and report whether Steam's
    /// stats map ended up populated, with a few values read back.
    UserStats {
        app_id: u32,
        steam_id64: u64,
        reply: mpsc::SyncSender<Result<UserStatsProbe, String>>,
    },
}

#[derive(Default)]
struct WorkerState {
    pending_reads: VecDeque<u32>,
    queued_reads: HashSet<u32>,
    active_reads: HashSet<u32>,
    read_recovery_attempted: HashSet<u32>,
    reads_after_refresh: HashSet<u32>,
    pending_refresh_order: VecDeque<u32>,
    pending_refreshes: HashMap<u32, RefreshRequest>,
    active_refreshes: HashSet<u32>,
    pending_playtime: HashMap<u32, PendingPlaytime>,
    #[cfg(any(debug_assertions, test))]
    queries: VecDeque<WorkerQuery>,
    next_playtime_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingPlaytime {
    identity_generation: u64,
    revision: u64,
    ready: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlaytimeSignal {
    Queued,
    Merged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefreshRequest {
    app_id: u32,
    refresh_guard: Option<StatsRefreshGuard>,
}

/// One request Steam has accepted and has not yet finished.
struct InFlight {
    app_id: u32,
    api_call: u64,
    #[cfg(any(debug_assertions, test))]
    probe_reply: Option<mpsc::SyncSender<Result<UserStatsProbe, String>>>,
}

/// Service commands and events through Steam's existing IPC wrappers.
pub(super) fn run_worker(shared: &WorkerShared) {
    loop {
        let observed = callback_notify::epoch();
        internal_callbacks::register_observed_handlers();
        if vapor_forge_features::identity::steam_id() == 0 {
            callback_notify::wait(observed);
            continue;
        }
        let Some(session) = connect_session() else {
            callback_notify::wait(observed);
            continue;
        };
        let generation = vapor_forge_features::identity::generation();
        let steam_id64 = vapor_forge_features::identity::steam_id();
        let context_epoch = shared.context_epoch.load(Ordering::Acquire);
        let mut in_flight: Vec<InFlight> = Vec::new();
        {
            let config = super::install::config();
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for app_id in crate::achievement_worker::stats_awaiting_snapshot()
                .into_iter()
                .filter(|app_id| config.is_controlled_app(AppId(*app_id)))
            {
                state.read_recovery_attempted.remove(&app_id);
                queue_read_locked(&mut state, app_id);
            }
        }
        debug!(
            user = session.user(),
            generation, "user-stats: session open"
        );

        loop {
            // Observe before servicing. Any producer or callback racing with this
            // pass changes the epoch and prevents the following wait from parking.
            let observed = callback_notify::epoch();
            if vapor_forge_features::identity::generation() != generation
                || vapor_forge_features::identity::steam_id() == 0
                || shared.context_epoch.load(Ordering::Acquire) != context_epoch
                || !session.is_current()
            {
                debug!(
                    generation,
                    outstanding = in_flight.len(),
                    "user-stats: account context changed"
                );
                for entry in in_flight.drain(..) {
                    #[cfg(any(debug_assertions, test))]
                    {
                        if let Some(reply) = entry.probe_reply {
                            let _ = reply.send(Err("Steam session changed".to_owned()));
                            continue;
                        }
                    }
                    finish_refresh(shared, entry.app_id);
                }
                drop(session);
                break;
            }
            service_until_quiescent(&session, shared, steam_id64, generation, &mut in_flight);
            callback_notify::wait(observed);
        }
    }
}

fn connect_session() -> Option<SteamUserStatsSession> {
    match SteamUserStatsSession::connect() {
        Ok(session) => Some(session),
        Err(error) => {
            debug!(error, "user-stats: Steam interface context unavailable");
            None
        }
    }
}

fn service_until_quiescent(
    session: &SteamUserStatsSession,
    shared: &WorkerShared,
    steam_id64: u64,
    identity_generation: u64,
    in_flight: &mut Vec<InFlight>,
) {
    consume_callback_events(session, shared, steam_id64, identity_generation, in_flight);
    while process_pending_playtime_pass(session, shared, steam_id64, identity_generation) {}
    process_pending_reads(session, shared);
    admit_refreshes(session, shared, steam_id64, in_flight);
}

/// Consume bounded chunks until the process-owned event queue is empty.
fn consume_callback_events(
    session: &SteamUserStatsSession,
    shared: &WorkerShared,
    steam_id64: u64,
    identity_generation: u64,
    in_flight: &mut Vec<InFlight>,
) {
    let expected_user = session.user();
    let config = super::install::config();
    loop {
        let events = internal_callbacks::take_events(MAX_DRAIN_PER_TICK);
        let completed = callback_notify::take_api_results(MAX_DRAIN_PER_TICK);
        let internal_may_remain = events.len() == MAX_DRAIN_PER_TICK;
        let api_results_may_remain = completed.len() == MAX_DRAIN_PER_TICK;
        let drained = events.len() + completed.len();
        for event in events {
            note_event_id(event.header.callback);
            dispatch_callback(
                shared,
                event,
                expected_user,
                steam_id64,
                identity_generation,
                |app_id| config.is_controlled_app(AppId(app_id)),
            );
        }
        for completed in completed {
            note_event_id(completed.callback);
            route_api_call_result(session, shared, steam_id64, in_flight, completed);
        }
        if drained > 0 {
            completion().drained += drained as u64;
        }
        if !internal_may_remain && !api_results_may_remain {
            return;
        }
    }
}

fn dispatch_callback(
    shared: &WorkerShared,
    event: CallbackEvent,
    expected_user: i32,
    steam_id64: u64,
    identity_generation: u64,
    controlled: impl FnOnce(u32) -> bool,
) {
    callbacks().delivered += 1;
    handle_playtime_callback(
        shared,
        &event,
        expected_user,
        steam_id64,
        identity_generation,
        controlled,
    );
}

fn route_api_call_result(
    _session: &SteamUserStatsSession,
    shared: &WorkerShared,
    expected_steam_id64: u64,
    in_flight: &mut Vec<InFlight>,
    completed: ApiCallResultEvent,
) {
    let Some(entry) = take_matching_api_call_result(in_flight, completed.api_call) else {
        return;
    };
    let app_id = entry.app_id;
    let Some(received) = decode_user_stats_result(&completed) else {
        completion().handle_contract += 1;
        warn!(
            app_id,
            api_call = entry.api_call,
            callback = completed.callback,
            payload_size = completed.payload_size,
            "user-stats invariant violation: completed API call has the wrong result contract"
        );
        #[cfg(any(debug_assertions, test))]
        if let Some(reply) = entry.probe_reply {
            let _ = reply.send(Err(format!(
                "completed API call has callback {} and payload size {}",
                completed.callback, completed.payload_size
            )));
            return;
        }
        finish_refresh(shared, app_id);
        return;
    };
    if !user_stats_result_matches(received, app_id, expected_steam_id64) {
        completion().handle_contract += 1;
        let result_game_id = received.game_id;
        let result_steam_id = received.steam_id;
        warn!(
            app_id,
            api_call = entry.api_call,
            result_game_id,
            result_steam_id,
            expected_steam_id64,
            "user-stats invariant violation: completed API call belongs to another request"
        );
        #[cfg(any(debug_assertions, test))]
        if let Some(reply) = entry.probe_reply {
            let _ = reply.send(Err(
                "completed API call belongs to another request".to_owned()
            ));
            return;
        }
        finish_refresh(shared, app_id);
        return;
    }
    let result = received.result;
    #[cfg(any(debug_assertions, test))]
    {
        if let Some(reply) = entry.probe_reply {
            let response = if result == ERESULT_OK {
                completion().by_handle += 1;
                _session
                    .read_stats_probe(app_id, entry.api_call, result)
                    .map_err(str::to_owned)
            } else {
                completion().handle_not_ok += 1;
                Err(format!("Steam returned non-OK result {result}"))
            };
            let _ = reply.send(response);
            return;
        }
    }

    if result == ERESULT_OK {
        completion().by_handle += 1;
        finish_refresh(shared, app_id);
    } else {
        completion().handle_not_ok += 1;
        warn!(
            app_id,
            api_call = entry.api_call,
            result,
            "user-stats: completed API call returned a non-OK result"
        );
        finish_refresh(shared, app_id);
    }
}

fn take_matching_api_call_result(in_flight: &mut Vec<InFlight>, api_call: u64) -> Option<InFlight> {
    let index = in_flight
        .iter()
        .position(|entry| entry.api_call == api_call)?;
    Some(in_flight.remove(index))
}

fn decode_user_stats_result(completed: &ApiCallResultEvent) -> Option<UserStatsReceived> {
    (completed.payload_size == std::mem::size_of::<UserStatsReceived>() as i32)
        .then(|| completed.decode::<UserStatsReceived>())
        .flatten()
}

fn user_stats_result_matches(received: UserStatsReceived, app_id: u32, steam_id64: u64) -> bool {
    received.game_id == u64::from(app_id) && received.steam_id == steam_id64
}

fn read_snapshot(session: &SteamUserStatsSession, app_id: u32) -> bool {
    let layout = snapshot_layout(app_id);
    match session.read_snapshot(app_id, layout.as_deref()) {
        Ok(snapshot) => super::achievement::observe_local_snapshot(snapshot),
        Err(error) => {
            warn!(app_id, error, "user-stats snapshot read failed");
            false
        }
    }
}

fn process_pending_reads(session: &SteamUserStatsSession, shared: &WorkerShared) {
    while let Some(app_id) = take_read(shared) {
        let succeeded = read_snapshot(session, app_id);
        finish_read(shared, app_id);
        if succeeded {
            clear_read_recovery(shared, app_id);
        } else {
            queue_read_recovery(shared, app_id);
        }
    }
}

fn clear_read_recovery(shared: &WorkerShared, app_id: u32) {
    shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .read_recovery_attempted
        .remove(&app_id);
}

/// A failed getter gets one event-driven cache refresh. Its completion queues
/// the second and final read through `reads_after_refresh`.
fn queue_read_recovery(shared: &WorkerShared, app_id: u32) {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !state.read_recovery_attempted.insert(app_id) {
        warn!(app_id, "user-stats snapshot recovery was exhausted");
        return;
    }
    state.reads_after_refresh.insert(app_id);
    queue_refresh_locked(&mut state, app_id, None);
    callback_notify::notify();
}

/// Take as much refresh work as the in-flight bound allows.
fn admit_refreshes(
    session: &SteamUserStatsSession,
    shared: &WorkerShared,
    steam_id64: u64,
    in_flight: &mut Vec<InFlight>,
) {
    // Queries are answered synchronously on this thread and are not requests, so
    // they are not subject to the in-flight bound.
    #[cfg(any(debug_assertions, test))]
    {
        while let Some(query) = take_query(shared) {
            run_query(session, query, in_flight);
        }
    }
    while in_flight.len() < MAX_IN_FLIGHT {
        let Some(request) = take_refresh(shared) else {
            return;
        };
        issue_refresh(session, shared, steam_id64, request, in_flight);
    }
}

fn issue_refresh(
    session: &SteamUserStatsSession,
    shared: &WorkerShared,
    steam_id64: u64,
    request: RefreshRequest,
    in_flight: &mut Vec<InFlight>,
) {
    let app_id = request.app_id;

    if let Some(guard) = request.refresh_guard.as_ref() {
        if !stats_refresh_guard_is_current(guard) {
            debug!(app_id, "discarded stale backend stats refresh");
            finish_refresh(shared, app_id);
            return;
        }
    }

    match session.request_stats(app_id, steam_id64) {
        Ok(api_call) => {
            completion().issued += 1;
            in_flight.push(InFlight {
                app_id,
                api_call,
                #[cfg(any(debug_assertions, test))]
                probe_reply: None,
            });
        }
        Err(error) => {
            warn!(app_id, error, "user-stats request could not be issued");
            finish_refresh(shared, app_id);
        }
    }
}

fn queue_read_locked(state: &mut WorkerState, app_id: u32) {
    if state.active_refreshes.contains(&app_id) || state.pending_refreshes.contains_key(&app_id) {
        state.reads_after_refresh.insert(app_id);
        return;
    }
    if state.queued_reads.insert(app_id) {
        state.pending_reads.push_back(app_id);
    }
}

fn queue_refresh_locked(
    state: &mut WorkerState,
    app_id: u32,
    refresh_guard: Option<StatsRefreshGuard>,
) {
    if let Some(pending) = state.pending_refreshes.get_mut(&app_id) {
        if refresh_guard.is_some() {
            pending.refresh_guard = refresh_guard;
        }
        return;
    }

    // A queued or currently executing read was requested against the pre-refresh
    // cache. Preserve that intent, but satisfy it only after the latest refresh.
    if state.queued_reads.remove(&app_id) {
        state.pending_reads.retain(|queued| *queued != app_id);
        state.reads_after_refresh.insert(app_id);
    }
    if state.active_reads.contains(&app_id) {
        state.reads_after_refresh.insert(app_id);
    }

    state.pending_refresh_order.push_back(app_id);
    state.pending_refreshes.insert(
        app_id,
        RefreshRequest {
            app_id,
            refresh_guard,
        },
    );
}

fn signal_pending_playtime(
    state: &mut WorkerState,
    app_id: u32,
    identity_generation: u64,
) -> PlaytimeSignal {
    state.next_playtime_revision = state.next_playtime_revision.wrapping_add(1);
    let revision = state.next_playtime_revision;
    let outcome = if state
        .pending_playtime
        .get(&app_id)
        .is_some_and(|pending| pending.identity_generation == identity_generation)
    {
        PlaytimeSignal::Merged
    } else {
        PlaytimeSignal::Queued
    };
    state.pending_playtime.insert(
        app_id,
        PendingPlaytime {
            identity_generation,
            revision,
            ready: true,
        },
    );
    outcome
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallbackDecision {
    Other,
    Rejected,
    Filtered,
    Signal(u32),
}

fn classify_callback(
    event: &CallbackEvent,
    expected_user: i32,
    steam_id64: u64,
    identity_generation: u64,
    controlled: impl FnOnce(u32) -> bool,
) -> CallbackDecision {
    if event.header.callback != APP_MINUTES_PLAYED_DATA_NOTICE {
        return CallbackDecision::Other;
    }
    if event.header.steam_user != expected_user
        || event.steam_id64 != steam_id64
        || event.identity_generation != identity_generation
    {
        return CallbackDecision::Rejected;
    }
    let Some(app_id) = event
        .decode::<AppMinutesPlayedDataNotice>()
        .map(|notice| notice.app_id)
        .filter(|app_id| *app_id != 0)
    else {
        return CallbackDecision::Rejected;
    };
    if !controlled(app_id) {
        return CallbackDecision::Filtered;
    }
    CallbackDecision::Signal(app_id)
}

fn handle_playtime_callback(
    shared: &WorkerShared,
    event: &CallbackEvent,
    expected_user: i32,
    steam_id64: u64,
    identity_generation: u64,
    controlled: impl FnOnce(u32) -> bool,
) {
    let decision = classify_callback(
        event,
        expected_user,
        steam_id64,
        identity_generation,
        controlled,
    );
    {
        let mut counters = callbacks();
        match decision {
            CallbackDecision::Other => return,
            CallbackDecision::Rejected => {
                counters.notices_seen += 1;
                counters.rejected += 1;
                return;
            }
            CallbackDecision::Filtered => {
                counters.notices_seen += 1;
                counters.filtered += 1;
                return;
            }
            CallbackDecision::Signal(_) => {
                counters.notices_seen += 1;
            }
        }
    }

    let CallbackDecision::Signal(app_id) = decision else {
        return;
    };
    let outcome = {
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        signal_pending_playtime(&mut state, app_id, identity_generation)
    };
    let mut counters = callbacks();
    match outcome {
        PlaytimeSignal::Queued => counters.queued += 1,
        PlaytimeSignal::Merged => counters.merged += 1,
    }
}

/// Process one bounded playtime batch. Returns true while another immediately
/// runnable batch remains, so the caller can continue without a timer or wakeup.
fn process_pending_playtime_pass(
    session: &SteamUserStatsSession,
    shared: &WorkerShared,
    steam_id64: u64,
    identity_generation: u64,
) -> bool {
    let ready = take_ready_playtime(shared, identity_generation, MAX_PLAYTIME_PER_PASS);
    for (app_id, expected) in ready {
        if vapor_forge_features::identity::generation() != identity_generation
            || vapor_forge_features::identity::steam_id() != steam_id64
        {
            finish_pending_playtime(shared, app_id, expected);
            return false;
        }
        let accepted = match session.playtime_snapshot(app_id) {
            Ok(snapshot)
                if snapshot.steam_id64 == steam_id64
                    && vapor_forge_features::identity::generation() == identity_generation =>
            {
                crate::playtime_worker::queue(snapshot)
            }
            Ok(_) => false,
            Err(error) => {
                warn!(app_id, error, "user-stats playtime snapshot failed");
                false
            }
        };
        match finish_pending_playtime(shared, app_id, expected) {
            PlaytimeCompletion::Removed if accepted => callbacks().completed += 1,
            PlaytimeCompletion::Removed => callbacks().failed += 1,
            PlaytimeCompletion::Superseded => {}
        }
    }
    has_ready_playtime(shared, identity_generation)
}

fn take_ready_playtime(
    shared: &WorkerShared,
    identity_generation: u64,
    limit: usize,
) -> Vec<(u32, PendingPlaytime)> {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state
        .pending_playtime
        .retain(|_, pending| pending.identity_generation == identity_generation);
    let mut ready = state
        .pending_playtime
        .iter()
        .filter(|(_, pending)| pending.ready)
        .map(|(app_id, pending)| (*app_id, *pending))
        .collect::<Vec<_>>();
    ready.sort_by_key(|(app_id, pending)| (pending.revision, *app_id));
    ready.truncate(limit);
    ready
}

fn has_ready_playtime(shared: &WorkerShared, identity_generation: u64) -> bool {
    shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_playtime
        .values()
        .any(|pending| pending.identity_generation == identity_generation && pending.ready)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlaytimeCompletion {
    Removed,
    Superseded,
}

fn finish_pending_playtime(
    shared: &WorkerShared,
    app_id: u32,
    expected: PendingPlaytime,
) -> PlaytimeCompletion {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(current) = state.pending_playtime.get_mut(&app_id) else {
        return PlaytimeCompletion::Superseded;
    };
    if *current != expected {
        return PlaytimeCompletion::Superseded;
    }
    state.pending_playtime.remove(&app_id);
    PlaytimeCompletion::Removed
}

/// Answer one read-only query on the session this thread already holds.
#[cfg(any(debug_assertions, test))]
fn run_query(session: &SteamUserStatsSession, query: WorkerQuery, in_flight: &mut Vec<InFlight>) {
    let WorkerQuery::UserStats {
        app_id,
        steam_id64,
        reply,
    } = query;
    match session.request_stats(app_id, steam_id64) {
        Ok(api_call) => {
            completion().issued += 1;
            in_flight.push(InFlight {
                app_id,
                api_call,
                probe_reply: Some(reply),
            });
        }
        Err(error) => {
            let _ = reply.send(Err(error.to_owned()));
        }
    }
}

fn note_event_id(callback: i32) {
    let mut counters = completion();
    if let Some(entry) = counters.ids.iter_mut().find(|(id, _)| *id == callback) {
        entry.1 += 1;
    } else if counters.ids.len() < MAX_TRACKED_IDS {
        counters.ids.push((callback, 1));
    }
}

fn finish_read(shared: &WorkerShared, app_id: u32) {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.active_reads.remove(&app_id);
}

fn finish_refresh(shared: &WorkerShared, app_id: u32) {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.active_refreshes.remove(&app_id);
    if state.pending_refreshes.contains_key(&app_id) {
        // A new refresh arrived while the completed one was in flight.
        callback_notify::notify();
        return;
    }
    if state.reads_after_refresh.remove(&app_id) {
        queue_read_locked(&mut state, app_id);
        callback_notify::notify();
    }
}

fn stats_refresh_guard_is_current(guard: &StatsRefreshGuard) -> bool {
    vapor_forge_features::identity::steam_id() == guard.steam_id64
        && vapor_forge_features::identity::generation() == guard.identity_generation
        && vapor_forge_cloud_core::device_descriptor()
            .is_some_and(|descriptor| descriptor.client_id == guard.client_id)
        && crate::cloud_backend::backend_context()
            .is_some_and(|backend| backend.credential_fingerprint() == guard.credential_fingerprint)
}

/// Both takers are non-blocking. The service loop owns all waiting.
#[cfg(any(debug_assertions, test))]
fn take_query(shared: &WorkerShared) -> Option<WorkerQuery> {
    shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .queries
        .pop_front()
}

fn take_read(shared: &WorkerShared) -> Option<u32> {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let app_id = state.pending_reads.pop_front()?;
    state.queued_reads.remove(&app_id);
    state.active_reads.insert(app_id);
    Some(app_id)
}

fn take_refresh(shared: &WorkerShared) -> Option<RefreshRequest> {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    while let Some(app_id) = state.pending_refresh_order.pop_front() {
        let Some(request) = state.pending_refreshes.remove(&app_id) else {
            continue;
        };
        state.active_refreshes.insert(app_id);
        return Some(request);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GENERATION: u64 = 7;
    const TEST_STEAM_ID: u64 = 76_561_198_000_000_001;

    fn kv_string(out: &mut Vec<u8>, key: &str, value: &str) {
        out.push(1);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }

    fn kv_int(out: &mut Vec<u8>, key: &str, value: i32) {
        out.push(2);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn kv_object(out: &mut Vec<u8>, key: &str, body: impl FnOnce(&mut Vec<u8>)) {
        out.push(0);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        body(out);
        out.push(8);
    }

    #[test]
    fn packet_schema_builds_a_typed_snapshot_layout() {
        const APP_ID: u32 = u32::MAX - 1;
        let mut schema = Vec::new();
        kv_object(&mut schema, "480", |root| {
            kv_object(root, "stats", |stats| {
                kv_object(stats, "11", |stat| {
                    kv_string(stat, "name", "STAT_SCORE");
                    kv_int(stat, "type", 1);
                });
                kv_object(stats, "12", |stat| {
                    kv_string(stat, "name", "STAT_RATE");
                    kv_int(stat, "type", 3);
                });
                kv_object(stats, "13", |stat| {
                    kv_object(stat, "bits", |bits| {
                        kv_object(bits, "2", |achievement| {
                            kv_string(achievement, "name", "ACH_WIN");
                        });
                    });
                });
            });
        });

        assert!(register_snapshot_schema(APP_ID, &schema));
        let layout = snapshot_layout(APP_ID).expect("layout should be cached");
        assert_eq!(layout.achievements.len(), 1);
        assert_eq!(layout.achievements[0].key, "ACH_WIN");
        assert_eq!(layout.achievements[0].c_key.to_bytes(), b"ACH_WIN");
        assert_eq!(layout.stats.len(), 2);
        assert_eq!(layout.stats[0].key.key, "STAT_SCORE");
        assert_eq!(layout.stats[0].kind, SnapshotStatKind::Int);
        assert_eq!(layout.stats[1].key.key, "STAT_RATE");
        assert_eq!(layout.stats[1].kind, SnapshotStatKind::AverageRate);
    }

    fn signal_at(shared: &WorkerShared, app_id: u32, generation: u64) -> PlaytimeSignal {
        signal_pending_playtime(&mut shared.state.lock().unwrap(), app_id, generation)
    }

    fn callback_event(callback: i32, steam_user: i32, app_id: Option<u32>) -> CallbackEvent {
        let payload = app_id
            .map(|app_id| app_id.to_le_bytes().to_vec().into_boxed_slice())
            .unwrap_or_default();
        CallbackEvent::from_bytes(
            steam_user,
            TEST_GENERATION,
            TEST_STEAM_ID,
            callback,
            &payload,
        )
    }

    fn classify_test(
        event: &CallbackEvent,
        expected_user: i32,
        controlled: impl FnOnce(u32) -> bool,
    ) -> CallbackDecision {
        classify_callback(
            event,
            expected_user,
            TEST_STEAM_ID,
            TEST_GENERATION,
            controlled,
        )
    }

    fn in_flight(api_call: u64) -> InFlight {
        InFlight {
            app_id: api_call as u32,
            api_call,
            #[cfg(any(debug_assertions, test))]
            probe_reply: None,
        }
    }

    #[test]
    fn playtime_pass_limit_leaves_the_remainder_ready() {
        let shared = WorkerShared::default();
        let generation = 7;
        for app_id in 1..=(MAX_PLAYTIME_PER_PASS as u32 + 3) {
            assert_eq!(
                signal_at(&shared, app_id, generation),
                PlaytimeSignal::Queued
            );
        }

        let ready = take_ready_playtime(&shared, generation, MAX_PLAYTIME_PER_PASS);
        assert_eq!(ready.len(), MAX_PLAYTIME_PER_PASS);
        for (app_id, expected) in ready {
            assert_eq!(
                finish_pending_playtime(&shared, app_id, expected),
                PlaytimeCompletion::Removed
            );
        }
        assert_eq!(shared.state.lock().unwrap().pending_playtime.len(), 3);
        assert!(has_ready_playtime(&shared, generation));
    }

    #[test]
    fn duplicate_playtime_signal_replaces_the_ready_revision() {
        let shared = WorkerShared::default();
        assert_eq!(signal_at(&shared, 480, 7), PlaytimeSignal::Queued);
        let first = shared.state.lock().unwrap().pending_playtime[&480];

        assert_eq!(signal_at(&shared, 480, 7), PlaytimeSignal::Merged);
        let second = shared.state.lock().unwrap().pending_playtime[&480];
        assert!(second.revision > first.revision);
        assert!(second.ready);
        assert_eq!(take_ready_playtime(&shared, 7, 1), vec![(480, second)]);
    }

    #[test]
    fn newer_playtime_signal_survives_an_older_completion() {
        let shared = WorkerShared::default();
        signal_at(&shared, 480, 7);
        let expected = take_ready_playtime(&shared, 7, 1)[0].1;

        signal_at(&shared, 480, 7);
        assert_eq!(
            finish_pending_playtime(&shared, 480, expected),
            PlaytimeCompletion::Superseded
        );
        assert_ne!(
            shared.state.lock().unwrap().pending_playtime[&480].revision,
            expected.revision
        );
    }

    #[test]
    fn failed_playtime_delivery_is_terminal() {
        let shared = WorkerShared::default();
        signal_at(&shared, 480, 7);
        let expected = take_ready_playtime(&shared, 7, 1)[0].1;

        assert_eq!(
            finish_pending_playtime(&shared, 480, expected),
            PlaytimeCompletion::Removed
        );
        assert!(!shared
            .state
            .lock()
            .unwrap()
            .pending_playtime
            .contains_key(&480));
    }

    #[test]
    fn stale_playtime_generation_is_pruned() {
        let shared = WorkerShared::default();
        signal_at(&shared, 480, 7);
        signal_at(&shared, 620, 8);

        let ready = take_ready_playtime(&shared, 8, 8);
        assert_eq!(
            ready.iter().map(|(app_id, _)| *app_id).collect::<Vec<_>>(),
            vec![620]
        );
        assert!(!shared
            .state
            .lock()
            .unwrap()
            .pending_playtime
            .contains_key(&480));
    }

    #[test]
    fn playtime_callback_validation_checks_id_recipient_payload_and_control() {
        assert_eq!(
            classify_test(&callback_event(1101, 3, Some(480)), 3, |_| true),
            CallbackDecision::Other
        );
        assert_eq!(
            classify_test(
                &callback_event(APP_MINUTES_PLAYED_DATA_NOTICE, 4, Some(480)),
                3,
                |_| true
            ),
            CallbackDecision::Rejected
        );
        assert_eq!(
            classify_test(
                &callback_event(APP_MINUTES_PLAYED_DATA_NOTICE, 3, None),
                3,
                |_| true
            ),
            CallbackDecision::Rejected
        );
        assert_eq!(
            classify_test(
                &callback_event(APP_MINUTES_PLAYED_DATA_NOTICE, 3, Some(0)),
                3,
                |_| true
            ),
            CallbackDecision::Rejected
        );
        assert_eq!(
            classify_test(
                &callback_event(APP_MINUTES_PLAYED_DATA_NOTICE, 3, Some(730)),
                3,
                |_| false
            ),
            CallbackDecision::Filtered
        );
        assert_eq!(
            classify_test(
                &callback_event(APP_MINUTES_PLAYED_DATA_NOTICE, 3, Some(480)),
                3,
                |_| true
            ),
            CallbackDecision::Signal(480)
        );
    }

    #[test]
    fn api_call_result_routes_only_the_matching_handle() {
        let mut requests = vec![in_flight(11), in_flight(22)];
        let selected = take_matching_api_call_result(&mut requests, 22)
            .expect("matching handle should be selected");

        assert_eq!(selected.api_call, 22);
        assert_eq!(
            requests
                .iter()
                .map(|entry| entry.api_call)
                .collect::<Vec<_>>(),
            vec![11]
        );
    }

    #[test]
    fn api_call_result_contract_is_checked_after_handle_selection() {
        let mut requests = vec![in_flight(11)];
        let completed = ApiCallResultEvent::new(11, 999, 20, [0u8; 20].into());

        assert!(take_matching_api_call_result(&mut requests, completed.api_call).is_some());
        assert!(decode_user_stats_result(&completed).is_none());
        assert!(requests.is_empty());
    }

    #[test]
    fn api_call_result_payload_must_match_the_requested_app_and_user() {
        let received = UserStatsReceived {
            game_id: 480,
            result: ERESULT_OK,
            steam_id: TEST_STEAM_ID,
        };

        assert!(user_stats_result_matches(received, 480, TEST_STEAM_ID));
        assert!(!user_stats_result_matches(received, 620, TEST_STEAM_ID));
        assert!(!user_stats_result_matches(received, 480, TEST_STEAM_ID + 1));
    }

    #[test]
    fn cache_reads_are_deduplicated() {
        let shared = WorkerShared::default();
        {
            let mut state = shared.state.lock().unwrap();
            queue_read_locked(&mut state, 480);
            queue_read_locked(&mut state, 480);
        }

        assert_eq!(take_read(&shared), Some(480));
        assert_eq!(take_read(&shared), None);
        finish_read(&shared, 480);
        let state = shared.state.lock().unwrap();
        assert!(!state.active_reads.contains(&480));
        assert!(state.pending_reads.is_empty());
    }

    #[test]
    fn failed_cache_read_gets_one_event_driven_refresh() {
        let shared = WorkerShared::default();
        {
            let mut state = shared.state.lock().unwrap();
            queue_read_locked(&mut state, 480);
        }
        assert_eq!(take_read(&shared), Some(480));
        finish_read(&shared, 480);

        queue_read_recovery(&shared, 480);
        {
            let state = shared.state.lock().unwrap();
            assert!(state.read_recovery_attempted.contains(&480));
            assert!(state.reads_after_refresh.contains(&480));
            assert!(state.pending_refreshes.contains_key(&480));
        }

        assert_eq!(
            take_refresh(&shared).map(|request| request.app_id),
            Some(480)
        );
        finish_refresh(&shared, 480);
        assert_eq!(take_read(&shared), Some(480));
        finish_read(&shared, 480);

        queue_read_recovery(&shared, 480);
        let state = shared.state.lock().unwrap();
        assert!(state.read_recovery_attempted.contains(&480));
        assert!(!state.reads_after_refresh.contains(&480));
        assert!(state.pending_refreshes.is_empty());
        assert!(state.pending_refresh_order.is_empty());
    }

    #[test]
    fn cache_read_waits_for_refresh_completion() {
        let shared = WorkerShared::default();
        {
            let mut state = shared.state.lock().unwrap();
            queue_refresh_locked(&mut state, 480, None);
            queue_read_locked(&mut state, 480);
        }

        assert_eq!(take_read(&shared), None);
        assert_eq!(
            take_refresh(&shared).map(|request| request.app_id),
            Some(480)
        );
        finish_refresh(&shared, 480);
        assert_eq!(take_read(&shared), Some(480));
    }

    #[test]
    fn later_refresh_moves_a_queued_read_behind_it() {
        let shared = WorkerShared::default();
        {
            let mut state = shared.state.lock().unwrap();
            queue_read_locked(&mut state, 480);
            queue_refresh_locked(&mut state, 480, None);
        }

        assert_eq!(take_read(&shared), None);
        assert_eq!(
            take_refresh(&shared).map(|request| request.app_id),
            Some(480)
        );
        finish_refresh(&shared, 480);
        assert_eq!(take_read(&shared), Some(480));
    }

    #[test]
    fn refresh_rerun_keeps_read_behind_the_latest_request() {
        let shared = WorkerShared::default();
        {
            let mut state = shared.state.lock().unwrap();
            queue_refresh_locked(&mut state, 480, None);
        }
        assert_eq!(
            take_refresh(&shared).map(|request| request.app_id),
            Some(480)
        );
        {
            let mut state = shared.state.lock().unwrap();
            queue_read_locked(&mut state, 480);
            queue_refresh_locked(&mut state, 480, None);
        }

        finish_refresh(&shared, 480);
        assert_eq!(take_read(&shared), None);
        assert_eq!(
            take_refresh(&shared).map(|request| request.app_id),
            Some(480)
        );
        finish_refresh(&shared, 480);
        assert_eq!(take_read(&shared), Some(480));
    }

    #[test]
    fn diagnostic_query_is_serviced_without_losing_pending_read() {
        let shared = WorkerShared::default();
        let (reply, _result) = mpsc::sync_channel(1);
        {
            let mut state = shared.state.lock().unwrap();
            queue_read_locked(&mut state, 480);
            state.queries.push_back(WorkerQuery::UserStats {
                app_id: 480,
                steam_id64: 7,
                reply,
            });
        }

        assert!(take_query(&shared).is_some());
        assert!(take_query(&shared).is_none());
        assert_eq!(take_read(&shared), Some(480));
    }

    // Takers are non-blocking; the epoch/futex boundary owns all parking.
    #[test]
    fn takers_do_not_block_on_an_empty_queue() {
        let shared = WorkerShared::default();
        assert!(take_query(&shared).is_none());
        assert!(take_read(&shared).is_none());
        assert!(take_refresh(&shared).is_none());
    }
}
