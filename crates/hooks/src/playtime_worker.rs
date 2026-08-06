#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use vapor_forge_cloud_core::PlaytimeEntry;
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_core::unix_now;
use vapor_forge_features::playtime::{PlaytimeGame, PlaytimeSnapshot};
use vapor_forge_sync_journal::{values, SyncJournal};

#[derive(Clone)]
struct PlaytimeWorker {
    pending: Arc<Mutex<HashMap<PendingPlaytimeKey, PlaytimeGame>>>,
    wake: mpsc::SyncSender<()>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PendingPlaytimeKey {
    owner: PendingPlaytimeOwner,
    app_id: u32,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PendingPlaytimeOwner {
    runtime: crate::client::playtime_downlink::RuntimeKey,
    principal_scope: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingPersistence {
    Complete,
    Retry,
    AwaitingPrincipal,
}

static WORKER: OnceLock<PlaytimeWorker> = OnceLock::new();
static WORKER_INIT: Mutex<()> = Mutex::new(());
static CONTEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
const SNAPSHOT_DEBOUNCE: Duration = Duration::from_millis(300);
const SNAPSHOT_HARD_DEADLINE: Duration = Duration::from_secs(2);
const READY_RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Default)]
struct DeviceBindingGate {
    permanently_blocked_generation: Option<u64>,
}

impl DeviceBindingGate {
    fn allows(&self, generation: u64) -> bool {
        self.permanently_blocked_generation != Some(generation)
    }

    fn record_failure(&mut self, generation: u64, retryable: bool) {
        self.permanently_blocked_generation = (!retryable).then_some(generation);
    }

    fn record_success(&mut self) {
        self.permanently_blocked_generation = None;
    }

    fn deadline(&self, generation: u64, deadline: Option<i64>) -> Option<i64> {
        if self.allows(generation) {
            deadline
        } else {
            None
        }
    }
}

pub fn ensure_started() {
    let _ = worker();
}

pub(crate) fn notify_context_changed() {
    CONTEXT_GENERATION.fetch_add(1, Ordering::AcqRel);
    if let Some(worker) = WORKER.get() {
        worker.wake();
    }
}

pub(crate) fn notify_principal_available() {
    if let Some(worker) = WORKER.get() {
        worker.wake();
    }
}

/// Whether this runtime is responsible for an app's playtime.
///
/// Steam delivers its whole library in one refresh, but the playtime of an app
/// the account genuinely owns is Steam's own to sync. The check sits at the two
/// intake points so a foreign app never reaches memory, let alone the backend.
///
/// Asks the effective config rather than classifying: this runs once per app in
/// a library-sized batch, and `classify_app` would additionally consult the
/// runtime ownership snapshot, which is not something a filter should touch.
fn is_ours(config: &RuntimeConfig, app_id: u32) -> bool {
    app_id != 0 && config.is_controlled_app(AppId(app_id))
}

/// Merge a native snapshot into the upload worker.
///
/// Returns false when the current event could not be retained.
pub fn queue(snapshot: PlaytimeSnapshot) -> bool {
    if snapshot.games.is_empty() {
        return true;
    }
    let Some(worker) = worker() else {
        return false;
    };
    let Some(owner) = current_playtime_owner() else {
        return false;
    };
    if snapshot.steam_id64 != owner.runtime.steam_id64 {
        return false;
    }
    let config = crate::client::install::config();
    let mut pending = worker
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for game in snapshot
        .games
        .into_iter()
        .filter(|game| is_ours(&config, game.app_id))
    {
        merge_pending_game(&mut pending, owner.clone(), game);
    }
    drop(pending);
    worker.wake();
    true
}

impl PlaytimeWorker {
    fn wake(&self) {
        let _ = self.wake.try_send(());
    }
}

fn worker() -> Option<&'static PlaytimeWorker> {
    if let Some(worker) = WORKER.get() {
        return Some(worker);
    }
    let _init = WORKER_INIT.lock().ok()?;
    if let Some(worker) = WORKER.get() {
        return Some(worker);
    }
    let journal = crate::sync_journal::shared()?;
    let pending = Arc::new(Mutex::new(HashMap::new()));
    let (wake, receiver) = mpsc::sync_channel(1);
    let worker_journal = Arc::clone(&journal);
    let worker_pending = Arc::clone(&pending);
    if std::thread::Builder::new()
        .name("playtime-upload".into())
        .spawn(move || upload_loop(worker_journal, worker_pending, receiver))
        .is_err()
    {
        warn!("playtime-sync: failed to start upload worker");
        return None;
    }
    info!("playtime-sync: durable journal ready");
    let _ = WORKER.set(PlaytimeWorker { pending, wake });
    WORKER.get()
}

fn upload_loop(
    journal: Arc<SyncJournal>,
    pending: Arc<Mutex<HashMap<PendingPlaytimeKey, PlaytimeGame>>>,
    wake: mpsc::Receiver<()>,
) {
    let mut first_pass = true;
    let mut next_attempt_at = None;
    let mut pending_retry_at = None;
    let mut device_binding = DeviceBindingGate::default();
    loop {
        let event = if first_pass {
            first_pass = false;
            UploadWake::Deadline
        } else {
            wait_for_upload_work(&wake, next_attempt_at, pending_retry_at)
        };
        let persistence = match event {
            UploadWake::Event => debounce_and_persist(&journal, &pending, &wake),
            UploadWake::Deadline => persist_pending(&journal, &pending),
            UploadWake::Disconnected => break,
        };
        pending_retry_at =
            (persistence == PendingPersistence::Retry).then(|| Instant::now() + READY_RETRY_DELAY);
        let binding_generation = CONTEXT_GENERATION.load(Ordering::Acquire);
        if device_binding.allows(binding_generation) {
            match flush(&journal) {
                FlushOutcome::Complete => device_binding.record_success(),
                FlushOutcome::DeviceBindingFailed { retryable } => {
                    device_binding.record_failure(binding_generation, retryable);
                }
            }
        }
        next_attempt_at = device_binding.deadline(
            CONTEXT_GENERATION.load(Ordering::Acquire),
            next_playtime_attempt_at(&journal),
        );
    }
}

enum UploadWake {
    Event,
    Deadline,
    Disconnected,
}

fn wait_for_upload_work(
    wake: &mpsc::Receiver<()>,
    next_attempt_at: Option<i64>,
    pending_retry_at: Option<Instant>,
) -> UploadWake {
    let journal_delay = next_attempt_at.map(|next_attempt_at| {
        let now = unix_now();
        if next_attempt_at <= now {
            READY_RETRY_DELAY
        } else {
            Duration::from_secs(next_attempt_at.saturating_sub(now) as u64)
        }
    });
    let pending_delay = pending_retry_at.map(|deadline| {
        deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO)
    });
    let delay = match (journal_delay, pending_delay) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (some, None) | (None, some) => some,
    };
    let Some(delay) = delay else {
        return match wake.recv() {
            Ok(()) => UploadWake::Event,
            Err(_) => UploadWake::Disconnected,
        };
    };
    match wake.recv_timeout(delay) {
        Ok(()) => UploadWake::Event,
        Err(mpsc::RecvTimeoutError::Timeout) => UploadWake::Deadline,
        Err(mpsc::RecvTimeoutError::Disconnected) => UploadWake::Disconnected,
    }
}

fn next_playtime_attempt_at(journal: &SyncJournal) -> Option<i64> {
    let backend = crate::cloud_backend::backend_context()?;
    vapor_forge_cloud_core::device_descriptor()?;
    let scope = crate::sync_journal::cached_principal_scope(backend.as_ref())?;
    match journal.next_playtime_attempt_at(&scope) {
        Ok(next) => next,
        Err(error) => {
            warn!(%error, "playtime-sync: failed to schedule journal");
            None
        }
    }
}

fn persist_pending(
    journal: &SyncJournal,
    pending: &Arc<Mutex<HashMap<PendingPlaytimeKey, PlaytimeGame>>>,
) -> PendingPersistence {
    let observed_at = unix_now();
    let mut pending_guard = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let games = std::mem::take(&mut *pending_guard)
        .into_iter()
        .collect::<Vec<_>>();
    drop(pending_guard);
    if games.is_empty() {
        return PendingPersistence::Complete;
    }
    let (mut games, unbound) = partition_pending_games(games);
    let mut awaiting_principal = false;
    if !unbound.is_empty() {
        let mut unresolved = Vec::new();
        for (mut key, game) in unbound {
            if let Some(scope) = crate::sync_journal::cached_principal_for_credential(
                &key.owner.runtime.credential_fingerprint,
            ) {
                key.owner.principal_scope = Some(scope);
                games.push((key, game));
            } else {
                unresolved.push((key, game));
            }
        }
        awaiting_principal = restore_pending(pending, unresolved);
    }
    if games.is_empty() {
        return if awaiting_principal {
            PendingPersistence::AwaitingPrincipal
        } else {
            PendingPersistence::Complete
        };
    }
    games = coalesce_pending_games(games);
    let Some(entries) = pending_entries(&games, observed_at) else {
        warn!("playtime-sync: pending snapshot has no principal scope");
        return PendingPersistence::Complete;
    };
    if let Err(error) = journal.enqueue_playtime(&entries) {
        warn!(%error, "playtime-sync: failed to persist snapshot");
        return if restore_pending(pending, games) {
            PendingPersistence::Retry
        } else {
            PendingPersistence::Complete
        };
    }
    if awaiting_principal {
        PendingPersistence::AwaitingPrincipal
    } else {
        PendingPersistence::Complete
    }
}

type PendingGames = Vec<(PendingPlaytimeKey, PlaytimeGame)>;

fn partition_pending_games(games: PendingGames) -> (PendingGames, PendingGames) {
    let mut bound = Vec::new();
    let mut unbound = Vec::new();
    for entry in games {
        if entry.0.owner.principal_scope.is_some() {
            bound.push(entry);
        } else {
            unbound.push(entry);
        }
    }
    (bound, unbound)
}

fn pending_entries(
    games: &[(PendingPlaytimeKey, PlaytimeGame)],
    observed_at: i64,
) -> Option<Vec<PlaytimeEntry>> {
    games
        .iter()
        .map(|(key, game)| {
            Some(PlaytimeEntry {
                owner_scope: key.owner.principal_scope.clone()?,
                owner_steam_id64: key.owner.runtime.steam_id64.to_string(),
                app_id: game.app_id,
                playtime_minutes: game.playtime_minutes,
                playtime_2weeks_minutes: game.playtime_2weeks_minutes,
                last_played_at: game.last_played_at,
                observed_at,
            })
        })
        .collect()
}

fn coalesce_pending_games(
    games: Vec<(PendingPlaytimeKey, PlaytimeGame)>,
) -> Vec<(PendingPlaytimeKey, PlaytimeGame)> {
    let mut pending = HashMap::new();
    for (key, game) in games {
        merge_pending_game(&mut pending, key.owner, game);
    }
    pending.into_iter().collect()
}

fn merge_pending_game(
    pending: &mut HashMap<PendingPlaytimeKey, PlaytimeGame>,
    owner: PendingPlaytimeOwner,
    game: PlaytimeGame,
) {
    let key = PendingPlaytimeKey {
        owner,
        app_id: game.app_id,
    };
    pending
        .entry(key)
        .and_modify(|current| {
            current.playtime_minutes = current.playtime_minutes.max(game.playtime_minutes);
            current.playtime_2weeks_minutes = game.playtime_2weeks_minutes;
            current.last_played_at = match (current.last_played_at, game.last_played_at) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (some, None) | (None, some) => some,
            };
        })
        .or_insert(game);
}

fn current_playtime_owner() -> Option<PendingPlaytimeOwner> {
    let runtime = crate::client::playtime_downlink::current_runtime_key()?;
    let backend = crate::cloud_backend::backend_context()?;
    if backend.credential_fingerprint() != runtime.credential_fingerprint {
        return None;
    }
    let principal_scope = crate::sync_journal::cached_principal_scope(backend.as_ref());
    if crate::client::playtime_downlink::current_runtime_key().as_ref() != Some(&runtime) {
        return None;
    }
    Some(PendingPlaytimeOwner {
        runtime,
        principal_scope,
    })
}

fn restore_pending(
    pending: &Arc<Mutex<HashMap<PendingPlaytimeKey, PlaytimeGame>>>,
    games: Vec<(PendingPlaytimeKey, PlaytimeGame)>,
) -> bool {
    let mut pending = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut restored = false;
    for (key, game) in games
        .into_iter()
        .filter(|(key, _)| pending_can_survive(&key.owner))
    {
        merge_pending_game(&mut pending, key.owner, game);
        restored = true;
    }
    restored
}

fn pending_can_survive(owner: &PendingPlaytimeOwner) -> bool {
    pending_can_survive_with(owner, |runtime| {
        crate::client::playtime_downlink::runtime_key_is_current(runtime)
    })
}

fn pending_can_survive_with(
    owner: &PendingPlaytimeOwner,
    is_current: impl FnOnce(&crate::client::playtime_downlink::RuntimeKey) -> bool,
) -> bool {
    owner.principal_scope.is_some() || is_current(&owner.runtime)
}

fn debounce_and_persist(
    journal: &SyncJournal,
    pending: &Arc<Mutex<HashMap<PendingPlaytimeKey, PlaytimeGame>>>,
    wake: &mpsc::Receiver<()>,
) -> PendingPersistence {
    let mut persistence = persist_pending(journal, pending);
    if collect_snapshot_burst(wake, SNAPSHOT_DEBOUNCE, SNAPSHOT_HARD_DEADLINE) {
        persistence = persist_pending(journal, pending);
    }
    persistence
}

fn collect_snapshot_burst(
    wake: &mpsc::Receiver<()>,
    debounce: Duration,
    hard_limit: Duration,
) -> bool {
    let hard_deadline = Instant::now() + hard_limit;
    let mut quiet_deadline = Instant::now() + debounce;
    let mut trailing = false;
    loop {
        let deadline = quiet_deadline.min(hard_deadline);
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match wake.recv_timeout(remaining) {
            Ok(()) => {
                trailing = true;
                quiet_deadline = (Instant::now() + debounce).min(hard_deadline);
            }
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    trailing
}

enum FlushOutcome {
    Complete,
    DeviceBindingFailed { retryable: bool },
}

fn flush(journal: &SyncJournal) -> FlushOutcome {
    let Some(backend) = crate::cloud_backend::backend_context() else {
        return FlushOutcome::Complete;
    };
    let Some(scope) = crate::sync_journal::cached_principal_scope(backend.as_ref()) else {
        return FlushOutcome::Complete;
    };
    let mut descriptor = None;

    for _ in 0..20 {
        let accounts = match journal.ready_playtime_accounts(&scope, unix_now()) {
            Ok(accounts) => accounts,
            Err(error) => {
                warn!(%error, "playtime-sync: failed to read pending accounts");
                return FlushOutcome::Complete;
            }
        };
        if accounts.is_empty() {
            return FlushOutcome::Complete;
        }
        if descriptor.is_none() {
            let Some(current) = vapor_forge_cloud_core::device_descriptor() else {
                return FlushOutcome::Complete;
            };
            if let Err(error) = backend.ensure_device_bound(&current) {
                let retryable = error.is_retryable();
                if retryable {
                    warn!(%error, "playtime-sync: device binding deferred");
                } else {
                    warn!(%error, "playtime-sync: device binding paused until context changes");
                }
                return FlushOutcome::DeviceBindingFailed { retryable };
            }
            descriptor = Some(current);
        }
        let client_id = descriptor
            .as_ref()
            .expect("descriptor initialized")
            .client_id;
        let mut attempted = false;
        for steam_id64 in accounts {
            let entries = match journal.pending_playtime(&scope, &steam_id64, unix_now()) {
                Ok(entries) => entries,
                Err(error) => {
                    warn!(%error, "playtime-sync: failed to read journal");
                    return FlushOutcome::Complete;
                }
            };
            if entries.is_empty() {
                continue;
            }
            attempted = true;
            match backend.upload_playtime(client_id, &steam_id64, &values(&entries)) {
                Ok(()) => {
                    if let Err(error) = journal.acknowledge_all(&entries) {
                        warn!(%error, "playtime-sync: failed to acknowledge upload");
                        return FlushOutcome::Complete;
                    }
                    debug!(count = entries.len(), %steam_id64, "playtime-sync: snapshot uploaded");
                }
                Err(error) if error.is_retryable() => {
                    warn!(%error, %steam_id64, "playtime-sync: upload deferred");
                    if let Err(mark_error) = journal.defer_all(&entries, unix_now()) {
                        warn!(%mark_error, "playtime-sync: failed to schedule retry");
                    }
                    return FlushOutcome::Complete;
                }
                Err(error) => {
                    warn!(%error, %steam_id64, "playtime-sync: server rejected snapshot");
                    if let Err(mark_error) = journal.acknowledge_all(&entries) {
                        warn!(%mark_error, "playtime-sync: failed to discard rejected snapshot");
                        return FlushOutcome::Complete;
                    }
                }
            }
        }
        if !attempted {
            return FlushOutcome::Complete;
        }
    }
    FlushOutcome::Complete
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(principal_scope: &str) -> PendingPlaytimeOwner {
        PendingPlaytimeOwner {
            runtime: crate::client::playtime_downlink::runtime_key(
                "credential".into(),
                76_561_198_000_000_001,
                7,
                11,
                13,
            ),
            principal_scope: Some(principal_scope.into()),
        }
    }

    fn game(app_id: u32, playtime_minutes: u32) -> PlaytimeGame {
        PlaytimeGame {
            app_id,
            playtime_minutes,
            playtime_2weeks_minutes: 0,
            last_played_at: None,
        }
    }

    #[test]
    fn principal_scope_is_part_of_the_pending_owner() {
        let mut pending = HashMap::new();
        merge_pending_game(&mut pending, owner("principal-a"), game(480, 10));
        merge_pending_game(&mut pending, owner("principal-b"), game(480, 20));

        assert_eq!(pending.len(), 2);
        assert_eq!(
            pending
                .keys()
                .filter_map(|key| key.owner.principal_scope.as_deref())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["principal-a", "principal-b"])
        );
    }

    #[test]
    fn captured_principal_scopes_survive_until_persistence() {
        let mut pending = HashMap::new();
        merge_pending_game(&mut pending, owner("principal-a"), game(480, 10));
        merge_pending_game(&mut pending, owner("principal-b"), game(620, 20));
        let pending = pending.into_iter().collect::<Vec<_>>();
        let entries = pending_entries(&pending, 100).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.owner_scope.as_str(), entry.app_id))
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([("principal-a", 480), ("principal-b", 620)])
        );
    }

    #[test]
    fn persistence_keeps_bound_games_from_a_stale_runtime() {
        let current = owner("principal-current");
        let mut stale = owner("principal-stale");
        stale.runtime.runtime_generation += 1;
        let games = vec![
            (
                PendingPlaytimeKey {
                    owner: current,
                    app_id: 480,
                },
                game(480, 10),
            ),
            (
                PendingPlaytimeKey {
                    owner: stale,
                    app_id: 620,
                },
                game(620, 20),
            ),
        ];

        let (bound, unbound) = partition_pending_games(games);

        assert_eq!(bound.len(), 2);
        assert!(unbound.is_empty());
    }

    #[test]
    fn partition_keeps_unbound_games_until_principal_lookup() {
        let mut current = owner("principal-current");
        current.principal_scope = None;
        let mut stale = owner("principal-stale");
        stale.principal_scope = None;
        stale.runtime.runtime_generation += 1;
        let games = vec![
            (
                PendingPlaytimeKey {
                    owner: current,
                    app_id: 480,
                },
                game(480, 10),
            ),
            (
                PendingPlaytimeKey {
                    owner: stale,
                    app_id: 620,
                },
                game(620, 20),
            ),
        ];

        let (bound, unbound) = partition_pending_games(games);

        assert!(bound.is_empty());
        assert_eq!(unbound.len(), 2);
    }

    #[test]
    fn only_bound_games_survive_a_stale_runtime() {
        let bound = owner("principal");
        let mut unbound = owner("principal");
        unbound.principal_scope = None;

        assert!(pending_can_survive_with(&bound, |_| false));
        assert!(!pending_can_survive_with(&unbound, |_| false));
        assert!(pending_can_survive_with(&unbound, |_| true));
    }

    #[test]
    fn unbound_snapshot_cannot_become_a_journal_entry() {
        let mut unbound = owner("principal");
        unbound.principal_scope = None;
        let games = vec![(
            PendingPlaytimeKey {
                owner: unbound,
                app_id: 480,
            },
            game(480, 10),
        )];

        assert!(pending_entries(&games, 100).is_none());
    }

    #[test]
    fn isolated_snapshot_does_not_request_a_trailing_write() {
        let (_wake, receiver) = mpsc::channel();

        assert!(!collect_snapshot_burst(
            &receiver,
            Duration::from_millis(1),
            Duration::from_millis(5),
        ));
    }

    #[test]
    fn snapshot_burst_requests_one_trailing_write() {
        let (wake, receiver) = mpsc::channel();
        wake.send(()).unwrap();
        wake.send(()).unwrap();
        drop(wake);

        assert!(collect_snapshot_burst(
            &receiver,
            Duration::from_millis(1),
            Duration::from_millis(5),
        ));
    }

    #[test]
    fn pending_persistence_deadline_wakes_without_journal_work() {
        let (_wake, receiver) = mpsc::channel();

        assert!(matches!(
            wait_for_upload_work(&receiver, None, Some(Instant::now())),
            UploadWake::Deadline
        ));
    }

    #[test]
    fn permanent_device_binding_failure_waits_for_a_context_change() {
        let mut gate = DeviceBindingGate::default();
        gate.record_failure(7, false);

        assert!(!gate.allows(7));
        assert_eq!(gate.deadline(7, Some(10)), None);
        assert!(gate.allows(8));
        assert_eq!(gate.deadline(8, Some(10)), Some(10));

        gate.record_failure(8, true);
        assert!(gate.allows(8));
        assert_eq!(gate.deadline(8, Some(10)), Some(10));
    }
}
