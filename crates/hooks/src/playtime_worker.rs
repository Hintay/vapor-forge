#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use vapor_forge_cloud_core::{CloudBackend, PlaytimeEntry, PlaytimeSession};
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_core::unix_now;
use vapor_forge_features::playtime::{PlaytimeGame, PlaytimeSnapshot};
use vapor_forge_sync_journal::{values, SyncJournal};

#[derive(Clone)]
struct PlaytimeWorker {
    pending: Arc<Mutex<HashMap<PendingPlaytimeKey, PlaytimeGame>>>,
    journal: Arc<SyncJournal>,
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
    principal_scope: String,
}

static WORKER: OnceLock<PlaytimeWorker> = OnceLock::new();
static WORKER_INIT: Mutex<()> = Mutex::new(());
const SNAPSHOT_DEBOUNCE: Duration = Duration::from_millis(300);
const SNAPSHOT_HARD_DEADLINE: Duration = Duration::from_secs(2);
const READY_RETRY_DELAY: Duration = Duration::from_secs(2);

pub fn ensure_started() {
    let _ = worker();
}

pub(crate) fn notify_context_changed() {
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
    match worker.pending.lock() {
        Ok(mut pending) => {
            for game in snapshot
                .games
                .into_iter()
                .filter(|game| is_ours(&config, game.app_id))
            {
                merge_pending_game(&mut pending, owner.clone(), game);
            }
            worker.wake();
            true
        }
        Err(_) => {
            warn!("playtime-sync: pending snapshot lock poisoned");
            false
        }
    }
}

/// Persist disconnected-playtime reports before acknowledging their CM request.
pub(crate) fn persist_sessions(backend: &dyn CloudBackend, sessions: &[PlaytimeSession]) -> bool {
    if !backend.accepts_playtime_sessions() {
        return true;
    }
    let config = crate::client::install::config();
    let sessions = sessions
        .iter()
        .filter(|session| is_ours(&config, session.app_id))
        .cloned()
        .collect::<Vec<_>>();
    if sessions.is_empty() {
        return true;
    }
    let Some(worker) = worker() else {
        return false;
    };
    match worker.journal.enqueue_playtime_sessions(&sessions) {
        Ok(_) => {
            worker.wake();
            true
        }
        Err(error) => {
            warn!(%error, "playtime-sync: failed to persist Steam session");
            false
        }
    }
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
    let _ = WORKER.set(PlaytimeWorker {
        pending,
        journal,
        wake,
    });
    WORKER.get()
}

fn upload_loop(
    journal: Arc<SyncJournal>,
    pending: Arc<Mutex<HashMap<PendingPlaytimeKey, PlaytimeGame>>>,
    wake: mpsc::Receiver<()>,
) {
    let mut first_pass = true;
    let mut next_attempt_at = None;
    loop {
        let event = if first_pass {
            first_pass = false;
            UploadWake::Deadline
        } else {
            wait_for_upload_work(&wake, next_attempt_at)
        };
        match event {
            UploadWake::Event => debounce_and_persist(&journal, &pending, &wake),
            UploadWake::Deadline => persist_pending(&journal, &pending),
            UploadWake::Disconnected => break,
        }
        flush(&journal);
        next_attempt_at = next_playtime_attempt_at(&journal);
    }
}

enum UploadWake {
    Event,
    Deadline,
    Disconnected,
}

fn wait_for_upload_work(wake: &mpsc::Receiver<()>, next_attempt_at: Option<i64>) -> UploadWake {
    let Some(next_attempt_at) = next_attempt_at else {
        return match wake.recv() {
            Ok(()) => UploadWake::Event,
            Err(_) => UploadWake::Disconnected,
        };
    };
    let now = unix_now();
    let delay = if next_attempt_at <= now {
        READY_RETRY_DELAY
    } else {
        Duration::from_secs(next_attempt_at.saturating_sub(now) as u64)
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
    let scope = match crate::sync_journal::principal_scope(backend.as_ref()) {
        Ok(scope) => scope,
        Err(error) => {
            warn!(%error, "playtime-sync: principal unavailable while scheduling retry");
            return Some(unix_now().saturating_add(READY_RETRY_DELAY.as_secs() as i64));
        }
    };
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
) {
    let observed_at = unix_now();
    let games = match pending.lock() {
        Ok(mut pending) => std::mem::take(&mut *pending)
            .into_iter()
            .collect::<Vec<_>>(),
        Err(_) => return,
    };
    if games.is_empty() {
        return;
    }
    let entries = pending_entries(&games, observed_at);
    if let Err(error) = journal.enqueue_playtime(&entries) {
        warn!(%error, "playtime-sync: failed to persist snapshot");
        restore_pending(pending, games);
    }
}

fn pending_entries(
    games: &[(PendingPlaytimeKey, PlaytimeGame)],
    observed_at: i64,
) -> Vec<PlaytimeEntry> {
    games
        .iter()
        .map(|(key, game)| PlaytimeEntry {
            owner_scope: key.owner.principal_scope.clone(),
            owner_steam_id64: key.owner.runtime.steam_id64.to_string(),
            app_id: game.app_id,
            playtime_minutes: game.playtime_minutes,
            playtime_2weeks_minutes: game.playtime_2weeks_minutes,
            last_played_at: game.last_played_at,
            observed_at,
        })
        .collect()
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
    let principal_scope = match crate::sync_journal::principal_scope(backend.as_ref()) {
        Ok(scope) => scope,
        Err(error) => {
            warn!(%error, "playtime-sync: principal scope unavailable");
            return None;
        }
    };
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
) {
    let Ok(mut pending) = pending.lock() else {
        return;
    };
    for (key, game) in games {
        merge_pending_game(&mut pending, key.owner, game);
    }
}

fn debounce_and_persist(
    journal: &SyncJournal,
    pending: &Arc<Mutex<HashMap<PendingPlaytimeKey, PlaytimeGame>>>,
    wake: &mpsc::Receiver<()>,
) {
    persist_pending(journal, pending);
    let hard_deadline = Instant::now() + SNAPSHOT_HARD_DEADLINE;
    let mut deadline = Instant::now() + SNAPSHOT_DEBOUNCE;
    while let Some(remaining) = deadline
        .min(hard_deadline)
        .checked_duration_since(Instant::now())
    {
        match wake.recv_timeout(remaining) {
            Ok(()) => {
                persist_pending(journal, pending);
                deadline = (Instant::now() + SNAPSHOT_DEBOUNCE).min(hard_deadline);
            }
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn flush(journal: &SyncJournal) -> bool {
    let Some(backend) = crate::cloud_backend::backend_context() else {
        return false;
    };
    let Some(descriptor) = vapor_forge_cloud_core::device_descriptor() else {
        return false;
    };
    if let Err(error) = backend.ensure_device_bound(&descriptor) {
        warn!(%error, "playtime-sync: device binding deferred");
        return false;
    }
    let scope = match crate::sync_journal::principal_scope(backend.as_ref()) {
        Ok(scope) => scope,
        Err(error) => {
            warn!(%error, "playtime-sync: principal scope unavailable");
            return false;
        }
    };

    for _ in 0..20 {
        let accounts = match journal.ready_playtime_accounts(&scope, unix_now()) {
            Ok(accounts) => accounts,
            Err(error) => {
                warn!(%error, "playtime-sync: failed to read pending accounts");
                return false;
            }
        };
        if accounts.is_empty() {
            return true;
        }
        let mut attempted = false;
        for steam_id64 in accounts {
            let sessions = match journal.pending_playtime_sessions(&scope, &steam_id64, unix_now())
            {
                Ok(sessions) => sessions,
                Err(error) => {
                    warn!(%error, "playtime-sync: failed to read pending sessions");
                    return false;
                }
            };
            if !sessions.is_empty() {
                attempted = true;
                match backend.upload_playtime_sessions(
                    descriptor.client_id,
                    &steam_id64,
                    &values(&sessions),
                ) {
                    Ok(()) => {
                        if let Err(error) = journal.acknowledge_all(&sessions) {
                            warn!(%error, "playtime-sync: failed to acknowledge sessions");
                            return false;
                        }
                        debug!(count = sessions.len(), %steam_id64, "playtime-sync: sessions uploaded");
                    }
                    Err(error) if error.is_retryable() => {
                        warn!(%error, %steam_id64, "playtime-sync: session upload deferred");
                        if let Err(mark_error) = journal.defer_all(&sessions, unix_now()) {
                            warn!(%mark_error, "playtime-sync: failed to schedule session retry");
                        }
                        return false;
                    }
                    Err(error) => {
                        warn!(%error, %steam_id64, "playtime-sync: server rejected sessions");
                        if let Err(mark_error) = journal.acknowledge_all(&sessions) {
                            warn!(%mark_error, "playtime-sync: failed to discard rejected sessions");
                            return false;
                        }
                    }
                }
            }
            let entries = match journal.pending_playtime(&scope, &steam_id64, unix_now()) {
                Ok(entries) => entries,
                Err(error) => {
                    warn!(%error, "playtime-sync: failed to read journal");
                    return false;
                }
            };
            if entries.is_empty() {
                continue;
            }
            attempted = true;
            match backend.upload_playtime(descriptor.client_id, &steam_id64, &values(&entries)) {
                Ok(()) => {
                    if let Err(error) = journal.acknowledge_all(&entries) {
                        warn!(%error, "playtime-sync: failed to acknowledge upload");
                        return false;
                    }
                    debug!(count = entries.len(), %steam_id64, "playtime-sync: snapshot uploaded");
                }
                Err(error) if error.is_retryable() => {
                    warn!(%error, %steam_id64, "playtime-sync: upload deferred");
                    if let Err(mark_error) = journal.defer_all(&entries, unix_now()) {
                        warn!(%mark_error, "playtime-sync: failed to schedule retry");
                    }
                    return false;
                }
                Err(error) => {
                    warn!(%error, %steam_id64, "playtime-sync: server rejected snapshot");
                    if let Err(mark_error) = journal.acknowledge_all(&entries) {
                        warn!(%mark_error, "playtime-sync: failed to discard rejected snapshot");
                        return false;
                    }
                }
            }
        }
        if !attempted {
            return true;
        }
    }
    true
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
            ),
            principal_scope: principal_scope.into(),
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
                .map(|key| key.owner.principal_scope.as_str())
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
        let entries = pending_entries(&pending, 100);
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.owner_scope.as_str(), entry.app_id))
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([("principal-a", 480), ("principal-b", 620)])
        );
    }
}
