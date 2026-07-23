#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prost::Message;
use tracing::{debug, info, warn};
use vapor_forge_cloud_core::PlaytimeEntry as RemotePlaytimeEntry;
use vapor_forge_features::playtime::{PlaytimeGame, PlaytimeSnapshot};
use vapor_forge_steam_protocol::{
    PlayerGetLastPlayedTimesResponse, PlayerLastPlayedGame, PlayerLastPlayedTimesNotification,
};
use vapor_forge_sync_state::playtime::{Outbox, PlaytimeEntry};

use crate::downsync_worker::SubscriptionContext;

#[derive(Clone)]
struct PlaytimeWorker {
    pending: Arc<Mutex<HashMap<(u64, u32), PlaytimeGame>>>,
    wake: mpsc::SyncSender<()>,
}

static WORKER: OnceLock<PlaytimeWorker> = OnceLock::new();
static WORKER_INIT: Mutex<()> = Mutex::new(());
static REMOTE_STATE: OnceLock<Mutex<Option<RemotePlaytimeState>>> = OnceLock::new();

#[derive(Debug)]
struct RemotePlaytimeState {
    context: SubscriptionContext,
    entries: HashMap<u32, RemotePlaytimeEntry>,
}

pub fn ensure_started() {
    let _ = worker();
}

pub fn queue(snapshot: PlaytimeSnapshot) {
    if snapshot.games.is_empty() {
        return;
    }
    let Some(worker) = worker() else {
        return;
    };
    match worker.pending.lock() {
        Ok(mut pending) => {
            for game in snapshot.games {
                let key = (snapshot.steam_id64, game.app_id);
                pending
                    .entry(key)
                    .and_modify(|current| {
                        current.playtime_minutes =
                            current.playtime_minutes.max(game.playtime_minutes);
                        current.playtime_2weeks_minutes = game.playtime_2weeks_minutes;
                        current.last_played_at = match (current.last_played_at, game.last_played_at)
                        {
                            (Some(a), Some(b)) => Some(a.max(b)),
                            (some, None) | (None, some) => some,
                        };
                    })
                    .or_insert(game);
            }
            worker.wake();
        }
        Err(_) => warn!("playtime-sync: pending snapshot lock poisoned"),
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
    let path = vapor_forge_sync_state::playtime::default_outbox_path()?;
    let outbox = match Outbox::open(&path) {
        Ok(outbox) => Arc::new(Mutex::new(outbox)),
        Err(error) => {
            warn!(%error, path = %path.display(), "playtime-sync: outbox unavailable");
            return None;
        }
    };
    let pending = Arc::new(Mutex::new(HashMap::new()));
    let (wake, receiver) = mpsc::sync_channel(1);
    let worker_outbox = Arc::clone(&outbox);
    let worker_pending = Arc::clone(&pending);
    if std::thread::Builder::new()
        .name("playtime-upload".into())
        .spawn(move || upload_loop(worker_outbox, worker_pending, receiver))
        .is_err()
    {
        warn!("playtime-sync: failed to start upload worker");
        return None;
    }
    info!(path = %path.display(), "playtime-sync: durable outbox ready");
    let _ = WORKER.set(PlaytimeWorker { pending, wake });
    WORKER.get()
}

fn upload_loop(
    outbox: Arc<Mutex<Outbox>>,
    pending: Arc<Mutex<HashMap<(u64, u32), PlaytimeGame>>>,
    wake: mpsc::Receiver<()>,
) {
    loop {
        match wake.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => debounce(&wake),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        persist_pending(&outbox, &pending);
        flush(&outbox);
    }
}

fn persist_pending(
    outbox: &Arc<Mutex<Outbox>>,
    pending: &Arc<Mutex<HashMap<(u64, u32), PlaytimeGame>>>,
) {
    let Some(backend) = crate::cloud_backend::backend_context() else {
        return;
    };
    let owner_scope = backend.credential_scope();
    let observed_at = unix_now();
    let games = match pending.lock() {
        Ok(mut pending) => pending.drain().collect::<Vec<_>>(),
        Err(_) => return,
    };
    if games.is_empty() {
        return;
    }
    let entries = games
        .into_iter()
        .map(|((steam_id64, _), game)| PlaytimeEntry {
            owner_scope: owner_scope.clone(),
            owner_steam_id64: steam_id64.to_string(),
            app_id: game.app_id,
            playtime_minutes: game.playtime_minutes,
            playtime_2weeks_minutes: game.playtime_2weeks_minutes,
            last_played_at: game.last_played_at,
            observed_at,
        })
        .collect::<Vec<_>>();
    match outbox.lock() {
        Ok(mut outbox) => {
            if let Err(error) = outbox.enqueue(&entries) {
                warn!(%error, "playtime-sync: failed to persist snapshot");
                restore_pending(pending, entries);
            }
        }
        Err(_) => restore_pending(pending, entries),
    }
}

fn restore_pending(
    pending: &Arc<Mutex<HashMap<(u64, u32), PlaytimeGame>>>,
    entries: Vec<PlaytimeEntry>,
) {
    let Ok(mut pending) = pending.lock() else {
        return;
    };
    for entry in entries {
        let Ok(steam_id64) = entry.owner_steam_id64.parse() else {
            continue;
        };
        pending
            .entry((steam_id64, entry.app_id))
            .and_modify(|current| {
                current.playtime_minutes = current.playtime_minutes.max(entry.playtime_minutes);
                current.last_played_at = match (current.last_played_at, entry.last_played_at) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (some, None) | (None, some) => some,
                };
            })
            .or_insert(PlaytimeGame {
                app_id: entry.app_id,
                playtime_minutes: entry.playtime_minutes,
                playtime_2weeks_minutes: entry.playtime_2weeks_minutes,
                last_played_at: entry.last_played_at,
            });
    }
}

fn debounce(wake: &mpsc::Receiver<()>) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match wake.recv_timeout(remaining) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn flush(outbox: &Arc<Mutex<Outbox>>) -> bool {
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
    let scope = backend.credential_scope();

    for _ in 0..20 {
        let accounts = match outbox.lock() {
            Ok(outbox) => match outbox.ready_accounts(&scope, unix_now()) {
                Ok(accounts) => accounts,
                Err(error) => {
                    warn!(%error, "playtime-sync: failed to read pending accounts");
                    return false;
                }
            },
            Err(_) => return false,
        };
        if accounts.is_empty() {
            return true;
        }
        let mut attempted = false;
        for steam_id64 in accounts {
            let entries = match outbox.lock() {
                Ok(outbox) => match outbox.pending(&scope, &steam_id64, unix_now()) {
                    Ok(entries) => entries,
                    Err(error) => {
                        warn!(%error, "playtime-sync: failed to read outbox");
                        return false;
                    }
                },
                Err(_) => return false,
            };
            if entries.is_empty() {
                continue;
            }
            attempted = true;
            let result = backend.upload_playtime(descriptor.client_id, &steam_id64, &entries);
            let mut guard = match outbox.lock() {
                Ok(guard) => guard,
                Err(_) => return false,
            };
            match result {
                Ok(()) => {
                    if let Err(error) = guard.mark_delivered(&entries) {
                        warn!(%error, "playtime-sync: failed to acknowledge upload");
                        return false;
                    }
                    debug!(count = entries.len(), %steam_id64, "playtime-sync: snapshot uploaded");
                }
                Err(error) if error.is_retryable() => {
                    warn!(%error, %steam_id64, "playtime-sync: upload deferred");
                    if let Err(mark_error) = guard.mark_failed(&entries, unix_now()) {
                        warn!(%mark_error, "playtime-sync: failed to schedule retry");
                    }
                    return false;
                }
                Err(error) => {
                    warn!(%error, %steam_id64, "playtime-sync: server rejected snapshot");
                    if let Err(mark_error) = guard.mark_delivered(&entries) {
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

/// Replace the cached remote playtime with a freshly converged snapshot. The
/// subscription context travels with the state so a logout, account switch,
/// device change, or backend reload makes it unusable immediately.
pub(crate) fn apply_remote_playtime(
    context: &SubscriptionContext,
    entries: Vec<RemotePlaytimeEntry>,
) {
    if !context.is_current() {
        return;
    }
    let next = RemotePlaytimeState {
        context: context.clone(),
        entries: entries
            .into_iter()
            .map(|entry| (entry.app_id, entry))
            .collect(),
    };
    let mut remote = REMOTE_STATE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if context.is_current() {
        *remote = Some(next);
    }
}

/// Drop cached down-sync state when the authoritative Steam identity changes.
pub(crate) fn clear_remote_playtime() {
    let Some(remote) = REMOTE_STATE.get() else {
        return;
    };
    *remote
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

pub(crate) fn merge_response(steam_id64: u64, body: &[u8]) -> Option<Vec<u8>> {
    let mut response = PlayerGetLastPlayedTimesResponse::decode(body).ok()?;
    merge_games(steam_id64, &mut response.games).then(|| response.encode_to_vec())
}

pub(crate) fn merge_notification(steam_id64: u64, body: &[u8]) -> Option<Vec<u8>> {
    let mut notification = PlayerLastPlayedTimesNotification::decode(body).ok()?;
    merge_games(steam_id64, &mut notification.games).then(|| notification.encode_to_vec())
}

fn merge_games(steam_id64: u64, games: &mut Vec<PlayerLastPlayedGame>) -> bool {
    let mut remote = REMOTE_STATE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let current_context = remote
        .as_ref()
        .map(|state| state.context.clone())
        .filter(SubscriptionContext::is_current);
    merge_cached_games(&mut remote, current_context.as_ref(), steam_id64, games)
}

fn merge_cached_games(
    remote: &mut Option<RemotePlaytimeState>,
    current_context: Option<&SubscriptionContext>,
    steam_id64: u64,
    games: &mut Vec<PlayerLastPlayedGame>,
) -> bool {
    let context_matches = remote
        .as_ref()
        .zip(current_context)
        .is_some_and(|(state, current)| state.context == *current);
    if !context_matches {
        *remote = None;
        return false;
    }
    let remote = remote.as_ref().expect("validated remote playtime state");
    if remote.context.steam_id64() != steam_id64 {
        return false;
    }
    let mut changed = false;
    for (app_id, state) in &remote.entries {
        let Ok(app_id_i32) = i32::try_from(*app_id) else {
            continue;
        };
        let Ok(forever) = i32::try_from(state.playtime_minutes) else {
            continue;
        };
        let Ok(two_weeks) = i32::try_from(state.playtime_2weeks_minutes) else {
            continue;
        };
        let last_playtime = state
            .last_played_at
            .and_then(|value| u32::try_from(value).ok());
        if let Some(game) = games
            .iter_mut()
            .find(|game| game.app_id == Some(app_id_i32))
        {
            let merged_forever = game.playtime_forever.unwrap_or(0).max(forever);
            let merged_last = match (game.last_playtime, last_playtime) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (some, None) | (None, some) => some,
            };
            changed |= game.playtime_forever != Some(merged_forever)
                || game.playtime_2weeks != Some(two_weeks)
                || game.last_playtime != merged_last;
            game.playtime_forever = Some(merged_forever);
            game.playtime_2weeks = Some(two_weeks);
            game.last_playtime = merged_last;
        } else {
            games.push(PlayerLastPlayedGame {
                app_id: Some(app_id_i32),
                playtime_forever: Some(forever),
                playtime_2weeks: Some(two_weeks),
                last_playtime,
                ..Default::default()
            });
            changed = true;
        }
    }
    changed
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(scope: &str, steam_id64: u64, generation: u64) -> SubscriptionContext {
        SubscriptionContext::new(scope.into(), 42, steam_id64, generation)
    }

    fn remote_entry(steam_id64: u64, app_id: u32) -> RemotePlaytimeEntry {
        RemotePlaytimeEntry {
            owner_scope: String::new(),
            owner_steam_id64: steam_id64.to_string(),
            app_id,
            playtime_minutes: 300,
            playtime_2weeks_minutes: 12,
            last_played_at: Some(1_800_000_000),
            observed_at: 20,
        }
    }

    fn cached_state(context: SubscriptionContext) -> Option<RemotePlaytimeState> {
        Some(RemotePlaytimeState {
            context,
            entries: [(620, remote_entry(76561198000000001, 620))]
                .into_iter()
                .collect(),
        })
    }

    #[test]
    fn remote_playtime_is_merged_without_changing_the_observed_body() {
        let steam_id64 = 76561198000000001;
        let current = context("scope-a", steam_id64, 7);
        let mut remote = cached_state(current.clone());
        let mut games = PlayerGetLastPlayedTimesResponse {
            games: vec![PlayerLastPlayedGame {
                app_id: Some(620),
                playtime_forever: Some(200),
                playtime_2weeks: Some(5),
                last_playtime: Some(1_700_000_000),
                ..Default::default()
            }],
        };
        let original = games.encode_to_vec();

        assert!(merge_cached_games(
            &mut remote,
            Some(&current),
            steam_id64,
            &mut games.games,
        ));
        assert_eq!(games.games[0].playtime_forever, Some(300));
        assert_eq!(games.games[0].playtime_2weeks, Some(12));
        assert_eq!(games.games[0].last_playtime, Some(1_800_000_000));
        let untouched = PlayerGetLastPlayedTimesResponse::decode(original.as_slice()).unwrap();
        assert_eq!(untouched.games[0].playtime_forever, Some(200));
    }

    #[test]
    fn prior_login_playtime_is_discarded_for_the_same_account() {
        let steam_id64 = 76561198000000001;
        let mut remote = cached_state(context("scope-a", steam_id64, 7));
        let current = context("scope-a", steam_id64, 8);
        let mut games = Vec::new();

        assert!(!merge_cached_games(
            &mut remote,
            Some(&current),
            steam_id64,
            &mut games,
        ));
        assert!(remote.is_none());
        assert!(games.is_empty());
    }

    #[test]
    fn prior_backend_playtime_is_discarded_for_the_same_identity() {
        let steam_id64 = 76561198000000001;
        let mut remote = cached_state(context("scope-a", steam_id64, 7));
        let current = context("scope-b", steam_id64, 7);
        let mut games = Vec::new();

        assert!(!merge_cached_games(
            &mut remote,
            Some(&current),
            steam_id64,
            &mut games,
        ));
        assert!(remote.is_none());
        assert!(games.is_empty());
    }

    #[test]
    fn other_account_packet_does_not_discard_the_current_cache() {
        let steam_id64 = 76561198000000001;
        let current = context("scope-a", steam_id64, 7);
        let mut remote = cached_state(current.clone());
        let mut games = Vec::new();

        assert!(!merge_cached_games(
            &mut remote,
            Some(&current),
            76561198000000002,
            &mut games,
        ));
        assert!(remote.is_some());
        assert!(games.is_empty());
    }
}
