use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::{debug, info, warn};
use vapor_forge_features::playtime::{PlaytimeGame, PlaytimeSnapshot};
use vapor_forge_playtime_sync::{CumulusSettings, Outbox, PlaytimeEntry};

#[derive(Clone)]
struct PlaytimeWorker {
    pending: Arc<Mutex<HashMap<(u64, u32), PlaytimeGame>>>,
    wake: mpsc::SyncSender<()>,
}

static WORKER: OnceLock<PlaytimeWorker> = OnceLock::new();
static WORKER_INIT: Mutex<()> = Mutex::new(());

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
    let path = vapor_forge_playtime_sync::default_outbox_path()?;
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
    let Some(settings) = settings_context() else {
        return;
    };
    let owner_scope =
        vapor_forge_playtime_sync::credential_scope(&settings.server_url, &settings.token);
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

fn flush(outbox: &Arc<Mutex<Outbox>>) {
    let Some(settings) = settings_context() else {
        return;
    };
    let Some(descriptor) = vapor_forge_achievement_sync::device_descriptor() else {
        return;
    };
    let binding_settings = vapor_forge_achievement_sync::CumulusSettings {
        server_url: settings.server_url.clone(),
        token: settings.token.clone(),
        timeout_connect_ms: settings.timeout_connect_ms,
        timeout_ms: settings.timeout_ms,
    };
    if let Err(error) =
        vapor_forge_achievement_sync::ensure_device_bound(&binding_settings, &descriptor)
    {
        warn!(%error, "playtime-sync: device binding deferred");
        return;
    }
    let scope = vapor_forge_playtime_sync::credential_scope(&settings.server_url, &settings.token);

    for _ in 0..20 {
        let accounts = match outbox.lock() {
            Ok(outbox) => match outbox.ready_accounts(&scope, unix_now()) {
                Ok(accounts) => accounts,
                Err(error) => {
                    warn!(%error, "playtime-sync: failed to read pending accounts");
                    return;
                }
            },
            Err(_) => return,
        };
        if accounts.is_empty() {
            return;
        }
        let mut attempted = false;
        for steam_id64 in accounts {
            let entries = match outbox.lock() {
                Ok(outbox) => match outbox.pending(&scope, &steam_id64, unix_now()) {
                    Ok(entries) => entries,
                    Err(error) => {
                        warn!(%error, "playtime-sync: failed to read outbox");
                        return;
                    }
                },
                Err(_) => return,
            };
            if entries.is_empty() {
                continue;
            }
            attempted = true;
            let result = vapor_forge_playtime_sync::upload(
                &settings,
                descriptor.client_id,
                &steam_id64,
                &entries,
            );
            let mut guard = match outbox.lock() {
                Ok(guard) => guard,
                Err(_) => return,
            };
            match result {
                Ok(()) => {
                    if let Err(error) = guard.mark_delivered(&entries) {
                        warn!(%error, "playtime-sync: failed to acknowledge upload");
                        return;
                    }
                    debug!(count = entries.len(), %steam_id64, "playtime-sync: snapshot uploaded");
                }
                Err(error) if error.is_retryable() => {
                    warn!(%error, %steam_id64, "playtime-sync: upload deferred");
                    if let Err(mark_error) = guard.mark_failed(&entries, unix_now()) {
                        warn!(%mark_error, "playtime-sync: failed to schedule retry");
                    }
                    return;
                }
                Err(error) => {
                    warn!(%error, %steam_id64, "playtime-sync: server rejected snapshot");
                    if let Err(mark_error) = guard.mark_delivered(&entries) {
                        warn!(%mark_error, "playtime-sync: failed to discard rejected snapshot");
                    }
                }
            }
        }
        if !attempted {
            return;
        }
    }
}

fn settings_context() -> Option<CumulusSettings> {
    let config = crate::client::install::config();
    if !config.cumulus_configured() {
        return None;
    }
    Some(CumulusSettings {
        server_url: config.cloud.server_url.clone(),
        token: config.cloud.token.clone(),
        timeout_connect_ms: config.cloud.timeout_connect_ms,
        timeout_ms: config.cloud.timeout_ms,
    })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
