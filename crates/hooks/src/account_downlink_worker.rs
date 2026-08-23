#![forbid(unsafe_code)]

use std::cell::Cell;
use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tracing::{debug, info, warn};
use vapor_forge_cloud_core::{
    AccountPlaytimeSnapshot, AccountStatsWakeup, AccountStreamEvent, AccountSyncState,
    CloudBackend, DeviceDescriptor, StreamCancellation, StreamOutcome,
};

use crate::client::playtime_downlink::{self, RuntimeKey};
use crate::context_signal::ContextChangeSignal;

static WORKER_STATE: Mutex<WorkerState> = Mutex::new(WorkerState::Stopped);
static CONTEXT_CHANGE: OnceLock<ContextChangeSignal> = OnceLock::new();
static ACTIVE_STREAM: Mutex<Option<ActiveStreamState>> = Mutex::new(None);
const RETRY_INITIAL: Duration = Duration::from_secs(2);
const RETRY_MAX: Duration = Duration::from_secs(30);

struct RetryBackoff {
    next: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerState {
    Stopped,
    Starting,
    Running,
}

struct WorkerLifetime;

impl Drop for WorkerLifetime {
    fn drop(&mut self) {
        *worker_state() = WorkerState::Stopped;
    }
}

impl RetryBackoff {
    fn new() -> Self {
        Self {
            next: RETRY_INITIAL,
        }
    }

    fn reset(&mut self) {
        self.next = RETRY_INITIAL;
    }

    fn take_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(RETRY_MAX);
        delay
    }
}

pub(crate) fn ensure_started() {
    let mut state = worker_state();
    if *state != WorkerState::Stopped {
        return;
    }
    *state = WorkerState::Starting;
    match std::thread::Builder::new()
        .name("account-downlink".into())
        .spawn(|| {
            let _lifetime = WorkerLifetime;
            run();
        }) {
        Ok(_) => *state = WorkerState::Running,
        Err(error) => {
            *state = WorkerState::Stopped;
            warn!(%error, "account-downlink: failed to start event worker");
        }
    }
}

pub(crate) fn notify_context_changed() {
    let config = crate::client::install::config();
    if config.local_cloud_configured() || config.cumulus_configured() {
        ensure_started();
    }
    cancel_active_stream_if_stale();
    context_change_signal().notify();
}

fn worker_state() -> std::sync::MutexGuard<'static, WorkerState> {
    WORKER_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn run() {
    let mut retry = RetryBackoff::new();
    let mut observed_context_revision = context_change_signal().revision();
    loop {
        let signal_revision = context_change_signal().revision();
        if signal_revision != observed_context_revision {
            retry.reset();
            observed_context_revision = signal_revision;
        }
        let Some((backend, descriptor, key)) = prerequisites() else {
            context_change_signal().wait_after(signal_revision);
            continue;
        };
        if let Err(error) = crate::sync_journal::resolve_principal_scope(backend.as_ref()) {
            warn!(%error, "account-downlink: principal resolution deferred");
            if error.is_retryable() {
                wait_for_retry(signal_revision, &mut retry);
            } else {
                context_change_signal().wait_after(signal_revision);
            }
            continue;
        }
        if !playtime_downlink::runtime_key_is_current(&key) {
            continue;
        }
        if let Err(error) = backend.ensure_device_bound(&descriptor) {
            warn!(%error, "account-downlink: device binding deferred");
            if error.is_retryable() {
                wait_for_retry(signal_revision, &mut retry);
            } else {
                context_change_signal().wait_after(signal_revision);
            }
            continue;
        }
        if !playtime_downlink::runtime_key_is_current(&key) {
            continue;
        }

        let steam_id64 = key.steam_id64.to_string();
        let cancellation = StreamCancellation::new();
        let active = activate_stream(cancellation.clone(), key.clone());
        if !playtime_downlink::runtime_key_is_current(&key) {
            cancellation.cancel();
        }
        let received_event = Cell::new(false);
        let mut on_event = |event| {
            if playtime_downlink::runtime_key_is_current(&key) {
                received_event.set(true);
                process_event(&key, event);
            }
        };
        let outcome = backend.stream_account_events(
            descriptor.client_id,
            &steam_id64,
            &cancellation,
            &mut on_event,
        );
        drop(active);
        if received_event.get() {
            retry.reset();
        }
        match outcome {
            Ok(StreamOutcome::Stopped) => {}
            Ok(StreamOutcome::Unsupported) => {
                debug!("account-downlink: backend has no remote event stream");
                context_change_signal().wait_after(signal_revision);
            }
            Err(error) if error.is_retryable() => {
                warn!(%error, "account-downlink: event stream deferred");
                wait_for_retry(signal_revision, &mut retry);
            }
            Err(error) => {
                warn!(%error, "account-downlink: event stream suspended until context changes");
                context_change_signal().wait_after(signal_revision);
            }
        }
    }
}

fn wait_for_retry(signal_revision: u64, retry: &mut RetryBackoff) {
    let delay = retry.take_delay();
    debug!(
        retry_millis = delay.as_millis(),
        "account-downlink: waiting before retry"
    );
    context_change_signal().wait_timeout_after(signal_revision, delay);
}

fn process_event(key: &RuntimeKey, event: AccountStreamEvent) {
    match event {
        AccountStreamEvent::Baseline(state) => process_baseline(key, state),
        AccountStreamEvent::Playtime(snapshot) => process_playtime(key, snapshot),
        AccountStreamEvent::StatsWakeup(wakeup) => process_stats_wakeup(key, wakeup),
    }
}

fn process_baseline(key: &RuntimeKey, state: AccountSyncState) {
    let app_ids = baseline_stats_apps(&state);
    process_playtime(
        key,
        AccountPlaytimeSnapshot {
            steam_id64: key.steam_id64.to_string(),
            playtime_revision: state.playtime_revision,
            origin_client_id: None,
            playtime: state.playtime,
        },
    );
    if !app_ids.is_empty() {
        process_stats_wakeup(
            key,
            AccountStatsWakeup {
                steam_id64: key.steam_id64.to_string(),
                origin_client_id: None,
                app_ids,
            },
        );
    }
}

fn baseline_stats_apps(state: &AccountSyncState) -> Vec<u32> {
    let mut app_ids = BTreeSet::new();
    app_ids.extend(state.stats_crcs.iter().map(|entry| entry.app_id));
    app_ids.extend(state.achievements.iter().map(|entry| entry.app_id));
    app_ids.extend(state.stats.iter().map(|entry| entry.app_id));
    app_ids.remove(&0);
    app_ids.into_iter().collect()
}

fn process_playtime(key: &RuntimeKey, snapshot: AccountPlaytimeSnapshot) {
    if !snapshot_is_valid(key.steam_id64, &snapshot) {
        warn!(
            revision = snapshot.playtime_revision,
            "account-downlink: rejected invalid playtime snapshot"
        );
        return;
    }
    let config = crate::client::install::config();
    let packet = playtime_downlink::apply_stream_snapshot(key.clone(), &snapshot, &config);
    if let Some(packet) = packet {
        info!(
            steam_id64 = key.steam_id64,
            revision = snapshot.playtime_revision,
            games = snapshot.playtime.len(),
            "account-downlink: queuing NotifyLastPlayedTimes"
        );
        crate::netpacket::queue_playtime_notification(packet, key.clone());
    } else {
        debug!(
            revision = snapshot.playtime_revision,
            "account-downlink: playtime snapshot applied without notification"
        );
    }
}

fn process_stats_wakeup(key: &RuntimeKey, wakeup: AccountStatsWakeup) {
    if !wakeup_is_valid(key.steam_id64, &wakeup) {
        warn!("account-downlink: rejected invalid stats wakeup");
        return;
    }
    let guard = crate::client::user_stats::StatsRefreshGuard {
        credential_fingerprint: key.credential_fingerprint.clone(),
        steam_id64: key.steam_id64,
        identity_generation: key.identity_generation,
        client_id: key.client_id,
        runtime_generation: key.runtime_generation,
    };
    let config = crate::client::install::config();
    for app_id in wakeup.app_ids {
        if !config.is_controlled_app(vapor_forge_config::AppId(app_id)) {
            continue;
        }
        if !crate::client::user_stats::queue_backend_stats_refresh(app_id, guard.clone()) {
            warn!(
                app_id,
                "account-downlink: user-stats refresh worker unavailable"
            );
        }
    }
}

struct ActiveStream(StreamCancellation);

#[derive(Clone)]
struct ActiveStreamState {
    cancellation: StreamCancellation,
    key: RuntimeKey,
}

impl Drop for ActiveStream {
    fn drop(&mut self) {
        let mut active = ACTIVE_STREAM
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active
            .as_ref()
            .is_some_and(|current| current.cancellation.ptr_eq(&self.0))
        {
            *active = None;
        }
    }
}

fn activate_stream(cancellation: StreamCancellation, key: RuntimeKey) -> ActiveStream {
    *ACTIVE_STREAM
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ActiveStreamState {
        cancellation: cancellation.clone(),
        key,
    });
    ActiveStream(cancellation)
}

fn cancel_active_stream_if_stale() {
    let active = ACTIVE_STREAM
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if let Some(active) = active {
        if !playtime_downlink::runtime_key_is_current(&active.key) {
            active.cancellation.cancel();
        }
    }
}

fn prerequisites() -> Option<(Arc<dyn CloudBackend>, DeviceDescriptor, RuntimeKey)> {
    let backend = crate::cloud_backend::backend_context()?;
    let descriptor = vapor_forge_cloud_core::device_descriptor()?;
    let steam_id64 = vapor_forge_features::identity::steam_id();
    if steam_id64 == 0 {
        return None;
    }
    let key = playtime_downlink::runtime_key(
        backend.credential_fingerprint(),
        steam_id64,
        vapor_forge_features::identity::generation(),
        descriptor.client_id,
        crate::client::install::runtime_generation(),
    );
    Some((backend, descriptor, key))
}

fn context_change_signal() -> &'static ContextChangeSignal {
    CONTEXT_CHANGE.get_or_init(ContextChangeSignal::default)
}

pub(crate) fn snapshot_is_valid(
    expected_steam_id64: u64,
    snapshot: &AccountPlaytimeSnapshot,
) -> bool {
    if snapshot.playtime.len() > 5_000 {
        return false;
    }
    if snapshot.steam_id64.parse::<u64>().ok() != Some(expected_steam_id64) {
        return false;
    }
    if snapshot
        .origin_client_id
        .as_deref()
        .is_some_and(|value| value.parse::<u64>().ok().filter(|id| *id != 0).is_none())
    {
        return false;
    }
    if snapshot.playtime_revision == 0 && !snapshot.playtime.is_empty() {
        return false;
    }
    let mut apps = HashSet::with_capacity(snapshot.playtime.len());
    snapshot.playtime.iter().all(|entry| {
        entry.app_id != 0
            && entry.observed_at > 0
            && entry.last_played_at.is_none_or(|value| value >= 0)
            && apps.insert(entry.app_id)
    })
}

pub(crate) fn wakeup_is_valid(expected_steam_id64: u64, wakeup: &AccountStatsWakeup) -> bool {
    if wakeup.steam_id64.parse::<u64>().ok() != Some(expected_steam_id64) {
        return false;
    }
    if wakeup
        .origin_client_id
        .as_deref()
        .is_some_and(|value| value.parse::<u64>().ok().filter(|id| *id != 0).is_none())
    {
        return false;
    }
    if wakeup.app_ids.is_empty() || wakeup.app_ids.len() > 5_000 {
        return false;
    }
    let mut seen = HashSet::with_capacity(wakeup.app_ids.len());
    wakeup
        .app_ids
        .iter()
        .copied()
        .all(|app_id| app_id != 0 && seen.insert(app_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vapor_forge_cloud_core::PlaytimeEntry;

    #[test]
    fn retry_backoff_is_bounded_and_resettable() {
        let mut retry = RetryBackoff::new();
        assert_eq!(retry.take_delay(), Duration::from_secs(2));
        assert_eq!(retry.take_delay(), Duration::from_secs(4));
        assert_eq!(retry.take_delay(), Duration::from_secs(8));
        assert_eq!(retry.take_delay(), Duration::from_secs(16));
        assert_eq!(retry.take_delay(), Duration::from_secs(30));
        assert_eq!(retry.take_delay(), Duration::from_secs(30));

        retry.reset();
        assert_eq!(retry.take_delay(), Duration::from_secs(2));
    }

    fn snapshot(revision: u64) -> AccountPlaytimeSnapshot {
        AccountPlaytimeSnapshot {
            steam_id64: "76561198000000001".into(),
            playtime_revision: revision,
            origin_client_id: Some("7".into()),
            playtime: vec![PlaytimeEntry {
                owner_scope: String::new(),
                owner_steam_id64: String::new(),
                app_id: 480,
                playtime_minutes: 42,
                playtime_2weeks_minutes: 3,
                last_played_at: Some(100),
                observed_at: 101,
            }],
        }
    }

    #[test]
    fn validates_exact_account_revision_and_unique_apps() {
        assert!(snapshot_is_valid(76_561_198_000_000_001, &snapshot(1)));
        assert!(!snapshot_is_valid(76_561_198_000_000_002, &snapshot(1)));
        assert!(!snapshot_is_valid(76_561_198_000_000_001, &snapshot(0)));

        let mut duplicate = snapshot(2);
        duplicate.playtime.push(duplicate.playtime[0].clone());
        assert!(!snapshot_is_valid(76_561_198_000_000_001, &duplicate));
    }

    #[test]
    fn validates_stats_wakeup_identity_and_unique_apps() {
        let good = AccountStatsWakeup {
            steam_id64: "76561198000000001".into(),
            origin_client_id: Some("91".into()),
            app_ids: vec![620, 480],
        };
        assert!(wakeup_is_valid(76_561_198_000_000_001, &good));

        let duplicate = AccountStatsWakeup {
            app_ids: vec![620, 620],
            ..good.clone()
        };
        assert!(!wakeup_is_valid(76_561_198_000_000_001, &duplicate));

        let wrong_account = AccountStatsWakeup {
            steam_id64: "76561198000000002".into(),
            ..good
        };
        assert!(!wakeup_is_valid(76_561_198_000_000_001, &wrong_account));
    }
}
