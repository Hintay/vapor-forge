#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tracing::{debug, warn};
use vapor_forge_cloud_core::{
    AccountStatsWakeup, CloudBackend, DeviceDescriptor, StreamCancellation, StreamOutcome,
};

use crate::context_signal::ContextChangeSignal;

static STARTED: OnceLock<()> = OnceLock::new();
static CONTEXT_CHANGE: OnceLock<ContextChangeSignal> = OnceLock::new();
static ACTIVE_STREAM: Mutex<Option<ActiveStreamState>> = Mutex::new(None);
const RETRY_DELAY: Duration = Duration::from_secs(2);

pub(crate) fn ensure_started() {
    if STARTED.set(()).is_err() {
        return;
    }
    if std::thread::Builder::new()
        .name("stats-wakeup".into())
        .spawn(run)
        .is_err()
    {
        warn!("stats-wakeup: failed to start SSE worker");
    }
}

pub(crate) fn notify_context_changed() {
    cancel_active_stream_if_stale();
    context_change_signal().notify();
}

fn run() {
    loop {
        let signal_revision = context_change_signal().revision();
        let Some((backend, descriptor, key)) = prerequisites() else {
            context_change_signal().wait_after(signal_revision);
            continue;
        };
        if let Err(error) = backend.ensure_device_bound(&descriptor) {
            warn!(%error, "stats-wakeup: device binding deferred");
            if error.is_retryable() {
                context_change_signal().wait_timeout_after(signal_revision, RETRY_DELAY);
            } else {
                context_change_signal().wait_after(signal_revision);
            }
            continue;
        }
        let steam_id64 = key.steam_id64.to_string();
        let cancellation = StreamCancellation::new();
        let active = activate_stream(cancellation.clone(), key.clone());
        if !stats_refresh_key_is_current(&key) {
            cancellation.cancel();
        }
        let mut on_wakeup = |wakeup: AccountStatsWakeup| {
            if !stats_refresh_key_is_current(&key) {
                return;
            }
            if !wakeup_is_valid(key.steam_id64, &wakeup) {
                warn!("stats-wakeup: rejected invalid wakeup");
                return;
            }
            // Origin is provenance only; the cloud may have changed the submitted state.
            let config = crate::client::install::config();
            for app_id in wakeup.app_ids {
                if !config.is_controlled_app(vapor_forge_config::AppId(app_id)) {
                    continue;
                }
                if !crate::client::user_stats::queue_backend_stats_refresh(app_id, key.clone()) {
                    warn!(
                        app_id,
                        "stats-wakeup: user-stats refresh worker unavailable"
                    );
                }
            }
        };
        let outcome = backend.stream_stats_wakeup(
            descriptor.client_id,
            &steam_id64,
            &cancellation,
            &mut on_wakeup,
        );
        drop(active);
        match outcome {
            Ok(StreamOutcome::Stopped) => {}
            Ok(StreamOutcome::Unsupported) => {
                debug!("stats-wakeup: backend has no remote event stream");
                context_change_signal().wait_after(signal_revision);
            }
            Err(error) if error.is_retryable() => {
                warn!(%error, "stats-wakeup: SSE stream deferred");
                context_change_signal().wait_timeout_after(signal_revision, RETRY_DELAY);
            }
            Err(error) => {
                warn!(%error, "stats-wakeup: SSE stream suspended until context changes");
                context_change_signal().wait_after(signal_revision);
            }
        }
    }
}

struct ActiveStream(StreamCancellation);

#[derive(Clone)]
struct ActiveStreamState {
    cancellation: StreamCancellation,
    key: crate::client::user_stats::StatsRefreshGuard,
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

fn activate_stream(
    cancellation: StreamCancellation,
    key: crate::client::user_stats::StatsRefreshGuard,
) -> ActiveStream {
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
        if !stats_refresh_key_is_current(&active.key) {
            active.cancellation.cancel();
        }
    }
}

fn prerequisites() -> Option<(
    Arc<dyn CloudBackend>,
    DeviceDescriptor,
    crate::client::user_stats::StatsRefreshGuard,
)> {
    let backend = crate::cloud_backend::backend_context()?;
    let descriptor = vapor_forge_cloud_core::device_descriptor()?;
    let steam_id64 = vapor_forge_features::identity::steam_id();
    if steam_id64 == 0 {
        return None;
    }
    let key = crate::client::user_stats::StatsRefreshGuard {
        credential_fingerprint: backend.credential_fingerprint(),
        steam_id64,
        identity_generation: vapor_forge_features::identity::generation(),
        client_id: descriptor.client_id,
    };
    Some((backend, descriptor, key))
}

fn stats_refresh_key_is_current(key: &crate::client::user_stats::StatsRefreshGuard) -> bool {
    vapor_forge_features::identity::steam_id() == key.steam_id64
        && vapor_forge_features::identity::generation() == key.identity_generation
        && vapor_forge_cloud_core::device_descriptor()
            .is_some_and(|descriptor| descriptor.client_id == key.client_id)
        && crate::cloud_backend::backend_context()
            .is_some_and(|backend| backend.credential_fingerprint() == key.credential_fingerprint)
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

fn context_change_signal() -> &'static ContextChangeSignal {
    CONTEXT_CHANGE.get_or_init(ContextChangeSignal::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_wakeup_rejects_state_payload_stand_ins() {
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

    #[test]
    fn stats_wakeup_accepts_same_client_origin() {
        let wakeup = AccountStatsWakeup {
            steam_id64: "76561198000000001".into(),
            origin_client_id: Some("91".into()),
            app_ids: vec![620],
        };

        assert!(wakeup_is_valid(76_561_198_000_000_001, &wakeup));
    }
}
