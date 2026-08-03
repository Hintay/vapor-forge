#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tracing::{debug, info, warn};
use vapor_forge_cloud_core::{
    AccountPlaytimeSnapshot, CloudBackend, DeviceDescriptor, StreamCancellation, StreamOutcome,
};

use crate::client::playtime_downlink::{self, RuntimeKey};

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
        .name("playtime-downlink".into())
        .spawn(run)
        .is_err()
    {
        warn!("playtime-downlink: failed to start SSE worker");
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
            warn!(%error, "playtime-downlink: device binding deferred");
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
        if !playtime_downlink::runtime_key_is_current(&key) {
            cancellation.cancel();
        }
        let mut on_snapshot = |snapshot: AccountPlaytimeSnapshot| {
            if !playtime_downlink::runtime_key_is_current(&key) {
                return;
            }
            if !snapshot_is_valid(key.steam_id64, &snapshot) {
                warn!(
                    revision = snapshot.playtime_revision,
                    "playtime-downlink: rejected invalid authoritative snapshot"
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
                    "playtime-downlink: queuing NotifyLastPlayedTimes"
                );
                crate::netpacket::queue_playtime_notification(packet, key.clone());
            } else {
                debug!(
                    revision = snapshot.playtime_revision,
                    "playtime-downlink: snapshot applied without notification"
                );
            }
        };
        let outcome = backend.stream_playtime(
            descriptor.client_id,
            &steam_id64,
            &cancellation,
            &mut on_snapshot,
        );
        drop(active);
        match outcome {
            Ok(StreamOutcome::Stopped) => {}
            Ok(StreamOutcome::Unsupported) => {
                debug!("playtime-downlink: backend has no remote event stream");
                context_change_signal().wait_after(signal_revision);
            }
            Err(error) if error.is_retryable() => {
                warn!(%error, "playtime-downlink: SSE stream deferred");
                context_change_signal().wait_timeout_after(signal_revision, RETRY_DELAY);
            }
            Err(error) => {
                warn!(%error, "playtime-downlink: SSE stream suspended until context changes");
                context_change_signal().wait_after(signal_revision);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use vapor_forge_cloud_core::PlaytimeEntry;

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
        assert!(snapshot_is_valid(76561198000000001, &snapshot(1)));
        assert!(!snapshot_is_valid(76561198000000002, &snapshot(1)));
        assert!(!snapshot_is_valid(76561198000000001, &snapshot(0)));

        let mut duplicate = snapshot(2);
        duplicate.playtime.push(duplicate.playtime[0].clone());
        assert!(!snapshot_is_valid(76561198000000001, &duplicate));
    }
}
