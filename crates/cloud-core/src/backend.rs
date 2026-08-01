use crate::{
    AccountPlaytimeSnapshot, AccountStatsWakeup, AccountSyncState, AchievementSchema,
    AppStatsQuery, AppStatsResult, DeviceDescriptor, PlaytimeEntry, PlaytimeSession,
    SteamAppSnapshot, SteamStateUploadResult, UploadIdentity,
};
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Result of offering a schema to a backend. Both variants are terminal: a
/// decline is the backend refusing the payload, not a failure to retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaUploadOutcome {
    Accepted,
    Declined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamOutcome {
    Unsupported,
    Stopped,
}

#[derive(Clone)]
pub struct StreamCancellation {
    inner: Arc<StreamCancellationInner>,
}

struct StreamCancellationInner {
    state: Mutex<StreamCancellationState>,
    changed: Condvar,
}

#[derive(Default)]
struct StreamCancellationState {
    cancelled: bool,
    revision: u64,
}

impl StreamCancellation {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StreamCancellationInner {
                state: Mutex::new(StreamCancellationState::default()),
                changed: Condvar::new(),
            }),
        }
    }

    pub fn cancel(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.cancelled {
            state.cancelled = true;
            state.revision = state.revision.wrapping_add(1);
            self.inner.changed.notify_all();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .cancelled
    }

    pub fn revision(&self) -> u64 {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .revision
    }

    /// Wake a stream forwarder after its reader produced a message.
    pub fn signal_activity(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.revision = state.revision.wrapping_add(1);
        self.inner.changed.notify_all();
    }

    pub fn wait_for_activity(&self, previous: u64) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.cancelled && state.revision == previous {
            state = self
                .inner
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    /// Wait for cancellation or for a transport retry delay to expire.
    pub fn wait_cancelled_timeout(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.cancelled {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let waited = self
                .inner
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = waited.0;
            if waited.1.timed_out() {
                break;
            }
        }
        state.cancelled
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Default for StreamCancellation {
    fn default() -> Self {
        Self::new()
    }
}

/// A backend failure reduced to what delivery scheduling needs: whether the
/// operation is worth retrying, plus a message for logs.
///
/// Backends keep their own richer error types and convert at the boundary.
#[derive(Clone, Debug)]
pub struct BackendError {
    message: String,
    retryable: bool,
}

impl BackendError {
    pub fn new(message: impl Into<String>, retryable: bool) -> Self {
        Self {
            message: message.into(),
            retryable,
        }
    }

    /// Whether the journal should schedule another attempt instead of giving up.
    pub fn is_retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BackendError {}

/// A destination that durable sync events can be delivered to.
///
/// Implementors own their own connection settings and credentials, so callers
/// never name a concrete backend or its configuration shape. Everything crossing
/// this boundary is a neutral type from this crate.
pub trait CloudBackend: Send + Sync {
    /// Partition key covering the destination only, ignoring credentials.
    ///
    /// Used where data stays valid across a credential change, so re-authenticating
    /// against the same destination does not orphan pending rows.
    fn endpoint_scope(&self) -> String;

    /// Stable partition key covering destination and authenticated principal,
    /// but not the bearer token itself.
    ///
    /// Used where data belongs to the authenticated principal. Token rotation
    /// for the same principal must not orphan pending rows, while switching to
    /// another principal must isolate state. Backends may need to authenticate
    /// to discover their stable principal id.
    fn principal_scope(&self) -> Result<String, BackendError>;

    /// Runtime-only fingerprint of the configured destination and credential.
    ///
    /// This must change when a bearer token changes and is used to reject
    /// in-flight results after config reloads. It must not be used as a durable
    /// owner scope for journal rows.
    fn credential_fingerprint(&self) -> String;

    /// Register this device with the backend before uploading on its behalf.
    fn ensure_device_bound(&self, descriptor: &DeviceDescriptor) -> Result<(), BackendError>;

    fn upload_achievement_schema(
        &self,
        schema: &AchievementSchema,
    ) -> Result<SchemaUploadOutcome, BackendError>;

    fn upload_playtime(
        &self,
        client_id: u64,
        steam_id64: &str,
        entries: &[PlaytimeEntry],
    ) -> Result<(), BackendError>;

    fn upload_playtime_sessions(
        &self,
        client_id: u64,
        steam_id64: &str,
        sessions: &[PlaytimeSession],
    ) -> Result<(), BackendError>;

    fn upload_steam_app_snapshot(
        &self,
        identity: &UploadIdentity,
        snapshot: &SteamAppSnapshot,
    ) -> Result<SteamStateUploadResult, BackendError>;

    /// Return the backend's converged state for one Steam account.
    fn pull_account_state(
        &self,
        client_id: u64,
        steam_id64: &str,
    ) -> Result<AccountSyncState, BackendError>;

    /// Conditionally return one app's authoritative stats using the CRC last
    /// issued by this backend. The schema version guards wire-id mappings.
    fn pull_app_stats(
        &self,
        client_id: u64,
        steam_id64: &str,
        query: &AppStatsQuery,
    ) -> Result<AppStatsResult, BackendError>;

    /// Stream committed playtime snapshots until the runtime context expires.
    /// Implementations reconnect transient transport failures internally and
    /// invoke `on_snapshot` only with complete authoritative snapshots.
    fn stream_playtime(
        &self,
        _client_id: u64,
        _steam_id64: &str,
        _cancellation: &StreamCancellation,
        _on_snapshot: &mut dyn FnMut(AccountPlaytimeSnapshot),
    ) -> Result<StreamOutcome, BackendError> {
        Ok(StreamOutcome::Unsupported)
    }

    /// Stream wakeup-only stats notifications. Implementations must not carry
    /// achievements or stat values here; callers re-enter Steam's native
    /// RequestCurrentStats path for the actual state merge.
    fn stream_stats_wakeup(
        &self,
        _client_id: u64,
        _steam_id64: &str,
        _cancellation: &StreamCancellation,
        _on_wakeup: &mut dyn FnMut(AccountStatsWakeup),
    ) -> Result<StreamOutcome, BackendError> {
        Ok(StreamOutcome::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_error_reports_retryability_and_message() {
        let transient = BackendError::new("timeout", true);
        assert!(transient.is_retryable());
        assert_eq!(transient.to_string(), "timeout");

        let permanent = BackendError::new("malformed payload", false);
        assert!(!permanent.is_retryable());
    }

    #[test]
    fn stream_cancellation_wakes_blocked_forwarders() {
        let cancellation = StreamCancellation::new();
        let waiter = cancellation.clone();
        let revision = waiter.revision();
        let thread = std::thread::spawn(move || {
            waiter.wait_for_activity(revision);
            waiter.is_cancelled()
        });

        cancellation.cancel();
        assert!(thread.join().unwrap());
    }
}
