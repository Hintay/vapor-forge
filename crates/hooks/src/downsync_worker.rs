#![forbid(unsafe_code)]

//! Down-sync worker: subscribes to the backend's converged account state and
//! applies each snapshot locally.
//!
//! A cumulus backend pushes the full [`AccountSyncState`] over SSE - the first
//! frame on connect and a fresh frame on every change — so there is no periodic
//! poll. Backends that cannot stream report `Unsupported`; down-sync remains
//! disabled for them instead of silently falling back to polling.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

use tracing::warn;
use vapor_forge_cloud_core::{AccountSyncState, CloudBackend, StreamOutcome};

static STARTED: OnceLock<()> = OnceLock::new();
static STOP: AtomicBool = AtomicBool::new(false);
static CONFIG_CHANGE: OnceLock<ConfigChangeSignal> = OnceLock::new();
/// The last snapshot applied, so a re-sent frame (every reconnect carries the
/// full state) does not repeat the achievement round-trip when nothing changed.
#[derive(Clone)]
struct AppliedSnapshot {
    context: SubscriptionContext,
    state: AccountSyncState,
}
static LAST_APPLIED: OnceLock<Mutex<Option<AppliedSnapshot>>> = OnceLock::new();

/// How long to wait when prerequisites (backend, device identity, Steam login)
/// are not ready yet, or after a stream error.
const WAIT_RETRY: Duration = Duration::from_secs(2);

#[derive(Default)]
struct ConfigChangeSignal {
    revision: Mutex<u64>,
    changed: Condvar,
}

impl ConfigChangeSignal {
    fn revision(&self) -> u64 {
        *self
            .revision
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn notify(&self) {
        let mut revision = self
            .revision
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *revision = revision.wrapping_add(1);
        self.changed.notify_all();
    }

    fn wait_after(&self, previous: u64) {
        let mut revision = self
            .revision
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *revision == previous {
            revision = self
                .changed
                .wait(revision)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

pub(crate) fn ensure_started() {
    if STARTED.set(()).is_err() {
        return;
    }
    if std::thread::Builder::new()
        .name("downsync".into())
        .spawn(run)
        .is_err()
    {
        warn!("cloud-sync: failed to start down-sync worker");
    }
}

fn run() {
    loop {
        if STOP.load(Ordering::Relaxed) {
            return;
        }
        let config_revision = config_change_signal().revision();
        let Some(prereqs) = prerequisites() else {
            sleep_interruptible(WAIT_RETRY);
            continue;
        };
        let (backend, context) = prereqs;
        let steam_id_str = context.steam_id64.to_string();
        let should_continue = || context.is_current();
        let mut on_state = |state: AccountSyncState| {
            if context.is_current() {
                apply(&context, state);
            }
        };
        match backend.stream_account_state(
            context.client_id,
            &steam_id_str,
            &should_continue,
            &mut on_state,
        ) {
            Ok(StreamOutcome::Stopped) if STOP.load(Ordering::Relaxed) => return,
            Ok(StreamOutcome::Stopped) => continue,
            Ok(StreamOutcome::Unsupported) => {
                warn!("cloud-sync: backend does not support event-driven down-sync");
                config_change_signal().wait_after(config_revision);
            }
            Err(error) if error.is_retryable() => {
                warn!(%error, "cloud-sync: down-sync stream deferred");
                sleep_interruptible(WAIT_RETRY);
            }
            Err(error) => {
                warn!(%error, "cloud-sync: down-sync suspended until its context changes");
                wait_for_context_change(&context);
            }
        }
    }
}

fn config_change_signal() -> &'static ConfigChangeSignal {
    CONFIG_CHANGE.get_or_init(ConfigChangeSignal::default)
}

/// Wake down-sync after the runtime publishes a successfully reloaded config.
pub(crate) fn notify_config_changed() {
    config_change_signal().notify();
}

/// Resolve everything a sync attempt needs, or `None` if not ready yet.
fn prerequisites() -> Option<(Box<dyn CloudBackend>, SubscriptionContext)> {
    let backend = crate::cloud_backend::backend_context()?;
    let descriptor = vapor_forge_cloud_core::device_descriptor()?;
    let steam_id64 = vapor_forge_features::identity::steam_id();
    if steam_id64 == 0 {
        return None;
    }
    let context = SubscriptionContext::new(
        backend.credential_scope(),
        descriptor.client_id,
        steam_id64,
        vapor_forge_features::identity::generation(),
    );
    Some((backend, context))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SubscriptionContext {
    credential_scope: String,
    client_id: u64,
    steam_id64: u64,
    identity_generation: u64,
}

impl SubscriptionContext {
    pub(crate) fn new(
        credential_scope: String,
        client_id: u64,
        steam_id64: u64,
        identity_generation: u64,
    ) -> Self {
        Self {
            credential_scope,
            client_id,
            steam_id64,
            identity_generation,
        }
    }

    pub(crate) fn steam_id64(&self) -> u64 {
        self.steam_id64
    }

    pub(crate) fn is_current(&self) -> bool {
        if STOP.load(Ordering::Relaxed) {
            return false;
        }
        let steam_id64 = vapor_forge_features::identity::steam_id();
        let identity_generation = vapor_forge_features::identity::generation();
        let client_id =
            vapor_forge_cloud_core::device_descriptor().map(|descriptor| descriptor.client_id);
        let backend = crate::cloud_backend::backend_context();
        self.matches(
            backend.as_ref().map(|backend| backend.credential_scope()),
            client_id,
            steam_id64,
            identity_generation,
        )
    }

    fn matches(
        &self,
        credential_scope: Option<String>,
        client_id: Option<u64>,
        steam_id64: u64,
        identity_generation: u64,
    ) -> bool {
        credential_scope.as_deref() == Some(self.credential_scope.as_str())
            && client_id == Some(self.client_id)
            && steam_id64 == self.steam_id64
            && identity_generation == self.identity_generation
    }
}

/// Apply a converged snapshot to the local playtime and achievement state,
/// skipping snapshots identical to the last applied one.
fn apply(context: &SubscriptionContext, state: AccountSyncState) {
    {
        let mut last = LAST_APPLIED
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last
            .as_ref()
            .is_some_and(|previous| snapshot_matches(previous, context, &state))
        {
            return;
        }
        *last = Some(AppliedSnapshot {
            context: context.clone(),
            state: state.clone(),
        });
    }
    crate::playtime_worker::apply_remote_playtime(context, state.playtime);
    crate::client::user_stats::queue_remote_state(context, state.achievements);
}

fn snapshot_matches(
    previous: &AppliedSnapshot,
    context: &SubscriptionContext,
    state: &AccountSyncState,
) -> bool {
    previous.context == *context && previous.state == *state
}

fn sleep_interruptible(total: Duration) {
    let step = Duration::from_millis(100);
    let mut slept = Duration::ZERO;
    while slept < total {
        if STOP.load(Ordering::Relaxed) {
            return;
        }
        let next = step.min(total - slept);
        std::thread::sleep(next);
        slept += next;
    }
}

fn wait_for_context_change(context: &SubscriptionContext) {
    while context.is_current() {
        sleep_interruptible(WAIT_RETRY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_context_expires_on_any_identity_or_backend_change() {
        let context = SubscriptionContext {
            credential_scope: "scope-a".into(),
            client_id: 42,
            steam_id64: 76561198000000001,
            identity_generation: 7,
        };
        assert!(context.matches(Some("scope-a".into()), Some(42), 76561198000000001, 7,));
        assert!(!context.matches(Some("scope-b".into()), Some(42), 76561198000000001, 7,));
        assert!(!context.matches(Some("scope-a".into()), Some(43), 76561198000000001, 7,));
        assert!(!context.matches(Some("scope-a".into()), Some(42), 76561198000000002, 7,));
        assert!(!context.matches(Some("scope-a".into()), Some(42), 76561198000000001, 8,));
    }

    #[test]
    fn applied_snapshot_is_bound_to_the_complete_subscription_context() {
        let context = SubscriptionContext {
            credential_scope: "scope-a".into(),
            client_id: 42,
            steam_id64: 76561198000000001,
            identity_generation: 8,
        };
        let state = AccountSyncState::default();
        let prior_login = AppliedSnapshot {
            context: SubscriptionContext {
                identity_generation: 7,
                ..context.clone()
            },
            state: state.clone(),
        };
        let prior_client = AppliedSnapshot {
            context: SubscriptionContext {
                client_id: 41,
                ..context.clone()
            },
            state: state.clone(),
        };
        let current_login = AppliedSnapshot {
            context: context.clone(),
            state: state.clone(),
        };

        assert!(!snapshot_matches(&prior_login, &context, &state));
        assert!(!snapshot_matches(&prior_client, &context, &state));
        assert!(snapshot_matches(&current_login, &context, &state));
    }

    #[test]
    fn config_change_signal_remembers_notification_before_wait() {
        let signal = ConfigChangeSignal::default();
        let revision = signal.revision();
        signal.notify();

        signal.wait_after(revision);
        assert_ne!(signal.revision(), revision);
    }
}
