#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::{debug, info, warn};
use vapor_forge_cloud_core::{CloudBackend, SchemaUploadOutcome};
use vapor_forge_cloud_cumulus::{CumulusBackend, CumulusSettings};
use vapor_forge_cloud_local::LocalBackend;
use vapor_forge_sync_state::{
    Outbox, QueuedAchievementEvent, QueuedAchievementSchema, UploadIdentity,
};

const MAX_UNATTRIBUTED_UPLOADS: usize = 4096;

#[derive(Clone)]
struct AchievementWorker {
    outbox: Arc<Mutex<Outbox>>,
    unattributed: Arc<Mutex<VecDeque<QueuedAchievementEvent>>>,
    wake: mpsc::SyncSender<()>,
}

static WORKER: OnceLock<AchievementWorker> = OnceLock::new();
static WORKER_INIT: Mutex<()> = Mutex::new(());

pub fn ensure_started() {
    let _ = worker();
}

pub fn queue_event(mut event: QueuedAchievementEvent) -> bool {
    if event.achievement_key.is_empty() || event.observed_at <= 0 {
        return false;
    }
    let Some(worker) = worker() else {
        return false;
    };
    if let Some((backend, identity)) = upload_context() {
        if owner_matches(&event.owner_steam_id64, &identity) {
            attribute_event(&mut event, backend.as_ref(), &identity);
            match worker.outbox.lock() {
                Ok(outbox) => match outbox.enqueue(&event, unix_now()) {
                    Ok(inserted) => {
                        if inserted {
                            worker.wake();
                        }
                        true
                    }
                    Err(error) => {
                        warn!(%error, "achievement-sync: failed to persist event");
                        false
                    }
                },
                Err(_) => {
                    warn!("achievement-sync: outbox lock poisoned");
                    false
                }
            }
        } else {
            event.owner_scope.clear();
            persist_pending_event(worker, &event)
        }
    } else {
        if event.owner_steam_id64.is_empty() {
            remember_current_steam_id(&mut event.owner_steam_id64);
        }
        if event.owner_steam_id64.is_empty() {
            defer(worker, event)
        } else {
            persist_pending_event(worker, &event)
        }
    }
}

pub fn queue_schema(app_id: u32, schema_version: Option<String>, content: Vec<u8>) {
    if content.is_empty() {
        return;
    }
    let Some(worker) = worker() else {
        return;
    };
    let schema = QueuedAchievementSchema {
        owner_scope: backend_context()
            .as_ref()
            .map(|backend| backend.endpoint_scope())
            .unwrap_or_default(),
        app_id,
        language: "english".into(),
        schema_version,
        content,
    };
    persist_pending_schema(worker, &schema);
}

impl AchievementWorker {
    fn wake(&self) {
        let _ = self.wake.try_send(());
    }
}

fn worker() -> Option<&'static AchievementWorker> {
    if let Some(worker) = WORKER.get() {
        return Some(worker);
    }
    let _init = WORKER_INIT.lock().ok()?;
    if let Some(worker) = WORKER.get() {
        return Some(worker);
    }
    let path = vapor_forge_sync_state::default_outbox_path()?;
    let outbox = match Outbox::open(&path) {
        Ok(outbox) => {
            let stored_descriptor = match outbox.load_device_descriptor() {
                Ok(descriptor) => descriptor,
                Err(error) => {
                    warn!(%error, "achievement-sync: failed to restore device identity");
                    None
                }
            };
            if let Some(descriptor) = stored_descriptor {
                vapor_forge_cloud_core::restore_device_descriptor(descriptor);
            }
            Arc::new(Mutex::new(outbox))
        }
        Err(error) => {
            warn!(%error, path = %path.display(), "achievement-sync: outbox unavailable");
            return None;
        }
    };
    let unattributed = Arc::new(Mutex::new(VecDeque::new()));
    let (wake, receiver) = mpsc::sync_channel(1);
    let worker_outbox = Arc::clone(&outbox);
    let worker_unattributed = Arc::clone(&unattributed);
    if std::thread::Builder::new()
        .name("achievement-upload".into())
        .spawn(move || upload_loop(worker_outbox, worker_unattributed, receiver))
        .is_err()
    {
        warn!("achievement-sync: failed to start upload worker");
        return None;
    }
    info!(path = %path.display(), "achievement-sync: durable outbox ready");
    let _ = WORKER.set(AchievementWorker {
        outbox,
        unattributed,
        wake,
    });
    WORKER.get()
}

fn persist_pending_event(worker: &AchievementWorker, event: &QueuedAchievementEvent) -> bool {
    match worker.outbox.lock() {
        Ok(outbox) => match outbox.enqueue(event, unix_now()) {
            Ok(inserted) => {
                if inserted {
                    worker.wake();
                }
                true
            }
            Err(error) => {
                warn!(%error, "achievement-sync: failed to persist pending event");
                false
            }
        },
        Err(_) => {
            warn!("achievement-sync: outbox lock poisoned");
            false
        }
    }
}

fn persist_pending_schema(worker: &AchievementWorker, schema: &QueuedAchievementSchema) {
    match worker.outbox.lock() {
        Ok(outbox) => {
            if let Err(error) = outbox.enqueue_schema(schema, unix_now()) {
                warn!(%error, app_id = schema.app_id, "achievement-sync: failed to persist pending schema");
            } else {
                worker.wake();
            }
        }
        Err(_) => warn!("achievement-sync: outbox lock poisoned"),
    }
}

fn defer(worker: &AchievementWorker, event: QueuedAchievementEvent) -> bool {
    let Ok(mut pending) = worker.unattributed.lock() else {
        warn!("achievement-sync: unattributed queue lock poisoned");
        return false;
    };
    if event.kind == "progress" {
        pending.retain(|existing| {
            existing.kind != "progress"
                || existing.app_id != event.app_id
                || existing.achievement_key != event.achievement_key
        });
    }
    if pending.len() == MAX_UNATTRIBUTED_UPLOADS {
        pending.pop_front();
        warn!("achievement-sync: unattributed queue full, discarded oldest item");
    }
    pending.push_back(event);
    drop(pending);
    worker.wake();
    true
}

fn flush_unattributed(
    outbox: &Arc<Mutex<Outbox>>,
    unattributed: &Arc<Mutex<VecDeque<QueuedAchievementEvent>>>,
    backend: &dyn CloudBackend,
    identity: &UploadIdentity,
) -> Result<(), vapor_forge_sync_state::OutboxError> {
    let guard = match outbox.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("achievement-sync: recovering poisoned outbox lock");
            poisoned.into_inner()
        }
    };
    let mut uploads = match unattributed.lock() {
        Ok(mut pending) => std::mem::take(&mut *pending),
        Err(poisoned) => {
            warn!("achievement-sync: recovering poisoned unattributed queue lock");
            let mut pending = poisoned.into_inner();
            std::mem::take(&mut *pending)
        }
    };
    let mut unmatched = VecDeque::new();
    while let Some(mut event) = uploads.pop_front() {
        if !owner_matches(&event.owner_steam_id64, identity) {
            unmatched.push_back(event);
            continue;
        }
        attribute_event(&mut event, backend, identity);
        let result = guard.enqueue(&event, unix_now()).map(|_| ());
        if let Err(error) = result {
            drop(guard);
            unmatched.push_back(event);
            unmatched.append(&mut uploads);
            restore_pending(unattributed, unmatched);
            return Err(error);
        }
    }
    drop(guard);
    restore_pending(unattributed, unmatched);
    Ok(())
}

fn restore_pending(
    unattributed: &Arc<Mutex<VecDeque<QueuedAchievementEvent>>>,
    mut restored: VecDeque<QueuedAchievementEvent>,
) {
    let mut pending = match unattributed.lock() {
        Ok(pending) => pending,
        Err(poisoned) => {
            warn!("achievement-sync: recovering poisoned unattributed queue lock");
            poisoned.into_inner()
        }
    };
    restored.append(&mut pending);
    *pending = restored;
}

fn owner_matches(recorded: &str, identity: &UploadIdentity) -> bool {
    !recorded.is_empty() && recorded == identity.steam_id64
}

fn remember_current_steam_id(destination: &mut String) {
    let steam_id = vapor_forge_features::identity::steam_id();
    if steam_id != 0 {
        *destination = steam_id.to_string();
    }
}

fn upload_loop(
    outbox: Arc<Mutex<Outbox>>,
    unattributed: Arc<Mutex<VecDeque<QueuedAchievementEvent>>>,
    wake: mpsc::Receiver<()>,
) {
    let mut last_pull = None;
    let mut last_pulled_achievements = None;
    while let Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) =
        wake.recv_timeout(Duration::from_secs(2))
    {
        persist_current_device_descriptor(&outbox);
        for _ in 0..10 {
            let Some(backend) = backend_context() else {
                break;
            };
            let Some(descriptor) = vapor_forge_cloud_core::device_descriptor() else {
                break;
            };
            if let Err(error) = backend.ensure_device_bound(&descriptor) {
                warn!(%error, "achievement-sync: device binding deferred");
                break;
            }
            let scope = backend.endpoint_scope();
            let mut attempted = false;
            match outbox.lock() {
                Ok(outbox) => {
                    if let Err(error) = outbox.attribute_pending_schemas(&scope) {
                        warn!(%error, "achievement-sync: failed to attribute schema uploads");
                        break;
                    }
                }
                Err(_) => break,
            }

            let schemas = match outbox.lock() {
                Ok(outbox) => match outbox.pending_schemas(unix_now(), &scope) {
                    Ok(schemas) => schemas,
                    Err(error) => {
                        warn!(%error, "achievement-sync: failed to read schema outbox");
                        break;
                    }
                },
                Err(_) => break,
            };
            for schema in &schemas {
                attempted = true;
                let result = backend.upload_achievement_schema(schema);
                let guard = match outbox.lock() {
                    Ok(guard) => guard,
                    Err(_) => break,
                };
                match result {
                    Ok(SchemaUploadOutcome::Accepted | SchemaUploadOutcome::Declined) => {
                        if let Err(error) = guard.mark_schema_delivered(schema) {
                            warn!(%error, app_id = schema.app_id, "achievement-sync: failed to acknowledge schema upload");
                        }
                    }
                    Err(error) if error.is_retryable() => {
                        warn!(%error, app_id = schema.app_id, "achievement-sync: schema upload deferred");
                        if let Err(mark_error) = guard.mark_schema_failed(schema, unix_now()) {
                            warn!(%mark_error, "achievement-sync: failed to schedule schema retry");
                        }
                    }
                    Err(error) => {
                        warn!(%error, app_id = schema.app_id, "achievement-sync: server permanently rejected schema");
                        if let Err(mark_error) = guard.mark_schema_delivered(schema) {
                            warn!(%mark_error, "achievement-sync: failed to discard rejected schema");
                        }
                    }
                }
            }

            let Some(identity) = upload_identity() else {
                if !attempted {
                    break;
                }
                continue;
            };
            match outbox.lock() {
                Ok(outbox) => {
                    if let Err(error) = outbox.attribute_pending(&scope, &identity.steam_id64) {
                        warn!(%error, "achievement-sync: failed to attribute event uploads");
                        break;
                    }
                }
                Err(_) => break,
            }
            if let Err(error) =
                flush_unattributed(&outbox, &unattributed, backend.as_ref(), &identity)
            {
                warn!(%error, "achievement-sync: failed to attribute pending events");
                break;
            }
            let events = match outbox.lock() {
                Ok(outbox) => match outbox.pending(unix_now(), &scope, &identity.steam_id64) {
                    Ok(events) => events,
                    Err(error) => {
                        warn!(%error, "achievement-sync: failed to read event outbox");
                        break;
                    }
                },
                Err(_) => break,
            };
            if !events.is_empty() {
                attempted = true;
                let result = backend.upload_achievement_events(&identity, &events);
                let mut guard = match outbox.lock() {
                    Ok(guard) => guard,
                    Err(_) => break,
                };
                match result {
                    Ok(()) => {
                        if let Err(error) = guard.mark_delivered(&events) {
                            warn!(%error, "achievement-sync: failed to acknowledge upload");
                            break;
                        }
                        debug!(count = events.len(), "achievement-sync: events uploaded");
                    }
                    Err(error) if error.is_retryable() => {
                        warn!(%error, count = events.len(), "achievement-sync: upload deferred");
                        if let Err(mark_error) = guard.mark_failed(&events, unix_now()) {
                            warn!(%mark_error, "achievement-sync: failed to schedule retry");
                        }
                        break;
                    }
                    Err(error) => {
                        if let Err(mark_error) =
                            guard.mark_rejected(&events, &error.to_string(), unix_now())
                        {
                            warn!(%mark_error, "achievement-sync: failed to discard rejected events");
                        } else {
                            warn!(%error, count = events.len(), "achievement-sync: server permanently rejected events");
                        }
                        break;
                    }
                }
            }
            if last_pull.map_or(true, |last: Instant| {
                last.elapsed() >= Duration::from_secs(60)
            }) {
                match backend.pull_account_state(descriptor.client_id, &identity.steam_id64) {
                    Ok(state) => {
                        if last_pulled_achievements.as_ref() != Some(&state.achievements) {
                            crate::client::user_stats::queue_remote_state(
                                state.achievements.clone(),
                            );
                            last_pulled_achievements = Some(state.achievements);
                        }
                        last_pull = Some(Instant::now());
                    }
                    Err(error) => warn!(%error, "achievement-sync: state pull deferred"),
                }
            }
            if !attempted {
                break;
            }
        }
    }
}

fn persist_current_device_descriptor(outbox: &Arc<Mutex<Outbox>>) {
    let Some(descriptor) = vapor_forge_cloud_core::device_descriptor() else {
        return;
    };
    match outbox.lock() {
        Ok(outbox) => {
            if let Err(error) = outbox.store_device_descriptor(&descriptor, unix_now()) {
                warn!(%error, "achievement-sync: failed to persist device identity");
            }
        }
        Err(_) => {
            warn!("achievement-sync: outbox lock poisoned while persisting device identity")
        }
    }
}

fn attribute_event(
    event: &mut QueuedAchievementEvent,
    backend: &dyn CloudBackend,
    identity: &UploadIdentity,
) {
    event.owner_scope = backend.endpoint_scope();
    event.owner_steam_id64.clone_from(&identity.steam_id64);
}

/// Composition root: the only place this worker names a concrete backend.
fn backend_context() -> Option<Box<dyn CloudBackend>> {
    let config = crate::client::install::config();
    if config.local_cloud_configured() {
        return match LocalBackend::open(&config.cloud.local_path) {
            Ok(backend) => Some(Box::new(backend)),
            Err(error) => {
                warn!(%error, "achievement-sync: local backend unavailable");
                None
            }
        };
    }
    if !config.cumulus_configured() {
        return None;
    }
    Some(Box::new(CumulusBackend::new(CumulusSettings {
        server_url: config.cloud.server_url.clone(),
        token: config.cloud.token.clone(),
        timeout_connect_ms: config.cloud.timeout_connect_ms,
        timeout_ms: config.cloud.timeout_ms,
    })))
}

fn upload_identity() -> Option<UploadIdentity> {
    let steam_id = vapor_forge_features::identity::steam_id();
    if steam_id == 0 {
        return None;
    }
    let descriptor = vapor_forge_cloud_core::device_descriptor()?;
    Some(UploadIdentity {
        client_id: descriptor.client_id,
        machine_name: descriptor.machine_name,
        os_type: descriptor.os_type,
        device_type: descriptor.device_type,
        steam_id64: steam_id.to_string(),
        persona_name: None,
    })
}

fn upload_context() -> Option<(Box<dyn CloudBackend>, UploadIdentity)> {
    Some((backend_context()?, upload_identity()?))
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

    fn identity(steam_id64: &str) -> UploadIdentity {
        UploadIdentity {
            client_id: 7,
            machine_name: "deck".into(),
            os_type: None,
            device_type: None,
            steam_id64: steam_id64.into(),
            persona_name: None,
        }
    }

    fn event(event_id: &str) -> QueuedAchievementEvent {
        QueuedAchievementEvent {
            owner_scope: String::new(),
            owner_steam_id64: "76561198000000001".into(),
            event_id: event_id.into(),
            app_id: 480,
            achievement_key: "ACH_TEST".into(),
            kind: "unlock".into(),
            progress_current: None,
            progress_max: None,
            observed_at: 1,
            unlocked_at: Some(1),
        }
    }

    #[test]
    fn unattributed_events_do_not_match_the_current_account() {
        let current = identity("76561198000000001");
        assert!(!owner_matches("", &current));
        assert!(owner_matches("76561198000000001", &current));
        assert!(!owner_matches("76561198000000002", &current));
    }

    #[test]
    fn restore_pending_recovers_a_poisoned_queue_without_losing_events() {
        let pending = Arc::new(Mutex::new(VecDeque::from([event("existing")])));
        let poisoned = Arc::clone(&pending);
        let panic = std::panic::catch_unwind(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("poison queue for test");
        });
        assert!(panic.is_err());

        restore_pending(&pending, VecDeque::from([event("restored")]));

        let pending = pending.lock().unwrap_or_else(|error| error.into_inner());
        let ids = pending
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["restored", "existing"]);
    }
}
