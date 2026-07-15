use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, info, warn};
use vapor_forge_achievement_sync::{
    CumulusSettings, Outbox, QueuedAchievementEvent, QueuedAchievementSchema, SchemaUploadOutcome,
    UploadIdentity,
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

pub fn queue_event(mut event: QueuedAchievementEvent) {
    if event.achievement_key.is_empty() || event.observed_at <= 0 {
        return;
    }
    let Some(worker) = worker() else {
        return;
    };
    if let Some((settings, identity)) = upload_context() {
        if owner_matches(&event.owner_steam_id64, &identity) {
            attribute_event(&mut event, &settings, &identity);
            match worker.outbox.lock() {
                Ok(outbox) => match outbox.enqueue(&event, unix_now()) {
                    Ok(true) => worker.wake(),
                    Ok(false) => {}
                    Err(error) => warn!(%error, "achievement-sync: failed to persist event"),
                },
                Err(_) => warn!("achievement-sync: outbox lock poisoned"),
            }
        } else {
            event.owner_scope.clear();
            persist_pending_event(worker, &event);
        }
    } else {
        if event.owner_steam_id64.is_empty() {
            remember_current_steam_id(&mut event.owner_steam_id64);
        }
        if event.owner_steam_id64.is_empty() {
            defer(worker, event);
        } else {
            persist_pending_event(worker, &event);
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
        owner_scope: settings_context()
            .as_ref()
            .map(vapor_forge_achievement_sync::upload_scope)
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
    let path = vapor_forge_achievement_sync::default_outbox_path()?;
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
                vapor_forge_achievement_sync::restore_device_descriptor(descriptor);
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

fn persist_pending_event(worker: &AchievementWorker, event: &QueuedAchievementEvent) {
    match worker.outbox.lock() {
        Ok(outbox) => match outbox.enqueue(event, unix_now()) {
            Ok(true) => worker.wake(),
            Ok(false) => {}
            Err(error) => warn!(%error, "achievement-sync: failed to persist pending event"),
        },
        Err(_) => warn!("achievement-sync: outbox lock poisoned"),
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

fn defer(worker: &AchievementWorker, event: QueuedAchievementEvent) {
    let Ok(mut pending) = worker.unattributed.lock() else {
        warn!("achievement-sync: unattributed queue lock poisoned");
        return;
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
}

fn flush_unattributed(
    outbox: &Arc<Mutex<Outbox>>,
    unattributed: &Arc<Mutex<VecDeque<QueuedAchievementEvent>>>,
    settings: &CumulusSettings,
    identity: &UploadIdentity,
) -> Result<(), vapor_forge_achievement_sync::OutboxError> {
    let mut uploads = match unattributed.lock() {
        Ok(mut pending) => std::mem::take(&mut *pending),
        Err(_) => return Ok(()),
    };
    let guard = match outbox.lock() {
        Ok(guard) => guard,
        Err(_) => return Ok(()),
    };
    let mut unmatched = VecDeque::new();
    while let Some(mut event) = uploads.pop_front() {
        if !owner_matches(&event.owner_steam_id64, identity) {
            unmatched.push_back(event);
            continue;
        }
        attribute_event(&mut event, settings, identity);
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
    if let Ok(mut pending) = unattributed.lock() {
        restored.append(&mut pending);
        *pending = restored;
    }
}

fn owner_matches(recorded: &str, identity: &UploadIdentity) -> bool {
    recorded.is_empty() || recorded == identity.steam_id64
}

fn remember_current_steam_id(destination: &mut String) {
    let steam_id = vapor_forge_features::rich_presence::local_steamid();
    if steam_id != 0 {
        *destination = steam_id.to_string();
    }
}

fn upload_loop(
    outbox: Arc<Mutex<Outbox>>,
    unattributed: Arc<Mutex<VecDeque<QueuedAchievementEvent>>>,
    wake: mpsc::Receiver<()>,
) {
    while let Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) =
        wake.recv_timeout(Duration::from_secs(2))
    {
        persist_current_device_descriptor(&outbox);
        for _ in 0..10 {
            let Some(settings) = settings_context() else {
                break;
            };
            let Some(descriptor) = vapor_forge_achievement_sync::device_descriptor() else {
                break;
            };
            if let Err(error) =
                vapor_forge_achievement_sync::ensure_device_bound(&settings, &descriptor)
            {
                warn!(%error, "achievement-sync: device binding deferred");
                break;
            }
            let scope = vapor_forge_achievement_sync::upload_scope(&settings);
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
                let result = vapor_forge_achievement_sync::upload_schema(&settings, schema);
                let guard = match outbox.lock() {
                    Ok(guard) => guard,
                    Err(_) => break,
                };
                match result {
                    Ok(SchemaUploadOutcome::Uploaded | SchemaUploadOutcome::Disabled) => {
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
            if let Err(error) = flush_unattributed(&outbox, &unattributed, &settings, &identity) {
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
                let result =
                    vapor_forge_achievement_sync::upload_events(&settings, &identity, &events);
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
            if !attempted {
                break;
            }
        }
    }
}

fn persist_current_device_descriptor(outbox: &Arc<Mutex<Outbox>>) {
    let Some(descriptor) = vapor_forge_achievement_sync::device_descriptor() else {
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
    settings: &CumulusSettings,
    identity: &UploadIdentity,
) {
    event.owner_scope = vapor_forge_achievement_sync::upload_scope(settings);
    event.owner_steam_id64.clone_from(&identity.steam_id64);
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

fn upload_identity() -> Option<UploadIdentity> {
    let steam_id = vapor_forge_features::rich_presence::local_steamid();
    if steam_id == 0 {
        return None;
    }
    let descriptor = vapor_forge_achievement_sync::device_descriptor()?;
    Some(UploadIdentity {
        client_id: Some(descriptor.client_id),
        machine_name: descriptor.machine_name,
        os_type: descriptor.os_type,
        device_type: descriptor.device_type,
        steam_id64: steam_id.to_string(),
        persona_name: None,
    })
}

fn upload_context() -> Option<(CumulusSettings, UploadIdentity)> {
    Some((settings_context()?, upload_identity()?))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
