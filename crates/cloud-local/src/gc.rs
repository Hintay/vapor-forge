use crate::{FolderStore, SyncthingGcConfig};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::time::Duration;
use tracing::{debug, warn};

const INITIAL_RECONNECT_DELAY: Duration = Duration::from_millis(250);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct InspectionKey {
    repository: PathBuf,
    manifest_scope: String,
}

#[derive(Clone)]
struct InspectionRequest {
    store: FolderStore,
    app_id: u32,
    syncthing: Option<SyncthingGcConfig>,
    epoch: u64,
    revision: u64,
}

impl InspectionRequest {
    fn key(&self) -> InspectionKey {
        InspectionKey {
            repository: self.store.root().to_owned(),
            manifest_scope: self.store.manifest_scope(self.app_id),
        }
    }

    fn listener_key(&self) -> Option<SyncthingListenerKey> {
        self.syncthing.clone().map(|settings| SyncthingListenerKey {
            repository: self.store.root().to_owned(),
            settings,
        })
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct SyncthingListenerKey {
    repository: PathBuf,
    settings: SyncthingGcConfig,
}

#[derive(Default)]
struct CoordinatorState {
    revisions: BTreeMap<InspectionKey, u64>,
    deferred: BTreeMap<InspectionKey, InspectionRequest>,
    listeners: BTreeMap<SyncthingListenerKey, ListenerRegistration>,
    next_listener_id: u64,
}

#[derive(Clone, Copy)]
struct ListenerRegistration {
    id: u64,
    wake_queued: bool,
}

enum WorkerMessage {
    Inspect(InspectionRequest),
    SyncthingEvent {
        key: SyncthingListenerKey,
        listener_id: u64,
    },
    SyncthingListenerStopped {
        key: SyncthingListenerKey,
        listener_id: u64,
        error: String,
    },
}

pub struct LocalGcCoordinator {
    state: Arc<Mutex<CoordinatorState>>,
    sender: Arc<mpsc::Sender<WorkerMessage>>,
    epoch: Arc<AtomicU64>,
    _lifetime: Arc<()>,
}

impl LocalGcCoordinator {
    pub fn try_new() -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::channel::<WorkerMessage>();
        let state = Arc::new(Mutex::new(CoordinatorState::default()));
        let worker_state = Arc::clone(&state);
        let epoch = Arc::new(AtomicU64::new(1));
        let worker_epoch = Arc::clone(&epoch);
        let lifetime = Arc::new(());
        let sender = Arc::new(sender);
        let worker_sender = Arc::downgrade(&sender);
        let worker_lifetime = Arc::downgrade(&lifetime);
        std::thread::Builder::new()
            .name("vapor-local-cloud-gc".into())
            .spawn(move || {
                run_inspections(
                    receiver,
                    worker_sender,
                    worker_state,
                    worker_epoch,
                    worker_lifetime,
                )
            })?;
        Ok(Self {
            state,
            sender,
            epoch,
            _lifetime: lifetime,
        })
    }

    pub fn queue_inspection(
        &self,
        store: FolderStore,
        app_id: u32,
        syncthing: Option<SyncthingGcConfig>,
    ) {
        if let Some(settings) = &syncthing {
            if let Err(error) = settings.validate_for_gc() {
                warn!(%error, "local cloud GC rejected unsafe synchronization guard");
                return;
            }
        }
        let request = {
            let mut state = self.state.lock().unwrap();
            let key = InspectionKey {
                repository: store.root().to_owned(),
                manifest_scope: store.manifest_scope(app_id),
            };
            let revision = advance_revision(&mut state.revisions, &key);
            state.deferred.remove(&key);
            InspectionRequest {
                store,
                app_id,
                syncthing,
                epoch: self.epoch.load(Ordering::Acquire),
                revision,
            }
        };
        self.send_request(request);
    }

    pub fn invalidate(&self) {
        let mut state = self.state.lock().unwrap();
        self.epoch.fetch_add(1, Ordering::AcqRel);
        state.revisions.clear();
        state.deferred.clear();
        state.listeners.clear();
    }

    fn send_request(&self, request: InspectionRequest) {
        if self.sender.send(WorkerMessage::Inspect(request)).is_err() {
            warn!("local cloud GC worker is unavailable");
        }
    }
}

fn run_inspections(
    receiver: mpsc::Receiver<WorkerMessage>,
    sender: Weak<mpsc::Sender<WorkerMessage>>,
    state: Arc<Mutex<CoordinatorState>>,
    epoch: Arc<AtomicU64>,
    lifetime: Weak<()>,
) {
    while let Ok(first) = receiver.recv() {
        let mut pending = BTreeMap::new();
        merge_worker_message(&mut pending, &state, &epoch, first);
        while let Ok(message) = receiver.try_recv() {
            merge_worker_message(&mut pending, &state, &epoch, message);
        }
        for request in pending.into_values() {
            if !request_is_current(&state, &epoch, &request) {
                continue;
            }
            match inspect_once(&state, &epoch, &request) {
                InspectionOutcome::Finished => finish_request(&state, &request),
                InspectionOutcome::DeferForSyncthing => {
                    defer_request(&state, &epoch, &sender, &lifetime, request)
                }
            }
        }
    }
}

enum InspectionOutcome {
    Finished,
    DeferForSyncthing,
}

fn inspect_once(
    state: &Mutex<CoordinatorState>,
    epoch: &AtomicU64,
    request: &InspectionRequest,
) -> InspectionOutcome {
    let report = match request.store.inspect_gc(request.app_id) {
        Ok(report) => report,
        Err(error) => {
            warn!(%error, "local cloud GC inspection failed closed");
            return InspectionOutcome::Finished;
        }
    };
    let syncthing_boundary = if report.candidate_manifests.is_empty() {
        None
    } else if let Some(syncthing) = &request.syncthing {
        match syncthing.prepare_for_gc(request.store.root(), &report) {
            Ok(boundary) => Some(boundary),
            Err(error) => {
                warn!(%error, "local cloud GC Syncthing boundary failed closed");
                return if error.is_retryable() {
                    InspectionOutcome::DeferForSyncthing
                } else {
                    InspectionOutcome::Finished
                };
            }
        }
    } else {
        None
    };
    if request.epoch != epoch.load(Ordering::Acquire) {
        return InspectionOutcome::Finished;
    }
    let plan = match request.store.prepare_gc_sweep(&report) {
        Ok(Some(plan)) => plan,
        Ok(None) => return InspectionOutcome::Finished,
        Err(error) => {
            warn!(%error, "local cloud GC preparation failed closed");
            return InspectionOutcome::Finished;
        }
    };

    if !request_is_current(state, epoch, request) {
        return InspectionOutcome::Finished;
    }
    match request.store.apply_gc_sweep(plan) {
        Ok(Some(sweep)) => {
            let deleted_manifests = sweep.deleted_manifests;
            if let (Some(syncthing), Some(boundary)) = (&request.syncthing, syncthing_boundary) {
                if let Err(error) = syncthing.publish_gc(boundary) {
                    let restored = match request.store.restore_gc_sweep(request.app_id, sweep) {
                        Ok(()) => true,
                        Err(restore_error) => {
                            warn!(%restore_error, "local cloud GC rollback failed");
                            false
                        }
                    };
                    warn!(%error, "local cloud GC Syncthing deletion scan failed");
                    return if restored && error.is_retryable() {
                        InspectionOutcome::DeferForSyncthing
                    } else {
                        InspectionOutcome::Finished
                    };
                }
            }
            if let Err(error) = request.store.finalize_gc_sweep(sweep) {
                warn!(%error, "local cloud GC private cleanup failed");
            }
            debug!(
                app_id = request.app_id,
                retained_manifests = report.retained_manifests.len(),
                deleted_manifests,
                "local cloud GC completed"
            );
        }
        Ok(None) => {}
        Err(error) => {
            warn!(%error, "local cloud GC deletion failed closed");
        }
    }
    InspectionOutcome::Finished
}

fn merge_worker_message(
    pending: &mut BTreeMap<InspectionKey, InspectionRequest>,
    state: &Mutex<CoordinatorState>,
    epoch: &AtomicU64,
    message: WorkerMessage,
) {
    match message {
        WorkerMessage::Inspect(request) => merge_pending_request(pending, request),
        WorkerMessage::SyncthingEvent { key, listener_id } => {
            let deferred = take_deferred_requests(state, epoch, &key, listener_id);
            for request in deferred {
                merge_pending_request(pending, request);
            }
        }
        WorkerMessage::SyncthingListenerStopped {
            key,
            listener_id,
            error,
        } => {
            let mut state = state.lock().unwrap();
            if state.listeners.get(&key).map(|listener| listener.id) == Some(listener_id) {
                state.listeners.remove(&key);
                warn!(%error, "local cloud GC Syncthing event listener stopped");
            }
        }
    }
}

fn take_deferred_requests(
    state: &Mutex<CoordinatorState>,
    epoch: &AtomicU64,
    listener_key: &SyncthingListenerKey,
    listener_id: u64,
) -> Vec<InspectionRequest> {
    let mut state = state.lock().unwrap();
    let Some(listener) = state.listeners.get_mut(listener_key) else {
        return Vec::new();
    };
    if listener.id != listener_id {
        return Vec::new();
    }
    listener.wake_queued = false;
    let keys = state
        .deferred
        .iter()
        .filter(|(_, request)| request.listener_key().as_ref() == Some(listener_key))
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    let mut requests = Vec::new();
    for key in keys {
        let Some(request) = state.deferred.remove(&key) else {
            continue;
        };
        if request_is_current_locked(&state, epoch, &request) {
            requests.push(request);
        }
    }
    requests
}

fn defer_request(
    state: &Arc<Mutex<CoordinatorState>>,
    epoch: &Arc<AtomicU64>,
    sender: &Weak<mpsc::Sender<WorkerMessage>>,
    lifetime: &Weak<()>,
    request: InspectionRequest,
) {
    let Some(listener_key) = request.listener_key() else {
        return;
    };
    let listener = {
        let mut state = state.lock().unwrap();
        if !request_is_current_locked(&state, epoch, &request) {
            return;
        }
        state.deferred.insert(request.key(), request);
        if state.listeners.contains_key(&listener_key) {
            None
        } else {
            state.next_listener_id = state.next_listener_id.wrapping_add(1).max(1);
            let listener_id = state.next_listener_id;
            state.listeners.insert(
                listener_key.clone(),
                ListenerRegistration {
                    id: listener_id,
                    wake_queued: false,
                },
            );
            Some(listener_id)
        }
    };
    let Some(listener_id) = listener else {
        return;
    };
    let Some(sender) = sender.upgrade() else {
        return;
    };
    let listener_state = Arc::clone(state);
    let listener_sender = sender.as_ref().clone();
    let listener_lifetime = lifetime.clone();
    let settings = listener_key.settings.clone();
    let thread_key = listener_key.clone();
    if let Err(error) = std::thread::Builder::new()
        .name("vapor-syncthing-events".into())
        .spawn(move || {
            run_syncthing_listener(
                settings,
                thread_key,
                listener_id,
                listener_state,
                listener_sender,
                listener_lifetime,
            )
        })
    {
        let mut state = state.lock().unwrap();
        if state
            .listeners
            .get(&listener_key)
            .map(|listener| listener.id)
            == Some(listener_id)
        {
            state.listeners.remove(&listener_key);
        }
        warn!(%error, "local cloud GC Syncthing event listener unavailable");
    }
}

fn run_syncthing_listener(
    settings: SyncthingGcConfig,
    key: SyncthingListenerKey,
    listener_id: u64,
    state: Arc<Mutex<CoordinatorState>>,
    sender: mpsc::Sender<WorkerMessage>,
    lifetime: Weak<()>,
) {
    let mut cursor = None;
    let mut connected = false;
    let mut reconnect_delay = INITIAL_RECONNECT_DELAY;
    loop {
        if lifetime.upgrade().is_none() || !listener_is_current(&state, &key, listener_id) {
            return;
        }
        match settings.wait_for_gc_events(cursor) {
            Ok(batch) => {
                let wakes_gc = !connected || batch.wakes_gc;
                connected = true;
                reconnect_delay = INITIAL_RECONNECT_DELAY;
                cursor = batch.last_id;
                if wakes_gc
                    && mark_listener_wake_queued(&state, &key, listener_id)
                    && sender
                        .send(WorkerMessage::SyncthingEvent {
                            key: key.clone(),
                            listener_id,
                        })
                        .is_err()
                {
                    return;
                }
            }
            Err(error) if error.is_retryable() => {
                debug!(%error, "local cloud GC Syncthing event listener reconnecting");
                connected = false;
                cursor = None;
                std::thread::sleep(reconnect_delay);
                reconnect_delay = reconnect_delay
                    .checked_mul(2)
                    .unwrap_or(MAX_RECONNECT_DELAY)
                    .min(MAX_RECONNECT_DELAY);
            }
            Err(error) => {
                let _ = sender.send(WorkerMessage::SyncthingListenerStopped {
                    key,
                    listener_id,
                    error: error.to_string(),
                });
                return;
            }
        }
    }
}

fn listener_is_current(
    state: &Mutex<CoordinatorState>,
    key: &SyncthingListenerKey,
    listener_id: u64,
) -> bool {
    state
        .lock()
        .unwrap()
        .listeners
        .get(key)
        .map(|listener| listener.id)
        == Some(listener_id)
}

fn mark_listener_wake_queued(
    state: &Mutex<CoordinatorState>,
    key: &SyncthingListenerKey,
    listener_id: u64,
) -> bool {
    let mut state = state.lock().unwrap();
    let Some(listener) = state.listeners.get_mut(key) else {
        return false;
    };
    if listener.id != listener_id || listener.wake_queued {
        return false;
    }
    listener.wake_queued = true;
    true
}

fn finish_request(state: &Mutex<CoordinatorState>, request: &InspectionRequest) {
    let Some(listener_key) = request.listener_key() else {
        return;
    };
    let mut state = state.lock().unwrap();
    state.deferred.remove(&request.key());
    if !state
        .deferred
        .values()
        .any(|deferred| deferred.listener_key().as_ref() == Some(&listener_key))
    {
        state.listeners.remove(&listener_key);
    }
}

fn merge_pending_request(
    pending: &mut BTreeMap<InspectionKey, InspectionRequest>,
    request: InspectionRequest,
) {
    let key = request.key();
    match pending.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(request);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let current = entry.get();
            if (request.epoch, request.revision) > (current.epoch, current.revision) {
                entry.insert(request);
            }
        }
    }
}

fn request_is_current(
    state: &Mutex<CoordinatorState>,
    epoch: &AtomicU64,
    request: &InspectionRequest,
) -> bool {
    if request.epoch != epoch.load(Ordering::Acquire) {
        return false;
    }
    request_is_current_locked(&state.lock().unwrap(), epoch, request)
}

fn request_is_current_locked(
    state: &CoordinatorState,
    epoch: &AtomicU64,
    request: &InspectionRequest,
) -> bool {
    request.epoch == epoch.load(Ordering::Acquire)
        && state.revisions.get(&request.key()).copied() == Some(request.revision)
}

fn advance_revision(revisions: &mut BTreeMap<InspectionKey, u64>, key: &InspectionKey) -> u64 {
    let revision = revisions.entry(key.clone()).or_default();
    *revision = revision.wrapping_add(1).max(1);
    *revision
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(store: FolderStore, revision: u64) -> InspectionRequest {
        request_for(store, 480, revision, None)
    }

    fn request_for(
        store: FolderStore,
        app_id: u32,
        revision: u64,
        syncthing: Option<SyncthingGcConfig>,
    ) -> InspectionRequest {
        InspectionRequest {
            store,
            app_id,
            syncthing,
            epoch: 1,
            revision,
        }
    }

    fn syncthing() -> SyncthingGcConfig {
        SyncthingGcConfig {
            url: "http://127.0.0.1:8384".into(),
            api_key: "secret".into(),
            folder_id: "cloud".into(),
            timeout_ms: 1_000,
        }
    }

    #[test]
    fn coalescing_keeps_the_newest_request_when_delivery_is_reordered() {
        let directory = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(directory.path(), 76_561_198_000_000_001).unwrap();
        let newest = request(store.clone(), 2);
        let stale = request(store, 1);
        let key = newest.key();
        let mut pending = BTreeMap::new();

        merge_pending_request(&mut pending, newest);
        merge_pending_request(&mut pending, stale);

        let retained = pending.get(&key).unwrap();
        assert_eq!(retained.revision, 2);
    }

    #[test]
    fn a_delayed_request_stays_stale_after_the_newest_request_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(directory.path(), 76_561_198_000_000_001).unwrap();
        let delayed = request(store.clone(), 1);
        let newest = request(store.clone(), 2);
        let key = newest.key();
        let epoch = AtomicU64::new(1);
        let mut state = CoordinatorState::default();
        state.revisions.insert(key.clone(), 2);

        assert!(!request_is_current_locked(&state, &epoch, &delayed));
        assert!(request_is_current_locked(&state, &epoch, &newest));
        assert_eq!(state.revisions.get(&key), Some(&2));

        let next = advance_revision(&mut state.revisions, &key);
        assert_eq!(next, 3);
        assert!(!request_is_current_locked(&state, &epoch, &delayed));
        assert!(request_is_current_locked(
            &state,
            &epoch,
            &request(store, next)
        ));
    }

    #[test]
    fn one_syncthing_event_wakes_every_deferred_app_in_the_folder() {
        let directory = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(directory.path(), 76_561_198_000_000_001).unwrap();
        let first = request_for(store.clone(), 480, 1, Some(syncthing()));
        let second = request_for(store, 570, 1, Some(syncthing()));
        let listener_key = first.listener_key().unwrap();
        let first_key = first.key();
        let second_key = second.key();
        let epoch = AtomicU64::new(1);
        let mut state = CoordinatorState::default();
        state.revisions.insert(first_key.clone(), 1);
        state.revisions.insert(second_key.clone(), 1);
        state.deferred.insert(first_key, first);
        state.deferred.insert(second_key, second);
        state.listeners.insert(
            listener_key.clone(),
            ListenerRegistration {
                id: 7,
                wake_queued: true,
            },
        );

        let state = Mutex::new(state);
        let requests = take_deferred_requests(&state, &epoch, &listener_key, 7);

        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests
                .into_iter()
                .map(|request| request.app_id)
                .collect::<Vec<_>>(),
            vec![480, 570]
        );
        assert!(
            !state
                .lock()
                .unwrap()
                .listeners
                .get(&listener_key)
                .unwrap()
                .wake_queued
        );
    }

    #[test]
    fn stale_listener_events_do_not_wake_deferred_gc() {
        let directory = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(directory.path(), 76_561_198_000_000_001).unwrap();
        let request = request_for(store, 480, 1, Some(syncthing()));
        let listener_key = request.listener_key().unwrap();
        let request_key = request.key();
        let epoch = AtomicU64::new(1);
        let mut state = CoordinatorState::default();
        state.revisions.insert(request_key.clone(), 1);
        state.deferred.insert(request_key, request);
        state.listeners.insert(
            listener_key.clone(),
            ListenerRegistration {
                id: 8,
                wake_queued: true,
            },
        );
        let state = Mutex::new(state);

        assert!(take_deferred_requests(&state, &epoch, &listener_key, 7).is_empty());
        assert_eq!(state.lock().unwrap().deferred.len(), 1);
    }

    #[test]
    fn repeated_syncthing_events_share_one_queued_wake() {
        let directory = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(directory.path(), 76_561_198_000_000_001).unwrap();
        let request = request_for(store, 480, 1, Some(syncthing()));
        let listener_key = request.listener_key().unwrap();
        let mut state = CoordinatorState::default();
        state.listeners.insert(
            listener_key.clone(),
            ListenerRegistration {
                id: 9,
                wake_queued: false,
            },
        );
        let state = Mutex::new(state);

        assert!(mark_listener_wake_queued(&state, &listener_key, 9));
        assert!(!mark_listener_wake_queued(&state, &listener_key, 9));
    }

    #[test]
    fn unsafe_syncthing_configuration_prevents_inspection_and_deletion() {
        let directory = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(directory.path(), 76_561_198_000_000_001).unwrap();
        let manifest = directory.path().join("480/manifests/old.json");
        let blob = directory.path().join("480/blobs/aa/old");
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&manifest, b"old manifest").unwrap();
        std::fs::write(&blob, b"old blob").unwrap();
        let coordinator = LocalGcCoordinator::try_new().unwrap();

        coordinator.queue_inspection(
            store,
            480,
            Some(SyncthingGcConfig {
                url: "http://192.0.2.1:8384".into(),
                api_key: "secret".into(),
                folder_id: "cloud".into(),
                timeout_ms: 1_000,
            }),
        );

        assert!(coordinator.state.lock().unwrap().revisions.is_empty());
        assert!(manifest.exists());
        assert!(blob.exists());
    }
}
