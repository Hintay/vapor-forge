use crate::{FolderStore, SyncthingGcConfig};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use tracing::{debug, warn};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct InspectionKey {
    repository: PathBuf,
    manifest_scope: String,
}

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
            manifest_scope: self.store.gc_manifest_scope(self.app_id),
        }
    }
}

#[derive(Default)]
struct CoordinatorState {
    revisions: BTreeMap<InspectionKey, u64>,
}

pub struct LocalGcCoordinator {
    state: Arc<Mutex<CoordinatorState>>,
    sender: mpsc::Sender<InspectionRequest>,
    epoch: Arc<AtomicU64>,
}

impl LocalGcCoordinator {
    pub fn try_new() -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::channel::<InspectionRequest>();
        let state = Arc::new(Mutex::new(CoordinatorState::default()));
        let worker_state = Arc::clone(&state);
        let epoch = Arc::new(AtomicU64::new(1));
        let worker_epoch = Arc::clone(&epoch);
        std::thread::Builder::new()
            .name("vapor-local-cloud-gc".into())
            .spawn(move || run_inspections(receiver, worker_state, worker_epoch))?;
        Ok(Self {
            state,
            sender,
            epoch,
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
                manifest_scope: store.gc_manifest_scope(app_id),
            };
            let revision = advance_revision(&mut state.revisions, &key);
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
    }

    fn send_request(&self, request: InspectionRequest) {
        if self.sender.send(request).is_err() {
            warn!("local cloud GC worker is unavailable");
        }
    }
}

fn run_inspections(
    receiver: mpsc::Receiver<InspectionRequest>,
    state: Arc<Mutex<CoordinatorState>>,
    epoch: Arc<AtomicU64>,
) {
    while let Ok(first) = receiver.recv() {
        let mut pending = BTreeMap::new();
        merge_pending_request(&mut pending, first);
        while let Ok(request) = receiver.try_recv() {
            merge_pending_request(&mut pending, request);
        }
        for request in pending.into_values() {
            if !request_is_current(&state, &epoch, &request) {
                continue;
            }
            let report = match request.store.inspect_gc(request.app_id) {
                Ok(report) => report,
                Err(error) => {
                    warn!(%error, "local cloud GC inspection failed closed");
                    continue;
                }
            };
            let syncthing_boundary = if report.candidate_manifests.is_empty() {
                None
            } else if let Some(syncthing) = &request.syncthing {
                match syncthing.prepare_for_gc(request.store.root(), &report) {
                    Ok(boundary) => Some(boundary),
                    Err(error) => {
                        warn!(%error, "local cloud GC Syncthing boundary failed closed");
                        continue;
                    }
                }
            } else {
                None
            };
            if request.epoch != epoch.load(Ordering::Acquire) {
                continue;
            }
            let plan = match request.store.prepare_gc_sweep(&report) {
                Ok(Some(plan)) => plan,
                Ok(None) => continue,
                Err(error) => {
                    warn!(%error, "local cloud GC preparation failed closed");
                    continue;
                }
            };

            if !request_is_current(&state, &epoch, &request) {
                continue;
            }
            match request.store.apply_gc_sweep(plan) {
                Ok(Some(sweep)) => {
                    if let (Some(syncthing), Some(boundary)) =
                        (&request.syncthing, syncthing_boundary)
                    {
                        if let Err(error) = syncthing.publish_gc(boundary) {
                            warn!(%error, "local cloud GC Syncthing deletion scan failed");
                        }
                    }
                    debug!(
                        app_id = request.app_id,
                        retained_manifests = report.retained_manifests.len(),
                        deleted_manifests = sweep.deleted_manifests,
                        "local cloud GC completed"
                    );
                }
                Ok(None) => {}
                Err(error) => {
                    warn!(%error, "local cloud GC deletion failed closed");
                }
            }
        }
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
        InspectionRequest {
            store,
            app_id: 480,
            syncthing: None,
            epoch: 1,
            revision,
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
