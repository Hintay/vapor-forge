use crate::{FolderStore, GcRoots};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use tracing::{debug, warn};

struct ActiveBatch {
    repository: PathBuf,
    manifest_scope: String,
    manifest_ids: BTreeSet<String>,
    blob_sha1s: BTreeSet<String>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct InspectionKey {
    repository: PathBuf,
    manifest_scope: String,
}

struct InspectionRequest {
    store: FolderStore,
    app_id: u32,
    roots: GcRoots,
}

impl InspectionRequest {
    fn key(&self) -> InspectionKey {
        InspectionKey {
            repository: self.store.root().to_owned(),
            manifest_scope: self.store.gc_manifest_scope(self.app_id),
        }
    }
}

struct DeferredInspection {
    store: FolderStore,
    app_id: u32,
}

#[derive(Default)]
struct CoordinatorState {
    active: HashMap<u64, ActiveBatch>,
    deferred: BTreeMap<InspectionKey, DeferredInspection>,
}

pub struct LocalGcCoordinator {
    state: Arc<Mutex<CoordinatorState>>,
    sender: mpsc::Sender<InspectionRequest>,
}

impl LocalGcCoordinator {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel::<InspectionRequest>();
        let state = Arc::new(Mutex::new(CoordinatorState::default()));
        let worker_state = Arc::clone(&state);
        std::thread::Builder::new()
            .name("vapor-local-cloud-gc".into())
            .spawn(move || run_inspections(receiver, worker_state))
            .expect("local cloud GC worker must start");
        Self { state, sender }
    }

    pub fn register_batch(
        &self,
        batch_id: u64,
        store: &FolderStore,
        app_id: u32,
        manifest_ids: &[String],
    ) {
        self.state.lock().unwrap().active.insert(
            batch_id,
            ActiveBatch {
                repository: store.root().to_owned(),
                manifest_scope: store.gc_manifest_scope(app_id),
                manifest_ids: manifest_ids.iter().cloned().collect(),
                blob_sha1s: BTreeSet::new(),
            },
        );
    }

    pub fn retain_blob(&self, batch_id: u64, sha1: &str) {
        if let Some(batch) = self.state.lock().unwrap().active.get_mut(&batch_id) {
            batch.blob_sha1s.insert(sha1.to_owned());
        }
    }

    pub fn unregister_batch(&self, batch_id: u64) {
        let requests = {
            let mut state = self.state.lock().unwrap();
            let Some(batch) = state.active.remove(&batch_id) else {
                return;
            };
            let keys = state
                .deferred
                .keys()
                .filter(|key| {
                    key.repository == batch.repository && key.manifest_scope == batch.manifest_scope
                })
                .cloned()
                .collect::<Vec<_>>();
            let deferred = keys
                .into_iter()
                .filter_map(|key| state.deferred.remove(&key).map(|request| (key, request)))
                .collect::<Vec<_>>();
            deferred
                .into_iter()
                .map(|(key, request)| InspectionRequest {
                    roots: roots_for(&state.active, &key.repository, &key.manifest_scope),
                    store: request.store,
                    app_id: request.app_id,
                })
                .collect::<Vec<_>>()
        };
        for request in requests {
            self.send_request(request);
        }
    }

    pub fn queue_inspection(&self, store: FolderStore, app_id: u32) {
        let request = {
            let mut state = self.state.lock().unwrap();
            let key = InspectionKey {
                repository: store.root().to_owned(),
                manifest_scope: store.gc_manifest_scope(app_id),
            };
            state.deferred.remove(&key);
            InspectionRequest {
                roots: roots_for(&state.active, &key.repository, &key.manifest_scope),
                store,
                app_id,
            }
        };
        self.send_request(request);
    }

    fn send_request(&self, request: InspectionRequest) {
        if self.sender.send(request).is_err() {
            warn!("local cloud GC worker is unavailable");
        }
    }
}

impl Default for LocalGcCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

fn run_inspections(
    receiver: mpsc::Receiver<InspectionRequest>,
    state: Arc<Mutex<CoordinatorState>>,
) {
    while let Ok(first) = receiver.recv() {
        let mut pending = BTreeMap::from([(first.key(), first)]);
        while let Ok(request) = receiver.try_recv() {
            pending.insert(request.key(), request);
        }
        for request in pending.into_values() {
            let report = match request.store.inspect_gc(request.app_id, &request.roots) {
                Ok(report) => report,
                Err(error) => {
                    warn!(%error, "local cloud GC inspection failed closed");
                    continue;
                }
            };
            let plan = match request.store.prepare_gc_sweep(&report) {
                Ok(Some(plan)) => plan,
                Ok(None) => {
                    defer_request(
                        &state,
                        InspectionRequest {
                            store: request.store.clone(),
                            app_id: request.app_id,
                            roots: request.roots.clone(),
                        },
                    );
                    continue;
                }
                Err(error) => {
                    warn!(%error, "local cloud GC preparation failed closed");
                    continue;
                }
            };

            let key = request.key();
            let mut coordinator = state.lock().unwrap();
            let current_roots =
                roots_for(&coordinator.active, &key.repository, &key.manifest_scope);
            match request.store.apply_gc_sweep(plan, &current_roots) {
                Ok(Some(sweep)) => debug!(
                    app_id = request.app_id,
                    retained_manifests = report.retained_manifests.len(),
                    deleted_manifests = sweep.deleted_manifests,
                    retained_blobs = report.retained_blobs.len(),
                    deleted_blobs = sweep.deleted_blobs,
                    "local cloud GC completed"
                ),
                Ok(None) => {
                    coordinator.deferred.insert(
                        key,
                        DeferredInspection {
                            store: request.store,
                            app_id: request.app_id,
                        },
                    );
                }
                Err(error) => warn!(%error, "local cloud GC deletion failed closed"),
            }
        }
    }
}

fn defer_request(state: &Mutex<CoordinatorState>, request: InspectionRequest) {
    state.lock().unwrap().deferred.insert(
        request.key(),
        DeferredInspection {
            store: request.store,
            app_id: request.app_id,
        },
    );
}

fn roots_for(
    active: &HashMap<u64, ActiveBatch>,
    repository: &Path,
    manifest_scope: &str,
) -> GcRoots {
    let mut roots = GcRoots::default();
    for batch in active
        .values()
        .filter(|batch| batch.repository == repository && batch.manifest_scope == manifest_scope)
    {
        roots
            .manifest_ids
            .extend(batch.manifest_ids.iter().cloned());
        roots.blob_sha1s.extend(batch.blob_sha1s.iter().cloned());
    }
    roots
}
