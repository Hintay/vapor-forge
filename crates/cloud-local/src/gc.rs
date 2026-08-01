use crate::{FolderStore, GcRoots};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{mpsc, Mutex};
use tracing::{debug, warn};

struct ActiveBatch {
    repository: PathBuf,
    manifest_ids: BTreeSet<String>,
    blob_sha1s: BTreeSet<String>,
}

struct InspectionRequest {
    store: FolderStore,
    roots: GcRoots,
}

pub struct LocalGcCoordinator {
    active: Mutex<HashMap<u64, ActiveBatch>>,
    sender: mpsc::Sender<InspectionRequest>,
}

impl LocalGcCoordinator {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel::<InspectionRequest>();
        std::thread::Builder::new()
            .name("vapor-local-cloud-gc".into())
            .spawn(move || run_inspections(receiver))
            .expect("local cloud GC worker must start");
        Self {
            active: Mutex::new(HashMap::new()),
            sender,
        }
    }

    pub fn register_batch(&self, batch_id: u64, store: &FolderStore, manifest_ids: &[String]) {
        self.active.lock().unwrap().insert(
            batch_id,
            ActiveBatch {
                repository: store.root().to_owned(),
                manifest_ids: manifest_ids.iter().cloned().collect(),
                blob_sha1s: BTreeSet::new(),
            },
        );
    }

    pub fn retain_blob(&self, batch_id: u64, sha1: &str) {
        if let Some(batch) = self.active.lock().unwrap().get_mut(&batch_id) {
            batch.blob_sha1s.insert(sha1.to_owned());
        }
    }

    pub fn unregister_batch(&self, batch_id: u64) {
        self.active.lock().unwrap().remove(&batch_id);
    }

    pub fn queue_inspection(&self, store: FolderStore) {
        let roots = self.roots_for(store.root());
        if self
            .sender
            .send(InspectionRequest { store, roots })
            .is_err()
        {
            warn!("local cloud GC worker is unavailable");
        }
    }

    fn roots_for(&self, repository: &std::path::Path) -> GcRoots {
        let active = self.active.lock().unwrap();
        let mut roots = GcRoots::default();
        for batch in active
            .values()
            .filter(|batch| batch.repository == repository)
        {
            roots
                .manifest_ids
                .extend(batch.manifest_ids.iter().cloned());
            roots.blob_sha1s.extend(batch.blob_sha1s.iter().cloned());
        }
        roots
    }
}

impl Default for LocalGcCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

fn run_inspections(receiver: mpsc::Receiver<InspectionRequest>) {
    while let Ok(first) = receiver.recv() {
        let mut pending = BTreeMap::from([(first.store.root().to_owned(), first)]);
        while let Ok(request) = receiver.try_recv() {
            pending.insert(request.store.root().to_owned(), request);
        }
        for request in pending.into_values() {
            match request.store.inspect_gc(&request.roots) {
                Ok(report) => debug!(
                    retained_manifests = report.retained_manifests.len(),
                    candidate_manifests = report.candidate_manifests.len(),
                    retained_blobs = report.retained_blobs.len(),
                    candidate_blobs = report.candidate_blobs.len(),
                    "local cloud GC inspection completed"
                ),
                Err(error) => warn!(%error, "local cloud GC inspection failed closed"),
            }
        }
    }
}
