use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};
use vapor_forge_cloud_core::{
    BackendError, ByteStore, ChangeList, CloudFileStore, FileEntry, FileMetadata, Quota, Transfer,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const FORMAT_VERSION: u32 = 1;
const FORMAT_FILE: &str = "format.json";
const MAX_FORMAT_BYTES: u64 = 64 * 1024;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_FILES: usize = 100_000;
const MAX_MANIFEST_PARENTS: usize = 4096;
const MAX_MANIFEST_OBJECTS: usize = 4096;
pub(crate) const MAX_SAVE_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CLOUD_PATH_BYTES: usize = 4096;
const MAX_SESSION_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_SESSION_RECORDS: usize = 4096;
static REPOSITORY_COORDINATORS: OnceLock<Mutex<HashMap<PathBuf, Weak<RepositoryCoordination>>>> =
    OnceLock::new();

#[derive(Clone)]
pub struct FolderStore {
    root: PathBuf,
    account: Option<String>,
    coordination: Arc<RepositoryCoordination>,
}

struct RepositoryCoordination {
    root: PathBuf,
    lock: Mutex<()>,
    work_root: PathBuf,
}

impl Drop for RepositoryCoordination {
    fn drop(&mut self) {
        let coordinators = REPOSITORY_COORDINATORS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut coordinators = coordinators
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let is_current = coordinators
            .get(&self.root)
            .is_some_and(|coordination| std::ptr::eq(coordination.as_ptr(), self));
        if !is_current {
            return;
        }
        coordinators.remove(&self.root);
        let _ = std::fs::remove_dir_all(&self.work_root);
        if let Some(parent) = self.work_root.parent() {
            let _ = sync_directory(parent);
        }
    }
}

#[derive(Clone)]
pub struct SaveOperation {
    inner: Arc<SaveOperationInner>,
}

struct SaveOperationInner {
    coordination: Arc<RepositoryCoordination>,
    repository: PathBuf,
    manifest_scope: String,
    app_id: u32,
    path: PathBuf,
    expected_heads: Vec<String>,
    parents: Vec<String>,
    original_files: BTreeMap<String, StoredFile>,
    force_publish: bool,
    minimum_revision: u64,
    io_lock: Mutex<()>,
    closed: AtomicBool,
}

impl Drop for SaveOperationInner {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire) {
            let _ = std::fs::remove_dir_all(&self.path);
            if let Some(parent) = self.path.parent() {
                let _ = sync_directory(parent);
            }
        }
    }
}

impl SaveOperation {
    pub fn abort(&self) -> Result<(), BackendError> {
        let _lock = self
            .inner
            .io_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        remove_dir_all_if_exists(&self.inner.path)?;
        if let Some(parent) = self.inner.path.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFile {
    pub path: String,
    pub blob_sha1: String,
    pub metadata: FileMetadata,
}

pub(crate) struct BoundDownload {
    file: std::fs::File,
    metadata: FileMetadata,
}

impl BoundDownload {
    pub(crate) fn read(mut self) -> Result<Vec<u8>, BackendError> {
        let capacity = usize::try_from(self.metadata.raw_size)
            .map_err(|_| permanent("local cloud file is too large for this process"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| permanent("local cloud file is too large for this process"))?;
        std::io::Read::by_ref(&mut self.file)
            .take(self.metadata.raw_size.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        verify_blob_bytes(&stored_file_from_metadata(&self.metadata), &bytes)?;
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreView {
    pub current_change_number: Option<u64>,
    pub max_revision: u64,
    pub heads: Vec<ManifestCandidate>,
}

impl StoreView {
    pub fn head_ids(&self) -> Vec<String> {
        self.heads.iter().map(|head| head.id.clone()).collect()
    }

    pub fn is_conflicted(&self) -> bool {
        self.current_change_number.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestCandidate {
    pub id: String,
    pub revision: u64,
    pub client_id: u64,
    pub machine_name: String,
    pub created_at_ms: u64,
    pub file_count: usize,
    pub total_bytes: u64,
    pub file_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitIdentity {
    pub client_id: u64,
    pub machine_name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    pub app_id: u32,
    pub manifest_scope: String,
    pub retained_manifests: Vec<String>,
    pub candidate_manifests: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct GcSweep {
    pub deleted_manifests: usize,
    moved_manifests: Vec<(String, PathBuf)>,
}

pub(crate) struct GcSweepPlan<'a> {
    _lock: MutexGuard<'a, ()>,
    root: PathBuf,
    app_id: u32,
    expected_manifests: BTreeSet<String>,
    candidate_manifests: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionPeer {
    pub client_id: u64,
    pub machine_name: String,
    pub time_last_updated: u32,
    pub os_type: Option<i32>,
    pub device_type: Option<i32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Format {
    version: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredFile {
    sha1: String,
    raw_size: u64,
    mtime: i64,
    platforms_to_sync: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SaveManifest {
    steam_id64: String,
    app_id: u32,
    revision: u64,
    parents: Vec<String>,
    client_id: u64,
    machine_name: String,
    created_at_ms: u64,
    files: BTreeMap<String, StoredFile>,
}

struct ResolvedApp {
    manifests: HashMap<String, SaveManifest>,
    heads: Vec<String>,
    max_revision: u64,
}

impl ResolvedApp {
    fn current(&self) -> Result<Option<(&str, &SaveManifest)>, BackendError> {
        match self.heads.as_slice() {
            [] => Ok(None),
            [id] => Ok(Some((id, &self.manifests[id]))),
            _ => Err(conflict("local cloud has unresolved manifest heads")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SessionStatus {
    Active,
    Suspended,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionClaim {
    app_id: u32,
    client_id: u64,
    machine_name: String,
    os_type: Option<i32>,
    device_type: Option<i32>,
    status: SessionStatus,
    observed_heads: Vec<String>,
    updated_at: u32,
    nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionOverride {
    app_id: u32,
    client_id: u64,
    superseded_claims: Vec<String>,
}

impl FolderStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BackendError> {
        Self::open_inner(root, None)
    }

    pub fn open_account(root: impl AsRef<Path>, steam_id64: u64) -> Result<Self, BackendError> {
        if steam_id64 == 0 {
            return Err(permanent("local cloud account is unavailable"));
        }
        Self::open_inner(root, Some(steam_id64.to_string()))
    }

    fn open_inner(root: impl AsRef<Path>, account: Option<String>) -> Result<Self, BackendError> {
        let root = root.as_ref();
        if root.as_os_str().is_empty() {
            return Err(permanent("local cloud path is empty"));
        }
        let root = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir().map_err(io_error)?.join(root)
        };
        create_durable_dir_all(&root)?;
        let root = root.canonicalize().map_err(io_error)?;
        let coordination = repository_coordination(&root)?;
        let store = Self {
            root,
            account,
            coordination,
        };
        store.initialize()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn view(&self, app_id: u32) -> Result<StoreView, BackendError> {
        validate_app_id(app_id)?;
        let _lock = self.lock_app(app_id)?;
        self.view_unlocked(app_id)
    }

    fn view_unlocked(&self, app_id: u32) -> Result<StoreView, BackendError> {
        let resolved = self.resolve_app(app_id)?;
        let current_change_number = match resolved.heads.as_slice() {
            [] => Some(0),
            [id] => Some(resolved.manifests[id].revision),
            _ => None,
        };
        let heads = resolved
            .heads
            .iter()
            .map(|id| {
                let manifest = &resolved.manifests[id];
                let total_bytes = manifest
                    .files
                    .values()
                    .fold(0u64, |total, file| total.saturating_add(file.raw_size));
                ManifestCandidate {
                    id: id.clone(),
                    revision: manifest.revision,
                    client_id: manifest.client_id,
                    machine_name: manifest.machine_name.clone(),
                    created_at_ms: manifest.created_at_ms,
                    file_count: manifest.files.len(),
                    total_bytes,
                    file_names: manifest.files.keys().take(8).cloned().collect(),
                }
            })
            .collect();
        Ok(StoreView {
            current_change_number,
            max_revision: resolved.max_revision,
            heads,
        })
    }

    pub fn changes_from_head(
        &self,
        app_id: u32,
        head: &str,
        since: u64,
    ) -> Result<ChangeList, BackendError> {
        validate_app_id(app_id)?;
        let _lock = self.lock_app(app_id)?;
        let resolved = self.resolve_app(app_id)?;
        if !resolved.heads.iter().any(|candidate| candidate == head) {
            return Err(conflict(
                "selected local cloud manifest is not an active head",
            ));
        }
        let manifest = resolved
            .manifests
            .get(head)
            .ok_or_else(|| incomplete("selected local cloud manifest is unavailable"))?;
        change_list_from_manifest(Some(manifest), since, true)
    }

    pub fn begin_operation(
        &self,
        app_id: u32,
        base_heads: &[String],
        resolution_heads: Option<&[String]>,
    ) -> Result<SaveOperation, BackendError> {
        self.begin_operation_with_revision(app_id, base_heads, resolution_heads, 0)
    }

    fn begin_operation_with_revision(
        &self,
        app_id: u32,
        base_heads: &[String],
        resolution_heads: Option<&[String]>,
        minimum_revision: u64,
    ) -> Result<SaveOperation, BackendError> {
        validate_app_id(app_id)?;
        let _lock = self.lock_app(app_id)?;
        let resolved = self.resolve_app(app_id)?;
        let base_heads = normalized_head_ids(base_heads)?;
        let resolution_heads = resolution_heads.map(normalized_head_ids).transpose()?;
        let expected_heads = resolution_heads
            .clone()
            .unwrap_or_else(|| base_heads.clone());
        let (parents, selected_id, original_files, force_publish) = match resolution_heads {
            Some(expected) => {
                if expected.len() < 2 || resolved.heads != expected {
                    return Err(conflict(
                        "local cloud conflict heads changed before resolution",
                    ));
                }
                let [selected] = base_heads.as_slice() else {
                    return Err(permanent(
                        "local conflict resolution requires one selected base",
                    ));
                };
                let selected = resolved.manifests.get(selected).ok_or_else(|| {
                    permanent("selected local conflict manifest is not an active head")
                })?;
                (
                    expected,
                    Some(base_heads[0].clone()),
                    selected.files.clone(),
                    true,
                )
            }
            None => {
                if resolved.heads != base_heads {
                    return Err(conflict("local cloud changed after the upload batch began"));
                }
                if resolved.heads.len() > 1 {
                    return Err(conflict(
                        "ordinary upload cannot cover unresolved manifest heads",
                    ));
                }
                let files = resolved
                    .current()?
                    .map(|(_, manifest)| manifest.files.clone())
                    .unwrap_or_default();
                let selected_id = base_heads.first().cloned();
                (base_heads, selected_id, files, false)
            }
        };

        let operation_path = self
            .coordination
            .work_root
            .join(format!("operation-{}", next_nonce()));
        let operation_blobs = operation_path.join("blobs");
        create_durable_dir_all(&operation_blobs)?;
        if let Some(selected_id) = selected_id.as_deref() {
            let mut copied = BTreeSet::new();
            for file in original_files.values() {
                if !copied.insert(file.sha1.clone()) {
                    continue;
                }
                let source = self.manifest_blob_path(app_id, selected_id, &file.sha1)?;
                let target = operation_blob_path(&operation_path, &file.sha1)?;
                link_or_copy(&source, &target)?;
            }
            sync_directory(&operation_blobs)?;
        }
        Ok(SaveOperation {
            inner: Arc::new(SaveOperationInner {
                coordination: Arc::clone(&self.coordination),
                repository: self.root.clone(),
                manifest_scope: self.manifest_scope(app_id),
                app_id,
                path: operation_path,
                expected_heads,
                parents,
                original_files,
                force_publish,
                minimum_revision,
                io_lock: Mutex::new(()),
                closed: AtomicBool::new(false),
            }),
        })
    }

    pub fn stage_file(
        &self,
        operation: &SaveOperation,
        path: &str,
        contents: &[u8],
        metadata: &FileMetadata,
    ) -> Result<StagedFile, BackendError> {
        self.validate_operation(operation)?;
        let _lock = operation
            .inner
            .io_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if operation.inner.closed.load(Ordering::Acquire) {
            return Err(permanent("local cloud operation is closed"));
        }
        validate_cloud_path(path)?;
        validate_metadata(contents, metadata)?;
        let blob_sha1 = metadata.sha1.to_ascii_lowercase();
        atomic_publish(
            &operation_blob_path(&operation.inner.path, &blob_sha1)?,
            contents,
        )?;
        Ok(StagedFile {
            path: path.to_owned(),
            blob_sha1,
            metadata: metadata.clone(),
        })
    }

    pub fn commit_operation(
        &self,
        operation: &SaveOperation,
        staged: &[StagedFile],
        deleted: &BTreeSet<String>,
        identity: &CommitIdentity,
    ) -> Result<u64, BackendError> {
        self.validate_operation(operation)?;
        validate_identity(identity)?;
        let _operation_lock = operation
            .inner
            .io_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if operation.inner.closed.load(Ordering::Acquire) {
            return Err(permanent("local cloud operation is closed"));
        }
        let app_id = operation.inner.app_id;
        let _lock = self.lock_app(app_id)?;
        let resolved = self.resolve_app(app_id)?;
        if resolved.heads != operation.inner.expected_heads {
            return Err(conflict("local cloud changed after the upload batch began"));
        }

        let mut files = operation.inner.original_files.clone();
        for path in deleted {
            validate_cloud_path(path)?;
            files.remove(path);
        }
        for file in staged {
            validate_cloud_path(&file.path)?;
            files.insert(
                file.path.clone(),
                StoredFile {
                    sha1: file.blob_sha1.clone(),
                    raw_size: file.metadata.raw_size,
                    mtime: file.metadata.mtime,
                    platforms_to_sync: file.metadata.platforms_to_sync,
                },
            );
        }
        self.prune_operation_blobs(operation, &files)?;
        self.verify_operation_files(operation, &files)?;
        if files == operation.inner.original_files && !operation.inner.force_publish {
            let revision = resolved
                .current()?
                .map_or(0, |(_, manifest)| manifest.revision);
            operation.inner.closed.store(true, Ordering::Release);
            remove_dir_all_if_exists(&operation.inner.path)?;
            sync_directory(&self.coordination.work_root)?;
            return Ok(revision);
        }
        self.publish_operation(
            operation,
            files,
            identity,
            resolved.max_revision.max(operation.inner.minimum_revision),
        )
    }

    pub fn abort_operation(&self, operation: &SaveOperation) -> Result<(), BackendError> {
        self.validate_operation(operation)?;
        operation.abort()
    }

    pub fn resolve_to_manifest(
        &self,
        app_id: u32,
        expected_heads: &[String],
        selected_head: &str,
        identity: &CommitIdentity,
        minimum_revision: u64,
    ) -> Result<u64, BackendError> {
        validate_app_id(app_id)?;
        validate_identity(identity)?;
        let expected_heads = normalized_head_ids(expected_heads)?;
        let operation = self.begin_operation_with_revision(
            app_id,
            &[selected_head.to_owned()],
            Some(&expected_heads),
            minimum_revision,
        )?;
        self.commit_operation(&operation, &[], &BTreeSet::new(), identity)
    }

    pub fn resolve_identical_heads(
        &self,
        app_id: u32,
        identity: &CommitIdentity,
    ) -> Result<Option<u64>, BackendError> {
        validate_app_id(app_id)?;
        validate_identity(identity)?;
        let (heads, selected) = {
            let _lock = self.lock_app(app_id)?;
            let resolved = self.resolve_app(app_id)?;
            if resolved.heads.len() < 2 {
                return Ok(None);
            }
            let selected = resolved.heads[0].clone();
            let selected_files = &resolved.manifests[&selected].files;
            if !resolved
                .heads
                .iter()
                .all(|head| &resolved.manifests[head].files == selected_files)
            {
                return Ok(None);
            }
            (resolved.heads, selected)
        };
        let operation = self.begin_operation(app_id, &[selected], Some(&heads))?;
        self.commit_operation(&operation, &[], &BTreeSet::new(), identity)
            .map(Some)
    }

    pub fn inspect_gc(&self, app_id: u32) -> Result<GcReport, BackendError> {
        validate_app_id(app_id)?;
        let target_scope = self.manifest_scope(app_id);
        let manifests = self.collect_manifest_objects(app_id)?;
        let referenced = manifests
            .values()
            .flat_map(|manifest| manifest.parents.iter())
            .collect::<BTreeSet<_>>();
        let head_ids = manifests
            .keys()
            .filter(|id| !referenced.contains(*id))
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut retained_manifest_ids = head_ids.clone();
        for head in &head_ids {
            retained_manifest_ids.extend(
                manifests[head]
                    .parents
                    .iter()
                    .filter(|parent| manifests.contains_key(*parent))
                    .cloned(),
            );
        }
        for id in &retained_manifest_ids {
            let manifest = manifests
                .get(id)
                .ok_or_else(|| incomplete("local cloud GC retained manifest is unavailable"))?;
            self.verify_files(app_id, id, &manifest.files)?;
        }

        let candidate_manifests = manifests
            .keys()
            .filter(|id| !retained_manifest_ids.contains(*id))
            .cloned()
            .collect();
        Ok(GcReport {
            app_id,
            manifest_scope: target_scope,
            retained_manifests: retained_manifest_ids.into_iter().collect(),
            candidate_manifests,
        })
    }

    pub(crate) fn prepare_gc_sweep(
        &self,
        report: &GcReport,
    ) -> Result<Option<GcSweepPlan<'_>>, BackendError> {
        if report.manifest_scope != self.manifest_scope(report.app_id) {
            return Err(permanent("invalid local cloud GC scope"));
        }
        let retained_manifests = unique_items(&report.retained_manifests)?;
        let candidate_manifests = unique_items(&report.candidate_manifests)?;
        if !retained_manifests.is_disjoint(&candidate_manifests) {
            return Err(permanent("invalid local cloud GC report"));
        }

        let _lock = self.lock_app(report.app_id)?;
        let current_manifests = collect_manifest_paths(&self.app_dir(report.app_id))?;
        let expected_manifests = retained_manifests
            .union(&candidate_manifests)
            .cloned()
            .collect::<BTreeSet<_>>();
        if current_manifests != expected_manifests {
            return Ok(None);
        }

        Ok(Some(GcSweepPlan {
            _lock,
            root: self.app_dir(report.app_id),
            app_id: report.app_id,
            expected_manifests,
            candidate_manifests,
        }))
    }

    pub(crate) fn apply_gc_sweep(
        &self,
        plan: GcSweepPlan<'_>,
    ) -> Result<Option<GcSweep>, BackendError> {
        if plan.root != self.app_dir(plan.app_id) {
            return Ok(None);
        }
        if collect_manifest_paths(&self.app_dir(plan.app_id))? != plan.expected_manifests {
            return Ok(None);
        }

        let mut moved_manifests = Vec::new();
        for id in &plan.candidate_manifests {
            match self.move_manifest_to_trash(plan.app_id, id) {
                Ok(Some(trash)) => moved_manifests.push((id.clone(), trash)),
                Ok(None) => {}
                Err(error) => {
                    let sweep = GcSweep {
                        deleted_manifests: moved_manifests.len(),
                        moved_manifests,
                    };
                    let _ = self.restore_gc_sweep_locked(plan.app_id, sweep);
                    return Err(error);
                }
            }
        }
        Ok(Some(GcSweep {
            deleted_manifests: moved_manifests.len(),
            moved_manifests,
        }))
    }

    pub(crate) fn finalize_gc_sweep(&self, sweep: GcSweep) -> Result<(), BackendError> {
        for (_, trash) in sweep.moved_manifests {
            remove_dir_all_if_exists(&trash)?;
        }
        sync_directory(&self.coordination.work_root)
    }

    pub(crate) fn restore_gc_sweep(&self, app_id: u32, sweep: GcSweep) -> Result<(), BackendError> {
        let _lock = self.lock_app(app_id)?;
        self.restore_gc_sweep_locked(app_id, sweep)
    }

    fn restore_gc_sweep_locked(&self, app_id: u32, sweep: GcSweep) -> Result<(), BackendError> {
        for (id, trash) in sweep.moved_manifests.into_iter().rev() {
            let destination = self.manifest_dir(app_id, &id)?;
            if destination.exists() {
                remove_dir_all_if_exists(&trash)?;
                continue;
            }
            std::fs::rename(&trash, &destination).map_err(io_error)?;
        }
        sync_directory(&self.app_dir(app_id))?;
        sync_directory(&self.coordination.work_root)
    }

    fn publish_operation(
        &self,
        operation: &SaveOperation,
        files: BTreeMap<String, StoredFile>,
        identity: &CommitIdentity,
        max_revision: u64,
    ) -> Result<u64, BackendError> {
        let revision = max_revision
            .checked_add(1)
            .ok_or_else(|| permanent("local cloud revision overflow"))?;
        let manifest = SaveManifest {
            steam_id64: self.manifest_account()?.to_owned(),
            app_id: operation.inner.app_id,
            revision,
            parents: operation.inner.parents.clone(),
            client_id: identity.client_id,
            machine_name: identity.machine_name.clone(),
            created_at_ms: unix_millis(),
            files,
        };
        let bytes = serde_json::to_vec(&manifest).map_err(json_error)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(permanent("local cloud manifest is too large"));
        }
        let id = hex_digest::<Sha256>(&bytes);
        validate_manifest(
            &id,
            self.manifest_account()?,
            operation.inner.app_id,
            &manifest,
        )?;
        atomic_publish(&operation.inner.path.join("manifest.json"), &bytes)?;
        sync_directory(&operation.inner.path.join("blobs"))?;
        sync_directory(&operation.inner.path)?;
        create_durable_dir_all(&self.app_dir(operation.inner.app_id))?;
        let destination = self.manifest_dir(operation.inner.app_id, &id)?;
        std::fs::rename(&operation.inner.path, &destination).map_err(io_error)?;
        operation.inner.closed.store(true, Ordering::Release);
        sync_directory(&self.coordination.work_root)?;
        sync_directory(&self.app_dir(operation.inner.app_id))?;
        Ok(revision)
    }

    pub fn launch_session(
        &self,
        app_id: u32,
        identity: &CommitIdentity,
        os_type: Option<i32>,
        device_type: Option<i32>,
        ignore_pending: bool,
    ) -> Result<Vec<SessionPeer>, BackendError> {
        validate_app_id(app_id)?;
        validate_identity(identity)?;
        let _lock = self.lock_app(app_id)?;
        let claims = self.read_session_claims(app_id)?;
        let mut overrides = self.read_session_overrides(app_id)?;
        let initial_live_claims = live_claim_ids(&claims);
        let superseded = superseded_live_claims(&overrides, &initial_live_claims);
        let pending = claims
            .iter()
            .filter(|(id, claim)| claim.client_id != identity.client_id && !superseded.contains(id))
            .map(|(_, claim)| SessionPeer {
                client_id: claim.client_id,
                machine_name: claim.machine_name.clone(),
                time_last_updated: claim.updated_at,
                os_type: claim.os_type,
                device_type: claim.device_type,
            })
            .collect::<Vec<_>>();
        if !pending.is_empty() && !ignore_pending {
            self.reconcile_loaded_session_overrides(overrides, &initial_live_claims)?;
            return Ok(pending);
        }
        if !pending.is_empty() {
            let mut superseded_claims = superseded;
            superseded_claims.extend(
                claims
                    .iter()
                    .filter(|(_, claim)| claim.client_id != identity.client_id)
                    .map(|(id, _)| id.clone()),
            );
            let mut superseded_claims = superseded_claims.into_iter().collect::<Vec<_>>();
            superseded_claims.sort();
            let override_record = SessionOverride {
                app_id,
                client_id: identity.client_id,
                superseded_claims,
            };
            let path = self.session_override_path(app_id, identity.client_id)?;
            self.write_session_override(&override_record)?;
            overrides.retain(|(existing, _)| existing != &path);
            overrides.push((path, override_record));
        }
        let claim_id = self.write_session_claim(SessionClaim {
            app_id,
            client_id: identity.client_id,
            machine_name: identity.machine_name.clone(),
            os_type,
            device_type,
            status: SessionStatus::Active,
            observed_heads: self.view_unlocked(app_id)?.head_ids(),
            updated_at: unix_seconds(),
            nonce: next_nonce(),
        })?;
        let mut final_live_claims = claims
            .iter()
            .filter(|(_, claim)| claim.client_id != identity.client_id)
            .map(|(id, _)| id.clone())
            .collect::<HashSet<_>>();
        final_live_claims.insert(claim_id);
        self.reconcile_loaded_session_overrides(overrides, &final_live_claims)?;
        Ok(Vec::new())
    }

    pub fn suspend_session(
        &self,
        app_id: u32,
        identity: &CommitIdentity,
    ) -> Result<(), BackendError> {
        self.update_session(app_id, identity, SessionStatus::Suspended)
    }

    pub fn resume_session(
        &self,
        app_id: u32,
        identity: &CommitIdentity,
    ) -> Result<(), BackendError> {
        self.update_session(app_id, identity, SessionStatus::Active)
    }

    pub fn exit_session(&self, app_id: u32, identity: &CommitIdentity) -> Result<(), BackendError> {
        validate_app_id(app_id)?;
        validate_identity(identity)?;
        let _lock = self.lock_app(app_id)?;
        if self
            .read_session_claim(app_id, identity.client_id)?
            .is_none()
        {
            return Ok(());
        }
        remove_if_exists(&self.session_claim_path(app_id, identity.client_id)?)?;
        let claims = self.read_session_claims(app_id)?;
        self.reconcile_session_overrides(app_id, &live_claim_ids(&claims))?;
        Ok(())
    }

    fn update_session(
        &self,
        app_id: u32,
        identity: &CommitIdentity,
        status: SessionStatus,
    ) -> Result<(), BackendError> {
        validate_app_id(app_id)?;
        validate_identity(identity)?;
        let _lock = self.lock_app(app_id)?;
        let mut claim = self
            .read_session_claim(app_id, identity.client_id)?
            .ok_or_else(|| conflict("local cloud session does not belong to this client"))?;
        let observed_heads = self.view_unlocked(app_id)?.head_ids();
        if claim.machine_name != identity.machine_name
            || claim.status != status
            || claim.observed_heads != observed_heads
        {
            claim.machine_name = identity.machine_name.clone();
            claim.status = status;
            claim.observed_heads = observed_heads;
            claim.updated_at = unix_seconds();
            claim.nonce = next_nonce();
            self.write_session_claim(claim)?;
        }
        let claims = self.read_session_claims(app_id)?;
        self.reconcile_session_overrides(app_id, &live_claim_ids(&claims))?;
        Ok(())
    }

    fn read_session_claims(
        &self,
        app_id: u32,
    ) -> Result<Vec<(String, SessionClaim)>, BackendError> {
        let directory = self.session_dir(app_id)?.join("claims");
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut claims = Vec::new();
        let mut entries = 0usize;
        for entry in std::fs::read_dir(directory).map_err(io_error)? {
            entries += 1;
            if entries > MAX_SESSION_RECORDS {
                return Err(permanent("too many local cloud session claims"));
            }
            let path = entry.map_err(io_error)?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = read_bounded_file(&path, MAX_SESSION_RECORD_BYTES, "session claim")?;
            let claim = serde_json::from_slice::<SessionClaim>(&bytes)
                .map_err(|_| incomplete("local cloud session claim is incomplete"))?;
            validate_session_claim(app_id, &claim)?;
            if session_record_client_id(&path)? != claim.client_id {
                return Err(permanent("local cloud session claim ClientID is invalid"));
            }
            claims.push((hex_digest::<Sha256>(&bytes), claim));
        }
        Ok(claims)
    }

    fn read_session_claim(
        &self,
        app_id: u32,
        client_id: u64,
    ) -> Result<Option<SessionClaim>, BackendError> {
        let path = self.session_claim_path(app_id, client_id)?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_bounded_file(&path, MAX_SESSION_RECORD_BYTES, "session claim")?;
        let claim = serde_json::from_slice::<SessionClaim>(&bytes)
            .map_err(|_| incomplete("local cloud session claim is incomplete"))?;
        validate_session_claim(app_id, &claim)?;
        if claim.client_id != client_id {
            return Err(permanent("local cloud session claim ClientID is invalid"));
        }
        Ok(Some(claim))
    }

    fn reconcile_session_overrides(
        &self,
        app_id: u32,
        live_claims: &HashSet<String>,
    ) -> Result<HashSet<String>, BackendError> {
        let overrides = self.read_session_overrides(app_id)?;
        self.reconcile_loaded_session_overrides(overrides, live_claims)
    }

    fn read_session_overrides(
        &self,
        app_id: u32,
    ) -> Result<Vec<(PathBuf, SessionOverride)>, BackendError> {
        let directory = self.session_dir(app_id)?.join("overrides");
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut overrides = Vec::new();
        let mut entries = 0usize;
        for entry in std::fs::read_dir(directory).map_err(io_error)? {
            entries += 1;
            if entries > MAX_SESSION_RECORDS {
                return Err(permanent("too many local cloud session overrides"));
            }
            let path = entry.map_err(io_error)?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = read_bounded_file(&path, MAX_SESSION_RECORD_BYTES, "session override")?;
            let record = serde_json::from_slice::<SessionOverride>(&bytes)
                .map_err(|_| incomplete("local cloud session override is incomplete"))?;
            validate_session_override(app_id, &record)?;
            if session_record_client_id(&path)? != record.client_id {
                return Err(permanent(
                    "local cloud session override ClientID is invalid",
                ));
            }
            overrides.push((path, record));
        }
        Ok(overrides)
    }

    fn reconcile_loaded_session_overrides(
        &self,
        overrides: Vec<(PathBuf, SessionOverride)>,
        live_claims: &HashSet<String>,
    ) -> Result<HashSet<String>, BackendError> {
        let mut superseded = HashSet::new();
        for (path, mut record) in overrides {
            let retained = record
                .superseded_claims
                .iter()
                .filter(|id| live_claims.contains(*id))
                .cloned()
                .collect::<Vec<_>>();
            if retained.is_empty() {
                remove_if_exists(&path)?;
                continue;
            }
            if retained != record.superseded_claims {
                record.superseded_claims = retained;
                self.write_session_override(&record)?;
            }
            superseded.extend(record.superseded_claims);
        }
        Ok(superseded)
    }

    fn write_session_claim(&self, claim: SessionClaim) -> Result<String, BackendError> {
        let path = self.session_claim_path(claim.app_id, claim.client_id)?;
        let bytes = serde_json::to_vec(&claim).map_err(json_error)?;
        if bytes.len() as u64 > MAX_SESSION_RECORD_BYTES {
            return Err(permanent("local cloud session claim is too large"));
        }
        atomic_replace(&path, &bytes)?;
        Ok(hex_digest::<Sha256>(&bytes))
    }

    fn write_session_override(&self, record: &SessionOverride) -> Result<(), BackendError> {
        let path = self.session_override_path(record.app_id, record.client_id)?;
        let bytes = serde_json::to_vec(record).map_err(json_error)?;
        if bytes.len() as u64 > MAX_SESSION_RECORD_BYTES {
            return Err(permanent("local cloud session override is too large"));
        }
        atomic_replace(&path, &bytes)
    }

    fn initialize(&self) -> Result<(), BackendError> {
        let format_path = self.root.join(FORMAT_FILE);
        if format_path.exists() {
            let bytes = read_bounded_file(&format_path, MAX_FORMAT_BYTES, "repository format")?;
            let format: Format = serde_json::from_slice(&bytes).map_err(json_error)?;
            if format.version != FORMAT_VERSION {
                return Err(permanent("unsupported local cloud repository format"));
            }
        } else {
            let bytes = serde_json::to_vec_pretty(&Format {
                version: FORMAT_VERSION,
            })
            .map_err(json_error)?;
            atomic_publish(&format_path, &bytes)?;
        }
        Ok(())
    }

    fn app_dir(&self, app_id: u32) -> PathBuf {
        let mut directory = self.root.clone();
        if let Some(account) = &self.account {
            directory.push(account);
        }
        directory.join(app_id.to_string())
    }

    pub fn manifest_scope(&self, app_id: u32) -> String {
        match &self.account {
            Some(account) => format!("{account}/{app_id}"),
            None => app_id.to_string(),
        }
    }

    fn session_dir(&self, app_id: u32) -> Result<PathBuf, BackendError> {
        if self.account.is_none() {
            return Err(permanent("local cloud session requires an account"));
        }
        Ok(self.app_dir(app_id).join("sessions"))
    }

    fn session_claim_path(&self, app_id: u32, client_id: u64) -> Result<PathBuf, BackendError> {
        if client_id == 0 {
            return Err(permanent("local cloud session ClientID is unavailable"));
        }
        Ok(self
            .session_dir(app_id)?
            .join("claims")
            .join(format!("{client_id}.json")))
    }

    fn session_override_path(&self, app_id: u32, client_id: u64) -> Result<PathBuf, BackendError> {
        if client_id == 0 {
            return Err(permanent("local cloud session ClientID is unavailable"));
        }
        Ok(self
            .session_dir(app_id)?
            .join("overrides")
            .join(format!("{client_id}.json")))
    }

    fn lock_app(&self, app_id: u32) -> Result<MutexGuard<'_, ()>, BackendError> {
        validate_app_id(app_id)?;
        Ok(self
            .coordination
            .lock
            .lock()
            .unwrap_or_else(|error| error.into_inner()))
    }

    fn manifest_account(&self) -> Result<&str, BackendError> {
        self.account
            .as_deref()
            .ok_or_else(|| permanent("local cloud save store requires an account"))
    }

    fn manifest_dir(&self, app_id: u32, id: &str) -> Result<PathBuf, BackendError> {
        validate_app_id(app_id)?;
        validate_manifest_id(id)?;
        Ok(self.app_dir(app_id).join(id))
    }

    fn manifest_blob_path(
        &self,
        app_id: u32,
        manifest_id: &str,
        hash: &str,
    ) -> Result<PathBuf, BackendError> {
        validate_blob_hash(hash)?;
        Ok(self
            .manifest_dir(app_id, manifest_id)?
            .join("blobs")
            .join(hash))
    }

    fn validate_operation(&self, operation: &SaveOperation) -> Result<(), BackendError> {
        if operation.inner.repository != self.root
            || operation.inner.manifest_scope != self.manifest_scope(operation.inner.app_id)
            || !Arc::ptr_eq(&operation.inner.coordination, &self.coordination)
        {
            return Err(permanent("local cloud operation belongs to another store"));
        }
        Ok(())
    }

    fn resolve_app(&self, app_id: u32) -> Result<ResolvedApp, BackendError> {
        validate_app_id(app_id)?;
        let manifests = self
            .collect_manifest_objects(app_id)?
            .into_iter()
            .collect::<HashMap<_, _>>();

        let parents = manifests
            .values()
            .flat_map(|manifest| manifest.parents.iter().cloned())
            .collect::<HashSet<_>>();
        let mut heads = manifests
            .keys()
            .filter(|id| !parents.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        heads.sort();
        let max_revision = manifests
            .values()
            .map(|manifest| manifest.revision)
            .max()
            .unwrap_or(0);
        Ok(ResolvedApp {
            manifests,
            heads,
            max_revision,
        })
    }

    fn verify_files(
        &self,
        app_id: u32,
        manifest_id: &str,
        files: &BTreeMap<String, StoredFile>,
    ) -> Result<(), BackendError> {
        for (path, file) in files {
            validate_cloud_path(path)?;
            verify_blob_file(
                &self.manifest_blob_path(app_id, manifest_id, &file.sha1)?,
                file,
            )?;
        }
        Ok(())
    }

    fn verify_operation_files(
        &self,
        operation: &SaveOperation,
        files: &BTreeMap<String, StoredFile>,
    ) -> Result<(), BackendError> {
        for (path, file) in files {
            validate_cloud_path(path)?;
            verify_blob_file(
                &operation_blob_path(&operation.inner.path, &file.sha1)?,
                file,
            )?;
        }
        Ok(())
    }

    fn prune_operation_blobs(
        &self,
        operation: &SaveOperation,
        files: &BTreeMap<String, StoredFile>,
    ) -> Result<(), BackendError> {
        let retained = files
            .values()
            .map(|file| file.sha1.as_str())
            .collect::<HashSet<_>>();
        let directory = operation.inner.path.join("blobs");
        for entry in std::fs::read_dir(&directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry
                .file_name()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| permanent("local cloud blob name is not UTF-8"))?;
            if !entry.file_type().map_err(io_error)?.is_file() || validate_blob_hash(&name).is_err()
            {
                return Err(permanent("invalid local cloud operation blob"));
            }
            if !retained.contains(name.as_str()) {
                remove_if_exists(&entry.path())?;
            }
        }
        Ok(())
    }

    fn collect_manifest_objects(
        &self,
        app_id: u32,
    ) -> Result<BTreeMap<String, SaveManifest>, BackendError> {
        collect_manifest_objects(&self.app_dir(app_id), self.manifest_account()?, app_id)
    }

    fn move_manifest_to_trash(
        &self,
        app_id: u32,
        id: &str,
    ) -> Result<Option<PathBuf>, BackendError> {
        let source = self.manifest_dir(app_id, id)?;
        if !source.exists() {
            return Ok(None);
        }
        let trash = self
            .coordination
            .work_root
            .join(format!("gc-{}", next_nonce()));
        std::fs::rename(&source, &trash).map_err(io_error)?;
        sync_directory(&self.app_dir(app_id))?;
        sync_directory(&self.coordination.work_root)?;
        Ok(Some(trash))
    }

    fn current_manifest(
        &self,
        app_id: u32,
    ) -> Result<Option<(String, SaveManifest)>, BackendError> {
        let resolved = self.resolve_app(app_id)?;
        Ok(resolved
            .current()?
            .map(|(id, manifest)| (id.to_owned(), manifest.clone())))
    }

    pub(crate) fn bind_download(
        &self,
        app_id: u32,
        path: &str,
    ) -> Result<(FileEntry, BoundDownload), BackendError> {
        validate_cloud_path(path)?;
        let _lock = self.lock_app(app_id)?;
        let (id, manifest) = self
            .current_manifest(app_id)?
            .ok_or_else(|| permanent("local cloud file not found"))?;
        let file = manifest
            .files
            .get(path)
            .ok_or_else(|| permanent(format!("local cloud file not found: {path}")))?;
        let blob_path = self.manifest_blob_path(app_id, &id, &file.sha1)?;
        let file_handle = open_blob_file(&blob_path, file)?;
        let metadata = FileMetadata {
            sha1: file.sha1.clone(),
            raw_size: file.raw_size,
            mtime: file.mtime,
            platforms_to_sync: file.platforms_to_sync,
        };
        Ok((
            FileEntry {
                path: path.to_owned(),
                metadata: metadata.clone(),
                change_number: manifest.revision,
            },
            BoundDownload {
                file: file_handle,
                metadata,
            },
        ))
    }
}

fn repository_coordination(root: &Path) -> Result<Arc<RepositoryCoordination>, BackendError> {
    let coordinators = REPOSITORY_COORDINATORS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut coordinators = coordinators
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(coordination) = coordinators.get(root).and_then(Weak::upgrade) {
        return Ok(coordination);
    }
    coordinators.retain(|_, coordination| coordination.strong_count() != 0);
    let parent = root
        .parent()
        .ok_or_else(|| permanent("local cloud repository has no parent directory"))?;
    let root_hash = hex_digest::<Sha256>(root.to_string_lossy().as_bytes());
    let work_root = parent.join(format!(".vapor-local-{}.work", &root_hash[..16]));
    create_durable_dir_all(&work_root)?;
    ensure_same_filesystem(root, &work_root)?;
    clear_work_root(&work_root)?;
    let coordination = Arc::new(RepositoryCoordination {
        root: root.to_owned(),
        lock: Mutex::new(()),
        work_root,
    });
    coordinators.insert(root.to_owned(), Arc::downgrade(&coordination));
    Ok(coordination)
}

impl ByteStore for FolderStore {
    fn read(&self, app_id: u32, path: &str) -> Result<Vec<u8>, BackendError> {
        self.bind_download(app_id, path)?.1.read()
    }

    fn write(
        &self,
        app_id: u32,
        path: &str,
        contents: &[u8],
        metadata: &FileMetadata,
    ) -> Result<u64, BackendError> {
        let view = self.view(app_id)?;
        let identity = current_identity()?;
        let operation = self.begin_operation(app_id, &view.head_ids(), None)?;
        let staged = self.stage_file(&operation, path, contents, metadata)?;
        self.commit_operation(&operation, &[staged], &BTreeSet::new(), &identity)
    }
}

impl CloudFileStore for FolderStore {
    fn changes_since(&self, app_id: u32, since: u64) -> Result<ChangeList, BackendError> {
        let _lock = self.lock_app(app_id)?;
        let resolved = self.resolve_app(app_id)?;
        let current = resolved.current()?;
        change_list_from_manifest(current.map(|(_, manifest)| manifest), since, false)
    }

    fn delete(&self, app_id: u32, path: &str) -> Result<u64, BackendError> {
        validate_cloud_path(path)?;
        let view = self.view(app_id)?;
        let identity = current_identity()?;
        let operation = self.begin_operation(app_id, &view.head_ids(), None)?;
        self.commit_operation(
            &operation,
            &[],
            &BTreeSet::from([path.to_owned()]),
            &identity,
        )
    }

    fn quota(&self, app_id: u32) -> Result<Quota, BackendError> {
        let _lock = self.lock_app(app_id)?;
        let resolved = self.resolve_app(app_id)?;
        let files = resolved.current()?.map(|(_, manifest)| &manifest.files);
        let used_bytes = files
            .into_iter()
            .flat_map(|files| files.values())
            .try_fold(0u64, |total, file| total.checked_add(file.raw_size))
            .ok_or_else(|| permanent("local cloud quota overflow"))?;
        let used_files = files.map_or(0, BTreeMap::len);
        Ok(Quota {
            used_bytes,
            total_bytes: i64::MAX as u64,
            used_files: u32::try_from(used_files)
                .map_err(|_| permanent("local cloud file count overflow"))?,
            total_files: u32::MAX,
        })
    }

    fn transfer(&self) -> Transfer<'_> {
        Transfer::Bridged(self)
    }
}

fn change_list_from_manifest(
    manifest: Option<&SaveManifest>,
    since: u64,
    force_full: bool,
) -> Result<ChangeList, BackendError> {
    let current_revision = manifest.map_or(0, |manifest| manifest.revision);
    if since > current_revision {
        return Err(conflict(
            "Steam change number is newer than the local manifest view",
        ));
    }
    if since == current_revision && !force_full {
        return Ok(ChangeList {
            current_change_number: current_revision,
            files: Vec::new(),
            deleted_paths: Vec::new(),
            is_delta: true,
        });
    }
    let files = manifest
        .into_iter()
        .flat_map(|manifest| manifest.files.iter())
        .map(|(path, file)| FileEntry {
            path: path.clone(),
            metadata: FileMetadata {
                sha1: file.sha1.clone(),
                raw_size: file.raw_size,
                mtime: file.mtime,
                platforms_to_sync: file.platforms_to_sync,
            },
            change_number: current_revision,
        })
        .collect();
    Ok(ChangeList {
        current_change_number: current_revision,
        files,
        deleted_paths: Vec::new(),
        is_delta: false,
    })
}

fn validate_app_id(app_id: u32) -> Result<(), BackendError> {
    if app_id == 0 {
        return Err(permanent(
            "local cloud does not support account-scope AppID 0",
        ));
    }
    Ok(())
}

fn validate_identity(identity: &CommitIdentity) -> Result<(), BackendError> {
    if identity.client_id == 0 {
        return Err(permanent("local cloud Steam ClientID is unavailable"));
    }
    let machine_name = identity.machine_name.trim();
    if machine_name.is_empty() || machine_name.len() > 255 || machine_name.contains('\0') {
        return Err(permanent("invalid local cloud machine name"));
    }
    Ok(())
}

fn validate_manifest(
    id: &str,
    steam_id64: &str,
    app_id: u32,
    manifest: &SaveManifest,
) -> Result<(), BackendError> {
    if manifest.steam_id64 != steam_id64
        || manifest.app_id != app_id
        || manifest.revision == 0
        || manifest.files.len() > MAX_MANIFEST_FILES
        || manifest.parents.len() > MAX_MANIFEST_PARENTS
    {
        return Err(permanent("invalid local cloud manifest"));
    }
    validate_identity(&CommitIdentity {
        client_id: manifest.client_id,
        machine_name: manifest.machine_name.clone(),
    })?;
    let parents = normalized_head_ids(&manifest.parents)?;
    if parents != manifest.parents || parents.iter().any(|parent| parent == id) {
        return Err(permanent("invalid local cloud manifest parents"));
    }
    let mut blob_sizes = HashMap::<&str, u64>::new();
    for (path, file) in &manifest.files {
        validate_cloud_path(path)?;
        if file.sha1.len() != 40
            || !file.sha1.bytes().all(|byte| byte.is_ascii_hexdigit())
            || file.sha1 != file.sha1.to_ascii_lowercase()
            || file.raw_size > MAX_SAVE_FILE_BYTES
            || file.mtime < 0
        {
            return Err(permanent("invalid local cloud manifest file"));
        }
        if blob_sizes
            .insert(file.sha1.as_str(), file.raw_size)
            .is_some_and(|size| size != file.raw_size)
        {
            return Err(permanent("inconsistent local cloud blob metadata"));
        }
    }
    Ok(())
}

fn validate_session_claim(app_id: u32, claim: &SessionClaim) -> Result<(), BackendError> {
    if claim.app_id != app_id || claim.nonce.is_empty() || claim.updated_at == 0 {
        return Err(permanent("invalid local cloud session claim"));
    }
    validate_identity(&CommitIdentity {
        client_id: claim.client_id,
        machine_name: claim.machine_name.clone(),
    })?;
    if normalized_head_ids(&claim.observed_heads)? != claim.observed_heads {
        return Err(permanent("invalid local cloud session heads"));
    }
    Ok(())
}

fn validate_session_override(app_id: u32, record: &SessionOverride) -> Result<(), BackendError> {
    if record.app_id != app_id
        || record.client_id == 0
        || normalized_head_ids(&record.superseded_claims)? != record.superseded_claims
    {
        return Err(permanent("invalid local cloud session override"));
    }
    Ok(())
}

fn live_claim_ids(claims: &[(String, SessionClaim)]) -> HashSet<String> {
    claims.iter().map(|(id, _)| id.clone()).collect()
}

fn superseded_live_claims(
    overrides: &[(PathBuf, SessionOverride)],
    live_claims: &HashSet<String>,
) -> HashSet<String> {
    overrides
        .iter()
        .flat_map(|(_, record)| record.superseded_claims.iter())
        .filter(|id| live_claims.contains(*id))
        .cloned()
        .collect()
}

fn session_record_client_id(path: &Path) -> Result<u64, BackendError> {
    let client_id = path
        .file_stem()
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| permanent("invalid local cloud session record name"))?;
    Ok(client_id)
}

fn normalized_head_ids(ids: &[String]) -> Result<Vec<String>, BackendError> {
    let mut normalized = ids.to_vec();
    for id in &normalized {
        if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(permanent("invalid local cloud manifest id"));
        }
    }
    normalized.sort();
    normalized.dedup();
    if normalized.len() != ids.len() {
        return Err(permanent("duplicate local cloud manifest id"));
    }
    Ok(normalized)
}

fn validate_manifest_id(id: &str) -> Result<(), BackendError> {
    if id.len() != 64
        || id != id.to_ascii_lowercase()
        || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(permanent("invalid local cloud manifest id"));
    }
    Ok(())
}

fn current_identity() -> Result<CommitIdentity, BackendError> {
    let descriptor = vapor_forge_cloud_core::device_descriptor()
        .ok_or_else(|| permanent("local cloud device identity is unavailable"))?;
    let identity = CommitIdentity {
        client_id: descriptor.client_id,
        machine_name: descriptor.machine_name,
    };
    validate_identity(&identity)?;
    Ok(identity)
}

fn validate_cloud_path(path: &str) -> Result<(), BackendError> {
    if path.is_empty()
        || path.len() > MAX_CLOUD_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\0')
        || path.contains('\\')
    {
        return Err(permanent("invalid local cloud path"));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(permanent("invalid local cloud path component"));
    }
    Ok(())
}

fn validate_metadata(contents: &[u8], metadata: &FileMetadata) -> Result<(), BackendError> {
    if metadata.raw_size > MAX_SAVE_FILE_BYTES {
        return Err(permanent("local cloud file exceeds the supported size"));
    }
    if contents.len() as u64 != metadata.raw_size {
        return Err(permanent("local cloud raw size does not match contents"));
    }
    if metadata.sha1.len() != 40 || !metadata.sha1.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(permanent("local cloud SHA-1 is invalid"));
    }
    if hex_digest::<Sha1>(contents) != metadata.sha1.to_ascii_lowercase() {
        return Err(permanent("local cloud SHA-1 does not match contents"));
    }
    Ok(())
}

pub(crate) fn atomic_publish(path: &Path, bytes: &[u8]) -> Result<(), BackendError> {
    if path.exists() {
        return file_matches_bytes(path, bytes)
            .map_err(io_error)?
            .then_some(())
            .ok_or_else(|| permanent("immutable local cloud object already has different bytes"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| permanent("local cloud object has no parent directory"))?;
    create_durable_dir_all(parent)?;
    let temporary = parent.join(format!(".syncthing.{}.tmp", next_nonce()));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary).map_err(io_error)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(io_error(error));
    }
    drop(file);
    match std::fs::hard_link(&temporary, path) {
        Ok(()) => {
            std::fs::remove_file(&temporary).map_err(io_error)?;
            sync_directory(parent)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&temporary);
            if file_matches_bytes(path, bytes).map_err(io_error)? {
                sync_directory(parent)?;
                Ok(())
            } else {
                Err(permanent("immutable local cloud object collision"))
            }
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(io_error(error))
        }
    }
}

pub(crate) fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), BackendError> {
    match file_matches_bytes(path, bytes) {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(error)),
    }
    let parent = path
        .parent()
        .ok_or_else(|| permanent("local cloud object has no parent directory"))?;
    create_durable_dir_all(parent)?;
    let temporary = parent.join(format!(".syncthing.{}.tmp", next_nonce()));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary).map_err(io_error)?;
    let write_result = file.write_all(bytes).and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temporary);
        return Err(io_error(error));
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(io_error(error));
    }
    sync_directory(parent)?;
    Ok(())
}

fn file_matches_bytes(path: &Path, expected: &[u8]) -> std::io::Result<bool> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() != expected.len() as u64 {
        return Ok(false);
    }
    let mut file = std::fs::File::open(path)?;
    let mut offset = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    while offset < expected.len() {
        let read = file.read(&mut buffer)?;
        if read == 0 || expected[offset..].get(..read) != Some(&buffer[..read]) {
            return Ok(false);
        }
        offset += read;
    }
    Ok(file.read(&mut buffer[..1])? == 0)
}

fn read_bounded_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, BackendError> {
    let metadata = std::fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(permanent(format!("invalid local cloud {label} file")));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| permanent(format!("local cloud {label} file is too large")))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| permanent(format!("local cloud {label} file is too large")))?;
    std::fs::File::open(path)
        .map_err(io_error)?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > maximum {
        return Err(permanent(format!("invalid local cloud {label} file")));
    }
    Ok(bytes)
}

fn create_durable_dir_all(path: &Path) -> Result<(), BackendError> {
    let mut missing = Vec::new();
    let mut current = path;
    while !current.exists() {
        missing.push(current.to_path_buf());
        current = current
            .parent()
            .ok_or_else(|| permanent("local cloud directory has no existing parent"))?;
    }
    if !current.is_dir() {
        return Err(permanent("local cloud path parent is not a directory"));
    }
    for directory in missing.into_iter().rev() {
        match std::fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !directory.is_dir() {
                    return Err(io_error(error));
                }
            }
            Err(error) => return Err(io_error(error)),
        }
        set_private_directory_mode(&directory)?;
        if let Some(parent) = directory.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_mode(path: &Path) -> Result<(), BackendError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(io_error)
}

#[cfg(not(unix))]
fn set_private_directory_mode(_path: &Path) -> Result<(), BackendError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), BackendError> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), BackendError> {
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), BackendError> {
    match std::fs::remove_file(path) {
        Ok(()) => path.parent().map_or(Ok(()), sync_directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn collect_manifest_objects(
    app_directory: &Path,
    steam_id64: &str,
    app_id: u32,
) -> Result<BTreeMap<String, SaveManifest>, BackendError> {
    if !app_directory.exists() {
        return Ok(BTreeMap::new());
    }
    let mut manifests = BTreeMap::new();
    for entry in std::fs::read_dir(app_directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let file_type = entry.file_type().map_err(io_error)?;
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| incomplete("local cloud manifest name is not UTF-8"))?;
        if is_non_manifest_app_entry(name) {
            continue;
        }
        if manifests.len() >= MAX_MANIFEST_OBJECTS {
            return Err(permanent("too many local cloud manifests"));
        }
        if !file_type.is_dir() || validate_manifest_id(name).is_err() {
            return Err(incomplete("local cloud manifest namespace is incomplete"));
        }
        validate_manifest_directory(&path)?;
        let bytes = read_bounded_file(&path.join("manifest.json"), MAX_MANIFEST_BYTES, "manifest")?;
        if hex_digest::<Sha256>(&bytes) != name {
            return Err(incomplete("local cloud manifest identity is invalid"));
        }
        let manifest = serde_json::from_slice::<SaveManifest>(&bytes)
            .map_err(|_| incomplete("local cloud manifest is incomplete"))?;
        validate_manifest(name, steam_id64, app_id, &manifest)?;
        validate_manifest_blobs(&path.join("blobs"), &manifest.files)?;
        if manifests.insert(name.to_owned(), manifest).is_some() {
            return Err(permanent("duplicate local cloud manifest identity"));
        }
    }
    Ok(manifests)
}

fn collect_manifest_paths(app_directory: &Path) -> Result<BTreeSet<String>, BackendError> {
    if !app_directory.exists() {
        return Ok(BTreeSet::new());
    }
    let mut paths = BTreeSet::new();
    for entry in std::fs::read_dir(app_directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let file_type = entry.file_type().map_err(io_error)?;
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| incomplete("local cloud manifest name is not UTF-8"))?;
        if is_non_manifest_app_entry(name) {
            continue;
        }
        if paths.len() >= MAX_MANIFEST_OBJECTS {
            return Err(permanent("too many local cloud manifests"));
        }
        if !file_type.is_dir() || validate_manifest_id(name).is_err() {
            return Err(incomplete("local cloud manifest namespace is incomplete"));
        }
        if !paths.insert(name.to_owned()) {
            return Err(permanent("duplicate local cloud manifest identity"));
        }
    }
    Ok(paths)
}

fn unique_items(items: &[String]) -> Result<BTreeSet<String>, BackendError> {
    let unique = items.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() != items.len() {
        return Err(permanent("invalid local cloud GC report"));
    }
    Ok(unique)
}

fn is_non_manifest_app_entry(name: &str) -> bool {
    matches!(name, "sessions" | "stats" | "playtime")
}

fn validate_manifest_directory(path: &Path) -> Result<(), BackendError> {
    let mut count = 0usize;
    let mut has_manifest = false;
    let mut has_blobs = false;
    for entry in std::fs::read_dir(path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry
            .file_name()
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| incomplete("local cloud manifest entry is not UTF-8"))?;
        let kind = entry.file_type().map_err(io_error)?;
        count += 1;
        if count > 2 {
            return Err(incomplete("local cloud manifest directory is incomplete"));
        }
        has_manifest |= name == "manifest.json" && kind.is_file();
        has_blobs |= name == "blobs" && kind.is_dir();
    }
    if count != 2 || !has_manifest || !has_blobs {
        return Err(incomplete("local cloud manifest directory is incomplete"));
    }
    Ok(())
}

fn validate_manifest_blobs(
    directory: &Path,
    files: &BTreeMap<String, StoredFile>,
) -> Result<(), BackendError> {
    let expected = files
        .values()
        .map(|file| (file.sha1.clone(), file.raw_size))
        .collect::<BTreeMap<_, _>>();
    let mut actual = BTreeSet::new();
    for entry in std::fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if !entry.file_type().map_err(io_error)?.is_file() {
            return Err(incomplete("local cloud manifest blob set is incomplete"));
        }
        let name = entry
            .file_name()
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| incomplete("local cloud blob name is not UTF-8"))?;
        if name.len() != 40
            || name != name.to_ascii_lowercase()
            || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(incomplete("invalid local cloud blob name"));
        }
        let Some(expected_size) = expected.get(&name) else {
            return Err(incomplete("local cloud manifest blob set is incomplete"));
        };
        if entry.metadata().map_err(io_error)?.len() != *expected_size {
            return Err(incomplete("local cloud manifest blob set is incomplete"));
        }
        actual.insert(name);
    }
    if actual != expected.keys().cloned().collect() {
        return Err(incomplete("local cloud manifest blob set is incomplete"));
    }
    Ok(())
}

fn operation_blob_path(operation: &Path, hash: &str) -> Result<PathBuf, BackendError> {
    validate_blob_hash(hash)?;
    Ok(operation.join("blobs").join(hash))
}

fn validate_blob_hash(hash: &str) -> Result<(), BackendError> {
    if hash.len() != 40
        || hash != hash.to_ascii_lowercase()
        || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(permanent("invalid local cloud blob hash"));
    }
    Ok(())
}

fn verify_blob_bytes(file: &StoredFile, bytes: &[u8]) -> Result<(), BackendError> {
    if bytes.len() as u64 != file.raw_size || hex_digest::<Sha1>(bytes) != file.sha1 {
        return Err(permanent("local cloud blob failed integrity verification"));
    }
    Ok(())
}

fn stored_file_from_metadata(metadata: &FileMetadata) -> StoredFile {
    StoredFile {
        sha1: metadata.sha1.clone(),
        raw_size: metadata.raw_size,
        mtime: metadata.mtime,
        platforms_to_sync: metadata.platforms_to_sync,
    }
}

fn open_blob_file(path: &Path, expected: &StoredFile) -> Result<std::fs::File, BackendError> {
    if expected.raw_size > MAX_SAVE_FILE_BYTES {
        return Err(permanent("local cloud file exceeds the supported size"));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.len() != expected.raw_size {
        return Err(permanent("local cloud blob failed integrity verification"));
    }
    std::fs::File::open(path).map_err(io_error)
}

fn verify_blob_file(path: &Path, expected: &StoredFile) -> Result<(), BackendError> {
    let mut file = open_blob_file(path, expected)?;
    let mut digest = Sha1::default();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        sha1::Digest::update(&mut digest, &buffer[..read]);
    }
    if format!("{:x}", sha1::Digest::finalize(digest)) != expected.sha1 {
        return Err(permanent("local cloud blob failed integrity verification"));
    }
    Ok(())
}

fn link_or_copy(source: &Path, target: &Path) -> Result<(), BackendError> {
    if target.exists() {
        return Ok(());
    }
    match std::fs::hard_link(source, target) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(source, target).map_err(io_error)?;
            std::fs::File::open(target)
                .and_then(|file| file.sync_all())
                .map_err(io_error)
        }
    }
}

fn remove_dir_all_if_exists(path: &Path) -> Result<(), BackendError> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn clear_work_root(path: &Path) -> Result<(), BackendError> {
    for entry in std::fs::read_dir(path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let entry_path = entry.path();
        let kind = entry.file_type().map_err(io_error)?;
        if kind.is_dir() {
            remove_dir_all_if_exists(&entry_path)?;
        } else {
            remove_if_exists(&entry_path)?;
        }
    }
    sync_directory(path)
}

#[cfg(unix)]
fn ensure_same_filesystem(left: &Path, right: &Path) -> Result<(), BackendError> {
    use std::os::unix::fs::MetadataExt;

    if std::fs::metadata(left).map_err(io_error)?.dev()
        != std::fs::metadata(right).map_err(io_error)?.dev()
    {
        return Err(permanent(
            "local cloud private work directory must share the repository filesystem",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_filesystem(_left: &Path, _right: &Path) -> Result<(), BackendError> {
    Ok(())
}

fn hex_digest<D: sha1::Digest + Default>(bytes: &[u8]) -> String {
    D::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn unix_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(u32::MAX)
}

fn next_nonce() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!(
        "{:x}-{:x}-{:x}",
        std::process::id(),
        unix_millis(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn io_error(error: std::io::Error) -> BackendError {
    BackendError::new(format!("local cloud I/O failed: {error}"), true)
}

fn json_error(error: serde_json::Error) -> BackendError {
    BackendError::new(format!("local cloud metadata failed: {error}"), false)
}

fn permanent(message: impl Into<String>) -> BackendError {
    BackendError::new(message, false)
}

fn incomplete(message: impl Into<String>) -> BackendError {
    BackendError::new(message, true)
}

fn conflict(message: impl Into<String>) -> BackendError {
    BackendError::new(message, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ACCOUNT: u64 = 76_561_198_000_000_001;

    fn metadata(contents: &[u8], mtime: i64) -> FileMetadata {
        FileMetadata {
            sha1: hex_digest::<Sha1>(contents),
            raw_size: contents.len() as u64,
            mtime,
            platforms_to_sync: u32::MAX,
        }
    }

    fn identity(client_id: u64, machine_name: &str) -> CommitIdentity {
        CommitIdentity {
            client_id,
            machine_name: machine_name.into(),
        }
    }

    fn stored_file(staged: StagedFile) -> StoredFile {
        StoredFile {
            sha1: staged.blob_sha1,
            raw_size: staged.metadata.raw_size,
            mtime: staged.metadata.mtime,
            platforms_to_sync: staged.metadata.platforms_to_sync,
        }
    }

    fn stage_detached(
        store: &FolderStore,
        path: &str,
        contents: &[u8],
        metadata: &FileMetadata,
    ) -> StagedFile {
        validate_cloud_path(path).unwrap();
        validate_metadata(contents, metadata).unwrap();
        let blob_sha1 = metadata.sha1.to_ascii_lowercase();
        let cache = store.coordination.work_root.join("test-blobs");
        create_durable_dir_all(&cache).unwrap();
        atomic_publish(&cache.join(&blob_sha1), contents).unwrap();
        StagedFile {
            path: path.to_owned(),
            blob_sha1,
            metadata: metadata.clone(),
        }
    }

    fn publish_manifest(
        store: &FolderStore,
        app_id: u32,
        revision: u64,
        parents: Vec<String>,
        identity: &CommitIdentity,
        created_at_ms: u64,
        files: BTreeMap<String, StoredFile>,
    ) -> String {
        let manifest = SaveManifest {
            steam_id64: store.manifest_account().unwrap().to_owned(),
            app_id,
            revision,
            parents,
            client_id: identity.client_id,
            machine_name: identity.machine_name.clone(),
            created_at_ms,
            files,
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let id = hex_digest::<Sha256>(&bytes);
        let existing = store.resolve_app(app_id).unwrap();
        let sources = manifest
            .files
            .values()
            .map(|file| {
                existing
                    .manifests
                    .keys()
                    .find_map(|candidate| {
                        let path = store
                            .manifest_blob_path(app_id, candidate, &file.sha1)
                            .unwrap();
                        path.exists().then_some(path)
                    })
                    .unwrap_or_else(|| {
                        store
                            .coordination
                            .work_root
                            .join("test-blobs")
                            .join(&file.sha1)
                    })
            })
            .collect::<Vec<_>>();
        let directory = store.manifest_dir(app_id, &id).unwrap();
        create_durable_dir_all(&directory.join("blobs")).unwrap();
        for (file, source) in manifest.files.values().zip(sources) {
            link_or_copy(&source, &directory.join("blobs").join(&file.sha1)).unwrap();
        }
        atomic_publish(&directory.join("manifest.json"), &bytes).unwrap();
        id
    }

    fn commit_file(
        store: &FolderStore,
        app_id: u32,
        path: &str,
        contents: &[u8],
        mtime: i64,
        identity: &CommitIdentity,
    ) -> u64 {
        let view = store.view(app_id).unwrap();
        let operation = store
            .begin_operation(app_id, &view.head_ids(), None)
            .unwrap();
        let staged = store
            .stage_file(&operation, path, contents, &metadata(contents, mtime))
            .unwrap();
        store
            .commit_operation(&operation, &[staged], &BTreeSet::new(), identity)
            .unwrap()
    }

    #[test]
    fn replacing_identical_bytes_keeps_the_existing_file() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("state.json");
        let link = temporary.path().join("state-link.json");
        atomic_replace(&path, b"same").unwrap();
        std::fs::hard_link(&path, &link).unwrap();

        atomic_replace(&path, b"same").unwrap();
        std::fs::write(&link, b"changed through link").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"changed through link");
    }

    #[cfg(unix)]
    #[test]
    fn published_objects_and_created_directories_use_private_modes() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("cloud/account/app/manifests");
        let path = parent.join("object.json");
        atomic_publish(&path, b"private").unwrap();

        for component in [
            directory.path().join("cloud"),
            directory.path().join("cloud/account"),
            directory.path().join("cloud/account/app"),
            parent,
        ] {
            assert_eq!(
                std::fs::metadata(component).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fn divergent_heads(store: &FolderStore) -> (String, String) {
        let root_identity = identity(1, "root");
        commit_file(store, 480, "save.dat", b"root", 1, &root_identity);
        let resolved = store.resolve_app(480).unwrap();
        let parent = resolved.heads[0].clone();
        let base_files = resolved.manifests[&parent].files.clone();

        let left_identity = identity(7, "deck");
        let mut left_files = base_files.clone();
        left_files.insert(
            "save.dat".into(),
            stored_file(stage_detached(
                store,
                "save.dat",
                b"left",
                &metadata(b"left", 2),
            )),
        );
        let left = publish_manifest(
            store,
            480,
            2,
            vec![parent.clone()],
            &left_identity,
            2_000,
            left_files,
        );

        let right_identity = identity(8, "desktop");
        let mut right_files = base_files;
        right_files.insert(
            "save.dat".into(),
            stored_file(stage_detached(
                store,
                "save.dat",
                b"right",
                &metadata(b"right", 3),
            )),
        );
        let right = publish_manifest(
            store,
            480,
            2,
            vec![parent],
            &right_identity,
            3_000,
            right_files,
        );
        (left, right)
    }

    #[test]
    fn work_root_is_removed_with_the_last_store() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let other = store.clone();
        let work_root = store.coordination.work_root.clone();
        create_durable_dir_all(&work_root.join("orphan")).unwrap();

        drop(store);
        assert!(work_root.exists());

        drop(other);
        assert!(!work_root.exists());
    }

    #[test]
    fn immutable_manifests_survive_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let contents = b"local save";
        let identity = identity(7, "deck");
        assert_eq!(
            commit_file(&store, 480, "Game/save.dat", contents, 10, &identity),
            1
        );
        assert!(!temporary.path().join("manifests").exists());
        assert_eq!(
            FolderStore::open_account(temporary.path(), TEST_ACCOUNT)
                .unwrap()
                .read(480, "Game/save.dat")
                .unwrap(),
            contents
        );
    }

    #[test]
    fn manifest_id_hashes_json_without_nonce() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        commit_file(&store, 480, "save.dat", b"save", 1, &identity(7, "deck"));
        let manifest_id = store.view(480).unwrap().head_ids().remove(0);
        let path = store
            .manifest_dir(480, &manifest_id)
            .unwrap()
            .join("manifest.json");
        let path = std::fs::canonicalize(path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let value = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        assert!(value.get("nonce").is_none());
        assert_eq!(
            path.parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            hex_digest::<Sha256>(&bytes)
        );
    }

    #[test]
    fn batch_publishes_one_commit_for_uploads_and_deletes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let identity = identity(7, "deck");
        commit_file(&store, 480, "old.dat", b"old", 1, &identity);
        let view = store.view(480).unwrap();
        let operation = store.begin_operation(480, &view.head_ids(), None).unwrap();
        let staged = store
            .stage_file(&operation, "new.dat", b"new", &metadata(b"new", 2))
            .unwrap();
        assert_eq!(
            store
                .commit_operation(
                    &operation,
                    &[staged],
                    &BTreeSet::from(["old.dat".into()]),
                    &identity,
                )
                .unwrap(),
            2
        );
        let changes = store.changes_since(480, 1).unwrap();
        assert!(!changes.is_delta);
        assert_eq!(changes.files[0].path, "new.dat");
        assert!(store.read(480, "old.dat").is_err());
    }

    #[test]
    fn a_new_manifest_owns_unchanged_blobs() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        commit_file(&store, 480, "a.dat", b"a1", 1, &owner);
        commit_file(&store, 480, "b.dat", b"b1", 1, &owner);
        commit_file(&store, 480, "a.dat", b"a2", 2, &owner);

        let head = store.view(480).unwrap().head_ids().remove(0);
        let manifest = &store.resolve_app(480).unwrap().manifests[&head];
        assert_eq!(manifest.files.len(), 2);
        for file in manifest.files.values() {
            assert!(store
                .manifest_blob_path(480, &head, &file.sha1)
                .unwrap()
                .is_file());
        }
        assert_eq!(store.read(480, "a.dat").unwrap(), b"a2");
        assert_eq!(store.read(480, "b.dat").unwrap(), b"b1");
    }

    #[test]
    fn stale_batch_cannot_cover_a_new_head() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let base = store.view(480).unwrap();
        let operation = store.begin_operation(480, &base.head_ids(), None).unwrap();
        let identity = identity(7, "deck");
        commit_file(&store, 480, "a", b"a", 1, &identity);
        let staged = store
            .stage_file(&operation, "b", b"b", &metadata(b"b", 2))
            .unwrap();
        assert!(store
            .commit_operation(&operation, &[staged], &BTreeSet::new(), &identity)
            .is_err());
    }

    #[test]
    fn blobs_are_addressed_by_the_sha1_steam_supplied() {
        let directory = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(directory.path(), TEST_ACCOUNT).unwrap();
        let contents = b"save data";
        let metadata = metadata(contents, 10);
        let operation = store.begin_operation(480, &[], None).unwrap();

        let staged = store
            .stage_file(&operation, "save.dat", contents, &metadata)
            .unwrap();

        assert_eq!(staged.blob_sha1, metadata.sha1);
        assert!(operation
            .inner
            .path
            .join("blobs")
            .join(&metadata.sha1)
            .is_file());
        // Re-staging identical contents must not fail, and must not need a
        // second digest pass to prove it.
        assert!(store
            .stage_file(&operation, "save.dat", contents, &metadata)
            .is_ok());
    }

    #[test]
    fn rejects_escape_paths_and_bad_hashes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let operation = store.begin_operation(480, &[], None).unwrap();
        let staged = store.stage_file(&operation, "../escape", b"save", &metadata(b"save", 10));
        assert!(staged.is_err());
        assert!(store.begin_operation(0, &[], None).is_err());
        let mut wrong = metadata(b"save", 10);
        wrong.sha1 = "0".repeat(40);
        assert!(store
            .stage_file(&operation, "save.dat", b"save", &wrong)
            .is_err());
        store.abort_operation(&operation).unwrap();
    }

    #[test]
    fn account_scopes_do_not_share_save_manifests() {
        let temporary = tempfile::tempdir().unwrap();
        let first = FolderStore::open_account(temporary.path(), 76_561_198_000_000_001).unwrap();
        let second = FolderStore::open_account(temporary.path(), 76_561_198_000_000_002).unwrap();
        let identity = identity(7, "deck");

        commit_file(&first, 480, "save.dat", b"first", 1, &identity);
        commit_file(&second, 480, "save.dat", b"second", 2, &identity);

        assert_eq!(first.read(480, "save.dat").unwrap(), b"first");
        assert_eq!(second.read(480, "save.dat").unwrap(), b"second");
        assert!(temporary.path().join("76561198000000001/480").is_dir());
        assert!(temporary.path().join("76561198000000002/480").is_dir());
    }

    #[test]
    fn divergent_heads_are_preserved_and_reads_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let (left, right) = divergent_heads(&store);
        let view = store.view(480).unwrap();
        assert_eq!(
            view.head_ids(),
            normalized_head_ids(&[left, right]).unwrap()
        );
        assert_eq!(view.current_change_number, None);
        assert!(store.read(480, "save.dat").is_err());
        assert!(store.changes_since(480, 0).is_err());
        assert!(store.quota(480).is_err());
    }

    #[test]
    fn active_conflict_head_can_be_served_as_a_full_snapshot() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let (left, _) = divergent_heads(&store);

        let changes = store.changes_from_head(480, &left, 2).unwrap();
        assert_eq!(changes.current_change_number, 2);
        assert!(!changes.is_delta);
        assert_eq!(changes.files.len(), 1);
        assert_eq!(changes.files[0].path, "save.dat");
    }

    #[test]
    fn keep_cloud_publishes_a_resolution_manifest() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let (left, right) = divergent_heads(&store);
        let heads = normalized_head_ids(&[left.clone(), right]).unwrap();
        let resolver = identity(9, "laptop");

        assert_eq!(
            store
                .resolve_to_manifest(480, &heads, &left, &resolver, 0)
                .unwrap(),
            3
        );
        let view = store.view(480).unwrap();
        assert_eq!(view.current_change_number, Some(3));
        assert_eq!(view.heads.len(), 1);
        assert_eq!(store.read(480, "save.dat").unwrap(), b"left");
        let resolved = store.resolve_app(480).unwrap();
        assert_eq!(resolved.manifests[&resolved.heads[0]].parents, heads);
    }

    #[test]
    fn identical_heads_converge_without_a_content_choice() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        commit_file(&store, 480, "save.dat", b"same", 1, &owner);
        let root = store.resolve_app(480).unwrap().heads[0].clone();
        let files = store.resolve_app(480).unwrap().manifests[&root]
            .files
            .clone();
        publish_manifest(
            &store,
            480,
            2,
            vec![root.clone()],
            &identity(7, "deck"),
            2_000,
            files.clone(),
        );
        publish_manifest(
            &store,
            480,
            2,
            vec![root],
            &identity(8, "desktop"),
            2_000,
            files,
        );
        assert_eq!(store.view(480).unwrap().heads.len(), 2);

        assert_eq!(
            store
                .resolve_identical_heads(480, &identity(9, "resolver"))
                .unwrap(),
            Some(3)
        );
        assert_eq!(store.view(480).unwrap().heads.len(), 1);
        assert_eq!(store.read(480, "save.dat").unwrap(), b"same");
    }

    #[test]
    fn keep_local_upload_closes_the_exact_conflict_heads() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let (left, right) = divergent_heads(&store);
        let heads = normalized_head_ids(&[left.clone(), right]).unwrap();
        let operation = store.begin_operation(480, &[left], Some(&heads)).unwrap();
        let staged = store
            .stage_file(&operation, "save.dat", b"chosen", &metadata(b"chosen", 4))
            .unwrap();
        let resolver = identity(7, "deck");

        assert_eq!(
            store
                .commit_operation(&operation, &[staged], &BTreeSet::new(), &resolver)
                .unwrap(),
            3
        );
        assert_eq!(store.read(480, "save.dat").unwrap(), b"chosen");
        let resolved = store.resolve_app(480).unwrap();
        assert_eq!(resolved.manifests[&resolved.heads[0]].parents, heads);
    }

    #[test]
    fn changed_conflict_heads_reject_resolution() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let (left, right) = divergent_heads(&store);
        let expected = normalized_head_ids(&[left.clone(), right.clone()]).unwrap();
        let right_manifest = store.resolve_app(480).unwrap().manifests[&right].clone();
        publish_manifest(
            &store,
            480,
            3,
            vec![right],
            &identity(10, "handheld"),
            4_000,
            right_manifest.files,
        );

        assert!(store
            .resolve_to_manifest(480, &expected, &left, &identity(7, "deck"), 0)
            .is_err());
    }

    #[test]
    fn missing_parent_object_does_not_invalidate_its_child() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        commit_file(&store, 480, "save.dat", b"root", 1, &owner);
        let resolved = store.resolve_app(480).unwrap();
        let root = resolved.heads[0].clone();
        let files = resolved.manifests[&root].files.clone();
        let child = publish_manifest(&store, 480, 2, vec![root.clone()], &owner, 2_000, files);
        std::fs::remove_dir_all(store.manifest_dir(480, &root).unwrap()).unwrap();

        assert_eq!(store.view(480).unwrap().head_ids(), vec![child]);
        assert_eq!(store.read(480, "save.dat").unwrap(), b"root");
    }

    #[test]
    fn incomplete_objects_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        commit_file(&store, 480, "save.dat", b"save", 1, &owner);
        let resolved = store.resolve_app(480).unwrap();
        let head = &resolved.heads[0];
        let file = &resolved.manifests[head].files["save.dat"];
        std::fs::remove_file(store.manifest_blob_path(480, head, &file.sha1).unwrap()).unwrap();
        assert!(store.view(480).is_err());

        let malformed = store.manifest_dir(481, &"a".repeat(64)).unwrap();
        create_durable_dir_all(&malformed.join("blobs")).unwrap();
        atomic_publish(&malformed.join("manifest.json"), b"not json").unwrap();
        assert!(store.view(481).is_err());
    }

    #[test]
    fn metadata_queries_do_not_read_blob_contents() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        commit_file(&store, 480, "save.dat", b"save", 1, &identity(7, "deck"));
        let resolved = store.resolve_app(480).unwrap();
        let head = &resolved.heads[0];
        let file = &resolved.manifests[head].files["save.dat"];
        std::fs::write(
            store.manifest_blob_path(480, head, &file.sha1).unwrap(),
            b"fail",
        )
        .unwrap();

        assert!(store.view(480).is_ok());
        assert!(store.changes_since(480, 0).is_ok());
        assert!(store.read(480, "save.dat").is_err());
        assert!(store.inspect_gc(480).is_err());
    }

    #[test]
    fn record_level_version_fields_are_not_accepted() {
        let manifest = serde_json::json!({
            "version": 1,
            "steam_id64": TEST_ACCOUNT.to_string(),
            "app_id": 480,
            "revision": 1,
            "parents": [],
            "client_id": 7,
            "machine_name": "deck",
            "created_at_ms": 1,
            "files": {}
        });
        let claim = serde_json::json!({
            "version": 1,
            "app_id": 480,
            "client_id": 7,
            "machine_name": "deck",
            "os_type": null,
            "device_type": null,
            "status": "active",
            "observed_heads": [],
            "updated_at": 1,
            "nonce": "n"
        });

        assert!(serde_json::from_value::<SaveManifest>(manifest).is_err());
        assert!(serde_json::from_value::<SessionClaim>(claim).is_err());
    }

    #[test]
    fn newer_steam_change_number_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        commit_file(&store, 480, "save.dat", b"save", 1, &identity(7, "deck"));
        assert!(store.changes_since(480, 2).is_err());
    }

    #[test]
    fn gc_inspection_retains_heads_and_their_direct_parents() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        for (contents, mtime) in [(b"one".as_slice(), 1), (b"two", 2), (b"three", 3)] {
            commit_file(&store, 480, "save.dat", contents, mtime, &owner);
        }
        let resolved = store.resolve_app(480).unwrap();
        let current = resolved.heads[0].clone();
        let previous = resolved.manifests[&current].parents[0].clone();
        let oldest = resolved.manifests[&previous].parents[0].clone();
        let report = store.inspect_gc(480).unwrap();
        assert_eq!(
            report
                .retained_manifests
                .into_iter()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([current, previous.clone()])
        );
        assert_eq!(report.candidate_manifests.len(), 1);
        assert!(report.candidate_manifests.contains(&oldest));
    }

    #[test]
    fn gc_sweep_deletes_obsolete_manifest_directories() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        for (contents, mtime) in [(b"one".as_slice(), 1), (b"two", 2), (b"three", 3)] {
            commit_file(&store, 480, "save.dat", contents, mtime, &owner);
        }
        let resolved = store.resolve_app(480).unwrap();
        let current = resolved.heads[0].clone();
        let previous = resolved.manifests[&current].parents[0].clone();
        let oldest = resolved.manifests[&previous].parents[0].clone();
        let current_blob = resolved.manifests[&current].files["save.dat"].sha1.clone();
        let report = store.inspect_gc(480).unwrap();

        let plan = store.prepare_gc_sweep(&report).unwrap().unwrap();
        let sweep = store.apply_gc_sweep(plan).unwrap().unwrap();
        assert_eq!(sweep.deleted_manifests, 1);
        assert!(!store.manifest_dir(480, &oldest).unwrap().exists());
        assert!(store.manifest_dir(480, &previous).unwrap().exists());
        assert!(store.manifest_dir(480, &current).unwrap().exists());
        assert!(store
            .manifest_blob_path(480, &current, &current_blob)
            .unwrap()
            .exists());
        assert_eq!(store.read(480, "save.dat").unwrap(), b"three");
        store.finalize_gc_sweep(sweep).unwrap();
    }

    #[test]
    fn gc_sweep_aborts_when_inventory_changes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        for (contents, mtime) in [(b"one".as_slice(), 1), (b"two", 2), (b"three", 3)] {
            commit_file(&store, 480, "save.dat", contents, mtime, &owner);
        }
        let report = store.inspect_gc(480).unwrap();
        let candidate = report.candidate_manifests[0].clone();
        let candidate_path = store.manifest_dir(480, &candidate).unwrap();

        commit_file(&store, 480, "save.dat", b"four", 4, &owner);
        assert!(store.prepare_gc_sweep(&report).unwrap().is_none());
        assert!(candidate_path.exists());

        let report = store.inspect_gc(480).unwrap();
        let plan = store.prepare_gc_sweep(&report).unwrap().unwrap();
        let unexpected = store.app_dir(480).join("f".repeat(64));
        std::fs::create_dir(&unexpected).unwrap();
        assert!(store.apply_gc_sweep(plan).unwrap().is_none());
    }

    #[test]
    fn gc_sweep_can_restore_candidates_when_publication_fails() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        for (contents, mtime) in [(b"one".as_slice(), 1), (b"two", 2), (b"three", 3)] {
            commit_file(&store, 480, "save.dat", contents, mtime, &owner);
        }
        let report = store.inspect_gc(480).unwrap();
        let candidate = report.candidate_manifests[0].clone();
        let plan = store.prepare_gc_sweep(&report).unwrap().unwrap();
        let sweep = store.apply_gc_sweep(plan).unwrap().unwrap();
        assert!(!store.manifest_dir(480, &candidate).unwrap().exists());

        store.restore_gc_sweep(480, sweep).unwrap();

        assert!(store.manifest_dir(480, &candidate).unwrap().exists());
        assert_eq!(store.resolve_app(480).unwrap().manifests.len(), 3);
    }

    #[test]
    fn gc_sweep_isolates_identical_blobs_by_app() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        for (contents, mtime) in [(b"shared".as_slice(), 1), (b"two", 2), (b"three", 3)] {
            commit_file(&store, 480, "save.dat", contents, mtime, &owner);
        }
        commit_file(&store, 481, "save.dat", b"shared", 1, &owner);
        let app_481_head = store.view(481).unwrap().head_ids().remove(0);
        let shared_blob = hex_digest::<Sha1>(b"shared");
        let report = store.inspect_gc(480).unwrap();

        let plan = store.prepare_gc_sweep(&report).unwrap().unwrap();
        let sweep = store.apply_gc_sweep(plan).unwrap().unwrap();
        assert_eq!(sweep.deleted_manifests, 1);
        assert!(store
            .manifest_blob_path(481, &app_481_head, &shared_blob)
            .unwrap()
            .exists());
        assert_eq!(store.read(481, "save.dat").unwrap(), b"shared");
        store.finalize_gc_sweep(sweep).unwrap();
    }

    #[test]
    fn gc_sweep_reclaims_only_the_requested_app_history() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), TEST_ACCOUNT).unwrap();
        let owner = identity(7, "deck");
        for app_id in [480, 481] {
            for revision in 1..=3 {
                let contents = format!("{app_id}-{revision}");
                commit_file(
                    &store,
                    app_id,
                    "save.dat",
                    contents.as_bytes(),
                    revision,
                    &owner,
                );
            }
        }
        let other = store.resolve_app(481).unwrap();
        let other_current = other.heads[0].clone();
        let other_previous = other.manifests[&other_current].parents[0].clone();
        let other_oldest = other.manifests[&other_previous].parents[0].clone();
        let report = store.inspect_gc(480).unwrap();

        assert_eq!(report.candidate_manifests.len(), 1);
        let plan = store.prepare_gc_sweep(&report).unwrap().unwrap();
        let sweep = store.apply_gc_sweep(plan).unwrap().unwrap();
        assert_eq!(sweep.deleted_manifests, 1);
        assert!(store.manifest_dir(481, &other_oldest).unwrap().exists());
        assert_eq!(store.resolve_app(481).unwrap().manifests.len(), 3);
        store.finalize_gc_sweep(sweep).unwrap();
    }

    #[test]
    fn session_claims_require_explicit_override() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), 76_561_198_000_000_001).unwrap();
        let first = identity(7, "deck");
        let second = identity(8, "desktop");

        assert!(store
            .launch_session(480, &first, Some(1), Some(2), false)
            .unwrap()
            .is_empty());
        let pending = store
            .launch_session(480, &second, Some(3), Some(4), false)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].client_id, first.client_id);
        assert!(store
            .launch_session(480, &second, Some(3), Some(4), true)
            .unwrap()
            .is_empty());
        store.suspend_session(480, &second).unwrap();
        let claim_path = store.session_claim_path(480, second.client_id).unwrap();
        let suspended = std::fs::read(&claim_path).unwrap();
        store.suspend_session(480, &second).unwrap();
        assert_eq!(std::fs::read(&claim_path).unwrap(), suspended);
        store.resume_session(480, &second).unwrap();
        let active = std::fs::read(&claim_path).unwrap();
        store.resume_session(480, &second).unwrap();
        assert_eq!(std::fs::read(&claim_path).unwrap(), active);
        store.exit_session(480, &second).unwrap();
        assert!(!store
            .session_claim_path(480, second.client_id)
            .unwrap()
            .exists());
        store.exit_session(480, &identity(9, "other")).unwrap();
    }

    #[test]
    fn repeated_session_override_discards_obsolete_claim_ids() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), 76_561_198_000_000_001).unwrap();
        let first = identity(7, "deck");
        let second = identity(8, "desktop");

        store
            .launch_session(480, &first, Some(1), Some(2), false)
            .unwrap();
        store
            .launch_session(480, &second, Some(3), Some(4), true)
            .unwrap();
        store.resume_session(480, &first).unwrap();
        store
            .launch_session(480, &second, Some(3), Some(4), true)
            .unwrap();

        let path = store
            .session_dir(480)
            .unwrap()
            .join("overrides")
            .join("8.json");
        let bytes = std::fs::read(path).unwrap();
        let record = serde_json::from_slice::<SessionOverride>(&bytes).unwrap();
        assert_eq!(record.superseded_claims.len(), 1);
        assert!(serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap()
            .get("nonce")
            .is_none());
        assert!(serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap()
            .get("updated_at")
            .is_none());
        assert!(store
            .launch_session(480, &second, Some(3), Some(4), false)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn concurrent_session_launches_allow_only_one_client() {
        let temporary = tempfile::tempdir().unwrap();
        let account = 76_561_198_000_000_001;
        let first_store = FolderStore::open_account(temporary.path(), account).unwrap();
        let second_store = FolderStore::open_account(temporary.path(), account).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let first_barrier = std::sync::Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            first_store.launch_session(480, &identity(7, "deck"), Some(1), Some(2), false)
        });
        let second = std::thread::spawn(move || {
            barrier.wait();
            second_store.launch_session(480, &identity(8, "desktop"), Some(3), Some(4), false)
        });

        let mut pending_counts = vec![
            first.join().unwrap().unwrap().len(),
            second.join().unwrap().unwrap().len(),
        ];
        pending_counts.sort_unstable();
        assert_eq!(pending_counts, vec![0, 1]);
        assert!(!temporary
            .path()
            .join(format!("{account}/480/.lock"))
            .exists());
    }

    #[test]
    fn session_record_name_must_match_its_client_id() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), 76_561_198_000_000_001).unwrap();
        store
            .launch_session(480, &identity(7, "deck"), Some(1), Some(2), false)
            .unwrap();
        std::fs::rename(
            store.session_claim_path(480, 7).unwrap(),
            store.session_claim_path(480, 8).unwrap(),
        )
        .unwrap();

        assert!(store
            .launch_session(480, &identity(9, "desktop"), Some(3), Some(4), false)
            .is_err());
    }
}
