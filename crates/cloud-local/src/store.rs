use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};
use vapor_forge_cloud_core::{
    BackendError, ByteStore, ChangeList, CloudFileStore, FileEntry, FileMetadata, Quota, Transfer,
};

const FORMAT_VERSION: u32 = 1;
const FORMAT_FILE: &str = "format.json";

#[derive(Clone)]
pub struct FolderStore {
    root: PathBuf,
    account: Option<String>,
    coordination: Arc<RepositoryCoordination>,
}

struct RepositoryCoordination {
    lock: Mutex<()>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFile {
    pub path: String,
    pub blob_sha1: String,
    pub metadata: FileMetadata,
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
pub struct GcRoots {
    pub manifest_ids: BTreeSet<String>,
    pub blob_sha1s: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    pub app_id: u32,
    pub manifest_scope: String,
    pub retained_manifests: Vec<String>,
    pub candidate_manifests: Vec<String>,
    pub retained_blobs: Vec<String>,
    pub candidate_blobs: Vec<String>,
    pub inspected_roots: GcRoots,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GcSweep {
    pub deleted_manifests: usize,
    pub deleted_blobs: usize,
}

pub(crate) struct GcSweepPlan<'a> {
    _lock: MutexGuard<'a, ()>,
    root: PathBuf,
    app_id: u32,
    inspected_roots: GcRoots,
    expected_manifests: BTreeSet<String>,
    expected_blobs: BTreeSet<String>,
    candidate_manifests: BTreeSet<String>,
    candidate_blobs: BTreeSet<String>,
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
struct Format {
    version: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredFile {
    sha1: String,
    raw_size: u64,
    mtime: i64,
    platforms_to_sync: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SaveManifest {
    version: u32,
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
struct SessionClaim {
    version: u32,
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
struct SessionOverride {
    version: u32,
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
        std::fs::create_dir_all(root).map_err(io_error)?;
        let root = root.canonicalize().map_err(io_error)?;
        let coordination = repository_coordination(&root);
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

    pub fn stage_file(
        &self,
        app_id: u32,
        path: &str,
        contents: &[u8],
        metadata: &FileMetadata,
    ) -> Result<StagedFile, BackendError> {
        validate_app_id(app_id)?;
        validate_cloud_path(path)?;
        validate_metadata(contents, metadata)?;
        let blob_sha1 = metadata.sha1.to_ascii_lowercase();
        self.publish_blob(app_id, &blob_sha1, contents)?;
        Ok(StagedFile {
            path: path.to_owned(),
            blob_sha1,
            metadata: metadata.clone(),
        })
    }

    pub fn commit_batch(
        &self,
        app_id: u32,
        base_heads: &[String],
        staged: &[StagedFile],
        deleted: &BTreeSet<String>,
        identity: &CommitIdentity,
        resolution_heads: Option<&[String]>,
    ) -> Result<u64, BackendError> {
        validate_app_id(app_id)?;
        validate_identity(identity)?;
        let _lock = self.lock_app(app_id)?;
        let resolved = self.resolve_app(app_id)?;
        let base_heads = normalized_head_ids(base_heads)?;
        let resolution_heads = resolution_heads.map(normalized_head_ids).transpose()?;
        let (parents, original_files, force_publish) = match resolution_heads {
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
                (expected, selected.files.clone(), true)
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
                (base_heads, files, false)
            }
        };
        let mut files = original_files.clone();
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
        self.verify_files(app_id, &files)?;
        if files == original_files && !force_publish {
            return Ok(resolved
                .current()?
                .map_or(0, |(_, manifest)| manifest.revision));
        }
        self.publish_manifest(app_id, parents, files, identity, resolved.max_revision)
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
        let _lock = self.lock_app(app_id)?;
        let resolved = self.resolve_app(app_id)?;
        let expected_heads = normalized_head_ids(expected_heads)?;
        if expected_heads.len() < 2 || resolved.heads != expected_heads {
            return Err(conflict(
                "local cloud conflict heads changed before resolution",
            ));
        }
        let selected = resolved
            .manifests
            .get(selected_head)
            .filter(|_| expected_heads.iter().any(|head| head == selected_head))
            .ok_or_else(|| permanent("selected cloud conflict manifest is not an active head"))?;
        self.verify_files(app_id, &selected.files)?;
        self.publish_manifest(
            app_id,
            expected_heads,
            selected.files.clone(),
            identity,
            resolved.max_revision.max(minimum_revision),
        )
    }

    pub fn resolve_identical_heads(
        &self,
        app_id: u32,
        identity: &CommitIdentity,
    ) -> Result<Option<u64>, BackendError> {
        validate_app_id(app_id)?;
        validate_identity(identity)?;
        let _lock = self.lock_app(app_id)?;
        let resolved = self.resolve_app(app_id)?;
        if resolved.heads.len() < 2 {
            return Ok(None);
        }
        let selected = resolved
            .manifests
            .get(&resolved.heads[0])
            .ok_or_else(|| incomplete("local cloud manifest head is unavailable"))?;
        if !resolved
            .heads
            .iter()
            .all(|head| resolved.manifests[head].files == selected.files)
        {
            return Ok(None);
        }
        self.verify_files(app_id, &selected.files)?;
        self.publish_manifest(
            app_id,
            resolved.heads,
            selected.files.clone(),
            identity,
            resolved.max_revision,
        )
        .map(Some)
    }

    pub fn inspect_gc(&self, app_id: u32, active: &GcRoots) -> Result<GcReport, BackendError> {
        validate_app_id(app_id)?;
        let target_scope = self.gc_manifest_scope(app_id);
        let manifests = collect_manifest_objects(&self.commit_dir(app_id), app_id)?;
        let referenced = manifests
            .values()
            .flat_map(|manifest| manifest.parents.iter())
            .collect::<BTreeSet<_>>();
        let mut retained_manifest_ids = BTreeSet::new();
        for (id, manifest) in manifests.iter().filter(|(id, _)| !referenced.contains(id)) {
            retained_manifest_ids.insert(id.clone());
            retained_manifest_ids.extend(
                manifest
                    .parents
                    .iter()
                    .filter(|parent| manifests.contains_key(*parent))
                    .cloned(),
            );
        }
        retained_manifest_ids.extend(active.manifest_ids.iter().cloned());
        if !active
            .manifest_ids
            .iter()
            .all(|id| manifests.contains_key(id))
        {
            return Err(incomplete("local cloud GC active manifest is unavailable"));
        }

        let mut retained_blobs = active.blob_sha1s.clone();
        for id in &retained_manifest_ids {
            let manifest = manifests
                .get(id)
                .ok_or_else(|| incomplete("local cloud GC retained manifest is unavailable"))?;
            for file in manifest.files.values() {
                self.read_blob(app_id, file)?;
                retained_blobs.insert(file.sha1.clone());
            }
        }

        let all_blobs = collect_blob_objects(&self.blob_dir(app_id))?;
        if !retained_blobs.iter().all(|sha1| all_blobs.contains(sha1)) {
            return Err(incomplete("local cloud GC active blob is unavailable"));
        }
        let candidate_manifests = manifests
            .keys()
            .filter(|id| !retained_manifest_ids.contains(*id))
            .cloned()
            .collect();
        let candidate_blobs = all_blobs.difference(&retained_blobs).cloned().collect();
        Ok(GcReport {
            app_id,
            manifest_scope: target_scope,
            retained_manifests: retained_manifest_ids.into_iter().collect(),
            candidate_manifests,
            retained_blobs: retained_blobs.into_iter().collect(),
            candidate_blobs,
            inspected_roots: active.clone(),
        })
    }

    pub(crate) fn prepare_gc_sweep(
        &self,
        report: &GcReport,
    ) -> Result<Option<GcSweepPlan<'_>>, BackendError> {
        if report.manifest_scope != self.gc_manifest_scope(report.app_id) {
            return Err(permanent("invalid local cloud GC scope"));
        }
        let retained_manifests = unique_items(&report.retained_manifests)?;
        let candidate_manifests = unique_items(&report.candidate_manifests)?;
        let retained_blobs = unique_items(&report.retained_blobs)?;
        let candidate_blobs = unique_items(&report.candidate_blobs)?;
        if !retained_manifests.is_disjoint(&candidate_manifests)
            || !retained_blobs.is_disjoint(&candidate_blobs)
        {
            return Err(permanent("invalid local cloud GC report"));
        }

        let _lock = self.lock_app(report.app_id)?;
        let current_manifests = collect_manifest_paths(&self.commit_dir(report.app_id))?;
        let expected_manifests = retained_manifests
            .union(&candidate_manifests)
            .cloned()
            .collect::<BTreeSet<_>>();
        let current_blobs = collect_blob_objects(&self.blob_dir(report.app_id))?;
        let expected_blobs = retained_blobs
            .union(&candidate_blobs)
            .cloned()
            .collect::<BTreeSet<_>>();
        if current_manifests != expected_manifests || current_blobs != expected_blobs {
            return Ok(None);
        }

        Ok(Some(GcSweepPlan {
            _lock,
            root: self.app_dir(report.app_id),
            app_id: report.app_id,
            inspected_roots: report.inspected_roots.clone(),
            expected_manifests,
            expected_blobs,
            candidate_manifests,
            candidate_blobs,
        }))
    }

    pub(crate) fn apply_gc_sweep(
        &self,
        plan: GcSweepPlan<'_>,
        active: &GcRoots,
    ) -> Result<Option<GcSweep>, BackendError> {
        if plan.root != self.app_dir(plan.app_id) || plan.inspected_roots != *active {
            return Ok(None);
        }
        if active
            .manifest_ids
            .iter()
            .any(|id| plan.candidate_manifests.contains(id))
            || !active.blob_sha1s.is_disjoint(&plan.candidate_blobs)
        {
            return Ok(None);
        }
        if collect_manifest_paths(&self.commit_dir(plan.app_id))? != plan.expected_manifests
            || collect_blob_objects(&self.blob_dir(plan.app_id))? != plan.expected_blobs
        {
            return Ok(None);
        }

        for id in &plan.candidate_manifests {
            remove_if_exists(&self.commit_dir(plan.app_id).join(format!("{id}.json")))?;
        }
        for sha1 in &plan.candidate_blobs {
            remove_if_exists(&self.blob_path(plan.app_id, sha1)?)?;
        }
        Ok(Some(GcSweep {
            deleted_manifests: plan.candidate_manifests.len(),
            deleted_blobs: plan.candidate_blobs.len(),
        }))
    }

    fn publish_manifest(
        &self,
        app_id: u32,
        parents: Vec<String>,
        files: BTreeMap<String, StoredFile>,
        identity: &CommitIdentity,
        max_revision: u64,
    ) -> Result<u64, BackendError> {
        let revision = max_revision
            .checked_add(1)
            .ok_or_else(|| permanent("local cloud revision overflow"))?;
        let manifest = SaveManifest {
            version: FORMAT_VERSION,
            app_id,
            revision,
            parents,
            client_id: identity.client_id,
            machine_name: identity.machine_name.clone(),
            created_at_ms: unix_millis(),
            files,
        };
        let bytes = serde_json::to_vec(&manifest).map_err(json_error)?;
        let id = hex_digest::<Sha256>(&bytes);
        let path = self.commit_dir(app_id).join(format!("{id}.json"));
        atomic_publish(&path, &bytes)?;
        let current = self.resolve_app(app_id)?;
        let Some((current_id, current_manifest)) = current.current()? else {
            return Err(permanent("published local manifest did not become current"));
        };
        if current_id != id || current_manifest.revision != revision {
            return Err(conflict(
                "another local manifest was published concurrently",
            ));
        }
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
                version: FORMAT_VERSION,
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
            version: FORMAT_VERSION,
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
        for entry in std::fs::read_dir(directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(io_error)?;
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
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
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
        for entry in std::fs::read_dir(directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record =
                serde_json::from_slice::<SessionOverride>(&std::fs::read(&path).map_err(io_error)?)
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
        atomic_replace(&path, &bytes)?;
        Ok(hex_digest::<Sha256>(&bytes))
    }

    fn write_session_override(&self, record: &SessionOverride) -> Result<(), BackendError> {
        let path = self.session_override_path(record.app_id, record.client_id)?;
        let bytes = serde_json::to_vec(record).map_err(json_error)?;
        atomic_replace(&path, &bytes)
    }

    fn initialize(&self) -> Result<(), BackendError> {
        let format_path = self.root.join(FORMAT_FILE);
        if format_path.exists() {
            let format: Format =
                serde_json::from_slice(&std::fs::read(&format_path).map_err(io_error)?)
                    .map_err(json_error)?;
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

    fn commit_dir(&self, app_id: u32) -> PathBuf {
        self.app_dir(app_id).join("manifests")
    }

    pub(crate) fn gc_manifest_scope(&self, app_id: u32) -> String {
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

    fn blob_dir(&self, app_id: u32) -> PathBuf {
        self.app_dir(app_id).join("blobs")
    }

    fn blob_path(&self, app_id: u32, hash: &str) -> Result<PathBuf, BackendError> {
        validate_app_id(app_id)?;
        if hash.len() != 40 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(permanent("invalid local cloud blob hash"));
        }
        Ok(self.blob_dir(app_id).join(&hash[..2]).join(hash))
    }

    fn publish_blob(&self, app_id: u32, hash: &str, contents: &[u8]) -> Result<(), BackendError> {
        atomic_publish(&self.blob_path(app_id, hash)?, contents)
    }

    fn resolve_app(&self, app_id: u32) -> Result<ResolvedApp, BackendError> {
        validate_app_id(app_id)?;
        let directory = self.commit_dir(app_id);
        if !directory.exists() {
            return Ok(ResolvedApp {
                manifests: HashMap::new(),
                heads: Vec::new(),
                max_revision: 0,
            });
        }
        let mut manifests = HashMap::new();
        for entry in std::fs::read_dir(&directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| incomplete("local cloud manifest has no UTF-8 id"))?;
            let bytes = std::fs::read(&path).map_err(io_error)?;
            if id.len() != 64 || hex_digest::<Sha256>(&bytes) != id {
                return Err(incomplete("local cloud manifest identity is invalid"));
            }
            let manifest = serde_json::from_slice::<SaveManifest>(&bytes)
                .map_err(|_| incomplete("local cloud manifest is incomplete"))?;
            validate_manifest(id, app_id, &manifest)?;
            self.verify_files(app_id, &manifest.files)?;
            manifests.insert(id.to_owned(), manifest);
        }

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
        files: &BTreeMap<String, StoredFile>,
    ) -> Result<(), BackendError> {
        for (path, file) in files {
            validate_cloud_path(path)?;
            self.read_blob(app_id, file)?;
        }
        Ok(())
    }

    fn read_blob(&self, app_id: u32, file: &StoredFile) -> Result<Vec<u8>, BackendError> {
        let bytes = std::fs::read(self.blob_path(app_id, &file.sha1)?).map_err(io_error)?;
        if bytes.len() as u64 != file.raw_size || hex_digest::<Sha1>(&bytes) != file.sha1 {
            return Err(permanent("local cloud blob failed integrity verification"));
        }
        Ok(bytes)
    }
}

fn repository_coordination(root: &Path) -> Arc<RepositoryCoordination> {
    static COORDINATORS: OnceLock<Mutex<HashMap<PathBuf, Weak<RepositoryCoordination>>>> =
        OnceLock::new();
    let coordinators = COORDINATORS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut coordinators = coordinators
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(coordination) = coordinators.get(root).and_then(Weak::upgrade) {
        return coordination;
    }
    coordinators.retain(|_, coordination| coordination.strong_count() != 0);
    let coordination = Arc::new(RepositoryCoordination {
        lock: Mutex::new(()),
    });
    coordinators.insert(root.to_owned(), Arc::downgrade(&coordination));
    coordination
}

impl ByteStore for FolderStore {
    fn read(&self, app_id: u32, path: &str) -> Result<Vec<u8>, BackendError> {
        validate_cloud_path(path)?;
        let _lock = self.lock_app(app_id)?;
        let resolved = self.resolve_app(app_id)?;
        let (_, current) = resolved
            .current()?
            .ok_or_else(|| permanent("local cloud file not found"))?;
        let file = current
            .files
            .get(path)
            .ok_or_else(|| permanent(format!("local cloud file not found: {path}")))?;
        self.read_blob(app_id, file)
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
        let staged = self.stage_file(app_id, path, contents, metadata)?;
        self.commit_batch(
            app_id,
            &view.head_ids(),
            &[staged],
            &BTreeSet::new(),
            &identity,
            None,
        )
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
        self.commit_batch(
            app_id,
            &view.head_ids(),
            &[],
            &BTreeSet::from([path.to_owned()]),
            &identity,
            None,
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

fn validate_manifest(id: &str, app_id: u32, manifest: &SaveManifest) -> Result<(), BackendError> {
    if manifest.version != FORMAT_VERSION || manifest.app_id != app_id || manifest.revision == 0 {
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
    for (path, file) in &manifest.files {
        validate_cloud_path(path)?;
        if file.sha1.len() != 40
            || !file.sha1.bytes().all(|byte| byte.is_ascii_hexdigit())
            || file.sha1 != file.sha1.to_ascii_lowercase()
        {
            return Err(permanent("invalid local cloud manifest file"));
        }
    }
    Ok(())
}

fn validate_session_claim(app_id: u32, claim: &SessionClaim) -> Result<(), BackendError> {
    if claim.version != FORMAT_VERSION
        || claim.app_id != app_id
        || claim.nonce.is_empty()
        || claim.updated_at == 0
    {
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
    if record.version != FORMAT_VERSION
        || record.app_id != app_id
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
    if path.is_empty() || path.starts_with('/') || path.contains('\0') || path.contains('\\') {
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
        return (std::fs::read(path).map_err(io_error)? == bytes)
            .then_some(())
            .ok_or_else(|| permanent("immutable local cloud object already has different bytes"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| permanent("local cloud object has no parent directory"))?;
    std::fs::create_dir_all(parent).map_err(io_error)?;
    let temporary = parent.join(format!(".syncthing.{}.tmp", next_nonce()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(io_error)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(io_error(error));
    }
    drop(file);
    match std::fs::hard_link(&temporary, path) {
        Ok(()) => {
            std::fs::remove_file(&temporary).map_err(io_error)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&temporary);
            if std::fs::read(path).map_err(io_error)? == bytes {
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
    match std::fs::read(path) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(error)),
    }
    let parent = path
        .parent()
        .ok_or_else(|| permanent("local cloud object has no parent directory"))?;
    std::fs::create_dir_all(parent).map_err(io_error)?;
    let temporary = parent.join(format!(".syncthing.{}.tmp", next_nonce()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(io_error)?;
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
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), BackendError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn collect_manifest_objects(
    directory: &Path,
    app_id: u32,
) -> Result<BTreeMap<String, SaveManifest>, BackendError> {
    if !directory.exists() {
        return Ok(BTreeMap::new());
    }
    let mut manifests = BTreeMap::new();
    for entry in std::fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let file_type = entry.file_type().map_err(io_error)?;
        let path = entry.path();
        if !file_type.is_file() {
            return Err(incomplete("local cloud manifest namespace is incomplete"));
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| incomplete("local cloud manifest name is not UTF-8"))?;
        if name.starts_with(".syncthing.") && name.ends_with(".tmp") {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            return Err(incomplete("local cloud manifest namespace is incomplete"));
        }
        let bytes = std::fs::read(&path).map_err(io_error)?;
        let id = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| incomplete("local cloud manifest has no UTF-8 id"))?;
        if id.len() != 64 || hex_digest::<Sha256>(&bytes) != id {
            return Err(incomplete("local cloud manifest identity is invalid"));
        }
        let manifest = serde_json::from_slice::<SaveManifest>(&bytes)
            .map_err(|_| incomplete("local cloud manifest is incomplete"))?;
        validate_manifest(id, app_id, &manifest)?;
        if manifests.insert(id.to_owned(), manifest).is_some() {
            return Err(permanent("duplicate local cloud manifest identity"));
        }
    }
    Ok(manifests)
}

fn collect_manifest_paths(directory: &Path) -> Result<BTreeSet<String>, BackendError> {
    if !directory.exists() {
        return Ok(BTreeSet::new());
    }
    let mut paths = BTreeSet::new();
    for entry in std::fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let file_type = entry.file_type().map_err(io_error)?;
        let path = entry.path();
        if !file_type.is_file() {
            return Err(incomplete("local cloud manifest namespace is incomplete"));
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| incomplete("local cloud manifest name is not UTF-8"))?;
        if name.starts_with(".syncthing.") && name.ends_with(".tmp") {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            return Err(incomplete("local cloud manifest namespace is incomplete"));
        }
        let id = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| incomplete("local cloud manifest has no UTF-8 id"))?;
        if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(incomplete("local cloud manifest identity is invalid"));
        }
        if !paths.insert(id.to_owned()) {
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

fn collect_blob_objects(root: &Path) -> Result<BTreeSet<String>, BackendError> {
    if !root.exists() {
        return Ok(BTreeSet::new());
    }
    let mut blobs = BTreeSet::new();
    for prefix_entry in std::fs::read_dir(root).map_err(io_error)? {
        let prefix_entry = prefix_entry.map_err(io_error)?;
        if !prefix_entry.file_type().map_err(io_error)?.is_dir() {
            return Err(incomplete("local cloud blob namespace is incomplete"));
        }
        let prefix = prefix_entry
            .file_name()
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| incomplete("local cloud blob prefix is not UTF-8"))?;
        if prefix.len() != 2
            || prefix != prefix.to_ascii_lowercase()
            || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(permanent("invalid local cloud blob prefix"));
        }
        for entry in std::fs::read_dir(prefix_entry.path()).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if !entry.file_type().map_err(io_error)?.is_file() {
                return Err(incomplete("local cloud blob namespace is incomplete"));
            }
            let name = entry
                .file_name()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| incomplete("local cloud blob name is not UTF-8"))?;
            if name.starts_with(".syncthing.") && name.ends_with(".tmp") {
                continue;
            }
            if name.len() != 40
                || name != name.to_ascii_lowercase()
                || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !name.starts_with(&prefix)
            {
                return Err(permanent("invalid local cloud blob name"));
            }
            blobs.insert(name);
        }
    }
    Ok(blobs)
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
            version: FORMAT_VERSION,
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
        atomic_publish(&store.commit_dir(app_id).join(format!("{id}.json")), &bytes).unwrap();
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
        let staged = store
            .stage_file(app_id, path, contents, &metadata(contents, mtime))
            .unwrap();
        store
            .commit_batch(
                app_id,
                &view.head_ids(),
                &[staged],
                &BTreeSet::new(),
                identity,
                None,
            )
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
            stored_file(
                store
                    .stage_file(480, "save.dat", b"left", &metadata(b"left", 2))
                    .unwrap(),
            ),
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
            stored_file(
                store
                    .stage_file(480, "save.dat", b"right", &metadata(b"right", 3))
                    .unwrap(),
            ),
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
    fn immutable_manifests_survive_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let contents = b"local save";
        let identity = identity(7, "deck");
        assert_eq!(
            commit_file(&store, 480, "Game/save.dat", contents, 10, &identity),
            1
        );
        assert!(!temporary.path().join("blobs/sha256").exists());
        assert_eq!(
            FolderStore::open(temporary.path())
                .unwrap()
                .read(480, "Game/save.dat")
                .unwrap(),
            contents
        );
    }

    #[test]
    fn manifest_id_hashes_json_without_nonce() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        commit_file(&store, 480, "save.dat", b"save", 1, &identity(7, "deck"));
        let path = std::fs::read_dir(store.commit_dir(480))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let bytes = std::fs::read(&path).unwrap();
        let value = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        assert!(value.get("nonce").is_none());
        assert_eq!(
            path.file_stem().unwrap().to_str().unwrap(),
            hex_digest::<Sha256>(&bytes)
        );
    }

    #[test]
    fn batch_publishes_one_commit_for_uploads_and_deletes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let identity = identity(7, "deck");
        commit_file(&store, 480, "old.dat", b"old", 1, &identity);
        let view = store.view(480).unwrap();
        let staged = store
            .stage_file(480, "new.dat", b"new", &metadata(b"new", 2))
            .unwrap();
        assert_eq!(
            store
                .commit_batch(
                    480,
                    &view.head_ids(),
                    &[staged],
                    &BTreeSet::from(["old.dat".into()]),
                    &identity,
                    None,
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
    fn stale_batch_cannot_cover_a_new_head() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let base = store.view(480).unwrap();
        let identity = identity(7, "deck");
        commit_file(&store, 480, "a", b"a", 1, &identity);
        let staged = store
            .stage_file(480, "b", b"b", &metadata(b"b", 2))
            .unwrap();
        assert!(store
            .commit_batch(
                480,
                &base.head_ids(),
                &[staged],
                &BTreeSet::new(),
                &identity,
                None,
            )
            .is_err());
    }

    #[test]
    fn blobs_are_addressed_by_the_sha1_steam_supplied() {
        let directory = tempfile::tempdir().unwrap();
        let store = FolderStore::open(directory.path()).unwrap();
        let contents = b"save data";
        let metadata = metadata(contents, 10);

        let staged = store
            .stage_file(480, "save.dat", contents, &metadata)
            .unwrap();

        assert_eq!(staged.blob_sha1, metadata.sha1);
        assert!(directory
            .path()
            .join("480/blobs")
            .join(&metadata.sha1[..2])
            .join(&metadata.sha1)
            .is_file());
        // Re-staging identical contents must not fail, and must not need a
        // second digest pass to prove it.
        assert!(store
            .stage_file(480, "save.dat", contents, &metadata)
            .is_ok());
    }

    #[test]
    fn rejects_escape_paths_and_bad_hashes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let identity = identity(7, "deck");
        let staged = store.stage_file(480, "../escape", b"save", &metadata(b"save", 10));
        assert!(staged.is_err());
        assert!(store
            .commit_batch(0, &[], &[], &BTreeSet::new(), &identity, None)
            .is_err());
        let mut wrong = metadata(b"save", 10);
        wrong.sha1 = "0".repeat(40);
        assert!(store.stage_file(480, "save.dat", b"save", &wrong).is_err());
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
        assert!(temporary
            .path()
            .join("76561198000000001/480/manifests")
            .is_dir());
        assert!(temporary
            .path()
            .join("76561198000000002/480/manifests")
            .is_dir());
    }

    #[test]
    fn divergent_heads_are_preserved_and_reads_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
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
        let store = FolderStore::open(temporary.path()).unwrap();
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
        let store = FolderStore::open(temporary.path()).unwrap();
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
        let store = FolderStore::open(temporary.path()).unwrap();
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
        let store = FolderStore::open(temporary.path()).unwrap();
        let (left, right) = divergent_heads(&store);
        let heads = normalized_head_ids(&[left.clone(), right]).unwrap();
        let staged = store
            .stage_file(480, "save.dat", b"chosen", &metadata(b"chosen", 4))
            .unwrap();
        let resolver = identity(7, "deck");

        assert_eq!(
            store
                .commit_batch(
                    480,
                    &[left],
                    &[staged],
                    &BTreeSet::new(),
                    &resolver,
                    Some(&heads),
                )
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
        let store = FolderStore::open(temporary.path()).unwrap();
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
        let store = FolderStore::open(temporary.path()).unwrap();
        let owner = identity(7, "deck");
        commit_file(&store, 480, "save.dat", b"root", 1, &owner);
        let resolved = store.resolve_app(480).unwrap();
        let root = resolved.heads[0].clone();
        let files = resolved.manifests[&root].files.clone();
        let child = publish_manifest(&store, 480, 2, vec![root.clone()], &owner, 2_000, files);
        std::fs::remove_file(store.commit_dir(480).join(format!("{root}.json"))).unwrap();

        assert_eq!(store.view(480).unwrap().head_ids(), vec![child]);
        assert_eq!(store.read(480, "save.dat").unwrap(), b"root");
    }

    #[test]
    fn incomplete_objects_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let owner = identity(7, "deck");
        commit_file(&store, 480, "save.dat", b"save", 1, &owner);
        let resolved = store.resolve_app(480).unwrap();
        let file = &resolved.manifests[&resolved.heads[0]].files["save.dat"];
        std::fs::remove_file(store.blob_path(480, &file.sha1).unwrap()).unwrap();
        assert!(store.view(480).is_err());

        let malformed = store
            .commit_dir(481)
            .join(format!("{}.json", "a".repeat(64)));
        atomic_publish(&malformed, b"not json").unwrap();
        assert!(store.view(481).is_err());
    }

    #[test]
    fn newer_steam_change_number_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        commit_file(&store, 480, "save.dat", b"save", 1, &identity(7, "deck"));
        assert!(store.changes_since(480, 2).is_err());
    }

    #[test]
    fn gc_inspection_retains_current_previous_and_active_objects() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let owner = identity(7, "deck");
        for (contents, mtime) in [(b"one".as_slice(), 1), (b"two", 2), (b"three", 3)] {
            commit_file(&store, 480, "save.dat", contents, mtime, &owner);
        }
        let resolved = store.resolve_app(480).unwrap();
        let current = resolved.heads[0].clone();
        let previous = resolved.manifests[&current].parents[0].clone();
        let oldest = resolved.manifests[&previous].parents[0].clone();
        let oldest_blob = resolved.manifests[&oldest].files["save.dat"].sha1.clone();

        let report = store.inspect_gc(480, &GcRoots::default()).unwrap();
        assert_eq!(report.retained_manifests.len(), 2);
        assert_eq!(report.candidate_manifests.len(), 1);
        assert!(report.candidate_manifests[0].contains(&oldest));
        assert_eq!(report.candidate_blobs, vec![oldest_blob.clone()]);

        let report = store
            .inspect_gc(
                480,
                &GcRoots {
                    manifest_ids: BTreeSet::from([oldest]),
                    blob_sha1s: BTreeSet::from([oldest_blob]),
                },
            )
            .unwrap();
        assert!(report.candidate_manifests.is_empty());
        assert!(report.candidate_blobs.is_empty());
    }

    #[test]
    fn gc_sweep_deletes_old_manifest_and_blob() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let owner = identity(7, "deck");
        for (contents, mtime) in [(b"one".as_slice(), 1), (b"two", 2), (b"three", 3)] {
            commit_file(&store, 480, "save.dat", contents, mtime, &owner);
        }
        let resolved = store.resolve_app(480).unwrap();
        let current = resolved.heads[0].clone();
        let previous = resolved.manifests[&current].parents[0].clone();
        let oldest = resolved.manifests[&previous].parents[0].clone();
        let oldest_blob = resolved.manifests[&oldest].files["save.dat"].sha1.clone();
        let current_blob = resolved.manifests[&current].files["save.dat"].sha1.clone();
        let roots = GcRoots::default();
        let report = store.inspect_gc(480, &roots).unwrap();

        let plan = store.prepare_gc_sweep(&report).unwrap().unwrap();
        let sweep = store.apply_gc_sweep(plan, &roots).unwrap().unwrap();
        assert_eq!(sweep.deleted_manifests, 1);
        assert_eq!(sweep.deleted_blobs, 1);
        assert!(!store
            .commit_dir(480)
            .join(format!("{oldest}.json"))
            .exists());
        assert!(!store.blob_path(480, &oldest_blob).unwrap().exists());
        assert!(store
            .commit_dir(480)
            .join(format!("{current}.json"))
            .exists());
        assert!(store
            .commit_dir(480)
            .join(format!("{previous}.json"))
            .exists());
        assert!(store.blob_path(480, &current_blob).unwrap().exists());
        assert_eq!(store.read(480, "save.dat").unwrap(), b"three");
    }

    #[test]
    fn gc_sweep_aborts_when_inventory_or_roots_change() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let owner = identity(7, "deck");
        for (contents, mtime) in [(b"one".as_slice(), 1), (b"two", 2), (b"three", 3)] {
            commit_file(&store, 480, "save.dat", contents, mtime, &owner);
        }
        let roots = GcRoots::default();
        let report = store.inspect_gc(480, &roots).unwrap();
        let candidate_path = store
            .commit_dir(480)
            .join(format!("{}.json", report.candidate_manifests[0]));
        let candidate_blob = store.blob_path(480, &report.candidate_blobs[0]).unwrap();

        let changed_roots = GcRoots {
            manifest_ids: BTreeSet::new(),
            blob_sha1s: BTreeSet::from([report.candidate_blobs[0].clone()]),
        };
        let plan = store.prepare_gc_sweep(&report).unwrap().unwrap();
        assert!(store
            .apply_gc_sweep(plan, &changed_roots)
            .unwrap()
            .is_none());
        assert!(candidate_path.exists());
        assert!(candidate_blob.exists());

        commit_file(&store, 480, "save.dat", b"four", 4, &owner);
        assert!(store.prepare_gc_sweep(&report).unwrap().is_none());
        assert!(candidate_path.exists());
        assert!(candidate_blob.exists());
    }

    #[test]
    fn gc_sweep_isolates_identical_blobs_by_app() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let owner = identity(7, "deck");
        for (contents, mtime) in [(b"shared".as_slice(), 1), (b"two", 2), (b"three", 3)] {
            commit_file(&store, 480, "save.dat", contents, mtime, &owner);
        }
        commit_file(&store, 481, "save.dat", b"shared", 1, &owner);
        let shared_blob = hex_digest::<Sha1>(b"shared");
        let roots = GcRoots::default();
        let report = store.inspect_gc(480, &roots).unwrap();

        assert!(report.candidate_blobs.contains(&shared_blob));
        let plan = store.prepare_gc_sweep(&report).unwrap().unwrap();
        let sweep = store.apply_gc_sweep(plan, &roots).unwrap().unwrap();
        assert_eq!(sweep.deleted_manifests, 1);
        assert_eq!(sweep.deleted_blobs, 1);
        assert!(!store.blob_path(480, &shared_blob).unwrap().exists());
        assert!(store.blob_path(481, &shared_blob).unwrap().exists());
        assert_eq!(store.read(481, "save.dat").unwrap(), b"shared");
    }

    #[test]
    fn gc_sweep_reclaims_only_the_requested_app_history() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
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
        let other_oldest_blob = other.manifests[&other_oldest].files["save.dat"]
            .sha1
            .clone();
        let roots = GcRoots::default();
        let report = store.inspect_gc(480, &roots).unwrap();

        assert_eq!(report.candidate_manifests.len(), 1);
        assert!(!report.candidate_blobs.contains(&other_oldest_blob));
        let plan = store.prepare_gc_sweep(&report).unwrap().unwrap();
        let sweep = store.apply_gc_sweep(plan, &roots).unwrap().unwrap();
        assert_eq!(sweep.deleted_manifests, 1);
        assert!(store
            .commit_dir(481)
            .join(format!("{other_oldest}.json"))
            .exists());
        assert!(store.blob_path(481, &other_oldest_blob).unwrap().exists());
        assert_eq!(store.resolve_app(481).unwrap().manifests.len(), 3);
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
