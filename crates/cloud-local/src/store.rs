use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeepLocalResolution {
    pub heads: Vec<String>,
    pub selected_head: String,
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
    pub retained_manifests: Vec<String>,
    pub candidate_manifests: Vec<String>,
    pub retained_blobs: Vec<String>,
    pub candidate_blobs: Vec<String>,
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
    nonce: String,
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
    Exited,
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
    updated_at: u32,
    nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredKeepLocalResolution {
    version: u32,
    app_id: u32,
    heads: Vec<String>,
    selected_head: String,
    client_id: u64,
    machine_name: String,
    nonce: String,
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
        let store = Self { root, account };
        store.initialize()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn view(&self, app_id: u32) -> Result<StoreView, BackendError> {
        validate_app_id(app_id)?;
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
        path: &str,
        contents: &[u8],
        metadata: &FileMetadata,
    ) -> Result<StagedFile, BackendError> {
        validate_cloud_path(path)?;
        validate_metadata(contents, metadata)?;
        let blob_sha1 = metadata.sha1.to_ascii_lowercase();
        self.publish_blob(&blob_sha1, contents)?;
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
        let _lock = self.lock_repository()?;
        let resolved = self.resolve_app(app_id)?;
        let base_heads = normalized_head_ids(base_heads)?;
        let resolution_heads = resolution_heads.map(normalized_head_ids).transpose()?;
        let clears_keep_local = resolution_heads.is_some();
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
        self.verify_files(&files)?;
        if files == original_files && !force_publish {
            return Ok(resolved
                .current()?
                .map_or(0, |(_, manifest)| manifest.revision));
        }
        let revision =
            self.publish_manifest(app_id, parents, files, identity, resolved.max_revision)?;
        if clears_keep_local && self.account.is_some() {
            remove_if_exists(&self.keep_local_resolution_path(app_id, identity.client_id)?)?;
        }
        Ok(revision)
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
        let _lock = self.lock_repository()?;
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
        self.verify_files(&selected.files)?;
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
        let _lock = self.lock_repository()?;
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
        self.verify_files(&selected.files)?;
        self.publish_manifest(
            app_id,
            resolved.heads,
            selected.files.clone(),
            identity,
            resolved.max_revision,
        )
        .map(Some)
    }

    pub fn record_keep_local_resolution(
        &self,
        app_id: u32,
        expected_heads: &[String],
        selected_head: &str,
        identity: &CommitIdentity,
    ) -> Result<(), BackendError> {
        validate_app_id(app_id)?;
        validate_identity(identity)?;
        let _lock = self.lock_repository()?;
        let resolved = self.resolve_app(app_id)?;
        let heads = normalized_head_ids(expected_heads)?;
        if heads.len() < 2 || resolved.heads != heads {
            return Err(conflict(
                "local cloud conflict heads changed before resolution",
            ));
        }
        if !heads.iter().any(|head| head == selected_head) {
            return Err(permanent(
                "selected local conflict manifest is not an active head",
            ));
        }
        let stored = StoredKeepLocalResolution {
            version: FORMAT_VERSION,
            app_id,
            heads,
            selected_head: selected_head.to_owned(),
            client_id: identity.client_id,
            machine_name: identity.machine_name.clone(),
            nonce: next_nonce(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(json_error)?;
        atomic_replace(
            &self.keep_local_resolution_path(app_id, identity.client_id)?,
            &bytes,
        )
    }

    pub fn keep_local_resolution(
        &self,
        app_id: u32,
        client_id: u64,
    ) -> Result<Option<KeepLocalResolution>, BackendError> {
        validate_app_id(app_id)?;
        if client_id == 0 {
            return Err(permanent("local cloud client identity is unavailable"));
        }
        let path = self.keep_local_resolution_path(app_id, client_id)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        let stored = serde_json::from_slice::<StoredKeepLocalResolution>(&bytes)
            .map_err(|_| incomplete("local cloud keep-local decision is incomplete"))?;
        validate_keep_local_resolution(app_id, client_id, &stored)?;
        let resolved = self.resolve_app(app_id)?;
        if resolved.heads != stored.heads {
            if resolved.heads.len() <= 1 {
                remove_if_exists(&path)?;
                return Ok(None);
            }
            return Err(conflict(
                "local cloud conflict heads changed after the keep-local decision",
            ));
        }
        Ok(Some(KeepLocalResolution {
            heads: stored.heads,
            selected_head: stored.selected_head,
            client_id: stored.client_id,
            machine_name: stored.machine_name,
        }))
    }

    pub fn clear_keep_local_resolution(
        &self,
        app_id: u32,
        client_id: u64,
    ) -> Result<(), BackendError> {
        remove_if_exists(&self.keep_local_resolution_path(app_id, client_id)?)
    }

    pub fn inspect_gc(&self, active: &GcRoots) -> Result<GcReport, BackendError> {
        let manifest_root = self.root.join("commits/saves");
        let mut manifests = BTreeMap::<String, SaveManifest>::new();
        collect_manifest_objects(&manifest_root, &manifest_root, &mut manifests)?;

        let mut retained = BTreeSet::new();
        let mut manifests_by_scope = BTreeMap::<String, BTreeSet<String>>::new();
        for path in manifests.keys() {
            let scope = manifest_scope(path)?;
            manifests_by_scope
                .entry(scope)
                .or_default()
                .insert(manifest_id(path)?.to_string());
        }
        for ids in manifests_by_scope.values() {
            let referenced = ids
                .iter()
                .filter_map(|id| {
                    manifests
                        .iter()
                        .find(|(path, _)| manifest_id(path).ok() == Some(id.as_str()))
                        .map(|(_, manifest)| manifest)
                })
                .flat_map(|manifest| manifest.parents.iter())
                .collect::<BTreeSet<_>>();
            let heads = ids
                .iter()
                .filter(|id| !referenced.contains(id))
                .cloned()
                .collect::<Vec<_>>();
            for head in heads {
                retained.insert(head.clone());
                let manifest = manifests
                    .iter()
                    .find(|(path, _)| manifest_id(path).ok() == Some(head.as_str()))
                    .map(|(_, manifest)| manifest)
                    .ok_or_else(|| incomplete("local cloud GC lost a manifest head"))?;
                retained.extend(
                    manifest
                        .parents
                        .iter()
                        .filter(|parent| ids.contains(*parent))
                        .cloned(),
                );
            }
        }
        retained.extend(active.manifest_ids.iter().cloned());
        if !active.manifest_ids.iter().all(|id| {
            manifests
                .keys()
                .any(|path| manifest_id(path).ok() == Some(id))
        }) {
            return Err(incomplete("local cloud GC active manifest is unavailable"));
        }

        let mut retained_manifest_paths = BTreeSet::new();
        let mut retained_blobs = active.blob_sha1s.clone();
        for (path, manifest) in &manifests {
            if retained.contains(manifest_id(path)?) {
                retained_manifest_paths.insert(path.clone());
                for file in manifest.files.values() {
                    self.read_blob(file)?;
                    retained_blobs.insert(file.sha1.clone());
                }
            }
        }

        let all_blobs = collect_blob_objects(&self.root.join("blobs/sha1"))?;
        if !retained_blobs.iter().all(|sha1| all_blobs.contains(sha1)) {
            return Err(incomplete("local cloud GC active blob is unavailable"));
        }
        let candidate_manifests = manifests
            .keys()
            .filter(|path| !retained_manifest_paths.contains(*path))
            .cloned()
            .collect();
        let candidate_blobs = all_blobs.difference(&retained_blobs).cloned().collect();
        Ok(GcReport {
            retained_manifests: retained_manifest_paths.into_iter().collect(),
            candidate_manifests,
            retained_blobs: retained_blobs.into_iter().collect(),
            candidate_blobs,
        })
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
            nonce: next_nonce(),
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
        self.materialize_checkout(app_id, &current_manifest.files)?;
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
        let claims = self.read_session_claims(app_id)?;
        let superseded = self.read_session_overrides(app_id)?;
        let pending = claims
            .iter()
            .filter(|(id, claim)| {
                claim.client_id != identity.client_id
                    && claim.status != SessionStatus::Exited
                    && !superseded.contains(id)
            })
            .map(|(_, claim)| SessionPeer {
                client_id: claim.client_id,
                machine_name: claim.machine_name.clone(),
                time_last_updated: claim.updated_at,
                os_type: claim.os_type,
                device_type: claim.device_type,
            })
            .collect::<Vec<_>>();
        if !pending.is_empty() && !ignore_pending {
            return Ok(pending);
        }
        if !pending.is_empty() {
            let mut superseded_claims = superseded;
            superseded_claims.extend(
                claims
                    .iter()
                    .filter(|(_, claim)| {
                        claim.client_id != identity.client_id
                            && claim.status != SessionStatus::Exited
                    })
                    .map(|(id, _)| id.clone()),
            );
            let mut superseded_claims = superseded_claims.into_iter().collect::<Vec<_>>();
            superseded_claims.sort();
            let override_record = SessionOverride {
                version: FORMAT_VERSION,
                app_id,
                client_id: identity.client_id,
                superseded_claims,
                updated_at: unix_seconds(),
                nonce: next_nonce(),
            };
            self.write_session_override(&override_record)?;
        }
        self.write_session_claim(SessionClaim {
            version: FORMAT_VERSION,
            app_id,
            client_id: identity.client_id,
            machine_name: identity.machine_name.clone(),
            os_type,
            device_type,
            status: SessionStatus::Active,
            observed_heads: self.view(app_id)?.head_ids(),
            updated_at: unix_seconds(),
            nonce: next_nonce(),
        })?;
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
        self.update_session(app_id, identity, SessionStatus::Exited)
    }

    fn update_session(
        &self,
        app_id: u32,
        identity: &CommitIdentity,
        status: SessionStatus,
    ) -> Result<(), BackendError> {
        validate_app_id(app_id)?;
        validate_identity(identity)?;
        let mut claims = self
            .read_session_claims(app_id)?
            .into_iter()
            .filter(|(_, claim)| claim.client_id == identity.client_id)
            .map(|(_, claim)| claim)
            .collect::<Vec<_>>();
        claims.sort_by_key(|claim| claim.updated_at);
        let mut claim = claims
            .pop()
            .ok_or_else(|| conflict("local cloud session does not belong to this client"))?;
        claim.machine_name = identity.machine_name.clone();
        claim.status = status;
        claim.observed_heads = self.view(app_id)?.head_ids();
        claim.updated_at = unix_seconds();
        claim.nonce = next_nonce();
        self.write_session_claim(claim)
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
            let bytes = std::fs::read(path).map_err(io_error)?;
            let claim = serde_json::from_slice::<SessionClaim>(&bytes)
                .map_err(|_| incomplete("local cloud session claim is incomplete"))?;
            validate_session_claim(app_id, &claim)?;
            claims.push((hex_digest::<Sha256>(&bytes), claim));
        }
        Ok(claims)
    }

    fn read_session_overrides(&self, app_id: u32) -> Result<HashSet<String>, BackendError> {
        let directory = self.session_dir(app_id)?.join("overrides");
        if !directory.exists() {
            return Ok(HashSet::new());
        }
        let mut superseded = HashSet::new();
        for entry in std::fs::read_dir(directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record =
                serde_json::from_slice::<SessionOverride>(&std::fs::read(path).map_err(io_error)?)
                    .map_err(|_| incomplete("local cloud session override is incomplete"))?;
            validate_session_override(app_id, &record)?;
            superseded.extend(record.superseded_claims);
        }
        Ok(superseded)
    }

    fn write_session_claim(&self, claim: SessionClaim) -> Result<(), BackendError> {
        let path = self
            .session_dir(claim.app_id)?
            .join("claims")
            .join(format!("{}.json", claim.client_id));
        let bytes = serde_json::to_vec(&claim).map_err(json_error)?;
        atomic_replace(&path, &bytes)
    }

    fn write_session_override(&self, record: &SessionOverride) -> Result<(), BackendError> {
        let path = self
            .session_dir(record.app_id)?
            .join("overrides")
            .join(format!("{}.json", record.client_id));
        let bytes = serde_json::to_vec(record).map_err(json_error)?;
        atomic_replace(&path, &bytes)
    }

    fn initialize(&self) -> Result<(), BackendError> {
        std::fs::create_dir_all(self.root.join("blobs/sha1")).map_err(io_error)?;
        std::fs::create_dir_all(self.root.join("commits/saves")).map_err(io_error)?;
        std::fs::create_dir_all(self.root.join("sessions")).map_err(io_error)?;
        std::fs::create_dir_all(self.root.join("records")).map_err(io_error)?;
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

    fn commit_dir(&self, app_id: u32) -> PathBuf {
        let mut directory = self.root.join("commits/saves");
        if let Some(account) = &self.account {
            directory.push(account);
        }
        directory.join(app_id.to_string())
    }

    fn session_dir(&self, app_id: u32) -> Result<PathBuf, BackendError> {
        let account = self
            .account
            .as_deref()
            .ok_or_else(|| permanent("local cloud session requires an account"))?;
        Ok(self
            .root
            .join("sessions")
            .join(account)
            .join(app_id.to_string()))
    }

    fn keep_local_resolution_path(
        &self,
        app_id: u32,
        client_id: u64,
    ) -> Result<PathBuf, BackendError> {
        Ok(self
            .session_dir(app_id)?
            .join("resolutions")
            .join(format!("{client_id}.json")))
    }

    fn lock_repository(&self) -> Result<File, BackendError> {
        let path = self.root.join(".vapor-forge.commit.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(io_error)?;
        FileExt::lock_exclusive(&file).map_err(io_error)?;
        Ok(file)
    }

    fn blob_path(&self, hash: &str) -> Result<PathBuf, BackendError> {
        if hash.len() != 40 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(permanent("invalid local cloud blob hash"));
        }
        Ok(self.root.join("blobs/sha1").join(&hash[..2]).join(hash))
    }

    fn publish_blob(&self, hash: &str, contents: &[u8]) -> Result<(), BackendError> {
        atomic_publish(&self.blob_path(hash)?, contents)
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
            self.verify_files(&manifest.files)?;
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

    fn verify_files(&self, files: &BTreeMap<String, StoredFile>) -> Result<(), BackendError> {
        for (path, file) in files {
            validate_cloud_path(path)?;
            self.read_blob(file)?;
        }
        Ok(())
    }

    fn materialize_checkout(
        &self,
        app_id: u32,
        files: &BTreeMap<String, StoredFile>,
    ) -> Result<(), BackendError> {
        let mut root = self.root.join("checkouts").join(device_id());
        if let Some(account) = &self.account {
            root.push(account);
        }
        root.push(app_id.to_string());
        std::fs::create_dir_all(&root).map_err(io_error)?;
        for (path, file) in files {
            let destination = joined_cloud_path(&root, path)?;
            let bytes = self.read_blob(file)?;
            atomic_replace(&destination, &bytes)?;
        }
        remove_unlisted_files(&root, &root, &files.keys().cloned().collect())
    }

    fn read_blob(&self, file: &StoredFile) -> Result<Vec<u8>, BackendError> {
        let bytes = std::fs::read(self.blob_path(&file.sha1)?).map_err(io_error)?;
        if bytes.len() as u64 != file.raw_size || hex_digest::<Sha1>(&bytes) != file.sha1 {
            return Err(permanent("local cloud blob failed integrity verification"));
        }
        Ok(bytes)
    }
}

impl ByteStore for FolderStore {
    fn read(&self, app_id: u32, path: &str) -> Result<Vec<u8>, BackendError> {
        validate_cloud_path(path)?;
        let resolved = self.resolve_app(app_id)?;
        let (_, current) = resolved
            .current()?
            .ok_or_else(|| permanent("local cloud file not found"))?;
        let file = current
            .files
            .get(path)
            .ok_or_else(|| permanent(format!("local cloud file not found: {path}")))?;
        self.read_blob(file)
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
        let staged = self.stage_file(path, contents, metadata)?;
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
    if manifest.version != FORMAT_VERSION
        || manifest.app_id != app_id
        || manifest.revision == 0
        || manifest.nonce.is_empty()
        || manifest.nonce.len() > 255
        || manifest.nonce.contains('\0')
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
        || record.updated_at == 0
        || record.nonce.is_empty()
        || normalized_head_ids(&record.superseded_claims)? != record.superseded_claims
    {
        return Err(permanent("invalid local cloud session override"));
    }
    Ok(())
}

fn validate_keep_local_resolution(
    app_id: u32,
    client_id: u64,
    record: &StoredKeepLocalResolution,
) -> Result<(), BackendError> {
    if record.version != FORMAT_VERSION
        || record.app_id != app_id
        || record.client_id != client_id
        || record.nonce.is_empty()
        || !record
            .heads
            .iter()
            .any(|head| head == &record.selected_head)
        || normalized_head_ids(&record.heads)? != record.heads
    {
        return Err(permanent("invalid local cloud keep-local decision"));
    }
    validate_identity(&CommitIdentity {
        client_id: record.client_id,
        machine_name: record.machine_name.clone(),
    })
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

fn joined_cloud_path(root: &Path, path: &str) -> Result<PathBuf, BackendError> {
    validate_cloud_path(path)?;
    let mut result = root.to_owned();
    for component in path.split('/') {
        result.push(component);
    }
    Ok(result)
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
    let parent = path
        .parent()
        .ok_or_else(|| permanent("local cloud checkout has no parent directory"))?;
    std::fs::create_dir_all(parent).map_err(io_error)?;
    let temporary = parent.join(format!(".syncthing.{}.tmp", next_nonce()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(io_error)
}

fn remove_if_exists(path: &Path) -> Result<(), BackendError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn remove_unlisted_files(
    root: &Path,
    directory: &Path,
    listed: &BTreeSet<String>,
) -> Result<(), BackendError> {
    for entry in std::fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let path = entry.path();
        if path.is_dir() {
            remove_unlisted_files(root, &path, listed)?;
            if std::fs::read_dir(&path).map_err(io_error)?.next().is_none() {
                std::fs::remove_dir(&path).map_err(io_error)?;
            }
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| permanent("local checkout escaped its root"))?
                .to_string_lossy()
                .replace('\\', "/");
            if !listed.contains(&relative) {
                std::fs::remove_file(path).map_err(io_error)?;
            }
        }
    }
    Ok(())
}

fn collect_manifest_objects(
    root: &Path,
    directory: &Path,
    manifests: &mut BTreeMap<String, SaveManifest>,
) -> Result<(), BackendError> {
    if !directory.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let file_type = entry.file_type().map_err(io_error)?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_manifest_objects(root, &path, manifests)?;
            continue;
        }
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
        let relative = path
            .strip_prefix(root)
            .map_err(|_| permanent("local cloud manifest escaped its namespace"))?;
        let components = relative
            .components()
            .map(|component| component.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| incomplete("local cloud manifest path is not UTF-8"))?;
        let app_component = match components.as_slice() {
            [app_id, _] => *app_id,
            [account, app_id, _] if account.parse::<u64>().is_ok_and(|account| account != 0) => {
                *app_id
            }
            _ => return Err(permanent("invalid local cloud manifest path")),
        };
        let app_id = app_component
            .parse::<u32>()
            .map_err(|_| permanent("invalid local cloud manifest AppID"))?;
        if app_id == 0 {
            continue;
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
        let key = components.join("/");
        if manifests.insert(key, manifest).is_some() {
            return Err(permanent("duplicate local cloud manifest path"));
        }
    }
    Ok(())
}

fn manifest_scope(path: &str) -> Result<String, BackendError> {
    Path::new(path)
        .parent()
        .map(|parent| parent.to_string_lossy().replace('\\', "/"))
        .filter(|scope| !scope.is_empty())
        .ok_or_else(|| permanent("invalid local cloud manifest scope"))
}

fn manifest_id(path: &str) -> Result<&str, BackendError> {
    Path::new(path)
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| permanent("invalid local cloud manifest id"))
}

fn collect_blob_objects(root: &Path) -> Result<BTreeSet<String>, BackendError> {
    if !root.exists() {
        return Err(incomplete("local cloud blob namespace is unavailable"));
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

fn device_id() -> String {
    vapor_forge_cloud_core::device_descriptor()
        .map(|descriptor| format!("{:016x}", descriptor.client_id))
        .unwrap_or_else(|| "local".to_string())
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
            nonce: format!("test-{}-{created_at_ms}", identity.client_id),
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
            .stage_file(path, contents, &metadata(contents, mtime))
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
                    .stage_file("save.dat", b"left", &metadata(b"left", 2))
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
                    .stage_file("save.dat", b"right", &metadata(b"right", 3))
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
    fn batch_publishes_one_commit_for_uploads_and_deletes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let identity = identity(7, "deck");
        commit_file(&store, 480, "old.dat", b"old", 1, &identity);
        let view = store.view(480).unwrap();
        let staged = store
            .stage_file("new.dat", b"new", &metadata(b"new", 2))
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
        let staged = store.stage_file("b", b"b", &metadata(b"b", 2)).unwrap();
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

        let staged = store.stage_file("save.dat", contents, &metadata).unwrap();

        assert_eq!(staged.blob_sha1, metadata.sha1);
        assert!(directory
            .path()
            .join("blobs/sha1")
            .join(&metadata.sha1[..2])
            .join(&metadata.sha1)
            .is_file());
        // Re-staging identical contents must not fail, and must not need a
        // second digest pass to prove it.
        assert!(store.stage_file("save.dat", contents, &metadata).is_ok());
    }

    #[test]
    fn rejects_escape_paths_and_bad_hashes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let identity = identity(7, "deck");
        let staged = store.stage_file("../escape", b"save", &metadata(b"save", 10));
        assert!(staged.is_err());
        assert!(store
            .commit_batch(0, &[], &[], &BTreeSet::new(), &identity, None)
            .is_err());
        let mut wrong = metadata(b"save", 10);
        wrong.sha1 = "0".repeat(40);
        assert!(store.stage_file("save.dat", b"save", &wrong).is_err());
    }

    #[test]
    fn account_scopes_do_not_share_save_manifests_or_checkouts() {
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
            .join("commits/saves/76561198000000001/480")
            .is_dir());
        assert!(temporary
            .path()
            .join("commits/saves/76561198000000002/480")
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
            .stage_file("save.dat", b"chosen", &metadata(b"chosen", 4))
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
    fn keep_local_decision_survives_reopen_and_clears_after_commit() {
        let temporary = tempfile::tempdir().unwrap();
        let account = 76_561_198_000_000_001;
        let store = FolderStore::open_account(temporary.path(), account).unwrap();
        let (left, right) = divergent_heads(&store);
        let heads = normalized_head_ids(&[left.clone(), right]).unwrap();
        let resolver = identity(7, "deck");
        store
            .record_keep_local_resolution(480, &heads, &left, &resolver)
            .unwrap();
        drop(store);

        let reopened = FolderStore::open_account(temporary.path(), account).unwrap();
        let decision = reopened
            .keep_local_resolution(480, resolver.client_id)
            .unwrap()
            .unwrap();
        assert_eq!(decision.heads, heads);
        assert_eq!(decision.selected_head, left);
        assert_eq!(decision.machine_name, resolver.machine_name);

        let staged = reopened
            .stage_file("save.dat", b"chosen", &metadata(b"chosen", 4))
            .unwrap();
        reopened
            .commit_batch(
                480,
                &[decision.selected_head],
                &[staged],
                &BTreeSet::new(),
                &resolver,
                Some(&decision.heads),
            )
            .unwrap();
        assert!(reopened
            .keep_local_resolution(480, resolver.client_id)
            .unwrap()
            .is_none());
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
        std::fs::remove_file(store.blob_path(&file.sha1).unwrap()).unwrap();
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

        let report = store.inspect_gc(&GcRoots::default()).unwrap();
        assert_eq!(report.retained_manifests.len(), 2);
        assert_eq!(report.candidate_manifests.len(), 1);
        assert!(report.candidate_manifests[0].contains(&oldest));
        assert_eq!(report.candidate_blobs, vec![oldest_blob.clone()]);

        let report = store
            .inspect_gc(&GcRoots {
                manifest_ids: BTreeSet::from([oldest]),
                blob_sha1s: BTreeSet::from([oldest_blob]),
            })
            .unwrap();
        assert!(report.candidate_manifests.is_empty());
        assert!(report.candidate_blobs.is_empty());
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
        store.resume_session(480, &second).unwrap();
        store.exit_session(480, &second).unwrap();
        assert!(store.exit_session(480, &identity(9, "other")).is_err());
    }

    #[test]
    fn repeated_session_override_retains_older_claim_ids() {
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
        let record =
            serde_json::from_slice::<SessionOverride>(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(record.superseded_claims.len(), 2);
        assert!(store
            .launch_session(480, &second, Some(3), Some(4), false)
            .unwrap()
            .is_empty());
    }
}
