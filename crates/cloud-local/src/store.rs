use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
    pub change_number: u64,
    pub heads: Vec<String>,
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
struct SaveCommit {
    version: u32,
    app_id: u32,
    parents: Vec<String>,
    device_id: String,
    created_at_ms: u64,
    nonce: String,
    files: BTreeMap<String, StoredFile>,
}

struct ResolvedApp {
    valid: HashMap<String, SaveCommit>,
    heads: Vec<String>,
    files: BTreeMap<String, StoredFile>,
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
        let resolved = self.resolve_app(app_id)?;
        Ok(StoreView {
            change_number: resolved.valid.len() as u64,
            heads: resolved.heads,
        })
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
    ) -> Result<u64, BackendError> {
        let resolved = self.resolve_app(app_id)?;
        if resolved.heads != base_heads {
            return Err(BackendError::new(
                "local cloud changed after the upload batch began",
                true,
            ));
        }
        let original_files = resolved.files;
        let mut files = original_files.clone();
        for path in deleted {
            validate_cloud_path(path)?;
            files.remove(path);
        }
        for file in staged {
            validate_cloud_path(&file.path)?;
            let blob = self.blob_path(&file.blob_sha1)?;
            if !blob.is_file() {
                return Err(permanent("staged local cloud blob is unavailable"));
            }
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
        if files == original_files && resolved.heads.len() <= 1 {
            return Ok(resolved.valid.len() as u64);
        }

        let commit = SaveCommit {
            version: FORMAT_VERSION,
            app_id,
            parents: base_heads.to_vec(),
            device_id: device_id(),
            created_at_ms: unix_millis(),
            nonce: next_nonce(),
            files,
        };
        let bytes = serde_json::to_vec(&commit).map_err(json_error)?;
        let id = hex_digest::<Sha256>(&bytes);
        let path = self.commit_dir(app_id).join(format!("{id}.json"));
        atomic_publish(&path, &bytes)?;
        let current = self.resolve_app(app_id)?;
        self.materialize_checkout(app_id, &current.files)?;
        Ok(current.valid.len() as u64)
    }

    /// Publish a deterministic merge commit when replicated folders produced
    /// concurrent heads, even when Steam has no file changes of its own.
    pub fn converge_app(&self, app_id: u32) -> Result<u64, BackendError> {
        let view = self.view(app_id)?;
        if view.heads.len() <= 1 {
            return Ok(view.change_number);
        }
        self.commit_batch(app_id, &view.heads, &[], &BTreeSet::new())
    }

    fn initialize(&self) -> Result<(), BackendError> {
        std::fs::create_dir_all(self.root.join("blobs/sha1")).map_err(io_error)?;
        std::fs::create_dir_all(self.root.join("blobs/sha256")).map_err(io_error)?;
        std::fs::create_dir_all(self.root.join("commits/saves")).map_err(io_error)?;
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
        let directory = self.commit_dir(app_id);
        if !directory.exists() {
            return Ok(ResolvedApp {
                valid: HashMap::new(),
                heads: Vec::new(),
                files: BTreeMap::new(),
            });
        }
        let mut candidates = HashMap::new();
        for entry in std::fs::read_dir(&directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            let bytes = std::fs::read(&path).map_err(io_error)?;
            if id.len() != 64 || hex_digest::<Sha256>(&bytes) != id {
                continue;
            }
            let Ok(commit) = serde_json::from_slice::<SaveCommit>(&bytes) else {
                continue;
            };
            if commit.version == FORMAT_VERSION
                && commit.app_id == app_id
                && commit.files.values().all(|file| self.blob_ready(file))
            {
                candidates.insert(id.to_owned(), commit);
            }
        }

        let mut valid = HashMap::new();
        loop {
            let ready = candidates
                .iter()
                .filter(|(id, commit)| {
                    !valid.contains_key(*id)
                        && commit
                            .parents
                            .iter()
                            .all(|parent| valid.contains_key(parent))
                })
                .map(|(id, commit)| (id.clone(), commit.clone()))
                .collect::<Vec<_>>();
            if ready.is_empty() {
                break;
            }
            valid.extend(ready);
        }

        let parents = valid
            .values()
            .flat_map(|commit| commit.parents.iter().cloned())
            .collect::<HashSet<_>>();
        let mut heads = valid
            .keys()
            .filter(|id| !parents.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        heads.sort();
        let files = merge_head_files(&valid, &heads);
        Ok(ResolvedApp {
            valid,
            heads,
            files,
        })
    }

    fn blob_ready(&self, file: &StoredFile) -> bool {
        self.blob_path(&file.sha1)
            .ok()
            .and_then(|path| path.metadata().ok())
            .is_some_and(|metadata| metadata.is_file() && metadata.len() == file.raw_size)
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

fn merge_head_files(
    valid: &HashMap<String, SaveCommit>,
    heads: &[String],
) -> BTreeMap<String, StoredFile> {
    match heads {
        [] => return BTreeMap::new(),
        [head] => return valid[head].files.clone(),
        _ => {}
    }

    let base = nearest_common_ancestor(valid, heads)
        .and_then(|id| valid.get(&id))
        .map(|commit| &commit.files);

    let mut paths = BTreeSet::new();
    if let Some(base) = base {
        paths.extend(base.keys().cloned());
    }
    for head in heads {
        paths.extend(valid[head].files.keys().cloned());
    }

    let mut merged = BTreeMap::new();
    for path in paths {
        let base_value = base.and_then(|files| files.get(&path));
        let changed = heads
            .iter()
            .filter(|head| valid[*head].files.get(&path) != base_value)
            .collect::<Vec<_>>();
        let selected = match changed.as_slice() {
            [] => base_value,
            [head] => valid[*head].files.get(&path),
            _ => {
                let first = valid[changed[0]].files.get(&path);
                if changed
                    .iter()
                    .all(|head| valid[*head].files.get(&path) == first)
                {
                    first
                } else {
                    let winner = changed
                        .into_iter()
                        .max_by(|left, right| compare_commits(valid, left, right))
                        .expect("changed heads are non-empty");
                    valid[winner].files.get(&path)
                }
            }
        };
        if let Some(file) = selected {
            merged.insert(path, file.clone());
        }
    }
    merged
}

fn nearest_common_ancestor(
    valid: &HashMap<String, SaveCommit>,
    heads: &[String],
) -> Option<String> {
    let distances = heads
        .iter()
        .map(|head| ancestor_distances(valid, head))
        .collect::<Vec<_>>();
    let first = distances.first()?;
    first
        .keys()
        .filter(|candidate| {
            distances[1..]
                .iter()
                .all(|distance| distance.contains_key(*candidate))
        })
        .min_by(|left, right| {
            ancestor_distance_metric(&distances, left)
                .cmp(&ancestor_distance_metric(&distances, right))
                .then_with(|| left.cmp(right))
        })
        .cloned()
}

fn ancestor_distances(valid: &HashMap<String, SaveCommit>, head: &str) -> HashMap<String, usize> {
    let mut distances = HashMap::from([(head.to_owned(), 0usize)]);
    let mut pending = std::collections::VecDeque::from([(head.to_owned(), 0usize)]);
    while let Some((id, distance)) = pending.pop_front() {
        let Some(commit) = valid.get(&id) else {
            continue;
        };
        let parent_distance = distance.saturating_add(1);
        for parent in &commit.parents {
            let should_visit = match distances.get(parent) {
                Some(current) => parent_distance < *current,
                None => true,
            };
            if should_visit {
                distances.insert(parent.clone(), parent_distance);
                pending.push_back((parent.clone(), parent_distance));
            }
        }
    }
    distances
}

fn ancestor_distance_metric(
    distances: &[HashMap<String, usize>],
    candidate: &str,
) -> (usize, usize) {
    distances.iter().fold((0, 0), |(maximum, total), map| {
        let distance = map[candidate];
        (maximum.max(distance), total.saturating_add(distance))
    })
}

fn compare_commits(
    valid: &HashMap<String, SaveCommit>,
    left: &str,
    right: &str,
) -> std::cmp::Ordering {
    let left_commit = &valid[left];
    let right_commit = &valid[right];
    left_commit
        .created_at_ms
        .cmp(&right_commit.created_at_ms)
        .then_with(|| left_commit.device_id.cmp(&right_commit.device_id))
        .then_with(|| left.cmp(right))
}

impl ByteStore for FolderStore {
    fn read(&self, app_id: u32, path: &str) -> Result<Vec<u8>, BackendError> {
        validate_cloud_path(path)?;
        let resolved = self.resolve_app(app_id)?;
        let file = resolved
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
        let staged = self.stage_file(path, contents, metadata)?;
        self.commit_batch(app_id, &view.heads, &[staged], &BTreeSet::new())
    }
}

impl CloudFileStore for FolderStore {
    fn changes_since(&self, app_id: u32, _since: u64) -> Result<ChangeList, BackendError> {
        let resolved = self.resolve_app(app_id)?;
        let current = resolved.valid.len() as u64;
        let files = resolved
            .files
            .into_iter()
            .map(|(path, file)| FileEntry {
                path,
                metadata: FileMetadata {
                    sha1: file.sha1,
                    raw_size: file.raw_size,
                    mtime: file.mtime,
                    platforms_to_sync: file.platforms_to_sync,
                },
                change_number: current,
            })
            .collect();
        Ok(ChangeList {
            current_change_number: current,
            files,
            deleted_paths: Vec::new(),
            is_delta: false,
        })
    }

    fn delete(&self, app_id: u32, path: &str) -> Result<u64, BackendError> {
        validate_cloud_path(path)?;
        let view = self.view(app_id)?;
        self.commit_batch(app_id, &view.heads, &[], &BTreeSet::from([path.to_owned()]))
    }

    fn quota(&self, app_id: u32) -> Result<Quota, BackendError> {
        let resolved = self.resolve_app(app_id)?;
        let used_bytes = resolved
            .files
            .values()
            .try_fold(0u64, |total, file| total.checked_add(file.raw_size))
            .ok_or_else(|| permanent("local cloud quota overflow"))?;
        Ok(Quota {
            used_bytes,
            total_bytes: i64::MAX as u64,
            used_files: u32::try_from(resolved.files.len())
                .map_err(|_| permanent("local cloud file count overflow"))?,
            total_files: u32::MAX,
        })
    }

    fn transfer(&self) -> Transfer<'_> {
        Transfer::Bridged(self)
    }
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

    fn publish_commit(
        store: &FolderStore,
        app_id: u32,
        parents: Vec<String>,
        device_id: &str,
        created_at_ms: u64,
        files: BTreeMap<String, StoredFile>,
    ) -> String {
        let commit = SaveCommit {
            version: FORMAT_VERSION,
            app_id,
            parents,
            device_id: device_id.into(),
            created_at_ms,
            nonce: format!("test-{device_id}-{created_at_ms}"),
            files,
        };
        let bytes = serde_json::to_vec(&commit).unwrap();
        let id = hex_digest::<Sha256>(&bytes);
        atomic_publish(&store.commit_dir(app_id).join(format!("{id}.json")), &bytes).unwrap();
        id
    }

    #[test]
    fn immutable_commits_survive_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let contents = b"local save";
        assert_eq!(
            store
                .write(480, "Game/save.dat", contents, &metadata(contents, 10))
                .unwrap(),
            1
        );
        assert!(temporary.path().join("blobs/sha256").is_dir());
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
        store
            .write(480, "old.dat", b"old", &metadata(b"old", 1))
            .unwrap();
        let view = store.view(480).unwrap();
        let staged = store
            .stage_file("new.dat", b"new", &metadata(b"new", 2))
            .unwrap();
        assert_eq!(
            store
                .commit_batch(
                    480,
                    &view.heads,
                    &[staged],
                    &BTreeSet::from(["old.dat".into()]),
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
        store.write(480, "a", b"a", &metadata(b"a", 1)).unwrap();
        let staged = store.stage_file("b", b"b", &metadata(b"b", 2)).unwrap();
        assert!(store
            .commit_batch(480, &base.heads, &[staged], &BTreeSet::new())
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
        assert!(store
            .write(480, "../escape", b"save", &metadata(b"save", 10))
            .is_err());
        let mut wrong = metadata(b"save", 10);
        wrong.sha1 = "0".repeat(40);
        assert!(store.write(480, "save.dat", b"save", &wrong).is_err());
    }

    #[test]
    fn account_scopes_do_not_share_save_manifests_or_checkouts() {
        let temporary = tempfile::tempdir().unwrap();
        let first = FolderStore::open_account(temporary.path(), 76_561_198_000_000_001).unwrap();
        let second = FolderStore::open_account(temporary.path(), 76_561_198_000_000_002).unwrap();

        first
            .write(480, "save.dat", b"first", &metadata(b"first", 1))
            .unwrap();
        second
            .write(480, "save.dat", b"second", &metadata(b"second", 2))
            .unwrap();

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
    fn divergent_heads_merge_changes_and_deletions_then_converge() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        for (path, contents) in [
            ("shared.dat", b"base".as_slice()),
            ("deleted.dat", b"delete".as_slice()),
        ] {
            store
                .write(480, path, contents, &metadata(contents, 1))
                .unwrap();
        }
        let base = store.resolve_app(480).unwrap();
        let parent = base.heads[0].clone();

        let mut left = base.files.clone();
        for (path, contents) in [
            ("left.dat", b"left".as_slice()),
            ("shared.dat", b"left-shared".as_slice()),
        ] {
            let staged = store
                .stage_file(path, contents, &metadata(contents, 20))
                .unwrap();
            left.insert(
                path.into(),
                StoredFile {
                    sha1: staged.blob_sha1,
                    raw_size: staged.metadata.raw_size,
                    mtime: staged.metadata.mtime,
                    platforms_to_sync: staged.metadata.platforms_to_sync,
                },
            );
        }
        publish_commit(&store, 480, vec![parent.clone()], "left", 20, left);

        let mut right = base.files;
        right.remove("deleted.dat");
        for (path, contents) in [
            ("right.dat", b"right".as_slice()),
            ("shared.dat", b"right-shared".as_slice()),
        ] {
            let staged = store
                .stage_file(path, contents, &metadata(contents, 30))
                .unwrap();
            right.insert(
                path.into(),
                StoredFile {
                    sha1: staged.blob_sha1,
                    raw_size: staged.metadata.raw_size,
                    mtime: staged.metadata.mtime,
                    platforms_to_sync: staged.metadata.platforms_to_sync,
                },
            );
        }
        publish_commit(&store, 480, vec![parent], "right", 30, right);

        let merged = store.resolve_app(480).unwrap();
        assert_eq!(merged.heads.len(), 2);
        assert!(merged.files.contains_key("left.dat"));
        assert!(merged.files.contains_key("right.dat"));
        assert!(!merged.files.contains_key("deleted.dat"));
        assert_eq!(store.read(480, "shared.dat").unwrap(), b"right-shared");

        store.converge_app(480).unwrap();
        assert_eq!(store.view(480).unwrap().heads.len(), 1);
    }

    #[test]
    fn merge_base_uses_graph_distance_when_clocks_move_backwards() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();

        let root_file = store
            .stage_file("save.dat", b"root", &metadata(b"root", 1))
            .unwrap();
        let root_files = BTreeMap::from([(
            root_file.path,
            StoredFile {
                sha1: root_file.blob_sha1,
                raw_size: root_file.metadata.raw_size,
                mtime: root_file.metadata.mtime,
                platforms_to_sync: root_file.metadata.platforms_to_sync,
            },
        )]);
        let root = publish_commit(&store, 480, Vec::new(), "root", 1_000, root_files.clone());

        let shared_file = store
            .stage_file("save.dat", b"shared", &metadata(b"shared", 2))
            .unwrap();
        let mut shared_files = root_files;
        shared_files.insert(
            shared_file.path,
            StoredFile {
                sha1: shared_file.blob_sha1,
                raw_size: shared_file.metadata.raw_size,
                mtime: shared_file.metadata.mtime,
                platforms_to_sync: shared_file.metadata.platforms_to_sync,
            },
        );
        let shared = publish_commit(&store, 480, vec![root], "shared", 10, shared_files.clone());

        let left_file = store
            .stage_file("save.dat", b"left", &metadata(b"left", 3))
            .unwrap();
        let mut left_files = shared_files.clone();
        left_files.insert(
            left_file.path,
            StoredFile {
                sha1: left_file.blob_sha1,
                raw_size: left_file.metadata.raw_size,
                mtime: left_file.metadata.mtime,
                platforms_to_sync: left_file.metadata.platforms_to_sync,
            },
        );
        publish_commit(&store, 480, vec![shared.clone()], "left", 20, left_files);
        publish_commit(&store, 480, vec![shared], "right", 30, shared_files);

        assert_eq!(store.read(480, "save.dat").unwrap(), b"left");
    }
}
