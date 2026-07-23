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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFile {
    pub path: String,
    pub blob_sha256: String,
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
    blob_sha256: String,
    steam_sha1: String,
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
        let root = root.as_ref();
        if root.as_os_str().is_empty() {
            return Err(permanent("local cloud path is empty"));
        }
        std::fs::create_dir_all(root).map_err(io_error)?;
        let root = root.canonicalize().map_err(io_error)?;
        let store = Self { root };
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
        let blob_sha256 = hex_digest::<Sha256>(contents);
        self.publish_blob(&blob_sha256, contents)?;
        Ok(StagedFile {
            path: path.to_owned(),
            blob_sha256,
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
            let blob = self.blob_path(&file.blob_sha256)?;
            if !blob.is_file() {
                return Err(permanent("staged local cloud blob is unavailable"));
            }
            files.insert(
                file.path.clone(),
                StoredFile {
                    blob_sha256: file.blob_sha256.clone(),
                    steam_sha1: file.metadata.sha1.clone(),
                    raw_size: file.metadata.raw_size,
                    mtime: file.metadata.mtime,
                    platforms_to_sync: file.metadata.platforms_to_sync,
                },
            );
        }
        if files == original_files {
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

    fn initialize(&self) -> Result<(), BackendError> {
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
        self.root.join("commits/saves").join(app_id.to_string())
    }

    fn blob_path(&self, hash: &str) -> Result<PathBuf, BackendError> {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(permanent("invalid local cloud blob hash"));
        }
        Ok(self.root.join("blobs/sha256").join(&hash[..2]).join(hash))
    }

    fn publish_blob(&self, hash: &str, contents: &[u8]) -> Result<(), BackendError> {
        let path = self.blob_path(hash)?;
        if path.exists() {
            let existing = std::fs::read(&path).map_err(io_error)?;
            if hex_digest::<Sha256>(&existing) != hash {
                return Err(permanent("local cloud blob hash collision"));
            }
            return Ok(());
        }
        atomic_publish(&path, contents)
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
        let files = match heads.as_slice() {
            [] => BTreeMap::new(),
            [head] => valid[head].files.clone(),
            _ => {
                let first = &valid[&heads[0]].files;
                if heads.iter().all(|head| &valid[head].files == first) {
                    first.clone()
                } else {
                    return Err(BackendError::new(
                        "local cloud contains concurrent save commits",
                        false,
                    ));
                }
            }
        };
        Ok(ResolvedApp {
            valid,
            heads,
            files,
        })
    }

    fn blob_ready(&self, file: &StoredFile) -> bool {
        self.blob_path(&file.blob_sha256)
            .ok()
            .and_then(|path| path.metadata().ok())
            .is_some_and(|metadata| metadata.is_file() && metadata.len() == file.raw_size)
    }

    fn materialize_checkout(
        &self,
        app_id: u32,
        files: &BTreeMap<String, StoredFile>,
    ) -> Result<(), BackendError> {
        let root = self
            .root
            .join("checkouts")
            .join(device_id())
            .join(app_id.to_string());
        std::fs::create_dir_all(&root).map_err(io_error)?;
        for (path, file) in files {
            let destination = joined_cloud_path(&root, path)?;
            let bytes = self.read_blob(file)?;
            atomic_replace(&destination, &bytes)?;
        }
        remove_unlisted_files(&root, &root, &files.keys().cloned().collect())
    }

    fn read_blob(&self, file: &StoredFile) -> Result<Vec<u8>, BackendError> {
        let bytes = std::fs::read(self.blob_path(&file.blob_sha256)?).map_err(io_error)?;
        if bytes.len() as u64 != file.raw_size
            || hex_digest::<Sha256>(&bytes) != file.blob_sha256
            || hex_digest::<Sha1>(&bytes) != file.steam_sha1
        {
            return Err(permanent("local cloud blob failed integrity verification"));
        }
        Ok(bytes)
    }
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
                    sha1: file.steam_sha1,
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

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), BackendError> {
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
}
