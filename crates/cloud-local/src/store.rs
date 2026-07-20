use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha1::{Digest, Sha1};
use std::path::{Path, PathBuf};
use std::time::Duration;
use vapor_forge_cloud_core::{
    BackendError, ByteStore, ChangeList, CloudFileStore, FileEntry, FileMetadata, Quota, Transfer,
};

const DATABASE_NAME: &str = ".vapor-forge-cloud.sqlite3";

#[derive(Clone)]
pub struct FolderStore {
    root: PathBuf,
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
        store.connection()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn connection(&self) -> Result<Connection, BackendError> {
        let connection = Connection::open(self.root.join(DATABASE_NAME)).map_err(sql_error)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(sql_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(sql_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(sql_error)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS apps (
                    app_id INTEGER PRIMARY KEY,
                    change_number INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE IF NOT EXISTS files (
                    app_id INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    sha1 TEXT,
                    raw_size INTEGER,
                    mtime INTEGER,
                    platforms_to_sync INTEGER,
                    change_number INTEGER NOT NULL,
                    deleted INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (app_id, path)
                 );
                 CREATE INDEX IF NOT EXISTS files_changes
                    ON files(app_id, change_number);",
            )
            .map_err(sql_error)?;
        Ok(connection)
    }

    fn file_path(&self, app_id: u32, cloud_path: &str) -> Result<PathBuf, BackendError> {
        validate_cloud_path(cloud_path)?;
        let mut path = self.root.join(app_id.to_string()).join("files");
        for component in cloud_path.split('/') {
            path.push(component);
        }
        Ok(path)
    }

    fn current_change(connection: &Connection, app_id: u32) -> Result<u64, BackendError> {
        connection
            .query_row(
                "SELECT change_number FROM apps WHERE app_id = ?1",
                params![app_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(sql_error)?
            .map(sql_u64)
            .transpose()
            .map(|value| value.unwrap_or(0))
    }
}

impl ByteStore for FolderStore {
    fn read(&self, app_id: u32, path: &str) -> Result<Vec<u8>, BackendError> {
        let connection = self.connection()?;
        let present = connection
            .query_row(
                "SELECT deleted FROM files WHERE app_id = ?1 AND path = ?2",
                params![app_id, path],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(sql_error)?
            .is_some_and(|deleted| !deleted);
        if !present {
            return Err(permanent(format!("local cloud file not found: {path}")));
        }
        std::fs::read(self.file_path(app_id, path)?).map_err(io_error)
    }

    fn write(
        &self,
        app_id: u32,
        path: &str,
        contents: &[u8],
        metadata: &FileMetadata,
    ) -> Result<u64, BackendError> {
        validate_metadata(contents, metadata)?;
        let destination = self.file_path(app_id, path)?;
        let parent = destination
            .parent()
            .ok_or_else(|| permanent("local cloud file has no parent directory"))?;
        std::fs::create_dir_all(parent).map_err(io_error)?;
        reject_symlink_ancestors(&self.root, parent)?;

        let temporary = parent.join(format!(
            ".vapor-forge-upload-{}-{}",
            std::process::id(),
            next_temporary_id()
        ));
        let write_result = (|| {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(io_error)?;
            file.write_all(contents).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            Ok::<(), BackendError>(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }

        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let current = Self::current_change(&transaction, app_id)?;
        let next = current
            .checked_add(1)
            .ok_or_else(|| permanent("local cloud change number overflow"))?;
        std::fs::rename(&temporary, &destination).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            io_error(error)
        })?;
        transaction
            .execute(
                "INSERT INTO apps(app_id, change_number) VALUES (?1, ?2)
                 ON CONFLICT(app_id) DO UPDATE SET change_number = excluded.change_number",
                params![app_id, sql_i64(next)?],
            )
            .map_err(sql_error)?;
        transaction
            .execute(
                "INSERT INTO files(
                    app_id, path, sha1, raw_size, mtime, platforms_to_sync,
                    change_number, deleted
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)
                 ON CONFLICT(app_id, path) DO UPDATE SET
                    sha1 = excluded.sha1,
                    raw_size = excluded.raw_size,
                    mtime = excluded.mtime,
                    platforms_to_sync = excluded.platforms_to_sync,
                    change_number = excluded.change_number,
                    deleted = 0",
                params![
                    app_id,
                    path,
                    metadata.sha1,
                    sql_i64(metadata.raw_size)?,
                    metadata.mtime,
                    i64::from(metadata.platforms_to_sync),
                    sql_i64(next)?,
                ],
            )
            .map_err(sql_error)?;
        transaction.commit().map_err(sql_error)?;
        Ok(next)
    }
}

impl CloudFileStore for FolderStore {
    fn changes_since(&self, app_id: u32, since: u64) -> Result<ChangeList, BackendError> {
        let connection = self.connection()?;
        let current = Self::current_change(&connection, app_id)?;
        let full = since == 0 || since > current;
        let mut statement = connection
            .prepare(
                "SELECT path, sha1, raw_size, mtime, platforms_to_sync,
                        change_number, deleted
                 FROM files
                 WHERE app_id = ?1 AND (?2 OR change_number > ?3)
                 ORDER BY path",
            )
            .map_err(sql_error)?;
        let rows = statement
            .query_map(params![app_id, full, sql_i64(since.min(current))?], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            })
            .map_err(sql_error)?;
        let mut files = Vec::new();
        let mut deleted_paths = Vec::new();
        for row in rows {
            let (path, sha1, raw_size, mtime, platforms, change, deleted) =
                row.map_err(sql_error)?;
            if deleted {
                if !full {
                    deleted_paths.push(path);
                }
                continue;
            }
            files.push(FileEntry {
                path,
                metadata: FileMetadata {
                    sha1: sha1.ok_or_else(|| permanent("local cloud metadata is incomplete"))?,
                    raw_size: sql_u64(
                        raw_size.ok_or_else(|| permanent("local cloud metadata is incomplete"))?,
                    )?,
                    mtime: mtime.ok_or_else(|| permanent("local cloud metadata is incomplete"))?,
                    platforms_to_sync: u32::try_from(
                        platforms.ok_or_else(|| permanent("local cloud metadata is incomplete"))?,
                    )
                    .map_err(|_| permanent("invalid local cloud platform mask"))?,
                },
                change_number: sql_u64(change)?,
            });
        }
        Ok(ChangeList {
            current_change_number: current,
            files,
            deleted_paths,
        })
    }

    fn delete(&self, app_id: u32, path: &str) -> Result<u64, BackendError> {
        let file_path = self.file_path(app_id, path)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let current = Self::current_change(&transaction, app_id)?;
        let existing = transaction
            .query_row(
                "SELECT deleted, change_number FROM files WHERE app_id = ?1 AND path = ?2",
                params![app_id, path],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(sql_error)?;
        if let Some((true, change)) = existing {
            return sql_u64(change);
        }
        if existing.is_none() {
            return Ok(current);
        }
        let next = current
            .checked_add(1)
            .ok_or_else(|| permanent("local cloud change number overflow"))?;
        transaction
            .execute(
                "UPDATE apps SET change_number = ?2 WHERE app_id = ?1",
                params![app_id, sql_i64(next)?],
            )
            .map_err(sql_error)?;
        transaction
            .execute(
                "UPDATE files SET sha1 = NULL, raw_size = NULL, mtime = NULL,
                    platforms_to_sync = NULL, change_number = ?3, deleted = 1
                 WHERE app_id = ?1 AND path = ?2",
                params![app_id, path, sql_i64(next)?],
            )
            .map_err(sql_error)?;
        if let Err(error) = std::fs::remove_file(file_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(io_error(error));
            }
        }
        transaction.commit().map_err(sql_error)?;
        Ok(next)
    }

    fn quota(&self, app_id: u32) -> Result<Quota, BackendError> {
        let connection = self.connection()?;
        let (used_bytes, used_files) = connection
            .query_row(
                "SELECT COALESCE(SUM(raw_size), 0), COUNT(*)
                 FROM files WHERE app_id = ?1 AND deleted = 0",
                params![app_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(sql_error)?;
        Ok(Quota {
            used_bytes: sql_u64(used_bytes)?,
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

fn validate_cloud_path(path: &str) -> Result<(), BackendError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\0') || path.contains('\\') {
        return Err(permanent("invalid local cloud path"));
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(permanent("invalid local cloud path component"));
    }
    Ok(())
}

fn reject_symlink_ancestors(root: &Path, parent: &Path) -> Result<(), BackendError> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| permanent("local cloud path escaped its root"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if std::fs::symlink_metadata(&current)
            .map_err(io_error)?
            .file_type()
            .is_symlink()
        {
            return Err(permanent("local cloud path contains a symlink"));
        }
    }
    Ok(())
}

fn validate_metadata(contents: &[u8], metadata: &FileMetadata) -> Result<(), BackendError> {
    if metadata.raw_size != contents.len() as u64 {
        return Err(permanent("local cloud raw size does not match contents"));
    }
    if metadata.sha1.len() != 40 || !metadata.sha1.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(permanent("local cloud SHA-1 is invalid"));
    }
    let actual = format!("{:x}", Sha1::digest(contents));
    if !actual.eq_ignore_ascii_case(&metadata.sha1) {
        return Err(permanent("local cloud SHA-1 does not match contents"));
    }
    Ok(())
}

fn next_temporary_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn sql_i64(value: u64) -> Result<i64, BackendError> {
    i64::try_from(value).map_err(|_| permanent("local cloud value exceeds SQLite range"))
}

fn sql_u64(value: i64) -> Result<u64, BackendError> {
    u64::try_from(value).map_err(|_| permanent("local cloud database contains a negative value"))
}

fn io_error(error: std::io::Error) -> BackendError {
    let retryable = matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
    );
    BackendError::new(format!("local cloud I/O failed: {error}"), retryable)
}

fn sql_error(error: rusqlite::Error) -> BackendError {
    BackendError::new(format!("local cloud database failed: {error}"), true)
}

fn permanent(message: impl Into<String>) -> BackendError {
    BackendError::new(message, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(contents: &[u8], mtime: i64) -> FileMetadata {
        FileMetadata {
            sha1: format!("{:x}", Sha1::digest(contents)),
            raw_size: contents.len() as u64,
            mtime,
            platforms_to_sync: u32::MAX,
        }
    }

    #[test]
    fn writes_readable_files_and_persists_change_numbers() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let contents = b"local save";
        assert_eq!(
            store
                .write(
                    480,
                    "%WinMyDocuments%/Game/save.dat",
                    contents,
                    &metadata(contents, 10),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            std::fs::read(
                temporary
                    .path()
                    .join("480/files/%WinMyDocuments%/Game/save.dat")
            )
            .unwrap(),
            contents
        );

        let reopened = FolderStore::open(temporary.path()).unwrap();
        let changes = reopened.changes_since(480, 0).unwrap();
        assert_eq!(changes.current_change_number, 1);
        assert_eq!(changes.files[0].path, "%WinMyDocuments%/Game/save.dat");
        assert_eq!(
            reopened.read(480, &changes.files[0].path).unwrap(),
            contents
        );
    }

    #[test]
    fn delta_reports_deletion_but_full_manifest_does_not() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let contents = b"save";
        store
            .write(480, "save.dat", contents, &metadata(contents, 10))
            .unwrap();
        assert_eq!(store.delete(480, "save.dat").unwrap(), 2);

        let delta = store.changes_since(480, 1).unwrap();
        assert_eq!(delta.deleted_paths, vec!["save.dat"]);
        let full = store.changes_since(480, 0).unwrap();
        assert!(full.files.is_empty());
        assert!(full.deleted_paths.is_empty());
    }

    #[test]
    fn rejects_escape_paths_and_bad_hashes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let contents = b"save";
        assert!(store
            .write(480, "../escape", contents, &metadata(contents, 10))
            .is_err());
        let mut wrong = metadata(contents, 10);
        wrong.sha1 = "0".repeat(40);
        assert!(store.write(480, "save.dat", contents, &wrong).is_err());
    }
}
