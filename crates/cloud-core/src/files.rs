//! Port for Steam cloud save storage.
//!
//! Steam performs cloud file transfers itself: it is handed an HTTP target and
//! PUTs or GETs the bytes directly, which never pass through this process. That
//! splits backends into two shapes, and this port models both:
//!
//! - **Direct** — the backend can issue a URL Steam may hit (Cumulus, or a
//!   Google Drive resumable session URI). Bytes go straight to the backend.
//! - **Bridged** — the backend has no URL to offer (a local folder). A local
//!   loopback transport serves Steam and hands the bytes to the backend.
//!
//! Metadata operations are the same either way, so they live on the store trait
//! itself; only byte movement varies.

use crate::BackendError;

/// Identity of a stored file, as Steam tracks it for sync decisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMetadata {
    /// SHA-1 of the raw contents, lowercase hex (40 characters).
    pub sha1: String,
    /// Size of the contents before any transfer encoding.
    pub raw_size: u64,
    /// Client-reported modification time, Unix seconds.
    pub mtime: i64,
    /// Steam platform mask the file should sync to.
    pub platforms_to_sync: u32,
}

/// A file present in the backend at a known change number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub metadata: FileMetadata,
    /// Change number at which this file reached its current state.
    pub change_number: u64,
}

/// Files changed since a caller-supplied change number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeList {
    /// The backend's newest change number; callers pass it back to resume.
    pub current_change_number: u64,
    pub files: Vec<FileEntry>,
    /// Paths removed after the requested change number.
    pub deleted_paths: Vec<String>,
}

/// Storage consumption for one app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub used_files: u32,
    pub total_files: u32,
}

/// One HTTP endpoint Steam is told to transfer against.
///
/// Split into parts rather than a URL string because Steam's protocol carries
/// authority, path, scheme, and headers as separate fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpTarget {
    /// Authority, optionally including a port (`host` or `host:port`).
    pub host: String,
    pub path: String,
    pub https: bool,
    /// Headers Steam must send, e.g. an authorization header.
    pub headers: Vec<HttpHeader>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// A contiguous span of a file that Steam uploads in one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadBlock {
    pub target: HttpTarget,
    pub offset: u64,
    pub length: u64,
}

/// How bytes reach a particular backend.
pub enum Transfer<'a> {
    /// Steam transfers directly against backend-issued targets.
    Direct(&'a dyn DirectTransfer),
    /// Bytes pass through a local transport into the backend.
    Bridged(&'a dyn ByteStore),
}

/// A backend that can hand Steam an HTTP target, keeping bytes out of this
/// process entirely.
pub trait DirectTransfer: Send + Sync {
    /// Targets Steam should PUT each span of the file to.
    ///
    /// Blocks must be contiguous and start at offset 0.
    fn upload_blocks(
        &self,
        app_id: u32,
        path: &str,
        metadata: &FileMetadata,
    ) -> Result<Vec<UploadBlock>, BackendError>;

    /// Finalize an upload whose blocks Steam has finished sending, returning the
    /// change number the file now holds.
    fn commit_upload(
        &self,
        app_id: u32,
        path: &str,
        metadata: &FileMetadata,
    ) -> Result<u64, BackendError>;

    /// Target Steam should GET the file from.
    fn download_target(&self, app_id: u32, path: &str) -> Result<HttpTarget, BackendError>;
}

/// A backend that exchanges whole file contents, for destinations with no URL
/// to offer Steam.
pub trait ByteStore: Send + Sync {
    fn read(&self, app_id: u32, path: &str) -> Result<Vec<u8>, BackendError>;

    /// Store contents, returning the change number the file now holds.
    fn write(
        &self,
        app_id: u32,
        path: &str,
        contents: &[u8],
        metadata: &FileMetadata,
    ) -> Result<u64, BackendError>;
}

/// A destination for Steam cloud saves.
///
/// Metadata operations are uniform; [`CloudFileStore::transfer`] selects how the
/// contents themselves move.
pub trait CloudFileStore: Send + Sync {
    fn changes_since(&self, app_id: u32, since: u64) -> Result<ChangeList, BackendError>;

    /// Remove a file, returning the change number recording the removal.
    fn delete(&self, app_id: u32, path: &str) -> Result<u64, BackendError>;

    fn quota(&self, app_id: u32) -> Result<Quota, BackendError>;

    fn transfer(&self) -> Transfer<'_>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FolderStore {
        change_number: u64,
    }

    impl ByteStore for FolderStore {
        fn read(&self, _app_id: u32, _path: &str) -> Result<Vec<u8>, BackendError> {
            Ok(b"save".to_vec())
        }

        fn write(
            &self,
            _app_id: u32,
            _path: &str,
            _contents: &[u8],
            _metadata: &FileMetadata,
        ) -> Result<u64, BackendError> {
            Ok(self.change_number + 1)
        }
    }

    impl CloudFileStore for FolderStore {
        fn changes_since(&self, _app_id: u32, _since: u64) -> Result<ChangeList, BackendError> {
            Ok(ChangeList {
                current_change_number: self.change_number,
                files: Vec::new(),
                deleted_paths: Vec::new(),
            })
        }

        fn delete(&self, _app_id: u32, _path: &str) -> Result<u64, BackendError> {
            Ok(self.change_number + 1)
        }

        fn quota(&self, _app_id: u32) -> Result<Quota, BackendError> {
            Ok(Quota {
                used_bytes: 0,
                total_bytes: 1 << 30,
                used_files: 0,
                total_files: 1000,
            })
        }

        fn transfer(&self) -> Transfer<'_> {
            Transfer::Bridged(self)
        }
    }

    /// A URL-less backend is expressible without implementing any HTTP concept.
    #[test]
    fn folder_backend_reports_bridged_transfer() {
        let store = FolderStore { change_number: 7 };
        assert!(matches!(store.transfer(), Transfer::Bridged(_)));
        assert_eq!(
            store.changes_since(480, 0).unwrap().current_change_number,
            7
        );
    }

    #[test]
    fn bridged_write_advances_the_change_number() {
        let store = FolderStore { change_number: 7 };
        let Transfer::Bridged(bytes) = store.transfer() else {
            panic!("expected a bridged backend");
        };
        let metadata = FileMetadata {
            sha1: "0".repeat(40),
            raw_size: 4,
            mtime: 1_700_000_000,
            platforms_to_sync: u32::MAX,
        };
        assert_eq!(bytes.write(480, "a.sav", b"save", &metadata).unwrap(), 8);
    }
}
