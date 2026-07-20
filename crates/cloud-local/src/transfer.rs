use std::collections::{HashMap, VecDeque};
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use vapor_forge_cloud_core::{BackendError, ByteStore, FileMetadata, HttpTarget};

use crate::FolderStore;

pub const LOCAL_TRANSFER_AUTHORITY: &str = "vapor-forge.local";
const TRANSFER_TTL: Duration = Duration::from_secs(15 * 60);
const TRANSFER_CAPACITY: usize = 4096;

pub enum LocalTransferOutcome {
    Upload(Result<u64, BackendError>),
    Download(Result<Vec<u8>, BackendError>),
}

struct UploadTransfer {
    store: FolderStore,
    app_id: u32,
    path: String,
    transfer_size: u64,
    metadata: FileMetadata,
    result: Mutex<Option<Result<u64, BackendError>>>,
}

enum TransferOperation {
    Upload(Arc<UploadTransfer>),
    Download {
        store: FolderStore,
        app_id: u32,
        path: String,
    },
}

struct IssuedTransfer {
    token: String,
    expires_at: Instant,
    operation: TransferOperation,
}

#[derive(Default)]
struct TransferRegistry {
    by_token: HashMap<String, IssuedTransfer>,
    order: VecDeque<String>,
}

pub fn issue_upload(
    store: FolderStore,
    app_id: u32,
    path: String,
    transfer_size: u64,
    metadata: FileMetadata,
) -> Result<(String, HttpTarget), BackendError> {
    let token = next_token();
    insert(IssuedTransfer {
        token: token.clone(),
        expires_at: Instant::now() + TRANSFER_TTL,
        operation: TransferOperation::Upload(Arc::new(UploadTransfer {
            store,
            app_id,
            path,
            transfer_size,
            metadata,
            result: Mutex::new(None),
        })),
    })?;
    Ok((token.clone(), target("upload", &token)))
}

pub fn issue_download(
    store: FolderStore,
    app_id: u32,
    path: String,
) -> Result<HttpTarget, BackendError> {
    let token = next_token();
    insert(IssuedTransfer {
        token: token.clone(),
        expires_at: Instant::now() + TRANSFER_TTL,
        operation: TransferOperation::Download {
            store,
            app_id,
            path,
        },
    })?;
    Ok(target("download", &token))
}

pub fn intercept_transfer(
    authority: &str,
    path: &str,
    body: &[u8],
) -> Option<LocalTransferOutcome> {
    if !authority.eq_ignore_ascii_case(LOCAL_TRANSFER_AUTHORITY) {
        return None;
    }
    let (kind, token) = parse_target(path)?;
    let operation = {
        let mut registry = registry().lock().ok()?;
        remove_expired(&mut registry, Instant::now());
        match registry.by_token.get(token)?.operation {
            TransferOperation::Upload(ref upload) if kind == "upload" => {
                TransferOperation::Upload(Arc::clone(upload))
            }
            TransferOperation::Download { .. } if kind == "download" => {
                let issued = registry.by_token.remove(token)?;
                registry.order.retain(|queued| queued != token);
                issued.operation
            }
            _ => return None,
        }
    };

    Some(match operation {
        TransferOperation::Upload(upload) => {
            let result = upload
                .result
                .lock()
                .ok()
                .and_then(|result| result.clone())
                .unwrap_or_else(|| complete_upload_body(&upload, body));
            if let Ok(mut status) = upload.result.lock() {
                *status = Some(result.clone());
            }
            LocalTransferOutcome::Upload(result)
        }
        TransferOperation::Download {
            store,
            app_id,
            path,
        } => LocalTransferOutcome::Download(store.read(app_id, &path)),
    })
}

pub fn commit_upload(token: &str) -> Result<u64, BackendError> {
    let issued = {
        let mut registry = registry()
            .lock()
            .map_err(|_| permanent("local transfer registry is poisoned"))?;
        remove_expired(&mut registry, Instant::now());
        let issued = registry
            .by_token
            .remove(token)
            .ok_or_else(|| permanent("local upload target is unknown"))?;
        registry.order.retain(|queued| queued != token);
        issued
    };
    let TransferOperation::Upload(upload) = issued.operation else {
        return Err(permanent("local transfer target is not an upload"));
    };
    let result = upload
        .result
        .lock()
        .map_err(|_| permanent("local upload result is poisoned"))?
        .clone()
        .ok_or_else(|| permanent("local upload transfer has not completed"))?;
    result
}

fn complete_upload_body(upload: &UploadTransfer, body: &[u8]) -> Result<u64, BackendError> {
    if body.len() as u64 != upload.transfer_size {
        return Err(permanent(
            "local upload transfer size does not match declaration",
        ));
    }
    let raw = if upload.transfer_size == upload.metadata.raw_size {
        body.to_vec()
    } else {
        decode_steam_zip(body, upload.metadata.raw_size)?
    };
    upload
        .store
        .write(upload.app_id, &upload.path, &raw, &upload.metadata)
}

fn decode_steam_zip(body: &[u8], raw_size: u64) -> Result<Vec<u8>, BackendError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(body))
        .map_err(|error| permanent(format!("invalid Steam upload ZIP: {error}")))?;
    if archive.len() != 1 {
        return Err(permanent("Steam upload ZIP must contain one entry"));
    }
    let entry = archive
        .by_index(0)
        .map_err(|error| permanent(format!("invalid Steam upload ZIP entry: {error}")))?;
    if entry.name() != "z" || !entry.is_file() || entry.size() != raw_size {
        return Err(permanent(
            "Steam upload ZIP entry does not match its declaration",
        ));
    }
    let capacity = usize::try_from(raw_size)
        .map_err(|_| permanent("local cloud file is too large for this process"))?;
    let mut raw = Vec::with_capacity(capacity);
    entry
        .take(raw_size.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|error| permanent(format!("failed to read Steam upload ZIP: {error}")))?;
    if raw.len() as u64 != raw_size {
        return Err(permanent("Steam upload ZIP expanded to the wrong size"));
    }
    Ok(raw)
}

fn target(kind: &str, token: &str) -> HttpTarget {
    HttpTarget {
        host: LOCAL_TRANSFER_AUTHORITY.into(),
        path: format!("/v1/{kind}/{token}"),
        https: false,
        headers: Vec::new(),
    }
}

fn parse_target(path: &str) -> Option<(&str, &str)> {
    let path = path.split('?').next()?;
    let mut parts = path.trim_start_matches('/').split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("v1"), Some(kind @ ("upload" | "download")), Some(token), None)
            if !token.is_empty() =>
        {
            Some((kind, token))
        }
        _ => None,
    }
}

fn insert(issued: IssuedTransfer) -> Result<(), BackendError> {
    let mut registry = registry()
        .lock()
        .map_err(|_| permanent("local transfer registry is poisoned"))?;
    remove_expired(&mut registry, Instant::now());
    if registry.by_token.len() >= TRANSFER_CAPACITY {
        return Err(BackendError::new(
            "local transfer registry capacity is exhausted",
            true,
        ));
    }
    registry.order.push_back(issued.token.clone());
    registry.by_token.insert(issued.token.clone(), issued);
    Ok(())
}

fn remove_expired(registry: &mut TransferRegistry, now: Instant) {
    while registry
        .order
        .front()
        .and_then(|token| registry.by_token.get(token))
        .is_some_and(|issued| issued.expires_at <= now)
    {
        if let Some(token) = registry.order.pop_front() {
            registry.by_token.remove(&token);
        }
    }
}

fn registry() -> &'static Mutex<TransferRegistry> {
    static REGISTRY: OnceLock<Mutex<TransferRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(TransferRegistry::default()))
}

fn next_token() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("{:016x}", NEXT.fetch_add(1, Ordering::Relaxed))
}

fn permanent(message: impl Into<String>) -> BackendError {
    BackendError::new(message, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::{Digest, Sha1};
    use vapor_forge_cloud_core::CloudFileStore;

    fn metadata(contents: &[u8]) -> FileMetadata {
        FileMetadata {
            sha1: format!("{:x}", Sha1::digest(contents)),
            raw_size: contents.len() as u64,
            mtime: 10,
            platforms_to_sync: u32::MAX,
        }
    }

    #[test]
    fn upload_and_download_are_completed_without_network_io() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open(temporary.path()).unwrap();
        let contents = b"in-process save";
        let (token, target) = issue_upload(
            store.clone(),
            480,
            "save.dat".into(),
            contents.len() as u64,
            metadata(contents),
        )
        .unwrap();
        let Some(LocalTransferOutcome::Upload(result)) =
            intercept_transfer(&target.host, &target.path, contents)
        else {
            panic!("upload was not intercepted");
        };
        assert_eq!(result.unwrap(), 1);
        assert_eq!(commit_upload(&token).unwrap(), 1);

        let target = issue_download(store.clone(), 480, "save.dat".into()).unwrap();
        let Some(LocalTransferOutcome::Download(result)) =
            intercept_transfer(&target.host, &target.path, &[])
        else {
            panic!("download was not intercepted");
        };
        assert_eq!(result.unwrap(), contents);
        assert_eq!(store.changes_since(480, 0).unwrap().files.len(), 1);
    }
}
