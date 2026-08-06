use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use tracing::warn;
use vapor_forge_cloud_core::{BackendError, CloudBackend};
use vapor_forge_core::unix_now;
use vapor_forge_sync_journal::{default_sync_journal_path, SyncJournal};

static JOURNAL: OnceLock<Option<Arc<SyncJournal>>> = OnceLock::new();
static PRINCIPAL_RESOLUTION: Mutex<()> = Mutex::new(());
static PRINCIPAL_CACHE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

/// The one journal handle for this process. redb allows a single open database
/// per file, so every subsystem — the upload workers and the cloud RPC adapter
/// alike — shares this handle. Journal methods take `&self` and each runs in a
/// single transaction, so no outer lock is needed.
pub(crate) fn shared() -> Option<Arc<SyncJournal>> {
    JOURNAL
        .get_or_init(|| {
            let path = default_sync_journal_path()?;
            match vapor_forge_sync_journal::shared(&path) {
                Ok(journal) => {
                    if let Ok(Some(descriptor)) = journal.load_device_descriptor() {
                        vapor_forge_cloud_core::restore_device_descriptor(descriptor);
                    }
                    Some(journal)
                }
                Err(error) => {
                    warn!(%error, path = %path.display(), "sync-journal: unavailable");
                    None
                }
            }
        })
        .clone()
}

/// Resolve and persist a principal from a background worker.
pub(crate) fn resolve_principal_scope(backend: &dyn CloudBackend) -> Result<String, BackendError> {
    let credential_fingerprint = backend.credential_fingerprint();
    if let Some(scope) = cached_principal_for_credential(&credential_fingerprint) {
        return Ok(scope);
    }

    let resolution = PRINCIPAL_RESOLUTION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(scope) = cached_principal_for_credential(&credential_fingerprint) {
        return Ok(scope);
    }
    let journal = shared().ok_or_else(|| BackendError::new("sync journal unavailable", true))?;
    match journal.load_backend_principal_scope(&credential_fingerprint) {
        Ok(Some(scope)) => {
            cache_principal(credential_fingerprint, scope.clone());
            drop(resolution);
            notify_principal_available();
            return Ok(scope);
        }
        Ok(None) => {}
        Err(error) => warn!(%error, "sync-journal: failed to read backend principal"),
    }
    let scope = backend.principal_scope()?;
    journal
        .store_backend_principal_scope(&credential_fingerprint, &scope, unix_now())
        .map_err(|error| {
            BackendError::new(
                format!("failed to persist backend principal: {error}"),
                true,
            )
        })?;
    cache_principal(credential_fingerprint, scope.clone());
    drop(resolution);
    notify_principal_available();
    Ok(scope)
}

/// Read a previously resolved principal without I/O.
pub(crate) fn cached_principal_scope(backend: &dyn CloudBackend) -> Option<String> {
    cached_principal_for_credential(&backend.credential_fingerprint())
}

pub(crate) fn cached_principal_for_credential(credential_fingerprint: &str) -> Option<String> {
    principal_cache()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(credential_fingerprint)
        .cloned()
}

fn cache_principal(credential_fingerprint: String, scope: String) {
    principal_cache()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(credential_fingerprint, scope);
}

fn principal_cache() -> &'static RwLock<HashMap<String, String>> {
    PRINCIPAL_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn notify_principal_available() {
    crate::achievement_worker::notify_principal_available();
    crate::playtime_worker::notify_principal_available();
    crate::client::user_stats::notify_principal_available();
}
