use std::sync::{Arc, OnceLock};

use tracing::warn;
use vapor_forge_cloud_core::{BackendError, CloudBackend};
use vapor_forge_core::unix_now;
use vapor_forge_sync_journal::{default_sync_journal_path, SyncJournal};

static JOURNAL: OnceLock<Option<Arc<SyncJournal>>> = OnceLock::new();

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

pub(crate) fn principal_scope(backend: &dyn CloudBackend) -> Result<String, BackendError> {
    let journal = shared().ok_or_else(|| BackendError::new("sync journal unavailable", true))?;
    let credential_fingerprint = backend.credential_fingerprint();
    match journal.load_backend_principal_scope(&credential_fingerprint) {
        Ok(Some(scope)) => return Ok(scope),
        Ok(None) => {}
        Err(error) => warn!(%error, "sync-journal: failed to read backend principal"),
    }

    let scope = backend.principal_scope()?;
    if let Err(error) =
        journal.store_backend_principal_scope(&credential_fingerprint, &scope, unix_now())
    {
        warn!(%error, "sync-journal: failed to persist backend principal");
    }
    Ok(scope)
}

/// Read a previously resolved principal without invoking the backend.
pub(crate) fn cached_principal_scope(backend: &dyn CloudBackend) -> Option<String> {
    shared()?
        .load_backend_principal_scope(&backend.credential_fingerprint())
        .ok()
        .flatten()
}
