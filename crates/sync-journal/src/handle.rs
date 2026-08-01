use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::{SyncJournal, SyncJournalError};

static HANDLES: OnceLock<Mutex<HashMap<PathBuf, Weak<SyncJournal>>>> = OnceLock::new();

/// Return the process-wide journal for `path`, opening it on first use.
///
/// structsy takes an exclusive `flock` per open database, so a second live
/// handle to the same file — even inside one process — fails to open. Every
/// subsystem that touches the journal must go through here rather than calling
/// [`SyncJournal::open`]; the journal's own methods are `&self` and each one
/// runs in a single transaction, so the shared handle needs no outer lock.
pub fn shared(path: &Path) -> Result<Arc<SyncJournal>, SyncJournalError> {
    let mut handles = HANDLES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(live) = handles.get(path).and_then(Weak::upgrade) {
        return Ok(live);
    }
    let journal = Arc::new(SyncJournal::open(path)?);
    // Entries for closed journals would otherwise accumulate forever.
    handles.retain(|_, handle| handle.strong_count() > 0);
    handles.insert(path.to_owned(), Arc::downgrade(&journal));
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_returns_one_handle_per_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sync-journal.redb");
        let first = shared(&path).unwrap();
        let second = shared(&path).unwrap();
        assert!(Arc::ptr_eq(&first, &second));

        // A second independent open would collide with the exclusive lock.
        assert!(SyncJournal::open(&path).is_err());

        drop(first);
        drop(second);
        assert!(SyncJournal::open(&path).is_ok());
    }
}
