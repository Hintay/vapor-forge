use std::path::PathBuf;

/// Return the on-disk path for durable sync data.
pub fn default_sync_journal_path() -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(root).join("vapor-forge/sync-journal.stry"));
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/share/vapor-forge/sync-journal.stry"))
}
