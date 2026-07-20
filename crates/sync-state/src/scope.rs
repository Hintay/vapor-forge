use std::path::PathBuf;

pub fn default_outbox_path() -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(root).join("vapor-forge/achievement-outbox.sqlite3"));
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/share/vapor-forge/achievement-outbox.sqlite3"))
}
