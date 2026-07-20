use std::path::Path;
use std::time::Duration;

use rusqlite::Connection;

use crate::OutboxError;

pub(crate) fn open_database(path: &Path, schema: &str) -> Result<Connection, OutboxError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;

    connection.execute_batch(schema)?;
    Ok(connection)
}
