#![forbid(unsafe_code)]

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

const BATCH_LIMIT: i64 = 500;
pub const STEAM_CLIENT_ID_HEADER: &str = "x-cumulus-steam-client-id";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlaytimeEntry {
    #[serde(skip_serializing)]
    pub owner_scope: String,
    #[serde(skip_serializing)]
    pub owner_steam_id64: String,
    pub app_id: u32,
    pub playtime_minutes: u32,
    pub playtime_2weeks_minutes: u32,
    pub last_played_at: Option<i64>,
    pub observed_at: i64,
}

#[derive(Clone, Debug)]
pub struct CumulusSettings {
    pub server_url: String,
    pub token: String,
    pub timeout_connect_ms: u64,
    pub timeout_ms: u64,
}

pub struct Outbox {
    connection: Connection,
}

impl Outbox {
    pub fn open(path: &Path) -> Result<Self, OutboxError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS playtime_outbox (
                owner_scope TEXT NOT NULL,
                owner_steam_id64 TEXT NOT NULL,
                app_id INTEGER NOT NULL,
                playtime_minutes INTEGER NOT NULL,
                playtime_2weeks_minutes INTEGER NOT NULL,
                last_played_at INTEGER,
                observed_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (owner_scope, owner_steam_id64, app_id)
            );
            CREATE INDEX IF NOT EXISTS ix_playtime_outbox_retry
                ON playtime_outbox(owner_scope, next_attempt_at, owner_steam_id64);",
        )?;
        Ok(Self { connection })
    }

    pub fn enqueue(&mut self, entries: &[PlaytimeEntry]) -> Result<usize, OutboxError> {
        let transaction = self.connection.transaction()?;
        let mut changed = 0;
        for entry in entries {
            changed += transaction.execute(
                "INSERT INTO playtime_outbox (
                    owner_scope, owner_steam_id64, app_id, playtime_minutes,
                    playtime_2weeks_minutes, last_played_at, observed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(owner_scope, owner_steam_id64, app_id) DO UPDATE SET
                    playtime_minutes = MAX(playtime_outbox.playtime_minutes, excluded.playtime_minutes),
                    playtime_2weeks_minutes = CASE
                        WHEN excluded.observed_at >= playtime_outbox.observed_at
                        THEN excluded.playtime_2weeks_minutes
                        ELSE playtime_outbox.playtime_2weeks_minutes
                    END,
                    last_played_at = CASE
                        WHEN playtime_outbox.last_played_at IS NULL THEN excluded.last_played_at
                        WHEN excluded.last_played_at IS NULL THEN playtime_outbox.last_played_at
                        ELSE MAX(playtime_outbox.last_played_at, excluded.last_played_at)
                    END,
                    observed_at = MAX(playtime_outbox.observed_at, excluded.observed_at),
                    attempts = 0,
                    next_attempt_at = 0",
                params![
                    entry.owner_scope,
                    entry.owner_steam_id64,
                    entry.app_id,
                    entry.playtime_minutes,
                    entry.playtime_2weeks_minutes,
                    entry.last_played_at,
                    entry.observed_at,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(changed)
    }

    pub fn ready_accounts(&self, owner_scope: &str, now: i64) -> Result<Vec<String>, OutboxError> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT owner_steam_id64 FROM playtime_outbox
             WHERE owner_scope = ?1 AND next_attempt_at <= ?2
             ORDER BY owner_steam_id64",
        )?;
        let rows = statement.query_map(params![owner_scope, now], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn pending(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
        now: i64,
    ) -> Result<Vec<PlaytimeEntry>, OutboxError> {
        let mut statement = self.connection.prepare(
            "SELECT owner_scope, owner_steam_id64, app_id, playtime_minutes,
                    playtime_2weeks_minutes, last_played_at, observed_at
             FROM playtime_outbox
             WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND next_attempt_at <= ?3
             ORDER BY app_id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![owner_scope, owner_steam_id64, now, BATCH_LIMIT],
            |row| {
                Ok(PlaytimeEntry {
                    owner_scope: row.get(0)?,
                    owner_steam_id64: row.get(1)?,
                    app_id: row.get(2)?,
                    playtime_minutes: row.get(3)?,
                    playtime_2weeks_minutes: row.get(4)?,
                    last_played_at: row.get(5)?,
                    observed_at: row.get(6)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn mark_delivered(&mut self, entries: &[PlaytimeEntry]) -> Result<(), OutboxError> {
        let transaction = self.connection.transaction()?;
        for entry in entries {
            transaction.execute(
                "DELETE FROM playtime_outbox
                 WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND app_id = ?3
                   AND observed_at = ?4 AND playtime_minutes = ?5
                   AND playtime_2weeks_minutes = ?6
                   AND last_played_at IS ?7",
                params![
                    entry.owner_scope,
                    entry.owner_steam_id64,
                    entry.app_id,
                    entry.observed_at,
                    entry.playtime_minutes,
                    entry.playtime_2weeks_minutes,
                    entry.last_played_at,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_failed(&mut self, entries: &[PlaytimeEntry], now: i64) -> Result<(), OutboxError> {
        let transaction = self.connection.transaction()?;
        for entry in entries {
            let attempts: i64 = transaction
                .query_row(
                    "SELECT attempts FROM playtime_outbox
                     WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND app_id = ?3
                       AND observed_at = ?4",
                    params![
                        entry.owner_scope,
                        entry.owner_steam_id64,
                        entry.app_id,
                        entry.observed_at
                    ],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            let delay = 1_i64 << attempts.min(8) as u32;
            transaction.execute(
                "UPDATE playtime_outbox SET attempts = attempts + 1, next_attempt_at = ?5
                 WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND app_id = ?3
                   AND observed_at = ?4",
                params![
                    entry.owner_scope,
                    entry.owner_steam_id64,
                    entry.app_id,
                    entry.observed_at,
                    now.saturating_add(delay),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn len(&self) -> Result<u64, OutboxError> {
        self.connection
            .query_row("SELECT COUNT(*) FROM playtime_outbox", [], |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn is_empty(&self) -> Result<bool, OutboxError> {
        self.len().map(|len| len == 0)
    }
}

#[derive(Serialize)]
struct UploadRequest<'a> {
    steam_id64: &'a str,
    apps: &'a [PlaytimeEntry],
}

pub fn upload(
    settings: &CumulusSettings,
    client_id: u64,
    steam_id64: &str,
    entries: &[PlaytimeEntry],
) -> Result<(), UploadError> {
    if entries.is_empty() {
        return Ok(());
    }
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_millis(settings.timeout_connect_ms)))
        .timeout_global(Some(Duration::from_millis(settings.timeout_ms)))
        .http_status_as_error(false)
        .build()
        .new_agent();
    let url = format!(
        "{}/api/v1/device/playtime",
        settings.server_url.trim_end_matches('/')
    );
    let body = serde_json::to_vec(&UploadRequest {
        steam_id64,
        apps: entries,
    })?;
    let response = agent
        .post(&url)
        .header("Authorization", &format!("Bearer {}", settings.token))
        .header(STEAM_CLIENT_ID_HEADER, &client_id.to_string())
        .header("Content-Type", "application/json")
        .send(body.as_slice())?;
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(UploadError::HttpStatus(status))
    }
}

pub fn credential_scope(server_url: &str, token: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in server_url
        .trim()
        .trim_end_matches('/')
        .bytes()
        .chain([0])
        .chain(token.trim().bytes())
        .chain([0])
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub fn default_outbox_path() -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(root).join("vapor-forge/playtime-outbox.sqlite3"));
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/share/vapor-forge/playtime-outbox.sqlite3"))
}

#[derive(Debug, thiserror::Error)]
pub enum OutboxError {
    #[error("playtime outbox filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("playtime outbox database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("Cumulus returned HTTP {0}")]
    HttpStatus(u16),
    #[error("Cumulus transport failed: {0}")]
    Transport(#[from] ureq::Error),
    #[error("playtime serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl UploadError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::HttpStatus(status) => {
                matches!(*status, 401 | 403 | 408 | 409 | 429) || *status >= 500
            }
            Self::Transport(_) => true,
            Self::Json(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(scope: &str, steam_id64: &str, app_id: u32, observed_at: i64) -> PlaytimeEntry {
        PlaytimeEntry {
            owner_scope: scope.into(),
            owner_steam_id64: steam_id64.into(),
            app_id,
            playtime_minutes: 120,
            playtime_2weeks_minutes: 20,
            last_played_at: Some(1_800_000_000),
            observed_at,
        }
    }

    #[test]
    fn latest_snapshot_replaces_rolling_window_and_preserves_total_maximum() {
        let directory = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::open(&directory.path().join("outbox.db")).unwrap();
        let first = entry("scope-a", "76561198000000001", 620, 10);
        outbox.enqueue(std::slice::from_ref(&first)).unwrap();
        let mut latest = first.clone();
        latest.playtime_minutes = 100;
        latest.playtime_2weeks_minutes = 5;
        latest.observed_at = 11;
        outbox.enqueue(std::slice::from_ref(&latest)).unwrap();

        let pending = outbox.pending("scope-a", "76561198000000001", 11).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].playtime_minutes, 120);
        assert_eq!(pending[0].playtime_2weeks_minutes, 5);
        assert_eq!(pending[0].observed_at, 11);
    }

    #[test]
    fn delivery_cannot_delete_a_newer_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::open(&directory.path().join("outbox.db")).unwrap();
        let first = entry("scope-a", "76561198000000001", 620, 10);
        outbox.enqueue(std::slice::from_ref(&first)).unwrap();
        let sent = outbox.pending("scope-a", "76561198000000001", 10).unwrap();
        let mut latest = first.clone();
        latest.playtime_minutes = 121;
        latest.observed_at = 11;
        outbox.enqueue(std::slice::from_ref(&latest)).unwrap();
        outbox.mark_delivered(&sent).unwrap();
        assert_eq!(outbox.len().unwrap(), 1);
    }

    #[test]
    fn accounts_and_credentials_are_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::open(&directory.path().join("outbox.db")).unwrap();
        outbox
            .enqueue(&[
                entry("scope-a", "76561198000000001", 620, 10),
                entry("scope-a", "76561198000000002", 620, 10),
                entry("scope-b", "76561198000000001", 620, 10),
            ])
            .unwrap();
        assert_eq!(outbox.ready_accounts("scope-a", 10).unwrap().len(), 2);
        assert_eq!(outbox.ready_accounts("scope-b", 10).unwrap().len(), 1);
    }
}
