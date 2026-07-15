#![forbid(unsafe_code)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BATCH_LIMIT: usize = 100;
pub const STEAM_CLIENT_ID_HEADER: &str = "x-cumulus-steam-client-id";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedAchievementEvent {
    #[serde(skip_serializing)]
    pub owner_scope: String,
    #[serde(skip_serializing)]
    pub owner_steam_id64: String,
    pub event_id: String,
    pub app_id: u32,
    pub achievement_key: String,
    pub kind: String,
    pub progress_current: Option<u32>,
    pub progress_max: Option<u32>,
    pub observed_at: i64,
    pub unlocked_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedConflictResolution {
    pub owner_scope: String,
    pub event_id: String,
    pub app_id: u32,
    pub base_change_number: u64,
    pub remote_change_number: u64,
    pub resolution: String,
    pub machine_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedAchievementSchema {
    pub owner_scope: String,
    pub app_id: u32,
    pub language: String,
    pub schema_version: Option<String>,
    pub content: Vec<u8>,
}

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn new_conflict_event_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(
        "conflict-{nanos:032x}-{:08x}-{sequence:016x}",
        std::process::id()
    )
}

#[derive(Clone, Debug)]
pub struct UploadIdentity {
    pub client_id: Option<u64>,
    pub machine_name: String,
    pub os_type: Option<i64>,
    pub device_type: Option<i64>,
    pub steam_id64: String,
    pub persona_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceDescriptor {
    pub client_id: u64,
    pub machine_name: String,
    pub os_type: Option<i64>,
    pub device_type: Option<i64>,
}

static DEVICE_DESCRIPTOR: OnceLock<Mutex<Option<DeviceDescriptor>>> = OnceLock::new();
static BOUND_DEVICES: OnceLock<Mutex<HashSet<(String, u64)>>> = OnceLock::new();

pub fn record_device_descriptor(descriptor: DeviceDescriptor) {
    if let Ok(mut current) = DEVICE_DESCRIPTOR.get_or_init(|| Mutex::new(None)).lock() {
        *current = Some(descriptor);
    }
}

pub fn device_descriptor() -> Option<DeviceDescriptor> {
    DEVICE_DESCRIPTOR
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|current| current.clone())
}

pub fn restore_device_descriptor(descriptor: DeviceDescriptor) {
    if let Ok(mut current) = DEVICE_DESCRIPTOR.get_or_init(|| Mutex::new(None)).lock() {
        if current.is_none() {
            *current = Some(descriptor);
        }
    }
}

pub fn record_local_client_id(client_id: u64) {
    if client_id == 0 {
        return;
    }
    let Ok(mut current) = DEVICE_DESCRIPTOR.get_or_init(|| Mutex::new(None)).lock() else {
        return;
    };
    update_local_client_id(&mut current, client_id);
}

fn update_local_client_id(current: &mut Option<DeviceDescriptor>, client_id: u64) {
    if current
        .as_ref()
        .is_some_and(|descriptor| descriptor.client_id == client_id)
    {
        return;
    }
    *current = Some(DeviceDescriptor {
        client_id,
        machine_name: local_machine_name(),
        os_type: None,
        device_type: None,
    });
}

fn local_machine_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".into())
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
            "CREATE TABLE IF NOT EXISTS achievement_outbox (
                event_id TEXT PRIMARY KEY NOT NULL,
                owner_scope TEXT NOT NULL,
                owner_steam_id64 TEXT NOT NULL,
                app_id INTEGER NOT NULL,
                achievement_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                progress_current INTEGER,
                progress_max INTEGER,
                observed_at INTEGER NOT NULL,
                unlocked_at INTEGER,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_achievement_outbox_retry
                ON achievement_outbox(next_attempt_at, created_at);
            CREATE INDEX IF NOT EXISTS ix_achievement_outbox_owner_retry
                ON achievement_outbox(owner_scope, owner_steam_id64, next_attempt_at, created_at);
            CREATE TABLE IF NOT EXISTS achievement_dead_letter (
                event_id TEXT PRIMARY KEY NOT NULL,
                owner_scope TEXT NOT NULL,
                owner_steam_id64 TEXT NOT NULL,
                app_id INTEGER NOT NULL,
                achievement_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                reason TEXT NOT NULL,
                failed_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conflict_resolution_outbox (
                event_id TEXT PRIMARY KEY NOT NULL,
                owner_scope TEXT NOT NULL,
                app_id INTEGER NOT NULL,
                base_change_number INTEGER NOT NULL,
                remote_change_number INTEGER NOT NULL,
                resolution TEXT NOT NULL,
                machine_name TEXT,
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_conflict_resolution_outbox_retry
                ON conflict_resolution_outbox(owner_scope, state, next_attempt_at, created_at);
            CREATE INDEX IF NOT EXISTS ix_conflict_resolution_outbox_upload
                ON conflict_resolution_outbox(owner_scope, app_id, remote_change_number, state, created_at);
            CREATE TABLE IF NOT EXISTS achievement_schema_outbox (
                owner_scope TEXT NOT NULL,
                app_id INTEGER NOT NULL,
                language TEXT NOT NULL,
                schema_version TEXT,
                content BLOB NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (owner_scope, app_id, language)
            );
            CREATE INDEX IF NOT EXISTS ix_achievement_schema_outbox_retry
                ON achievement_schema_outbox(owner_scope, next_attempt_at, created_at);
            CREATE TABLE IF NOT EXISTS device_identity (
                singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                client_id TEXT NOT NULL,
                machine_name TEXT NOT NULL,
                os_type INTEGER,
                device_type INTEGER,
                updated_at INTEGER NOT NULL
            );",
        )?;
        Ok(Self { connection })
    }

    pub fn load_device_descriptor(&self) -> Result<Option<DeviceDescriptor>, OutboxError> {
        self.connection
            .query_row(
                "SELECT client_id, machine_name, os_type, device_type
                 FROM device_identity WHERE singleton = 1",
                [],
                |row| {
                    let client_id: String = row.get(0)?;
                    Ok(DeviceDescriptor {
                        client_id: client_id.parse().map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?,
                        machine_name: row.get(1)?,
                        os_type: row.get(2)?,
                        device_type: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn store_device_descriptor(
        &self,
        descriptor: &DeviceDescriptor,
        now: i64,
    ) -> Result<(), OutboxError> {
        self.connection.execute(
            "INSERT INTO device_identity (
                singleton, client_id, machine_name, os_type, device_type, updated_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(singleton) DO UPDATE SET
                client_id = excluded.client_id,
                machine_name = excluded.machine_name,
                os_type = excluded.os_type,
                device_type = excluded.device_type,
                updated_at = excluded.updated_at
             WHERE client_id != excluded.client_id
                OR machine_name != excluded.machine_name
                OR os_type IS NOT excluded.os_type
                OR device_type IS NOT excluded.device_type",
            params![
                descriptor.client_id.to_string(),
                descriptor.machine_name,
                descriptor.os_type,
                descriptor.device_type,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn attribute_pending(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
    ) -> Result<(), OutboxError> {
        if owner_scope.is_empty() || owner_steam_id64.is_empty() {
            return Ok(());
        }
        let transaction = self.connection.unchecked_transaction()?;

        transaction.execute(
            "DELETE FROM achievement_outbox AS current
             WHERE current.owner_scope = ?1
               AND current.owner_steam_id64 = ?2
               AND current.kind = 'progress'
               AND EXISTS (
                 SELECT 1 FROM achievement_outbox AS pending
                 WHERE pending.owner_scope = ''
                   AND pending.owner_steam_id64 = ?2
                   AND pending.kind = 'progress'
                   AND pending.app_id = current.app_id
                   AND pending.achievement_key = current.achievement_key
                   AND pending.created_at >= current.created_at
               )",
            params![owner_scope, owner_steam_id64],
        )?;
        transaction.execute(
            "DELETE FROM achievement_outbox AS pending
             WHERE pending.owner_scope = ''
               AND pending.owner_steam_id64 = ?2
               AND pending.kind = 'progress'
               AND EXISTS (
                 SELECT 1 FROM achievement_outbox AS current
                 WHERE current.owner_scope = ?1
                   AND current.owner_steam_id64 = ?2
                   AND current.kind = 'progress'
                   AND current.app_id = pending.app_id
                   AND current.achievement_key = pending.achievement_key
                   AND current.created_at > pending.created_at
               )",
            params![owner_scope, owner_steam_id64],
        )?;
        transaction.execute(
            "UPDATE achievement_outbox
             SET owner_scope = ?1
             WHERE owner_scope = '' AND owner_steam_id64 = ?2",
            params![owner_scope, owner_steam_id64],
        )?;
        transaction.execute(
            "DELETE FROM achievement_outbox
             WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND kind = 'progress'
               AND event_id NOT IN (
                 SELECT event_id FROM achievement_outbox
                 WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND kind = 'progress'
                 ORDER BY created_at DESC, event_id DESC LIMIT 5000
               )",
            params![owner_scope, owner_steam_id64],
        )?;

        transaction.commit()?;
        Ok(())
    }

    pub fn attribute_pending_schemas(&self, owner_scope: &str) -> Result<(), OutboxError> {
        if owner_scope.is_empty() {
            return Ok(());
        }
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO achievement_schema_outbox (
                owner_scope, app_id, language, schema_version, content,
                attempts, next_attempt_at, created_at
             )
             SELECT ?1, app_id, language, schema_version, content,
                    attempts, next_attempt_at, created_at
             FROM achievement_schema_outbox
             WHERE owner_scope = ''
             ON CONFLICT(owner_scope, app_id, language) DO UPDATE SET
                schema_version = excluded.schema_version,
                content = excluded.content,
                attempts = excluded.attempts,
                next_attempt_at = excluded.next_attempt_at,
                created_at = excluded.created_at
             WHERE excluded.created_at >= achievement_schema_outbox.created_at",
            params![owner_scope],
        )?;
        transaction.execute(
            "DELETE FROM achievement_schema_outbox WHERE owner_scope = ''",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn enqueue(&self, event: &QueuedAchievementEvent, now: i64) -> Result<bool, OutboxError> {
        let transaction = self.connection.unchecked_transaction()?;
        if event.kind == "progress" {
            transaction.execute(
                "DELETE FROM achievement_outbox
                 WHERE owner_scope = ?1 AND owner_steam_id64 = ?2
                   AND app_id = ?3 AND achievement_key = ?4 AND kind = 'progress'",
                params![
                    event.owner_scope,
                    event.owner_steam_id64,
                    event.app_id,
                    event.achievement_key,
                ],
            )?;
        }
        let changed = transaction.execute(
            "INSERT OR IGNORE INTO achievement_outbox (
                owner_scope, owner_steam_id64, event_id, app_id, achievement_key,
                kind, progress_current, progress_max, observed_at, unlocked_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.owner_scope,
                event.owner_steam_id64,
                event.event_id,
                event.app_id,
                event.achievement_key,
                event.kind,
                event.progress_current,
                event.progress_max,
                event.observed_at,
                event.unlocked_at,
                now,
            ],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        transaction.execute(
            "DELETE FROM achievement_outbox
             WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND kind = 'progress'
               AND event_id NOT IN (
                 SELECT event_id FROM achievement_outbox
                 WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND kind = 'progress'
                 ORDER BY created_at DESC, event_id DESC LIMIT 5000
             )",
            params![event.owner_scope, event.owner_steam_id64],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn pending(
        &self,
        now: i64,
        owner_scope: &str,
        owner_steam_id64: &str,
    ) -> Result<Vec<QueuedAchievementEvent>, OutboxError> {
        let mut statement = self.connection.prepare(
            "SELECT owner_scope, owner_steam_id64, event_id, app_id,
                    achievement_key, kind, progress_current, progress_max,
                    observed_at, unlocked_at
             FROM achievement_outbox
             WHERE next_attempt_at <= ?1 AND owner_scope = ?2 AND owner_steam_id64 = ?3
             ORDER BY created_at, event_id
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![now, owner_scope, owner_steam_id64, BATCH_LIMIT as i64],
            |row| {
                Ok(QueuedAchievementEvent {
                    owner_scope: row.get(0)?,
                    owner_steam_id64: row.get(1)?,
                    event_id: row.get(2)?,
                    app_id: row.get(3)?,
                    achievement_key: row.get(4)?,
                    kind: row.get(5)?,
                    progress_current: row.get(6)?,
                    progress_max: row.get(7)?,
                    observed_at: row.get(8)?,
                    unlocked_at: row.get(9)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn mark_delivered(&mut self, events: &[QueuedAchievementEvent]) -> Result<(), OutboxError> {
        let transaction = self.connection.transaction()?;
        for event in events {
            transaction.execute(
                "DELETE FROM achievement_outbox
                 WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND event_id = ?3",
                params![event.owner_scope, event.owner_steam_id64, event.event_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_failed(
        &mut self,
        events: &[QueuedAchievementEvent],
        now: i64,
    ) -> Result<(), OutboxError> {
        let transaction = self.connection.transaction()?;
        for event in events {
            let attempts: i64 = transaction
                .query_row(
                    "SELECT attempts FROM achievement_outbox
                     WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND event_id = ?3",
                    params![event.owner_scope, event.owner_steam_id64, event.event_id],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            let delay = 1_i64 << (attempts.min(8) as u32);
            transaction.execute(
                "UPDATE achievement_outbox
                 SET attempts = attempts + 1, next_attempt_at = ?4
                 WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND event_id = ?3",
                params![
                    event.owner_scope,
                    event.owner_steam_id64,
                    event.event_id,
                    now.saturating_add(delay)
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_rejected(
        &mut self,
        events: &[QueuedAchievementEvent],
        reason: &str,
        now: i64,
    ) -> Result<(), OutboxError> {
        let transaction = self.connection.transaction()?;
        for event in events {
            transaction.execute(
                "INSERT OR REPLACE INTO achievement_dead_letter (
                    event_id, owner_scope, owner_steam_id64, app_id,
                    achievement_key, kind, reason, failed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.event_id,
                    event.owner_scope,
                    event.owner_steam_id64,
                    event.app_id,
                    event.achievement_key,
                    event.kind,
                    reason,
                    now,
                ],
            )?;
            transaction.execute(
                "DELETE FROM achievement_outbox
                 WHERE owner_scope = ?1 AND owner_steam_id64 = ?2 AND event_id = ?3",
                params![event.owner_scope, event.owner_steam_id64, event.event_id],
            )?;
        }
        transaction.execute(
            "DELETE FROM achievement_dead_letter WHERE event_id NOT IN (
                SELECT event_id FROM achievement_dead_letter
                ORDER BY failed_at DESC, event_id DESC LIMIT 1000
             )",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn len(&self) -> Result<u64, OutboxError> {
        self.connection
            .query_row("SELECT COUNT(*) FROM achievement_outbox", [], |row| {
                row.get(0)
            })
            .map_err(Into::into)
    }

    pub fn is_empty(&self) -> Result<bool, OutboxError> {
        self.len().map(|len| len == 0)
    }

    pub fn enqueue_schema(
        &self,
        schema: &QueuedAchievementSchema,
        now: i64,
    ) -> Result<(), OutboxError> {
        self.connection.execute(
            "INSERT INTO achievement_schema_outbox (
                owner_scope, app_id, language, schema_version, content, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(owner_scope, app_id, language) DO UPDATE SET
                schema_version = excluded.schema_version,
                content = excluded.content,
                attempts = 0,
                next_attempt_at = 0,
                created_at = excluded.created_at",
            params![
                schema.owner_scope,
                schema.app_id,
                schema.language,
                schema.schema_version,
                schema.content,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn pending_schemas(
        &self,
        now: i64,
        owner_scope: &str,
    ) -> Result<Vec<QueuedAchievementSchema>, OutboxError> {
        let mut statement = self.connection.prepare(
            "SELECT owner_scope, app_id, language,
                    schema_version, content
             FROM achievement_schema_outbox
             WHERE next_attempt_at <= ?1 AND owner_scope = ?2
             ORDER BY created_at, app_id LIMIT 10",
        )?;
        let rows = statement.query_map(params![now, owner_scope], |row| {
            Ok(QueuedAchievementSchema {
                owner_scope: row.get(0)?,
                app_id: row.get(1)?,
                language: row.get(2)?,
                schema_version: row.get(3)?,
                content: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn mark_schema_delivered(
        &self,
        schema: &QueuedAchievementSchema,
    ) -> Result<(), OutboxError> {
        self.connection.execute(
            "DELETE FROM achievement_schema_outbox
             WHERE owner_scope = ?1 AND app_id = ?2 AND language = ?3",
            params![schema.owner_scope, schema.app_id, schema.language],
        )?;
        Ok(())
    }

    pub fn mark_schema_failed(
        &self,
        schema: &QueuedAchievementSchema,
        now: i64,
    ) -> Result<(), OutboxError> {
        let attempts: i64 = self
            .connection
            .query_row(
                "SELECT attempts FROM achievement_schema_outbox
                 WHERE owner_scope = ?1 AND app_id = ?2 AND language = ?3",
                params![schema.owner_scope, schema.app_id, schema.language],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let delay = 1_i64 << (attempts.min(8) as u32);
        self.connection.execute(
            "UPDATE achievement_schema_outbox
             SET attempts = attempts + 1, next_attempt_at = ?4
             WHERE owner_scope = ?1 AND app_id = ?2 AND language = ?3",
            params![
                schema.owner_scope,
                schema.app_id,
                schema.language,
                now.saturating_add(delay),
            ],
        )?;
        Ok(())
    }

    pub fn enqueue_conflict(
        &mut self,
        resolution: &QueuedConflictResolution,
        now: i64,
    ) -> Result<(), OutboxError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM conflict_resolution_outbox
             WHERE owner_scope = ?1 AND app_id = ?2 AND event_id <> ?3",
            params![
                resolution.owner_scope,
                resolution.app_id,
                resolution.event_id
            ],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO conflict_resolution_outbox (
                event_id, owner_scope, app_id, base_change_number, remote_change_number,
                resolution, machine_name, state, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                resolution.event_id,
                resolution.owner_scope,
                resolution.app_id,
                resolution.base_change_number,
                resolution.remote_change_number,
                resolution.resolution,
                resolution.machine_name,
                if resolution.resolution == "kept_cloud" {
                    "ready"
                } else {
                    "pending_upload"
                },
                now,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn pending_cloud_conflicts(
        &self,
        now: i64,
        owner_scope: &str,
    ) -> Result<Vec<QueuedConflictResolution>, OutboxError> {
        let mut statement = self.connection.prepare(
            "SELECT owner_scope, event_id, app_id, base_change_number, remote_change_number,
                    resolution, machine_name
             FROM conflict_resolution_outbox
             WHERE owner_scope = ?1 AND state = 'ready' AND next_attempt_at <= ?2
             ORDER BY created_at, event_id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![owner_scope, now, BATCH_LIMIT as i64],
            conflict_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn pending_local_conflict(
        &self,
        owner_scope: &str,
        app_id: u32,
        remote_change_number: u64,
    ) -> Result<Option<QueuedConflictResolution>, OutboxError> {
        self.connection
            .query_row(
                "SELECT owner_scope, event_id, app_id, base_change_number, remote_change_number,
                        resolution, machine_name
                 FROM conflict_resolution_outbox
                 WHERE owner_scope = ?1 AND state = 'pending_upload' AND app_id = ?2
                   AND remote_change_number = ?3
                 ORDER BY created_at DESC LIMIT 1",
                params![owner_scope, app_id, remote_change_number],
                conflict_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn mark_conflict_delivered(
        &self,
        resolution: &QueuedConflictResolution,
    ) -> Result<(), OutboxError> {
        self.connection.execute(
            "DELETE FROM conflict_resolution_outbox WHERE owner_scope = ?1 AND event_id = ?2",
            params![resolution.owner_scope, resolution.event_id],
        )?;
        Ok(())
    }

    pub fn mark_conflict_failed(
        &self,
        resolution: &QueuedConflictResolution,
        now: i64,
    ) -> Result<(), OutboxError> {
        let attempts: i64 = self
            .connection
            .query_row(
                "SELECT attempts FROM conflict_resolution_outbox
                     WHERE owner_scope = ?1 AND event_id = ?2",
                params![resolution.owner_scope, resolution.event_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let delay = 1_i64 << (attempts.min(8) as u32);
        self.connection.execute(
            "UPDATE conflict_resolution_outbox
             SET attempts = attempts + 1, next_attempt_at = ?3
             WHERE owner_scope = ?1 AND event_id = ?2",
            params![
                resolution.owner_scope,
                resolution.event_id,
                now.saturating_add(delay)
            ],
        )?;
        Ok(())
    }

    pub fn conflict_len(&self) -> Result<u64, OutboxError> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM conflict_resolution_outbox",
                [],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }
}

fn conflict_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueuedConflictResolution> {
    Ok(QueuedConflictResolution {
        owner_scope: row.get(0)?,
        event_id: row.get(1)?,
        app_id: row.get(2)?,
        base_change_number: row.get(3)?,
        remote_change_number: row.get(4)?,
        resolution: row.get(5)?,
        machine_name: row.get(6)?,
    })
}

#[derive(Serialize)]
struct UploadRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<&'a str>,
    machine_name: &'a str,
    os_type: Option<i64>,
    device_type: Option<i64>,
    steam_id64: &'a str,
    persona_name: Option<&'a str>,
    events: &'a [QueuedAchievementEvent],
}

#[derive(Serialize)]
struct SchemaUploadRequest<'a> {
    app_id: u32,
    language: &'a str,
    schema_version: Option<&'a str>,
    content_base64: String,
}

#[derive(Serialize)]
struct DeviceBindingRequest<'a> {
    client_id: &'a str,
    machine_name: &'a str,
    os_type: Option<i64>,
    device_type: Option<i64>,
}

#[derive(Deserialize)]
struct SchemaUploadResponse {
    accepted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaUploadOutcome {
    Uploaded,
    Disabled,
}

pub fn ensure_device_bound(
    settings: &CumulusSettings,
    descriptor: &DeviceDescriptor,
) -> Result<(), UploadError> {
    let scope = credential_scope(&settings.server_url, &settings.token);
    let cache_key = (scope, descriptor.client_id);
    if BOUND_DEVICES
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .is_ok_and(|bound| bound.contains(&cache_key))
    {
        return Ok(());
    }
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_millis(settings.timeout_connect_ms)))
        .timeout_global(Some(Duration::from_millis(settings.timeout_ms)))
        .http_status_as_error(false)
        .build()
        .new_agent();
    let url = format!(
        "{}/api/v1/device/bind",
        settings.server_url.trim_end_matches('/')
    );
    let client_id = descriptor.client_id.to_string();
    let body = serde_json::to_vec(&DeviceBindingRequest {
        client_id: &client_id,
        machine_name: &descriptor.machine_name,
        os_type: descriptor.os_type,
        device_type: descriptor.device_type,
    })?;
    let response = agent
        .post(&url)
        .header("Authorization", &format!("Bearer {}", settings.token))
        .header(STEAM_CLIENT_ID_HEADER, &client_id)
        .header("Content-Type", "application/json")
        .send(body.as_slice())?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(UploadError::HttpStatus(status));
    }
    if let Ok(mut bound) = BOUND_DEVICES
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
    {
        bound.insert(cache_key);
    }
    Ok(())
}

pub fn upload_events(
    settings: &CumulusSettings,
    identity: &UploadIdentity,
    events: &[QueuedAchievementEvent],
) -> Result<(), UploadError> {
    if events.is_empty() {
        return Ok(());
    }
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_millis(settings.timeout_connect_ms)))
        .timeout_global(Some(Duration::from_millis(settings.timeout_ms)))
        .http_status_as_error(false)
        .build()
        .new_agent();
    let url = format!(
        "{}/api/v1/device/achievement-events",
        settings.server_url.trim_end_matches('/')
    );
    let client_id = identity.client_id.map(|value| value.to_string());
    let body = serde_json::to_vec(&UploadRequest {
        client_id: client_id.as_deref(),
        machine_name: &identity.machine_name,
        os_type: identity.os_type,
        device_type: identity.device_type,
        steam_id64: &identity.steam_id64,
        persona_name: identity.persona_name.as_deref(),
        events,
    })?;
    let mut request = agent
        .post(&url)
        .header("Authorization", &format!("Bearer {}", settings.token))
        .header("Content-Type", "application/json");
    if let Some(client_id) = client_id.as_deref() {
        request = request.header(STEAM_CLIENT_ID_HEADER, client_id);
    }
    let response = request.send(body.as_slice())?;
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(UploadError::HttpStatus(status))
    }
}

pub fn upload_schema(
    settings: &CumulusSettings,
    schema: &QueuedAchievementSchema,
) -> Result<SchemaUploadOutcome, UploadError> {
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_millis(settings.timeout_connect_ms)))
        .timeout_global(Some(Duration::from_millis(settings.timeout_ms)))
        .http_status_as_error(false)
        .build()
        .new_agent();
    let url = format!(
        "{}/api/v1/device/achievement-schema",
        settings.server_url.trim_end_matches('/')
    );
    let body = serde_json::to_vec(&SchemaUploadRequest {
        app_id: schema.app_id,
        language: &schema.language,
        schema_version: schema.schema_version.as_deref(),
        content_base64: STANDARD.encode(&schema.content),
    })?;
    let request = agent
        .post(&url)
        .header("Authorization", &format!("Bearer {}", settings.token))
        .header("Content-Type", "application/json");
    let mut response = request.send(body.as_slice())?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(UploadError::HttpStatus(status));
    }
    let response: SchemaUploadResponse =
        serde_json::from_str(&response.body_mut().read_to_string()?)?;
    Ok(if response.accepted {
        SchemaUploadOutcome::Uploaded
    } else {
        SchemaUploadOutcome::Disabled
    })
}

pub fn upload_scope(settings: &CumulusSettings) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in settings
        .server_url
        .trim()
        .trim_end_matches('/')
        .bytes()
        .chain([0])
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
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
        return Some(PathBuf::from(root).join("vapor-forge/achievement-outbox.sqlite3"));
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/share/vapor-forge/achievement-outbox.sqlite3"))
}

#[derive(Debug, thiserror::Error)]
pub enum OutboxError {
    #[error("outbox filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("outbox database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("Cumulus returned HTTP {0}")]
    HttpStatus(u16),
    #[error("Cumulus transport failed: {0}")]
    Transport(#[from] ureq::Error),
    #[error("achievement event serialization failed: {0}")]
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
    use std::io::{Read, Write};
    use std::sync::mpsc;

    fn event(id: &str) -> QueuedAchievementEvent {
        QueuedAchievementEvent {
            owner_scope: "scope-a".into(),
            owner_steam_id64: "76561198000000091".into(),
            event_id: id.into(),
            app_id: 620,
            achievement_key: "WAKE_UP".into(),
            kind: "unlock".into(),
            progress_current: None,
            progress_max: None,
            observed_at: 1_800_000_002,
            unlocked_at: Some(1_800_000_000),
        }
    }

    fn one_request_server() -> (String, mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                if let Some(index) = request.windows(4).position(|value| value == b"\r\n\r\n") {
                    break index + 4;
                }
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            while request.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
            }
            sender.send(String::from_utf8(request).unwrap()).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .unwrap();
        });
        (format!("http://{address}"), receiver)
    }

    fn settings(server_url: String) -> CumulusSettings {
        CumulusSettings {
            server_url,
            token: "device-secret".into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 2_000,
        }
    }

    fn identity() -> UploadIdentity {
        UploadIdentity {
            client_id: Some(91),
            machine_name: "Deck".into(),
            os_type: Some(1),
            device_type: Some(2),
            steam_id64: "76561198000000091".into(),
            persona_name: None,
        }
    }

    fn schema() -> QueuedAchievementSchema {
        QueuedAchievementSchema {
            owner_scope: "scope-a".into(),
            app_id: 620,
            language: "english".into(),
            schema_version: Some("abc123".into()),
            content: b"binary-schema".to_vec(),
        }
    }

    #[test]
    fn persists_deduplicates_and_delivers_events() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let first = event("11111111-1111-4111-8111-111111111111");
        {
            let mut outbox = Outbox::open(&path).unwrap();
            assert!(outbox.enqueue(&first, 10).unwrap());
            assert!(!outbox.enqueue(&first, 11).unwrap());
            assert_eq!(outbox.len().unwrap(), 1);
            outbox
                .mark_failed(std::slice::from_ref(&first), 20)
                .unwrap();
            assert!(outbox
                .pending(20, &first.owner_scope, &first.owner_steam_id64)
                .unwrap()
                .is_empty());
        }
        let mut reopened = Outbox::open(&path).unwrap();
        assert_eq!(
            reopened
                .pending(21, &first.owner_scope, &first.owner_steam_id64)
                .unwrap(),
            vec![first.clone()]
        );
        reopened.mark_delivered(&[first]).unwrap();
        assert_eq!(reopened.len().unwrap(), 0);
    }

    #[test]
    fn persists_device_identity_across_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let descriptor = DeviceDescriptor {
            client_id: u64::MAX - 7,
            machine_name: "Steam Deck".into(),
            os_type: Some(20),
            device_type: Some(1),
        };
        {
            let outbox = Outbox::open(&path).unwrap();
            outbox.store_device_descriptor(&descriptor, 10).unwrap();
        }

        let reopened = Outbox::open(&path).unwrap();
        assert_eq!(reopened.load_device_descriptor().unwrap(), Some(descriptor));
    }

    #[test]
    fn internal_client_id_preserves_matching_protocol_metadata() {
        let descriptor = DeviceDescriptor {
            client_id: 91,
            machine_name: "Steam Deck".into(),
            os_type: Some(20),
            device_type: Some(1),
        };
        let mut current = Some(descriptor.clone());
        update_local_client_id(&mut current, 91);
        assert_eq!(current, Some(descriptor));

        update_local_client_id(&mut current, 92);
        let replacement = current.expect("new ClientID should replace stale identity");
        assert_eq!(replacement.client_id, 92);
        assert!(!replacement.machine_name.is_empty());
        assert_eq!(replacement.os_type, None);
        assert_eq!(replacement.device_type, None);
    }

    #[test]
    fn durable_pending_events_are_claimed_only_by_the_same_steam_account() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let mut first = event("11111111-1111-4111-8111-111111111111");
        first.owner_scope.clear();
        let mut other = event("22222222-2222-4222-8222-222222222222");
        other.owner_scope.clear();
        other.owner_steam_id64 = "76561198000000092".into();
        let mut pending_schema = schema();
        pending_schema.owner_scope.clear();
        {
            let outbox = Outbox::open(&path).unwrap();
            outbox.enqueue(&first, 10).unwrap();
            outbox.enqueue(&other, 11).unwrap();
            outbox.enqueue_schema(&pending_schema, 12).unwrap();
        }

        let reopened = Outbox::open(&path).unwrap();
        reopened
            .attribute_pending("scope-a", &first.owner_steam_id64)
            .unwrap();
        reopened.attribute_pending_schemas("scope-a").unwrap();
        let mut attributed = first.clone();
        attributed.owner_scope = "scope-a".into();
        assert_eq!(
            reopened
                .pending(12, "scope-a", &first.owner_steam_id64)
                .unwrap(),
            vec![attributed]
        );
        assert_eq!(
            reopened.pending(12, "", &other.owner_steam_id64).unwrap(),
            vec![other]
        );
        let mut attributed_schema = pending_schema;
        attributed_schema.owner_scope = "scope-a".into();
        assert_eq!(
            reopened.pending_schemas(12, "scope-a").unwrap(),
            vec![attributed_schema]
        );
    }

    #[test]
    fn attributing_pending_progress_keeps_the_newest_value() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let outbox = Outbox::open(&path).unwrap();
        let mut current = event("11111111-1111-4111-8111-111111111111");
        current.kind = "progress".into();
        current.progress_current = Some(2);
        current.progress_max = Some(10);
        outbox.enqueue(&current, 10).unwrap();

        let mut pending = current.clone();
        pending.owner_scope.clear();
        pending.event_id = "22222222-2222-4222-8222-222222222222".into();
        pending.progress_current = Some(8);
        outbox.enqueue(&pending, 11).unwrap();
        outbox
            .attribute_pending("scope-a", &current.owner_steam_id64)
            .unwrap();

        pending.owner_scope = "scope-a".into();
        assert_eq!(
            outbox
                .pending(11, "scope-a", &current.owner_steam_id64)
                .unwrap(),
            vec![pending]
        );
    }

    #[test]
    fn event_id_collision_does_not_discard_previous_progress() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let outbox = Outbox::open(&path).unwrap();

        let mut previous = event("11111111-1111-4111-8111-111111111111");
        previous.kind = "progress".into();
        previous.progress_current = Some(3);
        previous.progress_max = Some(10);
        outbox.enqueue(&previous, 10).unwrap();

        let mut collision = event("22222222-2222-4222-8222-222222222222");
        collision.achievement_key = "OTHER_KEY".into();
        outbox.enqueue(&collision, 11).unwrap();

        let mut replacement = previous.clone();
        replacement.event_id.clone_from(&collision.event_id);
        replacement.progress_current = Some(7);
        assert!(!outbox.enqueue(&replacement, 12).unwrap());

        assert_eq!(
            outbox
                .pending(12, &previous.owner_scope, &previous.owner_steam_id64)
                .unwrap(),
            vec![previous, collision]
        );
    }

    #[test]
    fn event_acknowledgements_cannot_cross_owner_scope() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let mut outbox = Outbox::open(&path).unwrap();
        let original = event("11111111-1111-4111-8111-111111111111");
        outbox.enqueue(&original, 10).unwrap();
        let mut forged = original.clone();
        forged.owner_scope = "scope-b".into();
        forged.owner_steam_id64 = "76561198000000092".into();

        outbox
            .mark_delivered(std::slice::from_ref(&forged))
            .unwrap();
        outbox
            .mark_failed(std::slice::from_ref(&forged), 10)
            .unwrap();
        outbox.mark_rejected(&[forged], "wrong owner", 10).unwrap();

        assert_eq!(
            outbox
                .pending(10, &original.owner_scope, &original.owner_steam_id64)
                .unwrap(),
            vec![original]
        );
    }

    #[test]
    fn progress_retention_is_scoped_to_one_owner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let mut outbox = Outbox::open(&path).unwrap();
        let mut other = event("ffffffff-ffff-4fff-8fff-ffffffffffff");
        other.owner_scope = "scope-b".into();
        other.kind = "progress".into();
        other.progress_current = Some(1);
        other.progress_max = Some(10);
        outbox.enqueue(&other, 1).unwrap();

        let transaction = outbox.connection.transaction().unwrap();
        for index in 0..5_001 {
            transaction
                .execute(
                    "INSERT INTO achievement_outbox (
                        event_id, owner_scope, owner_steam_id64, app_id, achievement_key,
                        kind, progress_current, progress_max, observed_at, created_at
                     ) VALUES (?1, 'scope-a', '76561198000000091', ?2, ?3,
                               'progress', 1, 10, 1, ?4)",
                    params![
                        format!("bulk-{index}"),
                        10_000_i64 + i64::from(index),
                        format!("KEY_{index}"),
                        index
                    ],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        let mut trigger = event("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
        trigger.kind = "progress".into();
        trigger.progress_current = Some(1);
        trigger.progress_max = Some(10);
        trigger.app_id = 999;
        trigger.achievement_key = "TRIGGER".into();
        outbox.enqueue(&trigger, 6_000).unwrap();

        assert_eq!(
            outbox
                .pending(6_000, &other.owner_scope, &other.owner_steam_id64)
                .unwrap(),
            vec![other]
        );
        let retained: i64 = outbox
            .connection
            .query_row(
                "SELECT COUNT(*) FROM achievement_outbox WHERE owner_scope = 'scope-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, 5_000);
    }

    #[test]
    fn authentication_failures_remain_retryable() {
        for status in [401, 403, 408, 409, 429, 500] {
            assert!(UploadError::HttpStatus(status).is_retryable(), "{status}");
        }
        for status in [400, 404, 413, 422] {
            assert!(!UploadError::HttpStatus(status).is_retryable(), "{status}");
        }
    }

    #[test]
    fn persists_and_coalesces_latest_schema() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let mut latest = schema();
        {
            let outbox = Outbox::open(&path).unwrap();
            outbox.enqueue_schema(&latest, 10).unwrap();
            latest.schema_version = Some("def456".into());
            latest.content = b"new-schema".to_vec();
            outbox.enqueue_schema(&latest, 11).unwrap();
        }
        let outbox = Outbox::open(&path).unwrap();
        assert_eq!(
            outbox.pending_schemas(11, "scope-a").unwrap(),
            vec![latest.clone()]
        );
        outbox.mark_schema_delivered(&latest).unwrap();
        assert!(outbox.pending_schemas(11, "scope-a").unwrap().is_empty());
    }

    #[test]
    fn isolates_accounts_and_coalesces_progress() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let outbox = Outbox::open(&path).unwrap();
        let mut first = event("11111111-1111-4111-8111-111111111111");
        first.kind = "progress".into();
        first.progress_current = Some(1);
        first.progress_max = Some(10);
        let mut latest = first.clone();
        latest.event_id = "22222222-2222-4222-8222-222222222222".into();
        latest.progress_current = Some(7);
        let mut other_account = event("33333333-3333-4333-8333-333333333333");
        other_account.owner_scope = "scope-b".into();
        let mut other_steam_account = event("44444444-4444-4444-8444-444444444444");
        other_steam_account.owner_steam_id64 = "76561198000000092".into();

        outbox.enqueue(&first, 10).unwrap();
        outbox.enqueue(&latest, 11).unwrap();
        outbox.enqueue(&other_account, 12).unwrap();
        outbox.enqueue(&other_steam_account, 12).unwrap();

        assert_eq!(
            outbox.pending(12, "scope-a", "76561198000000091").unwrap(),
            vec![latest]
        );
        assert_eq!(
            outbox.pending(12, "scope-b", "76561198000000091").unwrap(),
            vec![other_account]
        );
        assert_eq!(
            outbox.pending(12, "scope-a", "76561198000000092").unwrap(),
            vec![other_steam_account]
        );
    }

    #[test]
    fn persists_conflict_choices_across_reopen_and_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let local = QueuedConflictResolution {
            owner_scope: "credential-a".into(),
            event_id: "conflict-local-1".into(),
            app_id: 480,
            base_change_number: 1,
            remote_change_number: 2,
            resolution: "kept_local".into(),
            machine_name: Some("Deck".into()),
        };
        {
            let mut outbox = Outbox::open(&path).unwrap();
            outbox.enqueue_conflict(&local, 10).unwrap();
            assert_eq!(
                outbox
                    .pending_local_conflict("credential-a", 480, 2)
                    .unwrap(),
                Some(local.clone())
            );
        }

        let mut reopened = Outbox::open(&path).unwrap();
        assert_eq!(
            reopened
                .pending_local_conflict("credential-a", 480, 2)
                .unwrap(),
            Some(local)
        );
        let cloud = QueuedConflictResolution {
            owner_scope: "credential-a".into(),
            event_id: "conflict-cloud-1".into(),
            app_id: 480,
            base_change_number: 2,
            remote_change_number: 3,
            resolution: "kept_cloud".into(),
            machine_name: Some("Deck".into()),
        };
        reopened.enqueue_conflict(&cloud, 20).unwrap();
        assert!(reopened
            .pending_local_conflict("credential-a", 480, 2)
            .unwrap()
            .is_none());
        assert_eq!(
            reopened
                .pending_cloud_conflicts(20, "credential-a")
                .unwrap(),
            vec![cloud.clone()]
        );
        reopened.mark_conflict_failed(&cloud, 20).unwrap();
        assert!(reopened
            .pending_cloud_conflicts(20, "credential-a")
            .unwrap()
            .is_empty());
        assert_eq!(
            reopened
                .pending_cloud_conflicts(21, "credential-a")
                .unwrap(),
            vec![cloud.clone()]
        );
        reopened.mark_conflict_delivered(&cloud).unwrap();
        assert_eq!(reopened.conflict_len().unwrap(), 0);
    }

    #[test]
    fn conflict_outbox_operations_are_credential_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.db");
        let mut outbox = Outbox::open(&path).unwrap();
        let first = QueuedConflictResolution {
            owner_scope: "credential-a".into(),
            event_id: "conflict-a".into(),
            app_id: 480,
            base_change_number: 1,
            remote_change_number: 2,
            resolution: "kept_cloud".into(),
            machine_name: None,
        };
        let second = QueuedConflictResolution {
            owner_scope: "credential-b".into(),
            event_id: "conflict-b".into(),
            ..first.clone()
        };
        outbox.enqueue_conflict(&first, 10).unwrap();
        outbox.enqueue_conflict(&second, 10).unwrap();

        assert_eq!(
            outbox.pending_cloud_conflicts(10, "credential-a").unwrap(),
            vec![first.clone()]
        );
        assert_eq!(
            outbox.pending_cloud_conflicts(10, "credential-b").unwrap(),
            vec![second.clone()]
        );
        outbox.mark_conflict_failed(&first, 10).unwrap();
        assert_eq!(
            outbox.pending_cloud_conflicts(10, "credential-b").unwrap(),
            vec![second.clone()]
        );
        outbox.mark_conflict_delivered(&first).unwrap();
        assert_eq!(outbox.conflict_len().unwrap(), 1);
        assert_eq!(
            outbox.pending_cloud_conflicts(10, "credential-b").unwrap(),
            vec![second]
        );
    }

    #[test]
    fn upload_scope_survives_key_rotation_and_normalizes_server_url() {
        let first = CumulusSettings {
            server_url: " https://cloud.example.test/api/ ".into(),
            token: "old-token".into(),
            timeout_connect_ms: 1,
            timeout_ms: 1,
        };
        let mut rotated = first.clone();
        rotated.server_url = "https://cloud.example.test/api".into();
        rotated.token = "new-token".into();
        assert_eq!(upload_scope(&first), upload_scope(&rotated));
        assert_ne!(
            credential_scope(&first.server_url, &first.token),
            credential_scope(&rotated.server_url, &rotated.token)
        );
        assert_eq!(
            credential_scope(&first.server_url, &first.token),
            credential_scope("https://cloud.example.test/api", &first.token)
        );
        let mut other_server = first.clone();
        other_server.server_url = "https://other.example.test/api".into();
        assert_ne!(upload_scope(&first), upload_scope(&other_server));
    }

    #[test]
    fn uploads_event_contract_to_cumulus() {
        let (url, request) = one_request_server();
        upload_events(
            &settings(url),
            &identity(),
            &[event("11111111-1111-4111-8111-111111111111")],
        )
        .unwrap();
        let request = request.recv().unwrap();
        assert!(request.starts_with("POST /api/v1/device/achievement-events HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer device-secret"));
        assert!(request
            .to_ascii_lowercase()
            .contains("x-cumulus-steam-client-id: 91"));
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["client_id"], "91");
        assert_eq!(body["events"][0]["kind"], "unlock");
    }

    #[test]
    fn uploads_events_without_client_id_for_an_already_bound_token() {
        let (url, request) = one_request_server();
        let mut identity = identity();
        identity.client_id = None;
        upload_events(
            &settings(url),
            &identity,
            &[event("11111111-1111-4111-8111-111111111111")],
        )
        .unwrap();
        let request = request.recv().unwrap();
        assert!(!request
            .to_ascii_lowercase()
            .contains("x-cumulus-steam-client-id:"));
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert!(body.get("client_id").is_none());
    }

    #[test]
    fn uploads_schema_contract_to_cumulus() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                if let Some(index) = request.windows(4).position(|value| value == b"\r\n\r\n") {
                    break index + 4;
                }
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            while request.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
            }
            sender.send(String::from_utf8(request).unwrap()).unwrap();
            let body = r#"{"accepted":true}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let outcome = upload_schema(&settings(format!("http://{address}")), &schema()).unwrap();
        assert_eq!(outcome, SchemaUploadOutcome::Uploaded);
        let request = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(request.starts_with("POST /api/v1/device/achievement-schema HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer device-secret"));
        assert!(!request
            .to_ascii_lowercase()
            .contains("x-cumulus-steam-client-id: 91"));
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert!(body.get("steam_id64").is_none());
        assert!(body.get("client_id").is_none());
        assert_eq!(body["app_id"], 620);
        assert_eq!(body["content_base64"], "YmluYXJ5LXNjaGVtYQ==");
    }
}
