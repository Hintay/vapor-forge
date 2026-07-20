use std::path::Path;

use rusqlite::Connection;

use crate::db::open_database;
use crate::OutboxError;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS achievement_outbox (
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
            );";

pub struct Outbox {
    pub(crate) connection: Connection,
}

impl Outbox {
    pub fn open(path: &Path) -> Result<Self, OutboxError> {
        open_database(path, SCHEMA).map(|connection| Self { connection })
    }
}
