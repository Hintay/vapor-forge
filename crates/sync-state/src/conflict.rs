use rusqlite::{params, OptionalExtension};

use crate::retry::retry_delay;
use crate::{Outbox, OutboxError, QueuedConflictResolution};

const BATCH_LIMIT: usize = 100;

impl Outbox {
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
        let delay = retry_delay(attempts);
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
