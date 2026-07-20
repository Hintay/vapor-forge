use rusqlite::{params, OptionalExtension};

use crate::retry::retry_delay;
use crate::{Outbox, OutboxError, QueuedAchievementEvent};

const BATCH_LIMIT: usize = 100;

impl Outbox {
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
             ORDER BY observed_at, created_at, event_id
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
            let delay = retry_delay(attempts);
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
}
