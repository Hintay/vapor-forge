use rusqlite::{params, OptionalExtension};

use crate::retry::retry_delay;
use crate::{Outbox, OutboxError, QueuedAchievementSchema};

impl Outbox {
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
        let delay = retry_delay(attempts);
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
}
