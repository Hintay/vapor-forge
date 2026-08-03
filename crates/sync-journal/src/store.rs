use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use structsy::{Fetch, Filter, Ref, Structsy, StructsyTx};
use vapor_forge_cloud_core::{
    AchievementSchema, DeviceDescriptor, PlaytimeEntry, PlaytimeSession, StatsCommit,
    SteamAppSnapshot,
};

use crate::record::*;
use crate::retry::retry_delay;
use crate::{ConflictResolutionEvent, SyncJournalError};

const PLAYTIME_BATCH_LIMIT: usize = 500;
const SCHEMA_BATCH_LIMIT: usize = 10;
const STATS_BATCH_LIMIT: usize = 100;
const CONFLICT_BATCH_LIMIT: usize = 100;

/// A record handed out for upload, carrying the identity needed to settle it.
///
/// `revision` is the guard that makes acknowledgement exact: a snapshot
/// observed while the upload was in flight bumps the stored revision, so
/// [`SyncJournal::acknowledge`] leaves the newer state alone.
#[derive(Clone, Debug)]
pub struct Queued<T> {
    pub value: T,
    id: String,
    revision: u64,
}

impl<T> Queued<T> {
    fn new(id: &Ref<impl structsy::Persistent>, revision: u64, value: T) -> Self {
        Self {
            value,
            id: id.to_string(),
            revision,
        }
    }

    fn reference<R: structsy::Persistent>(&self) -> Result<Ref<R>, SyncJournalError> {
        self.id
            .parse()
            .map_err(|_| SyncJournalError::Storage(format!("unusable record id: {}", self.id)))
    }
}

/// Copy the values out of a batch for handing to a backend.
pub fn values<T: Clone>(items: &[Queued<T>]) -> Vec<T> {
    items.iter().map(|item| item.value.clone()).collect()
}

mod sealed {
    pub trait Sealed {}
}

/// Journal record kinds that are uploaded and then settled by identity.
pub trait Journaled: sealed::Sealed + Sized {
    #[doc(hidden)]
    fn settle(journal: &SyncJournal, items: &[Queued<Self>]) -> Result<(), SyncJournalError>;
    #[doc(hidden)]
    fn postpone(
        journal: &SyncJournal,
        items: &[Queued<Self>],
        now: i64,
    ) -> Result<(), SyncJournalError>;
}

/// Wire one public value type to its stored record so the generic outbox API
/// can settle it without exposing the storage layout.
macro_rules! journaled {
    ($value:ty, $record:ty) => {
        impl sealed::Sealed for $value {}

        impl Journaled for $value {
            fn settle(
                journal: &SyncJournal,
                items: &[Queued<Self>],
            ) -> Result<(), SyncJournalError> {
                journal.write(|tx| {
                    for item in items {
                        let id = item.reference::<$record>()?;
                        let Some(stored) = tx.read(&id)? else {
                            continue;
                        };
                        if stored.revision == item.revision {
                            tx.delete(&id)?;
                        }
                    }
                    Ok(())
                })
            }

            fn postpone(
                journal: &SyncJournal,
                items: &[Queued<Self>],
                now: i64,
            ) -> Result<(), SyncJournalError> {
                journal.write(|tx| {
                    for item in items {
                        let id = item.reference::<$record>()?;
                        let Some(mut stored) = tx.read(&id)? else {
                            continue;
                        };
                        if stored.revision != item.revision {
                            continue;
                        }
                        stored.next_attempt_at = now.saturating_add(retry_delay(stored.attempts));
                        stored.attempts = stored.attempts.saturating_add(1);
                        tx.update(&id, &stored)?;
                    }
                    Ok(())
                })
            }
        }
    };
}

journaled!(PlaytimeEntry, PlaytimeRecord);
journaled!(PlaytimeSession, PlaytimeSessionRecord);
journaled!(AchievementSchema, SchemaRecord);
journaled!(SteamAppSnapshot, StatsRecord);
journaled!(ConflictResolutionEvent, ConflictRecord);

pub struct SyncJournal {
    database: Structsy,
    /// Serializes write transactions.
    ///
    /// persy locks per record id and an insert always mints a fresh one, so two
    /// concurrent transactions can both observe "no record matches" and both
    /// insert, leaving two rows for one logical identity. The default
    /// `TxStrategy::LastWin` does not reject that, and `#[index(mode =
    /// "cluster")]` deliberately permits duplicate keys. Every write therefore
    /// runs under this lock, which makes a check-and-insert inside one
    /// transaction atomic against the other journal writers.
    writer: Mutex<()>,
}

impl SyncJournal {
    /// Open the journal at `path`.
    ///
    /// structsy holds an exclusive file lock for the lifetime of the returned
    /// value, so a process must not keep two handles to the same file open at
    /// once. Use [`crate::shared`] unless the caller genuinely owns the file.
    pub fn open(path: &Path) -> Result<Self, SyncJournalError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            set_private_directory_mode(parent)?;
        }
        let database = Structsy::open(path)?;
        set_private_file_mode(path)?;
        database.define::<PlaytimeRecord>()?;
        database.define::<PlaytimeSessionRecord>()?;
        database.define::<SchemaRecord>()?;
        database.define::<StatsRecord>()?;
        database.define::<ConflictRecord>()?;
        database.define::<DeviceRecord>()?;
        database.define::<BackendPrincipalRecord>()?;
        Ok(Self {
            database,
            writer: Mutex::new(()),
        })
    }

    // -----------------------------------------------------------------------
    // Generic outbox
    // -----------------------------------------------------------------------

    /// Drop a record that has been accepted, or permanently rejected, by the
    /// backend. A record updated since it was handed out is left in place.
    pub fn acknowledge<T: Journaled>(&self, item: &Queued<T>) -> Result<(), SyncJournalError> {
        T::settle(self, std::slice::from_ref(item))
    }

    pub fn acknowledge_all<T: Journaled>(
        &self,
        items: &[Queued<T>],
    ) -> Result<(), SyncJournalError> {
        T::settle(self, items)
    }

    /// Schedule another attempt after a retryable failure.
    pub fn defer<T: Journaled>(&self, item: &Queued<T>, now: i64) -> Result<(), SyncJournalError> {
        T::postpone(self, std::slice::from_ref(item), now)
    }

    pub fn defer_all<T: Journaled>(
        &self,
        items: &[Queued<T>],
        now: i64,
    ) -> Result<(), SyncJournalError> {
        T::postpone(self, items, now)
    }

    // -----------------------------------------------------------------------
    // Playtime totals
    // -----------------------------------------------------------------------

    pub fn enqueue_playtime(&self, entries: &[PlaytimeEntry]) -> Result<usize, SyncJournalError> {
        self.write(|tx| {
            for incoming in entries {
                let existing = Filter::<PlaytimeRecord>::new()
                    .owned_by(
                        incoming.owner_scope.clone(),
                        incoming.owner_steam_id64.clone(),
                    )
                    .for_app(incoming.app_id)
                    .fetch_tx(tx)
                    .next();
                match existing {
                    Some((id, mut stored)) => {
                        if stored.merge(incoming) {
                            tx.update(&id, &stored)?;
                        }
                    }
                    None => {
                        tx.insert(&PlaytimeRecord::new(incoming))?;
                    }
                }
            }
            Ok(entries.len())
        })
    }

    /// Accounts under `owner_scope` with playtime or sessions due for upload.
    pub fn ready_playtime_accounts(
        &self,
        owner_scope: &str,
        now: i64,
    ) -> Result<Vec<String>, SyncJournalError> {
        let mut accounts = BTreeSet::new();
        for (_, record) in self.fetch(
            Filter::<PlaytimeRecord>::new()
                .scoped(owner_scope.to_owned())
                .ready(..=now),
        ) {
            accounts.insert(record.owner_steam_id64);
        }
        for (_, record) in self.fetch(
            Filter::<PlaytimeSessionRecord>::new()
                .scoped(owner_scope.to_owned())
                .ready(..=now),
        ) {
            accounts.insert(record.owner_steam_id64);
        }
        Ok(accounts.into_iter().collect())
    }

    /// Earliest time any playtime record in this scope is eligible for upload.
    pub fn next_playtime_attempt_at(
        &self,
        owner_scope: &str,
    ) -> Result<Option<i64>, SyncJournalError> {
        let totals = self
            .fetch(Filter::<PlaytimeRecord>::new().scoped(owner_scope.to_owned()))
            .map(|(_, record)| record.next_attempt_at)
            .min();
        let sessions = self
            .fetch(Filter::<PlaytimeSessionRecord>::new().scoped(owner_scope.to_owned()))
            .map(|(_, record)| record.next_attempt_at)
            .min();
        Ok(match (totals, sessions) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (some, None) | (None, some) => some,
        })
    }

    pub fn pending_playtime(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
        now: i64,
    ) -> Result<Vec<Queued<PlaytimeEntry>>, SyncJournalError> {
        let mut pending = self
            .fetch(
                Filter::<PlaytimeRecord>::new()
                    .owned_by(owner_scope.to_owned(), owner_steam_id64.to_owned())
                    .ready(..=now),
            )
            .map(|(id, record)| {
                (
                    record.app_id,
                    Queued::new(&id, record.revision, record.value()),
                )
            })
            .collect::<Vec<_>>();
        pending.sort_by_key(|(app_id, _)| *app_id);
        pending.truncate(PLAYTIME_BATCH_LIMIT);
        Ok(pending.into_iter().map(|(_, queued)| queued).collect())
    }

    pub fn playtime_len(&self) -> Result<u64, SyncJournalError> {
        Ok(self.database.scan::<PlaytimeRecord>()?.count() as u64)
    }

    pub fn playtime_empty(&self) -> Result<bool, SyncJournalError> {
        self.playtime_len().map(|len| len == 0)
    }

    // -----------------------------------------------------------------------
    // Steam-authored playtime sessions
    // -----------------------------------------------------------------------

    /// Persist sessions that Steam has finalized. Re-delivery of a session
    /// already on file is a no-op, so the CM request can be acknowledged more
    /// than once.
    pub fn enqueue_playtime_sessions(
        &self,
        sessions: &[PlaytimeSession],
    ) -> Result<usize, SyncJournalError> {
        self.write(|tx| {
            let mut inserted = 0;
            for session in sessions {
                let known = Filter::<PlaytimeSessionRecord>::new()
                    .identified(
                        session.owner_scope.clone(),
                        session.owner_steam_id64.clone(),
                        session.session_id.clone(),
                    )
                    .fetch_tx(tx)
                    .next()
                    .is_some();
                if known {
                    continue;
                }
                tx.insert(&PlaytimeSessionRecord::new(session))?;
                inserted += 1;
            }
            Ok(inserted)
        })
    }

    pub fn pending_playtime_sessions(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
        now: i64,
    ) -> Result<Vec<Queued<PlaytimeSession>>, SyncJournalError> {
        let mut pending = self
            .fetch(
                Filter::<PlaytimeSessionRecord>::new()
                    .owned_by(owner_scope.to_owned(), owner_steam_id64.to_owned())
                    .ready(..=now),
            )
            .map(|(id, record)| {
                (
                    (
                        record.started_at,
                        record.created_at,
                        record.session_id.clone(),
                    ),
                    Queued::new(&id, record.revision, record.value()),
                )
            })
            .collect::<Vec<_>>();
        pending.sort_by(|(left, _), (right, _)| left.cmp(right));
        pending.truncate(PLAYTIME_BATCH_LIMIT);
        Ok(pending.into_iter().map(|(_, queued)| queued).collect())
    }

    pub fn playtime_session_len(&self) -> Result<u64, SyncJournalError> {
        Ok(self.database.scan::<PlaytimeSessionRecord>()?.count() as u64)
    }

    // -----------------------------------------------------------------------
    // Achievement schemas
    // -----------------------------------------------------------------------

    pub fn enqueue_schema(
        &self,
        schema: &AchievementSchema,
        now: i64,
    ) -> Result<(), SyncJournalError> {
        self.write(|tx| {
            let existing = Filter::<SchemaRecord>::new()
                .identified(
                    schema.owner_scope.clone(),
                    schema.app_id,
                    schema.language.clone(),
                )
                .fetch_tx(tx)
                .next();
            let mut record = SchemaRecord::new(schema, now);
            match existing {
                Some((id, stored)) => {
                    record.revision = stored.revision.wrapping_add(1);
                    record.created_at = stored.created_at;
                    tx.update(&id, &record)?;
                }
                None => {
                    tx.insert(&record)?;
                }
            }
            Ok(())
        })
    }

    /// Attach the backend scope to schemas queued before one was known.
    pub fn attribute_pending_schemas(&self, owner_scope: &str) -> Result<(), SyncJournalError> {
        if owner_scope.is_empty() {
            return Ok(());
        }
        self.write(|tx| {
            let orphans = Filter::<SchemaRecord>::new()
                .scoped(String::new())
                .fetch_tx(tx)
                .collect::<Vec<_>>();
            for (id, mut record) in orphans {
                record.owner_scope = owner_scope.to_owned();
                record.revision = record.revision.wrapping_add(1);
                tx.update(&id, &record)?;
            }
            Ok(())
        })
    }

    pub fn pending_schemas(
        &self,
        now: i64,
        owner_scope: &str,
    ) -> Result<Vec<Queued<AchievementSchema>>, SyncJournalError> {
        let mut pending = self
            .fetch(
                Filter::<SchemaRecord>::new()
                    .scoped(owner_scope.to_owned())
                    .ready(..=now),
            )
            .map(|(id, record)| {
                (
                    (record.created_at, record.app_id),
                    Queued::new(&id, record.revision, record.value()),
                )
            })
            .collect::<Vec<_>>();
        pending.sort_by_key(|(left, _)| *left);
        pending.truncate(SCHEMA_BATCH_LIMIT);
        Ok(pending.into_iter().map(|(_, queued)| queued).collect())
    }

    pub fn next_schema_attempt_at(
        &self,
        owner_scope: &str,
    ) -> Result<Option<i64>, SyncJournalError> {
        Ok(self
            .fetch(Filter::<SchemaRecord>::new().scoped(owner_scope.to_owned()))
            .map(|(_, record)| record.next_attempt_at)
            .min())
    }

    // -----------------------------------------------------------------------
    // Stats commits and the snapshots that complete them
    // -----------------------------------------------------------------------

    /// Record that Steam is about to commit stats for one app. A newer commit
    /// supersedes any snapshot still queued for that app.
    pub fn enqueue_stats_commit(&self, commit: &StatsCommit) -> Result<(), SyncJournalError> {
        self.write(|tx| {
            let existing = Self::stats_for(
                tx,
                &commit.owner_scope,
                &commit.owner_steam_id64,
                commit.app_id,
            );
            let mut record = StatsRecord::new(commit);
            match existing {
                Some((id, stored)) => {
                    record.revision = stored.revision.wrapping_add(1);
                    tx.update(&id, &record)?;
                }
                None => {
                    tx.insert(&record)?;
                }
            }
            Ok(())
        })
    }

    pub fn pending_stats_commit(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
        app_id: u32,
    ) -> Result<Option<StatsCommit>, SyncJournalError> {
        Ok(self
            .stats_record(owner_scope, owner_steam_id64, app_id)
            .filter(|(_, record)| !record.has_snapshot())
            .map(|(_, record)| record.commit()))
    }

    /// Whether this app has a marker or snapshot still owed to the backend.
    pub fn stats_sync_pending(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
        app_id: u32,
    ) -> Result<bool, SyncJournalError> {
        Ok(self
            .stats_record(owner_scope, owner_steam_id64, app_id)
            .is_some())
    }

    /// Upgrade a pending commit marker into the snapshot Steam produced for it.
    /// Returns `false` when the marker has since been replaced by a newer
    /// commit, in which case the snapshot describes stale state.
    pub fn complete_stats_snapshot(
        &self,
        snapshot: &SteamAppSnapshot,
    ) -> Result<bool, SyncJournalError> {
        self.write(|tx| {
            let Some((id, mut record)) = Self::stats_for(
                tx,
                &snapshot.owner_scope,
                &snapshot.owner_steam_id64,
                snapshot.app_id,
            ) else {
                return Ok(false);
            };
            if record.has_snapshot() || record.commit_id != snapshot.commit_id {
                return Ok(false);
            }
            record.complete(snapshot);
            tx.update(&id, &record)?;
            Ok(true)
        })
    }

    pub fn pending_stats_snapshots(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
        now: i64,
    ) -> Result<Vec<Queued<SteamAppSnapshot>>, SyncJournalError> {
        let mut pending = self
            .fetch(
                Filter::<StatsRecord>::new()
                    .owned_by(owner_scope.to_owned(), owner_steam_id64.to_owned())
                    .ready(..=now),
            )
            .filter_map(|(id, record)| {
                let snapshot = record.snapshot()?;
                Some((
                    (record.created_at, record.app_id),
                    Queued::new(&id, record.revision, snapshot),
                ))
            })
            .collect::<Vec<_>>();
        pending.sort_by_key(|(left, _)| *left);
        pending.truncate(STATS_BATCH_LIMIT);
        Ok(pending.into_iter().map(|(_, queued)| queued).collect())
    }

    pub fn next_stats_snapshot_attempt_at(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
    ) -> Result<Option<i64>, SyncJournalError> {
        Ok(self
            .fetch(
                Filter::<StatsRecord>::new()
                    .owned_by(owner_scope.to_owned(), owner_steam_id64.to_owned()),
            )
            .filter(|(_, record)| record.has_snapshot())
            .map(|(_, record)| record.next_attempt_at)
            .min())
    }

    /// Apps holding a commit that still owes a snapshot from Steam and whose
    /// backoff has elapsed. Callers ask Steam to produce one.
    pub fn stats_awaiting_snapshot(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
        now: i64,
    ) -> Result<Vec<u32>, SyncJournalError> {
        Ok(self
            .fetch(
                Filter::<StatsRecord>::new()
                    .owned_by(owner_scope.to_owned(), owner_steam_id64.to_owned())
                    .ready(..=now),
            )
            .filter(|(_, record)| !record.has_snapshot())
            .map(|(_, record)| record.app_id)
            .collect())
    }

    /// Put a refused upload back into the awaiting-snapshot state and adopt the
    /// baseline the backend reported. Returns `false` when the record has since
    /// been replaced by a newer commit, which already supersedes this one.
    pub fn reopen_stats_commit(
        &self,
        item: &Queued<SteamAppSnapshot>,
        base_crc_stats: Option<u32>,
        now: i64,
    ) -> Result<bool, SyncJournalError> {
        self.write(|tx| {
            let id = item.reference::<StatsRecord>()?;
            let Some(mut stored) = tx.read(&id)? else {
                return Ok(false);
            };
            if stored.revision != item.revision {
                return Ok(false);
            }
            stored.reopen(base_crc_stats, now);
            tx.update(&id, &stored)?;
            Ok(true)
        })
    }

    // -----------------------------------------------------------------------
    // Cloud conflict resolutions
    // -----------------------------------------------------------------------

    /// Queue a resolution, superseding any earlier one for the same app.
    pub fn enqueue_conflict(
        &self,
        resolution: &ConflictResolutionEvent,
        now: i64,
    ) -> Result<(), SyncJournalError> {
        self.write(|tx| {
            let superseded = Filter::<ConflictRecord>::new()
                .for_app(resolution.owner_scope.clone(), resolution.app_id)
                .fetch_tx(tx)
                .filter(|(_, record)| record.event_id != resolution.event_id)
                .map(|(id, _)| id)
                .collect::<Vec<_>>();
            for id in superseded {
                tx.delete(&id)?;
            }
            let existing = Filter::<ConflictRecord>::new()
                .identified(resolution.owner_scope.clone(), resolution.event_id.clone())
                .fetch_tx(tx)
                .next();
            let mut record = ConflictRecord::new(resolution, now);
            match existing {
                Some((id, stored)) => {
                    record.revision = stored.revision.wrapping_add(1);
                    record.created_at = stored.created_at;
                    tx.update(&id, &record)?;
                }
                None => {
                    tx.insert(&record)?;
                }
            }
            Ok(())
        })
    }

    /// Move conflicts staged under a credential to its resolved principal.
    pub fn attribute_pending_conflicts(
        &self,
        credential_scope: &str,
        principal_scope: &str,
    ) -> Result<(), SyncJournalError> {
        if credential_scope.is_empty()
            || principal_scope.is_empty()
            || credential_scope == principal_scope
        {
            return Ok(());
        }
        self.write(|tx| {
            let staged = Filter::<ConflictRecord>::new()
                .scoped(credential_scope.to_owned())
                .fetch_tx(tx)
                .collect::<Vec<_>>();
            for (id, mut record) in staged {
                let superseded = Filter::<ConflictRecord>::new()
                    .for_app(principal_scope.to_owned(), record.app_id)
                    .fetch_tx(tx)
                    .map(|(id, _)| id)
                    .collect::<Vec<_>>();
                for superseded_id in superseded {
                    tx.delete(&superseded_id)?;
                }
                record.owner_scope = principal_scope.to_owned();
                record.revision = record.revision.wrapping_add(1);
                tx.update(&id, &record)?;
            }
            Ok(())
        })
    }

    /// Resolutions the backend still needs to be told about.
    pub fn pending_cloud_conflicts(
        &self,
        now: i64,
        owner_scope: &str,
    ) -> Result<Vec<Queued<ConflictResolutionEvent>>, SyncJournalError> {
        let mut pending = self
            .fetch(
                Filter::<ConflictRecord>::new()
                    .scoped(owner_scope.to_owned())
                    .ready(..=now),
            )
            .filter(|(_, record)| record.kept_cloud())
            .map(|(id, record)| {
                (
                    (record.created_at, record.event_id.clone()),
                    Queued::new(&id, record.revision, record.value()),
                )
            })
            .collect::<Vec<_>>();
        pending.sort_by(|(left, _), (right, _)| left.cmp(right));
        pending.truncate(CONFLICT_BATCH_LIMIT);
        Ok(pending.into_iter().map(|(_, queued)| queued).collect())
    }

    /// The local-wins resolution to bind to the next upload batch, if any.
    pub fn pending_local_conflict(
        &self,
        owner_scope: &str,
        app_id: u32,
        remote_change_number: u64,
    ) -> Result<Option<Queued<ConflictResolutionEvent>>, SyncJournalError> {
        Ok(self
            .fetch(Filter::<ConflictRecord>::new().for_app(owner_scope.to_owned(), app_id))
            .filter(|(_, record)| {
                record.remote_change_number == remote_change_number && !record.kept_cloud()
            })
            .max_by_key(|(_, record)| record.created_at)
            .map(|(id, record)| Queued::new(&id, record.revision, record.value())))
    }

    pub fn conflict_len(&self) -> Result<u64, SyncJournalError> {
        Ok(self.database.scan::<ConflictRecord>()?.count() as u64)
    }

    pub fn stats_len(&self) -> Result<u64, SyncJournalError> {
        Ok(self.database.scan::<StatsRecord>()?.count() as u64)
    }

    // -----------------------------------------------------------------------
    // Device identity and backend principal
    // -----------------------------------------------------------------------

    pub fn load_device_descriptor(&self) -> Result<Option<DeviceDescriptor>, SyncJournalError> {
        Ok(self
            .database
            .scan::<DeviceRecord>()?
            .next()
            .map(|(_, record)| record.value()))
    }

    pub fn store_device_descriptor(
        &self,
        descriptor: &DeviceDescriptor,
        now: i64,
    ) -> Result<bool, SyncJournalError> {
        let _writer = self
            .writer
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let existing = self.database.scan::<DeviceRecord>()?.next();
        if existing
            .as_ref()
            .is_some_and(|(_, record)| record.value() == *descriptor)
        {
            return Ok(false);
        }

        let record = DeviceRecord {
            client_id: descriptor.client_id,
            machine_name: descriptor.machine_name.clone(),
            os_type: descriptor.os_type,
            device_type: descriptor.device_type,
            observed_at: now,
        };
        let mut transaction = self.database.begin()?;
        match existing {
            Some((id, _)) => transaction.update(&id, &record)?,
            None => {
                transaction.insert(&record)?;
            }
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn load_backend_principal_scope(
        &self,
        credential_fingerprint: &str,
    ) -> Result<Option<String>, SyncJournalError> {
        if credential_fingerprint.is_empty() {
            return Ok(None);
        }
        Ok(self
            .fetch(
                Filter::<BackendPrincipalRecord>::new()
                    .identified(credential_fingerprint.to_owned()),
            )
            .next()
            .map(|(_, record)| record.principal_scope))
    }

    pub fn store_backend_principal_scope(
        &self,
        credential_fingerprint: &str,
        principal_scope: &str,
        now: i64,
    ) -> Result<(), SyncJournalError> {
        if credential_fingerprint.is_empty() || principal_scope.is_empty() {
            return Ok(());
        }
        self.write(|tx| {
            let record = BackendPrincipalRecord {
                credential_fingerprint: credential_fingerprint.to_owned(),
                principal_scope: principal_scope.to_owned(),
                observed_at: now,
            };
            let existing = Filter::<BackendPrincipalRecord>::new()
                .identified(credential_fingerprint.to_owned())
                .fetch_tx(tx)
                .next();
            match existing {
                Some((id, _)) => tx.update(&id, &record)?,
                None => {
                    tx.insert(&record)?;
                }
            }
            Ok(())
        })
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// Run `action` in one transaction, rolling back if it fails.
    ///
    /// Holds [`Self::writer`] for the whole transaction, so a check-and-insert
    /// written inside `action` cannot race another writer.
    fn write<T>(
        &self,
        action: impl FnOnce(&mut structsy::OwnedSytx) -> Result<T, SyncJournalError>,
    ) -> Result<T, SyncJournalError> {
        let _writer = self
            .writer
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut transaction = self.database.begin()?;
        let output = action(&mut transaction)?;
        transaction.commit()?;
        Ok(output)
    }

    fn fetch<T: structsy::Persistent + 'static>(
        &self,
        filter: Filter<T>,
    ) -> impl Iterator<Item = (Ref<T>, T)> + '_ {
        self.database.fetch(filter)
    }

    fn stats_record(
        &self,
        owner_scope: &str,
        owner_steam_id64: &str,
        app_id: u32,
    ) -> Option<(Ref<StatsRecord>, StatsRecord)> {
        self.fetch(Filter::<StatsRecord>::new().identified(
            owner_scope.to_owned(),
            owner_steam_id64.to_owned(),
            app_id,
        ))
        .next()
    }

    fn stats_for(
        tx: &mut structsy::OwnedSytx,
        owner_scope: &str,
        owner_steam_id64: &str,
        app_id: u32,
    ) -> Option<(Ref<StatsRecord>, StatsRecord)> {
        Filter::<StatsRecord>::new()
            .identified(owner_scope.to_owned(), owner_steam_id64.to_owned(), app_id)
            .fetch_tx(tx)
            .next()
    }
}

#[cfg(unix)]
fn set_private_directory_mode(path: &Path) -> Result<(), SyncJournalError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory_mode(_path: &Path) -> Result<(), SyncJournalError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) -> Result<(), SyncJournalError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) -> Result<(), SyncJournalError> {
    Ok(())
}
