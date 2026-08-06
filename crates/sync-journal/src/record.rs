//! On-disk record types.
//!
//! One `Persistent` struct per journal record kind, with `#[index]` on exactly
//! the fields the queries below filter by. These types are private: the public
//! API speaks in `vapor_forge_cloud_core` values, so the storage layout stays
//! an implementation detail and `cloud-core` needs no storage dependency.

use std::ops::RangeBounds;

use structsy::derive::{queries, Persistent, PersistentEmbedded};
use vapor_forge_cloud_core::{
    AchievementSchema, DeviceDescriptor, OfficialAchievementState, OfficialStatState,
    PlaytimeEntry, StatsCommit, SteamAppSnapshot,
};

use crate::ConflictResolutionEvent;

/// Resolution value meaning the cloud copy won, which is the only outcome the
/// backend needs to be told about.
pub(crate) const KEPT_CLOUD: &str = "kept_cloud";

/// Bumped on every in-place update so an acknowledgement can tell whether the
/// record still holds what the caller uploaded.
pub(crate) type Revision = u64;

#[derive(Persistent)]
pub(crate) struct PlaytimeRecord {
    #[index(mode = "cluster")]
    pub(crate) owner_scope: String,
    #[index(mode = "cluster")]
    pub(crate) owner_steam_id64: String,
    pub(crate) app_id: u32,
    pub(crate) playtime_minutes: u32,
    pub(crate) playtime_2weeks_minutes: u32,
    pub(crate) last_played_at: Option<i64>,
    pub(crate) observed_at: i64,
    pub(crate) revision: Revision,
    pub(crate) attempts: i64,
    #[index(mode = "cluster")]
    pub(crate) next_attempt_at: i64,
    pub(crate) created_at: i64,
}

#[queries(PlaytimeRecord)]
pub(crate) trait PlaytimeQueries {
    fn scoped(self, owner_scope: String) -> Self;
    fn owned_by(self, owner_scope: String, owner_steam_id64: String) -> Self;
    fn for_app(self, app_id: u32) -> Self;
    fn ready<R: RangeBounds<i64>>(self, next_attempt_at: R) -> Self;
}

#[derive(Persistent)]
pub(crate) struct SchemaRecord {
    #[index(mode = "cluster")]
    pub(crate) owner_scope: String,
    pub(crate) app_id: u32,
    pub(crate) language: String,
    pub(crate) schema_version: Option<String>,
    pub(crate) content: Vec<u8>,
    pub(crate) revision: Revision,
    pub(crate) attempts: i64,
    #[index(mode = "cluster")]
    pub(crate) next_attempt_at: i64,
    pub(crate) created_at: i64,
}

#[queries(SchemaRecord)]
pub(crate) trait SchemaQueries {
    fn scoped(self, owner_scope: String) -> Self;
    fn identified(self, owner_scope: String, app_id: u32, language: String) -> Self;
    fn ready<R: RangeBounds<i64>>(self, next_attempt_at: R) -> Self;
}

#[derive(PersistentEmbedded)]
pub(crate) struct AchievementStateRecord {
    pub(crate) key: String,
    pub(crate) unlocked: bool,
    pub(crate) unlocked_at: Option<i64>,
}

#[derive(PersistentEmbedded)]
pub(crate) struct StatStateRecord {
    pub(crate) key: String,
    pub(crate) value_type: String,
    pub(crate) value: String,
}

/// A stats commit and, once Steam has produced it, the snapshot that completes
/// it. Both live in one record because a newer commit deliberately supersedes
/// an older snapshot: the snapshot describes state Steam has already replaced.
/// `snapshot_observed_at` is the discriminator — `None` means "still awaiting
/// Steam's snapshot".
#[derive(Persistent)]
pub(crate) struct StatsRecord {
    #[index(mode = "cluster")]
    pub(crate) owner_scope: String,
    #[index(mode = "cluster")]
    pub(crate) owner_steam_id64: String,
    #[index(mode = "cluster")]
    pub(crate) app_id: u32,
    pub(crate) commit_id: String,
    pub(crate) base_crc_stats: Option<u32>,
    pub(crate) dirty_stat_ids: Vec<u32>,
    pub(crate) observed_at: i64,
    pub(crate) snapshot_observed_at: Option<i64>,
    pub(crate) snapshot_achievements: Vec<AchievementStateRecord>,
    pub(crate) snapshot_stats: Vec<StatStateRecord>,
    pub(crate) revision: Revision,
    pub(crate) attempts: i64,
    #[index(mode = "cluster")]
    pub(crate) next_attempt_at: i64,
    pub(crate) created_at: i64,
}

#[queries(StatsRecord)]
pub(crate) trait StatsQueries {
    fn owned_by(self, owner_scope: String, owner_steam_id64: String) -> Self;
    fn identified(self, owner_scope: String, owner_steam_id64: String, app_id: u32) -> Self;
    fn ready<R: RangeBounds<i64>>(self, next_attempt_at: R) -> Self;
}

#[derive(Persistent)]
pub(crate) struct ConflictRecord {
    #[index(mode = "cluster")]
    pub(crate) owner_scope: String,
    #[index(mode = "cluster")]
    pub(crate) event_id: String,
    #[index(mode = "cluster")]
    pub(crate) app_id: u32,
    pub(crate) base_change_number: u64,
    pub(crate) remote_change_number: u64,
    pub(crate) resolution: String,
    pub(crate) machine_name: Option<String>,
    pub(crate) revision: Revision,
    pub(crate) attempts: i64,
    #[index(mode = "cluster")]
    pub(crate) next_attempt_at: i64,
    pub(crate) created_at: i64,
}

#[queries(ConflictRecord)]
pub(crate) trait ConflictQueries {
    fn scoped(self, owner_scope: String) -> Self;
    fn identified(self, owner_scope: String, event_id: String) -> Self;
    fn for_app(self, owner_scope: String, app_id: u32) -> Self;
    fn ready<R: RangeBounds<i64>>(self, next_attempt_at: R) -> Self;
}

/// Singleton: this machine's device identity.
#[derive(Persistent)]
pub(crate) struct DeviceRecord {
    pub(crate) client_id: u64,
    pub(crate) machine_name: String,
    pub(crate) os_type: Option<i64>,
    pub(crate) device_type: Option<i64>,
    pub(crate) observed_at: i64,
}

/// The stable owner scope discovered for one backend credential.
#[derive(Persistent)]
pub(crate) struct BackendPrincipalRecord {
    #[index(mode = "exclusive")]
    pub(crate) credential_fingerprint: String,
    pub(crate) principal_scope: String,
    pub(crate) observed_at: i64,
}

#[queries(BackendPrincipalRecord)]
pub(crate) trait BackendPrincipalQueries {
    fn identified(self, credential_fingerprint: String) -> Self;
}

// ---------------------------------------------------------------------------
// Conversions to and from the public cloud-core values
// ---------------------------------------------------------------------------

impl PlaytimeRecord {
    pub(crate) fn new(entry: &PlaytimeEntry) -> Self {
        Self {
            owner_scope: entry.owner_scope.clone(),
            owner_steam_id64: entry.owner_steam_id64.clone(),
            app_id: entry.app_id,
            playtime_minutes: entry.playtime_minutes,
            playtime_2weeks_minutes: entry.playtime_2weeks_minutes,
            last_played_at: entry.last_played_at,
            observed_at: entry.observed_at,
            revision: 0,
            attempts: 0,
            next_attempt_at: 0,
            created_at: entry.observed_at,
        }
    }

    pub(crate) fn value(&self) -> PlaytimeEntry {
        PlaytimeEntry {
            owner_scope: self.owner_scope.clone(),
            owner_steam_id64: self.owner_steam_id64.clone(),
            app_id: self.app_id,
            playtime_minutes: self.playtime_minutes,
            playtime_2weeks_minutes: self.playtime_2weeks_minutes,
            last_played_at: self.last_played_at,
            observed_at: self.observed_at,
        }
    }

    /// Fold a newer observation into this record. A snapshot observed while an
    /// upload was in flight must not be lost, so counters only ever grow.
    ///
    /// Returns whether any value moved. A re-observation of identical values
    /// must not bump the revision, or every redundant sample would re-arm an
    /// upload and invalidate an acknowledgement still in flight.
    pub(crate) fn merge(&mut self, incoming: &PlaytimeEntry) -> bool {
        let playtime_minutes = self.playtime_minutes.max(incoming.playtime_minutes);
        let last_played_at = max_option(self.last_played_at, incoming.last_played_at);
        let playtime_2weeks_minutes = if incoming.observed_at >= self.observed_at {
            incoming.playtime_2weeks_minutes
        } else {
            self.playtime_2weeks_minutes
        };
        if playtime_minutes == self.playtime_minutes
            && last_played_at == self.last_played_at
            && playtime_2weeks_minutes == self.playtime_2weeks_minutes
        {
            return false;
        }
        self.playtime_minutes = playtime_minutes;
        self.last_played_at = last_played_at;
        self.playtime_2weeks_minutes = playtime_2weeks_minutes;
        self.observed_at = self.observed_at.max(incoming.observed_at);
        self.revision = self.revision.wrapping_add(1);
        self.attempts = 0;
        self.next_attempt_at = 0;
        true
    }
}

impl SchemaRecord {
    pub(crate) fn new(schema: &AchievementSchema, now: i64) -> Self {
        Self {
            owner_scope: schema.owner_scope.clone(),
            app_id: schema.app_id,
            language: schema.language.clone(),
            schema_version: schema.schema_version.clone(),
            content: schema.content.clone(),
            revision: 0,
            attempts: 0,
            next_attempt_at: 0,
            created_at: now,
        }
    }

    pub(crate) fn value(&self) -> AchievementSchema {
        AchievementSchema {
            owner_scope: self.owner_scope.clone(),
            app_id: self.app_id,
            language: self.language.clone(),
            schema_version: self.schema_version.clone(),
            content: self.content.clone(),
        }
    }
}

impl StatsRecord {
    pub(crate) fn new(commit: &StatsCommit) -> Self {
        Self {
            owner_scope: commit.owner_scope.clone(),
            owner_steam_id64: commit.owner_steam_id64.clone(),
            app_id: commit.app_id,
            commit_id: commit.commit_id.clone(),
            base_crc_stats: commit.base_crc_stats,
            dirty_stat_ids: commit.dirty_stat_ids.clone(),
            observed_at: commit.observed_at,
            snapshot_observed_at: None,
            snapshot_achievements: Vec::new(),
            snapshot_stats: Vec::new(),
            revision: 0,
            attempts: 0,
            next_attempt_at: 0,
            created_at: commit.observed_at,
        }
    }

    pub(crate) fn commit(&self) -> StatsCommit {
        StatsCommit {
            owner_scope: self.owner_scope.clone(),
            owner_steam_id64: self.owner_steam_id64.clone(),
            commit_id: self.commit_id.clone(),
            app_id: self.app_id,
            base_crc_stats: self.base_crc_stats,
            dirty_stat_ids: self.dirty_stat_ids.clone(),
            observed_at: self.observed_at,
        }
    }

    pub(crate) fn has_snapshot(&self) -> bool {
        self.snapshot_observed_at.is_some()
    }

    /// Fill in the snapshot Steam produced for the commit this record holds.
    pub(crate) fn complete(&mut self, snapshot: &SteamAppSnapshot) {
        self.snapshot_observed_at = Some(snapshot.observed_at);
        self.snapshot_achievements = snapshot
            .achievements
            .iter()
            .map(|achievement| AchievementStateRecord {
                key: achievement.key.clone(),
                unlocked: achievement.unlocked,
                unlocked_at: achievement.unlocked_at,
            })
            .collect();
        self.snapshot_stats = snapshot
            .stats
            .iter()
            .map(|stat| StatStateRecord {
                key: stat.key.clone(),
                value_type: stat.value_type.clone(),
                value: stat.value.clone(),
            })
            .collect();
        self.revision = self.revision.wrapping_add(1);
        self.attempts = 0;
        self.next_attempt_at = 0;
    }

    /// Return the record to the awaiting-snapshot state after the backend
    /// refused the upload, adopting the baseline the backend reported. Dropping
    /// the snapshot takes the record out of the upload queue until Steam
    /// rebuilds it from the refreshed cache.
    pub(crate) fn reopen(&mut self, base_crc_stats: Option<u32>, now: i64) {
        self.base_crc_stats = base_crc_stats;
        self.snapshot_observed_at = None;
        self.snapshot_achievements = Vec::new();
        self.snapshot_stats = Vec::new();
        self.observed_at = now;
        self.revision = self.revision.wrapping_add(1);
        self.attempts = 0;
        self.next_attempt_at = 0;
    }

    pub(crate) fn snapshot(&self) -> Option<SteamAppSnapshot> {
        Some(SteamAppSnapshot {
            owner_scope: self.owner_scope.clone(),
            owner_steam_id64: self.owner_steam_id64.clone(),
            commit_id: self.commit_id.clone(),
            app_id: self.app_id,
            base_crc_stats: self.base_crc_stats,
            dirty_stat_ids: self.dirty_stat_ids.clone(),
            achievements: self
                .snapshot_achievements
                .iter()
                .map(|achievement| OfficialAchievementState {
                    key: achievement.key.clone(),
                    unlocked: achievement.unlocked,
                    unlocked_at: achievement.unlocked_at,
                })
                .collect(),
            stats: self
                .snapshot_stats
                .iter()
                .map(|stat| OfficialStatState {
                    key: stat.key.clone(),
                    value_type: stat.value_type.clone(),
                    value: stat.value.clone(),
                })
                .collect(),
            observed_at: self.snapshot_observed_at?,
        })
    }
}

impl ConflictRecord {
    pub(crate) fn new(resolution: &ConflictResolutionEvent, now: i64) -> Self {
        Self {
            owner_scope: resolution.owner_scope.clone(),
            event_id: resolution.event_id.clone(),
            app_id: resolution.app_id,
            base_change_number: resolution.base_change_number,
            remote_change_number: resolution.remote_change_number,
            resolution: resolution.resolution.clone(),
            machine_name: resolution.machine_name.clone(),
            revision: 0,
            attempts: 0,
            next_attempt_at: 0,
            created_at: now,
        }
    }

    pub(crate) fn value(&self) -> ConflictResolutionEvent {
        ConflictResolutionEvent {
            owner_scope: self.owner_scope.clone(),
            event_id: self.event_id.clone(),
            app_id: self.app_id,
            base_change_number: self.base_change_number,
            remote_change_number: self.remote_change_number,
            resolution: self.resolution.clone(),
            machine_name: self.machine_name.clone(),
        }
    }

    pub(crate) fn kept_cloud(&self) -> bool {
        self.resolution == KEPT_CLOUD
    }
}

impl DeviceRecord {
    pub(crate) fn value(&self) -> DeviceDescriptor {
        DeviceDescriptor {
            client_id: self.client_id,
            machine_name: self.machine_name.clone(),
            os_type: self.os_type,
            device_type: self.device_type,
        }
    }
}

fn max_option(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}
