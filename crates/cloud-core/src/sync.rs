use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AchievementSchema {
    pub owner_scope: String,
    pub app_id: u32,
    pub language: String,
    pub schema_version: Option<String>,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct UploadIdentity {
    pub client_id: u64,
    pub machine_name: String,
    pub os_type: Option<i64>,
    pub device_type: Option<i64>,
    pub steam_id64: String,
    pub persona_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaytimeEntry {
    #[serde(skip)]
    pub owner_scope: String,
    #[serde(skip)]
    pub owner_steam_id64: String,
    pub app_id: u32,
    pub playtime_minutes: u32,
    pub playtime_2weeks_minutes: u32,
    pub last_played_at: Option<i64>,
    pub observed_at: i64,
}

/// One playtime segment Steam reports after a connection interruption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaytimeSession {
    #[serde(skip)]
    pub owner_scope: String,
    #[serde(skip)]
    pub owner_steam_id64: String,
    pub session_id: String,
    pub app_id: u32,
    pub started_at: u32,
    pub seconds: u32,
    pub offline: bool,
    pub owner_account_id: u32,
    pub observed_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsCommit {
    pub owner_scope: String,
    pub owner_steam_id64: String,
    pub commit_id: String,
    pub app_id: u32,
    pub base_crc_stats: Option<u32>,
    pub dirty_stat_ids: Vec<u32>,
    pub observed_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteamAppSnapshot {
    #[serde(skip)]
    pub owner_scope: String,
    #[serde(skip)]
    pub owner_steam_id64: String,
    pub commit_id: String,
    pub app_id: u32,
    pub base_crc_stats: Option<u32>,
    pub dirty_stat_ids: Vec<u32>,
    pub achievements: Vec<OfficialAchievementState>,
    pub stats: Vec<OfficialStatState>,
    pub observed_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficialAchievementState {
    pub key: String,
    pub unlocked: bool,
    pub unlocked_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficialStatState {
    pub key: String,
    pub value_type: String,
    pub value: String,
}

/// Converged achievement state returned by a backend to another device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AchievementSyncState {
    pub app_id: u32,
    pub achievement_key: String,
    pub unlocked: bool,
    pub progress_current: Option<u32>,
    pub progress_max: Option<u32>,
    pub observed_at: i64,
    pub unlocked_at: Option<i64>,
}

/// Converged ordinary stat state returned by a backend to another device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatSyncState {
    pub app_id: u32,
    pub stat_key: String,
    pub value_type: String,
    pub value: String,
    pub observed_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStatsCrc {
    pub app_id: u32,
    pub crc_stats: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppStatsUploadStatus {
    Uninitialized,
    NoChange,
    Applied,
    StatsOutOfDate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStatsUploadResult {
    pub app_id: u32,
    pub status: AppStatsUploadStatus,
    pub crc_stats: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteamStateUploadResult {
    pub stats_apps: Vec<AppStatsUploadResult>,
}

/// One conditional read of the backend-authoritative stats map for an app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStatsQuery {
    pub app_id: u32,
    pub client_crc_stats: Option<u32>,
    /// Lower-case hex SHA supplied by Valve for the schema used to encode the
    /// eventual Steam response.
    pub schema_version: String,
}

/// Result of a conditional app-stats read. `Uninitialized` is deliberately
/// distinct from an initialized app whose authoritative snapshot is empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AppStatsResult {
    Uninitialized,
    SchemaMismatch {
        schema_version: Option<String>,
    },
    /// Only a backend that issues its own stats token can answer this: deciding
    /// that nothing changed means comparing the client's token against a record
    /// of what this backend last issued.
    Unchanged {
        schema_version: String,
        crc_stats: u32,
    },
    Modified {
        schema_version: String,
        /// The token this backend issues for the returned state, or `None` when it
        /// issues none and the caller must derive one from the content.
        ///
        /// A backend that arbitrates writes has to issue its own, because the
        /// client hands the token back and the backend compares it against its own
        /// record. A backend with no arbiter has nothing to compare against, so the
        /// token has to be a deterministic function of the state instead, which
        /// every reader can compute alike.
        crc_stats: Option<u32>,
        achievements: Vec<AchievementSyncState>,
        stats: Vec<StatSyncState>,
    },
}

/// Account state that can be pulled after locally observed changes are uploaded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSyncState {
    pub stats_crcs: Vec<AppStatsCrc>,
    pub playtime_revision: u64,
    pub achievements: Vec<AchievementSyncState>,
    pub stats: Vec<StatSyncState>,
    pub playtime: Vec<PlaytimeEntry>,
}

/// One authoritative playtime snapshot delivered by a backend event stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPlaytimeSnapshot {
    pub steam_id64: String,
    pub playtime_revision: u64,
    pub origin_client_id: Option<String>,
    pub playtime: Vec<PlaytimeEntry>,
}

/// Backend notification that the authoritative stats for one or more apps may
/// have changed. This is intentionally a wakeup signal only; clients must
/// re-enter Steam's native stats request path to fetch and merge state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountStatsWakeup {
    pub steam_id64: String,
    pub origin_client_id: Option<String>,
    pub app_ids: Vec<u32>,
}
