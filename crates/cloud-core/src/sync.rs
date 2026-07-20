use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AchievementEvent {
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
