use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use vapor_forge_cloud_core::{
    AccountSyncState, AchievementEvent, AchievementSchema, AchievementSyncState, BackendError,
    CloudBackend, DeviceDescriptor, PlaytimeEntry, SchemaUploadOutcome, UploadIdentity,
};

use crate::store::atomic_publish;

const RECORD_VERSION: u32 = 1;

pub struct LocalBackend {
    root: PathBuf,
    scope: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AchievementRecord {
    version: u32,
    steam_id64: String,
    event: AchievementEvent,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlaytimeRecord {
    version: u32,
    steam_id64: String,
    client_id: u64,
    entry: PlaytimeEntry,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SchemaRecord {
    version: u32,
    app_id: u32,
    language: String,
    schema_version: Option<String>,
    blob_sha256: String,
}

impl LocalBackend {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BackendError> {
        let store = crate::FolderStore::open(root)?;
        let root = store.root().to_path_buf();
        let scope = format!("local:{}", root.display());
        Ok(Self { root, scope })
    }

    fn account_root(&self, steam_id64: &str) -> Result<PathBuf, BackendError> {
        validate_steam_id(steam_id64)?;
        Ok(self.root.join("records/accounts").join(steam_id64))
    }

    fn publish_record<T: Serialize>(
        &self,
        directory: &Path,
        identity: &[u8],
        value: &T,
    ) -> Result<(), BackendError> {
        let bytes = serde_json::to_vec(value).map_err(json_error)?;
        let id = digest(identity);
        atomic_publish(&directory.join(&id[..2]).join(format!("{id}.json")), &bytes)
    }

    fn read_records<T: for<'de> Deserialize<'de>>(
        &self,
        directory: &Path,
    ) -> Result<Vec<T>, BackendError> {
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for shard in std::fs::read_dir(directory).map_err(io_error)? {
            let shard = shard.map_err(io_error)?.path();
            if !shard.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(shard).map_err(io_error)? {
                let path = entry.map_err(io_error)?.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                records.push(
                    serde_json::from_slice(&std::fs::read(path).map_err(io_error)?)
                        .map_err(json_error)?,
                );
            }
        }
        Ok(records)
    }

    fn reduce_achievements(
        &self,
        steam_id64: &str,
    ) -> Result<Vec<AchievementSyncState>, BackendError> {
        let records: Vec<AchievementRecord> =
            self.read_records(&self.account_root(steam_id64)?.join("achievement-events"))?;
        let mut events = HashMap::<String, AchievementEvent>::new();
        for record in records {
            if record.version != RECORD_VERSION || record.steam_id64 != steam_id64 {
                return Err(permanent("invalid local achievement record"));
            }
            if let Some(existing) = events.get(&record.event.event_id) {
                if existing != &record.event {
                    return Err(permanent("conflicting local achievement event ID"));
                }
            } else {
                events.insert(record.event.event_id.clone(), record.event);
            }
        }
        let mut events = events.into_values().collect::<Vec<_>>();
        events.sort_by(|a, b| (a.observed_at, &a.event_id).cmp(&(b.observed_at, &b.event_id)));
        let mut states = BTreeMap::<(u32, String), AchievementSyncState>::new();
        for event in events {
            let state = states
                .entry((event.app_id, event.achievement_key.clone()))
                .or_insert_with(|| AchievementSyncState {
                    app_id: event.app_id,
                    achievement_key: event.achievement_key.clone(),
                    unlocked: false,
                    progress_current: None,
                    progress_max: None,
                    observed_at: event.observed_at,
                    unlocked_at: None,
                });
            state.observed_at = event.observed_at;
            match event.kind.as_str() {
                "unlock" => {
                    state.unlocked = true;
                    let incoming = event.unlocked_at.or(Some(event.observed_at));
                    state.unlocked_at = min_option(state.unlocked_at, incoming);
                }
                "clear" => {
                    state.unlocked = false;
                    state.unlocked_at = None;
                    state.progress_current = None;
                    state.progress_max = None;
                }
                "progress" => {
                    state.progress_current =
                        max_option_u32(state.progress_current, event.progress_current);
                    state.progress_max = max_option_u32(state.progress_max, event.progress_max);
                }
                _ => return Err(permanent("invalid local achievement event kind")),
            }
        }
        Ok(states.into_values().collect())
    }

    fn reduce_playtime(&self, steam_id64: &str) -> Result<Vec<PlaytimeEntry>, BackendError> {
        let records: Vec<PlaytimeRecord> =
            self.read_records(&self.account_root(steam_id64)?.join("playtime"))?;
        let mut states = BTreeMap::<u32, (PlaytimeEntry, (i64, u64, String))>::new();
        for record in records {
            if record.version != RECORD_VERSION || record.steam_id64 != steam_id64 {
                return Err(permanent("invalid local playtime record"));
            }
            let tie = serde_json::to_vec(&record).map_err(json_error)?;
            let order = (record.entry.observed_at, record.client_id, digest(&tie));
            let entry = states.entry(record.entry.app_id).or_insert_with(|| {
                let mut value = record.entry.clone();
                value.owner_scope = self.scope.clone();
                value.owner_steam_id64 = steam_id64.to_owned();
                (value, order.clone())
            });
            entry.0.playtime_minutes = entry.0.playtime_minutes.max(record.entry.playtime_minutes);
            entry.0.last_played_at =
                max_option(entry.0.last_played_at, record.entry.last_played_at);
            if order > entry.1 {
                entry.0.playtime_2weeks_minutes = record.entry.playtime_2weeks_minutes;
                entry.0.observed_at = record.entry.observed_at;
                entry.1 = order;
            }
        }
        Ok(states.into_values().map(|(entry, _)| entry).collect())
    }
}

impl CloudBackend for LocalBackend {
    fn endpoint_scope(&self) -> String {
        self.scope.clone()
    }

    fn credential_scope(&self) -> String {
        self.scope.clone()
    }

    fn ensure_device_bound(&self, descriptor: &DeviceDescriptor) -> Result<(), BackendError> {
        if descriptor.client_id == 0 {
            Err(permanent("local cloud device ID is unavailable"))
        } else {
            Ok(())
        }
    }

    fn upload_achievement_events(
        &self,
        identity: &UploadIdentity,
        events: &[AchievementEvent],
    ) -> Result<(), BackendError> {
        let directory = self
            .account_root(&identity.steam_id64)?
            .join("achievement-events");
        for event in events {
            if !valid_achievement_event(event)
                || (!event.owner_steam_id64.is_empty()
                    && event.owner_steam_id64 != identity.steam_id64)
            {
                return Err(permanent("invalid local achievement event"));
            }
            let record = AchievementRecord {
                version: RECORD_VERSION,
                steam_id64: identity.steam_id64.clone(),
                event: event.clone(),
            };
            let identity = format!("{}\0{}", identity.steam_id64, event.event_id);
            self.publish_record(&directory, identity.as_bytes(), &record)?;
        }
        Ok(())
    }

    fn upload_achievement_schema(
        &self,
        schema: &AchievementSchema,
    ) -> Result<SchemaUploadOutcome, BackendError> {
        if schema.app_id == 0 || schema.content.is_empty() {
            return Ok(SchemaUploadOutcome::Declined);
        }
        let blob_sha256 = digest(&schema.content);
        atomic_publish(
            &self
                .root
                .join("blobs/sha256")
                .join(&blob_sha256[..2])
                .join(&blob_sha256),
            &schema.content,
        )?;
        let record = SchemaRecord {
            version: RECORD_VERSION,
            app_id: schema.app_id,
            language: schema.language.clone(),
            schema_version: schema.schema_version.clone(),
            blob_sha256,
        };
        let bytes = serde_json::to_vec(&record).map_err(json_error)?;
        let id = digest(&bytes);
        atomic_publish(
            &self
                .root
                .join("records/schemas")
                .join(schema.app_id.to_string())
                .join(format!("{id}.json")),
            &bytes,
        )?;
        Ok(SchemaUploadOutcome::Accepted)
    }

    fn upload_playtime(
        &self,
        client_id: u64,
        steam_id64: &str,
        entries: &[PlaytimeEntry],
    ) -> Result<(), BackendError> {
        let directory = self.account_root(steam_id64)?.join("playtime");
        for entry in entries {
            if entry.app_id == 0
                || entry.observed_at <= 0
                || entry.last_played_at.is_some_and(|value| value < 0)
                || (!entry.owner_steam_id64.is_empty() && entry.owner_steam_id64 != steam_id64)
            {
                return Err(permanent("invalid local playtime observation"));
            }
            let record = PlaytimeRecord {
                version: RECORD_VERSION,
                steam_id64: steam_id64.to_owned(),
                client_id,
                entry: entry.clone(),
            };
            let bytes = serde_json::to_vec(&record).map_err(json_error)?;
            self.publish_record(&directory, &bytes, &record)?;
        }
        Ok(())
    }

    fn pull_account_state(
        &self,
        _client_id: u64,
        steam_id64: &str,
    ) -> Result<AccountSyncState, BackendError> {
        Ok(AccountSyncState {
            achievements: self.reduce_achievements(steam_id64)?,
            playtime: self.reduce_playtime(steam_id64)?,
        })
    }
}

fn validate_steam_id(value: &str) -> Result<(), BackendError> {
    if value.parse::<u64>().is_ok_and(|value| value != 0) {
        Ok(())
    } else {
        Err(permanent("invalid Steam account ID"))
    }
}

fn valid_achievement_event(event: &AchievementEvent) -> bool {
    let key = event.achievement_key.trim();
    if event.event_id.is_empty()
        || event.event_id.len() > 128
        || event.event_id.contains('\0')
        || event.app_id == 0
        || key.is_empty()
        || key.len() > 255
        || key.contains('\0')
        || event.observed_at <= 0
        || event.unlocked_at.is_some_and(|value| value <= 0)
        || event.progress_max == Some(0)
        || matches!((event.progress_current, event.progress_max), (Some(a), Some(b)) if a > b)
    {
        return false;
    }
    match event.kind.as_str() {
        "unlock" => true,
        "progress" => event.progress_current.is_some() && event.progress_max.is_some_and(|v| v > 0),
        "clear" => {
            event.progress_current.is_none()
                && event.progress_max.is_none()
                && event.unlocked_at.is_none()
        }
        _ => false,
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn max_option(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (some, None) | (None, some) => some,
    }
}

fn min_option(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (some, None) | (None, some) => some,
    }
}

fn max_option_u32(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (some, None) | (None, some) => some,
    }
}

fn io_error(error: std::io::Error) -> BackendError {
    BackendError::new(format!("local account sync I/O failed: {error}"), true)
}

fn json_error(error: serde_json::Error) -> BackendError {
    BackendError::new(
        format!("local account sync metadata failed: {error}"),
        false,
    )
}

fn permanent(message: impl Into<String>) -> BackendError {
    BackendError::new(message, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> UploadIdentity {
        UploadIdentity {
            client_id: 7,
            machine_name: "deck".into(),
            os_type: None,
            device_type: None,
            steam_id64: "76561198000000001".into(),
            persona_name: None,
        }
    }

    #[test]
    fn account_state_converges_immutable_records() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let identity = identity();
        backend
            .upload_achievement_events(
                &identity,
                &[
                    AchievementEvent {
                        owner_scope: String::new(),
                        owner_steam_id64: identity.steam_id64.clone(),
                        event_id: "unlock-a".into(),
                        app_id: 480,
                        achievement_key: "ACH_WIN".into(),
                        kind: "unlock".into(),
                        progress_current: None,
                        progress_max: None,
                        observed_at: 10,
                        unlocked_at: Some(9),
                    },
                    AchievementEvent {
                        owner_scope: String::new(),
                        owner_steam_id64: identity.steam_id64.clone(),
                        event_id: "clear-a".into(),
                        app_id: 480,
                        achievement_key: "ACH_WIN".into(),
                        kind: "clear".into(),
                        progress_current: None,
                        progress_max: None,
                        observed_at: 20,
                        unlocked_at: None,
                    },
                ],
            )
            .unwrap();
        backend
            .upload_playtime(
                7,
                &identity.steam_id64,
                &[PlaytimeEntry {
                    owner_scope: String::new(),
                    owner_steam_id64: identity.steam_id64.clone(),
                    app_id: 480,
                    playtime_minutes: 30,
                    playtime_2weeks_minutes: 10,
                    last_played_at: Some(100),
                    observed_at: 10,
                }],
            )
            .unwrap();
        backend
            .upload_playtime(
                8,
                &identity.steam_id64,
                &[PlaytimeEntry {
                    owner_scope: String::new(),
                    owner_steam_id64: identity.steam_id64.clone(),
                    app_id: 480,
                    playtime_minutes: 20,
                    playtime_2weeks_minutes: 4,
                    last_played_at: Some(90),
                    observed_at: 20,
                }],
            )
            .unwrap();

        let state = backend.pull_account_state(7, &identity.steam_id64).unwrap();
        assert!(!state.achievements[0].unlocked);
        assert_eq!(state.playtime[0].playtime_minutes, 30);
        assert_eq!(state.playtime[0].playtime_2weeks_minutes, 4);
        assert_eq!(state.playtime[0].last_played_at, Some(100));
    }
}
