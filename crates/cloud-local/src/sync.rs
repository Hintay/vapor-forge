use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use vapor_forge_cloud_core::{
    AccountSyncState, AchievementSchema, AchievementSyncState, AppStatsQuery, AppStatsResult,
    AppStatsUploadResult, AppStatsUploadStatus, BackendError, CloudBackend, DeviceDescriptor,
    PlaytimeEntry, SchemaUploadOutcome, StatSyncState, SteamAppSnapshot, SteamStateUploadResult,
    UploadIdentity,
};

use crate::store::atomic_replace;

const STATS_DIR: &str = "stats";
const PLAYTIME_DIR: &str = "playtime";
const MAX_STATS_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STATS_ENTRIES: usize = 100_000;
const MAX_PLAYTIME_RECORD_BYTES: u64 = 64 * 1024;
const MAX_DEVICE_RECORDS: usize = 4096;
const MAX_ACCOUNT_APPS: usize = 100_000;

pub struct LocalBackend {
    root: PathBuf,
    scope: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PlaytimeRecord {
    steam_id64: String,
    client_id: u64,
    entry: PlaytimeEntry,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SteamAppStateRecord {
    steam_id64: String,
    client_id: u64,
    app_id: u32,
    commit_id: String,
    observed_at: i64,
    achievements: Vec<StoredAchievementState>,
    stats: Vec<StoredStatState>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredAchievementState {
    key: String,
    unlocked: bool,
    unlocked_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredStatState {
    key: String,
    value_type: String,
    value: String,
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
        Ok(self.root.join(steam_id64))
    }

    fn app_root(&self, steam_id64: &str, app_id: u32) -> Result<PathBuf, BackendError> {
        if app_id == 0 {
            return Err(permanent("invalid local AppID"));
        }
        Ok(self.account_root(steam_id64)?.join(app_id.to_string()))
    }

    fn account_app_roots(&self, steam_id64: &str) -> Result<Vec<(u32, PathBuf)>, BackendError> {
        let account_root = self.account_root(steam_id64)?;
        if !account_root.exists() {
            return Ok(Vec::new());
        }
        let mut apps = Vec::new();
        for entry in std::fs::read_dir(account_root).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if !entry.file_type().map_err(io_error)?.is_dir() {
                continue;
            }
            let Some(app_id) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value != 0)
            else {
                continue;
            };
            if apps.len() >= MAX_ACCOUNT_APPS {
                return Err(permanent("too many local account App directories"));
            }
            apps.push((app_id, entry.path()));
        }
        apps.sort_by_key(|(app_id, _)| *app_id);
        Ok(apps)
    }

    fn read_playtime_records_with_paths(
        &self,
        directory: &Path,
    ) -> Result<Vec<(PathBuf, PlaytimeRecord)>, BackendError> {
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for entry in std::fs::read_dir(directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            if !entry.file_type().map_err(io_error)?.is_file() {
                return Err(permanent("invalid local playtime state file"));
            }
            if records.len() >= MAX_DEVICE_RECORDS {
                return Err(permanent("too many local playtime state files"));
            }
            let bytes = read_bounded_json_file(&path, MAX_PLAYTIME_RECORD_BYTES, "playtime state")?;
            let value = serde_json::from_slice(&bytes).map_err(json_error)?;
            records.push((path, value));
        }
        Ok(records)
    }

    /// Read the current state published by each device for the requested Apps.
    fn read_app_records(
        &self,
        steam_id64: &str,
        only_app_id: Option<u32>,
    ) -> Result<Vec<SteamAppStateRecord>, BackendError> {
        let app_roots = match only_app_id {
            Some(app_id) => vec![(app_id, self.app_root(steam_id64, app_id)?)],
            None => self.account_app_roots(steam_id64)?,
        };
        let mut all_records = Vec::new();
        for (app_id, app_root) in app_roots {
            let directory = app_root.join(STATS_DIR);
            if !directory.exists() {
                continue;
            }
            let mut app_records = 0usize;
            for entry in std::fs::read_dir(directory).map_err(io_error)? {
                let entry = entry.map_err(io_error)?;
                if !entry.file_type().map_err(io_error)?.is_file() {
                    continue;
                }
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                if app_records >= MAX_DEVICE_RECORDS {
                    return Err(permanent("too many local Steam app state files"));
                }
                let bytes = read_stats_record_bytes(&path)?;
                let record =
                    serde_json::from_slice::<SteamAppStateRecord>(&bytes).map_err(json_error)?;
                validate_stats_record(&record, steam_id64, app_id, Some(&path))?;
                all_records.push(record);
                app_records += 1;
            }
        }
        Ok(all_records)
    }

    /// Converge achievement and stat state from records already read.
    ///
    /// Per key, last writer wins, ordered by `(observed_at, client_id, commit_id)`.
    /// `commit_id` is already a content digest, so it breaks ties without
    /// re-serializing and re-hashing the record on every pass.
    ///
    /// Commutative and idempotent by construction, which is the property a folder
    /// needs: it has no arbiter, so nothing computed here may be treated as a
    /// decision that a later arrival cannot revise.
    fn reduce_app_state(
        records: &[SteamAppStateRecord],
        only_app_id: Option<u32>,
    ) -> Result<(Vec<AchievementSyncState>, Vec<StatSyncState>), BackendError> {
        let mut achievements = BTreeMap::<(u32, String), AchievementSyncState>::new();
        let mut stats = BTreeMap::<(u32, String), (StatSyncState, MergeOrder)>::new();
        for record in records {
            let app_id = record.app_id;
            if only_app_id.is_some_and(|wanted| wanted != app_id) {
                continue;
            }
            let order = (
                record.observed_at,
                record.client_id,
                record.commit_id.clone(),
            );
            for achievement in &record.achievements {
                merge_achievement(
                    &mut achievements,
                    (app_id, achievement.key.clone()),
                    AchievementSyncState {
                        app_id,
                        achievement_key: achievement.key.clone(),
                        unlocked: achievement.unlocked,
                        progress_current: None,
                        progress_max: None,
                        observed_at: record.observed_at,
                        unlocked_at: achievement.unlocked_at,
                    },
                );
            }
            for stat in &record.stats {
                let state = StatSyncState {
                    app_id,
                    stat_key: stat.key.clone(),
                    value_type: stat.value_type.clone(),
                    value: stat.value.clone(),
                    observed_at: record.observed_at,
                };
                insert_latest(&mut stats, (app_id, state.stat_key.clone()), state, &order);
            }
        }
        Ok((
            achievements.into_values().collect(),
            stats.into_values().map(|(state, _)| state).collect(),
        ))
    }

    fn reduce_playtime(&self, steam_id64: &str) -> Result<Vec<PlaytimeEntry>, BackendError> {
        let mut observations = Vec::new();
        for (app_id, app_root) in self.account_app_roots(steam_id64)? {
            let records = self.read_playtime_records_with_paths(&app_root.join(PLAYTIME_DIR))?;
            for (path, record) in records {
                validate_playtime_record(&record, steam_id64, app_id, Some(&path))?;
                let tie = serde_json::to_vec(&record).map_err(json_error)?;
                observations.push((
                    (record.entry.observed_at, record.client_id, digest(&tie)),
                    record.entry,
                ));
            }
        }
        observations.sort_by(|left, right| left.0.cmp(&right.0));

        let mut states = BTreeMap::<u32, PlaytimeEntry>::new();
        for (_, mut incoming) in observations {
            incoming.owner_scope = self.scope.clone();
            incoming.owner_steam_id64 = steam_id64.to_owned();
            states
                .entry(incoming.app_id)
                .and_modify(|current| {
                    current.playtime_minutes =
                        current.playtime_minutes.max(incoming.playtime_minutes);
                    current.last_played_at =
                        max_option(current.last_played_at, incoming.last_played_at);
                    current.playtime_2weeks_minutes = incoming.playtime_2weeks_minutes;
                    current.observed_at = incoming.observed_at;
                })
                .or_insert(incoming);
        }
        Ok(states.into_values().collect())
    }

    /// Read the converged playtime state for one account on demand.
    pub fn pull_playtime(&self, steam_id64: &str) -> Result<Vec<PlaytimeEntry>, BackendError> {
        self.reduce_playtime(steam_id64)
    }
}

impl CloudBackend for LocalBackend {
    fn endpoint_scope(&self) -> String {
        self.scope.clone()
    }

    fn principal_scope(&self) -> Result<String, BackendError> {
        Ok(self.scope.clone())
    }

    fn credential_fingerprint(&self) -> String {
        self.scope.clone()
    }

    fn ensure_device_bound(&self, descriptor: &DeviceDescriptor) -> Result<(), BackendError> {
        if descriptor.client_id == 0 {
            Err(permanent("local cloud device ID is unavailable"))
        } else {
            Ok(())
        }
    }

    fn accepts_achievement_schemas(&self) -> bool {
        false
    }

    fn upload_achievement_schema(
        &self,
        _schema: &AchievementSchema,
    ) -> Result<SchemaUploadOutcome, BackendError> {
        Ok(SchemaUploadOutcome::Declined)
    }

    fn upload_playtime(
        &self,
        client_id: u64,
        steam_id64: &str,
        entries: &[PlaytimeEntry],
    ) -> Result<(), BackendError> {
        if entries.is_empty() {
            return Ok(());
        }
        if client_id == 0 {
            return Err(permanent("local playtime ClientID is unavailable"));
        }
        for entry in entries {
            if entry.app_id == 0
                || entry.observed_at <= 0
                || entry.last_played_at.is_some_and(|value| value < 0)
                || (!entry.owner_steam_id64.is_empty() && entry.owner_steam_id64 != steam_id64)
            {
                return Err(permanent("invalid local playtime observation"));
            }
        }
        for entry in entries {
            let incoming = PlaytimeRecord {
                steam_id64: steam_id64.to_owned(),
                client_id,
                entry: entry.clone(),
            };
            // Each device owns one cumulative playtime record per App.
            let path = self
                .app_root(steam_id64, entry.app_id)?
                .join(PLAYTIME_DIR)
                .join(format!("{client_id}.json"));
            let record = if path.exists() {
                let bytes =
                    read_bounded_json_file(&path, MAX_PLAYTIME_RECORD_BYTES, "playtime state")?;
                let existing =
                    serde_json::from_slice::<PlaytimeRecord>(&bytes).map_err(json_error)?;
                validate_playtime_record(&existing, steam_id64, entry.app_id, Some(&path))?;
                fold_playtime_records(existing, incoming)?
            } else {
                incoming
            };
            let bytes = serde_json::to_vec(&record).map_err(json_error)?;
            if bytes.len() as u64 > MAX_PLAYTIME_RECORD_BYTES {
                return Err(permanent("local playtime state file is too large"));
            }
            atomic_replace(&path, &bytes)?;
        }
        Ok(())
    }

    fn upload_steam_app_snapshot(
        &self,
        identity: &UploadIdentity,
        snapshot: &SteamAppSnapshot,
    ) -> Result<SteamStateUploadResult, BackendError> {
        if snapshot.commit_id.is_empty()
            || snapshot.app_id == 0
            || identity.client_id == 0
            || snapshot.owner_steam_id64 != identity.steam_id64
        {
            return Err(permanent("invalid local Steam app snapshot"));
        }
        let path = self
            .app_root(&identity.steam_id64, snapshot.app_id)?
            .join(STATS_DIR)
            .join(format!("{}.json", identity.client_id));
        let incoming = SteamAppStateRecord {
            steam_id64: identity.steam_id64.clone(),
            client_id: identity.client_id,
            app_id: snapshot.app_id,
            commit_id: snapshot.commit_id.clone(),
            observed_at: snapshot.observed_at,
            achievements: snapshot
                .achievements
                .iter()
                .map(|achievement| StoredAchievementState {
                    key: achievement.key.clone(),
                    unlocked: achievement.unlocked,
                    unlocked_at: achievement.unlocked_at,
                })
                .collect(),
            stats: snapshot
                .stats
                .iter()
                .map(|stat| StoredStatState {
                    key: stat.key.clone(),
                    value_type: stat.value_type.clone(),
                    value: stat.value.clone(),
                })
                .collect(),
        };
        validate_stats_record(
            &incoming,
            &identity.steam_id64,
            snapshot.app_id,
            Some(&path),
        )?;
        let record = if path.exists() {
            let existing =
                serde_json::from_slice::<SteamAppStateRecord>(&read_stats_record_bytes(&path)?)
                    .map_err(json_error)?;
            validate_stats_record(
                &existing,
                &identity.steam_id64,
                snapshot.app_id,
                Some(&path),
            )?;
            fold_device_records(existing, incoming)
        } else {
            incoming
        };
        let bytes = serde_json::to_vec(&record).map_err(json_error)?;
        if bytes.len() as u64 > MAX_STATS_RECORD_BYTES {
            return Err(permanent("local Steam app state file is too large"));
        }
        atomic_replace(&path, &bytes)?;
        Ok(SteamStateUploadResult {
            stats_apps: vec![AppStatsUploadResult {
                app_id: snapshot.app_id,
                status: AppStatsUploadStatus::Applied,
                crc_stats: None,
            }],
        })
    }

    fn pull_account_state(
        &self,
        _client_id: u64,
        steam_id64: &str,
    ) -> Result<AccountSyncState, BackendError> {
        // One read, one pass. Reducing achievements and stats separately parsed the
        // whole corpus twice for a single call.
        let (achievements, stats) =
            Self::reduce_app_state(&self.read_app_records(steam_id64, None)?, None)?;
        Ok(AccountSyncState {
            stats_crcs: Vec::new(),
            // Local state is read on Steam's native pull boundary, not published
            // through the revisioned remote event stream.
            playtime_revision: 0,
            achievements,
            stats,
            playtime: self.reduce_playtime(steam_id64)?,
        })
    }

    fn pull_app_stats(
        &self,
        _client_id: u64,
        steam_id64: &str,
        query: &AppStatsQuery,
    ) -> Result<AppStatsResult, BackendError> {
        let records = self.read_app_records(steam_id64, Some(query.app_id))?;
        if records.is_empty() {
            return Ok(AppStatsResult::Uninitialized);
        }
        let (mut achievements, mut stats) = Self::reduce_app_state(&records, Some(query.app_id))?;
        achievements.sort_by(|left, right| left.achievement_key.cmp(&right.achievement_key));
        stats.sort_by(|left, right| left.stat_key.cmp(&right.stat_key));
        // A folder has no arbiter, so it issues no stats token and never answers
        // Unchanged. The caller derives the token from the state it is about to
        // encode for the client, which is the only input the client can observe.
        // Hashing this reduced state instead would fold `observed_at` in, and then
        // re-observing identical state would look like a change.
        Ok(AppStatsResult::Modified {
            schema_version: query.schema_version.clone(),
            crc_stats: None,
            achievements,
            stats,
        })
    }
}

/// Converge one achievement across devices.
///
/// Unlocking is treated as one-way. A snapshot lists every achievement for the app,
/// so a device that has not seen an unlock reports it as locked, truthfully but
/// incompletely. Ordering those reports by time would let the device that knows
/// less overwrite the device that knows more, and the loser would then have its own
/// unlock erased when the converged state came back to it.
///
/// `ClearAchievement` is a development-time call that shipped games do not use to
/// reset a player, so there is no legitimate transition from unlocked back to
/// locked to preserve. Modelling one would cost the protection above and buy
/// nothing.
///
/// The time is the earliest known one, so a later re-observation of the same unlock
/// cannot push the date forward, and `observed_at` is the latest, so it still
/// reports when the state was last confirmed.
fn merge_achievement(
    states: &mut BTreeMap<(u32, String), AchievementSyncState>,
    key: (u32, String),
    incoming: AchievementSyncState,
) {
    match states.get_mut(&key) {
        Some(current) => {
            current.unlocked |= incoming.unlocked;
            current.observed_at = current.observed_at.max(incoming.observed_at);
            current.unlocked_at = match (current.unlocked_at, incoming.unlocked_at) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (some, None) | (None, some) => some,
            };
            if !current.unlocked {
                current.unlocked_at = None;
            }
        }
        None => {
            states.insert(key, incoming);
        }
    }
}

/// Merge order for one observed key: newest wins, then the higher device id, then
/// the commit digest, so two devices are never resolved by chance. `commit_id` is
/// already a content digest, so ordering costs no extra hashing.
type MergeOrder = (i64, u64, String);

fn insert_latest<K: Ord, V>(
    states: &mut BTreeMap<K, (V, MergeOrder)>,
    key: K,
    state: V,
    order: &MergeOrder,
) {
    if states.get(&key).is_none_or(|current| *order > current.1) {
        states.insert(key, (state, order.clone()));
    }
}

/// Fold a new complete observation into the state owned by one device.
fn fold_device_records(
    existing: SteamAppStateRecord,
    incoming: SteamAppStateRecord,
) -> SteamAppStateRecord {
    let mut achievements = BTreeMap::<String, StoredAchievementState>::new();
    let mut stats = BTreeMap::<String, (StoredStatState, (i64, String))>::new();
    for record in [&existing, &incoming] {
        let order = (record.observed_at, record.commit_id.clone());
        for achievement in &record.achievements {
            match achievements.get_mut(&achievement.key) {
                Some(current) => {
                    current.unlocked |= achievement.unlocked;
                    current.unlocked_at = match (current.unlocked_at, achievement.unlocked_at) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (some, None) | (None, some) => some,
                    };
                    if !current.unlocked {
                        current.unlocked_at = None;
                    }
                }
                None => {
                    achievements.insert(achievement.key.clone(), achievement.clone());
                }
            }
        }
        for stat in &record.stats {
            if stats.get(&stat.key).is_none_or(|current| order > current.1) {
                stats.insert(stat.key.clone(), (stat.clone(), order.clone()));
            }
        }
    }
    let latest = if (incoming.observed_at, &incoming.commit_id)
        >= (existing.observed_at, &existing.commit_id)
    {
        &incoming
    } else {
        &existing
    };
    let commit_id = latest.commit_id.clone();
    let observed_at = latest.observed_at;
    SteamAppStateRecord {
        steam_id64: incoming.steam_id64,
        client_id: incoming.client_id,
        app_id: incoming.app_id,
        commit_id,
        observed_at,
        achievements: achievements.into_values().collect(),
        stats: stats.into_values().map(|(state, _)| state).collect(),
    }
}

fn fold_playtime_records(
    existing: PlaytimeRecord,
    incoming: PlaytimeRecord,
) -> Result<PlaytimeRecord, BackendError> {
    let existing_tie = serde_json::to_vec(&existing).map_err(json_error)?;
    let incoming_tie = serde_json::to_vec(&incoming).map_err(json_error)?;
    let incoming_is_newer = (incoming.entry.observed_at, digest(&incoming_tie))
        >= (existing.entry.observed_at, digest(&existing_tie));
    let mut record = if incoming_is_newer {
        incoming.clone()
    } else {
        existing.clone()
    };
    record.entry.playtime_minutes = existing
        .entry
        .playtime_minutes
        .max(incoming.entry.playtime_minutes);
    record.entry.last_played_at =
        max_option(existing.entry.last_played_at, incoming.entry.last_played_at);
    Ok(record)
}

fn validate_playtime_record(
    record: &PlaytimeRecord,
    steam_id64: &str,
    app_id: u32,
    path: Option<&Path>,
) -> Result<(), BackendError> {
    if record.steam_id64 != steam_id64
        || record.client_id == 0
        || record.entry.app_id != app_id
        || record.entry.observed_at <= 0
        || record.entry.last_played_at.is_some_and(|value| value < 0)
        || (!record.entry.owner_steam_id64.is_empty()
            && record.entry.owner_steam_id64 != steam_id64)
        || path.is_some_and(|path| record_client_id(path).ok() != Some(record.client_id))
    {
        return Err(permanent("invalid local playtime observation"));
    }
    Ok(())
}

fn read_bounded_json_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, BackendError> {
    let metadata = std::fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(permanent(format!("invalid local {label} file")));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| permanent(format!("local {label} file is too large")))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| permanent(format!("local {label} file is too large")))?;
    std::fs::File::open(path)
        .map_err(io_error)?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > maximum {
        return Err(permanent(format!("invalid local {label} file")));
    }
    Ok(bytes)
}

fn read_stats_record_bytes(path: &Path) -> Result<Vec<u8>, BackendError> {
    read_bounded_json_file(path, MAX_STATS_RECORD_BYTES, "Steam app state")
}

fn validate_stats_record(
    record: &SteamAppStateRecord,
    steam_id64: &str,
    app_id: u32,
    path: Option<&Path>,
) -> Result<(), BackendError> {
    if record.steam_id64 != steam_id64
        || record.client_id == 0
        || record.app_id != app_id
        || record.commit_id.is_empty()
        || record.commit_id.len() > 255
        || record.commit_id.contains('\0')
        || record.observed_at <= 0
        || match record.achievements.len().checked_add(record.stats.len()) {
            Some(count) => count > MAX_STATS_ENTRIES,
            None => true,
        }
        || path.is_some_and(|path| record_client_id(path).ok() != Some(record.client_id))
    {
        return Err(permanent("invalid local Steam app state record"));
    }

    let mut achievement_keys = HashSet::with_capacity(record.achievements.len());
    for achievement in &record.achievements {
        let key = achievement.key.trim();
        if key.is_empty()
            || key.len() > 255
            || key.contains('\0')
            || !achievement_keys.insert(achievement.key.as_str())
            || achievement.unlocked_at.is_some_and(|value| {
                value <= 0 || value > i64::from(u32::MAX) || !achievement.unlocked
            })
        {
            return Err(permanent("invalid local Steam achievement state"));
        }
    }

    let mut stat_keys = HashSet::with_capacity(record.stats.len());
    for stat in &record.stats {
        let key = stat.key.trim();
        let valid_value = match stat.value_type.as_str() {
            "int" => stat.value.parse::<i32>().is_ok(),
            "float" | "average_rate" => stat.value.parse::<f32>().is_ok(),
            _ => false,
        };
        if key.is_empty()
            || key.len() > 255
            || key.contains('\0')
            || !stat_keys.insert(stat.key.as_str())
            || stat.value.len() > 255
            || stat.value.contains('\0')
            || !valid_value
        {
            return Err(permanent("invalid local Steam stat state"));
        }
    }
    Ok(())
}

fn validate_steam_id(value: &str) -> Result<(), BackendError> {
    if value.parse::<u64>().is_ok_and(|value| value != 0) {
        Ok(())
    } else {
        Err(permanent("invalid Steam account ID"))
    }
}

fn record_client_id(path: &Path) -> Result<u64, BackendError> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| permanent("invalid local ClientID record name"))
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
    use vapor_forge_cloud_core::{OfficialAchievementState, OfficialStatState};

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

    fn playtime_entry(steam_id64: &str, app_id: u32, minutes: u32) -> PlaytimeEntry {
        PlaytimeEntry {
            owner_scope: String::new(),
            owner_steam_id64: steam_id64.to_owned(),
            app_id,
            playtime_minutes: minutes,
            playtime_2weeks_minutes: 5,
            last_played_at: Some(1_800_000_000),
            observed_at: 1_800_000_001,
        }
    }

    fn json_files(directory: &std::path::Path) -> usize {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return 0;
        };
        let mut count = 0;
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                count += json_files(&path);
            } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
                count += 1;
            }
        }
        count
    }

    fn playtime_files(root: &std::path::Path, steam_id64: &str) -> usize {
        let account = root.join(steam_id64);
        let Ok(apps) = std::fs::read_dir(account) else {
            return 0;
        };
        apps.map(|app| json_files(&app.unwrap().path().join(PLAYTIME_DIR)))
            .sum()
    }

    #[test]
    fn schemas_are_not_persisted_by_the_local_backend() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let schema = AchievementSchema {
            owner_scope: String::new(),
            app_id: 480,
            language: "english".into(),
            schema_version: Some("sha".into()),
            content: b"schema".to_vec(),
        };

        assert_eq!(
            backend.upload_achievement_schema(&schema).unwrap(),
            SchemaUploadOutcome::Declined
        );
        assert!(!backend.accepts_achievement_schemas());
        assert!(!temporary.path().join("records").exists());
        assert!(!temporary.path().join("records/schemas").exists());
        assert!(!temporary.path().join("blobs/sha256").exists());
    }

    #[test]
    fn account_data_uses_the_account_app_layout() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let identity = identity();
        let app_id = 480;
        backend
            .upload_steam_app_snapshot(
                &identity,
                &SteamAppSnapshot {
                    owner_scope: String::new(),
                    owner_steam_id64: identity.steam_id64.clone(),
                    commit_id: "commit".into(),
                    app_id,
                    base_crc_stats: None,
                    dirty_stat_ids: Vec::new(),
                    achievements: Vec::new(),
                    stats: Vec::new(),
                    observed_at: 1_800_000_001,
                },
            )
            .unwrap();
        backend
            .upload_playtime(
                identity.client_id,
                &identity.steam_id64,
                &[playtime_entry(&identity.steam_id64, app_id, 120)],
            )
            .unwrap();
        let app_root = temporary
            .path()
            .join(&identity.steam_id64)
            .join(app_id.to_string());
        assert!(app_root
            .join(STATS_DIR)
            .join(format!("{}.json", identity.client_id))
            .is_file());
        assert!(app_root
            .join(PLAYTIME_DIR)
            .join(format!("{}.json", identity.client_id))
            .is_file());
        assert_eq!(json_files(&app_root.join(PLAYTIME_DIR)), 1);
        assert!(!app_root.join("playtime/totals").exists());
        assert!(!temporary.path().join("records").exists());
    }

    #[test]
    fn repeated_observations_of_one_app_reuse_a_single_object() {
        // The store used to address a record by the whole observation, so a
        // moving `observed_at` produced a new immutable file every sample even
        // when the playtime had not changed. One device saw 9,680 files for a
        // single app in two days.
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let steam_id64 = "76561198000000001";

        for observed_at in 0..8 {
            let mut entry = playtime_entry(steam_id64, 480, 120);
            entry.observed_at = 1_800_000_001 + observed_at;
            backend.upload_playtime(7, steam_id64, &[entry]).unwrap();
        }
        assert_eq!(playtime_files(temporary.path(), steam_id64), 1);

        // A second app and a second device each get their own object, so the
        // count is bounded by apps times devices rather than by observations.
        backend
            .upload_playtime(7, steam_id64, &[playtime_entry(steam_id64, 730, 5)])
            .unwrap();
        backend
            .upload_playtime(8, steam_id64, &[playtime_entry(steam_id64, 480, 90)])
            .unwrap();
        assert_eq!(playtime_files(temporary.path(), steam_id64), 3);
    }

    #[test]
    fn playtime_rejects_zero_client_without_writing() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let steam_id64 = "76561198000000001";

        assert!(backend
            .upload_playtime(0, steam_id64, &[playtime_entry(steam_id64, 480, 120)])
            .is_err());
        assert!(!temporary.path().join(steam_id64).exists());
    }

    #[test]
    fn playtime_rejects_oversized_device_records() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let steam_id64 = "76561198000000001";
        let directory = temporary
            .path()
            .join(steam_id64)
            .join("480")
            .join(PLAYTIME_DIR);
        std::fs::create_dir_all(&directory).unwrap();
        let file = std::fs::File::create(directory.join("7.json")).unwrap();
        file.set_len(MAX_PLAYTIME_RECORD_BYTES + 1).unwrap();

        assert!(backend.pull_playtime(steam_id64).is_err());
    }

    #[test]
    fn a_growing_total_overwrites_the_device_object_and_still_reduces_to_the_max() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let steam_id64 = "76561198000000001";

        for minutes in [120, 180, 240] {
            let mut entry = playtime_entry(steam_id64, 480, minutes);
            entry.observed_at = 1_800_000_000 + i64::from(minutes);
            backend.upload_playtime(7, steam_id64, &[entry]).unwrap();
        }

        assert_eq!(playtime_files(temporary.path(), steam_id64), 1);
        let reduced = backend.pull_playtime(steam_id64).unwrap();
        assert_eq!(reduced.len(), 1);
        assert_eq!(reduced[0].app_id, 480);
        assert_eq!(reduced[0].playtime_minutes, 240);
    }

    #[test]
    fn one_device_playtime_does_not_regress_on_delayed_observations() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let steam_id64 = "76561198000000001";

        let mut newer = playtime_entry(steam_id64, 480, 240);
        newer.playtime_2weeks_minutes = 30;
        newer.last_played_at = Some(300);
        newer.observed_at = 300;
        backend.upload_playtime(7, steam_id64, &[newer]).unwrap();

        let mut delayed = playtime_entry(steam_id64, 480, 120);
        delayed.playtime_2weeks_minutes = 10;
        delayed.last_played_at = Some(400);
        delayed.observed_at = 200;
        backend.upload_playtime(7, steam_id64, &[delayed]).unwrap();

        let mut latest = playtime_entry(steam_id64, 480, 180);
        latest.playtime_2weeks_minutes = 20;
        latest.last_played_at = Some(350);
        latest.observed_at = 500;
        backend.upload_playtime(7, steam_id64, &[latest]).unwrap();

        let reduced = backend.pull_playtime(steam_id64).unwrap();
        assert_eq!(reduced[0].playtime_minutes, 240);
        assert_eq!(reduced[0].playtime_2weeks_minutes, 20);
        assert_eq!(reduced[0].last_played_at, Some(400));
        assert_eq!(reduced[0].observed_at, 500);
    }

    #[test]
    fn local_playtime_is_pull_only() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let steam_id64 = "76561198000000001";
        backend
            .upload_playtime(7, steam_id64, &[playtime_entry(steam_id64, 480, 120)])
            .unwrap();

        assert_eq!(backend.pull_playtime(steam_id64).unwrap().len(), 1);
        assert_eq!(
            backend
                .stream_account_events(
                    7,
                    steam_id64,
                    &vapor_forge_cloud_core::StreamCancellation::new(),
                    &mut |_| unreachable!(),
                )
                .unwrap(),
            vapor_forge_cloud_core::StreamOutcome::Unsupported
        );
    }

    #[test]
    fn account_state_converges_device_records() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let identity = identity();
        backend
            .upload_steam_app_snapshot(
                &identity,
                &SteamAppSnapshot {
                    owner_scope: String::new(),
                    owner_steam_id64: identity.steam_id64.clone(),
                    commit_id: "commit-1".into(),
                    app_id: 480,
                    base_crc_stats: None,
                    dirty_stat_ids: Vec::new(),
                    achievements: vec![OfficialAchievementState {
                        key: "ACH_WIN".into(),
                        unlocked: true,
                        unlocked_at: Some(9),
                    }],
                    stats: vec![OfficialStatState {
                        key: "STAT_SCORE".into(),
                        value_type: "int".into(),
                        value: "1".into(),
                    }],
                    observed_at: 10,
                },
            )
            .unwrap();
        backend
            .upload_steam_app_snapshot(
                &identity,
                &SteamAppSnapshot {
                    owner_scope: String::new(),
                    owner_steam_id64: identity.steam_id64.clone(),
                    commit_id: "commit-2".into(),
                    app_id: 480,
                    base_crc_stats: None,
                    dirty_stat_ids: Vec::new(),
                    achievements: vec![OfficialAchievementState {
                        key: "ACH_WIN".into(),
                        unlocked: false,
                        unlocked_at: None,
                    }],
                    stats: vec![OfficialStatState {
                        key: "STAT_SCORE".into(),
                        value_type: "int".into(),
                        value: "3".into(),
                    }],
                    observed_at: 20,
                },
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
                    playtime_minutes: 40,
                    playtime_2weeks_minutes: 4,
                    last_played_at: Some(90),
                    observed_at: 20,
                }],
            )
            .unwrap();
        let state = backend.pull_account_state(7, &identity.steam_id64).unwrap();
        // Unlocking is one-way, so the later record reporting it as locked does not
        // win. It asserted the opposite before: a snapshot names every achievement,
        // so a device that has not seen an unlock reports it locked truthfully, and
        // letting that win destroys the unlock and then propagates the loss back.
        // The earliest known time survives with it.
        assert!(state.achievements[0].unlocked);
        assert_eq!(state.achievements[0].unlocked_at, Some(9));
        // Ordinary stats are genuinely not monotonic, so they still take the latest.
        assert_eq!(state.stats[0].stat_key, "STAT_SCORE");
        assert_eq!(state.stats[0].value, "3");
        assert_eq!(state.playtime[0].playtime_minutes, 40);
        assert_eq!(state.playtime[0].playtime_2weeks_minutes, 4);
        assert_eq!(state.playtime[0].last_played_at, Some(100));
    }

    #[test]
    fn a_folder_issues_no_stats_token_and_re_observation_does_not_change_the_state() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let identity = identity();
        let snapshot = |commit_id: &str, observed_at: i64| SteamAppSnapshot {
            owner_scope: String::new(),
            owner_steam_id64: identity.steam_id64.clone(),
            commit_id: commit_id.into(),
            app_id: 480,
            base_crc_stats: None,
            dirty_stat_ids: Vec::new(),
            achievements: vec![OfficialAchievementState {
                key: "ACH_WIN".into(),
                unlocked: true,
                unlocked_at: Some(9),
            }],
            stats: vec![OfficialStatState {
                key: "STAT_SCORE".into(),
                value_type: "int".into(),
                value: "1".into(),
            }],
            observed_at,
        };
        let query = |client_crc_stats| AppStatsQuery {
            app_id: 480,
            client_crc_stats,
            schema_version: "sha".into(),
        };

        assert_eq!(
            backend
                .pull_app_stats(7, &identity.steam_id64, &query(None))
                .unwrap(),
            AppStatsResult::Uninitialized
        );

        // Everything the Steam client can observe, and nothing else. `observed_at`
        // is deliberately excluded: it is this crate's merge ordering key, it moves
        // on every re-observation, and a token computed over it would report a
        // change the client cannot see.
        type ClientVisible = (Vec<(String, bool, Option<i64>)>, Vec<(String, String)>);
        fn client_visible(result: &AppStatsResult) -> (Option<u32>, ClientVisible) {
            match result {
                AppStatsResult::Modified {
                    crc_stats,
                    achievements,
                    stats,
                    ..
                } => (
                    *crc_stats,
                    (
                        achievements
                            .iter()
                            .map(|state| {
                                (
                                    state.achievement_key.clone(),
                                    state.unlocked,
                                    state.unlocked_at,
                                )
                            })
                            .collect(),
                        stats
                            .iter()
                            .map(|state| (state.stat_key.clone(), state.value.clone()))
                            .collect(),
                    ),
                ),
                other => panic!("expected Modified, got {other:?}"),
            }
        }

        backend
            .upload_steam_app_snapshot(&identity, &snapshot("commit-1", 10))
            .unwrap();
        let first = backend
            .pull_app_stats(7, &identity.steam_id64, &query(None))
            .unwrap();

        // The same state observed again, later. A folder cannot decide that nothing
        // changed, so it still answers Modified whatever token the client presents,
        // and it still issues none of its own.
        backend
            .upload_steam_app_snapshot(&identity, &snapshot("commit-2", 20))
            .unwrap();
        let second = backend
            .pull_app_stats(7, &identity.steam_id64, &query(Some(0x1234)))
            .unwrap();

        assert_eq!(client_visible(&first), client_visible(&second));
        assert_eq!(
            client_visible(&second),
            (
                None,
                (
                    vec![("ACH_WIN".to_owned(), true, Some(9))],
                    vec![("STAT_SCORE".to_owned(), "1".to_owned())],
                )
            )
        );
    }

    #[test]
    fn two_devices_unlocking_different_achievements_do_not_erase_each_other() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let identity = identity();
        let steam_id64 = identity.steam_id64.clone();
        // Each device reports the whole app, so it names the achievement it has not
        // seen as locked. That report is truthful and incomplete at the same time.
        let publish = |client_id: u64, observed_at: i64, first: bool, second: bool| {
            let mut with_device = identity.clone();
            with_device.client_id = client_id;
            let ach = |key: &str, unlocked: bool, at: i64| OfficialAchievementState {
                key: key.into(),
                unlocked,
                unlocked_at: unlocked.then_some(at),
            };
            backend
                .upload_steam_app_snapshot(
                    &with_device,
                    &SteamAppSnapshot {
                        owner_scope: String::new(),
                        owner_steam_id64: steam_id64.clone(),
                        commit_id: format!("commit-{client_id}"),
                        app_id: 480,
                        base_crc_stats: None,
                        dirty_stat_ids: Vec::new(),
                        achievements: vec![
                            ach("ACH_FIRST", first, 100),
                            ach("ACH_SECOND", second, 200),
                        ],
                        stats: Vec::new(),
                        observed_at,
                    },
                )
                .unwrap();
        };

        publish(7, 10, true, false);
        // Device 8 observes later and knows only about the second achievement.
        publish(8, 20, false, true);

        let state = backend.pull_account_state(7, &steam_id64).unwrap();
        let mut by_key = state
            .achievements
            .iter()
            .map(|a| (a.achievement_key.as_str(), (a.unlocked, a.unlocked_at)))
            .collect::<Vec<_>>();
        by_key.sort();
        assert_eq!(
            by_key,
            vec![
                ("ACH_FIRST", (true, Some(100))),
                ("ACH_SECOND", (true, Some(200))),
            ]
        );
    }

    #[test]
    fn a_re_observed_unlock_keeps_its_earliest_time() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let identity = identity();
        let steam_id64 = identity.steam_id64.clone();
        for (nth, unlocked_at) in [(0, 500), (1, 900)] {
            backend
                .upload_steam_app_snapshot(
                    &identity,
                    &SteamAppSnapshot {
                        owner_scope: String::new(),
                        owner_steam_id64: steam_id64.clone(),
                        commit_id: format!("commit-{nth}"),
                        app_id: 480,
                        base_crc_stats: None,
                        dirty_stat_ids: Vec::new(),
                        achievements: vec![OfficialAchievementState {
                            key: "ACH_WIN".into(),
                            unlocked: true,
                            unlocked_at: Some(unlocked_at),
                        }],
                        stats: Vec::new(),
                        observed_at: 1_000 + nth,
                    },
                )
                .unwrap();
        }

        let state = backend.pull_account_state(7, &steam_id64).unwrap();
        assert_eq!(state.achievements[0].unlocked_at, Some(500));
        // observed_at still tracks the most recent confirmation.
        assert_eq!(state.achievements[0].observed_at, 1_001);
    }

    #[test]
    fn device_stats_reuse_one_rolling_state_file() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let identity = identity();
        let steam_id64 = identity.steam_id64.clone();
        let publish = |client_id: u64, nth: i64, score: i64| {
            let mut with_device = identity.clone();
            with_device.client_id = client_id;
            backend
                .upload_steam_app_snapshot(
                    &with_device,
                    &SteamAppSnapshot {
                        owner_scope: String::new(),
                        owner_steam_id64: steam_id64.clone(),
                        commit_id: format!("commit-{client_id}-{nth}"),
                        app_id: 480,
                        base_crc_stats: None,
                        dirty_stat_ids: Vec::new(),
                        achievements: vec![OfficialAchievementState {
                            key: "ACH_WIN".into(),
                            unlocked: nth == 0,
                            unlocked_at: (nth == 0).then_some(9),
                        }],
                        stats: vec![OfficialStatState {
                            key: "STAT_SCORE".into(),
                            value_type: "int".into(),
                            value: score.to_string(),
                        }],
                        observed_at: 1_800_000_000 + nth,
                    },
                )
                .unwrap();
        };
        let latest_score = || {
            let state = backend.pull_account_state(7, &steam_id64).unwrap();
            assert_eq!(state.achievements.len(), 1);
            assert!(state.achievements[0].unlocked);
            assert_eq!(state.stats.len(), 1);
            state.stats[0].value.clone()
        };
        let stats_root = temporary
            .path()
            .join(&steam_id64)
            .join("480")
            .join(STATS_DIR);

        for nth in 0..32 {
            publish(7, nth, nth);
        }
        assert_eq!(json_files(&stats_root), 1);
        assert_eq!(latest_score(), "31");

        // A delayed observation from the same device cannot replace newer Stats,
        // while its earlier achievement unlock remains part of the rolling state.
        publish(7, 5, 9_999);
        assert_eq!(json_files(&stats_root), 1);
        assert_eq!(latest_score(), "31");

        // Every device owns one path. Reads merge those current states without
        // either device rewriting the other's file.
        publish(8, 40, 4_000);
        assert_eq!(json_files(&stats_root), 2);
        assert_eq!(latest_score(), "4000");

        let bytes = std::fs::read(stats_root.join("7.json")).unwrap();
        let value = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        assert!(value.get("snapshot").is_none());
        assert!(value.get("base_crc_stats").is_none());
        assert!(!stats_root.join("snapshots").exists());
        assert!(!stats_root.join("packs").exists());
    }

    #[test]
    fn stats_record_identity_and_shape_are_validated() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let identity = identity();
        backend
            .upload_steam_app_snapshot(
                &identity,
                &SteamAppSnapshot {
                    owner_scope: String::new(),
                    owner_steam_id64: identity.steam_id64.clone(),
                    commit_id: "commit".into(),
                    app_id: 480,
                    base_crc_stats: None,
                    dirty_stat_ids: Vec::new(),
                    achievements: Vec::new(),
                    stats: Vec::new(),
                    observed_at: 1_800_000_001,
                },
            )
            .unwrap();
        let path = temporary
            .path()
            .join(&identity.steam_id64)
            .join("480/stats/7.json");
        let mut value =
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap();
        value["unexpected"] = serde_json::Value::Bool(true);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(backend
            .pull_app_stats(
                identity.client_id,
                &identity.steam_id64,
                &AppStatsQuery {
                    app_id: 480,
                    client_crc_stats: None,
                    schema_version: "sha".into(),
                },
            )
            .is_err());

        value.as_object_mut().unwrap().remove("unexpected");
        value["client_id"] = serde_json::Value::from(8);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(backend.pull_account_state(7, &identity.steam_id64).is_err());
    }
}
