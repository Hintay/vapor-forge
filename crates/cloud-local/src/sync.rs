use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use vapor_forge_cloud_core::{
    AccountSyncState, AchievementSchema, AchievementSyncState, AppStatsQuery, AppStatsResult,
    AppStatsUploadResult, AppStatsUploadStatus, BackendError, CloudBackend, DeviceDescriptor,
    OfficialAchievementState, OfficialStatState, PlaytimeEntry, PlaytimeSession,
    SchemaUploadOutcome, StatSyncState, SteamAppSnapshot, SteamStateUploadResult, UploadIdentity,
};

use crate::store::{atomic_publish, atomic_replace};

const RECORD_VERSION: u32 = 1;

const APP_SNAPSHOT_DIR: &str = "steam-app-snapshots";
const APP_PACK_DIR: &str = "steam-app-packs";

/// Loose records this device may leave unpacked for one app before folding them.
///
/// Records are immutable and content addressed, so the directory would otherwise
/// grow by one file per observation forever and every read would parse all of
/// them. Packing trades that for one rewritten file per (device, app).
const APP_PACK_THRESHOLD: usize = 16;

pub struct LocalBackend {
    root: PathBuf,
    scope: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlaytimeRecord {
    version: u32,
    steam_id64: String,
    client_id: u64,
    entry: PlaytimeEntry,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlaytimeSessionRecord {
    version: u32,
    steam_id64: String,
    client_id: u64,
    session: PlaytimeSession,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SteamAppSnapshotRecord {
    version: u32,
    steam_id64: String,
    client_id: u64,
    snapshot: SteamAppSnapshot,
    /// Commit ids this record folded. Present only on a pack.
    ///
    /// Reclaimed one cycle late: a pack lists what it absorbed, and the run after
    /// that deletes those files. A new pack file and a batch of deletions are not
    /// guaranteed to reach a peer in that order, so the delay gives every peer a
    /// full scan interval to receive the pack that supersedes them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    covered: Vec<String>,
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

    fn read_records_with_paths<T: for<'de> Deserialize<'de>>(
        &self,
        directory: &Path,
    ) -> Result<Vec<(PathBuf, T)>, BackendError> {
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
                let value = serde_json::from_slice(&std::fs::read(&path).map_err(io_error)?)
                    .map_err(json_error)?;
                records.push((path, value));
            }
        }
        Ok(records)
    }

    fn read_records<T: for<'de> Deserialize<'de>>(
        &self,
        directory: &Path,
    ) -> Result<Vec<T>, BackendError> {
        Ok(self
            .read_records_with_paths(directory)?
            .into_iter()
            .map(|(_, value)| value)
            .collect())
    }

    /// Every app-state record for one account: the loose immutable observations
    /// plus each device's pack. A pack is the same record type, so it needs no
    /// separate parse or reduce path, and the merge is idempotent, so a pack
    /// coexisting with records it already folded changes nothing.
    fn read_app_records(
        &self,
        steam_id64: &str,
    ) -> Result<Vec<SteamAppSnapshotRecord>, BackendError> {
        let account_root = self.account_root(steam_id64)?;
        let mut records: Vec<SteamAppSnapshotRecord> =
            self.read_records(&account_root.join(APP_PACK_DIR))?;
        records.extend(
            self.read_records::<SteamAppSnapshotRecord>(&account_root.join(APP_SNAPSHOT_DIR))?,
        );
        for record in &records {
            if record.version != RECORD_VERSION || record.steam_id64 != steam_id64 {
                return Err(permanent("invalid local app state record"));
            }
            if record.snapshot.commit_id.is_empty()
                || record.snapshot.app_id == 0
                || record.snapshot.observed_at <= 0
            {
                return Err(permanent("invalid local Steam app snapshot"));
            }
        }
        Ok(records)
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
        records: &[SteamAppSnapshotRecord],
        only_app_id: Option<u32>,
    ) -> Result<(Vec<AchievementSyncState>, Vec<StatSyncState>), BackendError> {
        let mut achievements = BTreeMap::<(u32, String), AchievementSyncState>::new();
        let mut stats = BTreeMap::<(u32, String), (StatSyncState, MergeOrder)>::new();
        for record in records {
            let app_id = record.snapshot.app_id;
            if only_app_id.is_some_and(|wanted| wanted != app_id) {
                continue;
            }
            let order = (
                record.snapshot.observed_at,
                record.client_id,
                record.snapshot.commit_id.clone(),
            );
            for achievement in &record.snapshot.achievements {
                let key = achievement.key.trim();
                if key.is_empty()
                    || key.len() > 255
                    || key.contains('\0')
                    || achievement.unlocked_at.is_some_and(|value| value <= 0)
                {
                    return Err(permanent("invalid local Steam achievement snapshot"));
                }
                merge_achievement(
                    &mut achievements,
                    (app_id, achievement.key.clone()),
                    AchievementSyncState {
                        app_id,
                        achievement_key: achievement.key.clone(),
                        unlocked: achievement.unlocked,
                        progress_current: None,
                        progress_max: None,
                        observed_at: record.snapshot.observed_at,
                        unlocked_at: achievement.unlocked_at,
                    },
                );
            }
            for stat in &record.snapshot.stats {
                let key = stat.key.trim();
                if key.is_empty()
                    || key.len() > 255
                    || key.contains('\0')
                    || stat.value_type.trim().is_empty()
                    || stat.value_type.contains('\0')
                    || stat.value.len() > 255
                    || stat.value.contains('\0')
                {
                    return Err(permanent("invalid local Steam stat snapshot"));
                }
                let state = StatSyncState {
                    app_id,
                    stat_key: stat.key.clone(),
                    value_type: stat.value_type.clone(),
                    value: stat.value.clone(),
                    observed_at: record.snapshot.observed_at,
                };
                insert_latest(&mut stats, (app_id, state.stat_key.clone()), state, &order);
            }
        }
        Ok((
            achievements.into_values().collect(),
            stats.into_values().map(|(state, _)| state).collect(),
        ))
    }

    /// Fold this device's loose records for one app into a single pack, and reclaim
    /// the batch the previous pack already folded.
    ///
    /// Only this device's own records are ever folded or deleted. A folder gives no
    /// reader a complete view, because a peer may still hold records this process
    /// has never seen, so collapsing another device's state here would be a
    /// decision taken on partial input. Within one device's own namespace there is
    /// no such gap: it wrote every one of those files itself.
    ///
    /// Runs on the write path, where the file count actually grows and the caller
    /// is already doing IO, so reads stay free of side effects.
    fn pack_own_records(&self, steam_id64: &str, client_id: u64) -> Result<(), BackendError> {
        let account_root = self.account_root(steam_id64)?;
        let pack_root = account_root.join(APP_PACK_DIR);
        let packs: Vec<(PathBuf, SteamAppSnapshotRecord)> =
            self.read_records_with_paths(&pack_root)?;
        let loose: Vec<(PathBuf, SteamAppSnapshotRecord)> =
            self.read_records_with_paths(&account_root.join(APP_SNAPSHOT_DIR))?;

        let covered = packs
            .iter()
            .filter(|(_, pack)| pack.client_id == client_id)
            .flat_map(|(_, pack)| pack.covered.iter().cloned())
            .collect::<std::collections::HashSet<_>>();

        let mut mine = BTreeMap::<u32, Vec<&SteamAppSnapshotRecord>>::new();
        for (path, record) in &loose {
            if record.client_id != client_id {
                continue;
            }
            if covered.contains(&record.snapshot.commit_id) {
                // Superseded by the pack on disk, which has had a full cycle to
                // reach every peer.
                let _ = std::fs::remove_file(path);
                continue;
            }
            mine.entry(record.snapshot.app_id).or_default().push(record);
        }

        for (app_id, records) in mine {
            if records.len() < APP_PACK_THRESHOLD {
                continue;
            }
            let existing = packs
                .iter()
                .map(|(_, pack)| pack)
                .find(|pack| pack.client_id == client_id && pack.snapshot.app_id == app_id);
            let folded = records
                .iter()
                .map(|record| record.snapshot.commit_id.clone())
                .collect::<Vec<_>>();
            let record = SteamAppSnapshotRecord {
                version: RECORD_VERSION,
                steam_id64: steam_id64.to_owned(),
                client_id,
                snapshot: fold_own_snapshots(
                    steam_id64,
                    client_id,
                    app_id,
                    existing.into_iter().chain(records.iter().copied()),
                ),
                covered: folded,
            };
            let bytes = serde_json::to_vec(&record).map_err(json_error)?;
            atomic_replace(
                &pack_root
                    .join(client_id.to_string())
                    .join(format!("{app_id}.json")),
                &bytes,
            )?;
        }
        Ok(())
    }

    fn reduce_playtime(&self, steam_id64: &str) -> Result<Vec<PlaytimeEntry>, BackendError> {
        let account_root = self.account_root(steam_id64)?;
        let records: Vec<PlaytimeRecord> = self.read_records(&account_root.join("playtime"))?;
        let sessions: Vec<PlaytimeSessionRecord> =
            self.read_records(&account_root.join("playtime-sessions"))?;
        let mut observations = Vec::with_capacity(records.len() + sessions.len());
        for record in records {
            if record.version != RECORD_VERSION || record.steam_id64 != steam_id64 {
                return Err(permanent("invalid local playtime record"));
            }
            if record.entry.app_id == 0
                || record.entry.observed_at <= 0
                || record.entry.last_played_at.is_some_and(|value| value < 0)
                || (!record.entry.owner_steam_id64.is_empty()
                    && record.entry.owner_steam_id64 != steam_id64)
            {
                return Err(permanent("invalid local playtime observation"));
            }
            let tie = serde_json::to_vec(&record).map_err(json_error)?;
            observations.push((
                (record.entry.observed_at, record.client_id, digest(&tie)),
                record.entry,
            ));
        }
        // Validated but not converged: `seconds` duplicates the snapshot
        // total, and `started_at + seconds` is not the session end.
        // See docs/developer/steam-playtime-source-analysis.md.
        for record in sessions {
            if record.version != RECORD_VERSION || record.steam_id64 != steam_id64 {
                return Err(permanent("invalid local playtime session record"));
            }
            if record.session.session_id.is_empty()
                || record.session.session_id.contains('\0')
                || record.session.app_id == 0
                || record.session.started_at == 0
                || record.session.seconds == 0
                || record.session.observed_at <= 0
                || (!record.session.owner_steam_id64.is_empty()
                    && record.session.owner_steam_id64 != steam_id64)
            {
                return Err(permanent("invalid local playtime session"));
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
            // One object per account, device and app, rewritten in place.
            // A record is a running total, so keeping the history buys nothing:
            // `reduce_playtime` takes the max of the monotonic fields and the
            // newest observation for the rest, and a device's latest record
            // already carries both. Addressing the object by the observation
            // instead made every sample a new immutable file, because
            // `observed_at` moves each time even when the playtime does not.
            // The device id is in the path, so each file has a single writer and
            // rewriting it cannot collide with another device.
            let id = digest(format!("{steam_id64}/{client_id}/{}", entry.app_id).as_bytes());
            let path = directory.join(&id[..2]).join(format!("{id}.json"));
            let bytes = serde_json::to_vec(&record).map_err(json_error)?;
            atomic_replace(&path, &bytes)?;
        }
        Ok(())
    }

    fn upload_playtime_sessions(
        &self,
        client_id: u64,
        steam_id64: &str,
        sessions: &[PlaytimeSession],
    ) -> Result<(), BackendError> {
        let directory = self.account_root(steam_id64)?.join("playtime-sessions");
        for session in sessions {
            if session.session_id.is_empty()
                || session.session_id.contains('\0')
                || session.app_id == 0
                || session.started_at == 0
                || session.seconds == 0
                || session.observed_at <= 0
                || (!session.owner_steam_id64.is_empty() && session.owner_steam_id64 != steam_id64)
            {
                return Err(permanent("invalid local playtime session"));
            }
            let record = PlaytimeSessionRecord {
                version: RECORD_VERSION,
                steam_id64: steam_id64.to_owned(),
                client_id,
                session: session.clone(),
            };
            self.publish_record(&directory, session.session_id.as_bytes(), &record)?;
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
            || snapshot.owner_steam_id64 != identity.steam_id64
        {
            return Err(permanent("invalid local Steam app snapshot"));
        }
        let record = SteamAppSnapshotRecord {
            version: RECORD_VERSION,
            steam_id64: identity.steam_id64.clone(),
            client_id: identity.client_id,
            snapshot: snapshot.clone(),
            covered: Vec::new(),
        };
        self.publish_record(
            &self
                .account_root(&identity.steam_id64)?
                .join(APP_SNAPSHOT_DIR),
            snapshot.commit_id.as_bytes(),
            &record,
        )?;
        self.pack_own_records(&identity.steam_id64, identity.client_id)?;
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
            Self::reduce_app_state(&self.read_app_records(steam_id64)?, None)?;
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
        // One read, filtered during the reduce. This used to parse the whole corpus
        // three times and only then retain a single app.
        let records = self.read_app_records(steam_id64)?;
        if !records
            .iter()
            .any(|record| record.snapshot.app_id == query.app_id)
        {
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
    if states.get(&key).map_or(true, |current| *order > current.1) {
        states.insert(key, (state, order.clone()));
    }
}

/// Merge several of one device's snapshots for one app into a single snapshot,
/// applying the same per-key order the read path uses. `client_id` is constant
/// across the inputs, so it drops out of the comparison.
fn fold_own_snapshots<'a>(
    steam_id64: &str,
    client_id: u64,
    app_id: u32,
    records: impl Iterator<Item = &'a SteamAppSnapshotRecord>,
) -> SteamAppSnapshot {
    let mut achievements = BTreeMap::<String, (OfficialAchievementState, (i64, String))>::new();
    let mut stats = BTreeMap::<String, (OfficialStatState, (i64, String))>::new();
    let mut observed_at = 0_i64;
    for record in records {
        let order = (
            record.snapshot.observed_at,
            record.snapshot.commit_id.clone(),
        );
        observed_at = observed_at.max(record.snapshot.observed_at);
        for achievement in &record.snapshot.achievements {
            match achievements.get_mut(&achievement.key) {
                Some((current, current_order)) => {
                    current.unlocked |= achievement.unlocked;
                    current.unlocked_at = match (current.unlocked_at, achievement.unlocked_at) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (some, None) | (None, some) => some,
                    };
                    if !current.unlocked {
                        current.unlocked_at = None;
                    }
                    *current_order = current_order.clone().max(order.clone());
                }
                None => {
                    achievements.insert(
                        achievement.key.clone(),
                        (achievement.clone(), order.clone()),
                    );
                }
            }
        }
        for stat in &record.snapshot.stats {
            if stats
                .get(&stat.key)
                .map_or(true, |current| order > current.1)
            {
                stats.insert(stat.key.clone(), (stat.clone(), order.clone()));
            }
        }
    }
    SteamAppSnapshot {
        owner_scope: String::new(),
        owner_steam_id64: steam_id64.to_owned(),
        // Stable across rewrites for one (account, device, app), so the pack keeps
        // one identity as it is replaced.
        commit_id: digest(format!("pack/{steam_id64}/{client_id}/{app_id}").as_bytes()),
        app_id,
        // A pack is converged state, not a commit against a baseline. Neither field
        // is read back anywhere in this crate.
        base_crc_stats: None,
        dirty_stat_ids: Vec::new(),
        achievements: achievements.into_values().map(|(state, _)| state).collect(),
        stats: stats.into_values().map(|(state, _)| state).collect(),
        observed_at,
    }
}

fn validate_steam_id(value: &str) -> Result<(), BackendError> {
    if value.parse::<u64>().is_ok_and(|value| value != 0) {
        Ok(())
    } else {
        Err(permanent("invalid Steam account ID"))
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

    fn record_files(root: &std::path::Path, steam_id64: &str, directory: &str) -> usize {
        let directory = root
            .join("records/accounts")
            .join(steam_id64)
            .join(directory);
        let Ok(shards) = std::fs::read_dir(&directory) else {
            return 0;
        };
        let mut count = 0;
        for shard in shards {
            for entry in std::fs::read_dir(shard.unwrap().path()).unwrap() {
                if entry.unwrap().path().extension().and_then(|e| e.to_str()) == Some("json") {
                    count += 1;
                }
            }
        }
        count
    }

    fn playtime_files(root: &std::path::Path, steam_id64: &str) -> usize {
        record_files(root, steam_id64, "playtime")
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
                .stream_playtime(
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
    fn account_state_converges_immutable_records() {
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
            .upload_playtime_sessions(
                7,
                &identity.steam_id64,
                &[PlaytimeSession {
                    owner_scope: String::new(),
                    owner_steam_id64: identity.steam_id64.clone(),
                    session_id: "covered-by-later-snapshot".into(),
                    app_id: 480,
                    started_at: 101,
                    seconds: 120,
                    offline: true,
                    owner_account_id: 39734273,
                    observed_at: 12,
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
        backend
            .upload_playtime_sessions(
                8,
                &identity.steam_id64,
                &[PlaytimeSession {
                    owner_scope: String::new(),
                    owner_steam_id64: identity.steam_id64.clone(),
                    session_id: "after-latest-snapshot".into(),
                    app_id: 480,
                    started_at: 200,
                    seconds: 180,
                    offline: false,
                    owner_account_id: 39734273,
                    observed_at: 21,
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
        // Sessions do not contribute.
        assert_eq!(state.playtime[0].playtime_minutes, 40);
        assert_eq!(state.playtime[0].playtime_2weeks_minutes, 4);
        // Not 380 (`started_at + seconds`).
        assert_eq!(state.playtime[0].last_played_at, Some(100));
    }

    #[test]
    fn a_session_alone_never_synthesizes_playtime() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let steam_id64 = "76561198000000001";
        backend
            .upload_playtime_sessions(
                7,
                steam_id64,
                &[PlaytimeSession {
                    owner_scope: String::new(),
                    owner_steam_id64: steam_id64.to_owned(),
                    session_id: "lonely".into(),
                    app_id: 480,
                    started_at: 1_800_000_000,
                    seconds: 3600,
                    offline: false,
                    owner_account_id: 39734273,
                    observed_at: 1_800_003_600,
                }],
            )
            .unwrap();

        // A 0-minute entry would overwrite Steam's own value.
        let state = backend.pull_account_state(7, steam_id64).unwrap();
        assert!(state.playtime.is_empty());
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
    fn own_records_are_packed_and_reclaimed_one_cycle_later() {
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
        let loose = || record_files(temporary.path(), &steam_id64, APP_SNAPSHOT_DIR);
        let packs = || record_files(temporary.path(), &steam_id64, APP_PACK_DIR);

        // Below the threshold nothing is folded.
        for nth in 0..(APP_PACK_THRESHOLD as i64 - 1) {
            publish(7, nth, nth);
        }
        assert_eq!(packs(), 0);
        assert_eq!(loose(), APP_PACK_THRESHOLD - 1);

        // Reaching it writes one pack and leaves the batch in place: deletion waits
        // a cycle so a peer cannot see the inputs vanish before the pack arrives.
        let threshold = APP_PACK_THRESHOLD as i64 - 1;
        publish(7, threshold, threshold);
        assert_eq!(packs(), 1);
        assert_eq!(loose(), APP_PACK_THRESHOLD);
        assert_eq!(latest_score(), threshold.to_string());

        // The next write reclaims what that pack folded. The pack carries the state
        // forward, so the answer does not change.
        publish(7, threshold + 1, threshold + 1);
        assert_eq!(packs(), 1);
        assert_eq!(loose(), 1);
        assert_eq!(latest_score(), (threshold + 1).to_string());

        // Another device's records are never folded or deleted, because this process
        // cannot know what that device still holds unsent.
        publish(8, 0, 4_000);
        assert_eq!(loose(), 2);
        assert_eq!(packs(), 1);
        // 4000 was observed at 1_800_000_000, older than device 7's latest, so the
        // per-key merge keeps device 7's value and the pack did not swallow a vote.
        assert_eq!(latest_score(), (threshold + 1).to_string());
    }

    #[test]
    fn an_invalid_session_still_fails_the_read() {
        let temporary = tempfile::tempdir().unwrap();
        let backend = LocalBackend::open(temporary.path()).unwrap();
        let steam_id64 = "76561198000000001";

        assert!(backend
            .upload_playtime_sessions(
                7,
                steam_id64,
                &[PlaytimeSession {
                    owner_scope: String::new(),
                    owner_steam_id64: steam_id64.to_owned(),
                    session_id: String::new(),
                    app_id: 480,
                    started_at: 1_800_000_000,
                    seconds: 3600,
                    offline: false,
                    owner_account_id: 39734273,
                    observed_at: 1_800_003_600,
                }],
            )
            .is_err());
    }
}
