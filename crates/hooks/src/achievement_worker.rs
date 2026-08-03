#![forbid(unsafe_code)]

use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

use prost::Message;
use tracing::{info, warn};
use vapor_forge_cloud_core::{
    AchievementSchema, AppStatsUploadResult, AppStatsUploadStatus, CloudBackend,
    OfficialAchievementState, OfficialStatState, SchemaUploadOutcome, StatsCommit,
    SteamAppSnapshot, SteamStateUploadResult, UploadIdentity,
};
use vapor_forge_core::unix_now;
use vapor_forge_steam_protocol::{
    ClientStoreUserStats2Request, ACHIEVEMENT_UNLOCK_TIME_UNKNOWN, EMSG_STORE_USERSTATS2,
};
use vapor_forge_sync_journal::SyncJournal;

#[derive(Clone)]
struct AchievementWorker {
    journal: Arc<SyncJournal>,
    wake: mpsc::SyncSender<()>,
}

static WORKER: OnceLock<AchievementWorker> = OnceLock::new();
static WORKER_INIT: Mutex<()> = Mutex::new(());
const READY_RETRY_DELAY: Duration = Duration::from_secs(2);

pub fn ensure_started() {
    let _ = worker();
}

pub(crate) fn notify_context_changed() {
    if let Some(worker) = WORKER.get() {
        worker.wake();
    }
}

pub(crate) fn stats_awaiting_snapshot() -> Vec<u32> {
    let Some(worker) = worker() else {
        return Vec::new();
    };
    let Some((backend, identity)) = upload_context() else {
        return Vec::new();
    };
    let Ok(scope) = crate::sync_journal::principal_scope(backend.as_ref()) else {
        return Vec::new();
    };
    worker
        .journal
        .stats_awaiting_snapshot(&scope, &identity.steam_id64, unix_now())
        .unwrap_or_default()
}

pub(crate) fn persist_store_commit(app_id: u32, emsg: u32, request: &[u8]) -> bool {
    let Some(worker) = worker() else {
        return false;
    };
    let Some((backend, identity)) = upload_context() else {
        return false;
    };
    let Some(owner_scope) = crate::sync_journal::cached_principal_scope(backend.as_ref()) else {
        return false;
    };
    let (base_crc_stats, mut dirty_stat_ids) = if emsg == EMSG_STORE_USERSTATS2 {
        match ClientStoreUserStats2Request::decode(request) {
            Ok(request) => (
                request.crc_stats,
                request
                    .stats
                    .into_iter()
                    .filter_map(|stat| stat.stat_id)
                    .collect(),
            ),
            Err(_) => return false,
        }
    } else {
        (None, Vec::new())
    };
    dirty_stat_ids.sort_unstable();
    dirty_stat_ids.dedup();
    let commit = StatsCommit {
        owner_scope,
        owner_steam_id64: identity.steam_id64.clone(),
        commit_id: vapor_forge_cloud_core::stats_commit_id(&identity.steam_id64, app_id, request),
        app_id,
        base_crc_stats,
        dirty_stat_ids,
        observed_at: unix_now(),
    };
    let persisted = worker.journal.enqueue_stats_commit(&commit).is_ok();
    if persisted {
        worker.wake();
    }
    persisted
}

/// The authoritative unlock time for one achievement, or `None`.
///
/// A locked achievement never has one. `ClearAchievement` clears the data bit but
/// leaves Steam's per-bit time in place, so a time read back alongside
/// `unlocked == false` is stale and must not travel with the state.
fn unlocked_at(unlocked: bool, unlock_time: u32) -> Option<i64> {
    if !unlocked || unlock_time == 0 || unlock_time == ACHIEVEMENT_UNLOCK_TIME_UNKNOWN {
        return None;
    }
    Some(i64::from(unlock_time))
}

pub(crate) fn queue_official_snapshot(
    snapshot: crate::client::user_stats::AchievementSnapshot,
) -> bool {
    // Asked here as well as at the trigger, because this is the last point before
    // the state becomes durable and every trigger drains through it. A genuinely
    // owned game's achievements are Steam's own to sync and must not be uploaded.
    if !crate::client::install::config()
        .is_controlled_app(vapor_forge_config::AppId(snapshot.app_id))
    {
        return true;
    }
    let Some(worker) = worker() else {
        return false;
    };
    let Some((backend, identity)) = upload_context() else {
        return false;
    };
    let Ok(scope) = crate::sync_journal::principal_scope(backend.as_ref()) else {
        return false;
    };
    let commit =
        match worker
            .journal
            .pending_stats_commit(&scope, &identity.steam_id64, snapshot.app_id)
        {
            Ok(Some(commit)) => commit,
            Ok(None) => return true,
            Err(_) => return false,
        };
    let official = SteamAppSnapshot {
        owner_scope: scope,
        owner_steam_id64: identity.steam_id64,
        commit_id: commit.commit_id,
        app_id: snapshot.app_id,
        base_crc_stats: commit.base_crc_stats,
        dirty_stat_ids: commit.dirty_stat_ids,
        achievements: snapshot
            .achievements
            .into_iter()
            .map(|achievement| OfficialAchievementState {
                unlocked_at: unlocked_at(achievement.unlocked, achievement.unlock_time),
                key: achievement.key,
                unlocked: achievement.unlocked,
            })
            .collect(),
        stats: snapshot
            .stats
            .into_iter()
            .map(|stat| OfficialStatState {
                key: stat.key,
                value_type: stat.value_type,
                value: stat.value,
            })
            .collect(),
        observed_at: unix_now(),
    };
    let persisted = worker
        .journal
        .complete_stats_snapshot(&official)
        .unwrap_or(false);
    if persisted {
        worker.wake();
    }
    persisted
}

pub(crate) fn has_pending_stats(owner_scope: &str, steam_id64: &str, app_id: u32) -> bool {
    worker().is_some_and(|worker| {
        worker
            .journal
            .stats_sync_pending(owner_scope, steam_id64, app_id)
            .unwrap_or(true)
    })
}

pub fn queue_schema(app_id: u32, schema_version: Option<String>, content: Vec<u8>) {
    if content.is_empty() {
        return;
    }
    let backend = crate::cloud_backend::backend_context();
    if backend
        .as_ref()
        .is_some_and(|backend| !backend.accepts_achievement_schemas())
    {
        return;
    }
    let Some(worker) = worker() else {
        return;
    };
    let schema = AchievementSchema {
        owner_scope: backend
            .as_ref()
            .map(|backend| backend.endpoint_scope())
            .unwrap_or_default(),
        app_id,
        language: "english".into(),
        schema_version,
        content,
    };
    persist_pending_schema(worker, &schema);
}

impl AchievementWorker {
    fn wake(&self) {
        let _ = self.wake.try_send(());
    }
}

fn worker() -> Option<&'static AchievementWorker> {
    if let Some(worker) = WORKER.get() {
        return Some(worker);
    }
    let _init = WORKER_INIT.lock().ok()?;
    if let Some(worker) = WORKER.get() {
        return Some(worker);
    }
    let journal = crate::sync_journal::shared()?;
    let (wake, receiver) = mpsc::sync_channel(1);
    let worker_journal = Arc::clone(&journal);
    if std::thread::Builder::new()
        .name("achievement-upload".into())
        .spawn(move || upload_loop(worker_journal, receiver))
        .is_err()
    {
        warn!("achievement-sync: failed to start upload worker");
        return None;
    }
    info!("achievement-sync: durable journal ready");
    let _ = WORKER.set(AchievementWorker { journal, wake });
    WORKER.get()
}

fn persist_pending_schema(worker: &AchievementWorker, schema: &AchievementSchema) {
    if let Err(error) = worker.journal.enqueue_schema(schema, unix_now()) {
        warn!(%error, app_id = schema.app_id, "achievement-sync: failed to persist pending schema");
    } else {
        worker.wake();
    }
}

fn upload_loop(journal: Arc<SyncJournal>, wake: mpsc::Receiver<()>) {
    let mut first_pass = true;
    let mut next_attempt_at = None;
    loop {
        if !first_pass && !wait_for_upload_work(&wake, next_attempt_at) {
            break;
        }
        first_pass = false;
        persist_current_device_descriptor(&journal);
        for _ in 0..10 {
            let Some(backend) = crate::cloud_backend::backend_context() else {
                break;
            };
            let Some(descriptor) = vapor_forge_cloud_core::device_descriptor() else {
                break;
            };
            if let Err(error) = backend.ensure_device_bound(&descriptor) {
                warn!(%error, "achievement-sync: device binding deferred");
                break;
            }
            let scope = backend.endpoint_scope();
            let mut attempted = false;
            if let Err(error) = journal.attribute_pending_schemas(&scope) {
                warn!(%error, "achievement-sync: failed to attribute schema uploads");
                break;
            }

            let schemas = match journal.pending_schemas(unix_now(), &scope) {
                Ok(schemas) => schemas,
                Err(error) => {
                    warn!(%error, "achievement-sync: failed to read schema journal");
                    break;
                }
            };
            for queued in &schemas {
                let schema = &queued.value;
                attempted = true;
                match backend.upload_achievement_schema(schema) {
                    Ok(SchemaUploadOutcome::Accepted | SchemaUploadOutcome::Declined) => {
                        if let Err(error) = journal.acknowledge(queued) {
                            warn!(%error, app_id = schema.app_id, "achievement-sync: failed to acknowledge schema upload");
                        }
                    }
                    Err(error) if error.is_retryable() => {
                        warn!(%error, app_id = schema.app_id, "achievement-sync: schema upload deferred");
                        if let Err(mark_error) = journal.defer(queued, unix_now()) {
                            warn!(%mark_error, "achievement-sync: failed to schedule schema retry");
                        }
                    }
                    Err(error) => {
                        warn!(%error, app_id = schema.app_id, "achievement-sync: server permanently rejected schema");
                        if let Err(mark_error) = journal.acknowledge(queued) {
                            warn!(%mark_error, "achievement-sync: failed to discard rejected schema");
                        }
                    }
                }
            }

            let Some(identity) = upload_identity() else {
                if !attempted {
                    break;
                }
                continue;
            };
            let stats_scope = match crate::sync_journal::principal_scope(backend.as_ref()) {
                Ok(scope) => scope,
                Err(error) => {
                    warn!(%error, "achievement-sync: principal scope unavailable");
                    break;
                }
            };
            let snapshots = match journal.pending_stats_snapshots(
                &stats_scope,
                &identity.steam_id64,
                unix_now(),
            ) {
                Ok(snapshots) => snapshots,
                Err(error) => {
                    warn!(%error, "achievement-sync: failed to read official snapshots");
                    break;
                }
            };
            for queued in &snapshots {
                let snapshot = &queued.value;
                attempted = true;
                match backend.upload_steam_app_snapshot(&identity, snapshot) {
                    // A stats_out_of_date verdict means the backend did not
                    // store this snapshot as given. Settling it here would drop
                    // state Steam already considers committed, so the commit is
                    // kept and rebuilt from the refreshed cache instead.
                    Ok(result) => match refused_app_result(snapshot, &result) {
                        Some(refused) => {
                            match journal.reopen_stats_commit(queued, refused.crc_stats, unix_now())
                            {
                                Ok(true) => queue_native_refresh_after_upload(snapshot),
                                Ok(false) => {}
                                Err(error) => {
                                    warn!(%error, app_id = snapshot.app_id, "achievement-sync: failed to reopen refused snapshot");
                                }
                            }
                        }
                        None => {
                            if let Err(error) = journal.acknowledge(queued) {
                                warn!(%error, app_id = snapshot.app_id, "achievement-sync: failed to acknowledge official snapshot");
                            }
                        }
                    },
                    Err(error) if error.is_retryable() => {
                        warn!(%error, app_id = snapshot.app_id, "achievement-sync: official snapshot deferred");
                        if let Err(mark_error) = journal.defer(queued, unix_now()) {
                            warn!(%mark_error, "achievement-sync: failed to schedule snapshot retry");
                        }
                        break;
                    }
                    Err(error) => {
                        warn!(%error, app_id = snapshot.app_id, "achievement-sync: official snapshot rejected");
                        if let Err(mark_error) = journal.acknowledge(queued) {
                            warn!(%mark_error, "achievement-sync: failed to discard rejected snapshot");
                        }
                    }
                }
            }
            if !attempted {
                break;
            }
        }
        next_attempt_at = next_achievement_attempt_at(&journal);
    }
}

fn wait_for_upload_work(wake: &mpsc::Receiver<()>, next_attempt_at: Option<i64>) -> bool {
    let Some(next_attempt_at) = next_attempt_at else {
        return wake.recv().is_ok();
    };
    let now = unix_now();
    let delay = if next_attempt_at <= now {
        READY_RETRY_DELAY
    } else {
        Duration::from_secs(next_attempt_at.saturating_sub(now) as u64)
    };
    !matches!(
        wake.recv_timeout(delay),
        Err(mpsc::RecvTimeoutError::Disconnected)
    )
}

fn next_achievement_attempt_at(journal: &SyncJournal) -> Option<i64> {
    let backend = crate::cloud_backend::backend_context()?;
    vapor_forge_cloud_core::device_descriptor()?;
    let endpoint_scope = backend.endpoint_scope();
    let schema = match (
        journal.next_schema_attempt_at(&endpoint_scope),
        journal.next_schema_attempt_at(""),
    ) {
        (Ok(scoped), Ok(orphaned)) => match (scoped, orphaned) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (some, None) | (None, some) => some,
        },
        (Err(error), _) | (_, Err(error)) => {
            warn!(%error, "achievement-sync: failed to schedule schema journal");
            None
        }
    };
    let Some(identity) = upload_identity() else {
        return schema;
    };
    let stats = match crate::sync_journal::principal_scope(backend.as_ref()) {
        Ok(scope) => match journal.next_stats_snapshot_attempt_at(&scope, &identity.steam_id64) {
            Ok(next) => next,
            Err(error) => {
                warn!(%error, "achievement-sync: failed to schedule stats journal");
                None
            }
        },
        Err(error) => {
            warn!(%error, "achievement-sync: principal unavailable while scheduling retry");
            Some(unix_now().saturating_add(READY_RETRY_DELAY.as_secs() as i64))
        }
    };
    match (schema, stats) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (some, None) | (None, some) => some,
    }
}

/// The backend's verdict for this app when it refused to store the snapshot as
/// uploaded. Its `crc_stats` is the baseline the retry has to be built on.
fn refused_app_result<'a>(
    snapshot: &SteamAppSnapshot,
    result: &'a SteamStateUploadResult,
) -> Option<&'a AppStatsUploadResult> {
    result.stats_apps.iter().find(|app| {
        app.app_id == snapshot.app_id && app.status == AppStatsUploadStatus::StatsOutOfDate
    })
}

fn queue_native_refresh_after_upload(snapshot: &SteamAppSnapshot) {
    let Some(guard) = crate::client::user_stats::current_backend_refresh_guard() else {
        warn!(
            app_id = snapshot.app_id,
            "achievement-sync: cannot queue stats_out_of_date refresh without current runtime guard"
        );
        return;
    };
    if !crate::client::user_stats::queue_backend_stats_refresh(snapshot.app_id, guard) {
        warn!(
            app_id = snapshot.app_id,
            "achievement-sync: user-stats refresh worker unavailable after stats_out_of_date"
        );
        return;
    }
    // The refresh only re-merges Steam's cache; it never produces a snapshot. The
    // reopened record has had its content cleared, so without this the record waits
    // for content that nothing will ever supply and stays pending forever.
    crate::client::user_stats::queue_snapshot_read(snapshot.app_id);
}

fn persist_current_device_descriptor(journal: &SyncJournal) {
    let Some(descriptor) = vapor_forge_cloud_core::device_descriptor() else {
        return;
    };
    if let Err(error) = journal.store_device_descriptor(&descriptor, unix_now()) {
        warn!(%error, "achievement-sync: failed to persist device identity");
    }
}

fn upload_identity() -> Option<UploadIdentity> {
    let steam_id = vapor_forge_features::identity::steam_id();
    if steam_id == 0 {
        return None;
    }
    let descriptor = vapor_forge_cloud_core::device_descriptor()?;
    Some(UploadIdentity {
        client_id: descriptor.client_id,
        machine_name: descriptor.machine_name,
        os_type: descriptor.os_type,
        device_type: descriptor.device_type,
        steam_id64: steam_id.to_string(),
        persona_name: None,
    })
}

fn upload_context() -> Option<(Arc<dyn CloudBackend>, UploadIdentity)> {
    Some((crate::cloud_backend::backend_context()?, upload_identity()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_time_is_kept_only_when_it_is_authoritative() {
        assert_eq!(unlocked_at(true, 1_515_505_966), Some(1_515_505_966));
        assert_eq!(unlocked_at(true, 0), None);
        assert_eq!(unlocked_at(true, ACHIEVEMENT_UNLOCK_TIME_UNKNOWN), None);
        // ClearAchievement leaves Steam's per-bit time behind, so a time read
        // back for a locked achievement describes the previous unlock.
        assert_eq!(unlocked_at(false, 1_515_505_966), None);
        assert_eq!(unlocked_at(false, 0), None);
    }
}
