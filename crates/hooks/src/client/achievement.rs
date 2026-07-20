#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::debug;
use vapor_forge_features::achievement_events::{
    AchievementCommitBuffer, PendingAchievement, SnapshotObservation,
};
use vapor_forge_sync_state::QueuedAchievementEvent;

static COMMIT_BUFFER: OnceLock<Mutex<AchievementCommitBuffer>> = OnceLock::new();
static DIRTY_STATS: OnceLock<Mutex<HashSet<(u64, u32)>>> = OnceLock::new();

fn flush_committed(owner_steam_id64: u64, app_id: u32) {
    let pending = match commit_buffer().lock() {
        Ok(buffer) => buffer.pending_for_app(owner_steam_id64, app_id),
        Err(_) => return,
    };

    for event in pending {
        let queued = crate::achievement_worker::queue_event(queued_event(&event));
        if queued {
            if let Ok(mut buffer) = commit_buffer().lock() {
                buffer.mark_sent(&event);
            }
        }
    }
}

pub(crate) fn observe_progress(
    owner_steam_id64: u64,
    app_id: u32,
    key: &str,
    current: u32,
    maximum: u32,
) -> bool {
    observe_progress_with(
        commit_buffer(),
        owner_steam_id64,
        app_id,
        key,
        current,
        maximum,
        unix_now(),
        crate::achievement_worker::queue_event,
    )
}

#[allow(clippy::too_many_arguments)]
fn observe_progress_with(
    buffer: &Mutex<AchievementCommitBuffer>,
    owner_steam_id64: u64,
    app_id: u32,
    key: &str,
    current: u32,
    maximum: u32,
    observed_at: i64,
    queue: impl FnOnce(QueuedAchievementEvent) -> bool,
) -> bool {
    let pending = {
        let Ok(mut buffer) = buffer.lock() else {
            return false;
        };
        if buffer.stage_progress(owner_steam_id64, app_id, key, current, maximum, observed_at) {
            PendingAchievement::Progress {
                owner_steam_id64,
                app_id,
                key: key.to_owned(),
                current,
                maximum,
                observed_at,
            }
        } else {
            let Some(pending) = buffer.pending_progress(owner_steam_id64, app_id, key) else {
                return false;
            };
            pending
        }
    };

    if !queue(queued_event(&pending)) {
        return false;
    }
    if let Ok(mut buffer) = buffer.lock() {
        buffer.mark_sent(&pending);
    }
    true
}

pub(crate) fn register_packet_schema(app_id: u32, content: &[u8]) {
    if app_id != 0 && !content.is_empty() {
        debug!(
            app_id,
            bytes = content.len(),
            "achievement receiver: schema registered"
        );
        super::user_stats::queue_snapshot(app_id);
    }
}

pub(crate) fn observe_local_snapshot(snapshot: super::user_stats::AchievementSnapshot) -> bool {
    let owner = vapor_forge_features::identity::steam_id();
    if owner == 0 {
        warn_snapshot(snapshot.app_id, "SteamID is unavailable");
        return false;
    }
    let observed_at = unix_now();
    let unlocked = snapshot
        .achievements
        .iter()
        .filter(|achievement| achievement.unlocked)
        .map(|achievement| {
            let unlocked_at = if achievement.unlock_time == 0 {
                observed_at
            } else {
                i64::from(achievement.unlock_time)
            };
            (achievement.key.clone(), unlocked_at)
        })
        .collect::<Vec<_>>();
    let latest_unlock_time = snapshot
        .achievements
        .iter()
        .map(|achievement| achievement.unlock_time)
        .max()
        .unwrap_or(0);
    let observation = commit_buffer()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .observe_snapshot(owner, snapshot.app_id, &unlocked, observed_at);
    let Some(observation) = observation else {
        warn_snapshot(snapshot.app_id, "snapshot identity is invalid");
        return false;
    };
    flush_committed(owner, snapshot.app_id);
    debug!(
        app_id = snapshot.app_id,
        achievements = snapshot.achievements.len(),
        unlocked = unlocked.len(),
        latest_unlock_time,
        baseline = observation == SnapshotObservation::Baseline,
        "achievement receiver: local snapshot observed"
    );
    true
}

fn warn_snapshot(app_id: u32, reason: &'static str) {
    tracing::warn!(
        app_id,
        reason,
        "achievement receiver: local baseline failed"
    );
}

pub(crate) fn stage_set(owner_steam_id64: u64, app_id: u32, key: &str) {
    if let Ok(mut buffer) = commit_buffer().lock() {
        buffer.stage_unlock(owner_steam_id64, app_id, key, unix_now());
    }
}

pub(crate) fn stage_clear(owner_steam_id64: u64, app_id: u32, key: &str) {
    if let Ok(mut buffer) = commit_buffer().lock() {
        buffer.stage_clear(owner_steam_id64, app_id, key, unix_now());
    }
}

pub(crate) fn observe_stat_write(owner_steam_id64: u64, app_id: u32) {
    if owner_steam_id64 == 0 || app_id == 0 {
        return;
    }
    dirty_stats()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert((owner_steam_id64, app_id));
}

pub(crate) fn commit_store(owner_steam_id64: u64, app_id: u32) {
    if let Ok(mut buffer) = commit_buffer().lock() {
        buffer.commit(owner_steam_id64, app_id);
    }
    flush_committed(owner_steam_id64, app_id);
    let stats_changed = dirty_stats()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&(owner_steam_id64, app_id));
    debug!(
        app_id,
        stats_changed, "achievement receiver: StoreStats committed"
    );
    super::user_stats::queue_snapshot(app_id);
}

fn queued_event(pending: &PendingAchievement) -> QueuedAchievementEvent {
    match pending {
        PendingAchievement::Unlock {
            owner_steam_id64,
            app_id,
            key,
            observed_at,
            unlocked_at,
        } => QueuedAchievementEvent {
            owner_scope: String::new(),
            owner_steam_id64: owner_steam_id64.to_string(),
            event_id: vapor_forge_sync_state::achievement_unlock_event_id(
                *owner_steam_id64,
                *app_id,
                key,
                *unlocked_at,
            ),
            app_id: *app_id,
            achievement_key: key.clone(),
            kind: "unlock".into(),
            progress_current: None,
            progress_max: None,
            observed_at: *observed_at,
            unlocked_at: Some(*unlocked_at),
        },
        PendingAchievement::Progress {
            owner_steam_id64,
            app_id,
            key,
            current,
            maximum,
            observed_at,
        } => QueuedAchievementEvent {
            owner_scope: String::new(),
            owner_steam_id64: owner_steam_id64.to_string(),
            event_id: vapor_forge_sync_state::new_achievement_event_id(),
            app_id: *app_id,
            achievement_key: key.clone(),
            kind: "progress".into(),
            progress_current: Some(*current),
            progress_max: Some(*maximum),
            observed_at: *observed_at,
            unlocked_at: None,
        },
        PendingAchievement::Clear {
            owner_steam_id64,
            app_id,
            key,
            observed_at,
        } => QueuedAchievementEvent {
            owner_scope: String::new(),
            owner_steam_id64: owner_steam_id64.to_string(),
            event_id: vapor_forge_sync_state::achievement_clear_event_id(
                *owner_steam_id64,
                *app_id,
                key,
                *observed_at,
            ),
            app_id: *app_id,
            achievement_key: key.clone(),
            kind: "clear".into(),
            progress_current: None,
            progress_max: None,
            observed_at: *observed_at,
            unlocked_at: None,
        },
    }
}

fn commit_buffer() -> &'static Mutex<AchievementCommitBuffer> {
    COMMIT_BUFFER.get_or_init(|| Mutex::new(AchievementCommitBuffer::default()))
}

fn dirty_stats() -> &'static Mutex<HashSet<(u64, u32)>> {
    DIRTY_STATS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_unlock_preserves_observation_time() {
        let pending = PendingAchievement::Unlock {
            owner_steam_id64: 76561198000000001,
            app_id: 736260,
            key: "BABA_TEST".into(),
            observed_at: 123,
            unlocked_at: 100,
        };
        let event = queued_event(&pending);
        assert_eq!(event.app_id, 736260);
        assert_eq!(event.achievement_key, "BABA_TEST");
        assert_eq!(event.observed_at, 123);
        assert_eq!(event.unlocked_at, Some(100));
        assert_eq!(event.event_id.len(), 36);
        assert_eq!(
            event.event_id.chars().filter(|&value| value == '-').count(),
            4
        );
    }

    #[test]
    fn progress_is_queued_immediately_and_deduplicated() {
        let buffer = Mutex::new(AchievementCommitBuffer::default());
        let queued = Mutex::new(Vec::new());
        let queue = |event| {
            queued.lock().unwrap().push(event);
            true
        };
        assert!(observe_progress_with(
            &buffer,
            76561198000000001,
            736260,
            "BABA_TEST",
            1,
            10,
            123,
            queue,
        ));
        assert!(!observe_progress_with(
            &buffer,
            76561198000000001,
            736260,
            "BABA_TEST",
            1,
            10,
            124,
            |_| panic!("duplicate progress must not be queued"),
        ));
        let queued = queued.into_inner().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].kind, "progress");
        assert_eq!(queued[0].progress_current, Some(1));
        assert_eq!(queued[0].progress_max, Some(10));
    }

    #[test]
    fn queued_clear_has_no_unlock_or_progress_payload() {
        let event = queued_event(&PendingAchievement::Clear {
            owner_steam_id64: 7,
            app_id: 480,
            key: "COLLECT".into(),
            observed_at: 123,
        });
        assert_eq!(event.kind, "clear");
        assert_eq!(event.unlocked_at, None);
        assert_eq!(event.progress_current, None);
        assert_eq!(event.progress_max, None);
        assert_eq!(event.event_id.len(), 36);
    }

    #[test]
    fn failed_progress_persistence_is_retried() {
        let buffer = Mutex::new(AchievementCommitBuffer::default());
        assert!(!observe_progress_with(
            &buffer,
            7,
            480,
            "COLLECT",
            2,
            10,
            123,
            |_| false,
        ));
        assert!(observe_progress_with(
            &buffer,
            7,
            480,
            "COLLECT",
            2,
            10,
            124,
            |_| true,
        ));
    }
}
