#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use tracing::debug;

static NO_SCHEMA: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();

/// Valve answered a donor stats request without a schema for this app.
///
/// The donor request clears the client's cached schema tokens precisely so Valve
/// cannot answer "unchanged", so an empty schema means there is no schema: the app
/// declares no achievements and no stats. There is no snapshot layout to read.
pub(crate) fn note_schema_unavailable(app_id: u32) {
    if app_id == 0 {
        return;
    }
    super::user_stats::remove_snapshot_schema(app_id);
    let first = NO_SCHEMA
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(app_id);
    if first {
        debug!(app_id, "achievement receiver: app declares no stats schema");
    }
}

/// Steam received an app's stats schema on the wire.
///
/// The schema arrival establishes that Steam's stats map can be read directly.
pub(crate) fn register_packet_schema(app_id: u32, content: &[u8]) -> bool {
    if content.is_empty() {
        return false;
    }
    // A schema did arrive after all, so a previous absence no longer holds. The
    // donor can change, and so can the app.
    if let Some(seen) = NO_SCHEMA.get() {
        if let Ok(mut seen) = seen.lock() {
            seen.remove(&app_id);
        }
    }
    debug!(
        app_id,
        bytes = content.len(),
        "achievement receiver: schema registered"
    );
    super::user_stats::register_snapshot_schema(app_id, content)
}

pub(crate) fn observe_local_snapshot(
    snapshot: super::user_stats::AchievementSnapshot,
    intent: &super::user_stats::StatsSnapshotIntent,
) -> bool {
    let app_id = snapshot.app_id;
    let achievements = snapshot.achievements.len();
    let stats = snapshot.stats.len();
    let persisted = crate::achievement_worker::queue_official_snapshot(snapshot, intent);
    debug!(
        app_id,
        achievements, stats, persisted, "achievement receiver: official Steam snapshot observed"
    );
    persisted
}
