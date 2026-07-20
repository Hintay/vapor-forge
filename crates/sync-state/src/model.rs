use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedConflictResolution {
    pub owner_scope: String,
    pub event_id: String,
    pub app_id: u32,
    pub base_change_number: u64,
    pub remote_change_number: u64,
    pub resolution: String,
    pub machine_name: Option<String>,
}

pub fn new_achievement_event_id() -> String {
    new_event_id()
}

pub fn achievement_unlock_event_id(
    owner_steam_id64: u64,
    app_id: u32,
    achievement_key: &str,
    unlocked_at: i64,
) -> String {
    let identity = format!(
        "vapor-forge:achievement:{owner_steam_id64}:{app_id}:{achievement_key}:{unlocked_at}"
    );
    uuid_from_digest(Sha256::digest(identity.as_bytes()), 8)
}

pub fn achievement_clear_event_id(
    owner_steam_id64: u64,
    app_id: u32,
    achievement_key: &str,
    observed_at: i64,
) -> String {
    let identity = format!(
        "vapor-forge:achievement-clear:{owner_steam_id64}:{app_id}:{achievement_key}:{observed_at}"
    );
    uuid_from_digest(Sha256::digest(identity.as_bytes()), 8)
}

pub fn new_conflict_event_id() -> String {
    new_event_id()
}

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn new_event_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let material = format!("{nanos}:{}:{sequence}", std::process::id());
    uuid_from_digest(Sha256::digest(material.as_bytes()), 4)
}

fn uuid_from_digest(digest: impl AsRef<[u8]>, version: u8) -> String {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_ref()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | (version << 4);
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_event_ids_are_valid_uuids() {
        assert!(looks_like_uuid(&new_achievement_event_id()));
        assert!(looks_like_uuid(&new_conflict_event_id()));
    }

    #[test]
    fn unlock_ids_are_stable_for_the_same_observation() {
        let first = achievement_unlock_event_id(7, 480, "ACH_WIN", 123);
        let second = achievement_unlock_event_id(7, 480, "ACH_WIN", 123);
        assert_eq!(first, second);
        assert!(looks_like_uuid(&first));
        assert_ne!(first, achievement_unlock_event_id(7, 480, "ACH_WIN", 124));
    }

    #[test]
    fn clear_ids_are_stable_for_the_same_observation() {
        let first = achievement_clear_event_id(7, 480, "ACH_WIN", 123);
        assert_eq!(first, achievement_clear_event_id(7, 480, "ACH_WIN", 123));
        assert!(looks_like_uuid(&first));
        assert_ne!(first, achievement_clear_event_id(7, 480, "ACH_WIN", 124));
    }

    fn looks_like_uuid(value: &str) -> bool {
        value.len() == 36
            && value
                .chars()
                .enumerate()
                .all(|(index, character)| match index {
                    8 | 13 | 18 | 23 => character == '-',
                    _ => character.is_ascii_hexdigit(),
                })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutboxError {
    #[error("outbox filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("outbox database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}
