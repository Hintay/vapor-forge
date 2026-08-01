#![forbid(unsafe_code)]

use std::collections::HashMap;

use prost::Message;
use vapor_forge_cloud_core::{AchievementSyncState, AppStatsResult, StatSyncState};
use vapor_forge_steam_protocol::{
    app_id_from_game_id, parse_achievement_bit_mappings, parse_stat_mappings, stats_crc,
    AchievementBlock, ClientGetUserStatsRequest, ClientGetUserStatsResponse, LegacyStatsEntry,
    PlayerAchievementUnlockTime, PlayerGetUserStatsRequest, PlayerGetUserStatsResponse,
    PlayerStatsEntry, ACHIEVEMENT_UNLOCK_TIME_UNKNOWN,
};

#[derive(Clone, Copy)]
struct AchievementWireId {
    stat_id: u32,
    achievement_bit: u32,
}

pub(crate) fn merge_service_stats_response(
    request: &PlayerGetUserStatsRequest,
    mut donor: PlayerGetUserStatsResponse,
    full_schema: &[u8],
    backend: Option<&AppStatsResult>,
) -> Option<Vec<u8>> {
    let app_id = request.appid.filter(|app_id| *app_id != 0)?;
    donor.schema = (request.sha_schema != donor.sha_schema).then(|| full_schema.to_vec());
    donor.stats.clear();
    donor.crc_stats = None;
    donor.crc_schema = None;
    match backend {
        Some(AppStatsResult::Unchanged { crc_stats, .. }) => {
            donor.crc_stats = Some(*crc_stats);
        }
        Some(AppStatsResult::Modified {
            crc_stats,
            achievements,
            stats,
            ..
        }) => {
            let entries = service_stats_entries(app_id, full_schema, achievements, stats)?;
            let derived = crc_stats.is_none();
            let crc = crc_stats.unwrap_or_else(|| stats_crc(&entries));
            donor.crc_stats = Some(crc);
            // A backend with no arbiter cannot answer the conditional read itself,
            // so the token we derived answers it here: matching what the client
            // already holds means the payload would tell it nothing new.
            if !(derived && request.crc_stats == Some(crc)) {
                donor.stats = entries;
            }
        }
        Some(AppStatsResult::Uninitialized | AppStatsResult::SchemaMismatch { .. }) | None => {}
    }
    Some(donor.encode_to_vec())
}

pub(crate) fn merge_legacy_stats_response(
    request: &ClientGetUserStatsRequest,
    mut donor: ClientGetUserStatsResponse,
    full_schema: &[u8],
    backend: Option<&AppStatsResult>,
) -> Option<Vec<u8>> {
    let game_id = request.game_id?;
    let app_id = app_id_from_game_id(game_id)?;
    donor.game_id = Some(game_id);
    donor.schema = Some(full_schema.to_vec());
    donor.stats.clear();
    donor.achievement_blocks.clear();
    donor.crc_stats = None;
    match backend {
        Some(AppStatsResult::Unchanged { crc_stats, .. }) => {
            donor.crc_stats = Some(*crc_stats);
        }
        Some(AppStatsResult::Modified {
            crc_stats,
            achievements,
            stats,
            ..
        }) => {
            let derived = crc_stats.is_none();
            let crc = match *crc_stats {
                // The derived token names the state, not the encoding the client
                // asked for, so it comes from the service-shaped entries here too.
                // Both request forms must answer the same number for one state.
                None => stats_crc(&service_stats_entries(
                    app_id,
                    full_schema,
                    achievements,
                    stats,
                )?),
                Some(crc) => crc,
            };
            donor.crc_stats = Some(crc);
            // See merge_service_stats_response: a derived token also answers the
            // conditional read.
            if !(derived && request.crc_stats == Some(crc)) {
                (donor.stats, donor.achievement_blocks) =
                    legacy_stats_entries(app_id, full_schema, achievements, stats)?;
            }
        }
        Some(AppStatsResult::Uninitialized | AppStatsResult::SchemaMismatch { .. }) | None => {}
    }
    Some(donor.encode_to_vec())
}

fn achievement_wire_ids(schema: &[u8]) -> Option<HashMap<String, AchievementWireId>> {
    let mappings = parse_achievement_bit_mappings(schema).ok()?;
    Some(
        mappings
            .into_iter()
            .map(|mapping| {
                (
                    mapping.key,
                    AchievementWireId {
                        stat_id: mapping.stat_id,
                        achievement_bit: mapping.achievement_bit,
                    },
                )
            })
            .collect::<HashMap<_, _>>(),
    )
}

fn stat_wire_ids(schema: &[u8]) -> Option<HashMap<String, u32>> {
    let mappings = parse_stat_mappings(schema).ok()?;
    Some(
        mappings
            .into_iter()
            .map(|mapping| (mapping.key, mapping.stat_id))
            .collect::<HashMap<_, _>>(),
    )
}

fn service_stats_entries(
    app_id: u32,
    schema: &[u8],
    achievements: &[AchievementSyncState],
    states: &[StatSyncState],
) -> Option<Vec<PlayerStatsEntry>> {
    let achievement_ids = achievement_wire_ids(schema)?;
    let stat_ids = stat_wire_ids(schema)?;
    let mut stats = Vec::new();
    // A key the schema in flight does not declare is skipped, not fatal. The stored
    // state is keyed by name while the wire form is keyed by id, so a schema
    // revision, a record written against an older schema, or a stat Steam reported
    // with a type this build does not encode all produce keys with no id. Failing
    // the whole call would drop the caller back to "no backend state" and clear
    // every stat for the app, so one unknown key would cost all the known ones.
    for stat in states.iter().filter(|stat| stat.app_id == app_id) {
        let Some(stat_id) = stat_ids.get(&stat.stat_key).copied() else {
            skipped_key("stat", &stat.stat_key);
            continue;
        };
        let Some(value) = stat_wire_value(stat) else {
            skipped_key("stat value", &stat.stat_key);
            continue;
        };
        set_service_stat(&mut stats, stat_id, value);
    }
    for achievement in achievements
        .iter()
        .filter(|achievement| achievement.app_id == app_id)
    {
        let Some(wire_id) = achievement_ids.get(&achievement.achievement_key).copied() else {
            skipped_key("achievement", &achievement.achievement_key);
            continue;
        };
        let Some(unlock_time) = unlock_time(achievement) else {
            skipped_key("achievement time", &achievement.achievement_key);
            continue;
        };
        if set_service_achievement(&mut stats, wire_id, achievement.unlocked, unlock_time).is_none()
        {
            skipped_key("achievement bit", &achievement.achievement_key);
        }
    }
    stats.sort_by_key(|entry| entry.stat_id.unwrap_or(u32::MAX));
    Some(stats)
}

/// One key that could not be encoded, reported once per key per process.
///
/// Silence here would hide a schema drift that quietly shrinks what the client gets
/// back, and a line per request would flood.
fn skipped_key(kind: &str, key: &str) {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static SEEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);
    let first = SEEN
        .lock()
        .map(|mut seen| {
            seen.get_or_insert_with(HashSet::new)
                .insert(format!("{kind}\0{key}"))
        })
        .unwrap_or(false);
    if first {
        tracing::warn!(kind, key, "stats merge: key not in the schema, skipped");
    }
}

fn set_service_stat(stats: &mut Vec<PlayerStatsEntry>, stat_id: u32, value: u32) {
    if let Some(entry) = stats
        .iter_mut()
        .find(|entry| entry.stat_id == Some(stat_id))
    {
        entry.stat_value = Some(value);
    } else {
        stats.push(PlayerStatsEntry {
            stat_id: Some(stat_id),
            stat_value: Some(value),
            unlock_times: Vec::new(),
        });
    }
}

fn set_service_achievement(
    stats: &mut Vec<PlayerStatsEntry>,
    wire_id: AchievementWireId,
    unlocked: bool,
    unlock_time: u32,
) -> Option<()> {
    if wire_id.achievement_bit >= u32::BITS {
        return None;
    }
    let bit = 1_u32 << wire_id.achievement_bit;
    let existing_index = stats
        .iter()
        .position(|entry| entry.stat_id == Some(wire_id.stat_id));
    let entry_index = match existing_index {
        Some(index) => index,
        None => {
            stats.push(PlayerStatsEntry {
                stat_id: Some(wire_id.stat_id),
                stat_value: Some(0),
                unlock_times: Vec::new(),
            });
            stats.len() - 1
        }
    };
    let entry = &mut stats[entry_index];
    let previous_value = entry.stat_value.unwrap_or(0);
    entry.stat_value = Some(if unlocked {
        previous_value | bit
    } else {
        previous_value & !bit
    });

    if unlocked {
        if let Some(existing) = entry
            .unlock_times
            .iter_mut()
            .find(|time| time.achievement_bit == Some(wire_id.achievement_bit))
        {
            existing.unlock_time = Some(unlock_time);
        } else {
            entry.unlock_times.push(PlayerAchievementUnlockTime {
                achievement_bit: Some(wire_id.achievement_bit),
                unlock_time: Some(unlock_time),
            });
            entry
                .unlock_times
                .sort_by_key(|time| time.achievement_bit.unwrap_or(u32::MAX));
        }
    } else {
        entry
            .unlock_times
            .retain(|time| time.achievement_bit != Some(wire_id.achievement_bit));
    }
    Some(())
}

fn legacy_stats_entries(
    app_id: u32,
    schema: &[u8],
    achievements: &[AchievementSyncState],
    states: &[StatSyncState],
) -> Option<(Vec<LegacyStatsEntry>, Vec<AchievementBlock>)> {
    let achievement_ids = achievement_wire_ids(schema)?;
    let stat_ids = stat_wire_ids(schema)?;
    let mut stats = Vec::new();
    let mut achievement_blocks = Vec::new();
    // See service_stats_entries: an unencodable key is skipped, never fatal.
    for stat in states.iter().filter(|stat| stat.app_id == app_id) {
        let Some(stat_id) = stat_ids.get(&stat.stat_key).copied() else {
            skipped_key("stat", &stat.stat_key);
            continue;
        };
        let Some(value) = stat_wire_value(stat) else {
            skipped_key("stat value", &stat.stat_key);
            continue;
        };
        stats.push(LegacyStatsEntry {
            stat_id: Some(stat_id),
            stat_value: Some(value),
        });
    }
    for achievement in achievements
        .iter()
        .filter(|achievement| achievement.app_id == app_id)
    {
        let Some(wire_id) = achievement_ids.get(&achievement.achievement_key).copied() else {
            skipped_key("achievement", &achievement.achievement_key);
            continue;
        };
        let Some(unlock_time) = unlock_time(achievement) else {
            skipped_key("achievement time", &achievement.achievement_key);
            continue;
        };
        if set_legacy_achievement(
            &mut achievement_blocks,
            wire_id,
            achievement.unlocked,
            unlock_time,
        )
        .is_none()
        {
            skipped_key("achievement bit", &achievement.achievement_key);
        }
    }
    stats.sort_by_key(|entry| entry.stat_id.unwrap_or(u32::MAX));
    achievement_blocks.sort_by_key(|block| block.achievement_id.unwrap_or(u32::MAX));
    Some((stats, achievement_blocks))
}

fn set_legacy_achievement(
    blocks: &mut Vec<AchievementBlock>,
    wire_id: AchievementWireId,
    unlocked: bool,
    unlock_time: u32,
) -> Option<()> {
    if wire_id.achievement_bit >= u32::BITS {
        return None;
    }
    let bit_index = usize::try_from(wire_id.achievement_bit).ok()?;
    let existing_index = blocks
        .iter()
        .position(|block| block.achievement_id == Some(wire_id.stat_id));
    let block_index = match existing_index {
        Some(index) => index,
        None => {
            blocks.push(AchievementBlock {
                achievement_id: Some(wire_id.stat_id),
                unlock_time: Vec::new(),
            });
            blocks.len() - 1
        }
    };
    let block = &mut blocks[block_index];
    if block.unlock_time.len() <= bit_index {
        block.unlock_time.resize(bit_index + 1, 0);
    }
    block.unlock_time[bit_index] = if unlocked { unlock_time } else { 0 };
    Some(())
}

fn stat_wire_value(stat: &StatSyncState) -> Option<u32> {
    match stat.value_type.as_str() {
        "int" => stat.value.parse::<i32>().ok().map(|value| value as u32),
        "float" | "average_rate" => stat.value.parse::<f32>().ok().map(|value| value.to_bits()),
        _ => None,
    }
}

/// The rtime32 to put on the wire for one achievement.
///
/// An unlocked achievement with no known time must still encode: returning `None`
/// here short-circuits `service_stats_entries` through its `?`, which makes the
/// whole merge return `None`, which drops the caller back to `backend = None` and
/// clears every stat for the app. One achievement with an unknown time would
/// silently disable cloud restore for that app. Steam's own sentinel is the honest
/// encoding for exactly this state, so emit it.
fn unlock_time(state: &AchievementSyncState) -> Option<u32> {
    if !state.unlocked {
        return Some(0);
    }
    Some(
        state
            .unlocked_at
            .filter(|value| *value > 0)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(ACHIEVEMENT_UNLOCK_TIME_UNKNOWN),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CUMULUS_STATS_CRC: u32 = 0x89ab_cdef;

    fn kv_string(out: &mut Vec<u8>, key: &str, value: &str) {
        out.push(1);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }

    fn kv_object(out: &mut Vec<u8>, key: &str, body: impl FnOnce(&mut Vec<u8>)) {
        out.push(0);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        body(out);
        out.push(8);
    }

    fn kv_int(out: &mut Vec<u8>, key: &str, value: i32) {
        out.push(2);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn schema() -> Vec<u8> {
        let mut schema = Vec::new();
        kv_object(&mut schema, "480", |root| {
            kv_object(root, "stats", |stats| {
                kv_object(stats, "11", |stat| {
                    kv_string(stat, "name", "STAT_SCORE");
                    kv_int(stat, "type", 1);
                });
                kv_object(stats, "12", |stat| {
                    kv_object(stat, "bits", |bits| {
                        kv_object(bits, "3", |achievement| {
                            kv_string(achievement, "name", "ACH_WIN");
                        });
                    });
                });
            });
        });
        schema
    }

    fn modified_result(unlocked: bool, unlocked_at: Option<i64>) -> AppStatsResult {
        modified_result_with_token(unlocked, unlocked_at, Some(CUMULUS_STATS_CRC))
    }

    fn modified_result_with_token(
        unlocked: bool,
        unlocked_at: Option<i64>,
        crc_stats: Option<u32>,
    ) -> AppStatsResult {
        AppStatsResult::Modified {
            schema_version: "010203".into(),
            crc_stats,
            achievements: vec![AchievementSyncState {
                app_id: 480,
                achievement_key: "ACH_WIN".into(),
                unlocked,
                progress_current: None,
                progress_max: None,
                observed_at: 20,
                unlocked_at,
            }],
            stats: vec![StatSyncState {
                app_id: 480,
                stat_key: "STAT_SCORE".into(),
                value_type: "int".into(),
                value: "3".into(),
                observed_at: 20,
            }],
        }
    }

    fn unchanged_result() -> AppStatsResult {
        AppStatsResult::Unchanged {
            schema_version: "010203".into(),
            crc_stats: CUMULUS_STATS_CRC,
        }
    }

    fn donor_service_response(schema: &[u8]) -> PlayerGetUserStatsResponse {
        PlayerGetUserStatsResponse {
            sha_schema: Some(vec![1, 2, 3]),
            crc_stats: Some(0x1111_2222),
            schema: Some(schema.to_vec()),
            stats: vec![PlayerStatsEntry {
                stat_id: Some(99),
                stat_value: Some(99),
                unlock_times: Vec::new(),
            }],
            crc_schema: Some(0x3333_4444),
        }
    }

    fn donor_legacy_response(schema: &[u8]) -> ClientGetUserStatsResponse {
        ClientGetUserStatsResponse {
            game_id: Some(480),
            eresult: Some(vapor_forge_steam_protocol::ERESULT_OK),
            crc_stats: Some(0x1111_2222),
            schema: Some(schema.to_vec()),
            stats: vec![LegacyStatsEntry {
                stat_id: Some(99),
                stat_value: Some(99),
            }],
            achievement_blocks: Vec::new(),
        }
    }

    #[test]
    fn service_user_stats_backend_response_preserves_unlock_time_and_stats() {
        let schema = schema();
        let request = PlayerGetUserStatsRequest {
            appid: Some(480),
            sha_schema: Some(vec![1, 2, 3]),
            crc_stats: Some(7),
            crc_schema: Some(0x1234_5678),
            ..Default::default()
        };
        let backend = modified_result(true, Some(10));
        let body = merge_service_stats_response(
            &request,
            donor_service_response(&schema),
            &schema,
            Some(&backend),
        )
        .expect("schema and backend state should synthesize a response");
        let response = PlayerGetUserStatsResponse::decode(body.as_slice()).unwrap();

        assert_eq!(response.sha_schema, Some(vec![1, 2, 3]));
        assert_eq!(response.crc_stats, Some(CUMULUS_STATS_CRC));
        assert_eq!(response.crc_schema, None);
        assert_eq!(response.schema, None);
        assert_eq!(response.stats.len(), 2);
        assert_eq!(response.stats[0].stat_id, Some(11));
        assert_eq!(response.stats[0].stat_value, Some(3));
        assert_eq!(response.stats[1].stat_id, Some(12));
        assert_eq!(response.stats[1].stat_value, Some(1 << 3));
        assert_eq!(response.stats[1].unlock_times.len(), 1);
        assert_eq!(response.stats[1].unlock_times[0].achievement_bit, Some(3));
        assert_eq!(response.stats[1].unlock_times[0].unlock_time, Some(10));
    }

    #[test]
    fn an_unlocked_achievement_with_no_known_time_still_encodes() {
        // Returning None here used to short-circuit the whole merge through the `?`
        // in service_stats_entries, dropping the caller to backend = None and
        // clearing every stat for the app. One achievement was enough to disable
        // cloud restore for it.
        let schema = schema();
        let backend = modified_result(true, None);
        let response = PlayerGetUserStatsResponse::decode(
            merge_service_stats_response(
                &PlayerGetUserStatsRequest {
                    appid: Some(480),
                    sha_schema: Some(vec![1, 2, 3]),
                    ..Default::default()
                },
                donor_service_response(&schema),
                &schema,
                Some(&backend),
            )
            .expect("an unknown unlock time must not abort the merge")
            .as_slice(),
        )
        .unwrap();

        assert_eq!(response.stats.len(), 2);
        assert_eq!(response.stats[1].stat_id, Some(12));
        assert_eq!(response.stats[1].stat_value, Some(1 << 3));
        // Steam's own encoding for "unlocked, real time unknown".
        assert_eq!(
            response.stats[1].unlock_times[0].unlock_time,
            Some(ACHIEVEMENT_UNLOCK_TIME_UNKNOWN)
        );
    }

    #[test]
    fn a_backend_that_issues_no_token_gets_one_derived_from_the_state() {
        let schema = schema();
        let backend = modified_result_with_token(true, Some(10), None);
        let AppStatsResult::Modified {
            achievements,
            stats,
            ..
        } = &backend
        else {
            panic!("fixture is Modified");
        };
        let expected =
            stats_crc(&service_stats_entries(480, &schema, achievements, stats).unwrap());

        let service = PlayerGetUserStatsResponse::decode(
            merge_service_stats_response(
                &PlayerGetUserStatsRequest {
                    appid: Some(480),
                    sha_schema: Some(vec![1, 2, 3]),
                    ..Default::default()
                },
                donor_service_response(&schema),
                &schema,
                Some(&backend),
            )
            .expect("schema and backend state should synthesize a response")
            .as_slice(),
        )
        .unwrap();
        let legacy = ClientGetUserStatsResponse::decode(
            merge_legacy_stats_response(
                &ClientGetUserStatsRequest {
                    game_id: Some(480),
                    ..Default::default()
                },
                donor_legacy_response(&schema),
                &schema,
                Some(&backend),
            )
            .expect("schema and backend state should synthesize a response")
            .as_slice(),
        )
        .unwrap();

        assert_eq!(service.crc_stats, Some(expected));
        assert_ne!(service.crc_stats, Some(CUMULUS_STATS_CRC));
        assert_eq!(service.stats.len(), 2);
        // The token names the state, not the encoding the client asked for, so both
        // request forms must answer the same number.
        assert_eq!(legacy.crc_stats, service.crc_stats);
        // The legacy encoding splits them: plain stats in `stats`, achievement bits
        // in `achievement_blocks`. Same state, same token, different shape.
        assert_eq!(legacy.stats.len(), 1);
        assert_eq!(legacy.achievement_blocks.len(), 1);

        // Presenting that same token back makes the derived answer conditional, the
        // way an arbiter's own token would: the client is told nothing changed and
        // the payload is left out.
        let repeat = PlayerGetUserStatsResponse::decode(
            merge_service_stats_response(
                &PlayerGetUserStatsRequest {
                    appid: Some(480),
                    sha_schema: Some(vec![1, 2, 3]),
                    crc_stats: Some(expected),
                    ..Default::default()
                },
                donor_service_response(&schema),
                &schema,
                Some(&backend),
            )
            .expect("schema and backend state should synthesize a response")
            .as_slice(),
        )
        .unwrap();
        assert_eq!(repeat.crc_stats, Some(expected));
        assert!(repeat.stats.is_empty());
    }

    #[test]
    fn service_user_stats_backend_response_writes_explicit_locked_state() {
        let schema = schema();
        let request = PlayerGetUserStatsRequest {
            appid: Some(480),
            sha_schema: Some(vec![1]),
            ..Default::default()
        };
        let backend = modified_result(false, None);
        let body = merge_service_stats_response(
            &request,
            donor_service_response(&schema),
            &schema,
            Some(&backend),
        )
        .expect("schema and backend state should synthesize a response");
        let response = PlayerGetUserStatsResponse::decode(body.as_slice()).unwrap();

        assert_eq!(response.stats[1].stat_id, Some(12));
        assert_eq!(response.stats[1].stat_value, Some(0));
        assert!(response.stats[1].unlock_times.is_empty());
    }

    #[test]
    fn legacy_user_stats_backend_response_writes_stats_and_unlock_time() {
        let schema = schema();
        let request = ClientGetUserStatsRequest {
            game_id: Some(480),
            crc_stats: Some(7),
            ..Default::default()
        };
        let backend = modified_result(true, Some(10));
        let body = merge_legacy_stats_response(
            &request,
            donor_legacy_response(&schema),
            &schema,
            Some(&backend),
        )
        .expect("schema and backend state should synthesize a response");
        let response = ClientGetUserStatsResponse::decode(body.as_slice()).unwrap();

        assert_eq!(response.game_id, Some(480));
        assert_ne!(response.crc_stats, Some(7));
        assert_eq!(response.schema, Some(schema));
        assert_eq!(response.stats.len(), 1);
        assert_eq!(response.stats[0].stat_id, Some(11));
        assert_eq!(response.stats[0].stat_value, Some(3));
        assert_eq!(response.achievement_blocks.len(), 1);
        assert_eq!(response.achievement_blocks[0].achievement_id, Some(12));
        assert_eq!(
            response.achievement_blocks[0].unlock_time,
            vec![0, 0, 0, 10]
        );
    }

    #[test]
    fn user_stats_backend_response_omits_stats_when_client_crc_matches_authority() {
        let schema = schema();
        let body = merge_service_stats_response(
            &PlayerGetUserStatsRequest {
                appid: Some(480),
                crc_stats: Some(CUMULUS_STATS_CRC),
                ..Default::default()
            },
            donor_service_response(&schema),
            &schema,
            Some(&unchanged_result()),
        )
        .unwrap();
        let response = PlayerGetUserStatsResponse::decode(body.as_slice()).unwrap();

        assert_eq!(response.crc_stats, Some(CUMULUS_STATS_CRC));
        assert!(response.stats.is_empty());
    }

    #[test]
    fn user_stats_backend_absence_returns_schema_only_response() {
        let schema = schema();
        let request = PlayerGetUserStatsRequest {
            appid: Some(480),
            sha_schema: Some(vec![9]),
            ..Default::default()
        };
        let body =
            merge_service_stats_response(&request, donor_service_response(&schema), &schema, None)
                .unwrap();
        let response = PlayerGetUserStatsResponse::decode(body.as_slice()).unwrap();
        assert_eq!(response.schema, Some(schema));
        assert_eq!(response.crc_stats, None);
        assert!(response.stats.is_empty());
    }

    #[test]
    fn user_stats_matching_schema_and_no_backend_preserves_local_cache() {
        let schema = schema();
        let request = PlayerGetUserStatsRequest {
            appid: Some(480),
            sha_schema: Some(vec![1, 2, 3]),
            ..Default::default()
        };
        let body =
            merge_service_stats_response(&request, donor_service_response(&schema), &schema, None)
                .unwrap();
        let response = PlayerGetUserStatsResponse::decode(body.as_slice()).unwrap();

        assert_eq!(response.schema, None);
        assert_eq!(response.crc_stats, None);
        assert!(response.stats.is_empty());
    }

    #[test]
    fn user_stats_schema_mismatch_returns_schema_only_response() {
        let schema = schema();
        let request = PlayerGetUserStatsRequest {
            appid: Some(480),
            sha_schema: Some(vec![9]),
            ..Default::default()
        };
        let backend = AppStatsResult::SchemaMismatch {
            schema_version: Some("other".into()),
        };
        let body = merge_service_stats_response(
            &request,
            donor_service_response(&schema),
            &schema,
            Some(&backend),
        )
        .unwrap();
        let response = PlayerGetUserStatsResponse::decode(body.as_slice()).unwrap();
        assert_eq!(response.schema, Some(schema));
        assert_eq!(response.crc_stats, None);
        assert!(response.stats.is_empty());
    }

    #[test]
    fn an_unknown_unlock_time_no_longer_refuses_the_whole_app() {
        // This asserted the opposite until the blast radius was measured. Refusing
        // was deliberate, on the reasoning that a time we do not know should not be
        // asserted. But the refusal is not scoped to the achievement: the `?` in
        // service_stats_entries aborts the merge, the caller falls back to
        // backend = None, and every stat for the app is cleared. One achievement
        // disabled cloud restore for all of them, and the safety of that fallback
        // rests on an unverified assumption about what Steam does with an
        // ERESULT_OK response carrying zero entries.
        //
        // Emitting Steam's own sentinel is not an assertion we invented: it is the
        // encoding Steam uses for this exact state, and it is what GetAchievement
        // hands back, so the common case is an exact round trip.
        let schema = schema();
        let request = PlayerGetUserStatsRequest {
            appid: Some(480),
            sha_schema: Some(vec![1]),
            ..Default::default()
        };
        let backend = modified_result(true, None);

        let body = merge_service_stats_response(
            &request,
            donor_service_response(&schema),
            &schema,
            Some(&backend),
        )
        .expect("one unknown unlock time must not clear the app");
        let response = PlayerGetUserStatsResponse::decode(body.as_slice()).unwrap();
        assert_eq!(response.stats.len(), 2);
    }

    #[test]
    fn user_stats_backend_response_rejects_unparseable_schema() {
        let request = PlayerGetUserStatsRequest {
            appid: Some(480),
            sha_schema: Some(vec![1]),
            ..Default::default()
        };
        let backend = modified_result(true, Some(10));

        assert!(merge_service_stats_response(
            &request,
            donor_service_response(b"not a binary keyvalues schema"),
            b"not a binary keyvalues schema",
            Some(&backend),
        )
        .is_none());
    }
}
