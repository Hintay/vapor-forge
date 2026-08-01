#![forbid(unsafe_code)]

//! Backend-authoritative playtime on its way into Steam.
//!
//! Steam ingests playtime through the `Player.ClientGetLastPlayedTimes#1`
//! response and the `PlayerClient.NotifyLastPlayedTimes#1` notification, so
//! this module corrects those rather than intercepting readers. Remote updates
//! populate a cache from their event stream. A local folder is read only when
//! Steam's own last-played-times response arrives.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use prost::Message;
use tracing::warn;
use vapor_forge_cloud_core::{AccountPlaytimeSnapshot, CloudBackend, PlaytimeEntry};
use vapor_forge_cloud_local::LocalBackend;
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_steam_protocol::{
    CMsgProtoBufHeader, PlayerGetLastPlayedTimesResponse, PlayerLastPlayedGame,
    PlayerLastPlayedTimesNotification, EMSG_SERVICE_METHOD_SEND_TO_CLIENT, K_MSG_HDR_PROTO_FLAG,
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeKey {
    pub credential_fingerprint: String,
    pub steam_id64: u64,
    pub identity_generation: u64,
    pub client_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CachedPlaytime {
    pub app_id: u32,
    pub playtime_minutes: u32,
    pub playtime_2weeks_minutes: u32,
    pub last_played_at: Option<i64>,
}

#[derive(Default)]
struct PlaytimeCache {
    key: Option<RuntimeKey>,
    revision: u64,
    games: HashMap<u32, CachedPlaytime>,
}

static CACHE: OnceLock<Mutex<PlaytimeCache>> = OnceLock::new();

pub(crate) fn runtime_key(
    credential_fingerprint: String,
    steam_id64: u64,
    identity_generation: u64,
    client_id: u64,
) -> RuntimeKey {
    RuntimeKey {
        credential_fingerprint,
        steam_id64,
        identity_generation,
        client_id,
    }
}

pub(crate) fn current_runtime_key() -> Option<RuntimeKey> {
    let backend = crate::cloud_backend::backend_context()?;
    let descriptor = vapor_forge_cloud_core::device_descriptor()?;
    let steam_id64 = vapor_forge_features::identity::steam_id();
    if steam_id64 == 0 {
        return None;
    }
    Some(runtime_key(
        backend.credential_fingerprint(),
        steam_id64,
        vapor_forge_features::identity::generation(),
        descriptor.client_id,
    ))
}

pub(crate) fn reset_account_state() {
    cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

pub(crate) fn runtime_key_is_current(key: &RuntimeKey) -> bool {
    current_runtime_key().as_ref() == Some(key)
}

pub(crate) fn apply_stream_snapshot(
    key: RuntimeKey,
    snapshot: &AccountPlaytimeSnapshot,
    config: &RuntimeConfig,
) -> Option<Vec<u8>> {
    let changed =
        store_backend_playtime(key.clone(), snapshot.playtime_revision, &snapshot.playtime)?;
    let games = changed
        .into_iter()
        .filter(|entry| requires_backend_playtime(config, entry.app_id))
        .filter_map(steam_game)
        .collect::<Vec<_>>();
    if games.is_empty() {
        return None;
    }
    build_notification_packet(key.steam_id64, games)
}

/// What the packet rewriter knows about backend playtime right now.
///
/// `Cold` and an empty `Known` differ: `Cold` means no state has arrived yet,
/// so Steam's own persisted values stand. `Known` means the backend has
/// spoken, and an app missing from it has no backend playtime.
enum PlaytimeView {
    Cold,
    Known(HashMap<u32, CachedPlaytime>),
}

fn playtime_view() -> PlaytimeView {
    let Some(key) = current_runtime_key() else {
        return PlaytimeView::Cold;
    };
    let cache = cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if cache.key.as_ref() != Some(&key) {
        return PlaytimeView::Cold;
    }
    PlaytimeView::Known(cache.games.clone())
}

fn response_playtime_view(config: &RuntimeConfig) -> PlaytimeView {
    if !config.local_cloud_configured() {
        return playtime_view();
    }
    let Some(key) = current_runtime_key() else {
        return PlaytimeView::Cold;
    };
    let backend = match LocalBackend::open(&config.cloud.local_path) {
        Ok(backend) => backend,
        Err(error) => {
            warn!(%error, "playtime-downlink: local state unavailable on Steam pull");
            return PlaytimeView::Cold;
        }
    };
    if backend.credential_fingerprint() != key.credential_fingerprint {
        return PlaytimeView::Cold;
    }
    let entries = match backend.pull_playtime(&key.steam_id64.to_string()) {
        Ok(entries) => entries,
        Err(error) => {
            warn!(%error, "playtime-downlink: local state read failed on Steam pull");
            return PlaytimeView::Cold;
        }
    };
    if !runtime_key_is_current(&key)
        || !std::ptr::eq(config, crate::client::install::config().as_ref())
    {
        return PlaytimeView::Cold;
    }
    PlaytimeView::Known(playtime_games(&entries))
}

pub(crate) fn rewrite_last_played_response(body: &[u8], config: &RuntimeConfig) -> Option<Vec<u8>> {
    let view = response_playtime_view(config);
    rewrite_response_with(body, config, &view)
}

pub(crate) fn rewrite_last_played_notification(
    body: &[u8],
    config: &RuntimeConfig,
) -> Option<Vec<u8>> {
    rewrite_notification_with(body, config, &playtime_view())
}

fn rewrite_response_with(
    body: &[u8],
    config: &RuntimeConfig,
    view: &PlaytimeView,
) -> Option<Vec<u8>> {
    let mut response = PlayerGetLastPlayedTimesResponse::decode(body).ok()?;
    overlay_games(&mut response.games, config, view, true)?;
    Some(response.encode_to_vec())
}

fn rewrite_notification_with(
    body: &[u8],
    config: &RuntimeConfig,
    view: &PlaytimeView,
) -> Option<Vec<u8>> {
    let mut notification =
        vapor_forge_steam_protocol::PlayerLastPlayedTimesNotification::decode(body).ok()?;
    overlay_games(&mut notification.games, config, view, false)?;
    Some(notification.encode_to_vec())
}

impl PlaytimeCache {
    fn clear(&mut self) {
        self.key = None;
        self.revision = 0;
        self.games.clear();
    }
}

fn cache() -> &'static Mutex<PlaytimeCache> {
    CACHE.get_or_init(|| Mutex::new(PlaytimeCache::default()))
}

fn store_backend_playtime(
    key: RuntimeKey,
    revision: u64,
    entries: &[PlaytimeEntry],
) -> Option<Vec<CachedPlaytime>> {
    let games = playtime_games(entries);
    let mut cache = cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if cache.key.as_ref() == Some(&key)
        && revision != 0
        && cache.revision != 0
        && revision <= cache.revision
    {
        return None;
    }
    let changed = games
        .values()
        .filter(|entry| cache.games.get(&entry.app_id) != Some(*entry))
        .cloned()
        .collect::<Vec<_>>();
    cache.key = Some(key);
    cache.revision = revision;
    cache.games = games;
    Some(changed)
}

fn playtime_games(entries: &[PlaytimeEntry]) -> HashMap<u32, CachedPlaytime> {
    entries
        .iter()
        .filter_map(cached_entry)
        .map(|entry| (entry.app_id, entry))
        .collect()
}

fn build_notification_packet(steam_id64: u64, games: Vec<PlayerLastPlayedGame>) -> Option<Vec<u8>> {
    if steam_id64 == 0 || games.is_empty() {
        return None;
    }
    let header = CMsgProtoBufHeader {
        steamid: Some(steam_id64),
        target_job_name: Some(
            vapor_forge_features::playtime::LAST_PLAYED_TIMES_NOTIFICATION_JOB_NAME.to_owned(),
        ),
        ..Default::default()
    }
    .encode_to_vec();
    let body = PlayerLastPlayedTimesNotification { games }.encode_to_vec();
    Some(vapor_forge_steam_protocol::assemble_raw(
        EMSG_SERVICE_METHOD_SEND_TO_CLIENT | K_MSG_HDR_PROTO_FLAG,
        &header,
        &body,
    ))
}

fn overlay_games(
    games: &mut Vec<PlayerLastPlayedGame>,
    config: &RuntimeConfig,
    view: &PlaytimeView,
    append_missing: bool,
) -> Option<()> {
    // Nothing known yet, so leave Steam's own entries in place.
    let PlaytimeView::Known(backend) = view else {
        return None;
    };
    let backend_games = backend
        .iter()
        .filter(|(app_id, _)| requires_backend_playtime(config, **app_id))
        .map(|(app_id, entry)| (*app_id, entry.clone()))
        .collect::<HashMap<_, _>>();
    let mut changed = false;
    let mut seen_backend_apps = HashSet::new();
    let missing_capacity = if append_missing {
        backend_games.len()
    } else {
        0
    };
    let mut rewritten = Vec::with_capacity(games.len() + missing_capacity);

    for game in games.drain(..) {
        let app_id = game
            .app_id
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value != 0);
        let Some(app_id) = app_id else {
            rewritten.push(game);
            continue;
        };
        if !requires_backend_playtime(config, app_id) {
            rewritten.push(game);
            continue;
        }
        match backend_games.get(&app_id).cloned() {
            Some(entry) => {
                seen_backend_apps.insert(app_id);
                let overlay = steam_game(entry)?;
                if !same_steam_game(&overlay, &game) {
                    changed = true;
                }
                rewritten.push(overlay);
            }
            // Backend holds nothing for this app.
            None => {
                changed = true;
            }
        }
    }

    if append_missing {
        let mut missing = backend_games
            .into_iter()
            .filter(|(app_id, _)| !seen_backend_apps.contains(app_id))
            .collect::<Vec<_>>();
        missing.sort_by_key(|(app_id, _)| *app_id);
        for (_, entry) in missing {
            rewritten.push(steam_game(entry)?);
            changed = true;
        }
    }

    if !changed {
        return None;
    }
    *games = rewritten;
    Some(())
}

fn cached_entry(entry: &PlaytimeEntry) -> Option<CachedPlaytime> {
    if entry.app_id == 0 || entry.last_played_at.is_some_and(|value| value < 0) {
        return None;
    }
    Some(CachedPlaytime {
        app_id: entry.app_id,
        playtime_minutes: entry.playtime_minutes,
        playtime_2weeks_minutes: entry.playtime_2weeks_minutes,
        last_played_at: entry.last_played_at,
    })
}

fn steam_game(entry: CachedPlaytime) -> Option<PlayerLastPlayedGame> {
    Some(PlayerLastPlayedGame {
        app_id: Some(i32::try_from(entry.app_id).ok()?),
        last_playtime: entry
            .last_played_at
            .and_then(|value| u32::try_from(value).ok()),
        playtime_2weeks: Some(saturating_i32(entry.playtime_2weeks_minutes)),
        playtime_forever: Some(saturating_i32(entry.playtime_minutes)),
        ..Default::default()
    })
}

fn same_steam_game(left: &PlayerLastPlayedGame, right: &PlayerLastPlayedGame) -> bool {
    left.app_id == right.app_id
        && left.last_playtime == right.last_playtime
        && left.playtime_2weeks == right.playtime_2weeks
        && left.playtime_forever == right.playtime_forever
        && left.first_playtime == right.first_playtime
        && left.playtime_windows_forever == right.playtime_windows_forever
        && left.playtime_mac_forever == right.playtime_mac_forever
        && left.playtime_linux_forever == right.playtime_linux_forever
        && left.first_windows_playtime == right.first_windows_playtime
        && left.first_mac_playtime == right.first_mac_playtime
        && left.first_linux_playtime == right.first_linux_playtime
        && left.last_windows_playtime == right.last_windows_playtime
        && left.last_mac_playtime == right.last_mac_playtime
        && left.last_linux_playtime == right.last_linux_playtime
        && left.playtime_disconnected == right.playtime_disconnected
        && left.playtime_deck_forever == right.playtime_deck_forever
        && left.first_deck_playtime == right.first_deck_playtime
        && left.last_deck_playtime == right.last_deck_playtime
}

fn requires_backend_playtime(config: &RuntimeConfig, app_id: u32) -> bool {
    app_id != 0
        && vapor_forge_features::apps::classify_app(config, AppId(app_id))
            .requires_injected_ownership()
}

fn saturating_i32(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::sync::Mutex;
    use vapor_forge_cloud_core::AccountSyncState;
    use vapor_forge_config::{AppsSection, InjectApp};

    /// Serializes tests that touch the process-wide cache or the `apps`
    /// account state, which they otherwise reset out from under each other.
    static ACCOUNT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn config_with(app_ids: &[u32]) -> RuntimeConfig {
        RuntimeConfig {
            apps: AppsSection {
                inject: app_ids
                    .iter()
                    .copied()
                    .map(|app_id| InjectApp {
                        id: AppId(app_id),
                        dlc: Vec::new(),
                        ticket: Default::default(),
                        purchase_time: 0,
                    })
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn config() -> RuntimeConfig {
        config_with(&[480])
    }

    fn view_with(apps: &[(u32, u32)]) -> PlaytimeView {
        PlaytimeView::Known(
            state_with(apps)
                .playtime
                .iter()
                .filter_map(cached_entry)
                .map(|entry| (entry.app_id, entry))
                .collect(),
        )
    }

    fn view(minutes: u32) -> PlaytimeView {
        view_with(&[(480, minutes)])
    }

    fn state_with(apps: &[(u32, u32)]) -> AccountSyncState {
        AccountSyncState {
            stats_crcs: Vec::new(),
            playtime_revision: 1,
            achievements: Vec::new(),
            stats: Vec::new(),
            playtime: apps
                .iter()
                .copied()
                .map(|(app_id, minutes)| PlaytimeEntry {
                    owner_scope: "scope-a".into(),
                    owner_steam_id64: "76561198000000001".into(),
                    app_id,
                    playtime_minutes: minutes,
                    playtime_2weeks_minutes: 7,
                    last_played_at: Some(1_800_000_000),
                    observed_at: 1_800_000_001,
                })
                .collect(),
        }
    }

    fn state(minutes: u32) -> AccountSyncState {
        state_with(&[(480, minutes)])
    }

    fn stream_snapshot(app_id: u32, revision: u64, minutes: u32) -> AccountPlaytimeSnapshot {
        AccountPlaytimeSnapshot {
            steam_id64: "76561198000000001".into(),
            playtime_revision: revision,
            origin_client_id: Some("7".into()),
            playtime: vec![PlaytimeEntry {
                owner_scope: String::new(),
                owner_steam_id64: String::new(),
                app_id,
                playtime_minutes: minutes,
                playtime_2weeks_minutes: 7,
                last_played_at: Some(1_800_000_000),
                observed_at: 1_800_000_001,
            }],
        }
    }

    #[test]
    fn last_played_response_replaces_existing_controlled_apps() {
        let body = PlayerGetLastPlayedTimesResponse {
            games: vec![
                PlayerLastPlayedGame {
                    app_id: Some(480),
                    playtime_forever: Some(12),
                    playtime_2weeks: Some(1),
                    last_playtime: Some(10),
                    ..Default::default()
                },
                PlayerLastPlayedGame {
                    app_id: Some(999),
                    playtime_forever: Some(99),
                    ..Default::default()
                },
            ],
        }
        .encode_to_vec();

        let rewritten = rewrite_response_with(&body, &config(), &view(180)).unwrap();
        let response = PlayerGetLastPlayedTimesResponse::decode(rewritten.as_slice()).unwrap();
        assert_eq!(response.games.len(), 2);
        assert_eq!(response.games[0].app_id, Some(480));
        assert_eq!(response.games[0].playtime_forever, Some(180));
        assert_eq!(response.games[0].playtime_2weeks, Some(7));
        assert_eq!(response.games[0].last_playtime, Some(1_800_000_000));
        assert_eq!(response.games[1].app_id, Some(999));
        assert_eq!(response.games[1].playtime_forever, Some(99));
    }

    #[test]
    fn last_played_response_appends_missing_controlled_apps_from_backend() {
        let body = PlayerGetLastPlayedTimesResponse {
            games: vec![PlayerLastPlayedGame {
                app_id: Some(999),
                playtime_forever: Some(99),
                ..Default::default()
            }],
        }
        .encode_to_vec();

        let rewritten = rewrite_response_with(&body, &config_with(&[480]), &view(180)).unwrap();
        let response = PlayerGetLastPlayedTimesResponse::decode(rewritten.as_slice()).unwrap();
        assert_eq!(response.games.len(), 2);
        assert_eq!(response.games[0].app_id, Some(999));
        assert_eq!(response.games[1].app_id, Some(480));
        assert_eq!(response.games[1].playtime_forever, Some(180));
    }

    #[test]
    fn last_played_notification_does_not_append_missing_controlled_apps() {
        let body = vapor_forge_steam_protocol::PlayerLastPlayedTimesNotification {
            games: vec![PlayerLastPlayedGame {
                app_id: Some(999),
                playtime_forever: Some(99),
                ..Default::default()
            }],
        }
        .encode_to_vec();

        assert!(rewrite_notification_with(&body, &config_with(&[480]), &view(180)).is_none());
    }

    #[test]
    fn owned_controlled_app_keeps_steam_last_played_entry() {
        let _guard = ACCOUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let app_id = AppId(482);
        vapor_forge_features::apps::record_actual_ownership(app_id, true);
        let body = PlayerGetLastPlayedTimesResponse {
            games: vec![PlayerLastPlayedGame {
                app_id: Some(app_id.0 as i32),
                playtime_forever: Some(12),
                playtime_2weeks: Some(1),
                last_playtime: Some(10),
                ..Default::default()
            }],
        }
        .encode_to_vec();

        assert!(rewrite_response_with(
            &body,
            &config_with(&[app_id.0]),
            &view_with(&[(app_id.0, 180)])
        )
        .is_none());
        vapor_forge_features::apps::reset_account_state();
    }

    #[test]
    fn last_played_overlay_removes_controlled_apps_the_backend_does_not_hold() {
        let body = PlayerGetLastPlayedTimesResponse {
            games: vec![
                PlayerLastPlayedGame {
                    app_id: Some(480),
                    playtime_forever: Some(12),
                    ..Default::default()
                },
                PlayerLastPlayedGame {
                    app_id: Some(999),
                    playtime_forever: Some(99),
                    ..Default::default()
                },
            ],
        }
        .encode_to_vec();

        let rewritten =
            rewrite_response_with(&body, &config(), &PlaytimeView::Known(HashMap::new())).unwrap();
        let response = PlayerGetLastPlayedTimesResponse::decode(rewritten.as_slice()).unwrap();
        assert_eq!(response.games.len(), 1);
        assert_eq!(response.games[0].app_id, Some(999));
    }

    #[test]
    fn cold_cache_leaves_steam_persisted_entries_untouched() {
        let body = PlayerGetLastPlayedTimesResponse {
            games: vec![PlayerLastPlayedGame {
                app_id: Some(480),
                playtime_forever: Some(12),
                ..Default::default()
            }],
        }
        .encode_to_vec();

        // A cold cache must not be read as "the backend holds nothing".
        assert!(rewrite_response_with(&body, &config(), &PlaytimeView::Cold).is_none());
        assert!(
            rewrite_response_with(&body, &config(), &PlaytimeView::Known(HashMap::new())).is_some(),
            "a backend that holds nothing must still drop the entry"
        );
    }

    #[test]
    fn cache_is_bound_to_runtime_fingerprint_generation_and_client() {
        let _guard = ACCOUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_account_state();
        let key = runtime_key("credential-a".into(), 76561198000000001, 2, 7);
        store_backend_playtime(
            key.clone(),
            state(240).playtime_revision,
            &state(240).playtime,
        );
        let cache = cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(cache.key.as_ref(), Some(&key));
        assert_eq!(cache.games.get(&480).unwrap().playtime_minutes, 240);
        assert_ne!(
            key,
            runtime_key("credential-b".into(), 76561198000000001, 2, 7)
        );
        assert_ne!(
            key,
            runtime_key("credential-a".into(), 76561198000000002, 2, 7)
        );
        assert_ne!(
            key,
            runtime_key("credential-a".into(), 76561198000000001, 3, 7)
        );
        assert_ne!(
            key,
            runtime_key("credential-a".into(), 76561198000000001, 2, 8)
        );
        drop(cache);
        reset_account_state();
    }

    #[test]
    fn stream_snapshot_builds_native_last_played_notification() {
        let _guard = ACCOUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_account_state();
        vapor_forge_features::apps::reset_account_state();
        let app_id = 246_813_579;
        let key = runtime_key("credential-stream".into(), 76561198000000001, 9, 7);
        let packet = apply_stream_snapshot(
            key,
            &stream_snapshot(app_id, 4, 321),
            &config_with(&[app_id]),
        )
        .unwrap();

        let (emsg, header, body) = vapor_forge_steam_protocol::unpack_raw(&packet).unwrap();
        assert_eq!(
            emsg,
            EMSG_SERVICE_METHOD_SEND_TO_CLIENT | K_MSG_HDR_PROTO_FLAG
        );
        let header = CMsgProtoBufHeader::decode(header).unwrap();
        assert_eq!(header.steamid, Some(76561198000000001));
        assert_eq!(
            header.target_job_name.as_deref(),
            Some(vapor_forge_features::playtime::LAST_PLAYED_TIMES_NOTIFICATION_JOB_NAME)
        );
        let body = PlayerLastPlayedTimesNotification::decode(body).unwrap();
        assert_eq!(body.games.len(), 1);
        assert_eq!(body.games[0].app_id, Some(app_id as i32));
        assert_eq!(body.games[0].playtime_forever, Some(321));
        assert_eq!(body.games[0].playtime_2weeks, Some(7));
        reset_account_state();
    }

    #[test]
    fn older_stream_revision_cannot_replace_newer_cache() {
        let _guard = ACCOUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_account_state();
        let app_id = 246_813_580;
        let key = runtime_key("credential-order".into(), 76561198000000001, 10, 8);
        assert!(apply_stream_snapshot(
            key.clone(),
            &stream_snapshot(app_id, 8, 500),
            &config_with(&[app_id]),
        )
        .is_some());
        assert!(apply_stream_snapshot(
            key,
            &stream_snapshot(app_id, 7, 100),
            &config_with(&[app_id]),
        )
        .is_none());
        let cache = cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(cache.revision, 8);
        assert_eq!(cache.games[&app_id].playtime_minutes, 500);
        drop(cache);
        reset_account_state();
    }
}
