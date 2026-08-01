//! AppAvatar: map a real AppId to another for networking so Steam's multiplayer
//! sees the avatar AppId in CMsgClientGamesPlayed.
//!
//! Priority order for lookups:
//!   1. Runtime map (flag-driven, set at LaunchApp time)
//!   2. Static map  (config + lua setavatar)
//!   3. Wildcard    (static map key 0)
//!
//! The unsafe CConfigStore vtable call lives in the hooks crate, not here.
//! on_launch_app receives the already-read launch options string.

use std::collections::HashMap;
use std::sync::Mutex;

use tracing::{debug, info};
use vapor_forge_config::{AppAvatarRule, AppId};
use vapor_forge_steam_protocol::app_id_from_game_id;

// Runtime flag-driven mappings (set at LaunchApp, per-launch).
// Writes happen on Steam main thread; reads on IPC threads.
static RUNTIME_MAP: Mutex<Option<HashMap<AppId, AppId>>> = Mutex::new(None);

/// Resolve the avatar AppId for a given real AppId.
/// Returns None if no mapping is configured.
pub fn get_avatar(app_id: AppId, static_map: &HashMap<AppId, AppId>) -> Option<AppId> {
    // 1. Runtime flag-driven map (per-launch).
    if let Some(map) = RUNTIME_MAP.lock().unwrap().as_ref() {
        if let Some(&avatar) = map.get(&app_id) {
            return Some(avatar);
        }
    }
    // 2. Static map (config + lua).
    if let Some(&avatar) = static_map.get(&app_id) {
        return Some(avatar);
    }
    // 3. Wildcard: key AppId(0) applies to every app.
    if let Some(&avatar) = static_map.get(&AppId(0)) {
        return Some(avatar);
    }
    None
}

/// Rewrite CMsgClientGamesPlayed body: replace game_id for avatared apps.
/// Returns Some(new_body) if any game_id was changed, None otherwise.
pub fn rewrite_games_played(
    body_bytes: &[u8],
    static_map: &HashMap<AppId, AppId>,
) -> Option<Vec<u8>> {
    use prost::Message;
    let mut msg = vapor_forge_steam_protocol::CMsgClientGamesPlayed::decode(body_bytes).ok()?;
    let mut changed = false;
    for game in &mut msg.games_played {
        if let Some(gid) = game.game_id {
            let Some(app_id) = app_id_from_game_id(gid).map(AppId) else {
                continue;
            };
            if let Some(avatar) = get_avatar(app_id, static_map) {
                game.game_id = Some(avatar.0 as u64);
                changed = true;
                debug!(
                    real = app_id.0,
                    avatar = avatar.0,
                    "app-avatar: game_id rewritten"
                );
            }
        }
    }
    if changed {
        Some(msg.encode_to_vec())
    } else {
        None
    }
}

/// Called from the LaunchApp hook (hooks crate) after reading launch options.
///
/// Evaluates flag rules and updates the runtime map for this app.
/// The CConfigStore read is done in the hooks layer (unsafe territory);
/// launch_opts is passed in as a plain string.
pub fn on_launch_app(app_id: AppId, rules: &[AppAvatarRule], launch_opts: &str) {
    // Clear any previous runtime mapping for this app before re-evaluating.
    if let Some(map) = RUNTIME_MAP.lock().unwrap().as_mut() {
        map.remove(&app_id);
    }

    if rules.is_empty() {
        return;
    }

    let any_applicable = rules.iter().any(|r| {
        if !r.apps.is_empty() && !r.apps.contains(&app_id) {
            return false;
        }
        if r.exclude.contains(&app_id) {
            return false;
        }
        !r.flag.is_empty()
    });
    if !any_applicable {
        return;
    }

    // launch_opts may be empty if CConfigStore offset was not resolved.
    if launch_opts.is_empty() {
        return;
    }

    for rule in rules {
        if rule.flag.is_empty() {
            continue;
        }
        if !rule.apps.is_empty() && !rule.apps.contains(&app_id) {
            continue;
        }
        if rule.exclude.contains(&app_id) {
            continue;
        }
        if !crate::launch_options::flag_appears_in(launch_opts, &rule.flag) {
            continue;
        }

        RUNTIME_MAP
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(app_id, rule.avatar);
        info!(
            app = app_id.0,
            avatar = rule.avatar.0,
            flag = %rule.flag,
            "app-avatar: flag rule matched"
        );
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use vapor_forge_steam_protocol::{CMsgClientGamesPlayed, GamePlayed};

    #[test]
    fn get_avatar_wildcard() {
        // Wildcard AppId(0) should match any app not explicitly listed.
        let map = HashMap::from([(AppId(0), AppId(480))]);
        assert_eq!(get_avatar(AppId(12345), &map), Some(AppId(480)));
    }

    #[test]
    fn rewrite_games_played_extracts_app_id_from_cgameid() {
        let source = CMsgClientGamesPlayed {
            games_played: vec![GamePlayed {
                game_id: Some((2_u64 << 24) | 736_260),
                ..Default::default()
            }],
            ..Default::default()
        };
        let map = HashMap::from([(AppId(736_260), AppId(480))]);

        let rewritten = rewrite_games_played(&source.encode_to_vec(), &map).unwrap();
        let decoded = CMsgClientGamesPlayed::decode(rewritten.as_slice()).unwrap();

        assert_eq!(decoded.games_played[0].game_id, Some(480));
    }
}
