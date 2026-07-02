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
use vapor_forge_config::{AppAvatarRule, AppAvatarSection, AppId};

// Static + Lua mappings (replaced on config reload).
static STATIC_MAP: Mutex<Option<HashMap<AppId, AppId>>> = Mutex::new(None);

// Runtime flag-driven mappings (set at LaunchApp, per-launch).
// Writes happen on Steam main thread; reads on IPC threads.
static RUNTIME_MAP: Mutex<Option<HashMap<AppId, AppId>>> = Mutex::new(None);

/// Populate the static map from the config section.
/// Replaces the entire map so hot-reload is clean.
pub fn load_static_map(section: &AppAvatarSection) {
    *STATIC_MAP.lock().unwrap() = Some(section.static_map.clone());
}

/// Insert a single avatar mapping (called from Lua setavatar and hot-reload merge).
pub fn set_avatar(app_id: AppId, avatar: AppId) {
    STATIC_MAP
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(app_id, avatar);
}

/// Resolve the avatar AppId for a given real AppId.
/// Returns None if no mapping is configured.
pub fn get_avatar(app_id: AppId) -> Option<AppId> {
    // 1. Runtime flag-driven map (per-launch).
    if let Some(map) = RUNTIME_MAP.lock().unwrap().as_ref() {
        if let Some(&avatar) = map.get(&app_id) {
            return Some(avatar);
        }
    }
    // 2. Static map (config + lua).
    let guard = STATIC_MAP.lock().unwrap();
    if let Some(map) = guard.as_ref() {
        if let Some(&avatar) = map.get(&app_id) {
            return Some(avatar);
        }
        // 3. Wildcard: key AppId(0) applies to every app.
        if let Some(&avatar) = map.get(&AppId(0)) {
            return Some(avatar);
        }
    }
    None
}

/// Rewrite CMsgClientGamesPlayed body: replace game_id for avatared apps.
/// Returns Some(new_body) if any game_id was changed, None otherwise.
pub fn rewrite_games_played(body_bytes: &[u8]) -> Option<Vec<u8>> {
    use prost::Message;
    let mut msg = vapor_forge_abi::CMsgClientGamesPlayed::decode(body_bytes).ok()?;
    let mut changed = false;
    for game in &mut msg.games_played {
        if let Some(gid) = game.game_id {
            let app_id = AppId(gid as u32);
            if let Some(avatar) = get_avatar(app_id) {
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
        if !flag_appears_in(launch_opts, &rule.flag) {
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

/// Word-boundary substring match for launch option flags.
///
/// A match is valid when the needle is surrounded by whitespace, quotes, or
/// string boundaries, preventing "-onlinefixfoo" from matching "-onlinefix".
fn flag_appears_in(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    let mut pos = 0;
    while pos + n.len() <= h.len() {
        if let Some(found) = haystack[pos..].find(needle) {
            let abs = pos + found;
            let before = if abs > 0 { h[abs - 1] } else { b' ' };
            let after_pos = abs + n.len();
            let after = if after_pos < h.len() { h[after_pos] } else { 0 };
            let sep = |b: u8| matches!(b, b' ' | b'\t' | b'"' | b'\'' | 0);
            if sep(before) && sep(after) {
                return true;
            }
            pos = abs + n.len();
        } else {
            break;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_word_boundary() {
        assert!(flag_appears_in("-onlinefix -other", "-onlinefix"));
        assert!(flag_appears_in("-onlinefix", "-onlinefix"));
        assert!(!flag_appears_in("-onlinefixfoo", "-onlinefix"));
        assert!(!flag_appears_in("foo-onlinefix", "-onlinefix"));
        assert!(flag_appears_in("\"-onlinefix\"", "-onlinefix"));
    }

    #[test]
    fn get_avatar_wildcard() {
        // Wildcard AppId(0) should match any app not explicitly listed.
        *STATIC_MAP.lock().unwrap() = Some({
            let mut m = HashMap::new();
            m.insert(AppId(0), AppId(480));
            m
        });
        assert_eq!(get_avatar(AppId(12345)), Some(AppId(480)));
        // Clean up for other tests.
        *STATIC_MAP.lock().unwrap() = None;
    }
}
