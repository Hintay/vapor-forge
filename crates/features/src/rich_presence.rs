//! Rich Presence rewriting for AppAvatar.
//!
//! When AppAvatar maps a real (unowned) AppId to another AppId for networking,
//! Valve's server will not broadcast rich presence for the real AppId because
//! the account does not own it. Friends then see stale cached status instead
//! of what is actually being played.
//!
//! To fix this we:
//! 1. Capture outgoing `CMsgClientRichPresenceUpload` KVs per real AppId.
//! 2. Cache an incoming self `CMsgClientPersonaState` as an inject template.
//! 3. Track which real AppId is currently being played (via GamesPlayed).
//! 4. While playing an avatar'd app, patch incoming self PersonaState packets
//!    with the real AppId and KVs, and manufacture inject packets so friends
//!    receive an update even if the server never sends one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use tracing::{debug, info};
use vapor_forge_abi::{
    ECLIENTPERSONASTATEFLAG_RICH_PRESENCE, EMSG_CLIENT_PERSONA_STATE,
    EPERSONASTATEFLAG_HAS_RICH_PRESENCE, K_MSG_HDR_PROTO_FLAG,
};
use vapor_forge_config::AppId;

type RichPresenceKvs = HashMap<AppId, Vec<(String, String)>>;

// Per-AppId rich presence KVs, extracted from the binary KV1 payload of
// CMsgClientRichPresenceUpload.
static RP_KVS: Mutex<Option<RichPresenceKvs>> = Mutex::new(None);

// Cached self PersonaState template (raw header + body bytes) used as the
// basis for manufactured inject packets.
static SELF_CACHE: Mutex<Option<SelfPersonaCache>> = Mutex::new(None);

// AppId currently being played through an avatar mapping. Zero means none.
static TRACKED_APP: AtomicU32 = AtomicU32::new(0);

// Current local SteamID, refreshed from outgoing packet headers so an account
// switch inside the same Steam process cannot retain the previous identity.
static LOCAL_STEAMID: AtomicU64 = AtomicU64::new(0);

// Set whenever tracking changes or new rich presence KVs arrive, so try_inject
// fires a manufactured PersonaState exactly once per change instead of on
// every RecvPkt call.
static INJECT_PENDING: AtomicBool = AtomicBool::new(false);

struct SelfPersonaCache {
    header: Vec<u8>,
    body: Vec<u8>,
}

/// Record the current local SteamID observed on an outgoing packet.
pub fn set_local_steamid(steamid: u64) {
    if steamid != 0 {
        LOCAL_STEAMID.store(steamid, Ordering::Release);
    }
}

pub fn local_steamid() -> u64 {
    LOCAL_STEAMID.load(Ordering::Acquire)
}

pub fn tracked_app() -> AppId {
    AppId(TRACKED_APP.load(Ordering::Acquire))
}

/// Called when CMsgClientGamesPlayed is sent. `app_ids` is the list of
/// game_id values from the outgoing message (already the *real* AppIds,
/// before AppAvatar rewriting); `is_avatared` reports whether AppAvatar has
/// a mapping configured for a given AppId.
pub fn on_games_played_update(app_ids: &[AppId], is_avatared: impl Fn(AppId) -> bool) {
    let topmost = app_ids.first().copied().unwrap_or(AppId(0));
    let new_tracked = if topmost.0 != 0 && is_avatared(topmost) {
        topmost.0
    } else {
        0
    };
    let old_tracked = TRACKED_APP.swap(new_tracked, Ordering::AcqRel);
    if new_tracked != 0 && new_tracked != old_tracked {
        INJECT_PENDING.store(true, Ordering::Release);
    }
}

/// Extract KVs from an outgoing CMsgClientRichPresenceUpload's binary KV1 payload
/// and cache them against the currently tracked AppId.
pub fn on_rich_presence_upload(kv_data: &[u8]) {
    let app = tracked_app();
    if app.0 == 0 {
        return;
    }

    let kvs = parse_binary_kv1(kv_data);
    debug!(
        app = app.0,
        pairs = kvs.len(),
        "rich_presence: captured KVs"
    );
    RP_KVS
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(app, kvs);
    INJECT_PENDING.store(true, Ordering::Release);
}

/// Cache a PersonaState packet (raw header/body bytes) as the inject template,
/// but only if it actually carries an entry for our own SteamID. PersonaState
/// broadcasts often describe other friends only, and those would make a poor
/// template since `build_inject_packet` needs to find our own entry in it.
/// If the local SteamID is not known yet, cache unconditionally as a fallback.
pub fn cache_self_persona(header: &[u8], body: &[u8]) {
    use prost::Message;
    let steamid = local_steamid();
    if steamid != 0 {
        let has_self = vapor_forge_abi::ClientPersonaState::decode(body)
            .map(|msg| msg.friends.iter().any(|f| f.friendid == Some(steamid)))
            .unwrap_or(false);
        if !has_self {
            return;
        }
    }

    *SELF_CACHE.lock().unwrap() = Some(SelfPersonaCache {
        header: header.to_vec(),
        body: body.to_vec(),
    });
}

/// Get cached rich presence KVs for an AppId, if any were captured.
pub fn get_kvs(app_id: AppId) -> Vec<(String, String)> {
    RP_KVS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&app_id))
        .cloned()
        .unwrap_or_default()
}

/// Peek the pending-inject flag without clearing it. Safe to call from a
/// cheap early-return gate.
pub fn has_inject_pending() -> bool {
    INJECT_PENDING.load(Ordering::Acquire)
}

/// Take the pending-inject flag if set, clearing it. Used to inject a
/// manufactured PersonaState exactly once per tracking/KV change.
pub fn take_inject_pending() -> bool {
    INJECT_PENDING.swap(false, Ordering::AcqRel)
}

/// Re-arm the pending-inject flag. Used when an inject attempt could not
/// complete (e.g. no self PersonaState cached yet) so it is retried later.
pub fn mark_inject_pending() {
    INJECT_PENDING.store(true, Ordering::Release);
}

/// Build a manufactured PersonaState packet (full raw bytes: header + body)
/// for the given AppId, based on the cached self PersonaState template.
pub fn build_inject_packet(app_id: AppId) -> Option<Vec<u8>> {
    use prost::Message;
    let cache = SELF_CACHE.lock().unwrap();
    let cache = cache.as_ref()?;
    let steamid = local_steamid();
    if steamid == 0 {
        return None;
    }

    let mut msg = vapor_forge_abi::ClientPersonaState::decode(cache.body.as_slice()).ok()?;
    let entry = msg
        .friends
        .iter_mut()
        .find(|f| f.friendid == Some(steamid))?;

    apply_game_fields(entry, app_id);
    set_rich_presence_flag(&mut msg);

    let new_body = msg.encode_to_vec();
    let emsg_raw = EMSG_CLIENT_PERSONA_STATE | K_MSG_HDR_PROTO_FLAG;
    Some(vapor_forge_abi::assemble_raw(
        emsg_raw,
        &cache.header,
        &new_body,
    ))
}

/// Patch a live incoming PersonaState body if we are currently tracking an
/// avatar'd app. Returns `Some(new_body)` if the self entry was patched.
pub fn patch_persona_state(body_bytes: &[u8]) -> Option<Vec<u8>> {
    use prost::Message;
    let app = tracked_app();
    if app.0 == 0 {
        return None;
    }
    let steamid = local_steamid();
    if steamid == 0 {
        return None;
    }

    let mut msg = vapor_forge_abi::ClientPersonaState::decode(body_bytes).ok()?;
    let entry = msg
        .friends
        .iter_mut()
        .find(|f| f.friendid == Some(steamid))?;

    apply_game_fields(entry, app);
    set_rich_presence_flag(&mut msg);

    info!(app = app.0, "rich_presence: patched live PersonaState");
    Some(msg.encode_to_vec())
}

fn apply_game_fields(entry: &mut vapor_forge_abi::PersonaStateFriend, app_id: AppId) {
    entry.game_played_app_id = Some(app_id.0);
    entry.gameid = Some(app_id.0 as u64);
    entry.rich_presence.clear();
    let kvs = get_kvs(app_id);
    let has_kvs = !kvs.is_empty();
    for (k, v) in kvs {
        entry.rich_presence.push(vapor_forge_abi::PersonaStateKV {
            key: Some(k),
            value: Some(v),
        });
    }

    let flags = entry.persona_state_flags.unwrap_or(0);
    entry.persona_state_flags = Some(if has_kvs {
        flags | EPERSONASTATEFLAG_HAS_RICH_PRESENCE
    } else {
        flags & !EPERSONASTATEFLAG_HAS_RICH_PRESENCE
    });
}

/// Mark the top-level status_flags as carrying rich presence field data.
fn set_rich_presence_flag(msg: &mut vapor_forge_abi::ClientPersonaState) {
    let flags = msg.status_flags.unwrap_or(0);
    msg.status_flags = Some(flags | ECLIENTPERSONASTATEFLAG_RICH_PRESENCE);
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BinaryKv1Type {
    Section = 0x00,
    String = 0x01,
    End = 0x08,
}

impl BinaryKv1Type {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Section),
            0x01 => Some(Self::String),
            0x08 => Some(Self::End),
            _ => None,
        }
    }
}

/// Parse Steam's binary KV1 format. Only top-level string pairs are collected;
/// nested structs are skipped over by depth tracking rather than being recursed
/// into, since rich presence KVs are always a flat list under one root struct.
fn parse_binary_kv1(data: &[u8]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut pos = 0;
    let mut depth = 0;

    while pos < data.len() {
        let typ = BinaryKv1Type::from_byte(data[pos]);
        pos += 1;
        match typ {
            Some(BinaryKv1Type::End) => {
                if depth > 0 {
                    depth -= 1;
                } else {
                    break;
                }
            }
            Some(BinaryKv1Type::Section) => {
                let _ = read_cstr(data, &mut pos);
                depth += 1;
            }
            Some(BinaryKv1Type::String) => {
                let key = read_cstr(data, &mut pos);
                let value = read_cstr(data, &mut pos);
                result.push((key, value));
            }
            None => break,
        }
    }
    result
}

fn read_cstr(data: &[u8], pos: &mut usize) -> String {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 {
        *pos += 1;
    }
    let s = std::str::from_utf8(&data[start..*pos])
        .unwrap_or("")
        .to_owned();
    if *pos < data.len() {
        *pos += 1; // skip NUL terminator
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kv1_flat_pairs() {
        // struct root, two string pairs, end.
        let mut data = vec![BinaryKv1Type::Section as u8];
        data.extend_from_slice(b"root\0");
        data.push(BinaryKv1Type::String as u8);
        data.extend_from_slice(b"status\0");
        data.extend_from_slice(b"In Menu\0");
        data.push(BinaryKv1Type::String as u8);
        data.extend_from_slice(b"steam_display\0");
        data.extend_from_slice(b"#Status\0");
        data.push(BinaryKv1Type::End as u8);
        data.push(BinaryKv1Type::End as u8);

        let kvs = parse_binary_kv1(&data);
        assert_eq!(
            kvs,
            vec![
                ("status".to_owned(), "In Menu".to_owned()),
                ("steam_display".to_owned(), "#Status".to_owned()),
            ]
        );
    }

    #[test]
    fn apply_game_fields_sets_flag_and_kvs() {
        RP_KVS.lock().unwrap().replace({
            let mut m = HashMap::new();
            m.insert(
                AppId(480),
                vec![("status".to_owned(), "Playing".to_owned())],
            );
            m
        });

        let mut entry = vapor_forge_abi::PersonaStateFriend::default();
        apply_game_fields(&mut entry, AppId(480));

        assert_eq!(entry.game_played_app_id, Some(480));
        assert_eq!(entry.gameid, Some(480));
        assert_eq!(entry.rich_presence.len(), 1);
        assert_eq!(
            entry.persona_state_flags.unwrap() & EPERSONASTATEFLAG_HAS_RICH_PRESENCE,
            EPERSONASTATEFLAG_HAS_RICH_PRESENCE
        );

        *RP_KVS.lock().unwrap() = None;
    }

    #[test]
    fn tracked_app_updates_on_avatared_topmost() {
        on_games_played_update(&[AppId(480)], |id| id == AppId(480));
        assert_eq!(tracked_app(), AppId(480));
        assert!(take_inject_pending());
        assert!(!take_inject_pending());

        on_games_played_update(&[], |_| false);
        assert_eq!(tracked_app(), AppId(0));
    }
}
