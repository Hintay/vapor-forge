//! Passive observation of Steam's authoritative last-played-time messages.
//!
//! Steam already requests these snapshots and pushes updates to the client.
//! This module only correlates responses and decodes notifications; it never
//! fabricates a request or modifies Steam's packet.

use std::collections::HashMap;
use std::sync::Mutex;

use prost::Message;
use vapor_forge_steam_protocol::{
    CMsgProtoBufHeader, PlayerGetLastPlayedTimesResponse, PlayerLastPlayedGame,
    PlayerLastPlayedTimesNotification,
};

pub const GET_LAST_PLAYED_TIMES_JOB_NAME: &str = "Player.ClientGetLastPlayedTimes#1";
pub const LAST_PLAYED_TIMES_NOTIFICATION_JOB_NAME: &str = "PlayerClient.NotifyLastPlayedTimes#1";
const MAX_PENDING_REQUESTS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaytimeSnapshot {
    pub steam_id64: u64,
    pub games: Vec<PlaytimeGame>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaytimeGame {
    pub app_id: u32,
    pub playtime_minutes: u32,
    pub playtime_2weeks_minutes: u32,
    pub last_played_at: Option<i64>,
}

static PENDING: Mutex<Option<HashMap<u64, u64>>> = Mutex::new(None);

pub fn observe_request(method: &str, header: &CMsgProtoBufHeader, fallback_steam_id64: u64) {
    if method != GET_LAST_PLAYED_TIMES_JOB_NAME {
        return;
    }
    let Some(job_id) = header.jobid_source.filter(|value| *value != 0) else {
        return;
    };
    let mut pending = PENDING.lock().unwrap();
    let pending = pending.get_or_insert_with(HashMap::new);
    if pending.len() >= MAX_PENDING_REQUESTS {
        pending.clear();
    }
    pending.insert(job_id, header.steamid.unwrap_or(fallback_steam_id64));
}

pub fn observe_response(
    header: &CMsgProtoBufHeader,
    body: &[u8],
    fallback_steam_id64: u64,
) -> Option<PlaytimeSnapshot> {
    let job_id = header.jobid_target?;
    let requested_by = PENDING.lock().ok()?.as_mut()?.remove(&job_id)?;
    let response = PlayerGetLastPlayedTimesResponse::decode(body).ok()?;
    snapshot(
        header
            .steamid
            .filter(|value| *value != 0)
            .or_else(|| (requested_by != 0).then_some(requested_by))
            .unwrap_or(fallback_steam_id64),
        response.games,
    )
}

pub fn observe_notification(
    method: &str,
    header: &CMsgProtoBufHeader,
    body: &[u8],
    fallback_steam_id64: u64,
) -> Option<PlaytimeSnapshot> {
    if method != LAST_PLAYED_TIMES_NOTIFICATION_JOB_NAME {
        return None;
    }
    let notification = PlayerLastPlayedTimesNotification::decode(body).ok()?;
    snapshot(
        header.steamid.unwrap_or(fallback_steam_id64),
        notification.games,
    )
}

fn snapshot(steam_id64: u64, games: Vec<PlayerLastPlayedGame>) -> Option<PlaytimeSnapshot> {
    if steam_id64 == 0 {
        return None;
    }
    let games = games.into_iter().filter_map(normalize_game).collect();
    Some(PlaytimeSnapshot { steam_id64, games })
}

fn normalize_game(game: PlayerLastPlayedGame) -> Option<PlaytimeGame> {
    let app_id = u32::try_from(game.app_id?)
        .ok()
        .filter(|value| *value != 0)?;
    let playtime_minutes = u32::try_from(game.playtime_forever?).ok()?;
    let playtime_2weeks_minutes = game
        .playtime_2weeks
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    Some(PlaytimeGame {
        app_id,
        playtime_minutes,
        playtime_2weeks_minutes,
        last_played_at: game
            .last_playtime
            .filter(|value| *value != 0)
            .map(i64::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn game(app_id: i32, forever: i32) -> PlayerLastPlayedGame {
        PlayerLastPlayedGame {
            app_id: Some(app_id),
            playtime_forever: Some(forever),
            playtime_2weeks: Some(12),
            last_playtime: Some(1_800_000_000),
            ..Default::default()
        }
    }

    #[test]
    fn correlates_native_response_without_modifying_it() {
        let job_id = 41_001;
        let request = CMsgProtoBufHeader {
            steamid: Some(76561198000000001),
            jobid_source: Some(job_id),
            ..Default::default()
        };
        observe_request(GET_LAST_PLAYED_TIMES_JOB_NAME, &request, 0);
        let response = PlayerGetLastPlayedTimesResponse {
            games: vec![game(620, 180), game(-1, 10)],
        };
        let snapshot = observe_response(
            &CMsgProtoBufHeader {
                jobid_target: Some(job_id),
                ..Default::default()
            },
            &response.encode_to_vec(),
            0,
        )
        .unwrap();
        assert_eq!(snapshot.steam_id64, 76561198000000001);
        assert_eq!(snapshot.games.len(), 1);
        assert_eq!(snapshot.games[0].app_id, 620);
        assert_eq!(snapshot.games[0].playtime_minutes, 180);
    }

    #[test]
    fn decodes_native_notification() {
        let notification = PlayerLastPlayedTimesNotification {
            games: vec![game(413150, 900)],
        };
        let snapshot = observe_notification(
            LAST_PLAYED_TIMES_NOTIFICATION_JOB_NAME,
            &CMsgProtoBufHeader {
                steamid: Some(76561198000000002),
                ..Default::default()
            },
            &notification.encode_to_vec(),
            0,
        )
        .unwrap();
        assert_eq!(snapshot.games[0].app_id, 413150);
        assert_eq!(snapshot.games[0].playtime_minutes, 900);
    }
}
