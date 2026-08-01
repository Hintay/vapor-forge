use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use vapor_forge_cloud_core::{
    AchievementSchema, AppStatsQuery, AppStatsResult, SteamAppSnapshot, SteamStateUploadResult,
    UploadIdentity,
};

use crate::{CumulusClient, CumulusError, CumulusSettings};

#[derive(Serialize)]
struct SchemaUploadRequest<'a> {
    app_id: u32,
    language: &'a str,
    schema_version: Option<&'a str>,
    content_base64: String,
}

#[derive(Serialize)]
struct AppStatsRequest<'a> {
    steam_id64: &'a str,
    app_id: u32,
    client_crc_stats: Option<u32>,
    schema_version: &'a str,
}

#[derive(Serialize)]
struct SteamStateUploadRequest<'a> {
    client_id: String,
    machine_name: &'a str,
    os_type: Option<i64>,
    device_type: Option<i64>,
    steam_id64: &'a str,
    persona_name: Option<&'a str>,
    apps: [SteamAppUpload<'a>; 1],
}

#[derive(Serialize)]
struct SteamAppUpload<'a> {
    app_id: u32,
    commit_id: &'a str,
    base_crc_stats: Option<u32>,
    dirty_stat_ids: &'a [u32],
    observed_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    playtime_minutes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    playtime_2weeks_minutes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_played_at: Option<i64>,
    achievements: Vec<AchievementUpload<'a>>,
    stats: &'a [vapor_forge_cloud_core::OfficialStatState],
}

#[derive(Serialize)]
struct AchievementUpload<'a> {
    key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    unlocked: bool,
    unlocked_at: Option<i64>,
}

#[derive(Deserialize)]
struct SchemaUploadResponse {
    accepted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaUploadOutcome {
    Uploaded,
    Disabled,
}

pub fn upload_schema(
    settings: &CumulusSettings,
    schema: &AchievementSchema,
) -> Result<SchemaUploadOutcome, CumulusError> {
    let response: SchemaUploadResponse = CumulusClient::new(settings, None).post_json_response(
        "/api/v1/device/achievement-schema",
        &SchemaUploadRequest {
            app_id: schema.app_id,
            language: &schema.language,
            schema_version: schema.schema_version.as_deref(),
            content_base64: STANDARD.encode(&schema.content),
        },
    )?;
    Ok(if response.accepted {
        SchemaUploadOutcome::Uploaded
    } else {
        SchemaUploadOutcome::Disabled
    })
}

pub fn upload_snapshot(
    settings: &CumulusSettings,
    identity: &UploadIdentity,
    snapshot: &SteamAppSnapshot,
) -> Result<SteamStateUploadResult, CumulusError> {
    let achievements = snapshot
        .achievements
        .iter()
        .map(|achievement| AchievementUpload {
            key: &achievement.key,
            name: None,
            unlocked: achievement.unlocked,
            unlocked_at: achievement.unlocked_at,
        })
        .collect();
    CumulusClient::new(settings, Some(identity.client_id)).post_json_response(
        "/api/v1/device/steam-state",
        &SteamStateUploadRequest {
            client_id: identity.client_id.to_string(),
            machine_name: &identity.machine_name,
            os_type: identity.os_type,
            device_type: identity.device_type,
            steam_id64: &identity.steam_id64,
            persona_name: identity.persona_name.as_deref(),
            apps: [SteamAppUpload {
                app_id: snapshot.app_id,
                commit_id: &snapshot.commit_id,
                base_crc_stats: snapshot.base_crc_stats,
                dirty_stat_ids: &snapshot.dirty_stat_ids,
                observed_at: snapshot.observed_at,
                playtime_minutes: None,
                playtime_2weeks_minutes: None,
                last_played_at: None,
                achievements,
                stats: &snapshot.stats,
            }],
        },
    )
}

pub fn pull_app_stats(
    settings: &CumulusSettings,
    client_id: u64,
    steam_id64: &str,
    query: &AppStatsQuery,
) -> Result<AppStatsResult, CumulusError> {
    CumulusClient::new(settings, Some(client_id)).post_json_response(
        "/api/v1/device/user-stats",
        &AppStatsRequest {
            steam_id64,
            app_id: query.app_id,
            client_crc_stats: query.client_crc_stats,
            schema_version: &query.schema_version,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::time::Duration;

    fn identity(client_id: u64) -> UploadIdentity {
        UploadIdentity {
            client_id,
            machine_name: "Deck".into(),
            os_type: Some(1),
            device_type: Some(2),
            steam_id64: "76561198000000091".into(),
            persona_name: None,
        }
    }

    fn settings(server_url: String) -> CumulusSettings {
        CumulusSettings {
            server_url,
            token: "device-secret".into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 2_000,
        }
    }

    fn one_request_server(response_body: &'static str) -> (String, mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                if let Some(index) = request.windows(4).position(|value| value == b"\r\n\r\n") {
                    break index + 4;
                }
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            while request.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
            }
            sender.send(String::from_utf8(request).unwrap()).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .unwrap();
        });
        (format!("http://{address}"), receiver)
    }

    #[test]
    fn uploads_schema_contract() {
        let (url, request) = one_request_server(r#"{"accepted":true}"#);
        let schema = AchievementSchema {
            owner_scope: "scope-a".into(),
            app_id: 620,
            language: "english".into(),
            schema_version: Some("abc123".into()),
            content: b"binary-schema".to_vec(),
        };
        assert_eq!(
            upload_schema(&settings(url), &schema).unwrap(),
            SchemaUploadOutcome::Uploaded
        );
        let request = request.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(request.starts_with("POST /api/v1/device/achievement-schema HTTP/1.1"));
        assert!(!request
            .to_ascii_lowercase()
            .contains("x-cumulus-steam-client-id:"));
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["app_id"], 620);
        assert_eq!(body["content_base64"], "YmluYXJ5LXNjaGVtYQ==");
    }

    #[test]
    fn uploads_snapshot_contract() {
        let (url, request) = one_request_server(
            r#"{"stats_apps":[{"app_id":620,"status":"stats_out_of_date","crc_stats":1234}]}"#,
        );
        let result = upload_snapshot(
            &settings(url),
            &identity(91),
            &SteamAppSnapshot {
                owner_scope: "scope-a".into(),
                owner_steam_id64: "76561198000000091".into(),
                commit_id: "commit-1".into(),
                app_id: 620,
                base_crc_stats: Some(7),
                dirty_stat_ids: vec![11, 12],
                achievements: vec![vapor_forge_cloud_core::OfficialAchievementState {
                    key: "WAKE_UP".into(),
                    unlocked: true,
                    unlocked_at: Some(1_800_000_000),
                }],
                stats: vec![vapor_forge_cloud_core::OfficialStatState {
                    key: "STAT_SCORE".into(),
                    value_type: "int".into(),
                    value: "42".into(),
                }],
                observed_at: 1_800_000_002,
            },
        )
        .unwrap();
        assert_eq!(result.stats_apps.len(), 1);
        assert_eq!(result.stats_apps[0].app_id, 620);
        let request = request.recv_timeout(Duration::from_secs(2)).unwrap();
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with("POST /api/v1/device/steam-state HTTP/1.1"));
        assert!(lower.contains("authorization: bearer device-secret"));
        assert!(lower.contains("x-cumulus-steam-client-id: 91"));
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["client_id"], "91");
        assert_eq!(body["steam_id64"], "76561198000000091");
        assert_eq!(body["apps"][0]["app_id"], 620);
        assert_eq!(body["apps"][0]["commit_id"], "commit-1");
        assert_eq!(body["apps"][0]["base_crc_stats"], 7);
        assert_eq!(
            body["apps"][0]["dirty_stat_ids"],
            serde_json::json!([11, 12])
        );
        assert!(body["apps"][0].get("playtime_minutes").is_none());
        assert!(body["apps"][0].get("playtime_2weeks_minutes").is_none());
        assert!(body["apps"][0].get("last_played_at").is_none());
        assert_eq!(body["apps"][0]["achievements"][0]["key"], "WAKE_UP");
        assert!(body["apps"][0]["achievements"][0].get("name").is_none());
        assert_eq!(body["apps"][0]["achievements"][0]["unlocked"], true);
        assert_eq!(body["apps"][0]["stats"][0]["key"], "STAT_SCORE");
    }
}
