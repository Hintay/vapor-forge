use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use vapor_forge_cloud_core::{AchievementEvent, AchievementSchema, UploadIdentity};

use crate::{CumulusClient, CumulusError, CumulusSettings};

#[derive(Serialize)]
struct UploadRequest<'a> {
    client_id: &'a str,
    machine_name: &'a str,
    os_type: Option<i64>,
    device_type: Option<i64>,
    steam_id64: &'a str,
    persona_name: Option<&'a str>,
    events: &'a [AchievementEvent],
}

#[derive(Serialize)]
struct SchemaUploadRequest<'a> {
    app_id: u32,
    language: &'a str,
    schema_version: Option<&'a str>,
    content_base64: String,
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

pub fn upload_events(
    settings: &CumulusSettings,
    identity: &UploadIdentity,
    events: &[AchievementEvent],
) -> Result<(), CumulusError> {
    if events.is_empty() {
        return Ok(());
    }
    let client_id = identity.client_id.to_string();
    CumulusClient::new(settings, Some(identity.client_id)).post_json_unit(
        "/api/v1/device/achievement-events",
        &UploadRequest {
            client_id: &client_id,
            machine_name: &identity.machine_name,
            os_type: identity.os_type,
            device_type: identity.device_type,
            steam_id64: &identity.steam_id64,
            persona_name: identity.persona_name.as_deref(),
            events,
        },
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::time::Duration;

    fn event() -> AchievementEvent {
        AchievementEvent {
            owner_scope: "scope-a".into(),
            owner_steam_id64: "76561198000000091".into(),
            event_id: "11111111-1111-4111-8111-111111111111".into(),
            app_id: 620,
            achievement_key: "WAKE_UP".into(),
            kind: "unlock".into(),
            progress_current: None,
            progress_max: None,
            observed_at: 1_800_000_002,
            unlocked_at: Some(1_800_000_000),
        }
    }

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
    fn uploads_event_contract() {
        let (url, request) = one_request_server("{}");
        let mut clear = event();
        clear.event_id = "22222222-2222-4222-8222-222222222222".into();
        clear.kind = "clear".into();
        clear.observed_at = 1_800_000_003;
        clear.unlocked_at = None;
        upload_events(&settings(url), &identity(91), &[event(), clear]).unwrap();
        let request = request.recv_timeout(Duration::from_secs(2)).unwrap();
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with("POST /api/v1/device/achievement-events HTTP/1.1"));
        assert!(lower.contains("authorization: bearer device-secret"));
        assert!(lower.contains("x-cumulus-steam-client-id: 91"));
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["client_id"], "91");
        assert_eq!(body["events"][0]["kind"], "unlock");
        assert_eq!(body["events"][1]["kind"], "clear");
        assert!(body["events"][1].get("unlocked_at").is_some());
        assert!(body["events"][1]["unlocked_at"].is_null());
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
}
