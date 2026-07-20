use serde::Serialize;
use vapor_forge_cloud_core::PlaytimeEntry;

use crate::{CumulusClient, CumulusError, CumulusSettings};

#[derive(Serialize)]
struct UploadRequest<'a> {
    steam_id64: &'a str,
    apps: &'a [PlaytimeEntry],
}

pub fn upload(
    settings: &CumulusSettings,
    client_id: u64,
    steam_id64: &str,
    entries: &[PlaytimeEntry],
) -> Result<(), CumulusError> {
    if entries.is_empty() {
        return Ok(());
    }
    CumulusClient::new(settings, Some(client_id)).post_json_unit(
        "/api/v1/device/playtime",
        &UploadRequest {
            steam_id64,
            apps: entries,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn uploads_playtime_contract() {
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
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });

        let settings = CumulusSettings {
            server_url: format!("http://{address}"),
            token: "device-secret".into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 2_000,
        };
        let entry = PlaytimeEntry {
            owner_scope: "scope-a".into(),
            owner_steam_id64: "76561198000000091".into(),
            app_id: 620,
            playtime_minutes: 120,
            playtime_2weeks_minutes: 20,
            last_played_at: Some(1_800_000_000),
            observed_at: 1_800_000_002,
        };
        upload(
            &settings,
            91,
            "76561198000000091",
            std::slice::from_ref(&entry),
        )
        .unwrap();

        let request = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(request.starts_with("POST /api/v1/device/playtime HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("x-cumulus-steam-client-id: 91"));
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["steam_id64"], "76561198000000091");
        assert_eq!(body["apps"][0]["app_id"], 620);
        assert!(body["apps"][0].get("owner_scope").is_none());
    }
}
