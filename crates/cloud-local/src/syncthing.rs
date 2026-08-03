use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use vapor_forge_cloud_core::BackendError;

#[derive(Clone, Eq, PartialEq)]
pub struct SyncthingGcConfig {
    pub url: String,
    pub api_key: String,
    pub folder_id: String,
    pub timeout_ms: u64,
}

impl SyncthingGcConfig {
    pub(crate) fn ready_for_gc(&self, repository: &Path) -> Result<bool, BackendError> {
        let base_url = self.url.trim().trim_end_matches('/');
        if base_url.is_empty() || self.api_key.trim().is_empty() || self.folder_id.trim().is_empty()
        {
            return Err(error("incomplete Syncthing GC configuration"));
        }
        let uri = base_url
            .parse::<ureq::http::Uri>()
            .map_err(|_| error("invalid Syncthing URL"))?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().is_none()
            || uri.query().is_some()
        {
            return Err(error("invalid Syncthing URL"));
        }
        let host = uri.host().ok_or_else(|| error("invalid Syncthing URL"))?;
        if uri.scheme_str() == Some("http") && !is_loopback_host(host) {
            return Err(error("remote Syncthing URL must use HTTPS"));
        }

        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(self.timeout_ms.max(1))))
            .http_status_as_error(false)
            .build()
            .new_agent();
        let first = self.folder_status(&agent, base_url)?;
        if !first.ready() {
            return Ok(false);
        }
        if !self.config_in_sync(&agent, base_url)? {
            return Ok(false);
        }

        let Some(first_folder) = self.folder_snapshot(&agent, base_url, repository)? else {
            return Ok(false);
        };

        let Some(first_devices) =
            self.device_snapshot(&agent, base_url, &first_folder.device_ids)?
        else {
            return Ok(false);
        };
        let Some(second_devices) =
            self.device_snapshot(&agent, base_url, &first_folder.device_ids)?
        else {
            return Ok(false);
        };
        let Some(second_folder) = self.folder_snapshot(&agent, base_url, repository)? else {
            return Ok(false);
        };
        let second = self.folder_status(&agent, base_url)?;
        let config_in_sync = self.config_in_sync(&agent, base_url)?;
        Ok(second.ready()
            && config_in_sync
            && first.sequence == second.sequence
            && first_folder == second_folder
            && first_devices == second_devices)
    }

    fn config_in_sync(&self, agent: &ureq::Agent, base_url: &str) -> Result<bool, BackendError> {
        let state: ConfigSync =
            self.get_json(agent, format!("{base_url}/rest/system/config/insync"), &[])?;
        Ok(state.config_in_sync)
    }

    fn folder_snapshot(
        &self,
        agent: &ureq::Agent,
        base_url: &str,
        repository: &Path,
    ) -> Result<Option<FolderSnapshot>, BackendError> {
        let folders: Vec<FolderConfig> =
            self.get_json(agent, format!("{base_url}/rest/config/folders"), &[])?;
        let Some(folder) = folders
            .into_iter()
            .find(|folder| folder.id == self.folder_id.trim())
        else {
            return Err(error("Syncthing folder is not configured"));
        };
        if folder.paused {
            return Ok(None);
        }
        if folder.folder_type != "sendreceive" {
            return Err(error("Syncthing folder must use send-receive mode"));
        }
        if folder.ignore_delete {
            return Err(error("Syncthing folder must propagate deletions"));
        }
        let folder_root = Path::new(&folder.path)
            .canonicalize()
            .map_err(|_| error("Syncthing folder path is unavailable"))?;
        let repository = repository
            .canonicalize()
            .map_err(|_| error("local cloud path is unavailable"))?;
        if !repository.starts_with(&folder_root) {
            return Err(error(
                "Syncthing folder does not cover the local cloud path",
            ));
        }

        let ignores: IgnorePatterns = self.get_json(
            agent,
            format!("{base_url}/rest/db/ignores"),
            &[("folder", self.folder_id.trim())],
        )?;
        if ignores.has_effective_rules() {
            return Err(error("Syncthing folder must not ignore repository paths"));
        }

        let mut device_ids = BTreeSet::new();
        for device in folder.devices {
            let device_id = device.device_id.trim();
            if device_id.is_empty() || !device_ids.insert(device_id.to_owned()) {
                return Err(error("Syncthing folder has an invalid device"));
            }
        }
        Ok(Some(FolderSnapshot {
            folder_root,
            device_ids,
        }))
    }

    fn device_snapshot(
        &self,
        agent: &ureq::Agent,
        base_url: &str,
        device_ids: &BTreeSet<String>,
    ) -> Result<Option<BTreeMap<String, DeviceSnapshot>>, BackendError> {
        if device_ids.is_empty() {
            return Ok(Some(BTreeMap::new()));
        }
        let connections: Connections =
            self.get_json(agent, format!("{base_url}/rest/system/connections"), &[])?;
        let mut snapshot = BTreeMap::new();
        for device_id in device_ids {
            let Some(connection) = connections.connections.get(device_id) else {
                return Ok(None);
            };
            if !connection.connected || connection.paused || connection.started_at.trim().is_empty()
            {
                return Ok(None);
            }
            let completion: Completion = self.get_json(
                agent,
                format!("{base_url}/rest/db/completion"),
                &[
                    ("folder", self.folder_id.trim()),
                    ("device", device_id.as_str()),
                ],
            )?;
            if !completion.ready() {
                return Ok(None);
            }
            snapshot.insert(
                device_id.clone(),
                DeviceSnapshot {
                    connection_started_at: connection.started_at.clone(),
                    completion_sequence: completion.sequence,
                },
            );
        }
        Ok(Some(snapshot))
    }

    fn folder_status(
        &self,
        agent: &ureq::Agent,
        base_url: &str,
    ) -> Result<FolderStatus, BackendError> {
        self.get_json(
            agent,
            format!("{base_url}/rest/db/status"),
            &[("folder", self.folder_id.trim())],
        )
    }

    fn get_json<T: DeserializeOwned>(
        &self,
        agent: &ureq::Agent,
        url: String,
        query: &[(&str, &str)],
    ) -> Result<T, BackendError> {
        let mut request = agent.get(url).header("X-API-Key", self.api_key.trim());
        for (key, value) in query {
            request = request.query(*key, *value);
        }
        let mut response = request
            .call()
            .map_err(|error_value| error(format!("Syncthing request failed: {error_value}")))?;
        if !response.status().is_success() {
            return Err(error(format!(
                "Syncthing request returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|error_value| error(format!("invalid Syncthing response: {error_value}")))?;
        serde_json::from_str(&body)
            .map_err(|error_value| error(format!("invalid Syncthing response: {error_value}")))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderStatus {
    #[serde(default)]
    need_bytes: u64,
    #[serde(default)]
    need_deletes: u64,
    #[serde(default)]
    need_directories: u64,
    #[serde(default)]
    need_files: u64,
    #[serde(default)]
    need_symlinks: u64,
    #[serde(default)]
    need_total_items: u64,
    #[serde(default)]
    pull_errors: u64,
    #[serde(default)]
    receive_only_changed_bytes: u64,
    #[serde(default)]
    receive_only_changed_deletes: u64,
    #[serde(default)]
    receive_only_changed_directories: u64,
    #[serde(default)]
    receive_only_changed_files: u64,
    #[serde(default)]
    receive_only_changed_symlinks: u64,
    #[serde(default)]
    receive_only_total_items: u64,
    #[serde(default)]
    sequence: u64,
    state: String,
}

impl FolderStatus {
    fn ready(&self) -> bool {
        self.state == "idle"
            && self.need_bytes == 0
            && self.need_deletes == 0
            && self.need_directories == 0
            && self.need_files == 0
            && self.need_symlinks == 0
            && self.need_total_items == 0
            && self.pull_errors == 0
            && self.receive_only_changed_bytes == 0
            && self.receive_only_changed_deletes == 0
            && self.receive_only_changed_directories == 0
            && self.receive_only_changed_files == 0
            && self.receive_only_changed_symlinks == 0
            && self.receive_only_total_items == 0
    }
}

#[derive(Deserialize)]
struct FolderConfig {
    id: String,
    path: String,
    #[serde(default)]
    paused: bool,
    #[serde(default, rename = "type")]
    folder_type: String,
    #[serde(default, rename = "ignoreDelete")]
    ignore_delete: bool,
    #[serde(default)]
    devices: Vec<FolderDevice>,
}

#[derive(Deserialize)]
struct FolderDevice {
    #[serde(rename = "deviceID")]
    device_id: String,
}

#[derive(Eq, PartialEq)]
struct FolderSnapshot {
    folder_root: PathBuf,
    device_ids: BTreeSet<String>,
}

#[derive(Deserialize)]
struct IgnorePatterns {
    #[serde(default)]
    ignore: Vec<String>,
    #[serde(default)]
    expanded: Vec<String>,
}

impl IgnorePatterns {
    fn has_effective_rules(&self) -> bool {
        self.ignore.iter().chain(&self.expanded).any(|rule| {
            let rule = rule.trim();
            !rule.is_empty() && !rule.starts_with("//")
        })
    }
}

#[derive(Deserialize)]
struct Connections {
    #[serde(default)]
    connections: HashMap<String, Connection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigSync {
    #[serde(default)]
    config_in_sync: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Connection {
    #[serde(default)]
    connected: bool,
    #[serde(default)]
    paused: bool,
    #[serde(default)]
    started_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Completion {
    completion: f64,
    #[serde(default)]
    need_bytes: u64,
    #[serde(default)]
    need_items: u64,
    #[serde(default)]
    need_deletes: u64,
    #[serde(default)]
    remote_state: String,
    #[serde(default)]
    sequence: u64,
}

impl Completion {
    fn ready(&self) -> bool {
        self.completion >= 100.0
            && self.need_bytes == 0
            && self.need_items == 0
            && self.need_deletes == 0
            && self.remote_state == "valid"
    }
}

#[derive(Eq, PartialEq)]
struct DeviceSnapshot {
    connection_started_at: String,
    completion_sequence: u64,
}

fn error(message: impl Into<String>) -> BackendError {
    BackendError::new(message, true)
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    const IDLE: &str = r#"{"state":"idle","sequence":7}"#;
    const CONFIG_SYNC: &str = r#"{"configInSync":true}"#;
    const FOLDER: &str = r#"[{"id":"cloud","path":"/","paused":false,"type":"sendreceive","ignoreDelete":false,"devices":[{"deviceID":"DEVICE-A"}]}]"#;
    const IGNORES: &str = r#"{"ignore":[],"expanded":[]}"#;
    const CONNECTIONS: &str = r#"{"connections":{"DEVICE-A":{"connected":true,"paused":false,"startedAt":"2026-08-04T00:00:00Z"}}}"#;
    const COMPLETE: &str = r#"{"completion":100.0,"needBytes":0,"needItems":0,"needDeletes":0,"remoteState":"valid","sequence":12}"#;

    #[test]
    fn include_directives_are_effective_ignore_rules() {
        assert!(!IgnorePatterns {
            ignore: vec!["// comment".into(), String::new()],
            expanded: Vec::new(),
        }
        .has_effective_rules());
        assert!(IgnorePatterns {
            ignore: vec!["#include extra.stignore".into()],
            expanded: Vec::new(),
        }
        .has_effective_rules());
    }

    #[test]
    fn remote_plaintext_api_is_rejected_before_connecting() {
        assert!(settings("http://192.0.2.1:8384".into())
            .ready_for_gc(Path::new("/"))
            .is_err());
    }

    #[test]
    fn accepts_an_idle_folder_with_connected_complete_devices() {
        let (url, requests) = server(&[
            (200, IDLE),
            (200, CONFIG_SYNC),
            (200, FOLDER),
            (200, IGNORES),
            (200, CONNECTIONS),
            (200, COMPLETE),
            (200, CONNECTIONS),
            (200, COMPLETE),
            (200, FOLDER),
            (200, IGNORES),
            (200, IDLE),
            (200, CONFIG_SYNC),
        ]);
        let settings = settings(url);

        assert!(settings.ready_for_gc(Path::new("/")).unwrap());
        let requests = (0..12)
            .map(|_| requests.recv().unwrap())
            .collect::<Vec<_>>();
        assert!(requests[0].starts_with("GET /rest/db/status?folder=cloud HTTP/1.1"));
        assert!(requests[1].starts_with("GET /rest/system/config/insync HTTP/1.1"));
        assert!(requests[2].starts_with("GET /rest/config/folders HTTP/1.1"));
        assert!(requests[3].starts_with("GET /rest/db/ignores?folder=cloud HTTP/1.1"));
        assert!(requests[4].starts_with("GET /rest/system/connections HTTP/1.1"));
        assert!(requests[5].contains("folder=cloud&device=DEVICE-A"));
        assert!(requests
            .iter()
            .all(|request| request.to_ascii_lowercase().contains("x-api-key: secret")));
    }

    #[test]
    fn rejects_a_busy_folder_without_querying_devices() {
        let (url, requests) = server(&[(200, r#"{"state":"syncing","sequence":7}"#)]);

        assert!(!settings(url).ready_for_gc(Path::new("/")).unwrap());
        assert!(requests.recv().unwrap().starts_with("GET /rest/db/status"));
        assert!(requests.try_recv().is_err());
    }

    #[test]
    fn rejects_a_configuration_that_is_not_active() {
        let (url, _) = server(&[(200, IDLE), (200, r#"{"configInSync":false}"#)]);

        assert!(!settings(url).ready_for_gc(Path::new("/")).unwrap());
    }

    #[test]
    fn rejects_a_disconnected_device() {
        let disconnected = r#"{"connections":{"DEVICE-A":{"connected":false,"paused":false}}}"#;
        let (url, _) = server(&[
            (200, IDLE),
            (200, CONFIG_SYNC),
            (200, FOLDER),
            (200, IGNORES),
            (200, disconnected),
        ]);

        assert!(!settings(url).ready_for_gc(Path::new("/")).unwrap());
    }

    #[test]
    fn rejects_an_incomplete_device() {
        let incomplete = r#"{"completion":100.0,"needBytes":0,"needItems":0,"needDeletes":0,"remoteState":"unknown","sequence":12}"#;
        let (url, _) = server(&[
            (200, IDLE),
            (200, CONFIG_SYNC),
            (200, FOLDER),
            (200, IGNORES),
            (200, CONNECTIONS),
            (200, incomplete),
        ]);

        assert!(!settings(url).ready_for_gc(Path::new("/")).unwrap());
    }

    #[test]
    fn rejects_a_folder_that_changes_during_the_check() {
        let changed = r#"{"state":"idle","sequence":8}"#;
        let (url, _) = server(&[
            (200, IDLE),
            (200, CONFIG_SYNC),
            (200, FOLDER),
            (200, IGNORES),
            (200, CONNECTIONS),
            (200, COMPLETE),
            (200, CONNECTIONS),
            (200, COMPLETE),
            (200, FOLDER),
            (200, IGNORES),
            (200, changed),
            (200, CONFIG_SYNC),
        ]);

        assert!(!settings(url).ready_for_gc(Path::new("/")).unwrap());
    }

    #[test]
    fn rejects_a_folder_that_does_not_cover_the_repository() {
        let folder = r#"[{"id":"cloud","path":"/tmp","paused":false,"type":"sendreceive","ignoreDelete":false,"devices":[]}]"#;
        let (url, _) = server(&[(200, IDLE), (200, CONFIG_SYNC), (200, folder)]);

        assert!(settings(url).ready_for_gc(Path::new("/")).is_err());
    }

    #[test]
    fn rejects_a_folder_that_cannot_receive_or_propagate_deletions() {
        let send_only = r#"[{"id":"cloud","path":"/","paused":false,"type":"sendonly","ignoreDelete":false,"devices":[]}]"#;
        let (url, _) = server(&[(200, IDLE), (200, CONFIG_SYNC), (200, send_only)]);
        assert!(settings(url).ready_for_gc(Path::new("/")).is_err());

        let ignores_deletes = r#"[{"id":"cloud","path":"/","paused":false,"type":"sendreceive","ignoreDelete":true,"devices":[]}]"#;
        let (url, _) = server(&[(200, IDLE), (200, CONFIG_SYNC), (200, ignores_deletes)]);
        assert!(settings(url).ready_for_gc(Path::new("/")).is_err());
    }

    #[test]
    fn rejects_a_folder_with_ignore_rules() {
        let ignores = r#"{"ignore":["blobs/**"],"expanded":["blobs/**"]}"#;
        let (url, _) = server(&[
            (200, IDLE),
            (200, CONFIG_SYNC),
            (200, FOLDER),
            (200, ignores),
        ]);

        assert!(settings(url).ready_for_gc(Path::new("/")).is_err());
    }

    #[test]
    fn rejects_a_device_that_changes_during_the_check() {
        let changed = r#"{"completion":100.0,"needBytes":0,"needItems":0,"needDeletes":0,"remoteState":"valid","sequence":13}"#;
        let (url, _) = server(&[
            (200, IDLE),
            (200, CONFIG_SYNC),
            (200, FOLDER),
            (200, IGNORES),
            (200, CONNECTIONS),
            (200, COMPLETE),
            (200, CONNECTIONS),
            (200, changed),
            (200, FOLDER),
            (200, IGNORES),
            (200, IDLE),
            (200, CONFIG_SYNC),
        ]);

        assert!(!settings(url).ready_for_gc(Path::new("/")).unwrap());
    }

    #[test]
    fn rejects_a_reconnected_device() {
        let reconnected = r#"{"connections":{"DEVICE-A":{"connected":true,"paused":false,"startedAt":"2026-08-04T00:01:00Z"}}}"#;
        let (url, _) = server(&[
            (200, IDLE),
            (200, CONFIG_SYNC),
            (200, FOLDER),
            (200, IGNORES),
            (200, CONNECTIONS),
            (200, COMPLETE),
            (200, reconnected),
            (200, COMPLETE),
            (200, FOLDER),
            (200, IGNORES),
            (200, IDLE),
            (200, CONFIG_SYNC),
        ]);

        assert!(!settings(url).ready_for_gc(Path::new("/")).unwrap());
    }

    #[test]
    fn rejects_a_folder_contract_that_changes_during_the_check() {
        let changed = r#"[{"id":"cloud","path":"/","paused":false,"type":"sendreceive","ignoreDelete":false,"devices":[]}]"#;
        let (url, _) = server(&[
            (200, IDLE),
            (200, CONFIG_SYNC),
            (200, FOLDER),
            (200, IGNORES),
            (200, CONNECTIONS),
            (200, COMPLETE),
            (200, CONNECTIONS),
            (200, COMPLETE),
            (200, changed),
            (200, IGNORES),
            (200, IDLE),
            (200, CONFIG_SYNC),
        ]);

        assert!(!settings(url).ready_for_gc(Path::new("/")).unwrap());
    }

    #[test]
    fn fails_closed_when_the_api_rejects_the_request() {
        let (url, _) = server(&[(403, "{}")]);

        assert!(settings(url).ready_for_gc(Path::new("/")).is_err());
    }

    fn settings(url: String) -> SyncthingGcConfig {
        SyncthingGcConfig {
            url,
            api_key: "secret".into(),
            folder_id: "cloud".into(),
            timeout_ms: 1_000,
        }
    }

    fn server(responses: &[(u16, &'static str)]) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let responses = responses.to_vec();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let count = stream.read(&mut buffer).unwrap();
                    request.extend_from_slice(&buffer[..count]);
                    if count == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = sender.send(String::from_utf8(request).unwrap());
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        (format!("http://{address}"), receiver)
    }
}
