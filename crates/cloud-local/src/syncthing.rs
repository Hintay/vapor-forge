use crate::GcReport;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use vapor_forge_cloud_core::BackendError;

const MAX_SYNCTHING_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const EVENT_LONG_POLL_SECONDS: u64 = 60;
const EVENT_TRANSPORT_MARGIN: Duration = Duration::from_secs(5);
const GC_EVENT_TYPES: &str = "StateChanged,LocalIndexUpdated,ConfigSaved";

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct SyncthingGcConfig {
    pub url: String,
    pub api_key: String,
    pub folder_id: String,
    pub timeout_ms: u64,
}

pub(crate) struct SyncthingBoundary {
    sequence: u64,
    relative_app: String,
    deleted_files: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct SyncthingEventBatch {
    pub(crate) last_id: Option<u64>,
    pub(crate) wakes_gc: bool,
}

impl SyncthingGcConfig {
    pub fn validate_for_gc(&self) -> Result<(), BackendError> {
        self.endpoint().map(|_| ())
    }

    pub fn ensure_ready_for_app(
        &self,
        repository: &Path,
        relative_app: &str,
    ) -> Result<(), BackendError> {
        let endpoint = self.endpoint()?;
        let agent = self.agent();
        self.validate_folder(&agent, &endpoint, repository)?;
        let relative = repository
            .join(relative_app)
            .exists()
            .then_some(relative_app);
        self.scan(&agent, &endpoint, relative)?;
        let before = self.folder_status(&agent, &endpoint)?;
        if !before.ready() {
            return Err(retryable("Syncthing folder is not locally settled"));
        }
        let after = self.folder_status(&agent, &endpoint)?;
        if !after.ready() || after.sequence != before.sequence {
            return Err(retryable("Syncthing folder changed during readiness check"));
        }
        Ok(())
    }

    pub(crate) fn prepare_for_gc(
        &self,
        repository: &Path,
        report: &GcReport,
    ) -> Result<SyncthingBoundary, BackendError> {
        let endpoint = self.endpoint()?;
        let agent = self.agent();
        self.validate_folder(&agent, &endpoint, repository)?;
        self.scan(&agent, &endpoint, Some(&report.manifest_scope))?;
        let status = self.folder_status(&agent, &endpoint)?;
        if !status.ready() {
            return Err(retryable("Syncthing folder is not locally settled"));
        }
        for manifest_id in &report.retained_manifests {
            let directory = repository.join(&report.manifest_scope).join(manifest_id);
            self.verify_indexed_tree(&agent, &endpoint, repository, &directory)?;
        }
        let mut deleted_files = Vec::new();
        for manifest_id in &report.candidate_manifests {
            let directory = repository.join(&report.manifest_scope).join(manifest_id);
            deleted_files
                .extend(self.verify_indexed_tree(&agent, &endpoint, repository, &directory)?);
        }
        deleted_files.sort();
        deleted_files.dedup();
        Ok(SyncthingBoundary {
            sequence: status.sequence,
            relative_app: report.manifest_scope.clone(),
            deleted_files,
        })
    }

    pub(crate) fn publish_gc(&self, boundary: SyncthingBoundary) -> Result<(), BackendError> {
        let endpoint = self.endpoint()?;
        let agent = self.agent();
        self.scan(&agent, &endpoint, Some(&boundary.relative_app))?;
        let status = self.folder_status(&agent, &endpoint)?;
        if !status.ready() || status.sequence <= boundary.sequence {
            return Err(retryable(
                "Syncthing did not index the local cloud deletion",
            ));
        }
        for relative in &boundary.deleted_files {
            let indexed: FileRecord = self.get_json(
                &agent,
                format!("{endpoint}/rest/db/file"),
                &[("folder", self.folder_id.trim()), ("file", relative)],
            )?;
            if !indexed.local.is_some_and(|local| local.deleted) {
                return Err(retryable(
                    "Syncthing did not index the local cloud deletion",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn wait_for_gc_events(
        &self,
        since: Option<u64>,
    ) -> Result<SyncthingEventBatch, BackendError> {
        let endpoint = self.endpoint()?;
        let agent = self.event_agent();
        let mut request = agent
            .get(format!("{endpoint}/rest/events"))
            .header("X-API-Key", self.api_key.trim())
            .query("events", GC_EVENT_TYPES)
            .query("since", since.unwrap_or_default().to_string())
            .query("timeout", EVENT_LONG_POLL_SECONDS.to_string());
        if since.is_none() {
            request = request.query("limit", "1");
        }
        let events: Vec<SyncthingEvent> = self.read_json_response(request.call(), false)?;
        let last_id = events.iter().map(|event| event.id).max().or(since);
        if since.is_some_and(|since| events.iter().any(|event| event.id <= since)) {
            return Err(retryable("Syncthing event cursor did not advance"));
        }
        Ok(SyncthingEventBatch {
            last_id,
            wakes_gc: events
                .iter()
                .any(|event| event.wakes_gc(self.folder_id.trim())),
        })
    }

    fn endpoint(&self) -> Result<String, BackendError> {
        let endpoint = self.url.trim().trim_end_matches('/');
        if endpoint.is_empty() || self.api_key.trim().is_empty() || self.folder_id.trim().is_empty()
        {
            return Err(permanent("incomplete Syncthing configuration"));
        }
        let uri = endpoint
            .parse::<ureq::http::Uri>()
            .map_err(|_| permanent("invalid Syncthing URL"))?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().is_none()
            || uri.query().is_some()
        {
            return Err(permanent("invalid Syncthing URL"));
        }
        let host = uri
            .host()
            .ok_or_else(|| permanent("invalid Syncthing URL"))?;
        if uri.scheme_str() == Some("http") && !is_loopback_host(host) {
            return Err(permanent("remote Syncthing URL must use HTTPS"));
        }
        Ok(endpoint.to_owned())
    }

    fn agent(&self) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(self.timeout_ms.max(1))))
            .http_status_as_error(false)
            .build()
            .new_agent()
    }

    fn event_agent(&self) -> ureq::Agent {
        let long_poll = Duration::from_secs(EVENT_LONG_POLL_SECONDS) + EVENT_TRANSPORT_MARGIN;
        ureq::Agent::config_builder()
            .timeout_global(Some(
                Duration::from_millis(self.timeout_ms.max(1)).max(long_poll),
            ))
            .http_status_as_error(false)
            .build()
            .new_agent()
    }

    fn validate_folder(
        &self,
        agent: &ureq::Agent,
        endpoint: &str,
        repository: &Path,
    ) -> Result<(), BackendError> {
        let sync: ConfigSync =
            self.get_json(agent, format!("{endpoint}/rest/system/config/insync"), &[])?;
        if !sync.config_in_sync {
            return Err(retryable("Syncthing configuration is not active"));
        }
        let folders: Vec<FolderConfig> =
            self.get_json(agent, format!("{endpoint}/rest/config/folders"), &[])?;
        let folder = folders
            .into_iter()
            .find(|folder| folder.id == self.folder_id.trim())
            .ok_or_else(|| permanent("Syncthing folder is not configured"))?;
        if folder.paused {
            return Err(retryable("Syncthing folder is paused"));
        }
        if folder.folder_type != "sendreceive" {
            return Err(permanent("Syncthing folder must use send-receive mode"));
        }
        if folder.ignore_delete {
            return Err(permanent("Syncthing folder must propagate deletions"));
        }
        if !folder.versioning.kind.trim().is_empty() {
            return Err(permanent(
                "Syncthing file versioning must be disabled for local cloud",
            ));
        }
        let folder_root = Path::new(&folder.path)
            .canonicalize()
            .map_err(|_| permanent("Syncthing folder path is unavailable"))?;
        let repository = repository
            .canonicalize()
            .map_err(|_| permanent("local cloud path is unavailable"))?;
        if folder_root != repository {
            return Err(permanent(
                "Syncthing folder path must equal the local cloud repository",
            ));
        }
        let ignores: IgnorePatterns = self.get_json(
            agent,
            format!("{endpoint}/rest/db/ignores"),
            &[("folder", self.folder_id.trim())],
        )?;
        if ignores.has_effective_rules() {
            return Err(permanent(
                "Syncthing folder must not ignore local cloud paths",
            ));
        }
        Ok(())
    }

    fn verify_indexed_tree(
        &self,
        agent: &ureq::Agent,
        endpoint: &str,
        repository: &Path,
        directory: &Path,
    ) -> Result<Vec<String>, BackendError> {
        if !directory.is_dir() {
            return Err(retryable("local cloud manifest is unavailable"));
        }
        let mut pending = vec![directory.to_owned()];
        let mut indexed_files = Vec::new();
        let relative_directory = directory
            .strip_prefix(repository)
            .map_err(|_| permanent("local cloud manifest escaped the repository"))?;
        let relative_directory = path_to_syncthing(relative_directory)?;
        let indexed: FileRecord = self.get_json(
            agent,
            format!("{endpoint}/rest/db/file"),
            &[
                ("folder", self.folder_id.trim()),
                ("file", relative_directory.as_str()),
            ],
        )?;
        let local = indexed
            .local
            .ok_or_else(|| retryable("Syncthing local index is incomplete"))?;
        if local.deleted || local.invalid || local.ignored {
            return Err(retryable("Syncthing local index is incomplete"));
        }
        indexed_files.push(relative_directory);
        while let Some(current) = pending.pop() {
            for entry in std::fs::read_dir(&current).map_err(io_error)? {
                let entry = entry.map_err(io_error)?;
                let path = entry.path();
                let kind = entry.file_type().map_err(io_error)?;
                if kind.is_dir() {
                    pending.push(path);
                    continue;
                }
                if !kind.is_file() {
                    return Err(permanent(
                        "local cloud manifest contains an unsupported entry",
                    ));
                }
                let relative = path
                    .strip_prefix(repository)
                    .map_err(|_| permanent("local cloud manifest escaped the repository"))?;
                let relative = path_to_syncthing(relative)?;
                let indexed: FileRecord = self.get_json(
                    agent,
                    format!("{endpoint}/rest/db/file"),
                    &[
                        ("folder", self.folder_id.trim()),
                        ("file", relative.as_str()),
                    ],
                )?;
                let local = indexed
                    .local
                    .ok_or_else(|| retryable("Syncthing local index is incomplete"))?;
                let size = entry.metadata().map_err(io_error)?.len();
                if local.deleted || local.invalid || local.ignored || local.size != size {
                    return Err(retryable("Syncthing local index is incomplete"));
                }
                indexed_files.push(relative);
            }
        }
        Ok(indexed_files)
    }

    fn scan(
        &self,
        agent: &ureq::Agent,
        endpoint: &str,
        relative: Option<&str>,
    ) -> Result<(), BackendError> {
        let mut request = agent
            .post(format!("{endpoint}/rest/db/scan"))
            .header("X-API-Key", self.api_key.trim())
            .query("folder", self.folder_id.trim());
        if let Some(relative) = relative {
            request = request.query("sub", relative);
        }
        let response = request
            .send_empty()
            .map_err(|error| retryable(format!("Syncthing request failed: {error}")))?;
        if !response.status().is_success() {
            return Err(retryable(format!(
                "Syncthing request returned HTTP {}",
                response.status().as_u16()
            )));
        }
        Ok(())
    }

    fn folder_status(
        &self,
        agent: &ureq::Agent,
        endpoint: &str,
    ) -> Result<FolderStatus, BackendError> {
        self.get_json(
            agent,
            format!("{endpoint}/rest/db/status"),
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
        self.read_json_response(request.call(), true)
    }

    fn read_json_response<T: DeserializeOwned>(
        &self,
        response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
        client_errors_retryable: bool,
    ) -> Result<T, BackendError> {
        let mut response =
            response.map_err(|error| retryable(format!("Syncthing request failed: {error}")))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let retryable_status =
                client_errors_retryable || status == 408 || status == 429 || status >= 500;
            return Err(BackendError::new(
                format!("Syncthing request returned HTTP {status}"),
                retryable_status,
            ));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_SYNCTHING_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|error| retryable(format!("invalid Syncthing response: {error}")))?;
        serde_json::from_str(&body)
            .map_err(|error| retryable(format!("invalid Syncthing response: {error}")))
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
    versioning: VersioningConfig,
}

#[derive(Default, Deserialize)]
struct VersioningConfig {
    #[serde(default, rename = "type")]
    kind: String,
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
#[serde(rename_all = "camelCase")]
struct ConfigSync {
    #[serde(default)]
    config_in_sync: bool,
}

#[derive(Deserialize)]
struct FileRecord {
    local: Option<LocalFileRecord>,
}

#[derive(Deserialize)]
struct SyncthingEvent {
    id: u64,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    data: SyncthingEventData,
}

impl SyncthingEvent {
    fn wakes_gc(&self, folder_id: &str) -> bool {
        match self.kind.as_str() {
            "ConfigSaved" => true,
            "LocalIndexUpdated" => self.data.folder.as_deref() == Some(folder_id),
            "StateChanged" => {
                self.data.folder.as_deref() == Some(folder_id)
                    && self.data.to.as_deref() == Some("idle")
            }
            _ => false,
        }
    }
}

#[derive(Default, Deserialize)]
struct SyncthingEventData {
    folder: Option<String>,
    to: Option<String>,
}

#[derive(Deserialize)]
struct LocalFileRecord {
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    invalid: bool,
    #[serde(default)]
    ignored: bool,
    size: u64,
}

fn path_to_syncthing(path: &Path) -> Result<String, BackendError> {
    let mut result = String::new();
    for component in path.components() {
        let value = component
            .as_os_str()
            .to_str()
            .ok_or_else(|| permanent("local cloud path is not UTF-8"))?;
        if !result.is_empty() {
            result.push('/');
        }
        result.push_str(value);
    }
    Ok(result)
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn io_error(error: std::io::Error) -> BackendError {
    BackendError::new(format!("local cloud I/O failed: {error}"), true)
}

fn permanent(message: impl Into<String>) -> BackendError {
    BackendError::new(message, false)
}

fn retryable(message: impl Into<String>) -> BackendError {
    BackendError::new(message, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread::JoinHandle;

    const CONFIG_SYNC: &str = r#"{"configInSync":true}"#;
    const IGNORES: &str = r#"{"ignore":[],"expanded":[]}"#;
    const IDLE_SEQUENCE_7: &str = r#"{"state":"idle","sequence":7}"#;
    const IDLE_SEQUENCE_8: &str = r#"{"state":"idle","sequence":8}"#;
    const INDEXED_FOUR_BYTES: &str =
        r#"{"local":{"deleted":false,"invalid":false,"ignored":false,"size":4}}"#;
    const INDEXED_THREE_BYTES: &str =
        r#"{"local":{"deleted":false,"invalid":false,"ignored":false,"size":3}}"#;
    const INDEXED_DIRECTORY: &str =
        r#"{"local":{"deleted":false,"invalid":false,"ignored":false,"size":0}}"#;
    const INDEXED_DELETION: &str =
        r#"{"local":{"deleted":true,"invalid":false,"ignored":false,"size":0}}"#;

    #[test]
    fn remote_plaintext_api_is_rejected() {
        let settings = SyncthingGcConfig {
            url: "http://192.0.2.1:8384".into(),
            api_key: "secret".into(),
            folder_id: "cloud".into(),
            timeout_ms: 1_000,
        };
        assert!(settings.validate_for_gc().is_err());
    }

    #[test]
    fn loopback_api_configuration_is_valid() {
        let settings = SyncthingGcConfig {
            url: "http://127.0.0.1:8384".into(),
            api_key: "secret".into(),
            folder_id: "cloud".into(),
            timeout_ms: 1_000,
        };
        assert!(settings.validate_for_gc().is_ok());
    }

    #[test]
    fn readiness_scans_and_requires_a_settled_folder() {
        let repository = tempfile::tempdir().unwrap();
        let server = MockServer::start(vec![
            ok(CONFIG_SYNC),
            ok(&folder_config(repository.path())),
            ok(IGNORES),
            ok("{}"),
            ok(IDLE_SEQUENCE_7),
            ok(IDLE_SEQUENCE_7),
        ]);

        settings(&server.url)
            .ensure_ready_for_app(repository.path(), "76561198000000000/480")
            .unwrap();

        let requests = server.finish();
        assert_eq!(requests.len(), 6);
        assert_root_scan(&requests[3]);
        assert_request(&requests[4], "GET", "/rest/db/status?folder=cloud");
        assert_request(&requests[5], "GET", "/rest/db/status?folder=cloud");
    }

    #[test]
    fn file_versioning_is_rejected() {
        let repository = tempfile::tempdir().unwrap();
        let config = serde_json::json!([{
            "id": "cloud",
            "path": repository.path().canonicalize().unwrap(),
            "paused": false,
            "type": "sendreceive",
            "ignoreDelete": false,
            "versioning": { "type": "simple" }
        }])
        .to_string();
        let server = MockServer::start(vec![ok(CONFIG_SYNC), ok(&config), ok(IGNORES)]);

        let error = settings(&server.url)
            .ensure_ready_for_app(repository.path(), "76561198000000000/480")
            .unwrap_err();
        assert!(!error.is_retryable());

        let requests = server.finish();
        assert_eq!(requests.len(), 2);
    }

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
    fn event_subscription_uses_a_cursor_and_filters_the_target_folder() {
        let server = MockServer::start(vec![ok(r#"[
                {"id":42,"type":"LocalIndexUpdated","data":{"folder":"other"}},
                {"id":43,"type":"StateChanged","data":{"folder":"cloud","to":"idle"}}
            ]"#)]);

        let batch = settings(&server.url).wait_for_gc_events(Some(41)).unwrap();

        assert_eq!(batch.last_id, Some(43));
        assert!(batch.wakes_gc);
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert_query_request(&requests[0], "GET", "/rest/events");
        let line = request_line(&requests[0]);
        assert!(line.contains("since=41"));
        assert!(line.contains("timeout=60"));
        assert!(!line.contains("limit="));
        assert!(line.contains("StateChanged"));
        assert!(line.contains("LocalIndexUpdated"));
        assert!(line.contains("ConfigSaved"));
    }

    #[test]
    fn event_subscription_baselines_without_waking_for_another_folder() {
        let server = MockServer::start(vec![ok(
            r#"[{"id":7,"type":"StateChanged","data":{"folder":"other","to":"idle"}}]"#,
        )]);

        let batch = settings(&server.url).wait_for_gc_events(None).unwrap();

        assert_eq!(batch.last_id, Some(7));
        assert!(!batch.wakes_gc);
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        let line = request_line(&requests[0]);
        assert!(line.contains("since=0"));
        assert!(line.contains("limit=1"));
    }

    #[test]
    fn event_subscription_rejects_a_nonadvancing_cursor() {
        let server = MockServer::start(vec![ok(r#"[{"id":41,"type":"ConfigSaved","data":{}}]"#)]);

        let error = settings(&server.url)
            .wait_for_gc_events(Some(41))
            .unwrap_err();

        assert!(error.is_retryable());
        assert_eq!(server.finish().len(), 1);
    }

    #[test]
    fn event_subscription_treats_authentication_failure_as_permanent() {
        let server = MockServer::start(vec![(401, "{}".into())]);

        let error = settings(&server.url).wait_for_gc_events(None).unwrap_err();

        assert!(!error.is_retryable());
        assert_eq!(server.finish().len(), 1);
    }

    #[test]
    fn gc_boundary_scans_verifies_and_publishes_in_order() {
        let (repository, report) = repository_fixture();
        let server = MockServer::start(vec![
            ok(CONFIG_SYNC),
            ok(&folder_config(repository.path())),
            ok(IGNORES),
            ok("{}"),
            ok(IDLE_SEQUENCE_7),
            ok(INDEXED_DIRECTORY),
            ok(INDEXED_FOUR_BYTES),
            ok(INDEXED_DIRECTORY),
            ok(INDEXED_THREE_BYTES),
            ok("{}"),
            ok(IDLE_SEQUENCE_8),
            ok(INDEXED_DELETION),
            ok(INDEXED_DELETION),
        ]);
        let settings = settings(&server.url);

        let boundary = settings.prepare_for_gc(repository.path(), &report).unwrap();
        assert_eq!(boundary.sequence, 7);
        assert_eq!(boundary.relative_app, report.manifest_scope);
        settings.publish_gc(boundary).unwrap();

        let requests = server.finish();
        assert_eq!(requests.len(), 13);
        assert_request(&requests[0], "GET", "/rest/system/config/insync");
        assert_request(&requests[1], "GET", "/rest/config/folders");
        assert_request(&requests[2], "GET", "/rest/db/ignores?folder=cloud");
        assert_scan(&requests[3], &report.manifest_scope);
        assert_request(&requests[4], "GET", "/rest/db/status?folder=cloud");
        assert_file_lookup(&requests[5], &format!("{}/retained", report.manifest_scope));
        assert_file_lookup(
            &requests[6],
            &format!("{}/retained/manifest.json", report.manifest_scope),
        );
        assert_file_lookup(
            &requests[7],
            &format!("{}/candidate", report.manifest_scope),
        );
        assert_file_lookup(
            &requests[8],
            &format!("{}/candidate/files/save.bin", report.manifest_scope),
        );
        assert_scan(&requests[9], &report.manifest_scope);
        assert_request(&requests[10], "GET", "/rest/db/status?folder=cloud");
        assert_file_lookup(
            &requests[11],
            &format!("{}/candidate", report.manifest_scope),
        );
        assert_file_lookup(
            &requests[12],
            &format!("{}/candidate/files/save.bin", report.manifest_scope),
        );
        assert!(requests.iter().all(|request| request
            .to_ascii_lowercase()
            .contains("x-api-key: secret\r\n")));
    }

    #[test]
    fn prepare_fails_closed_before_indexing_an_unsettled_folder() {
        let (repository, report) = repository_fixture();
        let server = MockServer::start(vec![
            ok(CONFIG_SYNC),
            ok(&folder_config(repository.path())),
            ok(IGNORES),
            ok("{}"),
            ok(r#"{"state":"syncing","sequence":7,"needFiles":1}"#),
            ok(INDEXED_FOUR_BYTES),
        ]);

        let error = settings(&server.url)
            .prepare_for_gc(repository.path(), &report)
            .err()
            .unwrap();
        assert!(error.is_retryable());

        let requests = server.finish();
        assert_eq!(requests.len(), 5);
        assert!(requests
            .iter()
            .all(|request| !request.starts_with("GET /rest/db/file?")));
    }

    #[test]
    fn prepare_fails_closed_when_scan_is_rejected() {
        let (repository, report) = repository_fixture();
        let server = MockServer::start(vec![
            ok(CONFIG_SYNC),
            ok(&folder_config(repository.path())),
            ok(IGNORES),
            (500, "{}".into()),
            ok(IDLE_SEQUENCE_7),
        ]);

        let error = settings(&server.url)
            .prepare_for_gc(repository.path(), &report)
            .err()
            .unwrap();
        assert!(error.is_retryable());

        let requests = server.finish();
        assert_eq!(requests.len(), 4);
        assert_scan(&requests[3], &report.manifest_scope);
    }

    #[test]
    fn prepare_fails_closed_for_incomplete_index_records() {
        let cases = [
            (200, r#"{"local":null}"#),
            (
                200,
                r#"{"local":{"deleted":false,"invalid":false,"ignored":false,"size":5}}"#,
            ),
            (
                200,
                r#"{"local":{"deleted":true,"invalid":false,"ignored":false,"size":4}}"#,
            ),
            (500, "{}"),
            (200, "{"),
        ];

        for (status, index_record) in cases {
            let (repository, report) = repository_fixture();
            let server = MockServer::start(vec![
                ok(CONFIG_SYNC),
                ok(&folder_config(repository.path())),
                ok(IGNORES),
                ok("{}"),
                ok(IDLE_SEQUENCE_7),
                ok(INDEXED_DIRECTORY),
                (status, index_record.into()),
                ok(INDEXED_THREE_BYTES),
            ]);

            let error = settings(&server.url)
                .prepare_for_gc(repository.path(), &report)
                .err()
                .unwrap();
            assert!(error.is_retryable());

            let requests = server.finish();
            assert_eq!(requests.len(), 7);
            assert_file_lookup(
                &requests[6],
                &format!("{}/retained/manifest.json", report.manifest_scope),
            );
        }
    }

    #[test]
    fn publish_requires_a_settled_advanced_sequence() {
        for status in [
            IDLE_SEQUENCE_7,
            r#"{"state":"syncing","sequence":8}"#,
            r#"{"state":"idle","sequence":8,"needDeletes":1}"#,
        ] {
            let server = MockServer::start(vec![ok("{}"), ok(status)]);
            let boundary = SyncthingBoundary {
                sequence: 7,
                relative_app: "76561198000000000/480".into(),
                deleted_files: Vec::new(),
            };

            let error = settings(&server.url).publish_gc(boundary).err().unwrap();
            assert!(error.is_retryable());

            let requests = server.finish();
            assert_eq!(requests.len(), 2);
            assert_scan(&requests[0], "76561198000000000/480");
            assert_request(&requests[1], "GET", "/rest/db/status?folder=cloud");
        }
    }

    fn repository_fixture() -> (tempfile::TempDir, GcReport) {
        let repository = tempfile::tempdir().unwrap();
        let manifest_scope = "76561198000000000/480";
        let retained = repository.path().join(manifest_scope).join("retained");
        let candidate = repository
            .path()
            .join(manifest_scope)
            .join("candidate/files");
        std::fs::create_dir_all(&retained).unwrap();
        std::fs::create_dir_all(&candidate).unwrap();
        std::fs::write(retained.join("manifest.json"), b"head").unwrap();
        std::fs::write(candidate.join("save.bin"), b"xyz").unwrap();
        (
            repository,
            GcReport {
                app_id: 480,
                manifest_scope: manifest_scope.into(),
                retained_manifests: vec!["retained".into()],
                candidate_manifests: vec!["candidate".into()],
            },
        )
    }

    fn folder_config(repository: &Path) -> String {
        serde_json::json!([{
            "id": "cloud",
            "path": repository.canonicalize().unwrap(),
            "paused": false,
            "type": "sendreceive",
            "ignoreDelete": false,
        }])
        .to_string()
    }

    fn settings(url: &str) -> SyncthingGcConfig {
        SyncthingGcConfig {
            url: url.into(),
            api_key: "secret".into(),
            folder_id: "cloud".into(),
            timeout_ms: 1_000,
        }
    }

    fn ok(body: &str) -> (u16, String) {
        (200, body.into())
    }

    fn assert_request(request: &str, method: &str, target: &str) {
        assert!(
            request.starts_with(&format!("{method} {target} HTTP/1.1\r\n")),
            "unexpected request: {request}"
        );
    }

    fn assert_scan(request: &str, relative: &str) {
        assert_query_request(request, "POST", "/rest/db/scan");
        assert!(request_line(request).contains("folder=cloud"));
        assert_query_path(request, "sub", relative);
    }

    fn assert_root_scan(request: &str) {
        assert_query_request(request, "POST", "/rest/db/scan");
        assert!(request_line(request).contains("folder=cloud"));
        assert!(!request_line(request).contains("sub="));
    }

    fn assert_file_lookup(request: &str, relative: &str) {
        assert_query_request(request, "GET", "/rest/db/file");
        assert!(request_line(request).contains("folder=cloud"));
        assert_query_path(request, "file", relative);
    }

    fn assert_query_request(request: &str, method: &str, target: &str) {
        assert!(
            request.starts_with(&format!("{method} {target}?")),
            "unexpected request: {request}"
        );
    }

    fn assert_query_path(request: &str, key: &str, value: &str) {
        let encoded = value.replace('/', "%2F");
        let line = request_line(request);
        assert!(
            line.contains(&format!("{key}={encoded}")) || line.contains(&format!("{key}={value}")),
            "missing query value in request: {request}"
        );
    }

    fn request_line(request: &str) -> &str {
        request.lines().next().unwrap()
    }

    struct MockServer {
        url: String,
        requests: mpsc::Receiver<String>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl MockServer {
        fn start(responses: Vec<(u16, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let (sender, requests) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                for (status, body) in responses {
                    let mut stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                stream.set_nonblocking(false).unwrap();
                                break stream;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                if thread_stop.load(Ordering::Acquire) {
                                    return;
                                }
                                std::thread::yield_now();
                            }
                            Err(error) => panic!("mock Syncthing server failed: {error}"),
                        }
                    };
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 1024];
                    loop {
                        let count = stream.read(&mut buffer).unwrap();
                        request.extend_from_slice(&buffer[..count]);
                        if count == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    sender.send(String::from_utf8(request).unwrap()).unwrap();
                    write!(
                        stream,
                        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                }
            });
            Self {
                url: format!("http://{address}"),
                requests,
                stop,
                thread: Some(thread),
            }
        }

        fn finish(mut self) -> Vec<String> {
            self.stop.store(true, Ordering::Release);
            self.thread.take().unwrap().join().unwrap();
            self.requests.try_iter().collect()
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}
