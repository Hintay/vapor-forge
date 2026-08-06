use crate::GcReport;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use vapor_forge_cloud_core::BackendError;

#[derive(Clone, Eq, PartialEq)]
pub struct SyncthingGcConfig {
    pub url: String,
    pub api_key: String,
    pub folder_id: String,
    pub timeout_ms: u64,
}

pub(crate) struct SyncthingBoundary {
    sequence: u64,
    relative_app: String,
}

impl SyncthingGcConfig {
    pub fn validate_for_gc(&self) -> Result<(), BackendError> {
        self.endpoint().map(|_| ())
    }

    pub(crate) fn prepare_for_gc(
        &self,
        repository: &Path,
        report: &GcReport,
    ) -> Result<SyncthingBoundary, BackendError> {
        let endpoint = self.endpoint()?;
        let agent = self.agent();
        self.validate_folder(&agent, &endpoint, repository)?;
        self.scan(&agent, &endpoint, &report.manifest_scope)?;
        let status = self.folder_status(&agent, &endpoint)?;
        if !status.ready() {
            return Err(retryable("Syncthing folder is not locally settled"));
        }
        for manifest_id in report
            .retained_manifests
            .iter()
            .chain(&report.candidate_manifests)
        {
            let directory = repository.join(&report.manifest_scope).join(manifest_id);
            self.verify_indexed_tree(&agent, &endpoint, repository, &directory)?;
        }
        Ok(SyncthingBoundary {
            sequence: status.sequence,
            relative_app: report.manifest_scope.clone(),
        })
    }

    pub(crate) fn publish_gc(&self, boundary: SyncthingBoundary) -> Result<(), BackendError> {
        let endpoint = self.endpoint()?;
        let agent = self.agent();
        self.scan(&agent, &endpoint, &boundary.relative_app)?;
        let status = self.folder_status(&agent, &endpoint)?;
        if !status.ready() || status.sequence <= boundary.sequence {
            return Err(retryable(
                "Syncthing did not index the local cloud deletion",
            ));
        }
        Ok(())
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
    ) -> Result<(), BackendError> {
        if !directory.is_dir() {
            return Err(retryable("local cloud manifest is unavailable"));
        }
        let mut pending = vec![directory.to_owned()];
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
            }
        }
        Ok(())
    }

    fn scan(
        &self,
        agent: &ureq::Agent,
        endpoint: &str,
        relative: &str,
    ) -> Result<(), BackendError> {
        let response = agent
            .post(format!("{endpoint}/rest/db/scan"))
            .header("X-API-Key", self.api_key.trim())
            .query("folder", self.folder_id.trim())
            .query("sub", relative)
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
        let mut response = request
            .call()
            .map_err(|error| retryable(format!("Syncthing request failed: {error}")))?;
        if !response.status().is_success() {
            return Err(retryable(format!(
                "Syncthing request returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let body = response
            .body_mut()
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
}
