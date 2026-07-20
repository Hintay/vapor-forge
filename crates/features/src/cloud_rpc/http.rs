use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use vapor_forge_cloud_core::device_descriptor;
use vapor_forge_cloud_cumulus::{
    CumulusClient as SharedCumulusClient, CumulusSettings, STEAM_CLIENT_ID_HEADER,
};
use vapor_forge_config::RuntimeConfig;
use vapor_forge_steam_protocol::CloudHttpHeader;

#[derive(Clone)]
pub(super) struct CloudSettings {
    pub(super) local_path: String,
    pub(super) server_url: String,
    pub(super) token: String,
    pub(super) steam_client_id: Option<u64>,
    pub(super) bind_device: bool,
    pub(super) timeout_connect_ms: u64,
    pub(super) timeout_ms: u64,
}

impl CloudSettings {
    pub(super) fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            local_path: config.cloud.local_path.trim().to_string(),
            server_url: config.cloud.server_url.trim().to_string(),
            token: config.cloud.token.trim().to_string(),
            steam_client_id: device_descriptor().map(|descriptor| descriptor.client_id),
            bind_device: true,
            timeout_connect_ms: config.cloud.timeout_connect_ms,
            timeout_ms: config.cloud.timeout_ms,
        }
    }
}

pub(super) struct Endpoint {
    pub(super) origin: String,
    pub(super) authority: String,
    base_path: String,
    pub(super) https: bool,
}

impl Endpoint {
    pub(super) fn parse(raw: &str) -> Result<Self, AdapterError> {
        let raw = raw.trim().trim_end_matches('/');
        let (https, rest) = if let Some(rest) = raw.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = raw.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(AdapterError::Protocol(
                "cloud.server_url must use http:// or https://".into(),
            ));
        };
        if rest.is_empty() || rest.contains('@') || rest.contains('?') || rest.contains('#') {
            return Err(AdapterError::Protocol("invalid cloud.server_url".into()));
        }
        let (authority, base_path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{}", path.trim_end_matches('/'))),
            None => (rest, String::new()),
        };
        if authority.is_empty() {
            return Err(AdapterError::Protocol("invalid cloud.server_url".into()));
        }
        Ok(Self {
            origin: raw.to_string(),
            authority: authority.to_string(),
            base_path,
            https,
        })
    }

    pub(super) fn resolve_path(&self, suffix: &str) -> String {
        format!("{}{}", self.base_path, suffix)
    }

    pub(super) fn matches_transfer_location(&self, authority: &str, path: &str) -> bool {
        if !authority.eq_ignore_ascii_case(&self.authority) {
            return false;
        }
        let Some(path) = path.strip_prefix(&self.resolve_path("/api/v1/")) else {
            return false;
        };
        let path = path.split('?').next().unwrap_or(path);
        let segments = path.split('/').collect::<Vec<_>>();
        matches!(
            segments.as_slice(),
            ["files", _, "content"] | ["upload-batches", _, "files", _, "blocks", _]
        )
    }
}

pub(super) fn parse_absolute_target(url: &str) -> Option<(bool, String, String)> {
    let uri = url.parse::<ureq::http::Uri>().ok()?;
    let https = match uri.scheme_str()? {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let authority = uri.authority()?.as_str().to_string();
    let path = uri.path_and_query()?.as_str().to_string();
    Some((https, authority, path))
}

pub(super) fn resolve_transfer_target(
    client: &CumulusClient,
    target: CumulusTransferTarget,
) -> Result<ResolvedTransferTarget, AdapterError> {
    if !target.url_path.starts_with('/') || target.url_path.starts_with("//") {
        return Err(AdapterError::Protocol(
            "Cumulus returned an invalid transfer path".into(),
        ));
    }
    let mut headers = target
        .request_headers
        .into_iter()
        .map(|header| {
            if header.name.is_empty()
                || header.name.contains(['\r', '\n'])
                || header.value.contains(['\r', '\n'])
            {
                return Err(AdapterError::Protocol(
                    "Cumulus returned an invalid transfer header".into(),
                ));
            }
            Ok(CloudHttpHeader {
                name: Some(header.name),
                value: Some(header.value),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (authority, path, https) = match target.url_host {
        Some(authority) => {
            if authority.is_empty()
                || authority.contains(['/', '@', '?', '#', '\r', '\n'])
                || format!("https://{authority}/")
                    .parse::<ureq::http::Uri>()
                    .ok()
                    .and_then(|uri| uri.authority().map(|value| value.as_str() == authority))
                    != Some(true)
            {
                return Err(AdapterError::Protocol(
                    "Cumulus returned an invalid transfer host".into(),
                ));
            }
            let https = target.use_https.ok_or_else(|| {
                AdapterError::Protocol("external transfer target omitted use_https".into())
            })?;
            (authority, target.url_path, https)
        }
        None => {
            if target.use_https.is_some() {
                return Err(AdapterError::Protocol(
                    "relative transfer target supplied use_https".into(),
                ));
            }
            headers.extend(client.auth_headers());
            (
                client.endpoint.authority.clone(),
                client.endpoint.resolve_path(&target.url_path),
                client.endpoint.https,
            )
        }
    };
    Ok(ResolvedTransferTarget {
        authority,
        path,
        https,
        headers,
    })
}

pub(super) struct CumulusClient {
    inner: SharedCumulusClient,
    endpoint: Endpoint,
}

impl CumulusClient {
    pub(super) fn new(settings: &CloudSettings) -> Result<Self, AdapterError> {
        let endpoint = Endpoint::parse(&settings.server_url)?;
        Ok(Self {
            inner: SharedCumulusClient::new(
                &CumulusSettings {
                    server_url: endpoint.origin.clone(),
                    token: settings.token.clone(),
                    timeout_connect_ms: settings.timeout_connect_ms,
                    timeout_ms: settings.timeout_ms,
                },
                settings.steam_client_id,
            ),
            endpoint,
        })
    }

    pub(super) fn auth_headers(&self) -> Vec<CloudHttpHeader> {
        let mut headers = vec![CloudHttpHeader {
            name: Some("Authorization".into()),
            value: Some(self.inner.authorization_header()),
        }];
        if let Some(client_id) = self.inner.steam_client_id_header() {
            headers.push(CloudHttpHeader {
                name: Some(STEAM_CLIENT_ID_HEADER.into()),
                value: Some(client_id.to_owned()),
            });
        }
        headers
    }

    pub(super) fn get_json<T: DeserializeOwned>(&self, suffix: &str) -> Result<T, AdapterError> {
        Ok(self.inner.get_json(suffix)?)
    }

    pub(super) fn post_json<T: DeserializeOwned>(
        &self,
        suffix: &str,
        body: &Value,
    ) -> Result<T, AdapterError> {
        Ok(self.inner.post_json_response(suffix, body)?)
    }

    pub(super) fn post_unit(&self, suffix: &str) -> Result<(), AdapterError> {
        Ok(self.inner.post_unit(suffix)?)
    }

    pub(super) fn post_json_unit(&self, suffix: &str, body: &Value) -> Result<(), AdapterError> {
        Ok(self.inner.post_json_unit(suffix, body)?)
    }

    pub(super) fn delete(&self, suffix: &str) -> Result<(), AdapterError> {
        Ok(self.inner.delete(suffix)?)
    }

    pub(super) fn delete_allow_not_found(&self, suffix: &str) -> Result<(), AdapterError> {
        Ok(self.inner.delete_allow_not_found(suffix)?)
    }
}

#[derive(Clone, Deserialize)]
pub(super) struct CumulusFile {
    pub(super) file_id: Option<i64>,
    pub(super) path: String,
    pub(super) size: i64,
    pub(super) sha1: String,
    pub(super) mtime: i64,
    pub(super) platforms_to_sync: i64,
}

#[derive(Deserialize)]
pub(super) struct CumulusChangelist {
    pub(super) current_change_number: i64,
    pub(super) app_buildid_hwm: i64,
    pub(super) basis: String,
    pub(super) changed: Vec<CumulusFile>,
    pub(super) deleted: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct CumulusManifest {
    pub(super) files: Vec<CumulusFile>,
}

#[derive(Deserialize)]
pub(super) struct CumulusBeginBatch {
    pub(super) batch_id: String,
    pub(super) app_change_number: i64,
}

#[derive(Deserialize)]
pub(super) struct CumulusDeclaredFile {
    pub(super) file_id: String,
    pub(super) transfer_size: u64,
    pub(super) block_requests: Vec<CumulusUploadBlock>,
}

#[derive(Deserialize)]
pub(super) struct CumulusUploadBlock {
    #[serde(flatten)]
    pub(super) target: CumulusTransferTarget,
    pub(super) http_method: i32,
    pub(super) block_offset: u64,
    pub(super) block_length: u32,
    pub(super) may_parallelize: bool,
}

#[derive(Deserialize)]
pub(super) struct CumulusTransferTarget {
    pub(super) url_host: Option<String>,
    pub(super) url_path: String,
    pub(super) use_https: Option<bool>,
    #[serde(default)]
    pub(super) request_headers: Vec<CumulusTransferHeader>,
}

#[derive(Deserialize)]
pub(super) struct CumulusTransferHeader {
    pub(super) name: String,
    pub(super) value: String,
}

pub(super) struct ResolvedTransferTarget {
    pub(super) authority: String,
    pub(super) path: String,
    pub(super) https: bool,
    pub(super) headers: Vec<CloudHttpHeader>,
}

#[derive(Deserialize)]
pub(super) struct CumulusCommit {
    pub(super) change_number: i64,
}

#[derive(Deserialize)]
pub(super) struct CumulusQuota {
    pub(super) quota_bytes: i64,
    pub(super) used_bytes: i64,
    pub(super) max_files: i64,
    pub(super) used_files: i64,
}

#[derive(Deserialize)]
pub(super) struct CumulusLaunch {
    pub(super) pending_operations: Vec<CumulusPendingOperation>,
}

#[derive(Deserialize)]
pub(super) struct CumulusPendingOperation {
    pub(super) operation: i64,
    pub(super) machine_name: String,
    pub(super) client_id: String,
    pub(super) time_last_updated: i64,
    pub(super) os_type: Option<i64>,
    pub(super) device_type: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum AdapterError {
    #[error("invalid Steam cloud RPC: {0}")]
    Protocol(String),
    #[error("Cumulus request queue is overloaded")]
    Overloaded,
    #[error("Cumulus transport failed: {0}")]
    Http(#[from] ureq::Error),
    #[error("invalid Cumulus JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid protobuf: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("conflict outbox failed: {0}")]
    Outbox(#[from] vapor_forge_sync_state::OutboxError),
    #[error("Cumulus client failed: {0}")]
    Client(#[from] vapor_forge_cloud_cumulus::CumulusError),
    #[error("cloud backend failed: {0}")]
    Backend(#[from] vapor_forge_cloud_core::BackendError),
}

pub(super) fn required<T>(value: Option<T>, field: &str) -> Result<T, AdapterError> {
    value.ok_or_else(|| AdapterError::Protocol(format!("missing {field}")))
}

pub(super) fn parse_batch_id(value: &str) -> Result<u64, AdapterError> {
    let id = value
        .parse::<u64>()
        .map_err(|_| AdapterError::Protocol("Cumulus returned a non-numeric batch id".into()))?;
    if id == 0 || id > i64::MAX as u64 {
        return Err(AdapterError::Protocol(
            "Cumulus batch id is outside the positive 63-bit range".into(),
        ));
    }
    Ok(id)
}

pub(super) fn signed_bits(value: u64) -> i64 {
    value as i64
}

pub(super) fn nonnegative_u64(value: i64, field: &str) -> Result<u64, AdapterError> {
    u64::try_from(value).map_err(|_| AdapterError::Protocol(format!("negative Cumulus {field}")))
}

pub(super) fn clamp_u32(value: i64) -> u32 {
    value.clamp(0, i64::from(u32::MAX)) as u32
}

pub(super) fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

pub(super) fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, AdapterError> {
    if hex.len() % 2 != 0 {
        return Err(AdapterError::Protocol("odd-length hex value".into()));
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

pub(super) fn hex_nibble(byte: u8) -> Result<u8, AdapterError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AdapterError::Protocol("invalid hex value".into())),
    }
}
