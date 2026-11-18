#![forbid(unsafe_code)]

pub mod achievement;
mod device_stream;
pub mod playtime;
pub mod port;

pub use port::CumulusBackend;

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use vapor_forge_cloud_core::{
    credential_fingerprint, principal_scope as scope_for_principal, DeviceDescriptor,
};

pub const STEAM_CLIENT_ID_HEADER: &str = "x-cumulus-steam-client-id";

#[derive(Clone, Debug)]
pub struct CumulusSettings {
    pub server_url: String,
    pub token: String,
    pub timeout_connect_ms: u64,
    pub timeout_ms: u64,
}

pub struct CumulusClient {
    agent: ureq::Agent,
    settings: CumulusSettings,
    steam_client_id: Option<String>,
}

impl CumulusClient {
    pub fn new(settings: &CumulusSettings, steam_client_id: Option<u64>) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_millis(settings.timeout_connect_ms)))
            .timeout_global(Some(Duration::from_millis(settings.timeout_ms)))
            .http_status_as_error(false)
            .build()
            .new_agent();
        Self {
            agent,
            settings: settings.clone(),
            steam_client_id: steam_client_id.map(|value| value.to_string()),
        }
    }

    pub fn post_json<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<ureq::http::Response<ureq::Body>, CumulusError> {
        let encoded = serde_json::to_vec(body)?;
        let url = format!("{}{}", self.settings.server_url.trim_end_matches('/'), path);
        let request = self
            .agent
            .post(&url)
            .header("Authorization", &format!("Bearer {}", self.settings.token))
            .header("Content-Type", "application/json");
        let request = if let Some(client_id) = &self.steam_client_id {
            request.header(STEAM_CLIENT_ID_HEADER, client_id)
        } else {
            request
        };
        check_response(request.send(encoded.as_slice())?)
    }

    pub fn get_json<R: DeserializeOwned>(&self, path: &str) -> Result<R, CumulusError> {
        let request = self
            .agent
            .get(&self.url(path))
            .header("Authorization", &self.authorization_header());
        let request = self.with_client_id(request);
        let mut response = check_response(request.call()?)?;
        let body = response.body_mut().read_to_string()?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn post_json_unit<T: Serialize>(&self, path: &str, body: &T) -> Result<(), CumulusError> {
        self.post_json(path, body).map(|_| ())
    }

    pub fn post_json_response<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, CumulusError> {
        let mut response = self.post_json(path, body)?;
        let body = response.body_mut().read_to_string()?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn post_unit(&self, path: &str) -> Result<(), CumulusError> {
        let request = self
            .agent
            .post(&self.url(path))
            .header("Authorization", &self.authorization_header());
        check_response(self.with_client_id(request).send_empty()?).map(|_| ())
    }

    pub fn delete(&self, path: &str) -> Result<(), CumulusError> {
        let request = self
            .agent
            .delete(&self.url(path))
            .header("Authorization", &self.authorization_header());
        check_response(self.with_client_id(request).call()?).map(|_| ())
    }

    pub fn delete_allow_not_found(&self, path: &str) -> Result<(), CumulusError> {
        let request = self
            .agent
            .delete(&self.url(path))
            .header("Authorization", &self.authorization_header());
        let response = self.with_client_id(request).call()?;
        if response.status().as_u16() == 404 {
            Ok(())
        } else {
            check_response(response).map(|_| ())
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.settings.server_url.trim_end_matches('/'), path)
    }

    pub fn authorization_header(&self) -> String {
        format!("Bearer {}", self.settings.token)
    }

    pub fn steam_client_id_header(&self) -> Option<&str> {
        self.steam_client_id.as_deref()
    }

    fn with_client_id<B>(&self, request: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        if let Some(client_id) = &self.steam_client_id {
            request.header(STEAM_CLIENT_ID_HEADER, client_id)
        } else {
            request
        }
    }
}

static BOUND_DEVICES: OnceLock<Mutex<HashSet<(String, DeviceDescriptor)>>> = OnceLock::new();

#[derive(serde::Deserialize)]
struct DevicePrincipalResponse {
    principal_id: String,
}

/// Resolve the principal behind the configured credential. The device client
/// id is sent when known, because a credential awaiting activation for one
/// Steam device is refused without it.
pub fn principal_scope(
    settings: &CumulusSettings,
    steam_client_id: Option<u64>,
) -> Result<String, CumulusError> {
    let response: DevicePrincipalResponse =
        CumulusClient::new(settings, steam_client_id).get_json("/api/v1/device/principal")?;
    Ok(scope_for_principal(
        &settings.server_url,
        &response.principal_id,
    ))
}

#[derive(Serialize)]
struct DeviceBindingRequest<'a> {
    client_id: &'a str,
    machine_name: &'a str,
    os_type: Option<i64>,
    device_type: Option<i64>,
}

pub fn ensure_device_bound(
    settings: &CumulusSettings,
    descriptor: &DeviceDescriptor,
) -> Result<(), CumulusError> {
    let scope = credential_fingerprint(&settings.server_url, &settings.token);
    let cache_key = (scope, descriptor.clone());
    if BOUND_DEVICES
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .is_ok_and(|bound| bound.contains(&cache_key))
    {
        return Ok(());
    }

    let client_id = descriptor.client_id.to_string();
    CumulusClient::new(settings, Some(descriptor.client_id)).post_json_unit(
        "/api/v1/device/bind",
        &DeviceBindingRequest {
            client_id: &client_id,
            machine_name: &descriptor.machine_name,
            os_type: descriptor.os_type,
            device_type: descriptor.device_type,
        },
    )?;

    if let Ok(mut bound) = BOUND_DEVICES
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
    {
        bound.insert(cache_key);
    }
    Ok(())
}

/// Upper bound on an error body read for its code. Error bodies are small JSON
/// objects; anything larger is not one of them.
const MAX_ERROR_BODY_BYTES: u64 = 64 * 1024;

/// Pass a successful response through, or turn a failed one into an error
/// carrying the server's error code when the body names one.
pub fn check_response(
    mut response: ureq::http::Response<ureq::Body>,
) -> Result<ureq::http::Response<ureq::Body>, CumulusError> {
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        return Ok(response);
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_ERROR_BODY_BYTES)
        .read_to_string()
        .unwrap_or_default();
    Err(CumulusError::from_status_body(status, &body))
}

#[derive(serde::Deserialize)]
struct ApiErrorEnvelope {
    error: ApiErrorBody,
}

#[derive(serde::Deserialize)]
struct ApiErrorBody {
    code: String,
    #[serde(default)]
    message: String,
}

/// Error codes after which retrying with the same credential and device cannot
/// succeed. Configuration has to change first.
const CREDENTIAL_BLOCKED_CODES: &[&str] = &[
    "credential_bound",
    "steam_account_owned",
    "device_revoked",
    "token_revoked",
    "steam_client_id_mismatch",
];

#[derive(Debug, thiserror::Error)]
pub enum CumulusError {
    #[error("Cumulus returned HTTP {0}")]
    HttpStatus(u16),
    #[error("Cumulus returned HTTP {status} ({code}): {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error("Cumulus transport failed: {0}")]
    Transport(#[from] ureq::Error),
    #[error("invalid Cumulus JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl CumulusError {
    /// Build the error for a failed response from its status and body.
    pub fn from_status_body(status: u16, body: &str) -> Self {
        match serde_json::from_str::<ApiErrorEnvelope>(body) {
            Ok(envelope) if !envelope.error.code.is_empty() => Self::Api {
                status,
                code: envelope.error.code,
                message: envelope.error.message,
            },
            _ => Self::HttpStatus(status),
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus(status) | Self::Api { status, .. } => Some(*status),
            Self::Transport(_) | Self::Json(_) => None,
        }
    }

    /// The server's error code, when the response carried one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Api { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The credential or device was refused in a way only a configuration
    /// change can fix. Such failures are not retryable, but they say nothing
    /// about the payload, so queued data must be kept.
    pub fn is_credential_blocked(&self) -> bool {
        self.code()
            .is_some_and(|code| CREDENTIAL_BLOCKED_CODES.contains(&code))
    }

    pub fn is_retryable(&self) -> bool {
        if self.is_credential_blocked() {
            return false;
        }
        match self {
            Self::HttpStatus(status) | Self::Api { status, .. } => {
                matches!(*status, 401 | 403 | 408 | 409 | 429) || *status >= 500
            }
            Self::Transport(_) => true,
            Self::Json(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_failures_remain_retryable() {
        for status in [401, 403, 408, 409, 429, 500] {
            assert!(CumulusError::HttpStatus(status).is_retryable(), "{status}");
        }
        for status in [400, 404, 413, 422] {
            assert!(!CumulusError::HttpStatus(status).is_retryable(), "{status}");
        }
    }

    fn api_error(status: u16, code: &str) -> CumulusError {
        CumulusError::from_status_body(
            status,
            &format!(r#"{{"error":{{"code":"{code}","message":"refused"}}}}"#),
        )
    }

    #[test]
    fn credential_refusals_are_permanent_and_keep_their_code() {
        for code in [
            "credential_bound",
            "steam_account_owned",
            "device_revoked",
            "token_revoked",
            "steam_client_id_mismatch",
        ] {
            let error = api_error(403, code);
            assert_eq!(error.code(), Some(code));
            assert!(error.is_credential_blocked(), "{code}");
            assert!(!error.is_retryable(), "{code}");
        }
    }

    #[test]
    fn pending_identity_requirements_stay_retryable() {
        for code in ["device_identity_required", "steam_client_id_required"] {
            let error = api_error(403, code);
            assert!(!error.is_credential_blocked(), "{code}");
            assert!(error.is_retryable(), "{code}");
        }
        assert!(api_error(409, "conflict").is_retryable());
        assert!(!api_error(400, "bad_request").is_retryable());
    }

    #[test]
    fn failed_responses_carry_the_server_error_code() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            let body = r#"{"error":{"code":"token_revoked","message":"token has been revoked"}}"#;
            write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let settings = CumulusSettings {
            server_url: format!("http://{address}"),
            token: "token".into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 2_000,
        };
        let error = principal_scope(&settings, Some(7)).unwrap_err();
        assert_eq!(error.status(), Some(403));
        assert_eq!(error.code(), Some("token_revoked"));
        assert!(error.is_credential_blocked());
        assert!(!error.is_retryable());
    }

    #[test]
    fn unparseable_error_bodies_fall_back_to_the_status() {
        let error = CumulusError::from_status_body(403, "<html>forbidden</html>");
        assert!(matches!(error, CumulusError::HttpStatus(403)));
        assert!(error.is_retryable());
        assert_eq!(error.status(), Some(403));
    }
}
