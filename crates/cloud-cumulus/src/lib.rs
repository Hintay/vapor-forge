#![forbid(unsafe_code)]

pub mod achievement;
pub mod playtime;

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use vapor_forge_cloud_core::{credential_scope, DeviceDescriptor};

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
        let response = request.send(encoded.as_slice())?;
        ensure_success(response.status().as_u16())?;
        Ok(response)
    }

    pub fn get_json<R: DeserializeOwned>(&self, path: &str) -> Result<R, CumulusError> {
        let request = self
            .agent
            .get(&self.url(path))
            .header("Authorization", &self.authorization_header());
        let request = self.with_client_id(request);
        let mut response = request.call()?;
        ensure_success(response.status().as_u16())?;
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
        let response = self.with_client_id(request).send_empty()?;
        ensure_success(response.status().as_u16())
    }

    pub fn delete(&self, path: &str) -> Result<(), CumulusError> {
        let request = self
            .agent
            .delete(&self.url(path))
            .header("Authorization", &self.authorization_header());
        let response = self.with_client_id(request).call()?;
        ensure_success(response.status().as_u16())
    }

    pub fn delete_allow_not_found(&self, path: &str) -> Result<(), CumulusError> {
        let request = self
            .agent
            .delete(&self.url(path))
            .header("Authorization", &self.authorization_header());
        let response = self.with_client_id(request).call()?;
        let status = response.status().as_u16();
        if status == 404 {
            Ok(())
        } else {
            ensure_success(status)
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
    let scope = credential_scope(&settings.server_url, &settings.token);
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

pub fn ensure_success(status: u16) -> Result<(), CumulusError> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(CumulusError::HttpStatus(status))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CumulusError {
    #[error("Cumulus returned HTTP {0}")]
    HttpStatus(u16),
    #[error("Cumulus transport failed: {0}")]
    Transport(#[from] ureq::Error),
    #[error("invalid Cumulus JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl CumulusError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::HttpStatus(status) => {
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
}
