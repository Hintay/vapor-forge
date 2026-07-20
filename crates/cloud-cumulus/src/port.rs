//! Cumulus as a [`CloudBackend`] implementation.
//!
//! The free functions in this crate stay the transport layer; this module owns
//! the settings and maps Cumulus errors onto the neutral port types.

use vapor_forge_cloud_core::{
    credential_scope, endpoint_scope, AchievementEvent, AchievementSchema, BackendError,
    CloudBackend, DeviceDescriptor, PlaytimeEntry, SchemaUploadOutcome, UploadIdentity,
};

use crate::{achievement, ensure_device_bound, playtime, CumulusError, CumulusSettings};

/// A Cumulus endpoint plus the credentials used to reach it.
pub struct CumulusBackend {
    settings: CumulusSettings,
}

impl CumulusBackend {
    pub fn new(settings: CumulusSettings) -> Self {
        Self { settings }
    }

    /// The underlying settings, for the Cloud RPC proxy which speaks Cumulus
    /// HTTP directly rather than through the port.
    pub fn settings(&self) -> &CumulusSettings {
        &self.settings
    }
}

impl From<CumulusError> for BackendError {
    fn from(error: CumulusError) -> Self {
        let retryable = error.is_retryable();
        BackendError::new(error.to_string(), retryable)
    }
}

impl CloudBackend for CumulusBackend {
    fn endpoint_scope(&self) -> String {
        endpoint_scope(&self.settings.server_url)
    }

    fn credential_scope(&self) -> String {
        credential_scope(&self.settings.server_url, &self.settings.token)
    }

    fn ensure_device_bound(&self, descriptor: &DeviceDescriptor) -> Result<(), BackendError> {
        ensure_device_bound(&self.settings, descriptor).map_err(BackendError::from)
    }

    fn upload_achievement_events(
        &self,
        identity: &UploadIdentity,
        events: &[AchievementEvent],
    ) -> Result<(), BackendError> {
        achievement::upload_events(&self.settings, identity, events).map_err(BackendError::from)
    }

    fn upload_achievement_schema(
        &self,
        schema: &AchievementSchema,
    ) -> Result<SchemaUploadOutcome, BackendError> {
        achievement::upload_schema(&self.settings, schema)
            .map(|outcome| match outcome {
                achievement::SchemaUploadOutcome::Uploaded => SchemaUploadOutcome::Accepted,
                achievement::SchemaUploadOutcome::Disabled => SchemaUploadOutcome::Declined,
            })
            .map_err(BackendError::from)
    }

    fn upload_playtime(
        &self,
        client_id: u64,
        steam_id64: &str,
        entries: &[PlaytimeEntry],
    ) -> Result<(), BackendError> {
        playtime::upload(&self.settings, client_id, steam_id64, entries).map_err(BackendError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(server_url: &str, token: &str) -> CumulusSettings {
        CumulusSettings {
            server_url: server_url.into(),
            token: token.into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 1_000,
        }
    }

    #[test]
    fn credential_scope_tracks_endpoint_and_token() {
        let backend = CumulusBackend::new(settings("https://cloud.test/api", "token"));
        assert_eq!(
            backend.credential_scope(),
            CumulusBackend::new(settings("https://cloud.test/api/", "token")).credential_scope(),
        );
        assert_ne!(
            backend.credential_scope(),
            CumulusBackend::new(settings("https://cloud.test/api", "other")).credential_scope(),
        );
    }

    #[test]
    fn cumulus_errors_keep_their_retry_classification() {
        let retryable: BackendError = CumulusError::HttpStatus(503).into();
        assert!(retryable.is_retryable());

        let permanent: BackendError = CumulusError::HttpStatus(400).into();
        assert!(!permanent.is_retryable());
    }
}
