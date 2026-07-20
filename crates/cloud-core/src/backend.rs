use std::fmt;

use crate::{AchievementEvent, AchievementSchema, DeviceDescriptor, PlaytimeEntry, UploadIdentity};

/// Result of offering a schema to a backend. Both variants are terminal: a
/// decline is the backend refusing the payload, not a failure to retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaUploadOutcome {
    Accepted,
    Declined,
}

/// A backend failure reduced to what delivery scheduling needs: whether the
/// operation is worth retrying, plus a message for logs.
///
/// Backends keep their own richer error types and convert at the boundary.
#[derive(Clone, Debug)]
pub struct BackendError {
    message: String,
    retryable: bool,
}

impl BackendError {
    pub fn new(message: impl Into<String>, retryable: bool) -> Self {
        Self {
            message: message.into(),
            retryable,
        }
    }

    /// Whether the outbox should schedule another attempt instead of giving up.
    pub fn is_retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BackendError {}

/// A destination that durable sync events can be delivered to.
///
/// Implementors own their own connection settings and credentials, so callers
/// never name a concrete backend or its configuration shape. Everything crossing
/// this boundary is a neutral type from this crate.
pub trait CloudBackend: Send + Sync {
    /// Partition key covering the destination only, ignoring credentials.
    ///
    /// Used where data stays valid across a credential change, so re-authenticating
    /// against the same destination does not orphan pending rows.
    fn endpoint_scope(&self) -> String;

    /// Partition key covering destination *and* credentials.
    ///
    /// Used where data belongs to the authenticated principal, so changing
    /// credentials isolates old rows instead of mixing them. Backends decide
    /// which credential fields participate; [`crate::credential_scope`] and
    /// [`crate::endpoint_scope`] provide the digests.
    fn credential_scope(&self) -> String;

    /// Register this device with the backend before uploading on its behalf.
    fn ensure_device_bound(&self, descriptor: &DeviceDescriptor) -> Result<(), BackendError>;

    fn upload_achievement_events(
        &self,
        identity: &UploadIdentity,
        events: &[AchievementEvent],
    ) -> Result<(), BackendError>;

    fn upload_achievement_schema(
        &self,
        schema: &AchievementSchema,
    ) -> Result<SchemaUploadOutcome, BackendError>;

    fn upload_playtime(
        &self,
        client_id: u64,
        steam_id64: &str,
        entries: &[PlaytimeEntry],
    ) -> Result<(), BackendError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_error_reports_retryability_and_message() {
        let transient = BackendError::new("timeout", true);
        assert!(transient.is_retryable());
        assert_eq!(transient.to_string(), "timeout");

        let permanent = BackendError::new("malformed payload", false);
        assert!(!permanent.is_retryable());
    }
}
