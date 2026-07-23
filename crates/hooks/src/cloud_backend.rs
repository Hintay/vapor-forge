#![forbid(unsafe_code)]

//! Composition root for the cloud backend: the only place the sync workers name
//! a concrete backend or its configuration shape.

use tracing::warn;
use vapor_forge_cloud_core::CloudBackend;
use vapor_forge_cloud_cumulus::{CumulusBackend, CumulusSettings};
use vapor_forge_cloud_local::LocalBackend;

/// Resolve the configured cloud backend, or `None` when cloud sync is disabled
/// or the local backend cannot be opened.
pub(crate) fn backend_context() -> Option<Box<dyn CloudBackend>> {
    let config = crate::client::install::config();
    if config.local_cloud_configured() {
        return match LocalBackend::open(&config.cloud.local_path) {
            Ok(backend) => Some(Box::new(backend)),
            Err(error) => {
                warn!(%error, "cloud-sync: local backend unavailable");
                None
            }
        };
    }
    if !config.cumulus_configured() {
        return None;
    }
    Some(Box::new(CumulusBackend::new(CumulusSettings {
        server_url: config.cloud.server_url.clone(),
        token: config.cloud.token.clone(),
        timeout_connect_ms: config.cloud.timeout_connect_ms,
        timeout_ms: config.cloud.timeout_ms,
    })))
}
