#![forbid(unsafe_code)]

//! Composition root for the cloud backend: the only place the sync workers name
//! a concrete backend or its configuration shape.

use std::sync::{Arc, OnceLock, RwLock};

use tracing::warn;
use vapor_forge_cloud_core::CloudBackend;
use vapor_forge_cloud_cumulus::{CumulusBackend, CumulusSettings};
use vapor_forge_cloud_local::LocalBackend;

#[derive(Clone, Debug, Eq, PartialEq)]
enum BackendKey {
    Local(String),
    Cumulus {
        credential_fingerprint: String,
        timeout_connect_ms: u64,
        timeout_ms: u64,
    },
}

struct CachedBackend {
    key: BackendKey,
    backend: Arc<dyn CloudBackend>,
}

static BACKEND: OnceLock<RwLock<Option<CachedBackend>>> = OnceLock::new();

fn backend_key(config: &vapor_forge_config::RuntimeConfig) -> Option<BackendKey> {
    if config.local_cloud_configured() {
        return Some(BackendKey::Local(config.cloud.local.path.clone()));
    }
    config.cumulus_configured().then(|| BackendKey::Cumulus {
        credential_fingerprint: vapor_forge_cloud_core::credential_fingerprint(
            &config.cloud.cumulus.server_url,
            &config.cloud.cumulus.token,
        ),
        timeout_connect_ms: config.cloud.cumulus.timeout_connect_ms,
        timeout_ms: config.cloud.cumulus.timeout_ms,
    })
}

/// Rebuild the configured backend outside Steam's packet detours.
pub(crate) fn refresh(config: &vapor_forge_config::RuntimeConfig) {
    let key = backend_key(config);
    let backend = match key.as_ref() {
        Some(BackendKey::Local(_)) => match LocalBackend::open(&config.cloud.local.path) {
            Ok(backend) => Some(Arc::new(backend) as Arc<dyn CloudBackend>),
            Err(error) => {
                warn!(%error, "cloud-sync: local backend unavailable");
                None
            }
        },
        Some(BackendKey::Cumulus { .. }) => Some(Arc::new(CumulusBackend::new(CumulusSettings {
            server_url: config.cloud.cumulus.server_url.clone(),
            token: config.cloud.cumulus.token.clone(),
            timeout_connect_ms: config.cloud.cumulus.timeout_connect_ms,
            timeout_ms: config.cloud.cumulus.timeout_ms,
        })) as Arc<dyn CloudBackend>),
        None => None,
    };
    let cached = key
        .zip(backend)
        .map(|(key, backend)| CachedBackend { key, backend });
    *BACKEND
        .get_or_init(|| RwLock::new(None))
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = cached;
}

/// Return the prebuilt backend without filesystem or network I/O.
pub(crate) fn backend_context() -> Option<Arc<dyn CloudBackend>> {
    let config = crate::client::install::config();
    let key = backend_key(&config)?;
    let cache = BACKEND
        .get_or_init(|| RwLock::new(None))
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache
        .as_ref()
        .filter(|cached| cached.key == key)
        .map(|cached| Arc::clone(&cached.backend))
}
