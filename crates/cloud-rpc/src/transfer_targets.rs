use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use vapor_forge_config::RuntimeConfig;

use super::http::CloudSettings;

const CAPACITY: usize = 4096;
const TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Eq, PartialEq)]
pub(super) struct CloudStateScope {
    credential_fingerprint: String,
    steam_id64: Option<u64>,
}

impl CloudStateScope {
    pub(super) fn from_config(config: &RuntimeConfig) -> Self {
        if config.local_cloud_configured() {
            return Self::local(
                &config.cloud.local_path,
                Some(vapor_forge_features::identity::steam_id()).filter(|id| *id != 0),
            );
        }
        Self {
            credential_fingerprint: vapor_forge_cloud_core::credential_fingerprint(
                &config.cloud.server_url,
                &config.cloud.token,
            ),
            steam_id64: Some(vapor_forge_features::identity::steam_id()).filter(|id| *id != 0),
        }
    }

    pub(super) fn from_settings(settings: &CloudSettings) -> Self {
        if !settings.local_path.is_empty() {
            return Self::local(&settings.local_path, settings.steam_id64);
        }
        Self {
            credential_fingerprint: vapor_forge_cloud_core::credential_fingerprint(
                &settings.server_url,
                &settings.token,
            ),
            steam_id64: settings.steam_id64,
        }
    }

    pub(super) fn credential_fingerprint(&self) -> &str {
        &self.credential_fingerprint
    }

    fn local(path: &str, steam_id64: Option<u64>) -> Self {
        Self {
            credential_fingerprint: vapor_forge_cloud_core::endpoint_scope(&format!(
                "file://{}/accounts/{}",
                path.trim(),
                steam_id64.unwrap_or(0)
            )),
            steam_id64,
        }
    }
}

#[derive(Default)]
pub(super) struct TransferTargetRegistry {
    targets: Mutex<VecDeque<IssuedTransferTarget>>,
}

struct IssuedTransferTarget {
    scope: CloudStateScope,
    authority: String,
    path: String,
    expires_at: Instant,
}

impl TransferTargetRegistry {
    pub(super) fn register(&self, scope: &CloudStateScope, authority: &str, path: &str) {
        let now = Instant::now();
        let mut targets = self.targets.lock().unwrap();
        remove_expired(&mut targets, now);
        if targets.len() == CAPACITY {
            targets.pop_front();
        }
        targets.push_back(IssuedTransferTarget {
            scope: scope.clone(),
            authority: authority.to_ascii_lowercase(),
            path: path.to_string(),
            expires_at: now + TTL,
        });
    }

    pub(super) fn contains(&self, scope: &CloudStateScope, authority: &str, path: &str) -> bool {
        let now = Instant::now();
        let mut targets = self.targets.lock().unwrap();
        remove_expired(&mut targets, now);
        targets.iter().any(|target| {
            target.scope == *scope
                && target.authority.eq_ignore_ascii_case(authority)
                && target.path == path
        })
    }
}

fn remove_expired(targets: &mut VecDeque<IssuedTransferTarget>, now: Instant) {
    while targets
        .front()
        .is_some_and(|target| target.expires_at <= now)
    {
        targets.pop_front();
    }
}
