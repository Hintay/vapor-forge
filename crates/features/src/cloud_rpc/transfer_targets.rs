use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use vapor_forge_config::RuntimeConfig;

use super::http::CloudSettings;

const CAPACITY: usize = 4096;
const TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Eq, PartialEq)]
pub(super) struct CloudStateScope {
    credential_scope: String,
}

impl CloudStateScope {
    pub(super) fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            credential_scope: vapor_forge_cloud_core::credential_scope(
                &config.cloud.server_url,
                &config.cloud.token,
            ),
        }
    }

    pub(super) fn from_settings(settings: &CloudSettings) -> Self {
        Self {
            credential_scope: vapor_forge_cloud_core::credential_scope(
                &settings.server_url,
                &settings.token,
            ),
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
