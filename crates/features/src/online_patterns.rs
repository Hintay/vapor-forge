//! Background fetch of online pattern overrides.
//!
//! After hook installation, a background thread fetches the latest patterns.toml
//! from the configured URL. If the content differs from the embedded patterns
//! (compared by FNV-1a hash), the file is written to the user's config directory
//! so the next startup picks it up via `PatternRegistry::with_overrides`.

use std::path::PathBuf;
use tracing::{debug, info, warn};

const CONNECT_TIMEOUT_MS: u64 = 3000;
const TOTAL_TIMEOUT_MS: u64 = 8000;

/// Result of an online pattern fetch attempt.
#[derive(Debug)]
pub enum FetchResult {
    Updated(PathBuf),
    AlreadyCurrent,
    Failed(String),
}

/// Fetch patterns.toml from `url`, compare with `embedded_hash`.
/// If different, write to `cache_path`. Returns what happened.
pub fn fetch_and_cache(url: &str, embedded_hash: u64, cache_path: &std::path::Path) -> FetchResult {
    let body = match do_fetch(url) {
        Ok(b) => b,
        Err(e) => return FetchResult::Failed(e),
    };

    let online_hash = fnv1a_64(body.as_bytes());
    if online_hash == embedded_hash {
        debug!("online-patterns: hash matches embedded, skipping write");
        return FetchResult::AlreadyCurrent;
    }

    if let Some(parent) = cache_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return FetchResult::Failed(format!("mkdir failed: {e}"));
        }
    }

    match std::fs::write(cache_path, &body) {
        Ok(()) => {
            info!(
                path = %cache_path.display(),
                "online-patterns: updated cache file"
            );
            FetchResult::Updated(cache_path.to_path_buf())
        }
        Err(e) => FetchResult::Failed(format!("write failed: {e}")),
    }
}

/// Spawn a background thread that fetches and caches online patterns.
pub fn spawn_fetch(url: String, embedded_hash: u64) {
    std::thread::Builder::new()
        .name("online-patterns".into())
        .spawn(move || {
            let cache_path = match pattern_cache_path() {
                Some(p) => p,
                None => return,
            };
            match fetch_and_cache(&url, embedded_hash, &cache_path) {
                FetchResult::Updated(p) => {
                    info!(path = %p.display(), "online-patterns: new patterns cached for next startup");
                }
                FetchResult::AlreadyCurrent => {
                    debug!("online-patterns: embedded patterns are current");
                }
                FetchResult::Failed(e) => {
                    warn!(error = %e, "online-patterns: fetch failed");
                }
            }
        })
        .ok();
}

fn do_fetch(url: &str) -> Result<String, String> {
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(std::time::Duration::from_millis(CONNECT_TIMEOUT_MS)))
        .timeout_global(Some(std::time::Duration::from_millis(TOTAL_TIMEOUT_MS)))
        .build()
        .new_agent();

    let body = agent
        .get(url)
        .call()
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("read body failed: {e}"))?;

    if body.is_empty() {
        return Err("empty response".into());
    }

    Ok(body)
}

fn pattern_cache_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(std::path::Path::new(&home).join(".config/vapor-forge/patterns.toml"))
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
