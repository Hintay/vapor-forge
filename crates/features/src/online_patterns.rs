//! Background fetch of online pattern hotfixes.
//!
//! A download is stored as a target candidate. Each hook module publishes its
//! own active cache only after validating the candidate against that live
//! module.
//! Removing `patterns_url` stops downloads and candidate promotion but does not
//! deactivate a validated target-specific cache.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fs2::FileExt;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use vapor_forge_patterns::registry::{PatternRegistry, PatternTarget};

const CONNECT_TIMEOUT_MS: u64 = 3000;
const TOTAL_TIMEOUT_MS: u64 = 8000;
const MAX_HOTFIX_BYTES: u64 = 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Result of an online pattern fetch attempt.
#[derive(Debug)]
pub enum FetchResult {
    Updated(PathBuf),
    AlreadyCurrent,
    Failed(String),
}

#[derive(Debug, Eq, PartialEq)]
pub enum PromotionResult {
    NoCandidate,
    AlreadyActive(PathBuf),
    Published(PathBuf),
}

/// Fetch and atomically cache one target-specific candidate.
pub fn fetch_and_cache(url: &str, target: PatternTarget) -> FetchResult {
    let candidate_path = match pattern_candidate_path(target, url) {
        Some(path) => path,
        None => {
            return FetchResult::Failed(
                "candidate path is unavailable or the expanded source URL is not HTTPS".to_owned(),
            )
        }
    };
    let body = match do_fetch(url) {
        Ok(b) => b,
        Err(e) => return FetchResult::Failed(e),
    };

    match cache_candidate(&candidate_path, body.as_bytes(), target) {
        Ok(false) => {
            debug!("online-patterns: cached hotfix is current");
            FetchResult::AlreadyCurrent
        }
        Ok(true) => {
            info!(
                path = %candidate_path.display(),
                "online-patterns: updated candidate file"
            );
            FetchResult::Updated(candidate_path)
        }
        Err(e) => FetchResult::Failed(format!("write failed: {e}")),
    }
}

/// Spawn a background thread that fetches and caches online patterns.
pub fn spawn_fetch(url_template: String, target: PatternTarget) {
    let result = std::thread::Builder::new()
        .name("online-patterns".into())
        .spawn(move || {
            let url = match expand_source_url(&url_template, target) {
                Ok(url) => url,
                Err(error) => {
                    warn!(%error, "online-patterns: invalid URL template");
                    return;
                }
            };
            match fetch_and_cache(&url, target) {
                FetchResult::Updated(p) => {
                    info!(path = %p.display(), "online-patterns: candidate cached for live validation");
                }
                FetchResult::AlreadyCurrent => {
                    debug!("online-patterns: candidate is current");
                }
                FetchResult::Failed(e) => {
                    warn!(error = %e, "online-patterns: fetch failed");
                }
            }
        });
    if let Err(error) = result {
        warn!(%error, "online-patterns: fetch thread could not be started");
    }
}

fn do_fetch(url: &str) -> Result<String, String> {
    if !url.starts_with("https://") {
        return Err("hotfix URL must use HTTPS".to_owned());
    }
    let agent = fetch_agent();

    let body = agent
        .get(url)
        .call()
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .body_mut()
        .with_config()
        .limit(MAX_HOTFIX_BYTES)
        .read_to_string()
        .map_err(|e| format!("read body failed: {e}"))?;

    if body.is_empty() {
        return Err("empty response".into());
    }

    Ok(body)
}

fn fetch_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .timeout_connect(Some(std::time::Duration::from_millis(CONNECT_TIMEOUT_MS)))
        .timeout_global(Some(std::time::Duration::from_millis(TOTAL_TIMEOUT_MS)))
        .build()
        .new_agent()
}

pub fn pattern_cache_path(target: PatternTarget, module: &str) -> Option<PathBuf> {
    if !matches!(module, "steamclient" | "steamui") {
        return None;
    }
    let home = std::env::var("HOME").ok()?;
    Some(
        std::path::Path::new(&home)
            .join(".config/vapor-forge")
            .join(active_pattern_file_name(target, module)),
    )
}

pub fn pattern_candidate_path(target: PatternTarget, expanded_url: &str) -> Option<PathBuf> {
    if !expanded_url.starts_with("https://") {
        return None;
    }
    let home = std::env::var("HOME").ok()?;
    Some(
        std::path::Path::new(&home)
            .join(".config/vapor-forge")
            .join(candidate_pattern_file_name(target, expanded_url)),
    )
}

pub fn validate_and_promote_candidate(
    url_template: &str,
    target: PatternTarget,
    module: &str,
    validate: impl FnOnce(&[u8]) -> Result<(), String>,
) -> Result<PromotionResult, String> {
    let expanded_url = expand_source_url(url_template, target)?;
    let candidate_path = pattern_candidate_path(target, &expanded_url)
        .ok_or_else(|| "HOME is unavailable; candidate path cannot be resolved".to_owned())?;
    let active_path = pattern_cache_path(target, module)
        .ok_or_else(|| format!("unsupported pattern module {module:?}"))?;
    validate_and_promote_candidate_at(&candidate_path, &active_path, target, validate)
}

fn active_pattern_file_name(target: PatternTarget, module: &str) -> String {
    format!(
        "patterns.{}.{}.{}.toml",
        target.architecture.as_str(),
        target.binary_family.as_str(),
        module,
    )
}

fn candidate_pattern_file_name(target: PatternTarget, expanded_url: &str) -> String {
    format!(
        "patterns.{}.{}.{}.candidate.toml",
        target.architecture.as_str(),
        target.binary_family.as_str(),
        source_sha256(expanded_url),
    )
}

fn expand_source_url(template: &str, target: PatternTarget) -> Result<String, String> {
    if !template.contains("{arch}") || !template.contains("{family}") {
        return Err("patterns_url must contain {arch} and {family}".to_owned());
    }
    let expanded = template
        .replace("{arch}", target.architecture.as_str())
        .replace("{family}", target.binary_family.as_str());
    if !expanded.starts_with("https://") {
        return Err("hotfix URL must use HTTPS".to_owned());
    }
    Ok(expanded)
}

fn source_sha256(source: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(source.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn cache_candidate(
    path: &std::path::Path,
    content: &[u8],
    target: PatternTarget,
) -> Result<bool, String> {
    with_path_lock(path, || {
        let incoming_revision = hotfix_revision(content, target, "downloaded candidate")?;
        let current = match std::fs::read(path) {
            Ok(current) => Some(current),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "candidate {} could not be read: {error}",
                    path.display()
                ))
            }
        };
        if let Some(current) = current {
            match hotfix_revision(&current, target, "cached candidate") {
                Ok(current_revision) if incoming_revision < current_revision => {
                    return Err(format!(
                        "candidate revision {incoming_revision} is older than cached revision {current_revision}"
                    ));
                }
                Ok(current_revision) if incoming_revision == current_revision => {
                    if current == content {
                        return Ok(false);
                    }
                    return Err(format!(
                        "candidate revision {incoming_revision} has different cached content"
                    ));
                }
                Ok(_) => {}
                Err(error) => {
                    warn!(path = %path.display(), %error, "online-patterns: replacing invalid candidate");
                }
            }
        }
        publish_atomically(path, content)?;
        Ok(true)
    })
}

fn validate_and_promote_candidate_at(
    candidate_path: &std::path::Path,
    active_path: &std::path::Path,
    target: PatternTarget,
    validate: impl FnOnce(&[u8]) -> Result<(), String>,
) -> Result<PromotionResult, String> {
    with_path_lock(candidate_path, move || {
        let content = match std::fs::read(candidate_path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PromotionResult::NoCandidate);
            }
            Err(error) => {
                return Err(format!(
                    "candidate {} could not be read: {error}",
                    candidate_path.display()
                ));
            }
        };
        let candidate_revision = hotfix_revision(&content, target, "candidate")?;
        with_path_lock(active_path, move || {
            let active = match std::fs::read(active_path) {
                Ok(active) => Some(active),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(format!(
                        "active cache {} could not be read: {error}",
                        active_path.display()
                    ));
                }
            };
            if let Some(active) = active {
                match hotfix_revision(&active, target, "active cache") {
                    Ok(active_revision) if candidate_revision < active_revision => {
                        return Err(format!(
                            "candidate revision {candidate_revision} is older than active revision {active_revision}"
                        ));
                    }
                    Ok(active_revision) if candidate_revision == active_revision => {
                        if active == content {
                            return Ok(PromotionResult::AlreadyActive(active_path.to_path_buf()));
                        }
                        return Err(format!(
                            "candidate revision {candidate_revision} has different active content"
                        ));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        warn!(path = %active_path.display(), %error, "online-patterns: replacing invalid active cache");
                    }
                }
            }
            validate(&content)?;
            publish_atomically(active_path, &content)?;
            Ok(PromotionResult::Published(active_path.to_path_buf()))
        })
    })
}

fn hotfix_revision(
    content: &[u8],
    target: PatternTarget,
    description: &str,
) -> Result<u64, String> {
    let text = std::str::from_utf8(content)
        .map_err(|error| format!("{description} is not UTF-8: {error}"))?;
    PatternRegistry::from_hotfix_text(text, target)
        .map_err(|error| format!("invalid {description}: {error}"))?
        .hotfix_revision()
        .ok_or_else(|| format!("{description} has no revision"))
}

fn with_path_lock<T>(
    path: &std::path::Path,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "cache path has no parent directory".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|error| format!("mkdir failed: {error}"))?;
    let lock_path = path_lock_path(path)?;
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| format!("lock {} could not be opened: {error}", lock_path.display()))?;
    lock_file
        .lock_exclusive()
        .map_err(|error| format!("lock {} failed: {error}", lock_path.display()))?;
    let _guard = PathLockGuard(&lock_file);
    operation()
}

fn path_lock_path(path: &std::path::Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "cache path has no parent directory".to_owned())?;
    let file_name = path
        .file_name()
        .ok_or_else(|| "cache path has no file name".to_owned())?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(parent.join(lock_name))
}

struct PathLockGuard<'a>(&'a std::fs::File);

impl Drop for PathLockGuard<'_> {
    fn drop(&mut self) {
        let _ = FileExt::unlock(self.0);
    }
}

fn publish_atomically(path: &std::path::Path, content: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "cache path has no parent directory".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|error| format!("mkdir failed: {error}"))?;

    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "cache path has an invalid file name".to_owned())?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("temporary file create failed: {error}"))?;
        file.write_all(content)
            .map_err(|error| format!("temporary file write failed: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("temporary file sync failed: {error}"))?;
        std::fs::rename(&temporary, path)
            .map_err(|error| format!("cache publish failed: {error}"))?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cache directory sync failed: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Barrier};
    use vapor_forge_patterns::registry::{PatternArchitecture, PatternTarget, SteamBinaryFamily};

    const TARGET: PatternTarget = PatternTarget {
        architecture: PatternArchitecture::X86_64,
        binary_family: SteamBinaryFamily::SteamRt,
    };

    const SOURCE_A: &str = "https://patterns-a.example/x86_64/steamrt.toml";
    const SOURCE_B: &str = "https://patterns-b.example/x86_64/steamrt.toml";

    fn hotfix(revision: u64, pattern: &str) -> Vec<u8> {
        format!(
            r#"[hotfix]
format = 1
revision = {revision}
architecture = "x86_64"
binary_family = "steamrt"

[steamclient."CUser::CheckAppOwnership"]
pattern = "{pattern}"
"#
        )
        .into_bytes()
    }

    #[test]
    fn url_template_selects_architecture_and_family() {
        let url =
            expand_source_url("https://patterns.example/{arch}/{family}.toml", TARGET).unwrap();
        assert_eq!(url, "https://patterns.example/x86_64/steamrt.toml");
    }

    #[test]
    fn url_template_requires_both_target_dimensions() {
        assert!(expand_source_url("https://patterns.example/x86_64.toml", TARGET).is_err());
        assert!(expand_source_url("http://patterns.example/{arch}/{family}.toml", TARGET).is_err());
    }

    #[test]
    fn fetch_transport_rejects_non_https_redirects() {
        assert!(fetch_agent().config().https_only());
    }

    #[test]
    fn atomic_publish_replaces_the_complete_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("patterns.x86_64.steamrt.toml");
        std::fs::write(&path, b"old").unwrap();

        publish_atomically(&path, b"new content").unwrap();

        assert_eq!(std::fs::read(path).unwrap(), b"new content");
    }

    #[test]
    fn candidate_isolated_by_source_while_active_is_source_independent() {
        let candidate_a = candidate_pattern_file_name(TARGET, SOURCE_A);
        let candidate_b = candidate_pattern_file_name(TARGET, SOURCE_B);
        assert_ne!(candidate_a, candidate_b);
        assert!(candidate_a.starts_with("patterns.x86_64.steamrt."));
        assert!(candidate_a.ends_with(".candidate.toml"));
        assert_eq!(
            candidate_a.len(),
            "patterns.x86_64.steamrt.".len() + 64 + ".candidate.toml".len()
        );
        assert_eq!(
            active_pattern_file_name(TARGET, "steamui"),
            "patterns.x86_64.steamrt.steamui.toml"
        );
    }

    #[test]
    fn active_cache_is_isolated_by_module() {
        assert_ne!(
            active_pattern_file_name(TARGET, "steamclient"),
            active_pattern_file_name(TARGET, "steamui")
        );
    }

    #[test]
    fn cache_namespaces_cover_every_architecture_and_family() {
        let targets = [
            PatternTarget {
                architecture: PatternArchitecture::X86,
                binary_family: SteamBinaryFamily::Ordinary,
            },
            PatternTarget {
                architecture: PatternArchitecture::X86,
                binary_family: SteamBinaryFamily::SteamRt,
            },
            PatternTarget {
                architecture: PatternArchitecture::X86_64,
                binary_family: SteamBinaryFamily::Ordinary,
            },
            PatternTarget {
                architecture: PatternArchitecture::X86_64,
                binary_family: SteamBinaryFamily::SteamRt,
            },
        ];
        let active_names = targets
            .iter()
            .map(|target| active_pattern_file_name(*target, "steamclient"))
            .collect::<BTreeSet<_>>();
        let candidate_names = targets
            .iter()
            .map(|target| candidate_pattern_file_name(*target, SOURCE_A))
            .collect::<BTreeSet<_>>();

        assert_eq!(active_names.len(), targets.len());
        assert_eq!(candidate_names.len(), targets.len());
    }

    #[test]
    fn rejected_candidate_does_not_replace_active() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("candidate.toml");
        let active = directory.path().join("active.toml");
        let candidate_content = hotfix(2, "AA BB CC");
        let active_content = hotfix(1, "11 22 33");
        std::fs::write(&candidate, &candidate_content).unwrap();
        std::fs::write(&active, &active_content).unwrap();

        let result = validate_and_promote_candidate_at(&candidate, &active, TARGET, |_| {
            Err("semantic rejection".to_owned())
        });

        assert_eq!(result.unwrap_err(), "semantic rejection");
        assert_eq!(std::fs::read(active).unwrap(), active_content);
    }

    #[test]
    fn unchanged_active_is_validated_only_by_the_active_loader() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("candidate.toml");
        let active = directory.path().join("active.toml");
        let content = hotfix(1, "AA BB CC");
        std::fs::write(&candidate, &content).unwrap();
        std::fs::write(&active, &content).unwrap();

        let result = validate_and_promote_candidate_at(&candidate, &active, TARGET, |_| {
            panic!("unchanged candidate must not be revalidated before active loading")
        })
        .unwrap();

        assert_eq!(result, PromotionResult::AlreadyActive(active));
    }

    #[test]
    fn module_active_files_are_promoted_independently() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("candidate.toml");
        let steamclient = directory.path().join("steamclient.toml");
        let steamui = directory.path().join("steamui.toml");
        let content = hotfix(1, "AA BB CC");
        std::fs::write(&candidate, &content).unwrap();

        validate_and_promote_candidate_at(&candidate, &steamclient, TARGET, |_| Ok(())).unwrap();

        assert_eq!(std::fs::read(steamclient).unwrap(), content);
        assert!(!steamui.exists());
    }

    #[test]
    fn candidate_revision_is_monotonic() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("candidate.toml");
        let revision_two = hotfix(2, "AA BB CC");

        assert!(cache_candidate(&candidate, &revision_two, TARGET).unwrap());
        assert!(!cache_candidate(&candidate, &revision_two, TARGET).unwrap());

        let same_revision =
            cache_candidate(&candidate, &hotfix(2, "11 22 33"), TARGET).unwrap_err();
        assert!(same_revision.contains("different cached content"));

        let older = cache_candidate(&candidate, &hotfix(1, "44 55 66"), TARGET).unwrap_err();
        assert!(older.contains("older than cached revision 2"));

        let revision_three = hotfix(3, "77 88 99");
        assert!(cache_candidate(&candidate, &revision_three, TARGET).unwrap());
        assert_eq!(std::fs::read(candidate).unwrap(), revision_three);
    }

    #[test]
    fn promotion_revision_is_monotonic() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("candidate.toml");
        let active = directory.path().join("active.toml");
        let active_content = hotfix(2, "AA BB CC");
        std::fs::write(&active, &active_content).unwrap();

        std::fs::write(&candidate, hotfix(1, "11 22 33")).unwrap();
        let older =
            validate_and_promote_candidate_at(&candidate, &active, TARGET, |_| Ok(())).unwrap_err();
        assert!(older.contains("older than active revision 2"));

        std::fs::write(&candidate, hotfix(2, "44 55 66")).unwrap();
        let same_revision =
            validate_and_promote_candidate_at(&candidate, &active, TARGET, |_| Ok(())).unwrap_err();
        assert!(same_revision.contains("different active content"));

        let newer_content = hotfix(3, "77 88 99");
        std::fs::write(&candidate, &newer_content).unwrap();
        let result =
            validate_and_promote_candidate_at(&candidate, &active, TARGET, |_| Ok(())).unwrap();
        assert_eq!(result, PromotionResult::Published(active.clone()));
        assert_eq!(std::fs::read(active).unwrap(), newer_content);
    }

    #[test]
    fn source_switch_reads_only_the_selected_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let source_a = directory
            .path()
            .join(candidate_pattern_file_name(TARGET, SOURCE_A));
        let source_b = directory
            .path()
            .join(candidate_pattern_file_name(TARGET, SOURCE_B));
        let active = directory.path().join("active.toml");
        std::fs::write(&source_a, hotfix(1, "AA BB CC")).unwrap();

        let result =
            validate_and_promote_candidate_at(&source_b, &active, TARGET, |_| Ok(())).unwrap();
        assert_eq!(result, PromotionResult::NoCandidate);
        assert!(!active.exists());

        let source_b_content = hotfix(2, "11 22 33");
        std::fs::write(&source_b, &source_b_content).unwrap();
        validate_and_promote_candidate_at(&source_b, &active, TARGET, |_| Ok(())).unwrap();
        assert_eq!(std::fs::read(active).unwrap(), source_b_content);
    }

    #[test]
    fn missing_selected_candidate_keeps_existing_active_cache() {
        let directory = tempfile::tempdir().unwrap();
        let selected = directory
            .path()
            .join(candidate_pattern_file_name(TARGET, SOURCE_B));
        let active = directory.path().join("active.toml");
        let active_content = hotfix(4, "AA BB CC");
        std::fs::write(&active, &active_content).unwrap();

        let result =
            validate_and_promote_candidate_at(&selected, &active, TARGET, |_| Ok(())).unwrap();

        assert_eq!(result, PromotionResult::NoCandidate);
        assert_eq!(std::fs::read(active).unwrap(), active_content);
    }

    #[test]
    fn wrong_architecture_candidate_does_not_replace_active_cache() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("candidate.toml");
        let active = directory.path().join("active.toml");
        let active_content = hotfix(1, "AA BB CC");
        let wrong_architecture = String::from_utf8(hotfix(2, "11 22 33"))
            .unwrap()
            .replace("architecture = \"x86_64\"", "architecture = \"x86\"");
        std::fs::write(&candidate, wrong_architecture).unwrap();
        std::fs::write(&active, &active_content).unwrap();

        let error = validate_and_promote_candidate_at(&candidate, &active, TARGET, |_| {
            panic!("wrong target must be rejected before semantic validation")
        })
        .unwrap_err();

        assert!(error.contains("hotfix target is x86/steamrt"));
        assert_eq!(std::fs::read(active).unwrap(), active_content);
    }

    #[test]
    fn candidate_update_waits_for_validation_and_publication() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("candidate.toml");
        let active = directory.path().join("active.toml");
        let first = hotfix(1, "AA BB CC");
        let second = hotfix(2, "11 22 33");
        std::fs::write(&candidate, &first).unwrap();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));

        std::thread::scope(|scope| {
            let entered_for_validation = Arc::clone(&entered);
            let release_validation = Arc::clone(&release);
            let validation_candidate = candidate.clone();
            let validation_active = active.clone();
            let validation_content = first.clone();
            let validation = scope.spawn(move || {
                validate_and_promote_candidate_at(
                    &validation_candidate,
                    &validation_active,
                    TARGET,
                    |content| {
                        assert_eq!(content, validation_content);
                        entered_for_validation.wait();
                        release_validation.wait();
                        Ok(())
                    },
                )
                .unwrap();
            });
            entered.wait();

            let update_candidate = candidate.clone();
            let update_content = second.clone();
            let update = scope.spawn(move || {
                cache_candidate(&update_candidate, &update_content, TARGET).unwrap()
            });
            release.wait();
            validation.join().unwrap();
            assert!(update.join().unwrap());
        });

        assert_eq!(std::fs::read(&active).unwrap(), first);
        assert_eq!(std::fs::read(&candidate).unwrap(), second);
        validate_and_promote_candidate_at(&candidate, &active, TARGET, |_| Ok(())).unwrap();
        assert_eq!(std::fs::read(active).unwrap(), second);
    }

    #[test]
    fn different_sources_share_the_active_revision_lock() {
        let directory = tempfile::tempdir().unwrap();
        let high_candidate = directory.path().join("high.candidate.toml");
        let low_candidate = directory.path().join("low.candidate.toml");
        let active = directory.path().join("active.toml");
        let initial = hotfix(1, "AA BB CC");
        let low = hotfix(2, "11 22 33");
        let high = hotfix(3, "44 55 66");
        std::fs::write(&active, initial).unwrap();
        std::fs::write(&low_candidate, low).unwrap();
        std::fs::write(&high_candidate, &high).unwrap();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));

        std::thread::scope(|scope| {
            let high_active = active.clone();
            let entered_high = Arc::clone(&entered);
            let release_high = Arc::clone(&release);
            let high_promotion = scope.spawn(move || {
                validate_and_promote_candidate_at(&high_candidate, &high_active, TARGET, |_| {
                    entered_high.wait();
                    release_high.wait();
                    Ok(())
                })
                .unwrap()
            });
            entered.wait();

            let low_active = active.clone();
            let low_promotion = scope.spawn(move || {
                validate_and_promote_candidate_at(&low_candidate, &low_active, TARGET, |_| {
                    panic!("older candidate must be rejected before semantic validation")
                })
            });
            release.wait();

            assert_eq!(
                high_promotion.join().unwrap(),
                PromotionResult::Published(active.clone())
            );
            let error = low_promotion.join().unwrap().unwrap_err();
            assert!(error.contains("older than active revision 3"));
        });

        assert_eq!(std::fs::read(active).unwrap(), high);
    }
}
