//! Native .so injection: evaluate LD_PRELOAD rules at LaunchApp time and hand
//! the resolved paths to the BuildSpawnEnvBlock hook (hooks crate) so it can
//! write LD_PRELOAD into the child process env block.
//!
//! Priority/filtering mirrors app_avatar: apps/exclude filters plus an
//! optional flag filter read from the user's launch options string.
//!
//! The unsafe CConfigStore read and SetEnvString call live in the hooks
//! crate, not here. on_launch_app receives the already-read launch options.

use std::collections::HashMap;
use std::sync::Mutex;

use steam_runtime_config::{AppId, LibraryInjectEntry};
use tracing::{debug, info};

// Pending injections keyed by AppId, set at LaunchApp time and consumed once
// by the BuildSpawnEnvBlock hook for that launch.
static PENDING: Mutex<Option<HashMap<AppId, Vec<String>>>> = Mutex::new(None);

/// Evaluate injection rules for an app launch.
/// `launch_opts` comes from CConfigStore (read in the hooks layer).
pub fn on_launch_app(app_id: AppId, libs: &[LibraryInjectEntry], launch_opts: &str) {
    // Clear any previous pending injection for this app before re-evaluating.
    if let Some(map) = PENDING.lock().unwrap().as_mut() {
        map.remove(&app_id);
    }

    let mut paths = Vec::new();
    for lib in libs {
        // App filter: apps list restricts, exclude always wins.
        if !lib.apps.is_empty() && !lib.apps.contains(&app_id) {
            continue;
        }
        if lib.exclude.contains(&app_id) {
            continue;
        }

        // Flag filter: only match when the launch options contain the flag
        // as a whole word.
        if !lib.flag.is_empty() {
            if launch_opts.is_empty() {
                continue;
            }
            if !flag_appears_in(launch_opts, &lib.flag) {
                continue;
            }
        }

        // Only .so files are supported for native injection in this phase.
        if !lib.path.ends_with(".so") && !lib.path.contains(".so.") {
            debug!(path = %lib.path, "library_inject: skipping non-.so file");
            continue;
        }

        paths.push(lib.path.clone());
    }

    if !paths.is_empty() {
        info!(app = app_id.0, count = paths.len(), "library_inject: pending injection set");
        PENDING
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(app_id, paths);
    }
}

/// Get pending injection paths for an app and consume them.
pub fn take_pending(app_id: AppId) -> Vec<String> {
    PENDING
        .lock()
        .unwrap()
        .as_mut()
        .and_then(|map| map.remove(&app_id))
        .unwrap_or_default()
}

/// Check if any injections are pending (fast path).
pub fn has_pending() -> bool {
    PENDING
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|map| !map.is_empty())
}

/// Word-boundary substring match for launch option flags.
///
/// A match is valid when the needle is surrounded by whitespace, quotes, or
/// string boundaries, preventing "-onlinefixfoo" from matching "-onlinefix".
fn flag_appears_in(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    let mut pos = 0;
    while pos + n.len() <= h.len() {
        if let Some(found) = haystack[pos..].find(needle) {
            let abs = pos + found;
            let before = if abs > 0 { h[abs - 1] } else { b' ' };
            let after_pos = abs + n.len();
            let after = if after_pos < h.len() { h[after_pos] } else { 0 };
            let sep = |b: u8| matches!(b, b' ' | b'\t' | b'"' | b'\'' | 0);
            if sep(before) && sep(after) {
                return true;
            }
            pos = abs + n.len();
        } else {
            break;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, flag: &str, apps: Vec<u32>, exclude: Vec<u32>) -> LibraryInjectEntry {
        LibraryInjectEntry {
            path: path.to_owned(),
            flag: flag.to_owned(),
            apps: apps.into_iter().map(AppId).collect(),
            exclude: exclude.into_iter().map(AppId).collect(),
        }
    }

    #[test]
    fn flag_word_boundary() {
        assert!(flag_appears_in("-onlinefix -other", "-onlinefix"));
        assert!(flag_appears_in("-onlinefix", "-onlinefix"));
        assert!(!flag_appears_in("-onlinefixfoo", "-onlinefix"));
        assert!(!flag_appears_in("foo-onlinefix", "-onlinefix"));
        assert!(flag_appears_in("\"-onlinefix\"", "-onlinefix"));
    }

    #[test]
    fn no_rules_means_no_pending() {
        let app = AppId(999001);
        on_launch_app(app, &[], "");
        assert!(take_pending(app).is_empty());
    }

    #[test]
    fn unconditional_rule_sets_pending() {
        let app = AppId(999002);
        let libs = vec![entry("/opt/mylib.so", "", vec![], vec![])];
        on_launch_app(app, &libs, "");
        let pending = take_pending(app);
        assert_eq!(pending, vec!["/opt/mylib.so".to_owned()]);
        // Consumed: a second take should be empty.
        assert!(take_pending(app).is_empty());
    }

    #[test]
    fn app_filter_restricts() {
        let app = AppId(999003);
        let other = AppId(999004);
        let libs = vec![entry("/opt/mylib.so", "", vec![other.0], vec![])];
        on_launch_app(app, &libs, "");
        assert!(take_pending(app).is_empty());
    }

    #[test]
    fn exclude_wins_over_apps() {
        let app = AppId(999005);
        let libs = vec![entry("/opt/mylib.so", "", vec![app.0], vec![app.0])];
        on_launch_app(app, &libs, "");
        assert!(take_pending(app).is_empty());
    }

    #[test]
    fn flag_filter_requires_match() {
        let app = AppId(999006);
        let libs = vec![entry("/opt/mylib.so", "-onlinefix", vec![], vec![])];
        on_launch_app(app, &libs, "");
        assert!(take_pending(app).is_empty());

        on_launch_app(app, &libs, "-onlinefix");
        assert_eq!(take_pending(app), vec!["/opt/mylib.so".to_owned()]);
    }

    #[test]
    fn non_so_paths_are_skipped() {
        let app = AppId(999007);
        let libs = vec![entry("/opt/notalib.txt", "", vec![], vec![])];
        on_launch_app(app, &libs, "");
        assert!(take_pending(app).is_empty());
    }

    #[test]
    fn versioned_so_paths_are_kept() {
        let app = AppId(999008);
        let libs = vec![entry("/opt/mylib.so.1.2", "", vec![], vec![])];
        on_launch_app(app, &libs, "");
        assert_eq!(take_pending(app), vec!["/opt/mylib.so.1.2".to_owned()]);
    }

    #[test]
    fn multiple_matching_libs_are_all_pending() {
        let app = AppId(999009);
        let libs = vec![
            entry("/opt/a.so", "", vec![], vec![]),
            entry("/opt/b.so", "", vec![], vec![]),
        ];
        on_launch_app(app, &libs, "");
        assert_eq!(
            take_pending(app),
            vec!["/opt/a.so".to_owned(), "/opt/b.so".to_owned()]
        );
    }

    #[test]
    fn has_pending_reflects_state() {
        let app = AppId(999010);
        let libs = vec![entry("/opt/mylib.so", "", vec![], vec![])];
        on_launch_app(app, &libs, "");
        assert!(has_pending());
        take_pending(app);
    }
}
