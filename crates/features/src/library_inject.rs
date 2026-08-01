//! Library injection: evaluate rules at SpawnProcess time and hand the
//! resolved paths to the BuildSpawnEnvBlock hook.
//!
//! Two injection modes:
//!   - Native .so: written as LD_PRELOAD
//!   - Proton .dll: written as LD_AUDIT (64-bit helper) + VAPOR_FORGE_INJECT_DLL
//!
//! The unsafe SetEnvString call lives in the hooks crate, not here.

use std::collections::HashMap;
use std::sync::Mutex;

use tracing::{debug, info};
use vapor_forge_config::{AppId, LibraryInjectEntry};

/// Resolved injection for a single game launch.
pub struct PendingInjection {
    pub native_libs: Vec<String>,   // .so paths for LD_PRELOAD
    pub proton_dll: Option<String>, // .dll path for Proton helper
}

static PENDING: Mutex<Option<HashMap<AppId, PendingInjection>>> = Mutex::new(None);

/// Evaluate injection rules for an app launch.
/// `launch_opts` comes from CConfigStore (read in the hooks layer).
pub fn on_launch_app(app_id: AppId, libs: &[LibraryInjectEntry], launch_opts: &str) {
    // Clear any previous pending injection for this app before re-evaluating.
    if let Some(map) = PENDING.lock().unwrap().as_mut() {
        map.remove(&app_id);
    }

    let mut native_libs = Vec::new();
    let mut proton_dll: Option<String> = None;

    for lib in libs {
        if !lib.apps.is_empty() && !lib.apps.contains(&app_id) {
            continue;
        }
        if lib.exclude.contains(&app_id) {
            continue;
        }
        if !lib.flag.is_empty() {
            if launch_opts.is_empty() {
                continue;
            }
            if !crate::launch_options::flag_appears_in(launch_opts, &lib.flag) {
                continue;
            }
        }

        if lib.path.ends_with(".dll") {
            if proton_dll.is_none() {
                proton_dll = Some(lib.path.clone());
            } else {
                debug!(path = %lib.path, "library_inject: only one DLL per launch supported");
            }
        } else if lib.path.ends_with(".so") || lib.path.contains(".so.") {
            native_libs.push(lib.path.clone());
        } else {
            debug!(path = %lib.path, "library_inject: unrecognized extension, skipping");
        }
    }

    if !native_libs.is_empty() || proton_dll.is_some() {
        let native_count = native_libs.len();
        let has_dll = proton_dll.is_some();
        info!(
            app = app_id.0,
            native = native_count,
            dll = has_dll,
            "library_inject: pending injection set"
        );
        PENDING
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(
                app_id,
                PendingInjection {
                    native_libs,
                    proton_dll,
                },
            );
    }
}

/// Get pending injection for an app and consume it.
pub fn take_pending(app_id: AppId) -> Option<PendingInjection> {
    PENDING
        .lock()
        .unwrap()
        .as_mut()
        .and_then(|map| map.remove(&app_id))
}

/// Check if any injections are pending (fast path).
pub fn has_pending() -> bool {
    PENDING
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|map| !map.is_empty())
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
    fn no_rules_means_no_pending() {
        let app = AppId(999001);
        on_launch_app(app, &[], "");
        assert!(take_pending(app).is_none());
    }

    #[test]
    fn unconditional_so_sets_pending() {
        let app = AppId(999002);
        let libs = vec![entry("/opt/mylib.so", "", vec![], vec![])];
        on_launch_app(app, &libs, "");
        let p = take_pending(app).unwrap();
        assert_eq!(p.native_libs, vec!["/opt/mylib.so".to_owned()]);
        assert!(p.proton_dll.is_none());
        assert!(take_pending(app).is_none());
    }

    #[test]
    fn app_filter_restricts() {
        let app = AppId(999003);
        let other = AppId(999004);
        let libs = vec![entry("/opt/mylib.so", "", vec![other.0], vec![])];
        on_launch_app(app, &libs, "");
        assert!(take_pending(app).is_none());
    }

    #[test]
    fn exclude_wins_over_apps() {
        let app = AppId(999005);
        let libs = vec![entry("/opt/mylib.so", "", vec![app.0], vec![app.0])];
        on_launch_app(app, &libs, "");
        assert!(take_pending(app).is_none());
    }

    #[test]
    fn flag_filter_requires_match() {
        let app = AppId(999006);
        let libs = vec![entry("/opt/mylib.so", "-onlinefix", vec![], vec![])];
        on_launch_app(app, &libs, "");
        assert!(take_pending(app).is_none());

        on_launch_app(app, &libs, "-onlinefix");
        let p = take_pending(app).unwrap();
        assert_eq!(p.native_libs, vec!["/opt/mylib.so".to_owned()]);
    }

    #[test]
    fn non_so_non_dll_paths_are_skipped() {
        let app = AppId(999007);
        let libs = vec![entry("/opt/notalib.txt", "", vec![], vec![])];
        on_launch_app(app, &libs, "");
        assert!(take_pending(app).is_none());
    }

    #[test]
    fn versioned_so_paths_are_kept() {
        let app = AppId(999008);
        let libs = vec![entry("/opt/mylib.so.1.2", "", vec![], vec![])];
        on_launch_app(app, &libs, "");
        let p = take_pending(app).unwrap();
        assert_eq!(p.native_libs, vec!["/opt/mylib.so.1.2".to_owned()]);
    }

    #[test]
    fn dll_path_sets_proton_dll() {
        let app = AppId(999011);
        let libs = vec![entry("/opt/mymod.dll", "", vec![], vec![])];
        on_launch_app(app, &libs, "");
        let p = take_pending(app).unwrap();
        assert!(p.native_libs.is_empty());
        assert_eq!(p.proton_dll.as_deref(), Some("/opt/mymod.dll"));
    }

    #[test]
    fn mixed_so_and_dll() {
        let app = AppId(999012);
        let libs = vec![
            entry("/opt/a.so", "", vec![], vec![]),
            entry("/opt/b.dll", "", vec![], vec![]),
        ];
        on_launch_app(app, &libs, "");
        let p = take_pending(app).unwrap();
        assert_eq!(p.native_libs, vec!["/opt/a.so".to_owned()]);
        assert_eq!(p.proton_dll.as_deref(), Some("/opt/b.dll"));
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
