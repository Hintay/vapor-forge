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
use vapor_forge_config::{AppId, LibraryInjectEntry, LibraryInjectSection};

/// Resolved injection for a single game launch.
pub struct PendingInjection {
    pub native_libs: Vec<String>,   // .so paths for LD_PRELOAD
    pub proton_dll: Option<String>, // .dll path for Proton helper
    /// Load the Proton helper so it can disable thread callouts on duplicate
    /// module loader entries (see `LoaderFixSection`).
    pub loader_fix: bool,
}

static PENDING: Mutex<Option<HashMap<AppId, PendingInjection>>> = Mutex::new(None);

/// Whether the section asks for the duplicate-module loader fix on this
/// launch: listed in `apps` or carrying `flag`, and not excluded.
pub fn loader_fix_requested(
    section: &LibraryInjectSection,
    app_id: AppId,
    launch_opts: &str,
) -> bool {
    let fix = &section.loader_fix;
    if fix.exclude.contains(&app_id) {
        return false;
    }
    fix.apps.contains(&app_id)
        || (!fix.flag.is_empty() && crate::launch_options::flag_appears_in(launch_opts, &fix.flag))
}

/// Whether the section can produce any injection at all (fast path for hooks).
pub fn section_is_active(section: &LibraryInjectSection) -> bool {
    !section.libs.is_empty()
        || !section.loader_fix.apps.is_empty()
        || !section.loader_fix.flag.is_empty()
}

/// Evaluate every rule of the section for an app launch.
pub fn on_launch_section(app_id: AppId, section: &LibraryInjectSection, launch_opts: &str) {
    let loader_fix = loader_fix_requested(section, app_id, launch_opts);
    evaluate(app_id, &section.libs, loader_fix, launch_opts);
}

/// Evaluate injection rules for an app launch.
/// `launch_opts` comes from CConfigStore (read in the hooks layer).
pub fn on_launch_app(app_id: AppId, libs: &[LibraryInjectEntry], launch_opts: &str) {
    evaluate(app_id, libs, false, launch_opts);
}

fn evaluate(app_id: AppId, libs: &[LibraryInjectEntry], loader_fix: bool, launch_opts: &str) {
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

    if !native_libs.is_empty() || proton_dll.is_some() || loader_fix {
        let native_count = native_libs.len();
        let has_dll = proton_dll.is_some();
        info!(
            app = app_id.0,
            native = native_count,
            dll = has_dll,
            loader_fix,
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
                    loader_fix,
                },
            );
    }
}

/// Merge the native libraries into the `LD_PRELOAD` value Steam is about to
/// write for the child process.
///
/// Steam composes that value from its own environment plus the overlay
/// renderers and writes it after BuildSpawnEnvBlock's callers have run, so a
/// value stored earlier in the map is lost. Our entries go first and keep
/// Steam's list, including its empty leading component, untouched.
pub fn merge_ld_preload(native_libs: &[String], steam_value: &str) -> String {
    let existing: Vec<&str> = steam_value.split(':').collect();
    let mut merged: Vec<&str> = native_libs
        .iter()
        .map(String::as_str)
        .filter(|lib| !lib.is_empty() && !existing.contains(lib))
        .collect();
    if merged.is_empty() {
        return steam_value.to_owned();
    }
    if !steam_value.is_empty() {
        merged.push(steam_value);
    }
    merged.join(":")
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
    use vapor_forge_config::LoaderFixSection;

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

    fn section(apps: Vec<u32>, flag: &str) -> LibraryInjectSection {
        section_with_exclude(apps, Vec::new(), flag)
    }

    fn section_with_exclude(apps: Vec<u32>, exclude: Vec<u32>, flag: &str) -> LibraryInjectSection {
        LibraryInjectSection {
            libs: Vec::new(),
            helper_path: String::new(),
            loader_fix: LoaderFixSection {
                apps: apps.into_iter().map(AppId).collect(),
                exclude: exclude.into_iter().map(AppId).collect(),
                flag: flag.to_owned(),
            },
        }
    }

    #[test]
    fn loader_fix_exclude_wins_over_apps_and_flag() {
        let app = AppId(999105);
        let section = section_with_exclude(vec![app.0], vec![app.0], "-loaderfix");
        on_launch_section(app, &section, "-loaderfix %command%");
        assert!(take_pending(app).is_none());
    }

    #[test]
    fn loader_fix_app_list_sets_pending_without_libraries() {
        let app = AppId(999101);
        let section = section(vec![app.0], "");
        assert!(section_is_active(&section));
        on_launch_section(app, &section, "");
        let p = take_pending(app).unwrap();
        assert!(p.loader_fix);
        assert!(p.native_libs.is_empty());
        assert!(p.proton_dll.is_none());
    }

    #[test]
    fn loader_fix_flag_requires_the_launch_option() {
        let app = AppId(999102);
        let section = section(vec![], "-loaderfix");
        on_launch_section(app, &section, "PROTON_LOG=1 %command%");
        assert!(take_pending(app).is_none());
        on_launch_section(app, &section, "-loaderfix %command%");
        assert!(take_pending(app).unwrap().loader_fix);
    }

    #[test]
    fn merge_ld_preload_puts_our_libraries_before_steams() {
        let ours = vec!["/home/u/a.so".to_owned(), "/home/u/b.so".to_owned()];
        let steam =
            ":/steam/ubuntu12_32/gameoverlayrenderer.so:/steam/ubuntu12_64/gameoverlayrenderer.so";
        assert_eq!(
            merge_ld_preload(&ours, steam),
            format!("/home/u/a.so:/home/u/b.so:{steam}")
        );
        assert_eq!(merge_ld_preload(&ours, ""), "/home/u/a.so:/home/u/b.so");
    }

    #[test]
    fn merge_ld_preload_skips_duplicates_and_empty_entries() {
        let ours = vec!["/home/u/a.so".to_owned(), String::new()];
        assert_eq!(
            merge_ld_preload(&ours, "/x.so:/home/u/a.so"),
            "/x.so:/home/u/a.so"
        );
        assert_eq!(merge_ld_preload(&[], "/x.so"), "/x.so");
    }

    #[test]
    fn loader_fix_is_off_for_other_apps() {
        let app = AppId(999103);
        let section = section(vec![999104], "");
        on_launch_section(app, &section, "");
        assert!(take_pending(app).is_none());
        assert!(!section_is_active(&LibraryInjectSection::default()));
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
