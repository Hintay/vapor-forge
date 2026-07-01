use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use inotify::{Inotify, WatchMask};
use steam_runtime_config::{AppId, RuntimeConfig};
use steam_runtime_features::package::PackageState;
use steam_runtime_scripting::ScriptState;
use tracing::{debug, info, warn};

pub fn start(
    config_store: &'static ArcSwap<RuntimeConfig>,
    script_store: &'static ArcSwap<ScriptState>,
    package_state: &'static PackageState,
    config_path: Option<PathBuf>,
) {
    let Some(path) = config_path else {
        debug!("watcher: no config file to watch");
        return;
    };

    std::thread::Builder::new()
        .name("config-watcher".into())
        .spawn(move || watch_loop(path, config_store, script_store, package_state))
        .ok();
}

fn watch_loop(
    path: PathBuf,
    config_store: &'static ArcSwap<RuntimeConfig>,
    script_store: &'static ArcSwap<ScriptState>,
    package_state: &'static PackageState,
) {
    let mut inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "watcher: inotify init failed");
            return;
        }
    };

    let dir = match path.parent() {
        Some(d) => d,
        None => return,
    };

    if let Err(e) = inotify.watches().add(
        dir,
        WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::CREATE,
    ) {
        warn!(error = %e, dir = %dir.display(), "watcher: add watch failed");
        return;
    }

    let filename = match path.file_name() {
        Some(f) => f.to_owned(),
        None => return,
    };

    info!(path = %path.display(), "watcher: watching config");

    let mut buf = [0u8; 4096];
    loop {
        let events = match inotify.read_events_blocking(&mut buf) {
            Ok(events) => events,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                warn!(error = %e, "watcher: read_events failed");
                return;
            }
        };

        let matched = events
            .into_iter()
            .any(|event| event.name.as_deref() == Some(OsStr::new(&filename)));

        if matched {
            std::thread::sleep(std::time::Duration::from_millis(50));
            reload_config(&path, config_store, script_store, package_state);
        }
    }
}

fn reload_config(
    path: &PathBuf,
    config_store: &'static ArcSwap<RuntimeConfig>,
    script_store: &'static ArcSwap<ScriptState>,
    package_state: &'static PackageState,
) {
    match RuntimeConfig::load(path) {
        Ok(mut new_config) => {
            // Re-execute Lua scripts
            let new_script_state = if !new_config.scripting.paths.is_empty() {
                steam_runtime_scripting::execute_scripts(&new_config.scripting.paths)
            } else {
                ScriptState::default()
            };

            // Merge script apps into config (same as initial load)
            let existing_ids: std::collections::HashSet<AppId> =
                new_config.apps.inject.iter().map(|a| a.id).collect();
            for &app_id in &new_script_state.apps {
                if !existing_ids.contains(&app_id) {
                    new_config
                        .apps
                        .inject
                        .push(steam_runtime_config::InjectApp {
                            id: app_id,
                            dlc: Vec::new(),
                            ticket: Default::default(),
                            purchase_time: 0,
                        });
                }
            }

            let inject_count = new_config.apps.inject.len();
            let dlc_count: usize = new_config.apps.inject.iter().map(|a| a.dlc.len()).sum();

            // Compute pkg0 diff BEFORE updating stores
            let controlled = steam_runtime_features::package::controlled_app_ids(
                &new_config,
                &new_script_state.apps,
            );
            let diff = package_state.compute_hot_reload_diff(&controlled);

            // Reload AppAvatar static map (config + lua).
            steam_runtime_features::app_avatar::load_static_map(&new_config.app_avatar);
            for (&app, &avatar) in &new_script_state.avatars {
                steam_runtime_features::app_avatar::set_avatar(app, avatar);
            }

            // Update stores
            config_store.store(Arc::new(new_config));
            script_store.store(Arc::new(new_script_state));

            // Apply pkg0 diff if pkg0 injection is active
            if package_state.is_active()
                && (!diff.additions.is_empty() || !diff.removals.is_empty())
            {
                // SAFETY: pkg0 and cuser are captured when package_state is active,
                // and all function pointers are resolved.
                unsafe { crate::package::apply_reload_diff(&diff) };
                package_state.apply_diff(&diff);
                info!(
                    additions = diff.additions.len(),
                    removals = diff.removals.len(),
                    "watcher: pkg0 diff applied"
                );
            }

            info!(inject = inject_count, dlc = dlc_count, "config reloaded");
        }
        Err(e) => {
            warn!(error = %e, "watcher: reload failed, keeping previous");
        }
    }
}
