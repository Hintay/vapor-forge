use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use inotify::{Inotify, WatchDescriptor, WatchMask};
use tracing::{debug, info, warn};
use vapor_forge_config::RuntimeConfig;

use crate::client::install::RuntimeSnapshot;

#[derive(Default)]
struct WatchTarget {
    config_names: HashSet<OsString>,
    scripts: bool,
}

#[derive(Default)]
struct WatchSet {
    paths: HashMap<PathBuf, WatchDescriptor>,
    targets: HashMap<WatchDescriptor, WatchTarget>,
}

pub(crate) fn start(
    base_config_store: &'static ArcSwap<RuntimeConfig>,
    runtime_store: &'static ArcSwap<RuntimeSnapshot>,
    config_path: Option<PathBuf>,
) {
    let Some(path) = config_path else {
        debug!("watcher: no config file to watch");
        return;
    };

    std::thread::Builder::new()
        .name("config-script-watcher".into())
        .spawn(move || watch_loop(path, base_config_store, runtime_store))
        .ok();
}

fn watch_loop(
    path: PathBuf,
    base_config_store: &'static ArcSwap<RuntimeConfig>,
    runtime_store: &'static ArcSwap<RuntimeSnapshot>,
) {
    let mut inotify = match Inotify::init() {
        Ok(inotify) => inotify,
        Err(error) => {
            warn!(%error, "watcher: inotify init failed");
            return;
        }
    };
    let mut watches = WatchSet::default();
    register_config_watch(&mut inotify, &mut watches, &path);
    refresh_script_watches(&mut inotify, &mut watches, &base_config_store.load());

    let mut buf = [0u8; 16 * 1024];
    loop {
        let events = match inotify.read_events_blocking(&mut buf) {
            Ok(events) => events,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                warn!(%error, "watcher: read_events failed");
                return;
            }
        };

        let mut config_changed = false;
        let mut lua_changed = false;
        for event in events {
            classify_event(
                &watches,
                &event.wd,
                event.name,
                &mut config_changed,
                &mut lua_changed,
            );
        }

        if config_changed || lua_changed {
            std::thread::sleep(std::time::Duration::from_millis(50));
            loop {
                match inotify.read_events(&mut buf) {
                    Ok(events) => {
                        for event in events {
                            classify_event(
                                &watches,
                                &event.wd,
                                event.name,
                                &mut config_changed,
                                &mut lua_changed,
                            );
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        warn!(%error, "watcher: failed to drain debounced events");
                        break;
                    }
                }
            }
            if config_changed {
                if reload_config(&path, base_config_store, runtime_store) {
                    refresh_script_watches(&mut inotify, &mut watches, &base_config_store.load());
                }
            } else {
                reload_lua(base_config_store, runtime_store);
            }
        }
    }
}

fn classify_event(
    watches: &WatchSet,
    wd: &WatchDescriptor,
    name: Option<&OsStr>,
    config_changed: &mut bool,
    lua_changed: &mut bool,
) {
    let Some(target) = watches.targets.get(wd) else {
        return;
    };
    let Some(name) = name else {
        return;
    };
    if target.config_names.contains(name) {
        *config_changed = true;
    }
    if target.scripts && Path::new(name).extension() == Some(OsStr::new("lua")) {
        *lua_changed = true;
    }
}

fn register_config_watch(inotify: &mut Inotify, watches: &mut WatchSet, path: &Path) {
    let Some(filename) = path.file_name() else {
        return;
    };
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if let Some(wd) = add_watch(inotify, watches, dir) {
        watches
            .targets
            .entry(wd)
            .or_default()
            .config_names
            .insert(filename.to_owned());
        info!(path = %path.display(), "watcher: watching config");
    }
}

fn refresh_script_watches(inotify: &mut Inotify, watches: &mut WatchSet, config: &RuntimeConfig) {
    for target in watches.targets.values_mut() {
        target.scripts = false;
    }

    let desired = crate::client::install::build_script_dirs(config)
        .into_iter()
        .map(|dir| expand_dir(&dir))
        .filter(|path| path.is_dir())
        .collect::<HashSet<_>>();
    for path in desired {
        if let Some(wd) = add_watch(inotify, watches, &path) {
            let target = watches.targets.entry(wd).or_default();
            if !target.scripts {
                info!(path = %path.display(), "watcher: watching Lua scripts");
            }
            target.scripts = true;
        }
    }

    let stale = watches
        .targets
        .iter()
        .filter(|(_, target)| !target.scripts && target.config_names.is_empty())
        .map(|(wd, _)| wd.clone())
        .collect::<Vec<_>>();
    for wd in stale {
        if let Err(error) = inotify.watches().remove(wd.clone()) {
            warn!(%error, "watcher: remove stale Lua watch failed");
        }
        watches.targets.remove(&wd);
        watches.paths.retain(|_, existing| existing != &wd);
    }
}

fn add_watch(
    inotify: &mut Inotify,
    watches: &mut WatchSet,
    path: &Path,
) -> Option<WatchDescriptor> {
    if let Some(wd) = watches.paths.get(path) {
        return Some(wd.clone());
    }
    let mask = WatchMask::CLOSE_WRITE
        | WatchMask::MOVED_TO
        | WatchMask::MOVED_FROM
        | WatchMask::CREATE
        | WatchMask::DELETE;
    match inotify.watches().add(path, mask) {
        Ok(wd) => {
            watches.paths.insert(path.to_path_buf(), wd.clone());
            watches.targets.entry(wd.clone()).or_default();
            Some(wd)
        }
        Err(error) => {
            warn!(%error, path = %path.display(), "watcher: add watch failed");
            None
        }
    }
}

fn expand_dir(dir: &str) -> PathBuf {
    if let Some(rest) = dir.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(dir)
}

fn reload_config(
    path: &Path,
    base_config_store: &'static ArcSwap<RuntimeConfig>,
    runtime_store: &'static ArcSwap<RuntimeSnapshot>,
) -> bool {
    match RuntimeConfig::load(path) {
        Ok(base_config) => {
            crate::client::install::sync_config_template(path);
            publish_runtime(
                base_config,
                base_config_store,
                runtime_store,
                "config and Lua scripts reloaded",
            );
            true
        }
        Err(error) => {
            warn!(%error, "watcher: config reload failed, keeping previous runtime");
            false
        }
    }
}

fn reload_lua(
    base_config_store: &'static ArcSwap<RuntimeConfig>,
    runtime_store: &'static ArcSwap<RuntimeSnapshot>,
) {
    publish_runtime(
        (**base_config_store.load()).clone(),
        base_config_store,
        runtime_store,
        "Lua scripts reloaded",
    );
}

fn publish_runtime(
    base_config: RuntimeConfig,
    base_config_store: &'static ArcSwap<RuntimeConfig>,
    runtime_store: &'static ArcSwap<RuntimeSnapshot>,
    message: &'static str,
) {
    let (new_config, new_script_runtime) = crate::client::install::build_runtime(&base_config);
    let new_script_state = &new_script_runtime.state;
    let inject_count = new_config.apps.inject.len();
    let dlc_count: usize = new_config.apps.inject.iter().map(|app| app.dlc.len()).sum();
    let controlled =
        vapor_forge_features::package::controlled_app_ids(&new_config, &new_script_state.apps);
    vapor_forge_features::achievements::load_stat_steam_ids(&new_script_state.stat_steam_ids);
    vapor_forge_features::app_avatar::load_static_map(&new_config.app_avatar);
    for (&app, &avatar) in &new_script_state.avatars {
        vapor_forge_features::app_avatar::set_avatar(app, avatar);
    }

    base_config_store.store(Arc::new(base_config));
    let snapshot = RuntimeSnapshot::new(new_config, new_script_runtime);
    crate::client::install::ensure_ipc_server_for_config(&snapshot.config);
    runtime_store.store(Arc::new(snapshot));

    crate::client::package::queue_reload(controlled);

    info!(inject = inject_count, dlc = dlc_count, message);
}
