#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use inotify::{Inotify, WatchDescriptor, WatchMask};
use tracing::{debug, info, warn};
use vapor_forge_config::RuntimeConfig;
use vapor_forge_scripting::{ManifestCodeProvider, RegistryHandle, ScriptRuntime};

use crate::client::install::RuntimeSnapshot;

#[derive(Debug, Clone, Copy)]
enum LuaChange {
    Upsert,
    Remove,
}

#[derive(Default)]
struct WatchTarget {
    config_names: HashSet<OsString>,
    scripts: bool,
    script_dir_names: HashSet<OsString>,
}

#[derive(Default)]
struct WatchSet {
    paths: HashMap<PathBuf, WatchDescriptor>,
    dirs: HashMap<WatchDescriptor, PathBuf>,
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
        let mut lua_changes: HashMap<PathBuf, LuaChange> = HashMap::new();
        let mut lua_order: Vec<PathBuf> = Vec::new();
        let mut script_dirs_changed = false;
        for event in events {
            classify_event(
                &watches,
                &event,
                &mut config_changed,
                &mut lua_changes,
                &mut lua_order,
                &mut script_dirs_changed,
            );
        }

        if config_changed || !lua_changes.is_empty() || script_dirs_changed {
            std::thread::sleep(std::time::Duration::from_millis(50));
            loop {
                match inotify.read_events(&mut buf) {
                    Ok(events) => {
                        for event in events {
                            classify_event(
                                &watches,
                                &event,
                                &mut config_changed,
                                &mut lua_changes,
                                &mut lua_order,
                                &mut script_dirs_changed,
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
                if script_dirs_changed {
                    refresh_script_watches(&mut inotify, &mut watches, &base_config_store.load());
                }
                if !lua_changes.is_empty() {
                    apply_lua_changes(&lua_order, &lua_changes, base_config_store, runtime_store);
                }
            }
        }
    }
}

fn apply_lua_changes(
    order: &[PathBuf],
    changes: &HashMap<PathBuf, LuaChange>,
    base_config_store: &'static ArcSwap<RuntimeConfig>,
    runtime_store: &'static ArcSwap<RuntimeSnapshot>,
) {
    let snapshot = runtime_store.load();
    let Some(handle) = snapshot.script_registry.clone() else {
        // No live registry — fall back to full rebuild.
        publish_full_rebuild(
            (**base_config_store.load()).clone(),
            base_config_store,
            runtime_store,
            "Lua scripts reloaded",
        );
        return;
    };
    drop(snapshot);

    for path in order {
        match changes.get(path).copied().unwrap_or(LuaChange::Upsert) {
            LuaChange::Remove => {
                handle.unload_file(path);
                debug!(path = %path.display(), "watcher: unload lua");
            }
            LuaChange::Upsert => match std::fs::read_to_string(path) {
                Ok(source) => {
                    let errors = handle.parse_file(path, &source);
                    for error in errors {
                        warn!(path = %path.display(), %error, "watcher: lua parse error");
                    }
                    debug!(path = %path.display(), "watcher: parse lua");
                }
                Err(error) => {
                    warn!(path = %path.display(), %error, "watcher: lua file read failed");
                }
            },
        }
    }

    publish_incremental(&handle, base_config_store, runtime_store);
}

fn classify_event(
    watches: &WatchSet,
    event: &inotify::Event<&OsStr>,
    config_changed: &mut bool,
    lua_changes: &mut HashMap<PathBuf, LuaChange>,
    lua_order: &mut Vec<PathBuf>,
    script_dirs_changed: &mut bool,
) {
    let Some(target) = watches.targets.get(&event.wd) else {
        return;
    };
    let Some(name) = event.name else {
        return;
    };
    if target.config_names.contains(name) {
        *config_changed = true;
    }
    if target.scripts && Path::new(name).extension() == Some(OsStr::new("lua")) {
        let Some(dir) = watches.dirs.get(&event.wd) else {
            return;
        };
        let full = dir.join(name);
        let action = if event.mask.contains(inotify::EventMask::DELETE)
            || event.mask.contains(inotify::EventMask::MOVED_FROM)
        {
            LuaChange::Remove
        } else {
            LuaChange::Upsert
        };
        if lua_changes.insert(full.clone(), action).is_none() {
            lua_order.push(full);
        }
    }
    if target.script_dir_names.contains(name) {
        *script_dirs_changed = true;
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
    let desired = crate::client::install::build_script_dirs(config)
        .into_iter()
        .map(|dir| absolute_path(expand_dir(&dir)))
        .collect::<HashSet<_>>();
    refresh_script_watches_for_paths(inotify, watches, desired);
}

fn refresh_script_watches_for_paths(
    inotify: &mut Inotify,
    watches: &mut WatchSet,
    desired: impl IntoIterator<Item = PathBuf>,
) {
    for target in watches.targets.values_mut() {
        target.scripts = false;
        target.script_dir_names.clear();
    }

    for path in desired {
        if let Some((parent, name)) = script_watch_anchor(&path) {
            if let Some(wd) = add_watch(inotify, watches, &parent) {
                let inserted = watches
                    .targets
                    .entry(wd)
                    .or_default()
                    .script_dir_names
                    .insert(name);
                if inserted {
                    info!(path = %path.display(), parent = %parent.display(), "watcher: watching for Lua script directory");
                }
            }
        }

        if path.is_dir() {
            if let Some(wd) = add_watch(inotify, watches, &path) {
                let target = watches.targets.entry(wd).or_default();
                if !target.scripts {
                    info!(path = %path.display(), "watcher: watching Lua scripts");
                }
                target.scripts = true;
            }
        }
    }

    let stale = watches
        .targets
        .iter()
        .filter(|(_, target)| {
            !target.scripts && target.config_names.is_empty() && target.script_dir_names.is_empty()
        })
        .map(|(wd, _)| wd.clone())
        .collect::<Vec<_>>();
    for wd in stale {
        if let Err(error) = inotify.watches().remove(wd.clone()) {
            warn!(%error, "watcher: remove stale Lua watch failed");
        }
        watches.targets.remove(&wd);
        watches.dirs.remove(&wd);
        watches.paths.retain(|_, existing| existing != &wd);
    }
}

fn absolute_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|current| current.join(&path))
            .unwrap_or(path)
    }
}

/// Return the nearest existing parent to watch and the next path component
/// whose creation or removal means script watches must be refreshed.
fn script_watch_anchor(path: &Path) -> Option<(PathBuf, OsString)> {
    let mut child = path.to_path_buf();
    loop {
        let parent = child.parent()?;
        if parent.is_dir() {
            return child
                .file_name()
                .map(|name| (parent.to_path_buf(), name.to_owned()));
        }
        child = parent.to_path_buf();
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
            watches.dirs.insert(wd.clone(), path.to_path_buf());
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
            publish_full_rebuild(
                base_config,
                base_config_store,
                runtime_store,
                "config and Lua scripts reloaded",
            );
            crate::downsync_worker::notify_config_changed();
            true
        }
        Err(error) => {
            warn!(%error, "watcher: config reload failed, keeping previous runtime");
            false
        }
    }
}

fn publish_full_rebuild(
    base_config: RuntimeConfig,
    base_config_store: &'static ArcSwap<RuntimeConfig>,
    runtime_store: &'static ArcSwap<RuntimeSnapshot>,
    message: &'static str,
) {
    let (new_config, new_script_runtime) = crate::client::install::build_runtime(&base_config);
    finalize_snapshot(
        base_config,
        new_config,
        new_script_runtime,
        base_config_store,
        runtime_store,
        message,
    );
}

fn publish_incremental(
    handle: &RegistryHandle,
    base_config_store: &'static ArcSwap<RuntimeConfig>,
    runtime_store: &'static ArcSwap<RuntimeSnapshot>,
) {
    let base_config = (**base_config_store.load()).clone();
    let state = handle.snapshot_state();
    let (has_basic, has_extended) = handle.provider_functions();
    let manifest_code_provider = if has_basic || has_extended {
        // Force provider construction by re-running Manifest lookups through a
        // fresh dummy call: the persistent handle already carries the callback
        // set, so we only need to advertise availability upward.
        Some(ManifestCodeProvider::from(
            handle.clone(),
            has_basic,
            has_extended,
        ))
    } else {
        None
    };
    let new_config = crate::client::install::merge_script_apps(base_config.clone(), &state.apps);
    let new_script_runtime = ScriptRuntime {
        state,
        manifest_code_provider,
        registry: Some(handle.clone()),
    };
    finalize_snapshot(
        base_config,
        new_config,
        new_script_runtime,
        base_config_store,
        runtime_store,
        "Lua scripts reloaded",
    );
}

fn finalize_snapshot(
    base_config: RuntimeConfig,
    new_config: RuntimeConfig,
    new_script_runtime: ScriptRuntime,
    base_config_store: &'static ArcSwap<RuntimeConfig>,
    runtime_store: &'static ArcSwap<RuntimeSnapshot>,
    message: &'static str,
) {
    let new_script_state = &new_script_runtime.state;
    let inject_count = new_config.apps.inject.len();
    let dlc_count: usize = new_config.apps.inject.iter().map(|app| app.dlc.len()).sum();
    let controlled =
        vapor_forge_features::package::controlled_app_ids(&new_config, &new_script_state.apps);
    base_config_store.store(Arc::new(base_config));
    let snapshot = RuntimeSnapshot::new(new_config, new_script_runtime);
    let service_config = Arc::clone(&snapshot.config);
    runtime_store.store(Arc::new(snapshot));
    crate::client::install::ensure_runtime_services_for_config(&service_config);

    crate::client::package::queue_reload(controlled);

    info!(inject = inject_count, dlc = dlc_count, message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn unique_temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vapor-forge-watcher-{}-{nonce}",
            std::process::id()
        ))
    }

    fn wait_for_flags(inotify: &mut Inotify, watches: &WatchSet) -> (bool, bool, bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut buf = [0u8; 4096];
        let mut config_changed = false;
        let mut lua_changes: HashMap<PathBuf, LuaChange> = HashMap::new();
        let mut lua_order: Vec<PathBuf> = Vec::new();
        let mut script_dirs_changed = false;

        while Instant::now() < deadline {
            match inotify.read_events(&mut buf) {
                Ok(events) => {
                    for event in events {
                        classify_event(
                            watches,
                            &event,
                            &mut config_changed,
                            &mut lua_changes,
                            &mut lua_order,
                            &mut script_dirs_changed,
                        );
                    }
                    if config_changed || !lua_changes.is_empty() || script_dirs_changed {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("failed to read inotify events: {error}"),
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        (config_changed, !lua_changes.is_empty(), script_dirs_changed)
    }

    #[test]
    fn notices_script_directory_created_after_watcher_startup() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let scripts = root.join("missing").join("lua");
        let mut inotify = Inotify::init().unwrap();
        let mut watches = WatchSet::default();

        refresh_script_watches_for_paths(&mut inotify, &mut watches, [scripts.clone()]);
        fs::create_dir_all(&scripts).unwrap();

        let (_, lua_changed, script_dirs_changed) = wait_for_flags(&mut inotify, &watches);
        assert!(!lua_changed);
        assert!(script_dirs_changed);

        refresh_script_watches_for_paths(&mut inotify, &mut watches, [scripts.clone()]);
        fs::write(scripts.join("736260.lua"), "addappid(736260)\n").unwrap();

        let (_, lua_changed, _) = wait_for_flags(&mut inotify, &watches);
        assert!(lua_changed);

        drop(inotify);
        fs::remove_dir_all(root).unwrap();
    }
}
