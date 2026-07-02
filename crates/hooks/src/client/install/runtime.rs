use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once, OnceLock};

use tracing::{info, warn};
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_scripting::ScriptState;

const CONFIG_FILENAME: &str = "config.toml";

static RUNTIME_INIT: Once = Once::new();
static RUNTIME_HOOKS_ENABLED: AtomicBool = AtomicBool::new(false);

pub(crate) static IPC_SERVER: OnceLock<Option<Arc<crate::ipc_server::IpcServer>>> = OnceLock::new();

static CONFIG: once_cell::sync::Lazy<arc_swap::ArcSwap<RuntimeConfig>> =
    once_cell::sync::Lazy::new(|| arc_swap::ArcSwap::from_pointee(RuntimeConfig::default()));

static SCRIPT_STATE: once_cell::sync::Lazy<arc_swap::ArcSwap<ScriptState>> =
    once_cell::sync::Lazy::new(|| arc_swap::ArcSwap::from_pointee(ScriptState::default()));

static PACKAGE_STATE: once_cell::sync::Lazy<vapor_forge_features::package::PackageState> =
    once_cell::sync::Lazy::new(vapor_forge_features::package::PackageState::new);

pub(crate) static TICKET_CACHE: once_cell::sync::Lazy<vapor_forge_features::ticket::TicketCache> =
    once_cell::sync::Lazy::new(|| {
        let cache_dir = std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".config/vapor-forge/cache"));
        vapor_forge_features::ticket::TicketCache::new(cache_dir)
    });

/// Initialize process-wide runtime state shared by every hook batch.
///
/// This sets up diagnostics, loads config and scripts, publishes the ArcSwap
/// stores, primes feature state, and starts config watching. It is intentionally
/// separate from steamclient detour installation so later modules can rely on
/// the same runtime without depending on steamclient-specific setup.
pub fn ensure_runtime_initialized() {
    RUNTIME_INIT.call_once(|| {
        // Early init so config loading errors can be logged.
        vapor_forge_diagnostics::init("info");

        let (config, config_path) = load_config();

        vapor_forge_diagnostics::init(&config.runtime.log_level);

        // Execute Lua scripts and merge addappid results into config.
        let (config, script_state) = execute_and_merge_scripts(config);

        let has_script_apps = !script_state.apps.is_empty();
        let hooks_enabled =
            config.has_any_inject_apps() || has_script_apps || config.apps.shared.enabled;

        let inject_count = config.apps.inject.len();
        let dlc_count: usize = config.apps.inject.iter().map(|a| a.dlc.len()).sum();
        if hooks_enabled {
            info!(
                inject = inject_count,
                dlc = dlc_count,
                script_apps = script_state.apps.len(),
                sharing = config.apps.shared.enabled,
                "hook-install: config ready"
            );
        } else {
            info!("hook-install: nothing to do, skipping");
        }

        if hooks_enabled {
            // Load stat donor SteamIDs from Lua scripts.
            vapor_forge_features::achievements::load_stat_steam_ids(&script_state.stat_steam_ids);

            // Load AppAvatar mappings from config static_map and Lua setavatar.
            vapor_forge_features::app_avatar::load_static_map(&config.app_avatar);
            for (&app, &avatar) in &script_state.avatars {
                vapor_forge_features::app_avatar::set_avatar(app, avatar);
            }
        }

        CONFIG.store(Arc::new(config));
        SCRIPT_STATE.store(Arc::new(script_state));
        RUNTIME_HOOKS_ENABLED.store(hooks_enabled, Ordering::Release);

        #[cfg(debug_assertions)]
        if CONFIG.load().debug.control_api {
            crate::debug_api::start();
        }

        if !hooks_enabled {
            return;
        }

        // Start the IPC server only when a feature that consumes IPC events
        // is enabled and a proton helper is available.
        {
            let cfg = CONFIG.load();
            let needs_ipc = hooks_enabled && cfg.ticket.auto_delegate;
            let has_proton = needs_ipc
                && (cfg
                    .library_inject
                    .libs
                    .iter()
                    .any(|l| l.path.ends_with(".dll"))
                    || !cfg.library_inject.helper_path.is_empty());
            let server = if has_proton {
                crate::ipc_server::IpcServer::start()
            } else {
                if needs_ipc {
                    warn!("hook-install: auto_delegate enabled but no proton helper configured");
                }
                None
            };
            let _ = IPC_SERVER.set(server);
        }

        // Force TICKET_CACHE lazy init while config is loaded.
        let _ = &*TICKET_CACHE;

        crate::watcher::start(&CONFIG, &SCRIPT_STATE, &PACKAGE_STATE, config_path);
    });
}

pub(crate) fn runtime_hooks_enabled() -> bool {
    RUNTIME_HOOKS_ENABLED.load(Ordering::Acquire)
}

pub(crate) fn config() -> arc_swap::Guard<Arc<RuntimeConfig>> {
    CONFIG.load()
}

/// Config ticket mode overlaid with runtime auto-delegate detections.
pub(crate) fn effective_ticket_mode(
    cfg: &RuntimeConfig,
    app_id: AppId,
) -> vapor_forge_config::TicketMode {
    let mode = cfg.ticket_mode(app_id);
    if mode == vapor_forge_config::TicketMode::Forge
        && vapor_forge_features::ticket::is_auto_delegate(app_id)
    {
        return vapor_forge_config::TicketMode::Delegate;
    }
    mode
}

pub(crate) fn script_state() -> arc_swap::Guard<Arc<ScriptState>> {
    SCRIPT_STATE.load()
}

pub(crate) fn package_state() -> &'static vapor_forge_features::package::PackageState {
    &PACKAGE_STATE
}

/// Build the ordered list of Lua script directories:
/// 1. {Steam}/config/lua/: Steam directory
/// 2. ~/.config/vapor-forge/scripts/: user config directory
/// 3. config.toml [scripting] paths: user-specified extra dirs (highest priority)
pub(crate) fn build_script_dirs(config: &RuntimeConfig) -> Vec<String> {
    let mut dirs = Vec::new();

    // 1. Steam root config/lua + config/scripts
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(format!("{}/.local/share/Steam/config/lua", home));
        dirs.push(format!("{}/.local/share/Steam/config/scripts", home));
    }

    // 2. User config directory
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(format!("{}/.config/vapor-forge/scripts", home));
    }

    // 3. Extra dirs from config. Highest priority; later dirs override earlier.
    for path in &config.scripting.paths {
        if !dirs.contains(path) {
            dirs.push(path.clone());
        }
    }

    dirs
}

/// Execute Lua scripts from default + config directories and merge addappid
/// results into the config's inject list.
fn execute_and_merge_scripts(mut config: RuntimeConfig) -> (RuntimeConfig, ScriptState) {
    let dirs = build_script_dirs(&config);
    if dirs.is_empty() {
        return (config, ScriptState::default());
    }

    let state = vapor_forge_scripting::execute_scripts(&dirs);

    // Merge script-added app IDs into config.apps.inject (dedup)
    let existing_ids: std::collections::HashSet<AppId> =
        config.apps.inject.iter().map(|a| a.id).collect();

    for &app_id in &state.apps {
        if !existing_ids.contains(&app_id) {
            config.apps.inject.push(vapor_forge_config::InjectApp {
                id: app_id,
                dlc: Vec::new(),
                ticket: Default::default(),
                purchase_time: 0,
            });
        }
    }

    (config, state)
}

fn config_search_paths() -> Vec<std::path::PathBuf> {
    let mut paths = vec![std::path::PathBuf::from(CONFIG_FILENAME)];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(
            std::path::Path::new(&home)
                .join(".config/vapor-forge")
                .join(CONFIG_FILENAME),
        );
    }
    paths
}

fn load_config() -> (RuntimeConfig, Option<std::path::PathBuf>) {
    for p in config_search_paths() {
        if p.exists() {
            match RuntimeConfig::load(&p) {
                Ok(config) => {
                    info!(path = %p.display(), "hook-install: config loaded");
                    return (config, Some(p));
                }
                Err(e) => {
                    warn!(path = %p.display(), error = %e, "hook-install: config error");
                }
            }
        }
    }
    info!("hook-install: no config, using defaults");
    (RuntimeConfig::default(), None)
}
