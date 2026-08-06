#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Once, OnceLock};

use tracing::{debug, info, warn};
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_scripting::{ManifestCodeProvider, RegistryHandle, ScriptRuntime, ScriptState};

const CONFIG_FILENAME: &str = "config.toml";

static RUNTIME_INIT: Once = Once::new();
static RUNTIME_READY: AtomicBool = AtomicBool::new(false);
static NEXT_RUNTIME_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(crate) static IPC_SERVER: OnceLock<Arc<crate::ipc_server::IpcServer>> = OnceLock::new();

pub(crate) struct RuntimeSnapshot {
    pub generation: u64,
    pub config: Arc<RuntimeConfig>,
    pub script_state: Arc<ScriptState>,
    pub manifest_code_provider: Option<Arc<ManifestCodeProvider>>,
    pub script_registry: Option<RegistryHandle>,
    pub avatar_map: Arc<HashMap<AppId, AppId>>,
}

impl RuntimeSnapshot {
    pub(crate) fn new(config: RuntimeConfig, script_runtime: ScriptRuntime) -> Self {
        let mut avatar_map = config.app_avatar.static_map.clone();
        avatar_map.extend(
            script_runtime
                .state
                .avatars
                .iter()
                .map(|(&app, &avatar)| (app, avatar)),
        );
        Self {
            generation: NEXT_RUNTIME_GENERATION.fetch_add(1, Ordering::AcqRel),
            config: Arc::new(config),
            script_state: Arc::new(script_runtime.state),
            manifest_code_provider: script_runtime.manifest_code_provider.map(Arc::new),
            script_registry: script_runtime.registry,
            avatar_map: Arc::new(avatar_map),
        }
    }
}

impl Default for RuntimeSnapshot {
    fn default() -> Self {
        Self::new(RuntimeConfig::default(), ScriptRuntime::default())
    }
}

static RUNTIME: once_cell::sync::Lazy<arc_swap::ArcSwap<RuntimeSnapshot>> =
    once_cell::sync::Lazy::new(|| arc_swap::ArcSwap::from_pointee(RuntimeSnapshot::default()));

static BASE_CONFIG: once_cell::sync::Lazy<arc_swap::ArcSwap<RuntimeConfig>> =
    once_cell::sync::Lazy::new(|| arc_swap::ArcSwap::from_pointee(RuntimeConfig::default()));

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
pub fn ensure_runtime_initialized() -> bool {
    RUNTIME_INIT.call_once(|| {
        // Early init so config loading errors can be logged.
        vapor_forge_diagnostics::init("info");

        let (base_config, config_path) = match load_config() {
            Ok(loaded) => loaded,
            Err(error) => {
                tracing::error!(%error, "hook-install: runtime initialization rejected");
                return;
            }
        };

        vapor_forge_diagnostics::init(&base_config.runtime.log_level);

        // Execute Lua scripts and merge addappid results into config.
        let (config, script_runtime) = build_runtime(&base_config);
        let script_state = &script_runtime.state;

        let inject_count = config.apps.inject.len();
        let dlc_count: usize = config.apps.inject.iter().map(|a| a.dlc.len()).sum();
        info!(
            inject = inject_count,
            dlc = dlc_count,
            script_apps = script_state.apps.len(),
            sharing = config.apps.shared.enabled,
            "hook-install: config ready"
        );

        BASE_CONFIG.store(Arc::new(base_config));
        let snapshot = RuntimeSnapshot::new(config, script_runtime);
        let service_config = Arc::clone(&snapshot.config);
        RUNTIME.store(Arc::new(snapshot));
        ensure_runtime_services_for_config(&service_config);

        crate::watcher::start(&BASE_CONFIG, &RUNTIME, config_path);

        #[cfg(debug_assertions)]
        if RUNTIME.load().config.debug.control_api {
            crate::debug_api::start();
        }

        // Force TICKET_CACHE lazy init while config is loaded.
        let _ = &*TICKET_CACHE;
        RUNTIME_READY.store(true, Ordering::Release);
    });
    RUNTIME_READY.load(Ordering::Acquire)
}

pub(crate) fn config() -> Arc<RuntimeConfig> {
    RUNTIME.load().config.clone()
}

pub(crate) fn runtime_snapshot() -> arc_swap::Guard<Arc<RuntimeSnapshot>> {
    RUNTIME.load()
}

pub(crate) fn runtime_generation() -> u64 {
    RUNTIME.load().generation
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

pub(crate) fn script_state() -> Arc<ScriptState> {
    RUNTIME.load().script_state.clone()
}

pub(crate) fn ensure_runtime_services_for_config(config: &RuntimeConfig) {
    crate::cloud_backend::refresh(config);
    if config.local_cloud_configured() || config.cumulus_configured() {
        crate::achievement_worker::ensure_started();
        crate::playtime_worker::ensure_started();
        crate::account_downlink_worker::ensure_started();
    }
    ensure_ipc_server_for_config(config);
}

fn ensure_ipc_server_for_config(config: &RuntimeConfig) {
    if !game_bridge_required(config) || IPC_SERVER.get().is_some() {
        return;
    }
    if crate::client::env::resolve_helper_path(&config.library_inject.helper_path).is_none() {
        warn!("hook-install: game bridge requested but no proton helper is available");
        return;
    }
    if let Some(server) = crate::ipc_server::IpcServer::start() {
        let _ = IPC_SERVER.set(server);
    }
}

fn game_bridge_required(config: &RuntimeConfig) -> bool {
    config.ticket.auto_delegate
}

pub(crate) fn package_state() -> &'static vapor_forge_features::package::PackageState {
    &PACKAGE_STATE
}

/// Build the ordered list of Lua script directories:
/// 1. {Steam}/config/lua/: Steam directory
/// 2. ~/.config/vapor-forge/scripts/: user config directory
/// 3. config.toml [scripting] paths: user-specified extra dirs (highest priority)
pub(crate) fn build_script_dirs(config: &RuntimeConfig) -> Vec<String> {
    let steam_root = steam_install_root();
    if let Some(root) = &steam_root {
        debug!(path = %root.display(), "scripting: resolved Steam root");
    }
    let home = std::env::var_os("HOME");
    build_script_dirs_for(config, steam_root.as_deref(), home.as_deref())
}

fn build_script_dirs_for(
    config: &RuntimeConfig,
    steam_root: Option<&Path>,
    home: Option<&std::ffi::OsStr>,
) -> Vec<String> {
    let mut dirs = Vec::new();

    // 1. Steam root config/lua
    if let Some(root) = steam_root {
        dirs.push(root.join("config/lua").to_string_lossy().into_owned());
    }

    // 2. User config directory
    if let Some(home) = home {
        dirs.push(
            PathBuf::from(home)
                .join(".config/vapor-forge/scripts")
                .to_string_lossy()
                .into_owned(),
        );
    }

    // 3. Extra dirs from config. Highest priority; later dirs override earlier.
    for path in &config.scripting.paths {
        if !dirs.contains(path) {
            dirs.push(path.clone());
        }
    }

    dirs
}

fn steam_install_root() -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok();
    let compat_root = std::env::var_os("STEAM_COMPAT_CLIENT_INSTALL_PATH").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    resolve_steam_install_root(
        current_exe.as_deref(),
        compat_root.as_deref(),
        home.as_deref(),
    )
}

fn resolve_steam_install_root(
    current_exe: Option<&Path>,
    compat_root: Option<&Path>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    current_exe
        .and_then(steam_root_from_executable)
        .or_else(|| compat_root.and_then(canonical_steam_root))
        .or_else(|| {
            let home = home?;
            [
                home.join(".steam/root"),
                home.join(".steam/steam"),
                home.join(".local/share/Steam"),
                home.join(".steam/debian-installation"),
            ]
            .into_iter()
            .find_map(|candidate| canonical_steam_root(&candidate))
        })
}

fn steam_root_from_executable(executable: &Path) -> Option<PathBuf> {
    if executable.file_name()? != "steam" {
        return None;
    }
    let runtime_dir = executable.parent()?;
    let runtime_name = runtime_dir.file_name()?.to_str()?;
    if !matches!(
        runtime_name,
        "ubuntu12_32" | "ubuntu12_64" | "linux32" | "linux64" | "steamrt32" | "steamrt64"
    ) {
        return None;
    }
    runtime_dir.parent().map(Path::to_path_buf)
}

fn canonical_steam_root(candidate: &Path) -> Option<PathBuf> {
    let root = candidate.canonicalize().ok()?;
    root.join("ubuntu12_32/steam").is_file().then_some(root)
}

/// Execute Lua scripts from default + config directories and merge addappid
/// results into the config's inject list.
pub(crate) fn build_runtime(base_config: &RuntimeConfig) -> (RuntimeConfig, ScriptRuntime) {
    let dirs = build_script_dirs(base_config);
    if dirs.is_empty() {
        return (base_config.clone(), ScriptRuntime::default());
    }

    let runtime = vapor_forge_scripting::execute_scripts_runtime(&dirs);
    let config = merge_script_apps(base_config.clone(), &runtime.state.apps);
    (config, runtime)
}

pub(crate) fn merge_script_apps(
    mut config: RuntimeConfig,
    apps: &std::collections::HashSet<AppId>,
) -> RuntimeConfig {
    let mut existing_ids: std::collections::HashSet<AppId> =
        config.apps.inject.iter().map(|a| a.id).collect();

    for &app_id in apps {
        if existing_ids.insert(app_id) {
            config.apps.inject.push(vapor_forge_config::InjectApp {
                id: app_id,
                dlc: Vec::new(),
                ticket: Default::default(),
                purchase_time: 0,
            });
        }
    }

    config
}

fn config_path_for_home(home: Option<&std::ffi::OsStr>) -> Option<std::path::PathBuf> {
    home.map(|home| {
        std::path::Path::new(home)
            .join(".config/vapor-forge")
            .join(CONFIG_FILENAME)
    })
}

fn load_config() -> Result<(RuntimeConfig, std::path::PathBuf), String> {
    load_config_for_home(std::env::var_os("HOME").as_deref())
}

fn load_config_for_home(
    home: Option<&std::ffi::OsStr>,
) -> Result<(RuntimeConfig, std::path::PathBuf), String> {
    let Some(path) = config_path_for_home(home) else {
        return Err("HOME is unavailable; configuration path cannot be resolved".to_owned());
    };
    if path.exists() {
        let config =
            RuntimeConfig::load(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        info!(path = %path.display(), "hook-install: config loaded");
        return Ok((config, path));
    }

    match RuntimeConfig::write_default_template(&path) {
        Ok(()) => match RuntimeConfig::load(&path) {
            Ok(config) => {
                info!(path = %path.display(), "hook-install: config template created");
                Ok((config, path))
            }
            Err(error) => Err(format!(
                "generated config {} failed to load: {error}",
                path.display()
            )),
        },
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let config = RuntimeConfig::load(&path)
                .map_err(|load_error| format!("{}: {load_error}", path.display()))?;
            Ok((config, path))
        }
        Err(error) => Err(format!(
            "config template {} could not be created: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_ID: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vapor-forge-{name}-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn steam_root_is_inferred_from_the_running_steam_executable() {
        let executable = Path::new("/home/user/.steam/debian-installation/ubuntu12_32/steam");

        assert_eq!(
            steam_root_from_executable(executable),
            Some(PathBuf::from("/home/user/.steam/debian-installation"))
        );
        assert_eq!(
            steam_root_from_executable(Path::new("/usr/bin/steam")),
            None
        );
    }

    #[test]
    fn steam_root_falls_back_to_the_home_symlink() {
        let base = temp_dir("steam-root");
        let home = base.join("home");
        let install = base.join("debian-installation");
        fs::create_dir_all(home.join(".steam")).unwrap();
        fs::create_dir_all(install.join("ubuntu12_32")).unwrap();
        fs::write(install.join("ubuntu12_32/steam"), []).unwrap();
        std::os::unix::fs::symlink(&install, home.join(".steam/root")).unwrap();

        let resolved = resolve_steam_install_root(None, None, Some(&home));

        assert_eq!(resolved, Some(install.canonicalize().unwrap()));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn runtime_config_path_is_canonical_for_the_home_directory() {
        assert_eq!(
            config_path_for_home(Some(std::ffi::OsStr::new("/home/user"))),
            Some(PathBuf::from("/home/user/.config/vapor-forge/config.toml"))
        );
        assert_eq!(config_path_for_home(None), None);
    }

    #[test]
    fn missing_home_rejects_runtime_initialization() {
        let error = load_config_for_home(None).unwrap_err();
        assert!(error.contains("HOME is unavailable"));
    }

    #[test]
    fn invalid_existing_config_is_terminal() {
        let base = temp_dir("invalid-config");
        let home = base.join("home");
        let path = config_path_for_home(Some(home.as_os_str())).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "unknown_field = true\n").unwrap();

        let error = load_config_for_home(Some(home.as_os_str())).unwrap_err();

        assert!(error.contains("unknown field"));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn absent_config_creates_and_loads_the_default_template() {
        let base = temp_dir("default-config");
        let home = base.join("home");

        let (config, path) = load_config_for_home(Some(home.as_os_str())).unwrap();

        assert!(path.is_file());
        assert!(config.apps.inject.is_empty());
        assert!(matches!(
            config.cloud.backend,
            vapor_forge_config::CloudBackendMode::Disabled
        ));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn script_directories_exclude_undocumented_steam_paths() {
        let mut config = RuntimeConfig::default();
        config.scripting.paths.push("/explicit/scripts".into());

        let dirs = build_script_dirs_for(
            &config,
            Some(Path::new("/steam")),
            Some(std::ffi::OsStr::new("/home/user")),
        );

        assert_eq!(
            dirs,
            [
                "/steam/config/lua",
                "/home/user/.config/vapor-forge/scripts",
                "/explicit/scripts",
            ]
        );
        assert!(!dirs.iter().any(|path| path.ends_with("config/scripts")));
    }

    #[test]
    fn script_apps_never_mutate_the_base_config() {
        let base = RuntimeConfig::default();
        let scripts: std::collections::HashSet<AppId> = [AppId(480)].into_iter().collect();
        let effective = merge_script_apps(base.clone(), &scripts);

        assert!(base.apps.inject.is_empty());
        assert_eq!(effective.apps.inject.len(), 1);
        assert_eq!(effective.apps.inject[0].id, AppId(480));

        let empty = std::collections::HashSet::new();
        let after_script_removal = merge_script_apps(base.clone(), &empty);
        assert!(after_script_removal.apps.inject.is_empty());
    }

    #[test]
    fn runtime_snapshot_merges_avatar_map_with_lua_precedence() {
        let mut config = RuntimeConfig::default();
        config.app_avatar.static_map.insert(AppId(480), AppId(10));
        config.app_avatar.static_map.insert(AppId(481), AppId(11));
        let mut scripts = ScriptRuntime::default();
        scripts.state.avatars.insert(AppId(480), AppId(20));

        let snapshot = RuntimeSnapshot::new(config, scripts);

        assert_eq!(snapshot.avatar_map.get(&AppId(480)), Some(&AppId(20)));
        assert_eq!(snapshot.avatar_map.get(&AppId(481)), Some(&AppId(11)));
    }

    #[test]
    fn game_bridge_is_only_required_for_auto_delegate() {
        let mut config = RuntimeConfig::default();
        assert!(!game_bridge_required(&config));

        config.cloud.backend = vapor_forge_config::CloudBackendMode::Cumulus;
        config.cloud.cumulus.server_url = "https://cumulus.example".into();
        config.cloud.cumulus.token = "token".into();
        assert!(config.cumulus_configured());
        assert!(!game_bridge_required(&config));

        config.ticket.auto_delegate = true;
        assert!(game_bridge_required(&config));
    }
}
