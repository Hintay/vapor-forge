use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Once, OnceLock};

use retour::GenericDetour;
use tracing::{debug, error, info, warn};
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_memory::{find_proc_self_maps_targets, ProcMapsEntry};
use vapor_forge_patterns::registry::PatternRegistry;
use vapor_forge_scripting::ScriptState;

use vapor_forge_hook_boundary::{validate_raw_hook_plan, RawAddressRange, RawHookEligibilityInput};

use crate::detour::{self, CodeRegion, PendingDetour};
use crate::hook_report::{log_drift_summary, log_hook_details, HookResult};

// ---------------------------------------------------------------------------
// Config paths
// ---------------------------------------------------------------------------

const CONFIG_FILENAME: &str = "config.toml";

// ---------------------------------------------------------------------------
// GetPackageInfo hook type (used only here for the special-case detour)
// ---------------------------------------------------------------------------

type GetPackageInfoHookFn = extern "C" fn(*mut c_void, u32, u64) -> *mut u8;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

static STEAMCLIENT_BATCH_INSTALL_ONCE: Once = Once::new();
static STEAMCLIENT_BATCH_FINISHED: AtomicBool = AtomicBool::new(false);
static RUNTIME_INIT: Once = Once::new();
static RUNTIME_HOOKS_ENABLED: AtomicBool = AtomicBool::new(false);

static mut GET_PKG_INFO_DETOUR: Option<GenericDetour<GetPackageInfoHookFn>> = None;

pub(crate) static PKG0_INJECTED: AtomicBool = AtomicBool::new(false);
static CPKG_INFO_CAPTURED: AtomicBool = AtomicBool::new(false);

static CODE_RANGE: OnceLock<(usize, usize)> = OnceLock::new();

pub(crate) static IPC_SERVER: OnceLock<Option<std::sync::Arc<crate::ipc_server::IpcServer>>> =
    OnceLock::new();

static CONFIG: once_cell::sync::Lazy<arc_swap::ArcSwap<RuntimeConfig>> =
    once_cell::sync::Lazy::new(|| arc_swap::ArcSwap::from_pointee(RuntimeConfig::default()));

pub(crate) static SCRIPT_STATE: once_cell::sync::Lazy<arc_swap::ArcSwap<ScriptState>> =
    once_cell::sync::Lazy::new(|| arc_swap::ArcSwap::from_pointee(ScriptState::default()));

pub(crate) static PACKAGE_STATE: once_cell::sync::Lazy<
    vapor_forge_features::package::PackageState,
> = once_cell::sync::Lazy::new(vapor_forge_features::package::PackageState::new);

pub(crate) static TICKET_CACHE: once_cell::sync::Lazy<vapor_forge_features::ticket::TicketCache> =
    once_cell::sync::Lazy::new(|| {
        let cache_dir = std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".config/vapor-forge/cache"));
        vapor_forge_features::ticket::TicketCache::new(cache_dir)
    });

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookBatch {
    SteamClient,
    SteamUi,
}

/// Install one hook batch. Safe to call multiple times.
pub fn install_hook_batch(batch: HookBatch) {
    ensure_runtime_initialized();
    match batch {
        HookBatch::SteamClient => install_steamclient_hook_batch(),
        HookBatch::SteamUi => install_steamui_hook_batch(),
    }
}

pub fn is_hook_batch_finished(batch: HookBatch) -> bool {
    match batch {
        HookBatch::SteamClient => STEAMCLIENT_BATCH_FINISHED.load(Ordering::Acquire),
        HookBatch::SteamUi => STEAMUI_BATCH_FINISHED.load(Ordering::Acquire),
    }
}

fn install_steamclient_hook_batch() {
    STEAMCLIENT_BATCH_INSTALL_ONCE.call_once(|| {
        info!("hook-install: steamclient batch started");
        do_install();
        STEAMCLIENT_BATCH_FINISHED.store(true, Ordering::Release);
        info!("hook-install: steamclient batch finished");
    });
}

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

        CONFIG.store(std::sync::Arc::new(config));
        SCRIPT_STATE.store(std::sync::Arc::new(script_state));
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

// ---------------------------------------------------------------------------
// Pattern registry
// ---------------------------------------------------------------------------

/// Load patterns: try external override file, fall back to embedded.
pub(crate) fn load_pattern_registry() -> PatternRegistry {
    if let Ok(home) = std::env::var("HOME") {
        let path = std::path::Path::new(&home).join(".config/vapor-forge/patterns.toml");
        if path.exists() {
            let reg = PatternRegistry::with_overrides(&path);
            info!(path = %path.display(), "patterns: loaded external overrides");
            return reg;
        }
    }
    PatternRegistry::embedded()
}

/// Resolve a function address from the registry and create a pending detour.
pub(crate) fn resolve_from_registry<F: retour::Function>(
    registry: &PatternRegistry,
    code: &CodeRegion,
    name: &str,
    replacement: F,
) -> Option<PendingDetour<F>> {
    let entry = registry.get(name).or_else(|| {
        warn!(hook = name, "pattern not found in registry");
        None
    })?;

    let addr = detour::resolve_pattern_entry(code, name, &entry)?;

    // SAFETY: F is a function pointer type; its bit pattern is the address.
    let replacement_addr: usize = unsafe { std::mem::transmute_copy(&replacement) };

    if let Err(e) = validate_hook_eligibility(name, addr, replacement_addr, code) {
        error!(hook = name, error = %e, "hook boundary validation failed");
        return None;
    }

    // SAFETY: addr is a validated code address in steamclient.so.
    let target: F = unsafe { std::mem::transmute_copy(&addr) };
    // SAFETY: target is a valid function pointer.
    unsafe { detour::create_detour(name, target, addr, replacement) }
}

// ---------------------------------------------------------------------------
// Hook boundary validation
// ---------------------------------------------------------------------------

fn validate_hook_eligibility(
    name: &str,
    target_addr: usize,
    replacement_addr: usize,
    code: &CodeRegion,
) -> vapor_forge_hook_boundary::Result<()> {
    validate_raw_hook_plan(RawHookEligibilityInput {
        module_name: "steamclient.so",
        expected_module_name: "steamclient.so",
        actual_architecture: "x86",
        expected_architecture: "x86",
        target_address: target_addr,
        replacement_address: replacement_addr,
        executable_range: RawAddressRange {
            start: code.base,
            end: code.base + code.bytes.len(),
        },
        write_requested: false,
    })?;
    debug!(
        hook = name,
        target = format_args!("0x{:x}", target_addr),
        replacement = format_args!("0x{:x}", replacement_addr),
        "hook boundary: eligible"
    );
    Ok(())
}

pub(crate) fn validate_vmt_hook_eligibility(
    name: &str,
    original_addr: usize,
    replacement_addr: usize,
) -> bool {
    let Some(&(base, end)) = CODE_RANGE.get() else {
        warn!(hook = name, "VMT validation skipped: code range not set");
        return false;
    };
    let result = validate_raw_hook_plan(RawHookEligibilityInput {
        module_name: "steamclient.so",
        expected_module_name: "steamclient.so",
        actual_architecture: "x86",
        expected_architecture: "x86",
        target_address: original_addr,
        replacement_address: replacement_addr,
        executable_range: RawAddressRange { start: base, end },
        write_requested: false,
    });
    if let Err(e) = result {
        warn!(hook = name, error = %e, "VMT hook boundary validation failed");
        return false;
    }
    debug!(
        hook = name,
        original = format_args!("0x{:x}", original_addr),
        replacement = format_args!("0x{:x}", replacement_addr),
        "VMT hook boundary: eligible"
    );
    true
}

// ---------------------------------------------------------------------------
// Core installation logic
// ---------------------------------------------------------------------------

fn do_install() {
    if !runtime_hooks_enabled() {
        return;
    }

    let code = match get_steamclient_code() {
        Some(c) => c,
        None => return,
    };
    let _ = CODE_RANGE.set((code.base, code.base + code.bytes.len()));

    // Load pattern registry: try external file first, fall back to embedded
    let registry = load_pattern_registry();
    info!(patterns = registry.len(), "patterns loaded");

    crate::vtable_scan::warmup();

    // Resolve pkg0 injection function addresses. These are not hooks and are called directly.
    super::package::resolve_functions(&code, &registry);

    if super::package::all_functions_resolved() {
        info!("hook-install: pkg0 functions resolved (4/4)");
    } else {
        warn!("hook-install: some pkg0 functions not resolved, injection may be limited");
    }

    // Phase 1: create all detours (retour allocates trampolines on a shared pool page).
    // Do NOT mprotect or PIC-repair yet. Modifying page permissions between allocations
    // would lock the pool page to RX before retour can write the next trampoline.
    let d_ownership = resolve_from_registry(
        &registry,
        &code,
        "CUser::CheckAppOwnership",
        super::ownership::hk_check_app_ownership as super::ownership::CheckAppOwnershipFn,
    );
    let d_subscribed = resolve_from_registry(
        &registry,
        &code,
        "CUser::GetSubscribedApps",
        super::ownership::hk_get_subscribed_apps as super::ownership::GetSubscribedAppsFn,
    );
    let d_remote_storage_ipc = resolve_from_registry(
        &registry,
        &code,
        "IClientRemoteStorage::RunIPCFrame",
        super::cloud::hk_remote_storage_run_ipc_frame as super::cloud::RunIPCFrameFn,
    );
    let d_app_mgr_ipc = resolve_from_registry(
        &registry,
        &code,
        "IClientAppManager::RunIPCFrame",
        super::dlc::hk_app_manager_run_ipc_frame as super::cloud::RunIPCFrameFn,
    );
    let d_client_apps_ipc = resolve_from_registry(
        &registry,
        &code,
        "IClientApps::RunIPCFrame",
        super::dlc::hk_client_apps_run_ipc_frame as super::cloud::RunIPCFrameFn,
    );
    let d_get_pkg_info = create_get_package_info_detour();
    let d_ticket_ext = resolve_from_registry(
        &registry,
        &code,
        "IClientUser::GetAppOwnershipTicketExtendedData",
        super::ticket::hk_ticket_ext_data as super::ticket::TicketExtDataFn,
    );
    let d_update_ticket = resolve_from_registry(
        &registry,
        &code,
        "IClientUser::BUpdateAppOwnershipTicket",
        super::ticket::hk_update_ticket as super::ticket::UpdateTicketFn,
    );
    let d_is_sub_ticket = resolve_from_registry(
        &registry,
        &code,
        "IClientUser::IsUserSubscribedAppInTicket",
        super::ticket::hk_is_subscribed_in_ticket as super::ticket::IsSubscribedInTicketFn,
    );
    let d_build_depot = resolve_from_registry(
        &registry,
        &code,
        "BuildDepotDependency",
        super::depot::hk_build_depot_dependency as super::depot::BuildDepotDependencyFn,
    );
    let d_depot_key = resolve_from_registry(
        &registry,
        &code,
        "LoadDepotDecryptionKey",
        super::depot::hk_load_depot_decryption_key as super::depot::LoadDepotDecryptionKeyFn,
    );
    let d_send_frame = resolve_from_registry(
        &registry,
        &code,
        "CWebSocketConnection::BBuildAndAsyncSendFrame",
        super::network::hk_send_frame as super::network::BBuildAndAsyncSendFrameFn,
    );
    let d_recv_pkt = resolve_from_registry(
        &registry,
        &code,
        "CCMConnection::RecvPkt",
        super::network::hk_recv_pkt as super::network::RecvPktFn,
    );
    let d_write_vdf = resolve_from_registry(
        &registry,
        &code,
        "CConfigStore::WriteVdfFile",
        super::cloud::hk_write_vdf_file as super::cloud::WriteVdfFileFn,
    );
    let d_build_spawn_env = resolve_from_registry(
        &registry,
        &code,
        "CUser::BuildSpawnEnvBlock",
        super::env::hk_build_spawn_env_block as super::env::BuildSpawnEnvBlockFn,
    );
    let d_spawn_process = resolve_from_registry(
        &registry,
        &code,
        "CUser::SpawnProcess",
        super::env::hk_spawn_process as super::env::SpawnProcessFn,
    );

    // Resolve SetCloudEnabledForApp vtable slot address for later VMT call
    super::cloud::resolve_set_cloud_fn(&registry, &code);

    // Resolve SetEnvString as a raw fn pointer for library injection.
    super::env::resolve_set_env_string(&registry, &code);

    macro_rules! hr {
        ($name:expr, $d:expr) => {
            HookResult {
                name: $name,
                installed: $d.is_some(),
                addr: $d.as_ref().map_or(0, |p| p.callee_addr),
            }
        };
    }
    let hook_results = vec![
        hr!("CUser::CheckAppOwnership", d_ownership),
        hr!("CUser::GetSubscribedApps", d_subscribed),
        hr!("IClientRemoteStorage::RunIPCFrame", d_remote_storage_ipc),
        hr!("IClientAppManager::RunIPCFrame", d_app_mgr_ipc),
        hr!("IClientApps::RunIPCFrame", d_client_apps_ipc),
        HookResult {
            name: "CPackageInfo::GetPackageInfo",
            installed: d_get_pkg_info.is_some(),
            addr: super::package::get_package_info_addr().unwrap_or(0),
        },
        hr!(
            "IClientUser::GetAppOwnershipTicketExtendedData",
            d_ticket_ext
        ),
        hr!("IClientUser::BUpdateAppOwnershipTicket", d_update_ticket),
        hr!("IClientUser::IsUserSubscribedAppInTicket", d_is_sub_ticket),
        hr!("BuildDepotDependency", d_build_depot),
        hr!("LoadDepotDecryptionKey", d_depot_key),
        hr!(
            "CWebSocketConnection::BBuildAndAsyncSendFrame",
            d_send_frame
        ),
        hr!("CCMConnection::RecvPkt", d_recv_pkt),
        hr!("CConfigStore::WriteVdfFile", d_write_vdf),
        hr!("CUser::BuildSpawnEnvBlock", d_build_spawn_env),
        hr!("CUser::SpawnProcess", d_spawn_process),
    ];

    // Phase 2: PIC-repair all trampolines, then enable.
    // SAFETY: each static is written exactly once during init.
    unsafe {
        detour::store_and_finalize(
            "CUser::CheckAppOwnership",
            std::ptr::addr_of_mut!(super::ownership::OWNERSHIP_DETOUR),
            d_ownership,
        );
        detour::store_and_finalize(
            "CUser::GetSubscribedApps",
            std::ptr::addr_of_mut!(super::ownership::SUBSCRIBED_DETOUR),
            d_subscribed,
        );
        detour::store_and_finalize(
            "IClientRemoteStorage::RunIPCFrame",
            std::ptr::addr_of_mut!(super::cloud::REMOTE_STORAGE_RUN_IPC_DETOUR),
            d_remote_storage_ipc,
        );
        detour::store_and_finalize(
            "IClientAppManager::RunIPCFrame",
            std::ptr::addr_of_mut!(super::dlc::APP_MANAGER_DETOUR),
            d_app_mgr_ipc,
        );
        detour::store_and_finalize(
            "IClientApps::RunIPCFrame",
            std::ptr::addr_of_mut!(super::dlc::CLIENT_APPS_DETOUR),
            d_client_apps_ipc,
        );
        detour::store_and_finalize(
            "CPackageInfo::GetPackageInfo",
            std::ptr::addr_of_mut!(GET_PKG_INFO_DETOUR),
            d_get_pkg_info,
        );
        detour::store_and_finalize(
            "IClientUser::GetAppOwnershipTicketExtendedData",
            std::ptr::addr_of_mut!(super::ticket::TICKET_EXT_DATA_DETOUR),
            d_ticket_ext,
        );
        detour::store_and_finalize(
            "IClientUser::BUpdateAppOwnershipTicket",
            std::ptr::addr_of_mut!(super::ticket::UPDATE_TICKET_DETOUR),
            d_update_ticket,
        );
        detour::store_and_finalize(
            "IClientUser::IsUserSubscribedAppInTicket",
            std::ptr::addr_of_mut!(super::ticket::IS_SUBSCRIBED_IN_TICKET_DETOUR),
            d_is_sub_ticket,
        );
        detour::store_and_finalize(
            "BuildDepotDependency",
            std::ptr::addr_of_mut!(super::depot::BUILD_DEPOT_DETOUR),
            d_build_depot,
        );
        detour::store_and_finalize(
            "LoadDepotDecryptionKey",
            std::ptr::addr_of_mut!(super::depot::DEPOT_KEY_DETOUR),
            d_depot_key,
        );
        detour::store_and_finalize(
            "CWebSocketConnection::BBuildAndAsyncSendFrame",
            std::ptr::addr_of_mut!(super::network::SEND_FRAME_DETOUR),
            d_send_frame,
        );
        detour::store_and_finalize(
            "CCMConnection::RecvPkt",
            std::ptr::addr_of_mut!(super::network::RECV_PKT_DETOUR),
            d_recv_pkt,
        );
        detour::store_and_finalize(
            "CConfigStore::WriteVdfFile",
            std::ptr::addr_of_mut!(super::cloud::WRITE_VDF_DETOUR),
            d_write_vdf,
        );
        detour::store_and_finalize(
            "CUser::BuildSpawnEnvBlock",
            std::ptr::addr_of_mut!(super::env::BUILD_SPAWN_ENV_DETOUR),
            d_build_spawn_env,
        );
        detour::store_and_finalize(
            "CUser::SpawnProcess",
            std::ptr::addr_of_mut!(super::env::SPAWN_PROCESS_DETOUR),
            d_spawn_process,
        );
    }

    log_drift_summary("steamclient.so", &hook_results);

    if CONFIG.load().runtime.diagnostics {
        log_hook_details("steamclient.so", &hook_results);
    }

    // Background fetch of online pattern updates
    let cfg = CONFIG.load();
    if !cfg.runtime.patterns_url.is_empty() {
        vapor_forge_features::online_patterns::spawn_fetch(
            cfg.runtime.patterns_url.clone(),
            vapor_forge_patterns::registry::EMBEDDED_PATTERNS_HASH,
        );
    }
}

// ---------------------------------------------------------------------------
// Config helper
// ---------------------------------------------------------------------------

pub(crate) fn config() -> arc_swap::Guard<std::sync::Arc<RuntimeConfig>> {
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

pub(crate) fn script_state() -> arc_swap::Guard<std::sync::Arc<ScriptState>> {
    SCRIPT_STATE.load()
}

// ---------------------------------------------------------------------------
// GetPackageInfo hook captures CPackageInfo* for pkg0 injection
// ---------------------------------------------------------------------------

extern "C" fn hk_get_package_info(
    this: *mut c_void,
    package_id: u32,
    access_token: u64,
) -> *mut u8 {
    // SAFETY: GET_PKG_INFO_DETOUR set before enabled.
    let original = crate::original::detour_or_return!(
        "GetPackageInfo",
        GET_PKG_INFO_DETOUR,
        std::ptr::null_mut()
    );
    let result = original.call(this, package_id, access_token);

    // Capture CPackageInfo* on first call, then use it to get pkg0
    if !CPKG_INFO_CAPTURED.swap(true, Ordering::AcqRel) {
        info!("package: captured CPackageInfo at 0x{:x}", this as usize);

        // Now call GetPackageInfo(this, 0, token) to get pkg0
        if !result.is_null() || package_id == 0 {
            // Try to get pkg0 using the captured CPackageInfo*
            let pkg0 = original.call(this, 0, super::package::PKG0_ACCESS_TOKEN);
            if !pkg0.is_null() {
                // SAFETY: pkg0 is a valid PackageInfo pointer.
                let status = unsafe { vapor_forge_abi::package_info::status(pkg0) };
                if status == 0 {
                    super::package::PKG0_PTR.store(pkg0 as usize, Ordering::Release);
                    info!("package: captured pkg0 at 0x{:x}", pkg0 as usize);
                } else {
                    warn!(status = status, "package: pkg0 status != Available");
                }
            } else {
                debug!("package: GetPackageInfo(0) returned null, will retry");
                CPKG_INFO_CAPTURED.store(false, Ordering::Release);
            }
        }
    }

    result
}

fn create_get_package_info_detour() -> Option<PendingDetour<GetPackageInfoHookFn>> {
    let addr = super::package::get_package_info_addr()?;

    let replacement_addr = hk_get_package_info as *const () as usize;
    if let Some(&(base, end)) = CODE_RANGE.get() {
        if let Err(e) = validate_hook_eligibility(
            "CPackageInfo::GetPackageInfo",
            addr,
            replacement_addr,
            &CodeRegion {
                base,
                bytes: unsafe { std::slice::from_raw_parts(base as *const u8, end - base) },
            },
        ) {
            error!(hook = "CPackageInfo::GetPackageInfo", error = %e, "hook boundary validation failed");
            return None;
        }
    }

    // SAFETY: addr is a validated code address.
    let target: GetPackageInfoHookFn = unsafe { std::mem::transmute(addr) };
    // SAFETY: target is valid.
    unsafe { detour::create_detour("GetPackageInfo", target, addr, hk_get_package_info) }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static STEAMUI_BATCH_INSTALL_ONCE: Once = Once::new();
static STEAMUI_BATCH_FINISHED: AtomicBool = AtomicBool::new(false);

/// Called from la_activity after steamui.so reaches a consistent loader state.
/// Safe to call multiple times; installs only once.
fn install_steamui_hook_batch() {
    STEAMUI_BATCH_INSTALL_ONCE.call_once(|| {
        info!("hook-install: steamui batch started");
        if !runtime_hooks_enabled() {
            STEAMUI_BATCH_FINISHED.store(true, Ordering::Release);
            info!(installed = false, "hook-install: steamui batch finished");
            return;
        }
        let Some(ui_code) = crate::ui::install::get_steamui_code() else {
            warn!(
                "hook-install: steamui.so executable mapping unavailable, skipping steamui hooks"
            );
            STEAMUI_BATCH_FINISHED.store(true, Ordering::Release);
            info!(installed = false, "hook-install: steamui batch finished");
            return;
        };
        let registry = load_pattern_registry();
        let installed = crate::ui::install::install(&ui_code, &registry);
        STEAMUI_BATCH_FINISHED.store(true, Ordering::Release);
        info!(installed, "hook-install: steamui batch finished");
    });
}

fn get_steamclient_code() -> Option<CodeRegion> {
    let entries = match find_proc_self_maps_targets(16) {
        Ok(e) => e,
        Err(e) => {
            error!("hook-install: proc-maps failed: {}", e);
            return None;
        }
    };

    let exec_entry = match find_steamclient_exec_mapping(&entries) {
        Some(e) => e,
        None => {
            error!("hook-install: no executable steamclient.so mapping");
            return None;
        }
    };

    let base = exec_entry.range.base.0;
    let size = exec_entry.range.size;
    debug!(
        base = format_args!("0x{:x}", base),
        size = format_args!("0x{:x}", size),
        "hook-install: steamclient exec mapping"
    );

    // SAFETY: reading the executable mapping of steamclient.so.
    let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    Some(CodeRegion { base, bytes })
}

/// Read a vtable slot value without modifying it.
///
/// # Safety
/// `this` must point to a valid C++ object with a vtable pointer as first field.
/// `slot` must be within vtable bounds.
pub(crate) unsafe fn read_vtable_slot(this: *mut c_void, slot: usize) -> Option<usize> {
    if this.is_null() {
        return None;
    }
    // SAFETY: caller guarantees this points to a C++ object.
    let vtable = unsafe { *(this as *const *const usize) };
    if vtable.is_null() {
        return None;
    }
    // SAFETY: caller guarantees slot is within vtable bounds.
    Some(unsafe { *vtable.add(slot) })
}

fn find_steamclient_exec_mapping(entries: &[ProcMapsEntry]) -> Option<&ProcMapsEntry> {
    entries.iter().find(|e| {
        e.permissions.contains('x')
            && (e.path.ends_with("/steamclient.so") || e.path == "steamclient.so")
    })
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
