use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Once, OnceLock};

use retour::GenericDetour;
use tracing::{debug, error, info, warn};
use vapor_forge_abi::CAppOwnershipInfo;
use vapor_forge_config::{AppId, DepotId, RuntimeConfig};
use vapor_forge_memory::{find_proc_self_maps_targets, ProcMapsEntry};
use vapor_forge_patterns::registry::PatternRegistry;
use vapor_forge_scripting::ScriptState;

use vapor_forge_hook_boundary::{validate_raw_hook_plan, RawAddressRange, RawHookEligibilityInput};

use crate::detour::{self, CodeRegion, PendingDetour};
use crate::hook_report::{log_drift_summary, log_hook_details, HookResult};
use crate::netpacket::SendFrameDecision;
use crate::original::{detour_or_return, vmt_or_return};
use crate::vmt;

// VMT slot indices resolved at runtime via VtableScan (no hardcoded values).

// ---------------------------------------------------------------------------
// Config paths
// ---------------------------------------------------------------------------

const CONFIG_FILENAME: &str = "config.toml";

// ---------------------------------------------------------------------------
// Function type aliases (non-unsafe for retour compatibility)
// ---------------------------------------------------------------------------

type CheckAppOwnershipFn = extern "C" fn(*mut c_void, u32, *mut CAppOwnershipInfo) -> u32;
type GetSubscribedAppsFn = extern "C" fn(*mut c_void, *mut u32, u32, u8) -> u32;
type RunIPCFrameFn = extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
type IsCloudEnabledForAppFn = extern "C" fn(*mut c_void, u32) -> bool;
type IsAppDlcInstalledFn = extern "C" fn(*mut c_void, u32, u32) -> bool;
type BIsDlcEnabledFn = extern "C" fn(*mut c_void, u32, u32, *mut c_void) -> bool;
type GetPackageInfoHookFn = extern "C" fn(*mut c_void, u32, u64) -> *mut u8;

// Network packet hook function types
type BBuildAndAsyncSendFrameFn = extern "C" fn(*mut c_void, i32, *mut u8, u32) -> bool;
type RecvPktFn = extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;

// Ticket hook function types
type TicketExtDataFn = extern "C" fn(
    *mut c_void, // this (CUser)
    u32,         // app_id
    *mut u8,     // p_ticket buffer
    u32,         // ticket_buf_size
    *mut u32,    // pi_app_id (out)
    *mut u32,    // pi_steam_id (out)
    *mut u32,    // pi_signature (out)
    *mut u32,    // pcb_signature (out)
) -> u32;
type UpdateTicketFn = extern "C" fn(*mut c_void, u32, bool) -> u32;
type IsSubscribedInTicketFn = extern "C" fn(*mut c_void, u32, u32, u32, u32) -> u8;
type GetSteamIDFn = extern "C" fn(*mut c_void) -> u64;
type LoadDepotDecryptionKeyFn = extern "C" fn(*mut c_void, u32, *const i8, *mut u8, u32) -> i32;
type BuildDepotDependencyFn = extern "C" fn(
    *mut c_void,
    u32,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut u32,
    *mut bool,
) -> bool;

// VDF write filtering
type WriteVdfFileFn = extern "C" fn(*mut c_void, u32, u32, *mut c_void, *const u8, u32) -> u32;
type SetCloudEnabledForAppFn = extern "C" fn(*mut c_void, u32, bool);

// AppAvatar LaunchApp VMT hook
type LaunchAppFn =
    extern "C" fn(*mut c_void, *mut u32, *mut c_void, *mut c_void, *mut c_void) -> *mut c_void;

// Library injection: BuildSpawnEnvBlock builds the child process env block for
// a game launch. CGameID is 8 bytes: low 24 bits = AppId, byte 3 = type (2 = app).
type BuildSpawnEnvBlockFn = extern "C" fn(
    *mut c_void, // CGameID* (param_2 at [EBP+8])
    *const i8,   // pExePath
    *const i8,   // pWorkingDir
    *mut c_void, // pLaunchOptionsOrContext
    u32,         // flags
    *mut c_void, // pSomething
    *mut c_void, // pEnvMap
    *mut c_void, // pContext
) -> i32;

// SetEnvString(pEnvMap, key, value): 3-param cdecl helper used to write into
// the env map built by BuildSpawnEnvBlock.
type SetEnvStringFn = extern "C" fn(*mut c_void, *const i8, *const i8);

// CUser::SpawnProcess: launches a game. pCommandLine contains user launch options.
type SpawnProcessFn = extern "C" fn(
    *mut c_void, // this (CUser)
    *const i8,   // pExePath
    *const i8,   // pCommandLine
    *const i8,   // pWorkingDir
    *mut c_void, // pGameID (CGameID*)
    *const i8,   // pExtraString
    u32,         // flags1
    u32,         // flags2
    u32,         // launchSource
    u32,         // flags3
    *mut u32,    // pPID
) -> i32;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

static STEAMCLIENT_BATCH_INSTALL_ONCE: Once = Once::new();
static STEAMCLIENT_BATCH_FINISHED: AtomicBool = AtomicBool::new(false);
static RUNTIME_INIT: Once = Once::new();
static RUNTIME_HOOKS_ENABLED: AtomicBool = AtomicBool::new(false);

static mut OWNERSHIP_DETOUR: Option<GenericDetour<CheckAppOwnershipFn>> = None;
static mut SUBSCRIBED_DETOUR: Option<GenericDetour<GetSubscribedAppsFn>> = None;
static mut REMOTE_STORAGE_RUN_IPC_DETOUR: Option<GenericDetour<RunIPCFrameFn>> = None;
static mut APP_MANAGER_DETOUR: Option<GenericDetour<RunIPCFrameFn>> = None;
static mut CLIENT_APPS_DETOUR: Option<GenericDetour<RunIPCFrameFn>> = None;
static mut GET_PKG_INFO_DETOUR: Option<GenericDetour<GetPackageInfoHookFn>> = None;

static mut TICKET_EXT_DATA_DETOUR: Option<GenericDetour<TicketExtDataFn>> = None;
static mut UPDATE_TICKET_DETOUR: Option<GenericDetour<UpdateTicketFn>> = None;
static mut IS_SUBSCRIBED_IN_TICKET_DETOUR: Option<GenericDetour<IsSubscribedInTicketFn>> = None;
static mut BUILD_DEPOT_DETOUR: Option<GenericDetour<BuildDepotDependencyFn>> = None;
static mut DEPOT_KEY_DETOUR: Option<GenericDetour<LoadDepotDecryptionKeyFn>> = None;
static mut SEND_FRAME_DETOUR: Option<GenericDetour<BBuildAndAsyncSendFrameFn>> = None;
static mut RECV_PKT_DETOUR: Option<GenericDetour<RecvPktFn>> = None;
static mut WRITE_VDF_DETOUR: Option<GenericDetour<WriteVdfFileFn>> = None;
static mut BUILD_SPAWN_ENV_DETOUR: Option<GenericDetour<BuildSpawnEnvBlockFn>> = None;
static mut SPAWN_PROCESS_DETOUR: Option<GenericDetour<SpawnProcessFn>> = None;

static mut ORIGINAL_IS_CLOUD_ENABLED: Option<IsCloudEnabledForAppFn> = None;
static mut SET_CLOUD_FN: Option<SetCloudEnabledForAppFn> = None;
static mut ORIG_IS_APP_DLC_INSTALLED: Option<IsAppDlcInstalledFn> = None;
static mut ORIG_B_IS_DLC_ENABLED: Option<BIsDlcEnabledFn> = None;
static mut ORIG_LAUNCH_APP: Option<LaunchAppFn> = None;
static mut SET_ENV_STRING_FN: Option<SetEnvStringFn> = None;
static mut ORIG_GET_STEAMID: Option<GetSteamIDFn> = None;

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

/// Source ticket from appId 7, lazily acquired on first derivation attempt.
static SOURCE_TICKET_7: OnceLock<Option<Vec<u8>>> = OnceLock::new();

static PKG0_INJECTED: AtomicBool = AtomicBool::new(false);
static CPKG_INFO_CAPTURED: AtomicBool = AtomicBool::new(false);

static CLOUD_VMT_DONE: AtomicBool = AtomicBool::new(false);
static APP_MANAGER_VMT_DONE: AtomicBool = AtomicBool::new(false);
static CLIENT_APPS_VMT_DONE: AtomicBool = AtomicBool::new(false);
static STEAMID_VMT_DONE: AtomicBool = AtomicBool::new(false);

static CODE_RANGE: OnceLock<(usize, usize)> = OnceLock::new();

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

fn runtime_hooks_enabled() -> bool {
    RUNTIME_HOOKS_ENABLED.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Pattern registry
// ---------------------------------------------------------------------------

/// Load patterns: try external override file, fall back to embedded.
fn load_pattern_registry() -> PatternRegistry {
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
fn resolve_from_registry<F: retour::Function>(
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

fn validate_vmt_hook_eligibility(
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
        hk_check_app_ownership as CheckAppOwnershipFn,
    );
    let d_subscribed = resolve_from_registry(
        &registry,
        &code,
        "CUser::GetSubscribedApps",
        hk_get_subscribed_apps as GetSubscribedAppsFn,
    );
    let d_remote_storage_ipc = resolve_from_registry(
        &registry,
        &code,
        "IClientRemoteStorage::RunIPCFrame",
        hk_remote_storage_run_ipc_frame as RunIPCFrameFn,
    );
    let d_app_mgr_ipc = resolve_from_registry(
        &registry,
        &code,
        "IClientAppManager::RunIPCFrame",
        hk_app_manager_run_ipc_frame as RunIPCFrameFn,
    );
    let d_client_apps_ipc = resolve_from_registry(
        &registry,
        &code,
        "IClientApps::RunIPCFrame",
        hk_client_apps_run_ipc_frame as RunIPCFrameFn,
    );
    let d_get_pkg_info = create_get_package_info_detour();
    let d_ticket_ext = resolve_from_registry(
        &registry,
        &code,
        "IClientUser::GetAppOwnershipTicketExtendedData",
        hk_ticket_ext_data as TicketExtDataFn,
    );
    let d_update_ticket = resolve_from_registry(
        &registry,
        &code,
        "IClientUser::BUpdateAppOwnershipTicket",
        hk_update_ticket as UpdateTicketFn,
    );
    let d_is_sub_ticket = resolve_from_registry(
        &registry,
        &code,
        "IClientUser::IsUserSubscribedAppInTicket",
        hk_is_subscribed_in_ticket as IsSubscribedInTicketFn,
    );
    let d_build_depot = resolve_from_registry(
        &registry,
        &code,
        "BuildDepotDependency",
        hk_build_depot_dependency as BuildDepotDependencyFn,
    );
    let d_depot_key = resolve_from_registry(
        &registry,
        &code,
        "LoadDepotDecryptionKey",
        hk_load_depot_decryption_key as LoadDepotDecryptionKeyFn,
    );
    let d_send_frame = resolve_from_registry(
        &registry,
        &code,
        "CWebSocketConnection::BBuildAndAsyncSendFrame",
        hk_send_frame as BBuildAndAsyncSendFrameFn,
    );
    let d_recv_pkt = resolve_from_registry(
        &registry,
        &code,
        "CCMConnection::RecvPkt",
        hk_recv_pkt as RecvPktFn,
    );
    let d_write_vdf = resolve_from_registry(
        &registry,
        &code,
        "CConfigStore::WriteVdfFile",
        hk_write_vdf_file as WriteVdfFileFn,
    );
    let d_build_spawn_env = resolve_from_registry(
        &registry,
        &code,
        "CUser::BuildSpawnEnvBlock",
        hk_build_spawn_env_block as BuildSpawnEnvBlockFn,
    );
    let d_spawn_process = resolve_from_registry(
        &registry,
        &code,
        "CUser::SpawnProcess",
        hk_spawn_process as SpawnProcessFn,
    );

    // Resolve SetCloudEnabledForApp vtable slot address for later VMT call
    resolve_set_cloud_fn(&registry, &code);

    // Resolve SetEnvString as a raw fn pointer for library injection.
    resolve_set_env_string(&registry, &code);

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
            std::ptr::addr_of_mut!(OWNERSHIP_DETOUR),
            d_ownership,
        );
        detour::store_and_finalize(
            "CUser::GetSubscribedApps",
            std::ptr::addr_of_mut!(SUBSCRIBED_DETOUR),
            d_subscribed,
        );
        detour::store_and_finalize(
            "IClientRemoteStorage::RunIPCFrame",
            std::ptr::addr_of_mut!(REMOTE_STORAGE_RUN_IPC_DETOUR),
            d_remote_storage_ipc,
        );
        detour::store_and_finalize(
            "IClientAppManager::RunIPCFrame",
            std::ptr::addr_of_mut!(APP_MANAGER_DETOUR),
            d_app_mgr_ipc,
        );
        detour::store_and_finalize(
            "IClientApps::RunIPCFrame",
            std::ptr::addr_of_mut!(CLIENT_APPS_DETOUR),
            d_client_apps_ipc,
        );
        detour::store_and_finalize(
            "CPackageInfo::GetPackageInfo",
            std::ptr::addr_of_mut!(GET_PKG_INFO_DETOUR),
            d_get_pkg_info,
        );
        detour::store_and_finalize(
            "IClientUser::GetAppOwnershipTicketExtendedData",
            std::ptr::addr_of_mut!(TICKET_EXT_DATA_DETOUR),
            d_ticket_ext,
        );
        detour::store_and_finalize(
            "IClientUser::BUpdateAppOwnershipTicket",
            std::ptr::addr_of_mut!(UPDATE_TICKET_DETOUR),
            d_update_ticket,
        );
        detour::store_and_finalize(
            "IClientUser::IsUserSubscribedAppInTicket",
            std::ptr::addr_of_mut!(IS_SUBSCRIBED_IN_TICKET_DETOUR),
            d_is_sub_ticket,
        );
        detour::store_and_finalize(
            "BuildDepotDependency",
            std::ptr::addr_of_mut!(BUILD_DEPOT_DETOUR),
            d_build_depot,
        );
        detour::store_and_finalize(
            "LoadDepotDecryptionKey",
            std::ptr::addr_of_mut!(DEPOT_KEY_DETOUR),
            d_depot_key,
        );
        detour::store_and_finalize(
            "CWebSocketConnection::BBuildAndAsyncSendFrame",
            std::ptr::addr_of_mut!(SEND_FRAME_DETOUR),
            d_send_frame,
        );
        detour::store_and_finalize(
            "CCMConnection::RecvPkt",
            std::ptr::addr_of_mut!(RECV_PKT_DETOUR),
            d_recv_pkt,
        );
        detour::store_and_finalize(
            "CConfigStore::WriteVdfFile",
            std::ptr::addr_of_mut!(WRITE_VDF_DETOUR),
            d_write_vdf,
        );
        detour::store_and_finalize(
            "CUser::BuildSpawnEnvBlock",
            std::ptr::addr_of_mut!(BUILD_SPAWN_ENV_DETOUR),
            d_build_spawn_env,
        );
        detour::store_and_finalize(
            "CUser::SpawnProcess",
            std::ptr::addr_of_mut!(SPAWN_PROCESS_DETOUR),
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
fn effective_ticket_mode(cfg: &RuntimeConfig, app_id: AppId) -> vapor_forge_config::TicketMode {
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
// Hook replacement functions: CheckAppOwnership
// ---------------------------------------------------------------------------

extern "C" fn hk_check_app_ownership(
    this: *mut c_void,
    app_id: u32,
    out: *mut CAppOwnershipInfo,
) -> u32 {
    // SAFETY: OWNERSHIP_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("CheckAppOwnership", OWNERSHIP_DETOUR, 0);
    let result = original.call(this, app_id, out);

    if out.is_null() {
        return result;
    }

    // Store CUser pointer for MarkLicenseAsChanged / ProcessPendingLicenseUpdates
    if super::package::CUSER_PTR.load(Ordering::Acquire) == 0 {
        super::package::CUSER_PTR.store(this as usize, Ordering::Release);
        debug!("package: captured CUser at 0x{:x}", this as usize);
    }

    // CUser also implements IClientUser; install the GetSteamID VMT hook once
    // we have a live instance, so ticket-delegate mode can spoof it.
    if !STEAMID_VMT_DONE.load(Ordering::Acquire) {
        install_steamid_vmt(this);
    }

    // pkg0 injection: triggered after GetPackageInfo hook captures CPackageInfo* + pkg0
    if super::package::PKG0_PTR.load(Ordering::Acquire) != 0
        && !PKG0_INJECTED.swap(true, Ordering::AcqRel)
    {
        let cfg = config();
        let ss = script_state();
        let controlled = vapor_forge_features::package::controlled_app_ids(&*cfg, &ss.apps);
        let plan = PACKAGE_STATE.compute_injection(&controlled);

        // SAFETY: pkg0 and cuser captured, function pointers resolved.
        unsafe { super::package::try_inject_once(&plan.app_ids) };
        PACKAGE_STATE.record_injected(&plan.app_ids);
        PACKAGE_STATE.set_active();
    }

    // Pump pending markAndProcess from watcher thread (runs on this Steam thread).
    super::package::pump_mark_and_process();

    let cfg = config();
    // SAFETY: out is a valid pointer provided by Steam's caller, filled by original.
    let info = unsafe { &mut *out };

    // If pkg0 injection is active, Steam's original already sees ownership
    // from pkg0. Still run the spoof as fallback for edge cases.
    vapor_forge_features::apps::on_check_ownership(&*cfg, AppId(app_id), result, info)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: GetSubscribedApps
// ---------------------------------------------------------------------------

extern "C" fn hk_get_subscribed_apps(
    this: *mut c_void,
    app_list: *mut u32,
    size: u32,
    a3: u8,
) -> u32 {
    // SAFETY: SUBSCRIBED_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("GetSubscribedApps", SUBSCRIBED_DETOUR, 0);
    let count = original.call(this, app_list, size, a3);

    let cfg = config();

    if app_list.is_null() || size == 0 {
        return count + vapor_forge_features::apps::get_subscribed_count_adjustment(&*cfg);
    }

    // SAFETY: app_list buffer has `size` u32 slots, provided by Steam's caller.
    let slice = unsafe { std::slice::from_raw_parts_mut(app_list, size as usize) };
    vapor_forge_features::apps::on_get_subscribed_apps(&*cfg, slice, count)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientRemoteStorage::RunIPCFrame (cloud VMT)
// ---------------------------------------------------------------------------

extern "C" fn hk_remote_storage_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !CLOUD_VMT_DONE.load(Ordering::Acquire) {
        install_cloud_vmt(this);
    }

    // SAFETY: REMOTE_STORAGE_RUN_IPC_DETOUR set before enabled.
    let original = detour_or_return!(
        "IClientRemoteStorage::RunIPCFrame",
        REMOTE_STORAGE_RUN_IPC_DETOUR,
        ()
    );
    original.call(this, a1, a2, a3);
}

extern "C" fn hk_is_cloud_enabled_for_app(this: *mut c_void, app_id: u32) -> bool {
    // SAFETY: ORIGINAL_IS_CLOUD_ENABLED set before VMT swap.
    let original = vmt_or_return!("IsCloudEnabledForApp", ORIGINAL_IS_CLOUD_ENABLED, true);
    let result = original(this, app_id);

    let cfg = config();
    let should_disable = cfg.app_category(AppId(app_id)).is_some()
        && !vapor_forge_features::apps::is_actually_owned(AppId(app_id))
        && !cfg.cloud_enabled_for_controlled_apps();

    if should_disable {
        // Write cloudenabled=false into Steam's in-memory config store (once per app).
        // This prevents the "out of date" cloud badge after hot-reload.
        // The VDF write filter strips it before disk flush.
        if vapor_forge_features::cloud::mark_cloud_wrote(AppId(app_id)) {
            if let Some(set_fn) = unsafe { *std::ptr::addr_of!(SET_CLOUD_FN) } {
                set_fn(this, app_id, false);
                info!(
                    app_id,
                    "cloud: SetCloudEnabledForApp(false) — badge suppressed"
                );
            }
        }
    }

    vapor_forge_features::cloud::on_is_cloud_enabled(&*cfg, AppId(app_id), result)
}

fn install_cloud_vmt(this: *mut c_void) {
    if CLOUD_VMT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }

    // Store original BEFORE swapping the vtable slot, so the hook callback
    // can find the original immediately if it fires on another thread.
    // SAFETY: this points to an IClientRemoteStorage C++ object; read vtable slot.
    let Some(slot) = crate::vtable_scan::slot_of("IClientRemoteStorage", "IsCloudEnabledForApp")
    else {
        warn!("hook-install: IsCloudEnabledForApp slot not found in VtableScan");
        return;
    };

    let orig_addr = unsafe { read_vtable_slot(this, slot) };
    let Some(addr) = orig_addr else { return };
    let replacement = hk_is_cloud_enabled_for_app as *const () as usize;

    if !validate_vmt_hook_eligibility("IsCloudEnabledForApp", addr, replacement) {
        return;
    }

    // SAFETY: transmuting a valid function address to a typed fn pointer.
    let orig_fn: IsCloudEnabledForAppFn = unsafe { std::mem::transmute(addr) };
    unsafe { std::ptr::addr_of_mut!(ORIGINAL_IS_CLOUD_ENABLED).write(Some(orig_fn)) };

    // SAFETY: swap the vtable slot (original already stored).
    unsafe {
        vmt::swap_vtable_slot("IsCloudEnabledForApp", this, slot, replacement);
    }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientAppManager::RunIPCFrame (DLC VMT)
// ---------------------------------------------------------------------------

extern "C" fn hk_app_manager_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !APP_MANAGER_VMT_DONE.load(Ordering::Acquire) {
        install_app_manager_vmt(this);
    }

    // SAFETY: APP_MANAGER_DETOUR set before enabled.
    let original = detour_or_return!("IClientAppManager::RunIPCFrame", APP_MANAGER_DETOUR, ());
    original.call(this, a1, a2, a3);
}

extern "C" fn hk_is_app_dlc_installed(this: *mut c_void, app_id: u32, dlc_id: u32) -> bool {
    // SAFETY: original function pointer set before VMT swap.
    let original = vmt_or_return!("IsAppDlcInstalled", ORIG_IS_APP_DLC_INSTALLED, false);
    let result = original(this, app_id, dlc_id);

    let cfg = config();
    vapor_forge_features::dlc::on_is_dlc_installed(&*cfg, AppId(app_id), AppId(dlc_id), result)
}

extern "C" fn hk_b_is_dlc_enabled(
    this: *mut c_void,
    app_id: u32,
    dlc_id: u32,
    unknown: *mut c_void,
) -> bool {
    // SAFETY: original function pointer set before VMT swap.
    let original = vmt_or_return!("BIsDlcEnabled", ORIG_B_IS_DLC_ENABLED, false);
    let result = original(this, app_id, dlc_id, unknown);

    let cfg = config();
    vapor_forge_features::dlc::on_is_dlc_enabled(&*cfg, AppId(app_id), AppId(dlc_id), result)
}

extern "C" fn hk_launch_app(
    this: *mut c_void,
    p_app_id: *mut u32,
    a2: *mut c_void,
    a3: *mut c_void,
    a4: *mut c_void,
) -> *mut c_void {
    if !p_app_id.is_null() {
        let app_id = unsafe { *p_app_id };
        debug!(app_id, "LaunchApp");
    }
    // Flag evaluation moved to SpawnProcess hook (has pCommandLine directly).
    let original = vmt_or_return!("LaunchApp", ORIG_LAUNCH_APP, std::ptr::null_mut());
    original(this, p_app_id, a2, a3, a4)
}

fn install_app_manager_vmt(this: *mut c_void) {
    if APP_MANAGER_VMT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }

    let slot_installed = crate::vtable_scan::slot_of("IClientAppManager", "IsAppDlcInstalled");
    let slot_enabled = crate::vtable_scan::slot_of("IClientAppManager", "BIsDlcEnabled");
    let slot_launch = crate::vtable_scan::slot_of("IClientAppManager", "LaunchApp");

    if let Some(slot) = slot_installed {
        if let Some(addr) = unsafe { read_vtable_slot(this, slot) } {
            let repl = hk_is_app_dlc_installed as *const () as usize;
            if validate_vmt_hook_eligibility("IsAppDlcInstalled", addr, repl) {
                unsafe {
                    std::ptr::addr_of_mut!(ORIG_IS_APP_DLC_INSTALLED)
                        .write(Some(std::mem::transmute(addr)));
                    vmt::swap_vtable_slot("IsAppDlcInstalled", this, slot, repl);
                }
            }
        }
    } else {
        warn!("hook-install: IsAppDlcInstalled slot not found");
    }

    if let Some(slot) = slot_enabled {
        if let Some(addr) = unsafe { read_vtable_slot(this, slot) } {
            let repl = hk_b_is_dlc_enabled as *const () as usize;
            if validate_vmt_hook_eligibility("BIsDlcEnabled", addr, repl) {
                unsafe {
                    std::ptr::addr_of_mut!(ORIG_B_IS_DLC_ENABLED)
                        .write(Some(std::mem::transmute(addr)));
                    vmt::swap_vtable_slot("BIsDlcEnabled", this, slot, repl);
                }
            }
        }
    } else {
        warn!("hook-install: BIsDlcEnabled slot not found");
    }

    // LaunchApp: intercept to evaluate AppAvatar flag rules at game-launch time.
    if let Some(slot) = slot_launch {
        if let Some(addr) = unsafe { read_vtable_slot(this, slot) } {
            let repl = hk_launch_app as *const () as usize;
            if validate_vmt_hook_eligibility("LaunchApp", addr, repl) {
                // SAFETY: original stored before VMT slot is replaced.
                unsafe {
                    std::ptr::addr_of_mut!(ORIG_LAUNCH_APP).write(Some(std::mem::transmute(addr)));
                    vmt::swap_vtable_slot("LaunchApp", this, slot, repl);
                }
            }
        }
    } else {
        debug!("hook-install: LaunchApp slot not found (app-avatar flag rules inactive)");
    }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientApps::RunIPCFrame (DLC count/data VMT)
// ---------------------------------------------------------------------------

extern "C" fn hk_client_apps_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !CLIENT_APPS_VMT_DONE.load(Ordering::Acquire) {
        install_client_apps_vmt(this);
    }

    // SAFETY: CLIENT_APPS_DETOUR set before enabled.
    let original = detour_or_return!("IClientApps::RunIPCFrame", CLIENT_APPS_DETOUR, ());
    original.call(this, a1, a2, a3);
}

// DLC enumeration (GetDLCCount / BGetDLCDataByIndex) is NOT hooked.
// DLC app IDs go into pkg0 alongside main app IDs, so Steam downloads
// their appinfo and handles enumeration natively.

fn install_client_apps_vmt(_this: *mut c_void) {
    if CLIENT_APPS_VMT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }
    // IClientApps VMT hooks removed. DLC handled via pkg0 injection.
}

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientUser::GetSteamID (ticket-delegate spoof)
// ---------------------------------------------------------------------------

/// Return the delegate (previous owner) SteamID while a delegate ticket
/// window is active for the currently launched app, otherwise pass through.
///
/// This spoof is global rather than keyed to a specific app: the runtime
/// only supports one delegate-ticket app being active at a time, which
/// matches the existing single-game-at-a-time launch model.
extern "C" fn hk_get_steamid(this: *mut c_void) -> u64 {
    // SAFETY: ORIG_GET_STEAMID set before the VMT slot is swapped.
    let original = vmt_or_return!("GetSteamID", ORIG_GET_STEAMID, 0);
    let real_steamid = original(this);

    let delegate = vapor_forge_features::ticket::delegate_steamid();
    if delegate != 0 {
        debug!(
            real = real_steamid,
            delegate, "ticket: GetSteamID returning delegate SteamID"
        );
        return delegate;
    }

    real_steamid
}

fn install_steamid_vmt(this: *mut c_void) {
    if STEAMID_VMT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }

    let Some(slot) = crate::vtable_scan::slot_of("IClientUser", "GetSteamID") else {
        warn!("hook-install: GetSteamID slot not found in VtableScan");
        return;
    };

    let Some(addr) = (unsafe { read_vtable_slot(this, slot) }) else {
        return;
    };
    let repl = hk_get_steamid as *const () as usize;

    if !validate_vmt_hook_eligibility("GetSteamID", addr, repl) {
        return;
    }

    // SAFETY: transmuting a valid function address to a typed fn pointer.
    let orig_fn: GetSteamIDFn = unsafe { std::mem::transmute(addr) };
    unsafe { std::ptr::addr_of_mut!(ORIG_GET_STEAMID).write(Some(orig_fn)) };

    // SAFETY: swap the vtable slot (original already stored).
    unsafe {
        vmt::swap_vtable_slot("GetSteamID", this, slot, repl);
    }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: CConfigStore::WriteVdfFile (VDF cloud filter)
// ---------------------------------------------------------------------------

extern "C" fn hk_write_vdf_file(
    a0: *mut c_void,
    a1: u32,
    a2: u32,
    a3: *mut c_void,
    buffer: *const u8,
    size: u32,
) -> u32 {
    if !buffer.is_null() && size > 0 {
        // SAFETY: buffer/size from Steam's serialized VDF.
        let data = unsafe { std::slice::from_raw_parts(buffer, size as usize) };
        if let Some(filtered) = vapor_forge_features::cloud::strip_cloud_from_vdf(data) {
            debug!(
                original = size,
                filtered = filtered.len(),
                "cloud: VDF write filtered"
            );
            // SAFETY: calling original with filtered buffer.
            let original = detour_or_return!("WriteVdfFile", WRITE_VDF_DETOUR, 0);
            return original.call(a0, a1, a2, a3, filtered.as_ptr(), filtered.len() as u32);
        }
    }

    // SAFETY: pass through unmodified.
    let original = detour_or_return!("WriteVdfFile", WRITE_VDF_DETOUR, 0);
    original.call(a0, a1, a2, a3, buffer, size)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: BuildSpawnEnvBlock (native .so injection)
// ---------------------------------------------------------------------------

extern "C" fn hk_build_spawn_env_block(
    game_id: *mut c_void,
    exe_path: *const i8,
    working_dir: *const i8,
    launch_ctx: *mut c_void,
    flags: u32,
    something: *mut c_void,
    env_map: *mut c_void,
    context: *mut c_void,
) -> i32 {
    // Call original first so Steam has already populated the env block.
    // SAFETY: BUILD_SPAWN_ENV_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("BuildSpawnEnvBlock", BUILD_SPAWN_ENV_DETOUR, 0);
    let result = original.call(
        game_id,
        exe_path,
        working_dir,
        launch_ctx,
        flags,
        something,
        env_map,
        context,
    );

    if game_id.is_null() || env_map.is_null() {
        return result;
    }

    // CGameID low 24 bits = AppId. SAFETY: game_id is a valid CGameID* from Steam's caller.
    let raw = unsafe { *(game_id as *const u32) };
    let app_id = AppId(raw & 0x00FF_FFFF);

    let injection = vapor_forge_features::library_inject::take_pending(app_id);
    let ipc_server = IPC_SERVER.get().and_then(|s| s.as_ref());

    if injection.is_none() && ipc_server.is_none() {
        return result;
    }

    // SAFETY: SET_ENV_STRING_FN resolved once at install time, never modified after.
    let Some(set_env) = (unsafe { *std::ptr::addr_of!(SET_ENV_STRING_FN) }) else {
        warn!(app = app_id.0, "library_inject: SetEnvString unresolved");
        return result;
    };

    // Native .so injection via LD_PRELOAD
    if let Some(ref inj) = injection {
        if !inj.native_libs.is_empty() {
            let ld_preload = inj.native_libs.join(":");
            if let Ok(value) = std::ffi::CString::new(ld_preload.as_str()) {
                set_env(
                    env_map,
                    b"LD_PRELOAD\0".as_ptr() as *const i8,
                    value.as_ptr(),
                );
                info!(app = app_id.0, paths = %ld_preload, "library_inject: LD_PRELOAD set");
            }
        }
    }

    let has_proton_dll = injection
        .as_ref()
        .and_then(|i| i.proton_dll.as_ref())
        .is_some();

    // IPC token injection: register a per-launch token whenever the IPC
    // server is running, regardless of whether this game has a DLL to
    // inject. The helper may be loaded solely for PE scanning.
    if let Some(server) = ipc_server {
        if let Ok(token) = vapor_forge_inject_protocol::generate_token() {
            server.register_token(token, app_id.0);
            let hex = vapor_forge_inject_protocol::token_to_hex(&token);
            if let (Ok(key), Ok(val)) = (
                std::ffi::CString::new(vapor_forge_inject_protocol::ENV_IPC_TOKEN),
                std::ffi::CString::new(hex.as_str()),
            ) {
                set_env(env_map, key.as_ptr(), val.as_ptr());
            }
            if let Ok(sock_val) = std::ffi::CString::new(server.socket_path()) {
                set_env(
                    env_map,
                    b"VAPOR_FORGE_IPC_SOCK\0".as_ptr() as *const i8,
                    sock_val.as_ptr(),
                );
            }
            debug!(app = app_id.0, "library_inject: IPC token injected");
        }

        // If no DLL injection is configured but IPC is needed, load the
        // proton helper anyway so it can scan PEs and report back.
        if !has_proton_dll {
            let cfg = config();
            if let Some(path) = resolve_helper_path(&cfg.library_inject.helper_path) {
                if let Ok(audit_val) = std::ffi::CString::new(path.as_str()) {
                    set_env(
                        env_map,
                        b"LD_AUDIT\0".as_ptr() as *const i8,
                        audit_val.as_ptr(),
                    );
                    debug!(app = app_id.0, helper = %path, "library_inject: helper loaded for IPC only");
                }
            }
        }
    }

    // Proton .dll injection via LD_AUDIT helper
    if let Some(ref inj) = injection {
        if let Some(dll_path) = &inj.proton_dll {
            let cfg = config();
            let resolved = resolve_helper_path(&cfg.library_inject.helper_path);
            match resolved {
                Some(path) => {
                    if let (Ok(audit_val), Ok(dll_val)) = (
                        std::ffi::CString::new(path.as_str()),
                        std::ffi::CString::new(dll_path.as_str()),
                    ) {
                        set_env(
                            env_map,
                            b"LD_AUDIT\0".as_ptr() as *const i8,
                            audit_val.as_ptr(),
                        );
                        set_env(
                            env_map,
                            b"VAPOR_FORGE_INJECT_DLL\0".as_ptr() as *const i8,
                            dll_val.as_ptr(),
                        );
                        info!(app = app_id.0, dll = %dll_path, helper = %path, "library_inject: Proton DLL injection set");
                    }
                }
                None => {
                    warn!(app = app_id.0, "library_inject: proton helper not found");
                }
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Hook replacement functions -- CUser::SpawnProcess (flag evaluation)
// ---------------------------------------------------------------------------

extern "C" fn hk_spawn_process(
    this: *mut c_void,
    exe_path: *const i8,
    command_line: *const i8,
    working_dir: *const i8,
    game_id: *mut c_void,
    extra: *const i8,
    flags1: u32,
    flags2: u32,
    launch_source: u32,
    flags3: u32,
    p_pid: *mut u32,
) -> i32 {
    // Extract AppId from CGameID (low 24 bits)
    if !game_id.is_null() {
        let raw = unsafe { *(game_id as *const u32) };
        let app_id = AppId(raw & 0x00FF_FFFF);

        // Read command line for flag evaluation
        let launch_opts = if !command_line.is_null() {
            unsafe { bounded_cstr_to_string(command_line, 4096) }
        } else {
            String::new()
        };

        let cfg = config();
        if !cfg.app_avatar.rules.is_empty() {
            vapor_forge_features::app_avatar::on_launch_app(
                app_id,
                &cfg.app_avatar.rules,
                &launch_opts,
            );
        }
        if !cfg.library_inject.libs.is_empty() {
            vapor_forge_features::library_inject::on_launch_app(
                app_id,
                &cfg.library_inject.libs,
                &launch_opts,
            );
        }
    }

    let original = detour_or_return!("SpawnProcess", SPAWN_PROCESS_DETOUR, -1);
    original.call(
        this,
        exe_path,
        command_line,
        working_dir,
        game_id,
        extra,
        flags1,
        flags2,
        launch_source,
        flags3,
        p_pid,
    )
}

/// Bounded read of a C string into a Rust String.
unsafe fn bounded_cstr_to_string(ptr: *const i8, max_len: usize) -> String {
    let mut len = 0usize;
    while len < max_len {
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// Resolve SetCloudEnabledForApp as a raw fn pointer, not a detour. It is called directly.
fn resolve_set_cloud_fn(registry: &PatternRegistry, code: &CodeRegion) {
    let entry = match registry.get("IClientRemoteStorage::SetCloudEnabledForApp") {
        Some(e) => e,
        None => return,
    };
    let addr = match detour::resolve_pattern_entry(code, "SetCloudEnabledForApp", &entry) {
        Some(a) => a,
        None => return,
    };
    // SAFETY: addr is a validated code address.
    let f: SetCloudEnabledForAppFn = unsafe { std::mem::transmute(addr) };
    unsafe { std::ptr::addr_of_mut!(SET_CLOUD_FN).write(Some(f)) };
    debug!(
        addr = format_args!("0x{:x}", addr),
        "SetCloudEnabledForApp resolved"
    );
}

/// Resolve SetEnvString as a raw fn pointer, not a detour. Called directly from
/// hk_build_spawn_env_block to inject LD_PRELOAD into the child env map.
const PROTON_HELPER_NAME: &str = "libvapor_forge_proton_inject.so";

/// Resolve the 64-bit proton inject helper path.
/// Priority: config override > same dir as our .so > /usr/lib > /usr/lib64.
fn resolve_helper_path(configured: &str) -> Option<String> {
    if !configured.is_empty() {
        let p = std::path::Path::new(configured);
        if p.exists() {
            return Some(configured.to_owned());
        }
        warn!(
            path = configured,
            "library_inject: configured helper_path not found"
        );
    }

    // Same directory as our own .so
    if let Some(dir) = own_library_dir() {
        let candidate = std::path::Path::new(&dir).join(PROTON_HELPER_NAME);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }

    // Standard system paths (helper is 64-bit)
    for dir in ["/usr/lib", "/usr/lib64"] {
        let candidate = std::path::Path::new(dir).join(PROTON_HELPER_NAME);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }

    None
}

/// Get the directory containing our own .so via dladdr.
fn own_library_dir() -> Option<String> {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let self_addr = own_library_dir as *const () as *mut libc::c_void;
    if unsafe { libc::dladdr(self_addr, &mut info) } == 0 || info.dli_fname.is_null() {
        return None;
    }
    let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) };
    let path_str = path.to_str().ok()?;
    std::path::Path::new(path_str)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
}

fn resolve_set_env_string(registry: &PatternRegistry, code: &CodeRegion) {
    let entry = match registry.get("SetEnvString") {
        Some(e) => e,
        None => return,
    };
    let call_addr = match detour::resolve_pattern_entry(code, "SetEnvString", &entry) {
        Some(a) => a,
        None => return,
    };
    // SAFETY: call_addr is a validated code address.
    let f: SetEnvStringFn = unsafe { std::mem::transmute(call_addr) };
    unsafe { std::ptr::addr_of_mut!(SET_ENV_STRING_FN).write(Some(f)) };
    debug!(
        addr = format_args!("0x{:x}", call_addr),
        "SetEnvString resolved"
    );
}

// ---------------------------------------------------------------------------
// Detour creation for special cases
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Hook replacement functions: GetAppOwnershipTicketExtendedData (ticket forge)
// ---------------------------------------------------------------------------

extern "C" fn hk_ticket_ext_data(
    this: *mut c_void,
    app_id: u32,
    p_ticket: *mut u8,
    ticket_buf_size: u32,
    pi_app_id: *mut u32,
    pi_steam_id: *mut u32,
    pi_signature: *mut u32,
    pcb_signature: *mut u32,
) -> u32 {
    // SAFETY: TICKET_EXT_DATA_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!(
        "GetAppOwnershipTicketExtendedData",
        TICKET_EXT_DATA_DETOUR,
        0
    );
    let result = original.call(
        this,
        app_id,
        p_ticket,
        ticket_buf_size,
        pi_app_id,
        pi_steam_id,
        pi_signature,
        pcb_signature,
    );

    // If Steam returned a valid ticket, cache it.
    // Persist decision:
    //   Controlled + delegate → always disk (cross-account)
    //   Controlled + forge   → never disk (re-acquirable)
    //   Uncontrolled (real)  → follows [ticket] cache setting
    if result > 0 && !p_ticket.is_null() {
        let size = result as usize;
        // SAFETY: p_ticket points to a buffer with at least `result` bytes written by Steam.
        let ticket_data = unsafe { std::slice::from_raw_parts(p_ticket, size) }.to_vec();
        let cfg = config();
        let persist = if cfg.app_category(AppId(app_id)).is_some() {
            effective_ticket_mode(&cfg, AppId(app_id)) == vapor_forge_config::TicketMode::Delegate
        } else {
            cfg.ticket.cache == vapor_forge_config::TicketCacheMode::Disk
        };
        TICKET_CACHE.store_app_ticket(AppId(app_id), ticket_data, persist);
        return result;
    }

    // Original returned 0, so check if this is a controlled app.
    let cfg = config();
    if cfg.app_category(AppId(app_id)).is_none() {
        return result;
    }

    let ticket_mode = effective_ticket_mode(&cfg, AppId(app_id));
    let ss = script_state();

    // Delegate mode: while inside the initial request window, prefer the
    // cached ticket (from a previous owner session) over forging so the
    // ticket's embedded SteamID matches an account that actually owns the
    // app. Once the window closes, fall through to the normal forge path
    // and stop spoofing GetSteamID.
    if ticket_mode == vapor_forge_config::TicketMode::Delegate {
        if vapor_forge_features::ticket::in_delegate_window(AppId(app_id)) {
            if let Some(ticket) = TICKET_CACHE.get_app_ticket(AppId(app_id), &ss.app_tickets) {
                if let Some(steamid) = extract_steamid_from_ticket(&ticket) {
                    vapor_forge_features::ticket::set_delegate_steamid(steamid);
                }
                return copy_ticket_to_buffer(
                    &ticket,
                    p_ticket,
                    ticket_buf_size,
                    pi_app_id,
                    pi_steam_id,
                    pi_signature,
                    pcb_signature,
                    app_id,
                    "delegate-cached",
                );
            }
            // No cached ticket available yet, fall through to forge below.
            debug!(
                app_id,
                "ticket: delegate window active but no cached ticket, forging"
            );
        } else {
            vapor_forge_features::ticket::clear_delegate_steamid();
        }
    }

    // Try to provide a ticket from cache / Lua / forge
    if let Some(ticket) = TICKET_CACHE.get_app_ticket(AppId(app_id), &ss.app_tickets) {
        return copy_ticket_to_buffer(
            &ticket,
            p_ticket,
            ticket_buf_size,
            pi_app_id,
            pi_steam_id,
            pi_signature,
            pcb_signature,
            app_id,
            "cached",
        );
    }

    // Forge from appId 7 source ticket
    if let Some(forged) = try_forge_ticket(this, app_id) {
        return copy_ticket_to_buffer(
            &forged.data,
            p_ticket,
            ticket_buf_size,
            pi_app_id,
            pi_steam_id,
            pi_signature,
            pcb_signature,
            app_id,
            "forged",
        );
    }

    debug!(
        app_id,
        "ticket: no ticket available (no cache, no source for forge)"
    );
    result
}

/// Extract the SteamID embedded in a raw ownership ticket, using the
/// standard `TICKET_STEAMID_OFFSET` (byte 8, little-endian u64). Returns
/// `None` if the ticket is too small to contain a SteamID field.
fn extract_steamid_from_ticket(ticket: &[u8]) -> Option<u64> {
    const STEAMID_OFFSET: usize = 8;
    let end = STEAMID_OFFSET.checked_add(8)?;
    let bytes: [u8; 8] = ticket.get(STEAMID_OFFSET..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Copy ticket data into the output buffer and populate offset pointers.
fn copy_ticket_to_buffer(
    ticket: &[u8],
    p_ticket: *mut u8,
    buf_size: u32,
    pi_app_id: *mut u32,
    pi_steam_id: *mut u32,
    pi_signature: *mut u32,
    pcb_signature: *mut u32,
    app_id: u32,
    source: &str,
) -> u32 {
    let copy_len = ticket.len().min(buf_size as usize);
    if p_ticket.is_null() || copy_len == 0 {
        return 0;
    }

    // SAFETY: p_ticket is a valid buffer of buf_size bytes, provided by Steam's caller.
    unsafe {
        std::ptr::copy_nonoverlapping(ticket.as_ptr(), p_ticket, copy_len);
    }

    // Fill out offset pointers for the forged ticket structure.
    // Use sensible defaults: signature is the last 128 bytes.
    let sig_size: u32 = 128;
    let total = copy_len as u32;
    let sig_offset = if total > sig_size {
        total - sig_size
    } else {
        0
    };
    let app_offset = if sig_offset >= 4 { sig_offset - 4 } else { 0 };

    if !pi_app_id.is_null() {
        // SAFETY: pi_app_id is a valid pointer from Steam's caller.
        unsafe { *pi_app_id = app_offset };
    }
    if !pi_steam_id.is_null() {
        // SAFETY: pi_steam_id is a valid pointer from Steam's caller.
        unsafe { *pi_steam_id = 8 };
    }
    if !pi_signature.is_null() {
        // SAFETY: pi_signature is a valid pointer from Steam's caller.
        unsafe { *pi_signature = sig_offset };
    }
    if !pcb_signature.is_null() {
        // SAFETY: pcb_signature is a valid pointer from Steam's caller.
        unsafe { *pcb_signature = sig_size };
    }

    info!(app_id, size = copy_len, source, "ticket: provided to Steam");
    total
}

/// Try to forge a ticket for `target_app_id` from the appId 7 source ticket.
fn try_forge_ticket(
    this: *mut c_void,
    target_app_id: u32,
) -> Option<vapor_forge_features::ticket::forge::ForgedTicket> {
    use vapor_forge_features::ticket::forge;

    let source = SOURCE_TICKET_7.get_or_init(|| acquire_source_ticket(this));

    let source_data = source.as_ref()?;
    let forged = forge::forge_from_source(source_data, target_app_id);
    if forged.is_some() {
        info!(target_app_id, "ticket: derived from appId 7 source");
    }
    forged
}

/// Acquire the source ticket (appId 7) by calling the original function directly.
fn acquire_source_ticket(this: *mut c_void) -> Option<Vec<u8>> {
    const BUF_SIZE: u32 = 4096;
    let mut buf = vec![0u8; BUF_SIZE as usize];
    let mut app_id_off: u32 = 0;
    let mut steam_id_off: u32 = 0;
    let mut sig_off: u32 = 0;
    let mut sig_size: u32 = 0;

    // SAFETY: TICKET_EXT_DATA_DETOUR set before hook enabled; calling the original.
    let size = unsafe {
        (*std::ptr::addr_of!(TICKET_EXT_DATA_DETOUR))
            .as_ref()?
            .call(
                this,
                vapor_forge_features::ticket::forge::SOURCE_APP_ID,
                buf.as_mut_ptr(),
                BUF_SIZE,
                &mut app_id_off,
                &mut steam_id_off,
                &mut sig_off,
                &mut sig_size,
            )
    };

    if size == 0 {
        warn!("ticket: failed to acquire source ticket (appId 7)");
        return None;
    }

    buf.truncate(size as usize);
    info!(size, "ticket: acquired source ticket from appId 7");
    Some(buf)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: BUpdateAppOwnershipTicket
// ---------------------------------------------------------------------------

extern "C" fn hk_update_ticket(this: *mut c_void, app_id: u32, force: bool) -> u32 {
    let cfg = config();
    if cfg.app_category(AppId(app_id)).is_some()
        && !vapor_forge_features::apps::is_actually_owned(AppId(app_id))
    {
        // For controlled apps, report success without asking Steam to update
        // (the real update would fail for apps we don't own).
        debug!(app_id, "ticket: BUpdateAppOwnershipTicket handled");
        return 1;
    }

    // SAFETY: UPDATE_TICKET_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("BUpdateAppOwnershipTicket", UPDATE_TICKET_DETOUR, 0);
    original.call(this, app_id, force)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: IsUserSubscribedAppInTicket
// ---------------------------------------------------------------------------

extern "C" fn hk_is_subscribed_in_ticket(
    this: *mut c_void,
    app_id: u32,
    arg2: u32,
    arg3: u32,
    arg4: u32,
) -> u8 {
    let cfg = config();
    if cfg.app_category(AppId(app_id)).is_some()
        && !vapor_forge_features::apps::is_actually_owned(AppId(app_id))
    {
        debug!(app_id, "ticket: IsUserSubscribedAppInTicket resolved");
        return 1;
    }

    // SAFETY: IS_SUBSCRIBED_IN_TICKET_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!(
        "IsUserSubscribedAppInTicket",
        IS_SUBSCRIBED_IN_TICKET_DETOUR,
        0
    );
    original.call(this, app_id, arg2, arg3, arg4)
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
    let original = detour_or_return!("GetPackageInfo", GET_PKG_INFO_DETOUR, std::ptr::null_mut());
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
// Hook replacement functions: BuildDepotDependency (manifest injection)
// ---------------------------------------------------------------------------

extern "C" fn hk_build_depot_dependency(
    this: *mut c_void,
    app_id: u32,
    user_config: *mut c_void,
    p_depot_info: *mut c_void,
    p_shared_depot_info: *mut c_void,
    p_steam_app: *mut c_void,
    p_build_id: *mut u32,
    pb_beta_fallback: *mut bool,
) -> bool {
    // SAFETY: calling original.
    let original = detour_or_return!("BuildDepotDependency", BUILD_DEPOT_DETOUR, false);
    let result = original.call(
        this,
        app_id,
        user_config,
        p_depot_info,
        p_shared_depot_info,
        p_steam_app,
        p_build_id,
        pb_beta_fallback,
    );

    if !p_depot_info.is_null() {
        let ss = script_state();
        if !ss.manifests.is_empty() {
            // SAFETY: p_depot_info is a CUtlVector<DepotEntry>* filled by Steam.
            let vec = p_depot_info as *mut vapor_forge_abi::CUtlVector<vapor_forge_abi::DepotEntry>;
            // SAFETY: vec is valid after BuildDepotDependency returned.
            let size = unsafe { (*vec).len() };
            if size > 0 && size <= unsafe { (*vec).capacity() } {
                // Collect depot IDs for safe lookup (convert raw u32 to DepotId).
                let mut depot_ids: Vec<DepotId> = Vec::with_capacity(size);
                for i in 0..size {
                    // SAFETY: i < size.
                    depot_ids.push(DepotId(unsafe { (*vec).get(i) }.depot_id));
                }
                let patches = vapor_forge_features::manifest::find_patches(&depot_ids, &*ss);
                for patch in &patches {
                    for i in 0..size {
                        // SAFETY: i < size.
                        let entry = unsafe { (*vec).get_mut(i) };
                        if entry.depot_id == patch.depot_id.0 {
                            info!(
                                depot_id = patch.depot_id.0,
                                old_gid = entry.manifest_gid,
                                new_gid = patch.new_gid.0,
                                "manifest: pinned"
                            );
                            entry.manifest_gid = patch.new_gid.0;
                            if let Some(new_size) = patch.new_size {
                                if new_size > 0 {
                                    entry.manifest_size = new_size;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Hook replacement functions: LoadDepotDecryptionKey (depot key injection)
// ---------------------------------------------------------------------------

extern "C" fn hk_load_depot_decryption_key(
    this: *mut c_void,
    foo: u32,
    key_name: *const i8,
    key_buf: *mut u8,
    key_size: u32,
) -> i32 {
    if !key_name.is_null() && key_size >= 32 && !key_buf.is_null() {
        if let Some(depot_id_raw) = extract_depot_id_from_raw(key_name) {
            let ss = script_state();
            if let Some(key) =
                vapor_forge_features::depot_key::provide_key(DepotId(depot_id_raw), &ss.depot_keys)
            {
                // SAFETY: key_buf has key_size capacity >= 32, we write 32 bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(key.as_ptr(), key_buf, 32);
                }
                return 32;
            }
        }
    }

    // SAFETY: calling original.
    let original = detour_or_return!("LoadDepotDecryptionKey", DEPOT_KEY_DETOUR, 0);
    original.call(this, foo, key_name, key_buf, key_size)
}

fn extract_depot_id_from_raw(key_name: *const i8) -> Option<u32> {
    // Bounded scan for "\DecryptionKey" in the C string.
    const MAX_SCAN: usize = 512;
    const TAG: &[u8] = b"\\DecryptionKey";

    // SAFETY: bounded read of key_name up to MAX_SCAN bytes or NUL.
    let mut len = 0;
    while len < MAX_SCAN {
        let byte = unsafe { *key_name.add(len) } as u8;
        if byte == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return None;
    }

    // SAFETY: we just verified [0..len) are readable non-NUL bytes.
    let bytes = unsafe { std::slice::from_raw_parts(key_name as *const u8, len) };

    // Find "\DecryptionKey" tag
    let tag_pos = bytes.windows(TAG.len()).position(|w| w == TAG)?;

    // Extract depot ID: digits between the last '\' before tag and tag_pos
    let before_tag = &bytes[..tag_pos];
    let id_start = before_tag.iter().rposition(|&b| b == b'\\')? + 1;
    let id_bytes = &before_tag[id_start..];
    let id_str = std::str::from_utf8(id_bytes).ok()?;
    id_str.parse().ok()
}

// ---------------------------------------------------------------------------
// Hook replacement functions: BBuildAndAsyncSendFrame (outgoing WS frames)
// ---------------------------------------------------------------------------

extern "C" fn hk_send_frame(this: *mut c_void, opcode: i32, data: *mut u8, size: u32) -> bool {
    const WEBSOCKET_BINARY: i32 = 2;
    if opcode == WEBSOCKET_BINARY && !data.is_null() && size > 0 {
        // SAFETY: data is a valid buffer of `size` bytes, provided by Steam.
        let slice = unsafe { std::slice::from_raw_parts(data, size as usize) };

        match crate::netpacket::decide_send_frame(slice) {
            SendFrameDecision::Pass => {}
            SendFrameDecision::Drop => return true,
            SendFrameDecision::Rewrite(rewritten) => {
                // SAFETY: calling original with rewritten data.
                let original =
                    detour_or_return!("BBuildAndAsyncSendFrame", SEND_FRAME_DETOUR, false);
                return original.call(
                    this,
                    opcode,
                    rewritten.as_ptr() as *mut u8,
                    rewritten.len() as u32,
                );
            }
        }
    }

    // SAFETY: SEND_FRAME_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("BBuildAndAsyncSendFrame", SEND_FRAME_DETOUR, false);
    original.call(this, opcode, data, size)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: RecvPkt (incoming packets)
// ---------------------------------------------------------------------------

extern "C" fn hk_recv_pkt(this: *mut c_void, packet: *mut c_void) -> *mut c_void {
    // Try to inject fabricated responses from completed fetches.
    // SAFETY: this and packet are valid pointers from Steam's caller.
    // The closure calls the original RecvPkt.
    let call_original =
        |t, p| detour_or_return!("RecvPkt", RECV_PKT_DETOUR, std::ptr::null_mut()).call(t, p);
    unsafe {
        crate::netpacket::try_inject(this, packet, call_original);
    }

    // Process the real packet normally
    // SAFETY: RECV_PKT_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("RecvPkt", RECV_PKT_DETOUR, std::ptr::null_mut());
    let result = original.call(this, packet);

    // Post-process: strip achievement stats from incoming responses
    if !packet.is_null() {
        unsafe { crate::netpacket::on_recv_packet(packet) };
    }

    result
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
        let Some(ui_code) = crate::ui::steamui::get_steamui_code() else {
            warn!(
                "hook-install: steamui.so executable mapping unavailable, skipping steamui hooks"
            );
            STEAMUI_BATCH_FINISHED.store(true, Ordering::Release);
            info!(installed = false, "hook-install: steamui batch finished");
            return;
        };
        let registry = load_pattern_registry();
        let installed = crate::ui::steamui::install(&ui_code, &registry);
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
unsafe fn read_vtable_slot(this: *mut c_void, slot: usize) -> Option<usize> {
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
