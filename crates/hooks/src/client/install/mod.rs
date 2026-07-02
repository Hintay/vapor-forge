use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use tracing::{debug, error, info, warn};
use vapor_forge_memory::{find_proc_self_maps_targets, ProcMapsEntry};
use vapor_forge_patterns::registry::PatternRegistry;

use vapor_forge_hook_boundary::{validate_raw_hook_plan, RawAddressRange, RawHookEligibilityInput};

use crate::detour::{self, CodeRegion, PendingDetour};
use crate::hook_report::{log_drift_summary, log_hook_details, store_results, HookResult};

mod package_info;
mod runtime;
mod steamclient;
mod steamui;

pub use runtime::ensure_runtime_initialized;
use runtime::runtime_hooks_enabled;
pub(crate) use runtime::{
    build_script_dirs, config, effective_ticket_mode, package_state, script_state, IPC_SERVER,
    TICKET_CACHE,
};

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static PKG0_INJECTED: AtomicBool = AtomicBool::new(false);

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
        HookBatch::SteamClient => steamclient::install_hook_batch(),
        HookBatch::SteamUi => steamui::install_hook_batch(),
    }
}

pub fn is_hook_batch_finished(batch: HookBatch) -> bool {
    match batch {
        HookBatch::SteamClient => steamclient::STEAMCLIENT_BATCH_FINISHED.load(Ordering::Acquire),
        HookBatch::SteamUi => steamui::STEAMUI_BATCH_FINISHED.load(Ordering::Acquire),
    }
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
    let d_get_pkg_info = package_info::create_detour();
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
            std::ptr::addr_of_mut!(package_info::GET_PKG_INFO_DETOUR),
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
    store_results("steamclient.so", &hook_results);

    if config().runtime.diagnostics {
        log_hook_details("steamclient.so", &hook_results);
    }

    // Background fetch of online pattern updates
    let cfg = config();
    if !cfg.runtime.patterns_url.is_empty() {
        vapor_forge_features::online_patterns::spawn_fetch(
            cfg.runtime.patterns_url.clone(),
            vapor_forge_patterns::registry::EMBEDDED_PATTERNS_HASH,
        );
    }
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

fn steamclient_code_range() -> Option<(usize, usize)> {
    CODE_RANGE.get().copied()
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
