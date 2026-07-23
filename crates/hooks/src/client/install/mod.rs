use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use tracing::{debug, error, info, warn};
use vapor_forge_memory::{find_proc_self_maps_targets, ProcMapsEntry};
use vapor_forge_patterns::registry::PatternRegistry;

use vapor_forge_hook_boundary::{validate_raw_hook_plan, RawAddressRange, RawHookEligibilityInput};

use crate::hook_report::{log_drift_summary, log_hook_details, store_results, HookResult};
use vapor_forge_hook_engine::detour::{self, CodeRegion, PendingDetour};

mod package_info;
mod runtime;
mod steamclient;
mod steamui;

pub use runtime::ensure_runtime_initialized;
pub(crate) use runtime::{
    build_runtime, build_script_dirs, config, effective_ticket_mode,
    ensure_runtime_services_for_config, merge_script_apps, package_state, runtime_snapshot,
    script_state, sync_config_template, RuntimeSnapshot, IPC_SERVER, TICKET_CACHE,
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
    if !steam_hook_batch_supported(batch) {
        warn!(
            batch = ?batch,
            arch = current_hook_architecture(),
            "hook-install: Steam hook batch skipped on unsupported process architecture"
        );
        mark_hook_batch_finished(batch);
        return;
    }
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

fn mark_hook_batch_finished(batch: HookBatch) {
    match batch {
        HookBatch::SteamClient => {
            steamclient::STEAMCLIENT_BATCH_FINISHED.store(true, Ordering::Release)
        }
        HookBatch::SteamUi => steamui::STEAMUI_BATCH_FINISHED.store(true, Ordering::Release),
    }
}

fn steam_hook_batch_supported(batch: HookBatch) -> bool {
    match batch {
        HookBatch::SteamClient => cfg!(target_os = "linux"),
        HookBatch::SteamUi => steamui_hooks_supported(),
    }
}

fn package_injection_supported() -> bool {
    cfg!(target_os = "linux")
}

fn vmt_scanner_supported() -> bool {
    cfg!(target_os = "linux")
}

fn env_hooks_supported() -> bool {
    cfg!(target_os = "linux")
}

fn steamui_hooks_supported() -> bool {
    cfg!(target_os = "linux") && std::env::var_os("VAPOR_FORGE_SKIP_STEAMUI_HOOKS").is_none()
}

fn current_hook_architecture() -> &'static str {
    if cfg!(target_pointer_width = "64") {
        "x86_64"
    } else if cfg!(target_pointer_width = "32") {
        "x86"
    } else {
        "unknown"
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
pub(crate) fn resolve_from_registry<F: vapor_forge_hook_engine::detour::HookFn>(
    registry: &PatternRegistry,
    code: &CodeRegion,
    name: &str,
    replacement: F,
) -> Option<PendingDetour<F>> {
    let addr = resolve_address_from_registry(registry, code, name)?;
    resolve_from_address(code, name, addr, replacement)
}

pub(crate) fn resolve_address_from_registry(
    registry: &PatternRegistry,
    code: &CodeRegion,
    name: &str,
) -> Option<usize> {
    let entry = registry.get(name).or_else(|| {
        warn!(hook = name, "pattern not found in registry");
        None
    })?;

    detour::resolve_pattern_entry(code, name, &entry)
}

fn resolve_from_address<F: vapor_forge_hook_engine::detour::HookFn>(
    code: &CodeRegion,
    name: &str,
    addr: usize,
    replacement: F,
) -> Option<PendingDetour<F>> {
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

fn resolve_cuser_stats_adapter<F: vapor_forge_hook_engine::detour::HookFn>(
    code: &CodeRegion,
    name: &str,
    public_method: &str,
    overload: usize,
    expected_overloads: usize,
    replacement: F,
) -> Option<PendingDetour<F>> {
    let slots = crate::vtable_scan::slots_of("IClientUserStats", public_method);
    if slots.len() != expected_overloads {
        error!(
            hook = name,
            public_method,
            found = slots.len(),
            expected = expected_overloads,
            "CUserStats adapter slot lookup failed"
        );
        return None;
    }
    let slot = slots[overload];
    let Some(addr) = crate::vtable_scan::method_address("CUserStats", slot) else {
        error!(
            hook = name,
            slot, "CUserStats adapter address was not found"
        );
        return None;
    };
    if !super::achievement_adapters::validate_adapter_target(code, name, addr) {
        error!(
            hook = name,
            slot,
            target = format_args!("0x{addr:x}"),
            "CUserStats adapter ABI validation failed"
        );
        return None;
    }
    debug!(
        hook = name,
        public_method,
        slot,
        target = format_args!("0x{addr:x}"),
        "CUserStats adapter resolved from vtable"
    );
    resolve_from_address(code, name, addr, replacement)
}

fn resolve_cuser_adapter<F: vapor_forge_hook_engine::detour::HookFn>(
    code: &CodeRegion,
    name: &str,
    public_method: &str,
    check_ownership: Option<usize>,
    replacement: F,
) -> Option<PendingDetour<F>> {
    let slots = crate::vtable_scan::slots_of("IClientUser", public_method);
    if slots.len() != 1 {
        error!(
            hook = name,
            public_method,
            found = slots.len(),
            "CUser adapter slot lookup failed"
        );
        return None;
    }
    let public_slot = slots[0];
    // Pick the CUser secondary vtable whose slot count matches the IClientUser
    // interface width, then take its entry at public_slot.
    let Some(iface_slot_count) = crate::vtable_scan::interface_slot_count("IClientUser") else {
        error!(
            hook = name,
            public_method, "IClientUser interface width unknown; cannot resolve CUser adapter"
        );
        return None;
    };
    let candidates = crate::vtable_scan::class_method_candidates("CUser")
        .into_iter()
        .filter(|candidate| candidate.offset_to_top < 0)
        .collect::<Vec<_>>();
    let mut by_slot = candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.slot == public_slot)
        .filter(|candidate| vtable_slot_count(&candidates, candidate.vtable_va) == iface_slot_count)
        .map(|candidate| {
            let implementation = super::ticket::resolve_adapter_implementation(
                code,
                name,
                candidate.func_va,
                check_ownership,
            )
            .unwrap_or(candidate.func_va);
            (candidate, implementation)
        })
        .collect::<Vec<_>>();
    by_slot.sort_by_key(|(_, implementation)| *implementation);
    by_slot.dedup_by_key(|(_, implementation)| *implementation);

    if by_slot.len() != 1 {
        error!(
            hook = name,
            public_method,
            public_slot,
            iface_slot_count,
            found = by_slot.len(),
            "CUser adapter slot resolution did not produce a unique target"
        );
        return None;
    }
    let (candidate, implementation) = by_slot[0];
    debug!(
        hook = name,
        public_method,
        public_slot,
        offset_to_top = candidate.offset_to_top,
        vtable = format_args!("0x{:x}", candidate.vtable_va),
        adapter = format_args!("0x{:x}", candidate.func_va),
        target = format_args!("0x{implementation:x}"),
        "CUser adapter resolved from vtable"
    );
    resolve_from_address(code, name, implementation, replacement)
}

fn vtable_slot_count(
    candidates: &[crate::vtable_scan::MethodCandidate],
    vtable_va: usize,
) -> usize {
    candidates
        .iter()
        .filter(|candidate| candidate.vtable_va == vtable_va)
        .map(|candidate| candidate.slot + 1)
        .max()
        .unwrap_or(0)
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
        actual_architecture: current_hook_architecture(),
        expected_architecture: current_hook_architecture(),
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
        actual_architecture: current_hook_architecture(),
        expected_architecture: current_hook_architecture(),
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
    let code = match get_steamclient_code() {
        Some(c) => c,
        None => return,
    };
    let _ = CODE_RANGE.set((code.base, code.base + code.bytes.len()));

    // Load pattern registry: try external file first, fall back to embedded
    let registry = load_pattern_registry();
    info!(patterns = registry.len(), "patterns loaded");

    if vmt_scanner_supported() {
        crate::vtable_scan::warmup();
    } else {
        info!(
            arch = current_hook_architecture(),
            "hook-install: VMT scanner hooks disabled on this architecture"
        );
    }

    // Resolve pkg0 injection function addresses. These are not hooks and are called directly.
    if package_injection_supported() {
        // SAFETY: registry entries are resolved and semantically validated
        // against this live steamclient executable mapping.
        unsafe { super::package::resolve_functions(&code, &registry) };

        if super::package::all_functions_resolved() {
            info!("hook-install: pkg0 functions resolved (4/4)");
        } else {
            warn!("hook-install: some pkg0 functions not resolved, injection may be limited");
        }
    } else {
        info!(
            arch = current_hook_architecture(),
            "hook-install: pkg0 injection disabled on this architecture"
        );
    }

    super::client_id::resolve(&registry, &code);
    super::eticket::resolve_set_api_call_result(&code, &registry);

    // Phase 1: create all detours (the engine allocates trampolines on a shared pool page).
    // Do NOT mprotect or PIC-repair yet. Modifying page permissions between allocations
    // would lock the pool page to RX before the engine can write the next trampoline.
    let d_steam_engine_init = resolve_from_registry(
        &registry,
        &code,
        "CSteamEngine::Init",
        super::eticket::hk_steam_engine_init as super::eticket::SteamEngineInitFn,
    );
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
    let d_remote_storage_ipc = if vmt_scanner_supported() {
        resolve_from_registry(
            &registry,
            &code,
            "IClientRemoteStorage::RunIPCFrame",
            super::cloud::hk_remote_storage_run_ipc_frame as super::cloud::RunIPCFrameFn,
        )
    } else {
        None
    };
    let d_app_mgr_ipc = if vmt_scanner_supported() {
        resolve_from_registry(
            &registry,
            &code,
            "IClientAppManager::RunIPCFrame",
            super::dlc::hk_app_manager_run_ipc_frame as super::cloud::RunIPCFrameFn,
        )
    } else {
        None
    };
    let d_client_apps_ipc = if vmt_scanner_supported() {
        resolve_from_registry(
            &registry,
            &code,
            "IClientApps::RunIPCFrame",
            super::dlc::hk_client_apps_run_ipc_frame as super::cloud::RunIPCFrameFn,
        )
    } else {
        None
    };
    let d_set_stat_int = resolve_cuser_stats_adapter(
        &code,
        super::achievement_adapters::SET_STAT_INT_NAME,
        "SetStat",
        0,
        2,
        super::achievement_adapters::hook_set_stat_int as super::achievement_adapters::SetStatIntFn,
    );
    let d_set_stat_float = resolve_cuser_stats_adapter(
        &code,
        super::achievement_adapters::SET_STAT_FLOAT_NAME,
        "SetStat",
        1,
        2,
        super::achievement_adapters::hook_set_stat_float
            as super::achievement_adapters::SetStatFloatFn,
    );
    let d_set_achievement = resolve_cuser_stats_adapter(
        &code,
        super::achievement_adapters::SET_ACHIEVEMENT_NAME,
        "SetAchievement",
        0,
        1,
        super::achievement_adapters::hook_set_achievement
            as super::achievement_adapters::SetAchievementFn,
    );
    let d_clear_achievement = resolve_cuser_stats_adapter(
        &code,
        super::achievement_adapters::CLEAR_ACHIEVEMENT_NAME,
        "ClearAchievement",
        0,
        1,
        super::achievement_adapters::hook_clear_achievement
            as super::achievement_adapters::SetAchievementFn,
    );
    let d_store_stats = resolve_cuser_stats_adapter(
        &code,
        super::achievement_adapters::STORE_STATS_NAME,
        "StoreStats",
        0,
        1,
        super::achievement_adapters::hook_store_stats as super::achievement_adapters::StoreStatsFn,
    );
    let d_achievement_progress = resolve_cuser_stats_adapter(
        &code,
        super::achievement_adapters::PROGRESS_NAME,
        "IndicateAchievementProgress",
        0,
        1,
        super::achievement_adapters::hook_progress
            as super::achievement_adapters::IndicateAchievementProgressFn,
    );
    super::achievement_adapters::register_remote_apply_targets(
        d_set_achievement
            .as_ref()
            .map_or(0, |detour| detour.callee_addr),
        d_clear_achievement
            .as_ref()
            .map_or(0, |detour| detour.callee_addr),
        d_store_stats
            .as_ref()
            .map_or(0, |detour| detour.callee_addr),
        d_achievement_progress
            .as_ref()
            .map_or(0, |detour| detour.callee_addr),
    );
    super::current_app::resolve(
        &code,
        d_achievement_progress
            .as_ref()
            .map(|detour| detour.callee_addr),
    );
    let d_get_pkg_info = if package_injection_supported() {
        package_info::create_detour()
    } else {
        None
    };
    let check_ownership = d_ownership.as_ref().map(|detour| detour.callee_addr);
    let d_ticket_ext = resolve_cuser_adapter(
        &code,
        super::ticket::TICKET_EXT_DATA_NAME,
        "GetAppOwnershipTicketExtendedData",
        check_ownership,
        super::ticket::hk_ticket_ext_data as super::ticket::TicketExtDataFn,
    );
    let d_update_ticket = resolve_cuser_adapter(
        &code,
        super::ticket::UPDATE_TICKET_NAME,
        "BUpdateAppOwnershipTicket",
        check_ownership,
        super::ticket::hk_update_ticket as super::ticket::UpdateTicketFn,
    );
    let d_is_sub_ticket = resolve_cuser_adapter(
        &code,
        super::ticket::IS_SUBSCRIBED_IN_TICKET_NAME,
        "IsUserSubscribedAppInTicket",
        check_ownership,
        super::ticket::hk_is_subscribed_in_ticket as super::ticket::IsSubscribedInTicketFn,
    );
    let d_request_enc = resolve_cuser_adapter(
        &code,
        super::eticket::REQUEST_ENCRYPTED_NAME,
        "RequestEncryptedAppTicket",
        check_ownership,
        super::eticket::hk_request_encrypted_app_ticket
            as super::eticket::RequestEncryptedAppTicketFn,
    );
    let d_get_enc = resolve_cuser_adapter(
        &code,
        super::eticket::GET_ENCRYPTED_NAME,
        "GetEncryptedAppTicket",
        check_ownership,
        super::eticket::hk_get_encrypted_app_ticket as super::eticket::GetEncryptedAppTicketFn,
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
    let d_post_work_item = resolve_from_registry(
        &registry,
        &code,
        "CWorkThreadPool::PostWorkItem",
        super::network::hk_post_work_item as super::network::WebSocketWorkerPostItemFn,
    );
    super::network::resolve_native_packet_functions(&registry, &code);
    // Route each response source's completion straight to its own injection
    // dispatch, so a fabricated response is delivered the moment it is ready
    // instead of waiting for the next inbound packet.
    vapor_forge_features::inject_wake::set_injection_router(Box::new(|source| {
        crate::netpacket::wake_source(source)
    }));
    let d_http_job_start = resolve_from_registry(
        &registry,
        &code,
        super::cloud_http::HTTP_JOB_START_NAME,
        super::cloud_http::hk_http_job_start as super::cloud_http::HttpJobStartFn,
    );
    let d_write_vdf = if vmt_scanner_supported() {
        resolve_from_registry(
            &registry,
            &code,
            "CConfigStore::WriteVdfFile",
            super::cloud::hk_write_vdf_file as super::cloud::WriteVdfFileFn,
        )
    } else {
        None
    };
    let d_build_spawn_env = if env_hooks_supported() {
        resolve_from_registry(
            &registry,
            &code,
            "CUser::BuildSpawnEnvBlock",
            super::env::hk_build_spawn_env_block as super::env::BuildSpawnEnvBlockFn,
        )
    } else {
        None
    };
    let d_spawn_process = if env_hooks_supported() {
        resolve_from_registry(
            &registry,
            &code,
            "CUser::SpawnProcess",
            super::env::hk_spawn_process as super::env::SpawnProcessFn,
        )
    } else {
        None
    };

    // Resolve SetEnvString as a raw fn pointer for library injection.
    if env_hooks_supported() {
        super::env::resolve_set_env_string(&registry, &code);
    }

    macro_rules! hr {
        ($name:expr, $d:expr) => {
            HookResult {
                name: $name,
                installed: $d.is_some(),
                addr: $d.as_ref().map_or(0, |p| p.callee_addr),
            }
        };
    }
    #[cfg_attr(not(target_pointer_width = "32"), allow(unused_mut))]
    let hook_results = vec![
        hr!("CSteamEngine::Init", d_steam_engine_init),
        hr!("CUser::CheckAppOwnership", d_ownership),
        hr!("CUser::GetSubscribedApps", d_subscribed),
        hr!("IClientRemoteStorage::RunIPCFrame", d_remote_storage_ipc),
        hr!("IClientAppManager::RunIPCFrame", d_app_mgr_ipc),
        hr!("IClientApps::RunIPCFrame", d_client_apps_ipc),
        hr!(
            super::achievement_adapters::SET_STAT_INT_NAME,
            d_set_stat_int
        ),
        hr!(
            super::achievement_adapters::SET_STAT_FLOAT_NAME,
            d_set_stat_float
        ),
        hr!(
            super::achievement_adapters::SET_ACHIEVEMENT_NAME,
            d_set_achievement
        ),
        hr!(
            super::achievement_adapters::CLEAR_ACHIEVEMENT_NAME,
            d_clear_achievement
        ),
        hr!(super::achievement_adapters::STORE_STATS_NAME, d_store_stats),
        hr!(
            super::achievement_adapters::PROGRESS_NAME,
            d_achievement_progress
        ),
        HookResult {
            name: package_info::hook_name(),
            installed: d_get_pkg_info.is_some(),
            addr: super::package::get_package_info_addr().unwrap_or(0),
        },
        hr!(
            "IClientUser::GetAppOwnershipTicketExtendedData",
            d_ticket_ext
        ),
        hr!("IClientUser::BUpdateAppOwnershipTicket", d_update_ticket),
        hr!("IClientUser::IsUserSubscribedAppInTicket", d_is_sub_ticket),
        hr!("IClientUser::RequestEncryptedAppTicket", d_request_enc),
        hr!("IClientUser::GetEncryptedAppTicket", d_get_enc),
        hr!("BuildDepotDependency", d_build_depot),
        hr!("LoadDepotDecryptionKey", d_depot_key),
        hr!(
            "CWebSocketConnection::BBuildAndAsyncSendFrame",
            d_send_frame
        ),
        hr!("CCMConnection::RecvPkt", d_recv_pkt),
        hr!("CWorkThreadPool::PostWorkItem", d_post_work_item),
        hr!(super::cloud_http::HTTP_JOB_START_NAME, d_http_job_start),
        hr!("CConfigStore::WriteVdfFile", d_write_vdf),
        hr!("CUser::BuildSpawnEnvBlock", d_build_spawn_env),
        hr!("CUser::SpawnProcess", d_spawn_process),
    ];

    // Phase 2: PIC-repair all trampolines, then enable.
    // SAFETY: each static is written exactly once during init.
    unsafe {
        detour::store_and_finalize(
            "CSteamEngine::Init",
            std::ptr::addr_of_mut!(super::eticket::STEAM_ENGINE_INIT_DETOUR),
            d_steam_engine_init,
        );
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
            super::achievement_adapters::SET_STAT_INT_NAME,
            std::ptr::addr_of_mut!(super::achievement_adapters::SET_STAT_INT_DETOUR),
            d_set_stat_int,
        );
        detour::store_and_finalize(
            super::achievement_adapters::SET_STAT_FLOAT_NAME,
            std::ptr::addr_of_mut!(super::achievement_adapters::SET_STAT_FLOAT_DETOUR),
            d_set_stat_float,
        );
        detour::store_and_finalize(
            super::achievement_adapters::SET_ACHIEVEMENT_NAME,
            std::ptr::addr_of_mut!(super::achievement_adapters::SET_ACHIEVEMENT_DETOUR),
            d_set_achievement,
        );
        detour::store_and_finalize(
            super::achievement_adapters::CLEAR_ACHIEVEMENT_NAME,
            std::ptr::addr_of_mut!(super::achievement_adapters::CLEAR_ACHIEVEMENT_DETOUR),
            d_clear_achievement,
        );
        detour::store_and_finalize(
            super::achievement_adapters::STORE_STATS_NAME,
            std::ptr::addr_of_mut!(super::achievement_adapters::STORE_STATS_DETOUR),
            d_store_stats,
        );
        detour::store_and_finalize(
            super::achievement_adapters::PROGRESS_NAME,
            std::ptr::addr_of_mut!(super::achievement_adapters::PROGRESS_DETOUR),
            d_achievement_progress,
        );
        detour::store_and_finalize(
            package_info::hook_name(),
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
            "IClientUser::RequestEncryptedAppTicket",
            std::ptr::addr_of_mut!(super::eticket::REQUEST_ENCRYPTED_DETOUR),
            d_request_enc,
        );
        detour::store_and_finalize(
            "IClientUser::GetEncryptedAppTicket",
            std::ptr::addr_of_mut!(super::eticket::GET_ENCRYPTED_DETOUR),
            d_get_enc,
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
            "CWorkThreadPool::PostWorkItem",
            std::ptr::addr_of_mut!(super::network::POST_WORK_ITEM_DETOUR),
            d_post_work_item,
        );
        detour::store_and_finalize(
            super::cloud_http::HTTP_JOB_START_NAME,
            std::ptr::addr_of_mut!(super::cloud_http::HTTP_JOB_START_DETOUR),
            d_http_job_start,
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
