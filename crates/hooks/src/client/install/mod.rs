use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use tracing::{debug, error, info, warn};
use vapor_forge_memory::{find_proc_self_maps_targets, ProcMapsEntry};
use vapor_forge_patterns::registry::{
    PatternArchitecture, PatternRegistry, PatternTarget, SteamBinaryFamily,
};

use crate::hook_report::{log_drift_summary, log_hook_details, store_results, HookResult};
use crate::pattern_resolver::{resolve_pattern_entry, validate_resolved_pattern, CodeRegion};
use vapor_forge_hook_engine::detour::{self, PendingDetour};
use vapor_forge_hook_engine::plan::{
    validate_hook_target, AddressRange, HookPlanError, HookTargetInput, ValidatedHookTarget,
};

mod package_info;
mod runtime;
mod steamclient;
mod steamui;

pub use runtime::ensure_runtime_initialized;
pub(crate) use runtime::{
    build_runtime, build_script_dirs, config, effective_ticket_mode,
    ensure_runtime_services_for_config, merge_script_apps, package_state, runtime_generation,
    runtime_snapshot, script_state, steam_install_root, RuntimeSnapshot, IPC_SERVER, TICKET_CACHE,
};

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static PKG0_INJECTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn reset_account_state() {
    PKG0_INJECTED.store(false, Ordering::Release);
    package_info::reset_account_state();
    package_state().reset_account_state();
}

#[cfg(test)]
pub(crate) fn seed_account_state_for_test() {
    PKG0_INJECTED.store(true, Ordering::Release);
    package_info::seed_account_state_for_test();
    package_state().set_active();
    package_state().record_injected(&[vapor_forge_config::AppId(5)]);
}

#[cfg(test)]
pub(crate) fn account_state_is_clear_for_test() -> bool {
    !PKG0_INJECTED.load(Ordering::Acquire)
        && package_info::account_state_is_clear_for_test()
        && !package_state().is_active()
        && package_state().injected_count() == 0
}

static CODE_RANGE: OnceLock<(usize, usize)> = OnceLock::new();

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookBatch {
    SteamClient,
    SteamUi,
}

const STEAMCLIENT_CAPABILITIES: &[crate::capability::Capability] = &[
    crate::capability::Capability::CallbackEvents,
    crate::capability::Capability::Ownership,
    crate::capability::Capability::PackageInjection,
    crate::capability::Capability::TicketOverrides,
    crate::capability::Capability::DepotInjection,
    crate::capability::Capability::ShaderCacheControl,
    crate::capability::Capability::DlcOverrides,
    crate::capability::Capability::CmInterception,
    crate::capability::Capability::NativeResponseDelivery,
    crate::capability::Capability::CloudControl,
    crate::capability::Capability::CloudHttp,
    crate::capability::Capability::LaunchEnvironment,
    crate::capability::Capability::LegacyCdKeyControl,
];

const STEAMUI_CAPABILITIES: &[crate::capability::Capability] = &[
    crate::capability::Capability::LibraryUi,
    crate::capability::Capability::OverviewMetadata,
    crate::capability::Capability::LibrarySnapshot,
    crate::capability::Capability::ConflictUiBridge,
];

pub(crate) fn disable_hook_batch_capabilities(batch: HookBatch, reason: &str) {
    let capabilities = match batch {
        HookBatch::SteamClient => STEAMCLIENT_CAPABILITIES,
        HookBatch::SteamUi => STEAMUI_CAPABILITIES,
    };
    crate::capability::disable_all(capabilities, reason);
}

/// Install one hook batch. Safe to call multiple times.
pub fn install_hook_batch(batch: HookBatch) {
    if !ensure_runtime_initialized() {
        warn!(
            ?batch,
            "hook-install: hook batch rejected because runtime initialization failed"
        );
        disable_hook_batch_capabilities(batch, "runtime initialization failed");
        mark_hook_batch_finished(batch);
        return;
    }
    if !steam_hook_batch_supported(batch) {
        warn!(
            batch = ?batch,
            arch = current_hook_architecture(),
            "hook-install: Steam hook batch skipped on unsupported process architecture"
        );
        disable_hook_batch_capabilities(batch, "process architecture is unsupported");
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

/// Load a target-specific hotfix after validating it against the live module.
pub(crate) fn load_pattern_registry(module: &str, code: &CodeRegion) -> Option<PatternRegistry> {
    let Some(target) = current_pattern_target(module, code) else {
        error!(
            module,
            "patterns: Steam binary family is unknown; hook batch rejected"
        );
        return None;
    };
    let patterns_url = config().runtime.patterns_url.clone();
    if !patterns_url.is_empty() {
        validate_hotfix_candidate(&patterns_url, target, module, code);
    }

    let registry = vapor_forge_features::online_patterns::pattern_cache_path(target, module)
        .filter(|path| path.is_file())
        .and_then(|path| match PatternRegistry::with_hotfix(&path, target) {
            Ok(registry) => match validate_live_hotfix(&registry, module, code) {
                Ok(()) => {
                    info!(
                        path = %path.display(),
                        architecture = target.architecture.as_str(),
                        binary_family = target.binary_family.as_str(),
                        "patterns: validated active hotfix"
                    );
                    Some(registry)
                }
                Err(error) => {
                    warn!(path = %path.display(), %error, "patterns: active hotfix rejected");
                    None
                }
            },
            Err(error) => {
                warn!(path = %path.display(), %error, "patterns: active hotfix rejected");
                None
            }
        })
        .unwrap_or_else(|| PatternRegistry::embedded_for_target(target));

    Some(registry)
}

fn validate_hotfix_candidate(
    patterns_url: &str,
    target: PatternTarget,
    module: &str,
    code: &CodeRegion,
) {
    let result = vapor_forge_features::online_patterns::validate_and_promote_candidate(
        patterns_url,
        target,
        module,
        |content| validate_hotfix_candidate_content(content, target, module, code),
    );
    let active_path = match result {
        Ok(vapor_forge_features::online_patterns::PromotionResult::NoCandidate) => return,
        Ok(vapor_forge_features::online_patterns::PromotionResult::AlreadyActive(path)) => {
            debug!(path = %path.display(), module, "patterns: candidate is already active");
            return;
        }
        Ok(vapor_forge_features::online_patterns::PromotionResult::Published(path)) => path,
        Err(error) => {
            warn!(%error, module, "patterns: candidate promotion rejected");
            return;
        }
    };
    info!(
        path = %active_path.display(),
        architecture = target.architecture.as_str(),
        binary_family = target.binary_family.as_str(),
        module,
        "patterns: candidate validated and published"
    );
}

fn validate_hotfix_candidate_content(
    content: &[u8],
    target: PatternTarget,
    module: &str,
    code: &CodeRegion,
) -> Result<(), String> {
    let text =
        std::str::from_utf8(content).map_err(|error| format!("candidate is not UTF-8: {error}"))?;
    let registry = PatternRegistry::from_hotfix_text(text, target)
        .map_err(|error| format!("candidate rejected: {error}"))?;
    validate_live_hotfix(&registry, module, code)
        .map_err(|error| format!("semantic validation failed: {error}"))
}

fn validate_live_hotfix(
    registry: &PatternRegistry,
    module: &str,
    code: &CodeRegion,
) -> Result<(), String> {
    for name in registry.override_names_for_module(module) {
        let entry = registry
            .get(name)
            .ok_or_else(|| format!("hotfix entry {name:?} disappeared"))?;
        let address =
            if module == "steamui" && name == "google::protobuf::RepeatedField<uint32>::Add" {
                crate::ui::install::resolve_repeated_field_add_address(code, registry)
            } else {
                resolve_pattern_entry(code, name, &entry)
            }
            .ok_or_else(|| format!("hotfix pattern {name:?} did not resolve uniquely"))?;
        let offset = address
            .checked_sub(code.base)
            .ok_or_else(|| format!("hotfix pattern {name:?} resolved outside the module"))?;
        vapor_forge_patterns::full_semantic::validate_live_pattern(
            module,
            std::mem::size_of::<usize>(),
            name,
            code.bytes,
            offset,
        )
        .map_err(|error| format!("hotfix pattern {name:?}: {error}"))?;
    }
    Ok(())
}

fn current_pattern_target(module: &str, code: &CodeRegion) -> Option<PatternTarget> {
    let architecture = PatternArchitecture::current()?;
    let entries = find_proc_self_maps_targets(64).ok()?;
    let binary_family = binary_family_for_code_region(&entries, module, code)?;
    Some(PatternTarget {
        architecture,
        binary_family,
    })
}

fn binary_family_for_code_region(
    entries: &[ProcMapsEntry],
    module: &str,
    code: &CodeRegion,
) -> Option<SteamBinaryFamily> {
    let file_name = format!("{module}.so");
    let suffix = format!("/{file_name}");
    let code_end = code.base.checked_add(code.bytes.len())?;
    let mapping = entries.iter().find(|entry| {
        entry.permissions.contains('x')
            && entry.range.base.0 <= code.base
            && entry.range.end.0 >= code_end
            && (entry.path.ends_with(&suffix) || entry.path == file_name.as_str())
    })?;
    steam_binary_family_from_path(std::path::Path::new(&mapping.path))
}

fn steam_binary_family_from_path(path: &std::path::Path) -> Option<SteamBinaryFamily> {
    let mut ordinary = false;
    for component in path
        .components()
        .filter_map(|part| part.as_os_str().to_str())
    {
        if matches!(component, "steamrt32" | "steamrt64") {
            return Some(SteamBinaryFamily::SteamRt);
        }
        if matches!(
            component,
            "ubuntu12_32" | "ubuntu12_64" | "linux32" | "linux64"
        ) {
            ordinary = true;
        }
    }
    ordinary.then_some(SteamBinaryFamily::Ordinary)
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

    let address = resolve_pattern_entry(code, name, &entry)?;
    validate_resolved_pattern("steamclient", code, name, address).then_some(address)
}

fn resolve_from_address<F: vapor_forge_hook_engine::detour::HookFn>(
    code: &CodeRegion,
    name: &str,
    addr: usize,
    replacement: F,
) -> Option<PendingDetour<F>> {
    // SAFETY: F is a function pointer type; its bit pattern is the address.
    let replacement_addr: usize = unsafe { std::mem::transmute_copy(&replacement) };

    let plan = match validate_hook_eligibility(name, addr, replacement_addr, code) {
        Ok(plan) => plan,
        Err(error) => {
            error!(hook = name, %error, "hook boundary validation failed");
            return None;
        }
    };

    // SAFETY: the typed replacement and resolved target share signature F.
    unsafe { detour::create_detour(name, plan) }
}

fn resolve_set_api_call_result(
    registry: &PatternRegistry,
    code: &CodeRegion,
) -> Option<PendingDetour<super::callback_notify::SetApiCallResultFn>> {
    const NAME: &str = "CSteamEngine::SetAPICallResult";
    let addr = resolve_address_from_registry(registry, code, NAME)?;
    let offset = addr.checked_sub(code.base)?;
    let evidence = vapor_forge_patterns::semantic::set_api_call_result_evidence(
        code.bytes,
        offset,
        std::mem::size_of::<usize>(),
    )?;
    if !evidence.is_complete() {
        error!(
            hook = NAME,
            addr = format_args!("0x{addr:x}"),
            ?evidence,
            "hook semantic validation failed"
        );
        return None;
    }
    debug!(
        hook = NAME,
        addr = format_args!("0x{addr:x}"),
        "hook semantic validation passed"
    );
    resolve_from_address(
        code,
        NAME,
        addr,
        super::callback_notify::hk_set_api_call_result
            as super::callback_notify::SetApiCallResultFn,
    )
}

fn resolve_interface_method<F: vapor_forge_hook_engine::detour::HookFn>(
    code: &CodeRegion,
    name: &str,
    interface: &str,
    method: &str,
    replacement: F,
) -> Option<PendingDetour<F>> {
    let address = resolve_interface_method_address(code, name, interface, method)?;
    resolve_from_address(code, name, address, replacement)
}

fn resolve_interface_method_address(
    code: &CodeRegion,
    name: &str,
    interface: &str,
    method: &str,
) -> Option<usize> {
    if interface == "IClientConfigStore" {
        let method_kind = match method {
            "GetUint64" => vapor_forge_patterns::vtable_scan::ConfigStoreUint64Method::Get,
            "SetUint64" => vapor_forge_patterns::vtable_scan::ConfigStoreUint64Method::Set,
            _ => {
                error!(
                    hook = name,
                    interface, method, "unsupported config-store method"
                );
                return None;
            }
        };
        let address = match crate::vtable_scan::config_store_uint64_method_address(method_kind) {
            Ok(address) => address,
            Err(error) => {
                error!(hook = name, interface, method, %error, "interface method semantic validation failed");
                return None;
            }
        };
        if address < code.base || address >= code.base.saturating_add(code.bytes.len()) {
            error!(
                hook = name,
                interface,
                method,
                address = format_args!("0x{address:x}"),
                "interface method is outside steamclient executable code"
            );
            return None;
        }
        debug!(
            hook = name,
            interface,
            method,
            address = format_args!("0x{address:x}"),
            "interface method semantic validation passed"
        );
        return Some(address);
    }
    let slots = crate::vtable_scan::slots_of(interface, method);
    if slots.len() != 1 {
        error!(
            hook = name,
            interface,
            method,
            found = slots.len(),
            "interface method lookup did not produce one slot"
        );
        return None;
    }
    let slot = slots[0];
    let Some(address) = crate::vtable_scan::method_address(interface, slot) else {
        error!(
            hook = name,
            interface, method, slot, "interface method address unavailable"
        );
        return None;
    };
    if address < code.base || address >= code.base.saturating_add(code.bytes.len()) {
        error!(
            hook = name,
            interface,
            method,
            address = format_args!("0x{address:x}"),
            "interface method is outside steamclient executable code"
        );
        return None;
    }
    Some(address)
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
) -> Result<ValidatedHookTarget, HookPlanError> {
    let target = validate_hook_target(HookTargetInput {
        target_address: target_addr,
        replacement_address: replacement_addr,
        executable_range: AddressRange {
            start: code.base,
            end: code.base + code.bytes.len(),
        },
    })?;
    debug!(
        hook = name,
        target = format_args!("0x{:x}", target_addr),
        replacement = format_args!("0x{:x}", replacement_addr),
        "hook boundary: eligible"
    );
    Ok(target)
}

// ---------------------------------------------------------------------------
// Core installation logic
// ---------------------------------------------------------------------------

fn do_install() {
    let code = match get_steamclient_code() {
        Some(c) => c,
        None => {
            disable_hook_batch_capabilities(
                HookBatch::SteamClient,
                "steamclient executable mapping is unavailable",
            );
            return;
        }
    };
    let _ = CODE_RANGE.set((code.base, code.base + code.bytes.len()));

    let Some(registry) = load_pattern_registry("steamclient", &code) else {
        disable_hook_batch_capabilities(
            HookBatch::SteamClient,
            "steamclient pattern target is unavailable",
        );
        return;
    };
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

    // Create every detour before finalizing their shared trampoline storage.
    let mut d_set_api_call_result = resolve_set_api_call_result(&registry, &code);
    let mut d_register_internal_callback = resolve_from_registry(
        &registry,
        &code,
        "CSteamEngine::RegisterInternalCallback",
        super::internal_callbacks::hk_register_internal_callback
            as super::internal_callbacks::RegisterInternalCallbackFn,
    );
    let mut d_get_steam_id = resolve_interface_method(
        &code,
        super::user::GET_STEAM_ID_NAME,
        "IClientUser",
        "GetSteamID",
        super::user::hk_get_steam_id as super::user::GetSteamIdFn,
    );
    let mut d_set_client_id = resolve_interface_method(
        &code,
        super::client_id::SET_UINT64_NAME,
        "IClientConfigStore",
        "SetUint64",
        super::client_id::hk_set_uint64 as super::client_id::SetUint64Fn,
    );
    let mut d_user_interface_init = resolve_from_registry(
        &registry,
        &code,
        super::steam_context::USER_INTERFACE_INIT_NAME,
        super::steam_context::hk_user_interface_init as super::steam_context::UserInterfaceInitFn,
    );
    let mut d_user_interface_destructor = resolve_from_registry(
        &registry,
        &code,
        super::steam_context::USER_INTERFACE_DESTRUCTOR_NAME,
        super::steam_context::hk_user_interface_destructor
            as super::steam_context::UserInterfaceDestructorFn,
    );
    let mut d_ownership = resolve_from_registry(
        &registry,
        &code,
        "CUser::CheckAppOwnership",
        super::ownership::hk_check_app_ownership as super::ownership::CheckAppOwnershipFn,
    );
    let mut d_subscribed = resolve_from_registry(
        &registry,
        &code,
        "CUser::GetSubscribedApps",
        super::ownership::hk_get_subscribed_apps as super::ownership::GetSubscribedAppsFn,
    );
    let mut d_is_cloud_enabled = resolve_interface_method(
        &code,
        super::cloud::IS_CLOUD_ENABLED_NAME,
        "IClientRemoteStorage",
        "IsCloudEnabledForApp",
        super::cloud::hk_is_cloud_enabled_for_app as super::cloud::IsCloudEnabledForAppFn,
    );
    if let Some(address) = resolve_interface_method_address(
        &code,
        "IClientRemoteStorage::SetCloudEnabledForApp",
        "IClientRemoteStorage",
        "SetCloudEnabledForApp",
    ) {
        super::cloud::set_set_cloud_function(address);
    }
    let d_is_cloud_enabled_for_account = resolve_interface_method(
        &code,
        super::cloud::IS_CLOUD_ENABLED_FOR_ACCOUNT_NAME,
        "IClientRemoteStorage",
        "IsCloudEnabledForAccount",
        super::cloud::hk_is_cloud_enabled_for_account as super::cloud::IsCloudEnabledForAccountFn,
    );
    let mut d_is_app_dlc_installed = resolve_interface_method(
        &code,
        super::dlc::IS_APP_DLC_INSTALLED_NAME,
        "IClientAppManager",
        "IsAppDlcInstalled",
        super::dlc::hk_is_app_dlc_installed as super::dlc::IsAppDlcInstalledFn,
    );
    let mut d_b_is_dlc_enabled = resolve_interface_method(
        &code,
        super::dlc::B_IS_DLC_ENABLED_NAME,
        "IClientAppManager",
        "BIsDlcEnabled",
        super::dlc::hk_b_is_dlc_enabled as super::dlc::BIsDlcEnabledFn,
    );
    super::current_app::resolve(&code);
    let d_get_pkg_info = if package_injection_supported() {
        package_info::create_detour()
    } else {
        None
    };
    let check_ownership = d_ownership.as_ref().map(|detour| detour.callee_addr);
    let mut d_ticket_ext = resolve_cuser_adapter(
        &code,
        super::ticket::TICKET_EXT_DATA_NAME,
        "GetAppOwnershipTicketExtendedData",
        check_ownership,
        super::ticket::hk_ticket_ext_data as super::ticket::TicketExtDataFn,
    );
    let mut d_update_ticket = resolve_cuser_adapter(
        &code,
        super::ticket::UPDATE_TICKET_NAME,
        "BUpdateAppOwnershipTicket",
        check_ownership,
        super::ticket::hk_update_ticket as super::ticket::UpdateTicketFn,
    );
    let mut d_is_sub_ticket = resolve_cuser_adapter(
        &code,
        super::ticket::IS_SUBSCRIBED_IN_TICKET_NAME,
        "IsUserSubscribedAppInTicket",
        check_ownership,
        super::ticket::hk_is_subscribed_in_ticket as super::ticket::IsSubscribedInTicketFn,
    );
    let mut d_get_enc = resolve_cuser_adapter(
        &code,
        super::eticket::GET_ENCRYPTED_NAME,
        "GetEncryptedAppTicket",
        check_ownership,
        super::eticket::hk_get_encrypted_app_ticket as super::eticket::GetEncryptedAppTicketFn,
    );
    let d_requires_legacy_cdkey = resolve_cuser_adapter(
        &code,
        super::legacy_cdkey::REQUIRES_LEGACY_CDKEY_NAME,
        "RequiresLegacyCDKey",
        check_ownership,
        super::legacy_cdkey::hk_requires_legacy_cdkey as super::legacy_cdkey::RequiresLegacyCdKeyFn,
    );
    let mut d_build_depot = resolve_from_registry(
        &registry,
        &code,
        "BuildDepotDependency",
        super::depot::hk_build_depot_dependency as super::depot::BuildDepotDependencyFn,
    );
    let mut d_depot_key = resolve_from_registry(
        &registry,
        &code,
        "LoadDepotDecryptionKey",
        super::depot::hk_load_depot_decryption_key as super::depot::LoadDepotDecryptionKeyFn,
    );
    let d_shader_cache_depot = resolve_from_registry(
        &registry,
        &code,
        super::shader::GET_SHADER_CACHE_DEPOT_NAME,
        super::shader::hk_get_shader_cache_depot as super::shader::GetShaderCacheDepotFn,
    );
    let mut d_send_frame = resolve_from_registry(
        &registry,
        &code,
        "CWebSocketConnection::BBuildAndAsyncSendFrame",
        super::network::hk_send_frame as super::network::BBuildAndAsyncSendFrameFn,
    );
    let mut d_recv_pkt = resolve_from_registry(
        &registry,
        &code,
        "CCMConnection::RecvPkt",
        super::network::hk_recv_pkt as super::network::RecvPktFn,
    );
    super::network::resolve_native_packet_functions(&registry, &code);
    vapor_forge_features::inject_wake::set_injection_generation_provider(Box::new(|| {
        super::network::injection_generation()
    }));
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
    let mut d_write_vdf = if vmt_scanner_supported() {
        resolve_from_registry(
            &registry,
            &code,
            "CConfigStore::WriteVdfFile",
            super::cloud::hk_write_vdf_file as super::cloud::WriteVdfFileFn,
        )
    } else {
        None
    };
    let mut d_build_spawn_env = if env_hooks_supported() {
        resolve_from_registry(
            &registry,
            &code,
            "CUser::BuildSpawnEnvBlock",
            super::env::hk_build_spawn_env_block as super::env::BuildSpawnEnvBlockFn,
        )
    } else {
        None
    };
    let mut d_spawn_process = if env_hooks_supported() {
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

    let callback_group_resolved = d_set_api_call_result.is_some()
        && d_register_internal_callback.is_some()
        && d_get_steam_id.is_some()
        && d_set_client_id.is_some()
        && d_user_interface_init.is_some()
        && d_user_interface_destructor.is_some();
    if !callback_group_resolved {
        d_set_api_call_result = None;
        d_register_internal_callback = None;
        d_get_steam_id = None;
        d_set_client_id = None;
        d_user_interface_init = None;
        d_user_interface_destructor = None;
    }

    if d_ownership.is_none() || d_subscribed.is_none() {
        d_ownership = None;
        d_subscribed = None;
    }
    if d_ticket_ext.is_none()
        || d_update_ticket.is_none()
        || d_is_sub_ticket.is_none()
        || d_get_enc.is_none()
    {
        d_ticket_ext = None;
        d_update_ticket = None;
        d_is_sub_ticket = None;
        d_get_enc = None;
    }
    if d_build_depot.is_none() || d_depot_key.is_none() {
        d_build_depot = None;
        d_depot_key = None;
    }
    if d_is_app_dlc_installed.is_none() || d_b_is_dlc_enabled.is_none() {
        d_is_app_dlc_installed = None;
        d_b_is_dlc_enabled = None;
    }
    if d_send_frame.is_none() || d_recv_pkt.is_none() {
        d_send_frame = None;
        d_recv_pkt = None;
    }
    if d_is_cloud_enabled.is_none()
        || d_write_vdf.is_none()
        || !super::cloud::set_cloud_function_ready()
    {
        d_is_cloud_enabled = None;
        d_write_vdf = None;
    }
    if d_build_spawn_env.is_none()
        || d_spawn_process.is_none()
        || !super::env::set_env_string_ready()
    {
        d_build_spawn_env = None;
        d_spawn_process = None;
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
    let mut hook_results = vec![
        hr!("CSteamEngine::SetAPICallResult", d_set_api_call_result),
        hr!(
            "CSteamEngine::RegisterInternalCallback",
            d_register_internal_callback
        ),
        hr!(super::user::GET_STEAM_ID_NAME, d_get_steam_id),
        hr!(super::client_id::SET_UINT64_NAME, d_set_client_id),
        hr!(
            super::steam_context::USER_INTERFACE_INIT_NAME,
            d_user_interface_init
        ),
        hr!(
            super::steam_context::USER_INTERFACE_DESTRUCTOR_NAME,
            d_user_interface_destructor
        ),
        hr!("CUser::CheckAppOwnership", d_ownership),
        hr!("CUser::GetSubscribedApps", d_subscribed),
        hr!(super::cloud::IS_CLOUD_ENABLED_NAME, d_is_cloud_enabled),
        hr!(
            super::dlc::IS_APP_DLC_INSTALLED_NAME,
            d_is_app_dlc_installed
        ),
        hr!(super::dlc::B_IS_DLC_ENABLED_NAME, d_b_is_dlc_enabled),
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
        hr!("IClientUser::GetEncryptedAppTicket", d_get_enc),
        hr!("BuildDepotDependency", d_build_depot),
        hr!("LoadDepotDecryptionKey", d_depot_key),
        hr!(
            "CWebSocketConnection::BBuildAndAsyncSendFrame",
            d_send_frame
        ),
        hr!("CCMConnection::RecvPkt", d_recv_pkt),
        hr!(super::cloud_http::HTTP_JOB_START_NAME, d_http_job_start),
        hr!("CConfigStore::WriteVdfFile", d_write_vdf),
        hr!("CUser::BuildSpawnEnvBlock", d_build_spawn_env),
        hr!("CUser::SpawnProcess", d_spawn_process),
        hr!(
            super::shader::GET_SHADER_CACHE_DEPOT_NAME,
            d_shader_cache_depot
        ),
        hr!(
            super::legacy_cdkey::REQUIRES_LEGACY_CDKEY_NAME,
            d_requires_legacy_cdkey
        ),
        hr!(
            super::cloud::IS_CLOUD_ENABLED_FOR_ACCOUNT_NAME,
            d_is_cloud_enabled_for_account
        ),
    ];

    macro_rules! finalize {
        ($index:expr, $name:expr, $storage:expr, $pending:expr) => {{
            // SAFETY: each process-lifetime detour slot is written once during initialization.
            let installed = unsafe { detour::store_and_finalize($name, $storage, $pending) };
            hook_results[$index].installed = installed;
            installed
        }};
    }

    finalize!(
        0,
        "CSteamEngine::SetAPICallResult",
        std::ptr::addr_of_mut!(super::callback_notify::SET_API_CALL_RESULT_DETOUR),
        d_set_api_call_result
    );
    finalize!(
        1,
        "CSteamEngine::RegisterInternalCallback",
        std::ptr::addr_of_mut!(super::internal_callbacks::REGISTER_INTERNAL_CALLBACK_DETOUR),
        d_register_internal_callback
    );
    finalize!(
        2,
        super::user::GET_STEAM_ID_NAME,
        std::ptr::addr_of_mut!(super::user::GET_STEAM_ID_DETOUR),
        d_get_steam_id
    );
    finalize!(
        3,
        super::client_id::SET_UINT64_NAME,
        std::ptr::addr_of_mut!(super::client_id::SET_UINT64_DETOUR),
        d_set_client_id
    );
    finalize!(
        4,
        super::steam_context::USER_INTERFACE_INIT_NAME,
        std::ptr::addr_of_mut!(super::steam_context::USER_INTERFACE_INIT_DETOUR),
        d_user_interface_init
    );
    finalize!(
        5,
        super::steam_context::USER_INTERFACE_DESTRUCTOR_NAME,
        std::ptr::addr_of_mut!(super::steam_context::USER_INTERFACE_DESTRUCTOR_DETOUR),
        d_user_interface_destructor
    );
    finalize!(
        6,
        "CUser::CheckAppOwnership",
        std::ptr::addr_of_mut!(super::ownership::OWNERSHIP_DETOUR),
        d_ownership
    );
    finalize!(
        7,
        "CUser::GetSubscribedApps",
        std::ptr::addr_of_mut!(super::ownership::SUBSCRIBED_DETOUR),
        d_subscribed
    );
    finalize!(
        8,
        super::cloud::IS_CLOUD_ENABLED_NAME,
        std::ptr::addr_of_mut!(super::cloud::IS_CLOUD_ENABLED_DETOUR),
        d_is_cloud_enabled
    );
    finalize!(
        9,
        super::dlc::IS_APP_DLC_INSTALLED_NAME,
        std::ptr::addr_of_mut!(super::dlc::IS_APP_DLC_INSTALLED_DETOUR),
        d_is_app_dlc_installed
    );
    finalize!(
        10,
        super::dlc::B_IS_DLC_ENABLED_NAME,
        std::ptr::addr_of_mut!(super::dlc::B_IS_DLC_ENABLED_DETOUR),
        d_b_is_dlc_enabled
    );
    finalize!(
        11,
        package_info::hook_name(),
        std::ptr::addr_of_mut!(package_info::GET_PKG_INFO_DETOUR),
        d_get_pkg_info
    );
    finalize!(
        12,
        "IClientUser::GetAppOwnershipTicketExtendedData",
        std::ptr::addr_of_mut!(super::ticket::TICKET_EXT_DATA_DETOUR),
        d_ticket_ext
    );
    finalize!(
        13,
        "IClientUser::BUpdateAppOwnershipTicket",
        std::ptr::addr_of_mut!(super::ticket::UPDATE_TICKET_DETOUR),
        d_update_ticket
    );
    finalize!(
        14,
        "IClientUser::IsUserSubscribedAppInTicket",
        std::ptr::addr_of_mut!(super::ticket::IS_SUBSCRIBED_IN_TICKET_DETOUR),
        d_is_sub_ticket
    );
    finalize!(
        15,
        "IClientUser::GetEncryptedAppTicket",
        std::ptr::addr_of_mut!(super::eticket::GET_ENCRYPTED_DETOUR),
        d_get_enc
    );
    finalize!(
        16,
        "BuildDepotDependency",
        std::ptr::addr_of_mut!(super::depot::BUILD_DEPOT_DETOUR),
        d_build_depot
    );
    finalize!(
        17,
        "LoadDepotDecryptionKey",
        std::ptr::addr_of_mut!(super::depot::DEPOT_KEY_DETOUR),
        d_depot_key
    );
    finalize!(
        18,
        "CWebSocketConnection::BBuildAndAsyncSendFrame",
        std::ptr::addr_of_mut!(super::network::SEND_FRAME_DETOUR),
        d_send_frame
    );
    finalize!(
        19,
        "CCMConnection::RecvPkt",
        std::ptr::addr_of_mut!(super::network::RECV_PKT_DETOUR),
        d_recv_pkt
    );
    finalize!(
        20,
        super::cloud_http::HTTP_JOB_START_NAME,
        std::ptr::addr_of_mut!(super::cloud_http::HTTP_JOB_START_DETOUR),
        d_http_job_start
    );
    finalize!(
        21,
        "CConfigStore::WriteVdfFile",
        std::ptr::addr_of_mut!(super::cloud::WRITE_VDF_DETOUR),
        d_write_vdf
    );
    finalize!(
        22,
        "CUser::BuildSpawnEnvBlock",
        std::ptr::addr_of_mut!(super::env::BUILD_SPAWN_ENV_DETOUR),
        d_build_spawn_env
    );
    finalize!(
        23,
        "CUser::SpawnProcess",
        std::ptr::addr_of_mut!(super::env::SPAWN_PROCESS_DETOUR),
        d_spawn_process
    );
    finalize!(
        24,
        super::shader::GET_SHADER_CACHE_DEPOT_NAME,
        std::ptr::addr_of_mut!(super::shader::GET_SHADER_CACHE_DEPOT_DETOUR),
        d_shader_cache_depot
    );
    finalize!(
        25,
        super::legacy_cdkey::REQUIRES_LEGACY_CDKEY_NAME,
        std::ptr::addr_of_mut!(super::legacy_cdkey::REQUIRES_LEGACY_CDKEY_DETOUR),
        d_requires_legacy_cdkey
    );
    // Capture-only: not a CloudControl requirement, the per-app gate still
    // sweeps on its own first call when this one is unavailable.
    finalize!(
        26,
        super::cloud::IS_CLOUD_ENABLED_FOR_ACCOUNT_NAME,
        std::ptr::addr_of_mut!(super::cloud::IS_CLOUD_ENABLED_FOR_ACCOUNT_DETOUR),
        d_is_cloud_enabled_for_account
    );
    super::callback_notify::set_hooks_ready(&[
        (hook_results[0].name, hook_results[0].installed),
        (hook_results[1].name, hook_results[1].installed),
        (hook_results[2].name, hook_results[2].installed),
        (hook_results[3].name, hook_results[3].installed),
        (hook_results[4].name, hook_results[4].installed),
        (hook_results[5].name, hook_results[5].installed),
    ]);
    let cm_ready = crate::capability::set_from_requirements(
        crate::capability::Capability::CmInterception,
        &[
            (hook_results[18].name, hook_results[18].installed),
            (hook_results[19].name, hook_results[19].installed),
        ],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::NativeResponseDelivery,
        &[
            ("cm-interception", cm_ready),
            (
                "CNetPacket and work-item callables",
                super::network::native_packet_functions_ready(),
            ),
        ],
    );
    let ownership_ready = crate::capability::set_from_requirements(
        crate::capability::Capability::Ownership,
        &[
            ("cm-interception", cm_ready),
            (hook_results[6].name, hook_results[6].installed),
            (hook_results[7].name, hook_results[7].installed),
        ],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::PackageInjection,
        &[
            ("ownership", ownership_ready),
            (hook_results[11].name, hook_results[11].installed),
            (
                "package callables",
                super::package::all_functions_resolved(),
            ),
        ],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::TicketOverrides,
        &[
            ("cm-interception", cm_ready),
            (hook_results[12].name, hook_results[12].installed),
            (hook_results[13].name, hook_results[13].installed),
            (hook_results[14].name, hook_results[14].installed),
            (hook_results[15].name, hook_results[15].installed),
        ],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::DepotInjection,
        &[
            ("cm-interception", cm_ready),
            (hook_results[16].name, hook_results[16].installed),
            (hook_results[17].name, hook_results[17].installed),
        ],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::ShaderCacheControl,
        &[(hook_results[24].name, hook_results[24].installed)],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::LegacyCdKeyControl,
        &[(hook_results[25].name, hook_results[25].installed)],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::DlcOverrides,
        &[
            ("cm-interception", cm_ready),
            (hook_results[9].name, hook_results[9].installed),
            (hook_results[10].name, hook_results[10].installed),
        ],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::CloudControl,
        &[
            ("cm-interception", cm_ready),
            (hook_results[8].name, hook_results[8].installed),
            (
                "SetCloudEnabledForApp",
                super::cloud::set_cloud_function_ready(),
            ),
            (hook_results[21].name, hook_results[21].installed),
        ],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::CloudHttp,
        &[(hook_results[20].name, hook_results[20].installed)],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::LaunchEnvironment,
        &[
            (hook_results[22].name, hook_results[22].installed),
            (hook_results[23].name, hook_results[23].installed),
            ("SetEnvString", super::env::set_env_string_ready()),
        ],
    );

    log_drift_summary("steamclient.so", &hook_results);
    store_results("steamclient.so", &hook_results);

    if config().runtime.diagnostics {
        log_hook_details("steamclient.so", &hook_results);
    }

    // Background fetch of online pattern updates
    let cfg = config();
    if !cfg.runtime.patterns_url.is_empty() {
        if let Some(target) = current_pattern_target("steamclient", &code) {
            vapor_forge_features::online_patterns::spawn_fetch(
                cfg.runtime.patterns_url.clone(),
                target,
            );
        } else {
            warn!("online-patterns: Steam binary family is unknown; update skipped");
        }
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

#[cfg(test)]
mod pattern_target_tests {
    use super::*;
    use vapor_forge_core::Address;

    static CODE_BYTES: [u8; 0x100] = [0; 0x100];
    static INVALID_HOTFIX_CODE: [u8; 8] = [0xc3, 0xc2, 0xc1, 0xc0, 0, 0, 0, 0];

    fn mapping(base: usize, end: usize, path: &str) -> ProcMapsEntry {
        ProcMapsEntry {
            range: vapor_forge_memory::ModuleRange {
                base: Address(base),
                end: Address(end),
                size: end - base,
            },
            permissions: "r-xp".to_owned(),
            file_offset: 0,
            path: path.to_owned(),
        }
    }

    #[test]
    fn classifies_ordinary_and_steamrt_paths() {
        assert_eq!(
            steam_binary_family_from_path(std::path::Path::new(
                "/home/user/.steam/ubuntu12_32/steamclient.so"
            )),
            Some(SteamBinaryFamily::Ordinary)
        );
        assert_eq!(
            steam_binary_family_from_path(std::path::Path::new(
                "/home/user/.steam/linux64/steamclient.so"
            )),
            Some(SteamBinaryFamily::Ordinary)
        );
        assert_eq!(
            steam_binary_family_from_path(std::path::Path::new(
                "/home/user/.steam/steamrt64/steamclient.so"
            )),
            Some(SteamBinaryFamily::SteamRt)
        );
        assert_eq!(
            steam_binary_family_from_path(std::path::Path::new("/tmp/steamclient.so")),
            None
        );
    }

    #[test]
    fn target_family_uses_the_mapping_that_contains_the_code_region() {
        let entries = [
            mapping(0x1000, 0x2000, "/home/user/.steam/linux64/steamclient.so"),
            mapping(0x3000, 0x4000, "/home/user/.steam/steamrt64/steamclient.so"),
        ];
        let code = CodeRegion {
            base: 0x3000,
            bytes: &CODE_BYTES,
        };

        assert_eq!(
            binary_family_for_code_region(&entries, "steamclient", &code),
            Some(SteamBinaryFamily::SteamRt)
        );
    }

    #[test]
    fn target_family_rejects_a_different_module_mapping() {
        let entries = [mapping(
            0x3000,
            0x4000,
            "/home/user/.steam/steamrt64/steamui.so",
        )];
        let code = CodeRegion {
            base: 0x3000,
            bytes: &CODE_BYTES,
        };

        assert_eq!(
            binary_family_for_code_region(&entries, "steamclient", &code),
            None
        );
    }

    #[test]
    fn candidate_content_passes_through_the_live_semantic_gate() {
        let architecture = PatternArchitecture::current().unwrap();
        let target = PatternTarget {
            architecture,
            binary_family: SteamBinaryFamily::SteamRt,
        };
        let content = format!(
            r#"[hotfix]
format = 1
revision = 1
architecture = "{}"
binary_family = "steamrt"

[steamclient."CUser::CheckAppOwnership"]
pattern = "C3 C2 C1 C0"
"#,
            architecture.as_str()
        );
        let code = CodeRegion {
            base: INVALID_HOTFIX_CODE.as_ptr() as usize,
            bytes: &INVALID_HOTFIX_CODE,
        };

        let error =
            validate_hotfix_candidate_content(content.as_bytes(), target, "steamclient", &code)
                .unwrap_err();

        assert!(error.contains("semantic validation failed"));
    }
}
