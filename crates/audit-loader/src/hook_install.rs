use core::ffi::c_void;
use std::sync::Once;

use retour::GenericDetour;
use steam_runtime_abi::CAppOwnershipInfo;
use steam_runtime_config::{AppCategory, RuntimeConfig};
use steam_runtime_diagnostics::log_message;
use steam_runtime_hooks::pic_thunk;
use steam_runtime_memory::{find_proc_self_maps_targets, ProcMapsEntry};
use steam_runtime_patterns::{follow_relative_call, Pattern};

const CHECK_APP_OWNERSHIP_PATTERN: &str =
    "E8 ? ? ? ? 88 45 ? 83 C4 10 84 C0 0F 84 ? ? ? ? 8B 45 ? 80 7D ? 00";

const GET_SUBSCRIBED_APPS_PATTERN: &str =
    "E8 ? ? ? ? 89 C6 83 C4 10 85 C0 0F 84 ? ? ? ? 8B 9D ? ? ? ? 39 D8";

const REMOTE_STORAGE_RUN_IPC_FRAME_PATTERN: &str =
    "55 89 E5 57 56 E8 ? ? ? ? 81 C6 ? ? ? ? 53 81 EC 60 05 00 00";

const IS_CLOUD_ENABLED_FOR_APP_SLOT: usize = 24;

const CONFIG_PATHS: &[&str] = &[
    "config.toml",
    "/home/hintay/.config/steam-runtime-rs/config.toml",
];

type CheckAppOwnershipFn = unsafe extern "C" fn(*mut c_void, u32, *mut CAppOwnershipInfo) -> u32;
type GetSubscribedAppsFn = unsafe extern "C" fn(*mut c_void, *mut u32, u32, u8) -> u32;
type RunIPCFrameFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
type IsCloudEnabledForAppFn = unsafe extern "C" fn(*mut c_void, u32) -> bool;

static HOOK_INSTALL: Once = Once::new();
static mut OWNERSHIP_DETOUR: Option<GenericDetour<CheckAppOwnershipFn>> = None;
static mut SUBSCRIBED_DETOUR: Option<GenericDetour<GetSubscribedAppsFn>> = None;
static mut RUN_IPC_DETOUR: Option<GenericDetour<RunIPCFrameFn>> = None;
static mut ORIGINAL_IS_CLOUD_ENABLED: Option<IsCloudEnabledForAppFn> = None;
pub(crate) static mut CONFIG: Option<RuntimeConfig> = None;
static VMT_HOOK_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// --- CheckAppOwnership hook ---

unsafe extern "C" fn hk_check_app_ownership(
    this: *mut c_void,
    app_id: u32,
    out: *mut CAppOwnershipInfo,
) -> u32 {
    // SAFETY: OWNERSHIP_DETOUR/CONFIG set before hook enabled, never modified after.
    let result = unsafe {
        (*std::ptr::addr_of!(OWNERSHIP_DETOUR))
            .as_ref()
            .unwrap()
            .call(this, app_id, out)
    };

    let config = unsafe { (*std::ptr::addr_of!(CONFIG)).as_ref() };
    let category = config.and_then(|c| c.app_category(app_id));

    if let Some(AppCategory::Inject | AppCategory::InjectDlc { .. }) = category {
        if result == 0 && !out.is_null() {
            // SAFETY: out is a valid pointer provided by Steam's caller.
            unsafe {
                let info = &mut *out;
                info.release_state = 2;
                info.owner = 1;
                info.exist_in_package_nums = 2;
                info.purchase_time = 1_600_000_000;
                info.owns_license = 1;
                info.license_expired = 0;
                info.license_permanent = 1;
                info.free_license = 0;
                info.family_shared = 0;
            }
            log_message(&format!("hook: ownership injected app_id={}", app_id));
            return 1;
        }
    }

    if config.map_or(false, |c| c.should_bypass_sharing(app_id)) && result != 0 && !out.is_null()
    {
        // SAFETY: out has been filled by the original function.
        let info = unsafe { &mut *out };
        if info.family_shared != 0 {
            info.family_shared = 0;
            log_message(&format!("hook: sharing bypass app_id={}", app_id));
        }
    }

    result
}

// --- GetSubscribedApps hook ---

unsafe extern "C" fn hk_get_subscribed_apps(
    this: *mut c_void,
    app_list: *mut u32,
    size: u32,
    a3: u8,
) -> u32 {
    // SAFETY: SUBSCRIBED_DETOUR set before hook enabled, never modified after.
    let mut count = unsafe {
        (*std::ptr::addr_of!(SUBSCRIBED_DETOUR))
            .as_ref()
            .unwrap()
            .call(this, app_list, size, a3)
    };

    let config = unsafe { (*std::ptr::addr_of!(CONFIG)).as_ref() };
    let inject_ids: Vec<u32> = config
        .map(|c| c.apps.inject.iter().map(|a| a.id).collect())
        .unwrap_or_default();

    if inject_ids.is_empty() {
        return count;
    }

    if app_list.is_null() || size == 0 {
        return count + inject_ids.len() as u32;
    }

    for &app_id in &inject_ids {
        if (count as usize) < size as usize {
            // SAFETY: app_list buffer has `size` slots, count < size.
            unsafe {
                *app_list.add(count as usize) = app_id;
            }
            count += 1;
        }
    }

    count
}

// --- Installation ---

pub fn try_install_hooks() {
    HOOK_INSTALL.call_once(do_install);
}

fn do_install() {
    let config = load_config();
    if !config.has_any_inject_apps() && !config.apps.shared.enabled {
        log_message("hook-install: nothing to do, skipping");
        return;
    }

    let inject_count = config.apps.inject.len();
    let dlc_count: usize = config.apps.inject.iter().map(|a| a.dlc.len()).sum();
    let shared_detail = if !config.apps.shared.include.is_empty() {
        format!(" include={:?}", config.apps.shared.include)
    } else if !config.apps.shared.exclude.is_empty() {
        format!(" exclude={:?}", config.apps.shared.exclude)
    } else {
        String::new()
    };
    log_message(&format!(
        "hook-install: {} inject, {} dlc, sharing={}{}",
        inject_count, dlc_count, config.apps.shared.enabled, shared_detail
    ));

    // SAFETY: storing config before hooks are enabled; never modified after.
    unsafe {
        std::ptr::addr_of_mut!(CONFIG).write(Some(config));
    }

    let code = match get_steamclient_code() {
        Some(c) => c,
        None => return,
    };

    // Phase 1: create all detours (retour allocates trampolines on a shared pool page).
    // Do NOT mprotect or PIC-repair yet — modifying page permissions between allocations
    // would lock the pool page to RX before retour can write the next trampoline.
    let ownership_callee = create_ownership_detour(&code);
    let subscribed_callee = create_subscribed_apps_detour(&code);
    let run_ipc_callee = create_run_ipc_frame_detour(&code);
    let app_mgr_callee = crate::dlc_hooks::create_app_manager_detour(&code);
    let client_apps_callee = crate::dlc_hooks::create_client_apps_detour(&code);

    // Phase 2: PIC-repair all trampolines, then enable.
    finalize_subscribed_apps_hook(subscribed_callee);
    finalize_ownership_hook(ownership_callee);
    finalize_run_ipc_frame_hook(run_ipc_callee);
    crate::dlc_hooks::finalize_app_manager_hook(app_mgr_callee);
    crate::dlc_hooks::finalize_client_apps_hook(client_apps_callee);
}

pub(crate) struct SteamClientCode {
    pub(crate) base: usize,
    pub(crate) bytes: &'static [u8],
}

fn get_steamclient_code() -> Option<SteamClientCode> {
    let entries = match find_proc_self_maps_targets(16) {
        Ok(e) => e,
        Err(e) => {
            log_message(&format!("hook-install: proc-maps failed: {}", e));
            return None;
        }
    };

    let exec_entry = match find_steamclient_exec_mapping(&entries) {
        Some(e) => e,
        None => {
            log_message("hook-install: no executable steamclient.so mapping");
            return None;
        }
    };

    let base = exec_entry.range.base.0;
    let size = exec_entry.range.size;
    log_message(&format!(
        "hook-install: steamclient exec base=0x{:x} size=0x{:x}",
        base, size
    ));

    // SAFETY: reading the executable mapping of steamclient.so.
    let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    Some(SteamClientCode { base, bytes })
}

fn resolve_callee(code: &SteamClientCode, name: &str, pattern_str: &str) -> Option<usize> {
    let pattern = match Pattern::parse(pattern_str) {
        Ok(p) => p,
        Err(e) => {
            log_message(&format!("hook-install: {} pattern parse failed: {}", name, e));
            return None;
        }
    };

    let call_site = match pattern.find_unique(code.bytes) {
        Ok(o) => o,
        Err(e) => {
            log_message(&format!("hook-install: {} match failed: {}", name, e));
            return None;
        }
    };

    match follow_relative_call(code.bytes, call_site) {
        Ok(o) if o >= 0 && (o as usize) < code.bytes.len() => {
            let addr = code.base + o as usize;
            log_message(&format!("hook-install: {} at 0x{:x}", name, addr));
            Some(addr)
        }
        Ok(o) => {
            log_message(&format!("hook-install: {} offset 0x{:x} out of bounds", name, o));
            None
        }
        Err(e) => {
            log_message(&format!("hook-install: {} follow failed: {}", name, e));
            None
        }
    }
}

fn create_ownership_detour(code: &SteamClientCode) -> Option<usize> {
    let addr = resolve_callee(code, "CheckAppOwnership", CHECK_APP_OWNERSHIP_PATTERN)?;

    // SAFETY: addr is a validated code address in steamclient.so.
    let target: CheckAppOwnershipFn = unsafe { std::mem::transmute(addr) };
    let detour = match unsafe { GenericDetour::new(target, hk_check_app_ownership) } {
        Ok(d) => d,
        Err(e) => {
            log_message(&format!("hook-install: CheckAppOwnership retour failed: {}", e));
            return None;
        }
    };

    // SAFETY: storing detour (not yet enabled).
    unsafe { std::ptr::addr_of_mut!(OWNERSHIP_DETOUR).write(Some(detour)) };
    log_message("hook-install: CheckAppOwnership detour created");
    Some(addr)
}

fn finalize_ownership_hook(callee_addr: Option<usize>) {
    let Some(addr) = callee_addr else { return };

    // SAFETY: OWNERSHIP_DETOUR was set in create phase.
    let tramp_addr = unsafe {
        (*std::ptr::addr_of!(OWNERSHIP_DETOUR))
            .as_ref()
            .unwrap()
            .trampoline() as *const _ as usize
    };
    repair_pic_thunk_at(tramp_addr, addr);

    // SAFETY: enabling the detour.
    unsafe {
        if let Err(e) = (*std::ptr::addr_of_mut!(OWNERSHIP_DETOUR))
            .as_mut()
            .unwrap()
            .enable()
        {
            log_message(&format!("hook-install: CheckAppOwnership enable failed: {}", e));
            return;
        }
    }
    log_message("hook-install: CheckAppOwnership INSTALLED");
}

fn create_subscribed_apps_detour(code: &SteamClientCode) -> Option<usize> {
    let addr = resolve_callee(code, "GetSubscribedApps", GET_SUBSCRIBED_APPS_PATTERN)?;

    // SAFETY: addr is a validated code address in steamclient.so.
    let target: GetSubscribedAppsFn = unsafe { std::mem::transmute(addr) };
    let detour = match unsafe { GenericDetour::new(target, hk_get_subscribed_apps) } {
        Ok(d) => d,
        Err(e) => {
            log_message(&format!("hook-install: GetSubscribedApps retour failed: {}", e));
            return None;
        }
    };

    // SAFETY: storing detour (not yet enabled).
    unsafe { std::ptr::addr_of_mut!(SUBSCRIBED_DETOUR).write(Some(detour)) };
    log_message("hook-install: GetSubscribedApps detour created");
    Some(addr)
}

fn finalize_subscribed_apps_hook(callee_addr: Option<usize>) {
    let Some(addr) = callee_addr else { return };

    // SAFETY: SUBSCRIBED_DETOUR was set in create phase.
    let tramp_addr = unsafe {
        (*std::ptr::addr_of!(SUBSCRIBED_DETOUR))
            .as_ref()
            .unwrap()
            .trampoline() as *const _ as usize
    };
    repair_pic_thunk_at(tramp_addr, addr);

    // SAFETY: enabling the detour.
    unsafe {
        if let Err(e) = (*std::ptr::addr_of_mut!(SUBSCRIBED_DETOUR))
            .as_mut()
            .unwrap()
            .enable()
        {
            log_message(&format!("hook-install: GetSubscribedApps enable failed: {}", e));
            return;
        }
    }
    log_message("hook-install: GetSubscribedApps INSTALLED");
}

pub(crate) fn repair_pic_thunk_at(tramp_addr: usize, callee_addr: usize) {
    // SAFETY: reading trampoline bytes for PIC thunk analysis.
    let tramp_bytes = unsafe { std::slice::from_raw_parts(tramp_addr as *const u8, 64) };

    let pic_result = pic_thunk::find_pic_thunk_call(tramp_bytes, tramp_addr as u32, &|addr| {
        let ptr = addr as usize as *const u8;
        if ptr.is_null() {
            return None;
        }
        // SAFETY: the call target should point into steamclient.so's executable mapping
        // which is readable in the current process. If it doesn't, this read may fault;
        // in practice PIC thunk targets are always within the same module.
        Some(unsafe { [*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)] })
    });

    if let Ok(site) = pic_result {
        let plan = pic_thunk::plan_pic_thunk_repair(site, callee_addr as u32);
        // SAFETY: making the trampoline writable for PIC repair.
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let page_start = tramp_addr & !(page_size - 1);
            libc::mprotect(
                page_start as *mut libc::c_void,
                page_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
            let patch_ptr = (tramp_addr + plan.call_site.offset_in_buffer) as *mut u8;
            for (i, &byte) in plan.patch_bytes.iter().enumerate() {
                *patch_ptr.add(i) = byte;
            }
            libc::mprotect(
                page_start as *mut libc::c_void,
                page_size,
                libc::PROT_READ | libc::PROT_EXEC,
            );
        }
        log_message("hook-install: PIC thunk repaired");
    }
}

// --- IClientRemoteStorage::RunIPCFrame hook (trampoline for VMT discovery) ---

unsafe extern "C" fn hk_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !VMT_HOOK_DONE.load(std::sync::atomic::Ordering::Acquire) {
        install_cloud_vmt_hook(this);
    }

    // SAFETY: RUN_IPC_DETOUR set before enabled.
    unsafe {
        (*std::ptr::addr_of!(RUN_IPC_DETOUR))
            .as_ref()
            .unwrap()
            .call(this, a1, a2, a3);
    }
}

unsafe extern "C" fn hk_is_cloud_enabled_for_app(this: *mut c_void, app_id: u32) -> bool {
    // SAFETY: ORIGINAL_IS_CLOUD_ENABLED set before VMT swap.
    let original = unsafe { (*std::ptr::addr_of!(ORIGINAL_IS_CLOUD_ENABLED)).unwrap() };
    let result = unsafe { original(this, app_id) };

    let config = unsafe { (*std::ptr::addr_of!(CONFIG)).as_ref() };
    let controlled = config.map_or(false, |c| c.app_category(app_id).is_some());

    if controlled && !config.map_or(false, |c| c.cloud_enabled_for_controlled_apps()) {
        if result {
            log_message(&format!("hook: cloud disabled app_id={}", app_id));
        }
        return false;
    }

    result
}

fn install_cloud_vmt_hook(this: *mut c_void) {
    if VMT_HOOK_DONE.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }

    if this.is_null() {
        log_message("hook-install: RunIPCFrame this is null, skipping VMT");
        return;
    }

    // SAFETY: this points to an IClientRemoteStorage object whose first field is a
    // vtable pointer (standard C++ ABI). We read the vtable to find slot 24.
    let vtable_ptr = unsafe { *(this as *const *const usize) };
    if vtable_ptr.is_null() {
        log_message("hook-install: vtable pointer is null");
        return;
    }

    // SAFETY: reading vtable slot 24 (IsCloudEnabledForApp)
    let slot_ptr = unsafe { vtable_ptr.add(IS_CLOUD_ENABLED_FOR_APP_SLOT) };
    let original_fn_addr = unsafe { *slot_ptr };

    log_message(&format!(
        "hook-install: IsCloudEnabledForApp vtable slot {} = 0x{:x}",
        IS_CLOUD_ENABLED_FOR_APP_SLOT, original_fn_addr
    ));

    // SAFETY: transmute the original function address to a typed fn pointer.
    let original: IsCloudEnabledForAppFn = unsafe { std::mem::transmute(original_fn_addr) };
    unsafe { std::ptr::addr_of_mut!(ORIGINAL_IS_CLOUD_ENABLED).write(Some(original)) };

    // SAFETY: overwrite the vtable slot with our hook. The vtable is in .data.rel.ro
    // which has been made writable by the loader (RELRO applied post-load).
    // We need to mprotect the page to make it writable.
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let slot_addr = slot_ptr as *mut usize;
        let page_start = (slot_addr as usize) & !(page_size - 1);
        libc::mprotect(
            page_start as *mut libc::c_void,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        *slot_addr = hk_is_cloud_enabled_for_app as usize;
        libc::mprotect(
            page_start as *mut libc::c_void,
            page_size,
            libc::PROT_READ,
        );
    }

    log_message("hook-install: IsCloudEnabledForApp VMT hook INSTALLED");
}

fn create_run_ipc_frame_detour(code: &SteamClientCode) -> Option<usize> {
    let pattern = match Pattern::parse(REMOTE_STORAGE_RUN_IPC_FRAME_PATTERN) {
        Ok(p) => p,
        Err(e) => {
            log_message(&format!("hook-install: RunIPCFrame pattern parse failed: {}", e));
            return None;
        }
    };

    // follow=None: pattern matches the function prologue directly
    let offset = match pattern.find_unique(code.bytes) {
        Ok(o) => o,
        Err(e) => {
            log_message(&format!("hook-install: RunIPCFrame match failed: {}", e));
            return None;
        }
    };

    let addr = code.base + offset;
    log_message(&format!("hook-install: RunIPCFrame at 0x{:x}", addr));

    // SAFETY: addr is a validated code address.
    let target: RunIPCFrameFn = unsafe { std::mem::transmute(addr) };
    let detour = match unsafe { GenericDetour::new(target, hk_run_ipc_frame) } {
        Ok(d) => d,
        Err(e) => {
            log_message(&format!("hook-install: RunIPCFrame retour failed: {}", e));
            return None;
        }
    };

    // SAFETY: storing detour (not yet enabled).
    unsafe { std::ptr::addr_of_mut!(RUN_IPC_DETOUR).write(Some(detour)) };
    log_message("hook-install: RunIPCFrame detour created");
    Some(addr)
}

fn finalize_run_ipc_frame_hook(callee_addr: Option<usize>) {
    let Some(addr) = callee_addr else { return };

    // SAFETY: RUN_IPC_DETOUR was set in create phase.
    let tramp_addr = unsafe {
        (*std::ptr::addr_of!(RUN_IPC_DETOUR))
            .as_ref()
            .unwrap()
            .trampoline() as *const _ as usize
    };
    repair_pic_thunk_at(tramp_addr, addr);

    // SAFETY: enabling the detour.
    unsafe {
        if let Err(e) = (*std::ptr::addr_of_mut!(RUN_IPC_DETOUR))
            .as_mut()
            .unwrap()
            .enable()
        {
            log_message(&format!("hook-install: RunIPCFrame enable failed: {}", e));
            return;
        }
    }
    log_message("hook-install: RunIPCFrame INSTALLED (VMT discovery on first call)");
}

fn load_config() -> RuntimeConfig {
    for path in CONFIG_PATHS {
        let p = std::path::Path::new(path);
        if p.exists() {
            match RuntimeConfig::load(p) {
                Ok(config) => {
                    log_message(&format!("hook-install: config loaded from {}", path));
                    return config;
                }
                Err(e) => {
                    log_message(&format!("hook-install: config error {}: {}", path, e));
                }
            }
        }
    }
    log_message("hook-install: no config, using defaults");
    RuntimeConfig::default()
}

fn find_steamclient_exec_mapping(entries: &[ProcMapsEntry]) -> Option<&ProcMapsEntry> {
    entries.iter().find(|e| {
        e.permissions.contains('x')
            && (e.path.ends_with("/steamclient.so") || e.path == "steamclient.so")
    })
}
