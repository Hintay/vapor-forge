use core::ffi::c_void;

use retour::GenericDetour;
use steam_runtime_config::RuntimeConfig;
use steam_runtime_diagnostics::log_message;
use steam_runtime_hooks::pic_thunk;
use steam_runtime_patterns::Pattern;

use crate::hook_install::{repair_pic_thunk_at, SteamClientCode};

const APP_MANAGER_RUN_IPC_FRAME_PATTERN: &str =
    "55 89 E5 57 56 E8 ? ? ? ? 81 C6 ? ? ? ? 53 81 EC 80 07 00 00";

const CLIENT_APPS_RUN_IPC_FRAME_PATTERN: &str =
    "55 89 E5 57 56 E8 ? ? ? ? 81 C6 ? ? ? ? 53 81 EC 70 01 00 00 8B 45 08 8B 4D 0C 8B 7D 14 89 85 18 FF FF FF";

const IS_APP_DLC_INSTALLED_SLOT: usize = 9;
const B_IS_DLC_ENABLED_SLOT: usize = 11;
const GET_DLC_COUNT_SLOT: usize = 8;
const B_GET_DLC_DATA_BY_INDEX_SLOT: usize = 9;

type RunIPCFrameFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
type IsAppDlcInstalledFn = unsafe extern "C" fn(*mut c_void, u32, u32) -> bool;
type BIsDlcEnabledFn = unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void) -> bool;
type GetDLCCountFn = unsafe extern "C" fn(*mut c_void, u32) -> u32;
type BGetDLCDataByIndexFn =
    unsafe extern "C" fn(*mut c_void, u32, i32, *mut u32, *mut bool, *mut u8, usize) -> bool;

static mut APP_MANAGER_DETOUR: Option<GenericDetour<RunIPCFrameFn>> = None;
static mut CLIENT_APPS_DETOUR: Option<GenericDetour<RunIPCFrameFn>> = None;
static mut ORIG_IS_APP_DLC_INSTALLED: Option<IsAppDlcInstalledFn> = None;
static mut ORIG_B_IS_DLC_ENABLED: Option<BIsDlcEnabledFn> = None;
static mut ORIG_GET_DLC_COUNT: Option<GetDLCCountFn> = None;
static mut ORIG_B_GET_DLC_DATA_BY_INDEX: Option<BGetDLCDataByIndexFn> = None;

static APP_MANAGER_VMT_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static CLIENT_APPS_VMT_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn config() -> Option<&'static RuntimeConfig> {
    // SAFETY: CONFIG in hook_install is set before hooks are enabled, never modified after.
    unsafe { (*std::ptr::addr_of!(crate::hook_install::CONFIG)).as_ref() }
}

fn is_controlled_dlc(app_id: u32, dlc_id: u32) -> bool {
    config().map_or(false, |c| {
        c.apps.inject.iter().any(|a| a.id == app_id && a.dlc.contains(&dlc_id))
    })
}

fn controlled_dlcs_for(app_id: u32) -> Vec<u32> {
    config()
        .map(|c| {
            c.apps
                .inject
                .iter()
                .find(|a| a.id == app_id)
                .map(|a| a.dlc.clone())
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

// --- IClientAppManager hooks ---

unsafe extern "C" fn hk_app_manager_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !APP_MANAGER_VMT_DONE.load(std::sync::atomic::Ordering::Acquire) {
        install_app_manager_vmt(this);
    }
    // SAFETY: APP_MANAGER_DETOUR set before enabled.
    unsafe {
        (*std::ptr::addr_of!(APP_MANAGER_DETOUR))
            .as_ref()
            .unwrap()
            .call(this, a1, a2, a3);
    }
}

unsafe extern "C" fn hk_is_app_dlc_installed(
    this: *mut c_void,
    app_id: u32,
    dlc_id: u32,
) -> bool {
    // SAFETY: original function pointer set before VMT swap.
    let original = unsafe { (*std::ptr::addr_of!(ORIG_IS_APP_DLC_INSTALLED)).unwrap() };
    let result = unsafe { original(this, app_id, dlc_id) };
    if !result && is_controlled_dlc(app_id, dlc_id) {
        log_message(&format!(
            "hook: DLC installed spoofed app={} dlc={}",
            app_id, dlc_id
        ));
        return true;
    }
    result
}

unsafe extern "C" fn hk_b_is_dlc_enabled(
    this: *mut c_void,
    app_id: u32,
    dlc_id: u32,
    unknown: *mut c_void,
) -> bool {
    // SAFETY: original function pointer set before VMT swap.
    let original = unsafe { (*std::ptr::addr_of!(ORIG_B_IS_DLC_ENABLED)).unwrap() };
    let result = unsafe { original(this, app_id, dlc_id, unknown) };
    if !result && is_controlled_dlc(app_id, dlc_id) {
        log_message(&format!(
            "hook: DLC enabled spoofed app={} dlc={}",
            app_id, dlc_id
        ));
        return true;
    }
    result
}

fn install_app_manager_vmt(this: *mut c_void) {
    if APP_MANAGER_VMT_DONE.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    if this.is_null() {
        return;
    }

    // SAFETY: reading vtable from C++ object.
    let vtable = unsafe { *(this as *const *const usize) };
    if vtable.is_null() {
        return;
    }

    // IsAppDlcInstalled (slot 9)
    let slot9 = unsafe { *vtable.add(IS_APP_DLC_INSTALLED_SLOT) };
    unsafe {
        std::ptr::addr_of_mut!(ORIG_IS_APP_DLC_INSTALLED)
            .write(Some(std::mem::transmute(slot9)));
    }

    // BIsDlcEnabled (slot 11)
    let slot11 = unsafe { *vtable.add(B_IS_DLC_ENABLED_SLOT) };
    unsafe {
        std::ptr::addr_of_mut!(ORIG_B_IS_DLC_ENABLED).write(Some(std::mem::transmute(slot11)));
    }

    // SAFETY: write to vtable slots.
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let slot9_ptr = vtable.add(IS_APP_DLC_INSTALLED_SLOT) as *mut usize;
        let page_start = (slot9_ptr as usize) & !(page_size - 1);
        libc::mprotect(
            page_start as *mut libc::c_void,
            page_size * 2,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        *slot9_ptr = hk_is_app_dlc_installed as *const () as usize;
        *(vtable.add(B_IS_DLC_ENABLED_SLOT) as *mut usize) =
            hk_b_is_dlc_enabled as *const () as usize;
        libc::mprotect(
            page_start as *mut libc::c_void,
            page_size * 2,
            libc::PROT_READ,
        );
    }

    log_message("hook-install: IClientAppManager DLC VMT hooks INSTALLED (slots 9, 11)");
}

// --- IClientApps hooks ---

unsafe extern "C" fn hk_client_apps_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !CLIENT_APPS_VMT_DONE.load(std::sync::atomic::Ordering::Acquire) {
        install_client_apps_vmt(this);
    }
    // SAFETY: CLIENT_APPS_DETOUR set before enabled.
    unsafe {
        (*std::ptr::addr_of!(CLIENT_APPS_DETOUR))
            .as_ref()
            .unwrap()
            .call(this, a1, a2, a3);
    }
}

unsafe extern "C" fn hk_get_dlc_count(this: *mut c_void, app_id: u32) -> u32 {
    // SAFETY: original function pointer set before VMT swap.
    let original = unsafe { (*std::ptr::addr_of!(ORIG_GET_DLC_COUNT)).unwrap() };
    let count = unsafe { original(this, app_id) };
    let extra = controlled_dlcs_for(app_id);
    if !extra.is_empty() {
        let total = count + extra.len() as u32;
        log_message(&format!(
            "hook: DLC count app={} original={} injected={} total={}",
            app_id,
            count,
            extra.len(),
            total
        ));
        return total;
    }
    count
}

unsafe extern "C" fn hk_b_get_dlc_data_by_index(
    this: *mut c_void,
    app_id: u32,
    index: i32,
    out_dlc_id: *mut u32,
    out_available: *mut bool,
    out_name: *mut u8,
    name_len: usize,
) -> bool {
    // SAFETY: original function pointer set before VMT swap.
    let original = unsafe { (*std::ptr::addr_of!(ORIG_B_GET_DLC_DATA_BY_INDEX)).unwrap() };
    let result =
        unsafe { original(this, app_id, index, out_dlc_id, out_available, out_name, name_len) };
    if result {
        return true;
    }

    let extra = controlled_dlcs_for(app_id);
    // SAFETY: original function pointer set before VMT swap; re-call to get original count.
    let orig_count_fn = unsafe { (*std::ptr::addr_of!(ORIG_GET_DLC_COUNT)).unwrap() };
    let orig_count = unsafe { orig_count_fn(this, app_id) } as i32;
    let inject_idx = index - orig_count;
    if inject_idx >= 0 && (inject_idx as usize) < extra.len() {
        let dlc_id = extra[inject_idx as usize];
        if !out_dlc_id.is_null() {
            // SAFETY: out_dlc_id is a valid pointer from Steam's caller.
            unsafe { *out_dlc_id = dlc_id };
        }
        if !out_available.is_null() {
            // SAFETY: out_available is a valid pointer from Steam's caller.
            unsafe { *out_available = true };
        }
        if !out_name.is_null() && name_len > 0 {
            // SAFETY: out_name buffer provided by Steam.
            let label = format!("DLC {}", dlc_id);
            let copy_len = label.len().min(name_len - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(label.as_ptr(), out_name, copy_len);
                *out_name.add(copy_len) = 0;
            }
        }
        log_message(&format!(
            "hook: DLC data injected app={} idx={} dlc={}",
            app_id, index, dlc_id
        ));
        return true;
    }

    false
}

fn install_client_apps_vmt(this: *mut c_void) {
    if CLIENT_APPS_VMT_DONE.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    if this.is_null() {
        return;
    }

    // SAFETY: reading vtable.
    let vtable = unsafe { *(this as *const *const usize) };
    if vtable.is_null() {
        return;
    }

    let slot8 = unsafe { *vtable.add(GET_DLC_COUNT_SLOT) };
    unsafe {
        std::ptr::addr_of_mut!(ORIG_GET_DLC_COUNT).write(Some(std::mem::transmute(slot8)));
    }

    let slot9 = unsafe { *vtable.add(B_GET_DLC_DATA_BY_INDEX_SLOT) };
    unsafe {
        std::ptr::addr_of_mut!(ORIG_B_GET_DLC_DATA_BY_INDEX)
            .write(Some(std::mem::transmute(slot9)));
    }

    // SAFETY: write to vtable slots.
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let slot8_ptr = vtable.add(GET_DLC_COUNT_SLOT) as *mut usize;
        let page_start = (slot8_ptr as usize) & !(page_size - 1);
        libc::mprotect(
            page_start as *mut libc::c_void,
            page_size * 2,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        *slot8_ptr = hk_get_dlc_count as *const () as usize;
        *(vtable.add(B_GET_DLC_DATA_BY_INDEX_SLOT) as *mut usize) =
            hk_b_get_dlc_data_by_index as *const () as usize;
        libc::mprotect(
            page_start as *mut libc::c_void,
            page_size * 2,
            libc::PROT_READ,
        );
    }

    log_message("hook-install: IClientApps DLC VMT hooks INSTALLED (slots 8, 9)");
}

// --- Create / finalize ---

pub fn create_app_manager_detour(code: &SteamClientCode) -> Option<usize> {
    let pattern = match Pattern::parse(APP_MANAGER_RUN_IPC_FRAME_PATTERN) {
        Ok(p) => p,
        Err(e) => {
            log_message(&format!(
                "hook-install: AppManager::RunIPCFrame pattern failed: {}",
                e
            ));
            return None;
        }
    };
    let offset = match pattern.find_unique(code.bytes) {
        Ok(o) => o,
        Err(e) => {
            log_message(&format!(
                "hook-install: AppManager::RunIPCFrame match failed: {}",
                e
            ));
            return None;
        }
    };
    let addr = code.base + offset;
    log_message(&format!(
        "hook-install: AppManager::RunIPCFrame at 0x{:x}",
        addr
    ));

    // SAFETY: addr is validated code.
    let target: RunIPCFrameFn = unsafe { std::mem::transmute(addr) };
    let detour = match unsafe { GenericDetour::new(target, hk_app_manager_run_ipc_frame) } {
        Ok(d) => d,
        Err(e) => {
            log_message(&format!(
                "hook-install: AppManager::RunIPCFrame retour failed: {}",
                e
            ));
            return None;
        }
    };
    // SAFETY: storing detour.
    unsafe { std::ptr::addr_of_mut!(APP_MANAGER_DETOUR).write(Some(detour)) };
    log_message("hook-install: AppManager::RunIPCFrame detour created");
    Some(addr)
}

pub fn finalize_app_manager_hook(callee_addr: Option<usize>) {
    let Some(addr) = callee_addr else { return };
    // SAFETY: detour was set.
    let tramp_addr = unsafe {
        (*std::ptr::addr_of!(APP_MANAGER_DETOUR))
            .as_ref()
            .unwrap()
            .trampoline() as *const _ as usize
    };
    repair_pic_thunk_at(tramp_addr, addr);
    // SAFETY: enabling.
    unsafe {
        if let Err(e) = (*std::ptr::addr_of_mut!(APP_MANAGER_DETOUR))
            .as_mut()
            .unwrap()
            .enable()
        {
            log_message(&format!(
                "hook-install: AppManager::RunIPCFrame enable failed: {}",
                e
            ));
            return;
        }
    }
    log_message("hook-install: AppManager::RunIPCFrame INSTALLED");
}

pub fn create_client_apps_detour(code: &SteamClientCode) -> Option<usize> {
    let pattern = match Pattern::parse(CLIENT_APPS_RUN_IPC_FRAME_PATTERN) {
        Ok(p) => p,
        Err(e) => {
            log_message(&format!(
                "hook-install: ClientApps::RunIPCFrame pattern failed: {}",
                e
            ));
            return None;
        }
    };
    let offset = match pattern.find_unique(code.bytes) {
        Ok(o) => o,
        Err(e) => {
            log_message(&format!(
                "hook-install: ClientApps::RunIPCFrame match failed: {}",
                e
            ));
            return None;
        }
    };
    let addr = code.base + offset;
    log_message(&format!(
        "hook-install: ClientApps::RunIPCFrame at 0x{:x}",
        addr
    ));

    // SAFETY: addr is validated code.
    let target: RunIPCFrameFn = unsafe { std::mem::transmute(addr) };
    let detour = match unsafe { GenericDetour::new(target, hk_client_apps_run_ipc_frame) } {
        Ok(d) => d,
        Err(e) => {
            log_message(&format!(
                "hook-install: ClientApps::RunIPCFrame retour failed: {}",
                e
            ));
            return None;
        }
    };
    // SAFETY: storing detour.
    unsafe { std::ptr::addr_of_mut!(CLIENT_APPS_DETOUR).write(Some(detour)) };
    log_message("hook-install: ClientApps::RunIPCFrame detour created");
    Some(addr)
}

pub fn finalize_client_apps_hook(callee_addr: Option<usize>) {
    let Some(addr) = callee_addr else { return };
    // SAFETY: detour was set.
    let tramp_addr = unsafe {
        (*std::ptr::addr_of!(CLIENT_APPS_DETOUR))
            .as_ref()
            .unwrap()
            .trampoline() as *const _ as usize
    };
    repair_pic_thunk_at(tramp_addr, addr);
    // SAFETY: enabling.
    unsafe {
        if let Err(e) = (*std::ptr::addr_of_mut!(CLIENT_APPS_DETOUR))
            .as_mut()
            .unwrap()
            .enable()
        {
            log_message(&format!(
                "hook-install: ClientApps::RunIPCFrame enable failed: {}",
                e
            ));
            return;
        }
    }
    log_message("hook-install: ClientApps::RunIPCFrame INSTALLED");
}
