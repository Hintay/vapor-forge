// Orchestration: install LdrLoadDll detour, detect trigger, load user DLL.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::detour::PreparedDetour;
use crate::maps;
use crate::nt_types::{
    LdrLoadDllFn, LdrLockLoaderLockFn, LdrUnlockLoaderLockFn, UnicodeString, STATUS_SUCCESS,
};
use crate::pe;
use crate::trigger;

static TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static INSTALL_LOCK: Mutex<()> = Mutex::new(());
static HELPER_LOADING: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicBool = AtomicBool::new(false);

const PE_NTDLL_SUFFIX: &str = "x86_64-windows/ntdll.dll";

/// Try to install the LdrLoadDll detour. Returns true if installed.
pub fn install_trigger() -> bool {
    let Ok(_install_guard) = INSTALL_LOCK.lock() else {
        log("detour install lock poisoned");
        return false;
    };
    if TRAMPOLINE.load(Ordering::Acquire) != 0 {
        return true;
    }

    let maps = maps::parse_self_maps();
    let (pe_base, pe_path) = match maps::find_module_with_path(&maps, PE_NTDLL_SUFFIX) {
        Some(v) => v,
        None => return false,
    };

    let pe_bytes = match std::fs::read(pe_path) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let load_rva = match pe::find_export_rva(&pe_bytes, "LdrLoadDll") {
        Some(rva) => rva,
        None => {
            log("no LdrLoadDll export in PE ntdll");
            return false;
        }
    };
    let Some(lock_rva) = pe::find_export_rva(&pe_bytes, "LdrLockLoaderLock") else {
        log("no LdrLockLoaderLock export in PE ntdll");
        return false;
    };
    let Some(unlock_rva) = pe::find_export_rva(&pe_bytes, "LdrUnlockLoaderLock") else {
        log("no LdrUnlockLoaderLock export in PE ntdll");
        return false;
    };

    let target = pe_base + load_rva as usize;
    // SAFETY: all three addresses are exports from the same mapped PE ntdll.
    let Some(_loader_guard) = (unsafe {
        WineLoaderGuard::acquire(pe_base + lock_rva as usize, pe_base + unlock_rva as usize)
    }) else {
        log("failed to acquire Wine loader lock");
        return false;
    };

    // SAFETY: target is LdrLoadDll's address in the mapped PE ntdll.
    let prepared =
        match unsafe { PreparedDetour::prepare(target, hook_ldr_load_dll as *const () as usize) } {
            Some(prepared) => prepared,
            None => {
                log("detour preparation failed");
                return false;
            }
        };

    let trampoline = prepared.trampoline();
    TRAMPOLINE.store(trampoline, Ordering::Release);

    // SAFETY: install_trigger is serialized. The loader invokes this during
    // pre-initialization or its dedicated retry path, before publishing success.
    let detour = match unsafe { prepared.activate() } {
        Some(detour) => detour,
        None => {
            let _ = TRAMPOLINE.compare_exchange(trampoline, 0, Ordering::AcqRel, Ordering::Acquire);
            log("detour activation failed");
            return false;
        }
    };
    debug_assert_eq!(detour.trampoline, trampoline);

    log("LdrLoadDll detour installed");

    // Check if trigger DLL was already loaded before the detour
    if trigger::trigger_already_loaded(&maps) {
        mark_pending();
        log("trigger already loaded, pending pickup armed");
    }
    install_loaded_achievement_observer(&maps);

    true
}

struct WineLoaderGuard {
    unlock: LdrUnlockLoaderLockFn,
    cookie: usize,
}

impl WineLoaderGuard {
    /// # Safety
    /// Both addresses must be matching exports from the live PE ntdll image.
    unsafe fn acquire(lock_addr: usize, unlock_addr: usize) -> Option<Self> {
        // SAFETY: caller validated both addresses as matching ntdll exports.
        let lock: LdrLockLoaderLockFn = unsafe { std::mem::transmute(lock_addr) };
        // SAFETY: caller validated both addresses as matching ntdll exports.
        let unlock: LdrUnlockLoaderLockFn = unsafe { std::mem::transmute(unlock_addr) };
        let mut disposition = 0u32;
        let mut cookie = 0usize;
        // SAFETY: output pointers are valid for the duration of the call.
        let status = unsafe { lock(0, &mut disposition, &mut cookie) };
        (status == STATUS_SUCCESS && cookie != 0).then_some(Self { unlock, cookie })
    }
}

impl Drop for WineLoaderGuard {
    fn drop(&mut self) {
        // SAFETY: cookie was returned by the matching successful lock call.
        let _ = unsafe { (self.unlock)(0, self.cookie) };
    }
}

pub fn mark_pending() {
    PENDING.store(true, Ordering::Release);
}

/// Called from the LdrLoadDll hook. Checks if this DLL load is a trigger
/// and reports PE analysis via IPC.
pub fn on_ldr_load_dll(name: &[u16], base_address: *mut core::ffi::c_void) {
    let dll_name = dll_name_to_string(name);
    if !dll_name.is_empty() {
        crate::ipc::send_dll_loaded(&dll_name);
    }

    // Check for Denuvo DLL names in every loaded DLL.
    if pe::is_denuvo_dll_name(name) {
        log("Denuvo DLL name detected");
        crate::ipc::send_denuvo_detected();
    }

    // Scan PE sections of the loaded module for DRM indicators.
    if !base_address.is_null() {
        scan_loaded_pe(base_address);
    }

    let trigger_seen = trigger::is_trigger_name(name);
    let pending_pickup = PENDING.swap(false, Ordering::AcqRel);

    if trigger_seen || pending_pickup {
        // Connect IPC before loading the helper DLL.
        crate::ipc::try_connect();
        crate::achievement_observer::install_for_module(&dll_name, base_address as usize);
        let maps = maps::parse_self_maps();
        install_loaded_achievement_observer(&maps);
        load_helper_now();
    }
}

fn install_loaded_achievement_observer(entries: &[maps::MapEntry]) {
    if let Some(entry) = maps::find_module(entries, "steam_api64.dll") {
        crate::achievement_observer::install_for_module("steam_api64.dll", entry.base);
    }
}

fn dll_name_to_string(name: &[u16]) -> String {
    String::from_utf16_lossy(name)
        .trim_end_matches('\0')
        .to_owned()
}

fn scan_loaded_pe(base: *mut core::ffi::c_void) {
    const MAX_HEADER_READ: usize = 4096;
    let addr = base as usize;
    let readable = crate::maps::mapping_size_at(addr).unwrap_or(0);
    if readable == 0 {
        return;
    }
    let len = readable.min(MAX_HEADER_READ);
    // SAFETY: reading within the verified mapping region of a loaded module.
    let header = unsafe { std::slice::from_raw_parts(addr as *const u8, len) };
    let sections = pe::section_names(header);
    for name in &sections {
        if pe::DENUVO_SECTIONS
            .iter()
            .any(|&ds| name.eq_ignore_ascii_case(ds))
        {
            log(&format!("Denuvo section detected: {name}"));
            crate::ipc::send_denuvo_detected();
            crate::ipc::send_pe_section(name);
        }
    }
}

fn load_helper_now() {
    if HELPER_LOADING.swap(true, Ordering::AcqRel) {
        return; // already loading/loaded
    }

    let dll_path = match std::env::var("VAPOR_FORGE_INJECT_DLL") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            log("VAPOR_FORGE_INJECT_DLL not set");
            HELPER_LOADING.store(false, Ordering::Release);
            return;
        }
    };

    log(&format!("loading DLL: {}", dll_path));

    let wine_path = trigger::linux_path_to_wine_nt(&dll_path);
    let tramp = TRAMPOLINE.load(Ordering::Acquire);
    if tramp == 0 {
        log("trampoline not available");
        HELPER_LOADING.store(false, Ordering::Release);
        return;
    }

    // SAFETY: calling the original LdrLoadDll through the trampoline.
    let orig: LdrLoadDllFn = unsafe { std::mem::transmute(tramp) };
    let mut us = UnicodeString {
        length: ((wine_path.len() - 1) * 2) as u16, // exclude NUL
        max_length: (wine_path.len() * 2) as u16,
        buffer: wine_path.as_ptr() as *mut u16,
    };
    let mut base: *mut core::ffi::c_void = std::ptr::null_mut();

    // SAFETY: orig is the relocated LdrLoadDll trampoline and all pointers live
    // through the call.
    let status = unsafe { orig(std::ptr::null_mut(), 0, &mut us, &mut base) };
    if status == STATUS_SUCCESS {
        log("DLL loaded successfully");
        crate::ipc::send_dll_inject_result(true);
    } else {
        log(&format!("LdrLoadDll failed: 0x{:08X}", status));
        crate::ipc::send_dll_inject_result(false);
        HELPER_LOADING.store(false, Ordering::Release);
    }
}

/// The hook function called from Wine PE threads via the detour.
/// Uses `extern "win64"` (Microsoft x64 ABI) to match LdrLoadDll's
/// calling convention.
///
/// # Safety
/// Called from Wine's PE code. Must not panic (would unwind through PE stack).
unsafe extern "win64" fn hook_ldr_load_dll(
    search_path: *mut u16,
    flags: u32,
    dll_name: *mut UnicodeString,
    base_address: *mut *mut core::ffi::c_void,
) -> i32 {
    let tramp = TRAMPOLINE.load(Ordering::Acquire);
    if tramp == 0 {
        return -1;
    }

    // SAFETY: TRAMPOLINE is written by Detour::install with a valid
    // LdrLoadDll-compatible trampoline address before this hook is active.
    let orig: LdrLoadDllFn = unsafe { std::mem::transmute(tramp) };
    // SAFETY: The hook receives LdrLoadDll's original arguments and forwards
    // them unchanged to the original trampoline with the same ABI.
    let status = unsafe { orig(search_path, flags, dll_name, base_address) };

    if status == STATUS_SUCCESS && !dll_name.is_null() {
        // Wrap in catch_unwind: a panic here would unwind through PE frames.
        let base = if base_address.is_null() {
            std::ptr::null_mut()
        } else {
            // SAFETY: On STATUS_SUCCESS, LdrLoadDll initialized base_address
            // when the caller supplied a non-null out pointer.
            unsafe { *base_address }
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: dll_name is checked for null above. Wine provides a
            // valid UNICODE_STRING for the duration of the callback.
            let name = unsafe { (*dll_name).as_slice() };
            on_ldr_load_dll(name, base);
        }));
    }

    status
}

pub(crate) fn log(msg: &str) {
    static PATH: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    let path = PATH.get_or_init(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        std::ffi::CString::new(format!(
            "{home}/.config/vapor-forge/vapor-forge-proton-inject.log"
        ))
        .unwrap_or_else(|_| std::ffi::CString::new("/tmp/vapor-forge-proton-inject.log").unwrap())
    });

    const MAX_LOG_SIZE: libc::off_t = 512 * 1024;

    // SAFETY: all libc calls use the valid CString path or stack/string buffers,
    // and failures are handled by returning early or ignoring diagnostic output.
    unsafe {
        let fd = libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o644,
        );
        if fd < 0 {
            return;
        }
        let pos = libc::lseek(fd, 0, libc::SEEK_END);
        if pos > MAX_LOG_SIZE {
            libc::ftruncate(fd, 0);
            libc::lseek(fd, 0, libc::SEEK_SET);
        }
        let pid = libc::getpid();
        let mut header = [0u8; 48];
        let header_len = {
            let s = format!("[vapor-forge-proton-inject][{pid}] ");
            let len = s.len().min(header.len());
            header[..len].copy_from_slice(&s.as_bytes()[..len]);
            len
        };
        libc::write(fd, header.as_ptr() as *const _, header_len);
        libc::write(fd, msg.as_ptr() as *const _, msg.len());
        libc::write(fd, b"\n".as_ptr() as *const _, 1);
        libc::close(fd);
    }
}
