// 64-bit LD_AUDIT helper for Wine/Proton game processes. It observes PE module
// loads, reports runtime events, and can inject a configured Windows DLL when
// a Steam trigger module loads.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
compile_error!("vapor-forge-proton-inject only supports 64-bit Linux targets");

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod detour;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod ipc;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod loader;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod loader_fix;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod mapping_event;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod maps;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod nt_types;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod pe;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod trigger;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use core::ffi::{c_char, c_uint, c_void};

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const LAV_CURRENT: c_uint = 2;

// ---------------------------------------------------------------------------
// LD_AUDIT interface
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[no_mangle]
pub extern "C" fn la_version(version: c_uint) -> c_uint {
    if version == 0 {
        0
    } else {
        LAV_CURRENT.min(version)
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[no_mangle]
pub extern "C" fn la_preinit(_cookie: *mut usize) {
    let has_dll = std::env::var_os("VAPOR_FORGE_INJECT_DLL").is_some();
    let has_ipc = std::env::var_os(vapor_forge_game_bridge::ENV_GAME_BRIDGE_SOCK).is_some();
    let has_loader_fix = loader_fix::enabled();

    if !has_dll && !has_ipc && !has_loader_fix {
        return;
    }

    // Do not perform socket I/O in the audit callback. The loader detour queues
    // reports, and the game-bridge worker connects asynchronously on demand.
    // Per-launch tokens may authenticate multiple Wine child processes.

    if loader::install_trigger() {
        return;
    }
    if current_executable_is_wine() {
        mapping_event::arm_observer();
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[no_mangle]
/// Select Wine-to-libc symbol bindings used to observe PE image mappings.
///
/// # Safety
/// Called by glibc with a live loader-owned link_map pointer.
pub unsafe extern "C" fn la_objopen(
    map: *mut c_void,
    _lmid: libc::c_long,
    _cookie: *mut usize,
) -> c_uint {
    // SAFETY: glibc supplies a valid link_map for this callback.
    unsafe { mapping_event::object_flags(map) }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[no_mangle]
/// Redirect Wine's libc mapping calls through the PE mapping observer.
///
/// # Safety
/// glibc supplies valid symbol and name pointers for the duration of this
/// callback.
pub unsafe extern "C" fn la_symbind64(
    symbol: *const mapping_event::Elf64Symbol,
    _index: c_uint,
    _reference_cookie: *mut usize,
    _definition_cookie: *mut usize,
    _flags: *mut c_uint,
    symbol_name: *const c_char,
) -> usize {
    // SAFETY: the arguments follow glibc's la_symbind64 contract.
    unsafe { mapping_event::bind_symbol(symbol, symbol_name) }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[no_mangle]
/// Observe a loader object-close callback.
///
/// # Safety
/// Called by glibc with a loader-owned cookie; this implementation does not
/// dereference it.
pub unsafe extern "C" fn la_objclose(_cookie: *mut usize) -> c_uint {
    0
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn current_executable_is_wine() -> bool {
    std::fs::read_link("/proc/self/exe")
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_owned()))
        .is_some_and(|name| name.to_string_lossy().to_ascii_lowercase().contains("wine"))
}
