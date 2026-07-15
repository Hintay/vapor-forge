// Proton DLL inject helper.
// 64-bit LD_AUDIT library loaded into Wine/Proton game processes.
// Detours Wine's LdrLoadDll to inject a user DLL when steam_api64.dll loads.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
compile_error!("vapor-forge-proton-inject only supports 64-bit Linux targets");

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod achievement_observer;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod detour;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod ipc;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod loader;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod maps;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod nt_types;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod pe;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod trigger;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use core::ffi::{c_uint, c_void};

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const LAV_CURRENT: c_uint = 2;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const POLL_INTERVAL_MS: u64 = 50;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const POLL_MAX_ATTEMPTS: u32 = 600; // 30 seconds

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

    if !has_dll && !has_ipc {
        return;
    }

    // Do NOT connect IPC here. Wine spawns multiple child processes
    // (wineboot, wineserver, services.exe) that all inherit the same
    // env vars. Connecting here would authenticate a non-game process
    // before the trigger path is active. IPC connects later when the
    // trigger fires, ensuring only the game process reports events.

    if loader::install_trigger() {
        return;
    }
    spawn_poll_thread();
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[no_mangle]
/// Observe a loader object-open callback without requesting symbol interception.
///
/// # Safety
/// Called by glibc with loader-owned pointers; this implementation does not
/// dereference them.
pub unsafe extern "C" fn la_objopen(
    _map: *mut c_void,
    _lmid: libc::c_long,
    _cookie: *mut usize,
) -> c_uint {
    0
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

// ---------------------------------------------------------------------------
// Poll thread
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn spawn_poll_thread() {
    std::thread::Builder::new()
        .name("vapor-forge-proton-inject-poll".into())
        .spawn(|| {
            for _ in 0..POLL_MAX_ATTEMPTS {
                if loader::install_trigger() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
            }
        })
        .ok();
}
