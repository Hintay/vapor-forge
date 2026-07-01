// Proton DLL inject helper.
// 64-bit LD_AUDIT library loaded into Wine/Proton game processes.
// Detours Wine's LdrLoadDll to inject a user DLL when steam_api64.dll loads.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod detour;
mod ipc;
mod loader;
mod maps;
mod nt_types;
mod pe;
mod trigger;

use core::ffi::{c_uint, c_void};

const LAV_CURRENT: c_uint = 2;
const POLL_INTERVAL_MS: u64 = 50;
const POLL_MAX_ATTEMPTS: u32 = 600; // 30 seconds

// ---------------------------------------------------------------------------
// LD_AUDIT interface
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn la_version(version: c_uint) -> c_uint {
    if version == 0 {
        0
    } else {
        LAV_CURRENT.min(version)
    }
}

#[no_mangle]
pub extern "C" fn la_preinit(_cookie: *mut usize) {
    let has_dll = std::env::var_os("STEAM_RUNTIME_INJECT_DLL").is_some();
    let has_ipc = std::env::var_os(inject_protocol::ENV_IPC_SOCK).is_some();

    if !has_dll && !has_ipc {
        return;
    }

    // Do NOT connect IPC here. Wine spawns multiple child processes
    // (wineboot, wineserver, services.exe) that all inherit the same
    // env vars. Connecting here would consume the one-time token from
    // a non-game process. IPC connects later when the trigger fires
    // (steam_api64.dll loaded), ensuring only the game process connects.

    if loader::install_trigger() {
        return;
    }
    spawn_poll_thread();
}

#[no_mangle]
pub unsafe extern "C" fn la_objopen(
    _map: *mut c_void,
    _lmid: libc::c_long,
    _cookie: *mut usize,
) -> c_uint {
    0
}

#[no_mangle]
pub unsafe extern "C" fn la_objclose(_cookie: *mut usize) -> c_uint {
    0
}

// ---------------------------------------------------------------------------
// Poll thread
// ---------------------------------------------------------------------------

fn spawn_poll_thread() {
    std::thread::Builder::new()
        .name("proton-inject-poll".into())
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
