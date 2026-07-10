use core::ffi::c_void;

use retour::GenericDetour;
use tracing::{debug, info, warn};
use vapor_forge_config::AppId;
use vapor_forge_patterns::registry::PatternRegistry;

use crate::detour::{self, CodeRegion};
use crate::original::detour_or_return;

use super::install::{config, IPC_SERVER};

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

// Library injection: BuildSpawnEnvBlock builds the child process env block for
// a game launch. CGameID is passed by pointer and is 8 bytes on both i686 and
// x86_64: low 24 bits = AppId, byte 3 = type (2 = app).
pub(crate) type BuildSpawnEnvBlockFn = extern "C" fn(
    *mut c_void, // CGameID*
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
pub(crate) type SetEnvStringFn = extern "C" fn(*mut c_void, *const i8, *const i8);

// CUser::SpawnProcess: launches a game. On x86_64 SysV, this/exe/command/dir/
// CGameID/extra are register args and later flags stay on the native ABI stack.
// pCommandLine contains user launch options.
pub(crate) type SpawnProcessFn = extern "C" fn(
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

pub(crate) static mut BUILD_SPAWN_ENV_DETOUR: Option<GenericDetour<BuildSpawnEnvBlockFn>> = None;
pub(crate) static mut SPAWN_PROCESS_DETOUR: Option<GenericDetour<SpawnProcessFn>> = None;
pub(crate) static mut SET_ENV_STRING_FN: Option<SetEnvStringFn> = None;

// ---------------------------------------------------------------------------
// Hook replacement functions: BuildSpawnEnvBlock (native .so injection)
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_build_spawn_env_block(
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

    // CGameID low 24 bits = AppId.
    // SAFETY: game_id is a valid CGameID* from Steam's caller.
    let raw = unsafe { *(game_id as *const u32) };
    let app_id = AppId(raw & 0x00FF_FFFF);

    let injection = vapor_forge_features::library_inject::take_pending(app_id);
    let cfg = config();
    let ipc_server = cfg.ticket.auto_delegate.then(|| IPC_SERVER.get()).flatten();

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
                set_env(env_map, c"LD_PRELOAD".as_ptr(), value.as_ptr());
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
                set_env(env_map, c"VAPOR_FORGE_IPC_SOCK".as_ptr(), sock_val.as_ptr());
            }
            debug!(app = app_id.0, "library_inject: IPC token injected");
        }

        // If no DLL injection is configured but IPC is needed, load the
        // proton helper anyway so it can scan PEs and report back.
        if !has_proton_dll {
            if let Some(path) = resolve_helper_path(&cfg.library_inject.helper_path) {
                if let Ok(audit_val) = std::ffi::CString::new(path.as_str()) {
                    set_env(env_map, c"LD_AUDIT".as_ptr(), audit_val.as_ptr());
                    debug!(app = app_id.0, helper = %path, "library_inject: helper loaded for IPC only");
                }
            }
        }
    }

    // Proton .dll injection via LD_AUDIT helper
    if let Some(ref inj) = injection {
        if let Some(dll_path) = &inj.proton_dll {
            let resolved = resolve_helper_path(&cfg.library_inject.helper_path);
            match resolved {
                Some(path) => {
                    if let (Ok(audit_val), Ok(dll_val)) = (
                        std::ffi::CString::new(path.as_str()),
                        std::ffi::CString::new(dll_path.as_str()),
                    ) {
                        set_env(env_map, c"LD_AUDIT".as_ptr(), audit_val.as_ptr());
                        set_env(
                            env_map,
                            c"VAPOR_FORGE_INJECT_DLL".as_ptr(),
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

pub(crate) extern "C" fn hk_spawn_process(
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
    // Extract AppId from CGameID (low 24 bits).
    if !game_id.is_null() {
        // SAFETY: game_id is a non-null CGameID pointer supplied by Steam.
        let raw = unsafe { *(game_id as *const u32) };
        let app_id = AppId(raw & 0x00FF_FFFF);

        // Read command line for flag evaluation
        let launch_opts = if !command_line.is_null() {
            // SAFETY: command_line is a non-null C string supplied by Steam.
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
        // SAFETY: caller guarantees ptr is readable through its NUL terminator;
        // max_len provides an additional upper bound.
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return String::new();
    }
    // SAFETY: the loop above just read the complete [0, len) range.
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Helper resolution
// ---------------------------------------------------------------------------

const PROTON_HELPER_NAME: &str = "libvapor_forge_proton_inject.so";

/// Resolve the 64-bit proton inject helper path.
/// Priority: config override > same dir as our .so > /usr/lib > /usr/lib64.
pub(crate) fn resolve_helper_path(configured: &str) -> Option<String> {
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
pub(crate) fn own_library_dir() -> Option<String> {
    // SAFETY: Dl_info is a plain C output structure initialized before dladdr.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let self_addr = own_library_dir as *const () as *mut libc::c_void;
    // SAFETY: self_addr names a function in this module and info is writable.
    if unsafe { libc::dladdr(self_addr, &mut info) } == 0 || info.dli_fname.is_null() {
        return None;
    }
    // SAFETY: successful dladdr returned a non-null loader-owned C string.
    let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) };
    let path_str = path.to_str().ok()?;
    std::path::Path::new(path_str)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
}

pub(crate) fn resolve_set_env_string(registry: &PatternRegistry, code: &CodeRegion) {
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
    // SAFETY: hook installation is single-threaded and publishes this slot once.
    unsafe { std::ptr::addr_of_mut!(SET_ENV_STRING_FN).write(Some(f)) };
    debug!(
        addr = format_args!("0x{:x}", call_addr),
        "SetEnvString resolved"
    );
}
