use core::ffi::c_void;

use tracing::{debug, info, warn};
use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_patterns::registry::PatternRegistry;

use crate::pattern_resolver::CodeRegion;
use vapor_forge_hook_engine::original::detour_or_return;

use super::install::{config, IPC_SERVER};

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

// Library injection: BuildSpawnEnvBlock builds the child process env block for
// a game launch. CGameID is passed by pointer and is 8 bytes on both i686 and
// x86_64: low 24 bits = AppId, byte 3 = type (2 = app).
pub(crate) type BuildSpawnEnvBlockFn = unsafe extern "C" fn(
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
pub(crate) type SetEnvStringFn = unsafe extern "C" fn(*mut c_void, *const i8, *const i8);

// CUser::SpawnProcess: launches a game. On x86_64 SysV, this/exe/command/dir/
// CGameID/extra are register args and later flags stay on the native ABI stack.
// pCommandLine contains user launch options.
pub(crate) type SpawnProcessFn = unsafe extern "C" fn(
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

pub(crate) static mut BUILD_SPAWN_ENV_DETOUR: Option<Detour<BuildSpawnEnvBlockFn>> = None;
pub(crate) static mut SPAWN_PROCESS_DETOUR: Option<Detour<SpawnProcessFn>> = None;
pub(crate) static mut SET_ENV_STRING_FN: Option<SetEnvStringFn> = None;
pub(crate) static mut SET_ENV_STRING_DETOUR: Option<Detour<SetEnvStringFn>> = None;

// Native libraries to merge into the LD_PRELOAD value Steam writes while the
// tagged env map's BuildSpawnEnvBlock call is active.
static PENDING_PRELOAD: std::sync::Mutex<Option<(usize, Vec<String>)>> =
    std::sync::Mutex::new(None);

/// Writer for the env map: the SetEnvString trampoline when the detour is
/// installed, the raw resolved function otherwise.
fn env_writer() -> Option<SetEnvStringFn> {
    // SAFETY: installation publishes both slots before any hook can run.
    unsafe {
        if (*std::ptr::addr_of!(SET_ENV_STRING_DETOUR)).is_some() {
            vapor_forge_hook_engine::original::original_detour(
                "SetEnvString",
                std::ptr::addr_of!(SET_ENV_STRING_DETOUR),
            )
        } else {
            *std::ptr::addr_of!(SET_ENV_STRING_FN)
        }
    }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: SetEnvString (LD_PRELOAD merge)
// ---------------------------------------------------------------------------

/// Steam composes the child's LD_PRELOAD from its own environment plus the
/// overlay renderers and writes it after the launch hooks ran, which discards
/// anything stored in the map earlier. Prepend the pending native libraries.
pub(crate) unsafe extern "C" fn hk_set_env_string(
    env_map: *mut c_void,
    key: *const i8,
    value: *const i8,
) {
    let original = detour_or_return!("SetEnvString", SET_ENV_STRING_DETOUR);
    if !key.is_null() && !value.is_null() {
        // SAFETY: Steam passes NUL-terminated strings for the duration of the call.
        let is_preload = unsafe { std::ffi::CStr::from_ptr(key) }.to_bytes() == b"LD_PRELOAD";
        if is_preload {
            let pending = PENDING_PRELOAD
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or(None);
            if let Some((map, libs)) = pending {
                if map == env_map as usize {
                    // SAFETY: value is a live NUL-terminated string from Steam.
                    let steam_value = unsafe { std::ffi::CStr::from_ptr(value) }
                        .to_string_lossy()
                        .into_owned();
                    let merged =
                        vapor_forge_features::library_inject::merge_ld_preload(&libs, &steam_value);
                    if let Ok(merged_c) = std::ffi::CString::new(merged.as_str()) {
                        info!(value = %merged, "library_inject: LD_PRELOAD merged with Steam's");
                        // SAFETY: forwards Steam's map and key with our merged value.
                        unsafe { original(env_map, key, merged_c.as_ptr()) };
                        return;
                    }
                }
            }
        }
    }
    // SAFETY: forwards Steam's untouched arguments.
    unsafe { original(env_map, key, value) }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: BuildSpawnEnvBlock (native .so injection)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_build_spawn_env_block(
    game_id: *mut c_void,
    exe_path: *const i8,
    working_dir: *const i8,
    launch_ctx: *mut c_void,
    flags: u32,
    something: *mut c_void,
    env_map: *mut c_void,
    context: *mut c_void,
) -> i32 {
    // SAFETY: BUILD_SPAWN_ENV_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("BuildSpawnEnvBlock", BUILD_SPAWN_ENV_DETOUR, 0);

    let mut native_libs = None;
    if crate::capability::is_ready(crate::capability::Capability::LaunchEnvironment)
        && !game_id.is_null()
        && !env_map.is_null()
    {
        // BuildSpawnEnvBlock forks and executes the child while the original call
        // is active. Update its input map before Steam snapshots the environment.
        // SAFETY: both pointers were validated above and belong to this invocation.
        native_libs = unsafe { inject_spawn_environment(game_id, env_map) };
    }

    // Steam overwrites LD_PRELOAD inside the original call; let the
    // SetEnvString detour merge our libraries into that write.
    if let Some(libs) = native_libs.clone() {
        if let Ok(mut pending) = PENDING_PRELOAD.lock() {
            *pending = Some((env_map as usize, libs));
        }
    }

    // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
    let result = unsafe {
        original(
            game_id,
            exe_path,
            working_dir,
            launch_ctx,
            flags,
            something,
            env_map,
            context,
        )
    };

    if native_libs.is_some() {
        if let Ok(mut pending) = PENDING_PRELOAD.lock() {
            *pending = None;
        }
    }
    result
}

/// Returns the native libraries written as LD_PRELOAD, if any, so the caller
/// can keep them merged into Steam's later write.
unsafe fn inject_spawn_environment(
    game_id: *mut c_void,
    env_map: *mut c_void,
) -> Option<Vec<String>> {
    // CGameID low 24 bits = AppId.
    // SAFETY: game_id is a valid CGameID* from Steam's caller.
    let raw = unsafe { *(game_id as *const u32) };
    let app_id = AppId(raw & 0x00FF_FFFF);

    let injection = vapor_forge_features::library_inject::take_pending(app_id);
    let cfg = config();
    let ipc_server = IPC_SERVER.get();

    if injection.is_none() && ipc_server.is_none() {
        return None;
    }

    let Some(set_env) = env_writer() else {
        warn!(app = app_id.0, "library_inject: SetEnvString unresolved");
        return None;
    };

    // Native .so injection via LD_PRELOAD
    let mut native_libs = None;
    if let Some(ref inj) = injection {
        if !inj.native_libs.is_empty() {
            let ld_preload = inj.native_libs.join(":");
            if let Ok(value) = std::ffi::CString::new(ld_preload.as_str()) {
                /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                unsafe { set_env(env_map, c"LD_PRELOAD".as_ptr(), value.as_ptr()) };
                info!(app = app_id.0, paths = %ld_preload, "library_inject: LD_PRELOAD set");
                native_libs = Some(inj.native_libs.clone());
            }
        }
    }

    let has_proton_dll = injection
        .as_ref()
        .and_then(|i| i.proton_dll.as_ref())
        .is_some();

    // Duplicate-module loader fix: the helper needs to be loaded and told to
    // look for the duplicate entry; the DLL and IPC paths below set LD_AUDIT
    // themselves, so only add it here when neither of them will.
    if injection.as_ref().is_some_and(|i| i.loader_fix) {
        /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
        unsafe { set_env(env_map, c"VAPOR_FORGE_LOADER_FIX".as_ptr(), c"1".as_ptr()) };
        if !has_proton_dll && ipc_server.is_none() {
            match resolve_helper_path(&cfg.library_inject.helper_path) {
                Some(path) => {
                    if let Ok(audit_val) = std::ffi::CString::new(path.as_str()) {
                        /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                        unsafe { set_env(env_map, c"LD_AUDIT".as_ptr(), audit_val.as_ptr()) };
                        info!(app = app_id.0, helper = %path, "library_inject: loader fix armed");
                    }
                }
                None => warn!(app = app_id.0, "library_inject: proton helper not found"),
            }
        } else {
            info!(app = app_id.0, "library_inject: loader fix armed");
        }
    }

    // IPC token injection: register a per-launch token whenever the IPC
    // server is running, regardless of whether this game has a DLL to
    // inject. The helper may be loaded solely for PE scanning.
    if let Some(server) = ipc_server {
        if let Ok(token) = vapor_forge_game_bridge::generate_token() {
            server.register_token(token, app_id.0);
            let hex = vapor_forge_game_bridge::token_to_hex(&token);
            if let (Ok(key), Ok(val)) = (
                std::ffi::CString::new(vapor_forge_game_bridge::ENV_GAME_BRIDGE_TOKEN),
                std::ffi::CString::new(hex.as_str()),
            ) {
                /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                unsafe { set_env(env_map, key.as_ptr(), val.as_ptr()) };
            }
            if let (Ok(key), Ok(val)) = (
                std::ffi::CString::new(vapor_forge_game_bridge::ENV_GAME_BRIDGE_SOCK),
                std::ffi::CString::new(server.socket_path()),
            ) {
                /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                unsafe { set_env(env_map, key.as_ptr(), val.as_ptr()) };
            }
            debug!(app = app_id.0, "library_inject: IPC token injected");
        }

        // If no DLL injection is configured but IPC is needed, load the
        // proton helper anyway so it can scan PEs and report back.
        if !has_proton_dll {
            if let Some(path) = resolve_helper_path(&cfg.library_inject.helper_path) {
                if let Ok(audit_val) = std::ffi::CString::new(path.as_str()) {
                    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                    unsafe { set_env(env_map, c"LD_AUDIT".as_ptr(), audit_val.as_ptr()) };
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
                        /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                        unsafe { set_env(env_map, c"LD_AUDIT".as_ptr(), audit_val.as_ptr()) };
                        /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                        unsafe {
                            set_env(
                                env_map,
                                c"VAPOR_FORGE_INJECT_DLL".as_ptr(),
                                dll_val.as_ptr(),
                            )
                        };
                        info!(app = app_id.0, dll = %dll_path, helper = %path, "library_inject: Proton DLL injection set");
                    }
                }
                None => {
                    warn!(app = app_id.0, "library_inject: proton helper not found");
                }
            }
        }
    }
    native_libs
}

// ---------------------------------------------------------------------------
// Hook replacement functions -- CUser::SpawnProcess (flag evaluation)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_spawn_process(
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
    let original = detour_or_return!("SpawnProcess", SPAWN_PROCESS_DETOUR, -1);
    if !crate::capability::is_ready(crate::capability::Capability::LaunchEnvironment) {
        // SAFETY: forwards Steam's untouched launch arguments.
        return unsafe {
            original(
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
        };
    }
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
        if vapor_forge_features::library_inject::section_is_active(&cfg.library_inject) {
            vapor_forge_features::library_inject::on_launch_section(
                app_id,
                &cfg.library_inject,
                &launch_opts,
            );
        }
    }

    // SAFETY: forwards Steam's launch arguments after recording the configured flags.
    unsafe {
        original(
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
    let call_addr =
        match crate::pattern_resolver::resolve_pattern_entry(code, "SetEnvString", &entry) {
            Some(a) => a,
            None => return,
        };
    if !crate::pattern_resolver::validate_resolved_pattern(
        "steamclient",
        code,
        "SetEnvString",
        call_addr,
    ) {
        return;
    }
    // SAFETY: call_addr is a validated code address.
    let f: SetEnvStringFn = unsafe { std::mem::transmute(call_addr) };
    // SAFETY: hook installation is single-threaded and publishes this slot once.
    unsafe { std::ptr::addr_of_mut!(SET_ENV_STRING_FN).write(Some(f)) };
    debug!(
        addr = format_args!("0x{:x}", call_addr),
        "SetEnvString resolved"
    );
}

pub(crate) fn set_env_string_ready() -> bool {
    // SAFETY: installation is the only writer and publishes the slot before this read.
    unsafe { (*std::ptr::addr_of!(SET_ENV_STRING_FN)).is_some() }
}
