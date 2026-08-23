#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
use once_cell::sync::Lazy;
#[cfg(target_os = "linux")]
use vapor_forge_core::{Lifecycle, SteamModuleState};

#[cfg(target_os = "linux")]
static LIFECYCLE: Lazy<Lifecycle> = Lazy::new(Lifecycle::new);
#[cfg(target_os = "linux")]
static STEAM_MODULES: Lazy<SteamModuleState> = Lazy::new(SteamModuleState::new);

#[cfg(target_os = "linux")]
mod linux_audit {
    use core::ffi::{c_char, c_uint, c_void};

    use vapor_forge_diagnostics::{log_cstr, log_early};
    use vapor_forge_memory::is_steam_target_name;

    use super::{LIFECYCLE, STEAM_MODULES};

    const LAV_CURRENT: c_uint = 2;

    type Lmid = libc::c_long;

    #[repr(C)]
    struct LinkMap {
        l_addr: usize,
        l_name: *mut c_char,
        l_ld: *mut c_void,
        l_next: *mut LinkMap,
        l_prev: *mut LinkMap,
    }

    #[no_mangle]
    pub extern "C" fn la_version(version: c_uint) -> c_uint {
        LIFECYCLE.mark_version_seen();
        log_early("la_version");
        if version == 0 {
            0
        } else {
            LAV_CURRENT.min(version)
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn la_objsearch(
        name: *const c_char,
        _cookie: *mut usize,
        _flag: c_uint,
    ) -> *mut c_char {
        // SAFETY: glibc passes a valid C string for the object name.
        unsafe { log_cstr("la_objsearch", name) };
        name.cast_mut()
    }

    #[no_mangle]
    pub unsafe extern "C" fn la_objopen(
        map: *mut c_void,
        _lmid: Lmid,
        _cookie: *mut usize,
    ) -> c_uint {
        LIFECYCLE.mark_object_seen();

        if map.is_null() {
            log_early("la_objopen: <null link_map>");
        } else {
            let map = map.cast::<LinkMap>();
            // SAFETY: glibc calls la_objopen with a valid link_map pointer.
            let name = unsafe { (*map).l_name };
            // SAFETY: link_map.l_name is a loader-owned C string.
            unsafe { log_cstr("la_objopen", name) };

            // SAFETY: bounded read of loader-owned C string.
            let module_name = unsafe { bounded_cstr_to_string(name, 4096) };
            if module_name.as_deref().is_some_and(is_steam_target_name) {
                log_early("la_objopen: Steam target module observed");
            }
            let target_kind = module_name
                .as_deref()
                .and_then(|n| STEAM_MODULES.mark_seen_by_name(n));

            if let Some(kind) = target_kind {
                log_early(&format!("la_objopen: marked {} seen", kind.as_str()));
                // Don't install from la_objopen because relocations aren't complete.
                // la_activity(LA_ACT_CONSISTENT) will fire after dlmopen finishes.
            }
        }

        0
    }

    #[no_mangle]
    pub extern "C" fn la_preinit(_cookie: *mut usize) {
        LIFECYCLE.mark_ready_for_heavy_init();
        log_early("la_preinit: ready for heavy init");
        clear_audit_env_for_steam();
        // Do not install hooks here. Even if steamclient is already mapped,
        // relocations may not be complete. la_activity(LA_ACT_CONSISTENT)
        // is the reliable signal that all pending relocations are done.
    }

    #[no_mangle]
    pub unsafe extern "C" fn la_objclose(_cookie: *mut usize) -> c_uint {
        LIFECYCLE.mark_closing();
        0
    }

    /// Called by the dynamic linker when the link map reaches a consistent state.
    /// LA_ACT_CONSISTENT (1) fires after dlmopen completes all relocations.
    #[no_mangle]
    pub extern "C" fn la_activity(_cookie: *mut usize, flag: c_uint) {
        const LA_ACT_CONSISTENT: c_uint = 1;
        if flag != LA_ACT_CONSISTENT || !LIFECYCLE.has_reached_ready_for_heavy_init() {
            return;
        }
        let steamclient_seen = STEAM_MODULES.steamclient_seen();
        let steamui_seen = STEAM_MODULES.steamui_seen();

        use vapor_forge_hooks::{
            ensure_runtime_initialized, install_hook_batch, is_hook_batch_finished, HookBatch,
        };

        if (steamclient_seen || steamui_seen) && !ensure_runtime_initialized() {
            log_early("la_activity: runtime initialization rejected; hooks disabled");
            return;
        }
        if steamclient_seen {
            install_hook_batch(HookBatch::SteamClient);
        }
        if steamui_seen {
            install_hook_batch(HookBatch::SteamUi);
        }

        let steamclient_finished =
            !steamclient_seen || is_hook_batch_finished(HookBatch::SteamClient);
        let steamui_finished = !steamui_seen || is_hook_batch_finished(HookBatch::SteamUi);
        if (steamclient_seen || steamui_seen) && steamclient_finished && steamui_finished {
            vapor_forge_hooks::restore_trampoline_pages_rx();
        }
    }

    fn clear_audit_env_for_steam() {
        // SAFETY: AT_EXECFN points to a loader-owned NUL-terminated string for
        // the lifetime of the process.
        let executable = unsafe {
            bounded_cstr_to_string(libc::getauxval(libc::AT_EXECFN) as *const c_char, 4096)
        };
        if !executable.as_deref().is_some_and(is_steam_executable_path) {
            return;
        }

        // SAFETY: la_preinit runs before the executable's main function. The
        // audit module is already loaded, so removing the variable only stops
        // child processes from inheriting it.
        if unsafe { libc::unsetenv(c"LD_AUDIT".as_ptr()) } == 0 {
            log_early("la_preinit: cleared inherited LD_AUDIT");
        } else {
            log_early("la_preinit: failed to clear inherited LD_AUDIT");
        }
    }

    fn is_steam_executable_path(path: &str) -> bool {
        path.rsplit('/').next() == Some("steam")
    }

    unsafe fn bounded_cstr_to_string(ptr: *const c_char, max_len: usize) -> Option<String> {
        if ptr.is_null() {
            return None;
        }

        let mut len = 0usize;
        while len < max_len {
            // SAFETY: Caller provides a loader-owned C string pointer. Reads are
            // bounded so this helper does not walk arbitrary memory forever.
            let byte = unsafe { *ptr.add(len).cast::<u8>() };
            if byte == 0 {
                break;
            }
            len += 1;
        }

        if len == 0 || len == max_len {
            return None;
        }

        // SAFETY: The byte range was checked above up to the first NUL byte.
        let bytes = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    #[cfg(test)]
    mod tests {
        use super::is_steam_executable_path;

        #[test]
        fn identifies_the_steam_client_executable() {
            assert!(is_steam_executable_path(
                "/home/deck/.local/share/Steam/ubuntu12_32/steam"
            ));
            assert!(is_steam_executable_path("steam"));
            assert!(!is_steam_executable_path("/usr/bin/steam.sh"));
            assert!(!is_steam_executable_path("/usr/bin/steamwebhelper"));
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod host_stub {
    #[allow(dead_code)]
    pub fn audit_loader_host_stub() {}
}
