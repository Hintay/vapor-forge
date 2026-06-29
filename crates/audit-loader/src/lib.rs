#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use once_cell::sync::Lazy;
use std::sync::atomic::AtomicU8;
use std::sync::Once;
use steam_runtime_core::{Lifecycle, SteamModuleState};

static LIFECYCLE: Lazy<Lifecycle> = Lazy::new(Lifecycle::new);
static STEAMCLIENT_ELF_METADATA_PROBE: Once = Once::new();
static STEAMCLIENT_MAPPED_BYTE_SAMPLE_PROBE: Once = Once::new();
static STEAM_MODULES: Lazy<SteamModuleState> = Lazy::new(SteamModuleState::new);
static STEAMUI_ELF_METADATA_PROBE: Once = Once::new();
static STEAMUI_MAPPED_BYTE_SAMPLE_PROBE: Once = Once::new();
static POST_TARGET_SNAPSHOT_ATTEMPTS: AtomicU8 = AtomicU8::new(0);

const MAX_POST_TARGET_SNAPSHOT_ATTEMPTS: u8 = 3;

#[cfg(target_os = "linux")]
mod linux_audit {
    use core::ffi::{c_char, c_uint, c_void};
    use std::sync::atomic::Ordering;

    use steam_runtime_diagnostics::{log_cstr, log_message};
    use steam_runtime_memory::{
        current_process_context, find_proc_self_maps_targets, is_steam_target_name,
        sample_mapped_target_module_bytes, summarize_elf_file, summarize_proc_maps_targets,
        ElfMetadataLimits, MappedByteSamplingLimits, MappedByteSamplingReport, ProcMapsEntry,
    };

    use super::{
        LIFECYCLE, MAX_POST_TARGET_SNAPSHOT_ATTEMPTS, POST_TARGET_SNAPSHOT_ATTEMPTS,
        STEAMCLIENT_ELF_METADATA_PROBE, STEAMCLIENT_MAPPED_BYTE_SAMPLE_PROBE,
        STEAMUI_ELF_METADATA_PROBE, STEAMUI_MAPPED_BYTE_SAMPLE_PROBE, STEAM_MODULES,
    };

    // glibc's current audit interface version. Keep this local so the crate can
    // still be checked on hosts whose libc bindings do not expose LAV_CURRENT.
    const LAV_CURRENT: c_uint = 2;
    const MAX_PROC_MAPS_TARGET_ENTRIES: usize = 8;

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
        log_message("la_version");

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
        // SAFETY: glibc passes a valid C string for the object name during the
        // audit callback. diagnostics caps the number of bytes read.
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
            log_message("la_objopen: <null link_map>");
        } else {
            let map = map.cast::<LinkMap>();
            // SAFETY: glibc calls la_objopen with a valid link_map pointer for
            // the object being opened. We only read l_name for bounded logging.
            let name = unsafe { (*map).l_name };
            // SAFETY: link_map.l_name is a loader-owned C string. diagnostics
            // caps the number of bytes read.
            unsafe { log_cstr("la_objopen", name) };

            // SAFETY: link_map.l_name is owned by the dynamic loader during
            // this callback. The helper caps reads to avoid unbounded walks.
            let module_name = unsafe { bounded_cstr_to_string(name, 4096) };
            if module_name.as_deref().is_some_and(is_steam_target_name) {
                log_message("phase2a: observed Steam target module via la_objopen");
            }
            let target_kind = module_name
                .as_deref()
                .and_then(|module_name| STEAM_MODULES.mark_seen_by_name(module_name));

            if let Some(kind) = target_kind {
                log_message(&format!(
                    "phase2b: marked target module seen via la_objopen: {}",
                    kind.as_str()
                ));
                log_phase3_loader_target_event("la_objopen-target", kind.as_str());
                maybe_log_post_target_snapshot("la_objopen-target");
            } else {
                maybe_log_post_target_snapshot("la_objopen-followup");
            }
        }

        // Phase 1 observes lifecycle only. Returning zero avoids requesting
        // symbol binding callbacks before the hook boundary is designed.
        0
    }

    #[no_mangle]
    pub extern "C" fn la_preinit(_cookie: *mut usize) {
        LIFECYCLE.mark_ready_for_heavy_init();
        log_message("la_preinit: ready for deferred heavy init");
        maybe_log_post_target_snapshot("la_preinit-ready");
    }

    #[no_mangle]
    pub unsafe extern "C" fn la_objclose(_cookie: *mut usize) -> c_uint {
        LIFECYCLE.mark_closing();
        log_message("la_objclose: mark closing only");
        0
    }

    fn maybe_log_post_target_snapshot(reason: &str) {
        if !STEAM_MODULES.any_seen() || !LIFECYCLE.has_reached_ready_for_heavy_init() {
            return;
        }

        let attempt = POST_TARGET_SNAPSHOT_ATTEMPTS.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| (current < MAX_POST_TARGET_SNAPSHOT_ATTEMPTS).then_some(current + 1),
        );

        let attempt = match attempt {
            Ok(previous) => previous + 1,
            Err(_) => return,
        };

        match find_proc_self_maps_targets(MAX_PROC_MAPS_TARGET_ENTRIES) {
            Ok(entries) => {
                let context = current_process_context();
                log_message(&format!(
                    "phase2b: post-target snapshot begin attempt={} reason={} pid={} ppid={} arch={} exe={} proc_maps_target_count={}",
                    attempt,
                    reason,
                    context.pid,
                    format_optional_u32(context.ppid),
                    context.arch,
                    context.exe.as_deref().unwrap_or("<unknown>"),
                    entries.len()
                ));
                log_phase3_proc_maps_entries(reason, &entries);
                log_phase4b_visible_elf_metadata(reason);
                log_trackc_visible_mapped_byte_samples(reason);
                let target_count = entries.len();
                for entry in &entries {
                    log_message(&format!(
                        "phase2b: target module base=0x{:x} end=0x{:x} size=0x{:x} perms={} path={}",
                        entry.range.base.0,
                        entry.range.end.0,
                        entry.range.size,
                        entry.permissions,
                        entry.path
                    ));
                }
                if target_count == 0 {
                    log_message("phase2b: no target modules in post-target snapshot");
                }
                log_message(&format!(
                    "phase2b: post-target snapshot end attempt={} targets={}",
                    attempt, target_count
                ));
            }
            Err(error) => log_message(&format!(
                "phase2b: post-target snapshot failed attempt={attempt}: {error}"
            )),
        }
    }

    fn log_phase3_loader_target_event(reason: &str, target_name: &str) {
        let context = current_process_context();
        log_message(&format!(
            "phase3: loader target event reason={} pid={} ppid={} arch={} exe={} target={}",
            reason,
            context.pid,
            format_optional_u32(context.ppid),
            context.arch,
            context.exe.as_deref().unwrap_or("<unknown>"),
            target_name
        ));

        match find_proc_self_maps_targets(MAX_PROC_MAPS_TARGET_ENTRIES) {
            Ok(entries) => {
                log_message(&format!(
                    "phase3: loader target proc maps reason={} target={} proc_maps_target_count={}",
                    reason,
                    target_name,
                    entries.len()
                ));
                log_phase3_proc_maps_entries(reason, &entries);
                log_phase4a_proc_maps_inventory(reason, &entries);
                log_phase4b_target_elf_metadata(reason, target_name, &entries);
                if LIFECYCLE.has_reached_ready_for_heavy_init() {
                    log_trackc_target_mapped_byte_sample_once(reason, target_name, &entries);
                }
            }
            Err(error) => log_message(&format!(
                "phase3: loader target proc maps failed reason={} target={} error={}",
                reason, target_name, error
            )),
        }
    }

    fn log_phase3_proc_maps_entries(reason: &str, entries: &[ProcMapsEntry]) {
        for entry in entries {
            log_message(&format!(
                "phase3: proc maps target reason={} base=0x{:x} end=0x{:x} size=0x{:x} perms={} path={}",
                reason,
                entry.range.base.0,
                entry.range.end.0,
                entry.range.size,
                entry.permissions,
                entry.path
            ));
        }
    }

    fn log_phase4a_proc_maps_inventory(reason: &str, entries: &[ProcMapsEntry]) {
        let context = current_process_context();
        let summaries = summarize_proc_maps_targets(entries);

        log_message(&format!(
            "phase4a: proc maps inventory reason={} pid={} ppid={} arch={} exe={} module_count={}",
            reason,
            context.pid,
            format_optional_u32(context.ppid),
            context.arch,
            context.exe.as_deref().unwrap_or("<unknown>"),
            summaries.len()
        ));

        for summary in summaries {
            log_message(&format!(
                "phase4a: module reason={} name={} path={} entries={} base=0x{:x} end=0x{:x} size=0x{:x} perms={}",
                reason,
                summary.name,
                summary.path,
                summary.entry_count,
                summary.range.base.0,
                summary.range.end.0,
                summary.range.size,
                summary.permissions
            ));
        }
    }

    fn log_phase4b_visible_elf_metadata(reason: &str) {
        let context = current_process_context();
        match find_proc_self_maps_targets(MAX_PROC_MAPS_TARGET_ENTRIES) {
            Ok(entries) => {
                let summaries = summarize_proc_maps_targets(&entries);
                log_message(&format!(
                    "phase4b: elf metadata begin reason={} pid={} ppid={} arch={} exe={} module_count={}",
                    reason,
                    context.pid,
                    format_optional_u32(context.ppid),
                    context.arch,
                    context.exe.as_deref().unwrap_or("<unknown>"),
                    summaries.len()
                ));

                let limits = ElfMetadataLimits::default();
                for summary in summaries {
                    log_phase4b_elf_metadata_once(reason, &summary, limits);
                }
                log_message(&format!("phase4b: elf metadata end reason={reason}"));
            }
            Err(error) => log_message(&format!(
                "phase4b: elf metadata proc maps failed reason={} pid={} ppid={} arch={} exe={} error={}",
                reason,
                context.pid,
                format_optional_u32(context.ppid),
                context.arch,
                context.exe.as_deref().unwrap_or("<unknown>"),
                error
            )),
        }
    }

    fn log_phase4b_target_elf_metadata(reason: &str, target_name: &str, entries: &[ProcMapsEntry]) {
        let summaries = summarize_proc_maps_targets(entries);
        let Some(summary) = summaries
            .into_iter()
            .find(|summary| summary.name == target_name)
        else {
            return;
        };

        log_message(&format!(
            "phase4b: elf metadata begin reason={} target={} module_count=1",
            reason, target_name
        ));
        log_phase4b_elf_metadata_once(reason, &summary, ElfMetadataLimits::default());
        log_message(&format!("phase4b: elf metadata end reason={reason}"));
    }

    fn log_phase4b_elf_metadata_once(
        reason: &str,
        summary: &steam_runtime_memory::ProcMapsModuleInventory,
        limits: ElfMetadataLimits,
    ) {
        match summary.name.as_str() {
            "steamclient.so" => STEAMCLIENT_ELF_METADATA_PROBE
                .call_once(|| log_phase4b_elf_metadata_summary(reason, summary, limits)),
            "steamui.so" => STEAMUI_ELF_METADATA_PROBE
                .call_once(|| log_phase4b_elf_metadata_summary(reason, summary, limits)),
            _ => {}
        }
    }

    fn log_phase4b_elf_metadata_summary(
        reason: &str,
        summary: &steam_runtime_memory::ProcMapsModuleInventory,
        limits: ElfMetadataLimits,
    ) {
        match summarize_elf_file(&summary.path, limits) {
            Ok(metadata) => {
                log_message(&format!(
                    "phase4b: elf metadata reason={} name={} path={} file_size={} kind={} class={} endian={} arch={} segments={} sections={} dynsym_count={} dynsym_names={} dynsym_truncated={} build_id={} gnu_hash={} sysv_hash={}",
                    reason,
                    metadata.name,
                    metadata.path,
                    metadata.file_size,
                    metadata.file_kind,
                    metadata.elf_class,
                    metadata.endian,
                    metadata.architecture,
                    metadata.segment_count,
                    metadata.section_count,
                    metadata.dynamic_symbol_count,
                    metadata.dynamic_symbol_names.len(),
                    metadata.dynamic_symbol_names_truncated,
                    metadata.build_id.as_deref().unwrap_or("none"),
                    metadata.gnu_hash_present,
                    metadata.sysv_hash_present
                ));
                for symbol_name in metadata.dynamic_symbol_names {
                    log_message(&format!(
                        "phase4b: dynsym reason={} module={} symbol={}",
                        reason, metadata.name, symbol_name
                    ));
                }
            }
            Err(error) => log_message(&format!(
                "phase4b: elf metadata failed reason={} name={} path={} error={}",
                reason, summary.name, summary.path, error
            )),
        }
    }

    fn log_trackc_visible_mapped_byte_samples(reason: &str) {
        if current_process_context().arch != "x86" {
            log_message(&format!(
                "trackc: mapped-byte sampling skipped reason={} detail=unsupported-arch",
                reason
            ));
            return;
        }

        match find_proc_self_maps_targets(MAX_PROC_MAPS_TARGET_ENTRIES) {
            Ok(entries) => {
                log_trackc_target_mapped_byte_sample_once(reason, "steamui.so", &entries);
                log_trackc_target_mapped_byte_sample_once(reason, "steamclient.so", &entries);
            }
            Err(error) => log_message(&format!(
                "trackc: mapped-byte sampling proc maps failed reason={} error={}",
                reason, error
            )),
        }
    }

    fn log_trackc_target_mapped_byte_sample_once(
        reason: &str,
        target_name: &str,
        entries: &[ProcMapsEntry],
    ) {
        if !entries.iter().any(|entry| {
            entry.path.rsplit('/').next() == Some(target_name) || entry.path == target_name
        }) {
            log_message(&format!(
                "trackc: mapped-byte sampling skipped reason={} target={} detail=no-target-mapping",
                reason, target_name
            ));
            return;
        }

        match target_name {
            "steamclient.so" => STEAMCLIENT_MAPPED_BYTE_SAMPLE_PROBE
                .call_once(|| log_trackc_target_mapped_byte_sample(reason, target_name, entries)),
            "steamui.so" => STEAMUI_MAPPED_BYTE_SAMPLE_PROBE
                .call_once(|| log_trackc_target_mapped_byte_sample(reason, target_name, entries)),
            _ => {}
        }
    }

    fn log_trackc_target_mapped_byte_sample(
        reason: &str,
        target_name: &str,
        entries: &[ProcMapsEntry],
    ) {
        log_message(&format!(
            "trackc: mapped-byte sampling begin reason={} target={}",
            reason, target_name
        ));

        // SAFETY: The entries come from the current process immediately before this call. The
        // memory crate revalidates target name, readable permissions, arithmetic, and containment
        // before copying bounded bytes, and only emits digest/structural results.
        let report = unsafe {
            sample_mapped_target_module_bytes(
                entries,
                target_name,
                MappedByteSamplingLimits::default(),
            )
        };

        log_trackc_mapped_byte_report(reason, &report);
        log_message(&format!(
            "trackc: mapped-byte sampling end reason={} target={} total_sampled_bytes={}",
            reason, target_name, report.total_sampled_bytes
        ));
    }

    fn log_trackc_mapped_byte_report(reason: &str, report: &MappedByteSamplingReport) {
        for sample in &report.samples {
            log_message(&format!(
                "trackc: sample reason={} module={} kind={} symbol={} requested_len={} digest={} matches_elf_magic={} path={}",
                reason,
                sample.module_name,
                sample.kind,
                sample.symbol.as_deref().unwrap_or("none"),
                sample.requested_len,
                sample.digest,
                format_optional_bool(sample.matches_elf_magic),
                sample.path
            ));
        }

        for skip in &report.skips {
            log_message(&format!(
                "trackc: sample skipped reason={} module={} kind={} detail={} path={}",
                reason, skip.module_name, skip.kind, skip.detail, skip.path
            ));
        }
    }

    fn format_optional_u32(value: Option<u32>) -> String {
        value
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned())
    }

    fn format_optional_bool(value: Option<bool>) -> String {
        value
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned())
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
}

#[cfg(not(target_os = "linux"))]
mod host_stub {
    #[allow(dead_code)]
    pub fn audit_loader_host_stub() {}
}
