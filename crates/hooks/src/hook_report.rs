use tracing::{debug, info};

pub(crate) struct HookResult {
    pub(crate) name: &'static str,
    pub(crate) installed: bool,
    pub(crate) addr: usize,
}

pub(crate) fn log_drift_summary(module_name: &str, hook_results: &[HookResult]) {
    let entries = match vapor_forge_memory::find_proc_self_maps_targets(16) {
        Ok(e) => e,
        Err(_) => return,
    };
    if let Some(entry) = entries
        .iter()
        .find(|e| e.path.ends_with(&format!("/{module_name}")))
    {
        let build_id = vapor_forge_memory::summarize_elf_file(
            &entry.path,
            vapor_forge_memory::ElfMetadataLimits::default(),
        )
        .ok()
        .and_then(|m| m.build_id);
        info!(
            module = module_name,
            build_id = build_id.as_deref().unwrap_or("unknown"),
            base = format_args!("0x{:x}", entry.range.base.0),
            "Diagnostics: module"
        );
    }

    let found = hook_results.iter().filter(|r| r.installed).count();
    let missing = hook_results.len() - found;
    info!(
        module = module_name,
        found = found,
        missing = missing,
        total = hook_results.len(),
        "Diagnostics: pattern summary"
    );

    for r in hook_results.iter().filter(|r| !r.installed) {
        info!(
            module = module_name,
            hook = r.name,
            "Diagnostics: pattern missing"
        );
    }
}

pub(crate) fn log_hook_details(module_name: &str, hook_results: &[HookResult]) {
    for r in hook_results {
        debug!(
            module = module_name,
            hook = r.name,
            installed = r.installed,
            addr = format_args!("0x{:x}", r.addr),
            "Diagnostics: hook detail"
        );
    }
}
