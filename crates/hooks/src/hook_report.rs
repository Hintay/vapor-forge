#![forbid(unsafe_code)]

use std::sync::Mutex;

#[cfg(target_os = "linux")]
use tracing::{debug, info};

pub(crate) struct HookResult {
    pub(crate) name: &'static str,
    pub(crate) installed: bool,
    pub(crate) addr: usize,
}

// ---------------------------------------------------------------------------
// Stored results for cross-module queries (e.g. debug API)
// ---------------------------------------------------------------------------

/// Lightweight copy of HookResult for cross-module queries.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(crate) struct StoredHook {
    pub(crate) name: &'static str,
    pub(crate) installed: bool,
    pub(crate) addr: usize,
}

/// Per-module storage entry.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(crate) struct ModuleResults {
    pub(crate) module: &'static str,
    pub(crate) hooks: Vec<StoredHook>,
}

static STORED_RESULTS: Mutex<Vec<ModuleResults>> = Mutex::new(Vec::new());

/// Persist hook results for a module so they can be queried later
/// (e.g. by the debug API). Safe to call for multiple modules.
pub(crate) fn store_results(module: &'static str, results: &[HookResult]) {
    let entry = ModuleResults {
        module,
        hooks: results
            .iter()
            .map(|r| StoredHook {
                name: r.name,
                installed: r.installed,
                addr: r.addr,
            })
            .collect(),
    };
    if let Ok(mut guard) = STORED_RESULTS.lock() {
        guard.push(entry);
    }
}

/// Access stored results. The callback receives a slice of all module results.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(crate) fn with_stored_results<R>(f: impl FnOnce(&[ModuleResults]) -> R) -> R {
    let guard = STORED_RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    f(&guard)
}

#[cfg(test)]
pub(crate) fn clear_stored_results() {
    STORED_RESULTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
