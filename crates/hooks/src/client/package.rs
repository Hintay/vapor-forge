use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tracing::{debug, error, info, warn};
use vapor_forge_abi::{
    package_info, CUtlMemoryGrowFn, GetPackageInfoArchFn, MarkLicenseAsChangedFn,
    ProcessPendingLicenseUpdatesFn,
};
use vapor_forge_config::AppId;
use vapor_forge_features::package::ReloadDiff;
use vapor_forge_patterns::registry::PatternRegistry;

use crate::detour::CodeRegion;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Access token for pkg0.
pub const PKG0_ACCESS_TOKEN: u64 = 10660652434190618804;

/// Batch grow size for CUtlMemory reallocation.
const GROW_BATCH: i32 = 16;

/// PackageInfo::status value for Available.
const PKG_STATUS_AVAILABLE: u32 = 0;

// ---------------------------------------------------------------------------
// Static state for raw function pointers resolved via pattern matching
// ---------------------------------------------------------------------------

static mut FN_MARK_LICENSE: Option<MarkLicenseAsChangedFn> = None;
static mut FN_PROCESS_UPDATES: Option<ProcessPendingLicenseUpdatesFn> = None;
static mut FN_GROW: Option<CUtlMemoryGrowFn> = None;
static mut FN_GET_PKG_INFO: Option<GetPackageInfoArchFn> = None;

/// Captured IClientUser `this` pointer from CheckAppOwnership.
pub(crate) static CUSER_PTR: AtomicUsize = AtomicUsize::new(0);

/// Captured package helper `this` pointer.
pub(crate) static CPKG_INFO_PTR: AtomicUsize = AtomicUsize::new(0);

/// Captured pkg0 PackageInfo pointer.
pub(crate) static PKG0_PTR: AtomicUsize = AtomicUsize::new(0);

/// Flag: watcher thread did CUtlVector mutation, Steam thread needs to markAndProcess.
static PENDING_MARK: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Resolution called from install::do_install
// ---------------------------------------------------------------------------

/// Resolve all 4 function addresses needed for pkg0 injection.
/// Not hooks. These are just address resolutions via pattern matching and are called directly.
pub fn resolve_functions(code: &CodeRegion, registry: &PatternRegistry) {
    let _ = resolve_from_registry_raw(
        registry,
        code,
        "CUser::MarkLicenseAsChanged",
        std::ptr::addr_of_mut!(FN_MARK_LICENSE),
    );
    let _ = resolve_from_registry_raw(
        registry,
        code,
        "CUser::ProcessPendingLicenseUpdates",
        std::ptr::addr_of_mut!(FN_PROCESS_UPDATES),
    );
    // x86_64 resolves this through the CUtlVector<u32> append helper callsite used
    // by pkg0's app-id list. The shared Grow body has several nearby variants and
    // RIP-relative selector strings, so following the typed callsite is the more
    // stable callable entry.
    let _ = resolve_from_registry_raw(
        registry,
        code,
        "CUtlMemory::Grow",
        std::ptr::addr_of_mut!(FN_GROW),
    );
    let _ = resolve_from_registry_raw(
        registry,
        code,
        "CPackageInfo::GetPackageInfo",
        std::ptr::addr_of_mut!(FN_GET_PKG_INFO),
    );
}

/// Resolve a function address from the registry and store it as a raw fn pointer.
fn resolve_from_registry_raw<F: Copy>(
    registry: &PatternRegistry,
    code: &CodeRegion,
    name: &str,
    storage: *mut Option<F>,
) -> Option<usize> {
    let entry = match registry.get(name) {
        Some(e) => e,
        None => {
            warn!(hook = name, "pattern not found in registry");
            return None;
        }
    };

    let addr = match crate::detour::resolve_pattern_entry(code, name, &entry) {
        Some(a) => a,
        None => return None,
    };

    // SAFETY: transmuting validated code address to typed fn pointer.
    unsafe {
        storage.write(Some(std::mem::transmute_copy(&addr)));
    }
    Some(addr)
}

/// Get the resolved GetPackageInfo function address (for hooking).
pub fn get_package_info_addr() -> Option<usize> {
    // SAFETY: FN_GET_PKG_INFO written once during init, read-only after.
    unsafe { (*std::ptr::addr_of!(FN_GET_PKG_INFO)).map(|f| f as usize) }
}

pub(crate) fn capture_pkg_info_this(this: *mut c_void) {
    if CPKG_INFO_PTR.load(Ordering::Acquire) == 0 {
        CPKG_INFO_PTR.store(this as usize, Ordering::Release);
        info!(
            "package: captured package helper this at 0x{:x}",
            this as usize
        );
    }
}

pub(crate) fn try_capture_pkg0_from_package_info(this: *mut c_void) {
    if PKG0_PTR.load(Ordering::Acquire) != 0 {
        return;
    }

    capture_pkg_info_this(this);
    let Some(pkg_ptr) = query_pkg0(this) else {
        return;
    };
    capture_validated_pkg0(pkg_ptr);
}

fn query_pkg0(this: *mut c_void) -> Option<*mut u8> {
    let get_pkg = match unsafe { *std::ptr::addr_of!(FN_GET_PKG_INFO) } {
        Some(f) => f,
        None => return None,
    };

    // The package lookup has different ABI surfaces per architecture. 32-bit
    // receives (package_id, access_token), while Linux x86_64 receives a pointer
    // to the package token key and searches the token-keyed package map.
    #[cfg(target_pointer_width = "64")]
    let pkg_ptr = get_pkg(this, &PKG0_ACCESS_TOKEN);
    #[cfg(target_pointer_width = "32")]
    let pkg_ptr = get_pkg(this, 0, PKG0_ACCESS_TOKEN);

    if pkg_ptr.is_null() {
        debug!("package: GetPackageInfo(pkg0 token) returned null");
        None
    } else {
        Some(pkg_ptr)
    }
}

/// Check whether all required functions are resolved.
pub fn all_functions_resolved() -> bool {
    // SAFETY: these are only written once during do_install, read-only after.
    unsafe {
        let common = (*std::ptr::addr_of!(FN_MARK_LICENSE)).is_some()
            && (*std::ptr::addr_of!(FN_PROCESS_UPDATES)).is_some()
            && (*std::ptr::addr_of!(FN_GROW)).is_some();

        common && (*std::ptr::addr_of!(FN_GET_PKG_INFO)).is_some()
    }
}

// ---------------------------------------------------------------------------
// Pkg0 capture called from hk_check_app_ownership
// ---------------------------------------------------------------------------

/// Attempt to capture pkg0. Called from the CheckAppOwnership hook.
///
/// # Safety
/// `cuser` must be a valid IClientUser pointer from Steam.
pub unsafe fn try_capture_pkg0(cuser: *mut c_void) {
    // Store cuser (first time only)
    if CUSER_PTR.load(Ordering::Acquire) == 0 {
        CUSER_PTR.store(cuser as usize, Ordering::Release);
        debug!("package: captured IClientUser at 0x{:x}", cuser as usize);
    }

    // Already captured?
    if PKG0_PTR.load(Ordering::Acquire) != 0 {
        return;
    }

    let cpkg = CPKG_INFO_PTR.load(Ordering::Acquire);
    if cpkg != 0 {
        try_capture_pkg0_from_package_info(cpkg as *mut c_void);
    }
}

// ---------------------------------------------------------------------------
// Injection called once after pkg0 is captured
// ---------------------------------------------------------------------------

/// Inject app IDs into pkg0 and trigger license re-evaluation.
///
/// Dedup: remove an existing app id before appending it to the injected package.
///
/// # Safety
/// Must only be called after pkg0 and cuser are captured, and all function
/// pointers are resolved.
pub unsafe fn try_inject_once(app_ids: &[AppId]) {
    let pkg0 = PKG0_PTR.load(Ordering::Acquire);
    if pkg0 == 0 {
        return;
    }
    let cuser = CUSER_PTR.load(Ordering::Acquire);
    if cuser == 0 {
        return;
    }

    if app_ids.is_empty() {
        debug!("package: no apps to inject");
        return;
    }

    // SAFETY: pkg0 is a validated PackageInfo pointer.
    let vec = unsafe { &mut *package_info::app_id_vec(pkg0 as *mut u8) };

    let mut injected = 0u32;
    for &app_id in app_ids {
        let raw_id = app_id.0;
        // Dedup: remove first, then append
        vec.find_and_fast_remove(&raw_id);
        if append_growing(vec, raw_id) {
            injected += 1;
        } else {
            error!(app_id = raw_id, "package: failed to append (grow failed)");
        }
    }

    if injected > 0 {
        mark_and_process(cuser);
        info!(
            injected = injected,
            total = app_ids.len(),
            "package: pkg0 injection complete"
        );
    }
}

// ---------------------------------------------------------------------------
// Hot-reload diff application
// ---------------------------------------------------------------------------

/// Apply a hot-reload diff to pkg0.
///
/// # Safety
/// Must only be called when pkg0 and cuser are captured, and all function
/// pointers are resolved.
pub unsafe fn apply_reload_diff(diff: &ReloadDiff) {
    let pkg0 = PKG0_PTR.load(Ordering::Acquire);
    if pkg0 == 0 {
        debug!("package: reload diff skipped — pkg0 not captured");
        return;
    }
    let cuser = CUSER_PTR.load(Ordering::Acquire);
    if cuser == 0 {
        return;
    }

    if diff.additions.is_empty() && diff.removals.is_empty() {
        return;
    }

    // SAFETY: pkg0 is a validated PackageInfo pointer.
    let vec = unsafe { &mut *package_info::app_id_vec(pkg0 as *mut u8) };
    let mut changed = false;

    // Removals: remove from pkg0 and queue UI removal for the UI thread.
    for &app_id in &diff.removals {
        let raw_id = app_id.0;
        if vec.find_and_fast_remove(&raw_id) {
            debug!(app_id = raw_id, "package: removed from pkg0");
            crate::ui::install::queue_removal(app_id);
            changed = true;
        }
    }

    // Additions: skip if already present (prevents Cloud "out of date" badge)
    for &app_id in &diff.additions {
        let raw_id = app_id.0;
        if vec.contains(&raw_id) {
            debug!(app_id = raw_id, "package: already in pkg0, skipping");
            continue;
        }
        if append_growing(vec, raw_id) {
            debug!(app_id = raw_id, "package: added to pkg0");
            changed = true;
        } else {
            error!(app_id = raw_id, "package: failed to append on reload");
        }
    }

    if changed {
        PENDING_MARK.store(true, Ordering::Release);
        info!(
            additions = diff.additions.len(),
            removals = diff.removals.len(),
            "package: reload mutation done, pending markAndProcess on Steam thread"
        );
    }
}

// ---------------------------------------------------------------------------
// Pump called from Steam thread (CheckAppOwnership hook)
// ---------------------------------------------------------------------------

/// Drain pending markAndProcess. Call from a Steam-thread hook callback.
pub fn pump_mark_and_process() {
    if !PENDING_MARK.swap(false, Ordering::AcqRel) {
        return;
    }
    let cuser = CUSER_PTR.load(Ordering::Acquire);
    if cuser == 0 {
        return;
    }
    mark_and_process(cuser);
    info!("package: pumped markAndProcess on Steam thread");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

pub(crate) fn capture_validated_pkg0(pkg_ptr: *mut u8) {
    if pkg_ptr.is_null() {
        return;
    }

    // SAFETY: caller found pkg_ptr through Steam's package structures.
    let package_id = unsafe { package_info::package_id(pkg_ptr) };
    if package_id != 0 {
        warn!(
            package_id = package_id,
            "package: token lookup did not return pkg0, skipping"
        );
        return;
    }

    // SAFETY: caller found pkg_ptr through Steam's package structures.
    let status = unsafe { package_info::status(pkg_ptr) };
    if status != PKG_STATUS_AVAILABLE {
        warn!(
            status = status,
            "package: pkg0 status != Available, skipping"
        );
        return;
    }

    PKG0_PTR.store(pkg_ptr as usize, Ordering::Release);
    info!("package: captured pkg0 at 0x{:x}", pkg_ptr as usize);
}

/// Append a value to a CUtlVector<u32>, growing the backing CUtlMemory if needed.
fn append_growing(vec: &mut vapor_forge_abi::CUtlVector<u32>, value: u32) -> bool {
    if vec.try_append(value) {
        return true;
    }

    // Need to grow by calling Steam's CUtlMemory::Grow.
    // SAFETY: FN_GROW written once during init, read-only after.
    let grow_fn = match unsafe { *std::ptr::addr_of!(FN_GROW) } {
        Some(f) => f,
        None => {
            error!("package: CUtlMemoryGrow not resolved");
            return false;
        }
    };

    // SAFETY: growing Steam's CUtlMemory via its own internal function.
    grow_fn(
        &mut vec.m_memory as *mut vapor_forge_abi::CUtlMemory<u32> as *mut c_void,
        GROW_BATCH,
    );

    vec.try_append(value)
}

/// Call MarkLicenseAsChanged(cuser, 0, true) + ProcessPendingLicenseUpdates(cuser).
fn mark_and_process(cuser: usize) {
    // SAFETY: FN_MARK_LICENSE and FN_PROCESS_UPDATES written once during init.
    let mark_fn = match unsafe { *std::ptr::addr_of!(FN_MARK_LICENSE) } {
        Some(f) => f,
        None => {
            error!("package: MarkLicenseAsChanged not resolved");
            return;
        }
    };
    let process_fn = match unsafe { *std::ptr::addr_of!(FN_PROCESS_UPDATES) } {
        Some(f) => f,
        None => {
            error!("package: ProcessPendingLicenseUpdates not resolved");
            return;
        }
    };

    // SAFETY: calling Steam functions with validated cuser pointer.
    mark_fn(cuser as *mut c_void, 0, true);
    process_fn(cuser as *mut c_void);
    debug!("package: mark + process called");
}
