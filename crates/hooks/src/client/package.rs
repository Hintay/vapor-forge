use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use tracing::{debug, error, info, warn};
use vapor_forge_config::AppId;
use vapor_forge_features::package::ReloadDiff;
use vapor_forge_patterns::registry::PatternRegistry;
use vapor_forge_steam_native_abi::{
    package_info, CUtlMemoryGrowFn, GetPackageInfoArchFn, MarkLicenseAsChangedFn,
    ProcessPendingLicenseUpdatesFn,
};

use crate::pattern_resolver::CodeRegion;

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
static CUSER_PTR: AtomicUsize = AtomicUsize::new(0);

/// Captured package helper `this` pointer.
static CPKG_INFO_PTR: AtomicUsize = AtomicUsize::new(0);

/// Captured pkg0 PackageInfo pointer.
static PKG0_PTR: AtomicUsize = AtomicUsize::new(0);

/// Latest desired controlled-app set. The watcher only replaces this queue;
/// Steam-owned memory is mutated by `pump_reload` on a Steam hook thread.
static PENDING_RELOAD: Mutex<Option<Vec<AppId>>> = Mutex::new(None);

/// Proof that package operations are executing inside the live
/// `CheckAppOwnership` callback on Steam's thread.
pub(crate) struct SteamPackageHookScope {
    _private: (),
}

impl SteamPackageHookScope {
    /// # Safety
    /// Must only be called for the dynamic extent of Steam's
    /// `CheckAppOwnership` callback.
    pub(crate) unsafe fn enter() -> Self {
        Self { _private: () }
    }
}

pub(crate) struct SteamPackageAccess<'hook> {
    pkg0: NonNull<u8>,
    cuser: NonNull<c_void>,
    mark_license: MarkLicenseAsChangedFn,
    process_updates: ProcessPendingLicenseUpdatesFn,
    grow: CUtlMemoryGrowFn,
    _scope: PhantomData<&'hook mut SteamPackageHookScope>,
}

impl<'hook> SteamPackageAccess<'hook> {
    pub(crate) fn from_hook(_scope: &'hook mut SteamPackageHookScope) -> Option<Self> {
        let pkg0 = NonNull::new(PKG0_PTR.load(Ordering::Acquire) as *mut u8)?;
        let cuser = NonNull::new(CUSER_PTR.load(Ordering::Acquire) as *mut c_void)?;
        // SAFETY: initialization writes each slot before hooks are enabled and
        // never mutates it afterward.
        let (mark_license, process_updates, grow) = unsafe {
            (
                (*std::ptr::addr_of!(FN_MARK_LICENSE))?,
                (*std::ptr::addr_of!(FN_PROCESS_UPDATES))?,
                (*std::ptr::addr_of!(FN_GROW))?,
            )
        };
        Some(Self {
            pkg0,
            cuser,
            mark_license,
            process_updates,
            grow,
            _scope: PhantomData,
        })
    }

    fn app_ids(&mut self) -> &mut vapor_forge_steam_native_abi::CUtlVector<u32> {
        // SAFETY: construction is restricted to the live Steam callback after
        // pkg0 validation, and the returned borrow cannot outlive this access.
        unsafe { &mut *package_info::app_id_vec(self.pkg0.as_ptr()) }
    }

    fn mark_and_process(&self) {
        // SAFETY: the capability holds the live callback's CUser and the
        // architecture-matched functions resolved before hook activation.
        unsafe {
            (self.mark_license)(self.cuser.as_ptr(), 0, false);
            (self.process_updates)(self.cuser.as_ptr());
        }
    }

    pub(crate) fn inject(&mut self, app_ids: &[AppId]) -> Vec<AppId> {
        if app_ids.is_empty() {
            debug!("package: no apps to inject");
            return Vec::new();
        }

        let mut injected = Vec::new();
        for &app_id in app_ids {
            let raw_id = app_id.0;
            // SAFETY: `app_ids` returns the validated pkg0 vector for this capability.
            if unsafe { self.app_ids().contains(&raw_id) } {
                continue;
            }
            if self.append(raw_id) {
                injected.push(app_id);
            } else {
                error!(app_id = raw_id, "package: failed to append (grow failed)");
            }
        }

        if !injected.is_empty() {
            self.mark_and_process();
            info!(
                injected = injected.len(),
                total = app_ids.len(),
                "package: pkg0 injection complete"
            );
        }
        injected
    }

    fn append(&mut self, value: u32) -> bool {
        // SAFETY: this capability owns the only mutable pkg0 access for the callback.
        if unsafe { self.app_ids().try_append(value) } {
            return true;
        }

        let grow = self.grow;
        let vec = self.app_ids();
        // SAFETY: `vec` is Steam's live CUtlVector and `grow` is the matching
        // CUtlMemory implementation resolved before hook activation.
        unsafe {
            grow(
                &mut vec.m_memory as *mut vapor_forge_steam_native_abi::CUtlMemory<u32>
                    as *mut c_void,
                GROW_BATCH,
            );
            vec.try_append(value)
        }
    }

    fn apply_reload_diff(&mut self, diff: &ReloadDiff) -> ReloadDiff {
        let mut applied = ReloadDiff {
            additions: Vec::new(),
            removals: Vec::new(),
        };

        for &app_id in &diff.removals {
            let raw_id = app_id.0;
            // SAFETY: the capability guarantees a live writable pkg0 vector.
            if unsafe { self.app_ids().find_and_fast_remove(&raw_id) } {
                debug!(app_id = raw_id, "package: removed from pkg0");
                crate::ui::install::queue_removal(app_id);
                applied.removals.push(app_id);
            }
        }

        for &app_id in &diff.additions {
            let raw_id = app_id.0;
            // SAFETY: the capability guarantees a live readable pkg0 vector.
            if unsafe { self.app_ids().contains(&raw_id) } {
                debug!(app_id = raw_id, "package: already in pkg0, skipping");
                continue;
            }
            if self.append(raw_id) {
                debug!(app_id = raw_id, "package: added to pkg0");
                applied.additions.push(app_id);
            } else {
                error!(app_id = raw_id, "package: failed to append on reload");
            }
        }

        if !applied.additions.is_empty() || !applied.removals.is_empty() {
            info!(
                additions = applied.additions.len(),
                removals = applied.removals.len(),
                "package: reload mutation applied on Steam thread"
            );
            self.mark_and_process();
        }
        applied
    }
}

// ---------------------------------------------------------------------------
// Resolution called from install::do_install
// ---------------------------------------------------------------------------

/// Resolve all 4 function addresses needed for pkg0 injection.
/// Not hooks. These are just address resolutions via pattern matching and are called directly.
/// # Safety
/// The registry must have been validated against `code` from the live
/// steamclient executable mapping.
pub unsafe fn resolve_functions(code: &CodeRegion, registry: &PatternRegistry) {
    if let Some(addr) = resolve_raw_address(registry, code, "CUser::MarkLicenseAsChanged") {
        // SAFETY: the registry entry identifies this concrete Steam function ABI.
        unsafe {
            std::ptr::addr_of_mut!(FN_MARK_LICENSE)
                .write(Some(std::mem::transmute::<usize, MarkLicenseAsChangedFn>(
                    addr,
                )));
        }
    }
    if let Some(addr) = resolve_raw_address(registry, code, "CUser::ProcessPendingLicenseUpdates") {
        // SAFETY: the registry entry identifies this concrete Steam function ABI.
        unsafe {
            std::ptr::addr_of_mut!(FN_PROCESS_UPDATES).write(Some(std::mem::transmute::<
                usize,
                ProcessPendingLicenseUpdatesFn,
            >(addr)));
        }
    }
    // x86_64 resolves this through the CUtlVector<u32> append helper callsite used
    // by pkg0's app-id list. The shared Grow body has several nearby variants and
    // RIP-relative selector strings, so following the typed callsite is the more
    // stable callable entry.
    if let Some(addr) = resolve_raw_address(registry, code, "CUtlMemory::Grow") {
        // SAFETY: the registry entry identifies this concrete Steam function ABI.
        unsafe {
            std::ptr::addr_of_mut!(FN_GROW)
                .write(Some(std::mem::transmute::<usize, CUtlMemoryGrowFn>(addr)));
        }
    }
    if let Some(addr) = resolve_raw_address(registry, code, "CPackageInfo::GetPackageInfo") {
        // SAFETY: the registry entry identifies this architecture-specific ABI.
        unsafe {
            std::ptr::addr_of_mut!(FN_GET_PKG_INFO)
                .write(Some(std::mem::transmute::<usize, GetPackageInfoArchFn>(
                    addr,
                )));
        }
    }
}

fn resolve_raw_address(registry: &PatternRegistry, code: &CodeRegion, name: &str) -> Option<usize> {
    let entry = match registry.get(name) {
        Some(e) => e,
        None => {
            warn!(hook = name, "pattern not found in registry");
            return None;
        }
    };

    crate::pattern_resolver::resolve_pattern_entry(code, name, &entry)
}

/// Get the resolved GetPackageInfo function address (for hooking).
pub fn get_package_info_addr() -> Option<usize> {
    // SAFETY: FN_GET_PKG_INFO written once during init, read-only after.
    unsafe { (*std::ptr::addr_of!(FN_GET_PKG_INFO)).map(|f| f as usize) }
}

/// # Safety
/// `this` must be the live CPackageInfo receiver for the active Steam callback.
pub(crate) unsafe fn capture_pkg_info_this(this: *mut c_void) {
    if CPKG_INFO_PTR.load(Ordering::Acquire) == 0 {
        CPKG_INFO_PTR.store(this as usize, Ordering::Release);
        info!(
            "package: captured package helper this at 0x{:x}",
            this as usize
        );
    }
}

#[cfg(target_pointer_width = "32")]
/// # Safety
/// `this` must be the live CPackageInfo receiver for the active Steam callback.
pub(crate) unsafe fn try_capture_pkg0_from_package_info(this: *mut c_void) {
    if PKG0_PTR.load(Ordering::Acquire) != 0 {
        return;
    }

    // SAFETY: inherited from this function's contract.
    unsafe { capture_pkg_info_this(this) };
    // SAFETY: inherited from this function's contract.
    let Some(pkg_ptr) = (unsafe { query_pkg0(this) }) else {
        return;
    };
    // SAFETY: pkg_ptr was returned by Steam's typed package lookup.
    unsafe { capture_validated_pkg0(pkg_ptr) };
}

#[cfg(target_pointer_width = "32")]
unsafe fn query_pkg0(this: *mut c_void) -> Option<*mut u8> {
    // SAFETY: resolved once before hook installation and read-only afterward.
    let get_pkg = unsafe { *std::ptr::addr_of!(FN_GET_PKG_INFO) }?;

    // The 32-bit lookup receives package_id and access_token directly.
    // SAFETY: caller guarantees the receiver is live and the function slot was resolved.
    let pkg_ptr = unsafe { get_pkg(this, 0, PKG0_ACCESS_TOKEN) };

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

pub(crate) fn pkg0_captured() -> bool {
    PKG0_PTR.load(Ordering::Acquire) != 0
}

#[cfg(debug_assertions)]
pub(crate) fn cuser_captured() -> bool {
    CUSER_PTR.load(Ordering::Acquire) != 0
}

/// # Safety
/// `this` must be the live CUser receiver for the active Steam callback.
pub(crate) unsafe fn capture_cuser(this: *mut c_void) {
    let previous = CUSER_PTR.swap(this as usize, Ordering::AcqRel);
    if previous != this as usize {
        debug!("package: updated CUser at 0x{:x}", this as usize);
    }
}

pub(crate) fn reset_account_state() {
    CUSER_PTR.store(0, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Pump called from Steam thread (CheckAppOwnership hook)
// ---------------------------------------------------------------------------

pub fn queue_reload(controlled: Vec<AppId>) {
    *PENDING_RELOAD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(controlled);
}

/// Apply the latest queued runtime state from a Steam-thread hook callback.
pub fn pump_reload(
    access: &mut SteamPackageAccess<'_>,
    snapshot_actual_ownership: impl FnOnce(&[AppId]),
) {
    let controlled = PENDING_RELOAD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    let Some(controlled) = controlled else {
        return;
    };

    let package_state = crate::client::install::package_state();
    let diff = package_state.compute_hot_reload_diff(&controlled);
    snapshot_actual_ownership(&diff.additions);
    let applied = access.apply_reload_diff(&diff);
    package_state.apply_diff(&applied);
    if !applied.additions.is_empty() || !applied.removals.is_empty() {
        info!("package: hot reload completed on Steam thread");
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// # Safety
/// `pkg_ptr` must point to a live PackageInfo returned by Steam. This function
/// validates the identifying fields and vector header before publishing it.
pub(crate) unsafe fn capture_validated_pkg0(pkg_ptr: *mut u8) {
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

    // SAFETY: caller guarantees pkg_ptr points to a live PackageInfo.
    let app_ids = unsafe { &*package_info::app_id_vec(pkg_ptr) };
    let size = app_ids.m_size;
    let capacity = app_ids.m_memory.m_n_allocation_count;
    let memory = app_ids.m_memory.m_p_memory;
    if size < 0
        || size as u32 > capacity
        || (capacity > 0 && (memory.is_null() || !memory.is_aligned()))
    {
        warn!(size, capacity, "package: pkg0 app vector header is invalid");
        return;
    }

    PKG0_PTR.store(pkg_ptr as usize, Ordering::Release);
    info!("package: captured pkg0 at 0x{:x}", pkg_ptr as usize);
}
