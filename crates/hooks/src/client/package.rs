use core::ffi::c_void;
use core::ptr::NonNull;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};

use tracing::{debug, error, info, warn};
use vapor_forge_config::AppId;
use vapor_forge_features::package::ReloadDiff;
use vapor_forge_patterns::registry::PatternRegistry;
use vapor_forge_steam_native_abi::{
    package_info, CUtlMemoryGrowFn, GetPackageInfoArchFn, MarkLicenseAsChangedFn,
    ProcessPendingLicenseUpdatesFn,
};

use crate::engine_work_item_site::EngineWorkItemSite;
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

const MAX_MAPS_ENTRIES: usize = 4096;

static WORK_ITEM_NAME: &[u8] = b"VaporPackageUpdate\0";

// ---------------------------------------------------------------------------
// Static state for raw function pointers resolved via pattern matching
// ---------------------------------------------------------------------------

static mut FN_MARK_LICENSE: Option<MarkLicenseAsChangedFn> = None;
static mut FN_PROCESS_UPDATES: Option<ProcessPendingLicenseUpdatesFn> = None;
static mut FN_GROW: Option<CUtlMemoryGrowFn> = None;
static mut FN_GET_PKG_INFO: Option<GetPackageInfoArchFn> = None;

static ENGINE_WORK_ITEM_SITE: OnceLock<EngineWorkItemSite> = OnceLock::new();

/// Captured IClientUser `this` pointer from CheckAppOwnership.
static CUSER_PTR: AtomicUsize = AtomicUsize::new(0);
static CUSER_GENERATION: AtomicU64 = AtomicU64::new(0);
static CUSER_GUARD: RwLock<()> = RwLock::new(());

/// Captured package helper `this` pointer.
static CPKG_INFO_PTR: AtomicUsize = AtomicUsize::new(0);

/// Captured pkg0 PackageInfo pointer.
static PKG0_PTR: AtomicUsize = AtomicUsize::new(0);

struct PendingUpdate {
    controlled: Vec<AppId>,
    generation: u64,
}

struct UpdateDispatch {
    pending: Option<PendingUpdate>,
    posted_generation: Option<u64>,
}

impl UpdateDispatch {
    fn replace_pending(&mut self, controlled: Vec<AppId>, generation: u64) {
        self.pending = Some(PendingUpdate {
            controlled,
            generation,
        });
    }

    fn arm(&mut self, generation: u64) -> bool {
        if self.posted_generation.is_some()
            || self
                .pending
                .as_ref()
                .is_none_or(|pending| pending.generation != generation)
        {
            return false;
        }
        self.posted_generation = Some(generation);
        true
    }

    fn take_for(&mut self, generation: u64) -> Option<Vec<AppId>> {
        if self.posted_generation != Some(generation) {
            return None;
        }
        self.pending
            .take()
            .filter(|pending| pending.generation == generation)
            .map(|pending| pending.controlled)
    }

    fn complete(&mut self, generation: u64) -> bool {
        if self.posted_generation != Some(generation) {
            return false;
        }
        self.posted_generation = None;
        true
    }

    fn reject_post(&mut self, generation: u64) {
        if !self.complete(generation) {
            return;
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.generation == generation)
        {
            self.pending = None;
        }
    }
}

static UPDATE_DISPATCH: Mutex<UpdateDispatch> = Mutex::new(UpdateDispatch {
    pending: None,
    posted_generation: None,
});

struct InjectionResult {
    appended: Vec<AppId>,
    complete: bool,
}

pub(crate) struct SteamPackageAccess {
    pkg0: NonNull<u8>,
    cuser: NonNull<c_void>,
    mark_license: MarkLicenseAsChangedFn,
    process_updates: ProcessPendingLicenseUpdatesFn,
    grow: CUtlMemoryGrowFn,
}

impl SteamPackageAccess {
    fn from_current(cuser: *mut c_void) -> Option<Self> {
        let pkg0 = NonNull::new(PKG0_PTR.load(Ordering::Acquire) as *mut u8)?;
        let cuser = NonNull::new(cuser)?;
        if cuser.as_ptr() as usize != CUSER_PTR.load(Ordering::Acquire) {
            return None;
        }
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
        })
    }

    fn app_ids(&mut self) -> &mut vapor_forge_steam_native_abi::CUtlVector<u32> {
        // SAFETY: construction is restricted to the live Steam callback after
        // pkg0 validation, and the returned borrow cannot outlive this access.
        unsafe { &mut *package_info::app_id_vec(self.pkg0.as_ptr()) }
    }

    fn publish_package_change(&self) {
        // SAFETY: the capability holds the current CUser and the
        // architecture-matched functions resolved before work is posted.
        unsafe {
            (self.mark_license)(self.cuser.as_ptr(), 0, true);
            (self.process_updates)(self.cuser.as_ptr());
        }
    }

    fn inject(&mut self, app_ids: &[AppId]) -> InjectionResult {
        if app_ids.is_empty() {
            debug!("package: no apps to inject");
            return InjectionResult {
                appended: Vec::new(),
                complete: true,
            };
        }

        let mut appended = Vec::new();
        let mut complete = true;
        for &app_id in app_ids {
            let raw_id = app_id.0;
            // SAFETY: `app_ids` returns the validated pkg0 vector for this capability.
            if unsafe { self.app_ids().contains(&raw_id) } {
                continue;
            }
            if self.append(raw_id) {
                appended.push(app_id);
            } else {
                complete = false;
                error!(app_id = raw_id, "package: failed to append (grow failed)");
            }
        }

        if !appended.is_empty() {
            self.publish_package_change();
            info!(
                injected = appended.len(),
                total = app_ids.len(),
                "package: app IDs appended to pkg0"
            );
        }
        InjectionResult { appended, complete }
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
                "package: reload mutation applied on Steam engine thread"
            );
            self.publish_package_change();
        }
        applied
    }
}

// ---------------------------------------------------------------------------
// Resolution called from install::do_install
// ---------------------------------------------------------------------------

/// Resolve the callables and engine queue layout needed for pkg0 mutation.
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
    resolve_engine_work_item_site(code);
}

fn resolve_engine_work_item_site(code: &CodeRegion) {
    let discovered =
        match crate::engine_work_item_site::discover(usize::BITS, code.base, code.bytes) {
            Ok(discovered) => discovered,
            Err(error) => {
                warn!(error, "package: engine work-item queue was not discovered");
                return;
            }
        };
    let code_end = code.base.saturating_add(code.bytes.len());
    if !(code.base..code_end).contains(&discovered.site.grow) {
        warn!(
            grow = format_args!("0x{:x}", discovered.site.grow),
            "package: decoded queue grow function is outside steamclient code"
        );
        return;
    }
    let data = vapor_forge_memory::find_proc_self_module_data("steamclient.so", MAX_MAPS_ENTRIES)
        .unwrap_or_default();
    let engine_slot = discovered.site.engine_slot;
    if engine_slot % std::mem::align_of::<usize>() != 0
        || !data
            .iter()
            .any(|range| (range.base.0..range.end.0).contains(&engine_slot))
    {
        warn!(
            engine_slot = format_args!("0x{engine_slot:x}"),
            "package: decoded engine slot is outside steamclient data"
        );
        return;
    }
    info!(
        engine_slot = format_args!("0x{engine_slot:x}"),
        mutex_offset = format_args!("0x{:x}", discovered.site.mutex_offset),
        queue_offset = format_args!("0x{:x}", discovered.site.queue_offset),
        grow = format_args!("0x{:x}", discovered.site.grow),
        item_size = discovered.site.item_size,
        producers = discovered.agreeing_producers,
        "package: engine work-item queue discovered"
    );
    let _ = ENGINE_WORK_ITEM_SITE.set(discovered.site);
}

fn resolve_raw_address(registry: &PatternRegistry, code: &CodeRegion, name: &str) -> Option<usize> {
    let entry = match registry.get(name) {
        Some(e) => e,
        None => {
            warn!(hook = name, "pattern not found in registry");
            return None;
        }
    };

    let address = crate::pattern_resolver::resolve_pattern_entry(code, name, &entry)?;
    crate::pattern_resolver::validate_resolved_pattern("steamclient", code, name, address)
        .then_some(address)
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
            && (*std::ptr::addr_of!(FN_GROW)).is_some()
            && ENGINE_WORK_ITEM_SITE.get().is_some();

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
    let generation = vapor_forge_features::identity::generation();
    if CUSER_PTR.load(Ordering::Acquire) != this as usize
        || CUSER_GENERATION.load(Ordering::Acquire) != generation
    {
        let _guard = CUSER_GUARD
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = CUSER_PTR.load(Ordering::Acquire);
        let previous_generation = CUSER_GENERATION.load(Ordering::Acquire);
        if previous != this as usize || previous_generation != generation {
            CUSER_PTR.store(this as usize, Ordering::Release);
            CUSER_GENERATION.store(generation, Ordering::Release);
            debug!("package: updated CUser at 0x{:x}", this as usize);
        }
    }
    queue_initial_injection();
}

pub(crate) fn reset_account_state() {
    {
        let _guard = CUSER_GUARD
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        CUSER_PTR.store(0, Ordering::Release);
        CUSER_GENERATION.store(0, Ordering::Release);
    }
    CPKG_INFO_PTR.store(0, Ordering::Release);
    PKG0_PTR.store(0, Ordering::Release);
    let mut dispatch = UPDATE_DISPATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    dispatch.pending = None;
    dispatch.posted_generation = None;
}

#[cfg(test)]
pub(crate) fn seed_account_state_for_test() {
    CUSER_PTR.store(1, Ordering::Release);
    CUSER_GENERATION.store(1, Ordering::Release);
    CPKG_INFO_PTR.store(2, Ordering::Release);
    PKG0_PTR.store(3, Ordering::Release);
    let mut dispatch = UPDATE_DISPATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    dispatch.replace_pending(vec![AppId(4)], 1);
    dispatch.posted_generation = Some(1);
}

#[cfg(test)]
pub(crate) fn account_state_is_clear_for_test() -> bool {
    CUSER_PTR.load(Ordering::Acquire) == 0
        && CUSER_GENERATION.load(Ordering::Acquire) == 0
        && CPKG_INFO_PTR.load(Ordering::Acquire) == 0
        && PKG0_PTR.load(Ordering::Acquire) == 0
        && {
            let dispatch = UPDATE_DISPATCH
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            dispatch.pending.is_none() && dispatch.posted_generation.is_none()
        }
}

// ---------------------------------------------------------------------------
// One-shot engine work item
// ---------------------------------------------------------------------------

pub fn queue_reload(controlled: Vec<AppId>) {
    let generation = vapor_forge_features::identity::generation();
    if generation == 0 {
        return;
    }
    UPDATE_DISPATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .replace_pending(controlled, generation);
    try_post_update();
}

// ---------------------------------------------------------------------------
// Genuine ownership from the account's license list
// ---------------------------------------------------------------------------

// Packages (id, access token) from the last CMsgClientLicenseList, kept until
// every package's info is available and the controlled apps were re-evaluated.
static PENDING_LICENSES: Mutex<Option<PendingLicenses>> = Mutex::new(None);
const MAX_LICENSE_REFRESH_ATTEMPTS: u32 = 40;

struct PendingLicenses {
    packages: Vec<(u32, u64)>,
    attempts: u32,
}

/// Remember the account's licenses; the next GetSubscribedApps call, which
/// Steam makes after processing a license change, re-evaluates ownership.
pub(crate) fn note_license_list(packages: Vec<(u32, u64)>) {
    let mut pending = PENDING_LICENSES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *pending = Some(PendingLicenses {
        packages,
        attempts: 0,
    });
}

/// Re-derive which controlled apps the account genuinely owns from the
/// licensed packages' app lists. Package 0 is never consulted, so the result is
/// independent of pkg0 injection; a purchase, gift or refund made while Steam
/// runs therefore updates the ownership cache instead of being frozen at the
/// pre-injection snapshot. Retries on later calls while package info is still
/// arriving from PICS.
pub(crate) fn run_pending_ownership_refresh(config: &vapor_forge_config::RuntimeConfig) {
    let packages = {
        let mut guard = PENDING_LICENSES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(pending) = guard.as_mut() else {
            return;
        };
        if CPKG_INFO_PTR.load(Ordering::Acquire) == 0 {
            // Package store not captured yet: keep the list for a later call.
            return;
        }
        pending.attempts += 1;
        if pending.attempts > MAX_LICENSE_REFRESH_ATTEMPTS {
            warn!(
                packages = pending.packages.len(),
                "package: license list refresh gave up, package info never completed"
            );
            *guard = None;
            return;
        }
        pending.packages.clone()
    };
    // SAFETY: resolved once before hook installation and read-only afterward.
    let Some(get_pkg) = (unsafe { *std::ptr::addr_of!(FN_GET_PKG_INFO) }) else {
        return;
    };
    let this = CPKG_INFO_PTR.load(Ordering::Acquire) as *mut c_void;
    let mut owned: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut missing = 0usize;
    for &(package_id, access_token) in &packages {
        // SAFETY: the receiver was captured from Steam's own GetPackageInfo
        // call and the callable was validated against this ABI.
        let pkg = unsafe { get_pkg(this, package_id, access_token) };
        if pkg.is_null() {
            missing += 1;
            continue;
        }
        // SAFETY: pkg was returned by Steam's typed package lookup.
        if unsafe { package_info::status(pkg) } != PKG_STATUS_AVAILABLE {
            missing += 1;
            continue;
        }
        // SAFETY: pkg was returned by Steam's typed package lookup.
        let app_ids = unsafe { &*package_info::app_id_vec(pkg) };
        let count = app_ids.len();
        let base = app_ids.m_memory.m_p_memory;
        if count > 0 && !base.is_null() {
            // SAFETY: Steam's vector header describes `count` live u32 elements.
            owned.extend(unsafe { std::slice::from_raw_parts(base as *const u32, count) });
        }
    }
    let runtime = crate::client::install::runtime_snapshot();
    let controlled =
        vapor_forge_features::package::controlled_app_ids(config, &runtime.script_state.apps);
    // With package info still missing for some licenses only positive findings
    // are safe to record: an app absent from the packages seen so far may live
    // in one of the missing ones. Downgrades wait for a complete picture.
    let complete = missing == 0;
    let mut changed = Vec::new();
    let mut owned_controlled = 0usize;
    for app_id in controlled {
        let is_owned = owned.contains(&app_id.0);
        if is_owned {
            owned_controlled += 1;
        }
        if !is_owned && !complete {
            continue;
        }
        let before = vapor_forge_features::apps::actual_ownership(app_id);
        vapor_forge_features::apps::record_actual_ownership(app_id, is_owned);
        if before != vapor_forge_features::apps::actual_ownership(app_id) {
            changed.push(app_id.0);
        }
    }
    let attempts = {
        let mut guard = PENDING_LICENSES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let attempts = guard.as_ref().map_or(0, |pending| pending.attempts);
        if complete {
            *guard = None;
        }
        attempts
    };
    if complete || attempts == 1 || !changed.is_empty() {
        info!(
            packages = packages.len(),
            missing,
            complete,
            owned_controlled,
            changed = changed.len(),
            changed_apps = ?changed.iter().take(16).collect::<Vec<_>>(),
            "package: ownership refreshed from license list"
        );
    }
}

fn queue_initial_injection() {
    if crate::client::install::PKG0_INJECTED.load(Ordering::Acquire) {
        try_post_update();
        return;
    }
    let generation = vapor_forge_features::identity::generation();
    if generation == 0
        || CUSER_PTR.load(Ordering::Acquire) == 0
        || CUSER_GENERATION.load(Ordering::Acquire) != generation
        || PKG0_PTR.load(Ordering::Acquire) == 0
    {
        return;
    }
    let runtime = crate::client::install::runtime_snapshot();
    let controlled = vapor_forge_features::package::controlled_app_ids(
        &runtime.config,
        &runtime.script_state.apps,
    );
    UPDATE_DISPATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .replace_pending(controlled, generation);
    try_post_update();
}

fn try_post_update() {
    let generation = vapor_forge_features::identity::generation();
    if !crate::capability::is_ready(crate::capability::Capability::PackageInjection)
        || CUSER_PTR.load(Ordering::Acquire) == 0
        || CUSER_GENERATION.load(Ordering::Acquire) != generation
        || PKG0_PTR.load(Ordering::Acquire) == 0
        || ENGINE_WORK_ITEM_SITE.get().is_none()
    {
        return;
    }
    let should_post = {
        let mut dispatch = UPDATE_DISPATCH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        dispatch.arm(generation)
    };
    if !should_post {
        return;
    }
    if post_engine_work_item(generation) {
        debug!(generation, "package: update work item posted");
        return;
    }

    let mut dispatch = UPDATE_DISPATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    dispatch.reject_post(generation);
    warn!(generation, "package: update work item could not be posted");
}

fn run_update_work_item(generation: u64) {
    let controlled = {
        let mut dispatch = UPDATE_DISPATCH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        dispatch.take_for(generation)
    };
    let Some(controlled) = controlled else {
        complete_update_work_item(generation);
        return;
    };

    if generation != vapor_forge_features::identity::generation() {
        complete_update_work_item(generation);
        return;
    }
    let Some(captured) = super::steam_context::capture() else {
        warn!(
            generation,
            "package: update work item has no current Steam context"
        );
        complete_update_work_item(generation);
        return;
    };
    if captured.identity_generation != generation {
        warn!(generation, "package: update work item context changed");
        complete_update_work_item(generation);
        return;
    }

    let result = super::steam_context::checked_call(captured, || {
        let _cuser_guard = CUSER_GUARD
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if CUSER_GENERATION.load(Ordering::Acquire) != generation {
            return false;
        }
        let cuser = CUSER_PTR.load(Ordering::Acquire) as *mut c_void;
        let Some(mut access) = SteamPackageAccess::from_current(cuser) else {
            return false;
        };
        let package_state = crate::client::install::package_state();
        if !crate::client::install::PKG0_INJECTED.load(Ordering::Acquire) {
            if !super::ownership::snapshot_actual_ownership(cuser, &controlled) {
                return false;
            }
            let plan = package_state.compute_injection(&controlled);
            let injection = access.inject(&plan.app_ids);
            package_state.record_injected(&injection.appended);
            if !injection.complete {
                return false;
            }
            package_state.set_active();
            crate::client::install::PKG0_INJECTED.store(true, Ordering::Release);
            info!(
                controlled = controlled.len(),
                injected = injection.appended.len(),
                "package: initial injection completed"
            );
            return true;
        }
        if !package_state.is_active() {
            return false;
        }
        let diff = package_state.compute_hot_reload_diff(&controlled);
        if !super::ownership::snapshot_actual_ownership(cuser, &diff.additions) {
            return false;
        }
        let applied = access.apply_reload_diff(&diff);
        package_state.apply_diff(&applied);
        info!(
            additions = applied.additions.len(),
            removals = applied.removals.len(),
            "package: hot reload work item completed"
        );
        true
    });
    if !matches!(result, Ok(true)) {
        warn!(generation, "package: update work item did not complete");
    }
    complete_update_work_item(generation);
}

fn complete_update_work_item(generation: u64) {
    {
        let mut dispatch = UPDATE_DISPATCH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !dispatch.complete(generation) {
            return;
        }
    }
    try_post_update();
}

fn post_engine_work_item(generation: u64) -> bool {
    let Some(site) = ENGINE_WORK_ITEM_SITE.get().copied() else {
        return false;
    };
    // SAFETY: the discovered site was validated against multiple native
    // producers and its global slot was checked against steamclient data.
    unsafe { post_engine_work_item_unchecked(site, generation) }
}

unsafe fn post_engine_work_item_unchecked(site: EngineWorkItemSite, generation: u64) -> bool {
    let pointer_size = std::mem::size_of::<usize>();
    if site.item_size != pointer_size * 5 {
        return false;
    }
    // SAFETY: the slot is aligned, mapped steamclient data admitted at install.
    let engine = unsafe { (site.engine_slot as *const *mut u8).read_volatile() };
    if engine.is_null() {
        return false;
    }
    // SAFETY: libc malloc returns storage aligned for any pointer field.
    let item = unsafe { libc::malloc(site.item_size) as *mut u8 };
    if item.is_null() {
        return false;
    }
    // SAFETY: item owns site.item_size writable bytes.
    unsafe {
        item.write_bytes(0, site.item_size);
        item.cast::<usize>().write(WORK_ITEM_NAME.as_ptr() as usize);
        item.add(pointer_size)
            .cast::<u64>()
            .write_unaligned(generation);
        item.add(pointer_size * 3)
            .cast::<usize>()
            .write(package_update_manager as *const () as usize);
        item.add(pointer_size * 4)
            .cast::<usize>()
            .write(package_update_invoker as *const () as usize);
    }

    // SAFETY: offsets and the mutex relationship were proved by the native
    // producer decoder. The engine owns this mutex for the queue's lifetime.
    let mutex = unsafe {
        engine
            .add(site.mutex_offset)
            .cast::<libc::pthread_mutex_t>()
    };
    // SAFETY: mutex points to Steam's live queue mutex.
    if unsafe { libc::pthread_mutex_lock(mutex) } != 0 {
        // SAFETY: Steam did not take ownership of item.
        unsafe { libc::free(item.cast()) };
        return false;
    }
    // SAFETY: the mutex remains locked and engine_slot remains mapped.
    let current_engine = unsafe { (site.engine_slot as *const *mut u8).read_volatile() };
    let inserted = if current_engine != engine {
        false
    } else {
        // SAFETY: queue_offset identifies the native CUtlVector<void *> header.
        unsafe { append_engine_work_item(site, engine, item.cast()) }
    };
    // SAFETY: this call balances the successful lock above.
    let unlock_result = unsafe { libc::pthread_mutex_unlock(mutex) };
    if !inserted || unlock_result != 0 {
        if !inserted {
            // SAFETY: Steam did not take ownership of item.
            unsafe { libc::free(item.cast()) };
        }
        return false;
    }
    true
}

unsafe fn append_engine_work_item(
    site: EngineWorkItemSite,
    engine: *mut u8,
    item: *mut c_void,
) -> bool {
    let pointer_size = std::mem::size_of::<usize>();
    // SAFETY: caller holds the decoded queue mutex and engine is current.
    let queue = unsafe { engine.add(site.queue_offset) };
    let allocation_offset = pointer_size;
    let count_offset = if pointer_size == 8 {
        pointer_size * 2
    } else {
        pointer_size * 3
    };
    // SAFETY: the decoded CUtlVector header contains these live fields.
    let mut capacity = unsafe { queue.add(allocation_offset).cast::<i32>().read() };
    // SAFETY: the decoded CUtlVector header contains these live fields.
    let count = unsafe { queue.add(count_offset).cast::<i32>().read() };
    if count < 0 || capacity < 0 || count > capacity {
        return false;
    }
    if count == capacity {
        type GrowFn = unsafe extern "C" fn(*mut c_void, i32);
        // SAFETY: discovery followed this exact queue producer's typed Grow call.
        let grow = unsafe { std::mem::transmute::<usize, GrowFn>(site.grow) };
        // SAFETY: queue is the matching CUtlMemory<void *> prefix.
        unsafe { grow(queue.cast(), 1) };
        // SAFETY: Grow updates the live allocation field in place.
        capacity = unsafe { queue.add(allocation_offset).cast::<i32>().read() };
        if capacity <= count {
            return false;
        }
    }
    // SAFETY: the queue pointer is the first field of the decoded vector header.
    let storage = unsafe { queue.cast::<*mut *mut c_void>().read() };
    if storage.is_null() || !storage.is_aligned() {
        return false;
    }
    // SAFETY: capacity exceeds count and caller holds the native queue mutex.
    unsafe {
        storage.add(count as usize).write(item);
        queue.add(count_offset).cast::<i32>().write(count + 1);
    }
    true
}

unsafe extern "C" fn package_update_invoker(storage: *const c_void) {
    if storage.is_null() {
        return;
    }
    // SAFETY: Steam passes the two-word callable storage beginning at item + 1 pointer.
    let generation = unsafe { storage.cast::<u64>().read_unaligned() };
    run_update_work_item(generation);
}

unsafe extern "C" fn package_update_manager(
    _destination: *mut c_void,
    _source: *const c_void,
    _operation: i32,
) -> bool {
    false
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
    queue_initial_injection();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatch() -> UpdateDispatch {
        UpdateDispatch {
            pending: None,
            posted_generation: None,
        }
    }

    #[test]
    fn reload_dispatch_keeps_only_the_latest_state() {
        let mut dispatch = dispatch();
        dispatch.replace_pending(vec![AppId(1)], 7);
        dispatch.replace_pending(vec![AppId(2), AppId(3)], 7);
        assert!(dispatch.arm(7));
        assert_eq!(dispatch.take_for(7), Some(vec![AppId(2), AppId(3)]));
    }

    #[test]
    fn reload_arriving_during_execution_arms_a_second_item() {
        let mut dispatch = dispatch();
        dispatch.replace_pending(vec![AppId(1)], 7);
        assert!(dispatch.arm(7));
        assert_eq!(dispatch.take_for(7), Some(vec![AppId(1)]));

        dispatch.replace_pending(vec![AppId(2)], 7);
        assert!(!dispatch.arm(7));
        assert!(dispatch.complete(7));
        assert!(dispatch.arm(7));
        assert_eq!(dispatch.take_for(7), Some(vec![AppId(2)]));
    }

    #[test]
    fn stale_item_cannot_disarm_a_new_generation() {
        let mut dispatch = dispatch();
        dispatch.replace_pending(vec![AppId(1)], 7);
        assert!(dispatch.arm(7));
        dispatch.pending = None;
        dispatch.posted_generation = None;

        dispatch.replace_pending(vec![AppId(2)], 8);
        assert!(dispatch.arm(8));
        assert!(!dispatch.complete(7));
        assert_eq!(dispatch.posted_generation, Some(8));
        assert_eq!(dispatch.take_for(8), Some(vec![AppId(2)]));
    }

    #[test]
    fn rejected_post_is_terminal_for_its_generation() {
        let mut dispatch = dispatch();
        dispatch.replace_pending(vec![AppId(1)], 7);
        assert!(dispatch.arm(7));
        dispatch.reject_post(7);
        assert!(dispatch.pending.is_none());
        assert!(dispatch.posted_generation.is_none());
    }
}
