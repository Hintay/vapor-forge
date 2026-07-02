use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use retour::GenericDetour;
use tracing::{debug, info, warn};
use vapor_forge_config::AppId;
use vapor_forge_patterns::registry::PatternRegistry;

use crate::detour::{self, CodeRegion};
use crate::original::{detour_or_return, vmt_or_return};
use crate::vmt;

use super::install::{config, validate_vmt_hook_eligibility, read_vtable_slot};

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type RunIPCFrameFn = extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
pub(crate) type IsCloudEnabledForAppFn = extern "C" fn(*mut c_void, u32) -> bool;
pub(crate) type SetCloudEnabledForAppFn = extern "C" fn(*mut c_void, u32, bool);
pub(crate) type WriteVdfFileFn = extern "C" fn(*mut c_void, u32, u32, *mut c_void, *const u8, u32) -> u32;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut REMOTE_STORAGE_RUN_IPC_DETOUR: Option<GenericDetour<RunIPCFrameFn>> = None;
pub(crate) static mut WRITE_VDF_DETOUR: Option<GenericDetour<WriteVdfFileFn>> = None;
pub(crate) static mut ORIGINAL_IS_CLOUD_ENABLED: Option<IsCloudEnabledForAppFn> = None;
pub(crate) static mut SET_CLOUD_FN: Option<SetCloudEnabledForAppFn> = None;
pub(crate) static CLOUD_VMT_DONE: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientRemoteStorage::RunIPCFrame (cloud VMT)
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_remote_storage_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !CLOUD_VMT_DONE.load(Ordering::Acquire) {
        install_cloud_vmt(this);
    }

    // SAFETY: REMOTE_STORAGE_RUN_IPC_DETOUR set before enabled.
    let original = detour_or_return!(
        "IClientRemoteStorage::RunIPCFrame",
        REMOTE_STORAGE_RUN_IPC_DETOUR,
        ()
    );
    original.call(this, a1, a2, a3);
}

extern "C" fn hk_is_cloud_enabled_for_app(this: *mut c_void, app_id: u32) -> bool {
    // SAFETY: ORIGINAL_IS_CLOUD_ENABLED set before VMT swap.
    let original = vmt_or_return!("IsCloudEnabledForApp", ORIGINAL_IS_CLOUD_ENABLED, true);
    let result = original(this, app_id);

    let cfg = config();
    let should_disable = cfg.app_category(AppId(app_id)).is_some()
        && !vapor_forge_features::apps::is_actually_owned(AppId(app_id))
        && !cfg.cloud_enabled_for_controlled_apps();

    if should_disable {
        // Write cloudenabled=false into Steam's in-memory config store (once per app).
        // This prevents the "out of date" cloud badge after hot-reload.
        // The VDF write filter strips it before disk flush.
        if vapor_forge_features::cloud::mark_cloud_wrote(AppId(app_id)) {
            if let Some(set_fn) = unsafe { *std::ptr::addr_of!(SET_CLOUD_FN) } {
                set_fn(this, app_id, false);
                info!(
                    app_id,
                    "cloud: SetCloudEnabledForApp(false) — badge suppressed"
                );
            }
        }
    }

    vapor_forge_features::cloud::on_is_cloud_enabled(&*cfg, AppId(app_id), result)
}

fn install_cloud_vmt(this: *mut c_void) {
    if CLOUD_VMT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }

    // Store original BEFORE swapping the vtable slot, so the hook callback
    // can find the original immediately if it fires on another thread.
    // SAFETY: this points to an IClientRemoteStorage C++ object; read vtable slot.
    let Some(slot) = crate::vtable_scan::slot_of("IClientRemoteStorage", "IsCloudEnabledForApp")
    else {
        warn!("hook-install: IsCloudEnabledForApp slot not found in VtableScan");
        return;
    };

    let orig_addr = unsafe { read_vtable_slot(this, slot) };
    let Some(addr) = orig_addr else { return };
    let replacement = hk_is_cloud_enabled_for_app as *const () as usize;

    if !validate_vmt_hook_eligibility("IsCloudEnabledForApp", addr, replacement) {
        return;
    }

    // SAFETY: transmuting a valid function address to a typed fn pointer.
    let orig_fn: IsCloudEnabledForAppFn = unsafe { std::mem::transmute(addr) };
    unsafe { std::ptr::addr_of_mut!(ORIGINAL_IS_CLOUD_ENABLED).write(Some(orig_fn)) };

    // SAFETY: swap the vtable slot (original already stored).
    unsafe {
        vmt::swap_vtable_slot("IsCloudEnabledForApp", this, slot, replacement);
    }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: CConfigStore::WriteVdfFile (VDF cloud filter)
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_write_vdf_file(
    a0: *mut c_void,
    a1: u32,
    a2: u32,
    a3: *mut c_void,
    buffer: *const u8,
    size: u32,
) -> u32 {
    if !buffer.is_null() && size > 0 {
        // SAFETY: buffer/size from Steam's serialized VDF.
        let data = unsafe { std::slice::from_raw_parts(buffer, size as usize) };
        if let Some(filtered) = vapor_forge_features::cloud::strip_cloud_from_vdf(data) {
            debug!(
                original = size,
                filtered = filtered.len(),
                "cloud: VDF write filtered"
            );
            // SAFETY: calling original with filtered buffer.
            let original = detour_or_return!("WriteVdfFile", WRITE_VDF_DETOUR, 0);
            return original.call(a0, a1, a2, a3, filtered.as_ptr(), filtered.len() as u32);
        }
    }

    // SAFETY: pass through unmodified.
    let original = detour_or_return!("WriteVdfFile", WRITE_VDF_DETOUR, 0);
    original.call(a0, a1, a2, a3, buffer, size)
}

/// Resolve SetCloudEnabledForApp as a raw fn pointer, not a detour. It is called directly.
pub(crate) fn resolve_set_cloud_fn(registry: &PatternRegistry, code: &CodeRegion) {
    let entry = match registry.get("IClientRemoteStorage::SetCloudEnabledForApp") {
        Some(e) => e,
        None => return,
    };
    let addr = match detour::resolve_pattern_entry(code, "SetCloudEnabledForApp", &entry) {
        Some(a) => a,
        None => return,
    };
    // SAFETY: addr is a validated code address.
    let f: SetCloudEnabledForAppFn = unsafe { std::mem::transmute(addr) };
    unsafe { std::ptr::addr_of_mut!(SET_CLOUD_FN).write(Some(f)) };
    debug!(
        addr = format_args!("0x{:x}", addr),
        "SetCloudEnabledForApp resolved"
    );
}
