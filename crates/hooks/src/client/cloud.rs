use core::ffi::c_void;
use tracing::{debug, info, warn};
use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;

use vapor_forge_hook_engine::original::{detour_or_return, vmt_or_return};
use vapor_forge_hook_engine::vmt;

use super::install::{config, plan_vmt_hook, read_vtable_slot, validate_steamclient_code_address};

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type RunIPCFrameFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
pub(crate) type IsCloudEnabledForAppFn = unsafe extern "C" fn(*mut c_void, u32) -> bool;
pub(crate) type SetCloudEnabledForAppFn = unsafe extern "C" fn(*mut c_void, u32, bool);
pub(crate) type WriteVdfFileFn =
    unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void, *const u8, u32) -> u32;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut REMOTE_STORAGE_RUN_IPC_DETOUR: Option<Detour<RunIPCFrameFn>> = None;
pub(crate) static mut WRITE_VDF_DETOUR: Option<Detour<WriteVdfFileFn>> = None;
pub(crate) static mut ORIGINAL_IS_CLOUD_ENABLED: Option<IsCloudEnabledForAppFn> = None;
pub(crate) static mut SET_CLOUD_FN: Option<SetCloudEnabledForAppFn> = None;
static CLOUD_VMT_GATE: vmt::InstallGate = vmt::InstallGate::new();
static SET_CLOUD_CAPTURE_GATE: vmt::InstallGate = vmt::InstallGate::new();

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientRemoteStorage::RunIPCFrame (cloud VMT)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_remote_storage_run_ipc_frame(
    this: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) {
    if !CLOUD_VMT_GATE.is_settled() {
        install_cloud_vmt(this);
    }

    // SAFETY: REMOTE_STORAGE_RUN_IPC_DETOUR set before enabled.
    let original = detour_or_return!(
        "IClientRemoteStorage::RunIPCFrame",
        REMOTE_STORAGE_RUN_IPC_DETOUR
    );
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(this, a1, a2, a3) };
}

unsafe extern "C" fn hk_is_cloud_enabled_for_app(this: *mut c_void, app_id: u32) -> bool {
    // SAFETY: ORIGINAL_IS_CLOUD_ENABLED set before VMT swap.
    let original = vmt_or_return!("IsCloudEnabledForApp", ORIGINAL_IS_CLOUD_ENABLED, true);
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, app_id) };

    let cfg = config();
    let should_disable = vapor_forge_features::apps::classify_app(&cfg, AppId(app_id))
        .requires_injected_ownership()
        && !cfg.cloud_enabled_for_controlled_apps();

    if should_disable {
        // Write cloudenabled=false into Steam's in-memory config store (once per app).
        // This prevents the "out of date" cloud badge after hot-reload.
        // The VDF write filter strips it before disk flush.
        if vapor_forge_features::cloud::mark_cloud_wrote(AppId(app_id)) {
            // SAFETY: captured from this object's VMT before the hook is enabled.
            if let Some(set_fn) = unsafe { *std::ptr::addr_of!(SET_CLOUD_FN) } {
                /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
                unsafe { set_fn(this, app_id, false) };
                info!(
                    app_id,
                    "cloud: SetCloudEnabledForApp(false) — badge suppressed"
                );
            }
        }
    }

    vapor_forge_features::cloud::on_is_cloud_enabled(&cfg, AppId(app_id), result)
}

fn install_cloud_vmt(this: *mut c_void) {
    let Some(attempt) = CLOUD_VMT_GATE.begin() else {
        return;
    };

    capture_set_cloud_from_vtable(this);

    // Store original BEFORE swapping the vtable slot, so the hook callback
    // can find the original immediately if it fires on another thread.
    // SAFETY: this points to an IClientRemoteStorage C++ object; read vtable slot.
    let Some(slot) = crate::vtable_scan::slot_of("IClientRemoteStorage", "IsCloudEnabledForApp")
    else {
        warn!("hook-install: IsCloudEnabledForApp slot not found in VtableScan");
        attempt.disable();
        return;
    };

    // SAFETY: this is the live IClientRemoteStorage object passed by Steam.
    let orig_addr = unsafe { read_vtable_slot(this, slot) };
    let Some(addr) = orig_addr else { return };
    let replacement = hk_is_cloud_enabled_for_app as *const () as usize;

    let Some(plan) = plan_vmt_hook("IsCloudEnabledForApp", addr, replacement) else {
        attempt.disable();
        return;
    };

    // SAFETY: transmuting a valid function address to a typed fn pointer.
    let orig_fn: IsCloudEnabledForAppFn = unsafe { std::mem::transmute(addr) };
    // SAFETY: initialization is serialized by CLOUD_VMT_GATE before slot swap.
    unsafe { std::ptr::addr_of_mut!(ORIGINAL_IS_CLOUD_ENABLED).write(Some(orig_fn)) };

    // SAFETY: swap the vtable slot (original already stored).
    if unsafe { vmt::swap_vtable_slot("IsCloudEnabledForApp", this, slot, plan) }.is_some() {
        attempt.commit();
    }
}

fn capture_set_cloud_from_vtable(this: *mut c_void) {
    if SET_CLOUD_CAPTURE_GATE.is_settled() {
        return;
    }
    let Some(attempt) = SET_CLOUD_CAPTURE_GATE.begin() else {
        return;
    };
    let Some(slot) = crate::vtable_scan::slot_of("IClientRemoteStorage", "SetCloudEnabledForApp")
    else {
        warn!("hook-install: SetCloudEnabledForApp slot not found in VtableScan");
        attempt.disable();
        return;
    };

    // SAFETY: this is the live IClientRemoteStorage object passed by Steam.
    let Some(addr) = (unsafe { read_vtable_slot(this, slot) }) else {
        return;
    };
    if !validate_steamclient_code_address("SetCloudEnabledForApp", addr) {
        attempt.disable();
        return;
    }

    // SAFETY: vtable slot was decoded from the live IClientRemoteStorage object.
    let f: SetCloudEnabledForAppFn = unsafe { std::mem::transmute(addr) };
    // SAFETY: initialization is serialized by SET_CLOUD_CAPTURE_GATE.
    unsafe { std::ptr::addr_of_mut!(SET_CLOUD_FN).write(Some(f)) };
    attempt.commit();
    debug!(
        addr = format_args!("0x{:x}", addr),
        slot, "SetCloudEnabledForApp captured from vtable"
    );
}

// ---------------------------------------------------------------------------
// Hook replacement functions: CConfigStore::WriteVdfFile (VDF cloud filter)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_write_vdf_file(
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
            return // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(a0, a1, a2, a3, filtered.as_ptr(), filtered.len() as u32) };
        }
    }

    // SAFETY: pass through unmodified.
    let original = detour_or_return!("WriteVdfFile", WRITE_VDF_DETOUR, 0);
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(a0, a1, a2, a3, buffer, size) }
}
