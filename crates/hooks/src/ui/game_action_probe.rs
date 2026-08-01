use core::ffi::{c_char, c_void};
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tracing::{info, warn};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::detour_or_return;
use vapor_forge_hook_engine::plan::{validate_hook_target, AddressRange, HookTargetInput};

use crate::hook_report::HookResult;
use crate::pattern_resolver::{resolve_pattern_entry, CodeRegion};

const HOOK_NAME: &str = "CGameActionController::ContinueGameAction";
pub(crate) const PROBE_HANDLE: i32 = i32::MIN + 0x4650;

type ContinueGameActionFn = unsafe extern "C" fn(*mut c_void, i32, *const c_char);

static mut DETOUR: Option<Detour<ContinueGameActionFn>> = None;
static ARMED: AtomicBool = AtomicBool::new(false);
static HIT: AtomicBool = AtomicBool::new(false);
static NATIVE_NEXT_HANDLE: AtomicU32 = AtomicU32::new(0);
static ACTIVE_HANDLE_COUNT: AtomicU32 = AtomicU32::new(0);
static ACTIVE_HANDLE_MIN: AtomicU32 = AtomicU32::new(0);
static ACTIVE_HANDLE_MAX: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
pub(crate) struct ProbeStatus {
    pub(crate) hit: bool,
    pub(crate) native_next_handle: u32,
    pub(crate) active_handle_count: u32,
    pub(crate) active_handle_min: u32,
    pub(crate) active_handle_max: u32,
}

unsafe fn capture_native_handles(controller: *mut c_void) {
    if controller.is_null() {
        return;
    }

    let controller = controller.cast::<u8>();
    // SAFETY: the ordinary x86 allocator stores its next handle at this offset.
    let next_handle = unsafe { controller.add(0x28).cast::<u32>().read_unaligned() };
    // SAFETY: the hook target validates the ordinary x86 active-count offset.
    let count = unsafe { controller.add(0x38).cast::<i32>().read_unaligned() };
    if !(0..=4096).contains(&count) {
        return;
    }

    NATIVE_NEXT_HANDLE.store(next_handle, Ordering::Release);
    ACTIVE_HANDLE_COUNT.store(count as u32, Ordering::Release);
    if count == 0 {
        ACTIVE_HANDLE_MIN.store(0, Ordering::Release);
        ACTIVE_HANDLE_MAX.store(0, Ordering::Release);
        return;
    }

    // SAFETY: the hook target validates the ordinary x86 action-vector offset.
    let actions = unsafe {
        controller
            .add(0x2c)
            .cast::<*const *const u8>()
            .read_unaligned()
    };
    if actions.is_null() {
        return;
    }

    let mut min_handle = u32::MAX;
    let mut max_handle = 0;
    for index in 0..count as usize {
        // SAFETY: Steam owns a stable action pointer array while dispatching this call.
        let action = unsafe { actions.add(index).read() };
        if action.is_null() {
            continue;
        }
        // SAFETY: each active CBaseGameAction stores its handle at offset 0x08.
        let handle = unsafe { action.add(0x08).cast::<u32>().read_unaligned() };
        min_handle = min_handle.min(handle);
        max_handle = max_handle.max(handle);
    }
    ACTIVE_HANDLE_MIN.store(min_handle, Ordering::Release);
    ACTIVE_HANDLE_MAX.store(max_handle, Ordering::Release);
}

unsafe extern "C" fn hook(controller: *mut c_void, handle: i32, action: *const c_char) {
    // SAFETY: Steam supplied the controller to its ContinueGameAction implementation.
    unsafe { capture_native_handles(controller) };

    if handle == PROBE_HANDLE && ARMED.swap(false, Ordering::AcqRel) {
        let action_matches = !action.is_null()
            // SAFETY: Steam passes a NUL-terminated action string to this function.
            && unsafe { CStr::from_ptr(action) }.to_bytes() == b"KeepRemote";
        HIT.store(action_matches, Ordering::Release);
        info!(
            handle = format_args!("{handle:#x}"),
            action_matches, "steamui: game action return probe reached native helper"
        );
        return;
    }

    let original = detour_or_return!(HOOK_NAME, DETOUR);
    // SAFETY: the typed Steam function and arguments satisfy the active FFI contract.
    unsafe { original(controller, handle, action) };
}

pub(crate) fn install(
    steamui_code: &CodeRegion,
    registry: &vapor_forge_patterns::registry::PatternRegistry,
) -> HookResult {
    let mut result = HookResult {
        name: HOOK_NAME,
        installed: false,
        addr: 0,
    };
    let Some(entry) = registry.get(HOOK_NAME) else {
        return result;
    };
    let Some(addr) = resolve_pattern_entry(steamui_code, HOOK_NAME, &entry) else {
        warn!("steamui: game action probe pattern not found");
        return result;
    };
    result.addr = addr;

    let replacement_address = hook as *const () as usize;
    let plan = match validate_hook_target(HookTargetInput {
        target_address: addr,
        replacement_address,
        executable_range: AddressRange {
            start: steamui_code.base,
            end: steamui_code.base + steamui_code.bytes.len(),
        },
    }) {
        Ok(plan) => plan,
        Err(error) => {
            warn!(%error, "steamui: game action probe target validation failed");
            return result;
        }
    };

    // SAFETY: the pattern-resolved target and replacement use ContinueGameActionFn.
    let pending = unsafe {
        vapor_forge_hook_engine::detour::create_detour::<ContinueGameActionFn>(HOOK_NAME, plan)
    };
    // SAFETY: SteamUI hook installation is single-threaded.
    result.installed = unsafe {
        vapor_forge_hook_engine::detour::store_and_finalize(
            HOOK_NAME,
            std::ptr::addr_of_mut!(DETOUR),
            pending,
        )
    };
    result
}

pub(crate) fn arm() -> i32 {
    HIT.store(false, Ordering::Release);
    ARMED.store(true, Ordering::Release);
    PROBE_HANDLE
}

pub(crate) fn status() -> ProbeStatus {
    ProbeStatus {
        hit: HIT.load(Ordering::Acquire),
        native_next_handle: NATIVE_NEXT_HANDLE.load(Ordering::Acquire),
        active_handle_count: ACTIVE_HANDLE_COUNT.load(Ordering::Acquire),
        active_handle_min: ACTIVE_HANDLE_MIN.load(Ordering::Acquire),
        active_handle_max: ACTIVE_HANDLE_MAX.load(Ordering::Acquire),
    }
}
