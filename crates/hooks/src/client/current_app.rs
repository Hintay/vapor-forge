use core::ffi::c_void;
use std::sync::OnceLock;

use tracing::{debug, error};

use crate::pattern_resolver::CodeRegion;

type CurrentAppIdFn = unsafe extern "C" fn(*mut c_void) -> u32;

#[derive(Clone, Copy)]
struct CurrentAppResolver {
    engine_slot: usize,
    get_current_app_id: CurrentAppIdFn,
}

static RESOLVER: OnceLock<CurrentAppResolver> = OnceLock::new();

pub(crate) fn resolve(code: &CodeRegion) {
    let slots = crate::vtable_scan::slots_of("IClientUserStats", "IndicateAchievementProgress");
    if slots.len() != 1 {
        error!(
            found = slots.len(),
            "current IPC AppID resolver source slot lookup failed"
        );
        return;
    }
    let Some(stats_adapter) = crate::vtable_scan::method_address("CUserStats", slots[0]) else {
        error!("current IPC AppID resolver source was not found");
        return;
    };
    let bitness = if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    };
    let Some(site) = stats_adapter.checked_sub(code.base).and_then(|offset| {
        vapor_forge_patterns::current_app::resolve(code.bytes, code.base as u64, offset, bitness)
    }) else {
        error!("current IPC AppID resolver validation failed");
        return;
    };
    let (Ok(engine_slot), Some(helper)) = (
        usize::try_from(site.engine_slot),
        code.base.checked_add(site.helper),
    ) else {
        error!("current IPC AppID resolver address is out of range");
        return;
    };
    // SAFETY: the helper and its call site were validated by the shared resolver.
    let get_current_app_id = unsafe { std::mem::transmute::<usize, CurrentAppIdFn>(helper) };
    if RESOLVER
        .set(CurrentAppResolver {
            engine_slot,
            get_current_app_id,
        })
        .is_ok()
    {
        debug!(
            engine_slot = format_args!("0x{engine_slot:x}"),
            helper = format_args!("0x{helper:x}"),
            "current IPC AppID resolver ready"
        );
    }
}

pub(crate) fn is_ready() -> bool {
    RESOLVER.get().is_some()
}

pub(crate) fn get() -> Option<u32> {
    let resolver = RESOLVER.get()?;
    // SAFETY: engine_slot is a validated steamclient data slot.
    let engine = unsafe { (resolver.engine_slot as *const *mut c_void).read() };
    if engine.is_null() {
        return None;
    }
    let app_id = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { (resolver.get_current_app_id)(engine) } & 0x00ff_ffff;
    (app_id != 0).then_some(app_id)
}
