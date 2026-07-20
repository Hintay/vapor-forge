use core::ffi::c_void;
use std::sync::OnceLock;

use tracing::{debug, error};

use vapor_forge_hook_engine::detour::CodeRegion;

type CurrentAppIdFn = unsafe extern "C" fn(*mut c_void) -> u32;

#[derive(Clone, Copy)]
struct CurrentAppResolver {
    engine_slot: usize,
    get_current_app_id: CurrentAppIdFn,
}

static RESOLVER: OnceLock<CurrentAppResolver> = OnceLock::new();

pub(crate) fn resolve(code: &CodeRegion, stats_adapter: Option<usize>) {
    let Some(stats_adapter) = stats_adapter else {
        return;
    };
    let Some((engine_slot, helper)) = parse_resolver(code, stats_adapter) else {
        error!("current IPC AppID resolver validation failed");
        return;
    };
    // SAFETY: the helper was decoded from a validated adapter and its body was checked below.
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

#[cfg(target_pointer_width = "32")]
fn parse_resolver(code: &CodeRegion, adapter: usize) -> Option<(usize, usize)> {
    let offset = adapter.checked_sub(code.base)?;
    let bytes = code.bytes.get(offset..offset.checked_add(0x120)?)?;
    let call = bytes.windows(15).position(|window| {
        window[0] == 0x55
            && window[1] == 0x57
            && window[2] == 0x56
            && window[3] == 0x53
            && window[4] == 0xe8
            && window[9] == 0x81
            && window[10] == 0xc3
    })?;
    let add = u32::from_le_bytes(bytes[call + 11..call + 15].try_into().ok()?);
    let pic_anchor = (adapter as u32)
        .wrapping_add(call as u32)
        .wrapping_add(9)
        .wrapping_add(add) as usize;

    for lea in 0..bytes.len().saturating_sub(5) {
        if bytes[lea] != 0x8d || bytes[lea + 1] != 0x83 {
            continue;
        }
        let displacement = i32::from_le_bytes(bytes[lea + 2..lea + 6].try_into().ok()?);
        let tail = &bytes[lea + 6..bytes.len().min(lea + 28)];
        let Some(call) = tail
            .windows(3)
            .position(|window| window == [0xff, 0x30, 0xe8])
        else {
            continue;
        };
        let relative_at = lea + 6 + call + 3;
        let relative = i32::from_le_bytes(
            bytes
                .get(relative_at..relative_at.saturating_add(4))?
                .try_into()
                .ok()?,
        );
        let helper = (adapter as u32)
            .wrapping_add(relative_at as u32)
            .wrapping_add(4)
            .wrapping_add(relative as u32) as usize;
        if validate_helper(code, helper) {
            return Some((
                pic_anchor.wrapping_add_signed(displacement as isize),
                helper,
            ));
        }
    }
    None
}

#[cfg(target_pointer_width = "64")]
fn parse_resolver(code: &CodeRegion, adapter: usize) -> Option<(usize, usize)> {
    let offset = adapter.checked_sub(code.base)?;
    let bytes = code.bytes.get(offset..offset.checked_add(0x140)?)?;
    for (index, window) in bytes.windows(15).enumerate() {
        if window[..3] != [0x48, 0x8d, 0x05]
            || window[7..10] != [0x48, 0x8b, 0x38]
            || window[10] != 0xe8
        {
            continue;
        }
        let root_relative = i32::from_le_bytes(window[3..7].try_into().ok()?);
        let engine_slot = (adapter + index + 7).wrapping_add_signed(root_relative as isize);
        let helper_relative = i32::from_le_bytes(window[11..15].try_into().ok()?);
        let helper = (adapter + index + 15).wrapping_add_signed(helper_relative as isize);
        if validate_helper(code, helper) {
            return Some((engine_slot, helper));
        }
    }
    None
}

#[cfg(target_pointer_width = "32")]
fn validate_helper(code: &CodeRegion, helper: usize) -> bool {
    let Some(offset) = helper.checked_sub(code.base) else {
        return false;
    };
    let Some(bytes) = code.bytes.get(offset..offset.saturating_add(0x50)) else {
        return false;
    };
    bytes.starts_with(&[
        0x8b, 0x4c, 0x24, 0x04, 0x8b, 0x81, 0x98, 0x0a, 0x00, 0x00, 0x8b, 0x91, 0x9c, 0x00, 0x00,
        0x00,
    ]) && bytes
        .windows(6)
        .any(|window| window == [0x8b, 0x89, 0xac, 0x0a, 0x00, 0x00])
        && bytes
            .windows(4)
            .any(|window| window == [0x8b, 0x40, 0x14, 0xc3])
}

#[cfg(target_pointer_width = "64")]
fn validate_helper(code: &CodeRegion, helper: usize) -> bool {
    let Some(offset) = helper.checked_sub(code.base) else {
        return false;
    };
    let Some(bytes) = code.bytes.get(offset..offset.saturating_add(0x60)) else {
        return false;
    };
    bytes.starts_with(&[
        0x48, 0x63, 0x87, 0xe8, 0x0d, 0x00, 0x00, 0x8b, 0x97, 0xf0, 0x00, 0x00, 0x00,
    ]) && bytes
        .windows(7)
        .any(|window| window == [0x48, 0x8b, 0x8f, 0x00, 0x0e, 0x00, 0x00])
        && bytes
            .windows(4)
            .any(|window| window == [0x8b, 0x40, 0x14, 0xc3])
}
