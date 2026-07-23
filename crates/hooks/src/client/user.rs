use core::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

use tracing::{debug, warn};

use vapor_forge_hook_engine::vmt;

use super::install::{read_vtable_slot, validate_vmt_hook_eligibility};

const GET_STEAM_ID_SLOT: usize = 10;
const HOOK_NAME: &str = "IClientUser::GetSteamID";

static ORIGINAL_GET_STEAM_ID: AtomicUsize = AtomicUsize::new(0);
static GET_STEAM_ID_GATE: vmt::InstallGate = vmt::InstallGate::new();

#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CSteamId {
    bits: u64,
}

#[cfg(target_pointer_width = "32")]
type GetSteamIdFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> CSteamId;
#[cfg(target_pointer_width = "64")]
type GetSteamIdFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> u64;

pub(crate) fn install_get_steam_id_hook(user: *mut c_void) {
    let Some(attempt) = GET_STEAM_ID_GATE.begin() else {
        return;
    };
    let Some(slot) = crate::vtable_scan::slot_of("IClientUser", "GetSteamID") else {
        warn!("hook-install: IClientUser::GetSteamID slot is unavailable");
        attempt.disable();
        return;
    };
    if slot != GET_STEAM_ID_SLOT {
        warn!(
            expected = GET_STEAM_ID_SLOT,
            actual = slot,
            "hook-install: IClientUser::GetSteamID slot drifted"
        );
        attempt.disable();
        return;
    }

    // SAFETY: `user` was returned by IClientEngine::GetIClientUser and slot 10
    // belongs to the versioned IClientUser wrapper.
    let Some(original) = (unsafe { read_vtable_slot(user, slot) }) else {
        return;
    };
    let replacement = replacement_address();
    if !validate_vmt_hook_eligibility(HOOK_NAME, original, replacement) {
        attempt.disable();
        return;
    }

    ORIGINAL_GET_STEAM_ID.store(original, Ordering::Release);
    // SAFETY: the replacement uses the architecture-specific CSteamID return ABI.
    if unsafe { vmt::swap_vtable_slot(HOOK_NAME, user, slot, replacement) }.is_some() {
        attempt.commit();
    }
}

pub(crate) fn refresh_real_steam_id(user: *mut c_void) -> Result<u64, &'static str> {
    let function = original_get_steam_id().or_else(|| {
        // SAFETY: `user` is the live IClientUser wrapper owned by this worker session.
        let address = unsafe { read_vtable_slot(user, GET_STEAM_ID_SLOT) }?;
        // SAFETY: slot 10 is IClientUser::GetSteamID for this interface.
        unsafe { function_from_address(address) }
    });
    let function = function.ok_or("IClientUser::GetSteamID is unavailable")?;
    let steam_id = call_get_steam_id(function, user, std::ptr::null());
    if steam_id != 0 && !vapor_forge_features::identity::is_valid_individual_steam_id(steam_id) {
        warn!(
            steam_id,
            "IClientUser::GetSteamID returned an invalid individual SteamID"
        );
        return Err("IClientUser::GetSteamID returned an invalid SteamID");
    }
    publish_real_steam_id(steam_id);
    Ok(steam_id)
}

fn publish_real_steam_id(steam_id: u64) {
    if vapor_forge_features::identity::set_authoritative_steam_id(steam_id) {
        crate::playtime_worker::clear_remote_playtime();
        vapor_forge_features::rich_presence::reset_account_state();
        debug!(steam_id, "Steam identity refreshed from IClientUser");
    }
}

fn original_get_steam_id() -> Option<GetSteamIdFn> {
    let address = ORIGINAL_GET_STEAM_ID.load(Ordering::Acquire);
    // SAFETY: installation stores the validated slot-10 function address.
    unsafe { function_from_address(address) }
}

unsafe fn function_from_address(address: usize) -> Option<GetSteamIdFn> {
    if address == 0 {
        return None;
    }
    // SAFETY: the caller has established that this is IClientUser vtable slot 10.
    Some(unsafe { std::mem::transmute::<usize, GetSteamIdFn>(address) })
}

#[cfg(target_pointer_width = "32")]
fn call_get_steam_id(function: GetSteamIdFn, this: *mut c_void, username: *const c_char) -> u64 {
    // On i686 SysV, Rust's repr(C) aggregate return emits the same hidden sret
    // buffer and `ret 4` convention used by the non-trivial C++ CSteamID class.
    // SAFETY: function is the validated 32-bit GetSteamID entry and arguments
    // are forwarded unchanged from the active call path.
    unsafe { function(this, username) }.bits
}

#[cfg(target_pointer_width = "64")]
fn call_get_steam_id(function: GetSteamIdFn, this: *mut c_void, username: *const c_char) -> u64 {
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { function(this, username) }
}

#[cfg(target_pointer_width = "32")]
unsafe extern "C" fn hook_get_steam_id(this: *mut c_void, username: *const c_char) -> CSteamId {
    CSteamId {
        bits: hooked_steam_id(this, username),
    }
}

#[cfg(target_pointer_width = "64")]
unsafe extern "C" fn hook_get_steam_id(this: *mut c_void, username: *const c_char) -> u64 {
    hooked_steam_id(this, username)
}

fn hooked_steam_id(this: *mut c_void, username: *const c_char) -> u64 {
    let Some(original) = original_get_steam_id() else {
        warn!("IClientUser::GetSteamID original function is unavailable");
        return 0;
    };
    let real = call_get_steam_id(original, this, username);
    if real == 0 || vapor_forge_features::identity::is_valid_individual_steam_id(real) {
        publish_real_steam_id(real);
    }

    let delegate = vapor_forge_features::ticket::delegate_steamid();
    if delegate != 0 {
        debug!(
            real,
            delegate, "ticket: GetSteamID returning delegate SteamID"
        );
        delegate
    } else {
        real
    }
}

fn replacement_address() -> usize {
    hook_get_steam_id as *const () as usize
}
