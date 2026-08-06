use core::ffi::{c_char, c_void};

use tracing::{debug, warn};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::original_detour;

pub(crate) const GET_STEAM_ID_NAME: &str = "IClientUser::GetSteamID";

#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CSteamId {
    bits: u64,
}

#[cfg(target_pointer_width = "32")]
pub(crate) type GetSteamIdFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> CSteamId;
#[cfg(target_pointer_width = "64")]
pub(crate) type GetSteamIdFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> u64;

pub(crate) static mut GET_STEAM_ID_DETOUR: Option<Detour<GetSteamIdFn>> = None;

fn publish_real_steam_id(steam_id: u64) {
    if super::set_authoritative_steam_id(steam_id) {
        debug!(steam_id, "Steam identity refreshed from IClientUser");
    }
}

fn original_get_steam_id() -> Option<GetSteamIdFn> {
    // SAFETY: installation stores the detour before enabling it.
    unsafe { original_detour(GET_STEAM_ID_NAME, std::ptr::addr_of!(GET_STEAM_ID_DETOUR)) }
}

#[cfg(target_pointer_width = "32")]
fn call_get_steam_id(function: GetSteamIdFn, this: *mut c_void, username: *const c_char) -> u64 {
    // SAFETY: function is the validated 32-bit GetSteamID entry.
    unsafe { function(this, username) }.bits
}

#[cfg(target_pointer_width = "64")]
fn call_get_steam_id(function: GetSteamIdFn, this: *mut c_void, username: *const c_char) -> u64 {
    // SAFETY: function is the validated 64-bit GetSteamID entry.
    unsafe { function(this, username) }
}

#[cfg(target_pointer_width = "32")]
pub(crate) unsafe extern "C" fn hk_get_steam_id(
    this: *mut c_void,
    username: *const c_char,
) -> CSteamId {
    CSteamId {
        bits: hooked_steam_id(this, username),
    }
}

#[cfg(target_pointer_width = "64")]
pub(crate) unsafe extern "C" fn hk_get_steam_id(this: *mut c_void, username: *const c_char) -> u64 {
    hooked_steam_id(this, username)
}

fn hooked_steam_id(this: *mut c_void, username: *const c_char) -> u64 {
    let Some(original) = original_get_steam_id() else {
        warn!("IClientUser::GetSteamID original function is unavailable");
        return 0;
    };
    let real = call_get_steam_id(original, this, username);
    if crate::capability::is_ready(crate::capability::Capability::CallbackEvents)
        && !super::steam_context::checked_call_active()
        && (real == 0 || vapor_forge_features::identity::is_valid_individual_steam_id(real))
    {
        publish_real_steam_id(real);
    }

    let delegate = crate::capability::is_ready(crate::capability::Capability::TicketOverrides)
        .then(vapor_forge_features::ticket::delegate_steamid)
        .unwrap_or(0);
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
