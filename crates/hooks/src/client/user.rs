use core::ffi::{c_char, c_void};
use std::collections::HashMap;
use std::sync::Mutex;

use tracing::{debug, info, warn};
use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::original_detour;

use crate::pattern_resolver::CodeRegion;

/// IPC client proxy for IClientUser::GetSteamID. Only callers inside the
/// Steam process reach it; games are served by the CUser entry below.
pub(crate) const GET_STEAM_ID_NAME: &str = "IClientUser::GetSteamID";
/// CUser implementation behind the IClientUser vtable, called by the IPC
/// dispatcher for every pipe, including game processes.
pub(crate) const CUSER_GET_STEAM_ID_NAME: &str = "CUser::GetSteamID";

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

#[cfg(target_pointer_width = "32")]
pub(crate) type CUserGetSteamIdFn = unsafe extern "C" fn(*mut c_void) -> CSteamId;
#[cfg(target_pointer_width = "64")]
pub(crate) type CUserGetSteamIdFn = unsafe extern "C" fn(*mut c_void) -> u64;

pub(crate) static mut GET_STEAM_ID_DETOUR: Option<Detour<GetSteamIdFn>> = None;
pub(crate) static mut CUSER_GET_STEAM_ID_DETOUR: Option<Detour<CUserGetSteamIdFn>> = None;

/// SteamID override already reported for each running app.
static LOGGED_OVERRIDES: Mutex<Option<HashMap<AppId, u64>>> = Mutex::new(None);

fn publish_real_steam_id(steam_id: u64) {
    if super::set_authoritative_steam_id(steam_id) {
        debug!(steam_id, "Steam identity refreshed from IClientUser");
    }
}

fn original_get_steam_id() -> Option<GetSteamIdFn> {
    // SAFETY: installation stores the detour before enabling it.
    unsafe { original_detour(GET_STEAM_ID_NAME, std::ptr::addr_of!(GET_STEAM_ID_DETOUR)) }
}

fn original_cuser_get_steam_id() -> Option<CUserGetSteamIdFn> {
    // SAFETY: installation stores the detour before enabling it.
    unsafe {
        original_detour(
            CUSER_GET_STEAM_ID_NAME,
            std::ptr::addr_of!(CUSER_GET_STEAM_ID_DETOUR),
        )
    }
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
fn call_cuser_get_steam_id(function: CUserGetSteamIdFn, this: *mut c_void) -> u64 {
    // SAFETY: function is the validated 32-bit CUser::GetSteamID entry.
    unsafe { function(this) }.bits
}

#[cfg(target_pointer_width = "64")]
fn call_cuser_get_steam_id(function: CUserGetSteamIdFn, this: *mut c_void) -> u64 {
    // SAFETY: function is the validated 64-bit CUser::GetSteamID entry.
    unsafe { function(this) }
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

#[cfg(target_pointer_width = "32")]
pub(crate) unsafe extern "C" fn hk_cuser_get_steam_id(this: *mut c_void) -> CSteamId {
    CSteamId {
        bits: presented_steam_id(this),
    }
}

#[cfg(target_pointer_width = "64")]
pub(crate) unsafe extern "C" fn hk_cuser_get_steam_id(this: *mut c_void) -> u64 {
    presented_steam_id(this)
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
    real
}

fn presented_steam_id(this: *mut c_void) -> u64 {
    let Some(original) = original_cuser_get_steam_id() else {
        warn!("CUser::GetSteamID original function is unavailable");
        return 0;
    };
    let real = call_cuser_get_steam_id(original, this);
    if real == 0 || !crate::capability::is_ready(crate::capability::Capability::SteamIdOverride) {
        return real;
    }
    // Only IPC requests carry a caller AppID; Steam's own calls keep the real
    // account.
    let Some(app_id) = super::current_app::get().map(AppId) else {
        return real;
    };
    let delegate = if crate::capability::is_ready(crate::capability::Capability::TicketOverrides) {
        vapor_forge_features::ticket::delegate_steamid(app_id)
    } else {
        0
    };
    let configured = super::install::runtime_snapshot()
        .config
        .steam_id
        .get(app_id);
    let presented = select_steam_id(real, delegate, configured);
    if presented != real {
        log_override(app_id, presented, delegate != 0);
    }
    presented
}

/// A delegate ticket's owner wins while its window is open, so the SteamID
/// matches the ticket the app was just given.
fn select_steam_id(real: u64, delegate: u64, configured: Option<u64>) -> u64 {
    if delegate != 0 {
        delegate
    } else {
        configured.unwrap_or(real)
    }
}

fn log_override(app_id: AppId, steam_id: u64, delegate: bool) {
    let mut logged = LOGGED_OVERRIDES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if logged
        .get_or_insert_with(HashMap::new)
        .insert(app_id, steam_id)
        == Some(steam_id)
    {
        return;
    }
    info!(
        app_id = app_id.0,
        steam_id,
        source = if delegate { "delegate" } else { "config" },
        "GetSteamID reporting replacement SteamID"
    );
}

/// Forget the reported overrides of apps that stopped running, so the next
/// launch logs its override again.
pub(crate) fn forget_stopped_overrides(now_playing: &[AppId]) {
    if let Some(logged) = LOGGED_OVERRIDES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_mut()
    {
        logged.retain(|app_id, _| now_playing.contains(app_id));
    }
}

/// The installed entry must still be the bare member read; the hook relies on
/// its return convention.
pub(crate) fn validate_cuser_get_steam_id(code: &CodeRegion, address: usize) -> bool {
    let Some(offset) = address.checked_sub(code.base) else {
        return false;
    };
    vapor_forge_patterns::cuser_adapter::validate_get_steam_id(code.bytes, offset, bitness())
}

pub(crate) fn resolve_cuser_implementation(code: &CodeRegion, entry: usize) -> Option<usize> {
    let offset = entry.checked_sub(code.base)?;
    let implementation = vapor_forge_patterns::cuser_adapter::resolve_get_steam_id_implementation(
        code.bytes,
        code.base as u64,
        offset,
        bitness(),
    )?;
    code.base.checked_add(implementation)
}

const fn bitness() -> u32 {
    if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::select_steam_id;

    const REAL: u64 = 76561198000000001;
    const DELEGATE: u64 = 76561198000000002;
    const CONFIGURED: u64 = 76561198000000003;

    #[test]
    fn real_steam_id_is_kept_without_overrides() {
        assert_eq!(select_steam_id(REAL, 0, None), REAL);
    }

    #[test]
    fn configured_steam_id_replaces_real_account() {
        assert_eq!(select_steam_id(REAL, 0, Some(CONFIGURED)), CONFIGURED);
    }

    #[test]
    fn delegate_window_takes_precedence_over_configuration() {
        assert_eq!(select_steam_id(REAL, DELEGATE, Some(CONFIGURED)), DELEGATE);
        assert_eq!(select_steam_id(REAL, DELEGATE, None), DELEGATE);
    }
}
