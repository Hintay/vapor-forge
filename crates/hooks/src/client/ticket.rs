use core::ffi::c_void;
use std::sync::OnceLock;

use retour::GenericDetour;
use tracing::{debug, info, warn};
use vapor_forge_config::AppId;

use crate::original::{detour_or_return, vmt_or_return};
use crate::vmt;

use super::install::{
    config, effective_ticket_mode, read_vtable_slot, runtime_snapshot,
    validate_vmt_hook_eligibility, TICKET_CACHE,
};

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type TicketExtDataFn = extern "C" fn(
    *mut c_void, // this (CUser)
    u32,         // app_id
    *mut u8,     // p_ticket buffer
    u32,         // ticket_buf_size
    *mut u32,    // pi_app_id (out)
    *mut u32,    // pi_steam_id (out)
    *mut u32,    // pi_signature (out)
    *mut u32,    // pcb_signature (out)
) -> u32;
pub(crate) type UpdateTicketFn = extern "C" fn(*mut c_void, u32, bool) -> u32;
#[cfg(target_pointer_width = "32")]
pub(crate) type IsSubscribedInTicketFn = extern "C" fn(*mut c_void, u32, u32, u32, u32) -> u8;
#[cfg(target_pointer_width = "64")]
pub(crate) type IsSubscribedInTicketFn = extern "C" fn(*mut c_void, u64, *const u64, u32) -> u8;
pub(crate) type GetSteamIDFn = extern "C" fn(*mut c_void) -> u64;

const USER_HAS_LICENSE_FOR_APP_RESULT_HAS_LICENSE: u8 = 0;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut TICKET_EXT_DATA_DETOUR: Option<GenericDetour<TicketExtDataFn>> = None;
pub(crate) static mut UPDATE_TICKET_DETOUR: Option<GenericDetour<UpdateTicketFn>> = None;
pub(crate) static mut IS_SUBSCRIBED_IN_TICKET_DETOUR: Option<
    GenericDetour<IsSubscribedInTicketFn>,
> = None;
pub(crate) static mut ORIG_GET_STEAMID: Option<GetSteamIDFn> = None;
static STEAMID_VMT_GATE: vmt::InstallGate = vmt::InstallGate::new();

/// Source ticket from appId 7, lazily acquired on first derivation attempt.
pub(crate) static SOURCE_TICKET_7: OnceLock<Option<Vec<u8>>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Hook replacement functions: GetAppOwnershipTicketExtendedData (ticket forge)
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_ticket_ext_data(
    this: *mut c_void,
    app_id: u32,
    p_ticket: *mut u8,
    ticket_buf_size: u32,
    pi_app_id: *mut u32,
    pi_steam_id: *mut u32,
    pi_signature: *mut u32,
    pcb_signature: *mut u32,
) -> u32 {
    let runtime = runtime_snapshot();
    let authority = vapor_forge_features::apps::classify_app(&runtime.config, AppId(app_id));
    if authority.requires_injected_ownership() {
        return provide_local_ticket(
            this,
            app_id,
            p_ticket,
            ticket_buf_size,
            pi_app_id,
            pi_steam_id,
            pi_signature,
            pcb_signature,
            &runtime,
        );
    }

    // SAFETY: TICKET_EXT_DATA_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!(
        "GetAppOwnershipTicketExtendedData",
        TICKET_EXT_DATA_DETOUR,
        0
    );
    let result = original.call(
        this,
        app_id,
        p_ticket,
        ticket_buf_size,
        pi_app_id,
        pi_steam_id,
        pi_signature,
        pcb_signature,
    );

    // If Steam returned a valid ticket, cache it.
    // Persist decision:
    //   Controlled + delegate → always disk (cross-account)
    //   Controlled + forge   → never disk (re-acquirable)
    //   Uncontrolled (real)  → follows [ticket] cache setting
    if result > 0 && !p_ticket.is_null() {
        let size = result as usize;
        // SAFETY: p_ticket points to a buffer with at least `result` bytes written by Steam.
        let ticket_data = unsafe { std::slice::from_raw_parts(p_ticket, size) }.to_vec();
        let cfg = config();
        let persist = if cfg.is_controlled_app(AppId(app_id)) {
            effective_ticket_mode(&cfg, AppId(app_id)) == vapor_forge_config::TicketMode::Delegate
        } else {
            cfg.ticket.cache == vapor_forge_config::TicketCacheMode::Disk
        };
        TICKET_CACHE.store_app_ticket(AppId(app_id), ticket_data, persist);
        return result;
    }

    result
}

#[allow(clippy::too_many_arguments)] // Mirrors Steam's FFI output parameters.
fn provide_local_ticket(
    this: *mut c_void,
    app_id: u32,
    p_ticket: *mut u8,
    ticket_buf_size: u32,
    pi_app_id: *mut u32,
    pi_steam_id: *mut u32,
    pi_signature: *mut u32,
    pcb_signature: *mut u32,
    runtime: &super::install::RuntimeSnapshot,
) -> u32 {
    let cfg = &runtime.config;
    let ticket_mode = effective_ticket_mode(cfg, AppId(app_id));
    let ss = &runtime.script_state;

    // Delegate mode: while inside the initial request window, prefer the
    // cached ticket (from a previous owner session) over forging so the
    // ticket's embedded SteamID matches an account that actually owns the
    // app. Once the window closes, fall through to the normal forge path
    // and stop spoofing GetSteamID.
    if ticket_mode == vapor_forge_config::TicketMode::Delegate {
        if vapor_forge_features::ticket::in_delegate_window(AppId(app_id)) {
            if let Some(ticket) = TICKET_CACHE.get_app_ticket(AppId(app_id), &ss.app_tickets) {
                if let Some(steamid) = extract_steamid_from_ticket(&ticket) {
                    vapor_forge_features::ticket::set_delegate_steamid(steamid);
                }
                return copy_ticket_to_buffer(
                    &ticket,
                    p_ticket,
                    ticket_buf_size,
                    pi_app_id,
                    pi_steam_id,
                    pi_signature,
                    pcb_signature,
                    app_id,
                    "delegate-cached",
                );
            }
            // No cached ticket available yet, fall through to forge below.
            debug!(
                app_id,
                "ticket: delegate window active but no cached ticket, forging"
            );
        } else {
            vapor_forge_features::ticket::clear_delegate_steamid();
        }
    }

    // Try to provide a ticket from cache / Lua / forge
    if let Some(ticket) = TICKET_CACHE.get_app_ticket(AppId(app_id), &ss.app_tickets) {
        return copy_ticket_to_buffer(
            &ticket,
            p_ticket,
            ticket_buf_size,
            pi_app_id,
            pi_steam_id,
            pi_signature,
            pcb_signature,
            app_id,
            "cached",
        );
    }

    // Forge from appId 7 source ticket
    if let Some(forged) = try_forge_ticket(this, app_id) {
        return copy_ticket_to_buffer(
            &forged.data,
            p_ticket,
            ticket_buf_size,
            pi_app_id,
            pi_steam_id,
            pi_signature,
            pcb_signature,
            app_id,
            "forged",
        );
    }

    debug!(
        app_id,
        "ticket: no ticket available (no cache, no source for forge)"
    );
    0
}

/// Extract the SteamID embedded in a raw ownership ticket, using the
/// standard `TICKET_STEAMID_OFFSET` (byte 8, little-endian u64). Returns
/// `None` if the ticket is too small to contain a SteamID field.
pub(crate) fn extract_steamid_from_ticket(ticket: &[u8]) -> Option<u64> {
    const STEAMID_OFFSET: usize = 8;
    let end = STEAMID_OFFSET.checked_add(8)?;
    let bytes: [u8; 8] = ticket.get(STEAMID_OFFSET..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Copy ticket data into the output buffer and populate offset pointers.
#[allow(clippy::too_many_arguments)] // Mirrors Steam's FFI output parameters.
pub(crate) fn copy_ticket_to_buffer(
    ticket: &[u8],
    p_ticket: *mut u8,
    buf_size: u32,
    pi_app_id: *mut u32,
    pi_steam_id: *mut u32,
    pi_signature: *mut u32,
    pcb_signature: *mut u32,
    app_id: u32,
    source: &str,
) -> u32 {
    const SIGNATURE_SIZE: usize = 128;
    const STEAM_ID_END: usize = 16;
    let minimum_size = SIGNATURE_SIZE + 4;
    if p_ticket.is_null()
        || ticket.len() < minimum_size.max(STEAM_ID_END)
        || ticket.len() > buf_size as usize
        || ticket.len() > u32::MAX as usize
    {
        return 0;
    }

    // SAFETY: p_ticket is a valid buffer of buf_size bytes, provided by Steam's caller.
    unsafe {
        std::ptr::copy_nonoverlapping(ticket.as_ptr(), p_ticket, ticket.len());
    }

    // Fill out offset pointers for the forged ticket structure.
    // Use sensible defaults: signature is the last 128 bytes.
    let sig_size = SIGNATURE_SIZE as u32;
    let total = ticket.len() as u32;
    let sig_offset = total - sig_size;
    let app_offset = sig_offset - 4;

    if !pi_app_id.is_null() {
        // SAFETY: pi_app_id is a valid pointer from Steam's caller.
        unsafe { *pi_app_id = app_offset };
    }
    if !pi_steam_id.is_null() {
        // SAFETY: pi_steam_id is a valid pointer from Steam's caller.
        unsafe { *pi_steam_id = 8 };
    }
    if !pi_signature.is_null() {
        // SAFETY: pi_signature is a valid pointer from Steam's caller.
        unsafe { *pi_signature = sig_offset };
    }
    if !pcb_signature.is_null() {
        // SAFETY: pcb_signature is a valid pointer from Steam's caller.
        unsafe { *pcb_signature = sig_size };
    }

    info!(
        app_id,
        size = ticket.len(),
        source,
        "ticket: provided to Steam"
    );
    total
}

/// Try to forge a ticket for `target_app_id` from the appId 7 source ticket.
pub(crate) fn try_forge_ticket(
    this: *mut c_void,
    target_app_id: u32,
) -> Option<vapor_forge_features::ticket::forge::ForgedTicket> {
    use vapor_forge_features::ticket::forge;

    let source = SOURCE_TICKET_7.get_or_init(|| acquire_source_ticket(this));

    let source_data = source.as_ref()?;
    let forged = forge::forge_from_source(source_data, target_app_id);
    if forged.is_some() {
        info!(target_app_id, "ticket: derived from appId 7 source");
    }
    forged
}

/// Acquire the source ticket (appId 7) by calling the original function directly.
pub(crate) fn acquire_source_ticket(this: *mut c_void) -> Option<Vec<u8>> {
    const BUF_SIZE: u32 = 4096;
    let mut buf = vec![0u8; BUF_SIZE as usize];
    let mut app_id_off: u32 = 0;
    let mut steam_id_off: u32 = 0;
    let mut sig_off: u32 = 0;
    let mut sig_size: u32 = 0;

    // SAFETY: TICKET_EXT_DATA_DETOUR set before hook enabled; calling the original.
    let size = unsafe {
        (*std::ptr::addr_of!(TICKET_EXT_DATA_DETOUR))
            .as_ref()?
            .call(
                this,
                vapor_forge_features::ticket::forge::SOURCE_APP_ID,
                buf.as_mut_ptr(),
                BUF_SIZE,
                &mut app_id_off,
                &mut steam_id_off,
                &mut sig_off,
                &mut sig_size,
            )
    };

    if size == 0 {
        warn!("ticket: failed to acquire source ticket (appId 7)");
        return None;
    }

    buf.truncate(size as usize);
    info!(size, "ticket: acquired source ticket from appId 7");
    Some(buf)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: BUpdateAppOwnershipTicket
// ---------------------------------------------------------------------------

pub(crate) extern "C" fn hk_update_ticket(this: *mut c_void, app_id: u32, force: bool) -> u32 {
    let cfg = config();
    if vapor_forge_features::apps::classify_app(&cfg, AppId(app_id)).requires_injected_ownership() {
        // For controlled apps, report success without asking Steam to update
        // (the real update would fail for apps we don't own).
        debug!(app_id, "ticket: BUpdateAppOwnershipTicket handled");
        return 1;
    }

    // SAFETY: UPDATE_TICKET_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("BUpdateAppOwnershipTicket", UPDATE_TICKET_DETOUR, 0);
    original.call(this, app_id, force)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: IsUserSubscribedAppInTicket
// ---------------------------------------------------------------------------

#[cfg(target_pointer_width = "32")]
pub(crate) extern "C" fn hk_is_subscribed_in_ticket(
    this: *mut c_void,
    steam_id_low: u32,
    steam_id_high: u32,
    game_id_ptr: u32,
    app_id: u32,
) -> u8 {
    if is_controlled_unowned_ticket_app(app_id) {
        debug!(app_id, "ticket: IsUserSubscribedAppInTicket resolved");
        return USER_HAS_LICENSE_FOR_APP_RESULT_HAS_LICENSE;
    }

    // SAFETY: IS_SUBSCRIBED_IN_TICKET_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!(
        "IsUserSubscribedAppInTicket",
        IS_SUBSCRIBED_IN_TICKET_DETOUR,
        0
    );
    original.call(this, steam_id_low, steam_id_high, game_id_ptr, app_id)
}

#[cfg(target_pointer_width = "64")]
pub(crate) extern "C" fn hk_is_subscribed_in_ticket(
    this: *mut c_void,
    steam_id: u64,
    game_id_ptr: *const u64,
    app_id: u32,
) -> u8 {
    if is_controlled_unowned_ticket_app(app_id) {
        debug!(app_id, "ticket: IsUserSubscribedAppInTicket resolved");
        return USER_HAS_LICENSE_FOR_APP_RESULT_HAS_LICENSE;
    }

    // SAFETY: IS_SUBSCRIBED_IN_TICKET_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!(
        "IsUserSubscribedAppInTicket",
        IS_SUBSCRIBED_IN_TICKET_DETOUR,
        0
    );
    original.call(this, steam_id, game_id_ptr, app_id)
}

fn is_controlled_unowned_ticket_app(app_id: u32) -> bool {
    let cfg = config();
    vapor_forge_features::apps::classify_app(&cfg, AppId(app_id)).requires_injected_ownership()
}

// ---------------------------------------------------------------------------
// Hook replacement functions: IClientUser::GetSteamID (ticket-delegate spoof)
// ---------------------------------------------------------------------------

/// Return the delegate (previous owner) SteamID while a delegate ticket
/// window is active for the currently launched app, otherwise pass through.
///
/// This spoof is global rather than keyed to a specific app: the runtime
/// only supports one delegate-ticket app being active at a time, which
/// matches the existing single-game-at-a-time launch model.
extern "C" fn hk_get_steamid(this: *mut c_void) -> u64 {
    // SAFETY: ORIG_GET_STEAMID set before the VMT slot is swapped.
    let original = vmt_or_return!("GetSteamID", ORIG_GET_STEAMID, 0);
    let real_steamid = original(this);

    let delegate = vapor_forge_features::ticket::delegate_steamid();
    if delegate != 0 {
        debug!(
            real = real_steamid,
            delegate, "ticket: GetSteamID returning delegate SteamID"
        );
        return delegate;
    }

    real_steamid
}

pub(crate) fn install_steamid_vmt(this: *mut c_void) {
    let Some(attempt) = STEAMID_VMT_GATE.begin() else {
        return;
    };

    let Some(slot) = crate::vtable_scan::slot_of("IClientUser", "GetSteamID") else {
        warn!("hook-install: GetSteamID slot not found in VtableScan");
        attempt.disable();
        return;
    };

    // SAFETY: this is the live IClientUser object passed by Steam.
    let Some(addr) = (unsafe { read_vtable_slot(this, slot) }) else {
        return;
    };
    let repl = hk_get_steamid as *const () as usize;

    if !validate_vmt_hook_eligibility("GetSteamID", addr, repl) {
        attempt.disable();
        return;
    }

    // SAFETY: transmuting a valid function address to a typed fn pointer.
    let orig_fn: GetSteamIDFn = unsafe { std::mem::transmute(addr) };
    // SAFETY: initialization is serialized before replacing the VMT slot.
    unsafe { std::ptr::addr_of_mut!(ORIG_GET_STEAMID).write(Some(orig_fn)) };

    // SAFETY: swap the vtable slot (original already stored).
    if unsafe { vmt::swap_vtable_slot("GetSteamID", this, slot, repl) }.is_some() {
        attempt.commit();
    }
}

pub(crate) fn steamid_vmt_settled() -> bool {
    STEAMID_VMT_GATE.is_settled()
}

#[cfg(test)]
mod tests {
    use super::copy_ticket_to_buffer;

    #[test]
    fn copy_ticket_rejects_short_ticket() {
        let ticket = vec![0xAA; 64];
        let mut output = vec![0u8; 256];
        assert_eq!(
            copy_ticket_to_buffer(
                &ticket,
                output.as_mut_ptr(),
                output.len() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                480,
                "test",
            ),
            0
        );
    }

    #[test]
    fn copy_ticket_rejects_truncation_and_reports_valid_offsets() {
        let ticket = vec![0xAA; 256];
        let mut short_output = vec![0u8; 128];
        assert_eq!(
            copy_ticket_to_buffer(
                &ticket,
                short_output.as_mut_ptr(),
                short_output.len() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                480,
                "test",
            ),
            0
        );

        let mut output = vec![0u8; ticket.len()];
        let (mut app, mut steam, mut signature, mut signature_size) = (0, 0, 0, 0);
        assert_eq!(
            copy_ticket_to_buffer(
                &ticket,
                output.as_mut_ptr(),
                output.len() as u32,
                &mut app,
                &mut steam,
                &mut signature,
                &mut signature_size,
                480,
                "test",
            ),
            ticket.len() as u32
        );
        assert_eq!((app, steam, signature, signature_size), (124, 8, 128, 128));
        assert_eq!(output, ticket);
    }
}
