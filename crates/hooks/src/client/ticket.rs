use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use retour::GenericDetour;
use tracing::{debug, info, warn};
use vapor_forge_config::AppId;

use crate::original::{detour_or_return, vmt_or_return};
use crate::vmt;

use super::install::{
    config, effective_ticket_mode, read_vtable_slot, script_state, validate_vmt_hook_eligibility,
    TICKET_CACHE,
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
pub(crate) type IsSubscribedInTicketFn = extern "C" fn(*mut c_void, u32, u32, u32, u32) -> u8;
pub(crate) type GetSteamIDFn = extern "C" fn(*mut c_void) -> u64;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut TICKET_EXT_DATA_DETOUR: Option<GenericDetour<TicketExtDataFn>> = None;
pub(crate) static mut UPDATE_TICKET_DETOUR: Option<GenericDetour<UpdateTicketFn>> = None;
pub(crate) static mut IS_SUBSCRIBED_IN_TICKET_DETOUR: Option<
    GenericDetour<IsSubscribedInTicketFn>,
> = None;
pub(crate) static mut ORIG_GET_STEAMID: Option<GetSteamIDFn> = None;
pub(crate) static STEAMID_VMT_DONE: AtomicBool = AtomicBool::new(false);

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
        let persist = if cfg.app_category(AppId(app_id)).is_some() {
            effective_ticket_mode(&cfg, AppId(app_id)) == vapor_forge_config::TicketMode::Delegate
        } else {
            cfg.ticket.cache == vapor_forge_config::TicketCacheMode::Disk
        };
        TICKET_CACHE.store_app_ticket(AppId(app_id), ticket_data, persist);
        return result;
    }

    // Original returned 0, so check if this is a controlled app.
    let cfg = config();
    if cfg.app_category(AppId(app_id)).is_none() {
        return result;
    }

    let ticket_mode = effective_ticket_mode(&cfg, AppId(app_id));
    let ss = script_state();

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
    result
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
    let copy_len = ticket.len().min(buf_size as usize);
    if p_ticket.is_null() || copy_len == 0 {
        return 0;
    }

    // SAFETY: p_ticket is a valid buffer of buf_size bytes, provided by Steam's caller.
    unsafe {
        std::ptr::copy_nonoverlapping(ticket.as_ptr(), p_ticket, copy_len);
    }

    // Fill out offset pointers for the forged ticket structure.
    // Use sensible defaults: signature is the last 128 bytes.
    let sig_size: u32 = 128;
    let total = copy_len as u32;
    let sig_offset = if total > sig_size {
        total - sig_size
    } else {
        0
    };
    let app_offset = if sig_offset >= 4 { sig_offset - 4 } else { 0 };

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

    info!(app_id, size = copy_len, source, "ticket: provided to Steam");
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
    if cfg.app_category(AppId(app_id)).is_some()
        && !vapor_forge_features::apps::is_actually_owned(AppId(app_id))
    {
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

pub(crate) extern "C" fn hk_is_subscribed_in_ticket(
    this: *mut c_void,
    app_id: u32,
    arg2: u32,
    arg3: u32,
    arg4: u32,
) -> u8 {
    let cfg = config();
    if cfg.app_category(AppId(app_id)).is_some()
        && !vapor_forge_features::apps::is_actually_owned(AppId(app_id))
    {
        debug!(app_id, "ticket: IsUserSubscribedAppInTicket resolved");
        return 1;
    }

    // SAFETY: IS_SUBSCRIBED_IN_TICKET_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!(
        "IsUserSubscribedAppInTicket",
        IS_SUBSCRIBED_IN_TICKET_DETOUR,
        0
    );
    original.call(this, app_id, arg2, arg3, arg4)
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
    if STEAMID_VMT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }

    let Some(slot) = crate::vtable_scan::slot_of("IClientUser", "GetSteamID") else {
        warn!("hook-install: GetSteamID slot not found in VtableScan");
        return;
    };

    let Some(addr) = (unsafe { read_vtable_slot(this, slot) }) else {
        return;
    };
    let repl = hk_get_steamid as *const () as usize;

    if !validate_vmt_hook_eligibility("GetSteamID", addr, repl) {
        return;
    }

    // SAFETY: transmuting a valid function address to a typed fn pointer.
    let orig_fn: GetSteamIDFn = unsafe { std::mem::transmute(addr) };
    unsafe { std::ptr::addr_of_mut!(ORIG_GET_STEAMID).write(Some(orig_fn)) };

    // SAFETY: swap the vtable slot (original already stored).
    unsafe {
        vmt::swap_vtable_slot("GetSteamID", this, slot, repl);
    }
}
