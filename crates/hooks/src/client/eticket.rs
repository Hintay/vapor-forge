use core::ffi::c_void;

use tracing::{debug, info};
use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;

use super::install::{runtime_snapshot, TICKET_CACHE};
use vapor_forge_hook_engine::original::detour_or_return;

// ---------------------------------------------------------------------------
// Detour names (used by resolve_cuser_adapter)
// ---------------------------------------------------------------------------

pub(crate) const GET_ENCRYPTED_NAME: &str = "IClientUser::GetEncryptedAppTicket";

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type GetEncryptedAppTicketFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, i32, *mut u32) -> bool;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut GET_ENCRYPTED_DETOUR: Option<Detour<GetEncryptedAppTicketFn>> = None;

fn cached_ticket_fits(needed: usize, cb_max: i32, ticket_is_null: bool) -> bool {
    !ticket_is_null && (needed as i64) <= i64::from(cb_max)
}

// ---------------------------------------------------------------------------
// Hook: IClientUser::GetEncryptedAppTicket
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_get_encrypted_app_ticket(
    this: *mut c_void,
    p_ticket: *mut u8,
    cb_max: i32,
    p_cb_used: *mut u32,
) -> bool {
    let original = detour_or_return!("GetEncryptedAppTicket", GET_ENCRYPTED_DETOUR, false);
    if !crate::capability::is_ready(crate::capability::Capability::TicketOverrides) {
        // SAFETY: forwards Steam's untouched encrypted-ticket query.
        return unsafe { original(this, p_ticket, cb_max, p_cb_used) };
    }
    let app_id = super::current_app::get().unwrap_or(0);
    if app_id != 0 {
        let runtime = runtime_snapshot();
        let controlled = vapor_forge_features::apps::classify_app(&runtime.config, AppId(app_id))
            .requires_injected_ownership();
        if controlled {
            if let Some(bytes) =
                TICKET_CACHE.get_enc_ticket(AppId(app_id), &runtime.script_state.enc_tickets)
            {
                let needed = bytes.len();
                if cached_ticket_fits(needed, cb_max, p_ticket.is_null()) {
                    // SAFETY: cached_ticket_fits verified a non-null destination with
                    // room for `needed` bytes; p_cb_used is checked before writing.
                    unsafe {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p_ticket, needed);
                        if !p_cb_used.is_null() {
                            *p_cb_used = needed as u32;
                        }
                    }
                    info!(
                        app_id,
                        size = needed,
                        "eticket: returned cached encrypted ticket"
                    );
                    return true;
                }
                if !p_cb_used.is_null() {
                    // SAFETY: Steam supplied this optional output pointer and it is non-null.
                    unsafe { *p_cb_used = needed as u32 };
                }
                debug!(
                    app_id,
                    needed, cb_max, "eticket: buffer too small, reported required size"
                );
                return false;
            }
        }
    }

    // SAFETY: forwards Steam's untouched encrypted-ticket query.
    unsafe { original(this, p_ticket, cb_max, p_cb_used) }
}

#[cfg(test)]
mod tests {
    use super::cached_ticket_fits;

    #[test]
    fn cached_ticket_fits_requires_non_null_and_room() {
        assert!(cached_ticket_fits(128, 128, false));
        assert!(cached_ticket_fits(128, 1024, false));
        assert!(!cached_ticket_fits(128, 1024, true));
        assert!(!cached_ticket_fits(0, 0, true));
        assert!(!cached_ticket_fits(129, 128, false));
        assert!(!cached_ticket_fits(1, 0, false));
        assert!(!cached_ticket_fits(1, -1, false));
    }
}
