use core::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use tracing::{debug, info, warn};
use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;

use super::install::{runtime_snapshot, TICKET_CACHE};
use vapor_forge_hook_engine::original::detour_or_return;

// ---------------------------------------------------------------------------
// Detour names (used by resolve_cuser_adapter)
// ---------------------------------------------------------------------------

pub(crate) const REQUEST_ENCRYPTED_NAME: &str = "IClientUser::RequestEncryptedAppTicket";
pub(crate) const GET_ENCRYPTED_NAME: &str = "IClientUser::GetEncryptedAppTicket";

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type RequestEncryptedAppTicketFn =
    unsafe extern "C" fn(*mut c_void, *const c_void, i32) -> u64;

pub(crate) type GetEncryptedAppTicketFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, i32, *mut u32) -> bool;

// CSteamEngine::SetAPICallResult — resolved by pattern, called directly.
//
// i686:
//   void SetAPICallResult(
//       CSteamEngine* this,    // [ebp+0x08]
//       void*         pipe,    // [ebp+0x0c]  null = broadcast
//       uint32        hCall_lo,// [ebp+0x10]
//       uint32        hCall_hi,// [ebp+0x14]  ┘ SteamAPICall_t
//       int32         bPost,   // [ebp+0x18]
//       const void*   pvParam, // [ebp+0x1c]  result payload
//       int32         cubParam,// [ebp+0x20]  payload size
//       int32         iCallback// [ebp+0x24]  callback type id
//   );
//
// x86_64 register mapping:
//   rdi=this, rsi=pipe, rdx=hCall, ecx=bPost,
//   r8=pvParam, r9d=cubParam, [rsp+0x08]=iCallback
#[cfg(target_pointer_width = "32")]
type SetAPICallResultFn = unsafe extern "C" fn(
    *mut c_void,   // this
    *mut c_void,   // pipe
    u32,           // hAsyncCall low
    u32,           // hAsyncCall high
    i32,           // bPostCallback
    *const c_void, // pvParam
    i32,           // cubParam
    i32,           // iCallback
);

#[cfg(target_pointer_width = "64")]
type SetAPICallResultFn = unsafe extern "C" fn(
    *mut c_void,   // this
    *mut c_void,   // pipe
    u64,           // hAsyncCall
    i32,           // bPostCallback
    *const c_void, // pvParam
    i32,           // cubParam
    i32,           // iCallback
);

// ---------------------------------------------------------------------------
// EncryptedAppTicketResponse_t
// ---------------------------------------------------------------------------

const ETICKET_RESPONSE_K_ICALLBACK: i32 = 154;
const ERESULT_OK: i32 = 1;

#[repr(C)]
struct EncryptedAppTicketResponse {
    m_eresult: i32,
}

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) type SteamEngineInitFn = unsafe extern "C" fn(*mut c_void);

pub(crate) static mut REQUEST_ENCRYPTED_DETOUR: Option<Detour<RequestEncryptedAppTicketFn>> = None;
pub(crate) static mut GET_ENCRYPTED_DETOUR: Option<Detour<GetEncryptedAppTicketFn>> = None;
pub(crate) static mut STEAM_ENGINE_INIT_DETOUR: Option<Detour<SteamEngineInitFn>> = None;

static FN_SET_API_CALL_RESULT: AtomicUsize = AtomicUsize::new(0);
static CSTEAM_ENGINE: AtomicUsize = AtomicUsize::new(0);

static LOCAL_ETICKET_REQUESTS: Mutex<Vec<(u32, usize)>> = Mutex::new(Vec::new());

fn reserve_local_eticket_request(app_id: u32) {
    let mut requests = LOCAL_ETICKET_REQUESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, pending)) = requests.iter_mut().find(|(id, _)| *id == app_id) {
        *pending = pending.saturating_add(1);
    } else {
        requests.push((app_id, 1));
    }
}

pub(crate) fn take_local_eticket_request(app_id: AppId) -> bool {
    let mut requests = LOCAL_ETICKET_REQUESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(index) = requests.iter().position(|(id, _)| *id == app_id.0) else {
        return false;
    };
    if requests[index].1 == 1 {
        requests.swap_remove(index);
    } else {
        requests[index].1 -= 1;
    }
    true
}

fn local_completion_ready() -> bool {
    CSTEAM_ENGINE.load(Ordering::Acquire) != 0
        && FN_SET_API_CALL_RESULT.load(Ordering::Acquire) != 0
}

fn cached_ticket_fits(needed: usize, cb_max: i32, ticket_is_null: bool) -> bool {
    !ticket_is_null && (needed as i64) <= i64::from(cb_max)
}

// ---------------------------------------------------------------------------
// Pattern resolution (called from do_install)
// ---------------------------------------------------------------------------

pub(crate) fn resolve_set_api_call_result(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    registry: &vapor_forge_patterns::registry::PatternRegistry,
) {
    let entry = match registry.get("CSteamEngine::SetAPICallResult") {
        Some(e) => e,
        None => {
            debug!("eticket: CSteamEngine::SetAPICallResult not in registry");
            return;
        }
    };
    if let Some(addr) = vapor_forge_hook_engine::detour::resolve_pattern_entry(
        code,
        "CSteamEngine::SetAPICallResult",
        &entry,
    ) {
        FN_SET_API_CALL_RESULT.store(addr, Ordering::Release);
        info!(
            va = format_args!("0x{addr:x}"),
            "eticket: SetAPICallResult resolved"
        );
    } else {
        warn!("eticket: CSteamEngine::SetAPICallResult not resolved");
    }
}

// ---------------------------------------------------------------------------
// CSteamEngine::Init hook (captures CSteamEngine*)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_steam_engine_init(this: *mut c_void) {
    let original = detour_or_return!("CSteamEngine::Init", STEAM_ENGINE_INIT_DETOUR);
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(this) };

    if !this.is_null() && CSTEAM_ENGINE.load(Ordering::Relaxed) == 0 {
        CSTEAM_ENGINE.store(this as usize, Ordering::Release);
        info!(
            va = format_args!("0x{:x}", this as usize),
            "eticket: CSteamEngine captured"
        );
    }
}

fn call_set_api_call_result(h_async_call: u64, app_id: u32) {
    let this = CSTEAM_ENGINE.load(Ordering::Acquire);
    if this == 0 {
        warn!(
            app_id,
            "eticket: CSteamEngine not captured, cannot pre-plant result"
        );
        return;
    }
    let set_fn_addr = FN_SET_API_CALL_RESULT.load(Ordering::Acquire);
    if set_fn_addr == 0 {
        warn!(app_id, "eticket: SetAPICallResult not resolved");
        return;
    }
    // SAFETY: resolved from steamclient.so executable code at init time.
    let set_fn = unsafe { std::mem::transmute::<usize, SetAPICallResultFn>(set_fn_addr) };

    let response = EncryptedAppTicketResponse {
        m_eresult: ERESULT_OK,
    };

    #[cfg(target_pointer_width = "32")]
    {
        // SAFETY: set_fn is the validated 32-bit SetAPICallResult entry and
        // response remains live for the duration of the call.
        unsafe {
            set_fn(
                this as *mut c_void,
                std::ptr::null_mut(),
                h_async_call as u32,
                (h_async_call >> 32) as u32,
                1, // bPostCallback
                &response as *const EncryptedAppTicketResponse as *const c_void,
                std::mem::size_of::<EncryptedAppTicketResponse>() as i32,
                ETICKET_RESPONSE_K_ICALLBACK,
            )
        };
    }

    #[cfg(target_pointer_width = "64")]
    {
        /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
        unsafe {
            set_fn(
                this as *mut c_void,
                std::ptr::null_mut(),
                h_async_call,
                1, // bPostCallback
                &response as *const EncryptedAppTicketResponse as *const c_void,
                std::mem::size_of::<EncryptedAppTicketResponse>() as i32,
                ETICKET_RESPONSE_K_ICALLBACK,
            )
        };
    }

    info!(
        app_id,
        h_async_call, "eticket: pre-planted OK via SetAPICallResult"
    );
}

// ---------------------------------------------------------------------------
// Hook: IClientUser::RequestEncryptedAppTicket
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_request_encrypted_app_ticket(
    this: *mut c_void,
    p_data: *const c_void,
    cb_data: i32,
) -> u64 {
    let original = detour_or_return!("RequestEncryptedAppTicket", REQUEST_ENCRYPTED_DETOUR, 0u64);

    let app_id = super::current_app::get().unwrap_or(0);
    let serve_local = app_id != 0 && {
        let runtime = runtime_snapshot();
        vapor_forge_features::apps::classify_app(&runtime.config, AppId(app_id))
            .requires_injected_ownership()
            && TICKET_CACHE
                .get_enc_ticket(AppId(app_id), &runtime.script_state.enc_tickets)
                .is_some()
            && local_completion_ready()
    };
    if serve_local {
        reserve_local_eticket_request(app_id);
    }

    let h_async_call = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, p_data, cb_data) };
    if h_async_call == 0 {
        if serve_local {
            let _ = take_local_eticket_request(AppId(app_id));
        }
        return 0;
    }

    if serve_local {
        call_set_api_call_result(h_async_call, app_id);
    } else {
        debug!(
            app_id,
            h_async_call, "eticket: passing RequestEncryptedAppTicket through"
        );
    }
    h_async_call
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

    let original = detour_or_return!("GetEncryptedAppTicket", GET_ENCRYPTED_DETOUR, false);
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(this, p_ticket, cb_max, p_cb_used) }
}

#[cfg(test)]
mod tests {
    use super::{cached_ticket_fits, reserve_local_eticket_request, take_local_eticket_request};
    use vapor_forge_config::AppId;

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

    #[test]
    fn local_request_reservations_are_consumed_once() {
        let app = 991_001;
        assert!(!take_local_eticket_request(AppId(app)));
        reserve_local_eticket_request(app);
        assert!(take_local_eticket_request(AppId(app)));
        assert!(!take_local_eticket_request(AppId(app)));
    }

    #[test]
    fn local_request_reservations_count_per_app() {
        let served = 991_002;
        let other = 991_003;
        reserve_local_eticket_request(served);
        reserve_local_eticket_request(served);
        assert!(!take_local_eticket_request(AppId(other)));
        assert!(take_local_eticket_request(AppId(served)));
        assert!(take_local_eticket_request(AppId(served)));
        assert!(!take_local_eticket_request(AppId(served)));
    }
}
