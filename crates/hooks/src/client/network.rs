use core::ffi::c_void;

use vapor_forge_hook_engine::detour::Detour;

use crate::netpacket::SendFrameDecision;
use vapor_forge_hook_engine::original::detour_or_return;

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type BBuildAndAsyncSendFrameFn =
    unsafe extern "C" fn(*mut c_void, i32, *mut u8, u32) -> bool;
pub(crate) type RecvPktFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;

// ---------------------------------------------------------------------------
// Static detour slots
// ---------------------------------------------------------------------------

pub(crate) static mut SEND_FRAME_DETOUR: Option<Detour<BBuildAndAsyncSendFrameFn>> = None;
pub(crate) static mut RECV_PKT_DETOUR: Option<Detour<RecvPktFn>> = None;

// ---------------------------------------------------------------------------
// Hook replacement functions: BBuildAndAsyncSendFrame (outgoing WS frames)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_send_frame(
    this: *mut c_void,
    opcode: i32,
    data: *mut u8,
    size: u32,
) -> bool {
    super::client_id::refresh_device_descriptor();

    const WEBSOCKET_BINARY: i32 = 2;
    if opcode == WEBSOCKET_BINARY && !data.is_null() && size > 0 {
        // SAFETY: data is a valid buffer of `size` bytes, provided by Steam.
        let slice = unsafe { std::slice::from_raw_parts(data, size as usize) };

        match crate::netpacket::decide_send_frame(slice) {
            SendFrameDecision::Pass => {}
            SendFrameDecision::Drop => return true,
            SendFrameDecision::Rewrite(rewritten) => {
                // SAFETY: calling original with rewritten data.
                let original =
                    detour_or_return!("BBuildAndAsyncSendFrame", SEND_FRAME_DETOUR, false);
                return // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(
                    this,
                    opcode,
                    rewritten.as_ptr() as *mut u8,
                    rewritten.len() as u32,
                ) };
            }
        }
    }

    // SAFETY: SEND_FRAME_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("BBuildAndAsyncSendFrame", SEND_FRAME_DETOUR, false);
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(this, opcode, data, size) }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: RecvPkt (incoming packets)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_recv_pkt(this: *mut c_void, packet: *mut c_void) -> *mut c_void {
    // Try to inject fabricated responses from completed fetches.
    // SAFETY: this and packet are valid pointers from Steam's caller.
    // The closure calls the original RecvPkt.
    let call_original = |t, p| {
        let original = detour_or_return!("RecvPkt", RECV_PKT_DETOUR, std::ptr::null_mut());
        // SAFETY: the typed original and unchanged callback arguments satisfy
        // RecvPkt's ABI contract.
        unsafe { original(t, p) }
    };
    // SAFETY: this and packet are the unchanged arguments supplied by Steam.
    unsafe {
        crate::netpacket::try_inject(this, packet, call_original);
    }

    // Process the real packet normally
    // SAFETY: RECV_PKT_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("RecvPkt", RECV_PKT_DETOUR, std::ptr::null_mut());
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, packet) };

    // Post-process: strip achievement stats from incoming responses
    if !packet.is_null() {
        // SAFETY: packet remains valid for the duration of the hook callback.
        unsafe { crate::netpacket::on_recv_packet(packet) };
    }

    result
}
