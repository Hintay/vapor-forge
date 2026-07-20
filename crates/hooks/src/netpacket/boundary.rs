use std::ffi::c_void;

use tracing::info;
use vapor_forge_features::{achievements, request_code, rich_presence};
use vapor_forge_packet_capture::{PacketChange, PacketDirection};
use vapor_forge_steam_native_abi::cnet_packet;

use super::router::{process_recv_frame, CLOUD_PENDING, LOCAL_RESPONSES, PENDING};

/// Check for pending responses and inject them through the current carrier packet.
///
/// # Safety
/// `this` and `packet` must be valid pointers as passed to `RecvPkt`.
pub(crate) unsafe fn try_inject<F>(this: *mut c_void, packet: *mut c_void, call_original: F)
where
    F: Fn(*mut c_void, *mut c_void) -> *mut c_void,
{
    let rp_inject_due = rich_presence::tracked_app().0 != 0 && rich_presence::has_inject_pending();
    if PENDING.is_empty()
        && CLOUD_PENDING.is_empty()
        && LOCAL_RESPONSES.lock().unwrap().is_empty()
        && !achievements::has_offline_responses()
        && !rp_inject_due
    {
        return;
    }
    if packet.is_null() {
        return;
    }

    for entry in PENDING.drain_completed() {
        let response = request_code::build_response_packet(
            &entry.req_hdr_bytes,
            entry.job_id,
            entry.gid,
            entry.code,
        );
        info!(
            gid = entry.gid,
            job_id = entry.job_id,
            code = entry.code,
            "netpacket: injecting manifest response"
        );
        // SAFETY: packet is valid for this callback and restored after the call.
        unsafe { inject_captured(this, packet, response, &call_original) };
    }

    for response in CLOUD_PENDING.drain_completed() {
        // Cumulus upload responses contain bearer credentials and are not captured.
        // SAFETY: packet is valid for this callback and the guard restores it.
        let _guard = unsafe { PacketSwapGuard::new(packet, response) };
        call_original(this, packet);
    }

    let local_responses = std::mem::take(&mut *LOCAL_RESPONSES.lock().unwrap());
    for response in local_responses {
        // SAFETY: packet is valid for this callback and restored after the call.
        unsafe { inject_captured(this, packet, response, &call_original) };
    }

    for response in achievements::drain_offline_responses() {
        // SAFETY: packet is valid for this callback and restored after the call.
        unsafe { inject_captured(this, packet, response.packet, &call_original) };
    }

    if rp_inject_due && rich_presence::take_inject_pending() {
        let app = rich_presence::tracked_app();
        match rich_presence::build_inject_packet(app) {
            Some(response) => {
                info!(
                    app = app.0,
                    "netpacket: injecting manufactured PersonaState"
                );
                // SAFETY: packet is valid for this callback and restored after the call.
                unsafe { inject_captured(this, packet, response, &call_original) };
            }
            None => rich_presence::mark_inject_pending(),
        }
    }
}

unsafe fn inject_captured<F>(
    this: *mut c_void,
    packet: *mut c_void,
    response: Vec<u8>,
    call_original: &F,
) where
    F: Fn(*mut c_void, *mut c_void) -> *mut c_void,
{
    crate::packet_capture::capture(
        PacketDirection::Recv,
        &response,
        PacketChange::Injected,
        None,
    );
    // SAFETY: packet is valid for this callback and the guard restores it.
    let _guard = unsafe { PacketSwapGuard::new(packet, response) };
    call_original(this, packet);
}

/// Read and optionally rewrite an incoming packet after Steam has processed it.
///
/// # Safety
/// `packet` must be a valid `CNetPacket` pointer.
pub(crate) unsafe fn on_recv_packet(packet: *mut c_void) {
    if packet.is_null() {
        return;
    }
    // SAFETY: packet is the non-null CNetPacket supplied by Steam.
    let p_data = unsafe { cnet_packet::data_slot(packet) };
    // SAFETY: packet is the same validated CNetPacket.
    let p_size = unsafe { cnet_packet::size_slot(packet) };
    // SAFETY: both slots point into the live CNetPacket.
    let data = unsafe { *p_data };
    // SAFETY: both slots point into the live CNetPacket.
    let size = unsafe { *p_size };
    if data.is_null() || size == 0 {
        return;
    }

    // SAFETY: Steam's packet supplies a non-null data pointer and byte size.
    let bytes = unsafe { std::slice::from_raw_parts(data, size as usize) };
    if let Some(replacement) = process_recv_frame(bytes) {
        // SAFETY: packet remains valid for this hook callback.
        unsafe { replace_packet_data(packet, replacement) };
    }
}

/// Replace `CNetPacket` data with process-lifetime bytes for Steam to consume.
///
/// # Safety
/// `packet` must be a valid `CNetPacket` pointer.
unsafe fn replace_packet_data(packet: *mut c_void, data: Vec<u8>) {
    let boxed = data.into_boxed_slice();
    let len = boxed.len() as u32;
    let ptr = Box::into_raw(boxed) as *mut u8;

    // SAFETY: packet is valid and ptr remains allocated for process lifetime.
    unsafe { cnet_packet::set_data(packet, ptr, len) };
}

struct PacketSwapGuard {
    p_data: *mut *mut u8,
    p_size: *mut u32,
    orig_data: *mut u8,
    orig_size: u32,
    _response: Box<[u8]>,
}

impl PacketSwapGuard {
    /// # Safety
    /// `packet` must be a valid `CNetPacket` pointer.
    unsafe fn new(packet: *mut c_void, response: Vec<u8>) -> Self {
        // SAFETY: caller guarantees packet is a valid CNetPacket.
        let p_data = unsafe { cnet_packet::data_slot(packet) };
        // SAFETY: caller guarantees packet is a valid CNetPacket.
        let p_size = unsafe { cnet_packet::size_slot(packet) };
        // SAFETY: both slots point into the live packet.
        let orig_data = unsafe { *p_data };
        // SAFETY: both slots point into the live packet.
        let orig_size = unsafe { *p_size };

        let mut response = response.into_boxed_slice();
        // SAFETY: both slots point into the live packet and response stays owned.
        unsafe {
            *p_data = response.as_mut_ptr();
            *p_size = response.len() as u32;
        }
        Self {
            p_data,
            p_size,
            orig_data,
            orig_size,
            _response: response,
        }
    }
}

impl Drop for PacketSwapGuard {
    fn drop(&mut self) {
        // SAFETY: the guard cannot outlive the packet callback that created it.
        unsafe {
            *self.p_data = self.orig_data;
            *self.p_size = self.orig_size;
        }
    }
}
