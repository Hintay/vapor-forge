use std::ffi::c_void;

use tracing::info;
use vapor_forge_features::inject_wake::InjectionSource;
use vapor_forge_features::{achievements, request_code, rich_presence};
use vapor_forge_packet_capture::{PacketChange, PacketDirection};
use vapor_forge_steam_native_abi::cnet_packet;

use super::router::{
    prepare_recv_post_action, process_recv_frame, RecvFrameDecision, CLOUD_PENDING,
    LOCAL_RESPONSES, PENDING,
};

/// Route one source's completed responses to the native injection dispatch. The
/// injection router calls this from the source's own completion point.
pub(crate) fn wake_source(source: InjectionSource) {
    match source {
        InjectionSource::Manifest => drain_manifest(),
        InjectionSource::Cloud => {
            drain_cloud();
            crate::ui::toast_bridge::request_pump();
        }
        InjectionSource::Achievements => drain_achievements(),
        InjectionSource::RichPresence => drain_rich_presence(),
    }
}

fn drain_manifest() {
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
            "netpacket: queuing manifest response"
        );
        capture_injected(&response);
        crate::client::network::enqueue_injection_for_generation(
            response,
            entry.response_generation,
        );
    }
}

fn drain_cloud() {
    for response in CLOUD_PENDING.drain_completed() {
        // Cumulus upload responses contain bearer credentials and are not captured.
        crate::client::network::enqueue_cloud_injection(response);
    }
}

/// Drain locally-answered responses (privacy fallbacks, StoreStats, ownership
/// tickets). Called directly from `queue_local_response` (already in-crate).
pub(crate) fn drain_local() {
    for response in std::mem::take(&mut *LOCAL_RESPONSES.lock().unwrap()) {
        capture_injected(&response.packet);
        crate::client::network::enqueue_injection_for_generation(
            response.packet,
            response.generation,
        );
    }
}

fn drain_achievements() {
    for response in achievements::drain_offline_responses() {
        capture_injected(&response.packet);
        crate::client::network::enqueue_injection_for_generation(
            response.packet,
            response.generation,
        );
    }
}

fn drain_rich_presence() {
    if rich_presence::tracked_app().0 == 0 || !rich_presence::has_inject_pending() {
        return;
    }
    if rich_presence::take_inject_pending() {
        let app = rich_presence::tracked_app();
        match rich_presence::build_inject_packet(app) {
            Some(response) => {
                info!(app = app.0, "netpacket: queuing manufactured PersonaState");
                capture_injected(&response);
                crate::client::network::enqueue_injection(response);
            }
            // Re-arm without poking; the next real trigger retries.
            None => rich_presence::mark_inject_pending(),
        }
    }
}

fn capture_injected(response: &[u8]) {
    crate::packet_capture::capture(
        PacketDirection::Recv,
        response,
        PacketChange::Injected,
        None,
    );
}

pub(crate) fn queue_playtime_notification(
    packet: Vec<u8>,
    context: crate::client::playtime_downlink::RuntimeKey,
) {
    capture_injected(&packet);
    crate::client::network::enqueue_playtime_injection(packet, context);
}

/// Read and optionally rewrite an incoming packet before Steam processes it.
///
/// The returned guard owns replacement bytes and restores the original packet
/// fields when synchronous RecvPkt dispatch returns.
///
/// # Safety
/// `packet` must be null or a valid `CNetPacket` pointer, and the guard must be
/// dropped before the packet can be released.
pub(crate) unsafe fn prepare_recv_packet(packet: *mut c_void) -> PreparedRecvPacket {
    if packet.is_null() {
        return PreparedRecvPacket::pass();
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
        return PreparedRecvPacket::pass();
    }

    // SAFETY: Steam's packet supplies a non-null data pointer and byte size.
    let bytes = unsafe { std::slice::from_raw_parts(data, size as usize) };
    let post_dispatch = RecvPostDispatch(prepare_recv_post_action(bytes));
    let decision = match process_recv_frame(bytes) {
        RecvFrameDecision::Pass => PreparedRecvDecision::Pass,
        RecvFrameDecision::Drop => PreparedRecvDecision::Drop,
        RecvFrameDecision::Rewrite(replacement) => {
            // SAFETY: caller guarantees packet remains live for the guard lifetime.
            PreparedRecvDecision::Rewrite(unsafe { PacketSwapGuard::new(packet, replacement) })
        }
    };
    PreparedRecvPacket {
        decision,
        post_dispatch,
    }
}

pub(crate) struct PreparedRecvPacket {
    pub(crate) decision: PreparedRecvDecision,
    pub(crate) post_dispatch: RecvPostDispatch,
}

impl PreparedRecvPacket {
    fn pass() -> Self {
        Self {
            decision: PreparedRecvDecision::Pass,
            post_dispatch: RecvPostDispatch(None),
        }
    }
}

pub(crate) enum PreparedRecvDecision {
    Pass,
    Drop,
    Rewrite(PacketSwapGuard),
}

pub(crate) struct RecvPostDispatch(Option<super::router::RecvPostAction>);

impl RecvPostDispatch {
    pub(crate) fn complete(self) {
        if let Some(action) = self.0 {
            super::router::complete_recv_post_action(action);
        }
    }
}

pub(crate) struct PacketSwapGuard {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_swap_guard_restores_steam_fields() {
        let mut packet_storage = [0usize; 8];
        let packet = packet_storage.as_mut_ptr().cast::<c_void>();
        let mut original = [1u8, 2, 3];
        // SAFETY: packet_storage is aligned and large enough for the native
        // CNetPacket slots used by these accessors.
        unsafe { cnet_packet::set_data(packet, original.as_mut_ptr(), original.len() as u32) };

        {
            // SAFETY: packet_storage remains live until the guard is dropped.
            let _guard = unsafe { PacketSwapGuard::new(packet, vec![9, 8]) };
            // SAFETY: packet points to the same live test storage.
            let data = unsafe { *cnet_packet::data_slot(packet) };
            // SAFETY: packet points to the same live test storage.
            let size = unsafe { *cnet_packet::size_slot(packet) };
            assert_eq!(size, 2);
            // SAFETY: the guard owns two initialized replacement bytes.
            assert_eq!(unsafe { std::slice::from_raw_parts(data, 2) }, [9, 8]);
        }

        assert_eq!(
            // SAFETY: packet points to the same live test storage.
            unsafe { *cnet_packet::data_slot(packet) },
            original.as_mut_ptr()
        );
        // SAFETY: packet points to the same live test storage.
        assert_eq!(unsafe { *cnet_packet::size_slot(packet) }, 3);
    }
}
