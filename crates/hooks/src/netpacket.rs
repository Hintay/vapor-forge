//! Thin unsafe shell for network packet interception.
//!
//! Handles manifest request codes and achievement stats at the raw packet layer.
//! Business logic lives in `steam_runtime_features::{request_code, achievements}`.

use prost::Message;
use steam_runtime_abi::{
    CMsgProtoBufHeader, GetManifestRequestCodeRequest, EMSG_GAMESPLAYED,
    EMSG_GAMESPLAYED_WITH_DATABLOB, EMSG_REQUEST_USERSTATS, EMSG_REQUEST_USERSTATS_RESPONSE,
    EMSG_SERVICE_METHOD_CALL_FROM_CLIENT, EMSG_SERVICE_METHOD_RESPONSE, K_MSG_HDR_PROTO_FLAG,
};
use steam_runtime_features::achievements;
use steam_runtime_features::request_code::{self, PendingQueue};
use tracing::{debug, error, info, warn};

use steam_runtime_config::AppId;

use crate::install::config;

// ---------------------------------------------------------------------------
// Singleton pending queue (manifest request codes)
// ---------------------------------------------------------------------------

static PENDING: once_cell::sync::Lazy<PendingQueue> = once_cell::sync::Lazy::new(PendingQueue::new);

// ---------------------------------------------------------------------------
// Outgoing frame handling called from BBuildAndAsyncSendFrame hook
// ---------------------------------------------------------------------------

pub enum SendFrameDecision {
    Pass,
    Drop,
    Rewrite(Vec<u8>),
}

/// Inspect an outgoing frame and decide whether to pass, drop, or rewrite it.
pub fn decide_send_frame(data: &[u8]) -> SendFrameDecision {
    match std::panic::catch_unwind(|| decide_send_frame_inner(data)) {
        Ok(decision) => decision,
        Err(_) => {
            error!("netpacket: panic in decide_send_frame, passing through");
            SendFrameDecision::Pass
        }
    }
}

fn decide_send_frame_inner(data: &[u8]) -> SendFrameDecision {
    let (emsg_raw, header_bytes, body_bytes) = match steam_runtime_abi::unpack_raw(data) {
        Some(v) => v,
        None => return SendFrameDecision::Pass,
    };
    let emsg = emsg_raw & !K_MSG_HDR_PROTO_FLAG;
    let is_proto = emsg_raw & K_MSG_HDR_PROTO_FLAG != 0;
    if !is_proto {
        return SendFrameDecision::Pass;
    }

    // ServiceMethod (EMsg 151): manifest request codes and achievement stats
    if emsg == EMSG_SERVICE_METHOD_CALL_FROM_CLIENT {
        let hdr = match CMsgProtoBufHeader::decode(header_bytes) {
            Ok(h) => h,
            Err(_) => return SendFrameDecision::Pass,
        };
        let method = match &hdr.target_job_name {
            Some(m) => m.as_str(),
            None => return SendFrameDecision::Pass,
        };

        if method == request_code::TARGET_JOB_NAME {
            if handle_manifest_send(&hdr, header_bytes, body_bytes) {
                return SendFrameDecision::Drop;
            }
            return SendFrameDecision::Pass;
        }

        if method == achievements::STATS_JOB_NAME {
            let cfg = config();
            if let Some(new_body) = achievements::on_send_service_stats(&hdr, body_bytes, &cfg) {
                if new_body.is_empty() {
                    return SendFrameDecision::Drop;
                }
                return SendFrameDecision::Rewrite(steam_runtime_abi::assemble_raw(
                    emsg_raw,
                    header_bytes,
                    &new_body,
                ));
            }
        }

        return SendFrameDecision::Pass;
    }

    if emsg == EMSG_REQUEST_USERSTATS {
        let cfg = config();
        if let Some(new_body) = achievements::on_send_legacy_stats(body_bytes, &cfg) {
            if new_body.is_empty() {
                return SendFrameDecision::Drop;
            }
            return SendFrameDecision::Rewrite(steam_runtime_abi::assemble_raw(
                emsg_raw,
                header_bytes,
                &new_body,
            ));
        }
    }

    // Rewrite CMsgClientGamesPlayed to substitute avatar AppIds.
    if emsg == EMSG_GAMESPLAYED || emsg == EMSG_GAMESPLAYED_WITH_DATABLOB {
        if let Some(new_body) =
            steam_runtime_features::app_avatar::rewrite_games_played(body_bytes)
        {
            return SendFrameDecision::Rewrite(steam_runtime_abi::assemble_raw(
                emsg_raw,
                header_bytes,
                &new_body,
            ));
        }
    }

    SendFrameDecision::Pass
}

fn handle_manifest_send(hdr: &CMsgProtoBufHeader, header_bytes: &[u8], body_bytes: &[u8]) -> bool {
    let req = match GetManifestRequestCodeRequest::decode(body_bytes) {
        Ok(r) => r,
        Err(e) => {
            warn!("netpacket: failed to decode manifest request: {}", e);
            return false;
        }
    };

    let app_id = req.app_id.unwrap_or(0);
    let depot_id = req.depot_id.unwrap_or(0);
    let gid = req.manifest_id.unwrap_or(0);
    let job_id = match hdr.jobid_source {
        Some(id) if id != 0 => id,
        _ => {
            debug!("netpacket: missing or zero jobid_source, passing through");
            return false;
        }
    };

    let cfg = config();
    if !request_code::should_intercept(AppId(app_id), &cfg) {
        return false;
    }

    info!(
        app_id,
        depot_id, gid, job_id, "netpacket: intercepted manifest request code"
    );
    PENDING.queue_fetch(job_id, gid, header_bytes.to_vec(), &cfg);

    true
}

// ---------------------------------------------------------------------------
// try_inject called from RecvPkt hook
// ---------------------------------------------------------------------------

/// Check for pending responses and inject them via carrier packet.
///
/// # Safety
/// `this` and `packet` must be valid pointers as passed to RecvPkt.
pub unsafe fn try_inject<F>(
    this: *mut std::ffi::c_void,
    packet: *mut std::ffi::c_void,
    call_original: F,
) where
    F: Fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void,
{
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        try_inject_inner(this, packet, &call_original)
    }));
    if let Err(_) = result {
        error!("netpacket: panic in try_inject");
    }
}

unsafe fn try_inject_inner<F>(
    this: *mut std::ffi::c_void,
    packet: *mut std::ffi::c_void,
    call_original: &F,
) where
    F: Fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void,
{
    if PENDING.is_empty() && !achievements::has_offline_responses() {
        return;
    }

    if packet.is_null() {
        return;
    }

    // Inject manifest request code responses
    let completed = PENDING.drain_completed();
    for entry in completed {
        let response_bytes = request_code::build_response_packet(
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
        let _guard = unsafe { PacketSwapGuard::new(packet, response_bytes) };
        call_original(this, packet);
    }

    // Inject offline achievement responses
    let offline = achievements::drain_offline_responses();
    for resp in offline {
        let _guard = unsafe { PacketSwapGuard::new(packet, resp.packet) };
        call_original(this, packet);
    }
}

/// Process an incoming RecvPkt for achievement stats stripping.
/// Called from the RecvPkt hook AFTER call_original.
///
/// # Safety
/// `packet` must be a valid CNetPacket pointer.
pub unsafe fn on_recv_packet(packet: *mut std::ffi::c_void) {
    if packet.is_null() {
        return;
    }
    if !achievements::has_pending() && !achievements::has_legacy_pending() {
        return;
    }

    let p_data = packet as *mut *mut u8;
    let p_size = unsafe { (packet as *mut u8).add(4) } as *mut u32;
    let data = unsafe { *p_data };
    let size = unsafe { *p_size };
    if data.is_null() || size == 0 {
        return;
    }

    let buf = unsafe { std::slice::from_raw_parts(data, size as usize) };
    let Some((emsg_raw, hdr_bytes, body_bytes)) = steam_runtime_abi::unpack_raw(buf) else {
        return;
    };
    let emsg = emsg_raw & !K_MSG_HDR_PROTO_FLAG;

    // ServiceMethod response (147): achievement stats
    if emsg == EMSG_SERVICE_METHOD_RESPONSE {
        let Ok(hdr) = CMsgProtoBufHeader::decode(hdr_bytes) else {
            return;
        };
        if let Some((new_hdr, new_body)) = achievements::on_recv_service_stats(&hdr, body_bytes) {
            let replacement = steam_runtime_abi::assemble_raw(emsg_raw, &new_hdr, &new_body);
            unsafe { replace_packet_data(packet, replacement) };
        }
    }

    // Legacy response (819): achievement stats
    if emsg == EMSG_REQUEST_USERSTATS_RESPONSE {
        let cfg = config();
        if let Some(new_body) = achievements::on_recv_legacy_stats(body_bytes, &cfg) {
            let replacement = steam_runtime_abi::assemble_raw(emsg_raw, hdr_bytes, &new_body);
            unsafe { replace_packet_data(packet, replacement) };
        }
    }
}

/// Replace CNetPacket data with new bytes (for recv-side rewriting).
///
/// # Safety
/// `packet` must be a valid CNetPacket pointer.
unsafe fn replace_packet_data(packet: *mut std::ffi::c_void, data: Vec<u8>) {
    // Leak the vec so the pointer remains valid for Steam to process.
    // This is intentional. The packet is consumed once by Steam and then
    // the CNetPacket is released. The leaked bytes are small (< 1 KB).
    let boxed = data.into_boxed_slice();
    let len = boxed.len() as u32;
    let ptr = Box::into_raw(boxed) as *mut u8;

    let p_data = packet as *mut *mut u8;
    let p_size = unsafe { (packet as *mut u8).add(4) } as *mut u32;
    unsafe {
        *p_data = ptr;
        *p_size = len;
    }
}

// ---------------------------------------------------------------------------
// RAII guard for CNetPacket data swap
// ---------------------------------------------------------------------------

struct PacketSwapGuard {
    p_data: *mut *mut u8,
    p_size: *mut u32,
    orig_data: *mut u8,
    orig_size: u32,
    _response: Box<[u8]>,
}

impl PacketSwapGuard {
    /// # Safety
    /// `packet` must be a valid CNetPacket pointer (i686 layout: +0 = *mut u8, +4 = u32).
    unsafe fn new(packet: *mut std::ffi::c_void, response: Vec<u8>) -> Self {
        let p_data = packet as *mut *mut u8;
        let p_size = unsafe { (packet as *mut u8).add(4) } as *mut u32;
        let orig_data = unsafe { *p_data };
        let orig_size = unsafe { *p_size };

        let mut response_box = response.into_boxed_slice();
        unsafe {
            *p_data = response_box.as_mut_ptr();
            *p_size = response_box.len() as u32;
        }

        Self {
            p_data,
            p_size,
            orig_data,
            orig_size,
            _response: response_box,
        }
    }
}

impl Drop for PacketSwapGuard {
    fn drop(&mut self) {
        unsafe {
            *self.p_data = self.orig_data;
            *self.p_size = self.orig_size;
        }
    }
}
