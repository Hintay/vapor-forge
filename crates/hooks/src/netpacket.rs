//! Thin unsafe shell for network packet interception.
//!
//! Handles manifest request codes and achievement stats at the raw packet layer.
//! Business logic lives in `steam_runtime_features::{request_code, achievements}`.

use prost::Message;
use steam_runtime_abi::{
    CMsgProtoBufHeader, GetManifestRequestCodeRequest, EMSG_CLIENT_PERSONA_STATE,
    EMSG_CLIENT_RICH_PRESENCE_UPLOAD, EMSG_ENCRYPTED_APPTICKET_RESPONSE, EMSG_GAMESPLAYED,
    EMSG_GAMESPLAYED_WITH_DATABLOB, EMSG_PICS_PRODUCT_INFO_REQUEST, EMSG_REQUEST_USERSTATS,
    EMSG_REQUEST_USERSTATS_RESPONSE, EMSG_SERVICE_METHOD_CALL_FROM_CLIENT,
    EMSG_SERVICE_METHOD_RESPONSE, K_MSG_HDR_PROTO_FLAG,
};
use steam_runtime_features::achievements;
use steam_runtime_features::request_code::{self, PendingQueue};
use steam_runtime_features::rich_presence;
use tracing::{debug, info, warn};

use steam_runtime_config::AppId;

use crate::install::config;

// ---------------------------------------------------------------------------
// Singleton pending queue (manifest request codes)
// ---------------------------------------------------------------------------

static PENDING: once_cell::sync::Lazy<PendingQueue> = once_cell::sync::Lazy::new(PendingQueue::new);

#[cfg(target_pointer_width = "32")]
const CNET_PACKET_DATA_OFFSET: usize = 4;
#[cfg(target_pointer_width = "32")]
const CNET_PACKET_SIZE_OFFSET: usize = 8;

#[cfg(target_pointer_width = "64")]
const CNET_PACKET_DATA_OFFSET: usize = 8;
#[cfg(target_pointer_width = "64")]
const CNET_PACKET_SIZE_OFFSET: usize = 16;

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

    // Rewrite CMsgClientGamesPlayed to substitute avatar AppIds, and track
    // which real AppId is being played for rich presence spoofing.
    if emsg == EMSG_GAMESPLAYED || emsg == EMSG_GAMESPLAYED_WITH_DATABLOB {
        capture_local_steamid(header_bytes);
        track_games_played(body_bytes);

        if let Some(new_body) = steam_runtime_features::app_avatar::rewrite_games_played(body_bytes)
        {
            return SendFrameDecision::Rewrite(steam_runtime_abi::assemble_raw(
                emsg_raw,
                header_bytes,
                &new_body,
            ));
        }
    }

    // Capture rich presence KVs for the currently tracked (avatared) AppId.
    if emsg == EMSG_CLIENT_RICH_PRESENCE_UPLOAD {
        capture_local_steamid(header_bytes);
        if let Ok(upload) = steam_runtime_abi::ClientRichPresenceUpload::decode(body_bytes) {
            if let Some(kv_data) = &upload.rich_presence_kv {
                rich_presence::on_rich_presence_upload(kv_data);
            }
        }
    }

    // Inject access tokens into CMsgClientPICSProductInfoRequest.
    if emsg == EMSG_PICS_PRODUCT_INFO_REQUEST {
        let ss = crate::install::script_state();
        if !ss.access_tokens.is_empty() {
            if let Some(new_body) = inject_access_tokens(body_bytes, &ss.access_tokens) {
                return SendFrameDecision::Rewrite(steam_runtime_abi::assemble_raw(
                    emsg_raw,
                    header_bytes,
                    &new_body,
                ));
            }
        }
    }

    SendFrameDecision::Pass
}

/// Record the local SteamID from a CMsgProtoBufHeader, if present.
/// Cheap no-op once the SteamID has already been captured.
fn capture_local_steamid(header_bytes: &[u8]) {
    if rich_presence::local_steamid() != 0 {
        return;
    }
    if let Ok(hdr) = CMsgProtoBufHeader::decode(header_bytes) {
        if let Some(steamid) = hdr.steamid {
            rich_presence::set_local_steamid(steamid);
        }
    }
}

/// Feed the outgoing CMsgClientGamesPlayed body to rich_presence so it can
/// track which real AppId (pre-avatar-rewrite) is currently being played.
fn track_games_played(body_bytes: &[u8]) {
    let Ok(msg) = steam_runtime_abi::CMsgClientGamesPlayed::decode(body_bytes) else {
        return;
    };
    let app_ids: Vec<AppId> = msg
        .games_played
        .iter()
        .filter_map(|g| g.game_id)
        .map(|gid| AppId(gid as u32))
        .collect();
    rich_presence::on_games_played_update(&app_ids, |app_id| {
        steam_runtime_features::app_avatar::get_avatar(app_id).is_some()
    });

    reset_stopped_delegate_windows(&app_ids);
}

/// Reset the ticket-delegate window for any controlled app that has stopped
/// being played (no longer present in the current GamesPlayed list), so a
/// future relaunch of that app gets a fresh delegate window.
fn reset_stopped_delegate_windows(now_playing: &[AppId]) {
    let cfg = config();
    for app in &cfg.apps.inject {
        if app.ticket != steam_runtime_config::TicketMode::Delegate {
            continue;
        }
        if !now_playing.contains(&app.id) {
            steam_runtime_features::ticket::reset_delegate_window(app.id);
        }
    }

    // Revoke IPC session tokens for games that have exited.
    if let Some(Some(server)) = crate::install::IPC_SERVER.get() {
        for app in &cfg.apps.inject {
            if !now_playing.contains(&app.id) {
                server.revoke_app_tokens(app.id.0);
            }
        }
    }
}

fn inject_access_tokens(
    body_bytes: &[u8],
    tokens: &std::collections::HashMap<AppId, u64>,
) -> Option<Vec<u8>> {
    let mut req = steam_runtime_abi::PicsProductInfoRequest::decode(body_bytes).ok()?;
    let mut changed = false;
    for app in &mut req.apps {
        let app_id = AppId(app.appid.unwrap_or(0));
        if let Some(&token) = tokens.get(&app_id) {
            app.access_token = Some(token);
            changed = true;
            debug!(app_id = app_id.0, token, "netpacket: access token injected");
        }
    }
    if changed {
        Some(req.encode_to_vec())
    } else {
        None
    }
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
    let rp_inject_due = rich_presence::tracked_app().0 != 0 && rich_presence::has_inject_pending();
    if PENDING.is_empty() && !achievements::has_offline_responses() && !rp_inject_due {
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

    // Inject a manufactured PersonaState carrying the real AppId and rich
    // presence KVs, once per tracking/KV change, so friends get an update
    // even when Valve's server never broadcasts one for an unowned AppId.
    if rp_inject_due && rich_presence::take_inject_pending() {
        let app = rich_presence::tracked_app();
        match rich_presence::build_inject_packet(app) {
            Some(inject_bytes) => {
                info!(
                    app = app.0,
                    "netpacket: injecting manufactured PersonaState"
                );
                let _guard = unsafe { PacketSwapGuard::new(packet, inject_bytes) };
                call_original(this, packet);
            }
            None => {
                // Self PersonaState not cached yet (or no local SteamID seen).
                // Retry on the next RecvPkt instead of dropping the update.
                rich_presence::mark_inject_pending();
            }
        }
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
    let p_data = unsafe { packet_data_slot(packet) };
    let p_size = unsafe { packet_size_slot(packet) };
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

    // Encrypted app ticket response (5527): cache or inject from Lua/cache
    if emsg == EMSG_ENCRYPTED_APPTICKET_RESPONSE {
        if let Some(new_body) = handle_encrypted_ticket_response(body_bytes) {
            let replacement = steam_runtime_abi::assemble_raw(emsg_raw, hdr_bytes, &new_body);
            unsafe { replace_packet_data(packet, replacement) };
        }
    }

    // PersonaState (766): cache our own entry as an inject template, and
    // patch it live with the real AppId/rich presence while an avatared app
    // is being played.
    if emsg == EMSG_CLIENT_PERSONA_STATE {
        rich_presence::cache_self_persona(hdr_bytes, body_bytes);
        if let Some(new_body) = rich_presence::patch_persona_state(body_bytes) {
            let replacement = steam_runtime_abi::assemble_raw(emsg_raw, hdr_bytes, &new_body);
            unsafe { replace_packet_data(packet, replacement) };
        }
    }
}

fn handle_encrypted_ticket_response(body_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut resp = steam_runtime_abi::EncryptedAppTicketResponse::decode(body_bytes).ok()?;
    let app_id = AppId(resp.app_id.unwrap_or(0));
    let eresult = resp.eresult.unwrap_or(2);

    let ticket_cache = &*crate::install::TICKET_CACHE;
    let ss = crate::install::script_state();

    if eresult == steam_runtime_abi::ERESULT_OK {
        // Success: cache the ticket for future use
        if let Some(ticket) = &resp.encrypted_app_ticket {
            if let Some(data) = &ticket.encrypted_ticket {
                let cfg = config();
                let persist = if cfg.app_category(app_id).is_some() {
                    cfg.ticket_mode(app_id) == steam_runtime_config::TicketMode::Delegate
                } else {
                    cfg.ticket.cache == steam_runtime_config::TicketCacheMode::Disk
                };
                ticket_cache.store_enc_ticket(app_id, data.clone(), persist);
            }
        }
        return None;
    }

    // Failed: try Lua-provided or cached encrypted ticket
    if let Some(data) = ticket_cache.get_enc_ticket(app_id, &ss.enc_tickets) {
        resp.eresult = Some(steam_runtime_abi::ERESULT_OK);
        let ticket = resp
            .encrypted_app_ticket
            .get_or_insert_with(Default::default);
        ticket.encrypted_ticket = Some(data);
        info!(
            app_id = app_id.0,
            "netpacket: encrypted ticket injected from cache/lua"
        );
        return Some(resp.encode_to_vec());
    }

    None
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

    let p_data = unsafe { packet_data_slot(packet) };
    let p_size = unsafe { packet_size_slot(packet) };
    unsafe {
        *p_data = ptr;
        *p_size = len;
    }
}

unsafe fn packet_data_slot(packet: *mut std::ffi::c_void) -> *mut *mut u8 {
    unsafe { (packet as *mut u8).add(CNET_PACKET_DATA_OFFSET) as *mut *mut u8 }
}

unsafe fn packet_size_slot(packet: *mut std::ffi::c_void) -> *mut u32 {
    unsafe { (packet as *mut u8).add(CNET_PACKET_SIZE_OFFSET) as *mut u32 }
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
    /// `packet` must be a valid CNetPacket pointer.
    unsafe fn new(packet: *mut std::ffi::c_void, response: Vec<u8>) -> Self {
        let p_data = unsafe { packet_data_slot(packet) };
        let p_size = unsafe { packet_size_slot(packet) };
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
