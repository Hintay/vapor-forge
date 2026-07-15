//! Thin unsafe shell for network packet interception.
//!
//! Handles manifest request codes and achievement stats at the raw packet layer.
//! Business logic lives in `vapor_forge_features::{request_code, achievements}`.

use prost::Message;
use tracing::{debug, info, warn};
use vapor_forge_abi::{
    cnet_packet, CMsgProtoBufHeader, GetManifestRequestCodeRequest, EMSG_CLIENT_PERSONA_STATE,
    EMSG_CLIENT_RICH_PRESENCE_UPLOAD, EMSG_ENCRYPTED_APPTICKET_RESPONSE, EMSG_GAMESPLAYED,
    EMSG_GAMESPLAYED_WITH_DATABLOB, EMSG_PICS_PRODUCT_INFO_REQUEST, EMSG_REQUEST_USERSTATS,
    EMSG_REQUEST_USERSTATS_RESPONSE, EMSG_SERVICE_METHOD_CALL_FROM_CLIENT,
    EMSG_SERVICE_METHOD_RESPONSE, K_MSG_HDR_PROTO_FLAG,
};
use vapor_forge_features::achievements;
use vapor_forge_features::request_code::{self, PendingQueue};
use vapor_forge_features::rich_presence;
use vapor_forge_packet_inspect::{PacketChange, PacketDirection};

use vapor_forge_config::AppId;

// ---------------------------------------------------------------------------
// Singleton pending queue (manifest request codes)
// ---------------------------------------------------------------------------

static PENDING: once_cell::sync::Lazy<PendingQueue> = once_cell::sync::Lazy::new(PendingQueue::new);
static CLOUD_PENDING: once_cell::sync::Lazy<vapor_forge_features::cloud_rpc::CloudRpcQueue> =
    once_cell::sync::Lazy::new(vapor_forge_features::cloud_rpc::CloudRpcQueue::new);

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
    let mut decision = SendFrameDecision::Pass;
    let (emsg_raw, header_bytes, body_bytes) = match vapor_forge_abi::unpack_raw(data) {
        Some(v) => v,
        None => {
            crate::packet_capture::capture(
                PacketDirection::Send,
                data,
                PacketChange::DecodeFailed,
                None,
            );
            return SendFrameDecision::Pass;
        }
    };
    let emsg = emsg_raw & !K_MSG_HDR_PROTO_FLAG;
    let is_proto = emsg_raw & K_MSG_HDR_PROTO_FLAG != 0;
    if !is_proto {
        crate::packet_capture::capture(PacketDirection::Send, data, PacketChange::Unchanged, None);
        return SendFrameDecision::Pass;
    }

    // ServiceMethod (EMsg 151): manifest request codes and achievement stats
    if emsg == EMSG_SERVICE_METHOD_CALL_FROM_CLIENT {
        let hdr = match CMsgProtoBufHeader::decode(header_bytes) {
            Ok(h) => h,
            Err(_) => {
                crate::packet_capture::capture(
                    PacketDirection::Send,
                    data,
                    PacketChange::DecodeFailed,
                    None,
                );
                return SendFrameDecision::Pass;
            }
        };
        let method = match &hdr.target_job_name {
            Some(m) => m.as_str(),
            None => {
                crate::packet_capture::capture(
                    PacketDirection::Send,
                    data,
                    PacketChange::Unchanged,
                    None,
                );
                return SendFrameDecision::Pass;
            }
        };

        if method == request_code::TARGET_JOB_NAME {
            if handle_manifest_send(&hdr, header_bytes, body_bytes) {
                decision = SendFrameDecision::Drop;
                crate::packet_capture::capture(
                    PacketDirection::Send,
                    data,
                    PacketChange::Dropped,
                    Some(0),
                );
                return decision;
            }
            crate::packet_capture::capture(
                PacketDirection::Send,
                data,
                PacketChange::Unchanged,
                None,
            );
            return decision;
        }

        let runtime = crate::client::install::runtime_snapshot();
        if CLOUD_PENDING.intercept(method, &hdr, header_bytes, body_bytes, &runtime.config) {
            info!(method, "netpacket: intercepted client cloud RPC");
            crate::packet_capture::capture(
                PacketDirection::Send,
                data,
                PacketChange::Dropped,
                Some(0),
            );
            return SendFrameDecision::Drop;
        }

        if method == achievements::STATS_JOB_NAME {
            if let Some(new_body) = achievements::on_send_service_stats(
                &hdr,
                body_bytes,
                &runtime.config,
                &runtime.script_state.stat_steam_ids,
            ) {
                if new_body.is_empty() {
                    decision = SendFrameDecision::Drop;
                    crate::packet_capture::capture(
                        PacketDirection::Send,
                        data,
                        PacketChange::Dropped,
                        Some(0),
                    );
                    return decision;
                }
                let replacement = vapor_forge_abi::assemble_raw(emsg_raw, header_bytes, &new_body);
                crate::packet_capture::capture(
                    PacketDirection::Send,
                    data,
                    PacketChange::Rewritten,
                    Some(replacement.len()),
                );
                return SendFrameDecision::Rewrite(replacement);
            }
        }

        crate::packet_capture::capture(PacketDirection::Send, data, PacketChange::Unchanged, None);
        return decision;
    }

    if emsg == EMSG_REQUEST_USERSTATS {
        let runtime = crate::client::install::runtime_snapshot();
        if let Some(new_body) = achievements::on_send_legacy_stats(
            body_bytes,
            &runtime.config,
            &runtime.script_state.stat_steam_ids,
        ) {
            if new_body.is_empty() {
                crate::packet_capture::capture(
                    PacketDirection::Send,
                    data,
                    PacketChange::Dropped,
                    Some(0),
                );
                return SendFrameDecision::Drop;
            }
            let replacement = vapor_forge_abi::assemble_raw(emsg_raw, header_bytes, &new_body);
            crate::packet_capture::capture(
                PacketDirection::Send,
                data,
                PacketChange::Rewritten,
                Some(replacement.len()),
            );
            return SendFrameDecision::Rewrite(replacement);
        }
    }

    // Rewrite CMsgClientGamesPlayed to substitute avatar AppIds, and track
    // which real AppId is being played for rich presence rewriting.
    if emsg == EMSG_GAMESPLAYED || emsg == EMSG_GAMESPLAYED_WITH_DATABLOB {
        capture_local_steamid(header_bytes);
        let runtime = crate::client::install::runtime_snapshot();
        track_games_played(body_bytes, &runtime);

        if let Some(new_body) =
            vapor_forge_features::app_avatar::rewrite_games_played(body_bytes, &runtime.avatar_map)
        {
            let replacement = vapor_forge_abi::assemble_raw(emsg_raw, header_bytes, &new_body);
            crate::packet_capture::capture(
                PacketDirection::Send,
                data,
                PacketChange::Rewritten,
                Some(replacement.len()),
            );
            return SendFrameDecision::Rewrite(replacement);
        }
    }

    // Capture rich presence KVs for the currently tracked (avatared) AppId.
    if emsg == EMSG_CLIENT_RICH_PRESENCE_UPLOAD {
        capture_local_steamid(header_bytes);
        if let Ok(upload) = vapor_forge_abi::ClientRichPresenceUpload::decode(body_bytes) {
            if let Some(kv_data) = &upload.rich_presence_kv {
                rich_presence::on_rich_presence_upload(kv_data);
            }
        }
    }

    // Inject access tokens into CMsgClientPICSProductInfoRequest.
    if emsg == EMSG_PICS_PRODUCT_INFO_REQUEST {
        let runtime = crate::client::install::runtime_snapshot();
        let ss = &runtime.script_state;
        if !ss.access_tokens.is_empty() {
            if let Some(new_body) = inject_access_tokens(body_bytes, &ss.access_tokens, &ss.apps) {
                let replacement = vapor_forge_abi::assemble_raw(emsg_raw, header_bytes, &new_body);
                crate::packet_capture::capture(
                    PacketDirection::Send,
                    data,
                    PacketChange::Rewritten,
                    Some(replacement.len()),
                );
                return SendFrameDecision::Rewrite(replacement);
            }
        }
    }

    crate::packet_capture::capture(PacketDirection::Send, data, PacketChange::Unchanged, None);
    decision
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
fn track_games_played(body_bytes: &[u8], runtime: &crate::client::install::RuntimeSnapshot) {
    let Ok(msg) = vapor_forge_abi::CMsgClientGamesPlayed::decode(body_bytes) else {
        return;
    };
    let app_ids: Vec<AppId> = msg
        .games_played
        .iter()
        .filter_map(|g| g.game_id)
        .map(|gid| AppId(gid as u32))
        .collect();
    rich_presence::on_games_played_update(&app_ids, |app_id| {
        vapor_forge_features::app_avatar::get_avatar(app_id, &runtime.avatar_map).is_some()
    });

    reset_stopped_delegate_windows(&app_ids, &runtime.config);
}

/// Reset the ticket-delegate window for any controlled app that has stopped
/// being played (no longer present in the current GamesPlayed list), so a
/// future relaunch of that app gets a fresh delegate window.
fn reset_stopped_delegate_windows(
    now_playing: &[AppId],
    config: &vapor_forge_config::RuntimeConfig,
) {
    for app in &config.apps.inject {
        if app.ticket != vapor_forge_config::TicketMode::Delegate {
            continue;
        }
        if !now_playing.contains(&app.id) {
            vapor_forge_features::ticket::reset_delegate_window(app.id);
        }
    }

    // Revoke IPC session tokens for games that have exited.
    if let Some(server) = crate::client::install::IPC_SERVER.get() {
        for app in &config.apps.inject {
            if !now_playing.contains(&app.id) {
                server.revoke_app_tokens(app.id.0);
            }
        }
    }
}

fn inject_access_tokens(
    body_bytes: &[u8],
    tokens: &std::collections::HashMap<AppId, u64>,
    controlled_apps: &[AppId],
) -> Option<Vec<u8>> {
    let mut req = vapor_forge_abi::PicsProductInfoRequest::decode(body_bytes).ok()?;
    let mut changed = false;
    for app in &mut req.apps {
        let app_id = AppId(app.appid.unwrap_or(0));
        let Some(&token) = tokens.get(&app_id) else {
            continue;
        };
        if token == 0 || !controlled_apps.contains(&app_id) {
            continue;
        }
        app.access_token = Some(token);
        changed = true;
        debug!(app_id = app_id.0, token, "netpacket: access token injected");
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

    let runtime = crate::client::install::runtime_snapshot();
    let cfg = &runtime.config;
    if !request_code::should_intercept(AppId(app_id), cfg) {
        return false;
    }

    info!(
        app_id,
        depot_id, gid, job_id, "netpacket: intercepted manifest request code"
    );
    let provider_timeout = std::time::Duration::from_millis(cfg.manifest.timeout_ms);
    let lua_callback = runtime.manifest_code_provider.clone().map(|provider| {
        std::sync::Arc::new(move |app_id, depot_id, gid| {
            provider.fetch_with_timeout(app_id, depot_id, gid, provider_timeout)
        }) as request_code::ManifestCodeCallback
    });
    PENDING.queue_fetch(
        request_code::ManifestCodeFetch {
            job_id,
            app_id,
            depot_id,
            gid,
            req_hdr_bytes: header_bytes.to_vec(),
        },
        cfg,
        lua_callback,
    )
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
    if PENDING.is_empty()
        && CLOUD_PENDING.is_empty()
        && !achievements::has_offline_responses()
        && !rp_inject_due
    {
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
        crate::packet_capture::capture(
            PacketDirection::Recv,
            &response_bytes,
            PacketChange::Injected,
            None,
        );
        // SAFETY: packet is valid for this callback and the guard restores it.
        let _guard = unsafe { PacketSwapGuard::new(packet, response_bytes) };
        call_original(this, packet);
    }

    // Inject Cumulus-backed Steam client Cloud service responses.
    for response_bytes in CLOUD_PENDING.drain_completed() {
        // Upload responses carry the Cumulus bearer token in HTTP headers, so
        // they must not be retained by the diagnostic packet capture.
        let _guard = unsafe { PacketSwapGuard::new(packet, response_bytes) };
        call_original(this, packet);
    }

    // Inject offline achievement responses
    let offline = achievements::drain_offline_responses();
    for resp in offline {
        crate::packet_capture::capture(
            PacketDirection::Recv,
            &resp.packet,
            PacketChange::Injected,
            None,
        );
        // SAFETY: packet is valid for this callback and the guard restores it.
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
                crate::packet_capture::capture(
                    PacketDirection::Recv,
                    &inject_bytes,
                    PacketChange::Injected,
                    None,
                );
                // SAFETY: packet is valid for this callback and the guard restores it.
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
    let buf = unsafe { std::slice::from_raw_parts(data, size as usize) };
    let Some((emsg_raw, hdr_bytes, body_bytes)) = vapor_forge_abi::unpack_raw(buf) else {
        crate::packet_capture::capture(
            PacketDirection::Recv,
            buf,
            PacketChange::DecodeFailed,
            None,
        );
        return;
    };
    let emsg = emsg_raw & !K_MSG_HDR_PROTO_FLAG;
    let mut change = PacketChange::Unchanged;
    let mut final_len = None;

    // ServiceMethod response (147): achievement stats
    if emsg == EMSG_SERVICE_METHOD_RESPONSE {
        let Ok(hdr) = CMsgProtoBufHeader::decode(hdr_bytes) else {
            crate::packet_capture::capture(
                PacketDirection::Recv,
                buf,
                PacketChange::DecodeFailed,
                None,
            );
            return;
        };
        if let Some((new_hdr, new_body)) = achievements::on_recv_service_stats(&hdr, body_bytes) {
            let replacement = vapor_forge_abi::assemble_raw(emsg_raw, &new_hdr, &new_body);
            final_len = Some(replacement.len());
            // SAFETY: packet remains valid for this hook callback.
            unsafe { replace_packet_data(packet, replacement) };
            change = PacketChange::Rewritten;
        }
    }

    // Legacy response (819): achievement stats
    if emsg == EMSG_REQUEST_USERSTATS_RESPONSE {
        let cfg = config();
        if let Some(new_body) = achievements::on_recv_legacy_stats(body_bytes, &cfg) {
            let replacement = vapor_forge_abi::assemble_raw(emsg_raw, hdr_bytes, &new_body);
            final_len = Some(replacement.len());
            // SAFETY: packet remains valid for this hook callback.
            unsafe { replace_packet_data(packet, replacement) };
            change = PacketChange::Rewritten;
        }
    }

    // Encrypted app ticket response (5527): cache or inject from Lua/cache
    if emsg == EMSG_ENCRYPTED_APPTICKET_RESPONSE {
        if let Some(new_body) = handle_encrypted_ticket_response(body_bytes) {
            let replacement = vapor_forge_abi::assemble_raw(emsg_raw, hdr_bytes, &new_body);
            final_len = Some(replacement.len());
            // SAFETY: packet remains valid for this hook callback.
            unsafe { replace_packet_data(packet, replacement) };
            change = PacketChange::Rewritten;
        }
    }

    // PersonaState (766): cache our own entry as an inject template, and
    // patch it live with the real AppId/rich presence while an avatared app
    // is being played.
    if emsg == EMSG_CLIENT_PERSONA_STATE {
        rich_presence::cache_self_persona(hdr_bytes, body_bytes);
        if let Some(new_body) = rich_presence::patch_persona_state(body_bytes) {
            let replacement = vapor_forge_abi::assemble_raw(emsg_raw, hdr_bytes, &new_body);
            final_len = Some(replacement.len());
            // SAFETY: packet remains valid for this hook callback.
            unsafe { replace_packet_data(packet, replacement) };
            change = PacketChange::Rewritten;
        }
    }

    crate::packet_capture::capture(PacketDirection::Recv, buf, change, final_len);
}

fn handle_encrypted_ticket_response(body_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut resp = vapor_forge_abi::EncryptedAppTicketResponse::decode(body_bytes).ok()?;
    let app_id = AppId(resp.app_id.unwrap_or(0));
    let eresult = resp.eresult.unwrap_or(2);

    let ticket_cache = &*crate::client::install::TICKET_CACHE;
    let runtime = crate::client::install::runtime_snapshot();
    let ss = &runtime.script_state;

    if eresult == vapor_forge_abi::ERESULT_OK {
        // Success: cache the ticket for future use
        if let Some(ticket) = &resp.encrypted_app_ticket {
            if let Some(data) = &ticket.encrypted_ticket {
                let cfg = &runtime.config;
                let persist = if cfg.is_controlled_app(app_id) {
                    cfg.ticket_mode(app_id) == vapor_forge_config::TicketMode::Delegate
                } else {
                    cfg.ticket.cache == vapor_forge_config::TicketCacheMode::Disk
                };
                ticket_cache.store_enc_ticket(app_id, data.clone(), persist);
            }
        }
        return None;
    }

    // Failed: try Lua-provided or cached encrypted ticket
    if let Some(data) = ticket_cache.get_enc_ticket(app_id, &ss.enc_tickets) {
        resp.eresult = Some(vapor_forge_abi::ERESULT_OK);
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

    // SAFETY: packet is valid and ptr remains allocated for process lifetime.
    unsafe { cnet_packet::set_data(packet, ptr, len) };
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
        // SAFETY: caller guarantees packet is a valid CNetPacket.
        let p_data = unsafe { cnet_packet::data_slot(packet) };
        // SAFETY: caller guarantees packet is a valid CNetPacket.
        let p_size = unsafe { cnet_packet::size_slot(packet) };
        // SAFETY: the slots above point into the live packet.
        let orig_data = unsafe { *p_data };
        // SAFETY: the slots above point into the live packet.
        let orig_size = unsafe { *p_size };

        let mut response_box = response.into_boxed_slice();
        // SAFETY: both slots point into the live packet and response_box stays
        // owned by the guard until restoration.
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
        // SAFETY: the guard cannot outlive the packet callback that created it.
        unsafe {
            *self.p_data = self.orig_data;
            *self.p_size = self.orig_size;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn access_tokens_require_addappid_and_skip_zero() {
        let request = vapor_forge_abi::PicsProductInfoRequest {
            apps: vec![
                vapor_forge_abi::PicsAppInfo {
                    appid: Some(480),
                    access_token: None,
                    only_public_obsolete: None,
                },
                vapor_forge_abi::PicsAppInfo {
                    appid: Some(730),
                    access_token: Some(7),
                    only_public_obsolete: None,
                },
                vapor_forge_abi::PicsAppInfo {
                    appid: Some(999),
                    access_token: None,
                    only_public_obsolete: None,
                },
            ],
            ..Default::default()
        };
        let tokens = HashMap::from([(AppId(480), 42), (AppId(730), 0), (AppId(999), 99)]);

        let rewritten =
            inject_access_tokens(&request.encode_to_vec(), &tokens, &[AppId(480), AppId(730)])
                .unwrap();
        let rewritten =
            vapor_forge_abi::PicsProductInfoRequest::decode(rewritten.as_slice()).unwrap();
        assert_eq!(rewritten.apps[0].access_token, Some(42));
        assert_eq!(rewritten.apps[1].access_token, Some(7));
        assert_eq!(rewritten.apps[2].access_token, None);
    }

    #[test]
    fn access_token_rewrite_is_none_without_eligible_apps() {
        let request = vapor_forge_abi::PicsProductInfoRequest {
            apps: vec![vapor_forge_abi::PicsAppInfo {
                appid: Some(480),
                access_token: None,
                only_public_obsolete: None,
            }],
            ..Default::default()
        };
        let tokens = HashMap::from([(AppId(480), 42)]);

        assert!(inject_access_tokens(&request.encode_to_vec(), &tokens, &[]).is_none());
    }
}
