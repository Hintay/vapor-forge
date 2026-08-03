#![forbid(unsafe_code)]

//! Safe routing and state coordination for intercepted Steam network packets.
//!
//! Feature decisions live in `vapor_forge_features`.

use prost::Message;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use tracing::{debug, info, warn};
use vapor_forge_core::unix_now;
use vapor_forge_features::achievements;
use vapor_forge_features::identity;
use vapor_forge_features::request_code::{self, PendingQueue};
use vapor_forge_features::rich_presence;
use vapor_forge_features::valve_filter::{self, PrivacyAction};
use vapor_forge_packet_capture::{PacketChange, PacketDirection};
use vapor_forge_steam_protocol::{
    app_id_from_game_id, CMsgProtoBufHeader, EncryptedAppTicket, EncryptedAppTicketRequest,
    EncryptedAppTicketResponse, GetAppOwnershipTicketRequest, GetAppOwnershipTicketResponse,
    PlayerGetUserStatsRequest, PlayerGetUserStatsResponse, PlayerPlayHistory,
    PlayerRecordDisconnectedPlaytimeRequest, PlayerRecordDisconnectedPlaytimeResponse,
    EMSG_CLIENT_LOGGED_OFF, EMSG_CLIENT_LOG_ON, EMSG_CLIENT_LOG_ON_RESPONSE,
    EMSG_CLIENT_PERSONA_STATE, EMSG_CLIENT_RICH_PRESENCE_UPLOAD,
    EMSG_CLIENT_SHARED_LIBRARY_STOP_PLAYING, EMSG_ENCRYPTED_APPTICKET_REQUEST,
    EMSG_ENCRYPTED_APPTICKET_RESPONSE, EMSG_GAMESPLAYED, EMSG_GAMESPLAYED_WITH_DATABLOB,
    EMSG_GET_APP_OWNERSHIP_TICKET, EMSG_GET_APP_OWNERSHIP_TICKET_RESPONSE,
    EMSG_PICS_PRODUCT_INFO_REQUEST, EMSG_REQUEST_USERSTATS, EMSG_REQUEST_USERSTATS_RESPONSE,
    EMSG_SERVICE_METHOD_CALL_FROM_CLIENT, EMSG_SERVICE_METHOD_RESPONSE,
    EMSG_SERVICE_METHOD_SEND_TO_CLIENT, EMSG_STORE_USERSTATS, EMSG_STORE_USERSTATS2, ERESULT_OK,
    FAMILY_GROUPS_NOTIFY_RUNNING_APPS_JOB, K_MSG_HDR_PROTO_FLAG,
    PLAYER_RECORD_DISCONNECTED_PLAYTIME_JOB_NAME,
};

use vapor_forge_config::AppId;

use super::stats_proxy;

// ---------------------------------------------------------------------------
// Singleton pending queue (manifest request codes)
// ---------------------------------------------------------------------------

pub(super) static PENDING: once_cell::sync::Lazy<PendingQueue> =
    once_cell::sync::Lazy::new(PendingQueue::new);
pub(super) static CLOUD_PENDING: once_cell::sync::Lazy<vapor_forge_cloud_rpc::CloudRpcQueue> =
    once_cell::sync::Lazy::new(vapor_forge_cloud_rpc::CloudRpcQueue::new);
const MAX_STATS_REQUESTS: usize = 4096;
const ERESULT_INVALID_PARAM: i32 = 8;
pub(super) struct LocalResponse {
    pub(super) packet: Vec<u8>,
    pub(super) generation: u64,
}
pub(super) static LOCAL_RESPONSES: once_cell::sync::Lazy<Mutex<VecDeque<LocalResponse>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(VecDeque::new()));
static STATS_REQUESTS: once_cell::sync::Lazy<Mutex<VecDeque<(u64, u32)>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(VecDeque::new()));
static PENDING_LOGIN_DEVICE: once_cell::sync::Lazy<
    Mutex<Option<vapor_forge_steam_protocol::ClientLogOnDevice>>,
> = once_cell::sync::Lazy::new(|| Mutex::new(None));

// A protected app without AppAvatar must not upload unscoped Rich Presence.
static BLOCKED_RICH_PRESENCE_APP: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Outgoing frame handling called from BBuildAndAsyncSendFrame hook
// ---------------------------------------------------------------------------

pub enum SendFrameDecision {
    Pass,
    Drop,
    Rewrite(Vec<u8>),
}

fn record_login_device(body: &[u8]) {
    let device = vapor_forge_steam_protocol::client_logon_device(body);
    if let Ok(mut current) = PENDING_LOGIN_DEVICE.lock() {
        *current = device;
    }
}

struct LoginDeviceCompletion {
    changed: bool,
    metadata_matched: bool,
    machine_name_present: bool,
    os_type: Option<i64>,
    device_type: Option<i64>,
}

fn complete_login_device(client_id: u64) -> LoginDeviceCompletion {
    let pending = PENDING_LOGIN_DEVICE
        .lock()
        .ok()
        .and_then(|mut pending| pending.take())
        .filter(|device| {
            device
                .client_instance_id
                .is_none_or(|request_client_id| request_client_id == client_id)
        });
    let Some(device) = pending else {
        return LoginDeviceCompletion {
            changed: vapor_forge_cloud_core::record_local_client_id(client_id),
            metadata_matched: false,
            machine_name_present: false,
            os_type: None,
            device_type: None,
        };
    };
    let completion = LoginDeviceCompletion {
        changed: false,
        metadata_matched: true,
        machine_name_present: !device.machine_name.trim().is_empty(),
        os_type: device.os_type,
        device_type: device.device_type,
    };
    LoginDeviceCompletion {
        changed: vapor_forge_cloud_core::record_device_descriptor(
            vapor_forge_cloud_core::DeviceDescriptor {
                client_id,
                machine_name: device.machine_name,
                os_type: device.os_type,
                device_type: device.device_type,
            },
        ),
        ..completion
    }
}

fn clear_pending_login_device() {
    if let Ok(mut pending) = PENDING_LOGIN_DEVICE.lock() {
        pending.take();
    }
}

pub(super) enum RecvFrameDecision {
    Pass,
    Drop,
    Rewrite(Vec<u8>),
}

/// Inspect an outgoing frame and decide whether to pass, drop, or rewrite it.
pub fn decide_send_frame(data: &[u8]) -> SendFrameDecision {
    let mut decision = SendFrameDecision::Pass;
    let (emsg_raw, header_bytes, body_bytes) = match vapor_forge_steam_protocol::unpack_raw(data) {
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
    if emsg == EMSG_CLIENT_LOG_ON {
        record_login_device(body_bytes);
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

        vapor_forge_features::playtime::observe_request(method, &hdr, identity::steam_id());

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
        if method == PLAYER_RECORD_DISCONNECTED_PLAYTIME_JOB_NAME {
            return handle_record_disconnected_playtime(
                emsg_raw,
                header_bytes,
                body_bytes,
                data,
                &runtime.config,
            );
        }
        if CLOUD_PENDING.intercept(
            method,
            &hdr,
            header_bytes,
            body_bytes,
            &runtime.config,
            crate::client::network::injection_generation(),
        ) {
            info!(method, "netpacket: intercepted client cloud RPC");
            crate::packet_capture::capture(
                PacketDirection::Send,
                data,
                PacketChange::Dropped,
                Some(0),
            );
            return SendFrameDecision::Drop;
        }

        if let Some((app_id, expects_response)) =
            vapor_forge_cloud_rpc::privacy_fallback(method, body_bytes, &runtime.config)
        {
            if expects_response && hdr.jobid_source.is_some_and(|job| job != 0) {
                queue_local_response(valve_filter::service_response(header_bytes, Vec::new(), 2));
            }
            info!(app_id, method, "netpacket: blocked Cloud fallback to Valve");
            capture_dropped(data);
            return SendFrameDecision::Drop;
        }

        match valve_filter::service_method_action(&hdr, header_bytes, body_bytes, &runtime.config) {
            PrivacyAction::Pass => {}
            PrivacyAction::Drop { app_id } => {
                info!(
                    app_id,
                    method, "netpacket: blocked Valve service notification"
                );
                capture_dropped(data);
                return SendFrameDecision::Drop;
            }
            PrivacyAction::Respond { app_id, packet } => {
                info!(
                    app_id,
                    method, "netpacket: answered Valve service request locally"
                );
                queue_local_response(packet);
                capture_dropped(data);
                return SendFrameDecision::Drop;
            }
        }

        if method == achievements::STATS_JOB_NAME {
            if let Some(decision) = stats_proxy::handle_proxy_service_stats(
                emsg_raw,
                header_bytes,
                body_bytes,
                data,
                &runtime.config,
                &runtime.script_state.stat_steam_ids,
            ) {
                return decision;
            }
            track_stats_request(&hdr, body_bytes);
        }

        crate::packet_capture::capture(PacketDirection::Send, data, PacketChange::Unchanged, None);
        return decision;
    }

    if emsg == EMSG_REQUEST_USERSTATS {
        let runtime = crate::client::install::runtime_snapshot();
        if let Some(decision) = stats_proxy::handle_proxy_legacy_stats(
            emsg_raw,
            header_bytes,
            body_bytes,
            data,
            &runtime.config,
            &runtime.script_state.stat_steam_ids,
        ) {
            return decision;
        }
    }

    if emsg == EMSG_STORE_USERSTATS || emsg == EMSG_STORE_USERSTATS2 {
        let runtime = crate::client::install::runtime_snapshot();
        match valve_filter::store_stats_action(emsg, header_bytes, body_bytes, &runtime.config) {
            PrivacyAction::Pass => {}
            PrivacyAction::Drop { app_id } => {
                info!(app_id, emsg, "netpacket: blocked StoreStats");
                capture_dropped(data);
                return SendFrameDecision::Drop;
            }
            PrivacyAction::Respond { app_id, packet } => {
                let persisted =
                    crate::achievement_worker::persist_store_commit(app_id, emsg, body_bytes);
                if persisted {
                    crate::client::user_stats::queue_snapshot_read(app_id);
                    info!(app_id, emsg, "netpacket: acknowledged StoreStats locally");
                } else {
                    warn!(
                        app_id,
                        emsg, "netpacket: acknowledged StoreStats without a durable commit marker"
                    );
                }
                queue_local_response(packet);
                capture_dropped(data);
                return SendFrameDecision::Drop;
            }
        }
    }

    if emsg == EMSG_GET_APP_OWNERSHIP_TICKET {
        if let Some((app_id, packet)) = local_ownership_ticket_response(header_bytes, body_bytes) {
            info!(
                app_id,
                "netpacket: answered ownership ticket request locally"
            );
            queue_local_response(packet);
            capture_dropped(data);
            return SendFrameDecision::Drop;
        }
    }

    if emsg == EMSG_ENCRYPTED_APPTICKET_REQUEST {
        if let Some((app_id, packet)) = local_encrypted_ticket_response(header_bytes, body_bytes) {
            info!(
                app_id,
                "netpacket: answered encrypted ticket request locally"
            );
            queue_local_response(packet);
            capture_dropped(data);
            return SendFrameDecision::Drop;
        }
    }

    // Rewrite CMsgClientGamesPlayed to substitute avatar AppIds, and track
    // which real AppId is being played for rich presence rewriting.
    if emsg == EMSG_GAMESPLAYED || emsg == EMSG_GAMESPLAYED_WITH_DATABLOB {
        capture_local_steamid(header_bytes);
        let runtime = crate::client::install::runtime_snapshot();
        track_games_played(body_bytes, &runtime);

        if let Some(filtered) =
            valve_filter::filter_games_played(body_bytes, &runtime.config, &runtime.avatar_map)
        {
            BLOCKED_RICH_PRESENCE_APP.store(
                filtered
                    .blocked_rich_presence_app
                    .map_or(0, |app_id| app_id.0),
                Ordering::Release,
            );
            let Some(new_body) = filtered.body else {
                crate::packet_capture::capture(
                    PacketDirection::Send,
                    data,
                    PacketChange::Unchanged,
                    None,
                );
                return SendFrameDecision::Pass;
            };
            let replacement =
                vapor_forge_steam_protocol::assemble_raw(emsg_raw, header_bytes, &new_body);
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
        if let Ok(upload) = vapor_forge_steam_protocol::ClientRichPresenceUpload::decode(body_bytes)
        {
            if let Some(kv_data) = &upload.rich_presence_kv {
                rich_presence::on_rich_presence_upload(kv_data);
            }
        }
        let blocked_app = BLOCKED_RICH_PRESENCE_APP.load(Ordering::Acquire);
        if blocked_app != 0 {
            info!(
                app_id = blocked_app,
                "netpacket: blocked Rich Presence upload"
            );
            capture_dropped(data);
            return SendFrameDecision::Drop;
        }
    }

    // Inject access tokens into CMsgClientPICSProductInfoRequest.
    if emsg == EMSG_PICS_PRODUCT_INFO_REQUEST {
        let runtime = crate::client::install::runtime_snapshot();
        let ss = &runtime.script_state;
        if !ss.access_tokens.is_empty() {
            if let Some(new_body) = inject_access_tokens(body_bytes, &ss.access_tokens, &ss.apps) {
                let replacement =
                    vapor_forge_steam_protocol::assemble_raw(emsg_raw, header_bytes, &new_body);
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

fn notify_device_context_changed() {
    crate::achievement_worker::notify_context_changed();
    crate::playtime_worker::notify_context_changed();
    crate::playtime_downlink_worker::notify_context_changed();
    crate::stats_wakeup_worker::notify_context_changed();
    crate::client::user_stats::notify_context_changed();
    stats_proxy::notify_context_changed();
}

fn handle_record_disconnected_playtime(
    emsg_raw: u32,
    header_bytes: &[u8],
    body: &[u8],
    original_packet: &[u8],
    config: &vapor_forge_config::RuntimeConfig,
) -> SendFrameDecision {
    let request = match PlayerRecordDisconnectedPlaytimeRequest::decode(body) {
        Ok(request) => request,
        Err(error) => {
            warn!(%error, "playtime-sync: blocked malformed Steam session request");
            queue_local_response(valve_filter::service_response(
                header_bytes,
                PlayerRecordDisconnectedPlaytimeResponse {}.encode_to_vec(),
                ERESULT_INVALID_PARAM,
            ));
            capture_dropped(original_packet);
            return SendFrameDecision::Drop;
        }
    };
    let mut protected_sessions = Vec::new();
    let mut valve_sessions = Vec::new();
    for session in request.play_sessions {
        let Some(app_id) = session.app_id.filter(|app_id| *app_id != 0) else {
            valve_sessions.push(session);
            continue;
        };
        if config.is_controlled_app(AppId(app_id)) {
            protected_sessions.push((app_id, session));
        } else {
            valve_sessions.push(session);
        }
    }
    if protected_sessions.is_empty() {
        return SendFrameDecision::Pass;
    }

    let Some(backend) = crate::cloud_backend::backend_context() else {
        warn!("playtime-sync: backend unavailable; controlled sessions were not recorded");
        return finish_disconnected_playtime(
            emsg_raw,
            header_bytes,
            original_packet,
            valve_sessions,
            0,
        );
    };
    if !backend.accepts_playtime_sessions() {
        for (app_id, _) in &protected_sessions {
            crate::client::user_stats::signal_router_playtime(*app_id);
        }
        return finish_disconnected_playtime(
            emsg_raw,
            header_bytes,
            original_packet,
            valve_sessions,
            protected_sessions.len(),
        );
    }
    let steam_id64 = identity::steam_id();
    if steam_id64 == 0 {
        warn!("playtime-sync: account unavailable; controlled sessions were not recorded");
        return finish_disconnected_playtime(
            emsg_raw,
            header_bytes,
            original_packet,
            valve_sessions,
            0,
        );
    }
    let Some(scope) = crate::sync_journal::cached_principal_scope(backend.as_ref()) else {
        warn!("playtime-sync: principal unavailable; controlled sessions were not recorded");
        return finish_disconnected_playtime(
            emsg_raw,
            header_bytes,
            original_packet,
            valve_sessions,
            0,
        );
    };
    let observed_at = unix_now();
    let mut protected = Vec::new();
    for (app_id, session) in protected_sessions {
        let Some(started_at) = session.session_time_start else {
            warn!(
                app_id,
                "playtime-sync: protected session omitted start time"
            );
            continue;
        };
        if started_at == 0 {
            warn!(
                app_id,
                "playtime-sync: protected session has zero start time"
            );
            continue;
        }
        let Some(seconds) = session.seconds.filter(|seconds| *seconds != 0) else {
            warn!(app_id, "playtime-sync: protected session omitted duration");
            continue;
        };
        let offline = session.offline.unwrap_or(false);
        let owner_account_id = session.owner.unwrap_or(steam_id64 as u32);
        protected.push(vapor_forge_cloud_core::PlaytimeSession {
            owner_scope: scope.clone(),
            owner_steam_id64: steam_id64.to_string(),
            session_id: vapor_forge_cloud_core::playtime_session_id(
                &steam_id64.to_string(),
                app_id,
                started_at,
                seconds,
                offline,
                owner_account_id,
            ),
            app_id,
            started_at,
            seconds,
            offline,
            owner_account_id,
            observed_at,
        });
    }
    if !crate::playtime_worker::persist_sessions(backend.as_ref(), &protected) {
        warn!("playtime-sync: controlled sessions could not be persisted");
        return finish_disconnected_playtime(
            emsg_raw,
            header_bytes,
            original_packet,
            valve_sessions,
            0,
        );
    }
    // Also sample the cumulative value for each disconnected-playtime report.
    // This supplements this recovery path only; ordinary exits rely on Steam's
    // minutes-played notification.
    for app_id in protected.iter().map(|session| session.app_id) {
        crate::client::user_stats::signal_router_playtime(app_id);
    }
    finish_disconnected_playtime(
        emsg_raw,
        header_bytes,
        original_packet,
        valve_sessions,
        protected.len(),
    )
}

fn finish_disconnected_playtime(
    emsg_raw: u32,
    header_bytes: &[u8],
    original_packet: &[u8],
    valve_sessions: Vec<PlayerPlayHistory>,
    persisted: usize,
) -> SendFrameDecision {
    if valve_sessions.is_empty() {
        queue_local_response(valve_filter::service_response(
            header_bytes,
            PlayerRecordDisconnectedPlaytimeResponse {}.encode_to_vec(),
            ERESULT_OK,
        ));
        info!(
            count = persisted,
            "playtime-sync: completed controlled Steam session response"
        );
        capture_dropped(original_packet);
        SendFrameDecision::Drop
    } else {
        let rewritten = PlayerRecordDisconnectedPlaytimeRequest {
            play_sessions: valve_sessions,
        }
        .encode_to_vec();
        let replacement =
            vapor_forge_steam_protocol::assemble_raw(emsg_raw, header_bytes, &rewritten);
        crate::packet_capture::capture(
            PacketDirection::Send,
            original_packet,
            PacketChange::Rewritten,
            Some(replacement.len()),
        );
        SendFrameDecision::Rewrite(replacement)
    }
}

/// Refresh the local SteamID from a CMsgProtoBufHeader, if present.
fn capture_local_steamid(header_bytes: &[u8]) {
    if let Ok(hdr) = CMsgProtoBufHeader::decode(header_bytes) {
        if let Some(steamid) = hdr.steamid {
            observe_local_steamid(steamid);
        }
    }
}

fn observe_local_steamid(steamid: u64) {
    crate::client::observe_steam_id(steamid);
}

pub(super) fn capture_dropped(data: &[u8]) {
    crate::packet_capture::capture(PacketDirection::Send, data, PacketChange::Dropped, Some(0));
}

pub(super) fn queue_local_response(packet: Vec<u8>) {
    queue_local_response_for_generation(packet, crate::client::network::injection_generation());
}

pub(super) fn queue_local_response_for_generation(packet: Vec<u8>, generation: u64) {
    {
        let mut queue = LOCAL_RESPONSES.lock().unwrap();
        queue.push_back(LocalResponse { packet, generation });
    }
    // Dispatch now instead of waiting for the next inbound packet.
    super::drain_local();
}

fn local_ownership_ticket_response(
    header_bytes: &[u8],
    body_bytes: &[u8],
) -> Option<(u32, Vec<u8>)> {
    let request = GetAppOwnershipTicketRequest::decode(body_bytes).ok()?;
    let app_id = request.app_id.filter(|app_id| *app_id != 0)?;
    let runtime = crate::client::install::runtime_snapshot();
    if !vapor_forge_features::apps::classify_app(&runtime.config, AppId(app_id))
        .requires_injected_ownership()
    {
        return None;
    }
    let ticket = crate::client::install::TICKET_CACHE
        .get_app_ticket(AppId(app_id), &runtime.script_state.app_tickets);
    let response = GetAppOwnershipTicketResponse {
        eresult: Some(if ticket.is_some() {
            ERESULT_OK as u32
        } else {
            2
        }),
        app_id: Some(app_id),
        ticket,
    };
    Some((
        app_id,
        valve_filter::emsg_response(
            EMSG_GET_APP_OWNERSHIP_TICKET_RESPONSE,
            header_bytes,
            response.encode_to_vec(),
        ),
    ))
}

fn local_encrypted_ticket_response(
    header_bytes: &[u8],
    body_bytes: &[u8],
) -> Option<(u32, Vec<u8>)> {
    let request = EncryptedAppTicketRequest::decode(body_bytes).ok()?;
    let app_id = request.app_id.filter(|id| *id != 0)?;
    let runtime = crate::client::install::runtime_snapshot();
    if !vapor_forge_features::apps::classify_app(&runtime.config, AppId(app_id))
        .requires_injected_ownership()
    {
        return None;
    }
    let ticket = crate::client::install::TICKET_CACHE
        .get_enc_ticket(AppId(app_id), &runtime.script_state.enc_tickets)?;
    Some((
        app_id,
        build_encrypted_ticket_response(header_bytes, app_id, ticket),
    ))
}

fn build_encrypted_ticket_response(header_bytes: &[u8], app_id: u32, ticket: Vec<u8>) -> Vec<u8> {
    let response = EncryptedAppTicketResponse {
        app_id: Some(app_id),
        eresult: Some(ERESULT_OK),
        encrypted_app_ticket: Some(EncryptedAppTicket {
            ticket_version_no: None,
            crc_encryptedticket: None,
            cb_encrypteduserdata: None,
            cb_encrypted_appownershipticket: None,
            encrypted_ticket: Some(ticket),
        }),
    };
    valve_filter::emsg_response(
        EMSG_ENCRYPTED_APPTICKET_RESPONSE,
        header_bytes,
        response.encode_to_vec(),
    )
}

/// Feed the outgoing CMsgClientGamesPlayed body to rich_presence so it can
/// track which real AppId (pre-avatar-rewrite) is currently being played.
fn track_games_played(body_bytes: &[u8], runtime: &crate::client::install::RuntimeSnapshot) {
    let Ok(msg) = vapor_forge_steam_protocol::CMsgClientGamesPlayed::decode(body_bytes) else {
        return;
    };
    let app_ids: Vec<AppId> = msg
        .games_played
        .iter()
        .filter_map(|g| g.game_id)
        .filter_map(app_id_from_game_id)
        .map(AppId)
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
        let active_app_ids: Vec<u32> = now_playing.iter().map(|app_id| app_id.0).collect();
        server.revoke_stopped_app_tokens(&active_app_ids);
    }
}

fn inject_access_tokens(
    body_bytes: &[u8],
    tokens: &std::collections::HashMap<AppId, u64>,
    controlled_apps: &std::collections::HashSet<AppId>,
) -> Option<Vec<u8>> {
    let mut req = vapor_forge_steam_protocol::PicsProductInfoRequest::decode(body_bytes).ok()?;
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
    let fetch = match request_code::plan_fetch(hdr, header_bytes, body_bytes) {
        Ok(fetch) => fetch,
        Err(request_code::ManifestFetchError::Decode(error)) => {
            warn!(%error, "netpacket: failed to decode manifest request");
            return false;
        }
        Err(request_code::ManifestFetchError::MissingJobId) => {
            debug!("netpacket: missing or zero jobid_source, passing through");
            return false;
        }
    };
    let request_code::ManifestCodeFetch {
        job_id,
        app_id,
        depot_id,
        gid,
        req_hdr_bytes,
    } = fetch;

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
            req_hdr_bytes,
        },
        cfg,
        lua_callback,
        crate::client::network::injection_generation(),
    )
}

/// Process an incoming frame before Steam handles the real packet.
pub(super) fn process_recv_frame(buf: &[u8]) -> RecvFrameDecision {
    let Some((emsg_raw, hdr_bytes, body_bytes)) = vapor_forge_steam_protocol::unpack_raw(buf)
    else {
        crate::packet_capture::capture(
            PacketDirection::Recv,
            buf,
            PacketChange::DecodeFailed,
            None,
        );
        return RecvFrameDecision::Pass;
    };
    let emsg = emsg_raw & !K_MSG_HDR_PROTO_FLAG;
    if emsg == EMSG_CLIENT_LOG_ON_RESPONSE {
        if let Some((steam_id, client_id)) =
            vapor_forge_steam_protocol::successful_logon_identity(hdr_bytes, body_bytes)
        {
            crate::client::set_authoritative_steam_id(steam_id);
            if let Some(client_id) = client_id {
                let completion = complete_login_device(client_id);
                if completion.changed {
                    notify_device_context_changed();
                }
                info!(
                    client_id,
                    metadata_matched = completion.metadata_matched,
                    machine_name_present = completion.machine_name_present,
                    os_type = ?completion.os_type,
                    device_type = ?completion.device_type,
                    "CM login: device identity captured"
                );
            } else {
                clear_pending_login_device();
            }
        } else {
            clear_pending_login_device();
        }
    } else if emsg == EMSG_CLIENT_LOGGED_OFF {
        clear_pending_login_device();
        crate::client::set_authoritative_steam_id(0);
    }
    let mut change = PacketChange::Unchanged;
    let mut final_len = None;
    let mut replacement = None;

    // ServiceMethod response (147): playtime observation and achievement stats.
    if emsg == EMSG_SERVICE_METHOD_RESPONSE {
        let Ok(hdr) = CMsgProtoBufHeader::decode(hdr_bytes) else {
            crate::packet_capture::capture(
                PacketDirection::Recv,
                buf,
                PacketChange::DecodeFailed,
                None,
            );
            return RecvFrameDecision::Pass;
        };
        if let Some(decision) = stats_proxy::handle_proxy_service_stats_response(&hdr, body_bytes) {
            crate::packet_capture::capture(
                PacketDirection::Recv,
                buf,
                PacketChange::Dropped,
                Some(0),
            );
            return decision;
        }
        if let Some(snapshot) =
            vapor_forge_features::playtime::observe_response(&hdr, body_bytes, identity::steam_id())
        {
            observe_local_steamid(snapshot.steam_id64);
            crate::playtime_worker::queue(snapshot);
            let config = crate::client::install::config();
            if let Some(new_body) =
                crate::client::playtime_downlink::rewrite_last_played_response(body_bytes, &config)
            {
                let rewritten =
                    vapor_forge_steam_protocol::assemble_raw(emsg_raw, hdr_bytes, &new_body);
                final_len = Some(rewritten.len());
                replacement = Some(rewritten);
                change = PacketChange::Rewritten;
            }
        }
        let observed_app_id = hdr.jobid_target.and_then(take_stats_request);
        let original_stats = PlayerGetUserStatsResponse::decode(body_bytes).ok();
        if let Some((new_hdr, new_body, schema)) =
            achievements::on_recv_service_stats(&hdr, body_bytes)
        {
            if let Some(schema) = schema {
                crate::client::achievement::register_packet_schema(schema.app_id, &schema.content);
                crate::achievement_worker::queue_schema(
                    schema.app_id,
                    schema.schema_version,
                    schema.content,
                );
            }
            let rewritten = vapor_forge_steam_protocol::assemble_raw(emsg_raw, &new_hdr, &new_body);
            final_len = Some(rewritten.len());
            replacement = Some(rewritten);
            change = PacketChange::Rewritten;
        } else if let (Some(app_id), Some(response)) = (observed_app_id, original_stats) {
            if let Some(schema) = response.schema {
                crate::client::achievement::register_packet_schema(app_id, &schema);
            }
        }
    }

    // ServiceMethodSendToClient (152): Steam's native playtime push.
    if emsg == EMSG_SERVICE_METHOD_SEND_TO_CLIENT {
        let Ok(hdr) = CMsgProtoBufHeader::decode(hdr_bytes) else {
            crate::packet_capture::capture(
                PacketDirection::Recv,
                buf,
                PacketChange::DecodeFailed,
                None,
            );
            return RecvFrameDecision::Pass;
        };
        if let Some(method) = hdr.target_job_name.as_deref() {
            if let Some(snapshot) = vapor_forge_features::playtime::observe_notification(
                method,
                &hdr,
                body_bytes,
                identity::steam_id(),
            ) {
                observe_local_steamid(snapshot.steam_id64);
                crate::playtime_worker::queue(snapshot);
                let config = crate::client::install::config();
                if let Some(new_body) =
                    crate::client::playtime_downlink::rewrite_last_played_notification(
                        body_bytes, &config,
                    )
                {
                    let rewritten =
                        vapor_forge_steam_protocol::assemble_raw(emsg_raw, hdr_bytes, &new_body);
                    final_len = Some(rewritten.len());
                    replacement = Some(rewritten);
                    change = PacketChange::Rewritten;
                }
            }
        }
    }

    // Legacy response (819): keep schema, remove reference-account values.
    if emsg == EMSG_REQUEST_USERSTATS_RESPONSE {
        if let Some(decision) = stats_proxy::handle_proxy_legacy_stats_response(body_bytes) {
            crate::packet_capture::capture(
                PacketDirection::Recv,
                buf,
                PacketChange::Dropped,
                Some(0),
            );
            return decision;
        }
        let config = crate::client::install::config();
        let original_stats =
            vapor_forge_steam_protocol::ClientGetUserStatsResponse::decode(body_bytes).ok();
        if let Some((new_body, schema)) = achievements::on_recv_legacy_stats(body_bytes, &config) {
            if let Some(schema) = schema {
                crate::client::achievement::register_packet_schema(schema.app_id, &schema.content);
                crate::achievement_worker::queue_schema(
                    schema.app_id,
                    schema.schema_version,
                    schema.content,
                );
            }
            let rewritten =
                vapor_forge_steam_protocol::assemble_raw(emsg_raw, hdr_bytes, &new_body);
            final_len = Some(rewritten.len());
            replacement = Some(rewritten);
            change = PacketChange::Rewritten;
        } else if let Some(response) = original_stats {
            if let Some(game_id) = response.game_id {
                if let (Some(app_id), Some(schema)) =
                    (app_id_from_game_id(game_id), response.schema)
                {
                    crate::client::achievement::register_packet_schema(app_id, &schema);
                }
            }
        }
    }

    // Encrypted app ticket response (5527): cache or inject from Lua/cache
    if emsg == EMSG_ENCRYPTED_APPTICKET_RESPONSE {
        if let Some(new_body) = handle_encrypted_ticket_response(body_bytes) {
            let rewritten =
                vapor_forge_steam_protocol::assemble_raw(emsg_raw, hdr_bytes, &new_body);
            final_len = Some(rewritten.len());
            replacement = Some(rewritten);
            change = PacketChange::Rewritten;
        }
    }

    // PersonaState (766): cache our own entry as an inject template, and
    // patch it live with the real AppId/rich presence while an avatared app
    // is being played.
    if emsg == EMSG_CLIENT_PERSONA_STATE {
        rich_presence::cache_self_persona(hdr_bytes, body_bytes);
        if let Some(new_body) = rich_presence::patch_persona_state(body_bytes) {
            let rewritten =
                vapor_forge_steam_protocol::assemble_raw(emsg_raw, hdr_bytes, &new_body);
            final_len = Some(rewritten.len());
            replacement = Some(rewritten);
            change = PacketChange::Rewritten;
        }
    }

    // SharedLibraryStopPlaying (9406): server tells the borrower to stop the
    // family-shared app because the real owner just started playing. Blank
    // the body so the client processes it as a no-op.
    if emsg == EMSG_CLIENT_SHARED_LIBRARY_STOP_PLAYING {
        let rewritten = vapor_forge_steam_protocol::assemble_raw(emsg_raw, hdr_bytes, &[]);
        info!("netpacket: cleared SharedLibraryStopPlaying body");
        final_len = Some(rewritten.len());
        replacement = Some(rewritten);
        change = PacketChange::Rewritten;
    }

    // FamilyGroupsClient.NotifyRunningApps#1: server notifies the family group
    // that the borrower is running an app; same suppression as above so the
    // owner side never gets asked to kick us.
    if emsg == EMSG_SERVICE_METHOD_RESPONSE {
        if let Ok(hdr) = CMsgProtoBufHeader::decode(hdr_bytes) {
            if hdr.target_job_name.as_deref() == Some(FAMILY_GROUPS_NOTIFY_RUNNING_APPS_JOB) {
                let rewritten = vapor_forge_steam_protocol::assemble_raw(emsg_raw, hdr_bytes, &[]);
                info!("netpacket: cleared FamilyGroupsClient.NotifyRunningApps body");
                final_len = Some(rewritten.len());
                replacement = Some(rewritten);
                change = PacketChange::Rewritten;
            }
        }
    }

    crate::packet_capture::capture(PacketDirection::Recv, buf, change, final_len);
    replacement.map_or(RecvFrameDecision::Pass, RecvFrameDecision::Rewrite)
}

fn track_stats_request(header: &CMsgProtoBufHeader, body: &[u8]) {
    let Some(job_id) = header.jobid_source.filter(|job_id| *job_id != 0) else {
        return;
    };
    let Some(app_id) = PlayerGetUserStatsRequest::decode(body)
        .ok()
        .and_then(|request| request.appid)
        .filter(|app_id| *app_id != 0)
    else {
        return;
    };
    let mut requests = STATS_REQUESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    requests.retain(|(existing, _)| *existing != job_id);
    if requests.len() == MAX_STATS_REQUESTS {
        requests.pop_front();
    }
    requests.push_back((job_id, app_id));
}

fn take_stats_request(job_id: u64) -> Option<u32> {
    let mut requests = STATS_REQUESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let position = requests
        .iter()
        .position(|(pending, _)| *pending == job_id)?;
    requests.remove(position).map(|(_, app_id)| app_id)
}

fn handle_encrypted_ticket_response(body_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut resp =
        vapor_forge_steam_protocol::EncryptedAppTicketResponse::decode(body_bytes).ok()?;
    let app_id = AppId(resp.app_id.unwrap_or(0));
    let eresult = resp.eresult.unwrap_or(2);

    let ticket_cache = &*crate::client::install::TICKET_CACHE;
    let runtime = crate::client::install::runtime_snapshot();
    let ss = &runtime.script_state;
    let cfg = &runtime.config;
    let controlled = cfg.is_controlled_app(app_id);

    if eresult == vapor_forge_steam_protocol::ERESULT_OK {
        // Success: cache the ticket for future use. For controlled apps we
        // additionally override Steam's response with our cache/Lua ticket if
        // one is configured, so the game side always ends up with the ticket
        // we control instead of whatever the CM sent.
        if let Some(ticket) = &resp.encrypted_app_ticket {
            if let Some(data) = &ticket.encrypted_ticket {
                let persist = if controlled {
                    cfg.ticket_mode(app_id) == vapor_forge_config::TicketMode::Delegate
                } else {
                    cfg.ticket.cache == vapor_forge_config::TicketCacheMode::Disk
                };
                ticket_cache.store_enc_ticket(app_id, data.clone(), persist);
            }
        }
        if controlled {
            if let Some(data) = ticket_cache.get_enc_ticket(app_id, &ss.enc_tickets) {
                let already_matches = resp
                    .encrypted_app_ticket
                    .as_ref()
                    .and_then(|t| t.encrypted_ticket.as_ref())
                    .is_some_and(|existing| existing == &data);
                if !already_matches {
                    let ticket = resp
                        .encrypted_app_ticket
                        .get_or_insert_with(Default::default);
                    ticket.encrypted_ticket = Some(data);
                    info!(
                        app_id = app_id.0,
                        "netpacket: encrypted ticket overridden with cached copy"
                    );
                    return Some(resp.encode_to_vec());
                }
            }
        }
        return None;
    }

    // Locally served requests are completed before they leave the client.
    // Preserve genuine CM failures for requests that were passed through.
    None
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn encrypted_ticket_response_completes_the_original_job() {
        let request_header = CMsgProtoBufHeader {
            steamid: Some(76561198000000000),
            jobid_source: Some(42),
            ..Default::default()
        };
        let ticket = vec![0x10, 0x20, 0x30, 0x40];

        let packet =
            build_encrypted_ticket_response(&request_header.encode_to_vec(), 480, ticket.clone());
        let (emsg_raw, header_bytes, body_bytes) =
            vapor_forge_steam_protocol::unpack_raw(&packet).unwrap();
        let response_header = CMsgProtoBufHeader::decode(header_bytes).unwrap();
        let response = EncryptedAppTicketResponse::decode(body_bytes).unwrap();

        assert_eq!(
            emsg_raw & !K_MSG_HDR_PROTO_FLAG,
            EMSG_ENCRYPTED_APPTICKET_RESPONSE
        );
        assert_eq!(response_header.jobid_source, None);
        assert_eq!(response_header.jobid_target, Some(42));
        assert_eq!(response_header.eresult, Some(ERESULT_OK));
        assert_eq!(response.app_id, Some(480));
        assert_eq!(response.eresult, Some(ERESULT_OK));
        assert_eq!(
            response
                .encrypted_app_ticket
                .and_then(|encrypted| encrypted.encrypted_ticket),
            Some(ticket)
        );
    }

    #[test]
    fn access_tokens_require_addappid_and_skip_zero() {
        let request = vapor_forge_steam_protocol::PicsProductInfoRequest {
            apps: vec![
                vapor_forge_steam_protocol::PicsAppInfo {
                    appid: Some(480),
                    access_token: None,
                    only_public_obsolete: None,
                },
                vapor_forge_steam_protocol::PicsAppInfo {
                    appid: Some(730),
                    access_token: Some(7),
                    only_public_obsolete: None,
                },
                vapor_forge_steam_protocol::PicsAppInfo {
                    appid: Some(999),
                    access_token: None,
                    only_public_obsolete: None,
                },
            ],
            obsolete_supports_package_tokens: Some(1),
            sequence_number: Some(77),
            single_response: Some(true),
            ..Default::default()
        };
        let tokens = HashMap::from([(AppId(480), 42), (AppId(730), 0), (AppId(999), 99)]);

        let controlled: std::collections::HashSet<AppId> =
            [AppId(480), AppId(730)].into_iter().collect();
        let rewritten =
            inject_access_tokens(&request.encode_to_vec(), &tokens, &controlled).unwrap();
        let rewritten =
            vapor_forge_steam_protocol::PicsProductInfoRequest::decode(rewritten.as_slice())
                .unwrap();
        assert_eq!(rewritten.apps[0].access_token, Some(42));
        assert_eq!(rewritten.apps[1].access_token, Some(7));
        assert_eq!(rewritten.apps[2].access_token, None);
        assert_eq!(rewritten.obsolete_supports_package_tokens, Some(1));
        assert_eq!(rewritten.sequence_number, Some(77));
        assert_eq!(rewritten.single_response, Some(true));
    }

    #[test]
    fn access_token_rewrite_is_none_without_eligible_apps() {
        let request = vapor_forge_steam_protocol::PicsProductInfoRequest {
            apps: vec![vapor_forge_steam_protocol::PicsAppInfo {
                appid: Some(480),
                access_token: None,
                only_public_obsolete: None,
            }],
            ..Default::default()
        };
        let tokens = HashMap::from([(AppId(480), 42)]);

        let empty: std::collections::HashSet<AppId> = std::collections::HashSet::new();
        assert!(inject_access_tokens(&request.encode_to_vec(), &tokens, &empty).is_none());
    }

    #[test]
    fn record_disconnected_playtime_passes_uncontrolled_apps_without_backend() {
        let body = PlayerRecordDisconnectedPlaytimeRequest {
            play_sessions: vec![vapor_forge_steam_protocol::PlayerPlayHistory {
                app_id: Some(999),
                session_time_start: Some(1_700_000_000),
                seconds: Some(60),
                offline: Some(false),
                owner: Some(39734273),
            }],
        }
        .encode_to_vec();

        assert!(matches!(
            handle_record_disconnected_playtime(
                0,
                &[],
                &body,
                &body,
                &vapor_forge_config::RuntimeConfig::default()
            ),
            SendFrameDecision::Pass
        ));
    }
}
