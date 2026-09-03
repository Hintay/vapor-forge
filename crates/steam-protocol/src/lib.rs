//! Steam network framing, EMsg constants, and protobuf message definitions.

#![forbid(unsafe_code)]

pub const MANIFEST_REQUEST_CODE_JOB_NAME: &str = "ContentServerDirectory.GetManifestRequestCode#1";
pub const PLAYER_GET_USER_STATS_JOB_NAME: &str = "Player.GetUserStats#1";
pub const PLAYER_RECORD_DISCONNECTED_PLAYTIME_JOB_NAME: &str =
    "Player.RecordDisconnectedPlaytime#1";

#[derive(Clone, prost::Message)]
struct CloudBeginHttpUploadWireView {
    #[prost(uint32, optional, tag = "1")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct CloudBeginUgcUploadWireView {
    #[prost(uint32, optional, tag = "1")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct CloudGetSingleFileInfoWireView {
    #[prost(uint32, optional, tag = "1")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct CloudShareFileWireView {
    #[prost(uint32, optional, tag = "1")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct CloudEnumerateUserFilesWireView {
    #[prost(uint32, optional, tag = "1")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct CloudCommitHttpUploadWireView {
    #[prost(uint32, optional, tag = "2")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct CloudCommitUgcUploadWireView {
    #[prost(uint32, optional, tag = "2")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct CloudGetFileDetailsWireView {
    #[prost(uint32, optional, tag = "2")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct CloudDeleteWireView {
    #[prost(uint32, optional, tag = "2")]
    app_id: Option<u32>,
}

// Private projections of published Steam protobuf messages. Prost ignores
// fields not declared here, so callers get the AppID semantics they need
// without exposing incomplete message definitions as public protocol types.
#[derive(Clone, prost::Message)]
struct ClientMetricsAppInterfaceStatsWireView {
    #[prost(uint64, optional, tag = "1")]
    game_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
struct ClientMetricsCloudAppSyncStatsWireView {
    #[prost(uint32, optional, tag = "1")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct PlayerGetGameBadgeLevelsWireView {
    #[prost(uint32, optional, tag = "1")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct PublishedFileGetUserFilesWireView {
    #[prost(uint32, optional, tag = "2")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct SteamDeckCompatibilityShouldPromptWireView {
    #[prost(uint32, optional, tag = "1")]
    app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
struct UserNewsGetUserNewsWireView {
    #[prost(uint32, optional, tag = "6")]
    filter_app_id: Option<u32>,
}

// No current public Steam protobuf declares the EMsg 820 request. Runtime
// packets establish its fixed64 game_id at field 1; keep that projection
// private instead of presenting an inferred request as a complete schema.
#[derive(Clone, prost::Message)]
struct LegacyStoreUserStatsRequestWireView {
    #[prost(fixed64, optional, tag = "1")]
    game_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
struct ClientLogOnResponseWireView {
    #[prost(int32, optional, tag = "1")]
    eresult: Option<i32>,
    #[prost(fixed64, optional, tag = "20")]
    client_supplied_steam_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
struct ClientLogOnWireView {
    #[prost(uint32, optional, tag = "7")]
    client_os_type: Option<u32>,
    #[prost(string, optional, tag = "96")]
    machine_name: Option<String>,
    #[prost(string, optional, tag = "97")]
    machine_name_userchosen: Option<String>,
    #[prost(uint32, optional, tag = "111")]
    gaming_device_type: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientLogOnDevice {
    pub machine_name: String,
    pub os_type: Option<i64>,
    pub device_type: Option<i64>,
}

/// Decode an AppID from a known Steam service-method request.
///
/// Each method is decoded according to its published protobuf message rather
/// than by assuming that a field number has the same meaning across methods.
pub fn service_method_app_id(method: &str, body: &[u8]) -> Option<u32> {
    use prost::Message;

    let app_id = match method {
        "ClientMetrics.ClientAppInterfaceStatsReport#1" => {
            let game_id = ClientMetricsAppInterfaceStatsWireView::decode(body)
                .ok()?
                .game_id?;
            return app_id_from_game_id(game_id);
        }
        "ClientMetrics.ClientCloudAppSyncStats#1" => {
            ClientMetricsCloudAppSyncStatsWireView::decode(body)
                .ok()?
                .app_id
        }
        "Player.GetGameBadgeLevels#1" => {
            PlayerGetGameBadgeLevelsWireView::decode(body).ok()?.app_id
        }
        "PublishedFile.GetUserFiles#1" => {
            PublishedFileGetUserFilesWireView::decode(body).ok()?.app_id
        }
        "Store.ShouldPromptForCompatibilityFeedback#1" => {
            SteamDeckCompatibilityShouldPromptWireView::decode(body)
                .ok()?
                .app_id
        }
        "UserNews.GetUserNews#1" => {
            UserNewsGetUserNewsWireView::decode(body)
                .ok()?
                .filter_app_id
        }
        method if method.starts_with("Cloud.") => return cloud_request_app_id(method, body),
        _ => return None,
    }?;

    (app_id != 0).then_some(app_id)
}

/// Extract the low 24-bit Steam AppID component from a 64-bit `CGameID`.
pub fn app_id_from_game_id(game_id: u64) -> Option<u32> {
    let app_id = game_id as u32 & 0x00ff_ffff;
    (app_id != 0).then_some(app_id)
}

/// Decode the CGameID inferred from an EMsg 820 request.
pub fn legacy_store_user_stats_game_id(body: &[u8]) -> Option<u64> {
    use prost::Message;

    LegacyStoreUserStatsRequestWireView::decode(body)
        .ok()?
        .game_id
}

/// Decode the AppID carried by a Steam `Cloud.*#1` request.
///
/// Keeping this method table with the protobuf ABI prevents runtime routing
/// and offline packet inspection from maintaining different field guesses.
pub fn cloud_request_app_id(method: &str, body: &[u8]) -> Option<u32> {
    use prost::Message;

    let app_id = match method {
        "Cloud.BeginHTTPUpload#1" => CloudBeginHttpUploadWireView::decode(body).ok()?.app_id,
        "Cloud.BeginUGCUpload#1" => CloudBeginUgcUploadWireView::decode(body).ok()?.app_id,
        "Cloud.GetSingleFileInfo#1" => CloudGetSingleFileInfoWireView::decode(body).ok()?.app_id,
        "Cloud.ShareFile#1" => CloudShareFileWireView::decode(body).ok()?.app_id,
        "Cloud.EnumerateUserFiles#1" => CloudEnumerateUserFilesWireView::decode(body).ok()?.app_id,
        "Cloud.CommitHTTPUpload#1" => CloudCommitHttpUploadWireView::decode(body).ok()?.app_id,
        "Cloud.CommitUGCUpload#1" => CloudCommitUgcUploadWireView::decode(body).ok()?.app_id,
        "Cloud.GetFileDetails#1" => CloudGetFileDetailsWireView::decode(body).ok()?.app_id,
        "Cloud.Delete#1" => CloudDeleteWireView::decode(body).ok()?.app_id,
        "Cloud.GetAppFileChangelist#1" => {
            CloudGetAppFileChangelistRequest::decode(body).ok()?.app_id
        }
        "Cloud.BeginAppUploadBatch#1" => CloudBeginAppUploadBatchRequest::decode(body).ok()?.app_id,
        "Cloud.ClientBeginFileUpload#1" => {
            CloudClientBeginFileUploadRequest::decode(body).ok()?.app_id
        }
        "Cloud.ClientCommitFileUpload#1" => {
            CloudClientCommitFileUploadRequest::decode(body)
                .ok()?
                .app_id
        }
        "Cloud.CompleteAppUploadBatch#1" | "Cloud.CompleteAppUploadBatchBlocking#1" => {
            CloudCompleteAppUploadBatchRequest::decode(body)
                .ok()?
                .app_id
        }
        "Cloud.ClientFileDownload#1" => CloudClientFileDownloadRequest::decode(body).ok()?.app_id,
        "Cloud.ClientDeleteFile#1" => CloudClientDeleteFileRequest::decode(body).ok()?.app_id,
        "Cloud.ClientGetAppQuotaUsage#1" => {
            CloudClientGetAppQuotaUsageRequest::decode(body)
                .ok()?
                .app_id
        }
        "Cloud.SignalAppLaunchIntent#1" => CloudAppLaunchIntentRequest::decode(body).ok()?.app_id,
        "Cloud.SuspendAppSession#1" => CloudAppSessionSuspendRequest::decode(body).ok()?.app_id,
        "Cloud.ResumeAppSession#1" => CloudAppSessionResumeRequest::decode(body).ok()?.app_id,
        "Cloud.SignalAppExitSyncDone#1" => {
            CloudAppExitSyncDoneNotification::decode(body).ok()?.app_id
        }
        "Cloud.ClientConflictResolution#1" => {
            CloudClientConflictResolutionNotification::decode(body)
                .ok()?
                .app_id
        }
        _ => None,
    }?;
    (app_id != 0).then_some(app_id)
}

// ---------------------------------------------------------------------------
// Network packet framing
// ---------------------------------------------------------------------------

/// 8-byte packet header: EMsg (with proto flag) + protobuf header length.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MsgHdr {
    /// Lower 31 bits = EMsg, bit 31 = proto flag.
    pub emsg: u32,
    /// Size of the protobuf header that follows.
    pub header_length: u32,
}

impl MsgHdr {
    pub const SIZE: usize = 8;
}

/// EMsg for `ServiceMethodCallFromClient`.
pub const EMSG_SERVICE_METHOD_CALL_FROM_CLIENT: u32 = 151;

/// EMsg for `ServiceMethodResponse`.
pub const EMSG_SERVICE_METHOD_RESPONSE: u32 = 147;

/// EMsg for server-initiated service notifications.
pub const EMSG_SERVICE_METHOD_SEND_TO_CLIENT: u32 = 152;

/// CM login request, successful response, and server-initiated logout.
pub const EMSG_CLIENT_LOG_ON: u32 = 5514;
pub const EMSG_CLIENT_LOG_ON_RESPONSE: u32 = 751;
pub const EMSG_CLIENT_LOGGED_OFF: u32 = 757;

/// Bit 31 indicates protobuf framing.
pub const K_MSG_HDR_PROTO_FLAG: u32 = 0x8000_0000;

/// Unpack a raw packet into (emsg_raw, header_bytes, body_bytes).
///
/// Returns `None` if the data is too short or the header length overflows.
pub fn unpack_raw(data: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    if data.len() < MsgHdr::SIZE {
        return None;
    }
    let emsg_raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let hdr_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

    let hdr_end = MsgHdr::SIZE.checked_add(hdr_len)?;
    if data.len() < hdr_end {
        return None;
    }

    let header_bytes = &data[MsgHdr::SIZE..hdr_end];
    let body_bytes = &data[hdr_end..];
    Some((emsg_raw, header_bytes, body_bytes))
}

/// Assemble a complete packet from parts.
pub fn assemble_raw(emsg_raw: u32, header_bytes: &[u8], body_bytes: &[u8]) -> Vec<u8> {
    let total = MsgHdr::SIZE + header_bytes.len() + body_bytes.len();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&emsg_raw.to_le_bytes());
    buf.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(header_bytes);
    buf.extend_from_slice(body_bytes);
    buf
}

// ---------------------------------------------------------------------------
// Protobuf messages with prost derive, no .proto needed
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
pub struct CMsgGcRoutingProtoBufHeader {
    #[prost(uint64, optional, tag = "1")]
    pub dst_gc_id_queue: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    pub dst_gc_dir_index: Option<u32>,
}

#[derive(Clone, prost::Oneof)]
pub enum MsgProtoBufHeaderIpAddress {
    #[prost(uint32, tag = "15")]
    V4(u32),
    #[prost(bytes, tag = "29")]
    V6(Vec<u8>),
}

#[derive(Clone, prost::Message)]
pub struct CMsgProtoBufHeader {
    #[prost(fixed64, optional, tag = "1")]
    pub steamid: Option<u64>,
    #[prost(int32, optional, tag = "2")]
    pub client_session_id: Option<i32>,
    #[prost(uint32, optional, tag = "3")]
    pub routing_app_id: Option<u32>,
    #[prost(fixed64, optional, tag = "10")]
    pub jobid_source: Option<u64>,
    #[prost(fixed64, optional, tag = "11")]
    pub jobid_target: Option<u64>,
    #[prost(string, optional, tag = "12")]
    pub target_job_name: Option<String>,
    #[prost(int32, optional, tag = "13")]
    pub eresult: Option<i32>,
    #[prost(string, optional, tag = "14")]
    pub error_message: Option<String>,
    #[prost(uint32, optional, tag = "16")]
    pub auth_account_flags: Option<u32>,
    #[prost(int32, optional, tag = "17")]
    pub transport_error: Option<i32>,
    #[prost(uint64, optional, tag = "18")]
    pub message_id: Option<u64>,
    #[prost(uint32, optional, tag = "19")]
    pub publisher_group_id: Option<u32>,
    #[prost(uint32, optional, tag = "20")]
    pub system_id: Option<u32>,
    #[prost(uint32, optional, tag = "22")]
    pub token_source: Option<u32>,
    #[prost(bool, optional, tag = "23")]
    pub admin_spoofing_user: Option<bool>,
    #[prost(int32, optional, tag = "24")]
    pub seq_num: Option<i32>,
    #[prost(uint32, optional, tag = "25")]
    pub webapi_key_id: Option<u32>,
    #[prost(bool, optional, tag = "26")]
    pub is_from_external_source: Option<bool>,
    #[prost(uint32, repeated, packed = "false", tag = "27")]
    pub forward_to_system_id: Vec<u32>,
    #[prost(uint32, optional, tag = "28")]
    pub cm_system_id: Option<u32>,
    #[prost(uint32, optional, tag = "31")]
    pub launcher_type: Option<u32>,
    #[prost(uint32, optional, tag = "32")]
    pub realm: Option<u32>,
    #[prost(int32, optional, tag = "33")]
    pub timeout_ms: Option<i32>,
    #[prost(string, optional, tag = "34")]
    pub debug_source: Option<String>,
    #[prost(uint32, optional, tag = "35")]
    pub debug_source_string_index: Option<u32>,
    #[prost(uint64, optional, tag = "36")]
    pub token_id: Option<u64>,
    #[prost(message, optional, tag = "37")]
    pub routing_gc: Option<CMsgGcRoutingProtoBufHeader>,
    #[prost(int32, optional, tag = "38")]
    pub session_disposition: Option<i32>,
    #[prost(string, optional, tag = "39")]
    pub wg_token: Option<String>,
    #[prost(string, optional, tag = "40")]
    pub webui_auth_key: Option<String>,
    #[prost(int32, repeated, packed = "false", tag = "41")]
    pub exclude_client_session_ids: Vec<i32>,
    #[prost(fixed64, optional, tag = "43")]
    pub admin_request_spoofing_steamid: Option<u64>,
    #[prost(bool, optional, tag = "44")]
    pub is_valve_dedicated_server: Option<bool>,
    #[prost(fixed64, optional, tag = "45")]
    pub trace_tag: Option<u64>,
    #[prost(oneof = "MsgProtoBufHeaderIpAddress", tags = "15, 29")]
    pub ip_addr: Option<MsgProtoBufHeaderIpAddress>,
}

/// Return the local account carried by a successful CM login response.
pub fn successful_logon_steam_id(header: &[u8], body: &[u8]) -> Option<u64> {
    use prost::Message;

    let response = ClientLogOnResponseWireView::decode(body).ok()?;
    if response.eresult.unwrap_or(2) != ERESULT_OK {
        return None;
    }
    let steam_id = CMsgProtoBufHeader::decode(header)
        .ok()
        .and_then(|header| header.steamid)
        .or(response.client_supplied_steam_id)?;
    (steam_id != 0).then_some(steam_id)
}

/// Return the device identity submitted with a CM login request.
pub fn client_logon_device(body: &[u8]) -> Option<ClientLogOnDevice> {
    use prost::Message;

    let request = ClientLogOnWireView::decode(body).ok()?;
    let machine_name = request
        .machine_name_userchosen
        .filter(|name| !name.trim().is_empty())
        .or(request.machine_name)
        .unwrap_or_default();
    Some(ClientLogOnDevice {
        machine_name,
        os_type: request.client_os_type.map(|value| i64::from(value as i32)),
        device_type: request.gaming_device_type.map(i64::from),
    })
}

#[derive(Clone, prost::Message)]
pub struct GetManifestRequestCodeRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub depot_id: Option<u32>,
    #[prost(uint64, optional, tag = "3")]
    pub manifest_id: Option<u64>,
    #[prost(string, optional, tag = "4")]
    pub app_branch: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub branch_password_hash: Option<String>,
}

#[derive(Clone, prost::Message)]
pub struct GetManifestRequestCodeResponse {
    #[prost(uint64, optional, tag = "1")]
    pub manifest_request_code: Option<u64>,
}

// ---------------------------------------------------------------------------
// Steam client Cloud service RPCs
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
pub struct CloudCdnReportNotification {
    #[prost(fixed64, optional, tag = "1")]
    pub steam_id: Option<u64>,
    #[prost(string, optional, tag = "2")]
    pub url: Option<String>,
    #[prost(bool, optional, tag = "3")]
    pub success: Option<bool>,
    #[prost(uint32, optional, tag = "4")]
    pub http_status_code: Option<u32>,
    #[prost(uint64, optional, tag = "5")]
    pub expected_bytes: Option<u64>,
    #[prost(uint64, optional, tag = "6")]
    pub received_bytes: Option<u64>,
    #[prost(uint32, optional, tag = "7")]
    pub duration: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudExternalStorageTransferReportNotification {
    #[prost(string, optional, tag = "1")]
    pub host: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub path: Option<String>,
    #[prost(bool, optional, tag = "3")]
    pub is_upload: Option<bool>,
    #[prost(bool, optional, tag = "4")]
    pub success: Option<bool>,
    #[prost(uint32, optional, tag = "5")]
    pub http_status_code: Option<u32>,
    #[prost(uint64, optional, tag = "6")]
    pub bytes_expected: Option<u64>,
    #[prost(uint64, optional, tag = "7")]
    pub bytes_actual: Option<u64>,
    #[prost(uint32, optional, tag = "8")]
    pub duration_ms: Option<u32>,
    #[prost(uint32, optional, tag = "9")]
    pub cell_id: Option<u32>,
    #[prost(bool, optional, tag = "10")]
    pub proxied: Option<bool>,
    #[prost(bool, optional, tag = "11")]
    pub ipv6_local: Option<bool>,
    #[prost(bool, optional, tag = "12")]
    pub ipv6_remote: Option<bool>,
    #[prost(uint32, optional, tag = "13")]
    pub time_to_connect_ms: Option<u32>,
    #[prost(uint32, optional, tag = "14")]
    pub time_to_send_request_ms: Option<u32>,
    #[prost(uint32, optional, tag = "15")]
    pub time_to_first_byte_ms: Option<u32>,
    #[prost(uint32, optional, tag = "16")]
    pub time_to_last_byte_ms: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudBeginAppUploadBatchRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(string, optional, tag = "2")]
    pub machine_name: Option<String>,
    #[prost(string, repeated, tag = "3")]
    pub files_to_upload: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub files_to_delete: Vec<String>,
    #[prost(uint64, optional, tag = "5")]
    pub client_id: Option<u64>,
    #[prost(uint64, optional, tag = "6")]
    pub app_build_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudBeginAppUploadBatchResponse {
    #[prost(uint64, optional, tag = "1")]
    pub batch_id: Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    pub app_change_number: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudCompleteAppUploadBatchRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub batch_id: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub batch_eresult: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudCompleteAppUploadBatchResponse {}

#[derive(Clone, prost::Message)]
pub struct CloudClientBeginFileUploadRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub file_size: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub raw_file_size: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub file_sha: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "5")]
    pub timestamp: Option<u64>,
    #[prost(string, optional, tag = "6")]
    pub filename: Option<String>,
    #[prost(uint32, optional, tag = "7")]
    pub platforms_to_sync: Option<u32>,
    #[prost(uint32, optional, tag = "9")]
    pub cell_id: Option<u32>,
    #[prost(bool, optional, tag = "10")]
    pub can_encrypt: Option<bool>,
    #[prost(bool, optional, tag = "11")]
    pub is_shared_file: Option<bool>,
    #[prost(uint32, optional, tag = "12")]
    pub deprecated_realm: Option<u32>,
    #[prost(uint64, optional, tag = "13")]
    pub upload_batch_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudHttpHeader {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub value: Option<String>,
}

#[derive(Clone, prost::Message)]
pub struct CloudFileUploadBlockDetails {
    #[prost(string, optional, tag = "1")]
    pub url_host: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub url_path: Option<String>,
    #[prost(bool, optional, tag = "3")]
    pub use_https: Option<bool>,
    #[prost(int32, optional, tag = "4")]
    pub http_method: Option<i32>,
    #[prost(message, repeated, tag = "5")]
    pub request_headers: Vec<CloudHttpHeader>,
    #[prost(uint64, optional, tag = "6")]
    pub block_offset: Option<u64>,
    #[prost(uint32, optional, tag = "7")]
    pub block_length: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub explicit_body_data: Option<Vec<u8>>,
    #[prost(bool, optional, tag = "9")]
    pub may_parallelize: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientBeginFileUploadResponse {
    #[prost(bool, optional, tag = "1")]
    pub encrypt_file: Option<bool>,
    #[prost(message, repeated, tag = "2")]
    pub block_requests: Vec<CloudFileUploadBlockDetails>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientCommitFileUploadRequest {
    #[prost(bool, optional, tag = "1")]
    pub transfer_succeeded: Option<bool>,
    #[prost(uint32, optional, tag = "2")]
    pub app_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub file_sha: Option<Vec<u8>>,
    #[prost(string, optional, tag = "4")]
    pub filename: Option<String>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientCommitFileUploadResponse {
    #[prost(bool, optional, tag = "1")]
    pub file_committed: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientFileDownloadRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(string, optional, tag = "2")]
    pub filename: Option<String>,
    #[prost(uint32, optional, tag = "3")]
    pub realm: Option<u32>,
    #[prost(bool, optional, tag = "4")]
    pub force_proxy: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientFileDownloadResponse {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub file_size: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub raw_file_size: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub sha_file: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "5")]
    pub timestamp: Option<u64>,
    #[prost(bool, optional, tag = "6")]
    pub is_explicit_delete: Option<bool>,
    #[prost(string, optional, tag = "7")]
    pub url_host: Option<String>,
    #[prost(string, optional, tag = "8")]
    pub url_path: Option<String>,
    #[prost(bool, optional, tag = "9")]
    pub use_https: Option<bool>,
    #[prost(message, repeated, tag = "10")]
    pub request_headers: Vec<CloudHttpHeader>,
    #[prost(bool, optional, tag = "11")]
    pub encrypted: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientDeleteFileRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(string, optional, tag = "2")]
    pub filename: Option<String>,
    #[prost(bool, optional, tag = "3")]
    pub is_explicit_delete: Option<bool>,
    #[prost(uint64, optional, tag = "4")]
    pub upload_batch_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientDeleteFileResponse {}

#[derive(Clone, prost::Message)]
pub struct CloudClientConflictResolutionNotification {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(bool, optional, tag = "2")]
    pub chose_local_files: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudGetAppFileChangelistRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub synced_change_number: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppFileInfo {
    #[prost(string, optional, tag = "1")]
    pub file_name: Option<String>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub sha_file: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "3")]
    pub timestamp: Option<u64>,
    #[prost(uint32, optional, tag = "4")]
    pub raw_file_size: Option<u32>,
    #[prost(int32, optional, tag = "5")]
    pub persist_state: Option<i32>,
    #[prost(uint32, optional, tag = "6")]
    pub platforms_to_sync: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    pub path_prefix_index: Option<u32>,
    #[prost(uint32, optional, tag = "8")]
    pub machine_name_index: Option<u32>,
    #[prost(bool, optional, tag = "9")]
    pub reupload_requested: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudGetAppFileChangelistResponse {
    #[prost(uint64, optional, tag = "1")]
    pub current_change_number: Option<u64>,
    #[prost(message, repeated, tag = "2")]
    pub files: Vec<CloudAppFileInfo>,
    #[prost(bool, optional, tag = "3")]
    pub is_only_delta: Option<bool>,
    #[prost(string, repeated, tag = "4")]
    pub path_prefixes: Vec<String>,
    #[prost(string, repeated, tag = "5")]
    pub machine_names: Vec<String>,
    #[prost(uint64, optional, tag = "6")]
    pub app_build_id_hwm: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppSessionSuspendRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub client_id: Option<u64>,
    #[prost(string, optional, tag = "3")]
    pub machine_name: Option<String>,
    #[prost(bool, optional, tag = "4")]
    pub cloud_sync_completed: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppSessionSuspendResponse {}

#[derive(Clone, prost::Message)]
pub struct CloudAppSessionResumeRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub client_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppSessionResumeResponse {}

#[derive(Clone, prost::Message)]
pub struct CloudAppLaunchIntentRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub client_id: Option<u64>,
    #[prost(string, optional, tag = "3")]
    pub machine_name: Option<String>,
    #[prost(bool, optional, tag = "4")]
    pub ignore_pending_operations: Option<bool>,
    #[prost(int32, optional, tag = "5")]
    pub os_type: Option<i32>,
    #[prost(int32, optional, tag = "6")]
    pub device_type: Option<i32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudPendingRemoteOperation {
    #[prost(int32, optional, tag = "1")]
    pub operation: Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub machine_name: Option<String>,
    #[prost(uint64, optional, tag = "3")]
    pub client_id: Option<u64>,
    #[prost(uint32, optional, tag = "4")]
    pub time_last_updated: Option<u32>,
    #[prost(int32, optional, tag = "5")]
    pub os_type: Option<i32>,
    #[prost(int32, optional, tag = "6")]
    pub device_type: Option<i32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppLaunchIntentResponse {
    #[prost(message, repeated, tag = "1")]
    pub pending_remote_operations: Vec<CloudPendingRemoteOperation>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppExitSyncDoneNotification {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub client_id: Option<u64>,
    #[prost(bool, optional, tag = "3")]
    pub uploads_completed: Option<bool>,
    #[prost(bool, optional, tag = "4")]
    pub uploads_required: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientGetAppQuotaUsageRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientGetAppQuotaUsageResponse {
    #[prost(uint32, optional, tag = "1")]
    pub existing_files: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub existing_bytes: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub max_num_files: Option<u32>,
    #[prost(uint64, optional, tag = "4")]
    pub max_num_bytes: Option<u64>,
}

// ---------------------------------------------------------------------------
// Encrypted app ticket
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
pub struct GetAppOwnershipTicketRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct GetAppOwnershipTicketResponse {
    #[prost(uint32, optional, tag = "1")]
    pub eresult: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub app_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub ticket: Option<Vec<u8>>,
}

#[derive(Clone, prost::Message)]
pub struct EncryptedAppTicketRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub userdata: Option<Vec<u8>>,
}

#[derive(Clone, prost::Message)]
pub struct EncryptedAppTicket {
    #[prost(uint32, optional, tag = "1")]
    pub ticket_version_no: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub crc_encryptedticket: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub cb_encrypteduserdata: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub cb_encrypted_appownershipticket: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub encrypted_ticket: Option<Vec<u8>>,
}

#[derive(Clone, prost::Message)]
pub struct EncryptedAppTicketResponse {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(int32, optional, tag = "2")]
    pub eresult: Option<i32>,
    #[prost(message, optional, tag = "3")]
    pub encrypted_app_ticket: Option<EncryptedAppTicket>,
}

// ---------------------------------------------------------------------------
// PICS ProductInfo (access token injection)
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
pub struct PicsProductInfoRequest {
    #[prost(message, repeated, tag = "1")]
    pub packages: Vec<PicsPackageInfo>,
    #[prost(message, repeated, tag = "2")]
    pub apps: Vec<PicsAppInfo>,
    #[prost(bool, optional, tag = "3")]
    pub meta_data_only: Option<bool>,
    #[prost(uint32, optional, tag = "4")]
    pub num_prev_failed: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    pub obsolete_supports_package_tokens: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub sequence_number: Option<u32>,
    #[prost(bool, optional, tag = "7")]
    pub single_response: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct PicsPackageInfo {
    #[prost(uint32, optional, tag = "1")]
    pub packageid: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub access_token: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct PicsAppInfo {
    #[prost(uint32, optional, tag = "1")]
    pub appid: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub access_token: Option<u64>,
    #[prost(bool, optional, tag = "3")]
    pub only_public_obsolete: Option<bool>,
}

// ---------------------------------------------------------------------------
// Achievement / stats messages
// ---------------------------------------------------------------------------

/// EMsg 151 outgoing: Player.GetUserStats#1 request
#[derive(Clone, prost::Message)]
pub struct PlayerGetUserStatsRequest {
    #[prost(uint64, optional, tag = "1")]
    pub steamid: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    pub appid: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub sha_schema: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "4")]
    pub crc_stats: Option<u32>,
    /// Published wire field. The current Steam x64 request path does not
    /// populate it, so callers must not use it as schema freshness state.
    #[prost(uint32, optional, tag = "5")]
    pub crc_schema: Option<u32>,
}

/// EMsg 147 incoming: Player.GetUserStats#1 response
#[derive(Clone, prost::Message)]
pub struct PlayerGetUserStatsResponse {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub sha_schema: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "2")]
    pub crc_stats: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub schema: Option<Vec<u8>>,
    #[prost(message, repeated, tag = "4")]
    pub stats: Vec<PlayerStatsEntry>,
    /// Published wire field retained for protocol fidelity. Runtime response
    /// synthesis intentionally leaves it absent.
    #[prost(uint32, optional, tag = "5")]
    pub crc_schema: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct PlayerStatsEntry {
    #[prost(uint32, optional, tag = "1")]
    pub stat_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub stat_value: Option<u32>,
    #[prost(message, repeated, tag = "3")]
    pub unlock_times: Vec<PlayerAchievementUnlockTime>,
}

#[derive(Clone, prost::Message)]
pub struct PlayerAchievementUnlockTime {
    #[prost(uint32, optional, tag = "1")]
    pub achievement_bit: Option<u32>,
    #[prost(fixed32, optional, tag = "2")]
    pub unlock_time: Option<u32>,
}

/// Steam's "unlocked, real time unknown" sentinel for a per-bit unlock time.
///
/// A valid rtime32 (2007-10-10) that the client backfills when it knows a bit is
/// set but has no authoritative timestamp. It is the encoding to emit downstream
/// for an unlocked achievement whose time we do not know: the alternative, an
/// absent time, cannot be represented in the wire form at all.
pub const ACHIEVEMENT_UNLOCK_TIME_UNKNOWN: u32 = 1_191_999_600;

/// Stats token for one app, derived from the state the Steam client will see.
///
/// The input is the canonical wire bytes of the `Player.GetUserStats#1` response's
/// repeated `stats` field, and nothing else. Everything invisible to the client
/// has to stay out, `observed_at` above all: the client reads this number as "has
/// my cache changed", so folding an observation timestamp in makes every
/// re-observation of unchanged state look like a change and forces a pointless
/// refetch.
///
/// A backend that issues its own token always wins over this function, because the
/// client hands the token back and that backend compares it against its own
/// record. This is for backends that issue none, where the token has to be a
/// deterministic function of content so that every reader derives the same one.
///
/// Kept byte-compatible with `steam_stats_wire.rs` in the Cumulus server so both
/// sides name the same state with the same number. The tests below duplicate that
/// crate's vectors deliberately.
pub fn stats_crc(stats: &[PlayerStatsEntry]) -> u32 {
    stats_crc32c(&canonical_stats_wire_bytes(stats))
}

/// CRC-32C (Castagnoli): reflected polynomial, inverted seed, inverted result.
fn stats_crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

/// Field 4 of the response, re-encoded one entry at a time in a fixed order so
/// that equal state always produces equal bytes. Entry order and per-entry unlock
/// time order are both normalized, because neither is guaranteed by whoever built
/// the list.
fn canonical_stats_wire_bytes(stats: &[PlayerStatsEntry]) -> Vec<u8> {
    use prost::Message;

    let mut bytes = Vec::new();
    for entry in sorted_player_stats(stats) {
        let entry = entry.encode_to_vec();
        bytes.push(0x22);
        encode_stats_varint(entry.len() as u64, &mut bytes);
        bytes.extend_from_slice(&entry);
    }
    bytes
}

fn encode_stats_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn sorted_player_stats(stats: &[PlayerStatsEntry]) -> Vec<PlayerStatsEntry> {
    let mut stats = stats.to_vec();
    stats.sort_by_key(|entry| entry.stat_id.unwrap_or(u32::MAX));
    for entry in &mut stats {
        entry
            .unlock_times
            .sort_by_key(|time| time.achievement_bit.unwrap_or(u32::MAX));
    }
    stats
}

// ---------------------------------------------------------------------------
// Native Steam playtime snapshots
// ---------------------------------------------------------------------------

/// `CPlayer_RecordDisconnectedPlaytime_Request`.
#[derive(Clone, prost::Message)]
pub struct PlayerRecordDisconnectedPlaytimeRequest {
    #[prost(message, repeated, tag = "3")]
    pub play_sessions: Vec<PlayerPlayHistory>,
}

/// `CPlayer_RecordDisconnectedPlaytime_Request.PlayHistory`.
#[derive(Clone, prost::Message)]
pub struct PlayerPlayHistory {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub session_time_start: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub seconds: Option<u32>,
    #[prost(bool, optional, tag = "4")]
    pub offline: Option<bool>,
    #[prost(uint32, optional, tag = "5")]
    pub owner: Option<u32>,
}

/// Empty `CPlayer_RecordDisconnectedPlaytime_Response`.
#[derive(Clone, prost::Message)]
pub struct PlayerRecordDisconnectedPlaytimeResponse {}

#[derive(Clone, prost::Message)]
pub struct PlayerGetLastPlayedTimesResponse {
    #[prost(message, repeated, tag = "1")]
    pub games: Vec<PlayerLastPlayedGame>,
}

#[derive(Clone, prost::Message)]
pub struct PlayerLastPlayedGame {
    #[prost(int32, optional, tag = "1")]
    pub app_id: Option<i32>,
    #[prost(uint32, optional, tag = "2")]
    pub last_playtime: Option<u32>,
    #[prost(int32, optional, tag = "3")]
    pub playtime_2weeks: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    pub playtime_forever: Option<i32>,
    #[prost(uint32, optional, tag = "5")]
    pub first_playtime: Option<u32>,
    #[prost(int32, optional, tag = "6")]
    pub playtime_windows_forever: Option<i32>,
    #[prost(int32, optional, tag = "7")]
    pub playtime_mac_forever: Option<i32>,
    #[prost(int32, optional, tag = "8")]
    pub playtime_linux_forever: Option<i32>,
    #[prost(uint32, optional, tag = "9")]
    pub first_windows_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "10")]
    pub first_mac_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "11")]
    pub first_linux_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "12")]
    pub last_windows_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "13")]
    pub last_mac_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "14")]
    pub last_linux_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "15")]
    pub playtime_disconnected: Option<u32>,
    #[prost(int32, optional, tag = "16")]
    pub playtime_deck_forever: Option<i32>,
    #[prost(uint32, optional, tag = "17")]
    pub first_deck_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "18")]
    pub last_deck_playtime: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct PlayerLastPlayedTimesNotification {
    #[prost(message, repeated, tag = "1")]
    pub games: Vec<PlayerLastPlayedGame>,
}

/// EMsg 818 outgoing: legacy CMsgClientGetUserStats
#[derive(Clone, prost::Message)]
pub struct ClientGetUserStatsRequest {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    pub crc_stats: Option<u32>,
    #[prost(int32, optional, tag = "3")]
    pub schema_local_version: Option<i32>,
    #[prost(fixed64, optional, tag = "4")]
    pub steam_id_for_user: Option<u64>,
}

/// EMsg 819 incoming: legacy CMsgClientGetUserStatsResponse
#[derive(Clone, prost::Message)]
pub struct ClientGetUserStatsResponse {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(int32, optional, tag = "2")]
    pub eresult: Option<i32>,
    #[prost(uint32, optional, tag = "3")]
    pub crc_stats: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub schema: Option<Vec<u8>>,
    #[prost(message, repeated, tag = "5")]
    pub stats: Vec<LegacyStatsEntry>,
    #[prost(message, repeated, tag = "6")]
    pub achievement_blocks: Vec<AchievementBlock>,
}

#[derive(Clone, prost::Message)]
pub struct LegacyStatsEntry {
    #[prost(uint32, optional, tag = "1")]
    pub stat_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub stat_value: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct AchievementBlock {
    #[prost(uint32, optional, tag = "1")]
    pub achievement_id: Option<u32>,
    #[prost(fixed32, repeated, packed = "false", tag = "2")]
    pub unlock_time: Vec<u32>,
}

/// Mapping from a Steam stats schema achievement key to the wire-level bit
/// used by `Player.GetUserStats#1` / `CMsgClientGetUserStatsResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AchievementBitMapping {
    pub stat_id: u32,
    pub achievement_bit: u32,
    pub key: String,
}

/// Mapping from a Steam stats schema ordinary stat key to the wire-level stat id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatMapping {
    pub stat_id: u32,
    pub key: String,
    pub value_type: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AchievementSchemaError {
    Truncated,
    InvalidUtf8,
    UnsupportedType(u8),
    LimitExceeded,
    MissingRoot,
}

const ACHIEVEMENT_SCHEMA_MAX_DEPTH: usize = 32;
const ACHIEVEMENT_SCHEMA_MAX_ENTRIES: usize = 100_000;

#[derive(Clone, Debug)]
enum AchievementSchemaValue {
    Object(std::collections::HashMap<String, AchievementSchemaValue>),
    String(String),
    Int(i64),
    Other,
}

impl AchievementSchemaValue {
    fn object(&self) -> Option<&std::collections::HashMap<String, AchievementSchemaValue>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    fn string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn int(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            _ => None,
        }
    }
}

struct AchievementSchemaParser<'a> {
    bytes: &'a [u8],
    position: usize,
    entries: usize,
}

impl<'a> AchievementSchemaParser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            entries: 0,
        }
    }

    fn byte(&mut self) -> Result<u8, AchievementSchemaError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(AchievementSchemaError::Truncated)?;
        self.position += 1;
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AchievementSchemaError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(AchievementSchemaError::LimitExceeded)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(AchievementSchemaError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn cstring(&mut self) -> Result<String, AchievementSchemaError> {
        let rest = self
            .bytes
            .get(self.position..)
            .ok_or(AchievementSchemaError::Truncated)?;
        let length = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(AchievementSchemaError::Truncated)?;
        let value = std::str::from_utf8(&rest[..length])
            .map_err(|_| AchievementSchemaError::InvalidUtf8)?
            .to_owned();
        self.position += length + 1;
        Ok(value)
    }

    fn object(
        &mut self,
        depth: usize,
    ) -> Result<std::collections::HashMap<String, AchievementSchemaValue>, AchievementSchemaError>
    {
        if depth > ACHIEVEMENT_SCHEMA_MAX_DEPTH {
            return Err(AchievementSchemaError::LimitExceeded);
        }
        let mut result = std::collections::HashMap::new();
        loop {
            let kind = self.byte()?;
            if kind == 8 {
                break;
            }
            self.entries += 1;
            if self.entries > ACHIEVEMENT_SCHEMA_MAX_ENTRIES {
                return Err(AchievementSchemaError::LimitExceeded);
            }
            let key = self.cstring()?;
            let value = match kind {
                0 => AchievementSchemaValue::Object(self.object(depth + 1)?),
                1 => AchievementSchemaValue::String(self.cstring()?),
                2 => AchievementSchemaValue::Int(i32::from_le_bytes(
                    self.take(4)?.try_into().expect("four bytes were requested"),
                ) as i64),
                3 | 4 | 6 => {
                    self.take(4)?;
                    AchievementSchemaValue::Other
                }
                5 => {
                    let units = u16::from_le_bytes(
                        self.take(2)?.try_into().expect("two bytes were requested"),
                    ) as usize;
                    self.take(units.saturating_mul(2))?;
                    AchievementSchemaValue::Other
                }
                7 => AchievementSchemaValue::Int(u64::from_le_bytes(
                    self.take(8)?
                        .try_into()
                        .expect("eight bytes were requested"),
                ) as i64),
                other => return Err(AchievementSchemaError::UnsupportedType(other)),
            };
            result.insert(key, value);
        }
        Ok(result)
    }
}

/// Parse the binary KeyValues stats schema returned by Steam and return the
/// achievement bit identifiers used by stats sync packets.
pub fn parse_achievement_bit_mappings(
    bytes: &[u8],
) -> Result<Vec<AchievementBitMapping>, AchievementSchemaError> {
    let root = parse_achievement_schema_root(bytes)?;
    let stats = schema_stats(&root)?;
    let mut mappings = Vec::new();
    for (stat_key, stat) in stats {
        let Ok(stat_id) = stat_key.parse::<u32>() else {
            continue;
        };
        let Some(bits) = stat
            .object()
            .and_then(|stat| stat.get("bits"))
            .and_then(AchievementSchemaValue::object)
        else {
            continue;
        };
        for (bit_key, achievement) in bits {
            let Ok(achievement_bit) = bit_key.parse::<u32>() else {
                continue;
            };
            let Some(key) = achievement
                .object()
                .and_then(|achievement| achievement.get("name"))
                .and_then(AchievementSchemaValue::string)
                .filter(|key| !key.trim().is_empty())
            else {
                continue;
            };
            mappings.push(AchievementBitMapping {
                stat_id,
                achievement_bit,
                key: key.to_owned(),
            });
        }
    }
    mappings.sort_by_key(|mapping| (mapping.stat_id, mapping.achievement_bit));
    Ok(mappings)
}

/// Parse the binary KeyValues stats schema returned by Steam and return the
/// ordinary stat identifiers used by stats sync packets.
pub fn parse_stat_mappings(bytes: &[u8]) -> Result<Vec<StatMapping>, AchievementSchemaError> {
    let root = parse_achievement_schema_root(bytes)?;
    let stats = schema_stats(&root)?;
    let mut mappings = Vec::new();
    for (stat_key, stat) in stats {
        let Ok(stat_id) = stat_key.parse::<u32>() else {
            continue;
        };
        let Some(stat) = stat.object() else {
            continue;
        };
        if stat.get("bits").is_some() {
            continue;
        }
        let Some(key) = stat
            .get("name")
            .and_then(AchievementSchemaValue::string)
            .filter(|key| !key.trim().is_empty())
        else {
            continue;
        };
        mappings.push(StatMapping {
            stat_id,
            key: key.to_owned(),
            value_type: stat
                .get("type")
                .and_then(AchievementSchemaValue::int)
                .or_else(|| stat.get("display").and_then(AchievementSchemaValue::int)),
        });
    }
    mappings.sort_by_key(|mapping| mapping.stat_id);
    Ok(mappings)
}

fn parse_achievement_schema_root(
    bytes: &[u8],
) -> Result<std::collections::HashMap<String, AchievementSchemaValue>, AchievementSchemaError> {
    let mut parser = AchievementSchemaParser::new(bytes);
    if parser.byte()? != 0 {
        return Err(AchievementSchemaError::MissingRoot);
    }
    let _root_name = parser.cstring()?;
    parser.object(0)
}

fn schema_stats(
    root: &std::collections::HashMap<String, AchievementSchemaValue>,
) -> Result<&std::collections::HashMap<String, AchievementSchemaValue>, AchievementSchemaError> {
    root.get("stats")
        .and_then(AchievementSchemaValue::object)
        .ok_or(AchievementSchemaError::MissingRoot)
}

#[derive(Clone, prost::Message)]
pub struct StoreUserStatsEntry {
    #[prost(uint32, optional, tag = "1")]
    pub stat_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub stat_value: Option<u32>,
}

/// EMsg 821 local acknowledgement for EMsg 820.
#[derive(Clone, prost::Message)]
pub struct ClientStoreUserStatsResponse {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(int32, optional, tag = "2")]
    pub eresult: Option<i32>,
    #[prost(uint32, optional, tag = "3")]
    pub crc_stats: Option<u32>,
    #[prost(message, repeated, tag = "4")]
    pub stats_failed_validation: Vec<StoreUserStatsFailedValidation>,
    #[prost(bool, optional, tag = "5")]
    pub stats_out_of_date: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct StoreUserStatsFailedValidation {
    #[prost(uint32, optional, tag = "1")]
    pub stat_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub reverted_stat_value: Option<u32>,
}

/// EMsg 5466 outgoing: commit stats for a specific Steam user.
#[derive(Clone, prost::Message)]
pub struct ClientStoreUserStats2Request {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(fixed64, optional, tag = "2")]
    pub settor_steam_id: Option<u64>,
    #[prost(fixed64, optional, tag = "3")]
    pub settee_steam_id: Option<u64>,
    #[prost(uint32, optional, tag = "4")]
    pub crc_stats: Option<u32>,
    #[prost(bool, optional, tag = "5")]
    pub explicit_reset: Option<bool>,
    #[prost(message, repeated, tag = "6")]
    pub stats: Vec<StoreUserStatsEntry>,
}

/// EMsg 5467 local acknowledgement for EMsg 5466.
#[derive(Clone, prost::Message)]
pub struct ClientStatsUpdated {
    #[prost(fixed64, optional, tag = "1")]
    pub steam_id: Option<u64>,
    #[prost(fixed64, optional, tag = "2")]
    pub game_id: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub crc_stats: Option<u32>,
    #[prost(message, repeated, tag = "4")]
    pub updated_stats: Vec<StoreUserStatsEntry>,
}

/// EMsg for CMsgClientPICSProductInfoRequest
pub const EMSG_PICS_PRODUCT_INFO_REQUEST: u32 = 8903;

/// EMsg for CMsgClientLicenseList: the account's package licenses, sent at
/// logon and again whenever they change (purchases, gifts, refunds).
pub const EMSG_CLIENT_LICENSE_LIST: u32 = 780;

/// One license of CMsgClientLicenseList (only the fields ownership needs).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClientLicense {
    #[prost(uint32, optional, tag = "1")]
    pub package_id: Option<u32>,
    #[prost(uint64, optional, tag = "17")]
    pub access_token: Option<u64>,
}

/// CMsgClientLicenseList body.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClientLicenseList {
    #[prost(int32, optional, tag = "1")]
    pub eresult: Option<i32>,
    #[prost(message, repeated, tag = "2")]
    pub licenses: Vec<ClientLicense>,
}

/// Package ids and access tokens of a CMsgClientLicenseList body, package 0
/// excluded: it is granted to every account and carries vapor-forge's own
/// injected apps, so it says nothing about genuine ownership.
pub fn licensed_packages(body: &[u8]) -> Option<Vec<(u32, u64)>> {
    use prost::Message;
    let list = ClientLicenseList::decode(body).ok()?;
    Some(
        list.licenses
            .iter()
            .filter_map(|license| {
                let package_id = license.package_id?;
                (package_id != 0).then_some((package_id, license.access_token.unwrap_or(0)))
            })
            .collect(),
    )
}

/// EMsg for CMsgClientRequestEncryptedAppTicketResponse
pub const EMSG_ENCRYPTED_APPTICKET_RESPONSE: u32 = 5527;
/// EMsg for CMsgClientRequestEncryptedAppTicket.
pub const EMSG_ENCRYPTED_APPTICKET_REQUEST: u32 = 5526;

/// EMsg ownership ticket request and response.
pub const EMSG_GET_APP_OWNERSHIP_TICKET: u32 = 857;
pub const EMSG_GET_APP_OWNERSHIP_TICKET_RESPONSE: u32 = 858;

/// EMsg constants for stats
pub const EMSG_REQUEST_USERSTATS: u32 = 818;
pub const EMSG_REQUEST_USERSTATS_RESPONSE: u32 = 819;
pub const EMSG_STORE_USERSTATS: u32 = 820;
pub const EMSG_STORE_USERSTATS_RESPONSE: u32 = 821;
pub const EMSG_STORE_USERSTATS2: u32 = 5466;
pub const EMSG_STATS_UPDATED: u32 = 5467;

// ---------------------------------------------------------------------------
// GamesPlayed messages
// ---------------------------------------------------------------------------

/// EMsg for CMsgClientGamesPlayed (modern path).
pub const EMSG_GAMESPLAYED: u32 = 742;
/// EMsg for CMsgClientGamesPlayedWithDataBlob (older path with extra blob).
pub const EMSG_GAMESPLAYED_WITH_DATABLOB: u32 = 5410;

#[derive(Clone, prost::Message)]
pub struct CMsgClientGamesPlayed {
    #[prost(message, repeated, tag = "1")]
    pub games_played: Vec<GamePlayed>,
    #[prost(uint32, optional, tag = "2")]
    pub client_os_type: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub cloud_gaming_platform: Option<u32>,
    #[prost(bool, optional, tag = "4")]
    pub recent_reauthentication: Option<bool>,
}

#[derive(Clone, prost::Oneof)]
pub enum IpAddressValue {
    #[prost(fixed32, tag = "1")]
    V4(u32),
    #[prost(bytes, tag = "2")]
    V6(Vec<u8>),
}

#[derive(Clone, prost::Message)]
pub struct CMsgIpAddress {
    #[prost(oneof = "IpAddressValue", tags = "1, 2")]
    pub ip: Option<IpAddressValue>,
}

#[derive(Clone, prost::Message)]
pub struct GamePlayedProcessInfo {
    #[prost(uint32, optional, tag = "1")]
    pub process_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub process_id_parent: Option<u32>,
    #[prost(bool, optional, tag = "3")]
    pub parent_is_steam: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct GamePlayed {
    #[prost(uint64, optional, tag = "1")]
    pub steam_id_gs: Option<u64>,
    #[prost(fixed64, optional, tag = "2")]
    pub game_id: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub deprecated_game_ip_address: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub game_port: Option<u32>,
    #[prost(bool, optional, tag = "5")]
    pub is_secure: Option<bool>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub token: Option<Vec<u8>>,
    #[prost(string, optional, tag = "7")]
    pub game_extra_info: Option<String>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub game_data_blob: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "9")]
    pub process_id: Option<u32>,
    #[prost(uint32, optional, tag = "10")]
    pub streaming_provider_id: Option<u32>,
    #[prost(uint32, optional, tag = "11")]
    pub game_flags: Option<u32>,
    #[prost(uint32, optional, tag = "12")]
    pub owner_id: Option<u32>,
    #[prost(string, optional, tag = "13")]
    pub vr_hmd_vendor: Option<String>,
    #[prost(string, optional, tag = "14")]
    pub vr_hmd_model: Option<String>,
    #[prost(uint32, optional, tag = "15")]
    pub launch_option_type: Option<u32>,
    #[prost(int32, optional, tag = "16")]
    pub primary_controller_type: Option<i32>,
    #[prost(string, optional, tag = "17")]
    pub primary_steam_controller_serial: Option<String>,
    #[prost(uint32, optional, tag = "18")]
    pub total_steam_controller_count: Option<u32>,
    #[prost(uint32, optional, tag = "19")]
    pub total_non_steam_controller_count: Option<u32>,
    #[prost(uint64, optional, tag = "20")]
    pub controller_workshop_file_id: Option<u64>,
    #[prost(uint32, optional, tag = "21")]
    pub launch_source: Option<u32>,
    #[prost(uint32, optional, tag = "22")]
    pub vr_hmd_runtime: Option<u32>,
    #[prost(message, optional, tag = "23")]
    pub game_ip_address: Option<CMsgIpAddress>,
    #[prost(uint32, optional, tag = "24")]
    pub controller_connection_type: Option<u32>,
    #[prost(int32, optional, tag = "25")]
    pub game_os_platform: Option<i32>,
    #[prost(uint32, optional, tag = "26")]
    pub game_build_id: Option<u32>,
    #[prost(uint32, optional, tag = "27")]
    pub compat_tool_id: Option<u32>,
    #[prost(string, optional, tag = "28")]
    pub compat_tool_cmd: Option<String>,
    #[prost(uint32, optional, tag = "29")]
    pub compat_tool_build_id: Option<u32>,
    #[prost(string, optional, tag = "30")]
    pub beta_name: Option<String>,
    #[prost(uint32, optional, tag = "31")]
    pub dlc_context: Option<u32>,
    #[prost(message, repeated, tag = "32")]
    pub process_id_list: Vec<GamePlayedProcessInfo>,
}

/// EResult constants
pub const ERESULT_OK: i32 = 1;
pub const ERESULT_NO_CONNECTION: i32 = 3;

// ---------------------------------------------------------------------------
// Rich Presence / PersonaState messages (AppAvatar rewriting)
// ---------------------------------------------------------------------------

/// EMsg for CMsgClientPersonaState.
pub const EMSG_CLIENT_PERSONA_STATE: u32 = 766;
/// EMsg for CMsgClientRichPresenceUpload.
pub const EMSG_CLIENT_RICH_PRESENCE_UPLOAD: u32 = 7501;
/// EMsg for CMsgClientSharedLibraryStopPlaying: server tells the client to
/// stop the family-shared app because the real owner just started playing.
pub const EMSG_CLIENT_SHARED_LIBRARY_STOP_PLAYING: u32 = 9406;
/// Service-method target job name for `FamilyGroupsClient.NotifyRunningApps#1`
/// (delivered inside an EMSG_SERVICE_METHOD_RESPONSE frame).
pub const FAMILY_GROUPS_NOTIFY_RUNNING_APPS_JOB: &str = "FamilyGroupsClient.NotifyRunningApps#1";

/// k_EClientPersonaStateFlagRichPresence: top-level status_flags bit meaning
/// "this message carries rich presence field data".
pub const ECLIENTPERSONASTATEFLAG_RICH_PRESENCE: u32 = 0x1000;
/// k_EPersonaStateFlag_HasRichPresence: per-friend persona_state_flags bit
/// meaning "this friend currently has rich presence set".
pub const EPERSONASTATEFLAG_HAS_RICH_PRESENCE: u32 = 0x1;

#[derive(Clone, prost::Message)]
pub struct PersonaStateKV {
    #[prost(string, optional, tag = "1")]
    pub key: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub value: Option<String>,
}

#[derive(Clone, prost::Message)]
pub struct PersonaStateClanData {
    #[prost(uint32, optional, tag = "1")]
    pub ogg_app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub chat_group_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct PersonaStateOtherGameData {
    #[prost(uint64, optional, tag = "1")]
    pub gameid: Option<u64>,
    #[prost(message, repeated, tag = "2")]
    pub rich_presence: Vec<PersonaStateKV>,
}

#[derive(Clone, prost::Message)]
pub struct PersonaStateFriend {
    #[prost(fixed64, optional, tag = "1")]
    pub friendid: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    pub persona_state: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub game_played_app_id: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub game_server_ip: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    pub game_server_port: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub persona_state_flags: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    pub online_session_instances: Option<u32>,
    #[prost(bool, optional, tag = "10")]
    pub persona_set_by_user: Option<bool>,
    #[prost(string, optional, tag = "15")]
    pub player_name: Option<String>,
    #[prost(uint32, optional, tag = "20")]
    pub query_port: Option<u32>,
    #[prost(fixed64, optional, tag = "25")]
    pub steamid_source: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "31")]
    pub avatar_hash: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "45")]
    pub last_logoff: Option<u32>,
    #[prost(uint32, optional, tag = "46")]
    pub last_logon: Option<u32>,
    #[prost(uint32, optional, tag = "47")]
    pub last_seen_online: Option<u32>,
    #[prost(uint32, optional, tag = "50")]
    pub clan_rank: Option<u32>,
    #[prost(string, optional, tag = "55")]
    pub game_name: Option<String>,
    #[prost(fixed64, optional, tag = "56")]
    pub gameid: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "60")]
    pub game_data_blob: Option<Vec<u8>>,
    #[prost(message, optional, tag = "64")]
    pub clan_data: Option<PersonaStateClanData>,
    #[prost(string, optional, tag = "65")]
    pub clan_tag: Option<String>,
    #[prost(message, repeated, tag = "71")]
    pub rich_presence: Vec<PersonaStateKV>,
    #[prost(fixed64, optional, tag = "72")]
    pub broadcast_id: Option<u64>,
    #[prost(fixed64, optional, tag = "73")]
    pub game_lobby_id: Option<u64>,
    #[prost(uint32, optional, tag = "74")]
    pub watching_broadcast_account_id: Option<u32>,
    #[prost(uint32, optional, tag = "75")]
    pub watching_broadcast_app_id: Option<u32>,
    #[prost(uint32, optional, tag = "76")]
    pub watching_broadcast_viewers: Option<u32>,
    #[prost(string, optional, tag = "77")]
    pub watching_broadcast_title: Option<String>,
    #[prost(bool, optional, tag = "78")]
    pub is_community_banned: Option<bool>,
    #[prost(bool, optional, tag = "79")]
    pub player_name_pending_review: Option<bool>,
    #[prost(bool, optional, tag = "80")]
    pub avatar_pending_review: Option<bool>,
    #[prost(bool, optional, tag = "81")]
    pub on_steam_deck: Option<bool>,
    #[prost(message, repeated, tag = "82")]
    pub other_game_data: Vec<PersonaStateOtherGameData>,
    #[prost(uint32, optional, tag = "83")]
    pub gaming_device_type: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct ClientPersonaState {
    #[prost(uint32, optional, tag = "1")]
    pub status_flags: Option<u32>,
    #[prost(message, repeated, tag = "2")]
    pub friends: Vec<PersonaStateFriend>,
}

#[derive(Clone, prost::Message)]
pub struct ClientRichPresenceUpload {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub rich_presence_kv: Option<Vec<u8>>,
    #[prost(fixed64, repeated, packed = "false", tag = "2")]
    pub steamid_broadcast: Vec<u64>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn licensed_packages_skips_package_zero_and_keeps_tokens() {
        use prost::Message;
        let list = ClientLicenseList {
            eresult: Some(1),
            licenses: vec![
                ClientLicense {
                    package_id: Some(0),
                    access_token: Some(1),
                },
                ClientLicense {
                    package_id: Some(342),
                    access_token: Some(0xdead_beef),
                },
                ClientLicense {
                    package_id: Some(451),
                    access_token: None,
                },
            ],
        };
        let packages = licensed_packages(&list.encode_to_vec()).unwrap();
        assert_eq!(packages, vec![(342, 0xdead_beef), (451, 0)]);
        assert!(licensed_packages(&[0xff, 0xff, 0xff]).is_none());
    }

    use super::*;
    use prost::Message;

    const TEST_APP_ID: u32 = 736_260;

    /// Shared fixture with `steam_stats_wire.rs` in the Cumulus server. Both sides
    /// must name this state with the same number, or a client that switches
    /// backends is told its cache is stale forever.
    fn cumulus_shared_fixture() -> Vec<PlayerStatsEntry> {
        vec![PlayerStatsEntry {
            stat_id: Some(11),
            stat_value: Some(3),
            unlock_times: vec![PlayerAchievementUnlockTime {
                achievement_bit: Some(1),
                unlock_time: Some(10),
            }],
        }]
    }

    #[test]
    fn stats_crc32c_uses_castagnoli_parameters() {
        assert_eq!(stats_crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn canonical_stats_wire_bytes_are_the_response_stats_field() {
        assert_eq!(
            canonical_stats_wire_bytes(&cumulus_shared_fixture()),
            vec![
                0x22, 0x0d, 0x08, 0x0b, 0x10, 0x03, 0x1a, 0x07, 0x08, 0x01, 0x15, 0x0a, 0x00, 0x00,
                0x00,
            ]
        );
    }

    #[test]
    fn stats_crc_matches_the_cumulus_shared_fixture() {
        assert_eq!(stats_crc(&cumulus_shared_fixture()), 0xc1f9_5243);
        assert_eq!(stats_crc(&[]), 0);
    }

    #[test]
    fn successful_logon_uses_the_authenticated_header_identity() {
        let header_steam_id = 76_561_198_106_179_127;
        let header = CMsgProtoBufHeader {
            steamid: Some(header_steam_id),
            ..Default::default()
        }
        .encode_to_vec();
        let body = ClientLogOnResponseWireView {
            eresult: Some(ERESULT_OK),
            client_supplied_steam_id: Some(76_561_198_000_000_001),
        }
        .encode_to_vec();

        assert_eq!(
            successful_logon_steam_id(&header, &body),
            Some(header_steam_id)
        );
    }

    #[test]
    fn client_logon_exposes_the_submitted_device_identity() {
        let body = ClientLogOnWireView {
            client_os_type: Some((-203_i32) as u32),
            machine_name: Some("generated-name".into()),
            machine_name_userchosen: Some("living-room".into()),
            gaming_device_type: Some(8),
        }
        .encode_to_vec();

        assert_eq!(
            client_logon_device(&body),
            Some(ClientLogOnDevice {
                machine_name: "living-room".into(),
                os_type: Some(-203),
                device_type: Some(8),
            })
        );
    }

    #[test]
    fn client_logon_falls_back_to_the_generated_machine_name() {
        let body = ClientLogOnWireView {
            client_os_type: None,
            machine_name: Some("generated-name".into()),
            machine_name_userchosen: Some("  ".into()),
            gaming_device_type: None,
        }
        .encode_to_vec();

        assert_eq!(
            client_logon_device(&body),
            Some(ClientLogOnDevice {
                machine_name: "generated-name".into(),
                os_type: None,
                device_type: None,
            })
        );
    }

    #[test]
    fn unsuccessful_logon_does_not_publish_an_identity() {
        let body = ClientLogOnResponseWireView {
            eresult: Some(2),
            client_supplied_steam_id: Some(76_561_198_106_179_127),
        }
        .encode_to_vec();

        assert_eq!(successful_logon_steam_id(&[], &body), None);
    }

    #[test]
    fn stats_crc_is_independent_of_the_order_the_entries_were_built_in() {
        let ordered = vec![
            PlayerStatsEntry {
                stat_id: Some(7),
                stat_value: Some(1),
                unlock_times: vec![
                    PlayerAchievementUnlockTime {
                        achievement_bit: Some(2),
                        unlock_time: Some(200),
                    },
                    PlayerAchievementUnlockTime {
                        achievement_bit: Some(5),
                        unlock_time: Some(500),
                    },
                ],
            },
            PlayerStatsEntry {
                stat_id: Some(9),
                stat_value: Some(4),
                unlock_times: Vec::new(),
            },
        ];
        let mut shuffled = ordered.clone();
        shuffled.reverse();
        shuffled[1].unlock_times.reverse();

        assert_eq!(stats_crc(&ordered), stats_crc(&shuffled));
        assert_ne!(stats_crc(&ordered), stats_crc(&cumulus_shared_fixture()));
    }

    #[test]
    fn unpack_assemble_roundtrip() {
        let hdr = b"\x01\x02\x03";
        let body = b"\x0A\x0B";
        let emsg: u32 = 0x8000_0097;
        let packet = assemble_raw(emsg, hdr, body);
        let (e, h, b) = unpack_raw(&packet).unwrap();
        assert_eq!(e, emsg);
        assert_eq!(h, hdr);
        assert_eq!(b, body);
    }

    #[test]
    fn unpack_too_short() {
        assert!(unpack_raw(&[0; 7]).is_none());
        assert!(unpack_raw(&[]).is_none());
    }

    #[test]
    fn unpack_header_length_overflow() {
        let mut packet = assemble_raw(1, b"hdr", b"body");
        packet[4] = 0xFF;
        packet[5] = 0xFF;
        assert!(unpack_raw(&packet).is_none());
    }

    #[test]
    fn unpack_empty_header_and_body() {
        let packet = assemble_raw(42, &[], &[]);
        let (e, h, b) = unpack_raw(&packet).unwrap();
        assert_eq!(e, 42);
        assert!(h.is_empty());
        assert!(b.is_empty());
    }

    #[test]
    fn unpack_header_only_no_body() {
        let packet = assemble_raw(1, b"header_data", &[]);
        let (_, h, b) = unpack_raw(&packet).unwrap();
        assert_eq!(h, b"header_data");
        assert!(b.is_empty());
    }

    #[test]
    fn service_method_app_id_uses_each_published_message_schema() {
        let app_interface = ClientMetricsAppInterfaceStatsWireView {
            game_id: Some((2_u64 << 24) | u64::from(TEST_APP_ID)),
        }
        .encode_to_vec();
        let cloud_sync = ClientMetricsCloudAppSyncStatsWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let badge_levels = PlayerGetGameBadgeLevelsWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let user_files = PublishedFileGetUserFilesWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let compatibility = SteamDeckCompatibilityShouldPromptWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let user_news = UserNewsGetUserNewsWireView {
            filter_app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();

        for (method, body) in [
            (
                "ClientMetrics.ClientAppInterfaceStatsReport#1",
                app_interface.as_slice(),
            ),
            (
                "ClientMetrics.ClientCloudAppSyncStats#1",
                cloud_sync.as_slice(),
            ),
            ("Player.GetGameBadgeLevels#1", badge_levels.as_slice()),
            ("PublishedFile.GetUserFiles#1", user_files.as_slice()),
            (
                "Store.ShouldPromptForCompatibilityFeedback#1",
                compatibility.as_slice(),
            ),
            ("UserNews.GetUserNews#1", user_news.as_slice()),
        ] {
            assert_eq!(service_method_app_id(method, body), Some(TEST_APP_ID));
        }
    }

    #[test]
    fn service_method_app_id_preserves_method_specific_field_meaning() {
        let field_one = PlayerGetGameBadgeLevelsWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();

        assert_eq!(
            service_method_app_id("PublishedFile.GetUserFiles#1", &field_one),
            None
        );
        assert_eq!(
            service_method_app_id("UserNews.GetUserNews#1", &field_one),
            None
        );
        assert_eq!(service_method_app_id("Unknown.Method#1", &field_one), None);
        assert_eq!(
            service_method_app_id("Player.GetGameBadgeLevels#1", &[0x08, 0x80]),
            None
        );
    }

    #[test]
    fn cloud_request_app_id_uses_each_published_message_schema() {
        let begin_http = CloudBeginHttpUploadWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let begin_ugc = CloudBeginUgcUploadWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let single_file = CloudGetSingleFileInfoWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let share_file = CloudShareFileWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let enumerate = CloudEnumerateUserFilesWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let commit_http = CloudCommitHttpUploadWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let commit_ugc = CloudCommitUgcUploadWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let file_details = CloudGetFileDetailsWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        let delete = CloudDeleteWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();

        for (method, body) in [
            ("Cloud.BeginHTTPUpload#1", begin_http.as_slice()),
            ("Cloud.BeginUGCUpload#1", begin_ugc.as_slice()),
            ("Cloud.GetSingleFileInfo#1", single_file.as_slice()),
            ("Cloud.ShareFile#1", share_file.as_slice()),
            ("Cloud.EnumerateUserFiles#1", enumerate.as_slice()),
            ("Cloud.CommitHTTPUpload#1", commit_http.as_slice()),
            ("Cloud.CommitUGCUpload#1", commit_ugc.as_slice()),
            ("Cloud.GetFileDetails#1", file_details.as_slice()),
            ("Cloud.Delete#1", delete.as_slice()),
        ] {
            assert_eq!(cloud_request_app_id(method, body), Some(TEST_APP_ID));
        }
    }

    #[test]
    fn service_method_app_id_rejects_zero_and_delegates_cloud_requests() {
        let zero = PlayerGetGameBadgeLevelsWireView { app_id: Some(0) }.encode_to_vec();
        assert_eq!(
            service_method_app_id("Player.GetGameBadgeLevels#1", &zero),
            None
        );

        let cloud = CloudCommitHttpUploadWireView {
            app_id: Some(TEST_APP_ID),
        }
        .encode_to_vec();
        assert_eq!(
            service_method_app_id("Cloud.CommitHTTPUpload#1", &cloud),
            Some(TEST_APP_ID)
        );
    }

    #[test]
    fn legacy_store_user_stats_reads_only_the_inferred_game_id() {
        let game_id = (2_u64 << 24) | u64::from(TEST_APP_ID);
        let mut body = vec![0x09];
        body.extend_from_slice(&game_id.to_le_bytes());
        body.extend_from_slice(&[0x10, 0x01]);

        assert_eq!(legacy_store_user_stats_game_id(&body), Some(game_id));
        assert_eq!(legacy_store_user_stats_game_id(&[0x10, 0x01]), None);
        assert_eq!(legacy_store_user_stats_game_id(&[0x09, 0x01]), None);
    }

    fn kv_string(out: &mut Vec<u8>, key: &str, value: &str) {
        out.push(1);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }

    fn kv_object(out: &mut Vec<u8>, key: &str, body: impl FnOnce(&mut Vec<u8>)) {
        out.push(0);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        body(out);
        out.push(8);
    }

    fn kv_int(out: &mut Vec<u8>, key: &str, value: i32) {
        out.push(2);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        out.extend_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_achievement_bit_mappings_from_binary_keyvalues_schema() {
        let mut schema = Vec::new();
        kv_object(&mut schema, "620", |root| {
            kv_object(root, "stats", |stats| {
                kv_object(stats, "11", |stat| {
                    kv_object(stat, "bits", |bits| {
                        kv_object(bits, "0", |achievement| {
                            kv_string(achievement, "name", "ACH_FIRST");
                        });
                        kv_object(bits, "3", |achievement| {
                            kv_string(achievement, "name", "ACH_THIRD");
                        });
                    });
                });
                kv_object(stats, "12", |stat| {
                    kv_object(stat, "bits", |bits| {
                        kv_object(bits, "1", |achievement| {
                            kv_string(achievement, "name", "ACH_OTHER");
                        });
                    });
                });
            });
        });

        assert_eq!(
            parse_achievement_bit_mappings(&schema).unwrap(),
            vec![
                AchievementBitMapping {
                    stat_id: 11,
                    achievement_bit: 0,
                    key: "ACH_FIRST".into(),
                },
                AchievementBitMapping {
                    stat_id: 11,
                    achievement_bit: 3,
                    key: "ACH_THIRD".into(),
                },
                AchievementBitMapping {
                    stat_id: 12,
                    achievement_bit: 1,
                    key: "ACH_OTHER".into(),
                },
            ]
        );
    }

    #[test]
    fn parses_ordinary_stat_mappings_from_binary_keyvalues_schema() {
        let mut schema = Vec::new();
        kv_object(&mut schema, "620", |root| {
            kv_object(root, "stats", |stats| {
                kv_object(stats, "11", |stat| {
                    kv_string(stat, "name", "STAT_SCORE");
                    kv_int(stat, "type", 1);
                });
                kv_object(stats, "12", |stat| {
                    kv_object(stat, "bits", |bits| {
                        kv_object(bits, "0", |achievement| {
                            kv_string(achievement, "name", "ACH_FIRST");
                        });
                    });
                });
            });
        });

        assert_eq!(
            parse_stat_mappings(&schema).unwrap(),
            vec![StatMapping {
                stat_id: 11,
                key: "STAT_SCORE".into(),
                value_type: Some(1),
            }]
        );
    }
}
