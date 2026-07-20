//! Steam network framing, EMsg constants, and protobuf message definitions.

#![forbid(unsafe_code)]

pub const MANIFEST_REQUEST_CODE_JOB_NAME: &str = "ContentServerDirectory.GetManifestRequestCode#1";
pub const PLAYER_GET_USER_STATS_JOB_NAME: &str = "Player.GetUserStats#1";

#[derive(Clone, prost::Message)]
pub struct CloudAppIdField1 {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppIdField2 {
    #[prost(uint32, optional, tag = "2")]
    pub app_id: Option<u32>,
}

pub type AppIdField1Request = CloudAppIdField1;
pub type AppIdField2Request = CloudAppIdField2;

/// Decode the AppID carried by a Steam `Cloud.*#1` request.
///
/// Keeping this method table with the protobuf ABI prevents runtime routing
/// and offline packet inspection from maintaining different field guesses.
pub fn cloud_request_app_id(method: &str, body: &[u8]) -> Option<u32> {
    use prost::Message;

    let app_id = match method {
        "Cloud.BeginHTTPUpload#1"
        | "Cloud.BeginUGCUpload#1"
        | "Cloud.GetSingleFileInfo#1"
        | "Cloud.ShareFile#1"
        | "Cloud.EnumerateUserFiles#1" => CloudAppIdField1::decode(body).ok()?.app_id,
        "Cloud.CommitHTTPUpload#1"
        | "Cloud.CommitUGCUpload#1"
        | "Cloud.GetFileDetails#1"
        | "Cloud.Delete#1" => CloudAppIdField2::decode(body).ok()?.app_id,
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
pub struct CMsgProtoBufHeader {
    #[prost(fixed64, optional, tag = "1")]
    pub steamid: Option<u64>,
    #[prost(fixed64, optional, tag = "10")]
    pub jobid_source: Option<u64>,
    #[prost(fixed64, optional, tag = "11")]
    pub jobid_target: Option<u64>,
    #[prost(string, optional, tag = "12")]
    pub target_job_name: Option<String>,
    #[prost(int32, optional, tag = "13")]
    pub eresult: Option<i32>,
    #[prost(int32, optional, tag = "17")]
    pub transport_error: Option<i32>,
    #[prost(int32, optional, tag = "24")]
    pub seq_num: Option<i32>,
}

#[derive(Clone, prost::Message)]
pub struct GetManifestRequestCodeRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub depot_id: Option<u32>,
    #[prost(uint64, optional, tag = "3")]
    pub manifest_id: Option<u64>,
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
    #[prost(uint32, optional, tag = "5")]
    pub crc_schema: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct PlayerStatsEntry {
    #[prost(uint32, optional, tag = "1")]
    pub stat_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub stat_value: Option<u32>,
}

// ---------------------------------------------------------------------------
// Native Steam playtime snapshots
// ---------------------------------------------------------------------------

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
    #[prost(fixed32, repeated, tag = "2")]
    pub unlock_time: Vec<u32>,
}

/// EMsg 820 outgoing: commit local stats to Steam.
#[derive(Clone, prost::Message)]
pub struct ClientStoreUserStatsRequest {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(bool, optional, tag = "2")]
    pub explicit_reset: Option<bool>,
    #[prost(message, repeated, tag = "3")]
    pub stats_to_store: Vec<StoreUserStatsEntry>,
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
    #[prost(bool, optional, tag = "5")]
    pub stats_out_of_date: Option<bool>,
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
pub struct PersonaStateFriend {
    #[prost(fixed64, optional, tag = "1")]
    pub friendid: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    pub persona_state: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub game_played_app_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub persona_state_flags: Option<u32>,
    #[prost(string, optional, tag = "55")]
    pub game_name: Option<String>,
    #[prost(fixed64, optional, tag = "56")]
    pub gameid: Option<u64>,
    #[prost(message, repeated, tag = "71")]
    pub rich_presence: Vec<PersonaStateKV>,
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
    #[prost(fixed64, repeated, tag = "2")]
    pub steamid_broadcast: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
