use super::http::{parse_absolute_target, AdapterError, Endpoint};
use super::transfer_targets::{CloudStateScope, TransferTargetRegistry};
use super::*;
use prost::Message;
use tracing::warn;
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_steam_protocol::*;

pub(super) fn request_app_id(method: &str, body: &[u8]) -> Option<u32> {
    vapor_forge_steam_protocol::cloud_request_app_id(method, body)
}

/// Identify a controlled Cloud request that must not fall through to Valve.
///
/// This is called after the Cumulus adapter declines the request. Unknown and
/// explicitly unowned apps are both protected so startup races cannot expose
/// an AppID before the ownership snapshot is ready.
pub fn privacy_fallback(method: &str, body: &[u8], config: &RuntimeConfig) -> Option<(u32, bool)> {
    privacy_fallback_with_ownership(method, body, config, crate::apps::actual_ownership)
}

pub fn privacy_fallback_with_ownership(
    method: &str,
    body: &[u8],
    config: &RuntimeConfig,
    ownership: impl FnOnce(AppId) -> crate::apps::OwnershipState,
) -> Option<(u32, bool)> {
    let app_id = request_app_id(method, body)?;
    crate::apps::classify_app_with_ownership(config, AppId(app_id), ownership)
        .requires_injected_ownership()
        .then_some((app_id, method_expects_response(method)))
}

pub(super) fn is_cumulus_transfer_report(
    method: &str,
    body: &[u8],
    config: &RuntimeConfig,
    transfer_targets: &TransferTargetRegistry,
) -> bool {
    if !config.cumulus_configured() {
        return false;
    }
    let Ok(endpoint) = Endpoint::parse(&config.cloud.server_url) else {
        return false;
    };
    let scope = CloudStateScope::from_config(config);
    match method {
        CDN_REPORT => CloudCdnReportNotification::decode(body)
            .ok()
            .and_then(|report| report.url)
            .and_then(|url| parse_absolute_target(&url))
            .is_some_and(|(https, authority, path)| {
                (https == endpoint.https && endpoint.matches_transfer_location(&authority, &path))
                    || transfer_targets.contains(&scope, &authority, &path)
            }),
        EXTERNAL_TRANSFER_REPORT => {
            let Some(report) = CloudExternalStorageTransferReportNotification::decode(body).ok()
            else {
                return false;
            };
            report.host.zip(report.path).is_some_and(|(host, path)| {
                endpoint.matches_transfer_location(&host, &path)
                    || transfer_targets.contains(&scope, &host, &path)
            })
        }
        _ => false,
    }
}

pub(super) fn method_expects_response(method: &str) -> bool {
    matches!(
        method,
        BEGIN_HTTP_UPLOAD
            | COMMIT_HTTP_UPLOAD
            | BEGIN_UGC_UPLOAD
            | COMMIT_UGC_UPLOAD
            | GET_FILE_DETAILS
            | GET_SINGLE_FILE_INFO
            | SHARE_FILE
            | ENUMERATE_USER_FILES
            | LEGACY_DELETE
            | GET_CHANGELIST
            | BEGIN_BATCH
            | BEGIN_FILE_UPLOAD
            | COMMIT_FILE_UPLOAD
            | COMPLETE_BATCH_BLOCKING
            | FILE_DOWNLOAD
            | DELETE_FILE
            | QUOTA_USAGE
            | LAUNCH_INTENT
            | SUSPEND_SESSION
            | RESUME_SESSION
    )
}

pub(super) struct RpcReply {
    pub(super) body: Vec<u8>,
    pub(super) eresult: i32,
}

impl RpcReply {
    pub(super) fn ok(body: Vec<u8>) -> Self {
        Self {
            body,
            eresult: super::ERESULT_OK,
        }
    }
}

pub(super) fn build_response_packet(
    request: &CMsgProtoBufHeader,
    result: Result<RpcReply, AdapterError>,
) -> Vec<u8> {
    let (body, eresult) = match result {
        Ok(reply) => (reply.body, reply.eresult),
        Err(error) => {
            warn!(method = ?request.target_job_name, %error, "cloud-rpc: request failed");
            (Vec::new(), ERESULT_FAIL)
        }
    };
    let response = CMsgProtoBufHeader {
        steamid: request.steamid,
        jobid_source: None,
        jobid_target: request.jobid_source,
        target_job_name: request.target_job_name.clone(),
        eresult: Some(eresult),
        transport_error: None,
        seq_num: None,
    };
    vapor_forge_steam_protocol::assemble_raw(
        EMSG_SERVICE_METHOD_RESPONSE | K_MSG_HDR_PROTO_FLAG,
        &response.encode_to_vec(),
        &body,
    )
}
