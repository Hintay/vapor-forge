//! Translation between Steam client's `Cloud.*#1` service RPCs and Cumulus.

use prost::Message;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;
use vapor_forge_abi::{
    CMsgProtoBufHeader, CloudAppExitSyncDoneNotification, CloudAppFileInfo,
    CloudAppLaunchIntentRequest, CloudAppLaunchIntentResponse, CloudAppSessionResumeRequest,
    CloudAppSessionResumeResponse, CloudAppSessionSuspendRequest, CloudAppSessionSuspendResponse,
    CloudBeginAppUploadBatchRequest, CloudBeginAppUploadBatchResponse, CloudCdnReportNotification,
    CloudClientBeginFileUploadRequest, CloudClientBeginFileUploadResponse,
    CloudClientCommitFileUploadRequest, CloudClientCommitFileUploadResponse,
    CloudClientConflictResolutionNotification, CloudClientDeleteFileRequest,
    CloudClientDeleteFileResponse, CloudClientFileDownloadRequest, CloudClientFileDownloadResponse,
    CloudClientGetAppQuotaUsageRequest, CloudClientGetAppQuotaUsageResponse,
    CloudCompleteAppUploadBatchRequest, CloudCompleteAppUploadBatchResponse,
    CloudExternalStorageTransferReportNotification, CloudFileUploadBlockDetails,
    CloudGetAppFileChangelistRequest, CloudGetAppFileChangelistResponse, CloudHttpHeader,
    CloudPendingRemoteOperation, EMSG_SERVICE_METHOD_RESPONSE, K_MSG_HDR_PROTO_FLAG,
};
use vapor_forge_config::{AppId, RuntimeConfig};

pub const GET_CHANGELIST: &str = "Cloud.GetAppFileChangelist#1";
pub const BEGIN_BATCH: &str = "Cloud.BeginAppUploadBatch#1";
pub const BEGIN_FILE_UPLOAD: &str = "Cloud.ClientBeginFileUpload#1";
pub const COMMIT_FILE_UPLOAD: &str = "Cloud.ClientCommitFileUpload#1";
pub const COMPLETE_BATCH: &str = "Cloud.CompleteAppUploadBatch#1";
pub const COMPLETE_BATCH_BLOCKING: &str = "Cloud.CompleteAppUploadBatchBlocking#1";
pub const FILE_DOWNLOAD: &str = "Cloud.ClientFileDownload#1";
pub const DELETE_FILE: &str = "Cloud.ClientDeleteFile#1";
pub const QUOTA_USAGE: &str = "Cloud.ClientGetAppQuotaUsage#1";
pub const LAUNCH_INTENT: &str = "Cloud.SignalAppLaunchIntent#1";
pub const SUSPEND_SESSION: &str = "Cloud.SuspendAppSession#1";
pub const RESUME_SESSION: &str = "Cloud.ResumeAppSession#1";
pub const EXIT_SYNC_DONE: &str = "Cloud.SignalAppExitSyncDone#1";
pub const CONFLICT_RESOLUTION: &str = "Cloud.ClientConflictResolution#1";
pub const CDN_REPORT: &str = "Cloud.CDNReport#1";
pub const EXTERNAL_TRANSFER_REPORT: &str = "Cloud.ExternalStorageTransferReport#1";

const ERESULT_OK: i32 = 1;
const ERESULT_FAIL: i32 = 2;
const ERESULT_TOO_MANY_PENDING: i32 = 108;
const HTTP_METHOD_PUT: i32 = 4;
const TRANSFER_TARGET_CAPACITY: usize = 4096;
const TRANSFER_TARGET_TTL: Duration = Duration::from_secs(15 * 60);

struct PendingResponse {
    receiver: mpsc::Receiver<Vec<u8>>,
}

struct QueuedRequest {
    app_id: u32,
    method: String,
    header: Vec<u8>,
    body: Vec<u8>,
    settings: CloudSettings,
    response: Option<mpsc::Sender<Vec<u8>>>,
}

struct AdapterState {
    current_change_numbers: HashMap<u32, u64>,
    client_change_numbers: HashMap<u32, u64>,
    active_batches: HashMap<u32, u64>,
    batches: HashMap<u64, BatchState>,
    files: HashMap<(u32, String), CumulusFile>,
    conflict_resolutions: HashMap<u32, PendingResolution>,
    transfer_targets: Arc<TransferTargetRegistry>,
}

impl Default for AdapterState {
    fn default() -> Self {
        Self::with_transfer_targets(Arc::new(TransferTargetRegistry::default()))
    }
}

impl AdapterState {
    fn with_transfer_targets(transfer_targets: Arc<TransferTargetRegistry>) -> Self {
        Self {
            current_change_numbers: HashMap::new(),
            client_change_numbers: HashMap::new(),
            active_batches: HashMap::new(),
            batches: HashMap::new(),
            files: HashMap::new(),
            conflict_resolutions: HashMap::new(),
            transfer_targets,
        }
    }
}

#[derive(Default)]
struct TransferTargetRegistry {
    targets: Mutex<VecDeque<IssuedTransferTarget>>,
}

struct IssuedTransferTarget {
    authority: String,
    path: String,
    expires_at: Instant,
}

impl TransferTargetRegistry {
    fn register(&self, authority: &str, path: &str) {
        let now = Instant::now();
        let mut targets = self.targets.lock().unwrap();
        while targets
            .front()
            .is_some_and(|target| target.expires_at <= now)
        {
            targets.pop_front();
        }
        if targets.len() == TRANSFER_TARGET_CAPACITY {
            targets.pop_front();
        }
        targets.push_back(IssuedTransferTarget {
            authority: authority.to_ascii_lowercase(),
            path: path.to_string(),
            expires_at: now + TRANSFER_TARGET_TTL,
        });
    }

    fn contains(&self, authority: &str, path: &str) -> bool {
        let now = Instant::now();
        let mut targets = self.targets.lock().unwrap();
        while targets
            .front()
            .is_some_and(|target| target.expires_at <= now)
        {
            targets.pop_front();
        }
        targets
            .iter()
            .any(|target| target.authority.eq_ignore_ascii_case(authority) && target.path == path)
    }
}

struct BatchState {
    app_id: u32,
    upload_paths: BTreeSet<String>,
    delete_paths: BTreeSet<String>,
    files: HashMap<String, String>,
}

struct PendingResolution {
    base_change_number: u64,
    resolution: &'static str,
}

/// Thread-safe queue used by the network hook. HTTP never runs on Steam's
/// websocket thread; completed packets are drained on a later receive frame.
pub struct CloudRpcQueue {
    pending: Mutex<Vec<PendingResponse>>,
    count: AtomicUsize,
    worker: mpsc::Sender<QueuedRequest>,
    report_worker: mpsc::SyncSender<QueuedRequest>,
    transfer_targets: Arc<TransferTargetRegistry>,
}

impl CloudRpcQueue {
    pub fn new() -> Self {
        let transfer_targets = Arc::new(TransferTargetRegistry::default());
        let worker_transfer_targets = Arc::clone(&transfer_targets);
        let (worker, receiver) = mpsc::channel::<QueuedRequest>();
        std::thread::spawn(move || {
            let mut state = AdapterState::with_transfer_targets(worker_transfer_targets);
            while let Ok(request) = receiver.recv() {
                let result = execute_rpc(
                    &mut state,
                    &request.settings,
                    &request.method,
                    &request.body,
                );
                if let Some(response) = request.response {
                    let packet = build_response_packet(&request.header, result);
                    let _ = response.send(packet);
                } else if let Err(error) = result {
                    warn!(
                        app_id = request.app_id,
                        method = request.method,
                        %error,
                        "cloud-rpc: notification failed"
                    );
                }
            }
        });
        let (report_worker, report_receiver) = mpsc::sync_channel::<QueuedRequest>(128);
        std::thread::spawn(move || {
            let mut state = AdapterState::default();
            while let Ok(request) = report_receiver.recv() {
                if let Err(error) = execute_rpc(
                    &mut state,
                    &request.settings,
                    &request.method,
                    &request.body,
                ) {
                    warn!(
                        method = request.method,
                        %error,
                        "cloud-rpc: transfer report failed"
                    );
                }
            }
        });
        Self {
            pending: Mutex::new(Vec::new()),
            count: AtomicUsize::new(0),
            worker,
            report_worker,
            transfer_targets,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count.load(Ordering::Acquire) == 0
    }

    /// Queue a supported Cumulus-backed RPC. Returns false when the packet
    /// must remain on Steam's normal path.
    pub fn intercept(
        &self,
        method: &str,
        request_header: &CMsgProtoBufHeader,
        request_header_bytes: &[u8],
        body: &[u8],
        config: &RuntimeConfig,
    ) -> bool {
        if is_cumulus_transfer_report(method, body, config, &self.transfer_targets) {
            if self
                .report_worker
                .try_send(QueuedRequest {
                    app_id: 0,
                    method: method.to_string(),
                    header: Vec::new(),
                    body: body.to_vec(),
                    settings: CloudSettings::from_config(config),
                    response: None,
                })
                .is_err()
            {
                warn!(method, "cloud-rpc: transfer report queue unavailable");
            }
            return true;
        }
        let Some(app_id) = request_app_id(method, body) else {
            return false;
        };
        if !config.cumulus_configured()
            || config.app_category(AppId(app_id)).is_none()
            || crate::apps::actual_ownership(AppId(app_id)) != Some(false)
        {
            return false;
        }

        let expects_response = method_expects_response(method);
        if expects_response && request_header.jobid_source.map_or(true, |job| job == 0) {
            warn!(app_id, method, "cloud-rpc: request has no response job id");
            return false;
        }

        let settings = CloudSettings::from_config(config);
        if expects_response {
            let (sender, receiver) = mpsc::channel();
            if self
                .worker
                .send(QueuedRequest {
                    app_id,
                    method: method.to_string(),
                    header: request_header_bytes.to_vec(),
                    body: body.to_vec(),
                    settings,
                    response: Some(sender),
                })
                .is_err()
            {
                warn!(app_id, method, "cloud-rpc: request worker stopped");
                return false;
            }
            self.pending
                .lock()
                .unwrap()
                .push(PendingResponse { receiver });
            self.count.fetch_add(1, Ordering::Release);
        } else {
            if self
                .worker
                .send(QueuedRequest {
                    app_id,
                    method: method.to_string(),
                    header: Vec::new(),
                    body: body.to_vec(),
                    settings,
                    response: None,
                })
                .is_err()
            {
                warn!(app_id, method, "cloud-rpc: notification worker stopped");
                return false;
            }
        }
        true
    }

    pub fn drain_completed(&self) -> Vec<Vec<u8>> {
        let mut pending = self.pending.lock().unwrap();
        let mut completed = Vec::new();
        let mut index = 0;
        while index < pending.len() {
            match pending[index].receiver.try_recv() {
                Ok(packet) => {
                    pending.swap_remove(index);
                    self.count.fetch_sub(1, Ordering::Release);
                    completed.push(packet);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    pending.swap_remove(index);
                    self.count.fetch_sub(1, Ordering::Release);
                }
                Err(mpsc::TryRecvError::Empty) => index += 1,
            }
        }
        completed
    }
}

impl Default for CloudRpcQueue {
    fn default() -> Self {
        Self::new()
    }
}

fn execute_rpc(
    state: &mut AdapterState,
    settings: &CloudSettings,
    method: &str,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let client = CumulusClient::new(settings)?;
    match method {
        GET_CHANGELIST => handle_changelist(state, &client, body),
        BEGIN_BATCH => handle_begin_batch(state, &client, body),
        BEGIN_FILE_UPLOAD => handle_begin_file_upload(state, &client, body),
        COMMIT_FILE_UPLOAD => handle_commit_file_upload(state, &client, body),
        COMPLETE_BATCH | COMPLETE_BATCH_BLOCKING => handle_complete_batch(state, &client, body),
        FILE_DOWNLOAD => handle_file_download(state, &client, body),
        DELETE_FILE => handle_delete_file(state, body),
        QUOTA_USAGE => handle_quota(&client, body),
        LAUNCH_INTENT => handle_launch(&client, body),
        SUSPEND_SESSION => handle_suspend(&client, body),
        RESUME_SESSION => handle_resume(&client, body),
        EXIT_SYNC_DONE => handle_exit(&client, body),
        CONFLICT_RESOLUTION => handle_conflict_resolution(state, body),
        CDN_REPORT => handle_cdn_report(&client, body),
        EXTERNAL_TRANSFER_REPORT => handle_external_transfer_report(&client, body),
        _ => Err(AdapterError::Protocol("unsupported cloud method".into())),
    }
}

fn handle_changelist(
    state: &mut AdapterState,
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudGetAppFileChangelistRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let synced = request.synced_change_number.unwrap_or(0);
    let response: CumulusChangelist = client.get_json(&format!(
        "/api/v1/apps/{app_id}/changelist?synced_change_number={synced}"
    ))?;
    let current = nonnegative_u64(response.current_change_number, "current_change_number")?;
    state.current_change_numbers.insert(app_id, current);
    state.client_change_numbers.insert(app_id, synced);

    if response.basis == "full" {
        state
            .files
            .retain(|(cached_app, _), _| *cached_app != app_id);
    }
    for file in &response.changed {
        state
            .files
            .insert((app_id, file.path.clone()), file.clone());
    }
    for path in &response.deleted {
        state.files.remove(&(app_id, path.clone()));
    }

    let mut prefixes = Vec::new();
    let mut prefix_indexes = BTreeMap::new();
    let mut files = Vec::with_capacity(response.changed.len() + response.deleted.len());
    for file in response.changed {
        files.push(steam_file_info(
            &file.path,
            Some(&file),
            0,
            &mut prefixes,
            &mut prefix_indexes,
        )?);
    }
    for path in response.deleted {
        files.push(steam_file_info(
            &path,
            None,
            2,
            &mut prefixes,
            &mut prefix_indexes,
        )?);
    }
    let has_files = !files.is_empty();
    let reply = CloudGetAppFileChangelistResponse {
        current_change_number: Some(current),
        files,
        is_only_delta: Some(response.basis == "delta"),
        path_prefixes: prefixes,
        machine_names: has_files
            .then(|| "Cumulus".to_string())
            .into_iter()
            .collect(),
        app_build_id_hwm: Some(nonnegative_u64(
            response.app_buildid_hwm,
            "app_buildid_hwm",
        )?),
    };
    Ok(RpcReply::ok(reply.encode_to_vec()))
}

fn handle_begin_batch(
    state: &mut AdapterState,
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudBeginAppUploadBatchRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let base = state
        .current_change_numbers
        .get(&app_id)
        .copied()
        .ok_or_else(|| {
            AdapterError::Protocol("upload started before a verified changelist".into())
        })?;
    let response: CumulusBeginBatch = client.post_json(
        &format!("/api/v1/steam/apps/{app_id}/upload-batches"),
        &json!({
            "base_change_number": signed_bits(base),
            "machine_name": request.machine_name,
            "app_build_id": request.app_build_id.map(signed_bits),
            "files_to_upload": request.files_to_upload,
            "files_to_delete": request.files_to_delete,
        }),
    )?;
    let batch_id = parse_batch_id(&response.batch_id)?;
    let batch = BatchState {
        app_id,
        upload_paths: request.files_to_upload.into_iter().collect(),
        delete_paths: request.files_to_delete.into_iter().collect(),
        files: HashMap::new(),
    };
    if let Some(previous) = state.active_batches.insert(app_id, batch_id) {
        state.batches.remove(&previous);
    }
    state.batches.insert(batch_id, batch);
    let reply = CloudBeginAppUploadBatchResponse {
        batch_id: Some(batch_id),
        app_change_number: Some(nonnegative_u64(
            response.app_change_number,
            "app_change_number",
        )?),
    };
    Ok(RpcReply::ok(reply.encode_to_vec()))
}

fn handle_begin_file_upload(
    state: &mut AdapterState,
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudClientBeginFileUploadRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let path = required(request.filename.clone(), "filename")?;
    let batch_id = find_batch_id(state, app_id, request.upload_batch_id)?;
    {
        let batch = state
            .batches
            .get(&batch_id)
            .ok_or_else(|| AdapterError::Protocol("unknown upload batch".into()))?;
        if !batch.upload_paths.contains(&path) {
            return Err(AdapterError::Protocol(format!(
                "file was not listed in BeginAppUploadBatch: {path}"
            )));
        }
    }

    let raw_size = u64::from(request.raw_file_size.or(request.file_size).unwrap_or(0));
    let reported_transfer = u64::from(request.file_size.unwrap_or(0));
    let transfer_size = if reported_transfer == 0 {
        raw_size
    } else {
        reported_transfer
    };
    let sha1 = bytes_to_hex(&required(request.file_sha, "file_sha")?);
    if sha1.len() != 40 {
        return Err(AdapterError::Protocol("file_sha is not a SHA-1".into()));
    }
    let declared: CumulusDeclaredFile = client.post_json(
        &format!("/api/v1/steam/upload-batches/{batch_id}/files"),
        &json!({
            "path": path,
            "transfer_size": transfer_size,
            "raw_size": raw_size,
            "sha1": sha1,
            "mtime": request.timestamp.unwrap_or(0),
            "platforms_to_sync": request.platforms_to_sync.unwrap_or(u32::MAX),
        }),
    )?;
    if declared.transfer_size != transfer_size {
        return Err(AdapterError::Protocol(
            "Cumulus changed the declared transfer size".into(),
        ));
    }
    if declared.file_id.is_empty() {
        return Err(AdapterError::Protocol(
            "Cumulus returned an empty file id".into(),
        ));
    }

    let mut block_requests = Vec::with_capacity(declared.block_requests.len());
    let mut expected_offset = 0_u64;
    if declared.block_requests.is_empty() {
        return Err(AdapterError::Protocol(
            "Cumulus returned no upload blocks".into(),
        ));
    }
    let block_count = declared.block_requests.len();
    for block in declared.block_requests {
        if block.http_method != HTTP_METHOD_PUT {
            return Err(AdapterError::Protocol(
                "Cumulus returned a non-PUT upload block".into(),
            ));
        }
        if block.block_offset != expected_offset {
            return Err(AdapterError::Protocol(
                "Cumulus upload blocks are not contiguous".into(),
            ));
        }
        let block_end = expected_offset
            .checked_add(u64::from(block.block_length))
            .ok_or_else(|| AdapterError::Protocol("Cumulus upload block overflow".into()))?;
        if block_end > transfer_size
            || (transfer_size > 0 && block.block_length == 0)
            || (transfer_size == 0 && block_count != 1)
        {
            return Err(AdapterError::Protocol(
                "Cumulus returned an invalid upload block length".into(),
            ));
        }
        let target = resolve_transfer_target(client, block.target)?;
        block_requests.push(CloudFileUploadBlockDetails {
            url_host: Some(target.authority),
            url_path: Some(target.path),
            use_https: Some(target.https),
            http_method: Some(block.http_method),
            request_headers: target.headers,
            block_offset: Some(block.block_offset),
            block_length: Some(block.block_length),
            explicit_body_data: None,
            may_parallelize: Some(block.may_parallelize),
        });
        expected_offset = block_end;
    }
    if expected_offset != transfer_size {
        return Err(AdapterError::Protocol(
            "Cumulus upload blocks do not cover the transfer".into(),
        ));
    }
    for block in &block_requests {
        state.transfer_targets.register(
            block
                .url_host
                .as_deref()
                .expect("resolved target has a host"),
            block
                .url_path
                .as_deref()
                .expect("resolved target has a path"),
        );
    }
    state
        .batches
        .get_mut(&batch_id)
        .expect("batch checked above")
        .files
        .insert(path, declared.file_id.clone());

    let reply = CloudClientBeginFileUploadResponse {
        encrypt_file: Some(false),
        block_requests,
    };
    Ok(RpcReply::ok(reply.encode_to_vec()))
}

fn handle_commit_file_upload(
    state: &mut AdapterState,
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudClientCommitFileUploadRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let path = required(request.filename, "filename")?;
    if !request.transfer_succeeded.unwrap_or(false) {
        return Ok(RpcReply::ok(
            CloudClientCommitFileUploadResponse {
                file_committed: Some(false),
            }
            .encode_to_vec(),
        ));
    }
    let batch_id = find_batch_id(state, app_id, None)?;
    let batch = state
        .batches
        .get(&batch_id)
        .ok_or_else(|| AdapterError::Protocol("unknown upload batch".into()))?;
    let file_id = batch
        .files
        .get(&path)
        .ok_or_else(|| AdapterError::Protocol("upload was not begun for this file".into()))?;
    client.post_unit(&format!(
        "/api/v1/upload-batches/{}/files/{file_id}/finalize",
        batch_id
    ))?;
    Ok(RpcReply::ok(
        CloudClientCommitFileUploadResponse {
            file_committed: Some(true),
        }
        .encode_to_vec(),
    ))
}

fn handle_complete_batch(
    state: &mut AdapterState,
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudCompleteAppUploadBatchRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let batch_id = find_batch_id(state, app_id, request.batch_id)?;
    if request.batch_eresult.unwrap_or(ERESULT_OK as u32) != ERESULT_OK as u32 {
        client.delete(&format!("/api/v1/upload-batches/{batch_id}"))?;
    } else {
        let resolution = state.conflict_resolutions.get(&app_id).map(|resolution| {
            json!({
                "base_change_number": signed_bits(resolution.base_change_number),
                "resolution": resolution.resolution,
            })
        });
        let commit: CumulusCommit = client.post_json(
            &format!("/api/v1/upload-batches/{batch_id}/commit"),
            &json!({ "conflict_resolution": resolution }),
        )?;
        state.current_change_numbers.insert(
            app_id,
            nonnegative_u64(commit.change_number, "change_number")?,
        );
        state.conflict_resolutions.remove(&app_id);
        state
            .files
            .retain(|(cached_app, _), _| *cached_app != app_id);
    }
    state.active_batches.remove(&app_id);
    state.batches.remove(&batch_id);
    Ok(RpcReply::ok(
        CloudCompleteAppUploadBatchResponse {}.encode_to_vec(),
    ))
}

fn handle_delete_file(state: &mut AdapterState, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudClientDeleteFileRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let path = required(request.filename, "filename")?;
    let batch_id = find_batch_id(state, app_id, request.upload_batch_id)?;
    let batch = state
        .batches
        .get(&batch_id)
        .ok_or_else(|| AdapterError::Protocol("unknown upload batch".into()))?;
    if !batch.delete_paths.contains(&path) {
        return Err(AdapterError::Protocol(format!(
            "file was not listed for deletion: {path}"
        )));
    }
    Ok(RpcReply::ok(
        CloudClientDeleteFileResponse {}.encode_to_vec(),
    ))
}

fn handle_file_download(
    state: &mut AdapterState,
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudClientFileDownloadRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let path = required(request.filename, "filename")?;
    let key = (app_id, path.clone());
    if !state.files.contains_key(&key) {
        let manifest: CumulusManifest =
            client.get_json(&format!("/api/v1/apps/{app_id}/manifest"))?;
        for file in manifest.files {
            state.files.insert((app_id, file.path.clone()), file);
        }
    }
    let file = state
        .files
        .get(&key)
        .ok_or_else(|| AdapterError::Protocol("download file is not in the manifest".into()))?;
    let file_id = required(file.file_id, "file_id")?;
    let target: CumulusTransferTarget =
        client.get_json(&format!("/api/v1/files/{file_id}/download-target"))?;
    let target = resolve_transfer_target(client, target)?;
    state
        .transfer_targets
        .register(&target.authority, &target.path);
    let size = clamp_u32(file.size);
    let reply = CloudClientFileDownloadResponse {
        app_id: Some(app_id),
        file_size: Some(size),
        raw_file_size: Some(size),
        sha_file: Some(hex_to_bytes(&file.sha1)?),
        timestamp: Some(nonnegative_u64(file.mtime, "mtime")?),
        is_explicit_delete: Some(false),
        url_host: Some(target.authority),
        url_path: Some(target.path),
        use_https: Some(target.https),
        request_headers: target.headers,
        encrypted: Some(false),
    };
    Ok(RpcReply::ok(reply.encode_to_vec()))
}

fn handle_quota(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudClientGetAppQuotaUsageRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let quota: CumulusQuota = client.get_json(&format!("/api/v1/apps/{app_id}/quota"))?;
    let reply = CloudClientGetAppQuotaUsageResponse {
        existing_files: Some(clamp_u32(quota.used_files)),
        existing_bytes: Some(nonnegative_u64(quota.used_bytes, "used_bytes")?),
        max_num_files: Some(clamp_u32(quota.max_files)),
        max_num_bytes: Some(nonnegative_u64(quota.quota_bytes, "quota_bytes")?),
    };
    Ok(RpcReply::ok(reply.encode_to_vec()))
}

fn handle_launch(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudAppLaunchIntentRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let response: CumulusLaunch = client.post_json(
        &format!("/api/v1/apps/{app_id}/session/launch"),
        &json!({
            "client_id": signed_bits(required(request.client_id, "client_id")?),
            "machine_name": request.machine_name.unwrap_or_else(|| "unknown".into()),
            "ignore_pending": request.ignore_pending_operations.unwrap_or(false),
            "os_type": request.os_type,
            "device_type": request.device_type,
        }),
    )?;
    let pending_remote_operations = response
        .pending_operations
        .into_iter()
        .map(|operation| CloudPendingRemoteOperation {
            operation: Some(operation.operation as i32),
            machine_name: Some(operation.machine_name),
            client_id: Some(operation.client_id as u64),
            time_last_updated: Some(clamp_u32(operation.time_last_updated)),
            os_type: operation.os_type.map(|value| value as i32),
            device_type: operation.device_type.map(|value| value as i32),
        })
        .collect::<Vec<_>>();
    let eresult = if pending_remote_operations.is_empty() {
        ERESULT_OK
    } else {
        ERESULT_TOO_MANY_PENDING
    };
    Ok(RpcReply {
        body: CloudAppLaunchIntentResponse {
            pending_remote_operations,
        }
        .encode_to_vec(),
        eresult,
    })
}

fn handle_suspend(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudAppSessionSuspendRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    client.post_json_unit(
        &format!("/api/v1/apps/{app_id}/session/suspend"),
        &json!({
            "client_id": signed_bits(required(request.client_id, "client_id")?),
            "cloud_sync_completed": request.cloud_sync_completed,
        }),
    )?;
    Ok(RpcReply::ok(
        CloudAppSessionSuspendResponse {}.encode_to_vec(),
    ))
}

fn handle_resume(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudAppSessionResumeRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    client.post_json_unit(
        &format!("/api/v1/apps/{app_id}/session/resume"),
        &json!({
            "client_id": signed_bits(required(request.client_id, "client_id")?),
        }),
    )?;
    Ok(RpcReply::ok(
        CloudAppSessionResumeResponse {}.encode_to_vec(),
    ))
}

fn handle_exit(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudAppExitSyncDoneNotification::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    client.post_json_unit(
        &format!("/api/v1/apps/{app_id}/session/exit"),
        &json!({
            "client_id": signed_bits(required(request.client_id, "client_id")?),
            "uploads_completed": request.uploads_completed,
            "uploads_required": request.uploads_required,
        }),
    )?;
    Ok(RpcReply::ok(Vec::new()))
}

fn handle_conflict_resolution(
    state: &mut AdapterState,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudClientConflictResolutionNotification::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    if request.chose_local_files.unwrap_or(false) {
        let base_change_number = state
            .client_change_numbers
            .get(&app_id)
            .copied()
            .unwrap_or(0);
        state.conflict_resolutions.insert(
            app_id,
            PendingResolution {
                base_change_number,
                resolution: "kept_local",
            },
        );
    } else {
        state.conflict_resolutions.remove(&app_id);
    }
    Ok(RpcReply::ok(Vec::new()))
}

fn handle_cdn_report(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let report = CloudCdnReportNotification::decode(body)?;
    client.post_json_unit(
        "/api/v1/steam/transfer-reports",
        &json!({
            "kind": "cdn",
            "target": required(report.url, "url")?,
            "is_upload": false,
            "success": report.success.unwrap_or(false),
            "http_status_code": report.http_status_code,
            "bytes_expected": report.expected_bytes,
            "bytes_actual": report.received_bytes,
            "duration_ms": report.duration,
        }),
    )?;
    Ok(RpcReply::ok(Vec::new()))
}

fn handle_external_transfer_report(
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let report = CloudExternalStorageTransferReportNotification::decode(body)?;
    let host = required(report.host, "host")?;
    let path = required(report.path, "path")?;
    client.post_json_unit(
        "/api/v1/steam/transfer-reports",
        &json!({
            "kind": "external",
            "target": format!("//{host}{path}"),
            "is_upload": report.is_upload,
            "success": report.success.unwrap_or(false),
            "http_status_code": report.http_status_code,
            "bytes_expected": report.bytes_expected,
            "bytes_actual": report.bytes_actual,
            "duration_ms": report.duration_ms,
            "cell_id": report.cell_id,
            "proxied": report.proxied,
            "ipv6_local": report.ipv6_local,
            "ipv6_remote": report.ipv6_remote,
            "time_to_connect_ms": report.time_to_connect_ms,
            "time_to_send_request_ms": report.time_to_send_request_ms,
            "time_to_first_byte_ms": report.time_to_first_byte_ms,
            "time_to_last_byte_ms": report.time_to_last_byte_ms,
        }),
    )?;
    Ok(RpcReply::ok(Vec::new()))
}

fn steam_file_info(
    path: &str,
    file: Option<&CumulusFile>,
    persist_state: i32,
    prefixes: &mut Vec<String>,
    prefix_indexes: &mut BTreeMap<String, u32>,
) -> Result<CloudAppFileInfo, AdapterError> {
    let (prefix, leaf) = split_cloud_path(path);
    let prefix_index = if let Some(index) = prefix_indexes.get(prefix) {
        *index
    } else {
        let index = prefixes.len() as u32;
        prefixes.push(prefix.to_string());
        prefix_indexes.insert(prefix.to_string(), index);
        index
    };
    Ok(CloudAppFileInfo {
        file_name: Some(leaf.to_string()),
        sha_file: file.map(|file| hex_to_bytes(&file.sha1)).transpose()?,
        timestamp: file
            .map(|file| nonnegative_u64(file.mtime, "mtime"))
            .transpose()?,
        raw_file_size: file.map(|file| clamp_u32(file.size)),
        persist_state: Some(persist_state),
        platforms_to_sync: Some(file.map_or(u32::MAX, |file| clamp_u32(file.platforms_to_sync))),
        path_prefix_index: Some(prefix_index),
        machine_name_index: Some(0),
        reupload_requested: None,
    })
}

fn split_cloud_path(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((prefix, leaf)) => (&path[..prefix.len() + 1], leaf),
        None => ("", path),
    }
}

fn find_batch_id(
    state: &AdapterState,
    app_id: u32,
    requested: Option<u64>,
) -> Result<u64, AdapterError> {
    let batch_id = requested
        .or_else(|| state.active_batches.get(&app_id).copied())
        .ok_or_else(|| AdapterError::Protocol("no active upload batch".into()))?;
    let batch = state
        .batches
        .get(&batch_id)
        .ok_or_else(|| AdapterError::Protocol("unknown upload batch".into()))?;
    if batch.app_id != app_id {
        return Err(AdapterError::Protocol(
            "upload batch belongs to another app".into(),
        ));
    }
    Ok(batch_id)
}

fn request_app_id(method: &str, body: &[u8]) -> Option<u32> {
    let app_id = match method {
        GET_CHANGELIST => CloudGetAppFileChangelistRequest::decode(body).ok()?.app_id,
        BEGIN_BATCH => CloudBeginAppUploadBatchRequest::decode(body).ok()?.app_id,
        BEGIN_FILE_UPLOAD => CloudClientBeginFileUploadRequest::decode(body).ok()?.app_id,
        COMMIT_FILE_UPLOAD => {
            CloudClientCommitFileUploadRequest::decode(body)
                .ok()?
                .app_id
        }
        COMPLETE_BATCH | COMPLETE_BATCH_BLOCKING => {
            CloudCompleteAppUploadBatchRequest::decode(body)
                .ok()?
                .app_id
        }
        FILE_DOWNLOAD => CloudClientFileDownloadRequest::decode(body).ok()?.app_id,
        DELETE_FILE => CloudClientDeleteFileRequest::decode(body).ok()?.app_id,
        QUOTA_USAGE => {
            CloudClientGetAppQuotaUsageRequest::decode(body)
                .ok()?
                .app_id
        }
        LAUNCH_INTENT => CloudAppLaunchIntentRequest::decode(body).ok()?.app_id,
        SUSPEND_SESSION => CloudAppSessionSuspendRequest::decode(body).ok()?.app_id,
        RESUME_SESSION => CloudAppSessionResumeRequest::decode(body).ok()?.app_id,
        EXIT_SYNC_DONE => CloudAppExitSyncDoneNotification::decode(body).ok()?.app_id,
        CONFLICT_RESOLUTION => {
            CloudClientConflictResolutionNotification::decode(body)
                .ok()?
                .app_id
        }
        _ => None,
    }?;
    (app_id != 0).then_some(app_id)
}

fn is_cumulus_transfer_report(
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
    match method {
        CDN_REPORT => CloudCdnReportNotification::decode(body)
            .ok()
            .and_then(|report| report.url)
            .and_then(|url| parse_absolute_target(&url))
            .is_some_and(|(https, authority, path)| {
                (https == endpoint.https && endpoint.matches_transfer_location(&authority, &path))
                    || transfer_targets.contains(&authority, &path)
            }),
        EXTERNAL_TRANSFER_REPORT => {
            let Some(report) = CloudExternalStorageTransferReportNotification::decode(body).ok()
            else {
                return false;
            };
            report.host.zip(report.path).is_some_and(|(host, path)| {
                endpoint.matches_transfer_location(&host, &path)
                    || transfer_targets.contains(&host, &path)
            })
        }
        _ => false,
    }
}

fn method_expects_response(method: &str) -> bool {
    matches!(
        method,
        GET_CHANGELIST
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

struct RpcReply {
    body: Vec<u8>,
    eresult: i32,
}

impl RpcReply {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            body,
            eresult: ERESULT_OK,
        }
    }
}

fn build_response_packet(
    request_header_bytes: &[u8],
    result: Result<RpcReply, AdapterError>,
) -> Vec<u8> {
    let request = CMsgProtoBufHeader::decode(request_header_bytes).unwrap_or_default();
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
        target_job_name: request.target_job_name,
        eresult: Some(eresult),
        transport_error: None,
        seq_num: None,
    };
    vapor_forge_abi::assemble_raw(
        EMSG_SERVICE_METHOD_RESPONSE | K_MSG_HDR_PROTO_FLAG,
        &response.encode_to_vec(),
        &body,
    )
}

#[derive(Clone)]
struct CloudSettings {
    server_url: String,
    token: String,
    timeout_connect_ms: u64,
    timeout_ms: u64,
}

impl CloudSettings {
    fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            server_url: config.cloud.server_url.trim().to_string(),
            token: config.cloud.token.trim().to_string(),
            timeout_connect_ms: config.cloud.timeout_connect_ms,
            timeout_ms: config.cloud.timeout_ms,
        }
    }
}

struct Endpoint {
    origin: String,
    authority: String,
    base_path: String,
    https: bool,
}

impl Endpoint {
    fn parse(raw: &str) -> Result<Self, AdapterError> {
        let raw = raw.trim().trim_end_matches('/');
        let (https, rest) = if let Some(rest) = raw.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = raw.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(AdapterError::Protocol(
                "cloud.server_url must use http:// or https://".into(),
            ));
        };
        if rest.is_empty() || rest.contains('@') || rest.contains('?') || rest.contains('#') {
            return Err(AdapterError::Protocol("invalid cloud.server_url".into()));
        }
        let (authority, base_path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{}", path.trim_end_matches('/'))),
            None => (rest, String::new()),
        };
        if authority.is_empty() {
            return Err(AdapterError::Protocol("invalid cloud.server_url".into()));
        }
        Ok(Self {
            origin: raw.to_string(),
            authority: authority.to_string(),
            base_path,
            https,
        })
    }

    fn resolve_path(&self, suffix: &str) -> String {
        format!("{}{}", self.base_path, suffix)
    }

    fn matches_transfer_location(&self, authority: &str, path: &str) -> bool {
        if !authority.eq_ignore_ascii_case(&self.authority) {
            return false;
        }
        let Some(path) = path.strip_prefix(&self.resolve_path("/api/v1/")) else {
            return false;
        };
        let path = path.split('?').next().unwrap_or(path);
        let segments = path.split('/').collect::<Vec<_>>();
        matches!(
            segments.as_slice(),
            ["files", _, "content"] | ["upload-batches", _, "files", _, "blocks", _]
        )
    }
}

fn parse_absolute_target(url: &str) -> Option<(bool, String, String)> {
    let uri = url.parse::<ureq::http::Uri>().ok()?;
    let https = match uri.scheme_str()? {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let authority = uri.authority()?.as_str().to_string();
    let path = uri.path_and_query()?.as_str().to_string();
    Some((https, authority, path))
}

fn resolve_transfer_target(
    client: &CumulusClient,
    target: CumulusTransferTarget,
) -> Result<ResolvedTransferTarget, AdapterError> {
    if !target.url_path.starts_with('/') || target.url_path.starts_with("//") {
        return Err(AdapterError::Protocol(
            "Cumulus returned an invalid transfer path".into(),
        ));
    }
    let mut headers = target
        .request_headers
        .into_iter()
        .map(|header| {
            if header.name.is_empty()
                || header.name.contains(['\r', '\n'])
                || header.value.contains(['\r', '\n'])
            {
                return Err(AdapterError::Protocol(
                    "Cumulus returned an invalid transfer header".into(),
                ));
            }
            Ok(CloudHttpHeader {
                name: Some(header.name),
                value: Some(header.value),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (authority, path, https) = match target.url_host {
        Some(authority) => {
            if authority.is_empty()
                || authority.contains(['/', '@', '?', '#', '\r', '\n'])
                || format!("https://{authority}/")
                    .parse::<ureq::http::Uri>()
                    .ok()
                    .and_then(|uri| uri.authority().map(|value| value.as_str() == authority))
                    != Some(true)
            {
                return Err(AdapterError::Protocol(
                    "Cumulus returned an invalid transfer host".into(),
                ));
            }
            let https = target.use_https.ok_or_else(|| {
                AdapterError::Protocol("external transfer target omitted use_https".into())
            })?;
            (authority, target.url_path, https)
        }
        None => {
            if target.use_https.is_some() {
                return Err(AdapterError::Protocol(
                    "relative transfer target supplied use_https".into(),
                ));
            }
            headers.push(client.auth_header());
            (
                client.endpoint.authority.clone(),
                client.endpoint.resolve_path(&target.url_path),
                client.endpoint.https,
            )
        }
    };
    Ok(ResolvedTransferTarget {
        authority,
        path,
        https,
        headers,
    })
}

struct CumulusClient {
    agent: ureq::Agent,
    endpoint: Endpoint,
    token: String,
}

impl CumulusClient {
    fn new(settings: &CloudSettings) -> Result<Self, AdapterError> {
        let endpoint = Endpoint::parse(&settings.server_url)?;
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_millis(settings.timeout_connect_ms)))
            .timeout_global(Some(Duration::from_millis(settings.timeout_ms)))
            .http_status_as_error(false)
            .build()
            .new_agent();
        Ok(Self {
            agent,
            endpoint,
            token: settings.token.clone(),
        })
    }

    fn auth_header(&self) -> CloudHttpHeader {
        CloudHttpHeader {
            name: Some("Authorization".into()),
            value: Some(format!("Bearer {}", self.token)),
        }
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}{}", self.endpoint.origin, suffix)
    }

    fn get_json<T: DeserializeOwned>(&self, suffix: &str) -> Result<T, AdapterError> {
        let response = self
            .agent
            .get(&self.url(suffix))
            .header("Authorization", &format!("Bearer {}", self.token))
            .call()?;
        decode_json_response(response)
    }

    fn post_json<T: DeserializeOwned>(
        &self,
        suffix: &str,
        body: &Value,
    ) -> Result<T, AdapterError> {
        let encoded = serde_json::to_vec(body)?;
        let response = self
            .agent
            .post(&self.url(suffix))
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .send(encoded.as_slice())?;
        decode_json_response(response)
    }

    fn post_unit(&self, suffix: &str) -> Result<(), AdapterError> {
        let response = self
            .agent
            .post(&self.url(suffix))
            .header("Authorization", &format!("Bearer {}", self.token))
            .send_empty()?;
        ensure_success(response.status().as_u16())
    }

    fn post_json_unit(&self, suffix: &str, body: &Value) -> Result<(), AdapterError> {
        let encoded = serde_json::to_vec(body)?;
        let response = self
            .agent
            .post(&self.url(suffix))
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .send(encoded.as_slice())?;
        ensure_success(response.status().as_u16())
    }

    fn delete(&self, suffix: &str) -> Result<(), AdapterError> {
        let response = self
            .agent
            .delete(&self.url(suffix))
            .header("Authorization", &format!("Bearer {}", self.token))
            .call()?;
        ensure_success(response.status().as_u16())
    }
}

fn decode_json_response<T: DeserializeOwned>(
    mut response: ureq::http::Response<ureq::Body>,
) -> Result<T, AdapterError> {
    ensure_success(response.status().as_u16())?;
    let body = response.body_mut().read_to_string()?;
    Ok(serde_json::from_str(&body)?)
}

fn ensure_success(status: u16) -> Result<(), AdapterError> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(AdapterError::HttpStatus(status))
    }
}

#[derive(Clone, Deserialize)]
struct CumulusFile {
    file_id: Option<i64>,
    path: String,
    size: i64,
    sha1: String,
    mtime: i64,
    platforms_to_sync: i64,
}

#[derive(Deserialize)]
struct CumulusChangelist {
    current_change_number: i64,
    app_buildid_hwm: i64,
    basis: String,
    changed: Vec<CumulusFile>,
    deleted: Vec<String>,
}

#[derive(Deserialize)]
struct CumulusManifest {
    files: Vec<CumulusFile>,
}

#[derive(Deserialize)]
struct CumulusBeginBatch {
    batch_id: String,
    app_change_number: i64,
}

#[derive(Deserialize)]
struct CumulusDeclaredFile {
    file_id: String,
    transfer_size: u64,
    block_requests: Vec<CumulusUploadBlock>,
}

#[derive(Deserialize)]
struct CumulusUploadBlock {
    #[serde(flatten)]
    target: CumulusTransferTarget,
    http_method: i32,
    block_offset: u64,
    block_length: u32,
    may_parallelize: bool,
}

#[derive(Deserialize)]
struct CumulusTransferTarget {
    url_host: Option<String>,
    url_path: String,
    use_https: Option<bool>,
    #[serde(default)]
    request_headers: Vec<CumulusTransferHeader>,
}

#[derive(Deserialize)]
struct CumulusTransferHeader {
    name: String,
    value: String,
}

struct ResolvedTransferTarget {
    authority: String,
    path: String,
    https: bool,
    headers: Vec<CloudHttpHeader>,
}

#[derive(Deserialize)]
struct CumulusCommit {
    change_number: i64,
}

#[derive(Deserialize)]
struct CumulusQuota {
    quota_bytes: i64,
    used_bytes: i64,
    max_files: i64,
    used_files: i64,
}

#[derive(Deserialize)]
struct CumulusLaunch {
    pending_operations: Vec<CumulusPendingOperation>,
}

#[derive(Deserialize)]
struct CumulusPendingOperation {
    operation: i64,
    machine_name: String,
    client_id: i64,
    time_last_updated: i64,
    os_type: Option<i64>,
    device_type: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
enum AdapterError {
    #[error("invalid Steam cloud RPC: {0}")]
    Protocol(String),
    #[error("Cumulus returned HTTP {0}")]
    HttpStatus(u16),
    #[error("Cumulus transport failed: {0}")]
    Http(#[from] ureq::Error),
    #[error("invalid Cumulus JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid protobuf: {0}")]
    Protobuf(#[from] prost::DecodeError),
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, AdapterError> {
    value.ok_or_else(|| AdapterError::Protocol(format!("missing {field}")))
}

fn parse_batch_id(value: &str) -> Result<u64, AdapterError> {
    let id = value
        .parse::<u64>()
        .map_err(|_| AdapterError::Protocol("Cumulus returned a non-numeric batch id".into()))?;
    if id == 0 || id > i64::MAX as u64 {
        return Err(AdapterError::Protocol(
            "Cumulus batch id is outside the positive 63-bit range".into(),
        ));
    }
    Ok(id)
}

fn signed_bits(value: u64) -> i64 {
    value as i64
}

fn nonnegative_u64(value: i64, field: &str) -> Result<u64, AdapterError> {
    u64::try_from(value).map_err(|_| AdapterError::Protocol(format!("negative Cumulus {field}")))
}

fn clamp_u32(value: i64) -> u32 {
    value.clamp(0, i64::from(u32::MAX)) as u32
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, AdapterError> {
    if hex.len() % 2 != 0 {
        return Err(AdapterError::Protocol("odd-length hex value".into()));
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, AdapterError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AdapterError::Protocol("invalid hex value".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vapor_forge_config::{AppsSection, CloudSection, InjectApp};

    fn one_response_server(body: &str) -> (String, mpsc::Receiver<String>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = body.to_string();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            sender.send(String::from_utf8(request).unwrap()).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        (format!("http://{address}"), receiver)
    }

    fn scripted_server(responses: &[(u16, &str)]) -> (String, mpsc::Receiver<String>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let responses = responses
            .iter()
            .map(|(status, body)| (*status, (*body).to_string()))
            .collect::<Vec<_>>();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                let header_end = loop {
                    if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break index + 4;
                    }
                    let read = stream.read(&mut buffer).unwrap();
                    assert_ne!(read, 0, "request closed before headers completed");
                    request.extend_from_slice(&buffer[..read]);
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while request.len() < header_end + content_length {
                    let read = stream.read(&mut buffer).unwrap();
                    assert_ne!(read, 0, "request closed before body completed");
                    request.extend_from_slice(&buffer[..read]);
                }
                sender.send(String::from_utf8(request).unwrap()).unwrap();
                let reason = match status {
                    200 => "OK",
                    204 => "No Content",
                    _ => "Test Response",
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                )
                .unwrap();
            }
        });
        (format!("http://{address}"), receiver)
    }

    fn put_upload_block(block: &CloudFileUploadBlockDetails, body: &[u8]) {
        use std::io::{Read, Write};

        assert_eq!(block.use_https, Some(false));
        assert_eq!(block.http_method, Some(HTTP_METHOD_PUT));
        let host = block.url_host.as_deref().unwrap();
        let path = block.url_path.as_deref().unwrap();
        let authorization = block
            .request_headers
            .iter()
            .find(|header| header.name.as_deref() == Some("Authorization"))
            .and_then(|header| header.value.as_deref())
            .unwrap();
        let mut stream = std::net::TcpStream::connect(host).unwrap();
        write!(
            stream,
            "PUT {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {authorization}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        )
        .unwrap();
        stream.write_all(body).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 204 No Content"));
    }

    #[test]
    fn endpoint_splits_origin_and_resolves_paths() {
        let endpoint = Endpoint::parse("https://cloud.example:8443/base/").unwrap();
        assert!(endpoint.https);
        assert_eq!(endpoint.authority, "cloud.example:8443");
        assert_eq!(endpoint.origin, "https://cloud.example:8443/base");
        assert_eq!(
            endpoint.resolve_path("/api/v1/files/1/content"),
            "/base/api/v1/files/1/content"
        );
    }

    #[test]
    fn response_routes_to_request_job() {
        let request = CMsgProtoBufHeader {
            steamid: Some(7),
            jobid_source: Some(99),
            jobid_target: None,
            target_job_name: Some(GET_CHANGELIST.into()),
            eresult: None,
            transport_error: None,
            seq_num: None,
        };
        let packet =
            build_response_packet(&request.encode_to_vec(), Ok(RpcReply::ok(vec![1, 2, 3])));
        let (_, header, body) = vapor_forge_abi::unpack_raw(&packet).unwrap();
        let response = CMsgProtoBufHeader::decode(header).unwrap();
        assert_eq!(response.jobid_target, Some(99));
        assert_eq!(response.eresult, Some(ERESULT_OK));
        assert_eq!(body, [1, 2, 3]);
    }

    #[test]
    fn path_prefix_round_trips() {
        assert_eq!(
            split_cloud_path("%WinMyDocuments%/Game/save.bin"),
            ("%WinMyDocuments%/Game/", "save.bin")
        );
        assert_eq!(split_cloud_path("api.dat"), ("", "api.dat"));
    }

    #[test]
    fn accepts_only_positive_63_bit_batch_ids() {
        assert_eq!(parse_batch_id("1").unwrap(), 1);
        assert_eq!(
            parse_batch_id(&i64::MAX.to_string()).unwrap(),
            i64::MAX as u64
        );
        assert!(parse_batch_id("0").is_err());
        assert!(parse_batch_id(&(i64::MAX as u64 + 1).to_string()).is_err());
        assert!(parse_batch_id("batch-1").is_err());
    }

    #[test]
    fn recognizes_only_decoded_cloud_methods() {
        let body = CloudClientCommitFileUploadRequest {
            transfer_succeeded: Some(true),
            app_id: Some(480),
            file_sha: None,
            filename: Some("save".into()),
        }
        .encode_to_vec();
        assert_eq!(request_app_id(COMMIT_FILE_UPLOAD, &body), Some(480));
        assert_eq!(request_app_id("RemoteStorage.FileWrite", &body), None);
    }

    #[test]
    fn preserves_cloud_rpc_response_semantics() {
        assert!(!method_expects_response(COMPLETE_BATCH));
        assert!(!method_expects_response(EXIT_SYNC_DONE));
        assert!(!method_expects_response(CDN_REPORT));
        assert!(!method_expects_response(EXTERNAL_TRANSFER_REPORT));
        assert!(!method_expects_response(CONFLICT_RESOLUTION));
        assert!(method_expects_response(COMPLETE_BATCH_BLOCKING));
        assert!(method_expects_response(BEGIN_FILE_UPLOAD));
    }

    #[test]
    fn intercepts_only_cumulus_transfer_reports_without_queuing_responses() {
        let config = RuntimeConfig {
            cloud: CloudSection {
                server_url: "https://cloud.example:8443/base".into(),
                token: "secret".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let queue = CloudRpcQueue::new();
        let header = CMsgProtoBufHeader::default();

        let external = CloudExternalStorageTransferReportNotification {
            host: Some("CLOUD.EXAMPLE:8443".into()),
            path: Some("/base/api/v1/upload-batches/b/files/f/blocks/0".into()),
            ..Default::default()
        };
        assert!(queue.intercept(
            EXTERNAL_TRANSFER_REPORT,
            &header,
            &[],
            &external.encode_to_vec(),
            &config,
        ));

        let cdn = CloudCdnReportNotification {
            url: Some("https://CLOUD.EXAMPLE:8443/base/api/v1/files/1/content".into()),
            ..Default::default()
        };
        assert!(queue.intercept(CDN_REPORT, &header, &[], &cdn.encode_to_vec(), &config,));
        assert!(queue.is_empty());
        assert!(queue.drain_completed().is_empty());

        let steam = CloudExternalStorageTransferReportNotification {
            host: Some("steamcloud-ugc.storage.googleapis.com".into()),
            path: Some("/steamcloud/save.dat".into()),
            ..Default::default()
        };
        assert!(!queue.intercept(
            EXTERNAL_TRANSFER_REPORT,
            &header,
            &[],
            &steam.encode_to_vec(),
            &config,
        ));

        queue
            .transfer_targets
            .register("bucket.example", "/save.dat?signature=one");
        let issued = CloudExternalStorageTransferReportNotification {
            host: Some("BUCKET.EXAMPLE".into()),
            path: Some("/save.dat?signature=one".into()),
            ..Default::default()
        };
        assert!(queue.intercept(
            EXTERNAL_TRANSFER_REPORT,
            &header,
            &[],
            &issued.encode_to_vec(),
            &config,
        ));
        let unissued = CloudExternalStorageTransferReportNotification {
            host: Some("bucket.example".into()),
            path: Some("/save.dat?signature=two".into()),
            ..Default::default()
        };
        assert!(!queue.intercept(
            EXTERNAL_TRANSFER_REPORT,
            &header,
            &[],
            &unissued.encode_to_vec(),
            &config,
        ));
    }

    #[test]
    fn forwards_cumulus_transfer_reports_to_cumulus() {
        let (server_url, captured) = scripted_server(&[(204, ""), (204, "")]);
        let settings = CloudSettings {
            server_url,
            token: "report-token".into(),
            timeout_connect_ms: 1000,
            timeout_ms: 2000,
        };
        let mut state = AdapterState::default();

        let external = CloudExternalStorageTransferReportNotification {
            host: Some("cloud.example".into()),
            path: Some("/api/v1/upload-batches/42/files/f/blocks/0".into()),
            is_upload: Some(true),
            success: Some(true),
            http_status_code: Some(204),
            bytes_expected: Some(4),
            bytes_actual: Some(4),
            duration_ms: Some(12),
            cell_id: Some(7),
            ..Default::default()
        };
        execute_rpc(
            &mut state,
            &settings,
            EXTERNAL_TRANSFER_REPORT,
            &external.encode_to_vec(),
        )
        .unwrap();

        let cdn = CloudCdnReportNotification {
            url: Some("https://cloud.example/api/v1/files/9/content".into()),
            success: Some(false),
            http_status_code: Some(503),
            expected_bytes: Some(8),
            received_bytes: Some(2),
            duration: Some(34),
            ..Default::default()
        };
        execute_rpc(&mut state, &settings, CDN_REPORT, &cdn.encode_to_vec()).unwrap();

        let external_request = captured.recv_timeout(Duration::from_secs(1)).unwrap();
        let cdn_request = captured.recv_timeout(Duration::from_secs(1)).unwrap();
        for request in [&external_request, &cdn_request] {
            assert!(request.starts_with("POST /api/v1/steam/transfer-reports HTTP/1.1"));
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer report-token"));
        }
        assert!(external_request.contains(r#""kind":"external""#));
        assert!(external_request.contains(r#""is_upload":true"#));
        assert!(cdn_request.contains(r#""kind":"cdn""#));
        assert!(cdn_request.contains(r#""success":false"#));
    }

    #[test]
    fn unknown_ownership_stays_on_steam_until_sampled() {
        let app_id = AppId(246_813_579);
        let config = RuntimeConfig {
            apps: AppsSection {
                inject: vec![InjectApp {
                    id: app_id,
                    dlc: Vec::new(),
                    ticket: Default::default(),
                    purchase_time: 0,
                }],
                ..Default::default()
            },
            cloud: CloudSection {
                server_url: "http://127.0.0.1:1".into(),
                token: "unused".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let request = CloudClientGetAppQuotaUsageRequest {
            app_id: Some(app_id.0),
        }
        .encode_to_vec();
        let header = CMsgProtoBufHeader {
            jobid_source: Some(1),
            target_job_name: Some(QUOTA_USAGE.into()),
            ..Default::default()
        };

        assert_eq!(crate::apps::actual_ownership(app_id), None);
        assert!(!CloudRpcQueue::new().intercept(
            QUOTA_USAGE,
            &header,
            &header.encode_to_vec(),
            &request,
            &config,
        ));
    }

    #[test]
    fn actually_owned_apps_stay_on_steam() {
        let app_id = AppId(246_813_580);
        let config = RuntimeConfig {
            apps: AppsSection {
                inject: vec![InjectApp {
                    id: app_id,
                    dlc: Vec::new(),
                    ticket: Default::default(),
                    purchase_time: 0,
                }],
                ..Default::default()
            },
            cloud: CloudSection {
                server_url: "http://127.0.0.1:1".into(),
                token: "unused".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        crate::apps::record_actual_ownership(app_id, true);
        let request = CloudClientGetAppQuotaUsageRequest {
            app_id: Some(app_id.0),
        }
        .encode_to_vec();
        let header = CMsgProtoBufHeader {
            jobid_source: Some(1),
            target_job_name: Some(QUOTA_USAGE.into()),
            ..Default::default()
        };

        assert!(!CloudRpcQueue::new().intercept(
            QUOTA_USAGE,
            &header,
            &header.encode_to_vec(),
            &request,
            &config,
        ));
    }

    #[test]
    fn changelist_http_response_maps_to_steam_rpc() {
        let (server_url, captured) = one_response_server(
            r#"{
                "current_change_number": 3,
                "app_buildid_hwm": 42,
                "basis": "full",
                "changed": [{
                    "file_id": 9,
                    "path": "%WinMyDocuments%/Game/save.bin",
                    "size": 4,
                    "sha1": "0000000000000000000000000000000000000000",
                    "mtime": 1700000000,
                    "platforms_to_sync": 4294967295
                }],
                "deleted": ["old.dat"]
            }"#,
        );
        let settings = CloudSettings {
            server_url,
            token: "secret-token".into(),
            timeout_connect_ms: 1000,
            timeout_ms: 2000,
        };
        let request = CloudGetAppFileChangelistRequest {
            app_id: Some(480),
            synced_change_number: Some(0),
        };
        let mut state = AdapterState::default();
        let reply = execute_rpc(
            &mut state,
            &settings,
            GET_CHANGELIST,
            &request.encode_to_vec(),
        )
        .unwrap();
        let response = CloudGetAppFileChangelistResponse::decode(reply.body.as_slice()).unwrap();
        assert_eq!(response.current_change_number, Some(3));
        assert_eq!(response.app_build_id_hwm, Some(42));
        assert_eq!(response.is_only_delta, Some(false));
        assert_eq!(response.path_prefixes, ["%WinMyDocuments%/Game/", ""]);
        assert_eq!(response.files[0].file_name.as_deref(), Some("save.bin"));
        assert_eq!(response.files[0].sha_file.as_deref(), Some(&[0_u8; 20][..]));
        assert_eq!(response.files[1].file_name.as_deref(), Some("old.dat"));
        assert_eq!(response.files[1].persist_state, Some(2));
        assert_eq!(state.current_change_numbers.get(&480), Some(&3));

        let request_text = captured.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request_text
            .starts_with("GET /api/v1/apps/480/changelist?synced_change_number=0 HTTP/1.1"));
        assert!(request_text
            .to_ascii_lowercase()
            .contains("authorization: bearer secret-token"));
    }

    #[test]
    fn download_uses_external_descriptor_without_cumulus_bearer() {
        let (server_url, captured) = scripted_server(&[
            (
                200,
                r#"{"files":[{"file_id":9,"path":"save.dat","size":4,"sha1":"1111111111111111111111111111111111111111","mtime":1700000000,"platforms_to_sync":4294967295}]}"#,
            ),
            (
                200,
                r#"{"url_host":"cdn.example","url_path":"/objects/save?signature=one","use_https":true,"request_headers":[{"name":"X-Signature","value":"one"}]}"#,
            ),
        ]);
        let settings = CloudSettings {
            server_url,
            token: "cumulus-secret".into(),
            timeout_connect_ms: 1000,
            timeout_ms: 2000,
        };
        let request = CloudClientFileDownloadRequest {
            app_id: Some(480),
            filename: Some("save.dat".into()),
            realm: None,
            force_proxy: None,
        };
        let mut state = AdapterState::default();
        let reply = execute_rpc(
            &mut state,
            &settings,
            FILE_DOWNLOAD,
            &request.encode_to_vec(),
        )
        .unwrap();
        let response = CloudClientFileDownloadResponse::decode(reply.body.as_slice()).unwrap();
        assert_eq!(response.url_host.as_deref(), Some("cdn.example"));
        assert_eq!(
            response.url_path.as_deref(),
            Some("/objects/save?signature=one")
        );
        assert_eq!(response.use_https, Some(true));
        assert_eq!(response.request_headers.len(), 1);
        assert_eq!(
            response.request_headers[0].name.as_deref(),
            Some("X-Signature")
        );
        assert!(response.request_headers.iter().all(|header| {
            !header
                .value
                .as_deref()
                .unwrap_or_default()
                .contains("cumulus-secret")
        }));
        assert!(state
            .transfer_targets
            .contains("CDN.EXAMPLE", "/objects/save?signature=one"));

        let requests = (0..2)
            .map(|_| captured.recv_timeout(Duration::from_secs(1)).unwrap())
            .collect::<Vec<_>>();
        assert!(requests[0].starts_with("GET /api/v1/apps/480/manifest HTTP/1.1"));
        assert!(requests[1].starts_with("GET /api/v1/files/9/download-target HTTP/1.1"));
        assert!(requests.iter().all(|request| request
            .to_ascii_lowercase()
            .contains("authorization: bearer cumulus-secret")));
    }

    #[test]
    fn full_upload_lifecycle_maps_rpc_and_http_in_order() {
        let (server_url, captured) = scripted_server(&[
            (
                200,
                r#"{"current_change_number":0,"app_buildid_hwm":0,"basis":"full","changed":[],"deleted":[]}"#,
            ),
            (200, r#"{"batch_id":"42","app_change_number":1}"#),
            (
                200,
                r#"{"file_id":"file-1","transfer_size":4,"block_requests":[{"url_host":null,"url_path":"/api/v1/upload-batches/42/files/file-1/blocks/0","use_https":null,"http_method":4,"request_headers":[],"block_offset":0,"block_length":4,"may_parallelize":false}]}"#,
            ),
            (204, ""),
            (204, ""),
            (200, r#"{"change_number":1}"#),
        ]);
        let settings = CloudSettings {
            server_url,
            token: "lifecycle-token".into(),
            timeout_connect_ms: 1000,
            timeout_ms: 2000,
        };
        let mut state = AdapterState::default();

        let changelist = CloudGetAppFileChangelistRequest {
            app_id: Some(480),
            synced_change_number: Some(0),
        };
        execute_rpc(
            &mut state,
            &settings,
            GET_CHANGELIST,
            &changelist.encode_to_vec(),
        )
        .unwrap();

        let begin = CloudBeginAppUploadBatchRequest {
            app_id: Some(480),
            machine_name: Some("deck".into()),
            files_to_upload: vec!["save.dat".into()],
            files_to_delete: Vec::new(),
            client_id: Some(7),
            app_build_id: Some(42),
        };
        let begin_reply =
            execute_rpc(&mut state, &settings, BEGIN_BATCH, &begin.encode_to_vec()).unwrap();
        let begin_response =
            CloudBeginAppUploadBatchResponse::decode(begin_reply.body.as_slice()).unwrap();
        let batch_id = begin_response.batch_id.unwrap();
        assert_eq!(batch_id, 42);
        assert_eq!(begin_response.app_change_number, Some(1));

        let declare = CloudClientBeginFileUploadRequest {
            app_id: Some(480),
            file_size: Some(4),
            raw_file_size: Some(4),
            file_sha: Some(vec![0x11; 20]),
            timestamp: Some(1_700_000_000),
            filename: Some("save.dat".into()),
            platforms_to_sync: Some(u32::MAX),
            cell_id: None,
            can_encrypt: Some(false),
            is_shared_file: Some(false),
            deprecated_realm: None,
            upload_batch_id: Some(batch_id),
        };
        let declare_reply = execute_rpc(
            &mut state,
            &settings,
            BEGIN_FILE_UPLOAD,
            &declare.encode_to_vec(),
        )
        .unwrap();
        let declare_response =
            CloudClientBeginFileUploadResponse::decode(declare_reply.body.as_slice()).unwrap();
        assert_eq!(declare_response.encrypt_file, Some(false));
        assert_eq!(declare_response.block_requests.len(), 1);
        assert_eq!(declare_response.block_requests[0].block_length, Some(4));
        put_upload_block(&declare_response.block_requests[0], b"save");

        let finalize = CloudClientCommitFileUploadRequest {
            transfer_succeeded: Some(true),
            app_id: Some(480),
            file_sha: Some(vec![0x11; 20]),
            filename: Some("save.dat".into()),
        };
        let finalize_reply = execute_rpc(
            &mut state,
            &settings,
            COMMIT_FILE_UPLOAD,
            &finalize.encode_to_vec(),
        )
        .unwrap();
        let finalize_response =
            CloudClientCommitFileUploadResponse::decode(finalize_reply.body.as_slice()).unwrap();
        assert_eq!(finalize_response.file_committed, Some(true));

        let complete = CloudCompleteAppUploadBatchRequest {
            app_id: Some(480),
            batch_id: Some(batch_id),
            batch_eresult: Some(ERESULT_OK as u32),
        };
        execute_rpc(
            &mut state,
            &settings,
            COMPLETE_BATCH,
            &complete.encode_to_vec(),
        )
        .unwrap();
        assert_eq!(state.current_change_numbers.get(&480), Some(&1));
        assert!(!state.active_batches.contains_key(&480));
        assert!(state.batches.is_empty());

        let requests = (0..6)
            .map(|_| captured.recv_timeout(Duration::from_secs(1)).unwrap())
            .collect::<Vec<_>>();
        let request_lines = requests
            .iter()
            .map(|request| request.lines().next().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            request_lines,
            [
                "GET /api/v1/apps/480/changelist?synced_change_number=0 HTTP/1.1",
                "POST /api/v1/steam/apps/480/upload-batches HTTP/1.1",
                "POST /api/v1/steam/upload-batches/42/files HTTP/1.1",
                "PUT /api/v1/upload-batches/42/files/file-1/blocks/0 HTTP/1.1",
                "POST /api/v1/upload-batches/42/files/file-1/finalize HTTP/1.1",
                "POST /api/v1/upload-batches/42/commit HTTP/1.1",
            ]
        );
        assert!(requests.iter().all(|request| request
            .to_ascii_lowercase()
            .contains("authorization: bearer lifecycle-token")));
    }
}
