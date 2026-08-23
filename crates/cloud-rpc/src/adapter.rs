use super::conflict_ui::LocalConflictCoordinator;
use super::http::*;
use super::protocol::RpcReply;
use super::transfer_targets::{CloudStateScope, TransferTargetRegistry};
use super::*;
use prost::Message;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;
use tracing::warn;
use vapor_forge_cloud_core::{device_descriptor, CloudBackend};
use vapor_forge_cloud_local::{FolderStore, LocalGcCoordinator};
use vapor_forge_core::unix_now;
use vapor_forge_steam_protocol::*;
use vapor_forge_sync_journal::{
    default_sync_journal_path, new_conflict_event_id, ConflictResolutionEvent, Queued, SyncJournal,
};

pub(super) struct AdapterState {
    pub(super) scope: Option<CloudStateScope>,
    pub(super) current_change_numbers: HashMap<u32, u64>,
    pub(super) client_change_numbers: HashMap<u32, u64>,
    pub(super) active_batches: HashMap<u32, u64>,
    pub(super) batches: HashMap<u64, BatchState>,
    pub(super) local_apps: HashMap<u32, LocalAppState>,
    pub(super) files: HashMap<(u32, String), CumulusFile>,
    /// Shared with every other journal user in this process; structsy allows
    /// only one open database per file, so this is never opened here directly.
    pub(super) journal: Option<Arc<SyncJournal>>,
    pub(super) transfer_targets: Arc<TransferTargetRegistry>,
    pub(super) principal_scope: Option<String>,
    pub(super) local_gc: Arc<LocalGcCoordinator>,
    pub(super) local_conflicts: Arc<LocalConflictCoordinator>,
    pub(super) local_store: Option<FolderStore>,
}

#[cfg(test)]
impl Default for AdapterState {
    fn default() -> Self {
        Self::with_transfer_targets_and_journal(Arc::new(TransferTargetRegistry::default()), None)
    }
}

impl AdapterState {
    pub(super) fn with_transfer_targets_gc_and_conflicts(
        transfer_targets: Arc<TransferTargetRegistry>,
        local_gc: Arc<LocalGcCoordinator>,
        local_conflicts: Arc<LocalConflictCoordinator>,
    ) -> Self {
        let journal = default_sync_journal_path().and_then(|path| match open_journal(&path) {
            Ok(journal) => Some(journal),
            Err(error) => {
                warn!(%error, path = %path.display(), "cloud-rpc: conflict journal unavailable");
                None
            }
        });
        Self::with_transfer_targets_journal_gc_and_conflicts(
            transfer_targets,
            journal,
            local_gc,
            local_conflicts,
        )
    }

    #[cfg(test)]
    pub(super) fn with_transfer_targets_and_journal(
        transfer_targets: Arc<TransferTargetRegistry>,
        journal: Option<Arc<SyncJournal>>,
    ) -> Self {
        let local_gc = Arc::new(LocalGcCoordinator::try_new().unwrap());
        let local_conflicts = LocalConflictCoordinator::try_new(Arc::clone(&local_gc)).unwrap();
        Self::with_transfer_targets_journal_gc_and_conflicts(
            transfer_targets,
            journal,
            local_gc,
            local_conflicts,
        )
    }

    fn with_transfer_targets_journal_gc_and_conflicts(
        transfer_targets: Arc<TransferTargetRegistry>,
        journal: Option<Arc<SyncJournal>>,
        local_gc: Arc<LocalGcCoordinator>,
        local_conflicts: Arc<LocalConflictCoordinator>,
    ) -> Self {
        Self {
            scope: None,
            current_change_numbers: HashMap::new(),
            client_change_numbers: HashMap::new(),
            active_batches: HashMap::new(),
            batches: HashMap::new(),
            local_apps: HashMap::new(),
            files: HashMap::new(),
            journal,
            transfer_targets,
            principal_scope: None,
            local_gc,
            local_conflicts,
            local_store: None,
        }
    }

    pub(super) fn prepare(&mut self, settings: &CloudSettings) {
        let scope = CloudStateScope::from_settings(settings);
        if self.scope.as_ref() == Some(&scope) {
            return;
        }
        if self.scope.is_some() {
            warn!("cloud-rpc: backend scope changed; discarded transient adapter state");
        }
        self.abort_local_operations();
        self.current_change_numbers.clear();
        self.client_change_numbers.clear();
        self.active_batches.clear();
        self.batches.clear();
        self.local_apps.clear();
        self.local_store = None;
        self.files.clear();
        self.principal_scope = None;
        self.scope = Some(scope);
    }

    pub(super) fn scope(&self) -> &CloudStateScope {
        self.scope
            .as_ref()
            .expect("adapter scope prepared before RPC dispatch")
    }

    fn abort_local_operations(&self) {
        for batch in self.batches.values() {
            if let Some(operation) = &batch.local_operation {
                if let Err(error) = operation.abort() {
                    warn!(%error, "cloud-rpc: failed to discard local upload operation");
                }
            }
        }
    }
}

pub(super) struct BatchState {
    pub(super) app_id: u32,
    pub(super) upload_paths: BTreeSet<String>,
    pub(super) delete_paths: BTreeSet<String>,
    pub(super) files: HashMap<String, String>,
    pub(super) local_files: HashMap<String, vapor_forge_cloud_local::StagedFile>,
    pub(super) local_operation: Option<vapor_forge_cloud_local::SaveOperation>,
    pub(super) local_identity: Option<vapor_forge_cloud_local::CommitIdentity>,
    pub(super) conflict_resolution: Option<Queued<ConflictResolutionEvent>>,
}

pub(super) struct LocalAppState {
    pub(super) identity: vapor_forge_cloud_local::CommitIdentity,
    pub(super) verified_heads: Vec<String>,
    pub(super) conflict: Option<LocalConflictState>,
    pub(super) pending_keep_local: Option<LocalKeepLocal>,
}

#[derive(Clone)]
pub(super) struct LocalConflictState {
    pub(super) heads: Vec<String>,
    pub(super) local_head: Option<String>,
    pub(super) remote_head: Option<String>,
}

#[derive(Clone)]
pub(super) struct LocalKeepLocal {
    pub(super) heads: Vec<String>,
    pub(super) selected_head: String,
}

pub(super) fn execute_rpc(
    state: &mut AdapterState,
    settings: &CloudSettings,
    method: &str,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    state.prepare(settings);
    match settings.backend {
        vapor_forge_config::CloudBackendMode::Local => {
            return super::local::execute_local_rpc(state, settings, method, body);
        }
        vapor_forge_config::CloudBackendMode::Cumulus => {}
        vapor_forge_config::CloudBackendMode::Disabled => {
            return Err(AdapterError::Protocol("cloud backend is disabled".into()));
        }
    }
    // Composition root for the RPC path: device binding and scoping go through
    // the backend port; the file transfers below still speak Cumulus HTTP.
    let backend = vapor_forge_cloud_cumulus::CumulusBackend::new(
        vapor_forge_cloud_cumulus::CumulusSettings {
            server_url: settings.server_url.clone(),
            token: settings.token.clone(),
            timeout_connect_ms: settings.timeout_connect_ms,
            timeout_ms: settings.timeout_ms,
        },
    );
    if settings.bind_device {
        let descriptor = device_descriptor().ok_or_else(|| {
            AdapterError::Protocol("Steam ClientID is not available for device binding".into())
        })?;
        backend.ensure_device_bound(&descriptor)?;
    }
    let client = CumulusClient::new(settings)?;
    match method {
        GET_CHANGELIST => handle_changelist(state, &client, body),
        BEGIN_BATCH => {
            let conflict_scope = backend.principal_scope()?;
            state.principal_scope = Some(conflict_scope.clone());
            if let Some(journal) = state.journal.as_deref() {
                journal.attribute_pending_conflicts(
                    state.scope().credential_fingerprint(),
                    &conflict_scope,
                )?;
            }
            if let Err(error) = deliver_ready_conflicts(state, &client, &conflict_scope) {
                warn!(%error, "cloud-rpc: deferred conflict report failed");
            }
            handle_begin_batch(state, &client, &conflict_scope, body)
        }
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
        CONFLICT_RESOLUTION => handle_conflict_resolution(state, &backend, &client, body),
        CDN_REPORT => handle_cdn_report(&client, body),
        EXTERNAL_TRANSFER_REPORT => handle_external_transfer_report(&client, body),
        _ => Err(AdapterError::Protocol("unsupported cloud method".into())),
    }
}

pub(super) fn handle_changelist(
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

pub(super) fn handle_begin_batch(
    state: &mut AdapterState,
    client: &CumulusClient,
    conflict_scope: &str,
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
    if let Some(previous) = state.active_batches.get(&app_id).copied() {
        client.delete_allow_not_found(&format!("/api/v1/upload-batches/{previous}"))?;
        state.active_batches.remove(&app_id);
        state.batches.remove(&previous);
    }
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
    let conflict_resolution = match state.journal.as_deref() {
        Some(journal) => journal.pending_local_conflict(conflict_scope, app_id, base)?,
        None => None,
    };
    let batch = BatchState {
        app_id,
        upload_paths: request.files_to_upload.into_iter().collect(),
        delete_paths: request.files_to_delete.into_iter().collect(),
        files: HashMap::new(),
        local_files: HashMap::new(),
        local_operation: None,
        local_identity: None,
        conflict_resolution,
    };
    state.active_batches.insert(app_id, batch_id);
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

pub(super) fn handle_begin_file_upload(
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
    let scope = state.scope().clone();
    for block in &block_requests {
        state.transfer_targets.register(
            &scope,
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

pub(super) fn handle_commit_file_upload(
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

pub(super) fn handle_complete_batch(
    state: &mut AdapterState,
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudCompleteAppUploadBatchRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let batch_id = find_batch_id(state, app_id, request.batch_id)?;
    if request.batch_eresult.unwrap_or_default() != super::ERESULT_OK as u32 {
        client.delete(&format!("/api/v1/upload-batches/{batch_id}"))?;
    } else {
        let resolution = state
            .batches
            .get(&batch_id)
            .and_then(|batch| batch.conflict_resolution.as_ref())
            .map(|queued| {
                json!({
                    "event_id": queued.value.event_id,
                    "base_change_number": signed_bits(queued.value.base_change_number),
                    "resolution": queued.value.resolution,
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
        state
            .files
            .retain(|(cached_app, _), _| *cached_app != app_id);
        if let Some(resolution) = state
            .batches
            .get(&batch_id)
            .and_then(|batch| batch.conflict_resolution.as_ref())
        {
            if let Some(journal) = state.journal.as_deref() {
                journal.acknowledge(resolution)?;
            }
        }
    }
    state.active_batches.remove(&app_id);
    state.batches.remove(&batch_id);
    Ok(RpcReply::ok(
        CloudCompleteAppUploadBatchResponse {}.encode_to_vec(),
    ))
}

pub(super) fn handle_delete_file(
    state: &mut AdapterState,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
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

pub(super) fn handle_file_download(
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
    let scope = state.scope().clone();
    state
        .transfer_targets
        .register(&scope, &target.authority, &target.path);
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

pub(super) fn handle_quota(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
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

pub(super) fn handle_launch(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudAppLaunchIntentRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let response: CumulusLaunch = client.post_json(
        &format!("/api/v1/apps/{app_id}/session/launch"),
        &json!({
            "client_id": required(request.client_id, "client_id")?.to_string(),
            "machine_name": request.machine_name.unwrap_or_else(|| "unknown".into()),
            "ignore_pending": request.ignore_pending_operations.unwrap_or(false),
            "os_type": request.os_type,
            "device_type": request.device_type,
        }),
    )?;
    let pending_remote_operations = response
        .pending_operations
        .into_iter()
        .map(|operation| {
            Ok(CloudPendingRemoteOperation {
                operation: Some(operation.operation as i32),
                machine_name: Some(operation.machine_name),
                client_id: Some(operation.client_id.parse().map_err(|_| {
                    AdapterError::Protocol("Cumulus returned an invalid Steam ClientID".into())
                })?),
                time_last_updated: Some(clamp_u32(operation.time_last_updated)),
                os_type: operation.os_type.map(|value| value as i32),
                device_type: operation.device_type.map(|value| value as i32),
            })
        })
        .collect::<Result<Vec<_>, AdapterError>>()?;
    let eresult = if pending_remote_operations.is_empty() {
        super::ERESULT_OK
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

pub(super) fn handle_suspend(
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudAppSessionSuspendRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    client.post_json_unit(
        &format!("/api/v1/apps/{app_id}/session/suspend"),
        &json!({
            "client_id": required(request.client_id, "client_id")?.to_string(),
            "cloud_sync_completed": request.cloud_sync_completed,
        }),
    )?;
    Ok(RpcReply::ok(
        CloudAppSessionSuspendResponse {}.encode_to_vec(),
    ))
}

pub(super) fn handle_resume(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudAppSessionResumeRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    client.post_json_unit(
        &format!("/api/v1/apps/{app_id}/session/resume"),
        &json!({
            "client_id": required(request.client_id, "client_id")?.to_string(),
        }),
    )?;
    Ok(RpcReply::ok(
        CloudAppSessionResumeResponse {}.encode_to_vec(),
    ))
}

pub(super) fn handle_exit(client: &CumulusClient, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudAppExitSyncDoneNotification::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    client.post_json_unit(
        &format!("/api/v1/apps/{app_id}/session/exit"),
        &json!({
            "client_id": required(request.client_id, "client_id")?.to_string(),
            "uploads_completed": request.uploads_completed,
            "uploads_required": request.uploads_required,
        }),
    )?;
    Ok(RpcReply::ok(Vec::new()))
}

pub(super) fn handle_conflict_resolution(
    state: &mut AdapterState,
    backend: &impl CloudBackend,
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudClientConflictResolutionNotification::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let base_change_number = state
        .client_change_numbers
        .get(&app_id)
        .copied()
        .ok_or_else(|| {
            AdapterError::Protocol("conflict reported before a verified changelist".into())
        })?;
    let remote_change_number = state
        .current_change_numbers
        .get(&app_id)
        .copied()
        .ok_or_else(|| {
            AdapterError::Protocol("conflict reported before a verified changelist".into())
        })?;
    let resolution = ConflictResolutionEvent {
        owner_scope: state.scope().credential_fingerprint().to_owned(),
        event_id: new_conflict_event_id(),
        app_id,
        base_change_number,
        remote_change_number,
        resolution: if request.chose_local_files.unwrap_or(false) {
            "kept_local".into()
        } else {
            "kept_cloud".into()
        },
        machine_name: device_descriptor().map(|descriptor| descriptor.machine_name),
    };
    let journal = state
        .journal
        .as_deref()
        .ok_or_else(|| AdapterError::Protocol("conflict journal is unavailable".into()))?;
    journal.enqueue_conflict(&resolution, unix_now())?;

    let conflict_scope = match backend.principal_scope() {
        Ok(scope) => scope,
        Err(error) => {
            warn!(app_id, %error, "cloud-rpc: conflict persisted pending principal lookup");
            return Ok(RpcReply::ok(Vec::new()));
        }
    };
    state.principal_scope = Some(conflict_scope.clone());
    if let Err(error) =
        journal.attribute_pending_conflicts(state.scope().credential_fingerprint(), &conflict_scope)
    {
        warn!(app_id, %error, "cloud-rpc: conflict persisted pending scope attribution");
        return Ok(RpcReply::ok(Vec::new()));
    }
    if resolution.resolution == "kept_cloud" {
        if let Err(error) = deliver_ready_conflicts(state, client, &conflict_scope) {
            warn!(app_id, %error, "cloud-rpc: kept-cloud report queued for retry");
        }
    }
    Ok(RpcReply::ok(Vec::new()))
}

pub(super) fn deliver_ready_conflicts(
    state: &AdapterState,
    client: &CumulusClient,
    conflict_scope: &str,
) -> Result<(), AdapterError> {
    let Some(journal) = state.journal.as_deref() else {
        return Ok(());
    };
    let now = unix_now();
    for queued in journal.pending_cloud_conflicts(now, conflict_scope)? {
        let resolution = &queued.value;
        let result = client.post_json_unit(
            &format!("/api/v1/apps/{}/conflicts/kept-cloud", resolution.app_id),
            &json!({
                "event_id": resolution.event_id,
                "base_change_number": signed_bits(resolution.base_change_number),
                "machine_name": resolution.machine_name,
            }),
        );
        match result {
            Ok(()) => journal.acknowledge(&queued)?,
            Err(error) => {
                journal.defer(&queued, now)?;
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Open the shared journal handle for `path`.
///
/// Always goes through the process-wide registry: structsy keeps an exclusive
/// lock per open database, so a private open here would fail whenever another
/// subsystem already holds the same file.
fn open_journal(path: &Path) -> Result<Arc<SyncJournal>, AdapterError> {
    Ok(vapor_forge_sync_journal::shared(path)?)
}

pub(super) fn handle_cdn_report(
    client: &CumulusClient,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
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

pub(super) fn handle_external_transfer_report(
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

pub(super) fn steam_file_info(
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

pub(super) fn split_cloud_path(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((prefix, leaf)) => (&path[..prefix.len() + 1], leaf),
        None => ("", path),
    }
}

pub(super) fn find_batch_id(
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
