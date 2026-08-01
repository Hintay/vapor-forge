use super::adapter::{AdapterState, BatchState, LocalAppState, LocalConflictState, LocalKeepLocal};
use super::http::{bytes_to_hex, hex_to_bytes, required, AdapterError, CloudSettings};
use super::protocol::RpcReply;
use super::*;
use prost::Message;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use vapor_forge_cloud_core::{device_descriptor, CloudFileStore, FileEntry, FileMetadata};
use vapor_forge_cloud_local::{
    commit_upload, issue_download, issue_upload, CommitIdentity, FolderStore, StoreView,
};
use vapor_forge_steam_protocol::*;

pub(super) fn execute_local_rpc(
    state: &mut AdapterState,
    settings: &CloudSettings,
    method: &str,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let steam_id64 = settings
        .steam_id64
        .filter(|steam_id64| *steam_id64 != 0)
        .ok_or_else(|| AdapterError::Protocol("local cloud account is unavailable".into()))?;
    let store = FolderStore::open_account(&settings.local_path, steam_id64)?;
    match method {
        GET_CHANGELIST => changelist(state, settings, &store, body),
        BEGIN_BATCH => begin_batch(state, settings, &store, body),
        BEGIN_FILE_UPLOAD => begin_file_upload(state, store, body),
        COMMIT_FILE_UPLOAD => commit_file_upload(state, body),
        COMPLETE_BATCH | COMPLETE_BATCH_BLOCKING => complete_batch(state, &store, body),
        FILE_DOWNLOAD => file_download(store, body),
        DELETE_FILE => delete_file(state, &store, body),
        QUOTA_USAGE => quota(&store, body),
        LAUNCH_INTENT => launch(state, settings, &store, body),
        SUSPEND_SESSION => suspend(state, settings, &store, body),
        RESUME_SESSION => resume(state, settings, &store, body),
        CONFLICT_RESOLUTION => conflict_resolution(state, settings, &store, body),
        EXIT_SYNC_DONE => exit(state, settings, &store, body),
        CDN_REPORT | EXTERNAL_TRANSFER_REPORT => Ok(RpcReply::ok(Vec::new())),
        _ => Err(AdapterError::Protocol(
            "unsupported local cloud method".into(),
        )),
    }
}

fn conflict_resolution(
    state: &mut AdapterState,
    settings: &CloudSettings,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudClientConflictResolutionNotification::decode(body)?;
    let app_id = local_app_id(request.app_id)?;
    let chose_local = request.chose_local_files.unwrap_or(false);
    let app = state.local_apps.get_mut(&app_id).ok_or_else(|| {
        AdapterError::Protocol("local conflict choice has no bound launch context".into())
    })?;
    let conflict = app.conflict.as_ref().ok_or_else(|| {
        AdapterError::Protocol("local conflict choice has no active manifest conflict".into())
    })?;
    if conflict.heads != store.view(app_id)?.head_ids() {
        return Err(AdapterError::Protocol(
            "local conflict heads changed before the Steam choice".into(),
        ));
    }
    if chose_local {
        let selected_head = conflict.local_head.clone().ok_or_else(|| {
            AdapterError::Protocol("Steam local side does not identify one manifest".into())
        })?;
        store.record_keep_local_resolution(
            app_id,
            &conflict.heads,
            &selected_head,
            &app.identity,
        )?;
        app.pending_keep_local = Some(LocalKeepLocal {
            heads: conflict.heads.clone(),
            selected_head,
        });
    } else {
        let selected_head = conflict.remote_head.as_deref().ok_or_else(|| {
            AdapterError::Protocol("Steam cloud side does not identify one manifest".into())
        })?;
        let identity = identity_for(
            settings,
            Some(app.identity.client_id),
            Some(app.identity.machine_name.clone()),
        )?;
        let change_number =
            store.resolve_to_manifest(app_id, &conflict.heads, selected_head, &identity, 0)?;
        state.current_change_numbers.insert(app_id, change_number);
        app.identity = identity;
        app.verified_heads = store.view(app_id)?.head_ids();
        app.conflict = None;
        app.pending_keep_local = None;
        state.local_gc.queue_inspection(store.clone());
    }
    Ok(RpcReply::ok(Vec::new()))
}

fn changelist(
    state: &mut AdapterState,
    settings: &CloudSettings,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudGetAppFileChangelistRequest::decode(body)?;
    let app_id = local_app_id(request.app_id)?;
    let synced = request.synced_change_number.unwrap_or(0);
    let identity = identity_for(settings, None, None)?;
    let mut view = store.view(app_id)?;
    if view.is_conflicted() && store.resolve_identical_heads(app_id, &identity)?.is_some() {
        state.local_gc.queue_inspection(store.clone());
        view = store.view(app_id)?;
    }
    let conflict = conflict_from_view(&view, identity.client_id);
    let stock_remote_head = conflict
        .as_ref()
        .and_then(|conflict| conflict.remote_head.as_deref())
        .and_then(|head| {
            view.heads
                .iter()
                .find(|candidate| candidate.id == head && candidate.revision >= synced)
                .map(|_| head.to_owned())
        });
    let custom_resolution =
        view.is_conflicted() && (view.heads.len() > 2 || stock_remote_head.is_none());
    state.local_conflicts.register(
        settings,
        app_id,
        &identity,
        &view,
        custom_resolution,
        synced,
    );
    state.local_apps.insert(
        app_id,
        LocalAppState {
            identity,
            verified_heads: view.head_ids(),
            conflict,
            pending_keep_local: None,
        },
    );
    if custom_resolution {
        state.current_change_numbers.insert(app_id, synced);
        state.client_change_numbers.insert(app_id, synced);
        return Ok(changelist_barrier(synced));
    }
    let changes = if let Some(head) = stock_remote_head.as_deref() {
        store.changes_from_head(app_id, head, synced)?
    } else {
        store.changes_since(app_id, synced)?
    };
    let current = changes.current_change_number;
    state.current_change_numbers.insert(app_id, current);
    state.client_change_numbers.insert(app_id, synced);

    let mut prefixes = Vec::new();
    let mut prefix_indexes = BTreeMap::new();
    let mut files = Vec::with_capacity(changes.files.len() + changes.deleted_paths.len());
    for file in &changes.files {
        files.push(file_info(
            &file.path,
            Some(file),
            0,
            &mut prefixes,
            &mut prefix_indexes,
        )?);
    }
    for path in &changes.deleted_paths {
        files.push(file_info(
            path,
            None,
            2,
            &mut prefixes,
            &mut prefix_indexes,
        )?);
    }
    let machine_names = (!files.is_empty())
        .then(|| "Local folder".to_string())
        .into_iter()
        .collect();
    Ok(RpcReply::ok(
        CloudGetAppFileChangelistResponse {
            current_change_number: Some(current),
            files,
            is_only_delta: Some(changes.is_delta),
            path_prefixes: prefixes,
            machine_names,
            app_build_id_hwm: Some(0),
        }
        .encode_to_vec(),
    ))
}

fn begin_batch(
    state: &mut AdapterState,
    settings: &CloudSettings,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudBeginAppUploadBatchRequest::decode(body)?;
    let app_id = local_app_id(request.app_id)?;
    let identity = identity_for(settings, request.client_id, request.machine_name)?;
    let app = state.local_apps.get(&app_id).ok_or_else(|| {
        AdapterError::Protocol("upload started before a verified local cloud view".into())
    })?;
    if app.identity.client_id != identity.client_id {
        return Err(AdapterError::Protocol(
            "upload ClientID does not match the verified local cloud view".into(),
        ));
    }
    let view = store.view(app_id)?;
    let durable_keep_local = store
        .keep_local_resolution(app_id, identity.client_id)?
        .map(|resolution| LocalKeepLocal {
            heads: resolution.heads,
            selected_head: resolution.selected_head,
        });
    let current_heads = view.head_ids();
    let keep_local = app
        .pending_keep_local
        .as_ref()
        .or(durable_keep_local.as_ref());
    let (base_heads, resolution_heads) = match keep_local {
        Some(resolution) => {
            if current_heads != resolution.heads {
                return Err(AdapterError::Protocol(
                    "local conflict heads changed before the upload batch".into(),
                ));
            }
            (
                vec![resolution.selected_head.clone()],
                Some(resolution.heads.clone()),
            )
        }
        None => {
            if view.is_conflicted() {
                return Err(AdapterError::Protocol(
                    "ordinary upload cannot cover unresolved manifest heads".into(),
                ));
            }
            if current_heads != app.verified_heads {
                return Err(AdapterError::Protocol(
                    "local cloud changed after the verified view".into(),
                ));
            }
            (current_heads, None)
        }
    };
    if let Some(previous) = state.active_batches.remove(&app_id) {
        state.local_gc.unregister_batch(previous);
        state.batches.remove(&previous);
    }
    let batch_id = next_batch_id();
    let gc_manifest_roots = resolution_heads.as_deref().unwrap_or(&base_heads).to_vec();
    state.active_batches.insert(app_id, batch_id);
    state.batches.insert(
        batch_id,
        BatchState {
            app_id,
            upload_paths: request.files_to_upload.into_iter().collect(),
            delete_paths: request.files_to_delete.into_iter().collect(),
            files: HashMap::new(),
            local_base_heads: base_heads,
            local_files: HashMap::new(),
            local_identity: Some(identity),
            local_resolution_heads: resolution_heads,
            conflict_resolution: None,
        },
    );
    state
        .local_gc
        .register_batch(batch_id, store, &gc_manifest_roots);
    Ok(RpcReply::ok(
        CloudBeginAppUploadBatchResponse {
            batch_id: Some(batch_id),
            app_change_number: Some(view.current_change_number.unwrap_or(view.max_revision)),
        }
        .encode_to_vec(),
    ))
}

fn begin_file_upload(
    state: &mut AdapterState,
    store: FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudClientBeginFileUploadRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let path = required(request.filename, "filename")?;
    let batch_id = super::adapter::find_batch_id(state, app_id, request.upload_batch_id)?;
    let batch = state
        .batches
        .get(&batch_id)
        .ok_or_else(|| AdapterError::Protocol("unknown upload batch".into()))?;
    if !batch.upload_paths.contains(&path) {
        return Err(AdapterError::Protocol(format!(
            "file was not listed in BeginAppUploadBatch: {path}"
        )));
    }
    let transfer_size = u64::from(request.file_size.unwrap_or(0));
    let raw_size = u64::from(request.raw_file_size.or(request.file_size).unwrap_or(0));
    let sha1 = bytes_to_hex(&required(request.file_sha, "file_sha")?);
    if sha1.len() != 40 {
        return Err(AdapterError::Protocol("file_sha is not a SHA-1".into()));
    }
    state.local_gc.retain_blob(batch_id, &sha1);
    let metadata = FileMetadata {
        sha1,
        raw_size,
        mtime: i64::try_from(request.timestamp.unwrap_or(0))
            .map_err(|_| AdapterError::Protocol("timestamp exceeds local range".into()))?,
        platforms_to_sync: request.platforms_to_sync.unwrap_or(u32::MAX),
    };
    let (token, target) = issue_upload(store, app_id, path.clone(), transfer_size, metadata)?;
    state
        .batches
        .get_mut(&batch_id)
        .expect("batch checked above")
        .files
        .insert(path, token);
    Ok(RpcReply::ok(
        CloudClientBeginFileUploadResponse {
            encrypt_file: Some(false),
            block_requests: vec![CloudFileUploadBlockDetails {
                url_host: Some(target.host),
                url_path: Some(target.path),
                use_https: Some(false),
                http_method: Some(HTTP_METHOD_PUT),
                request_headers: Vec::new(),
                block_offset: Some(0),
                block_length: Some(u32::try_from(transfer_size).map_err(|_| {
                    AdapterError::Protocol("local upload exceeds Steam block range".into())
                })?),
                explicit_body_data: None,
                may_parallelize: Some(false),
            }],
        }
        .encode_to_vec(),
    ))
}

fn commit_file_upload(state: &mut AdapterState, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudClientCommitFileUploadRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let path = required(request.filename, "filename")?;
    let batch_id = super::adapter::find_batch_id(state, app_id, None)?;
    let token = state
        .batches
        .get(&batch_id)
        .and_then(|batch| batch.files.get(&path))
        .cloned()
        .ok_or_else(|| AdapterError::Protocol("upload was not begun for this file".into()))?;
    let committed = if request.transfer_succeeded.unwrap_or(false) {
        match commit_upload(&token) {
            Ok(staged) => {
                state
                    .batches
                    .get_mut(&batch_id)
                    .expect("batch checked above")
                    .local_files
                    .insert(path, staged);
                true
            }
            Err(_) => false,
        }
    } else {
        false
    };
    Ok(RpcReply::ok(
        CloudClientCommitFileUploadResponse {
            file_committed: Some(committed),
        }
        .encode_to_vec(),
    ))
}

fn complete_batch(
    state: &mut AdapterState,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudCompleteAppUploadBatchRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let batch_id = super::adapter::find_batch_id(state, app_id, request.batch_id)?;
    let committed = request.batch_eresult.unwrap_or_default() == super::ERESULT_OK as u32;
    if committed {
        let batch = state
            .batches
            .get(&batch_id)
            .ok_or_else(|| AdapterError::Protocol("unknown upload batch".into()))?;
        if let Some(path) = batch
            .upload_paths
            .iter()
            .find(|path| !batch.local_files.contains_key(*path))
        {
            return Err(AdapterError::Protocol(format!(
                "upload batch completed before file was committed: {path}"
            )));
        }
        let staged = batch.local_files.values().cloned().collect::<Vec<_>>();
        let identity = batch.local_identity.as_ref().ok_or_else(|| {
            AdapterError::Protocol("local upload batch has no bound identity".into())
        })?;
        let change_number = store.commit_batch(
            app_id,
            &batch.local_base_heads,
            &staged,
            &batch.delete_paths,
            identity,
            batch.local_resolution_heads.as_deref(),
        )?;
        state.current_change_numbers.insert(app_id, change_number);
        let view = store.view(app_id)?;
        let app = state.local_apps.get_mut(&app_id).ok_or_else(|| {
            AdapterError::Protocol("local upload batch lost its verified app state".into())
        })?;
        app.identity = identity.clone();
        app.verified_heads = view.head_ids();
        app.conflict = None;
        app.pending_keep_local = None;
    }
    state.active_batches.remove(&app_id);
    state.batches.remove(&batch_id);
    state.local_gc.unregister_batch(batch_id);
    if committed {
        state.local_gc.queue_inspection(store.clone());
    }
    Ok(RpcReply::ok(
        CloudCompleteAppUploadBatchResponse {}.encode_to_vec(),
    ))
}

fn delete_file(
    state: &mut AdapterState,
    _store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudClientDeleteFileRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let path = required(request.filename, "filename")?;
    let batch_id = super::adapter::find_batch_id(state, app_id, request.upload_batch_id)?;
    if !state
        .batches
        .get(&batch_id)
        .is_some_and(|batch| batch.delete_paths.contains(&path))
    {
        return Err(AdapterError::Protocol(format!(
            "file was not listed for deletion: {path}"
        )));
    }
    Ok(RpcReply::ok(
        CloudClientDeleteFileResponse {}.encode_to_vec(),
    ))
}

fn file_download(store: FolderStore, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudClientFileDownloadRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let path = required(request.filename, "filename")?;
    let file = store
        .changes_since(app_id, 0)?
        .files
        .into_iter()
        .find(|file| file.path == path)
        .ok_or_else(|| AdapterError::Protocol("download file is not in the manifest".into()))?;
    let target = issue_download(store, app_id, path)?;
    let size = u32::try_from(file.metadata.raw_size)
        .map_err(|_| AdapterError::Protocol("local cloud file exceeds Steam size range".into()))?;
    Ok(RpcReply::ok(
        CloudClientFileDownloadResponse {
            app_id: Some(app_id),
            file_size: Some(size),
            raw_file_size: Some(size),
            sha_file: Some(hex_to_bytes(&file.metadata.sha1)?),
            timestamp: Some(
                u64::try_from(file.metadata.mtime).map_err(|_| {
                    AdapterError::Protocol("local cloud timestamp is negative".into())
                })?,
            ),
            is_explicit_delete: Some(false),
            url_host: Some(target.host),
            url_path: Some(target.path),
            use_https: Some(false),
            request_headers: Vec::new(),
            encrypted: Some(false),
        }
        .encode_to_vec(),
    ))
}

fn quota(store: &FolderStore, body: &[u8]) -> Result<RpcReply, AdapterError> {
    let request = CloudClientGetAppQuotaUsageRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let quota = store.quota(app_id)?;
    Ok(RpcReply::ok(
        CloudClientGetAppQuotaUsageResponse {
            existing_files: Some(quota.used_files),
            existing_bytes: Some(quota.used_bytes),
            max_num_files: Some(quota.total_files),
            max_num_bytes: Some(quota.total_bytes),
        }
        .encode_to_vec(),
    ))
}

fn launch(
    state: &mut AdapterState,
    settings: &CloudSettings,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudAppLaunchIntentRequest::decode(body)?;
    let app_id = local_app_id(request.app_id)?;
    let identity = identity_for(settings, request.client_id, request.machine_name)?;
    let view = store.view(app_id)?;
    let conflict = conflict_from_view(&view, identity.client_id);
    let custom_resolution = view.is_conflicted()
        && (view.heads.len() > 2
            || conflict
                .as_ref()
                .and_then(|conflict| conflict.remote_head.as_ref())
                .is_none());
    let minimum_revision = state
        .client_change_numbers
        .get(&app_id)
        .copied()
        .unwrap_or_default();
    let custom_pending = state.local_conflicts.arm(
        settings,
        app_id,
        &identity,
        &view,
        custom_resolution,
        minimum_revision,
    );
    let peers = if custom_pending {
        Vec::new()
    } else {
        store.launch_session(
            app_id,
            &identity,
            request.os_type,
            request.device_type,
            request.ignore_pending_operations.unwrap_or(false),
        )?
    };
    if !custom_pending && peers.is_empty() {
        state.local_sessions.insert(app_id);
    } else {
        state.local_sessions.remove(&app_id);
    }
    let mut pending_remote_operations = peers
        .into_iter()
        .map(|peer| CloudPendingRemoteOperation {
            operation: Some(1),
            machine_name: Some(peer.machine_name),
            client_id: Some(peer.client_id),
            time_last_updated: Some(peer.time_last_updated),
            os_type: peer.os_type,
            device_type: peer.device_type,
        })
        .collect::<Vec<_>>();
    if custom_pending {
        let time_last_updated = view
            .heads
            .iter()
            .map(|head| (head.created_at_ms / 1_000).min(u32::MAX as u64) as u32)
            .max()
            .unwrap_or_default();
        pending_remote_operations.push(CloudPendingRemoteOperation {
            operation: Some(1),
            machine_name: Some("Multiple saved versions".into()),
            client_id: Some(0),
            time_last_updated: Some(time_last_updated),
            os_type: request.os_type,
            device_type: request.device_type,
        });
    }
    let verified_heads = view.head_ids();
    let app = state.local_apps.entry(app_id).or_insert(LocalAppState {
        identity: identity.clone(),
        verified_heads: verified_heads.clone(),
        conflict: None,
        pending_keep_local: None,
    });
    if app.verified_heads != verified_heads {
        app.conflict = None;
        app.pending_keep_local = None;
    }
    app.identity = identity;
    app.verified_heads = verified_heads;
    let eresult = if pending_remote_operations.is_empty() {
        super::ERESULT_OK
    } else {
        super::ERESULT_TOO_MANY_PENDING
    };
    Ok(RpcReply {
        body: CloudAppLaunchIntentResponse {
            pending_remote_operations,
        }
        .encode_to_vec(),
        eresult,
    })
}

fn suspend(
    state: &mut AdapterState,
    settings: &CloudSettings,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudAppSessionSuspendRequest::decode(body)?;
    let app_id = local_app_id(request.app_id)?;
    let machine_name = request.machine_name.or_else(|| {
        state
            .local_apps
            .get(&app_id)
            .map(|app| app.identity.machine_name.clone())
    });
    let identity = identity_for(settings, request.client_id, machine_name)?;
    store.suspend_session(app_id, &identity)?;
    update_local_identity(state, app_id, identity);
    Ok(RpcReply::ok(
        CloudAppSessionSuspendResponse {}.encode_to_vec(),
    ))
}

fn resume(
    state: &mut AdapterState,
    settings: &CloudSettings,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudAppSessionResumeRequest::decode(body)?;
    let app_id = local_app_id(request.app_id)?;
    let machine_name = state
        .local_apps
        .get(&app_id)
        .map(|app| app.identity.machine_name.clone());
    let identity = identity_for(settings, request.client_id, machine_name)?;
    store.resume_session(app_id, &identity)?;
    update_local_identity(state, app_id, identity);
    Ok(RpcReply::ok(
        CloudAppSessionResumeResponse {}.encode_to_vec(),
    ))
}

fn exit(
    state: &mut AdapterState,
    settings: &CloudSettings,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudAppExitSyncDoneNotification::decode(body)?;
    let app_id = local_app_id(request.app_id)?;
    if !state.local_sessions.remove(&app_id) {
        return Ok(RpcReply::ok(Vec::new()));
    }
    let machine_name = state
        .local_apps
        .get(&app_id)
        .map(|app| app.identity.machine_name.clone());
    let identity = identity_for(settings, request.client_id, machine_name)?;
    store.exit_session(app_id, &identity)?;
    update_local_identity(state, app_id, identity);
    Ok(RpcReply::ok(Vec::new()))
}

fn local_app_id(app_id: Option<u32>) -> Result<u32, AdapterError> {
    let app_id = required(app_id, "appid")?;
    if app_id == 0 {
        return Err(AdapterError::Protocol(
            "local cloud does not support account-scope AppID 0".into(),
        ));
    }
    Ok(app_id)
}

fn identity_for(
    settings: &CloudSettings,
    request_client_id: Option<u64>,
    machine_name: Option<String>,
) -> Result<CommitIdentity, AdapterError> {
    let settings_client_id = settings.steam_client_id.filter(|client_id| *client_id != 0);
    let request_client_id = request_client_id.filter(|client_id| *client_id != 0);
    if let (Some(expected), Some(actual)) = (settings_client_id, request_client_id) {
        if expected != actual {
            return Err(AdapterError::Protocol(
                "local cloud request ClientID does not match the active Steam device".into(),
            ));
        }
    }
    let client_id = request_client_id.or(settings_client_id).ok_or_else(|| {
        AdapterError::Protocol("local cloud Steam ClientID is unavailable".into())
    })?;
    let descriptor = device_descriptor().filter(|descriptor| descriptor.client_id == client_id);
    let machine_name = machine_name
        .filter(|name| !name.trim().is_empty())
        .or_else(|| descriptor.map(|descriptor| descriptor.machine_name))
        .unwrap_or_else(|| "Local machine".to_string());
    Ok(CommitIdentity {
        client_id,
        machine_name,
    })
}

fn conflict_from_view(view: &StoreView, client_id: u64) -> Option<LocalConflictState> {
    if !view.is_conflicted() {
        return None;
    }
    let local = view
        .heads
        .iter()
        .filter(|head| head.client_id == client_id)
        .collect::<Vec<_>>();
    let (local_head, remote_head) = if view.heads.len() == 2 && local.len() == 1 {
        let local_id = local[0].id.clone();
        let remote_id = view
            .heads
            .iter()
            .find(|head| head.id != local_id)
            .map(|head| head.id.clone());
        (Some(local_id), remote_id)
    } else {
        (None, None)
    };
    Some(LocalConflictState {
        heads: view.head_ids(),
        local_head,
        remote_head,
    })
}

fn update_local_identity(state: &mut AdapterState, app_id: u32, identity: CommitIdentity) {
    if let Some(app) = state.local_apps.get_mut(&app_id) {
        app.identity = identity;
    }
}

fn changelist_barrier(change_number: u64) -> RpcReply {
    RpcReply::ok(
        CloudGetAppFileChangelistResponse {
            current_change_number: Some(change_number),
            files: Vec::new(),
            is_only_delta: Some(false),
            path_prefixes: Vec::new(),
            machine_names: Vec::new(),
            app_build_id_hwm: Some(0),
        }
        .encode_to_vec(),
    )
}

fn file_info(
    path: &str,
    file: Option<&FileEntry>,
    persist_state: i32,
    prefixes: &mut Vec<String>,
    prefix_indexes: &mut BTreeMap<String, u32>,
) -> Result<CloudAppFileInfo, AdapterError> {
    let (prefix, leaf) = super::adapter::split_cloud_path(path);
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
        sha_file: file
            .map(|entry| hex_to_bytes(&entry.metadata.sha1))
            .transpose()?,
        timestamp: file
            .map(|entry| {
                u64::try_from(entry.metadata.mtime)
                    .map_err(|_| AdapterError::Protocol("local cloud timestamp is negative".into()))
            })
            .transpose()?,
        raw_file_size: file
            .map(|entry| {
                u32::try_from(entry.metadata.raw_size).map_err(|_| {
                    AdapterError::Protocol("local cloud file exceeds Steam size range".into())
                })
            })
            .transpose()?,
        persist_state: Some(persist_state),
        platforms_to_sync: Some(file.map_or(u32::MAX, |entry| entry.metadata.platforms_to_sync)),
        path_prefix_index: Some(prefix_index),
        machine_name_index: Some(0),
        reupload_requested: None,
    })
}

fn next_batch_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
