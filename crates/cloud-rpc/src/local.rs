use super::adapter::{AdapterState, BatchState};
use super::http::{bytes_to_hex, hex_to_bytes, required, AdapterError, CloudSettings};
use super::protocol::RpcReply;
use super::*;
use prost::Message;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use vapor_forge_cloud_core::{CloudFileStore, FileEntry, FileMetadata};
use vapor_forge_cloud_local::{commit_upload, issue_download, issue_upload, FolderStore};
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
        GET_CHANGELIST => changelist(state, &store, body),
        BEGIN_BATCH => begin_batch(state, &store, body),
        BEGIN_FILE_UPLOAD => begin_file_upload(state, store, body),
        COMMIT_FILE_UPLOAD => commit_file_upload(state, body),
        COMPLETE_BATCH | COMPLETE_BATCH_BLOCKING => complete_batch(state, &store, body),
        FILE_DOWNLOAD => file_download(store, body),
        DELETE_FILE => delete_file(state, &store, body),
        QUOTA_USAGE => quota(&store, body),
        LAUNCH_INTENT => launch(body),
        SUSPEND_SESSION => {
            empty_response::<CloudAppSessionSuspendRequest, CloudAppSessionSuspendResponse>(body)
        }
        RESUME_SESSION => {
            empty_response::<CloudAppSessionResumeRequest, CloudAppSessionResumeResponse>(body)
        }
        CONFLICT_RESOLUTION => conflict_resolution(state, &store, body),
        EXIT_SYNC_DONE | CDN_REPORT | EXTERNAL_TRANSFER_REPORT => Ok(RpcReply::ok(Vec::new())),
        _ => Err(AdapterError::Protocol(
            "unsupported local cloud method".into(),
        )),
    }
}

fn conflict_resolution(
    state: &mut AdapterState,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudClientConflictResolutionNotification::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let change_number = store.converge_app(app_id)?;
    state.current_change_numbers.insert(app_id, change_number);
    Ok(RpcReply::ok(Vec::new()))
}

fn changelist(
    state: &mut AdapterState,
    store: &FolderStore,
    body: &[u8],
) -> Result<RpcReply, AdapterError> {
    let request = CloudGetAppFileChangelistRequest::decode(body)?;
    let app_id = required(request.app_id, "appid")?;
    let synced = request.synced_change_number.unwrap_or(0);
    let changes = store.changes_since(app_id, synced)?;
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
    store: &FolderStore,
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
    if let Some(previous) = state.active_batches.remove(&app_id) {
        state.batches.remove(&previous);
    }
    let view = store.view(app_id)?;
    if view.change_number != base {
        return Err(AdapterError::Protocol(
            "local cloud changed after the verified changelist".into(),
        ));
    }
    let batch_id = next_batch_id();
    state.active_batches.insert(app_id, batch_id);
    state.batches.insert(
        batch_id,
        BatchState {
            app_id,
            upload_paths: request.files_to_upload.into_iter().collect(),
            delete_paths: request.files_to_delete.into_iter().collect(),
            files: HashMap::new(),
            local_base_heads: view.heads,
            local_files: HashMap::new(),
            conflict_resolution: None,
        },
    );
    Ok(RpcReply::ok(
        CloudBeginAppUploadBatchResponse {
            batch_id: Some(batch_id),
            app_change_number: Some(view.change_number),
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
    if request.batch_eresult.unwrap_or_default() == super::ERESULT_OK as u32 {
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
        let change_number = store.commit_batch(
            app_id,
            &batch.local_base_heads,
            &staged,
            &batch.delete_paths,
        )?;
        state.current_change_numbers.insert(app_id, change_number);
    }
    state.active_batches.remove(&app_id);
    state.batches.remove(&batch_id);
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

fn launch(body: &[u8]) -> Result<RpcReply, AdapterError> {
    CloudAppLaunchIntentRequest::decode(body)?;
    Ok(RpcReply::ok(
        CloudAppLaunchIntentResponse {
            pending_remote_operations: Vec::new(),
        }
        .encode_to_vec(),
    ))
}

fn empty_response<Request, Response>(body: &[u8]) -> Result<RpcReply, AdapterError>
where
    Request: Message + Default,
    Response: Message + Default,
{
    Request::decode(body)?;
    Ok(RpcReply::ok(Response::default().encode_to_vec()))
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
