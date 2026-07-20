use super::adapter::*;
use super::http::*;
use super::protocol::*;
use super::queue::*;
use super::transfer_targets::*;
use super::*;
use prost::Message;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use vapor_forge_config::{AppId, AppsSection, CloudSection, InjectApp, RuntimeConfig};
use vapor_forge_steam_protocol::*;
use vapor_forge_sync_state::Outbox;

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
                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
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
    let mut stream = std::net::TcpStream::connect(host).unwrap();
    write!(stream, "PUT {path} HTTP/1.1\r\nHost: {host}\r\n").unwrap();
    for header in &block.request_headers {
        writeln!(
            stream,
            "{}: {}\r",
            header.name.as_deref().unwrap(),
            header.value.as_deref().unwrap()
        )
        .unwrap();
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
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
    let packet = build_response_packet(&request, Ok(RpcReply::ok(vec![1, 2, 3])));
    let (_, header, body) = vapor_forge_steam_protocol::unpack_raw(&packet).unwrap();
    let response = CMsgProtoBufHeader::decode(header).unwrap();
    assert_eq!(response.jobid_target, Some(99));
    assert_eq!(response.eresult, Some(super::ERESULT_OK));
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
fn recognizes_legacy_app_cloud_methods() {
    let field_one = AppIdField1Request { app_id: Some(480) }.encode_to_vec();
    for method in [
        BEGIN_HTTP_UPLOAD,
        BEGIN_UGC_UPLOAD,
        GET_SINGLE_FILE_INFO,
        SHARE_FILE,
        ENUMERATE_USER_FILES,
    ] {
        assert_eq!(request_app_id(method, &field_one), Some(480), "{method}");
    }

    let field_two = AppIdField2Request { app_id: Some(480) }.encode_to_vec();
    for method in [
        COMMIT_HTTP_UPLOAD,
        COMMIT_UGC_UPLOAD,
        GET_FILE_DETAILS,
        LEGACY_DELETE,
    ] {
        assert_eq!(request_app_id(method, &field_two), Some(480), "{method}");
    }

    assert_eq!(request_app_id("Cloud.GetClientEncryptionKey#1", &[]), None);
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
    assert!(method_expects_response(GET_FILE_DETAILS));
    assert!(method_expects_response(ENUMERATE_USER_FILES));
}

#[test]
fn critical_notifications_bypass_response_backpressure_without_blocking() {
    let (sender, receiver) = mpsc::sync_channel(RPC_CHANNEL_CAPACITY);
    let worker = RpcWorker {
        sender,
        outstanding_responses: Arc::new(AtomicUsize::new(0)),
    };
    let reservations = (0..RPC_QUEUE_CAPACITY)
        .map(|_| worker.try_reserve_response().unwrap())
        .collect::<Vec<_>>();
    assert!(worker.try_reserve_response().is_none());

    worker
        .sender
        .try_send(QueuedRequest {
            app_id: 480,
            method: COMPLETE_BATCH.into(),
            body: Vec::new(),
            settings: CloudSettings {
                local_path: String::new(),
                server_url: "http://127.0.0.1".into(),
                token: "token".into(),
                steam_client_id: Some(7),
                bind_device: false,
                timeout_connect_ms: 1,
                timeout_ms: 1,
            },
            response: None,
        })
        .unwrap();
    assert_eq!(receiver.try_recv().unwrap().method, COMPLETE_BATCH);
    drop(reservations);
}

#[test]
fn adapter_state_is_discarded_when_cumulus_scope_changes() {
    let mut state = AdapterState::default();
    let first = CloudSettings {
        local_path: String::new(),
        server_url: "https://cloud-a.example".into(),
        token: "token-a".into(),
        steam_client_id: Some(7),
        bind_device: false,
        timeout_connect_ms: 1,
        timeout_ms: 1,
    };
    state.prepare(&first);
    let first_scope = state.scope().clone();
    state
        .transfer_targets
        .register(&first_scope, "cdn-a.example", "/object");
    state.current_change_numbers.insert(480, 91);
    state.active_batches.insert(480, 42);
    state.batches.insert(
        42,
        BatchState {
            app_id: 480,
            upload_paths: BTreeSet::new(),
            delete_paths: BTreeSet::new(),
            files: HashMap::new(),
            conflict_resolution: None,
        },
    );

    let mut second = first.clone();
    second.server_url = "https://cloud-b.example".into();
    state.prepare(&second);

    assert!(state.current_change_numbers.is_empty());
    assert!(state.active_batches.is_empty());
    assert!(state.batches.is_empty());
    let second_scope = CloudStateScope::from_settings(&second);
    assert!(state.scope() == &second_scope);
    assert!(state
        .transfer_targets
        .contains(&first_scope, "cdn-a.example", "/object"));
    assert!(!state
        .transfer_targets
        .contains(&second_scope, "cdn-a.example", "/object"));
}

#[test]
fn response_reservation_is_held_until_the_response_is_drained() {
    let outstanding = Arc::new(AtomicUsize::new(1));
    let reservation = ResponseReservation {
        outstanding: Arc::clone(&outstanding),
    };
    let (sender, receiver) = mpsc::channel();
    let queue = CloudRpcQueue::new();
    queue.track_response(receiver, reservation);
    sender.send(vec![1, 2, 3]).unwrap();

    assert_eq!(outstanding.load(Ordering::Acquire), 1);
    assert_eq!(queue.drain_completed(), vec![vec![1, 2, 3]]);
    assert_eq!(outstanding.load(Ordering::Acquire), 0);
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

    queue.transfer_targets.register(
        &CloudStateScope::from_config(&config),
        "bucket.example",
        "/save.dat?signature=one",
    );
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
        local_path: String::new(),
        server_url,
        token: "report-token".into(),
        steam_client_id: None,
        bind_device: false,
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
fn replacing_an_upload_batch_aborts_the_previous_server_batch() {
    let (server_url, captured) = scripted_server(&[
        (
            200,
            r#"{"current_change_number":0,"app_buildid_hwm":0,"basis":"full","changed":[],"deleted":[]}"#,
        ),
        (200, r#"{"batch_id":"42","app_change_number":1}"#),
        (204, ""),
        (200, r#"{"batch_id":"43","app_change_number":1}"#),
    ]);
    let settings = CloudSettings {
        local_path: String::new(),
        server_url,
        token: "batch-token".into(),
        steam_client_id: None,
        bind_device: false,
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
        ..Default::default()
    };
    execute_rpc(&mut state, &settings, BEGIN_BATCH, &begin.encode_to_vec()).unwrap();
    execute_rpc(&mut state, &settings, BEGIN_BATCH, &begin.encode_to_vec()).unwrap();

    let lines = (0..4)
        .map(|_| {
            captured
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        lines,
        [
            "GET /api/v1/apps/480/changelist?synced_change_number=0 HTTP/1.1",
            "POST /api/v1/steam/apps/480/upload-batches HTTP/1.1",
            "DELETE /api/v1/upload-batches/42 HTTP/1.1",
            "POST /api/v1/steam/apps/480/upload-batches HTTP/1.1",
        ]
    );
    assert_eq!(state.active_batches.get(&480), Some(&43));
    assert!(!state.batches.contains_key(&42));
}

#[test]
fn conflict_results_are_reported_or_bound_to_the_next_batch() {
    let directory = tempfile::tempdir().unwrap();
    let outbox_path = directory.path().join("conflicts.db");
    let (server_url, captured) = scripted_server(&[
        (
            200,
            r#"{"current_change_number":2,"app_buildid_hwm":0,"basis":"delta","changed":[],"deleted":[]}"#,
        ),
        (200, "{}"),
        (200, r#"{"batch_id":"42","app_change_number":3}"#),
        (204, ""),
        (200, r#"{"batch_id":"43","app_change_number":3}"#),
    ]);
    let settings = CloudSettings {
        local_path: String::new(),
        server_url,
        token: "conflict-token".into(),
        steam_client_id: None,
        bind_device: false,
        timeout_connect_ms: 1000,
        timeout_ms: 2000,
    };
    let mut state = AdapterState {
        conflict_outbox_path: Some(outbox_path.clone()),
        ..Default::default()
    };
    let changelist = CloudGetAppFileChangelistRequest {
        app_id: Some(480),
        synced_change_number: Some(1),
    };
    execute_rpc(
        &mut state,
        &settings,
        GET_CHANGELIST,
        &changelist.encode_to_vec(),
    )
    .unwrap();
    let changelist_request = captured.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(changelist_request.starts_with("GET /api/v1/apps/480/changelist"));

    let kept_cloud = CloudClientConflictResolutionNotification {
        app_id: Some(480),
        chose_local_files: Some(false),
    };
    execute_rpc(
        &mut state,
        &settings,
        CONFLICT_RESOLUTION,
        &kept_cloud.encode_to_vec(),
    )
    .unwrap();
    let report = captured.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(report.starts_with("POST /api/v1/apps/480/conflicts/kept-cloud HTTP/1.1"));
    assert!(report.contains(r#""base_change_number":1"#));
    let report_body: serde_json::Value =
        serde_json::from_str(report.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let event_id = report_body["event_id"].as_str().unwrap();
    assert_eq!(event_id.len(), 36);
    assert_eq!(event_id.chars().filter(|&value| value == '-').count(), 4);

    let kept_local = CloudClientConflictResolutionNotification {
        app_id: Some(480),
        chose_local_files: Some(true),
    };
    execute_rpc(
        &mut state,
        &settings,
        CONFLICT_RESOLUTION,
        &kept_local.encode_to_vec(),
    )
    .unwrap();
    let begin = CloudBeginAppUploadBatchRequest {
        app_id: Some(480),
        machine_name: Some("deck".into()),
        ..Default::default()
    };
    execute_rpc(&mut state, &settings, BEGIN_BATCH, &begin.encode_to_vec()).unwrap();
    let begin_request = captured.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(begin_request.starts_with("POST /api/v1/steam/apps/480/upload-batches"));
    let resolution = state
        .batches
        .get(&42)
        .and_then(|batch| batch.conflict_resolution.as_ref())
        .unwrap();
    assert_eq!(resolution.base_change_number, 1);
    assert_eq!(resolution.remote_change_number, 2);
    assert_eq!(resolution.resolution, "kept_local");
    assert_eq!(
        Outbox::open(&outbox_path).unwrap().conflict_len().unwrap(),
        1,
        "binding a local choice to a batch must not remove it"
    );

    let failed = CloudCompleteAppUploadBatchRequest {
        app_id: Some(480),
        batch_id: Some(42),
        batch_eresult: None,
    };
    execute_rpc(
        &mut state,
        &settings,
        COMPLETE_BATCH,
        &failed.encode_to_vec(),
    )
    .unwrap();
    assert_eq!(
        Outbox::open(&outbox_path).unwrap().conflict_len().unwrap(),
        1,
        "an aborted batch must retain the local choice"
    );

    execute_rpc(&mut state, &settings, BEGIN_BATCH, &begin.encode_to_vec()).unwrap();
    assert!(state
        .batches
        .get(&43)
        .and_then(|batch| batch.conflict_resolution.as_ref())
        .is_some());
}

#[test]
fn unknown_ownership_declines_cumulus_but_requires_privacy_fallback() {
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

    assert_eq!(
        crate::apps::actual_ownership(app_id),
        crate::apps::OwnershipState::Unknown
    );
    assert!(!CloudRpcQueue::new().intercept(
        QUOTA_USAGE,
        &header,
        &header.encode_to_vec(),
        &request,
        &config,
    ));
    assert_eq!(
        privacy_fallback(QUOTA_USAGE, &request, &config),
        Some((app_id.0, true))
    );

    let legacy_request = AppIdField2Request {
        app_id: Some(app_id.0),
    }
    .encode_to_vec();
    assert_eq!(
        privacy_fallback(GET_FILE_DETAILS, &legacy_request, &config),
        Some((app_id.0, true))
    );
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

    let legacy_request = AppIdField1Request {
        app_id: Some(app_id.0),
    }
    .encode_to_vec();
    assert_eq!(
        privacy_fallback(GET_SINGLE_FILE_INFO, &legacy_request, &config),
        None
    );
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
        local_path: String::new(),
        server_url,
        token: "secret-token".into(),
        steam_client_id: Some(11_047_413_376_560_171_870),
        bind_device: false,
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
    assert!(
        request_text.starts_with("GET /api/v1/apps/480/changelist?synced_change_number=0 HTTP/1.1")
    );
    assert!(request_text
        .to_ascii_lowercase()
        .contains("authorization: bearer secret-token"));
    assert!(request_text
        .to_ascii_lowercase()
        .contains("x-cumulus-steam-client-id: 11047413376560171870"));
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
        local_path: String::new(),
        server_url,
        token: "cumulus-secret".into(),
        steam_client_id: None,
        bind_device: false,
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
    assert!(state.transfer_targets.contains(
        state.scope(),
        "CDN.EXAMPLE",
        "/objects/save?signature=one"
    ));

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
        local_path: String::new(),
        server_url,
        token: "lifecycle-token".into(),
        steam_client_id: Some(7),
        bind_device: false,
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
        batch_eresult: Some(super::ERESULT_OK as u32),
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
    assert!(requests.iter().all(|request| request
        .to_ascii_lowercase()
        .contains("x-cumulus-steam-client-id: 7")));
}

#[test]
fn local_folder_lifecycle_uses_in_process_transfer_targets() {
    let directory = tempfile::tempdir().unwrap();
    let settings = CloudSettings {
        local_path: directory.path().to_string_lossy().into_owned(),
        server_url: String::new(),
        token: String::new(),
        steam_client_id: Some(7),
        bind_device: false,
        timeout_connect_ms: 1,
        timeout_ms: 1,
    };
    let mut state = AdapterState::default();
    let app_id = 480;

    let changelist = CloudGetAppFileChangelistRequest {
        app_id: Some(app_id),
        synced_change_number: Some(0),
    };
    let reply = execute_rpc(
        &mut state,
        &settings,
        GET_CHANGELIST,
        &changelist.encode_to_vec(),
    )
    .unwrap();
    let response = CloudGetAppFileChangelistResponse::decode(reply.body.as_slice()).unwrap();
    assert_eq!(response.current_change_number, Some(0));
    assert!(response.files.is_empty());

    let begin = CloudBeginAppUploadBatchRequest {
        app_id: Some(app_id),
        machine_name: Some("deck".into()),
        files_to_upload: vec!["save.dat".into()],
        files_to_delete: Vec::new(),
        client_id: Some(7),
        app_build_id: Some(1),
    };
    let reply = execute_rpc(&mut state, &settings, BEGIN_BATCH, &begin.encode_to_vec()).unwrap();
    let batch = CloudBeginAppUploadBatchResponse::decode(reply.body.as_slice()).unwrap();
    let batch_id = batch.batch_id.unwrap();

    let contents = b"save";
    let declare = CloudClientBeginFileUploadRequest {
        app_id: Some(app_id),
        file_size: Some(contents.len() as u32),
        raw_file_size: Some(contents.len() as u32),
        file_sha: Some(hex_to_bytes("13a4a11319d31c1b323d5774f44240a9ffc984d0").unwrap()),
        timestamp: Some(1_700_000_000),
        filename: Some("save.dat".into()),
        platforms_to_sync: Some(u32::MAX),
        cell_id: None,
        can_encrypt: Some(false),
        is_shared_file: Some(false),
        deprecated_realm: None,
        upload_batch_id: Some(batch_id),
    };
    let reply = execute_rpc(
        &mut state,
        &settings,
        BEGIN_FILE_UPLOAD,
        &declare.encode_to_vec(),
    )
    .unwrap();
    let declared = CloudClientBeginFileUploadResponse::decode(reply.body.as_slice()).unwrap();
    let target = &declared.block_requests[0];
    let outcome = vapor_forge_cloud_local::intercept_transfer(
        target.url_host.as_deref().unwrap(),
        target.url_path.as_deref().unwrap(),
        contents,
    )
    .unwrap();
    assert!(matches!(
        outcome,
        vapor_forge_cloud_local::LocalTransferOutcome::Upload(Ok(1))
    ));

    let commit = CloudClientCommitFileUploadRequest {
        transfer_succeeded: Some(true),
        app_id: Some(app_id),
        file_sha: declare.file_sha,
        filename: Some("save.dat".into()),
    };
    let reply = execute_rpc(
        &mut state,
        &settings,
        COMMIT_FILE_UPLOAD,
        &commit.encode_to_vec(),
    )
    .unwrap();
    assert_eq!(
        CloudClientCommitFileUploadResponse::decode(reply.body.as_slice())
            .unwrap()
            .file_committed,
        Some(true)
    );
    let complete = CloudCompleteAppUploadBatchRequest {
        app_id: Some(app_id),
        batch_id: Some(batch_id),
        batch_eresult: Some(super::ERESULT_OK as u32),
    };
    execute_rpc(
        &mut state,
        &settings,
        COMPLETE_BATCH,
        &complete.encode_to_vec(),
    )
    .unwrap();

    let download = CloudClientFileDownloadRequest {
        app_id: Some(app_id),
        filename: Some("save.dat".into()),
        realm: None,
        force_proxy: None,
    };
    let reply = execute_rpc(
        &mut state,
        &settings,
        FILE_DOWNLOAD,
        &download.encode_to_vec(),
    )
    .unwrap();
    let download = CloudClientFileDownloadResponse::decode(reply.body.as_slice()).unwrap();
    let outcome = vapor_forge_cloud_local::intercept_transfer(
        download.url_host.as_deref().unwrap(),
        download.url_path.as_deref().unwrap(),
        &[],
    )
    .unwrap();
    match outcome {
        vapor_forge_cloud_local::LocalTransferOutcome::Download(result) => {
            assert_eq!(result.unwrap(), contents)
        }
        _ => panic!("expected local download"),
    }

    let begin_delete = CloudBeginAppUploadBatchRequest {
        app_id: Some(app_id),
        machine_name: Some("deck".into()),
        files_to_upload: Vec::new(),
        files_to_delete: vec!["save.dat".into()],
        client_id: Some(7),
        app_build_id: Some(1),
    };
    let reply = execute_rpc(
        &mut state,
        &settings,
        BEGIN_BATCH,
        &begin_delete.encode_to_vec(),
    )
    .unwrap();
    let delete_batch = CloudBeginAppUploadBatchResponse::decode(reply.body.as_slice())
        .unwrap()
        .batch_id
        .unwrap();
    let delete = CloudClientDeleteFileRequest {
        app_id: Some(app_id),
        filename: Some("save.dat".into()),
        is_explicit_delete: Some(true),
        upload_batch_id: Some(delete_batch),
    };
    execute_rpc(&mut state, &settings, DELETE_FILE, &delete.encode_to_vec()).unwrap();
    let complete = CloudCompleteAppUploadBatchRequest {
        app_id: Some(app_id),
        batch_id: Some(delete_batch),
        batch_eresult: Some(super::ERESULT_OK as u32),
    };
    execute_rpc(
        &mut state,
        &settings,
        COMPLETE_BATCH,
        &complete.encode_to_vec(),
    )
    .unwrap();

    let delta = CloudGetAppFileChangelistRequest {
        app_id: Some(app_id),
        synced_change_number: Some(1),
    };
    let reply = execute_rpc(
        &mut state,
        &settings,
        GET_CHANGELIST,
        &delta.encode_to_vec(),
    )
    .unwrap();
    let delta = CloudGetAppFileChangelistResponse::decode(reply.body.as_slice()).unwrap();
    assert_eq!(delta.current_change_number, Some(2));
    assert_eq!(delta.files.len(), 1);
    assert_eq!(delta.files[0].persist_state, Some(2));
}
