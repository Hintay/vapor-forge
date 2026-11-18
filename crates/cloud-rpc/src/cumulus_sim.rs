//! Two-device save sync simulation against a running Cumulus server.
//!
//! These tests drive the Cloud RPC adapter exactly as Steam does (changelist,
//! begin batch, declare files, upload blocks to the returned transfer target,
//! finalize, complete, download) and assert the outcomes against a real
//! server. They are ignored by default; `scripts/cumulus-sim.sh` starts a
//! throwaway server and runs them with:
//!
//! - `CUMULUS_SIM_URL`: server origin, for example `http://127.0.0.1:18080`
//! - `CUMULUS_SIM_ADMIN_USER` / `CUMULUS_SIM_ADMIN_PASSWORD`: an administrator
//!   used to provision an isolated user and device keys for each test

use super::adapter::*;
use super::http::*;
use super::transfer_targets::*;
use super::*;
use prost::Message;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vapor_forge_cloud_core::DeviceDescriptor;
use vapor_forge_cloud_cumulus::CumulusSettings;
use vapor_forge_config::CloudBackendMode;
use vapor_forge_steam_protocol::*;

const APP_ID: u32 = 480;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the simulation"))
}

fn unique() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // Keep ids well inside the signed 53-bit range so every layer stores them.
    (nanos % 1_000_000_000_000) * 100 + COUNTER.fetch_add(1, Ordering::Relaxed) % 100 + 1
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .http_status_as_error(false)
        .build()
        .new_agent()
}

fn read_json(mut response: ureq::http::Response<ureq::Body>, what: &str) -> Value {
    let status = response.status().as_u16();
    let body = response.body_mut().read_to_string().unwrap_or_default();
    assert!(
        (200..300).contains(&status),
        "{what} failed with HTTP {status}: {body}"
    );
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body).unwrap()
    }
}

/// Administrator session used only for provisioning and for inspecting server
/// state that devices cannot read.
struct Admin {
    url: String,
    agent: ureq::Agent,
    cookie: String,
}

impl Admin {
    fn login() -> Self {
        let url = env("CUMULUS_SIM_URL");
        let agent = agent();
        let response = agent
            .post(&format!("{url}/admin/api/login"))
            .header("Content-Type", "application/json")
            .send(
                serde_json::to_vec(&json!({
                    "username": env("CUMULUS_SIM_ADMIN_USER"),
                    "password": env("CUMULUS_SIM_ADMIN_PASSWORD"),
                }))
                .unwrap()
                .as_slice(),
            )
            .unwrap();
        let cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("cml_session="))
            .and_then(|value| value.split(';').next())
            .expect("admin login sets a session cookie")
            .to_string();
        read_json(response, "admin login");
        Self { url, agent, cookie }
    }

    fn send(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let url = format!("{}{path}", self.url);
        let response = match (method, body) {
            ("GET", _) => self.agent.get(&url).header("Cookie", &self.cookie).call(),
            ("DELETE", _) => self
                .agent
                .delete(&url)
                .header("Cookie", &self.cookie)
                .call(),
            ("POST", body) => self
                .agent
                .post(&url)
                .header("Cookie", &self.cookie)
                .header("Content-Type", "application/json")
                .send(
                    serde_json::to_vec(&body.unwrap_or(Value::Null))
                        .unwrap()
                        .as_slice(),
                ),
            _ => unreachable!(),
        }
        .unwrap();
        read_json(response, &format!("{method} {path}"))
    }

    /// Create an isolated user and return its id.
    fn create_user(&self, label: &str) -> i64 {
        let name = format!("sim-{label}-{}", unique());
        self.send(
            "POST",
            "/admin/api/users",
            Some(json!({
                "name": name,
                "email": format!("{name}@example.test"),
                "password": "SimPassphrase!2026-member",
            })),
        )["id"]
            .as_i64()
            .unwrap()
    }

    fn create_token(&self, user_id: i64) -> String {
        self.send(
            "POST",
            &format!("/admin/api/users/{user_id}/tokens"),
            Some(json!({ "label": "simulation" })),
        )["token"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

/// One simulated Steam client: its own adapter state, credential and ClientID.
struct Device {
    settings: CloudSettings,
    state: AdapterState,
    _journal_dir: Option<tempfile::TempDir>,
}

impl Device {
    fn new(token: String, client_id: u64, steam_id64: u64, with_journal: bool) -> Self {
        let server_url = env("CUMULUS_SIM_URL");
        let settings = CloudSettings {
            backend: CloudBackendMode::Cumulus,
            local_path: String::new(),
            syncthing: None,
            server_url: server_url.clone(),
            token: token.clone(),
            steam_client_id: Some(client_id),
            steam_machine_name: Some(format!("sim-{client_id}")),
            steam_id64: Some(steam_id64),
            bind_device: false,
            timeout_connect_ms: 5_000,
            timeout_ms: 20_000,
        };
        // The adapter binds through the process-wide device descriptor, which a
        // test process cannot hold for two devices at once, so bind directly.
        vapor_forge_cloud_cumulus::ensure_device_bound(
            &CumulusSettings {
                server_url,
                token,
                timeout_connect_ms: 5_000,
                timeout_ms: 20_000,
            },
            &DeviceDescriptor {
                client_id,
                machine_name: format!("sim-{client_id}"),
                os_type: None,
                device_type: None,
            },
        )
        .expect("device binds");
        let (journal_dir, journal) = if with_journal {
            let dir = tempfile::tempdir().unwrap();
            let journal = vapor_forge_sync_journal::shared(&dir.path().join("journal")).unwrap();
            (Some(dir), Some(journal))
        } else {
            (None, None)
        };
        let state = AdapterState::with_transfer_targets_and_journal(
            Arc::new(TransferTargetRegistry::default()),
            journal,
        );
        Self {
            settings,
            state,
            _journal_dir: journal_dir,
        }
    }

    fn rpc<R: Message + Default>(&mut self, method: &str, request: &impl Message) -> R {
        let reply = execute_rpc(
            &mut self.state,
            &self.settings,
            method,
            &request.encode_to_vec(),
        )
        .unwrap_or_else(|error| panic!("{method} failed: {error}"));
        R::decode(reply.body.as_slice()).unwrap()
    }

    fn changelist(&mut self, synced: u64) -> Changelist {
        let response: CloudGetAppFileChangelistResponse = self.rpc(
            GET_CHANGELIST,
            &CloudGetAppFileChangelistRequest {
                app_id: Some(APP_ID),
                synced_change_number: Some(synced),
            },
        );
        let files = response
            .files
            .iter()
            .map(|file| {
                let prefix = response
                    .path_prefixes
                    .get(file.path_prefix_index.unwrap_or(0) as usize)
                    .cloned()
                    .unwrap_or_default();
                (
                    format!("{prefix}{}", file.file_name.as_deref().unwrap()),
                    file.persist_state.unwrap_or_default(),
                )
            })
            .collect();
        Changelist {
            current: response.current_change_number.unwrap(),
            delta: response.is_only_delta.unwrap_or(false),
            files,
        }
    }

    /// Begin a batch, declare and upload every file, finalize each one and
    /// return the batch id. The batch is not completed.
    fn stage_batch(&mut self, files: &[(&str, &[u8])]) -> u64 {
        let begin: CloudBeginAppUploadBatchResponse = self.rpc(
            BEGIN_BATCH,
            &CloudBeginAppUploadBatchRequest {
                app_id: Some(APP_ID),
                machine_name: self.settings.steam_machine_name.clone(),
                files_to_upload: files.iter().map(|(path, _)| path.to_string()).collect(),
                files_to_delete: Vec::new(),
                client_id: self.settings.steam_client_id,
                app_build_id: Some(1),
            },
        );
        let batch_id = begin.batch_id.unwrap();
        for (path, content) in files {
            let sha = Sha1::digest(content).to_vec();
            let declared: CloudClientBeginFileUploadResponse = self.rpc(
                BEGIN_FILE_UPLOAD,
                &CloudClientBeginFileUploadRequest {
                    app_id: Some(APP_ID),
                    file_size: Some(content.len() as u32),
                    raw_file_size: Some(content.len() as u32),
                    file_sha: Some(sha.clone()),
                    timestamp: Some(1_700_000_000),
                    filename: Some(path.to_string()),
                    platforms_to_sync: Some(u32::MAX),
                    cell_id: None,
                    can_encrypt: Some(false),
                    is_shared_file: Some(false),
                    deprecated_realm: None,
                    upload_batch_id: Some(batch_id),
                },
            );
            assert!(!declared.block_requests.is_empty());
            for block in &declared.block_requests {
                let offset = block.block_offset.unwrap() as usize;
                let length = block.block_length.unwrap() as usize;
                put_block(block, &content[offset..offset + length]);
            }
            let committed: CloudClientCommitFileUploadResponse = self.rpc(
                COMMIT_FILE_UPLOAD,
                &CloudClientCommitFileUploadRequest {
                    transfer_succeeded: Some(true),
                    app_id: Some(APP_ID),
                    file_sha: Some(sha),
                    filename: Some(path.to_string()),
                },
            );
            assert_eq!(committed.file_committed, Some(true));
        }
        batch_id
    }

    fn complete_batch(&mut self, batch_id: u64) -> u64 {
        let _: CloudCompleteAppUploadBatchResponse = self.rpc(
            COMPLETE_BATCH,
            &CloudCompleteAppUploadBatchRequest {
                app_id: Some(APP_ID),
                batch_id: Some(batch_id),
                batch_eresult: Some(super::ERESULT_OK as u32),
            },
        );
        self.state.current_change_numbers[&APP_ID]
    }

    /// Steam always asks for the changelist before it uploads.
    fn upload(&mut self, synced: u64, files: &[(&str, &[u8])]) -> u64 {
        self.changelist(synced);
        let batch_id = self.stage_batch(files);
        self.complete_batch(batch_id)
    }

    fn download(&mut self, path: &str) -> Vec<u8> {
        let response: CloudClientFileDownloadResponse = self.rpc(
            FILE_DOWNLOAD,
            &CloudClientFileDownloadRequest {
                app_id: Some(APP_ID),
                filename: Some(path.to_string()),
                realm: None,
                force_proxy: None,
            },
        );
        let scheme = if response.use_https == Some(true) {
            "https"
        } else {
            "http"
        };
        let url = format!(
            "{scheme}://{}{}",
            response.url_host.unwrap(),
            response.url_path.unwrap()
        );
        let mut request = agent().get(&url);
        for header in &response.request_headers {
            request = request.header(
                header.name.as_deref().unwrap(),
                header.value.as_deref().unwrap(),
            );
        }
        let mut reply = request.call().unwrap();
        assert_eq!(reply.status().as_u16(), 200, "download of {path}");
        let body = reply.body_mut().read_to_vec().unwrap();
        assert_eq!(
            Sha1::digest(&body).to_vec(),
            response.sha_file.unwrap(),
            "downloaded bytes match the advertised SHA-1"
        );
        body
    }

    /// GET a device API path with this device's credential.
    fn get(&self, path: &str) -> Value {
        let response = agent()
            .get(&format!("{}{path}", self.settings.server_url))
            .header("Authorization", &format!("Bearer {}", self.settings.token))
            .header(
                vapor_forge_cloud_cumulus::STEAM_CLIENT_ID_HEADER,
                &self.settings.steam_client_id.unwrap().to_string(),
            )
            .call()
            .unwrap();
        read_json(response, path)
    }

    /// POST a device API path with this device's credential, returning the
    /// status and the decoded body.
    fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        let mut response = agent()
            .post(&format!("{}{path}", self.settings.server_url))
            .header("Authorization", &format!("Bearer {}", self.settings.token))
            .header(
                vapor_forge_cloud_cumulus::STEAM_CLIENT_ID_HEADER,
                &self.settings.steam_client_id.unwrap().to_string(),
            )
            .header("Content-Type", "application/json")
            .send(serde_json::to_vec(body).unwrap().as_slice())
            .unwrap();
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    fn version_numbers(&self) -> Vec<i64> {
        let mut numbers = self
            .get(&format!("/api/v1/apps/{APP_ID}/versions"))
            .as_array()
            .unwrap()
            .iter()
            .map(|version| version["change_number"].as_i64().unwrap())
            .collect::<Vec<_>>();
        numbers.sort_unstable();
        numbers
    }
}

#[derive(Debug)]
struct Changelist {
    current: u64,
    delta: bool,
    /// Full path to Steam persist state (0 = present, 2 = deleted).
    files: BTreeMap<String, i32>,
}

fn put_block(block: &CloudFileUploadBlockDetails, body: &[u8]) {
    assert_eq!(block.http_method, Some(HTTP_METHOD_PUT));
    let scheme = if block.use_https == Some(true) {
        "https"
    } else {
        "http"
    };
    let url = format!(
        "{scheme}://{}{}",
        block.url_host.as_deref().unwrap(),
        block.url_path.as_deref().unwrap()
    );
    let mut request = agent().put(&url);
    for header in &block.request_headers {
        request = request.header(
            header.name.as_deref().unwrap(),
            header.value.as_deref().unwrap(),
        );
    }
    let mut response = request.send(body).unwrap();
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    assert!(
        (200..300).contains(&status),
        "block upload failed with HTTP {status}: {text}"
    );
}

/// One user with two Steam devices on the same Steam account.
fn two_devices(label: &str, b_journal: bool) -> (Admin, i64, Device, Device) {
    let admin = Admin::login();
    let user_id = admin.create_user(label);
    let steam_id64 = 76_561_197_960_265_728 + unique() % 1_000_000_000;
    let a = Device::new(admin.create_token(user_id), unique(), steam_id64, false);
    let b = Device::new(admin.create_token(user_id), unique(), steam_id64, b_journal);
    (admin, user_id, a, b)
}

#[test]
#[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
fn cumulus_sim_1_delta_lists_only_changed_files() {
    let (_admin, _, mut a, mut b) = two_devices("delta", false);

    let n1 = a.upload(0, &[("a.dat", b"v1"), ("b.dat", b"same")]);
    let full = b.changelist(0);
    assert_eq!(full.current, n1);
    assert!(!full.delta, "first sync is a full listing");
    assert_eq!(
        full.files.keys().cloned().collect::<Vec<_>>(),
        ["a.dat", "b.dat"]
    );
    assert_eq!(b.download("a.dat"), b"v1");
    assert_eq!(b.download("b.dat"), b"same");

    // Steam uploads only the file that changed; b.dat is carried over.
    let n2 = a.upload(n1, &[("a.dat", b"v2")]);
    assert_eq!(n2, n1 + 1);
    let delta = b.changelist(n1);
    println!("scenario 1: n1={n1} n2={n2} delta={delta:?}");
    assert_eq!(delta.current, n2);
    assert!(delta.delta, "a retained base yields a delta");
    assert_eq!(delta.files, BTreeMap::from([("a.dat".to_string(), 0)]));
    assert_eq!(b.download("a.dat"), b"v2");

    // Re-declaring the unchanged file with identical content and metadata in
    // a later batch must not surface it either.
    let n3 = a.upload(n2, &[("a.dat", b"v3"), ("b.dat", b"same")]);
    let delta = b.changelist(n2);
    println!("scenario 1b: n3={n3} delta={delta:?}");
    assert_eq!(delta.current, n3);
    assert_eq!(delta.files, BTreeMap::from([("a.dat".to_string(), 0)]));
}

#[test]
#[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
fn cumulus_sim_2_lost_commit_response_replays_the_change_number() {
    let (_admin, _, mut a, _) = two_devices("replay", false);
    let n1 = a.upload(0, &[("save.dat", b"one")]);

    a.changelist(n1);
    let batch_id = a.stage_batch(&[("save.dat", b"two")]);
    // The commit reaches the server but Steam never sees the response.
    let (status, first) = a.post(
        &format!("/api/v1/upload-batches/{batch_id}/commit"),
        &json!({ "conflict_resolution": null }),
    );
    assert_eq!(status, 200, "{first}");
    let first = first["change_number"].as_u64().unwrap();
    let versions_after_first = a.version_numbers();

    // Steam retries CompleteAppUploadBatch for the same batch.
    let replayed = a.complete_batch(batch_id);
    let versions_after_replay = a.version_numbers();
    println!("scenario 2: first={first} replayed={replayed} versions={versions_after_replay:?}");
    assert_eq!(first, n1 + 1);
    assert_eq!(replayed, first);
    assert_eq!(versions_after_first, versions_after_replay);
    assert_eq!(versions_after_replay.last().copied(), Some(first as i64));
}

#[test]
#[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
fn cumulus_sim_3_device_ahead_of_server_gets_a_full_listing() {
    let (_admin, _, mut a, mut b) = two_devices("ahead", false);
    let n1 = a.upload(0, &[("save.dat", b"one")]);

    let ahead = b.changelist(n1 + 50);
    println!("scenario 3: n1={n1} ahead={ahead:?}");
    assert_eq!(ahead.current, n1);
    assert!(!ahead.delta, "a device ahead of the server gets basis full");
    assert_eq!(ahead.files, BTreeMap::from([("save.dat".to_string(), 0)]));
}

#[test]
#[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
fn cumulus_sim_4_app_deletion_keeps_the_change_floor() {
    let (admin, user_id, mut a, mut b) = two_devices("delete", false);
    let n1 = a.upload(0, &[("save.dat", b"one")]);
    let n2 = a.upload(n1, &[("save.dat", b"two")]);
    let synced = b.changelist(0);
    assert_eq!(synced.current, n2);

    admin.send(
        "DELETE",
        &format!("/admin/api/users/{user_id}/apps/{APP_ID}"),
        None,
    );

    let after = b.changelist(n2);
    println!("scenario 4: n2={n2} after_delete={after:?}");
    assert_eq!(
        after.current, n2,
        "the change number floor survives deletion"
    );
    assert!(after.delta, "a device at the floor gets an empty delta");
    assert!(after.files.is_empty());

    // The next upload is based on the floor and continues the numbering.
    let batch_id = b.stage_batch(&[("save.dat", b"local")]);
    let n3 = b.complete_batch(batch_id);
    println!("scenario 4: upload after delete -> {n3}");
    assert_eq!(n3, n2 + 1);
    assert_eq!(b.download("save.dat"), b"local");
}

#[test]
#[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
fn cumulus_sim_5_kept_cloud_records_the_version_the_user_kept() {
    let (admin, user_id, mut a, mut b) = two_devices("conflict", true);
    let n1 = a.upload(0, &[("save.dat", b"one")]);
    assert_eq!(b.changelist(0).current, n1);

    // A uploads while B also changed the save locally.
    let n2 = a.upload(n1, &[("save.dat", b"two")]);
    let seen = b.changelist(n1);
    assert_eq!(seen.current, n2);

    // Another version lands before B's choice is reported.
    let n3 = a.upload(n2, &[("save.dat", b"three")]);
    assert_eq!(n3, n2 + 1);

    // Steam on B shows the conflict dialog and the user keeps the cloud files
    // it was shown, which are version n2.
    let reply = execute_rpc(
        &mut b.state,
        &b.settings,
        CONFLICT_RESOLUTION,
        &CloudClientConflictResolutionNotification {
            app_id: Some(APP_ID),
            chose_local_files: Some(false),
        }
        .encode_to_vec(),
    )
    .unwrap();
    assert!(reply.body.is_empty());

    let conflicts = admin.send(
        "GET",
        &format!("/admin/api/users/{user_id}/conflicts"),
        None,
    );
    println!("scenario 5: n1={n1} n2={n2} n3={n3} conflicts={conflicts}");
    let items = conflicts["items"]
        .as_array()
        .or_else(|| conflicts.as_array())
        .expect("conflict page lists items");
    assert_eq!(items.len(), 1, "exactly one conflict recorded: {conflicts}");
    let conflict = &items[0];
    assert_eq!(conflict["resolution"], "kept_cloud");
    assert_eq!(conflict["base_change_number"].as_u64(), Some(n1));
    assert_eq!(
        conflict["resulting_change_number"].as_u64(),
        Some(n2),
        "the recorded result is the version the user kept, not the newest"
    );
}
