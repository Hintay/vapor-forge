//! Safe business logic for manifest request code interception.
//!
//! This module handles queuing, fetching, and response fabrication for
//! `ContentServerDirectory.GetManifestRequestCode#1` RPCs, all without
//! any `unsafe` code.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use prost::Message;
use tracing::{debug, info, warn};
use vapor_forge_config::{AppId, ManifestProvider, ManifestSection, RuntimeConfig};
use vapor_forge_steam_protocol::{
    CMsgProtoBufHeader, GetManifestRequestCodeResponse, EMSG_SERVICE_METHOD_RESPONSE,
    ERESULT_NO_CONNECTION, K_MSG_HDR_PROTO_FLAG,
};

pub type ManifestCodeCallback =
    Arc<dyn Fn(u32, u32, u64) -> Result<Option<u64>, String> + Send + Sync>;

pub struct ManifestCodeFetch {
    pub job_id: u64,
    pub app_id: u32,
    pub depot_id: u32,
    pub gid: u64,
    pub req_hdr_bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum ManifestFetchError {
    Decode(prost::DecodeError),
    MissingJobId,
}

pub fn plan_fetch(
    header: &CMsgProtoBufHeader,
    header_bytes: &[u8],
    body_bytes: &[u8],
) -> Result<ManifestCodeFetch, ManifestFetchError> {
    let request = vapor_forge_steam_protocol::GetManifestRequestCodeRequest::decode(body_bytes)
        .map_err(ManifestFetchError::Decode)?;
    Ok(ManifestCodeFetch {
        job_id: header
            .jobid_source
            .filter(|job_id| *job_id != 0)
            .ok_or(ManifestFetchError::MissingJobId)?,
        app_id: request.app_id.unwrap_or(0),
        depot_id: request.depot_id.unwrap_or(0),
        gid: request.manifest_id.unwrap_or(0),
        req_hdr_bytes: header_bytes.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ServiceMethod name we intercept.
pub const TARGET_JOB_NAME: &str = vapor_forge_steam_protocol::MANIFEST_REQUEST_CODE_JOB_NAME;

const MAX_PENDING_FETCHES: usize = 16;

// ---------------------------------------------------------------------------
// Pending fetch state
// ---------------------------------------------------------------------------

struct Pending {
    job_id: u64,
    gid: u64,
    result: Arc<Mutex<Option<u64>>>,
    done: Arc<AtomicBool>,
    /// Serialized request header bytes used to fabricate the response header.
    req_hdr_bytes: Vec<u8>,
    response_generation: u64,
}

/// A completed manifest code fetch, ready for injection.
pub struct CompletedFetch {
    pub job_id: u64,
    pub gid: u64,
    pub code: u64,
    pub req_hdr_bytes: Vec<u8>,
    pub response_generation: u64,
}

/// Thread-safe queue of in-flight manifest code fetches.
pub struct PendingQueue {
    list: Mutex<Vec<Pending>>,
}

impl PendingQueue {
    pub fn new() -> Self {
        Self {
            list: Mutex::new(Vec::new()),
        }
    }

    /// Queue a new manifest code fetch. Spawns a background thread to call
    /// the configured providers and stores the result for later draining.
    pub fn queue_fetch(
        &self,
        request: ManifestCodeFetch,
        manifest: &ManifestSection,
        script_callback: Option<ManifestCodeCallback>,
        response_generation: u64,
    ) -> bool {
        let ManifestCodeFetch {
            job_id,
            app_id,
            depot_id,
            gid,
            req_hdr_bytes,
        } = request;
        let result = Arc::new(Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));

        let pending = Pending {
            job_id,
            gid,
            result: Arc::clone(&result),
            done: Arc::clone(&done),
            req_hdr_bytes,
            response_generation,
        };

        {
            let mut list = self.list.lock().unwrap();
            if list.len() >= MAX_PENDING_FETCHES {
                warn!(job_id, gid, "request_code: pending queue full");
                return false;
            }
            list.push(pending);
        }

        let result_clone = Arc::clone(&result);
        let done_clone = Arc::clone(&done);
        let providers = manifest.providers.clone();
        let timeout_connect_ms = manifest.timeout_connect_ms;
        let timeout_ms = manifest.timeout_ms;
        let spawn_result = std::thread::Builder::new()
            .name("manifest-code-fetch".to_owned())
            .spawn(move || {
                let script_code = script_callback.and_then(|callback| {
                    match catch_unwind(AssertUnwindSafe(|| callback(app_id, depot_id, gid))) {
                        Ok(Ok(code)) => code.filter(|code| *code > 0),
                        Ok(Err(error)) => {
                            warn!(gid, %error, "request_code: script provider unavailable");
                            None
                        }
                        Err(_) => {
                            warn!(gid, "request_code: script provider panicked");
                            None
                        }
                    }
                });
                let code = script_code.or_else(|| {
                    fetch_manifest_code(gid, &providers, timeout_connect_ms, timeout_ms)
                });
                {
                    let mut lock = result_clone.lock().unwrap();
                    // Some(0) = failed, Some(n) = success
                    *lock = Some(code.unwrap_or(0));
                }
                done_clone.store(true, Ordering::Release);
                debug!(gid, code = ?code, "request_code: fetch complete");
                // Dispatch the completed manifest response now instead of waiting
                // for the next inbound packet.
                crate::inject_wake::wake(crate::inject_wake::InjectionSource::Manifest);
            });
        if let Err(error) = spawn_result {
            let mut list = self.list.lock().unwrap();
            if let Some(index) = list
                .iter()
                .position(|pending| pending.job_id == job_id && pending.gid == gid)
            {
                list.swap_remove(index);
            }
            warn!(job_id, gid, %error, "request_code: failed to start fetch thread");
            return false;
        }
        true
    }

    /// Drain all completed entries from the pending list.
    pub fn drain_completed(&self) -> Vec<CompletedFetch> {
        let mut list = self.list.lock().unwrap();
        let mut completed = Vec::new();
        let mut i = 0;

        while i < list.len() {
            if list[i].done.load(Ordering::Acquire) {
                let entry = list.swap_remove(i);

                let code = entry.result.lock().unwrap().unwrap_or(0);
                completed.push(CompletedFetch {
                    job_id: entry.job_id,
                    gid: entry.gid,
                    code,
                    req_hdr_bytes: entry.req_hdr_bytes,
                    response_generation: entry.response_generation,
                });
                // Don't increment i because swap_remove moved the last element to position i.
            } else {
                i += 1;
            }
        }

        completed
    }
}

impl Default for PendingQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Interception check
// ---------------------------------------------------------------------------

/// Returns `true` if this app requires a local manifest request-code response.
pub fn should_intercept(app_id: AppId, config: &RuntimeConfig) -> bool {
    should_intercept_with_ownership(app_id, config, crate::apps::actual_ownership)
}

pub fn should_intercept_with_ownership(
    app_id: AppId,
    config: &RuntimeConfig,
    ownership: impl FnOnce(AppId) -> crate::apps::OwnershipState,
) -> bool {
    crate::apps::classify_app_with_ownership(config, app_id, ownership)
        .requires_injected_ownership()
}

// ---------------------------------------------------------------------------
// Built-in providers
// ---------------------------------------------------------------------------

const OPENSTEAMTOOL_USER_AGENT: &str = "OpenSteamTool/1.0";
const MAX_PROVIDER_RESPONSE_BYTES: u64 = 4096;

fn fetch_manifest_code(
    gid: u64,
    providers: &[ManifestProvider],
    timeout_connect_ms: u64,
    timeout_ms: u64,
) -> Option<u64> {
    for &provider in providers {
        let (name, url_template) = provider_endpoint(provider);
        let url = url_template.replace("{gid}", &gid.to_string());
        debug!(
            provider = name,
            gid, "request_code: trying built-in provider"
        );

        match fetch_from_provider(provider, &url, timeout_connect_ms, timeout_ms) {
            Ok(code) if code > 0 => {
                info!(
                    provider = name,
                    gid, code, "request_code: manifest code obtained"
                );
                return Some(code);
            }
            Ok(_) => warn!(provider = name, gid, "request_code: provider returned zero"),
            Err(error) => {
                warn!(provider = name, gid, %error, "request_code: provider failed");
            }
        }
    }

    None
}

fn provider_endpoint(provider: ManifestProvider) -> (&'static str, &'static str) {
    match provider {
        ManifestProvider::OpenSteamTool => {
            ("opensteamtool", "https://manifest.opensteamtool.com/{gid}")
        }
        ManifestProvider::Wudrm => ("wudrm", "http://gmrc.wudrm.com/manifest/{gid}"),
        ManifestProvider::SteamRun => ("steamrun", "https://manifest.steam.run/api/manifest/{gid}"),
    }
}

fn fetch_from_provider(
    provider: ManifestProvider,
    url: &str,
    timeout_connect_ms: u64,
    timeout_ms: u64,
) -> Result<u64, String> {
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(std::time::Duration::from_millis(timeout_connect_ms)))
        .timeout_global(Some(std::time::Duration::from_millis(timeout_ms)))
        .build()
        .new_agent();

    let mut request = agent.get(url);
    if provider == ManifestProvider::OpenSteamTool {
        request = request.header("User-Agent", OPENSTEAMTOOL_USER_AGENT);
    }

    let mut response = request.call().map_err(|error| error.to_string())?;
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_PROVIDER_RESPONSE_BYTES)
        .read_to_string()
        .map_err(|error| error.to_string())?;
    parse_provider_response(provider, body.trim())
}

fn parse_provider_response(provider: ManifestProvider, body: &str) -> Result<u64, String> {
    let body = body.trim();
    if provider == ManifestProvider::SteamRun {
        let value: serde_json::Value =
            serde_json::from_str(body).map_err(|error| error.to_string())?;
        return value
            .get("content")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "missing string content field".to_owned())?
            .parse::<u64>()
            .map_err(|error| error.to_string());
    }

    body.parse::<u64>().map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// Response fabrication
// ---------------------------------------------------------------------------

/// Build a complete fabricated `ServiceMethodResponse` packet from parts.
///
/// Uses protobuf types from `steam-protocol` and `assemble_raw` to produce the
/// final byte vector using safe code, with no raw pointers involved.
pub fn build_response_packet(req_hdr_bytes: &[u8], _job_id: u64, _gid: u64, code: u64) -> Vec<u8> {
    // Parse the original request header to copy fields
    let req_hdr = CMsgProtoBufHeader::decode(req_hdr_bytes).unwrap_or_default();

    let eresult = if code > 0 {
        Some(1_i32)
    } else {
        Some(ERESULT_NO_CONNECTION)
    };

    let resp_hdr = CMsgProtoBufHeader {
        steamid: req_hdr.steamid,
        jobid_source: None,
        jobid_target: req_hdr.jobid_source, // route response to the original caller
        target_job_name: req_hdr.target_job_name.clone(),
        eresult,
        transport_error: None,
        seq_num: None,
        ..Default::default()
    };

    let resp_body = GetManifestRequestCodeResponse {
        manifest_request_code: if code > 0 { Some(code) } else { None },
    };

    let hdr_bytes = resp_hdr.encode_to_vec();
    let body_bytes = resp_body.encode_to_vec();
    let emsg_raw = EMSG_SERVICE_METHOD_RESPONSE | K_MSG_HDR_PROTO_FLAG;

    vapor_forge_steam_protocol::assemble_raw(emsg_raw, &hdr_bytes, &body_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn make_req_header(job_id: u64, method: &str) -> Vec<u8> {
        CMsgProtoBufHeader {
            steamid: Some(0x0110_0001_DEAD_BEEF),
            jobid_source: Some(job_id),
            target_job_name: Some(method.to_owned()),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn script_only_manifest() -> ManifestSection {
        ManifestSection {
            providers: Vec::new(),
            ..ManifestSection::default()
        }
    }

    #[test]
    fn build_response_routes_to_caller() {
        let req_hdr = make_req_header(42, TARGET_JOB_NAME);
        let packet = build_response_packet(&req_hdr, 42, 123, 99999);
        let (emsg, hdr_bytes, body_bytes) =
            vapor_forge_steam_protocol::unpack_raw(&packet).unwrap();
        assert_eq!(emsg, EMSG_SERVICE_METHOD_RESPONSE | K_MSG_HDR_PROTO_FLAG);

        let resp_hdr = CMsgProtoBufHeader::decode(hdr_bytes).unwrap();
        assert_eq!(resp_hdr.jobid_target, Some(42));
        assert_eq!(resp_hdr.eresult, Some(1));

        let resp_body = GetManifestRequestCodeResponse::decode(body_bytes).unwrap();
        assert_eq!(resp_body.manifest_request_code, Some(99999));
    }

    #[test]
    fn build_response_failure_returns_no_connection() {
        let req_hdr = make_req_header(7, TARGET_JOB_NAME);
        let packet = build_response_packet(&req_hdr, 7, 123, 0);
        let (_, hdr_bytes, body_bytes) = vapor_forge_steam_protocol::unpack_raw(&packet).unwrap();

        let resp_hdr = CMsgProtoBufHeader::decode(hdr_bytes).unwrap();
        assert_eq!(resp_hdr.eresult, Some(ERESULT_NO_CONNECTION));
        assert_eq!(resp_hdr.transport_error, None);
        assert_eq!(resp_hdr.seq_num, None);

        let resp_body = GetManifestRequestCodeResponse::decode(body_bytes).unwrap();
        assert_eq!(resp_body.manifest_request_code, None);
    }

    #[test]
    fn fetch_plan_preserves_request_context_and_rejects_missing_jobs() {
        let header_bytes = make_req_header(42, TARGET_JOB_NAME);
        let header = CMsgProtoBufHeader::decode(header_bytes.as_slice()).unwrap();
        let body = vapor_forge_steam_protocol::GetManifestRequestCodeRequest {
            app_id: Some(480),
            depot_id: Some(481),
            manifest_id: Some(1234),
            ..Default::default()
        }
        .encode_to_vec();
        let fetch = plan_fetch(&header, &header_bytes, &body).unwrap();
        assert_eq!(fetch.job_id, 42);
        assert_eq!(fetch.app_id, 480);
        assert_eq!(fetch.depot_id, 481);
        assert_eq!(fetch.gid, 1234);
        assert_eq!(fetch.req_hdr_bytes, header_bytes);

        assert!(matches!(
            plan_fetch(&CMsgProtoBufHeader::default(), &[], &body),
            Err(ManifestFetchError::MissingJobId)
        ));
        assert!(matches!(
            plan_fetch(&header, &[], &[0xff]),
            Err(ManifestFetchError::Decode(_))
        ));
    }

    #[test]
    fn should_intercept_only_when_injected_ownership_is_required() {
        let config = RuntimeConfig {
            apps: vapor_forge_config::AppsSection {
                inject: vec![vapor_forge_config::InjectApp {
                    id: AppId(480),
                    dlc: Vec::new(),
                    ticket: Default::default(),
                    purchase_time: 0,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(should_intercept(AppId(480), &config));
        assert!(!should_intercept(AppId(999), &config));

        let without_provider = RuntimeConfig {
            manifest: script_only_manifest(),
            ..config.clone()
        };
        assert!(should_intercept(AppId(480), &without_provider));

        let owned_app = AppId(246_813_583);
        let owned_config = RuntimeConfig {
            apps: vapor_forge_config::AppsSection {
                inject: vec![vapor_forge_config::InjectApp {
                    id: owned_app,
                    dlc: Vec::new(),
                    ticket: Default::default(),
                    purchase_time: 0,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        crate::apps::record_actual_ownership(owned_app, true);
        assert!(!should_intercept(owned_app, &owned_config));
    }

    #[test]
    fn pending_queue_uses_lua_callback_with_request_context() {
        let queue = PendingQueue::new();
        let seen = Arc::new(Mutex::new(None));
        let seen_by_callback = Arc::clone(&seen);
        let callback: ManifestCodeCallback = Arc::new(move |app_id, depot_id, gid| {
            *seen_by_callback.lock().unwrap() = Some((app_id, depot_id, gid));
            Ok(Some(4444))
        });

        assert!(queue.queue_fetch(
            ManifestCodeFetch {
                job_id: 99,
                app_id: 480,
                depot_id: 481,
                gid: 1234,
                req_hdr_bytes: make_req_header(99, TARGET_JOB_NAME),
            },
            &script_only_manifest(),
            Some(callback),
            7,
        ));

        let completed = (0..100)
            .find_map(|_| {
                let completed = queue.drain_completed();
                if completed.is_empty() {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    None
                } else {
                    Some(completed)
                }
            })
            .expect("Lua callback did not complete");
        assert_eq!(*seen.lock().unwrap(), Some((480, 481, 1234)));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].code, 4444);
    }

    #[test]
    fn pending_queue_rejects_overload() {
        let queue = PendingQueue::new();
        let barrier = Arc::new(std::sync::Barrier::new(MAX_PENDING_FETCHES + 1));
        let callback: ManifestCodeCallback = {
            let barrier = Arc::clone(&barrier);
            Arc::new(move |_, _, _| {
                barrier.wait();
                Ok(Some(1))
            })
        };

        for job_id in 0..MAX_PENDING_FETCHES as u64 {
            assert!(queue.queue_fetch(
                ManifestCodeFetch {
                    job_id: job_id + 1,
                    app_id: 480,
                    depot_id: 481,
                    gid: job_id + 100,
                    req_hdr_bytes: Vec::new(),
                },
                &script_only_manifest(),
                Some(Arc::clone(&callback)),
                7,
            ));
        }
        assert!(!queue.queue_fetch(
            ManifestCodeFetch {
                job_id: 99,
                app_id: 480,
                depot_id: 481,
                gid: 999,
                req_hdr_bytes: Vec::new(),
            },
            &script_only_manifest(),
            Some(callback),
            7,
        ));
        barrier.wait();
    }

    #[test]
    fn pending_queue_completes_provider_failure() {
        let queue = PendingQueue::new();
        let callback: ManifestCodeCallback = Arc::new(|_, _, _| Err("unavailable".to_owned()));
        assert!(queue.queue_fetch(
            ManifestCodeFetch {
                job_id: 99,
                app_id: 480,
                depot_id: 481,
                gid: 1234,
                req_hdr_bytes: make_req_header(99, TARGET_JOB_NAME),
            },
            &script_only_manifest(),
            Some(callback),
            7,
        ));

        let completed = (0..100)
            .find_map(|_| {
                let completed = queue.drain_completed();
                if completed.is_empty() {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    None
                } else {
                    Some(completed)
                }
            })
            .expect("provider failure did not complete");
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].job_id, 99);
        assert_eq!(completed[0].code, 0);
    }

    #[test]
    fn pending_queue_completes_provider_panic() {
        let queue = PendingQueue::new();
        let callback: ManifestCodeCallback = Arc::new(|_, _, _| panic!("provider panic"));
        assert!(queue.queue_fetch(
            ManifestCodeFetch {
                job_id: 99,
                app_id: 480,
                depot_id: 481,
                gid: 1234,
                req_hdr_bytes: make_req_header(99, TARGET_JOB_NAME),
            },
            &script_only_manifest(),
            Some(callback),
            7,
        ));

        let completed = (0..100)
            .find_map(|_| {
                let completed = queue.drain_completed();
                if completed.is_empty() {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    None
                } else {
                    Some(completed)
                }
            })
            .expect("provider panic did not complete");
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].job_id, 99);
        assert_eq!(completed[0].code, 0);
    }

    #[test]
    fn parses_built_in_provider_responses() {
        assert_eq!(
            parse_provider_response(ManifestProvider::OpenSteamTool, "123456").unwrap(),
            123456
        );
        assert_eq!(
            parse_provider_response(ManifestProvider::Wudrm, " 654321 ").unwrap(),
            654321
        );
        assert_eq!(
            parse_provider_response(ManifestProvider::SteamRun, r#"{"content":"9999999999"}"#,)
                .unwrap(),
            9_999_999_999
        );
        assert!(parse_provider_response(ManifestProvider::SteamRun, r#"{"other":"1"}"#).is_err());
    }
}
