//! Safe business logic for manifest request code interception.
//!
//! This module handles queuing, fetching, and response fabrication for
//! `ContentServerDirectory.GetManifestRequestCode#1` RPCs, all without
//! any `unsafe` code.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use prost::Message;
use tracing::{debug, error, info, warn};
use vapor_forge_abi::{
    CMsgProtoBufHeader, GetManifestRequestCodeResponse, EMSG_SERVICE_METHOD_RESPONSE,
    K_MSG_HDR_PROTO_FLAG,
};
use vapor_forge_config::{AppId, RuntimeConfig};

pub type ManifestCodeCallback =
    Arc<dyn Fn(u32, u32, u64) -> Result<Option<u64>, String> + Send + Sync>;

pub struct ManifestCodeFetch {
    pub job_id: u64,
    pub app_id: u32,
    pub depot_id: u32,
    pub gid: u64,
    pub req_hdr_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ServiceMethod name we intercept.
pub use vapor_forge_packet_inspect::MANIFEST_REQUEST_CODE_JOB_NAME as TARGET_JOB_NAME;

/// Manifest code provider endpoints.
/// `{gid}` is replaced with the manifest ID.
pub const PROVIDERS: &[(&str, &str)] = &[
    ("opensteamtool", "https://manifest.opensteamtool.com/{gid}"),
    ("wudrm", "http://gmrc.wudrm.com/manifest/{gid}"),
    ("steamrun", "https://manifest.steam.run/api/manifest/{gid}"),
];

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
}

/// A completed manifest code fetch, ready for injection.
pub struct CompletedFetch {
    pub job_id: u64,
    pub gid: u64,
    pub code: u64,
    pub req_hdr_bytes: Vec<u8>,
}

/// Thread-safe queue of in-flight manifest code fetches.
pub struct PendingQueue {
    list: Mutex<Vec<Pending>>,
    /// Fast-path counter: if zero, callers can skip the lock entirely.
    count: AtomicUsize,
}

impl PendingQueue {
    pub fn new() -> Self {
        Self {
            list: Mutex::new(Vec::new()),
            count: AtomicUsize::new(0),
        }
    }

    /// Returns `true` if there are no pending fetches (fast atomic check).
    pub fn is_empty(&self) -> bool {
        self.count.load(Ordering::Acquire) == 0
    }

    /// Queue a new manifest code fetch. Spawns a background thread to call
    /// the external providers and stores the result for later draining.
    pub fn queue_fetch(
        &self,
        request: ManifestCodeFetch,
        config: &RuntimeConfig,
        lua_callback: Option<ManifestCodeCallback>,
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
        };

        {
            let mut list = self.list.lock().unwrap();
            if list.len() >= MAX_PENDING_FETCHES {
                warn!(
                    job_id,
                    gid, "request_code: pending queue full, passing request through"
                );
                return false;
            }
            list.push(pending);
            self.count.fetch_add(1, Ordering::Release);
        }

        let providers: Vec<String> = config.manifest.providers.clone();
        let timeout_connect_ms = config.manifest.timeout_connect_ms;
        let timeout_ms = config.manifest.timeout_ms;

        // Spawn a thread to fetch the manifest code
        let result_clone = Arc::clone(&result);
        let done_clone = Arc::clone(&done);
        let spawn_result = std::thread::Builder::new()
            .name("manifest-code-fetch".to_owned())
            .spawn(move || {
                let lua_code =
                    lua_callback.and_then(|callback| match callback(app_id, depot_id, gid) {
                        Ok(code) => code,
                        Err(error) => {
                            warn!(gid, %error, "request_code: Lua provider unavailable");
                            None
                        }
                    });
                let code = lua_code.or_else(|| {
                    fetch_manifest_code(gid, &providers, timeout_connect_ms, timeout_ms)
                });
                {
                    let mut lock = result_clone.lock().unwrap();
                    // Some(0) = failed, Some(n) = success
                    *lock = Some(code.unwrap_or(0));
                }
                done_clone.store(true, Ordering::Release);
                debug!(gid, code = ?code, "request_code: fetch complete");
            });
        if let Err(error) = spawn_result {
            let mut list = self.list.lock().unwrap();
            if let Some(index) = list
                .iter()
                .position(|pending| pending.job_id == job_id && pending.gid == gid)
            {
                list.swap_remove(index);
                self.count.fetch_sub(1, Ordering::Release);
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
                self.count.fetch_sub(1, Ordering::Release);

                let code = entry.result.lock().unwrap().unwrap_or(0);
                completed.push(CompletedFetch {
                    job_id: entry.job_id,
                    gid: entry.gid,
                    code,
                    req_hdr_bytes: entry.req_hdr_bytes,
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

/// Returns `true` if this app's request should be intercepted (dropped from
/// the outgoing wire and fetched from an external provider instead).
pub fn should_intercept(app_id: AppId, config: &RuntimeConfig) -> bool {
    crate::apps::classify_app(config, app_id).requires_injected_ownership()
}

// ---------------------------------------------------------------------------
// Response fabrication
// ---------------------------------------------------------------------------

/// Build a complete fabricated `ServiceMethodResponse` packet from parts.
///
/// Uses protobuf types from `steam-abi` and `assemble_raw` to produce the
/// final byte vector using safe code, with no raw pointers involved.
pub fn build_response_packet(req_hdr_bytes: &[u8], _job_id: u64, _gid: u64, code: u64) -> Vec<u8> {
    // Parse the original request header to copy fields
    let req_hdr = CMsgProtoBufHeader::decode(req_hdr_bytes).unwrap_or_default();

    let (eresult, transport_error, seq_num) = if code > 0 {
        (Some(1_i32), None, None) // EResult::OK
    } else {
        (Some(15_i32), Some(1_i32), Some(1_i32)) // EResult::AccessDenied
    };

    let resp_hdr = CMsgProtoBufHeader {
        steamid: req_hdr.steamid,
        jobid_source: None,
        jobid_target: req_hdr.jobid_source, // route response to the original caller
        target_job_name: req_hdr.target_job_name.clone(),
        eresult,
        transport_error,
        seq_num,
    };

    let resp_body = GetManifestRequestCodeResponse {
        manifest_request_code: if code > 0 { Some(code) } else { None },
    };

    let hdr_bytes = resp_hdr.encode_to_vec();
    let body_bytes = resp_body.encode_to_vec();
    let emsg_raw = EMSG_SERVICE_METHOD_RESPONSE | K_MSG_HDR_PROTO_FLAG;

    vapor_forge_abi::assemble_raw(emsg_raw, &hdr_bytes, &body_bytes)
}

// ---------------------------------------------------------------------------
// HTTP fetch with provider fallback
// ---------------------------------------------------------------------------

/// Fetch the manifest request code from external providers.
/// Returns `Some(code)` on success, `None` on failure.
fn fetch_manifest_code(
    gid: u64,
    providers: &[String],
    timeout_connect_ms: u64,
    timeout_ms: u64,
) -> Option<u64> {
    for provider_name in providers {
        let url_template = match provider_name.as_str() {
            "opensteamtool" => "https://manifest.opensteamtool.com/{gid}",
            "wudrm" => "http://gmrc.wudrm.com/manifest/{gid}",
            "steamrun" => "https://manifest.steam.run/api/manifest/{gid}",
            unknown => {
                warn!(
                    provider = unknown,
                    "request_code: unknown provider, skipping"
                );
                continue;
            }
        };
        let url = url_template.replace("{gid}", &gid.to_string());
        let name = provider_name.as_str();
        debug!(provider = name, url = %url, "request_code: trying provider");

        match fetch_from_provider(name, &url, timeout_connect_ms, timeout_ms) {
            Ok(code) if code > 0 => {
                info!(
                    provider = name,
                    gid, code, "request_code: manifest code obtained"
                );
                return Some(code);
            }
            Ok(_) => {
                warn!(provider = name, gid, "request_code: provider returned 0");
            }
            Err(e) => {
                warn!(provider = name, gid, error = %e, "request_code: provider failed");
            }
        }
    }

    error!(gid, "request_code: all providers failed");
    None
}

fn fetch_from_provider(
    name: &str,
    url: &str,
    timeout_connect_ms: u64,
    timeout_ms: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(std::time::Duration::from_millis(timeout_connect_ms)))
        .timeout_global(Some(std::time::Duration::from_millis(timeout_ms)))
        .build()
        .new_agent();

    let mut req = agent.get(url);

    // Per-provider User-Agent
    if name == "opensteamtool" {
        req = req.header("User-Agent", "OpenSteamTool/1.0");
    }

    let body = req.call()?.body_mut().read_to_string()?;
    let body = body.trim();

    if name == "steamrun" {
        // JSON format: {"manifest_request_code": 12345}
        parse_steamrun_json(body)
    } else {
        // Plain uint64 string
        body.parse::<u64>()
            .map_err(|e| format!("parse error: {} (body: {:?})", e, body).into())
    }
}

fn parse_steamrun_json(body: &str) -> Result<u64, Box<dyn std::error::Error>> {
    // Minimal JSON parsing avoids pulling in serde_json for one field.
    // Expected: {"manifest_request_code": 12345} or {"manifest_request_code":12345}
    let key = "\"manifest_request_code\"";
    let pos = body.find(key).ok_or("missing manifest_request_code key")?;

    let after_key = &body[pos + key.len()..];
    // Skip optional whitespace and colon
    let after_colon = after_key
        .trim_start()
        .strip_prefix(':')
        .ok_or("missing colon after key")?
        .trim_start();

    // Read digits
    let digits: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return Err("no digits after key".into());
    }

    digits
        .parse::<u64>()
        .map_err(|e| format!("parse error: {}", e).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn make_req_header(job_id: u64, method: &str) -> Vec<u8> {
        CMsgProtoBufHeader {
            steamid: Some(0x0110_0001_DEAD_BEEF),
            jobid_source: Some(job_id),
            jobid_target: None,
            target_job_name: Some(method.to_owned()),
            eresult: None,
            transport_error: None,
            seq_num: None,
        }
        .encode_to_vec()
    }

    #[test]
    fn build_response_routes_to_caller() {
        let req_hdr = make_req_header(42, TARGET_JOB_NAME);
        let packet = build_response_packet(&req_hdr, 42, 123, 99999);
        let (emsg, hdr_bytes, body_bytes) = vapor_forge_abi::unpack_raw(&packet).unwrap();
        assert_eq!(emsg, EMSG_SERVICE_METHOD_RESPONSE | K_MSG_HDR_PROTO_FLAG);

        let resp_hdr = CMsgProtoBufHeader::decode(hdr_bytes).unwrap();
        assert_eq!(resp_hdr.jobid_target, Some(42));
        assert_eq!(resp_hdr.eresult, Some(1));

        let resp_body = GetManifestRequestCodeResponse::decode(body_bytes).unwrap();
        assert_eq!(resp_body.manifest_request_code, Some(99999));
    }

    #[test]
    fn build_response_failure_returns_access_denied() {
        let req_hdr = make_req_header(7, TARGET_JOB_NAME);
        let packet = build_response_packet(&req_hdr, 7, 123, 0);
        let (_, hdr_bytes, body_bytes) = vapor_forge_abi::unpack_raw(&packet).unwrap();

        let resp_hdr = CMsgProtoBufHeader::decode(hdr_bytes).unwrap();
        assert_eq!(resp_hdr.eresult, Some(15));

        let resp_body = GetManifestRequestCodeResponse::decode(body_bytes).unwrap();
        assert_eq!(resp_body.manifest_request_code, None);
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
            &RuntimeConfig::default(),
            Some(callback),
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
                &RuntimeConfig::default(),
                Some(Arc::clone(&callback)),
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
            &RuntimeConfig::default(),
            Some(callback),
        ));
        barrier.wait();
    }

    #[test]
    fn parse_steamrun_json_valid() {
        let body = r#"{"manifest_request_code": 12345678}"#;
        assert_eq!(parse_steamrun_json(body).unwrap(), 12345678);
    }

    #[test]
    fn parse_steamrun_json_no_key() {
        assert!(parse_steamrun_json(r#"{"other": 1}"#).is_err());
    }

    #[test]
    fn parse_steamrun_json_zero() {
        let body = r#"{"manifest_request_code": 0}"#;
        assert_eq!(parse_steamrun_json(body).unwrap(), 0);
    }
}
