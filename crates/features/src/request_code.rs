//! Safe business logic for manifest request code interception.
//!
//! This module handles queuing, fetching, and response fabrication for
//! `ContentServerDirectory.GetManifestRequestCode#1` RPCs, all without
//! any `unsafe` code.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use prost::Message;
use tracing::{debug, warn};
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_steam_protocol::{
    CMsgProtoBufHeader, GetManifestRequestCodeResponse, EMSG_SERVICE_METHOD_RESPONSE,
    K_MSG_HDR_PROTO_FLAG,
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
    /// the configured script callback and stores the result for later draining.
    pub fn queue_fetch(
        &self,
        request: ManifestCodeFetch,
        callback: ManifestCodeCallback,
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
                warn!(
                    job_id,
                    gid, "request_code: pending queue full, passing request through"
                );
                return false;
            }
            list.push(pending);
        }

        let result_clone = Arc::clone(&result);
        let done_clone = Arc::clone(&done);
        let spawn_result = std::thread::Builder::new()
            .name("manifest-code-fetch".to_owned())
            .spawn(move || {
                let code = match catch_unwind(AssertUnwindSafe(|| callback(app_id, depot_id, gid)))
                {
                    Ok(Ok(code)) => code,
                    Ok(Err(error)) => {
                        warn!(gid, %error, "request_code: script provider unavailable");
                        None
                    }
                    Err(_) => {
                        warn!(gid, "request_code: script provider panicked");
                        None
                    }
                };
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

/// Returns `true` if this app requires an injected manifest request code.
pub fn should_intercept(app_id: AppId, config: &RuntimeConfig, provider_available: bool) -> bool {
    should_intercept_with_ownership(
        app_id,
        config,
        provider_available,
        crate::apps::actual_ownership,
    )
}

pub fn should_intercept_with_ownership(
    app_id: AppId,
    config: &RuntimeConfig,
    provider_available: bool,
    ownership: impl FnOnce(AppId) -> crate::apps::OwnershipState,
) -> bool {
    provider_available
        && crate::apps::classify_app_with_ownership(config, app_id, ownership)
            .requires_injected_ownership()
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
    fn build_response_failure_returns_access_denied() {
        let req_hdr = make_req_header(7, TARGET_JOB_NAME);
        let packet = build_response_packet(&req_hdr, 7, 123, 0);
        let (_, hdr_bytes, body_bytes) = vapor_forge_steam_protocol::unpack_raw(&packet).unwrap();

        let resp_hdr = CMsgProtoBufHeader::decode(hdr_bytes).unwrap();
        assert_eq!(resp_hdr.eresult, Some(15));

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
        assert!(should_intercept(AppId(480), &config, true));
        assert!(!should_intercept(AppId(480), &config, false));
        assert!(!should_intercept(AppId(999), &config, true));

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
        assert!(!should_intercept(owned_app, &owned_config, true));
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
            callback,
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
                Arc::clone(&callback),
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
            callback,
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
            callback,
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
            callback,
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
}
