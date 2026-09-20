//! Safe business logic for manifest request code interception.
//!
//! This module handles queuing, fetching, and response fabrication for
//! `ContentServerDirectory.GetManifestRequestCode#1` RPCs, all without
//! any `unsafe` code.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use prost::Message;
use tracing::{debug, info, warn};
use vapor_forge_config::{
    AppId, ManifestResponseFormat, ManifestSection, ManifestSource, RuntimeConfig,
};
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
        let min_interval_ms = manifest.min_interval_ms;
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
                    fetch_manifest_code(
                        FetchContext {
                            app_id,
                            depot_id,
                            gid,
                        },
                        &providers,
                        timeout_connect_ms,
                        timeout_ms,
                        min_interval_ms,
                    )
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

const MAX_PROVIDER_RESPONSE_BYTES: u64 = 4096;

/// Cooldown applied when a provider answers 429 without a usable `Retry-After`.
const DEFAULT_RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(60);
/// Ceiling on any cooldown, so one absurd `Retry-After` cannot park a provider
/// for the rest of the Steam session.
const MAX_RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(300);
/// Applied when a provider itself is unhealthy (transport error, 5xx, a
/// Cloudflare block). Steam asks for one code per depot, so without this a
/// dead source costs a wasted round trip on every single gid.
const FAILURE_COOLDOWN: Duration = Duration::from_secs(60);

/// Instants before which a rate-limited provider must not be contacted again.
///
/// Steam resolves several depot manifests back to back. Without this, one 429
/// would be re-earned on every following gid: a wasted round trip each time,
/// and more load on a provider that just asked us to back off.
static PROVIDER_COOLDOWNS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn provider_cooldowns() -> &'static Mutex<HashMap<String, Instant>> {
    PROVIDER_COOLDOWNS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// When each provider was last contacted, for the self-imposed pacing.
static PROVIDER_LAST_REQUEST: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn provider_last_request() -> &'static Mutex<HashMap<String, Instant>> {
    PROVIDER_LAST_REQUEST.get_or_init(|| Mutex::new(HashMap::new()))
}

/// What one manifest code request is for. `{depotId}` / `{appId}` providers
/// need more than the gid.
#[derive(Clone, Copy, Debug)]
struct FetchContext {
    app_id: u32,
    depot_id: u32,
    gid: u64,
}

/// How long to wait before the next request to `name` may go out, reserving
/// the slot when the wait is zero.
///
/// Returning the wait instead of sleeping keeps the lock out of the sleep and
/// keeps this testable.
fn reserve_slot_in(
    last: &mut HashMap<String, Instant>,
    name: &str,
    now: Instant,
    min_interval: Duration,
) -> Option<Duration> {
    match last.get(name) {
        Some(&previous) => {
            let elapsed = now.saturating_duration_since(previous);
            if elapsed < min_interval {
                return Some(min_interval - elapsed);
            }
            last.insert(name.to_owned(), now);
            None
        }
        None => {
            last.insert(name.to_owned(), now);
            None
        }
    }
}

/// Block until this provider may be contacted again.
fn wait_for_slot(name: &str, min_interval: Duration) {
    if min_interval.is_zero() {
        return;
    }
    loop {
        let wait = {
            let mut last = provider_last_request()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            reserve_slot_in(&mut last, name, Instant::now(), min_interval)
        };
        match wait {
            Some(wait) => std::thread::sleep(wait),
            None => return,
        }
    }
}

/// Outcome of one provider attempt. 429 is kept distinct from ordinary failure
/// so the caller can park the provider instead of just moving to the next one.
#[derive(Debug)]
enum ProviderOutcome {
    Code(u64),
    RateLimited(Duration),
    /// The provider is answering, but not for this target — a pool that holds
    /// no licence for the app says so per request (20770407 replies 401
    /// `Unauthorized`). Nothing is wrong with the source, so it must NOT be
    /// put on cooldown: the next gid may well be one it can serve.
    Denied(u16),
    /// The provider itself is unhealthy; put it on cooldown.
    Failed(String),
}

/// Remaining cooldown for `provider`, clearing the entry once it has expired.
fn cooldown_remaining_in(
    cooldowns: &mut HashMap<String, Instant>,
    name: &str,
    now: Instant,
) -> Option<Duration> {
    let until = *cooldowns.get(name)?;
    if until > now {
        Some(until - now)
    } else {
        cooldowns.remove(name);
        None
    }
}

fn start_cooldown_in(
    cooldowns: &mut HashMap<String, Instant>,
    name: &str,
    now: Instant,
    retry_after: Duration,
) -> Duration {
    let capped = retry_after.min(MAX_RATE_LIMIT_COOLDOWN);
    cooldowns.insert(name.to_owned(), now + capped);
    capped
}

fn cooldown_remaining(name: &str) -> Option<Duration> {
    let mut cooldowns = provider_cooldowns()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    cooldown_remaining_in(&mut cooldowns, name, Instant::now())
}

fn start_cooldown(name: &str, retry_after: Duration) -> Duration {
    let mut cooldowns = provider_cooldowns()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    start_cooldown_in(&mut cooldowns, name, Instant::now(), retry_after)
}

/// `Retry-After` in its delta-seconds form. The HTTP-date form is not accepted:
/// ManifestDeX documents seconds, and anything unparsable falls back to
/// [`DEFAULT_RATE_LIMIT_COOLDOWN`] rather than being treated as "retry now".
fn parse_retry_after(value: Option<&str>) -> Option<Duration> {
    let seconds = value?.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds))
}

fn fetch_manifest_code(
    context: FetchContext,
    providers: &[ManifestSource],
    timeout_connect_ms: u64,
    timeout_ms: u64,
    min_interval_ms: u64,
) -> Option<u64> {
    let FetchContext {
        app_id,
        depot_id,
        gid,
    } = context;

    for provider in providers {
        let name = provider.name();

        // A user-defined entry can be malformed; skip it and keep the rest of
        // the chain working rather than failing the whole fetch.
        if let Some(rejection) = provider.rejection() {
            warn!(gid, %rejection, "request_code: skipping unusable provider");
            continue;
        }

        if let Some(remaining) = cooldown_remaining(name) {
            debug!(
                provider = name,
                gid,
                remaining_ms = remaining.as_millis() as u64,
                "request_code: provider rate limited, skipping"
            );
            continue;
        }

        let url = provider.resolve_url(app_id, depot_id, gid);
        debug!(
            provider = name,
            gid, depot_id, "request_code: trying provider"
        );

        // Pace before the request, not after a 429: these are small shared
        // services and the cooldown only reacts once the damage is done.
        wait_for_slot(name, provider.min_interval(min_interval_ms));

        match fetch_from_provider(provider, &url, timeout_connect_ms, timeout_ms) {
            ProviderOutcome::Code(code) if code > 0 => {
                info!(
                    provider = name,
                    gid, code, "request_code: manifest code obtained"
                );
                return Some(code);
            }
            ProviderOutcome::Code(_) => {
                warn!(provider = name, gid, "request_code: provider returned zero")
            }
            ProviderOutcome::RateLimited(retry_after) => {
                let cooldown = start_cooldown(name, retry_after);
                warn!(
                    provider = name,
                    gid,
                    cooldown_ms = cooldown.as_millis() as u64,
                    "request_code: provider rate limited, backing off"
                );
            }
            ProviderOutcome::Denied(status) => {
                // Per-target answer, not a provider fault: no cooldown.
                debug!(
                    provider = name,
                    gid, depot_id, status, "request_code: provider does not have this manifest"
                );
            }
            ProviderOutcome::Failed(error) => {
                let cooldown = start_cooldown(name, FAILURE_COOLDOWN);
                warn!(
                    provider = name,
                    gid,
                    %error,
                    cooldown_ms = cooldown.as_millis() as u64,
                    "request_code: provider failed, backing off"
                );
            }
        }
    }

    None
}

fn fetch_from_provider(
    provider: &ManifestSource,
    url: &str,
    timeout_connect_ms: u64,
    timeout_ms: u64,
) -> ProviderOutcome {
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_millis(timeout_connect_ms)))
        .timeout_global(Some(Duration::from_millis(timeout_ms)))
        // Keep non-2xx as a response so 429 can be told apart from a transport
        // failure and its Retry-After header read.
        .http_status_as_error(false)
        .build()
        .new_agent();

    let mut request = agent.get(url);
    if let Some(user_agent) = provider.user_agent() {
        request = request.header("User-Agent", user_agent);
    }

    let mut response = match request.call() {
        Ok(response) => response,
        Err(error) => return ProviderOutcome::Failed(error.to_string()),
    };

    let status = response.status();
    if status.as_u16() == 429 {
        let retry_after = parse_retry_after(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
        )
        .unwrap_or(DEFAULT_RATE_LIMIT_COOLDOWN);
        return ProviderOutcome::RateLimited(retry_after);
    }
    // 401/404 mean "not this manifest", not "this source is broken". Everything
    // else non-2xx — including 403, which here is a Cloudflare block rather than
    // a per-target refusal — is treated as the provider being unhealthy.
    if matches!(status.as_u16(), 401 | 404) {
        return ProviderOutcome::Denied(status.as_u16());
    }
    if !status.is_success() {
        return ProviderOutcome::Failed(format!("http status {}", status.as_u16()));
    }

    let body = match response
        .body_mut()
        .with_config()
        .limit(MAX_PROVIDER_RESPONSE_BYTES)
        .read_to_string()
    {
        Ok(body) => body,
        Err(error) => return ProviderOutcome::Failed(error.to_string()),
    };

    match parse_provider_response(provider, body.trim()) {
        Ok(code) => ProviderOutcome::Code(code),
        Err(error) => ProviderOutcome::Failed(error),
    }
}

fn parse_provider_response(provider: &ManifestSource, body: &str) -> Result<u64, String> {
    let body = body.trim();
    if provider.response_format() == ManifestResponseFormat::Json {
        let field = provider
            .json_field()
            .ok_or_else(|| "json provider has no json_field".to_owned())?;
        let value: serde_json::Value =
            serde_json::from_str(body).map_err(|error| error.to_string())?;
        let found = value
            .get(field)
            .ok_or_else(|| format!("missing {field} field"))?;
        // Accept both `{"content":"123"}` and `{"content":123}`: a custom
        // endpoint's shape is not ours to dictate.
        return match found {
            serde_json::Value::String(text) => text
                .trim()
                .parse::<u64>()
                .map_err(|error| error.to_string()),
            serde_json::Value::Number(number) => number
                .as_u64()
                .ok_or_else(|| format!("{field} is not an unsigned integer")),
            _ => Err(format!("{field} is neither a string nor a number")),
        };
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
    use vapor_forge_config::{CustomManifestProvider, ManifestProvider};

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
            apps: vapor_forge_config::AppsSection::with_inject(vec![
                vapor_forge_config::InjectApp {
                    id: AppId(480),
                    dlc: Vec::new(),
                    ticket: Default::default(),
                    purchase_time: 0,
                },
            ]),
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
            apps: vapor_forge_config::AppsSection::with_inject(vec![
                vapor_forge_config::InjectApp {
                    id: owned_app,
                    dlc: Vec::new(),
                    ticket: Default::default(),
                    purchase_time: 0,
                },
            ]),
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

    fn built_in(provider: ManifestProvider) -> ManifestSource {
        ManifestSource::BuiltIn(provider)
    }

    fn custom(
        name: &str,
        format: ManifestResponseFormat,
        json_field: Option<&str>,
    ) -> ManifestSource {
        ManifestSource::Custom(CustomManifestProvider {
            name: name.to_owned(),
            url: format!("https://{name}.example/{{gid}}"),
            user_agent: None,
            format,
            json_field: json_field.map(str::to_owned),
            min_interval_ms: None,
        })
    }

    #[test]
    fn parses_built_in_provider_responses() {
        assert_eq!(
            parse_provider_response(&built_in(ManifestProvider::ManifestDex), "123456").unwrap(),
            123456
        );
        assert_eq!(
            parse_provider_response(&built_in(ManifestProvider::OpenSteamTool), "123456").unwrap(),
            123456
        );
        assert_eq!(
            parse_provider_response(&built_in(ManifestProvider::Wudrm), " 654321 ").unwrap(),
            654321
        );
        assert_eq!(
            parse_provider_response(
                &built_in(ManifestProvider::SteamRun),
                r#"{"content":"9999999999"}"#,
            )
            .unwrap(),
            9_999_999_999
        );
        assert!(
            parse_provider_response(&built_in(ManifestProvider::SteamRun), r#"{"other":"1"}"#)
                .is_err()
        );
    }

    #[test]
    fn parses_custom_provider_responses() {
        let plain = custom("plain", ManifestResponseFormat::Plain, None);
        assert_eq!(parse_provider_response(&plain, " 42 ").unwrap(), 42);
        assert!(parse_provider_response(&plain, "42abc").is_err());

        // A custom JSON endpoint may quote the code or leave it a number.
        let json = custom("json", ManifestResponseFormat::Json, Some("code"));
        assert_eq!(
            parse_provider_response(&json, r#"{"code":"777"}"#).unwrap(),
            777
        );
        assert_eq!(
            parse_provider_response(&json, r#"{"code":777}"#).unwrap(),
            777
        );
        assert!(parse_provider_response(&json, r#"{"code":true}"#).is_err());
        assert!(parse_provider_response(&json, r#"{"other":1}"#).is_err());
    }

    #[test]
    fn malformed_custom_entries_are_rejected_before_any_request() {
        let no_placeholder = ManifestSource::Custom(CustomManifestProvider {
            name: "mirror".to_owned(),
            url: "https://my.mirror/latest".to_owned(),
            user_agent: None,
            format: ManifestResponseFormat::Plain,
            json_field: None,
            min_interval_ms: None,
        });

        // fetch_manifest_code skips these, so an empty chain yields no code and
        // — the point of the check — issues no HTTP request.
        assert!(no_placeholder.rejection().is_some());
        let context = FetchContext {
            app_id: 730,
            depot_id: 731,
            gid: 1,
        };
        assert_eq!(
            fetch_manifest_code(context, &[no_placeholder], 10, 10, 0),
            None
        );
    }

    #[test]
    fn resolves_every_placeholder_in_a_custom_url() {
        let pool = ManifestSource::Custom(CustomManifestProvider {
            name: "pool".to_owned(),
            // Valve's own GetManifestRequestCode shape: depot, then manifest.
            url: "https://example.test/manifest/{depotId}/{gid}".to_owned(),
            user_agent: None,
            format: ManifestResponseFormat::Plain,
            json_field: None,
            min_interval_ms: None,
        });
        assert_eq!(
            pool.resolve_url(730, 731, 555),
            "https://example.test/manifest/731/555"
        );
        assert!(pool.rejection().is_none());

        let with_app = ManifestSource::Custom(CustomManifestProvider {
            name: "withapp".to_owned(),
            url: "https://example.test/{appId}/{depotId}/{gid}".to_owned(),
            user_agent: None,
            format: ManifestResponseFormat::Plain,
            json_field: None,
            min_interval_ms: None,
        });
        assert_eq!(
            with_app.resolve_url(730, 731, 555),
            "https://example.test/730/731/555"
        );

        // Built-ins that take only the gid leave the other placeholders inert.
        assert_eq!(
            built_in(ManifestProvider::Wudrm).resolve_url(730, 731, 555),
            "http://gmrc.wudrm.com/manifest/555"
        );
        // The built-in pool provider is itself depot-shaped.
        assert_eq!(
            built_in(ManifestProvider::Pool20770407).resolve_url(730, 731, 555),
            "https://20770407.xyz/manifest/731/555"
        );
        assert!(built_in(ManifestProvider::Pool20770407)
            .user_agent()
            .is_some_and(|ua| ua.starts_with("vapor-forge/")));
    }

    #[test]
    fn denial_is_not_a_provider_fault() {
        // A pool that holds no licence for the app answers 401 per request.
        // Cooling it down would hide it from every later gid, including the
        // ones it can serve — so Denied must stay distinct from Failed.
        let denied = ProviderOutcome::Denied(401);
        let failed = ProviderOutcome::Failed("http status 503".to_owned());

        assert!(matches!(denied, ProviderOutcome::Denied(401)));
        assert!(matches!(failed, ProviderOutcome::Failed(_)));

        // The cooldown table is only ever written for the failure classes.
        let mut cooldowns = HashMap::new();
        let now = Instant::now();
        start_cooldown_in(&mut cooldowns, "unhealthy", now, FAILURE_COOLDOWN);
        assert_eq!(
            cooldown_remaining_in(&mut cooldowns, "unhealthy", now),
            Some(FAILURE_COOLDOWN)
        );
        assert_eq!(
            cooldown_remaining_in(&mut cooldowns, "denied-but-healthy", now),
            None
        );
    }

    #[test]
    fn pacing_defers_a_second_request_then_lets_it_through() {
        let mut last = HashMap::new();
        let now = Instant::now();
        let interval = Duration::from_millis(1000);

        // First request reserves the slot immediately.
        assert_eq!(reserve_slot_in(&mut last, "pool", now, interval), None);

        // A second one inside the window is told how long to wait, and does
        // not reserve — otherwise concurrent callers would all think they won.
        assert_eq!(
            reserve_slot_in(
                &mut last,
                "pool",
                now + Duration::from_millis(400),
                interval
            ),
            Some(Duration::from_millis(600))
        );

        // Another provider is unaffected.
        assert_eq!(reserve_slot_in(&mut last, "other", now, interval), None);

        // Past the window it goes through and re-reserves.
        assert_eq!(
            reserve_slot_in(
                &mut last,
                "pool",
                now + Duration::from_millis(1200),
                interval
            ),
            None
        );
        assert_eq!(
            reserve_slot_in(
                &mut last,
                "pool",
                now + Duration::from_millis(1300),
                interval
            ),
            Some(Duration::from_millis(900))
        );
    }

    #[test]
    fn parses_retry_after_delta_seconds() {
        assert_eq!(parse_retry_after(Some("30")), Some(Duration::from_secs(30)));
        assert_eq!(parse_retry_after(Some(" 5 ")), Some(Duration::from_secs(5)));
        assert_eq!(parse_retry_after(Some("0")), Some(Duration::ZERO));
        // HTTP-date form is deliberately unsupported; caller substitutes the default.
        assert_eq!(
            parse_retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
            None
        );
        assert_eq!(parse_retry_after(Some("")), None);
        assert_eq!(parse_retry_after(None), None);
    }

    #[test]
    fn cooldown_hides_a_provider_until_it_expires() {
        let mut cooldowns = HashMap::new();
        let now = Instant::now();

        assert_eq!(
            cooldown_remaining_in(&mut cooldowns, "manifestdex", now),
            None
        );

        start_cooldown_in(&mut cooldowns, "manifestdex", now, Duration::from_secs(30));

        assert_eq!(
            cooldown_remaining_in(&mut cooldowns, "manifestdex", now),
            Some(Duration::from_secs(30))
        );
        // Other providers stay usable.
        assert_eq!(
            cooldown_remaining_in(&mut cooldowns, "opensteamtool", now),
            None
        );

        let later = now + Duration::from_secs(31);
        assert_eq!(
            cooldown_remaining_in(&mut cooldowns, "manifestdex", later),
            None
        );
        // The expired entry is dropped rather than left to accumulate.
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn cooldown_is_capped() {
        let mut cooldowns = HashMap::new();
        let now = Instant::now();

        let applied = start_cooldown_in(
            &mut cooldowns,
            "manifestdex",
            now,
            Duration::from_secs(86_400),
        );

        assert_eq!(applied, MAX_RATE_LIMIT_COOLDOWN);
        assert_eq!(
            cooldown_remaining_in(&mut cooldowns, "manifestdex", now),
            Some(MAX_RATE_LIMIT_COOLDOWN)
        );
    }
}
