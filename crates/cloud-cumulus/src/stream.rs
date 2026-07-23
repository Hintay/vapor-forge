//! Server-Sent Events subscription for converged account state.
//!
//! Cumulus pushes the full [`AccountSyncState`] as the first frame and again on
//! every change, so a subscriber never polls. This module owns the blocking
//! ureq stream loop: it reconnects with backoff, decodes `sync_state` frames,
//! and hands each decoded state to the caller's closure.

use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use vapor_forge_cloud_core::{AccountSyncState, BackendError, StreamOutcome};

use crate::{CumulusSettings, STEAM_CLIENT_ID_HEADER};

/// Maximum idle time while waiting for stream bytes. Cumulus sends an SSE
/// keep-alive every 15 seconds, so three missed heartbeats force a reconnect.
/// This is deliberately an idle-read timeout, not a maximum connection age.
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Bounds the wait for response headers, so a server that accepts the socket but
/// never sends a response cannot pin the reader thread indefinitely. Because
/// ureq carries the RecvResponse deadline into RecvBody, this also caps a healthy
/// connection's age; it is kept well above `STREAM_IDLE_TIMEOUT` so the idle
/// timeout still governs dead-body detection and this only forces an occasional
/// reconnect.
const STREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const STOP_POLL_GRANULARITY: Duration = Duration::from_millis(100);

/// Run the subscription until its context expires.
pub(crate) fn run(
    settings: &CumulusSettings,
    client_id: u64,
    steam_id64: &str,
    should_continue: &dyn Fn() -> bool,
    on_state: &mut dyn FnMut(AccountSyncState),
) -> Result<StreamOutcome, BackendError> {
    let agent = build_agent(settings);
    let url = format!(
        "{}/api/v1/device/sync-state/stream?steam_id64={}",
        settings.server_url.trim_end_matches('/'),
        steam_id64
    );
    let authorization = format!("Bearer {}", settings.token);
    let client_id = client_id.to_string();
    let mut backoff = BACKOFF_INITIAL;
    loop {
        if !should_continue() {
            return Ok(StreamOutcome::Stopped);
        }
        match connect_once(
            &agent,
            &url,
            &authorization,
            &client_id,
            should_continue,
            on_state,
        ) {
            Connection::Stopped => return Ok(StreamOutcome::Stopped),
            // A connection that delivered frames is healthy; retry promptly.
            Connection::Disconnected { delivered } => {
                if delivered {
                    backoff = BACKOFF_INITIAL;
                }
            }
            Connection::Error { error, delivered } if error.is_retryable() => {
                if delivered {
                    backoff = BACKOFF_INITIAL;
                }
                tracing::warn!(
                    %error,
                    retry_secs = backoff.as_secs(),
                    "Cumulus account-state stream will reconnect"
                );
            }
            Connection::Error { error, .. } => return Err(error),
        }
        sleep_interruptible(backoff, should_continue);
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

enum Connection {
    Stopped,
    Disconnected {
        delivered: bool,
    },
    Error {
        error: BackendError,
        delivered: bool,
    },
}

enum ConnectionMessage {
    State(AccountSyncState),
    Finished(Connection),
}

fn connect_once(
    agent: &ureq::Agent,
    url: &str,
    authorization: &str,
    client_id: &str,
    should_continue: &dyn Fn() -> bool,
    on_state: &mut dyn FnMut(AccountSyncState),
) -> Connection {
    let (sender, receiver) = mpsc::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let reader_cancelled = Arc::clone(&cancelled);
    let agent = agent.clone();
    let url = url.to_string();
    let authorization = authorization.to_string();
    let client_id = client_id.to_string();
    if std::thread::Builder::new()
        .name("cumulus-sse-read".into())
        .spawn(move || {
            let continue_reading = || !reader_cancelled.load(Ordering::Relaxed);
            let mut send_state = |state| {
                if sender.send(ConnectionMessage::State(state)).is_err() {
                    reader_cancelled.store(true, Ordering::Relaxed);
                }
            };
            let outcome = connect_once_blocking(
                &agent,
                &url,
                &authorization,
                &client_id,
                &continue_reading,
                &mut send_state,
            );
            let _ = sender.send(ConnectionMessage::Finished(outcome));
        })
        .is_err()
    {
        return Connection::Error {
            error: BackendError::new("failed to start Cumulus SSE reader", true),
            delivered: false,
        };
    }
    forward_connection(receiver, &cancelled, should_continue, on_state)
}

/// Forward reader-thread results while keeping subscription cancellation
/// independent from a blocking socket read. A cancelled reader may remain
/// blocked until its next keep-alive or body deadline, but it no longer owns
/// the caller callback and therefore cannot deliver stale state.
fn forward_connection(
    receiver: mpsc::Receiver<ConnectionMessage>,
    cancelled: &AtomicBool,
    should_continue: &dyn Fn() -> bool,
    on_state: &mut dyn FnMut(AccountSyncState),
) -> Connection {
    let mut delivered = false;
    loop {
        if !should_continue() {
            cancelled.store(true, Ordering::Relaxed);
            return Connection::Stopped;
        }
        match receiver.recv_timeout(STOP_POLL_GRANULARITY) {
            Ok(ConnectionMessage::State(state)) => {
                if !should_continue() {
                    cancelled.store(true, Ordering::Relaxed);
                    return Connection::Stopped;
                }
                on_state(state);
                delivered = true;
            }
            Ok(ConnectionMessage::Finished(outcome)) => return outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Connection::Disconnected { delivered };
            }
        }
    }
}

fn connect_once_blocking(
    agent: &ureq::Agent,
    url: &str,
    authorization: &str,
    client_id: &str,
    should_continue: &dyn Fn() -> bool,
    on_state: &mut dyn FnMut(AccountSyncState),
) -> Connection {
    let response = match agent
        .get(url)
        .header("Authorization", authorization)
        .header("Accept", "text/event-stream")
        .header(STEAM_CLIENT_ID_HEADER, client_id)
        .call()
    {
        Ok(response) => response,
        Err(error) => {
            return Connection::Error {
                error: crate::CumulusError::Transport(error).into(),
                delivered: false,
            };
        }
    };
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        // A 404 can mean an older Cumulus instance that is upgraded in place.
        // Keep reopening the SSE endpoint so down-sync becomes available
        // without a config reload or client restart.
        let retryable = matches!(status, 404 | 408 | 409 | 429) || status >= 500;
        return Connection::Error {
            error: BackendError::new(format!("Cumulus stream returned HTTP {status}"), retryable),
            delivered: false,
        };
    }

    let mut reader = BufReader::new(response.into_body().into_reader());
    let mut event = String::new();
    let mut data = String::new();
    let mut line = String::new();
    let mut delivered = false;
    loop {
        if !should_continue() {
            return Connection::Stopped;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return Connection::Disconnected { delivered }, // clean EOF
            Ok(_) => {}
            // Read error or the idle timeout firing: reconnect.
            Err(_) => return Connection::Disconnected { delivered },
        }
        if !should_continue() {
            return Connection::Stopped;
        }
        let field = line.trim_end_matches(['\r', '\n']);
        if field.is_empty() {
            // Blank line ends a frame. Dispatch a completed sync_state payload.
            match decode_frame(&event, &data) {
                Ok(Some(state)) => {
                    on_state(state);
                    delivered = true;
                }
                Ok(None) => {}
                Err(error) => return Connection::Error { error, delivered },
            }
            event.clear();
            data.clear();
            continue;
        }
        if let Some(value) = field.strip_prefix("event:") {
            event = value.trim().to_string();
        } else if let Some(value) = field.strip_prefix("data:") {
            // SSE strips a single leading space after the field colon.
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.strip_prefix(' ').unwrap_or(value));
        }
        // `:` comment lines (keep-alive) and unknown fields are ignored.
    }
}

fn decode_frame(event: &str, data: &str) -> Result<Option<AccountSyncState>, BackendError> {
    if event != "sync_state" || data.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(data).map(Some).map_err(|error| {
        BackendError::new(format!("invalid Cumulus sync_state JSON: {error}"), true)
    })
}

fn build_agent(settings: &CumulusSettings) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_millis(settings.timeout_connect_ms)))
        // ureq 3 carries the RecvResponse deadline into RecvBody, so a finite
        // value here doubles as a maximum SSE connection age. It is kept large
        // (see `STREAM_RESPONSE_TIMEOUT`) so `STREAM_IDLE_TIMEOUT` still governs
        // dead-stream detection; its real job is to bound the header wait so a
        // server that accepts the socket but never replies cannot pin the reader
        // thread forever.
        .timeout_recv_response(Some(STREAM_RESPONSE_TIMEOUT))
        // The body is long-lived, so there is no global deadline. This timeout
        // only detects a stream that stops producing frames or keep-alives.
        .timeout_global(None)
        .timeout_recv_body(Some(STREAM_IDLE_TIMEOUT))
        .http_status_as_error(false)
        .build()
        .new_agent()
}

fn sleep_interruptible(total: Duration, should_continue: &dyn Fn() -> bool) {
    let mut slept = Duration::ZERO;
    while slept < total {
        if !should_continue() {
            return;
        }
        let step = STOP_POLL_GRANULARITY.min(total - slept);
        std::thread::sleep(step);
        slept += step;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal SSE frame parse over a fixed reader, proving `sync_state`
    /// payloads decode and non-data frames (ready, keep-alive) are skipped.
    #[test]
    fn parses_sync_state_frames_and_skips_others() {
        let body = concat!(
            "event: ready\ndata: {}\n\n",
            ":keep-alive\n\n",
            "event: sync_state\n",
            "data: {\"achievements\":[],\"playtime\":[{\"app_id\":620,",
            "\"playtime_minutes\":42,\"playtime_2weeks_minutes\":0,",
            "\"last_played_at\":null,\"observed_at\":10}]}\n\n",
        );
        let mut reader = BufReader::new(body.as_bytes());
        let mut event = String::new();
        let mut data = String::new();
        let mut line = String::new();
        let mut states = Vec::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let field = line.trim_end_matches(['\r', '\n']);
            if field.is_empty() {
                if event == "sync_state" && !data.is_empty() {
                    states.push(serde_json::from_str::<AccountSyncState>(&data).unwrap());
                }
                event.clear();
                data.clear();
                continue;
            }
            if let Some(value) = field.strip_prefix("event:") {
                event = value.trim().to_string();
            } else if let Some(value) = field.strip_prefix("data:") {
                data.push_str(value.strip_prefix(' ').unwrap_or(value));
            }
        }
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].playtime[0].app_id, 620);
        assert_eq!(states[0].playtime[0].playtime_minutes, 42);
    }

    #[test]
    fn malformed_sync_state_is_a_recoverable_connection_error() {
        let error = decode_frame("sync_state", "{not-json}").unwrap_err();
        assert!(error.is_retryable());
        assert!(error
            .to_string()
            .contains("invalid Cumulus sync_state JSON"));
    }

    #[test]
    fn reconnects_after_malformed_frame_and_delivers_valid_snapshot() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let bodies = [
                "event: sync_state\ndata: {not-json}\n\n",
                concat!(
                    "event: sync_state\n",
                    "data: {\"achievements\":[],\"playtime\":[]}\n\n",
                ),
            ];
            for body in bodies {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{body}"
                )
                .unwrap();
            }
        });
        let settings = CumulusSettings {
            server_url: format!("http://{address}"),
            token: "stream-token".into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 1_000,
        };
        let keep_running = AtomicBool::new(true);
        let mut states = Vec::new();
        let outcome = run(
            &settings,
            7,
            "76561198000000001",
            &|| keep_running.load(Ordering::Relaxed),
            &mut |state| {
                states.push(state);
                keep_running.store(false, Ordering::Relaxed);
            },
        )
        .unwrap();

        server.join().unwrap();
        assert_eq!(outcome, StreamOutcome::Stopped);
        assert_eq!(states, vec![AccountSyncState::default()]);
    }

    #[test]
    fn reconnects_when_stream_endpoint_appears_after_404() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let responses = [
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Content-Type: text/event-stream\r\n",
                    "Connection: close\r\n\r\n",
                    "event: sync_state\n",
                    "data: {\"achievements\":[],\"playtime\":[]}\n\n",
                ),
            ];
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).unwrap();
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let settings = CumulusSettings {
            server_url: format!("http://{address}"),
            token: "stream-token".into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 1_000,
        };
        let keep_running = AtomicBool::new(true);
        let mut states = Vec::new();

        let outcome = run(
            &settings,
            7,
            "76561198000000001",
            &|| keep_running.load(Ordering::Relaxed),
            &mut |state| {
                states.push(state);
                keep_running.store(false, Ordering::Relaxed);
            },
        )
        .unwrap();

        server.join().unwrap();
        assert_eq!(outcome, StreamOutcome::Stopped);
        assert_eq!(states, vec![AccountSyncState::default()]);
    }

    #[test]
    fn rest_timeout_does_not_limit_stream_lifetime() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: text/event-stream\r\n",
                        "Connection: close\r\n\r\n",
                        "event: sync_state\n",
                        "data: {\"achievements\":[],\"playtime\":[]}\n\n",
                    )
                    .as_bytes(),
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(250));
            let _ = stream.write_all(
                concat!(
                    "event: sync_state\n",
                    "data: {\"achievements\":[],\"playtime\":[{",
                    "\"app_id\":620,\"playtime_minutes\":1,",
                    "\"playtime_2weeks_minutes\":0,",
                    "\"last_played_at\":null,\"observed_at\":1}]}\n\n",
                )
                .as_bytes(),
            );
        });
        let settings = CumulusSettings {
            server_url: format!("http://{address}"),
            token: "stream-token".into(),
            timeout_connect_ms: 1_000,
            // The ordinary REST deadline previously tore down the SSE body
            // before frame two; the stream now uses its own relaxed deadline.
            timeout_ms: 100,
        };
        let agent = build_agent(&settings);
        let mut states = Vec::new();

        let outcome = connect_once_blocking(
            &agent,
            &format!("http://{address}/api/v1/device/sync-state/stream?steam_id64=1"),
            "Bearer stream-token",
            "7",
            &|| true,
            &mut |state| states.push(state),
        );

        server.join().unwrap();
        assert!(matches!(
            outcome,
            Connection::Disconnected { delivered: true }
        ));
        assert_eq!(states.len(), 2);
        assert_eq!(states[1].playtime[0].app_id, 620);
    }

    #[test]
    fn expired_context_discards_queued_state_without_waiting_for_reader() {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(ConnectionMessage::State(AccountSyncState::default()))
            .unwrap();
        let cancelled = AtomicBool::new(false);
        let mut delivered = false;

        let outcome =
            forward_connection(receiver, &cancelled, &|| false, &mut |_| delivered = true);

        assert!(matches!(outcome, Connection::Stopped));
        assert!(cancelled.load(Ordering::Relaxed));
        assert!(!delivered);
    }
}
