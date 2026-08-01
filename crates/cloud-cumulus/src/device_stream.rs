//! Device-authenticated SSE transport for revisioned account-state events.

use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use vapor_forge_cloud_core::{BackendError, StreamCancellation, StreamOutcome};

use crate::{CumulusError, CumulusSettings, STEAM_CLIENT_ID_HEADER};

const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const STREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct StreamSpec {
    pub route: &'static str,
    pub event_name: &'static str,
    pub stream_name: &'static str,
}

#[derive(Clone)]
struct ConnectionRequest {
    agent: ureq::Agent,
    url: String,
    authorization: String,
    client_id: String,
    spec: StreamSpec,
}

pub(crate) fn run<T>(
    settings: &CumulusSettings,
    client_id: u64,
    steam_id64: &str,
    spec: StreamSpec,
    cancellation: &StreamCancellation,
    on_connected: &mut dyn FnMut() -> Result<Option<T>, BackendError>,
    on_message: &mut dyn FnMut(T),
) -> Result<StreamOutcome, BackendError>
where
    T: DeserializeOwned + Send + 'static,
{
    let request = ConnectionRequest {
        agent: build_agent(settings),
        url: format!(
            "{}{}?steam_id64={steam_id64}",
            settings.server_url.trim_end_matches('/'),
            spec.route,
        ),
        authorization: format!("Bearer {}", settings.token),
        client_id: client_id.to_string(),
        spec,
    };
    let mut backoff = BACKOFF_INITIAL;
    loop {
        if cancellation.is_cancelled() {
            return Ok(StreamOutcome::Stopped);
        }
        match connect_once(&request, cancellation, on_connected, on_message) {
            Connection::Stopped => return Ok(StreamOutcome::Stopped),
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
                    stream = spec.stream_name,
                    "Cumulus device stream will reconnect"
                );
            }
            Connection::Error { error, .. } => return Err(error),
        }
        if cancellation.wait_cancelled_timeout(backoff) {
            return Ok(StreamOutcome::Stopped);
        }
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

impl Connection {
    fn with_prior_delivery(self, prior: bool) -> Self {
        match self {
            Self::Disconnected { delivered } => Self::Disconnected {
                delivered: prior || delivered,
            },
            Self::Error { error, delivered } => Self::Error {
                error,
                delivered: prior || delivered,
            },
            Self::Stopped => Self::Stopped,
        }
    }
}

enum ConnectionMessage<T> {
    Connected,
    Message(T),
    Finished(Connection),
}

#[derive(Debug)]
enum ReadLineError {
    Io,
    InvalidUtf8,
    TooLarge,
}

struct SignalActivityOnDrop(StreamCancellation);

impl Drop for SignalActivityOnDrop {
    fn drop(&mut self) {
        self.0.signal_activity();
    }
}

fn connect_once<T>(
    request: &ConnectionRequest,
    cancellation: &StreamCancellation,
    on_connected: &mut dyn FnMut() -> Result<Option<T>, BackendError>,
    on_message: &mut dyn FnMut(T),
) -> Connection
where
    T: DeserializeOwned + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let reader_cancellation = cancellation.clone();
    let reader_stop = Arc::new(AtomicBool::new(false));
    let reader_stop_for_thread = Arc::clone(&reader_stop);
    let request = request.clone();
    let stream_name = request.spec.stream_name;
    if std::thread::Builder::new()
        .name(format!("cumulus-{stream_name}-sse"))
        .spawn(move || {
            let _signal_on_drop = SignalActivityOnDrop(reader_cancellation.clone());
            let continue_reading = || {
                !reader_cancellation.is_cancelled()
                    && !reader_stop_for_thread.load(Ordering::Acquire)
            };
            let connected_sender = sender.clone();
            let connected_cancellation = reader_cancellation.clone();
            let mut signal_connected = || {
                if connected_sender.send(ConnectionMessage::Connected).is_ok() {
                    connected_cancellation.signal_activity();
                } else {
                    reader_stop_for_thread.store(true, Ordering::Release);
                }
            };
            let mut send_message = |message| {
                if sender.send(ConnectionMessage::Message(message)).is_ok() {
                    reader_cancellation.signal_activity();
                } else {
                    reader_stop_for_thread.store(true, Ordering::Release);
                }
            };
            let outcome = connect_once_blocking(
                &request,
                &continue_reading,
                &mut signal_connected,
                &mut send_message,
            );
            let _ = sender.send(ConnectionMessage::Finished(outcome));
        })
        .is_err()
    {
        return Connection::Error {
            error: BackendError::new(
                format!("failed to start Cumulus {stream_name} SSE reader"),
                true,
            ),
            delivered: false,
        };
    }
    forward_connection(
        receiver,
        cancellation,
        reader_stop.as_ref(),
        on_connected,
        on_message,
    )
}

fn forward_connection<T>(
    receiver: mpsc::Receiver<ConnectionMessage<T>>,
    cancellation: &StreamCancellation,
    reader_stop: &AtomicBool,
    on_connected: &mut dyn FnMut() -> Result<Option<T>, BackendError>,
    on_message: &mut dyn FnMut(T),
) -> Connection {
    let mut delivered = false;
    loop {
        if cancellation.is_cancelled() {
            reader_stop.store(true, Ordering::Release);
            return Connection::Stopped;
        }
        let observed = cancellation.revision();
        match receiver.try_recv() {
            Ok(ConnectionMessage::Connected) => {
                // The subscription is active before the baseline pull starts.
                // Events racing with the pull stay behind this marker in the FIFO.
                let baseline = match on_connected() {
                    Ok(baseline) => baseline,
                    Err(error) => {
                        reader_stop.store(true, Ordering::Release);
                        return Connection::Error { error, delivered };
                    }
                };
                if cancellation.is_cancelled() {
                    reader_stop.store(true, Ordering::Release);
                    return Connection::Stopped;
                }
                if let Some(message) = baseline {
                    on_message(message);
                }
            }
            Ok(ConnectionMessage::Message(message)) => {
                if cancellation.is_cancelled() {
                    reader_stop.store(true, Ordering::Release);
                    return Connection::Stopped;
                }
                on_message(message);
                delivered = true;
            }
            Ok(ConnectionMessage::Finished(outcome)) => {
                reader_stop.store(true, Ordering::Release);
                return outcome.with_prior_delivery(delivered);
            }
            Err(mpsc::TryRecvError::Empty) => cancellation.wait_for_activity(observed),
            Err(mpsc::TryRecvError::Disconnected) => {
                reader_stop.store(true, Ordering::Release);
                return Connection::Disconnected { delivered };
            }
        }
    }
}

fn connect_once_blocking<T>(
    request: &ConnectionRequest,
    should_continue: &dyn Fn() -> bool,
    on_connected: &mut dyn FnMut(),
    on_message: &mut dyn FnMut(T),
) -> Connection
where
    T: DeserializeOwned,
{
    let response = match request
        .agent
        .get(&request.url)
        .header("Authorization", &request.authorization)
        .header("Accept", "text/event-stream")
        .header(STEAM_CLIENT_ID_HEADER, &request.client_id)
        .call()
    {
        Ok(response) => response,
        Err(error) => {
            return Connection::Error {
                error: CumulusError::Transport(error).into(),
                delivered: false,
            };
        }
    };
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let retryable = stream_status_retryable(status);
        return Connection::Error {
            error: BackendError::new(
                format!(
                    "Cumulus {} stream returned HTTP {status}",
                    request.spec.stream_name
                ),
                retryable,
            ),
            delivered: false,
        };
    }
    on_connected();

    let mut reader = BufReader::new(response.into_body().into_reader());
    let mut event = String::new();
    let mut data = String::new();
    let mut line = String::new();
    let mut delivered = false;
    let mut frame_bytes = 0usize;
    loop {
        if !should_continue() {
            return Connection::Stopped;
        }
        line.clear();
        match read_line_bounded(&mut reader, &mut line, MAX_EVENT_BYTES) {
            Ok(0) => return Connection::Disconnected { delivered },
            Ok(bytes) => {
                frame_bytes = frame_bytes.saturating_add(bytes);
                if frame_bytes > MAX_EVENT_BYTES {
                    return Connection::Error {
                        error: snapshot_too_large(),
                        delivered,
                    };
                }
            }
            Err(ReadLineError::Io) => return Connection::Disconnected { delivered },
            Err(ReadLineError::InvalidUtf8) => {
                return Connection::Error {
                    error: BackendError::new(
                        format!("Cumulus {} stream is not UTF-8", request.spec.stream_name),
                        true,
                    ),
                    delivered,
                };
            }
            Err(ReadLineError::TooLarge) => {
                return Connection::Error {
                    error: snapshot_too_large(),
                    delivered,
                };
            }
        }
        if !should_continue() {
            return Connection::Stopped;
        }
        let field = line.trim_end_matches(['\r', '\n']);
        if field.is_empty() {
            match decode_frame(
                &event,
                &data,
                request.spec.event_name,
                request.spec.stream_name,
            ) {
                Ok(Some(message)) => {
                    on_message(message);
                    delivered = true;
                }
                Ok(None) => {}
                Err(error) => return Connection::Error { error, delivered },
            }
            event.clear();
            data.clear();
            frame_bytes = 0;
            continue;
        }
        if let Some(value) = field.strip_prefix("event:") {
            event = value.trim().to_owned();
        } else if let Some(value) = field.strip_prefix("data:") {
            if data.len().saturating_add(value.len()) > MAX_EVENT_BYTES {
                return Connection::Error {
                    error: snapshot_too_large(),
                    delivered,
                };
            }
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.strip_prefix(' ').unwrap_or(value));
        }
    }
}

fn stream_status_retryable(status: u16) -> bool {
    matches!(status, 404 | 408 | 409 | 429) || status >= 500
}

fn read_line_bounded(
    reader: &mut impl BufRead,
    output: &mut String,
    limit: usize,
) -> Result<usize, ReadLineError> {
    output.clear();
    let mut read = 0usize;
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|_| ReadLineError::Io)?;
        if available.is_empty() {
            break;
        }
        let length = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if read.saturating_add(length) > limit {
            return Err(ReadLineError::TooLarge);
        }
        let has_newline = available[length - 1] == b'\n';
        bytes.extend_from_slice(&available[..length]);
        reader.consume(length);
        read += length;
        if has_newline {
            break;
        }
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ReadLineError::InvalidUtf8)?;
    output.push_str(text);
    Ok(read)
}

fn snapshot_too_large() -> BackendError {
    BackendError::new("Cumulus device stream event exceeds 4 MiB", false)
}

fn decode_frame<T: DeserializeOwned>(
    event: &str,
    data: &str,
    expected_event: &str,
    stream_name: &str,
) -> Result<Option<T>, BackendError> {
    if event != expected_event || data.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(data).map(Some).map_err(|error| {
        BackendError::new(
            format!("invalid Cumulus {stream_name} event: {error}"),
            false,
        )
    })
}

fn build_agent(settings: &CumulusSettings) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_millis(settings.timeout_connect_ms)))
        .timeout_recv_response(Some(STREAM_RESPONSE_TIMEOUT))
        .timeout_global(None)
        .timeout_recv_body(Some(STREAM_IDLE_TIMEOUT))
        .http_status_as_error(false)
        .build()
        .new_agent()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_authoritative_playtime_snapshot_and_ignores_keepalive() {
        assert!(
            decode_frame::<vapor_forge_cloud_core::AccountPlaytimeSnapshot>(
                "",
                "",
                "playtime_snapshot",
                "playtime",
            )
            .unwrap()
            .is_none()
        );
        let snapshot = decode_frame::<vapor_forge_cloud_core::AccountPlaytimeSnapshot>(
            "playtime_snapshot",
            concat!(
                "{\"steam_id64\":\"76561198000000001\",",
                "\"playtime_revision\":9,\"origin_client_id\":\"7\",",
                "\"playtime\":[{\"app_id\":620,\"playtime_minutes\":42,",
                "\"playtime_2weeks_minutes\":3,\"last_played_at\":100,",
                "\"observed_at\":101}]}"
            ),
            "playtime_snapshot",
            "playtime",
        )
        .unwrap()
        .unwrap();
        assert_eq!(snapshot.playtime_revision, 9);
        assert_eq!(snapshot.origin_client_id.as_deref(), Some("7"));
        assert_eq!(snapshot.playtime[0].playtime_minutes, 42);
    }

    #[test]
    fn malformed_snapshot_is_not_treated_as_an_old_protocol() {
        let error = decode_frame::<vapor_forge_cloud_core::AccountPlaytimeSnapshot>(
            "playtime_snapshot",
            "{}",
            "playtime_snapshot",
            "playtime",
        )
        .unwrap_err();
        assert!(!error.is_retryable());
    }

    #[test]
    fn missing_stream_endpoint_remains_retryable_during_server_rollout() {
        assert!(stream_status_retryable(404));
        assert!(!stream_status_retryable(400));
    }

    #[test]
    fn bounded_reader_rejects_a_line_before_it_can_grow_past_the_limit() {
        let input = std::io::Cursor::new(b"123456789\n");
        let mut reader = BufReader::new(input);
        let mut line = String::new();

        assert!(matches!(
            read_line_bounded(&mut reader, &mut line, 8),
            Err(ReadLineError::TooLarge)
        ));
        assert!(line.is_empty());
    }

    #[test]
    fn bounded_reader_accepts_utf8_split_across_fill_buffers() {
        let input = std::io::Cursor::new("data: é\n".as_bytes());
        let mut reader = BufReader::with_capacity(1, input);
        let mut line = String::new();

        assert_eq!(read_line_bounded(&mut reader, &mut line, 32).unwrap(), 9);
        assert_eq!(line, "data: é\n");
    }

    #[test]
    fn device_stream_sends_bound_identity_and_delivers_snapshot() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 2048];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            request_sender
                .send(String::from_utf8(request).unwrap())
                .unwrap();
            stream
                .write_all(
                    concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: text/event-stream\r\n",
                        "Connection: close\r\n\r\n",
                        "event: playtime_snapshot\n",
                        "id: 3\n",
                        "data: {\"steam_id64\":\"76561198000000001\",",
                        "\"playtime_revision\":3,\"origin_client_id\":null,",
                        "\"playtime\":[]}\n\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let settings = CumulusSettings {
            server_url: format!("http://{address}"),
            token: "stream-token".into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 1_000,
        };
        let cancellation = StreamCancellation::new();
        let cancel_after_snapshot = cancellation.clone();
        let mut snapshots = Vec::new();
        let mut baseline = || {
            Ok(Some(vapor_forge_cloud_core::AccountPlaytimeSnapshot {
                steam_id64: "76561198000000001".into(),
                playtime_revision: 2,
                origin_client_id: None,
                playtime: Vec::new(),
            }))
        };
        let outcome = run(
            &settings,
            7,
            "76561198000000001",
            StreamSpec {
                route: "/api/v1/device/playtime-events",
                event_name: "playtime_snapshot",
                stream_name: "playtime",
            },
            &cancellation,
            &mut baseline,
            &mut |snapshot: vapor_forge_cloud_core::AccountPlaytimeSnapshot| {
                snapshots.push(snapshot);
                if snapshots.len() == 2 {
                    cancel_after_snapshot.cancel();
                }
            },
        )
        .unwrap();

        server.join().unwrap();
        assert_eq!(outcome, StreamOutcome::Stopped);
        assert_eq!(
            snapshots
                .iter()
                .map(|snapshot| snapshot.playtime_revision)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        let request = request_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert!(request.starts_with(
            "GET /api/v1/device/playtime-events?steam_id64=76561198000000001 HTTP/1.1"
        ));
        let request = request.to_ascii_lowercase();
        assert!(request.contains("authorization: bearer stream-token"));
        assert!(request.contains("accept: text/event-stream"));
        assert!(request.contains("x-cumulus-steam-client-id: 7"));
    }
}
