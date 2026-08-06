//! Device-authenticated SSE transport for revisioned account-state events.

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectProxyConnector, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout,
    RustlsConnector, Transport,
};
use vapor_forge_cloud_core::{
    AccountPlaytimeSnapshot, AccountStatsWakeup, AccountStreamEvent, AccountSyncState,
    BackendError, StreamCancellation, StreamOutcome,
};

use crate::{CumulusError, CumulusSettings, STEAM_CLIENT_ID_HEADER};

const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const STREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;
const ACCOUNT_MESSAGE_CAPACITY: usize = 16;

#[derive(Clone, Copy)]
pub(crate) struct StreamSpec {
    pub route: &'static str,
    pub event_name: &'static str,
    pub stream_name: &'static str,
}

#[derive(Clone)]
struct ConnectionRequest {
    agent: ureq::Agent,
    connection: ConnectionCloser,
    url: String,
    authorization: String,
    client_id: String,
    spec: StreamSpec,
}

#[derive(Clone, Default)]
struct ConnectionCloser {
    state: Arc<Mutex<ConnectionState>>,
}

#[derive(Default)]
struct ConnectionState {
    stopped: bool,
    streams: Vec<TcpStream>,
}

impl ConnectionCloser {
    fn track(&self, stream: &TcpStream) -> io::Result<()> {
        let tracked = stream.try_clone()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.stopped {
            let _ = stream.shutdown(Shutdown::Both);
        } else {
            state.streams.push(tracked);
        }
        Ok(())
    }

    fn stop(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.stopped = true;
        for stream in state.streams.drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn is_stopped(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stopped
    }
}

impl fmt::Debug for ConnectionCloser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionCloser")
            .field("stopped", &self.is_stopped())
            .finish()
    }
}

#[derive(Debug)]
struct CancellableTcpConnector {
    closer: ConnectionCloser,
}

impl CancellableTcpConnector {
    fn new(closer: ConnectionCloser) -> Self {
        Self { closer }
    }
}

impl<In: Transport> Connector<In> for CancellableTcpConnector {
    type Out = Either<In, CancellableTcpTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails<'_>,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        if let Some(transport) = chained {
            return Ok(Some(Either::A(transport)));
        }

        let started = Instant::now();
        let timeout = details.timeout.not_zero().map(|duration| *duration);
        let mut last_error = None;
        let address_count = details.addrs.len();
        for (index, address) in details.addrs.iter().enumerate() {
            let stream = match timeout {
                Some(timeout) => {
                    let remaining = timeout.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        return Err(ureq::Error::Timeout(details.timeout.reason));
                    }
                    let attempts_left = address_count - index;
                    TcpStream::connect_timeout(
                        address,
                        connect_attempt_budget(remaining, attempts_left),
                    )
                }
                None => TcpStream::connect(address),
            };
            match stream {
                Ok(stream) => {
                    if details.config.no_delay() {
                        stream.set_nodelay(true)?;
                    }
                    self.closer.track(&stream)?;
                    let buffers = LazyBuffers::new(
                        details.config.input_buffer_size(),
                        details.config.output_buffer_size(),
                    );
                    return Ok(Some(Either::B(CancellableTcpTransport::new(
                        stream, buffers,
                    ))));
                }
                Err(error) => last_error = Some(error),
            }
        }

        match last_error {
            Some(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Err(ureq::Error::Timeout(details.timeout.reason))
            }
            Some(error) => Err(error.into()),
            None => Err(ureq::Error::ConnectionFailed),
        }
    }
}

fn connect_attempt_budget(remaining: Duration, attempts_left: usize) -> Duration {
    debug_assert!(attempts_left > 0);
    let budget = remaining / u32::try_from(attempts_left).unwrap_or(u32::MAX);
    if budget.is_zero() {
        remaining
    } else {
        budget
    }
}

struct CancellableTcpTransport {
    stream: TcpStream,
    buffers: LazyBuffers,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl CancellableTcpTransport {
    fn new(stream: TcpStream, buffers: LazyBuffers) -> Self {
        Self {
            stream,
            buffers,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

impl fmt::Debug for CancellableTcpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellableTcpTransport")
            .field("peer", &self.stream.peer_addr().ok())
            .finish()
    }
}

impl Transport for CancellableTcpTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        update_socket_timeout(
            timeout,
            &mut self.write_timeout,
            &self.stream,
            TcpStream::set_write_timeout,
        )?;
        let output = &self.buffers.output()[..amount];
        self.stream
            .write_all(output)
            .map_err(|error| map_socket_error(error, timeout))
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        update_socket_timeout(
            timeout,
            &mut self.read_timeout,
            &self.stream,
            TcpStream::set_read_timeout,
        )?;
        let input = self.buffers.input_append_buf();
        let amount = self
            .stream
            .read(input)
            .map_err(|error| map_socket_error(error, timeout))?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        false
    }
}

fn update_socket_timeout(
    timeout: NextTimeout,
    previous: &mut Option<Duration>,
    stream: &TcpStream,
    update: impl FnOnce(&TcpStream, Option<Duration>) -> io::Result<()>,
) -> Result<(), ureq::Error> {
    let current = timeout.not_zero().map(|duration| *duration);
    if current != *previous {
        update(stream, current)?;
        *previous = current;
    }
    Ok(())
}

fn map_socket_error(error: io::Error, timeout: NextTimeout) -> ureq::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        ureq::Error::Timeout(timeout.reason)
    } else {
        error.into()
    }
}

pub(crate) fn run_account(
    settings: &CumulusSettings,
    client_id: u64,
    steam_id64: &str,
    cancellation: &StreamCancellation,
    on_connected: &mut dyn FnMut() -> Result<AccountSyncState, BackendError>,
    on_event: &mut dyn FnMut(AccountStreamEvent),
) -> Result<StreamOutcome, BackendError> {
    let request_for = |spec: StreamSpec| {
        let connection = ConnectionCloser::default();
        ConnectionRequest {
            agent: build_agent(settings, connection.clone()),
            connection,
            url: format!(
                "{}{}?steam_id64={steam_id64}",
                settings.server_url.trim_end_matches('/'),
                spec.route,
            ),
            authorization: format!("Bearer {}", settings.token),
            client_id: client_id.to_string(),
            spec,
        }
    };
    let playtime_spec = StreamSpec {
        route: "/api/v1/device/playtime-events",
        event_name: "playtime_snapshot",
        stream_name: "playtime",
    };
    let stats_spec = StreamSpec {
        route: "/api/v1/device/stats-events",
        event_name: "stats_wakeup",
        stream_name: "stats",
    };
    let mut backoff = BACKOFF_INITIAL;
    loop {
        if cancellation.is_cancelled() {
            return Ok(StreamOutcome::Stopped);
        }
        let playtime_request = request_for(playtime_spec);
        let stats_request = request_for(stats_spec);
        let (incremental, retry_error) = match connect_pair_once(
            &playtime_request,
            &stats_request,
            cancellation,
            on_connected,
            on_event,
        ) {
            Connection::Stopped => return Ok(StreamOutcome::Stopped),
            Connection::Disconnected { incremental } => (incremental, None),
            Connection::Error { error, incremental } if error.is_retryable() => {
                (incremental, Some(error))
            }
            Connection::Error { error, .. } => return Err(error),
        };
        let delay = reconnect_delay(&mut backoff, incremental);
        if let Some(error) = retry_error {
            tracing::warn!(
                %error,
                retry_secs = delay.as_secs(),
                "Cumulus account streams will reconnect"
            );
        }
        if cancellation.wait_cancelled_timeout(delay) {
            return Ok(StreamOutcome::Stopped);
        }
    }
}

fn reconnect_delay(backoff: &mut Duration, incremental: bool) -> Duration {
    if incremental {
        *backoff = BACKOFF_INITIAL;
    }
    let delay = *backoff;
    *backoff = (*backoff * 2).min(BACKOFF_MAX);
    delay
}

enum Connection {
    Stopped,
    Disconnected {
        incremental: bool,
    },
    Error {
        error: BackendError,
        incremental: bool,
    },
}

impl Connection {
    fn with_prior_incremental(self, prior: bool) -> Self {
        match self {
            Self::Disconnected { incremental } => Self::Disconnected {
                incremental: prior || incremental,
            },
            Self::Error { error, incremental } => Self::Error {
                error,
                incremental: prior || incremental,
            },
            Self::Stopped => Self::Stopped,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamKind {
    Playtime,
    Stats,
}

enum AccountConnectionMessage {
    Connected(StreamKind),
    Event(AccountStreamEvent),
    Finished(StreamKind, Connection),
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

struct ReaderThread {
    stop: Arc<AtomicBool>,
    connection: ConnectionCloser,
    join: JoinHandle<()>,
}

impl ReaderThread {
    fn stop(&self, cancellation: &StreamCancellation) {
        self.stop.store(true, Ordering::Release);
        self.connection.stop();
        cancellation.signal_activity();
    }

    fn join(self) {
        if self.join.join().is_err() {
            tracing::error!("Cumulus account SSE reader panicked");
        }
    }
}

fn connect_pair_once(
    playtime_request: &ConnectionRequest,
    stats_request: &ConnectionRequest,
    cancellation: &StreamCancellation,
    on_connected: &mut dyn FnMut() -> Result<AccountSyncState, BackendError>,
    on_event: &mut dyn FnMut(AccountStreamEvent),
) -> Connection {
    let (sender, receiver) = account_message_channel();
    let baseline_ready = Arc::new(AtomicBool::new(false));
    let playtime_reader = match spawn_reader::<AccountPlaytimeSnapshot>(
        playtime_request.clone(),
        StreamKind::Playtime,
        AccountStreamEvent::Playtime,
        sender.clone(),
        cancellation.clone(),
        Arc::clone(&baseline_ready),
    ) {
        Ok(reader) => reader,
        Err(error) => {
            return Connection::Error {
                error,
                incremental: false,
            };
        }
    };
    let stats_reader = match spawn_reader::<AccountStatsWakeup>(
        stats_request.clone(),
        StreamKind::Stats,
        AccountStreamEvent::StatsWakeup,
        sender,
        cancellation.clone(),
        Arc::clone(&baseline_ready),
    ) {
        Ok(reader) => reader,
        Err(error) => {
            playtime_reader.stop(cancellation);
            playtime_reader.join();
            return Connection::Error {
                error,
                incremental: false,
            };
        }
    };
    let readers = [playtime_reader, stats_reader];
    let outcome = forward_pair(
        receiver,
        cancellation,
        baseline_ready.as_ref(),
        on_connected,
        on_event,
    );
    stop_readers(&readers, cancellation);
    join_readers(readers);
    outcome
}

fn account_message_channel() -> (
    mpsc::SyncSender<AccountConnectionMessage>,
    mpsc::Receiver<AccountConnectionMessage>,
) {
    mpsc::sync_channel(ACCOUNT_MESSAGE_CAPACITY)
}

fn spawn_reader<T>(
    request: ConnectionRequest,
    kind: StreamKind,
    wrap: fn(T) -> AccountStreamEvent,
    sender: mpsc::SyncSender<AccountConnectionMessage>,
    cancellation: StreamCancellation,
    baseline_ready: Arc<AtomicBool>,
) -> Result<ReaderThread, BackendError>
where
    T: DeserializeOwned + Send + 'static,
{
    let stream_name = request.spec.stream_name;
    let stop = Arc::new(AtomicBool::new(false));
    let reader_stop = Arc::clone(&stop);
    let connection = request.connection.clone();
    let join = std::thread::Builder::new()
        .name(format!("cumulus-{stream_name}-sse"))
        .spawn(move || {
            let _signal_on_drop = SignalActivityOnDrop(cancellation.clone());
            let continue_reading =
                || !cancellation.is_cancelled() && !reader_stop.load(Ordering::Acquire);
            let connected_sender = sender.clone();
            let connected_cancellation = cancellation.clone();
            let connected_stop = Arc::clone(&reader_stop);
            let connected_baseline_ready = Arc::clone(&baseline_ready);
            let mut signal_connected = || {
                if connected_sender
                    .send(AccountConnectionMessage::Connected(kind))
                    .is_ok()
                {
                    connected_cancellation.signal_activity();
                    wait_for_baseline(
                        connected_baseline_ready.as_ref(),
                        &connected_cancellation,
                        connected_stop.as_ref(),
                    );
                } else {
                    connected_stop.store(true, Ordering::Release);
                }
            };
            let event_sender = sender.clone();
            let event_cancellation = cancellation.clone();
            let mut send_message = |message| {
                if event_sender
                    .send(AccountConnectionMessage::Event(wrap(message)))
                    .is_ok()
                {
                    event_cancellation.signal_activity();
                } else {
                    reader_stop.store(true, Ordering::Release);
                }
            };
            let outcome = connect_once_blocking(
                &request,
                &continue_reading,
                &mut signal_connected,
                &mut send_message,
            );
            let _ = sender.send(AccountConnectionMessage::Finished(kind, outcome));
        })
        .map_err(|error| {
            BackendError::new(
                format!("failed to start Cumulus {stream_name} SSE reader: {error}"),
                true,
            )
        })?;
    Ok(ReaderThread {
        stop,
        connection,
        join,
    })
}

fn wait_for_baseline(
    baseline_ready: &AtomicBool,
    cancellation: &StreamCancellation,
    stop: &AtomicBool,
) {
    while !baseline_ready.load(Ordering::Acquire)
        && !cancellation.is_cancelled()
        && !stop.load(Ordering::Acquire)
    {
        let observed = cancellation.revision();
        if baseline_ready.load(Ordering::Acquire)
            || cancellation.is_cancelled()
            || stop.load(Ordering::Acquire)
        {
            break;
        }
        cancellation.wait_for_activity(observed);
    }
}

fn forward_pair(
    receiver: mpsc::Receiver<AccountConnectionMessage>,
    cancellation: &StreamCancellation,
    baseline_ready: &AtomicBool,
    on_connected: &mut dyn FnMut() -> Result<AccountSyncState, BackendError>,
    on_event: &mut dyn FnMut(AccountStreamEvent),
) -> Connection {
    let mut incremental = false;
    let mut connected = [false; 2];
    let mut baseline_delivered = false;
    loop {
        if cancellation.is_cancelled() {
            return Connection::Stopped;
        }
        let observed = cancellation.revision();
        match receiver.try_recv() {
            Ok(AccountConnectionMessage::Connected(kind)) => {
                connected[stream_index(kind)] = true;
                if connected.iter().all(|value| *value) && !baseline_delivered {
                    let baseline = match on_connected() {
                        Ok(baseline) => baseline,
                        Err(error) => {
                            return Connection::Error { error, incremental };
                        }
                    };
                    if cancellation.is_cancelled() {
                        return Connection::Stopped;
                    }
                    on_event(AccountStreamEvent::Baseline(baseline));
                    baseline_delivered = true;
                    baseline_ready.store(true, Ordering::Release);
                    cancellation.signal_activity();
                }
            }
            Ok(AccountConnectionMessage::Event(event)) => {
                if cancellation.is_cancelled() {
                    return Connection::Stopped;
                }
                if !baseline_delivered {
                    return Connection::Error {
                        error: BackendError::new(
                            "Cumulus account stream event crossed the baseline barrier",
                            false,
                        ),
                        incremental,
                    };
                }
                on_event(event);
                incremental = true;
            }
            Ok(AccountConnectionMessage::Finished(kind, outcome)) => {
                tracing::debug!(stream = ?kind, "Cumulus account stream ended");
                return outcome.with_prior_incremental(incremental);
            }
            Err(mpsc::TryRecvError::Empty) => cancellation.wait_for_activity(observed),
            Err(mpsc::TryRecvError::Disconnected) => {
                return Connection::Disconnected { incremental };
            }
        }
    }
}

fn stream_index(kind: StreamKind) -> usize {
    match kind {
        StreamKind::Playtime => 0,
        StreamKind::Stats => 1,
    }
}

fn stop_readers(readers: &[ReaderThread; 2], cancellation: &StreamCancellation) {
    for reader in readers {
        reader.stop(cancellation);
    }
}

fn join_readers(readers: [ReaderThread; 2]) {
    for reader in readers {
        reader.join();
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
                incremental: false,
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
            incremental: false,
        };
    }
    on_connected();

    let mut reader = BufReader::new(response.into_body().into_reader());
    let mut event = String::new();
    let mut data = String::new();
    let mut line = String::new();
    let mut incremental = false;
    let mut frame_bytes = 0usize;
    loop {
        if !should_continue() {
            return Connection::Stopped;
        }
        line.clear();
        match read_line_bounded(&mut reader, &mut line, MAX_EVENT_BYTES) {
            Ok(0) => return Connection::Disconnected { incremental },
            Ok(bytes) => {
                frame_bytes = frame_bytes.saturating_add(bytes);
                if frame_bytes > MAX_EVENT_BYTES {
                    return Connection::Error {
                        error: snapshot_too_large(),
                        incremental,
                    };
                }
            }
            Err(ReadLineError::Io) => return Connection::Disconnected { incremental },
            Err(ReadLineError::InvalidUtf8) => {
                return Connection::Error {
                    error: BackendError::new(
                        format!("Cumulus {} stream is not UTF-8", request.spec.stream_name),
                        true,
                    ),
                    incremental,
                };
            }
            Err(ReadLineError::TooLarge) => {
                return Connection::Error {
                    error: snapshot_too_large(),
                    incremental,
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
                    incremental = true;
                }
                Ok(None) => {}
                Err(error) => return Connection::Error { error, incremental },
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
                    incremental,
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

fn build_agent(settings: &CumulusSettings, connection: ConnectionCloser) -> ureq::Agent {
    let connection_timeout = Duration::from_millis(settings.timeout_connect_ms);
    let config = ureq::Agent::config_builder()
        .timeout_resolve(Some(connection_timeout))
        .timeout_connect(Some(connection_timeout))
        .timeout_recv_response(Some(STREAM_RESPONSE_TIMEOUT))
        .timeout_global(None)
        .timeout_recv_body(Some(STREAM_IDLE_TIMEOUT))
        .http_status_as_error(false)
        .build();
    let connector =
        ().chain(ConnectProxyConnector::default())
            .chain(CancellableTcpConnector::new(connection))
            .chain(RustlsConnector::default());
    ureq::Agent::with_parts(config, connector, DefaultResolver::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_account_state() -> AccountSyncState {
        AccountSyncState {
            stats_crcs: Vec::new(),
            playtime_revision: 0,
            achievements: Vec::new(),
            stats: Vec::new(),
            playtime: Vec::new(),
        }
    }

    #[test]
    fn account_message_channel_applies_backpressure_at_its_capacity() {
        let (sender, _receiver) = account_message_channel();
        for _ in 0..ACCOUNT_MESSAGE_CAPACITY {
            sender
                .try_send(AccountConnectionMessage::Connected(StreamKind::Playtime))
                .unwrap();
        }

        assert!(matches!(
            sender.try_send(AccountConnectionMessage::Connected(StreamKind::Stats)),
            Err(mpsc::TrySendError::Full(_))
        ));
    }

    #[test]
    fn connection_attempts_reserve_budget_for_later_addresses() {
        assert_eq!(
            connect_attempt_budget(Duration::from_secs(12), 3),
            Duration::from_secs(4)
        );
        assert_eq!(
            connect_attempt_budget(Duration::from_secs(8), 2),
            Duration::from_secs(4)
        );
        assert_eq!(
            connect_attempt_budget(Duration::from_secs(4), 1),
            Duration::from_secs(4)
        );
    }

    #[test]
    fn stream_agent_bounds_resolution_and_connection_time() {
        let settings = CumulusSettings {
            server_url: "https://cumulus.invalid".into(),
            token: "stream-token".into(),
            timeout_connect_ms: 125,
            timeout_ms: 1_000,
        };
        let agent = build_agent(&settings, ConnectionCloser::default());
        let timeouts = agent.config().timeouts();
        let expected = Some(Duration::from_millis(125));

        assert_eq!(timeouts.resolve, expected);
        assert_eq!(timeouts.connect, expected);
    }

    #[test]
    fn baseline_without_incremental_events_does_not_reset_backoff_progress() {
        let (sender, receiver) = account_message_channel();
        sender
            .send(AccountConnectionMessage::Connected(StreamKind::Playtime))
            .unwrap();
        sender
            .send(AccountConnectionMessage::Connected(StreamKind::Stats))
            .unwrap();
        sender
            .send(AccountConnectionMessage::Finished(
                StreamKind::Playtime,
                Connection::Disconnected { incremental: false },
            ))
            .unwrap();
        drop(sender);

        let cancellation = StreamCancellation::new();
        let baseline_ready = AtomicBool::new(false);
        let mut events = Vec::new();
        let outcome = forward_pair(
            receiver,
            &cancellation,
            &baseline_ready,
            &mut || Ok(empty_account_state()),
            &mut |event| events.push(event),
        );

        assert!(baseline_ready.load(Ordering::Acquire));
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], AccountStreamEvent::Baseline(_)));
        let Connection::Disconnected { incremental } = outcome else {
            panic!("expected a disconnected stream round");
        };
        assert!(!incremental);

        let mut backoff = Duration::from_secs(8);
        assert_eq!(
            reconnect_delay(&mut backoff, incremental),
            Duration::from_secs(8)
        );
        assert_eq!(backoff, Duration::from_secs(16));
        assert_eq!(reconnect_delay(&mut backoff, true), BACKOFF_INITIAL);
        assert_eq!(backoff, Duration::from_secs(2));
    }

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
    fn ending_one_stream_interrupts_and_joins_the_other_reader() {
        use std::sync::Barrier;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sibling_closed_sender, sibling_closed_receiver) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let response_barrier = Arc::new(Barrier::new(2));
            let mut handlers = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let response_barrier = Arc::clone(&response_barrier);
                let sibling_closed_sender = sibling_closed_sender.clone();
                handlers.push(std::thread::spawn(move || {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 2048];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let read = stream.read(&mut buffer).unwrap();
                        request.extend_from_slice(&buffer[..read]);
                    }
                    let request = String::from_utf8(request).unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                    response_barrier.wait();

                    if request.contains("/playtime-events?") {
                        let mut byte = [0u8; 1];
                        let closed = loop {
                            match stream.read(&mut byte) {
                                Ok(0) => break true,
                                Ok(_) => continue,
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        io::ErrorKind::ConnectionReset
                                            | io::ErrorKind::BrokenPipe
                                            | io::ErrorKind::UnexpectedEof
                                    ) =>
                                {
                                    break true;
                                }
                                Err(error) => panic!("unexpected sibling socket error: {error}"),
                            }
                        };
                        sibling_closed_sender.send(closed).unwrap();
                    }
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        });

        let settings = CumulusSettings {
            server_url: format!("http://{address}"),
            token: "stream-token".into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 1_000,
        };
        let request_for = |spec: StreamSpec| {
            let connection = ConnectionCloser::default();
            ConnectionRequest {
                agent: build_agent(&settings, connection.clone()),
                connection,
                url: format!("{}{}?steam_id64=1", settings.server_url, spec.route),
                authorization: "Bearer stream-token".into(),
                client_id: "7".into(),
                spec,
            }
        };
        let playtime_request = request_for(StreamSpec {
            route: "/playtime-events",
            event_name: "playtime_snapshot",
            stream_name: "playtime",
        });
        let stats_request = request_for(StreamSpec {
            route: "/stats-events",
            event_name: "stats_wakeup",
            stream_name: "stats",
        });
        let cancellation = StreamCancellation::new();
        let mut baseline_calls = 0;
        let started = Instant::now();
        let outcome = connect_pair_once(
            &playtime_request,
            &stats_request,
            &cancellation,
            &mut || {
                baseline_calls += 1;
                Ok(empty_account_state())
            },
            &mut |_| {},
        );

        assert!(matches!(
            outcome,
            Connection::Disconnected { incremental: false }
        ));
        assert_eq!(baseline_calls, 1);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(sibling_closed_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap());
        server.join().unwrap();
    }

    #[test]
    fn account_streams_share_one_baseline_and_send_bound_identity() {
        use std::io::{Read, Write};
        use std::sync::{Condvar, Mutex};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let done = Arc::new((Mutex::new(false), Condvar::new()));
        let server_done = Arc::clone(&done);
        let server = std::thread::spawn(move || {
            let mut handlers = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request_sender = request_sender.clone();
                let done = Arc::clone(&server_done);
                handlers.push(std::thread::spawn(move || {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 2048];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let read = stream.read(&mut buffer).unwrap();
                        request.extend_from_slice(&buffer[..read]);
                    }
                    let request = String::from_utf8(request).unwrap();
                    request_sender.send(request.clone()).unwrap();
                    let frame = if request.contains("/playtime-events?") {
                        concat!(
                            "event: playtime_snapshot\n",
                            "data: {\"steam_id64\":\"76561198000000001\",",
                            "\"playtime_revision\":3,\"origin_client_id\":null,",
                            "\"playtime\":[]}\n\n"
                        )
                    } else {
                        concat!(
                            "event: stats_wakeup\n",
                            "data: {\"steam_id64\":\"76561198000000001\",",
                            "\"origin_client_id\":null,\"app_ids\":[480]}\n\n"
                        )
                    };
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{frame}"
                    )
                    .unwrap();
                    stream.flush().unwrap();
                    let (lock, changed) = &*done;
                    let mut finished = lock.lock().unwrap();
                    while !*finished {
                        finished = changed.wait(finished).unwrap();
                    }
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        });
        let settings = CumulusSettings {
            server_url: format!("http://{address}"),
            token: "stream-token".into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 1_000,
        };
        let cancellation = StreamCancellation::new();
        let cancel_after_events = cancellation.clone();
        let mut events = Vec::new();
        let mut baseline_calls = 0;
        let mut baseline = || {
            baseline_calls += 1;
            let mut baseline = empty_account_state();
            baseline.playtime_revision = 2;
            Ok(baseline)
        };
        let outcome = run_account(
            &settings,
            7,
            "76561198000000001",
            &cancellation,
            &mut baseline,
            &mut |event| {
                events.push(event);
                if events.len() == 3 {
                    cancel_after_events.cancel();
                }
            },
        )
        .unwrap();

        {
            let (lock, changed) = &*done;
            *lock.lock().unwrap() = true;
            changed.notify_all();
        }
        server.join().unwrap();
        assert_eq!(outcome, StreamOutcome::Stopped);
        assert_eq!(baseline_calls, 1);
        assert!(matches!(
            events.first(),
            Some(AccountStreamEvent::Baseline(_))
        ));
        assert!(events
            .iter()
            .any(|event| matches!(event, AccountStreamEvent::Playtime(_))));
        assert!(events
            .iter()
            .any(|event| matches!(event, AccountStreamEvent::StatsWakeup(_))));

        let requests = [
            request_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            request_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
        ];
        assert!(requests.iter().any(|request| request.starts_with(
            "GET /api/v1/device/playtime-events?steam_id64=76561198000000001 HTTP/1.1"
        )));
        assert!(requests.iter().any(|request| request
            .starts_with("GET /api/v1/device/stats-events?steam_id64=76561198000000001 HTTP/1.1")));
        for request in requests.map(|request| request.to_ascii_lowercase()) {
            assert!(request.contains("authorization: bearer stream-token"));
            assert!(request.contains("accept: text/event-stream"));
            assert!(request.contains("x-cumulus-steam-client-id: 7"));
        }
    }
}
