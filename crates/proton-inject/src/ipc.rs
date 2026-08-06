// Asynchronous game-bridge client for the Steam runtime hook. A background
// worker authenticates with the per-launch token and sends diagnostics. The
// bounded queue keeps socket failures off Wine loader threads; DLL injection
// remains independent of bridge availability.

use std::os::unix::net::UnixStream;
use std::sync::{mpsc, OnceLock};
use std::time::{Duration, Instant};

use vapor_forge_game_bridge::{self as proto, Message};

use crate::loader::log;

static APP_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static OUTBOUND: OnceLock<Option<mpsc::SyncSender<Message>>> = OnceLock::new();
const OUTBOUND_CAPACITY: usize = 1024;
const CONNECT_WINDOW: Duration = Duration::from_secs(10);
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(25);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(1);

struct LaunchSession {
    socket_path: String,
    token: [u8; proto::TOKEN_LEN],
    app_id: u32,
    connect_deadline: Instant,
}

impl LaunchSession {
    fn from_environment() -> Option<Self> {
        let socket_path = match std::env::var(proto::ENV_GAME_BRIDGE_SOCK) {
            Ok(path) if !path.is_empty() => path,
            _ => return None,
        };
        let token_hex = match std::env::var(proto::ENV_GAME_BRIDGE_TOKEN) {
            Ok(token) if !token.is_empty() => token,
            _ => {
                log("ipc: no launch token");
                return None;
            }
        };
        let token = match proto::token_from_hex(&token_hex) {
            Some(token) => token,
            None => {
                log("ipc: invalid launch token");
                return None;
            }
        };
        let app_id = parse_app_id_from_env();
        APP_ID.store(app_id, std::sync::atomic::Ordering::Release);
        Some(Self {
            socket_path,
            token,
            app_id,
            connect_deadline: Instant::now() + CONNECT_WINDOW,
        })
    }
}

enum ConnectResult {
    Connected(UnixStream),
    Retryable,
    Terminal,
}

/// Ensure the non-blocking transport exists. It connects when data is queued.
pub fn try_connect() {
    let _ = outbound();
}

fn connect(session: &LaunchSession) -> ConnectResult {
    let mut stream = match UnixStream::connect(&session.socket_path) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("ipc: connect failed: {e}"));
            return if retryable_connect_error(e.kind()) {
                ConnectResult::Retryable
            } else {
                ConnectResult::Terminal
            };
        }
    };

    // Set a short read/write timeout so the game process doesn't stall.
    let timeout = std::time::Duration::from_millis(500);
    let _ = stream.set_write_timeout(Some(timeout));
    let _ = stream.set_read_timeout(Some(timeout));

    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() } as u32;
    let hello = Message::Hello {
        token: session.token,
        app_id: session.app_id,
        pid,
    };
    if let Err(e) = proto::write_message(&mut stream, &hello) {
        log(&format!("ipc: hello send failed: {e}"));
        return ConnectResult::Retryable;
    }

    // Wait for ACK
    match proto::read_message(&mut stream) {
        Ok(Message::Ack) => {
            log(&format!("ipc: connected (app_id={})", session.app_id));
        }
        Ok(other) => {
            log(&format!("ipc: unexpected response: {other:?}"));
            return ConnectResult::Terminal;
        }
        Err(e) => {
            log(&format!("ipc: ack read failed: {e}"));
            return ConnectResult::Terminal;
        }
    }

    ConnectResult::Connected(stream)
}

fn retryable_connect_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
    )
}

/// Report that a Denuvo indicator was found.
pub fn send_denuvo_detected() {
    let app_id = APP_ID.load(std::sync::atomic::Ordering::Acquire);
    send(Message::DenuvoDetected { app_id });
}

/// Report a loaded DLL name.
pub fn send_dll_loaded(name: &str) {
    let app_id = APP_ID.load(std::sync::atomic::Ordering::Acquire);
    send(Message::DllLoaded {
        app_id,
        name: name.to_owned(),
    });
}

/// Report DLL injection result.
pub fn send_dll_inject_result(success: bool) {
    let app_id = APP_ID.load(std::sync::atomic::Ordering::Acquire);
    send(Message::DllInjectResult { app_id, success });
}

/// Report a PE section name.
pub fn send_pe_section(section_name: &str) {
    let app_id = APP_ID.load(std::sync::atomic::Ordering::Acquire);
    send(Message::PeSection {
        app_id,
        section_name: section_name.to_owned(),
    });
}

fn send(msg: Message) -> bool {
    let Some(outbound) = outbound() else {
        return false;
    };
    match outbound.try_send(msg) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(_)) => {
            log("ipc: outbound queue full, dropping message");
            false
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            log("ipc: outbound transport unavailable");
            false
        }
    }
}

fn outbound() -> Option<&'static mpsc::SyncSender<Message>> {
    OUTBOUND
        .get_or_init(|| {
            let session = LaunchSession::from_environment()?;
            let (sender, receiver) = mpsc::sync_channel(OUTBOUND_CAPACITY);
            if std::thread::Builder::new()
                .name("vapor-forge-game-bridge".into())
                .spawn(move || outbound_loop(receiver, session))
                .is_err()
            {
                log("ipc: failed to start outbound transport");
                return None;
            }
            Some(sender)
        })
        .as_ref()
}

fn outbound_loop(receiver: mpsc::Receiver<Message>, session: LaunchSession) {
    let mut stream = None;
    let mut retry_delay = INITIAL_RETRY_DELAY;
    while let Ok(message) = receiver.recv() {
        loop {
            if stream.is_none() {
                match connect(&session) {
                    ConnectResult::Connected(connected) => {
                        stream = Some(connected);
                        retry_delay = INITIAL_RETRY_DELAY;
                    }
                    ConnectResult::Retryable => {
                        if !wait_for_retry(session.connect_deadline, retry_delay) {
                            log("ipc: launch connection window expired");
                            return;
                        }
                        retry_delay = next_retry_delay(retry_delay);
                        continue;
                    }
                    ConnectResult::Terminal => {
                        log("ipc: launch session rejected");
                        return;
                    }
                }
            }
            if stream
                .as_mut()
                .is_some_and(|current| proto::write_message(current, &message).is_ok())
            {
                break;
            }
            stream = None;
            if !wait_for_retry(session.connect_deadline, retry_delay) {
                log("ipc: launch connection ended");
                return;
            }
            retry_delay = next_retry_delay(retry_delay);
        }
    }
}

fn wait_for_retry(deadline: Instant, delay: Duration) -> bool {
    let now = Instant::now();
    let Some(remaining) = deadline.checked_duration_since(now) else {
        return false;
    };
    std::thread::sleep(delay.min(remaining));
    Instant::now() < deadline
}

fn next_retry_delay(current: Duration) -> Duration {
    current.saturating_mul(2).min(MAX_RETRY_DELAY)
}

/// Parse app_id from CGameID-style env or fallback.
/// Steam sets SteamGameId in the child env block.
fn parse_app_id_from_env() -> u32 {
    std::env::var("SteamGameId")
        .ok()
        .and_then(|value| app_id_from_steam_game_id(&value))
        .unwrap_or(0)
}

fn app_id_from_steam_game_id(value: &str) -> Option<u32> {
    let game_id = value.parse::<u64>().ok()?;
    let app_id = game_id as u32 & 0x00ff_ffff;
    (app_id != 0).then_some(app_id)
}

#[cfg(test)]
mod tests {
    use super::{
        app_id_from_steam_game_id, next_retry_delay, INITIAL_RETRY_DELAY, MAX_RETRY_DELAY,
    };

    #[test]
    fn extracts_app_id_from_steam_game_id() {
        assert_eq!(app_id_from_steam_game_id("736260"), Some(736_260));
        assert_eq!(
            app_id_from_steam_game_id(&((2_u64 << 24) | 736_260).to_string()),
            Some(736_260)
        );
        assert_eq!(app_id_from_steam_game_id("0"), None);
        assert_eq!(app_id_from_steam_game_id("invalid"), None);
    }

    #[test]
    fn connection_retry_delay_is_exponential_and_capped() {
        let mut delay = INITIAL_RETRY_DELAY;
        for _ in 0..16 {
            delay = next_retry_delay(delay);
        }
        assert_eq!(delay, MAX_RETRY_DELAY);
    }
}
