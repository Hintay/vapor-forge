// Asynchronous game-bridge client for the Steam runtime hook. A background
// worker authenticates with the per-launch token, sends diagnostics, and
// reconnects when transport fails. The bounded queue
// keeps socket failures off Wine loader threads; DLL injection remains
// independent of bridge availability.

use std::os::unix::net::UnixStream;
use std::sync::{mpsc, OnceLock};

use vapor_forge_game_bridge::{self as proto, Message};

use crate::loader::log;

static APP_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static OUTBOUND: OnceLock<mpsc::SyncSender<Message>> = OnceLock::new();
const OUTBOUND_CAPACITY: usize = 1024;

/// Ensure the non-blocking transport exists. It connects when data is queued.
pub fn try_connect() {
    let _ = outbound();
}

fn connect() -> Option<UnixStream> {
    let sock_path = match std::env::var(proto::ENV_GAME_BRIDGE_SOCK) {
        Ok(p) if !p.is_empty() => p,
        _ => return None,
    };
    let token_hex = match std::env::var(proto::ENV_GAME_BRIDGE_TOKEN) {
        Ok(t) if !t.is_empty() => t,
        _ => {
            log("ipc: no token, skipping");
            return None;
        }
    };
    let token = match proto::token_from_hex(&token_hex) {
        Some(t) => t,
        None => {
            log("ipc: invalid token hex");
            return None;
        }
    };

    let app_id = APP_ID.load(std::sync::atomic::Ordering::Acquire);

    let mut stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("ipc: connect failed: {e}"));
            return None;
        }
    };

    // Set a short read/write timeout so the game process doesn't stall.
    let timeout = std::time::Duration::from_millis(500);
    let _ = stream.set_write_timeout(Some(timeout));
    let _ = stream.set_read_timeout(Some(timeout));

    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() } as u32;
    let hello = Message::Hello { token, app_id, pid };
    if let Err(e) = proto::write_message(&mut stream, &hello) {
        log(&format!("ipc: hello send failed: {e}"));
        return None;
    }

    // Wait for ACK
    match proto::read_message(&mut stream) {
        Ok(Message::Ack) => {
            log(&format!("ipc: connected (app_id={app_id})"));
        }
        Ok(other) => {
            log(&format!("ipc: unexpected response: {other:?}"));
            return None;
        }
        Err(e) => {
            log(&format!("ipc: ack read failed: {e}"));
            return None;
        }
    }

    Some(stream)
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
    match outbound().try_send(msg) {
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

fn outbound() -> &'static mpsc::SyncSender<Message> {
    OUTBOUND.get_or_init(|| {
        APP_ID.store(
            parse_app_id_from_env(),
            std::sync::atomic::Ordering::Release,
        );
        let (sender, receiver) = mpsc::sync_channel(OUTBOUND_CAPACITY);
        if std::thread::Builder::new()
            .name("vapor-forge-game-bridge".into())
            .spawn(move || outbound_loop(receiver))
            .is_err()
        {
            log("ipc: failed to start outbound transport");
        }
        sender
    })
}

fn outbound_loop(receiver: mpsc::Receiver<Message>) {
    let mut stream = None;
    while let Ok(message) = receiver.recv() {
        loop {
            if stream.is_none() {
                stream = connect();
            }
            if stream
                .as_mut()
                .is_some_and(|current| proto::write_message(current, &message).is_ok())
            {
                break;
            }
            stream = None;
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
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
    use super::app_id_from_steam_game_id;

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
}
