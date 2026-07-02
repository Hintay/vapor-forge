// IPC client for communicating with the main vapor-forge process.
// Connects to a Unix domain socket, authenticates with a per-launch token,
// then sends PE analysis results and DLL injection status.
//
// Gracefully degrades: if the socket is unavailable or the env vars are
// missing, all operations are silent no-ops. DLL injection still works
// without IPC.

use std::os::unix::net::UnixStream;
use std::sync::Mutex;

use vapor_forge_inject_protocol::{self as proto, Message};

use crate::loader::log;

static CLIENT: Mutex<Option<UnixStream>> = Mutex::new(None);
static APP_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Try to establish an IPC connection. Called once during initialization.
/// Returns silently if env vars are missing or the socket is unreachable.
pub fn try_connect() {
    let sock_path = match std::env::var(proto::ENV_IPC_SOCK) {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };
    let token_hex = match std::env::var(proto::ENV_IPC_TOKEN) {
        Ok(t) if !t.is_empty() => t,
        _ => {
            log("ipc: no token, skipping");
            return;
        }
    };
    let token = match proto::token_from_hex(&token_hex) {
        Some(t) => t,
        None => {
            log("ipc: invalid token hex");
            return;
        }
    };

    let app_id = parse_app_id_from_env();
    APP_ID.store(app_id, std::sync::atomic::Ordering::Release);

    let mut stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("ipc: connect failed: {e}"));
            return;
        }
    };

    // Set a short read/write timeout so the game process doesn't stall.
    let timeout = std::time::Duration::from_millis(500);
    let _ = stream.set_write_timeout(Some(timeout));
    let _ = stream.set_read_timeout(Some(timeout));

    let pid = unsafe { libc::getpid() } as u32;
    let hello = Message::Hello { token, app_id, pid };
    if let Err(e) = proto::write_message(&mut stream, &hello) {
        log(&format!("ipc: hello send failed: {e}"));
        return;
    }

    // Wait for ACK
    match proto::read_message(&mut stream) {
        Ok(Message::Ack) => {
            log(&format!("ipc: connected (app_id={app_id})"));
        }
        Ok(other) => {
            log(&format!("ipc: unexpected response: {other:?}"));
            return;
        }
        Err(e) => {
            log(&format!("ipc: ack read failed: {e}"));
            return;
        }
    }

    *CLIENT.lock().unwrap() = Some(stream);
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

fn send(msg: Message) {
    let mut guard = CLIENT.lock().unwrap();
    let Some(stream) = guard.as_mut() else {
        return;
    };
    if let Err(e) = proto::write_message(stream, &msg) {
        log(&format!("ipc: send failed: {e}"));
        // Drop the broken connection.
        *guard = None;
    }
}

/// Parse app_id from CGameID-style env or fallback.
/// Steam sets SteamGameId in the child env block.
fn parse_app_id_from_env() -> u32 {
    std::env::var("SteamGameId")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0)
}
