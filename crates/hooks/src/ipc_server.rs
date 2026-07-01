// IPC server: accepts connections from proton-inject helper processes
// running inside Wine/Proton game instances. Validates per-launch tokens
// and dispatches messages (Denuvo detection, DLL load events).

use std::collections::HashMap;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use inject_protocol::{self as proto, Message};
use tracing::{debug, info, warn};

struct TokenEntry {
    app_id: u32,
    // Token stays valid for the entire game session. Multiple Wine child
    // processes (launcher, game, overlay) may connect with the same token.
}

pub struct IpcServer {
    socket_path: String,
    tokens: Arc<Mutex<HashMap<[u8; proto::TOKEN_LEN], TokenEntry>>>,
}

impl IpcServer {
    pub fn start() -> Option<Arc<Self>> {
        let socket_path = proto::default_socket_path()?;

        let dir = std::path::Path::new(&socket_path).parent()?;
        let _ = std::fs::create_dir_all(dir);

        // Set directory permissions to 0700.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }

        // Remove stale socket from a previous run.
        let _ = std::fs::remove_file(&socket_path);

        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, "ipc-server: failed to bind socket");
                return None;
            }
        };

        info!(path = %socket_path, "ipc-server: listening");

        let server = Arc::new(Self {
            socket_path,
            tokens: Arc::new(Mutex::new(HashMap::new())),
        });

        let srv = Arc::clone(&server);
        std::thread::Builder::new()
            .name("ipc-server".into())
            .spawn(move || srv.accept_loop(listener))
            .ok()?;

        Some(server)
    }

    /// Register a session token for an upcoming game launch.
    pub fn register_token(&self, token: [u8; proto::TOKEN_LEN], app_id: u32) {
        let Ok(mut tokens) = self.tokens.lock() else {
            warn!("ipc-server: token map lock poisoned");
            return;
        };
        tokens.insert(token, TokenEntry { app_id });
        debug!(app_id, "ipc-server: token registered");
    }

    /// Remove a token when the game exits (called from CMsgClientGamesPlayed).
    pub fn revoke_app_tokens(&self, app_id: u32) {
        let Ok(mut tokens) = self.tokens.lock() else {
            warn!("ipc-server: token map lock poisoned");
            return;
        };
        tokens.retain(|_, e| e.app_id != app_id);
    }

    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    fn accept_loop(&self, listener: UnixListener) {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let tokens = Arc::clone(&self.tokens);
                    std::thread::Builder::new()
                        .name("ipc-conn".into())
                        .spawn(move || handle_connection(s, tokens))
                        .ok();
                }
                Err(e) => {
                    warn!(error = %e, "ipc-server: accept error");
                }
            }
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn handle_connection(
    mut stream: UnixStream,
    tokens: Arc<Mutex<HashMap<[u8; proto::TOKEN_LEN], TokenEntry>>>,
) {
    let timeout = Duration::from_secs(5);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    // First message must be HELLO.
    let hello = match proto::read_message(&mut stream) {
        Ok(m) => m,
        Err(e) => {
            debug!(error = %e, "ipc-server: read hello failed");
            return;
        }
    };

    let (app_id, pid) = match hello {
        Message::Hello { token, app_id, pid } => {
            // Validate the session token. Don't remove it: multiple Wine
            // child processes (launcher, game, overlay) share the same
            // env and may connect with the same token. Tokens are revoked
            // when the game exits via CMsgClientGamesPlayed.
            let Ok(guard) = tokens.lock() else {
                warn!("ipc-server: token map lock poisoned");
                return;
            };
            match guard.get(&token) {
                Some(e) if e.app_id == app_id => {
                    info!(app_id, pid, "ipc-server: client authenticated");
                }
                Some(e) => {
                    warn!(
                        claimed = app_id,
                        expected = e.app_id,
                        "ipc-server: app_id mismatch"
                    );
                    return;
                }
                None => {
                    warn!(app_id, pid, "ipc-server: invalid token");
                    return;
                }
            }
            drop(guard);
            (app_id, pid)
        }
        _ => {
            warn!("ipc-server: first message was not HELLO");
            return;
        }
    };

    // Send ACK.
    if let Err(e) = proto::write_message(&mut stream, &Message::Ack) {
        warn!(error = %e, "ipc-server: ack send failed");
        return;
    }

    // Longer timeout for the message loop.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));

    loop {
        let msg = match proto::read_message(&mut stream) {
            Ok(m) => m,
            Err(proto::DecodeError::Io(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                debug!(app_id, pid, "ipc-server: client disconnected");
                break;
            }
            Err(proto::DecodeError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                debug!(app_id, pid, error = %e, "ipc-server: read error");
                break;
            }
        };

        match msg {
            Message::DenuvoDetected { app_id: aid } => {
                info!(app_id = aid, pid, "ipc-server: Denuvo detected by helper");
                on_denuvo_detected(aid);
            }
            Message::DllLoaded { app_id: aid, name } => {
                debug!(app_id = aid, dll = %name, pid, "ipc-server: DLL loaded");
            }
            Message::DllInjectResult {
                app_id: aid,
                success,
            } => {
                if success {
                    info!(app_id = aid, pid, "ipc-server: DLL injection succeeded");
                } else {
                    warn!(app_id = aid, pid, "ipc-server: DLL injection failed");
                }
            }
            Message::PeSection {
                app_id: aid,
                section_name,
            } => {
                debug!(
                    app_id = aid,
                    section = %section_name,
                    pid,
                    "ipc-server: PE section reported"
                );
            }
            _ => {
                debug!(?msg, "ipc-server: unexpected message from client");
            }
        }
    }
}

/// Called when a proton-inject helper detects Denuvo in a game process.
fn on_denuvo_detected(app_id: u32) {
    let cfg = crate::install::config();
    if !cfg.ticket.auto_delegate {
        info!(
            app_id,
            "ipc-server: Denuvo detected (auto_delegate off, no action taken)"
        );
        return;
    }

    let aid = steam_runtime_config::AppId(app_id);
    if cfg.ticket_mode(aid) == steam_runtime_config::TicketMode::Delegate {
        debug!(app_id, "ipc-server: app already in delegate mode");
        return;
    }

    steam_runtime_features::ticket::add_auto_delegate(aid);
    info!(app_id, "ipc-server: Denuvo detected, auto-delegate enabled");
}
