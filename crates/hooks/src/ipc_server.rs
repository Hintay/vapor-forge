#![forbid(unsafe_code)]

// IPC server for vapor-forge-proton-inject helpers in Wine/Proton processes.
// It validates reusable per-launch tokens and dispatches diagnostics, Denuvo
// signals, and DLL injection results.

use std::collections::HashMap;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use vapor_forge_game_bridge::{self as proto, Message};

struct TokenEntry {
    app_id: u32,
    registered_at: Instant,
    seen_active: bool,
    // Multiple Wine child processes may share a token. An unused token expires
    // after startup grace; an active token remains valid until the app stops.
}

pub struct IpcServer {
    socket_path: String,
    tokens: Arc<Mutex<HashMap<[u8; proto::TOKEN_LEN], TokenEntry>>>,
    active_connections: Arc<AtomicUsize>,
}

const TOKEN_STARTUP_GRACE: Duration = Duration::from_secs(5 * 60);
const MAX_SESSION_TOKENS: usize = 1024;
const MAX_IPC_CONNECTIONS: usize = 128;

impl IpcServer {
    pub fn start() -> Option<Arc<Self>> {
        let socket_path = proto::default_socket_path()?;

        let dir = std::path::Path::new(&socket_path).parent()?;
        if let Err(error) = std::fs::create_dir_all(dir) {
            warn!(%error, path = %dir.display(), "ipc-server: failed to create socket directory");
            return None;
        }

        // Set directory permissions to 0700.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            {
                warn!(%error, path = %dir.display(), "ipc-server: failed to secure socket directory");
                return None;
            }
        }

        // Remove stale socket from a previous run.
        if let Err(error) = std::fs::remove_file(&socket_path) {
            if error.kind() != io::ErrorKind::NotFound {
                warn!(%error, path = %socket_path, "ipc-server: failed to remove stale socket");
                return None;
            }
        }

        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, "ipc-server: failed to bind socket");
                return None;
            }
        };
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            {
                warn!(%error, path = %socket_path, "ipc-server: failed to secure socket");
                drop(listener);
                let _ = std::fs::remove_file(&socket_path);
                return None;
            }
        }

        info!(path = %socket_path, "ipc-server: listening");

        let server = Arc::new(Self {
            socket_path,
            tokens: Arc::new(Mutex::new(HashMap::new())),
            active_connections: Arc::new(AtomicUsize::new(0)),
        });

        let srv = Arc::clone(&server);
        if let Err(error) = std::thread::Builder::new()
            .name("ipc-server".into())
            .spawn(move || srv.accept_loop(listener))
        {
            warn!(%error, "ipc-server: failed to start accept thread");
            return None;
        }

        Some(server)
    }

    /// Register a session token for an upcoming game launch.
    pub fn register_token(&self, token: [u8; proto::TOKEN_LEN], app_id: u32) {
        let Ok(mut tokens) = self.tokens.lock() else {
            warn!("ipc-server: token map lock poisoned");
            return;
        };
        let now = Instant::now();
        tokens.retain(|_, entry| {
            entry.seen_active
                || now.saturating_duration_since(entry.registered_at) < TOKEN_STARTUP_GRACE
        });
        if tokens.len() == MAX_SESSION_TOKENS {
            if let Some(oldest) = tokens
                .iter()
                .min_by_key(|(_, entry)| entry.registered_at)
                .map(|(token, _)| *token)
            {
                tokens.remove(&oldest);
            }
            warn!("ipc-server: token capacity reached, discarded oldest launch token");
        }
        tokens.insert(
            token,
            TokenEntry {
                app_id,
                registered_at: now,
                seen_active: false,
            },
        );
        debug!(app_id, "ipc-server: token registered");
    }

    pub fn revoke_stopped_app_tokens(&self, active_app_ids: &[u32]) {
        let Ok(mut tokens) = self.tokens.lock() else {
            warn!("ipc-server: token map lock poisoned");
            return;
        };
        update_session_tokens(&mut tokens, active_app_ids, Instant::now());
    }

    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    fn accept_loop(&self, listener: UnixListener) {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let Some(permit) =
                        ConnectionPermit::acquire(Arc::clone(&self.active_connections))
                    else {
                        warn!(
                            limit = MAX_IPC_CONNECTIONS,
                            "ipc-server: connection limit reached"
                        );
                        continue;
                    };
                    let tokens = Arc::clone(&self.tokens);
                    if let Err(error) = std::thread::Builder::new()
                        .name("ipc-conn".into())
                        .spawn(move || handle_connection(s, tokens, permit))
                    {
                        warn!(%error, "ipc-server: failed to spawn connection worker");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "ipc-server: accept error");
                }
            }
        }
    }
}

fn update_session_tokens(
    tokens: &mut HashMap<[u8; proto::TOKEN_LEN], TokenEntry>,
    active_app_ids: &[u32],
    now: Instant,
) {
    tokens.retain(|_, entry| {
        if active_app_ids.contains(&entry.app_id) {
            entry.seen_active = true;
            return true;
        }
        if entry.seen_active {
            return false;
        }
        now.saturating_duration_since(entry.registered_at) < TOKEN_STARTUP_GRACE
    });
}

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn acquire(active: Arc<AtomicUsize>) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_IPC_CONNECTIONS).then_some(current + 1)
            })
            .ok()?;
        Some(Self { active })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
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
    _permit: ConnectionPermit,
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
                    (app_id, pid)
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
            Message::DenuvoDetected { app_id: aid } if aid == app_id => {
                info!(app_id, pid, "ipc-server: Denuvo detected by helper");
                on_denuvo_detected(app_id);
            }
            Message::DllLoaded { app_id: aid, name } if aid == app_id => {
                debug!(app_id, dll = %name, pid, "ipc-server: DLL loaded");
            }
            Message::DllInjectResult {
                app_id: aid,
                success,
            } if aid == app_id => {
                if success {
                    info!(app_id, pid, "ipc-server: DLL injection succeeded");
                } else {
                    warn!(app_id, pid, "ipc-server: DLL injection failed");
                }
            }
            Message::PeSection {
                app_id: aid,
                section_name,
            } if aid == app_id => {
                debug!(
                    app_id,
                    section = %section_name,
                    pid,
                    "ipc-server: PE section reported"
                );
            }
            Message::DenuvoDetected { app_id: aid }
            | Message::DllLoaded { app_id: aid, .. }
            | Message::DllInjectResult { app_id: aid, .. }
            | Message::PeSection { app_id: aid, .. } => {
                warn!(
                    authenticated = app_id,
                    claimed = aid,
                    pid,
                    "ipc-server: message app_id mismatch"
                );
                break;
            }
            _ => {
                debug!(?msg, "ipc-server: unexpected message from client");
            }
        }
    }
}

/// Called when a vapor-forge-proton-inject helper detects Denuvo in a game process.
fn on_denuvo_detected(app_id: u32) {
    let cfg = crate::client::install::config();
    if !cfg.ticket.auto_delegate {
        info!(
            app_id,
            "ipc-server: Denuvo detected (auto_delegate off, no action taken)"
        );
        return;
    }

    let aid = vapor_forge_config::AppId(app_id);
    if cfg.ticket_mode(aid) == vapor_forge_config::TicketMode::Delegate {
        debug!(app_id, "ipc-server: app already in delegate mode");
        return;
    }

    vapor_forge_features::ticket::add_auto_delegate(aid);
    info!(app_id, "ipc-server: Denuvo detected, auto-delegate enabled");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(app_id: u32, registered_at: Instant) -> TokenEntry {
        TokenEntry {
            app_id,
            registered_at,
            seen_active: false,
        }
    }

    #[test]
    fn launch_token_survives_until_first_active_update() {
        let now = Instant::now();
        let mut tokens = HashMap::from([([1; proto::TOKEN_LEN], entry(480, now))]);

        update_session_tokens(&mut tokens, &[], now);
        assert_eq!(tokens.len(), 1);

        update_session_tokens(&mut tokens, &[480], now);
        let token = tokens.values().next().unwrap();
        assert!(token.seen_active);

        update_session_tokens(&mut tokens, &[], now);
        assert!(tokens.is_empty());
    }

    #[test]
    fn launch_token_expires_if_game_never_becomes_active() {
        let now = Instant::now();
        let registered_at = now.checked_sub(TOKEN_STARTUP_GRACE).unwrap();
        let mut tokens = HashMap::from([([1; proto::TOKEN_LEN], entry(480, registered_at))]);

        update_session_tokens(&mut tokens, &[], now);
        assert!(tokens.is_empty());
    }

    #[test]
    fn connection_permits_enforce_and_release_the_limit() {
        let active = Arc::new(AtomicUsize::new(MAX_IPC_CONNECTIONS - 1));
        let permit = ConnectionPermit::acquire(Arc::clone(&active)).unwrap();
        assert!(ConnectionPermit::acquire(Arc::clone(&active)).is_none());
        drop(permit);
        assert_eq!(active.load(Ordering::Acquire), MAX_IPC_CONNECTIONS - 1);
    }
}
