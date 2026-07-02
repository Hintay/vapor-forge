use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use tracing::{info, warn};

const SOCK_FILE_NAME: &str = "debug.sock";
const MAX_COMMAND_LEN: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

static STARTED: OnceLock<()> = OnceLock::new();
static SOCKET_PATH: OnceLock<String> = OnceLock::new();

pub fn start() {
    let _ = STARTED.get_or_init(|| {
        if !current_process_is_steam() {
            info!("debug-api: skipped outside steam process");
            return;
        }

        let Some(socket_path) = default_socket_path() else {
            warn!("debug-api: XDG_RUNTIME_DIR is not set");
            return;
        };

        let Some(dir) = Path::new(&socket_path).parent() else {
            warn!("debug-api: socket path has no parent");
            return;
        };
        if let Err(e) = std::fs::create_dir_all(dir) {
            warn!(error = %e, path = %dir.display(), "debug-api: failed to create socket dir");
            return;
        }
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        if !remove_stale_socket(&socket_path) {
            return;
        }

        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(e) => {
                warn!(error = %e, path = %socket_path, "debug-api: failed to bind socket");
                return;
            }
        };
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
        let _ = SOCKET_PATH.set(socket_path.clone());

        if let Err(e) = std::thread::Builder::new()
            .name("debug-api".into())
            .spawn(move || accept_loop(listener))
        {
            warn!(error = %e, "debug-api: failed to spawn accept thread");
            return;
        }

        info!(path = %socket_path, "debug-api: listening");
    });
}

pub(crate) fn socket_path() -> Option<&'static str> {
    SOCKET_PATH.get().map(String::as_str)
}

fn accept_loop(listener: UnixListener) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = std::thread::Builder::new()
                    .name("debug-api-conn".into())
                    .spawn(move || handle_connection(stream))
                {
                    warn!(error = %e, "debug-api: failed to spawn connection thread");
                }
            }
            Err(e) => warn!(error = %e, "debug-api: accept error"),
        }
    }
}

fn handle_connection(mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let reader_stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(e) => {
            let _ = writeln!(stream, "err clone failed: {e}");
            return;
        }
    };
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.len() > MAX_COMMAND_LEN {
                    let _ = writeln!(stream, "err command too long");
                    break;
                }
                let response = super::command::dispatch(line.trim_end_matches(['\r', '\n']));
                if writeln!(stream, "{response}").is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = writeln!(stream, "err read failed: {e}");
                break;
            }
        }
    }
}

pub(crate) fn default_socket_path() -> Option<String> {
    if let Ok(path) = std::env::var("VAPOR_FORGE_DEBUG_SOCKET") {
        if !path.is_empty() {
            return Some(path);
        }
    }

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok()?;
    let uid = runtime_dir.rsplit('/').next().filter(|part| {
        !part.is_empty() && part.as_bytes().iter().all(|byte| byte.is_ascii_digit())
    })?;
    Some(format!("/tmp/vapor-forge-{uid}/{SOCK_FILE_NAME}"))
}

fn remove_stale_socket(socket_path: &str) -> bool {
    match std::fs::symlink_metadata(socket_path) {
        Ok(meta) if meta.file_type().is_socket() => match std::fs::remove_file(socket_path) {
            Ok(()) => true,
            Err(e) => {
                warn!(error = %e, path = %socket_path, "debug-api: failed to remove stale socket");
                false
            }
        },
        Ok(_) => {
            warn!(path = %socket_path, "debug-api: refusing to replace non-socket path");
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            warn!(error = %e, path = %socket_path, "debug-api: failed to stat socket path");
            false
        }
    }
}

fn current_process_is_steam() -> bool {
    std::fs::read_to_string("/proc/self/comm")
        .map(|comm| comm.trim() == "steam")
        .unwrap_or(false)
}

#[cfg(test)]
pub(crate) fn debug_target_from_comm(comm: &str) -> Option<super::DebugTarget> {
    match comm.trim() {
        "steam" => Some(super::DebugTarget::SteamClient),
        "steamui" => Some(super::DebugTarget::SteamUi),
        _ => None,
    }
}
