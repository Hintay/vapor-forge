use std::io::Read;
#[cfg(target_family = "unix")]
use std::io::Write;
#[cfg(target_family = "unix")]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use vapor_forge_packet_capture::format_captured_summary_json;

use super::cli::{filter_suffix, Filters, OutputFormat};

pub(super) fn watch(socket: &str, filters: Filters, interval: Duration) -> Result<(), String> {
    let mut last_id = 0u64;
    loop {
        let command = format!("packet list{} --json", filter_suffix(&filters));
        let response = send_debug_command(socket, &command)?;
        let json = ok_payload(&response)?;
        let packets: serde_json::Value =
            serde_json::from_str(json).map_err(|error| format!("parse JSON failed: {error}"))?;
        let Some(array) = packets.as_array() else {
            return Err("packet list did not return an array".to_owned());
        };

        for packet in array {
            let Some(summary) = packet.get("summary") else {
                continue;
            };
            let id = summary
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if id <= last_id {
                continue;
            }
            println!("{}", format_captured_summary_json(summary));
            last_id = last_id.max(id);
        }

        std::thread::sleep(interval);
    }
}

pub(super) fn send_debug_command(socket: &str, command: &str) -> Result<String, String> {
    #[cfg(not(target_family = "unix"))]
    {
        let _ = (socket, command);
        return Err("debug API socket client is only available on Unix targets".to_owned());
    }

    #[cfg(target_family = "unix")]
    {
        let mut stream = UnixStream::connect(socket)
            .map_err(|error| format!("connect {socket} failed: {error}"))?;
        stream
            .write_all(command.as_bytes())
            .and_then(|_| stream.write_all(b"\n"))
            .map_err(|error| format!("write command failed: {error}"))?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| format!("shutdown write failed: {error}"))?;

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|error| format!("read response failed: {error}"))?;
        Ok(response.trim_end().to_owned())
    }
}

pub(super) fn print_response(response: &str, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            println!("{response}");
            Ok(())
        }
        OutputFormat::Json => {
            println!("{}", ok_payload(response)?);
            Ok(())
        }
    }
}

fn ok_payload(response: &str) -> Result<&str, String> {
    response
        .strip_prefix("ok ")
        .ok_or_else(|| response.to_owned())
}

pub(super) fn json_suffix(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Text => "",
        OutputFormat::Json => " --json",
    }
}

pub(super) fn default_socket_path() -> Result<String, String> {
    if let Ok(path) = std::env::var("VAPOR_FORGE_DEBUG_SOCKET") {
        if !path.is_empty() {
            return Ok(path);
        }
    }

    let runtime_dir =
        std::env::var("XDG_RUNTIME_DIR").map_err(|_| "XDG_RUNTIME_DIR is not set".to_owned())?;
    let uid = runtime_dir
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty() && part.as_bytes().iter().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| "could not derive uid from XDG_RUNTIME_DIR".to_owned())?;
    Ok(format!("/tmp/vapor-forge-{uid}/debug.sock"))
}
