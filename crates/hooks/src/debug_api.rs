use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use tracing::{info, warn};

const SOCK_FILE_NAME: &str = "debug.sock";
const DEFAULT_TOAST_BODY: &str = "Debug API toast";
const DEFAULT_DURATION_MS: u32 = 5000;
const MAX_COMMAND_LEN: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

static STARTED: OnceLock<()> = OnceLock::new();
static SOCKET_PATH: OnceLock<String> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebugTarget {
    SteamClient,
    SteamUi,
}

#[derive(Debug, Eq, PartialEq)]
enum DebugCommand<'a> {
    Help,
    Ping,
    Dump,
    Toast(ToastArgs<'a>),
    Unknown(&'a str),
}

#[derive(Debug, Eq, PartialEq)]
enum ToastArgs<'a> {
    Default,
    Fields(&'a str),
}

impl DebugTarget {
    fn name(self) -> &'static str {
        match self {
            DebugTarget::SteamClient => "steamclient",
            DebugTarget::SteamUi => "steamui",
        }
    }
}

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
                let response = dispatch(line.trim_end_matches(['\r', '\n']));
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

fn dispatch(command: &str) -> String {
    let trimmed = command.trim();
    if trimmed.is_empty() || trimmed == "help" {
        return help_response();
    }
    if let Some(command) = strip_target(trimmed, "steamui").or_else(|| strip_target(trimmed, "ui"))
    {
        return dispatch_local(DebugTarget::SteamUi, command);
    }
    if let Some(command) =
        strip_target(trimmed, "steamclient").or_else(|| strip_target(trimmed, "client"))
    {
        return dispatch_local(DebugTarget::SteamClient, command);
    }
    if is_toast_command(trimmed) {
        return dispatch_local(DebugTarget::SteamUi, trimmed);
    }
    dispatch_local(DebugTarget::SteamClient, trimmed)
}

fn dispatch_local(target: DebugTarget, command: &str) -> String {
    match parse_command(command) {
        DebugCommand::Help => help_response(),
        DebugCommand::Ping => "ok pong".to_owned(),
        DebugCommand::Dump => dump_response(target),
        DebugCommand::Toast(args) => queue_toast_command(target, args),
        DebugCommand::Unknown(command) => format!("err unknown command: {command}"),
    }
}

fn strip_target<'a>(command: &'a str, target: &str) -> Option<&'a str> {
    command
        .strip_prefix(target)
        .and_then(|rest| rest.strip_prefix(char::is_whitespace))
        .map(str::trim)
}

fn is_toast_command(command: &str) -> bool {
    command == "toast" || command.starts_with("toast ")
}

fn parse_command(command: &str) -> DebugCommand<'_> {
    let trimmed = command.trim();
    if trimmed.is_empty() || trimmed == "help" {
        return DebugCommand::Help;
    }
    if trimmed == "ping" {
        return DebugCommand::Ping;
    }
    if trimmed == "dump" || trimmed == "status" {
        return DebugCommand::Dump;
    }
    if trimmed == "toast" {
        return DebugCommand::Toast(ToastArgs::Default);
    }
    if let Some(args) = trimmed.strip_prefix("toast ") {
        return DebugCommand::Toast(ToastArgs::Fields(args));
    }
    DebugCommand::Unknown(trimmed)
}

fn queue_toast_command(target: DebugTarget, args: ToastArgs<'_>) -> String {
    if target != DebugTarget::SteamUi {
        return "err toast is a steamui command".to_owned();
    }

    match args {
        ToastArgs::Default => {
            vapor_forge_features::toast::show_toast_with_kind(
                vapor_forge_features::toast::ToastKind::Info,
                "Vapor Forge",
                DEFAULT_TOAST_BODY,
                None,
                DEFAULT_DURATION_MS,
            );
            request_target_pump(target);
            "ok queued toast".to_owned()
        }
        ToastArgs::Fields(args) => match queue_toast_fields(args) {
            Ok(response) => response,
            Err(e) => e,
        },
    }
}

fn queue_toast_fields(args: &str) -> Result<String, String> {
    let parsed = parse_toast_args(args)?;

    if let Some(style) = parsed.style {
        vapor_forge_features::toast::show_toast_with_style(
            parsed.kind,
            style,
            &parsed.title,
            &parsed.body,
            parsed.icon.as_deref(),
            parsed.duration_ms,
        );
    } else {
        vapor_forge_features::toast::show_toast_with_kind(
            parsed.kind,
            &parsed.title,
            &parsed.body,
            parsed.icon.as_deref(),
            parsed.duration_ms,
        );
    }
    request_target_pump(DebugTarget::SteamUi);
    Ok(format!(
        "ok queued toast kind={} style={} title={} body={} duration_ms={}",
        toast_kind_name(parsed.kind),
        toast_style_name(
            parsed
                .style
                .unwrap_or_else(|| default_toast_style(parsed.kind))
        ),
        quote_text(&parsed.title),
        quote_text(&parsed.body),
        parsed.duration_ms
    ))
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedToast {
    kind: vapor_forge_features::toast::ToastKind,
    style: Option<vapor_forge_features::toast::ToastStyle>,
    title: String,
    body: String,
    duration_ms: u32,
    icon: Option<String>,
}

fn parse_toast_args(args: &str) -> Result<ParsedToast, String> {
    let tokens = tokenize_toast_args(args)?;
    let mut kind = vapor_forge_features::toast::ToastKind::Info;
    let mut style = None;
    let mut title: Option<String> = None;
    let mut body: Option<String> = None;
    let mut duration_ms = DEFAULT_DURATION_MS;
    let mut icon: Option<String> = None;
    let mut body_words = Vec::new();
    let mut index = 0;

    while index < tokens.len() {
        if let Some(parsed_kind) = parse_toast_kind(&tokens[index]) {
            kind = parsed_kind;
            index += 1;
            continue;
        }
        if let Some(parsed_style) = parse_toast_style(&tokens[index]) {
            style = Some(parsed_style);
            index += 1;
            continue;
        }
        break;
    }

    while index < tokens.len() {
        if token_is_toast_option(&tokens[index]) {
            let (key, value, next_index) = parse_toast_option(&tokens, index)?;
            apply_toast_option(
                key,
                value,
                &mut kind,
                &mut style,
                &mut title,
                &mut body,
                &mut duration_ms,
                &mut icon,
            )?;
            index = next_index;
        } else {
            body_words.push(tokens[index].as_str());
            index += 1;
        }
    }

    if body.is_none() && !body_words.is_empty() {
        body = Some(body_words.join(" "));
    }

    Ok(ParsedToast {
        kind,
        style,
        title: non_empty(title.as_deref().unwrap_or(""), "Vapor Forge").to_owned(),
        body: non_empty(body.as_deref().unwrap_or(""), DEFAULT_TOAST_BODY).to_owned(),
        duration_ms,
        icon,
    })
}

fn token_is_toast_option(token: &str) -> bool {
    token.starts_with("--") || token.contains('=')
}

fn parse_toast_option(tokens: &[String], index: usize) -> Result<(&str, &str, usize), String> {
    let token = tokens[index].as_str();
    if let Some(option) = token.strip_prefix("--") {
        if let Some((key, value)) = option.split_once('=') {
            return Ok((key, value, index + 1));
        }
        let Some(value) = tokens.get(index + 1) else {
            return Err(format!(
                "err missing value for toast option: {}",
                quote_text(token)
            ));
        };
        return Ok((option, value, index + 2));
    }
    if let Some((key, value)) = token.split_once('=') {
        return Ok((key, value, index + 1));
    }
    Err(format!("err invalid toast option: {}", quote_text(token)))
}

fn apply_toast_option(
    key: &str,
    value: &str,
    kind: &mut vapor_forge_features::toast::ToastKind,
    style: &mut Option<vapor_forge_features::toast::ToastStyle>,
    title: &mut Option<String>,
    body: &mut Option<String>,
    duration_ms: &mut u32,
    icon: &mut Option<String>,
) -> Result<(), String> {
    match key.trim().to_ascii_lowercase().as_str() {
        "kind" | "type" => {
            *kind = parse_toast_kind(value)
                .ok_or_else(|| format!("err invalid toast kind: {}", quote_text(value)))?;
        }
        "style" => {
            *style = Some(
                parse_toast_style(value)
                    .ok_or_else(|| format!("err invalid toast style: {}", quote_text(value)))?,
            );
        }
        "title" => *title = Some(value.to_owned()),
        "body" | "message" | "text" => *body = Some(value.to_owned()),
        "duration" | "duration_ms" | "ms" => *duration_ms = parse_duration(value)?,
        "icon" => *icon = Some(value.to_owned()),
        _ => return Err(format!("err unknown toast option: {}", quote_text(key))),
    }
    Ok(())
}

fn tokenize_toast_args(args: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for ch in args.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(quote_char) = quote {
            if ch == quote_char {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }

    if escaped {
        current.push('\\');
    }
    if quote.is_some() {
        return Err("err unterminated quote in toast command".to_owned());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn parse_toast_kind(value: &str) -> Option<vapor_forge_features::toast::ToastKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" | "normal" => Some(vapor_forge_features::toast::ToastKind::Info),
        "warning" | "warn" => Some(vapor_forge_features::toast::ToastKind::Warning),
        "error" | "err" => Some(vapor_forge_features::toast::ToastKind::Error),
        _ => None,
    }
}

fn parse_toast_style(value: &str) -> Option<vapor_forge_features::toast::ToastStyle> {
    match value.trim().to_ascii_lowercase().as_str() {
        "accent" => Some(vapor_forge_features::toast::ToastStyle::Accent),
        "banner" => Some(vapor_forge_features::toast::ToastStyle::Banner),
        _ => None,
    }
}

fn default_toast_style(
    kind: vapor_forge_features::toast::ToastKind,
) -> vapor_forge_features::toast::ToastStyle {
    match kind {
        vapor_forge_features::toast::ToastKind::Info => {
            vapor_forge_features::toast::ToastStyle::Accent
        }
        vapor_forge_features::toast::ToastKind::Warning
        | vapor_forge_features::toast::ToastKind::Error => {
            vapor_forge_features::toast::ToastStyle::Banner
        }
    }
}

fn toast_kind_name(kind: vapor_forge_features::toast::ToastKind) -> &'static str {
    match kind {
        vapor_forge_features::toast::ToastKind::Info => "info",
        vapor_forge_features::toast::ToastKind::Warning => "warning",
        vapor_forge_features::toast::ToastKind::Error => "error",
    }
}

fn toast_style_name(style: vapor_forge_features::toast::ToastStyle) -> &'static str {
    match style {
        vapor_forge_features::toast::ToastStyle::Accent => "accent",
        vapor_forge_features::toast::ToastStyle::Banner => "banner",
    }
}

fn request_target_pump(target: DebugTarget) {
    if target == DebugTarget::SteamUi {
        crate::ui::toast_bridge::request_pump();
    }
}

fn non_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

fn parse_duration(value: &str) -> Result<u32, String> {
    if value.is_empty() {
        return Ok(DEFAULT_DURATION_MS);
    }
    value
        .parse::<u32>()
        .map_err(|_| format!("err invalid duration_ms: {}", quote_text(value)))
}

fn help_response() -> String {
    "ok commands: help; ping; dump/status; steamclient <command>; steamui <command>; toast; toast <body>; toast kind=warning style=banner title=\"Title\" body=\"Body\" duration=8000 icon=\"URL\"; toast warning banner --title \"Title\" --body \"Body\" --duration 8000"
        .to_owned()
}

fn dump_response(target: DebugTarget) -> String {
    format!(
        "ok {{\"debug\":{{\"target\":\"{}\",\"socket\":\"{}\"}},\"toast\":{{\"pending\":{},\"has_work\":{}}}}}",
        target.name(),
        json_escape(SOCKET_PATH.get().map(String::as_str).unwrap_or("")),
        vapor_forge_features::toast::pending_count(),
        vapor_forge_features::toast::has_pending_work()
    )
}

fn default_socket_path() -> Option<String> {
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
fn debug_target_from_comm(comm: &str) -> Option<DebugTarget> {
    match comm.trim() {
        "steam" => Some(DebugTarget::SteamClient),
        "steamui" => Some(DebugTarget::SteamUi),
        _ => None,
    }
}

fn quote_text(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn help_is_default_for_empty_command() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert!(dispatch("").contains("commands"));
    }

    #[test]
    fn dump_returns_jsonish_response() {
        let _guard = TEST_LOCK.lock().unwrap();
        let response = dispatch("dump");
        assert!(response.starts_with("ok {"));
        assert!(response.contains("\"toast\""));
        assert!(response.contains("\"target\":\"steamclient\""));
    }

    #[test]
    fn target_dump_selects_namespace() {
        let _guard = TEST_LOCK.lock().unwrap();
        let response = dispatch("steamui dump");
        assert!(response.contains("\"target\":\"steamui\""));
    }

    #[test]
    fn ping_is_lightweight_probe() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert_eq!(dispatch("ping"), "ok pong");
        assert_eq!(dispatch("steamui ping"), "ok pong");
    }

    #[test]
    fn status_aliases_dump() {
        let _guard = TEST_LOCK.lock().unwrap();
        let response = dispatch("steamui status");
        assert!(response.starts_with("ok {"));
        assert!(response.contains("\"target\":\"steamui\""));
    }

    #[test]
    fn toast_command_queues_work() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();

        let response = dispatch("steamui toast Plain body text");
        assert!(response.contains("queued toast"));
        assert!(vapor_forge_features::toast::has_pending_work());
        assert_eq!(vapor_forge_features::toast::pending_count(), 1);

        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();
    }

    #[test]
    fn toast_command_accepts_warning_kind() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();

        let response = dispatch("steamui toast warning body=\"Warning Body\"");
        assert!(response.contains("kind=warning"));
        assert!(response.contains("style=banner"));
        let pending = vapor_forge_features::toast::take_pending();
        assert_eq!(pending.len(), 1);
        let script = vapor_forge_features::toast::toast_script(&pending[0]);
        assert!(script.contains("kind:\"warning\""));
        assert!(script.contains("style:\"banner\""));
        assert!(script.contains("critical:false"));

        vapor_forge_features::toast::mark_idle_if_empty();
    }

    #[test]
    fn toast_command_accepts_error_kind() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();

        let response = dispatch("toast err body=\"Error Body\"");
        assert!(response.contains("kind=error"));
        assert!(response.contains("style=banner"));
        let pending = vapor_forge_features::toast::take_pending();
        assert_eq!(pending.len(), 1);
        let script = vapor_forge_features::toast::toast_script(&pending[0]);
        assert!(script.contains("kind:\"error\""));
        assert!(script.contains("style:\"banner\""));
        assert!(script.contains("critical:true"));

        vapor_forge_features::toast::mark_idle_if_empty();
    }

    #[test]
    fn toast_command_accepts_explicit_style() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();

        let response = dispatch("steamui toast warning accent body=\"Accent Body\"");
        assert!(response.contains("kind=warning"));
        assert!(response.contains("style=accent"));
        let pending = vapor_forge_features::toast::take_pending();
        assert_eq!(pending.len(), 1);
        let script = vapor_forge_features::toast::toast_script(&pending[0]);
        assert!(script.contains("kind:\"warning\""));
        assert!(script.contains("style:\"accent\""));

        vapor_forge_features::toast::mark_idle_if_empty();
    }

    #[test]
    fn toast_command_accepts_key_value_options() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();

        let response = dispatch(
            "steamui toast kind=warning style=accent title=\"Readable Title\" body=\"Readable Body\" duration=1234 icon=https://example.invalid/icon.png",
        );
        assert!(response.contains("kind=warning"));
        assert!(response.contains("style=accent"));
        assert!(response.contains("title=\"Readable Title\""));
        assert!(response.contains("body=\"Readable Body\""));
        assert!(response.contains("duration_ms=1234"));
        let pending = vapor_forge_features::toast::take_pending();
        assert_eq!(pending.len(), 1);
        let script = vapor_forge_features::toast::toast_script(&pending[0]);
        assert!(script.contains("kind:\"warning\""));
        assert!(script.contains("style:\"accent\""));
        assert!(script.contains("title:\"Readable Title\""));
        assert!(script.contains("body:\"Readable Body\""));
        assert!(script.contains("icon:\"https://example.invalid/icon.png\""));

        vapor_forge_features::toast::mark_idle_if_empty();
    }

    #[test]
    fn toast_command_accepts_flag_options() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();

        let response = dispatch(
            "steamui toast warning banner --title \"Flag Title\" --body \"Flag Body\" --duration 2345",
        );
        assert!(response.contains("kind=warning"));
        assert!(response.contains("style=banner"));
        assert!(response.contains("title=\"Flag Title\""));
        assert!(response.contains("body=\"Flag Body\""));
        assert!(response.contains("duration_ms=2345"));

        let pending = vapor_forge_features::toast::take_pending();
        assert_eq!(pending.len(), 1);
        vapor_forge_features::toast::mark_idle_if_empty();
    }

    #[test]
    fn toast_is_steamui_only() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();

        let response = dispatch("steamclient toast body=\"Body\"");
        assert_eq!(response, "err toast is a steamui command");
        assert_eq!(vapor_forge_features::toast::pending_count(), 0);
    }

    #[test]
    fn invalid_toast_duration_is_rejected() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();

        let response = dispatch("toast body=\"Body\" duration=nope");
        assert_eq!(response, "err invalid duration_ms: \"nope\"");
        assert_eq!(vapor_forge_features::toast::pending_count(), 0);
    }

    #[test]
    fn invalid_key_value_toast_option_is_rejected() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = vapor_forge_features::toast::take_pending();
        vapor_forge_features::toast::mark_idle_if_empty();

        let response = dispatch("toast unknown=value body=hello");
        assert_eq!(response, "err unknown toast option: \"unknown\"");
        assert_eq!(vapor_forge_features::toast::pending_count(), 0);
    }

    #[test]
    fn command_parser_normalizes_known_commands() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert_eq!(parse_command(" help "), DebugCommand::Help);
        assert_eq!(parse_command("status"), DebugCommand::Dump);
        assert_eq!(
            parse_command("toast hello"),
            DebugCommand::Toast(ToastArgs::Fields("hello"))
        );
        assert_eq!(parse_command("unknown"), DebugCommand::Unknown("unknown"));
    }

    #[test]
    fn toast_kind_parser_accepts_aliases() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert_eq!(
            parse_toast_kind("warn"),
            Some(vapor_forge_features::toast::ToastKind::Warning)
        );
        assert_eq!(
            parse_toast_kind("err"),
            Some(vapor_forge_features::toast::ToastKind::Error)
        );
        assert_eq!(parse_toast_kind("other"), None);
    }

    #[test]
    fn toast_tokenizer_preserves_quoted_spaces() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert_eq!(
            tokenize_toast_args("title=\"Hello World\" body='Single quoted'").unwrap(),
            vec!["title=Hello World", "body=Single quoted"]
        );
        assert_eq!(
            tokenize_toast_args("body=\"escaped \\\"quote\\\"\"").unwrap(),
            vec!["body=escaped \"quote\""]
        );
        assert_eq!(
            tokenize_toast_args("body=\"unfinished").unwrap_err(),
            "err unterminated quote in toast command"
        );
    }

    #[test]
    fn debug_target_can_be_parsed_from_comm() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert_eq!(
            debug_target_from_comm("steamui\n"),
            Some(DebugTarget::SteamUi)
        );
        assert_eq!(
            debug_target_from_comm("steam\n"),
            Some(DebugTarget::SteamClient)
        );
        assert_eq!(debug_target_from_comm("steamwebhelper\n"), None);
    }

    #[test]
    fn default_socket_path_uses_shared_tmp() {
        let _guard = TEST_LOCK.lock().unwrap();
        std::env::remove_var("VAPOR_FORGE_DEBUG_SOCKET");
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        assert_eq!(
            default_socket_path().as_deref(),
            Some("/tmp/vapor-forge-1000/debug.sock")
        );
    }

    #[test]
    fn target_prefixes_are_stripped() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert_eq!(
            strip_target("steamui toast hi", "steamui"),
            Some("toast hi")
        );
        assert_eq!(strip_target("steamui", "steamui"), None);
        assert_eq!(strip_target("steamuis toast", "steamui"), None);
    }
}
