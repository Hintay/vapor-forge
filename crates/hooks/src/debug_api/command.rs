use super::toast_args::{default_toast_style, parse_toast_args, toast_kind_name, toast_style_name};
use super::{DebugTarget, DEFAULT_DURATION_MS, DEFAULT_TOAST_BODY};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DebugCommand<'a> {
    Help,
    Ping,
    Dump,
    Toast(ToastArgs<'a>),
    Unknown(&'a str),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ToastArgs<'a> {
    Default,
    Fields(&'a str),
}

pub(crate) fn dispatch(command: &str) -> String {
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

pub(crate) fn strip_target<'a>(command: &'a str, target: &str) -> Option<&'a str> {
    command
        .strip_prefix(target)
        .and_then(|rest| rest.strip_prefix(char::is_whitespace))
        .map(str::trim)
}

fn is_toast_command(command: &str) -> bool {
    command == "toast" || command.starts_with("toast ")
}

pub(crate) fn parse_command(command: &str) -> DebugCommand<'_> {
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

fn request_target_pump(target: DebugTarget) {
    if target == DebugTarget::SteamUi {
        crate::ui::toast_bridge::request_pump();
    }
}

fn help_response() -> String {
    "ok commands: help; ping; dump/status; steamclient <command>; steamui <command>; toast; toast <body>; toast kind=warning style=banner title=\"Title\" body=\"Body\" duration=8000 icon=\"URL\"; toast warning banner --title \"Title\" --body \"Body\" --duration 8000"
        .to_owned()
}

fn dump_response(target: DebugTarget) -> String {
    format!(
        "ok {{\"debug\":{{\"target\":\"{}\",\"socket\":\"{}\"}},\"toast\":{{\"pending\":{},\"has_work\":{}}}}}",
        target.name(),
        json_escape(super::server::socket_path().unwrap_or("")),
        vapor_forge_features::toast::pending_count(),
        vapor_forge_features::toast::has_pending_work()
    )
}

pub(crate) fn quote_text(value: &str) -> String {
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
