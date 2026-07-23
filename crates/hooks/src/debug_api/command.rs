use serde_json::json;
use std::fmt::Write;
use vapor_forge_packet_capture::{PacketChange, PacketDirection, PacketSummary, PacketType};

use super::toast_args::{default_toast_style, parse_toast_args, toast_kind_name, toast_style_name};
use super::{DebugTarget, DEFAULT_DURATION_MS, DEFAULT_TOAST_BODY};
use crate::packet_capture::{CapturedPacket, PacketCaptureFilter, PacketCaptureMode};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DebugCommand<'a> {
    Help,
    Ping,
    Dump,
    Config,
    Hooks,
    Apps,
    Pkg0,
    Packet(&'a str),
    Patterns,
    Version,
    Log(&'a str),
    NativeInject,
    NativeInjectSelf,
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

    let (cmd, json) = strip_json_flag(trimmed);

    if let Some(sub) = strip_target(cmd, "steamui").or_else(|| strip_target(cmd, "ui")) {
        return dispatch_local(DebugTarget::SteamUi, sub, json);
    }
    if let Some(sub) = strip_target(cmd, "steamclient").or_else(|| strip_target(cmd, "client")) {
        return dispatch_local(DebugTarget::SteamClient, sub, json);
    }
    if is_toast_command(cmd) {
        return dispatch_local(DebugTarget::SteamUi, cmd, json);
    }
    dispatch_local(DebugTarget::SteamClient, cmd, json)
}

fn strip_json_flag(command: &str) -> (&str, bool) {
    if let Some(rest) = command.strip_suffix(" --json") {
        (rest.trim_end(), true)
    } else if command == "--json" {
        ("", true)
    } else {
        (command, false)
    }
}

fn dispatch_local(target: DebugTarget, command: &str, json: bool) -> String {
    match parse_command(command) {
        DebugCommand::Help => help_response(),
        DebugCommand::Ping => "ok pong".to_owned(),
        DebugCommand::Dump => dump_response(target, json),
        DebugCommand::Config => config_response(json),
        DebugCommand::Hooks => hooks_response(json),
        DebugCommand::Apps => apps_response(json),
        DebugCommand::Pkg0 => pkg0_response(json),
        DebugCommand::Packet(args) => packet_response(target, args, json),
        DebugCommand::Patterns => patterns_response(json),
        DebugCommand::Version => version_response(json),
        DebugCommand::Log(level) => log_response(level, json),
        DebugCommand::NativeInject => native_inject_response(json),
        DebugCommand::NativeInjectSelf => native_inject_self_response(json),
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
    if trimmed == "config" {
        return DebugCommand::Config;
    }
    if trimmed == "hooks" {
        return DebugCommand::Hooks;
    }
    if trimmed == "apps" {
        return DebugCommand::Apps;
    }
    if trimmed == "pkg0" {
        return DebugCommand::Pkg0;
    }
    if trimmed == "packet" {
        return DebugCommand::Packet("");
    }
    if let Some(args) = trimmed.strip_prefix("packet ") {
        return DebugCommand::Packet(args.trim());
    }
    if trimmed == "patterns" {
        return DebugCommand::Patterns;
    }
    if trimmed == "version" {
        return DebugCommand::Version;
    }
    if let Some(level) = trimmed.strip_prefix("log ") {
        return DebugCommand::Log(level.trim());
    }
    if trimmed == "log" {
        return DebugCommand::Log("");
    }
    if trimmed == "native-inject-self" || trimmed == "inject-self" {
        return DebugCommand::NativeInjectSelf;
    }
    if trimmed == "native-inject" || trimmed == "inject" {
        return DebugCommand::NativeInject;
    }
    if trimmed == "toast" {
        return DebugCommand::Toast(ToastArgs::Default);
    }
    if let Some(args) = trimmed.strip_prefix("toast ") {
        return DebugCommand::Toast(ToastArgs::Fields(args));
    }
    DebugCommand::Unknown(trimmed)
}

// ---------------------------------------------------------------------------
// Toast command (no --json variant, output is always text)
// ---------------------------------------------------------------------------

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

#[cfg(target_os = "linux")]
fn request_target_pump(target: DebugTarget) {
    if target == DebugTarget::SteamUi {
        crate::ui::toast_bridge::request_pump();
    }
}

#[cfg(not(target_os = "linux"))]
fn request_target_pump(_target: DebugTarget) {}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn help_response() -> String {
    let mut out = String::from("ok commands:\n");
    out.push_str("  help                  show this help\n");
    out.push_str("  ping                  connectivity check\n");
    out.push_str("  version               build version and commit\n");
    out.push_str("  config                runtime configuration summary\n");
    out.push_str("  hooks                 installed hooks and addresses\n");
    out.push_str("  apps                  controlled apps with ownership status\n");
    out.push_str("  pkg0                  package injection status\n");
    out.push_str("  packet ...            packet capture and inspection\n");
    out.push_str("  patterns              pattern match results\n");
    out.push_str("  log [level]           query or set log level\n");
    out.push_str("  native-inject         arm a native dispatch self-test\n");
    out.push_str("  native-inject-self    dispatch a captured packet from our own thread\n");
    out.push_str("  dump/status           toast subsystem status\n");
    out.push_str("  toast [args]          queue a toast notification\n");
    out.push('\n');
    out.push_str("  Add --json to any command for machine-readable output.\n");
    out.push_str("  Prefix with steamui/steamclient to select target.");
    out
}

// ---------------------------------------------------------------------------
// Dump / status
// ---------------------------------------------------------------------------

fn dump_response(target: DebugTarget, json_mode: bool) -> String {
    let pending = vapor_forge_features::toast::pending_count();
    let has_work = vapor_forge_features::toast::has_pending_work();
    let socket = super::server::socket_path().unwrap_or("");

    if json_mode {
        return format!(
            "ok {}",
            json!({
                "debug": {"target": target.name(), "socket": socket},
                "toast": {"pending": pending, "has_work": has_work},
            })
        );
    }

    let mut out = String::from("ok\n");
    let _ = writeln!(out, "  target:   {}", target.name());
    let _ = writeln!(out, "  socket:   {socket}");
    let _ = writeln!(out, "  toast:    {pending} pending, has_work={has_work}");
    out.truncate(out.trim_end().len());
    out
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn config_response(json_mode: bool) -> String {
    #[cfg(target_os = "linux")]
    let cfg = crate::client::install::config();
    #[cfg(not(target_os = "linux"))]
    let cfg = vapor_forge_config::RuntimeConfig::default();

    let inject_ids: Vec<u32> = cfg.apps.inject.iter().map(|a| a.id.0).collect();
    let ticket_cache = match cfg.ticket.cache {
        vapor_forge_config::TicketCacheMode::Session => "session",
        vapor_forge_config::TicketCacheMode::Disk => "disk",
    };

    if json_mode {
        return format!(
            "ok {}",
            json!({
                "runtime": {"log_level": cfg.runtime.log_level, "diagnostics": cfg.runtime.diagnostics},
                "apps": {"inject_count": cfg.apps.inject.len(), "inject_ids": inject_ids, "shared_enabled": cfg.apps.shared.enabled},
                "cloud": {
                    "enabled": cfg.cloud.enabled,
                    "cumulus_configured": cfg.cumulus_configured(),
                    "server_url": cfg.cloud.server_url,
                },
                "ticket": {"cache": ticket_cache, "auto_delegate": cfg.ticket.auto_delegate},
                "toast": {"enabled": cfg.toast.enabled},
                "scripting": {"paths": cfg.scripting.paths},
                "debug": {"control_api": cfg.debug.control_api},
            })
        );
    }

    let cloud_str = match cfg.cloud.enabled {
        Some(true) => "true",
        Some(false) => "false",
        None => "auto",
    };

    let mut out = String::from("ok\n");
    let _ = writeln!(out, "  [runtime]");
    let _ = writeln!(out, "    log_level:      {}", cfg.runtime.log_level);
    let _ = writeln!(out, "    diagnostics:    {}", cfg.runtime.diagnostics);
    let _ = writeln!(out, "  [apps]");
    let _ = writeln!(
        out,
        "    inject:         {} apps {:?}",
        cfg.apps.inject.len(),
        inject_ids
    );
    let _ = writeln!(out, "    shared:         {}", cfg.apps.shared.enabled);
    let _ = writeln!(out, "  [cloud]");
    let _ = writeln!(out, "    enabled:        {cloud_str}");
    let _ = writeln!(
        out,
        "    cumulus:        {}",
        if cfg.cumulus_configured() {
            cfg.cloud.server_url.as_str()
        } else {
            "disabled"
        }
    );
    let _ = writeln!(out, "  [ticket]");
    let _ = writeln!(out, "    cache:          {ticket_cache}");
    let _ = writeln!(out, "    auto_delegate:  {}", cfg.ticket.auto_delegate);
    let _ = writeln!(out, "  [toast]");
    let _ = writeln!(out, "    enabled:        {}", cfg.toast.enabled);
    let _ = writeln!(out, "  [scripting]");
    let _ = writeln!(out, "    paths:          {:?}", cfg.scripting.paths);
    let _ = writeln!(out, "  [debug]");
    let _ = write!(out, "    control_api:    {}", cfg.debug.control_api);
    out
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

fn hooks_response(json_mode: bool) -> String {
    crate::hook_report::with_stored_results(|modules| {
        if modules.is_empty() {
            if json_mode {
                return format!("ok {}", json!({"installed": false}));
            }
            return "ok no hooks installed".to_owned();
        }

        if json_mode {
            let mut map = serde_json::Map::new();
            for module in modules {
                let hooks: Vec<_> = module
                    .hooks
                    .iter()
                    .map(|h| json!({"name": h.name, "installed": h.installed, "addr": format!("0x{:x}", h.addr)}))
                    .collect();
                map.insert(module.module.to_owned(), serde_json::Value::Array(hooks));
            }
            return format!("ok {}", serde_json::Value::Object(map));
        }

        let mut out = String::from("ok\n");
        for module in modules {
            let installed = module.hooks.iter().filter(|h| h.installed).count();
            let total = module.hooks.len();
            let _ = writeln!(out, "  {} ({}/{})", module.module, installed, total);
            for h in &module.hooks {
                if h.installed {
                    let _ = writeln!(out, "    {:<50} 0x{:x}", h.name, h.addr);
                } else {
                    let _ = writeln!(out, "    {:<50} MISS", h.name);
                }
            }
        }
        out.truncate(out.trim_end().len());
        out
    })
}

// ---------------------------------------------------------------------------
// Apps
// ---------------------------------------------------------------------------

fn apps_response(json_mode: bool) -> String {
    #[cfg(target_os = "linux")]
    let cfg = crate::client::install::config();
    #[cfg(not(target_os = "linux"))]
    let cfg = vapor_forge_config::RuntimeConfig::default();

    let injected_into_pkg0 = |app_id| {
        #[cfg(target_os = "linux")]
        {
            crate::client::install::package_state().is_injected_into_pkg0(app_id)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = app_id;
            false
        }
    };

    if json_mode {
        let controlled: Vec<_> = cfg
            .apps
            .inject
            .iter()
            .map(|app| {
                let ownership =
                    ownership_label(vapor_forge_features::apps::actual_ownership(app.id));
                let injected = injected_into_pkg0(app.id);
                let ticket = match app.ticket {
                    vapor_forge_config::TicketMode::Forge => "forge",
                    vapor_forge_config::TicketMode::Delegate => "delegate",
                };
                let dlc: Vec<u32> = app.dlc.iter().map(|d| d.0).collect();
                json!({
                    "id": app.id.0,
                    "ownership": ownership,
                    "injected_into_pkg0": injected,
                    "ticket": ticket,
                    "dlc": dlc
                })
            })
            .collect();
        return format!("ok {}", json!({"controlled": controlled}));
    }

    if cfg.apps.inject.is_empty() {
        return "ok no controlled apps".to_owned();
    }

    let mut out = String::new();
    let _ = writeln!(out, "ok Controlled Apps ({}):", cfg.apps.inject.len());
    for app in &cfg.apps.inject {
        let ownership = ownership_label(vapor_forge_features::apps::actual_ownership(app.id));
        let injected = injected_into_pkg0(app.id);
        let ticket = match app.ticket {
            vapor_forge_config::TicketMode::Forge => "forge",
            vapor_forge_config::TicketMode::Delegate => "delegate",
        };
        let dlc: Vec<u32> = app.dlc.iter().map(|d| d.0).collect();
        let _ = writeln!(
            out,
            "  {:<10} ownership={:<7} injected={:<3} ticket={:<10} dlc={:?}",
            app.id.0,
            ownership,
            if injected { "yes" } else { "no" },
            ticket,
            dlc
        );
    }
    out.truncate(out.trim_end().len());
    out
}

fn ownership_label(state: vapor_forge_features::apps::OwnershipState) -> &'static str {
    match state {
        vapor_forge_features::apps::OwnershipState::Unknown => "unknown",
        vapor_forge_features::apps::OwnershipState::Unowned => "unowned",
        vapor_forge_features::apps::OwnershipState::Owned => "owned",
    }
}

// ---------------------------------------------------------------------------
// Pkg0
// ---------------------------------------------------------------------------

fn pkg0_response(json_mode: bool) -> String {
    #[cfg(target_os = "linux")]
    let pkg0_captured = crate::client::package::pkg0_captured();
    #[cfg(not(target_os = "linux"))]
    let pkg0_captured = false;

    #[cfg(target_os = "linux")]
    let cuser_captured = crate::client::package::cuser_captured();
    #[cfg(not(target_os = "linux"))]
    let cuser_captured = false;

    #[cfg(target_os = "linux")]
    let pkg_state = crate::client::install::package_state();
    #[cfg(target_os = "linux")]
    let active = pkg_state.is_active();
    #[cfg(not(target_os = "linux"))]
    let active = false;

    #[cfg(target_os = "linux")]
    let injected_count = pkg_state.injected_count();
    #[cfg(not(target_os = "linux"))]
    let injected_count = 0;

    #[cfg(target_os = "linux")]
    let cfg = crate::client::install::config();
    #[cfg(not(target_os = "linux"))]
    let cfg = vapor_forge_config::RuntimeConfig::default();
    let inject_count = cfg.apps.inject.len();

    if json_mode {
        return format!(
            "ok {}",
            json!({
                "pkg0_captured": pkg0_captured,
                "cuser_captured": cuser_captured,
                "inject_count": inject_count,
                "injected_count": injected_count,
                "active": active,
            })
        );
    }

    let check = |b: bool| if b { "yes" } else { "no" };
    let mut out = String::from("ok\n");
    let _ = writeln!(out, "  pkg0:      {}", check(pkg0_captured));
    let _ = writeln!(out, "  cuser:     {}", check(cuser_captured));
    let _ = writeln!(out, "  desired:   {} apps", inject_count);
    let _ = writeln!(out, "  injected:  {} apps", injected_count);
    let _ = write!(out, "  active:    {}", check(active));
    out
}

// ---------------------------------------------------------------------------
// Packet capture
// ---------------------------------------------------------------------------

fn packet_response(target: DebugTarget, args: &str, json_mode: bool) -> String {
    if target != DebugTarget::SteamClient {
        return "err packet is a steamclient command".to_owned();
    }

    let tokens: Vec<&str> = args.split_whitespace().collect();
    match tokens.as_slice() {
        [] | ["help"] => packet_help_response(),
        ["capture", rest @ ..] => packet_capture_response(rest, json_mode),
        ["list", rest @ ..] => packet_list_response(rest, json_mode),
        ["show", id] => match parse_u64_arg(id) {
            Ok(id) => packet_show_response(id, json_mode),
            Err(e) => e,
        },
        ["save", id, path] => match parse_u64_arg(id) {
            Ok(id) => packet_save_response(id, path, json_mode),
            Err(e) => e,
        },
        other => format!("err unknown packet command: {}", other.join(" ")),
    }
}

fn packet_help_response() -> String {
    let mut out = String::from("ok packet commands:\n");
    out.push_str("  packet capture status\n");
    out.push_str("  packet capture on [summary|raw] [direction=recv] [type=metrics] [emsg=5527] [app=480] [changed=rewritten]\n");
    out.push_str("  packet capture off\n");
    out.push_str("  packet capture clear\n");
    out.push_str("  packet capture limit N\n");
    out.push_str("  packet capture filter clear\n");
    out.push_str("  packet list [direction=recv] [type=...] [emsg=...] [app=...] [changed=...]\n");
    out.push_str("  packet show ID\n");
    out.push_str("  packet save ID PATH");
    out
}

fn packet_capture_response(tokens: &[&str], json_mode: bool) -> String {
    match tokens {
        [] | ["status"] => packet_capture_status_response(json_mode),
        ["off"] => {
            crate::packet_capture::set_mode(PacketCaptureMode::Off);
            if json_mode {
                format!("ok {}", json!({ "mode": "off" }))
            } else {
                "ok packet capture mode=off".to_owned()
            }
        }
        ["clear"] => {
            crate::packet_capture::clear();
            if json_mode {
                format!("ok {}", json!({ "cleared": true }))
            } else {
                "ok packet capture cleared".to_owned()
            }
        }
        ["limit", value] => match value.parse::<usize>() {
            Ok(limit) => {
                let applied = crate::packet_capture::set_limit(limit);
                if json_mode {
                    format!("ok {}", json!({ "limit": applied }))
                } else {
                    format!("ok packet capture limit={applied}")
                }
            }
            Err(e) => format!("err invalid limit: {e}"),
        },
        ["filter", "clear"] => {
            crate::packet_capture::clear_filter();
            if json_mode {
                format!("ok {}", json!({ "filter_cleared": true }))
            } else {
                "ok packet capture filter cleared".to_owned()
            }
        }
        ["on", rest @ ..] => packet_capture_on_response(rest, json_mode),
        other => format!("err unknown packet capture command: {}", other.join(" ")),
    }
}

fn packet_capture_status_response(json_mode: bool) -> String {
    let status = crate::packet_capture::status();
    if json_mode {
        return format!(
            "ok {}",
            json!({
                "mode": status.mode.label(),
                "limit": status.limit,
                "len": status.len,
                "next_id": status.next_id,
                "filter": filter_json(&status.filter),
            })
        );
    }

    format!(
        "ok packet capture mode={} len={} limit={} filter={}",
        status.mode.label(),
        status.len,
        status.limit,
        filter_text(&status.filter)
    )
}

fn packet_capture_on_response(tokens: &[&str], json_mode: bool) -> String {
    let mut mode = PacketCaptureMode::Summary;
    let mut filter = PacketCaptureFilter::empty();

    for token in tokens {
        match *token {
            "summary" => mode = PacketCaptureMode::Summary,
            "raw" => mode = PacketCaptureMode::Raw,
            key_value => {
                if let Err(e) = apply_filter_token(&mut filter, key_value) {
                    return e;
                }
            }
        }
    }

    crate::packet_capture::set_filter(filter.clone());
    crate::packet_capture::set_mode(mode);
    if json_mode {
        return format!(
            "ok {}",
            json!({
                "mode": mode.label(),
                "filter": filter_json(&filter),
            })
        );
    }
    format!(
        "ok packet capture mode={} filter={}",
        mode.label(),
        filter_text(&filter)
    )
}

fn packet_list_response(tokens: &[&str], json_mode: bool) -> String {
    let filter = match parse_filter_tokens(tokens) {
        Ok(filter) => filter,
        Err(e) => return e,
    };
    let packets: Vec<_> = crate::packet_capture::list()
        .into_iter()
        .filter(|packet| filter.matches(&packet.summary))
        .collect();

    if json_mode {
        let values: Vec<_> = packets.iter().map(packet_json).collect();
        return format!("ok {}", serde_json::Value::Array(values));
    }

    if packets.is_empty() {
        return "ok no captured packets".to_owned();
    }

    let mut out = String::from("ok\n");
    for packet in packets {
        let _ = writeln!(out, "  {}", summary_line(&packet.summary));
    }
    out.truncate(out.trim_end().len());
    out
}

fn packet_show_response(id: u64, json_mode: bool) -> String {
    let Some(packet) = crate::packet_capture::get(id) else {
        return format!("err packet {id} not found");
    };

    if json_mode {
        return format!("ok {}", packet_json(&packet));
    }

    let mut out = format!("ok {}\n", summary_line(&packet.summary));
    if let Some(raw) = &packet.raw {
        let _ = writeln!(out, "  raw_len: {}", raw.len());
        let _ = writeln!(out, "  raw_hex_prefix: {}", hex_prefix(raw, 96));
    } else {
        out.push_str("  raw: not captured\n");
    }
    out.truncate(out.trim_end().len());
    out
}

fn packet_save_response(id: u64, path: &str, json_mode: bool) -> String {
    let Some(packet) = crate::packet_capture::get(id) else {
        return format!("err packet {id} not found");
    };
    let Some(raw) = packet.raw else {
        return format!("err packet {id} has no raw bytes; enable raw capture first");
    };
    let len = raw.len();
    match std::fs::write(path, raw) {
        Ok(()) if json_mode => format!(
            "ok {}",
            json!({
                "id": id,
                "path": path,
                "bytes": len,
            })
        ),
        Ok(()) => format!("ok saved packet {id} to {path}"),
        Err(e) => format!("err save failed: {e}"),
    }
}

fn parse_filter_tokens(tokens: &[&str]) -> Result<PacketCaptureFilter, String> {
    let mut filter = PacketCaptureFilter::empty();
    for token in tokens {
        apply_filter_token(&mut filter, token)?;
    }
    Ok(filter)
}

fn apply_filter_token(filter: &mut PacketCaptureFilter, token: &str) -> Result<(), String> {
    let Some((key, value)) = token.split_once('=') else {
        return Err(format!(
            "err expected key=value filter, got {}",
            quote_text(token)
        ));
    };
    match key {
        "direction" | "dir" => filter.direction = Some(parse_direction(value)?),
        "type" => filter.packet_type = Some(parse_packet_type(value)?),
        "emsg" => filter.emsg = Some(parse_u32_arg(value)?),
        "app" | "app_id" | "appid" => filter.app_id = Some(parse_u32_arg(value)?),
        "changed" | "change" => filter.changed = Some(parse_change(value)?),
        other => return Err(format!("err unknown packet filter key: {other}")),
    }
    Ok(())
}

fn parse_direction(value: &str) -> Result<PacketDirection, String> {
    match value {
        "send" => Ok(PacketDirection::Send),
        "recv" => Ok(PacketDirection::Recv),
        other => Err(format!("err unknown direction: {other}")),
    }
}

fn parse_packet_type(value: &str) -> Result<PacketType, String> {
    match value {
        "encrypted-ticket" | "ticket" => Ok(PacketType::EncryptedTicket),
        "ownership-ticket" => Ok(PacketType::OwnershipTicket),
        "pics" => Ok(PacketType::Pics),
        "manifest-code" | "manifest" => Ok(PacketType::ManifestCode),
        "stats" => Ok(PacketType::Stats),
        "metrics" => Ok(PacketType::Metrics),
        "cloud" => Ok(PacketType::Cloud),
        "app-metadata" | "metadata" => Ok(PacketType::AppMetadata),
        "rich-presence" | "rp" => Ok(PacketType::RichPresence),
        "games-played" => Ok(PacketType::GamesPlayed),
        "persona" => Ok(PacketType::Persona),
        "unknown" => Ok(PacketType::Unknown),
        other => Err(format!("err unknown packet type: {other}")),
    }
}

fn parse_change(value: &str) -> Result<PacketChange, String> {
    match value {
        "unchanged" => Ok(PacketChange::Unchanged),
        "dropped" | "drop" => Ok(PacketChange::Dropped),
        "rewritten" | "rewrite" => Ok(PacketChange::Rewritten),
        "injected" | "inject" => Ok(PacketChange::Injected),
        "queued" | "queue" => Ok(PacketChange::Queued),
        "decode-failed" | "decode_failed" => Ok(PacketChange::DecodeFailed),
        other => Err(format!("err unknown packet change: {other}")),
    }
}

fn parse_u32_arg(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|e| format!("err invalid u32: {e}"))
    } else {
        value
            .parse::<u32>()
            .map_err(|e| format!("err invalid u32: {e}"))
    }
}

fn parse_u64_arg(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|e| format!("err invalid id: {e}"))
}

fn summary_line(summary: &PacketSummary) -> String {
    let emsg = summary
        .emsg
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let apps = if summary.app_ids.is_empty() {
        "-".to_owned()
    } else {
        format!("{:?}", summary.app_ids)
    };
    let len = match summary.final_len {
        Some(final_len) if final_len != summary.original_len => {
            format!("{}->{final_len}", summary.original_len)
        }
        _ => summary.original_len.to_string(),
    };
    format!(
        "#{:<4} {:<4} emsg={:<5} type={:<16} app={} change={:<13} len={}",
        summary.id,
        summary.direction.label(),
        emsg,
        summary.packet_type.label(),
        apps,
        summary.change.label(),
        len
    )
}

fn packet_json(packet: &CapturedPacket) -> serde_json::Value {
    json!({
        "summary": summary_json(&packet.summary),
        "raw": packet.raw.as_ref().map(|raw| json!({
            "len": raw.len(),
            "hex_prefix": hex_prefix(raw, 96),
        })),
    })
}

fn summary_json(summary: &PacketSummary) -> serde_json::Value {
    json!({
        "id": summary.id,
        "direction": summary.direction.label(),
        "emsg_raw": summary.emsg_raw,
        "emsg": summary.emsg,
        "proto": summary.proto,
        "type": summary.packet_type.label(),
        "app_ids": summary.app_ids,
        "steamid": summary.steamid,
        "job": summary.job,
        "eresult": summary.eresult,
        "change": summary.change.label(),
        "original_len": summary.original_len,
        "final_len": summary.final_len,
        "header_len": summary.header_len,
        "body_len": summary.body_len,
        "decode_error": summary.decode_error,
    })
}

fn filter_json(filter: &PacketCaptureFilter) -> serde_json::Value {
    json!({
        "direction": filter.direction.map(PacketDirection::label),
        "type": filter.packet_type.map(PacketType::label),
        "emsg": filter.emsg,
        "app_id": filter.app_id,
        "changed": filter.changed.map(PacketChange::label),
    })
}

fn filter_text(filter: &PacketCaptureFilter) -> String {
    let mut parts = Vec::new();
    if let Some(direction) = filter.direction {
        parts.push(format!("direction={}", direction.label()));
    }
    if let Some(packet_type) = filter.packet_type {
        parts.push(format!("type={}", packet_type.label()));
    }
    if let Some(emsg) = filter.emsg {
        parts.push(format!("emsg={emsg}"));
    }
    if let Some(app_id) = filter.app_id {
        parts.push(format!("app={app_id}"));
    }
    if let Some(changed) = filter.changed {
        parts.push(format!("changed={}", changed.label()));
    }
    if parts.is_empty() {
        "none".to_owned()
    } else {
        parts.join(",")
    }
}

fn hex_prefix(bytes: &[u8], max: usize) -> String {
    let mut out = String::new();
    for byte in bytes.iter().take(max) {
        let _ = write!(out, "{byte:02x}");
    }
    if bytes.len() > max {
        out.push_str("...");
    }
    out
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

fn patterns_response(json_mode: bool) -> String {
    crate::hook_report::with_stored_results(|modules| {
        if modules.is_empty() {
            if json_mode {
                return "ok {}".to_owned();
            }
            return "ok no patterns resolved".to_owned();
        }

        if json_mode {
            let mut map = serde_json::Map::new();
            for module in modules {
                let patterns: Vec<_> = module
                    .hooks
                    .iter()
                    .map(|h| {
                        if h.installed {
                            json!({"name": h.name, "addr": format!("0x{:x}", h.addr)})
                        } else {
                            json!({"name": h.name, "addr": null})
                        }
                    })
                    .collect();
                map.insert(module.module.to_owned(), serde_json::Value::Array(patterns));
            }
            return format!("ok {}", serde_json::Value::Object(map));
        }

        let mut out = String::from("ok\n");
        for module in modules {
            let hit = module.hooks.iter().filter(|h| h.installed).count();
            let total = module.hooks.len();
            let _ = writeln!(out, "  {} ({}/{})", module.module, hit, total);
            for h in &module.hooks {
                if h.installed {
                    let _ = writeln!(out, "    {:<50} 0x{:x}", h.name, h.addr);
                } else {
                    let _ = writeln!(out, "    {:<50} MISS", h.name);
                }
            }
        }
        out.truncate(out.trim_end().len());
        out
    })
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

fn version_response(json_mode: bool) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let commit = option_env!("GIT_COMMIT").unwrap_or("dev");

    if json_mode {
        return format!("ok {}", json!({"version": version, "commit": commit}));
    }

    format!("ok vapor-forge {version} ({commit})")
}

// ---------------------------------------------------------------------------
// Log
// ---------------------------------------------------------------------------

fn log_response(level: &str, json_mode: bool) -> String {
    if level.is_empty() {
        let current = vapor_forge_diagnostics::current_level_name();
        if json_mode {
            return format!("ok {}", json!({"level": current}));
        }
        return format!("ok level={current}");
    }

    match level {
        "error" | "warn" | "info" | "debug" | "trace" => {
            let applied = vapor_forge_diagnostics::set_level(level);
            if json_mode {
                format!("ok {}", json!({"level": applied}))
            } else {
                format!("ok level={applied}")
            }
        }
        _ => format!("err unknown log level: {}", quote_text(level)),
    }
}

// ---------------------------------------------------------------------------
// Native dispatch self-test
// ---------------------------------------------------------------------------

/// Arm a one-shot self-test of the native injection dispatch. The next inbound
/// packet, once dispatch context is captured, is replayed through the production
/// injection path; the result appears in the logs (native-inject: ...).
fn native_inject_response(json_mode: bool) -> String {
    #[cfg(target_os = "linux")]
    {
        let ready = crate::client::network::arm_native_inject_selftest();
        if json_mode {
            format!("ok {}", json!({"armed": true, "dispatch_ready": ready}))
        } else {
            format!("ok armed native-inject self-test (dispatch_ready={ready}); replays next inbound packet, see logs")
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = json_mode;
        "err native-inject is only available in the steamclient process".to_owned()
    }
}

/// Test active dispatch from a thread we own: replay one captured inbound body
/// from a freshly spawned thread (no RecvPkt), to check that AddWorkItem +
/// WakeWorker deliver while the CM connection is idle.
fn native_inject_self_response(json_mode: bool) -> String {
    #[cfg(target_os = "linux")]
    {
        let detail = crate::client::network::spawn_own_thread_dispatch_test();
        if json_mode {
            let ok = detail.starts_with("ok");
            format!("ok {}", json!({"ok": ok, "detail": detail}))
        } else {
            detail
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = json_mode;
        "err native-inject-self is only available in the steamclient process".to_owned()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn quote_text(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
