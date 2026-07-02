use std::fmt::Write;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;

use serde_json::json;

use super::toast_args::{default_toast_style, parse_toast_args, toast_kind_name, toast_style_name};
use super::{DebugTarget, DEFAULT_DURATION_MS, DEFAULT_TOAST_BODY};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DebugCommand<'a> {
    Help,
    Ping,
    Dump,
    Config,
    Hooks,
    Apps,
    Pkg0,
    Patterns,
    Version,
    Log(&'a str),
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
        DebugCommand::Patterns => patterns_response(json),
        DebugCommand::Version => version_response(json),
        DebugCommand::Log(level) => log_response(level, json),
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
    out.push_str("  patterns              pattern match results\n");
    out.push_str("  log [level]           query or set log level\n");
    out.push_str("  dump/status           toast subsystem status\n");
    out.push_str("  toast [args]          queue a toast notification\n");
    out.push_str("\n");
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
                "cloud": {"enabled": cfg.cloud.enabled},
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
    let _ = writeln!(out, "    inject:         {} apps {:?}", cfg.apps.inject.len(), inject_ids);
    let _ = writeln!(out, "    shared:         {}", cfg.apps.shared.enabled);
    let _ = writeln!(out, "  [cloud]");
    let _ = writeln!(out, "    enabled:        {cloud_str}");
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

    if json_mode {
        let controlled: Vec<_> = cfg
            .apps
            .inject
            .iter()
            .map(|app| {
                let owned = vapor_forge_features::apps::is_actually_owned(app.id);
                let ticket = match app.ticket {
                    vapor_forge_config::TicketMode::Forge => "forge",
                    vapor_forge_config::TicketMode::Delegate => "delegate",
                };
                let dlc: Vec<u32> = app.dlc.iter().map(|d| d.0).collect();
                json!({"id": app.id.0, "owned": owned, "ticket": ticket, "dlc": dlc})
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
        let owned = vapor_forge_features::apps::is_actually_owned(app.id);
        let ticket = match app.ticket {
            vapor_forge_config::TicketMode::Forge => "forge",
            vapor_forge_config::TicketMode::Delegate => "delegate",
        };
        let dlc: Vec<u32> = app.dlc.iter().map(|d| d.0).collect();
        let _ = writeln!(
            out,
            "  {:<10} owned={:<5} ticket={:<10} dlc={:?}",
            app.id.0,
            if owned { "yes" } else { "no" },
            ticket,
            dlc
        );
    }
    out.truncate(out.trim_end().len());
    out
}

// ---------------------------------------------------------------------------
// Pkg0
// ---------------------------------------------------------------------------

fn pkg0_response(json_mode: bool) -> String {
    #[cfg(target_os = "linux")]
    let pkg0_captured = crate::client::package::PKG0_PTR.load(Ordering::Acquire) != 0;
    #[cfg(not(target_os = "linux"))]
    let pkg0_captured = false;

    #[cfg(target_os = "linux")]
    let cuser_captured = crate::client::package::CUSER_PTR.load(Ordering::Acquire) != 0;
    #[cfg(not(target_os = "linux"))]
    let cuser_captured = false;

    #[cfg(target_os = "linux")]
    let pkg_state = crate::client::install::package_state();
    #[cfg(target_os = "linux")]
    let active = pkg_state.is_active();
    #[cfg(not(target_os = "linux"))]
    let active = false;

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
                "active": active,
            })
        );
    }

    let check = |b: bool| if b { "yes" } else { "no" };
    let mut out = String::from("ok\n");
    let _ = writeln!(out, "  pkg0:      {}", check(pkg0_captured));
    let _ = writeln!(out, "  cuser:     {}", check(cuser_captured));
    let _ = writeln!(out, "  injected:  {} apps", inject_count);
    let _ = write!(out, "  active:    {}", check(active));
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
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn quote_text(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
