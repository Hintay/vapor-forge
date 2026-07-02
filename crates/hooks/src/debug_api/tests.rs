use super::command::{dispatch, parse_command, strip_target, DebugCommand, ToastArgs};
use super::server::{debug_target_from_comm, default_socket_path};
use super::toast_args::{parse_toast_kind, tokenize_toast_args};
use super::DebugTarget;
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
