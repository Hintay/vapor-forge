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
    let response = dispatch("dump --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"toast\""));
    assert!(response.contains("\"target\":\"steamclient\""));
}

#[test]
fn target_dump_selects_namespace() {
    let _guard = TEST_LOCK.lock().unwrap();
    let response = dispatch("steamui dump --json");
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
    let response = dispatch("steamui status --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"target\":\"steamui\""));
}

#[test]
fn toast_command_queues_work() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();

    let response = dispatch("steamui toast Plain body text");
    assert!(response.contains("queued toast"));
    assert!(vapor_forge_features::toast::has_pending_work());
    assert_eq!(vapor_forge_features::toast::pending_count(), 1);

    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();
}

#[test]
fn toast_command_accepts_warning_kind() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();

    let response = dispatch("steamui toast warning body=\"Warning Body\"");
    assert!(response.contains("kind=warning"));
    assert!(response.contains("style=banner"));
    let pending = vapor_forge_features::toast::take_pending();
    assert_eq!(pending.len(), 1);
    let script = vapor_forge_features::toast::toast_script(&pending[0]);
    assert!(script.contains("kind:\"warning\""));
    assert!(script.contains("style:\"banner\""));
    assert!(script.contains("critical:false"));

    let _ = vapor_forge_features::toast::take_ui_work();
}

#[test]
fn toast_command_accepts_error_kind() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();

    let response = dispatch("toast err body=\"Error Body\"");
    assert!(response.contains("kind=error"));
    assert!(response.contains("style=banner"));
    let pending = vapor_forge_features::toast::take_pending();
    assert_eq!(pending.len(), 1);
    let script = vapor_forge_features::toast::toast_script(&pending[0]);
    assert!(script.contains("kind:\"error\""));
    assert!(script.contains("style:\"banner\""));
    assert!(script.contains("critical:true"));

    let _ = vapor_forge_features::toast::take_ui_work();
}

#[test]
fn toast_command_accepts_explicit_style() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();

    let response = dispatch("steamui toast warning accent body=\"Accent Body\"");
    assert!(response.contains("kind=warning"));
    assert!(response.contains("style=accent"));
    let pending = vapor_forge_features::toast::take_pending();
    assert_eq!(pending.len(), 1);
    let script = vapor_forge_features::toast::toast_script(&pending[0]);
    assert!(script.contains("kind:\"warning\""));
    assert!(script.contains("style:\"accent\""));

    let _ = vapor_forge_features::toast::take_ui_work();
}

#[test]
fn toast_command_accepts_key_value_options() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();

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

    let _ = vapor_forge_features::toast::take_ui_work();
}

#[test]
fn toast_command_accepts_flag_options() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();

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
    let _ = vapor_forge_features::toast::take_ui_work();
}

#[test]
fn toast_is_steamui_only() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();

    let response = dispatch("steamclient toast body=\"Body\"");
    assert_eq!(response, "err toast is a steamui command");
    assert_eq!(vapor_forge_features::toast::pending_count(), 0);
}

#[test]
fn invalid_toast_duration_is_rejected() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();

    let response = dispatch("toast body=\"Body\" duration=nope");
    assert_eq!(response, "err invalid duration_ms: \"nope\"");
    assert_eq!(vapor_forge_features::toast::pending_count(), 0);
}

#[test]
fn invalid_key_value_toast_option_is_rejected() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = vapor_forge_features::toast::take_pending();
    let _ = vapor_forge_features::toast::take_ui_work();

    let response = dispatch("toast unknown=value body=hello");
    assert_eq!(response, "err unknown toast option: \"unknown\"");
    assert_eq!(vapor_forge_features::toast::pending_count(), 0);
}

#[test]
fn command_parser_normalizes_known_commands() {
    let _guard = TEST_LOCK.lock().unwrap();
    assert_eq!(parse_command(" help "), DebugCommand::Help);
    assert_eq!(parse_command("status"), DebugCommand::Dump);
    assert_eq!(parse_command("config"), DebugCommand::Config);
    assert_eq!(parse_command("hooks"), DebugCommand::Hooks);
    assert_eq!(parse_command("apps"), DebugCommand::Apps);
    assert_eq!(parse_command("stats"), DebugCommand::Stats(""));
    assert_eq!(
        parse_command("stats refresh 620"),
        DebugCommand::Stats("refresh 620")
    );
    assert_eq!(parse_command("pkg0"), DebugCommand::Pkg0);
    assert_eq!(parse_command("packet"), DebugCommand::Packet(""));
    assert_eq!(
        parse_command("packet capture status"),
        DebugCommand::Packet("capture status")
    );
    assert_eq!(parse_command("patterns"), DebugCommand::Patterns);
    assert_eq!(parse_command("version"), DebugCommand::Version);
    assert_eq!(parse_command("log debug"), DebugCommand::Log("debug"));
    assert_eq!(parse_command("log"), DebugCommand::Log(""));
    assert_eq!(parse_command("native-inject"), DebugCommand::NativeInject);
    assert_eq!(parse_command("inject"), DebugCommand::NativeInject);
    assert_eq!(
        parse_command("native-inject-self"),
        DebugCommand::NativeInjectSelf
    );
    assert_eq!(parse_command("inject-self"), DebugCommand::NativeInjectSelf);
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

// ---------------------------------------------------------------------------
// New command tests
// ---------------------------------------------------------------------------

#[test]
fn config_returns_json_with_runtime_section() {
    let _guard = TEST_LOCK.lock().unwrap();
    let response = dispatch("config --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"runtime\":{"));
    assert!(response.contains("\"log_level\":"));
    assert!(response.contains("\"apps\":{"));
    assert!(response.contains("\"toast\":{"));
    assert!(response.contains("\"ticket\":{"));
    assert!(response.contains("\"cloud\":{"));
    assert!(response.contains("\"scripting\":{"));
    assert!(response.contains("\"debug\":{"));
}

#[test]
fn hooks_returns_json() {
    let _guard = TEST_LOCK.lock().unwrap();
    crate::hook_report::clear_stored_results();

    let response = dispatch("hooks --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"installed\":false"));
}

#[test]
fn hooks_with_stored_results() {
    let _guard = TEST_LOCK.lock().unwrap();
    crate::hook_report::clear_stored_results();

    crate::hook_report::store_results(
        "test.so",
        &[
            crate::hook_report::HookResult {
                name: "TestHook::Alpha",
                installed: true,
                addr: 0xdead,
            },
            crate::hook_report::HookResult {
                name: "TestHook::Beta",
                installed: false,
                addr: 0,
            },
        ],
    );

    let response = dispatch("hooks --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"test.so\":["));
    assert!(response.contains("\"TestHook::Alpha\""));
    assert!(response.contains("\"installed\":true"));
    assert!(response.contains("\"TestHook::Beta\""));
    assert!(response.contains("\"installed\":false"));
}

#[test]
fn apps_returns_controlled_list() {
    let _guard = TEST_LOCK.lock().unwrap();
    let response = dispatch("apps --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"controlled\":["));
}

#[test]
fn pkg0_returns_capture_status() {
    let _guard = TEST_LOCK.lock().unwrap();
    let response = dispatch("pkg0 --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"pkg0_captured\":"));
    assert!(response.contains("\"cuser_captured\":"));
    assert!(response.contains("\"inject_count\":"));
    assert!(response.contains("\"injected_count\":"));
    assert!(response.contains("\"active\":"));
}

#[test]
fn packet_capture_status_and_filter_are_exposed() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = dispatch("packet capture off");
    let _ = dispatch("packet capture clear");
    let _ = dispatch("packet capture filter clear");

    let response = dispatch("packet capture status --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"mode\":\"off\""));

    let response = dispatch("packet capture on raw direction=recv type=persona changed=rewritten");
    assert_eq!(
        response,
        "ok packet capture mode=raw filter=direction=recv,type=persona,changed=rewritten"
    );

    let response = dispatch("packet capture status --json");
    assert!(response.contains("\"mode\":\"raw\""));
    assert!(response.contains("\"direction\":\"recv\""));
    assert!(response.contains("\"type\":\"persona\""));
    assert!(response.contains("\"changed\":\"rewritten\""));

    for packet_type in ["ownership-ticket", "metrics", "cloud", "app-metadata"] {
        assert_eq!(
            dispatch(&format!("packet capture on summary type={packet_type}")),
            format!("ok packet capture mode=summary filter=type={packet_type}")
        );
    }

    let response = dispatch("packet capture limit 64 --json");
    assert_eq!(response, "ok {\"limit\":64}");
    let response = dispatch("packet capture off --json");
    assert_eq!(response, "ok {\"mode\":\"off\"}");

    let _ = dispatch("packet capture limit 128");
    let _ = dispatch("packet capture clear");
    let _ = dispatch("packet capture filter clear");
}

#[test]
fn packet_capture_filters_limits_and_exposes_raw_packets() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = dispatch("packet capture off");
    let _ = dispatch("packet capture clear");
    let _ = dispatch("packet capture filter clear");
    let _ = dispatch("packet capture limit 2");
    assert_eq!(
        dispatch("packet capture on raw direction=recv"),
        "ok packet capture mode=raw filter=direction=recv"
    );

    crate::packet_capture::capture(
        vapor_forge_packet_capture::PacketDirection::Send,
        b"filtered",
        vapor_forge_packet_capture::PacketChange::Unchanged,
        None,
    );
    for raw in [
        b"first".as_slice(),
        b"second".as_slice(),
        b"third".as_slice(),
    ] {
        crate::packet_capture::capture(
            vapor_forge_packet_capture::PacketDirection::Recv,
            raw,
            vapor_forge_packet_capture::PacketChange::Unchanged,
            None,
        );
    }

    let packets = crate::packet_capture::list();
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].raw.as_deref(), Some(b"second".as_slice()));
    assert_eq!(packets[1].raw.as_deref(), Some(b"third".as_slice()));
    assert!(packets[0].summary.id < packets[1].summary.id);
    assert_eq!(
        packets[0].summary.change,
        vapor_forge_packet_capture::PacketChange::DecodeFailed
    );

    let list = dispatch("packet list direction=recv --json");
    let payload = list.strip_prefix("ok ").unwrap();
    let value: serde_json::Value = serde_json::from_str(payload).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 2);

    let show = dispatch(&format!("packet show {} --json", packets[1].summary.id));
    assert!(show.contains("\"raw\":{\"hex_prefix\":\"7468697264\",\"len\":5}"));

    let _ = dispatch("packet capture off");
    let _ = dispatch("packet capture clear");
    let _ = dispatch("packet capture filter clear");
    let _ = dispatch("packet capture limit 128");
}

#[test]
fn packet_command_is_steamclient_only() {
    let _guard = TEST_LOCK.lock().unwrap();
    assert_eq!(
        dispatch("steamui packet capture status"),
        "err packet is a steamclient command"
    );
}

#[test]
fn patterns_returns_json() {
    let _guard = TEST_LOCK.lock().unwrap();
    crate::hook_report::clear_stored_results();

    let response = dispatch("patterns --json");
    assert!(response.starts_with("ok {"));
}

#[test]
fn patterns_shows_stored_results() {
    let _guard = TEST_LOCK.lock().unwrap();
    crate::hook_report::clear_stored_results();

    crate::hook_report::store_results(
        "test.so",
        &[
            crate::hook_report::HookResult {
                name: "TestHook::Alpha",
                installed: true,
                addr: 0xdead,
            },
            crate::hook_report::HookResult {
                name: "TestHook::Beta",
                installed: false,
                addr: 0,
            },
        ],
    );

    let response = dispatch("patterns --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"test.so\":["));
    assert!(response.contains("\"TestHook::Alpha\""));
    assert!(response.contains("\"addr\":\"0xdead\""));
    assert!(response.contains("\"TestHook::Beta\""));
    assert!(response.contains("\"addr\":null"));
}

#[test]
fn version_returns_json() {
    let _guard = TEST_LOCK.lock().unwrap();
    let response = dispatch("version --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"version\":"));
    assert!(response.contains("\"commit\":"));
}

#[test]
fn log_without_args_returns_current_level() {
    let _guard = TEST_LOCK.lock().unwrap();
    let response = dispatch("log --json");
    assert!(response.starts_with("ok {"));
    assert!(response.contains("\"level\":"));
}

#[test]
fn log_sets_level() {
    let _guard = TEST_LOCK.lock().unwrap();

    let response = dispatch("log debug --json");
    assert_eq!(response, "ok {\"level\":\"debug\"}");

    let response = dispatch("log --json");
    assert!(response.contains("\"level\":\"debug\""));

    let response = dispatch("log info --json");
    assert_eq!(response, "ok {\"level\":\"info\"}");
}

#[test]
fn log_rejects_invalid_level() {
    let _guard = TEST_LOCK.lock().unwrap();
    let response = dispatch("log banana");
    assert!(response.starts_with("err unknown log level:"));
}

#[test]
fn help_lists_new_commands() {
    let _guard = TEST_LOCK.lock().unwrap();
    let response = dispatch("help");
    assert!(response.contains("config"));
    assert!(response.contains("hooks"));
    assert!(response.contains("apps"));
    assert!(response.contains("pkg0"));
    assert!(response.contains("patterns"));
    assert!(response.contains("version"));
    assert!(response.contains("log"));
    assert!(response.contains("native-inject"));
}
