use vapor_forge_core::{AppId, DepotId, ManifestId};

use crate::bindings::parse_hex_key;
use crate::{
    execute_scripts, execute_scripts_report, execute_scripts_report_with_options,
    ScriptExecutionOptions,
};

#[test]
fn parses_hex_key() {
    assert_eq!(
        parse_hex_key("deadbeef"),
        Some(vec![0xde, 0xad, 0xbe, 0xef])
    );
    assert_eq!(parse_hex_key("zz"), None);
    assert_eq!(parse_hex_key("abc"), None);
}

#[test]
fn executes_addappid_script() {
    let dir = std::env::temp_dir().join(format!("lua-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join("test.lua"), "addappid(480)\naddappid(730)\n").unwrap();

    let state = execute_scripts(&[dir.to_string_lossy().into_owned()]);
    assert_eq!(state.apps, vec![AppId(480), AppId(730)]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn executes_setmanifestid_script() {
    let dir = std::env::temp_dir().join(format!("lua-manifest-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("test.lua"),
        concat!(
            "setmanifestid(12345, \"9876543210\", 1024)\n",
            "setManifestid(12346, \"9876543211\", 2048)\n",
        ),
    )
    .unwrap();

    let state = execute_scripts(&[dir.to_string_lossy().into_owned()]);
    assert_eq!(state.manifests.len(), 2);
    let manifest = &state.manifests[&DepotId(12345)];
    assert_eq!(manifest.gid, ManifestId(9876543210));
    assert_eq!(manifest.size, Some(1024));
    let camel_case_manifest = &state.manifests[&DepotId(12346)];
    assert_eq!(camel_case_manifest.gid, ManifestId(9876543211));
    assert_eq!(camel_case_manifest.size, Some(2048));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn executes_setstat_script() {
    let dir = std::env::temp_dir().join(format!("lua-stat-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("test.lua"),
        "setstat(480, \"76561198000000000\")\n",
    )
    .unwrap();

    let state = execute_scripts(&[dir.to_string_lossy().into_owned()]);
    assert_eq!(
        state.stat_steam_ids.get(&AppId(480)),
        Some(&76561198000000000)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_records_lua_call_order() {
    let dir = std::env::temp_dir().join(format!("lua-report-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("10-first.lua"),
        "addappid(480)\nsetavatar(480, 730)\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("20-second.lua"),
        "setappticket(480, \"deadbeef\")\n",
    )
    .unwrap();

    let report = execute_scripts_report(&[dir.to_string_lossy().into_owned()]);
    let functions = report
        .calls
        .iter()
        .map(|call| call.function)
        .collect::<Vec<_>>();

    assert_eq!(functions, vec!["addappid", "setavatar", "setappticket"]);
    assert!(report.calls[0].path.ends_with("10-first.lua"));
    assert!(report.calls[2].path.ends_with("20-second.lua"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_can_disable_lua_network_api() {
    let dir = std::env::temp_dir().join(format!("lua-network-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("test.lua"),
        "http_get(\"https://example.invalid/path?token=secret\")\n",
    )
    .unwrap();

    let report = execute_scripts_report_with_options(
        &[dir.to_string_lossy().into_owned()],
        ScriptExecutionOptions::check_default(),
    );

    assert!(report.files[0].result.is_err());
    assert_eq!(report.calls[0].function, "http_get");
    assert!(report.calls[0].detail.contains("?<redacted>"));
    assert!(report.files[0]
        .result
        .as_ref()
        .unwrap_err()
        .contains("http_get disabled"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_can_restrict_lua_network_hosts() {
    let dir = std::env::temp_dir().join(format!("lua-host-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("test.lua"),
        "http_get(\"https://blocked.invalid/path\")\n",
    )
    .unwrap();

    let report = execute_scripts_report_with_options(
        &[dir.to_string_lossy().into_owned()],
        ScriptExecutionOptions {
            allow_network: true,
            allowed_hosts: vec!["allowed.invalid".to_owned()],
            network_timeout_ms: Some(1000),
            redact_network_urls: true,
            record_calls: true,
        },
    );

    assert!(report.files[0].result.is_err());
    assert!(report.files[0]
        .result
        .as_ref()
        .unwrap_err()
        .contains("not allowed"));

    let _ = std::fs::remove_dir_all(&dir);
}
