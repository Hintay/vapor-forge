use vapor_forge_core::{AppId, DepotId, ManifestId};

use crate::bindings::parse_hex_key;
use crate::{
    execute_scripts, execute_scripts_report, execute_scripts_report_with_options,
    execute_scripts_runtime, ScriptExecutionOptions,
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
    std::fs::write(dir.join("test.lua"), "AddAppId(480)\nADDAPPID(730)\n").unwrap();

    let state = execute_scripts(&[dir.to_string_lossy().into_owned()]);
    assert_eq!(state.apps, [AppId(480), AppId(730)].into_iter().collect());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn addappid_deduplicates_and_rejects_out_of_range_ids() {
    let dir = std::env::temp_dir().join(format!("lua-addappid-validation-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("test.lua"),
        "addappid(-1)\naddappid(480)\naddappid(480)\n",
    )
    .unwrap();

    let report = execute_scripts_report(&[dir.to_string_lossy().into_owned()]);
    assert_eq!(report.state.apps, [AppId(480)].into_iter().collect());
    assert!(report.files[0]
        .result
        .as_ref()
        .unwrap_err()
        .contains("arg1 must be integer"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn addappid_only_records_exact_depot_keys() {
    let dir = std::env::temp_dir().join(format!("lua-depot-key-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("test.lua"),
        concat!(
            "addappid(480, 1, \"deadbeef\")\n",
            "addappid(730, 1, \"0000000000000000000000000000000000000000000000000000000000000000\")\n",
        ),
    )
    .unwrap();

    let state = execute_scripts(&[dir.to_string_lossy().into_owned()]);
    assert!(!state.depot_keys.contains_key(&DepotId(480)));
    assert_eq!(state.depot_keys[&DepotId(730)], vec![0; 32]);

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
            "SETManifestID(12346, \"9876543211\", 2048)\n",
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
        "setStat(480, \"76561198000000000\")\n",
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
fn registered_functions_are_case_insensitive_and_addtoken_is_standard() {
    let dir = std::env::temp_dir().join(format!("lua-case-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("test.lua"),
        concat!(
            "AddAppId(480)\n",
            "SetAppTicket(480, \"deadbeef\")\n",
            "SETETICKET(480, \"cafebabe\")\n",
            "SetStat(480, \"76561198000000000\")\n",
            "SetAvatar(480, 730)\n",
            "AddToken(480, \"18446744073709551615\")\n",
            "assert(setAccessToken == nil)\n",
        ),
    )
    .unwrap();

    let state = execute_scripts(&[dir.to_string_lossy().into_owned()]);
    assert_eq!(state.apps, [AppId(480)].into_iter().collect());
    assert_eq!(state.app_tickets[&AppId(480)], vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(state.enc_tickets[&AppId(480)], vec![0xca, 0xfe, 0xba, 0xbe]);
    assert_eq!(state.stat_steam_ids[&AppId(480)], 76561198000000000);
    assert_eq!(state.avatars[&AppId(480)], AppId(730));
    assert_eq!(state.access_tokens[&AppId(480)], u64::MAX);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_code_callbacks_prefer_extended_then_fall_back_to_basic() {
    let dir = std::env::temp_dir().join(format!("lua-provider-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("00-helper.lua"),
        "function extended_code() return \"18446744073709551615\" end\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("manifest.lua"),
        concat!(
            "function fetch_manifest_code_ex(app_id, depot_id, gid)\n",
            "  if app_id == 480 and depot_id == 481 then return extended_code() end\n",
            "  return nil\n",
            "end\n",
            "function fetch_manifest_code(gid)\n",
            "  return \"9876543210\"\n",
            "end\n",
        ),
    )
    .unwrap();

    let runtime = execute_scripts_runtime(&[dir.to_string_lossy().into_owned()]);
    let provider = runtime.manifest_code_provider.unwrap();
    assert!(provider.has_extended());
    assert!(provider.has_basic());
    assert_eq!(provider.fetch(480, 481, 123).unwrap(), Some(u64::MAX));
    assert_eq!(provider.fetch(999, 1000, 123).unwrap(), Some(9876543210));
    assert_eq!(provider.fetch(0, 1000, 123).unwrap(), Some(9876543210));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_callback_receives_exact_64_bit_gid() {
    let dir = std::env::temp_dir().join(format!("lua-provider-gid-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("manifest.lua"),
        "function fetch_manifest_code(gid) return tostring(gid) end\n",
    )
    .unwrap();

    let runtime = execute_scripts_runtime(&[dir.to_string_lossy().into_owned()]);
    let provider = runtime.manifest_code_provider.unwrap();
    let gid = 7_722_356_807_987_328_477_u64;
    assert_eq!(provider.fetch(1, 1, gid).unwrap(), Some(gid));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_callback_instruction_budget_stops_infinite_loop() {
    let dir = std::env::temp_dir().join(format!("lua-provider-budget-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("manifest.lua");
    std::fs::write(
        &path,
        "function fetch_manifest_code(gid) while true do end end\n",
    )
    .unwrap();

    let runtime = execute_scripts_runtime(&[dir.to_string_lossy().into_owned()]);
    let registry = runtime.registry.unwrap();
    let error = registry.invoke_basic(1).unwrap_err();
    assert!(error
        .to_string()
        .contains("manifest provider instruction budget exhausted"));

    let errors = registry.parse_file(
        &path,
        "function fetch_manifest_code(gid) return tostring(gid + 1) end\n",
    );
    assert!(errors.is_empty());
    assert_eq!(registry.invoke_basic(41).unwrap(), Some(42));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_callback_instruction_budget_allows_normal_provider() {
    let dir =
        std::env::temp_dir().join(format!("lua-provider-budget-normal-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("manifest.lua"),
        concat!(
            "function fetch_manifest_code(gid)\n",
            "  local total = 0\n",
            "  for i = 1, 1000 do total = total + i end\n",
            "  return tostring(gid + total)\n",
            "end\n",
        ),
    )
    .unwrap();

    let runtime = execute_scripts_runtime(&[dir.to_string_lossy().into_owned()]);
    let provider = runtime.manifest_code_provider.unwrap();
    assert_eq!(provider.fetch(1, 1, 9).unwrap(), Some(500_509));
    assert_eq!(provider.fetch(1, 1, 10).unwrap(), Some(500_510));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_callback_allows_only_one_http_request() {
    let dir = std::env::temp_dir().join(format!("lua-provider-http-budget-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("manifest.lua");
    std::fs::write(
        &path,
        concat!(
            "function fetch_manifest_code(gid)\n",
            "  http_get(\"invalid://first\")\n",
            "  http_get(\"invalid://second\")\n",
            "  return tostring(gid)\n",
            "end\n",
        ),
    )
    .unwrap();

    let runtime = execute_scripts_runtime(&[dir.to_string_lossy().into_owned()]);
    let registry = runtime.registry.unwrap();
    let error = registry.invoke_basic(1).unwrap_err();
    assert!(error
        .to_string()
        .contains("manifest provider HTTP request budget exhausted"));

    let errors = registry.parse_file(
        &path,
        concat!(
            "function fetch_manifest_code(gid)\n",
            "  http_get(\"invalid://only\")\n",
            "  return tostring(gid)\n",
            "end\n",
        ),
    );
    assert!(errors.is_empty());
    assert_eq!(registry.invoke_basic(9).unwrap(), Some(9));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripts_share_one_vm_and_continue_after_runtime_errors() {
    let dir = std::env::temp_dir().join(format!("lua-shared-runtime-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("00-helper.lua"),
        "function shared_app() return 480 end\naddappid(shared_app())\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("10-consumer.lua"),
        concat!(
            "error(\"expected failure\")\n",
            "addappid(730)\n",
            "function fetch_manifest_code(gid) return tostring(shared_app() + gid) end\n",
        ),
    )
    .unwrap();

    let report = execute_scripts_report(&[dir.to_string_lossy().into_owned()]);
    assert_eq!(
        report.state.apps,
        [AppId(480), AppId(730)].into_iter().collect()
    );
    assert!(report.files.iter().any(|file| file.result.is_err()));
    assert!(report
        .manifest_code_provider
        .unwrap()
        .fetch(1, 1, 1)
        .unwrap()
        .is_some_and(|code| code == 481));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn provider_scripts_execute_top_level_side_effects_once() {
    let dir = std::env::temp_dir().join(format!("lua-single-execution-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("manifest.lua"),
        concat!(
            "load_count = (load_count or 0) + 1\n",
            "function fetch_manifest_code(gid) return tostring(load_count) end\n",
        ),
    )
    .unwrap();

    let runtime = execute_scripts_runtime(&[dir.to_string_lossy().into_owned()]);
    let provider = runtime.manifest_code_provider.unwrap();
    assert_eq!(provider.fetch(1, 1, 1).unwrap(), Some(1));
    assert_eq!(provider.fetch(1, 1, 2).unwrap(), Some(1));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn script_registry_excludes_blocking_and_escape_libraries() {
    let dir = std::env::temp_dir().join(format!("lua-restricted-libs-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("restricted.lua"),
        concat!(
            "assert(io == nil and os == nil and package == nil)\n",
            "assert(debug == nil and ffi == nil and jit == nil)\n",
            "assert(require == nil and dofile == nil and loadfile == nil)\n",
            "assert(print == nil and coroutine == nil)\n",
            "assert(math.floor(1.9) == 1)\n",
            "assert(string.lower(\"A\") == \"a\")\n",
            "assert(table.concat({\"a\", \"b\"}) == \"ab\")\n",
            "assert(bit.bxor(1, 3) == 2)\n",
            "addappid(480)\n",
        ),
    )
    .unwrap();

    let report = execute_scripts_report(&[dir.to_string_lossy().into_owned()]);
    assert!(report.files.iter().all(|file| file.result.is_ok()));
    assert_eq!(report.state.apps, [AppId(480)].into_iter().collect());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripts_without_manifest_callbacks_do_not_create_provider() {
    let dir = std::env::temp_dir().join(format!("lua-no-provider-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join("app.lua"), "addappid(736260)\n").unwrap();

    let runtime = execute_scripts_runtime(&[dir.to_string_lossy().into_owned()]);
    assert_eq!(runtime.state.apps, [AppId(736260)].into_iter().collect());
    assert!(runtime.manifest_code_provider.is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn incremental_reload_removes_file_apps_after_the_last_reference() {
    let dir = std::env::temp_dir().join(format!(
        "lua-incremental-app-removal-{}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let first = dir.join("00-first.lua");
    let second = dir.join("10-second.lua");
    std::fs::write(&first, "addappid(480)\n").unwrap();
    std::fs::write(&second, "addappid(480)\n").unwrap();

    let runtime = execute_scripts_runtime(&[dir.to_string_lossy().into_owned()]);
    let registry = runtime.registry.unwrap();
    assert_eq!(
        registry.snapshot_state().apps,
        [AppId(480)].into_iter().collect()
    );

    registry.unload_file(&first);
    assert_eq!(
        registry.snapshot_state().apps,
        [AppId(480)].into_iter().collect()
    );

    let errors = registry.parse_file(&second, "addappid(730)\n");
    assert!(errors.is_empty());
    assert_eq!(
        registry.snapshot_state().apps,
        [AppId(730)].into_iter().collect()
    );

    registry.unload_file(&second);
    assert!(registry.snapshot_state().apps.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn http_helpers_accept_headers_and_return_failure_status() {
    let dir = std::env::temp_dir().join(format!("lua-http-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("test.lua"),
        concat!(
            "body, status = HTTP_GET(\"invalid://manifest\", ",
            "{[\"X-Test\"] = \"yes\"})\n",
            "assert(body == nil)\n",
            "assert(status == \"HTTP request failed\")\n",
            "post_body, post_status = HTTP_POST(\"invalid://manifest\", \"x=1\", ",
            "{[\"X-Test\"] = \"yes\"})\n",
            "assert(post_body == nil)\n",
            "assert(post_status == \"HTTP request failed\")\n",
        ),
    )
    .unwrap();

    let report = execute_scripts_report(&[dir.to_string_lossy().into_owned()]);
    assert!(report.files.iter().all(|file| file.result.is_ok()));

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
