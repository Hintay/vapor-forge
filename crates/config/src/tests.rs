use crate::template::{parse_commented_section_header, CommentedSectionHeader, TEMPLATE_EXAMPLES};
use crate::{
    AppCategory, AppId, CloudBackendMode, RuntimeConfig, TicketCacheMode, CONFIG_TEMPLATE,
};

#[test]
fn parses_empty_config() {
    let config: RuntimeConfig = toml::from_str("").expect("empty config should parse");
    assert!(!config.has_any_inject_apps());
    assert!(config.should_bypass_sharing(AppId(480)));
    assert!(config.toast.enabled);
    assert!(config.toast.init);
    assert_eq!(config.debug.control_api, cfg!(debug_assertions));
}

#[test]
fn template_parses_and_keeps_safe_defaults() {
    let config: RuntimeConfig = toml::from_str(CONFIG_TEMPLATE).expect("template should parse");
    assert_eq!(config.runtime.log_level, "info");
    assert!(!config.runtime.diagnostics);
    assert!(config.toast.enabled);
    assert!(config.toast.init);
    assert!(config.apps.shared.enabled);
    assert!(!config.has_any_inject_apps());
    assert!(!config.cloud_enabled_for_controlled_apps());
    assert_eq!(config.cloud.backend, CloudBackendMode::Disabled);
    assert!(!config.cloud.local.syncthing.enabled);
    assert_eq!(config.cloud.local.syncthing.url, "http://127.0.0.1:8384");
    assert!(config.cloud.local.syncthing.api_key.is_empty());
    assert!(config.cloud.local.syncthing.folder_id.is_empty());
    assert_eq!(config.ticket.cache, TicketCacheMode::Disk);
    assert!(!config.ticket.auto_delegate);
}

#[test]
fn template_example_metadata_matches_default_template() {
    let dry_run = RuntimeConfig::sync_default_template_dry_run(CONFIG_TEMPLATE)
        .expect("template dry-run should succeed");
    let expected = TEMPLATE_EXAMPLES
        .iter()
        .map(|example| (*example).to_owned())
        .collect::<Vec<_>>();

    assert!(!dry_run.changed);
    assert_eq!(dry_run.kept_commented_examples, expected);
    assert!(dry_run.pruned_commented_examples.is_empty());
}

#[test]
fn commented_section_header_is_not_runtime_config() {
    let config: RuntimeConfig =
        toml::from_str("#[debug]\n# control_api = false\n").expect("comment should parse");

    assert_eq!(config.debug.control_api, cfg!(debug_assertions));
    assert_eq!(
        parse_commented_section_header("#[debug]\n"),
        Some(CommentedSectionHeader {
            path: vec!["debug".to_owned()],
            array: false,
        })
    );
    assert_eq!(
        parse_commented_section_header("# [[apps.inject]]\n"),
        Some(CommentedSectionHeader {
            path: vec!["apps".to_owned(), "inject".to_owned()],
            array: true,
        })
    );
}

#[test]
fn write_default_template_does_not_overwrite() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "vapor-forge-config-test-{}-{unique}",
        std::process::id()
    ));
    let path = dir.join("config.toml");

    RuntimeConfig::write_default_template(&path).expect("first write should create template");
    let err = RuntimeConfig::write_default_template(&path)
        .expect_err("second write must not overwrite existing config");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

    let written = std::fs::read_to_string(&path).expect("template should be readable");
    assert!(written.contains("Vapor Forge configuration"));

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sync_default_template_adds_sorts_and_preserves_values() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "vapor-forge-config-sync-test-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        r#"[ticket]
auto_delegate = true

[runtime]
diagnostics = true

[custom]
value = 1
"#,
    )
    .expect("test config should be written");

    assert!(RuntimeConfig::sync_default_template(&path).expect("sync should succeed"));
    let synced = std::fs::read_to_string(&path).expect("synced config should be readable");
    let config: RuntimeConfig = toml::from_str(&synced).expect("synced config should parse");

    assert!(config.runtime.diagnostics);
    assert!(config.ticket.auto_delegate);
    assert_eq!(config.ticket.cache, TicketCacheMode::Disk);
    assert!(synced.contains(r#"log_level = "info""#));
    assert!(synced.contains("[toast]"));
    assert!(synced.contains("[apps.shared]"));
    assert!(synced.contains("[custom]"));
    assert!(synced.contains("# [[apps.inject]]"));
    assert!(synced.contains("# [[library_inject.libs]]"));

    let runtime_pos = synced
        .find("[runtime]")
        .expect("runtime table should exist");
    let toast_pos = synced.find("[toast]").expect("toast table should exist");
    let apps_pos = synced
        .find("[apps.shared]")
        .expect("apps.shared table should exist");
    let cloud_pos = synced.find("[cloud]").expect("cloud table should exist");
    let ticket_pos = synced.find("[ticket]").expect("ticket table should exist");
    let manifest_pos = synced
        .find("[manifest]")
        .expect("manifest table should exist");
    let achievements_pos = synced
        .find("[achievements]")
        .expect("achievements table should exist");
    let scripting_pos = synced
        .find("[scripting]")
        .expect("scripting table should exist");
    let custom_pos = synced.find("[custom]").expect("custom table should exist");
    assert!(runtime_pos < toast_pos);
    assert!(toast_pos < apps_pos);
    assert!(apps_pos < cloud_pos);
    assert!(cloud_pos < ticket_pos);
    assert!(ticket_pos < custom_pos);

    let debug_example_pos = synced
        .find("# [debug]")
        .expect("debug example should exist");
    let runtime_example_pos = synced
        .find("# patterns_url")
        .expect("runtime example should exist");
    let shared_example_pos = synced
        .find("# include")
        .expect("apps.shared example should exist");
    let app_example_pos = synced
        .find("# [[apps.inject]]")
        .expect("apps example should exist");
    let manifest_example_pos = synced
        .find("# providers")
        .expect("manifest example should exist");
    let avatar_example_pos = synced
        .find("# [app_avatar]")
        .expect("app_avatar example should exist");
    let library_example_pos = synced
        .find("# [[library_inject.libs]]")
        .expect("library_inject example should exist");
    assert!(runtime_pos < runtime_example_pos);
    assert!(runtime_example_pos < toast_pos);
    assert!(apps_pos < shared_example_pos);
    assert!(shared_example_pos < cloud_pos);
    assert!(manifest_pos < manifest_example_pos);
    assert!(manifest_example_pos < achievements_pos);
    assert!(scripting_pos < debug_example_pos);
    assert!(debug_example_pos < app_example_pos);
    assert!(app_example_pos < avatar_example_pos);
    assert!(avatar_example_pos < library_example_pos);

    assert!(!RuntimeConfig::sync_default_template(&path).expect("second sync should succeed"));

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sync_default_template_preserves_uncommented_examples_as_config() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "vapor-forge-config-edited-examples-test-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        r#"[runtime]
diagnostics = true

[debug]
control_api = false
"#,
    )
    .expect("test config should be written");

    assert!(RuntimeConfig::sync_default_template(&path).expect("sync should succeed"));
    let synced = std::fs::read_to_string(&path).expect("synced config should be readable");
    let config: RuntimeConfig = toml::from_str(&synced).expect("synced config should parse");

    assert!(config.runtime.diagnostics);
    assert!(!config.debug.control_api);
    assert!(synced.contains("[debug]"));
    assert!(!synced.contains("Development API socket"));
    assert!(!synced.contains("# [debug]"));
    assert!(!synced.contains("# control_api"));
    assert!(synced.contains("# [[apps.inject]]"));
    assert!(synced.contains("# [[library_inject.libs]]"));
    assert!(synced.contains("[toast]"));

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sync_default_template_dry_run_reports_changes() {
    let dry_run = RuntimeConfig::sync_default_template_dry_run(
        r#"[runtime]
diagnostics = true

[debug]
control_api = false
"#,
    )
    .expect("dry-run should succeed");

    assert!(dry_run.changed);
    assert!(dry_run
        .added_fields
        .contains(&"runtime.log_level".to_owned()));
    assert!(dry_run.added_fields.contains(&"toast.enabled".to_owned()));
    assert!(dry_run
        .kept_commented_examples
        .contains(&"[[apps.inject]]".to_owned()));
    assert!(dry_run
        .pruned_commented_examples
        .contains(&"[debug]".to_owned()));
    assert!(!dry_run.synced.contains("# [debug]"));
    let config: RuntimeConfig = toml::from_str(&dry_run.synced).expect("synced config parses");
    assert!(config.runtime.diagnostics);
    assert!(!config.debug.control_api);
}

#[test]
fn sync_default_template_prunes_examples_for_dotted_user_config() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "vapor-forge-config-dotted-example-test-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    let path = dir.join("config.toml");
    std::fs::write(&path, "debug.control_api = false\n").expect("test config should be written");

    assert!(RuntimeConfig::sync_default_template(&path).expect("sync should succeed"));
    let synced = std::fs::read_to_string(&path).expect("synced config should be readable");
    let config: RuntimeConfig = toml::from_str(&synced).expect("synced config should parse");

    assert!(!config.debug.control_api);
    assert!(synced.contains("debug.control_api = false"));
    assert!(!synced.contains("Development API socket"));
    assert!(!synced.contains("# [debug]"));

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn steam_toasts_can_be_disabled() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [toast]
            enabled = false
            init = false
            "#,
    )
    .expect("parse");

    assert!(!config.toast.enabled);
    assert!(!config.toast.init);
}

#[test]
fn debug_control_api_can_be_disabled() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [debug]
            control_api = false
            "#,
    )
    .expect("parse");

    assert!(!config.debug.control_api);
}

#[test]
fn shared_enabled_by_default() {
    let config: RuntimeConfig = toml::from_str("").expect("parse");
    assert!(config.apps.shared.enabled);
    assert!(config.should_bypass_sharing(AppId(12345)));
}

#[test]
fn shared_include_restricts() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [apps.shared]
            include = [570, 730]
            "#,
    )
    .expect("parse");
    assert!(config.should_bypass_sharing(AppId(570)));
    assert!(config.should_bypass_sharing(AppId(730)));
    assert!(!config.should_bypass_sharing(AppId(480)));
}

#[test]
fn shared_exclude_blocks() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [apps.shared]
            exclude = [730]
            "#,
    )
    .expect("parse");
    assert!(config.should_bypass_sharing(AppId(570)));
    assert!(!config.should_bypass_sharing(AppId(730)));
}

#[test]
fn shared_can_be_disabled() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [apps.shared]
            enabled = false
            "#,
    )
    .expect("parse");
    assert!(!config.should_bypass_sharing(AppId(480)));
}

#[test]
fn parses_inject_with_dlc() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [[apps.inject]]
            id = 480
            dlc = [505730, 505740]

            [[apps.inject]]
            id = 730
            "#,
    )
    .expect("parse");

    assert_eq!(config.app_category(AppId(480)), Some(AppCategory::Inject));
    assert_eq!(config.app_category(AppId(730)), Some(AppCategory::Inject));
    assert_eq!(
        config.app_category(AppId(505730)),
        Some(AppCategory::InjectDlc { parent: AppId(480) })
    );
    assert_eq!(config.app_category(AppId(999)), None);
    assert!(config.is_controlled_app(AppId(480)));
    assert!(config.is_controlled_app(AppId(505730)));
    assert!(!config.is_controlled_app(AppId(999)));

    let all = config.inject_app_ids();
    assert_eq!(all.len(), 4);
}

#[test]
fn cloud_defaults_to_disabled() {
    let config: RuntimeConfig = toml::from_str("").expect("parse");
    assert_eq!(config.cloud.backend, CloudBackendMode::Disabled);
    assert!(!config.cloud_enabled_for_controlled_apps());
    assert!(!config.local_cloud_configured());
    assert!(!config.cumulus_configured());
    assert_eq!(config.cloud.cumulus.timeout_connect_ms, 5000);
    assert_eq!(config.cloud.cumulus.timeout_ms, 15000);
}

#[test]
fn cumulus_configuration_enables_controlled_cloud() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [cloud]
            backend = "cumulus"

            [cloud.cumulus]
            server_url = "https://cloud.example.com/base"
            token = "device-token"
            timeout_connect_ms = 123
            timeout_ms = 456
            "#,
    )
    .expect("parse");

    assert!(config.cumulus_configured());
    assert!(config.cloud_enabled_for_controlled_apps());
    assert_eq!(config.cloud.cumulus.timeout_connect_ms, 123);
    assert_eq!(config.cloud.cumulus.timeout_ms, 456);
}

#[test]
fn local_configuration_enables_only_the_local_backend() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [cloud]
            backend = "local"

            [cloud.local]
            path = "/tmp/vapor-cloud"
            "#,
    )
    .expect("parse");

    assert!(config.local_cloud_configured());
    assert!(!config.cumulus_configured());
    assert!(config.cloud_enabled_for_controlled_apps());
    assert_eq!(config.cloud.local.path, "/tmp/vapor-cloud");
}

#[test]
fn dormant_backend_settings_do_not_enable_cloud() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [cloud.cumulus]
            server_url = "https://cloud.example.com/base"
            token = "device-token"
            "#,
    )
    .expect("parse");

    assert_eq!(config.cloud.backend, CloudBackendMode::Disabled);
    assert!(!config.cloud_enabled_for_controlled_apps());
    assert!(!config.cumulus_configured());
}

#[test]
fn ticket_defaults() {
    let config: RuntimeConfig = toml::from_str("").expect("parse");
    assert_eq!(config.ticket.cache, TicketCacheMode::Disk);
    assert!(!config.ticket.auto_delegate);
}

#[test]
fn ticket_session_cache_parses() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [ticket]
            cache = "session"
            "#,
    )
    .expect("parse");
    assert_eq!(config.ticket.cache, TicketCacheMode::Session);
}

#[test]
fn ticket_auto_delegate_parses() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [ticket]
            auto_delegate = true
            "#,
    )
    .expect("parse");
    assert!(config.ticket.auto_delegate);
}

#[test]
fn library_inject_defaults_to_empty() {
    let config: RuntimeConfig = toml::from_str("").expect("parse");
    assert!(config.library_inject.libs.is_empty());
}

#[test]
fn library_inject_parses_entries() {
    let config: RuntimeConfig = toml::from_str(
        r#"
            [[library_inject.libs]]
            path = "/home/user/mylib.so"
            flag = "-onlinefix"
            apps = [480]
            exclude = [730]
            "#,
    )
    .expect("parse");
    assert_eq!(config.library_inject.libs.len(), 1);
    let entry = &config.library_inject.libs[0];
    assert_eq!(entry.path, "/home/user/mylib.so");
    assert_eq!(entry.flag, "-onlinefix");
    assert_eq!(entry.apps, vec![AppId(480)]);
    assert_eq!(entry.exclude, vec![AppId(730)]);
}
