use std::collections::HashMap;
use std::path::PathBuf;

use serde::Serialize;
use vapor_forge_core::{AppId, DepotId};
use vapor_forge_scripting::{
    execute_scripts_report_with_options, ManifestOverride, ScriptCallReport,
    ScriptExecutionOptions, ScriptExecutionReport, ScriptFileReport, ScriptState,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-script-check: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let dirs = args
        .dirs
        .iter()
        .map(|dir| dir.display().to_string())
        .collect::<Vec<_>>();
    let report = execute_scripts_report_with_options(
        &dirs,
        ScriptExecutionOptions {
            allow_network: args.allow_network,
            allowed_hosts: args.allowed_hosts.clone(),
            network_timeout_ms: args.network_timeout_ms,
            redact_network_urls: !args.show_url_query,
            record_calls: true,
        },
    );

    if args.format == OutputFormat::Json {
        print_json(&args, &dirs, &report)?;
    } else {
        print_text(&args, &dirs, &report);
    }

    if report.files.iter().any(|file| file.result.is_err()) {
        return Err("one or more scripts failed".to_owned());
    }

    Ok(())
}

fn print_text(args: &Args, dirs: &[String], report: &ScriptExecutionReport) {
    print_list("script_dirs", &dirs);
    println!("network_allowed={}", args.allow_network);
    print_list("allowed_hosts", &args.allowed_hosts);
    if let Some(timeout_ms) = args.network_timeout_ms {
        println!("network_timeout_ms={timeout_ms}");
    }
    print_list("skipped_dirs", &report.skipped_dirs);
    println!(
        "fetch_manifest_code={}",
        report
            .manifest_code_provider
            .as_ref()
            .is_some_and(|provider| provider.has_basic())
    );
    println!(
        "fetch_manifest_code_ex={}",
        report
            .manifest_code_provider
            .as_ref()
            .is_some_and(|provider| provider.has_extended())
    );

    println!("file_execution_order:");
    if report.files.is_empty() {
        println!("  (none)");
    } else {
        for (index, file) in report.files.iter().enumerate() {
            match &file.result {
                Ok(()) => println!("  - #{:03} ok {}", index + 1, file.path),
                Err(error) => println!("  - #{:03} error {}: {error}", index + 1, file.path),
            }
        }
    }

    println!("lua_call_order:");
    if report.calls.is_empty() {
        println!("  (none)");
    } else {
        for (index, call) in report.calls.iter().enumerate() {
            println!(
                "  - #{:03} {} {} ({})",
                index + 1,
                call.function,
                call.detail,
                call.path
            );
        }
    }

    print_state(&report.state);
}

struct Args {
    dirs: Vec<PathBuf>,
    allow_network: bool,
    allowed_hosts: Vec<String>,
    network_timeout_ms: Option<u64>,
    show_url_query: bool,
    format: OutputFormat,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OutputFormat {
    Text,
    Json,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut dirs = Vec::new();
        let mut allow_network = false;
        let mut allowed_hosts = Vec::new();
        let mut network_timeout_ms = None;
        let mut show_url_query = false;
        let mut format = OutputFormat::Text;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--dir" => dirs.push(PathBuf::from(next_value(&mut args, "--dir")?)),
                "--allow-network" => allow_network = true,
                "--allow-host" => {
                    allow_network = true;
                    allowed_hosts.push(next_value(&mut args, "--allow-host")?);
                }
                "--network-timeout-ms" => {
                    let value = next_value(&mut args, "--network-timeout-ms")?;
                    network_timeout_ms =
                        Some(value.parse::<u64>().map_err(|error| {
                            format!("invalid --network-timeout-ms value: {error}")
                        })?);
                }
                "--show-url-query" => show_url_query = true,
                "--format" => {
                    let value = next_value(&mut args, "--format")?;
                    format = match value.as_str() {
                        "text" => OutputFormat::Text,
                        "json" => OutputFormat::Json,
                        other => return Err(format!("unsupported format {other:?}\n{}", usage())),
                    };
                }
                "-h" | "--help" => return Err(usage()),
                other if other.starts_with('-') => {
                    return Err(format!("unknown argument {other:?}\n{}", usage()));
                }
                path => dirs.push(PathBuf::from(path)),
            }
        }

        if dirs.is_empty() {
            return Err(usage());
        }

        Ok(Self {
            dirs,
            allow_network,
            allowed_hosts,
            network_timeout_ms,
            show_url_query,
            format,
        })
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value\n{}", usage()))
}

fn usage() -> String {
    concat!(
        "usage: vapor-forge-script-check [--dir DIR]... [DIR...]\n",
        "\n",
        "Executes Lua scripts with the clean Vapor Forge Lua API and prints final script state.\n",
        "http_get/http_post are disabled unless --allow-network or --allow-host HOST is passed.\n",
        "Options: --network-timeout-ms N, --show-url-query, --format text|json"
    )
    .to_owned()
}

fn print_state(state: &ScriptState) {
    print_app_list("addappid_apps", &state.apps);
    print_bytes_map("depot_keys", &state.depot_keys);
    print_manifests("manifests", &state.manifests);
    print_bytes_map("app_tickets", &state.app_tickets);
    print_bytes_map("encrypted_app_tickets", &state.enc_tickets);
    print_u64_map("stat_steam_ids", &state.stat_steam_ids);
    print_app_map("avatars", &state.avatars);
    print_u64_map("access_tokens", &state.access_tokens);
}

fn print_list(label: &str, values: &[String]) {
    println!("{label}:");
    if values.is_empty() {
        println!("  (none)");
    } else {
        for value in values {
            println!("  - {value}");
        }
    }
}

fn print_app_list(label: &str, values: &[AppId]) {
    println!("{label}:");
    if values.is_empty() {
        println!("  (none)");
    } else {
        for app_id in values {
            println!("  - {}", app_id.0);
        }
    }
}

fn print_bytes_map<K>(label: &str, values: &HashMap<K, Vec<u8>>)
where
    K: Copy + Eq + std::hash::Hash + Ord + IdValue,
{
    println!("{label}:");
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| key.id_value());

    if entries.is_empty() {
        println!("  (none)");
    } else {
        for (key, bytes) in entries {
            println!(
                "  - {} len={} hex={}",
                key.id_value(),
                bytes.len(),
                hex_string(bytes)
            );
        }
    }
}

fn print_manifests(label: &str, values: &HashMap<DepotId, ManifestOverride>) {
    println!("{label}:");
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(depot_id, _)| depot_id.0);

    if entries.is_empty() {
        println!("  (none)");
    } else {
        for (depot_id, manifest) in entries {
            match manifest.size {
                Some(size) => println!(
                    "  - depot={} gid={} size={size}",
                    depot_id.0, manifest.gid.0
                ),
                None => println!(
                    "  - depot={} gid={} size=(none)",
                    depot_id.0, manifest.gid.0
                ),
            }
        }
    }
}

fn print_u64_map<K>(label: &str, values: &HashMap<K, u64>)
where
    K: Copy + Eq + std::hash::Hash + Ord + IdValue,
{
    println!("{label}:");
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| key.id_value());

    if entries.is_empty() {
        println!("  (none)");
    } else {
        for (key, value) in entries {
            println!("  - {} {value}", key.id_value());
        }
    }
}

fn print_app_map(label: &str, values: &HashMap<AppId, AppId>) {
    println!("{label}:");
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(app_id, _)| app_id.0);

    if entries.is_empty() {
        println!("  (none)");
    } else {
        for (app_id, avatar) in entries {
            println!("  - {} -> {}", app_id.0, avatar.0);
        }
    }
}

trait IdValue {
    fn id_value(self) -> u32;
}

impl IdValue for AppId {
    fn id_value(self) -> u32 {
        self.0
    }
}

impl IdValue for DepotId {
    fn id_value(self) -> u32 {
        self.0
    }
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn print_json(args: &Args, dirs: &[String], report: &ScriptExecutionReport) -> Result<(), String> {
    let json = JsonOutput::from_report(args, dirs, report);
    let text = serde_json::to_string_pretty(&json)
        .map_err(|error| format!("serialize JSON failed: {error}"))?;
    println!("{text}");
    Ok(())
}

#[derive(Serialize)]
struct JsonOutput {
    script_dirs: Vec<String>,
    network_allowed: bool,
    allowed_hosts: Vec<String>,
    network_timeout_ms: Option<u64>,
    skipped_dirs: Vec<String>,
    fetch_manifest_code: bool,
    fetch_manifest_code_ex: bool,
    files: Vec<JsonFile>,
    lua_calls: Vec<JsonCall>,
    state: JsonState,
}

impl JsonOutput {
    fn from_report(args: &Args, dirs: &[String], report: &ScriptExecutionReport) -> Self {
        Self {
            script_dirs: dirs.to_vec(),
            network_allowed: args.allow_network,
            allowed_hosts: args.allowed_hosts.clone(),
            network_timeout_ms: args.network_timeout_ms,
            skipped_dirs: report.skipped_dirs.clone(),
            fetch_manifest_code: report
                .manifest_code_provider
                .as_ref()
                .is_some_and(|provider| provider.has_basic()),
            fetch_manifest_code_ex: report
                .manifest_code_provider
                .as_ref()
                .is_some_and(|provider| provider.has_extended()),
            files: report
                .files
                .iter()
                .enumerate()
                .map(|(index, file)| JsonFile::from_report(index + 1, file))
                .collect(),
            lua_calls: report
                .calls
                .iter()
                .enumerate()
                .map(|(index, call)| JsonCall::from_report(index + 1, call))
                .collect(),
            state: JsonState::from_state(&report.state),
        }
    }
}

#[derive(Serialize)]
struct JsonFile {
    order: usize,
    path: String,
    ok: bool,
    error: Option<String>,
}

impl JsonFile {
    fn from_report(order: usize, file: &ScriptFileReport) -> Self {
        Self {
            order,
            path: file.path.clone(),
            ok: file.result.is_ok(),
            error: file.result.as_ref().err().cloned(),
        }
    }
}

#[derive(Serialize)]
struct JsonCall {
    order: usize,
    path: String,
    function: &'static str,
    detail: String,
}

impl JsonCall {
    fn from_report(order: usize, call: &ScriptCallReport) -> Self {
        Self {
            order,
            path: call.path.clone(),
            function: call.function,
            detail: call.detail.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonState {
    addappid_apps: Vec<u32>,
    depot_keys: Vec<JsonBytesEntry>,
    manifests: Vec<JsonManifest>,
    app_tickets: Vec<JsonBytesEntry>,
    encrypted_app_tickets: Vec<JsonBytesEntry>,
    stat_steam_ids: Vec<JsonU64Entry>,
    avatars: Vec<JsonAvatarEntry>,
    access_tokens: Vec<JsonU64Entry>,
}

impl JsonState {
    fn from_state(state: &ScriptState) -> Self {
        Self {
            addappid_apps: state.apps.iter().map(|app_id| app_id.0).collect(),
            depot_keys: bytes_entries(&state.depot_keys),
            manifests: manifest_entries(&state.manifests),
            app_tickets: bytes_entries(&state.app_tickets),
            encrypted_app_tickets: bytes_entries(&state.enc_tickets),
            stat_steam_ids: u64_entries(&state.stat_steam_ids),
            avatars: avatar_entries(&state.avatars),
            access_tokens: u64_entries(&state.access_tokens),
        }
    }
}

#[derive(Serialize)]
struct JsonBytesEntry {
    id: u32,
    len: usize,
    hex: String,
}

#[derive(Serialize)]
struct JsonManifest {
    depot_id: u32,
    gid: u64,
    size: Option<u64>,
}

#[derive(Serialize)]
struct JsonU64Entry {
    id: u32,
    value: u64,
}

#[derive(Serialize)]
struct JsonAvatarEntry {
    app_id: u32,
    avatar: u32,
}

fn bytes_entries<K>(values: &HashMap<K, Vec<u8>>) -> Vec<JsonBytesEntry>
where
    K: Copy + Eq + std::hash::Hash + Ord + IdValue,
{
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| key.id_value());
    entries
        .into_iter()
        .map(|(key, bytes)| JsonBytesEntry {
            id: key.id_value(),
            len: bytes.len(),
            hex: hex_string(bytes),
        })
        .collect()
}

fn manifest_entries(values: &HashMap<DepotId, ManifestOverride>) -> Vec<JsonManifest> {
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(depot_id, _)| depot_id.0);
    entries
        .into_iter()
        .map(|(depot_id, manifest)| JsonManifest {
            depot_id: depot_id.0,
            gid: manifest.gid.0,
            size: manifest.size,
        })
        .collect()
}

fn u64_entries<K>(values: &HashMap<K, u64>) -> Vec<JsonU64Entry>
where
    K: Copy + Eq + std::hash::Hash + Ord + IdValue,
{
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| key.id_value());
    entries
        .into_iter()
        .map(|(key, value)| JsonU64Entry {
            id: key.id_value(),
            value: *value,
        })
        .collect()
}

fn avatar_entries(values: &HashMap<AppId, AppId>) -> Vec<JsonAvatarEntry> {
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(app_id, _)| app_id.0);
    entries
        .into_iter()
        .map(|(app_id, avatar)| JsonAvatarEntry {
            app_id: app_id.0,
            avatar: avatar.0,
        })
        .collect()
}
