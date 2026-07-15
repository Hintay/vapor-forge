use std::io::Read;
#[cfg(target_family = "unix")]
use std::io::Write;
#[cfg(target_family = "unix")]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use prost::Message;
use vapor_forge_abi::{
    CMsgClientGamesPlayed, CMsgProtoBufHeader, ClientGetUserStatsRequest,
    GetManifestRequestCodeRequest, PlayerGetUserStatsRequest, EMSG_CLIENT_RICH_PRESENCE_UPLOAD,
    EMSG_GAMESPLAYED, EMSG_GAMESPLAYED_WITH_DATABLOB, EMSG_PICS_PRODUCT_INFO_REQUEST,
    EMSG_REQUEST_USERSTATS, EMSG_SERVICE_METHOD_CALL_FROM_CLIENT, K_MSG_HDR_PROTO_FLAG,
};
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_packet_inspect::{
    summarize_packet, PacketChange, PacketDirection, PacketSummary, PacketType,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-packet-tool: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let Args {
        socket,
        format,
        command,
    } = Args::parse(std::env::args().skip(1))?;
    match command {
        Command::Capture(capture) => {
            let command = capture_command(capture, format);
            print_response(
                &send_debug_command(&resolve_socket(socket.as_deref())?, &command)?,
                format,
            )
        }
        Command::List(filters) => {
            let command = format!(
                "packet list{}{}",
                filter_suffix(&filters),
                json_suffix(format)
            );
            print_response(
                &send_debug_command(&resolve_socket(socket.as_deref())?, &command)?,
                format,
            )
        }
        Command::Show(id) => {
            let command = format!("packet show {id}{}", json_suffix(format));
            print_response(
                &send_debug_command(&resolve_socket(socket.as_deref())?, &command)?,
                format,
            )
        }
        Command::Save { id, path } => {
            let command = format!("packet save {id} {path}{}", json_suffix(format));
            print_response(
                &send_debug_command(&resolve_socket(socket.as_deref())?, &command)?,
                format,
            )
        }
        Command::Watch { filters, interval } => {
            watch(&resolve_socket(socket.as_deref())?, filters, interval)
        }
        Command::Decode { input, direction } => decode_offline(input, direction, format),
        Command::Explain { input, direction } => explain_offline(input, direction, format),
        Command::Simulate {
            input,
            direction,
            config,
        } => simulate_offline(input, direction, config, format),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Text,
    Json,
}

struct Args {
    socket: Option<String>,
    format: OutputFormat,
    command: Command,
}

enum Command {
    Capture(CaptureCommand),
    List(Filters),
    Show(u64),
    Save {
        id: u64,
        path: String,
    },
    Watch {
        filters: Filters,
        interval: Duration,
    },
    Decode {
        input: Input,
        direction: PacketDirection,
    },
    Explain {
        input: Input,
        direction: PacketDirection,
    },
    Simulate {
        input: Input,
        direction: PacketDirection,
        config: Option<String>,
    },
}

enum CaptureCommand {
    Status,
    On { raw: bool, filters: Filters },
    Off,
    Clear,
    Limit(usize),
    FilterClear,
}

#[derive(Default)]
struct Filters {
    direction: Option<String>,
    packet_type: Option<String>,
    emsg: Option<String>,
    app_id: Option<String>,
    changed: Option<String>,
}

enum Input {
    File(String),
    Hex(String),
    StdinHex,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut socket = None;
        let mut format = OutputFormat::Text;
        let mut rest = Vec::new();
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--socket" => socket = Some(next_value(&mut args, "--socket")?),
                "--format" => {
                    format = match next_value(&mut args, "--format")?.as_str() {
                        "text" => OutputFormat::Text,
                        "json" => OutputFormat::Json,
                        other => return Err(format!("unsupported format {other:?}\n{}", usage())),
                    };
                }
                "-h" | "--help" => return Err(usage()),
                other => {
                    rest.push(other.to_owned());
                    rest.extend(args);
                    break;
                }
            }
        }

        if rest.is_empty() {
            return Err(usage());
        }

        let command = parse_command(&rest)?;
        Ok(Self {
            socket,
            format,
            command,
        })
    }
}

fn resolve_socket(socket: Option<&str>) -> Result<String, String> {
    match socket {
        Some(socket) => Ok(socket.to_owned()),
        None => default_socket_path(),
    }
}

fn parse_command(args: &[String]) -> Result<Command, String> {
    match args[0].as_str() {
        "capture" => parse_capture(&args[1..]).map(Command::Capture),
        "list" => Ok(Command::List(parse_filters(&args[1..])?)),
        "show" => {
            let id = args
                .get(1)
                .ok_or_else(usage)?
                .parse::<u64>()
                .map_err(|error| format!("invalid packet id: {error}"))?;
            Ok(Command::Show(id))
        }
        "save" => {
            let id = args
                .get(1)
                .ok_or_else(usage)?
                .parse::<u64>()
                .map_err(|error| format!("invalid packet id: {error}"))?;
            let path = args.get(2).ok_or_else(usage)?.to_owned();
            Ok(Command::Save { id, path })
        }
        "watch" => parse_watch(&args[1..]),
        "decode" => {
            let (input, direction) = parse_offline_args(&args[1..], PacketDirection::Recv)?;
            Ok(Command::Decode { input, direction })
        }
        "explain" => {
            let (direction, rest) = match args.get(1).map(String::as_str) {
                Some("send") => (PacketDirection::Send, &args[2..]),
                Some("recv") => (PacketDirection::Recv, &args[2..]),
                _ => (PacketDirection::Recv, &args[1..]),
            };
            let (input, _) = parse_offline_args(rest, direction)?;
            Ok(Command::Explain { input, direction })
        }
        "simulate" => parse_simulate(&args[1..]),
        other => Err(format!("unknown command {other:?}\n{}", usage())),
    }
}

fn parse_simulate(args: &[String]) -> Result<Command, String> {
    let (direction, rest) = match args.first().map(String::as_str) {
        Some("send") => (PacketDirection::Send, &args[1..]),
        Some("recv") => (PacketDirection::Recv, &args[1..]),
        _ => (PacketDirection::Send, args),
    };
    let mut input = Input::StdinHex;
    let mut config = None;
    let mut index = 0usize;
    while index < rest.len() {
        match rest[index].as_str() {
            "--file" => {
                index += 1;
                input = Input::File(required(rest, index, "--file")?.to_owned());
            }
            "--hex" => {
                index += 1;
                input = Input::Hex(required(rest, index, "--hex")?.to_owned());
            }
            "--config" => {
                index += 1;
                config = Some(required(rest, index, "--config")?.to_owned());
            }
            other => return Err(format!("unknown simulate option {other:?}\n{}", usage())),
        }
        index += 1;
    }
    Ok(Command::Simulate {
        input,
        direction,
        config,
    })
}

fn parse_offline_args(
    args: &[String],
    default_direction: PacketDirection,
) -> Result<(Input, PacketDirection), String> {
    let mut input = Input::StdinHex;
    let mut direction = default_direction;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--file" => {
                index += 1;
                input = Input::File(required(args, index, "--file")?.to_owned());
            }
            "--hex" => {
                index += 1;
                input = Input::Hex(required(args, index, "--hex")?.to_owned());
            }
            "--direction" => {
                index += 1;
                direction = parse_direction(required(args, index, "--direction")?)?;
            }
            other => return Err(format!("unknown offline option {other:?}\n{}", usage())),
        }
        index += 1;
    }
    Ok((input, direction))
}

fn parse_capture(args: &[String]) -> Result<CaptureCommand, String> {
    match args.first().map(String::as_str) {
        None | Some("status") => Ok(CaptureCommand::Status),
        Some("off") => Ok(CaptureCommand::Off),
        Some("clear") => Ok(CaptureCommand::Clear),
        Some("filter-clear") => Ok(CaptureCommand::FilterClear),
        Some("limit") => {
            let limit = args
                .get(1)
                .ok_or_else(usage)?
                .parse::<usize>()
                .map_err(|error| format!("invalid limit: {error}"))?;
            Ok(CaptureCommand::Limit(limit))
        }
        Some("on") => {
            let mut raw = false;
            let mut filter_args = Vec::new();
            for arg in &args[1..] {
                match arg.as_str() {
                    "--raw" | "raw" => raw = true,
                    "summary" => raw = false,
                    other => filter_args.push(other.to_owned()),
                }
            }
            Ok(CaptureCommand::On {
                raw,
                filters: parse_filters(&filter_args)?,
            })
        }
        Some(other) => Err(format!("unknown capture command {other:?}\n{}", usage())),
    }
}

fn parse_watch(args: &[String]) -> Result<Command, String> {
    let mut interval = Duration::from_millis(1000);
    let mut filter_args = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--interval-ms" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--interval-ms requires a value".to_owned())?;
                let ms = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid interval: {error}"))?;
                interval = Duration::from_millis(ms);
            }
            other => filter_args.push(other.to_owned()),
        }
        index += 1;
    }
    Ok(Command::Watch {
        filters: parse_filters(&filter_args)?,
        interval,
    })
}

fn parse_filters(args: &[String]) -> Result<Filters, String> {
    let mut filters = Filters::default();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--direction" => {
                index += 1;
                filters.direction = Some(required(args, index, "--direction")?.to_owned());
            }
            "--type" => {
                index += 1;
                filters.packet_type = Some(required(args, index, "--type")?.to_owned());
            }
            "--emsg" => {
                index += 1;
                filters.emsg = Some(required(args, index, "--emsg")?.to_owned());
            }
            "--app-id" | "--app" => {
                index += 1;
                filters.app_id = Some(required(args, index, "--app-id")?.to_owned());
            }
            "--changed" | "--change" => {
                index += 1;
                filters.changed = Some(required(args, index, "--changed")?.to_owned());
            }
            other => {
                if let Some((key, value)) = other.split_once('=') {
                    set_filter(&mut filters, key, value)?;
                } else {
                    return Err(format!("unknown filter {other:?}\n{}", usage()));
                }
            }
        }
        index += 1;
    }
    Ok(filters)
}

fn set_filter(filters: &mut Filters, key: &str, value: &str) -> Result<(), String> {
    match key {
        "direction" | "dir" => filters.direction = Some(value.to_owned()),
        "type" => filters.packet_type = Some(value.to_owned()),
        "emsg" => filters.emsg = Some(value.to_owned()),
        "app" | "app_id" | "appid" => filters.app_id = Some(value.to_owned()),
        "changed" | "change" => filters.changed = Some(value.to_owned()),
        other => return Err(format!("unknown filter key {other:?}")),
    }
    Ok(())
}

fn capture_command(command: CaptureCommand, format: OutputFormat) -> String {
    let command = match command {
        CaptureCommand::Status => "packet capture status".to_owned(),
        CaptureCommand::On { raw, filters } => format!(
            "packet capture on {}{}",
            if raw { "raw" } else { "summary" },
            filter_suffix(&filters)
        ),
        CaptureCommand::Off => "packet capture off".to_owned(),
        CaptureCommand::Clear => "packet capture clear".to_owned(),
        CaptureCommand::Limit(limit) => format!("packet capture limit {limit}"),
        CaptureCommand::FilterClear => "packet capture filter clear".to_owned(),
    };
    format!("{command}{}", json_suffix(format))
}

fn filter_suffix(filters: &Filters) -> String {
    let mut out = String::new();
    if let Some(value) = &filters.direction {
        out.push_str(&format!(" direction={value}"));
    }
    if let Some(value) = &filters.packet_type {
        out.push_str(&format!(" type={value}"));
    }
    if let Some(value) = &filters.emsg {
        out.push_str(&format!(" emsg={value}"));
    }
    if let Some(value) = &filters.app_id {
        out.push_str(&format!(" app={value}"));
    }
    if let Some(value) = &filters.changed {
        out.push_str(&format!(" changed={value}"));
    }
    out
}

fn watch(socket: &str, filters: Filters, interval: Duration) -> Result<(), String> {
    let mut last_id = 0u64;
    loop {
        let command = format!("packet list{} --json", filter_suffix(&filters));
        let response = send_debug_command(socket, &command)?;
        let json = ok_payload(&response)?;
        let packets: serde_json::Value =
            serde_json::from_str(json).map_err(|error| format!("parse JSON failed: {error}"))?;
        let Some(array) = packets.as_array() else {
            return Err("packet list did not return an array".to_owned());
        };

        for packet in array {
            let Some(summary) = packet.get("summary") else {
                continue;
            };
            let id = summary
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if id <= last_id {
                continue;
            }
            println!("{}", format_summary_json(summary));
            last_id = last_id.max(id);
        }

        std::thread::sleep(interval);
    }
}

fn format_summary_json(summary: &serde_json::Value) -> String {
    let id = summary
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let direction = summary
        .get("direction")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let emsg = summary
        .get("emsg")
        .and_then(serde_json::Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let packet_type = summary
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let changed = summary
        .get("change")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let app_ids = summary.get("app_ids").unwrap_or(&serde_json::Value::Null);
    format!(
        "#{id:<4} {direction:<4} emsg={emsg:<5} type={packet_type:<16} app={app_ids} change={changed}"
    )
}

fn decode_offline(
    input: Input,
    direction: PacketDirection,
    format: OutputFormat,
) -> Result<(), String> {
    let bytes = input.read()?;
    let summary = summarize_packet(0, direction, &bytes, PacketChange::Unchanged, None);
    match format {
        OutputFormat::Text => {
            println!("{}", format_summary(&summary));
            Ok(())
        }
        OutputFormat::Json => {
            println!("{}", summary_json(&summary));
            Ok(())
        }
    }
}

fn explain_offline(
    input: Input,
    direction: PacketDirection,
    format: OutputFormat,
) -> Result<(), String> {
    let bytes = input.read()?;
    let summary = summarize_packet(0, direction, &bytes, PacketChange::Unchanged, None);
    let routes = explain_routes(&summary);
    match format {
        OutputFormat::Text => {
            println!("{}", format_summary(&summary));
            if routes.is_empty() {
                println!("  explain: no known handler route");
            } else {
                println!("  handler routes:");
                for route in routes {
                    println!("    - {route}");
                }
            }
            println!("  note: offline explain does not simulate runtime state");
            Ok(())
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "summary": summary_json_value(&summary),
                    "routes": routes,
                    "runtime_state": "not-simulated",
                })
            );
            Ok(())
        }
    }
}

fn explain_routes(summary: &PacketSummary) -> Vec<&'static str> {
    match (summary.direction, summary.packet_type) {
        (PacketDirection::Send, PacketType::ManifestCode) => {
            vec!["send: manifest request-code intercept/drop depends on config"]
        }
        (PacketDirection::Send, PacketType::Stats) => {
            vec!["send: achievement stats offline response decision depends on config"]
        }
        (PacketDirection::Send, PacketType::GamesPlayed) => {
            vec!["send: games-played avatar rewrite and delegate-window reset"]
        }
        (PacketDirection::Send, PacketType::RichPresence) => {
            vec!["send: rich-presence KV capture"]
        }
        (PacketDirection::Send, PacketType::Pics) => {
            vec!["send: PICS access-token injection depends on script state"]
        }
        (PacketDirection::Recv, PacketType::Stats) => {
            vec!["recv: achievement stats response patch depends on pending offline state"]
        }
        (PacketDirection::Recv, PacketType::EncryptedTicket) => {
            vec!["recv: encrypted ticket cache/injection depends on ticket cache and script state"]
        }
        (PacketDirection::Recv, PacketType::Persona) => {
            vec!["recv: PersonaState cache/patch depends on rich-presence tracking state"]
        }
        _ => Vec::new(),
    }
}

#[derive(Clone, Debug)]
struct SimulationResult {
    decision: SimDecision,
    handler: &'static str,
    reason: String,
    final_len: Option<usize>,
    assumptions: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SimDecision {
    Pass,
    Drop,
    Rewrite,
    NeedsRuntimeState,
}

impl SimDecision {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Drop => "drop",
            Self::Rewrite => "rewrite",
            Self::NeedsRuntimeState => "needs-runtime-state",
        }
    }
}

fn simulate_offline(
    input: Input,
    direction: PacketDirection,
    config_path: Option<String>,
    format: OutputFormat,
) -> Result<(), String> {
    let bytes = input.read()?;
    let config = load_sim_config(config_path.as_deref())?;
    let summary = summarize_packet(0, direction, &bytes, PacketChange::Unchanged, None);
    let result = match direction {
        PacketDirection::Send => simulate_send(&bytes, &config),
        PacketDirection::Recv => simulate_recv(&summary),
    };

    match format {
        OutputFormat::Text => {
            println!("{}", format_summary(&summary));
            println!(
                "  simulate: decision={} handler={} final_len={}",
                result.decision.label(),
                result.handler,
                result
                    .final_len
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_owned())
            );
            println!("  reason: {}", result.reason);
            if !result.assumptions.is_empty() {
                println!("  assumptions:");
                for assumption in result.assumptions {
                    println!("    - {assumption}");
                }
            }
            Ok(())
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "summary": summary_json_value(&summary),
                    "simulation": simulation_json(&result),
                })
            );
            Ok(())
        }
    }
}

fn load_sim_config(path: Option<&str>) -> Result<RuntimeConfig, String> {
    match path {
        Some(path) => RuntimeConfig::load(std::path::Path::new(path))
            .map_err(|error| format!("load config {path:?} failed: {error}")),
        None => Ok(RuntimeConfig::default()),
    }
}

fn simulate_send(data: &[u8], config: &RuntimeConfig) -> SimulationResult {
    let Some((emsg_raw, header_bytes, body_bytes)) = vapor_forge_abi::unpack_raw(data) else {
        return sim_result(
            SimDecision::Pass,
            "decode",
            "invalid Steam packet framing; send hook passes the frame through",
            None,
        );
    };
    let emsg = emsg_raw & !K_MSG_HDR_PROTO_FLAG;
    let is_proto = emsg_raw & K_MSG_HDR_PROTO_FLAG != 0;
    if !is_proto {
        return sim_result(
            SimDecision::Pass,
            "non-proto",
            "non-protobuf packet; send hook does not mutate it",
            None,
        );
    }

    if emsg == EMSG_SERVICE_METHOD_CALL_FROM_CLIENT {
        return simulate_send_service_method(emsg_raw, header_bytes, body_bytes, config);
    }
    if emsg == EMSG_REQUEST_USERSTATS {
        return simulate_legacy_stats(emsg_raw, header_bytes, body_bytes, config);
    }
    if emsg == EMSG_GAMESPLAYED || emsg == EMSG_GAMESPLAYED_WITH_DATABLOB {
        return simulate_games_played(emsg_raw, header_bytes, body_bytes, config);
    }
    if emsg == EMSG_CLIENT_RICH_PRESENCE_UPLOAD {
        return sim_result(
            SimDecision::Pass,
            "rich-presence-capture",
            "rich presence upload only updates runtime tracking state",
            None,
        );
    }
    if emsg == EMSG_PICS_PRODUCT_INFO_REQUEST {
        return sim_result(
            SimDecision::NeedsRuntimeState,
            "pics-access-token",
            "PICS access-token injection depends on Lua/script runtime state",
            None,
        );
    }

    sim_result(
        SimDecision::Pass,
        "unknown",
        "no send-side handler matched",
        None,
    )
}

fn simulate_send_service_method(
    emsg_raw: u32,
    header_bytes: &[u8],
    body_bytes: &[u8],
    config: &RuntimeConfig,
) -> SimulationResult {
    let Ok(header) = CMsgProtoBufHeader::decode(header_bytes) else {
        return sim_result(
            SimDecision::Pass,
            "service-method",
            "protobuf header failed to decode; send hook passes the frame through",
            None,
        );
    };
    let Some(method) = header.target_job_name.as_deref() else {
        return sim_result(
            SimDecision::Pass,
            "service-method",
            "missing target_job_name; send hook passes the frame through",
            None,
        );
    };

    if method == vapor_forge_packet_inspect::MANIFEST_REQUEST_CODE_JOB_NAME {
        return simulate_manifest_request(&header, body_bytes, config);
    }
    if method == vapor_forge_packet_inspect::STATS_JOB_NAME {
        return simulate_service_stats(emsg_raw, header_bytes, body_bytes, config);
    }

    sim_result(
        SimDecision::Pass,
        "service-method",
        format!("unhandled service method {method:?}"),
        None,
    )
}

fn simulate_manifest_request(
    header: &CMsgProtoBufHeader,
    body_bytes: &[u8],
    config: &RuntimeConfig,
) -> SimulationResult {
    let Ok(req) = GetManifestRequestCodeRequest::decode(body_bytes) else {
        return sim_result(
            SimDecision::Pass,
            "manifest-request-code",
            "manifest request body failed to decode; send hook passes the frame through",
            None,
        );
    };
    let Some(job_id) = header.jobid_source else {
        return sim_result(
            SimDecision::Pass,
            "manifest-request-code",
            "missing jobid_source; send hook cannot queue a response",
            None,
        );
    };
    if job_id == 0 {
        return sim_result(
            SimDecision::Pass,
            "manifest-request-code",
            "zero jobid_source; send hook cannot queue a response",
            None,
        );
    }
    let app_id = AppId(req.app_id.unwrap_or(0));
    if config.is_controlled_app(app_id) {
        return sim_result(
            SimDecision::Drop,
            "manifest-request-code",
            format!(
                "controlled app {} will be fetched through manifest providers",
                app_id.0
            ),
            Some(0),
        );
    }
    sim_result(
        SimDecision::Pass,
        "manifest-request-code",
        format!("app {} is not controlled by config", app_id.0),
        None,
    )
}

fn simulate_service_stats(
    emsg_raw: u32,
    header_bytes: &[u8],
    body_bytes: &[u8],
    config: &RuntimeConfig,
) -> SimulationResult {
    let Ok(header) = CMsgProtoBufHeader::decode(header_bytes) else {
        return sim_result(
            SimDecision::Pass,
            "achievement-service-stats",
            "protobuf header failed to decode; send hook passes the frame through",
            None,
        );
    };
    let Ok(mut req) = PlayerGetUserStatsRequest::decode(body_bytes) else {
        return sim_result(
            SimDecision::Pass,
            "achievement-service-stats",
            "stats request body failed to decode; send hook passes the frame through",
            None,
        );
    };
    let Some(app_id) = req.appid.map(AppId) else {
        return sim_result(
            SimDecision::Pass,
            "achievement-service-stats",
            "stats request has no appid",
            None,
        );
    };
    if !config.is_controlled_app(app_id) {
        return sim_result(
            SimDecision::Pass,
            "achievement-service-stats",
            format!("app {} is not controlled by config", app_id.0),
            None,
        );
    }
    if header.jobid_source.is_none() {
        return sim_result(
            SimDecision::Pass,
            "achievement-service-stats",
            "missing jobid_source; achievement redirect cannot track the response",
            None,
        );
    }
    if config.achievements.offline_schema {
        return sim_result_with_assumptions(
            SimDecision::Drop,
            "achievement-service-stats",
            format!(
                "offline_schema is enabled; controlled app {} gets an offline response",
                app_id.0
            ),
            Some(0),
            vec!["controlled apps are treated as unowned in offline simulation"],
        );
    }

    req.sha_schema = None;
    req.steamid = Some(default_ref_steamid());
    let new_body = req.encode_to_vec();
    let final_len = vapor_forge_abi::assemble_raw(emsg_raw, header_bytes, &new_body).len();
    sim_result_with_assumptions(
        SimDecision::Rewrite,
        "achievement-service-stats",
        format!(
            "controlled app {} stats request would be redirected to a reference SteamID",
            app_id.0
        ),
        Some(final_len),
        vec!["controlled apps are treated as unowned in offline simulation"],
    )
}

fn simulate_legacy_stats(
    emsg_raw: u32,
    header_bytes: &[u8],
    body_bytes: &[u8],
    config: &RuntimeConfig,
) -> SimulationResult {
    let Ok(mut req) = ClientGetUserStatsRequest::decode(body_bytes) else {
        return sim_result(
            SimDecision::Pass,
            "achievement-legacy-stats",
            "legacy stats request body failed to decode; send hook passes the frame through",
            None,
        );
    };
    let Some(game_id) = req.game_id else {
        return sim_result(
            SimDecision::Pass,
            "achievement-legacy-stats",
            "legacy stats request has no game_id",
            None,
        );
    };
    let app_id = AppId(game_id as u32);
    if req.schema_local_version != Some(-1) {
        return sim_result(
            SimDecision::Pass,
            "achievement-legacy-stats",
            "schema_local_version is not -1",
            None,
        );
    }
    if !config.is_controlled_app(app_id) {
        return sim_result(
            SimDecision::Pass,
            "achievement-legacy-stats",
            format!("app {} is not controlled by config", app_id.0),
            None,
        );
    }
    if config.achievements.offline_schema {
        return sim_result_with_assumptions(
            SimDecision::Drop,
            "achievement-legacy-stats",
            format!(
                "offline_schema is enabled; controlled app {} gets an offline response",
                app_id.0
            ),
            Some(0),
            vec!["controlled apps are treated as unowned in offline simulation"],
        );
    }

    req.steam_id_for_user = Some(default_ref_steamid());
    let new_body = req.encode_to_vec();
    let final_len = vapor_forge_abi::assemble_raw(emsg_raw, header_bytes, &new_body).len();
    sim_result_with_assumptions(
        SimDecision::Rewrite,
        "achievement-legacy-stats",
        format!(
            "controlled app {} legacy stats request would be redirected to a reference SteamID",
            app_id.0
        ),
        Some(final_len),
        vec!["controlled apps are treated as unowned in offline simulation"],
    )
}

fn simulate_games_played(
    emsg_raw: u32,
    header_bytes: &[u8],
    body_bytes: &[u8],
    config: &RuntimeConfig,
) -> SimulationResult {
    let Ok(mut msg) = CMsgClientGamesPlayed::decode(body_bytes) else {
        return sim_result(
            SimDecision::Pass,
            "games-played-avatar",
            "games-played body failed to decode; send hook passes the frame through",
            None,
        );
    };

    let mut rewrites = Vec::new();
    for game in &mut msg.games_played {
        let Some(game_id) = game.game_id else {
            continue;
        };
        let app_id = AppId(game_id as u32);
        let Some(avatar) = avatar_from_static_config(app_id, config) else {
            continue;
        };
        game.game_id = Some(avatar.0 as u64);
        rewrites.push((app_id, avatar));
    }

    if rewrites.is_empty() {
        return sim_result_with_assumptions(
            SimDecision::Pass,
            "games-played-avatar",
            "no static app_avatar mapping matched",
            None,
            vec!["runtime launch-flag avatar rules are not simulated"],
        );
    }

    let new_body = msg.encode_to_vec();
    let final_len = vapor_forge_abi::assemble_raw(emsg_raw, header_bytes, &new_body).len();
    let pairs = rewrites
        .iter()
        .map(|(app, avatar)| format!("{}->{}", app.0, avatar.0))
        .collect::<Vec<_>>()
        .join(", ");
    sim_result_with_assumptions(
        SimDecision::Rewrite,
        "games-played-avatar",
        format!("static app_avatar mapping rewrites {pairs}"),
        Some(final_len),
        vec!["runtime launch-flag avatar rules are not simulated"],
    )
}

fn simulate_recv(summary: &PacketSummary) -> SimulationResult {
    match summary.packet_type {
        PacketType::Stats => sim_result(
            SimDecision::NeedsRuntimeState,
            "achievement-stats-response",
            "recv stats rewriting depends on pending request state",
            None,
        ),
        PacketType::EncryptedTicket => sim_result(
            SimDecision::NeedsRuntimeState,
            "encrypted-ticket",
            "encrypted ticket rewriting depends on cache and Lua/script state",
            None,
        ),
        PacketType::Persona => sim_result(
            SimDecision::NeedsRuntimeState,
            "persona-rich-presence",
            "PersonaState patching depends on cached self persona and tracked rich presence",
            None,
        ),
        _ => sim_result(
            SimDecision::Pass,
            "unknown",
            "no recv-side handler can be verified offline for this packet",
            None,
        ),
    }
}

fn simulation_json(result: &SimulationResult) -> serde_json::Value {
    serde_json::json!({
        "decision": result.decision.label(),
        "handler": result.handler,
        "reason": result.reason,
        "final_len": result.final_len,
        "assumptions": result.assumptions,
    })
}

fn sim_result(
    decision: SimDecision,
    handler: &'static str,
    reason: impl Into<String>,
    final_len: Option<usize>,
) -> SimulationResult {
    sim_result_with_assumptions(decision, handler, reason, final_len, Vec::new())
}

fn sim_result_with_assumptions(
    decision: SimDecision,
    handler: &'static str,
    reason: impl Into<String>,
    final_len: Option<usize>,
    assumptions: Vec<&'static str>,
) -> SimulationResult {
    SimulationResult {
        decision,
        handler,
        reason: reason.into(),
        final_len,
        assumptions,
    }
}

fn avatar_from_static_config(app_id: AppId, config: &RuntimeConfig) -> Option<AppId> {
    config
        .app_avatar
        .static_map
        .get(&app_id)
        .copied()
        .or_else(|| config.app_avatar.static_map.get(&AppId(0)).copied())
}

fn default_ref_steamid() -> u64 {
    76561198028121353
}

fn format_summary(summary: &PacketSummary) -> String {
    let emsg = summary
        .emsg
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let apps = if summary.app_ids.is_empty() {
        "-".to_owned()
    } else {
        format!("{:?}", summary.app_ids)
    };
    format!(
        "{} emsg={} type={} app={} change={} len={}",
        summary.direction.label(),
        emsg,
        summary.packet_type.label(),
        apps,
        summary.change.label(),
        summary.original_len
    )
}

fn summary_json(summary: &PacketSummary) -> String {
    summary_json_value(summary).to_string()
}

fn summary_json_value(summary: &PacketSummary) -> serde_json::Value {
    serde_json::json!({
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

fn send_debug_command(socket: &str, command: &str) -> Result<String, String> {
    #[cfg(not(target_family = "unix"))]
    {
        let _ = (socket, command);
        return Err("debug API socket client is only available on Unix targets".to_owned());
    }

    #[cfg(target_family = "unix")]
    {
        let mut stream = UnixStream::connect(socket)
            .map_err(|error| format!("connect {socket} failed: {error}"))?;
        stream
            .write_all(command.as_bytes())
            .and_then(|_| stream.write_all(b"\n"))
            .map_err(|error| format!("write command failed: {error}"))?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| format!("shutdown write failed: {error}"))?;

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|error| format!("read response failed: {error}"))?;
        Ok(response.trim_end().to_owned())
    }
}

impl Input {
    fn read(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::File(path) => {
                std::fs::read(path).map_err(|error| format!("read {path} failed: {error}"))
            }
            Self::Hex(hex) => parse_hex_dump(hex),
            Self::StdinHex => {
                let mut input = String::new();
                std::io::stdin()
                    .read_to_string(&mut input)
                    .map_err(|error| format!("read stdin failed: {error}"))?;
                parse_hex_dump(&input)
            }
        }
    }
}

fn parse_direction(value: &str) -> Result<PacketDirection, String> {
    match value {
        "send" => Ok(PacketDirection::Send),
        "recv" => Ok(PacketDirection::Recv),
        other => Err(format!("invalid direction {other:?}")),
    }
}

fn parse_hex_dump(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();

    for line in input.lines() {
        let line = strip_offset(line.trim());
        for raw in line.split_whitespace() {
            let token = raw
                .trim_matches(|c: char| matches!(c, ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')'));
            if token.is_empty() || token.ends_with(':') {
                continue;
            }
            let token = token
                .rsplit_once('=')
                .map(|(_, value)| value)
                .unwrap_or(token);
            let token = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
                .unwrap_or(token);
            if token.len() == 2 && token.as_bytes().iter().all(u8::is_ascii_hexdigit) {
                out.push(byte_from_hex(token)?);
            } else if token.len() > 2
                && token.len() % 2 == 0
                && token.as_bytes().iter().all(u8::is_ascii_hexdigit)
            {
                for index in (0..token.len()).step_by(2) {
                    out.push(byte_from_hex(&token[index..index + 2])?);
                }
            }
        }
    }

    if out.is_empty() {
        Err("hex input did not contain any bytes".to_owned())
    } else {
        Ok(out)
    }
}

fn strip_offset(line: &str) -> &str {
    let Some((prefix, rest)) = line.split_once(':') else {
        return line;
    };
    if !prefix.is_empty() && prefix.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        rest
    } else {
        line
    }
}

fn byte_from_hex(hex: &str) -> Result<u8, String> {
    u8::from_str_radix(hex, 16).map_err(|error| format!("invalid hex byte {hex:?}: {error}"))
}

fn print_response(response: &str, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            println!("{response}");
            Ok(())
        }
        OutputFormat::Json => {
            println!("{}", ok_payload(response)?);
            Ok(())
        }
    }
}

fn ok_payload(response: &str) -> Result<&str, String> {
    response
        .strip_prefix("ok ")
        .ok_or_else(|| response.to_owned())
}

fn json_suffix(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Text => "",
        OutputFormat::Json => " --json",
    }
}

fn default_socket_path() -> Result<String, String> {
    if let Ok(path) = std::env::var("VAPOR_FORGE_DEBUG_SOCKET") {
        if !path.is_empty() {
            return Ok(path);
        }
    }

    let runtime_dir =
        std::env::var("XDG_RUNTIME_DIR").map_err(|_| "XDG_RUNTIME_DIR is not set".to_owned())?;
    let uid = runtime_dir
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty() && part.as_bytes().iter().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| "could not derive uid from XDG_RUNTIME_DIR".to_owned())?;
    Ok(format!("/tmp/vapor-forge-{uid}/debug.sock"))
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value\n{}", usage()))
}

fn required<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn usage() -> String {
    concat!(
        "usage: vapor-forge-packet-tool [--socket PATH] [--format text|json] <command>\n",
        "\n",
        "commands:\n",
        "  capture status\n",
        "  capture on [--raw] [--direction send|recv] [--type TYPE] [--emsg EMSG] [--app-id APPID] [--changed CHANGE]\n",
        "  capture off\n",
        "  capture clear\n",
        "  capture limit N\n",
        "  capture filter-clear\n",
        "  list [filters]\n",
        "  show ID\n",
        "  save ID PATH\n",
        "  watch [filters] [--interval-ms N]\n",
        "  decode [--direction send|recv] [--file PATH | --hex HEX]\n",
        "  explain [send|recv] [--file PATH | --hex HEX]\n",
        "  simulate [send|recv] [--config PATH] [--file PATH | --hex HEX]"
    )
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_dump_with_offsets_and_punctuation() {
        assert_eq!(
            parse_hex_dump("0000: 01 02 0x03, bytes=04\n0004: 0506").unwrap(),
            vec![1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn capture_commands_honor_output_format() {
        assert_eq!(
            capture_command(CaptureCommand::Status, OutputFormat::Text),
            "packet capture status"
        );
        assert_eq!(
            capture_command(CaptureCommand::Status, OutputFormat::Json),
            "packet capture status --json"
        );
        assert_eq!(
            capture_command(CaptureCommand::Off, OutputFormat::Json),
            "packet capture off --json"
        );
    }

    #[test]
    fn explain_command_defaults_to_recv() {
        let args =
            Args::parse(["--format", "json", "explain", "--hex", "010203"].map(str::to_owned))
                .unwrap();
        assert_eq!(args.format, OutputFormat::Json);
        match args.command {
            Command::Explain { direction, .. } => assert_eq!(direction, PacketDirection::Recv),
            _ => panic!("expected explain command"),
        }
    }

    #[test]
    fn explain_command_accepts_send_direction_prefix() {
        let args = Args::parse(["explain", "send", "--hex", "010203"].map(str::to_owned)).unwrap();
        match args.command {
            Command::Explain { direction, .. } => assert_eq!(direction, PacketDirection::Send),
            _ => panic!("expected explain command"),
        }
    }

    #[test]
    fn simulate_command_defaults_to_send_and_accepts_config() {
        let args = Args::parse(
            ["simulate", "--config", "config.toml", "--hex", "010203"].map(str::to_owned),
        )
        .unwrap();
        match args.command {
            Command::Simulate {
                direction, config, ..
            } => {
                assert_eq!(direction, PacketDirection::Send);
                assert_eq!(config.as_deref(), Some("config.toml"));
            }
            _ => panic!("expected simulate command"),
        }
    }

    #[test]
    fn simulate_manifest_request_for_controlled_app_drops() {
        let header = CMsgProtoBufHeader {
            steamid: None,
            jobid_source: Some(42),
            jobid_target: None,
            target_job_name: Some(
                vapor_forge_packet_inspect::MANIFEST_REQUEST_CODE_JOB_NAME.to_owned(),
            ),
            eresult: None,
            transport_error: None,
            seq_num: None,
        };
        let body = GetManifestRequestCodeRequest {
            app_id: Some(480),
            depot_id: Some(481),
            manifest_id: Some(123),
        };
        let packet = vapor_forge_abi::assemble_raw(
            EMSG_SERVICE_METHOD_CALL_FROM_CLIENT | K_MSG_HDR_PROTO_FLAG,
            &header.encode_to_vec(),
            &body.encode_to_vec(),
        );
        let mut config = RuntimeConfig::default();
        config.apps.inject.push(vapor_forge_config::InjectApp {
            id: AppId(480),
            dlc: Vec::new(),
            ticket: vapor_forge_config::TicketMode::Forge,
            purchase_time: 0,
        });

        let result = simulate_send(&packet, &config);
        assert_eq!(result.decision, SimDecision::Drop);
        assert_eq!(result.handler, "manifest-request-code");
        assert_eq!(result.final_len, Some(0));
    }
}
