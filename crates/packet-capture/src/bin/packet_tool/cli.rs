use std::time::Duration;

use vapor_forge_packet_capture::PacketDirection;

use super::capture::{default_socket_path, json_suffix};
use super::input::{parse_direction, Input};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OutputFormat {
    Text,
    Json,
}

pub(super) struct Args {
    pub(super) socket: Option<String>,
    pub(super) format: OutputFormat,
    pub(super) command: Command,
}

pub(super) enum Command {
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

pub(super) enum CaptureCommand {
    Status,
    On { raw: bool, filters: Filters },
    Off,
    Clear,
    Limit(usize),
    FilterClear,
}

#[derive(Default)]
pub(super) struct Filters {
    pub(super) direction: Option<String>,
    pub(super) packet_type: Option<String>,
    pub(super) emsg: Option<String>,
    pub(super) app_id: Option<String>,
    pub(super) changed: Option<String>,
}

impl Args {
    pub(super) fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
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

pub(super) fn resolve_socket(socket: Option<&str>) -> Result<String, String> {
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

pub(super) fn capture_command(command: CaptureCommand, format: OutputFormat) -> String {
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

pub(super) fn filter_suffix(filters: &Filters) -> String {
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
