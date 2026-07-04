use std::path::PathBuf;

use prost::Message;
use serde::Serialize;
use vapor_forge_abi::{
    CMsgProtoBufHeader, EncryptedAppTicketResponse, EMSG_ENCRYPTED_APPTICKET_RESPONSE,
    K_MSG_HDR_PROTO_FLAG,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-ticket-tool: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return Err(usage());
    }

    let command = args.remove(0);
    match command.as_str() {
        "app-ticket" => app_ticket_command(&args),
        "encrypted-ticket-response" => encrypted_ticket_response_command(&args),
        "packet" => packet_command(&args),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n{}", usage())),
    }
}

fn app_ticket_command(args: &[String]) -> Result<(), String> {
    let args = TicketArgs::parse(args)?;
    let bytes = args.input.read()?;
    let report = inspect_app_ticket(&bytes, &args);
    emit(&report, args.format)
}

fn encrypted_ticket_response_command(args: &[String]) -> Result<(), String> {
    let args = CommonArgs::parse(args)?;
    let bytes = args.input.read()?;
    let report = inspect_encrypted_ticket_response(&bytes)?;
    emit(&report, args.format)
}

fn packet_command(args: &[String]) -> Result<(), String> {
    let args = CommonArgs::parse(args)?;
    let bytes = args.input.read()?;
    let report = inspect_packet(&bytes)?;
    emit(&report, args.format)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Text,
    Json,
}

trait TextReport {
    fn print_text(&self);
}

fn emit<T>(report: &T, format: OutputFormat) -> Result<(), String>
where
    T: Serialize + TextReport,
{
    match format {
        OutputFormat::Text => report.print_text(),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(report)
                .map_err(|error| format!("serialize JSON failed: {error}"))?;
            println!("{json}");
        }
    }
    Ok(())
}

struct CommonArgs {
    input: Input,
    format: OutputFormat,
}

impl CommonArgs {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut input = Input::StdinHex;
        let mut format = OutputFormat::Text;
        let mut index = 0usize;

        while index < args.len() {
            match args[index].as_str() {
                "--file" => {
                    index += 1;
                    input = Input::File(PathBuf::from(required_value(args, index, "--file")?));
                }
                "--hex" => {
                    index += 1;
                    input = Input::Hex(required_value(args, index, "--hex")?.to_owned());
                }
                "--format" => {
                    index += 1;
                    format = parse_format(required_value(args, index, "--format")?)?;
                }
                "-h" | "--help" => return Err(usage()),
                other => return Err(format!("unknown argument {other:?}\n{}", usage())),
            }
            index += 1;
        }

        Ok(Self { input, format })
    }
}

struct TicketArgs {
    input: Input,
    format: OutputFormat,
    app_id_offset: Option<usize>,
    steamid_offset: usize,
    signature_offset: Option<usize>,
    signature_size: usize,
    forge_target_app_id: Option<u32>,
}

impl TicketArgs {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut common_args = Vec::new();
        let mut app_id_offset = None;
        let mut steamid_offset = 8usize;
        let mut signature_offset = None;
        let mut signature_size = 128usize;
        let mut forge_target_app_id = None;
        let mut index = 0usize;

        while index < args.len() {
            match args[index].as_str() {
                "--app-id-offset" => {
                    index += 1;
                    app_id_offset = Some(parse_usize(required_value(
                        args,
                        index,
                        "--app-id-offset",
                    )?)?);
                }
                "--steamid-offset" => {
                    index += 1;
                    steamid_offset = parse_usize(required_value(args, index, "--steamid-offset")?)?;
                }
                "--signature-offset" => {
                    index += 1;
                    signature_offset = Some(parse_usize(required_value(
                        args,
                        index,
                        "--signature-offset",
                    )?)?);
                }
                "--signature-size" => {
                    index += 1;
                    signature_size = parse_usize(required_value(args, index, "--signature-size")?)?;
                }
                "--forge-target" | "--target-app-id" => {
                    index += 1;
                    forge_target_app_id =
                        Some(parse_u32(required_value(args, index, "--forge-target")?)?);
                }
                other => common_args.push(other.to_owned()),
            }
            index += 1;
        }

        let common = CommonArgs::parse(&common_args)?;
        Ok(Self {
            input: common.input,
            format: common.format,
            app_id_offset,
            steamid_offset,
            signature_offset,
            signature_size,
            forge_target_app_id,
        })
    }
}

enum Input {
    File(PathBuf),
    Hex(String),
    StdinHex,
}

impl Input {
    fn read(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::File(path) => std::fs::read(path)
                .map_err(|error| format!("read {} failed: {error}", path.display())),
            Self::Hex(hex) => parse_hex_dump(hex),
            Self::StdinHex => {
                let mut input = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)
                    .map_err(|error| format!("read stdin failed: {error}"))?;
                parse_hex_dump(&input)
            }
        }
    }
}

#[derive(Serialize)]
struct AppTicketReport {
    size: usize,
    steamid_offset: usize,
    steamid: Option<u64>,
    app_id_offset: Option<usize>,
    app_id: Option<u32>,
    signature_offset: Option<usize>,
    signature_size: usize,
    signature_present: bool,
    forgeable_with_current_rules: bool,
    forge_preview: Option<ForgePreview>,
}

#[derive(Serialize)]
struct ForgePreview {
    target_app_id: u32,
    total_size: u32,
    app_id_offset: u32,
    steam_id_offset: u32,
    signature_offset: u32,
    signature_size: u32,
    steamid: Option<u64>,
    inserted_app_id: Option<u32>,
}

fn inspect_app_ticket(bytes: &[u8], args: &TicketArgs) -> AppTicketReport {
    let signature_offset = args
        .signature_offset
        .or_else(|| bytes.len().checked_sub(args.signature_size));
    let app_id_offset = args
        .app_id_offset
        .or_else(|| signature_offset.and_then(|offset| offset.checked_sub(4)));
    let steamid = read_u64_le(bytes, args.steamid_offset);
    let app_id = app_id_offset.and_then(|offset| read_u32_le(bytes, offset));
    let signature_present = signature_offset.is_some_and(|offset| {
        offset
            .checked_add(args.signature_size)
            .and_then(|end| bytes.get(offset..end))
            .is_some()
    });
    let forge_preview = args.forge_target_app_id.and_then(|target_app_id| {
        vapor_forge_features::ticket::forge::forge_from_source(bytes, target_app_id).map(|forged| {
            ForgePreview {
                target_app_id,
                total_size: forged.total_size,
                app_id_offset: forged.app_id_offset,
                steam_id_offset: forged.steam_id_offset,
                signature_offset: forged.signature_offset,
                signature_size: forged.signature_size,
                steamid: read_u64_le(&forged.data, forged.steam_id_offset as usize),
                inserted_app_id: read_u32_le(&forged.data, forged.app_id_offset as usize),
            }
        })
    });

    AppTicketReport {
        size: bytes.len(),
        steamid_offset: args.steamid_offset,
        steamid,
        app_id_offset,
        app_id,
        signature_offset,
        signature_size: args.signature_size,
        signature_present,
        forgeable_with_current_rules: bytes.len() > args.signature_size,
        forge_preview,
    }
}

impl TextReport for AppTicketReport {
    fn print_text(&self) {
        println!("app-ticket: size={}", self.size);
        println!(
            "  steamid: {} at offset 0x{:x}",
            fmt_opt_u64(self.steamid),
            self.steamid_offset
        );
        println!(
            "  app_id: {} at offset {}",
            fmt_opt_u32(self.app_id),
            fmt_opt_offset(self.app_id_offset)
        );
        println!(
            "  signature: offset={} size={} present={}",
            fmt_opt_offset(self.signature_offset),
            self.signature_size,
            self.signature_present
        );
        println!(
            "  forgeable_with_current_rules: {}",
            self.forgeable_with_current_rules
        );
        if let Some(preview) = &self.forge_preview {
            println!(
                "  forge_preview: target_app_id={} total_size={} app_id_offset=0x{:x} signature_offset=0x{:x}",
                preview.target_app_id,
                preview.total_size,
                preview.app_id_offset,
                preview.signature_offset
            );
        }
    }
}

#[derive(Serialize)]
struct EncryptedTicketResponseReport {
    app_id: Option<u32>,
    eresult: Option<i32>,
    ticket_version_no: Option<u32>,
    crc_encryptedticket: Option<u32>,
    cb_encrypteduserdata: Option<u32>,
    cb_encrypted_appownershipticket: Option<u32>,
    encrypted_ticket_size: Option<usize>,
    encrypted_ticket_prefix_hex: Option<String>,
}

fn inspect_encrypted_ticket_response(
    bytes: &[u8],
) -> Result<EncryptedTicketResponseReport, String> {
    let resp = EncryptedAppTicketResponse::decode(bytes)
        .map_err(|error| format!("decode EncryptedAppTicketResponse failed: {error}"))?;
    Ok(encrypted_response_report(resp))
}

fn encrypted_response_report(resp: EncryptedAppTicketResponse) -> EncryptedTicketResponseReport {
    let ticket = resp.encrypted_app_ticket;
    let encrypted_ticket = ticket
        .as_ref()
        .and_then(|ticket| ticket.encrypted_ticket.as_ref());
    EncryptedTicketResponseReport {
        app_id: resp.app_id,
        eresult: resp.eresult,
        ticket_version_no: ticket.as_ref().and_then(|ticket| ticket.ticket_version_no),
        crc_encryptedticket: ticket
            .as_ref()
            .and_then(|ticket| ticket.crc_encryptedticket),
        cb_encrypteduserdata: ticket
            .as_ref()
            .and_then(|ticket| ticket.cb_encrypteduserdata),
        cb_encrypted_appownershipticket: ticket
            .as_ref()
            .and_then(|ticket| ticket.cb_encrypted_appownershipticket),
        encrypted_ticket_size: encrypted_ticket.map(Vec::len),
        encrypted_ticket_prefix_hex: encrypted_ticket
            .map(|bytes| hex_compact(&bytes[..bytes.len().min(16)])),
    }
}

impl TextReport for EncryptedTicketResponseReport {
    fn print_text(&self) {
        println!("encrypted-ticket-response:");
        println!("  app_id: {}", fmt_opt_u32(self.app_id));
        println!("  eresult: {}", fmt_opt_i32(self.eresult));
        println!(
            "  ticket_version_no: {}",
            fmt_opt_u32(self.ticket_version_no)
        );
        println!(
            "  crc_encryptedticket: {}",
            fmt_opt_u32_hex(self.crc_encryptedticket)
        );
        println!(
            "  cb_encrypteduserdata: {}",
            fmt_opt_u32(self.cb_encrypteduserdata)
        );
        println!(
            "  cb_encrypted_appownershipticket: {}",
            fmt_opt_u32(self.cb_encrypted_appownershipticket)
        );
        println!(
            "  encrypted_ticket_size: {}",
            self.encrypted_ticket_size
                .map(|size| size.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        println!(
            "  encrypted_ticket_prefix_hex: {}",
            self.encrypted_ticket_prefix_hex.as_deref().unwrap_or("-")
        );
    }
}

#[derive(Serialize)]
struct PacketReport {
    size: usize,
    emsg_raw: u32,
    emsg: u32,
    proto: bool,
    header_length: usize,
    body_length: usize,
    header: ProtoHeaderReport,
    body_type: Option<&'static str>,
    encrypted_ticket_response: Option<EncryptedTicketResponseReport>,
}

#[derive(Serialize)]
struct ProtoHeaderReport {
    steamid: Option<u64>,
    jobid_source: Option<u64>,
    jobid_target: Option<u64>,
    target_job_name: Option<String>,
    eresult: Option<i32>,
    transport_error: Option<i32>,
    seq_num: Option<i32>,
}

fn inspect_packet(bytes: &[u8]) -> Result<PacketReport, String> {
    let Some((emsg_raw, header_bytes, body_bytes)) = vapor_forge_abi::unpack_raw(bytes) else {
        return Err("packet is too short or has invalid header length".to_owned());
    };
    let emsg = emsg_raw & !K_MSG_HDR_PROTO_FLAG;
    let proto = emsg_raw & K_MSG_HDR_PROTO_FLAG != 0;
    let header = CMsgProtoBufHeader::decode(header_bytes)
        .map_err(|error| format!("decode CMsgProtoBufHeader failed: {error}"))?;
    let encrypted_ticket_response = if emsg == EMSG_ENCRYPTED_APPTICKET_RESPONSE {
        Some(inspect_encrypted_ticket_response(body_bytes)?)
    } else {
        None
    };
    let body_type = if encrypted_ticket_response.is_some() {
        Some("EncryptedAppTicketResponse")
    } else {
        None
    };

    Ok(PacketReport {
        size: bytes.len(),
        emsg_raw,
        emsg,
        proto,
        header_length: header_bytes.len(),
        body_length: body_bytes.len(),
        header: ProtoHeaderReport {
            steamid: header.steamid,
            jobid_source: header.jobid_source,
            jobid_target: header.jobid_target,
            target_job_name: header.target_job_name,
            eresult: header.eresult,
            transport_error: header.transport_error,
            seq_num: header.seq_num,
        },
        body_type,
        encrypted_ticket_response,
    })
}

impl TextReport for PacketReport {
    fn print_text(&self) {
        println!(
            "packet: size={} emsg={} emsg_raw=0x{:x} proto={} header_len={} body_len={}",
            self.size, self.emsg, self.emsg_raw, self.proto, self.header_length, self.body_length
        );
        println!("  header.steamid: {}", fmt_opt_u64(self.header.steamid));
        println!(
            "  header.jobid_source: {}",
            fmt_opt_u64(self.header.jobid_source)
        );
        println!(
            "  header.jobid_target: {}",
            fmt_opt_u64(self.header.jobid_target)
        );
        println!(
            "  header.target_job_name: {}",
            self.header.target_job_name.as_deref().unwrap_or("-")
        );
        println!("  body_type: {}", self.body_type.unwrap_or("-"));
        if let Some(resp) = &self.encrypted_ticket_response {
            resp.print_text();
        }
    }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn parse_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        other => Err(format!("unsupported format {other:?}")),
    }
}

fn parse_u32(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|error| format!("invalid u32 {value:?}: {error}"))
    } else {
        value
            .parse::<u32>()
            .map_err(|error| format!("invalid u32 {value:?}: {error}"))
    }
}

fn parse_usize(value: &str) -> Result<usize, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        usize::from_str_radix(hex, 16).map_err(|error| format!("invalid usize {value:?}: {error}"))
    } else {
        value
            .parse::<usize>()
            .map_err(|error| format!("invalid usize {value:?}: {error}"))
    }
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
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

fn hex_compact(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn fmt_opt_offset(value: Option<usize>) -> String {
    value
        .map(|value| format!("0x{value:x}"))
        .unwrap_or_else(|| "-".to_owned())
}

fn fmt_opt_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn fmt_opt_u32_hex(value: Option<u32>) -> String {
    value
        .map(|value| format!("0x{value:x}"))
        .unwrap_or_else(|| "-".to_owned())
}

fn fmt_opt_i32(value: Option<i32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn fmt_opt_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn usage() -> String {
    concat!(
        "usage: vapor-forge-ticket-tool <app-ticket|encrypted-ticket-response|packet> [options]\n",
        "\n",
        "common options: [--file PATH | --hex HEX] [--format text|json]\n",
        "app-ticket options: [--steamid-offset N] [--app-id-offset N] ",
        "[--signature-offset N] [--signature-size N] [--forge-target APPID]\n"
    )
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ticket_extracts_default_fields() {
        let mut ticket = vec![0u8; 132];
        ticket[8..16].copy_from_slice(&76561198000000001u64.to_le_bytes());
        ticket[0..4].copy_from_slice(&480u32.to_le_bytes());
        let args = TicketArgs {
            input: Input::Hex(String::new()),
            format: OutputFormat::Text,
            app_id_offset: Some(0),
            steamid_offset: 8,
            signature_offset: None,
            signature_size: 128,
            forge_target_app_id: None,
        };

        let report = inspect_app_ticket(&ticket, &args);
        assert_eq!(report.steamid, Some(76561198000000001));
        assert_eq!(report.app_id, Some(480));
        assert_eq!(report.signature_offset, Some(4));
        assert!(report.signature_present);
    }

    #[test]
    fn app_ticket_forge_preview_uses_runtime_logic() {
        let mut ticket = vec![0u8; 328];
        ticket[8..16].copy_from_slice(&76561198000000001u64.to_le_bytes());
        let args = TicketArgs {
            input: Input::Hex(String::new()),
            format: OutputFormat::Text,
            app_id_offset: None,
            steamid_offset: 8,
            signature_offset: None,
            signature_size: 128,
            forge_target_app_id: Some(480),
        };

        let report = inspect_app_ticket(&ticket, &args);
        let preview = report.forge_preview.unwrap();
        assert_eq!(preview.total_size, 332);
        assert_eq!(preview.app_id_offset, 200);
        assert_eq!(preview.inserted_app_id, Some(480));
    }

    #[test]
    fn parses_hex_key_value_output() {
        let bytes = parse_hex_dump("hex=01020304").unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }
}
