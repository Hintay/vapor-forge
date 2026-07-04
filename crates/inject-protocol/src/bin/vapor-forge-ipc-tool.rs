use std::io::{self, Cursor, Read};
use std::path::PathBuf;

use vapor_forge_inject_protocol as proto;
use vapor_forge_inject_protocol::{Message, TOKEN_LEN};

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-ipc-tool: {error}");
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
        "encode" => encode_command(&args),
        "decode" => decode_command(&args),
        "send" => send_command(&args),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n{}", usage())),
    }
}

fn encode_command(args: &[String]) -> Result<(), String> {
    let message = parse_message(args)?;
    println!("message={}", format_message(&message));
    println!("hex={}", hex_compact(&message.encode()));
    Ok(())
}

fn decode_command(args: &[String]) -> Result<(), String> {
    let mut payload_only = false;
    let mut chunks = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--payload" => payload_only = true,
            "-h" | "--help" => return Err(decode_usage()),
            other => chunks.push(other.to_owned()),
        }
    }

    let input = if chunks.is_empty() {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|error| format!("read stdin failed: {error}"))?;
        input
    } else {
        chunks.join(" ")
    };

    let bytes = parse_hex_dump(&input)?;
    let messages = if payload_only {
        vec![proto::decode_payload(&bytes).map_err(|error| format!("decode failed: {error}"))?]
    } else {
        decode_frames(&bytes)?
    };

    for (index, message) in messages.iter().enumerate() {
        if messages.len() == 1 {
            println!("message={}", format_message(message));
            println!("hex={}", hex_compact(&message.encode()));
        } else {
            println!("message[{index}]={}", format_message(message));
            println!("hex[{index}]={}", hex_compact(&message.encode()));
        }
    }
    Ok(())
}

fn send_command(args: &[String]) -> Result<(), String> {
    let mut socket = proto::default_socket_path().map(PathBuf::from);
    let mut token = None;
    let mut app_id = None;
    let mut pid = std::process::id();
    let mut raw = false;
    let mut read_response = false;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--socket" => {
                index += 1;
                socket = Some(PathBuf::from(required_value(args, index, "--socket")?));
            }
            "--token" => {
                index += 1;
                token = Some(parse_token(required_value(args, index, "--token")?)?);
            }
            "--app-id" => {
                index += 1;
                app_id = Some(parse_u32(required_value(args, index, "--app-id")?)?);
            }
            "--pid" => {
                index += 1;
                pid = parse_u32(required_value(args, index, "--pid")?)?;
            }
            "--raw" => raw = true,
            "--read-response" => read_response = true,
            "-h" | "--help" => return Err(send_usage()),
            _ => break,
        }
        index += 1;
    }

    let Some(socket) = socket else {
        return Err("no socket path; pass --socket or set XDG_RUNTIME_DIR".to_owned());
    };
    let message = parse_message(&args[index..])?;

    #[cfg(not(unix))]
    {
        let _ = (socket, token, app_id, pid, raw, read_response, message);
        Err("Unix sockets are not supported on this target".to_owned())
    }

    #[cfg(unix)]
    {
        send_unix(socket, token, app_id, pid, raw, read_response, message)
    }
}

#[cfg(unix)]
fn send_unix(
    socket: PathBuf,
    token: Option<[u8; TOKEN_LEN]>,
    app_id: Option<u32>,
    pid: u32,
    raw: bool,
    read_response: bool,
    message: Message,
) -> Result<(), String> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)
        .map_err(|error| format!("connect {} failed: {error}", socket.display()))?;

    if !raw {
        let token = token.ok_or_else(|| "send requires --token unless --raw is set".to_owned())?;
        let app_id = app_id
            .or_else(|| message_app_id(&message))
            .ok_or_else(|| "send requires --app-id for messages without app_id".to_owned())?;
        let hello = Message::Hello { token, app_id, pid };
        proto::write_message(&mut stream, &hello)
            .map_err(|error| format!("send hello failed: {error}"))?;
        match proto::read_message(&mut stream) {
            Ok(Message::Ack) => println!("response=Ack"),
            Ok(other) => return Err(format!("expected Ack, got {}", format_message(&other))),
            Err(error) => return Err(format!("read Ack failed: {error}")),
        }
    }

    proto::write_message(&mut stream, &message)
        .map_err(|error| format!("send message failed: {error}"))?;
    println!("sent={}", format_message(&message));

    if read_response {
        let response = proto::read_message(&mut stream)
            .map_err(|error| format!("read response failed: {error}"))?;
        println!("response={}", format_message(&response));
    }

    Ok(())
}

fn parse_message(args: &[String]) -> Result<Message, String> {
    if args.is_empty() {
        return Err(message_usage());
    }

    let kind = args[0].as_str();
    let fields = MessageFields::parse(&args[1..])?;
    match kind {
        "hello" => {
            let token = fields.token_required()?;
            let app_id = fields.app_id_required()?;
            let pid = fields.pid.unwrap_or_else(std::process::id);
            Ok(Message::Hello { token, app_id, pid })
        }
        "denuvo" | "denuvo-detected" => Ok(Message::DenuvoDetected {
            app_id: fields.app_id_required()?,
        }),
        "dll-loaded" => Ok(Message::DllLoaded {
            app_id: fields.app_id_required()?,
            name: fields.string_required("name", 1)?,
        }),
        "dll-inject-result" => Ok(Message::DllInjectResult {
            app_id: fields.app_id_required()?,
            success: fields.bool_required("success", 1)?,
        }),
        "pe-section" => Ok(Message::PeSection {
            app_id: fields.app_id_required()?,
            section_name: fields.string_required("section", 1)?,
        }),
        "ack" => Ok(Message::Ack),
        "set-delegate" => Ok(Message::SetDelegate {
            app_id: fields.app_id_required()?,
            enable: fields.bool_required("enable", 1)?,
        }),
        "-h" | "--help" => Err(message_usage()),
        other => Err(format!("unknown message {other:?}\n{}", message_usage())),
    }
}

struct MessageFields {
    positional: Vec<String>,
    token: Option<[u8; TOKEN_LEN]>,
    app_id: Option<u32>,
    pid: Option<u32>,
    name: Option<String>,
    section: Option<String>,
    success: Option<bool>,
    enable: Option<bool>,
}

impl MessageFields {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut fields = Self {
            positional: Vec::new(),
            token: None,
            app_id: None,
            pid: None,
            name: None,
            section: None,
            success: None,
            enable: None,
        };

        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--token" => {
                    index += 1;
                    fields.token = Some(parse_token(required_value(args, index, "--token")?)?);
                }
                "--app-id" => {
                    index += 1;
                    fields.app_id = Some(parse_u32(required_value(args, index, "--app-id")?)?);
                }
                "--pid" => {
                    index += 1;
                    fields.pid = Some(parse_u32(required_value(args, index, "--pid")?)?);
                }
                "--name" => {
                    index += 1;
                    fields.name = Some(required_value(args, index, "--name")?.to_owned());
                }
                "--section" => {
                    index += 1;
                    fields.section = Some(required_value(args, index, "--section")?.to_owned());
                }
                "--success" => {
                    index += 1;
                    fields.success = Some(parse_bool(required_value(args, index, "--success")?)?);
                }
                "--enable" => {
                    index += 1;
                    fields.enable = Some(parse_bool(required_value(args, index, "--enable")?)?);
                }
                other if other.starts_with('-') => {
                    return Err(format!("unknown message option {other:?}"));
                }
                other => fields.positional.push(other.to_owned()),
            }
            index += 1;
        }

        if fields.app_id.is_none() {
            if let Some(value) = fields.positional.first() {
                fields.app_id = Some(parse_u32(value)?);
            }
        }

        Ok(fields)
    }

    fn token_required(&self) -> Result<[u8; TOKEN_LEN], String> {
        self.token
            .ok_or_else(|| "message requires --token HEX".to_owned())
    }

    fn app_id_required(&self) -> Result<u32, String> {
        self.app_id
            .ok_or_else(|| "message requires --app-id APP_ID or positional APP_ID".to_owned())
    }

    fn string_required(&self, name: &str, positional_index: usize) -> Result<String, String> {
        match name {
            "name" => self.name.clone(),
            "section" => self.section.clone(),
            _ => None,
        }
        .or_else(|| self.positional.get(positional_index).cloned())
        .ok_or_else(|| format!("message requires --{name} VALUE"))
    }

    fn bool_required(&self, name: &str, positional_index: usize) -> Result<bool, String> {
        match name {
            "success" => self.success,
            "enable" => self.enable,
            _ => None,
        }
        .or_else(|| {
            self.positional
                .get(positional_index)
                .and_then(|value| parse_bool(value).ok())
        })
        .ok_or_else(|| format!("message requires --{name} true|false"))
    }
}

fn message_app_id(message: &Message) -> Option<u32> {
    match message {
        Message::Hello { app_id, .. }
        | Message::DenuvoDetected { app_id }
        | Message::DllLoaded { app_id, .. }
        | Message::DllInjectResult { app_id, .. }
        | Message::PeSection { app_id, .. }
        | Message::SetDelegate { app_id, .. } => Some(*app_id),
        Message::Ack => None,
    }
}

fn parse_token(value: &str) -> Result<[u8; TOKEN_LEN], String> {
    proto::token_from_hex(value).ok_or_else(|| {
        format!(
            "invalid token hex: expected {} hex characters",
            TOKEN_LEN * 2
        )
    })
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

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "1" | "true" | "yes" | "on" | "enable" | "enabled" | "success" => Ok(true),
        "0" | "false" | "no" | "off" | "disable" | "disabled" | "fail" | "failed" => Ok(false),
        other => Err(format!("invalid bool {other:?}")),
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

fn decode_frames(bytes: &[u8]) -> Result<Vec<Message>, String> {
    let mut cursor = Cursor::new(bytes);
    let mut messages = Vec::new();

    while cursor.position() < bytes.len() as u64 {
        let before = cursor.position();
        let message =
            proto::read_message(&mut cursor).map_err(|error| format!("decode failed: {error}"))?;
        if cursor.position() == before {
            return Err("decoder made no progress".to_owned());
        }
        messages.push(message);
    }

    Ok(messages)
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

fn format_message(message: &Message) -> String {
    match message {
        Message::Hello { token, app_id, pid } => {
            format!(
                "Hello app_id={app_id} pid={pid} token={}",
                proto::token_to_hex(token)
            )
        }
        Message::DenuvoDetected { app_id } => format!("DenuvoDetected app_id={app_id}"),
        Message::DllLoaded { app_id, name } => {
            format!("DllLoaded app_id={app_id} name={name:?}")
        }
        Message::DllInjectResult { app_id, success } => {
            format!("DllInjectResult app_id={app_id} success={success}")
        }
        Message::PeSection {
            app_id,
            section_name,
        } => format!("PeSection app_id={app_id} section={section_name:?}"),
        Message::Ack => "Ack".to_owned(),
        Message::SetDelegate { app_id, enable } => {
            format!("SetDelegate app_id={app_id} enable={enable}")
        }
    }
}

fn usage() -> String {
    format!(
        "{}\n\n{}\n\n{}\n\n{}",
        "usage: vapor-forge-ipc-tool <encode|decode|send> ...",
        message_usage(),
        decode_usage(),
        send_usage()
    )
}

fn message_usage() -> String {
    concat!(
        "messages:\n",
        "  hello --token HEX --app-id APP_ID [--pid PID]\n",
        "  denuvo APP_ID\n",
        "  dll-loaded APP_ID NAME\n",
        "  dll-inject-result APP_ID true|false\n",
        "  pe-section APP_ID SECTION\n",
        "  ack\n",
        "  set-delegate APP_ID true|false"
    )
    .to_owned()
}

fn decode_usage() -> String {
    "decode: vapor-forge-ipc-tool decode [--payload] [HEX_OR_HEXDUMP]".to_owned()
}

fn send_usage() -> String {
    concat!(
        "send: vapor-forge-ipc-tool send [--socket PATH] --token HEX [--app-id APP_ID] ",
        "[--pid PID] [--raw] [--read-response] MESSAGE ..."
    )
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_contiguous_hex_frame() {
        let msg = Message::DenuvoDetected { app_id: 480 };
        let hex = hex_compact(&msg.encode());
        assert_eq!(parse_hex_dump(&hex).unwrap(), msg.encode());
    }

    #[test]
    fn parses_xxd_style_hex_dump() {
        let bytes = parse_hex_dump("00000000: 0500 0000 02e0 0100 00  .........").unwrap();
        assert_eq!(bytes, vec![5, 0, 0, 0, 2, 0xE0, 1, 0, 0]);
    }

    #[test]
    fn parses_hex_key_value_output() {
        let bytes = parse_hex_dump("hex=0500000002e0010000").unwrap();
        assert_eq!(bytes, vec![5, 0, 0, 0, 2, 0xE0, 1, 0, 0]);
    }

    #[test]
    fn decodes_multiple_frames() {
        let mut bytes = Message::DenuvoDetected { app_id: 480 }.encode();
        bytes.extend(Message::Ack.encode());
        let messages = decode_frames(&bytes).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], Message::DenuvoDetected { app_id: 480 });
        assert_eq!(messages[1], Message::Ack);
    }

    #[test]
    fn parses_positional_message_fields() {
        let args = vec![
            "dll-loaded".to_owned(),
            "480".to_owned(),
            "denuvo64.dll".to_owned(),
        ];
        assert_eq!(
            parse_message(&args).unwrap(),
            Message::DllLoaded {
                app_id: 480,
                name: "denuvo64.dll".to_owned()
            }
        );
    }
}
