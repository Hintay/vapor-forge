use std::io::Read;

use vapor_forge_packet_capture::PacketDirection;

pub(super) enum Input {
    File(String),
    Hex(String),
    StdinHex,
}

impl Input {
    pub(super) fn read(&self) -> Result<Vec<u8>, String> {
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

pub(super) fn parse_direction(value: &str) -> Result<PacketDirection, String> {
    match value {
        "send" => Ok(PacketDirection::Send),
        "recv" => Ok(PacketDirection::Recv),
        other => Err(format!("invalid direction {other:?}")),
    }
}

pub(super) fn parse_hex_dump(input: &str) -> Result<Vec<u8>, String> {
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
