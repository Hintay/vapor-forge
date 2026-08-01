use std::io::Read;

use vapor_forge_packet_capture::PacketDirection;
pub(super) use vapor_forge_tool_support::parse_hex_dump;

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
