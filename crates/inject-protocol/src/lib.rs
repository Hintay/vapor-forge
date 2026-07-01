// IPC protocol between proton-inject (64-bit Wine child) and the main
// steam-runtime-rs process (32-bit Linux Steam).
//
// Wire format: [u32 len][u8 msg_type][payload...]
// len = size of msg_type + payload (does NOT include the 4-byte len field).
// All multi-byte integers are little-endian.

use std::io::{self, Read, Write};

pub const TOKEN_LEN: usize = 32;
pub const MAX_MSG_SIZE: usize = 4096;
pub const MAX_NAME_LEN: usize = 260;

// Socket path environment variable name.
pub const ENV_IPC_SOCK: &str = "STEAM_RUNTIME_IPC_SOCK";

// Per-launch authentication token environment variable name.
pub const ENV_IPC_TOKEN: &str = "STEAM_RUNTIME_IPC_TOKEN";

// Default socket directory under XDG_RUNTIME_DIR.
pub const SOCK_DIR_NAME: &str = "steam-runtime-rs";
pub const SOCK_FILE_NAME: &str = "ipc.sock";

// -----------------------------------------------------------------------
// Message types
// -----------------------------------------------------------------------

const MSG_HELLO: u8 = 0x01;
const MSG_DENUVO_DETECTED: u8 = 0x02;
const MSG_DLL_LOADED: u8 = 0x03;
const MSG_DLL_INJECT_RESULT: u8 = 0x04;
const MSG_PE_SECTION: u8 = 0x05;
const MSG_ACK: u8 = 0x80;
const MSG_SET_DELEGATE: u8 = 0x81;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    // Client -> Server
    Hello {
        token: [u8; TOKEN_LEN],
        app_id: u32,
        pid: u32,
    },
    DenuvoDetected {
        app_id: u32,
    },
    DllLoaded {
        app_id: u32,
        name: String,
    },
    DllInjectResult {
        app_id: u32,
        success: bool,
    },
    PeSection {
        app_id: u32,
        section_name: String,
    },

    // Server -> Client
    Ack,
    SetDelegate {
        app_id: u32,
        enable: bool,
    },
}

// -----------------------------------------------------------------------
// Encoding
// -----------------------------------------------------------------------

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Message::Hello { token, app_id, pid } => {
                payload.push(MSG_HELLO);
                payload.extend_from_slice(token);
                payload.extend_from_slice(&app_id.to_le_bytes());
                payload.extend_from_slice(&pid.to_le_bytes());
            }
            Message::DenuvoDetected { app_id } => {
                payload.push(MSG_DENUVO_DETECTED);
                payload.extend_from_slice(&app_id.to_le_bytes());
            }
            Message::DllLoaded { app_id, name } => {
                payload.push(MSG_DLL_LOADED);
                payload.extend_from_slice(&app_id.to_le_bytes());
                let name_bytes = name.as_bytes();
                let len = name_bytes.len().min(MAX_NAME_LEN) as u16;
                payload.extend_from_slice(&len.to_le_bytes());
                payload.extend_from_slice(&name_bytes[..len as usize]);
            }
            Message::DllInjectResult { app_id, success } => {
                payload.push(MSG_DLL_INJECT_RESULT);
                payload.extend_from_slice(&app_id.to_le_bytes());
                payload.push(if *success { 1 } else { 0 });
            }
            Message::PeSection { app_id, section_name } => {
                payload.push(MSG_PE_SECTION);
                payload.extend_from_slice(&app_id.to_le_bytes());
                let name_bytes = section_name.as_bytes();
                let len = name_bytes.len().min(MAX_NAME_LEN) as u16;
                payload.extend_from_slice(&len.to_le_bytes());
                payload.extend_from_slice(&name_bytes[..len as usize]);
            }
            Message::Ack => {
                payload.push(MSG_ACK);
            }
            Message::SetDelegate { app_id, enable } => {
                payload.push(MSG_SET_DELEGATE);
                payload.extend_from_slice(&app_id.to_le_bytes());
                payload.push(if *enable { 1 } else { 0 });
            }
        }
        let len = payload.len() as u32;
        let mut buf = Vec::with_capacity(4 + payload.len());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&payload);
        buf
    }
}

// -----------------------------------------------------------------------
// Decoding
// -----------------------------------------------------------------------

#[derive(Debug)]
pub enum DecodeError {
    Io(io::Error),
    BadLength(u32),
    UnknownType(u8),
    TooShort,
}

impl From<io::Error> for DecodeError {
    fn from(e: io::Error) -> Self {
        DecodeError::Io(e)
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Io(e) => write!(f, "io: {e}"),
            DecodeError::BadLength(n) => write!(f, "bad message length: {n}"),
            DecodeError::UnknownType(t) => write!(f, "unknown message type: 0x{t:02x}"),
            DecodeError::TooShort => write!(f, "payload too short"),
        }
    }
}

pub fn read_message(reader: &mut impl Read) -> Result<Message, DecodeError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len == 0 || len as usize > MAX_MSG_SIZE {
        return Err(DecodeError::BadLength(len));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    decode_payload(&buf)
}

pub fn write_message(writer: &mut impl Write, msg: &Message) -> io::Result<()> {
    let bytes = msg.encode();
    writer.write_all(&bytes)?;
    writer.flush()
}

fn decode_payload(buf: &[u8]) -> Result<Message, DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::TooShort);
    }
    let msg_type = buf[0];
    let data = &buf[1..];
    match msg_type {
        MSG_HELLO => {
            if data.len() < TOKEN_LEN + 8 {
                return Err(DecodeError::TooShort);
            }
            let mut token = [0u8; TOKEN_LEN];
            token.copy_from_slice(&data[..TOKEN_LEN]);
            let app_id = u32::from_le_bytes(data[TOKEN_LEN..TOKEN_LEN + 4].try_into().unwrap());
            let pid = u32::from_le_bytes(data[TOKEN_LEN + 4..TOKEN_LEN + 8].try_into().unwrap());
            Ok(Message::Hello { token, app_id, pid })
        }
        MSG_DENUVO_DETECTED => {
            if data.len() < 4 {
                return Err(DecodeError::TooShort);
            }
            let app_id = u32::from_le_bytes(data[..4].try_into().unwrap());
            Ok(Message::DenuvoDetected { app_id })
        }
        MSG_DLL_LOADED => {
            if data.len() < 6 {
                return Err(DecodeError::TooShort);
            }
            let app_id = u32::from_le_bytes(data[..4].try_into().unwrap());
            let name_len = u16::from_le_bytes(data[4..6].try_into().unwrap()) as usize;
            if data.len() < 6 + name_len {
                return Err(DecodeError::TooShort);
            }
            let name = String::from_utf8_lossy(&data[6..6 + name_len]).into_owned();
            Ok(Message::DllLoaded { app_id, name })
        }
        MSG_DLL_INJECT_RESULT => {
            if data.len() < 5 {
                return Err(DecodeError::TooShort);
            }
            let app_id = u32::from_le_bytes(data[..4].try_into().unwrap());
            let success = data[4] != 0;
            Ok(Message::DllInjectResult { app_id, success })
        }
        MSG_PE_SECTION => {
            if data.len() < 6 {
                return Err(DecodeError::TooShort);
            }
            let app_id = u32::from_le_bytes(data[..4].try_into().unwrap());
            let name_len = u16::from_le_bytes(data[4..6].try_into().unwrap()) as usize;
            if data.len() < 6 + name_len {
                return Err(DecodeError::TooShort);
            }
            let section_name = String::from_utf8_lossy(&data[6..6 + name_len]).into_owned();
            Ok(Message::PeSection { app_id, section_name })
        }
        MSG_ACK => Ok(Message::Ack),
        MSG_SET_DELEGATE => {
            if data.len() < 5 {
                return Err(DecodeError::TooShort);
            }
            let app_id = u32::from_le_bytes(data[..4].try_into().unwrap());
            let enable = data[4] != 0;
            Ok(Message::SetDelegate { app_id, enable })
        }
        _ => Err(DecodeError::UnknownType(msg_type)),
    }
}

// -----------------------------------------------------------------------
// Token helpers
// -----------------------------------------------------------------------

pub fn generate_token() -> io::Result<[u8; TOKEN_LEN]> {
    let mut token = [0u8; TOKEN_LEN];
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(&mut token)?;
    Ok(token)
}

pub fn token_to_hex(token: &[u8; TOKEN_LEN]) -> String {
    let mut s = String::with_capacity(TOKEN_LEN * 2);
    for b in token {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn token_from_hex(hex: &str) -> Option<[u8; TOKEN_LEN]> {
    if hex.len() != TOKEN_LEN * 2 {
        return None;
    }
    let mut token = [0u8; TOKEN_LEN];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        token[i] = (hi << 4) | lo;
    }
    Some(token)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Compute the default socket path: $XDG_RUNTIME_DIR/steam-runtime-rs/ipc.sock
pub fn default_socket_path() -> Option<String> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok()?;
    Some(format!("{runtime_dir}/{SOCK_DIR_NAME}/{SOCK_FILE_NAME}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trip() {
        let token = [0xAB; TOKEN_LEN];
        let msg = Message::Hello {
            token,
            app_id: 480,
            pid: 1234,
        };
        let bytes = msg.encode();
        let decoded = decode_payload(&bytes[4..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn denuvo_detected_round_trip() {
        let msg = Message::DenuvoDetected { app_id: 12345 };
        let bytes = msg.encode();
        let decoded = decode_payload(&bytes[4..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn dll_loaded_round_trip() {
        let msg = Message::DllLoaded {
            app_id: 480,
            name: "denuvo64.dll".into(),
        };
        let bytes = msg.encode();
        let decoded = decode_payload(&bytes[4..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn dll_inject_result_round_trip() {
        let msg = Message::DllInjectResult {
            app_id: 480,
            success: true,
        };
        let bytes = msg.encode();
        let decoded = decode_payload(&bytes[4..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn pe_section_round_trip() {
        let msg = Message::PeSection {
            app_id: 480,
            section_name: ".themida".into(),
        };
        let bytes = msg.encode();
        let decoded = decode_payload(&bytes[4..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn ack_round_trip() {
        let msg = Message::Ack;
        let bytes = msg.encode();
        let decoded = decode_payload(&bytes[4..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn set_delegate_round_trip() {
        let msg = Message::SetDelegate {
            app_id: 480,
            enable: true,
        };
        let bytes = msg.encode();
        let decoded = decode_payload(&bytes[4..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn token_hex_round_trip() {
        let token = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
        ];
        let hex = token_to_hex(&token);
        assert_eq!(hex.len(), 64);
        let back = token_from_hex(&hex).unwrap();
        assert_eq!(token, back);
    }

    #[test]
    fn read_write_message_via_cursor() {
        let msg = Message::Hello {
            token: [0x42; TOKEN_LEN],
            app_id: 999,
            pid: 5678,
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = read_message(&mut cursor).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn unknown_type_returns_error() {
        let payload = [0xFF, 0x00, 0x00, 0x00];
        assert!(matches!(
            decode_payload(&payload),
            Err(DecodeError::UnknownType(0xFF))
        ));
    }

    #[test]
    fn too_short_payload_returns_error() {
        let payload = [MSG_HELLO, 0x00]; // HELLO needs 40 bytes
        assert!(matches!(decode_payload(&payload), Err(DecodeError::TooShort)));
    }
}
