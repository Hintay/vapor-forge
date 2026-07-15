// IPC protocol between the 64-bit Wine child helper and the main 32-bit Steam
// process.
//
// Wire format: [u32 len][u8 msg_type][payload...]
// len = size of msg_type + payload (does NOT include the 4-byte len field).
// All multi-byte integers are little-endian.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};

pub const TOKEN_LEN: usize = 32;
pub const EVENT_ID_LEN: usize = 16;
pub const MAX_MSG_SIZE: usize = 4096;
pub const MAX_NAME_LEN: usize = 260;
pub const MAX_ACHIEVEMENT_KEY_LEN: usize = 255;

// Socket path environment variable name.
pub const ENV_GAME_BRIDGE_SOCK: &str = "VAPOR_FORGE_GAME_BRIDGE_SOCK";

// Per-launch authentication token environment variable name.
pub const ENV_GAME_BRIDGE_TOKEN: &str = "VAPOR_FORGE_GAME_BRIDGE_TOKEN";

// Default socket directory under XDG_RUNTIME_DIR.
pub const SOCK_DIR_NAME: &str = "vapor-forge";
pub const SOCK_FILE_NAME: &str = "game-bridge.sock";

// -----------------------------------------------------------------------
// Message types
// -----------------------------------------------------------------------

const MSG_HELLO: u8 = 0x01;
const MSG_DENUVO_DETECTED: u8 = 0x02;
const MSG_DLL_LOADED: u8 = 0x03;
const MSG_DLL_INJECT_RESULT: u8 = 0x04;
const MSG_PE_SECTION: u8 = 0x05;
const MSG_ACHIEVEMENT_UNLOCKED: u8 = 0x06;
const MSG_ACHIEVEMENT_PROGRESS: u8 = 0x07;
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
    AchievementUnlocked {
        event_id: [u8; EVENT_ID_LEN],
        app_id: u32,
        achievement_key: String,
        observed_at: i64,
        unlocked_at: i64,
    },
    AchievementProgress {
        event_id: [u8; EVENT_ID_LEN],
        app_id: u32,
        achievement_key: String,
        current: u32,
        maximum: u32,
        observed_at: i64,
    },
    // Server -> Client
    Ack,
    SetDelegate {
        app_id: u32,
        enable: bool,
    },
}

#[derive(Default)]
pub struct AchievementDeduplicator {
    unlocked: HashSet<String>,
    progress: HashMap<String, (u32, u32)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingAchievement {
    Unlock {
        key: String,
    },
    Progress {
        key: String,
        current: u32,
        maximum: u32,
    },
}

#[derive(Default)]
pub struct AchievementCommitBuffer {
    deduplicator: AchievementDeduplicator,
    pending_unlocks: HashSet<String>,
    pending_progress: HashMap<String, (u32, u32)>,
}

impl AchievementCommitBuffer {
    pub fn stage_unlock(&mut self, key: &str) -> bool {
        if !self.deduplicator.accept_unlock(key) {
            return false;
        }
        self.pending_progress.remove(key);
        self.pending_unlocks.insert(key.to_owned());
        true
    }

    pub fn stage_progress(&mut self, key: &str, current: u32, maximum: u32) -> bool {
        if !self.deduplicator.accept_progress(key, current, maximum) {
            return false;
        }
        self.pending_progress
            .insert(key.to_owned(), (current, maximum));
        true
    }

    pub fn pending(&self) -> Vec<PendingAchievement> {
        let mut values = self
            .pending_unlocks
            .iter()
            .cloned()
            .map(|key| PendingAchievement::Unlock { key })
            .collect::<Vec<_>>();
        values.extend(
            self.pending_progress
                .iter()
                .map(|(key, &(current, maximum))| PendingAchievement::Progress {
                    key: key.clone(),
                    current,
                    maximum,
                }),
        );
        values
    }

    pub fn mark_sent(&mut self, pending: &PendingAchievement) {
        match pending {
            PendingAchievement::Unlock { key } => {
                self.pending_unlocks.remove(key);
            }
            PendingAchievement::Progress {
                key,
                current,
                maximum,
            } => {
                if self.pending_progress.get(key) == Some(&(*current, *maximum)) {
                    self.pending_progress.remove(key);
                }
            }
        }
    }

    pub fn clear(&mut self, key: &str) {
        self.deduplicator.forget_unlock(key);
        self.deduplicator.forget_progress(key);
        self.pending_unlocks.remove(key);
        self.pending_progress.remove(key);
    }
}

impl AchievementDeduplicator {
    pub fn accept_unlock(&mut self, key: &str) -> bool {
        if key.is_empty() || !self.unlocked.insert(key.to_owned()) {
            return false;
        }
        self.progress.remove(key);
        true
    }

    pub fn accept_progress(&mut self, key: &str, current: u32, maximum: u32) -> bool {
        if key.is_empty() || maximum == 0 || current > maximum || self.unlocked.contains(key) {
            return false;
        }
        let value = (current, maximum);
        if self.progress.get(key) == Some(&value) {
            return false;
        }
        self.progress.insert(key.to_owned(), value);
        true
    }

    pub fn forget_unlock(&mut self, key: &str) {
        self.unlocked.remove(key);
    }

    pub fn forget_progress(&mut self, key: &str) {
        self.progress.remove(key);
    }
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
            Message::PeSection {
                app_id,
                section_name,
            } => {
                payload.push(MSG_PE_SECTION);
                payload.extend_from_slice(&app_id.to_le_bytes());
                let name_bytes = section_name.as_bytes();
                let len = name_bytes.len().min(MAX_NAME_LEN) as u16;
                payload.extend_from_slice(&len.to_le_bytes());
                payload.extend_from_slice(&name_bytes[..len as usize]);
            }
            Message::AchievementUnlocked {
                event_id,
                app_id,
                achievement_key,
                observed_at,
                unlocked_at,
            } => {
                payload.push(MSG_ACHIEVEMENT_UNLOCKED);
                payload.extend_from_slice(event_id);
                payload.extend_from_slice(&app_id.to_le_bytes());
                push_bounded_string(&mut payload, achievement_key, MAX_ACHIEVEMENT_KEY_LEN);
                payload.extend_from_slice(&observed_at.to_le_bytes());
                payload.extend_from_slice(&unlocked_at.to_le_bytes());
            }
            Message::AchievementProgress {
                event_id,
                app_id,
                achievement_key,
                current,
                maximum,
                observed_at,
            } => {
                payload.push(MSG_ACHIEVEMENT_PROGRESS);
                payload.extend_from_slice(event_id);
                payload.extend_from_slice(&app_id.to_le_bytes());
                push_bounded_string(&mut payload, achievement_key, MAX_ACHIEVEMENT_KEY_LEN);
                payload.extend_from_slice(&current.to_le_bytes());
                payload.extend_from_slice(&maximum.to_le_bytes());
                payload.extend_from_slice(&observed_at.to_le_bytes());
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

fn push_bounded_string(payload: &mut Vec<u8>, value: &str, maximum: usize) {
    let bytes = value.as_bytes();
    let len = bytes.len().min(maximum) as u16;
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(&bytes[..len as usize]);
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

pub fn decode_message_bytes(bytes: &[u8]) -> Result<Message, DecodeError> {
    if bytes.len() < 4 {
        return Err(DecodeError::TooShort);
    }
    let len = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    if len == 0 || len as usize > MAX_MSG_SIZE {
        return Err(DecodeError::BadLength(len));
    }
    let payload_len = len as usize;
    if bytes.len() < 4 + payload_len {
        return Err(DecodeError::TooShort);
    }
    decode_payload(&bytes[4..4 + payload_len])
}

pub fn write_message(writer: &mut impl Write, msg: &Message) -> io::Result<()> {
    let bytes = msg.encode();
    writer.write_all(&bytes)?;
    writer.flush()
}

pub fn decode_payload(buf: &[u8]) -> Result<Message, DecodeError> {
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
            Ok(Message::PeSection {
                app_id,
                section_name,
            })
        }
        MSG_ACHIEVEMENT_UNLOCKED => {
            let (event_id, app_id, achievement_key, tail) = decode_achievement_prefix(data)?;
            if tail.len() < 16 {
                return Err(DecodeError::TooShort);
            }
            let observed_at = i64::from_le_bytes(tail[..8].try_into().unwrap());
            let unlocked_at = i64::from_le_bytes(tail[8..16].try_into().unwrap());
            Ok(Message::AchievementUnlocked {
                event_id,
                app_id,
                achievement_key,
                observed_at,
                unlocked_at,
            })
        }
        MSG_ACHIEVEMENT_PROGRESS => {
            let (event_id, app_id, achievement_key, tail) = decode_achievement_prefix(data)?;
            if tail.len() < 16 {
                return Err(DecodeError::TooShort);
            }
            let current = u32::from_le_bytes(tail[..4].try_into().unwrap());
            let maximum = u32::from_le_bytes(tail[4..8].try_into().unwrap());
            let observed_at = i64::from_le_bytes(tail[8..16].try_into().unwrap());
            Ok(Message::AchievementProgress {
                event_id,
                app_id,
                achievement_key,
                current,
                maximum,
                observed_at,
            })
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

type AchievementPrefix<'a> = ([u8; EVENT_ID_LEN], u32, String, &'a [u8]);

fn decode_achievement_prefix(data: &[u8]) -> Result<AchievementPrefix<'_>, DecodeError> {
    if data.len() < EVENT_ID_LEN + 6 {
        return Err(DecodeError::TooShort);
    }
    let mut event_id = [0u8; EVENT_ID_LEN];
    event_id.copy_from_slice(&data[..EVENT_ID_LEN]);
    let app_offset = EVENT_ID_LEN;
    let app_id = u32::from_le_bytes(data[app_offset..app_offset + 4].try_into().unwrap());
    let len_offset = app_offset + 4;
    let key_len = u16::from_le_bytes(data[len_offset..len_offset + 2].try_into().unwrap()) as usize;
    let key_offset = len_offset + 2;
    if key_len > MAX_ACHIEVEMENT_KEY_LEN || data.len() < key_offset + key_len {
        return Err(DecodeError::TooShort);
    }
    let achievement_key = String::from_utf8_lossy(&data[key_offset..key_offset + key_len]).into();
    Ok((
        event_id,
        app_id,
        achievement_key,
        &data[key_offset + key_len..],
    ))
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

pub fn generate_event_id() -> io::Result<[u8; EVENT_ID_LEN]> {
    let mut event_id = [0u8; EVENT_ID_LEN];
    let mut file = std::fs::File::open("/dev/urandom")?;
    file.read_exact(&mut event_id)?;
    event_id[6] = (event_id[6] & 0x0f) | 0x40;
    event_id[8] = (event_id[8] & 0x3f) | 0x80;
    Ok(event_id)
}

pub fn event_id_to_uuid(event_id: &[u8; EVENT_ID_LEN]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        event_id[0], event_id[1], event_id[2], event_id[3],
        event_id[4], event_id[5], event_id[6], event_id[7],
        event_id[8], event_id[9], event_id[10], event_id[11],
        event_id[12], event_id[13], event_id[14], event_id[15]
    )
}

pub fn event_id_from_uuid(value: &str) -> Option<[u8; EVENT_ID_LEN]> {
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if compact.len() != EVENT_ID_LEN * 2 {
        return None;
    }
    let mut event_id = [0u8; EVENT_ID_LEN];
    for (index, chunk) in compact.as_bytes().chunks(2).enumerate() {
        event_id[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(event_id)
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

/// Compute the default socket path: $XDG_RUNTIME_DIR/vapor-forge/game-bridge.sock
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
    fn achievement_unlocked_round_trip() {
        let msg = Message::AchievementUnlocked {
            event_id: [0x11; EVENT_ID_LEN],
            app_id: 620,
            achievement_key: "WAKE_UP".into(),
            observed_at: 1_800_000_002,
            unlocked_at: 1_800_000_000,
        };
        let bytes = msg.encode();
        assert_eq!(decode_payload(&bytes[4..]).unwrap(), msg);
    }

    #[test]
    fn achievement_progress_round_trip() {
        let msg = Message::AchievementProgress {
            event_id: [0x22; EVENT_ID_LEN],
            app_id: 620,
            achievement_key: "COLLECT".into(),
            current: 3,
            maximum: 10,
            observed_at: 1_800_000_001,
        };
        let bytes = msg.encode();
        assert_eq!(decode_payload(&bytes[4..]).unwrap(), msg);
    }

    #[test]
    fn event_id_uuid_round_trip() {
        let id = [
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55,
        ];
        let encoded = event_id_to_uuid(&id);
        assert_eq!(encoded, "11111111-2222-4333-8444-555555555555");
        assert_eq!(event_id_from_uuid(&encoded), Some(id));
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
    fn achievement_deduplicator_tracks_semantic_state() {
        let mut state = AchievementDeduplicator::default();
        assert!(state.accept_progress("COLLECT", 1, 10));
        assert!(!state.accept_progress("COLLECT", 1, 10));
        assert!(state.accept_progress("COLLECT", 2, 10));
        assert!(state.accept_unlock("COLLECT"));
        assert!(!state.accept_unlock("COLLECT"));
        assert!(!state.accept_progress("COLLECT", 3, 10));
        assert!(!state.accept_progress("", 1, 10));
        assert!(!state.accept_progress("BROKEN", 11, 10));
        state.forget_unlock("COLLECT");
        assert!(state.accept_unlock("COLLECT"));
        state.forget_progress("OTHER");
    }

    #[test]
    fn achievement_commit_buffer_waits_for_store_boundary() {
        let mut buffer = AchievementCommitBuffer::default();
        assert!(buffer.stage_progress("FIRST", 2, 10));
        assert!(buffer.stage_progress("FIRST", 7, 10));
        assert!(buffer.stage_unlock("SECOND"));
        assert!(!buffer.stage_unlock("SECOND"));

        let pending = buffer.pending();
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&PendingAchievement::Progress {
            key: "FIRST".into(),
            current: 7,
            maximum: 10,
        }));
        let unlock = PendingAchievement::Unlock {
            key: "SECOND".into(),
        };
        assert!(pending.contains(&unlock));

        buffer.mark_sent(&unlock);
        assert_eq!(buffer.pending().len(), 1);
        buffer.clear("FIRST");
        assert!(buffer.pending().is_empty());
        assert!(buffer.stage_progress("FIRST", 1, 10));
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
        assert!(matches!(
            decode_payload(&payload),
            Err(DecodeError::TooShort)
        ));
    }
}
