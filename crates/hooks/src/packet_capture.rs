#![forbid(unsafe_code)]

#[cfg(debug_assertions)]
use std::collections::VecDeque;
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
#[cfg(debug_assertions)]
use std::sync::Mutex;

#[cfg(debug_assertions)]
use vapor_forge_packet_capture::{summarize_packet, PacketSummary, PacketType};
use vapor_forge_packet_capture::{PacketChange, PacketDirection};

#[cfg(debug_assertions)]
const MODE_OFF: u8 = 0;
#[cfg(debug_assertions)]
const MODE_SUMMARY: u8 = 1;
#[cfg(debug_assertions)]
const MODE_RAW: u8 = 2;
#[cfg(debug_assertions)]
const DEFAULT_LIMIT: usize = 128;
#[cfg(debug_assertions)]
const MAX_LIMIT: usize = 4096;
#[cfg(debug_assertions)]
const MAX_RAW_PACKET_SIZE: usize = 256 * 1024;

#[cfg(debug_assertions)]
static MODE: AtomicU8 = AtomicU8::new(MODE_OFF);
#[cfg(debug_assertions)]
static LIMIT: AtomicUsize = AtomicUsize::new(DEFAULT_LIMIT);
#[cfg(debug_assertions)]
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
#[cfg(debug_assertions)]
static FILTER: Mutex<PacketCaptureFilter> = Mutex::new(PacketCaptureFilter::empty());
#[cfg(debug_assertions)]
static BUFFER: Mutex<VecDeque<CapturedPacket>> = Mutex::new(VecDeque::new());

#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
pub struct CapturedPacket {
    pub summary: PacketSummary,
    pub raw: Option<Vec<u8>>,
}

#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
pub struct PacketCaptureStatus {
    pub mode: PacketCaptureMode,
    pub limit: usize,
    pub len: usize,
    pub next_id: u64,
    pub filter: PacketCaptureFilter,
}

#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketCaptureMode {
    Off,
    Summary,
    Raw,
}

#[cfg(debug_assertions)]
impl PacketCaptureMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Summary => "summary",
            Self::Raw => "raw",
        }
    }
}

#[cfg(debug_assertions)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketCaptureFilter {
    pub direction: Option<PacketDirection>,
    pub packet_type: Option<PacketType>,
    pub emsg: Option<u32>,
    pub app_id: Option<u32>,
    pub changed: Option<PacketChange>,
}

#[cfg(debug_assertions)]
impl PacketCaptureFilter {
    pub const fn empty() -> Self {
        Self {
            direction: None,
            packet_type: None,
            emsg: None,
            app_id: None,
            changed: None,
        }
    }

    pub fn matches(&self, summary: &PacketSummary) -> bool {
        if self
            .direction
            .is_some_and(|value| value != summary.direction)
        {
            return false;
        }
        if self
            .packet_type
            .is_some_and(|value| value != summary.packet_type)
        {
            return false;
        }
        if self.emsg.is_some_and(|value| summary.emsg != Some(value)) {
            return false;
        }
        if self
            .app_id
            .is_some_and(|value| !summary.app_ids.contains(&value))
        {
            return false;
        }
        if self.changed.is_some_and(|value| value != summary.change) {
            return false;
        }
        true
    }
}

#[cfg(debug_assertions)]
pub fn mode() -> PacketCaptureMode {
    match MODE.load(Ordering::Acquire) {
        MODE_SUMMARY => PacketCaptureMode::Summary,
        MODE_RAW => PacketCaptureMode::Raw,
        _ => PacketCaptureMode::Off,
    }
}

#[cfg(debug_assertions)]
pub fn set_mode(mode: PacketCaptureMode) {
    let raw = match mode {
        PacketCaptureMode::Off => MODE_OFF,
        PacketCaptureMode::Summary => MODE_SUMMARY,
        PacketCaptureMode::Raw => MODE_RAW,
    };
    MODE.store(raw, Ordering::Release);
}

#[cfg(debug_assertions)]
pub fn set_filter(filter: PacketCaptureFilter) {
    let mut guard = FILTER.lock().unwrap_or_else(|e| e.into_inner());
    *guard = filter;
}

#[cfg(debug_assertions)]
pub fn clear_filter() {
    set_filter(PacketCaptureFilter::empty());
}

#[cfg(debug_assertions)]
pub fn set_limit(limit: usize) -> usize {
    let limit = limit.clamp(1, MAX_LIMIT);
    LIMIT.store(limit, Ordering::Release);
    trim_to_limit(limit);
    limit
}

#[cfg(debug_assertions)]
pub fn clear() {
    BUFFER.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

#[cfg(debug_assertions)]
pub fn status() -> PacketCaptureStatus {
    let len = BUFFER.lock().unwrap_or_else(|e| e.into_inner()).len();
    let filter = FILTER.lock().unwrap_or_else(|e| e.into_inner()).clone();
    PacketCaptureStatus {
        mode: mode(),
        limit: LIMIT.load(Ordering::Acquire),
        len,
        next_id: NEXT_ID.load(Ordering::Acquire),
        filter,
    }
}

#[cfg(debug_assertions)]
pub fn list() -> Vec<CapturedPacket> {
    BUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect()
}

#[cfg(debug_assertions)]
pub fn get(id: u64) -> Option<CapturedPacket> {
    BUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|packet| packet.summary.id == id)
        .cloned()
}

#[cfg(debug_assertions)]
pub fn capture(
    direction: PacketDirection,
    data: &[u8],
    change: PacketChange,
    final_len: Option<usize>,
) {
    let mode = mode();
    if mode == PacketCaptureMode::Off {
        return;
    }

    let id = NEXT_ID.fetch_add(1, Ordering::AcqRel);
    let summary = summarize_packet(id, direction, data, change, final_len);
    let filter = FILTER.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if !filter.matches(&summary) {
        return;
    }

    let raw = if mode == PacketCaptureMode::Raw && data.len() <= MAX_RAW_PACKET_SIZE {
        Some(data.to_vec())
    } else {
        None
    };

    let mut guard = BUFFER.lock().unwrap_or_else(|e| e.into_inner());
    guard.push_back(CapturedPacket { summary, raw });
    let limit = LIMIT.load(Ordering::Acquire);
    while guard.len() > limit {
        guard.pop_front();
    }
}

#[cfg(not(debug_assertions))]
#[inline]
pub fn capture(
    _direction: PacketDirection,
    _data: &[u8],
    _change: PacketChange,
    _final_len: Option<usize>,
) {
}

#[cfg(debug_assertions)]
fn trim_to_limit(limit: usize) {
    let mut guard = BUFFER.lock().unwrap_or_else(|e| e.into_inner());
    while guard.len() > limit {
        guard.pop_front();
    }
}
