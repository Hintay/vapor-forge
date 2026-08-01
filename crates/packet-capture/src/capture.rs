use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::{summarize_packet, PacketChange, PacketDirection, PacketSummary, PacketType};

const MODE_OFF: u8 = 0;
const MODE_SUMMARY: u8 = 1;
const MODE_RAW: u8 = 2;

pub const DEFAULT_CAPTURE_LIMIT: usize = 128;
pub const MAX_CAPTURE_LIMIT: usize = 4096;
pub const MAX_RAW_PACKET_SIZE: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct CapturedPacket {
    pub summary: PacketSummary,
    pub raw: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct PacketCaptureStatus {
    pub mode: PacketCaptureMode,
    pub limit: usize,
    pub len: usize,
    pub next_id: u64,
    pub filter: PacketCaptureFilter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketCaptureMode {
    Off,
    Summary,
    Raw,
}

impl PacketCaptureMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Summary => "summary",
            Self::Raw => "raw",
        }
    }

    const fn from_raw(raw: u8) -> Self {
        match raw {
            MODE_SUMMARY => Self::Summary,
            MODE_RAW => Self::Raw,
            _ => Self::Off,
        }
    }

    const fn as_raw(self) -> u8 {
        match self {
            Self::Off => MODE_OFF,
            Self::Summary => MODE_SUMMARY,
            Self::Raw => MODE_RAW,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketCaptureFilter {
    pub direction: Option<PacketDirection>,
    pub packet_type: Option<PacketType>,
    pub emsg: Option<u32>,
    pub app_id: Option<u32>,
    pub changed: Option<PacketChange>,
}

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

impl Default for PacketCaptureFilter {
    fn default() -> Self {
        Self::empty()
    }
}

/// Thread-safe bounded capture storage independent of any process singleton.
pub struct CaptureBuffer {
    mode: AtomicU8,
    limit: AtomicUsize,
    next_id: AtomicU64,
    filter: Mutex<PacketCaptureFilter>,
    packets: Mutex<VecDeque<CapturedPacket>>,
    max_limit: usize,
    max_raw_packet_size: usize,
}

impl CaptureBuffer {
    pub const fn new() -> Self {
        Self::with_limits(
            DEFAULT_CAPTURE_LIMIT,
            MAX_CAPTURE_LIMIT,
            MAX_RAW_PACKET_SIZE,
        )
    }

    pub const fn with_limits(
        default_limit: usize,
        max_limit: usize,
        max_raw_packet_size: usize,
    ) -> Self {
        let max_limit = if max_limit == 0 { 1 } else { max_limit };
        let default_limit = if default_limit == 0 {
            1
        } else if default_limit > max_limit {
            max_limit
        } else {
            default_limit
        };
        Self {
            mode: AtomicU8::new(MODE_OFF),
            limit: AtomicUsize::new(default_limit),
            next_id: AtomicU64::new(1),
            filter: Mutex::new(PacketCaptureFilter::empty()),
            packets: Mutex::new(VecDeque::new()),
            max_limit,
            max_raw_packet_size,
        }
    }

    pub fn mode(&self) -> PacketCaptureMode {
        PacketCaptureMode::from_raw(self.mode.load(Ordering::Acquire))
    }

    pub fn set_mode(&self, mode: PacketCaptureMode) {
        self.mode.store(mode.as_raw(), Ordering::Release);
    }

    pub fn set_filter(&self, filter: PacketCaptureFilter) {
        *self
            .filter
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = filter;
    }

    pub fn clear_filter(&self) {
        self.set_filter(PacketCaptureFilter::empty());
    }

    pub fn set_limit(&self, limit: usize) -> usize {
        let limit = limit.clamp(1, self.max_limit);
        self.limit.store(limit, Ordering::Release);
        self.trim_to_limit(limit);
        limit
    }

    pub fn clear(&self) {
        self.packets
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }

    pub fn status(&self) -> PacketCaptureStatus {
        let len = self
            .packets
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        let filter = self
            .filter
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        PacketCaptureStatus {
            mode: self.mode(),
            limit: self.limit.load(Ordering::Acquire),
            len,
            next_id: self.next_id.load(Ordering::Acquire),
            filter,
        }
    }

    pub fn list(&self) -> Vec<CapturedPacket> {
        self.packets
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    pub fn get(&self, id: u64) -> Option<CapturedPacket> {
        self.packets
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .find(|packet| packet.summary.id == id)
            .cloned()
    }

    pub fn capture(
        &self,
        direction: PacketDirection,
        data: &[u8],
        change: PacketChange,
        final_len: Option<usize>,
    ) {
        let mode = self.mode();
        if mode == PacketCaptureMode::Off {
            return;
        }

        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        let summary = summarize_packet(id, direction, data, change, final_len);
        let filter = self
            .filter
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        if !filter.matches(&summary) {
            return;
        }

        let raw = if mode == PacketCaptureMode::Raw && data.len() <= self.max_raw_packet_size {
            Some(data.to_vec())
        } else {
            None
        };
        let mut packets = self
            .packets
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        packets.push_back(CapturedPacket { summary, raw });
        let limit = self.limit.load(Ordering::Acquire);
        while packets.len() > limit {
            packets.pop_front();
        }
    }

    fn trim_to_limit(&self, limit: usize) {
        let mut packets = self
            .packets
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while packets.len() > limit {
            packets.pop_front();
        }
    }
}

impl Default for CaptureBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_buffer_filters_bounds_and_exposes_raw_packets() {
        let capture = CaptureBuffer::with_limits(2, 4, 16);
        capture.set_filter(PacketCaptureFilter {
            direction: Some(PacketDirection::Recv),
            ..PacketCaptureFilter::empty()
        });
        capture.set_mode(PacketCaptureMode::Raw);

        capture.capture(
            PacketDirection::Send,
            b"filtered",
            PacketChange::Unchanged,
            None,
        );
        for raw in [b"first".as_slice(), b"second", b"third"] {
            capture.capture(PacketDirection::Recv, raw, PacketChange::Unchanged, None);
        }

        let packets = capture.list();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].raw.as_deref(), Some(b"second".as_slice()));
        assert_eq!(packets[1].raw.as_deref(), Some(b"third".as_slice()));
        assert!(packets[0].summary.id < packets[1].summary.id);
        assert_eq!(packets[0].summary.change, PacketChange::DecodeFailed);
        assert!(capture.get(packets[1].summary.id).is_some());
    }

    #[test]
    fn capture_buffer_limit_and_clear_operations_are_local() {
        let capture = CaptureBuffer::with_limits(3, 4, 4);
        assert_eq!(capture.set_limit(0), 1);
        assert_eq!(capture.set_limit(99), 4);
        capture.set_mode(PacketCaptureMode::Summary);
        capture.capture(PacketDirection::Recv, b"bad", PacketChange::Unchanged, None);
        assert_eq!(capture.status().len, 1);
        assert!(capture.list()[0].raw.is_none());

        capture.set_filter(PacketCaptureFilter {
            app_id: Some(480),
            ..PacketCaptureFilter::empty()
        });
        capture.clear();
        capture.clear_filter();
        let status = capture.status();
        assert_eq!(status.len, 0);
        assert_eq!(status.filter, PacketCaptureFilter::empty());
    }
}
