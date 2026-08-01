#![forbid(unsafe_code)]

#[cfg(debug_assertions)]
use vapor_forge_packet_capture::CaptureBuffer;
#[cfg(debug_assertions)]
pub use vapor_forge_packet_capture::{PacketCaptureFilter, PacketCaptureMode};
use vapor_forge_packet_capture::{PacketChange, PacketDirection};

#[cfg(debug_assertions)]
static CAPTURE: CaptureBuffer = CaptureBuffer::new();

#[cfg(debug_assertions)]
pub fn set_mode(mode: PacketCaptureMode) {
    CAPTURE.set_mode(mode);
}

#[cfg(debug_assertions)]
pub fn set_filter(filter: PacketCaptureFilter) {
    CAPTURE.set_filter(filter);
}

#[cfg(debug_assertions)]
pub fn clear_filter() {
    CAPTURE.clear_filter();
}

#[cfg(debug_assertions)]
pub fn set_limit(limit: usize) -> usize {
    CAPTURE.set_limit(limit)
}

#[cfg(debug_assertions)]
pub fn clear() {
    CAPTURE.clear();
}

#[cfg(debug_assertions)]
pub fn status() -> vapor_forge_packet_capture::PacketCaptureStatus {
    CAPTURE.status()
}

#[cfg(debug_assertions)]
pub fn list() -> Vec<vapor_forge_packet_capture::CapturedPacket> {
    CAPTURE.list()
}

#[cfg(debug_assertions)]
pub fn get(id: u64) -> Option<vapor_forge_packet_capture::CapturedPacket> {
    CAPTURE.get(id)
}

#[cfg(debug_assertions)]
pub fn capture(
    direction: PacketDirection,
    data: &[u8],
    change: PacketChange,
    final_len: Option<usize>,
) {
    CAPTURE.capture(direction, data, change, final_len);
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
