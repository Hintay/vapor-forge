#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::c_char;
use std::sync::atomic::{AtomicU8, Ordering};

use tracing::span;
use tracing::{Event, Metadata, Subscriber};

const PREFIX: &[u8] = b"[vapor-forge] ";
const NEWLINE: &[u8] = b"\n";

// Level encoding: ERROR=1 WARN=2 INFO=3 DEBUG=4 TRACE=5 (matches tracing::Level numeric order)
const LEVEL_ERROR: u8 = 1;
const LEVEL_WARN: u8 = 2;
const LEVEL_INFO: u8 = 3;
const LEVEL_DEBUG: u8 = 4;
const LEVEL_TRACE: u8 = 5;

/// Shared dynamic log level. Checked on every event so it can be changed at
/// runtime (e.g. via the debug API).
static DYNAMIC_LEVEL: AtomicU8 = AtomicU8::new(LEVEL_INFO);

fn level_to_u8(level: &tracing::Level) -> u8 {
    match *level {
        tracing::Level::ERROR => LEVEL_ERROR,
        tracing::Level::WARN => LEVEL_WARN,
        tracing::Level::INFO => LEVEL_INFO,
        tracing::Level::DEBUG => LEVEL_DEBUG,
        tracing::Level::TRACE => LEVEL_TRACE,
    }
}

// ---------------------------------------------------------------------------
// Minimal tracing subscriber that writes to stderr via libc::write.
// Safe for LD_AUDIT context (no complex allocations in the hot path).
// ---------------------------------------------------------------------------

struct StderrSubscriber;

impl Subscriber for StderrSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        level_to_u8(metadata.level()) <= DYNAMIC_LEVEL.load(Ordering::Relaxed)
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        use std::fmt::Write;
        let mut buf = String::with_capacity(256);
        let _ = write!(buf, "[vapor-forge][{}] ", event.metadata().level());

        // Visit the event fields to extract the message
        struct Visitor<'a>(&'a mut String);
        impl<'a> tracing::field::Visit for Visitor<'a> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    let _ = write!(self.0, "{:?}", value);
                } else {
                    let _ = write!(self.0, " {}={:?}", field.name(), value);
                }
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    let _ = write!(self.0, "{}", value);
                } else {
                    let _ = write!(self.0, " {}={}", field.name(), value);
                }
            }
            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                let _ = write!(self.0, " {}={}", field.name(), value);
            }
            fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                let _ = write!(self.0, " {}={}", field.name(), value);
            }
            fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                let _ = write!(self.0, " {}={}", field.name(), value);
            }
        }
        event.record(&mut Visitor(&mut buf));
        buf.push('\n');

        // Write to stderr via libc::write (safe for LD_AUDIT context)
        // SAFETY: libc::write is called with a valid pointer and byte length from
        // an immutable Rust slice. fd=2 is stderr; failures are intentionally ignored.
        unsafe {
            libc::write(2, buf.as_ptr() as *const _, buf.len());
        }
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initialize the global tracing subscriber with the given level filter.
///
/// Level is one of: "error", "warn", "info", "debug", "trace".
/// Unknown values default to "info". Safe to call multiple times; only the
/// first call sets the global subscriber (subsequent calls are silently ignored).
pub fn init(level: &str) {
    set_level(level);
    let subscriber = StderrSubscriber;
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Change the active log level at runtime. Returns the name of the level
/// that was actually set (normalizes unknown values to "info").
pub fn set_level(level: &str) -> &'static str {
    let (encoded, name) = match level {
        "error" => (LEVEL_ERROR, "error"),
        "warn" => (LEVEL_WARN, "warn"),
        "debug" => (LEVEL_DEBUG, "debug"),
        "trace" => (LEVEL_TRACE, "trace"),
        "info" => (LEVEL_INFO, "info"),
        _ => (LEVEL_INFO, "info"),
    };
    DYNAMIC_LEVEL.store(encoded, Ordering::Relaxed);
    name
}

/// Return the name of the current dynamic log level.
pub fn current_level_name() -> &'static str {
    match DYNAMIC_LEVEL.load(Ordering::Relaxed) {
        LEVEL_ERROR => "error",
        LEVEL_WARN => "warn",
        LEVEL_DEBUG => "debug",
        LEVEL_TRACE => "trace",
        _ => "info",
    }
}

// ---------------------------------------------------------------------------
// Early-boot logging (before tracing is initialized)
// ---------------------------------------------------------------------------

/// Log a simple message to stderr before tracing is initialized.
pub fn log_early(message: &str) {
    write_stderr(PREFIX);
    write_stderr(message.as_bytes());
    write_stderr(NEWLINE);
}

/// Logs a bounded C string to stderr.
///
/// Used by audit-loader's la_objsearch/la_objopen for logging C strings from
/// the dynamic loader. These are called before tracing is initialized.
///
/// # Safety
///
/// If `value` is non-null, it must point to a readable NUL-terminated C string.
/// The implementation caps reads to a fixed maximum length, but the pointer
/// still has to be valid for byte reads up to the first NUL byte or that cap.
pub unsafe fn log_cstr(prefix: &str, value: *const c_char) {
    write_stderr(PREFIX);
    write_stderr(prefix.as_bytes());
    write_stderr(b": ");

    if value.is_null() {
        write_stderr(b"<null>");
    } else {
        // SAFETY: The caller upholds that a non-null value points to readable
        // C string memory. write_cstr_lossy caps the maximum number of bytes.
        unsafe { write_cstr_lossy(value, 4096) };
    }

    write_stderr(NEWLINE);
}

fn write_stderr(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }

    // SAFETY: libc::write is called with a valid pointer and byte length from an
    // immutable Rust slice. fd=2 is stderr; failures are intentionally ignored.
    unsafe {
        let _ = libc::write(2, bytes.as_ptr().cast(), bytes.len());
    }
}

unsafe fn write_cstr_lossy(ptr: *const c_char, max_len: usize) {
    let mut len = 0usize;
    while len < max_len {
        // SAFETY: Caller promises ptr points to a C string. Access is bounded by
        // max_len to keep audit logging conservative.
        let byte = unsafe { *ptr.add(len).cast::<u8>() };
        if byte == 0 {
            break;
        }
        len += 1;
    }

    if len > 0 {
        // SAFETY: The range [ptr, ptr + len) was just read byte-by-byte above.
        let bytes = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) };
        write_stderr(bytes);
    }

    if len == max_len {
        write_stderr(b"...");
    }
}
