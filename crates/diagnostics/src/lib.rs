#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::c_char;

const PREFIX: &[u8] = b"[steam-runtime-rs] ";
const NEWLINE: &[u8] = b"\n";

pub fn log_message(message: &str) {
    write_stderr(PREFIX);
    write_stderr(message.as_bytes());
    write_stderr(NEWLINE);
}

/// Logs a bounded C string to stderr.
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
        // SAFETY: The dynamic loader provides NUL-terminated C strings for audit
        // callback names. We cap output length to avoid walking unbounded memory
        // if a future caller violates that contract.
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
