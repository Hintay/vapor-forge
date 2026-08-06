use core::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::loader;

const LA_FLG_BINDTO: u32 = 0x01;
const LA_FLG_BINDFROM: u32 = 0x02;
const FUTEX_WAIT_PRIVATE: libc::c_int = 128;
const FUTEX_WAKE_PRIVATE: libc::c_int = 129;

static MMAP_ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static MMAP64_ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static EVENT_SEQUENCE: AtomicU32 = AtomicU32::new(0);
static WORKER_ARMED: AtomicBool = AtomicBool::new(false);

type MmapFn = unsafe extern "C" fn(
    *mut c_void,
    usize,
    libc::c_int,
    libc::c_int,
    libc::c_int,
    libc::off64_t,
) -> *mut c_void;

#[repr(C)]
pub struct Elf64Symbol {
    name: u32,
    info: u8,
    other: u8,
    section_index: u16,
    value: u64,
    size: u64,
}

#[repr(C)]
struct LinkMapPrefix {
    address: usize,
    name: *const c_char,
    dynamic: *mut c_void,
    next: *mut c_void,
    previous: *mut c_void,
}

/// # Safety
/// `map` must point to the link_map supplied by glibc to la_objopen.
pub unsafe fn object_flags(map: *mut c_void) -> u32 {
    if map.is_null() {
        return 0;
    }
    // SAFETY: the caller forwards glibc's live link_map pointer.
    let name = unsafe { (*map.cast::<LinkMapPrefix>()).name };
    if name.is_null() {
        return 0;
    }
    // SAFETY: l_name is a NUL-terminated string owned by the dynamic loader.
    let name = unsafe { std::ffi::CStr::from_ptr(name) }.to_bytes();
    let basename = name.rsplit(|byte| *byte == b'/').next().unwrap_or(name);

    if basename == b"libc.so.6" {
        return LA_FLG_BINDTO;
    }
    if name.is_empty() || contains_ascii_case_insensitive(name, b"wine") || basename == b"ntdll.so"
    {
        return LA_FLG_BINDFROM;
    }
    0
}

/// # Safety
/// `symbol` and `symbol_name` must follow glibc's la_symbind64 contract.
pub unsafe fn bind_symbol(symbol: *const Elf64Symbol, symbol_name: *const c_char) -> usize {
    if symbol.is_null() || symbol_name.is_null() {
        return 0;
    }
    // SAFETY: the pointers remain valid during la_symbind64.
    let value = unsafe { (*symbol).value as usize };
    // SAFETY: glibc supplies a NUL-terminated symbol name.
    let name = unsafe { std::ffi::CStr::from_ptr(symbol_name) }.to_bytes();
    match name {
        b"mmap" => {
            MMAP_ORIGINAL.store(value, Ordering::Release);
            mmap_hook as *const () as usize
        }
        b"mmap64" => {
            MMAP64_ORIGINAL.store(value, Ordering::Release);
            mmap64_hook as *const () as usize
        }
        _ => value,
    }
}

pub fn spawn_install_worker() {
    if WORKER_ARMED.swap(true, Ordering::AcqRel) {
        return;
    }
    if std::thread::Builder::new()
        .name("vapor-forge-proton-inject-map".into())
        .spawn(install_worker)
        .is_err()
    {
        WORKER_ARMED.store(false, Ordering::Release);
        loader::log("failed to start PE mapping worker");
    }
}

fn install_worker() {
    let mut observed = EVENT_SEQUENCE.load(Ordering::Acquire);
    loop {
        if loader::install_trigger() {
            WORKER_ARMED.store(false, Ordering::Release);
            return;
        }

        let current = EVENT_SEQUENCE.load(Ordering::Acquire);
        if current != observed {
            observed = current;
            continue;
        }

        // SAFETY: EVENT_SEQUENCE has a stable process-lifetime address and the
        // expected value closes the check-to-wait race.
        let _ = unsafe {
            libc::syscall(
                libc::SYS_futex,
                EVENT_SEQUENCE.as_ptr(),
                FUTEX_WAIT_PRIVATE,
                current,
                std::ptr::null::<libc::timespec>(),
            )
        };
    }
}

unsafe extern "C" fn mmap_hook(
    address: *mut c_void,
    length: usize,
    protection: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off64_t,
) -> *mut c_void {
    // SAFETY: la_symbind64 recorded the matching libc function before returning
    // this hook address to the dynamic loader.
    let result = unsafe {
        call_mmap(
            &MMAP_ORIGINAL,
            address,
            length,
            protection,
            flags,
            fd,
            offset,
        )
    };
    observe_mapping(result, fd);
    result
}

unsafe extern "C" fn mmap64_hook(
    address: *mut c_void,
    length: usize,
    protection: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off64_t,
) -> *mut c_void {
    // SAFETY: la_symbind64 recorded the matching libc function before returning
    // this hook address to the dynamic loader.
    let result = unsafe {
        call_mmap(
            &MMAP64_ORIGINAL,
            address,
            length,
            protection,
            flags,
            fd,
            offset,
        )
    };
    observe_mapping(result, fd);
    result
}

#[allow(clippy::too_many_arguments)]
unsafe fn call_mmap(
    original: &AtomicUsize,
    address: *mut c_void,
    length: usize,
    protection: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off64_t,
) -> *mut c_void {
    let address_value = original.load(Ordering::Acquire);
    if address_value == 0 {
        return libc::MAP_FAILED;
    }
    // SAFETY: la_symbind64 stored the address of the matching mmap ABI.
    let function: MmapFn = unsafe { std::mem::transmute(address_value) };
    // SAFETY: the hook forwards the arguments from the original call unchanged.
    unsafe { function(address, length, protection, flags, fd, offset) }
}

fn observe_mapping(result: *mut c_void, fd: libc::c_int) {
    if !WORKER_ARMED.load(Ordering::Acquire) || result == libc::MAP_FAILED || fd < 0 {
        return;
    }
    if fd_targets_pe_ntdll(fd) {
        EVENT_SEQUENCE.fetch_add(1, Ordering::Release);
        // SAFETY: waking a futex requires only the stable atomic address.
        let _ = unsafe {
            libc::syscall(
                libc::SYS_futex,
                EVENT_SEQUENCE.as_ptr(),
                FUTEX_WAKE_PRIVATE,
                1,
            )
        };
    }
}

fn fd_targets_pe_ntdll(fd: libc::c_int) -> bool {
    let mut descriptor_buffer = [0u8; 32];
    let Some(path_length) = descriptor_path(fd, &mut descriptor_buffer) else {
        return false;
    };
    let mut target = [0u8; 512];
    // SAFETY: both buffers are writable for their declared lengths and the
    // descriptor path is NUL-terminated.
    let length = unsafe {
        libc::syscall(
            libc::SYS_readlinkat,
            libc::AT_FDCWD,
            descriptor_buffer.as_ptr().cast::<c_char>(),
            target.as_mut_ptr(),
            target.len(),
        )
    };
    if length <= 0 {
        return false;
    }
    let mut path = &target[..length as usize];
    if let Some(without_marker) = path.strip_suffix(b" (deleted)") {
        path = without_marker;
    }
    path_length != 0 && ends_with_ascii_case_insensitive(path, b"/ntdll.dll")
}

fn descriptor_path(fd: libc::c_int, output: &mut [u8; 32]) -> Option<usize> {
    const PREFIX: &[u8] = b"/proc/self/fd/";
    output[..PREFIX.len()].copy_from_slice(PREFIX);

    let mut digits = [0u8; 10];
    let mut value = fd as u32;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let length = PREFIX.len() + count;
    for index in 0..count {
        output[PREFIX.len() + index] = digits[count - index - 1];
    }
    output[length] = 0;
    Some(length)
}

fn contains_ascii_case_insensitive(value: &[u8], needle: &[u8]) -> bool {
    value.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn ends_with_ascii_case_insensitive(value: &[u8], suffix: &[u8]) -> bool {
    value.len() >= suffix.len()
        && value[value.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_descriptor_path() {
        let mut path = [0u8; 32];
        let length = descriptor_path(123, &mut path).unwrap();
        assert_eq!(&path[..=length], b"/proc/self/fd/123\0");
    }

    #[test]
    fn matches_ntdll_mapping_paths_case_insensitively() {
        assert!(ends_with_ascii_case_insensitive(
            b"/compat/files/lib64/wine/x86_64-windows/ntdll.dll",
            b"/ntdll.dll"
        ));
        assert!(ends_with_ascii_case_insensitive(
            b"/compat/NTDLL.DLL",
            b"/ntdll.dll"
        ));
        assert!(!ends_with_ascii_case_insensitive(
            b"/compat/ntdll.so",
            b"/ntdll.dll"
        ));
    }
}
