use core::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::loader;

const LA_FLG_BINDTO: u32 = 0x01;
const LA_FLG_BINDFROM: u32 = 0x02;
static MMAP_ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static MMAP64_ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static MPROTECT_ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static OBSERVER_ARMED: AtomicBool = AtomicBool::new(false);
static NTDLL_MAPPED: AtomicBool = AtomicBool::new(false);
static NTDLL_EXECUTABLE_MAPPING_SEEN: AtomicBool = AtomicBool::new(false);

type MmapFn = unsafe extern "C" fn(
    *mut c_void,
    usize,
    libc::c_int,
    libc::c_int,
    libc::c_int,
    libc::off64_t,
) -> *mut c_void;

type MprotectFn = unsafe extern "C" fn(*mut c_void, usize, libc::c_int) -> libc::c_int;

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
        b"mprotect" => {
            MPROTECT_ORIGINAL.store(value, Ordering::Release);
            mprotect_hook as *const () as usize
        }
        _ => value,
    }
}

pub fn arm_observer() {
    NTDLL_MAPPED.store(false, Ordering::Release);
    NTDLL_EXECUTABLE_MAPPING_SEEN.store(false, Ordering::Release);
    OBSERVER_ARMED.store(true, Ordering::Release);
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
    observe_mapping(result, length, protection, fd, offset);
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
    observe_mapping(result, length, protection, fd, offset);
    result
}

unsafe extern "C" fn mprotect_hook(
    address: *mut c_void,
    length: usize,
    protection: libc::c_int,
) -> libc::c_int {
    let address_value = MPROTECT_ORIGINAL.load(Ordering::Acquire);
    if address_value == 0 {
        return -1;
    }
    // SAFETY: la_symbind64 stored the address of libc's matching mprotect ABI.
    let function: MprotectFn = unsafe { std::mem::transmute(address_value) };
    // SAFETY: the hook forwards the arguments from the original call unchanged.
    let result = unsafe { function(address, length, protection) };
    if result == 0
        && protection & libc::PROT_EXEC != 0
        && OBSERVER_ARMED.load(Ordering::Acquire)
        && NTDLL_MAPPED.load(Ordering::Acquire)
        && loader::install_trigger()
    {
        OBSERVER_ARMED.store(false, Ordering::Release);
    }
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

fn observe_mapping(
    result: *mut c_void,
    length: usize,
    protection: libc::c_int,
    fd: libc::c_int,
    offset: libc::off64_t,
) {
    if !OBSERVER_ARMED.load(Ordering::Acquire) || result == libc::MAP_FAILED || fd < 0 || offset < 0
    {
        return;
    }
    if !fd_targets_pe_ntdll(fd) {
        return;
    }
    if protection & libc::PROT_EXEC != 0 {
        NTDLL_EXECUTABLE_MAPPING_SEEN.store(true, Ordering::Release);
    }
    if mapping_reaches_image_end(fd, length, offset as u64) {
        NTDLL_MAPPED.store(true, Ordering::Release);
        if NTDLL_EXECUTABLE_MAPPING_SEEN.load(Ordering::Acquire) && loader::install_trigger() {
            OBSERVER_ARMED.store(false, Ordering::Release);
        }
    }
}

fn mapping_reaches_image_end(fd: libc::c_int, length: usize, offset: u64) -> bool {
    let Some(image_size) = pe_image_size(fd) else {
        return false;
    };
    offset
        .checked_add(length as u64)
        .is_some_and(|end| end >= image_size as u64)
}

fn pe_image_size(fd: libc::c_int) -> Option<u32> {
    let mut header = [0u8; 4096];
    // SAFETY: header is writable for its declared length and pread does not
    // modify the descriptor offset.
    let read = unsafe { libc::pread(fd, header.as_mut_ptr().cast::<c_void>(), header.len(), 0) };
    if read < 0x40 {
        return None;
    }
    parse_pe_image_size(&header[..read as usize])
}

fn parse_pe_image_size(header: &[u8]) -> Option<u32> {
    if read_u16(header, 0)? != 0x5a4d {
        return None;
    }
    let pe_offset = read_u32(header, 0x3c)? as usize;
    if read_u32(header, pe_offset)? != 0x0000_4550 {
        return None;
    }
    let optional_header = pe_offset.checked_add(24)?;
    match read_u16(header, optional_header)? {
        0x10b | 0x20b => read_u32(header, optional_header.checked_add(56)?),
        _ => None,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
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

    #[test]
    fn reads_pe_image_size() {
        let mut header = [0u8; 256];
        header[0..2].copy_from_slice(&0x5a4d_u16.to_le_bytes());
        header[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        header[0x80..0x84].copy_from_slice(&0x0000_4550_u32.to_le_bytes());
        header[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        header[0xd0..0xd4].copy_from_slice(&0xb8000_u32.to_le_bytes());

        assert_eq!(parse_pe_image_size(&header), Some(0xb8000));
        assert_eq!(parse_pe_image_size(&header[..0xd2]), None);
        header[0] = 0;
        assert_eq!(parse_pe_image_size(&header), None);
    }
}
