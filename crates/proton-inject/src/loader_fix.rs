// Duplicate-module loader fix.
//
// A third-party loader registers a second USER32.dll loader entry whose
// DllBase is a synthetic stub but whose EntryPoint is the real user32 DllMain.
// Wine then runs DllMain(DLL_THREAD_DETACH) twice for every exiting thread and
// win32u's thread_detach double-frees. Setting LDR_NO_DLL_CALLS on the duplicate
// entry, what LdrDisableThreadCalloutsForDll does, makes ntdll skip it.
//
// Runs on PE threads from the LdrLoadDll hook, so the TEB is available. Memory
// is only read through process_vm_readv: an unmapped page yields an error
// instead of faulting the game.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

use crate::loader::log;

pub const ENV_LOADER_FIX: &str = "VAPOR_FORGE_LOADER_FIX";

// Wine's winternl.h values, not the Windows ones (0x40 / 0x80000000).
const LDR_NO_DLL_CALLS: u32 = 0x0004_0000;
const LDR_PROCESS_ATTACHED: u32 = 0x0008_0000;

const TEB_SELF: usize = 0x30;
const TEB_PEB: usize = 0x60;
const PEB_LDR_DATA: usize = 0x18;
// PEB_LDR_DATA list heads and the matching LDR_DATA_TABLE_ENTRY link offsets.
const LISTS: [(&str, usize, usize); 3] = [
    ("load", 0x10, 0x00),
    ("memory", 0x20, 0x10),
    ("init", 0x30, 0x20),
];
const ENTRY_DLL_BASE: usize = 0x30;
const ENTRY_ENTRY_POINT: usize = 0x38;
const ENTRY_BASE_NAME: usize = 0x58;
const ENTRY_FLAGS: usize = 0x68;
const MAX_LIST_LEN: usize = 2048;
const SCAN_CHUNK: usize = 1 << 20;
const SCAN_MAX_REGION: usize = 256 << 20;
const SCAN_INTERVAL_MS: u64 = 2000;

static PATCHED_ENTRY: AtomicUsize = AtomicUsize::new(0);
static ANNOUNCED: AtomicBool = AtomicBool::new(false);
static LAST_SCAN_MS: AtomicU64 = AtomicU64::new(0);

pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os(ENV_LOADER_FIX).is_some_and(|v| !v.is_empty()))
}

/// Called after every successful LdrLoadDll on the loading PE thread.
pub fn on_module_loaded() {
    if !enabled() {
        return;
    }
    if !ANNOUNCED.swap(true, Ordering::AcqRel) {
        log("loader fix armed (duplicate USER32 entry)");
    }
    let patched = PATCHED_ENTRY.load(Ordering::Acquire);
    if patched != 0 {
        if let Some(flags) = read::<u32>(patched + ENTRY_FLAGS) {
            if flags & LDR_NO_DLL_CALLS == 0 {
                log("loader fix: flag cleared, re-applying");
                PATCHED_ENTRY.store(0, Ordering::Release);
            } else {
                return;
            }
        }
    }
    try_apply();
}

#[derive(Clone, Copy)]
struct User32Entry {
    entry: usize,
    dll_base: usize,
    entry_point: usize,
    flags: u32,
    lists: [bool; 3],
}

fn try_apply() {
    let Some(real_base) = real_user32_base() else {
        return;
    };
    let mut found: Vec<User32Entry> = Vec::new();
    if let Some(ldr) = loader_data() {
        for (index, (_, head_off, link_off)) in LISTS.iter().enumerate() {
            walk_list(ldr + head_off, *link_off, index, &mut found);
        }
    }
    let Some(real) = found.iter().find(|e| e.dll_base == real_base).copied() else {
        return;
    };
    let duplicates: Vec<User32Entry> = found
        .iter()
        .filter(|e| e.entry != real.entry && e.dll_base != real_base)
        .copied()
        .collect();
    for dup in &duplicates {
        log(&format!(
            "loader fix: USER32 entry {:#x} DllBase={:#x} EntryPoint={:#x} Flags={:#x} lists={}{}{}",
            dup.entry,
            dup.dll_base,
            dup.entry_point,
            dup.flags,
            if dup.lists[0] { "load " } else { "" },
            if dup.lists[1] { "memory " } else { "" },
            if dup.lists[2] { "init" } else { "" }
        ));
    }
    if let Some(dup) = duplicates
        .iter()
        .find(|d| d.entry_point == real.entry_point)
    {
        patch(dup.entry, "loader list");
        return;
    }
    // Not linked into any PEB list: look for the entry by its DllBase in
    // writable memory instead. Throttled, the scan touches every small heap
    // region.
    let now = now_ms();
    if now.saturating_sub(LAST_SCAN_MS.load(Ordering::Acquire)) < SCAN_INTERVAL_MS {
        return;
    }
    LAST_SCAN_MS.store(now, Ordering::Release);
    if let Some(entry) = scan_for_duplicate(real_base, real.entry_point) {
        patch(entry, "memory scan");
    }
}

fn patch(entry: usize, how: &str) {
    let Some(flags) = read::<u32>(entry + ENTRY_FLAGS) else {
        return;
    };
    if flags & LDR_NO_DLL_CALLS != 0 {
        PATCHED_ENTRY.store(entry, Ordering::Release);
        return;
    }
    let updated = flags | LDR_NO_DLL_CALLS;
    if write(entry + ENTRY_FLAGS, &updated) && read::<u32>(entry + ENTRY_FLAGS) == Some(updated) {
        PATCHED_ENTRY.store(entry, Ordering::Release);
        log(&format!(
            "loader fix: LDR_NO_DLL_CALLS set on {:#x} via {how}, Flags {:#x} -> {:#x}{}",
            entry,
            flags,
            updated,
            if flags & LDR_PROCESS_ATTACHED == 0 {
                " (entry not marked process-attached)"
            } else {
                ""
            }
        ));
    } else {
        log(&format!("loader fix: write to {entry:#x} failed"));
    }
}

fn loader_data() -> Option<usize> {
    let teb: usize;
    // SAFETY: on wine x86_64 the TEB lives at the gs base and TEB.NtTib.Self is
    // at 0x30; this runs on a PE thread. A wrong value only yields an unreadable
    // address, which the process_vm_readv reads below reject.
    unsafe {
        core::arch::asm!(
            "mov {teb}, qword ptr gs:[{off}]",
            teb = out(reg) teb,
            off = const TEB_SELF,
            options(nostack, readonly, preserves_flags)
        );
    }
    if teb == 0 {
        return None;
    }
    let peb = read::<usize>(teb + TEB_PEB)?;
    let ldr = read::<usize>(peb + PEB_LDR_DATA)?;
    (ldr != 0).then_some(ldr)
}

fn walk_list(head: usize, link_off: usize, list_index: usize, found: &mut Vec<User32Entry>) {
    let mut node = match read::<usize>(head) {
        Some(n) => n,
        None => return,
    };
    let mut steps = 0;
    while node != head && node != 0 && steps < MAX_LIST_LEN {
        steps += 1;
        let entry = node.wrapping_sub(link_off);
        if name_is_user32(entry) {
            if let Some(existing) = found.iter_mut().find(|e| e.entry == entry) {
                existing.lists[list_index] = true;
            } else if let (Some(dll_base), Some(entry_point), Some(flags)) = (
                read::<usize>(entry + ENTRY_DLL_BASE),
                read::<usize>(entry + ENTRY_ENTRY_POINT),
                read::<u32>(entry + ENTRY_FLAGS),
            ) {
                let mut lists = [false; 3];
                lists[list_index] = true;
                found.push(User32Entry {
                    entry,
                    dll_base,
                    entry_point,
                    flags,
                    lists,
                });
            }
        }
        node = match read::<usize>(node) {
            Some(n) => n,
            None => return,
        };
    }
}

fn name_is_user32(entry: usize) -> bool {
    let len = match read::<u16>(entry + ENTRY_BASE_NAME) {
        Some(l) => l as usize,
        None => return false,
    };
    let buffer = match read::<usize>(entry + ENTRY_BASE_NAME + 8) {
        Some(b) => b,
        None => return false,
    };
    const WANT: &[u8] = b"user32.dll";
    if len != WANT.len() * 2 || buffer == 0 {
        return false;
    }
    let mut name = [0u16; 10];
    if !read_into(buffer, &mut name) {
        return false;
    }
    utf16_eq_ignore_ascii_case(&name, WANT)
}

fn utf16_eq_ignore_ascii_case(name: &[u16], want: &[u8]) -> bool {
    name.len() == want.len()
        && name
            .iter()
            .zip(want)
            .all(|(&c, &w)| c < 128 && (c as u8).eq_ignore_ascii_case(&w))
}

/// Image base of the real user32.dll: its file-backed header mapping.
fn real_user32_base() -> Option<usize> {
    crate::maps::parse_self_maps()
        .into_iter()
        .filter(|m| m.offset == 0 && m.perms.starts_with('r'))
        .find(|m| {
            m.path
                .rsplit('/')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("user32.dll"))
        })
        .map(|m| m.base)
}

/// Find the duplicate entry by scanning writable anonymous memory for an
/// LDR_DATA_TABLE_ENTRY whose DllBase is one of the loader's high rwx stubs.
fn scan_for_duplicate(real_base: usize, real_entry_point: usize) -> Option<usize> {
    let maps = crate::maps::parse_self_maps();
    let stubs: Vec<usize> = maps
        .iter()
        .filter(|m| {
            m.path.is_empty()
                && m.perms.starts_with("rwx")
                && m.end - m.base >= 0x10_0000
                && m.base >= 0x7f00_0000_0000
        })
        .map(|m| m.base)
        .collect();
    if stubs.is_empty() {
        return None;
    }
    let mut buf = vec![0u8; SCAN_CHUNK];
    for region in maps
        .iter()
        .filter(|m| (m.path.is_empty() || m.path == "[heap]") && m.perms.starts_with("rw"))
        .filter(|m| m.end - m.base <= SCAN_MAX_REGION)
    {
        let mut off = region.base;
        while off < region.end {
            let len = (region.end - off).min(SCAN_CHUNK);
            if !read_into(off, &mut buf[..len]) {
                break;
            }
            for &stub in &stubs {
                let pat = stub.to_ne_bytes();
                let mut pos = 0;
                while let Some(hit) = find(&buf[pos..len], &pat) {
                    let at = off + pos + hit;
                    pos += hit + 8;
                    if at < ENTRY_DLL_BASE || (at - ENTRY_DLL_BASE) & 7 != 0 {
                        continue;
                    }
                    let entry = at - ENTRY_DLL_BASE;
                    if read::<usize>(entry + ENTRY_DLL_BASE) != Some(stub)
                        || read::<usize>(entry + ENTRY_ENTRY_POINT) != Some(real_entry_point)
                        || stub == real_base
                        || !name_is_user32(entry)
                    {
                        continue;
                    }
                    log(&format!(
                        "loader fix: USER32 entry {entry:#x} found by scan, DllBase={stub:#x}"
                    ));
                    return Some(entry);
                }
            }
            off += len.saturating_sub(8).max(1);
        }
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read<T: Copy>(addr: usize) -> Option<T> {
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    let len = core::mem::size_of::<T>();
    let local = libc::iovec {
        iov_base: value.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: both iovecs describe valid lengths; the kernel copies from our own
    // address space and fails cleanly on an unmapped remote page.
    let copied = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    if copied == len as isize {
        // SAFETY: the kernel wrote exactly `len` bytes into `value`.
        Some(unsafe { value.assume_init() })
    } else {
        None
    }
}

fn read_into<T: Copy>(addr: usize, out: &mut [T]) -> bool {
    let len = core::mem::size_of_val(out);
    if len == 0 {
        return true;
    }
    let local = libc::iovec {
        iov_base: out.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: `out` is a live buffer of `len` bytes; unmapped remote pages fail.
    let copied = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    copied == len as isize
}

fn write<T: Copy>(addr: usize, value: &T) -> bool {
    let len = core::mem::size_of::<T>();
    let local = libc::iovec {
        iov_base: (value as *const T).cast_mut().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: writes to our own address space; a read-only or unmapped target
    // fails instead of faulting.
    let copied = unsafe { libc::process_vm_writev(libc::getpid(), &local, 1, &remote, 1, 0) };
    copied == len as isize
}

fn now_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_name_compare_ignores_ascii_case() {
        let name: Vec<u16> = "USER32.dll".encode_utf16().collect();
        assert!(utf16_eq_ignore_ascii_case(&name, b"user32.dll"));
        let other: Vec<u16> = "user33.dll".encode_utf16().collect();
        assert!(!utf16_eq_ignore_ascii_case(&other, b"user32.dll"));
        assert!(!utf16_eq_ignore_ascii_case(&name[..5], b"user32.dll"));
    }

    #[test]
    fn reads_and_writes_own_memory() {
        let mut cell = 0x1234_5678u32;
        let addr = &mut cell as *mut u32 as usize;
        assert_eq!(read::<u32>(addr), Some(0x1234_5678));
        assert!(write(addr, &0x9abc_def0u32));
        assert_eq!(cell, 0x9abc_def0);
        assert_eq!(read::<u32>(8), None);
    }

    #[test]
    fn find_locates_needle() {
        assert_eq!(find(b"abcdef", b"cd"), Some(2));
        assert_eq!(find(b"abcdef", b"xy"), None);
    }
}
