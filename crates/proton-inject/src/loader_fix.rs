// Duplicate-module loader fix.
//
// Some third-party loaders register extra loader
// entries for modules that are already loaded: the entry's DllBase is a
// synthetic stub but its EntryPoint is the real module's DllMain. Wine then
// runs that DllMain twice for every thread attach and detach, and user32's
// second DLL_THREAD_DETACH double-frees inside win32u. Setting LDR_NO_DLL_CALLS
// on every such duplicate, what LdrDisableThreadCalloutsForDll does, makes
// ntdll skip its callouts while leaving the loader's own bookkeeping alone.
//
// Runs on PE threads from the LdrLoadDll hook, so the TEB is available. Memory
// is only read through process_vm_readv: an unmapped page yields an error
// instead of faulting the game.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

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
const MAX_NAME_CHARS: usize = 64;
const SCAN_CHUNK: usize = 1 << 20;
const SCAN_MAX_REGION: usize = 256 << 20;
const SCAN_INTERVAL_MS: u64 = 2000;

static ANNOUNCED: AtomicBool = AtomicBool::new(false);
static LAST_SCAN_MS: AtomicU64 = AtomicU64::new(0);
// Entries already patched (re-verified on later calls) and duplicates already
// reported (so the log stays quiet once the picture is known).
static PATCHED: Mutex<Vec<usize>> = Mutex::new(Vec::new());
static REPORTED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

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
        log("loader fix armed (duplicate module entries)");
    }
    // A duplicate whose flag was cleared again is treated as new.
    if let Ok(mut patched) = PATCHED.lock() {
        patched.retain(|&entry| {
            read::<u32>(entry + ENTRY_FLAGS).is_some_and(|flags| flags & LDR_NO_DLL_CALLS != 0)
        });
    }
    try_apply();
}

/// One LDR_DATA_TABLE_ENTRY as seen in the PEB lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModuleEntry {
    pub entry: usize,
    pub dll_base: usize,
    pub entry_point: usize,
    pub flags: u32,
    /// Lower-cased BaseDllName.
    pub name: String,
    pub lists: [bool; 3],
}

/// A duplicate entry and the real entry it shadows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Duplicate {
    pub entry: usize,
    pub real_entry: usize,
    /// Whether the duplicate reuses the real module's entry point, the case
    /// that produces double callouts and gets patched.
    pub shares_entry_point: bool,
}

/// Decide which entries are duplicates of a file-backed module with the same
/// name. `is_file_backed(dll_base, name)` says whether the module image at
/// `dll_base` is the real, file-mapped `name`.
pub(crate) fn find_duplicates(
    entries: &[ModuleEntry],
    is_file_backed: impl Fn(usize, &str) -> bool,
) -> Vec<Duplicate> {
    let mut out = Vec::new();
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        let same: Vec<&ModuleEntry> = entries.iter().filter(|e| e.name == name).collect();
        if same.len() < 2 {
            continue;
        }
        let Some(real) = same.iter().find(|e| is_file_backed(e.dll_base, name)) else {
            continue;
        };
        for e in same.iter().filter(|e| e.entry != real.entry) {
            // Two genuinely different modules that happen to share a base name
            // are both file-backed and keep their own entry points; skip those.
            if is_file_backed(e.dll_base, name) {
                continue;
            }
            out.push(Duplicate {
                entry: e.entry,
                real_entry: real.entry,
                shares_entry_point: e.entry_point != 0 && e.entry_point == real.entry_point,
            });
        }
    }
    out
}

fn try_apply() {
    let maps = crate::maps::parse_self_maps();
    let is_file_backed = |dll_base: usize, name: &str| {
        maps.iter().any(|m| {
            m.base <= dll_base
                && dll_base < m.end
                && m.path
                    .rsplit('/')
                    .next()
                    .is_some_and(|base| base.eq_ignore_ascii_case(name))
        })
    };

    let mut entries: Vec<ModuleEntry> = Vec::new();
    if let Some(ldr) = loader_data() {
        for (index, (_, head_off, link_off)) in LISTS.iter().enumerate() {
            walk_list(ldr + head_off, *link_off, index, &mut entries);
        }
    }
    if entries.is_empty() {
        return;
    }

    let duplicates = find_duplicates(&entries, is_file_backed);
    let mut patched_any = false;
    for dup in &duplicates {
        let Some(e) = entries.iter().find(|e| e.entry == dup.entry) else {
            continue;
        };
        report(e, dup);
        if dup.shares_entry_point && patch(e, "loader list") {
            patched_any = true;
        }
    }
    if patched_any || duplicates.iter().any(|d| d.shares_entry_point) {
        return;
    }

    // Nothing in the PEB lists: look for an entry pointing at one of the
    // loader's high anonymous rwx stubs in writable memory instead. Throttled,
    // the scan touches every small heap region.
    let now = now_ms();
    if now.saturating_sub(LAST_SCAN_MS.load(Ordering::Acquire)) < SCAN_INTERVAL_MS {
        return;
    }
    LAST_SCAN_MS.store(now, Ordering::Release);
    if let Some(e) = scan_for_duplicate(&maps, &entries, &is_file_backed) {
        let dup = Duplicate {
            entry: e.entry,
            real_entry: 0,
            shares_entry_point: true,
        };
        report(&e, &dup);
        patch(&e, "memory scan");
    }
}

fn report(e: &ModuleEntry, dup: &Duplicate) {
    let Ok(mut reported) = REPORTED.lock() else {
        return;
    };
    if reported.contains(&e.entry) {
        return;
    }
    reported.push(e.entry);
    log(&format!(
        "loader fix: duplicate {} entry {:#x} DllBase={:#x} EntryPoint={:#x} Flags={:#x} lists={}{}{} real={:#x}{}",
        e.name,
        e.entry,
        e.dll_base,
        e.entry_point,
        e.flags,
        if e.lists[0] { "load " } else { "" },
        if e.lists[1] { "memory " } else { "" },
        if e.lists[2] { "init" } else { "" },
        dup.real_entry,
        if dup.shares_entry_point {
            " (shares the real entry point)"
        } else {
            " (own entry point, left alone)"
        }
    ));
}

/// Set LDR_NO_DLL_CALLS on the entry; returns whether it is now set.
fn patch(e: &ModuleEntry, how: &str) -> bool {
    if PATCHED.lock().is_ok_and(|p| p.contains(&e.entry)) {
        return true;
    }
    let Some(flags) = read::<u32>(e.entry + ENTRY_FLAGS) else {
        return false;
    };
    if flags & LDR_NO_DLL_CALLS != 0 {
        remember_patched(e.entry);
        return true;
    }
    let updated = flags | LDR_NO_DLL_CALLS;
    if write(e.entry + ENTRY_FLAGS, &updated) && read::<u32>(e.entry + ENTRY_FLAGS) == Some(updated)
    {
        remember_patched(e.entry);
        log(&format!(
            "loader fix: LDR_NO_DLL_CALLS set on {} entry {:#x} via {how}, Flags {:#x} -> {:#x}{}",
            e.name,
            e.entry,
            flags,
            updated,
            if flags & LDR_PROCESS_ATTACHED == 0 {
                " (entry not marked process-attached)"
            } else {
                ""
            }
        ));
        true
    } else {
        log(&format!("loader fix: write to {:#x} failed", e.entry));
        false
    }
}

fn remember_patched(entry: usize) {
    if let Ok(mut patched) = PATCHED.lock() {
        if !patched.contains(&entry) {
            patched.push(entry);
        }
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

fn walk_list(head: usize, link_off: usize, list_index: usize, entries: &mut Vec<ModuleEntry>) {
    let mut node = match read::<usize>(head) {
        Some(n) => n,
        None => return,
    };
    let mut steps = 0;
    while node != head && node != 0 && steps < MAX_LIST_LEN {
        steps += 1;
        let entry = node.wrapping_sub(link_off);
        if let Some(existing) = entries.iter_mut().find(|e| e.entry == entry) {
            existing.lists[list_index] = true;
        } else if let Some(mut module) = read_entry(entry) {
            module.lists[list_index] = true;
            entries.push(module);
        }
        node = match read::<usize>(node) {
            Some(n) => n,
            None => return,
        };
    }
}

fn read_entry(entry: usize) -> Option<ModuleEntry> {
    let name = base_name(entry)?;
    Some(ModuleEntry {
        entry,
        dll_base: read::<usize>(entry + ENTRY_DLL_BASE)?,
        entry_point: read::<usize>(entry + ENTRY_ENTRY_POINT)?,
        flags: read::<u32>(entry + ENTRY_FLAGS)?,
        name,
        lists: [false; 3],
    })
}

/// Lower-cased BaseDllName of an entry, when it is a plausible module name.
fn base_name(entry: usize) -> Option<String> {
    let len = read::<u16>(entry + ENTRY_BASE_NAME)? as usize;
    let buffer = read::<usize>(entry + ENTRY_BASE_NAME + 8)?;
    if len == 0 || len % 2 != 0 || len / 2 > MAX_NAME_CHARS || buffer == 0 {
        return None;
    }
    let mut name = vec![0u16; len / 2];
    if !read_into(buffer, &mut name) {
        return None;
    }
    let text = String::from_utf16(&name).ok()?;
    if text.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(text.to_ascii_lowercase())
}

/// Find a duplicate entry by scanning writable anonymous memory for an
/// LDR_DATA_TABLE_ENTRY whose DllBase is one of the loader's high rwx stubs
/// and whose EntryPoint matches the file-backed module of the same name.
fn scan_for_duplicate(
    maps: &[crate::maps::MapEntry],
    entries: &[ModuleEntry],
    is_file_backed: &impl Fn(usize, &str) -> bool,
) -> Option<ModuleEntry> {
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
                    let Some(candidate) = read_entry(at - ENTRY_DLL_BASE) else {
                        continue;
                    };
                    if candidate.dll_base != stub || is_file_backed(stub, &candidate.name) {
                        continue;
                    }
                    let real = entries
                        .iter()
                        .find(|e| e.name == candidate.name && is_file_backed(e.dll_base, &e.name));
                    if real.is_some_and(|r| r.entry_point == candidate.entry_point) {
                        log(&format!(
                            "loader fix: {} entry {:#x} found by scan, DllBase={:#x}",
                            candidate.name, candidate.entry, stub
                        ));
                        return Some(candidate);
                    }
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

    fn module(entry: usize, dll_base: usize, entry_point: usize, name: &str) -> ModuleEntry {
        ModuleEntry {
            entry,
            dll_base,
            entry_point,
            flags: LDR_PROCESS_ATTACHED,
            name: name.to_owned(),
            lists: [true; 3],
        }
    }

    #[test]
    fn duplicate_sharing_the_entry_point_is_flagged() {
        let entries = vec![
            module(0x1000, 0x6f00_0000, 0x6f00_1000, "user32.dll"),
            module(0x2000, 0x7f00_0000, 0x6f00_1000, "user32.dll"),
            module(0x3000, 0x6e00_0000, 0x6e00_1000, "kernel32.dll"),
        ];
        let dups = find_duplicates(&entries, |base, _| {
            base == 0x6f00_0000 || base == 0x6e00_0000
        });
        assert_eq!(
            dups,
            vec![Duplicate {
                entry: 0x2000,
                real_entry: 0x1000,
                shares_entry_point: true
            }]
        );
    }

    #[test]
    fn duplicate_with_its_own_entry_point_is_reported_not_patched() {
        let entries = vec![
            module(0x1000, 0x6f00_0000, 0x6f00_1000, "ntdll.dll"),
            module(0x2000, 0x7f00_0000, 0x7f00_0100, "ntdll.dll"),
        ];
        let dups = find_duplicates(&entries, |base, _| base == 0x6f00_0000);
        assert_eq!(dups.len(), 1);
        assert!(!dups[0].shares_entry_point);
    }

    #[test]
    fn two_file_backed_modules_with_one_name_are_left_alone() {
        let entries = vec![
            module(0x1000, 0x6f00_0000, 0x6f00_1000, "winmm.dll"),
            module(0x2000, 0x5f00_0000, 0x5f00_1000, "winmm.dll"),
        ];
        let dups = find_duplicates(&entries, |_, _| true);
        assert!(dups.is_empty());
        let none = find_duplicates(&entries, |_, _| false);
        assert!(none.is_empty());
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
