use core::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

use tracing::{info, warn};

type ExecuteJavaScriptFn = unsafe extern "C" fn(*mut c_void, *const c_char);

const CHTML_WINDOW_RTTI_NAME: &[u8] = b"11CHTMLWindow\0";
const REGISTER_JS_METHOD_SLOT: usize = 6;
// This is the non-deleting destructor on both supported ABIs.
const DESTRUCTOR_SLOT: usize = 8;

static HTML_WINDOW_VTABLE: AtomicUsize = AtomicUsize::new(0);
static EXEC_JS_ADDR: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug)]
struct MapsEntry {
    start: usize,
    end: usize,
    perms: String,
    path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExecuteResult {
    Executed,
    Unavailable,
}

pub(super) fn execute_javascript_on(window: usize, script: &str) -> ExecuteResult {
    let exec_addr = EXEC_JS_ADDR.load(Ordering::Acquire);
    if window == 0 || exec_addr == 0 {
        return ExecuteResult::Unavailable;
    }
    let Ok(script) = std::ffi::CString::new(script) else {
        warn!("toast: script contains unexpected NUL byte");
        return ExecuteResult::Unavailable;
    };
    // SAFETY: installation validates the method address. The RegisterJSMethod
    // and destructor hooks make the exact CHTMLWindow registry authoritative.
    let execute: ExecuteJavaScriptFn = unsafe { std::mem::transmute(exec_addr) };
    // SAFETY: the string remains live for the synchronous Steam call.
    unsafe { execute(window as *mut c_void, script.as_ptr()) };
    ExecuteResult::Executed
}

pub(crate) fn lifecycle_method_addresses() -> Option<(usize, usize)> {
    let maps = read_maps()?;
    let vtable = resolve_html_window_vtable(&maps)?;
    let register = vtable_method_address(vtable, REGISTER_JS_METHOD_SLOT, &maps)?;
    let destructor = vtable_method_address(vtable, DESTRUCTOR_SLOT, &maps)?;
    Some((register, destructor))
}

fn vtable_method_address(vtable: usize, slot: usize, maps: &[MapsEntry]) -> Option<usize> {
    let offset = slot.checked_mul(std::mem::size_of::<usize>())?;
    let address = read_usize(vtable.checked_add(offset)?, maps)?;
    is_executable_addr(address, maps).then_some(address)
}

fn resolve_html_window_vtable(maps: &[MapsEntry]) -> Option<usize> {
    let cached_vtable = HTML_WINDOW_VTABLE.load(Ordering::Acquire);
    let cached_exec = EXEC_JS_ADDR.load(Ordering::Acquire);
    if cached_vtable != 0
        && cached_exec != 0
        && is_readable_addr(cached_vtable, maps)
        && is_executable_addr(cached_exec, maps)
    {
        return Some(cached_vtable);
    }

    let name_addr = find_steamui_bytes(CHTML_WINDOW_RTTI_NAME, maps)?;
    let Some((vtable, exec)) = find_primary_vtable_for_name(name_addr, maps) else {
        warn!("toast: validated CHTMLWindow primary vtable not found");
        return None;
    };

    HTML_WINDOW_VTABLE.store(vtable, Ordering::Release);
    EXEC_JS_ADDR.store(exec, Ordering::Release);
    info!(
        vtable = format_args!("{:#x}", vtable),
        execute_js = format_args!("{:#x}", exec),
        "toast: CHTMLWindow resolved"
    );
    Some(vtable)
}

fn find_primary_vtable_for_name(name_addr: usize, maps: &[MapsEntry]) -> Option<(usize, usize)> {
    let word = std::mem::size_of::<usize>();
    for hit in find_readable_ptrs(name_addr, maps) {
        let Some(typeinfo) = hit.checked_sub(word) else {
            continue;
        };
        if !is_readable_range(typeinfo, word.saturating_mul(2), maps) {
            continue;
        }
        let Some(vtable) = find_primary_vtable(typeinfo, maps) else {
            continue;
        };
        let Some(exec) = read_usize(vtable, maps) else {
            continue;
        };
        if is_executable_addr(exec, maps) {
            return Some((vtable, exec));
        }
    }
    None
}

fn find_primary_vtable(typeinfo: usize, maps: &[MapsEntry]) -> Option<usize> {
    let word = std::mem::size_of::<usize>();
    for typeinfo_slot in find_readable_ptrs(typeinfo, maps) {
        if typeinfo_slot < word {
            continue;
        }
        let offset_to_top_addr = typeinfo_slot - word;
        let Some(offset_to_top) = read_isize(offset_to_top_addr, maps) else {
            continue;
        };
        let Some(method0) = typeinfo_slot.checked_add(word) else {
            continue;
        };
        if offset_to_top == 0
            && is_readable_range(method0, word, maps)
            && read_usize(method0, maps).is_some_and(|addr| is_executable_addr(addr, maps))
        {
            return Some(method0);
        }
    }
    None
}

fn find_steamui_bytes(needle: &[u8], maps: &[MapsEntry]) -> Option<usize> {
    maps.iter()
        .filter(|entry| {
            entry.path.ends_with("/steamui.so")
                && entry.perms.starts_with('r')
                && entry.end >= entry.start
        })
        .find_map(|entry| find_bytes_in_range(entry.start, entry.end, needle))
}

fn find_readable_ptrs(value: usize, maps: &[MapsEntry]) -> Vec<usize> {
    let mut out = Vec::new();
    for entry in maps.iter().filter(|entry| {
        entry.path.ends_with("/steamui.so")
            && entry.perms.starts_with('r')
            && entry.end > entry.start
    }) {
        find_ptrs_in_entry(value, entry, &mut out);
    }
    out
}

fn find_ptrs_in_entry(value: usize, entry: &MapsEntry, out: &mut Vec<usize>) {
    let len = entry.end.saturating_sub(entry.start);
    if len < std::mem::size_of::<usize>() {
        return;
    }

    let mut bytes = vec![0u8; len];
    if !read_process_bytes(entry.start, &mut bytes) {
        return;
    }

    let word = std::mem::size_of::<usize>();
    let first = align_up(entry.start, word) - entry.start;
    let mut offset = first;
    while offset.saturating_add(word) <= bytes.len() {
        if read_usize_from_bytes(&bytes[offset..offset + word]) == value {
            out.push(entry.start + offset);
        }
        offset = offset.saturating_add(word);
    }
}

fn find_bytes_in_range(start: usize, end: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || end.saturating_sub(start) < needle.len() {
        return None;
    }
    let len = end - start;
    let mut haystack = vec![0u8; len];
    if !read_process_bytes(start, &mut haystack) {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| start + offset)
}

fn read_usize(addr: usize, maps: &[MapsEntry]) -> Option<usize> {
    if !is_readable_range(addr, std::mem::size_of::<usize>(), maps) {
        return None;
    }
    let mut bytes = [0u8; std::mem::size_of::<usize>()];
    if !read_process_bytes(addr, &mut bytes) {
        return None;
    }
    Some(read_usize_from_bytes(&bytes))
}

fn read_isize(addr: usize, maps: &[MapsEntry]) -> Option<isize> {
    if !is_readable_range(addr, std::mem::size_of::<isize>(), maps) {
        return None;
    }
    let mut bytes = [0u8; std::mem::size_of::<isize>()];
    if !read_process_bytes(addr, &mut bytes) {
        return None;
    }
    Some(isize::from_ne_bytes(bytes))
}

fn read_usize_from_bytes(bytes: &[u8]) -> usize {
    let mut out = [0u8; std::mem::size_of::<usize>()];
    out.copy_from_slice(&bytes[..std::mem::size_of::<usize>()]);
    usize::from_ne_bytes(out)
}

fn read_process_bytes(addr: usize, out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }

    let local = libc::iovec {
        iov_base: out.as_mut_ptr().cast(),
        iov_len: out.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut c_void,
        iov_len: out.len(),
    };
    // SAFETY: process_vm_readv copies from this process into an owned buffer.
    // Invalid or stale remote mappings report an error instead of trapping here.
    let read = unsafe {
        libc::process_vm_readv(
            libc::getpid(),
            &local,
            1,
            &remote as *const libc::iovec,
            1,
            0,
        )
    };
    read == out.len() as isize
}

fn is_readable_addr(addr: usize, maps: &[MapsEntry]) -> bool {
    is_readable_range(addr, 1, maps)
}

fn is_readable_range(addr: usize, len: usize, maps: &[MapsEntry]) -> bool {
    let end = addr.saturating_add(len);
    maps.iter()
        .any(|entry| entry.perms.starts_with('r') && addr >= entry.start && end <= entry.end)
}

fn is_executable_addr(addr: usize, maps: &[MapsEntry]) -> bool {
    maps.iter()
        .any(|entry| entry.perms.contains('x') && addr >= entry.start && addr < entry.end)
}

fn read_maps() -> Option<Vec<MapsEntry>> {
    let text = std::fs::read_to_string("/proc/self/maps").ok()?;
    Some(text.lines().filter_map(parse_maps_line).collect())
}

fn parse_maps_line(line: &str) -> Option<MapsEntry> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?.to_owned();
    parts.next()?;
    parts.next()?;
    parts.next()?;
    let path = parts.next().unwrap_or("").to_owned();
    let mut bounds = range.splitn(2, '-');
    let start = usize::from_str_radix(bounds.next()?, 16).ok()?;
    let end = usize::from_str_radix(bounds.next()?, 16).ok()?;
    Some(MapsEntry {
        start,
        end,
        perms,
        path,
    })
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maps_line_reads_path() {
        let line = "1000-2000 rw-p 00000000 08:01 42 /tmp/steamui.so";
        let entry = parse_maps_line(line).expect("entry");
        assert_eq!(entry.start, 0x1000);
        assert_eq!(entry.end, 0x2000);
        assert_eq!(entry.perms, "rw-p");
        assert_eq!(entry.path, "/tmp/steamui.so");
    }

    #[test]
    fn primary_vtable_uses_pointer_sized_itanium_slots() {
        let typeinfo = 0x1234_5000usize;
        let executable = primary_vtable_uses_pointer_sized_itanium_slots as *const () as usize;
        let mut vtable_prefix = Box::new([0usize, typeinfo, executable]);
        let base = vtable_prefix.as_mut_ptr() as usize;
        let end = base + std::mem::size_of_val(&*vtable_prefix);

        let maps = vec![
            MapsEntry {
                start: base,
                end,
                perms: "r--p".to_owned(),
                path: "/tmp/steamui.so".to_owned(),
            },
            MapsEntry {
                start: executable.saturating_sub(0x10),
                end: executable.saturating_add(0x10),
                perms: "r-xp".to_owned(),
                path: "/tmp/steamui.so".to_owned(),
            },
        ];

        assert_eq!(
            find_primary_vtable(typeinfo, &maps),
            Some(base + std::mem::size_of::<usize>() * 2)
        );
    }

    #[test]
    fn typeinfo_lookup_skips_unrelated_name_pointer_hits() {
        let name_addr = 0x1234_5678usize;
        let executable = typeinfo_lookup_skips_unrelated_name_pointer_hits as *const () as usize;
        let mut words = Box::new([0usize; 12]);
        let base = words.as_mut_ptr() as usize;
        let word = std::mem::size_of::<usize>();
        let typeinfo = base + word * 4;
        let vtable = base + word * 10;

        words[1] = name_addr;
        words[4] = 1;
        words[5] = name_addr;
        words[8] = 0;
        words[9] = typeinfo;
        words[10] = executable;

        let maps = vec![
            MapsEntry {
                start: base,
                end: base + std::mem::size_of_val(&*words),
                perms: "r--p".to_owned(),
                path: "/tmp/steamui.so".to_owned(),
            },
            MapsEntry {
                start: executable,
                end: executable.saturating_add(1),
                perms: "r-xp".to_owned(),
                path: "/tmp/steamui.so".to_owned(),
            },
        ];

        assert_eq!(
            find_primary_vtable_for_name(name_addr, &maps),
            Some((vtable, executable))
        );
    }

    #[test]
    fn lifecycle_methods_use_pointer_sized_vtable_slots() {
        let executable = lifecycle_methods_use_pointer_sized_vtable_slots as *const () as usize;
        let mut methods = Box::new([0usize; DESTRUCTOR_SLOT + 1]);
        methods[REGISTER_JS_METHOD_SLOT] = executable;
        methods[DESTRUCTOR_SLOT] = executable;
        let vtable = methods.as_mut_ptr() as usize;
        let maps = vec![
            MapsEntry {
                start: vtable,
                end: vtable + std::mem::size_of_val(&*methods),
                perms: "r--p".to_owned(),
                path: "/tmp/steamui.so".to_owned(),
            },
            MapsEntry {
                start: executable,
                end: executable.saturating_add(1),
                perms: "r-xp".to_owned(),
                path: "/tmp/steamui.so".to_owned(),
            },
        ];

        assert_eq!(
            vtable_method_address(vtable, REGISTER_JS_METHOD_SLOT, &maps),
            Some(executable)
        );
        assert_eq!(
            vtable_method_address(vtable, DESTRUCTOR_SLOT, &maps),
            Some(executable)
        );
    }
}
