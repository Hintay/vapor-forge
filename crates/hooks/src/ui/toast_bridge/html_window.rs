use core::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use tracing::{info, warn};

use super::monotonic_ns;

type ExecuteJavaScriptFn = unsafe extern "C" fn(*mut c_void, *const c_char);

const CHTML_WINDOW_RTTI_NAME: &[u8] = b"11CHTMLWindow\0";
const CHTML_WINDOW_MIN_SIZE: usize = 0x3c;
const MAX_HTML_WINDOWS: usize = 64;
const BOOTSTRAP_RETRY_NS: u64 = 1_000_000_000;
const BOOTSTRAP_SCAN_BUDGET: usize = 32 * 1024 * 1024;
const MAX_BOOTSTRAP_HIT_LOGS: usize = 32;

static HTML_WINDOW_VTABLE: AtomicUsize = AtomicUsize::new(0);
static EXEC_JS_ADDR: AtomicUsize = AtomicUsize::new(0);
static NEXT_BOOTSTRAP_NS: AtomicU64 = AtomicU64::new(0);
static BOOTSTRAP_CURSOR: AtomicUsize = AtomicUsize::new(0);
static BOOTSTRAP_HIT_LOGS: AtomicUsize = AtomicUsize::new(0);
static HTML_WINDOWS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

#[derive(Clone, Debug)]
struct MapsEntry {
    start: usize,
    end: usize,
    perms: String,
    path: String,
}

pub(super) fn execute_javascript(script: &str) -> bool {
    let maps = match read_maps() {
        Some(maps) => maps,
        None => return false,
    };

    let windows = match find_html_windows(&maps) {
        Some(windows) if !windows.is_empty() => windows,
        _ => return false,
    };

    let exec_addr = EXEC_JS_ADDR.load(Ordering::Acquire);
    if exec_addr == 0 || !is_executable_addr(exec_addr, &maps) {
        return false;
    }

    let Ok(script_cstr) = std::ffi::CString::new(script) else {
        warn!("toast: script contains unexpected NUL byte");
        return false;
    };

    // SAFETY: exec_addr is CHTMLWindow::ExecuteJavaScript from the validated
    // CHTMLWindow primary vtable. The selected windows are validated against
    // that same vtable before calling.
    let execute: ExecuteJavaScriptFn = unsafe { std::mem::transmute(exec_addr) };
    for window in windows {
        /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
        unsafe { execute(window as *mut c_void, script_cstr.as_ptr()) };
    }
    true
}

pub(crate) fn html_windows() -> Vec<usize> {
    let Some(maps) = read_maps() else {
        return Vec::new();
    };
    find_html_windows(&maps).unwrap_or_default()
}

pub(crate) fn execute_javascript_on(window: usize, script: &str) -> bool {
    let Some(maps) = read_maps() else {
        return false;
    };
    let Some(vtable) = resolve_html_window_vtable(&maps) else {
        return false;
    };
    if !is_html_window_candidate(window, vtable, &maps) {
        return false;
    }
    let exec_addr = EXEC_JS_ADDR.load(Ordering::Acquire);
    if !is_executable_addr(exec_addr, &maps) {
        return false;
    }
    let Ok(script) = std::ffi::CString::new(script) else {
        return false;
    };
    // SAFETY: the window and slot are validated against the current mappings.
    let execute: ExecuteJavaScriptFn = unsafe { std::mem::transmute(exec_addr) };
    // SAFETY: the string remains live for the synchronous Steam call.
    unsafe { execute(window as *mut c_void, script.as_ptr()) };
    true
}

pub(crate) fn register_js_method_address() -> Option<usize> {
    const REGISTER_JS_METHOD_SLOT: usize = 6;
    let maps = read_maps()?;
    let vtable = resolve_html_window_vtable(&maps)?;
    let address = read_usize(
        vtable + REGISTER_JS_METHOD_SLOT * std::mem::size_of::<usize>(),
        &maps,
    )?;
    is_executable_addr(address, &maps).then_some(address)
}

fn find_html_windows(maps: &[MapsEntry]) -> Option<Vec<usize>> {
    let vtable = resolve_html_window_vtable(maps)?;

    if let Some(windows) = cached_html_windows(vtable, maps) {
        return Some(windows);
    }

    let now = monotonic_ns();
    let next = NEXT_BOOTSTRAP_NS.load(Ordering::Acquire);
    if now < next {
        return None;
    }
    NEXT_BOOTSTRAP_NS.store(now.saturating_add(BOOTSTRAP_RETRY_NS), Ordering::Release);

    let windows = bootstrap_html_windows(vtable, maps)?;
    if windows.is_empty() {
        return None;
    }
    store_html_windows(&windows);
    Some(windows)
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

fn cached_html_windows(vtable: usize, maps: &[MapsEntry]) -> Option<Vec<usize>> {
    let Ok(mut windows) = HTML_WINDOWS.lock() else {
        warn!("toast: CHTMLWindow cache lock poisoned");
        return None;
    };
    windows.retain(|&window| is_html_window_candidate(window, vtable, maps));
    if windows.is_empty() {
        None
    } else {
        Some(windows.clone())
    }
}

fn store_html_windows(windows: &[usize]) {
    let Ok(mut cached) = HTML_WINDOWS.lock() else {
        warn!("toast: CHTMLWindow cache lock poisoned");
        return;
    };
    cached.clear();
    cached.extend_from_slice(windows);
}

fn bootstrap_html_windows(vtable: usize, maps: &[MapsEntry]) -> Option<Vec<usize>> {
    let mut budget = BOOTSTRAP_SCAN_BUDGET;
    let mut cursor = BOOTSTRAP_CURSOR.load(Ordering::Acquire);
    let mut saw_cursor_entry = cursor == 0;
    let mut windows = Vec::new();

    for entry in maps.iter().filter(|entry| is_bootstrap_scan_entry(entry)) {
        if !saw_cursor_entry {
            if cursor < entry.end {
                saw_cursor_entry = true;
            } else {
                continue;
            }
        }

        let start = if cursor >= entry.start && cursor < entry.end {
            cursor
        } else {
            entry.start
        };
        let start = align_up(start, std::mem::size_of::<usize>());
        if start.saturating_add(CHTML_WINDOW_MIN_SIZE) > entry.end {
            cursor = 0;
            continue;
        }

        let scan_len = budget.min(entry.end.saturating_sub(start));
        let scan_end = start.saturating_add(scan_len);
        scan_window_candidates(entry, start, scan_end, vtable, maps, &mut windows);
        if windows.len() >= MAX_HTML_WINDOWS {
            BOOTSTRAP_CURSOR.store(0, Ordering::Release);
            info!(count = windows.len(), "toast: CHTMLWindow scan resolved");
            return Some(windows);
        }

        budget = budget.saturating_sub(scan_len);
        if scan_end < entry.end {
            if !windows.is_empty() {
                BOOTSTRAP_CURSOR.store(0, Ordering::Release);
                info!(count = windows.len(), "toast: CHTMLWindow scan resolved");
                return Some(windows);
            }
            BOOTSTRAP_CURSOR.store(scan_end, Ordering::Release);
            return None;
        }
        cursor = 0;
        if budget == 0 {
            BOOTSTRAP_CURSOR.store(0, Ordering::Release);
            return None;
        }
    }

    BOOTSTRAP_CURSOR.store(0, Ordering::Release);
    if !windows.is_empty() {
        info!(count = windows.len(), "toast: CHTMLWindow scan resolved");
    }
    Some(windows)
}

pub(super) fn bootstrap_scan_pending() -> bool {
    BOOTSTRAP_CURSOR.load(Ordering::Acquire) != 0
}

fn is_bootstrap_scan_entry(entry: &MapsEntry) -> bool {
    entry.perms.starts_with("rw")
        && entry.end > entry.start
        && (entry.path.is_empty() || entry.path == "[heap]" || entry.path.starts_with("[anon"))
}

fn scan_window_candidates(
    entry: &MapsEntry,
    start: usize,
    end: usize,
    vtable: usize,
    maps: &[MapsEntry],
    windows: &mut Vec<usize>,
) {
    if end <= start {
        return;
    }

    let len = end - start;
    let mut bytes = vec![0u8; len];
    if !read_process_bytes(start, &mut bytes) {
        return;
    }

    let word = std::mem::size_of::<usize>();
    let mut offset = 0usize;
    while offset.saturating_add(word) <= bytes.len() {
        if read_usize_from_bytes(&bytes[offset..offset + word]) == vtable {
            let window = start + offset;
            let accepted = is_html_window_candidate(window, vtable, maps);
            log_bootstrap_hit(entry, window, accepted);
            if accepted && !windows.contains(&window) {
                windows.push(window);
                if windows.len() >= MAX_HTML_WINDOWS {
                    return;
                }
            }
        }
        offset = offset.saturating_add(word);
    }
}

fn is_html_window_candidate(window: usize, vtable: usize, maps: &[MapsEntry]) -> bool {
    if !is_readable_range(window, CHTML_WINDOW_MIN_SIZE, maps) {
        return false;
    }
    if read_usize(window, maps) != Some(vtable) {
        return false;
    }

    object_has_readable_member_pointer(window, CHTML_WINDOW_MIN_SIZE, maps)
}

fn object_has_readable_member_pointer(object: usize, scan_size: usize, maps: &[MapsEntry]) -> bool {
    let word = std::mem::size_of::<usize>();
    let mut offset = word;
    while offset.saturating_add(word) <= scan_size {
        if read_usize(object.saturating_add(offset), maps)
            .is_some_and(|addr| is_readable_addr(addr, maps))
        {
            return true;
        }
        offset = offset.saturating_add(word);
    }
    false
}

fn log_bootstrap_hit(entry: &MapsEntry, window: usize, accepted: bool) {
    if BOOTSTRAP_HIT_LOGS.fetch_add(1, Ordering::Relaxed) >= MAX_BOOTSTRAP_HIT_LOGS {
        return;
    }

    let path = if entry.path.is_empty() {
        "[anonymous]"
    } else {
        &entry.path
    };
    info!(
        window = format_args!("{:#x}", window),
        accepted,
        region_start = format_args!("{:#x}", entry.start),
        region_end = format_args!("{:#x}", entry.end),
        perms = %entry.perms,
        path = %path,
        "toast: CHTMLWindow vtable pointer hit"
    );
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
    fn bootstrap_scan_accepts_heap_and_anonymous_mappings() {
        let heap = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "rw-p".to_owned(),
            path: "[heap]".to_owned(),
        };
        let anon = MapsEntry {
            start: 0x2000,
            end: 0x3000,
            perms: "rw-p".to_owned(),
            path: String::new(),
        };
        assert!(is_bootstrap_scan_entry(&heap));
        assert!(is_bootstrap_scan_entry(&anon));
    }

    #[test]
    fn bootstrap_scan_rejects_file_backed_mappings() {
        let entry = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "rw-p".to_owned(),
            path: "/memfd/steam-object-arena".to_owned(),
        };
        assert!(!is_bootstrap_scan_entry(&entry));
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
    fn window_candidate_validation_scans_pointer_sized_members() {
        let mut target = Box::new(42usize);
        let mut object = Box::new([0usize, target.as_mut() as *mut usize as usize]);
        let object_base = object.as_mut_ptr() as usize;
        let target_addr = target.as_mut() as *mut usize as usize;

        let maps = vec![
            MapsEntry {
                start: object_base,
                end: object_base + std::mem::size_of_val(&*object),
                perms: "rw-p".to_owned(),
                path: "[heap]".to_owned(),
            },
            MapsEntry {
                start: target_addr,
                end: target_addr + std::mem::size_of::<usize>(),
                perms: "rw-p".to_owned(),
                path: "[heap]".to_owned(),
            },
        ];

        assert!(object_has_readable_member_pointer(
            object_base,
            std::mem::size_of_val(&*object),
            &maps
        ));
    }
}
