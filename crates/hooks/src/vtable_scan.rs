use std::collections::HashMap;
use std::sync::{Once, OnceLock};

use tracing::{debug, info, warn};
use vapor_forge_memory::find_proc_self_maps_targets;
use vapor_forge_patterns::vtable_scan::DEFAULT_INTERFACES;

static SCAN_ONCE: Once = Once::new();
static SCAN_RESULT: OnceLock<ScanResult> = OnceLock::new();

const MAX_SLOTS: usize = 250;
const MAX_SUBOBJECT_OFFSET: isize = 0x10_0000;
const STRING_MAX: usize = 96;
const RECENT_LEAS: usize = 6;
const EARLY_SCAN: usize = 0x400;

#[derive(Clone, Debug)]
pub struct Method {
    pub slot: usize,
    pub name: String,
    pub func_va: usize,
    pub func_hash: u32,
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub name: String,
    pub vtable_va: usize,
    pub methods: Vec<Method>,
}

struct ScanResult {
    interfaces: Vec<Interface>,
    by_name: HashMap<String, usize>,
    class_vtables: HashMap<String, Vec<ClassVtable>>,
}

#[derive(Clone, Debug)]
struct ClassVtable {
    vtable_va: usize,
    offset_to_top: isize,
    methods: Vec<Method>,
}

struct CandidateVtable {
    vtable_va: usize,
    offset_to_top: isize,
    slots: Vec<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MethodCandidate {
    pub vtable_va: usize,
    pub offset_to_top: isize,
    pub slot: usize,
    pub func_va: usize,
}

struct SegmentRanges {
    text: Vec<(usize, usize)>,
    rodata: Vec<(usize, usize)>,
}

pub fn warmup() {
    SCAN_ONCE.call_once(do_scan);
}

pub fn slot_of(iface: &str, method: &str) -> Option<usize> {
    let result = SCAN_RESULT.get()?;
    let idx = *result.by_name.get(iface)?;
    let iface_data = &result.interfaces[idx];
    iface_data
        .methods
        .iter()
        .find(|m| m.name == method)
        .map(|m| m.slot)
}

#[allow(dead_code)] // Kept for runtime diagnostics that inspect the decoded interface table.
pub fn find_interface(iface: &str) -> Option<&'static Interface> {
    let result = SCAN_RESULT.get()?;
    let idx = *result.by_name.get(iface)?;
    Some(&result.interfaces[idx])
}

pub fn slots_of(iface: &str, method: &str) -> Vec<usize> {
    let Some(result) = SCAN_RESULT.get() else {
        return Vec::new();
    };
    let Some(&idx) = result.by_name.get(iface) else {
        return Vec::new();
    };
    result.interfaces[idx]
        .methods
        .iter()
        .filter(|method_data| method_data.name == method)
        .map(|method_data| method_data.slot)
        .collect()
}

pub fn method_address(class: &str, slot: usize) -> Option<usize> {
    let result = SCAN_RESULT.get()?;
    let idx = *result.by_name.get(class)?;
    result.interfaces[idx]
        .methods
        .get(slot)
        .map(|method| method.func_va)
}

pub fn interface_slot_count(iface: &str) -> Option<usize> {
    let result = SCAN_RESULT.get()?;
    let idx = *result.by_name.get(iface)?;
    Some(result.interfaces[idx].methods.len())
}

pub fn class_method_candidates(class: &str) -> Vec<MethodCandidate> {
    let Some(result) = SCAN_RESULT.get() else {
        return Vec::new();
    };
    let Some(vtables) = result.class_vtables.get(class) else {
        return Vec::new();
    };
    vtables
        .iter()
        .flat_map(|vtable| {
            vtable.methods.iter().map(|method| MethodCandidate {
                vtable_va: vtable.vtable_va,
                offset_to_top: vtable.offset_to_top,
                slot: method.slot,
                func_va: method.func_va,
            })
        })
        .collect()
}

fn do_scan() {
    let t0 = std::time::Instant::now();

    let segs = match build_segments() {
        Some(s) => s,
        None => {
            warn!("vtable-scan: failed to build segment ranges");
            return;
        }
    };

    if segs.text.is_empty() || segs.rodata.is_empty() {
        warn!(
            text_count = segs.text.len(),
            rodata_count = segs.rodata.len(),
            "vtable-scan: missing segments"
        );
        return;
    }

    let mut interest: std::collections::HashSet<&str> =
        DEFAULT_INTERFACES.iter().copied().collect();
    interest.insert("CUserStats");
    interest.insert("CUser");
    let candidates = find_candidate_vtables(&segs, true);

    let mut interfaces: Vec<Interface> = Vec::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut class_vtables: HashMap<String, Vec<ClassVtable>> = HashMap::new();

    for candidate in &candidates {
        let iface_name = match typeinfo_class_name(candidate.vtable_va, &segs) {
            Some(n) => n,
            None => continue,
        };
        if !interest.contains(iface_name.as_str()) {
            continue;
        }

        if iface_name == "CUser" {
            let methods = candidate
                .slots
                .iter()
                .enumerate()
                .map(|(slot, &func_va)| Method {
                    slot,
                    name: String::new(),
                    func_va,
                    func_hash: 0,
                })
                .collect();
            class_vtables
                .entry(iface_name)
                .or_default()
                .push(ClassVtable {
                    vtable_va: candidate.vtable_va,
                    offset_to_top: candidate.offset_to_top,
                    methods,
                });
            continue;
        }
        if candidate.offset_to_top != 0 {
            continue;
        }

        if let Some(&existing_idx) = by_name.get(&iface_name) {
            if interfaces[existing_idx].methods.len() >= candidate.slots.len() {
                continue;
            }
        }

        let mut methods = Vec::with_capacity(candidate.slots.len());
        for (idx, &slot_va) in candidate.slots.iter().enumerate() {
            let (name, func_hash) = decode_wrapper(slot_va, &segs);
            methods.push(Method {
                slot: idx,
                name,
                func_va: slot_va,
                func_hash,
            });
        }

        let rec = Interface {
            name: iface_name.clone(),
            vtable_va: candidate.vtable_va,
            methods,
        };

        if let Some(&existing_idx) = by_name.get(&iface_name) {
            interfaces[existing_idx] = rec;
        } else {
            by_name.insert(iface_name, interfaces.len());
            interfaces.push(rec);
        }
    }

    let mut func_hash_count = 0usize;
    for iface in &interfaces {
        for m in &iface.methods {
            if m.func_hash != 0 {
                func_hash_count += 1;
            }
        }
    }

    let elapsed = t0.elapsed();
    info!(
        found = interfaces.len(),
        expected = DEFAULT_INTERFACES.len() + 1,
        class_vtables = class_vtables.values().map(Vec::len).sum::<usize>(),
        func_hashes = func_hash_count,
        candidates = candidates.len(),
        elapsed_ms = format_args!("{:.1}", elapsed.as_secs_f64() * 1000.0),
        "vtable-scan complete"
    );

    for iface in &interfaces {
        let named: Vec<_> = iface
            .methods
            .iter()
            .filter(|m| !m.name.is_empty())
            .collect();
        debug!(
            iface = iface.name.as_str(),
            vtable = format_args!("0x{:x}", iface.vtable_va),
            slots = iface.methods.len(),
            named = named.len(),
            "vtable-scan: interface found"
        );
    }

    let _ = SCAN_RESULT.set(ScanResult {
        interfaces,
        by_name,
        class_vtables,
    });
}

fn build_segments() -> Option<SegmentRanges> {
    let _entries = find_proc_self_maps_targets(64).ok()?;
    // Also read ALL /proc/self/maps to get full steamclient.so segments
    let all_maps = std::fs::read_to_string("/proc/self/maps").ok()?;

    let mut text = Vec::new();
    let mut rodata = Vec::new();

    for line in all_maps.lines() {
        if !line.contains("steamclient.so") {
            continue;
        }
        if let Some(entry) = parse_maps_line(line) {
            if entry.perms.contains('x') {
                text.push((entry.start, entry.end));
            } else if entry.perms.starts_with('r') && !entry.perms.contains('w') {
                rodata.push((entry.start, entry.end));
            }
        }
    }

    // Also include rw- segments (for .data.rel.ro which may appear as rw after RELRO)
    for line in all_maps.lines() {
        if !line.contains("steamclient.so") {
            continue;
        }
        if let Some(entry) = parse_maps_line(line) {
            if entry.perms.starts_with("rw") {
                rodata.push((entry.start, entry.end));
            }
        }
    }

    Some(SegmentRanges { text, rodata })
}

struct MapsEntry {
    start: usize,
    end: usize,
    perms: String,
}

fn parse_maps_line(line: &str) -> Option<MapsEntry> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?.to_owned();
    let mut bounds = range.splitn(2, '-');
    let start = usize::from_str_radix(bounds.next()?, 16).ok()?;
    let end = usize::from_str_radix(bounds.next()?, 16).ok()?;
    Some(MapsEntry { start, end, perms })
}

fn in_text(va: usize, segs: &SegmentRanges) -> bool {
    segs.text.iter().any(|&(lo, hi)| va >= lo && va < hi)
}

fn is_in_segments(va: usize, len: usize, segs: &SegmentRanges) -> bool {
    let end = va.saturating_add(len);
    segs.text
        .iter()
        .chain(segs.rodata.iter())
        .any(|&(lo, hi)| va >= lo && end <= hi)
}

fn word_size() -> usize {
    std::mem::size_of::<usize>()
}

#[cfg(target_pointer_width = "64")]
unsafe fn read_word_unaligned(addr: usize) -> usize {
    // SAFETY: caller verified addr..addr+8 is readable.
    unsafe { (addr as *const u64).read_unaligned() as usize }
}

#[cfg(target_pointer_width = "32")]
unsafe fn read_word_unaligned(addr: usize) -> usize {
    // SAFETY: caller verified addr..addr+4 is readable.
    unsafe { (addr as *const u32).read_unaligned() as usize }
}

#[cfg(target_pointer_width = "64")]
fn resolve_slot_value(raw: usize, segs: &SegmentRanges, module_base: usize) -> usize {
    let _ = module_base;
    let va = raw;
    if in_text(va, segs) {
        return va;
    }
    0
}

#[cfg(target_pointer_width = "32")]
fn resolve_slot_value(raw: usize, segs: &SegmentRanges, module_base: usize) -> usize {
    let va = raw;
    if in_text(va, segs) {
        return va;
    }
    let lifted = module_base.wrapping_add(va);
    if in_text(lifted, segs) {
        return lifted;
    }
    0
}

#[cfg(target_pointer_width = "64")]
fn resolve_any_module_ptr(raw: usize, segs: &SegmentRanges, module_base: usize) -> usize {
    let _ = module_base;
    let module_end = segs
        .text
        .iter()
        .chain(segs.rodata.iter())
        .map(|&(_, hi)| hi)
        .max()
        .unwrap_or(0);

    let va = raw;
    if va >= module_base && va < module_end {
        return va;
    }
    0
}

#[cfg(target_pointer_width = "32")]
fn resolve_any_module_ptr(raw: usize, segs: &SegmentRanges, module_base: usize) -> usize {
    let module_end = segs
        .text
        .iter()
        .chain(segs.rodata.iter())
        .map(|&(_, hi)| hi)
        .max()
        .unwrap_or(0);

    let va = raw;
    if va >= module_base && va < module_end {
        return va;
    }
    let lifted = module_base.wrapping_add(va);
    if lifted >= module_base && lifted < module_end {
        return lifted;
    }
    0
}

fn module_base(segs: &SegmentRanges) -> usize {
    segs.text
        .iter()
        .chain(segs.rodata.iter())
        .map(|&(lo, _)| lo)
        .min()
        .unwrap_or(0)
}

fn read_cstring(va: usize, segs: &SegmentRanges) -> String {
    let Some(bytes) = mapped_slice(&segs.rodata, va, STRING_MAX) else {
        return String::new();
    };
    let mut out = String::new();
    for &byte in bytes {
        if byte == 0 {
            return out;
        }
        if !(0x20..=0x7e).contains(&byte) {
            return String::new();
        }
        out.push(byte as char);
    }
    String::new()
}

fn mapped_slice(ranges: &[(usize, usize)], va: usize, max_len: usize) -> Option<&'static [u8]> {
    let &(_, end) = ranges
        .iter()
        .find(|&&(start, end)| start <= va && va < end)?;
    let len = max_len.min(end.checked_sub(va)?);
    if len == 0 {
        return None;
    }
    // SAFETY: the selected /proc/self/maps range proves va..va+len is readable.
    Some(unsafe { std::slice::from_raw_parts(va as *const u8, len) })
}

fn typeinfo_class_name(method0_va: usize, segs: &SegmentRanges) -> Option<String> {
    let base = module_base(segs);
    let word = word_size();

    // SAFETY: method0_va - word points to the typeinfo slot in the vtable header.
    // Use read_unaligned: during dlmopen the data may not be fully relocated.
    let ti_ptr = method0_va.checked_sub(word)?;
    if !is_in_segments(ti_ptr, word, segs) {
        return None;
    }
    // SAFETY: ti_ptr range was checked against readable segments above.
    let ti_raw = unsafe { read_word_unaligned(ti_ptr) };
    let ti = resolve_any_module_ptr(ti_raw, segs, base);
    if ti == 0 {
        return None;
    }

    // SAFETY: typeinfo + word points to the name pointer in Itanium C++ ABI.
    let name_ptr = ti.checked_add(word)?;
    if !is_in_segments(name_ptr, word, segs) {
        return None;
    }
    // SAFETY: name_ptr range was checked against readable segments above.
    let name_raw = unsafe { read_word_unaligned(name_ptr) };
    let name_va = resolve_any_module_ptr(name_raw, segs, base);
    if name_va == 0 {
        return None;
    }

    let nm = read_cstring(name_va, segs);
    if nm.is_empty() {
        return None;
    }

    // Parse the Itanium ABI "<length><class-name>" encoding.
    let mut i = 0;
    let mut declared = 0usize;
    let bytes = nm.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        declared = declared * 10 + (bytes[i] - b'0') as usize;
        i += 1;
    }
    if i == 0 {
        return None;
    }

    let body = &nm[i..];
    if body.len() != declared {
        return None;
    }
    if body.starts_with("IClient") && body.ends_with("Map") {
        return Some(body[..body.len() - 3].to_owned());
    }
    Some(body.to_owned())
}

fn find_candidate_vtables(segs: &SegmentRanges, include_secondary: bool) -> Vec<CandidateVtable> {
    let base = module_base(segs);
    let word = word_size();
    let mut out = Vec::new();

    for &(seg_lo, seg_hi) in &segs.rodata {
        let mut p = seg_lo + 2 * word;
        while p + word <= seg_hi {
            // SAFETY: p is within a readable rodata segment.
            let raw = unsafe { read_word_unaligned(p) };
            let method0 = resolve_slot_value(raw, segs, base);
            if method0 == 0 {
                p += word;
                continue;
            }

            // SAFETY: reading vtable header slots (use read_unaligned for safety).
            let ti = unsafe { read_word_unaligned(p - word) };
            // SAFETY: p starts two words into the segment, so the header is readable.
            let ot = unsafe { read_word_unaligned(p - 2 * word) } as isize;
            if (!include_secondary && ot != 0)
                || !(-MAX_SUBOBJECT_OFFSET..=0).contains(&ot)
                || ti == 0
            {
                p += word;
                continue;
            }

            let mut slots = Vec::with_capacity(64);
            slots.push(method0);
            let mut q = p + word;
            while q + word <= seg_hi {
                // SAFETY: q is within the segment.
                let v = unsafe { read_word_unaligned(q) };
                let resolved = resolve_slot_value(v, segs, base);
                if resolved == 0 {
                    break;
                }
                slots.push(resolved);
                if slots.len() >= MAX_SLOTS {
                    break;
                }
                q += word;
            }

            if slots.len() >= 3 {
                out.push(CandidateVtable {
                    vtable_va: p,
                    offset_to_top: ot,
                    slots,
                });
            }
            p += word;
        }
    }

    out
}

#[cfg(target_pointer_width = "32")]
fn find_pic_anchor(func_start: usize, scan_len: usize, segs: &SegmentRanges) -> usize {
    let Some(bytes) = mapped_slice(&segs.text, func_start, scan_len) else {
        return 0;
    };
    for i in 0..bytes.len().saturating_sub(11) {
        if bytes[i] != 0xE8 {
            continue;
        }
        let after_call = func_start + i + 5;
        let end = (i + 5 + 16).min(bytes.len().saturating_sub(5));
        for j in (i + 5)..end {
            let b0 = bytes[j];
            let b1 = bytes[j + 1];
            if b0 == 0x81 && (b1 & 0xF8) == 0xC0 {
                let imm = i32::from_le_bytes(bytes[j + 2..j + 6].try_into().unwrap());
                return (after_call as i64 + imm as i64) as usize;
            }
        }
    }
    0
}

#[cfg(target_pointer_width = "64")]
fn decode_wrapper(func_start: usize, segs: &SegmentRanges) -> (String, u32) {
    decode_wrapper_x86_64(func_start, segs)
}

#[cfg(target_pointer_width = "32")]
fn decode_wrapper(func_start: usize, segs: &SegmentRanges) -> (String, u32) {
    let pic_base = find_pic_anchor(func_start, 0x40, segs);
    if pic_base == 0 {
        return (String::new(), 0);
    }

    let Some(bytes) = mapped_slice(&segs.text, func_start, EARLY_SCAN) else {
        return (String::new(), 0);
    };

    let mut recent = [const { String::new() }; RECENT_LEAS];
    let mut head = 0usize;
    let mut method = String::new();
    let mut func_hash = 0u32;
    let mut tipc_matched = false;

    for i in 0..bytes.len().saturating_sub(5) {
        let b = bytes[i];

        // Look for CALL (E8) to match the first ipc-internal call
        if b == 0xE8 && !tipc_matched {
            for k in 0..RECENT_LEAS {
                let idx = (head + RECENT_LEAS - 1 - k) % RECENT_LEAS;
                let s = &recent[idx];
                if s.is_empty() {
                    continue;
                }
                if method.is_empty() && is_method_shape(s) {
                    method = s.clone();
                    break;
                }
            }
            tipc_matched = !method.is_empty();
        }

        // LEA r32, [reg + disp32] (8D XX where modrm indicates [reg+disp32])
        if b == 0x8D && i + 6 <= bytes.len() {
            let modrm = bytes[i + 1];
            if (modrm & 0xC0) == 0x80 && (modrm & 0x07) != 4 {
                let disp = i32::from_le_bytes(bytes[i + 2..i + 6].try_into().unwrap());
                let target =
                    ((pic_base as u64).wrapping_add(disp as u32 as u64) & 0xFFFFFFFF) as usize;
                let s = read_cstring(target, segs);
                if !s.is_empty() {
                    recent[head] = s;
                    head = (head + 1) % RECENT_LEAS;
                }
            }
        }

        // funcHash: C7 45 ?? IMM32 6A 04 50 57 E8
        if func_hash == 0
            && i + 12 <= bytes.len()
            && bytes[i] == 0xC7
            && bytes[i + 1] == 0x45
            && bytes[i + 7] == 0x6A
            && bytes[i + 8] == 0x04
            && bytes[i + 9] == 0x50
            && bytes[i + 10] == 0x57
            && bytes[i + 11] == 0xE8
        {
            func_hash = u32::from_le_bytes(bytes[i + 3..i + 7].try_into().unwrap());
        }

        if tipc_matched && func_hash != 0 {
            return (method, func_hash);
        }
    }

    (method, func_hash)
}

#[cfg(target_pointer_width = "64")]
fn decode_wrapper_x86_64(func_start: usize, segs: &SegmentRanges) -> (String, u32) {
    let Some(bytes) = mapped_slice(&segs.text, func_start, EARLY_SCAN) else {
        return (String::new(), 0);
    };
    let mut recent = [const { String::new() }; RECENT_LEAS];
    let mut head = 0usize;
    let mut method = String::new();
    let mut func_hash = 0u32;

    for i in 0..bytes.len().saturating_sub(8) {
        let b = bytes[i];

        // RIP-relative LEA: 48/4c 8d modrm disp32.
        if (b == 0x48 || b == 0x4c) && i + 7 <= bytes.len() {
            let op = bytes[i + 1];
            let modrm = bytes[i + 2];
            if op == 0x8d && (modrm & 0xc7) == 0x05 {
                let disp = i32::from_le_bytes(bytes[i + 3..i + 7].try_into().unwrap());
                let target = (func_start + i + 7).wrapping_add_signed(disp as isize);
                let s = read_cstring(target, segs);
                if !s.is_empty() {
                    if method.is_empty() && is_method_shape(&s) {
                        method = s.clone();
                    }
                    recent[head] = s;
                    head = (head + 1) % RECENT_LEAS;
                }
            }
        }

        // Some wrappers move method names through recent LEAs before the IPC call.
        if b == 0xe8 && method.is_empty() {
            for k in 0..RECENT_LEAS {
                let idx = (head + RECENT_LEAS - 1 - k) % RECENT_LEAS;
                let s = &recent[idx];
                if is_method_shape(s) {
                    method = s.clone();
                    break;
                }
            }
        }

        // Hash constants are passed as 32-bit immediates. Keep this deliberately
        // broad; the name is what slot lookup uses today, the hash is diagnostic.
        if func_hash == 0 && i + 7 <= bytes.len() && b == 0xc7 {
            let modrm = bytes[i + 1];
            if (modrm & 0xc0) == 0x40 || (modrm & 0xc0) == 0x80 {
                func_hash = u32::from_le_bytes(bytes[i + 3..i + 7].try_into().unwrap());
            }
        }

        if !method.is_empty() && func_hash != 0 {
            break;
        }
    }

    (method, func_hash)
}

fn is_method_shape(s: &str) -> bool {
    if s.len() < 2 || s.len() > 96 {
        return false;
    }
    if s.starts_with("IClient") {
        return false;
    }
    if s.contains('/') || s.contains('%') || s.contains(' ') {
        return false;
    }
    let first = s.as_bytes()[0];
    first.is_ascii_alphabetic() || first == b'_'
}
