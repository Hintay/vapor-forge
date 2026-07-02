use std::collections::HashMap;
use std::sync::Once;

use tracing::{debug, info, warn};
use vapor_forge_memory::find_proc_self_maps_targets;

static SCAN_ONCE: Once = Once::new();
static mut SCAN_RESULT: Option<ScanResult> = None;

const MAX_SLOTS: usize = 250;
const STRING_MAX: usize = 96;
const RECENT_LEAS: usize = 6;
const EARLY_SCAN: usize = 0x400;

const INTERESTING_IFACES: &[&str] = &[
    "IClientAppManager",
    "IClientApps",
    "IClientRemoteStorage",
    "IClientUser",
    "IClientUtils",
];

#[derive(Clone, Debug)]
pub struct Method {
    pub slot: usize,
    pub name: String,
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
}

struct SegmentRanges {
    text: Vec<(usize, usize)>,
    rodata: Vec<(usize, usize)>,
}

pub fn warmup() {
    SCAN_ONCE.call_once(do_scan);
}

pub fn slot_of(iface: &str, method: &str) -> Option<usize> {
    // SAFETY: SCAN_RESULT is set in warmup (Once), never modified after.
    let result = unsafe { (*std::ptr::addr_of!(SCAN_RESULT)).as_ref()? };
    let idx = *result.by_name.get(iface)?;
    let iface_data = &result.interfaces[idx];
    iface_data
        .methods
        .iter()
        .find(|m| m.name == method)
        .map(|m| m.slot)
}

pub fn find_interface(iface: &str) -> Option<&'static Interface> {
    // SAFETY: SCAN_RESULT is set in warmup (Once), never modified after.
    let result = unsafe { (*std::ptr::addr_of!(SCAN_RESULT)).as_ref()? };
    let idx = *result.by_name.get(iface)?;
    Some(&result.interfaces[idx])
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

    let interest: std::collections::HashSet<&str> = INTERESTING_IFACES.iter().copied().collect();
    let candidates = find_candidate_vtables(&segs);

    let mut interfaces: Vec<Interface> = Vec::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();

    for (method0_va, slots) in &candidates {
        let iface_name = match typeinfo_iface_name(*method0_va, &segs) {
            Some(n) => n,
            None => continue,
        };
        if !interest.contains(iface_name.as_str()) {
            continue;
        }

        if let Some(&existing_idx) = by_name.get(&iface_name) {
            if interfaces[existing_idx].methods.len() >= slots.len() {
                continue;
            }
        }

        let mut methods = Vec::with_capacity(slots.len());
        for (idx, &slot_va) in slots.iter().enumerate() {
            let (name, func_hash) = decode_wrapper(slot_va, &segs);
            methods.push(Method {
                slot: idx,
                name,
                func_hash,
            });
        }

        let rec = Interface {
            name: iface_name.clone(),
            vtable_va: *method0_va,
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
        expected = INTERESTING_IFACES.len(),
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

    // SAFETY: storing result; never modified after.
    unsafe {
        std::ptr::addr_of_mut!(SCAN_RESULT).write(Some(ScanResult {
            interfaces,
            by_name,
        }));
    }
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

fn in_rodata(va: usize, segs: &SegmentRanges) -> bool {
    segs.rodata.iter().any(|&(lo, hi)| va >= lo && va < hi)
}

fn is_in_segments(va: usize, len: usize, segs: &SegmentRanges) -> bool {
    let end = va.saturating_add(len);
    segs.text
        .iter()
        .chain(segs.rodata.iter())
        .any(|&(lo, hi)| va >= lo && end <= hi)
}

fn resolve_slot_value(raw: u32, segs: &SegmentRanges, module_base: usize) -> usize {
    let va = raw as usize;
    if in_text(va, segs) {
        return va;
    }
    let lifted = module_base.wrapping_add(va);
    if in_text(lifted, segs) {
        return lifted;
    }
    0
}

fn resolve_any_module_ptr(raw: u32, segs: &SegmentRanges, module_base: usize) -> usize {
    let module_end = segs
        .text
        .iter()
        .chain(segs.rodata.iter())
        .map(|&(_, hi)| hi)
        .max()
        .unwrap_or(0);

    let va = raw as usize;
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
    if !in_rodata(va, segs) {
        return String::new();
    }
    // SAFETY: va is within a readable segment of steamclient.so.
    let ptr = va as *const u8;
    let mut out = String::new();
    for i in 0..STRING_MAX {
        // SAFETY: bounded read within verified readable segment.
        let byte = unsafe { *ptr.add(i) };
        if byte == 0 {
            return out;
        }
        if byte < 0x20 || byte > 0x7e {
            return String::new();
        }
        out.push(byte as char);
    }
    String::new()
}

fn typeinfo_iface_name(method0_va: usize, segs: &SegmentRanges) -> Option<String> {
    let base = module_base(segs);

    // SAFETY: method0_va - 4 points to the typeinfo slot in the vtable header.
    // Use read_unaligned: during dlmopen the data may not be fully relocated.
    let ti_ptr = (method0_va - 4) as *const u32;
    if !is_in_segments(ti_ptr as usize, 4, segs) {
        return None;
    }
    let ti_raw = unsafe { ti_ptr.read_unaligned() };
    let ti = resolve_any_module_ptr(ti_raw, segs, base);
    if ti == 0 {
        return None;
    }

    // SAFETY: typeinfo + 4 points to the name pointer.
    let name_ptr = (ti + 4) as *const u32;
    if !is_in_segments(name_ptr as usize, 4, segs) {
        return None;
    }
    let name_raw = unsafe { name_ptr.read_unaligned() };
    let name_va = resolve_any_module_ptr(name_raw, segs, base);
    if name_va == 0 {
        return None;
    }

    let nm = read_cstring(name_va, segs);
    if nm.is_empty() {
        return None;
    }

    // Parse "<digits>IClient<Foo>Map"
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
    if !body.starts_with("IClient") || !body.ends_with("Map") {
        return None;
    }

    let iface = &body[..body.len() - 3]; // strip "Map"
    Some(iface.to_owned())
}

fn find_candidate_vtables(segs: &SegmentRanges) -> Vec<(usize, Vec<usize>)> {
    let base = module_base(segs);
    let mut out = Vec::new();

    for &(seg_lo, seg_hi) in &segs.rodata {
        let mut p = seg_lo + 8;
        while p + 4 <= seg_hi {
            // SAFETY: p is within a readable rodata segment.
            let raw = unsafe { (p as *const u32).read_unaligned() };
            let method0 = resolve_slot_value(raw, segs, base);
            if method0 == 0 {
                p += 4;
                continue;
            }

            // SAFETY: reading vtable header slots (use read_unaligned for safety).
            let ti = unsafe { ((p - 4) as *const u32).read_unaligned() };
            let ot = unsafe { ((p - 8) as *const u32).read_unaligned() };
            if ot != 0 || ti == 0 {
                p += 4;
                continue;
            }

            let mut slots = Vec::with_capacity(64);
            slots.push(method0);
            let mut q = p + 4;
            while q + 4 <= seg_hi {
                // SAFETY: q is within the segment.
                let v = unsafe { (q as *const u32).read_unaligned() };
                let resolved = resolve_slot_value(v, segs, base);
                if resolved == 0 {
                    break;
                }
                slots.push(resolved);
                if slots.len() >= MAX_SLOTS {
                    break;
                }
                q += 4;
            }

            if slots.len() >= 3 {
                out.push((p, slots));
            }
            p += 4;
        }
    }

    out
}

fn find_pic_anchor(func_start: usize, scan_len: usize, segs: &SegmentRanges) -> usize {
    if !in_text(func_start, segs) {
        return 0;
    }
    // SAFETY: func_start is in .text.
    let base = func_start as *const u8;
    for i in 0..scan_len.saturating_sub(11) {
        // SAFETY: bounded read within .text.
        let byte = unsafe { *base.add(i) };
        if byte != 0xE8 {
            continue;
        }
        let after_call = func_start + i + 5;
        let end = (i + 5 + 16).min(scan_len.saturating_sub(5));
        for j in (i + 5)..end {
            // SAFETY: bounded read.
            let b0 = unsafe { *base.add(j) };
            let b1 = unsafe { *base.add(j + 1) };
            if b0 == 0x81 && (b1 & 0xF8) == 0xC0 {
                // add r32, imm32
                // SAFETY: reading 4-byte immediate (unaligned: instruction stream).
                let imm = unsafe { ((func_start + j + 2) as *const i32).read_unaligned() };
                return (after_call as i64 + imm as i64) as usize;
            }
        }
    }
    0
}

fn decode_wrapper(func_start: usize, segs: &SegmentRanges) -> (String, u32) {
    let pic_base = find_pic_anchor(func_start, 0x40, segs);
    if pic_base == 0 {
        return (String::new(), 0);
    }

    // SAFETY: func_start is in .text, reading up to EARLY_SCAN bytes.
    let base = func_start as *const u8;

    let mut recent = [const { String::new() }; RECENT_LEAS];
    let mut head = 0usize;
    let mut method = String::new();
    let mut func_hash = 0u32;
    let mut tipc_matched = false;

    for i in 0..EARLY_SCAN.saturating_sub(5) {
        // SAFETY: bounded read.
        let b = unsafe { *base.add(i) };

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
        if b == 0x8D && i + 6 <= EARLY_SCAN {
            // SAFETY: bounded read.
            let modrm = unsafe { *base.add(i + 1) };
            if (modrm & 0xC0) == 0x80 && (modrm & 0x07) != 4 {
                // SAFETY: reading 4-byte displacement.
                let disp = unsafe { ((func_start + i + 2) as *const i32).read_unaligned() };
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
        if func_hash == 0 && i + 12 <= EARLY_SCAN {
            // SAFETY: bounded reads.
            unsafe {
                if *base.add(i) == 0xC7
                    && *base.add(i + 1) == 0x45
                    && *base.add(i + 7) == 0x6A
                    && *base.add(i + 8) == 0x04
                    && *base.add(i + 9) == 0x50
                    && *base.add(i + 10) == 0x57
                    && *base.add(i + 11) == 0xE8
                {
                    func_hash = ((func_start + i + 3) as *const u32).read_unaligned();
                }
            }
        }

        if tipc_matched && func_hash != 0 {
            return (method, func_hash);
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
