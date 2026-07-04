use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use iced_x86::code_asm::*;
use vapor_forge_patterns::registry::{
    parse_toml_patterns, FollowMode, PatternDef, RuntimePatternEntry, EMBEDDED_PATTERNS,
};
use vapor_forge_patterns::vtable_scan::{self, ElfClass};
use vapor_forge_patterns::{
    find_prologue_upwards, follow_last_call_before_ret, follow_relative_call, Pattern,
};

const PT_LOAD: u32 = 1;
const PF_X: u32 = 0x1;
const FOLLOW_CALL_SCAN_BYTES: usize = 256;
const UPWARD_SCAN_BYTES: usize = 0x10000;

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-pattern-scan: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let patterns = PatternSet::load(&args)?;
    let mut failed = false;

    if let Some(path) = args.steamclient.as_deref() {
        failed |= scan_module("steamclient", path, &patterns)?;
    }
    if let Some(path) = args.steamui.as_deref() {
        failed |= scan_module("steamui", path, &patterns)?;
    }

    if failed {
        Err("one or more required patterns failed".to_owned())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct Args {
    arch: Option<PatternArch>,
    patterns: Option<PathBuf>,
    steamclient: Option<PathBuf>,
    steamui: Option<PathBuf>,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut arch = None;
        let mut patterns = None;
        let mut steamclient = None;
        let mut steamui = None;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--arch" => {
                    arch = Some(PatternArch::parse(&next_value(&mut args, "--arch")?)?);
                }
                "--patterns" => {
                    patterns = Some(next_path(&mut args, "--patterns")?);
                }
                "--steamclient" => {
                    steamclient = Some(next_path(&mut args, "--steamclient")?);
                }
                "--steamui" => {
                    steamui = Some(next_path(&mut args, "--steamui")?);
                }
                "-h" | "--help" => {
                    return Err(usage());
                }
                other => {
                    return Err(format!("unknown argument {other:?}\n{}", usage()));
                }
            }
        }

        if arch.is_some() && patterns.is_some() {
            return Err(format!(
                "--arch and --patterns cannot be used together\n{}",
                usage()
            ));
        }

        if steamclient.is_none() && steamui.is_none() {
            return Err(usage());
        }

        Ok(Self {
            arch,
            patterns,
            steamclient,
            steamui,
        })
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value\n{}", usage()))
}

fn next_path(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf, String> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{flag} requires a path\n{}", usage()))
}

fn usage() -> String {
    "usage: vapor-forge-pattern-scan [--arch x86|x86_64] [--patterns PATH] [--steamclient PATH] [--steamui PATH]".to_owned()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PatternArch {
    X86,
    X86_64,
}

impl PatternArch {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "x86" | "i386" | "i686" => Ok(Self::X86),
            "x86_64" | "amd64" => Ok(Self::X86_64),
            other => Err(format!("unsupported pattern arch {other:?}\n{}", usage())),
        }
    }

    fn patterns_path(self) -> PathBuf {
        let res_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../res");
        match self {
            Self::X86 => res_dir.join("patterns.toml"),
            Self::X86_64 => res_dir.join("patterns.x86_64.toml"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
        }
    }
}

struct PatternSet {
    source: String,
    entries: Vec<ScanEntry>,
}

impl PatternSet {
    fn load(args: &Args) -> Result<Self, String> {
        if let Some(path) = args.patterns.as_deref() {
            return Self::load_file(path, format!("patterns={}", path.display()));
        }

        if let Some(arch) = args.arch {
            let path = arch.patterns_path();
            return Self::load_file(&path, format!("arch={} {}", arch.name(), path.display()));
        }

        let mut entries: Vec<_> = EMBEDDED_PATTERNS.iter().map(ScanEntry::from).collect();
        entries.sort_by(|a, b| a.module.cmp(&b.module).then_with(|| a.name.cmp(&b.name)));
        Ok(Self {
            source: "embedded patterns".to_owned(),
            entries,
        })
    }

    fn load_file(path: &Path, source: String) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let mut entries: Vec<_> = parse_toml_patterns(&text)?
            .into_iter()
            .map(ScanEntry::from)
            .collect();
        entries.sort_by(|a, b| a.module.cmp(&b.module).then_with(|| a.name.cmp(&b.name)));
        Ok(Self { source, entries })
    }
}

struct ScanEntry {
    name: String,
    pattern: String,
    follow: FollowMode,
    prologue: Option<Vec<u8>>,
    callee_pattern: Option<String>,
    optional: bool,
    pic_entry: bool,
    module: String,
}

impl From<&PatternDef> for ScanEntry {
    fn from(entry: &PatternDef) -> Self {
        Self {
            name: entry.name.to_owned(),
            pattern: entry.pattern.to_owned(),
            follow: entry.follow,
            prologue: entry.prologue.map(<[u8]>::to_vec),
            callee_pattern: entry.callee_pattern.map(str::to_owned),
            optional: entry.optional,
            pic_entry: entry.pic_entry,
            module: entry.module.to_owned(),
        }
    }
}

impl From<(String, RuntimePatternEntry)> for ScanEntry {
    fn from((name, entry): (String, RuntimePatternEntry)) -> Self {
        Self {
            name,
            pattern: entry.pattern,
            follow: entry.follow,
            prologue: entry.prologue,
            callee_pattern: entry.callee_pattern,
            optional: entry.optional,
            pic_entry: entry.pic_entry,
            module: entry.module,
        }
    }
}

fn scan_module(module: &str, path: &Path, patterns: &PatternSet) -> Result<bool, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let is_elf64 = data.get(4) == Some(&2);
    let segment = executable_segment(&data)?;
    let entries: Vec<_> = patterns
        .entries
        .iter()
        .filter(|entry| entry.module == module)
        .collect();
    if entries.is_empty() {
        return Err(format!(
            "no patterns for module {module:?} in {}",
            patterns.source
        ));
    }

    println!(
        "{}: {} source={} text_file_off=0x{:x} text_vaddr=0x{:x} text_size=0x{:x}",
        module,
        path.display(),
        patterns.source,
        segment.file_offset,
        segment.vaddr,
        segment.bytes.len()
    );

    let mut failed = false;
    let mut resolved = HashMap::new();
    for group in group_scan_entries(&entries) {
        let entry = group[0];
        match resolve_entry_group(segment.bytes, &group) {
            Ok(result) => {
                if group.len() == 1 {
                    println!(
                        "  OK   {:<58} text+0x{:x} va=0x{:x} hits={}",
                        entry.name,
                        result.target_offset,
                        segment.vaddr + result.target_offset as u64,
                        result.match_count
                    );
                } else {
                    println!(
                        "  OK   {:<58} text+0x{:x} va=0x{:x} hits={} variant={}/{}",
                        entry.name,
                        result.target_offset,
                        segment.vaddr + result.target_offset as u64,
                        result.match_count,
                        result.variant_index + 1,
                        group.len()
                    );
                }
                resolved.insert(entry.name.as_str(), result.target_offset);
            }
            Err(error) => {
                let severity = if entry.optional {
                    "optional"
                } else {
                    failed = true;
                    "required"
                };
                println!(
                    "  {:<4} {:<58} hits={} {} ({})",
                    error.label(),
                    entry.name,
                    error.match_count(),
                    severity,
                    error
                );
            }
        }
    }

    if module == "steamclient" {
        failed |= scan_public_wrapper_collisions(path, segment.vaddr, &resolved);
        failed |= if is_elf64 {
            scan_steamclient64_layouts(segment.bytes, segment.vaddr, &resolved)
        } else {
            scan_steamclient32_layouts(segment.bytes, segment.vaddr, &resolved)
        };
    } else if module == "steamui" {
        failed |= if is_elf64 {
            scan_steamui64_layouts(segment.bytes, segment.vaddr, &resolved)
        } else {
            scan_steamui32_layouts(segment.bytes, segment.vaddr, &resolved)
        };
    }
    failed |= scan_semantic_coverage(
        module,
        if is_elf64 {
            SemanticArch::X86_64
        } else {
            SemanticArch::X86
        },
        &entries,
    );
    println!();

    Ok(failed)
}

fn group_scan_entries<'a>(entries: &[&'a ScanEntry]) -> Vec<Vec<&'a ScanEntry>> {
    let mut groups: Vec<Vec<&ScanEntry>> = Vec::new();
    for &entry in entries {
        if let Some(group) = groups
            .last_mut()
            .filter(|group| group[0].name == entry.name && group[0].module == entry.module)
        {
            group.push(entry);
        } else {
            groups.push(vec![entry]);
        }
    }
    groups
}

fn scan_public_wrapper_collisions(
    path: &Path,
    text_vaddr: u64,
    resolved: &HashMap<&str, usize>,
) -> bool {
    let interfaces = vtable_scan::DEFAULT_INTERFACES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let report = match vtable_scan::scan_file(path, Some(&interfaces)) {
        Ok(report) => report,
        Err(error) => {
            println!("  WARN {:<58} {}", "IClient public wrapper check", error);
            return false;
        }
    };

    let mut failed = false;
    let mut allowed = 0usize;
    let mut implementation_required = 0usize;
    for (&entry_name, &target_offset) in resolved {
        let policy = wrapper_policy(entry_name);
        let Some(method_name) = entry_name.rsplit("::").next() else {
            continue;
        };
        let target_va = text_vaddr + target_offset as u64;
        for iface in &report.interfaces {
            if !iface.name.starts_with("IClient") {
                continue;
            }
            for method in &iface.methods {
                if method.name == method_name && method.func_va == target_va {
                    match policy {
                        WrapperPolicy::ImplementationRequired => {
                            println!(
                                "  FAIL {:<58} va=0x{:x} matches public {}::{} slot {}",
                                entry_name, target_va, iface.name, method.name, method.slot
                            );
                            print_possible_implementations(path, &iface.name, method.slot);
                            failed = true;
                            implementation_required += 1;
                        }
                        WrapperPolicy::WrapperAllowed => {
                            allowed += 1;
                        }
                        WrapperPolicy::NotApplicable => {}
                    }
                }
            }
        }
    }

    if !failed {
        println!(
            "  OK   {:<58} allowed={} blocked={}",
            "IClient public wrapper policy", allowed, implementation_required
        );
    }

    failed
}

fn print_possible_implementations(path: &Path, interface_name: &str, slot: usize) {
    let candidates = match discover_possible_implementations(path, interface_name, slot) {
        Ok(candidates) => candidates,
        Err(error) => {
            println!("       possible implementations: unavailable ({})", error);
            return;
        }
    };

    if candidates.is_empty() {
        println!("       possible implementations: none found by slot");
        return;
    }

    for candidate in candidates.into_iter().take(8) {
        if candidate.func_va == candidate.resolved_va {
            println!(
                "       possible implementation: {} slot {} func=0x{:x}",
                candidate.class_name, candidate.slot, candidate.func_va
            );
        } else {
            println!(
                "       possible implementation: {} slot {} func=0x{:x} -> 0x{:x}",
                candidate.class_name, candidate.slot, candidate.func_va, candidate.resolved_va
            );
        }
    }
}

#[derive(Clone, Debug)]
struct ImplementationCandidate {
    class_name: String,
    slot: usize,
    func_va: u64,
    resolved_va: u64,
    rank: usize,
}

fn discover_possible_implementations(
    path: &Path,
    interface_name: &str,
    slot: usize,
) -> Result<Vec<ImplementationCandidate>, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let image = DiagnosticImage::parse(&data)?;
    let mut candidates = Vec::new();

    for (vtable_va, slots) in find_diagnostic_vtables(&image) {
        if slot >= slots.len() {
            continue;
        }
        let Some(class_name) = diagnostic_typeinfo_name(&image, vtable_va) else {
            continue;
        };
        if class_name.starts_with("IClient") {
            continue;
        }

        let func_va = slots[slot];
        let resolved_va = follow_diagnostic_thunk(&image, func_va).unwrap_or(func_va);
        candidates.push(ImplementationCandidate {
            rank: implementation_candidate_rank(interface_name, &class_name),
            class_name,
            slot,
            func_va,
            resolved_va,
        });
    }

    candidates.sort_by(|a, b| {
        a.rank
            .cmp(&b.rank)
            .then_with(|| a.class_name.cmp(&b.class_name))
            .then_with(|| a.func_va.cmp(&b.func_va))
    });
    candidates.dedup_by(|a, b| {
        a.class_name == b.class_name && a.func_va == b.func_va && a.resolved_va == b.resolved_va
    });
    Ok(candidates)
}

fn implementation_candidate_rank(interface_name: &str, class_name: &str) -> usize {
    let wanted = interface_name.trim_start_matches("IClient");
    if class_name == format!("C{wanted}") {
        return 0;
    }
    if class_name.contains(wanted) {
        return 1;
    }
    match interface_name {
        "IClientUser" if class_name == "CUser" => 0,
        "IClientRemoteStorage" if class_name.contains("RemoteStorage") => 0,
        "IClientApps" if class_name.contains("Apps") => 0,
        "IClientAppManager" if class_name.contains("AppManager") => 0,
        _ => 10,
    }
}

fn follow_diagnostic_thunk(image: &DiagnosticImage<'_>, func_va: u64) -> Option<u64> {
    match image.class {
        ElfClass::Elf64 => follow_diagnostic_thunk_x64(image, func_va),
        ElfClass::Elf32 => follow_diagnostic_thunk_x86(image, func_va),
    }
}

fn follow_diagnostic_thunk_x64(image: &DiagnosticImage<'_>, func_va: u64) -> Option<u64> {
    if image.read_u8_va(func_va) == Some(0xe9) {
        return relative_target(image, func_va, 1, 5);
    }
    if image.read_u8_va(func_va) == Some(0x48)
        && image.read_u8_va(func_va + 1) == Some(0x81)
        && image
            .read_u8_va(func_va + 2)
            .is_some_and(|modrm| modrm & 0xf8 == 0xe8)
        && image.read_u8_va(func_va + 7) == Some(0xe9)
    {
        return relative_target(image, func_va + 7, 1, 5);
    }
    if image.read_u8_va(func_va) == Some(0x48)
        && image.read_u8_va(func_va + 1) == Some(0x83)
        && image
            .read_u8_va(func_va + 2)
            .is_some_and(|modrm| modrm & 0xf8 == 0xe8)
        && image.read_u8_va(func_va + 4) == Some(0xe9)
    {
        return relative_target(image, func_va + 4, 1, 5);
    }
    None
}

fn follow_diagnostic_thunk_x86(image: &DiagnosticImage<'_>, func_va: u64) -> Option<u64> {
    if image.read_u8_va(func_va) == Some(0xe9) {
        return relative_target(image, func_va, 1, 5);
    }
    if image.read_u8_va(func_va) == Some(0x81)
        && image
            .read_u8_va(func_va + 1)
            .is_some_and(|modrm| modrm & 0xf8 == 0xe8)
        && image.read_u8_va(func_va + 6) == Some(0xe9)
    {
        return relative_target(image, func_va + 6, 1, 5);
    }
    if image.read_u8_va(func_va) == Some(0x83)
        && image
            .read_u8_va(func_va + 1)
            .is_some_and(|modrm| modrm & 0xf8 == 0xe8)
        && image.read_u8_va(func_va + 3) == Some(0xe9)
    {
        return relative_target(image, func_va + 3, 1, 5);
    }
    None
}

fn relative_target(
    image: &DiagnosticImage<'_>,
    instr_va: u64,
    disp_offset: u64,
    instr_len: u64,
) -> Option<u64> {
    let disp = image.read_i32_va(instr_va + disp_offset)?;
    let target = instr_va
        .wrapping_add(instr_len)
        .wrapping_add_signed(disp as i64);
    image.in_text(target).then_some(target)
}

struct DiagnosticImage<'a> {
    data: &'a [u8],
    class: ElfClass,
    loads: Vec<DiagnosticLoadSegment>,
}

#[derive(Clone, Copy)]
struct DiagnosticLoadSegment {
    offset: u64,
    vaddr: u64,
    filesz: u64,
    flags: u32,
}

impl<'a> DiagnosticImage<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.get(..4) != Some(b"\x7fELF") {
            return Err("input is not an ELF file".to_owned());
        }
        if data.get(5) != Some(&1) {
            return Err("big-endian ELF files are not supported".to_owned());
        }
        let class = match data.get(4) {
            Some(1) => ElfClass::Elf32,
            Some(2) => ElfClass::Elf64,
            _ => return Err("unsupported ELF class".to_owned()),
        };
        let loads = match class {
            ElfClass::Elf32 => diagnostic_loads_elf32(data)?,
            ElfClass::Elf64 => diagnostic_loads_elf64(data)?,
        };
        Ok(Self { data, class, loads })
    }

    fn word_size(&self) -> usize {
        match self.class {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        }
    }

    fn va_to_offset(&self, va: u64) -> Option<usize> {
        for load in &self.loads {
            let end = load.vaddr.checked_add(load.filesz)?;
            if va >= load.vaddr && va < end {
                return Some((load.offset + (va - load.vaddr)) as usize);
            }
        }
        None
    }

    fn in_text(&self, va: u64) -> bool {
        self.loads
            .iter()
            .any(|load| load.flags & PF_X != 0 && va >= load.vaddr && va < load.vaddr + load.filesz)
    }

    fn in_module(&self, va: u64) -> bool {
        self.loads
            .iter()
            .any(|load| va >= load.vaddr && va < load.vaddr + load.filesz)
    }

    fn read_word_va(&self, va: u64) -> Option<u64> {
        let offset = self.va_to_offset(va)?;
        match self.class {
            ElfClass::Elf32 => read_u32(self.data, offset).ok().map(u64::from),
            ElfClass::Elf64 => read_u64(self.data, offset).ok(),
        }
    }

    fn read_i32_va(&self, va: u64) -> Option<i32> {
        let offset = self.va_to_offset(va)?;
        let bytes = self.data.get(offset..offset + 4)?;
        Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u8_va(&self, va: u64) -> Option<u8> {
        self.data.get(self.va_to_offset(va)?).copied()
    }

    fn read_cstring(&self, va: u64) -> String {
        let Some(offset) = self.va_to_offset(va) else {
            return String::new();
        };
        let mut out = String::new();
        for &byte in self.data[offset..].iter().take(96) {
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
}

fn diagnostic_loads_elf32(data: &[u8]) -> Result<Vec<DiagnosticLoadSegment>, String> {
    let phoff = read_u32(data, 28)? as usize;
    let phentsize = read_u16(data, 42)? as usize;
    let phnum = read_u16(data, 44)? as usize;
    let mut loads = Vec::new();

    for idx in 0..phnum {
        let off = phoff + idx * phentsize;
        let p_type = read_u32(data, off)?;
        if p_type != PT_LOAD {
            continue;
        }
        loads.push(DiagnosticLoadSegment {
            offset: read_u32(data, off + 4)? as u64,
            vaddr: read_u32(data, off + 8)? as u64,
            filesz: read_u32(data, off + 16)? as u64,
            flags: read_u32(data, off + 24)?,
        });
    }

    Ok(loads)
}

fn diagnostic_loads_elf64(data: &[u8]) -> Result<Vec<DiagnosticLoadSegment>, String> {
    let phoff = read_u64(data, 32)? as usize;
    let phentsize = read_u16(data, 54)? as usize;
    let phnum = read_u16(data, 56)? as usize;
    let mut loads = Vec::new();

    for idx in 0..phnum {
        let off = phoff + idx * phentsize;
        let p_type = read_u32(data, off)?;
        if p_type != PT_LOAD {
            continue;
        }
        loads.push(DiagnosticLoadSegment {
            flags: read_u32(data, off + 4)?,
            offset: read_u64(data, off + 8)?,
            vaddr: read_u64(data, off + 16)?,
            filesz: read_u64(data, off + 32)?,
        });
    }

    Ok(loads)
}

fn find_diagnostic_vtables(image: &DiagnosticImage<'_>) -> Vec<(u64, Vec<u64>)> {
    let word = image.word_size() as u64;
    let mut out = Vec::new();

    for load in &image.loads {
        if load.flags & PF_X != 0 {
            continue;
        }
        let mut p = load.vaddr + 2 * word;
        let end = load.vaddr + load.filesz;
        while p + word <= end {
            let Some(method0_raw) = image.read_word_va(p) else {
                break;
            };
            if !image.in_text(method0_raw) {
                p += word;
                continue;
            }

            let ti = image.read_word_va(p - word).unwrap_or(0);
            if ti == 0 || !image.in_module(ti) {
                p += word;
                continue;
            }

            let mut slots = Vec::with_capacity(64);
            slots.push(method0_raw);
            let mut q = p + word;
            while q + word <= end {
                let Some(raw) = image.read_word_va(q) else {
                    break;
                };
                if !image.in_text(raw) {
                    break;
                }
                slots.push(raw);
                if slots.len() >= 250 {
                    break;
                }
                q += word;
            }

            if slots.len() >= 3 {
                out.push((p, slots));
            }
            p += word;
        }
    }

    out
}

fn diagnostic_typeinfo_name(image: &DiagnosticImage<'_>, vtable_va: u64) -> Option<String> {
    let word = image.word_size() as u64;
    let ti = image.read_word_va(vtable_va.checked_sub(word)?)?;
    if !image.in_module(ti) {
        return None;
    }
    let name_va = image.read_word_va(ti.checked_add(word)?)?;
    if !image.in_module(name_va) {
        return None;
    }
    let name = image.read_cstring(name_va);
    let (digits, body) = split_decimal_prefix(&name)?;
    if body.len() != digits {
        return None;
    }
    Some(body.trim_end_matches("Map").to_owned())
}

fn split_decimal_prefix(text: &str) -> Option<(usize, &str)> {
    let split = text
        .as_bytes()
        .iter()
        .position(|byte| !byte.is_ascii_digit())?;
    if split == 0 {
        return None;
    }
    let value = text[..split].parse().ok()?;
    Some((value, &text[split..]))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WrapperPolicy {
    ImplementationRequired,
    WrapperAllowed,
    NotApplicable,
}

fn wrapper_policy(name: &str) -> WrapperPolicy {
    match name {
        "IClientRemoteStorage::RunIPCFrame"
        | "IClientAppManager::RunIPCFrame"
        | "IClientApps::RunIPCFrame" => WrapperPolicy::WrapperAllowed,
        "IClientUser::BUpdateAppOwnershipTicket"
        | "IClientUser::GetAppOwnershipTicketExtendedData"
        | "IClientUser::IsUserSubscribedAppInTicket" => WrapperPolicy::ImplementationRequired,
        _ if name.starts_with("IClient") => WrapperPolicy::ImplementationRequired,
        _ => WrapperPolicy::NotApplicable,
    }
}

struct SemanticCheck {
    name: &'static str,
    label: &'static str,
    validate: fn(&[u8], usize) -> Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticArch {
    X86,
    X86_64,
}

#[derive(Debug, Default)]
struct Evidence {
    missing: Vec<&'static str>,
}

impl Evidence {
    fn required<const N: usize>(requirements: [(&'static str, bool); N]) -> Self {
        let mut evidence = Self::default();
        for (label, present) in requirements {
            evidence.require(label, present);
        }
        evidence
    }

    fn require(&mut self, label: &'static str, present: bool) {
        if !present {
            self.missing.push(label);
        }
    }

    fn reject(&mut self, label: &'static str, present: bool) {
        if present {
            self.missing.push(label);
        }
    }

    fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    fn describe(&self) -> String {
        if self.missing.is_empty() {
            "semantic validation failed".to_owned()
        } else {
            format!("missing {}", self.missing.join(", "))
        }
    }
}

fn evidence_result(evidence: Option<Evidence>, detail: &'static str) -> Option<&'static str> {
    evidence?.is_complete().then_some(detail)
}

const STEAMCLIENT32_SEMANTIC_CHECKS: &[SemanticCheck] = &[
    SemanticCheck {
        name: "CUser::CheckAppOwnership",
        label: "CUser::CheckAppOwnership body",
        validate: validate_check_app_ownership32,
    },
    SemanticCheck {
        name: "CUser::GetSubscribedApps",
        label: "CUser::GetSubscribedApps body",
        validate: validate_get_subscribed_apps32,
    },
    SemanticCheck {
        name: "IClientRemoteStorage::RunIPCFrame",
        label: "IClientRemoteStorage::RunIPCFrame body",
        validate: validate_ipc_run_frame32,
    },
    SemanticCheck {
        name: "IClientAppManager::RunIPCFrame",
        label: "IClientAppManager::RunIPCFrame body",
        validate: validate_ipc_run_frame32,
    },
    SemanticCheck {
        name: "IClientApps::RunIPCFrame",
        label: "IClientApps::RunIPCFrame body",
        validate: validate_ipc_run_frame32,
    },
    SemanticCheck {
        name: "LoadDepotDecryptionKey",
        label: "LoadDepotDecryptionKey body",
        validate: validate_load_depot_key32,
    },
    SemanticCheck {
        name: "BuildDepotDependency",
        label: "BuildDepotDependency body",
        validate: validate_build_depot_dependency32,
    },
    SemanticCheck {
        name: "CWebSocketConnection::BBuildAndAsyncSendFrame",
        label: "CWebSocketConnection::BBuildAndAsyncSendFrame body",
        validate: validate_websocket_send_frame32,
    },
    SemanticCheck {
        name: "CCMConnection::RecvPkt",
        label: "CCMConnection::RecvPkt body",
        validate: validate_ccm_recv_pkt32,
    },
    SemanticCheck {
        name: "CUser::MarkLicenseAsChanged",
        label: "CUser::MarkLicenseAsChanged body",
        validate: validate_mark_license_changed32,
    },
    SemanticCheck {
        name: "CUser::ProcessPendingLicenseUpdates",
        label: "CUser::ProcessPendingLicenseUpdates body",
        validate: validate_process_pending_license_updates32,
    },
    SemanticCheck {
        name: "CUtlMemory::Grow",
        label: "CUtlMemory::Grow body",
        validate: validate_cutl_memory_grow32,
    },
    SemanticCheck {
        name: "CConfigStore::WriteVdfFile",
        label: "CConfigStore::WriteVdfFile body",
        validate: validate_write_vdf_file32,
    },
    SemanticCheck {
        name: "CUser::SpawnProcess",
        label: "CUser::SpawnProcess body",
        validate: validate_spawn_process32,
    },
    SemanticCheck {
        name: "CUser::BuildSpawnEnvBlock",
        label: "CUser::BuildSpawnEnvBlock body",
        validate: validate_build_spawn_env_block32,
    },
    SemanticCheck {
        name: "SetEnvString",
        label: "SetEnvString body",
        validate: validate_set_env_string32,
    },
];

const STEAMCLIENT64_SEMANTIC_CHECKS: &[SemanticCheck] = &[
    SemanticCheck {
        name: "CUser::CheckAppOwnership",
        label: "CUser::CheckAppOwnership body",
        validate: validate_check_app_ownership64,
    },
    SemanticCheck {
        name: "CUser::GetSubscribedApps",
        label: "CUser::GetSubscribedApps body",
        validate: validate_get_subscribed_apps64,
    },
    SemanticCheck {
        name: "IClientRemoteStorage::RunIPCFrame",
        label: "IClientRemoteStorage::RunIPCFrame body",
        validate: validate_ipc_run_frame64,
    },
    SemanticCheck {
        name: "IClientAppManager::RunIPCFrame",
        label: "IClientAppManager::RunIPCFrame body",
        validate: validate_ipc_run_frame64,
    },
    SemanticCheck {
        name: "IClientApps::RunIPCFrame",
        label: "IClientApps::RunIPCFrame body",
        validate: validate_ipc_run_frame64,
    },
    SemanticCheck {
        name: "LoadDepotDecryptionKey",
        label: "LoadDepotDecryptionKey body",
        validate: validate_load_depot_key64,
    },
    SemanticCheck {
        name: "BuildDepotDependency",
        label: "BuildDepotDependency body",
        validate: validate_build_depot_dependency64,
    },
    SemanticCheck {
        name: "CWebSocketConnection::BBuildAndAsyncSendFrame",
        label: "CWebSocketConnection::BBuildAndAsyncSendFrame body",
        validate: validate_websocket_send_frame64,
    },
    SemanticCheck {
        name: "CCMConnection::RecvPkt",
        label: "CCMConnection::RecvPkt body",
        validate: validate_ccm_recv_pkt64,
    },
    SemanticCheck {
        name: "CUser::MarkLicenseAsChanged",
        label: "CUser::MarkLicenseAsChanged body",
        validate: validate_mark_license_changed64,
    },
    SemanticCheck {
        name: "CUser::ProcessPendingLicenseUpdates",
        label: "CUser::ProcessPendingLicenseUpdates body",
        validate: validate_process_pending_license_updates64,
    },
    SemanticCheck {
        name: "CUtlMemory::Grow",
        label: "CUtlMemory::Grow body",
        validate: validate_cutl_memory_grow64,
    },
    SemanticCheck {
        name: "CConfigStore::WriteVdfFile",
        label: "CConfigStore::WriteVdfFile body",
        validate: validate_write_vdf_file64,
    },
    SemanticCheck {
        name: "CUser::SpawnProcess",
        label: "CUser::SpawnProcess body",
        validate: validate_spawn_process64,
    },
    SemanticCheck {
        name: "CUser::BuildSpawnEnvBlock",
        label: "CUser::BuildSpawnEnvBlock body",
        validate: validate_build_spawn_env_block64,
    },
    SemanticCheck {
        name: "SetEnvString",
        label: "SetEnvString body",
        validate: validate_set_env_string64,
    },
];

const STEAMUI32_SEMANTIC_CHECKS: &[SemanticCheck] = &[
    SemanticCheck {
        name: "CSteamUIAppController::RunFrame",
        label: "CSteamUIAppController::RunFrame body",
        validate: validate_steamui_run_frame32,
    },
    SemanticCheck {
        name: "CSteamUIAppController::FillInAppOverview",
        label: "CSteamUIAppController::FillInAppOverview body",
        validate: validate_fill_in_app_overview32,
    },
    SemanticCheck {
        name: "CSteamUIAppController::BuildCompleteAppOverviewChange",
        label: "CSteamUIAppController::BuildCompleteAppOverviewChange body",
        validate: validate_build_complete_app_overview_change32,
    },
    SemanticCheck {
        name: "CSteamUIAppController::GetAppByID",
        label: "CSteamUIAppController::GetAppByID body",
        validate: validate_get_app_by_id32,
    },
    SemanticCheck {
        name: "CUpdateManager::MarkAppChange",
        label: "CUpdateManager::MarkAppChange body",
        validate: validate_mark_app_change32,
    },
    SemanticCheck {
        name: "google::protobuf::RepeatedField<uint32>::Add",
        label: "google::protobuf::RepeatedField<uint32>::Add body",
        validate: validate_repeated_field_add32,
    },
];

const STEAMUI64_SEMANTIC_CHECKS: &[SemanticCheck] = &[
    SemanticCheck {
        name: "CSteamUIAppController::RunFrame",
        label: "CSteamUIAppController::RunFrame body",
        validate: validate_steamui_run_frame64,
    },
    SemanticCheck {
        name: "CSteamUIAppController::FillInAppOverview",
        label: "CSteamUIAppController::FillInAppOverview body",
        validate: validate_fill_in_app_overview64,
    },
    SemanticCheck {
        name: "CSteamUIAppController::BuildCompleteAppOverviewChange",
        label: "CSteamUIAppController::BuildCompleteAppOverviewChange body",
        validate: validate_build_complete_app_overview_change64,
    },
    SemanticCheck {
        name: "CSteamUIAppController::GetAppByID",
        label: "CSteamUIAppController::GetAppByID body",
        validate: validate_get_app_by_id64,
    },
    SemanticCheck {
        name: "CUpdateManager::MarkAppChange",
        label: "CUpdateManager::MarkAppChange body",
        validate: validate_mark_app_change64,
    },
    SemanticCheck {
        name: "google::protobuf::RepeatedField<uint32>::Add",
        label: "google::protobuf::RepeatedField<uint32>::Add body",
        validate: validate_repeated_field_add64,
    },
];

const STEAMCLIENT_SPECIAL_SEMANTIC_CHECKS: &[&str] = &[
    "IClientUser::GetAppOwnershipTicketExtendedData",
    "IClientUser::BUpdateAppOwnershipTicket",
    "IClientUser::IsUserSubscribedAppInTicket",
    "CPackageInfo::GetPackageInfo",
];

fn has_semantic_validation(module: &str, arch: SemanticArch, name: &str) -> bool {
    let checks = match (module, arch) {
        ("steamclient", SemanticArch::X86) => STEAMCLIENT32_SEMANTIC_CHECKS,
        ("steamclient", SemanticArch::X86_64) => STEAMCLIENT64_SEMANTIC_CHECKS,
        ("steamui", SemanticArch::X86) => STEAMUI32_SEMANTIC_CHECKS,
        ("steamui", SemanticArch::X86_64) => STEAMUI64_SEMANTIC_CHECKS,
        _ => &[],
    };

    checks.iter().any(|check| check.name == name)
        || (module == "steamclient" && STEAMCLIENT_SPECIAL_SEMANTIC_CHECKS.contains(&name))
}

fn scan_semantic_coverage(module: &str, arch: SemanticArch, entries: &[&ScanEntry]) -> bool {
    let mut failed = false;
    for group in group_scan_entries(entries) {
        let entry = group[0];
        if !has_semantic_validation(module, arch, &entry.name) {
            println!(
                "  FAIL {:<58} required (no semantic validation registered)",
                entry.name
            );
            failed = true;
        }
    }
    failed
}

fn scan_semantic_checks(
    code: &[u8],
    vaddr: u64,
    resolved: &HashMap<&str, usize>,
    checks: &[SemanticCheck],
    arch: SemanticArch,
) -> bool {
    let mut failed = false;
    for check in checks {
        let Some(&offset) = resolved.get(check.name) else {
            continue;
        };
        match (check.validate)(code, offset) {
            Some(detail) => println!("  OK   {:<58} {}", check.label, detail),
            None => {
                let detail = semantic_failure_evidence(arch, check.name, code, offset)
                    .map(|evidence| evidence.describe())
                    .unwrap_or_else(|| "semantic validation failed".to_owned());
                println!(
                    "  FAIL {:<58} va=0x{:x} required ({})",
                    check.label,
                    vaddr + offset as u64,
                    detail
                );
                failed = true;
            }
        }
    }
    failed
}

fn print_evidence_failure(
    label: &str,
    vaddr: u64,
    evidence: Option<&Evidence>,
    fallback: &'static str,
) {
    let detail = evidence
        .map(Evidence::describe)
        .unwrap_or_else(|| fallback.to_owned());
    println!(
        "  FAIL {:<58} va=0x{:x} required ({})",
        label, vaddr, detail
    );
}

fn scan_steamui64_layouts(code: &[u8], vaddr: u64, resolved: &HashMap<&str, usize>) -> bool {
    let mut failed = false;
    failed |= scan_semantic_checks(
        code,
        vaddr,
        resolved,
        &STEAMUI64_SEMANTIC_CHECKS,
        SemanticArch::X86_64,
    );

    if let Some(&add_offset) = resolved.get("google::protobuf::RepeatedField<uint32>::Add") {
        if is_x64_reflection_repeated_field_setter(code, add_offset) {
            println!(
                "  FAIL {:<58} va=0x{:x} required (resolved protobuf reflection helper, not 2-arg Add ABI)",
                "google::protobuf::RepeatedField<uint32>::Add ABI",
                vaddr + add_offset as u64
            );
            failed = true;
        }
    }

    if let Some(&fill_offset) = resolved.get("CSteamUIAppController::FillInAppOverview") {
        match discover_steam_app64_layout(code, fill_offset) {
            Some(layout) => println!(
                "  OK   {:<58} game_id=0x{:x} app_id=0x{:x} purchased_time=0x{:x}",
                "CSteamApp layout",
                layout.game_id_off,
                layout.app_id_off,
                layout.purchased_time_off
            ),
            None => {
                let evidence = fill_in_app_overview64_evidence(code, fill_offset);
                print_evidence_failure(
                    "CSteamApp layout",
                    vaddr + fill_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    if let Some(&build_offset) =
        resolved.get("CSteamUIAppController::BuildCompleteAppOverviewChange")
    {
        match discover_app_overview_change64_layout(code, build_offset) {
            Some(layout) => println!(
                "  OK   {:<58} app_overview=0x{:x} removed_appid=0x{:x}",
                "CAppOverviewChange layout", layout.app_overview_off, layout.removed_appid_off
            ),
            None => {
                let evidence = build_complete_app_overview_change64_evidence(code, build_offset);
                print_evidence_failure(
                    "CAppOverviewChange layout",
                    vaddr + build_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    failed
}

fn scan_steamui32_layouts(code: &[u8], vaddr: u64, resolved: &HashMap<&str, usize>) -> bool {
    let mut failed = false;
    failed |= scan_semantic_checks(
        code,
        vaddr,
        resolved,
        &STEAMUI32_SEMANTIC_CHECKS,
        SemanticArch::X86,
    );

    if let Some(&fill_offset) = resolved.get("CSteamUIAppController::FillInAppOverview") {
        match discover_steam_app32_layout(code, fill_offset) {
            Some(layout) => println!(
                "  OK   {:<58} game_id=0x{:x} app_id=0x{:x} purchased_time=0x{:x}",
                "CSteamApp layout",
                layout.game_id_off,
                layout.app_id_off,
                layout.purchased_time_off
            ),
            None => {
                let evidence = fill_in_app_overview32_evidence(code, fill_offset);
                print_evidence_failure(
                    "CSteamApp layout",
                    vaddr + fill_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    if let Some(&build_offset) =
        resolved.get("CSteamUIAppController::BuildCompleteAppOverviewChange")
    {
        match discover_app_overview_change32_layout(code, build_offset) {
            Some(layout) => println!(
                "  OK   {:<58} app_overview=0x{:x} removed_appid=0x{:x}",
                "CAppOverviewChange layout", layout.app_overview_off, layout.removed_appid_off
            ),
            None => {
                let evidence = build_complete_app_overview_change32_evidence(code, build_offset);
                print_evidence_failure(
                    "CAppOverviewChange layout",
                    vaddr + build_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    failed
}

fn is_x64_reflection_repeated_field_setter(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = code.get(offset..offset.saturating_add(0x40)) else {
        return false;
    };

    // The known bad x86_64 match is a protobuf reflection setter reached by
    // a tail-jump thunk. It consumes rdx/ecx/r8 in addition to rdi/rsi, so it
    // is not callable as RepeatedFieldAddFn(field, &value).
    bytes.starts_with(&[
        0x41, 0x55, // push r13
        0x48, 0x83, 0xc7, 0x08, // add rdi, 8
    ]) && bytes.windows(3).any(|w| w == [0x45, 0x89, 0xc5])
        && bytes.windows(3).any(|w| w == [0x41, 0x89, 0xcc])
        && bytes.windows(3).any(|w| w == [0x48, 0x89, 0xd5])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SteamAppLayout {
    game_id_off: usize,
    app_id_off: usize,
    purchased_time_off: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AppOverviewChangeLayout {
    app_overview_off: usize,
    removed_appid_off: usize,
}

fn discover_steam_app64_layout(
    code: &[u8],
    fill_in_app_overview_offset: usize,
) -> Option<SteamAppLayout> {
    let bytes = bounded_tail(code, fill_in_app_overview_offset, 0x900)?;

    let game_id_off = find_x64_rbp_dword_or_qword_load(bytes, 0x08)?;
    let app_id_off = find_x64_rbp_dword_or_qword_load(bytes, 0x10)?;
    let purchased_time_off = find_x64_rbp_dword_or_qword_load(bytes, 0x2c)?;

    Some(SteamAppLayout {
        game_id_off,
        app_id_off,
        purchased_time_off,
    })
}

fn discover_steam_app32_layout(
    code: &[u8],
    fill_in_app_overview_offset: usize,
) -> Option<SteamAppLayout> {
    let bytes = bounded_tail(code, fill_in_app_overview_offset, 0x900)?;

    let game_id_off = find_x86_steam_app_game_id_load(bytes)?;
    let app_id_off = find_x86_any_reg_disp8_load(bytes, 0x0c)?;
    let purchased_time_off = find_x86_any_reg_disp8_load(bytes, 0x28)?;

    Some(SteamAppLayout {
        game_id_off,
        app_id_off,
        purchased_time_off,
    })
}

fn discover_app_overview_change64_layout(
    code: &[u8],
    build_complete_offset: usize,
) -> Option<AppOverviewChangeLayout> {
    let bytes = bounded_tail(code, build_complete_offset, 0x200)?;
    if !bytes.windows(4).any(|w| w == [0x48, 0x8d, 0x7b, 0x18]) {
        return None;
    }
    if !bytes.windows(4).any(|w| w == [0xc6, 0x43, 0x40, 0x01])
        || !bytes.windows(4).any(|w| w == [0x83, 0x4b, 0x10, 0x01])
    {
        return None;
    }
    Some(AppOverviewChangeLayout {
        app_overview_off: 0x18,
        removed_appid_off: 0x28,
    })
}

fn discover_app_overview_change32_layout(
    code: &[u8],
    build_complete_offset: usize,
) -> Option<AppOverviewChangeLayout> {
    let bytes = bounded_tail(code, build_complete_offset, 0x120)?;
    if !bytes.windows(3).any(|w| w == [0x83, 0xc2, 0x10]) {
        return None;
    }
    if !bytes.windows(4).any(|w| w == [0xc6, 0x42, 0x2c, 0x01])
        || !bytes.windows(4).any(|w| w == [0x83, 0x4a, 0x08, 0x01])
    {
        return None;
    }
    Some(AppOverviewChangeLayout {
        app_overview_off: 0x10,
        removed_appid_off: 0x1c,
    })
}

fn bounded_tail(bytes: &[u8], offset: usize, max_len: usize) -> Option<&[u8]> {
    let tail = bytes.get(offset..)?;
    Some(&tail[..tail.len().min(max_len)])
}

fn has_seq(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && bytes.windows(needle.len()).any(|w| w == needle)
}

fn has_x86_cmp_eax_any_imm32(bytes: &[u8], values: &[u32]) -> bool {
    values
        .iter()
        .any(|&value| has_x86_cmp_eax_imm32(bytes, value))
}

fn has_asm32(
    bytes: &[u8],
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> bool {
    has_asm(bytes, 32, build)
}

fn asm_bytes32(
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> Option<Vec<u8>> {
    asm_bytes(32, build)
}

fn has_asm64(
    bytes: &[u8],
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> bool {
    has_asm(bytes, 64, build)
}

fn asm_bytes64(
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> Option<Vec<u8>> {
    asm_bytes(64, build)
}

fn has_asm(
    bytes: &[u8],
    bitness: u32,
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> bool {
    let Some(needle) = asm_bytes(bitness, build) else {
        return false;
    };
    has_seq(bytes, &needle)
}

fn asm_bytes(
    bitness: u32,
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> Option<Vec<u8>> {
    let Ok(mut asm) = iced_x86::code_asm::CodeAssembler::new(bitness) else {
        return None;
    };
    if build(&mut asm).is_err() {
        return None;
    }
    let Ok(needle) = asm.assemble(0) else {
        return None;
    };
    Some(needle)
}

fn has_x86_mov_from_esi_disp8(bytes: &[u8], disp: u8) -> bool {
    bytes.windows(3).any(|w| {
        w[0] == 0x8b && (0x40..=0x7f).contains(&w[1]) && (w[1] & 0x07) == 0x06 && w[2] == disp
    })
}

fn has_x86_mov_from_any_disp8(bytes: &[u8], disp: u8) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == 0x8b && (0x40..=0x7f).contains(&w[1]) && w[2] == disp)
}

fn has_x86_mov_edi_from_esi_disp32(bytes: &[u8], accepted_disps: &[u32]) -> bool {
    bytes.windows(6).any(|w| {
        if w[0] != 0x8b || w[1] != 0xbe {
            return false;
        }
        let disp = u32::from_le_bytes([w[2], w[3], w[4], w[5]]);
        accepted_disps.is_empty() || accepted_disps.contains(&disp)
    })
}

fn has_x86_lea_eax_from_esi_disp32(bytes: &[u8], accepted_disps: &[u32]) -> bool {
    bytes.windows(6).any(|w| {
        if w[0] != 0x8d || w[1] != 0x86 {
            return false;
        }
        let disp = u32::from_le_bytes([w[2], w[3], w[4], w[5]]);
        accepted_disps.is_empty() || accepted_disps.contains(&disp)
    })
}

fn has_x86_license_vector_load32(bytes: &[u8]) -> bool {
    has_x86_mov_edi_from_esi_disp32(bytes, &[0x1B14, 0x1B18])
}

fn has_x86_license_vector_base32(bytes: &[u8]) -> bool {
    has_x86_lea_eax_from_esi_disp32(bytes, &[0x1AE4, 0x1AE8])
}

fn has_x86_shl_rm32_by_2(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == 0xc1 && (0xe0..=0xe7).contains(&w[1]) && w[2] == 0x02)
}

fn has_x86_and_eax_imm8(bytes: &[u8], imm: u8) -> bool {
    has_seq(bytes, &[0x83, 0xe0, imm])
}

fn has_x86_or_al_imm8(bytes: &[u8], imm: u8) -> bool {
    has_seq(bytes, &[0x0c, imm])
}

fn has_x86_sub_eax_imm8(bytes: &[u8], imm: u8) -> bool {
    has_seq(bytes, &[0x83, 0xe8, imm])
}

fn has_x86_cmp_eax_imm32(bytes: &[u8], imm: u32) -> bool {
    let imm = imm.to_le_bytes();
    bytes.windows(5).any(|w| w[0] == 0x3d && w[1..5] == imm)
}

fn has_x86_fstp_esp_disp8(bytes: &[u8], disp: u8) -> bool {
    has_seq(bytes, &[0xd9, 0x5c, 0x24, disp])
}

fn find_x86_sub_eax_imm32_matching(
    bytes: &[u8],
    mut matches_imm: impl FnMut(u32) -> bool,
) -> Option<u32> {
    bytes.windows(5).find_map(|w| {
        if w[0] != 0x2d {
            return None;
        }
        let imm = u32::from_le_bytes([w[1], w[2], w[3], w[4]]);
        matches_imm(imm).then_some(imm)
    })
}

fn has_x86_test_ebp_disp8_imm8(bytes: &[u8], disp: u8, imm: u8) -> bool {
    has_seq(bytes, &[0xf6, 0x45, disp, imm])
}

fn has_x86_cmp_rm32_imm8(bytes: &[u8], disp: u32, imm: u8) -> bool {
    let disp = disp.to_le_bytes();
    bytes
        .windows(7)
        .any(|w| w[0] == 0x83 && matches!(w[1], 0xb8..=0xbf) && w[2..6] == disp && w[6] == imm)
}

fn has_x86_rm32_disp32_load(bytes: &[u8], disp: u32) -> bool {
    let disp = disp.to_le_bytes();
    bytes
        .windows(6)
        .any(|w| w[0] == 0x8b && matches!(w[1], 0x80..=0xbf) && w[2..6] == disp)
}

fn has_x86_ebp_store_i32(bytes: &[u8], value: i32) -> bool {
    let value = value.to_le_bytes();
    bytes.windows(7).any(|w| {
        w[0] == 0xc7
            && matches!(w[1], 0x40..=0x7f)
            && w[3] == value[0]
            && w[4] == value[1]
            && w[5] == value[2]
            && w[6] == value[3]
    }) || bytes.windows(10).any(|w| {
        w[0] == 0xc7
            && matches!(w[1], 0x80..=0xbf)
            && w[6] == value[0]
            && w[7] == value[1]
            && w[8] == value[2]
            && w[9] == value[3]
    })
}

fn has_x86_call_after(bytes: &[u8], marker: &[u8], max_distance: usize) -> bool {
    bytes.windows(marker.len()).enumerate().any(|(idx, w)| {
        w == marker
            && bytes[idx + marker.len()..bytes.len().min(idx + marker.len() + max_distance)]
                .contains(&0xe8)
    })
}

fn has_asm32_call_after(
    bytes: &[u8],
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
    max_distance: usize,
) -> bool {
    let Some(marker) = asm_bytes32(build) else {
        return false;
    };
    has_x86_call_after(bytes, &marker, max_distance)
}

fn has_asm64_call_after(
    bytes: &[u8],
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
    max_distance: usize,
) -> bool {
    let Some(marker) = asm_bytes64(build) else {
        return false;
    };
    has_x86_call_after(bytes, &marker, max_distance)
}

fn has_x86_push_edx_call_after(bytes: &[u8], max_distance: usize) -> bool {
    has_x86_call_after(bytes, &[0x52], max_distance)
}

fn has_x64_rsp_store_cl(bytes: &[u8]) -> bool {
    bytes
        .windows(4)
        .any(|w| w[0] == 0x88 && w[1] == 0x4c && w[2] == 0x24)
}

fn has_x64_stack_spill_r32(bytes: &[u8], reg: u8) -> bool {
    let modrm = 0x44 | ((reg & 0x07) << 3);
    bytes
        .windows(4)
        .any(|w| w[0] == 0x89 && w[1] == modrm && w[2] == 0x24)
}

fn has_x64_movsd_rbp_disp32_from_xmm0(bytes: &[u8], disp: i32) -> bool {
    let disp = disp.to_le_bytes();
    bytes
        .windows(8)
        .any(|w| w[0] == 0xf2 && w[1] == 0x0f && w[2] == 0x11 && w[3] == 0x85 && w[4..8] == disp)
}

fn has_x64_push_rbp_negative_local_before_call(bytes: &[u8]) -> bool {
    bytes.windows(7).enumerate().any(|(idx, w)| {
        if w[0] != 0x48
            || w[1] != 0x8d
            || w[2] != 0x85
            || i32::from_le_bytes([w[3], w[4], w[5], w[6]]) >= 0
        {
            return false;
        }
        let after_lea = &bytes[idx + 7..bytes.len().min(idx + 0x50)];
        let Some(push_rax_at) = after_lea.iter().position(|&byte| byte == 0x50) else {
            return false;
        };
        after_lea[push_rax_at + 1..].contains(&0xe8)
    })
}

fn has_x64_rm32_disp32_load(bytes: &[u8], disp: u32) -> bool {
    let disp = disp.to_le_bytes();
    bytes
        .windows(6)
        .any(|w| w[0] == 0x8b && matches!(w[1], 0x80..=0xbf) && w[2..6] == disp)
        || bytes
            .windows(7)
            .any(|w| w[0] == 0x44 && w[1] == 0x8b && matches!(w[2], 0x80..=0xbf) && w[3..7] == disp)
}

fn has_x64_rip_lea(bytes: &[u8], modrm: u8) -> bool {
    bytes
        .windows(7)
        .any(|w| w[0] == 0x48 && w[1] == 0x8d && w[2] == modrm)
}

fn semantic_failure_evidence(
    arch: SemanticArch,
    name: &str,
    code: &[u8],
    offset: usize,
) -> Option<Evidence> {
    match (arch, name) {
        (SemanticArch::X86, "CUser::CheckAppOwnership") => {
            check_app_ownership32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::CheckAppOwnership") => {
            check_app_ownership64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUser::GetSubscribedApps") => {
            get_subscribed_apps32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::GetSubscribedApps") => {
            get_subscribed_apps64_evidence(code, offset)
        }
        (SemanticArch::X86, "IClientRemoteStorage::RunIPCFrame")
        | (SemanticArch::X86, "IClientAppManager::RunIPCFrame")
        | (SemanticArch::X86, "IClientApps::RunIPCFrame") => ipc_run_frame32_evidence(code, offset),
        (SemanticArch::X86_64, "IClientRemoteStorage::RunIPCFrame")
        | (SemanticArch::X86_64, "IClientAppManager::RunIPCFrame")
        | (SemanticArch::X86_64, "IClientApps::RunIPCFrame") => {
            ipc_run_frame64_evidence(code, offset)
        }
        (SemanticArch::X86, "LoadDepotDecryptionKey") => load_depot_key32_evidence(code, offset),
        (SemanticArch::X86_64, "LoadDepotDecryptionKey") => load_depot_key64_evidence(code, offset),
        (SemanticArch::X86, "BuildDepotDependency") => {
            build_depot_dependency32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "BuildDepotDependency") => {
            build_depot_dependency64_evidence(code, offset)
        }
        (SemanticArch::X86, "CWebSocketConnection::BBuildAndAsyncSendFrame") => {
            websocket_send_frame32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CWebSocketConnection::BBuildAndAsyncSendFrame") => {
            websocket_send_frame64_evidence(code, offset)
        }
        (SemanticArch::X86, "CCMConnection::RecvPkt") => ccm_recv_pkt32_evidence(code, offset),
        (SemanticArch::X86_64, "CCMConnection::RecvPkt") => ccm_recv_pkt64_evidence(code, offset),
        (SemanticArch::X86, "CUser::MarkLicenseAsChanged") => {
            mark_license_changed32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::MarkLicenseAsChanged") => {
            mark_license_changed64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUser::ProcessPendingLicenseUpdates") => {
            process_pending_license_updates32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::ProcessPendingLicenseUpdates") => {
            process_pending_license_updates64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUtlMemory::Grow") => cutl_memory_grow32_evidence(code, offset),
        (SemanticArch::X86_64, "CUtlMemory::Grow") => cutl_memory_grow64_evidence(code, offset),
        (SemanticArch::X86, "CConfigStore::WriteVdfFile") => {
            write_vdf_file32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CConfigStore::WriteVdfFile") => {
            write_vdf_file64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUser::SpawnProcess") => spawn_process32_evidence(code, offset),
        (SemanticArch::X86_64, "CUser::SpawnProcess") => spawn_process64_evidence(code, offset),
        (SemanticArch::X86, "CUser::BuildSpawnEnvBlock") => {
            build_spawn_env_block32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::BuildSpawnEnvBlock") => {
            build_spawn_env_block64_evidence(code, offset)
        }
        (SemanticArch::X86, "SetEnvString") => set_env_string32_evidence(code, offset),
        (SemanticArch::X86_64, "SetEnvString") => set_env_string64_evidence(code, offset),
        (SemanticArch::X86, "CSteamUIAppController::RunFrame") => {
            steamui_run_frame32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CSteamUIAppController::RunFrame") => {
            steamui_run_frame64_evidence(code, offset)
        }
        (SemanticArch::X86, "CSteamUIAppController::FillInAppOverview") => {
            fill_in_app_overview32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CSteamUIAppController::FillInAppOverview") => {
            fill_in_app_overview64_evidence(code, offset)
        }
        (SemanticArch::X86, "CSteamUIAppController::BuildCompleteAppOverviewChange") => {
            build_complete_app_overview_change32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CSteamUIAppController::BuildCompleteAppOverviewChange") => {
            build_complete_app_overview_change64_evidence(code, offset)
        }
        (SemanticArch::X86, "CSteamUIAppController::GetAppByID") => {
            get_app_by_id32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CSteamUIAppController::GetAppByID") => {
            get_app_by_id64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUpdateManager::MarkAppChange") => {
            mark_app_change32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUpdateManager::MarkAppChange") => {
            mark_app_change64_evidence(code, offset)
        }
        (SemanticArch::X86, "google::protobuf::RepeatedField<uint32>::Add") => {
            repeated_field_add32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "google::protobuf::RepeatedField<uint32>::Add") => {
            repeated_field_add64_evidence(code, offset)
        }
        _ => None,
    }
}

fn validate_check_app_ownership32(code: &[u8], offset: usize) -> Option<&'static str> {
    check_app_ownership32_evidence(code, offset)?
        .is_complete()
        .then_some("ownership result + license state")
}

fn check_app_ownership32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x360)?;
    let has_result_frame = has_asm32(bytes, |a| a.sub(esp, 0xACu32))
        && (has_asm32(bytes, |a| a.mov(ecx, 8)) || has_asm32(bytes, |a| a.mov(ecx, 0x0D)))
        && (has_asm32(bytes, |a| a.mov(dword_ptr(eax), -1))
            || has_asm32(bytes, |a| a.mov(dword_ptr(esi), -1)));
    let has_license_state = (has_x86_rm32_disp32_load(bytes, 0x1bd4)
        && has_x86_rm32_disp32_load(bytes, 0x1bf0))
        || (has_x86_rm32_disp32_load(bytes, 0x1bd0) && has_x86_rm32_disp32_load(bytes, 0x1bec));
    let has_success_flags = (has_asm32(bytes, |a| a.mov(byte_ptr(eax + 0x28), 1))
        || has_asm32(bytes, |a| a.mov(byte_ptr(esi + 0x28), 1)))
        && (has_asm32(bytes, |a| a.mov(byte_ptr(eax + 0x30), 1))
            || has_asm32(bytes, |a| a.mov(byte_ptr(esi + 0x30), 1)))
        && (has_asm32(bytes, |a| a.mov(word_ptr(eax + 0x33), bx))
            || has_asm32(bytes, |a| a.mov(word_ptr(esi + 0x33), di)));
    let has_owned_app_iteration = (has_asm32(bytes, |a| a.mov(ecx, dword_ptr(edi + 0x0C)))
        || has_asm32(bytes, |a| a.mov(eax, dword_ptr(edi + 0x0C)))
        || has_asm32(bytes, |a| a.mov(eax, dword_ptr(eax + 0x0C))))
        && (has_x86_rm32_disp32_load(bytes, 0x1bc8) || has_x86_rm32_disp32_load(bytes, 0x1bc4))
        && (has_asm32(bytes, |a| a.lea(edx, dword_ptr(eax + eax * 8)))
            || has_asm32(bytes, |a| a.lea(ecx, dword_ptr(edx + edx * 8))));

    let mut evidence = Evidence::default();
    evidence.require("ownership result frame", has_result_frame);
    evidence.require("license state offsets", has_license_state);
    evidence.require("success result writes", has_success_flags);
    evidence.require("owned app vector iteration", has_owned_app_iteration);
    Some(evidence)
}

fn validate_check_app_ownership64(code: &[u8], offset: usize) -> Option<&'static str> {
    check_app_ownership64_evidence(code, offset)?
        .is_complete()
        .then_some("ownership result + license state")
}

fn check_app_ownership64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x360)?;
    let has_result_frame = has_asm64(bytes, |a| a.sub(rsp, 0xB8))
        && has_asm64(bytes, |a| a.mov(ecx, 6))
        && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x70), -1));
    let has_license_state =
        has_x64_rm32_disp32_load(bytes, 0x2498) && has_x64_rm32_disp32_load(bytes, 0x24bc);
    let has_success_flags = has_asm64(bytes, |a| a.mov(byte_ptr(r14 + 0x28), 1))
        && has_asm64(bytes, |a| a.mov(byte_ptr(r14 + 0x30), 1))
        && has_asm64(bytes, |a| a.mov(word_ptr(r14 + 0x33), r8w));
    let has_owned_app_iteration = has_asm64(bytes, |a| a.mov(eax, dword_ptr(rax + 0x10)))
        && has_asm64(bytes, |a| a.movsxd(rdx, dword_ptr(rdx + r13 * 4)));

    let mut evidence = Evidence::default();
    evidence.require("ownership result frame", has_result_frame);
    evidence.require("license state offsets", has_license_state);
    evidence.require("success result writes", has_success_flags);
    evidence.require("owned app vector iteration", has_owned_app_iteration);
    Some(evidence)
}

fn validate_get_subscribed_apps32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        get_subscribed_apps32_evidence(code, offset),
        "args=appid-list flags",
    )
}

fn get_subscribed_apps32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        (
            "subscription flag argument",
            has_asm32(bytes, |a| a.movzx(eax, byte_ptr(ebp + 0x14))),
        ),
        (
            "appid list source",
            has_asm32(bytes, |a| {
                a.push(0)?;
                a.push(0)
            }) || has_asm32(bytes, |a| a.mov(edx, dword_ptr(ecx + 0x1BD0))),
        ),
    ]))
}

fn validate_get_subscribed_apps64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        get_subscribed_apps64_evidence(code, offset),
        "args=appid-list flags",
    )
}

fn get_subscribed_apps64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x260)?;
    Some(Evidence::required([
        (
            "include hidden subscriptions flag",
            has_x64_rsp_store_cl(bytes),
        ),
        (
            "license vector count",
            has_asm64(bytes, |a| a.mov(eax, dword_ptr(rdi + 0x2498))),
        ),
        (
            "license vector entry stride",
            has_asm64(bytes, |a| a.lea(rbx, qword_ptr(r15 + r15 * 4)))
                && has_asm64(bytes, |a| a.shl(rbx, 4)),
        ),
        (
            "license vector base",
            has_asm64(bytes, |a| a.add(rbx, qword_ptr(r12 + 0x2488))),
        ),
        (
            "license app id filter",
            has_asm64(bytes, |a| a.mov(r13d, dword_ptr(rbx)))
                && has_asm64(bytes, |a| a.cmp(r13d, -1)),
        ),
        (
            "package lookup state",
            has_asm64(bytes, |a| a.add(rdi, 0x1018))
                && has_asm64(bytes, |a| a.cmp(dword_ptr(rax + 0x18), 3)),
        ),
    ]))
}

fn validate_ipc_run_frame32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        ipc_run_frame32_evidence(code, offset),
        "ipc-wrapper mode=4 dispatch",
    )
}

fn ipc_run_frame32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x900)?;
    Some(Evidence::required([
        ("mode=4 ipc argument", has_asm32(bytes, |a| a.push(4))),
        (
            "known ipc dispatch id",
            has_x86_cmp_eax_any_imm32(
                bytes,
                &[
                    0x872F_E86C,
                    0x872F_E86D,
                    0x872F_E86E,
                    0x7A0A_85B0,
                    0x7A0A_85B2,
                    0x7A0A_85B7,
                    0xA688_9C36,
                    0xA688_9C37,
                    0xA688_9C39,
                ],
            ),
        ),
    ]))
}

fn validate_ipc_run_frame64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        ipc_run_frame64_evidence(code, offset),
        "ipc-wrapper mode=4 dispatch",
    )
}

fn ipc_run_frame64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        ("mode=4 ipc argument", has_asm64(bytes, |a| a.mov(edx, 4))),
        (
            "known ipc dispatch id",
            has_x86_cmp_eax_any_imm32(
                bytes,
                &[
                    0x872F_E86C,
                    0x872F_E86D,
                    0x7A0A_85B0,
                    0x7A0A_85B7,
                    0xA688_9C36,
                    0xA688_9C37,
                ],
            ),
        ),
    ]))
}

fn validate_load_depot_key32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        load_depot_key32_evidence(code, offset),
        "args=depot/key output",
    )
}

fn load_depot_key32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x120)?;
    Some(Evidence::required([
        (
            "depot id argument",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(esp + 0x44))),
        ),
        (
            "output buffer argument",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(esp + 0x48))),
        ),
        (
            "key loader call",
            has_asm32_call_after(
                bytes,
                |a| {
                    a.push(esi)?;
                    a.push(ebx)
                },
                0x08,
            ) || has_asm32_call_after(bytes, |a| a.push(dword_ptr(ebp + 0x0C)), 0x20),
        ),
    ]))
}

fn validate_load_depot_key64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(load_depot_key64_evidence(code, offset), "key-size=128")
}

fn load_depot_key64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        ("key size 128", has_asm64(bytes, |a| a.mov(esi, 0x80))),
        ("key buffer argument", has_asm64(bytes, |a| a.mov(rdi, rdx))),
    ]))
}

fn validate_build_depot_dependency32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        build_depot_dependency32_evidence(code, offset),
        "args=depot dependency",
    )
}

fn build_depot_dependency32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    let old_large_arg_form = has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x08)))
        && has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x10)))
        && has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x14)))
        && has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x24)))
        && has_asm32(bytes, |a| a.sub(esp, 0x22Cu32));
    let steamrt_arg_form = has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x08)))
        && has_asm32(bytes, |a| a.mov(ebx, dword_ptr(ebp + 0x10)))
        && has_asm32(bytes, |a| a.mov(esi, dword_ptr(ebp + 0x0C)))
        && has_asm32(bytes, |a| a.sub(esp, 0x6Cu32));
    Some(Evidence::required([
        (
            "known depot dependency arg form",
            old_large_arg_form || steamrt_arg_form,
        ),
        (
            "ownership result init",
            has_asm32(bytes, |a| a.mov(ecx, 0x0D)) && has_x86_ebp_store_i32(bytes, -1),
        ),
        (
            "CheckAppOwnership arguments",
            has_asm32_call_after(bytes, |a| a.push(dword_ptr(eax + 0x80)), 0x20),
        ),
        (
            "dependency state/result path",
            has_asm32(bytes, |a| a.add(edi, 0xB88u32))
                || has_asm32(bytes, |a| a.mov(dword_ptr(ebx + 0x14), eax)),
        ),
    ]))
}

fn validate_build_depot_dependency64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        build_depot_dependency64_evidence(code, offset),
        "args=depot dependency",
    )
}

fn build_depot_dependency64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        (
            "eighth argument load",
            has_asm64(bytes, |a| a.mov(rax, qword_ptr(rsp + 0x2C8))),
        ),
        (
            "self-named profiling scope",
            has_asm64(bytes, |a| a.mov(esi, 4)) && has_x64_rip_lea(bytes, 0x3d),
        ),
        (
            "ownership result init",
            has_asm64(bytes, |a| a.mov(ecx, 6))
                && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x130), -1)),
        ),
        (
            "CUser ownership check call receiver",
            has_asm64(bytes, |a| a.mov(rdi, qword_ptr(r14 + 0xF8))),
        ),
        (
            "app state lookup map",
            has_asm64(bytes, |a| a.add(rbp, 0xF20)),
        ),
    ]))
}

fn validate_websocket_send_frame32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        websocket_send_frame32_evidence(code, offset),
        "websocket frame builder",
    )
}

fn websocket_send_frame32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x190)?;
    Some(Evidence::required([
        (
            "websocket open-state check",
            has_asm32(bytes, |a| a.cmp(dword_ptr(edx + 0x10), 2)),
        ),
        (
            "websocket frame header buffer",
            has_asm32(bytes, |a| a.sub(esp, 0xACu32)),
        ),
        (
            "header builder bounds",
            has_asm32(bytes, |a| a.push(0x40)) && has_asm32(bytes, |a| a.push(0x0E)),
        ),
        (
            "websocket opcode encoding",
            has_x86_and_eax_imm8(bytes, 0x0F) && has_x86_or_al_imm8(bytes, 0x80),
        ),
        (
            "payload length tiers",
            has_asm32(bytes, |a| a.cmp(dword_ptr(ebp + 0x14), 0x7D))
                && has_asm32(bytes, |a| a.cmp(dword_ptr(ebp + 0x14), 0xFFFF)),
        ),
        (
            "payload argument",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x10)))
                || has_asm32(bytes, |a| a.mov(dword_ptr(ebp - 0xA0), eax)),
        ),
    ]))
}

fn validate_websocket_send_frame64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        websocket_send_frame64_evidence(code, offset),
        "websocket frame builder",
    )
}

fn websocket_send_frame64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x1c0)?;
    Some(Evidence::required([
        (
            "websocket open-state check",
            has_asm64(bytes, |a| a.cmp(dword_ptr(rdi + 0x18), 2)),
        ),
        (
            "frame type argument",
            has_asm64(bytes, |a| a.mov(r13d, esi)),
        ),
        ("payload argument", has_asm64(bytes, |a| a.mov(rbx, rdx))),
        (
            "websocket frame header buffer",
            has_asm64(bytes, |a| a.mov(ecx, 0x40)) && has_asm64(bytes, |a| a.mov(edx, 0x0E)),
        ),
        (
            "websocket opcode/length encoding",
            has_asm64(bytes, |a| a.and(esi, 0x0F))
                && has_asm64(bytes, |a| a.or(sil, 0x80))
                && has_asm64(bytes, |a| a.cmp(ebp, 0xFFFF)),
        ),
        (
            "masking key xor loop",
            has_asm64(bytes, |a| a.bswap(eax))
                && has_asm64(bytes, |a| a.xor(sil, byte_ptr(rbx + r14)))
                && has_asm64(bytes, |a| a.add(r14, 1)),
        ),
    ]))
}

fn validate_ccm_recv_pkt32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(ccm_recv_pkt32_evidence(code, offset), "ccm receive packet")
}

fn ccm_recv_pkt32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x190)?;
    Some(Evidence::required([
        ("receive mode argument", has_asm32(bytes, |a| a.push(1))),
        (
            "connection receive call",
            has_asm32_call_after(bytes, |a| a.push(1), 0x20),
        ),
        ("packet null check", has_asm32(bytes, |a| a.test(eax, eax))),
        (
            "packet status validation",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(esi + 0x04)))
                && has_x86_sub_eax_imm8(bytes, 1)
                && has_x86_cmp_eax_imm32(bytes, 0x00FF_FFFE),
        ),
        (
            "packet virtual consume",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(esi)))
                && has_asm32(bytes, |a| a.mov(edx, dword_ptr(eax + 0x08)))
                && (has_asm32(bytes, |a| a.call(dword_ptr(eax + 0x04)))
                    || has_asm32(bytes, |a| a.jmp(eax))),
        ),
    ]))
}

fn validate_ccm_recv_pkt64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(ccm_recv_pkt64_evidence(code, offset), "ccm receive packet")
}

fn ccm_recv_pkt64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        ("receive mode argument", has_asm64(bytes, |a| a.mov(esi, 1))),
        (
            "connection receive call",
            has_asm64_call_after(bytes, |a| a.mov(rdi, rbp), 0x10),
        ),
        ("packet null check", has_asm64(bytes, |a| a.test(rax, rax))),
    ]))
}

fn validate_mark_license_changed32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        mark_license_changed32_evidence(code, offset),
        "license-vector dirty mark",
    )
}

fn mark_license_changed32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    Some(Evidence::required([
        ("license vector load", has_x86_license_vector_load32(bytes)),
        (
            "dirty flag write",
            has_asm32(bytes, |a| a.mov(byte_ptr(esp + 0x1C), al)),
        ),
        ("license vector base", has_x86_license_vector_base32(bytes)),
        (
            "license id hash",
            has_asm32(bytes, |a| a.imul_3(edi, edi, 0x85EBCA6Bu32))
                || has_asm32(bytes, |a| a.imul_3(ebp, ebp, 0x85EBCA6Bu32)),
        ),
        (
            "license state hash table",
            (has_x86_rm32_disp32_load(bytes, 0x1ae4)
                && has_x86_rm32_disp32_load(bytes, 0x1af0)
                && has_x86_rm32_disp32_load(bytes, 0x1b04))
                || (has_x86_rm32_disp32_load(bytes, 0x1ae8)
                    && has_x86_rm32_disp32_load(bytes, 0x1af4)
                    && has_x86_rm32_disp32_load(bytes, 0x1b08)),
        ),
        (
            "package app-state lookup",
            has_x86_rm32_disp32_load(bytes, 0x0c58) && has_x86_rm32_disp32_load(bytes, 0x0c6c),
        ),
    ]))
}

fn validate_mark_license_changed64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        mark_license_changed64_evidence(code, offset),
        "license-vector dirty mark",
    )
}

fn mark_license_changed64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        ("license id save", has_asm64(bytes, |a| a.mov(ebx, esi))),
        (
            "license state map",
            has_asm64(bytes, |a| a.lea(rbp, qword_ptr(rax + 0xF20))),
        ),
        (
            "license state lookup",
            has_asm64_call_after(bytes, |a| a.mov(esi, ebx), 0x20),
        ),
        (
            "ownership result init",
            has_asm64(bytes, |a| a.mov(ecx, 6))
                && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x40), -1)),
        ),
        (
            "ownership recheck call",
            has_asm64(bytes, |a| a.mov(rdi, r12)) && has_asm64(bytes, |a| a.test(al, al)),
        ),
    ]))
}

fn validate_process_pending_license_updates32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        process_pending_license_updates32_evidence(code, offset),
        "pending-license loop",
    )
}

fn process_pending_license_updates32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    Some(Evidence::required([
        (
            "pending-license count offset",
            has_x86_rm32_disp32_load(bytes, 0x1bd0) || has_x86_rm32_disp32_load(bytes, 0x1bd4),
        ),
        (
            "pending-license vector base",
            has_x86_rm32_disp32_load(bytes, 0x1bc4) || has_x86_rm32_disp32_load(bytes, 0x1bc8),
        ),
        (
            "pending-license entry stride",
            (has_asm32(bytes, |a| a.lea(ebx, dword_ptr(esi + esi * 8)))
                || has_asm32(bytes, |a| a.lea(esi, dword_ptr(edi + edi * 8))))
                && (has_asm32(bytes, |a| a.shl(ebx, 3)) || has_asm32(bytes, |a| a.shl(esi, 3))),
        ),
        (
            "pending-license status filter",
            has_asm32(bytes, |a| a.cmp(dword_ptr(eax + 0x14), 0x50)),
        ),
        (
            "license change mark call",
            has_asm32(bytes, |a| a.push(0))
                && has_asm32(bytes, |a| a.push(dword_ptr(eax)))
                && has_asm32_call_after(bytes, |a| a.push(dword_ptr(eax)), 0x20),
        ),
        (
            "removed entry compaction",
            has_x86_sub_eax_imm8(bytes, 1) && has_x86_push_edx_call_after(bytes, 0x20),
        ),
        (
            "changed-license followup",
            has_x86_rm32_disp32_load(bytes, 0x1b14) || has_x86_rm32_disp32_load(bytes, 0x1b18),
        ),
    ]))
}

fn validate_process_pending_license_updates64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        process_pending_license_updates64_evidence(code, offset),
        "pending-license loop",
    )
}

fn process_pending_license_updates64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    Some(Evidence::required([
        (
            "pending-license count offset",
            has_asm64(bytes, |a| a.mov(edx, dword_ptr(rdi + 0x2570))),
        ),
        (
            "pending-license vector base",
            has_asm64(bytes, |a| a.add(rax, 0x2560)),
        ),
        (
            "pending-license entry stride",
            has_asm64(bytes, |a| a.lea(rax, qword_ptr(rbx + rbx * 4)))
                && has_asm64(bytes, |a| a.shl(rax, 4)),
        ),
        (
            "license id load",
            has_asm64(bytes, |a| a.mov(esi, dword_ptr(rax)))
                && has_asm64(bytes, |a| a.cmp(esi, -1)),
        ),
        (
            "package appid vector iteration",
            has_asm64(bytes, |a| a.mov(edx, dword_ptr(r15 + 0x50)))
                && has_asm64(bytes, |a| a.mov(ebp, dword_ptr(rax + r14 * 4))),
        ),
        (
            "license state lookup map",
            has_asm64(bytes, |a| a.lea(r13, qword_ptr(rax + 0xF20))),
        ),
        (
            "pending update state write",
            has_asm64(bytes, |a| a.mov(byte_ptr(rax + 0x233E), 0)),
        ),
    ]))
}

fn validate_cutl_memory_grow32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        cutl_memory_grow32_evidence(code, offset),
        "cutlmemory<u32> grow",
    )
}

fn cutl_memory_grow32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        (
            "allocation pointer load",
            has_x86_mov_from_esi_disp8(bytes, 0x08),
        ),
        (
            "allocation count load",
            has_x86_mov_from_esi_disp8(bytes, 0x04),
        ),
        ("u32 element size", has_asm32(bytes, |a| a.push(4))),
        ("count scaled by u32", has_x86_shl_rm32_by_2(bytes)),
        (
            "allocation count store",
            has_asm32(bytes, |a| a.mov(dword_ptr(esi + 0x04), eax)),
        ),
        (
            "allocator vtable call",
            has_asm32(bytes, |a| a.call(dword_ptr(ebx + 0x18)))
                || has_asm32(bytes, |a| a.call(dword_ptr(ecx + 0x14))),
        ),
    ]))
}

fn validate_cutl_memory_grow64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(cutl_memory_grow64_evidence(code, offset), "cutlmemory grow")
}

fn cutl_memory_grow64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        (
            "CUtlMemory receiver save",
            has_asm64(bytes, |a| a.mov(rbx, rdi)),
        ),
        (
            "requested grow count save",
            has_asm64(bytes, |a| a.mov(r12d, esi)),
        ),
        (
            "allocation count/capacity loads",
            has_asm64(bytes, |a| a.mov(esi, dword_ptr(rbx + 0x0C)))
                && has_asm64(bytes, |a| a.mov(edi, dword_ptr(rbx + 0x08))),
        ),
        (
            "u32 element size",
            has_asm64(bytes, |a| a.mov(ecx, 4))
                && has_asm64(bytes, |a| a.lea(rsi, qword_ptr(rax * 4))),
        ),
        (
            "allocation count store",
            has_asm64(bytes, |a| a.mov(dword_ptr(rbx + 0x08), eax)),
        ),
        (
            "allocator grow/realloc call",
            has_asm64(bytes, |a| a.call(qword_ptr(r11 + 0x30)))
                || has_asm64(bytes, |a| a.call(qword_ptr(r11 + 0x28))),
        ),
        (
            "allocation pointer store",
            has_asm64(bytes, |a| a.mov(qword_ptr(rbx), rax)),
        ),
    ]))
}

fn validate_write_vdf_file32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(write_vdf_file32_evidence(code, offset), "vdf write path")
}

fn write_vdf_file32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        (
            "write size cap",
            has_asm32(bytes, |a| a.cmp(esi, 0x06400000)),
        ),
        (
            "write buffer object",
            has_asm32(bytes, |a| a.lea(ecx, dword_ptr(esp + 0x14)))
                && has_asm32(bytes, |a| a.mov(dword_ptr(esp + 0x14), 0)),
        ),
        (
            "optional compression path",
            has_asm32(bytes, |a| a.test(esi, esi)) && has_asm32(bytes, |a| a.test(edi, edi)),
        ),
        (
            "vdf write flags",
            has_asm32(bytes, |a| {
                a.push(1)?;
                a.push(0)?;
                a.push(1)?;
                a.push(0)?;
                a.push(0)
            }),
        ),
        (
            "VDF write dispatch",
            has_asm32_call_after(
                bytes,
                |a| {
                    a.push(1)?;
                    a.push(0)?;
                    a.push(1)?;
                    a.push(0)?;
                    a.push(0)
                },
                0x40,
            ),
        ),
    ]))
}

fn validate_write_vdf_file64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(write_vdf_file64_evidence(code, offset), "vdf write path")
}

fn write_vdf_file64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        (
            "write size cap",
            has_asm64(bytes, |a| a.cmp(r9d, 0x06400000)),
        ),
        (
            "optional compression path",
            has_asm64(bytes, |a| a.test(r8, r8)) && has_asm64(bytes, |a| a.mov(rdi, r15)),
        ),
        (
            "write buffer object",
            has_asm64(bytes, |a| a.lea(rbx, qword_ptr(rsp + 0x20))),
        ),
        ("write flag argument", has_asm64(bytes, |a| a.push(1))),
        ("vdf object argument", has_asm64(bytes, |a| a.mov(rdi, r12))),
        (
            "VDF write dispatch",
            has_asm64_call_after(
                bytes,
                |a| {
                    a.mov(rcx, rax)?;
                    a.mov(edx, r14d)
                },
                0x40,
            ),
        ),
    ]))
}

fn validate_spawn_process32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(spawn_process32_evidence(code, offset), "spawn process args")
}

fn spawn_process32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    Some(Evidence::required([
        (
            "spawn launch-info argument",
            has_asm32(bytes, |a| a.mov(esi, dword_ptr(ebp + 0x18))),
        ),
        (
            "game id discriminator",
            has_asm32(bytes, |a| a.cmp(byte_ptr(esi + 0x03), 2))
                && has_asm32(bytes, |a| a.and(eax, 0x00FF_FFFF))
                && has_asm32(bytes, |a| a.cmp(eax, 0x31673)),
        ),
        (
            "launch context allocation",
            has_asm32_call_after(bytes, |a| a.push(0x94), 0x20),
        ),
        (
            "launch context init",
            has_asm32(bytes, |a| a.mov(dword_ptr(edx + 0x90), -1))
                || has_asm32(bytes, |a| a.mov(dword_ptr(edx + 0xC0), -1)),
        ),
        (
            "environment block builder call",
            has_asm32(bytes, |a| a.push(dword_ptr(ebp + 0x24)))
                && has_asm32(bytes, |a| a.push(1))
                && has_asm32_call_after(bytes, |a| a.push(dword_ptr(ebp + 0x24)), 0x80),
        ),
    ]))
}

fn validate_spawn_process64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(spawn_process64_evidence(code, offset), "spawn process args")
}

fn spawn_process64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x240)?;
    Some(Evidence::required([
        (
            "path argument save",
            has_asm64(bytes, |a| a.mov(r15, rdi)) && has_asm64(bytes, |a| a.mov(rbx, rsi)),
        ),
        ("env argument save", has_asm64(bytes, |a| a.mov(r12, r8))),
        (
            "game id discriminator",
            has_asm64(bytes, |a| a.cmp(byte_ptr(r8 + 0x03), 2))
                && has_asm64(bytes, |a| a.cmp(eax, 0x31673)),
        ),
        (
            "launch context allocation",
            has_asm64(bytes, |a| a.mov(edi, 0xC8))
                && has_asm64(bytes, |a| a.mov(dword_ptr(rdx + 0xC0), -1)),
        ),
        (
            "environment block builder call",
            has_asm64(bytes, |a| a.push(1))
                && has_asm64(bytes, |a| a.mov(r9d, dword_ptr(rbp + 0x18)))
                && has_asm64_call_after(bytes, |a| a.mov(r8, r12), 0x10)
                && has_x64_push_rbp_negative_local_before_call(bytes),
        ),
    ]))
}

fn validate_build_spawn_env_block32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        build_spawn_env_block32_evidence(code, offset),
        "spawn env builder",
    )
}

fn build_spawn_env_block32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x320)?;
    Some(Evidence::required([
        (
            "env output arguments",
            (has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x20)))
                || has_asm32(bytes, |a| a.mov(ebx, dword_ptr(ebp + 0x20))))
                && (has_asm32(bytes, |a| a.mov(ecx, dword_ptr(ebp + 0x24)))
                    || has_asm32(bytes, |a| a.mov(edx, dword_ptr(ebp + 0x24)))),
        ),
        (
            "env source flags",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x18)))
                && has_x86_and_eax_imm8(bytes, 1)
                && has_x86_test_ebp_disp8_imm8(bytes, 0x18, 2),
        ),
        (
            "game id parsing",
            ((has_asm32(bytes, |a| a.cmp(byte_ptr(edi + 0x03), 2))
                && (has_asm32(bytes, |a| a.movzx(eax, byte_ptr(edi + 0x01)))
                    || has_asm32(bytes, |a| a.movzx(edx, byte_ptr(edi + 0x01)))))
                || (has_asm32(bytes, |a| a.cmp(byte_ptr(esi + 0x03), 2))
                    && has_asm32(bytes, |a| a.movzx(eax, byte_ptr(esi + 0x01)))))
                && has_asm32(bytes, |a| a.shl(eax, 0x10)),
        ),
        (
            "env vector construction",
            has_asm32_call_after(bytes, |a| a.push(-1), 0x30)
                && has_asm32(bytes, |a| a.push(0x7FFF_FFFF)),
        ),
        (
            "fixed env block reservation",
            has_asm32_call_after(bytes, |a| a.push(0x5D), 0x30),
        ),
    ]))
}

fn validate_build_spawn_env_block64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        build_spawn_env_block64_evidence(code, offset),
        "spawn env builder",
    )
}

fn build_spawn_env_block64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    Some(Evidence::required([
        (
            "output env block pointer",
            has_asm64(bytes, |a| a.mov(rax, qword_ptr(rbp + 0x10))),
        ),
        (
            "env destination pointer",
            has_asm64(bytes, |a| a.mov(r14, qword_ptr(rbp + 0x18))),
        ),
        (
            "env var source object",
            has_asm64(bytes, |a| a.mov(qword_ptr(rbp - 0x31F0), rsi))
                && has_asm64(bytes, |a| a.mov(qword_ptr(rbp - 0x31E8), rcx)),
        ),
        (
            "Steam launch id formatting",
            has_asm64(bytes, |a| a.mov(r8d, 0x2F)) && has_asm64(bytes, |a| a.mov(esi, 0x1000)),
        ),
        (
            "env vector append",
            has_asm64_call_after(bytes, |a| a.mov(edx, -1), 0x40)
                && has_asm64(bytes, |a| a.mov(byte_ptr(rbp - 0x3100), 0)),
        ),
    ]))
}

fn validate_set_env_string32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(set_env_string32_evidence(code, offset), "env map insertion")
}

fn set_env_string32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        (
            "environment map load",
            has_x86_mov_from_any_disp8(bytes, 0x78),
        ),
        ("setenv key hash", has_asm32(bytes, |a| a.push(0x417))),
        ("insert mode argument", has_asm32(bytes, |a| a.push(1))),
    ]))
}

fn validate_set_env_string64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(set_env_string64_evidence(code, offset), "env map insertion")
}

fn set_env_string64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        (
            "environment map count",
            has_asm64(bytes, |a| a.mov(eax, dword_ptr(r15 + 0xA4))),
        ),
        (
            "environment map base",
            has_asm64(bytes, |a| a.lea(r14, qword_ptr(r15 + 0x80))),
        ),
        ("insert mode argument", has_asm64(bytes, |a| a.mov(ecx, 1))),
    ]))
}

fn validate_steamui_run_frame32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(steamui_run_frame32_evidence(code, offset), "ui frame tick")
}

fn steamui_run_frame32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        ("frame time store", has_x86_fstp_esp_disp8(bytes, 0x0C)),
        (
            "app controller state load",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(eax + 0xB70))),
        ),
    ]))
}

fn validate_steamui_run_frame64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(steamui_run_frame64_evidence(code, offset), "ui frame tick")
}

fn steamui_run_frame64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        (
            "frame time virtual call",
            has_asm64(bytes, |a| a.call(qword_ptr(rax + 0x28)))
                && has_x64_movsd_rbp_disp32_from_xmm0(bytes, -0x1240),
        ),
        (
            "app controller update calls",
            has_asm64(bytes, |a| a.call(qword_ptr(rax + 0x58)))
                && has_asm64(bytes, |a| a.call(qword_ptr(rax + 0x150))),
        ),
        (
            "frame-time comparison",
            has_asm64(bytes, |a| a.comisd(xmm0, qword_ptr(rbp - 0x1240))),
        ),
        (
            "controller active flag",
            has_asm64(bytes, |a| a.cmp(byte_ptr(rbx + 0x20), 0)),
        ),
    ]))
}

fn validate_fill_in_app_overview32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        fill_in_app_overview32_evidence(code, offset),
        "steam app layout fill",
    )
}

fn fill_in_app_overview32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let layout = discover_steam_app32_layout(code, offset);
    let mut evidence = Evidence::default();
    evidence.require("CSteamApp layout discovered", layout.is_some());
    if let Some(layout) = layout {
        evidence.require("game_id offset 0x04", layout.game_id_off == 0x04);
        evidence.require("app_id offset 0x0c", layout.app_id_off == 0x0c);
        evidence.require(
            "purchased_time offset 0x28",
            layout.purchased_time_off == 0x28,
        );
    }
    Some(evidence)
}

fn validate_fill_in_app_overview64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        fill_in_app_overview64_evidence(code, offset),
        "steam app layout fill",
    )
}

fn fill_in_app_overview64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let layout = discover_steam_app64_layout(code, offset);
    let mut evidence = Evidence::default();
    evidence.require("CSteamApp layout discovered", layout.is_some());
    if let Some(layout) = layout {
        evidence.require("game_id offset 0x08", layout.game_id_off == 0x08);
        evidence.require("app_id offset 0x10", layout.app_id_off == 0x10);
        evidence.require(
            "purchased_time offset 0x2c",
            layout.purchased_time_off == 0x2c,
        );
    }
    Some(evidence)
}

fn validate_build_complete_app_overview_change32(
    code: &[u8],
    offset: usize,
) -> Option<&'static str> {
    evidence_result(
        build_complete_app_overview_change32_evidence(code, offset),
        "overview change layout",
    )
}

fn build_complete_app_overview_change32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let layout = discover_app_overview_change32_layout(code, offset);
    let mut evidence = Evidence::default();
    evidence.require("CAppOverviewChange layout discovered", layout.is_some());
    if let Some(layout) = layout {
        evidence.require("app_overview offset 0x10", layout.app_overview_off == 0x10);
        evidence.require(
            "removed_appid offset 0x1c",
            layout.removed_appid_off == 0x1c,
        );
    }
    Some(evidence)
}

fn validate_build_complete_app_overview_change64(
    code: &[u8],
    offset: usize,
) -> Option<&'static str> {
    evidence_result(
        build_complete_app_overview_change64_evidence(code, offset),
        "overview change layout",
    )
}

fn build_complete_app_overview_change64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let layout = discover_app_overview_change64_layout(code, offset);
    let mut evidence = Evidence::default();
    evidence.require("CAppOverviewChange layout discovered", layout.is_some());
    if let Some(layout) = layout {
        evidence.require("app_overview offset 0x18", layout.app_overview_off == 0x18);
        evidence.require(
            "removed_appid offset 0x28",
            layout.removed_appid_off == 0x28,
        );
    }
    Some(evidence)
}

fn validate_get_app_by_id32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(get_app_by_id32_evidence(code, offset), "app lookup")
}

fn get_app_by_id32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        (
            "appid argument load",
            has_asm32(bytes, |a| a.mov(ebx, dword_ptr(ebp + 0x10))),
        ),
        (
            "receiver argument load",
            has_asm32(bytes, |a| a.mov(esi, dword_ptr(ebp + 0x08))),
        ),
        (
            "app map load",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(eax + 0x9E0))),
        ),
    ]))
}

fn validate_get_app_by_id64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(get_app_by_id64_evidence(code, offset), "app lookup")
}

fn get_app_by_id64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        ("appid stack spill", has_x64_stack_spill_r32(bytes, 6)),
        ("lookup mode stack spill", has_x64_stack_spill_r32(bytes, 2)),
        (
            "app entry null check",
            has_asm64(bytes, |a| {
                a.mov(eax, dword_ptr(rax))?;
                a.test(eax, eax)
            }),
        ),
    ]))
}

fn validate_mark_app_change32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        mark_app_change32_evidence(code, offset),
        "library change mark",
    )
}

fn mark_app_change32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x120)?;
    Some(Evidence::required([
        (
            "library app map load",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(eax + 0x9E0))),
        ),
        (
            "change flag materialization",
            has_asm32(bytes, |a| a.sete(cl)),
        ),
    ]))
}

fn validate_mark_app_change64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        mark_app_change64_evidence(code, offset),
        "library change mark",
    )
}

fn mark_app_change64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        ("change kind filter", has_asm64(bytes, |a| a.cmp(edi, 7))),
        (
            "library app map load",
            has_asm64(bytes, |a| a.mov(rdi, qword_ptr(rax + 0xB58))),
        ),
        ("app object save", has_asm64(bytes, |a| a.mov(r12, rax))),
    ]))
}

fn validate_repeated_field_add32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        repeated_field_add32_evidence(code, offset),
        "repeated-field add abi",
    )
}

fn repeated_field_add32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x120)?;
    Some(Evidence::required([
        (
            "field size/capacity check",
            has_asm32(bytes, |a| {
                a.mov(esi, dword_ptr(ebx))?;
                a.cmp(esi, dword_ptr(ebx + 0x04))
            }),
        ),
        (
            "append slot write",
            has_asm32(bytes, |a| a.lea(edi, dword_ptr(esi + 0x01)))
                || has_asm32(bytes, |a| a.mov(dword_ptr(eax + esi * 4), edx)),
        ),
    ]))
}

fn validate_repeated_field_add64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        repeated_field_add64_evidence(code, offset),
        "repeated-field add abi",
    )
}

fn repeated_field_add64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        (
            "field size/capacity check",
            has_asm64(bytes, |a| {
                a.mov(eax, dword_ptr(rdi + 0x04))?;
                a.cmp(dword_ptr(rdi), eax)
            }),
        ),
        (
            "field size increment",
            has_asm64(bytes, |a| {
                a.lea(edx, dword_ptr(rax + 0x01))?;
                a.mov(dword_ptr(rbp), edx)
            }),
        ),
        (
            "append slot write",
            has_asm64(bytes, |a| a.mov(dword_ptr(r8 + rax * 4), edx)),
        ),
    ]))
}

fn find_x64_rbp_dword_or_qword_load(bytes: &[u8], expected_disp: u8) -> Option<usize> {
    let has_mov_eax = bytes
        .windows(3)
        .any(|w| w[0] == 0x8b && w[1] == 0x45 && w[2] == expected_disp);
    let has_mov_r32 = bytes.windows(4).any(|w| {
        w[0] == 0x44 && w[1] == 0x8b && (0x40..=0x7f).contains(&w[2]) && w[3] == expected_disp
    });
    let has_mov_rax = bytes
        .windows(4)
        .any(|w| w == [0x48, 0x8b, 0x45, expected_disp]);
    (has_mov_eax || has_mov_r32 || has_mov_rax).then_some(expected_disp as usize)
}

fn find_x86_any_reg_disp8_load(bytes: &[u8], expected_disp: u8) -> Option<usize> {
    bytes
        .windows(3)
        .any(|w| w[0] == 0x8b && (0x40..=0x7f).contains(&w[1]) && w[2] == expected_disp)
        .then_some(expected_disp as usize)
}

fn find_x86_steam_app_game_id_load(bytes: &[u8]) -> Option<usize> {
    let high_then_low = bytes
        .windows(6)
        .any(|w| w == [0x8b, 0x50, 0x08, 0x8b, 0x40, 0x04]);
    let low_then_high = bytes
        .windows(6)
        .any(|w| w == [0x8b, 0x40, 0x04, 0x8b, 0x50, 0x08]);
    (high_then_low || low_then_high).then_some(0x04)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageMapLayout {
    count_off: usize,
    elements_off: usize,
    node_size: usize,
    node_key_off: usize,
    node_value_off: usize,
}

fn scan_steamclient64_layouts(code: &[u8], vaddr: u64, resolved: &HashMap<&str, usize>) -> bool {
    let mut failed = false;
    failed |= scan_semantic_checks(
        code,
        vaddr,
        resolved,
        &STEAMCLIENT64_SEMANTIC_CHECKS,
        SemanticArch::X86_64,
    );

    if let Some(&ticket_ext_offset) = resolved.get("IClientUser::GetAppOwnershipTicketExtendedData")
    {
        let evidence = ticket_ext_data_mode4_thunk64_evidence(code, ticket_ext_offset);
        if evidence.as_ref().is_some_and(Evidence::is_complete) {
            println!(
                "  OK   {:<58} layer=mode4-thunk",
                "IClientUser::GetAppOwnershipTicketExtendedData body"
            );
        } else {
            print_evidence_failure(
                "IClientUser::GetAppOwnershipTicketExtendedData body",
                vaddr + ticket_ext_offset as u64,
                evidence.as_ref(),
                "body is not the mode=4 ticket thunk",
            );
            failed = true;
        }
    }

    if let (Some(&update_offset), Some(&check_offset)) = (
        resolved.get("IClientUser::BUpdateAppOwnershipTicket"),
        resolved.get("CUser::CheckAppOwnership"),
    ) {
        let evidence = update_ticket64_evidence(code, update_offset, check_offset);
        match validate_update_ticket64(code, update_offset, check_offset) {
            Some(validation) => println!(
                "  OK   {:<58} receiver={} check_ownership_call=true",
                "IClientUser::BUpdateAppOwnershipTicket body",
                validation.receiver.label()
            ),
            None => {
                print_evidence_failure(
                    "IClientUser::BUpdateAppOwnershipTicket body",
                    vaddr + update_offset as u64,
                    evidence.as_ref(),
                    "body is not the ownership-ticket updater",
                );
                failed = true;
            }
        }
    }

    if let Some(&is_subscribed_offset) = resolved.get("IClientUser::IsUserSubscribedAppInTicket") {
        let evidence = is_user_subscribed_app_in_ticket64_evidence(code, is_subscribed_offset);
        if evidence.as_ref().is_some_and(Evidence::is_complete) {
            println!(
                "  OK   {:<58} status_filter=true returns=0/1/2",
                "IClientUser::IsUserSubscribedAppInTicket body"
            );
        } else {
            print_evidence_failure(
                "IClientUser::IsUserSubscribedAppInTicket body",
                vaddr + is_subscribed_offset as u64,
                evidence.as_ref(),
                "body is not the ticket subscription checker",
            );
            failed = true;
        }
    }

    if let Some(&get_package_info_offset) = resolved.get("CPackageInfo::GetPackageInfo") {
        match discover_package_info64_layout(code, get_package_info_offset) {
            Some(layout) => {
                println!(
                    "  OK   {:<58} root=0x{:x} elements=0x{:x} node=0x{:x} key=0x{:x} value=0x{:x}",
                    "CPackageInfo::GetPackageInfo token map",
                    layout.count_off,
                    layout.elements_off,
                    layout.node_size,
                    layout.node_key_off,
                    layout.node_value_off
                );
            }
            None => {
                let evidence = package_info64_evidence(code, get_package_info_offset);
                print_evidence_failure(
                    "CPackageInfo::GetPackageInfo token map",
                    vaddr + get_package_info_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    failed
}

fn scan_steamclient32_layouts(code: &[u8], vaddr: u64, resolved: &HashMap<&str, usize>) -> bool {
    let mut failed = false;
    failed |= scan_semantic_checks(
        code,
        vaddr,
        resolved,
        &STEAMCLIENT32_SEMANTIC_CHECKS,
        SemanticArch::X86,
    );

    if let Some(&ticket_ext_offset) = resolved.get("IClientUser::GetAppOwnershipTicketExtendedData")
    {
        let evidence = ticket_ext_data_mode4_thunk32_evidence(code, ticket_ext_offset);
        if evidence.as_ref().is_some_and(Evidence::is_complete) {
            println!(
                "  OK   {:<58} layer=mode4-thunk",
                "IClientUser::GetAppOwnershipTicketExtendedData body"
            );
        } else {
            print_evidence_failure(
                "IClientUser::GetAppOwnershipTicketExtendedData body",
                vaddr + ticket_ext_offset as u64,
                evidence.as_ref(),
                "body is not the mode=4 ticket thunk",
            );
            failed = true;
        }
    }

    if let (Some(&update_offset), Some(&check_offset)) = (
        resolved.get("IClientUser::BUpdateAppOwnershipTicket"),
        resolved.get("CUser::CheckAppOwnership"),
    ) {
        let evidence = update_ticket32_evidence(code, update_offset, check_offset);
        match validate_update_ticket32(code, update_offset, check_offset) {
            Some(validation) => println!(
                "  OK   {:<58} receiver={} check_ownership_call=true",
                "IClientUser::BUpdateAppOwnershipTicket body",
                validation.receiver.label()
            ),
            None => {
                print_evidence_failure(
                    "IClientUser::BUpdateAppOwnershipTicket body",
                    vaddr + update_offset as u64,
                    evidence.as_ref(),
                    "body is not the ownership-ticket updater",
                );
                failed = true;
            }
        }
    }

    if let Some(&is_subscribed_offset) = resolved.get("IClientUser::IsUserSubscribedAppInTicket") {
        let evidence = is_user_subscribed_app_in_ticket32_evidence(code, is_subscribed_offset);
        if evidence.as_ref().is_some_and(Evidence::is_complete) {
            println!(
                "  OK   {:<58} status_filter=true returns=0/1/2",
                "IClientUser::IsUserSubscribedAppInTicket body"
            );
        } else {
            print_evidence_failure(
                "IClientUser::IsUserSubscribedAppInTicket body",
                vaddr + is_subscribed_offset as u64,
                evidence.as_ref(),
                "body is not the ticket subscription checker",
            );
            failed = true;
        }
    }

    if let Some(&get_package_info_offset) = resolved.get("CPackageInfo::GetPackageInfo") {
        match discover_package_info32_layout(code, get_package_info_offset) {
            Some(layout) => {
                println!(
                    "  OK   {:<58} root=0x{:x} elements=0x{:x} node=0x{:x} key=0x{:x} value=0x{:x}",
                    "CPackageInfo::GetPackageInfo package map",
                    layout.count_off,
                    layout.elements_off,
                    layout.node_size,
                    layout.node_key_off,
                    layout.node_value_off
                );
            }
            None => {
                let evidence = package_info32_evidence(code, get_package_info_offset);
                print_evidence_failure(
                    "CPackageInfo::GetPackageInfo package map",
                    vaddr + get_package_info_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    failed
}

fn ticket_ext_data_mode4_thunk32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let Some(bytes) = bounded_tail(code, offset, 0x160) else {
        return None;
    };

    let has_mode4 = has_asm32(bytes, |a| a.push(4));
    let adjusts_this_to_cuser =
        find_x86_sub_eax_imm32_matching(bytes, |imm| matches!(imm, 0x18d4 | 0x18d8)).is_some();
    let calls_shared_builder_after_mode = has_call_after_mode4_push(bytes);

    let mut evidence = Evidence::default();
    evidence.require("mode=4 argument", has_mode4);
    evidence.require("ClientUser to CUser adjustment", adjusts_this_to_cuser);
    evidence.require(
        "shared ticket builder call",
        calls_shared_builder_after_mode,
    );
    Some(evidence)
}

fn ticket_ext_data_mode4_thunk64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let Some(bytes) = bounded_tail(code, offset, 0x100) else {
        return None;
    };

    let has_mode4 = has_asm64(bytes, |a| a.push(4));
    let adjusts_this_to_cuser = has_asm64(bytes, |a| a.lea(rdi, qword_ptr(r12 - 0x1FD0)));
    let calls_shared_builder_after_mode = has_call_after_mode4_push(bytes);

    let mut evidence = Evidence::default();
    evidence.require("mode=4 argument", has_mode4);
    evidence.require("ClientUser to CUser adjustment", adjusts_this_to_cuser);
    evidence.require(
        "shared ticket builder call",
        calls_shared_builder_after_mode,
    );
    Some(evidence)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UpdateTicketValidation {
    receiver: UpdateTicketReceiver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateTicketReceiver {
    ClientUserAdjusted(u32),
    DirectCUser,
    DirectCUserWithAdjacentWrapper,
}

impl UpdateTicketReceiver {
    fn label(self) -> String {
        match self {
            Self::ClientUserAdjusted(adjust) => format!("clientuser-adjusted(-0x{adjust:x})"),
            Self::DirectCUser => "direct-cuser".to_owned(),
            Self::DirectCUserWithAdjacentWrapper => {
                "direct-cuser(wrapper-adjust=-0x1fd0)".to_owned()
            }
        }
    }
}

fn validate_update_ticket32(
    code: &[u8],
    offset: usize,
    check_ownership_offset: usize,
) -> Option<UpdateTicketValidation> {
    let bytes = bounded_tail(code, offset, 0x280)?;
    if !update_ticket32_evidence(code, offset, check_ownership_offset)?.is_complete() {
        return None;
    }

    update_ticket32_receiver(bytes).map(|receiver| UpdateTicketValidation { receiver })
}

fn update_ticket32_evidence(
    code: &[u8],
    offset: usize,
    check_ownership_offset: usize,
) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x280)?;
    let has_force_arg_branch = has_asm32(bytes, |a| a.cmp(byte_ptr(ebp + 0x10), 0));
    let has_result_struct_init = has_asm32(bytes, |a| a.mov(ecx, 0x0D))
        && bytes
            .windows(7)
            .any(|w| w[0] == 0xc7 && w[1] == 0x45 && w[3..7] == [0xff, 0xff, 0xff, 0xff]);
    let calls_check_ownership =
        has_relative_call_to(code, offset, bytes.len(), check_ownership_offset);
    let receiver = update_ticket32_receiver(bytes);

    let mut evidence = Evidence::default();
    evidence.require("force argument branch", has_force_arg_branch);
    evidence.require("ownership result struct init", has_result_struct_init);
    evidence.require("CheckAppOwnership call", calls_check_ownership);
    evidence.require("CUser receiver layout", receiver.is_some());
    Some(evidence)
}

fn update_ticket32_receiver(bytes: &[u8]) -> Option<UpdateTicketReceiver> {
    let receiver_adjust_window = &bytes[..bytes.len().min(0x100)];
    if let Some(adjust) = find_x86_sub_eax_imm32_matching(receiver_adjust_window, |imm| {
        matches!(imm, 0x18d4 | 0x18d8)
            && has_x86_cmp_rm32_imm8(bytes, 0u32.wrapping_sub(imm - 0xf8), 0x04)
    }) {
        return Some(UpdateTicketReceiver::ClientUserAdjusted(adjust));
    }

    let direct_cuser_layout = has_asm32(bytes, |a| a.cmp(dword_ptr(eax + 0xF8), 4));
    direct_cuser_layout.then_some(UpdateTicketReceiver::DirectCUser)
}

fn validate_update_ticket64(
    code: &[u8],
    offset: usize,
    check_ownership_offset: usize,
) -> Option<UpdateTicketValidation> {
    let bytes = bounded_tail(code, offset, 0x330)?;
    if !update_ticket64_evidence(code, offset, check_ownership_offset)?.is_complete() {
        return None;
    }
    Some(UpdateTicketValidation {
        receiver: update_ticket64_receiver(bytes),
    })
}

fn update_ticket64_evidence(
    code: &[u8],
    offset: usize,
    check_ownership_offset: usize,
) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x330)?;
    let has_force_arg_branch = has_asm64(bytes, |a| a.test(dl, dl));
    let has_status_check = has_asm64(bytes, |a| a.cmp(dword_ptr(rbx + 0x1E8), 4));
    let has_result_struct_init = has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x70), -1))
        && has_asm64(bytes, |a| a.mov(ecx, 6));
    let calls_check_ownership =
        has_relative_call_to(code, offset, bytes.len(), check_ownership_offset);

    let mut evidence = Evidence::default();
    evidence.require("force argument branch", has_force_arg_branch);
    evidence.require("ticket status check", has_status_check);
    evidence.require("ownership result struct init", has_result_struct_init);
    evidence.require("CheckAppOwnership call", calls_check_ownership);
    Some(evidence)
}

fn update_ticket64_receiver(bytes: &[u8]) -> UpdateTicketReceiver {
    let has_adjacent_wrapper = has_asm64(bytes, |a| a.sub(rdi, 0x1FD0));
    if has_adjacent_wrapper {
        UpdateTicketReceiver::DirectCUserWithAdjacentWrapper
    } else {
        UpdateTicketReceiver::DirectCUser
    }
}

fn has_relative_call_to(
    code: &[u8],
    function_offset: usize,
    max_len: usize,
    target_offset: usize,
) -> bool {
    let end = code.len().min(function_offset.saturating_add(max_len));
    let mut cursor = function_offset;
    while cursor + 5 <= end {
        if code[cursor] == 0xe8
            && relative_call_target_offset(code, cursor)
                .is_some_and(|target| target == target_offset)
        {
            return true;
        }
        cursor += 1;
    }
    false
}

fn relative_call_target_offset(code: &[u8], call_offset: usize) -> Option<usize> {
    let disp: [u8; 4] = code
        .get(call_offset + 1..call_offset + 5)?
        .try_into()
        .ok()?;
    let target = call_offset as isize + 5 + i32::from_le_bytes(disp) as isize;
    (target >= 0 && (target as usize) < code.len()).then_some(target as usize)
}

fn has_call_after_mode4_push(bytes: &[u8]) -> bool {
    let Some(push_mode4) = asm_bytes32(|a| a.push(4)) else {
        return false;
    };
    bytes.windows(push_mode4.len()).enumerate().any(|(idx, w)| {
        w == push_mode4.as_slice()
            && bytes[idx + push_mode4.len()..bytes.len().min(idx + 0x30)]
                .iter()
                .any(|&byte| byte == 0xe8)
    })
}

fn is_user_subscribed_app_in_ticket32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let Some(bytes) = bounded_tail(code, offset, 0x1f0) else {
        return None;
    };

    let has_status_filter = has_asm32(bytes, |a| {
        a.and(edx, -3)?;
        a.cmp(edx, 1)
    });
    let has_no_entries_return = x86_has_stack_return_code(bytes, 2);
    let has_miss_return = x86_has_stack_return_code(bytes, 1);
    let has_hit_return = x86_has_stack_return_code(bytes, 0);
    let removes_ticket_entry = has_asm32(bytes, |a| a.mov(dword_ptr(ecx + 0x1884), eax));

    let mut evidence = Evidence::default();
    evidence.require("ticket status filter", has_status_filter);
    evidence.require("no-entry return code 2", has_no_entries_return);
    evidence.require("miss return code 1", has_miss_return);
    evidence.require("hit return code 0", has_hit_return);
    evidence.reject("ticket removal side effect", removes_ticket_entry);
    Some(evidence)
}

fn is_user_subscribed_app_in_ticket64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let Some(bytes) = bounded_tail(code, offset, 0x140) else {
        return None;
    };

    let has_status_filter = has_asm64(bytes, |a| {
        a.and(edx, -3)?;
        a.cmp(edx, 1)
    });
    let has_no_entries_return = has_asm64(bytes, |a| a.mov(esi, 2));
    let has_miss_return = has_asm64(bytes, |a| a.mov(esi, 1));
    let has_hit_return = has_asm64(bytes, |a| a.xor(esi, esi));
    let removes_ticket_entry = has_asm64(bytes, |a| a.mov(dword_ptr(r13 + 0x1F60), edx));

    let mut evidence = Evidence::default();
    evidence.require("ticket status filter", has_status_filter);
    evidence.require("no-entry return code 2", has_no_entries_return);
    evidence.require("miss return code 1", has_miss_return);
    evidence.require("hit return code 0", has_hit_return);
    evidence.reject("ticket removal side effect", removes_ticket_entry);
    Some(evidence)
}

fn x86_has_stack_return_code(bytes: &[u8], value: u8) -> bool {
    bytes.windows(8).any(|w| {
        w[0] == 0xc7
            && w[1] == 0x44
            && w[2] == 0x24
            && w[4] == value
            && w[5] == 0x00
            && w[6] == 0x00
            && w[7] == 0x00
    })
}

fn discover_package_info32_layout(
    code: &[u8],
    get_package_info_offset: usize,
) -> Option<PackageMapLayout> {
    let bytes = code.get(get_package_info_offset..get_package_info_offset.saturating_add(0x240))?;

    // CPackageInfo::GetPackageInfo(this, package_id, access_token) must load
    // both halves of access_token from stack and search the package-id map.
    if !find_x86_get_package_info_args(bytes) {
        return None;
    }

    let root_off = find_x86_mov_eax_eax_disp8(bytes)?;
    let elements_off = find_x86_mov_edx_ebx_disp8(bytes)?;
    let node_size = find_x86_node_size(bytes)?;
    let node_key_off = find_x86_node_key_off(bytes)?;
    let node_value_off = find_x86_node_value_off(bytes)?;

    Some(PackageMapLayout {
        count_off: root_off,
        elements_off,
        node_size,
        node_key_off,
        node_value_off,
    })
}

fn package_info32_evidence(code: &[u8], get_package_info_offset: usize) -> Option<Evidence> {
    let bytes = code.get(get_package_info_offset..get_package_info_offset.saturating_add(0x240))?;
    let has_args = find_x86_get_package_info_args(bytes);
    let root_off = find_x86_mov_eax_eax_disp8(bytes);
    let elements_off = find_x86_mov_edx_ebx_disp8(bytes);
    let node_size = find_x86_node_size(bytes);
    let node_key_off = find_x86_node_key_off(bytes);
    let node_value_off = find_x86_node_value_off(bytes);

    let mut evidence = Evidence::default();
    evidence.require("package id and access token args", has_args);
    evidence.require("package map root offset", root_off.is_some());
    evidence.require("package map elements offset", elements_off.is_some());
    evidence.require("package map node size", node_size.is_some());
    evidence.require("package map key offset", node_key_off.is_some());
    evidence.require("package map value offset", node_value_off.is_some());
    Some(evidence)
}

fn discover_package_info64_layout(
    code: &[u8],
    get_package_info_offset: usize,
) -> Option<PackageMapLayout> {
    let bytes = code.get(get_package_info_offset..get_package_info_offset.saturating_add(0x120))?;
    let root_off = find_x64_movslq_rdi_disp32(bytes)?;
    let elements_off = find_x64_mov_rdi_rdi_disp32(bytes)?;
    let node_size = find_x64_node_size(bytes)?;
    let node_key_off = find_x64_node_key_off(bytes)?;
    let node_value_off =
        find_x64_inline_return_off(bytes).or_else(|| find_x64_pointer_return_off(bytes))?;

    Some(PackageMapLayout {
        count_off: root_off,
        elements_off,
        node_size,
        node_key_off,
        node_value_off,
    })
}

fn package_info64_evidence(code: &[u8], get_package_info_offset: usize) -> Option<Evidence> {
    let bytes = code.get(get_package_info_offset..get_package_info_offset.saturating_add(0x120))?;
    let root_off = find_x64_movslq_rdi_disp32(bytes);
    let elements_off = find_x64_mov_rdi_rdi_disp32(bytes);
    let node_size = find_x64_node_size(bytes);
    let node_key_off = find_x64_node_key_off(bytes);
    let node_value_off =
        find_x64_inline_return_off(bytes).or_else(|| find_x64_pointer_return_off(bytes));

    let mut evidence = Evidence::default();
    evidence.require("token map root offset", root_off.is_some());
    evidence.require("token map elements offset", elements_off.is_some());
    evidence.require("token map node size", node_size.is_some());
    evidence.require("token map key offset", node_key_off.is_some());
    evidence.require("token map value offset", node_value_off.is_some());
    Some(evidence)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<usize> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw) as usize)
}

fn find_x86_get_package_info_args(bytes: &[u8]) -> bool {
    let package_id = bytes.windows(3).any(|w| w == [0x8b, 0x75, 0x0c]);
    let token_stack_pair = bytes.windows(3).any(|w| w == [0x8b, 0x45, 0x10])
        && bytes.windows(3).any(|w| w == [0x8b, 0x55, 0x14]);
    let token_stack_xmm = bytes
        .windows(5)
        .any(|w| w == [0xf3, 0x0f, 0x7e, 0x4d, 0x10]);
    let token_compare_sse = bytes
        .windows(5)
        .any(|w| w == [0xf3, 0x0f, 0x7e, 0x47, 0x08]);
    let token_compare_scalar = bytes
        .windows(7)
        .any(|w| w == [0x8b, 0x43, 0x08, 0x33, 0x7b, 0x0c, 0x31]);
    package_id
        && (token_stack_pair || token_stack_xmm)
        && (token_compare_sse || token_compare_scalar)
}

fn find_x86_mov_eax_eax_disp8(bytes: &[u8]) -> Option<usize> {
    bytes
        .get(..0x80)?
        .windows(3)
        .find_map(|w| (w[0..2] == [0x8b, 0x40]).then_some(w[2] as usize))
}

fn find_x86_mov_edx_ebx_disp8(bytes: &[u8]) -> Option<usize> {
    bytes.get(..0x120)?.windows(3).find_map(|w| {
        matches!(
            &w[0..2],
            // mov edx,[ebx+disp]
            [0x8b, 0x53]
                // mov ebx,[ecx+disp]
                | [0x8b, 0x59]
                // mov ecx,[ebx+disp]
                | [0x8b, 0x4b]
                // mov ecx,[ecx+disp]
                | [0x8b, 0x49]
        )
        .then_some(w[2] as usize)
    })
}

fn find_x86_node_size(bytes: &[u8]) -> Option<usize> {
    if bytes
        .windows(6)
        .any(|w| w == [0x8d, 0x04, 0x40, 0x8d, 0x04, 0xc2])
    {
        return Some(0x18);
    }
    if bytes
        .windows(6)
        .any(|w| w == [0x8d, 0x04, 0x52, 0x8d, 0x04, 0xc3])
    {
        return Some(0x18);
    }
    if let Some(shift) = bytes
        .windows(6)
        .find_map(|w| (w[0..3] == [0x8d, 0x04, 0x40] && w[3..5] == [0xc1, 0xe0]).then_some(w[5]))
    {
        return 3usize.checked_shl(shift as u32);
    }
    bytes.windows(6).find_map(|w| {
        (w[0..3] == [0x8d, 0x1c, 0x5b] && w[3..5] == [0xc1, 0xe3])
            .then(|| 3usize.checked_shl(w[5] as u32))
            .flatten()
    })
}

fn find_x86_node_key_off(bytes: &[u8]) -> Option<usize> {
    bytes.windows(3).find_map(|w| {
        ((w[0..2] == [0x39, 0x70]) || (w[0..2] == [0x3b, 0x70])).then_some(w[2] as usize)
    })
}

fn find_x86_node_value_off(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(3)
        .find_map(|w| (w[0..2] == [0x8b, 0x78]).then_some(w[2] as usize))
        .or_else(|| {
            bytes
                .windows(4)
                .find_map(|w| (w[0..3] == [0x8b, 0x44, 0x03]).then_some(w[3] as usize))
        })
}

fn find_x64_movslq_rdi_disp32(bytes: &[u8]) -> Option<usize> {
    bytes.windows(7).enumerate().find_map(|(idx, w)| {
        (w[0..3] == [0x48, 0x63, 0x87])
            .then(|| read_u32_le(bytes, idx + 3))
            .flatten()
    })
}

fn find_x64_mov_rdi_rdi_disp32(bytes: &[u8]) -> Option<usize> {
    bytes.windows(7).enumerate().find_map(|(idx, w)| {
        (w[0..3] == [0x48, 0x8b, 0xbf])
            .then(|| read_u32_le(bytes, idx + 3))
            .flatten()
    })
}

fn find_x64_node_size(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .find_map(|w| (w[0..3] == [0x48, 0x6b, 0xc0]).then_some(w[3] as usize))
        .or_else(|| {
            bytes.windows(7).find_map(|w| {
                (w[0..3] == [0x48, 0x69, 0xc0])
                    .then(|| u32::from_le_bytes([w[3], w[4], w[5], w[6]]) as usize)
            })
        })
        .or_else(|| {
            bytes.windows(4).find_map(|w| {
                (w[0..3] == [0x48, 0xc1, 0xe0])
                    .then(|| 1usize.checked_shl(w[3] as u32))
                    .flatten()
            })
        })
        .filter(|size| *size >= 0x20 && *size <= 0x100)
}

fn find_x64_node_key_off(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).find_map(|w| {
        ((w[0..3] == [0x48, 0x8b, 0x50]) || (w[0..3] == [0x48, 0x8b, 0x48]))
            .then_some(w[3] as usize)
    })
}

fn find_x64_inline_return_off(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(5)
        .find_map(|w| (w[0..3] == [0x48, 0x83, 0xc0] && w[4] == 0xc3).then_some(w[3] as usize))
        .or_else(|| {
            bytes.windows(7).find_map(|w| {
                (w[0..2] == [0x48, 0x05] && w[6] == 0xc3)
                    .then(|| u32::from_le_bytes([w[2], w[3], w[4], w[5]]) as usize)
            })
        })
}

fn find_x64_pointer_return_off(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(5)
        .find_map(|w| (w[0..4] == [0x48, 0x8b, 0x44, 0x07]).then_some(w[4] as usize))
}

#[derive(Clone)]
struct ResolveResult {
    target_offset: usize,
    match_count: usize,
    variant_index: usize,
}

#[derive(Debug)]
struct VariantTarget {
    variant_index: usize,
    target_offset: usize,
}

#[derive(Debug)]
enum ResolveError {
    PatternParse(String),
    CalleePatternParse(String),
    NoMatch,
    Ambiguous(usize),
    VariantConflict(Vec<VariantTarget>),
    Follow(String, usize),
    MissingPrologue,
    CalleePatternMismatch(usize),
    PicEntryNotFound,
}

impl ResolveError {
    fn label(&self) -> &'static str {
        match self {
            Self::NoMatch => "MISS",
            Self::Ambiguous(_) => "AMB",
            _ => "FAIL",
        }
    }

    fn match_count(&self) -> usize {
        match self {
            Self::NoMatch => 0,
            Self::Ambiguous(count)
            | Self::Follow(_, count)
            | Self::CalleePatternMismatch(count) => *count,
            Self::VariantConflict(targets) => targets.len(),
            _ => 0,
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PatternParse(error) => write!(f, "pattern parse failed: {error}"),
            Self::CalleePatternParse(error) => write!(f, "callee pattern parse failed: {error}"),
            Self::NoMatch => write!(f, "pattern has no match"),
            Self::Ambiguous(count) => write!(f, "pattern is not unique: found {count} matches"),
            Self::VariantConflict(targets) => {
                write!(f, "pattern variants resolve to different targets:")?;
                for target in targets {
                    write!(
                        f,
                        " variant={} text+0x{:x}",
                        target.variant_index + 1,
                        target.target_offset
                    )?;
                }
                Ok(())
            }
            Self::Follow(error, _) => write!(f, "follow failed: {error}"),
            Self::MissingPrologue => write!(f, "upward follow requires prologue bytes"),
            Self::CalleePatternMismatch(_) => {
                write!(f, "no call target matched callee_pattern")
            }
            Self::PicEntryNotFound => write!(f, "PIC entry not found before prologue"),
        }
    }
}

fn resolve_entry_group(
    haystack: &[u8],
    entries: &[&ScanEntry],
) -> Result<ResolveResult, ResolveError> {
    let mut best_error = None;
    let mut successes = Vec::new();
    for (variant_index, entry) in entries.iter().copied().enumerate() {
        match resolve_entry(haystack, entry) {
            Ok(mut result) => {
                result.variant_index = variant_index;
                successes.push(result);
            }
            Err(error) => {
                best_error = Some(prefer_resolve_error(best_error.take(), error));
            }
        }
    }
    if let Some(result) = unique_successful_variant(successes)? {
        return Ok(result);
    }
    Err(best_error.unwrap_or(ResolveError::NoMatch))
}

fn unique_successful_variant(
    successes: Vec<ResolveResult>,
) -> Result<Option<ResolveResult>, ResolveError> {
    let Some(first) = successes.first() else {
        return Ok(None);
    };
    if successes
        .iter()
        .all(|result| result.target_offset == first.target_offset)
    {
        return Ok(Some(first.clone()));
    }

    Err(ResolveError::VariantConflict(
        successes
            .into_iter()
            .map(|result| VariantTarget {
                variant_index: result.variant_index,
                target_offset: result.target_offset,
            })
            .collect(),
    ))
}

fn prefer_resolve_error(previous: Option<ResolveError>, current: ResolveError) -> ResolveError {
    let Some(previous) = previous else {
        return current;
    };
    let previous_rank = resolve_error_rank(&previous);
    let current_rank = resolve_error_rank(&current);
    if current_rank > previous_rank {
        current
    } else if current_rank == previous_rank && current.match_count() > previous.match_count() {
        current
    } else {
        previous
    }
}

fn resolve_error_rank(error: &ResolveError) -> u8 {
    match error {
        ResolveError::NoMatch => 0,
        ResolveError::Ambiguous(_) => 1,
        _ => 2,
    }
}

fn resolve_entry(haystack: &[u8], entry: &ScanEntry) -> Result<ResolveResult, ResolveError> {
    let pattern = Pattern::parse(&entry.pattern)
        .map_err(|error| ResolveError::PatternParse(error.to_string()))?;
    let matches = pattern.find_all(haystack);
    if matches.is_empty() {
        return Err(ResolveError::NoMatch);
    }

    let match_count = matches.len();
    let target_offset = match entry.follow {
        FollowMode::None => unique_match(&matches)?,
        FollowMode::Relative => {
            let offset = unique_match(&matches)?;
            let target = follow_relative_call(haystack, offset)
                .map_err(|error| ResolveError::Follow(error.to_string(), match_count))?;
            if target < 0 || target as usize >= haystack.len() {
                return Err(ResolveError::Follow(
                    "relative target is out of bounds".to_owned(),
                    match_count,
                ));
            }
            target as usize
        }
        FollowMode::Upward => {
            let offset = unique_match(&matches)?;
            let prologue = entry
                .prologue
                .as_deref()
                .ok_or(ResolveError::MissingPrologue)?;
            find_prologue_upwards(haystack, offset, prologue, UPWARD_SCAN_BYTES)
                .map_err(|error| ResolveError::Follow(error.to_string(), match_count))?
        }
        FollowMode::Call => resolve_call_target(haystack, entry, &matches)?,
    };

    let target_offset = if entry.pic_entry {
        find_pic_entry(haystack, target_offset).ok_or(ResolveError::PicEntryNotFound)?
    } else {
        target_offset
    };

    Ok(ResolveResult {
        target_offset,
        match_count,
        variant_index: 0,
    })
}

fn unique_match(matches: &[usize]) -> Result<usize, ResolveError> {
    match matches {
        [] => Err(ResolveError::NoMatch),
        [offset] => Ok(*offset),
        many => Err(ResolveError::Ambiguous(many.len())),
    }
}

fn resolve_call_target(
    haystack: &[u8],
    entry: &ScanEntry,
    matches: &[usize],
) -> Result<usize, ResolveError> {
    let callee_pattern = entry
        .callee_pattern
        .as_deref()
        .map(Pattern::parse)
        .transpose()
        .map_err(|error| ResolveError::CalleePatternParse(error.to_string()))?;

    for &offset in matches {
        let Ok(target) = follow_last_call_before_ret(haystack, offset, FOLLOW_CALL_SCAN_BYTES)
        else {
            continue;
        };
        if let Some(callee_pattern) = callee_pattern.as_ref() {
            if !callee_pattern.matches_at(haystack, target) {
                continue;
            }
        }
        return Ok(target);
    }

    if callee_pattern.is_some() {
        Err(ResolveError::CalleePatternMismatch(matches.len()))
    } else {
        Err(ResolveError::Follow(
            "no call before RET".to_owned(),
            matches.len(),
        ))
    }
}

fn find_pic_entry(haystack: &[u8], prologue_offset: usize) -> Option<usize> {
    for offset in [10usize, 11] {
        let candidate = prologue_offset.checked_sub(offset)?;
        if haystack.get(candidate) == Some(&0xE8) {
            return Some(candidate);
        }
    }
    None
}

struct ExecutableSegment<'a> {
    bytes: &'a [u8],
    file_offset: u64,
    vaddr: u64,
}

fn executable_segment(data: &[u8]) -> Result<ExecutableSegment<'_>, String> {
    if data.get(..4) != Some(b"\x7fELF") {
        return Err("input is not an ELF file".to_owned());
    }
    if data.get(5) != Some(&1) {
        return Err("big-endian ELF files are not supported".to_owned());
    }

    match data.get(4) {
        Some(1) => executable_segment_elf32(data),
        Some(2) => executable_segment_elf64(data),
        _ => Err("unsupported ELF class".to_owned()),
    }
}

fn executable_segment_elf32(data: &[u8]) -> Result<ExecutableSegment<'_>, String> {
    let phoff = read_u32(data, 28)? as usize;
    let phentsize = read_u16(data, 42)? as usize;
    let phnum = read_u16(data, 44)? as usize;
    let mut best = None;

    for idx in 0..phnum {
        let off = phoff + idx * phentsize;
        let p_type = read_u32(data, off)?;
        let p_offset = read_u32(data, off + 4)? as u64;
        let p_vaddr = read_u32(data, off + 8)? as u64;
        let p_filesz = read_u32(data, off + 16)? as u64;
        let p_flags = read_u32(data, off + 24)?;
        if p_type == PT_LOAD && p_flags & PF_X != 0 {
            best = choose_largest_segment(best, p_offset, p_vaddr, p_filesz);
        }
    }

    slice_segment(data, best)
}

fn executable_segment_elf64(data: &[u8]) -> Result<ExecutableSegment<'_>, String> {
    let phoff = read_u64(data, 32)? as usize;
    let phentsize = read_u16(data, 54)? as usize;
    let phnum = read_u16(data, 56)? as usize;
    let mut best = None;

    for idx in 0..phnum {
        let off = phoff + idx * phentsize;
        let p_type = read_u32(data, off)?;
        let p_flags = read_u32(data, off + 4)?;
        let p_offset = read_u64(data, off + 8)?;
        let p_vaddr = read_u64(data, off + 16)?;
        let p_filesz = read_u64(data, off + 32)?;
        if p_type == PT_LOAD && p_flags & PF_X != 0 {
            best = choose_largest_segment(best, p_offset, p_vaddr, p_filesz);
        }
    }

    slice_segment(data, best)
}

fn choose_largest_segment(
    current: Option<(u64, u64, u64)>,
    file_offset: u64,
    vaddr: u64,
    file_size: u64,
) -> Option<(u64, u64, u64)> {
    match current {
        Some((_, _, current_size)) if current_size >= file_size => current,
        _ => Some((file_offset, vaddr, file_size)),
    }
}

fn slice_segment(
    data: &[u8],
    segment: Option<(u64, u64, u64)>,
) -> Result<ExecutableSegment<'_>, String> {
    let Some((file_offset, vaddr, file_size)) = segment else {
        return Err("ELF file has no executable PT_LOAD segment".to_owned());
    };
    let start = file_offset as usize;
    let end = start
        .checked_add(file_size as usize)
        .ok_or_else(|| "executable segment range overflows usize".to_owned())?;
    let bytes = data
        .get(start..end)
        .ok_or_else(|| "executable segment extends past EOF".to_owned())?;
    Ok(ExecutableSegment {
        bytes,
        file_offset,
        vaddr,
    })
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| "ELF header is truncated".to_owned())?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| "ELF header is truncated".to_owned())?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| "ELF header is truncated".to_owned())?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn place_asm32(
        code: &mut [u8],
        offset: usize,
        build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>,
    ) {
        let mut asm = CodeAssembler::new(32).expect("32-bit assembler should initialize");
        build(&mut asm).expect("test assembly should encode");
        let bytes = asm.assemble(0).expect("test assembly should assemble");
        code[offset..offset + bytes.len()].copy_from_slice(&bytes);
    }

    fn place_asm64(
        code: &mut [u8],
        offset: usize,
        build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>,
    ) {
        let mut asm = CodeAssembler::new(64).expect("64-bit assembler should initialize");
        build(&mut asm).expect("test assembly should encode");
        let bytes = asm.assemble(0).expect("test assembly should assemble");
        code[offset..offset + bytes.len()].copy_from_slice(&bytes);
    }

    fn missing_semantic_validations(toml: &str, arch: SemanticArch) -> Vec<String> {
        let mut entries = BTreeSet::new();
        for (name, entry) in parse_toml_patterns(toml).expect("patterns should parse") {
            entries.insert((entry.module, name));
        }

        entries
            .into_iter()
            .filter_map(|(module, name)| {
                (!has_semantic_validation(&module, arch, &name))
                    .then(|| format!("{module}::{name}"))
            })
            .collect()
    }

    #[test]
    fn parses_arch_aliases() {
        assert_eq!(PatternArch::parse("x86").unwrap(), PatternArch::X86);
        assert_eq!(PatternArch::parse("i686").unwrap(), PatternArch::X86);
        assert_eq!(PatternArch::parse("x86_64").unwrap(), PatternArch::X86_64);
        assert_eq!(PatternArch::parse("amd64").unwrap(), PatternArch::X86_64);
    }

    #[test]
    fn args_accept_arch_and_modules() {
        let args = Args::parse([
            "--arch".to_owned(),
            "x86_64".to_owned(),
            "--steamclient".to_owned(),
            "steamclient.so".to_owned(),
            "--steamui".to_owned(),
            "steamui.so".to_owned(),
        ])
        .unwrap();

        assert_eq!(args.arch, Some(PatternArch::X86_64));
        assert!(args.patterns.is_none());
        assert_eq!(args.steamclient.unwrap(), PathBuf::from("steamclient.so"));
        assert_eq!(args.steamui.unwrap(), PathBuf::from("steamui.so"));
    }

    #[test]
    fn args_reject_arch_with_explicit_patterns() {
        let err = Args::parse([
            "--arch".to_owned(),
            "x86_64".to_owned(),
            "--patterns".to_owned(),
            "res/patterns.x86_64.toml".to_owned(),
            "--steamclient".to_owned(),
            "steamclient.so".to_owned(),
        ])
        .unwrap_err();

        assert!(err.contains("--arch and --patterns cannot be used together"));
    }

    #[test]
    fn x86_patterns_have_semantic_validation() {
        let missing = missing_semantic_validations(
            include_str!("../../../../res/patterns.toml"),
            SemanticArch::X86,
        );
        assert!(
            missing.is_empty(),
            "missing semantic validation: {missing:?}"
        );
    }

    #[test]
    fn x86_64_patterns_have_semantic_validation() {
        let missing = missing_semantic_validations(
            include_str!("../../../../res/patterns.x86_64.toml"),
            SemanticArch::X86_64,
        );
        assert!(
            missing.is_empty(),
            "missing semantic validation: {missing:?}"
        );
    }

    #[test]
    fn validates_check_app_ownership32_ubuntu12_shape() {
        let mut code = vec![0x90; 0x420];
        let start = 0x20;
        place_asm32(&mut code, start + 0x10, |a| a.sub(esp, 0xACu32));
        place_asm32(&mut code, start + 0x20, |a| a.mov(ecx, 8));
        place_asm32(&mut code, start + 0x30, |a| a.mov(dword_ptr(eax), -1));
        place_asm32(&mut code, start + 0x40, |a| {
            a.mov(ecx, dword_ptr(eax + 0x1BD4))
        });
        place_asm32(&mut code, start + 0x50, |a| {
            a.mov(eax, dword_ptr(eax + 0x1BF0))
        });
        place_asm32(&mut code, start + 0x60, |a| a.mov(byte_ptr(eax + 0x28), 1));
        place_asm32(&mut code, start + 0x70, |a| a.mov(byte_ptr(eax + 0x30), 1));
        place_asm32(&mut code, start + 0x80, |a| a.mov(word_ptr(eax + 0x33), bx));
        place_asm32(&mut code, start + 0x90, |a| {
            a.mov(ecx, dword_ptr(edi + 0x0C))
        });
        place_asm32(&mut code, start + 0xa0, |a| {
            a.mov(eax, dword_ptr(eax + 0x1BC8))
        });
        place_asm32(&mut code, start + 0xb0, |a| {
            a.lea(edx, dword_ptr(eax + eax * 8))
        });

        assert_eq!(
            validate_check_app_ownership32(&code, start),
            Some("ownership result + license state")
        );
    }

    #[test]
    fn validates_check_app_ownership32_steamrt_shape() {
        let mut code = vec![0x90; 0x420];
        let start = 0x20;
        place_asm32(&mut code, start + 0x10, |a| a.sub(esp, 0xACu32));
        place_asm32(&mut code, start + 0x20, |a| a.mov(ecx, 0x0D));
        place_asm32(&mut code, start + 0x30, |a| a.mov(dword_ptr(esi), -1));
        place_asm32(&mut code, start + 0x40, |a| {
            a.mov(edx, dword_ptr(eax + 0x1BD0))
        });
        place_asm32(&mut code, start + 0x50, |a| {
            a.mov(ecx, dword_ptr(eax + 0x1BEC))
        });
        place_asm32(&mut code, start + 0x60, |a| a.mov(byte_ptr(esi + 0x28), 1));
        place_asm32(&mut code, start + 0x70, |a| a.mov(byte_ptr(esi + 0x30), 1));
        place_asm32(&mut code, start + 0x80, |a| a.mov(word_ptr(esi + 0x33), di));
        place_asm32(&mut code, start + 0x90, |a| {
            a.mov(eax, dword_ptr(eax + 0x0C))
        });
        place_asm32(&mut code, start + 0xa0, |a| {
            a.mov(edx, dword_ptr(edx + 0x1BC4))
        });
        place_asm32(&mut code, start + 0xb0, |a| {
            a.lea(ecx, dword_ptr(edx + edx * 8))
        });

        assert_eq!(
            validate_check_app_ownership32(&code, start),
            Some("ownership result + license state")
        );
    }

    #[test]
    fn validates_check_app_ownership64_shape() {
        let mut code = vec![0x90; 0x420];
        let start = 0x20;
        place_asm64(&mut code, start + 0x10, |a| a.sub(rsp, 0xB8));
        place_asm64(&mut code, start + 0x20, |a| a.mov(ecx, 6));
        place_asm64(&mut code, start + 0x30, |a| {
            a.mov(dword_ptr(rsp + 0x70), -1)
        });
        place_asm64(&mut code, start + 0x40, |a| {
            a.mov(edx, dword_ptr(rbx + 0x2498))
        });
        place_asm64(&mut code, start + 0x50, |a| {
            a.mov(r9d, dword_ptr(rbx + 0x24BC))
        });
        place_asm64(&mut code, start + 0x60, |a| a.mov(byte_ptr(r14 + 0x28), 1));
        place_asm64(&mut code, start + 0x70, |a| a.mov(byte_ptr(r14 + 0x30), 1));
        place_asm64(&mut code, start + 0x80, |a| {
            a.mov(word_ptr(r14 + 0x33), r8w)
        });
        place_asm64(&mut code, start + 0x90, |a| {
            a.mov(eax, dword_ptr(rax + 0x10))
        });
        place_asm64(&mut code, start + 0xa0, |a| {
            a.movsxd(rdx, dword_ptr(rdx + r13 * 4))
        });

        assert_eq!(
            validate_check_app_ownership64(&code, start),
            Some("ownership result + license state")
        );
    }

    #[test]
    fn discovers_steam_app32_layout_from_fill_in_app_overview() {
        let mut code = vec![0x90; 0x300];
        let start = 0x20;
        place_asm32(&mut code, start + 0x40, |a| {
            a.mov(eax, dword_ptr(ebx + 0x0C))
        });
        place_asm32(&mut code, start + 0x80, |a| {
            a.mov(edx, dword_ptr(eax + 0x08))?;
            a.mov(eax, dword_ptr(eax + 0x04))
        });
        place_asm32(&mut code, start + 0xc0, |a| {
            a.mov(eax, dword_ptr(ebx + 0x28))
        });

        let layout = discover_steam_app32_layout(&code, start).unwrap();
        assert_eq!(
            layout,
            SteamAppLayout {
                game_id_off: 0x04,
                app_id_off: 0x0c,
                purchased_time_off: 0x28,
            }
        );
    }

    #[test]
    fn discovers_steam_app64_layout_from_fill_in_app_overview() {
        let mut code = vec![0x90; 0x300];
        let start = 0x20;
        place_asm64(&mut code, start + 0x20, |a| {
            a.mov(rax, qword_ptr(rbp + 0x08))
        });
        place_asm64(&mut code, start + 0x40, |a| {
            a.mov(r12d, dword_ptr(rbp + 0x10))
        });
        place_asm64(&mut code, start + 0x80, |a| {
            a.mov(eax, dword_ptr(rbp + 0x2C))
        });

        let layout = discover_steam_app64_layout(&code, start).unwrap();
        assert_eq!(
            layout,
            SteamAppLayout {
                game_id_off: 0x08,
                app_id_off: 0x10,
                purchased_time_off: 0x2c,
            }
        );
    }

    #[test]
    fn discovers_app_overview_change32_layout_from_build_complete() {
        let mut code = vec![0x90; 0x180];
        let start = 0x20;
        place_asm32(&mut code, start + 0x30, |a| a.mov(byte_ptr(edx + 0x2C), 1));
        place_asm32(&mut code, start + 0x38, |a| a.or(dword_ptr(edx + 0x08), 1));
        place_asm32(&mut code, start + 0x40, |a| a.add(edx, 0x10));

        let layout = discover_app_overview_change32_layout(&code, start).unwrap();
        assert_eq!(
            layout,
            AppOverviewChangeLayout {
                app_overview_off: 0x10,
                removed_appid_off: 0x1c,
            }
        );
    }

    #[test]
    fn discovers_app_overview_change64_layout_from_build_complete() {
        let mut code = vec![0x90; 0x180];
        let start = 0x20;
        place_asm64(&mut code, start + 0x30, |a| {
            a.lea(rdi, qword_ptr(rbx + 0x18))
        });
        place_asm64(&mut code, start + 0x40, |a| a.mov(byte_ptr(rbx + 0x40), 1));
        place_asm64(&mut code, start + 0x50, |a| a.or(dword_ptr(rbx + 0x10), 1));

        let layout = discover_app_overview_change64_layout(&code, start).unwrap();
        assert_eq!(
            layout,
            AppOverviewChangeLayout {
                app_overview_off: 0x18,
                removed_appid_off: 0x28,
            }
        );
    }

    #[test]
    fn discovers_package_info32_layout_from_lookup_shape() {
        let mut code = vec![0x90; 0x300];
        let start = 0x20;
        place_asm32(&mut code, start, |a| {
            a.mov(esi, dword_ptr(ebp + 0x0C))?;
            a.mov(eax, dword_ptr(ebp + 0x10))?;
            a.mov(edx, dword_ptr(ebp + 0x14))
        });
        place_asm32(&mut code, start + 0x20, |a| {
            a.mov(eax, dword_ptr(eax + 0x18))
        });
        place_asm32(&mut code, start + 0x30, |a| {
            a.mov(edx, dword_ptr(ebx + 0x2C))
        });
        place_asm32(&mut code, start + 0x40, |a| {
            a.lea(eax, dword_ptr(eax + eax * 2))?;
            a.lea(eax, dword_ptr(edx + eax * 8))
        });
        place_asm32(&mut code, start + 0x50, |a| {
            a.cmp(dword_ptr(eax + 0x10), esi)
        });
        place_asm32(&mut code, start + 0x60, |a| {
            a.mov(edi, dword_ptr(eax + 0x14))
        });
        place_asm32(&mut code, start + 0x70, |a| {
            a.movq(xmm0, qword_ptr(edi + 0x08))
        });

        let layout = discover_package_info32_layout(&code, start).unwrap();
        assert_eq!(layout.count_off, 0x18);
        assert_eq!(layout.elements_off, 0x2c);
        assert_eq!(layout.node_size, 0x18);
        assert_eq!(layout.node_key_off, 0x10);
        assert_eq!(layout.node_value_off, 0x14);
    }

    #[test]
    fn discovers_package_info64_layout_from_lookup_shape() {
        let mut code = vec![0x90; 0x200];
        let start = 0x30;
        place_asm64(&mut code, start, |a| a.movsxd(rax, dword_ptr(rdi + 0x570)));
        place_asm64(&mut code, start + 0x10, |a| {
            a.mov(rdi, qword_ptr(rdi + 0x588))
        });
        place_asm64(&mut code, start + 0x20, |a| a.imul_3(rax, rax, 0x78));
        place_asm64(&mut code, start + 0x30, |a| {
            a.mov(rdx, qword_ptr(rax + 0x10))
        });
        place_asm64(&mut code, start + 0x40, |a| {
            a.add(rax, 0x18)?;
            a.ret()
        });

        let layout = discover_package_info64_layout(&code, start).unwrap();
        assert_eq!(layout.count_off, 0x570);
        assert_eq!(layout.elements_off, 0x588);
        assert_eq!(layout.node_size, 0x78);
        assert_eq!(layout.node_key_off, 0x10);
        assert_eq!(layout.node_value_off, 0x18);
    }

    #[test]
    fn validates_is_user_subscribed_app_in_ticket32_checker() {
        let mut code = vec![0x90; 0x220];
        let start = 0x20;
        place_asm32(&mut code, start + 0x40, |a| {
            a.and(edx, -3)?;
            a.cmp(edx, 1)
        });
        place_asm32(&mut code, start + 0x70, |a| a.mov(dword_ptr(esp + 0x0C), 2));
        place_asm32(&mut code, start + 0xa0, |a| a.mov(dword_ptr(esp + 0x0C), 1));
        place_asm32(&mut code, start + 0xd0, |a| a.mov(dword_ptr(esp + 0x0C), 0));

        assert!(is_user_subscribed_app_in_ticket32_evidence(&code, start)
            .unwrap()
            .is_complete());
    }

    #[test]
    fn rejects_is_user_subscribed_app_in_ticket32_remover() {
        let mut code = vec![0x90; 0x220];
        let start = 0x20;
        place_asm32(&mut code, start + 0x40, |a| {
            a.and(edx, -3)?;
            a.cmp(edx, 1)
        });
        place_asm32(&mut code, start + 0x70, |a| a.mov(dword_ptr(esp + 0x0C), 2));
        place_asm32(&mut code, start + 0xa0, |a| a.mov(dword_ptr(esp + 0x0C), 1));
        place_asm32(&mut code, start + 0xd0, |a| a.mov(dword_ptr(esp + 0x0C), 0));
        place_asm32(&mut code, start + 0x100, |a| {
            a.mov(dword_ptr(ecx + 0x1884), eax)
        });

        let evidence = is_user_subscribed_app_in_ticket32_evidence(&code, start).unwrap();
        assert!(!evidence.is_complete());
        assert_eq!(evidence.missing, vec!["ticket removal side effect"]);
    }

    #[test]
    fn classifies_public_wrapper_policy() {
        assert_eq!(
            wrapper_policy("IClientRemoteStorage::RunIPCFrame"),
            WrapperPolicy::WrapperAllowed
        );
        assert_eq!(
            wrapper_policy("IClientUser::BUpdateAppOwnershipTicket"),
            WrapperPolicy::ImplementationRequired
        );
        assert_eq!(
            wrapper_policy("CUser::CheckAppOwnership"),
            WrapperPolicy::NotApplicable
        );
    }

    #[test]
    fn entry_group_reports_variant_target_conflicts() {
        let haystack = [0xAA, 0xBB, 0x90, 0xCC, 0xDD];
        let variant_a = ScanEntry {
            name: "Test::VariantConflict".to_owned(),
            pattern: "AA BB".to_owned(),
            follow: FollowMode::None,
            prologue: None,
            callee_pattern: None,
            optional: false,
            pic_entry: false,
            module: "steamclient".to_owned(),
        };
        let variant_b = ScanEntry {
            name: "Test::VariantConflict".to_owned(),
            pattern: "CC DD".to_owned(),
            follow: FollowMode::None,
            prologue: None,
            callee_pattern: None,
            optional: false,
            pic_entry: false,
            module: "steamclient".to_owned(),
        };
        let entries = [&variant_a, &variant_b];

        let result = resolve_entry_group(&haystack, &entries);
        match result {
            Err(ResolveError::VariantConflict(targets)) => {
                assert_eq!(targets.len(), 2);
                assert_eq!(targets[0].variant_index, 0);
                assert_eq!(targets[0].target_offset, 0);
                assert_eq!(targets[1].variant_index, 1);
                assert_eq!(targets[1].target_offset, 3);
            }
            Ok(_) => panic!("variant conflict should not resolve as OK"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
