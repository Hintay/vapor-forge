use std::collections::HashMap;
use std::path::{Path, PathBuf};

use iced_x86::code_asm::*;
use vapor_forge_patterns::elf::{ElfImage, ExecutableSegment};
use vapor_forge_patterns::registry::{
    parse_toml_patterns, FollowMode, PatternDef, RuntimePatternEntry, EMBEDDED_PATTERNS,
};
use vapor_forge_patterns::scan::{
    group_variants, resolve_entry_group, select_variants_for_library_path, PatternRef,
    ResolveError, ResolveResult,
};
use vapor_forge_patterns::vtable_scan::{self, ElfClass};
use vapor_forge_patterns::Pattern;

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
        Err("one or more patterns failed".to_owned())
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
    pic_entry: bool,
    steamrt_variant: bool,
    module: String,
}

impl<'a> From<&'a ScanEntry> for PatternRef<'a> {
    fn from(entry: &'a ScanEntry) -> Self {
        Self {
            name: &entry.name,
            pattern: &entry.pattern,
            follow: entry.follow,
            prologue: entry.prologue.as_deref(),
            callee_pattern: entry.callee_pattern.as_deref(),
            pic_entry: entry.pic_entry,
            steamrt_variant: entry.steamrt_variant,
            module: &entry.module,
        }
    }
}

impl From<&PatternDef> for ScanEntry {
    fn from(entry: &PatternDef) -> Self {
        Self {
            name: entry.name.to_owned(),
            pattern: entry.pattern.to_owned(),
            follow: entry.follow,
            prologue: entry.prologue.map(<[u8]>::to_vec),
            callee_pattern: entry.callee_pattern.map(str::to_owned),
            pic_entry: entry.pic_entry,
            steamrt_variant: entry.steamrt_variant,
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
            pic_entry: entry.pic_entry,
            steamrt_variant: entry.steamrt_variant,
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
    let variants = entries
        .iter()
        .map(|entry| PatternRef::from(*entry))
        .collect::<Vec<_>>();
    let variants = select_variants_for_library_path(&variants, path);
    for group in group_variants(&variants) {
        let entry = group[0];
        let resolution = if is_elf64 && entry.name == "google::protobuf::RepeatedField<uint32>::Add"
        {
            resolve_equivalent_repeated_field_add64(segment.bytes, &group)
        } else {
            resolve_entry_group(segment.bytes, &group)
        };
        match resolution {
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
                resolved.insert(entry.name, result.target_offset);
            }
            Err(error) => {
                failed = true;
                println!(
                    "  {:<4} {:<58} hits={} required ({})",
                    error.status().label(),
                    entry.name,
                    error.match_count(),
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
        failed |= scan_config_store_uint64_wrapper_abi(path);
        failed |= scan_user_stats_wrapper_abi(path, &data);
        failed |= scan_cuser_stats_adapters(
            path,
            segment.bytes,
            segment.vaddr,
            if is_elf64 {
                SemanticArch::X86_64
            } else {
                SemanticArch::X86
            },
        );
        failed |= scan_cuser_adapters(
            path,
            segment.bytes,
            segment.vaddr,
            if is_elf64 {
                SemanticArch::X86_64
            } else {
                SemanticArch::X86
            },
            &resolved,
        );
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

fn resolve_equivalent_repeated_field_add64(
    code: &[u8],
    entries: &[PatternRef<'_>],
) -> Result<ResolveResult, ResolveError> {
    let mut match_count = 0usize;
    for (variant_index, entry) in entries.iter().enumerate() {
        let pattern = Pattern::parse(entry.pattern)
            .map_err(|error| ResolveError::PatternParse(error.to_string()))?;
        let matches = pattern.find_all(code);
        match_count += matches.len();
        if let Some(target_offset) = matches.into_iter().find(|&offset| {
            repeated_field_add64_evidence(code, offset)
                .is_some_and(|evidence| evidence.is_complete())
        }) {
            return Ok(ResolveResult {
                target_offset,
                match_count,
                variant_index,
            });
        }
    }
    if match_count == 0 {
        Err(ResolveError::NoMatch)
    } else {
        Err(ResolveError::CalleePatternMismatch(match_count))
    }
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
    let mut implementation_required = 0usize;
    for (&entry_name, &target_offset) in resolved {
        if !requires_interface_implementation(entry_name) {
            continue;
        }
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
                    println!(
                        "  FAIL {:<58} va=0x{:x} matches public {}::{} slot {}",
                        entry_name, target_va, iface.name, method.name, method.slot
                    );
                    print_possible_implementations(path, &iface.name, method.slot);
                    failed = true;
                    implementation_required += 1;
                }
            }
        }
    }

    if !failed {
        println!(
            "  OK   {:<58} blocked={}",
            "IClient public wrapper check", implementation_required
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
    let image = ElfImage::parse(&data)?;
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

fn follow_diagnostic_thunk(image: &ElfImage<'_>, func_va: u64) -> Option<u64> {
    match image.class {
        ElfClass::Elf64 => follow_diagnostic_thunk_x64(image, func_va),
        ElfClass::Elf32 => follow_diagnostic_thunk_x86(image, func_va),
    }
}

fn follow_diagnostic_thunk_x64(image: &ElfImage<'_>, func_va: u64) -> Option<u64> {
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

fn follow_diagnostic_thunk_x86(image: &ElfImage<'_>, func_va: u64) -> Option<u64> {
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
    image: &ElfImage<'_>,
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

fn find_diagnostic_vtables(image: &ElfImage<'_>) -> Vec<(u64, Vec<u64>)> {
    let word = image.word_size() as u64;
    let mut out = Vec::new();

    for load in &image.loads {
        if load.is_executable() {
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

fn diagnostic_typeinfo_name(image: &ElfImage<'_>, vtable_va: u64) -> Option<String> {
    let word = image.word_size() as u64;
    let ti = image.read_word_va(vtable_va.checked_sub(word)?)?;
    if !image.in_module(ti) {
        return None;
    }
    let name_va = image.read_word_va(ti.checked_add(word)?)?;
    if !image.in_module(name_va) {
        return None;
    }
    let name = image.read_cstring(name_va, 96);
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

include!("vapor-forge-pattern-scan/semantic.rs");

fn executable_segment(data: &[u8]) -> Result<ExecutableSegment<'_>, String> {
    ElfImage::parse(data)?.largest_executable_segment()
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

    fn place_http_download_consumer32(code: &mut [u8], offset: usize) {
        place_asm32(code, offset, |a| {
            a.mov(eax, dword_ptr(edx + 0x50))?;
            a.mov(eax, dword_ptr(eax + 0x94))?;
            a.test(eax, eax)?;
            a.mov(ebx, dword_ptr(edx + 0x54))?;
            a.mov(ecx, dword_ptr(eax))?;
            a.push(dword_ptr(ebx + 0x38))?;
            a.push(edx)?;
            a.push(eax)?;
            a.call(dword_ptr(ecx + 0x18))
        });
    }

    fn place_http_download_consumer64(code: &mut [u8], offset: usize) {
        place_asm64(code, offset, |a| {
            a.mov(rax, qword_ptr(rsi + 0x68))?;
            a.mov(rdi, qword_ptr(rax + 0xe0))?;
            a.test(rdi, rdi)?;
            a.mov(rax, qword_ptr(rsi + 0x70))?;
            a.mov(rdx, qword_ptr(rax + 0x50))?;
            a.mov(rax, qword_ptr(rdi))?;
            a.call(qword_ptr(rax + 0x30))
        });
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
    fn validates_http_request_job_start32_cdecl_shape() {
        let mut code = vec![0x90; 0x300];
        let start = 0x20;
        place_asm32(&mut code, start + 0x10, |a| {
            a.mov(ebx, dword_ptr(ebp + 0x14))?;
            a.mov(eax, dword_ptr(ebp + 0x0C))?;
            a.mov(edx, dword_ptr(ebp + 0x10))?;
            a.mov(edi, dword_ptr(ebp + 0x08))
        });
        place_asm32(&mut code, start + 0x30, |a| {
            a.add(dword_ptr(edi + 0x38), 1)?;
            a.adc(dword_ptr(edi + 0x3C), 0)?;
            a.mov(eax, dword_ptr(eax + 0x60))
        });
        place_asm32(&mut code, start + 0x50, |a| a.or(byte_ptr(edx + 0x46), al));
        place_http_download_consumer32(&mut code, 0x220);

        assert!(http_request_job_start32_evidence(&code, start)
            .is_some_and(|evidence| evidence.is_complete()));

        let incomplete = &code[..start + 0x50];
        assert!(http_request_job_start32_evidence(incomplete, start)
            .is_some_and(|evidence| !evidence.is_complete()));
    }

    #[test]
    fn validates_http_request_job_start32_steamrt_shape() {
        let mut code = vec![0x90; 0x300];
        let start = 0x20;
        place_asm32(&mut code, start + 0x10, |a| {
            a.mov(eax, dword_ptr(ebp + 0x10))?;
            a.mov(edi, dword_ptr(ebp + 0x08))?;
            a.mov(ebx, dword_ptr(ebp + 0x0C))?;
            a.mov(eax, dword_ptr(ebp + 0x14))
        });
        place_asm32(&mut code, start + 0x30, |a| {
            a.movq(xmm0, qword_ptr(edi + 0x38))?;
            a.movdqa(xmm1, xmmword_ptr(esi + 0x1234))?;
            a.paddq(xmm0, xmm1)?;
            a.movq(qword_ptr(edi + 0x38), xmm0)?;
            a.mov(eax, dword_ptr(ebx + 0x60))
        });
        place_asm32(&mut code, start + 0x50, |a| a.or(byte_ptr(ecx + 0x46), al));
        place_http_download_consumer32(&mut code, 0x220);

        assert!(http_request_job_start32_evidence(&code, start)
            .is_some_and(|evidence| evidence.is_complete()));
    }

    #[test]
    fn validates_http_request_job_start64_linux_shape() {
        let mut code = vec![0x90; 0x300];
        let start = 0x20;
        place_asm64(&mut code, start + 0x10, |a| {
            a.mov(r12, rsi)?;
            a.mov(rbp, rdi)?;
            a.mov(qword_ptr(rsp + 0x08), rdx)?;
            a.add(qword_ptr(rdi + 0x40), 1)?;
            a.mov(r15, qword_ptr(rsi + 0x88))?;
            a.or(byte_ptr(r12 + 0x52), al)
        });
        place_http_download_consumer64(&mut code, 0x220);

        assert!(http_request_job_start64_evidence(&code, start)
            .is_some_and(|evidence| evidence.is_complete()));
    }

    #[test]
    fn validates_mark_license_changed64_added_state_shape() {
        let mut code = vec![0x90; 0x300];
        let start = 0x20;
        place_asm64(&mut code, start + 0x10, |a| {
            a.mov(byte_ptr(rsp + 0x18), dl)?;
            a.mov(dword_ptr(rsp + 0x1c), esi)?;
            a.mov(edx, dword_ptr(rdi + 0x2394))?;
            a.imul_3(ebx, ebx, 0x85EBCA6Bu32)?;
            a.imul_3(ebx, ebx, 0xC2B2AE35u32)?;
            a.cmp(byte_ptr(rax + 4), 0)?;
            a.mov(byte_ptr(rsp + 0x18), 1)
        });

        assert_eq!(
            validate_mark_license_changed64(&code, start),
            Some("license change map update")
        );
    }

    #[test]
    fn rejects_cd_key_body_as_mark_license_changed64() {
        let mut code = vec![0x90; 0x300];
        let start = 0x20;
        place_asm64(&mut code, start + 0x10, |a| {
            a.mov(ebp, esi)?;
            a.lea(r12, qword_ptr(rax + 0xF20))?;
            a.mov(ecx, 7)?;
            a.mov(dword_ptr(rsp), -1)?;
            a.mov(rdi, r13)?;
            a.test(al, al)
        });

        assert!(validate_mark_license_changed64(&code, start).is_none());
    }

    #[test]
    fn recognizes_x86_cgameid_reference_abi() {
        let code = asm_bytes32(|a| {
            a.push(ebp)?;
            a.mov(ebp, esp)?;
            a.mov(eax, dword_ptr(ebp + 0x0c))?;
            a.movq(xmm0, qword_ptr(eax))
        })
        .unwrap();
        assert!(wrapper_dereferences_game_id(&code, ElfClass::Elf32));

        let by_value = asm_bytes32(|a| a.mov(eax, dword_ptr(ebp + 0x0c))).unwrap();
        assert!(!wrapper_dereferences_game_id(&by_value, ElfClass::Elf32));
    }

    #[test]
    fn recognizes_x86_cgameid_reference_abi_after_frame_spill() {
        let code = asm_bytes32(|a| {
            a.push(ebp)?;
            a.mov(ebp, esp)?;
            a.mov(edx, dword_ptr(ebp + 0x0c))?;
            a.mov(dword_ptr(ebp - 0x70), edx)?;
            a.xor(edx, edx)?;
            a.mov(edx, dword_ptr(ebp - 0x70))?;
            a.movq(xmm0, qword_ptr(edx))
        })
        .unwrap();
        assert!(wrapper_dereferences_game_id(&code, ElfClass::Elf32));

        let by_value = asm_bytes32(|a| {
            a.mov(edx, dword_ptr(ebp + 0x0c))?;
            a.mov(dword_ptr(ebp - 0x70), edx)?;
            a.mov(eax, dword_ptr(ebp - 0x70))
        })
        .unwrap();
        assert!(!wrapper_dereferences_game_id(&by_value, ElfClass::Elf32));
    }

    #[test]
    fn recognizes_x86_64_cgameid_reference_abi() {
        let code = asm_bytes64(|a| {
            a.mov(r12, rsi)?;
            a.mov(rax, qword_ptr(r12))
        })
        .unwrap();
        assert!(wrapper_dereferences_game_id(&code, ElfClass::Elf64));

        let by_value = asm_bytes64(|a| a.mov(rax, rsi)).unwrap();
        assert!(!wrapper_dereferences_game_id(&by_value, ElfClass::Elf64));
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
    fn discovers_current_package_info64_layout_from_lookup_shape() {
        let mut code = vec![0x90; 0x200];
        let start = 0x30;
        place_asm64(&mut code, start, |a| a.movsxd(rax, dword_ptr(rdi + 0x570)));
        place_asm64(&mut code, start + 0x10, |a| {
            a.mov(rcx, qword_ptr(rdi + 0x588))
        });
        place_asm64(&mut code, start + 0x20, |a| a.imul_3(rax, rax, 0x78));
        place_asm64(&mut code, start + 0x30, |a| {
            a.cmp(rdx, qword_ptr(rax + 0x10))
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
    fn cuser_adapter_resolution_rejects_missing_implementation() {
        let code = vec![0x90; 0x200];
        assert_eq!(
            resolve_cuser_adapter_implementation(
                &code,
                0,
                0x20,
                CUserAdapterKind::IsSubscribedInTicket,
                SemanticArch::X86_64,
                &HashMap::new(),
            ),
            None
        );
    }

    #[test]
    fn cuser_adapter_resolution_follows_wrapper_to_implementation() {
        let mut code = vec![0x90; 0x400];
        let wrapper = 0x20usize;
        let implementation = 0x280usize;
        let call = wrapper + 14;
        let displacement = (implementation as isize - (call + 5) as isize) as i32;
        let mut wrapper_bytes = vec![
            0x89, 0xd1, // mov ecx, edx
            0x48, 0x8d, 0x54, 0x24, 0x08, // lea rdx, [rsp+8]
            0x48, 0x8d, 0xbf, 0x30, 0xe0, 0xff, 0xff, // lea rdi, [rdi-0x1fd0]
            0xe8, // call implementation
        ];
        wrapper_bytes.extend_from_slice(&displacement.to_le_bytes());
        wrapper_bytes.push(0xc3);
        code[wrapper..wrapper + wrapper_bytes.len()].copy_from_slice(&wrapper_bytes);
        code[implementation..implementation + 22].copy_from_slice(&[
            0x83, 0xe2, 0xfd, 0x83, 0xfa, 0x01, // ticket status filter
            0x41, 0xb8, 0x02, 0x00, 0x00, 0x00, // return code 2
            0x41, 0xb8, 0x01, 0x00, 0x00, 0x00, // return code 1
            0x45, 0x31, 0xc0, // return code 0
            0xc3,
        ]);

        assert_eq!(
            resolve_cuser_adapter_implementation(
                &code,
                0,
                wrapper,
                CUserAdapterKind::IsSubscribedInTicket,
                SemanticArch::X86_64,
                &HashMap::new(),
            ),
            Some(implementation)
        );
    }
}
