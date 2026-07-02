use std::fmt;
use std::path::{Path, PathBuf};

use vapor_forge_patterns::registry::{FollowMode, PatternDef, EMBEDDED_PATTERNS};
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
    let mut failed = false;

    if let Some(path) = args.steamclient.as_deref() {
        failed |= scan_module("steamclient", path)?;
    }
    if let Some(path) = args.steamui.as_deref() {
        failed |= scan_module("steamui", path)?;
    }

    if failed {
        Err("one or more required patterns failed".to_owned())
    } else {
        Ok(())
    }
}

struct Args {
    steamclient: Option<PathBuf>,
    steamui: Option<PathBuf>,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut steamclient = None;
        let mut steamui = None;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
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

        if steamclient.is_none() && steamui.is_none() {
            return Err(usage());
        }

        Ok(Self {
            steamclient,
            steamui,
        })
    }
}

fn next_path(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf, String> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{flag} requires a path\n{}", usage()))
}

fn usage() -> String {
    "usage: vapor-forge-pattern-scan [--steamclient PATH] [--steamui PATH]".to_owned()
}

fn scan_module(module: &str, path: &Path) -> Result<bool, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let segment = executable_segment(&data)?;
    let entries: Vec<_> = EMBEDDED_PATTERNS
        .iter()
        .filter(|entry| entry.module == module)
        .collect();
    if entries.is_empty() {
        return Err(format!("no embedded patterns for module {module:?}"));
    }

    println!(
        "{}: {} text_file_off=0x{:x} text_vaddr=0x{:x} text_size=0x{:x}",
        module,
        path.display(),
        segment.file_offset,
        segment.vaddr,
        segment.bytes.len()
    );

    let mut failed = false;
    for entry in entries {
        match resolve_entry(segment.bytes, entry) {
            Ok(result) => {
                println!(
                    "  OK   {:<58} text+0x{:x} hits={}",
                    entry.name, result.target_offset, result.match_count
                );
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
    println!();

    Ok(failed)
}

struct ResolveResult {
    target_offset: usize,
    match_count: usize,
}

#[derive(Debug)]
enum ResolveError {
    PatternParse(String),
    CalleePatternParse(String),
    NoMatch,
    Ambiguous(usize),
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
            Self::Follow(error, _) => write!(f, "follow failed: {error}"),
            Self::MissingPrologue => write!(f, "upward follow requires prologue bytes"),
            Self::CalleePatternMismatch(_) => {
                write!(f, "no call target matched callee_pattern")
            }
            Self::PicEntryNotFound => write!(f, "PIC entry not found before prologue"),
        }
    }
}

fn resolve_entry(haystack: &[u8], entry: &PatternDef) -> Result<ResolveResult, ResolveError> {
    let pattern = Pattern::parse(entry.pattern)
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
            let prologue = entry.prologue.ok_or(ResolveError::MissingPrologue)?;
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
    entry: &PatternDef,
    matches: &[usize],
) -> Result<usize, ResolveError> {
    let callee_pattern = entry
        .callee_pattern
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
