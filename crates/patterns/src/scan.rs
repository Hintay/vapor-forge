use std::fmt;
use std::path::{Path, PathBuf};

use crate::registry::{FollowMode, PatternDef, EMBEDDED_PATTERNS};
use crate::{find_prologue_upwards, follow_last_call_before_ret, follow_relative_call, Pattern};

const PT_LOAD: u32 = 1;
const PF_X: u32 = 0x1;
const FOLLOW_CALL_SCAN_BYTES: usize = 256;
const UPWARD_SCAN_BYTES: usize = 0x10000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

impl ElfClass {
    pub fn bits(self) -> u8 {
        match self {
            Self::Elf32 => 32,
            Self::Elf64 => 64,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ModuleScanReport {
    pub module: String,
    pub path: PathBuf,
    pub elf_class: ElfClass,
    pub text_file_off: u64,
    pub text_vaddr: u64,
    pub text_size: usize,
    pub entries: Vec<PatternScanEntry>,
}

impl ModuleScanReport {
    pub fn required_failures(&self) -> impl Iterator<Item = &PatternScanEntry> {
        self.entries
            .iter()
            .filter(|entry| !entry.optional && entry.status != PatternScanStatus::Ok)
    }

    pub fn failure_count(&self) -> usize {
        self.required_failures().count()
    }

    pub fn ok_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.status == PatternScanStatus::Ok)
            .count()
    }

    pub fn miss_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.status != PatternScanStatus::Ok)
            .count()
    }
}

#[derive(Clone, Debug)]
pub struct PatternScanEntry {
    pub name: &'static str,
    pub optional: bool,
    pub status: PatternScanStatus,
    pub match_count: usize,
    pub target_offset: Option<usize>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatternScanStatus {
    Ok,
    Miss,
    Ambiguous,
    Fail,
}

impl PatternScanStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Miss => "MISS",
            Self::Ambiguous => "AMB",
            Self::Fail => "FAIL",
        }
    }
}

pub fn scan_module(module: &str, path: &Path) -> Result<ModuleScanReport, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let segment = executable_segment(&data)?;
    let patterns: Vec<_> = EMBEDDED_PATTERNS
        .iter()
        .filter(|entry| entry.module == module)
        .collect();
    if patterns.is_empty() {
        return Err(format!("no embedded patterns for module {module:?}"));
    }

    let entries = group_pattern_defs(&patterns)
        .into_iter()
        .map(|group| scan_entry_group(segment.bytes, &group))
        .collect();

    Ok(ModuleScanReport {
        module: module.to_owned(),
        path: path.to_owned(),
        elf_class: segment.elf_class,
        text_file_off: segment.file_offset,
        text_vaddr: segment.vaddr,
        text_size: segment.bytes.len(),
        entries,
    })
}

fn group_pattern_defs<'a>(entries: &[&'a PatternDef]) -> Vec<Vec<&'a PatternDef>> {
    let mut groups: Vec<Vec<&PatternDef>> = Vec::new();
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

fn scan_entry_group(haystack: &[u8], entries: &[&'static PatternDef]) -> PatternScanEntry {
    let entry = entries[0];
    match resolve_entry_group(haystack, entries) {
        Ok(result) => PatternScanEntry {
            name: entry.name,
            optional: entry.optional,
            status: PatternScanStatus::Ok,
            match_count: result.match_count,
            target_offset: Some(result.target_offset),
            error: None,
        },
        Err(error) => PatternScanEntry {
            name: entry.name,
            optional: entry.optional,
            status: error.status(),
            match_count: error.match_count(),
            target_offset: None,
            error: Some(error.to_string()),
        },
    }
}

#[derive(Clone)]
struct ResolveResult {
    target_offset: usize,
    match_count: usize,
}

fn resolve_entry_group(
    haystack: &[u8],
    entries: &[&'static PatternDef],
) -> Result<ResolveResult, ResolveError> {
    let mut best_error = None;
    let mut successes = Vec::new();
    for entry in entries {
        match resolve_entry(haystack, entry) {
            Ok(result) => successes.push(result),
            Err(error) => best_error = Some(prefer_resolve_error(best_error.take(), error)),
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
            .map(|result| result.target_offset)
            .collect(),
    ))
}

fn prefer_resolve_error(previous: Option<ResolveError>, current: ResolveError) -> ResolveError {
    let Some(previous) = previous else {
        return current;
    };
    let previous_rank = resolve_error_rank(&previous);
    let current_rank = resolve_error_rank(&current);
    if current_rank > previous_rank
        || current_rank == previous_rank && current.match_count() > previous.match_count()
    {
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

#[derive(Debug)]
enum ResolveError {
    PatternParse(String),
    CalleePatternParse(String),
    NoMatch,
    Ambiguous(usize),
    VariantConflict(Vec<usize>),
    Follow(String, usize),
    MissingPrologue,
    CalleePatternMismatch(usize),
    PicEntryNotFound,
}

impl ResolveError {
    fn status(&self) -> PatternScanStatus {
        match self {
            Self::NoMatch => PatternScanStatus::Miss,
            Self::Ambiguous(_) => PatternScanStatus::Ambiguous,
            _ => PatternScanStatus::Fail,
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
                    write!(f, " text+0x{target:x}")?;
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
    elf_class: ElfClass,
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

    slice_segment(data, best, ElfClass::Elf32)
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

    slice_segment(data, best, ElfClass::Elf64)
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
    elf_class: ElfClass,
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
        elf_class,
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

    static VARIANT_A: PatternDef = PatternDef {
        name: "Test::VariantConflict",
        pattern: "AA BB",
        follow: FollowMode::None,
        prologue: None,
        callee_pattern: None,
        optional: false,
        pic_entry: false,
        module: "steamclient",
    };

    static VARIANT_B: PatternDef = PatternDef {
        name: "Test::VariantConflict",
        pattern: "CC DD",
        follow: FollowMode::None,
        prologue: None,
        callee_pattern: None,
        optional: false,
        pic_entry: false,
        module: "steamclient",
    };

    #[test]
    fn entry_group_reports_variant_target_conflicts() {
        let haystack = [0xAA, 0xBB, 0x90, 0xCC, 0xDD];
        let entries = [&VARIANT_A, &VARIANT_B];

        let result = resolve_entry_group(&haystack, &entries);
        match result {
            Err(ResolveError::VariantConflict(targets)) => {
                assert_eq!(targets, vec![0, 3]);
            }
            Ok(_) => panic!("variant conflict should not resolve as OK"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
