use std::fmt;
use std::path::{Path, PathBuf};

use crate::elf::{ElfImage, ExecutableSegment};
use crate::registry::{FollowMode, PatternDef, RuntimePatternEntry};
use crate::{find_prologue_upwards, follow_last_call_before_ret, follow_relative_call, Pattern};

const FOLLOW_CALL_SCAN_BYTES: usize = 256;
const UPWARD_SCAN_BYTES: usize = 0x10000;

pub use crate::elf::ElfClass;

/// Borrowed view of one pattern variant.
///
/// The resolve pipeline below is written against this rather than against
/// [`PatternDef`] so it can serve both the build-time embedded table and
/// patterns a tool loaded from a file at run time, without either side owning
/// the other's storage.
#[derive(Clone, Copy, Debug)]
pub struct PatternRef<'a> {
    pub name: &'a str,
    pub pattern: &'a str,
    pub follow: FollowMode,
    pub prologue: Option<&'a [u8]>,
    pub callee_pattern: Option<&'a str>,
    pub pic_entry: bool,
    pub steamrt_variant: bool,
    pub module: &'a str,
}

impl<'a> From<&'a PatternDef> for PatternRef<'a> {
    fn from(entry: &'a PatternDef) -> Self {
        Self {
            name: entry.name,
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

impl<'a> From<&'a (String, RuntimePatternEntry)> for PatternRef<'a> {
    fn from((name, entry): &'a (String, RuntimePatternEntry)) -> Self {
        Self {
            name,
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
    pub fn failures(&self) -> impl Iterator<Item = &PatternScanEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.status != PatternScanStatus::Ok)
    }

    pub fn failure_count(&self) -> usize {
        self.failures().count()
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
    pub name: String,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LibraryFamily {
    Ordinary,
    SteamRt,
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

/// Scan one library image with the pattern set that matches its
/// architecture. `path` only selects the library family and labels the report.
pub fn scan_module(
    module: &str,
    path: &Path,
    data: &[u8],
    patterns: &[PatternRef<'_>],
    accept: Option<CandidateCheck<'_>>,
) -> Result<ModuleScanReport, String> {
    let segment = executable_segment(data)?;
    let variants = patterns
        .iter()
        .copied()
        .filter(|entry| entry.module == module)
        .collect::<Vec<_>>();
    if variants.is_empty() {
        return Err(format!("no patterns for module {module:?}"));
    }

    let variants = select_variants_for_library_path(&variants, path);
    let entries = group_variants(&variants)
        .into_iter()
        .map(|group| scan_entry_group(segment.bytes, &group, accept))
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

/// Select the ordinary wildcard entry or the steamrt variants for each group.
pub fn select_variants_for_library_path<'a>(
    entries: &[PatternRef<'a>],
    path: &Path,
) -> Vec<PatternRef<'a>> {
    let family = path
        .components()
        .filter_map(|part| part.as_os_str().to_str())
        .fold(None, |family, component| match component {
            "steamrt32" | "steamrt64" => Some(LibraryFamily::SteamRt),
            "ubuntu12_32" | "ubuntu12_64" | "linux32" | "linux64" if family.is_none() => {
                Some(LibraryFamily::Ordinary)
            }
            _ => family,
        });
    let Some(family) = family else {
        return entries.to_vec();
    };

    group_variants(entries)
        .into_iter()
        .flat_map(|group| {
            let use_steamrt =
                family == LibraryFamily::SteamRt && group.iter().any(|entry| entry.steamrt_variant);
            group
                .into_iter()
                .filter(move |entry| entry.steamrt_variant == use_steamrt)
        })
        .collect()
}

/// Group consecutive variants that share a name and module.
pub fn group_variants<'a>(entries: &[PatternRef<'a>]) -> Vec<Vec<PatternRef<'a>>> {
    let mut groups: Vec<Vec<PatternRef<'a>>> = Vec::new();
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

fn scan_entry_group(
    haystack: &[u8],
    entries: &[PatternRef<'_>],
    accept: Option<CandidateCheck<'_>>,
) -> PatternScanEntry {
    let entry = entries[0];
    match resolve_entry_group_with(haystack, entries, accept) {
        Ok(result) => PatternScanEntry {
            name: entry.name.to_owned(),
            status: PatternScanStatus::Ok,
            match_count: result.match_count,
            target_offset: Some(result.target_offset),
            error: None,
        },
        Err(error) => PatternScanEntry {
            name: entry.name.to_owned(),
            status: error.status(),
            match_count: error.match_count(),
            target_offset: None,
            error: Some(error.to_string()),
        },
    }
}

#[derive(Clone, Debug)]
pub struct ResolveResult {
    pub target_offset: usize,
    pub match_count: usize,
    /// Index of the variant within its group that produced this result.
    pub variant_index: usize,
}

/// Chooses between several matches of one pattern. It receives the scanned
/// code, the entry name and a candidate match offset; returning true accepts
/// that candidate. Accepted candidates are equivalent for the caller (for
/// example several instantiations of one template), so the first accepted
/// match wins. Callers plug in the entry's semantic validator here.
pub type CandidateCheck<'c> = &'c dyn Fn(&[u8], &str, usize) -> bool;

/// Where one variant of a conflicting group resolved to.
#[derive(Clone, Copy, Debug)]
pub struct VariantTarget {
    pub variant_index: usize,
    pub target_offset: usize,
}

/// Resolve every variant of one pattern group and require them to agree.
pub fn resolve_entry_group(
    haystack: &[u8],
    entries: &[PatternRef<'_>],
) -> Result<ResolveResult, ResolveError> {
    resolve_entry_group_with(haystack, entries, None)
}

/// [`resolve_entry_group`] with a candidate check that settles patterns
/// matching more than once.
pub fn resolve_entry_group_with(
    haystack: &[u8],
    entries: &[PatternRef<'_>],
    accept: Option<CandidateCheck<'_>>,
) -> Result<ResolveResult, ResolveError> {
    let mut best_error = None;
    let mut successes = Vec::new();
    for (variant_index, entry) in entries.iter().enumerate() {
        match resolve_entry(haystack, entry, accept) {
            Ok(mut result) => {
                result.variant_index = variant_index;
                successes.push(result);
            }
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
pub enum ResolveError {
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
    pub fn status(&self) -> PatternScanStatus {
        match self {
            Self::NoMatch => PatternScanStatus::Miss,
            Self::Ambiguous(_) => PatternScanStatus::Ambiguous,
            _ => PatternScanStatus::Fail,
        }
    }

    pub fn match_count(&self) -> usize {
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

fn resolve_entry(
    haystack: &[u8],
    entry: &PatternRef<'_>,
    accept: Option<CandidateCheck<'_>>,
) -> Result<ResolveResult, ResolveError> {
    let pattern = Pattern::parse(entry.pattern)
        .map_err(|error| ResolveError::PatternParse(error.to_string()))?;
    let matches = pattern.find_all(haystack);
    if matches.is_empty() {
        return Err(ResolveError::NoMatch);
    }

    let match_count = matches.len();
    let target_offset = match entry.follow {
        FollowMode::None => select_match(haystack, entry, &matches, accept)?,
        FollowMode::Relative => {
            let offset = select_match(haystack, entry, &matches, accept)?;
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
            let offset = select_match(haystack, entry, &matches, accept)?;
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
        variant_index: 0,
    })
}

fn select_match(
    haystack: &[u8],
    entry: &PatternRef<'_>,
    matches: &[usize],
    accept: Option<CandidateCheck<'_>>,
) -> Result<usize, ResolveError> {
    match matches {
        [] => Err(ResolveError::NoMatch),
        [offset] => Ok(*offset),
        many => {
            let accepted = accept
                .map(|accept| {
                    many.iter()
                        .copied()
                        .filter(|&offset| accept(haystack, entry.name, offset))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            accepted
                .first()
                .copied()
                .ok_or(ResolveError::Ambiguous(many.len()))
        }
    }
}

fn resolve_call_target(
    haystack: &[u8],
    entry: &PatternRef<'_>,
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
        let Some(candidate) = prologue_offset.checked_sub(offset) else {
            continue;
        };
        if is_pic_preamble(haystack, candidate, offset) {
            return Some(candidate);
        }
    }
    haystack
        .get(prologue_offset..prologue_offset + 3)
        .is_some_and(|bytes| bytes == [0x55, 0x89, 0xe5])
        .then_some(prologue_offset)
}

fn is_pic_preamble(haystack: &[u8], offset: usize, len: usize) -> bool {
    let Some(bytes) = haystack.get(offset..offset + len) else {
        return false;
    };
    bytes[0] == 0xe8
        && match len {
            10 => bytes[5] == 0x05,
            11 => bytes[5] == 0x81 && matches!(bytes[6], 0xc1 | 0xc3 | 0xc5 | 0xc6 | 0xc7),
            _ => false,
        }
}

fn executable_segment(data: &[u8]) -> Result<ExecutableSegment<'_>, String> {
    ElfImage::parse(data)?.largest_executable_segment()
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
        pic_entry: false,
        steamrt_variant: false,
        module: "steamclient",
    };

    static VARIANT_B: PatternDef = PatternDef {
        name: "Test::VariantConflict",
        pattern: "CC DD",
        follow: FollowMode::None,
        prologue: None,
        callee_pattern: None,
        pic_entry: false,
        steamrt_variant: true,
        module: "steamclient",
    };

    static AMBIGUOUS: PatternDef = PatternDef {
        name: "Test::Ambiguous",
        pattern: "AA BB",
        follow: FollowMode::None,
        prologue: None,
        callee_pattern: None,
        pic_entry: false,
        steamrt_variant: false,
        module: "steamclient",
    };

    #[test]
    fn candidate_check_settles_ambiguous_matches() {
        let haystack = [0xAA, 0xBB, 0x90, 0xAA, 0xBB];
        let entries = [PatternRef::from(&AMBIGUOUS)];
        assert!(matches!(
            resolve_entry_group(&haystack, &entries),
            Err(ResolveError::Ambiguous(2))
        ));

        let accept_second =
            |_: &[u8], name: &str, offset: usize| name == "Test::Ambiguous" && offset == 3;
        let result = resolve_entry_group_with(&haystack, &entries, Some(&accept_second)).unwrap();
        assert_eq!((result.target_offset, result.match_count), (3, 2));

        // Equivalent candidates: the first accepted match wins.
        let accept_all = |_: &[u8], _: &str, _: usize| true;
        let result = resolve_entry_group_with(&haystack, &entries, Some(&accept_all)).unwrap();
        assert_eq!((result.target_offset, result.match_count), (0, 2));

        let reject_all = |_: &[u8], _: &str, _: usize| false;
        assert!(matches!(
            resolve_entry_group_with(&haystack, &entries, Some(&reject_all)),
            Err(ResolveError::Ambiguous(2))
        ));
    }

    #[test]
    fn entry_group_reports_variant_target_conflicts() {
        let haystack = [0xAA, 0xBB, 0x90, 0xCC, 0xDD];
        let entries = [PatternRef::from(&VARIANT_A), PatternRef::from(&VARIANT_B)];

        match resolve_entry_group(&haystack, &entries) {
            Err(error @ ResolveError::VariantConflict(_)) => {
                let ResolveError::VariantConflict(targets) = &error else {
                    unreachable!()
                };
                assert_eq!(
                    targets
                        .iter()
                        .map(|target| (target.variant_index, target.target_offset))
                        .collect::<Vec<_>>(),
                    vec![(0, 0), (1, 3)]
                );
                // The message names the offending variant, not just the offset.
                assert_eq!(
                    error.to_string(),
                    "pattern variants resolve to different targets: variant=1 text+0x0 variant=2 text+0x3"
                );
            }
            Ok(_) => panic!("variant conflict should not resolve as OK"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn library_path_selects_the_matching_binary_family() {
        let entries = [PatternRef::from(&VARIANT_A), PatternRef::from(&VARIANT_B)];
        let ordinary_x86 = select_variants_for_library_path(
            &entries,
            Path::new("/steam/ubuntu12_32/steamclient.so"),
        );
        let ordinary_x64 =
            select_variants_for_library_path(&entries, Path::new("/steam/linux64/steamclient.so"));
        let steamrt = select_variants_for_library_path(
            &entries,
            Path::new("/steam/steamrt64/steamclient.so"),
        );
        assert_eq!(ordinary_x86.len(), 1);
        assert_eq!(ordinary_x86[0].pattern, VARIANT_A.pattern);
        assert_eq!(ordinary_x64.len(), 1);
        assert_eq!(ordinary_x64[0].pattern, VARIANT_A.pattern);
        assert_eq!(steamrt.len(), 1);
        assert_eq!(steamrt[0].pattern, VARIANT_B.pattern);
    }

    #[test]
    fn every_non_ok_entry_counts_as_a_failure() {
        let report = ModuleScanReport {
            module: "steamclient".to_owned(),
            path: PathBuf::from("steamclient.so"),
            elf_class: ElfClass::Elf64,
            text_file_off: 0,
            text_vaddr: 0,
            text_size: 0,
            entries: [
                PatternScanStatus::Ok,
                PatternScanStatus::Miss,
                PatternScanStatus::Ambiguous,
                PatternScanStatus::Fail,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, status)| PatternScanEntry {
                name: format!("pattern-{index}"),
                status,
                match_count: 0,
                target_offset: None,
                error: None,
            })
            .collect(),
        };

        assert_eq!(report.ok_count(), 1);
        assert_eq!(report.failure_count(), 3);
        assert_eq!(report.failures().count(), 3);
    }

    #[test]
    fn pic_entry_supports_both_x86_compiler_layouts() {
        let external_preamble = [0xe8, 0, 0, 0, 0, 0x05, 0, 0, 0, 0, 0x55, 0x89, 0xe5, 0x57];
        assert_eq!(find_pic_entry(&external_preamble, 10), Some(0));

        let inline_preamble = [0x55, 0x89, 0xe5, 0x57, 0xe8, 0, 0, 0, 0];
        assert_eq!(find_pic_entry(&inline_preamble, 0), Some(0));
    }
}
