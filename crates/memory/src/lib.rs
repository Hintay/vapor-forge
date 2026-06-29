#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use std::collections::{BTreeMap, BTreeSet};
use steam_runtime_core::Address;
use thiserror::Error;

const MAX_PROC_MAPS_LINE_LEN: usize = 4096;
const MAX_PROC_MAPS_PATH_LEN: usize = 1024;
const DEFAULT_MAX_ELF_FILE_SIZE: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_DYNAMIC_SYMBOL_NAMES: usize = 64;
const DEFAULT_MAX_DYNAMIC_SYMBOL_NAME_LEN: usize = 256;
const DEFAULT_MAX_HEADER_SAMPLE_BYTES: usize = 16;
const DEFAULT_MAX_SYMBOL_SAMPLE_BYTES: usize = 16;
const DEFAULT_MAX_SYMBOL_SAMPLES_PER_MODULE: usize = 2;
const DEFAULT_MAX_SAMPLED_BYTES_PER_MODULE: usize = 32;
const DEFAULT_MAX_SAMPLED_BYTES_PER_PROCESS: usize = 64;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("failed to read /proc/self/maps: {0}")]
    ProcMapsReadFailed(#[from] std::io::Error),
    #[error("ELF metadata path is not a public Steam target module: {0}")]
    ElfUnsupportedTargetPath(String),
    #[error("ELF metadata file is too large: path={path} size={size} max={max}")]
    ElfFileTooLarge { path: String, size: u64, max: u64 },
    #[error("failed to read ELF metadata file {path}: {source}")]
    ElfReadFailed {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse ELF metadata file {path}: {message}")]
    ElfParseFailed { path: String, message: String },
}

pub type Result<T> = core::result::Result<T, MemoryError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleRange {
    pub base: Address,
    pub end: Address,
    pub size: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub exe: Option<String>,
    pub arch: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcMapsEntry {
    pub range: ModuleRange,
    pub permissions: String,
    pub file_offset: usize,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcMapsModuleInventory {
    pub name: String,
    pub path: String,
    pub entry_count: usize,
    pub range: ModuleRange,
    pub permissions: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfMetadataLimits {
    pub max_file_size: u64,
    pub max_dynamic_symbol_names: usize,
    pub max_dynamic_symbol_name_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfMetadataSummary {
    pub name: String,
    pub path: String,
    pub file_size: u64,
    pub file_kind: String,
    pub elf_class: String,
    pub endian: String,
    pub architecture: String,
    pub segment_count: usize,
    pub section_count: usize,
    pub dynamic_symbol_count: usize,
    pub dynamic_symbol_names: Vec<String>,
    pub dynamic_symbol_names_truncated: bool,
    pub build_id: Option<String>,
    pub gnu_hash_present: bool,
    pub sysv_hash_present: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSymbolQuestionResult {
    pub id: String,
    pub answer: bool,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappedByteSamplingLimits {
    pub max_header_sample_bytes: usize,
    pub max_symbol_sample_bytes: usize,
    pub max_symbol_samples_per_module: usize,
    pub max_sampled_bytes_per_module: usize,
    pub max_sampled_bytes_per_process: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappedByteSample {
    pub module_name: String,
    pub path: String,
    pub kind: String,
    pub symbol: Option<String>,
    pub requested_len: usize,
    pub digest: String,
    pub matches_elf_magic: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappedByteSampleSkip {
    pub module_name: String,
    pub path: String,
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappedByteSamplingReport {
    pub module_name: String,
    pub path: String,
    pub samples: Vec<MappedByteSample>,
    pub skips: Vec<MappedByteSampleSkip>,
    pub total_sampled_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicDynamicSymbolSampleCandidate {
    name: String,
    relative_address: usize,
}

#[derive(Debug)]
struct ProcMapsModuleInventoryBuilder {
    name: String,
    path: String,
    entry_count: usize,
    lowest_base: usize,
    highest_end: usize,
    permissions: BTreeSet<String>,
}

pub fn current_process_context() -> ProcessContext {
    ProcessContext {
        pid: std::process::id(),
        ppid: read_parent_pid(),
        exe: std::fs::read_link("/proc/self/exe")
            .ok()
            .map(|path| path.display().to_string()),
        arch: std::env::consts::ARCH,
    }
}

pub fn find_proc_self_maps_targets(max_entries: usize) -> Result<Vec<ProcMapsEntry>> {
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    Ok(find_proc_maps_targets_in_text(&maps, max_entries))
}

pub fn summarize_proc_self_maps_targets(
    max_entries: usize,
) -> Result<Vec<ProcMapsModuleInventory>> {
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    Ok(summarize_proc_maps_targets_in_text(&maps, max_entries))
}

pub fn summarize_proc_maps_targets(entries: &[ProcMapsEntry]) -> Vec<ProcMapsModuleInventory> {
    let mut modules = BTreeMap::<String, ProcMapsModuleInventoryBuilder>::new();

    for entry in entries {
        let Some(name) = steam_target_display_name(&entry.path) else {
            continue;
        };

        modules
            .entry(entry.path.clone())
            .and_modify(|summary| {
                summary.entry_count += 1;
                summary.lowest_base = summary.lowest_base.min(entry.range.base.0);
                summary.highest_end = summary.highest_end.max(entry.range.end.0);
                summary.permissions.insert(entry.permissions.clone());
            })
            .or_insert_with(|| ProcMapsModuleInventoryBuilder {
                name: name.to_owned(),
                path: entry.path.clone(),
                entry_count: 1,
                lowest_base: entry.range.base.0,
                highest_end: entry.range.end.0,
                permissions: BTreeSet::from([entry.permissions.clone()]),
            });
    }

    modules
        .into_values()
        .map(ProcMapsModuleInventoryBuilder::finish)
        .collect()
}

pub fn summarize_elf_file(path: &str, limits: ElfMetadataLimits) -> Result<ElfMetadataSummary> {
    let Some(name) = steam_target_display_name(path) else {
        return Err(MemoryError::ElfUnsupportedTargetPath(path.to_owned()));
    };

    let metadata = std::fs::metadata(path).map_err(|source| MemoryError::ElfReadFailed {
        path: path.to_owned(),
        source,
    })?;
    let file_size = metadata.len();
    if file_size > limits.max_file_size {
        return Err(MemoryError::ElfFileTooLarge {
            path: path.to_owned(),
            size: file_size,
            max: limits.max_file_size,
        });
    }

    let bytes = std::fs::read(path).map_err(|source| MemoryError::ElfReadFailed {
        path: path.to_owned(),
        source,
    })?;
    let file =
        object::File::parse(bytes.as_slice()).map_err(|error| MemoryError::ElfParseFailed {
            path: path.to_owned(),
            message: error.to_string(),
        })?;

    let mut dynamic_symbol_names = Vec::new();
    let mut dynamic_symbol_names_truncated = false;
    let mut dynamic_symbol_count = 0usize;
    for symbol in file.dynamic_symbols() {
        dynamic_symbol_count += 1;
        if dynamic_symbol_names.len() >= limits.max_dynamic_symbol_names {
            dynamic_symbol_names_truncated = true;
            continue;
        }
        let Ok(symbol_name) = symbol.name() else {
            continue;
        };
        if symbol_name.is_empty() {
            continue;
        }
        dynamic_symbol_names.push(truncate_str(
            symbol_name,
            limits.max_dynamic_symbol_name_len,
        ));
    }

    let mut gnu_hash_present = false;
    let mut sysv_hash_present = false;
    for section in file.sections() {
        match section.name() {
            Ok(".gnu.hash") => gnu_hash_present = true,
            Ok(".hash") => sysv_hash_present = true,
            _ => {}
        }
    }

    let build_id = file
        .build_id()
        .map_err(|error| MemoryError::ElfParseFailed {
            path: path.to_owned(),
            message: error.to_string(),
        })?
        .map(bytes_to_hex);

    Ok(ElfMetadataSummary {
        name: name.to_owned(),
        path: path.to_owned(),
        file_size,
        file_kind: format!("{:?}", file.kind()),
        elf_class: if file.is_64() { "ELF64" } else { "ELF32" }.to_owned(),
        endian: format!("{:?}", file.endianness()),
        architecture: format!("{:?}", file.architecture()),
        segment_count: file.segments().count(),
        section_count: file.sections().count(),
        dynamic_symbol_count,
        dynamic_symbol_names,
        dynamic_symbol_names_truncated,
        build_id,
        gnu_hash_present,
        sysv_hash_present,
    })
}

pub fn analyze_public_dynamic_symbol_questions(
    summary: &ElfMetadataSummary,
) -> Vec<DynamicSymbolQuestionResult> {
    vec![
        DynamicSymbolQuestionResult {
            id: "has_dynamic_symbols".to_owned(),
            answer: summary.dynamic_symbol_count > 0,
            detail: format!("dynamic_symbol_count={}", summary.dynamic_symbol_count),
        },
        DynamicSymbolQuestionResult {
            id: "has_bounded_symbol_sample".to_owned(),
            answer: !summary.dynamic_symbol_names.is_empty(),
            detail: format!(
                "sample_count={} truncated={}",
                summary.dynamic_symbol_names.len(),
                summary.dynamic_symbol_names_truncated
            ),
        },
        DynamicSymbolQuestionResult {
            id: "has_build_id".to_owned(),
            answer: summary.build_id.is_some(),
            detail: format!("build_id={}", summary.build_id.as_deref().unwrap_or("none")),
        },
        DynamicSymbolQuestionResult {
            id: "has_runtime_hash_table".to_owned(),
            answer: summary.gnu_hash_present || summary.sysv_hash_present,
            detail: format!(
                "gnu_hash={} sysv_hash={}",
                summary.gnu_hash_present, summary.sysv_hash_present
            ),
        },
        DynamicSymbolQuestionResult {
            id: "sample_has_unmangled_names".to_owned(),
            answer: summary
                .dynamic_symbol_names
                .iter()
                .any(|symbol| !looks_like_mangled_cpp_symbol(symbol)),
            detail: "bounded sample heuristic".to_owned(),
        },
        DynamicSymbolQuestionResult {
            id: "sample_has_mangled_cpp_names".to_owned(),
            answer: summary
                .dynamic_symbol_names
                .iter()
                .any(|symbol| looks_like_mangled_cpp_symbol(symbol)),
            detail: "bounded sample heuristic".to_owned(),
        },
    ]
}

/// Samples a bounded number of bytes from current-process mappings for one public target module.
///
/// # Safety
///
/// The caller must ensure that `entries` came from the current process and still describe live,
/// readable mappings. This function validates names, permissions, arithmetic, and containment
/// before copying bytes, but it cannot prove that raw addresses from `/proc/self/maps` are still
/// valid at the moment of the read.
pub unsafe fn sample_mapped_target_module_bytes(
    entries: &[ProcMapsEntry],
    target_name: &str,
    limits: MappedByteSamplingLimits,
) -> MappedByteSamplingReport {
    let module_name = steam_target_display_name(target_name)
        .unwrap_or(target_name)
        .to_owned();
    let mut report = MappedByteSamplingReport {
        module_name: module_name.clone(),
        path: String::new(),
        samples: Vec::new(),
        skips: Vec::new(),
        total_sampled_bytes: 0,
    };

    if steam_target_display_name(target_name).is_none() {
        push_sample_skip(
            &mut report,
            "unknown",
            "unsupported-target",
            "target name is not allowed",
        );
        return report;
    }

    let module_entries = entries
        .iter()
        .filter(|entry| steam_target_display_name(&entry.path) == Some(module_name.as_str()))
        .collect::<Vec<_>>();

    if module_entries.is_empty() {
        push_sample_skip(
            &mut report,
            "unknown",
            "module",
            "no proc-maps entry for target",
        );
        return report;
    }

    report.path = module_entries[0].path.clone();

    sample_mapping_header(&mut report, &module_entries, limits);
    sample_public_dynamic_symbols(&mut report, &module_entries, limits);

    report
}

fn sample_mapping_header(
    report: &mut MappedByteSamplingReport,
    module_entries: &[&ProcMapsEntry],
    limits: MappedByteSamplingLimits,
) {
    let Some(entry) = module_entries
        .iter()
        .copied()
        .find(|entry| entry.file_offset == 0 && is_readable_mapping(entry))
    else {
        push_sample_skip(
            report,
            "unknown",
            "mapping-header",
            "no readable offset-zero mapping",
        );
        return;
    };

    let len = limits
        .max_header_sample_bytes
        .min(remaining_module_budget(report, limits))
        .min(remaining_process_budget(report, limits))
        .min(entry.range.size);
    if len == 0 {
        push_sample_skip(
            report,
            &entry.path,
            "mapping-header",
            "sample length is zero",
        );
        return;
    }

    if !range_is_contained_in_entry(entry, entry.range.base.0, len) {
        push_sample_skip(
            report,
            &entry.path,
            "mapping-header",
            "range is not contained",
        );
        return;
    }

    // SAFETY: The public caller accepted the raw-address contract. This helper also selected a
    // readable /proc/self/maps entry and checked that the requested range is fully contained in it.
    let bytes = unsafe { copy_mapped_bytes(entry.range.base.0, len) };
    push_sample(
        report,
        &entry.path,
        "mapping-header",
        None,
        len,
        Some(bytes.starts_with(b"\x7fELF")),
        &bytes,
    );
}

fn sample_public_dynamic_symbols(
    report: &mut MappedByteSamplingReport,
    module_entries: &[&ProcMapsEntry],
    limits: MappedByteSamplingLimits,
) {
    if report.path.is_empty() {
        push_sample_skip(
            report,
            "unknown",
            "public-dynsym",
            "module path is unavailable",
        );
        return;
    }

    let candidates = match public_dynamic_symbol_sample_candidates(
        &report.path,
        limits.max_symbol_samples_per_module,
    ) {
        Ok(candidates) => candidates,
        Err(error) => {
            push_sample_skip(report, "unknown", "public-dynsym", &error.to_string());
            return;
        }
    };

    if candidates.is_empty() {
        push_sample_skip(
            report,
            "unknown",
            "public-dynsym",
            "no public dynamic symbol candidate",
        );
        return;
    }

    let Some(load_base) = module_entries
        .iter()
        .copied()
        .filter(|entry| entry.file_offset == 0)
        .map(|entry| entry.range.base.0)
        .min()
    else {
        push_sample_skip(
            report,
            "unknown",
            "public-dynsym",
            "load base is unavailable",
        );
        return;
    };

    for candidate in candidates {
        let Some(address) = load_base.checked_add(candidate.relative_address) else {
            push_sample_skip(
                report,
                "unknown",
                "public-dynsym",
                "symbol address overflow",
            );
            continue;
        };
        let Some(entry) = module_entries.iter().copied().find(|entry| {
            is_readable_mapping(entry) && range_is_contained_in_entry(entry, address, 1)
        }) else {
            push_sample_skip(
                report,
                "unknown",
                "public-dynsym",
                "symbol is not in readable mapping",
            );
            continue;
        };

        let len = limits
            .max_symbol_sample_bytes
            .min(remaining_module_budget(report, limits))
            .min(remaining_process_budget(report, limits))
            .min(entry.range.end.0.saturating_sub(address));
        if len == 0 {
            push_sample_skip(
                report,
                &entry.path,
                "public-dynsym",
                "sample budget exhausted",
            );
            continue;
        }
        if !range_is_contained_in_entry(entry, address, len) {
            push_sample_skip(
                report,
                &entry.path,
                "public-dynsym",
                "range is not contained",
            );
            continue;
        }

        // SAFETY: The public caller accepted the raw-address contract. The symbol-derived address
        // was converted from disk ELF metadata and checked against one readable mapping entry.
        let bytes = unsafe { copy_mapped_bytes(address, len) };
        push_sample(
            report,
            &entry.path,
            "public-dynsym",
            Some(truncate_str(&candidate.name, 128)),
            len,
            None,
            &bytes,
        );
    }
}

fn public_dynamic_symbol_sample_candidates(
    path: &str,
    max_candidates: usize,
) -> Result<Vec<PublicDynamicSymbolSampleCandidate>> {
    let Some(_) = steam_target_display_name(path) else {
        return Err(MemoryError::ElfUnsupportedTargetPath(path.to_owned()));
    };

    let bytes = std::fs::read(path).map_err(|source| MemoryError::ElfReadFailed {
        path: path.to_owned(),
        source,
    })?;
    let file =
        object::File::parse(bytes.as_slice()).map_err(|error| MemoryError::ElfParseFailed {
            path: path.to_owned(),
            message: error.to_string(),
        })?;

    let mut candidates = Vec::new();
    for symbol in file.dynamic_symbols() {
        if candidates.len() >= max_candidates {
            break;
        }
        let address = symbol.address();
        if address == 0 || !symbol_is_in_load_segment(&file, address) {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let Some(relative_address) = usize::try_from(address).ok() else {
            continue;
        };
        candidates.push(PublicDynamicSymbolSampleCandidate {
            name: truncate_str(name, 128),
            relative_address,
        });
    }

    Ok(candidates)
}

fn symbol_is_in_load_segment(file: &object::File<'_>, address: u64) -> bool {
    file.segments().any(|segment| {
        let start = segment.address();
        let Some(end) = start.checked_add(segment.size()) else {
            return false;
        };
        address >= start && address < end
    })
}

fn push_sample(
    report: &mut MappedByteSamplingReport,
    path: &str,
    kind: &str,
    symbol: Option<String>,
    requested_len: usize,
    matches_elf_magic: Option<bool>,
    bytes: &[u8],
) {
    report.total_sampled_bytes = report.total_sampled_bytes.saturating_add(bytes.len());
    report.samples.push(MappedByteSample {
        module_name: report.module_name.clone(),
        path: path.to_owned(),
        kind: kind.to_owned(),
        symbol,
        requested_len,
        digest: fnv1a64_digest(bytes),
        matches_elf_magic,
    });
}

fn push_sample_skip(report: &mut MappedByteSamplingReport, path: &str, kind: &str, detail: &str) {
    report.skips.push(MappedByteSampleSkip {
        module_name: report.module_name.clone(),
        path: path.to_owned(),
        kind: kind.to_owned(),
        detail: truncate_str(detail, 256),
    });
}

fn remaining_module_budget(
    report: &MappedByteSamplingReport,
    limits: MappedByteSamplingLimits,
) -> usize {
    limits
        .max_sampled_bytes_per_module
        .saturating_sub(report.total_sampled_bytes)
}

fn remaining_process_budget(
    report: &MappedByteSamplingReport,
    limits: MappedByteSamplingLimits,
) -> usize {
    limits
        .max_sampled_bytes_per_process
        .saturating_sub(report.total_sampled_bytes)
}

fn is_readable_mapping(entry: &ProcMapsEntry) -> bool {
    entry.permissions.starts_with('r')
}

fn range_is_contained_in_entry(entry: &ProcMapsEntry, address: usize, len: usize) -> bool {
    if len == 0 || address < entry.range.base.0 {
        return false;
    }
    let Some(end) = address.checked_add(len) else {
        return false;
    };
    end <= entry.range.end.0
}

unsafe fn copy_mapped_bytes(address: usize, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    // SAFETY: The caller guarantees that the source range is readable in the current process and
    // that the destination buffer has at least `len` bytes.
    unsafe { core::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), len) };
    bytes
}

fn fnv1a64_digest(bytes: &[u8]) -> String {
    let mut value = 0xcbf29ce484222325u64;
    for byte in bytes {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{value:016x}")
}

pub fn is_steam_target_name(name_or_path: &str) -> bool {
    module_name_matches(name_or_path, "steamclient.so")
        || module_name_matches(name_or_path, "steamui.so")
}

fn module_name_matches(name_or_path: &str, expected: &str) -> bool {
    name_or_path == expected || name_or_path.rsplit('/').next() == Some(expected)
}

fn steam_target_display_name(name_or_path: &str) -> Option<&'static str> {
    if module_name_matches(name_or_path, "steamclient.so") {
        Some("steamclient.so")
    } else if module_name_matches(name_or_path, "steamui.so") {
        Some("steamui.so")
    } else {
        None
    }
}

fn read_parent_pid() -> Option<u32> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    parse_parent_pid_from_stat(&stat)
}

fn parse_parent_pid_from_stat(stat: &str) -> Option<u32> {
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

fn find_proc_maps_targets_in_text(maps: &str, max_entries: usize) -> Vec<ProcMapsEntry> {
    maps.lines()
        .filter_map(parse_proc_maps_entry)
        .filter(|entry| is_steam_target_name(&entry.path))
        .take(max_entries)
        .collect()
}

fn summarize_proc_maps_targets_in_text(
    maps: &str,
    max_entries: usize,
) -> Vec<ProcMapsModuleInventory> {
    let entries = find_proc_maps_targets_in_text(maps, max_entries);
    summarize_proc_maps_targets(&entries)
}

fn parse_proc_maps_entry(line: &str) -> Option<ProcMapsEntry> {
    if line.len() > MAX_PROC_MAPS_LINE_LEN {
        return None;
    }

    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let permissions = parts.next()?;
    if permissions.len() > 16 {
        return None;
    }

    let mut bounds = range.splitn(2, '-');
    let start = usize::from_str_radix(bounds.next()?, 16).ok()?;
    let end = usize::from_str_radix(bounds.next()?, 16).ok()?;

    let file_offset = usize::from_str_radix(parts.next()?, 16).ok()?;

    for _ in 0..2 {
        parts.next()?;
    }

    let path = parts.next()?;
    if path.len() > MAX_PROC_MAPS_PATH_LEN {
        return None;
    }

    Some(ProcMapsEntry {
        range: ModuleRange {
            base: Address(start),
            end: Address(end),
            size: end.saturating_sub(start),
        },
        permissions: permissions.to_owned(),
        file_offset,
        path: path.to_owned(),
    })
}

impl ProcMapsModuleInventoryBuilder {
    fn finish(self) -> ProcMapsModuleInventory {
        ProcMapsModuleInventory {
            name: self.name,
            path: self.path,
            entry_count: self.entry_count,
            range: ModuleRange {
                base: Address(self.lowest_base),
                end: Address(self.highest_end),
                size: self.highest_end.saturating_sub(self.lowest_base),
            },
            permissions: join_permissions(&self.permissions),
        }
    }
}

fn join_permissions(permissions: &BTreeSet<String>) -> String {
    permissions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn truncate_str(value: &str, max_len: usize) -> String {
    value.chars().take(max_len).collect()
}

fn looks_like_mangled_cpp_symbol(symbol: &str) -> bool {
    symbol.starts_with("_Z")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

impl Default for ElfMetadataLimits {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_ELF_FILE_SIZE,
            max_dynamic_symbol_names: DEFAULT_MAX_DYNAMIC_SYMBOL_NAMES,
            max_dynamic_symbol_name_len: DEFAULT_MAX_DYNAMIC_SYMBOL_NAME_LEN,
        }
    }
}

impl Default for MappedByteSamplingLimits {
    fn default() -> Self {
        Self {
            max_header_sample_bytes: DEFAULT_MAX_HEADER_SAMPLE_BYTES,
            max_symbol_sample_bytes: DEFAULT_MAX_SYMBOL_SAMPLE_BYTES,
            max_symbol_samples_per_module: DEFAULT_MAX_SYMBOL_SAMPLES_PER_MODULE,
            max_sampled_bytes_per_module: DEFAULT_MAX_SAMPLED_BYTES_PER_MODULE,
            max_sampled_bytes_per_process: DEFAULT_MAX_SAMPLED_BYTES_PER_PROCESS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        analyze_public_dynamic_symbol_questions, bytes_to_hex, find_proc_maps_targets_in_text,
        fnv1a64_digest, is_steam_target_name, parse_parent_pid_from_stat, parse_proc_maps_entry,
        range_is_contained_in_entry, sample_mapped_target_module_bytes, summarize_elf_file,
        summarize_proc_maps_targets_in_text, truncate_str, ElfMetadataLimits, ElfMetadataSummary,
        MappedByteSamplingLimits, MemoryError,
    };

    #[test]
    fn detects_target_module_names_and_paths() {
        assert!(is_steam_target_name("steamclient.so"));
        assert!(is_steam_target_name(
            "/home/user/.steam/steam/ubuntu12_32/steamui.so"
        ));
        assert!(!is_steam_target_name("libc.so.6"));
    }

    #[test]
    fn parses_parent_pid_from_proc_stat() {
        assert_eq!(
            parse_parent_pid_from_stat("123 (steam) S 456 1 2"),
            Some(456)
        );
        assert_eq!(parse_parent_pid_from_stat("123 steam S 456"), None);
    }

    #[test]
    fn parses_proc_maps_entry() {
        let entry =
            parse_proc_maps_entry("f7d00000-f7d21000 r--p 00000000 08:01 42 /tmp/steamui.so")
                .expect("maps entry should parse");

        assert_eq!(entry.range.base.0, 0xf7d00000);
        assert_eq!(entry.range.end.0, 0xf7d21000);
        assert_eq!(entry.range.size, 0x21000);
        assert_eq!(entry.permissions, "r--p");
        assert_eq!(entry.file_offset, 0);
        assert_eq!(entry.path, "/tmp/steamui.so");
    }

    #[test]
    fn filters_proc_maps_targets() {
        let maps = "\
f7d00000-f7d21000 r--p 00000000 08:01 42 /tmp/steamui.so\n\
f7d21000-f7d22000 r--p 00000000 08:01 43 /lib/libc.so.6\n\
f7d22000-f7d23000 r--p 00000000 08:01 44 /tmp/steamclient.so\n";

        let entries = find_proc_maps_targets_in_text(maps, 8);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/tmp/steamui.so");
        assert_eq!(entries[1].path, "/tmp/steamclient.so");
    }

    #[test]
    fn applies_proc_maps_entry_limit() {
        let maps = "\
f7d00000-f7d21000 r--p 00000000 08:01 42 /tmp/steamui.so\n\
f7d22000-f7d23000 r--p 00000000 08:01 44 /tmp/steamclient.so\n";

        let entries = find_proc_maps_targets_in_text(maps, 1);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/tmp/steamui.so");
    }

    #[test]
    fn summarizes_proc_maps_targets_by_path() {
        let maps = "\
f7d00000-f7d21000 r--p 00000000 08:01 42 /tmp/steamui.so\n\
f7d21000-f7d83000 r-xp 00021000 08:01 42 /tmp/steamui.so\n\
f7d83000-f7d84000 rw-p 00083000 08:01 42 /tmp/steamui.so\n\
f7d84000-f7d85000 r--p 00000000 08:01 43 /lib/libc.so.6\n\
f7d85000-f7d90000 r--p 00000000 08:01 44 /tmp/steamclient.so\n";

        let summaries = summarize_proc_maps_targets_in_text(maps, 8);

        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].name, "steamclient.so");
        assert_eq!(summaries[0].path, "/tmp/steamclient.so");
        assert_eq!(summaries[0].entry_count, 1);
        assert_eq!(summaries[0].permissions, "r--p");

        assert_eq!(summaries[1].name, "steamui.so");
        assert_eq!(summaries[1].path, "/tmp/steamui.so");
        assert_eq!(summaries[1].entry_count, 3);
        assert_eq!(summaries[1].range.base.0, 0xf7d00000);
        assert_eq!(summaries[1].range.end.0, 0xf7d84000);
        assert_eq!(summaries[1].range.size, 0x84000);
        assert_eq!(summaries[1].permissions, "r--p,r-xp,rw-p");
    }

    #[test]
    fn formats_build_id_bytes_as_hex() {
        assert_eq!(bytes_to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn truncates_symbol_names_by_chars() {
        assert_eq!(truncate_str("abcdef", 3), "abc");
        assert_eq!(truncate_str("abcdef", 16), "abcdef");
    }

    #[test]
    fn rejects_non_target_elf_paths() {
        let error = summarize_elf_file("/tmp/libc.so.6", ElfMetadataLimits::default())
            .expect_err("non-target paths should be rejected");
        assert!(matches!(error, MemoryError::ElfUnsupportedTargetPath(_)));
    }

    #[test]
    fn summarizes_target_named_elf_file_from_disk() {
        let source = std::env::current_exe().expect("test executable path should be available");
        let work_dir =
            std::env::temp_dir().join(format!("steam-runtime-rs-elf-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work_dir);
        std::fs::create_dir_all(&work_dir).expect("test directory should be created");
        let target = work_dir.join("steamui.so");
        std::fs::copy(&source, &target).expect("test executable should be copied");

        let summary = summarize_elf_file(
            &target.display().to_string(),
            ElfMetadataLimits {
                max_dynamic_symbol_names: 4,
                ..ElfMetadataLimits::default()
            },
        )
        .expect("target-named ELF file should summarize");

        assert_eq!(summary.name, "steamui.so");
        assert_eq!(summary.path, target.display().to_string());
        assert!(summary.file_size > 0);
        assert!(!summary.file_kind.is_empty());
        assert!(summary.elf_class == "ELF32" || summary.elf_class == "ELF64");
        assert!(!summary.architecture.is_empty());

        let _ = std::fs::remove_dir_all(&work_dir);
    }

    #[test]
    fn answers_public_dynamic_symbol_questions_from_summary() {
        let summary = ElfMetadataSummary {
            name: "steamui.so".to_owned(),
            path: "/tmp/steamui.so".to_owned(),
            file_size: 1024,
            file_kind: "Dynamic".to_owned(),
            elf_class: "ELF32".to_owned(),
            endian: "Little".to_owned(),
            architecture: "I386".to_owned(),
            segment_count: 4,
            section_count: 32,
            dynamic_symbol_count: 2,
            dynamic_symbol_names: vec![
                "steam_runtime_plain_symbol".to_owned(),
                "_Z3foov".to_owned(),
            ],
            dynamic_symbol_names_truncated: false,
            build_id: Some("001122".to_owned()),
            gnu_hash_present: true,
            sysv_hash_present: false,
        };

        let results = analyze_public_dynamic_symbol_questions(&summary);

        assert!(results
            .iter()
            .any(|result| result.id == "has_dynamic_symbols" && result.answer));
        assert!(results
            .iter()
            .any(|result| result.id == "has_bounded_symbol_sample" && result.answer));
        assert!(results
            .iter()
            .any(|result| result.id == "has_build_id" && result.answer));
        assert!(results
            .iter()
            .any(|result| result.id == "has_runtime_hash_table" && result.answer));
        assert!(results
            .iter()
            .any(|result| result.id == "sample_has_unmangled_names" && result.answer));
        assert!(results
            .iter()
            .any(|result| result.id == "sample_has_mangled_cpp_names" && result.answer));
    }

    #[test]
    fn checks_range_containment() {
        let entry = parse_proc_maps_entry("1000-2000 r--p 00000000 08:01 42 /tmp/steamui.so")
            .expect("maps entry should parse");

        assert!(range_is_contained_in_entry(&entry, 0x1000, 16));
        assert!(range_is_contained_in_entry(&entry, 0x1ff0, 16));
        assert!(!range_is_contained_in_entry(&entry, 0x0fff, 16));
        assert!(!range_is_contained_in_entry(&entry, 0x1ff1, 16));
        assert!(!range_is_contained_in_entry(&entry, 0x1000, 0));
    }

    #[test]
    fn hashes_samples_without_raw_bytes() {
        assert_eq!(fnv1a64_digest(b"\x7fELF"), "fnv1a64:28b265382f1249f3");
    }

    #[test]
    fn samples_current_process_target_named_mapping() {
        let mapped = b"\x7fELFtrack-c-synthetic-symbol";
        let base = mapped.as_ptr() as usize;
        let line = format!(
            "{base:x}-{:x} r--p 00000000 08:01 42 /tmp/steamui.so",
            base + mapped.len()
        );
        let entry = parse_proc_maps_entry(&line).expect("synthetic maps entry should parse");

        // SAFETY: The synthetic entry points to the live `mapped` byte slice for the duration of
        // this call and the range is read-only in the current test process.
        let report = unsafe {
            sample_mapped_target_module_bytes(
                &[entry],
                "steamui.so",
                MappedByteSamplingLimits {
                    max_symbol_samples_per_module: 0,
                    ..MappedByteSamplingLimits::default()
                },
            )
        };

        assert_eq!(report.module_name, "steamui.so");
        assert_eq!(report.total_sampled_bytes, 16);
        assert_eq!(report.samples.len(), 1);
        assert_eq!(report.samples[0].kind, "mapping-header");
        assert_eq!(report.samples[0].matches_elf_magic, Some(true));
        assert!(report.samples[0].digest.starts_with("fnv1a64:"));
    }
}
