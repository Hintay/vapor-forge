use object::{Object, ObjectSegment, ObjectSymbol};

use crate::proc_maps::{range_is_contained_in_entry, ProcMapsEntry};
use crate::targets::steam_target_display_name;
use crate::util::{fnv1a64_digest, truncate_str};
use crate::{MemoryError, Result};

const DEFAULT_MAX_HEADER_SAMPLE_BYTES: usize = 16;
const DEFAULT_MAX_SYMBOL_SAMPLE_BYTES: usize = 16;
const DEFAULT_MAX_SYMBOL_SAMPLES_PER_MODULE: usize = 2;
const DEFAULT_MAX_SAMPLED_BYTES_PER_MODULE: usize = 32;
const DEFAULT_MAX_SAMPLED_BYTES_PER_PROCESS: usize = 64;

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
    let bytes = unsafe { copy_current_process_mapped_bytes(entry.range.base.0, len) };
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
        let bytes = unsafe { copy_current_process_mapped_bytes(address, len) };
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

unsafe fn copy_current_process_mapped_bytes(address: usize, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    // SAFETY: The caller guarantees that the source range is readable in the current process.
    // The destination buffer has exactly `len` bytes.
    unsafe { core::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), len) };
    bytes
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
