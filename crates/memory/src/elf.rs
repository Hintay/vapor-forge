use object::{Object, ObjectSection, ObjectSymbol};

use crate::targets::steam_target_display_name;
use crate::util::{bytes_to_hex, looks_like_mangled_cpp_symbol, truncate_str};
use crate::{MemoryError, Result};

const DEFAULT_MAX_ELF_FILE_SIZE: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_DYNAMIC_SYMBOL_NAMES: usize = 64;
const DEFAULT_MAX_DYNAMIC_SYMBOL_NAME_LEN: usize = 256;

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

impl Default for ElfMetadataLimits {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_ELF_FILE_SIZE,
            max_dynamic_symbol_names: DEFAULT_MAX_DYNAMIC_SYMBOL_NAMES,
            max_dynamic_symbol_name_len: DEFAULT_MAX_DYNAMIC_SYMBOL_NAME_LEN,
        }
    }
}
