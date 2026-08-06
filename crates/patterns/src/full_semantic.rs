#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;

use iced_x86::code_asm::*;

use crate::elf::{ElfClass, ElfImage};
use crate::registry::{FollowMode, RuntimePatternEntry};
use crate::scan::{group_variants, PatternRef};
use crate::vtable_scan;

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

include!("bin/vapor-forge-pattern-scan/semantic.rs");

pub fn validate_live_pattern(
    module: &str,
    pointer_width: usize,
    name: &str,
    code: &[u8],
    offset: usize,
) -> Result<(), String> {
    let arch = semantic_arch(pointer_width)?;
    if module == "steamclient" && name == "CPackageInfo::GetPackageInfo" {
        let valid = match arch {
            SemanticArch::X86 => discover_package_info32_layout(code, offset).is_some(),
            SemanticArch::X86_64 => discover_package_info64_layout(code, offset).is_some(),
        };
        return valid
            .then_some(())
            .ok_or_else(|| "package-info map semantics are incomplete".to_owned());
    }
    let checks = semantic_checks(module, arch)?;
    let check = checks
        .iter()
        .find(|check| check.name == name)
        .ok_or_else(|| format!("no live semantic validator is registered for {name:?}"))?;
    if (check.validate)(code, offset).is_some() {
        return Ok(());
    }
    let detail = semantic_failure_evidence(arch, name, code, offset)
        .map(|evidence| evidence.describe())
        .unwrap_or_else(|| "semantic validation failed".to_owned());
    Err(detail)
}

pub fn has_live_validator(module: &str, pointer_width: usize, name: &str) -> bool {
    let Ok(arch) = semantic_arch(pointer_width) else {
        return false;
    };
    if module == "steamclient" && name == "CPackageInfo::GetPackageInfo" {
        return true;
    }
    semantic_checks(module, arch).is_ok_and(|checks| checks.iter().any(|check| check.name == name))
}

fn semantic_arch(pointer_width: usize) -> Result<SemanticArch, String> {
    match pointer_width {
        4 => Ok(SemanticArch::X86),
        8 => Ok(SemanticArch::X86_64),
        width => Err(format!("unsupported pointer width {width}")),
    }
}

fn semantic_checks(module: &str, arch: SemanticArch) -> Result<&'static [SemanticCheck], String> {
    Ok(match (module, arch) {
        ("steamclient", SemanticArch::X86) => STEAMCLIENT32_SEMANTIC_CHECKS,
        ("steamclient", SemanticArch::X86_64) => STEAMCLIENT64_SEMANTIC_CHECKS,
        ("steamui", SemanticArch::X86) => STEAMUI32_SEMANTIC_CHECKS,
        ("steamui", SemanticArch::X86_64) => STEAMUI64_SEMANTIC_CHECKS,
        _ => return Err(format!("unsupported pattern module {module:?}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::EMBEDDED_PATTERNS;

    #[test]
    fn rejects_unregistered_runtime_semantics() {
        let error =
            validate_live_pattern("steamclient", 8, "Unknown::Function", &[0xc3], 0).unwrap_err();
        assert!(error.contains("no live semantic validator"));
    }

    #[test]
    fn rejects_unrelated_function_body() {
        assert!(validate_live_pattern(
            "steamclient",
            8,
            "CSteamEngine::SetAPICallResult",
            &[0xc3; 128],
            0,
        )
        .is_err());
    }

    #[test]
    fn every_embedded_pattern_has_x86_and_x64_runtime_validation() {
        for entry in EMBEDDED_PATTERNS {
            assert!(
                has_live_validator(entry.module, 4, entry.name),
                "missing x86 validator for {}",
                entry.name
            );
            assert!(
                has_live_validator(entry.module, 8, entry.name),
                "missing x64 validator for {}",
                entry.name
            );
        }
    }
}
