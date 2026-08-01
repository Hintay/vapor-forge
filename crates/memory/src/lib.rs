#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

//! Read-only process/module visibility helpers.
//!
//! This crate is not a general memory editing API. Its unsafe surface is
//! intentionally limited to bounded byte sampling from current-process mappings
//! after `/proc/self/maps` containment checks.

use thiserror::Error;

mod elf;
mod proc_maps;
mod sampling;
mod targets;
mod util;

pub use elf::{
    analyze_public_dynamic_symbol_questions, summarize_elf_file, DynamicSymbolQuestionResult,
    ElfMetadataLimits, ElfMetadataSummary,
};
pub use proc_maps::{
    current_process_context, current_process_range_has_permissions,
    current_process_range_is_readonly_data, current_process_ranges_match,
    find_proc_self_maps_targets, find_proc_self_module_data, summarize_proc_maps_targets,
    summarize_proc_self_maps_targets, ModuleRange, ProcMapsEntry, ProcMapsModuleInventory,
    ProcessContext, ProcessRangeQuery,
};
pub use sampling::{
    sample_mapped_target_module_bytes, MappedByteSample, MappedByteSampleSkip,
    MappedByteSamplingLimits, MappedByteSamplingReport,
};
pub use targets::is_steam_target_name;

#[cfg(test)]
pub(crate) use proc_maps::{
    find_proc_maps_targets_in_text, module_data_ranges_in_text, parse_parent_pid_from_stat,
    parse_proc_maps_entry, range_is_contained_in_entry, summarize_proc_maps_targets_in_text,
};
#[cfg(test)]
pub(crate) use util::{bytes_to_hex, fnv1a64_digest, truncate_str};

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

#[cfg(test)]
mod tests {
    use super::{
        analyze_public_dynamic_symbol_questions, bytes_to_hex, find_proc_maps_targets_in_text,
        fnv1a64_digest, is_steam_target_name, module_data_ranges_in_text,
        parse_parent_pid_from_stat, parse_proc_maps_entry, range_is_contained_in_entry,
        sample_mapped_target_module_bytes, summarize_elf_file, summarize_proc_maps_targets_in_text,
        truncate_str, ElfMetadataLimits, ElfMetadataSummary, MappedByteSamplingLimits, MemoryError,
        ModuleRange,
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
    fn parses_anonymous_proc_maps_entry_with_an_empty_path() {
        let entry = parse_proc_maps_entry("d2c09000-d2c57000 rw-p 00000000 00:00 0 ")
            .expect("anonymous maps entry should parse");

        assert_eq!(entry.range.base.0, 0xd2c09000);
        assert_eq!(entry.path, "");
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

    /// The layout a 32-bit steamclient.so actually presents: four named
    /// segments and an unnamed .bss butted against the last one.
    const STEAMCLIENT_MAPS: &str = "\
cfcd1000-d0b4e000 r--p 00000000 08:30 224582 /steam/ubuntu12_32/steamclient.so\n\
d0b4e000-d2b27000 r-xp 00e7c000 08:30 224582 /steam/ubuntu12_32/steamclient.so\n\
d2b27000-d2be1000 r--p 02e54000 08:30 224582 /steam/ubuntu12_32/steamclient.so\n\
d2be1000-d2c09000 rw-p 02f0d000 08:30 224582 /steam/ubuntu12_32/steamclient.so\n\
d2c09000-d2c57000 rw-p 00000000 00:00 0 \n\
d2c57000-d2ead000 r--p 00000000 08:30 224584 /steam/ubuntu12_32/steamservice.so\n";

    fn contains(ranges: &[ModuleRange], address: usize) -> bool {
        ranges
            .iter()
            .any(|range| (range.base.0..range.end.0).contains(&address))
    }

    #[test]
    fn module_data_covers_bss_but_stops_at_the_next_module() {
        let ranges = module_data_ranges_in_text(STEAMCLIENT_MAPS, "steamclient.so", 64);

        // A pointer global in .bss, which no named entry covers.
        assert!(contains(&ranges, 0xd2c5_1c18));
        // The r-- and rw- segments.
        assert!(contains(&ranges, 0xcfcd_1000));
        assert!(contains(&ranges, 0xd2be_1000));
        // Executable memory is not data, which is what a mis-decoded address
        // most often turns out to be.
        assert!(!contains(&ranges, 0xd0b4_e000));
        // The next module starts where the .bss ends.
        assert!(!contains(&ranges, 0xd2c5_7000));
    }

    #[test]
    fn module_data_is_empty_for_an_unmapped_module() {
        assert!(module_data_ranges_in_text(STEAMCLIENT_MAPS, "steamui.so", 64).is_empty());
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
    fn module_data_limit_is_applied_after_module_selection() {
        let maps = concat!(
            "1000-2000 rw-p 00000000 00:00 0 [heap]\n",
            "3000-4000 r--p 00000000 08:01 42 /tmp/steamclient.so\n",
            "4000-5000 rw-p 00001000 08:01 42 /tmp/steamclient.so\n",
            "5000-6000 rw-p 00000000 00:00 0 \n",
        );
        let ranges = module_data_ranges_in_text(maps, "steamclient.so", 8);
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges.last().unwrap().end.0, 0x6000);
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
            std::env::temp_dir().join(format!("vapor-forge-elf-test-{}", std::process::id()));
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
            dynamic_symbol_names: vec!["vapor_forge_plain_symbol".to_owned(), "_Z3foov".to_owned()],
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
