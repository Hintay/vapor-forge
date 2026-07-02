use std::collections::{BTreeMap, BTreeSet};

use vapor_forge_core::Address;

use crate::targets::{is_steam_target_name, steam_target_display_name};
use crate::Result;

const MAX_PROC_MAPS_LINE_LEN: usize = 4096;
const MAX_PROC_MAPS_PATH_LEN: usize = 1024;

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

fn read_parent_pid() -> Option<u32> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    parse_parent_pid_from_stat(&stat)
}

pub(crate) fn parse_parent_pid_from_stat(stat: &str) -> Option<u32> {
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

pub(crate) fn find_proc_maps_targets_in_text(maps: &str, max_entries: usize) -> Vec<ProcMapsEntry> {
    maps.lines()
        .filter_map(parse_proc_maps_entry)
        .filter(|entry| is_steam_target_name(&entry.path))
        .take(max_entries)
        .collect()
}

pub(crate) fn summarize_proc_maps_targets_in_text(
    maps: &str,
    max_entries: usize,
) -> Vec<ProcMapsModuleInventory> {
    let entries = find_proc_maps_targets_in_text(maps, max_entries);
    summarize_proc_maps_targets(&entries)
}

pub(crate) fn parse_proc_maps_entry(line: &str) -> Option<ProcMapsEntry> {
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

pub(crate) fn range_is_contained_in_entry(
    entry: &ProcMapsEntry,
    address: usize,
    len: usize,
) -> bool {
    if len == 0 || address < entry.range.base.0 {
        return false;
    }
    let Some(end) = address.checked_add(len) else {
        return false;
    };
    end <= entry.range.end.0
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
