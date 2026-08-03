use std::collections::{HashMap, HashSet};
use std::path::Path;

pub use crate::elf::ElfClass;
use crate::elf::ElfImage;

const MAX_SLOTS: usize = 250;
const MAX_SUBOBJECT_OFFSET: i64 = 0x10_0000;
const STRING_MAX: usize = 96;
const RECENT_LEAS: usize = 6;
const EARLY_SCAN: usize = 0x400;

pub const DEFAULT_INTERFACES: &[&str] = &[
    "IClientAppManager",
    "IClientApps",
    "IClientRemoteStorage",
    "IClientUser",
    "IClientUserStats",
    "IClientUtils",
];

#[derive(Clone, Debug)]
pub struct VtableScanReport {
    pub path: String,
    pub elf_class: ElfClass,
    pub candidate_count: usize,
    pub interfaces: Vec<Interface>,
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub name: String,
    pub vtable_va: u64,
    pub methods: Vec<Method>,
}

#[derive(Clone, Debug)]
pub struct Method {
    pub slot: usize,
    pub name: String,
    pub func_va: u64,
    pub func_hash: u32,
}

#[derive(Clone, Debug)]
pub struct ClassVtable {
    pub name: String,
    pub vtable_va: u64,
    pub offset_to_top: i64,
    pub methods: Vec<Method>,
}

struct CandidateVtable {
    vtable_va: u64,
    offset_to_top: i64,
    slots: Vec<u64>,
}

pub fn scan_file(path: &Path, interfaces: Option<&[String]>) -> Result<VtableScanReport, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let image = ElfImage::parse(&data)?;
    let wanted = interfaces.map(|items| items.iter().map(String::as_str).collect::<HashSet<_>>());
    let candidates = find_candidate_vtables(&image, false);

    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut found = Vec::<Interface>::new();

    for candidate in &candidates {
        let Some((name, is_interface)) = typeinfo_class_name(&image, candidate.vtable_va) else {
            continue;
        };
        if let Some(wanted) = wanted.as_ref() {
            if !wanted.contains(name.as_str()) {
                continue;
            }
        } else if !is_interface {
            continue;
        }

        if let Some(&existing) = by_name.get(&name) {
            if found[existing].methods.len() >= candidate.slots.len() {
                continue;
            }
        }

        let methods = candidate
            .slots
            .iter()
            .enumerate()
            .map(|(slot, &func_va)| {
                let (method_name, func_hash) = decode_wrapper(&image, func_va);
                Method {
                    slot,
                    name: method_name,
                    func_va,
                    func_hash,
                }
            })
            .collect();

        let interface = Interface {
            name: name.clone(),
            vtable_va: candidate.vtable_va,
            methods,
        };

        if let Some(&existing) = by_name.get(&name) {
            found[existing] = interface;
        } else {
            by_name.insert(name, found.len());
            found.push(interface);
        }
    }

    found.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(VtableScanReport {
        path: path.display().to_string(),
        elf_class: image.class,
        candidate_count: candidates.len(),
        interfaces: found,
    })
}

pub fn scan_class_vtables(path: &Path, class: &str) -> Result<Vec<ClassVtable>, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let image = ElfImage::parse(&data)?;
    let mut found = Vec::new();

    for candidate in find_candidate_vtables(&image, true) {
        let Some((name, _)) = typeinfo_class_name(&image, candidate.vtable_va) else {
            continue;
        };
        if name != class {
            continue;
        }
        let methods = candidate
            .slots
            .iter()
            .enumerate()
            .map(|(slot, &func_va)| Method {
                slot,
                name: String::new(),
                func_va,
                func_hash: 0,
            })
            .collect();
        found.push(ClassVtable {
            name,
            vtable_va: candidate.vtable_va,
            offset_to_top: candidate.offset_to_top,
            methods,
        });
    }

    found.sort_by_key(|vtable| (vtable.offset_to_top, vtable.vtable_va));
    Ok(found)
}

fn find_candidate_vtables(image: &ElfImage<'_>, include_secondary: bool) -> Vec<CandidateVtable> {
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
            let ot_raw = image.read_word_va(p - 2 * word).unwrap_or(1);
            let Some(offset_to_top) = decode_offset_to_top(image.class, ot_raw) else {
                p += word;
                continue;
            };
            if (!include_secondary && offset_to_top != 0) || ti == 0 || !image.in_module(ti) {
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
                if slots.len() >= MAX_SLOTS {
                    break;
                }
                q += word;
            }

            if slots.len() >= 3 {
                out.push(CandidateVtable {
                    vtable_va: p,
                    offset_to_top,
                    slots,
                });
            }
            p += word;
        }
    }

    out
}

fn decode_offset_to_top(class: ElfClass, raw: u64) -> Option<i64> {
    let value = match class {
        ElfClass::Elf32 => i64::from(raw as u32 as i32),
        ElfClass::Elf64 => raw as i64,
    };
    (-MAX_SUBOBJECT_OFFSET..=0)
        .contains(&value)
        .then_some(value)
}

fn typeinfo_class_name(image: &ElfImage<'_>, vtable_va: u64) -> Option<(String, bool)> {
    let word = image.word_size() as u64;
    let ti = image.read_word_va(vtable_va.checked_sub(word)?)?;
    if !image.in_module(ti) {
        return None;
    }
    let name_va = image.read_word_va(ti.checked_add(word)?)?;
    if !image.in_module(name_va) {
        return None;
    }
    let name = image.read_cstring(name_va, STRING_MAX);
    let (digits, body) = split_decimal_prefix(&name)?;
    if body.len() != digits {
        return None;
    }
    if body.starts_with("IClient") && body.ends_with("Map") {
        Some((body[..body.len() - 3].to_owned(), true))
    } else {
        Some((body.to_owned(), false))
    }
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

fn decode_wrapper(image: &ElfImage<'_>, func_va: u64) -> (String, u32) {
    match image.class {
        ElfClass::Elf32 => decode_wrapper_x86(image, func_va),
        ElfClass::Elf64 => decode_wrapper_x86_64(image, func_va),
    }
}

fn decode_wrapper_x86(image: &ElfImage<'_>, func_va: u64) -> (String, u32) {
    let Some(pic_base) = find_pic_anchor(image, func_va) else {
        return (String::new(), 0);
    };

    let mut recent = Vec::<String>::new();
    let mut method = String::new();
    let mut func_hash = 0u32;
    let mut ipc_matched = false;

    for i in 0..EARLY_SCAN.saturating_sub(12) {
        let va = func_va + i as u64;
        let Some(byte) = image.read_u8_va(va) else {
            break;
        };

        if byte == 0xe8 && !ipc_matched {
            if let Some(found) = recent.iter().rev().find(|s| is_method_shape(s)) {
                method = found.clone();
                ipc_matched = true;
            }
        }

        if byte == 0x8d {
            if let Some(modrm) = image.read_u8_va(va + 1) {
                if (modrm & 0xc0) == 0x80 && (modrm & 0x07) != 4 {
                    if let Some(disp) = image.read_i32_va(va + 2) {
                        let target = (pic_base as i64 + disp as i64) as u32 as u64;
                        let text = image.read_cstring(target, STRING_MAX);
                        if !text.is_empty() {
                            recent.push(text);
                            if recent.len() > RECENT_LEAS {
                                recent.remove(0);
                            }
                        }
                    }
                }
            }
        }

        if func_hash == 0
            && image.read_u8_va(va) == Some(0xc7)
            && image.read_u8_va(va + 1) == Some(0x45)
            && image.read_u8_va(va + 7) == Some(0x6a)
            && image.read_u8_va(va + 8) == Some(0x04)
            && image.read_u8_va(va + 9) == Some(0x50)
            && image.read_u8_va(va + 10) == Some(0x57)
            && image.read_u8_va(va + 11) == Some(0xe8)
        {
            func_hash = image.read_u32_va(va + 3).unwrap_or(0);
        }

        if ipc_matched && func_hash != 0 {
            break;
        }
    }

    (method, func_hash)
}

fn find_pic_anchor(image: &ElfImage<'_>, func_va: u64) -> Option<u64> {
    for i in 0..0x40usize.saturating_sub(11) {
        let va = func_va + i as u64;
        if image.read_u8_va(va)? != 0xe8 {
            continue;
        }
        let after_call = va + 5;
        let end = (i + 5 + 16).min(0x40usize.saturating_sub(5));
        for j in (i + 5)..end {
            let add_va = func_va + j as u64;
            let b0 = image.read_u8_va(add_va)?;
            let b1 = image.read_u8_va(add_va + 1)?;
            if b0 == 0x81 && (b1 & 0xf8) == 0xc0 {
                let imm = image.read_i32_va(add_va + 2)?;
                return Some((after_call as i64 + imm as i64) as u32 as u64);
            }
        }
    }
    None
}

fn decode_wrapper_x86_64(image: &ElfImage<'_>, func_va: u64) -> (String, u32) {
    let mut recent = Vec::<String>::new();
    let mut method = String::new();
    let mut func_hash = 0u32;

    for i in 0..EARLY_SCAN.saturating_sub(8) {
        let va = func_va + i as u64;
        let Some(byte) = image.read_u8_va(va) else {
            break;
        };

        if (byte == 0x48 || byte == 0x4c)
            && image.read_u8_va(va + 1) == Some(0x8d)
            && image
                .read_u8_va(va + 2)
                .is_some_and(|modrm| (modrm & 0xc7) == 0x05)
        {
            if let Some(disp) = image.read_i32_va(va + 3) {
                let target = (va + 7).wrapping_add_signed(disp as i64);
                let text = image.read_cstring(target, STRING_MAX);
                if !text.is_empty() {
                    if method.is_empty() && is_method_shape(&text) {
                        method = text.clone();
                    }
                    recent.push(text);
                    if recent.len() > RECENT_LEAS {
                        recent.remove(0);
                    }
                }
            }
        }

        if byte == 0xe8 && method.is_empty() {
            if let Some(found) = recent.iter().rev().find(|s| is_method_shape(s)) {
                method = found.clone();
            }
        }

        if func_hash == 0
            && byte == 0xc7
            && image
                .read_u8_va(va + 1)
                .is_some_and(|modrm| (modrm & 0x38) == 0)
        {
            func_hash = read_c7_imm32(image, va).unwrap_or(0);
        }

        if !method.is_empty() && func_hash != 0 {
            break;
        }
    }

    (method, func_hash)
}

fn read_c7_imm32(image: &ElfImage<'_>, instr_va: u64) -> Option<u32> {
    let modrm = image.read_u8_va(instr_va + 1)?;
    let mode = modrm >> 6;
    let rm = modrm & 0x07;
    let mut imm_va = instr_va + 2;

    if rm == 4 {
        imm_va += 1;
    }

    match (mode, rm) {
        (0, 5) => imm_va += 4,
        (1, _) => imm_va += 1,
        (2, _) => imm_va += 4,
        _ => {}
    }

    let value = image.read_u32_va(imm_va)?;
    if image.read_u8_va(imm_va + 4) == Some(0xe8) {
        Some(value)
    } else {
        None
    }
}

fn is_method_shape(text: &str) -> bool {
    if text.len() < 2 || text.len() > STRING_MAX {
        return false;
    }
    if text.starts_with("IClient") {
        return false;
    }
    if text.contains('/') || text.contains('%') || text.contains(' ') {
        return false;
    }
    text.as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
}
