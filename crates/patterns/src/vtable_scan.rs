use std::collections::{HashMap, HashSet};
use std::path::Path;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 0x1;
const MAX_SLOTS: usize = 250;
const STRING_MAX: usize = 96;
const RECENT_LEAS: usize = 6;
const EARLY_SCAN: usize = 0x400;

pub const DEFAULT_INTERFACES: &[&str] = &[
    "IClientAppManager",
    "IClientApps",
    "IClientRemoteStorage",
    "IClientUser",
    "IClientUtils",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

impl ElfClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Elf32 => "ELF32",
            Self::Elf64 => "ELF64",
        }
    }

    fn word_size(self) -> usize {
        match self {
            Self::Elf32 => 4,
            Self::Elf64 => 8,
        }
    }
}

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

pub fn scan_file(path: &Path, interfaces: Option<&[String]>) -> Result<VtableScanReport, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let image = ElfImage::parse(&data)?;
    let wanted = interfaces.map(|items| items.iter().map(String::as_str).collect::<HashSet<_>>());
    let candidates = find_candidate_vtables(&image);

    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut found = Vec::<Interface>::new();

    for (vtable_va, slots) in &candidates {
        let Some(name) = typeinfo_iface_name(&image, *vtable_va) else {
            continue;
        };
        if let Some(wanted) = wanted.as_ref() {
            if !wanted.contains(name.as_str()) {
                continue;
            }
        }

        if let Some(&existing) = by_name.get(&name) {
            if found[existing].methods.len() >= slots.len() {
                continue;
            }
        }

        let methods = slots
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
            vtable_va: *vtable_va,
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

struct ElfImage<'a> {
    data: &'a [u8],
    class: ElfClass,
    loads: Vec<LoadSegment>,
}

#[derive(Clone, Copy)]
struct LoadSegment {
    offset: u64,
    vaddr: u64,
    filesz: u64,
    flags: u32,
}

impl<'a> ElfImage<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.get(..4) != Some(b"\x7fELF") {
            return Err("input is not an ELF file".to_owned());
        }
        if data.get(5) != Some(&1) {
            return Err("big-endian ELF files are not supported".to_owned());
        }

        let class = match data.get(4) {
            Some(1) => ElfClass::Elf32,
            Some(2) => ElfClass::Elf64,
            _ => return Err("unsupported ELF class".to_owned()),
        };

        let loads = match class {
            ElfClass::Elf32 => parse_loads_elf32(data)?,
            ElfClass::Elf64 => parse_loads_elf64(data)?,
        };
        if loads.is_empty() {
            return Err("ELF file has no PT_LOAD segments".to_owned());
        }

        Ok(Self { data, class, loads })
    }

    fn word_size(&self) -> usize {
        self.class.word_size()
    }

    fn va_to_offset(&self, va: u64) -> Option<usize> {
        for load in &self.loads {
            let end = load.vaddr.checked_add(load.filesz)?;
            if va >= load.vaddr && va < end {
                return Some((load.offset + (va - load.vaddr)) as usize);
            }
        }
        None
    }

    fn in_text(&self, va: u64) -> bool {
        self.loads
            .iter()
            .any(|load| load.flags & PF_X != 0 && va >= load.vaddr && va < load.vaddr + load.filesz)
    }

    fn in_module(&self, va: u64) -> bool {
        self.loads
            .iter()
            .any(|load| va >= load.vaddr && va < load.vaddr + load.filesz)
    }

    fn read_word_va(&self, va: u64) -> Option<u64> {
        let offset = self.va_to_offset(va)?;
        match self.class {
            ElfClass::Elf32 => read_u32(self.data, offset).ok().map(u64::from),
            ElfClass::Elf64 => read_u64(self.data, offset).ok(),
        }
    }

    fn read_u32_va(&self, va: u64) -> Option<u32> {
        read_u32(self.data, self.va_to_offset(va)?).ok()
    }

    fn read_i32_va(&self, va: u64) -> Option<i32> {
        let offset = self.va_to_offset(va)?;
        let bytes = self.data.get(offset..offset + 4)?;
        Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u8_va(&self, va: u64) -> Option<u8> {
        self.data.get(self.va_to_offset(va)?).copied()
    }

    fn read_cstring(&self, va: u64) -> String {
        let Some(offset) = self.va_to_offset(va) else {
            return String::new();
        };
        let mut out = String::new();
        for &byte in self.data[offset..].iter().take(STRING_MAX) {
            if byte == 0 {
                return out;
            }
            if !(0x20..=0x7e).contains(&byte) {
                return String::new();
            }
            out.push(byte as char);
        }
        String::new()
    }
}

fn parse_loads_elf32(data: &[u8]) -> Result<Vec<LoadSegment>, String> {
    let phoff = read_u32(data, 28)? as usize;
    let phentsize = read_u16(data, 42)? as usize;
    let phnum = read_u16(data, 44)? as usize;
    let mut loads = Vec::new();

    for idx in 0..phnum {
        let off = phoff + idx * phentsize;
        let p_type = read_u32(data, off)?;
        if p_type != PT_LOAD {
            continue;
        }
        loads.push(LoadSegment {
            offset: read_u32(data, off + 4)? as u64,
            vaddr: read_u32(data, off + 8)? as u64,
            filesz: read_u32(data, off + 16)? as u64,
            flags: read_u32(data, off + 24)?,
        });
    }

    Ok(loads)
}

fn parse_loads_elf64(data: &[u8]) -> Result<Vec<LoadSegment>, String> {
    let phoff = read_u64(data, 32)? as usize;
    let phentsize = read_u16(data, 54)? as usize;
    let phnum = read_u16(data, 56)? as usize;
    let mut loads = Vec::new();

    for idx in 0..phnum {
        let off = phoff + idx * phentsize;
        let p_type = read_u32(data, off)?;
        if p_type != PT_LOAD {
            continue;
        }
        loads.push(LoadSegment {
            flags: read_u32(data, off + 4)?,
            offset: read_u64(data, off + 8)?,
            vaddr: read_u64(data, off + 16)?,
            filesz: read_u64(data, off + 32)?,
        });
    }

    Ok(loads)
}

fn find_candidate_vtables(image: &ElfImage<'_>) -> Vec<(u64, Vec<u64>)> {
    let word = image.word_size() as u64;
    let mut out = Vec::new();

    for load in &image.loads {
        if load.flags & PF_X != 0 {
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
            let ot = image.read_word_va(p - 2 * word).unwrap_or(1);
            if ot != 0 || ti == 0 || !image.in_module(ti) {
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
                out.push((p, slots));
            }
            p += word;
        }
    }

    out
}

fn typeinfo_iface_name(image: &ElfImage<'_>, vtable_va: u64) -> Option<String> {
    let word = image.word_size() as u64;
    let ti = image.read_word_va(vtable_va.checked_sub(word)?)?;
    if !image.in_module(ti) {
        return None;
    }
    let name_va = image.read_word_va(ti.checked_add(word)?)?;
    if !image.in_module(name_va) {
        return None;
    }
    let name = image.read_cstring(name_va);
    let (digits, body) = split_decimal_prefix(&name)?;
    if body.len() != digits || !body.starts_with("IClient") || !body.ends_with("Map") {
        return None;
    }
    Some(body[..body.len() - 3].to_owned())
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
                        let text = image.read_cstring(target);
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
                let text = image.read_cstring(target);
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
