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
    "IClientConfigStore",
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
    pub candidate_count: usize,
    pub methods: Vec<Method>,
}

#[derive(Clone, Debug)]
pub struct Method {
    pub slot: usize,
    pub name: String,
    pub func_va: u64,
    pub func_hash: u32,
}

#[cfg(any(feature = "tools", feature = "runtime-semantic"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigStoreUint64Method {
    Get,
    Set,
}

#[cfg(any(feature = "tools", feature = "runtime-semantic"))]
impl ConfigStoreUint64Method {
    pub fn name(self) -> &'static str {
        match self {
            Self::Get => "GetUint64",
            Self::Set => "SetUint64",
        }
    }

    pub fn slot(self) -> usize {
        match self {
            Self::Get => 3,
            Self::Set => 11,
        }
    }
}

#[cfg(any(feature = "tools", feature = "runtime-semantic"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConfigStoreUint64AbiEvidence {
    pub this_argument: bool,
    pub store_argument: bool,
    pub key_argument: bool,
    pub value_argument: bool,
    pub dword_serialization: bool,
    pub qword_serialization: bool,
    pub return_value: bool,
}

#[cfg(any(feature = "tools", feature = "runtime-semantic"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigStoreUint64AbiSummary {
    pub get_slot: usize,
    pub set_slot: usize,
    pub get_hash: u32,
    pub set_hash: u32,
}

#[cfg(any(feature = "tools", feature = "runtime-semantic"))]
impl ConfigStoreUint64AbiEvidence {
    pub fn is_complete(self) -> bool {
        self.this_argument
            && self.store_argument
            && self.key_argument
            && self.value_argument
            && self.dword_serialization
            && self.qword_serialization
            && self.return_value
    }

    pub fn describe(self) -> String {
        let missing = [
            ("this argument", self.this_argument),
            ("store argument", self.store_argument),
            ("key argument", self.key_argument),
            ("uint64 argument", self.value_argument),
            ("32-bit serialization", self.dword_serialization),
            ("64-bit serialization", self.qword_serialization),
            ("return value", self.return_value),
        ]
        .into_iter()
        .filter_map(|(name, present)| (!present).then_some(name))
        .collect::<Vec<_>>();
        if missing.is_empty() {
            "complete".to_owned()
        } else {
            format!("missing {}", missing.join(", "))
        }
    }
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

        let candidate_count = if let Some(&existing) = by_name.get(&name) {
            let candidate_count = found[existing].candidate_count + 1;
            if found[existing].methods.len() >= candidate.slots.len() {
                found[existing].candidate_count = candidate_count;
                continue;
            }
            candidate_count
        } else {
            1
        };

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
            candidate_count,
            methods,
        };

        if let Some(&existing) = by_name.get(&name) {
            if found[existing].methods.len() < interface.methods.len() {
                found[existing] = interface;
            } else {
                found[existing].candidate_count = candidate_count;
            }
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

#[cfg(any(feature = "tools", feature = "runtime-semantic"))]
pub fn config_store_uint64_wrapper_evidence(
    bytes: &[u8],
    class: ElfClass,
    method: ConfigStoreUint64Method,
) -> ConfigStoreUint64AbiEvidence {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

    let mut decoder = Decoder::with_ip(class.bits().into(), bytes, 0, DecoderOptions::NONE);
    let mut evidence = ConfigStoreUint64AbiEvidence::default();
    let mut before_first_call = true;
    let mut x86_value_low = false;
    let mut x86_value_high = false;
    let mut x86_return_low = false;
    let mut x86_return_high = false;

    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }

        if class == ElfClass::Elf64 && before_first_call {
            let source = (instruction.mnemonic() == Mnemonic::Mov
                && instruction.op1_kind() == OpKind::Register)
                .then(|| instruction.op1_register());
            evidence.this_argument |= source == Some(Register::RDI);
            evidence.store_argument |= source == Some(Register::ESI);
            evidence.key_argument |= source == Some(Register::RDX);
            evidence.value_argument |= source == Some(Register::RCX);
        }

        if class == ElfClass::Elf32 && instruction.memory_base() == Register::EBP {
            match instruction.memory_displacement64() {
                0x08 => evidence.this_argument = true,
                0x0c => evidence.store_argument = true,
                0x10 => evidence.key_argument = true,
                0x14 => {
                    x86_value_low = true;
                    x86_value_high |= instruction.memory_size().size() == 8;
                }
                0x18 => x86_value_high = true,
                _ => {}
            }
        }

        let width = match class {
            ElfClass::Elf32 if instruction.mnemonic() == Mnemonic::Push => {
                instruction_immediate(&instruction, 0)
            }
            ElfClass::Elf64
                if instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op0_register() == Register::EDX =>
            {
                instruction_immediate(&instruction, 1)
            }
            _ => None,
        };
        evidence.dword_serialization |= width == Some(4);
        evidence.qword_serialization |= width == Some(8);

        if evidence.qword_serialization {
            evidence.return_value |= match (class, method) {
                (ElfClass::Elf64, ConfigStoreUint64Method::Get) => {
                    instruction.mnemonic() == Mnemonic::Mov
                        && instruction.op0_kind() == OpKind::Register
                        && instruction.op0_register() == Register::RAX
                        && instruction.op1_kind() == OpKind::Register
                }
                (ElfClass::Elf64, ConfigStoreUint64Method::Set) => {
                    instruction.mnemonic() == Mnemonic::Mov
                        && instruction.op0_kind() == OpKind::Register
                        && instruction.op0_register() == Register::EAX
                        && instruction.op1_kind() == OpKind::Register
                }
                (ElfClass::Elf32, ConfigStoreUint64Method::Get) => {
                    let writes_return_register =
                        matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Movd)
                            && instruction.op0_kind() == OpKind::Register
                            && matches!(instruction.op0_register(), Register::EAX | Register::EDX);
                    if writes_return_register {
                        x86_return_low |= instruction.op0_register() == Register::EAX;
                        x86_return_high |= instruction.op0_register() == Register::EDX;
                    }
                    x86_return_low && x86_return_high
                }
                (ElfClass::Elf32, ConfigStoreUint64Method::Set) => {
                    instruction.mnemonic() == Mnemonic::Movzx
                        && instruction.op0_kind() == OpKind::Register
                        && instruction.op0_register() == Register::EAX
                        && instruction.op1_kind() == OpKind::Memory
                }
            };
        }

        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            before_first_call = false;
        }
        if instruction.flow_control() == FlowControl::Return {
            break;
        }
    }

    if class == ElfClass::Elf32 {
        evidence.value_argument = x86_value_low && x86_value_high;
        if method == ConfigStoreUint64Method::Get {
            evidence.return_value = x86_return_low && x86_return_high;
        }
    }

    evidence
}

#[cfg(any(feature = "tools", feature = "runtime-semantic"))]
pub fn validate_config_store_uint64_abi(
    path: &Path,
    report: &VtableScanReport,
) -> Result<ConfigStoreUint64AbiSummary, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let image = ElfImage::parse(&data)?;
    let interface = report
        .interfaces
        .iter()
        .find(|interface| interface.name == "IClientConfigStore")
        .ok_or_else(|| "IClientConfigStore vtable was not found".to_owned())?;
    if interface.candidate_count != 1 {
        return Err(format!(
            "IClientConfigStore produced {} RTTI vtables",
            interface.candidate_count
        ));
    }

    let mut slots = [0usize; 2];
    let mut hashes = [0u32; 2];
    for (index, method_kind) in [ConfigStoreUint64Method::Get, ConfigStoreUint64Method::Set]
        .into_iter()
        .enumerate()
    {
        let methods = interface
            .methods
            .iter()
            .filter(|method| method.name == method_kind.name())
            .collect::<Vec<_>>();
        if methods.len() != 1 {
            return Err(format!(
                "IClientConfigStore::{} produced {} slots",
                method_kind.name(),
                methods.len()
            ));
        }
        let method = methods[0];
        if method.slot != method_kind.slot() {
            return Err(format!(
                "IClientConfigStore::{} is slot {}, expected {}",
                method_kind.name(),
                method.slot,
                method_kind.slot()
            ));
        }
        if method.func_hash == 0 {
            return Err(format!(
                "IClientConfigStore::{} IPC hash was not decoded",
                method_kind.name()
            ));
        }
        let offset = image.va_to_offset(method.func_va).ok_or_else(|| {
            format!(
                "IClientConfigStore::{} wrapper is outside the file image",
                method_kind.name()
            )
        })?;
        let bytes = &data[offset..data.len().min(offset.saturating_add(0x240))];
        let evidence = config_store_uint64_wrapper_evidence(bytes, image.class, method_kind);
        if !evidence.is_complete() {
            return Err(format!(
                "IClientConfigStore::{} ABI validation failed: {}",
                method_kind.name(),
                evidence.describe()
            ));
        }
        slots[index] = method.slot;
        hashes[index] = method.func_hash;
    }
    if hashes[0] == hashes[1] {
        return Err("GetUint64 and SetUint64 share an IPC hash".to_owned());
    }

    Ok(ConfigStoreUint64AbiSummary {
        get_slot: slots[0],
        set_slot: slots[1],
        get_hash: hashes[0],
        set_hash: hashes[1],
    })
}

#[cfg(any(feature = "tools", feature = "runtime-semantic"))]
fn instruction_immediate(instruction: &iced_x86::Instruction, operand: u32) -> Option<u64> {
    use iced_x86::OpKind;

    Some(match instruction.op_kind(operand) {
        OpKind::Immediate8 => u64::from(instruction.immediate8()),
        OpKind::Immediate8to16 => instruction.immediate8to16() as u64,
        OpKind::Immediate8to32 => instruction.immediate8to32() as u64,
        OpKind::Immediate8to64 => instruction.immediate8to64() as u64,
        OpKind::Immediate16 => u64::from(instruction.immediate16()),
        OpKind::Immediate32 => u64::from(instruction.immediate32()),
        OpKind::Immediate32to64 => instruction.immediate32to64() as u64,
        OpKind::Immediate64 => instruction.immediate64(),
        _ => return None,
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

#[cfg(all(test, any(feature = "tools", feature = "runtime-semantic")))]
mod tests {
    use iced_x86::code_asm::*;

    use super::*;

    fn wrapper64(method: ConfigStoreUint64Method, include_key: bool) -> Vec<u8> {
        let mut asm = CodeAssembler::new(64).unwrap();
        asm.mov(rbx, rdi).unwrap();
        asm.mov(r14d, esi).unwrap();
        if include_key {
            asm.mov(r13, rdx).unwrap();
        }
        asm.mov(r12, rcx).unwrap();
        asm.mov(edx, 4).unwrap();
        asm.mov(edx, 8).unwrap();
        match method {
            ConfigStoreUint64Method::Get => asm.mov(rax, r12).unwrap(),
            ConfigStoreUint64Method::Set => asm.mov(eax, r12d).unwrap(),
        }
        asm.ret().unwrap();
        asm.assemble(0).unwrap()
    }

    fn wrapper32(method: ConfigStoreUint64Method, valid_return: bool) -> Vec<u8> {
        let mut asm = CodeAssembler::new(32).unwrap();
        asm.mov(eax, dword_ptr(ebp + 8)).unwrap();
        asm.mov(ecx, dword_ptr(ebp + 0x0c)).unwrap();
        asm.push(dword_ptr(ebp + 0x10)).unwrap();
        asm.mov(eax, dword_ptr(ebp + 0x14)).unwrap();
        asm.mov(edx, dword_ptr(ebp + 0x18)).unwrap();
        asm.push(4).unwrap();
        asm.push(8).unwrap();
        match method {
            ConfigStoreUint64Method::Get => {
                asm.mov(eax, dword_ptr(ebp - 8)).unwrap();
                asm.mov(edx, dword_ptr(ebp - 4)).unwrap();
            }
            ConfigStoreUint64Method::Set if valid_return => {
                asm.movzx(eax, byte_ptr(ebp - 1)).unwrap();
            }
            ConfigStoreUint64Method::Set => {
                asm.mov(ecx, dword_ptr(ebp - 4)).unwrap();
            }
        }
        asm.ret().unwrap();
        asm.assemble(0).unwrap()
    }

    #[test]
    fn validates_config_store_uint64_abis() {
        for method in [ConfigStoreUint64Method::Get, ConfigStoreUint64Method::Set] {
            assert!(config_store_uint64_wrapper_evidence(
                &wrapper64(method, true),
                ElfClass::Elf64,
                method
            )
            .is_complete());
            assert!(config_store_uint64_wrapper_evidence(
                &wrapper32(method, true),
                ElfClass::Elf32,
                method
            )
            .is_complete());
        }
    }

    #[test]
    fn validates_x86_packed_uint64_argument_load() {
        for method in [ConfigStoreUint64Method::Get, ConfigStoreUint64Method::Set] {
            let mut bytes = wrapper32(method, true);
            let low_load = asm_bytes32(|asm| asm.mov(eax, dword_ptr(ebp + 0x14))).unwrap();
            let high_load = asm_bytes32(|asm| asm.mov(edx, dword_ptr(ebp + 0x18))).unwrap();
            let low_offset = bytes
                .windows(low_load.len())
                .position(|window| window == low_load)
                .unwrap();
            bytes.drain(low_offset..low_offset + low_load.len());
            let high_offset = bytes
                .windows(high_load.len())
                .position(|window| window == high_load)
                .unwrap();
            bytes.splice(
                high_offset..high_offset + high_load.len(),
                asm_bytes32(|asm| asm.movq(xmm0, qword_ptr(ebp + 0x14))).unwrap(),
            );

            assert!(
                config_store_uint64_wrapper_evidence(&bytes, ElfClass::Elf32, method).is_complete()
            );
        }
    }

    #[test]
    fn rejects_incomplete_config_store_uint64_abis() {
        let missing_key = config_store_uint64_wrapper_evidence(
            &wrapper64(ConfigStoreUint64Method::Get, false),
            ElfClass::Elf64,
            ConfigStoreUint64Method::Get,
        );
        assert!(!missing_key.is_complete());
        assert!(!missing_key.key_argument);

        let missing_return = config_store_uint64_wrapper_evidence(
            &wrapper32(ConfigStoreUint64Method::Set, false),
            ElfClass::Elf32,
            ConfigStoreUint64Method::Set,
        );
        assert!(!missing_return.is_complete());
        assert!(!missing_return.return_value);

        let mut missing_high_return = wrapper32(ConfigStoreUint64Method::Get, true);
        let high_return = asm_bytes32(|asm| asm.mov(edx, dword_ptr(ebp - 4))).unwrap();
        let offset = missing_high_return
            .windows(high_return.len())
            .position(|window| window == high_return)
            .unwrap();
        missing_high_return.drain(offset..offset + high_return.len());
        let missing_high_return = config_store_uint64_wrapper_evidence(
            &missing_high_return,
            ElfClass::Elf32,
            ConfigStoreUint64Method::Get,
        );
        assert!(!missing_high_return.is_complete());
        assert!(!missing_high_return.return_value);
    }

    fn asm_bytes32(
        build: impl FnOnce(&mut CodeAssembler) -> Result<(), iced_x86::IcedError>,
    ) -> Option<Vec<u8>> {
        let mut asm = CodeAssembler::new(32).ok()?;
        build(&mut asm).ok()?;
        asm.assemble(0).ok()
    }
}
