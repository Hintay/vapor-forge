#![forbid(unsafe_code)]

//! Steam's app-info cache lookup, read from the license cache rebuild.
//!
//! `CUser::RemoveSiteLicenses` ends with `RebuildLicensesCache(this)` followed
//! by the license notice call and `return 1`. The rebuild looks each licensed
//! app up through `GetAppInfo(cache, app_id)`, where the cache is a fixed
//! member of the engine object. `GetAppInfo` is an inlined red-black tree
//! search (`left` at node offset 0, `right` at 4) followed by checks on the
//! found record; its last byte check is the flag the app-info response parser
//! sets for app IDs the server reported as unknown. The tree layout and that
//! flag are read from its body.
//!
//! The runtime and the offline scan both decode through here.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

const SITE_LICENSE_WINDOW: usize = 0x240;
const REBUILD_WINDOW: usize = 0x1800;
const LOOKUP_WINDOW: usize = 0xa0;
const ARGUMENT_LOOKBACK: usize = 12;
const MIN_CACHE_OFFSET: usize = 0x100;
const MAX_CACHE_OFFSET: usize = 0x10000;
const MAX_FIELD_OFFSET: usize = 0x100;

/// Red-black tree node layout of the app-info cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeLayout {
    /// Root node index (`i32`, `-1` when empty) in the cache.
    pub root: usize,
    /// Node array pointer in the cache.
    pub nodes: usize,
    /// Node size in bytes.
    pub stride: usize,
    /// App ID (`u32`) in a node.
    pub key: usize,
    /// Record pointer in a node.
    pub value: usize,
}

impl TreeLayout {
    /// Left and right child indices (`i32`) in a node.
    pub const LEFT: usize = 0;
    pub const RIGHT: usize = 4;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppInfoLookup {
    pub rebuild: usize,
    pub get_app_info: usize,
    /// Cache offset in the engine object.
    pub cache_offset: usize,
    /// Engine pointer slot the rebuild reads, when it is addressed directly.
    pub engine_slot: Option<usize>,
    pub tree: TreeLayout,
    /// Record byte that is nonzero for an app ID the server reported unknown.
    pub unknown_flag: usize,
}

pub fn decode(
    bitness: u32,
    code_base: usize,
    code: &[u8],
    remove_site_licenses: usize,
) -> Result<AppInfoLookup, &'static str> {
    let rebuild = rebuild_call(bitness, code_base, code, remove_site_licenses)?;
    let instructions = decode_window(bitness, code_base, code, rebuild, REBUILD_WINDOW)
        .ok_or("license cache rebuild is outside the code region")?;
    let mut tried = Vec::new();
    for (index, instruction) in instructions.iter().enumerate() {
        let Some(target) = direct_call_target(instruction) else {
            continue;
        };
        if tried.contains(&target) {
            continue;
        }
        tried.push(target);
        let Some((tree, unknown_flag)) = decode_lookup(bitness, code_base, code, target) else {
            continue;
        };
        let lookback = &instructions[index.saturating_sub(ARGUMENT_LOOKBACK)..index];
        let cache_offset = cache_offset(lookback).ok_or("app-info lookup has no cache operand")?;
        return Ok(AppInfoLookup {
            rebuild,
            get_app_info: target,
            cache_offset,
            engine_slot: engine_slot(lookback),
            tree,
            unknown_flag,
        });
    }
    Err("license cache rebuild makes no app-info lookup")
}

/// The call before the notice call that precedes `mov eax, 1`.
fn rebuild_call(
    bitness: u32,
    code_base: usize,
    code: &[u8],
    entry: usize,
) -> Result<usize, &'static str> {
    let instructions = decode_window(bitness, code_base, code, entry, SITE_LICENSE_WINDOW)
        .ok_or("site-license removal is outside the code region")?;
    let mut calls = Vec::new();
    for instruction in &instructions {
        if let Some(target) = direct_call_target(instruction) {
            calls.push(target);
        }
        let returns_one = instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::EAX
            && is_immediate(instruction, 1, 1);
        if returns_one {
            let [.., rebuild, notify] = calls[..] else {
                return Err("site-license removal returns 1 without rebuilding");
            };
            if rebuild == notify {
                return Err("site-license removal rebuild and notice calls coincide");
            }
            return Ok(rebuild);
        }
    }
    Err("site-license removal has no rebuilt return")
}

fn decode_lookup(
    bitness: u32,
    code_base: usize,
    code: &[u8],
    entry: usize,
) -> Option<(TreeLayout, usize)> {
    let pointer_size = bitness as usize / 8;
    let instructions = decode_window(bitness, code_base, code, entry, LOOKUP_WINDOW)?;

    // The root index is loaded from the cache and compared with -1.
    let root_check = instructions.iter().position(|instruction| {
        instruction.mnemonic() == Mnemonic::Cmp
            && instruction.op0_kind() == OpKind::Register
            && is_immediate(instruction, 1, u64::from(u32::MAX))
    })?;
    let compared = instructions[root_check].op0_register().full_register();
    let root_load = (0..root_check)
        .rev()
        .find(|&index| writes_register(&instructions[index], compared))?;
    let (cache_register, root) = field_load(&instructions[root_load], 4)?;

    let nodes_load = (root_load + 1..instructions.len()).find(|&index| {
        field_load(&instructions[index], pointer_size)
            .is_some_and(|(base, _)| base == cache_register)
    })?;
    let (_, nodes) = field_load(&instructions[nodes_load], pointer_size)?;
    if nodes == root {
        return None;
    }

    // Node address arithmetic up to the key comparison gives the node size.
    let mut stride = 1usize;
    let mut scaled = false;
    let mut key = None;
    let mut key_index = 0;
    for (index, instruction) in instructions.iter().enumerate().skip(nodes_load + 1) {
        match instruction.mnemonic() {
            Mnemonic::Shl
                if instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Immediate8 =>
            {
                stride = stride.checked_shl(u32::from(instruction.immediate8()))?;
                scaled = true;
            }
            Mnemonic::Lea if instruction.memory_index() != Register::None => {
                let scale = instruction.memory_index_scale() as usize;
                stride *= if instruction.memory_base() == instruction.memory_index() {
                    scale + 1
                } else {
                    scale
                };
                scaled = true;
            }
            _ => {}
        }
        if let Some(offset) = node_field(instruction, 4) {
            if offset > TreeLayout::RIGHT {
                key = Some(offset);
                key_index = index;
                break;
            }
        }
    }
    let key = key?;
    if !scaled || stride < key + 4 {
        return None;
    }
    let has_child = |offset| {
        instructions
            .iter()
            .any(|instruction| node_field(instruction, 4) == Some(offset))
    };
    if !has_child(TreeLayout::LEFT) || !has_child(TreeLayout::RIGHT) {
        return None;
    }

    let (value_index, value) = instructions
        .iter()
        .enumerate()
        .skip(key_index + 1)
        .find_map(|(index, instruction)| {
            let offset = node_field(instruction, pointer_size)?;
            (instruction.mnemonic() == Mnemonic::Mov
                && offset >= key + 4
                && offset + pointer_size <= stride)
                .then_some((index, offset))
        })?;

    let unknown_flag = instructions
        .iter()
        .skip(value_index + 1)
        .find_map(|instruction| {
            let offset = node_field(instruction, 1)?;
            matches!(instruction.mnemonic(), Mnemonic::Cmp | Mnemonic::Movzx).then_some(offset)
        })?;

    Some((
        TreeLayout {
            root,
            nodes,
            stride,
            key,
            value,
        },
        unknown_flag,
    ))
}

/// The cache operand: the last `lea reg, [reg + offset]` or `add reg, offset`
/// in the engine-member range before the lookup call. Frame and stack
/// arithmetic is not an engine member.
fn cache_offset(lookback: &[Instruction]) -> Option<usize> {
    lookback.iter().rev().find_map(|instruction| {
        let offset = match instruction.mnemonic() {
            Mnemonic::Lea
                if instruction.memory_index() == Register::None
                    && instruction.memory_base().is_gpr()
                    && !is_stack(instruction.memory_base().full_register()) =>
            {
                usize::try_from(instruction.memory_displacement64()).ok()?
            }
            Mnemonic::Add
                if instruction.op0_kind() == OpKind::Register
                    && !is_stack(instruction.op0_register().full_register()) =>
            {
                match instruction.op1_kind() {
                    OpKind::Immediate32 | OpKind::Immediate8to32 | OpKind::Immediate32to64 => {
                        usize::try_from(instruction.immediate(1)).ok()?
                    }
                    _ => return None,
                }
            }
            _ => return None,
        };
        (MIN_CACHE_OFFSET..MAX_CACHE_OFFSET)
            .contains(&offset)
            .then_some(offset)
    })
}

fn engine_slot(lookback: &[Instruction]) -> Option<usize> {
    lookback
        .iter()
        .rev()
        .find(|instruction| {
            matches!(instruction.mnemonic(), Mnemonic::Lea | Mnemonic::Mov)
                && instruction.is_ip_rel_memory_operand()
        })
        .map(|instruction| instruction.ip_rel_memory_address() as usize)
}

/// `(base, offset)` of `mov reg, [base + offset]` reading `width` bytes from
/// a field of a register-held object.
fn field_load(instruction: &Instruction, width: usize) -> Option<(Register, usize)> {
    if !matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Movsxd)
        || instruction.op0_kind() != OpKind::Register
        || instruction.op1_kind() != OpKind::Memory
        || instruction.memory_index() != Register::None
        || instruction.memory_size().size() != width
    {
        return None;
    }
    let base = instruction.memory_base().full_register();
    if !base.is_gpr() || is_stack(base) {
        return None;
    }
    let offset = usize::try_from(instruction.memory_displacement64()).ok()?;
    (offset < MAX_FIELD_OFFSET).then_some((base, offset))
}

/// Offset of a `width`-byte memory operand on a register-held node or record.
fn node_field(instruction: &Instruction, width: usize) -> Option<usize> {
    if instruction.mnemonic() == Mnemonic::Lea
        || instruction.memory_size().size() != width
        || !(0..instruction.op_count())
            .any(|operand| instruction.op_kind(operand) == OpKind::Memory)
    {
        return None;
    }
    let base = instruction.memory_base().full_register();
    if !base.is_gpr() || is_stack(base) {
        return None;
    }
    let offset = usize::try_from(instruction.memory_displacement64()).ok()?;
    (offset < MAX_FIELD_OFFSET).then_some(offset)
}

fn writes_register(instruction: &Instruction, register: Register) -> bool {
    instruction.op_count() > 0
        && instruction.op0_kind() == OpKind::Register
        && instruction.op0_register().full_register() == register
}

fn is_stack(register: Register) -> bool {
    matches!(register, Register::RSP | Register::RBP)
}

fn is_immediate(instruction: &Instruction, operand: u32, value: u64) -> bool {
    match instruction.op_kind(operand) {
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 => {
            instruction.immediate(operand) == value
        }
        OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate32to64 => {
            instruction.immediate(operand) as u32 == value as u32
        }
        _ => false,
    }
}

fn direct_call_target(instruction: &Instruction) -> Option<usize> {
    (instruction.flow_control() == FlowControl::Call)
        .then(|| instruction.near_branch_target() as usize)
}

fn decode_window(
    bitness: u32,
    code_base: usize,
    code: &[u8],
    entry: usize,
    length: usize,
) -> Option<Vec<Instruction>> {
    let offset = entry.checked_sub(code_base)?;
    let window = code.get(offset..)?;
    let window = &window[..window.len().min(length)];
    Some(
        Decoder::with_ip(bitness, window, entry as u64, DecoderOptions::NONE)
            .into_iter()
            .take_while(|instruction| !instruction.is_invalid())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::code_asm::*;
    use iced_x86::BlockEncoderOptions;

    const BASE: u64 = 0x10_0000;

    struct Assembled {
        code: Vec<u8>,
        remove: u64,
        rebuild: u64,
        lookup: u64,
    }

    /// Site-license removal, rebuild and the current x86_64 lookup shape.
    fn current64(cache_offset: i32) -> Assembled {
        let mut a = CodeAssembler::new(64).unwrap();
        let mut remove = a.create_label();
        let mut rebuild = a.create_label();
        let mut notify = a.create_label();
        let mut block = a.create_label();
        let mut lookup = a.create_label();
        let mut other = a.create_label();
        let mut slot = a.create_label();
        let mut walk_left = a.create_label();
        let mut node = a.create_label();
        let mut found = a.create_label();
        let mut none = a.create_label();
        let mut empty = a.create_label();

        a.set_label(&mut remove).unwrap();
        a.push(rbx).unwrap();
        a.mov(rbx, rdi).unwrap();
        a.xor(edx, edx).unwrap();
        a.call(other).unwrap();
        a.mov(rdi, rbx).unwrap();
        a.call(rebuild).unwrap();
        a.mov(rdi, rbx).unwrap();
        a.call(notify).unwrap();
        a.mov(eax, 1).unwrap();
        a.pop(rbx).unwrap();
        a.ret().unwrap();

        a.set_label(&mut rebuild).unwrap();
        a.push(rbx).unwrap();
        a.call(other).unwrap();
        a.lea(rax, ptr(slot)).unwrap();
        a.mov(rax, qword_ptr(rax)).unwrap();
        a.lea(rbx, qword_ptr(rax + cache_offset)).unwrap();
        a.mov(rdi, rbx).unwrap();
        a.call(block).unwrap();
        a.mov(esi, ebp).unwrap();
        a.mov(rdi, rbx).unwrap();
        a.call(lookup).unwrap();
        a.pop(rbx).unwrap();
        a.ret().unwrap();

        a.set_label(&mut lookup).unwrap();
        a.movsxd(rax, dword_ptr(rdi + 0x28)).unwrap();
        a.cmp(eax, -1).unwrap();
        a.je(none).unwrap();
        a.mov(r8, qword_ptr(rdi + 0x40)).unwrap();
        a.jmp(node).unwrap();
        a.set_label(&mut walk_left).unwrap();
        a.movsxd(rax, dword_ptr(rdx)).unwrap();
        a.cmp(eax, -1).unwrap();
        a.je(none).unwrap();
        a.set_label(&mut node).unwrap();
        a.shl(rax, 5).unwrap();
        a.lea(rdx, qword_ptr(r8 + rax)).unwrap();
        a.mov(ecx, dword_ptr(rdx + 0x10)).unwrap();
        a.cmp(esi, ecx).unwrap();
        a.jb(walk_left).unwrap();
        a.jae(found).unwrap();
        a.movsxd(rax, dword_ptr(rdx + 4)).unwrap();
        a.cmp(eax, -1).unwrap();
        a.jne(node).unwrap();
        a.set_label(&mut none).unwrap();
        a.xor(eax, eax).unwrap();
        a.ret().unwrap();
        a.set_label(&mut found).unwrap();
        a.mov(rax, qword_ptr(r8 + rax + 0x18)).unwrap();
        a.test(rax, rax).unwrap();
        a.je(none).unwrap();
        a.mov(rdi, qword_ptr(empty)).unwrap();
        a.cmp(qword_ptr(rax + 0x20), rdi).unwrap();
        a.cmp(byte_ptr(rax + 0x14), 0).unwrap();
        a.jne(none).unwrap();
        a.ret().unwrap();

        a.set_label(&mut notify).unwrap();
        a.ret().unwrap();
        a.set_label(&mut block).unwrap();
        a.ret().unwrap();
        a.set_label(&mut other).unwrap();
        a.ret().unwrap();
        a.set_label(&mut slot).unwrap();
        a.dq(&[0]).unwrap();
        a.set_label(&mut empty).unwrap();
        a.dq(&[0]).unwrap();

        let result = a
            .assemble_options(BASE, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();
        Assembled {
            remove: result.label_ip(&remove).unwrap(),
            rebuild: result.label_ip(&rebuild).unwrap(),
            lookup: result.label_ip(&lookup).unwrap(),
            code: result.inner.code_buffer,
        }
    }

    /// The i686 shape: 24-byte nodes, a byte flag read with `movzx`, and the
    /// cache operand built with `add`.
    fn current32() -> Assembled {
        let mut a = CodeAssembler::new(32).unwrap();
        let mut remove = a.create_label();
        let mut rebuild = a.create_label();
        let mut notify = a.create_label();
        let mut block = a.create_label();
        let mut lookup = a.create_label();
        let mut compare = a.create_label();
        let mut walk_left = a.create_label();
        let mut node = a.create_label();
        let mut found = a.create_label();
        let mut none = a.create_label();

        a.set_label(&mut remove).unwrap();
        a.push(ebx).unwrap();
        a.mov(ebx, dword_ptr(esp + 8)).unwrap();
        a.push(ebx).unwrap();
        a.call(rebuild).unwrap();
        a.mov(dword_ptr(esp), ebx).unwrap();
        a.call(notify).unwrap();
        a.add(esp, 4).unwrap();
        a.mov(eax, 1).unwrap();
        a.pop(ebx).unwrap();
        a.ret().unwrap();

        a.set_label(&mut rebuild).unwrap();
        a.push(esi).unwrap();
        a.mov(eax, dword_ptr(ebp - 0x98)).unwrap();
        a.mov(eax, dword_ptr(eax)).unwrap();
        a.mov(esi, eax).unwrap();
        a.add(esi, 0xf28).unwrap();
        a.push(esi).unwrap();
        a.call(block).unwrap();
        a.pop(ecx).unwrap();
        a.push(edi).unwrap();
        a.push(esi).unwrap();
        a.call(lookup).unwrap();
        a.add(esp, 8).unwrap();
        a.pop(esi).unwrap();
        a.ret().unwrap();

        a.set_label(&mut lookup).unwrap();
        a.push(esi).unwrap();
        a.push(ebx).unwrap();
        a.mov(ecx, dword_ptr(esp + 0xc)).unwrap();
        a.mov(edx, dword_ptr(esp + 0x10)).unwrap();
        a.mov(eax, dword_ptr(ecx + 0x1c)).unwrap();
        a.cmp(eax, -1).unwrap();
        a.je(none).unwrap();
        a.mov(ecx, dword_ptr(ecx + 0x30)).unwrap();
        a.jmp(node).unwrap();
        a.set_label(&mut walk_left).unwrap();
        a.mov(eax, dword_ptr(eax)).unwrap();
        a.cmp(eax, -1).unwrap();
        a.je(none).unwrap();
        a.set_label(&mut node).unwrap();
        a.lea(eax, dword_ptr(eax + eax * 2)).unwrap();
        a.lea(eax, dword_ptr(ecx + eax * 8)).unwrap();
        a.cmp(dword_ptr(eax + 0x10), edx).unwrap();
        a.ja(walk_left).unwrap();
        a.jae(found).unwrap();
        a.mov(eax, dword_ptr(eax + 4)).unwrap();
        a.cmp(eax, -1).unwrap();
        a.jne(node).unwrap();
        a.set_label(&mut none).unwrap();
        a.xor(esi, esi).unwrap();
        a.mov(eax, esi).unwrap();
        a.pop(ebx).unwrap();
        a.pop(esi).unwrap();
        a.ret().unwrap();
        a.set_label(&mut found).unwrap();
        a.mov(esi, dword_ptr(eax + 0x14)).unwrap();
        a.test(esi, esi).unwrap();
        a.je(none).unwrap();
        a.push(0x14).unwrap();
        a.lea(eax, dword_ptr(esi + 0x1c)).unwrap();
        a.push(eax).unwrap();
        a.call(compare).unwrap();
        a.movzx(edx, byte_ptr(esi + 0x10)).unwrap();
        a.add(esp, 8).unwrap();
        a.pop(ebx).unwrap();
        a.mov(eax, esi).unwrap();
        a.pop(esi).unwrap();
        a.ret().unwrap();

        a.set_label(&mut notify).unwrap();
        a.ret().unwrap();
        a.set_label(&mut block).unwrap();
        a.ret().unwrap();
        a.set_label(&mut compare).unwrap();
        a.ret().unwrap();

        let result = a
            .assemble_options(BASE, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();
        Assembled {
            remove: result.label_ip(&remove).unwrap(),
            rebuild: result.label_ip(&rebuild).unwrap(),
            lookup: result.label_ip(&lookup).unwrap(),
            code: result.inner.code_buffer,
        }
    }

    #[test]
    fn decodes_the_x86_64_lookup() {
        let assembled = current64(0x13d8);
        let lookup = decode(
            64,
            BASE as usize,
            &assembled.code,
            assembled.remove as usize,
        )
        .expect("lookup decodes");
        assert_eq!(lookup.rebuild, assembled.rebuild as usize);
        assert_eq!(lookup.get_app_info, assembled.lookup as usize);
        assert_eq!(lookup.cache_offset, 0x13d8);
        assert!(lookup.engine_slot.is_some());
        assert_eq!(
            lookup.tree,
            TreeLayout {
                root: 0x28,
                nodes: 0x40,
                stride: 0x20,
                key: 0x10,
                value: 0x18,
            }
        );
        assert_eq!(lookup.unknown_flag, 0x14);
    }

    #[test]
    fn decodes_the_i686_lookup() {
        let assembled = current32();
        let lookup = decode(
            32,
            BASE as usize,
            &assembled.code,
            assembled.remove as usize,
        )
        .expect("lookup decodes");
        assert_eq!(lookup.rebuild, assembled.rebuild as usize);
        assert_eq!(lookup.get_app_info, assembled.lookup as usize);
        assert_eq!(lookup.cache_offset, 0xf28);
        assert_eq!(lookup.engine_slot, None);
        assert_eq!(
            lookup.tree,
            TreeLayout {
                root: 0x1c,
                nodes: 0x30,
                stride: 0x18,
                key: 0x10,
                value: 0x14,
            }
        );
        assert_eq!(lookup.unknown_flag, 0x10);
    }

    #[test]
    fn ignores_stack_arithmetic_next_to_the_cache_operand() {
        let mut a = CodeAssembler::new(64).unwrap();
        a.lea(rbx, qword_ptr(rax + 0x13d8)).unwrap();
        a.lea(rsi, qword_ptr(rsp + 0x120)).unwrap();
        a.add(rsp, 0x200).unwrap();
        let code = a.assemble(BASE).unwrap();
        let lookback: Vec<_> = Decoder::with_ip(64, &code, BASE, DecoderOptions::NONE)
            .into_iter()
            .collect();
        assert_eq!(cache_offset(&lookback), Some(0x13d8));
    }

    #[test]
    fn rejects_a_cache_operand_outside_the_engine_member_range() {
        let assembled = current64(0x40);
        assert!(decode(
            64,
            BASE as usize,
            &assembled.code,
            assembled.remove as usize
        )
        .is_err());
    }
}
