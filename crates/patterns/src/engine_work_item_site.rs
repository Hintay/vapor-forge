#![forbid(unsafe_code)]

//! Discovery of Steam's next-frame `CSteamEngine` work-item queue.
//!
//! The queue producer is an inlined template, so there is no callable enqueue
//! wrapper. Steam emits many copies of the same producer. The decoder admits a
//! layout only when at least two copies independently identify the same engine
//! global, mutex, vector fields, item ABI, and typed vector-grow function.

use std::collections::{HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

const FORWARD_WINDOW: usize = 0x180;
const BACKWARD_WINDOW: usize = 0x90;
const PIC_LOOKBACK: usize = 0x100;
const MIN_ENGINE_FIELD: usize = 0x100;
const MAX_ENGINE_FIELD: usize = 0x10000;
const MIN_AGREEING_PRODUCERS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EngineWorkItemSite {
    /// Pointer slot holding the process-lifetime `CSteamEngine` instance.
    pub engine_slot: usize,
    pub mutex_offset: usize,
    pub queue_offset: usize,
    /// `CUtlMemory<void *>::Grow(int)` used by the queue itself.
    pub grow: usize,
    /// Native allocation entry called by the queue producer.
    pub allocate: usize,
    pub item_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveredEngineWorkItemSite {
    pub site: EngineWorkItemSite,
    pub agreeing_producers: usize,
}

pub fn discover(
    bitness: u32,
    code_base: usize,
    code: &[u8],
) -> Result<DiscoveredEngineWorkItemSite, &'static str> {
    let anchor = match bitness {
        32 => &b"\xc7\x04\x24\x14\x00\x00\x00"[..],
        64 => &b"\xbf\x28\x00\x00\x00"[..],
        _ => return Err("unsupported pointer width"),
    };
    let mut layouts: HashMap<EngineWorkItemSite, usize> = HashMap::new();
    let mut cursor = 0usize;
    while let Some(relative) = find_bytes(&code[cursor..], anchor) {
        let offset = cursor + relative;
        if let Some(site) = decode_producer(bitness, code_base, code, offset) {
            *layouts.entry(site).or_default() += 1;
        }
        cursor = offset.saturating_add(1);
    }

    let mut admitted = layouts
        .into_iter()
        .filter(|(_, count)| *count >= MIN_AGREEING_PRODUCERS);
    let Some((site, agreeing_producers)) = admitted.next() else {
        return Err("no repeated CSteamEngine work-item producer was found");
    };
    if admitted.next().is_some() {
        return Err("CSteamEngine work-item producers disagree on their layout");
    }
    Ok(DiscoveredEngineWorkItemSite {
        site,
        agreeing_producers,
    })
}

fn decode_producer(
    bitness: u32,
    code_base: usize,
    code: &[u8],
    anchor_offset: usize,
) -> Option<EngineWorkItemSite> {
    let pointer_size = bitness as usize / 8;
    let anchor_ip = code_base.checked_add(anchor_offset)?;
    let window = code.get(anchor_offset..)?;
    let window = &window[..window.len().min(FORWARD_WINDOW)];
    let mut decoder = Decoder::with_ip(bitness, window, anchor_ip as u64, DecoderOptions::NONE);
    let mut instruction = Instruction::default();

    decoder.decode_out(&mut instruction);
    if !allocation_size_instruction(&instruction, bitness, pointer_size * 5) {
        return None;
    }
    decoder.decode_out(&mut instruction);
    let allocate = direct_call_target(&instruction)?;

    let item_register = if bitness == 64 {
        Register::RAX
    } else {
        Register::EAX.full_register()
    };
    let mut item_registers = HashSet::from([item_register]);
    let mut has_name = false;
    let mut callable_bytes = HashSet::new();
    let mut field_accesses: HashMap<(Register, usize), HashSet<usize>> = HashMap::new();
    let mut expressions: HashMap<Register, (Register, usize)> = HashMap::new();
    let mut queued_calls = Vec::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            break;
        }

        if instruction.op0_kind() == OpKind::Memory
            && instruction.memory_index() == Register::None
            && item_registers.contains(&instruction.memory_base().full_register())
        {
            let offset = usize::try_from(instruction.memory_displacement64()).ok()?;
            let width = instruction.memory_size().size();
            if offset == 0 && width == pointer_size {
                has_name = true;
            }
            let callable_start = pointer_size * 3;
            let callable_end = pointer_size * 5;
            for byte in offset.max(callable_start)..offset.saturating_add(width).min(callable_end) {
                callable_bytes.insert(byte);
            }
        }

        if instruction.op0_kind() == OpKind::Memory || instruction.op1_kind() == OpKind::Memory {
            let base = instruction.memory_base().full_register();
            if base.is_gpr() && instruction.memory_index() == Register::None {
                if let Ok(offset) = usize::try_from(instruction.memory_displacement64()) {
                    if (MIN_ENGINE_FIELD..MAX_ENGINE_FIELD).contains(&offset) {
                        field_accesses
                            .entry((base, offset))
                            .or_default()
                            .insert(instruction.memory_size().size());
                    }
                }
            }
        }

        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.memory_index() == Register::None
            && instruction.memory_base().is_gpr()
        {
            if let Ok(offset) = usize::try_from(instruction.memory_displacement64()) {
                expressions.insert(
                    instruction.op0_register().full_register(),
                    (instruction.memory_base().full_register(), offset),
                );
            }
        }
        if bitness == 32
            && instruction.mnemonic() == Mnemonic::Push
            && instruction.op0_kind() == OpKind::Register
        {
            if let Some(expression) = expressions.get(&instruction.op0_register().full_register()) {
                expressions.insert(Register::RSP, *expression);
            }
        }
        if let Some(target) = direct_call_target(&instruction) {
            let argument = if bitness == 64 {
                expressions.get(&Register::RDI).copied()
            } else {
                expressions.get(&Register::RSP).copied()
            };
            if let Some((base, offset)) = argument {
                queued_calls.push((base, offset, target));
            }
            if bitness == 32 {
                expressions.remove(&Register::RSP);
            }
        }

        let copies_item = instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && item_registers.contains(&instruction.op1_register().full_register());
        if instruction.op0_kind() == OpKind::Register {
            let destination = instruction.op0_register().full_register();
            if !copies_item {
                item_registers.remove(&destination);
            }
            if instruction.mnemonic() != Mnemonic::Lea {
                expressions.remove(&destination);
            }
            if copies_item {
                item_registers.insert(destination);
            }
        }
    }

    if !has_name || callable_bytes.len() != pointer_size * 2 {
        return None;
    }

    let allocation_delta = pointer_size;
    let count_delta = if bitness == 64 {
        pointer_size * 2
    } else {
        pointer_size * 3
    };
    let mut queues = Vec::new();
    for &(base, offset) in field_accesses.keys() {
        let pointer = field_accesses
            .get(&(base, offset))
            .is_some_and(|widths| widths.contains(&pointer_size));
        let allocation = field_accesses
            .get(&(base, offset + allocation_delta))
            .is_some_and(|widths| widths.contains(&4));
        let count = field_accesses
            .get(&(base, offset + count_delta))
            .is_some_and(|widths| widths.contains(&4));
        if pointer && allocation && count {
            queues.push((base, offset));
        }
    }
    queues.sort_unstable_by_key(|(base, offset)| (base.number(), *offset));
    queues.dedup();
    let [(engine_register, queue_offset)] = queues[..] else {
        return None;
    };
    let grow = queued_calls
        .iter()
        .find(|(base, offset, _)| *base == engine_register && *offset == queue_offset)
        .map(|(_, _, target)| *target)?;
    let (engine_slot, mutex_offset) = decode_producer_prefix(
        bitness,
        code_base,
        code,
        anchor_offset,
        engine_register,
        queue_offset,
    )?;

    Some(EngineWorkItemSite {
        engine_slot,
        mutex_offset,
        queue_offset,
        grow,
        allocate,
        item_size: pointer_size * 5,
    })
}

fn decode_producer_prefix(
    bitness: u32,
    code_base: usize,
    code: &[u8],
    anchor_offset: usize,
    engine_register: Register,
    queue_offset: usize,
) -> Option<(usize, usize)> {
    let pic = if bitness == 32 {
        Some(find_pic_anchor(code_base, code, anchor_offset)?)
    } else {
        None
    };
    let start = anchor_offset.saturating_sub(BACKWARD_WINDOW);
    let anchor_ip = code_base.checked_add(anchor_offset)?;
    let mut results = HashSet::new();

    for candidate_start in start..anchor_offset {
        let bytes = code.get(candidate_start..anchor_offset)?;
        let candidate_ip = code_base.checked_add(candidate_start)?;
        let mut decoder =
            Decoder::with_ip(bitness, bytes, candidate_ip as u64, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut engine_slot = None;
        let mut recent_leas: Vec<(usize, usize)> = Vec::new();
        let mut mutexes = HashSet::new();
        let mut decoded = 0usize;

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                break;
            }
            decoded += 1;
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == engine_register
                && instruction.op1_kind() == OpKind::Memory
                && instruction.memory_index() == Register::None
            {
                engine_slot = resolve_global_memory(&instruction, pic);
            }
            if instruction.mnemonic() == Mnemonic::Lea
                && instruction.memory_base().full_register() == engine_register
                && instruction.memory_index() == Register::None
            {
                if let Ok(offset) = usize::try_from(instruction.memory_displacement64()) {
                    if (MIN_ENGINE_FIELD..queue_offset).contains(&offset) {
                        recent_leas.push((decoded, offset));
                    }
                }
            }
            if direct_call_target(&instruction).is_some() {
                for &(lea_instruction, offset) in &recent_leas {
                    if decoded.saturating_sub(lea_instruction) <= 3 {
                        mutexes.insert(offset);
                    }
                }
            }
        }
        if decoder.ip() as usize != anchor_ip {
            continue;
        }
        if mutexes.len() != 1 {
            continue;
        }
        let Some(engine_slot) = engine_slot else {
            continue;
        };
        let mutex_offset = *mutexes.iter().next()?;
        results.insert((engine_slot, mutex_offset));
    }
    if results.len() != 1 {
        return None;
    }
    results.into_iter().next()
}

fn allocation_size_instruction(instruction: &Instruction, bitness: u32, expected: usize) -> bool {
    if instruction.mnemonic() != Mnemonic::Mov {
        return false;
    }
    let value = match instruction.op1_kind() {
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64 => {
            usize::try_from(instruction.immediate(1)).ok()
        }
        _ => None,
    };
    if value != Some(expected) {
        return false;
    }
    if bitness == 64 {
        instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == Register::RDI
    } else {
        instruction.op0_kind() == OpKind::Memory
            && instruction.memory_base().full_register() == Register::RSP
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() == 0
    }
}

fn direct_call_target(instruction: &Instruction) -> Option<usize> {
    if instruction.mnemonic() != Mnemonic::Call {
        return None;
    }
    match instruction.op0_kind() {
        OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instruction.near_branch_target() as usize)
        }
        _ => None,
    }
}

fn resolve_global_memory(
    instruction: &Instruction,
    pic: Option<(Register, usize)>,
) -> Option<usize> {
    if instruction.is_ip_rel_memory_operand() {
        return Some(instruction.ip_rel_memory_address() as usize);
    }
    let (pic_register, anchor) = pic?;
    if instruction.memory_base() != pic_register || instruction.memory_index() != Register::None {
        return None;
    }
    Some(add_x86_displacement(
        anchor,
        instruction.memory_displacement32() as i32,
    ))
}

fn find_pic_anchor(code_base: usize, code: &[u8], site_offset: usize) -> Option<(Register, usize)> {
    let start = site_offset.saturating_sub(PIC_LOOKBACK);
    for call_offset in (start..site_offset).rev() {
        if code.get(call_offset) != Some(&0xe8) {
            continue;
        }
        let Some(relative) = read_i32(code, call_offset + 1) else {
            continue;
        };
        let after_call = (code_base as u32)
            .wrapping_add(call_offset as u32)
            .wrapping_add(5);
        let Some(thunk_offset) = (after_call.wrapping_add(relative as u32) as usize)
            .checked_sub(code_base)
            .filter(|offset| *offset < code.len())
        else {
            continue;
        };
        let Some(thunk) = code.get(thunk_offset..thunk_offset + 4) else {
            continue;
        };
        if thunk[0] != 0x8b || thunk[1] & 0xc7 != 0x04 || thunk[2] != 0x24 || thunk[3] != 0xc3 {
            continue;
        }
        let register_code = (thunk[1] >> 3) & 7;
        let add_offset = call_offset + 5;
        let immediate = if register_code == 0 && code.get(add_offset) == Some(&0x05) {
            let Some(value) = read_u32(code, add_offset + 1) else {
                continue;
            };
            value
        } else if code.get(add_offset) == Some(&0x81)
            && code.get(add_offset + 1) == Some(&(0xc0 | register_code))
        {
            let Some(value) = read_u32(code, add_offset + 2) else {
                continue;
            };
            value
        } else {
            continue;
        };
        return Some((
            x86_register(register_code)?,
            after_call.wrapping_add(immediate) as usize,
        ));
    }
    None
}

fn x86_register(code: u8) -> Option<Register> {
    [
        Register::EAX,
        Register::ECX,
        Register::EDX,
        Register::EBX,
        Register::ESP,
        Register::EBP,
        Register::ESI,
        Register::EDI,
    ]
    .get(code as usize)
    .copied()
}

fn add_x86_displacement(address: usize, displacement: i32) -> usize {
    (address as u32).wrapping_add(displacement as u32) as usize
}

fn read_u32(code: &[u8], offset: usize) -> Option<u32> {
    code.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i32(code: &[u8], offset: usize) -> Option<i32> {
    read_u32(code, offset).map(|value| value as i32)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let mut cursor = 0usize;
    while let Some(relative) = memchr::memchr(first, haystack.get(cursor..)?) {
        let offset = cursor + relative;
        if haystack.get(offset..offset + needle.len()) == Some(needle) {
            return Some(offset);
        }
        cursor = offset.saturating_add(1);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: usize = 0x1000;
    const ALLOCATE: usize = 0x1700;
    const GROW: usize = 0x1710;

    fn call(bytes: &mut Vec<u8>, start: usize, target: usize) {
        let next = BASE + start + bytes.len() + 5;
        bytes.push(0xe8);
        bytes.extend_from_slice(&((target as i64 - next as i64) as i32).to_le_bytes());
    }

    fn producer(bitness: u32, start: usize, allocate: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        if bitness == 64 {
            bytes.extend_from_slice(b"\x48\x8b\x2d");
            bytes.extend_from_slice(&((0x9000 - (BASE + start + 7)) as u32).to_le_bytes());
            bytes.extend_from_slice(b"\x48\x8d\x9d\xd0\x21\0\0\x48\x89\xdf");
            call(&mut bytes, start, 0x1720);
            bytes.extend_from_slice(b"\xbf\x28\0\0\0");
            call(&mut bytes, start, allocate);
            bytes.extend_from_slice(b"\x48\x89\x30\x48\x89\x50\x18\x48\x89\x48\x20");
            bytes.extend_from_slice(b"\x48\x63\xb5\x10\x22\0\0");
            bytes.extend_from_slice(b"\x48\x8b\x8d\0\x22\0\0\x3b\xb5\x08\x22\0\0");
            bytes.extend_from_slice(b"\x48\x8d\xbd\0\x22\0\0");
        } else {
            call(&mut bytes, start, BASE + 0x700);
            bytes.extend_from_slice(b"\x81\xc3");
            bytes.extend_from_slice(&((0xa000 - (BASE + start + 5)) as u32).to_le_bytes());
            bytes.extend_from_slice(b"\x8b\xb3\0\xf0\xff\xff");
            bytes.extend_from_slice(b"\x8d\xbe\xd8\x1a\0\0\x57");
            call(&mut bytes, start, 0x1720);
            bytes.extend_from_slice(b"\xc7\x04\x24\x14\0\0\0");
            call(&mut bytes, start, allocate);
            bytes.extend_from_slice(b"\x89\x10\x89\x48\x0c\x89\x78\x10");
            bytes.extend_from_slice(b"\x8b\x8e\xf4\x1a\0\0\x8b\x96\xf8\x1a\0\0");
            bytes.extend_from_slice(b"\x8b\xae\0\x1b\0\0\x8d\xbe\xf4\x1a\0\0\x57");
        }
        call(&mut bytes, start, GROW);
        bytes.push(0xc3);
        bytes
    }

    fn image(bitness: u32, second_allocator: usize) -> Vec<u8> {
        let mut code = vec![0xcc; 0x800];
        for (start, allocate) in [(0x40, ALLOCATE), (0x240, second_allocator)] {
            let bytes = producer(bitness, start, allocate);
            code[start..start + bytes.len()].copy_from_slice(&bytes);
        }
        code[0x700..0x704].copy_from_slice(b"\x8b\x1c\x24\xc3");
        code
    }

    #[test]
    fn identifies_native_allocator_and_queue_on_both_architectures() {
        for bitness in [64, 32] {
            let found = discover(bitness, BASE, &image(bitness, ALLOCATE)).unwrap();
            assert_eq!(found.agreeing_producers, 2);
            assert_eq!(found.site.allocate, ALLOCATE);
            assert_eq!(found.site.grow, GROW);
            assert_eq!(found.site.engine_slot, 0x9000);
            assert_eq!(found.site.item_size, bitness as usize / 8 * 5);
            assert_eq!(
                found.site.mutex_offset,
                if bitness == 64 { 0x21d0 } else { 0x1ad8 }
            );
            assert_eq!(
                found.site.queue_offset,
                if bitness == 64 { 0x2200 } else { 0x1af4 }
            );
        }
    }

    #[test]
    fn rejects_producers_that_disagree_on_allocator_ownership() {
        for bitness in [64, 32] {
            assert!(discover(bitness, BASE, &image(bitness, ALLOCATE + 0x30)).is_err());
        }
    }

    #[test]
    fn rejects_a_single_producer_and_truncated_allocation_call() {
        for bitness in [64, 32] {
            let code = image(bitness, ALLOCATE);
            assert!(discover(bitness, BASE, &code[..0x200]).is_err());
            let anchor = if bitness == 64 {
                &b"\xbf\x28\0\0\0"[..]
            } else {
                &b"\xc7\x04\x24\x14\0\0\0"[..]
            };
            let mut code = code;
            for start in [0x40, 0x240] {
                let call = start + find_bytes(&code[start..], anchor).unwrap() + anchor.len();
                code[call] = 0x90;
            }
            assert!(discover(bitness, BASE, &code).is_err());
        }
    }
}
