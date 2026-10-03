#![forbid(unsafe_code)]

//! Runtime decode of Steam's own bare-`CWorkItem` post site.
//!
//! `CWebSocketConnection::PostDelayedCloseWorkItem` is the shortest place where
//! Steam allocates a plain `CWorkItem`, fills it in, and hands it to
//! `CWorkThreadPool::AddWorkItem`. Native injection needs the same three
//! build-specific values that site loads, so they are read back from it instead
//! of being pinned to an RVA:
//!
//! * the pointer slot holding the CNet `CWorkThreadPool`, which is the pool that
//!   owns the threads Steam's own network work runs on;
//! * the `CFastTimerCumulativeTimer` vtable, which every work item's embedded
//!   profiling sub-objects point at (their vptrs are normally written by the C++
//!   constructor, and a hand-built item has to write them itself);
//! * the item's allocation size and the non-zero fields its constructor sets,
//!   which is everything a zeroed buffer still needs before Steam sees it.
//!
//! Every value is fail-closed: a decode that does not produce all of them leaves
//! native dispatch disabled rather than posting a half-formed item.
//!
//! Kept out of `client` so it compiles, and is tested, on non-Linux hosts too.

use std::collections::{HashMap, HashSet};

use iced_x86::{
    Decoder, DecoderOptions, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};

/// Bytes decoded forward from the match. Steam's constructor ends well inside
/// this; the surplus only ever adds candidates that the checks below reject.
const WINDOW: usize = 0x200;
/// Bytes searched backwards for the i686 PIC anchor. The `get_pc_thunk` call
/// sits in the prologue, a few instructions before any pattern can match.
const PIC_LOOKBACK: usize = 0x100;
const MIN_ITEM_SIZE: usize = 0x40;
const MAX_ITEM_SIZE: usize = 0x1000;
/// Steam's work item embeds four cumulative timers. Requiring most of them
/// separates the timer vtable from the item's own vtable, which is stored once.
const MIN_TIMER_VPTRS: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkItemSite {
    /// Pointer slot holding the CNet `CWorkThreadPool`. Dereferenced at post
    /// time, not here: the pool is published after this decode runs.
    pub(crate) pool_slot: usize,
    /// `CFastTimerCumulativeTimer` vtable shared by the item's embedded timers.
    pub(crate) timer_vtable: usize,
    /// Bytes Steam allocates for one item.
    pub(crate) item_size: usize,
    /// Offsets the timer vtable is written to, ascending.
    pub(crate) timer_vptr_offsets: Vec<usize>,
    /// The refcount, the one field the constructor initialises to 1. A caller
    /// reference is owned until the item's completion callback releases it.
    pub(crate) refcount_offset: usize,
    /// Offsets and widths, at most 8, of the "no value" sentinels set to -1.
    pub(crate) sentinel_offsets: Vec<(usize, usize)>,
    /// `CWorkThreadPool::AddWorkItem`, taken from this site's own call. Compared
    /// against the pattern-resolved address so a mis-scan of either is caught.
    pub(crate) add_work_item: usize,
}

pub(crate) fn decode(
    bitness: u32,
    code_base: usize,
    code: &[u8],
    site: usize,
) -> Result<WorkItemSite, &'static str> {
    let pointer_size = bitness as usize / 8;
    let offset = site
        .checked_sub(code_base)
        .ok_or("site precedes the code region")?;
    let window = code.get(offset..).ok_or("site is past the code region")?;
    let window = &window[..window.len().min(WINDOW)];
    let pic = if bitness == 32 {
        Some(find_pic_anchor(code_base, code, offset).ok_or("no i686 PIC anchor before the site")?)
    } else {
        None
    };

    let mut decoder = Decoder::with_ip(bitness, window, site as u64, DecoderOptions::NONE);
    let mut factory = InstructionInfoFactory::new();
    let mut instruction = Instruction::default();
    // Resolved absolute addresses currently held in registers.
    let mut tracked: HashMap<Register, usize> = HashMap::new();
    // Per resolved address: the item offsets it was stored at, and the last
    // store's address. Keyed by value so a reused register stays separated.
    let mut stores: HashMap<usize, (Vec<usize>, usize)> = HashMap::new();
    let mut calls: Vec<(usize, usize)> = Vec::new();
    // Registers holding the freshly allocated item, seeded with the allocator's
    // return register and extended through plain register copies.
    let mut item_registers: HashSet<Register> = HashSet::new();
    let mut ones: Vec<usize> = Vec::new();
    let mut sentinels: Vec<(usize, usize)> = Vec::new();
    let mut pool_slot = None;
    let mut last_immediate = None;
    let mut item_size = None;

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            break;
        }
        let ip = instruction.ip() as usize;

        if instruction.mnemonic() == Mnemonic::Call {
            if instruction.op0_kind() == OpKind::NearBranch64
                || instruction.op0_kind() == OpKind::NearBranch32
            {
                calls.push((ip, instruction.near_branch_target() as usize));
            }
            // The allocator call is the first one whose in-flight argument is a
            // plausible item size. Some builds load the pool global only after
            // this call, so a preceding lea does not mark it; the size does.
            if item_size.is_none()
                && last_immediate
                    .is_some_and(|size| (MIN_ITEM_SIZE..=MAX_ITEM_SIZE).contains(&size))
            {
                item_size = last_immediate;
                item_registers.clear();
                item_registers.insert(return_register(bitness));
            }
            // Caller-saved registers do not survive; used_registers does not
            // model the ABI clobbers, so drop everything.
            tracked.clear();
            continue;
        }

        if instruction.mnemonic() == Mnemonic::Lea {
            if let Some(address) = resolve_lea(&instruction, pic) {
                tracked.insert(instruction.op0_register().full_register(), address);
                continue;
            }
        }

        if let Some(value) = immediate(&instruction) {
            last_immediate = Some(value);
        }
        if pool_slot.is_none() {
            if let Some(address) = dereferenced(&instruction, &tracked) {
                pool_slot = Some(address);
            }
        }
        if let Some((address, field)) = stored_pointer(&instruction, &tracked, pointer_size) {
            let entry = stores.entry(address).or_insert_with(|| (Vec::new(), ip));
            entry.0.push(field);
            entry.1 = ip;
        }
        if let Some((field, width, value)) = stored_immediate(&instruction, &item_registers) {
            // The refcount is read back through an AtomicU32, so a wider store
            // would not be the field this code knows how to release.
            if value == 1 && width == 4 {
                ones.push(field);
            } else if value == -1 && width <= 8 {
                sentinels.push((field, width));
            }
        }
        // `mov item_reg, other` propagates the allocation; every other write to a
        // register takes it out of both sets.
        let copies_item = instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && item_registers.contains(&instruction.op1_register().full_register());

        let info = factory.info(&instruction);
        for used in info.used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::ReadWrite
                    | OpAccess::CondWrite
                    | OpAccess::ReadCondWrite
            ) {
                tracked.remove(&used.register().full_register());
                item_registers.remove(&used.register().full_register());
            }
        }
        if copies_item {
            item_registers.insert(instruction.op0_register().full_register());
        }
    }

    let pool_slot = pool_slot.ok_or("no dereferenced pool global at the site")?;
    let item_size = item_size.ok_or("no allocation size at the site")?;
    if !(MIN_ITEM_SIZE..=MAX_ITEM_SIZE).contains(&item_size) || item_size % pointer_size != 0 {
        return Err("implausible work item size");
    }
    let (timer_vtable, (mut timer_vptr_offsets, last_store)) = stores
        .into_iter()
        .filter(|(_, (offsets, _))| offsets.len() >= MIN_TIMER_VPTRS)
        .max_by_key(|(_, (offsets, _))| offsets.len())
        .ok_or("no repeated vtable store at the site")?;
    timer_vptr_offsets.sort_unstable();
    timer_vptr_offsets.dedup();
    if timer_vptr_offsets.len() < MIN_TIMER_VPTRS {
        return Err("no repeated vtable store at the site");
    }
    if timer_vptr_offsets
        .iter()
        .any(|offset| offset + pointer_size > item_size)
    {
        return Err("timer vptr offset is outside the work item");
    }
    // Exactly one field is initialised to 1, and it is the refcount. Anything
    // else means the constructor changed shape and the offset is a guess.
    let [refcount_offset] = ones[..] else {
        return Err("the work item has no single field initialised to 1");
    };
    if refcount_offset % 4 != 0 {
        return Err("the refcount field is not 4-byte aligned");
    }
    sentinels.sort_unstable();
    sentinels.dedup();
    if sentinels
        .iter()
        .chain(std::iter::once(&(refcount_offset, 4)))
        .any(|(offset, width)| offset + width > item_size)
    {
        return Err("an initialised field is outside the work item");
    }
    let add_work_item = calls
        .into_iter()
        .find(|(ip, _)| *ip > last_store)
        .map(|(_, target)| target)
        .ok_or("no enqueue call after the work item is filled in")?;

    Ok(WorkItemSite {
        pool_slot,
        timer_vtable,
        item_size,
        timer_vptr_offsets,
        refcount_offset,
        sentinel_offsets: sentinels,
        add_work_item,
    })
}

/// Where the allocator returns the new item.
fn return_register(bitness: u32) -> Register {
    if bitness == 64 {
        Register::RAX
    } else {
        Register::EAX.full_register()
    }
}

/// `lea reg, [rip + disp32]` on x86_64, or its i686 PIC form `lea reg, [pic + disp32]`.
fn resolve_lea(instruction: &Instruction, pic: Option<(Register, usize)>) -> Option<usize> {
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

/// `mov reg, [tracked]` or `push [tracked]`, the two ways a pointer global is
/// read through its slot. i686 builds that pass the pool on the stack push it
/// straight from the slot.
fn dereferenced(instruction: &Instruction, tracked: &HashMap<Register, usize>) -> Option<usize> {
    let reads_slot = match instruction.mnemonic() {
        Mnemonic::Mov => {
            instruction.op0_kind() == OpKind::Register && instruction.op1_kind() == OpKind::Memory
        }
        Mnemonic::Push => instruction.op0_kind() == OpKind::Memory,
        _ => false,
    };
    if !reads_slot
        || instruction.memory_index() != Register::None
        || instruction.memory_displacement64() != 0
    {
        return None;
    }
    tracked
        .get(&instruction.memory_base().full_register())
        .copied()
}

/// `mov [item + offset], tracked`, the vtable stores the constructor emits.
fn stored_pointer(
    instruction: &Instruction,
    tracked: &HashMap<Register, usize>,
    pointer_size: usize,
) -> Option<(usize, usize)> {
    if instruction.mnemonic() != Mnemonic::Mov
        || instruction.op0_kind() != OpKind::Memory
        || instruction.op1_kind() != OpKind::Register
        || instruction.memory_size().size() != pointer_size
        || instruction.memory_index() != Register::None
        || !instruction.memory_base().is_gpr()
    {
        return None;
    }
    let field = usize::try_from(instruction.memory_displacement64()).ok()?;
    if field >= MAX_ITEM_SIZE {
        return None;
    }
    let address = tracked.get(&instruction.op1_register().full_register())?;
    Some((*address, field))
}

/// `mov [item + offset], imm`, the constructor's non-zero field initialisers.
/// Returns the offset, the store width, and the sign-extended value.
fn stored_immediate(
    instruction: &Instruction,
    item_registers: &HashSet<Register>,
) -> Option<(usize, usize, i64)> {
    if instruction.mnemonic() != Mnemonic::Mov
        || instruction.op0_kind() != OpKind::Memory
        || instruction.memory_index() != Register::None
        || !item_registers.contains(&instruction.memory_base().full_register())
    {
        return None;
    }
    let width = instruction.memory_size().size();
    let value = match instruction.op1_kind() {
        OpKind::Immediate8 => i64::from(instruction.immediate8()),
        OpKind::Immediate16 => i64::from(instruction.immediate16()),
        OpKind::Immediate32 => i64::from(instruction.immediate32() as i32),
        OpKind::Immediate32to64 => instruction.immediate32to64(),
        _ => return None,
    };
    // A -1 stored as a 4-byte field reads back as 0xffffffff.
    let value = if width == 4 && value == i64::from(u32::MAX) {
        -1
    } else {
        value
    };
    let offset = usize::try_from(instruction.memory_displacement64()).ok()?;
    (offset < MAX_ITEM_SIZE).then_some((offset, width, value))
}

/// The immediate of a `push imm` or a `mov reg, imm`, the two ways the size
/// argument reaches the allocator on either arch.
fn immediate(instruction: &Instruction) -> Option<usize> {
    let operand = match instruction.mnemonic() {
        Mnemonic::Push => 0,
        Mnemonic::Mov if instruction.op0_kind() == OpKind::Register => 1,
        _ => return None,
    };
    match instruction.op_kind(operand) {
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64 => {
            usize::try_from(instruction.immediate(operand)).ok()
        }
        OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => {
            usize::try_from(instruction.immediate(operand) as i64).ok()
        }
        _ => None,
    }
}

/// The i686 `call __x86.get_pc_thunk.<reg>` / `add <reg>, imm32` prologue pair
/// that establishes the GOT-relative base every global reference is taken from.
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
        // mov <reg>, [esp] ; ret
        if thunk[0] != 0x8b || thunk[1] & 0xc7 != 0x04 || thunk[2] != 0x24 || thunk[3] != 0xc3 {
            continue;
        }
        let register_code = (thunk[1] >> 3) & 7;
        let add_offset = call_offset + 5;
        let immediate = if register_code == 0 && code.get(add_offset) == Some(&0x05) {
            read_u32(code, add_offset + 1)?
        } else if code.get(add_offset) == Some(&0x81)
            && code.get(add_offset + 1) == Some(&(0xc0 | register_code))
        {
            read_u32(code, add_offset + 2)?
        } else {
            continue;
        };
        let register = x86_register(register_code)?;
        return Some((register, after_call.wrapping_add(immediate) as usize));
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

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::code_asm::*;
    use iced_x86::{BlockEncoderOptions, Code, MemoryOperand};

    /// Addresses the synthetic sites refer to; only their relations matter.
    const BASE: usize = 0x0200_0000;
    const ALLOCATOR: u64 = 0x0280_0000;
    const ADD_WORK_ITEM: u64 = 0x0280_1000;
    const POOL_SLOT: usize = 0x0300_0040;
    const TIMER_VTABLE: usize = 0x02f0_0100;
    const ITEM_VTABLE: usize = 0x02f0_0800;
    /// The i686 prologue's `add ebx, imm32`; globals are taken relative to the
    /// address it produces.
    const PIC_ADD: i32 = 0x0100_0000;

    struct Site {
        code: Vec<u8>,
        /// Where the decode starts: past the prologue on i686.
        site: usize,
        /// The `AddWorkItem` call.
        enqueue: usize,
    }

    /// What the inlined constructor writes, and so what the decode reads back.
    struct Item {
        size: u32,
        refcount: i32,
        timer_vptrs: [i32; 4],
        /// Offset and width of each field set to -1.
        sentinels: &'static [(i32, usize)],
    }

    const X86_ITEM: Item = Item {
        size: 0xa4,
        refcount: 0x04,
        timer_vptrs: [0x24, 0x3c, 0x54, 0x6c],
        sentinels: &[(0x84, 4), (0x88, 4), (0x98, 4)],
    };
    const X64_ITEM: Item = Item {
        size: 0xd8,
        refcount: 0x08,
        timer_vptrs: [0x30, 0x50, 0x70, 0x90],
        sentinels: &[(0xb0, 8), (0xc8, 4)],
    };
    const X64_LARGER_ITEM: Item = Item {
        size: 0xe8,
        refcount: 0x08,
        timer_vptrs: [0x40, 0x60, 0x80, 0xa0],
        sentinels: &[(0xc0, 8), (0xd8, 4)],
    };

    impl Item {
        fn decoded(&self) -> WorkItemSite {
            WorkItemSite {
                pool_slot: POOL_SLOT,
                timer_vtable: TIMER_VTABLE,
                item_size: self.size as usize,
                timer_vptr_offsets: self.timer_vptrs.map(|offset| offset as usize).to_vec(),
                refcount_offset: self.refcount as usize,
                sentinel_offsets: self
                    .sentinels
                    .iter()
                    .map(|&(offset, width)| (offset as usize, width))
                    .collect(),
                add_work_item: ADD_WORK_ITEM as usize,
            }
        }

        /// Fields after the sentinels: a copied value and a non-sentinel constant.
        fn tail(&self) -> [i32; 2] {
            [self.size as i32 - 0x0c, self.size as i32 - 0x08]
        }
    }

    /// Assemble at `BASE` and return the code with the address of each label.
    fn assemble<const N: usize>(
        bitness: u32,
        build: impl FnOnce(&mut CodeAssembler, &mut [CodeLabel; N]) -> Result<(), IcedError>,
    ) -> (Vec<u8>, [usize; N]) {
        let mut a = CodeAssembler::new(bitness).unwrap();
        let mut labels = [(); N].map(|()| a.create_label());
        build(&mut a, &mut labels).unwrap();
        let result = a
            .assemble_options(
                BASE as u64,
                BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
            )
            .unwrap();
        let ips = labels.map(|label| result.label_ip(&label).unwrap() as usize);
        (result.inner.code_buffer, ips)
    }

    /// `lea reg, [rip + target]` for an absolute target outside the code.
    fn lea_rip(
        a: &mut CodeAssembler,
        register: AsmRegister64,
        target: usize,
    ) -> Result<(), IcedError> {
        a.add_instruction(Instruction::with2(
            Code::Lea_r64_m,
            Register::from(register),
            MemoryOperand::with_base_displ(Register::RIP, target as i64),
        )?)
    }

    /// i686 PIC: a `get_pc_thunk` call in the prologue, the pool passed on the
    /// stack, and the item kept in the allocator's return register throughout.
    fn x86_site() -> Site {
        let item = &X86_ITEM;
        // Globals are addressed from the anchor, which is only known once the
        // prologue is laid out. Every displacement is a full imm32 on both
        // passes, so the layout does not move between them.
        let layout = |anchor: usize| {
            let from_anchor = |address: usize| address.wrapping_sub(anchor) as i32;
            assemble(32, |a, [after_thunk, site, enqueue]| {
                // `__x86.get_pc_thunk.bx`, placed ahead of the function so a
                // truncated body still reaches it.
                let mut thunk = a.create_label();
                let mut exit = a.create_label();
                a.set_label(&mut thunk)?;
                a.mov(ebx, dword_ptr(esp))?;
                a.ret()?;
                a.push(edi)?;
                a.push(esi)?;
                a.push(ebx)?;
                a.mov(esi, dword_ptr(esp + 0x10))?;
                a.call(thunk)?;
                a.set_label(after_thunk)?;
                a.add(ebx, PIC_ADD)?;
                a.set_label(site)?;
                a.cmp(dword_ptr(esi + 0x10), 2)?;
                a.jne(exit)?;
                a.lea(eax, ptr(ebx + from_anchor(POOL_SLOT)))?;
                a.sub(esp, 0x0c)?;
                a.mov(edi, dword_ptr(eax))?;
                a.push(item.size as i32)?;
                a.call(ALLOCATOR)?;
                a.mov(ecx, dword_ptr(esi + 0x0c))?;
                a.lea(edx, ptr(ebx + from_anchor(TIMER_VTABLE)))?;
                for offset in item.timer_vptrs {
                    a.mov(dword_ptr(eax + offset), edx)?;
                }
                a.mov(dword_ptr(eax + item.refcount), 1)?;
                a.mov(dword_ptr(eax + 0x08), 0)?;
                for &(offset, _) in item.sentinels {
                    a.mov(dword_ptr(eax + offset), -1)?;
                }
                a.lea(edx, ptr(ebx + from_anchor(ITEM_VTABLE)))?;
                a.mov(dword_ptr(eax), edx)?;
                let [copied, constant] = item.tail();
                a.mov(dword_ptr(eax + copied), ecx)?;
                a.mov(dword_ptr(eax + constant), 1000)?;
                a.pop(ecx)?;
                a.pop(esi)?;
                a.push(eax)?;
                a.push(edi)?;
                a.set_label(enqueue)?;
                a.call(ADD_WORK_ITEM)?;
                a.add(esp, 0x10)?;
                a.mov(eax, 1)?;
                a.set_label(&mut exit)?;
                a.pop(ebx)?;
                a.pop(esi)?;
                a.pop(edi)?;
                a.ret()
            })
        };
        let (_, [after_thunk, ..]) = layout(0);
        let (code, [_, site, enqueue]) = layout(after_thunk.wrapping_add(PIC_ADD as usize));
        Site {
            code,
            site,
            enqueue,
        }
    }

    /// x86_64 with the pool global read before the allocation and parked in a
    /// callee-saved register, entered at the pattern match.
    fn x64_site_pool_first() -> Site {
        let item = &X64_ITEM;
        let (code, [site, enqueue]) = assemble(64, |a, [site, enqueue]| {
            let mut exit = a.create_label();
            a.set_label(site)?;
            a.cmp(dword_ptr(rdi + 0x18), 2)?;
            a.jne(exit)?;
            lea_rip(a, rax, POOL_SLOT)?;
            a.mov(edi, item.size)?;
            a.mov(rbp, qword_ptr(rax))?;
            a.call(ALLOCATOR)?;
            x64_constructor(a, item)?;
            a.mov(rdi, rbp)?;
            a.set_label(enqueue)?;
            a.call(ADD_WORK_ITEM)?;
            a.mov(eax, 1)?;
            a.set_label(&mut exit)?;
            a.ret()
        });
        Site {
            code,
            site,
            enqueue,
        }
    }

    /// x86_64 that reads the pool global only after filling the item in, so no
    /// global load precedes the allocation size; entered at the function start.
    fn x64_site_pool_last() -> Site {
        let item = &X64_LARGER_ITEM;
        let (code, [site, enqueue]) = assemble(64, |a, [site, enqueue]| {
            let mut exit = a.create_label();
            a.set_label(site)?;
            a.push(rbx)?;
            a.cmp(dword_ptr(rdi + 0x10), 2)?;
            a.mov(rbx, rdi)?;
            a.jne(exit)?;
            a.mov(edi, item.size)?;
            a.call(ALLOCATOR)?;
            x64_constructor(a, item)?;
            lea_rip(a, rax, POOL_SLOT)?;
            a.mov(rdi, qword_ptr(rax))?;
            a.set_label(enqueue)?;
            a.call(ADD_WORK_ITEM)?;
            a.mov(eax, 1)?;
            a.set_label(&mut exit)?;
            a.pop(rbx)?;
            a.ret()
        });
        Site {
            code,
            site,
            enqueue,
        }
    }

    /// The inlined constructor: the item moves from rax to rsi, and rax is then
    /// reused for both vtables.
    fn x64_constructor(a: &mut CodeAssembler, item: &Item) -> Result<(), IcedError> {
        a.mov(edx, dword_ptr(rbx + 0x14))?;
        a.mov(rsi, rax)?;
        a.mov(dword_ptr(rax + item.refcount), 1)?;
        a.mov(qword_ptr(rax + 0x10), 0)?;
        a.xor(eax, eax)?;
        a.mov(word_ptr(rsi + 0x22), ax)?;
        lea_rip(a, rax, TIMER_VTABLE)?;
        for offset in item.timer_vptrs {
            a.mov(qword_ptr(rsi + offset), rax)?;
        }
        lea_rip(a, rax, ITEM_VTABLE)?;
        a.mov(qword_ptr(rsi), rax)?;
        for &(offset, width) in item.sentinels {
            match width {
                8 => a.mov(qword_ptr(rsi + offset), -1)?,
                _ => a.mov(dword_ptr(rsi + offset), -1)?,
            }
        }
        let [copied, constant] = item.tail();
        a.mov(dword_ptr(rsi + copied), edx)?;
        a.mov(dword_ptr(rsi + constant), 1000)
    }

    #[test]
    fn decodes_the_i686_site() {
        let site = x86_site();
        assert_eq!(
            decode(32, BASE, &site.code, site.site),
            Ok(X86_ITEM.decoded())
        );
    }

    #[test]
    fn decodes_the_x86_64_site() {
        let site = x64_site_pool_first();
        assert_eq!(
            decode(64, BASE, &site.code, site.site),
            Ok(X64_ITEM.decoded())
        );
    }

    #[test]
    fn decodes_the_x86_64_site_with_the_pool_load_after_the_allocation() {
        let site = x64_site_pool_last();
        assert_eq!(
            decode(64, BASE, &site.code, site.site),
            Ok(X64_LARGER_ITEM.decoded())
        );
    }

    #[test]
    fn a_truncated_site_fails_closed() {
        for (bitness, site) in [(32, x86_site()), (64, x64_site_pool_first())] {
            let cut = &site.code[..site.enqueue - BASE];
            assert_eq!(
                decode(bitness, BASE, cut, site.site),
                Err("no enqueue call after the work item is filled in")
            );
        }
    }

    #[test]
    fn a_site_outside_the_code_region_fails_closed() {
        let site = x64_site_pool_first();
        let end = BASE + site.code.len();
        assert!(decode(64, BASE, &site.code, BASE - 1).is_err());
        assert!(decode(64, BASE, &site.code, end).is_err());
    }

    #[test]
    fn an_i686_site_without_a_pic_prologue_fails_closed() {
        // Starting at the site itself puts the get_pc_thunk call out of reach,
        // which is the shape a moved prologue would present.
        let site = x86_site();
        let body = &site.code[site.site - BASE..];
        assert_eq!(
            decode(32, site.site, body, site.site),
            Err("no i686 PIC anchor before the site")
        );
    }
}
