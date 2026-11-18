//! Steam's lookup of the AppID behind the IPC call being dispatched.
//!
//! `CUserStats::IndicateAchievementProgress` falls back to the calling pipe's
//! AppID when it is given no game ID. That path loads the global
//! `CSteamEngine` pointer and calls a helper which reads the current
//! `HSteamPipe` from the engine and looks it up in the engine's pipe-to-AppID
//! tree. The runtime and the offline scan share this resolver so both accept
//! the same call site and helper.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, MemorySize, Mnemonic, OpKind, Register,
};

/// The call site can sit on a cold branch far from the adapter entry.
const ADAPTER_SCAN: usize = 0x1000;
const HELPER_SCAN: usize = 0x60;
/// Instructions allowed between the slot address and the engine load; the
/// compiler interleaves argument spills there.
const SLOT_LOAD_LOOKAHEAD: usize = 8;

/// `node->key` and `node->value` of the pipe-to-AppID tree.
const NODE_KEY: u64 = 0x10;
const NODE_VALUE: u64 = 0x14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentAppSite {
    /// Address of the global `CSteamEngine *`.
    pub engine_slot: u64,
    /// Offset of the lookup helper in `code`.
    pub helper: usize,
}

/// Resolve the engine slot and lookup helper used by the adapter at
/// `adapter_offset`. Exactly one validated site must exist.
pub fn resolve(
    code: &[u8],
    text_vaddr: u64,
    adapter_offset: usize,
    bitness: u32,
) -> Option<CurrentAppSite> {
    let instructions = decode(code, text_vaddr, adapter_offset, ADAPTER_SCAN, bitness)?;
    let mut sites = match bitness {
        64 => sites64(&instructions),
        32 => sites32(code, text_vaddr, &instructions),
        _ => return None,
    }
    .into_iter()
    .filter_map(|(engine_slot, helper_va)| {
        let helper = usize::try_from(helper_va.checked_sub(text_vaddr)?).ok()?;
        validate_helper(code, text_vaddr, helper, bitness).then_some(CurrentAppSite {
            engine_slot,
            helper,
        })
    })
    .collect::<Vec<_>>();
    sites.sort_unstable_by_key(|site| (site.engine_slot, site.helper));
    sites.dedup();
    match sites.as_slice() {
        [site] => Some(*site),
        _ => None,
    }
}

fn decode(
    code: &[u8],
    text_vaddr: u64,
    offset: usize,
    len: usize,
    bitness: u32,
) -> Option<Vec<Instruction>> {
    let end = code.len().min(offset.checked_add(len)?);
    let bytes = code.get(offset..end)?;
    let ip = text_vaddr.checked_add(offset as u64)?;
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }
    Some(instructions)
}

fn near_call_target(instruction: &Instruction) -> Option<u64> {
    (instruction.mnemonic() == Mnemonic::Call
        && matches!(
            instruction.op0_kind(),
            OpKind::NearBranch32 | OpKind::NearBranch64
        ))
    .then(|| instruction.near_branch_target())
}

/// `lea reg, [rip+slot]`, then `mov rdi, [reg]; call helper` within a few
/// instructions, or the same load as a single `mov rdi, [rip+slot]`.
fn sites64(instructions: &[Instruction]) -> Vec<(u64, u64)> {
    let loads_engine = |instruction: &Instruction, base: Register| {
        instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::RDI
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_size() == MemorySize::UInt64
            && instruction.memory_base() == base
            && instruction.memory_index() == Register::None
    };
    let mut sites = Vec::new();
    for (index, instruction) in instructions.iter().enumerate() {
        if loads_engine(instruction, Register::RIP) {
            if let Some(helper) = instructions.get(index + 1).and_then(near_call_target) {
                sites.push((instruction.ip_rel_memory_address(), helper));
            }
            continue;
        }
        let is_slot_address = instruction.mnemonic() == Mnemonic::Lea
            && instruction.memory_base() == Register::RIP
            && instruction.op0_register().size() == 8;
        if !is_slot_address {
            continue;
        }
        let slot_register = instruction.op0_register();
        let following = instructions
            .iter()
            .enumerate()
            .skip(index + 1)
            .take(SLOT_LOAD_LOOKAHEAD);
        for (load_index, load) in following {
            if loads_engine(load, slot_register) && load.memory_displacement64() == 0 {
                if let Some(helper) = instructions.get(load_index + 1).and_then(near_call_target) {
                    sites.push((instruction.ip_rel_memory_address(), helper));
                }
                break;
            }
            if load.flow_control() != FlowControl::Next || writes_register(load, slot_register) {
                break;
            }
        }
    }
    sites
}

fn writes_register(instruction: &Instruction, register: Register) -> bool {
    instruction.op0_kind() == OpKind::Register
        && instruction.op0_register().full_register() == register.full_register()
}

/// Position-independent i686: `call __x86.get_pc_thunk.bx; add ebx, got`,
/// then `lea reg, [ebx+slot]` and `push dword [reg]` directly before the
/// helper call.
fn sites32(code: &[u8], text_vaddr: u64, instructions: &[Instruction]) -> Vec<(u64, u64)> {
    let mut got = None;
    let mut sites = Vec::new();
    let stack = stack_offsets32(instructions);
    let mut spilled_got = Vec::new();
    for (index, instruction) in instructions.iter().enumerate() {
        let Some(thunk) = near_call_target(instruction) else {
            continue;
        };
        let Some(thunk_offset) = thunk
            .checked_sub(text_vaddr)
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            continue;
        };
        if code.get(thunk_offset..thunk_offset.saturating_add(4))
            != Some(&[0x8b, 0x04, 0x24, 0xc3][..])
        {
            continue;
        }
        let Some(add) = instructions.get(index + 1) else {
            continue;
        };
        if add.mnemonic() != Mnemonic::Add
            || add.op0_register() != Register::EAX
            || add.op1_kind() != OpKind::Immediate32
        {
            continue;
        }
        let base = (add.ip() as u32).wrapping_add(add.immediate32());
        for store_index in index + 2..instructions.len().min(index + 20) {
            let store = &instructions[store_index];
            if store.mnemonic() == Mnemonic::Mov
                && store.op0_kind() == OpKind::Memory
                && store.memory_base() == Register::ESP
                && store.memory_index() == Register::None
                && store.memory_size() == MemorySize::UInt32
                && store.op1_register() == Register::EAX
            {
                if let Some(sp) = stack[store_index] {
                    spilled_got.push((
                        store_index,
                        sp + i64::from(store.memory_displacement32() as i32),
                        base,
                    ));
                }
                break;
            }
            if store.flow_control() != FlowControl::Next || writes_register(store, Register::EAX) {
                break;
            }
        }
    }
    for (index, instruction) in instructions.iter().enumerate() {
        if let Some(thunk) = near_call_target(instruction) {
            if loads_return_address_into_ebx(code, text_vaddr, thunk) {
                got = instructions.get(index + 1).and_then(|add| {
                    (add.mnemonic() == Mnemonic::Add
                        && add.op0_kind() == OpKind::Register
                        && add.op0_register() == Register::EBX
                        && add.op1_kind() == OpKind::Immediate32)
                        .then(|| u64::from((add.ip() as u32).wrapping_add(add.immediate32())))
                });
                continue;
            }
        }
        // A compiler may spill the EAX PIC base and reload it into EBX on a
        // cold branch. Stack depths are computed along control-flow edges so
        // an earlier return's epilogue cannot change that slot's identity.
        let reloaded_got = index.checked_sub(1).and_then(|load_index| {
            let load = &instructions[load_index];
            if load.mnemonic() != Mnemonic::Mov
                || load.op0_register() != Register::EBX
                || load.op1_kind() != OpKind::Memory
                || load.memory_base() != Register::ESP
                || load.memory_index() != Register::None
                || load.memory_size() != MemorySize::UInt32
            {
                return None;
            }
            let slot = stack[load_index]? + i64::from(load.memory_displacement32() as i32);
            spilled_got
                .iter()
                .find_map(|&(store_index, stored_slot, base)| {
                    if store_index >= load_index || slot != stored_slot {
                        return None;
                    }
                    let overwritten = instructions
                        .iter()
                        .enumerate()
                        .take(load_index)
                        .skip(store_index + 1)
                        .any(|(index, write)| {
                            write.op0_kind() == OpKind::Memory
                                && write.memory_base() == Register::ESP
                                && write.memory_index() == Register::None
                                && stack[index].is_some_and(|sp| {
                                    let start =
                                        sp + i64::from(write.memory_displacement32() as i32);
                                    start < slot + 4
                                        && start + write.memory_size().size() as i64 > slot
                                })
                                && !matches!(
                                    write.mnemonic(),
                                    Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Push
                                )
                        });
                    (!overwritten).then_some(u64::from(base))
                })
        });
        let Some(got) = reloaded_got.or(got) else {
            continue;
        };
        let is_slot_address = instruction.mnemonic() == Mnemonic::Lea
            && instruction.memory_base() == Register::EBX
            && instruction.memory_index() == Register::None;
        if !is_slot_address {
            continue;
        }
        let slot_register = instruction.op0_register();
        let engine_slot = u64::from((got as u32).wrapping_add(instruction.memory_displacement32()));
        let lookahead = instructions
            .iter()
            .enumerate()
            .skip(index + 1)
            .take(SLOT_LOAD_LOOKAHEAD);
        for (push_index, push) in lookahead {
            let pushes_engine = push.mnemonic() == Mnemonic::Push
                && push.op0_kind() == OpKind::Memory
                && push.memory_base() == slot_register
                && push.memory_index() == Register::None
                && push.memory_displacement32() == 0;
            if !pushes_engine {
                if push.flow_control() != FlowControl::Next || writes_register(push, slot_register)
                {
                    break;
                }
                continue;
            }
            if let Some(helper) = instructions.get(push_index + 1).and_then(near_call_target) {
                sites.push((engine_slot, helper));
            }
            break;
        }
    }
    sites
}

/// Stack depth at each reachable instruction. Conflicting paths discard the
/// affected value, and returns do not fall through into cold blocks.
fn stack_offsets32(instructions: &[Instruction]) -> Vec<Option<i64>> {
    use std::collections::{HashMap, VecDeque};
    type Stack = (Option<i64>, Option<i64>);
    let indices: HashMap<_, _> = instructions
        .iter()
        .enumerate()
        .map(|(i, instruction)| (instruction.ip(), i))
        .collect();
    let mut states: Vec<Option<Stack>> = vec![None; instructions.len()];
    let mut pending = VecDeque::new();
    if !instructions.is_empty() {
        states[0] = Some((Some(0), None));
        pending.push_back(0);
    }
    while let Some(index) = pending.pop_front() {
        let instruction = &instructions[index];
        let (mut sp, mut fp) = states[index].unwrap();
        let flow = instruction.flow_control();
        match instruction.mnemonic() {
            Mnemonic::Push | Mnemonic::Pop => {
                sp = sp.map(|sp| sp + i64::from(instruction.stack_pointer_increment()));
            }
            Mnemonic::Add | Mnemonic::Sub if instruction.op0_register() == Register::ESP => {
                let delta = instruction
                    .try_immediate(1)
                    .ok()
                    .map(|value| i64::from(value as i32));
                sp = sp.zip(delta).map(|(sp, delta)| {
                    if instruction.mnemonic() == Mnemonic::Add {
                        sp + delta
                    } else {
                        sp - delta
                    }
                });
            }
            Mnemonic::Mov if instruction.op0_register() == Register::EBP => {
                fp = (instruction.op1_register() == Register::ESP)
                    .then_some(sp)
                    .flatten();
            }
            Mnemonic::Mov if instruction.op0_register() == Register::ESP => {
                sp = (instruction.op1_register() == Register::EBP)
                    .then_some(fp)
                    .flatten();
            }
            Mnemonic::Lea if instruction.op0_register() == Register::ESP => {
                sp = if instruction.memory_base() == Register::EBP
                    && instruction.memory_index() == Register::None
                {
                    fp.map(|fp| fp + i64::from(instruction.memory_displacement32() as i32))
                } else {
                    None
                };
            }
            Mnemonic::Leave => {
                sp = fp.map(|fp| fp + 4);
                fp = None;
            }
            _ => {}
        }
        let mut next = Vec::new();
        if matches!(
            flow,
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) {
            if let Some(&target) = indices.get(&instruction.near_branch_target()) {
                next.push(target);
            }
        }
        if matches!(
            flow,
            FlowControl::Next
                | FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::ConditionalBranch
        ) && index + 1 < instructions.len()
        {
            next.push(index + 1);
        }
        for target in next {
            let merged = states[target].map_or((sp, fp), |old| {
                (
                    (old.0 == sp).then_some(sp).flatten(),
                    (old.1 == fp).then_some(fp).flatten(),
                )
            });
            if states[target] != Some(merged) {
                states[target] = Some(merged);
                pending.push_back(target);
            }
        }
    }
    states
        .into_iter()
        .map(|state| state.and_then(|state| state.0))
        .collect()
}

/// `mov ebx, [esp]; ret`
fn loads_return_address_into_ebx(code: &[u8], text_vaddr: u64, target: u64) -> bool {
    let Some(offset) = target
        .checked_sub(text_vaddr)
        .and_then(|offset| usize::try_from(offset).ok())
    else {
        return false;
    };
    code.get(offset..offset.saturating_add(4)) == Some(&[0x8b, 0x1c, 0x24, 0xc3][..])
}

/// The helper reads at least three engine members (tree root, current pipe,
/// node array), compares the pipe against `node->key`, and returns
/// `node->value` as a dword. It calls nothing.
pub fn validate_helper(code: &[u8], text_vaddr: u64, offset: usize, bitness: u32) -> bool {
    let Some(instructions) = decode(code, text_vaddr, offset, HELPER_SCAN, bitness) else {
        return false;
    };
    let mut body = instructions.iter().peekable();
    let mut saved = Vec::new();
    let mut engine = match bitness {
        64 => Some(Register::RDI),
        32 => {
            while body
                .peek()
                .is_some_and(|instruction| instruction.mnemonic() == Mnemonic::Push)
            {
                let push = body.next().unwrap();
                if push.op0_kind() != OpKind::Register
                    || !matches!(
                        push.op0_register(),
                        Register::EBX | Register::ESI | Register::EDI | Register::EBP
                    )
                {
                    return false;
                }
                saved.push(push.op0_register());
            }
            let Some(load) = body.next() else {
                return false;
            };
            let loads_this = load.mnemonic() == Mnemonic::Mov
                && load.op0_kind() == OpKind::Register
                && load.op1_kind() == OpKind::Memory
                && load.memory_base() == Register::ESP
                && load.memory_displacement32() == 4 + 4 * saved.len() as u32;
            if !loads_this {
                return false;
            }
            Some(load.op0_register())
        }
        _ => return false,
    };

    let mut member_loads = 0usize;
    let mut dword_members = Vec::new();
    let mut compares_key = false;
    while let Some(instruction) = body.next() {
        if instruction.is_invalid() {
            return false;
        }
        match instruction.flow_control() {
            FlowControl::Next
            | FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch => {}
            FlowControl::Return => continue,
            _ => return false,
        }
        let reads_engine = engine.is_some_and(|engine| {
            instruction.op1_kind() == OpKind::Memory
                && instruction.memory_base().full_register() == engine.full_register()
                && instruction.memory_index() == Register::None
                && matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Movsxd)
        });
        if reads_engine {
            member_loads += 1;
            if matches!(
                instruction.memory_size(),
                MemorySize::UInt32 | MemorySize::Int32
            ) {
                dword_members.push(instruction.op0_register().full_register());
            }
        }
        if instruction.mnemonic() == Mnemonic::Cmp
            && instruction.op0_kind() == OpKind::Memory
            && instruction.memory_size() == MemorySize::UInt32
            && instruction.memory_displacement64() == NODE_KEY
            && instruction.op1_kind() == OpKind::Register
            && dword_members.contains(&instruction.op1_register().full_register())
        {
            compares_key = true;
        }
        let mut tail = body.clone();
        let restores_registers = saved.iter().rev().all(|&register| {
            tail.next().is_some_and(|instruction| {
                instruction.mnemonic() == Mnemonic::Pop && instruction.op0_register() == register
            })
        });
        let returns_value = instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::EAX
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_size() == MemorySize::UInt32
            && instruction.memory_displacement64() == NODE_VALUE
            && restores_registers
            && tail
                .next()
                .is_some_and(|next| next.mnemonic() == Mnemonic::Ret && next.op_count() == 0);
        if returns_value {
            return member_loads >= 3 && compares_key;
        }
        // The engine pointer is gone once its register is overwritten.
        if instruction.op0_kind() == OpKind::Register
            && engine.is_some_and(|engine| {
                instruction.op0_register().full_register() == engine.full_register()
            })
        {
            engine = None;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{resolve, validate_helper, CurrentAppSite};
    use iced_x86::code_asm::*;
    use iced_x86::{BlockEncoderOptions, Code, Instruction, MemoryOperand, Register};

    const TEXT_VADDR: u64 = 0x10_0000;
    const ENGINE_SLOT64: u64 = 0x40_0000;
    const GOT32: u32 = 0x30_0000;
    const ENGINE_SLOT_FROM_GOT32: i32 = 0x1d0;

    struct Image {
        code: Vec<u8>,
        helper: usize,
    }

    /// Assemble an adapter entry followed by its helper and return both
    /// offsets relative to `TEXT_VADDR`.
    fn image(
        bitness: u32,
        build: impl FnOnce(&mut CodeAssembler, CodeLabel) -> Result<(), IcedError>,
        helper: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>,
    ) -> Image {
        let mut assembler = CodeAssembler::new(bitness).unwrap();
        let mut helper_label = assembler.create_label();
        build(&mut assembler, helper_label).unwrap();
        for _ in 0..8 {
            assembler.int3().unwrap();
        }
        assembler.set_label(&mut helper_label).unwrap();
        helper(&mut assembler).unwrap();
        let result = assembler
            .assemble_options(
                TEXT_VADDR,
                BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
            )
            .unwrap();
        let helper = (result.label_ip(&helper_label).unwrap() - TEXT_VADDR) as usize;
        Image {
            code: result.inner.code_buffer,
            helper,
        }
    }

    /// x86_64 helper: pipe loaded into `esi`, value read through an indexed
    /// address.
    fn helper64(a: &mut CodeAssembler) -> Result<(), IcedError> {
        let mut walk = a.create_label();
        let mut next = a.create_label();
        let mut found = a.create_label();
        let mut missing = a.create_label();
        a.movsxd(rax, dword_ptr(rdi + 0xde8))?;
        a.mov(esi, dword_ptr(rdi + 0xf0))?;
        a.cmp(eax, -1)?;
        a.je(missing)?;
        a.mov(rcx, qword_ptr(rdi + 0xe00))?;
        a.jmp(walk)?;
        a.set_label(&mut next)?;
        a.movsxd(rax, dword_ptr(rdx))?;
        a.cmp(eax, -1)?;
        a.je(missing)?;
        a.set_label(&mut walk)?;
        a.lea(rax, qword_ptr(rax + rax * 2))?;
        a.shl(rax, 3)?;
        a.lea(rdx, qword_ptr(rcx + rax))?;
        a.cmp(dword_ptr(rdx + 0x10), esi)?;
        a.jg(next)?;
        a.jge(found)?;
        a.movsxd(rax, dword_ptr(rdx + 4))?;
        a.cmp(eax, -1)?;
        a.jne(walk)?;
        a.set_label(&mut missing)?;
        a.xor(eax, eax)?;
        a.ret()?;
        a.set_label(&mut found)?;
        a.mov(eax, dword_ptr(rcx + rax + 0x14))?;
        a.ret()
    }

    /// i686 helper: engine taken from the stack, pipe loaded into `edx`.
    fn helper32(a: &mut CodeAssembler) -> Result<(), IcedError> {
        let mut walk = a.create_label();
        let mut next = a.create_label();
        let mut found = a.create_label();
        let mut missing = a.create_label();
        a.mov(ecx, dword_ptr(esp + 4))?;
        a.mov(eax, dword_ptr(ecx + 0xa98))?;
        a.mov(edx, dword_ptr(ecx + 0x9c))?;
        a.cmp(eax, -1)?;
        a.je(missing)?;
        a.mov(ecx, dword_ptr(ecx + 0xaac))?;
        a.jmp(walk)?;
        a.set_label(&mut next)?;
        a.mov(eax, dword_ptr(eax))?;
        a.cmp(eax, -1)?;
        a.je(missing)?;
        a.set_label(&mut walk)?;
        a.lea(eax, dword_ptr(eax + eax * 2))?;
        a.lea(eax, dword_ptr(ecx + eax * 8))?;
        a.cmp(dword_ptr(eax + 0x10), edx)?;
        a.jg(next)?;
        a.jge(found)?;
        a.mov(eax, dword_ptr(eax + 4))?;
        a.cmp(eax, -1)?;
        a.jne(walk)?;
        a.set_label(&mut missing)?;
        a.xor(eax, eax)?;
        a.ret()?;
        a.set_label(&mut found)?;
        a.mov(eax, dword_ptr(eax + 0x14))?;
        a.ret()
    }

    /// x86_64 adapter whose engine lookup sits on a branch far past the entry.
    fn adapter64(a: &mut CodeAssembler, helper: CodeLabel) -> Result<(), IcedError> {
        let mut cold = a.create_label();
        a.push(r15)?;
        a.test(rdx, rdx)?;
        a.je(cold)?;
        for _ in 0..0x200 {
            a.nop()?;
        }
        a.pop(r15)?;
        a.ret()?;
        a.set_label(&mut cold)?;
        a.add_instruction(Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RIP, ENGINE_SLOT64 as i64),
        )?)?;
        a.mov(rdi, qword_ptr(rax))?;
        a.call(helper)?;
        a.pop(r15)?;
        a.ret()
    }

    /// x86_64 adapter that spills its arguments between the slot address and
    /// the engine load.
    fn adapter64_spilled(a: &mut CodeAssembler, helper: CodeLabel) -> Result<(), IcedError> {
        a.push(r13)?;
        a.sub(rsp, 0x38)?;
        a.add_instruction(Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RIP, ENGINE_SLOT64 as i64),
        )?)?;
        a.mov(dword_ptr(rsp + 0x1c), r8d)?;
        a.mov(qword_ptr(rsp + 0x10), rdx)?;
        a.mov(qword_ptr(rsp + 8), rsi)?;
        a.mov(rdi, qword_ptr(rax))?;
        a.call(helper)?;
        a.add(rsp, 0x38)?;
        a.pop(r13)?;
        a.ret()
    }

    /// i686 adapter: PIC base from the pc thunk, then the engine pushed as
    /// the helper's only argument.
    fn adapter32(a: &mut CodeAssembler, helper: CodeLabel) -> Result<(), IcedError> {
        let mut thunk = a.create_label();
        let mut after_thunk = a.create_label();
        a.push(ebp)?;
        a.push(edi)?;
        a.push(esi)?;
        a.push(ebx)?;
        a.call(thunk)?;
        a.set_label(&mut after_thunk)?;
        a.add(ebx, GOT32 as i32)?;
        a.sub(esp, 0x2c)?;
        a.lea(eax, dword_ptr(ebx + ENGINE_SLOT_FROM_GOT32))?;
        a.sub(esp, 0x0c)?;
        a.push(dword_ptr(eax))?;
        a.call(helper)?;
        a.add(esp, 0x3c)?;
        a.pop(ebx)?;
        a.pop(esi)?;
        a.pop(edi)?;
        a.pop(ebp)?;
        a.ret()?;
        a.set_label(&mut thunk)?;
        a.mov(ebx, dword_ptr(esp))?;
        a.ret()
    }

    #[test]
    fn resolves_x64_site_on_a_cold_branch() {
        let image = image(64, adapter64, helper64);
        assert_eq!(
            resolve(&image.code, TEXT_VADDR, 0, 64),
            Some(CurrentAppSite {
                engine_slot: ENGINE_SLOT64,
                helper: image.helper,
            })
        );
    }

    #[test]
    fn resolves_x64_site_with_interleaved_spills() {
        let image = image(64, adapter64_spilled, helper64);
        assert_eq!(
            resolve(&image.code, TEXT_VADDR, 0, 64),
            Some(CurrentAppSite {
                engine_slot: ENGINE_SLOT64,
                helper: image.helper,
            })
        );
    }

    #[test]
    fn slot_register_must_survive_until_the_engine_load() {
        let image = image(
            64,
            |a, helper| {
                a.add_instruction(Instruction::with2(
                    Code::Lea_r64_m,
                    Register::RAX,
                    MemoryOperand::with_base_displ(Register::RIP, ENGINE_SLOT64 as i64),
                )?)?;
                a.mov(rax, qword_ptr(rsp + 8))?;
                a.mov(rdi, qword_ptr(rax))?;
                a.call(helper)?;
                a.ret()
            },
            helper64,
        );
        assert_eq!(resolve(&image.code, TEXT_VADDR, 0, 64), None);
    }

    #[test]
    fn resolves_x86_site_through_the_pic_base() {
        let image = image(32, adapter32, helper32);
        let add_ip = TEXT_VADDR as u32 + 4 + 5;
        let expected = add_ip
            .wrapping_add(GOT32)
            .wrapping_add(ENGINE_SLOT_FROM_GOT32 as u32);
        assert_eq!(
            resolve(&image.code, TEXT_VADDR, 0, 32),
            Some(CurrentAppSite {
                engine_slot: u64::from(expected),
                helper: image.helper,
            })
        );
    }

    #[test]
    fn resolves_spilled_x86_pic_base_on_a_cold_branch() {
        for overwrite in [false, true] {
            let image = image(
                32,
                |a, helper| {
                    let mut thunk = a.create_label();
                    let mut cold = a.create_label();
                    a.call(thunk)?;
                    a.add(eax, GOT32 as i32)?;
                    a.push(ebp)?;
                    a.push(edi)?;
                    a.push(esi)?;
                    a.push(ebx)?;
                    a.sub(esp, 0x2c)?;
                    a.mov(dword_ptr(esp + 4), eax)?;
                    if overwrite {
                        a.mov(dword_ptr(esp + 4), 0)?;
                    }
                    a.test(ecx, ecx)?;
                    a.je(cold)?;
                    a.add(esp, 0x2c)?;
                    a.pop(ebx)?;
                    a.pop(esi)?;
                    a.pop(edi)?;
                    a.pop(ebp)?;
                    a.ret()?;
                    a.set_label(&mut cold)?;
                    a.sub(esp, 0xc)?;
                    a.mov(ebx, dword_ptr(esp + 0x10))?;
                    a.lea(eax, dword_ptr(ebx + ENGINE_SLOT_FROM_GOT32))?;
                    a.push(dword_ptr(eax))?;
                    a.call(helper)?;
                    a.add(esp, 0x3c)?;
                    a.pop(ebx)?;
                    a.pop(esi)?;
                    a.pop(edi)?;
                    a.pop(ebp)?;
                    a.ret()?;
                    a.set_label(&mut thunk)?;
                    a.mov(eax, dword_ptr(esp))?;
                    a.ret()
                },
                helper32,
            );
            let expected = (TEXT_VADDR as u32 + 5)
                .wrapping_add(GOT32)
                .wrapping_add(ENGINE_SLOT_FROM_GOT32 as u32);
            assert_eq!(
                resolve(&image.code, TEXT_VADDR, 0, 32),
                (!overwrite).then_some(CurrentAppSite {
                    engine_slot: u64::from(expected),
                    helper: image.helper,
                })
            );
        }
    }

    #[test]
    fn helper_must_compare_the_loaded_pipe() {
        // The key compare uses a register that never held an engine member.
        let helper = image(
            64,
            |a, _| a.nop(),
            |a| {
                let mut found = a.create_label();
                a.movsxd(rax, dword_ptr(rdi + 0xde8))?;
                a.mov(esi, dword_ptr(rdi + 0xf0))?;
                a.mov(rcx, qword_ptr(rdi + 0xe00))?;
                a.cmp(dword_ptr(rcx + 0x10), r8d)?;
                a.je(found)?;
                a.xor(eax, eax)?;
                a.ret()?;
                a.set_label(&mut found)?;
                a.mov(eax, dword_ptr(rcx + 0x14))?;
                a.ret()
            },
        );
        assert!(!validate_helper(
            &helper.code,
            TEXT_VADDR,
            helper.helper,
            64
        ));
        let valid = image(64, |a, _| a.nop(), helper64);
        assert!(validate_helper(&valid.code, TEXT_VADDR, valid.helper, 64));
    }

    #[test]
    fn x86_helper_accounts_for_saved_registers_and_requires_their_restore() {
        for wrong_restore in [false, true] {
            let image = image(32, adapter32, |a| {
                a.push(ebx)?;
                a.mov(edx, dword_ptr(esp + 8))?;
                a.mov(eax, dword_ptr(edx + 0xe00))?;
                a.mov(ebx, dword_ptr(edx + 0x9c))?;
                a.mov(ecx, dword_ptr(edx + 0xe14))?;
                a.cmp(dword_ptr(ecx + 0x10), ebx)?;
                a.mov(eax, dword_ptr(ecx + 0x14))?;
                if wrong_restore {
                    a.pop(esi)?;
                } else {
                    a.pop(ebx)?;
                }
                a.ret()
            });
            assert_eq!(
                validate_helper(&image.code, TEXT_VADDR, image.helper, 32),
                !wrong_restore
            );
        }
    }

    #[test]
    fn helper_must_not_call_out() {
        let helper = image(
            64,
            |a, _| a.nop(),
            |a| {
                a.movsxd(rax, dword_ptr(rdi + 0xde8))?;
                a.mov(esi, dword_ptr(rdi + 0xf0))?;
                a.mov(rcx, qword_ptr(rdi + 0xe00))?;
                a.call(TEXT_VADDR)?;
                a.cmp(dword_ptr(rcx + 0x10), esi)?;
                a.mov(eax, dword_ptr(rcx + 0x14))?;
                a.ret()
            },
        );
        assert!(!validate_helper(
            &helper.code,
            TEXT_VADDR,
            helper.helper,
            64
        ));
    }

    #[test]
    fn rejects_adapter_without_a_validated_helper() {
        // The same site shape, but the callee is not the lookup helper.
        let image = image(64, adapter64, |a| {
            a.xor(eax, eax)?;
            a.ret()
        });
        assert_eq!(resolve(&image.code, TEXT_VADDR, 0, 64), None);
    }
}
