//! Resolution of `CUser` implementations behind IClientUser vtable entries.
//!
//! Steam exposes `IClientUser` as a secondary base of `CUser`, so a vtable
//! entry is usually a `this`-adjusting thunk that tail-jumps into the
//! implementation. The runtime hook installer and the offline pattern scan
//! share these helpers so both resolve and validate the same target.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, MemorySize, Mnemonic, OpKind, Register,
};

const THUNK_SCAN: usize = 0x20;
const IMPLEMENTATION_SCAN: usize = 0x80;

fn bounded(code: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    let end = code.len().min(offset.checked_add(len)?);
    code.get(offset..end)
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32
            | OpKind::Immediate32to64
    )
}

/// A secondary-base thunk rewrites the object pointer before jumping: `sub rdi`
/// on x86_64, `sub dword [esp+4]` on x86.
fn adjusts_this(instruction: &Instruction) -> bool {
    match instruction.mnemonic() {
        Mnemonic::Sub | Mnemonic::Add => {
            let object_pointer = match instruction.op0_kind() {
                OpKind::Register => instruction.op0_register() == Register::RDI,
                OpKind::Memory => {
                    instruction.memory_base() == Register::ESP
                        && instruction.memory_displacement64() == 4
                }
                _ => false,
            };
            object_pointer && is_immediate(instruction.op1_kind())
        }
        Mnemonic::Lea => {
            instruction.op0_register() == Register::RDI
                && instruction.memory_base() == Register::RDI
        }
        _ => false,
    }
}

/// Offset of the implementation behind a `this`-adjusting adapter thunk at
/// `offset`, or `None` when the bytes there are not such a thunk.
pub fn adapter_thunk_target(
    code: &[u8],
    text_vaddr: u64,
    offset: usize,
    bitness: u32,
) -> Option<usize> {
    let bytes = bounded(code, offset, THUNK_SCAN)?;
    let ip = text_vaddr.checked_add(offset as u64)?;
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let adjust = decoder.decode();
    if adjust.is_invalid() || !adjusts_this(&adjust) {
        return None;
    }
    let jump = decoder.decode();
    if jump.is_invalid()
        || jump.mnemonic() != Mnemonic::Jmp
        || jump.flow_control() != FlowControl::UnconditionalBranch
    {
        return None;
    }
    let target = usize::try_from(jump.near_branch_target().checked_sub(text_vaddr)?).ok()?;
    (target < code.len()).then_some(target)
}

/// `CUser::RequiresLegacyCDKey(AppId_t, bool *pbHasKey)` clears `*pbHasKey`
/// through a register before its first early return. That byte store is the
/// evidence that the out-parameter contract assumed by the hook still holds.
pub fn validate_requires_legacy_cdkey(code: &[u8], offset: usize, bitness: u32) -> bool {
    let Some(bytes) = bounded(code, offset, IMPLEMENTATION_SCAN) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(bitness, bytes, offset as u64, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return false;
        }
        let clears_flag = instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Memory
            && instruction.memory_size() == MemorySize::UInt8
            && instruction.memory_displacement64() == 0
            && !matches!(
                instruction.memory_base(),
                Register::None | Register::RSP | Register::RBP | Register::ESP | Register::EBP
            )
            && instruction.op1_kind() == OpKind::Immediate8
            && instruction.immediate8() == 0;
        if clears_flag {
            return true;
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
        ) {
            return false;
        }
    }
    false
}

/// Resolve the `CUser::RequiresLegacyCDKey` implementation behind the
/// IClientUser vtable entry at `offset`. The entry is either an adapter thunk
/// or the implementation itself; the result is validated either way.
pub fn resolve_requires_legacy_cdkey_implementation(
    code: &[u8],
    text_vaddr: u64,
    offset: usize,
    bitness: u32,
) -> Option<usize> {
    let target = adapter_thunk_target(code, text_vaddr, offset, bitness).unwrap_or(offset);
    validate_requires_legacy_cdkey(code, target, bitness).then_some(target)
}

/// `CUser::GetSteamID` returns the account's CSteamID member and nothing else:
/// `mov rax, qword [rdi + disp]; ret` on x86_64. On x86 the result is written
/// through the hidden return pointer as two dword copies from adjacent
/// members, and `ret 4` pops that pointer. The hook relies on this shape for
/// its return convention and for the absence of side effects.
pub fn validate_get_steam_id(code: &[u8], offset: usize, bitness: u32) -> bool {
    let Some(bytes) = bounded(code, offset, THUNK_SCAN) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(bitness, bytes, offset as u64, DecoderOptions::NONE);
    match bitness {
        64 => validate_get_steam_id64(&mut decoder),
        32 => validate_get_steam_id32(&mut decoder),
        _ => false,
    }
}

fn validate_get_steam_id64(decoder: &mut Decoder<'_>) -> bool {
    let load = decoder.decode();
    let loads_member = !load.is_invalid()
        && load.mnemonic() == Mnemonic::Mov
        && load.op0_kind() == OpKind::Register
        && load.op0_register() == Register::RAX
        && load.op1_kind() == OpKind::Memory
        && load.memory_size() == MemorySize::UInt64
        && load.memory_base() == Register::RDI
        && load.memory_index() == Register::None;
    let ret = decoder.decode();
    loads_member && !ret.is_invalid() && ret.mnemonic() == Mnemonic::Ret && ret.op_count() == 0
}

fn validate_get_steam_id32(decoder: &mut Decoder<'_>) -> bool {
    let mut loads = Vec::new();
    let mut stores = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return false;
        }
        match instruction.flow_control() {
            FlowControl::Return => {
                let pops_result_pointer = instruction.op_count() == 1
                    && instruction.op0_kind() == OpKind::Immediate16
                    && instruction.immediate16() == 4;
                return pops_result_pointer && copies_steam_id32(&loads, &stores);
            }
            FlowControl::Next => {}
            _ => return false,
        }
        if instruction.mnemonic() != Mnemonic::Mov {
            continue;
        }
        let member = |base: Register| !matches!(base, Register::None | Register::ESP);
        if instruction.op1_kind() == OpKind::Memory
            && instruction.memory_size() == MemorySize::UInt32
            && member(instruction.memory_base())
            && instruction.memory_index() == Register::None
        {
            loads.push((
                instruction.memory_base(),
                instruction.memory_displacement32(),
            ));
        } else if instruction.op0_kind() == OpKind::Memory
            && instruction.memory_size() == MemorySize::UInt32
            && member(instruction.memory_base())
            && instruction.memory_index() == Register::None
        {
            stores.push((
                instruction.memory_base(),
                instruction.memory_displacement32(),
            ));
        }
    }
    false
}

/// Two loads from adjacent dwords of one object, stored to offsets 0 and 4 of
/// the result.
fn copies_steam_id32(loads: &[(Register, u32)], stores: &[(Register, u32)]) -> bool {
    let [(load_base_a, member_a), (load_base_b, member_b)] = loads else {
        return false;
    };
    let [(store_base_a, out_a), (store_base_b, out_b)] = stores else {
        return false;
    };
    let adjacent = member_a.wrapping_sub(*member_b) == 4 || member_b.wrapping_sub(*member_a) == 4;
    load_base_a == load_base_b
        && adjacent
        && store_base_a == store_base_b
        && store_base_a != load_base_a
        && (*out_a).min(*out_b) == 0
        && (*out_a).max(*out_b) == 4
}

/// Resolve the `CUser::GetSteamID` implementation behind the IClientUser
/// vtable entry at `offset`. Current builds read the member straight through
/// the adjusted `this`, so the entry is usually the implementation itself.
pub fn resolve_get_steam_id_implementation(
    code: &[u8],
    text_vaddr: u64,
    offset: usize,
    bitness: u32,
) -> Option<usize> {
    let target = adapter_thunk_target(code, text_vaddr, offset, bitness).unwrap_or(offset);
    validate_get_steam_id(code, target, bitness).then_some(target)
}

#[cfg(test)]
mod tests {
    use super::{
        resolve_get_steam_id_implementation, resolve_requires_legacy_cdkey_implementation,
    };
    use iced_x86::code_asm::*;
    use iced_x86::BlockEncoderOptions;

    const TEXT_VADDR: u64 = 0x10_0000;
    const IMPL_OFFSET: usize = 0x40;

    // sub rdi, 0x1fd0
    const ADJUST_THIS_X64: &[u8] = &[0x48, 0x81, 0xef, 0xd0, 0x1f, 0x00, 0x00];
    // sub dword [esp + 4], 0x18d4
    const ADJUST_THIS_X86: &[u8] = &[0x81, 0x6c, 0x24, 0x04, 0xd4, 0x18, 0x00, 0x00];

    const IMPLEMENTATION_X64: &[u8] = &[
        0x41, 0x55, // push r13
        0x49, 0x89, 0xfd, // mov r13, rdi
        0x49, 0x89, 0xd4, // mov r12, rdx
        0xc6, 0x02, 0x00, // mov byte [rdx], 0
        0xc3, // ret
    ];
    const IMPLEMENTATION_X86: &[u8] = &[
        0x55, // push ebp
        0x8b, 0x44, 0x24, 0x0c, // mov eax, [esp + 0xc]
        0xc6, 0x00, 0x00, // mov byte [eax], 0
        0xc3, // ret
    ];
    const UNRELATED_X64: &[u8] = &[
        0x41, 0x55, // push r13
        0xc6, 0x44, 0x24, 0x24, 0x00, // mov byte [rsp + 0x24], 0
        0xc3, // ret
    ];
    const UNRELATED_X86: &[u8] = &[
        0x55, // push ebp
        0xc6, 0x44, 0x24, 0x10, 0x00, // mov byte [esp + 0x10], 0
        0xc3, // ret
    ];

    fn thunk_image(prefix: &[u8], implementation: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0xcc; IMPL_OFFSET + implementation.len()];
        bytes[..prefix.len()].copy_from_slice(prefix);
        let opcode = prefix.len();
        bytes[opcode] = 0xe9;
        let displacement = IMPL_OFFSET as i32 - (opcode as i32 + 5);
        bytes[opcode + 1..opcode + 5].copy_from_slice(&displacement.to_le_bytes());
        bytes[IMPL_OFFSET..].copy_from_slice(implementation);
        bytes
    }

    #[test]
    fn resolves_x64_implementation_behind_thunk() {
        let code = thunk_image(ADJUST_THIS_X64, IMPLEMENTATION_X64);
        assert_eq!(
            resolve_requires_legacy_cdkey_implementation(&code, TEXT_VADDR, 0, 64),
            Some(IMPL_OFFSET)
        );
    }

    #[test]
    fn resolves_x86_implementation_behind_thunk() {
        let code = thunk_image(ADJUST_THIS_X86, IMPLEMENTATION_X86);
        assert_eq!(
            resolve_requires_legacy_cdkey_implementation(&code, TEXT_VADDR, 0, 32),
            Some(IMPL_OFFSET)
        );
    }

    #[test]
    fn accepts_direct_implementation_entry() {
        assert_eq!(
            resolve_requires_legacy_cdkey_implementation(IMPLEMENTATION_X64, TEXT_VADDR, 0, 64),
            Some(0)
        );
        assert_eq!(
            resolve_requires_legacy_cdkey_implementation(IMPLEMENTATION_X86, TEXT_VADDR, 0, 32),
            Some(0)
        );
    }

    #[test]
    fn rejects_implementation_without_flag_reset() {
        let code = thunk_image(ADJUST_THIS_X64, UNRELATED_X64);
        assert_eq!(
            resolve_requires_legacy_cdkey_implementation(&code, TEXT_VADDR, 0, 64),
            None
        );
        let code = thunk_image(ADJUST_THIS_X86, UNRELATED_X86);
        assert_eq!(
            resolve_requires_legacy_cdkey_implementation(&code, TEXT_VADDR, 0, 32),
            None
        );
    }

    fn assemble(
        bitness: u32,
        build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>,
    ) -> Vec<u8> {
        let mut assembler = CodeAssembler::new(bitness).unwrap();
        build(&mut assembler).unwrap();
        assembler.assemble(TEXT_VADDR).unwrap()
    }

    /// x86_64 secondary-base entry reading the member through the adjusted
    /// `this`.
    fn steam_id_member_read64() -> Vec<u8> {
        assemble(64, |a| {
            a.mov(rax, qword_ptr(rdi - 0x1d56))?;
            a.ret()
        })
    }

    /// i686 entry copying the member through the hidden result pointer.
    fn steam_id_sret_copy32(result_pop: u32, high: i32) -> Vec<u8> {
        assemble(32, |a| {
            a.push(ebx)?;
            a.mov(edx, dword_ptr(esp + 0x0c))?;
            a.mov(eax, dword_ptr(esp + 0x08))?;
            a.mov(ebx, dword_ptr(edx + high))?;
            a.mov(ecx, dword_ptr(edx - 0x1752))?;
            a.mov(dword_ptr(eax + 4), ebx)?;
            a.mov(dword_ptr(eax), ecx)?;
            a.pop(ebx)?;
            if result_pop == 0 {
                a.ret()
            } else {
                a.ret_1(result_pop)
            }
        })
    }

    #[test]
    fn get_steam_id_accepts_direct_member_read() {
        assert_eq!(
            resolve_get_steam_id_implementation(&steam_id_member_read64(), TEXT_VADDR, 0, 64),
            Some(0)
        );
        assert_eq!(
            resolve_get_steam_id_implementation(
                &steam_id_sret_copy32(4, -0x174e),
                TEXT_VADDR,
                0,
                32
            ),
            Some(0)
        );
    }

    #[test]
    fn get_steam_id_follows_this_adjusting_thunk() {
        let implementation;
        let code = {
            let mut assembler = CodeAssembler::new(64).unwrap();
            let mut target = assembler.create_label();
            assembler.sub(rdi, 0x1fd0).unwrap();
            assembler.jmp(target).unwrap();
            assembler.int3().unwrap();
            assembler.set_label(&mut target).unwrap();
            assembler.mov(rax, qword_ptr(rdi + 0x27a)).unwrap();
            assembler.ret().unwrap();
            let result = assembler
                .assemble_options(
                    TEXT_VADDR,
                    BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
                )
                .unwrap();
            implementation = (result.label_ip(&target).unwrap() - TEXT_VADDR) as usize;
            result.inner.code_buffer
        };
        assert_ne!(implementation, 0);
        assert_eq!(
            resolve_get_steam_id_implementation(&code, TEXT_VADDR, 0, 64),
            Some(implementation)
        );
    }

    #[test]
    fn get_steam_id_rejects_other_shapes() {
        let narrow_read = assemble(64, |a| {
            a.mov(eax, dword_ptr(rdi + 0x27a))?;
            a.ret()
        });
        let side_effect = assemble(64, |a| {
            a.mov(rax, qword_ptr(rdi + 0x27a))?;
            a.mov(qword_ptr(rdi + 0x280), rax)?;
            a.ret()
        });
        assert_eq!(
            resolve_get_steam_id_implementation(&narrow_read, TEXT_VADDR, 0, 64),
            None
        );
        assert_eq!(
            resolve_get_steam_id_implementation(&side_effect, TEXT_VADDR, 0, 64),
            None
        );
        // Plain `ret` would leave the hidden result pointer on the stack.
        assert_eq!(
            resolve_get_steam_id_implementation(
                &steam_id_sret_copy32(0, -0x174e),
                TEXT_VADDR,
                0,
                32
            ),
            None
        );
        // The two halves must come from adjacent dwords.
        assert_eq!(
            resolve_get_steam_id_implementation(
                &steam_id_sret_copy32(4, -0x1740),
                TEXT_VADDR,
                0,
                32
            ),
            None
        );
    }

    #[test]
    fn rejects_thunk_leaving_the_code_region() {
        let mut code = thunk_image(ADJUST_THIS_X64, IMPLEMENTATION_X64);
        code.truncate(IMPL_OFFSET);
        assert_eq!(
            resolve_requires_legacy_cdkey_implementation(&code, TEXT_VADDR, 0, 64),
            None
        );
    }
}
