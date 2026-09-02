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

#[cfg(test)]
mod tests {
    use super::resolve_requires_legacy_cdkey_implementation;

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
