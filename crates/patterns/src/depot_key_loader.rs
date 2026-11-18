//! The calls Steam's depot-key loader makes on its output `CUtlBuffer`.
//!
//! `LoadDepotDecryptionKey(_, depot_id, CUtlBuffer *out)` formats
//! `Software\Valve\Steam\Depots\<id>\DecryptionKey`, ensures `out` can hold
//! [`KEY_CAPACITY`] bytes, reads the config-store value into `out->Base()`
//! and, when something was read, moves the put position to its length. A
//! replacement that serves its own key has to make the same two buffer calls,
//! so their targets are read from the loader itself: the first direct call
//! passed the capacity, and the first direct call after the config-store
//! (indirect) read that is passed a zero seek type.
//!
//! The runtime and the offline scan both decode through here.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

/// The capacity the loader reserves before reading the key.
pub const KEY_CAPACITY: u32 = 0x80;
/// `CUtlBuffer::SEEK_HEAD`.
pub const SEEK_HEAD: i32 = 0;
const WINDOW: usize = 0x140;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyBufferCalls {
    /// `CUtlBuffer::EnsureCapacity(this, int)`.
    pub ensure_capacity: usize,
    /// `CUtlBuffer::SeekPut(this, SeekType_t, int)`.
    pub seek_put: usize,
}

pub fn decode(
    bitness: u32,
    code_base: usize,
    code: &[u8],
    entry: usize,
) -> Result<KeyBufferCalls, &'static str> {
    let offset = entry
        .checked_sub(code_base)
        .ok_or("loader precedes the code region")?;
    let window = code.get(offset..).ok_or("loader is past the code region")?;
    let window = &window[..window.len().min(WINDOW)];

    let mut capacity_argument = false;
    let mut zero_argument = false;
    let mut ensure_capacity = None;
    let mut read = false;
    let mut seek_put = None;
    for instruction in Decoder::with_ip(bitness, window, entry as u64, DecoderOptions::NONE) {
        if instruction.is_invalid() {
            break;
        }
        capacity_argument |= passes_immediate(&instruction, KEY_CAPACITY as u64);
        zero_argument |= passes_zero(&instruction);
        match instruction.flow_control() {
            FlowControl::Call => {
                let target = instruction.near_branch_target() as usize;
                if ensure_capacity.is_none() {
                    if capacity_argument {
                        ensure_capacity = Some(target);
                    }
                } else if read && zero_argument {
                    seek_put = Some(target);
                    break;
                }
                capacity_argument = false;
                zero_argument = false;
            }
            FlowControl::IndirectCall => {
                read |= ensure_capacity.is_some();
                capacity_argument = false;
                zero_argument = false;
            }
            _ => {}
        }
    }

    let ensure_capacity = ensure_capacity.ok_or("no capacity reservation call")?;
    if !read {
        return Err("no config-store read after the capacity reservation");
    }
    let seek_put = seek_put.ok_or("no put-position call after the read")?;
    let end = code_base + code.len();
    if ![ensure_capacity, seek_put]
        .iter()
        .all(|target| (code_base..end).contains(target))
        || ensure_capacity == seek_put
    {
        return Err("buffer call targets are not distinct code addresses");
    }
    Ok(KeyBufferCalls {
        ensure_capacity,
        seek_put,
    })
}

/// `mov esi, imm` (the second SysV argument) or `push imm` (an i686 argument).
fn passes_immediate(instruction: &Instruction, value: u64) -> bool {
    let immediate = |operand| {
        matches!(
            instruction.op_kind(operand),
            OpKind::Immediate8to32 | OpKind::Immediate32 | OpKind::Immediate8
        ) && instruction.immediate(operand) == value
    };
    match instruction.mnemonic() {
        Mnemonic::Mov => {
            instruction.op0_kind() == OpKind::Register
                && instruction.op0_register() == Register::ESI
                && immediate(1)
        }
        Mnemonic::Push => immediate(0),
        _ => false,
    }
}

/// `xor esi, esi` or `push 0`.
fn passes_zero(instruction: &Instruction) -> bool {
    match instruction.mnemonic() {
        Mnemonic::Xor => {
            instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && instruction.op0_register() == Register::ESI
                && instruction.op1_register() == Register::ESI
        }
        Mnemonic::Mov => passes_immediate(instruction, 0),
        Mnemonic::Push => passes_immediate(instruction, 0),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::code_asm::*;
    use iced_x86::BlockEncoderOptions;

    const BASE: u64 = 0x10_0000;

    /// The loader body with its helper calls, assembled at `BASE`; the
    /// helpers sit after the body so their addresses are inside the region.
    fn loader64(capacity: i32) -> (Vec<u8>, u64, u64) {
        let mut a = CodeAssembler::new(64).unwrap();
        let mut ensure = a.create_label();
        let mut format = a.create_label();
        let mut seek = a.create_label();
        let mut found = a.create_label();
        a.push(r12).unwrap();
        a.mov(rdi, rdx).unwrap();
        a.push(rbp).unwrap();
        a.mov(ebp, esi).unwrap();
        a.mov(esi, capacity).unwrap();
        a.push(rbx).unwrap();
        a.mov(rbx, rdx).unwrap();
        a.call(ensure).unwrap();
        a.mov(edx, ebp).unwrap();
        a.mov(rdi, rsp).unwrap();
        a.call(format).unwrap();
        a.mov(rcx, qword_ptr(rbx)).unwrap();
        a.mov(r8d, 0x80).unwrap();
        a.mov(esi, 1).unwrap();
        a.mov(rax, qword_ptr(rdi)).unwrap();
        a.call(qword_ptr(rax + 0x30)).unwrap();
        a.mov(edx, eax).unwrap();
        a.test(edx, edx).unwrap();
        a.jne(found).unwrap();
        a.ret().unwrap();
        a.set_label(&mut found).unwrap();
        a.xor(esi, esi).unwrap();
        a.mov(rdi, rbx).unwrap();
        a.call(seek).unwrap();
        a.ret().unwrap();
        a.set_label(&mut ensure).unwrap();
        a.ret().unwrap();
        a.set_label(&mut format).unwrap();
        a.ret().unwrap();
        a.set_label(&mut seek).unwrap();
        a.ret().unwrap();
        let result = a
            .assemble_options(BASE, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();
        let (ensure, seek) = (
            result.label_ip(&ensure).unwrap(),
            result.label_ip(&seek).unwrap(),
        );
        (result.inner.code_buffer, ensure, seek)
    }

    fn loader32() -> (Vec<u8>, u64, u64) {
        let mut a = CodeAssembler::new(32).unwrap();
        let mut thunk = a.create_label();
        let mut ensure = a.create_label();
        let mut format = a.create_label();
        let mut seek = a.create_label();
        let mut found = a.create_label();
        a.push(edi).unwrap();
        a.push(esi).unwrap();
        a.push(ebx).unwrap();
        a.call(thunk).unwrap();
        a.add(ebx, 0x10_0000).unwrap();
        a.sub(esp, 0x118).unwrap();
        a.mov(esi, dword_ptr(esp + 0x130)).unwrap();
        a.push(0x80).unwrap();
        a.push(esi).unwrap();
        a.call(ensure).unwrap();
        a.push(dword_ptr(esp + 0x128)).unwrap();
        a.call(format).unwrap();
        a.mov(eax, dword_ptr(eax + 0x18)).unwrap();
        a.push(dword_ptr(esi)).unwrap();
        a.call(eax).unwrap();
        a.test(eax, eax).unwrap();
        a.jne(found).unwrap();
        a.ret().unwrap();
        a.set_label(&mut found).unwrap();
        a.push(eax).unwrap();
        a.push(0).unwrap();
        a.push(esi).unwrap();
        a.call(seek).unwrap();
        a.ret().unwrap();
        for label in [&mut thunk, &mut ensure, &mut format, &mut seek] {
            a.set_label(label).unwrap();
            a.ret().unwrap();
        }
        let result = a
            .assemble_options(BASE, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();
        let (ensure, seek) = (
            result.label_ip(&ensure).unwrap(),
            result.label_ip(&seek).unwrap(),
        );
        (result.inner.code_buffer, ensure, seek)
    }

    #[test]
    fn decodes_both_buffer_calls() {
        for (bitness, (code, ensure, seek)) in [(64, loader64(0x80)), (32, loader32())] {
            assert_eq!(
                decode(bitness, BASE as usize, &code, BASE as usize),
                Ok(KeyBufferCalls {
                    ensure_capacity: ensure as usize,
                    seek_put: seek as usize,
                })
            );
        }
    }

    #[test]
    fn rejects_a_loader_without_the_key_capacity() {
        let (code, _, _) = loader64(0x40);
        assert!(decode(64, BASE as usize, &code, BASE as usize).is_err());
    }
}
