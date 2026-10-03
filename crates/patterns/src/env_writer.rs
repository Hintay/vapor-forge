//! Calling convention of Steam's environment-map writer.
//!
//! `SetEnvString` took `(envMap, key, value)` up to public build 1788652215 and
//! `(envMap, key, value, flag, separator)` from 1790380355 on, on both
//! architectures. The hook both calls this function and detours it, so getting
//! the count wrong would hand a five-parameter callee three arguments.
//!
//! The count is read from the function itself rather than inferred from which
//! pattern matched: an argument a caller never passes would be read from the
//! caller's frame or a stale register, so a body that reads the fourth and fifth
//! is one that is passed them.

use crate::arg_flow;

/// Bytes decoded from the entry. The argument reads all sit in the opening
/// checks, well inside this.
const WINDOW: usize = 0x80;

/// The separator every observed call site passes, `':'`.
pub const PATH_SEPARATOR: u32 = 0x3a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvWriterAbi {
    /// `(envMap, key, value)`.
    KeyValue,
    /// `(envMap, key, value, flag, separator)`.
    KeyValueSeparator,
}

/// Classify the writer at `offset`, or `None` if its shape is neither form.
pub fn decode_abi(bitness: u32, code: &[u8], offset: usize) -> Option<EnvWriterAbi> {
    let trace = arg_flow::trace(bitness, code, offset, WINDOW);
    // The key is the one argument both forms must reach for.
    if !trace.arguments_read.contains(&1) {
        return None;
    }
    let extras = [3u8, 4]
        .iter()
        .filter(|position| trace.arguments_read.contains(position))
        .count();
    match extras {
        0 => Some(EnvWriterAbi::KeyValue),
        2 => Some(EnvWriterAbi::KeyValueSeparator),
        // One of the two alone means the walk lost track rather than a third
        // convention; refuse instead of guessing.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::code_asm::*;

    /// Calls that leave the entry: PIC thunk, hashing, map insertion.
    const EXTERNAL: u64 = 0x0100_0000;
    const PIC_ADD: i32 = 0x004b_2c57;

    fn assemble(
        bitness: u32,
        build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>,
    ) -> Vec<u8> {
        let mut assembler = CodeAssembler::new(bitness).unwrap();
        build(&mut assembler).unwrap();
        assembler.assemble(0).unwrap()
    }

    /// i686 `(envMap, key, value)`: the PIC thunk ahead of the frame, both
    /// strings null-checked, then the key hashed and inserted.
    fn x86_key_value() -> Vec<u8> {
        assemble(32, |a| {
            let mut out = a.create_label();
            a.call(EXTERNAL)?;
            a.add(eax, PIC_ADD)?;
            a.push(ebp)?;
            a.mov(ebp, esp)?;
            a.push(edi)?;
            a.push(esi)?;
            a.push(ebx)?;
            a.sub(esp, 0x5c)?;
            a.mov(dword_ptr(ebp - 0x34), eax)?;
            a.mov(eax, dword_ptr(ebp + 0x0c))?;
            a.test(eax, eax)?;
            a.je(out)?;
            a.mov(eax, dword_ptr(ebp + 0x10))?;
            a.test(eax, eax)?;
            a.je(out)?;
            a.mov(eax, dword_ptr(ebp + 8))?;
            a.mov(eax, dword_ptr(eax + 0x78))?;
            a.mov(ebx, dword_ptr(ebp - 0x34))?;
            a.sub(esp, 0x0c)?;
            a.push(dword_ptr(ebp + 0x0c))?;
            a.call(EXTERNAL)?;
            a.add(esp, 0x10)?;
            a.push(1)?;
            a.push(0x417)?;
            a.push(eax)?;
            a.push(dword_ptr(ebp + 0x0c))?;
            a.call(EXTERNAL)?;
            a.set_label(&mut out)?;
            a.lea(esp, ptr(ebp - 0x0c))?;
            a.pop(ebx)?;
            a.pop(esi)?;
            a.pop(edi)?;
            a.pop(ebp)?;
            a.ret()
        })
    }

    /// i686 `(envMap, key, value, flag, separator)`: the separator kept in a
    /// local, and the flag compared before the value is checked.
    fn x86_key_value_separator() -> Vec<u8> {
        assemble(32, |a| {
            let mut out = a.create_label();
            let mut checked = a.create_label();
            a.call(EXTERNAL)?;
            a.add(eax, PIC_ADD)?;
            a.push(ebp)?;
            a.mov(ebp, esp)?;
            a.push(edi)?;
            a.push(esi)?;
            a.push(ebx)?;
            a.sub(esp, 0x4c)?;
            a.mov(esi, dword_ptr(ebp + 0x0c))?;
            a.mov(edi, dword_ptr(ebp + 8))?;
            a.mov(dword_ptr(ebp - 0x2c), eax)?;
            a.mov(eax, dword_ptr(ebp + 0x18))?;
            a.mov(dword_ptr(ebp - 0x30), eax)?;
            a.test(esi, esi)?;
            a.je(out)?;
            a.cmp(dword_ptr(ebp + 0x14), 1)?;
            a.je(checked)?;
            a.mov(eax, dword_ptr(ebp + 0x10))?;
            a.test(eax, eax)?;
            a.je(out)?;
            a.set_label(&mut checked)?;
            a.mov(ebx, dword_ptr(ebp - 0x2c))?;
            a.lea(eax, ptr(ebp - 0x24))?;
            a.sub(esp, 8)?;
            a.push(dword_ptr(ebp + 0x10))?;
            a.push(eax)?;
            a.call(EXTERNAL)?;
            a.set_label(&mut out)?;
            a.lea(esp, ptr(ebp - 0x0c))?;
            a.pop(ebx)?;
            a.pop(esi)?;
            a.pop(edi)?;
            a.pop(ebp)?;
            a.ret()
        })
    }

    /// x86_64 `(envMap, key, value)`: arguments parked in callee-saved
    /// registers, and the insert's own constant arguments written into the
    /// fourth and fifth argument registers rather than read from them.
    fn x64_key_value() -> Vec<u8> {
        assemble(64, |a| {
            let mut out = a.create_label();
            a.push(r15)?;
            a.mov(r15, rdi)?;
            a.push(r13)?;
            a.push(rbx)?;
            a.mov(rbx, rsi)?;
            a.sub(rsp, 0x50)?;
            a.test(rsi, rsi)?;
            a.mov(r13, qword_ptr(0x28).fs())?;
            a.mov(qword_ptr(rsp + 0x48), r13)?;
            a.mov(r13, rdx)?;
            a.je(out)?;
            a.test(r13, r13)?;
            a.je(out)?;
            a.mov(eax, dword_ptr(r15 + 0xa4))?;
            a.mov(rdi, rbx)?;
            a.call(EXTERNAL)?;
            a.mov(ecx, 1)?;
            a.mov(rdi, rbx)?;
            a.mov(edx, 0x417)?;
            a.mov(rsi, rax)?;
            a.call(EXTERNAL)?;
            a.mov(qword_ptr(rsp + 0x18), r13)?;
            a.set_label(&mut out)?;
            a.add(rsp, 0x50)?;
            a.pop(rbx)?;
            a.pop(r13)?;
            a.pop(r15)?;
            a.ret()
        })
    }

    /// x86_64 `(envMap, key, value, flag, separator)`: the two extra arguments
    /// parked alongside the others and written into the stack entry.
    fn x64_key_value_separator() -> Vec<u8> {
        assemble(64, |a| {
            let mut out = a.create_label();
            let mut checked = a.create_label();
            a.push(r15)?;
            a.mov(r15, rdi)?;
            a.push(r13)?;
            a.push(r12)?;
            a.mov(r12d, ecx)?;
            a.push(rbp)?;
            a.mov(rbp, rdx)?;
            a.push(rbx)?;
            a.mov(rbx, rsi)?;
            a.sub(rsp, 0x50)?;
            a.test(rsi, rsi)?;
            a.mov(r13, qword_ptr(0x28).fs())?;
            a.mov(qword_ptr(rsp + 0x48), r13)?;
            a.mov(r13d, r8d)?;
            a.je(out)?;
            a.test(rbp, rbp)?;
            a.jne(checked)?;
            a.cmp(r12d, 1)?;
            a.jne(out)?;
            a.set_label(&mut checked)?;
            a.lea(rdi, ptr(rsp + 0x30))?;
            a.mov(rsi, rbp)?;
            a.call(EXTERNAL)?;
            a.mov(dword_ptr(rsp + 0x38), r12d)?;
            a.mov(byte_ptr(rsp + 0x3c), r13b)?;
            a.set_label(&mut out)?;
            a.add(rsp, 0x50)?;
            a.pop(rbx)?;
            a.pop(rbp)?;
            a.pop(r12)?;
            a.pop(r13)?;
            a.pop(r15)?;
            a.ret()
        })
    }

    #[test]
    fn classifies_both_conventions_on_both_architectures() {
        let shapes = [
            ("i686, three", 32, x86_key_value(), EnvWriterAbi::KeyValue),
            (
                "i686, five",
                32,
                x86_key_value_separator(),
                EnvWriterAbi::KeyValueSeparator,
            ),
            ("x86_64, three", 64, x64_key_value(), EnvWriterAbi::KeyValue),
            (
                "x86_64, five",
                64,
                x64_key_value_separator(),
                EnvWriterAbi::KeyValueSeparator,
            ),
        ];
        for (shape, bitness, code, expected) in shapes {
            assert_eq!(decode_abi(bitness, &code, 0), Some(expected), "{shape}");
        }
    }

    #[test]
    fn rejects_a_body_that_reads_only_one_extra_argument() {
        let code = assemble(64, |a| {
            a.mov(rbx, rsi)?;
            a.mov(r12d, ecx)?;
            a.ret()
        });
        assert_eq!(decode_abi(64, &code, 0), None);
    }

    #[test]
    fn rejects_a_body_that_never_reads_the_key() {
        // `ret` on both architectures: nothing is read, so nothing is claimed.
        assert_eq!(decode_abi(32, &[0xc3], 0), None);
        assert_eq!(decode_abi(64, &[0xc3], 0), None);
    }
}
