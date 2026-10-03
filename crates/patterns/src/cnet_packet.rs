//! Field offsets of Steam's `CNetPacket`, read from the functions that fill it.
//!
//! These fields sit at different offsets in different builds, so they are not
//! pinned. `Init` stores its arguments straight into the packet, `Release`
//! decrements the refcount first thing, and `Alloc` passes the object size to
//! Steam's allocator; each of those is stable in meaning even where the code
//! around it is not.
//!
//! The runtime and the offline scan both decode through here, so what the scan
//! reports is what the hooks will use.

use crate::arg_flow::{self, Value};
use iced_x86::Mnemonic;

const INIT_WINDOW: usize = 0x200;
const RELEASE_WINDOW: usize = 0x40;
const ALLOC_WINDOW: usize = 0x80;
/// Well past the largest packet seen, and small enough to reject a store into
/// something that is not a packet.
const MAX_FIELD_END: usize = 0x100;
const MIN_OBJECT_SIZE: usize = 0x10;
const MAX_OBJECT_SIZE: usize = 0x400;

/// Offsets `CNetPacket::Init(packet, conn_id, data, size, owned_data, add_ref)`
/// stores its arguments at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketFields {
    pub conn_id: usize,
    pub data: usize,
    pub size: usize,
    pub owned_data: usize,
}

impl PacketFields {
    /// Offset and width of each field, for a target with `pointer_size`-byte pointers.
    pub fn spans(&self, pointer_size: usize) -> [(usize, usize); 4] {
        [
            (self.conn_id, 4),
            (self.data, pointer_size),
            (self.size, 4),
            (self.owned_data, pointer_size),
        ]
    }

    /// One past the last byte any field occupies.
    pub fn end(&self, pointer_size: usize) -> usize {
        self.spans(pointer_size)
            .iter()
            .map(|(offset, width)| offset + width)
            .max()
            .unwrap_or(0)
    }
}

/// Everything native packet injection relies on, checked against itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketApi {
    pub fields: PacketFields,
    pub refcount: usize,
    pub object_size: usize,
}

/// Read the field offsets from `CNetPacket::Init` at `offset` in `code`.
pub fn decode_init(bitness: u32, code: &[u8], offset: usize) -> Result<PacketFields, &'static str> {
    let pointer_size = bitness as usize / 8;
    let trace = arg_flow::trace(bitness, code, offset, INIT_WINDOW);
    let field = |argument: u8, width: usize, label: &'static str| {
        let mut offsets: Vec<(i64, usize)> = trace
            .stores
            .iter()
            .filter(|store| {
                store.object == Value::Arg(0) && store.value == Some(Value::Arg(argument))
            })
            .map(|store| (store.offset, store.width))
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        // Two different destinations for one argument means the walk crossed
        // into code it does not understand; neither can be trusted.
        match offsets[..] {
            [(offset, stored)] if stored == width => usize::try_from(offset)
                .ok()
                .filter(|offset| offset % width == 0 && offset + width <= MAX_FIELD_END)
                .ok_or(label),
            _ => Err(label),
        }
    };
    let fields = PacketFields {
        conn_id: field(1, 4, "connection id store")?,
        data: field(2, pointer_size, "data pointer store")?,
        size: field(3, 4, "size store")?,
        owned_data: field(4, pointer_size, "owned buffer store")?,
    };
    if overlaps(&fields.spans(pointer_size)) {
        return Err("distinct packet fields");
    }
    Ok(fields)
}

/// Read the refcount offset from `CNetPacket::Release` at `offset` in `code`.
pub fn decode_release(bitness: u32, code: &[u8], offset: usize) -> Result<usize, &'static str> {
    const LABEL: &str = "refcount decrement";
    let trace = arg_flow::trace(bitness, code, offset, RELEASE_WINDOW);
    let update = trace
        .updates
        .iter()
        .find(|update| update.object == Value::Arg(0))
        .ok_or(LABEL)?;
    let decrements = match update.mnemonic {
        Mnemonic::Sub => update.operand == Some(1),
        Mnemonic::Add => update.operand == Some(-1),
        Mnemonic::Dec => true,
        _ => false,
    };
    if !decrements || update.width != 4 {
        return Err(LABEL);
    }
    usize::try_from(update.offset)
        .ok()
        .filter(|offset| offset % 4 == 0 && offset + 4 <= MAX_FIELD_END)
        .ok_or(LABEL)
}

/// Read the object size from `CNetPacket::Alloc` at `offset` in `code`.
pub fn decode_alloc(bitness: u32, code: &[u8], offset: usize) -> Result<usize, &'static str> {
    let trace = arg_flow::trace(bitness, code, offset, ALLOC_WINDOW);
    // Steam allocates through its allocator interface: an indirect call whose
    // first argument after `this` is the object size.
    let (allocation, size) = trace
        .calls
        .iter()
        .find_map(|call| match (call.target, call.args[1]) {
            (None, Some(Value::Imm(size))) => Some((call.ip, size)),
            _ => None,
        })
        .ok_or("allocator call with a constant size")?;
    let object = Value::Returned(allocation);
    if !trace
        .calls
        .iter()
        .any(|call| call.ip > allocation && call.target.is_some() && call.args[0] == Some(object))
    {
        return Err("constructor call on the allocation");
    }
    if trace.returned != Some(object) {
        return Err("allocation returned");
    }
    usize::try_from(size)
        .ok()
        .filter(|size| (MIN_OBJECT_SIZE..=MAX_OBJECT_SIZE).contains(size))
        .ok_or("plausible packet size")
}

/// Decode all three functions and require them to describe one object.
pub fn decode_api(
    bitness: u32,
    code: &[u8],
    alloc: usize,
    init: usize,
    release: usize,
) -> Result<PacketApi, &'static str> {
    let pointer_size = bitness as usize / 8;
    let fields = decode_init(bitness, code, init)?;
    let refcount = decode_release(bitness, code, release)?;
    let object_size = decode_alloc(bitness, code, alloc)?;
    let mut spans = fields.spans(pointer_size).to_vec();
    spans.push((refcount, 4));
    if overlaps(&spans) {
        return Err("refcount apart from the packet fields");
    }
    if fields.end(pointer_size).max(refcount + 4) > object_size {
        return Err("packet fields inside the allocation");
    }
    Ok(PacketApi {
        fields,
        refcount,
        object_size,
    })
}

fn overlaps(spans: &[(usize, usize)]) -> bool {
    spans.iter().enumerate().any(|(index, &(start, width))| {
        spans[index + 1..]
            .iter()
            .any(|&(other, other_width)| start < other + other_width && other < start + width)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::code_asm::*;

    /// Each region holds `Alloc`, `Init` and `Release` at these offsets.
    const ALLOC: usize = 0x00;
    const INIT: usize = 0x80;
    const RELEASE: usize = 0x180;

    /// Calls that leave the region: allocator lock, constructor, PIC thunk.
    const EXTERNAL: u64 = 0x0100_0000;
    /// Displacements off the i686 PIC base; any full imm32 will do.
    const PIC_ADD: i32 = 0x003b_eb35;
    const GLOBAL: i32 = 0x08cc;

    const fn api(
        [conn_id, data, size, owned_data]: [usize; 4],
        refcount: usize,
        object_size: usize,
    ) -> PacketApi {
        PacketApi {
            fields: PacketFields {
                conn_id,
                data,
                size,
                owned_data,
            },
            refcount,
            object_size,
        }
    }

    /// The layouts either side of client build 1790380355.
    const X86_LAYOUT: PacketApi = api([0x00, 0x04, 0x08, 0x10], 0x0c, 0x20);
    const X86_GROWN_LAYOUT: PacketApi = api([0x00, 0x0c, 0x10, 0x18], 0x14, 0x38);
    const X64_LAYOUT: PacketApi = api([0x00, 0x08, 0x10, 0x18], 0x14, 0x30);
    const X64_GROWN_LAYOUT: PacketApi = api([0x00, 0x10, 0x18, 0x20], 0x1c, 0x58);

    fn displacement(offset: usize) -> i32 {
        offset as i32
    }

    /// `Alloc` through Steam's allocator interface, with the source line as a
    /// second constant argument that must not be taken for the size.
    fn x86_alloc(layout: &PacketApi) -> Vec<u8> {
        assemble(32, |a| {
            a.push(esi)?;
            a.push(ebx)?;
            a.call(EXTERNAL)?;
            a.add(ebx, PIC_ADD)?;
            a.sub(esp, 8)?;
            a.mov(eax, dword_ptr(ebx + GLOBAL))?;
            a.mov(eax, dword_ptr(eax))?;
            a.lea(ecx, ptr(ebx - 0x0010_0000))?;
            a.mov(edx, dword_ptr(eax))?;
            a.push(1)?;
            a.push(0)?;
            a.push(0x7bf)?;
            a.push(ecx)?;
            a.push(layout.object_size as i32)?;
            a.push(eax)?;
            a.call(dword_ptr(edx + 0x14))?;
            a.add(esp, 0x18)?;
            a.sub(esp, 0x0c)?;
            a.push(eax)?;
            a.mov(esi, eax)?;
            a.call(EXTERNAL)?;
            a.add(esp, 0x18)?;
            a.mov(eax, esi)?;
            a.pop(ebx)?;
            a.pop(esi)?;
            a.ret()
        })
    }

    fn x64_alloc(layout: &PacketApi) -> Vec<u8> {
        assemble(64, |a| {
            a.push(rbx)?;
            a.mov(rax, qword_ptr(rbx + GLOBAL))?;
            a.mov(r9d, 1)?;
            a.xor(r8d, r8d)?;
            a.mov(ecx, 0x7bf)?;
            a.mov(esi, layout.object_size as u32)?;
            a.mov(rdi, qword_ptr(rax))?;
            a.mov(rax, qword_ptr(rdi))?;
            a.call(qword_ptr(rax + 0x28))?;
            a.mov(rbx, rax)?;
            a.mov(rdi, rax)?;
            a.call(EXTERNAL)?;
            a.mov(rax, rbx)?;
            a.pop(rbx)?;
            a.ret()
        })
    }

    /// i686 `Init` with a frame pointer: arguments read through ebp and
    /// relayed through eax. `spill_data` is the steamrt build, which parks the
    /// data argument in a local first and stores it from there.
    fn x86_frame_init(layout: &PacketApi, spill_data: bool) -> Vec<u8> {
        let fields = layout.fields;
        let arg = |index: i32| ebp + (8 + 4 * index);
        assemble(32, |a| {
            let mut out = a.create_label();
            a.push(ebp)?;
            a.mov(ebp, esp)?;
            a.push(edi)?;
            a.call(EXTERNAL)?;
            a.add(edi, PIC_ADD)?;
            a.push(esi)?;
            a.push(ebx)?;
            a.sub(esp, 0x2c)?;
            // add_ref, or the data pointer on steamrt, kept in a local.
            a.mov(eax, dword_ptr(arg(if spill_data { 2 } else { 5 })))?;
            a.mov(esi, dword_ptr(arg(0)))?;
            a.mov(dword_ptr(ebp - 0x2c), eax)?;
            a.test(eax, eax)?;
            a.je(out)?;
            a.mov(ecx, dword_ptr(arg(3)))?;
            a.test(ecx, ecx)?;
            a.je(out)?;
            a.mov(eax, dword_ptr(arg(1)))?;
            a.mov(dword_ptr(esi + displacement(layout.object_size - 4)), 0)?;
            a.mov(dword_ptr(esi + displacement(fields.conn_id)), eax)?;
            if spill_data {
                a.mov(eax, dword_ptr(ebp - 0x2c))?;
            } else {
                a.mov(eax, dword_ptr(arg(2)))?;
            }
            a.mov(dword_ptr(esi + displacement(fields.data)), eax)?;
            a.mov(eax, dword_ptr(arg(3)))?;
            a.mov(dword_ptr(esi + displacement(fields.size)), eax)?;
            a.mov(eax, dword_ptr(arg(4)))?;
            a.mov(dword_ptr(esi + displacement(fields.owned_data)), eax)?;
            a.set_label(&mut out)?;
            a.lea(esp, ptr(ebp - 0x0c))?;
            a.pop(ebx)?;
            a.pop(esi)?;
            a.pop(edi)?;
            a.pop(ebp)?;
            a.ret()
        })
    }

    /// i686 `Init` without a frame pointer: arguments read through esp once
    /// the frame is set up, and stored straight from the registers holding them.
    fn x86_frameless_init(layout: &PacketApi) -> Vec<u8> {
        let fields = layout.fields;
        // Four pushes, the frame, and the return address.
        let arg = |index: i32| esp + (0x1c + 0x10 + 4 + 4 * index);
        assemble(32, |a| {
            let mut out = a.create_label();
            a.push(ebp)?;
            a.push(edi)?;
            a.push(esi)?;
            a.push(ebx)?;
            a.call(EXTERNAL)?;
            a.add(ebx, PIC_ADD)?;
            a.sub(esp, 0x1c)?;
            a.mov(eax, dword_ptr(arg(5)))?;
            a.mov(ebp, dword_ptr(arg(2)))?;
            a.mov(esi, dword_ptr(arg(0)))?;
            a.mov(ecx, dword_ptr(arg(1)))?;
            a.mov(edi, dword_ptr(arg(3)))?;
            a.mov(dword_ptr(esp + 4), eax)?;
            a.mov(edx, dword_ptr(arg(4)))?;
            a.test(ebp, ebp)?;
            a.je(out)?;
            a.test(edi, edi)?;
            a.je(out)?;
            a.mov(dword_ptr(esi + displacement(fields.conn_id)), ecx)?;
            a.mov(dword_ptr(esi + displacement(fields.owned_data)), edx)?;
            a.mov(dword_ptr(esi + displacement(fields.data)), ebp)?;
            a.mov(dword_ptr(esi + displacement(fields.size)), edi)?;
            a.mov(dword_ptr(esi + displacement(layout.object_size - 4)), 0)?;
            a.set_label(&mut out)?;
            a.add(esp, 0x1c)?;
            a.pop(ebx)?;
            a.pop(esi)?;
            a.pop(edi)?;
            a.pop(ebp)?;
            a.ret()
        })
    }

    /// x86_64 `Init`: arguments parked in callee-saved registers, one of which
    /// first holds the stack guard, with a computed value stored beside them.
    fn x64_init(layout: &PacketApi) -> Vec<u8> {
        let fields = layout.fields;
        assemble(64, |a| {
            let mut out = a.create_label();
            a.push(r15)?;
            a.mov(r15d, esi)?;
            a.push(r14)?;
            a.mov(r14, r8)?;
            a.push(r13)?;
            a.push(r12)?;
            a.mov(r12, rdx)?;
            a.push(rbp)?;
            a.mov(ebp, ecx)?;
            a.push(rbx)?;
            a.mov(rbx, rdi)?;
            a.sub(rsp, 0x18)?;
            a.test(rdx, rdx)?;
            a.mov(r13, qword_ptr(0x28).fs())?;
            a.mov(qword_ptr(rsp + 8), r13)?;
            a.mov(r13d, r9d)?;
            a.je(out)?;
            a.test(ebp, ebp)?;
            a.je(out)?;
            a.mov(dword_ptr(rbx + displacement(fields.conn_id)), r15d)?;
            a.mov(qword_ptr(rbx + displacement(fields.data)), r12)?;
            a.mov(dword_ptr(rbx + displacement(fields.size)), ebp)?;
            a.mov(qword_ptr(rbx + displacement(fields.owned_data)), r14)?;
            a.mov(qword_ptr(rbx + displacement(layout.object_size - 8)), 0)?;
            a.movzx(eax, byte_ptr(r12))?;
            a.mov(dword_ptr(rbx + displacement(fields.conn_id + 4)), eax)?;
            a.set_label(&mut out)?;
            a.add(rsp, 0x18)?;
            a.pop(rbx)?;
            a.pop(rbp)?;
            a.pop(r12)?;
            a.pop(r13)?;
            a.pop(r14)?;
            a.pop(r15)?;
            a.ret()
        })
    }

    /// i686 `Release` behind a full prologue, so `this` is read off the stack.
    fn x86_release(layout: &PacketApi) -> Vec<u8> {
        assemble(32, |a| {
            let mut free = a.create_label();
            a.push(ebp)?;
            a.push(edi)?;
            a.push(esi)?;
            a.push(ebx)?;
            a.call(EXTERNAL)?;
            a.add(ebx, PIC_ADD)?;
            a.sub(esp, 0x2c)?;
            a.mov(edi, dword_ptr(esp + 0x40))?;
            a.sub(dword_ptr(edi + displacement(layout.refcount)), 1)?;
            a.je(free)?;
            a.add(esp, 0x2c)?;
            a.pop(ebx)?;
            a.pop(esi)?;
            a.pop(edi)?;
            a.pop(ebp)?;
            a.ret()?;
            a.set_label(&mut free)?;
            a.ud2()
        })
    }

    /// The compiler shapes seen across client builds, each with the layout it
    /// was observed with.
    fn shapes() -> [(&'static str, u32, Vec<u8>, PacketApi); 5] {
        let x86 = |init: fn(&PacketApi) -> Vec<u8>, layout: PacketApi| {
            region(&x86_alloc(&layout), &init(&layout), &x86_release(&layout))
        };
        let x64 = |layout: PacketApi| {
            region(
                &x64_alloc(&layout),
                &x64_init(&layout),
                &synthetic_release(displacement(layout.refcount)),
            )
        };
        [
            (
                "i686 with a frame pointer",
                32,
                x86(|layout| x86_frame_init(layout, false), X86_LAYOUT),
                X86_LAYOUT,
            ),
            (
                "i686 steamrt, data argument spilled",
                32,
                x86(|layout| x86_frame_init(layout, true), X86_LAYOUT),
                X86_LAYOUT,
            ),
            (
                "i686 without a frame pointer",
                32,
                x86(x86_frameless_init, X86_GROWN_LAYOUT),
                X86_GROWN_LAYOUT,
            ),
            ("x86_64", 64, x64(X64_LAYOUT), X64_LAYOUT),
            ("x86_64 grown", 64, x64(X64_GROWN_LAYOUT), X64_GROWN_LAYOUT),
        ]
    }

    #[test]
    fn decodes_every_compiler_shape() {
        for (shape, bitness, code, expected) in shapes() {
            assert_eq!(
                decode_api(bitness, &code, ALLOC, INIT, RELEASE),
                Ok(expected),
                "{shape}"
            );
        }
    }

    #[test]
    fn rejects_each_function_in_another_role() {
        for (shape, bitness, code, _) in shapes() {
            for offset in [ALLOC, RELEASE] {
                assert!(decode_init(bitness, &code, offset).is_err(), "{shape}");
            }
            for offset in [ALLOC, INIT] {
                assert!(decode_release(bitness, &code, offset).is_err(), "{shape}");
            }
            for offset in [INIT, RELEASE] {
                assert!(decode_alloc(bitness, &code, offset).is_err(), "{shape}");
            }
        }
    }

    fn assemble(
        bitness: u32,
        build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>,
    ) -> Vec<u8> {
        let mut assembler = CodeAssembler::new(bitness).unwrap();
        build(&mut assembler).unwrap();
        assembler.assemble(0).unwrap()
    }

    fn synthetic_alloc(size: u32) -> Vec<u8> {
        assemble(64, |a| {
            let mut constructor = a.create_label();
            a.push(rbx)?;
            a.mov(esi, size)?;
            a.call(qword_ptr(rax + 0x28))?;
            a.mov(rbx, rax)?;
            a.mov(rdi, rax)?;
            a.call(constructor)?;
            a.mov(rax, rbx)?;
            a.pop(rbx)?;
            a.ret()?;
            a.set_label(&mut constructor)?;
            a.ret()
        })
    }

    fn synthetic_init(extra: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>) -> Vec<u8> {
        assemble(64, |a| {
            a.mov(dword_ptr(rdi), esi)?;
            a.mov(qword_ptr(rdi + 0x08), rdx)?;
            a.mov(dword_ptr(rdi + 0x10), ecx)?;
            a.mov(qword_ptr(rdi + 0x18), r8)?;
            extra(a)?;
            a.ret()
        })
    }

    fn synthetic_release(refcount: i32) -> Vec<u8> {
        assemble(64, |a| {
            a.sub(dword_ptr(rdi + refcount), 1)?;
            a.ret()
        })
    }

    /// Lay the three functions out at the region offsets.
    fn region(alloc: &[u8], init: &[u8], release: &[u8]) -> Vec<u8> {
        let mut code = vec![0xcc; RELEASE + 0x40];
        code[ALLOC..ALLOC + alloc.len()].copy_from_slice(alloc);
        code[INIT..INIT + init.len()].copy_from_slice(init);
        code[RELEASE..RELEASE + release.len()].copy_from_slice(release);
        code
    }

    #[test]
    fn decodes_a_consistent_synthetic_packet() {
        let code = region(
            &synthetic_alloc(0x30),
            &synthetic_init(|_| Ok(())),
            &synthetic_release(0x14),
        );
        assert_eq!(
            decode_api(64, &code, ALLOC, INIT, RELEASE),
            Ok(api([0x00, 0x08, 0x10, 0x18], 0x14, 0x30))
        );
    }

    #[test]
    fn rejects_an_argument_stored_at_two_offsets() {
        let init = synthetic_init(|a| a.mov(qword_ptr(rdi + 0x20), rdx));
        assert_eq!(decode_init(64, &init, 0), Err("data pointer store"));
    }

    #[test]
    fn rejects_a_refcount_inside_a_field() {
        let code = region(
            &synthetic_alloc(0x30),
            &synthetic_init(|_| Ok(())),
            &synthetic_release(0x10),
        );
        assert_eq!(
            decode_api(64, &code, ALLOC, INIT, RELEASE),
            Err("refcount apart from the packet fields")
        );
    }

    #[test]
    fn rejects_fields_past_the_allocation() {
        let code = region(
            &synthetic_alloc(0x18),
            &synthetic_init(|_| Ok(())),
            &synthetic_release(0x14),
        );
        assert_eq!(
            decode_api(64, &code, ALLOC, INIT, RELEASE),
            Err("packet fields inside the allocation")
        );
    }
}
