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

    /// Each fixture holds `Alloc`, `Init` and `Release` cut from one client
    /// build, at these offsets.
    const ALLOC: usize = 0x00;
    const INIT: usize = 0x80;
    const RELEASE: usize = 0x180;

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

    /// Frame-pointer i686, frame-pointer-free i686, the steamrt i686 build that
    /// spills the data argument to the stack before storing it, and x86_64
    /// either side of the layout change.
    const BUILDS: [(&str, u32, &[u8], PacketApi); 5] = [
        (
            "x86 1788652215",
            32,
            include_bytes!("testdata/cnet_packet/x86_1788652215.bin"),
            api([0x00, 0x04, 0x08, 0x10], 0x0c, 0x20),
        ),
        (
            "x86 1790380355",
            32,
            include_bytes!("testdata/cnet_packet/x86_1790380355.bin"),
            api([0x00, 0x0c, 0x10, 0x18], 0x14, 0x38),
        ),
        (
            "x86 steamrt 1788652215",
            32,
            include_bytes!("testdata/cnet_packet/x86_steamrt_1788652215.bin"),
            api([0x00, 0x04, 0x08, 0x10], 0x0c, 0x20),
        ),
        (
            "x86_64 1788652215",
            64,
            include_bytes!("testdata/cnet_packet/x86_64_1788652215.bin"),
            api([0x00, 0x08, 0x10, 0x18], 0x14, 0x30),
        ),
        (
            "x86_64 1790380355",
            64,
            include_bytes!("testdata/cnet_packet/x86_64_1790380355.bin"),
            api([0x00, 0x10, 0x18, 0x20], 0x1c, 0x58),
        ),
    ];

    #[test]
    fn decodes_every_captured_build() {
        for (build, bitness, code, expected) in BUILDS {
            assert_eq!(
                decode_api(bitness, code, ALLOC, INIT, RELEASE),
                Ok(expected),
                "{build}"
            );
        }
    }

    #[test]
    fn rejects_each_function_in_another_role() {
        for (build, bitness, code, _) in BUILDS {
            for offset in [ALLOC, RELEASE] {
                assert!(decode_init(bitness, code, offset).is_err(), "{build}");
            }
            for offset in [ALLOC, INIT] {
                assert!(decode_release(bitness, code, offset).is_err(), "{build}");
            }
            for offset in [INIT, RELEASE] {
                assert!(decode_alloc(bitness, code, offset).is_err(), "{build}");
            }
        }
    }

    fn assemble(build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>) -> Vec<u8> {
        let mut assembler = CodeAssembler::new(64).unwrap();
        build(&mut assembler).unwrap();
        assembler.assemble(0).unwrap()
    }

    fn synthetic_alloc(size: u32) -> Vec<u8> {
        assemble(|a| {
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
        assemble(|a| {
            a.mov(dword_ptr(rdi), esi)?;
            a.mov(qword_ptr(rdi + 0x08), rdx)?;
            a.mov(dword_ptr(rdi + 0x10), ecx)?;
            a.mov(qword_ptr(rdi + 0x18), r8)?;
            extra(a)?;
            a.ret()
        })
    }

    fn synthetic_release(refcount: i32) -> Vec<u8> {
        assemble(|a| {
            a.sub(dword_ptr(rdi + refcount), 1)?;
            a.ret()
        })
    }

    /// Lay the three functions out at the fixture offsets.
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
