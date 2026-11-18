//! HTTP request fields shared by the live hook and offline validation.
//!
//! The streaming consumer identifies the handler independently of the request
//! constructor. Both must describe the same request tail before it is used.
//! On i686 the header and body consumers must agree on the handler, and the
//! rest of the tail sits at fixed distances below it: builds move the whole
//! tail together (handler 0x94 with host 0x58, handler 0xa0 with host 0x64).

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLayout64 {
    pub host: usize,
    pub path: usize,
    pub body_data: usize,
    pub body_size: usize,
    pub download_handler: usize,
}

/// Recover the request tail from its constructor and both streaming callbacks.
/// Response headers may be owned indirectly or embedded in the response.
pub fn decode_request64(code: &[u8]) -> Result<RequestLayout64, &'static str> {
    let mut headers = Vec::new();
    let mut bodies = Vec::new();
    for (start, bytes) in code.windows(4).enumerate() {
        if bytes[0] == 0x48 && bytes[1] == 0x8b && bytes[2] & 0xc7 == 0x46 && bytes[3] == 0x68 {
            if let Some((handler, body)) = consumer(code, start) {
                let offsets = if body { &mut bodies } else { &mut headers };
                if !offsets.contains(&handler) {
                    offsets.push(handler);
                }
            }
        }
    }
    headers.retain(|handler| bodies.contains(handler));
    let mut layouts = Vec::new();
    for handler in headers {
        // The request tail contains two strings, a pointer, a CUtlBuffer,
        // and two callback pointers. Its constructor proves the string and
        // buffer positions; the consumers prove the streaming callback slot.
        let Some(host) = handler.checked_sub(0x60) else {
            continue;
        };
        let layout = RequestLayout64 {
            host,
            path: host + 8,
            body_data: host + 0x18,
            body_size: host + 0x2c,
            download_handler: handler,
        };
        if constructor(code, layout) {
            layouts.push(layout);
        }
    }
    match layouts.as_slice() {
        [layout] => Ok(*layout),
        [] => Err("HTTP request constructor and streaming consumers disagree"),
        _ => Err("HTTP request layout is ambiguous"),
    }
}

/// The i686 request tail, at fixed distances below the download handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLayout32 {
    pub host: usize,
    pub path: usize,
    pub body_data: usize,
    pub body_size: usize,
    pub download_handler: usize,
}

impl RequestLayout32 {
    fn from_handler(handler: usize) -> Option<Self> {
        Some(Self {
            host: handler.checked_sub(0x3c)?,
            path: handler.checked_sub(0x38)?,
            body_data: handler.checked_sub(0x30)?,
            body_size: handler.checked_sub(0x20)?,
            download_handler: handler,
        })
    }
}

/// Recover the i686 request tail from the header and body streaming
/// consumers, which must name the same download handler slot.
pub fn decode_request32(code: &[u8]) -> Result<RequestLayout32, &'static str> {
    let mut headers = Vec::new();
    let mut bodies = Vec::new();
    for (start, bytes) in code.windows(3).enumerate() {
        // mov r32, [r32 + 0x50]: the handle's request pointer.
        if bytes[0] == 0x8b
            && bytes[1] & 0xc0 == 0x40
            && bytes[1] & 0x07 != 0x04
            && bytes[2] == 0x50
        {
            if let Some((handler, body)) = consumer32(code, start) {
                let offsets = if body { &mut bodies } else { &mut headers };
                if !offsets.contains(&handler) {
                    offsets.push(handler);
                }
            }
        }
    }
    headers.retain(|handler| bodies.contains(handler));
    match headers.as_slice() {
        [handler] => {
            RequestLayout32::from_handler(*handler).ok_or("HTTP request handler slot is too low")
        }
        [] => Err("HTTP header and body consumers disagree"),
        _ => Err("HTTP request layout is ambiguous"),
    }
}

fn consumer32(code: &[u8], start: usize) -> Option<(usize, bool)> {
    use Origin::*;
    let mut instructions = {
        let tail = code.get(start..)?;
        Decoder::with_ip(
            32,
            &tail[..tail.len().min(0x50)],
            start as u64,
            DecoderOptions::NONE,
        )
        .into_iter()
        .take_while(|i| !i.is_invalid())
    };
    let first = instructions.next()?;
    if first.mnemonic() != Mnemonic::Mov
        || first.op0_kind() != OpKind::Register
        || first.op1_kind() != OpKind::Memory
        || first.memory_index() != Register::None
        || first.memory_displacement64() != 0x50
    {
        return None;
    }
    let mut registers = std::collections::HashMap::from([
        (first.memory_base(), Handle),
        (first.op0_register(), Request),
    ]);
    let mut headers_pushed = false;
    let mut handler_pushed = None;
    for i in instructions {
        if matches!(
            i.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Call
        ) {
            break;
        }
        if i.flow_control() == FlowControl::IndirectCall {
            let Some(Vtable(handler)) = registers.get(&i.memory_base()).copied() else {
                break;
            };
            if i.op0_kind() != OpKind::Memory
                || i.memory_index() != Register::None
                || handler_pushed != Some(handler)
            {
                break;
            }
            return match i.memory_displacement64() {
                0x18 if headers_pushed => Some((handler, false)),
                0x1c => Some((handler, true)),
                _ => None,
            };
        }
        if i.mnemonic() == Mnemonic::Push {
            match i.op0_kind() {
                OpKind::Register => match registers.get(&i.op0_register()) {
                    Some(Headers) => headers_pushed = true,
                    Some(Handler(handler)) => handler_pushed = Some(*handler),
                    _ => {}
                },
                OpKind::Memory => {
                    headers_pushed |= registers.get(&i.memory_base()) == Some(&Response)
                        && i.memory_index() == Register::None
                        && i.memory_displacement64() == 0x38;
                }
                _ => {}
            }
            continue;
        }
        if i.op0_kind() != OpKind::Register {
            continue;
        }
        let mut value = None;
        if matches!(i.mnemonic(), Mnemonic::Mov | Mnemonic::Lea)
            && i.op1_kind() == OpKind::Memory
            && i.memory_index() == Register::None
        {
            let offset = i.memory_displacement64() as usize;
            value = match (i.mnemonic(), registers.get(&i.memory_base()), offset) {
                (Mnemonic::Mov, Some(Handle), 0x50) => Some(Request),
                (Mnemonic::Mov, Some(Request), offset)
                    if (0x80..0x120).contains(&offset) && offset % 4 == 0 =>
                {
                    Some(Handler(offset))
                }
                (Mnemonic::Mov, Some(Handle), 0x54) => Some(Response),
                (Mnemonic::Lea, Some(Response), 0x38) => Some(Headers),
                (Mnemonic::Mov, Some(Handler(offset)), 0) => Some(Vtable(*offset)),
                _ => None,
            };
        } else if i.mnemonic() == Mnemonic::Mov && i.op1_kind() == OpKind::Register {
            value = registers.get(&i.op1_register()).copied();
        }
        if matches!(i.mnemonic(), Mnemonic::Test | Mnemonic::Cmp) {
            continue;
        }
        let register = i.op0_register().full_register32();
        registers.remove(&register);
        if i.op0_register() == register {
            if let Some(value) = value {
                registers.insert(register, value);
            }
        }
    }
    None
}

fn instructions(code: &[u8], start: usize, limit: usize) -> Vec<Instruction> {
    let Some(tail) = code.get(start..) else {
        return Vec::new();
    };
    Decoder::with_ip(
        64,
        &tail[..tail.len().min(limit)],
        start as u64,
        DecoderOptions::NONE,
    )
    .into_iter()
    .take_while(|i| !i.is_invalid())
    .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Origin {
    Handle,
    Request,
    Handler(usize),
    Response,
    Headers,
    Vtable(usize),
    Buffer,
}

fn consumer(code: &[u8], start: usize) -> Option<(usize, bool)> {
    use Origin::*;
    // The body buffer arrives in whichever callee-saved register the build
    // keeps it in; RBX in steamrt builds, R13 in older ordinary builds.
    let mut registers = std::collections::HashMap::from([
        (Register::RSI, Handle),
        (Register::RBX, Buffer),
        (Register::RBP, Buffer),
        (Register::R12, Buffer),
        (Register::R13, Buffer),
        (Register::R14, Buffer),
        (Register::R15, Buffer),
    ]);
    for i in instructions(code, start, 0x70) {
        if matches!(
            i.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Call
        ) {
            break;
        }
        if i.flow_control() == FlowControl::IndirectCall {
            let Some(Vtable(handler)) = registers.get(&i.memory_base()).copied() else {
                break;
            };
            if i.op0_kind() != OpKind::Memory
                || i.memory_index() != Register::None
                || registers.get(&Register::RDI) != Some(&Handler(handler))
                || registers.get(&Register::RSI) != Some(&Handle)
            {
                break;
            }
            return match (i.memory_displacement64(), registers.get(&Register::RDX)) {
                (0x30, Some(Headers)) => Some((handler, false)),
                (0x38, Some(Buffer)) => Some((handler, true)),
                _ => None,
            };
        }
        let mut value = None;
        if i.op0_kind() == OpKind::Register {
            if i.mnemonic() == Mnemonic::Mov && i.op1_kind() == OpKind::Register {
                value = registers.get(&i.op1_register()).copied();
            } else if matches!(i.mnemonic(), Mnemonic::Mov | Mnemonic::Lea)
                && i.op1_kind() == OpKind::Memory
                && i.memory_index() == Register::None
            {
                let base = registers.get(&i.memory_base());
                let offset = i.memory_displacement64() as usize;
                value = match (i.mnemonic(), base, offset) {
                    (Mnemonic::Mov, Some(Handle), 0x68) => Some(Request),
                    (Mnemonic::Mov, Some(Request), offset)
                        if (0xc0..0x140).contains(&offset) && offset % 8 == 0 =>
                    {
                        Some(Handler(offset))
                    }
                    (Mnemonic::Mov, Some(Handle), 0x70) => Some(Response),
                    (_, Some(Response), 0x50) => Some(Headers),
                    (Mnemonic::Mov, Some(Handler(offset)), 0) => Some(Vtable(*offset)),
                    _ => None,
                };
            }
            // TEST/CMP read their operands; every other unmodelled destination
            // loses its origin, including writes through a 32-bit alias.
            if !matches!(
                i.mnemonic(),
                Mnemonic::Test | Mnemonic::Cmp | Mnemonic::Push
            ) {
                let register = i.op0_register().full_register();
                registers.remove(&register);
                if i.op0_register() == register {
                    if let Some(value) = value {
                        registers.insert(register, value);
                    }
                }
            }
        }
    }
    None
}

fn constructor(code: &[u8], layout: RequestLayout64) -> bool {
    // The constructor clears the host/path pair with one zeroed vector store.
    code.windows(2).enumerate().any(|(offset, bytes)| {
        if bytes != [0x0f, 0x11] {
            return false;
        }
        let start = if offset > 0 && code[offset - 1] & 0xf0 == 0x40 {
            offset - 1
        } else {
            offset
        };
        let tail = instructions(code, start, 0x90);
        let Some(store) = tail.first() else {
            return false;
        };
        if store.mnemonic() != Mnemonic::Movups
            || store.op0_kind() != OpKind::Memory
            || store.memory_index() != Register::None
            || store.memory_displacement64() as usize != layout.host
            || store.op1_register() != Register::XMM0
        {
            return false;
        }
        let base = store.memory_base();
        if matches!(base, Register::None | Register::RSP | Register::RIP) {
            return false;
        }
        // The buffer and path addresses may be formed before or after the
        // store, and either directly in RDI or in a register copied there, so
        // try every decode that lands exactly on the store. Older builds zero
        // XMM0 up to 0x46 bytes ahead of the store.
        (start.saturating_sub(0x60)..start).any(|begin| {
            let before = instructions(code, begin, start - begin);
            let lands = before.last().is_some_and(|i| i.next_ip() as usize == start);
            lands && constructor_sequence(code, &before, &tail, base, layout)
        })
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Field {
    BodyData,
    Path,
}

/// Track the body-data and path addresses through `before` (up to the vector
/// store) and `tail` (from it): the zeroing must precede the store, the first
/// call after it must construct the buffer at body data, and a later call must
/// receive the path.
fn constructor_sequence(
    code: &[u8],
    before: &[Instruction],
    tail: &[Instruction],
    base: Register,
    layout: RequestLayout64,
) -> bool {
    const CALLER_SAVED: [Register; 9] = [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
    ];
    let mut fields: std::collections::HashMap<Register, Field> = std::collections::HashMap::new();
    let mut zero = false;
    let mut buffer_call = false;
    for (index, i) in before.iter().chain(&tail[1..]).enumerate() {
        let after_store = index >= before.len();
        if i.flow_control() == FlowControl::Return {
            return false;
        }
        if i.mnemonic() == Mnemonic::Pxor
            && i.op0_register() == Register::XMM0
            && i.op1_register() == Register::XMM0
        {
            zero |= !after_store;
            continue;
        }
        if matches!(
            i.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            if !after_store {
                return false;
            }
            let rdi = fields.get(&Register::RDI).copied();
            if !buffer_call {
                if !zero
                    || rdi != Some(Field::BodyData)
                    || i.flow_control() != FlowControl::Call
                    || !buffer_constructor(code, i.near_branch_target() as usize)
                {
                    return false;
                }
                buffer_call = true;
            } else if rdi == Some(Field::Path) {
                return true;
            }
            for register in CALLER_SAVED {
                fields.remove(&register);
            }
            continue;
        }
        if i.op0_kind() != OpKind::Register {
            continue;
        }
        let destination = i.op0_register().full_register();
        let value = if i.mnemonic() == Mnemonic::Lea
            && i.memory_base() == base
            && i.memory_index() == Register::None
        {
            match i.memory_displacement64() as usize {
                offset if offset == layout.body_data => Some(Field::BodyData),
                offset if offset == layout.path => Some(Field::Path),
                _ => None,
            }
        } else if i.mnemonic() == Mnemonic::Mov && i.op1_kind() == OpKind::Register {
            fields.get(&i.op1_register().full_register()).copied()
        } else {
            None
        };
        if matches!(i.mnemonic(), Mnemonic::Test | Mnemonic::Cmp) {
            continue;
        }
        if destination == base {
            return false;
        }
        fields.remove(&destination);
        if let Some(value) = value {
            fields.insert(destination, value);
        }
    }
    false
}

fn buffer_constructor(code: &[u8], target: usize) -> bool {
    let body = instructions(code, target, 0x40);
    let clears = |offset, mnemonic| {
        body.iter().any(|i| {
            i.mnemonic() == mnemonic
                && i.op0_kind() == OpKind::Memory
                && i.memory_base() == Register::RDI
                && i.memory_index() == Register::None
                && i.memory_displacement64() == offset
        })
    };
    // CUtlBuffer's data pointer is at zero; its zeroed [8,24) contains Put at20.
    clears(0, Mnemonic::Mov)
        && clears(8, Mnemonic::Movups)
        && body.iter().any(|i| i.mnemonic() == Mnemonic::Ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::code_asm::*;

    fn fixture(host: i32, embedded_headers: bool, body_handler: i32) -> Vec<u8> {
        let mut a = CodeAssembler::new(64).unwrap();
        let mut buffer_ctor = a.create_label();
        let mut string_ctor = a.create_label();
        a.mov(rax, qword_ptr(rsi + 0x68)).unwrap();
        a.mov(rdi, qword_ptr(rax + host + 0x60)).unwrap();
        a.test(rdi, rdi).unwrap();
        a.mov(rax, qword_ptr(rsi + 0x70)).unwrap();
        if embedded_headers {
            a.lea(rdx, ptr(rax + 0x50)).unwrap();
        } else {
            a.mov(rdx, qword_ptr(rax + 0x50)).unwrap();
        }
        a.mov(rax, qword_ptr(rdi)).unwrap();
        a.call(qword_ptr(rax + 0x30)).unwrap();
        a.ret().unwrap();
        a.mov(rax, qword_ptr(rsi + 0x68)).unwrap();
        a.mov(rdi, qword_ptr(rax + body_handler)).unwrap();
        a.test(rdi, rdi).unwrap();
        a.mov(rax, qword_ptr(rdi)).unwrap();
        a.mov(rdx, rbx).unwrap();
        a.call(qword_ptr(rax + 0x38)).unwrap();
        a.ret().unwrap();
        a.lea(r13, ptr(rbx + host + 0x18)).unwrap();
        a.pxor(xmm0, xmm0).unwrap();
        a.mov(rdi, r13).unwrap();
        a.movups(xmmword_ptr(rbx + host), xmm0).unwrap();
        a.mov(qword_ptr(rbx + host + 0x10), 0).unwrap();
        a.call(buffer_ctor).unwrap();
        a.lea(rdi, ptr(rbx + host + 8)).unwrap();
        a.call(string_ctor).unwrap();
        a.ret().unwrap();
        a.set_label(&mut buffer_ctor).unwrap();
        a.pxor(xmm0, xmm0).unwrap();
        a.mov(qword_ptr(rdi), 0).unwrap();
        a.movups(xmmword_ptr(rdi + 8), xmm0).unwrap();
        a.ret().unwrap();
        a.set_label(&mut string_ctor).unwrap();
        a.ret().unwrap();
        a.assemble(0).unwrap()
    }

    /// Older ordinary builds keep the body buffer in R13, zero XMM0 before
    /// forming the buffer address, form the path address early in R14, and
    /// make unrelated calls between the buffer and path constructors.
    fn ordinary_fixture(host: i32) -> Vec<u8> {
        let handler = host + 0x60;
        let mut a = CodeAssembler::new(64).unwrap();
        let mut buffer_ctor = a.create_label();
        let mut string_ctor = a.create_label();
        let mut unrelated = a.create_label();
        a.mov(rax, qword_ptr(rsi + 0x68)).unwrap();
        a.mov(rdi, qword_ptr(rax + handler)).unwrap();
        a.test(rdi, rdi).unwrap();
        a.mov(rax, qword_ptr(rsi + 0x70)).unwrap();
        a.mov(rdx, qword_ptr(rax + 0x50)).unwrap();
        a.mov(rax, qword_ptr(rdi)).unwrap();
        a.call(qword_ptr(rax + 0x30)).unwrap();
        a.ret().unwrap();
        a.mov(rax, qword_ptr(rsi + 0x68)).unwrap();
        a.mov(rdi, qword_ptr(rax + handler)).unwrap();
        a.test(rdi, rdi).unwrap();
        a.mov(rax, qword_ptr(rdi)).unwrap();
        a.mov(rdx, r13).unwrap();
        a.call(qword_ptr(rax + 0x38)).unwrap();
        a.ret().unwrap();
        a.pxor(xmm0, xmm0).unwrap();
        a.lea(r15, ptr(rbx + host + 0x18)).unwrap();
        a.mov(rdi, r15).unwrap();
        a.lea(r14, ptr(rbx + host + 8)).unwrap();
        a.movups(xmmword_ptr(rbx + host), xmm0).unwrap();
        a.mov(qword_ptr(rbx + host + 0x10), 0).unwrap();
        a.call(buffer_ctor).unwrap();
        a.mov(edi, 0x20).unwrap();
        a.call(unrelated).unwrap();
        a.mov(rdi, rax).unwrap();
        a.call(unrelated).unwrap();
        a.mov(rdi, r14).unwrap();
        a.call(string_ctor).unwrap();
        a.ret().unwrap();
        a.set_label(&mut buffer_ctor).unwrap();
        a.pxor(xmm0, xmm0).unwrap();
        a.mov(qword_ptr(rdi), 0).unwrap();
        a.movups(xmmword_ptr(rdi + 8), xmm0).unwrap();
        a.ret().unwrap();
        a.set_label(&mut string_ctor).unwrap();
        a.ret().unwrap();
        a.set_label(&mut unrelated).unwrap();
        a.ret().unwrap();
        a.assemble(0).unwrap()
    }

    #[test]
    fn recovers_ordinary_request_layout() {
        assert_eq!(
            decode_request64(&ordinary_fixture(0x80)),
            Ok(RequestLayout64 {
                host: 0x80,
                path: 0x88,
                body_data: 0x98,
                body_size: 0xac,
                download_handler: 0xe0,
            })
        );
    }

    #[test]
    fn rejects_a_path_register_clobbered_by_a_call() {
        let code = ordinary_fixture(0x80);
        // Moving the path into a caller-saved register before the unrelated
        // calls must not count: the calls clobber it.
        let path = code
            .windows(4)
            .position(|w| w == [0x4c, 0x8d, 0xb3, 0x88])
            .unwrap();
        let mut broken = code.clone();
        broken[path..path + 3].copy_from_slice(&[0x48, 0x8d, 0x8b]);
        let copy = broken
            .windows(3)
            .position(|w| w == [0x4c, 0x89, 0xf7])
            .unwrap();
        broken[copy..copy + 3].copy_from_slice(&[0x48, 0x89, 0xcf]);
        assert!(decode_request64(&broken).is_err());
    }

    /// i686 header and body consumers. Older builds push the response's
    /// header field directly; newer ones form its address first.
    fn fixture32(handler: i32, embedded_headers: bool, body_handler: i32) -> Vec<u8> {
        let mut a = CodeAssembler::new(32).unwrap();
        a.mov(edx, dword_ptr(ecx + 8)).unwrap();
        a.mov(eax, dword_ptr(edx + 0x50)).unwrap();
        a.mov(eax, dword_ptr(eax + handler)).unwrap();
        a.test(eax, eax).unwrap();
        a.mov(edi, dword_ptr(edx + 0x54)).unwrap();
        a.sub(esp, 4).unwrap();
        a.mov(ebx, dword_ptr(eax)).unwrap();
        if embedded_headers {
            a.lea(ecx, ptr(edi + 0x38)).unwrap();
            a.push(ecx).unwrap();
        } else {
            a.push(dword_ptr(edi + 0x38)).unwrap();
        }
        a.push(edx).unwrap();
        a.push(eax).unwrap();
        a.call(dword_ptr(ebx + 0x18)).unwrap();
        a.ret().unwrap();
        a.mov(edx, dword_ptr(esi + 8)).unwrap();
        a.mov(eax, dword_ptr(edx + 0x50)).unwrap();
        a.mov(eax, dword_ptr(eax + body_handler)).unwrap();
        a.test(eax, eax).unwrap();
        a.mov(ecx, dword_ptr(eax)).unwrap();
        a.sub(esp, 4).unwrap();
        a.push(dword_ptr(ebp - 0x4c)).unwrap();
        a.push(edx).unwrap();
        a.push(eax).unwrap();
        a.call(dword_ptr(ecx + 0x1c)).unwrap();
        a.ret().unwrap();
        a.assemble(0).unwrap()
    }

    #[test]
    fn recovers_i686_request_layouts_from_both_consumer_shapes() {
        for (handler, embedded, host) in [(0x94, false, 0x58), (0xa0, true, 0x64)] {
            assert_eq!(
                decode_request32(&fixture32(handler, embedded, handler)),
                Ok(RequestLayout32 {
                    host,
                    path: host + 4,
                    body_data: host + 0xc,
                    body_size: host + 0x1c,
                    download_handler: handler as usize,
                })
            );
        }
    }

    #[test]
    fn rejects_i686_consumers_that_disagree() {
        assert!(decode_request32(&fixture32(0xa0, true, 0x94)).is_err());
    }

    #[test]
    fn rejects_an_i686_header_consumer_without_headers() {
        let mut a = CodeAssembler::new(32).unwrap();
        a.mov(edx, dword_ptr(ecx + 8)).unwrap();
        a.mov(eax, dword_ptr(edx + 0x50)).unwrap();
        a.mov(eax, dword_ptr(eax + 0xa0)).unwrap();
        a.mov(ebx, dword_ptr(eax)).unwrap();
        a.push(edx).unwrap();
        a.push(eax).unwrap();
        a.call(dword_ptr(ebx + 0x18)).unwrap();
        a.ret().unwrap();
        let code = a.assemble(0).unwrap();
        // Start at the request load after `mov edx, [ecx + 8]`.
        assert!(consumer32(&code, 3).is_none());
    }

    #[test]
    fn recovers_old_and_embedded_header_request_layouts() {
        for (host, embedded) in [(0x80, false), (0x90, true)] {
            let layout = decode_request64(&fixture(host, embedded, host + 0x60)).unwrap();
            assert_eq!(
                layout,
                RequestLayout64 {
                    host: host as usize,
                    path: host as usize + 8,
                    body_data: host as usize + 0x18,
                    body_size: host as usize + 0x2c,
                    download_handler: host as usize + 0x60,
                }
            );
        }
    }

    #[test]
    fn rejects_mismatched_header_and_body_handlers() {
        assert!(decode_request64(&fixture(0x90, true, 0xe8)).is_err());
    }

    #[test]
    fn rejects_ambiguous_request_layouts() {
        let mut code = fixture(0x80, false, 0xe0);
        code.extend(fixture(0x90, true, 0xf0));
        assert_eq!(
            decode_request64(&code),
            Err("HTTP request layout is ambiguous")
        );
    }

    #[test]
    fn rejects_unrelated_constructor_and_missing_buffer_constructor() {
        let mut code = fixture(0x90, true, 0xf0);
        let zero = code
            .windows(7)
            .position(|w| w == [0x48, 0xc7, 0x07, 0, 0, 0, 0])
            .unwrap();
        code[zero..zero + 7].fill(0x90);
        assert!(decode_request64(&code).is_err());
        let code = fixture(0x90, true, 0xf0);
        let constructor = code
            .windows(3)
            .position(|w| w == [0x4c, 0x8d, 0xab])
            .unwrap();
        assert!(decode_request64(&code[..constructor]).is_err());
    }

    #[test]
    fn rejects_clobbered_callback_arguments() {
        let code = fixture(0x90, true, 0xf0);
        let call = code
            .windows(3)
            .position(|w| w == [0xff, 0x50, 0x30])
            .unwrap();
        for clobber in [[0x31, 0xf6], [0x31, 0xff], [0x31, 0xd2], [0x31, 0xc0]] {
            let mut broken = code.clone();
            broken.splice(call..call, clobber);
            // Restore relative calls after insertion by testing the consumer
            // directly, independently of constructor call relocation.
            assert_eq!(consumer(&broken, 0), None);
        }
    }
}
