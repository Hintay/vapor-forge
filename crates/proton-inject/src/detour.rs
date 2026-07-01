// x86_64 inline detour. Unsafe: direct memory patching.

use std::ptr;

// `mov rax, imm64; jmp rax` = 12 bytes. We steal at least this many
// prologue bytes, rounded up to the next instruction boundary.
const MIN_STOLEN: usize = 12;
const MAX_PROLOGUE_SCAN: usize = 32;

pub struct Detour {
    pub trampoline: usize,
}

impl Detour {
    /// Install a detour: overwrite `target` prologue with a jump to `hook`.
    /// Returns a Detour whose trampoline calls the original function.
    ///
    /// # Safety
    /// `target` must be a valid executable function address with a patchable prologue.
    pub unsafe fn install(target: usize, hook: usize) -> Option<Self> {
        let stolen = prologue_steal_bytes(target)?;
        let tramp = alloc_trampoline(stolen + 12)?; // stolen bytes + jmp back

        // Check for RIP-relative instructions in the stolen prologue.
        // The trampoline doesn't relocate addresses, so RIP-relative ops
        // would reference wrong memory from the new location.
        let prologue = unsafe { std::slice::from_raw_parts(target as *const u8, stolen) };
        if contains_rip_relative(prologue) {
            return None;
        }

        // Copy stolen prologue to trampoline
        unsafe {
            ptr::copy_nonoverlapping(target as *const u8, tramp as *mut u8, stolen);
        }

        // Append `mov rax, <target+stolen>; jmp rax` to trampoline
        let back_addr = target + stolen;
        write_abs_jmp(tramp + stolen, back_addr);

        // Make trampoline executable
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let tramp_page = tramp & !(page_size - 1);
        unsafe {
            libc::mprotect(
                tramp_page as *mut libc::c_void,
                page_size * 2,
                libc::PROT_READ | libc::PROT_EXEC,
            );
        }

        // Make target writable and patch it
        let target_page = target & !(page_size - 1);
        unsafe {
            if libc::mprotect(
                target_page as *mut libc::c_void,
                page_size * 2,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            ) != 0
            {
                return None;
            }
        }

        write_abs_jmp(target, hook);

        // NOP remaining stolen bytes after the jump
        for i in 12..stolen {
            unsafe { *((target + i) as *mut u8) = 0x90 };
        }

        // Restore target page to RX
        unsafe {
            libc::mprotect(
                target_page as *mut libc::c_void,
                page_size * 2,
                libc::PROT_READ | libc::PROT_EXEC,
            );
        }

        Some(Detour { trampoline: tramp })
    }
}

/// Write `mov rax, imm64; jmp rax` (12 bytes) at the given address.
fn write_abs_jmp(addr: usize, target: usize) {
    let p = addr as *mut u8;
    unsafe {
        *p = 0x48;            // REX.W
        *p.add(1) = 0xB8;    // MOV RAX, imm64
        ptr::copy_nonoverlapping(
            &target as *const usize as *const u8,
            p.add(2),
            8,
        );
        *p.add(10) = 0xFF;   // JMP
        *p.add(11) = 0xE0;   // RAX
    }
}

/// Determine how many bytes to steal from the prologue (>= MIN_STOLEN,
/// on an instruction boundary). Returns None if we can't determine.
fn prologue_steal_bytes(addr: usize) -> Option<usize> {
    let bytes = unsafe { std::slice::from_raw_parts(addr as *const u8, MAX_PROLOGUE_SCAN) };
    let mut pos = 0;
    while pos < MIN_STOLEN && pos < MAX_PROLOGUE_SCAN {
        let len = insn_length_x64(&bytes[pos..])?;
        pos += len;
    }
    if pos >= MIN_STOLEN { Some(pos) } else { None }
}

/// Minimal x86_64 instruction length decoder for common prologue patterns.
/// Returns the instruction length or None for unrecognized opcodes.
fn insn_length_x64(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }

    let mut i = 0;

    // REX prefix (0x40-0x4F)
    let has_rex = bytes[i] >= 0x40 && bytes[i] <= 0x4F;
    let rex = if has_rex { i += 1; bytes[i - 1] } else { 0 };
    let rex_w = rex & 0x08 != 0;

    if i >= bytes.len() {
        return None;
    }

    let op = bytes[i];
    i += 1;

    match op {
        // PUSH r64 (50-57) / POP r64 (58-5F)
        0x50..=0x5F => Some(i),
        // NOP
        0x90 => Some(i),
        // RET
        0xC3 => Some(i),
        // MOV r/m64, reg / MOV reg, r/m64
        0x89 | 0x8B => {
            i += modrm_length(&bytes[i..])?;
            Some(i)
        }
        // LEA reg, [r/m]
        0x8D => {
            i += modrm_length(&bytes[i..])?;
            Some(i)
        }
        // SUB r/m, imm8 (83 /5)
        0x83 => {
            i += modrm_length(&bytes[i..])?;
            i += 1; // imm8
            Some(i)
        }
        // SUB r/m, imm32 (81 /5)
        0x81 => {
            i += modrm_length(&bytes[i..])?;
            i += 4; // imm32
            Some(i)
        }
        // MOV r64, imm64 (B8-BF with REX.W)
        0xB8..=0xBF if rex_w => {
            i += 8; // imm64
            Some(i)
        }
        // MOV r32, imm32 (B8-BF without REX.W)
        0xB8..=0xBF => {
            i += 4; // imm32
            Some(i)
        }
        // XOR r/m, reg
        0x31 | 0x33 => {
            i += modrm_length(&bytes[i..])?;
            Some(i)
        }
        // TEST r/m, reg
        0x85 => {
            i += modrm_length(&bytes[i..])?;
            Some(i)
        }
        // CALL rel32 / JMP rel32
        0xE8 | 0xE9 => {
            i += 4; // rel32
            Some(i)
        }
        // Two-byte opcode (0F xx)
        0x0F => {
            if i >= bytes.len() { return None; }
            let op2 = bytes[i];
            i += 1;
            match op2 {
                // Jcc rel32
                0x80..=0x8F => {
                    i += 4;
                    Some(i)
                }
                // MOVZX, MOVSX
                0xB6 | 0xB7 | 0xBE | 0xBF => {
                    i += modrm_length(&bytes[i..])?;
                    Some(i)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Compute the length of a ModR/M + SIB + displacement sequence.
fn modrm_length(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let modrm = bytes[0];
    let md = modrm >> 6;
    let rm = modrm & 0x07;
    let mut len = 1; // ModR/M byte itself

    if md == 3 {
        // Register direct: no SIB, no disp
        return Some(len);
    }

    // Check for SIB byte
    if rm == 4 {
        len += 1; // SIB
    }

    match md {
        0 => {
            if rm == 5 {
                len += 4; // RIP-relative (disp32)
            }
            // SIB with base=5 and mod=0 also has disp32
            if rm == 4 && bytes.get(1).map_or(false, |&sib| sib & 0x07 == 5) {
                len += 4;
            }
        }
        1 => len += 1, // disp8
        2 => len += 4, // disp32
        _ => {}
    }

    Some(len)
}

/// Allocate RWX memory for the trampoline via mmap.
fn alloc_trampoline(size: usize) -> Option<usize> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let alloc_size = (size + page_size - 1) & !(page_size - 1);

    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            alloc_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        None
    } else {
        Some(ptr as usize)
    }
}

/// Scan stolen prologue bytes for RIP-relative addressing (mod=00, rm=5 in ModR/M).
/// These instructions reference memory relative to RIP; copying them to a
/// trampoline at a different address would make them access wrong memory.
/// Returns true if any such instruction is found.
fn contains_rip_relative(bytes: &[u8]) -> bool {
    let mut pos = 0;
    while pos < bytes.len() {
        let start = pos;

        // Skip REX prefix
        if bytes[pos] >= 0x40 && bytes[pos] <= 0x4F {
            pos += 1;
            if pos >= bytes.len() {
                break;
            }
        }

        let op = bytes[pos];
        pos += 1;

        // Instructions with ModR/M byte
        let has_modrm = matches!(
            op,
            0x01 | 0x03 | 0x09 | 0x0B
                | 0x21 | 0x23 | 0x29 | 0x2B
                | 0x31 | 0x33 | 0x39 | 0x3B
                | 0x63 | 0x69 | 0x6B
                | 0x81 | 0x83 | 0x85 | 0x87
                | 0x89 | 0x8B | 0x8D | 0x8F
                | 0xC7 | 0xD1 | 0xD3
                | 0xF7 | 0xFF
        );

        if has_modrm && pos < bytes.len() {
            let modrm = bytes[pos];
            let md = modrm >> 6;
            let rm = modrm & 0x07;

            // mod=00, rm=5 on x86_64 is [RIP+disp32]
            if md == 0 && rm == 5 {
                return true;
            }
        }

        // Also check CALL rel32 and JMP rel32: these are PC-relative
        // and would jump to wrong targets from the trampoline.
        if op == 0xE8 || op == 0xE9 {
            return true;
        }

        // Advance to next instruction using the length decoder
        match insn_length_x64(&bytes[start..]) {
            Some(len) => pos = start + len,
            None => break,
        }
    }
    false
}
