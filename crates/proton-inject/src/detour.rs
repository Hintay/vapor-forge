// x86_64 inline detour. Unsafe: direct memory patching.

use std::ptr;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Instruction, InstructionBlock,
};

// `jmp qword ptr [rip]; <address>` does not clobber a general-purpose register.
const ABS_JMP_LEN: usize = 14;
const MAX_PROLOGUE_SCAN: usize = 64;

pub struct PreparedDetour {
    target: usize,
    hook: usize,
    stolen: usize,
    trampoline: usize,
    allocation_size: usize,
    activated: bool,
}

impl PreparedDetour {
    /// Build a relocated trampoline without changing the target function.
    ///
    /// # Safety
    /// `target` must be a mapped executable function address.
    pub unsafe fn prepare(target: usize, hook: usize) -> Option<Self> {
        let readable = crate::maps::executable_span_at(target)?.min(MAX_PROLOGUE_SCAN);
        if readable < ABS_JMP_LEN {
            return None;
        }
        // SAFETY: executable_span_at verified that this range is inside an executable mapping.
        let prologue = unsafe { std::slice::from_raw_parts(target as *const u8, readable) };
        let (instructions, stolen) = decode_stolen(prologue, target as u64)?;

        let (trampoline, allocation_size) = alloc_trampoline()?;
        let encoded = match encode_block(&instructions, trampoline as u64) {
            Some(encoded) if encoded.len() + ABS_JMP_LEN <= allocation_size => encoded,
            _ => {
                free_trampoline(trampoline, allocation_size);
                return None;
            }
        };

        // SAFETY: trampoline is writable and large enough for both byte ranges.
        unsafe {
            ptr::copy_nonoverlapping(encoded.as_ptr(), trampoline as *mut u8, encoded.len());
            write_abs_jmp(trampoline + encoded.len(), target + stolen);
        }
        if !set_memory_protection(
            trampoline,
            encoded.len() + ABS_JMP_LEN,
            libc::PROT_READ | libc::PROT_EXEC,
        ) {
            free_trampoline(trampoline, allocation_size);
            return None;
        }

        Some(Self {
            target,
            hook,
            stolen,
            trampoline,
            allocation_size,
            activated: false,
        })
    }

    pub fn trampoline(&self) -> usize {
        self.trampoline
    }

    /// Activate the prepared jump after the caller has published `trampoline`.
    ///
    /// # Safety
    /// No other thread may execute the first `stolen` bytes of the target while
    /// this method changes them.
    pub unsafe fn activate(mut self) -> Option<Detour> {
        if !set_memory_protection(
            self.target,
            self.stolen,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        ) {
            return None;
        }

        // SAFETY: target is writable for `stolen` bytes and stolen >= ABS_JMP_LEN.
        unsafe {
            write_abs_jmp(self.target, self.hook);
            ptr::write_bytes(
                (self.target + ABS_JMP_LEN) as *mut u8,
                0x90,
                self.stolen - ABS_JMP_LEN,
            );
        }

        // Keep the hook usable even if restoring RX unexpectedly fails. Returning
        // None after patching would leave an active hook without publishing its
        // trampoline to the caller.
        let _ = set_memory_protection(self.target, self.stolen, libc::PROT_READ | libc::PROT_EXEC);

        self.activated = true;
        Some(Detour {
            trampoline: self.trampoline,
        })
    }
}

impl Drop for PreparedDetour {
    fn drop(&mut self) {
        if !self.activated {
            free_trampoline(self.trampoline, self.allocation_size);
        }
    }
}

pub struct Detour {
    pub trampoline: usize,
}

fn decode_stolen(bytes: &[u8], ip: u64) -> Option<(Vec<Instruction>, usize)> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    let mut stolen = 0usize;
    while stolen < ABS_JMP_LEN {
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.len() == 0 {
            return None;
        }
        stolen = instruction.next_ip().checked_sub(ip)? as usize;
        instructions.push(instruction);
    }
    Some((instructions, stolen))
}

fn encode_block(instructions: &[Instruction], new_ip: u64) -> Option<Vec<u8>> {
    let block = InstructionBlock::new(instructions, new_ip);
    BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
        .ok()
        .map(|result| result.code_buffer)
}

/// Write `jmp qword ptr [rip+0]` followed by an absolute 64-bit destination.
unsafe fn write_abs_jmp(address: usize, destination: usize) {
    let jump = [0xFF_u8, 0x25, 0x00, 0x00, 0x00, 0x00];
    // SAFETY: caller guarantees a writable ABS_JMP_LEN-byte destination.
    unsafe {
        ptr::copy_nonoverlapping(jump.as_ptr(), address as *mut u8, jump.len());
        ptr::copy_nonoverlapping(
            &destination as *const usize as *const u8,
            (address + jump.len()) as *mut u8,
            std::mem::size_of::<usize>(),
        );
    }
}

fn page_size() -> Option<usize> {
    // SAFETY: sysconf has no pointer preconditions.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (value > 0).then_some(value as usize)
}

fn page_range(address: usize, len: usize) -> Option<(usize, usize)> {
    let page_size = page_size()?;
    let start = address & !(page_size - 1);
    let end = address.checked_add(len)?.checked_add(page_size - 1)? & !(page_size - 1);
    Some((start, end.checked_sub(start)?))
}

fn set_memory_protection(address: usize, len: usize, protection: i32) -> bool {
    let Some((start, span)) = page_range(address, len) else {
        return false;
    };
    // SAFETY: start/span cover mapped pages supplied by the caller.
    unsafe { libc::mprotect(start as *mut libc::c_void, span, protection) == 0 }
}

fn alloc_trampoline() -> Option<(usize, usize)> {
    let allocation_size = page_size()?;
    // SAFETY: anonymous mmap ignores fd/offset and returns a fresh mapping.
    let mapped = unsafe {
        libc::mmap(
            ptr::null_mut(),
            allocation_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    (mapped != libc::MAP_FAILED).then_some((mapped as usize, allocation_size))
}

fn free_trampoline(address: usize, allocation_size: usize) {
    // SAFETY: address/allocation_size came from alloc_trampoline.
    unsafe {
        libc::munmap(address as *mut libc::c_void, allocation_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relocates_near_conditional_branch() {
        let mut bytes = vec![0x0F, 0x85, 0x10, 0x00, 0x00, 0x00];
        bytes.resize(ABS_JMP_LEN + 8, 0x90);
        let (instructions, _) = decode_stolen(&bytes, 0x1000).unwrap();
        let encoded = encode_block(&instructions, 0x2000).unwrap();
        let mut decoder = Decoder::with_ip(64, &encoded, 0x2000, DecoderOptions::NONE);
        let branch = decoder.decode();
        assert_eq!(branch.near_branch_target(), 0x1016);
    }

    #[test]
    fn page_range_uses_only_required_pages() {
        let page = page_size().unwrap();
        assert_eq!(page_range(page * 2 + 16, 14), Some((page * 2, page)));
        assert_eq!(
            page_range(page * 2 + page - 8, 14),
            Some((page * 2, page * 2))
        );
    }

    #[test]
    fn prepare_does_not_modify_target() {
        let page = page_size().unwrap();
        // SAFETY: mapping is test-owned and released before returning.
        let mapped = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED);
        let target = mapped as usize;
        // SAFETY: the mapping has at least one page of writable bytes.
        unsafe {
            ptr::write_bytes(target as *mut u8, 0x90, 32);
            *((target + 31) as *mut u8) = 0xC3;
        }
        // SAFETY: target is the executable mapping created above.
        let prepared = unsafe { PreparedDetour::prepare(target, target + 31) }.unwrap();
        // SAFETY: target remains mapped for the assertion.
        let bytes = unsafe { std::slice::from_raw_parts(target as *const u8, ABS_JMP_LEN) };
        assert!(bytes.iter().all(|byte| *byte == 0x90));
        drop(prepared);
        // SAFETY: mapped/page are the exact values returned by mmap.
        unsafe { libc::munmap(mapped, page) };
    }
}
