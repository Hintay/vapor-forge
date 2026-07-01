use retour::GenericDetour;
use steam_runtime_patterns::{follow_relative_call, Pattern};
use tracing::{debug, error, info, warn};

use crate::pic_thunk;

pub struct CodeRegion {
    pub base: usize,
    pub bytes: &'static [u8],
}

pub struct PendingDetour<F: retour::Function> {
    pub detour: GenericDetour<F>,
    pub callee_addr: usize,
}

pub fn resolve_callee(
    code: &CodeRegion,
    name: &str,
    pattern_str: &str,
    follow: bool,
) -> Option<usize> {
    let pattern = match Pattern::parse(pattern_str) {
        Ok(p) => p,
        Err(e) => {
            error!(hook = name, error = %e, "pattern parse failed");
            return None;
        }
    };

    let offset = match pattern.find_unique(code.bytes) {
        Ok(o) => o,
        Err(e) => {
            warn!(hook = name, error = %e, "pattern match failed");
            return None;
        }
    };

    if !follow {
        let addr = code.base + offset;
        debug!(
            hook = name,
            addr = format_args!("0x{:x}", addr),
            "pattern matched (prologue)"
        );
        return Some(addr);
    }

    match follow_relative_call(code.bytes, offset) {
        Ok(o) if o >= 0 && (o as usize) < code.bytes.len() => {
            let addr = code.base + o as usize;
            debug!(
                hook = name,
                addr = format_args!("0x{:x}", addr),
                "callee resolved"
            );
            Some(addr)
        }
        Ok(o) => {
            warn!(
                hook = name,
                offset = format_args!("0x{:x}", o),
                "callee offset out of bounds"
            );
            None
        }
        Err(e) => {
            error!(hook = name, error = %e, "follow relative call failed");
            None
        }
    }
}

/// Scan backward from a prologue address to find the PIC preamble entry point.
/// PIC functions on i686 start with `E8 rel32` (CALL thunk) + `ADD reg, imm32`
/// before the prologue. The ADD is 5 bytes (EAX, opcode 05) or 6 bytes (other
/// registers, opcode 81 Cx), giving a total preamble of 10 or 11 bytes.
pub fn find_pic_entry(prologue_addr: usize) -> Option<usize> {
    for offset in [10usize, 11] {
        if prologue_addr < offset {
            continue;
        }
        let candidate = prologue_addr - offset;
        // SAFETY: candidate is within the steamclient.so code segment.
        let byte = unsafe { *(candidate as *const u8) };
        if byte == 0xE8 {
            return Some(candidate);
        }
    }
    warn!(
        addr = format_args!("0x{:x}", prologue_addr),
        "find_pic_entry: no E8 CALL found before prologue"
    );
    None
}

/// Create a detour without enabling it.
///
/// # Safety
/// `target` must be a valid function pointer matching the signature `F`.
pub unsafe fn create_detour<F: retour::Function>(
    name: &str,
    target: F,
    callee_addr: usize,
    replacement: F,
) -> Option<PendingDetour<F>> {
    // Sanity check: reject obviously invalid target addresses.
    // During la_objopen, steamclient.so may not be fully relocated yet,
    // which can produce garbage addresses from pattern resolution.
    if callee_addr < 0x10000 {
        error!(
            hook = name,
            addr = format_args!("0x{:x}", callee_addr),
            "target address suspiciously low, skipping"
        );
        return None;
    }

    // SAFETY: caller guarantees target is valid.
    // Note: GenericDetour::new() does NOT overwrite the original function.
    // that only happens on enable(). So the original prologue is still
    // readable at callee_addr until finalize_detour calls enable().
    match unsafe { GenericDetour::new(target, replacement) } {
        Ok(detour) => {
            debug!(hook = name, "detour created");
            Some(PendingDetour {
                detour,
                callee_addr,
            })
        }
        Err(e) => {
            error!(hook = name, error = %e, "retour detour creation failed");
            None
        }
    }
}

/// Apply PIC-thunk repair to a trampoline and enable the detour.
///
/// # Safety
/// The detour must have been created and not yet enabled.
pub unsafe fn finalize_detour<F: retour::Function>(
    name: &str,
    detour: &mut GenericDetour<F>,
    callee_addr: usize,
) {
    let tramp_addr = detour.trampoline() as *const _ as usize;

    // Read the original prologue NOW, before enable() overwrites it.
    let mut prologue = [0u8; 16];
    // SAFETY: enable() hasn't been called yet, so callee_addr still has
    // the original function bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(callee_addr as *const u8, prologue.as_mut_ptr(), 16);
    }

    repair_pic_thunk(tramp_addr, callee_addr, &prologue);

    // SAFETY: enabling the detour.
    if let Err(e) = unsafe { detour.enable() } {
        error!(hook = name, error = %e, "detour enable failed");
        return;
    }
    info!(hook = name, "detour INSTALLED");
}

/// PIC thunk repair using the saved original prologue.
///
/// retour rewrites call instructions in the trampoline (changing their
/// displacement to point at retour's own thunk stubs). We cannot rely on
/// the trampoline's call targets to identify PIC thunks. Instead, scan the
/// saved original prologue to find call-to-thunk patterns, then verify the
/// trampoline has an E8 (call) at the same offset before patching.
fn repair_pic_thunk(tramp_addr: usize, callee_addr: usize, original_prologue: &[u8; 16]) {
    // SAFETY: reading trampoline bytes.
    let tramp_bytes = unsafe { std::slice::from_raw_parts(tramp_addr as *const u8, 64) };

    // Scan the ORIGINAL prologue (pre-retour) for PIC thunk calls.
    // The original call targets (PIC thunk functions) are still intact in
    // steamclient.so. Only the function's own prologue bytes were overwritten.
    let result = pic_thunk::find_pic_thunk_call(original_prologue, callee_addr as u32, &|addr| {
        let ptr = addr as usize as *const u8;
        if ptr.is_null() {
            return None;
        }
        // SAFETY: PIC thunk is a small function elsewhere in the module,
        // not affected by retour's prologue overwrite.
        Some(unsafe { [*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)] })
    });

    let Ok(site) = result else { return };

    let offset = site.offset_in_buffer;
    let register = site.register;

    // Verify: the trampoline must have a call (E8) at this offset.
    if offset >= tramp_bytes.len() || tramp_bytes[offset] != 0xE8 {
        return;
    }

    let call_address = callee_addr as u32 + offset as u32;
    let plan = pic_thunk::plan_pic_thunk_repair(site, call_address);

    // SAFETY: making the trampoline writable for PIC repair.
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let page_start = tramp_addr & !(page_size - 1);
        if libc::mprotect(
            page_start as *mut libc::c_void,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        ) != 0
        {
            error!("PIC thunk repair: mprotect(RWX) failed");
            return;
        }
        let patch_ptr = (tramp_addr + offset) as *mut u8;
        for (i, &byte) in plan.patch_bytes.iter().enumerate() {
            *patch_ptr.add(i) = byte;
        }
        if libc::mprotect(
            page_start as *mut libc::c_void,
            page_size,
            libc::PROT_READ | libc::PROT_EXEC,
        ) != 0
        {
            warn!("PIC thunk repair: mprotect(RX) restore failed");
        }
    }
    info!(
        register = format_args!("{:?}", register),
        offset = offset,
        "PIC thunk repaired"
    );
}
