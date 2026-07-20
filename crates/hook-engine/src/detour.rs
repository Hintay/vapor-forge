use retour::GenericDetour;
use std::sync::Mutex;
use tracing::{debug, error, info, warn};
use vapor_forge_patterns::registry::{FollowMode, PatternLookup, PatternVariantLookup};
use vapor_forge_patterns::{
    find_prologue_upwards, follow_last_call_before_ret, follow_relative_call, Pattern,
};

use vapor_forge_hook_boundary::pic_thunk;

static TRAMPOLINE_PAGES: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Function-pointer types the active backend can hook.
///
/// Callers bound their generics on this instead of naming the backend, so the
/// backend can be swapped per target architecture.
pub use retour::Function as HookFn;

/// An installed detour owning the patch and its trampoline.
///
/// Backend-specific; callers hold it opaquely and reach the original entry
/// point through [`crate::original::original_detour`].
pub type Detour<F> = GenericDetour<F>;

pub struct CodeRegion {
    pub base: usize,
    pub bytes: &'static [u8],
}

pub struct PendingDetour<F: HookFn> {
    pub detour: Detour<F>,
    pub callee_addr: usize,
}

pub fn resolve_pattern_entry(
    code: &CodeRegion,
    name: &str,
    entry: &PatternLookup<'_>,
) -> Option<usize> {
    for (variant_index, variant) in entry.variants().enumerate() {
        if let Some(addr) = resolve_pattern_variant(code, name, variant_index, variant) {
            return Some(addr);
        }
    }
    None
}

fn resolve_pattern_variant(
    code: &CodeRegion,
    name: &str,
    variant_index: usize,
    entry: PatternVariantLookup<'_>,
) -> Option<usize> {
    let addr = match entry.follow() {
        FollowMode::None => resolve_callee(code, name, entry.pattern(), false)?,
        FollowMode::Relative => resolve_callee(code, name, entry.pattern(), true)?,
        FollowMode::Upward => {
            let prologue = entry.prologue_bytes().or_else(|| {
                error!(
                    hook = name,
                    variant = variant_index,
                    "upward follow requires prologue bytes"
                );
                None
            })?;
            resolve_prologue_upwards(code, name, entry.pattern(), prologue)?
        }
        FollowMode::Call => resolve_follow_call(code, name, entry)?,
    };

    if entry.pic_entry() {
        find_pic_entry(addr)
    } else {
        Some(addr)
    }
}

fn resolve_callee(code: &CodeRegion, name: &str, pattern_str: &str, follow: bool) -> Option<usize> {
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

fn resolve_prologue_upwards(
    code: &CodeRegion,
    name: &str,
    body_pattern_str: &str,
    prologue_bytes: &[u8],
) -> Option<usize> {
    let body_pattern = match Pattern::parse(body_pattern_str) {
        Ok(p) => p,
        Err(e) => {
            error!(hook = name, error = %e, "body pattern parse failed");
            return None;
        }
    };

    let body_offset = match body_pattern.find_unique(code.bytes) {
        Ok(o) => o,
        Err(e) => {
            warn!(hook = name, error = %e, "body pattern match failed");
            return None;
        }
    };

    match find_prologue_upwards(code.bytes, body_offset, prologue_bytes, 0x10000) {
        Ok(entry_offset) => {
            let addr = code.base + entry_offset;
            debug!(
                hook = name,
                body = format_args!("0x{:x}", code.base + body_offset),
                entry = format_args!("0x{:x}", addr),
                "prologue resolved"
            );
            Some(addr)
        }
        Err(e) => {
            warn!(hook = name, error = %e, "prologue scan failed");
            None
        }
    }
}

fn resolve_follow_call(
    code: &CodeRegion,
    name: &str,
    entry: PatternVariantLookup<'_>,
) -> Option<usize> {
    let pattern = match Pattern::parse(entry.pattern()) {
        Ok(p) => p,
        Err(e) => {
            error!(hook = name, error = %e, "callsite pattern parse failed");
            return None;
        }
    };
    let callee_pattern = match entry.callee_pattern() {
        Some(pattern) => match Pattern::parse(pattern) {
            Ok(p) => Some(p),
            Err(e) => {
                error!(hook = name, error = %e, "callee pattern parse failed");
                return None;
            }
        },
        None => None,
    };

    let matches = pattern.find_all(code.bytes);
    if matches.is_empty() {
        warn!(hook = name, "callsite pattern match failed: no match");
        return None;
    }

    for offset in matches.iter().copied() {
        let Ok(callee_offset) = follow_last_call_before_ret(code.bytes, offset, 256) else {
            continue;
        };
        let addr = code.base + callee_offset;
        if let Some(callee_pattern) = callee_pattern.as_ref() {
            if !callee_pattern.matches_at(code.bytes, callee_offset) {
                continue;
            }
        }
        debug!(
            hook = name,
            match_addr = format_args!("0x{:x}", code.base + offset),
            match_count = matches.len(),
            addr = format_args!("0x{:x}", addr),
            "call target resolved"
        );
        return Some(addr);
    }

    warn!(
        hook = name,
        match_count = matches.len(),
        has_callee_pattern = callee_pattern.is_some(),
        "no matching call target found"
    );
    None
}

/// Scan backward from a prologue address to find the PIC preamble entry point.
/// PIC functions on i686 start with `E8 rel32` (CALL thunk) + `ADD reg, imm32`
/// before the prologue. The ADD is 5 bytes (EAX, opcode 05) or 6 bytes (other
/// registers, opcode 81 Cx), giving a total preamble of 10 or 11 bytes.
fn find_pic_entry(prologue_addr: usize) -> Option<usize> {
    if !cfg!(target_pointer_width = "32") {
        return Some(prologue_addr);
    }

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
pub unsafe fn create_detour<F: HookFn>(
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

    ensure_trampoline_pages_writable();

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

/// Restore all trampoline pages touched by PIC repair to RX.
///
/// Called after a loader-consistent install pass. A future create_detour call
/// will reopen these pages before asking retour to allocate again.
pub fn restore_trampoline_pages_rx() {
    set_trampoline_pages_protection(libc::PROT_READ | libc::PROT_EXEC, "RX");
}

/// Store a pending detour into its process-lifetime slot and finalize it.
///
/// Returns whether a detour was present and finalized.
///
/// # Safety
/// `storage` must point to a valid `Option<Detour<F>>` slot that lives
/// for the process lifetime.
pub unsafe fn store_and_finalize<F: HookFn>(
    name: &str,
    storage: *mut Option<Detour<F>>,
    pending: Option<PendingDetour<F>>,
) -> bool {
    let Some(p) = pending else { return false };
    let callee_addr = p.callee_addr;

    // SAFETY: storing detour before enable so hook callbacks can access it.
    unsafe { storage.write(Some(p.detour)) };

    // SAFETY: storage points to the slot we just initialized.
    unsafe {
        let Some(detour) = (*storage).as_mut() else {
            error!(hook = name, "stored detour missing after initialization");
            return false;
        };
        finalize_detour(name, detour, callee_addr);
    }
    true
}

fn ensure_trampoline_pages_writable() {
    set_trampoline_pages_protection(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, "RWX");
}

fn set_trampoline_pages_protection(protection: i32, label: &str) {
    let Ok(pages) = TRAMPOLINE_PAGES.lock() else {
        return;
    };
    if pages.is_empty() {
        return;
    }
    let page_size = page_size();
    let mut failures = 0usize;
    for &page_start in pages.iter() {
        // SAFETY: page_start values are page-aligned trampoline pages that
        // were previously accepted by mprotect during PIC repair.
        let rc = unsafe { libc::mprotect(page_start as *mut libc::c_void, page_size, protection) };
        if rc != 0 {
            failures += 1;
        }
    }
    if failures == 0 {
        debug!(
            pages = pages.len(),
            protection = label,
            "trampoline pages protected"
        );
    } else {
        warn!(
            pages = pages.len(),
            failures,
            protection = label,
            "trampoline page protection failed"
        );
    }
}

/// Apply PIC-thunk repair to a trampoline and enable the detour.
///
/// # Safety
/// The detour must have been created and not yet enabled.
pub(crate) unsafe fn finalize_detour<F: HookFn>(
    name: &str,
    detour: &mut Detour<F>,
    callee_addr: usize,
) {
    let tramp_addr = detour.trampoline() as *const _ as usize;
    remember_trampoline_page(trampoline_page_start(tramp_addr));

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
    if !cfg!(target_pointer_width = "32") {
        return;
    }

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
        let page_size = page_size();
        let page_start = trampoline_page_start(tramp_addr);
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
    }
    info!(
        register = format_args!("{:?}", register),
        offset = offset,
        "PIC thunk repaired"
    );
}

fn remember_trampoline_page(page_start: usize) {
    let Ok(mut pages) = TRAMPOLINE_PAGES.lock() else {
        return;
    };
    if !pages.contains(&page_start) {
        pages.push(page_start);
    }
}

fn trampoline_page_start(addr: usize) -> usize {
    let page_size = page_size();
    addr & !(page_size - 1)
}

fn page_size() -> usize {
    // SAFETY: sysconf is thread-safe and does not retain pointers.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}
