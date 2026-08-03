use retour::GenericDetour;
use std::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::plan::ValidatedHookTarget;

use crate::pic_thunk;

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

pub struct PendingDetour<F: HookFn> {
    pub detour: Detour<F>,
    pub callee_addr: usize,
}

/// Create a detour without enabling it.
///
/// # Safety
/// The validated target and replacement addresses must both point to functions
/// matching the signature `F`.
pub unsafe fn create_detour<F: HookFn>(
    name: &str,
    target: ValidatedHookTarget,
) -> Option<PendingDetour<F>> {
    let callee_addr = target.target_address;
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

    // SAFETY: caller guarantees the validated addresses use signature F.
    let target_fn = unsafe { F::from_ptr(target.target_address as *const ()) };
    // SAFETY: caller guarantees the validated addresses use signature F.
    let replacement_fn = unsafe { F::from_ptr(target.replacement_address as *const ()) };

    // SAFETY: caller guarantees both function pointers are valid.
    // Note: GenericDetour::new() does NOT overwrite the original function.
    // that only happens on enable(). So the original prologue is still
    // readable at callee_addr until finalize_detour calls enable().
    match unsafe { GenericDetour::new(target_fn, replacement_fn) } {
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
        finalize_detour(name, detour, callee_addr)
    }
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
) -> bool {
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
        return false;
    }
    info!(hook = name, "detour INSTALLED");
    true
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

    let Some(relocated_len) = trampoline_relocated_prefix_len32(
        tramp_bytes,
        tramp_addr as u32,
        callee_addr as u32,
        original_prologue.len(),
    ) else {
        return;
    };
    if !range_within_relocated_prefix(offset, 5, relocated_len) {
        return;
    }

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

fn trampoline_relocated_prefix_len32(
    trampoline: &[u8],
    trampoline_address: u32,
    callee_address: u32,
    original_window_len: usize,
) -> Option<usize> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};

    let original_end = callee_address.checked_add(original_window_len as u32)?;
    let mut decoder = Decoder::with_ip(
        32,
        trampoline,
        u64::from(trampoline_address),
        DecoderOptions::NONE,
    );
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return None;
        }
        if instruction.mnemonic() != Mnemonic::Jmp
            || !matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32
            )
        {
            continue;
        }
        let target = instruction.near_branch_target() as u32;
        if target > callee_address && target <= original_end {
            return Some(target.wrapping_sub(callee_address) as usize);
        }
    }
    None
}

fn range_within_relocated_prefix(offset: usize, len: usize, relocated_len: usize) -> bool {
    offset
        .checked_add(len)
        .is_some_and(|end| end <= relocated_len)
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

#[cfg(test)]
mod tests {
    use super::{range_within_relocated_prefix, trampoline_relocated_prefix_len32};

    fn append_return_jump(bytes: &mut Vec<u8>, trampoline_address: u32, target: u32) {
        let jump_address = trampoline_address + bytes.len() as u32;
        bytes.push(0xe9);
        bytes.extend_from_slice(&target.wrapping_sub(jump_address + 5).to_le_bytes());
    }

    #[test]
    fn measures_only_the_prefix_relocated_by_retour() {
        let trampoline_address = 0xf670_0054;
        let callee_address = 0xd22e_36b0;
        let mut bytes = vec![0x55, 0x89, 0xe5, 0x57, 0x56];
        append_return_jump(&mut bytes, trampoline_address, callee_address + 5);
        bytes.extend_from_slice(&[0xe8, 0, 0, 0, 0]);

        let relocated_len =
            trampoline_relocated_prefix_len32(&bytes, trampoline_address, callee_address, 16)
                .unwrap();
        assert_eq!(relocated_len, 5);
        assert!(!range_within_relocated_prefix(8, 5, relocated_len));
    }

    #[test]
    fn includes_a_pic_call_relocated_before_the_return_jump() {
        let trampoline_address = 0xf670_0054;
        let callee_address = 0xd22e_36b0;
        let mut bytes = vec![0x55, 0x57, 0x56, 0x53, 0xe8, 0, 0, 0, 0];
        append_return_jump(&mut bytes, trampoline_address, callee_address + 9);

        let relocated_len =
            trampoline_relocated_prefix_len32(&bytes, trampoline_address, callee_address, 16)
                .unwrap();
        assert_eq!(relocated_len, 9);
        assert!(range_within_relocated_prefix(4, 5, relocated_len));
    }
}
