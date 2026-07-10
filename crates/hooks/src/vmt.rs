use tracing::{debug, error, info};

/// Swap a vtable slot pointer and return the original value.
///
/// # Safety
/// `this` must point to a valid C++ object with a vtable pointer as its first field.
/// `slot` must be within the vtable bounds. The replacement function must match the
/// slot's calling convention and signature.
pub unsafe fn swap_vtable_slot(
    name: &str,
    this: *mut std::ffi::c_void,
    slot: usize,
    replacement: usize,
) -> Option<usize> {
    if this.is_null() {
        error!(hook = name, "VMT swap failed: this is null");
        return None;
    }

    // SAFETY: this points to a C++ object; first field is vtable pointer.
    let vtable = unsafe { *(this as *const *const usize) };
    if vtable.is_null() {
        error!(hook = name, "VMT swap failed: vtable is null");
        return None;
    }

    // SAFETY: reading the original slot value.
    let slot_ptr = unsafe { vtable.add(slot) };
    // SAFETY: slot_ptr was derived from the validated vtable and slot index.
    let original = unsafe { *slot_ptr };

    debug!(
        hook = name,
        slot = slot,
        original = format_args!("0x{:x}", original),
        "vtable slot read"
    );

    // SAFETY: write to vtable slot. Need mprotect since .data.rel.ro may be read-only.
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let slot_addr = slot_ptr as usize;
        let page_start = slot_addr & !(page_size - 1);
        let page_end =
            (slot_addr + std::mem::size_of::<usize>() + page_size - 1) & !(page_size - 1);
        let region_size = page_end - page_start;

        if libc::mprotect(
            page_start as *mut libc::c_void,
            region_size,
            libc::PROT_READ | libc::PROT_WRITE,
        ) != 0
        {
            error!(hook = name, "mprotect(RW) failed for VMT swap");
            return None;
        }

        *(slot_ptr as *mut usize) = replacement;

        if libc::mprotect(
            page_start as *mut libc::c_void,
            region_size,
            libc::PROT_READ,
        ) != 0
        {
            error!(hook = name, "mprotect(R) restore failed after VMT swap");
        }
    }

    info!(hook = name, slot = slot, "VMT hook INSTALLED");
    Some(original)
}
