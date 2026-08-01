use std::sync::atomic::{AtomicU8, Ordering};

use tracing::{debug, error, info};

use crate::plan::ValidatedHookTarget;

const INSTALL_IDLE: u8 = 0;
const INSTALLING: u8 = 1;
const INSTALLED: u8 = 2;
const DISABLED: u8 = 3;

pub struct InstallGate(AtomicU8);

impl Default for InstallGate {
    fn default() -> Self {
        Self::new()
    }
}

impl InstallGate {
    pub const fn new() -> Self {
        Self(AtomicU8::new(INSTALL_IDLE))
    }

    pub(crate) fn is_installed(&self) -> bool {
        self.0.load(Ordering::Acquire) == INSTALLED
    }

    pub fn is_settled(&self) -> bool {
        self.is_installed() || self.0.load(Ordering::Acquire) == DISABLED
    }

    pub fn begin(&self) -> Option<InstallAttempt<'_>> {
        self.0
            .compare_exchange(
                INSTALL_IDLE,
                INSTALLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()
            .map(|_| InstallAttempt {
                gate: self,
                committed: false,
            })
    }
}

pub struct InstallAttempt<'a> {
    gate: &'a InstallGate,
    committed: bool,
}

impl InstallAttempt<'_> {
    pub fn commit(mut self) {
        self.gate.0.store(INSTALLED, Ordering::Release);
        self.committed = true;
    }

    pub fn disable(mut self) {
        self.gate.0.store(DISABLED, Ordering::Release);
        self.committed = true;
    }
}

impl Drop for InstallAttempt<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.gate.0.store(INSTALL_IDLE, Ordering::Release);
        }
    }
}

/// Swap a vtable slot pointer and return the original value.
///
/// # Safety
/// `this` must point to a valid C++ object with a vtable pointer as its first field.
/// `slot` must be within the vtable bounds. The validated replacement function
/// must match the slot's calling convention and signature.
pub unsafe fn swap_vtable_slot(
    name: &str,
    this: *mut std::ffi::c_void,
    slot: usize,
    target: ValidatedHookTarget,
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
    if original != target.target_address {
        error!(
            hook = name,
            planned = format_args!("0x{:x}", target.target_address),
            actual = format_args!("0x{original:x}"),
            "VMT swap failed: slot changed after validation"
        );
        return None;
    }
    let replacement = target.replacement_address;

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

#[cfg(test)]
mod tests {
    use super::InstallGate;
    use crate::plan::{validate_hook_target, AddressRange, HookTargetInput};

    #[test]
    fn install_gate_retries_failure_and_commits_success() {
        let gate = InstallGate::new();
        {
            let _failed_attempt = gate.begin().expect("first attempt");
            assert!(gate.begin().is_none());
        }
        assert!(!gate.is_installed());

        gate.begin().expect("retry after failure").commit();
        assert!(gate.is_installed());
        assert!(gate.is_settled());
        assert!(gate.begin().is_none());
    }

    #[test]
    fn install_gate_distinguishes_disabled_from_installed() {
        let gate = InstallGate::new();
        gate.begin().unwrap().disable();
        assert!(gate.is_settled());
        assert!(!gate.is_installed());
        assert!(gate.begin().is_none());
    }

    #[test]
    fn swap_rejects_a_slot_that_changed_after_validation() {
        let vtable = [0x1200usize];
        let object_vtable = vtable.as_ptr();
        let this = std::ptr::addr_of!(object_vtable) as *mut std::ffi::c_void;
        let target = validate_hook_target(HookTargetInput {
            target_address: 0x1100,
            replacement_address: 0x2000,
            executable_range: AddressRange {
                start: 0x1000,
                end: 0x1800,
            },
        })
        .unwrap();

        // SAFETY: `this` points to a test-owned object with one readable slot;
        // the mismatch returns before any memory protection or write occurs.
        let result = unsafe { super::swap_vtable_slot("test", this, 0, target) };

        assert_eq!(result, None);
        assert_eq!(vtable[0], 0x1200);
    }
}
