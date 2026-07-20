use tracing::error;

use crate::detour::{Detour, HookFn};

/// Look up a stored detour's original entry point from a hook callback.
///
/// Returns the trampoline as a plain function pointer of the hooked type, so
/// call sites invoke it directly and stay independent of the backend.
///
/// # Safety
/// `storage` must point at a process-lifetime detour slot that is initialized
/// before the hook is enabled and never moved afterward.
pub unsafe fn original_detour<F: HookFn>(
    hook: &str,
    storage: *const Option<Detour<F>>,
) -> Option<F> {
    // SAFETY: caller guarantees storage is a stable, initialized detour slot.
    let detour = unsafe { (*storage).as_ref() };
    let Some(detour) = detour else {
        error!(hook, "original detour missing, using fallback");
        return None;
    };
    // SAFETY: the trampoline stays mapped for the process lifetime and holds
    // the relocated prologue of a function with signature `F`.
    Some(unsafe { F::from_ptr(detour.trampoline() as *const ()) })
}

/// Look up a stored VMT original from a hook callback.
///
/// # Safety
/// `storage` must point at a process-lifetime function pointer slot that is
/// initialized before the VMT slot is swapped.
pub unsafe fn original_vmt<F: Copy>(hook: &str, storage: *const Option<F>) -> Option<F> {
    // SAFETY: caller guarantees storage is a stable, initialized VMT slot.
    let original = unsafe { *storage };
    if original.is_none() {
        error!(hook, "original VMT function missing, using fallback");
    }
    original
}

#[macro_export]
macro_rules! detour_or_return {
    ($hook:expr, $slot:ident) => {{
        let Some(original) =
            // SAFETY: hook installation initializes the process-lifetime slot
            // before enabling the corresponding detour.
            (unsafe { $crate::original::original_detour($hook, std::ptr::addr_of!($slot)) })
        else {
            return;
        };
        original
    }};
    ($hook:expr, $slot:ident, $fallback:expr) => {{
        let Some(original) =
            // SAFETY: hook installation initializes the process-lifetime slot
            // before enabling the corresponding detour.
            (unsafe { $crate::original::original_detour($hook, std::ptr::addr_of!($slot)) })
        else {
            return $fallback;
        };
        original
    }};
}

#[macro_export]
macro_rules! vmt_or_return {
    ($hook:expr, $slot:ident, $fallback:expr) => {{
        let Some(original) =
            // SAFETY: VMT installation stores the original function before
            // replacing the corresponding slot.
            (unsafe { $crate::original::original_vmt($hook, std::ptr::addr_of!($slot)) })
        else {
            return $fallback;
        };
        original
    }};
}

// `#[macro_export]` places these at the crate root; re-export them here so
// callers can reach them through the module path as well.
pub use crate::{detour_or_return, vmt_or_return};
