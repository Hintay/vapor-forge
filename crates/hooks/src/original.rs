use retour::GenericDetour;
use tracing::error;

/// Look up a stored detour original from a hook callback.
///
/// # Safety
/// `storage` must point at a process-lifetime detour slot that is initialized
/// before the hook is enabled and never moved afterward.
pub(crate) unsafe fn original_detour<F: retour::Function>(
    hook: &str,
    storage: *const Option<GenericDetour<F>>,
) -> Option<&'static GenericDetour<F>> {
    // SAFETY: caller guarantees storage is a stable, initialized detour slot.
    let detour = unsafe { (*storage).as_ref() };
    if detour.is_none() {
        error!(hook, "original detour missing, using fallback");
    }
    detour
}

/// Look up a stored VMT original from a hook callback.
///
/// # Safety
/// `storage` must point at a process-lifetime function pointer slot that is
/// initialized before the VMT slot is swapped.
pub(crate) unsafe fn original_vmt<F: Copy>(hook: &str, storage: *const Option<F>) -> Option<F> {
    // SAFETY: caller guarantees storage is a stable, initialized VMT slot.
    let original = unsafe { *storage };
    if original.is_none() {
        error!(hook, "original VMT function missing, using fallback");
    }
    original
}

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

pub(crate) use detour_or_return;
pub(crate) use vmt_or_return;
