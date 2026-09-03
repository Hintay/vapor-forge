use core::ffi::c_void;

use tracing::debug;
use vapor_forge_config::AppId;
use vapor_forge_features::apps::AppAuthority;
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::detour_or_return;

use super::install::config;
use crate::pattern_resolver::CodeRegion;

pub(crate) const REQUIRES_LEGACY_CDKEY_NAME: &str = "IClientUser::RequiresLegacyCDKey";

/// `bool RequiresLegacyCDKey(AppId_t appId, bool *pbHasKey)`.
pub(crate) type RequiresLegacyCdKeyFn = unsafe extern "C" fn(*mut c_void, u32, *mut bool) -> bool;

pub(crate) static mut REQUIRES_LEGACY_CDKEY_DETOUR: Option<Detour<RequiresLegacyCdKeyFn>> = None;

/// Controlled apps never report a legacy CD key requirement. The launch flow
/// then skips its `GettingLegacyKey` task and no `ClientGetLegacyGameKey`
/// request is sent for them.
fn suppresses_legacy_cdkey(authority: AppAuthority) -> bool {
    authority.is_controlled()
}

// ---------------------------------------------------------------------------
// Hook: IClientUser::RequiresLegacyCDKey
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_requires_legacy_cdkey(
    this: *mut c_void,
    app_id: u32,
    has_key: *mut bool,
) -> bool {
    let original = detour_or_return!(
        REQUIRES_LEGACY_CDKEY_NAME,
        REQUIRES_LEGACY_CDKEY_DETOUR,
        false
    );
    if crate::capability::is_ready(crate::capability::Capability::LegacyCdKeyControl) {
        let cfg = config();
        let authority = vapor_forge_features::apps::classify_app(&cfg, AppId(app_id));
        if suppresses_legacy_cdkey(authority) {
            if !has_key.is_null() {
                // SAFETY: Steam passes a writable flag that the original function
                // also clears before returning.
                unsafe { *has_key = false };
            }
            debug!(
                app_id,
                "legacy-cdkey: controlled app reports no CD key requirement"
            );
            return false;
        }
    }
    // SAFETY: forwards Steam's untouched query with the original arguments.
    unsafe { original(this, app_id, has_key) }
}

// ---------------------------------------------------------------------------
// Implementation resolution behind the IClientUser vtable entry
// ---------------------------------------------------------------------------

/// Resolve the `CUser::RequiresLegacyCDKey` implementation behind the
/// IClientUser vtable entry. The shared resolver follows the `this`-adjusting
/// adapter thunk and validates the target; detouring the implementation also
/// covers Steam's direct internal callers.
pub(crate) fn resolve_implementation(code: &CodeRegion, entry: usize) -> Option<usize> {
    let offset = entry.checked_sub(code.base)?;
    let bitness = if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    };
    let implementation =
        vapor_forge_patterns::cuser_adapter::resolve_requires_legacy_cdkey_implementation(
            code.bytes,
            code.base as u64,
            offset,
            bitness,
        )?;
    code.base.checked_add(implementation)
}

#[cfg(test)]
mod tests {
    use super::{resolve_implementation, suppresses_legacy_cdkey};
    use crate::pattern_resolver::CodeRegion;
    use vapor_forge_config::AppCategory;
    use vapor_forge_features::apps::{AppAuthority, OwnershipState};

    const BASE: usize = 0x10_0000;

    #[cfg(target_pointer_width = "64")]
    const IMPLEMENTATION: &[u8] = &[
        0x41, 0x55, // push r13
        0x49, 0x89, 0xd4, // mov r12, rdx
        0xc6, 0x02, 0x00, // mov byte [rdx], 0
        0xc3, // ret
    ];
    #[cfg(target_pointer_width = "32")]
    const IMPLEMENTATION: &[u8] = &[
        0x55, // push ebp
        0x8b, 0x44, 0x24, 0x0c, // mov eax, [esp + 0xc]
        0xc6, 0x00, 0x00, // mov byte [eax], 0
        0xc3, // ret
    ];

    #[test]
    fn resolves_addresses_relative_to_the_code_base() {
        let mut bytes = vec![0xcc; 0x10];
        bytes.extend_from_slice(IMPLEMENTATION);
        let code = CodeRegion {
            base: BASE,
            bytes: Box::leak(bytes.into_boxed_slice()),
        };
        assert_eq!(
            resolve_implementation(&code, BASE + 0x10),
            Some(BASE + 0x10)
        );
        assert_eq!(resolve_implementation(&code, BASE - 1), None);
    }

    #[test]
    fn only_controlled_apps_are_suppressed() {
        let controlled = AppAuthority::Controlled {
            category: AppCategory::Inject,
            ownership: OwnershipState::Owned,
        };
        assert!(suppresses_legacy_cdkey(controlled));
        assert!(!suppresses_legacy_cdkey(AppAuthority::Uncontrolled));
    }
}
