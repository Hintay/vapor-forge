use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{debug, error};
use vapor_forge_hook_engine::detour::Detour;

use crate::pattern_resolver::CodeRegion;
use vapor_forge_hook_engine::detour::{self, PendingDetour};

pub(super) type GetPackageInfoHookFn = vapor_forge_steam_native_abi::GetPackageInfoArchFn;

pub(super) static mut GET_PKG_INFO_DETOUR: Option<Detour<GetPackageInfoHookFn>> = None;
static CPKG_INFO_CAPTURED: AtomicBool = AtomicBool::new(false);

pub(super) fn reset_account_state() {
    CPKG_INFO_CAPTURED.store(false, Ordering::Release);
}

#[cfg(test)]
pub(super) fn seed_account_state_for_test() {
    CPKG_INFO_CAPTURED.store(true, Ordering::Release);
}

#[cfg(test)]
pub(super) fn account_state_is_clear_for_test() -> bool {
    !CPKG_INFO_CAPTURED.load(Ordering::Acquire)
}

pub(super) fn hook_name() -> &'static str {
    "CPackageInfo::GetPackageInfo"
}

#[cfg(target_pointer_width = "32")]
unsafe extern "C" fn hk_get_package_info(
    this: *mut c_void,
    package_id: u32,
    access_token: u64,
) -> *mut u8 {
    // SAFETY: GET_PKG_INFO_DETOUR set before enabled.
    let original = vapor_forge_hook_engine::original::detour_or_return!(
        "GetPackageInfo",
        GET_PKG_INFO_DETOUR,
        std::ptr::null_mut()
    );
    // SAFETY: the original function and unchanged callback arguments satisfy
    // the validated 32-bit GetPackageInfo ABI.
    let result = unsafe { original(this, package_id, access_token) };

    if !crate::capability::is_ready(crate::capability::Capability::PackageInjection) {
        return result;
    }

    // Capture CPackageInfo* on first call, then use it to get pkg0.
    if !CPKG_INFO_CAPTURED.swap(true, Ordering::AcqRel) {
        // SAFETY: `this` is the live CPackageInfo receiver for this hook callback.
        unsafe { super::super::package::capture_pkg_info_this(this) };

        // Now call GetPackageInfo(this, 0, token) to get pkg0.
        if !result.is_null() || package_id == 0 {
            // SAFETY: `this` is the live CPackageInfo receiver for this hook callback.
            unsafe { super::super::package::try_capture_pkg0_from_package_info(this) };
            if !super::super::package::pkg0_captured() {
                debug!("package: GetPackageInfo(0) returned null, will retry");
                CPKG_INFO_CAPTURED.store(false, Ordering::Release);
            }
        }
    }

    result
}

#[cfg(target_pointer_width = "64")]
unsafe extern "C" fn hk_get_package_info64(
    this: *mut c_void,
    package_id: u32,
    access_token: u64,
) -> *mut u8 {
    // SAFETY: GET_PKG_INFO_DETOUR set before enabled.
    let original = vapor_forge_hook_engine::original::detour_or_return!(
        "GetPackageInfo",
        GET_PKG_INFO_DETOUR,
        std::ptr::null_mut()
    );
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, package_id, access_token) };

    if !crate::capability::is_ready(crate::capability::Capability::PackageInjection) {
        return result;
    }

    // Capture the package store and use the same package-id/token lookup for pkg0.
    if !CPKG_INFO_CAPTURED.swap(true, Ordering::AcqRel) {
        // SAFETY: `this` is the live CPackageInfo receiver for this hook callback.
        unsafe { super::super::package::capture_pkg_info_this(this) };

        let pkg0_token = super::super::package::PKG0_ACCESS_TOKEN;
        let result_is_pkg0 = if result.is_null() {
            false
        } else {
            // SAFETY: result is a non-null PackageInfo returned by Steam.
            unsafe { vapor_forge_steam_native_abi::package_info::package_id(result) == 0 }
        };
        let pkg0 = if result_is_pkg0 {
            result
        } else {
            /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
            unsafe { original(this, 0, pkg0_token) }
        };

        if !pkg0.is_null() {
            // SAFETY: pkg0 is a PackageInfo returned by the original lookup.
            unsafe { super::super::package::capture_validated_pkg0(pkg0) };
        }

        if !super::super::package::pkg0_captured() {
            debug!("package: GetPackageInfo64(pkg0 token) returned null, will retry");
            CPKG_INFO_CAPTURED.store(false, Ordering::Release);
        }
    }

    result
}

pub(super) fn create_detour() -> Option<PendingDetour<GetPackageInfoHookFn>> {
    let addr = super::super::package::get_package_info_addr()?;

    #[cfg(target_pointer_width = "32")]
    let replacement = hk_get_package_info as GetPackageInfoHookFn;
    #[cfg(target_pointer_width = "64")]
    let replacement = hk_get_package_info64 as GetPackageInfoHookFn;

    let replacement_addr = replacement as *const () as usize;
    let hook_name = hook_name();
    let (base, end) = super::steamclient_code_range().or_else(|| {
        error!(
            hook = hook_name,
            "hook boundary validation failed: code range unavailable"
        );
        None
    })?;
    // SAFETY: this range was captured from steamclient's executable mapping.
    let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, end - base) };
    let plan = super::validate_hook_eligibility(
        hook_name,
        addr,
        replacement_addr,
        &CodeRegion { base, bytes },
    )
    .inspect_err(|error| {
        error!(hook = hook_name, %error, "hook boundary validation failed");
    })
    .ok()?;

    // SAFETY: the validated target and typed replacement share the package-info ABI.
    unsafe { detour::create_detour(hook_name, plan) }
}
