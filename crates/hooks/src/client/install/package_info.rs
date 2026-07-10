use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use retour::GenericDetour;
use tracing::{debug, error};

use crate::detour::{self, CodeRegion, PendingDetour};

pub(super) type GetPackageInfoHookFn = vapor_forge_abi::GetPackageInfoArchFn;

pub(super) static mut GET_PKG_INFO_DETOUR: Option<GenericDetour<GetPackageInfoHookFn>> = None;
static CPKG_INFO_CAPTURED: AtomicBool = AtomicBool::new(false);

pub(super) fn hook_name() -> &'static str {
    "CPackageInfo::GetPackageInfo"
}

#[cfg(target_pointer_width = "32")]
extern "C" fn hk_get_package_info(
    this: *mut c_void,
    package_id: u32,
    access_token: u64,
) -> *mut u8 {
    // SAFETY: GET_PKG_INFO_DETOUR set before enabled.
    let original = crate::original::detour_or_return!(
        "GetPackageInfo",
        GET_PKG_INFO_DETOUR,
        std::ptr::null_mut()
    );
    let result = original.call(this, package_id, access_token);

    // Capture CPackageInfo* on first call, then use it to get pkg0.
    if !CPKG_INFO_CAPTURED.swap(true, Ordering::AcqRel) {
        super::super::package::capture_pkg_info_this(this);

        // Now call GetPackageInfo(this, 0, token) to get pkg0.
        if !result.is_null() || package_id == 0 {
            super::super::package::try_capture_pkg0_from_package_info(this);
            if super::super::package::PKG0_PTR.load(Ordering::Acquire) == 0 {
                debug!("package: GetPackageInfo(0) returned null, will retry");
                CPKG_INFO_CAPTURED.store(false, Ordering::Release);
            }
        }
    }

    result
}

#[cfg(target_pointer_width = "64")]
extern "C" fn hk_get_package_info64(this: *mut c_void, key: *const u64) -> *mut u8 {
    // SAFETY: GET_PKG_INFO_DETOUR set before enabled.
    let original = crate::original::detour_or_return!(
        "GetPackageInfo",
        GET_PKG_INFO_DETOUR,
        std::ptr::null_mut()
    );
    let result = original.call(this, key);

    // Linux x86_64 receives the CPackageInfo package-store subobject plus a
    // package-token key pointer. The function walks the token map discovered by
    // the scanner and returns the inline PackageInfo value from the matched node.
    // Once the store object is captured, ask Steam's original lookup for pkg0's
    // known token rather than relying on a fixed map offset in the hook.
    if !CPKG_INFO_CAPTURED.swap(true, Ordering::AcqRel) {
        super::super::package::capture_pkg_info_this(this);

        let pkg0_token = super::super::package::PKG0_ACCESS_TOKEN;
        let result_is_pkg0 = if result.is_null() {
            false
        } else {
            // SAFETY: result is a non-null PackageInfo returned by Steam.
            unsafe { vapor_forge_abi::package_info::package_id(result) == 0 }
        };
        let pkg0 = if result_is_pkg0 {
            result
        } else {
            original.call(this, &pkg0_token)
        };

        if !pkg0.is_null() {
            super::super::package::capture_validated_pkg0(pkg0);
        }

        if super::super::package::PKG0_PTR.load(Ordering::Acquire) == 0 {
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
    if let Some((base, end)) = super::steamclient_code_range() {
        // SAFETY: steamclient_code_range is populated from the executable
        // steamclient.so mapping and kept for validation only.
        let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, end - base) };
        if let Err(e) = super::validate_hook_eligibility(
            hook_name,
            addr,
            replacement_addr,
            &CodeRegion { base, bytes },
        ) {
            error!(hook = hook_name, error = %e, "hook boundary validation failed");
            return None;
        }
    }

    // SAFETY: addr is a validated code address.
    let target: GetPackageInfoHookFn = unsafe { std::mem::transmute(addr) };
    // SAFETY: target is valid.
    unsafe { detour::create_detour(hook_name, target, addr, replacement) }
}
