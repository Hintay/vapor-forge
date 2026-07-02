use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use retour::GenericDetour;
use tracing::{debug, error, info, warn};

use crate::detour::{self, CodeRegion, PendingDetour};

pub(super) type GetPackageInfoHookFn = extern "C" fn(*mut c_void, u32, u64) -> *mut u8;

pub(super) static mut GET_PKG_INFO_DETOUR: Option<GenericDetour<GetPackageInfoHookFn>> = None;
static CPKG_INFO_CAPTURED: AtomicBool = AtomicBool::new(false);

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
        info!("package: captured CPackageInfo at 0x{:x}", this as usize);

        // Now call GetPackageInfo(this, 0, token) to get pkg0.
        if !result.is_null() || package_id == 0 {
            // Try to get pkg0 using the captured CPackageInfo*.
            let pkg0 = original.call(this, 0, super::super::package::PKG0_ACCESS_TOKEN);
            if !pkg0.is_null() {
                // SAFETY: pkg0 is a valid PackageInfo pointer.
                let status = unsafe { vapor_forge_abi::package_info::status(pkg0) };
                if status == 0 {
                    super::super::package::PKG0_PTR.store(pkg0 as usize, Ordering::Release);
                    info!("package: captured pkg0 at 0x{:x}", pkg0 as usize);
                } else {
                    warn!(status = status, "package: pkg0 status != Available");
                }
            } else {
                debug!("package: GetPackageInfo(0) returned null, will retry");
                CPKG_INFO_CAPTURED.store(false, Ordering::Release);
            }
        }
    }

    result
}

pub(super) fn create_detour() -> Option<PendingDetour<GetPackageInfoHookFn>> {
    let addr = super::super::package::get_package_info_addr()?;

    let replacement_addr = hk_get_package_info as *const () as usize;
    if let Some((base, end)) = super::steamclient_code_range() {
        // SAFETY: steamclient_code_range is populated from the executable
        // steamclient.so mapping and kept for validation only.
        let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, end - base) };
        if let Err(e) = super::validate_hook_eligibility(
            "CPackageInfo::GetPackageInfo",
            addr,
            replacement_addr,
            &CodeRegion { base, bytes },
        ) {
            error!(hook = "CPackageInfo::GetPackageInfo", error = %e, "hook boundary validation failed");
            return None;
        }
    }

    // SAFETY: addr is a validated code address.
    let target: GetPackageInfoHookFn = unsafe { std::mem::transmute(addr) };
    // SAFETY: target is valid.
    unsafe { detour::create_detour("GetPackageInfo", target, addr, hk_get_package_info) }
}
