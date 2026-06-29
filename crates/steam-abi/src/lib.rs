#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::c_void;

#[repr(C)]
pub struct CAppOwnershipInfo {
    pub sub_id: i32,
    pub release_state: i32,
    pub owner: u32,
    pub master_subscription_app_id: i32,
    pub trial_time: u32,
    pub exist_in_package_nums: i32,
    pub region: [u8; 2],
    pub _pad_1a: [u8; 2],
    pub purchase_time: u32,
    pub real_owner: u32,
    pub owns_license: u8,
    pub license_expired: u8,
    pub _field_26: u8,
    pub low_violence: u8,
    pub free_license: u8,
    pub region_restricted: u8,
    pub from_free_weekend: u8,
    pub license_locked: u8,
    pub license_pending: u8,
    pub retail_license: u8,
    pub auto_grant: u8,
    pub license_permanent: u8,
    pub _field_30: u8,
    pub _field_31: u8,
    pub site_license: u8,
    pub _field_33: u8,
    pub _field_34: u8,
    pub family_shared: u8,
    pub _field_36: u8,
    pub _field_37: u8,
}

pub type CheckAppOwnershipFn =
    unsafe extern "C" fn(this: *mut c_void, app_id: u32, out: *mut CAppOwnershipInfo) -> u32;

#[cfg(test)]
mod tests {
    use super::CAppOwnershipInfo;
    use core::mem;

    #[test]
    fn app_ownership_info_size() {
        assert_eq!(mem::size_of::<CAppOwnershipInfo>(), 0x38);
    }

    #[test]
    fn app_ownership_info_exist_in_package_nums_offset() {
        let base = core::ptr::null::<CAppOwnershipInfo>();
        // SAFETY: null pointer field offset calculation, no dereference
        let offset = unsafe { core::ptr::addr_of!((*base).exist_in_package_nums) as usize };
        assert_eq!(offset, 0x14);
    }

    #[test]
    fn app_ownership_info_purchase_time_offset() {
        let base = core::ptr::null::<CAppOwnershipInfo>();
        // SAFETY: null pointer field offset calculation, no dereference
        let offset = unsafe { core::ptr::addr_of!((*base).purchase_time) as usize };
        assert_eq!(offset, 0x1C);
    }

    #[test]
    fn app_ownership_info_owns_license_offset() {
        let base = core::ptr::null::<CAppOwnershipInfo>();
        // SAFETY: null pointer field offset calculation, no dereference
        let offset = unsafe { core::ptr::addr_of!((*base).owns_license) as usize };
        assert_eq!(offset, 0x24);
    }
}
