//! Native Steam process ABI layouts and callable function signatures.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::c_void;

// Valve's CUtlMemory/CUtlVector. Source keeps the same compact control
// fields on Linux x86_64: pointer + allocation count + grow size.
#[repr(C)]
pub struct CUtlMemory<T> {
    pub m_p_memory: *mut T,
    pub m_n_allocation_count: u32,
    pub m_n_grow_size: u32,
}

#[repr(C)]
pub struct CUtlVector<T> {
    pub m_memory: CUtlMemory<T>,
    pub m_size: i32,
}

impl<T> CUtlVector<T> {
    pub fn len(&self) -> usize {
        if self.m_size < 0 {
            0
        } else {
            self.m_size as usize
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.m_n_allocation_count() as usize
    }

    fn m_n_allocation_count(&self) -> u32 {
        self.m_memory.m_n_allocation_count
    }

    /// # Safety
    /// Index must be < len().
    pub unsafe fn get(&self, index: usize) -> &T {
        // SAFETY: caller guarantees index is in bounds for m_p_memory.
        unsafe { &*self.m_memory.m_p_memory.add(index) }
    }

    /// # Safety
    /// Index must be < len().
    pub unsafe fn get_mut(&mut self, index: usize) -> &mut T {
        // SAFETY: caller guarantees index is in bounds for m_p_memory.
        unsafe { &mut *self.m_memory.m_p_memory.add(index) }
    }

    /// # Safety
    /// The vector must reference a live, readable allocation containing at
    /// least `len()` initialized elements.
    pub unsafe fn contains(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        for i in 0..self.len() {
            // SAFETY: i < len()
            if unsafe { self.get(i) } == value {
                return true;
            }
        }
        false
    }

    /// # Safety
    /// The vector must reference a live, writable allocation containing at
    /// least `len()` initialized elements.
    pub unsafe fn find_and_fast_remove(&mut self, value: &T) -> bool
    where
        T: PartialEq + Copy,
    {
        for i in 0..self.len() {
            // SAFETY: i < len()
            if unsafe { *self.get(i) } == *value {
                let last = self.m_size - 1;
                // SAFETY: i and last are valid indices
                unsafe {
                    *self.m_memory.m_p_memory.add(i) = *self.m_memory.m_p_memory.add(last as usize);
                }
                self.m_size -= 1;
                return true;
            }
        }
        false
    }

    /// # Safety
    /// The vector must reference a live, writable allocation covering its
    /// reported capacity.
    pub unsafe fn try_append(&mut self, value: T) -> bool
    where
        T: Copy,
    {
        if (self.m_size as u32) >= self.m_memory.m_n_allocation_count {
            return false;
        }
        // SAFETY: m_size < allocation_count, so the write is in bounds.
        unsafe {
            *self.m_memory.m_p_memory.add(self.m_size as usize) = value;
        }
        self.m_size += 1;
        true
    }
}

// Native PackageInfo returned by CPackageInfo::GetPackageInfo.
pub mod package_info {
    use super::{c_void, CUtlVector};

    #[repr(C)]
    pub struct PackageInfo {
        pub package_id: u32,
        pub change_number: i32,
        pub pics_token: u64,
        pub billing_type: i32,
        pub license_type: i32,
        pub status: i32,
        pub sha1_hash: [u8; 20],
        pub package_info_node_begin: *mut c_void,
        pub extend_node_begin: *mut c_void,
        pub app_id_vec: CUtlVector<u32>,
        pub depot_id_vec: CUtlVector<u32>,
    }

    /// # Safety
    /// pkg must point to a valid PackageInfo struct in Steam memory.
    pub unsafe fn package_id(pkg: *const u8) -> u32 {
        let pkg = pkg.cast::<PackageInfo>();
        // SAFETY: caller guarantees pkg points to a valid PackageInfo struct.
        unsafe { core::ptr::addr_of!((*pkg).package_id).read() }
    }

    /// # Safety
    /// pkg must point to a valid PackageInfo struct in Steam memory.
    pub unsafe fn status(pkg: *const u8) -> u32 {
        let pkg = pkg.cast::<PackageInfo>();
        // SAFETY: caller guarantees pkg points to a valid PackageInfo struct.
        unsafe { core::ptr::addr_of!((*pkg).status).read() as u32 }
    }

    /// # Safety
    /// pkg must point to a valid PackageInfo struct in Steam memory.
    pub unsafe fn app_id_vec(pkg: *mut u8) -> *mut CUtlVector<u32> {
        let pkg = pkg.cast::<PackageInfo>();
        // SAFETY: caller guarantees pkg points to a valid PackageInfo struct.
        unsafe { core::ptr::addr_of_mut!((*pkg).app_id_vec) }
    }
}

pub mod cnet_packet {
    use core::ffi::c_void;

    #[repr(C)]
    pub struct CNetPacketPrefix {
        pub packet_type: u32,
        pub data: *mut u8,
        pub size: u32,
        pub refs: i32,
        pub owned_data: *mut u8,
        _unknown_20: *mut c_void,
        _unknown_tail: [u32; 2],
    }

    // CNetPacket is not polymorphic. Native pointer alignment inserts four
    // bytes after packet_type on x86_64.
    pub const DATA_OFFSET: usize = core::mem::offset_of!(CNetPacketPrefix, data);
    pub const SIZE_OFFSET: usize = core::mem::offset_of!(CNetPacketPrefix, size);
    pub const REFS_OFFSET: usize = core::mem::offset_of!(CNetPacketPrefix, refs);
    pub const OWNED_DATA_OFFSET: usize = core::mem::offset_of!(CNetPacketPrefix, owned_data);

    const _: () = {
        #[cfg(target_pointer_width = "32")]
        {
            assert!(DATA_OFFSET == 0x04);
            assert!(SIZE_OFFSET == 0x08);
            assert!(REFS_OFFSET == 0x0c);
            assert!(OWNED_DATA_OFFSET == 0x10);
            assert!(core::mem::size_of::<CNetPacketPrefix>() == 0x20);
        }
        #[cfg(target_pointer_width = "64")]
        {
            assert!(DATA_OFFSET == 0x08);
            assert!(SIZE_OFFSET == 0x10);
            assert!(REFS_OFFSET == 0x14);
            assert!(OWNED_DATA_OFFSET == 0x18);
            assert!(core::mem::size_of::<CNetPacketPrefix>() == 0x30);
        }
    };

    /// # Safety
    /// packet must point to a valid CNetPacket object.
    pub unsafe fn data_slot(packet: *mut c_void) -> *mut *mut u8 {
        let packet = packet.cast::<CNetPacketPrefix>();
        // SAFETY: caller guarantees packet points to a valid CNetPacket object.
        unsafe { core::ptr::addr_of_mut!((*packet).data) }
    }

    /// # Safety
    /// packet must point to a valid CNetPacket object.
    pub unsafe fn size_slot(packet: *mut c_void) -> *mut u32 {
        let packet = packet.cast::<CNetPacketPrefix>();
        // SAFETY: caller guarantees packet points to a valid CNetPacket object.
        unsafe { core::ptr::addr_of_mut!((*packet).size) }
    }

    /// # Safety
    /// packet must point to a valid CNetPacket object, and data must remain
    /// valid until Steam has consumed the packet.
    pub unsafe fn set_data(packet: *mut c_void, data: *mut u8, size: u32) {
        // SAFETY: caller guarantees packet points to a valid CNetPacket object.
        let p_data = unsafe { data_slot(packet) };
        // SAFETY: caller guarantees packet points to a valid CNetPacket object.
        let p_size = unsafe { size_slot(packet) };
        // SAFETY: p_data and p_size point to CNetPacket fields.
        unsafe {
            *p_data = data;
            *p_size = size;
        }
    }
}

pub mod steamui {
    use core::ffi::c_void;
    use core::marker::PhantomData;

    #[repr(transparent)]
    struct SteamPtr<T> {
        #[cfg(target_pointer_width = "32")]
        _addr: u32,
        #[cfg(target_pointer_width = "64")]
        _addr: u64,
        _marker: PhantomData<*mut T>,
    }

    #[repr(C)]
    struct RepeatedPtrFieldOpaque {
        #[cfg(target_pointer_width = "32")]
        _words: [u32; 4],
        #[cfg(target_pointer_width = "64")]
        _words: [usize; 3],
    }

    #[repr(C)]
    struct RepeatedFieldU32Opaque {
        _current_size: i32,
        _total_size: i32,
        _arena_or_elements: SteamPtr<u32>,
    }

    #[repr(C)]
    pub struct CAppOverviewChange {
        #[cfg(target_pointer_width = "32")]
        _prefix: [u32; 3],
        #[cfg(target_pointer_width = "64")]
        _prefix: [u32; 4],
        _app_overview: RepeatedPtrFieldOpaque,
        removed_appid: RepeatedFieldU32Opaque,
    }

    impl CAppOverviewChange {
        pub const REMOVED_APPID_OFFSET: usize = core::mem::offset_of!(Self, removed_appid);

        /// # Safety
        /// change must point to a valid SteamUI CAppOverview_Change object.
        pub unsafe fn mutable_removed_appid(change: *mut c_void) -> *mut c_void {
            let change = change.cast::<Self>();
            // SAFETY: caller guarantees change points to the expected SteamUI object.
            unsafe { core::ptr::addr_of_mut!((*change).removed_appid).cast() }
        }
    }

    // SteamUI passes this object as a packed app record.
    #[repr(C, packed)]
    pub struct CSteamApp {
        pub vfptr: *mut c_void,
        pub game_id: u64,
        pub app_id: u32,
        pub unknown1: u16,
        pub unknown2: u16,
        pub release_state: u32,
        pub ownership_flags: u32,
        pub app_state_flags: u32,
        pub steam_id: u64,
        pub purchased_time: u32,
        pub change_number: u32,
        pub license_expiration_time: u32,
        pub master_sub_app_id: u32,
        pub proto_app_type: u32,
        pub parent_app_id: u32,
    }

    impl CSteamApp {
        pub const VFPTR_OFFSET: usize = core::mem::offset_of!(Self, vfptr);
        pub const GAME_ID_OFFSET: usize = core::mem::offset_of!(Self, game_id);
        pub const APP_ID_OFFSET: usize = core::mem::offset_of!(Self, app_id);
        pub const UNKNOWN1_OFFSET: usize = core::mem::offset_of!(Self, unknown1);
        pub const UNKNOWN2_OFFSET: usize = core::mem::offset_of!(Self, unknown2);
        pub const RELEASE_STATE_OFFSET: usize = core::mem::offset_of!(Self, release_state);
        pub const OWNERSHIP_FLAGS_OFFSET: usize = core::mem::offset_of!(Self, ownership_flags);
        pub const APP_STATE_FLAGS_OFFSET: usize = core::mem::offset_of!(Self, app_state_flags);
        pub const STEAM_ID_OFFSET: usize = core::mem::offset_of!(Self, steam_id);
        pub const PURCHASED_TIME_OFFSET: usize = core::mem::offset_of!(Self, purchased_time);
        pub const CHANGE_NUMBER_OFFSET: usize = core::mem::offset_of!(Self, change_number);
        pub const LICENSE_EXPIRATION_TIME_OFFSET: usize =
            core::mem::offset_of!(Self, license_expiration_time);
        pub const MASTER_SUB_APP_ID_OFFSET: usize = core::mem::offset_of!(Self, master_sub_app_id);
        pub const PROTO_APP_TYPE_OFFSET: usize = core::mem::offset_of!(Self, proto_app_type);
        pub const PARENT_APP_ID_OFFSET: usize = core::mem::offset_of!(Self, parent_app_id);
    }

    #[cfg(target_pointer_width = "32")]
    const _: () = {
        assert!(CAppOverviewChange::REMOVED_APPID_OFFSET == 0x1c);
        assert!(core::mem::size_of::<CSteamApp>() == 0x40);
        assert!(CSteamApp::VFPTR_OFFSET == 0x00);
        assert!(CSteamApp::GAME_ID_OFFSET == 0x04);
        assert!(CSteamApp::APP_ID_OFFSET == 0x0c);
        assert!(CSteamApp::UNKNOWN1_OFFSET == 0x10);
        assert!(CSteamApp::UNKNOWN2_OFFSET == 0x12);
        assert!(CSteamApp::RELEASE_STATE_OFFSET == 0x14);
        assert!(CSteamApp::OWNERSHIP_FLAGS_OFFSET == 0x18);
        assert!(CSteamApp::APP_STATE_FLAGS_OFFSET == 0x1c);
        assert!(CSteamApp::STEAM_ID_OFFSET == 0x20);
        assert!(CSteamApp::PURCHASED_TIME_OFFSET == 0x28);
        assert!(CSteamApp::CHANGE_NUMBER_OFFSET == 0x2c);
        assert!(CSteamApp::LICENSE_EXPIRATION_TIME_OFFSET == 0x30);
        assert!(CSteamApp::MASTER_SUB_APP_ID_OFFSET == 0x34);
        assert!(CSteamApp::PROTO_APP_TYPE_OFFSET == 0x38);
        assert!(CSteamApp::PARENT_APP_ID_OFFSET == 0x3c);
    };

    #[cfg(target_pointer_width = "64")]
    const _: () = {
        // 64-bit SteamUI uses wider pointers inside protobuf repeated fields.
        assert!(CAppOverviewChange::REMOVED_APPID_OFFSET == 0x28);
        assert!(core::mem::size_of::<CSteamApp>() == 0x44);
        assert!(CSteamApp::VFPTR_OFFSET == 0x00);
        assert!(CSteamApp::GAME_ID_OFFSET == 0x08);
        assert!(CSteamApp::APP_ID_OFFSET == 0x10);
        assert!(CSteamApp::UNKNOWN1_OFFSET == 0x14);
        assert!(CSteamApp::UNKNOWN2_OFFSET == 0x16);
        assert!(CSteamApp::RELEASE_STATE_OFFSET == 0x18);
        assert!(CSteamApp::OWNERSHIP_FLAGS_OFFSET == 0x1c);
        assert!(CSteamApp::APP_STATE_FLAGS_OFFSET == 0x20);
        assert!(CSteamApp::STEAM_ID_OFFSET == 0x24);
        assert!(CSteamApp::PURCHASED_TIME_OFFSET == 0x2c);
        assert!(CSteamApp::CHANGE_NUMBER_OFFSET == 0x30);
        assert!(CSteamApp::LICENSE_EXPIRATION_TIME_OFFSET == 0x34);
        assert!(CSteamApp::MASTER_SUB_APP_ID_OFFSET == 0x38);
        assert!(CSteamApp::PROTO_APP_TYPE_OFFSET == 0x3c);
        assert!(CSteamApp::PARENT_APP_ID_OFFSET == 0x40);
    };

    #[cfg(test)]
    mod tests {
        use super::*;
        use core::mem;

        #[test]
        fn repeated_ptr_field_size() {
            #[cfg(target_pointer_width = "32")]
            assert_eq!(mem::size_of::<RepeatedPtrFieldOpaque>(), 0x10);
            #[cfg(target_pointer_width = "64")]
            assert_eq!(mem::size_of::<RepeatedPtrFieldOpaque>(), 0x18);
        }

        #[test]
        fn repeated_field_u32_size() {
            #[cfg(target_pointer_width = "32")]
            assert_eq!(mem::size_of::<RepeatedFieldU32Opaque>(), 0x0c);
            #[cfg(target_pointer_width = "64")]
            assert_eq!(mem::size_of::<RepeatedFieldU32Opaque>(), 0x10);
        }

        #[test]
        fn steam_ptr_size() {
            assert_eq!(mem::size_of::<SteamPtr<u32>>(), mem::size_of::<usize>());
        }

        #[cfg(target_pointer_width = "32")]
        #[test]
        fn app_overview_change_removed_appid_offset() {
            assert_eq!(CAppOverviewChange::REMOVED_APPID_OFFSET, 0x1c);
        }

        #[cfg(target_pointer_width = "32")]
        #[test]
        fn steam_app_offsets() {
            assert_eq!(mem::size_of::<CSteamApp>(), 0x40);
            assert_eq!(CSteamApp::VFPTR_OFFSET, 0x00);
            assert_eq!(CSteamApp::GAME_ID_OFFSET, 0x04);
            assert_eq!(CSteamApp::APP_ID_OFFSET, 0x0c);
            assert_eq!(CSteamApp::UNKNOWN1_OFFSET, 0x10);
            assert_eq!(CSteamApp::UNKNOWN2_OFFSET, 0x12);
            assert_eq!(CSteamApp::RELEASE_STATE_OFFSET, 0x14);
            assert_eq!(CSteamApp::OWNERSHIP_FLAGS_OFFSET, 0x18);
            assert_eq!(CSteamApp::APP_STATE_FLAGS_OFFSET, 0x1c);
            assert_eq!(CSteamApp::STEAM_ID_OFFSET, 0x20);
            assert_eq!(CSteamApp::PURCHASED_TIME_OFFSET, 0x28);
            assert_eq!(CSteamApp::CHANGE_NUMBER_OFFSET, 0x2c);
            assert_eq!(CSteamApp::LICENSE_EXPIRATION_TIME_OFFSET, 0x30);
            assert_eq!(CSteamApp::MASTER_SUB_APP_ID_OFFSET, 0x34);
            assert_eq!(CSteamApp::PROTO_APP_TYPE_OFFSET, 0x38);
            assert_eq!(CSteamApp::PARENT_APP_ID_OFFSET, 0x3c);
        }

        #[cfg(target_pointer_width = "64")]
        #[test]
        fn steam_app_offsets() {
            assert_eq!(mem::size_of::<CSteamApp>(), 0x44);
            assert_eq!(CSteamApp::VFPTR_OFFSET, 0x00);
            assert_eq!(CSteamApp::GAME_ID_OFFSET, 0x08);
            assert_eq!(CSteamApp::APP_ID_OFFSET, 0x10);
            assert_eq!(CSteamApp::UNKNOWN1_OFFSET, 0x14);
            assert_eq!(CSteamApp::UNKNOWN2_OFFSET, 0x16);
            assert_eq!(CSteamApp::RELEASE_STATE_OFFSET, 0x18);
            assert_eq!(CSteamApp::OWNERSHIP_FLAGS_OFFSET, 0x1c);
            assert_eq!(CSteamApp::APP_STATE_FLAGS_OFFSET, 0x20);
            assert_eq!(CSteamApp::STEAM_ID_OFFSET, 0x24);
            assert_eq!(CSteamApp::PURCHASED_TIME_OFFSET, 0x2c);
            assert_eq!(CSteamApp::CHANGE_NUMBER_OFFSET, 0x30);
            assert_eq!(CSteamApp::LICENSE_EXPIRATION_TIME_OFFSET, 0x34);
            assert_eq!(CSteamApp::MASTER_SUB_APP_ID_OFFSET, 0x38);
            assert_eq!(CSteamApp::PROTO_APP_TYPE_OFFSET, 0x3c);
            assert_eq!(CSteamApp::PARENT_APP_ID_OFFSET, 0x40);
        }
    }
}

// Depot manifest entry (0x20 bytes) produced by BuildDepotDependency.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DepotEntry {
    pub depot_id: u32,
    pub app_id: u32,
    pub manifest_gid: u64,
    pub manifest_size: u64,
    pub dlc_app_id: u32,
    pub lcs_required: u8,
    pub b_not_new_target: u8,
    pub shared_install: u8,
    pub _padding: u8,
}

// Function signatures for pkg0 injection
pub type GetPackageInfoFn = unsafe extern "C" fn(*mut c_void, u32, u64) -> *mut u8;
pub type GetPackageInfo64Fn = unsafe extern "C" fn(*mut c_void, *const u64) -> *mut u8;
#[cfg(target_pointer_width = "32")]
pub type GetPackageInfoArchFn = GetPackageInfoFn;
#[cfg(target_pointer_width = "64")]
pub type GetPackageInfoArchFn = GetPackageInfo64Fn;
pub type MarkLicenseAsChangedFn = unsafe extern "C" fn(*mut c_void, u32, bool) -> i64;
pub type ProcessPendingLicenseUpdatesFn = unsafe extern "C" fn(*mut c_void) -> bool;
pub type CUtlMemoryGrowFn = unsafe extern "C" fn(*mut c_void, i32) -> *mut c_void;

/// Mirrors `EAppReleaseState` from `steamclientpublic.h`.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EAppReleaseState {
    #[default]
    Unknown = 0,
    Unavailable = 1,
    Prerelease = 2,
    PreloadOnly = 3,
    Released = 4,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CAppOwnershipInfo {
    pub package_id: i32,
    pub release_state: i32,
    pub owner_account_id: u32,
    pub master_subscription_app_id: i32,
    pub trial_seconds: u32,
    pub exist_in_package_nums: i32,
    pub purchase_country_code: [u8; 4],
    pub purchase_time: u32,
    pub license_expiration_time: u32,
    pub owns_license: u8,
    pub license_expired: u8,
    pub is_permanent: u8,
    pub low_violence: u8,
    pub free_license: u8,
    pub region_restricted: u8,
    pub from_free_weekend: u8,
    pub license_locked: u8,
    pub license_pending: u8,
    pub retail_license: u8,
    pub auto_grant: u8,
    pub license_permanent: u8,
    pub guest_pass: u8,
    pub borrowed: u8,
    pub any_site_license: u8,
    pub all_site_licenses: u8,
    pub all_activation_required: u8,
    pub family_shared: u8,
    pub _unknown_36: u8,
    pub _unknown_37: u8,
}

impl CAppOwnershipInfo {
    pub const SIZE: usize = 0x38;

    pub const RELEASE_STATE_OFFSET: usize = core::mem::offset_of!(Self, release_state);
    pub const OWNER_ACCOUNT_ID_OFFSET: usize = core::mem::offset_of!(Self, owner_account_id);
    pub const EXIST_IN_PACKAGE_NUMS_OFFSET: usize =
        core::mem::offset_of!(Self, exist_in_package_nums);
    pub const PURCHASE_TIME_OFFSET: usize = core::mem::offset_of!(Self, purchase_time);

    pub const OWNS_LICENSE_OFFSET: usize = core::mem::offset_of!(Self, owns_license);

    pub const LICENSE_EXPIRED_OFFSET: usize = core::mem::offset_of!(Self, license_expired);

    pub const IS_PERMANENT_OFFSET: usize = core::mem::offset_of!(Self, is_permanent);

    pub const FREE_LICENSE_OFFSET: usize = core::mem::offset_of!(Self, free_license);

    pub const LICENSE_PERMANENT_OFFSET: usize = core::mem::offset_of!(Self, license_permanent);

    pub const FAMILY_SHARED_OFFSET: usize = core::mem::offset_of!(Self, family_shared);

    pub fn zeroed() -> Self {
        Self::default()
    }
}

impl CAppOwnershipInfo {
    /// Injected package identifier that vapor-forge synthesises via pkg0
    /// injection. Ownership records for controlled apps should point at it so
    /// downstream code and DRM see a consistent package association.
    pub const INJECTED_PACKAGE_ID: i32 = 0;

    /// Fill in the fields Steam checks when deciding whether the caller owns
    /// an app. Purchase metadata remains unchanged.
    pub fn grant_spoofed_ownership(&mut self) {
        self.package_id = Self::INJECTED_PACKAGE_ID;
        self.release_state = EAppReleaseState::Released as i32;
        self.owner_account_id = 1;
        self.exist_in_package_nums = 2;
        self.owns_license = 1;
        self.license_expired = 0;
        self.is_permanent = 1;
        self.free_license = 0;
        self.family_shared = 0;
    }

    pub fn owner(&self) -> u32 {
        self.owner_account_id
    }

    pub fn set_owner(&mut self, owner_account_id: u32) {
        self.owner_account_id = owner_account_id;
    }

    pub fn owns_license(&self) -> u8 {
        self.owns_license
    }

    pub fn is_permanent_license(&self) -> u8 {
        self.is_permanent
    }

    pub fn is_family_shared(&self) -> bool {
        self.family_shared != 0
    }

    pub fn set_family_shared(&mut self, shared: bool) {
        self.family_shared = u8::from(shared);
    }

    pub fn clear_family_shared(&mut self) {
        self.family_shared = 0;
    }
}

pub type CheckAppOwnershipFn =
    unsafe extern "C" fn(this: *mut c_void, app_id: u32, out: *mut CAppOwnershipInfo) -> bool;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn package_info_offsets_match_steam_layout() {
        assert_eq!(mem::offset_of!(package_info::PackageInfo, package_id), 0x00);
        assert_eq!(
            mem::offset_of!(package_info::PackageInfo, change_number),
            0x04
        );
        assert_eq!(mem::offset_of!(package_info::PackageInfo, pics_token), 0x08);
        assert_eq!(
            mem::offset_of!(package_info::PackageInfo, billing_type),
            0x10
        );
        assert_eq!(
            mem::offset_of!(package_info::PackageInfo, license_type),
            0x14
        );
        assert_eq!(mem::offset_of!(package_info::PackageInfo, status), 0x18);
        assert_eq!(mem::offset_of!(package_info::PackageInfo, sha1_hash), 0x1c);
        assert_eq!(
            mem::offset_of!(package_info::PackageInfo, package_info_node_begin),
            0x30
        );

        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(
                mem::offset_of!(package_info::PackageInfo, extend_node_begin),
                0x34
            );
            assert_eq!(mem::offset_of!(package_info::PackageInfo, app_id_vec), 0x38);
            assert_eq!(
                mem::offset_of!(package_info::PackageInfo, depot_id_vec),
                0x48
            );
            assert_eq!(mem::size_of::<package_info::PackageInfo>(), 0x58);
        }

        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(
                mem::offset_of!(package_info::PackageInfo, extend_node_begin),
                0x38
            );
            assert_eq!(mem::offset_of!(package_info::PackageInfo, app_id_vec), 0x40);
            assert_eq!(
                mem::offset_of!(package_info::PackageInfo, depot_id_vec),
                0x58
            );
            assert_eq!(mem::size_of::<package_info::PackageInfo>(), 0x70);
        }
    }

    #[test]
    fn cutl_vector_layout() {
        assert_eq!(
            mem::offset_of!(CUtlMemory<u32>, m_n_allocation_count),
            mem::size_of::<usize>()
        );
        assert_eq!(
            mem::offset_of!(CUtlMemory<u32>, m_n_grow_size),
            mem::size_of::<usize>() + 0x04
        );
        assert_eq!(
            mem::offset_of!(CUtlVector<u32>, m_size),
            mem::size_of::<CUtlMemory<u32>>()
        );
        #[cfg(target_pointer_width = "32")]
        assert_eq!(mem::size_of::<CUtlVector<u32>>(), 0x10);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(mem::size_of::<CUtlVector<u32>>(), 0x18);
    }

    #[test]
    fn cnet_packet_offsets_match_steam_layout() {
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(cnet_packet::DATA_OFFSET, 0x04);
            assert_eq!(cnet_packet::SIZE_OFFSET, 0x08);
            assert_eq!(cnet_packet::REFS_OFFSET, 0x0c);
            assert_eq!(cnet_packet::OWNED_DATA_OFFSET, 0x10);
            assert_eq!(mem::size_of::<cnet_packet::CNetPacketPrefix>(), 0x20);
        }
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(cnet_packet::DATA_OFFSET, 0x08);
            assert_eq!(cnet_packet::SIZE_OFFSET, 0x10);
            assert_eq!(cnet_packet::REFS_OFFSET, 0x14);
            assert_eq!(cnet_packet::OWNED_DATA_OFFSET, 0x18);
            assert_eq!(mem::size_of::<cnet_packet::CNetPacketPrefix>(), 0x30);
        }
    }

    #[test]
    fn cnet_packet_accessors_address_expected_slots() {
        let mut packet = [0u8; 32];
        let base = packet.as_mut_ptr() as usize;
        let packet_ptr = packet.as_mut_ptr().cast::<c_void>();
        // SAFETY: packet is a stack buffer large enough for the tested slots.
        let data_slot = unsafe { cnet_packet::data_slot(packet_ptr) } as usize;
        // SAFETY: packet is a stack buffer large enough for the tested slots.
        let size_slot = unsafe { cnet_packet::size_slot(packet_ptr) } as usize;
        assert_eq!(data_slot, base + cnet_packet::DATA_OFFSET);
        assert_eq!(size_slot, base + cnet_packet::SIZE_OFFSET);
    }

    #[test]
    fn app_ownership_info_layout_and_helpers() {
        assert_eq!(mem::size_of::<CAppOwnershipInfo>(), CAppOwnershipInfo::SIZE);
        assert_eq!(CAppOwnershipInfo::SIZE, 0x38);
        assert_eq!(CAppOwnershipInfo::EXIST_IN_PACKAGE_NUMS_OFFSET, 0x14);
        assert_eq!(CAppOwnershipInfo::PURCHASE_TIME_OFFSET, 0x1c);
        assert_eq!(CAppOwnershipInfo::OWNS_LICENSE_OFFSET, 0x24);
        assert_eq!(CAppOwnershipInfo::IS_PERMANENT_OFFSET, 0x26);
        assert_eq!(CAppOwnershipInfo::FREE_LICENSE_OFFSET, 0x28);
        assert_eq!(CAppOwnershipInfo::LICENSE_PERMANENT_OFFSET, 0x2f);
        assert_eq!(CAppOwnershipInfo::FAMILY_SHARED_OFFSET, 0x35);

        let mut info = CAppOwnershipInfo::zeroed();
        info.purchase_time = 0xcafe_babe;
        info.grant_spoofed_ownership();
        assert_eq!(info.owner(), 1);
        assert_eq!(info.owns_license(), 1);
        assert_eq!(info.is_permanent_license(), 1);
        assert_eq!(info.license_permanent, 0);
        assert!(!info.is_family_shared());
        let release_state = { info.release_state };
        assert_eq!(release_state, EAppReleaseState::Released as i32);
        let purchase_time = { info.purchase_time };
        assert_eq!(purchase_time, 0xcafe_babe);
    }

    #[test]
    fn depot_entry_layout() {
        assert_eq!(mem::size_of::<DepotEntry>(), 0x20);
        assert_eq!(mem::offset_of!(DepotEntry, manifest_gid), 0x08);
        assert_eq!(mem::offset_of!(DepotEntry, manifest_size), 0x10);
        assert_eq!(mem::offset_of!(DepotEntry, dlc_app_id), 0x18);
    }
}
