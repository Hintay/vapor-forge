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

    pub fn contains(&self, value: &T) -> bool
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

    pub fn find_and_fast_remove(&mut self, value: &T) -> bool
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

    pub fn try_append(&mut self, value: T) -> bool
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
        _vptr: *mut c_void,
        pub data: *mut u8,
        pub size: u32,
    }

    // Linux CNetPacket starts with a vptr, followed by the packet data pointer
    // and the packet byte size.
    pub const DATA_OFFSET: usize = core::mem::offset_of!(CNetPacketPrefix, data);
    pub const SIZE_OFFSET: usize = core::mem::offset_of!(CNetPacketPrefix, size);

    const _: () = {
        #[cfg(target_pointer_width = "32")]
        {
            assert!(DATA_OFFSET == 0x04);
            assert!(SIZE_OFFSET == 0x08);
        }
        #[cfg(target_pointer_width = "64")]
        {
            assert!(DATA_OFFSET == 0x08);
            assert!(SIZE_OFFSET == 0x10);
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
pub type GetPackageInfoFn = extern "C" fn(*mut c_void, u32, u64) -> *mut u8;
pub type GetPackageInfo64Fn = extern "C" fn(*mut c_void, *const u64) -> *mut u8;
#[cfg(target_pointer_width = "32")]
pub type GetPackageInfoArchFn = GetPackageInfoFn;
#[cfg(target_pointer_width = "64")]
pub type GetPackageInfoArchFn = GetPackageInfo64Fn;
pub type MarkLicenseAsChangedFn = extern "C" fn(*mut c_void, u32, bool) -> i64;
pub type ProcessPendingLicenseUpdatesFn = extern "C" fn(*mut c_void) -> bool;
pub type CUtlMemoryGrowFn = extern "C" fn(*mut c_void, i32) -> *mut c_void;

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
    pub _unknown_24: [u8; 4],
    pub owns_license: u8,
    pub license_expired: u8,
    pub _unknown_2a: [u8; 2],
    pub free_license: u8,
    pub _unknown_2d: [u8; 3],
    pub license_permanent: u8,
    pub _unknown_31: [u8; 2],
    pub license_flags_pair: [u8; 2],
    pub family_shared: u8,
    pub _pad_36: [u8; 2],
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

    pub const FREE_LICENSE_OFFSET: usize = core::mem::offset_of!(Self, free_license);

    pub const LICENSE_PERMANENT_OFFSET: usize = core::mem::offset_of!(Self, license_permanent);

    pub const FAMILY_SHARED_OFFSET: usize = core::mem::offset_of!(Self, family_shared);

    pub const LICENSE_FLAGS_OFFSET: usize = core::mem::offset_of!(Self, license_flags_pair);

    pub fn zeroed() -> Self {
        Self::default()
    }
}

impl CAppOwnershipInfo {
    pub fn grant_spoofed_ownership(&mut self, purchase_time: u32) {
        self.release_state = 2;
        self.owner_account_id = 1;
        self.exist_in_package_nums = 2;
        self.purchase_time = purchase_time;
        self.owns_license = 1;
        self.license_expired = 0;
        self.free_license = 0;
        self.license_permanent = 1;
        self.license_flags_pair = [1, 1];
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

    pub fn license_permanent(&self) -> u8 {
        self.license_permanent
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
    unsafe extern "C" fn(this: *mut c_void, app_id: u32, out: *mut CAppOwnershipInfo) -> u32;

// ---------------------------------------------------------------------------
// Network packet framing
// ---------------------------------------------------------------------------

/// 8-byte packet header: EMsg (with proto flag) + protobuf header length.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MsgHdr {
    /// Lower 31 bits = EMsg, bit 31 = proto flag.
    pub emsg: u32,
    /// Size of the protobuf header that follows.
    pub header_length: u32,
}

impl MsgHdr {
    pub const SIZE: usize = 8;
}

/// EMsg for `ServiceMethodCallFromClient`.
pub const EMSG_SERVICE_METHOD_CALL_FROM_CLIENT: u32 = 151;

/// EMsg for `ServiceMethodResponse`.
pub const EMSG_SERVICE_METHOD_RESPONSE: u32 = 147;

/// EMsg for server-initiated service notifications.
pub const EMSG_SERVICE_METHOD_SEND_TO_CLIENT: u32 = 152;

/// Bit 31 indicates protobuf framing.
pub const K_MSG_HDR_PROTO_FLAG: u32 = 0x8000_0000;

/// Unpack a raw packet into (emsg_raw, header_bytes, body_bytes).
///
/// Returns `None` if the data is too short or the header length overflows.
pub fn unpack_raw(data: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    if data.len() < MsgHdr::SIZE {
        return None;
    }
    let emsg_raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let hdr_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

    let hdr_end = MsgHdr::SIZE.checked_add(hdr_len)?;
    if data.len() < hdr_end {
        return None;
    }

    let header_bytes = &data[MsgHdr::SIZE..hdr_end];
    let body_bytes = &data[hdr_end..];
    Some((emsg_raw, header_bytes, body_bytes))
}

/// Assemble a complete packet from parts.
pub fn assemble_raw(emsg_raw: u32, header_bytes: &[u8], body_bytes: &[u8]) -> Vec<u8> {
    let total = MsgHdr::SIZE + header_bytes.len() + body_bytes.len();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&emsg_raw.to_le_bytes());
    buf.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(header_bytes);
    buf.extend_from_slice(body_bytes);
    buf
}

// ---------------------------------------------------------------------------
// Protobuf messages with prost derive, no .proto needed
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
pub struct CMsgProtoBufHeader {
    #[prost(fixed64, optional, tag = "1")]
    pub steamid: Option<u64>,
    #[prost(fixed64, optional, tag = "10")]
    pub jobid_source: Option<u64>,
    #[prost(fixed64, optional, tag = "11")]
    pub jobid_target: Option<u64>,
    #[prost(string, optional, tag = "12")]
    pub target_job_name: Option<String>,
    #[prost(int32, optional, tag = "13")]
    pub eresult: Option<i32>,
    #[prost(int32, optional, tag = "17")]
    pub transport_error: Option<i32>,
    #[prost(int32, optional, tag = "24")]
    pub seq_num: Option<i32>,
}

#[derive(Clone, prost::Message)]
pub struct GetManifestRequestCodeRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub depot_id: Option<u32>,
    #[prost(uint64, optional, tag = "3")]
    pub manifest_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct GetManifestRequestCodeResponse {
    #[prost(uint64, optional, tag = "1")]
    pub manifest_request_code: Option<u64>,
}

// ---------------------------------------------------------------------------
// Steam client Cloud service RPCs
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
pub struct CloudCdnReportNotification {
    #[prost(fixed64, optional, tag = "1")]
    pub steam_id: Option<u64>,
    #[prost(string, optional, tag = "2")]
    pub url: Option<String>,
    #[prost(bool, optional, tag = "3")]
    pub success: Option<bool>,
    #[prost(uint32, optional, tag = "4")]
    pub http_status_code: Option<u32>,
    #[prost(uint64, optional, tag = "5")]
    pub expected_bytes: Option<u64>,
    #[prost(uint64, optional, tag = "6")]
    pub received_bytes: Option<u64>,
    #[prost(uint32, optional, tag = "7")]
    pub duration: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudExternalStorageTransferReportNotification {
    #[prost(string, optional, tag = "1")]
    pub host: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub path: Option<String>,
    #[prost(bool, optional, tag = "3")]
    pub is_upload: Option<bool>,
    #[prost(bool, optional, tag = "4")]
    pub success: Option<bool>,
    #[prost(uint32, optional, tag = "5")]
    pub http_status_code: Option<u32>,
    #[prost(uint64, optional, tag = "6")]
    pub bytes_expected: Option<u64>,
    #[prost(uint64, optional, tag = "7")]
    pub bytes_actual: Option<u64>,
    #[prost(uint32, optional, tag = "8")]
    pub duration_ms: Option<u32>,
    #[prost(uint32, optional, tag = "9")]
    pub cell_id: Option<u32>,
    #[prost(bool, optional, tag = "10")]
    pub proxied: Option<bool>,
    #[prost(bool, optional, tag = "11")]
    pub ipv6_local: Option<bool>,
    #[prost(bool, optional, tag = "12")]
    pub ipv6_remote: Option<bool>,
    #[prost(uint32, optional, tag = "13")]
    pub time_to_connect_ms: Option<u32>,
    #[prost(uint32, optional, tag = "14")]
    pub time_to_send_request_ms: Option<u32>,
    #[prost(uint32, optional, tag = "15")]
    pub time_to_first_byte_ms: Option<u32>,
    #[prost(uint32, optional, tag = "16")]
    pub time_to_last_byte_ms: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudBeginAppUploadBatchRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(string, optional, tag = "2")]
    pub machine_name: Option<String>,
    #[prost(string, repeated, tag = "3")]
    pub files_to_upload: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub files_to_delete: Vec<String>,
    #[prost(uint64, optional, tag = "5")]
    pub client_id: Option<u64>,
    #[prost(uint64, optional, tag = "6")]
    pub app_build_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudBeginAppUploadBatchResponse {
    #[prost(uint64, optional, tag = "1")]
    pub batch_id: Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    pub app_change_number: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudCompleteAppUploadBatchRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub batch_id: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub batch_eresult: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudCompleteAppUploadBatchResponse {}

#[derive(Clone, prost::Message)]
pub struct CloudClientBeginFileUploadRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub file_size: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub raw_file_size: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub file_sha: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "5")]
    pub timestamp: Option<u64>,
    #[prost(string, optional, tag = "6")]
    pub filename: Option<String>,
    #[prost(uint32, optional, tag = "7")]
    pub platforms_to_sync: Option<u32>,
    #[prost(uint32, optional, tag = "9")]
    pub cell_id: Option<u32>,
    #[prost(bool, optional, tag = "10")]
    pub can_encrypt: Option<bool>,
    #[prost(bool, optional, tag = "11")]
    pub is_shared_file: Option<bool>,
    #[prost(uint32, optional, tag = "12")]
    pub deprecated_realm: Option<u32>,
    #[prost(uint64, optional, tag = "13")]
    pub upload_batch_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudHttpHeader {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub value: Option<String>,
}

#[derive(Clone, prost::Message)]
pub struct CloudFileUploadBlockDetails {
    #[prost(string, optional, tag = "1")]
    pub url_host: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub url_path: Option<String>,
    #[prost(bool, optional, tag = "3")]
    pub use_https: Option<bool>,
    #[prost(int32, optional, tag = "4")]
    pub http_method: Option<i32>,
    #[prost(message, repeated, tag = "5")]
    pub request_headers: Vec<CloudHttpHeader>,
    #[prost(uint64, optional, tag = "6")]
    pub block_offset: Option<u64>,
    #[prost(uint32, optional, tag = "7")]
    pub block_length: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub explicit_body_data: Option<Vec<u8>>,
    #[prost(bool, optional, tag = "9")]
    pub may_parallelize: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientBeginFileUploadResponse {
    #[prost(bool, optional, tag = "1")]
    pub encrypt_file: Option<bool>,
    #[prost(message, repeated, tag = "2")]
    pub block_requests: Vec<CloudFileUploadBlockDetails>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientCommitFileUploadRequest {
    #[prost(bool, optional, tag = "1")]
    pub transfer_succeeded: Option<bool>,
    #[prost(uint32, optional, tag = "2")]
    pub app_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub file_sha: Option<Vec<u8>>,
    #[prost(string, optional, tag = "4")]
    pub filename: Option<String>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientCommitFileUploadResponse {
    #[prost(bool, optional, tag = "1")]
    pub file_committed: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientFileDownloadRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(string, optional, tag = "2")]
    pub filename: Option<String>,
    #[prost(uint32, optional, tag = "3")]
    pub realm: Option<u32>,
    #[prost(bool, optional, tag = "4")]
    pub force_proxy: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientFileDownloadResponse {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub file_size: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub raw_file_size: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub sha_file: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "5")]
    pub timestamp: Option<u64>,
    #[prost(bool, optional, tag = "6")]
    pub is_explicit_delete: Option<bool>,
    #[prost(string, optional, tag = "7")]
    pub url_host: Option<String>,
    #[prost(string, optional, tag = "8")]
    pub url_path: Option<String>,
    #[prost(bool, optional, tag = "9")]
    pub use_https: Option<bool>,
    #[prost(message, repeated, tag = "10")]
    pub request_headers: Vec<CloudHttpHeader>,
    #[prost(bool, optional, tag = "11")]
    pub encrypted: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientDeleteFileRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(string, optional, tag = "2")]
    pub filename: Option<String>,
    #[prost(bool, optional, tag = "3")]
    pub is_explicit_delete: Option<bool>,
    #[prost(uint64, optional, tag = "4")]
    pub upload_batch_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientDeleteFileResponse {}

#[derive(Clone, prost::Message)]
pub struct CloudClientConflictResolutionNotification {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(bool, optional, tag = "2")]
    pub chose_local_files: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudGetAppFileChangelistRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub synced_change_number: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppFileInfo {
    #[prost(string, optional, tag = "1")]
    pub file_name: Option<String>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub sha_file: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "3")]
    pub timestamp: Option<u64>,
    #[prost(uint32, optional, tag = "4")]
    pub raw_file_size: Option<u32>,
    #[prost(int32, optional, tag = "5")]
    pub persist_state: Option<i32>,
    #[prost(uint32, optional, tag = "6")]
    pub platforms_to_sync: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    pub path_prefix_index: Option<u32>,
    #[prost(uint32, optional, tag = "8")]
    pub machine_name_index: Option<u32>,
    #[prost(bool, optional, tag = "9")]
    pub reupload_requested: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudGetAppFileChangelistResponse {
    #[prost(uint64, optional, tag = "1")]
    pub current_change_number: Option<u64>,
    #[prost(message, repeated, tag = "2")]
    pub files: Vec<CloudAppFileInfo>,
    #[prost(bool, optional, tag = "3")]
    pub is_only_delta: Option<bool>,
    #[prost(string, repeated, tag = "4")]
    pub path_prefixes: Vec<String>,
    #[prost(string, repeated, tag = "5")]
    pub machine_names: Vec<String>,
    #[prost(uint64, optional, tag = "6")]
    pub app_build_id_hwm: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppSessionSuspendRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub client_id: Option<u64>,
    #[prost(string, optional, tag = "3")]
    pub machine_name: Option<String>,
    #[prost(bool, optional, tag = "4")]
    pub cloud_sync_completed: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppSessionSuspendResponse {}

#[derive(Clone, prost::Message)]
pub struct CloudAppSessionResumeRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub client_id: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppSessionResumeResponse {}

#[derive(Clone, prost::Message)]
pub struct CloudAppLaunchIntentRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub client_id: Option<u64>,
    #[prost(string, optional, tag = "3")]
    pub machine_name: Option<String>,
    #[prost(bool, optional, tag = "4")]
    pub ignore_pending_operations: Option<bool>,
    #[prost(int32, optional, tag = "5")]
    pub os_type: Option<i32>,
    #[prost(int32, optional, tag = "6")]
    pub device_type: Option<i32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudPendingRemoteOperation {
    #[prost(int32, optional, tag = "1")]
    pub operation: Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub machine_name: Option<String>,
    #[prost(uint64, optional, tag = "3")]
    pub client_id: Option<u64>,
    #[prost(uint32, optional, tag = "4")]
    pub time_last_updated: Option<u32>,
    #[prost(int32, optional, tag = "5")]
    pub os_type: Option<i32>,
    #[prost(int32, optional, tag = "6")]
    pub device_type: Option<i32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppLaunchIntentResponse {
    #[prost(message, repeated, tag = "1")]
    pub pending_remote_operations: Vec<CloudPendingRemoteOperation>,
}

#[derive(Clone, prost::Message)]
pub struct CloudAppExitSyncDoneNotification {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub client_id: Option<u64>,
    #[prost(bool, optional, tag = "3")]
    pub uploads_completed: Option<bool>,
    #[prost(bool, optional, tag = "4")]
    pub uploads_required: Option<bool>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientGetAppQuotaUsageRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct CloudClientGetAppQuotaUsageResponse {
    #[prost(uint32, optional, tag = "1")]
    pub existing_files: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub existing_bytes: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub max_num_files: Option<u32>,
    #[prost(uint64, optional, tag = "4")]
    pub max_num_bytes: Option<u64>,
}

// ---------------------------------------------------------------------------
// Encrypted app ticket
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
pub struct GetAppOwnershipTicketRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct GetAppOwnershipTicketResponse {
    #[prost(uint32, optional, tag = "1")]
    pub eresult: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub app_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub ticket: Option<Vec<u8>>,
}

#[derive(Clone, prost::Message)]
pub struct EncryptedAppTicketRequest {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub userdata: Option<Vec<u8>>,
}

#[derive(Clone, prost::Message)]
pub struct EncryptedAppTicket {
    #[prost(uint32, optional, tag = "1")]
    pub ticket_version_no: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub crc_encryptedticket: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub cb_encrypteduserdata: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub cb_encrypted_appownershipticket: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub encrypted_ticket: Option<Vec<u8>>,
}

#[derive(Clone, prost::Message)]
pub struct EncryptedAppTicketResponse {
    #[prost(uint32, optional, tag = "1")]
    pub app_id: Option<u32>,
    #[prost(int32, optional, tag = "2")]
    pub eresult: Option<i32>,
    #[prost(message, optional, tag = "3")]
    pub encrypted_app_ticket: Option<EncryptedAppTicket>,
}

// ---------------------------------------------------------------------------
// PICS ProductInfo (access token injection)
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
pub struct PicsProductInfoRequest {
    #[prost(message, repeated, tag = "1")]
    pub packages: Vec<PicsPackageInfo>,
    #[prost(message, repeated, tag = "2")]
    pub apps: Vec<PicsAppInfo>,
    #[prost(bool, optional, tag = "3")]
    pub meta_data_only: Option<bool>,
    #[prost(uint32, optional, tag = "4")]
    pub num_prev_failed: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct PicsPackageInfo {
    #[prost(uint32, optional, tag = "1")]
    pub packageid: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub access_token: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct PicsAppInfo {
    #[prost(uint32, optional, tag = "1")]
    pub appid: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub access_token: Option<u64>,
    #[prost(bool, optional, tag = "3")]
    pub only_public_obsolete: Option<bool>,
}

// ---------------------------------------------------------------------------
// Achievement / stats messages
// ---------------------------------------------------------------------------

/// EMsg 151 outgoing: Player.GetUserStats#1 request
#[derive(Clone, prost::Message)]
pub struct PlayerGetUserStatsRequest {
    #[prost(uint64, optional, tag = "1")]
    pub steamid: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    pub appid: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub sha_schema: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "4")]
    pub crc_stats: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    pub crc_schema: Option<u32>,
}

/// EMsg 147 incoming: Player.GetUserStats#1 response
#[derive(Clone, prost::Message)]
pub struct PlayerGetUserStatsResponse {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub sha_schema: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "2")]
    pub crc_stats: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub schema: Option<Vec<u8>>,
    #[prost(message, repeated, tag = "4")]
    pub stats: Vec<PlayerStatsEntry>,
    #[prost(uint32, optional, tag = "5")]
    pub crc_schema: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct PlayerStatsEntry {
    #[prost(uint32, optional, tag = "1")]
    pub stat_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub stat_value: Option<u32>,
}

// ---------------------------------------------------------------------------
// Native Steam playtime snapshots
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
pub struct PlayerGetLastPlayedTimesResponse {
    #[prost(message, repeated, tag = "1")]
    pub games: Vec<PlayerLastPlayedGame>,
}

#[derive(Clone, prost::Message)]
pub struct PlayerLastPlayedGame {
    #[prost(int32, optional, tag = "1")]
    pub app_id: Option<i32>,
    #[prost(uint32, optional, tag = "2")]
    pub last_playtime: Option<u32>,
    #[prost(int32, optional, tag = "3")]
    pub playtime_2weeks: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    pub playtime_forever: Option<i32>,
    #[prost(uint32, optional, tag = "5")]
    pub first_playtime: Option<u32>,
    #[prost(int32, optional, tag = "6")]
    pub playtime_windows_forever: Option<i32>,
    #[prost(int32, optional, tag = "7")]
    pub playtime_mac_forever: Option<i32>,
    #[prost(int32, optional, tag = "8")]
    pub playtime_linux_forever: Option<i32>,
    #[prost(uint32, optional, tag = "9")]
    pub first_windows_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "10")]
    pub first_mac_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "11")]
    pub first_linux_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "12")]
    pub last_windows_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "13")]
    pub last_mac_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "14")]
    pub last_linux_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "15")]
    pub playtime_disconnected: Option<u32>,
    #[prost(int32, optional, tag = "16")]
    pub playtime_deck_forever: Option<i32>,
    #[prost(uint32, optional, tag = "17")]
    pub first_deck_playtime: Option<u32>,
    #[prost(uint32, optional, tag = "18")]
    pub last_deck_playtime: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct PlayerLastPlayedTimesNotification {
    #[prost(message, repeated, tag = "1")]
    pub games: Vec<PlayerLastPlayedGame>,
}

/// EMsg 818 outgoing: legacy CMsgClientGetUserStats
#[derive(Clone, prost::Message)]
pub struct ClientGetUserStatsRequest {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    pub crc_stats: Option<u32>,
    #[prost(int32, optional, tag = "3")]
    pub schema_local_version: Option<i32>,
    #[prost(fixed64, optional, tag = "4")]
    pub steam_id_for_user: Option<u64>,
}

/// EMsg 819 incoming: legacy CMsgClientGetUserStatsResponse
#[derive(Clone, prost::Message)]
pub struct ClientGetUserStatsResponse {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(int32, optional, tag = "2")]
    pub eresult: Option<i32>,
    #[prost(uint32, optional, tag = "3")]
    pub crc_stats: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub schema: Option<Vec<u8>>,
    #[prost(message, repeated, tag = "5")]
    pub stats: Vec<LegacyStatsEntry>,
    #[prost(message, repeated, tag = "6")]
    pub achievement_blocks: Vec<AchievementBlock>,
}

#[derive(Clone, prost::Message)]
pub struct LegacyStatsEntry {
    #[prost(uint32, optional, tag = "1")]
    pub stat_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub stat_value: Option<u32>,
}

#[derive(Clone, prost::Message)]
pub struct AchievementBlock {
    #[prost(uint32, optional, tag = "1")]
    pub achievement_id: Option<u32>,
    #[prost(fixed32, repeated, tag = "2")]
    pub unlock_time: Vec<u32>,
}

/// EMsg 820 outgoing: commit local stats to Steam.
#[derive(Clone, prost::Message)]
pub struct ClientStoreUserStatsRequest {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(bool, optional, tag = "2")]
    pub explicit_reset: Option<bool>,
    #[prost(message, repeated, tag = "3")]
    pub stats_to_store: Vec<StoreUserStatsEntry>,
}

#[derive(Clone, prost::Message)]
pub struct StoreUserStatsEntry {
    #[prost(uint32, optional, tag = "1")]
    pub stat_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub stat_value: Option<u32>,
}

/// EMsg 821 local acknowledgement for EMsg 820.
#[derive(Clone, prost::Message)]
pub struct ClientStoreUserStatsResponse {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(int32, optional, tag = "2")]
    pub eresult: Option<i32>,
    #[prost(uint32, optional, tag = "3")]
    pub crc_stats: Option<u32>,
    #[prost(bool, optional, tag = "5")]
    pub stats_out_of_date: Option<bool>,
}

/// EMsg 5466 outgoing: commit stats for a specific Steam user.
#[derive(Clone, prost::Message)]
pub struct ClientStoreUserStats2Request {
    #[prost(fixed64, optional, tag = "1")]
    pub game_id: Option<u64>,
    #[prost(fixed64, optional, tag = "2")]
    pub settor_steam_id: Option<u64>,
    #[prost(fixed64, optional, tag = "3")]
    pub settee_steam_id: Option<u64>,
    #[prost(uint32, optional, tag = "4")]
    pub crc_stats: Option<u32>,
    #[prost(bool, optional, tag = "5")]
    pub explicit_reset: Option<bool>,
    #[prost(message, repeated, tag = "6")]
    pub stats: Vec<StoreUserStatsEntry>,
}

/// EMsg 5467 local acknowledgement for EMsg 5466.
#[derive(Clone, prost::Message)]
pub struct ClientStatsUpdated {
    #[prost(fixed64, optional, tag = "1")]
    pub steam_id: Option<u64>,
    #[prost(fixed64, optional, tag = "2")]
    pub game_id: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub crc_stats: Option<u32>,
    #[prost(message, repeated, tag = "4")]
    pub updated_stats: Vec<StoreUserStatsEntry>,
}

/// EMsg for CMsgClientPICSProductInfoRequest
pub const EMSG_PICS_PRODUCT_INFO_REQUEST: u32 = 8903;

/// EMsg for CMsgClientRequestEncryptedAppTicketResponse
pub const EMSG_ENCRYPTED_APPTICKET_RESPONSE: u32 = 5527;
/// EMsg for CMsgClientRequestEncryptedAppTicket.
pub const EMSG_ENCRYPTED_APPTICKET_REQUEST: u32 = 5526;

/// EMsg ownership ticket request and response.
pub const EMSG_GET_APP_OWNERSHIP_TICKET: u32 = 857;
pub const EMSG_GET_APP_OWNERSHIP_TICKET_RESPONSE: u32 = 858;

/// EMsg constants for stats
pub const EMSG_REQUEST_USERSTATS: u32 = 818;
pub const EMSG_REQUEST_USERSTATS_RESPONSE: u32 = 819;
pub const EMSG_STORE_USERSTATS: u32 = 820;
pub const EMSG_STORE_USERSTATS_RESPONSE: u32 = 821;
pub const EMSG_STORE_USERSTATS2: u32 = 5466;
pub const EMSG_STATS_UPDATED: u32 = 5467;

// ---------------------------------------------------------------------------
// GamesPlayed messages
// ---------------------------------------------------------------------------

/// EMsg for CMsgClientGamesPlayed (modern path).
pub const EMSG_GAMESPLAYED: u32 = 742;
/// EMsg for CMsgClientGamesPlayedWithDataBlob (older path with extra blob).
pub const EMSG_GAMESPLAYED_WITH_DATABLOB: u32 = 5410;

#[derive(Clone, prost::Message)]
pub struct CMsgClientGamesPlayed {
    #[prost(message, repeated, tag = "1")]
    pub games_played: Vec<GamePlayed>,
}

#[derive(Clone, prost::Message)]
pub struct GamePlayed {
    #[prost(uint64, optional, tag = "1")]
    pub steam_id_gs: Option<u64>,
    #[prost(fixed64, optional, tag = "2")]
    pub game_id: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub deprecated_game_ip_address: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub game_port: Option<u32>,
    #[prost(bool, optional, tag = "5")]
    pub is_secure: Option<bool>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub token: Option<Vec<u8>>,
    #[prost(string, optional, tag = "7")]
    pub game_extra_info: Option<String>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub game_data_blob: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "9")]
    pub process_id: Option<u32>,
    #[prost(uint32, optional, tag = "10")]
    pub streaming_provider_id: Option<u32>,
    #[prost(uint32, optional, tag = "11")]
    pub game_flags: Option<u32>,
    #[prost(uint32, optional, tag = "12")]
    pub owner_id: Option<u32>,
}

/// EResult constants
pub const ERESULT_OK: i32 = 1;
pub const ERESULT_NO_CONNECTION: i32 = 3;

// ---------------------------------------------------------------------------
// Rich Presence / PersonaState messages (AppAvatar rewriting)
// ---------------------------------------------------------------------------

/// EMsg for CMsgClientPersonaState.
pub const EMSG_CLIENT_PERSONA_STATE: u32 = 766;
/// EMsg for CMsgClientRichPresenceUpload.
pub const EMSG_CLIENT_RICH_PRESENCE_UPLOAD: u32 = 7501;

/// k_EClientPersonaStateFlagRichPresence: top-level status_flags bit meaning
/// "this message carries rich presence field data".
pub const ECLIENTPERSONASTATEFLAG_RICH_PRESENCE: u32 = 0x1000;
/// k_EPersonaStateFlag_HasRichPresence: per-friend persona_state_flags bit
/// meaning "this friend currently has rich presence set".
pub const EPERSONASTATEFLAG_HAS_RICH_PRESENCE: u32 = 0x1;

#[derive(Clone, prost::Message)]
pub struct PersonaStateKV {
    #[prost(string, optional, tag = "1")]
    pub key: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub value: Option<String>,
}

#[derive(Clone, prost::Message)]
pub struct PersonaStateFriend {
    #[prost(fixed64, optional, tag = "1")]
    pub friendid: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    pub persona_state: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub game_played_app_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub persona_state_flags: Option<u32>,
    #[prost(string, optional, tag = "55")]
    pub game_name: Option<String>,
    #[prost(fixed64, optional, tag = "56")]
    pub gameid: Option<u64>,
    #[prost(message, repeated, tag = "71")]
    pub rich_presence: Vec<PersonaStateKV>,
}

#[derive(Clone, prost::Message)]
pub struct ClientPersonaState {
    #[prost(uint32, optional, tag = "1")]
    pub status_flags: Option<u32>,
    #[prost(message, repeated, tag = "2")]
    pub friends: Vec<PersonaStateFriend>,
}

#[derive(Clone, prost::Message)]
pub struct ClientRichPresenceUpload {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub rich_presence_kv: Option<Vec<u8>>,
    #[prost(fixed64, repeated, tag = "2")]
    pub steamid_broadcast: Vec<u64>,
}

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
        }

        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(cnet_packet::DATA_OFFSET, 0x08);
            assert_eq!(cnet_packet::SIZE_OFFSET, 0x10);
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
    fn unpack_assemble_roundtrip() {
        let hdr = b"\x01\x02\x03";
        let body = b"\x0A\x0B";
        let emsg: u32 = 0x8000_0097;
        let packet = assemble_raw(emsg, hdr, body);
        let (e, h, b) = unpack_raw(&packet).unwrap();
        assert_eq!(e, emsg);
        assert_eq!(h, hdr);
        assert_eq!(b, body);
    }

    #[test]
    fn unpack_too_short() {
        assert!(unpack_raw(&[0; 7]).is_none());
        assert!(unpack_raw(&[]).is_none());
    }

    #[test]
    fn unpack_header_length_overflow() {
        let mut packet = assemble_raw(1, b"hdr", b"body");
        // corrupt header_length to exceed packet size
        packet[4] = 0xFF;
        packet[5] = 0xFF;
        assert!(unpack_raw(&packet).is_none());
    }

    #[test]
    fn unpack_empty_header_and_body() {
        let packet = assemble_raw(42, &[], &[]);
        let (e, h, b) = unpack_raw(&packet).unwrap();
        assert_eq!(e, 42);
        assert!(h.is_empty());
        assert!(b.is_empty());
    }

    #[test]
    fn unpack_header_only_no_body() {
        let packet = assemble_raw(1, b"header_data", &[]);
        let (_, h, b) = unpack_raw(&packet).unwrap();
        assert_eq!(h, b"header_data");
        assert!(b.is_empty());
    }

    #[test]
    fn app_ownership_info_size() {
        assert_eq!(mem::size_of::<CAppOwnershipInfo>(), CAppOwnershipInfo::SIZE);
        assert_eq!(CAppOwnershipInfo::SIZE, 0x38);
    }

    #[test]
    fn app_ownership_info_exist_in_package_nums_offset() {
        assert_eq!(CAppOwnershipInfo::EXIST_IN_PACKAGE_NUMS_OFFSET, 0x14);
    }

    #[test]
    fn app_ownership_info_purchase_time_offset() {
        assert_eq!(CAppOwnershipInfo::PURCHASE_TIME_OFFSET, 0x1C);
    }

    #[test]
    fn app_ownership_info_owns_license_offset() {
        assert_eq!(CAppOwnershipInfo::OWNS_LICENSE_OFFSET, 0x28);
    }

    #[test]
    fn app_ownership_info_license_permanent_offset() {
        assert_eq!(CAppOwnershipInfo::LICENSE_PERMANENT_OFFSET, 0x30);
    }

    #[test]
    fn app_ownership_info_license_flags_offset() {
        assert_eq!(CAppOwnershipInfo::LICENSE_FLAGS_OFFSET, 0x33);
    }

    #[test]
    fn app_ownership_info_family_shared_offset() {
        assert_eq!(CAppOwnershipInfo::FAMILY_SHARED_OFFSET, 0x35);
    }

    #[test]
    fn app_ownership_info_spoof_helpers_use_layout_offsets() {
        let mut info = CAppOwnershipInfo::zeroed();
        info.grant_spoofed_ownership(1_600_000_000);

        assert_eq!(info.owner(), 1);
        assert_eq!(info.owns_license(), 1);
        assert_eq!(info.license_permanent(), 1);
        assert!(!info.is_family_shared());

        info.set_owner(42);
        info.set_family_shared(true);
        assert_eq!(info.owner(), 42);
        assert!(info.is_family_shared());

        info.clear_family_shared();
        assert!(!info.is_family_shared());
    }

    #[test]
    fn depot_entry_size() {
        assert_eq!(mem::size_of::<super::DepotEntry>(), 0x20);
    }

    #[test]
    fn depot_entry_manifest_gid_offset() {
        let offset = mem::offset_of!(super::DepotEntry, manifest_gid);
        assert_eq!(offset, 0x08);
    }

    #[test]
    fn depot_entry_manifest_size_offset() {
        let offset = mem::offset_of!(super::DepotEntry, manifest_size);
        assert_eq!(offset, 0x10);
    }

    #[test]
    fn depot_entry_dlc_app_id_offset() {
        let offset = mem::offset_of!(super::DepotEntry, dlc_app_id);
        assert_eq!(offset, 0x18);
    }
}
