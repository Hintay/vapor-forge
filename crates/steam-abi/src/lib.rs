#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::c_void;

// Valve's CUtlMemory/CUtlVector (32-bit layout)
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

    pub fn capacity(&self) -> usize {
        self.m_n_allocation_count() as usize
    }

    fn m_n_allocation_count(&self) -> u32 {
        self.m_memory.m_n_allocation_count
    }

    /// # Safety
    /// Index must be < len().
    pub unsafe fn get(&self, index: usize) -> &T {
        unsafe { &*self.m_memory.m_p_memory.add(index) }
    }

    /// # Safety
    /// Index must be < len().
    pub unsafe fn get_mut(&mut self, index: usize) -> &mut T {
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

// PackageInfo accessors (offsets from 32-bit steamclient.so)
pub mod package_info {
    use super::CUtlVector;

    const STATUS_OFF: usize = 0x18;
    const APP_ID_VEC_OFF: usize = 0x38;

    /// # Safety
    /// pkg must point to a valid PackageInfo struct in Steam memory.
    pub unsafe fn status(pkg: *const u8) -> u32 {
        unsafe { *(pkg.add(STATUS_OFF) as *const u32) }
    }

    /// # Safety
    /// pkg must point to a valid PackageInfo struct in Steam memory.
    pub unsafe fn app_id_vec(pkg: *mut u8) -> *mut CUtlVector<u32> {
        // SAFETY: caller guarantees pkg points to a valid PackageInfo struct.
        unsafe { pkg.add(APP_ID_VEC_OFF) as *mut CUtlVector<u32> }
    }
}

pub mod steamui {
    use core::ffi::c_void;
    use core::marker::PhantomData;

    #[repr(transparent)]
    struct Ptr32<T> {
        _addr: u32,
        _marker: PhantomData<*mut T>,
    }

    #[repr(C)]
    struct RepeatedPtrFieldOpaque {
        _words: [u32; 4],
    }

    #[repr(C)]
    struct RepeatedFieldU32Opaque {
        _current_size: i32,
        _total_size: i32,
        _elements: Ptr32<u32>,
    }

    #[repr(C)]
    pub struct CAppOverviewChange {
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

    const _: () = {
        assert!(CAppOverviewChange::REMOVED_APPID_OFFSET == 0x20);
    };

    #[cfg(test)]
    mod tests {
        use super::*;
        use core::mem;

        #[test]
        fn repeated_ptr_field_size() {
            assert_eq!(mem::size_of::<RepeatedPtrFieldOpaque>(), 0x10);
        }

        #[test]
        fn repeated_field_u32_size() {
            assert_eq!(mem::size_of::<RepeatedFieldU32Opaque>(), 0x0c);
        }

        #[test]
        fn ptr32_size() {
            assert_eq!(mem::size_of::<Ptr32<u32>>(), 0x04);
        }

        #[test]
        fn app_overview_change_removed_appid_offset() {
            assert_eq!(CAppOverviewChange::REMOVED_APPID_OFFSET, 0x20);
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
pub type MarkLicenseAsChangedFn = extern "C" fn(*mut c_void, u32, bool) -> i64;
pub type ProcessPendingLicenseUpdatesFn = extern "C" fn(*mut c_void) -> bool;
pub type CUtlMemoryGrowFn = extern "C" fn(*mut c_void, i32) -> *mut c_void;

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
// Encrypted app ticket
// ---------------------------------------------------------------------------

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

/// EMsg for CMsgClientPICSProductInfoRequest
pub const EMSG_PICS_PRODUCT_INFO_REQUEST: u32 = 8903;

/// EMsg for CMsgClientRequestEncryptedAppTicketResponse
pub const EMSG_ENCRYPTED_APPTICKET_RESPONSE: u32 = 5527;

/// EMsg constants for stats
pub const EMSG_REQUEST_USERSTATS: u32 = 818;
pub const EMSG_REQUEST_USERSTATS_RESPONSE: u32 = 819;

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
// Rich Presence / PersonaState messages (AppAvatar spoofing)
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

    #[test]
    fn depot_entry_size() {
        assert_eq!(mem::size_of::<super::DepotEntry>(), 0x20);
    }

    #[test]
    fn depot_entry_manifest_gid_offset() {
        let base = core::ptr::null::<super::DepotEntry>();
        // SAFETY: null pointer field offset calculation, no dereference
        let offset = unsafe { core::ptr::addr_of!((*base).manifest_gid) as usize };
        assert_eq!(offset, 0x08);
    }

    #[test]
    fn depot_entry_manifest_size_offset() {
        let base = core::ptr::null::<super::DepotEntry>();
        // SAFETY: null pointer field offset calculation, no dereference
        let offset = unsafe { core::ptr::addr_of!((*base).manifest_size) as usize };
        assert_eq!(offset, 0x10);
    }

    #[test]
    fn depot_entry_dlc_app_id_offset() {
        let base = core::ptr::null::<super::DepotEntry>();
        // SAFETY: null pointer field offset calculation, no dereference
        let offset = unsafe { core::ptr::addr_of!((*base).dlc_app_id) as usize };
        assert_eq!(offset, 0x18);
    }
}
