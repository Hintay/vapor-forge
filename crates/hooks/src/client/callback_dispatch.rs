//! Registered Steam event contracts.

use core::ffi::c_void;

const MAX_API_RESULT_PAYLOAD: usize = 1024 * 1024;
pub(super) const MAX_INTERNAL_CALLBACK_PAYLOAD: usize = 32;

/// `UserStatsReceived_t`.
pub(super) const USER_STATS_RECEIVED: i32 = 1101;
/// `AppMinutesPlayedDataNotice_t`.
pub(super) const APP_MINUTES_PLAYED_DATA_NOTICE: i32 = 0x000f_908e;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CallbackRegistration {
    pub(super) id: i32,
    pub(super) name: &'static str,
    pub(super) payload_size: usize,
}

/// Internal callbacks with an in-process consumer.
pub(super) const REGISTRATIONS: &[CallbackRegistration] = &[CallbackRegistration {
    id: APP_MINUTES_PLAYED_DATA_NOTICE,
    name: "AppMinutesPlayedDataNotice_t",
    payload_size: 4,
}];

/// API-call results accepted from registered handles.
pub(super) const API_RESULT_REGISTRATIONS: &[CallbackRegistration] = &[CallbackRegistration {
    id: USER_STATS_RECEIVED,
    name: "UserStatsReceived_t",
    payload_size: 20,
}];

#[inline]
pub(super) fn registration(id: i32) -> Option<&'static CallbackRegistration> {
    REGISTRATIONS.iter().find(|entry| entry.id == id)
}

#[inline]
pub(super) fn is_api_result_registered(id: i32) -> bool {
    API_RESULT_REGISTRATIONS.iter().any(|entry| entry.id == id)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CallbackHeader {
    pub(super) steam_user: i32,
    pub(super) callback: i32,
    pub(super) payload_size: i32,
}

/// One fixed-size internal callback copied during `Run`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CallbackEvent {
    pub(super) header: CallbackHeader,
    pub(super) identity_generation: u64,
    pub(super) steam_id64: u64,
    payload: [u8; MAX_INTERNAL_CALLBACK_PAYLOAD],
}

impl CallbackEvent {
    /// Copy a registered fixed-size payload while Steam owns it.
    ///
    /// # Safety
    /// `payload` must cover the registered payload size for this call.
    pub(super) unsafe fn copy_from_raw(
        steam_user: i32,
        identity_generation: u64,
        steam_id64: u64,
        registration: &CallbackRegistration,
        payload: *const c_void,
    ) -> Option<Self> {
        if payload.is_null() || registration.payload_size > MAX_INTERNAL_CALLBACK_PAYLOAD {
            return None;
        }
        let mut copied = [0u8; MAX_INTERNAL_CALLBACK_PAYLOAD];
        // SAFETY: the caller guarantees the fixed registered payload contract.
        unsafe {
            std::ptr::copy_nonoverlapping(
                payload.cast::<u8>(),
                copied.as_mut_ptr(),
                registration.payload_size,
            )
        };
        Some(Self {
            header: CallbackHeader {
                steam_user,
                callback: registration.id,
                payload_size: registration.payload_size as i32,
            },
            identity_generation,
            steam_id64,
            payload: copied,
        })
    }

    pub(super) fn decode<T: SteamPayload>(&self) -> Option<T> {
        let size = usize::try_from(self.header.payload_size).ok()?;
        (self.header.callback == T::CALLBACK_ID && size <= self.payload.len())
            .then(|| T::decode(&self.payload[..size]))
            .flatten()
    }

    #[cfg(test)]
    pub(super) fn from_bytes(
        steam_user: i32,
        identity_generation: u64,
        steam_id64: u64,
        callback: i32,
        payload: &[u8],
    ) -> Self {
        let mut copied = [0u8; MAX_INTERNAL_CALLBACK_PAYLOAD];
        let size = payload.len().min(copied.len());
        copied[..size].copy_from_slice(&payload[..size]);
        Self {
            header: CallbackHeader {
                steam_user,
                callback,
                payload_size: payload.len() as i32,
            },
            identity_generation,
            steam_id64,
            payload: copied,
        }
    }
}

pub(super) trait SteamPayload: Sized {
    const CALLBACK_ID: i32;

    fn decode(payload: &[u8]) -> Option<Self>;
}

/// A registered `SteamAPICall_t` and its copied result payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ApiCallResultEvent {
    pub(super) api_call: u64,
    pub(super) callback: i32,
    pub(super) payload_size: i32,
    payload: Box<[u8]>,
}

impl ApiCallResultEvent {
    pub(super) fn new(api_call: u64, callback: i32, payload_size: i32, payload: Box<[u8]>) -> Self {
        Self {
            api_call,
            callback,
            payload_size,
            payload,
        }
    }

    /// # Safety
    /// A positive accepted size requires `payload` to cover that many readable bytes.
    pub(super) unsafe fn copy_from_raw(
        api_call: u64,
        callback: i32,
        payload_size: i32,
        payload: *const c_void,
    ) -> Self {
        // SAFETY: the caller provides the live Steam payload for this frame.
        let copied = unsafe { copy_payload_from_raw(payload_size, payload) };
        Self::new(api_call, callback, payload_size, copied)
    }

    pub(super) fn decode<T: SteamPayload>(&self) -> Option<T> {
        (self.callback == T::CALLBACK_ID)
            .then(|| T::decode(&self.payload))
            .flatten()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AppMinutesPlayedDataNotice {
    pub(super) app_id: u32,
}

impl SteamPayload for AppMinutesPlayedDataNotice {
    const CALLBACK_ID: i32 = APP_MINUTES_PLAYED_DATA_NOTICE;

    fn decode(payload: &[u8]) -> Option<Self> {
        (payload.len() == 4).then(|| Self {
            app_id: u32::from_le_bytes(payload.try_into().expect("length checked")),
        })
    }
}

/// Steam's packed-4 `UserStatsReceived_t` result.
#[repr(C, packed(4))]
#[derive(Clone, Copy, Default)]
pub(super) struct UserStatsReceived {
    pub(super) game_id: u64,
    pub(super) result: i32,
    pub(super) steam_id: u64,
}

impl SteamPayload for UserStatsReceived {
    const CALLBACK_ID: i32 = USER_STATS_RECEIVED;

    fn decode(payload: &[u8]) -> Option<Self> {
        (payload.len() == 20).then(|| Self {
            game_id: u64::from_le_bytes(payload[0..8].try_into().expect("length checked")),
            result: i32::from_le_bytes(payload[8..12].try_into().expect("length checked")),
            steam_id: u64::from_le_bytes(payload[12..20].try_into().expect("length checked")),
        })
    }
}

unsafe fn copy_payload_from_raw(payload_size: i32, payload: *const c_void) -> Box<[u8]> {
    usize::try_from(payload_size)
        .ok()
        .filter(|size| *size <= MAX_API_RESULT_PAYLOAD)
        .and_then(|size| {
            if size == 0 {
                return Some(Box::default());
            }
            if payload.is_null() {
                return None;
            }
            // SAFETY: the caller guarantees the live Steam payload covers size.
            Some(unsafe { std::slice::from_raw_parts(payload.cast::<u8>(), size) }.into())
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_filters_unregistered_callbacks() {
        assert_eq!(
            registration(APP_MINUTES_PLAYED_DATA_NOTICE)
                .unwrap()
                .payload_size,
            4
        );
        assert!(registration(703).is_none());
        assert!(registration(USER_STATS_RECEIVED).is_none());
        assert!(is_api_result_registered(USER_STATS_RECEIVED));
        assert!(!is_api_result_registered(703));
    }

    #[test]
    fn fixed_callback_decoder_rejects_wrong_contract() {
        let short = CallbackEvent::from_bytes(3, 1, 7, APP_MINUTES_PLAYED_DATA_NOTICE, &[0; 3]);
        assert_eq!(short.decode::<AppMinutesPlayedDataNotice>(), None);
        let wrong = CallbackEvent::from_bytes(3, 1, 7, 42, &480u32.to_le_bytes());
        assert_eq!(wrong.decode::<AppMinutesPlayedDataNotice>(), None);
    }
}
