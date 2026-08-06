use core::ffi::{c_char, c_void, CStr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::detour_or_return;

use super::steam_context::CapturedInterfaces;

pub(crate) const SET_UINT64_NAME: &str = "IClientConfigStore::SetUint64";
const INSTALL_CONFIG_STORE: u32 = 1;
const CLIENT_ID_KEY: &[u8] = b"streaming/ClientID\0";
const SITE_LICENSE_KEY: &[u8] = b"sitelicense/ClientID\0";

static CAPTURE_ARMED: AtomicBool = AtomicBool::new(false);
static CAPTURE_REVISION: AtomicU64 = AtomicU64::new(0);
static CAPTURE_CONFIG_STORE: AtomicUsize = AtomicUsize::new(0);

type GetUint64Fn = unsafe extern "C" fn(*mut c_void, u32, *const c_char, u64) -> u64;
pub(crate) type SetUint64Fn = unsafe extern "C" fn(*mut c_void, u32, *const c_char, u64) -> bool;
pub(crate) static mut SET_UINT64_DETOUR: Option<Detour<SetUint64Fn>> = None;

pub(super) fn read_or_arm(captured: CapturedInterfaces) -> Result<Option<u64>, &'static str> {
    let getter_address = crate::vtable_scan::config_store_uint64_method_address(
        vapor_forge_patterns::vtable_scan::ConfigStoreUint64Method::Get,
    )
    .map_err(|_| "IClientConfigStore::GetUint64 semantic validation failed")?;
    if getter_address == 0 {
        return Err("IClientConfigStore::GetUint64 address is invalid");
    }
    // SAFETY: runtime vtable discovery identified this method on the captured
    // IClientConfigStore wrapper.
    let getter: GetUint64Fn = unsafe { std::mem::transmute(getter_address) };

    arm_capture(captured);
    let result = super::steam_context::checked_call(captured, || {
        read_client_id(getter, captured.config_store)
    });
    match result {
        Ok(Some(value)) => {
            cancel_capture();
            Ok(Some(value))
        }
        Ok(None) => Ok(None),
        Err(error) => {
            cancel_capture();
            Err(error)
        }
    }
}

fn arm_capture(captured: CapturedInterfaces) {
    CAPTURE_REVISION.store(captured.revision, Ordering::Relaxed);
    CAPTURE_CONFIG_STORE.store(captured.config_store as usize, Ordering::Relaxed);
    CAPTURE_ARMED.store(true, Ordering::Release);
}

pub(crate) fn cancel_capture() {
    CAPTURE_ARMED.store(false, Ordering::Release);
}

pub(crate) unsafe extern "C" fn hk_set_uint64(
    this: *mut c_void,
    store: u32,
    key: *const c_char,
    value: u64,
) -> bool {
    let original = detour_or_return!(SET_UINT64_NAME, SET_UINT64_DETOUR, false);
    // SAFETY: the typed Steam function and arguments satisfy the active hook contract.
    let result = unsafe { original(this, store, key, value) };

    if !crate::capability::is_ready(crate::capability::Capability::CallbackEvents)
        || !CAPTURE_ARMED.load(Ordering::Acquire)
        || store != INSTALL_CONFIG_STORE
        || value == 0
        || this as usize != CAPTURE_CONFIG_STORE.load(Ordering::Relaxed)
        || !is_client_id_key(key)
    {
        return result;
    }
    let revision = CAPTURE_REVISION.load(Ordering::Relaxed);
    if !super::steam_context::config_store_is_current(revision, this)
        || CAPTURE_ARMED
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return result;
    }
    crate::netpacket::complete_client_id_capture(value);
    result
}

fn is_client_id_key(key: *const c_char) -> bool {
    if key.is_null() {
        return false;
    }
    // SAFETY: SetUint64 requires a readable NUL-terminated key for this call.
    let key = unsafe { CStr::from_ptr(key) }.to_bytes_with_nul();
    key == CLIENT_ID_KEY || key == SITE_LICENSE_KEY
}

fn read_client_id(getter: GetUint64Fn, config_store: *mut c_void) -> Option<u64> {
    // SAFETY: the caller holds the captured owner context for both calls.
    let streaming = unsafe {
        getter(
            config_store,
            INSTALL_CONFIG_STORE,
            CLIENT_ID_KEY.as_ptr().cast(),
            0,
        )
    };
    if streaming != 0 {
        return Some(streaming);
    }
    // SAFETY: the caller holds the captured owner context for both calls.
    let site_license = unsafe {
        getter(
            config_store,
            INSTALL_CONFIG_STORE,
            SITE_LICENSE_KEY.as_ptr().cast(),
            0,
        )
    };
    (site_license != 0).then_some(site_license)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static VALUES: Mutex<(u64, u64, usize)> = Mutex::new((0, 0, 0));

    unsafe extern "C" fn fake_getter(
        _this: *mut c_void,
        store: u32,
        key: *const c_char,
        _default: u64,
    ) -> u64 {
        assert_eq!(store, INSTALL_CONFIG_STORE);
        // SAFETY: tests pass one of the module's static keys.
        let key = unsafe { CStr::from_ptr(key) }.to_bytes_with_nul();
        let mut values = VALUES.lock().unwrap();
        values.2 += 1;
        if key == CLIENT_ID_KEY {
            values.0
        } else if key == SITE_LICENSE_KEY {
            values.1
        } else {
            0
        }
    }

    #[test]
    fn streaming_client_id_avoids_site_license_read() {
        let _guard = TEST_LOCK.lock().unwrap();
        *VALUES.lock().unwrap() = (7, 9, 0);
        assert_eq!(read_client_id(fake_getter, std::ptr::null_mut()), Some(7));
        assert_eq!(VALUES.lock().unwrap().2, 1);
    }

    #[test]
    fn site_license_is_read_only_after_zero_streaming_value() {
        let _guard = TEST_LOCK.lock().unwrap();
        *VALUES.lock().unwrap() = (0, 9, 0);
        assert_eq!(read_client_id(fake_getter, std::ptr::null_mut()), Some(9));
        assert_eq!(VALUES.lock().unwrap().2, 2);
    }
}
