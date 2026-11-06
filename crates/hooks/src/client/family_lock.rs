use core::ffi::c_void;

use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::detour_or_return;

pub(crate) const GET_LOCKING_ACCOUNT_NAME: &str = "CFamilySharing::GetLockingAccount";

pub(crate) type GetLockingAccountFn = unsafe extern "C" fn(*mut c_void, u32) -> u32;

pub(crate) static mut GET_LOCKING_ACCOUNT_DETOUR: Option<Detour<GetLockingAccountFn>> = None;

/// Reports controlled apps and apps the sharing policy allows as unlocked.
/// Steam blocks launching an app, flags it as in use and shows the locking
/// member in the UI from this lookup; the lock table itself stays intact.
pub(crate) unsafe extern "C" fn hk_get_locking_account(family: *mut c_void, app_id: u32) -> u32 {
    let original = detour_or_return!(GET_LOCKING_ACCOUNT_NAME, GET_LOCKING_ACCOUNT_DETOUR, 0);
    // SAFETY: forwards Steam's family object and app ID to the original lookup.
    let account = unsafe { original(family, app_id) };
    if account != 0
        && crate::capability::is_ready(crate::capability::Capability::FamilyLockBypass)
        && vapor_forge_features::valve_filter::bypasses_family_lock(
            &crate::client::install::config(),
            AppId(app_id),
        )
    {
        return 0;
    }
    account
}
