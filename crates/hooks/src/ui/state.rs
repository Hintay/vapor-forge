use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use vapor_forge_hook_engine::detour::Detour;

pub(crate) const EAPP_OWNERSHIP_FLAGS_NONE: u32 = 0;
pub(crate) const EAPP_STATE_UNINSTALLED: u32 = 1;
pub(crate) const EAPPCHANGE_ADDED_OR_CREATED: u32 = 1;

pub(crate) type GetAppByIdFn = unsafe extern "C" fn(*mut c_void, u32, bool) -> *mut c_void;
pub(crate) type MarkAppChangeFn = unsafe extern "C" fn(*mut c_void, u32, u32);
pub(crate) type RepeatedFieldAddFn = unsafe extern "C" fn(*mut c_void, *const u32);

pub(crate) static mut GET_APP_BY_ID_DETOUR: Option<Detour<GetAppByIdFn>> = None;
pub(crate) static mut MARK_APP_CHANGE_DETOUR: Option<Detour<MarkAppChangeFn>> = None;

pub(crate) static APP_CHANGE_SOURCE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static CONFLICT_UI_READY: AtomicBool = AtomicBool::new(false);
