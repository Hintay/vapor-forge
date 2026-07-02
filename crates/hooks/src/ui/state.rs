use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use retour::GenericDetour;

pub(crate) const EAPP_OWNERSHIP_FLAGS_NONE: u32 = 0;
pub(crate) const EAPP_STATE_UNINSTALLED: u32 = 0;
pub(crate) const EAPPCHANGE_ADDED_OR_CREATED: u32 = 1;

pub(crate) type GetAppByIdFn = extern "C" fn(*mut c_void, u32, bool) -> *mut c_void;
pub(crate) type MarkAppChangeFn = extern "C" fn(*mut c_void, u32, u32);
pub(crate) type RepeatedFieldAddFn = extern "C" fn(*mut c_void, *const u32);

pub(crate) static mut GET_APP_BY_ID_DETOUR: Option<GenericDetour<GetAppByIdFn>> = None;
pub(crate) static mut MARK_APP_CHANGE_DETOUR: Option<GenericDetour<MarkAppChangeFn>> = None;

pub(crate) static CONTROLLER: AtomicUsize = AtomicUsize::new(0);
pub(crate) static APP_CHANGE_SOURCE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static INSTALLED: AtomicBool = AtomicBool::new(false);
