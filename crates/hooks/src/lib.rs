#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
pub mod detour;
#[cfg(target_os = "linux")]
pub mod install;
#[cfg(target_os = "linux")]
pub mod ipc_server;
#[cfg(target_os = "linux")]
pub mod netpacket;
#[cfg(target_os = "linux")]
pub mod package;
pub mod pic_thunk;
#[cfg(target_os = "linux")]
pub mod vmt;
#[cfg(target_os = "linux")]
pub mod vtable_scan;
#[cfg(target_os = "linux")]
pub mod watcher;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum HookError {
    #[error("no PIC thunk call found in the scanned region")]
    NoPicThunkFound,
    #[error("PIC thunk uses an unsupported register (reg_field={0})")]
    UnsupportedThunkRegister(u8),
    #[error("mprotect failed: {0}")]
    MprotectFailed(i32),
}
