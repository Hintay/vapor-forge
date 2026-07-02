#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
pub mod client;
#[cfg(all(target_os = "linux", debug_assertions))]
pub mod debug_api;
#[cfg(target_os = "linux")]
pub mod detour;
#[cfg(target_os = "linux")]
pub(crate) mod hook_report;
#[cfg(target_os = "linux")]
pub use client::install;
#[cfg(target_os = "linux")]
pub use client::package;
#[cfg(target_os = "linux")]
pub mod ipc_server;
#[cfg(target_os = "linux")]
pub mod netpacket;
#[cfg(target_os = "linux")]
pub(crate) mod original;
pub mod pic_thunk;
#[cfg(target_os = "linux")]
pub mod ui;
#[cfg(target_os = "linux")]
pub use ui::install as steamui;
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
