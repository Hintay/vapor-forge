#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
pub(crate) mod achievement_worker;
#[cfg(target_os = "linux")]
pub(crate) mod client;
#[cfg(any(
    all(target_os = "linux", debug_assertions),
    all(test, target_family = "unix")
))]
#[cfg_attr(all(not(target_os = "linux"), test), allow(dead_code))]
pub(crate) mod debug_api;
#[cfg(any(target_os = "linux", test))]
pub(crate) mod hook_report;
#[cfg(target_os = "linux")]
pub(crate) mod ipc_server;
#[cfg(target_os = "linux")]
pub(crate) mod netpacket;
#[cfg(any(target_os = "linux", test))]
pub(crate) mod packet_capture;
#[cfg(target_os = "linux")]
pub(crate) mod playtime_worker;
#[cfg(target_os = "linux")]
pub(crate) mod ui;
#[cfg(target_os = "linux")]
pub(crate) mod vtable_scan;
#[cfg(target_os = "linux")]
pub(crate) mod watcher;

#[cfg(target_os = "linux")]
pub use client::install::{
    ensure_runtime_initialized, install_hook_batch, is_hook_batch_finished, HookBatch,
};
#[cfg(target_os = "linux")]
pub use vapor_forge_hook_engine::detour::restore_trampoline_pages_rx;
