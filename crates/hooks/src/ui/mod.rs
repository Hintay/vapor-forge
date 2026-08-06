pub mod install;
pub mod library;
pub(crate) mod reverse_bridge;
pub(crate) mod state;
pub mod toast_bridge;

pub(crate) fn conflict_ui_ready() -> bool {
    state::CONFLICT_UI_READY.load(std::sync::atomic::Ordering::Acquire)
}

pub(crate) fn set_conflict_ui_ready(ready: bool) {
    state::CONFLICT_UI_READY.store(ready, std::sync::atomic::Ordering::Release);
    if let Some(queue) = crate::netpacket::cloud_rpc_queue() {
        queue.set_conflict_ui_ready(ready);
    }
}
