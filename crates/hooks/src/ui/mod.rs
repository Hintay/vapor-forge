pub mod install;
pub mod library;
pub(crate) mod reverse_bridge;
pub(crate) mod state;
pub mod toast_bridge;

pub(crate) fn conflict_ui_ready() -> bool {
    state::CONFLICT_UI_READY.load(std::sync::atomic::Ordering::Acquire)
}
