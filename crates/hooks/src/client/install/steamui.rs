use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

use tracing::{info, warn};

static STEAMUI_BATCH_INSTALL_ONCE: Once = Once::new();
pub(super) static STEAMUI_BATCH_FINISHED: AtomicBool = AtomicBool::new(false);

/// Called from la_activity after steamui.so reaches a consistent loader state.
/// Safe to call multiple times; installs only once.
pub(super) fn install_hook_batch() {
    STEAMUI_BATCH_INSTALL_ONCE.call_once(|| {
        info!("hook-install: steamui batch started");
        let Some(ui_code) = crate::ui::install::get_steamui_code() else {
            warn!(
                "hook-install: steamui.so executable mapping unavailable, skipping steamui hooks"
            );
            STEAMUI_BATCH_FINISHED.store(true, Ordering::Release);
            info!(installed = false, "hook-install: steamui batch finished");
            return;
        };
        let registry = super::load_pattern_registry();
        let installed = crate::ui::install::install(&ui_code, &registry);
        STEAMUI_BATCH_FINISHED.store(true, Ordering::Release);
        info!(installed, "hook-install: steamui batch finished");
    });
}
