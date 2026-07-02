use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

use tracing::info;

static STEAMCLIENT_BATCH_INSTALL_ONCE: Once = Once::new();
pub(super) static STEAMCLIENT_BATCH_FINISHED: AtomicBool = AtomicBool::new(false);

pub(super) fn install_hook_batch() {
    STEAMCLIENT_BATCH_INSTALL_ONCE.call_once(|| {
        info!("hook-install: steamclient batch started");
        super::do_install();
        STEAMCLIENT_BATCH_FINISHED.store(true, Ordering::Release);
        info!("hook-install: steamclient batch finished");
    });
}
