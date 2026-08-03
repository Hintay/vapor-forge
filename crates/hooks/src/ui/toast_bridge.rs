use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(super) mod html_window;

static PUMP_REQUESTED: AtomicBool = AtomicBool::new(false);
static BRIDGE_PRIMED: AtomicBool = AtomicBool::new(false);
static FIRST_BOOTSTRAP_NS: AtomicU64 = AtomicU64::new(0);
static LAST_BOOTSTRAP_NS: AtomicU64 = AtomicU64::new(0);
static LAST_CONFLICT_REVISION: AtomicU64 = AtomicU64::new(0);

const EARLY_BOOTSTRAP_WINDOW_NS: u64 = 60_000_000_000;
const EARLY_BOOTSTRAP_INTERVAL_NS: u64 = 250_000_000;

pub fn bootstrap() {
    if BRIDGE_PRIMED.load(Ordering::Acquire) {
        return;
    }
    let now = monotonic_ns();
    if now == 0 {
        return;
    }

    let first = FIRST_BOOTSTRAP_NS.load(Ordering::Acquire);
    if first == 0 {
        FIRST_BOOTSTRAP_NS.store(now, Ordering::Release);
    } else if now.saturating_sub(first) > EARLY_BOOTSTRAP_WINDOW_NS {
        return;
    }

    let last = LAST_BOOTSTRAP_NS.load(Ordering::Acquire);
    if now.saturating_sub(last) < EARLY_BOOTSTRAP_INTERVAL_NS {
        return;
    }
    LAST_BOOTSTRAP_NS.store(now, Ordering::Release);

    let _ = html_window::execute_javascript(vapor_forge_features::toast::bridge_script());
}

pub fn pump() {
    let requested = PUMP_REQUESTED.swap(false, Ordering::AcqRel);
    if crate::ui::reverse_bridge::take_window_context_changed() {
        if let Some(queue) = crate::netpacket::cloud_rpc_queue() {
            queue.invalidate_conflict_ui_context();
        }
    }
    let conflict_revision = crate::netpacket::cloud_rpc_queue().map_or(
        0,
        vapor_forge_cloud_rpc::CloudRpcQueue::conflict_ui_revision,
    );
    let conflict_changed = conflict_revision != LAST_CONFLICT_REVISION.load(Ordering::Acquire);
    if !requested && !conflict_changed && !vapor_forge_features::toast::has_pending_work() {
        return;
    }

    let bridge_injected =
        html_window::execute_javascript(vapor_forge_features::toast::bridge_script());
    if !bridge_injected {
        return;
    }

    // The first successful pump only injects the bridge. The next pump may send queued toasts.
    if !BRIDGE_PRIMED.load(Ordering::Acquire) {
        BRIDGE_PRIMED.store(true, Ordering::Release);
        return;
    }

    pump_cloud_conflicts(conflict_revision);

    let toasts = vapor_forge_features::toast::take_pending();

    for (idx, toast) in toasts.iter().enumerate() {
        let script = vapor_forge_features::toast::toast_script(toast);
        if !html_window::execute_javascript(&script) {
            vapor_forge_features::toast::restore_pending(&toasts[idx..]);
            if html_window::bootstrap_scan_pending() {
                return;
            }
            return;
        }
    }

    vapor_forge_features::toast::mark_idle_if_empty();
}

fn pump_cloud_conflicts(revision: u64) {
    let Some(queue) = crate::netpacket::cloud_rpc_queue() else {
        LAST_CONFLICT_REVISION.store(revision, Ordering::Release);
        return;
    };
    let windows = crate::ui::reverse_bridge::registered_windows();
    if windows.is_empty() {
        LAST_CONFLICT_REVISION.store(revision, Ordering::Release);
        return;
    }

    for callback in crate::ui::reverse_bridge::take_callbacks() {
        let Some((window, _)) = windows
            .iter()
            .find(|(_, generation)| *generation == callback.window_generation)
        else {
            continue;
        };
        let context = conflict_context(callback.window_generation);
        let result = queue.submit_conflict_choice(callback.as_str(), context);
        tracing::info!(
            window_generation = callback.window_generation,
            ?result,
            "steamui: cloud conflict choice received"
        );
        if result != vapor_forge_cloud_rpc::ConflictSubmitResult::Accepted {
            let ack = vapor_forge_cloud_rpc::ConflictUiAck {
                token: callback.as_str().to_owned(),
                app_id: 0,
                accepted: false,
                error: "stale_choice".into(),
                resume_launch: false,
                cancel_launch: false,
            };
            let _ = execute_conflict_update(*window, &[], &[ack]);
        }
    }

    let mut delivered = true;
    for (window, generation) in windows {
        let context = conflict_context(generation);
        let dialogs = queue.conflict_dialogs(context);
        let acks = queue.conflict_acks(context);
        if dialogs.is_empty() && acks.is_empty() {
            continue;
        }
        if execute_conflict_update(window, &dialogs, &acks) {
            let tokens = acks.iter().map(|ack| ack.token.clone()).collect::<Vec<_>>();
            queue.acknowledge_conflict_acks(context, &tokens);
        } else {
            delivered = false;
            queue.retry_conflict_ui_context(context);
        }
    }
    if delivered {
        LAST_CONFLICT_REVISION.store(revision, Ordering::Release);
    } else {
        PUMP_REQUESTED.store(true, Ordering::Release);
    }
}

fn conflict_context(window_generation: u64) -> vapor_forge_cloud_rpc::ConflictUiContext {
    let config = crate::client::install::config();
    vapor_forge_cloud_rpc::ConflictUiContext {
        steam_id64: vapor_forge_features::identity::steam_id(),
        identity_generation: vapor_forge_features::identity::generation(),
        connection_generation: crate::client::network::injection_generation(),
        window_generation,
        cloud_scope: vapor_forge_cloud_rpc::conflict_ui_scope(&config),
    }
}

fn execute_conflict_update(
    window: usize,
    dialogs: &[vapor_forge_cloud_rpc::ConflictDialog],
    acks: &[vapor_forge_cloud_rpc::ConflictUiAck],
) -> bool {
    let Ok(dialogs) = serde_json::to_string(dialogs) else {
        return false;
    };
    let Ok(acks) = serde_json::to_string(acks) else {
        return false;
    };
    let script = format!(
        "try {{ var b=window.VaporForgeUIBridge||window.VaporForgeToastBridge; if(b){{({dialogs}).forEach(function(v){{b.showCloudConflict(v);}});({acks}).forEach(function(v){{b.ackCloudConflict(v);}});}} }} catch(e) {{ console.log('[VaporForgeUI] conflict update failed: '+e); }}"
    );
    html_window::execute_javascript_on(window, &script)
}

#[cfg(any(target_pointer_width = "32", debug_assertions, test))]
pub fn request_pump() {
    PUMP_REQUESTED.store(true, Ordering::Release);
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes to the provided timespec pointer.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}
