use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod html_window;

static PUMP_REQUESTED: AtomicBool = AtomicBool::new(false);
static BRIDGE_PRIMED: AtomicBool = AtomicBool::new(false);
static FIRST_BOOTSTRAP_NS: AtomicU64 = AtomicU64::new(0);
static LAST_BOOTSTRAP_NS: AtomicU64 = AtomicU64::new(0);

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
    if !requested && !vapor_forge_features::toast::has_pending_work() {
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

#[cfg(debug_assertions)]
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
