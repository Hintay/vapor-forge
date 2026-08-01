#![forbid(unsafe_code)]

//! Wake-up signal shared by the backend downlink workers.
//!
//! A worker whose backend has no event stream parks until the runtime context
//! — account, device or credential — changes, rather than polling. The revision
//! counter is what makes that race-free: the worker reads it before starting a
//! stream and waits on *that* value afterwards, so a change observed while the
//! stream was running is never missed.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct ContextChangeSignal {
    revision: Mutex<u64>,
    changed: Condvar,
}

impl ContextChangeSignal {
    /// Read the current revision before doing work that the next change should
    /// interrupt.
    pub(crate) fn revision(&self) -> u64 {
        *self
            .revision
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn notify(&self) {
        let mut revision = self
            .revision
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *revision = revision.wrapping_add(1);
        self.changed.notify_all();
    }

    /// Park until the revision moves past `previous`. Returns immediately when
    /// a change already landed since `previous` was read.
    pub(crate) fn wait_after(&self, previous: u64) {
        let mut revision = self
            .revision
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *revision == previous {
            revision = self
                .changed
                .wait(revision)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    /// Wait for a context change, or until a transport retry delay expires.
    pub(crate) fn wait_timeout_after(&self, previous: u64, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut revision = self
            .revision
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *revision == previous {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let waited = self
                .changed
                .wait_timeout(revision, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            revision = waited.0;
            if waited.1.timed_out() {
                return *revision != previous;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_change_observed_before_waiting_does_not_park() {
        let signal = ContextChangeSignal::default();
        let before = signal.revision();
        signal.notify();
        // Would deadlock if `wait_after` ignored changes that already landed.
        signal.wait_after(before);
        assert_ne!(signal.revision(), before);
    }

    #[test]
    fn waiting_wakes_on_the_next_change() {
        let signal = Arc::new(ContextChangeSignal::default());
        let before = signal.revision();
        let waiter = {
            let signal = Arc::clone(&signal);
            std::thread::spawn(move || signal.wait_after(before))
        };
        while signal.revision() == before {
            signal.notify();
            std::thread::yield_now();
        }
        waiter.join().unwrap();
    }
}
