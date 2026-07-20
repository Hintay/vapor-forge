#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use tracing::{debug, warn};

use super::steam_session::{spawn_user_stats_worker, SteamUserStatsSession};

const MAX_PENDING_SNAPSHOTS: usize = 32;
const SNAPSHOT_RETRY_LIMIT: u8 = 3;
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const SNAPSHOT_RETRY_INTERVAL: Duration = Duration::from_secs(1);

static WORKER: OnceLock<Mutex<Option<StatsWorker>>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct AchievementSnapshot {
    pub app_id: u32,
    pub achievements: Vec<AchievementState>,
}

#[derive(Debug)]
pub(crate) struct AchievementState {
    pub key: String,
    pub unlocked: bool,
    pub unlock_time: u32,
}

pub(crate) fn queue_snapshot(app_id: u32) {
    if app_id == 0 {
        return;
    }
    if let Some(worker) = worker() {
        worker.queue(app_id);
    }
}

pub(crate) fn ensure_worker_started() {
    let _ = worker();
}

fn worker() -> Option<StatsWorker> {
    let slot = WORKER.get_or_init(|| Mutex::new(None));
    let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = StatsWorker::start();
    }
    guard.clone()
}

#[derive(Clone)]
struct StatsWorker {
    shared: Arc<WorkerShared>,
}

impl StatsWorker {
    fn start() -> Option<Self> {
        let shared = Arc::new(WorkerShared::default());
        if !spawn_user_stats_worker(Arc::clone(&shared)) {
            warn!("failed to start user-stats SteamThreadTools worker");
            return None;
        }
        Some(Self { shared })
    }

    fn queue(&self, app_id: u32) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.tracked.contains(&app_id) {
            state.rerun.insert(app_id);
            return;
        }
        if state.pending.len() >= MAX_PENDING_SNAPSHOTS {
            warn!(app_id, "user-stats snapshot queue is full");
            return;
        }
        state.tracked.insert(app_id);
        state.retry_count.remove(&app_id);
        state.pending.push_back(app_id);
        self.shared.wake.notify_one();
    }
}

#[derive(Default)]
pub(super) struct WorkerShared {
    state: Mutex<WorkerState>,
    wake: Condvar,
}

#[derive(Default)]
struct WorkerState {
    pending: VecDeque<u32>,
    tracked: HashSet<u32>,
    rerun: HashSet<u32>,
    retry_count: HashMap<u32, u8>,
}

pub(super) fn run_worker(shared: &WorkerShared) {
    loop {
        match SteamUserStatsSession::connect() {
            Ok(session) => {
                drop(session);
                break;
            }
            Err(error) => {
                warn!(error, "Steam identity session connection failed");
                wait_for_signal(shared, CONNECT_RETRY_INTERVAL);
            }
        }
    }

    loop {
        let app_id = wait_for_snapshot(shared);
        let established =
            match SteamUserStatsSession::connect().and_then(|session| session.snapshot(app_id)) {
                Ok(snapshot) => super::achievement::observe_local_snapshot(snapshot),
                Err(error) => {
                    warn!(app_id, error, "user-stats snapshot failed");
                    false
                }
            };
        let retry_scheduled = finish_snapshot(shared, app_id, established);
        if !established {
            debug!(
                app_id,
                retry_scheduled, "user-stats snapshot did not establish a baseline"
            );
        }
        if retry_scheduled {
            wait_for_signal(shared, SNAPSHOT_RETRY_INTERVAL);
        }
    }
}

fn finish_snapshot(shared: &WorkerShared, app_id: u32, established: bool) -> bool {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if established {
        state.retry_count.remove(&app_id);
        if state.rerun.remove(&app_id) {
            state.pending.push_back(app_id);
            shared.wake.notify_one();
        } else {
            state.tracked.remove(&app_id);
        }
        return false;
    }

    if state.rerun.remove(&app_id) {
        state.retry_count.insert(app_id, 0);
        state.pending.push_back(app_id);
        shared.wake.notify_one();
        return true;
    }

    let retries = state.retry_count.entry(app_id).or_default();
    if *retries < SNAPSHOT_RETRY_LIMIT {
        *retries += 1;
        state.pending.push_back(app_id);
        shared.wake.notify_one();
        true
    } else {
        state.retry_count.remove(&app_id);
        state.tracked.remove(&app_id);
        false
    }
}

fn wait_for_signal(shared: &WorkerShared, timeout: Duration) {
    let state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    drop(
        shared
            .wake
            .wait_timeout(state, timeout)
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
}

fn wait_for_snapshot(shared: &WorkerShared) -> u32 {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    while state.pending.is_empty() {
        state = shared
            .wake
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    state
        .pending
        .pop_front()
        .expect("pending snapshot queue is non-empty")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_snapshot_is_retried_with_a_bound() {
        let shared = WorkerShared::default();
        {
            let mut state = shared.state.lock().unwrap();
            state.tracked.insert(480);
        }

        for expected in 1..=SNAPSHOT_RETRY_LIMIT {
            assert!(finish_snapshot(&shared, 480, false));
            let mut state = shared.state.lock().unwrap();
            assert_eq!(state.retry_count.get(&480), Some(&expected));
            assert_eq!(state.pending.pop_front(), Some(480));
        }
        assert!(!finish_snapshot(&shared, 480, false));
        let state = shared.state.lock().unwrap();
        assert!(!state.tracked.contains(&480));
        assert!(!state.retry_count.contains_key(&480));
    }
}
