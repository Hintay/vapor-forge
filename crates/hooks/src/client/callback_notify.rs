//! Event-driven wakeup and API-call completion capture.

use core::ffi::c_void;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};

use vapor_forge_hook_engine::detour::Detour;

use super::callback_dispatch::{self, ApiCallResultEvent};

#[cfg(target_pointer_width = "32")]
pub(crate) type SetApiCallResultFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u32, i32, *const c_void, i32, i32);

#[cfg(target_pointer_width = "64")]
pub(crate) type SetApiCallResultFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u64, i32, *const c_void, i32, i32);

pub(crate) static mut SET_API_CALL_RESULT_DETOUR: Option<Detour<SetApiCallResultFn>> = None;

static WAKE_EPOCH: AtomicU32 = AtomicU32::new(0);
static HOOKS_READY: AtomicBool = AtomicBool::new(false);
static API_CALLS: Mutex<ApiCallState> = Mutex::new(ApiCallState::new());
#[cfg(any(debug_assertions, test))]
static API_RESULTS: AtomicU32 = AtomicU32::new(0);
#[cfg(any(debug_assertions, test))]
static REGISTERED_API_RESULTS: AtomicU32 = AtomicU32::new(0);
#[cfg(any(debug_assertions, test))]
static LAST_API_RESULT_CALLBACK: AtomicU32 = AtomicU32::new(0);

struct ApiCallState {
    session: Option<u64>,
    api_calls: Vec<(u64, i32)>,
    completed: VecDeque<ApiCallResultEvent>,
    issuing: Option<IssuingApiCall>,
}

struct IssuingApiCall {
    session: u64,
    callback: i32,
    candidates: Vec<ApiCallResultEvent>,
}

impl ApiCallState {
    const fn new() -> Self {
        Self {
            session: None,
            api_calls: Vec::new(),
            completed: VecDeque::new(),
            issuing: None,
        }
    }

    fn activate(&mut self, session: u64) {
        if self.session != Some(session) {
            self.api_calls.clear();
            self.completed.clear();
            self.issuing = None;
            self.session = Some(session);
        }
    }

    fn clear(&mut self, session: u64) {
        if self.session == Some(session) {
            self.api_calls.clear();
            self.completed.clear();
            self.issuing = None;
            self.session = None;
        }
    }

    fn begin_issue(&mut self, session: u64, callback: i32) -> bool {
        if self.session != Some(session)
            || self.issuing.is_some()
            || !callback_dispatch::is_api_result_registered(callback)
        {
            return false;
        }
        self.issuing = Some(IssuingApiCall {
            session,
            callback,
            candidates: Vec::new(),
        });
        true
    }

    fn finish_issue(&mut self, session: u64, api_call: u64, callback: i32) -> IssueOutcome {
        let Some(issuing) = self.issuing.take() else {
            return IssueOutcome::Rejected;
        };
        if self.session != Some(session)
            || issuing.session != session
            || issuing.callback != callback
            || api_call == 0
        {
            return IssueOutcome::Rejected;
        }
        if let Some(event) = issuing
            .candidates
            .into_iter()
            .find(|event| event.api_call == api_call && event.callback == callback)
        {
            self.completed.push_back(event);
            return IssueOutcome::Completed;
        }
        if self.register(session, api_call, callback) {
            IssueOutcome::Registered
        } else {
            IssueOutcome::Rejected
        }
    }

    fn cancel_issue(&mut self, session: u64, callback: i32) {
        if self
            .issuing
            .as_ref()
            .is_some_and(|issuing| issuing.session == session && issuing.callback == callback)
        {
            self.issuing = None;
        }
    }

    fn register(&mut self, session: u64, api_call: u64, callback: i32) -> bool {
        if self.session != Some(session)
            || api_call == 0
            || !callback_dispatch::is_api_result_registered(callback)
            || self
                .api_calls
                .iter()
                .any(|(registered, _)| *registered == api_call)
        {
            return false;
        }
        self.api_calls.push((api_call, callback));
        true
    }

    fn registered_session(&self, api_call: u64, callback: i32) -> Option<u64> {
        let session = self.session?;
        self.api_calls
            .iter()
            .any(|&(registered, expected)| registered == api_call && expected == callback)
            .then_some(session)
    }

    fn accepted_session(&self, api_call: u64, callback: i32) -> Option<u64> {
        self.registered_session(api_call, callback).or_else(|| {
            self.issuing
                .as_ref()
                .filter(|issuing| issuing.callback == callback)
                .map(|issuing| issuing.session)
        })
    }

    fn publish(&mut self, session: u64, event: ApiCallResultEvent) -> bool {
        if self.session != Some(session) {
            return false;
        }
        if let Some(index) = self.api_calls.iter().position(|&(api_call, callback)| {
            api_call == event.api_call && callback == event.callback
        }) {
            self.api_calls.swap_remove(index);
            self.completed.push_back(event);
            return true;
        }
        let Some(issuing) = self
            .issuing
            .as_mut()
            .filter(|issuing| issuing.session == session && issuing.callback == event.callback)
        else {
            return false;
        };
        if !issuing
            .candidates
            .iter()
            .any(|candidate| candidate.api_call == event.api_call)
        {
            issuing.candidates.push(event);
        }
        false
    }

    fn take(&mut self, limit: usize) -> Vec<ApiCallResultEvent> {
        let count = self.completed.len().min(limit);
        self.completed.drain(..count).collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IssueOutcome {
    Registered,
    Completed,
    Rejected,
}

struct PreparedApiResult {
    session: u64,
    event: ApiCallResultEvent,
}

pub(crate) fn set_hooks_ready(ready: bool) {
    if HOOKS_READY.swap(ready, Ordering::AcqRel) != ready {
        notify();
    }
}

pub(super) fn hooks_ready() -> bool {
    HOOKS_READY.load(Ordering::Acquire)
}

pub(super) fn activate_session(session: u64) {
    api_calls().activate(session);
}

pub(super) fn clear_session(session: u64) {
    api_calls().clear(session);
}

pub(super) fn clear_account() {
    let mut state = api_calls();
    state.api_calls.clear();
    state.completed.clear();
    state.issuing = None;
    state.session = None;
    notify();
}

pub(super) fn begin_api_call(session: u64, callback: i32) -> bool {
    api_calls().begin_issue(session, callback)
}

pub(super) fn finish_api_call(session: u64, api_call: u64, callback: i32) -> bool {
    match api_calls().finish_issue(session, api_call, callback) {
        IssueOutcome::Registered => true,
        IssueOutcome::Completed => {
            #[cfg(any(debug_assertions, test))]
            REGISTERED_API_RESULTS.fetch_add(1, Ordering::Relaxed);
            notify();
            true
        }
        IssueOutcome::Rejected => false,
    }
}

pub(super) fn cancel_api_call(session: u64, callback: i32) {
    api_calls().cancel_issue(session, callback);
}

pub(super) fn take_api_results(limit: usize) -> Vec<ApiCallResultEvent> {
    api_calls().take(limit)
}

#[cfg(any(debug_assertions, test))]
pub(super) fn diagnostic_status() -> String {
    let state = api_calls();
    format!(
        "api_results={} registered_api_results={} last_api_result_id={} registered_calls={} api_pending={} issuing={} session={}",
        API_RESULTS.load(Ordering::Relaxed),
        REGISTERED_API_RESULTS.load(Ordering::Relaxed),
        LAST_API_RESULT_CALLBACK.load(Ordering::Relaxed),
        state.api_calls.len(),
        state.completed.len(),
        state.issuing.is_some(),
        state.session.unwrap_or_default(),
    )
}

#[inline]
pub(super) fn epoch() -> u32 {
    WAKE_EPOCH.load(Ordering::Acquire)
}

#[inline]
pub(super) fn notify() {
    WAKE_EPOCH.fetch_add(1, Ordering::Release);
    futex_wake();
}

pub(super) fn wait(observed: u32) {
    if epoch() != observed {
        return;
    }
    // SAFETY: Linux futex reads this process-lifetime aligned AtomicU32.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            std::ptr::addr_of!(WAKE_EPOCH).cast::<u32>(),
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            observed,
            std::ptr::null::<libc::timespec>(),
        );
    }
}

fn api_calls() -> MutexGuard<'static, ApiCallState> {
    API_CALLS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[inline]
fn futex_wake() {
    // SAFETY: waking a process-lifetime futex with no waiter is allowed.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            std::ptr::addr_of!(WAKE_EPOCH).cast::<u32>(),
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            1,
        );
    }
}

unsafe fn prepare_registered_api_result(
    api_call: u64,
    callback: i32,
    payload: *const c_void,
    payload_size: i32,
) -> Option<PreparedApiResult> {
    #[cfg(any(debug_assertions, test))]
    {
        API_RESULTS.fetch_add(1, Ordering::Relaxed);
        LAST_API_RESULT_CALLBACK.store(callback as u32, Ordering::Relaxed);
    }
    if api_call == 0 || !callback_dispatch::is_api_result_registered(callback) {
        return None;
    }
    let session = api_calls().accepted_session(api_call, callback)?;
    // SAFETY: Steam owns the live result payload for this hook frame.
    let event =
        unsafe { ApiCallResultEvent::copy_from_raw(api_call, callback, payload_size, payload) };
    Some(PreparedApiResult { session, event })
}

fn publish_registered_api_result(prepared: Option<PreparedApiResult>) {
    let published =
        prepared.is_some_and(|prepared| api_calls().publish(prepared.session, prepared.event));
    if published {
        #[cfg(any(debug_assertions, test))]
        REGISTERED_API_RESULTS.fetch_add(1, Ordering::Relaxed);
        notify();
    }
}

#[cfg(target_pointer_width = "32")]
pub(crate) unsafe extern "C" fn hk_set_api_call_result(
    engine: *mut c_void,
    client_context: *mut c_void,
    api_call_low: u32,
    api_call_high: u32,
    target_pipe: i32,
    payload: *const c_void,
    payload_size: i32,
    callback: i32,
) {
    let api_call = u64::from(api_call_low) | (u64::from(api_call_high) << 32);
    // SAFETY: Steam owns the result payload during this hook call.
    let prepared =
        unsafe { prepare_registered_api_result(api_call, callback, payload, payload_size) };
    let Some(original) = original_set_api_call_result() else {
        return;
    };
    // SAFETY: forwards the untouched arguments before publishing readiness.
    unsafe {
        original(
            engine,
            client_context,
            api_call_low,
            api_call_high,
            target_pipe,
            payload,
            payload_size,
            callback,
        )
    };
    publish_registered_api_result(prepared);
}

#[cfg(target_pointer_width = "64")]
pub(crate) unsafe extern "C" fn hk_set_api_call_result(
    engine: *mut c_void,
    client_context: *mut c_void,
    api_call: u64,
    target_pipe: i32,
    payload: *const c_void,
    payload_size: i32,
    callback: i32,
) {
    // SAFETY: Steam owns the result payload during this hook call.
    let prepared =
        unsafe { prepare_registered_api_result(api_call, callback, payload, payload_size) };
    let Some(original) = original_set_api_call_result() else {
        return;
    };
    // SAFETY: forwards the untouched arguments before publishing readiness.
    unsafe {
        original(
            engine,
            client_context,
            api_call,
            target_pipe,
            payload,
            payload_size,
            callback,
        )
    };
    publish_registered_api_result(prepared);
}

fn original_set_api_call_result() -> Option<SetApiCallResultFn> {
    // SAFETY: installation writes this slot before enabling the hook.
    let detour = unsafe { &*std::ptr::addr_of!(SET_API_CALL_RESULT_DETOUR) }.as_ref()?;
    // SAFETY: the trampoline has the architecture-specific validated ABI.
    Some(unsafe {
        std::mem::transmute::<*const (), SetApiCallResultFn>(detour.trampoline() as *const ())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_session_owns_registered_handles() {
        let mut state = ApiCallState::new();
        state.activate(7);
        assert!(state.register(7, 14, callback_dispatch::USER_STATS_RECEIVED));
        assert!(!state.register(8, 15, callback_dispatch::USER_STATS_RECEIVED));
        assert_eq!(
            state.registered_session(14, callback_dispatch::USER_STATS_RECEIVED),
            Some(7)
        );
        state.clear(7);
        assert_eq!(
            state.registered_session(14, callback_dispatch::USER_STATS_RECEIVED),
            None
        );
    }

    #[test]
    fn completion_during_request_issue_is_matched_after_handle_return() {
        let mut state = ApiCallState::new();
        state.activate(7);
        assert!(state.begin_issue(7, callback_dispatch::USER_STATS_RECEIVED));
        let event = ApiCallResultEvent::new(
            14,
            callback_dispatch::USER_STATS_RECEIVED,
            20,
            vec![0; 20].into_boxed_slice(),
        );
        assert_eq!(
            state.accepted_session(14, callback_dispatch::USER_STATS_RECEIVED),
            Some(7)
        );
        assert!(!state.publish(7, event));
        assert_eq!(
            state.finish_issue(7, 14, callback_dispatch::USER_STATS_RECEIVED),
            IssueOutcome::Completed
        );
        assert_eq!(state.take(1)[0].api_call, 14);
        assert!(state.api_calls.is_empty());
    }
}
