//! Steam internal callback registration and delivery.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::pin::Pin;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

use vapor_forge_hook_engine::detour::Detour;

use super::callback_dispatch::{
    self, AppMinutesPlayedDataNotice, CallbackEvent, APP_MINUTES_PLAYED_DATA_NOTICE,
};

const MAX_OBSERVED_USERS: usize = 16;
const EVENT_CAPACITY: usize = 256;
// Steam can publish one minutes notice per library entry in a single refresh.
// Entries are keyed by (account generation, AppID), so repeat notices only set
// the pending bit. A new account reuses stale-generation slots.
const APP_EVENT_CAPACITY: usize = 64 * 1024;

pub(crate) type RegisterInternalCallbackFn = unsafe extern "C" fn(*mut InternalCallback);

pub(crate) static mut REGISTER_INTERNAL_CALLBACK_DETOUR: Option<
    Detour<RegisterInternalCallbackFn>,
> = None;

static OBSERVED_USERS: [AtomicI32; MAX_OBSERVED_USERS] =
    [const { AtomicI32::new(0) }; MAX_OBSERVED_USERS];
static EVENT_HINT: AtomicUsize = AtomicUsize::new(0);
static EVENT_CURSOR: AtomicUsize = AtomicUsize::new(0);
static DROPPED_EVENTS: AtomicU32 = AtomicU32::new(0);
static EVENTS: [EventSlot; EVENT_CAPACITY] = [const { EventSlot::new() }; EVENT_CAPACITY];
static APP_EVENTS: CoalescedEvents<APP_EVENT_CAPACITY> = CoalescedEvents::new();
static HANDLERS: Mutex<Vec<Pin<Box<InternalCallback>>>> = Mutex::new(Vec::new());

#[repr(C)]
struct InternalCallbackVTable {
    run: unsafe extern "C" fn(*mut InternalCallback, *const c_void),
    validate: unsafe extern "C" fn(*mut InternalCallback, *mut c_void, *mut c_void),
}

static INTERNAL_CALLBACK_VTABLE: InternalCallbackVTable = InternalCallbackVTable {
    run: run_internal_callback,
    validate: validate_internal_callback,
};

#[repr(C)]
pub(crate) struct InternalCallback {
    vtable: *const InternalCallbackVTable,
    steam_user: i32,
    #[cfg(target_pointer_width = "64")]
    _user_padding: i32,
    manager: *mut c_void,
    callback: i32,
    #[cfg(target_pointer_width = "64")]
    _callback_padding: i32,
}

// SAFETY: the object is pinned before Steam sees it. Steam only writes
// `manager`; all other fields and the vtable live for the process lifetime.
unsafe impl Send for InternalCallback {}

impl InternalCallback {
    fn new(steam_user: i32, callback: i32) -> Self {
        Self {
            vtable: &INTERNAL_CALLBACK_VTABLE,
            steam_user,
            #[cfg(target_pointer_width = "64")]
            _user_padding: 0,
            manager: std::ptr::null_mut(),
            callback,
            #[cfg(target_pointer_width = "64")]
            _callback_padding: 0,
        }
    }
}

struct EventSlot {
    state: AtomicU8,
    event: UnsafeCell<MaybeUninit<CallbackEvent>>,
}

// SAFETY: a producer owns the payload while state is 1; the consumer owns it
// while state is 3. State transitions publish all payload bytes.
unsafe impl Sync for EventSlot {}

impl EventSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            event: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

struct CoalescedEventSlot {
    state: AtomicU8,
    pending: AtomicU8,
    event: UnsafeCell<MaybeUninit<CallbackEvent>>,
}

// SAFETY: state 1 initializes a slot, state 2 publishes it, and state 3 gives a
// producer or the consumer exclusive access while comparing or replacing it.
unsafe impl Sync for CoalescedEventSlot {}

impl CoalescedEventSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            pending: AtomicU8::new(0),
            event: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

struct CoalescedEvents<const N: usize> {
    slots: [CoalescedEventSlot; N],
    cursor: AtomicUsize,
    ready: AtomicU8,
    dropped: AtomicU32,
    merged: AtomicU32,
}

impl<const N: usize> CoalescedEvents<N> {
    const fn new() -> Self {
        Self {
            slots: [const { CoalescedEventSlot::new() }; N],
            cursor: AtomicUsize::new(0),
            ready: AtomicU8::new(0),
            dropped: AtomicU32::new(0),
            merged: AtomicU32::new(0),
        }
    }

    fn enqueue(&self, event: CallbackEvent) -> bool {
        let Some(notice) = event.decode::<AppMinutesPlayedDataNotice>() else {
            return false;
        };
        let start = event_hash(&event, notice.app_id) % N;
        'probe: for offset in 0..N {
            let slot = &self.slots[(start + offset) % N];
            loop {
                let mut state = slot.state.load(Ordering::Acquire);
                while state == 1 || state == 3 {
                    std::hint::spin_loop();
                    state = slot.state.load(Ordering::Acquire);
                }
                if state == 0 {
                    if slot
                        .state
                        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        continue;
                    }
                    // SAFETY: state 1 gives this producer exclusive initialization rights.
                    unsafe { (*slot.event.get()).write(event) };
                    slot.pending.store(1, Ordering::Relaxed);
                    slot.state.store(2, Ordering::Release);
                    self.ready.store(1, Ordering::Release);
                    return true;
                }
                if slot
                    .state
                    .compare_exchange(2, 3, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    continue;
                }
                // SAFETY: state 3 gives this producer exclusive access.
                let existing = unsafe { *(*slot.event.get()).as_ptr() };
                if existing == event {
                    let queued = slot
                        .pending
                        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok();
                    slot.state.store(2, Ordering::Release);
                    if queued {
                        self.ready.store(1, Ordering::Release);
                        return true;
                    }
                    self.merged.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                let stale_context = existing.identity_generation != event.identity_generation
                    || existing.steam_id64 != event.steam_id64
                    || existing.header.steam_user != event.header.steam_user;
                if stale_context {
                    // SAFETY: state 3 excludes every other reader and writer.
                    unsafe { (*slot.event.get()).write(event) };
                    slot.pending.store(1, Ordering::Relaxed);
                    slot.state.store(2, Ordering::Release);
                    self.ready.store(1, Ordering::Release);
                    return true;
                }
                slot.state.store(2, Ordering::Release);
                continue 'probe;
            }
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
        false
    }

    fn take_into(&self, events: &mut Vec<CallbackEvent>, limit: usize) {
        if events.len() >= limit || self.ready.swap(0, Ordering::AcqRel) == 0 {
            return;
        }
        let start = self.cursor.load(Ordering::Relaxed) % N;
        let mut next = start;
        let mut exhausted = true;
        for offset in 0..N {
            if events.len() >= limit {
                exhausted = false;
                break;
            }
            let index = (start + offset) % N;
            next = (index + 1) % N;
            let slot = &self.slots[index];
            let claimed = loop {
                let mut state = slot.state.load(Ordering::Acquire);
                while state == 1 || state == 3 {
                    std::hint::spin_loop();
                    state = slot.state.load(Ordering::Acquire);
                }
                if state != 2 {
                    break false;
                }
                if slot
                    .state
                    .compare_exchange(2, 3, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    break true;
                }
            };
            if !claimed {
                continue;
            }
            if slot.pending.swap(0, Ordering::AcqRel) != 0 {
                // SAFETY: state 3 gives the consumer exclusive access.
                events.push(unsafe { *(*slot.event.get()).as_ptr() });
            }
            slot.state.store(2, Ordering::Release);
        }
        self.cursor.store(next, Ordering::Relaxed);
        if !exhausted {
            self.ready.store(1, Ordering::Release);
        }
    }

    #[cfg(any(debug_assertions, test))]
    fn pending(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.pending.load(Ordering::Relaxed) != 0)
            .count()
    }

    #[cfg(any(debug_assertions, test))]
    fn used(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.state.load(Ordering::Relaxed) == 2)
            .count()
    }
}

fn event_hash(event: &CallbackEvent, app_id: u32) -> usize {
    let mut value = u64::from(app_id) | ((event.header.steam_user as u32 as u64) << 32);
    value ^= event.identity_generation.rotate_left(17);
    value ^= event.steam_id64.rotate_left(37);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    (value ^ (value >> 31)) as usize
}

/// Observe concrete Steam users while Steam registers its own handlers.
pub(crate) unsafe extern "C" fn hk_register_internal_callback(handler: *mut InternalCallback) {
    let observed = if handler.is_null() {
        0
    } else {
        // SAFETY: Steam passed its live internal callback object to this ABI.
        unsafe { (*handler).steam_user }
    };

    if let Some(original) = original_register() {
        // SAFETY: forwards the untouched handler to Steam's registration wrapper.
        unsafe { original(handler) };
    }

    if crate::capability::is_ready(crate::capability::Capability::CallbackEvents) && observed != 0 {
        observe_user(observed);
    }
}

/// Register vapor handlers for concrete users observed by the hook.
///
/// Called only by the worker. No handler collection lock is held while entering Steam.
pub(super) fn register_observed_handlers() {
    if !crate::capability::is_ready(crate::capability::Capability::CallbackEvents) {
        return;
    }
    let Some(original) = original_register() else {
        return;
    };
    let users = observed_users();
    for steam_user in users {
        for registration in callback_dispatch::REGISTRATIONS {
            let exists = handlers().iter().any(|handler| {
                handler.steam_user == steam_user && handler.callback == registration.id
            });
            if exists {
                continue;
            }

            let mut handler = Box::pin(InternalCallback::new(steam_user, registration.id));
            // SAFETY: only a stable raw address is derived; the pinned value is
            // not moved and remains owned by `HANDLERS` for process lifetime.
            let raw = unsafe { Pin::as_mut(&mut handler).get_unchecked_mut() as *mut _ };
            // SAFETY: handler is pinned and remains owned below for process life.
            unsafe { original(raw) };
            if handler.manager.is_null() {
                continue;
            }
            handlers().push(handler);
        }
    }
}

pub(super) fn take_events(limit: usize) -> Vec<CallbackEvent> {
    let mut events = Vec::with_capacity(limit);
    let start = EVENT_CURSOR.fetch_add(1, Ordering::Relaxed);
    for offset in 0..EVENT_CAPACITY {
        if events.len() >= limit {
            break;
        }
        let index = start.wrapping_add(offset) % EVENT_CAPACITY;
        let slot = &EVENTS[index];
        if slot
            .state
            .compare_exchange(2, 3, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        // SAFETY: state 3 gives this single consumer exclusive ownership.
        events.push(unsafe { (*slot.event.get()).assume_init_read() });
        slot.state.store(0, Ordering::Release);
    }
    APP_EVENTS.take_into(&mut events, limit);
    events
}

#[cfg(any(debug_assertions, test))]
pub(super) fn diagnostic_status() -> String {
    format!(
        "internal_users={} internal_handlers={} internal_pending={} internal_app_slots={} internal_merged={} internal_dropped={}",
        observed_users().len(),
        handlers().len(),
        EVENTS
            .iter()
            .filter(|slot| slot.state.load(Ordering::Relaxed) == 2)
            .count()
            + APP_EVENTS.pending(),
        APP_EVENTS.used(),
        APP_EVENTS.merged.load(Ordering::Relaxed),
        DROPPED_EVENTS
            .load(Ordering::Relaxed)
            .saturating_add(APP_EVENTS.dropped.load(Ordering::Relaxed)),
    )
}

pub(super) fn observe_user(steam_user: i32) {
    if steam_user == 0 {
        return;
    }
    for slot in &OBSERVED_USERS {
        let current = slot.load(Ordering::Acquire);
        if current == steam_user {
            return;
        }
        if current == 0
            && slot
                .compare_exchange(0, steam_user, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            super::callback_notify::notify();
            return;
        }
    }
}

fn observed_users() -> Vec<i32> {
    OBSERVED_USERS
        .iter()
        .map(|slot| slot.load(Ordering::Acquire))
        .filter(|user| *user != 0)
        .collect()
}

fn handlers() -> std::sync::MutexGuard<'static, Vec<Pin<Box<InternalCallback>>>> {
    HANDLERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn original_register() -> Option<RegisterInternalCallbackFn> {
    // SAFETY: installation writes the detour before enabling the hook.
    let detour = unsafe { &*std::ptr::addr_of!(REGISTER_INTERNAL_CALLBACK_DETOUR) }.as_ref()?;
    // SAFETY: the trampoline has the validated one-argument wrapper ABI.
    Some(unsafe {
        std::mem::transmute::<*const (), RegisterInternalCallbackFn>(
            detour.trampoline() as *const ()
        )
    })
}

unsafe extern "C" fn run_internal_callback(handler: *mut InternalCallback, payload: *const c_void) {
    if handler.is_null() {
        return;
    }
    // SAFETY: Steam invokes the vtable with the registered pinned object.
    let handler = unsafe { &*handler };
    let Some(registration) = callback_dispatch::registration(handler.callback) else {
        return;
    };
    let Some((identity_generation, steam_id64)) =
        super::steam_context::callback_identity(handler.steam_user)
    else {
        return;
    };
    // SAFETY: the registration fixes the payload length for this callback ID.
    let Some(event) = (unsafe {
        CallbackEvent::copy_from_raw(
            handler.steam_user,
            identity_generation,
            steam_id64,
            registration,
            payload,
        )
    }) else {
        return;
    };
    let queued = if event.header.callback == APP_MINUTES_PLAYED_DATA_NOTICE {
        APP_EVENTS.enqueue(event)
    } else {
        enqueue(event)
    };
    if queued {
        super::callback_notify::notify();
    }
}

unsafe extern "C" fn validate_internal_callback(
    _handler: *mut InternalCallback,
    _output: *mut c_void,
    _context: *mut c_void,
) {
}

fn enqueue(event: CallbackEvent) -> bool {
    let start = EVENT_HINT.fetch_add(1, Ordering::Relaxed);
    for offset in 0..EVENT_CAPACITY {
        let slot = &EVENTS[start.wrapping_add(offset) % EVENT_CAPACITY];
        if slot
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        // SAFETY: state 1 gives this producer exclusive ownership.
        unsafe { (*slot.event.get()).write(event) };
        slot.state.store(2, Ordering::Release);
        return true;
    }
    DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_event(app_id: u32, generation: u64) -> CallbackEvent {
        CallbackEvent::from_bytes(
            3,
            generation,
            76_561_198_000_000_001,
            APP_MINUTES_PLAYED_DATA_NOTICE,
            &app_id.to_le_bytes(),
        )
    }

    #[test]
    fn handler_layout_matches_steam_abi() {
        #[cfg(target_pointer_width = "64")]
        assert_eq!(std::mem::size_of::<InternalCallback>(), 0x20);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(std::mem::size_of::<InternalCallback>(), 0x10);
    }

    #[test]
    fn minutes_notices_coalesce_until_consumed() {
        let events = CoalescedEvents::<8>::new();
        let event = app_event(480, 7);

        assert!(events.enqueue(event));
        assert!(!events.enqueue(event));
        assert_eq!(events.pending(), 1);

        let mut drained = Vec::new();
        events.take_into(&mut drained, 8);
        assert_eq!(drained, vec![event]);
        assert_eq!(events.pending(), 0);

        assert!(events.enqueue(event));
        events.take_into(&mut drained, 8);
        assert_eq!(drained, vec![event, event]);
    }

    #[test]
    fn different_apps_in_one_generation_remain_distinct() {
        let events = CoalescedEvents::<8>::new();
        assert!(events.enqueue(app_event(480, 7)));
        assert!(events.enqueue(app_event(620, 7)));

        let mut drained = Vec::new();
        events.take_into(&mut drained, 8);
        assert_eq!(drained.len(), 2);
    }

    #[test]
    fn new_generation_reclaims_a_full_stale_table() {
        let events = CoalescedEvents::<1>::new();
        assert!(events.enqueue(app_event(480, 7)));
        assert!(events.enqueue(app_event(620, 8)));

        let mut drained = Vec::new();
        events.take_into(&mut drained, 1);
        assert_eq!(drained, vec![app_event(620, 8)]);
        assert_eq!(events.used(), 1);
        assert_eq!(events.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn burst_larger_than_the_generic_queue_drains_without_loss() {
        const BURST: usize = EVENT_CAPACITY + 17;
        let events = CoalescedEvents::<512>::new();
        for app_id in 1..=BURST as u32 {
            assert!(events.enqueue(app_event(app_id, 7)));
        }

        let mut drained = Vec::new();
        while drained.len() < BURST {
            let mut batch = Vec::new();
            events.take_into(&mut batch, 64);
            assert!(!batch.is_empty());
            drained.extend(batch);
        }
        drained.sort_by_key(|event| event.decode::<AppMinutesPlayedDataNotice>().unwrap().app_id);
        assert_eq!(drained.len(), BURST);
        assert_eq!(events.dropped.load(Ordering::Relaxed), 0);
        assert_eq!(events.pending(), 0);
    }
}
