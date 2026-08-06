use core::ffi::{c_char, c_void};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use once_cell::sync::Lazy;
use tracing::{info, warn};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::detour_or_return;
use vapor_forge_hook_engine::plan::{validate_hook_target, AddressRange, HookTargetInput};

use crate::hook_report::HookResult;
use crate::pattern_resolver::CodeRegion;

const RESOLVE_METHOD: &[u8] = b"Apps.VaporForgeResolveCloudConflict\0";
const CONFIRM_METHOD: &[u8] = b"Apps.VaporForgeConfirmCloudConflict\0";
const RETRY_METHOD: &[u8] = b"Apps.VaporForgeRetryCloudConflict\0";
const READY_METHOD: &[u8] = b"Apps.VaporForgeConfirmUIBridge\0";
const READY_SIGNAL: &[u8] = b"cloud-conflict:3";
const URL_METHOD: &[u8] = b"URL.ExecuteSteamURL";
const CONTINUE_METHOD: &[u8] = b"Apps.ContinueGameAction";
const TOKEN_LENGTH: usize = 64;

static NEXT_WINDOW_GENERATION: AtomicU64 = AtomicU64::new(1);
static STRING_HANDLER_VPTR: AtomicUsize = AtomicUsize::new(0);
static WINDOWS: Lazy<Mutex<HashMap<usize, WindowRegistration>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CALLBACKS: Mutex<VecDeque<CallbackToken>> = Mutex::new(VecDeque::new());

#[derive(Clone, Copy)]
struct WindowRegistration {
    generation: u64,
    reverse_registered: bool,
    bootstrap_dispatched: bool,
    bridge_confirmed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CallbackKind {
    Choice,
    Receipt,
    Retry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CallbackToken {
    bytes: [u8; TOKEN_LENGTH],
    pub(super) window_generation: u64,
    pub(super) kind: CallbackKind,
}

impl CallbackToken {
    pub(super) fn as_str(&self) -> &str {
        // SAFETY: the callback accepts only ASCII hexadecimal bytes.
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
    }
}

type RegisterJsMethodFn = unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, i32);
type DestructorFn = unsafe extern "C" fn(*mut c_void);
type StringCallbackFn = unsafe extern "C" fn(*mut c_void, *const c_char);

static mut REGISTER_JS_METHOD_DETOUR: Option<Detour<RegisterJsMethodFn>> = None;
static mut DESTRUCTOR_DETOUR: Option<Detour<DestructorFn>> = None;

#[repr(C)]
struct StringBinding {
    vptr: usize,
    context: *mut c_void,
    function: StringCallbackFn,
    adjustment: isize,
}

const _: [(); std::mem::size_of::<usize>() * 4] = [(); std::mem::size_of::<StringBinding>()];

unsafe extern "C" fn hook(
    window: *mut c_void,
    name: *const c_char,
    binding: *mut c_void,
    kind: i32,
) {
    let original = detour_or_return!("CHTMLWindow::RegisterJSMethod", REGISTER_JS_METHOD_DETOUR);
    let is_string_handler = !binding.is_null() && kind == 1 && c_string_eq(name, URL_METHOD);
    let is_window_marker = kind == 1 && c_string_eq(name, CONTINUE_METHOD);
    let string_handler_vptr = if is_string_handler {
        // SAFETY: every JS method binding begins with its vtable pointer.
        unsafe { binding.cast::<usize>().read_unaligned() }
    } else {
        0
    };
    // SAFETY: Steam supplied the arguments to the hooked method.
    unsafe { original(window, name, binding, kind) };
    if !crate::capability::is_ready(crate::capability::Capability::ConflictUiBridge)
        || window.is_null()
        || binding.is_null()
        || kind != 1
    {
        return;
    }

    if is_string_handler {
        if string_handler_vptr != 0 {
            STRING_HANDLER_VPTR.store(string_handler_vptr, Ordering::Release);
            register_waiting_windows(original);
        }
        return;
    }

    if is_window_marker {
        capture_window(window as usize);
        register_window(original, window as usize);
    }
}

unsafe extern "C" fn destructor_hook(window: *mut c_void) {
    let original = detour_or_return!("CHTMLWindow::~CHTMLWindow", DESTRUCTOR_DETOUR);
    if crate::capability::is_ready(crate::capability::Capability::ConflictUiBridge)
        && !window.is_null()
    {
        retire_window(window as usize);
    }
    // SAFETY: Steam supplied the object to the hooked non-deleting destructor.
    unsafe { original(window) };
}

fn capture_window(window: usize) -> u64 {
    let generation = NEXT_WINDOW_GENERATION.fetch_add(1, Ordering::AcqRel);
    WINDOWS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(
            window,
            WindowRegistration {
                generation,
                reverse_registered: false,
                bootstrap_dispatched: false,
                bridge_confirmed: false,
            },
        );
    publish_window_change();
    update_conflict_ui_ready();
    generation
}

fn publish_window_change() {
    super::toast_bridge::request_pump();
}

fn register_waiting_windows(original: RegisterJsMethodFn) {
    let windows = WINDOWS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .filter_map(|(window, state)| (!state.reverse_registered).then_some(*window))
        .collect::<Vec<_>>();
    for window in windows {
        register_window(original, window);
    }
}

fn register_window(original: RegisterJsMethodFn, window: usize) {
    let vptr = STRING_HANDLER_VPTR.load(Ordering::Acquire);
    if vptr == 0 {
        return;
    }
    let generation = {
        let mut windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
        let Some(state) = windows.get_mut(&window) else {
            return;
        };
        if state.reverse_registered {
            return;
        }
        state.generation
    };
    let methods: [(&[u8], StringCallbackFn); 4] = [
        (RESOLVE_METHOD, receive_choice),
        (CONFIRM_METHOD, receive_receipt),
        (RETRY_METHOD, receive_retry),
        (READY_METHOD, receive_ready),
    ];
    let mut bindings: Vec<*mut StringBinding> = Vec::with_capacity(methods.len());
    for _ in &methods {
        // SAFETY: Steam's handler deleting destructor uses the process allocator.
        let binding =
            unsafe { libc::malloc(std::mem::size_of::<StringBinding>()) }.cast::<StringBinding>();
        if binding.is_null() {
            for allocated in bindings {
                // SAFETY: Steam has not received these allocations yet.
                unsafe { libc::free(allocated.cast()) };
            }
            return;
        }
        bindings.push(binding);
    }
    for ((name, function), binding) in methods.into_iter().zip(bindings) {
        // SAFETY: malloc returned writable storage with the requested size.
        unsafe {
            binding.write(StringBinding {
                vptr,
                context: generation as usize as *mut c_void,
                function,
                adjustment: 0,
            });
            original(
                window as *mut c_void,
                name.as_ptr().cast(),
                binding.cast(),
                1,
            );
        }
    }
    let registered = {
        let mut windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
        windows.get_mut(&window).is_some_and(|state| {
            if state.generation != generation {
                return false;
            }
            state.reverse_registered = true;
            state.bootstrap_dispatched = false;
            state.bridge_confirmed = false;
            true
        })
    };
    if registered {
        publish_window_change();
        update_conflict_ui_ready();
        info!(
            window = format_args!("{window:#x}"),
            generation, "steamui: reverse bridge registered"
        );
    }
}

unsafe extern "C" fn receive_choice(context: *mut c_void, token: *const c_char) {
    // SAFETY: Steam supplies the registered binding context and one string argument.
    unsafe { receive_token(context, token, CallbackKind::Choice) };
}

unsafe extern "C" fn receive_receipt(context: *mut c_void, token: *const c_char) {
    // SAFETY: Steam supplies the registered binding context and one string argument.
    unsafe { receive_token(context, token, CallbackKind::Receipt) };
}

unsafe extern "C" fn receive_retry(context: *mut c_void, token: *const c_char) {
    // SAFETY: Steam supplies the registered binding context and one string argument.
    unsafe { receive_token(context, token, CallbackKind::Retry) };
}

unsafe extern "C" fn receive_ready(context: *mut c_void, signal: *const c_char) {
    let window_generation = context as usize as u64;
    if window_generation == 0 || !c_string_eq(signal, READY_SIGNAL) {
        return;
    }
    confirm_bridge_ready(window_generation);
}

unsafe fn receive_token(context: *mut c_void, token: *const c_char, kind: CallbackKind) {
    let window_generation = context as usize as u64;
    if window_generation == 0 || token.is_null() || !window_generation_is_ready(window_generation) {
        return;
    }
    let mut bytes = [0u8; TOKEN_LENGTH];
    for (index, byte) in bytes.iter_mut().enumerate() {
        // SAFETY: Steam's one-string adaptor supplies a readable NUL-terminated string.
        let value = unsafe { token.cast::<u8>().add(index).read() };
        if !value.is_ascii_hexdigit() {
            return;
        }
        *byte = value;
    }
    // SAFETY: the accepted token must end after exactly TOKEN_LENGTH bytes.
    if unsafe { token.cast::<u8>().add(TOKEN_LENGTH).read() } != 0 {
        return;
    }
    enqueue_callback(CallbackToken {
        bytes,
        window_generation,
        kind,
    });
}

fn window_generation_is_ready(window_generation: u64) -> bool {
    WINDOWS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .values()
        .any(|state| {
            state.generation == window_generation
                && state.reverse_registered
                && state.bridge_confirmed
        })
}

fn enqueue_callback(callback: CallbackToken) {
    let mut queue = CALLBACKS.lock().unwrap_or_else(|error| error.into_inner());
    if queue.contains(&callback) {
        return;
    }
    queue.push_back(callback);
    drop(queue);
    super::toast_bridge::request_pump();
}

fn c_string_eq(value: *const c_char, expected: &[u8]) -> bool {
    if value.is_null() {
        return false;
    }
    for (index, expected) in expected.iter().copied().enumerate() {
        // SAFETY: Steam supplies a NUL-terminated method name during registration.
        if unsafe { value.cast::<u8>().add(index).read() } != expected {
            return false;
        }
    }
    // SAFETY: the expected prefix was readable and the next byte terminates the name.
    unsafe { value.cast::<u8>().add(expected.len()).read() == 0 }
}

pub(super) fn pending_bridge_windows() -> Vec<(usize, u64)> {
    WINDOWS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .filter_map(|(window, state)| {
            (state.reverse_registered && !state.bootstrap_dispatched && !state.bridge_confirmed)
                .then_some((*window, state.generation))
        })
        .collect()
}

pub(super) fn ready_windows() -> Vec<(usize, u64)> {
    let windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
    windows
        .iter()
        .filter_map(|(window, state)| {
            (state.reverse_registered && state.bridge_confirmed)
                .then_some((*window, state.generation))
        })
        .collect()
}

pub(super) fn live_window_generations() -> Vec<u64> {
    WINDOWS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .values()
        .map(|state| state.generation)
        .collect()
}

pub(super) fn mark_bridge_dispatched(window: usize, generation: u64) {
    let mut windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(state) = windows.get_mut(&window) {
        if state.generation == generation && state.reverse_registered {
            state.bootstrap_dispatched = true;
        }
    }
}

fn confirm_bridge_ready(window_generation: u64) -> bool {
    let confirmed = {
        let mut windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
        windows.iter_mut().find_map(|(window, state)| {
            if state.generation != window_generation || !state.reverse_registered {
                return None;
            }
            let changed = !state.bridge_confirmed;
            state.bridge_confirmed = true;
            Some((*window, changed))
        })
    };
    let Some((window, changed)) = confirmed else {
        return false;
    };
    if changed {
        info!(
            window = format_args!("{window:#x}"),
            generation = window_generation,
            "steamui: UI bridge confirmed"
        );
        update_conflict_ui_ready();
        publish_window_change();
    }
    true
}

#[cfg(test)]
fn invalidate_window(window: usize, generation: u64) {
    let removed = {
        let mut windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
        if windows
            .get(&window)
            .is_some_and(|state| state.generation == generation)
        {
            windows.remove(&window);
            true
        } else {
            false
        }
    };
    if removed {
        publish_window_change();
        update_conflict_ui_ready();
    }
}

fn retire_window(window: usize) {
    let removed = WINDOWS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&window)
        .is_some();
    if removed {
        publish_window_change();
        update_conflict_ui_ready();
    }
}

pub(super) fn set_runtime_ready(ready: bool) {
    crate::capability::set(
        crate::capability::Capability::ConflictUiBridge,
        ready,
        if ready {
            ""
        } else {
            "RunFrame or CHTMLWindow lifecycle hooks unavailable"
        },
    );
    update_conflict_ui_ready();
}

fn update_conflict_ui_ready() {
    let ready = crate::capability::is_ready(crate::capability::Capability::ConflictUiBridge)
        && WINDOWS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .any(|state| state.reverse_registered && state.bridge_confirmed);
    super::set_conflict_ui_ready(ready);
}

pub(super) fn take_callbacks() -> Vec<CallbackToken> {
    CALLBACKS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .drain(..)
        .collect()
}

pub(super) fn install(steamui_code: &CodeRegion) -> Vec<HookResult> {
    const REGISTER_NAME: &str = "CHTMLWindow::RegisterJSMethod";
    const DESTRUCTOR_NAME: &str = "CHTMLWindow::~CHTMLWindow";
    let mut results = vec![
        HookResult {
            name: REGISTER_NAME,
            installed: false,
            addr: 0,
        },
        HookResult {
            name: DESTRUCTOR_NAME,
            installed: false,
            addr: 0,
        },
    ];
    let Some((register_address, destructor_address)) =
        super::toast_bridge::html_window::lifecycle_method_addresses()
    else {
        warn!("steamui: CHTMLWindow lifecycle vtable slots not found");
        return results;
    };
    results[0].addr = register_address;
    results[1].addr = destructor_address;
    let range = AddressRange {
        start: steamui_code.base,
        end: steamui_code.base + steamui_code.bytes.len(),
    };
    let Some(register_plan) = validate_hook_target(HookTargetInput {
        target_address: register_address,
        replacement_address: hook as *const () as usize,
        executable_range: range,
    })
    .inspect_err(|error| warn!(%error, "steamui: RegisterJSMethod target validation failed"))
    .ok() else {
        return results;
    };
    let Some(destructor_plan) = validate_hook_target(HookTargetInput {
        target_address: destructor_address,
        replacement_address: destructor_hook as *const () as usize,
        executable_range: range,
    })
    .inspect_err(|error| warn!(%error, "steamui: CHTMLWindow destructor validation failed"))
    .ok() else {
        return results;
    };
    // SAFETY: the validated non-deleting destructor slot and replacement share this ABI.
    let destructor_pending = unsafe {
        vapor_forge_hook_engine::detour::create_detour::<DestructorFn>(
            DESTRUCTOR_NAME,
            destructor_plan,
        )
    };
    // SAFETY: SteamUI initialization writes the detour slot once.
    results[1].installed = unsafe {
        vapor_forge_hook_engine::detour::store_and_finalize(
            DESTRUCTOR_NAME,
            std::ptr::addr_of_mut!(DESTRUCTOR_DETOUR),
            destructor_pending,
        )
    };
    if !results[1].installed {
        return results;
    }

    // SAFETY: the validated RegisterJSMethod slot and replacement share this ABI.
    let register_pending = unsafe {
        vapor_forge_hook_engine::detour::create_detour::<RegisterJsMethodFn>(
            REGISTER_NAME,
            register_plan,
        )
    };
    // SAFETY: SteamUI initialization writes the detour slot once.
    results[0].installed = unsafe {
        vapor_forge_hook_engine::detour::store_and_finalize(
            REGISTER_NAME,
            std::ptr::addr_of_mut!(REGISTER_JS_METHOD_DETOUR),
            register_pending,
        )
    };
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_registry() {
        WINDOWS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        CALLBACKS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        crate::capability::set(
            crate::capability::Capability::ConflictUiBridge,
            false,
            "test reset",
        );
        let _ = vapor_forge_features::toast::take_ui_work();
        update_conflict_ui_ready();
    }

    fn register_test_window(window: usize) -> u64 {
        let generation = capture_window(window);
        let mut windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
        let state = windows.get_mut(&window).unwrap();
        state.reverse_registered = true;
        generation
    }

    #[test]
    fn bootstrap_dispatch_does_not_mark_the_ui_ready() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();

        let generation = register_test_window(0x1000);
        set_runtime_ready(true);
        mark_bridge_dispatched(0x1000, generation);

        assert!(pending_bridge_windows().is_empty());
        assert!(ready_windows().is_empty());
        assert!(!super::super::conflict_ui_ready());
        reset_registry();
    }

    #[test]
    fn ready_acknowledgement_requires_the_current_window_generation() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();

        let first = register_test_window(0x1000);
        let second = register_test_window(0x1000);
        set_runtime_ready(true);
        let ready = std::ffi::CString::new("cloud-conflict:3").unwrap();
        let wrong = std::ffi::CString::new("cloud-conflict:2").unwrap();

        // SAFETY: both strings are live NUL-terminated test inputs.
        unsafe { receive_ready(first as usize as *mut c_void, ready.as_ptr()) };
        // SAFETY: both strings are live NUL-terminated test inputs.
        unsafe { receive_ready(second as usize as *mut c_void, wrong.as_ptr()) };
        assert!(ready_windows().is_empty());
        assert!(!super::super::conflict_ui_ready());

        // SAFETY: the string is a live NUL-terminated test input.
        unsafe { receive_ready(second as usize as *mut c_void, ready.as_ptr()) };
        assert_eq!(ready_windows(), vec![(0x1000, second)]);
        assert!(super::super::conflict_ui_ready());

        retire_window(0x1000);
        assert!(ready_windows().is_empty());
        assert!(!super::super::conflict_ui_ready());
        reset_registry();
    }

    #[test]
    fn conflict_callbacks_require_a_confirmed_current_generation() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();

        let first = register_test_window(0x1000);
        let token = std::ffi::CString::new("a".repeat(TOKEN_LENGTH)).unwrap();
        // SAFETY: the token is a live NUL-terminated test input.
        unsafe { receive_choice(first as usize as *mut c_void, token.as_ptr()) };
        assert!(take_callbacks().is_empty());

        assert!(confirm_bridge_ready(first));
        // SAFETY: the token is a live NUL-terminated test input.
        unsafe { receive_choice(first as usize as *mut c_void, token.as_ptr()) };
        assert_eq!(take_callbacks().len(), 1);

        register_test_window(0x1000);
        // SAFETY: the token is a live NUL-terminated test input.
        unsafe { receive_choice(first as usize as *mut c_void, token.as_ptr()) };
        assert!(take_callbacks().is_empty());
        reset_registry();
    }

    #[test]
    fn replacement_changes_generation_without_retaining_the_old_entry() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();

        let first = capture_window(0x1000);
        let second = capture_window(0x1000);

        assert_ne!(first, second);
        let windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[&0x1000].generation, second);
        drop(windows);
        assert!(vapor_forge_features::toast::take_ui_work());

        invalidate_window(0x1000, first);
        assert!(WINDOWS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains_key(&0x1000));
        reset_registry();
    }

    #[test]
    fn destruction_retires_the_exact_window_and_publishes_work() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();

        let generation = capture_window(0x1000);
        capture_window(0x2000);
        let _ = vapor_forge_features::toast::take_ui_work();

        retire_window(0x1000);

        let windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
        assert!(!windows.contains_key(&0x1000));
        assert!(windows.contains_key(&0x2000));
        drop(windows);
        assert!(vapor_forge_features::toast::take_ui_work());
        invalidate_window(0x1000, generation);
        reset_registry();
    }

    #[test]
    fn live_generations_include_each_registered_window_once() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();

        let first = capture_window(0x1000);
        let second = capture_window(0x2000);
        let mut generations = live_window_generations();
        generations.sort_unstable();

        assert_eq!(generations, vec![first, second]);
        reset_registry();
    }

    #[test]
    fn callback_queue_preserves_more_than_one_ui_turn_of_choices() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();

        for index in 0..40u8 {
            let mut bytes = [b'0'; TOKEN_LENGTH];
            bytes[TOKEN_LENGTH - 2] = b"0123456789abcdef"[(index / 16) as usize];
            bytes[TOKEN_LENGTH - 1] = b"0123456789abcdef"[(index % 16) as usize];
            enqueue_callback(CallbackToken {
                bytes,
                window_generation: 7,
                kind: CallbackKind::Choice,
            });
        }

        assert_eq!(take_callbacks().len(), 40);
        reset_registry();
    }

    #[test]
    fn callback_after_a_drain_publishes_the_next_ui_turn() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let first = CallbackToken {
            bytes: [b'1'; TOKEN_LENGTH],
            window_generation: 7,
            kind: CallbackKind::Choice,
        };
        let second = CallbackToken {
            bytes: [b'2'; TOKEN_LENGTH],
            window_generation: 7,
            kind: CallbackKind::Choice,
        };

        enqueue_callback(first);
        assert!(vapor_forge_features::toast::take_ui_work());
        assert_eq!(take_callbacks(), vec![first]);
        enqueue_callback(second);

        assert!(vapor_forge_features::toast::take_ui_work());
        assert_eq!(take_callbacks(), vec![second]);
        reset_registry();
    }

    #[test]
    fn choice_receipt_and_retry_are_distinct_events() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let bytes = [b'a'; TOKEN_LENGTH];

        for kind in [
            CallbackKind::Choice,
            CallbackKind::Receipt,
            CallbackKind::Retry,
        ] {
            enqueue_callback(CallbackToken {
                bytes,
                window_generation: 7,
                kind,
            });
        }

        let callbacks = take_callbacks();
        assert_eq!(callbacks.len(), 3);
        assert_eq!(callbacks[0].kind, CallbackKind::Choice);
        assert_eq!(callbacks[1].kind, CallbackKind::Receipt);
        assert_eq!(callbacks[2].kind, CallbackKind::Retry);
        reset_registry();
    }
}
