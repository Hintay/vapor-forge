use core::ffi::{c_char, c_void};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::Mutex;

use once_cell::sync::Lazy;
use tracing::{info, warn};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::detour_or_return;
use vapor_forge_hook_engine::plan::{validate_hook_target, AddressRange, HookTargetInput};

use crate::hook_report::HookResult;
use crate::pattern_resolver::CodeRegion;

const RESOLVE_METHOD: &[u8] = b"Apps.VaporForgeResolveCloudConflict\0";
const URL_METHOD: &[u8] = b"URL.ExecuteSteamURL";
const CONTINUE_METHOD: &[u8] = b"Apps.ContinueGameAction";
const TOKEN_LENGTH: usize = 64;
const CALLBACK_CAPACITY: usize = 32;

static NEXT_WINDOW_GENERATION: AtomicU64 = AtomicU64::new(1);
static STRING_HANDLER_VPTR: AtomicUsize = AtomicUsize::new(0);
static WINDOW_CONTEXT_CHANGED: AtomicBool = AtomicBool::new(false);
static WINDOWS: Lazy<Mutex<HashMap<usize, WindowRegistration>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CALLBACKS: Mutex<VecDeque<CallbackToken>> = Mutex::new(VecDeque::new());

#[derive(Clone, Copy)]
struct WindowRegistration {
    generation: u64,
    registered: bool,
}

#[derive(Clone, Copy)]
pub(super) struct CallbackToken {
    bytes: [u8; TOKEN_LENGTH],
    pub(super) window_generation: u64,
}

impl CallbackToken {
    pub(super) fn as_str(&self) -> &str {
        // SAFETY: the callback accepts only ASCII hexadecimal bytes.
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
    }
}

type RegisterJsMethodFn = unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, i32);

static mut DETOUR: Option<Detour<RegisterJsMethodFn>> = None;

#[repr(C)]
struct StringBinding {
    vptr: usize,
    context: *mut c_void,
    function: unsafe extern "C" fn(*mut c_void, *const c_char),
    adjustment: isize,
}

const _: [(); std::mem::size_of::<usize>() * 4] = [(); std::mem::size_of::<StringBinding>()];

unsafe extern "C" fn hook(
    window: *mut c_void,
    name: *const c_char,
    binding: *mut c_void,
    kind: i32,
) {
    let original = detour_or_return!("CHTMLWindow::RegisterJSMethod", DETOUR);
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
    if window.is_null() || binding.is_null() || kind != 1 {
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
        let generation = NEXT_WINDOW_GENERATION.fetch_add(1, Ordering::AcqRel);
        WINDOWS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                window as usize,
                WindowRegistration {
                    generation,
                    registered: false,
                },
            );
        WINDOW_CONTEXT_CHANGED.store(true, Ordering::Release);
        register_window(original, window as usize);
        super::toast_bridge::request_pump();
    }
}

fn register_waiting_windows(original: RegisterJsMethodFn) {
    let windows = WINDOWS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .filter_map(|(window, state)| (!state.registered).then_some(*window))
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
        if state.registered {
            return;
        }
        state.registered = true;
        state.generation
    };
    // SAFETY: Steam's handler deleting destructor uses the process allocator.
    let binding =
        unsafe { libc::malloc(std::mem::size_of::<StringBinding>()) }.cast::<StringBinding>();
    if binding.is_null() {
        WINDOWS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(window)
            .and_modify(|state| state.registered = false);
        return;
    }
    // SAFETY: malloc returned writable storage with the requested size.
    unsafe {
        binding.write(StringBinding {
            vptr,
            context: generation as usize as *mut c_void,
            function: receive_choice,
            adjustment: 0,
        });
        original(
            window as *mut c_void,
            RESOLVE_METHOD.as_ptr().cast(),
            binding.cast(),
            1,
        );
    }
    info!(
        window = format_args!("{window:#x}"),
        generation, "steamui: reverse bridge registered"
    );
}

unsafe extern "C" fn receive_choice(context: *mut c_void, token: *const c_char) {
    let window_generation = context as usize as u64;
    if window_generation == 0 || token.is_null() {
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
    let mut queue = CALLBACKS.lock().unwrap_or_else(|error| error.into_inner());
    if queue.len() < CALLBACK_CAPACITY {
        queue.push_back(CallbackToken {
            bytes,
            window_generation,
        });
        drop(queue);
        super::toast_bridge::request_pump();
    }
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

pub(super) fn registered_windows() -> Vec<(usize, u64)> {
    let mut windows = WINDOWS.lock().unwrap_or_else(|error| error.into_inner());
    windows.retain(|window, _| super::toast_bridge::html_window::is_html_window(*window));
    windows
        .iter()
        .filter_map(|(window, state)| state.registered.then_some((*window, state.generation)))
        .collect()
}

pub(super) fn take_callbacks() -> Vec<CallbackToken> {
    CALLBACKS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .drain(..)
        .collect()
}

pub(super) fn take_window_context_changed() -> bool {
    WINDOW_CONTEXT_CHANGED.swap(false, Ordering::AcqRel)
}

pub(super) fn install(steamui_code: &CodeRegion) -> HookResult {
    const NAME: &str = "CHTMLWindow::RegisterJSMethod";
    let mut result = HookResult {
        name: NAME,
        installed: false,
        addr: 0,
    };
    let Some(address) = super::toast_bridge::html_window::register_js_method_address() else {
        warn!("steamui: RegisterJSMethod vtable slot not found");
        return result;
    };
    result.addr = address;
    let Some(plan) = validate_hook_target(HookTargetInput {
        target_address: address,
        replacement_address: hook as *const () as usize,
        executable_range: AddressRange {
            start: steamui_code.base,
            end: steamui_code.base + steamui_code.bytes.len(),
        },
    })
    .inspect_err(|error| warn!(%error, "steamui: RegisterJSMethod target validation failed"))
    .ok() else {
        return result;
    };
    // SAFETY: the primary CHTMLWindow vtable slot and replacement share this ABI.
    let pending =
        unsafe { vapor_forge_hook_engine::detour::create_detour::<RegisterJsMethodFn>(NAME, plan) };
    // SAFETY: SteamUI initialization writes the detour slot once.
    result.installed = unsafe {
        vapor_forge_hook_engine::detour::store_and_finalize(
            NAME,
            std::ptr::addr_of_mut!(DETOUR),
            pending,
        )
    };
    result
}
