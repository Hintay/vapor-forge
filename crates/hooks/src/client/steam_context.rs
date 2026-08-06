//! Generation-bound Steam interface context.

use core::ffi::c_void;
use std::cell::Cell;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;

use tracing::{debug, warn};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::original_detour;

const OWNER_INTERFACE_SLOTS: usize = 32;
const MAX_MAPS_LINE_LEN: usize = 4096;

pub(crate) const USER_INTERFACE_INIT_NAME: &str = "CUserInterface::Init";
pub(crate) const USER_INTERFACE_DESTRUCTOR_NAME: &str = "CUserInterface::~CUserInterface";

pub(crate) type UserInterfaceInitFn = unsafe extern "C" fn(*mut c_void, i32, i32);
pub(crate) type UserInterfaceDestructorFn = unsafe extern "C" fn(*mut c_void);

pub(crate) static mut USER_INTERFACE_INIT_DETOUR: Option<Detour<UserInterfaceInitFn>> = None;
pub(crate) static mut USER_INTERFACE_DESTRUCTOR_DETOUR: Option<Detour<UserInterfaceDestructorFn>> =
    None;

static REVISION: AtomicU64 = AtomicU64::new(0);
static OWNER_PTR: AtomicUsize = AtomicUsize::new(0);
static USER_PTR: AtomicUsize = AtomicUsize::new(0);
static STATS_PTR: AtomicUsize = AtomicUsize::new(0);
static CONFIG_STORE_PTR: AtomicUsize = AtomicUsize::new(0);
static STEAM_USER: AtomicI32 = AtomicI32::new(0);
static IDENTITY_GENERATION: AtomicU64 = AtomicU64::new(0);
static STEAM_ID64: AtomicU64 = AtomicU64::new(0);
static CALL_GUARD: RwLock<()> = RwLock::new(());
static PACKET_IDENTITY: std::sync::Mutex<Option<(u64, u64)>> = std::sync::Mutex::new(None);

thread_local! {
    static CHECKED_CALL_DEPTH: Cell<u32> = const { Cell::new(0) };
}

struct CheckedCallScope;

impl CheckedCallScope {
    fn enter() -> Self {
        CHECKED_CALL_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}

impl Drop for CheckedCallScope {
    fn drop(&mut self) {
        CHECKED_CALL_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

pub(super) fn checked_call_active() -> bool {
    CHECKED_CALL_DEPTH.with(|depth| depth.get() != 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CapturedInterfaces {
    pub(super) revision: u64,
    pub(super) identity_generation: u64,
    pub(super) steam_id64: u64,
    pub(super) steam_user: i32,
    pub(super) owner: *mut c_void,
    pub(super) user: *mut c_void,
    pub(super) stats: *mut c_void,
    pub(super) config_store: *mut c_void,
}

// SAFETY: Steam owns these objects. Every dereference is serialized with owner
// replacement and checked against the context revision.
unsafe impl Send for CapturedInterfaces {}

pub(crate) unsafe extern "C" fn hk_user_interface_init(
    owner: *mut c_void,
    steam_user: i32,
    steam_pipe: i32,
) {
    // SAFETY: installation initializes the detour before enabling it.
    let Some(original) = (unsafe {
        original_detour(
            USER_INTERFACE_INIT_NAME,
            std::ptr::addr_of!(USER_INTERFACE_INIT_DETOUR),
        )
    }) else {
        return;
    };
    // SAFETY: forwards Steam's live owner and unchanged handles.
    unsafe { original(owner, steam_user, steam_pipe) };
    if crate::capability::is_ready(crate::capability::Capability::CallbackEvents) {
        observe_owner(owner, steam_user);
    }
}

pub(crate) unsafe extern "C" fn hk_user_interface_destructor(owner: *mut c_void) {
    if crate::capability::is_ready(crate::capability::Capability::CallbackEvents) {
        invalidate_owner(owner);
    }
    // SAFETY: installation initializes the detour before enabling it.
    let Some(original) = (unsafe {
        original_detour(
            USER_INTERFACE_DESTRUCTOR_NAME,
            std::ptr::addr_of!(USER_INTERFACE_DESTRUCTOR_DETOUR),
        )
    }) else {
        return;
    };
    // SAFETY: forwards Steam's live owner after readers have released it.
    unsafe { original(owner) };
}

pub(crate) fn observe_user_interface(this: *mut c_void, steam_id64: u64) {
    if this.is_null()
        || steam_id64 == 0
        || !vapor_forge_features::identity::is_valid_individual_steam_id(steam_id64)
        || this as usize != USER_PTR.load(Ordering::Acquire)
        || OWNER_PTR.load(Ordering::Acquire) == 0
    {
        return;
    }
    let generation = vapor_forge_features::identity::generation();
    if generation == 0 {
        return;
    }
    if IDENTITY_GENERATION.load(Ordering::Acquire) == generation
        && STEAM_ID64.load(Ordering::Acquire) == steam_id64
    {
        return;
    }
    let changed = write_context(|current| {
        if current.owner != 0 && current.user == this as usize {
            current.identity_generation = generation;
            current.steam_id64 = steam_id64;
        }
    });
    if changed {
        super::callback_notify::notify();
    }
}

pub(crate) fn observe_packet_identity(steam_id64: u64) {
    if !vapor_forge_features::identity::is_valid_individual_steam_id(steam_id64)
        || vapor_forge_features::identity::steam_id() != steam_id64
    {
        return;
    }
    let generation = vapor_forge_features::identity::generation();
    *PACKET_IDENTITY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((generation, steam_id64));
    observe_user_interface(USER_PTR.load(Ordering::Acquire) as *mut c_void, steam_id64);
}

pub(super) fn capture() -> Option<CapturedInterfaces> {
    loop {
        let revision = REVISION.load(Ordering::Acquire);
        if revision & 1 != 0 {
            std::hint::spin_loop();
            continue;
        }
        let captured = CapturedInterfaces {
            revision,
            identity_generation: IDENTITY_GENERATION.load(Ordering::Acquire),
            steam_id64: STEAM_ID64.load(Ordering::Acquire),
            steam_user: STEAM_USER.load(Ordering::Acquire),
            owner: OWNER_PTR.load(Ordering::Acquire) as *mut c_void,
            user: USER_PTR.load(Ordering::Acquire) as *mut c_void,
            stats: STATS_PTR.load(Ordering::Acquire) as *mut c_void,
            config_store: CONFIG_STORE_PTR.load(Ordering::Acquire) as *mut c_void,
        };
        if REVISION.load(Ordering::Acquire) != revision {
            continue;
        }
        if captured.owner.is_null()
            || captured.user.is_null()
            || captured.stats.is_null()
            || captured.config_store.is_null()
            || captured.steam_user == 0
            || captured.steam_id64 == 0
            || captured.identity_generation != vapor_forge_features::identity::generation()
            || captured.steam_id64 != vapor_forge_features::identity::steam_id()
        {
            return None;
        }
        return Some(captured);
    }
}

pub(super) fn is_current(captured: CapturedInterfaces) -> bool {
    captured.revision == REVISION.load(Ordering::Acquire)
        && captured.identity_generation == vapor_forge_features::identity::generation()
        && captured.steam_id64 == vapor_forge_features::identity::steam_id()
        && captured.owner as usize == OWNER_PTR.load(Ordering::Acquire)
        && captured.user as usize == USER_PTR.load(Ordering::Acquire)
        && captured.stats as usize == STATS_PTR.load(Ordering::Acquire)
        && captured.config_store as usize == CONFIG_STORE_PTR.load(Ordering::Acquire)
        && captured.steam_user == STEAM_USER.load(Ordering::Acquire)
}

pub(super) fn config_store_is_current(revision: u64, config_store: *mut c_void) -> bool {
    revision != 0
        && revision == REVISION.load(Ordering::Acquire)
        && config_store as usize == CONFIG_STORE_PTR.load(Ordering::Acquire)
        && IDENTITY_GENERATION.load(Ordering::Acquire)
            == vapor_forge_features::identity::generation()
        && STEAM_ID64.load(Ordering::Acquire) == vapor_forge_features::identity::steam_id()
}

pub(super) fn callback_identity(steam_user: i32) -> Option<(u64, u64)> {
    let revision = REVISION.load(Ordering::Acquire);
    if revision & 1 != 0 {
        return None;
    }
    let current_user = STEAM_USER.load(Ordering::Acquire);
    let identity_generation = IDENTITY_GENERATION.load(Ordering::Acquire);
    let steam_id64 = STEAM_ID64.load(Ordering::Acquire);
    if REVISION.load(Ordering::Acquire) != revision
        || steam_user == 0
        || steam_user != current_user
        || identity_generation == 0
        || steam_id64 == 0
        || identity_generation != vapor_forge_features::identity::generation()
        || steam_id64 != vapor_forge_features::identity::steam_id()
    {
        return None;
    }
    Some((identity_generation, steam_id64))
}

pub(super) fn checked_call<T>(
    captured: CapturedInterfaces,
    call: impl FnOnce() -> T,
) -> Result<T, &'static str> {
    let _guard = CALL_GUARD
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !is_current(captured) {
        return Err("Steam interface context changed");
    }
    let _scope = CheckedCallScope::enter();
    let result = call();
    if !is_current(captured) {
        return Err("Steam interface context changed");
    }
    Ok(result)
}

pub(crate) fn invalidate_identity() {
    super::client_id::cancel_capture();
    *PACKET_IDENTITY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    if write_context(|current| {
        current.identity_generation = 0;
        current.steam_id64 = 0;
    }) {
        super::callback_notify::clear_account();
    }
}

#[cfg(any(debug_assertions, test))]
pub(crate) fn diagnostic_status() -> String {
    format!(
        "context_revision={} steam_user={} owner=0x{:x} user_ptr=0x{:x} stats_ptr=0x{:x} config_store_ptr=0x{:x}",
        REVISION.load(Ordering::Relaxed),
        STEAM_USER.load(Ordering::Relaxed),
        OWNER_PTR.load(Ordering::Relaxed),
        USER_PTR.load(Ordering::Relaxed),
        STATS_PTR.load(Ordering::Relaxed),
        CONFIG_STORE_PTR.load(Ordering::Relaxed),
    )
}

fn observe_owner(owner: *mut c_void, steam_user: i32) {
    if owner.is_null() || steam_user == 0 {
        return;
    }
    let Some(user_vtable) =
        crate::vtable_scan::find_interface("IClientUser").map(|interface| interface.vtable_va)
    else {
        warn!("steam-context: IClientUser vtable unavailable");
        return;
    };
    let Some(stats_vtable) =
        crate::vtable_scan::find_interface("IClientUserStats").map(|interface| interface.vtable_va)
    else {
        warn!("steam-context: IClientUserStats vtable unavailable");
        return;
    };
    let Some(config_store_vtable) = crate::vtable_scan::find_interface("IClientConfigStore")
        .map(|interface| interface.vtable_va)
    else {
        warn!("steam-context: IClientConfigStore vtable unavailable");
        return;
    };
    let Some(mappings) = readable_mappings() else {
        warn!("steam-context: readable mappings unavailable");
        return;
    };
    let Some((user_offset, user)) = find_owner_member(owner, user_vtable, &mappings) else {
        warn!("steam-context: owner does not contain one IClientUser member");
        return;
    };
    let Some((stats_offset, stats)) = find_owner_member(owner, stats_vtable, &mappings) else {
        warn!("steam-context: owner does not contain one IClientUserStats member");
        return;
    };
    let Some((config_store_offset, config_store)) =
        find_owner_member(owner, config_store_vtable, &mappings)
    else {
        warn!("steam-context: owner does not contain one IClientConfigStore member");
        return;
    };
    if user == stats || user == config_store || stats == config_store {
        warn!("steam-context: owner interface members alias");
        return;
    }

    let packet_identity = *PACKET_IDENTITY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (identity_generation, steam_id64) = packet_identity
        .filter(|(generation, steam_id64)| {
            *generation == vapor_forge_features::identity::generation()
                && *steam_id64 == vapor_forge_features::identity::steam_id()
        })
        .unwrap_or_default();

    let changed = write_context(|current| {
        *current = ContextValues {
            owner: owner as usize,
            user: user as usize,
            stats: stats as usize,
            config_store: config_store as usize,
            steam_user,
            identity_generation,
            steam_id64,
        };
    });
    super::internal_callbacks::observe_user(steam_user);
    if changed {
        debug!(
            owner = format_args!("0x{:x}", owner as usize),
            user_offset = format_args!("0x{user_offset:x}"),
            stats_offset = format_args!("0x{stats_offset:x}"),
            config_store_offset = format_args!("0x{config_store_offset:x}"),
            "steam-context: captured owner interfaces"
        );
        super::client_id::cancel_capture();
        super::callback_notify::clear_account();
    }
}

fn invalidate_owner(owner: *mut c_void) {
    if owner.is_null() || owner as usize != OWNER_PTR.load(Ordering::Acquire) {
        return;
    }
    if write_context(|current| {
        if current.owner == owner as usize {
            *current = ContextValues::default();
        }
    }) {
        super::client_id::cancel_capture();
        super::callback_notify::clear_account();
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct ContextValues {
    owner: usize,
    user: usize,
    stats: usize,
    config_store: usize,
    steam_user: i32,
    identity_generation: u64,
    steam_id64: u64,
}

fn write_context(update: impl FnOnce(&mut ContextValues)) -> bool {
    let _guard = CALL_GUARD
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut values = ContextValues {
        owner: OWNER_PTR.load(Ordering::Relaxed),
        user: USER_PTR.load(Ordering::Relaxed),
        stats: STATS_PTR.load(Ordering::Relaxed),
        config_store: CONFIG_STORE_PTR.load(Ordering::Relaxed),
        steam_user: STEAM_USER.load(Ordering::Relaxed),
        identity_generation: IDENTITY_GENERATION.load(Ordering::Relaxed),
        steam_id64: STEAM_ID64.load(Ordering::Relaxed),
    };
    let previous = values;
    update(&mut values);
    if values == previous {
        return false;
    }
    let start = loop {
        let current = REVISION.load(Ordering::Acquire);
        if current & 1 == 0
            && REVISION
                .compare_exchange(
                    current,
                    current.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            break current;
        }
        std::hint::spin_loop();
    };
    OWNER_PTR.store(values.owner, Ordering::Relaxed);
    USER_PTR.store(values.user, Ordering::Relaxed);
    STATS_PTR.store(values.stats, Ordering::Relaxed);
    CONFIG_STORE_PTR.store(values.config_store, Ordering::Relaxed);
    STEAM_USER.store(values.steam_user, Ordering::Relaxed);
    IDENTITY_GENERATION.store(values.identity_generation, Ordering::Relaxed);
    STEAM_ID64.store(values.steam_id64, Ordering::Relaxed);
    REVISION.store(start.wrapping_add(2), Ordering::Release);
    true
}

#[derive(Clone, Copy)]
struct ReadableMapping {
    start: usize,
    end: usize,
}

fn readable_mappings() -> Option<Vec<ReadableMapping>> {
    let contents = std::fs::read_to_string("/proc/self/maps").ok()?;
    let mut mappings = Vec::new();
    for line in contents.lines() {
        if line.len() > MAX_MAPS_LINE_LEN {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(permissions) = fields.next() else {
            continue;
        };
        if !permissions.starts_with('r') {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
        ) else {
            continue;
        };
        mappings.push(ReadableMapping { start, end });
    }
    Some(mappings)
}

fn find_owner_member(
    owner: *mut c_void,
    expected_vtable: usize,
    mappings: &[ReadableMapping],
) -> Option<(usize, *mut c_void)> {
    let owner = owner as usize;
    let word = std::mem::size_of::<usize>();
    let mut matched = None;
    for index in 0..OWNER_INTERFACE_SLOTS {
        let offset = index.checked_mul(word)?;
        let slot = owner.checked_add(offset)?;
        if !is_readable(slot, word, mappings) {
            continue;
        }
        // SAFETY: this owner member slot is readable.
        let candidate = unsafe { (slot as *const usize).read_unaligned() };
        if candidate == 0 || !is_readable(candidate, word, mappings) {
            continue;
        }
        // SAFETY: the candidate's first pointer-sized word is readable.
        let vtable = unsafe { (candidate as *const usize).read_unaligned() };
        if vtable != expected_vtable {
            continue;
        }
        if matched.is_some() {
            return None;
        }
        matched = Some((offset, candidate as *mut c_void));
    }
    matched
}

fn is_readable(address: usize, length: usize, mappings: &[ReadableMapping]) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    mappings
        .iter()
        .any(|mapping| address >= mapping.start && end <= mapping.end)
}
