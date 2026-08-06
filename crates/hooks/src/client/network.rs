use core::ffi::c_void;
use std::alloc::Layout;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};

use tracing::{info, warn};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_patterns::registry::PatternRegistry;

use crate::netpacket::SendFrameDecision;
use crate::pattern_resolver::CodeRegion;
use crate::work_item_site::WorkItemSite;
use vapor_forge_hook_engine::original::detour_or_return;
// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type BBuildAndAsyncSendFrameFn =
    unsafe extern "C" fn(*mut c_void, i32, *mut u8, u32) -> bool;
pub(crate) type RecvPktFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
pub(crate) type WorkThreadPoolAddWorkItemFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool;
type PacketAllocFn = unsafe extern "C" fn() -> *mut c_void;
type PacketInitFn = unsafe extern "C" fn(*mut c_void, u32, *mut u8, u32, *mut u8, u32);
type PacketReleaseFn = unsafe extern "C" fn(*mut c_void);

// ---------------------------------------------------------------------------
// Static detour slots
// ---------------------------------------------------------------------------

pub(crate) static mut SEND_FRAME_DETOUR: Option<Detour<BBuildAndAsyncSendFrameFn>> = None;
pub(crate) static mut RECV_PKT_DETOUR: Option<Detour<RecvPktFn>> = None;

static PACKET_ALLOC_ADDR: AtomicUsize = AtomicUsize::new(0);
static PACKET_INIT_ADDR: AtomicUsize = AtomicUsize::new(0);
static PACKET_RELEASE_ADDR: AtomicUsize = AtomicUsize::new(0);
static ADD_WORK_ITEM_ADDR: AtomicUsize = AtomicUsize::new(0);

// Production native-dispatch state. Fabricated responses queue here and are
// dispatched on CNet's frame thread through a custom CWorkItem.
static INJECTION_QUEUE: OnceLock<Mutex<VecDeque<QueuedInjection>>> = OnceLock::new();
// Steam's own bare-CWorkItem post site, decoded once at install.
static WORK_ITEM_SITE: OnceLock<WorkItemSite> = OnceLock::new();
// Serializes context publication, invalidation, work-item claims, and native delivery.
static DISPATCH: DispatchCoordinator = DispatchCoordinator::new();
// One-shot native-dispatch self-test, armed from the debug socket.
static NATIVE_INJECT_ARMED: AtomicBool = AtomicBool::new(false);
// One-shot flush of anything a source queued before dispatch context was ready.
static WARMUP_FLUSH_DONE: AtomicBool = AtomicBool::new(false);
// One real inbound body, captured once, replayed by the own-thread dispatch test
// (a safe payload Steam has already handled). Gated by the atomic so the hot path
// pays only an atomic load once captured.
static LAST_INBOUND_CAPTURED: AtomicBool = AtomicBool::new(false);
static LAST_INBOUND_BODY: Mutex<Option<Vec<u8>>> = Mutex::new(None);
static CM_FAIL_CLOSED_REPORTED: AtomicBool = AtomicBool::new(false);

// Covers the doubles the embedded cumulative timers hold on either arch.
const WORK_ITEM_ALIGN: usize = 16;
// Diagnostic soft bound. Producers have their own admission limits; once a
// response is accepted here it is retained until dispatch or stale rejection.
const MAX_QUEUED_INJECTIONS: usize = 64;
// Steam's own map runs to a few thousand lines; this only has to reach past
// steamclient and its .bss.
const MAX_MAPS_ENTRIES: usize = 4096;

fn current_pthread() -> usize {
    // SAFETY: pthread_self has no preconditions and only reads the current tid.
    unsafe { libc::pthread_self() as usize }
}

pub(crate) fn resolve_native_packet_functions(registry: &PatternRegistry, code: &CodeRegion) {
    let packet_alloc =
        super::install::resolve_address_from_registry(registry, code, "CNetPacket::Alloc");
    let packet_init =
        super::install::resolve_address_from_registry(registry, code, "CNetPacket::Init");
    let packet_release =
        super::install::resolve_address_from_registry(registry, code, "CNetPacket::Release");
    let add_work_item = super::install::resolve_address_from_registry(
        registry,
        code,
        "CWorkThreadPool::AddWorkItem",
    );

    if let Some(addr) = packet_alloc {
        PACKET_ALLOC_ADDR.store(addr, Ordering::Release);
    }
    if let Some(addr) = packet_init {
        PACKET_INIT_ADDR.store(addr, Ordering::Release);
    }
    if let Some(addr) = packet_release {
        PACKET_RELEASE_ADDR.store(addr, Ordering::Release);
    }
    if let Some(addr) = add_work_item {
        ADD_WORK_ITEM_ADDR.store(addr, Ordering::Release);
    }
    resolve_work_item_site(registry, code, add_work_item);

    info!(
        packet_alloc = %format_resolved_addr(packet_alloc),
        packet_init = %format_resolved_addr(packet_init),
        packet_release = %format_resolved_addr(packet_release),
        add_work_item = %format_resolved_addr(add_work_item),
        "native-packet: Steam CNetPacket and work-item functions resolved"
    );
}

pub(crate) fn native_packet_functions_ready() -> bool {
    WORK_ITEM_SITE.get().is_some()
        && ADD_WORK_ITEM_ADDR.load(Ordering::Acquire) != 0
        && PACKET_ALLOC_ADDR.load(Ordering::Acquire) != 0
        && PACKET_INIT_ADDR.load(Ordering::Acquire) != 0
        && PACKET_RELEASE_ADDR.load(Ordering::Acquire) != 0
}

/// Read back the three build-specific values injection needs from Steam's own
/// bare-`CWorkItem` post, and admit them only if they are consistent with the
/// separately resolved enqueue function and with steamclient's own mappings.
fn resolve_work_item_site(
    registry: &PatternRegistry,
    code: &CodeRegion,
    add_work_item: Option<usize>,
) {
    let Some(site) = super::install::resolve_address_from_registry(
        registry,
        code,
        "CWebSocketConnection::PostDelayedCloseWorkItem",
    ) else {
        warn!("native-inject: work item post site is unresolved, dispatch stays off");
        return;
    };
    let decoded = match crate::work_item_site::decode(usize::BITS, code.base, code.bytes, site) {
        Ok(decoded) => decoded,
        Err(error) => {
            warn!(error, "native-inject: work item post site did not decode");
            return;
        }
    };
    if Some(decoded.add_work_item) != add_work_item {
        warn!(
            decoded = format_args!("0x{:x}", decoded.add_work_item),
            resolved = %format_resolved_addr(add_work_item),
            "native-inject: the site's enqueue call disagrees with the resolved AddWorkItem"
        );
        return;
    }
    // Both are read or stored as pointers, so a decode that drifted into .text
    // or out of the module has to be rejected before anything dereferences it.
    // That is the failure a pinned RVA produced before these values were
    // inferred. The pool slot lives in .bss, so the check has to reach past the
    // module's named segments.
    let data = vapor_forge_memory::find_proc_self_module_data("steamclient.so", MAX_MAPS_ENTRIES)
        .unwrap_or_default();
    for (label, address) in [
        ("pool slot", decoded.pool_slot),
        ("timer vtable", decoded.timer_vtable),
    ] {
        let aligned = address % std::mem::align_of::<usize>() == 0;
        if !aligned
            || !data
                .iter()
                .any(|range| (range.base.0..range.end.0).contains(&address))
        {
            warn!(
                label,
                aligned,
                address = format_args!("0x{address:x}"),
                "native-inject: decoded address is not steamclient data"
            );
            return;
        }
    }
    info!(
        site = format_args!("0x{site:x}"),
        pool_slot = format_args!("0x{:x}", decoded.pool_slot),
        timer_vtable = format_args!("0x{:x}", decoded.timer_vtable),
        item_size = decoded.item_size,
        timer_vptrs = ?decoded.timer_vptr_offsets,
        refcount = decoded.refcount_offset,
        sentinels = ?decoded.sentinel_offsets,
        "native-inject: work item post site decoded"
    );
    let _ = WORK_ITEM_SITE.set(decoded);
}

fn format_resolved_addr(addr: Option<usize>) -> String {
    addr.map_or_else(|| "unresolved".to_owned(), |addr| format!("0x{addr:x}"))
}

// ---------------------------------------------------------------------------
// Hook replacement functions: BBuildAndAsyncSendFrame (outgoing WS frames)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_send_frame(
    this: *mut c_void,
    opcode: i32,
    data: *mut u8,
    size: u32,
) -> bool {
    const WEBSOCKET_BINARY: i32 = 2;
    // SAFETY: SEND_FRAME_DETOUR is initialized before this replacement is enabled.
    let original = detour_or_return!("BBuildAndAsyncSendFrame", SEND_FRAME_DETOUR, false);
    if !crate::capability::is_ready(crate::capability::Capability::CmInterception) {
        if opcode == WEBSOCKET_BINARY && !data.is_null() && size > 0 {
            if !CM_FAIL_CLOSED_REPORTED.swap(true, Ordering::AcqRel) {
                warn!("netpacket: CM interception is incomplete; binary sends are blocked");
            }
            return false;
        }
        // SAFETY: forwards the untouched non-binary frame to Steam.
        return unsafe { original(this, opcode, data, size) };
    }
    if opcode == WEBSOCKET_BINARY && !data.is_null() && size > 0 {
        // SAFETY: data is a valid buffer of `size` bytes, provided by Steam.
        let slice = unsafe { std::slice::from_raw_parts(data, size as usize) };

        match crate::netpacket::decide_send_frame(slice) {
            SendFrameDecision::Pass => {}
            SendFrameDecision::Drop => return true,
            SendFrameDecision::Retry => return false,
            SendFrameDecision::Rewrite(rewritten) => {
                // SAFETY: the rewritten buffer remains live through the synchronous call.
                return unsafe {
                    original(
                        this,
                        opcode,
                        rewritten.as_ptr() as *mut u8,
                        rewritten.len() as u32,
                    )
                };
            }
        }
    }

    // SAFETY: forwards the untouched frame to Steam.
    unsafe { original(this, opcode, data, size) }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: RecvPkt (incoming packets)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_recv_pkt(this: *mut c_void, packet: *mut c_void) {
    // SAFETY: RECV_PKT_DETOUR is initialized before this replacement is enabled.
    let original = detour_or_return!("RecvPkt", RECV_PKT_DETOUR);
    if !crate::capability::is_ready(crate::capability::Capability::CmInterception) {
        // SAFETY: forwards the untouched packet to Steam.
        unsafe { original(this, packet) };
        return;
    }
    // One-shot capture of the receiver / conn id for native dispatch (worker_this
    // comes from the post-item hook).
    let context_captured = capture_dispatch_context(this, packet);
    let captured_generation = injection_generation();
    maybe_warmup_flush();
    capture_last_inbound_body(packet);
    maybe_fire_armed_selftest(packet);

    // Injection is driven per-source (each fabricated response dispatches itself
    // the moment it is ready); no sweep is needed on the inbound path.

    // RecvPkt dispatches synchronously. Keep rewritten bytes alive through the
    // original call, then restore Steam's owned payload before its caller
    // releases the CNetPacket.
    // SAFETY: packet is the live CNetPacket supplied by Steam's caller.
    let prepared = unsafe { crate::netpacket::prepare_recv_packet(packet) };
    let delivered = match prepared.decision {
        crate::netpacket::PreparedRecvDecision::Pass => {
            // SAFETY: forwarding this callback's unchanged object and packet pointers.
            unsafe { original(this, packet) };
            true
        }
        crate::netpacket::PreparedRecvDecision::Drop => false,
        crate::netpacket::PreparedRecvDecision::Rewrite(_guard) => {
            // SAFETY: forwarding this callback's unchanged object and rewritten packet bytes.
            unsafe { original(this, packet) };
            true
        }
    };
    if delivered {
        prepared.post_dispatch.complete();
    }
    // Packet routing can discover an account transition and invalidate the
    // context above. This same real packet is authoritative for the new context.
    if !context_captured || injection_generation() != captured_generation {
        capture_dispatch_context(this, packet);
        maybe_warmup_flush();
    }
}

// Work-item vtable. `#[repr(C)]` of 9 function pointers auto-scales to the
// per-arch slot spacing (4-byte on i386, 8-byte on x64); the execute callback is
// slot index 6 (i386 vtable+0x18, x64 vtable+0x30) either way.
#[repr(C)]
struct NativeProbeWorkItemVtable {
    destroy: unsafe extern "C" fn(*mut c_void),
    deleting_destroy: unsafe extern "C" fn(*mut c_void),
    pre_destroy: unsafe extern "C" fn(*mut c_void) -> bool,
    slot_3: unsafe extern "C" fn(*mut c_void) -> bool,
    slot_4: unsafe extern "C" fn(*mut c_void) -> bool,
    aux: unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool,
    execute: unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool,
    slot_7: unsafe extern "C" fn(*mut c_void) -> bool,
    slot_8: unsafe extern "C" fn(*mut c_void) -> bool,
}

fn original_recv_pkt_probe() -> Option<RecvPktFn> {
    // SAFETY: the detour slot is process-lifetime storage initialized by hook installation.
    unsafe {
        vapor_forge_hook_engine::original::original_detour(
            "CCMConnection::RecvPkt::packet-smoke",
            std::ptr::addr_of!(RECV_PKT_DETOUR),
        )
    }
}

// ---------------------------------------------------------------------------
// Production native dispatch: deliver fabricated responses on the WebSocket
// worker thread by constructing a real CNetPacket and posting a custom
// CWorkItem through AddWorkItem. Replaces the borrow-shell injection.
// ---------------------------------------------------------------------------

struct QueuedInjection {
    body: Vec<u8>,
    generation: u64,
    playtime_context: Option<super::playtime_downlink::RuntimeKey>,
    _cloud_permit: Option<vapor_forge_cloud_rpc::ResponsePermit>,
}

fn take_next_dispatchable(
    queue: &mut VecDeque<QueuedInjection>,
    generation: u64,
    current: Option<&super::playtime_downlink::RuntimeKey>,
) -> (Option<QueuedInjection>, usize) {
    let mut discarded = 0;
    while let Some(queued) = queue.pop_front() {
        if queued.generation == generation
            && queued
                .playtime_context
                .as_ref()
                .is_none_or(|context| Some(context) == current)
        {
            return (Some(queued), discarded);
        }
        discarded += 1;
    }
    (None, discarded)
}

fn injection_queue() -> &'static Mutex<VecDeque<QueuedInjection>> {
    INJECTION_QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DispatchContext {
    receiver: usize,
    conn_id: u32,
    recv_pthread: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveDispatch {
    generation: u64,
    pthread: usize,
}

struct DispatchState {
    generation: u64,
    context: Option<DispatchContext>,
    posted_generation: u64,
    active_dispatch: Option<ActiveDispatch>,
    transition_in_progress: bool,
    release_transition_on_idle: bool,
}

impl DispatchState {
    const fn new() -> Self {
        Self {
            generation: 1,
            context: None,
            posted_generation: 0,
            active_dispatch: None,
            transition_in_progress: false,
            release_transition_on_idle: false,
        }
    }
}

struct DispatchCoordinator {
    // Coordinator methods acquire this state before the injection queue.
    state: Mutex<DispatchState>,
    idle: Condvar,
    published_generation: AtomicU64,
}

struct TransitionOutcome {
    previous_generation: u64,
    discarded: VecDeque<QueuedInjection>,
}

struct CaptureOutcome {
    connection_changed: bool,
    published: bool,
    discarded: VecDeque<QueuedInjection>,
}

enum BeginDispatch<'a> {
    Stale,
    WrongThread {
        expected: usize,
    },
    Empty {
        discarded: usize,
    },
    Ready {
        context: DispatchContext,
        injection: QueuedInjection,
        discarded: usize,
        _lease: DispatchLease<'a>,
    },
}

struct DispatchLease<'a> {
    coordinator: &'a DispatchCoordinator,
    active: ActiveDispatch,
}

struct PostClaim<'a> {
    state: MutexGuard<'a, DispatchState>,
    generation: u64,
}

impl DispatchCoordinator {
    const fn new() -> Self {
        Self {
            state: Mutex::new(DispatchState::new()),
            idle: Condvar::new(),
            published_generation: AtomicU64::new(1),
        }
    }

    fn lock(&self) -> MutexGuard<'_, DispatchState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn current_generation(&self) -> u64 {
        self.published_generation.load(Ordering::Acquire)
    }

    fn generation_is_current(&self, generation: u64) -> bool {
        self.lock().generation == generation
    }

    fn context(&self) -> Option<DispatchContext> {
        let state = self.lock();
        (!state.transition_in_progress)
            .then_some(state.context)
            .flatten()
    }

    fn advance_generation(
        &self,
        state: &mut DispatchState,
        queue: &Mutex<VecDeque<QueuedInjection>>,
    ) -> TransitionOutcome {
        let previous_generation = state.generation;
        state.generation = next_injection_generation(previous_generation);
        state.posted_generation = 0;
        let discarded = {
            let mut queue = queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *queue)
        };
        TransitionOutcome {
            previous_generation,
            discarded,
        }
    }

    fn finish_transition(&self, state: &mut DispatchState, reentrant: bool) {
        if reentrant {
            state.release_transition_on_idle = true;
        } else {
            self.published_generation
                .store(state.generation, Ordering::Release);
            state.transition_in_progress = false;
            self.idle.notify_all();
        }
    }

    fn invalidate_generation(
        &self,
        expected_generation: Option<u64>,
        pthread: usize,
        queue: &Mutex<VecDeque<QueuedInjection>>,
    ) -> Option<TransitionOutcome> {
        let mut state = self.lock();
        while state.transition_in_progress {
            if state
                .active_dispatch
                .is_some_and(|active| active.pthread == pthread)
            {
                return None;
            }
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if expected_generation.is_some_and(|expected| state.generation != expected) {
            return None;
        }

        state.transition_in_progress = true;
        state.context = None;
        self.idle.notify_all();
        let reentrant = state
            .active_dispatch
            .is_some_and(|active| active.pthread == pthread);
        while state.active_dispatch.is_some() && !reentrant {
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }

        let outcome = self.advance_generation(&mut state, queue);
        self.finish_transition(&mut state, reentrant);
        Some(outcome)
    }

    fn capture(
        &self,
        context: DispatchContext,
        pthread: usize,
        observed_generation: u64,
        queue: &Mutex<VecDeque<QueuedInjection>>,
    ) -> CaptureOutcome {
        let mut state = self.lock();
        while state.transition_in_progress {
            if state
                .active_dispatch
                .is_some_and(|active| active.pthread == pthread)
            {
                return CaptureOutcome {
                    connection_changed: false,
                    published: false,
                    discarded: VecDeque::new(),
                };
            }
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if state.generation != observed_generation {
            return CaptureOutcome {
                connection_changed: false,
                published: false,
                discarded: VecDeque::new(),
            };
        }

        let connection_changed = state.context.is_some_and(|previous| {
            previous.receiver != context.receiver || previous.conn_id != context.conn_id
        });
        let mut discarded = VecDeque::new();
        if connection_changed {
            state.transition_in_progress = true;
            state.context = None;
            self.idle.notify_all();
            while state.active_dispatch.is_some() {
                if state
                    .active_dispatch
                    .is_some_and(|active| active.pthread == pthread)
                {
                    let outcome = self.advance_generation(&mut state, queue);
                    discarded = outcome.discarded;
                    self.finish_transition(&mut state, true);
                    return CaptureOutcome {
                        connection_changed: true,
                        published: false,
                        discarded,
                    };
                }
                state = self
                    .idle
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            discarded = self.advance_generation(&mut state, queue).discarded;
        }

        state.context = Some(context);
        if connection_changed {
            self.finish_transition(&mut state, false);
        }
        CaptureOutcome {
            connection_changed,
            published: true,
            discarded,
        }
    }

    fn enqueue_if_current(
        &self,
        queue: &Mutex<VecDeque<QueuedInjection>>,
        injection: QueuedInjection,
    ) -> Result<usize, QueuedInjection> {
        let state = self.lock();
        if state.transition_in_progress || injection.generation != state.generation {
            return Err(injection);
        }
        let mut queue = queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous_len = queue.len();
        queue.push_back(injection);
        Ok(previous_len)
    }

    fn claim_posted<'a>(
        &'a self,
        queue: &Mutex<VecDeque<QueuedInjection>>,
    ) -> Option<PostClaim<'a>> {
        let mut state = self.lock();
        if state.transition_in_progress || state.context.is_none() || state.posted_generation != 0 {
            return None;
        }
        if queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
        {
            return None;
        }
        let generation = state.generation;
        state.posted_generation = generation;
        Some(PostClaim { state, generation })
    }

    fn begin_dispatch<'a>(
        &'a self,
        queue: &Mutex<VecDeque<QueuedInjection>>,
        generation: u64,
        pthread: usize,
        current: Option<&super::playtime_downlink::RuntimeKey>,
    ) -> BeginDispatch<'a> {
        let mut state = self.lock();
        if state.transition_in_progress
            || state.generation != generation
            || state.posted_generation != generation
            || state.active_dispatch.is_some()
        {
            return BeginDispatch::Stale;
        }
        let Some(context) = state.context else {
            return BeginDispatch::Stale;
        };
        if context.recv_pthread != pthread {
            return BeginDispatch::WrongThread {
                expected: context.recv_pthread,
            };
        }

        let (injection, discarded) = {
            let mut queue = queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            take_next_dispatchable(&mut queue, generation, current)
        };
        let Some(injection) = injection else {
            return BeginDispatch::Empty { discarded };
        };
        let active = ActiveDispatch {
            generation,
            pthread,
        };
        state.active_dispatch = Some(active);
        BeginDispatch::Ready {
            context,
            injection,
            discarded,
            _lease: DispatchLease {
                coordinator: self,
                active,
            },
        }
    }

    fn disarm_posted(&self, generation: u64) -> bool {
        let mut state = self.lock();
        if state.posted_generation != generation {
            return false;
        }
        state.posted_generation = 0;
        true
    }

    #[cfg(test)]
    fn wait_for_transition(&self) {
        let mut state = self.lock();
        while !state.transition_in_progress {
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

impl Drop for DispatchLease<'_> {
    fn drop(&mut self) {
        let mut state = self.coordinator.lock();
        if state.active_dispatch != Some(self.active) {
            return;
        }
        state.active_dispatch = None;
        if state.release_transition_on_idle {
            state.release_transition_on_idle = false;
            self.coordinator
                .published_generation
                .store(state.generation, Ordering::Release);
            state.transition_in_progress = false;
        }
        self.coordinator.idle.notify_all();
    }
}

fn next_injection_generation(generation: u64) -> u64 {
    let next = generation.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

/// Refresh the native dispatch context from a real inbound packet.
pub(crate) fn capture_dispatch_context(this: *mut c_void, packet: *mut c_void) -> bool {
    if this.is_null() || packet.is_null() {
        return false;
    }
    let observed_generation = injection_generation();
    // SAFETY: packet is the live CNetPacket; its first field is the conn id.
    let conn_id = unsafe { *(packet as *const u32) };
    let pthread = current_pthread();
    let outcome = DISPATCH.capture(
        DispatchContext {
            receiver: this as usize,
            conn_id,
            recv_pthread: pthread,
        },
        pthread,
        observed_generation,
        injection_queue(),
    );
    if outcome.connection_changed {
        WARMUP_FLUSH_DONE.store(false, Ordering::Release);
        if !outcome.discarded.is_empty() {
            info!(
                discarded = outcome.discarded.len(),
                "native-inject: discarded responses from the old connection"
            );
        }
        if let Some(queue) = crate::netpacket::cloud_rpc_queue() {
            queue.cancel_pending_conflicts();
        }
        crate::netpacket::notify_stats_context_changed();
    }
    if !outcome.published {
        warn!("native-inject: ignored stale or recursive dispatch-context capture");
    }
    outcome.published
}

pub(crate) fn injection_generation() -> u64 {
    DISPATCH.current_generation()
}

/// Invalidate queued responses and require a fresh real packet before dispatch.
pub(crate) fn invalidate_injection_context() {
    let outcome = DISPATCH.invalidate_generation(None, current_pthread(), injection_queue());
    WARMUP_FLUSH_DONE.store(false, Ordering::Release);
    if let Some(outcome) = outcome {
        if !outcome.discarded.is_empty() {
            info!(
                discarded = outcome.discarded.len(),
                "native-inject: discarded responses from invalidated context"
            );
        }
        crate::netpacket::notify_stats_context_changed();
    }
}

fn dispatch_ready() -> bool {
    native_packet_functions_ready() && DISPATCH.context().is_some()
}

pub(crate) fn response_delivery_ready() -> bool {
    if !crate::capability::is_ready(crate::capability::Capability::NativeResponseDelivery)
        || !dispatch_ready()
    {
        return false;
    }
    let Some(site) = WORK_ITEM_SITE.get() else {
        return false;
    };
    // SAFETY: installation validates the pointer-aligned pool slot against the
    // live steamclient mapping before publishing WORK_ITEM_SITE.
    !unsafe { (site.pool_slot as *const *mut c_void).read() }.is_null()
}

fn terminate_dispatch_generation(generation: u64, reason: &'static str) {
    let Some(outcome) =
        DISPATCH.invalidate_generation(Some(generation), current_pthread(), injection_queue())
    else {
        info!(
            generation,
            reason, "native-inject: ignored stale work-item failure"
        );
        return;
    };
    warn!(
        generation,
        discarded = outcome.discarded.len(),
        reason,
        "native-inject: terminated connection generation"
    );
    WARMUP_FLUSH_DONE.store(false, Ordering::Release);
    if let Some(queue) = crate::netpacket::cloud_rpc_queue() {
        queue.cancel_pending_conflicts();
    }
    crate::netpacket::notify_stats_context_changed();
}

/// Queue a fabricated response and post a worker item to deliver it. If the
/// dispatch context is not captured yet, the body stays queued for a later post.
pub(crate) fn enqueue_injection(body: Vec<u8>) {
    enqueue_injection_for_generation(body, injection_generation());
}

pub(crate) fn enqueue_injection_for_generation(body: Vec<u8>, generation: u64) {
    enqueue(QueuedInjection {
        body,
        generation,
        playtime_context: None,
        _cloud_permit: None,
    });
}

pub(crate) fn enqueue_cloud_injection(response: vapor_forge_cloud_rpc::CompletedResponse) {
    let (body, generation, permit) = response.into_parts();
    enqueue(QueuedInjection {
        body,
        generation,
        playtime_context: None,
        _cloud_permit: Some(permit),
    });
}

pub(crate) fn enqueue_playtime_injection(
    body: Vec<u8>,
    context: super::playtime_downlink::RuntimeKey,
) {
    enqueue(QueuedInjection {
        body,
        generation: injection_generation(),
        playtime_context: Some(context),
        _cloud_permit: None,
    });
}

fn enqueue(injection: QueuedInjection) {
    let generation = injection.generation;
    let previous_len = match DISPATCH.enqueue_if_current(injection_queue(), injection) {
        Ok(previous_len) => previous_len,
        Err(_) => {
            info!(
                generation,
                current_generation = injection_generation(),
                "native-inject: discarded stale response before enqueue"
            );
            return;
        }
    };
    if previous_len >= MAX_QUEUED_INJECTIONS {
        warn!(
            queued = previous_len,
            "native-inject: queue exceeded its expected bound; retaining accepted responses"
        );
    }
    schedule_injection_drain();
}

/// Once dispatch context is fully captured, flush anything a source queued
/// during warmup (before dispatch was ready). One-shot; afterwards each source
/// dispatches itself via the injection router.
fn maybe_warmup_flush() {
    if WARMUP_FLUSH_DONE.load(Ordering::Acquire) || !dispatch_ready() {
        return;
    }
    if !WARMUP_FLUSH_DONE.swap(true, Ordering::AcqRel) {
        schedule_injection_drain();
    }
}

/// Hand one work item to the CNet pool. Steam's own post at the decoded site
/// calls `AddWorkItem` and returns, with no separate wake: the enqueue starts the
/// pool's threads and signals them itself.
fn schedule_injection_drain() {
    if !crate::capability::is_ready(crate::capability::Capability::NativeResponseDelivery) {
        return;
    }
    let Some(site) = WORK_ITEM_SITE.get() else {
        return;
    };
    let add_work_item_addr = ADD_WORK_ITEM_ADDR.load(Ordering::Acquire);
    if add_work_item_addr == 0
        || PACKET_ALLOC_ADDR.load(Ordering::Acquire) == 0
        || PACKET_INIT_ADDR.load(Ordering::Acquire) == 0
        || PACKET_RELEASE_ADDR.load(Ordering::Acquire) == 0
    {
        return;
    }

    // SAFETY: the slot was checked to be a pointer-aligned address inside a
    // steamclient mapping when the site was decoded.
    let pool = unsafe { (site.pool_slot as *const *mut c_void).read() };
    if pool.is_null() {
        // CNet has not published its pool yet; the next enqueue retries.
        return;
    }
    // SAFETY: address resolved inside steamclient.so via pattern; ABI matches.
    let add_work_item: WorkThreadPoolAddWorkItemFn =
        unsafe { std::mem::transmute(add_work_item_addr) };
    let Some(mut claim) = DISPATCH.claim_posted(injection_queue()) else {
        return;
    };
    let generation = claim.generation;
    let item = NativeWorkItem::allocate(site, generation);

    // Keep the lifecycle lock through Steam's ownership handoff. A completed
    // invalidation therefore cannot be followed by a late post for its old
    // generation.
    // SAFETY: pool is the CNet CWorkThreadPool; item is an ABI-shaped CWorkItem.
    let posted = unsafe { add_work_item(pool, item) };
    info!(
        posted,
        item = format_args!("{item:p}"),
        pool = format_args!("{pool:p}"),
        "native-inject: posted work item"
    );
    if !posted {
        // SAFETY: Steam rejected the item, so ownership never left us.
        unsafe { NativeWorkItem::free(item) };
        claim.state.transition_in_progress = true;
        claim.state.context = None;
        let outcome = DISPATCH.advance_generation(&mut claim.state, injection_queue());
        DISPATCH.finish_transition(&mut claim.state, false);
        debug_assert_eq!(outcome.previous_generation, generation);
        drop(claim);
        WARMUP_FLUSH_DONE.store(false, Ordering::Release);
        warn!(
            generation,
            discarded = outcome.discarded.len(),
            reason = "Steam rejected CNet work item",
            "native-inject: terminated connection generation"
        );
        if let Some(queue) = crate::netpacket::cloud_rpc_queue() {
            queue.cancel_pending_conflicts();
        }
    }
}

static NATIVE_INJECT_VTABLE: NativeProbeWorkItemVtable = NativeProbeWorkItemVtable {
    destroy: native_inject_noop,
    deleting_destroy: native_inject_deleting_destroy,
    pre_destroy: native_inject_true,
    slot_3: native_inject_true,
    slot_4: native_inject_true,
    aux: native_inject_slot_14,
    execute: native_inject_execute,
    slot_7: native_inject_true,
    slot_8: native_inject_true,
};

unsafe extern "C" fn native_inject_true(_item: *mut c_void) -> bool {
    true
}

/// Arch-generic CWorkItem: a zeroed buffer replaying the non-zero writes Steam's
/// own constructor makes, every one of them read back from the decoded site. Only
/// the vtable is ours; the rest is what Steam would have written itself.
struct NativeWorkItem;

impl NativeWorkItem {
    fn layout(size: usize) -> Layout {
        let allocation_size = size
            .checked_add(std::mem::size_of::<u64>())
            .expect("work item allocation size");
        // The size was range-checked at decode; align is a fixed power of two.
        Layout::from_size_align(allocation_size, WORK_ITEM_ALIGN).expect("work item layout")
    }

    fn allocate(site: &WorkItemSite, generation: u64) -> *mut c_void {
        // SAFETY: the layout has a non-zero size, checked when the site decoded.
        let base = unsafe { std::alloc::alloc_zeroed(Self::layout(site.item_size)) };
        if base.is_null() {
            std::alloc::handle_alloc_error(Self::layout(site.item_size));
        }
        // SAFETY: base owns item_size zeroed bytes, and every offset written here
        // was checked against item_size when the site decoded.
        unsafe {
            base.cast::<usize>()
                .write_unaligned(&NATIVE_INJECT_VTABLE as *const _ as usize);
            base.add(site.refcount_offset)
                .cast::<u32>()
                .write_unaligned(1);
            for &offset in &site.timer_vptr_offsets {
                base.add(offset)
                    .cast::<usize>()
                    .write_unaligned(site.timer_vtable);
            }
            for &(offset, width) in &site.sentinel_offsets {
                let field = base.add(offset);
                match width {
                    8 => field.cast::<u64>().write_unaligned(u64::MAX),
                    4 => field.cast::<u32>().write_unaligned(u32::MAX),
                    2 => field.cast::<u16>().write_unaligned(u16::MAX),
                    _ => field.write_unaligned(u8::MAX),
                }
            }
            // The ABI-visible object ends at item_size. This process-owned trailer
            // binds the completion to the connection that posted it.
            base.add(site.item_size)
                .cast::<u64>()
                .write_unaligned(generation);
        }
        base.cast::<c_void>()
    }

    /// # Safety
    /// `item` must be a pointer previously returned by [`NativeWorkItem::allocate`].
    unsafe fn generation(item: *mut c_void) -> u64 {
        let Some(site) = WORK_ITEM_SITE.get() else {
            return 0;
        };
        // SAFETY: allocate reserves and writes the trailer immediately after item_size.
        unsafe {
            item.cast::<u8>()
                .add(site.item_size)
                .cast::<u64>()
                .read_unaligned()
        }
    }

    /// # Safety
    /// `item` must be a pointer previously returned by [`NativeWorkItem::allocate`].
    unsafe fn free(item: *mut c_void) {
        let Some(site) = WORK_ITEM_SITE.get() else {
            return;
        };
        // SAFETY: caller guarantees item came from allocate(), whose layout is
        // derived from the same site.
        unsafe { std::alloc::dealloc(item.cast::<u8>(), Self::layout(site.item_size)) };
    }
}

/// Drop the caller-owned reference at the per-arch CWorkItem refcount offset.
fn release_inject_caller_ref(item: *mut c_void) {
    let Some(site) = WORK_ITEM_SITE.get() else {
        return;
    };
    let addr = (item as usize).wrapping_add(site.refcount_offset);
    let ref_count = addr as *const std::sync::atomic::AtomicU32;
    // SAFETY: item+refcount is the CWorkItem's u32 refcount, which the decode
    // admitted only as a 4-byte field, and the allocation is 16-byte aligned.
    unsafe { (*ref_count).fetch_sub(1, Ordering::AcqRel) };
}

unsafe extern "C" fn native_inject_noop(_item: *mut c_void) {}

unsafe extern "C" fn native_inject_slot_14(_item: *mut c_void, _arg: *mut c_void) -> bool {
    // Runs on a pool worker thread; never dispatch packets here.
    true
}

unsafe extern "C" fn native_inject_deleting_destroy(item: *mut c_void) {
    // Completion owns the post state; destruction can follow a newer post.
    // SAFETY: this slot is the ownership terminal for our allocation.
    unsafe { NativeWorkItem::free(item) };
}

/// Completion notify, called by `CWorkThreadPool::BFrameFuncHandleCompletedWorkItems`.
/// For the CNet pool that drain runs from `CNet::BFrameHandleCompletedWorkItems`,
/// on the same frame thread as `CNet::BFrameFuncPollConnections`, which is where
/// Steam delivers inbound packets. Returning true suppresses Steam's "job no
/// longer existed to notify" warning.
unsafe extern "C" fn native_inject_execute(item: *mut c_void, _arg: *mut c_void) -> bool {
    // SAFETY: Steam invokes this slot only for an item allocated above.
    let generation = unsafe { NativeWorkItem::generation(item) };
    let pthread = current_pthread();
    // Drop the caller-owned reference now that Steam's queue reference drives
    // destruction after this returns.
    release_inject_caller_ref(item);
    if generation == 0 {
        info!(
            generation,
            "native-inject: stale work item completed without dispatch"
        );
        return true;
    }
    match drain_injections(generation, pthread) {
        DrainResult::Complete => {
            info!(
                pthread = format_args!("0x{pthread:x}"),
                item = format_args!("{item:p}"),
                "native-inject: completion on the RecvPkt thread"
            );
        }
        DrainResult::Stale => {
            DISPATCH.disarm_posted(generation);
            info!(
                generation,
                "native-inject: stale work item completed without dispatch"
            );
            return true;
        }
        DrainResult::WrongThread { expected } => {
            // Calling RecvPkt off its own thread is what the whole native dispatch
            // exists to avoid, so leave the queue alone and say so.
            warn!(
                pthread = format_args!("0x{pthread:x}"),
                expected = format_args!("0x{expected:x}"),
                "native-inject: completion ran off the RecvPkt thread, skipping dispatch"
            );
            DISPATCH.disarm_posted(generation);
            terminate_dispatch_generation(
                generation,
                "CNet work item completed on the wrong thread",
            );
            return true;
        }
    }
    // Producers that raced the drain observed the armed state and left their
    // response queued. Disarm first, then publish one successor if needed.
    DISPATCH.disarm_posted(generation);
    if injection_generation() == generation {
        schedule_injection_drain();
    }
    true
}

enum DrainResult {
    Complete,
    Stale,
    WrongThread { expected: usize },
}

fn drain_injections(generation: u64, pthread: usize) -> DrainResult {
    let alloc_addr = PACKET_ALLOC_ADDR.load(Ordering::Acquire);
    let init_addr = PACKET_INIT_ADDR.load(Ordering::Acquire);
    let release_addr = PACKET_RELEASE_ADDR.load(Ordering::Acquire);
    if alloc_addr == 0 || init_addr == 0 || release_addr == 0 {
        return DrainResult::Stale;
    }
    let Some(recv_pkt) = original_recv_pkt_probe() else {
        return DrainResult::Stale;
    };
    // SAFETY: addresses resolved inside steamclient.so via pattern; ABIs match.
    let packet_alloc: PacketAllocFn = unsafe { std::mem::transmute(alloc_addr) };
    // SAFETY: addresses resolved inside steamclient.so via pattern; ABIs match.
    let packet_init: PacketInitFn = unsafe { std::mem::transmute(init_addr) };
    // SAFETY: addresses resolved inside steamclient.so via pattern; ABIs match.
    let packet_release: PacketReleaseFn = unsafe { std::mem::transmute(release_addr) };

    loop {
        let current = super::playtime_downlink::current_runtime_key();
        let (context, mut queued, discarded, _lease) =
            match DISPATCH.begin_dispatch(injection_queue(), generation, pthread, current.as_ref())
            {
                BeginDispatch::Stale => return DrainResult::Stale,
                BeginDispatch::WrongThread { expected } => {
                    return DrainResult::WrongThread { expected };
                }
                BeginDispatch::Empty { discarded } => {
                    if discarded != 0 {
                        info!(
                            discarded,
                            "native-inject: discarded stale playtime notifications"
                        );
                    }
                    return DrainResult::Complete;
                }
                BeginDispatch::Ready {
                    context,
                    injection,
                    discarded,
                    _lease,
                } => (context, injection, discarded, _lease),
            };
        if discarded != 0 {
            info!(
                discarded,
                "native-inject: discarded stale playtime notifications"
            );
        }
        if queued.body.is_empty() {
            continue;
        }
        let ptr = queued.body.as_mut_ptr();
        let len = queued.body.len() as u32;
        // SAFETY: PacketAlloc yields a fresh CNetPacket; body stays alive across
        // the synchronous RecvPkt dispatch and owned_data is null, so Steam does
        // not free it.
        let packet = unsafe { packet_alloc() };
        if packet.is_null() {
            warn!("native-inject: packet allocation failed");
            terminate_dispatch_generation(generation, "CNetPacket allocation failed");
            return DrainResult::Stale;
        }
        if !DISPATCH.generation_is_current(generation) {
            // A same-thread hook may invalidate reentrantly while allocation is
            // running. External invalidation remains blocked by the lease.
            // SAFETY: packet is live and has not been handed to RecvPkt.
            unsafe { packet_release(packet) };
            return DrainResult::Stale;
        }
        // SAFETY: packet is live; conn_id is a real connection id; body outlives
        // the synchronous dispatch below.
        unsafe { packet_init(packet, context.conn_id, ptr, len, std::ptr::null_mut(), 1) };
        if !DISPATCH.generation_is_current(generation) {
            // Do not enter the old receiver if PacketInit caused a reentrant
            // account or connection transition on this thread.
            // SAFETY: packet remains live and RecvPkt has not taken ownership.
            unsafe { packet_release(packet) };
            return DrainResult::Stale;
        }
        // SAFETY: the lease keeps this context valid through the synchronous call.
        unsafe { recv_pkt(context.receiver as *mut c_void, packet) };
        let owned_after = read_word_at(
            packet,
            vapor_forge_steam_native_abi::cnet_packet::OWNED_DATA_OFFSET,
        );
        info!(
            conn_id = format_args!("0x{:x}", context.conn_id),
            len,
            packet = format_args!("{packet:p}"),
            owned_after = %format_optional_word(owned_after),
            "native-inject: dispatched packet"
        );
        // SAFETY: release the packet after synchronous dispatch has finished.
        unsafe { packet_release(packet) };
    }
}

/// Arm a one-shot native-dispatch self-test. Called from the debug socket. The
/// next inbound packet, once dispatch context is ready, is replayed once through
/// the production injection path. Returns whether dispatch is already ready.
///
/// Gated with `debug_api`, its only caller.
#[cfg(any(debug_assertions, test))]
pub(crate) fn arm_native_inject_selftest() -> bool {
    NATIVE_INJECT_ARMED.store(true, Ordering::Release);
    dispatch_ready()
}

/// If armed and dispatch is ready, replay this inbound packet's body once through
/// the production dispatch, then disarm. Arch-generic (reads the CNetPacket slots).
fn maybe_fire_armed_selftest(packet: *mut c_void) {
    if !NATIVE_INJECT_ARMED.load(Ordering::Acquire) || packet.is_null() || !dispatch_ready() {
        return;
    }
    // SAFETY: packet is the live CNetPacket supplied to the RecvPkt hook.
    let data = unsafe { *vapor_forge_steam_native_abi::cnet_packet::data_slot(packet) };
    // SAFETY: same live CNetPacket.
    let size = unsafe { *vapor_forge_steam_native_abi::cnet_packet::size_slot(packet) };
    if data.is_null() || size == 0 || size as usize > 1024 * 1024 {
        // Stay armed until a packet with a usable body arrives.
        return;
    }
    if !NATIVE_INJECT_ARMED.swap(false, Ordering::AcqRel) {
        // Another RecvPkt already claimed the armed shot.
        return;
    }
    // SAFETY: data points to `size` bytes for this dispatch.
    let body = unsafe { std::slice::from_raw_parts(data, size as usize) }.to_vec();
    let context = DISPATCH.context();
    info!(
        len = body.len(),
        conn_id = format_args!("0x{:x}", context.map_or(0, |context| context.conn_id)),
        recv_pthread = format_args!("0x{:x}", context.map_or(0, |context| context.recv_pthread)),
        "native-inject: self-test replaying one inbound packet through dispatch"
    );
    enqueue_injection(body);
}

/// Capture one real inbound body (once) for the own-thread dispatch test. Gated
/// by an atomic so the hot RecvPkt path pays only a load after the first capture.
fn capture_last_inbound_body(packet: *mut c_void) {
    if LAST_INBOUND_CAPTURED.load(Ordering::Acquire) || packet.is_null() {
        return;
    }
    // SAFETY: packet is the live CNetPacket supplied to the RecvPkt hook.
    let data = unsafe { *vapor_forge_steam_native_abi::cnet_packet::data_slot(packet) };
    // SAFETY: same live CNetPacket.
    let size = unsafe { *vapor_forge_steam_native_abi::cnet_packet::size_slot(packet) };
    if data.is_null() || size == 0 || size as usize > 1024 * 1024 {
        return;
    }
    // SAFETY: data points to `size` bytes for the duration of this hook call.
    let body = unsafe { std::slice::from_raw_parts(data, size as usize) }.to_vec();
    *LAST_INBOUND_BODY.lock().unwrap() = Some(body);
    LAST_INBOUND_CAPTURED.store(true, Ordering::Release);
}

/// Test the active-dispatch path from a thread we own: replay one captured
/// inbound body from a freshly spawned thread (not RecvPkt, not a pool worker).
/// Validates that AddWorkItem alone drives delivery while the CM connection is
/// idle, which is the prerequisite for pumping injections off the RecvPkt
/// cadence. Returns a status line for the debug socket.
///
/// Gated with `debug_api`, its only caller.
#[cfg(any(debug_assertions, test))]
pub(crate) fn spawn_own_thread_dispatch_test() -> String {
    if !dispatch_ready() {
        return "err dispatch context not ready (needs a prior inbound packet)".to_owned();
    }
    let body = match LAST_INBOUND_BODY.lock().unwrap().clone() {
        Some(body) => body,
        None => {
            return "err no captured inbound body yet (waiting for first inbound packet)".to_owned()
        }
    };
    let len = body.len();
    let spawned = std::thread::Builder::new()
        .name("vf-inject-test".to_owned())
        .spawn(move || {
            info!(
                len = body.len(),
                pthread = format_args!("0x{:x}", current_pthread()),
                "native-inject: OWN-THREAD dispatch test enqueuing (no RecvPkt)"
            );
            enqueue_injection(body);
        })
        .is_ok();
    if !spawned {
        return "err failed to spawn dispatch thread".to_owned();
    }
    format!("ok spawned own-thread dispatch of {len}B; watch logs for execute + dispatched")
}

fn read_aligned_word(ptr: *mut c_void) -> Option<usize> {
    let addr = ptr as usize;
    if addr == 0 || addr & (std::mem::align_of::<usize>() - 1) != 0 {
        return None;
    }
    // SAFETY: used only for Steam-owned hook arguments at the point Steam passed them in.
    Some(unsafe { *(addr as *const usize) })
}

fn read_word_at(base: *mut c_void, offset: usize) -> Option<usize> {
    read_aligned_word(base.wrapping_add(offset))
}

fn format_optional_word(value: Option<usize>) -> String {
    value.map_or_else(|| "unreadable".to_owned(), |value| format!("0x{value:x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};

    fn key(
        credential_fingerprint: &str,
        steam_id64: u64,
        identity_generation: u64,
        client_id: u64,
        runtime_generation: u64,
    ) -> super::super::playtime_downlink::RuntimeKey {
        super::super::playtime_downlink::runtime_key(
            credential_fingerprint.to_owned(),
            steam_id64,
            identity_generation,
            client_id,
            runtime_generation,
        )
    }

    fn playtime(body: u8, context: super::super::playtime_downlink::RuntimeKey) -> QueuedInjection {
        QueuedInjection {
            body: vec![body],
            generation: 7,
            playtime_context: Some(context),
            _cloud_permit: None,
        }
    }

    fn ordinary(body: u8, generation: u64) -> QueuedInjection {
        QueuedInjection {
            body: vec![body],
            generation,
            playtime_context: None,
            _cloud_permit: None,
        }
    }

    fn context(receiver: usize, conn_id: u32, recv_pthread: usize) -> DispatchContext {
        DispatchContext {
            receiver,
            conn_id,
            recv_pthread,
        }
    }

    #[test]
    fn queued_playtime_is_discarded_across_every_runtime_boundary() {
        let current = key("credential-a", 76_561_198_000_000_001, 4, 7, 9);
        let mut queue = VecDeque::from([
            playtime(1, key("credential-b", current.steam_id64, 4, 7, 9)),
            playtime(2, key("credential-a", 76_561_198_000_000_002, 4, 7, 9)),
            playtime(3, key("credential-a", current.steam_id64, 5, 7, 9)),
            playtime(4, key("credential-a", current.steam_id64, 4, 8, 9)),
            playtime(7, key("credential-a", current.steam_id64, 4, 7, 10)),
            QueuedInjection {
                body: vec![5],
                generation: 7,
                playtime_context: None,
                _cloud_permit: None,
            },
            playtime(6, current.clone()),
        ]);

        let (ordinary, discarded) = take_next_dispatchable(&mut queue, 7, Some(&current));
        assert_eq!(discarded, 5);
        assert_eq!(ordinary.unwrap().body, vec![5]);

        let (current_playtime, discarded) = take_next_dispatchable(&mut queue, 7, Some(&current));
        assert_eq!(discarded, 0);
        assert_eq!(current_playtime.unwrap().body, vec![6]);
        assert!(queue.is_empty());
    }

    #[test]
    fn queued_playtime_is_discarded_when_backend_is_disabled() {
        let mut queue = VecDeque::from([playtime(
            1,
            key("credential-a", 76_561_198_000_000_001, 4, 7, 9),
        )]);

        let (queued, discarded) = take_next_dispatchable(&mut queue, 7, None);
        assert!(queued.is_none());
        assert_eq!(discarded, 1);
    }

    #[test]
    fn queued_response_is_discarded_after_connection_generation_changes() {
        let mut queue = VecDeque::from([QueuedInjection {
            body: vec![1],
            generation: 6,
            playtime_context: None,
            _cloud_permit: None,
        }]);

        let (queued, discarded) = take_next_dispatchable(&mut queue, 7, None);
        assert!(queued.is_none());
        assert_eq!(discarded, 1);
    }

    #[test]
    fn stale_work_item_cannot_disarm_the_current_generation() {
        let coordinator = DispatchCoordinator::new();
        let queue = Mutex::new(VecDeque::new());
        assert!(
            coordinator
                .capture(context(1, 10, 100), 100, 1, &queue)
                .published
        );
        assert!(coordinator
            .enqueue_if_current(&queue, ordinary(1, 1))
            .is_ok());
        let old_claim = coordinator.claim_posted(&queue).unwrap();
        assert_eq!(old_claim.generation, 1);
        drop(old_claim);

        let invalidated = coordinator
            .invalidate_generation(None, 200, &queue)
            .unwrap();
        assert_eq!(invalidated.previous_generation, 1);
        assert!(coordinator
            .enqueue_if_current(&queue, ordinary(9, 1))
            .is_err());
        assert!(
            coordinator
                .capture(context(2, 20, 200), 200, 2, &queue)
                .published
        );
        assert!(coordinator
            .enqueue_if_current(&queue, ordinary(2, 2))
            .is_ok());
        let new_claim = coordinator.claim_posted(&queue).unwrap();
        assert_eq!(new_claim.generation, 2);
        drop(new_claim);

        assert!(!coordinator.disarm_posted(1));
        assert_eq!(coordinator.lock().posted_generation, 2);
        assert!(coordinator.disarm_posted(2));
    }

    #[test]
    fn invalidation_waits_for_a_dequeued_dispatch_to_finish() {
        let coordinator = Arc::new(DispatchCoordinator::new());
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        assert!(
            coordinator
                .capture(context(1, 10, 100), 100, 1, &queue)
                .published
        );
        assert!(coordinator
            .enqueue_if_current(&queue, ordinary(1, 1))
            .is_ok());
        drop(coordinator.claim_posted(&queue).unwrap());
        let lease = match coordinator.begin_dispatch(&queue, 1, 100, None) {
            BeginDispatch::Ready { _lease, .. } => _lease,
            _ => panic!("dispatch did not start"),
        };

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_coordinator = Arc::clone(&coordinator);
        let worker_queue = Arc::clone(&queue);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let outcome = worker_coordinator
                .invalidate_generation(None, 200, &worker_queue)
                .unwrap();
            done_tx.send(outcome.previous_generation).unwrap();
        });
        started_rx.recv().unwrap();
        coordinator.wait_for_transition();
        assert!(done_rx.try_recv().is_err());
        assert!(coordinator.context().is_none());
        assert_eq!(coordinator.current_generation(), 1);

        drop(lease);
        assert_eq!(done_rx.recv().unwrap(), 1);
        worker.join().unwrap();
        assert_eq!(coordinator.current_generation(), 2);
    }

    #[test]
    fn connection_replacement_waits_for_a_dequeued_dispatch_to_finish() {
        let coordinator = Arc::new(DispatchCoordinator::new());
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let old = context(1, 10, 100);
        let new = context(2, 20, 200);
        assert!(coordinator.capture(old, 100, 1, &queue).published);
        assert!(coordinator
            .enqueue_if_current(&queue, ordinary(1, 1))
            .is_ok());
        drop(coordinator.claim_posted(&queue).unwrap());
        let lease = match coordinator.begin_dispatch(&queue, 1, 100, None) {
            BeginDispatch::Ready { _lease, .. } => _lease,
            _ => panic!("dispatch did not start"),
        };

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_coordinator = Arc::clone(&coordinator);
        let worker_queue = Arc::clone(&queue);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let outcome = worker_coordinator.capture(new, 200, 1, &worker_queue);
            done_tx
                .send((outcome.connection_changed, outcome.published))
                .unwrap();
        });
        started_rx.recv().unwrap();
        coordinator.wait_for_transition();
        assert!(done_rx.try_recv().is_err());
        assert!(coordinator.context().is_none());
        assert_eq!(coordinator.current_generation(), 1);

        drop(lease);
        assert_eq!(done_rx.recv().unwrap(), (true, true));
        worker.join().unwrap();
        assert_eq!(coordinator.current_generation(), 2);
        assert_eq!(coordinator.context(), Some(new));
    }

    #[test]
    fn reentrant_invalidation_is_released_after_dispatch_returns() {
        let coordinator = DispatchCoordinator::new();
        let queue = Mutex::new(VecDeque::new());
        assert!(
            coordinator
                .capture(context(1, 10, 100), 100, 1, &queue)
                .published
        );
        assert!(coordinator
            .enqueue_if_current(&queue, ordinary(1, 1))
            .is_ok());
        drop(coordinator.claim_posted(&queue).unwrap());
        let lease = match coordinator.begin_dispatch(&queue, 1, 100, None) {
            BeginDispatch::Ready { _lease, .. } => _lease,
            _ => panic!("dispatch did not start"),
        };

        let outcome = coordinator
            .invalidate_generation(None, 100, &queue)
            .unwrap();
        assert_eq!(outcome.previous_generation, 1);
        assert!(coordinator.lock().transition_in_progress);
        assert!(coordinator.context().is_none());
        assert_eq!(coordinator.current_generation(), 1);

        drop(lease);
        assert!(!coordinator.lock().transition_in_progress);
        assert_eq!(coordinator.current_generation(), 2);
    }

    #[test]
    fn invalidation_does_not_publish_the_old_connection_in_the_new_generation() {
        let coordinator = DispatchCoordinator::new();
        let queue = Mutex::new(VecDeque::new());
        let old = context(1, 10, 100);
        let new = context(2, 20, 200);
        assert!(coordinator.capture(old, 100, 1, &queue).published);

        coordinator
            .invalidate_generation(None, 200, &queue)
            .unwrap();
        assert_eq!(coordinator.current_generation(), 2);
        assert!(coordinator.context().is_none());
        assert!(!coordinator.capture(old, 100, 1, &queue).published);
        assert!(coordinator.context().is_none());

        assert!(coordinator.capture(new, 200, 2, &queue).published);
        assert_eq!(coordinator.context(), Some(new));
    }

    #[test]
    fn enqueue_between_empty_drain_and_disarm_gets_a_successor_post() {
        let coordinator = DispatchCoordinator::new();
        let queue = Mutex::new(VecDeque::new());
        assert!(
            coordinator
                .capture(context(1, 10, 100), 100, 1, &queue)
                .published
        );
        assert!(coordinator
            .enqueue_if_current(&queue, ordinary(1, 1))
            .is_ok());
        let current_claim = coordinator.claim_posted(&queue).unwrap();
        queue.lock().unwrap().clear();
        drop(current_claim);

        assert!(coordinator
            .enqueue_if_current(&queue, ordinary(2, 1))
            .is_ok());
        assert!(coordinator.disarm_posted(1));
        let successor = coordinator.claim_posted(&queue).unwrap();
        assert_eq!(successor.generation, 1);
    }

    #[test]
    fn connection_generation_never_uses_the_unarmed_value() {
        assert_eq!(next_injection_generation(u64::MAX), 1);
        assert_eq!(next_injection_generation(7), 8);
    }
}
