use core::ffi::c_void;
use std::alloc::Layout;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

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
// The CCMConnection captured from RecvPkt (the receiver we dispatch onto).
static CM_RECEIVER: AtomicUsize = AtomicUsize::new(0);
// The thread RecvPkt is delivered on, so dispatch can refuse to run anywhere else.
static RECV_PTHREAD: AtomicUsize = AtomicUsize::new(0);
// The connection id read from a real incoming packet's first field.
static CM_CONN_ID: AtomicUsize = AtomicUsize::new(0);
static CM_CONN_ID_SET: AtomicBool = AtomicBool::new(false);
// Every fabricated response is bound to the connection/account context in
// which its request was accepted. A reconnect or context reset invalidates it.
static INJECTION_GENERATION: AtomicU64 = AtomicU64::new(1);
// One-shot native-dispatch self-test, armed from the debug socket.
static NATIVE_INJECT_ARMED: AtomicBool = AtomicBool::new(false);
// One-shot flush of anything a source queued before dispatch context was ready.
static WARMUP_FLUSH_DONE: AtomicBool = AtomicBool::new(false);
static WORK_ITEM_POSTED: AtomicBool = AtomicBool::new(false);
// One real inbound body, captured once, replayed by the own-thread dispatch test
// (a safe payload Steam has already handled). Gated by the atomic so the hot path
// pays only an atomic load once captured.
static LAST_INBOUND_CAPTURED: AtomicBool = AtomicBool::new(false);
static LAST_INBOUND_BODY: Mutex<Option<Vec<u8>>> = Mutex::new(None);

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
    if opcode == WEBSOCKET_BINARY && !data.is_null() && size > 0 {
        // SAFETY: data is a valid buffer of `size` bytes, provided by Steam.
        let slice = unsafe { std::slice::from_raw_parts(data, size as usize) };

        match crate::netpacket::decide_send_frame(slice) {
            SendFrameDecision::Pass => {}
            SendFrameDecision::Drop => return true,
            SendFrameDecision::Retry => return false,
            SendFrameDecision::Rewrite(rewritten) => {
                // SAFETY: calling original with rewritten data.
                let original =
                    detour_or_return!("BBuildAndAsyncSendFrame", SEND_FRAME_DETOUR, false);
                return // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(
                    this,
                    opcode,
                    rewritten.as_ptr() as *mut u8,
                    rewritten.len() as u32,
                ) };
            }
        }
    }

    // SAFETY: SEND_FRAME_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("BBuildAndAsyncSendFrame", SEND_FRAME_DETOUR, false);
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(this, opcode, data, size) }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: RecvPkt (incoming packets)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_recv_pkt(this: *mut c_void, packet: *mut c_void) {
    // One-shot capture of the receiver / conn id for native dispatch (worker_this
    // comes from the post-item hook).
    capture_dispatch_context(this, packet);
    maybe_warmup_flush();
    post_injection();
    capture_last_inbound_body(packet);
    maybe_fire_armed_selftest(packet);

    // SAFETY: RECV_PKT_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("RecvPkt", RECV_PKT_DETOUR);

    // Injection is driven per-source (each fabricated response dispatches itself
    // the moment it is ready); no sweep is needed on the inbound path.

    // RecvPkt dispatches synchronously. Keep rewritten bytes alive through the
    // original call, then restore Steam's owned payload before its caller
    // releases the CNetPacket.
    // SAFETY: packet is the live CNetPacket supplied by Steam's caller.
    match unsafe { crate::netpacket::prepare_recv_packet(packet) } {
        crate::netpacket::PreparedRecvPacket::Pass => {
            // SAFETY: forwarding this callback's unchanged object and packet pointers.
            unsafe { original(this, packet) };
        }
        crate::netpacket::PreparedRecvPacket::Drop => {}
        crate::netpacket::PreparedRecvPacket::Rewrite(_guard) => {
            // SAFETY: forwarding this callback's unchanged object and rewritten packet bytes.
            unsafe { original(this, packet) };
        }
    }
    // Packet routing can discover an account transition and invalidate the
    // context above. This same real packet is authoritative for the new context.
    capture_dispatch_context(this, packet);
    maybe_warmup_flush();
    post_injection();
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

/// Refresh the native dispatch context from a real inbound packet.
pub(crate) fn capture_dispatch_context(this: *mut c_void, packet: *mut c_void) {
    if this.is_null() || packet.is_null() {
        return;
    }
    let receiver = this as usize;
    // SAFETY: packet is the live CNetPacket; its first field is the conn id.
    let conn_id = unsafe { *(packet as *const u32) } as usize;
    let previous_receiver = CM_RECEIVER.load(Ordering::Acquire);
    let previous_conn_set = CM_CONN_ID_SET.load(Ordering::Acquire);
    let previous_conn_id = CM_CONN_ID.load(Ordering::Acquire);
    let connection_changed = (previous_receiver != 0 && previous_receiver != receiver)
        || (previous_conn_set && previous_conn_id != conn_id);
    if connection_changed {
        INJECTION_GENERATION.fetch_add(1, Ordering::AcqRel);
        WARMUP_FLUSH_DONE.store(false, Ordering::Release);
        if let Some(queue) = crate::netpacket::cloud_rpc_queue() {
            queue.cancel_pending_conflicts();
        }
    }
    CM_RECEIVER.store(receiver, Ordering::Release);
    CM_CONN_ID.store(conn_id, Ordering::Release);
    CM_CONN_ID_SET.store(true, Ordering::Release);
    // A reconnect can move delivery to a different thread.
    RECV_PTHREAD.store(current_pthread(), Ordering::Release);
}

pub(crate) fn injection_generation() -> u64 {
    INJECTION_GENERATION.load(Ordering::Acquire)
}

/// Invalidate queued responses and require a fresh real packet before dispatch.
pub(crate) fn invalidate_injection_context() {
    INJECTION_GENERATION.fetch_add(1, Ordering::AcqRel);
    CM_RECEIVER.store(0, Ordering::Release);
    CM_CONN_ID_SET.store(false, Ordering::Release);
    RECV_PTHREAD.store(0, Ordering::Release);
    WARMUP_FLUSH_DONE.store(false, Ordering::Release);
    WORK_ITEM_POSTED.store(false, Ordering::Release);
}

fn dispatch_ready() -> bool {
    WORK_ITEM_SITE.get().is_some()
        && CM_RECEIVER.load(Ordering::Acquire) != 0
        && CM_CONN_ID_SET.load(Ordering::Acquire)
        && ADD_WORK_ITEM_ADDR.load(Ordering::Acquire) != 0
        && PACKET_ALLOC_ADDR.load(Ordering::Acquire) != 0
        && PACKET_INIT_ADDR.load(Ordering::Acquire) != 0
        && PACKET_RELEASE_ADDR.load(Ordering::Acquire) != 0
}

pub(crate) fn response_delivery_ready() -> bool {
    if !dispatch_ready() || RECV_PTHREAD.load(Ordering::Acquire) == 0 {
        return false;
    }
    let Some(site) = WORK_ITEM_SITE.get() else {
        return false;
    };
    // SAFETY: installation validates the pointer-aligned pool slot against the
    // live steamclient mapping before publishing WORK_ITEM_SITE.
    !unsafe { (site.pool_slot as *const *mut c_void).read() }.is_null()
}

fn terminate_dispatch_generation(reason: &'static str) {
    let discarded = {
        let mut queue = injection_queue().lock().unwrap();
        let discarded = queue.len();
        queue.clear();
        discarded
    };
    warn!(
        discarded,
        reason, "native-inject: terminated connection generation"
    );
    invalidate_injection_context();
    if let Some(queue) = crate::netpacket::cloud_rpc_queue() {
        queue.cancel_pending_conflicts();
    }
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
    {
        let mut queue = injection_queue().lock().unwrap();
        if queue.len() >= MAX_QUEUED_INJECTIONS {
            warn!(
                queued = queue.len(),
                "native-inject: queue exceeded its expected bound; retaining accepted responses"
            );
        }
        queue.push_back(injection);
    }
    post_injection();
}

/// Once dispatch context is fully captured, flush anything a source queued
/// during warmup (before dispatch was ready). One-shot; afterwards each source
/// dispatches itself via the injection router.
fn maybe_warmup_flush() {
    if WARMUP_FLUSH_DONE.load(Ordering::Acquire) || !dispatch_ready() {
        return;
    }
    if !WARMUP_FLUSH_DONE.swap(true, Ordering::AcqRel) {
        post_injection();
    }
}

/// Hand one work item to the CNet pool. Steam's own post at the decoded site
/// calls `AddWorkItem` and returns, with no separate wake: the enqueue starts the
/// pool's threads and signals them itself.
fn post_injection() {
    if !dispatch_ready() {
        return;
    }
    if injection_queue().lock().unwrap().is_empty() {
        return;
    }
    if WORK_ITEM_POSTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let Some(site) = WORK_ITEM_SITE.get() else {
        WORK_ITEM_POSTED.store(false, Ordering::Release);
        return;
    };
    // SAFETY: the slot was checked to be a pointer-aligned address inside a
    // steamclient mapping when the site was decoded.
    let pool = unsafe { (site.pool_slot as *const *mut c_void).read() };
    if pool.is_null() {
        // CNet has not published its pool yet; the next enqueue retries.
        WORK_ITEM_POSTED.store(false, Ordering::Release);
        return;
    }
    // SAFETY: address resolved inside steamclient.so via pattern; ABI matches.
    let add_work_item: WorkThreadPoolAddWorkItemFn =
        unsafe { std::mem::transmute(ADD_WORK_ITEM_ADDR.load(Ordering::Acquire)) };
    let item = NativeWorkItem::allocate(site);

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
        WORK_ITEM_POSTED.store(false, Ordering::Release);
        terminate_dispatch_generation("Steam rejected CNet work item");
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
        // The size was range-checked at decode; align is a fixed power of two.
        Layout::from_size_align(size, WORK_ITEM_ALIGN).expect("work item layout")
    }

    fn allocate(site: &WorkItemSite) -> *mut c_void {
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
        }
        base.cast::<c_void>()
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
    WORK_ITEM_POSTED.store(false, Ordering::Release);
    // SAFETY: this slot is the ownership terminal for our allocation.
    unsafe { NativeWorkItem::free(item) };
}

/// Completion notify, called by `CWorkThreadPool::BFrameFuncHandleCompletedWorkItems`.
/// For the CNet pool that drain runs from `CNet::BFrameHandleCompletedWorkItems`,
/// on the same frame thread as `CNet::BFrameFuncPollConnections`, which is where
/// Steam delivers inbound packets. Returning true suppresses Steam's "job no
/// longer existed to notify" warning.
unsafe extern "C" fn native_inject_execute(item: *mut c_void, _arg: *mut c_void) -> bool {
    WORK_ITEM_POSTED.store(false, Ordering::Release);
    let pthread = current_pthread();
    // Drop the caller-owned reference now that Steam's queue reference drives
    // destruction after this returns.
    release_inject_caller_ref(item);
    let expected = RECV_PTHREAD.load(Ordering::Acquire);
    if pthread != expected {
        // Calling RecvPkt off its own thread is what the whole native dispatch
        // exists to avoid, so leave the queue alone and say so.
        warn!(
            pthread = format_args!("0x{pthread:x}"),
            expected = format_args!("0x{expected:x}"),
            "native-inject: completion ran off the RecvPkt thread, skipping dispatch"
        );
        terminate_dispatch_generation("CNet work item completed on the wrong thread");
        return true;
    }
    info!(
        pthread = format_args!("0x{pthread:x}"),
        item = format_args!("{item:p}"),
        "native-inject: completion on the RecvPkt thread"
    );
    drain_injections();
    true
}

fn drain_injections() {
    let receiver = CM_RECEIVER.load(Ordering::Acquire);
    let conn_id = CM_CONN_ID.load(Ordering::Acquire) as u32;
    let alloc_addr = PACKET_ALLOC_ADDR.load(Ordering::Acquire);
    let init_addr = PACKET_INIT_ADDR.load(Ordering::Acquire);
    let release_addr = PACKET_RELEASE_ADDR.load(Ordering::Acquire);
    if receiver == 0 || alloc_addr == 0 || init_addr == 0 || release_addr == 0 {
        return;
    }
    let Some(recv_pkt) = original_recv_pkt_probe() else {
        return;
    };
    // SAFETY: addresses resolved inside steamclient.so via pattern; ABIs match.
    let packet_alloc: PacketAllocFn = unsafe { std::mem::transmute(alloc_addr) };
    // SAFETY: addresses resolved inside steamclient.so via pattern; ABIs match.
    let packet_init: PacketInitFn = unsafe { std::mem::transmute(init_addr) };
    // SAFETY: addresses resolved inside steamclient.so via pattern; ABIs match.
    let packet_release: PacketReleaseFn = unsafe { std::mem::transmute(release_addr) };

    loop {
        let current = super::playtime_downlink::current_runtime_key();
        let generation = injection_generation();
        let (queued, discarded) = take_next_dispatchable(
            &mut injection_queue().lock().unwrap(),
            generation,
            current.as_ref(),
        );
        if discarded != 0 {
            info!(
                discarded,
                "native-inject: discarded stale playtime notifications"
            );
        }
        let Some(mut queued) = queued else {
            break;
        };
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
            injection_queue().lock().unwrap().push_front(queued);
            warn!("native-inject: packet allocation failed; response retained");
            break;
        }
        // SAFETY: packet is live; conn_id is a real connection id; body outlives
        // the synchronous dispatch below.
        unsafe {
            packet_init(packet, conn_id, ptr, len, std::ptr::null_mut(), 1);
            recv_pkt(receiver as *mut c_void, packet);
        }
        let owned_after = read_word_at(
            packet,
            vapor_forge_steam_native_abi::cnet_packet::OWNED_DATA_OFFSET,
        );
        info!(
            conn_id = format_args!("0x{conn_id:x}"),
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
    info!(
        len = body.len(),
        conn_id = format_args!("0x{:x}", CM_CONN_ID.load(Ordering::Acquire)),
        recv_pthread = format_args!("0x{:x}", RECV_PTHREAD.load(Ordering::Acquire)),
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

    fn key(
        credential_fingerprint: &str,
        steam_id64: u64,
        identity_generation: u64,
        client_id: u64,
    ) -> super::super::playtime_downlink::RuntimeKey {
        super::super::playtime_downlink::runtime_key(
            credential_fingerprint.to_owned(),
            steam_id64,
            identity_generation,
            client_id,
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

    #[test]
    fn queued_playtime_is_discarded_across_every_runtime_boundary() {
        let current = key("credential-a", 76_561_198_000_000_001, 4, 7);
        let mut queue = VecDeque::from([
            playtime(1, key("credential-b", current.steam_id64, 4, 7)),
            playtime(2, key("credential-a", 76_561_198_000_000_002, 4, 7)),
            playtime(3, key("credential-a", current.steam_id64, 5, 7)),
            playtime(4, key("credential-a", current.steam_id64, 4, 8)),
            QueuedInjection {
                body: vec![5],
                generation: 7,
                playtime_context: None,
                _cloud_permit: None,
            },
            playtime(6, current.clone()),
        ]);

        let (ordinary, discarded) = take_next_dispatchable(&mut queue, 7, Some(&current));
        assert_eq!(discarded, 4);
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
            key("credential-a", 76_561_198_000_000_001, 4, 7),
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
}
