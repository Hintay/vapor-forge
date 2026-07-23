use core::ffi::c_void;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use tracing::info;
use vapor_forge_hook_engine::detour::{CodeRegion, Detour};
use vapor_forge_patterns::registry::PatternRegistry;

use crate::netpacket::SendFrameDecision;
use vapor_forge_hook_engine::original::detour_or_return;

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type BBuildAndAsyncSendFrameFn =
    unsafe extern "C" fn(*mut c_void, i32, *mut u8, u32) -> bool;
pub(crate) type RecvPktFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
pub(crate) type WorkThreadPoolAddWorkItemFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool;
pub(crate) type WebSocketWorkerPostItemFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
type WorkerWakeStateFn = unsafe extern "C" fn(*mut c_void, usize);
type PacketAllocFn = unsafe extern "C" fn() -> *mut c_void;
type PacketInitFn = unsafe extern "C" fn(*mut c_void, u32, *mut u8, u32, *mut u8, u32);
type PacketReleaseFn = unsafe extern "C" fn(*mut c_void);

// ---------------------------------------------------------------------------
// Static detour slots
// ---------------------------------------------------------------------------

pub(crate) static mut SEND_FRAME_DETOUR: Option<Detour<BBuildAndAsyncSendFrameFn>> = None;
pub(crate) static mut RECV_PKT_DETOUR: Option<Detour<RecvPktFn>> = None;
// Production one-shot worker_this capture hook (both arches).
pub(crate) static mut POST_WORK_ITEM_DETOUR: Option<Detour<WebSocketWorkerPostItemFn>> = None;

static PACKET_ALLOC_ADDR: AtomicUsize = AtomicUsize::new(0);
static PACKET_INIT_ADDR: AtomicUsize = AtomicUsize::new(0);
static PACKET_RELEASE_ADDR: AtomicUsize = AtomicUsize::new(0);
static ADD_WORK_ITEM_ADDR: AtomicUsize = AtomicUsize::new(0);
static WAKE_WORKER_ADDR: AtomicUsize = AtomicUsize::new(0);

// Production native-dispatch state. Fabricated responses queue here and are
// dispatched on the WebSocket worker thread through a custom CWorkItem.
static INJECTION_QUEUE: OnceLock<Mutex<VecDeque<Vec<u8>>>> = OnceLock::new();
// The CWorkThreadPool worker owner captured from the post-item wrapper.
static WORKER_THIS: AtomicUsize = AtomicUsize::new(0);
// The CCMConnection captured from RecvPkt (the receiver we dispatch onto).
static CM_RECEIVER: AtomicUsize = AtomicUsize::new(0);
// The connection id read from a real incoming packet's first field.
static CM_CONN_ID: AtomicUsize = AtomicUsize::new(0);
static CM_CONN_ID_SET: AtomicBool = AtomicBool::new(false);
// One-shot flush of anything a source queued before dispatch context was ready.
static WARMUP_FLUSH_DONE: AtomicBool = AtomicBool::new(false);

#[cfg(target_pointer_width = "32")]
const WORKER_THREAD_POOL_OFFSET: usize = 0x5c;
#[cfg(target_pointer_width = "64")]
const WORKER_THREAD_POOL_OFFSET: usize = 0x68;
#[cfg(target_pointer_width = "32")]
const WORKER_WAKE_EVENT_OFFSET: usize = 0x470;
#[cfg(target_pointer_width = "64")]
const WORKER_WAKE_EVENT_OFFSET: usize = 0x5e0;
#[cfg(target_pointer_width = "32")]
const HTTP_WORK_ITEM_LIST_SENTINEL_REL: usize = 0x2e633cc;
#[cfg(target_pointer_width = "64")]
const HTTP_WORK_ITEM_LIST_SENTINEL_REL: usize = 0x2ac8978;

// Per-arch CWorkItem layout for native injection dispatch.
#[cfg(target_pointer_width = "32")]
const WORK_ITEM_SIZE: usize = 0xb0;
#[cfg(target_pointer_width = "64")]
const WORK_ITEM_SIZE: usize = 0xe8;
#[cfg(target_pointer_width = "32")]
const WORK_ITEM_REFCOUNT_OFFSET: usize = 0x04;
#[cfg(target_pointer_width = "64")]
const WORK_ITEM_REFCOUNT_OFFSET: usize = 0x08;
#[cfg(target_pointer_width = "32")]
const WORK_ITEM_SENTINEL_OFFSETS: &[usize] = &[0x24, 0x3c, 0x54, 0x6c];
#[cfg(target_pointer_width = "64")]
const WORK_ITEM_SENTINEL_OFFSETS: &[usize] = &[0x30, 0x50, 0x70, 0x90];
#[cfg(target_pointer_width = "32")]
const WORK_ITEM_MINUS_ONE_U32_OFFSETS: &[usize] = &[0x84, 0x88, 0x98];
#[cfg(target_pointer_width = "64")]
const WORK_ITEM_MINUS_ONE_U32_OFFSETS: &[usize] = &[0xc8];
#[cfg(target_pointer_width = "32")]
const WORK_ITEM_MINUS_ONE_PTR_OFFSETS: &[usize] = &[];
#[cfg(target_pointer_width = "64")]
const WORK_ITEM_MINUS_ONE_PTR_OFFSETS: &[usize] = &[0xb0];

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
    // Optional: absence leaves dispatch to the worker loop's own poll cadence.
    let wake_worker = super::install::resolve_address_from_registry(
        registry,
        code,
        "CWorkThreadPool::WakeWorker",
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
    if let Some(addr) = wake_worker {
        WAKE_WORKER_ADDR.store(addr, Ordering::Release);
    }

    info!(
        packet_alloc = %format_resolved_addr(packet_alloc),
        packet_init = %format_resolved_addr(packet_init),
        packet_release = %format_resolved_addr(packet_release),
        add_work_item = %format_resolved_addr(add_work_item),
        wake_worker = %format_resolved_addr(wake_worker),
        "native-packet: Steam CNetPacket and work-item functions resolved"
    );
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
    super::client_id::refresh_device_descriptor();

    const WEBSOCKET_BINARY: i32 = 2;
    if opcode == WEBSOCKET_BINARY && !data.is_null() && size > 0 {
        // SAFETY: data is a valid buffer of `size` bytes, provided by Steam.
        let slice = unsafe { std::slice::from_raw_parts(data, size as usize) };

        match crate::netpacket::decide_send_frame(slice) {
            SendFrameDecision::Pass => {}
            SendFrameDecision::Drop => return true,
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

    // SAFETY: RECV_PKT_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("RecvPkt", RECV_PKT_DETOUR);

    // Injection is driven per-source (each fabricated response dispatches itself
    // the moment it is ready); no sweep is needed on the inbound path.

    // RecvPkt dispatches synchronously. Keep rewritten bytes alive through the
    // original call, then restore Steam's owned payload before its caller
    // releases the CNetPacket.
    // SAFETY: packet is the live CNetPacket supplied by Steam's caller.
    let _guard = unsafe { crate::netpacket::prepare_recv_packet(packet) };
    // SAFETY: forwarding this callback's unchanged object and packet pointers.
    unsafe { original(this, packet) };
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

fn injection_queue() -> &'static Mutex<VecDeque<Vec<u8>>> {
    INJECTION_QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// One-shot capture from the RecvPkt hook: the CCMConnection receiver we dispatch
/// onto and a real connection id. The worker owner comes from the post-item hook.
pub(crate) fn capture_dispatch_context(this: *mut c_void, packet: *mut c_void) {
    if !this.is_null() {
        let _ = CM_RECEIVER.compare_exchange(0, this as usize, Ordering::AcqRel, Ordering::Acquire);
    }
    if !packet.is_null() && !CM_CONN_ID_SET.load(Ordering::Acquire) {
        // SAFETY: packet is the live CNetPacket; its first field is the conn id.
        let conn_id = unsafe { *(packet as *const u32) } as usize;
        CM_CONN_ID.store(conn_id, Ordering::Release);
        CM_CONN_ID_SET.store(true, Ordering::Release);
    }
}

/// Capture worker_this from the post-item wrapper (arg1 = worker). Disabling the
/// detour from inside itself would race concurrent posts, so instead the body is
/// a single compare_exchange that fails fast once captured, then forwards.
pub(crate) unsafe extern "C" fn hk_post_work_item(worker: *mut c_void, job: *mut c_void) {
    if !worker.is_null() && WORKER_THIS.load(Ordering::Acquire) == 0 {
        let _ =
            WORKER_THIS.compare_exchange(0, worker as usize, Ordering::AcqRel, Ordering::Acquire);
    }
    maybe_warmup_flush();
    // SAFETY: POST_WORK_ITEM_DETOUR is set before the hook is enabled.
    let original = detour_or_return!("CWorkThreadPool::PostWorkItem", POST_WORK_ITEM_DETOUR);
    // SAFETY: typed original with the callback's own unchanged arguments.
    unsafe { original(worker, job) };
}

fn dispatch_ready() -> bool {
    WORKER_THIS.load(Ordering::Acquire) != 0
        && CM_RECEIVER.load(Ordering::Acquire) != 0
        && CM_CONN_ID_SET.load(Ordering::Acquire)
        && ADD_WORK_ITEM_ADDR.load(Ordering::Acquire) != 0
        && PACKET_ALLOC_ADDR.load(Ordering::Acquire) != 0
        && PACKET_INIT_ADDR.load(Ordering::Acquire) != 0
        && PACKET_RELEASE_ADDR.load(Ordering::Acquire) != 0
}

/// Queue a fabricated response and post a worker item to deliver it. If the
/// dispatch context is not captured yet, the body stays queued for a later post.
pub(crate) fn enqueue_injection(body: Vec<u8>) {
    injection_queue().lock().unwrap().push_back(body);
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

fn post_injection() {
    if !dispatch_ready() {
        return;
    }
    if injection_queue().lock().unwrap().is_empty() {
        return;
    }
    let worker_this = WORKER_THIS.load(Ordering::Acquire);
    // SAFETY: address resolved inside steamclient.so via pattern; ABI matches.
    let add_work_item: WorkThreadPoolAddWorkItemFn =
        unsafe { std::mem::transmute(ADD_WORK_ITEM_ADDR.load(Ordering::Acquire)) };

    let list_sentinel =
        resolve_steamclient_image_rva_any_segment(HTTP_WORK_ITEM_LIST_SENTINEL_REL).unwrap_or(0);
    let item = NativeWorkItem::boxed(&NATIVE_INJECT_VTABLE, list_sentinel);
    let pool = worker_this.wrapping_add(WORKER_THREAD_POOL_OFFSET) as *mut c_void;

    // SAFETY: pool is the worker's CWorkThreadPool; item is an ABI-shaped CWorkItem.
    let posted = unsafe { add_work_item(pool, item) };
    info!(
        posted,
        item = format_args!("{item:p}"),
        worker_this = format_args!("0x{worker_this:x}"),
        "native-inject: posted work item"
    );
    if !posted {
        // SAFETY: Steam rejected the item, so ownership never left us.
        unsafe { NativeWorkItem::free(item) };
        return;
    }
    let wake_addr = WAKE_WORKER_ADDR.load(Ordering::Acquire);
    if wake_addr != 0 {
        // SAFETY: the same wake primitive Steam's post wrapper calls.
        let wake: WorkerWakeStateFn = unsafe { std::mem::transmute(wake_addr) };
        let wake_object = worker_this.wrapping_add(WORKER_WAKE_EVENT_OFFSET) as *mut c_void;
        // SAFETY: wake is the resolved wake function; wake_object is worker+offset.
        unsafe { wake(wake_object, 1) };
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

/// Arch-generic CWorkItem: a zeroed byte buffer holding the fields Steam's post
/// wrapper sets. Size and field offsets come from the WORK_ITEM_* constants.
#[repr(C, align(8))]
struct NativeWorkItem {
    bytes: [u8; WORK_ITEM_SIZE],
}

impl NativeWorkItem {
    fn boxed(vtable: *const NativeProbeWorkItemVtable, sentinel: usize) -> *mut c_void {
        let mut item: Box<NativeWorkItem> = Box::new(NativeWorkItem {
            bytes: [0; WORK_ITEM_SIZE],
        });
        let base = item.bytes.as_mut_ptr();
        // SAFETY: base owns WORK_ITEM_SIZE bytes and every offset is within it.
        unsafe {
            core::ptr::write_unaligned(base.cast::<usize>(), vtable as usize);
            core::ptr::write_unaligned(base.add(WORK_ITEM_REFCOUNT_OFFSET).cast::<u32>(), 1);
            for &off in WORK_ITEM_SENTINEL_OFFSETS {
                core::ptr::write_unaligned(base.add(off).cast::<usize>(), sentinel);
            }
            for &off in WORK_ITEM_MINUS_ONE_PTR_OFFSETS {
                core::ptr::write_unaligned(base.add(off).cast::<usize>(), usize::MAX);
            }
            for &off in WORK_ITEM_MINUS_ONE_U32_OFFSETS {
                core::ptr::write_unaligned(base.add(off).cast::<u32>(), u32::MAX);
            }
        }
        Box::into_raw(item) as *mut c_void
    }

    /// # Safety
    /// `item` must be a pointer previously returned by [`NativeWorkItem::boxed`].
    unsafe fn free(item: *mut c_void) {
        // SAFETY: caller guarantees item came from boxed(); reclaim the Box.
        unsafe { drop(Box::from_raw(item as *mut NativeWorkItem)) };
    }
}

/// Drop the caller-owned reference at the per-arch CWorkItem refcount offset.
fn release_inject_caller_ref(item: *mut c_void) {
    let addr = (item as usize).wrapping_add(WORK_ITEM_REFCOUNT_OFFSET);
    let ref_count = addr as *const std::sync::atomic::AtomicU32;
    // SAFETY: item+refcount is the CWorkItem's u32 refcount, correctly aligned.
    unsafe { (*ref_count).fetch_sub(1, Ordering::AcqRel) };
}

unsafe extern "C" fn native_inject_noop(_item: *mut c_void) {}

unsafe extern "C" fn native_inject_slot_14(_item: *mut c_void, _arg: *mut c_void) -> bool {
    // May run on a non-worker thread; never dispatch packets here.
    true
}

unsafe extern "C" fn native_inject_deleting_destroy(item: *mut c_void) {
    // SAFETY: this slot is the ownership terminal for our allocation.
    unsafe { NativeWorkItem::free(item) };
}

unsafe extern "C" fn native_inject_execute(item: *mut c_void, _arg: *mut c_void) -> bool {
    info!(
        pthread = format_args!("0x{:x}", current_pthread()),
        item = format_args!("{item:p}"),
        "native-inject: execute on worker thread"
    );
    // Drop the caller-owned reference now that Steam's queue reference drives
    // destruction after this returns.
    release_inject_caller_ref(item);
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
        let Some(mut body) = injection_queue().lock().unwrap().pop_front() else {
            break;
        };
        if body.is_empty() {
            continue;
        }
        let ptr = body.as_mut_ptr();
        let len = body.len() as u32;
        // SAFETY: PacketAlloc yields a fresh CNetPacket; body stays alive across
        // the synchronous RecvPkt dispatch and owned_data is null, so Steam does
        // not free it.
        let packet = unsafe { packet_alloc() };
        if packet.is_null() {
            continue;
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

fn resolve_steamclient_image_rva_any_segment(image_rva: usize) -> Option<usize> {
    let entries = vapor_forge_memory::find_proc_self_maps_targets(64).ok()?;
    let module_base = entries
        .iter()
        .filter(|entry| entry.path.ends_with("/steamclient.so") || entry.path == "steamclient.so")
        .map(|entry| entry.range.base.0)
        .min()?;
    let addr = module_base.checked_add(image_rva)?;
    entries
        .iter()
        .any(|entry| {
            (entry.path.ends_with("/steamclient.so") || entry.path == "steamclient.so")
                && addr >= entry.range.base.0
                && addr < entry.range.end.0
        })
        .then_some(addr)
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
