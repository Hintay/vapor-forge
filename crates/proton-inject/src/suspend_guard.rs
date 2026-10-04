// Suspension guard for Wine's process-wide ntdll locks.
//
// Wine keeps two locks reachable from the PEB: the PEB lock (environment,
// current directory and DOS path conversion, so CreateFileW too) and the
// loader lock (module loading and lookup). A thread suspended while holding
// either one blocks every other thread that needs it until it is resumed. Code
// that suspends the other threads of its process and then calls into such APIs
// deadlocks.
//
// The NtSuspendThread detour returns only once the target is stopped outside
// both locks: a thread caught holding one is resumed, given time to leave, and
// suspended again. A thread that was already suspended is passed through
// unchanged.
//
// The hook can run while other threads are suspended inside glibc with its
// locks held, so it must not allocate.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::detour::PreparedDetour;
use crate::loader::{log, log_args};

type Handle = *mut core::ffi::c_void;
type SuspendFn = unsafe extern "win64" fn(Handle, *mut u32) -> i32;
type GetContextFn = unsafe extern "win64" fn(Handle, *mut Context) -> i32;
type QueryThreadFn =
    unsafe extern "win64" fn(Handle, u32, *mut core::ffi::c_void, u32, *mut u32) -> i32;
type DelayFn = unsafe extern "win64" fn(u8, *const i64) -> i32;
type DuplicateFn =
    unsafe extern "win64" fn(Handle, Handle, Handle, *mut Handle, u32, u32, u32) -> i32;
type CloseFn = unsafe extern "win64" fn(Handle) -> i32;

const TEB_SELF: usize = 0x30;
const TEB_CLIENT_PROCESS: usize = 0x40;
const TEB_CLIENT_THREAD: usize = 0x48;
const TEB_PEB: usize = 0x60;
const PEB_FAST_PEB_LOCK: usize = 0x38;
const PEB_LOADER_LOCK: usize = 0x110;
const CS_OWNING_THREAD: usize = 0x10;

const THREAD_BASIC_INFORMATION: u32 = 0;
const THREAD_GET_CONTEXT: u32 = 0x0008;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const CURRENT_PROCESS: Handle = usize::MAX as Handle;
const CONTEXT_AMD64_CONTROL: u32 = 0x0010_0001;
const CONTEXT_FLAGS: usize = 0x30;

const MAX_RETRIES: u32 = 2000;
// Relative 100 us, in 100 ns units.
const RETRY_DELAY: i64 = -1000;

static TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static RESUME: AtomicUsize = AtomicUsize::new(0);
static GET_CONTEXT: AtomicUsize = AtomicUsize::new(0);
static QUERY_THREAD: AtomicUsize = AtomicUsize::new(0);
static DELAY: AtomicUsize = AtomicUsize::new(0);
static DUPLICATE: AtomicUsize = AtomicUsize::new(0);
static CLOSE: AtomicUsize = AtomicUsize::new(0);

#[repr(C, align(16))]
struct Context([u8; 0x4d0]);

#[repr(C)]
#[derive(Default)]
struct ThreadBasicInformation {
    exit_status: i32,
    teb: usize,
    unique_process: usize,
    unique_thread: usize,
    affinity_mask: usize,
    priority: i32,
    base_priority: i32,
}

/// Install the NtSuspendThread detour in the PE ntdll mapped at `pe_base`.
/// Must run while no other thread can execute NtSuspendThread's prologue.
pub fn install(pe_base: usize, pe_bytes: &[u8]) -> bool {
    if TRAMPOLINE.load(Ordering::Acquire) != 0 {
        return true;
    }
    let export =
        |name: &str| crate::pe::find_export_rva(pe_bytes, name).map(|rva| pe_base + rva as usize);
    let (
        Some(suspend),
        Some(resume),
        Some(get_context),
        Some(query_thread),
        Some(delay),
        Some(duplicate),
        Some(close),
    ) = (
        export("NtSuspendThread"),
        export("NtResumeThread"),
        export("NtGetContextThread"),
        export("NtQueryInformationThread"),
        export("NtDelayExecution"),
        export("NtDuplicateObject"),
        export("NtClose"),
    )
    else {
        log("suspend guard: missing PE ntdll exports");
        return false;
    };
    RESUME.store(resume, Ordering::Release);
    GET_CONTEXT.store(get_context, Ordering::Release);
    QUERY_THREAD.store(query_thread, Ordering::Release);
    DELAY.store(delay, Ordering::Release);
    DUPLICATE.store(duplicate, Ordering::Release);
    CLOSE.store(close, Ordering::Release);

    // SAFETY: suspend is NtSuspendThread's address in the mapped PE ntdll.
    let Some(prepared) =
        (unsafe { PreparedDetour::prepare(suspend, hook_nt_suspend_thread as *const () as usize) })
    else {
        log("suspend guard: detour preparation failed");
        return false;
    };
    let trampoline = prepared.trampoline();
    TRAMPOLINE.store(trampoline, Ordering::Release);
    // SAFETY: the caller serializes installation before other PE threads run.
    if unsafe { prepared.activate() }.is_none() {
        TRAMPOLINE.store(0, Ordering::Release);
        log("suspend guard: detour activation failed");
        return false;
    }
    log("suspend guard: NtSuspendThread detour installed");
    true
}

/// # Safety
/// Called from PE code with NtSuspendThread's arguments.
unsafe extern "win64" fn hook_nt_suspend_thread(handle: Handle, previous: *mut u32) -> i32 {
    // SAFETY: the hook is only reachable after install published TRAMPOLINE.
    let suspend: SuspendFn = unsafe { std::mem::transmute(TRAMPOLINE.load(Ordering::Acquire)) };
    // Callers often open threads with suspend access only.
    let inspect = InspectHandle::open(handle);
    let Some(thread_id) = query_target(inspect.handle).other_thread() else {
        // SAFETY: forwards the caller's arguments unchanged.
        return unsafe { suspend(handle, previous) };
    };

    let mut retries = 0;
    loop {
        let mut count = 0u32;
        // SAFETY: count is a valid out pointer for this call.
        let status = unsafe { suspend(handle, &mut count) };
        // Only a suspension this call started can be undone and retried.
        let retry = status >= 0 && count == 0 && retries < MAX_RETRIES && {
            wait_until_stopped(inspect.handle);
            holds_any(&lock_owners(), thread_id)
        };
        if !retry {
            if !previous.is_null() {
                // SAFETY: previous is the caller's optional out pointer.
                unsafe { *previous = count };
            }
            if retries == MAX_RETRIES {
                log_args(format_args!(
                    "suspend guard: suspended thread {thread_id:#x} still holding an ntdll lock after {retries} retries"
                ));
            } else if retries > 0 {
                log_args(format_args!(
                    "suspend guard: thread {thread_id:#x} left the ntdll locks after {retries} retries"
                ));
            }
            return status;
        }
        resume(handle);
        delay();
        retries += 1;
    }
}

fn teb() -> usize {
    let teb: usize;
    // SAFETY: on wine x86_64 the TEB lives at the gs base and TEB.NtTib.Self is
    // at 0x30; the hook only runs on PE threads.
    unsafe {
        core::arch::asm!(
            "mov {teb}, qword ptr gs:[{off}]",
            teb = out(reg) teb,
            off = const TEB_SELF,
            options(nostack, readonly, preserves_flags)
        );
    }
    teb
}

/// A handle to the same thread with query and context access, duplicated from
/// the caller's handle when possible and closed on drop.
struct InspectHandle {
    handle: Handle,
    owned: bool,
}

impl InspectHandle {
    fn open(handle: Handle) -> Self {
        let duplicate = DUPLICATE.load(Ordering::Acquire);
        if duplicate == 0 {
            return Self {
                handle,
                owned: false,
            };
        }
        // SAFETY: duplicate is NtDuplicateObject from the mapped PE ntdll.
        let duplicate: DuplicateFn = unsafe { std::mem::transmute(duplicate) };
        let mut copy: Handle = std::ptr::null_mut();
        // SAFETY: copy is a valid out pointer; both process handles are the
        // current-process pseudo handle.
        let status = unsafe {
            duplicate(
                CURRENT_PROCESS,
                handle,
                CURRENT_PROCESS,
                &mut copy,
                THREAD_QUERY_LIMITED_INFORMATION | THREAD_GET_CONTEXT,
                0,
                0,
            )
        };
        let owned = status >= 0 && !copy.is_null();
        Self {
            handle: if owned { copy } else { handle },
            owned,
        }
    }
}

impl Drop for InspectHandle {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        // SAFETY: CLOSE holds NtClose, set before the hook was activated, and
        // the handle was duplicated by this guard.
        let close: CloseFn = unsafe { std::mem::transmute(CLOSE.load(Ordering::Acquire)) };
        // SAFETY: closes the guard's own duplicate.
        unsafe { close(self.handle) };
    }
}

/// The thread behind a handle, next to the calling thread's own ids.
#[derive(Default)]
struct Target {
    status: i32,
    process: usize,
    thread: usize,
    own_process: usize,
    own_thread: usize,
}

impl Target {
    /// Thread id when the handle names another thread of this process.
    fn other_thread(&self) -> Option<usize> {
        (self.status >= 0 && self.process == self.own_process && self.thread != self.own_thread)
            .then_some(self.thread)
    }
}

fn query_target(handle: Handle) -> Target {
    let query = QUERY_THREAD.load(Ordering::Acquire);
    let teb = teb();
    if query == 0 || teb == 0 {
        return Target {
            status: -1,
            ..Target::default()
        };
    }
    // SAFETY: query is NtQueryInformationThread from the mapped PE ntdll.
    let query: QueryThreadFn = unsafe { std::mem::transmute(query) };
    let mut info = ThreadBasicInformation::default();
    // SAFETY: info is a writable THREAD_BASIC_INFORMATION of the stated size.
    let status = unsafe {
        query(
            handle,
            THREAD_BASIC_INFORMATION,
            (&mut info as *mut ThreadBasicInformation).cast(),
            std::mem::size_of::<ThreadBasicInformation>() as u32,
            std::ptr::null_mut(),
        )
    };
    // SAFETY: TEB client id fields are always mapped for the current thread.
    let (own_process, own_thread) = unsafe {
        (
            std::ptr::read_volatile((teb + TEB_CLIENT_PROCESS) as *const usize),
            std::ptr::read_volatile((teb + TEB_CLIENT_THREAD) as *const usize),
        )
    };
    Target {
        status,
        process: info.unique_process,
        thread: info.unique_thread,
        own_process,
        own_thread,
    }
}

/// Wine delivers a suspension asynchronously; fetching the context waits until
/// the target has actually stopped.
fn wait_until_stopped(handle: Handle) {
    let get_context = GET_CONTEXT.load(Ordering::Acquire);
    if get_context == 0 {
        return;
    }
    // SAFETY: get_context is NtGetContextThread from the mapped PE ntdll.
    let get_context: GetContextFn = unsafe { std::mem::transmute(get_context) };
    let mut context = Context([0; 0x4d0]);
    context.0[CONTEXT_FLAGS..CONTEXT_FLAGS + 4]
        .copy_from_slice(&CONTEXT_AMD64_CONTROL.to_le_bytes());
    // SAFETY: context is a 16-byte aligned, CONTEXT-sized buffer.
    unsafe { get_context(handle, &mut context) };
}

/// Thread ids recorded as owners of the PEB lock and the loader lock; 0 for a
/// free or missing lock.
fn lock_owners() -> [usize; 2] {
    let teb = teb();
    if teb == 0 {
        return [0; 2];
    }
    // SAFETY: the TEB, its PEB and the critical sections the PEB points to stay
    // mapped for the life of the process.
    unsafe {
        let peb = std::ptr::read_volatile((teb + TEB_PEB) as *const usize);
        if peb == 0 {
            return [0; 2];
        }
        [PEB_FAST_PEB_LOCK, PEB_LOADER_LOCK].map(|field| {
            let lock = std::ptr::read_volatile((peb + field) as *const usize);
            if lock == 0 {
                0
            } else {
                std::ptr::read_volatile((lock + CS_OWNING_THREAD) as *const usize)
            }
        })
    }
}

fn holds_any(owners: &[usize], thread_id: usize) -> bool {
    thread_id != 0 && owners.contains(&thread_id)
}

fn resume(handle: Handle) {
    // SAFETY: RESUME holds NtResumeThread, set before the hook was activated.
    let resume: SuspendFn = unsafe { std::mem::transmute(RESUME.load(Ordering::Acquire)) };
    // SAFETY: a null previous-count pointer is allowed.
    unsafe { resume(handle, std::ptr::null_mut()) };
}

fn delay() {
    // SAFETY: DELAY holds NtDelayExecution, set before the hook was activated.
    let delay: DelayFn = unsafe { std::mem::transmute(DELAY.load(Ordering::Acquire)) };
    // SAFETY: the interval points to a live relative timeout.
    unsafe { delay(0, &RETRY_DELAY) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(process: usize, thread: usize) -> Target {
        Target {
            status: 0,
            process,
            thread,
            own_process: 0x20,
            own_thread: 0x24,
        }
    }

    #[test]
    fn guards_other_threads_of_this_process_only() {
        assert_eq!(target(0x20, 0x30).other_thread(), Some(0x30));
        assert_eq!(target(0x20, 0x24).other_thread(), None);
        assert_eq!(target(0x40, 0x30).other_thread(), None);
        let denied = Target {
            status: 0xc000_0022_u32 as i32,
            ..target(0x20, 0x30)
        };
        assert_eq!(denied.other_thread(), None);
    }

    #[test]
    fn retries_only_while_the_target_owns_a_lock() {
        assert!(holds_any(&[0x30, 0], 0x30));
        assert!(holds_any(&[0, 0x30], 0x30));
        assert!(!holds_any(&[0x34, 0], 0x30));
        assert!(!holds_any(&[0, 0], 0));
    }
}
