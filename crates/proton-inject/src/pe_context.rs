// Syscall user dispatch bridging for Rust code called from Wine PE threads.
//
// Wine builds with syscall user dispatch keep a per-thread selector byte in the
// TEB. While a thread runs PE code the selector blocks every Linux syscall
// issued outside the main-namespace libc, and Wine's SIGSYS handler dispatches
// the trapped syscall as an NT syscall. This audit library lives in its own
// link-map namespace with a separate libc copy, so any syscall it makes from a
// PE hook is misrouted. `UnixScope` opens the selector for the duration of the
// hook work and keeps asynchronous signals blocked, because Wine's signal exit
// path closes the selector again for any thread outside a syscall frame.

use core::ffi::{c_char, c_long, c_void, CStr};
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

/// TEB offset of `amd64_thread_data::syscall_dispatch`. Older Wine builds leave
/// this byte unused and zeroed, which `UnixScope` treats as nothing to do.
const SELECTOR_OFFSET: usize = 0x340;
const SELECTOR_ALLOW: u8 = 0;
const SELECTOR_BLOCK: u8 = 1;

const LM_ID_BASE: c_long = 0;
const KERNEL_SIGSET_SIZE: c_long = 8;

/// Signals that report a fault in the running code stay deliverable.
const SYNCHRONOUS_SIGNALS: [libc::c_int; 6] = [
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGTRAP,
    libc::SIGABRT,
];

static MAIN_LIBC: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static MAIN_SYSCALL: AtomicUsize = AtomicUsize::new(0);

type SyscallFn = unsafe extern "C" fn(c_long, ...) -> c_long;

/// Remember the main-namespace libc link map reported to `la_objopen`.
///
/// # Safety
/// `map` must be the live `struct link_map` pointer glibc passed to the audit
/// callback.
pub unsafe fn record_object(map: *mut c_void, lmid: c_long) {
    if lmid != LM_ID_BASE || map.is_null() {
        return;
    }
    // SAFETY: `l_name` is the second pointer-sized field of `struct link_map`.
    let name = unsafe { *(map as *const *const c_char).add(1) };
    if name.is_null() {
        return;
    }
    // SAFETY: glibc keeps `l_name` NUL-terminated for the object's lifetime.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    if name.ends_with(b"/libc.so.6") || name == b"libc.so.6" {
        MAIN_LIBC.store(map, Ordering::Release);
    }
}

/// Resolve `syscall` in the main-namespace libc. Must run in Unix context
/// after `la_objopen` reported that libc.
pub fn resolve() {
    if MAIN_SYSCALL.load(Ordering::Acquire) != 0 {
        return;
    }
    let map = MAIN_LIBC.load(Ordering::Acquire);
    if map.is_null() {
        return;
    }
    // SAFETY: MAIN_LIBC is a loaded link map whose dynamic section stays mapped.
    match unsafe { lookup_symbol(map, b"syscall") } {
        Some(symbol) => MAIN_SYSCALL.store(symbol, Ordering::Release),
        None => crate::loader::log("pe context: main libc syscall not found"),
    }
}

const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const STT_FUNC: u8 = 2;
const SHN_UNDEF: u16 = 0;

#[repr(C)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

/// Look up a defined function in a loaded object through its GNU hash table.
///
/// # Safety
/// `map` must be a live `struct link_map` of a fully loaded object.
unsafe fn lookup_symbol(map: *mut c_void, name: &[u8]) -> Option<usize> {
    // SAFETY: `l_addr` and `l_ld` are the first and third fields of the link
    // map; the dynamic array is terminated by DT_NULL.
    let (base, mut dynamic) = unsafe {
        let fields = map as *const usize;
        (*fields, *fields.add(2) as *const [i64; 2])
    };
    // glibc stores most dynamic pointers relocated; keep raw offsets working.
    let absolute = |value: i64| {
        let value = value as usize;
        if value < base {
            value + base
        } else {
            value
        }
    };
    let (mut strtab, mut symtab, mut gnu_hash) = (0, 0, 0);
    loop {
        // SAFETY: walking the object's dynamic array up to DT_NULL.
        let [tag, value] = unsafe { *dynamic };
        match tag {
            DT_NULL => break,
            DT_STRTAB => strtab = absolute(value),
            DT_SYMTAB => symtab = absolute(value),
            DT_GNU_HASH => gnu_hash = absolute(value),
            _ => {}
        }
        // SAFETY: the array continues until the DT_NULL entry.
        dynamic = unsafe { dynamic.add(1) };
    }
    if strtab == 0 || symtab == 0 || gnu_hash == 0 {
        return None;
    }

    let hash = gnu_hash_of(name);
    // SAFETY: the GNU hash layout is a header of four u32 values, a bloom
    // filter of u64 words, the buckets and the chain array, all mapped.
    unsafe {
        let header = gnu_hash as *const u32;
        let bucket_count = *header;
        let symbol_offset = *header.add(1);
        let bloom_words = *header.add(2) as usize;
        let buckets = header.add(4 + bloom_words * 2);
        let chains = buckets.add(bucket_count as usize);
        if bucket_count == 0 {
            return None;
        }
        let mut index = *buckets.add((hash % bucket_count) as usize);
        if index < symbol_offset {
            return None;
        }
        loop {
            let chain_hash = *chains.add((index - symbol_offset) as usize);
            if chain_hash | 1 == hash | 1 {
                let symbol = &*(symtab as *const Elf64Sym).add(index as usize);
                let symbol_name =
                    CStr::from_ptr((strtab + symbol.st_name as usize) as *const c_char);
                if symbol_name.to_bytes() == name
                    && symbol.st_info & 0xf == STT_FUNC
                    && symbol.st_shndx != SHN_UNDEF
                {
                    return Some(base + symbol.st_value as usize);
                }
            }
            if chain_hash & 1 != 0 {
                return None;
            }
            index += 1;
        }
    }
}

fn gnu_hash_of(name: &[u8]) -> u32 {
    name.iter().fold(5381u32, |hash, &byte| {
        hash.wrapping_mul(33).wrapping_add(byte as u32)
    })
}

/// Unix-side section entered from a PE hook. Dropping it restores the selector
/// and the signal mask.
pub struct UnixScope {
    active: bool,
    saved_mask: Option<u64>,
}

impl UnixScope {
    /// Open the syscall selector of the current thread if it is closed.
    ///
    /// # Safety
    /// Must run on a Wine thread, where the gs base holds the TEB.
    pub unsafe fn enter() -> Self {
        // SAFETY: the caller guarantees a Wine thread.
        if unsafe { read_selector() } != SELECTOR_BLOCK {
            return Self {
                active: false,
                saved_mask: None,
            };
        }
        let saved_mask = block_async_signals();
        // SAFETY: the caller guarantees a Wine thread.
        unsafe { write_selector(SELECTOR_ALLOW) };
        Self {
            active: true,
            saved_mask,
        }
    }

    /// Run PE code inside the scope with the selector closed and the caller's
    /// signal mask restored.
    pub fn call_pe<R>(&mut self, call: impl FnOnce() -> R) -> R {
        if !self.active {
            return call();
        }
        self.leave();
        let result = call();
        self.saved_mask = block_async_signals();
        // SAFETY: an active scope was entered on this Wine thread.
        unsafe { write_selector(SELECTOR_ALLOW) };
        result
    }

    fn leave(&mut self) {
        // SAFETY: an active scope was entered on this Wine thread.
        unsafe { write_selector(SELECTOR_BLOCK) };
        if let Some(mask) = self.saved_mask.take() {
            set_signal_mask(libc::SIG_SETMASK, mask);
        }
    }
}

impl Drop for UnixScope {
    fn drop(&mut self) {
        if self.active {
            self.leave();
        }
    }
}

/// Block asynchronous signals through the main libc, whose syscalls the
/// selector always allows. Returns the previous mask.
fn block_async_signals() -> Option<u64> {
    let mut mask = !0u64;
    for signal in SYNCHRONOUS_SIGNALS {
        mask &= !(1u64 << (signal - 1));
    }
    set_signal_mask(libc::SIG_BLOCK, mask)
}

fn set_signal_mask(how: libc::c_int, mask: u64) -> Option<u64> {
    let syscall = MAIN_SYSCALL.load(Ordering::Acquire);
    if syscall == 0 {
        return None;
    }
    // SAFETY: MAIN_SYSCALL holds glibc's variadic `syscall` function.
    let syscall: SyscallFn = unsafe { core::mem::transmute(syscall) };
    let mut previous = 0u64;
    // SAFETY: rt_sigprocmask reads `mask` and writes `previous`, both 8-byte
    // kernel sigsets that outlive the call.
    let result = unsafe {
        syscall(
            libc::SYS_rt_sigprocmask,
            how as c_long,
            &mask as *const u64,
            &mut previous as *mut u64,
            KERNEL_SIGSET_SIZE,
        )
    };
    (result == 0).then_some(previous)
}

/// # Safety
/// Must run on a Wine thread.
unsafe fn read_selector() -> u8 {
    let value: u8;
    // SAFETY: the caller guarantees gs points at the current TEB.
    unsafe {
        core::arch::asm!(
            "mov {value}, byte ptr gs:[{offset}]",
            value = out(reg_byte) value,
            offset = const SELECTOR_OFFSET,
            options(nostack, preserves_flags)
        );
    }
    value
}

/// # Safety
/// Must run on a Wine thread.
unsafe fn write_selector(value: u8) {
    // SAFETY: the caller guarantees gs points at the current TEB. The asm is
    // not marked `nomem`, so it orders against surrounding memory accesses.
    unsafe {
        core::arch::asm!(
            "mov byte ptr gs:[{offset}], {value}",
            value = in(reg_byte) value,
            offset = const SELECTOR_OFFSET,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_mask_keeps_fault_signals_deliverable() {
        let mut mask = !0u64;
        for signal in SYNCHRONOUS_SIGNALS {
            mask &= !(1u64 << (signal - 1));
        }
        assert_eq!(mask & (1 << (libc::SIGSEGV - 1)), 0);
        assert_ne!(mask & (1 << (libc::SIGUSR1 - 1)), 0);
        assert_ne!(mask & (1 << (libc::SIGALRM - 1)), 0);
    }

    #[test]
    fn gnu_hash_matches_reference_values() {
        assert_eq!(gnu_hash_of(b""), 0x0000_1505);
        assert_eq!(gnu_hash_of(b"printf"), 0x156b_2bb8);
        assert_eq!(gnu_hash_of(b"exit"), 0x7c96_7e3f);
    }
}
