//! Detour on `CHTTPRequestJob::Start` that short-circuits cloud transfers whose
//! target is the process-local sentinel authority.
//!
//! Field offsets are architecture-specific candidates recovered from Steam's
//! request constructor, body setter, yielding wait path, and download callback.
//! A candidate is admitted only when every field agrees with an unconsumed local
//! transfer contract; every other request is forwarded unchanged.
//!
//! Start's second argument is a `CHTTPRequestHandle` (typeinfo confirmed), and
//! the handle owns both the request and a `CHTTPResponse`. On i686 the request
//! is at `+0x50` and the response at `+0x54`; on x86_64 they are `+0x68` and
//! `+0x70`. The two are easy to confuse, and the consequences are not subtle:
//! writing the status through the request pointer lands on the node tree at
//! request `+0x0c`, whose destructor then walks 200 as a node address. The
//! offsets below are the response ones. `job_response` is confirmed against a
//! live client: the slot at handle `+0x50` holds exactly the pointer the detour
//! already receives as its third argument, and `+0x54` holds the response.

use core::ffi::c_void;
use std::mem::MaybeUninit;

use tracing::{info, warn};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::detour_or_return;

pub(crate) const HTTP_JOB_START_NAME: &str = "CHTTPRequestJob::Start";

pub(crate) type HttpJobStartFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, bool);

pub(crate) static mut HTTP_JOB_START_DETOUR: Option<Detour<HttpJobStartFn>> = None;
const MAX_LOCAL_TRANSFER_BYTES: usize = 512 * 1024 * 1024;

struct HttpLayout {
    request_host: usize,
    request_path: usize,
    request_body_data: usize,
    request_body_size: usize,
    request_download_handler: usize,
    job_complete: usize,
    job_success: usize,
    job_request: usize,
    job_response: usize,
    response_status: usize,
    download_body_vtable: usize,
}

#[cfg(target_pointer_width = "64")]
const HTTP_LAYOUTS: &[HttpLayout] = &[HttpLayout {
    request_host: 0x80,
    request_path: 0x88,
    request_body_data: 0x98,
    request_body_size: 0xac,
    request_download_handler: 0xe0,
    job_complete: 0x22,
    job_success: 0x23,
    job_request: 0x68,
    job_response: 0x70,
    response_status: 0x0c,
    download_body_vtable: 0x38,
}];

#[cfg(target_pointer_width = "32")]
const HTTP_LAYOUTS: &[HttpLayout] = &[HttpLayout {
    request_host: 0x58,
    request_path: 0x5c,
    request_body_data: 0x64,
    request_body_size: 0x74,
    request_download_handler: 0x94,
    job_complete: 0x16,
    job_success: 0x17,
    job_request: 0x50,
    job_response: 0x54,
    response_status: 0x08,
    download_body_vtable: 0x1c,
}];

pub(crate) unsafe extern "C" fn hk_http_job_start(
    manager: *mut c_void,
    job: *mut c_void,
    request: *mut c_void,
    flag: bool,
) {
    // Only a target issued by the local adapter can admit a candidate layout.
    // All reads use process_vm_readv, so layout drift is a clean miss.
    let Some(admitted) = HTTP_LAYOUTS.iter().find_map(|layout| {
        // SAFETY: `request` is Steam's live hook argument; probing uses
        // process_vm_readv so an invalid candidate is reported as a miss.
        let identity = unsafe { probe_request_identity(request, layout) }?;
        let contract = vapor_forge_cloud_local::transfer_contract(&identity.host, &identity.path)?;
        // SAFETY: the transfer contract authenticates the request identity;
        // admission validates every remaining field before returning it.
        unsafe { admit_local_transfer(job, request, layout, identity, contract) }
    }) else {
        let original = detour_or_return!(HTTP_JOB_START_NAME, HTTP_JOB_START_DETOUR);
        // SAFETY: forwards Steam's untouched hook arguments to the trampoline.
        unsafe { original(manager, job, request, flag) };
        return;
    };

    #[cfg(debug_assertions)]
    // SAFETY: admission proved this layout against the live job and request.
    unsafe {
        log_handle_layout(job, request, admitted.layout)
    };
    let Some(outcome) = vapor_forge_cloud_local::intercept_transfer(
        &admitted.identity.host,
        &admitted.identity.path,
        &admitted.body,
    ) else {
        let original = detour_or_return!(HTTP_JOB_START_NAME, HTTP_JOB_START_DETOUR);
        // SAFETY: forwards Steam's untouched hook arguments to the trampoline.
        unsafe { original(manager, job, request, flag) };
        return;
    };
    let result = match outcome {
        vapor_forge_cloud_local::LocalTransferOutcome::Upload(result) => result,
        vapor_forge_cloud_local::LocalTransferOutcome::Download(result) => {
            result.and_then(|body| {
                let Some(download) = admitted.download else {
                    return Err(vapor_forge_cloud_core::BackendError::new(
                        "local download handler was not admitted",
                        false,
                    ));
                };
                // SAFETY: admission validated the handler's virtual Run target
                // before the transfer token was consumed.
                unsafe { invoke_download_handler(job, download, &body) }
            })
        }
    };
    // SAFETY: admission proved the handle flags and response status writable.
    unsafe { complete_job(job, admitted.layout, admitted.status, result.is_ok()) };
    match result {
        Ok(()) => info!(
            host = admitted.identity.host,
            path = admitted.identity.path,
            body_size = admitted.body.len(),
            "cloud-http: completed local transfer in process"
        ),
        Err(error) => warn!(
            host = admitted.identity.host,
            path = admitted.identity.path,
            %error,
            "cloud-http: local transfer failed"
        ),
    }
}

struct RequestIdentity {
    host: String,
    path: String,
}

struct RequestProbe {
    body_data: usize,
    body_size: i32,
}

struct AdmittedTransfer {
    layout: &'static HttpLayout,
    identity: RequestIdentity,
    body: Vec<u8>,
    status: *mut i32,
    download: Option<DownloadHandler>,
}

/// Read only the two identity strings needed to recognize an issued local target.
unsafe fn probe_request_identity(
    request: *mut c_void,
    layout: &HttpLayout,
) -> Option<RequestIdentity> {
    if request.is_null() {
        return None;
    }
    let base = request as usize;
    let host_field = base.checked_add(layout.request_host)?;
    let (host, path) = if layout.request_path == layout.request_host + std::mem::size_of::<usize>()
    {
        let pointers: [usize; 2] = read_process_value(host_field)?;
        (pointers[0], pointers[1])
    } else {
        (
            read_process_value(host_field)?,
            read_process_value(base.checked_add(layout.request_path)?)?,
        )
    };
    Some(RequestIdentity {
        host: read_string(host)?,
        path: read_string(path)?,
    })
}

unsafe fn probe_request(request: *mut c_void, layout: &HttpLayout) -> Option<RequestProbe> {
    let base = request as usize;
    Some(RequestProbe {
        body_data: read_process_value(base.checked_add(layout.request_body_data)?)?,
        body_size: read_process_value(base.checked_add(layout.request_body_size)?)?,
    })
}

/// Prove every field that may be read, written, or called before consuming the
/// local transfer token.
unsafe fn admit_local_transfer(
    job: *mut c_void,
    request: *mut c_void,
    layout: &'static HttpLayout,
    identity: RequestIdentity,
    contract: vapor_forge_cloud_local::LocalTransferContract,
) -> Option<AdmittedTransfer> {
    // SAFETY: the caller provides Steam's live request and this probe performs
    // checked process reads for the candidate layout.
    let probe = unsafe { probe_request(request, layout) }?;
    let (body, download) = match contract {
        vapor_forge_cloud_local::LocalTransferContract::Upload { transfer_size } => {
            let size = usize::try_from(transfer_size).ok()?;
            if size > MAX_LOCAL_TRANSFER_BYTES
                || probe.body_size < 0
                || usize::try_from(probe.body_size).ok()? != size
                || (size != 0 && probe.body_data == 0)
            {
                warn!("cloud-http: upload request layout does not match its transfer contract");
                return None;
            }
            (read_process_bytes(probe.body_data, size)?, None)
        }
        vapor_forge_cloud_local::LocalTransferContract::Download => {
            let download_handler: usize = read_process_value(
                (request as usize).checked_add(layout.request_download_handler)?,
            )?;
            if probe.body_size != 0 || download_handler == 0 {
                warn!("cloud-http: download request layout does not match its transfer contract");
                return None;
            }
            let download = prepare_download_handler(layout, download_handler)?;
            (Vec::new(), Some(download))
        }
    };
    // SAFETY: the request contract and all candidate fields above were
    // validated before the response slot is inspected and modified.
    let status = unsafe { unset_response_status(job, request, layout) }?;
    Some(AdmittedTransfer {
        layout,
        identity,
        body,
        status,
        download,
    })
}

/// Minimal `CUtlBuffer` view used by the streaming body callback.
#[repr(C)]
struct UtlBufferView {
    data: *const u8,
    reserved: [u8; 12],
    put: i32,
}

type DownloadBody = unsafe extern "C" fn(*mut c_void, *mut c_void, *const UtlBufferView);

#[derive(Clone, Copy)]
struct DownloadHandler {
    handler: *mut c_void,
    body: DownloadBody,
}

/// Validate and capture the download handler's virtual Run method.
fn prepare_download_handler(layout: &HttpLayout, handler: usize) -> Option<DownloadHandler> {
    if handler == 0 {
        return None;
    }
    let pointer_size = std::mem::size_of::<usize>();
    let vtable: usize = read_process_value(handler)?;
    let vtable_len = layout.download_body_vtable.checked_add(pointer_size)?;
    let body_slot = vtable.checked_add(layout.download_body_vtable)?;
    let body_address: usize = read_process_value(body_slot)?;
    let valid = vapor_forge_memory::current_process_ranges_match(&[
        vapor_forge_memory::ProcessRangeQuery {
            address: handler,
            len: pointer_size,
            read: Some(true),
            write: None,
            execute: None,
            file_backed: false,
        },
        vapor_forge_memory::ProcessRangeQuery {
            address: vtable,
            len: vtable_len,
            read: Some(true),
            write: Some(false),
            execute: Some(false),
            file_backed: true,
        },
        vapor_forge_memory::ProcessRangeQuery {
            address: body_address,
            len: 1,
            read: Some(true),
            write: None,
            execute: Some(true),
            file_backed: false,
        },
    ])
    .unwrap_or(false);
    if !valid {
        return None;
    }
    #[cfg(debug_assertions)]
    log_download_handler(handler, vtable, body_address);
    // SAFETY: `body_address` is the executable streaming body slot for
    // `(handler, request_handle, CUtlBuffer&)` on this architecture.
    let body: DownloadBody = unsafe { std::mem::transmute(body_address) };
    Some(DownloadHandler {
        handler: handler as *mut c_void,
        body,
    })
}

#[cfg(debug_assertions)]
fn log_download_handler(handler: usize, vtable: usize, run: usize) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::AcqRel) {
        info!(
            handler = format_args!("{handler:#x}"),
            vtable = format_args!("{vtable:#x}"),
            run = format_args!("{run:#x}"),
            "cloud-http-layout: download handler"
        );
    }
}

/// Hand a downloaded body to Steam's admitted streaming callback.
unsafe fn invoke_download_handler(
    handle: *mut c_void,
    handler: DownloadHandler,
    body: &[u8],
) -> Result<(), vapor_forge_cloud_core::BackendError> {
    let put = i32::try_from(body.len()).map_err(|_| {
        vapor_forge_cloud_core::BackendError::new("local download exceeds CUtlBuffer range", false)
    })?;
    let buffer = UtlBufferView {
        data: body.as_ptr(),
        reserved: [0; 12],
        put,
    };
    // SAFETY: `handler` and `handle` belong to the admitted live request, and
    // the buffer view remains readable for the synchronous callback.
    unsafe { (handler.body)(handler.handler, handle, &buffer) };
    Ok(())
}

/// One-shot dump of the live request handle, so the offsets this module relies
/// on can be read off a running client instead of inferred from a sample.
///
/// # Safety
/// `job` and `request` must be the live objects from the Start callback.
#[cfg(debug_assertions)]
unsafe fn log_handle_layout(job: *mut c_void, request: *mut c_void, layout: &HttpLayout) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if job.is_null() || LOGGED.swap(true, Ordering::AcqRel) {
        return;
    }
    // The handle is 0x64 bytes on i686 and 0x90 on x86_64.
    let words = if cfg!(target_pointer_width = "64") {
        0x90 / 4
    } else {
        0x64 / 4
    };
    // SAFETY: the handle owns at least this many bytes, per its own allocation
    // size at both call sites of Start.
    let Some(handle) = (0..words)
        .map(|index| {
            read_process_value::<u32>((job as usize).checked_add(index * 4)?)
                .map(|value| format!("{index:02x}:{value:08x}"))
        })
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    info!(
        job = format_args!("{job:p}"),
        request = format_args!("{request:p}"),
        words = %handle.join(" "),
        "cloud-http-layout: request handle"
    );
    for offset in [layout.job_response, layout.job_response + 4] {
        let Some(address) = (job as usize).checked_add(offset) else {
            continue;
        };
        let Some(slot) = read_process_value::<usize>(address) else {
            continue;
        };
        if slot < 0x1000 {
            continue;
        }
        // SAFETY: the slot holds a heap pointer; the objects at both candidate
        // offsets are larger than the window read here.
        let Some(fields) = (0..8)
            .map(|index| {
                read_process_value::<u32>(slot.checked_add(index * 4)?)
                    .map(|value| format!("{:02x}:{value:08x}", index * 4))
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        info!(
            offset = format_args!("0x{offset:x}"),
            object = format_args!("0x{slot:x}"),
            fields = %fields.join(" "),
            "cloud-http-layout: handle slot"
        );
    }
}

/// Range the status field can hold before a transfer has run. The constructor
/// writes 500 and the live client is observed to reach `Start` with 0; either
/// way an offset that has drifted onto a pointer, a refcount or a size reads far
/// outside this, which is the whole point of checking.
const RESPONSE_STATUS_RANGE: std::ops::RangeInclusive<i32> = 0..=599;

/// The handle's response status field, but only once it has been confirmed to
/// still hold the constructor's own value.
///
/// This is the check that would have caught the i686 offsets being wrong: the
/// pair used to resolve to a node tree root inside the request instead, which
/// reads as a heap pointer, nowhere near a status code.
///
/// # Safety
/// `job` must be null or the live request handle from the Start callback.
unsafe fn unset_response_status(
    job: *mut c_void,
    request: *mut c_void,
    layout: &HttpLayout,
) -> Option<*mut i32> {
    if job.is_null() || request.is_null() {
        return None;
    }
    let base = job as usize;
    let owned_request: usize = read_process_value(base.checked_add(layout.job_request)?)?;
    if owned_request != request as usize {
        warn!("cloud-http: request handle layout mismatch, declining to intercept");
        return None;
    }
    let complete: u8 = read_process_value(base.checked_add(layout.job_complete)?)?;
    let success: u8 = read_process_value(base.checked_add(layout.job_success)?)?;
    if complete > 1 || success > 1 {
        warn!("cloud-http: request flags are invalid, declining to intercept");
        return None;
    }
    let response: usize = read_process_value(base.checked_add(layout.job_response)?)?;
    if response == 0 {
        warn!("cloud-http: request handle carries no response, declining to intercept");
        return None;
    }
    let status_address = response.checked_add(layout.response_status)?;
    let current: i32 = read_process_value(status_address)?;
    if !RESPONSE_STATUS_RANGE.contains(&current) {
        warn!(
            current,
            "cloud-http: response status field is not a status code, declining to intercept"
        );
        return None;
    }
    vapor_forge_memory::current_process_ranges_match(&[
        vapor_forge_memory::ProcessRangeQuery {
            address: base.checked_add(layout.job_complete)?,
            len: layout.job_success - layout.job_complete + 1,
            read: Some(true),
            write: Some(true),
            execute: None,
            file_backed: false,
        },
        vapor_forge_memory::ProcessRangeQuery {
            address: status_address,
            len: std::mem::size_of::<i32>(),
            read: Some(true),
            write: Some(true),
            execute: None,
            file_backed: false,
        },
    ])
    .unwrap_or(false)
    .then_some(status_address as *mut i32)
}

/// Mark an HTTP job complete with a synthesized status, so the yielding wait in
/// EYielding{Upload,Download}File returns immediately without any network I/O.
///
/// # Safety
/// `job` must be the live request handle from the Start callback and `status`
/// must be the slot [`unset_response_status`] returned for it.
unsafe fn complete_job(job: *mut c_void, layout: &HttpLayout, status: *mut i32, success: bool) {
    // SAFETY: the slot was confirmed to hold the constructor's own sentinel.
    // EYielding* requires 200..=299.
    unsafe { status.write_unaligned(if success { 200 } else { 500 }) };
    // SAFETY: the success/complete flags are single bytes at the confirmed
    // offsets within the live handle; the wait fast-paths off them.
    unsafe {
        job.cast::<u8>()
            .add(layout.job_success)
            .write(u8::from(success));
        job.cast::<u8>().add(layout.job_complete).write(1);
    }
}

fn read_string(address: usize) -> Option<String> {
    if address == 0 {
        return Some(String::new());
    }
    let mut bytes = [0_u8; 2048];
    let read = read_process_into(address, &mut bytes)?;
    let end = bytes[..read].iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&bytes[..end]).ok().map(str::to_owned)
}

trait ProcessValue: Copy {}
impl ProcessValue for u8 {}
impl ProcessValue for i32 {}
impl ProcessValue for u32 {}
impl ProcessValue for usize {}
impl ProcessValue for [usize; 2] {}

fn read_process_value<T: ProcessValue>(address: usize) -> Option<T> {
    if address == 0 {
        return None;
    }
    let mut value = MaybeUninit::<T>::uninit();
    let local = libc::iovec {
        iov_base: value.as_mut_ptr().cast::<c_void>(),
        iov_len: std::mem::size_of::<T>(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: std::mem::size_of::<T>(),
    };
    // SAFETY: the local iovec points to writable MaybeUninit storage. The kernel
    // validates the remote current-process address and reports failure/short read.
    let read = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    if read != std::mem::size_of::<T>() as isize {
        return None;
    }
    // SAFETY: an exact read initialized every byte of T and T: Copy.
    Some(unsafe { value.assume_init() })
}

fn read_process_bytes(address: usize, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).ok()?;
    bytes.resize(len, 0);
    let read = read_process_into(address, &mut bytes)?;
    (read == len).then_some(bytes)
}

fn read_process_into(address: usize, destination: &mut [u8]) -> Option<usize> {
    if address == 0 || destination.is_empty() {
        return None;
    }
    let local = libc::iovec {
        iov_base: destination.as_mut_ptr().cast::<c_void>(),
        iov_len: destination.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: destination.len(),
    };
    // SAFETY: destination is writable for its full length; the kernel validates
    // the remote range instead of letting Rust dereference it.
    let read = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    (read > 0).then_some(read as usize)
}
