//! Detour on `CHTTPRequestJob::Start` that short-circuits cloud transfers whose
//! target is the process-local sentinel authority.
//!
//! Field offsets are architecture-specific layouts recovered from Steam's
//! request constructor, body setter, yielding wait path, and download callback.
//! The detour only acts on requests the local Cloud adapter itself issued
//! (sentinel authority); every other request is forwarded unchanged.

use core::ffi::{c_char, c_void, CStr};

use tracing::{debug, info, warn};
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::detour_or_return;

pub(crate) const HTTP_JOB_START_NAME: &str = "CHTTPRequestJob::Start";

pub(crate) type HttpJobStartFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, bool);

pub(crate) static mut HTTP_JOB_START_DETOUR: Option<Detour<HttpJobStartFn>> = None;

struct HttpLayout {
    request_host: usize,
    request_path: usize,
    request_body_data: usize,
    request_body_size: usize,
    request_upload_handler: usize,
    request_download_handler: usize,
    job_complete: usize,
    job_success: usize,
    job_response: usize,
    response_status: usize,
    download_closure: usize,
    download_callback: usize,
}

#[cfg(target_pointer_width = "64")]
const HTTP_LAYOUT: HttpLayout = HttpLayout {
    request_host: 0x80,
    request_path: 0x88,
    request_body_data: 0x98,
    request_body_size: 0xac,
    request_upload_handler: 0xd8,
    request_download_handler: 0xe0,
    job_complete: 0x22,
    job_success: 0x23,
    job_response: 0x70,
    response_status: 0x0c,
    download_closure: 0x58,
    download_callback: 0x70,
};

#[cfg(target_pointer_width = "32")]
const HTTP_LAYOUT: HttpLayout = HttpLayout {
    request_host: 0x58,
    request_path: 0x5c,
    request_body_data: 0x64,
    request_body_size: 0x74,
    request_upload_handler: 0x90,
    request_download_handler: 0x94,
    job_complete: 0x16,
    job_success: 0x17,
    job_response: 0x50,
    response_status: 0x0c,
    download_closure: 0x2c,
    download_callback: 0x38,
};

pub(crate) unsafe extern "C" fn hk_http_job_start(
    manager: *mut c_void,
    job: *mut c_void,
    request: *mut c_void,
    flag: bool,
) {
    // This detour runs on every HTTP request; reject non-cloud ones before any
    // allocation.
    // SAFETY: `request` is the live CHTTPRequestHandle from this callback.
    if !unsafe { request_is_cloud_related(request) } {
        let original = detour_or_return!(HTTP_JOB_START_NAME, HTTP_JOB_START_DETOUR);
        // SAFETY: forwarding this callback's own arguments to the original Start.
        unsafe { original(manager, job, request, flag) };
        return;
    }

    // SAFETY: `request` is the live CHTTPRequestHandle Steam passed to this
    // Start callback; it stays valid for the duration of the call.
    if let Some(probe) = unsafe { probe_request(request) } {
        // SAFETY: `request` and `job` are the live objects from this callback;
        // probe was read from the same request.
        if let Some(outcome) = unsafe { intercept_local_transfer(request, job, &probe) } {
            match outcome {
                Ok(()) => info!(
                    host = probe.host,
                    path = probe.path,
                    body_size = probe.body_size,
                    "cloud-http: completed local transfer in process"
                ),
                Err(error) => warn!(
                    host = probe.host,
                    path = probe.path,
                    %error,
                    "cloud-http: local transfer failed"
                ),
            }
            return;
        }
        if crate::netpacket::is_cloud_transfer_target(&probe.host, &probe.path) {
            let logged_path = probe.path.split('?').next().unwrap_or(&probe.path);
            info!(
                host = probe.host,
                path = logged_path,
                request = format_args!("0x{:x}", request as usize),
                job = format_args!("0x{:x}", job as usize),
                body = format_args!("0x{:x}", probe.body_data),
                body_size = probe.body_size,
                upload_handler = probe.upload_handler != 0,
                download_handler = probe.download_handler != 0,
                "cloud-http-probe: yielding transfer request"
            );
        }
    } else {
        debug!(
            request = format_args!("0x{:x}", request as usize),
            "cloud-http-probe: request layout was unreadable"
        );
    }

    let original = detour_or_return!(HTTP_JOB_START_NAME, HTTP_JOB_START_DETOUR);
    // SAFETY: forwarding this callback's own arguments to the original Start.
    unsafe { original(manager, job, request, flag) };
}

struct RequestProbe {
    host: String,
    path: String,
    body_data: usize,
    body_size: i32,
    upload_handler: usize,
    download_handler: usize,
}

/// Whether the request targets the local sentinel or a cloud transfer target.
/// Reads host/path as borrowed `&str` so the common case does not allocate.
///
/// # Safety
/// `request` must be null or a live CHTTPRequestHandle with the confirmed
/// layout for the current architecture.
unsafe fn request_is_cloud_related(request: *mut c_void) -> bool {
    if request.is_null() {
        return false;
    }
    let bytes = request.cast::<u8>();
    // SAFETY: host is a `const char*` field at the confirmed offset; the borrow
    // is only used within this call.
    let Some(host) = (unsafe { borrow_c_str(bytes.add(HTTP_LAYOUT.request_host)) }) else {
        return false;
    };
    if host.eq_ignore_ascii_case(vapor_forge_cloud_local::LOCAL_TRANSFER_AUTHORITY) {
        return true;
    }
    // SAFETY: path is a `const char*` field at the confirmed offset.
    let Some(path) = (unsafe { borrow_c_str(bytes.add(HTTP_LAYOUT.request_path)) }) else {
        return false;
    };
    crate::netpacket::is_cloud_transfer_target(host, path)
}

/// Read a `const char*` field as a borrowed `&str`. A null pointer yields "".
///
/// # Safety
/// `field` must point to a readable pointer slot; the pointed-to string, if
/// non-null, must be NUL-terminated and outlive `'a`.
unsafe fn borrow_c_str<'a>(field: *const u8) -> Option<&'a str> {
    // SAFETY: `field` addresses a pointer-sized slot in the live request object.
    let value = unsafe { field.cast::<*const c_char>().read_unaligned() };
    if value.is_null() {
        return Some("");
    }
    // SAFETY: `value` is a live, NUL-terminated C string owned by the request.
    unsafe { CStr::from_ptr(value) }.to_str().ok()
}

/// Read the transfer-relevant fields out of a CHTTPRequestHandle.
///
/// # Safety
/// `request` must be null or point to a live CHTTPRequestHandle with the
/// confirmed layout for the current architecture.
unsafe fn probe_request(request: *mut c_void) -> Option<RequestProbe> {
    if request.is_null() {
        return None;
    }
    let bytes = request.cast::<u8>();
    // SAFETY: host/path are `const char*` fields at the confirmed offsets within
    // the live request object.
    let host = unsafe { read_string_pointer(bytes.add(HTTP_LAYOUT.request_host)) }?;
    // SAFETY: as above, for the path field.
    let path = unsafe { read_string_pointer(bytes.add(HTTP_LAYOUT.request_path)) }?;
    // SAFETY: the embedded CUtlBuffer's data pointer sits at the confirmed
    // offset inside the live request; read_unaligned tolerates any alignment.
    let body_data = unsafe {
        bytes
            .add(HTTP_LAYOUT.request_body_data)
            .cast::<usize>()
            .read_unaligned()
    };
    // SAFETY: the CUtlBuffer's put (write length) field at the confirmed offset.
    let body_size = unsafe {
        bytes
            .add(HTTP_LAYOUT.request_body_size)
            .cast::<i32>()
            .read_unaligned()
    };
    // SAFETY: upload response handler pointer at the confirmed offset.
    let upload_handler = unsafe {
        bytes
            .add(HTTP_LAYOUT.request_upload_handler)
            .cast::<usize>()
            .read_unaligned()
    };
    // SAFETY: download response handler pointer at the confirmed offset.
    let download_handler = unsafe {
        bytes
            .add(HTTP_LAYOUT.request_download_handler)
            .cast::<usize>()
            .read_unaligned()
    };
    Some(RequestProbe {
        host,
        path,
        body_data,
        body_size,
        upload_handler,
        download_handler,
    })
}

/// Serve a request locally when its host/path is a folder-store sentinel.
///
/// Returns `None` when the request is not local (caller forwards it to Steam),
/// otherwise the outcome of the in-process transfer.
///
/// # Safety
/// `request` and `job` must be the live objects from the Start callback, and
/// `probe` must have been read from `request`.
unsafe fn intercept_local_transfer(
    request: *mut c_void,
    job: *mut c_void,
    probe: &RequestProbe,
) -> Option<Result<(), vapor_forge_cloud_core::BackendError>> {
    let body = if probe.body_size <= 0 {
        &[][..]
    } else {
        if probe.body_data == 0 {
            return Some(Err(vapor_forge_cloud_core::BackendError::new(
                "local upload body pointer is null",
                false,
            )));
        }
        // SAFETY: probe.body_data / body_size come from the request's embedded
        // CUtlBuffer, which holds `body_size` initialized bytes for this upload.
        unsafe {
            std::slice::from_raw_parts(
                probe.body_data as *const u8,
                usize::try_from(probe.body_size).ok()?,
            )
        }
    };
    let outcome = vapor_forge_cloud_local::intercept_transfer(&probe.host, &probe.path, body)?;
    let result = match outcome {
        vapor_forge_cloud_local::LocalTransferOutcome::Upload(result) => result.map(|_| ()),
        vapor_forge_cloud_local::LocalTransferOutcome::Download(result) => {
            // SAFETY: `request` is live and `download_handler` was read from it.
            result.and_then(|body| unsafe {
                inject_download_body(request, probe.download_handler, &body)
            })
        }
    };
    // SAFETY: `job` is the live HTTP job from this callback.
    unsafe { complete_job(job, result.is_ok()) };
    Some(result)
}

/// Minimal view matching the head of Steam's CUtlBuffer: data pointer, then the
/// put (write length) field the download callback reads.
#[repr(C)]
struct UtlBufferView {
    data: *const u8,
    reserved: [u8; 12],
    put: i32,
}

/// Hand a downloaded body to Steam's own download callback so its existing
/// decompress / SHA / write-file path runs unchanged.
///
/// # Safety
/// `request` must be the live request and `handler` must be null or a live
/// download response handler with the confirmed layout.
unsafe fn inject_download_body(
    request: *mut c_void,
    handler: usize,
    body: &[u8],
) -> Result<(), vapor_forge_cloud_core::BackendError> {
    if handler == 0 {
        return Err(vapor_forge_cloud_core::BackendError::new(
            "local download response handler is null",
            false,
        ));
    }
    let put = i32::try_from(body.len()).map_err(|_| {
        vapor_forge_cloud_core::BackendError::new("local download exceeds CUtlBuffer range", false)
    })?;
    // SAFETY: the callback function pointer sits at the confirmed offset within
    // the live handler object.
    let callback_address = unsafe {
        (handler as *const u8)
            .add(HTTP_LAYOUT.download_callback)
            .cast::<usize>()
            .read_unaligned()
    };
    if callback_address == 0 {
        return Err(vapor_forge_cloud_core::BackendError::new(
            "local download callback is null",
            false,
        ));
    }
    type DownloadCallback = unsafe extern "C" fn(*mut c_void, *mut c_void, *const UtlBufferView);
    // SAFETY: callback_address is the type-erased download callback for this
    // handler; its ABI matches DownloadCallback.
    let callback: DownloadCallback = unsafe { std::mem::transmute(callback_address) };
    let buffer = UtlBufferView {
        data: body.as_ptr(),
        reserved: [0; 12],
        put,
    };
    let closure = (handler as *mut u8)
        .wrapping_add(HTTP_LAYOUT.download_closure)
        .cast::<c_void>();
    // SAFETY: `closure` is the handler's type-erased state, `request` is live,
    // and `buffer` outlives the call. The callback copies `buffer` into Steam's
    // own destination buffer.
    unsafe { callback(closure, request, &buffer) };
    Ok(())
}

/// Mark an HTTP job complete with a synthesized status, so the yielding wait in
/// EYielding{Upload,Download}File returns immediately without any network I/O.
///
/// # Safety
/// `job` must be null or the live HTTP job from the Start callback.
unsafe fn complete_job(job: *mut c_void, success: bool) {
    if job.is_null() {
        return;
    }
    let bytes = job.cast::<u8>();
    // SAFETY: the response pointer sits at the confirmed offset within the live
    // job object.
    let response = unsafe {
        bytes
            .add(HTTP_LAYOUT.job_response)
            .cast::<*mut u8>()
            .read_unaligned()
    };
    if !response.is_null() {
        // SAFETY: `response` is the job's live response object; the HTTP status
        // is an i32 at the confirmed offset. EYielding* requires 200..=299.
        unsafe {
            response
                .add(HTTP_LAYOUT.response_status)
                .cast::<i32>()
                .write_unaligned(if success { 200 } else { 500 });
        }
    }
    // SAFETY: the success/complete flags are single bytes at the confirmed
    // offsets within the live job; the wait fast-paths off them.
    unsafe {
        bytes.add(HTTP_LAYOUT.job_success).write(u8::from(success));
        bytes.add(HTTP_LAYOUT.job_complete).write(1);
    }
}

/// Read a `const char*` field and copy it into an owned `String`.
///
/// # Safety
/// `field` must point to a readable `*const c_char` slot; the pointed-to string,
/// if non-null, must be NUL-terminated.
unsafe fn read_string_pointer(field: *const u8) -> Option<String> {
    // SAFETY: `field` addresses a pointer-sized slot in the live request object.
    let value = unsafe { field.cast::<*const c_char>().read_unaligned() };
    if value.is_null() {
        return Some(String::new());
    }
    // SAFETY: `value` is a live, NUL-terminated C string owned by the request.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .ok()
        .map(str::to_owned)
}
