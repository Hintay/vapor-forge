// NT API type definitions for Wine's PE ntdll.

pub const STATUS_SUCCESS: i32 = 0;

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub max_length: u16,
    pub buffer: *mut u16,
}

impl UnicodeString {
    pub fn as_slice(&self) -> &[u16] {
        if self.buffer.is_null() || self.length == 0 {
            return &[];
        }
        let chars = self.length as usize / 2;
        // SAFETY: caller guarantees buffer is valid for length bytes.
        unsafe { std::slice::from_raw_parts(self.buffer, chars) }
    }
}

// LdrLoadDll uses the Microsoft x64 calling convention (win64/ms_abi).
pub type LdrLoadDllFn = unsafe extern "win64" fn(
    search_path: *mut u16,
    flags: u32,
    dll_name: *mut UnicodeString,
    base_address: *mut *mut core::ffi::c_void,
) -> i32;
