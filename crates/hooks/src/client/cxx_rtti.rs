//! C++ object headers for the objects VF hands to Steam.
//!
//! Steam treats these as polymorphic C++ objects. Some builds read
//! `typeid(*object).name()` before dispatching to them (for example
//! `CInternalCallbacks::DispatchCallback` in 1794536281), which follows the
//! Itanium ABI layout: the word before the address point is the type_info
//! pointer and the word before that is offset-to-top. A bare function-pointer
//! table would hand Steam whatever memory precedes it.

use core::ffi::{c_char, c_void, CStr};

/// The part of `std::type_info` Steam reads: the name pointer after the
/// type_info's own vtable pointer. Nothing calls through that vtable pointer.
#[repr(C)]
pub(crate) struct TypeInfo {
    vtable: *const c_void,
    name: *const c_char,
}

// SAFETY: both fields point to immutable process-lifetime data.
unsafe impl Sync for TypeInfo {}

impl TypeInfo {
    /// `name` is an Itanium-mangled type name without a leading `*`.
    pub(crate) const fn new(name: &'static CStr) -> Self {
        Self {
            vtable: core::ptr::null(),
            name: name.as_ptr(),
        }
    }

    #[cfg(test)]
    pub(crate) fn name(&self) -> &'static CStr {
        // SAFETY: `name` comes from a `&'static CStr`.
        unsafe { CStr::from_ptr(self.name) }
    }
}

/// A primary vtable: offset-to-top, the type_info pointer, then the virtual
/// functions. Objects store [`CxxVtable::address_point`].
#[repr(C)]
pub(crate) struct CxxVtable<T> {
    offset_to_top: isize,
    type_info: *const TypeInfo,
    entries: T,
}

// SAFETY: the type_info pointer refers to an immutable static, and the entries
// are function pointers.
unsafe impl<T: Sync> Sync for CxxVtable<T> {}

impl<T> CxxVtable<T> {
    pub(crate) const fn new(type_info: &'static TypeInfo, entries: T) -> Self {
        Self {
            offset_to_top: 0,
            type_info,
            entries,
        }
    }

    /// The address an object's vtable pointer must hold.
    pub(crate) const fn address_point(&'static self) -> *const T {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TYPE: TypeInfo = TypeInfo::new(c"N10VaporForge4TestE");
    static VTABLE: CxxVtable<[usize; 2]> = CxxVtable::new(&TYPE, [1, 2]);

    #[test]
    fn address_point_is_preceded_by_type_info_and_offset_to_top() {
        let words = VTABLE.address_point().cast::<usize>();
        // SAFETY: `CxxVtable` is `repr(C)`; the two words before the entries
        // are its own fields.
        let (type_info, offset_to_top, first) = unsafe {
            (
                *words.sub(1) as *const TypeInfo,
                *words.sub(2) as isize,
                *words,
            )
        };
        assert_eq!(offset_to_top, 0);
        assert_eq!(first, 1);
        // SAFETY: the pointer was just read from the static vtable.
        let name = unsafe { &*type_info }.name();
        assert_eq!(name, c"N10VaporForge4TestE");
        assert_ne!(name.to_bytes()[0], b'*');
    }
}
