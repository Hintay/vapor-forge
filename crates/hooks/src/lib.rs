#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod pic_thunk;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum HookError {
    #[error("no PIC thunk call found in the scanned region")]
    NoPicThunkFound,
    #[error("PIC thunk uses an unsupported register (reg_field={0})")]
    UnsupportedThunkRegister(u8),
    #[error("mprotect failed: {0}")]
    MprotectFailed(i32),
}
