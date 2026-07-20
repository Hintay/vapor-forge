//! Generic detour and VMT hooking mechanics: pattern-resolved trampoline
//! creation, PIC repair, trampoline page protection, and vtable slot swapping.
//!
//! This crate carries no knowledge of Steam's classes, interfaces, or modules;
//! callers supply the target addresses and code region.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod detour;
pub mod original;
pub mod vmt;
