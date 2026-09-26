//! Calling convention of Steam's environment-map writer.
//!
//! `SetEnvString` took `(envMap, key, value)` up to public build 1788652215 and
//! `(envMap, key, value, flag, separator)` from 1790380355 on, on both
//! architectures. The hook both calls this function and detours it, so getting
//! the count wrong would hand a five-parameter callee three arguments.
//!
//! The count is read from the function itself rather than inferred from which
//! pattern matched: an argument a caller never passes would be read from the
//! caller's frame or a stale register, so a body that reads the fourth and fifth
//! is one that is passed them.

use crate::arg_flow;

/// Bytes decoded from the entry. The argument reads all sit in the opening
/// checks, well inside this.
const WINDOW: usize = 0x80;

/// The separator every observed call site passes, `':'`.
pub const PATH_SEPARATOR: u32 = 0x3a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvWriterAbi {
    /// `(envMap, key, value)`.
    KeyValue,
    /// `(envMap, key, value, flag, separator)`.
    KeyValueSeparator,
}

/// Classify the writer at `offset`, or `None` if its shape is neither form.
pub fn decode_abi(bitness: u32, code: &[u8], offset: usize) -> Option<EnvWriterAbi> {
    let trace = arg_flow::trace(bitness, code, offset, WINDOW);
    // The key is the one argument both forms must reach for.
    if !trace.arguments_read.contains(&1) {
        return None;
    }
    let extras = [3u8, 4]
        .iter()
        .filter(|position| trace.arguments_read.contains(position))
        .count();
    match extras {
        0 => Some(EnvWriterAbi::KeyValue),
        2 => Some(EnvWriterAbi::KeyValueSeparator),
        // One of the two alone means the walk lost track rather than a third
        // convention; refuse instead of guessing.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both conventions, captured from the entry of the real writer in each
    /// build: i686 and x86_64, before and after the parameters were added.
    const BUILDS: [(&str, u32, &[u8], EnvWriterAbi); 4] = [
        (
            "x86 1788652215",
            32,
            include_bytes!("testdata/env_writer/x86_1788652215.bin"),
            EnvWriterAbi::KeyValue,
        ),
        (
            "x86 1790380355",
            32,
            include_bytes!("testdata/env_writer/x86_1790380355.bin"),
            EnvWriterAbi::KeyValueSeparator,
        ),
        (
            "x86_64 1788652215",
            64,
            include_bytes!("testdata/env_writer/x86_64_1788652215.bin"),
            EnvWriterAbi::KeyValue,
        ),
        (
            "x86_64 1790380355",
            64,
            include_bytes!("testdata/env_writer/x86_64_1790380355.bin"),
            EnvWriterAbi::KeyValueSeparator,
        ),
    ];

    #[test]
    fn classifies_every_captured_build() {
        for (build, bitness, code, expected) in BUILDS {
            assert_eq!(decode_abi(bitness, code, 0), Some(expected), "{build}");
        }
    }

    #[test]
    fn rejects_a_body_that_never_reads_the_key() {
        // `ret` on both architectures: nothing is read, so nothing is claimed.
        assert_eq!(decode_abi(32, &[0xc3], 0), None);
        assert_eq!(decode_abi(64, &[0xc3], 0), None);
    }
}
