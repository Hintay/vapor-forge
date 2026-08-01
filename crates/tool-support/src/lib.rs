#![forbid(unsafe_code)]

//! Input parsing shared by the developer tool binaries.
//!
//! The tools all accept the same loosely-specified hex input — whatever a user
//! pastes out of `xxd`, a debug log, or a `key=value` dump — so the tolerant
//! parser lives here instead of being re-derived per tool.

use std::fmt::Write;

/// Parse bytes out of a hex dump.
///
/// Deliberately permissive, because the input is whatever the user pasted:
/// leading `xxd`-style offsets are dropped, `0x` prefixes and bracketing
/// punctuation are stripped, `key=value` tokens keep only the value, and any
/// token that is not an even-length run of hex digits is skipped. Trailing
/// ASCII columns from `xxd` therefore fall away on their own.
pub fn parse_hex_dump(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();

    for line in input.lines() {
        let line = strip_offset(line.trim());
        for raw in line.split_whitespace() {
            let token = raw
                .trim_matches(|c: char| matches!(c, ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')'));
            if token.is_empty() || token.ends_with(':') {
                continue;
            }
            let token = token
                .rsplit_once('=')
                .map(|(_, value)| value)
                .unwrap_or(token);
            let token = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
                .unwrap_or(token);
            if token.len() == 2 && token.as_bytes().iter().all(u8::is_ascii_hexdigit) {
                out.push(byte_from_hex(token)?);
            } else if token.len() > 2
                && token.len() % 2 == 0
                && token.as_bytes().iter().all(u8::is_ascii_hexdigit)
            {
                for index in (0..token.len()).step_by(2) {
                    out.push(byte_from_hex(&token[index..index + 2])?);
                }
            }
        }
    }

    if out.is_empty() {
        Err("hex input did not contain any bytes".to_owned())
    } else {
        Ok(out)
    }
}

/// Accept both decimal and `0x`-prefixed hexadecimal.
pub fn parse_u32(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|error| format!("invalid u32 {value:?}: {error}"))
    } else {
        value
            .parse::<u32>()
            .map_err(|error| format!("invalid u32 {value:?}: {error}"))
    }
}

/// Accept both decimal and `0x`-prefixed hexadecimal.
pub fn parse_usize(value: &str) -> Result<usize, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        usize::from_str_radix(hex, 16).map_err(|error| format!("invalid usize {value:?}: {error}"))
    } else {
        value
            .parse::<usize>()
            .map_err(|error| format!("invalid usize {value:?}: {error}"))
    }
}

/// Lower-case hex with no separators, the form the tools echo back.
pub fn hex_compact(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Drop an `xxd`-style hex offset prefix such as `00000010:`.
fn strip_offset(line: &str) -> &str {
    let Some((prefix, rest)) = line.split_once(':') else {
        return line;
    };
    if !prefix.is_empty() && prefix.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        rest
    } else {
        line
    }
}

fn byte_from_hex(hex: &str) -> Result<u8, String> {
    u8::from_str_radix(hex, 16).map_err(|error| format!("invalid hex byte {hex:?}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xxd_style_dump_and_drops_the_offset_column() {
        let dump = "00000000: 0102 0304  ....\n00000004: 05\n";
        assert_eq!(parse_hex_dump(dump).unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn parses_key_value_and_bracketed_tokens() {
        assert_eq!(
            parse_hex_dump("token=0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(parse_hex_dump("[0x01, 0x02]").unwrap(), vec![1, 2]);
    }

    #[test]
    fn skips_tokens_that_are_not_whole_hex_bytes() {
        // "abc" is odd-length and "zz" is not hex, so only the real byte lands.
        assert_eq!(parse_hex_dump("abc zz ff").unwrap(), vec![0xff]);
    }

    #[test]
    fn input_without_any_bytes_is_an_error() {
        assert!(parse_hex_dump("").is_err());
        assert!(parse_hex_dump("no hex here\n").is_err());
    }

    #[test]
    fn a_non_hex_prefix_is_not_mistaken_for_an_offset() {
        // "note" is not hex, so the line keeps its "note:" prefix and yields
        // only the trailing byte.
        assert_eq!(parse_hex_dump("note: 0a").unwrap(), vec![0x0a]);
    }

    #[test]
    fn numbers_accept_decimal_and_hex() {
        assert_eq!(parse_u32("480").unwrap(), 480);
        assert_eq!(parse_u32("0x1E0").unwrap(), 480);
        assert_eq!(parse_usize("0X10").unwrap(), 16);
        assert!(parse_u32("").is_err());
        assert!(parse_usize("0xzz").is_err());
    }

    #[test]
    fn hex_compact_round_trips_through_the_parser() {
        let bytes = vec![0x00, 0x0f, 0xff, 0x10];
        assert_eq!(hex_compact(&bytes), "000fff10");
        assert_eq!(parse_hex_dump(&hex_compact(&bytes)).unwrap(), bytes);
    }
}
