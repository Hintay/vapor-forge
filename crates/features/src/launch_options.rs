//! Matching against a Steam app's launch-option string.

/// Word-boundary substring match for launch option flags.
///
/// A match is valid when the needle is surrounded by whitespace, quotes, or
/// string boundaries, preventing "-onlinefixfoo" from matching "-onlinefix".
pub(crate) fn flag_appears_in(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    let mut pos = 0;
    while pos + n.len() <= h.len() {
        if let Some(found) = haystack[pos..].find(needle) {
            let abs = pos + found;
            let before = if abs > 0 { h[abs - 1] } else { b' ' };
            let after_pos = abs + n.len();
            let after = if after_pos < h.len() { h[after_pos] } else { 0 };
            let sep = |b: u8| matches!(b, b' ' | b'\t' | b'"' | b'\'' | 0);
            if sep(before) && sep(after) {
                return true;
            }
            pos = abs + n.len();
        } else {
            break;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_word_boundary() {
        assert!(flag_appears_in("-onlinefix -other", "-onlinefix"));
        assert!(flag_appears_in("-onlinefix", "-onlinefix"));
        assert!(!flag_appears_in("-onlinefixfoo", "-onlinefix"));
        assert!(!flag_appears_in("foo-onlinefix", "-onlinefix"));
        assert!(flag_appears_in("\"-onlinefix\"", "-onlinefix"));
    }

    #[test]
    fn an_empty_flag_never_matches() {
        assert!(!flag_appears_in("-onlinefix", ""));
        assert!(!flag_appears_in("", ""));
    }
}
