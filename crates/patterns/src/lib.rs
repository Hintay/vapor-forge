#![forbid(unsafe_code)]

use thiserror::Error;

pub mod elf;
pub mod vtable_scan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatternToken {
    Byte(u8),
    Wildcard,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PatternError {
    #[error("pattern is empty")]
    Empty,
    #[error("invalid pattern token: {0}")]
    InvalidToken(String),
    #[error("pattern has no match")]
    NoMatch,
    #[error("pattern is not unique: found {0} matches")]
    Ambiguous(usize),
    #[error("relative follow target is out of bounds")]
    FollowOutOfBounds,
    #[error("relative follow requires a call/jmp rel32 opcode at the match offset")]
    FollowUnsupportedOpcode,
    #[error("no call target found before RET")]
    NoCallTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pattern {
    tokens: Vec<PatternToken>,
}

impl Pattern {
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let mut tokens = Vec::new();
        for raw in text.split_whitespace() {
            let token = match raw {
                "?" | "??" => PatternToken::Wildcard,
                hex => {
                    let value = u8::from_str_radix(hex, 16)
                        .map_err(|_| PatternError::InvalidToken(hex.to_owned()))?;
                    PatternToken::Byte(value)
                }
            };
            tokens.push(token);
        }

        if tokens.is_empty() {
            return Err(PatternError::Empty);
        }

        Ok(Self { tokens })
    }

    pub fn tokens(&self) -> &[PatternToken] {
        &self.tokens
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub fn matches_at(&self, haystack: &[u8], offset: usize) -> bool {
        let Some(window) = haystack.get(offset..offset + self.tokens.len()) else {
            return false;
        };
        self.tokens
            .iter()
            .zip(window)
            .all(|(token, &byte)| match token {
                PatternToken::Byte(expected) => *expected == byte,
                PatternToken::Wildcard => true,
            })
    }

    pub fn find_all(&self, haystack: &[u8]) -> Vec<usize> {
        if haystack.len() < self.tokens.len() {
            return Vec::new();
        }
        let limit = haystack.len() - self.tokens.len();

        let Some((anchor_index, anchor_bytes)) = self.longest_literal_run() else {
            return (0..=limit).collect();
        };

        let mut matches = Vec::new();
        let finder = memchr::memmem::Finder::new(&anchor_bytes);
        let mut search_from = 0usize;
        while let Some(relative) = finder.find(&haystack[search_from..]) {
            let anchor_offset = search_from + relative;
            if anchor_offset >= anchor_index {
                let candidate = anchor_offset - anchor_index;
                if candidate <= limit && self.matches_at(haystack, candidate) {
                    matches.push(candidate);
                }
            }
            search_from = anchor_offset + 1;
        }

        matches
    }

    pub fn find_unique(&self, haystack: &[u8]) -> Result<usize, PatternError> {
        let matches = self.find_all(haystack);
        match matches.len() {
            0 => Err(PatternError::NoMatch),
            1 => Ok(matches[0]),
            n => Err(PatternError::Ambiguous(n)),
        }
    }

    fn longest_literal_run(&self) -> Option<(usize, Vec<u8>)> {
        let mut best_start = 0usize;
        let mut best_len = 0usize;
        let mut current_start = 0usize;
        let mut current_len = 0usize;

        for (idx, token) in self.tokens.iter().enumerate() {
            match token {
                PatternToken::Byte(_) => {
                    if current_len == 0 {
                        current_start = idx;
                    }
                    current_len += 1;
                    if current_len > best_len {
                        best_start = current_start;
                        best_len = current_len;
                    }
                }
                PatternToken::Wildcard => {
                    current_len = 0;
                }
            }
        }

        if best_len == 0 {
            return None;
        }

        let bytes = self.tokens[best_start..best_start + best_len]
            .iter()
            .map(|token| match token {
                PatternToken::Byte(byte) => *byte,
                PatternToken::Wildcard => unreachable!("literal run contains no wildcards"),
            })
            .collect();
        Some((best_start, bytes))
    }
}

/// Scan backward from `body_offset` to find a function prologue.
///
/// The prologue bytes are stored in reverse order:
/// "scan order", i.e. `prologue[0]` is the byte **closest** to the body
/// (highest address), and `prologue[N-1]` is the function entry byte
/// (lowest address). The returned offset is the function entry point.
///
/// This mirrors the C++ logic:
/// ```text
/// for i in 0..max_scan:
///     for j in 0..prologue.len():
///         check haystack[body_offset - i - j] == prologue[j]
///     if all match: return body_offset - i - prologue.len() + 1
/// ```
pub fn find_prologue_upwards(
    haystack: &[u8],
    body_offset: usize,
    prologue: &[u8],
    max_scan: usize,
) -> Result<usize, PatternError> {
    if prologue.is_empty() {
        return Err(PatternError::Empty);
    }

    let limit = max_scan.min(body_offset);
    for i in 0..=limit {
        let anchor = body_offset - i;
        let mut found = true;
        for (j, &expected) in prologue.iter().enumerate() {
            if anchor < j {
                found = false;
                break;
            }
            if haystack[anchor - j] != expected {
                found = false;
                break;
            }
        }
        if found {
            // Function entry is at the lowest-addressed prologue byte.
            return Ok(anchor - prologue.len() + 1);
        }
    }

    Err(PatternError::NoMatch)
}

/// Follows an `E8` (call) or `E9` (jmp) rel32 at `match_offset` to its target,
/// returned as a byte offset relative to the start of `haystack`.
pub fn follow_relative_call(haystack: &[u8], match_offset: usize) -> Result<i64, PatternError> {
    const REL32_INSTR_LEN: usize = 5;

    let opcode = *haystack
        .get(match_offset)
        .ok_or(PatternError::FollowOutOfBounds)?;
    if opcode != 0xE8 && opcode != 0xE9 {
        return Err(PatternError::FollowUnsupportedOpcode);
    }

    let disp_bytes = haystack
        .get(match_offset + 1..match_offset + REL32_INSTR_LEN)
        .ok_or(PatternError::FollowOutOfBounds)?;
    let displacement =
        i32::from_le_bytes([disp_bytes[0], disp_bytes[1], disp_bytes[2], disp_bytes[3]]);

    Ok(match_offset as i64 + REL32_INSTR_LEN as i64 + displacement as i64)
}

/// Scan forward from `offset` for up to `max_scan` bytes, find the last
/// `E8 rel32` CALL before the next `C3` RET, and return its target offset
/// relative to the start of `haystack`.
pub fn follow_last_call_before_ret(
    haystack: &[u8],
    offset: usize,
    max_scan: usize,
) -> Result<usize, PatternError> {
    let end = offset.saturating_add(max_scan).min(haystack.len());
    let mut last_call_target = None;

    let mut pos = offset;
    while pos + 5 <= end {
        let byte = haystack[pos];
        if byte == 0xC3 {
            break;
        }
        if byte == 0xE8 {
            let rel = i32::from_le_bytes([
                haystack[pos + 1],
                haystack[pos + 2],
                haystack[pos + 3],
                haystack[pos + 4],
            ]);
            let target = pos as i64 + 5 + rel as i64;
            if target >= 0 && (target as usize) < haystack.len() {
                last_call_target = Some(target as usize);
            }
            pos += 5;
        } else {
            pos += 1;
        }
    }

    last_call_target.ok_or(PatternError::NoCallTarget)
}

// ---------------------------------------------------------------------------
// Pattern registry loaded from TOML file
// ---------------------------------------------------------------------------

pub mod registry;
pub mod scan;

#[cfg(test)]
mod tests {
    use super::{
        find_prologue_upwards, follow_last_call_before_ret, follow_relative_call, Pattern,
        PatternError, PatternToken,
    };

    #[test]
    fn parses_bytes_and_wildcards() {
        let pattern = Pattern::parse("E8 ? ?? 83 c4").expect("pattern should parse");
        assert_eq!(
            pattern.tokens(),
            &[
                PatternToken::Byte(0xE8),
                PatternToken::Wildcard,
                PatternToken::Wildcard,
                PatternToken::Byte(0x83),
                PatternToken::Byte(0xC4),
            ]
        );
    }

    #[test]
    fn rejects_empty_pattern() {
        assert_eq!(Pattern::parse("   "), Err(PatternError::Empty));
    }

    #[test]
    fn rejects_invalid_hex() {
        assert_eq!(
            Pattern::parse("E8 ZZ"),
            Err(PatternError::InvalidToken("ZZ".to_owned()))
        );
    }

    #[test]
    fn finds_all_matches_including_wildcards() {
        let haystack = [0x00, 0x83, 0xC4, 0x90, 0x83, 0x10];
        let pattern = Pattern::parse("83 ?").expect("pattern should parse");
        assert_eq!(pattern.find_all(&haystack), vec![1, 4]);
    }

    #[test]
    fn finds_matches_with_leading_wildcard() {
        let haystack = [0x00, 0x83, 0xC4, 0x90, 0x83, 0x10];
        let pattern = Pattern::parse("? 83").expect("pattern should parse");
        assert_eq!(pattern.find_all(&haystack), vec![0, 3]);
    }

    #[test]
    fn finds_overlapping_literal_anchor_matches() {
        let haystack = [0xAA, 0xAA, 0xAA];
        let pattern = Pattern::parse("AA AA").expect("pattern should parse");
        assert_eq!(pattern.find_all(&haystack), vec![0, 1]);
        assert_eq!(
            pattern.find_unique(&haystack),
            Err(PatternError::Ambiguous(2))
        );
    }

    #[test]
    fn find_unique_returns_single_offset() {
        let haystack = [0x90, 0xE8, 0x01, 0x02, 0x03, 0x04, 0x88];
        let pattern = Pattern::parse("E8 ? ? ? ? 88").expect("pattern should parse");
        assert_eq!(pattern.find_unique(&haystack), Ok(1));
    }

    #[test]
    fn find_unique_rejects_ambiguous() {
        let haystack = [0x83, 0xC4, 0x00, 0x83, 0xC4];
        let pattern = Pattern::parse("83 C4").expect("pattern should parse");
        assert_eq!(
            pattern.find_unique(&haystack),
            Err(PatternError::Ambiguous(2))
        );
    }

    #[test]
    fn find_unique_rejects_no_match() {
        let haystack = [0x00, 0x11, 0x22];
        let pattern = Pattern::parse("DE AD").expect("pattern should parse");
        assert_eq!(pattern.find_unique(&haystack), Err(PatternError::NoMatch));
    }

    #[test]
    fn follows_forward_call_rel32() {
        // E8 03 00 00 00 at offset 0 -> target = 0 + 5 + 3 = 8
        let haystack = [0xE8, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xC3];
        assert_eq!(follow_relative_call(&haystack, 0), Ok(8));
    }

    #[test]
    fn follows_backward_call_rel32() {
        // at offset 10: E8 F6 FF FF FF -> disp = -10 -> target = 10 + 5 - 10 = 5
        let mut haystack = [0x90u8; 16];
        haystack[10] = 0xE8;
        haystack[11] = 0xF6;
        haystack[12] = 0xFF;
        haystack[13] = 0xFF;
        haystack[14] = 0xFF;
        assert_eq!(follow_relative_call(&haystack, 10), Ok(5));
    }

    #[test]
    fn rejects_non_call_opcode() {
        let haystack = [0x90, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(
            follow_relative_call(&haystack, 0),
            Err(PatternError::FollowUnsupportedOpcode)
        );
    }

    #[test]
    fn rejects_truncated_displacement() {
        let haystack = [0xE8, 0x01, 0x02];
        assert_eq!(
            follow_relative_call(&haystack, 0),
            Err(PatternError::FollowOutOfBounds)
        );
    }

    #[test]
    fn finds_prologue_upwards_standard() {
        // Memory layout:
        //   offset 3: 55 89 E5  (push ebp; mov ebp, esp; function prologue)
        //   offset 10: 83 EC 24 (sub esp, 0x24; body pattern match)
        //
        // Prologue bytes in scan order (closest to body first):
        //   [0xE5, 0x89, 0x55]
        // Scanning from body_offset=10 backward:
        //   anchor=10: haystack[10]=0x83 != 0xE5
        //   ...
        //   anchor=5: haystack[5]=0xE5 == [0], haystack[4]=0x89 == [1], haystack[3]=0x55 == [2]
        //   → function entry = 5 - 3 + 1 = 3
        let mut buf = [0x90u8; 20];
        buf[3] = 0x55;
        buf[4] = 0x89;
        buf[5] = 0xE5;
        buf[10] = 0x83;
        buf[11] = 0xEC;
        buf[12] = 0x24;
        let result = find_prologue_upwards(&buf, 10, &[0xE5, 0x89, 0x55], 100);
        assert_eq!(result, Ok(3));
    }

    #[test]
    fn finds_prologue_upwards_four_byte() {
        // Simulate: prologue "53 56 57 55" (scan order = closest to body first)
        // In memory (forward): 55 57 56 53 ... body
        let mut buf = [0x90u8; 30];
        buf[4] = 0x55;
        buf[5] = 0x57;
        buf[6] = 0x56;
        buf[7] = 0x53;
        // body at offset 15
        buf[15] = 0x83;
        buf[16] = 0xEC;
        buf[17] = 0x0C;
        // Scan from 15, prologue [0x53, 0x56, 0x57, 0x55]
        // anchor=7: buf[7]=0x53, buf[6]=0x56, buf[5]=0x57, buf[4]=0x55 → match
        // entry = 7 - 4 + 1 = 4
        let result = find_prologue_upwards(&buf, 15, &[0x53, 0x56, 0x57, 0x55], 100);
        assert_eq!(result, Ok(4));
    }

    #[test]
    fn prologue_not_found_returns_no_match() {
        let buf = [0x90u8; 20];
        let result = find_prologue_upwards(&buf, 15, &[0x55, 0x89, 0xE5], 100);
        assert_eq!(result, Err(PatternError::NoMatch));
    }

    #[test]
    fn prologue_respects_max_scan() {
        // Prologue exists but beyond max_scan distance
        let mut buf = [0x90u8; 30];
        buf[3] = 0x55;
        buf[4] = 0x89;
        buf[5] = 0xE5;
        // body at offset 20
        let result = find_prologue_upwards(&buf, 20, &[0xE5, 0x89, 0x55], 5);
        assert_eq!(result, Err(PatternError::NoMatch));
    }

    #[test]
    fn resolves_call_site_then_follows_to_callee() {
        // Synthetic buffer: a unique call-site signature, then NOPs, then the callee.
        // The call at offset 4 (E8 0A 00 00 00) targets 4 + 5 + 10 = 19.
        let mut haystack = [0x90u8; 32];
        haystack[4] = 0xE8;
        haystack[5] = 0x0A;
        haystack[6] = 0x00;
        haystack[7] = 0x00;
        haystack[8] = 0x00;
        haystack[9] = 0x88;
        haystack[10] = 0x45;

        let pattern = Pattern::parse("E8 ? ? ? ? 88 45").expect("pattern should parse");
        let site = pattern.find_unique(&haystack).expect("call site is unique");
        assert_eq!(site, 4);

        let callee = follow_relative_call(&haystack, site).expect("callee resolves");
        assert_eq!(callee, 19);
    }

    #[test]
    fn follows_last_call_before_ret() {
        let mut haystack = [0x90u8; 40];
        haystack[4] = 0xE8;
        haystack[5] = 0x05;
        haystack[6] = 0x00;
        haystack[7] = 0x00;
        haystack[8] = 0x00;
        haystack[12] = 0xE8;
        haystack[13] = 0x09;
        haystack[14] = 0x00;
        haystack[15] = 0x00;
        haystack[16] = 0x00;
        haystack[20] = 0xC3;

        assert_eq!(follow_last_call_before_ret(&haystack, 0, 32), Ok(26));
    }

    #[test]
    fn last_call_stops_at_ret() {
        let mut haystack = [0x90u8; 32];
        haystack[3] = 0xC3;
        haystack[4] = 0xE8;
        haystack[5] = 0x01;

        assert_eq!(
            follow_last_call_before_ret(&haystack, 0, 16),
            Err(PatternError::NoCallTarget)
        );
    }
}
