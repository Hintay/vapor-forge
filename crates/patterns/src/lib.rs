#![forbid(unsafe_code)]

use thiserror::Error;

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

    fn matches_at(&self, haystack: &[u8], offset: usize) -> bool {
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
        (0..=haystack.len() - self.tokens.len())
            .filter(|&offset| self.matches_at(haystack, offset))
            .collect()
    }

    pub fn find_unique(&self, haystack: &[u8]) -> Result<usize, PatternError> {
        let matches = self.find_all(haystack);
        match matches.len() {
            0 => Err(PatternError::NoMatch),
            1 => Ok(matches[0]),
            n => Err(PatternError::Ambiguous(n)),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{follow_relative_call, Pattern, PatternError, PatternToken};

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
}
