use tracing::{debug, error, warn};
use vapor_forge_patterns::registry::{FollowMode, PatternLookup, PatternVariantLookup};
use vapor_forge_patterns::{
    find_prologue_upwards, follow_last_call_before_ret, follow_relative_call, Pattern,
};

pub(crate) struct CodeRegion {
    pub(crate) base: usize,
    pub(crate) bytes: &'static [u8],
}

pub(crate) fn resolve_pattern_entry(
    code: &CodeRegion,
    name: &str,
    entry: &PatternLookup<'_>,
) -> Option<usize> {
    for (variant_index, variant) in entry.variants().enumerate() {
        if let Some(addr) = resolve_pattern_variant(code, name, variant_index, variant) {
            return Some(addr);
        }
    }
    None
}

fn resolve_pattern_variant(
    code: &CodeRegion,
    name: &str,
    variant_index: usize,
    entry: PatternVariantLookup<'_>,
) -> Option<usize> {
    let addr = match entry.follow() {
        FollowMode::None => resolve_callee(code, name, entry.pattern(), false)?,
        FollowMode::Relative => resolve_callee(code, name, entry.pattern(), true)?,
        FollowMode::Upward => {
            let prologue = entry.prologue_bytes().or_else(|| {
                error!(
                    hook = name,
                    variant = variant_index,
                    "upward follow requires prologue bytes"
                );
                None
            })?;
            resolve_prologue_upwards(code, name, entry.pattern(), prologue)?
        }
        FollowMode::Call => resolve_follow_call(code, name, entry)?,
    };

    if entry.pic_entry() {
        find_pic_entry(code, addr)
    } else {
        Some(addr)
    }
}

fn resolve_callee(code: &CodeRegion, name: &str, pattern_str: &str, follow: bool) -> Option<usize> {
    let pattern = match Pattern::parse(pattern_str) {
        Ok(pattern) => pattern,
        Err(error) => {
            error!(hook = name, %error, "pattern parse failed");
            return None;
        }
    };
    let offset = match pattern.find_unique(code.bytes) {
        Ok(offset) => offset,
        Err(error) => {
            warn!(hook = name, %error, "pattern match failed");
            return None;
        }
    };

    if !follow {
        let addr = code.base + offset;
        debug!(
            hook = name,
            addr = format_args!("0x{addr:x}"),
            "pattern matched"
        );
        return Some(addr);
    }

    match follow_relative_call(code.bytes, offset) {
        Ok(target) if target >= 0 && (target as usize) < code.bytes.len() => {
            let addr = code.base + target as usize;
            debug!(
                hook = name,
                addr = format_args!("0x{addr:x}"),
                "callee resolved"
            );
            Some(addr)
        }
        Ok(target) => {
            warn!(
                hook = name,
                offset = format_args!("0x{target:x}"),
                "callee out of bounds"
            );
            None
        }
        Err(error) => {
            error!(hook = name, %error, "follow relative call failed");
            None
        }
    }
}

fn resolve_prologue_upwards(
    code: &CodeRegion,
    name: &str,
    body_pattern_str: &str,
    prologue_bytes: &[u8],
) -> Option<usize> {
    let body_pattern = match Pattern::parse(body_pattern_str) {
        Ok(pattern) => pattern,
        Err(error) => {
            error!(hook = name, %error, "body pattern parse failed");
            return None;
        }
    };
    let body_offset = match body_pattern.find_unique(code.bytes) {
        Ok(offset) => offset,
        Err(error) => {
            warn!(hook = name, %error, "body pattern match failed");
            return None;
        }
    };

    match find_prologue_upwards(code.bytes, body_offset, prologue_bytes, 0x10000) {
        Ok(entry_offset) => {
            let addr = code.base + entry_offset;
            debug!(
                hook = name,
                body = format_args!("0x{:x}", code.base + body_offset),
                entry = format_args!("0x{addr:x}"),
                "prologue resolved"
            );
            Some(addr)
        }
        Err(error) => {
            warn!(hook = name, %error, "prologue scan failed");
            None
        }
    }
}

fn resolve_follow_call(
    code: &CodeRegion,
    name: &str,
    entry: PatternVariantLookup<'_>,
) -> Option<usize> {
    let pattern = match Pattern::parse(entry.pattern()) {
        Ok(pattern) => pattern,
        Err(error) => {
            error!(hook = name, %error, "callsite pattern parse failed");
            return None;
        }
    };
    let callee_pattern = match entry.callee_pattern() {
        Some(pattern) => match Pattern::parse(pattern) {
            Ok(pattern) => Some(pattern),
            Err(error) => {
                error!(hook = name, %error, "callee pattern parse failed");
                return None;
            }
        },
        None => None,
    };
    let matches = pattern.find_all(code.bytes);
    if matches.is_empty() {
        warn!(hook = name, "callsite pattern did not match");
        return None;
    }

    for offset in matches.iter().copied() {
        let Ok(callee_offset) = follow_last_call_before_ret(code.bytes, offset, 256) else {
            continue;
        };
        if callee_pattern
            .as_ref()
            .is_some_and(|pattern| !pattern.matches_at(code.bytes, callee_offset))
        {
            continue;
        }
        let addr = code.base + callee_offset;
        debug!(
            hook = name,
            match_addr = format_args!("0x{:x}", code.base + offset),
            match_count = matches.len(),
            addr = format_args!("0x{addr:x}"),
            "call target resolved"
        );
        return Some(addr);
    }

    warn!(
        hook = name,
        match_count = matches.len(),
        has_callee_pattern = callee_pattern.is_some(),
        "no matching call target found"
    );
    None
}

fn find_pic_entry(code: &CodeRegion, prologue_addr: usize) -> Option<usize> {
    if !cfg!(target_pointer_width = "32") {
        return Some(prologue_addr);
    }
    let prologue_offset = prologue_addr.checked_sub(code.base)?;
    for preamble_len in [10usize, 11] {
        let Some(candidate_offset) = prologue_offset.checked_sub(preamble_len) else {
            continue;
        };
        if is_pic_preamble(code.bytes, candidate_offset, preamble_len) {
            return Some(code.base + candidate_offset);
        }
    }
    if code
        .bytes
        .get(prologue_offset..prologue_offset + 3)
        .is_some_and(|bytes| bytes == [0x55, 0x89, 0xe5])
    {
        return Some(prologue_addr);
    }
    warn!(
        addr = format_args!("0x{prologue_addr:x}"),
        "PIC entry preamble not found"
    );
    None
}

fn is_pic_preamble(code: &[u8], offset: usize, len: usize) -> bool {
    let Some(bytes) = code.get(offset..offset + len) else {
        return false;
    };
    bytes[0] == 0xe8
        && match len {
            10 => bytes[5] == 0x05,
            11 => bytes[5] == 0x81 && matches!(bytes[6], 0xc1 | 0xc3 | 0xc5 | 0xc6 | 0xc7),
            _ => false,
        }
}
