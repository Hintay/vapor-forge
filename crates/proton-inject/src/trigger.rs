// Trigger detection: decide when to inject the user's DLL.
// Pure safe code operating on slices.

use crate::maps::MapEntry;

const TRIGGER_DLLS: &[&str] = &["steam_api64.dll", "steamclient.dll"];

/// Check if a UTF-16LE DLL name (from Wine's UNICODE_STRING) is a trigger.
pub fn is_trigger_name(name: &[u16]) -> bool {
    for trigger in TRIGGER_DLLS {
        if u16_ends_with_ascii_ci(name, trigger) {
            return true;
        }
    }
    false
}

/// Check if any trigger DLL is already loaded (scan /proc/self/maps).
pub fn trigger_already_loaded(maps: &[MapEntry]) -> bool {
    TRIGGER_DLLS.iter().any(|dll| {
        maps.iter().any(|e| {
            e.path
                .rsplit('/')
                .next()
                .map_or(false, |name| ascii_eq_ci(name, dll))
        })
    })
}

/// Convert a Linux absolute path to a Wine NT path in UTF-16LE.
/// Result: `\??\unix` + path, NUL-terminated.
pub fn linux_path_to_wine_nt(path: &str) -> Vec<u16> {
    let prefix = "\\??\\unix";
    let mut out: Vec<u16> = Vec::with_capacity(prefix.len() + path.len() + 1);
    for b in prefix.bytes() {
        out.push(b as u16);
    }
    for b in path.bytes() {
        out.push(b as u16);
    }
    out.push(0);
    out
}

fn u16_ends_with_ascii_ci(haystack: &[u16], needle: &str) -> bool {
    let n = needle.len();
    if haystack.len() < n {
        return false;
    }
    let start = haystack.len() - n;
    for (i, expected) in needle.bytes().enumerate() {
        let actual = haystack[start + i];
        if !ascii_char_eq_ci(actual, expected) {
            return false;
        }
    }
    true
}

fn ascii_eq_ci(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

fn ascii_char_eq_ci(wide: u16, ascii: u8) -> bool {
    if wide > 127 {
        return false;
    }
    (wide as u8).to_ascii_lowercase() == ascii.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_trigger_name() {
        let name: Vec<u16> = "steam_api64.dll".encode_utf16().collect();
        assert!(is_trigger_name(&name));

        let name: Vec<u16> = "C:\\windows\\system32\\Steam_API64.DLL"
            .encode_utf16()
            .collect();
        assert!(is_trigger_name(&name));

        let name: Vec<u16> = "kernel32.dll".encode_utf16().collect();
        assert!(!is_trigger_name(&name));
    }

    #[test]
    fn linux_to_wine_path() {
        let result = linux_path_to_wine_nt("/home/user/mod.dll");
        let expected: Vec<u16> = "\\??\\unix/home/user/mod.dll\0".encode_utf16().collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn trigger_in_maps() {
        let maps = vec![MapEntry {
            base: 0x1000,
            end: 0x2000,
            path: "/some/path/steam_api64.dll".into(),
        }];
        assert!(trigger_already_loaded(&maps));

        let maps = vec![MapEntry {
            base: 0x1000,
            end: 0x2000,
            path: "/usr/lib/libc.so.6".into(),
        }];
        assert!(!trigger_already_loaded(&maps));
    }
}
