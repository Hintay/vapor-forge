// Trigger detection: decide when to inject the user's DLL.
// Pure safe code operating on slices.

use crate::maps::MapEntry;
/// Trigger-name matching lives in `vapor-forge-pe` next to the DLL list; this
/// module keeps the process-local half of the check.
pub use crate::pe::is_trigger_name;
use crate::pe::TRIGGER_DLLS;

/// Check if any trigger DLL is already loaded (scan /proc/self/maps).
pub fn trigger_already_loaded(maps: &[MapEntry]) -> bool {
    TRIGGER_DLLS.iter().any(|dll| {
        maps.iter().any(|e| {
            e.path
                .rsplit('/')
                .next()
                .is_some_and(|name| ascii_eq_ci(name, dll))
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

fn ascii_eq_ci(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            perms: "r-xp".into(),
            offset: 0,
            path: "/some/path/steam_api64.dll".into(),
        }];
        assert!(trigger_already_loaded(&maps));

        let maps = vec![MapEntry {
            base: 0x1000,
            end: 0x2000,
            perms: "r-xp".into(),
            offset: 0,
            path: "/usr/lib/libc.so.6".into(),
        }];
        assert!(!trigger_already_loaded(&maps));
    }
}
