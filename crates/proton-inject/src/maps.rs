// /proc/self/maps parser. Pure safe code.

#[allow(dead_code)]
pub struct MapEntry {
    pub base: usize,
    pub end: usize,
    pub path: String,
}

pub fn parse_self_maps() -> Vec<MapEntry> {
    let text = match std::fs::read_to_string("/proc/self/maps") {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut entries = Vec::new();
    for line in text.lines() {
        if let Some(entry) = parse_line(line) {
            entries.push(entry);
        }
    }
    entries
}

pub fn find_module<'a>(entries: &'a [MapEntry], suffix: &str) -> Option<&'a MapEntry> {
    entries
        .iter()
        .find(|e| e.path.ends_with(suffix) || e.path.rsplit('/').next() == Some(suffix))
}

pub fn find_module_with_path<'a>(
    entries: &'a [MapEntry],
    suffix: &str,
) -> Option<(usize, &'a str)> {
    let entry = find_module(entries, suffix)?;
    Some((entry.base, &entry.path))
}

fn parse_line(line: &str) -> Option<MapEntry> {
    // Format: addr_start-addr_end perms offset dev inode path
    let mut parts = line.splitn(6, char::is_whitespace);
    let range = parts.next()?;
    let _perms = parts.next()?;
    let _offset = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    let path = parts.next().unwrap_or("").trim();

    let (start_hex, end_hex) = range.split_once('-')?;
    let base = usize::from_str_radix(start_hex, 16).ok()?;
    let end = usize::from_str_radix(end_hex, 16).ok()?;

    if path.is_empty() || path.starts_with('[') {
        return None;
    }

    Some(MapEntry {
        base,
        end,
        path: path.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maps_line() {
        let line = "7f000000-7f001000 r-xp 00000000 08:01 12345 /usr/lib/libfoo.so";
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.base, 0x7f000000);
        assert_eq!(entry.end, 0x7f001000);
        assert_eq!(entry.path, "/usr/lib/libfoo.so");
    }

    #[test]
    fn skips_anonymous_mappings() {
        assert!(parse_line("7f000000-7f001000 rw-p 00000000 00:00 0").is_none());
        assert!(parse_line("7f000000-7f001000 rw-p 00000000 00:00 0 [heap]").is_none());
    }

    #[test]
    fn finds_module_by_suffix() {
        let entries = vec![
            MapEntry {
                base: 0x1000,
                end: 0x2000,
                path: "/usr/lib/wine/x86_64-windows/ntdll.dll".into(),
            },
            MapEntry {
                base: 0x3000,
                end: 0x4000,
                path: "/usr/lib/libfoo.so".into(),
            },
        ];
        assert!(find_module(&entries, "ntdll.dll").is_some());
        assert!(find_module(&entries, "bar.dll").is_none());
    }
}
