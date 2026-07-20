// /proc/self/maps parser. Pure safe code.

#[allow(dead_code)]
pub struct MapEntry {
    pub base: usize,
    pub end: usize,
    pub perms: String,
    pub offset: usize,
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

pub fn readable_span_at(addr: usize) -> Option<usize> {
    mapping_span_at(addr, 'r')
}

pub fn executable_span_at(addr: usize) -> Option<usize> {
    mapping_span_at(addr, 'x')
}

fn mapping_span_at(addr: usize, required_permission: char) -> Option<usize> {
    let text = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next()?;
        let perms = fields.next()?;
        let Some((start_hex, end_hex)) = range.split_once('-') else {
            continue;
        };
        let (Ok(base), Ok(end)) = (
            usize::from_str_radix(start_hex, 16),
            usize::from_str_radix(end_hex, 16),
        ) else {
            continue;
        };
        if addr >= base && addr < end && perms.contains(required_permission) {
            return Some(end - addr);
        }
    }
    None
}

fn parse_line(line: &str) -> Option<MapEntry> {
    // Format: addr_start-addr_end perms offset dev inode path
    let mut parts = line.splitn(6, char::is_whitespace);
    let range = parts.next()?;
    let perms = parts.next()?.to_owned();
    let offset = usize::from_str_radix(parts.next()?, 16).ok()?;
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
        perms,
        offset,
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
        assert_eq!(entry.perms, "r-xp");
        assert_eq!(entry.offset, 0);
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
                perms: "r-xp".into(),
                offset: 0,
                path: "/usr/lib/wine/x86_64-windows/ntdll.dll".into(),
            },
            MapEntry {
                base: 0x3000,
                end: 0x4000,
                perms: "r-xp".into(),
                offset: 0,
                path: "/usr/lib/libfoo.so".into(),
            },
        ];
        assert!(find_module(&entries, "ntdll.dll").is_some());
        assert!(find_module(&entries, "bar.dll").is_none());
    }
}
