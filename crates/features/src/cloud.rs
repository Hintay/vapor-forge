use std::collections::HashSet;
use std::sync::Mutex;

use tracing::info;
use vapor_forge_config::{AppId, RuntimeConfig};

pub fn on_is_cloud_enabled(config: &RuntimeConfig, app_id: AppId, original: bool) -> bool {
    let controlled =
        config.app_category(app_id).is_some() && !crate::apps::is_actually_owned(app_id);
    if controlled && !config.cloud_enabled_for_controlled_apps() {
        if original {
            info!(app_id = app_id.0, "feat: cloud managed");
        }
        return false;
    }
    original
}

// ---------------------------------------------------------------------------
// Cloud-write tracking for VDF filtering
// ---------------------------------------------------------------------------

static CLOUD_WROTE_APPS: Mutex<Option<HashSet<AppId>>> = Mutex::new(None);

/// Record that we called SetCloudEnabledForApp(false) for this app.
/// Called from the IsCloudEnabledForApp hook before the Set call.
pub fn mark_cloud_wrote(app_id: AppId) -> bool {
    let mut guard = CLOUD_WROTE_APPS.lock().unwrap();
    let set = guard.get_or_insert_with(HashSet::new);
    set.insert(app_id)
}

/// Snapshot the set of apps we wrote cloudenabled for.
fn snapshot_wrote_apps() -> HashSet<AppId> {
    CLOUD_WROTE_APPS
        .lock()
        .unwrap()
        .as_ref()
        .cloned()
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// VDF buffer filtering
// ---------------------------------------------------------------------------

const MAX_ROAMING_CONFIG_BYTES: usize = 64 * 1024 * 1024;
const USER_ROAMING_KEY: &[u8] = b"\"UserRoamingConfigStore\"";
const CLOUDENABLED_KEY: &[u8] = b"\"cloudenabled\"";

/// Filter a serialized UserRoamingConfigStore VDF buffer, removing
/// `cloudenabled` entries for controlled apps.
///
/// Returns `Some(filtered)` if the buffer was modified, `None` if no
/// changes were needed (caller should use original buffer).
pub fn strip_cloud_from_vdf(buffer: &[u8]) -> Option<Vec<u8>> {
    if buffer.len() > MAX_ROAMING_CONFIG_BYTES {
        return None;
    }
    if !contains_bytes(buffer, USER_ROAMING_KEY) || !contains_bytes(buffer, CLOUDENABLED_KEY) {
        return None;
    }
    let wrote = snapshot_wrote_apps();
    if wrote.is_empty() {
        return None;
    }
    strip_controlled_cloud(buffer, &wrote)
}

fn strip_controlled_cloud(buf: &[u8], wrote: &HashSet<AppId>) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(buf.len());
    let mut changed = false;
    let mut i = 0;

    while i < buf.len() {
        let (line_start, line_end, next) = next_line(buf, i);

        let app_id = parse_vdf_app_id(&buf[line_start..line_end]);
        if let Some(id) = app_id {
            if wrote.contains(&id) {
                if let Some(block_end) = try_strip_block(buf, next, id, &mut out, line_start) {
                    changed = true;
                    i = block_end;
                    continue;
                }
            }
        }

        out.extend_from_slice(&buf[line_start..next]);
        i = next;
    }

    if changed {
        Some(out)
    } else {
        None
    }
}

fn try_strip_block(
    buf: &[u8],
    after_id_line: usize,
    _app_id: AppId,
    out: &mut Vec<u8>,
    id_line_start: usize,
) -> Option<usize> {
    let (brace_start, brace_end, body_start) = next_line(buf, after_id_line);
    if !is_brace(&buf[brace_start..brace_end], b'{') {
        return None;
    }

    let mark = out.len();
    // Speculatively append the app id line and opening brace
    out.extend_from_slice(&buf[id_line_start..body_start]);

    let mut depth = 1usize;
    let mut p = body_start;
    let mut has_other = false;
    let mut had_cloud = false;

    while p < buf.len() {
        let (ls, le, ln) = next_line(buf, p);
        let line = &buf[ls..le];

        if is_brace(line, b'{') {
            depth += 1;
            out.extend_from_slice(&buf[ls..ln]);
        } else if is_brace(line, b'}') {
            out.extend_from_slice(&buf[ls..ln]);
            depth -= 1;
            if depth == 0 {
                if !has_other {
                    // cloudenabled-only block → drop entirely
                    out.truncate(mark);
                } else if !had_cloud {
                    // no cloudenabled found → no change needed, but already appended
                }
                return if had_cloud || !has_other {
                    Some(ln)
                } else {
                    None
                };
            }
        } else if is_cloudenabled_key(line) {
            had_cloud = true;
            // Drop this line (don't append)
        } else {
            has_other = true;
            out.extend_from_slice(&buf[ls..ln]);
        }
        p = ln;
    }

    // Malformed (no matching brace) → roll back
    out.truncate(mark);
    None
}

fn next_line(buf: &[u8], start: usize) -> (usize, usize, usize) {
    let end = buf[start..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| start + p)
        .unwrap_or(buf.len());
    let next = if end < buf.len() { end + 1 } else { buf.len() };
    (start, end, next)
}

fn is_brace(line: &[u8], brace: u8) -> bool {
    let trimmed = line
        .iter()
        .copied()
        .skip_while(|&b| b == b'\t' || b == b' ');
    let mut found_brace = false;
    for b in trimmed {
        if !found_brace {
            if b == brace {
                found_brace = true;
            } else {
                return false;
            }
        } else if b != b'\t' && b != b' ' && b != b'\r' {
            return false;
        }
    }
    found_brace
}

fn is_cloudenabled_key(line: &[u8]) -> bool {
    let s: &[u8] = line;
    let mut i = 0;
    while i < s.len() && (s[i] == b'\t' || s[i] == b' ') {
        i += 1;
    }
    if i >= s.len() || s[i] != b'"' {
        return false;
    }
    i += 1;
    let key = b"cloudenabled";
    if s.len() - i < key.len() + 1 {
        return false;
    }
    if &s[i..i + key.len()] != key {
        return false;
    }
    i += key.len();
    i < s.len() && s[i] == b'"'
}

fn parse_vdf_app_id(line: &[u8]) -> Option<AppId> {
    let mut i = 0;
    while i < line.len() && (line[i] == b'\t' || line[i] == b' ') {
        i += 1;
    }
    if i >= line.len() || line[i] != b'"' {
        return None;
    }
    i += 1;
    let start = i;
    while i < line.len() && line[i].is_ascii_digit() {
        i += 1;
    }
    if i == start || i >= line.len() || line[i] != b'"' {
        return None;
    }
    // Verify rest of line is whitespace only (it's a key, not key-value)
    let rest = &line[i + 1..];
    if rest.iter().any(|&b| b != b'\t' && b != b' ' && b != b'\r') {
        return None;
    }
    let digits = std::str::from_utf8(&line[start..i]).ok()?;
    digits.parse::<u32>().ok().map(AppId)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_cloudenabled_only_block() {
        let vdf = br#""UserRoamingConfigStore"
{
	"Software"
	{
		"Valve"
		{
			"Steam"
			{
				"apps"
				{
					"480"
					{
						"cloudenabled"		"0"
					}
				}
			}
		}
	}
}
"#;
        let wrote: HashSet<AppId> = [AppId(480)].into();
        let result = strip_controlled_cloud(vdf, &wrote).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(!text.contains("\"480\""));
        assert!(!text.contains("cloudenabled"));
    }

    #[test]
    fn strip_preserves_other_keys() {
        let vdf = br#""UserRoamingConfigStore"
{
	"apps"
	{
		"480"
		{
			"cloudenabled"		"0"
			"LaunchOptions"		"--test"
		}
	}
}
"#;
        let wrote: HashSet<AppId> = [AppId(480)].into();
        let result = strip_controlled_cloud(vdf, &wrote).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("\"480\""));
        assert!(text.contains("LaunchOptions"));
        assert!(!text.contains("cloudenabled"));
    }

    #[test]
    fn strip_ignores_non_controlled_apps() {
        let vdf = br#""UserRoamingConfigStore"
{
	"apps"
	{
		"730"
		{
			"cloudenabled"		"1"
		}
	}
}
"#;
        let wrote: HashSet<AppId> = [AppId(480)].into();
        assert!(strip_controlled_cloud(vdf, &wrote).is_none());
    }

    #[test]
    fn no_strip_without_roaming_key() {
        let buf = b"some random data";
        assert!(strip_cloud_from_vdf(buf).is_none());
    }

    #[test]
    fn parse_app_id_from_vdf_line() {
        assert_eq!(parse_vdf_app_id(b"\t\t\"480\""), Some(AppId(480)));
        assert_eq!(parse_vdf_app_id(b"\t\"480\"\t\t\"value\""), None);
        assert_eq!(parse_vdf_app_id(b"\t\"notanumber\""), None);
    }
}
