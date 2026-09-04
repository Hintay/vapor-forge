use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing::info;
use vapor_forge_config::{AppId, RuntimeConfig};

pub fn on_is_cloud_enabled(config: &RuntimeConfig, app_id: AppId, original: bool) -> bool {
    let controlled = crate::apps::classify_app(config, app_id).requires_injected_ownership();
    #[cfg(debug_assertions)]
    log_cloud_gate(app_id, controlled, original, config);
    // Steam answers false for an app the account has no license for, so a
    // controlled app's cloud has to be asserted here whichever backend serves
    // it. Answering with Steam's own value leaves the game believing it has no
    // cloud storage even though every sync request is being served.
    if controlled && (config.cumulus_configured() || config.local_cloud_configured()) {
        if !original {
            info!(app_id = app_id.0, "feat: cloud enabled by backend");
        }
        return true;
    }
    if controlled && !config.cloud_enabled_for_controlled_apps() {
        if original {
            info!(app_id = app_id.0, "feat: cloud managed");
        }
        return false;
    }
    original
}

/// Controlled apps whose Steam cloud has to be switched off up front.
///
/// Steam's logon sync visits every app that still has cloud enabled before it
/// consults the per-app gate, so waiting for the gate leaves a window in which
/// controlled apps sync against Valve and fail.
pub fn apps_to_disable(config: &RuntimeConfig) -> Vec<AppId> {
    if config.cloud_enabled_for_controlled_apps() {
        return Vec::new();
    }
    config
        .apps
        .inject()
        .iter()
        .map(|app| app.id)
        .filter(|&app_id| crate::apps::classify_app(config, app_id).requires_injected_ownership())
        .collect()
}

/// App ids with an `appmanifest_<id>.acf` in any Steam library folder.
///
/// Steam's logon sync only evaluates installed apps, and it runs while the
/// sweep's writes are still being applied, so those apps have to go first.
pub fn installed_app_ids(steam_root: &Path) -> HashSet<AppId> {
    let mut libraries = vec![steam_root.to_path_buf()];
    if let Ok(text) = std::fs::read_to_string(steam_root.join("steamapps/libraryfolders.vdf")) {
        for line in text.lines() {
            if let Some(path) = vdf_string_value(line, "path") {
                let path = PathBuf::from(path.replace("\\\\", "\\"));
                if !libraries.contains(&path) {
                    libraries.push(path);
                }
            }
        }
    }
    let mut installed = HashSet::new();
    for library in libraries {
        let Ok(entries) = std::fs::read_dir(library.join("steamapps")) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(app_id) = name
                .strip_prefix("appmanifest_")
                .and_then(|rest| rest.strip_suffix(".acf"))
                .and_then(|digits| digits.parse::<u32>().ok())
            {
                installed.insert(AppId(app_id));
            }
        }
    }
    installed
}

/// Value of a `"key" "value"` VDF line when `key` matches.
fn vdf_string_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut parts = line.trim().splitn(2, char::is_whitespace);
    let found_key = parts.next()?.trim_matches('"');
    if found_key != key {
        return None;
    }
    Some(parts.next()?.trim().trim_matches('"'))
}

/// Move installed apps to the front, keeping the relative order otherwise.
pub fn order_installed_first(app_ids: &mut [AppId], installed: &HashSet<AppId>) {
    app_ids.sort_by_key(|app_id| !installed.contains(app_id));
}

/// Report what Steam itself answered for an app, once per app. Whether the gate
/// needs to be forced open depends entirely on that value, and it is not
/// observable from the outside.
#[cfg(debug_assertions)]
fn log_cloud_gate(app_id: AppId, controlled: bool, original: bool, config: &RuntimeConfig) {
    static SEEN: Mutex<Option<HashSet<AppId>>> = Mutex::new(None);
    let first = SEEN
        .lock()
        .unwrap()
        .get_or_insert_with(HashSet::new)
        .insert(app_id);
    if first {
        info!(
            app_id = app_id.0,
            controlled,
            steam_answered = original,
            local = config.local_cloud_configured(),
            cumulus = config.cumulus_configured(),
            "feat: cloud gate"
        );
    }
}

// ---------------------------------------------------------------------------
// Cloud gate state: apps currently forced off, and apps ever written
// ---------------------------------------------------------------------------

struct GateState {
    /// Apps whose cloud we currently hold at `false`.
    forced_off: HashSet<AppId>,
    /// Apps we ever wrote a `cloudenabled` value for; the VDF filter keeps
    /// every such entry out of the on-disk roaming config.
    touched: HashSet<AppId>,
}

static GATE_STATE: Mutex<Option<GateState>> = Mutex::new(None);

fn with_gate_state<R>(f: impl FnOnce(&mut GateState) -> R) -> R {
    let mut guard = GATE_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.get_or_insert_with(|| GateState {
        forced_off: HashSet::new(),
        touched: HashSet::new(),
    });
    f(state)
}

/// Record that we are about to call SetCloudEnabledForApp(false) for this app.
/// Returns true the first time the app is forced off.
pub fn mark_cloud_wrote(app_id: AppId) -> bool {
    with_gate_state(|state| {
        state.touched.insert(app_id);
        state.forced_off.insert(app_id)
    })
}

/// Record that we switched the app's cloud back on. The app stays in the VDF
/// filter so the explicit `cloudenabled` entry never reaches disk either.
pub fn mark_cloud_restored(app_id: AppId) -> bool {
    with_gate_state(|state| {
        state.touched.insert(app_id);
        state.forced_off.remove(&app_id)
    })
}

/// Whether we currently hold this app's cloud at `false`.
pub fn is_forced_off(app_id: AppId) -> bool {
    with_gate_state(|state| state.forced_off.contains(&app_id))
}

/// Apps the VDF filter must strip `cloudenabled` for.
fn snapshot_wrote_apps() -> HashSet<AppId> {
    with_gate_state(|state| state.touched.clone())
}

/// What the next sweep has to change to match the configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CloudPlan {
    /// Controlled apps that still need SetCloudEnabledForApp(false).
    pub disable: Vec<AppId>,
    /// Apps we forced off that no longer qualify (script removed, backend
    /// configured, genuine ownership learned) and get their cloud back.
    pub enable: Vec<AppId>,
}

/// Reconcile the forced-off set with the current configuration and ownership.
pub fn cloud_plan(config: &RuntimeConfig) -> CloudPlan {
    let desired = apps_to_disable(config);
    with_gate_state(|state| {
        let disable = desired
            .iter()
            .copied()
            .filter(|app_id| !state.forced_off.contains(app_id))
            .collect();
        let mut enable: Vec<AppId> = state
            .forced_off
            .iter()
            .copied()
            .filter(|app_id| !desired.contains(app_id))
            .collect();
        enable.sort_unstable();
        CloudPlan { disable, enable }
    })
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
    use vapor_forge_config::{
        CloudBackendMode, CloudSection, CumulusCloudSection, InjectApp, LocalCloudSection,
    };

    const TEST_APP_ID: AppId = AppId(246_813_579);

    fn config_with_inject(ids: &[u32]) -> RuntimeConfig {
        RuntimeConfig {
            apps: vapor_forge_config::AppsSection::with_inject(
                ids.iter()
                    .map(|&id| InjectApp {
                        id: AppId(id),
                        dlc: Vec::new(),
                        ticket: Default::default(),
                        purchase_time: 0,
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn apps_to_disable_lists_controlled_apps_without_genuine_ownership() {
        let config = config_with_inject(&[5_551, 5_552]);
        assert_eq!(apps_to_disable(&config), vec![AppId(5_551), AppId(5_552)]);
        crate::apps::record_actual_ownership(AppId(5_552), true);
        assert_eq!(apps_to_disable(&config), vec![AppId(5_551)]);
    }

    #[test]
    fn apps_to_disable_is_empty_when_a_backend_serves_cloud() {
        let mut config = config_with_inject(&[5_553]);
        config.cloud.backend = CloudBackendMode::Local;
        assert!(apps_to_disable(&config).is_empty());
    }

    #[test]
    fn cloud_plan_disables_new_apps_and_restores_dropped_ones() {
        let _guard = crate::apps::ACCOUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let a = AppId(5_561);
        let b = AppId(5_562);
        let config = config_with_inject(&[a.0, b.0]);
        let plan = cloud_plan(&config);
        assert!(plan.disable.contains(&a) && plan.disable.contains(&b));
        assert!(plan.enable.is_empty());

        assert!(mark_cloud_wrote(a));
        assert!(!mark_cloud_wrote(a));
        assert!(mark_cloud_wrote(b));
        assert_eq!(cloud_plan(&config), CloudPlan::default());

        // `b` becomes genuinely owned: it must get its cloud back.
        crate::apps::record_actual_ownership(b, true);
        assert_eq!(cloud_plan(&config).enable, vec![b]);
        assert!(mark_cloud_restored(b));
        assert!(!is_forced_off(b));
        assert!(is_forced_off(a));

        // Backend configured: nothing stays forced off.
        let mut with_backend = config_with_inject(&[a.0]);
        with_backend.cloud.backend = CloudBackendMode::Local;
        assert_eq!(cloud_plan(&with_backend).enable, vec![a]);
        mark_cloud_restored(a);
        crate::apps::record_actual_ownership(b, false);
    }

    #[test]
    fn installed_app_ids_reads_every_library_folder() {
        let root = tempfile::tempdir().unwrap();
        let extra = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("steamapps")).unwrap();
        std::fs::create_dir_all(extra.path().join("steamapps")).unwrap();
        std::fs::write(
            root.path().join("steamapps/libraryfolders.vdf"),
            format!(
                "\"libraryfolders\"\n{{\n\t\"0\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n\t\"1\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n}}\n",
                root.path().display(),
                extra.path().display()
            ),
        )
        .unwrap();
        std::fs::write(root.path().join("steamapps/appmanifest_232430.acf"), "").unwrap();
        std::fs::write(extra.path().join("steamapps/appmanifest_648590.acf"), "").unwrap();
        std::fs::write(extra.path().join("steamapps/appmanifest_x.acf"), "").unwrap();

        let installed = installed_app_ids(root.path());
        assert_eq!(installed, HashSet::from([AppId(232_430), AppId(648_590)]));
    }

    #[test]
    fn installed_app_ids_is_empty_without_a_library() {
        let root = tempfile::tempdir().unwrap();
        assert!(installed_app_ids(root.path()).is_empty());
    }

    #[test]
    fn order_installed_first_keeps_relative_order() {
        let mut ids = vec![AppId(1), AppId(2), AppId(3), AppId(4)];
        order_installed_first(&mut ids, &HashSet::from([AppId(4), AppId(2)]));
        assert_eq!(ids, vec![AppId(2), AppId(4), AppId(1), AppId(3)]);
    }

    fn controlled_config(cloud: CloudSection) -> RuntimeConfig {
        RuntimeConfig {
            apps: vapor_forge_config::AppsSection::with_inject(vec![InjectApp {
                id: TEST_APP_ID,
                dlc: Vec::new(),
                ticket: Default::default(),
                purchase_time: 0,
            }]),
            cloud,
            ..Default::default()
        }
    }

    #[test]
    fn cumulus_forces_the_remote_storage_enable_gate_open() {
        let config = controlled_config(CloudSection {
            backend: CloudBackendMode::Cumulus,
            cumulus: CumulusCloudSection {
                server_url: "https://cloud.example.com".into(),
                token: "device-token".into(),
                ..Default::default()
            },
            ..Default::default()
        });

        assert!(on_is_cloud_enabled(&config, TEST_APP_ID, false));
    }

    #[test]
    fn a_local_folder_backend_forces_the_gate_open_too() {
        // Steam answers false for an app the account has no license for, so a
        // controlled app served by the folder store has to be asserted open the
        // same way Cumulus is. Leaving it to Steam is what made a game report
        // that it had no cloud save directory while every sync request for it
        // was being served.
        let config = controlled_config(CloudSection {
            backend: CloudBackendMode::Local,
            local: LocalCloudSection {
                path: "/tmp/vapor-forge-cloud".into(),
                ..Default::default()
            },
            ..Default::default()
        });

        assert!(on_is_cloud_enabled(&config, TEST_APP_ID, false));
    }

    #[test]
    fn disabled_backend_does_not_force_an_originally_disabled_app_on() {
        let config = controlled_config(CloudSection::default());

        assert!(!on_is_cloud_enabled(&config, TEST_APP_ID, false));
    }

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
