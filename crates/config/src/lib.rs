#![forbid(unsafe_code)]

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;

// Re-export newtypes so callers only need to depend on steam-runtime-config.
pub use steam_runtime_core::{AppId, DepotId, ManifestId};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadFailed(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    ParseFailed(#[from] toml::de::Error),
}

/// Root configuration. Lua scripts are the primary configuration method;
/// this TOML file serves as a simple fallback and for debugging.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub apps: AppsSection,
    #[serde(default)]
    pub scripting: ScriptingSection,
    #[serde(default)]
    pub ticket: TicketSection,
    #[serde(default)]
    pub manifest: ManifestSection,
    #[serde(default)]
    pub achievements: AchievementsSection,
    #[serde(default)]
    pub app_avatar: AppAvatarSection,
    #[serde(default)]
    pub library_inject: LibraryInjectSection,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeSection {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub diagnostics: bool,
    #[serde(default)]
    pub patterns_url: String,
}

/// Controlled apps.
///
/// - `inject`: apps the user does NOT own. Full ownership + optional DLC.
/// - `shared`: family sharing concurrent-play bypass.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AppsSection {
    #[serde(default)]
    pub inject: Vec<InjectApp>,
    #[serde(default)]
    pub shared: SharedSection,
    #[serde(default)]
    pub cloud_enabled: Option<bool>,
}

/// An app to inject ownership for, with optional DLC list.
#[derive(Clone, Debug, Deserialize)]
pub struct InjectApp {
    pub id: AppId,
    #[serde(default)]
    pub dlc: Vec<AppId>,
}

/// Family sharing concurrent-play bypass.
///
/// Enabled by default for ALL family-shared apps.
/// - Set `include` to bypass ONLY listed apps (whitelist).
/// - Set `exclude` to bypass all EXCEPT listed apps (blacklist).
/// - `include` and `exclude` are mutually exclusive; if both are set, `include` takes precedence.
/// - Neither set = all family-shared apps are bypassed.
/// - `enabled = false` disables entirely.
#[derive(Clone, Debug, Deserialize)]
pub struct SharedSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub include: Vec<AppId>,
    #[serde(default)]
    pub exclude: Vec<AppId>,
}

impl SharedSection {
    pub fn allows(&self, app_id: AppId) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.include.is_empty() {
            return self.include.contains(&app_id);
        }
        if !self.exclude.is_empty() {
            return !self.exclude.contains(&app_id);
        }
        true
    }
}

impl Default for SharedSection {
    fn default() -> Self {
        Self {
            enabled: true,
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ScriptingSection {
    #[serde(default)]
    pub paths: Vec<String>,
}

/// Achievement/stats schema configuration.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AchievementsSection {
    #[serde(default)]
    pub offline_schema: bool,
}

/// AppAvatar: map a real AppId to another for networking.
///
/// Integer keys are static mappings. Use 0 as wildcard for all unowned apps.
/// `rules` is an array of flag-driven rules evaluated at LaunchApp.
///
/// ```toml
/// [app_avatar]
/// 480 = 730
/// 0 = 730
///
/// [[app_avatar.rules]]
/// flag = "-onlinefix"
/// avatar = 480
/// ```
#[derive(Clone, Debug, Default)]
pub struct AppAvatarSection {
    pub static_map: HashMap<AppId, AppId>,
    pub rules: Vec<AppAvatarRule>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AppAvatarRule {
    pub flag: String,
    pub avatar: AppId,
    #[serde(default)]
    pub apps: Vec<AppId>,
    #[serde(default)]
    pub exclude: Vec<AppId>,
}

impl<'de> serde::Deserialize<'de> for AppAvatarSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;

        struct AppAvatarVisitor;

        impl<'de> Visitor<'de> for AppAvatarVisitor {
            type Value = AppAvatarSection;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("app_avatar table with integer keys and optional rules array")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut static_map = HashMap::new();
                let mut rules = Vec::new();

                while let Some(key) = map.next_key::<String>()? {
                    if key == "rules" {
                        rules = map.next_value()?;
                    } else if let Ok(app_id) = key.parse::<u32>() {
                        let avatar: u32 = map.next_value()?;
                        static_map.insert(AppId(app_id), AppId(avatar));
                    } else {
                        let _ = map.next_value::<toml::Value>();
                    }
                }

                Ok(AppAvatarSection { static_map, rules })
            }
        }

        deserializer.deserialize_map(AppAvatarVisitor)
    }
}

/// Native .so injection via LD_PRELOAD, applied at BuildSpawnEnvBlock time.
///
/// Each entry lists a library path plus optional app/flag filters, mirroring
/// the AppAvatar rule shape. Rules are evaluated at LaunchApp; matching paths
/// are joined and written into the child process env block.
///
/// ```toml
/// [[library_inject.libs]]
/// path = "/home/deck/mylib.so"
/// flag = "-onlinefix"
/// apps = [480]
/// ```
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LibraryInjectSection {
    #[serde(default)]
    pub libs: Vec<LibraryInjectEntry>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LibraryInjectEntry {
    pub path: String,
    #[serde(default)]
    pub flag: String,
    #[serde(default)]
    pub apps: Vec<AppId>,
    #[serde(default)]
    pub exclude: Vec<AppId>,
}

/// Ticket caching and forging configuration.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TicketSection {
    #[serde(default)]
    pub cache: TicketCacheMode,
}

/// Manifest request code fetch configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct ManifestSection {
    #[serde(default = "default_providers")]
    pub providers: Vec<String>,
    #[serde(default = "default_timeout_connect_ms")]
    pub timeout_connect_ms: u64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for ManifestSection {
    fn default() -> Self {
        Self {
            providers: default_providers(),
            timeout_connect_ms: default_timeout_connect_ms(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

fn default_providers() -> Vec<String> {
    vec![
        "opensteamtool".to_owned(),
        "wudrm".to_owned(),
        "steamrun".to_owned(),
    ]
}

fn default_timeout_connect_ms() -> u64 {
    5000
}

fn default_timeout_ms() -> u64 {
    15000
}

/// Where intercepted tickets are cached.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TicketCacheMode {
    /// In-memory only. Tickets are lost when Steam restarts.
    #[default]
    Session,
    /// Persist tickets to disk so they survive restarts.
    Disk,
}

impl Default for RuntimeSection {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            diagnostics: false,
            patterns_url: String::new(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppCategory {
    Inject,
    InjectDlc { parent: AppId },
}

impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    pub fn app_category(&self, app_id: AppId) -> Option<AppCategory> {
        for app in &self.apps.inject {
            if app.id == app_id {
                return Some(AppCategory::Inject);
            }
            if app.dlc.contains(&app_id) {
                return Some(AppCategory::InjectDlc { parent: app.id });
            }
        }
        None
    }

    pub fn should_bypass_sharing(&self, app_id: AppId) -> bool {
        self.apps.shared.allows(app_id)
    }

    pub fn inject_app_ids(&self) -> HashSet<AppId> {
        let mut ids = HashSet::new();
        for app in &self.apps.inject {
            ids.insert(app.id);
            ids.extend(&app.dlc);
        }
        ids
    }

    pub fn inject_dlc_map(&self) -> HashMap<AppId, Vec<AppId>> {
        self.apps
            .inject
            .iter()
            .filter(|app| !app.dlc.is_empty())
            .map(|app| (app.id, app.dlc.clone()))
            .collect()
    }

    pub fn has_any_inject_apps(&self) -> bool {
        !self.apps.inject.is_empty()
    }

    pub fn cloud_enabled_for_controlled_apps(&self) -> bool {
        self.apps.cloud_enabled.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::{AppCategory, AppId, RuntimeConfig, TicketCacheMode};

    #[test]
    fn parses_empty_config() {
        let config: RuntimeConfig = toml::from_str("").expect("empty config should parse");
        assert!(!config.has_any_inject_apps());
        assert!(config.should_bypass_sharing(AppId(480)));
    }

    #[test]
    fn shared_enabled_by_default() {
        let config: RuntimeConfig = toml::from_str("").expect("parse");
        assert!(config.apps.shared.enabled);
        assert!(config.should_bypass_sharing(AppId(12345)));
    }

    #[test]
    fn shared_include_restricts() {
        let config: RuntimeConfig = toml::from_str(
            r#"
            [apps.shared]
            include = [570, 730]
            "#,
        )
        .expect("parse");
        assert!(config.should_bypass_sharing(AppId(570)));
        assert!(config.should_bypass_sharing(AppId(730)));
        assert!(!config.should_bypass_sharing(AppId(480)));
    }

    #[test]
    fn shared_exclude_blocks() {
        let config: RuntimeConfig = toml::from_str(
            r#"
            [apps.shared]
            exclude = [730]
            "#,
        )
        .expect("parse");
        assert!(config.should_bypass_sharing(AppId(570)));
        assert!(!config.should_bypass_sharing(AppId(730)));
    }

    #[test]
    fn shared_can_be_disabled() {
        let config: RuntimeConfig = toml::from_str(
            r#"
            [apps.shared]
            enabled = false
            "#,
        )
        .expect("parse");
        assert!(!config.should_bypass_sharing(AppId(480)));
    }

    #[test]
    fn parses_inject_with_dlc() {
        let config: RuntimeConfig = toml::from_str(
            r#"
            [[apps.inject]]
            id = 480
            dlc = [505730, 505740]

            [[apps.inject]]
            id = 730
            "#,
        )
        .expect("parse");

        assert_eq!(config.app_category(AppId(480)), Some(AppCategory::Inject));
        assert_eq!(config.app_category(AppId(730)), Some(AppCategory::Inject));
        assert_eq!(
            config.app_category(AppId(505730)),
            Some(AppCategory::InjectDlc { parent: AppId(480) })
        );
        assert_eq!(config.app_category(AppId(999)), None);

        let all = config.inject_app_ids();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn cloud_defaults_to_disabled() {
        let config: RuntimeConfig = toml::from_str("").expect("parse");
        assert!(!config.cloud_enabled_for_controlled_apps());
    }

    #[test]
    fn ticket_defaults_to_session_cache() {
        let config: RuntimeConfig = toml::from_str("").expect("parse");
        assert_eq!(config.ticket.cache, TicketCacheMode::Session);
    }

    #[test]
    fn ticket_disk_cache_parses() {
        let config: RuntimeConfig = toml::from_str(
            r#"
            [ticket]
            cache = "disk"
            "#,
        )
        .expect("parse");
        assert_eq!(config.ticket.cache, TicketCacheMode::Disk);
    }

    #[test]
    fn library_inject_defaults_to_empty() {
        let config: RuntimeConfig = toml::from_str("").expect("parse");
        assert!(config.library_inject.libs.is_empty());
    }

    #[test]
    fn library_inject_parses_entries() {
        let config: RuntimeConfig = toml::from_str(
            r#"
            [[library_inject.libs]]
            path = "/home/deck/mylib.so"
            flag = "-onlinefix"
            apps = [480]
            exclude = [730]
            "#,
        )
        .expect("parse");
        assert_eq!(config.library_inject.libs.len(), 1);
        let entry = &config.library_inject.libs[0];
        assert_eq!(entry.path, "/home/deck/mylib.so");
        assert_eq!(entry.flag, "-onlinefix");
        assert_eq!(entry.apps, vec![AppId(480)]);
        assert_eq!(entry.exclude, vec![AppId(730)]);
    }
}
