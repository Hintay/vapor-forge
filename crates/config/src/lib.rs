#![forbid(unsafe_code)]

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;

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
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeSection {
    #[serde(default = "default_log_level")]
    pub log_level: String,
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
    pub id: u32,
    #[serde(default)]
    pub dlc: Vec<u32>,
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
    pub include: Vec<u32>,
    #[serde(default)]
    pub exclude: Vec<u32>,
}

impl SharedSection {
    pub fn allows(&self, app_id: u32) -> bool {
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

impl Default for RuntimeSection {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
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
    InjectDlc { parent: u32 },
}

impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    pub fn app_category(&self, app_id: u32) -> Option<AppCategory> {
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

    pub fn should_bypass_sharing(&self, app_id: u32) -> bool {
        self.apps.shared.allows(app_id)
    }

    pub fn inject_app_ids(&self) -> HashSet<u32> {
        let mut ids = HashSet::new();
        for app in &self.apps.inject {
            ids.insert(app.id);
            ids.extend(&app.dlc);
        }
        ids
    }

    pub fn inject_dlc_map(&self) -> HashMap<u32, Vec<u32>> {
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
    use super::{AppCategory, RuntimeConfig};

    #[test]
    fn parses_empty_config() {
        let config: RuntimeConfig = toml::from_str("").expect("empty config should parse");
        assert!(!config.has_any_inject_apps());
        assert!(config.should_bypass_sharing(480));
    }

    #[test]
    fn shared_enabled_by_default() {
        let config: RuntimeConfig = toml::from_str("").expect("parse");
        assert!(config.apps.shared.enabled);
        assert!(config.should_bypass_sharing(12345));
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
        assert!(config.should_bypass_sharing(570));
        assert!(config.should_bypass_sharing(730));
        assert!(!config.should_bypass_sharing(480));
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
        assert!(config.should_bypass_sharing(570));
        assert!(!config.should_bypass_sharing(730));
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
        assert!(!config.should_bypass_sharing(480));
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

        assert_eq!(config.app_category(480), Some(AppCategory::Inject));
        assert_eq!(config.app_category(730), Some(AppCategory::Inject));
        assert_eq!(
            config.app_category(505730),
            Some(AppCategory::InjectDlc { parent: 480 })
        );
        assert_eq!(config.app_category(999), None);

        let all = config.inject_app_ids();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn cloud_defaults_to_disabled() {
        let config: RuntimeConfig = toml::from_str("").expect("parse");
        assert!(!config.cloud_enabled_for_controlled_apps());
    }
}
