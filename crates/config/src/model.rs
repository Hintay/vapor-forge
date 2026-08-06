use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::{AppId, ConfigError};

/// Root runtime configuration. Lua scripts extend the app-specific state.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub toast: ToastSection,
    #[serde(default)]
    pub debug: DebugSection,
    #[serde(default)]
    pub apps: AppsSection,
    #[serde(default)]
    pub cloud: CloudSection,
    #[serde(default)]
    pub scripting: ScriptingSection,
    #[serde(default)]
    pub ticket: TicketSection,
    #[serde(default)]
    pub achievements: AchievementsSection,
    #[serde(default)]
    pub app_avatar: AppAvatarSection,
    #[serde(default)]
    pub library_inject: LibraryInjectSection,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSection {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub diagnostics: bool,
    #[serde(default)]
    pub patterns_url: String,
}

/// Steam internal toast notifications shown through SteamUI WebUI.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToastSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub init: bool,
}

/// Development-only local control API.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSection {
    #[serde(default = "default_debug_control_api")]
    pub control_api: bool,
}

/// Controlled apps.
///
/// - `inject`: apps the user does NOT own. Full ownership + optional DLC.
/// - `shared`: family sharing concurrent-play unlock.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppsSection {
    #[serde(default)]
    pub inject: Vec<InjectApp>,
    #[serde(default)]
    pub shared: SharedSection,
}

/// An app to inject ownership for, with optional DLC list.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectApp {
    pub id: AppId,
    #[serde(default)]
    pub dlc: Vec<AppId>,
    #[serde(default)]
    pub ticket: TicketMode,
    /// Unix timestamp shown as purchase date in the Steam library UI.
    /// 0 = auto (current time at first FillInAppOverview call).
    #[serde(default)]
    pub purchase_time: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TicketMode {
    /// Default: derive tickets from appId 7 source with current user's SteamID.
    #[default]
    Forge,
    /// Delegate to cached ticket from previous owner session. During the
    /// first few ticket requests after launch, return the cached ticket
    /// (with the original owner's SteamID). After the window closes,
    /// switch to derived mode with the current user's SteamID.
    Delegate,
}

/// Family sharing concurrent-play unlock.
///
/// Enabled by default for ALL family-shared apps.
/// - Set `include` to unlock ONLY listed apps (whitelist).
/// - Set `exclude` to unlock all EXCEPT listed apps (blacklist).
/// - `include` and `exclude` are mutually exclusive; if both are set, `include` takes precedence.
/// - Neither set = all family-shared apps are unlocked.
/// - `enabled = false` disables entirely.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Cloud backend selection and settings for controlled apps.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSection {
    #[serde(default)]
    pub backend: CloudBackendMode,
    #[serde(default)]
    pub local: LocalCloudSection,
    #[serde(default)]
    pub cumulus: CumulusCloudSection,
}

impl Default for CloudSection {
    fn default() -> Self {
        Self {
            backend: CloudBackendMode::Disabled,
            local: LocalCloudSection::default(),
            cumulus: CumulusCloudSection::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudBackendMode {
    #[default]
    Disabled,
    Local,
    Cumulus,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCloudSection {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub syncthing: SyncthingSection,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CumulusCloudSection {
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default = "default_timeout_connect_ms")]
    pub timeout_connect_ms: u64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl std::fmt::Debug for CumulusCloudSection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CumulusCloudSection")
            .field("server_url", &self.server_url)
            .field("token", &"[REDACTED]")
            .field("timeout_connect_ms", &self.timeout_connect_ms)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl Default for CumulusCloudSection {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            token: String::new(),
            timeout_connect_ms: default_timeout_connect_ms(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

/// Optional Syncthing integration for the local cloud repository.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncthingSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_syncthing_url")]
    pub url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub folder_id: String,
    #[serde(default = "default_syncthing_timeout_ms")]
    pub timeout_ms: u64,
}

impl std::fmt::Debug for SyncthingSection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyncthingSection")
            .field("enabled", &self.enabled)
            .field("url", &self.url)
            .field("api_key", &"[REDACTED]")
            .field("folder_id", &self.folder_id)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl Default for SyncthingSection {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_syncthing_url(),
            api_key: String::new(),
            folder_id: String::new(),
            timeout_ms: default_syncthing_timeout_ms(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptingSection {
    #[serde(default)]
    pub paths: Vec<String>,
}

/// Achievement/stats schema configuration.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AchievementsSection {
    #[serde(default)]
    pub offline_schema: bool,
}

/// AppAvatar: map a real AppId to another for networking.
///
/// Integer keys are static mappings. Use 0 as wildcard for all unowned apps.
/// `rules` is an array of flag-driven rules evaluated at SpawnProcess.
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
#[serde(deny_unknown_fields)]
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
                        return Err(serde::de::Error::unknown_field(
                            &key,
                            &["rules", "an unsigned 32-bit AppID"],
                        ));
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
/// the AppAvatar rule shape. Rules are evaluated at SpawnProcess; matching paths
/// are joined and written into the child process env block.
///
/// ```toml
/// [[library_inject.libs]]
/// path = "/home/user/mylib.so"
/// flag = "-onlinefix"
/// apps = [480]
/// ```
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryInjectSection {
    #[serde(default)]
    pub libs: Vec<LibraryInjectEntry>,
    #[serde(default)]
    pub helper_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryInjectEntry {
    pub path: String,
    #[serde(default)]
    pub flag: String,
    #[serde(default)]
    pub apps: Vec<AppId>,
    #[serde(default)]
    pub exclude: Vec<AppId>,
}

/// Ticket configuration.
///
/// - Forge source tickets (appId 7): always memory-only.
/// - Delegate captured tickets: always persisted to disk.
/// - Other tickets (Lua-provided, real intercepted): controlled by `cache`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketSection {
    /// Persistence for non-delegate, non-derived tickets (Lua-provided or
    /// intercepted real tickets). Default: disk.
    #[serde(default)]
    pub cache: TicketCacheMode,
    /// Automatically detect Denuvo-protected games (via PE section scanning
    /// in the vapor-forge-proton-inject helper) and enable delegate ticket mode for them.
    /// Requires library injection with a proton helper configured.
    #[serde(default)]
    pub auto_delegate: bool,
}

/// Persistence mode for non-delegate, non-derived tickets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TicketCacheMode {
    /// In-memory only. Lost when Steam restarts.
    Session,
    /// Persist to disk. Survives restarts.
    #[default]
    Disk,
}

fn default_timeout_connect_ms() -> u64 {
    5000
}

fn default_timeout_ms() -> u64 {
    15000
}

fn default_syncthing_url() -> String {
    "http://127.0.0.1:8384".into()
}

fn default_syncthing_timeout_ms() -> u64 {
    2000
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

impl Default for ToastSection {
    fn default() -> Self {
        Self {
            enabled: true,
            init: true,
        }
    }
}

impl Default for DebugSection {
    fn default() -> Self {
        Self {
            control_api: default_debug_control_api(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_debug_control_api() -> bool {
    cfg!(debug_assertions)
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

    /// Returns whether this AppId is managed by the effective runtime config.
    ///
    /// Script-provided AppIds are merged into `apps.inject` before the runtime
    /// config is published, so this remains the single source of truth for
    /// both configured and scripted apps.
    pub fn is_controlled_app(&self, app_id: AppId) -> bool {
        self.app_category(app_id).is_some()
    }

    pub fn purchase_time(&self, app_id: AppId) -> u32 {
        self.apps
            .inject
            .iter()
            .find(|a| a.id == app_id)
            .map(|a| a.purchase_time)
            .unwrap_or(0)
    }

    pub fn ticket_mode(&self, app_id: AppId) -> TicketMode {
        self.apps
            .inject
            .iter()
            .find(|a| a.id == app_id)
            .map(|a| a.ticket)
            .unwrap_or(TicketMode::Forge)
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
        self.cloud.backend != CloudBackendMode::Disabled
    }

    pub fn local_cloud_configured(&self) -> bool {
        self.cloud.backend == CloudBackendMode::Local
    }

    pub fn cumulus_configured(&self) -> bool {
        self.cloud.backend == CloudBackendMode::Cumulus
    }
}
