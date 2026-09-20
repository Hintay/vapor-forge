use serde::de::{IntoDeserializer, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

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
    pub manifest: ManifestSection,
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
    #[serde(default = "default_patterns_url")]
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
    inject: Vec<InjectApp>,
    #[serde(default)]
    pub shared: SharedSection,
    #[serde(skip)]
    app_index: OnceLock<HashMap<AppId, AppCategory>>,
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
    /// Script-provided apps use the Lua source mtime when this is zero.
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
///
/// Native `.so` entries are merged in front of the `LD_PRELOAD` value Steam
/// composes for the game (its overlay renderers), so they reach the game
/// process even though Steam writes that variable after the launch hooks ran.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryInjectSection {
    #[serde(default)]
    pub libs: Vec<LibraryInjectEntry>,
    #[serde(default)]
    pub helper_path: String,
    #[serde(default)]
    pub loader_fix: LoaderFixSection,
}

/// Duplicate-module loader fix, applied by the Proton helper.
///
/// The helper disables thread callouts on any extra loader entry that shares
/// a loaded module's name and entry point, as some third-party loaders register for
/// user32, which otherwise makes wine run that DllMain twice per thread attach
/// and exit. It is only applied where asked for:
///
/// ```toml
/// [library_inject.loader_fix]
/// apps = [812140]      # always on for these apps
/// exclude = []         # never, even when flagged
/// flag = "-loaderfix"  # on for any app whose launch options carry the flag
/// ```
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderFixSection {
    #[serde(default)]
    pub apps: Vec<AppId>,
    #[serde(default)]
    pub exclude: Vec<AppId>,
    #[serde(default)]
    pub flag: String,
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

/// Manifest request-code provider configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSection {
    #[serde(default = "default_manifest_providers")]
    pub providers: Vec<ManifestSource>,
    #[serde(default = "default_timeout_connect_ms")]
    pub timeout_connect_ms: u64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Minimum gap between two requests to the same provider.
    ///
    /// These endpoints are small shared services — 20770407 publishes 10
    /// requests / 10 s per IP and degrades for everyone when one client
    /// floods it — and Steam asks for one code per depot, so a big install
    /// would burst without this.
    #[serde(default = "default_min_interval_ms")]
    pub min_interval_ms: u64,
}

impl Default for ManifestSection {
    fn default() -> Self {
        Self {
            providers: default_manifest_providers(),
            timeout_connect_ms: default_timeout_connect_ms(),
            timeout_ms: default_timeout_ms(),
            min_interval_ms: default_min_interval_ms(),
        }
    }
}

/// A provider shipped with the build.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize)]
pub enum ManifestProvider {
    /// A pool of accounts that hold real licences. Since 2026-09-09 Valve only
    /// mints a request code for an account that owns the app, so this is the
    /// shape that still works: it asks Valve per request and takes Valve's own
    /// (depot, manifest) parameters, resolving the app id itself. A title
    /// nobody in the pool owns answers `Unauthorized`.
    #[serde(rename = "20770407")]
    Pool20770407,
    #[serde(rename = "manifestdex")]
    ManifestDex,
    #[serde(rename = "opensteamtool")]
    OpenSteamTool,
    #[serde(rename = "wudrm")]
    Wudrm,
    #[serde(rename = "steamrun")]
    SteamRun,
}

impl ManifestProvider {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pool20770407 => "20770407",
            Self::ManifestDex => "manifestdex",
            Self::OpenSteamTool => "opensteamtool",
            Self::Wudrm => "wudrm",
            Self::SteamRun => "steamrun",
        }
    }

    pub const fn url_template(self) -> &'static str {
        match self {
            Self::Pool20770407 => "https://20770407.xyz/manifest/{depotId}/{gid}",
            Self::ManifestDex => "https://manifest.manifestdex.com/{gid}",
            Self::OpenSteamTool => "https://manifest.opensteamtool.com/{gid}",
            Self::Wudrm => "http://gmrc.wudrm.com/manifest/{gid}",
            Self::SteamRun => "https://manifest.steam.run/api/manifest/{gid}",
        }
    }

    /// Providers that reject or rate-limit the default agent string.
    pub const fn user_agent(self) -> Option<&'static str> {
        match self {
            // Identify as ourselves rather than borrow another client's string:
            // this endpoint is a small shared service whose operator may one day
            // quota by client, and we would rather be our own small bucket.
            Self::Pool20770407 => Some(concat!("vapor-forge/", env!("CARGO_PKG_VERSION"))),
            Self::ManifestDex => Some("ManifestDeX/1.0"),
            Self::OpenSteamTool => Some("OpenSteamTool/1.0"),
            Self::Wudrm | Self::SteamRun => None,
        }
    }

    pub const fn response_format(self) -> ManifestResponseFormat {
        match self {
            Self::SteamRun => ManifestResponseFormat::Json,
            _ => ManifestResponseFormat::Plain,
        }
    }

    /// Field holding the code for [`ManifestResponseFormat::Json`] providers.
    pub const fn json_field(self) -> Option<&'static str> {
        match self {
            Self::SteamRun => Some("content"),
            _ => None,
        }
    }
}

/// How a provider's 200 response carries the request code.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ManifestResponseFormat {
    /// Whole body is the decimal code.
    #[default]
    Plain,
    /// Code sits in a top-level JSON string or number field.
    Json,
}

/// A provider defined in the config file, so a new source can be used without
/// waiting for a build that knows about it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CustomManifestProvider {
    /// Identifies the entry in logs and in the rate-limit cooldown table.
    pub name: String,
    /// Endpoint with a `{gid}` placeholder.
    pub url: String,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub format: ManifestResponseFormat,
    /// Required when `format = "json"`.
    #[serde(default)]
    pub json_field: Option<String>,
    /// Overrides `[manifest] min_interval_ms` for this provider.
    #[serde(default)]
    pub min_interval_ms: Option<u64>,
}

/// One entry of the provider chain: a built-in name, or an inline table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestSource {
    BuiltIn(ManifestProvider),
    Custom(CustomManifestProvider),
}

impl ManifestSource {
    pub fn name(&self) -> &str {
        match self {
            Self::BuiltIn(provider) => provider.name(),
            Self::Custom(custom) => &custom.name,
        }
    }

    pub fn url_template(&self) -> &str {
        match self {
            Self::BuiltIn(provider) => provider.url_template(),
            Self::Custom(custom) => &custom.url,
        }
    }

    pub fn user_agent(&self) -> Option<&str> {
        match self {
            Self::BuiltIn(provider) => provider.user_agent(),
            Self::Custom(custom) => custom.user_agent.as_deref(),
        }
    }

    pub fn response_format(&self) -> ManifestResponseFormat {
        match self {
            Self::BuiltIn(provider) => provider.response_format(),
            Self::Custom(custom) => custom.format,
        }
    }

    pub fn json_field(&self) -> Option<&str> {
        match self {
            Self::BuiltIn(provider) => provider.json_field(),
            Self::Custom(custom) => custom.json_field.as_deref(),
        }
    }

    /// Minimum gap before the next request to this provider.
    pub fn min_interval(&self, section_default_ms: u64) -> std::time::Duration {
        let ms = match self {
            Self::BuiltIn(_) => section_default_ms,
            Self::Custom(custom) => custom.min_interval_ms.unwrap_or(section_default_ms),
        };
        std::time::Duration::from_millis(ms)
    }

    /// Expand the endpoint template for one request.
    ///
    /// `{gid}` is always substituted; `{depotId}` and `{appId}` let a provider
    /// that mints codes through licensed accounts take Valve's own
    /// GetManifestRequestCode shape (depot plus manifest).
    pub fn resolve_url(&self, app_id: u32, depot_id: u32, gid: u64) -> String {
        self.url_template()
            .replace("{gid}", &gid.to_string())
            .replace("{depotId}", &depot_id.to_string())
            .replace("{appId}", &app_id.to_string())
    }

    /// Why this entry cannot be used, or `None` when it is well-formed.
    ///
    /// A bad entry is skipped rather than failing the whole config: the point
    /// of custom providers is that users edit them without a build, so one typo
    /// must not take the other sources down with it.
    pub fn rejection(&self) -> Option<String> {
        let Self::Custom(custom) = self else {
            return None;
        };
        if custom.name.trim().is_empty() {
            return Some("custom manifest provider has an empty name".to_owned());
        }
        if !custom.url.contains("{gid}") {
            return Some(format!(
                "custom manifest provider `{}` has no {{gid}} placeholder in its url",
                custom.name
            ));
        }
        if !custom.url.starts_with("http://") && !custom.url.starts_with("https://") {
            return Some(format!(
                "custom manifest provider `{}` must use an http:// or https:// url",
                custom.name
            ));
        }
        if custom.format == ManifestResponseFormat::Json
            && custom.json_field.as_deref().unwrap_or("").trim().is_empty()
        {
            return Some(format!(
                "custom manifest provider `{}` sets format = \"json\" but no json_field",
                custom.name
            ));
        }
        None
    }
}

impl<'de> Deserialize<'de> for ManifestSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SourceVisitor;

        impl<'de> Visitor<'de> for SourceVisitor {
            type Value = ManifestSource;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a built-in provider name or a custom provider table")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                // Delegate so an unknown name still reports the built-in list.
                ManifestProvider::deserialize(value.into_deserializer())
                    .map(ManifestSource::BuiltIn)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                CustomManifestProvider::deserialize(serde::de::value::MapAccessDeserializer::new(
                    map,
                ))
                .map(ManifestSource::Custom)
            }
        }

        deserializer.deserialize_any(SourceVisitor)
    }
}

impl ManifestSection {
    /// Problems that make individual entries unusable, plus duplicate names.
    ///
    /// Names key the rate-limit cooldown table, so a duplicate would make two
    /// sources share one cooldown.
    pub fn rejections(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for source in &self.providers {
            if let Some(problem) = source.rejection() {
                problems.push(problem);
                continue;
            }
            if !seen.insert(source.name()) {
                problems.push(format!(
                    "duplicate manifest provider name `{}`",
                    source.name()
                ));
            }
        }
        problems
    }
}

fn default_manifest_providers() -> Vec<ManifestSource> {
    vec![
        ManifestSource::BuiltIn(ManifestProvider::Pool20770407),
        ManifestSource::BuiltIn(ManifestProvider::ManifestDex),
        ManifestSource::BuiltIn(ManifestProvider::OpenSteamTool),
        ManifestSource::BuiltIn(ManifestProvider::Wudrm),
        ManifestSource::BuiltIn(ManifestProvider::SteamRun),
    ]
}

fn default_timeout_connect_ms() -> u64 {
    5000
}

fn default_timeout_ms() -> u64 {
    15000
}

fn default_min_interval_ms() -> u64 {
    1000
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
            patterns_url: default_patterns_url(),
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

/// Online pattern hotfixes come from this repository's own pattern sources, so
/// a Steam update can be answered by pushing a file instead of shipping a build.
/// `{arch}` selects the per-architecture file; ordinary and steamrt are already
/// covered inside it as `[[...variants]]`. An empty value disables the fetch.
fn default_patterns_url() -> String {
    "https://raw.githubusercontent.com/Hintay/vapor-forge/main/res/patterns/{arch}.toml".to_owned()
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

impl AppsSection {
    pub fn with_inject(inject: Vec<InjectApp>) -> Self {
        let apps = Self {
            inject,
            ..Self::default()
        };
        apps.app_index();
        apps
    }

    pub fn inject(&self) -> &[InjectApp] {
        &self.inject
    }

    pub fn push_inject(&mut self, app: InjectApp) {
        if let Some(index) = self.app_index.get_mut() {
            index.reserve(1 + app.dlc.len());
            Self::index_app(index, &app);
        }
        self.inject.push(app);
    }

    pub fn extend_inject(&mut self, apps: Vec<InjectApp>) {
        if apps.is_empty() {
            return;
        }

        self.inject.reserve(apps.len());
        if let Some(index) = self.app_index.get_mut() {
            let additional_entries = apps.iter().map(|app| 1 + app.dlc.len()).sum();
            index.reserve(additional_entries);
            for app in &apps {
                Self::index_app(index, app);
            }
        }
        self.inject.extend(apps);
    }

    fn app_category(&self, app_id: AppId) -> Option<AppCategory> {
        self.app_index().get(&app_id).copied()
    }

    fn is_controlled_app(&self, app_id: AppId) -> bool {
        self.app_index().contains_key(&app_id)
    }

    fn app_index(&self) -> &HashMap<AppId, AppCategory> {
        self.app_index.get_or_init(|| {
            let entry_count = self.inject.iter().map(|app| 1 + app.dlc.len()).sum();
            let mut index = HashMap::with_capacity(entry_count);
            for app in &self.inject {
                Self::index_app(&mut index, app);
            }
            index
        })
    }

    fn index_app(index: &mut HashMap<AppId, AppCategory>, app: &InjectApp) {
        index.entry(app.id).or_insert(AppCategory::Inject);
        for &dlc in &app.dlc {
            index
                .entry(dlc)
                .or_insert(AppCategory::InjectDlc { parent: app.id });
        }
    }
}

impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&text)?;
        config.apps.app_index();
        Ok(config)
    }

    pub fn app_category(&self, app_id: AppId) -> Option<AppCategory> {
        self.apps.app_category(app_id)
    }

    /// Returns whether this AppId is managed by the effective runtime config.
    ///
    /// Script-provided AppIds are merged into `apps.inject` before the runtime
    /// config is published, so this remains the single source of truth for
    /// both configured and scripted apps.
    pub fn is_controlled_app(&self, app_id: AppId) -> bool {
        self.apps.is_controlled_app(app_id)
    }

    pub fn purchase_time(&self, app_id: AppId) -> u32 {
        self.apps
            .inject()
            .iter()
            .find(|a| a.id == app_id)
            .map(|a| a.purchase_time)
            .unwrap_or(0)
    }

    pub fn ticket_mode(&self, app_id: AppId) -> TicketMode {
        self.apps
            .inject()
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
        for app in self.apps.inject() {
            ids.insert(app.id);
            ids.extend(&app.dlc);
        }
        ids
    }

    pub fn inject_dlc_map(&self) -> HashMap<AppId, Vec<AppId>> {
        self.apps
            .inject()
            .iter()
            .filter(|app| !app.dlc.is_empty())
            .map(|app| (app.id, app.dlc.clone()))
            .collect()
    }

    pub fn has_any_inject_apps(&self) -> bool {
        !self.apps.inject().is_empty()
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
