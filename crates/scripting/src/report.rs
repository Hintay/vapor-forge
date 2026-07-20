use vapor_forge_core::ScriptState;

use crate::registry::RegistryHandle;
use crate::ManifestCodeProvider;

#[derive(Clone, Debug, Default)]
pub struct ScriptExecutionReport {
    pub state: ScriptState,
    pub manifest_code_provider: Option<ManifestCodeProvider>,
    pub registry: Option<RegistryHandle>,
    pub files: Vec<ScriptFileReport>,
    pub calls: Vec<ScriptCallReport>,
    pub skipped_dirs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ScriptFileReport {
    pub path: String,
    pub result: Result<(), String>,
}

#[derive(Clone, Debug)]
pub struct ScriptCallReport {
    pub path: String,
    pub function: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct ScriptExecutionOptions {
    pub allow_network: bool,
    pub allowed_hosts: Vec<String>,
    pub network_timeout_ms: Option<u64>,
    pub redact_network_urls: bool,
    pub record_calls: bool,
}

impl ScriptExecutionOptions {
    pub fn runtime() -> Self {
        Self {
            allow_network: true,
            allowed_hosts: Vec::new(),
            network_timeout_ms: None,
            redact_network_urls: false,
            record_calls: false,
        }
    }

    pub fn report_default() -> Self {
        Self {
            allow_network: true,
            allowed_hosts: Vec::new(),
            network_timeout_ms: None,
            redact_network_urls: false,
            record_calls: true,
        }
    }

    pub fn check_default() -> Self {
        Self {
            allow_network: false,
            allowed_hosts: Vec::new(),
            network_timeout_ms: None,
            redact_network_urls: true,
            record_calls: true,
        }
    }
}

impl Default for ScriptExecutionOptions {
    fn default() -> Self {
        Self::runtime()
    }
}
