use std::path::PathBuf;

use tracing::{info, warn};
use vapor_forge_core::ScriptState;

use crate::registry::RegistryHandle;
use crate::report::{ScriptCallReport, ScriptExecutionOptions, ScriptFileReport};

#[derive(Clone, Debug)]
pub(crate) struct ScriptSource {
    pub path: PathBuf,
    pub source: String,
}

pub(crate) struct ProviderExecution {
    pub state: ScriptState,
    pub files: Vec<ScriptFileReport>,
    pub calls: Vec<ScriptCallReport>,
    pub provider: Option<ManifestCodeProvider>,
    pub handle: RegistryHandle,
}

#[derive(Clone)]
pub struct ManifestCodeProvider {
    handle: RegistryHandle,
    has_basic: bool,
    has_extended: bool,
}

impl std::fmt::Debug for ManifestCodeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestCodeProvider")
            .field("has_basic", &self.has_basic)
            .field("has_extended", &self.has_extended)
            .finish_non_exhaustive()
    }
}

impl ManifestCodeProvider {
    /// Build a provider that reuses an existing registry handle, e.g. after an
    /// incremental Lua reload rediscovered the callback set.
    pub fn from(handle: RegistryHandle, has_basic: bool, has_extended: bool) -> Self {
        Self {
            handle,
            has_basic,
            has_extended,
        }
    }

    pub(crate) fn execute(
        sources: Vec<ScriptSource>,
        options: ScriptExecutionOptions,
    ) -> Result<ProviderExecution, String> {
        let registry =
            crate::registry::ScriptRegistry::new(&options).map_err(|error| error.to_string())?;
        let handle = RegistryHandle::new(registry);

        let files: Vec<ScriptFileReport> = sources
            .iter()
            .map(|source| {
                let errors = handle.parse_file(&source.path, &source.source);
                ScriptFileReport {
                    path: source.path.display().to_string(),
                    result: if errors.is_empty() {
                        Ok(())
                    } else {
                        Err(errors.join("\n"))
                    },
                }
            })
            .collect();

        let (has_basic, has_extended) = handle.provider_functions();
        let state = handle.snapshot_state();
        let calls = handle.drain_calls();

        let provider = if has_basic || has_extended {
            Some(Self {
                handle: handle.clone(),
                has_basic,
                has_extended,
            })
        } else {
            None
        };

        Ok(ProviderExecution {
            state,
            files,
            calls,
            provider,
            handle,
        })
    }

    pub fn fetch(&self, app_id: u32, depot_id: u32, gid: u64) -> Result<Option<u64>, String> {
        let results = self
            .handle
            .invoke_manifest_callbacks(app_id, depot_id, gid, self.has_extended, self.has_basic)
            .map_err(|error| error.to_string())?;
        if let Some(result) = results.extended {
            match result {
                Ok(Some(code)) => {
                    info!(
                        app_id,
                        depot_id,
                        gid,
                        code,
                        "request_code: manifest code obtained from fetch_manifest_code_ex"
                    );
                    return Ok(Some(code));
                }
                Ok(None) => {}
                Err(error) => warn!(
                    gid,
                    %error,
                    "request_code: fetch_manifest_code_ex failed"
                ),
            }
        }
        if let Some(result) = results.basic {
            match result {
                Ok(Some(code)) => {
                    info!(
                        gid,
                        code, "request_code: manifest code obtained from fetch_manifest_code"
                    );
                    return Ok(Some(code));
                }
                Ok(None) => {}
                Err(error) => warn!(
                    gid,
                    %error,
                    "request_code: fetch_manifest_code failed"
                ),
            }
        }
        Ok(None)
    }

    pub fn has_basic(&self) -> bool {
        self.has_basic
    }

    pub fn has_extended(&self) -> bool {
        self.has_extended
    }
}
