use std::path::Path;

use tracing::{debug, info, warn};
use vapor_forge_core::ScriptState;

use crate::manifest_provider::{ManifestCodeProvider, ScriptSource};
use crate::registry::RegistryHandle;
use crate::report::{ScriptExecutionOptions, ScriptExecutionReport, ScriptFileReport};

#[derive(Clone, Debug, Default)]
pub struct ScriptRuntime {
    pub state: ScriptState,
    pub manifest_code_provider: Option<ManifestCodeProvider>,
    pub registry: Option<RegistryHandle>,
}

pub fn execute_scripts(dirs: &[String]) -> ScriptState {
    execute_scripts_runtime(dirs).state
}

pub fn execute_scripts_runtime(dirs: &[String]) -> ScriptRuntime {
    let report = execute_scripts_report_with_options(dirs, ScriptExecutionOptions::runtime());

    for skipped in &report.skipped_dirs {
        debug!(dir = %skipped, "scripting: directory not found, skipping");
    }
    for file in &report.files {
        if let Err(error) = &file.result {
            warn!(
                error = %error,
                file = %file.path,
                "scripting: script execution failed"
            );
        }
    }

    if !report.state.apps.is_empty() || report.manifest_code_provider.is_some() {
        info!(
            apps = report.state.apps.len(),
            depot_keys = report.state.depot_keys.len(),
            manifests = report.state.manifests.len(),
            tickets = report.state.app_tickets.len(),
            manifest_code = report
                .manifest_code_provider
                .as_ref()
                .is_some_and(ManifestCodeProvider::has_basic),
            manifest_code_ex = report
                .manifest_code_provider
                .as_ref()
                .is_some_and(ManifestCodeProvider::has_extended),
            "scripting: scripts loaded"
        );
    }

    ScriptRuntime {
        state: report.state,
        manifest_code_provider: report.manifest_code_provider,
        registry: report.registry,
    }
}

pub fn execute_scripts_report(dirs: &[String]) -> ScriptExecutionReport {
    execute_scripts_report_with_options(dirs, ScriptExecutionOptions::report_default())
}

pub fn execute_scripts_report_with_options(
    dirs: &[String],
    options: ScriptExecutionOptions,
) -> ScriptExecutionReport {
    let mut report = ScriptExecutionReport::default();
    let mut sources = Vec::new();

    for dir in dirs {
        let expanded = expand_dir(dir);
        if !expanded.is_dir() {
            report.skipped_dirs.push(expanded.display().to_string());
            continue;
        }

        let mut entries: Vec<_> = match std::fs::read_dir(&expanded) {
            Ok(read_dir) => read_dir
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "lua"))
                .collect(),
            Err(error) => {
                report.files.push(ScriptFileReport {
                    path: expanded.display().to_string(),
                    result: Err(format!("read_dir failed: {error}")),
                });
                continue;
            }
        };
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            let path = entry.path();
            match std::fs::read_to_string(&path) {
                Ok(source) => sources.push(ScriptSource { path, source }),
                Err(error) => report.files.push(ScriptFileReport {
                    path: path.display().to_string(),
                    result: Err(error.to_string()),
                }),
            }
        }
    }

    match ManifestCodeProvider::execute(sources, options) {
        Ok(execution) => {
            report.state = execution.state;
            report.files.extend(execution.files);
            report.calls = execution.calls;
            report.manifest_code_provider = execution.provider;
            report.registry = Some(execution.handle);
        }
        Err(error) => report.files.push(ScriptFileReport {
            path: "<lua-runtime>".to_owned(),
            result: Err(error),
        }),
    }

    report
}

fn expand_dir(dir: &str) -> std::path::PathBuf {
    let path = Path::new(dir);
    if !dir.starts_with('~') {
        return path.to_path_buf();
    }

    std::env::var_os("HOME")
        .map(|home| Path::new(&home).join(dir.trim_start_matches("~/")))
        .unwrap_or_else(|| path.to_path_buf())
}
