use std::path::Path;

use tracing::{debug, info, warn};
use vapor_forge_core::ScriptState;

use crate::bindings::execute_file;
use crate::report::{ScriptExecutionOptions, ScriptExecutionReport, ScriptFileReport};

pub fn execute_scripts(dirs: &[String]) -> ScriptState {
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

    if !report.state.apps.is_empty() {
        info!(
            apps = report.state.apps.len(),
            depot_keys = report.state.depot_keys.len(),
            manifests = report.state.manifests.len(),
            tickets = report.state.app_tickets.len(),
            "scripting: scripts loaded"
        );
    }

    report.state
}

pub fn execute_scripts_report(dirs: &[String]) -> ScriptExecutionReport {
    execute_scripts_report_with_options(dirs, ScriptExecutionOptions::report_default())
}

pub fn execute_scripts_report_with_options(
    dirs: &[String],
    options: ScriptExecutionOptions,
) -> ScriptExecutionReport {
    let mut report = ScriptExecutionReport::default();

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
            let result = execute_file(&path, &mut report.state, &options, &mut report.calls)
                .map_err(|error| error.to_string());
            report.files.push(ScriptFileReport {
                path: path.display().to_string(),
                result,
            });
        }
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
