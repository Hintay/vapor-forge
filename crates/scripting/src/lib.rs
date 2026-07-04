#![forbid(unsafe_code)]

use thiserror::Error;

mod bindings;
mod executor;
mod report;

#[cfg(test)]
mod tests;

pub use executor::{execute_scripts, execute_scripts_report, execute_scripts_report_with_options};
pub use report::{
    ScriptCallReport, ScriptExecutionOptions, ScriptExecutionReport, ScriptFileReport,
};
pub use vapor_forge_core::{ManifestOverride, ScriptState};

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
