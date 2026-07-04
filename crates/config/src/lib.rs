#![forbid(unsafe_code)]

use thiserror::Error;

mod model;
mod template;

#[cfg(test)]
mod tests;

pub use model::*;
pub use template::{TemplateSyncDryRun, CONFIG_TEMPLATE};

// Re-export newtypes so callers only need to depend on vapor-forge-config.
pub use vapor_forge_core::{AppId, DepotId, ManifestId};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadFailed(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    ParseFailed(#[from] toml::de::Error),
}
