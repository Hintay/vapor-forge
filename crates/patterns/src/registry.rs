//! Pattern registry with compiled-in defaults and runtime TOML override.

use std::collections::HashMap;
use std::path::Path;

/// Follow mode for pattern resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FollowMode {
    /// Pattern matches the function prologue directly.
    None,
    /// Pattern matches a call site; follow E8/E9 rel32 to callee.
    Relative,
    /// Pattern matches function body; scan upward for prologue bytes.
    Upward,
}

/// A single pattern definition (compile-time or runtime).
#[derive(Clone, Debug)]
pub struct PatternDef {
    pub name: &'static str,
    pub pattern: &'static str,
    pub follow: FollowMode,
    pub prologue: Option<&'static [u8]>,
    pub optional: bool,
    pub pic_entry: bool,
}

// Generated at compile time from res/patterns.toml
include!(concat!(env!("OUT_DIR"), "/patterns_generated.rs"));

/// Runtime pattern entry (loaded from external TOML file).
#[derive(Clone, Debug)]
pub struct RuntimePatternEntry {
    pub pattern: String,
    pub follow: FollowMode,
    pub prologue: Option<Vec<u8>>,
    pub optional: bool,
    pub pic_entry: bool,
}

/// Pattern registry with embedded defaults + optional runtime overrides.
pub struct PatternRegistry {
    overrides: HashMap<String, RuntimePatternEntry>,
}

impl PatternRegistry {
    /// Create a registry with embedded patterns only (no runtime overrides).
    pub fn embedded() -> Self {
        Self {
            overrides: HashMap::new(),
        }
    }

    /// Load runtime overrides from a TOML file. Patterns in the file take
    /// precedence over compiled-in defaults.
    pub fn with_overrides(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => match parse_toml_overrides(&text) {
                Ok(overrides) => Self { overrides },
                Err(e) => {
                    eprintln!("[steam-runtime-rs] WARNING: pattern override parse error in {}: {}, falling back to embedded", path.display(), e);
                    Self::embedded()
                }
            },
            Err(e) => {
                eprintln!("[steam-runtime-rs] WARNING: failed to read pattern overrides {}: {}, falling back to embedded", path.display(), e);
                Self::embedded()
            }
        }
    }

    /// Look up a pattern by function name. Runtime override wins over embedded.
    pub fn get(&self, name: &str) -> Option<PatternLookup<'_>> {
        if let Some(rt) = self.overrides.get(name) {
            return Some(PatternLookup::Runtime(rt));
        }
        EMBEDDED_PATTERNS
            .iter()
            .find(|p| p.name == name)
            .map(PatternLookup::Embedded)
    }

    /// Number of unique patterns (embedded + overrides).
    pub fn len(&self) -> usize {
        let mut names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for p in EMBEDDED_PATTERNS {
            names.insert(p.name);
        }
        for k in self.overrides.keys() {
            names.insert(k);
        }
        names.len()
    }

    pub fn is_empty(&self) -> bool {
        EMBEDDED_PATTERNS.is_empty() && self.overrides.is_empty()
    }
}

/// A looked-up pattern from either embedded or runtime data.
pub enum PatternLookup<'a> {
    Embedded(&'a PatternDef),
    Runtime(&'a RuntimePatternEntry),
}

impl<'a> PatternLookup<'a> {
    pub fn pattern(&self) -> &str {
        match self {
            Self::Embedded(p) => p.pattern,
            Self::Runtime(p) => &p.pattern,
        }
    }

    pub fn follow(&self) -> FollowMode {
        match self {
            Self::Embedded(p) => p.follow,
            Self::Runtime(p) => p.follow,
        }
    }

    pub fn prologue_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Embedded(p) => p.prologue,
            Self::Runtime(p) => p.prologue.as_deref(),
        }
    }

    pub fn optional(&self) -> bool {
        match self {
            Self::Embedded(p) => p.optional,
            Self::Runtime(p) => p.optional,
        }
    }

    pub fn pic_entry(&self) -> bool {
        match self {
            Self::Embedded(p) => p.pic_entry,
            Self::Runtime(p) => p.pic_entry,
        }
    }
}

/// Parse TOML overrides (same format as res/patterns.toml).
fn parse_toml_overrides(text: &str) -> Result<HashMap<String, RuntimePatternEntry>, String> {
    // Minimal manual TOML parsing to avoid serde at runtime.
    // Format: [steamclient."FunctionName"]\nfollow = "..."\npattern = "..."
    let mut result = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_pattern: Option<String> = None;
    let mut current_follow = FollowMode::None;
    let mut current_prologue: Option<Vec<u8>> = None;
    let mut current_optional = false;
    let mut current_pic_entry = false;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("[steamclient.") {
            // Flush previous entry
            if let (Some(name), Some(pattern)) = (current_name.take(), current_pattern.take()) {
                result.insert(
                    name,
                    RuntimePatternEntry {
                        pattern,
                        follow: current_follow,
                        prologue: current_prologue.take(),
                        optional: current_optional,
                        pic_entry: current_pic_entry,
                    },
                );
            }
            current_follow = FollowMode::None;
            current_prologue = None;
            current_optional = false;
            current_pic_entry = false;

            // Parse: [steamclient."FunctionName"]
            let inner = line
                .trim_start_matches("[steamclient.")
                .trim_end_matches(']')
                .trim_matches('"');
            current_name = Some(inner.to_owned());
        } else if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match key {
                "pattern" => current_pattern = Some(value.to_owned()),
                "follow" => {
                    current_follow = match value {
                        "relative" => FollowMode::Relative,
                        "upward" => FollowMode::Upward,
                        _ => FollowMode::None,
                    };
                }
                "prologue" => {
                    current_prologue = Some(
                        value
                            .split_whitespace()
                            .filter_map(|h| u8::from_str_radix(h, 16).ok())
                            .collect(),
                    );
                }
                "optional" => current_optional = value == "true",
                "pic_entry" => current_pic_entry = value == "true",
                _ => {}
            }
        }
    }

    // Flush last entry
    if let (Some(name), Some(pattern)) = (current_name, current_pattern) {
        result.insert(
            name,
            RuntimePatternEntry {
                pattern,
                follow: current_follow,
                prologue: current_prologue,
                optional: current_optional,
                pic_entry: current_pic_entry,
            },
        );
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_patterns_loaded() {
        assert!(EMBEDDED_PATTERNS.len() >= 16);
    }

    #[test]
    fn registry_finds_embedded() {
        let reg = PatternRegistry::embedded();
        let lookup = reg.get("CUser::CheckAppOwnership").expect("should find");
        assert_eq!(lookup.follow(), FollowMode::Relative);
        assert!(!lookup.pattern().is_empty());
    }

    #[test]
    fn registry_finds_upward_with_prologue() {
        let reg = PatternRegistry::embedded();
        let lookup = reg
            .get("IClientUser::GetAppOwnershipTicketExtendedData")
            .expect("should find");
        assert_eq!(lookup.follow(), FollowMode::Upward);
        assert!(lookup.prologue_bytes().is_some());
        assert!(lookup.optional());
    }

    #[test]
    fn runtime_override_wins() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"]
follow = "none"
pattern = "AA BB CC"
"#;
        let overrides = parse_toml_overrides(toml).unwrap();
        let reg = PatternRegistry { overrides };
        let lookup = reg.get("CUser::CheckAppOwnership").expect("should find");
        assert_eq!(lookup.pattern(), "AA BB CC");
        assert_eq!(lookup.follow(), FollowMode::None);
    }
}
