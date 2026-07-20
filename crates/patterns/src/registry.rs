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
    /// Pattern identifies a code region; scan forward for the last E8 CALL
    /// before a RET (C3) and follow it. Used when the target function is
    /// called from a unique context but its own body is not unique.
    Call,
}

/// A single pattern definition (compile-time or runtime).
#[derive(Clone, Debug)]
pub struct PatternDef {
    pub name: &'static str,
    pub pattern: &'static str,
    pub follow: FollowMode,
    pub prologue: Option<&'static [u8]>,
    pub callee_pattern: Option<&'static str>,
    pub optional: bool,
    pub pic_entry: bool,
    /// Which shared library this pattern targets ("steamclient" or "steamui").
    pub module: &'static str,
}

// Generated at compile time from res/patterns.toml
include!(concat!(env!("OUT_DIR"), "/patterns_generated.rs"));

/// Runtime pattern entry (loaded from external TOML file).
#[derive(Clone, Debug)]
pub struct RuntimePatternEntry {
    pub pattern: String,
    pub follow: FollowMode,
    pub prologue: Option<Vec<u8>>,
    pub callee_pattern: Option<String>,
    pub optional: bool,
    pub pic_entry: bool,
    pub module: String,
}

/// Pattern registry with embedded defaults + optional runtime overrides.
pub struct PatternRegistry {
    overrides: HashMap<String, Vec<RuntimePatternEntry>>,
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
                    eprintln!("[vapor-forge] WARNING: pattern override parse error in {}: {}, falling back to embedded", path.display(), e);
                    Self::embedded()
                }
            },
            Err(e) => {
                eprintln!("[vapor-forge] WARNING: failed to read pattern overrides {}: {}, falling back to embedded", path.display(), e);
                Self::embedded()
            }
        }
    }

    /// Look up a pattern by function name. Runtime override wins over embedded.
    pub fn get(&self, name: &str) -> Option<PatternLookup<'_>> {
        if let Some(rt) = self.overrides.get(name) {
            return Some(PatternLookup {
                variants: rt.iter().map(PatternVariantLookup::Runtime).collect(),
            });
        }
        let variants = EMBEDDED_PATTERNS
            .iter()
            .filter(|p| p.name == name)
            .map(PatternVariantLookup::Embedded)
            .collect::<Vec<_>>();
        (!variants.is_empty()).then_some(PatternLookup { variants })
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

/// Parse a complete TOML pattern file (same format as res/patterns.toml).
pub fn parse_toml_patterns(text: &str) -> Result<Vec<(String, RuntimePatternEntry)>, String> {
    parse_toml_entries(text)
}

/// A looked-up pattern group from either embedded or runtime data.
pub struct PatternLookup<'a> {
    variants: Vec<PatternVariantLookup<'a>>,
}

impl<'a> PatternLookup<'a> {
    pub fn variants(&self) -> impl Iterator<Item = PatternVariantLookup<'a>> + '_ {
        self.variants.iter().copied()
    }

    fn primary(&self) -> &PatternVariantLookup<'a> {
        &self.variants[0]
    }

    pub fn pattern(&self) -> &str {
        self.primary().pattern()
    }

    pub fn follow(&self) -> FollowMode {
        self.primary().follow()
    }

    pub fn prologue_bytes(&self) -> Option<&[u8]> {
        self.primary().prologue_bytes()
    }

    pub fn callee_pattern(&self) -> Option<&str> {
        self.primary().callee_pattern()
    }

    pub fn optional(&self) -> bool {
        self.primary().optional()
    }

    pub fn pic_entry(&self) -> bool {
        self.primary().pic_entry()
    }

    pub fn module(&self) -> &str {
        self.primary().module()
    }
}

/// A single candidate in a looked-up pattern group.
#[derive(Clone, Copy)]
pub enum PatternVariantLookup<'a> {
    Embedded(&'a PatternDef),
    Runtime(&'a RuntimePatternEntry),
}

impl<'a> PatternVariantLookup<'a> {
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

    pub fn callee_pattern(&self) -> Option<&str> {
        match self {
            Self::Embedded(p) => p.callee_pattern,
            Self::Runtime(p) => p.callee_pattern.as_deref(),
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

    pub fn module(&self) -> &str {
        match self {
            Self::Embedded(p) => p.module,
            Self::Runtime(p) => &p.module,
        }
    }
}

/// Parse TOML overrides (same format as res/patterns.toml).
fn parse_toml_overrides(text: &str) -> Result<HashMap<String, Vec<RuntimePatternEntry>>, String> {
    let mut result = HashMap::new();
    for (name, entry) in parse_toml_entries(text)? {
        result.entry(name).or_insert_with(Vec::new).push(entry);
    }
    Ok(result)
}

fn parse_toml_entries(text: &str) -> Result<Vec<(String, RuntimePatternEntry)>, String> {
    // Minimal manual TOML parsing to avoid serde at runtime.
    // Format: [steamclient."FunctionName"] or [steamui."FunctionName"]
    let mut result = Vec::new();
    let mut defaults: HashMap<(String, String), RuntimePatternEntry> = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_module: Option<String> = None;
    let mut current_is_variant = false;
    let mut current_start_line = 0usize;
    let mut current_pattern: Option<String> = None;
    let mut current_follow: Option<FollowMode> = None;
    let mut current_prologue: Option<Vec<u8>> = None;
    let mut current_callee_pattern: Option<String> = None;
    let mut current_optional: Option<bool> = None;
    let mut current_pic_entry: Option<bool> = None;

    let flush = |result: &mut Vec<(String, RuntimePatternEntry)>,
                 defaults: &mut HashMap<(String, String), RuntimePatternEntry>,
                 name: Option<String>,
                 module: Option<String>,
                 is_variant: bool,
                 start_line: usize,
                 pattern: Option<String>,
                 follow: Option<FollowMode>,
                 prologue: Option<Vec<u8>>,
                 callee_pattern: Option<String>,
                 optional: Option<bool>,
                 pic_entry: Option<bool>|
     -> Result<(), String> {
        let Some(name) = name else {
            return Ok(());
        };
        let Some(module) = module else {
            return Err(format!(
                "line {start_line}: missing module for section {name:?}"
            ));
        };
        let Some(pattern) = pattern else {
            return Err(format!(
                "line {start_line}: missing required pattern for {name:?}"
            ));
        };
        let inherited = is_variant
            .then(|| defaults.get(&(module.clone(), name.clone())))
            .flatten();
        let entry = RuntimePatternEntry {
            pattern,
            follow: follow
                .unwrap_or_else(|| inherited.map_or(FollowMode::None, |entry| entry.follow)),
            prologue: prologue.or_else(|| inherited.and_then(|entry| entry.prologue.clone())),
            callee_pattern: callee_pattern
                .or_else(|| inherited.and_then(|entry| entry.callee_pattern.clone())),
            optional: optional.unwrap_or_else(|| inherited.is_some_and(|entry| entry.optional)),
            pic_entry: pic_entry.unwrap_or_else(|| inherited.is_some_and(|entry| entry.pic_entry)),
            module: module.clone(),
        };
        if !is_variant {
            defaults.insert((module, name.clone()), entry.clone());
        }
        result.push((name, entry));

        Ok(())
    };

    for (line_idx, line) in text.lines().enumerate() {
        let line_no = line_idx + 1;
        let line = strip_inline_comment(line).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') {
            let (module, name, is_variant) = parse_section_header(line, line_no)?;
            flush(
                &mut result,
                &mut defaults,
                current_name.take(),
                current_module.take(),
                current_is_variant,
                current_start_line,
                current_pattern.take(),
                current_follow,
                current_prologue.take(),
                current_callee_pattern.take(),
                current_optional,
                current_pic_entry,
            )?;
            current_follow = None;
            current_prologue = None;
            current_callee_pattern = None;
            current_optional = None;
            current_pic_entry = None;
            current_module = Some(module);
            current_name = Some(name);
            current_is_variant = is_variant;
            current_start_line = line_no;
        } else if let Some((key, value)) = line.split_once('=') {
            if current_name.is_none() {
                return Err(format!("line {line_no}: key outside a pattern section"));
            }
            let key = key.trim();
            let value = value.trim();
            match key {
                "pattern" => current_pattern = Some(parse_quoted_string(value, line_no, key)?),
                "follow" => {
                    current_follow =
                        Some(match parse_quoted_string(value, line_no, key)?.as_str() {
                            "none" => FollowMode::None,
                            "relative" => FollowMode::Relative,
                            "upward" => FollowMode::Upward,
                            "call" => FollowMode::Call,
                            other => {
                                return Err(format!(
                                    "line {line_no}: unknown follow mode {other:?}"
                                ));
                            }
                        });
                }
                "prologue" => {
                    let value = parse_quoted_string(value, line_no, key)?;
                    current_prologue = Some(parse_hex_bytes(&value, line_no, key)?);
                }
                "callee_pattern" => {
                    current_callee_pattern = Some(parse_quoted_string(value, line_no, key)?)
                }
                "optional" if current_is_variant => {
                    return Err(format!(
                        "line {line_no}: optional is only allowed on the primary pattern section"
                    ));
                }
                "optional" => current_optional = Some(parse_bool(value, line_no, key)?),
                "pic_entry" => current_pic_entry = Some(parse_bool(value, line_no, key)?),
                _ => return Err(format!("line {line_no}: unknown key {key:?}")),
            }
        } else {
            return Err(format!(
                "line {line_no}: expected section header or key/value"
            ));
        }
    }

    // Flush last entry
    flush(
        &mut result,
        &mut defaults,
        current_name,
        current_module,
        current_is_variant,
        current_start_line,
        current_pattern,
        current_follow,
        current_prologue,
        current_callee_pattern,
        current_optional,
        current_pic_entry,
    )?;

    Ok(result)
}

fn strip_inline_comment(line: &str) -> &str {
    let mut in_string = false;
    for (idx, ch) in line.char_indices() {
        if ch == '"' {
            in_string = !in_string;
        } else if ch == '#' && !in_string {
            return &line[..idx];
        }
    }
    line
}

fn parse_section_header(line: &str, line_no: usize) -> Result<(String, String, bool), String> {
    let (inner, is_variant) = if line.starts_with("[[") {
        if !line.ends_with("]]") {
            return Err(format!("line {line_no}: malformed section header"));
        }
        (&line[2..line.len() - 2], true)
    } else {
        if !line.ends_with(']') {
            return Err(format!("line {line_no}: malformed section header"));
        }
        (&line[1..line.len() - 1], false)
    };

    if is_variant && !inner.ends_with(".variants") {
        return Err(format!("line {line_no}: malformed section header"));
    }
    let inner = inner.strip_suffix(".variants").unwrap_or(inner);
    let (module, quoted_name) = inner
        .split_once('.')
        .ok_or_else(|| format!("line {line_no}: malformed section header"))?;
    if module != "steamclient" && module != "steamui" {
        return Err(format!(
            "line {line_no}: unsupported pattern module {module:?}"
        ));
    }
    let name = parse_quoted_string(quoted_name.trim(), line_no, "section name")?;
    if name.is_empty() {
        return Err(format!("line {line_no}: empty pattern section name"));
    }
    Ok((module.to_owned(), name, is_variant))
}

fn parse_quoted_string(value: &str, line_no: usize, key: &str) -> Result<String, String> {
    if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
        return Err(format!("line {line_no}: {key} must be a quoted string"));
    }
    Ok(value[1..value.len() - 1].to_owned())
}

fn parse_hex_bytes(value: &str, line_no: usize, key: &str) -> Result<Vec<u8>, String> {
    if value.trim().is_empty() {
        return Err(format!("line {line_no}: {key} must not be empty"));
    }
    let mut bytes = Vec::new();
    for token in value.split_whitespace() {
        if token.len() != 2 {
            return Err(format!(
                "line {line_no}: invalid hex byte {token:?} in {key}"
            ));
        }
        let byte = u8::from_str_radix(token, 16)
            .map_err(|_| format!("line {line_no}: invalid hex byte {token:?} in {key}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn parse_bool(value: &str, line_no: usize, key: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("line {line_no}: {key} must be true or false")),
    }
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
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(lookup.follow(), FollowMode::None);
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        assert_eq!(lookup.follow(), FollowMode::Relative);
        assert!(!lookup.pattern().is_empty());
    }

    #[test]
    fn registry_omits_vtable_resolved_ticket_adapters() {
        let reg = PatternRegistry::embedded();
        for name in [
            "IClientUser::GetAppOwnershipTicketExtendedData",
            "IClientUser::BUpdateAppOwnershipTicket",
            "IClientUser::IsUserSubscribedAppInTicket",
        ] {
            assert!(reg.get(name).is_none(), "{name} should use vtable scanning");
        }
    }

    #[test]
    fn runtime_override_wins() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"]
follow = "none"
pattern = "AA BB CC"
callee_pattern = "55 89 E5"
"#;
        let overrides = parse_toml_overrides(toml).unwrap();
        let reg = PatternRegistry { overrides };
        let lookup = reg.get("CUser::CheckAppOwnership").expect("should find");
        assert_eq!(lookup.pattern(), "AA BB CC");
        assert_eq!(lookup.callee_pattern(), Some("55 89 E5"));
        assert_eq!(lookup.follow(), FollowMode::None);
    }

    #[test]
    fn runtime_override_rejects_unknown_follow() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"]
follow = "sideways"
pattern = "AA BB CC"
"#;
        let err = parse_toml_overrides(toml).unwrap_err();
        assert!(err.contains("unknown follow mode"));
    }

    #[test]
    fn runtime_override_rejects_invalid_prologue_hex() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"]
follow = "upward"
prologue = "55 GG"
pattern = "AA BB CC"
"#;
        let err = parse_toml_overrides(toml).unwrap_err();
        assert!(err.contains("invalid hex byte"));
    }

    #[test]
    fn runtime_override_rejects_missing_pattern() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"]
follow = "none"
"#;
        let err = parse_toml_overrides(toml).unwrap_err();
        assert!(err.contains("missing required pattern"));
    }

    #[test]
    fn runtime_override_rejects_unknown_key() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"]
follow = "none"
pattern = "AA BB CC"
offset = "0"
"#;
        let err = parse_toml_overrides(toml).unwrap_err();
        assert!(err.contains("unknown key"));
    }

    #[test]
    fn runtime_override_allows_inline_comments() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"] # replacement pattern
follow = "none"
pattern = "AA BB CC" # bytes
optional = true
"#;
        let overrides = parse_toml_overrides(toml).unwrap();
        let entry = &overrides.get("CUser::CheckAppOwnership").unwrap()[0];
        assert_eq!(entry.pattern, "AA BB CC");
        assert!(entry.optional);
    }

    #[test]
    fn runtime_override_allows_variants() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"]
follow = "relative"
pattern = "E8 ? ? ? ?"
optional = true

[[steamclient."CUser::CheckAppOwnership".variants]]
pattern = "E9 ? ? ? ?"
"#;
        let overrides = parse_toml_overrides(toml).unwrap();
        let entries = overrides.get("CUser::CheckAppOwnership").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].pattern, "E9 ? ? ? ?");
        assert_eq!(entries[1].follow, FollowMode::Relative);
        assert!(entries[1].optional);
    }

    #[test]
    fn runtime_override_rejects_variant_optional() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"]
pattern = "E8 ? ? ? ?"

[[steamclient."CUser::CheckAppOwnership".variants]]
pattern = "E9 ? ? ? ?"
optional = true
"#;
        let err = parse_toml_overrides(toml).unwrap_err();
        assert!(err.contains("optional is only allowed on the primary pattern section"));
    }
}
