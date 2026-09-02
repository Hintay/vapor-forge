//! Pattern registry with compiled-in defaults and validated runtime hotfixes.

use std::collections::HashMap;
use std::path::Path;

use crate::{Pattern, PatternToken};

const HOTFIX_FORMAT: u32 = 1;
const MAX_HOTFIX_VARIANTS_PER_PATTERN: usize = 8;
const MAX_HOTFIX_SELECTED_VARIANTS: usize = 64;
const MAX_HOTFIX_PATTERN_TOKENS: usize = 256;
const MAX_HOTFIX_PROLOGUE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PatternArchitecture {
    X86,
    X86_64,
}

impl PatternArchitecture {
    pub const fn current() -> Option<Self> {
        if cfg!(target_arch = "x86") {
            Some(Self::X86)
        } else if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else {
            None
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "x86" => Ok(Self::X86),
            "x86_64" => Ok(Self::X86_64),
            _ => Err(format!("unsupported hotfix architecture {value:?}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SteamBinaryFamily {
    Ordinary,
    SteamRt,
}

impl SteamBinaryFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::SteamRt => "steamrt",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "ordinary" => Ok(Self::Ordinary),
            "steamrt" => Ok(Self::SteamRt),
            _ => Err(format!("unsupported Steam binary family {value:?}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PatternTarget {
    pub architecture: PatternArchitecture,
    pub binary_family: SteamBinaryFamily,
}

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
    pub pic_entry: bool,
    pub steamrt_variant: bool,
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
    pub pic_entry: bool,
    pub steamrt_variant: bool,
    pub module: String,
}

/// Pattern registry with embedded defaults and validated runtime hotfixes.
pub struct PatternRegistry {
    overrides: HashMap<String, Vec<RuntimePatternEntry>>,
    target: Option<PatternTarget>,
    hotfix_revision: Option<u64>,
}

impl PatternRegistry {
    /// Create a registry with embedded patterns only (no runtime overrides).
    pub fn embedded() -> Self {
        Self {
            overrides: HashMap::new(),
            target: None,
            hotfix_revision: None,
        }
    }

    pub fn embedded_for_target(target: PatternTarget) -> Self {
        Self {
            overrides: HashMap::new(),
            target: Some(target),
            hotfix_revision: None,
        }
    }

    /// Load a hotfix file for one exact runtime target.
    pub fn with_hotfix(path: &Path, expected: PatternTarget) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Self::from_hotfix_text(&text, expected)
    }

    pub fn from_hotfix_text(text: &str, expected: PatternTarget) -> Result<Self, String> {
        let parsed = parse_hotfix(text)?;
        if parsed.target != expected {
            return Err(format!(
                "hotfix target is {}/{}, expected {}/{}",
                parsed.target.architecture.as_str(),
                parsed.target.binary_family.as_str(),
                expected.architecture.as_str(),
                expected.binary_family.as_str()
            ));
        }
        validate_hotfix_entries(&parsed.overrides, expected)?;
        Ok(Self {
            overrides: parsed.overrides,
            target: Some(expected),
            hotfix_revision: Some(parsed.revision),
        })
    }

    pub fn hotfix_revision(&self) -> Option<u64> {
        self.hotfix_revision
    }

    /// Look up a pattern by function name. Runtime override wins over embedded.
    pub fn get(&self, name: &str) -> Option<PatternLookup<'_>> {
        if let Some(rt) = self.overrides.get(name) {
            let selected = select_runtime_variants(rt, self.target);
            return Some(PatternLookup {
                variants: selected
                    .into_iter()
                    .map(PatternVariantLookup::Runtime)
                    .collect(),
            });
        }
        let candidates = EMBEDDED_PATTERNS
            .iter()
            .filter(|p| p.name == name)
            .collect::<Vec<_>>();
        let variants = select_embedded_variants(&candidates, self.target)
            .into_iter()
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

    pub fn override_names_for_module(&self, module: &str) -> Vec<&str> {
        let mut names = self
            .overrides
            .iter()
            .filter_map(|(name, entries)| {
                entries
                    .first()
                    .is_some_and(|entry| entry.module == module)
                    .then_some(name.as_str())
            })
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    pub fn override_modules(&self) -> Vec<&str> {
        let mut modules = self
            .overrides
            .values()
            .filter_map(|entries| entries.first().map(|entry| entry.module.as_str()))
            .collect::<Vec<_>>();
        modules.sort_unstable();
        modules.dedup();
        modules
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

struct ParsedHotfix {
    target: PatternTarget,
    revision: u64,
    overrides: HashMap<String, Vec<RuntimePatternEntry>>,
}

fn parse_hotfix(text: &str) -> Result<ParsedHotfix, String> {
    let mut format = None;
    let mut revision = None;
    let mut architecture = None;
    let mut binary_family = None;
    let mut metadata_seen = false;
    let mut in_metadata = false;
    let mut patterns_started = false;
    let mut patterns = String::new();

    for (line_index, original_line) in text.lines().enumerate() {
        let line_no = line_index + 1;
        let line = strip_inline_comment(original_line).trim();
        if line.starts_with('[') {
            if line == "[hotfix]" {
                if metadata_seen || patterns_started {
                    return Err(format!(
                        "line {line_no}: hotfix metadata must be the first and only metadata section"
                    ));
                }
                metadata_seen = true;
                in_metadata = true;
                continue;
            }
            if !metadata_seen {
                return Err(format!("line {line_no}: missing hotfix metadata"));
            }
            in_metadata = false;
            patterns_started = true;
        }

        if in_metadata {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("line {line_no}: expected hotfix key/value"))?;
            let key = key.trim();
            let value = value.trim();
            match key {
                "format" => {
                    let parsed = value
                        .parse::<u32>()
                        .map_err(|_| format!("line {line_no}: format must be an integer"))?;
                    if format.replace(parsed).is_some() {
                        return Err(format!("line {line_no}: duplicate format"));
                    }
                }
                "revision" => {
                    let parsed = value
                        .parse::<u64>()
                        .map_err(|_| format!("line {line_no}: revision must be an integer"))?;
                    if parsed == 0 {
                        return Err(format!("line {line_no}: revision must be non-zero"));
                    }
                    if revision.replace(parsed).is_some() {
                        return Err(format!("line {line_no}: duplicate revision"));
                    }
                }
                "architecture" => {
                    let value = parse_quoted_string(value, line_no, key)?;
                    let parsed = PatternArchitecture::parse(&value)?;
                    if architecture.replace(parsed).is_some() {
                        return Err(format!("line {line_no}: duplicate architecture"));
                    }
                }
                "binary_family" => {
                    let value = parse_quoted_string(value, line_no, key)?;
                    let parsed = SteamBinaryFamily::parse(&value)?;
                    if binary_family.replace(parsed).is_some() {
                        return Err(format!("line {line_no}: duplicate binary_family"));
                    }
                }
                _ => return Err(format!("line {line_no}: unknown hotfix key {key:?}")),
            }
            continue;
        }

        patterns.push_str(original_line);
        patterns.push('\n');
    }

    if !metadata_seen {
        return Err("missing [hotfix] metadata".to_owned());
    }
    let format = format.ok_or_else(|| "missing hotfix format".to_owned())?;
    if format != HOTFIX_FORMAT {
        return Err(format!("unsupported hotfix format {format}"));
    }
    let revision = revision.ok_or_else(|| "missing hotfix revision".to_owned())?;
    let target = PatternTarget {
        architecture: architecture.ok_or_else(|| "missing hotfix architecture".to_owned())?,
        binary_family: binary_family.ok_or_else(|| "missing hotfix binary_family".to_owned())?,
    };
    Ok(ParsedHotfix {
        target,
        revision,
        overrides: parse_toml_overrides(&patterns)?,
    })
}

fn validate_hotfix_entries(
    overrides: &HashMap<String, Vec<RuntimePatternEntry>>,
    target: PatternTarget,
) -> Result<(), String> {
    if overrides.is_empty() {
        return Err("hotfix contains no pattern entries".to_owned());
    }
    let mut selected_variants = 0usize;
    for (name, entries) in overrides {
        let Some(first) = entries.first() else {
            return Err(format!("hotfix pattern {name:?} has no variants"));
        };
        let variant_count = entries.iter().filter(|entry| entry.steamrt_variant).count();
        if variant_count > MAX_HOTFIX_VARIANTS_PER_PATTERN {
            return Err(format!(
                "hotfix pattern {name:?} exceeds {MAX_HOTFIX_VARIANTS_PER_PATTERN} variants"
            ));
        }
        selected_variants = selected_variants.saturating_add(
            if target.binary_family == SteamBinaryFamily::SteamRt && variant_count != 0 {
                variant_count
            } else {
                1
            },
        );
        if selected_variants > MAX_HOTFIX_SELECTED_VARIANTS {
            return Err(format!(
                "hotfix exceeds {MAX_HOTFIX_SELECTED_VARIANTS} selected variants"
            ));
        }
        EMBEDDED_PATTERNS
            .iter()
            .find(|entry| entry.name == name && entry.module == first.module)
            .ok_or_else(|| {
                format!(
                    "hotfix pattern {name:?} is not registered for module {:?}",
                    first.module
                )
            })?;
        if target.binary_family == SteamBinaryFamily::Ordinary {
            if entries.iter().any(|entry| entry.steamrt_variant) {
                return Err(format!(
                    "ordinary hotfix pattern {name:?} must use one wildcarded primary entry"
                ));
            }
            let pattern = Pattern::parse(&first.pattern)
                .map_err(|error| format!("invalid pattern for {name:?}: {error}"))?;
            if !pattern.tokens().contains(&PatternToken::Wildcard) {
                return Err(format!(
                    "ordinary hotfix pattern {name:?} must contain a wildcard"
                ));
            }
        }
        for entry in entries {
            if entry.module != first.module {
                return Err(format!(
                    "hotfix pattern {name:?} spans more than one module"
                ));
            }
            let pattern = Pattern::parse(&entry.pattern)
                .map_err(|error| format!("invalid pattern for {name:?}: {error}"))?;
            if pattern.tokens().len() > MAX_HOTFIX_PATTERN_TOKENS {
                return Err(format!(
                    "hotfix pattern {name:?} exceeds {MAX_HOTFIX_PATTERN_TOKENS} tokens"
                ));
            }
            if let Some(callee) = entry.callee_pattern.as_deref() {
                let callee = Pattern::parse(callee)
                    .map_err(|error| format!("invalid callee pattern for {name:?}: {error}"))?;
                if callee.tokens().len() > MAX_HOTFIX_PATTERN_TOKENS {
                    return Err(format!(
                        "hotfix callee pattern {name:?} exceeds {MAX_HOTFIX_PATTERN_TOKENS} tokens"
                    ));
                }
            }
            if entry
                .prologue
                .as_ref()
                .is_some_and(|bytes| bytes.len() > MAX_HOTFIX_PROLOGUE_BYTES)
            {
                return Err(format!(
                    "hotfix prologue {name:?} exceeds {MAX_HOTFIX_PROLOGUE_BYTES} bytes"
                ));
            }
            if entry.follow == FollowMode::Upward && entry.prologue.is_none() {
                return Err(format!(
                    "hotfix pattern {name:?} uses upward follow without a prologue"
                ));
            }
        }
    }
    Ok(())
}

fn select_runtime_variants(
    entries: &[RuntimePatternEntry],
    target: Option<PatternTarget>,
) -> Vec<&RuntimePatternEntry> {
    select_variants(entries, target, |entry| entry.steamrt_variant)
}

fn select_embedded_variants<'a>(
    entries: &[&'a PatternDef],
    target: Option<PatternTarget>,
) -> Vec<&'a PatternDef> {
    select_variants(entries, target, |entry| entry.steamrt_variant)
        .into_iter()
        .copied()
        .collect()
}

fn select_variants<T>(
    entries: &[T],
    target: Option<PatternTarget>,
    is_steamrt: impl Fn(&T) -> bool,
) -> Vec<&T> {
    let Some(target) = target else {
        return entries.iter().collect();
    };
    if target.binary_family == SteamBinaryFamily::SteamRt && entries.iter().any(&is_steamrt) {
        entries.iter().filter(|entry| is_steamrt(entry)).collect()
    } else {
        entries.iter().filter(|entry| !is_steamrt(entry)).collect()
    }
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
            pic_entry: pic_entry.unwrap_or_else(|| inherited.is_some_and(|entry| entry.pic_entry)),
            steamrt_variant: is_variant,
            module: module.clone(),
        };
        if !is_variant
            && defaults
                .insert((module, name.clone()), entry.clone())
                .is_some()
        {
            return Err(format!(
                "line {start_line}: duplicate primary pattern section for {name:?}"
            ));
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
                current_pic_entry,
            )?;
            current_follow = None;
            current_prologue = None;
            current_callee_pattern = None;
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
    fn feature_patterns_exist_in_both_architectures() {
        const REQUIRED: [&str; 5] = [
            "CHTTPRequestJob::Start",
            "CConfigStore::WriteVdfFile",
            "CUser::SpawnProcess",
            "CUser::BuildSpawnEnvBlock",
            "SetEnvString",
        ];
        for (architecture, source) in [
            ("x86", include_str!("../../../res/patterns.toml")),
            ("x86_64", include_str!("../../../res/patterns.x86_64.toml")),
        ] {
            let entries = parse_toml_patterns(source).unwrap();
            for name in REQUIRED {
                entries
                    .iter()
                    .find(|(entry_name, entry)| entry_name == name && !entry.steamrt_variant)
                    .unwrap_or_else(|| panic!("{architecture} has no primary pattern for {name}"));
            }
        }
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
            "IClientUser::RequiresLegacyCDKey",
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
        let reg = PatternRegistry {
            overrides,
            target: None,
            hotfix_revision: None,
        };
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
"#;
        let overrides = parse_toml_overrides(toml).unwrap();
        let entry = &overrides.get("CUser::CheckAppOwnership").unwrap()[0];
        assert_eq!(entry.pattern, "AA BB CC");
    }

    #[test]
    fn runtime_override_allows_variants() {
        let toml = r#"
[steamclient."CUser::CheckAppOwnership"]
follow = "relative"
pattern = "E8 ? ? ? ?"

[[steamclient."CUser::CheckAppOwnership".variants]]
pattern = "E9 ? ? ? ?"
"#;
        let overrides = parse_toml_overrides(toml).unwrap();
        let entries = overrides.get("CUser::CheckAppOwnership").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].pattern, "E9 ? ? ? ?");
        assert_eq!(entries[1].follow, FollowMode::Relative);
    }

    #[test]
    fn hotfix_requires_an_exact_target() {
        let text = r#"
[hotfix]
format = 1
revision = 1
architecture = "x86_64"
binary_family = "ordinary"

[steamclient."CUser::CheckAppOwnership"]
follow = "none"
pattern = "AA ? CC"
"#;
        let expected = PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::Ordinary,
        };
        let registry = PatternRegistry::from_hotfix_text(text, expected).unwrap();
        assert_eq!(registry.hotfix_revision(), Some(1));
        assert_eq!(
            registry.override_names_for_module("steamclient").as_slice(),
            ["CUser::CheckAppOwnership"]
        );

        let wrong_family = PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::SteamRt,
        };
        assert!(PatternRegistry::from_hotfix_text(text, wrong_family).is_err());

        let wrong_architecture = PatternTarget {
            architecture: PatternArchitecture::X86,
            binary_family: SteamBinaryFamily::Ordinary,
        };
        assert!(PatternRegistry::from_hotfix_text(text, wrong_architecture).is_err());
    }

    #[test]
    fn hotfix_requires_a_nonzero_revision() {
        let target = PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::Ordinary,
        };
        for (revision, expected) in [
            ("", "missing hotfix revision"),
            ("revision = 0", "revision must be non-zero"),
            ("revision = invalid", "revision must be an integer"),
        ] {
            let text = format!(
                r#"
[hotfix]
format = 1
{revision}
architecture = "x86_64"
binary_family = "ordinary"

[steamclient."CUser::CheckAppOwnership"]
pattern = "AA ? CC"
"#
            );

            let error = PatternRegistry::from_hotfix_text(&text, target)
                .err()
                .unwrap();
            assert!(error.contains(expected), "unexpected error: {error}");
        }
    }

    #[test]
    fn hotfix_rejects_duplicate_revision() {
        let text = r#"
[hotfix]
format = 1
revision = 1
revision = 2
architecture = "x86_64"
binary_family = "ordinary"

[steamclient."CUser::CheckAppOwnership"]
pattern = "AA ? CC"
"#;
        let target = PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::Ordinary,
        };

        let error = PatternRegistry::from_hotfix_text(text, target)
            .err()
            .unwrap();

        assert!(error.contains("duplicate revision"));
    }

    #[test]
    fn hotfix_rejects_unregistered_patterns() {
        let text = r#"
[hotfix]
format = 1
revision = 1
architecture = "x86"
binary_family = "steamrt"

[steamclient."Unknown::Function"]
pattern = "AA BB CC"
"#;
        let expected = PatternTarget {
            architecture: PatternArchitecture::X86,
            binary_family: SteamBinaryFamily::SteamRt,
        };
        let error = PatternRegistry::from_hotfix_text(text, expected)
            .err()
            .unwrap();
        assert!(error.contains("is not registered"));
    }

    #[test]
    fn hotfix_rejects_duplicate_primary_sections() {
        let text = r#"
[hotfix]
format = 1
revision = 1
architecture = "x86"
binary_family = "ordinary"

[steamclient."CUser::CheckAppOwnership"]
pattern = "AA BB CC"

[steamclient."CUser::CheckAppOwnership"]
pattern = "DD EE FF"
"#;
        let expected = PatternTarget {
            architecture: PatternArchitecture::X86,
            binary_family: SteamBinaryFamily::Ordinary,
        };
        let error = PatternRegistry::from_hotfix_text(text, expected)
            .err()
            .unwrap();
        assert!(error.contains("duplicate primary"));
    }

    #[test]
    fn runtime_target_separates_ordinary_and_steamrt_variants() {
        let ordinary = PatternRegistry::embedded_for_target(PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::Ordinary,
        });
        let steamrt = PatternRegistry::embedded_for_target(PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::SteamRt,
        });
        let ordinary_entry = ordinary
            .get("CSteamEngine::RegisterInternalCallback")
            .unwrap();
        let steamrt_entry = steamrt
            .get("CSteamEngine::RegisterInternalCallback")
            .unwrap();

        assert_eq!(ordinary_entry.variants().count(), 1);
        assert_eq!(steamrt_entry.variants().count(), 1);
        assert_ne!(ordinary_entry.pattern(), steamrt_entry.pattern());
    }

    #[test]
    fn ordinary_hotfix_rejects_variants() {
        let text = r#"
[hotfix]
format = 1
revision = 1
architecture = "x86_64"
binary_family = "ordinary"

[steamclient."CUser::CheckAppOwnership"]
pattern = "AA BB CC"

[[steamclient."CUser::CheckAppOwnership".variants]]
pattern = "DD EE FF"
"#;
        let expected = PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::Ordinary,
        };
        let error = PatternRegistry::from_hotfix_text(text, expected)
            .err()
            .unwrap();
        assert!(error.contains("must use one wildcarded primary"));
    }

    #[test]
    fn ordinary_hotfix_rejects_a_fully_literal_primary() {
        let text = r#"
[hotfix]
format = 1
revision = 1
architecture = "x86_64"
binary_family = "ordinary"

[steamclient."CUser::CheckAppOwnership"]
pattern = "AA BB CC"
"#;
        let expected = PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::Ordinary,
        };
        let error = PatternRegistry::from_hotfix_text(text, expected)
            .err()
            .unwrap();
        assert!(error.contains("must contain a wildcard"));
    }

    #[test]
    fn steamrt_hotfix_rejects_excessive_variants() {
        let mut text = String::from(
            r#"
[hotfix]
format = 1
revision = 1
architecture = "x86_64"
binary_family = "steamrt"

[steamclient."CUser::CheckAppOwnership"]
pattern = "AA BB CC"
"#,
        );
        for _ in 0..=MAX_HOTFIX_VARIANTS_PER_PATTERN {
            text.push_str(
                r#"
[[steamclient."CUser::CheckAppOwnership".variants]]
pattern = "AA BB CC"
"#,
            );
        }
        let target = PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::SteamRt,
        };

        let error = PatternRegistry::from_hotfix_text(&text, target)
            .err()
            .unwrap();

        assert!(error.contains("exceeds 8 variants"));
    }

    #[test]
    fn hotfix_rejects_oversized_scan_patterns() {
        let pattern = std::iter::once("AA")
            .chain(std::iter::repeat_n("?", MAX_HOTFIX_PATTERN_TOKENS))
            .collect::<Vec<_>>()
            .join(" ");
        let text = format!(
            r#"
[hotfix]
format = 1
revision = 1
architecture = "x86_64"
binary_family = "steamrt"

[steamclient."CUser::CheckAppOwnership"]
pattern = "{pattern}"
"#
        );
        let target = PatternTarget {
            architecture: PatternArchitecture::X86_64,
            binary_family: SteamBinaryFamily::SteamRt,
        };

        let error = PatternRegistry::from_hotfix_text(&text, target)
            .err()
            .unwrap();

        assert!(error.contains("exceeds 256 tokens"));
    }

    #[test]
    fn runtime_override_rejects_optional() {
        for toml in [
            r#"
[steamclient."CUser::CheckAppOwnership"]
pattern = "E8 ? ? ? ?"
optional = true
"#,
            r#"
[steamclient."CUser::CheckAppOwnership"]
pattern = "E8 ? ? ? ?"

[[steamclient."CUser::CheckAppOwnership".variants]]
pattern = "E9 ? ? ? ?"
optional = true
"#,
        ] {
            let err = parse_toml_overrides(toml).unwrap_err();
            assert!(err.contains("unknown key \"optional\""));
        }
    }
}
