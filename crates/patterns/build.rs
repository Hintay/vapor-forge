use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let toml_path = Path::new(&manifest_dir).join("../../res/patterns.toml");

    println!("cargo:rerun-if-changed={}", toml_path.display());

    let toml_str = fs::read_to_string(&toml_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", toml_path.display(), e));

    let root: TomlRoot = toml::from_str(&toml_str)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", toml_path.display(), e));

    let mut all_entries: Vec<(String, &str, &TomlEntry)> = Vec::new();
    for (name, entry) in root.steamclient.as_ref().into_iter().flatten() {
        all_entries.push((name.clone(), "steamclient", entry));
    }
    for (name, entry) in root.steamui.as_ref().into_iter().flatten() {
        all_entries.push((name.clone(), "steamui", entry));
    }
    all_entries.sort_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(&b.0)));

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("patterns_generated.rs");

    let mut code = String::new();
    code.push_str("// Auto-generated from res/patterns.toml. Do not edit.\n\n");
    code.push_str(&format!(
        "pub const EMBEDDED_PATTERNS: &[crate::registry::PatternDef; {}] = &[\n",
        all_entries.len()
    ));

    for (name, module, entry) in &all_entries {
        let follow = match entry.follow.as_deref().unwrap_or("none") {
            "none" => "None",
            "relative" => "Relative",
            "upward" => "Upward",
            "call" => "Call",
            other => panic!("unknown follow mode {:?} for pattern {:?}", other, name),
        };
        let prologue = match &entry.prologue {
            Some(p) => format!("Some(&{:?})", parse_hex_bytes(p)),
            None => "None".to_owned(),
        };
        let callee_pattern = match &entry.callee_pattern {
            Some(p) => format!("Some({:?})", p),
            None => "None".to_owned(),
        };
        let optional = entry.optional.unwrap_or(false);
        let pic_entry = entry.pic_entry.unwrap_or(false);

        code.push_str(&format!(
            "    crate::registry::PatternDef {{ name: {:?}, pattern: {:?}, follow: crate::registry::FollowMode::{}, prologue: {}, callee_pattern: {}, optional: {}, pic_entry: {}, module: {:?} }},\n",
            name, entry.pattern, follow, prologue, callee_pattern, optional, pic_entry, module
        ));
    }

    code.push_str("];\n\n");

    // Content hash of the source TOML for online update comparison
    let hash = fnv1a_64(toml_str.as_bytes());
    code.push_str(&format!(
        "pub const EMBEDDED_PATTERNS_HASH: u64 = 0x{:016x};\n",
        hash
    ));

    fs::write(&out_path, code)
        .unwrap_or_else(|e| panic!("failed to write {}: {}", out_path.display(), e));
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn parse_hex_bytes(hex_str: &str) -> Vec<u8> {
    hex_str
        .split_whitespace()
        .map(|h| u8::from_str_radix(h, 16).unwrap_or_else(|_| panic!("invalid hex: {}", h)))
        .collect()
}

// Minimal TOML structures for build.rs (no dependency on the crate's own types)
#[derive(serde::Deserialize)]
struct TomlRoot {
    steamclient: Option<HashMap<String, TomlEntry>>,
    steamui: Option<HashMap<String, TomlEntry>>,
}

#[derive(serde::Deserialize)]
struct TomlEntry {
    pattern: String,
    follow: Option<String>,
    prologue: Option<String>,
    callee_pattern: Option<String>,
    optional: Option<bool>,
    pic_entry: Option<bool>,
}
