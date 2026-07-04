use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let res_dir = Path::new(&manifest_dir).join("../../res");
    let default_toml_path = res_dir.join("patterns.toml");
    let x86_64_toml_path = res_dir.join("patterns.x86_64.toml");
    let toml_path = if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
        && x86_64_toml_path.exists()
    {
        x86_64_toml_path
    } else {
        default_toml_path
    };

    println!("cargo:rerun-if-changed={}", toml_path.display());
    println!(
        "cargo:rerun-if-changed={}",
        res_dir.join("patterns.x86_64.toml").display()
    );

    let toml_str = fs::read_to_string(&toml_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", toml_path.display(), e));

    let root: TomlRoot = toml::from_str(&toml_str)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", toml_path.display(), e));

    let mut all_entries: Vec<GeneratedEntry> = Vec::new();
    for (name, entry) in root.steamclient.as_ref().into_iter().flatten() {
        push_generated_entries(&mut all_entries, name, "steamclient", entry);
    }
    for (name, entry) in root.steamui.as_ref().into_iter().flatten() {
        push_generated_entries(&mut all_entries, name, "steamui", entry);
    }
    all_entries.sort_by(|a, b| {
        a.module
            .cmp(&b.module)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.ordinal.cmp(&b.ordinal))
    });

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("patterns_generated.rs");

    let mut code = String::new();
    code.push_str("// Auto-generated from res/patterns.toml. Do not edit.\n\n");
    code.push_str(&format!(
        "pub const EMBEDDED_PATTERNS: &[crate::registry::PatternDef; {}] = &[\n",
        all_entries.len()
    ));

    for entry in &all_entries {
        let follow = match entry.follow.as_deref().unwrap_or("none") {
            "none" => "None",
            "relative" => "Relative",
            "upward" => "Upward",
            "call" => "Call",
            other => panic!(
                "unknown follow mode {:?} for pattern {:?}",
                other, entry.name
            ),
        };
        let prologue = match &entry.prologue {
            Some(p) => format!("Some(&{:?})", parse_hex_bytes(p)),
            None => "None".to_owned(),
        };
        let callee_pattern = match &entry.callee_pattern {
            Some(p) => format!("Some({:?})", p),
            None => "None".to_owned(),
        };

        code.push_str(&format!(
            "    crate::registry::PatternDef {{ name: {:?}, pattern: {:?}, follow: crate::registry::FollowMode::{}, prologue: {}, callee_pattern: {}, optional: {}, pic_entry: {}, module: {:?} }},\n",
            entry.name, entry.pattern, follow, prologue, callee_pattern, entry.optional, entry.pic_entry, entry.module
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
    variants: Option<Vec<TomlVariant>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlVariant {
    pattern: String,
    follow: Option<String>,
    prologue: Option<String>,
    callee_pattern: Option<String>,
    pic_entry: Option<bool>,
}

struct GeneratedEntry {
    name: String,
    module: String,
    ordinal: usize,
    pattern: String,
    follow: Option<String>,
    prologue: Option<String>,
    callee_pattern: Option<String>,
    optional: bool,
    pic_entry: bool,
}

fn push_generated_entries(
    out: &mut Vec<GeneratedEntry>,
    name: &str,
    module: &str,
    entry: &TomlEntry,
) {
    let optional = entry.optional.unwrap_or(false);
    out.push(GeneratedEntry {
        name: name.to_owned(),
        module: module.to_owned(),
        ordinal: 0,
        pattern: entry.pattern.clone(),
        follow: entry.follow.clone(),
        prologue: entry.prologue.clone(),
        callee_pattern: entry.callee_pattern.clone(),
        optional,
        pic_entry: entry.pic_entry.unwrap_or(false),
    });

    for (idx, variant) in entry.variants.as_deref().unwrap_or(&[]).iter().enumerate() {
        out.push(GeneratedEntry {
            name: name.to_owned(),
            module: module.to_owned(),
            ordinal: idx + 1,
            pattern: variant.pattern.clone(),
            follow: variant.follow.clone().or_else(|| entry.follow.clone()),
            prologue: variant.prologue.clone().or_else(|| entry.prologue.clone()),
            callee_pattern: variant
                .callee_pattern
                .clone()
                .or_else(|| entry.callee_pattern.clone()),
            optional,
            pic_entry: variant
                .pic_entry
                .unwrap_or_else(|| entry.pic_entry.unwrap_or(false)),
        });
    }
}
