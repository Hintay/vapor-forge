use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let res_dir = Path::new(&manifest_dir).join("../../res");
    let default_toml_path = res_dir.join("patterns/x86.toml");
    let x86_64_toml_path = res_dir.join("patterns/x86_64.toml");
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
        res_dir.join("patterns/x86_64.toml").display()
    );

    let toml_str = fs::read_to_string(&toml_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", toml_path.display(), e));

    let root: TomlRoot = toml::from_str(&toml_str)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", toml_path.display(), e));

    // The file is also served as the online hotfix, so it must carry the
    // `[hotfix]` block and name the architecture it is compiled for.
    let hotfix = root
        .hotfix
        .as_ref()
        .unwrap_or_else(|| panic!("{} has no [hotfix] block", toml_path.display()));
    let expected_architecture = if toml_path.ends_with("x86_64.toml") {
        "x86_64"
    } else {
        "x86"
    };
    assert_eq!(
        hotfix.architecture,
        expected_architecture,
        "{} declares the wrong architecture",
        toml_path.display()
    );

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
    code.push_str("// Auto-generated from res/patterns/x86.toml. Do not edit.\n\n");
    code.push_str("/// The pattern file compiled into this build, byte for byte.\n");
    code.push_str(&format!(
        "pub const EMBEDDED_SOURCE: &str = include_str!({:?});\n\n",
        toml_path.canonicalize().unwrap().display().to_string()
    ));
    code.push_str(
        "/// The commit this build was made from, when it is known. A published hotfix\n\
         /// from the official repository is taken only if it is newer than this.\n",
    );
    code.push_str(&format!(
        "pub const EMBEDDED_COMMIT: Option<&str> = {:?};\n\n",
        build_commit(&res_dir.join(".."))
    ));
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
            "entry" => "Entry",
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
            "    crate::registry::PatternDef {{ name: {:?}, pattern: {:?}, follow: crate::registry::FollowMode::{}, prologue: {}, callee_pattern: {}, pic_entry: {}, steamrt_variant: {}, module: {:?} }},\n",
            entry.name, entry.pattern, follow, prologue, callee_pattern, entry.pic_entry, entry.steamrt, entry.module
        ));
    }

    code.push_str("];\n");

    fs::write(&out_path, code)
        .unwrap_or_else(|e| panic!("failed to write {}: {}", out_path.display(), e));
}

/// The commit this build is made from, if it can be told.
///
/// A `git archive` export carries it in `res/build-commit` through the
/// `export-subst` attribute, and a checkout asks git. A copy of the working tree
/// without `.git` has none.
fn build_commit(repo_root: &Path) -> Option<String> {
    let stamped = repo_root.join("res/build-commit");
    println!("cargo:rerun-if-changed={}", stamped.display());
    if let Ok(text) = fs::read_to_string(&stamped) {
        let text = text.trim();
        if is_commit(text) {
            return Some(text.to_owned());
        }
    }

    let git_dir = repo_root.join(".git");
    if !git_dir.exists() {
        return None;
    }
    // Rebuild when HEAD moves: the file itself on a detached HEAD, the branch
    // ref otherwise, which may live loose or in packed-refs.
    let head = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head.display());
    if let Some(branch) = fs::read_to_string(&head)
        .ok()
        .and_then(|head| head.trim().strip_prefix("ref: ").map(str::to_owned))
    {
        println!("cargo:rerun-if-changed={}", git_dir.join(branch).display());
        println!(
            "cargo:rerun-if-changed={}",
            git_dir.join("packed-refs").display()
        );
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    (output.status.success() && is_commit(commit)).then(|| commit.to_owned())
}

fn is_commit(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
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
    hotfix: Option<TomlHotfix>,
    steamclient: Option<HashMap<String, TomlEntry>>,
    steamui: Option<HashMap<String, TomlEntry>>,
}

/// The parts of the `[hotfix]` block the build needs; the registry's own parser
/// validates the whole block when the file is loaded as a hotfix.
#[derive(serde::Deserialize)]
struct TomlHotfix {
    architecture: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlEntry {
    pattern: String,
    follow: Option<String>,
    prologue: Option<String>,
    callee_pattern: Option<String>,
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
    /// A variant is a steamrt shape unless it says otherwise. `false` makes it
    /// an additional ordinary shape, which is only for a genuine ABI change:
    /// two shapes of one function that the ordinary family must choose between.
    steamrt: Option<bool>,
}

struct GeneratedEntry {
    name: String,
    module: String,
    ordinal: usize,
    pattern: String,
    follow: Option<String>,
    prologue: Option<String>,
    callee_pattern: Option<String>,
    pic_entry: bool,
    steamrt: bool,
}

fn push_generated_entries(
    out: &mut Vec<GeneratedEntry>,
    name: &str,
    module: &str,
    entry: &TomlEntry,
) {
    out.push(GeneratedEntry {
        name: name.to_owned(),
        module: module.to_owned(),
        ordinal: 0,
        pattern: entry.pattern.clone(),
        follow: entry.follow.clone(),
        prologue: entry.prologue.clone(),
        callee_pattern: entry.callee_pattern.clone(),
        pic_entry: entry.pic_entry.unwrap_or(false),
        steamrt: false,
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
            pic_entry: variant
                .pic_entry
                .unwrap_or_else(|| entry.pic_entry.unwrap_or(false)),
            steamrt: variant.steamrt.unwrap_or(true),
        });
    }
}
