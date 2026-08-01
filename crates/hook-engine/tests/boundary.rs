//! Guards the property that justifies this crate existing separately: the
//! engine must stay reusable for any target, not just Steam.
//!
//! Cargo already prevents a dependency on Steam-specific crates. Nothing,
//! however, prevents Steam knowledge being written directly into the engine —
//! that is what this test checks. It lives outside `src/` so its own needles
//! are not part of the scanned sources.

const STEAM_SPECIFIC: &[&str] = &[
    "steamclient",
    "steamui",
    "CSteamEngine",
    "IClient",
    "CUser",
    "SteamAPI",
];

const SOURCES: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../src/lib.rs")),
    ("detour.rs", include_str!("../src/detour.rs")),
    ("original.rs", include_str!("../src/original.rs")),
    ("pic_thunk.rs", include_str!("../src/pic_thunk.rs")),
    ("plan.rs", include_str!("../src/plan.rs")),
    ("vmt.rs", include_str!("../src/vmt.rs")),
];

const MANIFEST: &str = include_str!("../Cargo.toml");

/// Strip `//` comments; comments may legitimately name a target module when
/// explaining a SAFETY invariant.
fn without_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find("//") {
            Some(index) => &line[..index],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn engine_code_carries_no_steam_specifics() {
    let mut found = Vec::new();
    for (file, source) in SOURCES {
        let code = without_line_comments(source);
        for needle in STEAM_SPECIFIC {
            if code.contains(needle) {
                found.push(format!("{file}: {needle}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "Steam specifics leaked into engine: {found:?}"
    );
}

#[test]
fn engine_manifest_carries_no_workspace_dependencies() {
    let dependencies = MANIFEST
        .split_once("[dependencies]")
        .map(|(_, dependencies)| dependencies)
        .unwrap_or_default();
    assert!(
        !dependencies.contains("vapor-forge-"),
        "hook-engine acquired a target-specific workspace dependency"
    );
}
