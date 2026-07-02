pub fn is_steam_target_name(name_or_path: &str) -> bool {
    module_name_matches(name_or_path, "steamclient.so")
        || module_name_matches(name_or_path, "steamui.so")
}

fn module_name_matches(name_or_path: &str, expected: &str) -> bool {
    name_or_path == expected || name_or_path.rsplit('/').next() == Some(expected)
}

pub(crate) fn steam_target_display_name(name_or_path: &str) -> Option<&'static str> {
    if module_name_matches(name_or_path, "steamclient.so") {
        Some("steamclient.so")
    } else if module_name_matches(name_or_path, "steamui.so") {
        Some("steamui.so")
    } else {
        None
    }
}
