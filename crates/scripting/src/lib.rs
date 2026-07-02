#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;

use mlua::prelude::*;
use thiserror::Error;
use tracing::{debug, info, warn};
pub use vapor_forge_core::{ManifestOverride, ScriptState};
use vapor_forge_core::{AppId, DepotId, ManifestId};

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn execute_scripts(dirs: &[String]) -> ScriptState {
    let mut state = ScriptState::default();

    for dir in dirs {
        let path = Path::new(dir);
        let expanded = if dir.starts_with('~') {
            if let Some(home) = std::env::var_os("HOME") {
                Path::new(&home).join(dir.trim_start_matches("~/"))
            } else {
                path.to_path_buf()
            }
        } else {
            path.to_path_buf()
        };

        if !expanded.is_dir() {
            debug!(dir = %expanded.display(), "scripting: directory not found, skipping");
            continue;
        }

        let mut entries: Vec<_> = match std::fs::read_dir(&expanded) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "lua"))
                .collect(),
            Err(e) => {
                warn!(error = %e, dir = %expanded.display(), "scripting: read_dir failed");
                continue;
            }
        };
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            if let Err(e) = execute_file(&entry.path(), &mut state) {
                warn!(
                    error = %e,
                    file = %entry.path().display(),
                    "scripting: script execution failed"
                );
            }
        }
    }

    if !state.apps.is_empty() {
        info!(
            apps = state.apps.len(),
            depot_keys = state.depot_keys.len(),
            manifests = state.manifests.len(),
            tickets = state.app_tickets.len(),
            "scripting: scripts loaded"
        );
    }

    state
}

fn execute_file(path: &Path, state: &mut ScriptState) -> Result<(), ScriptError> {
    let source = std::fs::read_to_string(path)?;
    let lua = Lua::new();

    let apps = std::sync::Arc::new(std::sync::Mutex::new(Vec::<AppId>::new()));
    let depot_keys = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<DepotId, Vec<u8>>::new()));
    let manifests = std::sync::Arc::new(std::sync::Mutex::new(
        HashMap::<DepotId, ManifestOverride>::new(),
    ));
    let tickets = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<AppId, Vec<u8>>::new()));
    let enc_tickets = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<AppId, Vec<u8>>::new()));
    let stat_ids = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<AppId, u64>::new()));
    let avatars = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<AppId, AppId>::new()));
    let access_tokens = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<AppId, u64>::new()));

    {
        let globals = lua.globals();

        let apps_clone = apps.clone();
        let depot_keys_clone = depot_keys.clone();
        globals.set(
            "addappid",
            lua.create_function(move |_, args: LuaMultiValue| {
                let id_raw = args
                    .front()
                    .and_then(|v| match v {
                        LuaValue::Integer(n) => Some(*n as u32),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        mlua::Error::RuntimeError("addappid: arg1 must be integer".into())
                    })?;
                let id = AppId(id_raw);

                let key_hex = args.get(2).and_then(|v| match v {
                    LuaValue::String(s) => Some(s.to_str().ok()?.to_owned()),
                    _ => None,
                });

                apps_clone.lock().unwrap().push(id);

                if let Some(hex) = key_hex {
                    if let Some(key) = parse_hex_key(&hex) {
                        // addappid's third arg is a depot key; depot_id == app_id in this context
                        depot_keys_clone
                            .lock()
                            .unwrap()
                            .insert(DepotId(id_raw), key);
                    }
                }

                debug!(id = id_raw, "lua: addappid");
                Ok(())
            })?,
        )?;

        let manifests_clone = manifests.clone();
        globals.set(
            "setmanifestid",
            lua.create_function(
                move |_, (depot_id_raw, gid_str, size): (u32, String, Option<u64>)| {
                    let gid_raw: u64 = gid_str.parse().map_err(|_| {
                        mlua::Error::RuntimeError("setmanifestid: gid must be decimal".into())
                    })?;
                    let depot_id = DepotId(depot_id_raw);
                    manifests_clone.lock().unwrap().insert(
                        depot_id,
                        ManifestOverride {
                            depot_id,
                            gid: ManifestId(gid_raw),
                            size,
                        },
                    );
                    debug!(depot_id = depot_id_raw, gid = gid_raw, "lua: setmanifestid");
                    Ok(())
                },
            )?,
        )?;

        let tickets_clone = tickets.clone();
        globals.set(
            "setappticket",
            lua.create_function(move |_, (app_id_raw, hex): (u32, String)| {
                let bytes = parse_hex_key(&hex).ok_or_else(|| {
                    mlua::Error::RuntimeError("setappticket: invalid hex string".into())
                })?;
                tickets_clone
                    .lock()
                    .unwrap()
                    .insert(AppId(app_id_raw), bytes);
                debug!(app_id = app_id_raw, "lua: setappticket");
                Ok(())
            })?,
        )?;

        let stat_ids = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<AppId, u64>::new()));
        let enc_tickets_clone = enc_tickets.clone();
        globals.set(
            "seteticket",
            lua.create_function(move |_, (app_id_raw, hex): (u32, String)| {
                let bytes = parse_hex_key(&hex).ok_or_else(|| {
                    mlua::Error::RuntimeError("seteticket: invalid hex string".into())
                })?;
                enc_tickets_clone
                    .lock()
                    .unwrap()
                    .insert(AppId(app_id_raw), bytes);
                debug!(app_id = app_id_raw, "lua: seteticket");
                Ok(())
            })?,
        )?;

        let stat_ids_clone = stat_ids.clone();
        globals.set(
            "setstat",
            lua.create_function(move |_, (app_id_raw, steamid_str): (u32, String)| {
                let steamid: u64 = steamid_str.parse().map_err(|_| {
                    mlua::Error::RuntimeError("setstat: steamid must be decimal string".into())
                })?;
                stat_ids_clone
                    .lock()
                    .unwrap()
                    .insert(AppId(app_id_raw), steamid);
                debug!(app_id = app_id_raw, steamid, "lua: setstat");
                Ok(())
            })?,
        )?;

        let avatars_clone = avatars.clone();
        globals.set(
            "setavatar",
            lua.create_function(move |_, (app_id_raw, avatar_raw): (u32, u32)| {
                avatars_clone
                    .lock()
                    .unwrap()
                    .insert(AppId(app_id_raw), AppId(avatar_raw));
                debug!(app_id = app_id_raw, avatar = avatar_raw, "lua: setavatar");
                Ok(())
            })?,
        )?;

        let access_tokens_clone = access_tokens.clone();
        globals.set(
            "setaccesstoken",
            lua.create_function(move |_, (app_id_raw, token): (u32, u64)| {
                access_tokens_clone
                    .lock()
                    .unwrap()
                    .insert(AppId(app_id_raw), token);
                debug!(app_id = app_id_raw, token, "lua: setaccesstoken");
                Ok(())
            })?,
        )?;

        globals.set(
            "http_get",
            lua.create_function(|_, url: String| {
                let body = ureq::Agent::new_with_defaults()
                    .get(&url)
                    .call()
                    .map_err(|e| mlua::Error::RuntimeError(format!("http_get failed: {e}")))?
                    .body_mut()
                    .read_to_string()
                    .map_err(|e| mlua::Error::RuntimeError(format!("http_get read failed: {e}")))?;
                Ok(body)
            })?,
        )?;

        globals.set(
            "http_post",
            lua.create_function(|_, (url, body): (String, String)| {
                let resp = ureq::Agent::new_with_defaults()
                    .post(&url)
                    .content_type("application/x-www-form-urlencoded")
                    .send(body.as_bytes())
                    .map_err(|e| mlua::Error::RuntimeError(format!("http_post failed: {e}")))?
                    .body_mut()
                    .read_to_string()
                    .map_err(|e| {
                        mlua::Error::RuntimeError(format!("http_post read failed: {e}"))
                    })?;
                Ok(resp)
            })?,
        )?;
    }

    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    lua.load(&source).set_name(filename.into_owned()).exec()?;

    debug!(file = %path.display(), "lua: script executed");

    state.apps.extend(apps.lock().unwrap().iter());
    state
        .depot_keys
        .extend(depot_keys.lock().unwrap().drain().collect::<Vec<_>>());
    state
        .manifests
        .extend(manifests.lock().unwrap().drain().collect::<Vec<_>>());
    state
        .app_tickets
        .extend(tickets.lock().unwrap().drain().collect::<Vec<_>>());
    state
        .stat_steam_ids
        .extend(stat_ids.lock().unwrap().drain().collect::<Vec<_>>());
    state
        .avatars
        .extend(avatars.lock().unwrap().drain().collect::<Vec<_>>());
    state
        .access_tokens
        .extend(access_tokens.lock().unwrap().drain().collect::<Vec<_>>());
    state
        .enc_tickets
        .extend(enc_tickets.lock().unwrap().drain().collect::<Vec<_>>());

    Ok(())
}

fn parse_hex_key(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_key() {
        assert_eq!(
            parse_hex_key("deadbeef"),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(parse_hex_key("zz"), None);
        assert_eq!(parse_hex_key("abc"), None);
    }

    #[test]
    fn executes_addappid_script() {
        let dir = std::env::temp_dir().join(format!("lua-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("test.lua"), "addappid(480)\naddappid(730)\n").unwrap();

        let state = execute_scripts(&[dir.to_string_lossy().into_owned()]);
        assert_eq!(state.apps, vec![AppId(480), AppId(730)]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn executes_setmanifestid_script() {
        let dir = std::env::temp_dir().join(format!("lua-manifest-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("test.lua"),
            "setmanifestid(12345, \"9876543210\", 1024)\n",
        )
        .unwrap();

        let state = execute_scripts(&[dir.to_string_lossy().into_owned()]);
        assert_eq!(state.manifests.len(), 1);
        let m = &state.manifests[&DepotId(12345)];
        assert_eq!(m.gid, ManifestId(9876543210));
        assert_eq!(m.size, Some(1024));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
