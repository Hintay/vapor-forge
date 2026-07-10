use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use mlua::prelude::*;
use vapor_forge_core::{AppId, DepotId, ManifestId};

use crate::report::{ScriptCallReport, ScriptExecutionOptions};
use crate::{ManifestOverride, ScriptError, ScriptState};

#[derive(Default)]
struct FileState {
    apps: Vec<AppId>,
    depot_keys: HashMap<DepotId, Vec<u8>>,
    manifests: HashMap<DepotId, ManifestOverride>,
    app_tickets: HashMap<AppId, Vec<u8>>,
    enc_tickets: HashMap<AppId, Vec<u8>>,
    stat_steam_ids: HashMap<AppId, u64>,
    avatars: HashMap<AppId, AppId>,
    access_tokens: HashMap<AppId, u64>,
}

type Shared<T> = Rc<RefCell<T>>;

#[derive(Clone)]
struct ScriptRunContext {
    path: String,
    calls: Shared<Vec<ScriptCallReport>>,
    record_calls: bool,
}

impl ScriptRunContext {
    fn new(path: String, record_calls: bool) -> Self {
        Self {
            path,
            calls: Rc::new(RefCell::new(Vec::new())),
            record_calls,
        }
    }

    fn push_call(&self, function: &'static str, detail: String) {
        if !self.record_calls {
            return;
        }
        self.calls.borrow_mut().push(ScriptCallReport {
            path: self.path.clone(),
            function,
            detail,
        });
    }

    fn drain_calls(&self) -> Vec<ScriptCallReport> {
        self.calls.borrow_mut().drain(..).collect()
    }
}

pub(crate) fn execute_file(
    path: &Path,
    state: &mut ScriptState,
    options: &ScriptExecutionOptions,
    calls: &mut Vec<ScriptCallReport>,
) -> Result<(), ScriptError> {
    let source = std::fs::read_to_string(path)?;
    let lua = Lua::new();
    let file_state = Rc::new(RefCell::new(FileState::default()));
    let ctx = ScriptRunContext::new(path.display().to_string(), options.record_calls);

    install_lua_api(&lua, &file_state, &ctx, options)?;

    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let exec_result = lua.load(&source).set_name(filename.into_owned()).exec();
    calls.extend(ctx.drain_calls());
    exec_result?;

    merge_file_state(state, file_state);
    Ok(())
}

fn install_lua_api(
    lua: &Lua,
    state: &Shared<FileState>,
    ctx: &ScriptRunContext,
    options: &ScriptExecutionOptions,
) -> Result<(), mlua::Error> {
    let globals = lua.globals();
    install_addappid(lua, &globals, state, ctx)?;
    install_setmanifestid(lua, &globals, state, ctx)?;
    install_ticket_api(lua, &globals, state, ctx)?;
    install_setstat(lua, &globals, state, ctx)?;
    install_setavatar(lua, &globals, state, ctx)?;
    install_setaccesstoken(lua, &globals, state, ctx)?;
    install_http_api(lua, &globals, options, ctx)
}

fn install_addappid(
    lua: &Lua,
    globals: &LuaTable,
    state: &Shared<FileState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    globals.set(
        "addappid",
        lua.create_function(move |_, args: LuaMultiValue| {
            let id_raw = args
                .front()
                .and_then(|value| match value {
                    LuaValue::Integer(n) => Some(*n as u32),
                    _ => None,
                })
                .ok_or_else(|| {
                    mlua::Error::RuntimeError("addappid: arg1 must be integer".into())
                })?;

            let key_hex = args.get(2).and_then(|value| match value {
                LuaValue::String(s) => Some(s.to_str().ok()?.to_owned()),
                _ => None,
            });

            let mut detail = format!("app_id={id_raw}");
            let mut state = state.borrow_mut();
            state.apps.push(AppId(id_raw));

            if let Some(hex) = key_hex {
                if let Some(key) = parse_hex_key(&hex) {
                    let key_len = key.len();
                    state.depot_keys.insert(DepotId(id_raw), key);
                    detail.push_str(&format!(" depot_key_len={key_len}"));
                }
            }

            ctx.push_call("addappid", detail);
            Ok(())
        })?,
    )
}

fn install_setmanifestid(
    lua: &Lua,
    globals: &LuaTable,
    state: &Shared<FileState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    let function = lua.create_function(
        move |_, (depot_id_raw, gid_str, size): (u32, String, Option<u64>)| {
            let gid_raw: u64 = gid_str.parse().map_err(|_| {
                mlua::Error::RuntimeError("setmanifestid: gid must be decimal".into())
            })?;
            let depot_id = DepotId(depot_id_raw);
            state.borrow_mut().manifests.insert(
                depot_id,
                ManifestOverride {
                    depot_id,
                    gid: ManifestId(gid_raw),
                    size,
                },
            );

            let detail = match size {
                Some(size) => format!("depot_id={depot_id_raw} gid={gid_raw} size={size}"),
                None => format!("depot_id={depot_id_raw} gid={gid_raw} size=(none)"),
            };
            ctx.push_call("setmanifestid", detail);
            Ok(())
        },
    )?;
    globals.set("setmanifestid", function.clone())?;
    globals.set("setManifestid", function)
}

fn install_ticket_api(
    lua: &Lua,
    globals: &LuaTable,
    state: &Shared<FileState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    install_hex_ticket_fn(
        lua,
        globals,
        state,
        ctx,
        "setappticket",
        |state, app_id, bytes| {
            state.app_tickets.insert(app_id, bytes);
        },
    )?;
    install_hex_ticket_fn(
        lua,
        globals,
        state,
        ctx,
        "seteticket",
        |state, app_id, bytes| {
            state.enc_tickets.insert(app_id, bytes);
        },
    )
}

fn install_hex_ticket_fn(
    lua: &Lua,
    globals: &LuaTable,
    state: &Shared<FileState>,
    ctx: &ScriptRunContext,
    name: &'static str,
    store: fn(&mut FileState, AppId, Vec<u8>),
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    globals.set(
        name,
        lua.create_function(move |_, (app_id_raw, hex): (u32, String)| {
            let bytes = parse_hex_key(&hex)
                .ok_or_else(|| mlua::Error::RuntimeError(format!("{name}: invalid hex string")))?;
            store(&mut state.borrow_mut(), AppId(app_id_raw), bytes);
            ctx.push_call(name, format!("app_id={app_id_raw} bytes={}", hex.len() / 2));
            Ok(())
        })?,
    )
}

fn install_setstat(
    lua: &Lua,
    globals: &LuaTable,
    state: &Shared<FileState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    globals.set(
        "setstat",
        lua.create_function(move |_, (app_id_raw, steamid_str): (u32, String)| {
            let steamid: u64 = steamid_str.parse().map_err(|_| {
                mlua::Error::RuntimeError("setstat: steamid must be decimal string".into())
            })?;
            state
                .borrow_mut()
                .stat_steam_ids
                .insert(AppId(app_id_raw), steamid);
            ctx.push_call("setstat", format!("app_id={app_id_raw} steamid={steamid}"));
            Ok(())
        })?,
    )
}

fn install_setavatar(
    lua: &Lua,
    globals: &LuaTable,
    state: &Shared<FileState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    globals.set(
        "setavatar",
        lua.create_function(move |_, (app_id_raw, avatar_raw): (u32, u32)| {
            state
                .borrow_mut()
                .avatars
                .insert(AppId(app_id_raw), AppId(avatar_raw));
            ctx.push_call(
                "setavatar",
                format!("app_id={app_id_raw} avatar={avatar_raw}"),
            );
            Ok(())
        })?,
    )
}

fn install_setaccesstoken(
    lua: &Lua,
    globals: &LuaTable,
    state: &Shared<FileState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    globals.set(
        "setaccesstoken",
        lua.create_function(move |_, (app_id_raw, token): (u32, u64)| {
            state
                .borrow_mut()
                .access_tokens
                .insert(AppId(app_id_raw), token);
            ctx.push_call(
                "setaccesstoken",
                format!("app_id={app_id_raw} token={token}"),
            );
            Ok(())
        })?,
    )
}

fn install_http_api(
    lua: &Lua,
    globals: &LuaTable,
    options: &ScriptExecutionOptions,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let get_options = options.clone();
    let get_ctx = ctx.clone();
    globals.set(
        "http_get",
        lua.create_function(move |_, url: String| {
            get_ctx.push_call(
                "http_get",
                format!("url={}", display_url(&url, get_options.redact_network_urls)),
            );
            ensure_network_allowed(&get_options, &url, "http_get")?;
            let body = http_agent(get_options.network_timeout_ms)
                .get(&url)
                .call()
                .map_err(|error| mlua::Error::RuntimeError(format!("http_get failed: {error}")))?
                .body_mut()
                .read_to_string()
                .map_err(|error| {
                    mlua::Error::RuntimeError(format!("http_get read failed: {error}"))
                })?;
            Ok(body)
        })?,
    )?;

    let post_options = options.clone();
    let post_ctx = ctx.clone();
    globals.set(
        "http_post",
        lua.create_function(move |_, (url, body): (String, String)| {
            post_ctx.push_call(
                "http_post",
                format!(
                    "url={} body_bytes={}",
                    display_url(&url, post_options.redact_network_urls),
                    body.len()
                ),
            );
            ensure_network_allowed(&post_options, &url, "http_post")?;
            let response = http_agent(post_options.network_timeout_ms)
                .post(&url)
                .content_type("application/x-www-form-urlencoded")
                .send(body.as_bytes())
                .map_err(|error| mlua::Error::RuntimeError(format!("http_post failed: {error}")))?
                .body_mut()
                .read_to_string()
                .map_err(|error| {
                    mlua::Error::RuntimeError(format!("http_post read failed: {error}"))
                })?;
            Ok(response)
        })?,
    )
}

fn ensure_network_allowed(
    options: &ScriptExecutionOptions,
    url: &str,
    function: &str,
) -> Result<(), mlua::Error> {
    if !options.allow_network {
        return Err(mlua::Error::RuntimeError(format!(
            "{function} disabled; pass --allow-network or --allow-host to vapor-forge-script-check"
        )));
    }

    if options.allowed_hosts.is_empty() {
        return Ok(());
    }

    let Some(host) = url_host(url) else {
        return Err(mlua::Error::RuntimeError(format!(
            "{function} URL has no host: {}",
            display_url(url, true)
        )));
    };
    if options.allowed_hosts.iter().any(|allowed| allowed == host) {
        return Ok(());
    }

    Err(mlua::Error::RuntimeError(format!(
        "{function} host {host:?} not allowed"
    )))
}

fn http_agent(timeout_ms: Option<u64>) -> ureq::Agent {
    let Some(timeout_ms) = timeout_ms else {
        return ureq::Agent::new_with_defaults();
    };

    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(timeout_ms)))
        .build()
        .new_agent()
}

fn display_url(url: &str, redact: bool) -> String {
    if !redact {
        return url.to_owned();
    }

    let end = url.find(['?', '#']).unwrap_or(url.len());
    if end == url.len() {
        url.to_owned()
    } else {
        format!("{}?<redacted>", &url[..end])
    }
}

fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host_port
        .strip_prefix('[')
        .and_then(|ipv6| ipv6.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| {
            host_port
                .split_once(':')
                .map_or(host_port, |(host, _)| host)
        });

    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn merge_file_state(state: &mut ScriptState, file_state: Shared<FileState>) {
    let mut file_state = file_state.borrow_mut();
    state.apps.append(&mut file_state.apps);
    state.depot_keys.extend(file_state.depot_keys.drain());
    state.manifests.extend(file_state.manifests.drain());
    state.app_tickets.extend(file_state.app_tickets.drain());
    state.enc_tickets.extend(file_state.enc_tickets.drain());
    state
        .stat_steam_ids
        .extend(file_state.stat_steam_ids.drain());
    state.avatars.extend(file_state.avatars.drain());
    state.access_tokens.extend(file_state.access_tokens.drain());
}

pub(crate) fn parse_hex_key(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}
