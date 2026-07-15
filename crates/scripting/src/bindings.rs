use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mlua::prelude::*;
use vapor_forge_core::{AppId, DepotId, ManifestId};

use crate::report::{ScriptCallReport, ScriptExecutionOptions};
use crate::{ManifestOverride, ScriptState};

const DEFAULT_HTTP_TIMEOUT_MS: u64 = 10_000;
const MAX_HTTP_BODY_BYTES: u64 = 256 * 1024;

#[derive(Clone, Default)]
pub(crate) struct RuntimeState {
    apps: Vec<AppId>,
    depot_keys: HashMap<DepotId, Vec<u8>>,
    manifests: HashMap<DepotId, ManifestOverride>,
    app_tickets: HashMap<AppId, Vec<u8>>,
    enc_tickets: HashMap<AppId, Vec<u8>>,
    stat_steam_ids: HashMap<AppId, u64>,
    avatars: HashMap<AppId, AppId>,
    access_tokens: HashMap<AppId, u64>,
}

type Shared<T> = Arc<Mutex<T>>;

fn lock_shared<T>(shared: &Shared<T>) -> MutexGuard<'_, T> {
    shared.lock().unwrap_or_else(|error| error.into_inner())
}

#[derive(Clone)]
pub(crate) struct ScriptRunContext {
    path: Shared<String>,
    calls: Shared<Vec<ScriptCallReport>>,
    record_calls: bool,
}

impl ScriptRunContext {
    fn new(record_calls: bool) -> Self {
        Self {
            path: Arc::new(Mutex::new(String::new())),
            calls: Arc::new(Mutex::new(Vec::new())),
            record_calls,
        }
    }

    pub(crate) fn set_path(&self, path: &str) {
        path.clone_into(&mut lock_shared(&self.path));
    }

    fn push_call(&self, function: &'static str, detail: String) {
        if !self.record_calls {
            return;
        }
        lock_shared(&self.calls).push(ScriptCallReport {
            path: lock_shared(&self.path).clone(),
            function,
            detail,
        });
    }

    pub(crate) fn drain_calls(&self) -> Vec<ScriptCallReport> {
        lock_shared(&self.calls).drain(..).collect()
    }
}

pub(crate) fn create_runtime(
    options: &ScriptExecutionOptions,
) -> LuaResult<(Lua, Shared<RuntimeState>, ScriptRunContext)> {
    let lua = Lua::new();
    let state = Arc::new(Mutex::new(RuntimeState::default()));
    let ctx = ScriptRunContext::new(options.record_calls);
    install_lua_api(&lua, &state, &ctx, options)?;
    Ok((lua, state, ctx))
}

pub(crate) fn execute_source(
    lua: &Lua,
    path: &Path,
    source: &str,
    ctx: &ScriptRunContext,
) -> Vec<String> {
    ctx.set_path(&path.display().to_string());
    let mut errors = Vec::new();
    let mut chunk = String::new();
    let mut chunk_start = 1;

    for (index, line) in source.lines().enumerate() {
        let line_no = index + 1;
        if chunk.is_empty() {
            chunk_start = line_no;
        } else {
            chunk.push('\n');
        }
        chunk.push_str(line);

        match lua
            .load(&chunk)
            .set_name(path.to_string_lossy())
            .into_function()
        {
            Ok(function) => {
                if let Err(error) = function.call::<()>(()) {
                    errors.push(format!("line {chunk_start}: {error}"));
                }
                chunk.clear();
            }
            Err(LuaError::SyntaxError {
                incomplete_input: true,
                ..
            }) => {}
            Err(error) => {
                errors.push(format!("line {chunk_start}: {error}"));
                chunk.clear();
            }
        }
    }

    if !chunk.trim().is_empty() {
        errors.push(format!(
            "line {chunk_start}: incomplete statement at end of file"
        ));
    }
    errors
}

pub(crate) fn snapshot_state(state: &Shared<RuntimeState>) -> ScriptState {
    let state = lock_shared(state);
    ScriptState {
        apps: state.apps.clone(),
        depot_keys: state.depot_keys.clone(),
        manifests: state.manifests.clone(),
        app_tickets: state.app_tickets.clone(),
        enc_tickets: state.enc_tickets.clone(),
        stat_steam_ids: state.stat_steam_ids.clone(),
        avatars: state.avatars.clone(),
        access_tokens: state.access_tokens.clone(),
    }
}

fn install_lua_api(
    lua: &Lua,
    state: &Shared<RuntimeState>,
    ctx: &ScriptRunContext,
    options: &ScriptExecutionOptions,
) -> Result<(), mlua::Error> {
    let globals = lua.globals();
    let registry = install_case_insensitive_lookup(lua, &globals)?;
    install_addappid(lua, &globals, &registry, state, ctx)?;
    install_setmanifestid(lua, &globals, &registry, state, ctx)?;
    install_ticket_api(lua, &globals, &registry, state, ctx)?;
    install_setstat(lua, &globals, &registry, state, ctx)?;
    install_setavatar(lua, &globals, &registry, state, ctx)?;
    install_addtoken(lua, &globals, &registry, state, ctx)?;
    install_http_api(lua, &globals, &registry, options, ctx)
}

fn install_case_insensitive_lookup(lua: &Lua, globals: &LuaTable) -> LuaResult<LuaTable> {
    let registry = lua.create_table()?;
    let lookup = registry.clone();
    let metatable = globals.metatable().unwrap_or(lua.create_table()?);
    metatable.set(
        "__index",
        lua.create_function(move |_, (_table, key): (LuaTable, LuaValue)| {
            let LuaValue::String(name) = key else {
                return Ok(LuaValue::Nil);
            };
            let Ok(name) = name.to_str() else {
                return Ok(LuaValue::Nil);
            };
            lookup.raw_get(name.to_ascii_lowercase())
        })?,
    )?;
    globals.set_metatable(Some(metatable));
    Ok(registry)
}

fn register_function(
    globals: &LuaTable,
    registry: &LuaTable,
    name: &'static str,
    function: LuaFunction,
) -> LuaResult<()> {
    globals.set(name, function.clone())?;
    registry.set(name, function)
}

fn install_addappid(
    lua: &Lua,
    globals: &LuaTable,
    registry: &LuaTable,
    state: &Shared<RuntimeState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    register_function(
        globals,
        registry,
        "addappid",
        lua.create_function(move |_, args: LuaMultiValue| {
            let id_raw = args
                .front()
                .and_then(|value| match value {
                    LuaValue::Integer(n) => u32::try_from(*n).ok(),
                    _ => None,
                })
                .ok_or_else(|| {
                    mlua::Error::RuntimeError("addappid: arg1 must be integer".into())
                })?;

            let key_hex = match args.get(2) {
                Some(LuaValue::String(value)) => Some(value.to_str()?.to_owned()),
                Some(_) => {
                    return Err(mlua::Error::RuntimeError(
                        "addappid: arg3 must be a depot key string".into(),
                    ));
                }
                None => None,
            };

            let mut detail = format!("app_id={id_raw}");
            let mut state = lock_shared(&state);
            let app_id = AppId(id_raw);
            if !state.apps.contains(&app_id) {
                state.apps.push(app_id);
            }

            if let Some(hex) = key_hex {
                if hex.len() == 64 {
                    let Some(key) = parse_hex_key(&hex) else {
                        return Err(mlua::Error::RuntimeError(
                            "addappid: arg3 must contain exactly 64 hex digits".into(),
                        ));
                    };
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
    registry: &LuaTable,
    state: &Shared<RuntimeState>,
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
            lock_shared(&state).manifests.insert(
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
    register_function(globals, registry, "setmanifestid", function)
}

fn install_ticket_api(
    lua: &Lua,
    globals: &LuaTable,
    registry: &LuaTable,
    state: &Shared<RuntimeState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    install_hex_ticket_fn(
        lua,
        globals,
        registry,
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
        registry,
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
    registry: &LuaTable,
    state: &Shared<RuntimeState>,
    ctx: &ScriptRunContext,
    name: &'static str,
    store: fn(&mut RuntimeState, AppId, Vec<u8>),
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    register_function(
        globals,
        registry,
        name,
        lua.create_function(move |_, (app_id_raw, hex): (u32, String)| {
            let bytes = parse_hex_key(&hex)
                .ok_or_else(|| mlua::Error::RuntimeError(format!("{name}: invalid hex string")))?;
            store(&mut lock_shared(&state), AppId(app_id_raw), bytes);
            ctx.push_call(name, format!("app_id={app_id_raw} bytes={}", hex.len() / 2));
            Ok(())
        })?,
    )
}

fn install_setstat(
    lua: &Lua,
    globals: &LuaTable,
    registry: &LuaTable,
    state: &Shared<RuntimeState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    register_function(
        globals,
        registry,
        "setstat",
        lua.create_function(move |_, (app_id_raw, steamid_str): (u32, String)| {
            let steamid: u64 = steamid_str.parse().map_err(|_| {
                mlua::Error::RuntimeError("setstat: steamid must be decimal string".into())
            })?;
            lock_shared(&state)
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
    registry: &LuaTable,
    state: &Shared<RuntimeState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    register_function(
        globals,
        registry,
        "setavatar",
        lua.create_function(move |_, (app_id_raw, avatar_raw): (u32, u32)| {
            lock_shared(&state)
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

fn install_addtoken(
    lua: &Lua,
    globals: &LuaTable,
    registry: &LuaTable,
    state: &Shared<RuntimeState>,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let state = state.clone();
    let ctx = ctx.clone();
    register_function(
        globals,
        registry,
        "addtoken",
        lua.create_function(move |_, (app_id_raw, token): (u32, Option<String>)| {
            if let Some(token) = token {
                let token = token.parse::<u64>().map_err(|_| {
                    mlua::Error::RuntimeError(
                        "addtoken: arg2 must be a decimal uint64 string".into(),
                    )
                })?;
                lock_shared(&state)
                    .access_tokens
                    .insert(AppId(app_id_raw), token);
                ctx.push_call("addtoken", format!("app_id={app_id_raw} token={token}"));
            }
            Ok(())
        })?,
    )
}

fn install_http_api(
    lua: &Lua,
    globals: &LuaTable,
    registry: &LuaTable,
    options: &ScriptExecutionOptions,
    ctx: &ScriptRunContext,
) -> Result<(), mlua::Error> {
    let get_options = options.clone();
    let get_ctx = ctx.clone();
    register_function(
        globals,
        registry,
        "http_get",
        lua.create_function(move |lua, (url, headers): (String, Option<LuaTable>)| {
            get_ctx.push_call(
                "http_get",
                format!("url={}", display_url(&url, get_options.redact_network_urls)),
            );
            ensure_network_allowed(&get_options, &url, "http_get")?;
            let mut request = http_agent(get_options.network_timeout_ms).get(&url);
            for (name, value) in collect_headers(headers)? {
                request = request.header(name, value);
            }
            match request.call() {
                Ok(mut response) => {
                    let status = response.status().as_u16() as LuaInteger;
                    let body = read_http_body(response.body_mut(), "http_get")?;
                    Ok((Some(body), LuaValue::Integer(status)))
                }
                Err(error) => {
                    tracing::warn!(%error, "http_get failed");
                    Ok((
                        None,
                        LuaValue::String(lua.create_string("HTTP request failed")?),
                    ))
                }
            }
        })?,
    )?;

    let post_options = options.clone();
    let post_ctx = ctx.clone();
    register_function(
        globals,
        registry,
        "http_post",
        lua.create_function(
            move |lua, (url, body, headers): (String, String, Option<LuaTable>)| {
                post_ctx.push_call(
                    "http_post",
                    format!(
                        "url={} body_bytes={}",
                        display_url(&url, post_options.redact_network_urls),
                        body.len()
                    ),
                );
                ensure_network_allowed(&post_options, &url, "http_post")?;
                let mut request = http_agent(post_options.network_timeout_ms).post(&url);
                for (name, value) in collect_headers(headers)? {
                    request = request.header(name, value);
                }
                match request.send(body.as_bytes()) {
                    Ok(mut response) => {
                        let status = response.status().as_u16() as LuaInteger;
                        let body = read_http_body(response.body_mut(), "http_post")?;
                        Ok((Some(body), LuaValue::Integer(status)))
                    }
                    Err(error) => {
                        tracing::warn!(%error, "http_post failed");
                        Ok((
                            None,
                            LuaValue::String(lua.create_string("HTTP request failed")?),
                        ))
                    }
                }
            },
        )?,
    )
}

fn collect_headers(headers: Option<LuaTable>) -> LuaResult<Vec<(String, String)>> {
    headers
        .map(|headers| headers.pairs::<String, String>().collect())
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn read_http_body(body: &mut ureq::Body, function: &str) -> LuaResult<String> {
    body.with_config()
        .limit(MAX_HTTP_BODY_BYTES)
        .lossy_utf8(true)
        .read_to_string()
        .map_err(|error| mlua::Error::RuntimeError(format!("{function} read failed: {error}")))
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
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_millis(
            timeout_ms.unwrap_or(DEFAULT_HTTP_TIMEOUT_MS),
        )))
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

pub(crate) fn parse_hex_key(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}
