use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, UNIX_EPOCH};

use mlua::prelude::*;
use vapor_forge_core::{AppId, DepotId, ManifestId};

use crate::report::{ScriptCallReport, ScriptExecutionOptions};
use crate::{ManifestOverride, ScriptState};

const DEFAULT_HTTP_TIMEOUT_MS: u64 = 10_000;
const MAX_HTTP_BODY_BYTES: u64 = 256 * 1024;

fn file_mtime_unix(path: &Path) -> Option<u32> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let secs = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
    u32::try_from(secs).ok()
}

#[derive(Clone, Default)]
pub(crate) struct RuntimeState {
    // Aggregated state exposed via ScriptState.
    apps: HashSet<AppId>,
    depot_keys: HashMap<DepotId, Vec<u8>>,
    manifests: HashMap<DepotId, ManifestOverride>,
    app_tickets: HashMap<AppId, Vec<u8>>,
    enc_tickets: HashMap<AppId, Vec<u8>>,
    stat_steam_ids: HashMap<AppId, u64>,
    avatars: HashMap<AppId, AppId>,
    access_tokens: HashMap<AppId, u64>,
    app_purchase_times: HashMap<AppId, u32>,

    // Per-file bookkeeping backing incremental parse / unload.
    current_file: Option<PathBuf>,
    file_depots: HashMap<PathBuf, HashSet<DepotId>>,
    file_manifest_overrides: HashMap<PathBuf, HashMap<DepotId, ManifestOverride>>,
    file_parse_sequence: HashMap<PathBuf, u64>,
    file_mtimes: HashMap<PathBuf, u32>,
    next_parse_sequence: u64,
    depot_refcount: HashMap<DepotId, u32>,
}

pub(crate) type Shared<T> = Arc<Mutex<T>>;

pub(crate) fn lock_shared<T>(shared: &Shared<T>) -> MutexGuard<'_, T> {
    shared.lock().unwrap_or_else(|error| error.into_inner())
}

#[derive(Clone)]
pub(crate) struct ScriptRunContext {
    path: Shared<String>,
    calls: Shared<Vec<ScriptCallReport>>,
    record_calls: bool,
}

impl ScriptRunContext {
    pub(crate) fn new(record_calls: bool) -> Self {
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
        app_purchase_times: state.app_purchase_times.clone(),
    }
}

/// Prepare `RuntimeState` to receive a file's contributions: drop any prior
/// slice for the same path, stamp its mtime and parse sequence, then mark it
/// as the active file so `addappid` / `setmanifestid` callbacks attribute
/// their writes correctly.
pub(crate) fn begin_parse_file(state: &Shared<RuntimeState>, path: &Path) {
    unload_file(state, path);
    let mut state = lock_shared(state);
    let owned = path.to_path_buf();
    state.next_parse_sequence += 1;
    let seq = state.next_parse_sequence;
    state.file_parse_sequence.insert(owned.clone(), seq);
    let mtime = file_mtime_unix(path).unwrap_or(0);
    state.file_mtimes.insert(owned.clone(), mtime);
    state.current_file = Some(owned);
}

pub(crate) fn end_parse_file(state: &Shared<RuntimeState>) {
    lock_shared(state).current_file = None;
}

/// Drop every contribution a file previously made: decrement depot refcounts,
/// erase entries whose count hits zero, and rebuild manifest overrides so the
/// active choice comes from a still-loaded file with the largest parse seq.
pub(crate) fn unload_file(state: &Shared<RuntimeState>, path: &Path) {
    let mut state = lock_shared(state);
    if let Some(depots) = state.file_depots.remove(path) {
        for depot_id in depots {
            let hit_zero = match state.depot_refcount.get_mut(&depot_id) {
                Some(count) => {
                    *count = count.saturating_sub(1);
                    *count == 0
                }
                None => false,
            };
            if hit_zero {
                state.depot_refcount.remove(&depot_id);
                state.depot_keys.remove(&depot_id);
                let app_id = AppId(depot_id.0);
                state.apps.remove(&app_id);
                state.app_purchase_times.remove(&app_id);
            }
        }
    }
    if let Some(overrides) = state.file_manifest_overrides.remove(path) {
        let affected: Vec<DepotId> = overrides.keys().copied().collect();
        for depot_id in affected {
            rebuild_manifest_override(&mut state, depot_id);
        }
    }
    state.file_parse_sequence.remove(path);
    state.file_mtimes.remove(path);
}

pub(crate) fn provider_functions(lua: &Lua) -> (bool, bool) {
    let globals = lua.globals();
    let has_basic = matches!(
        globals.raw_get::<LuaValue>("fetch_manifest_code"),
        Ok(LuaValue::Function(_))
    );
    let has_extended = matches!(
        globals.raw_get::<LuaValue>("fetch_manifest_code_ex"),
        Ok(LuaValue::Function(_))
    );
    (has_basic, has_extended)
}

pub(crate) fn invoke_manifest_basic(lua: &Lua, gid: u64) -> LuaResult<Option<u64>> {
    let function: LuaFunction = lua.globals().raw_get("fetch_manifest_code")?;
    parse_manifest_code(function.call(exact_lua_uint(lua, gid)?)?)
}

pub(crate) fn invoke_manifest_extended(
    lua: &Lua,
    app_id: u32,
    depot_id: u32,
    gid: u64,
) -> LuaResult<Option<u64>> {
    let function: LuaFunction = lua.globals().raw_get("fetch_manifest_code_ex")?;
    parse_manifest_code(function.call((
        exact_lua_uint(lua, app_id as u64)?,
        exact_lua_uint(lua, depot_id as u64)?,
        exact_lua_uint(lua, gid)?,
    ))?)
}

fn exact_lua_uint(lua: &Lua, value: u64) -> LuaResult<LuaValue> {
    const MAX_EXACT_LUA_NUMBER: u64 = (1_u64 << 53) - 1;
    if value <= LuaInteger::MAX as u64 && value <= MAX_EXACT_LUA_NUMBER {
        Ok(LuaValue::Integer(value as LuaInteger))
    } else {
        Ok(LuaValue::String(lua.create_string(value.to_string())?))
    }
}

fn parse_manifest_code(value: LuaValue) -> LuaResult<Option<u64>> {
    match value {
        LuaValue::Nil => Ok(None),
        LuaValue::Integer(value) if value >= 0 => Ok(Some(value as u64)),
        LuaValue::String(value) => value.to_str()?.parse::<u64>().map(Some).map_err(|_| {
            LuaError::RuntimeError(
                "manifest request code must be a decimal uint64 string".to_owned(),
            )
        }),
        _ => Err(LuaError::RuntimeError(
            "manifest request code must be nil, an integer, or a decimal string".to_owned(),
        )),
    }
}

pub(crate) fn install_lua_api(
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
            let depot_id = DepotId(id_raw);

            let current_file = state.current_file.clone();
            if let Some(path) = current_file {
                let first_time_for_file = state
                    .file_depots
                    .entry(path.clone())
                    .or_default()
                    .insert(depot_id);
                if first_time_for_file {
                    let rc = state.depot_refcount.entry(depot_id).or_insert(0);
                    *rc += 1;
                    if *rc == 1 {
                        state.apps.insert(app_id);
                    }
                    let mtime = state.file_mtimes.get(&path).copied().unwrap_or(0);
                    if mtime != 0 {
                        let slot = state.app_purchase_times.entry(app_id).or_insert(0);
                        if mtime > *slot {
                            *slot = mtime;
                        }
                    }
                }
            } else {
                // Direct-invocation path (e.g. tests) without a parse context.
                state.apps.insert(app_id);
            }

            if let Some(hex) = key_hex {
                if hex.len() == 64 {
                    let Some(key) = parse_hex_key(&hex) else {
                        return Err(mlua::Error::RuntimeError(
                            "addappid: arg3 must contain exactly 64 hex digits".into(),
                        ));
                    };
                    let key_len = key.len();
                    // Non-empty always wins; empty may only fill a missing slot.
                    if !key.is_empty() || !state.depot_keys.contains_key(&depot_id) {
                        state.depot_keys.insert(depot_id, key);
                    }
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
            let override_value = ManifestOverride {
                depot_id,
                gid: ManifestId(gid_raw),
                size,
            };
            let mut state = lock_shared(&state);
            let current_file = state.current_file.clone();
            if let Some(path) = current_file {
                state
                    .file_manifest_overrides
                    .entry(path)
                    .or_default()
                    .insert(depot_id, override_value);
                rebuild_manifest_override(&mut state, depot_id);
            } else {
                state.manifests.insert(depot_id, override_value);
            }

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

fn rebuild_manifest_override(state: &mut RuntimeState, depot_id: DepotId) {
    let mut winner: Option<(u64, ManifestOverride)> = None;
    for (file, overrides) in &state.file_manifest_overrides {
        if let Some(entry) = overrides.get(&depot_id) {
            let seq = state.file_parse_sequence.get(file).copied().unwrap_or(0);
            if winner.as_ref().is_none_or(|(best, _)| seq > *best) {
                winner = Some((seq, entry.clone()));
            }
        }
    }
    match winner {
        Some((_, value)) => {
            state.manifests.insert(depot_id, value);
        }
        None => {
            state.manifests.remove(&depot_id);
        }
    }
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
