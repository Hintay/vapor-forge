use std::path::PathBuf;
use std::sync::mpsc;

use mlua::prelude::*;
use tracing::{info, warn};
use vapor_forge_core::ScriptState;

use crate::bindings::{create_runtime, execute_source, snapshot_state};
use crate::report::{ScriptCallReport, ScriptExecutionOptions, ScriptFileReport};

#[derive(Clone, Debug)]
pub(crate) struct ScriptSource {
    pub path: PathBuf,
    pub source: String,
}

pub(crate) struct ProviderExecution {
    pub state: ScriptState,
    pub files: Vec<ScriptFileReport>,
    pub calls: Vec<ScriptCallReport>,
    pub provider: Option<ManifestCodeProvider>,
}

#[derive(Clone)]
pub struct ManifestCodeProvider {
    sender: mpsc::Sender<ProviderRequest>,
    has_basic: bool,
    has_extended: bool,
}

impl std::fmt::Debug for ManifestCodeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestCodeProvider")
            .field("has_basic", &self.has_basic)
            .field("has_extended", &self.has_extended)
            .finish_non_exhaustive()
    }
}

struct ProviderRequest {
    app_id: u32,
    depot_id: u32,
    gid: u64,
    response: mpsc::SyncSender<Result<Option<u64>, String>>,
}

struct ProviderReady {
    state: ScriptState,
    files: Vec<ScriptFileReport>,
    calls: Vec<ScriptCallReport>,
    has_basic: bool,
    has_extended: bool,
}

impl ManifestCodeProvider {
    pub(crate) fn execute(
        sources: Vec<ScriptSource>,
        options: ScriptExecutionOptions,
    ) -> Result<ProviderExecution, String> {
        if sources.is_empty() {
            return Ok(ProviderExecution {
                state: ScriptState::default(),
                files: Vec::new(),
                calls: Vec::new(),
                provider: None,
            });
        }

        let (request_tx, request_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("lua-runtime".to_owned())
            .spawn(move || runtime_loop(sources, options, request_rx, ready_tx))
            .map_err(|error| format!("failed to start Lua runtime: {error}"))?;

        let ready = ready_rx
            .recv()
            .map_err(|_| "Lua runtime stopped during initialization".to_owned())??;
        let provider = (ready.has_basic || ready.has_extended).then_some(Self {
            sender: request_tx,
            has_basic: ready.has_basic,
            has_extended: ready.has_extended,
        });
        Ok(ProviderExecution {
            state: ready.state,
            files: ready.files,
            calls: ready.calls,
            provider,
        })
    }

    pub fn fetch(&self, app_id: u32, depot_id: u32, gid: u64) -> Result<Option<u64>, String> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        self.sender
            .send(ProviderRequest {
                app_id,
                depot_id,
                gid,
                response: response_tx,
            })
            .map_err(|_| "Lua manifest provider is no longer running".to_owned())?;
        response_rx
            .recv()
            .map_err(|_| "Lua manifest provider stopped before responding".to_owned())?
    }

    pub fn has_basic(&self) -> bool {
        self.has_basic
    }

    pub fn has_extended(&self) -> bool {
        self.has_extended
    }
}

fn runtime_loop(
    sources: Vec<ScriptSource>,
    options: ScriptExecutionOptions,
    requests: mpsc::Receiver<ProviderRequest>,
    ready: mpsc::SyncSender<Result<ProviderReady, String>>,
) {
    let (lua, state, ctx) = match create_runtime(&options) {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return;
        }
    };

    let files = sources
        .iter()
        .map(|source| {
            let errors = execute_source(&lua, &source.path, &source.source, &ctx);
            ScriptFileReport {
                path: source.path.display().to_string(),
                result: if errors.is_empty() {
                    Ok(())
                } else {
                    Err(errors.join("\n"))
                },
            }
        })
        .collect();

    let globals = lua.globals();
    let has_basic = matches!(
        globals.raw_get::<LuaValue>("fetch_manifest_code"),
        Ok(LuaValue::Function(_))
    );
    let has_extended = matches!(
        globals.raw_get::<LuaValue>("fetch_manifest_code_ex"),
        Ok(LuaValue::Function(_))
    );
    drop(globals);

    if ready
        .send(Ok(ProviderReady {
            state: snapshot_state(&state),
            files,
            calls: ctx.drain_calls(),
            has_basic,
            has_extended,
        }))
        .is_err()
    {
        return;
    }

    if !has_basic && !has_extended {
        return;
    }
    while let Ok(request) = requests.recv() {
        let result = invoke_provider(&lua, has_basic, has_extended, &request);
        let _ = request.response.send(Ok(result));
    }
}

fn invoke_provider(
    lua: &Lua,
    has_basic: bool,
    has_extended: bool,
    request: &ProviderRequest,
) -> Option<u64> {
    if has_extended && request.app_id != 0 && request.depot_id != 0 {
        match call_extended(lua, request.app_id, request.depot_id, request.gid) {
            Ok(Some(code)) => {
                info!(
                    app_id = request.app_id,
                    depot_id = request.depot_id,
                    gid = request.gid,
                    code,
                    "request_code: manifest code obtained from fetch_manifest_code_ex"
                );
                return Some(code);
            }
            Ok(None) => {}
            Err(error) => warn!(
                gid = request.gid,
                %error,
                "request_code: fetch_manifest_code_ex failed"
            ),
        }
    }

    if has_basic {
        match call_basic(lua, request.gid) {
            Ok(Some(code)) => {
                info!(
                    gid = request.gid,
                    code, "request_code: manifest code obtained from fetch_manifest_code"
                );
                return Some(code);
            }
            Ok(None) => {}
            Err(error) => warn!(
                gid = request.gid,
                %error,
                "request_code: fetch_manifest_code failed"
            ),
        }
    }

    None
}

fn call_extended(lua: &Lua, app_id: u32, depot_id: u32, gid: u64) -> LuaResult<Option<u64>> {
    let function: LuaFunction = lua.globals().raw_get("fetch_manifest_code_ex")?;
    parse_code(function.call((
        exact_lua_uint(lua, app_id as u64)?,
        exact_lua_uint(lua, depot_id as u64)?,
        exact_lua_uint(lua, gid)?,
    ))?)
}

fn call_basic(lua: &Lua, gid: u64) -> LuaResult<Option<u64>> {
    let function: LuaFunction = lua.globals().raw_get("fetch_manifest_code")?;
    parse_code(function.call(exact_lua_uint(lua, gid)?)?)
}

fn exact_lua_uint(lua: &Lua, value: u64) -> LuaResult<LuaValue> {
    const MAX_EXACT_LUA_NUMBER: u64 = (1_u64 << 53) - 1;
    if value <= LuaInteger::MAX as u64 && value <= MAX_EXACT_LUA_NUMBER {
        Ok(LuaValue::Integer(value as LuaInteger))
    } else {
        Ok(LuaValue::String(lua.create_string(value.to_string())?))
    }
}

fn parse_code(value: LuaValue) -> LuaResult<Option<u64>> {
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
