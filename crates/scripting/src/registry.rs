use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mlua::prelude::*;
use vapor_forge_core::ScriptState;

use crate::bindings::{
    begin_parse_file, end_parse_file, execute_source, install_lua_api, invoke_manifest_basic,
    invoke_manifest_extended, provider_functions, snapshot_state, unload_file,
    ProviderNetworkBudget, RuntimeState, ScriptRunContext, Shared,
};
use crate::report::{ScriptCallReport, ScriptExecutionOptions};

const PROVIDER_INSTRUCTION_BUDGET: u32 = 1_000_000;
const PROVIDER_HOOK_INTERVAL: u32 = 10_000;
const PROVIDER_BUDGET_EXHAUSTED: &str = "manifest provider instruction budget exhausted";
const DEFAULT_PROVIDER_NETWORK_TIMEOUT_MS: u64 = 10_000;
const BLOCKING_BASE_GLOBALS: [&str; 4] = ["dofile", "loadfile", "print", "coroutine"];

pub(crate) struct ScriptRegistry {
    lua: Lua,
    state: Shared<RuntimeState>,
    ctx: ScriptRunContext,
    provider_network_budget: ProviderNetworkBudget,
    provider_network_timeout: Duration,
}

pub(crate) struct ManifestCallbackResults {
    pub extended: Option<Result<Option<u64>, String>>,
    pub basic: Option<Result<Option<u64>, String>>,
}

impl ScriptRegistry {
    pub(crate) fn new(options: &ScriptExecutionOptions) -> LuaResult<Self> {
        let libraries = LuaStdLib::TABLE
            | LuaStdLib::STRING
            | LuaStdLib::BIT
            | LuaStdLib::MATH
            | LuaStdLib::JIT;
        let lua = Lua::new_with(libraries, LuaOptions::default())?;
        disable_and_remove_luajit(&lua)?;
        let globals = lua.globals();
        for name in BLOCKING_BASE_GLOBALS {
            globals.raw_set(name, LuaNil)?;
        }
        let state: Shared<RuntimeState> = Arc::new(Mutex::new(RuntimeState::default()));
        let ctx = ScriptRunContext::new(options.record_calls);
        let provider_network_budget = ProviderNetworkBudget::default();
        install_lua_api(&lua, &state, &ctx, options, &provider_network_budget)?;
        Ok(Self {
            lua,
            state,
            ctx,
            provider_network_budget,
            provider_network_timeout: Duration::from_millis(
                options
                    .network_timeout_ms
                    .unwrap_or(DEFAULT_PROVIDER_NETWORK_TIMEOUT_MS),
            ),
        })
    }

    pub(crate) fn parse_file(&mut self, path: &Path, source: &str) -> Vec<String> {
        begin_parse_file(&self.state, path);
        let errors = execute_source(&self.lua, path, source, &self.ctx);
        end_parse_file(&self.state);
        errors
    }

    pub(crate) fn unload_file(&mut self, path: &Path) {
        unload_file(&self.state, path);
    }

    pub(crate) fn snapshot_state(&self) -> ScriptState {
        snapshot_state(&self.state)
    }

    pub(crate) fn take_calls(&self) -> Vec<ScriptCallReport> {
        self.ctx.drain_calls()
    }

    pub(crate) fn provider_functions(&self) -> (bool, bool) {
        provider_functions(&self.lua)
    }

    pub(crate) fn invoke_basic(&self, gid: u64) -> LuaResult<Option<u64>> {
        self.invoke_provider(|lua| invoke_manifest_basic(lua, gid))
    }

    pub(crate) fn invoke_extended(
        &self,
        app_id: u32,
        depot_id: u32,
        gid: u64,
    ) -> LuaResult<Option<u64>> {
        self.invoke_provider(|lua| invoke_manifest_extended(lua, app_id, depot_id, gid))
    }

    pub(crate) fn invoke_manifest_callbacks(
        &self,
        app_id: u32,
        depot_id: u32,
        gid: u64,
        has_extended: bool,
        has_basic: bool,
    ) -> LuaResult<ManifestCallbackResults> {
        self.invoke_provider(|lua| {
            let extended = (has_extended && app_id != 0 && depot_id != 0).then(|| {
                invoke_manifest_extended(lua, app_id, depot_id, gid)
                    .map_err(|error| error.to_string())
            });
            let has_code = extended
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .is_some_and(Option::is_some);
            let basic = (has_basic && !has_code)
                .then(|| invoke_manifest_basic(lua, gid).map_err(|error| error.to_string()));
            Ok(ManifestCallbackResults { extended, basic })
        })
    }

    fn invoke_provider<T>(&self, invoke: impl FnOnce(&Lua) -> LuaResult<T>) -> LuaResult<T> {
        let _network_guard = self
            .provider_network_budget
            .begin(self.provider_network_timeout)?;
        let remaining = AtomicU32::new(PROVIDER_INSTRUCTION_BUDGET / PROVIDER_HOOK_INTERVAL);
        self.lua.set_hook(
            LuaHookTriggers::new().every_nth_instruction(PROVIDER_HOOK_INTERVAL),
            move |_, _| {
                let previous =
                    remaining.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        value.checked_sub(1)
                    });
                match previous {
                    Ok(value) if value > 1 => Ok(LuaVmState::Continue),
                    _ => Err(LuaError::RuntimeError(PROVIDER_BUDGET_EXHAUSTED.into())),
                }
            },
        );
        let _guard = ProviderHookGuard { lua: &self.lua };
        invoke(&self.lua)
    }
}

struct ProviderHookGuard<'lua> {
    lua: &'lua Lua,
}

impl Drop for ProviderHookGuard<'_> {
    fn drop(&mut self) {
        self.lua.remove_hook();
    }
}

fn disable_and_remove_luajit(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let jit: LuaTable = globals.raw_get("jit")?;
    jit.raw_get::<LuaFunction>("off")?.call::<()>(())?;
    jit.raw_get::<LuaFunction>("flush")?.call::<()>(())?;
    lua.unload("jit")?;
    globals.raw_set("jit", LuaNil)
}

/// Cheap-to-clone handle over `ScriptRegistry`. All operations serialize
/// through one mutex; writes (parse/unload) are triggered by the watcher
/// thread while callback invocations run on IPC threads.
#[derive(Clone)]
pub struct RegistryHandle {
    inner: Arc<Mutex<ScriptRegistry>>,
}

impl std::fmt::Debug for RegistryHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryHandle").finish_non_exhaustive()
    }
}

impl RegistryHandle {
    pub(crate) fn new(registry: ScriptRegistry) -> Self {
        Self {
            inner: Arc::new(Mutex::new(registry)),
        }
    }

    pub fn parse_file(&self, path: &Path, source: &str) -> Vec<String> {
        lock_registry(&self.inner).parse_file(path, source)
    }

    pub fn unload_file(&self, path: &Path) {
        lock_registry(&self.inner).unload_file(path)
    }

    pub fn snapshot_state(&self) -> ScriptState {
        lock_registry(&self.inner).snapshot_state()
    }

    pub fn drain_calls(&self) -> Vec<ScriptCallReport> {
        lock_registry(&self.inner).take_calls()
    }

    pub fn provider_functions(&self) -> (bool, bool) {
        lock_registry(&self.inner).provider_functions()
    }

    pub fn invoke_basic(&self, gid: u64) -> LuaResult<Option<u64>> {
        let registry = lock_registry(&self.inner);
        registry.invoke_basic(gid)
    }

    pub fn invoke_extended(&self, app_id: u32, depot_id: u32, gid: u64) -> LuaResult<Option<u64>> {
        let registry = lock_registry(&self.inner);
        registry.invoke_extended(app_id, depot_id, gid)
    }

    pub(crate) fn invoke_manifest_callbacks(
        &self,
        app_id: u32,
        depot_id: u32,
        gid: u64,
        has_extended: bool,
        has_basic: bool,
    ) -> LuaResult<ManifestCallbackResults> {
        let registry = self.inner.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => {
                LuaError::RuntimeError("manifest provider registry is busy".into())
            }
            std::sync::TryLockError::Poisoned(error) => {
                LuaError::RuntimeError(format!("manifest provider registry failed: {error}"))
            }
        })?;
        registry.invoke_manifest_callbacks(app_id, depot_id, gid, has_extended, has_basic)
    }
}

fn lock_registry(inner: &Arc<Mutex<ScriptRegistry>>) -> std::sync::MutexGuard<'_, ScriptRegistry> {
    inner.lock().unwrap_or_else(|error| error.into_inner())
}

/// Enumerate `.lua` files in `dir` sorted lexicographically.
#[allow(dead_code)]
pub(crate) fn collect_lua_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "lua") && path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_callback_fails_while_registry_is_busy() {
        let registry = ScriptRegistry::new(&ScriptExecutionOptions::default()).unwrap();
        let handle = RegistryHandle::new(registry);
        let _guard = handle.inner.lock().unwrap();

        let error = match handle.invoke_manifest_callbacks(480, 481, 1, true, true) {
            Ok(_) => panic!("busy registry accepted a manifest callback"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("registry is busy"));
    }
}
