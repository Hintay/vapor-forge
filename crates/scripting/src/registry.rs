use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mlua::prelude::*;
use vapor_forge_core::ScriptState;

use crate::bindings::{
    begin_parse_file, end_parse_file, execute_source, install_lua_api, invoke_manifest_basic,
    invoke_manifest_extended, provider_functions, snapshot_state, unload_file, RuntimeState,
    ScriptRunContext, Shared,
};
use crate::report::{ScriptCallReport, ScriptExecutionOptions};

pub(crate) struct ScriptRegistry {
    lua: Lua,
    state: Shared<RuntimeState>,
    ctx: ScriptRunContext,
}

impl ScriptRegistry {
    pub(crate) fn new(options: &ScriptExecutionOptions) -> LuaResult<Self> {
        let lua = Lua::new();
        let state: Shared<RuntimeState> = Arc::new(Mutex::new(RuntimeState::default()));
        let ctx = ScriptRunContext::new(options.record_calls);
        install_lua_api(&lua, &state, &ctx, options)?;
        Ok(Self { lua, state, ctx })
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
        invoke_manifest_basic(&self.lua, gid)
    }

    pub(crate) fn invoke_extended(
        &self,
        app_id: u32,
        depot_id: u32,
        gid: u64,
    ) -> LuaResult<Option<u64>> {
        invoke_manifest_extended(&self.lua, app_id, depot_id, gid)
    }
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
        lock_registry(&self.inner).invoke_basic(gid)
    }

    pub fn invoke_extended(&self, app_id: u32, depot_id: u32, gid: u64) -> LuaResult<Option<u64>> {
        lock_registry(&self.inner).invoke_extended(app_id, depot_id, gid)
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
