use core::ffi::c_void;

use tracing::debug;
use vapor_forge_config::DepotId;
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_hook_engine::original::detour_or_return;

use super::install::runtime_snapshot;

pub(crate) const GET_SHADER_CACHE_DEPOT_NAME: &str = "CShaderCacheManager::GetShaderCacheDepot";

pub(crate) type GetShaderCacheDepotFn = unsafe extern "C" fn(*mut c_void) -> u32;

pub(crate) static mut GET_SHADER_CACHE_DEPOT_DETOUR: Option<Detour<GetShaderCacheDepotFn>> = None;

pub(crate) unsafe extern "C" fn hk_get_shader_cache_depot(app_info: *mut c_void) -> u32 {
    let original = detour_or_return!(
        GET_SHADER_CACHE_DEPOT_NAME,
        GET_SHADER_CACHE_DEPOT_DETOUR,
        0
    );
    // SAFETY: forwards Steam's app-info object to the matching accessor.
    let depot_id = unsafe { original(app_info) };
    if depot_id == 0
        || !crate::capability::is_ready(crate::capability::Capability::ShaderCacheControl)
    {
        return depot_id;
    }

    let runtime = runtime_snapshot();
    if !vapor_forge_features::depot_key::should_skip_shader_depot(
        DepotId(depot_id),
        &runtime.config,
        &runtime.script_state.depot_keys,
    ) {
        return depot_id;
    }

    debug!(depot_id, "shader-cache: skipped keyless controlled depot");
    0
}
