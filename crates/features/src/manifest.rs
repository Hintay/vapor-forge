use steam_runtime_config::{DepotId, ManifestId};
use steam_runtime_scripting::ScriptState;

pub struct ManifestPatch {
    pub depot_id: DepotId,
    pub new_gid: ManifestId,
    pub new_size: Option<u64>,
}

/// For each depot_id, check if there's a Lua manifest override.
pub fn find_patches(depot_ids: &[DepotId], script_state: &ScriptState) -> Vec<ManifestPatch> {
    depot_ids
        .iter()
        .filter_map(|&depot_id| {
            script_state
                .manifests
                .get(&depot_id)
                .map(|ov| ManifestPatch {
                    depot_id,
                    new_gid: ov.gid,
                    new_size: ov.size,
                })
        })
        .collect()
}
