use std::collections::HashMap;
use steam_runtime_config::DepotId;
use tracing::info;

const DEPOT_KEY_SIZE: usize = 32;

/// Try to provide a depot decryption key from Lua-registered keys.
/// Returns the key bytes if found and valid (exactly 32 bytes), None otherwise.
pub fn provide_key(
    depot_id: DepotId,
    keys: &HashMap<DepotId, Vec<u8>>,
) -> Option<[u8; DEPOT_KEY_SIZE]> {
    let key = keys.get(&depot_id)?;
    if key.len() != DEPOT_KEY_SIZE {
        return None;
    }
    let mut out = [0u8; DEPOT_KEY_SIZE];
    out.copy_from_slice(key);
    info!(depot_id = depot_id.0, "depot_key: provided");
    Some(out)
}
