use std::collections::HashMap;
use tracing::info;
use vapor_forge_config::{AppId, DepotId, RuntimeConfig};

const DEPOT_KEY_SIZE: usize = 32;

pub fn has_key(depot_id: DepotId, keys: &HashMap<DepotId, Vec<u8>>) -> bool {
    keys.get(&depot_id)
        .is_some_and(|key| key.len() == DEPOT_KEY_SIZE)
}

pub fn should_skip_shader_depot(
    depot_id: DepotId,
    config: &RuntimeConfig,
    keys: &HashMap<DepotId, Vec<u8>>,
) -> bool {
    depot_id.0 != 0 && config.is_controlled_app(AppId(depot_id.0)) && !has_key(depot_id, keys)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_presence_requires_exact_size() {
        let depot_id = DepotId(480);
        let mut keys = HashMap::new();
        assert!(!has_key(depot_id, &keys));

        keys.insert(depot_id, vec![0; DEPOT_KEY_SIZE - 1]);
        assert!(!has_key(depot_id, &keys));

        keys.insert(depot_id, vec![0; DEPOT_KEY_SIZE]);
        assert!(has_key(depot_id, &keys));
    }

    #[test]
    fn shader_skip_covers_controlled_apps_and_dlc_without_keys() {
        let mut config = RuntimeConfig::default();
        config.apps.push_inject(vapor_forge_config::InjectApp {
            id: AppId(480),
            dlc: vec![AppId(481)],
            ticket: Default::default(),
            purchase_time: 0,
        });
        let mut keys = HashMap::new();

        assert!(should_skip_shader_depot(DepotId(480), &config, &keys));
        assert!(should_skip_shader_depot(DepotId(481), &config, &keys));
        assert!(!should_skip_shader_depot(DepotId(482), &config, &keys));
        assert!(!should_skip_shader_depot(DepotId(0), &config, &keys));

        keys.insert(DepotId(481), vec![0; DEPOT_KEY_SIZE]);
        assert!(!should_skip_shader_depot(DepotId(481), &config, &keys));
    }
}
