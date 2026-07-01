use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use steam_runtime_config::{AppId, TicketCacheMode};
use tracing::{debug, info, warn};

/// Thread-safe ticket cache with optional disk persistence.
pub struct TicketCache {
    mode: TicketCacheMode,
    cache_dir: Option<PathBuf>,
    app_tickets: Mutex<HashMap<AppId, Vec<u8>>>,
    enc_tickets: Mutex<HashMap<AppId, Vec<u8>>>,
}

impl TicketCache {
    pub fn new(mode: TicketCacheMode, cache_dir: Option<PathBuf>) -> Self {
        Self {
            mode,
            cache_dir,
            app_tickets: Mutex::new(HashMap::new()),
            enc_tickets: Mutex::new(HashMap::new()),
        }
    }

    /// Get an app ticket. Priority: Lua-provided → memory cache → disk cache.
    pub fn get_app_ticket(
        &self,
        app_id: AppId,
        lua_tickets: &HashMap<AppId, Vec<u8>>,
    ) -> Option<Vec<u8>> {
        // 1. Lua-provided tickets take highest priority
        if let Some(t) = lua_tickets.get(&app_id) {
            debug!(app_id = app_id.0, "ticket: using Lua-provided app ticket");
            return Some(t.clone());
        }
        // 2. In-memory cache
        if let Some(t) = self.app_tickets.lock().unwrap().get(&app_id) {
            debug!(app_id = app_id.0, "ticket: using cached app ticket");
            return Some(t.clone());
        }
        // 3. Disk cache (only in Disk mode)
        if self.mode == TicketCacheMode::Disk {
            if let Some(t) = self.load_from_disk(app_id, "ticket") {
                debug!(app_id = app_id.0, "ticket: loaded app ticket from disk");
                // Populate memory cache for future lookups
                self.app_tickets.lock().unwrap().insert(app_id, t.clone());
                return Some(t);
            }
        }
        None
    }

    /// Get an encrypted app ticket. Priority: Lua-provided → memory cache → disk cache.
    pub fn get_enc_ticket(
        &self,
        app_id: AppId,
        lua_tickets: &HashMap<AppId, Vec<u8>>,
    ) -> Option<Vec<u8>> {
        if let Some(t) = lua_tickets.get(&app_id) {
            debug!(
                app_id = app_id.0,
                "ticket: using Lua-provided encrypted ticket"
            );
            return Some(t.clone());
        }
        if let Some(t) = self.enc_tickets.lock().unwrap().get(&app_id) {
            debug!(app_id = app_id.0, "ticket: using cached encrypted ticket");
            return Some(t.clone());
        }
        if self.mode == TicketCacheMode::Disk {
            if let Some(t) = self.load_from_disk(app_id, "enc_ticket") {
                debug!(
                    app_id = app_id.0,
                    "ticket: loaded encrypted ticket from disk"
                );
                self.enc_tickets.lock().unwrap().insert(app_id, t.clone());
                return Some(t);
            }
        }
        None
    }

    /// Cache a ticket intercepted from Steam's real response.
    pub fn store_app_ticket(&self, app_id: AppId, data: Vec<u8>) {
        info!(
            app_id = app_id.0,
            size = data.len(),
            "ticket: caching app ticket"
        );
        if self.mode == TicketCacheMode::Disk {
            self.save_to_disk(app_id, "ticket", &data);
        }
        self.app_tickets.lock().unwrap().insert(app_id, data);
    }

    /// Cache an encrypted ticket intercepted from Steam's real response.
    pub fn store_enc_ticket(&self, app_id: AppId, data: Vec<u8>) {
        info!(
            app_id = app_id.0,
            size = data.len(),
            "ticket: caching encrypted ticket"
        );
        if self.mode == TicketCacheMode::Disk {
            self.save_to_disk(app_id, "enc_ticket", &data);
        }
        self.enc_tickets.lock().unwrap().insert(app_id, data);
    }

    fn load_from_disk(&self, app_id: AppId, prefix: &str) -> Option<Vec<u8>> {
        let dir = self.cache_dir.as_ref()?;
        let path = dir.join(format!("{}_{}.bin", prefix, app_id.0));
        std::fs::read(&path).ok()
    }

    fn save_to_disk(&self, app_id: AppId, prefix: &str, data: &[u8]) {
        let Some(dir) = &self.cache_dir else { return };
        let _ = std::fs::create_dir_all(dir);
        let path = dir.join(format!("{}_{}.bin", prefix, app_id.0));
        if let Err(e) = std::fs::write(&path, data) {
            warn!(error = %e, app_id = app_id.0, "ticket: disk cache write failed");
        }
    }
}

/// Ticket forging: create a ticket for a target app from a source ticket (appId 7).
pub mod forge {
    /// The source app whose ticket we clone from.
    pub const SOURCE_APP_ID: u32 = 7;

    /// Offset of the SteamID within a standard ownership ticket.
    const TICKET_STEAMID_OFFSET: usize = 8;

    /// Size of the RSA signature at the end of a ticket.
    const SIGNATURE_SIZE: usize = 128;

    /// A ticket forged from a source ticket for a different appId.
    pub struct ForgedTicket {
        /// The complete forged ticket data.
        pub data: Vec<u8>,
        /// Total ticket size (the data.len() value Steam should see).
        pub total_size: u32,
        /// Byte offset of the appId field within the forged ticket.
        pub app_id_offset: u32,
        /// Byte offset of the SteamID field within the forged ticket.
        pub steam_id_offset: u32,
        /// Byte offset where the signature begins.
        pub signature_offset: u32,
        /// Size of the signature in bytes.
        pub signature_size: u32,
    }

    /// Forge a ticket for `target_app_id` from a source ticket.
    ///
    /// Layout: `[signed_data] [target_app_id le32] [signature]`
    ///
    /// The target appId is inserted between the signed body and the signature,
    /// matching the SLSsteam forging strategy.
    pub fn forge_from_source(source_ticket: &[u8], target_app_id: u32) -> Option<ForgedTicket> {
        if source_ticket.len() <= SIGNATURE_SIZE {
            return None;
        }
        let signed_size = source_ticket.len() - SIGNATURE_SIZE;

        let mut data = Vec::with_capacity(source_ticket.len() + 4);
        // Copy everything before the signature
        data.extend_from_slice(&source_ticket[..signed_size]);
        // Insert target appId
        data.extend_from_slice(&target_app_id.to_le_bytes());
        // Append the original signature
        data.extend_from_slice(&source_ticket[signed_size..]);

        let app_id_offset = signed_size as u32;
        let signature_offset = app_id_offset + 4;

        Some(ForgedTicket {
            total_size: data.len() as u32,
            app_id_offset,
            steam_id_offset: TICKET_STEAMID_OFFSET as u32,
            signature_offset,
            signature_size: SIGNATURE_SIZE as u32,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn cache_stores_and_retrieves_app_ticket() {
        let cache = TicketCache::new(TicketCacheMode::Session, None);
        let ticket = vec![0xDE, 0xAD, 0xBE, 0xEF];
        cache.store_app_ticket(AppId(480), ticket.clone());

        let empty_lua: HashMap<AppId, Vec<u8>> = HashMap::new();
        assert_eq!(cache.get_app_ticket(AppId(480), &empty_lua), Some(ticket));
        assert_eq!(cache.get_app_ticket(AppId(730), &empty_lua), None);
    }

    #[test]
    fn lua_tickets_take_priority() {
        let cache = TicketCache::new(TicketCacheMode::Session, None);
        cache.store_app_ticket(AppId(480), vec![0x01, 0x02]);

        let mut lua: HashMap<AppId, Vec<u8>> = HashMap::new();
        lua.insert(AppId(480), vec![0xAA, 0xBB]);

        // Lua ticket should win over cached
        assert_eq!(
            cache.get_app_ticket(AppId(480), &lua),
            Some(vec![0xAA, 0xBB])
        );
    }

    #[test]
    fn disk_cache_round_trip() {
        let dir = std::env::temp_dir().join(format!("ticket-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = TicketCache::new(TicketCacheMode::Disk, Some(dir.clone()));

        let ticket = vec![0x11, 0x22, 0x33, 0x44];
        cache.store_app_ticket(AppId(999), ticket.clone());

        // Create a fresh cache (simulates restart) pointed at same dir
        let cache2 = TicketCache::new(TicketCacheMode::Disk, Some(dir.clone()));
        let empty_lua: HashMap<AppId, Vec<u8>> = HashMap::new();
        assert_eq!(cache2.get_app_ticket(AppId(999), &empty_lua), Some(ticket));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_mode_does_not_touch_disk() {
        let dir = std::env::temp_dir().join(format!("ticket-nodisk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = TicketCache::new(TicketCacheMode::Session, Some(dir.clone()));

        cache.store_app_ticket(AppId(480), vec![0xFF]);

        // No files should exist on disk
        assert!(!dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forge_from_source_produces_valid_ticket() {
        // Create a fake source ticket: 200 bytes of body + 128 bytes of signature
        let mut source = vec![0u8; 328];
        // Put some recognizable data
        for (i, b) in source.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }

        let forged = forge::forge_from_source(&source, 480).expect("forge should succeed");

        // Output should be 4 bytes larger (inserted appId)
        assert_eq!(forged.data.len(), 332);
        assert_eq!(forged.total_size, 332);

        // The first 200 bytes (signed body) should be identical
        assert_eq!(&forged.data[..200], &source[..200]);

        // Bytes 200..204 should be appId 480 in little-endian
        assert_eq!(&forged.data[200..204], &480u32.to_le_bytes());

        // Bytes 204..332 should be the original signature (bytes 200..328)
        assert_eq!(&forged.data[204..332], &source[200..328]);

        assert_eq!(forged.app_id_offset, 200);
        assert_eq!(forged.signature_offset, 204);
        assert_eq!(forged.signature_size, 128);
        assert_eq!(forged.steam_id_offset, 8);
    }

    #[test]
    fn forge_rejects_too_small_ticket() {
        // Ticket smaller than signature size, cannot forge.
        let source = vec![0u8; 64];
        assert!(forge::forge_from_source(&source, 480).is_none());
    }

    #[test]
    fn enc_ticket_cache_works() {
        let cache = TicketCache::new(TicketCacheMode::Session, None);
        let ticket = vec![0xCA, 0xFE];
        cache.store_enc_ticket(AppId(480), ticket.clone());

        let empty_lua: HashMap<AppId, Vec<u8>> = HashMap::new();
        assert_eq!(cache.get_enc_ticket(AppId(480), &empty_lua), Some(ticket));
        assert_eq!(cache.get_enc_ticket(AppId(730), &empty_lua), None);
    }
}
