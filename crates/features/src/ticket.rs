use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tracing::{debug, info, warn};
use vapor_forge_config::AppId;

/// Thread-safe ticket cache.
///
/// - Forge source tickets (appId 7): always memory-only.
/// - Delegate captured tickets: always persisted to disk.
/// - Other tickets: controlled by `persist` flag at store time.
pub struct TicketCache {
    cache_dir: Option<PathBuf>,
    app_tickets: Mutex<HashMap<AppId, Vec<u8>>>,
    enc_tickets: Mutex<HashMap<AppId, Vec<u8>>>,
}

impl TicketCache {
    pub fn new(cache_dir: Option<PathBuf>) -> Self {
        Self {
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
        if let Some(t) = lua_tickets.get(&app_id) {
            debug!(app_id = app_id.0, "ticket: using Lua-provided app ticket");
            return Some(t.clone());
        }
        if let Some(t) = self.app_tickets.lock().unwrap_or_else(|e| e.into_inner()).get(&app_id) {
            debug!(app_id = app_id.0, "ticket: using cached app ticket");
            return Some(t.clone());
        }
        if let Some(t) = self.load_from_disk(app_id, "ticket") {
            debug!(app_id = app_id.0, "ticket: loaded app ticket from disk");
            self.app_tickets.lock().unwrap_or_else(|e| e.into_inner()).insert(app_id, t.clone());
            return Some(t);
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
        if let Some(t) = self.enc_tickets.lock().unwrap_or_else(|e| e.into_inner()).get(&app_id) {
            debug!(app_id = app_id.0, "ticket: using cached encrypted ticket");
            return Some(t.clone());
        }
        if let Some(t) = self.load_from_disk(app_id, "enc_ticket") {
            debug!(
                app_id = app_id.0,
                "ticket: loaded encrypted ticket from disk"
            );
            self.enc_tickets.lock().unwrap_or_else(|e| e.into_inner()).insert(app_id, t.clone());
            return Some(t);
        }
        None
    }

    /// Cache a ticket. `persist` = true writes to disk (for delegate tickets
    /// that must survive across account sessions).
    pub fn store_app_ticket(&self, app_id: AppId, data: Vec<u8>, persist: bool) {
        info!(
            app_id = app_id.0,
            size = data.len(),
            persist,
            "ticket: caching app ticket"
        );
        if persist {
            self.save_to_disk(app_id, "ticket", &data);
        }
        self.app_tickets.lock().unwrap_or_else(|e| e.into_inner()).insert(app_id, data);
    }

    /// Cache an encrypted ticket. `persist` = true writes to disk.
    pub fn store_enc_ticket(&self, app_id: AppId, data: Vec<u8>, persist: bool) {
        info!(
            app_id = app_id.0,
            size = data.len(),
            persist,
            "ticket: caching encrypted ticket"
        );
        if persist {
            self.save_to_disk(app_id, "enc_ticket", &data);
        }
        self.enc_tickets.lock().unwrap_or_else(|e| e.into_inner()).insert(app_id, data);
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

// ---------------------------------------------------------------------------
// Delegate mode: serve a cached ticket (from a previous owner session) during
// an initial request window, then switch to derived mode.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Auto-delegate: runtime-detected Denuvo apps
// ---------------------------------------------------------------------------

use std::collections::HashSet;

static AUTO_DELEGATE_APPS: Mutex<Option<HashSet<AppId>>> = Mutex::new(None);

/// Mark an app as auto-detected Denuvo. Subsequent `is_auto_delegate`
/// checks will return true for this app. Does not modify config.
pub fn add_auto_delegate(app_id: AppId) {
    let mut guard = AUTO_DELEGATE_APPS.lock().unwrap_or_else(|e| e.into_inner());
    guard.get_or_insert_with(HashSet::new).insert(app_id);
}

/// Check if an app was auto-detected as Denuvo at runtime.
pub fn is_auto_delegate(app_id: AppId) -> bool {
    AUTO_DELEGATE_APPS
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|s| s.contains(&app_id))
}

/// Clear auto-delegate for an app (e.g. on game exit).
pub fn remove_auto_delegate(app_id: AppId) {
    if let Some(set) = AUTO_DELEGATE_APPS.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        set.remove(&app_id);
    }
}

// ---------------------------------------------------------------------------
// Delegate window
// ---------------------------------------------------------------------------

/// Number of ticket requests per app that get served from cache before we
/// switch over to forging with the current user's SteamID.
const DELEGATE_WINDOW_SIZE: u32 = 2;

/// Per-AppId count of ticket requests seen so far in delegate mode.
static DELEGATE_COUNTS: Mutex<Option<HashMap<AppId, u32>>> = Mutex::new(None);

/// SteamID to return from GetSteamID while a delegate window is active.
/// Zero means no delegate window is active.
static DELEGATE_STEAMID: AtomicU64 = AtomicU64::new(0);

/// Check if we're still in the delegate window for this app.
///
/// Each call counts as one request. Returns true (serve cached ticket) for
/// the first `DELEGATE_WINDOW_SIZE` calls, then false afterwards.
pub fn in_delegate_window(app_id: AppId) -> bool {
    let mut guard = DELEGATE_COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    let counts = guard.get_or_insert_with(HashMap::new);
    let count = counts.entry(app_id).or_insert(0);
    *count += 1;
    let in_window = *count <= DELEGATE_WINDOW_SIZE;
    if !in_window {
        // Window just closed (or already closed): stop overriding GetSteamID.
        clear_delegate_steamid();
    }
    in_window
}

/// Reset the delegate window for an app. Called when the game exits
/// (observed via CMsgClientGamesPlayed no longer listing the app), so a
/// future relaunch gets a fresh delegate window.
pub fn reset_delegate_window(app_id: AppId) {
    if let Some(counts) = DELEGATE_COUNTS.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        counts.remove(&app_id);
    }
    clear_delegate_steamid();
}

/// Set the SteamID to return from GetSteamID while a delegate window is active.
pub fn set_delegate_steamid(steamid: u64) {
    DELEGATE_STEAMID.store(steamid, Ordering::Release);
}

/// Get the delegate SteamID (0 = no delegate active).
pub fn delegate_steamid() -> u64 {
    DELEGATE_STEAMID.load(Ordering::Acquire)
}

/// Clear the delegate SteamID (called when the window closes or the game exits).
pub fn clear_delegate_steamid() {
    DELEGATE_STEAMID.store(0, Ordering::Release);
}

/// Ticket forging: create a ticket for a target app from a source ticket (appId 7).
pub mod forge {
    /// The source app whose ticket we clone from.
    pub const SOURCE_APP_ID: u32 = 7;

    /// Offset of the SteamID within a standard ownership ticket.
    const TICKET_STEAMID_OFFSET: usize = 8;

    /// Size of the RSA signature at the end of a ticket.
    const SIGNATURE_SIZE: usize = 128;

    /// A ticket derived from a source ticket for a different appId.
    pub struct ForgedTicket {
        /// The complete derived ticket data.
        pub data: Vec<u8>,
        /// Total ticket size (the data.len() value Steam should see).
        pub total_size: u32,
        /// Byte offset of the appId field within the derived ticket.
        pub app_id_offset: u32,
        /// Byte offset of the SteamID field within the derived ticket.
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
    /// The target appId is inserted between the signed body and the signature.
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
        let cache = TicketCache::new(None);
        let ticket = vec![0xDE, 0xAD, 0xBE, 0xEF];
        cache.store_app_ticket(AppId(480), ticket.clone(), false);

        let empty_lua: HashMap<AppId, Vec<u8>> = HashMap::new();
        assert_eq!(cache.get_app_ticket(AppId(480), &empty_lua), Some(ticket));
        assert_eq!(cache.get_app_ticket(AppId(730), &empty_lua), None);
    }

    #[test]
    fn lua_tickets_take_priority() {
        let cache = TicketCache::new(None);
        cache.store_app_ticket(AppId(480), vec![0x01, 0x02], false);

        let mut lua: HashMap<AppId, Vec<u8>> = HashMap::new();
        lua.insert(AppId(480), vec![0xAA, 0xBB]);

        assert_eq!(
            cache.get_app_ticket(AppId(480), &lua),
            Some(vec![0xAA, 0xBB])
        );
    }

    #[test]
    fn persist_true_writes_to_disk() {
        let dir = std::env::temp_dir().join(format!("ticket-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = TicketCache::new(Some(dir.clone()));

        let ticket = vec![0x11, 0x22, 0x33, 0x44];
        cache.store_app_ticket(AppId(999), ticket.clone(), true);

        // Fresh cache (simulates restart) reads from disk
        let cache2 = TicketCache::new(Some(dir.clone()));
        let empty_lua: HashMap<AppId, Vec<u8>> = HashMap::new();
        assert_eq!(cache2.get_app_ticket(AppId(999), &empty_lua), Some(ticket));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_false_does_not_touch_disk() {
        let dir = std::env::temp_dir().join(format!("ticket-nodisk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = TicketCache::new(Some(dir.clone()));

        cache.store_app_ticket(AppId(480), vec![0xFF], false);

        assert!(!dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forge_from_source_produces_valid_ticket() {
        // Create a test source ticket: 200 bytes of body + 128 bytes of signature
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
        // Ticket smaller than signature size, cannot derive.
        let source = vec![0u8; 64];
        assert!(forge::forge_from_source(&source, 480).is_none());
    }

    #[test]
    fn enc_ticket_cache_works() {
        let cache = TicketCache::new(None);
        let ticket = vec![0xCA, 0xFE];
        cache.store_enc_ticket(AppId(480), ticket.clone(), false);

        let empty_lua: HashMap<AppId, Vec<u8>> = HashMap::new();
        assert_eq!(cache.get_enc_ticket(AppId(480), &empty_lua), Some(ticket));
        assert_eq!(cache.get_enc_ticket(AppId(730), &empty_lua), None);
    }

    // Delegate window tests use distinct AppIds per test since the state is
    // global (mirrors the real single-process usage) and tests run in parallel.

    #[test]
    fn delegate_window_allows_first_n_requests_then_forges() {
        let app = AppId(100_001);
        // First DELEGATE_WINDOW_SIZE (2) requests: still in window.
        assert!(in_delegate_window(app));
        assert!(in_delegate_window(app));
        // Third request: window closed.
        assert!(!in_delegate_window(app));
        assert!(!in_delegate_window(app));
    }

    #[test]
    fn delegate_window_is_independent_per_app() {
        let app_a = AppId(100_002);
        let app_b = AppId(100_003);

        assert!(in_delegate_window(app_a));
        // app_b's window is unaffected by app_a's count.
        assert!(in_delegate_window(app_b));
        assert!(in_delegate_window(app_a));
        assert!(in_delegate_window(app_b));
        // Both windows close after their own 2 requests.
        assert!(!in_delegate_window(app_a));
        assert!(!in_delegate_window(app_b));
    }

    #[test]
    fn reset_delegate_window_restarts_the_count() {
        let app = AppId(100_004);
        assert!(in_delegate_window(app));
        assert!(in_delegate_window(app));
        assert!(!in_delegate_window(app));

        reset_delegate_window(app);

        // Window reopened: first two requests are back in-window.
        assert!(in_delegate_window(app));
        assert!(in_delegate_window(app));
        assert!(!in_delegate_window(app));
    }

    #[test]
    fn delegate_steamid_set_get_clear() {
        set_delegate_steamid(76561198000000001);
        assert_eq!(delegate_steamid(), 76561198000000001);
        clear_delegate_steamid();
        assert_eq!(delegate_steamid(), 0);
    }

    #[test]
    fn delegate_window_closing_clears_steamid() {
        let app = AppId(100_005);
        // Exhaust the window first (may already be partially consumed by parallel tests).
        reset_delegate_window(app);
        assert!(in_delegate_window(app));
        assert!(in_delegate_window(app));
        // Set the steamid right before the 3rd call that will close the window.
        set_delegate_steamid(76561198000000002);
        assert!(!in_delegate_window(app));
        // The 3rd call exceeded the window and should have cleared the steamid.
        assert_eq!(delegate_steamid(), 0);
    }
}
