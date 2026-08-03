//! Cumulus as a [`CloudBackend`] implementation.
//!
//! The free functions in this crate stay the transport layer; this module owns
//! the settings and maps Cumulus errors onto the neutral port types.

use std::collections::BTreeSet;

use vapor_forge_cloud_core::{
    credential_fingerprint, endpoint_scope, AccountPlaytimeSnapshot, AccountStatsWakeup,
    AccountSyncState, AchievementSchema, AppStatsQuery, AppStatsResult, BackendError, CloudBackend,
    DeviceDescriptor, PlaytimeEntry, PlaytimeSession, SchemaUploadOutcome, SteamAppSnapshot,
    SteamStateUploadResult, StreamCancellation, StreamOutcome, UploadIdentity,
};

use crate::{
    achievement, ensure_device_bound, playtime, CumulusClient, CumulusError, CumulusSettings,
};

/// A Cumulus endpoint plus the credentials used to reach it.
pub struct CumulusBackend {
    settings: CumulusSettings,
}

impl CumulusBackend {
    pub fn new(settings: CumulusSettings) -> Self {
        Self { settings }
    }

    /// The underlying settings, for the Cloud RPC proxy which speaks Cumulus
    /// HTTP directly rather than through the port.
    pub fn settings(&self) -> &CumulusSettings {
        &self.settings
    }
}

impl From<CumulusError> for BackendError {
    fn from(error: CumulusError) -> Self {
        let retryable = error.is_retryable();
        BackendError::new(error.to_string(), retryable)
    }
}

impl CloudBackend for CumulusBackend {
    fn endpoint_scope(&self) -> String {
        endpoint_scope(&self.settings.server_url)
    }

    fn principal_scope(&self) -> Result<String, BackendError> {
        crate::principal_scope(&self.settings).map_err(BackendError::from)
    }

    fn credential_fingerprint(&self) -> String {
        credential_fingerprint(&self.settings.server_url, &self.settings.token)
    }

    fn ensure_device_bound(&self, descriptor: &DeviceDescriptor) -> Result<(), BackendError> {
        ensure_device_bound(&self.settings, descriptor).map_err(BackendError::from)
    }

    fn accepts_achievement_schemas(&self) -> bool {
        true
    }

    fn upload_achievement_schema(
        &self,
        schema: &AchievementSchema,
    ) -> Result<SchemaUploadOutcome, BackendError> {
        achievement::upload_schema(&self.settings, schema)
            .map(|outcome| match outcome {
                achievement::SchemaUploadOutcome::Uploaded => SchemaUploadOutcome::Accepted,
                achievement::SchemaUploadOutcome::Disabled => SchemaUploadOutcome::Declined,
            })
            .map_err(BackendError::from)
    }

    fn upload_playtime(
        &self,
        client_id: u64,
        steam_id64: &str,
        entries: &[PlaytimeEntry],
    ) -> Result<(), BackendError> {
        playtime::upload(&self.settings, client_id, steam_id64, entries).map_err(BackendError::from)
    }

    fn accepts_playtime_sessions(&self) -> bool {
        true
    }

    fn upload_playtime_sessions(
        &self,
        client_id: u64,
        steam_id64: &str,
        sessions: &[PlaytimeSession],
    ) -> Result<(), BackendError> {
        playtime::upload_sessions(&self.settings, client_id, steam_id64, sessions)
            .map_err(BackendError::from)
    }

    fn upload_steam_app_snapshot(
        &self,
        identity: &UploadIdentity,
        snapshot: &SteamAppSnapshot,
    ) -> Result<SteamStateUploadResult, BackendError> {
        achievement::upload_snapshot(&self.settings, identity, snapshot).map_err(BackendError::from)
    }

    fn pull_account_state(
        &self,
        client_id: u64,
        steam_id64: &str,
    ) -> Result<AccountSyncState, BackendError> {
        if !steam_id64
            .parse::<u64>()
            .is_ok_and(|steam_id| steam_id != 0)
        {
            return Err(BackendError::new("invalid Steam account ID", false));
        }
        CumulusClient::new(&self.settings, Some(client_id))
            .get_json(&format!(
                "/api/v1/device/sync-state?steam_id64={steam_id64}"
            ))
            .map_err(BackendError::from)
    }

    fn pull_app_stats(
        &self,
        client_id: u64,
        steam_id64: &str,
        query: &AppStatsQuery,
    ) -> Result<AppStatsResult, BackendError> {
        achievement::pull_app_stats(&self.settings, client_id, steam_id64, query)
            .map_err(BackendError::from)
    }

    fn stream_playtime(
        &self,
        client_id: u64,
        steam_id64: &str,
        cancellation: &StreamCancellation,
        on_snapshot: &mut dyn FnMut(AccountPlaytimeSnapshot),
    ) -> Result<StreamOutcome, BackendError> {
        let mut on_connected = || {
            self.pull_account_state(client_id, steam_id64)
                .map(|state| Some(playtime_snapshot(steam_id64, state)))
        };
        crate::device_stream::run(
            &self.settings,
            client_id,
            steam_id64,
            crate::device_stream::StreamSpec {
                route: "/api/v1/device/playtime-events",
                event_name: "playtime_snapshot",
                stream_name: "playtime",
            },
            cancellation,
            &mut on_connected,
            on_snapshot,
        )
    }

    fn stream_stats_wakeup(
        &self,
        client_id: u64,
        steam_id64: &str,
        cancellation: &StreamCancellation,
        on_wakeup: &mut dyn FnMut(AccountStatsWakeup),
    ) -> Result<StreamOutcome, BackendError> {
        let mut on_connected = || {
            self.pull_account_state(client_id, steam_id64)
                .map(|state| stats_wakeup(steam_id64, state))
        };
        crate::device_stream::run(
            &self.settings,
            client_id,
            steam_id64,
            crate::device_stream::StreamSpec {
                route: "/api/v1/device/stats-events",
                event_name: "stats_wakeup",
                stream_name: "stats",
            },
            cancellation,
            &mut on_connected,
            on_wakeup,
        )
    }
}

fn playtime_snapshot(steam_id64: &str, state: AccountSyncState) -> AccountPlaytimeSnapshot {
    AccountPlaytimeSnapshot {
        steam_id64: steam_id64.to_owned(),
        playtime_revision: state.playtime_revision,
        origin_client_id: None,
        playtime: state.playtime,
    }
}

fn stats_wakeup(steam_id64: &str, state: AccountSyncState) -> Option<AccountStatsWakeup> {
    let mut app_ids = BTreeSet::new();
    app_ids.extend(
        state
            .stats_crcs
            .into_iter()
            .map(|state| state.app_id)
            .filter(|app_id| *app_id != 0),
    );
    app_ids.extend(
        state
            .achievements
            .into_iter()
            .map(|state| state.app_id)
            .filter(|app_id| *app_id != 0),
    );
    app_ids.extend(
        state
            .stats
            .into_iter()
            .map(|state| state.app_id)
            .filter(|app_id| *app_id != 0),
    );
    if app_ids.is_empty() {
        return None;
    }
    Some(AccountStatsWakeup {
        steam_id64: steam_id64.to_owned(),
        origin_client_id: None,
        app_ids: app_ids.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_response_server(body: &'static str) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            sender.send(String::from_utf8(request).unwrap()).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        (format!("http://{address}"), receiver)
    }

    fn settings(server_url: &str, token: &str) -> CumulusSettings {
        CumulusSettings {
            server_url: server_url.into(),
            token: token.into(),
            timeout_connect_ms: 1_000,
            timeout_ms: 1_000,
        }
    }

    #[test]
    fn credential_fingerprint_tracks_endpoint_and_token() {
        let backend = CumulusBackend::new(settings("https://cloud.test/api", "token"));
        assert_eq!(
            backend.credential_fingerprint(),
            CumulusBackend::new(settings("https://cloud.test/api/", "token"))
                .credential_fingerprint(),
        );
        assert_ne!(
            backend.credential_fingerprint(),
            CumulusBackend::new(settings("https://cloud.test/api", "other"))
                .credential_fingerprint(),
        );
    }

    #[test]
    fn principal_scope_comes_from_backend_principal_not_token() {
        let (server_url, request) = one_response_server(r#"{"principal_id":"user:42"}"#);
        let backend = CumulusBackend::new(settings(&server_url, "token-a"));
        assert_eq!(
            backend.principal_scope().unwrap(),
            vapor_forge_cloud_core::principal_scope(&server_url, "user:42")
        );

        let request = request
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(request.starts_with("GET /api/v1/device/principal HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer token-a"));
    }

    #[test]
    fn cumulus_errors_keep_their_retry_classification() {
        let retryable: BackendError = CumulusError::HttpStatus(503).into();
        assert!(retryable.is_retryable());

        let permanent: BackendError = CumulusError::HttpStatus(400).into();
        assert!(!permanent.is_retryable());
    }

    #[test]
    fn reconnect_stats_baseline_is_deduplicated_and_sorted() {
        let state = serde_json::from_str::<AccountSyncState>(
            r#"{"stats_crcs":[{"app_id":620,"crc_stats":1}],"playtime_revision":0,"achievements":[{"app_id":480,"achievement_key":"ACH_WIN","unlocked":true,"progress_current":null,"progress_max":null,"observed_at":20,"unlocked_at":10}],"stats":[{"app_id":620,"stat_key":"STAT_SCORE","value_type":"int","value":"3","observed_at":20}],"playtime":[]}"#,
        )
        .unwrap();

        assert_eq!(
            stats_wakeup("76561198000000001", state).unwrap().app_ids,
            vec![480, 620]
        );
    }

    #[test]
    fn pulls_converged_account_state_with_device_identity() {
        let (server_url, request) = one_response_server(
            r#"{"stats_crcs":[{"app_id":480,"crc_stats":305419896}],"playtime_revision":7,"achievements":[{"app_id":480,"achievement_key":"ACH_WIN","unlocked":true,"progress_current":null,"progress_max":null,"observed_at":20,"unlocked_at":10}],"stats":[{"app_id":480,"stat_key":"STAT_SCORE","value_type":"int","value":"3","observed_at":20}],"playtime":[{"app_id":480,"playtime_minutes":30,"playtime_2weeks_minutes":4,"last_played_at":100,"observed_at":20}]}"#,
        );
        let backend = CumulusBackend::new(settings(&server_url, "pull-token"));
        let state = backend.pull_account_state(7, "76561198000000001").unwrap();
        assert!(state.achievements[0].unlocked);
        assert_eq!(state.stats[0].stat_key, "STAT_SCORE");
        assert_eq!(state.playtime[0].playtime_minutes, 30);
        assert_eq!(state.playtime_revision, 7);
        assert_eq!(state.stats_crcs[0].crc_stats, 305419896);

        let request = request
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(request
            .starts_with("GET /api/v1/device/sync-state?steam_id64=76561198000000001 HTTP/1.1"));
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer pull-token"));
        assert!(lower.contains("x-cumulus-steam-client-id: 7"));
    }
}
