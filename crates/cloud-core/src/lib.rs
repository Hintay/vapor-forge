#![forbid(unsafe_code)]

mod backend;
mod device;
mod files;
mod sync;

use sha2::{Digest, Sha256};

pub use backend::{
    BackendError, CloudBackend, SchemaUploadOutcome, StreamCancellation, StreamOutcome,
};
pub use device::{
    device_descriptor, record_device_descriptor, record_local_client_id, restore_device_descriptor,
    DeviceDescriptor,
};
pub use files::{
    ByteStore, ChangeList, CloudFileStore, DirectTransfer, FileEntry, FileMetadata, HttpHeader,
    HttpTarget, Quota, Transfer, UploadBlock,
};
pub use sync::{
    AccountPlaytimeSnapshot, AccountStatsWakeup, AccountSyncState, AchievementSchema,
    AchievementSyncState, AppStatsCrc, AppStatsQuery, AppStatsResult, AppStatsUploadResult,
    AppStatsUploadStatus, OfficialAchievementState, OfficialStatState, PlaytimeEntry,
    PlaytimeSession, StatSyncState, StatsCommit, SteamAppSnapshot, SteamStateUploadResult,
    UploadIdentity,
};

/// Stable identity for a Steam-authored playtime session.
pub fn playtime_session_id(
    steam_id64: &str,
    app_id: u32,
    started_at: u32,
    seconds: u32,
    offline: bool,
    owner_account_id: u32,
) -> String {
    let identity = format!(
        "{steam_id64}\0{app_id}\0{started_at}\0{seconds}\0{}\0{owner_account_id}",
        u8::from(offline)
    );
    scope_digest(b"playtime-session", &[identity.as_bytes()])
}

pub fn stats_commit_id(steam_id64: &str, app_id: u32, request: &[u8]) -> String {
    let request_digest = Sha256::digest(request);
    scope_digest(
        b"stats-commit",
        &[
            steam_id64.as_bytes(),
            &app_id.to_be_bytes(),
            &request_digest,
        ],
    )
}

const SCOPE_DOMAIN: &[u8] = b"vapor-forge/scope/v1";

pub fn endpoint_scope(server_url: &str) -> String {
    scope_digest(b"endpoint", &[normalized_server_url(server_url).as_bytes()])
}

pub fn credential_fingerprint(server_url: &str, token: &str) -> String {
    scope_digest(
        b"credential",
        &[
            normalized_server_url(server_url).as_bytes(),
            token.trim().as_bytes(),
        ],
    )
}

pub fn principal_scope(server_url: &str, principal_id: &str) -> String {
    scope_digest(
        b"principal",
        &[
            normalized_server_url(server_url).as_bytes(),
            principal_id.trim().as_bytes(),
        ],
    )
}

fn normalized_server_url(server_url: &str) -> &str {
    server_url.trim().trim_end_matches('/')
}

fn scope_digest(kind: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, SCOPE_DOMAIN);
    update_field(&mut hasher, kind);
    for field in fields {
        update_field(&mut hasher, field);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn update_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_normalized_domain_separated_sha256_values() {
        let endpoint = endpoint_scope(" https://cloud.example.test/api/ ");
        assert_eq!(endpoint, endpoint_scope("https://cloud.example.test/api"));
        assert_eq!(endpoint.len(), 64);
        assert!(endpoint.bytes().all(|byte| byte.is_ascii_hexdigit()));

        let credential = credential_fingerprint("https://cloud.example.test/api", "token");
        let principal = principal_scope("https://cloud.example.test/api", "user:1");
        assert_ne!(endpoint, credential);
        assert_ne!(credential, principal);
        assert_ne!(
            credential,
            credential_fingerprint("https://cloud.example.test/api", "other-token")
        );
        assert_eq!(
            principal,
            principal_scope("https://cloud.example.test/api/", "user:1")
        );
        assert_ne!(
            principal,
            principal_scope("https://cloud.example.test/api", "user:2")
        );
    }
}
