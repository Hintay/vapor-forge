#![forbid(unsafe_code)]

mod backend;
mod device;
mod files;
mod sync;

use sha2::{Digest, Sha256};

pub use backend::{BackendError, CloudBackend, SchemaUploadOutcome, StreamOutcome};
pub use device::{
    device_descriptor, record_device_descriptor, record_local_client_id, restore_device_descriptor,
    DeviceDescriptor,
};
pub use files::{
    ByteStore, ChangeList, CloudFileStore, DirectTransfer, FileEntry, FileMetadata, HttpHeader,
    HttpTarget, Quota, Transfer, UploadBlock,
};
pub use sync::{
    AccountSyncState, AchievementEvent, AchievementSchema, AchievementSyncState, PlaytimeEntry,
    UploadIdentity,
};

const SCOPE_DOMAIN: &[u8] = b"vapor-forge/scope/v1";

pub fn endpoint_scope(server_url: &str) -> String {
    scope_digest(b"endpoint", &[normalized_server_url(server_url).as_bytes()])
}

pub fn credential_scope(server_url: &str, token: &str) -> String {
    scope_digest(
        b"credential",
        &[
            normalized_server_url(server_url).as_bytes(),
            token.trim().as_bytes(),
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

        let credential = credential_scope("https://cloud.example.test/api", "token");
        assert_ne!(endpoint, credential);
        assert_ne!(
            credential,
            credential_scope("https://cloud.example.test/api", "other-token")
        );
    }
}
