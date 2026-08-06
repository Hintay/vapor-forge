#![forbid(unsafe_code)]

mod gc;
mod store;
mod sync;
mod syncthing;
mod transfer;

pub use gc::LocalGcCoordinator;
pub use store::{
    CommitIdentity, FolderStore, GcReport, ManifestCandidate, SaveOperation, SessionPeer,
    StagedFile, StoreView,
};
pub use sync::LocalBackend;
pub use syncthing::SyncthingGcConfig;
pub use transfer::{
    commit_upload, intercept_transfer, issue_download, issue_upload, transfer_contract,
    LocalTransferContract, LocalTransferOutcome, LOCAL_TRANSFER_AUTHORITY,
};
