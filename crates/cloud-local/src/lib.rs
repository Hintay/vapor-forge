#![forbid(unsafe_code)]

mod store;
mod transfer;

pub use store::{FolderStore, StagedFile, StoreView};
pub use transfer::{
    commit_upload, intercept_transfer, issue_download, issue_upload, LocalTransferOutcome,
    LOCAL_TRANSFER_AUTHORITY,
};
