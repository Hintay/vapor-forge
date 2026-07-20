//! Translation between Steam client's `Cloud.*#1` service RPCs and Cumulus.

mod adapter;
mod http;
mod protocol;
mod queue;
mod transfer_targets;

pub use protocol::{privacy_fallback, privacy_fallback_with_ownership};
pub use queue::CloudRpcQueue;

pub const GET_CHANGELIST: &str = "Cloud.GetAppFileChangelist#1";
pub const BEGIN_HTTP_UPLOAD: &str = "Cloud.BeginHTTPUpload#1";
pub const COMMIT_HTTP_UPLOAD: &str = "Cloud.CommitHTTPUpload#1";
pub const BEGIN_UGC_UPLOAD: &str = "Cloud.BeginUGCUpload#1";
pub const COMMIT_UGC_UPLOAD: &str = "Cloud.CommitUGCUpload#1";
pub const GET_FILE_DETAILS: &str = "Cloud.GetFileDetails#1";
pub const GET_SINGLE_FILE_INFO: &str = "Cloud.GetSingleFileInfo#1";
pub const SHARE_FILE: &str = "Cloud.ShareFile#1";
pub const ENUMERATE_USER_FILES: &str = "Cloud.EnumerateUserFiles#1";
pub const LEGACY_DELETE: &str = "Cloud.Delete#1";
pub const BEGIN_BATCH: &str = "Cloud.BeginAppUploadBatch#1";
pub const BEGIN_FILE_UPLOAD: &str = "Cloud.ClientBeginFileUpload#1";
pub const COMMIT_FILE_UPLOAD: &str = "Cloud.ClientCommitFileUpload#1";
pub const COMPLETE_BATCH: &str = "Cloud.CompleteAppUploadBatch#1";
pub const COMPLETE_BATCH_BLOCKING: &str = "Cloud.CompleteAppUploadBatchBlocking#1";
pub const FILE_DOWNLOAD: &str = "Cloud.ClientFileDownload#1";
pub const DELETE_FILE: &str = "Cloud.ClientDeleteFile#1";
pub const QUOTA_USAGE: &str = "Cloud.ClientGetAppQuotaUsage#1";
pub const LAUNCH_INTENT: &str = "Cloud.SignalAppLaunchIntent#1";
pub const SUSPEND_SESSION: &str = "Cloud.SuspendAppSession#1";
pub const RESUME_SESSION: &str = "Cloud.ResumeAppSession#1";
pub const EXIT_SYNC_DONE: &str = "Cloud.SignalAppExitSyncDone#1";
pub const CONFLICT_RESOLUTION: &str = "Cloud.ClientConflictResolution#1";
pub const CDN_REPORT: &str = "Cloud.CDNReport#1";
pub const EXTERNAL_TRANSFER_REPORT: &str = "Cloud.ExternalStorageTransferReport#1";

const ERESULT_OK: i32 = 1;
const ERESULT_FAIL: i32 = 2;
const ERESULT_TOO_MANY_PENDING: i32 = 108;
const HTTP_METHOD_PUT: i32 = 4;
const RPC_WORKER_SHARDS: usize = 4;
const RPC_QUEUE_CAPACITY: usize = 64;
const RPC_CHANNEL_CAPACITY: usize = RPC_QUEUE_CAPACITY * 2;

#[cfg(test)]
mod tests;
