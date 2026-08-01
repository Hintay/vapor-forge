#![forbid(unsafe_code)]

mod handle;
mod model;
mod paths;
mod record;
mod retry;
mod store;

pub use handle::shared;
pub use model::{new_conflict_event_id, ConflictResolutionEvent, SyncJournalError};
pub use paths::default_sync_journal_path;
pub use store::{values, Journaled, Queued, SyncJournal};
#[cfg(test)]
mod tests;
