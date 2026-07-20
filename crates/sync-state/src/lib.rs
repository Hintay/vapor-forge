#![forbid(unsafe_code)]

mod achievement;
mod conflict;
mod db;
mod device;
mod model;
mod outbox;
pub mod playtime;
mod retry;
mod schema;
mod scope;

pub use model::{
    achievement_clear_event_id, achievement_unlock_event_id, new_achievement_event_id,
    new_conflict_event_id, OutboxError, QueuedConflictResolution,
};
pub use outbox::Outbox;
pub use scope::default_outbox_path;
pub use vapor_forge_cloud_core::{credential_scope, endpoint_scope};
pub use vapor_forge_cloud_core::{
    device_descriptor, record_device_descriptor, record_local_client_id, restore_device_descriptor,
    DeviceDescriptor,
};
pub use vapor_forge_cloud_core::{
    AchievementEvent as QueuedAchievementEvent, AchievementSchema as QueuedAchievementSchema,
    UploadIdentity,
};
#[cfg(test)]
mod tests;
