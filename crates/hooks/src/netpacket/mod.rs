//! Steam packet interception split into a safe router and raw packet boundary.

mod boundary;
mod router;

pub(crate) use boundary::{drain_local, prepare_recv_packet, wake_source};
pub(crate) use router::{decide_send_frame, is_cloud_transfer_target, SendFrameDecision};
