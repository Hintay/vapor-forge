//! Steam packet interception split into a safe router and raw packet boundary.

mod boundary;
mod router;

pub(crate) use boundary::{on_recv_packet, try_inject};
pub(crate) use router::{decide_send_frame, is_cloud_transfer_target, SendFrameDecision};
