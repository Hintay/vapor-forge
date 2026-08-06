//! Steam packet interception split into a safe router and raw packet boundary.

mod boundary;
mod router;
mod stats_proxy;

pub(crate) use boundary::{
    drain_local, prepare_recv_packet, queue_playtime_notification, wake_source,
    PreparedRecvDecision,
};
pub(crate) use router::{
    cancel_client_id_capture, complete_client_id_capture, decide_send_frame, SendFrameDecision,
};
pub(crate) use stats_proxy::notify_context_changed as notify_stats_context_changed;

pub(crate) fn cloud_rpc_queue() -> Option<&'static vapor_forge_cloud_rpc::CloudRpcQueue> {
    router::cloud_rpc_queue()
}
