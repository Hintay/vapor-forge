use super::adapter::{execute_rpc, AdapterState};
use super::conflict_ui::{
    ConflictDialog, ConflictSubmitResult, ConflictUiAck, ConflictUiContext,
    LocalConflictCoordinator,
};
use super::http::{AdapterError, CloudSettings};
use super::protocol::{
    build_failure_response_packet, build_response_packet, intercepted_request_app_id,
    is_backend_transfer_report, method_expects_response, RpcReply,
};
use super::transfer_targets::TransferTargetRegistry;
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use tracing::warn;
use vapor_forge_config::RuntimeConfig;
use vapor_forge_steam_protocol::*;

struct PendingResponse {
    receiver: mpsc::Receiver<Vec<u8>>,
    fallback: Vec<u8>,
    response_generation: u64,
    reservation: ResponsePermit,
}

/// A completed response together with the capacity permit that remains live
/// until the native injection path dispatches or rejects it as stale.
pub struct CompletedResponse {
    pub packet: Vec<u8>,
    pub response_generation: u64,
    permit: ResponsePermit,
}

impl CompletedResponse {
    pub fn into_parts(self) -> (Vec<u8>, u64, ResponsePermit) {
        (self.packet, self.response_generation, self.permit)
    }
}

pub(super) struct QueuedResponse {
    pub(super) sender: mpsc::Sender<Vec<u8>>,
    pub(super) request_header: CMsgProtoBufHeader,
}

pub(super) struct QueuedRequest {
    pub(super) app_id: u32,
    pub(super) method: String,
    pub(super) body: Vec<u8>,
    pub(super) settings: CloudSettings,
    pub(super) response: Option<QueuedResponse>,
    pub(super) context_epoch: u64,
}

fn complete_request(request: QueuedRequest, result: Result<RpcReply, AdapterError>) {
    if let Some(response) = request.response {
        let packet = build_response_packet(&response.request_header, result);
        let _ = response.sender.send(packet);
        vapor_forge_features::inject_wake::wake(
            vapor_forge_features::inject_wake::InjectionSource::Cloud,
        );
    } else if let Err(error) = result {
        warn!(
            app_id = request.app_id,
            method = request.method,
            %error,
            "cloud-rpc: notification failed"
        );
    }
}

pub(super) struct RpcWorker {
    pub(super) sender: mpsc::SyncSender<QueuedRequest>,
    pub(super) outstanding_responses: Arc<AtomicUsize>,
}

impl RpcWorker {
    pub(super) fn try_reserve_response(&self) -> Option<ResponsePermit> {
        self.outstanding_responses
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                (queued < RPC_QUEUE_CAPACITY).then_some(queued + 1)
            })
            .ok()?;
        Some(ResponsePermit {
            outstanding: Arc::clone(&self.outstanding_responses),
        })
    }
}

pub struct ResponsePermit {
    pub(super) outstanding: Arc<AtomicUsize>,
}

impl Drop for ResponsePermit {
    fn drop(&mut self) {
        self.outstanding.fetch_sub(1, Ordering::AcqRel);
    }
}
/// Thread-safe queue used by the network hook. HTTP never runs on Steam's
/// websocket thread; each completion wakes its native injection source.
pub struct CloudRpcQueue {
    pending: Mutex<Vec<PendingResponse>>,
    worker: RpcWorker,
    report_worker: mpsc::SyncSender<QueuedRequest>,
    pub(super) transfer_targets: Arc<TransferTargetRegistry>,
    local_gc: Arc<vapor_forge_cloud_local::LocalGcCoordinator>,
    local_conflicts: Arc<LocalConflictCoordinator>,
    context_epoch: Arc<std::sync::atomic::AtomicU64>,
}

impl CloudRpcQueue {
    pub fn try_new() -> std::io::Result<Self> {
        let transfer_targets = Arc::new(TransferTargetRegistry::default());
        let local_gc = Arc::new(vapor_forge_cloud_local::LocalGcCoordinator::try_new()?);
        let local_conflicts = LocalConflictCoordinator::try_new(Arc::clone(&local_gc))?;
        let context_epoch = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let outstanding_responses = Arc::new(AtomicUsize::new(0));
        let worker_transfer_targets = Arc::clone(&transfer_targets);
        let worker_local_gc = Arc::clone(&local_gc);
        let worker_local_conflicts = Arc::clone(&local_conflicts);
        let (worker_sender, worker_receiver) =
            mpsc::sync_channel::<QueuedRequest>(RPC_CHANNEL_CAPACITY);
        let worker_context_epoch = Arc::clone(&context_epoch);
        std::thread::Builder::new()
            .name("vapor-cloud-rpc".into())
            .spawn(move || {
                let mut state = AdapterState::with_transfer_targets_gc_and_conflicts(
                    worker_transfer_targets,
                    worker_local_gc,
                    worker_local_conflicts,
                );
                while let Ok(request) = worker_receiver.recv() {
                    if request.context_epoch != worker_context_epoch.load(Ordering::Acquire) {
                        complete_request(
                            request,
                            Err(AdapterError::Protocol(
                                "cloud request context changed before completion".into(),
                            )),
                        );
                        continue;
                    }
                    let result = execute_rpc(
                        &mut state,
                        &request.settings,
                        &request.method,
                        &request.body,
                    );
                    complete_request(request, result);
                }
            })?;
        let worker = RpcWorker {
            sender: worker_sender,
            outstanding_responses,
        };
        let report_transfer_targets = Arc::clone(&transfer_targets);
        let report_local_gc = Arc::clone(&local_gc);
        let report_local_conflicts = Arc::clone(&local_conflicts);
        let (report_worker, report_receiver) = mpsc::sync_channel::<QueuedRequest>(128);
        std::thread::Builder::new()
            .name("vapor-cloud-report".into())
            .spawn(move || {
                let mut state = AdapterState::with_transfer_targets_gc_and_conflicts(
                    report_transfer_targets,
                    report_local_gc,
                    report_local_conflicts,
                );
                while let Ok(request) = report_receiver.recv() {
                    if let Err(error) = execute_rpc(
                        &mut state,
                        &request.settings,
                        &request.method,
                        &request.body,
                    ) {
                        warn!(
                            method = request.method,
                            %error,
                            "cloud-rpc: transfer report failed"
                        );
                    }
                }
            })?;
        Ok(Self {
            pending: Mutex::new(Vec::new()),
            worker,
            report_worker,
            transfer_targets,
            local_gc,
            local_conflicts,
            context_epoch,
        })
    }

    pub fn set_conflict_ui_ready(&self, ready: bool) {
        self.local_conflicts.set_ui_ready(ready);
    }

    pub fn conflict_dialogs(&self, context: ConflictUiContext) -> Vec<ConflictDialog> {
        self.local_conflicts.dialogs(context)
    }

    pub fn submit_conflict_choice(
        &self,
        token: &str,
        context: ConflictUiContext,
    ) -> ConflictSubmitResult {
        self.local_conflicts.submit(token, context)
    }

    pub fn conflict_ack_deliveries(&self, context: ConflictUiContext) -> Vec<ConflictUiAck> {
        self.local_conflicts.ack_deliveries(context)
    }

    pub fn queue_conflict_ack(&self, context: ConflictUiContext, ack: ConflictUiAck) {
        self.local_conflicts.queue_ack(context, ack);
    }

    pub fn acknowledge_conflict_ack(&self, context: ConflictUiContext, token: &str) -> bool {
        self.local_conflicts.acknowledge_ack(context, token)
    }

    pub fn retry_conflict_ack(&self, context: ConflictUiContext, token: &str) -> bool {
        self.local_conflicts.retry_ack(context, token)
    }

    pub fn retry_conflict_dialog(&self, context: ConflictUiContext, token: &str) -> bool {
        self.local_conflicts.retry_dialog(context, token)
    }

    pub fn defer_conflict_ack(&self, context: ConflictUiContext, token: &str) -> bool {
        self.local_conflicts.defer_ack(context, token)
    }

    pub fn retry_conflict_ui_context(&self, context: ConflictUiContext) {
        self.local_conflicts.retry_context(context);
    }

    pub fn retain_conflict_ui_windows(&self, generations: &[u64]) {
        self.local_conflicts.retain_ui_windows(generations);
    }

    pub fn cancel_pending_conflicts(&self) {
        self.context_epoch.fetch_add(1, Ordering::AcqRel);
        self.local_gc.invalidate();
        self.local_conflicts.cancel_pending();
    }

    pub fn invalidate_local_gc(&self) {
        self.local_gc.invalidate();
    }

    pub(super) fn track_response(
        &self,
        receiver: mpsc::Receiver<Vec<u8>>,
        fallback: Vec<u8>,
        response_generation: u64,
        reservation: ResponsePermit,
    ) {
        self.pending.lock().unwrap().push(PendingResponse {
            receiver,
            fallback,
            response_generation,
            reservation,
        });
    }

    /// Queue a supported cloud RPC. Returns false when the packet
    /// must remain on Steam's normal path.
    pub fn intercept(
        &self,
        method: &str,
        request_header: &CMsgProtoBufHeader,
        _request_header_bytes: &[u8],
        body: &[u8],
        config: &RuntimeConfig,
        response_generation: u64,
    ) -> bool {
        if is_backend_transfer_report(method, body, config, &self.transfer_targets) {
            if self
                .report_worker
                .try_send(QueuedRequest {
                    app_id: 0,
                    method: method.to_string(),
                    body: body.to_vec(),
                    settings: CloudSettings::from_config(config),
                    response: None,
                    context_epoch: 0,
                })
                .is_err()
            {
                warn!(method, "cloud-rpc: transfer report queue unavailable");
            }
            return true;
        }
        let Some(app_id) = intercepted_request_app_id(method, body, config) else {
            return false;
        };

        let expects_response = method_expects_response(method);
        if expects_response && request_header.jobid_source.is_none_or(|job| job == 0) {
            warn!(app_id, method, "cloud-rpc: request has no response job id");
            return false;
        }

        let settings = CloudSettings::from_config(config);
        if expects_response {
            let worker = &self.worker;
            let Some(reservation) = worker.try_reserve_response() else {
                warn!(app_id, method, "cloud-rpc: response capacity exhausted");
                return false;
            };
            let (sender, receiver) = mpsc::channel();
            let fallback = build_failure_response_packet(request_header);
            self.track_response(receiver, fallback, response_generation, reservation);
            let request = QueuedRequest {
                app_id,
                method: method.to_string(),
                body: body.to_vec(),
                settings,
                response: Some(QueuedResponse {
                    sender: sender.clone(),
                    request_header: request_header.clone(),
                }),
                context_epoch: self.context_epoch.load(Ordering::Acquire),
            };
            if worker.sender.try_send(request).is_err() {
                warn!(app_id, method, "cloud-rpc: request queue unavailable");
                let packet = build_failure_response_packet(request_header);
                let _ = sender.send(packet);
                vapor_forge_features::inject_wake::wake(
                    vapor_forge_features::inject_wake::InjectionSource::Cloud,
                );
            }
        } else {
            let request = QueuedRequest {
                app_id,
                method: method.to_string(),
                body: body.to_vec(),
                settings,
                response: None,
                context_epoch: self.context_epoch.load(Ordering::Acquire),
            };
            if self.worker.sender.try_send(request).is_err() {
                warn!(app_id, method, "cloud-rpc: notification queue unavailable");
                return false;
            }
        }
        true
    }

    pub fn drain_completed(&self) -> Vec<CompletedResponse> {
        let mut pending = self.pending.lock().unwrap();
        let mut completed = Vec::new();
        let mut index = 0;
        while index < pending.len() {
            match pending[index].receiver.try_recv() {
                Ok(packet) => {
                    let entry = pending.swap_remove(index);
                    completed.push(CompletedResponse {
                        packet,
                        response_generation: entry.response_generation,
                        permit: entry.reservation,
                    });
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    let entry = pending.swap_remove(index);
                    completed.push(CompletedResponse {
                        packet: entry.fallback,
                        response_generation: entry.response_generation,
                        permit: entry.reservation,
                    });
                }
                Err(mpsc::TryRecvError::Empty) => index += 1,
            }
        }
        completed
    }
}
