use super::adapter::{execute_rpc, AdapterState};
use super::http::{AdapterError, CloudSettings};
use super::protocol::{
    build_response_packet, is_cumulus_transfer_report, method_expects_response, request_app_id,
};
use super::transfer_targets::TransferTargetRegistry;
use super::*;
use prost::Message;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use tracing::warn;
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_steam_protocol::*;

struct PendingResponse {
    receiver: mpsc::Receiver<Vec<u8>>,
    _reservation: ResponseReservation,
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
}

pub(super) struct RpcWorker {
    pub(super) sender: mpsc::SyncSender<QueuedRequest>,
    pub(super) outstanding_responses: Arc<AtomicUsize>,
}

impl RpcWorker {
    pub(super) fn try_reserve_response(&self) -> Option<ResponseReservation> {
        self.outstanding_responses
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                (queued < RPC_QUEUE_CAPACITY).then_some(queued + 1)
            })
            .ok()?;
        Some(ResponseReservation {
            outstanding: Arc::clone(&self.outstanding_responses),
        })
    }
}

pub(super) struct ResponseReservation {
    pub(super) outstanding: Arc<AtomicUsize>,
}

impl Drop for ResponseReservation {
    fn drop(&mut self) {
        self.outstanding.fetch_sub(1, Ordering::AcqRel);
    }
}
/// Thread-safe queue used by the network hook. HTTP never runs on Steam's
/// websocket thread; completed packets are drained on a later receive frame.
pub struct CloudRpcQueue {
    pending: Mutex<Vec<PendingResponse>>,
    count: AtomicUsize,
    workers: Box<[RpcWorker]>,
    report_worker: mpsc::SyncSender<QueuedRequest>,
    pub(super) transfer_targets: Arc<TransferTargetRegistry>,
}

impl CloudRpcQueue {
    pub fn new() -> Self {
        let transfer_targets = Arc::new(TransferTargetRegistry::default());
        let workers = (0..RPC_WORKER_SHARDS)
            .map(|_| {
                let worker_transfer_targets = Arc::clone(&transfer_targets);
                let (sender, receiver) = mpsc::sync_channel::<QueuedRequest>(RPC_CHANNEL_CAPACITY);
                let outstanding_responses = Arc::new(AtomicUsize::new(0));
                std::thread::spawn(move || {
                    let mut state = AdapterState::with_transfer_targets(worker_transfer_targets);
                    while let Ok(request) = receiver.recv() {
                        let result = execute_rpc(
                            &mut state,
                            &request.settings,
                            &request.method,
                            &request.body,
                        );
                        if let Some(response) = request.response {
                            let packet = build_response_packet(&response.request_header, result);
                            let _ = response.sender.send(packet);
                        } else if let Err(error) = result {
                            warn!(
                                app_id = request.app_id,
                                method = request.method,
                                %error,
                                "cloud-rpc: notification failed"
                            );
                        }
                    }
                });
                RpcWorker {
                    sender,
                    outstanding_responses,
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let (report_worker, report_receiver) = mpsc::sync_channel::<QueuedRequest>(128);
        std::thread::spawn(move || {
            let mut state = AdapterState::default();
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
        });
        Self {
            pending: Mutex::new(Vec::new()),
            count: AtomicUsize::new(0),
            workers,
            report_worker,
            transfer_targets,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count.load(Ordering::Acquire) == 0
    }

    pub(super) fn worker(&self, app_id: u32) -> &RpcWorker {
        &self.workers[app_id as usize % self.workers.len()]
    }

    pub(super) fn track_response(
        &self,
        receiver: mpsc::Receiver<Vec<u8>>,
        reservation: ResponseReservation,
    ) {
        self.pending.lock().unwrap().push(PendingResponse {
            receiver,
            _reservation: reservation,
        });
        self.count.fetch_add(1, Ordering::Release);
    }

    /// Queue a supported Cumulus-backed RPC. Returns false when the packet
    /// must remain on Steam's normal path.
    pub fn intercept(
        &self,
        method: &str,
        request_header: &CMsgProtoBufHeader,
        _request_header_bytes: &[u8],
        body: &[u8],
        config: &RuntimeConfig,
    ) -> bool {
        if config.cumulus_configured() && method == LAUNCH_INTENT {
            capture_device_descriptor(body);
        }
        if is_cumulus_transfer_report(method, body, config, &self.transfer_targets) {
            if self
                .report_worker
                .try_send(QueuedRequest {
                    app_id: 0,
                    method: method.to_string(),
                    body: body.to_vec(),
                    settings: CloudSettings::from_config(config),
                    response: None,
                })
                .is_err()
            {
                warn!(method, "cloud-rpc: transfer report queue unavailable");
            }
            return true;
        }
        let Some(app_id) = request_app_id(method, body) else {
            return false;
        };
        if !config.cumulus_configured()
            || !crate::apps::classify_app(config, AppId(app_id)).is_confirmed_unowned()
        {
            return false;
        }

        let expects_response = method_expects_response(method);
        if expects_response && request_header.jobid_source.map_or(true, |job| job == 0) {
            warn!(app_id, method, "cloud-rpc: request has no response job id");
            return false;
        }

        let settings = CloudSettings::from_config(config);
        if expects_response {
            let worker = self.worker(app_id);
            let Some(reservation) = worker.try_reserve_response() else {
                warn!(app_id, method, "cloud-rpc: response capacity exhausted");
                return false;
            };
            let (sender, receiver) = mpsc::channel();
            let request = QueuedRequest {
                app_id,
                method: method.to_string(),
                body: body.to_vec(),
                settings,
                response: Some(QueuedResponse {
                    sender: sender.clone(),
                    request_header: request_header.clone(),
                }),
            };
            if worker.sender.try_send(request).is_err() {
                warn!(app_id, method, "cloud-rpc: request queue unavailable");
                let packet = build_response_packet(request_header, Err(AdapterError::Overloaded));
                let _ = sender.send(packet);
            }
            self.track_response(receiver, reservation);
        } else {
            let request = QueuedRequest {
                app_id,
                method: method.to_string(),
                body: body.to_vec(),
                settings,
                response: None,
            };
            if self.worker(app_id).sender.try_send(request).is_err() {
                warn!(app_id, method, "cloud-rpc: notification queue unavailable");
                return false;
            }
        }
        true
    }

    pub fn drain_completed(&self) -> Vec<Vec<u8>> {
        let mut pending = self.pending.lock().unwrap();
        let mut completed = Vec::new();
        let mut index = 0;
        while index < pending.len() {
            match pending[index].receiver.try_recv() {
                Ok(packet) => {
                    pending.swap_remove(index);
                    self.count.fetch_sub(1, Ordering::Release);
                    completed.push(packet);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    pending.swap_remove(index);
                    self.count.fetch_sub(1, Ordering::Release);
                }
                Err(mpsc::TryRecvError::Empty) => index += 1,
            }
        }
        completed
    }
}

fn capture_device_descriptor(body: &[u8]) {
    let Ok(request) = CloudAppLaunchIntentRequest::decode(body) else {
        return;
    };
    let Some(client_id) = request.client_id.filter(|client_id| *client_id != 0) else {
        return;
    };
    vapor_forge_cloud_core::record_device_descriptor(vapor_forge_cloud_core::DeviceDescriptor {
        client_id,
        machine_name: request.machine_name.unwrap_or_default(),
        os_type: request.os_type.map(i64::from),
        device_type: request.device_type.map(i64::from),
    });
}

impl Default for CloudRpcQueue {
    fn default() -> Self {
        Self::new()
    }
}
