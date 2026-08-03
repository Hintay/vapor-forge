use crate::http::CloudSettings;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use vapor_forge_cloud_local::{
    CommitIdentity, FolderStore, LocalGcCoordinator, ManifestCandidate, StoreView,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConflictUiContext {
    pub steam_id64: u64,
    pub identity_generation: u64,
    pub connection_generation: u64,
    pub window_generation: u64,
    pub cloud_scope: [u8; 32],
}

#[derive(Clone, Debug, Serialize)]
pub struct ConflictDialog {
    pub app_id: u32,
    pub cancel_token: String,
    pub candidates: Vec<ConflictDialogCandidate>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConflictDialogCandidate {
    pub token: String,
    pub revision: u64,
    pub machine_name: String,
    pub created_at_ms: u64,
    pub file_count: usize,
    pub total_bytes: u64,
    pub file_names: Vec<String>,
    pub is_local: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConflictUiAck {
    pub token: String,
    pub app_id: u32,
    pub accepted: bool,
    pub error: String,
    pub resume_launch: bool,
    pub cancel_launch: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictSubmitResult {
    Accepted,
    Unknown,
    Stale,
}

#[derive(Clone)]
struct PendingConflict {
    settings: CloudSettings,
    identity: CommitIdentity,
    heads: Vec<String>,
    candidates: Vec<ManifestCandidate>,
    resolving: bool,
    armed: bool,
    minimum_revision: u64,
    cloud_scope: [u8; 32],
}

#[derive(Clone)]
struct Binding {
    key: (u64, u32),
    head: String,
    context: ConflictUiContext,
}

#[derive(Clone)]
struct Choice {
    key: (u64, u32),
    head: String,
    token: String,
    context: ConflictUiContext,
    epoch: u64,
    pending: PendingConflict,
}

#[derive(Default)]
struct State {
    epoch: u64,
    pending: HashMap<(u64, u32), PendingConflict>,
    presented: HashSet<((u64, u32), ConflictUiContext)>,
    bindings: HashMap<String, Binding>,
    acks: VecDeque<(ConflictUiContext, ConflictUiAck)>,
}

pub(crate) struct LocalConflictCoordinator {
    state: Mutex<State>,
    revision: AtomicU64,
    choices: mpsc::Sender<Choice>,
}

impl LocalConflictCoordinator {
    pub(crate) fn new(gc: Arc<LocalGcCoordinator>) -> Arc<Self> {
        Arc::new_cyclic(|weak: &std::sync::Weak<Self>| {
            let (choices, receiver) = mpsc::channel::<Choice>();
            let worker = weak.clone();
            std::thread::spawn(move || {
                while let Ok(choice) = receiver.recv() {
                    let result = apply_choice(&choice, &gc);
                    if let Some(coordinator) = worker.upgrade() {
                        coordinator.finish_choice(choice, result);
                    } else {
                        break;
                    }
                }
            });
            Self {
                state: Mutex::new(State::default()),
                revision: AtomicU64::new(1),
                choices,
            }
        })
    }

    pub(crate) fn register(
        &self,
        settings: &CloudSettings,
        app_id: u32,
        identity: &CommitIdentity,
        view: &StoreView,
        required: bool,
        minimum_revision: u64,
    ) {
        let Some(steam_id64) = settings.steam_id64.filter(|id| *id != 0) else {
            return;
        };
        let key = (steam_id64, app_id);
        if !required {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            let removed_pending = state.pending.remove(&key).is_some();
            discard_key_bindings(&mut state, key);
            if removed_pending {
                self.bump_revision();
            }
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let armed = state.pending.get(&key).is_some_and(|pending| pending.armed);
        let pending = PendingConflict {
            settings: settings.clone(),
            identity: identity.clone(),
            heads: view.head_ids(),
            candidates: view.heads.clone(),
            resolving: false,
            armed,
            minimum_revision,
            cloud_scope: settings.conflict_scope(),
        };
        let unchanged = state.pending.get_mut(&key).is_some_and(|current| {
            current.minimum_revision = current.minimum_revision.max(minimum_revision);
            current.heads == pending.heads
                && current.identity == pending.identity
                && current.cloud_scope == pending.cloud_scope
        });
        if unchanged {
            return;
        }
        state.pending.insert(key, pending);
        discard_key_bindings(&mut state, key);
        self.bump_revision();
    }

    pub(crate) fn arm(
        &self,
        settings: &CloudSettings,
        app_id: u32,
        identity: &CommitIdentity,
        view: &StoreView,
        required: bool,
        minimum_revision: u64,
    ) -> bool {
        let Some(steam_id64) = settings.steam_id64.filter(|id| *id != 0) else {
            return false;
        };
        let key = (steam_id64, app_id);
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(pending) = state.pending.get_mut(&key) {
            if pending.heads == view.head_ids()
                && pending.identity == *identity
                && pending.cloud_scope == settings.conflict_scope()
            {
                pending.minimum_revision = pending.minimum_revision.max(minimum_revision);
                if !pending.armed {
                    pending.armed = true;
                    self.bump_revision();
                }
                return true;
            }
        }
        drop(state);
        if !required {
            return false;
        }
        self.register(settings, app_id, identity, view, true, minimum_revision);
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Some(pending) = state.pending.get_mut(&key) else {
            return false;
        };
        pending.armed = true;
        self.bump_revision();
        true
    }

    pub(crate) fn dialogs(&self, context: ConflictUiContext) -> Vec<ConflictDialog> {
        if context.steam_id64 == 0 || context.window_generation == 0 {
            return Vec::new();
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let keys = state
            .pending
            .iter()
            .filter(|((steam_id64, _), pending)| {
                *steam_id64 == context.steam_id64
                    && pending.cloud_scope == context.cloud_scope
                    && pending.armed
                    && !pending.resolving
            })
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        let mut dialogs = Vec::new();
        for key in keys {
            if state.presented.contains(&(key, context)) {
                continue;
            }
            let Some(pending) = state.pending.get(&key).cloned() else {
                continue;
            };
            let candidates = pending
                .candidates
                .iter()
                .map(|candidate| {
                    let token = next_token(key, &candidate.id, context);
                    state.bindings.insert(
                        token.clone(),
                        Binding {
                            key,
                            head: candidate.id.clone(),
                            context,
                        },
                    );
                    ConflictDialogCandidate {
                        token,
                        revision: candidate.revision,
                        machine_name: candidate.machine_name.clone(),
                        created_at_ms: candidate.created_at_ms,
                        file_count: candidate.file_count,
                        total_bytes: candidate.total_bytes,
                        file_names: candidate.file_names.clone(),
                        is_local: candidate.client_id == pending.identity.client_id,
                    }
                })
                .collect();
            let cancel_token = next_token(key, "cancel", context);
            state.bindings.insert(
                cancel_token.clone(),
                Binding {
                    key,
                    head: String::new(),
                    context,
                },
            );
            state.presented.insert((key, context));
            dialogs.push(ConflictDialog {
                app_id: key.1,
                cancel_token,
                candidates,
            });
        }
        dialogs
    }

    pub(crate) fn submit(&self, token: &str, context: ConflictUiContext) -> ConflictSubmitResult {
        let choice = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            let Some(binding) = state.bindings.get(token).cloned() else {
                return ConflictSubmitResult::Unknown;
            };
            if binding.context != context || binding.key.0 != context.steam_id64 {
                if binding.context.steam_id64 == context.steam_id64
                    && binding.context.cloud_scope != context.cloud_scope
                {
                    state.pending.remove(&binding.key);
                    discard_key_bindings(&mut state, binding.key);
                    self.bump_revision();
                }
                return ConflictSubmitResult::Stale;
            }
            if binding.head.is_empty() {
                state.pending.remove(&binding.key);
                discard_key_bindings(&mut state, binding.key);
                state.acks.push_back((
                    context,
                    ConflictUiAck {
                        token: token.to_owned(),
                        app_id: binding.key.1,
                        accepted: true,
                        error: String::new(),
                        resume_launch: false,
                        cancel_launch: true,
                    },
                ));
                self.bump_revision();
                return ConflictSubmitResult::Accepted;
            }
            let Some(pending) = state.pending.get_mut(&binding.key) else {
                return ConflictSubmitResult::Stale;
            };
            if pending.resolving || pending.heads.is_empty() {
                return ConflictSubmitResult::Stale;
            }
            pending.resolving = true;
            let pending = pending.clone();
            let epoch = state.epoch;
            discard_key_bindings(&mut state, binding.key);
            Choice {
                key: binding.key,
                head: binding.head,
                token: token.to_owned(),
                context,
                epoch,
                pending,
            }
        };
        if self.choices.send(choice).is_err() {
            return ConflictSubmitResult::Stale;
        }
        ConflictSubmitResult::Accepted
    }

    pub(crate) fn acks(&self, context: ConflictUiContext) -> Vec<ConflictUiAck> {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .acks
            .iter()
            .filter_map(|(target, ack)| (*target == context).then_some(ack.clone()))
            .collect()
    }

    pub(crate) fn acknowledge_acks(&self, context: ConflictUiContext, tokens: &[String]) {
        let tokens = tokens.iter().map(String::as_str).collect::<HashSet<_>>();
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .acks
            .retain(|(target, ack)| *target != context || !tokens.contains(ack.token.as_str()));
    }

    pub(crate) fn retry_context(&self, context: ConflictUiContext) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state
            .bindings
            .retain(|_, binding| binding.context != context);
        state
            .presented
            .retain(|(_, presented)| *presented != context);
        self.bump_revision();
    }

    pub(crate) fn invalidate_ui_context(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.bindings.clear();
        state.presented.clear();
        state.acks.clear();
        self.bump_revision();
    }

    pub(crate) fn cancel_pending(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.epoch = state.epoch.wrapping_add(1);
        let canceled = !state.pending.is_empty();
        state.pending.clear();
        state.presented.clear();
        state.bindings.clear();
        state.acks.clear();
        drop(state);
        if canceled {
            self.bump_revision();
        }
        canceled
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    fn finish_choice(&self, choice: Choice, result: Result<(), String>) {
        {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            let current = state.epoch == choice.epoch
                && state.pending.get(&choice.key).is_some_and(|pending| {
                    pending.heads == choice.pending.heads
                        && pending.identity == choice.pending.identity
                });
            if !current {
                return;
            }
            match result {
                Ok(()) => {
                    state.pending.remove(&choice.key);
                    discard_key_bindings(&mut state, choice.key);
                    state.acks.push_back((
                        choice.context,
                        ConflictUiAck {
                            token: choice.token,
                            app_id: choice.key.1,
                            accepted: true,
                            error: String::new(),
                            resume_launch: true,
                            cancel_launch: false,
                        },
                    ));
                }
                Err(message) => {
                    tracing::warn!(
                        steam_id64 = choice.key.0,
                        app_id = choice.key.1,
                        error = %message,
                        "cloud conflict resolution failed"
                    );
                    if let Some(pending) = state.pending.get_mut(&choice.key) {
                        pending.resolving = false;
                    }
                    state.presented.retain(|(key, _)| *key != choice.key);
                    state.acks.push_back((
                        choice.context,
                        ConflictUiAck {
                            token: choice.token,
                            app_id: choice.key.1,
                            accepted: false,
                            error: "save_failed".into(),
                            resume_launch: false,
                            cancel_launch: false,
                        },
                    ));
                }
            }
        }
        self.bump_revision();
    }

    fn bump_revision(&self) {
        self.revision.fetch_add(1, Ordering::AcqRel);
    }
}

fn apply_choice(choice: &Choice, gc: &LocalGcCoordinator) -> Result<(), String> {
    let store = FolderStore::open_account(&choice.pending.settings.local_path, choice.key.0)
        .map_err(|error| error.to_string())?;
    let view = store
        .view(choice.key.1)
        .map_err(|error| error.to_string())?;
    if view.head_ids() != choice.pending.heads {
        return Err("Local cloud versions changed before the choice completed".into());
    }
    let candidate = choice
        .pending
        .candidates
        .iter()
        .find(|candidate| candidate.id == choice.head)
        .ok_or_else(|| "Selected local cloud version is no longer available".to_string())?;
    store
        .resolve_to_manifest(
            choice.key.1,
            &choice.pending.heads,
            &candidate.id,
            &choice.pending.identity,
            choice.pending.minimum_revision,
        )
        .map_err(|error| error.to_string())?;
    gc.queue_inspection(store, choice.key.1);
    Ok(())
}

fn discard_key_bindings(state: &mut State, key: (u64, u32)) {
    state.bindings.retain(|_, binding| binding.key != key);
    state.presented.retain(|(presented, _)| *presented != key);
}

fn next_token(key: (u64, u32), head: &str, context: ConflictUiContext) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut digest = Sha256::new();
    digest.update(key.0.to_le_bytes());
    digest.update(key.1.to_le_bytes());
    digest.update(head.as_bytes());
    digest.update(context.identity_generation.to_le_bytes());
    digest.update(context.connection_generation.to_le_bytes());
    digest.update(context.window_generation.to_le_bytes());
    digest.update(context.cloud_scope);
    digest.update(sequence.to_le_bytes());
    digest.update(now.to_le_bytes());
    let bytes = digest.finalize();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::time::{Duration, Instant};
    use vapor_forge_cloud_core::FileMetadata;

    fn candidate(byte: char, client_id: u64) -> ManifestCandidate {
        ManifestCandidate {
            id: byte.to_string().repeat(64),
            revision: client_id,
            client_id,
            machine_name: format!("device-{client_id}"),
            created_at_ms: client_id * 1_000,
            file_count: 1,
            total_bytes: client_id,
            file_names: vec!["save.dat".into()],
        }
    }

    fn settings() -> CloudSettings {
        CloudSettings {
            local_path: String::new(),
            server_url: String::new(),
            token: String::new(),
            steam_client_id: Some(7),
            steam_machine_name: Some("deck".into()),
            steam_id64: Some(76_561_198_000_000_001),
            bind_device: false,
            timeout_connect_ms: 1,
            timeout_ms: 1,
        }
    }

    fn settings_at(path: &Path) -> CloudSettings {
        let mut settings = settings();
        settings.local_path = path.to_string_lossy().into_owned();
        settings
    }

    fn context() -> ConflictUiContext {
        context_for(&settings())
    }

    fn context_for(settings: &CloudSettings) -> ConflictUiContext {
        ConflictUiContext {
            steam_id64: 76_561_198_000_000_001,
            identity_generation: 2,
            connection_generation: 3,
            window_generation: 4,
            cloud_scope: settings.conflict_scope(),
        }
    }

    fn three_head_store() -> (tempfile::TempDir, FolderStore, StoreView) {
        const ACCOUNT: u64 = 76_561_198_000_000_001;
        let temporary = tempfile::tempdir().unwrap();
        let store = FolderStore::open_account(temporary.path(), ACCOUNT).unwrap();
        let identity = CommitIdentity {
            client_id: 1,
            machine_name: "root".into(),
        };
        let staged = store
            .stage_file(
                480,
                "save.dat",
                b"root",
                &FileMetadata {
                    sha1: "dc76e9f0c0006e8f919e0c515c66dbba3982f785".into(),
                    raw_size: 4,
                    mtime: 1,
                    platforms_to_sync: u32::MAX,
                },
            )
            .unwrap();
        store
            .commit_batch(480, &[], &[staged], &BTreeSet::new(), &identity, None)
            .unwrap();

        let root = store.view(480).unwrap().head_ids().remove(0);
        let directory = temporary.path().join(format!("{ACCOUNT}/480/manifests"));
        let root_bytes = std::fs::read(directory.join(format!("{root}.json"))).unwrap();
        let root_manifest = serde_json::from_slice::<serde_json::Value>(&root_bytes).unwrap();
        for (client_id, machine_name) in [(7, "deck"), (8, "desktop"), (9, "laptop")] {
            let mut manifest = root_manifest.clone();
            manifest["revision"] = serde_json::json!(2);
            manifest["parents"] = serde_json::json!([root.clone()]);
            manifest["client_id"] = serde_json::json!(client_id);
            manifest["machine_name"] = serde_json::json!(machine_name);
            manifest["created_at_ms"] = serde_json::json!(client_id * 1_000);
            let bytes = serde_json::to_vec(&manifest).unwrap();
            let id = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            std::fs::write(directory.join(format!("{id}.json")), bytes).unwrap();
        }
        let view = store.view(480).unwrap();
        assert_eq!(view.heads.len(), 3);
        (temporary, store, view)
    }

    fn wait_for_ack(
        coordinator: &LocalConflictCoordinator,
        context: ConflictUiContext,
    ) -> ConflictUiAck {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(ack) = coordinator.acks(context).into_iter().next() {
                return ack;
            }
            assert!(
                Instant::now() < deadline,
                "conflict choice did not complete"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn tokens_are_bound_to_one_ui_context_and_one_choice() {
        let gc = Arc::new(LocalGcCoordinator::new());
        let coordinator = LocalConflictCoordinator::new(gc);
        let view = StoreView {
            current_change_number: None,
            max_revision: 9,
            heads: vec![candidate('a', 7), candidate('b', 8), candidate('c', 9)],
        };
        coordinator.arm(
            &settings(),
            480,
            &CommitIdentity {
                client_id: 7,
                machine_name: "device-7".into(),
            },
            &view,
            true,
            0,
        );

        let dialogs = coordinator.dialogs(context());
        assert_eq!(dialogs.len(), 1);
        assert_eq!(dialogs[0].candidates.len(), 3);
        let first = dialogs[0].candidates[0].token.clone();
        let second = dialogs[0].candidates[1].token.clone();
        assert_eq!(first.len(), 64);

        for stale in [
            ConflictUiContext {
                identity_generation: context().identity_generation + 1,
                ..context()
            },
            ConflictUiContext {
                connection_generation: context().connection_generation + 1,
                ..context()
            },
            ConflictUiContext {
                window_generation: context().window_generation + 1,
                ..context()
            },
        ] {
            assert_eq!(
                coordinator.submit(&first, stale),
                ConflictSubmitResult::Stale
            );
        }
        assert_eq!(
            coordinator.submit(&second, context()),
            ConflictSubmitResult::Accepted
        );
        assert_eq!(
            coordinator.submit(&first, context()),
            ConflictSubmitResult::Unknown
        );
    }

    #[test]
    fn registered_conflict_is_presented_only_after_launch_arms_it() {
        let gc = Arc::new(LocalGcCoordinator::new());
        let coordinator = LocalConflictCoordinator::new(gc);
        let view = StoreView {
            current_change_number: None,
            max_revision: 9,
            heads: vec![candidate('a', 7), candidate('b', 8), candidate('c', 9)],
        };
        let identity = CommitIdentity {
            client_id: 7,
            machine_name: "device-7".into(),
        };

        coordinator.register(&settings(), 480, &identity, &view, true, 0);
        assert!(coordinator.dialogs(context()).is_empty());

        assert!(coordinator.arm(&settings(), 480, &identity, &view, true, 0));
        assert_eq!(coordinator.dialogs(context()).len(), 1);
    }

    #[test]
    fn stored_choice_publishes_resolution_before_ack() {
        let (temporary, store, view) = three_head_store();
        let gc = Arc::new(LocalGcCoordinator::new());
        let coordinator = LocalConflictCoordinator::new(gc);
        let settings = settings_at(temporary.path());
        let context = context_for(&settings);
        coordinator.arm(
            &settings,
            480,
            &CommitIdentity {
                client_id: 7,
                machine_name: "deck".into(),
            },
            &view,
            true,
            50,
        );
        let dialog = coordinator.dialogs(context).remove(0);
        let token = dialog
            .candidates
            .iter()
            .find(|candidate| !candidate.is_local)
            .unwrap()
            .token
            .clone();

        assert_eq!(
            coordinator.submit(&token, context),
            ConflictSubmitResult::Accepted
        );
        let ack = wait_for_ack(&coordinator, context);
        assert!(ack.accepted);
        let resolved = store.view(480).unwrap();
        assert_eq!(resolved.heads.len(), 1);
        assert_eq!(resolved.current_change_number, Some(51));
        assert!(coordinator.dialogs(context).is_empty());
    }

    #[test]
    fn current_device_choice_also_publishes_a_resolution() {
        let (temporary, store, view) = three_head_store();
        let gc = Arc::new(LocalGcCoordinator::new());
        let coordinator = LocalConflictCoordinator::new(gc);
        let settings = settings_at(temporary.path());
        let context = context_for(&settings);
        coordinator.arm(
            &settings,
            480,
            &CommitIdentity {
                client_id: 7,
                machine_name: "deck".into(),
            },
            &view,
            true,
            0,
        );
        let selected_head = view
            .heads
            .iter()
            .find(|candidate| candidate.client_id == 7)
            .unwrap()
            .id
            .clone();
        let dialog = coordinator.dialogs(context).remove(0);
        let selected = dialog
            .candidates
            .iter()
            .find(|candidate| candidate.is_local)
            .unwrap();
        let token = selected.token.clone();

        assert_eq!(
            coordinator.submit(&token, context),
            ConflictSubmitResult::Accepted
        );
        let ack = wait_for_ack(&coordinator, context);
        assert!(ack.accepted);
        let resolved = store.view(480).unwrap();
        assert_eq!(resolved.heads.len(), 1);
        assert!(resolved.heads[0].revision > view.max_revision);
        assert_ne!(resolved.heads[0].id, selected_head);
    }

    #[test]
    fn accepted_choice_resumes_the_game_action() {
        let (temporary, _store, view) = three_head_store();
        let gc = Arc::new(LocalGcCoordinator::new());
        let coordinator = LocalConflictCoordinator::new(gc);
        let settings = settings_at(temporary.path());
        let context = context_for(&settings);
        coordinator.arm(
            &settings,
            480,
            &CommitIdentity {
                client_id: 7,
                machine_name: "deck".into(),
            },
            &view,
            true,
            0,
        );
        let token = coordinator.dialogs(context)[0].candidates[1].token.clone();

        assert_eq!(
            coordinator.submit(&token, context),
            ConflictSubmitResult::Accepted
        );
        let ack = wait_for_ack(&coordinator, context);
        assert!(ack.accepted);
        assert_eq!(ack.app_id, 480);
        assert!(ack.resume_launch);
        assert!(!ack.cancel_launch);
    }

    #[test]
    fn cancel_cancels_the_game_action() {
        let (temporary, _store, view) = three_head_store();
        let gc = Arc::new(LocalGcCoordinator::new());
        let coordinator = LocalConflictCoordinator::new(gc);
        let settings = settings_at(temporary.path());
        let context = context_for(&settings);
        coordinator.arm(
            &settings,
            480,
            &CommitIdentity {
                client_id: 7,
                machine_name: "deck".into(),
            },
            &view,
            true,
            0,
        );
        let cancel = coordinator.dialogs(context)[0].cancel_token.clone();

        assert_eq!(
            coordinator.submit(&cancel, context),
            ConflictSubmitResult::Accepted
        );
        let ack = wait_for_ack(&coordinator, context);
        assert!(ack.accepted);
        assert_eq!(ack.app_id, 480);
        assert!(!ack.resume_launch);
        assert!(ack.cancel_launch);
    }

    #[test]
    fn changed_cloud_scope_rejects_the_choice() {
        let (temporary, store, view) = three_head_store();
        let gc = Arc::new(LocalGcCoordinator::new());
        let coordinator = LocalConflictCoordinator::new(gc);
        let settings = settings_at(temporary.path());
        coordinator.arm(
            &settings,
            480,
            &CommitIdentity {
                client_id: 7,
                machine_name: "deck".into(),
            },
            &view,
            true,
            0,
        );
        let old_context = context_for(&settings);
        let token = coordinator.dialogs(old_context)[0].candidates[0]
            .token
            .clone();
        let new_context = ConflictUiContext {
            cloud_scope: [0x5a; 32],
            ..old_context
        };
        assert_eq!(
            coordinator.submit(&token, new_context),
            ConflictSubmitResult::Stale
        );
        assert_eq!(store.view(480).unwrap(), view);
        assert!(coordinator.dialogs(old_context).is_empty());
    }

    #[test]
    fn changed_heads_reject_the_choice_and_allow_a_new_dialog() {
        let temporary = tempfile::tempdir().unwrap();
        FolderStore::open_account(temporary.path(), context().steam_id64).unwrap();
        let gc = Arc::new(LocalGcCoordinator::new());
        let coordinator = LocalConflictCoordinator::new(gc);
        let settings = settings_at(temporary.path());
        let context = context_for(&settings);
        let view = StoreView {
            current_change_number: None,
            max_revision: 9,
            heads: vec![candidate('a', 7), candidate('b', 8), candidate('c', 9)],
        };
        coordinator.arm(
            &settings,
            480,
            &CommitIdentity {
                client_id: 7,
                machine_name: "device-7".into(),
            },
            &view,
            true,
            0,
        );
        let token = coordinator.dialogs(context)[0].candidates[0].token.clone();
        assert_eq!(
            coordinator.submit(&token, context),
            ConflictSubmitResult::Accepted
        );
        let ack = wait_for_ack(&coordinator, context);
        assert!(!ack.accepted);
        assert_eq!(ack.error, "save_failed");
        assert_eq!(coordinator.dialogs(context).len(), 1);
    }

    #[test]
    fn resolved_view_discards_old_multi_head_tokens() {
        let gc = Arc::new(LocalGcCoordinator::new());
        let coordinator = LocalConflictCoordinator::new(gc);
        let mut view = StoreView {
            current_change_number: None,
            max_revision: 9,
            heads: vec![candidate('a', 7), candidate('b', 8), candidate('c', 9)],
        };
        let identity = CommitIdentity {
            client_id: 7,
            machine_name: "device-7".into(),
        };
        coordinator.arm(&settings(), 480, &identity, &view, true, 0);
        let token = coordinator.dialogs(context())[0].candidates[0]
            .token
            .clone();

        view.current_change_number = Some(10);
        view.heads.truncate(1);
        coordinator.register(&settings(), 480, &identity, &view, false, 0);
        assert!(coordinator.dialogs(context()).is_empty());
        assert_eq!(
            coordinator.submit(&token, context()),
            ConflictSubmitResult::Unknown
        );
    }
}
