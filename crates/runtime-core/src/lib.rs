#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimePhase {
    Created = 0,
    AuditVersionSeen = 1,
    ObjectSeen = 2,
    ReadyForHeavyInit = 3,
    Closing = 4,
}

impl RuntimePhase {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::AuditVersionSeen,
            2 => Self::ObjectSeen,
            3 => Self::ReadyForHeavyInit,
            4 => Self::Closing,
            _ => Self::Created,
        }
    }
}

#[derive(Debug)]
pub struct Lifecycle {
    phase: AtomicU8,
    ready_for_heavy_init_seen: AtomicBool,
}

impl Lifecycle {
    pub const fn new() -> Self {
        Self {
            phase: AtomicU8::new(RuntimePhase::Created as u8),
            ready_for_heavy_init_seen: AtomicBool::new(false),
        }
    }

    pub fn mark_version_seen(&self) {
        self.raise_to(RuntimePhase::AuditVersionSeen);
    }

    pub fn mark_object_seen(&self) {
        self.raise_to(RuntimePhase::ObjectSeen);
    }

    pub fn mark_ready_for_heavy_init(&self) {
        self.ready_for_heavy_init_seen
            .store(true, Ordering::Release);
        self.raise_to(RuntimePhase::ReadyForHeavyInit);
    }

    pub fn mark_closing(&self) {
        self.phase
            .store(RuntimePhase::Closing as u8, Ordering::Release);
    }

    pub fn phase(&self) -> RuntimePhase {
        RuntimePhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    pub fn has_reached_ready_for_heavy_init(&self) -> bool {
        self.ready_for_heavy_init_seen.load(Ordering::Acquire)
    }

    fn raise_to(&self, target: RuntimePhase) {
        let target = target as u8;
        let mut current = self.phase.load(Ordering::Acquire);

        while current < target {
            match self.phase.compare_exchange_weak(
                current,
                target,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AppId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DepotId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ManifestId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Address(pub usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SteamModuleKind {
    SteamClient,
    SteamUi,
}

impl SteamModuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SteamClient => "steamclient.so",
            Self::SteamUi => "steamui.so",
        }
    }

    pub fn from_name_or_path(name_or_path: &str) -> Option<Self> {
        let name = name_or_path.rsplit('/').next().unwrap_or(name_or_path);
        match name {
            "steamclient.so" => Some(Self::SteamClient),
            "steamui.so" => Some(Self::SteamUi),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct SteamModuleState {
    steamclient_seen: AtomicBool,
    steamui_seen: AtomicBool,
}

impl SteamModuleState {
    pub const fn new() -> Self {
        Self {
            steamclient_seen: AtomicBool::new(false),
            steamui_seen: AtomicBool::new(false),
        }
    }

    pub fn mark_seen_by_name(&self, name_or_path: &str) -> Option<SteamModuleKind> {
        let kind = SteamModuleKind::from_name_or_path(name_or_path)?;

        match kind {
            SteamModuleKind::SteamClient => self.steamclient_seen.store(true, Ordering::Release),
            SteamModuleKind::SteamUi => self.steamui_seen.store(true, Ordering::Release),
        }

        Some(kind)
    }

    pub fn steamclient_seen(&self) -> bool {
        self.steamclient_seen.load(Ordering::Acquire)
    }

    pub fn steamui_seen(&self) -> bool {
        self.steamui_seen.load(Ordering::Acquire)
    }

    pub fn any_seen(&self) -> bool {
        self.steamclient_seen() || self.steamui_seen()
    }
}

impl Default for SteamModuleState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Lifecycle, RuntimePhase, SteamModuleKind, SteamModuleState};

    #[test]
    fn lifecycle_only_moves_forward_until_closing() {
        let lifecycle = Lifecycle::new();

        assert_eq!(lifecycle.phase(), RuntimePhase::Created);
        assert!(!lifecycle.has_reached_ready_for_heavy_init());
        lifecycle.mark_object_seen();
        lifecycle.mark_version_seen();
        assert_eq!(lifecycle.phase(), RuntimePhase::ObjectSeen);
        assert!(!lifecycle.has_reached_ready_for_heavy_init());

        lifecycle.mark_ready_for_heavy_init();
        assert_eq!(lifecycle.phase(), RuntimePhase::ReadyForHeavyInit);
        assert!(lifecycle.has_reached_ready_for_heavy_init());

        lifecycle.mark_closing();
        assert_eq!(lifecycle.phase(), RuntimePhase::Closing);
        assert!(lifecycle.has_reached_ready_for_heavy_init());
    }

    #[test]
    fn steam_module_state_tracks_public_module_names() {
        let state = SteamModuleState::new();

        assert_eq!(
            state.mark_seen_by_name("/home/user/.steam/steam/ubuntu12_32/steamclient.so"),
            Some(SteamModuleKind::SteamClient)
        );
        assert!(state.steamclient_seen());
        assert!(!state.steamui_seen());

        assert_eq!(
            state.mark_seen_by_name("steamui.so"),
            Some(SteamModuleKind::SteamUi)
        );
        assert!(state.any_seen());
        assert_eq!(state.mark_seen_by_name("libc.so.6"), None);
    }
}
