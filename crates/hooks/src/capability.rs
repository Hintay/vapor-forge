#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(any(debug_assertions, test))]
use std::sync::Mutex;

use tracing::{info, warn};

const UNKNOWN: u8 = 0;
const READY: u8 = 1;
const DISABLED: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum Capability {
    CallbackEvents,
    Ownership,
    PackageInjection,
    TicketOverrides,
    DepotInjection,
    ShaderCacheControl,
    DlcOverrides,
    CmInterception,
    NativeResponseDelivery,
    CloudControl,
    CloudHttp,
    LaunchEnvironment,
    LibraryUi,
    OverviewMetadata,
    LibrarySnapshot,
    ConflictUiBridge,
    LegacyCdKeyControl,
}

impl Capability {
    pub(crate) const ALL: [Self; 17] = [
        Self::CallbackEvents,
        Self::Ownership,
        Self::PackageInjection,
        Self::TicketOverrides,
        Self::DepotInjection,
        Self::ShaderCacheControl,
        Self::DlcOverrides,
        Self::CmInterception,
        Self::NativeResponseDelivery,
        Self::CloudControl,
        Self::CloudHttp,
        Self::LaunchEnvironment,
        Self::LibraryUi,
        Self::OverviewMetadata,
        Self::LibrarySnapshot,
        Self::ConflictUiBridge,
        Self::LegacyCdKeyControl,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::CallbackEvents => "callback-events",
            Self::Ownership => "ownership",
            Self::PackageInjection => "package-injection",
            Self::TicketOverrides => "ticket-overrides",
            Self::DepotInjection => "depot-injection",
            Self::ShaderCacheControl => "shader-cache-control",
            Self::DlcOverrides => "dlc-overrides",
            Self::CmInterception => "cm-interception",
            Self::NativeResponseDelivery => "native-response-delivery",
            Self::CloudControl => "cloud-control",
            Self::CloudHttp => "cloud-http",
            Self::LaunchEnvironment => "launch-environment",
            Self::LibraryUi => "library-ui",
            Self::OverviewMetadata => "overview-metadata",
            Self::LibrarySnapshot => "library-snapshot",
            Self::ConflictUiBridge => "conflict-ui-bridge",
            Self::LegacyCdKeyControl => "legacy-cdkey-control",
        }
    }

    pub(crate) const fn failure_policy(self) -> FailurePolicy {
        match self {
            Self::CmInterception
            | Self::NativeResponseDelivery
            | Self::CloudControl
            | Self::CloudHttp
            | Self::ConflictUiBridge => FailurePolicy::FailClosed,
            _ => FailurePolicy::DisableFeature,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailurePolicy {
    DisableFeature,
    FailClosed,
}

impl FailurePolicy {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::DisableFeature => "disable-feature",
            Self::FailClosed => "fail-closed",
        }
    }
}

#[cfg(any(debug_assertions, test))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityStatus {
    pub(crate) capability: Capability,
    pub(crate) ready: bool,
    pub(crate) initialized: bool,
    pub(crate) reason: Option<String>,
}

static STATES: [AtomicU8; Capability::ALL.len()] =
    [const { AtomicU8::new(UNKNOWN) }; Capability::ALL.len()];
#[cfg(any(debug_assertions, test))]
static REASONS: Mutex<Vec<(Capability, String)>> = Mutex::new(Vec::new());

pub(crate) fn set(capability: Capability, ready: bool, reason: impl Into<String>) {
    let state = if ready { READY } else { DISABLED };
    STATES[capability as usize].store(state, Ordering::Release);

    let reason = reason.into();
    #[cfg(any(debug_assertions, test))]
    {
        let mut reasons = REASONS.lock().unwrap_or_else(|error| error.into_inner());
        reasons.retain(|(stored, _)| *stored != capability);
        if !ready && !reason.is_empty() {
            reasons.push((capability, reason.clone()));
        }
    }

    if ready {
        info!(
            capability = capability.name(),
            policy = capability.failure_policy().name(),
            "hook capability ready"
        );
    } else {
        warn!(
            capability = capability.name(),
            policy = capability.failure_policy().name(),
            reason,
            "hook capability disabled"
        );
    }
}

pub(crate) fn set_from_requirements(capability: Capability, requirements: &[(&str, bool)]) -> bool {
    let missing = requirements
        .iter()
        .filter_map(|(name, ready)| (!ready).then_some(*name))
        .collect::<Vec<_>>();
    let ready = missing.is_empty();
    set(
        capability,
        ready,
        if ready {
            String::new()
        } else {
            format!("missing {}", missing.join(", "))
        },
    );
    ready
}

pub(crate) fn disable_all(capabilities: &[Capability], reason: &str) {
    for &capability in capabilities {
        set(capability, false, reason);
    }
}

pub(crate) fn is_ready(capability: Capability) -> bool {
    STATES[capability as usize].load(Ordering::Acquire) == READY
}

#[cfg(any(debug_assertions, test))]
pub(crate) fn statuses() -> Vec<CapabilityStatus> {
    let reasons = REASONS.lock().unwrap_or_else(|error| error.into_inner());
    Capability::ALL
        .into_iter()
        .map(|capability| {
            let state = STATES[capability as usize].load(Ordering::Acquire);
            CapabilityStatus {
                capability,
                ready: state == READY,
                initialized: state != UNKNOWN,
                reason: reasons
                    .iter()
                    .find_map(|(stored, reason)| (*stored == capability).then(|| reason.clone())),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_ready_and_disabled_capabilities() {
        set(Capability::LaunchEnvironment, true, "");
        disable_all(&[Capability::OverviewMetadata], "missing FillInAppOverview");

        assert!(is_ready(Capability::LaunchEnvironment));
        assert!(!is_ready(Capability::OverviewMetadata));
        let statuses = statuses();
        assert!(statuses.iter().any(|status| {
            status.capability == Capability::OverviewMetadata
                && status.initialized
                && status.reason.as_deref() == Some("missing FillInAppOverview")
        }));
    }

    #[test]
    fn requirement_failures_name_every_missing_dependency() {
        let ready = set_from_requirements(
            Capability::LibrarySnapshot,
            &[("BuildComplete", false), ("RepeatedField::Add", false)],
        );
        assert!(!ready);
        let status = statuses()
            .into_iter()
            .find(|status| status.capability == Capability::LibrarySnapshot)
            .unwrap();
        assert_eq!(
            status.reason.as_deref(),
            Some("missing BuildComplete, RepeatedField::Add")
        );
    }
}
