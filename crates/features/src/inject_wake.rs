//! Cross-crate hook for the per-source injection dispatch.
//!
//! Each fabricated-response source lives here in `features`, but the injection
//! machinery (packet construction + delivery on the worker thread) lives in the
//! hooks crate. When a source produces a response it calls [`wake`] with its
//! [`InjectionSource`]; the hooks crate registers a router that drains that one
//! source and dispatches it immediately, instead of a collective sweep driven by
//! the next inbound packet.

use std::sync::OnceLock;

/// Identifies which response source just produced work, so the registered
/// router drains only that source rather than scanning all of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InjectionSource {
    /// Manifest request-code responses (async fetch completion).
    Manifest,
    /// Client cloud RPC responses (async worker completion).
    Cloud,
    /// Offline achievement stat responses.
    Achievements,
    /// Manufactured rich-presence PersonaState.
    RichPresence,
}

type Router = Box<dyn Fn(InjectionSource) + Send + Sync>;
type GenerationProvider = Box<dyn Fn() -> u64 + Send + Sync>;

static ROUTER: OnceLock<Router> = OnceLock::new();
static GENERATION_PROVIDER: OnceLock<GenerationProvider> = OnceLock::new();

/// Register the per-source injection router. Called once by the hooks crate at
/// install time.
pub fn set_injection_router(router: Router) {
    let _ = ROUTER.set(router);
}

/// Register the native connection generation captured with fabricated responses.
pub fn set_injection_generation_provider(provider: GenerationProvider) {
    let _ = GENERATION_PROVIDER.set(provider);
}

pub fn injection_generation() -> u64 {
    GENERATION_PROVIDER.get().map_or(0, |provider| provider())
}

/// Dispatch the given source's completed responses now. A no-op until the router
/// is registered (before that, sources keep their responses queued and the
/// warmup flush picks them up once dispatch is ready).
pub fn wake(source: InjectionSource) {
    if let Some(router) = ROUTER.get() {
        router(source);
    }
}
