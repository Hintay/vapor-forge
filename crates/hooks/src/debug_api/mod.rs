#![forbid(unsafe_code)]

mod command;
mod server;
mod toast_args;

#[cfg(test)]
mod tests;

const DEFAULT_TOAST_BODY: &str = "Debug API toast";
const DEFAULT_DURATION_MS: u32 = 5000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DebugTarget {
    SteamClient,
    SteamUi,
}

impl DebugTarget {
    fn name(self) -> &'static str {
        match self {
            DebugTarget::SteamClient => "steamclient",
            DebugTarget::SteamUi => "steamui",
        }
    }
}

pub fn start() {
    server::start();
}
