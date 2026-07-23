use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static LOCAL_IDENTITY: Mutex<LocalIdentity> = Mutex::new(LocalIdentity {
    steam_id64: 0,
    authoritative: false,
});
static IDENTITY_GENERATION: AtomicU64 = AtomicU64::new(0);

struct LocalIdentity {
    steam_id64: u64,
    authoritative: bool,
}

impl LocalIdentity {
    fn observe(&mut self, steam_id64: u64) -> bool {
        if !is_valid_individual_steam_id(steam_id64) || self.authoritative {
            return false;
        }
        let changed = self.steam_id64 != steam_id64;
        self.steam_id64 = steam_id64;
        changed
    }

    fn set_authoritative(&mut self, steam_id64: u64) -> bool {
        if steam_id64 != 0 && !is_valid_individual_steam_id(steam_id64) {
            return false;
        }
        let changed = self.steam_id64 != steam_id64;
        self.steam_id64 = steam_id64;
        self.authoritative = true;
        changed
    }
}

/// Record a non-zero SteamID observed on a Steam packet. Packet observations
/// cannot replace identity state already confirmed by IClientUser.
pub fn observe_steam_id(steam_id64: u64) -> bool {
    let changed = LOCAL_IDENTITY
        .lock()
        .is_ok_and(|mut identity| identity.observe(steam_id64));
    if changed {
        IDENTITY_GENERATION.fetch_add(1, Ordering::Relaxed);
    }
    changed
}

/// Record the current value returned by Steam's live IClientUser::GetSteamID.
/// Zero is meaningful and clears a stale account after logout.
pub fn set_authoritative_steam_id(steam_id64: u64) -> bool {
    let changed = LOCAL_IDENTITY
        .lock()
        .is_ok_and(|mut identity| identity.set_authoritative(steam_id64));
    if changed {
        IDENTITY_GENERATION.fetch_add(1, Ordering::Relaxed);
    }
    changed
}

pub fn steam_id() -> u64 {
    LOCAL_IDENTITY
        .lock()
        .map_or(0, |identity| identity.steam_id64)
}

/// Monotonic identity session generation. It changes on logout and account
/// switches even if a later login returns to the same SteamID.
pub fn generation() -> u64 {
    IDENTITY_GENERATION.load(Ordering::Relaxed)
}

pub fn is_valid_individual_steam_id(steam_id64: u64) -> bool {
    const ACCOUNT_TYPE_INDIVIDUAL: u64 = 1;
    let account_id = steam_id64 & 0xffff_ffff;
    let account_type = (steam_id64 >> 52) & 0xf;
    let universe = steam_id64 >> 56;
    account_id != 0 && account_type == ACCOUNT_TYPE_INDIVIDUAL && universe != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authoritative_identity_rejects_stale_packet_observations() {
        let mut identity = LocalIdentity {
            steam_id64: 0,
            authoritative: false,
        };
        let first = 76561198000000001;
        let second = 76561198000000002;
        assert!(identity.observe(first));
        assert!(!identity.set_authoritative(first));
        assert!(!identity.observe(second));
        assert_eq!(identity.steam_id64, first);
        assert!(identity.set_authoritative(0));
        assert!(!identity.observe(second));
        assert_eq!(identity.steam_id64, 0);
    }

    #[test]
    fn validates_individual_steam_id_layout() {
        assert!(is_valid_individual_steam_id(76561198106179127));
        assert!(!is_valid_individual_steam_id(0));
        assert!(!is_valid_individual_steam_id(0x0000_0001_0000_0001));
        assert!(!is_valid_individual_steam_id(0x0110_0001_0000_0000));
    }

    #[test]
    fn invalid_authoritative_value_does_not_poison_identity() {
        let mut identity = LocalIdentity {
            steam_id64: 0,
            authoritative: false,
        };
        assert!(!identity.set_authoritative(0x0000_0001_0000_0001));
        assert_eq!(identity.steam_id64, 0);
        assert!(!identity.authoritative);
        assert!(identity.observe(76561198106179127));
    }
}
