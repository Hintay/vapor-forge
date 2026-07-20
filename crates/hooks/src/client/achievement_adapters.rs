use core::ffi::{c_char, c_void};

use tracing::{debug, error};
use vapor_forge_hook_engine::detour::Detour;

use vapor_forge_hook_engine::detour::CodeRegion;
use vapor_forge_hook_engine::original::original_detour;

pub(crate) const SET_STAT_INT_NAME: &str = "CUserStats::SetStat(int32)";
pub(crate) const SET_STAT_FLOAT_NAME: &str = "CUserStats::SetStat(float)";
pub(crate) const SET_ACHIEVEMENT_NAME: &str = "CUserStats::SetAchievement";
pub(crate) const CLEAR_ACHIEVEMENT_NAME: &str = "CUserStats::ClearAchievement";
pub(crate) const STORE_STATS_NAME: &str = "CUserStats::StoreStats";
pub(crate) const PROGRESS_NAME: &str = "CUserStats::IndicateAchievementProgress";

const MAX_ACHIEVEMENT_KEY_LEN: usize = 128;

pub(crate) fn validate_adapter_target(code: &CodeRegion, name: &str, target: usize) -> bool {
    let Some(offset) = target.checked_sub(code.base) else {
        return false;
    };
    let Some(bytes) = code
        .bytes
        .get(offset..code.bytes.len().min(offset.saturating_add(0x240)))
    else {
        return false;
    };
    validate_adapter_bytes(name, bytes)
}

#[cfg(target_pointer_width = "32")]
fn validate_adapter_bytes(name: &str, bytes: &[u8]) -> bool {
    match name {
        SET_STAT_INT_NAME => validate_forwarding_adapter32(bytes, 0xe4),
        SET_STAT_FLOAT_NAME => validate_forwarding_adapter32(bytes, 0xe8),
        SET_ACHIEVEMENT_NAME => validate_forwarding_adapter32(bytes, 0xf0),
        CLEAR_ACHIEVEMENT_NAME => {
            validate_forwarding_adapter32(bytes, 0xf4)
                || (has_seq(bytes, &[0x83, 0xec, 0x5c])
                    && has_seq(bytes, &[0x8b, 0x74, 0x24, 0x70])
                    && has_seq(bytes, &[0x8b, 0x06, 0x8b, 0x80, 0xf4, 0x00, 0x00, 0x00])
                    && has_seq(bytes, &[0x8b, 0x44, 0x24, 0x7c, 0xf3, 0x0f, 0x7e, 0x00]))
        }
        STORE_STATS_NAME => {
            has_seq(bytes, &[0x55, 0x89, 0xe5, 0x57, 0x56, 0x53])
                && (has_seq(bytes, &[0x83, 0xec, 0x44]) || has_seq(bytes, &[0x83, 0xec, 0x54]))
                && has_seq(bytes, &[0x8b, 0x45, 0x0c])
                && (has_seq(bytes, &[0x8b, 0x30, 0x8b, 0x58, 0x04])
                    || has_seq(bytes, &[0x8b, 0x38, 0x8b, 0x40, 0x04]))
                && has_seq(bytes, &[0xc1, 0xe8, 0x18])
                && (has_seq(bytes, &[0xf7, 0xc6, 0xff, 0xff, 0xff, 0x00])
                    || has_seq(bytes, &[0xf7, 0xc7, 0xff, 0xff, 0xff, 0x00]))
        }
        PROGRESS_NAME => {
            let old_shape = has_seq(
                bytes,
                &[
                    0x83, 0xec, 0x2c, 0x8b, 0x44, 0x24, 0x40, 0x8b, 0x74, 0x24, 0x44, 0x8b, 0x4c,
                    0x24, 0x48, 0x8b, 0x7c, 0x24, 0x4c,
                ],
            ) && has_seq(bytes, &[0x0f, 0xb6, 0x46, 0x03]);
            let current_shape = has_seq(
                bytes,
                &[
                    0x81, 0xec, 0x0c, 0x01, 0x00, 0x00, 0x8b, 0x8c, 0x24, 0x24, 0x01, 0x00, 0x00,
                ],
            ) && has_seq(bytes, &[0x0f, 0xb6, 0x41, 0x03])
                && has_seq(bytes, &[0x39, 0xbc, 0x24, 0x2c, 0x01, 0x00, 0x00]);
            (old_shape || current_shape)
                && has_seq(bytes, &[0x3c, 0x01])
                && has_seq(bytes, &[0x3c, 0x02])
        }
        _ => false,
    }
}

#[cfg(target_pointer_width = "32")]
fn validate_forwarding_adapter32(bytes: &[u8], implementation_slot: u8) -> bool {
    let old_shape = has_seq(
        bytes,
        &[
            0x83,
            0xec,
            0x38,
            0x8b,
            0x6c,
            0x24,
            0x4c,
            0x8b,
            0x45,
            0x00,
            0x8b,
            0x80,
            implementation_slot,
            0x00,
            0x00,
            0x00,
        ],
    ) && has_seq(bytes, &[0xff, 0xd0, 0x83, 0xc4, 0x4c]);
    let current_shape = has_seq(bytes, &[0x83, 0xec, 0x48])
        && has_seq(bytes, &[0x8b, 0x74, 0x24, 0x5c, 0x8b, 0x06])
        && bytes.windows(6).any(|window| {
            window[0] == 0x8b && window[2..] == [implementation_slot, 0x00, 0x00, 0x00]
        })
        && has_seq(bytes, &[0x8b, 0x44, 0x24, 0x60, 0xf3, 0x0f, 0x7e, 0x00])
        && has_seq(bytes, &[0xff, 0xd7, 0x83, 0xc4, 0x20]);
    old_shape || current_shape
}

#[cfg(target_pointer_width = "64")]
fn validate_adapter_bytes(name: &str, bytes: &[u8]) -> bool {
    let semantics = match name {
        SET_STAT_INT_NAME => has_vtable_load64(bytes, 0x1c8),
        SET_STAT_FLOAT_NAME => has_vtable_load64(bytes, 0x1d0),
        SET_ACHIEVEMENT_NAME => has_vtable_load64(bytes, 0x1e0),
        CLEAR_ACHIEVEMENT_NAME => has_vtable_load64(bytes, 0x1e8),
        STORE_STATS_NAME => {
            has_seq(bytes, &[0x48, 0xc1, 0xe8, 0x18])
                && has_seq(bytes, &[0x3c, 0x01])
                && has_seq(bytes, &[0x3c, 0x02])
        }
        PROGRESS_NAME => {
            has_seq(bytes, &[0x0f, 0xb6, 0x46, 0x03])
                && has_seq(bytes, &[0x3c, 0x01])
                && has_seq(bytes, &[0x3c, 0x02])
        }
        _ => false,
    };
    semantics && dereferences_cgameid64(bytes)
}

#[cfg(target_pointer_width = "64")]
fn has_vtable_load64(bytes: &[u8], displacement: u32) -> bool {
    let displacement = displacement.to_le_bytes();
    bytes.windows(7).any(|window| {
        (window[0] == 0x48 || window[0] == 0x4c) && window[1] == 0x8b && window[3..] == displacement
    })
}

#[cfg(target_pointer_width = "64")]
fn dereferences_cgameid64(bytes: &[u8]) -> bool {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};

    let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
    let mut aliases = std::collections::HashSet::from([Register::RSI]);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if instruction.op1_kind() == OpKind::Memory
            && instruction.memory_displacement64() <= 7
            && aliases.contains(&instruction.memory_base())
        {
            return true;
        }
        if instruction.mnemonic() == Mnemonic::Mov && instruction.op0_kind() == OpKind::Register {
            let destination = instruction.op0_register();
            if instruction.op1_kind() == OpKind::Register
                && aliases.contains(&instruction.op1_register())
            {
                aliases.insert(destination);
            } else {
                aliases.remove(&destination);
            }
        }
    }
    false
}

fn has_seq(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

pub(crate) type SetStatIntFn =
    unsafe extern "C" fn(*mut c_void, *const u64, *const c_char, i32) -> u8;
pub(crate) type SetStatFloatFn =
    unsafe extern "C" fn(*mut c_void, *const u64, *const c_char, f32) -> u8;
pub(crate) type SetAchievementFn =
    unsafe extern "C" fn(*mut c_void, *const u64, *const c_char) -> u8;
pub(crate) type StoreStatsFn = unsafe extern "C" fn(*mut c_void, *const u64) -> u8;
pub(crate) type IndicateAchievementProgressFn =
    unsafe extern "C" fn(*mut c_void, *const u64, *const c_char, u32, u32) -> u8;

pub(crate) static mut SET_STAT_INT_DETOUR: Option<Detour<SetStatIntFn>> = None;
pub(crate) static mut SET_STAT_FLOAT_DETOUR: Option<Detour<SetStatFloatFn>> = None;
pub(crate) static mut SET_ACHIEVEMENT_DETOUR: Option<Detour<SetAchievementFn>> = None;
pub(crate) static mut CLEAR_ACHIEVEMENT_DETOUR: Option<Detour<SetAchievementFn>> = None;
pub(crate) static mut STORE_STATS_DETOUR: Option<Detour<StoreStatsFn>> = None;
pub(crate) static mut PROGRESS_DETOUR: Option<Detour<IndicateAchievementProgressFn>> = None;

pub(crate) unsafe extern "C" fn hook_set_stat_int(
    this: *mut c_void,
    game_id: *const u64,
    stat_name: *const c_char,
    value: i32,
) -> u8 {
    let identity = owner_and_app(game_id);
    // SAFETY: installation initializes this process-lifetime slot before
    // enabling the detour and never moves it afterward.
    let Some(original) =
        (unsafe { original_detour(SET_STAT_INT_NAME, std::ptr::addr_of!(SET_STAT_INT_DETOUR)) })
    else {
        return 0;
    };
    let accepted = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, game_id, stat_name, value) };
    if accepted != 0 {
        observe_stat_write(identity);
    }
    accepted
}

pub(crate) unsafe extern "C" fn hook_set_stat_float(
    this: *mut c_void,
    game_id: *const u64,
    stat_name: *const c_char,
    value: f32,
) -> u8 {
    let identity = owner_and_app(game_id);
    // SAFETY: see hook_set_stat_int.
    let Some(original) = (unsafe {
        original_detour(
            SET_STAT_FLOAT_NAME,
            std::ptr::addr_of!(SET_STAT_FLOAT_DETOUR),
        )
    }) else {
        return 0;
    };
    let accepted = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, game_id, stat_name, value) };
    if accepted != 0 {
        observe_stat_write(identity);
    }
    accepted
}

pub(crate) unsafe extern "C" fn hook_set_achievement(
    this: *mut c_void,
    game_id: *const u64,
    achievement_key: *const c_char,
) -> u8 {
    let identity = achievement_identity(game_id, achievement_key);
    // SAFETY: see hook_set_stat_int.
    let Some(original) = (unsafe {
        original_detour(
            SET_ACHIEVEMENT_NAME,
            std::ptr::addr_of!(SET_ACHIEVEMENT_DETOUR),
        )
    }) else {
        return 0;
    };
    let accepted = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, game_id, achievement_key) };
    debug!(accepted, "achievement receiver: SetAchievement observed");
    if accepted != 0 {
        if let Some((owner, app_id, key)) = identity {
            super::achievement::stage_set(owner, app_id, &key);
        }
    }
    accepted
}

pub(crate) unsafe extern "C" fn hook_clear_achievement(
    this: *mut c_void,
    game_id: *const u64,
    achievement_key: *const c_char,
) -> u8 {
    let identity = achievement_identity(game_id, achievement_key);
    // SAFETY: see hook_set_stat_int.
    let Some(original) = (unsafe {
        original_detour(
            CLEAR_ACHIEVEMENT_NAME,
            std::ptr::addr_of!(CLEAR_ACHIEVEMENT_DETOUR),
        )
    }) else {
        return 0;
    };
    let accepted = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, game_id, achievement_key) };
    debug!(accepted, "achievement receiver: ClearAchievement observed");
    if accepted != 0 {
        if let Some((owner, app_id, key)) = identity {
            super::achievement::stage_clear(owner, app_id, &key);
        }
    }
    accepted
}

pub(crate) unsafe extern "C" fn hook_store_stats(this: *mut c_void, game_id: *const u64) -> u8 {
    let identity = owner_and_app(game_id);
    // SAFETY: see hook_set_stat_int.
    let Some(original) =
        (unsafe { original_detour(STORE_STATS_NAME, std::ptr::addr_of!(STORE_STATS_DETOUR)) })
    else {
        return 0;
    };
    let accepted = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, game_id) };
    debug!(accepted, "achievement receiver: StoreStats observed");
    if accepted != 0 {
        if let Some((owner, app_id)) = identity {
            super::achievement::commit_store(owner, app_id);
        }
    }
    accepted
}

pub(crate) unsafe extern "C" fn hook_progress(
    this: *mut c_void,
    game_id: *const u64,
    achievement_key: *const c_char,
    current: u32,
    maximum: u32,
) -> u8 {
    let identity = achievement_identity(game_id, achievement_key);
    // SAFETY: see hook_set_stat_int.
    let Some(original) =
        (unsafe { original_detour(PROGRESS_NAME, std::ptr::addr_of!(PROGRESS_DETOUR)) })
    else {
        return 0;
    };
    let accepted = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, game_id, achievement_key, current, maximum) };
    debug!(
        accepted,
        "achievement receiver: IndicateAchievementProgress observed"
    );
    if accepted == 0 {
        return accepted;
    }
    let Some((owner, app_id, key)) = identity else {
        return accepted;
    };
    if current > maximum || maximum == 0 {
        debug!(
            app_id,
            current, maximum, "achievement progress ignored: invalid range"
        );
        return accepted;
    }
    if !super::achievement::observe_progress(owner, app_id, &key, current, maximum) {
        debug!(
            app_id,
            key, current, maximum, "achievement progress not queued"
        );
    }
    accepted
}

fn observe_stat_write(identity: Option<(u64, u32)>) {
    if let Some((owner, app_id)) = identity {
        super::achievement::observe_stat_write(owner, app_id);
    }
}

fn achievement_identity(
    game_id: *const u64,
    achievement_key: *const c_char,
) -> Option<(u64, u32, String)> {
    let (owner, app_id) = owner_and_app(game_id)?;
    bounded_key(achievement_key).map(|key| (owner, app_id, key))
}

fn owner_and_app(game_id: *const u64) -> Option<(u64, u32)> {
    let Some(app_id) = explicit_app_id(game_id) else {
        debug!("achievement event ignored: CGameID unavailable");
        return None;
    };
    let owner = vapor_forge_features::identity::steam_id();
    if owner == 0 {
        debug!(app_id, "achievement event ignored: SteamID unavailable");
        return None;
    }
    Some((owner, app_id))
}

fn explicit_app_id(game_id: *const u64) -> Option<u32> {
    if game_id.is_null() {
        return None;
    }
    // SAFETY: CUserStats supplies a live CGameID pointer for this call.
    let app_id = unsafe { game_id.read() as u32 } & 0x00ff_ffff;
    (app_id != 0).then_some(app_id)
}

fn bounded_key(key: *const c_char) -> Option<String> {
    if key.is_null() {
        return None;
    }
    let mut bytes = Vec::new();
    for index in 0..MAX_ACHIEVEMENT_KEY_LEN {
        // SAFETY: CUserStats supplies a live NUL-terminated name for this call.
        let byte = unsafe { key.add(index).read() } as u8;
        if byte == 0 {
            return (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte);
    }
    error!("achievement event ignored: key is not NUL-terminated");
    None
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn extracts_cgameid_app_id_and_bounded_key() {
        let game_id = (1u64 << 24) | 736260;
        let key = CString::new("BABA_ABSTRACT").unwrap();
        assert_eq!(explicit_app_id(&game_id), Some(736260));
        assert_eq!(bounded_key(key.as_ptr()), Some("BABA_ABSTRACT".into()));
    }

    #[test]
    fn rejects_missing_or_unterminated_arguments() {
        let unterminated = [b'A' as c_char; MAX_ACHIEVEMENT_KEY_LEN];
        assert_eq!(explicit_app_id(std::ptr::null()), None);
        assert_eq!(bounded_key(std::ptr::null()), None);
        assert_eq!(bounded_key(unterminated.as_ptr()), None);
    }
}
