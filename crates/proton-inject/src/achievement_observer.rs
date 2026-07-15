use std::ffi::{c_char, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::detour::PreparedDetour;
use crate::{ipc, loader::log, maps, pe};

type SetAchievementFn =
    unsafe extern "win64" fn(instance: isize, achievement_name: *const c_char) -> bool;
type StoreStatsFn = unsafe extern "win64" fn(instance: isize) -> bool;
type IndicateProgressFn = unsafe extern "win64" fn(
    instance: isize,
    achievement_name: *const c_char,
    current: u32,
    maximum: u32,
) -> bool;
type GetAchievementAndUnlockTimeFn = unsafe extern "win64" fn(
    instance: isize,
    achievement_name: *const c_char,
    achieved: *mut bool,
    unlock_time: *mut u32,
) -> bool;
static INSTALL_LOCK: Mutex<()> = Mutex::new(());
static SET_ACHIEVEMENT_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static CLEAR_ACHIEVEMENT_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static INDICATE_PROGRESS_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static STORE_STATS_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static GET_ACHIEVEMENT_AND_UNLOCK_TIME: AtomicUsize = AtomicUsize::new(0);
static ACHIEVEMENT_STATE: OnceLock<Mutex<vapor_forge_game_bridge::AchievementCommitBuffer>> =
    OnceLock::new();

pub fn install_for_module(dll_name: &str, base_address: usize) {
    if !dll_name.eq_ignore_ascii_case("steam_api64.dll") || base_address == 0 {
        return;
    }
    let Ok(_guard) = INSTALL_LOCK.lock() else {
        return;
    };
    let entries = maps::parse_self_maps();
    let Some(path) = maps::module_path_at(&entries, base_address) else {
        log("achievement observer: steam_api64 path unavailable");
        return;
    };
    let Ok(bytes) = std::fs::read(path) else {
        log("achievement observer: steam_api64 image unreadable");
        return;
    };
    if let Some(target) = export_address(
        &bytes,
        base_address,
        "SteamAPI_ISteamUserStats_GetAchievementAndUnlockTime",
    ) {
        GET_ACHIEVEMENT_AND_UNLOCK_TIME.store(target, Ordering::Release);
    }
    install_export(
        &bytes,
        base_address,
        "SteamAPI_ISteamUserStats_SetAchievement",
        hook_set_achievement as *const () as usize,
        &SET_ACHIEVEMENT_TRAMPOLINE,
    );
    install_export(
        &bytes,
        base_address,
        "SteamAPI_ISteamUserStats_ClearAchievement",
        hook_clear_achievement as *const () as usize,
        &CLEAR_ACHIEVEMENT_TRAMPOLINE,
    );
    install_export(
        &bytes,
        base_address,
        "SteamAPI_ISteamUserStats_IndicateAchievementProgress",
        hook_indicate_progress as *const () as usize,
        &INDICATE_PROGRESS_TRAMPOLINE,
    );
    install_export(
        &bytes,
        base_address,
        "SteamAPI_ISteamUserStats_StoreStats",
        hook_store_stats as *const () as usize,
        &STORE_STATS_TRAMPOLINE,
    );
}

fn export_address(image: &[u8], base_address: usize, export: &str) -> Option<usize> {
    let rva = pe::find_export_rva(image, export)?;
    base_address.checked_add(rva as usize)
}

fn install_export(
    image: &[u8],
    base_address: usize,
    export: &str,
    hook: usize,
    trampoline_slot: &AtomicUsize,
) {
    if trampoline_slot.load(Ordering::Acquire) != 0 {
        return;
    }
    let Some(target) = export_address(image, base_address, export) else {
        return;
    };
    // SAFETY: target is an exported function in the mapped steam_api64 image.
    let Some(prepared) = (unsafe { PreparedDetour::prepare(target, hook) }) else {
        log("achievement observer: detour preparation failed");
        return;
    };
    let trampoline = prepared.trampoline();
    trampoline_slot.store(trampoline, Ordering::Release);
    // SAFETY: installation is serialized and the trampoline is published.
    if unsafe { prepared.activate() }.is_none() {
        let _ =
            trampoline_slot.compare_exchange(trampoline, 0, Ordering::AcqRel, Ordering::Acquire);
        log("achievement observer: detour activation failed");
        return;
    }
    log(&format!("achievement observer installed: {export}"));
}

unsafe extern "win64" fn hook_set_achievement(
    instance: isize,
    achievement_name: *const c_char,
) -> bool {
    let trampoline = SET_ACHIEVEMENT_TRAMPOLINE.load(Ordering::Acquire);
    if trampoline == 0 {
        return false;
    }
    // SAFETY: the trampoline was created from a function with this exact ABI.
    let original: SetAchievementFn = unsafe { std::mem::transmute(trampoline) };
    // SAFETY: arguments are forwarded unchanged to the original export.
    let success = unsafe { original(instance, achievement_name) };
    if success {
        // SAFETY: a successful Steam API call consumed this NUL-terminated key.
        if let Some(name) = unsafe { bounded_name(achievement_name) } {
            let _ = achievement_state()
                .lock()
                .map(|mut state| state.stage_unlock(&name));
        }
    }
    success
}

unsafe extern "win64" fn hook_clear_achievement(
    instance: isize,
    achievement_name: *const c_char,
) -> bool {
    let trampoline = CLEAR_ACHIEVEMENT_TRAMPOLINE.load(Ordering::Acquire);
    if trampoline == 0 {
        return false;
    }
    // SAFETY: the trampoline was created from a function with this exact ABI.
    let original: SetAchievementFn = unsafe { std::mem::transmute(trampoline) };
    // SAFETY: arguments are forwarded unchanged to the original export.
    let success = unsafe { original(instance, achievement_name) };
    if success {
        // SAFETY: a successful Steam API call consumed this NUL-terminated key.
        if let Some(name) = unsafe { bounded_name(achievement_name) } {
            if let Ok(mut state) = achievement_state().lock() {
                state.clear(&name);
            }
        }
    }
    success
}

unsafe extern "win64" fn hook_indicate_progress(
    instance: isize,
    achievement_name: *const c_char,
    current: u32,
    maximum: u32,
) -> bool {
    let trampoline = INDICATE_PROGRESS_TRAMPOLINE.load(Ordering::Acquire);
    if trampoline == 0 {
        return false;
    }
    // SAFETY: the trampoline was created from a function with this exact ABI.
    let original: IndicateProgressFn = unsafe { std::mem::transmute(trampoline) };
    // SAFETY: arguments are forwarded unchanged to the original export.
    let success = unsafe { original(instance, achievement_name, current, maximum) };
    if success && maximum > 0 && current <= maximum {
        // SAFETY: a successful Steam API call consumed this NUL-terminated key.
        if let Some(name) = unsafe { bounded_name(achievement_name) } {
            let _ = achievement_state()
                .lock()
                .map(|mut state| state.stage_progress(&name, current, maximum));
        }
    }
    success
}

unsafe extern "win64" fn hook_store_stats(instance: isize) -> bool {
    let trampoline = STORE_STATS_TRAMPOLINE.load(Ordering::Acquire);
    if trampoline == 0 {
        return false;
    }
    // SAFETY: the trampoline was created from a function with this exact ABI.
    let original: StoreStatsFn = unsafe { std::mem::transmute(trampoline) };
    // SAFETY: the argument is forwarded unchanged to the original export.
    let success = unsafe { original(instance) };
    if success {
        flush_committed(instance);
    }
    success
}

fn flush_committed(instance: isize) {
    let pending = match achievement_state().lock() {
        Ok(state) => state.pending(),
        Err(_) => return,
    };
    for event in pending {
        let sent = match &event {
            vapor_forge_game_bridge::PendingAchievement::Unlock { key } => {
                let Some(unlocked_at) = achievement_unlock_time(instance, key) else {
                    log(&format!(
                        "achievement observer: unlock time unavailable for {key}"
                    ));
                    continue;
                };
                ipc::send_achievement_unlocked(key, unlocked_at)
            }
            vapor_forge_game_bridge::PendingAchievement::Progress {
                key,
                current,
                maximum,
            } => ipc::send_achievement_progress(key, *current, *maximum),
        };
        if sent {
            if let Ok(mut state) = achievement_state().lock() {
                state.mark_sent(&event);
            }
        }
    }
}

fn achievement_unlock_time(instance: isize, key: &str) -> Option<i64> {
    let address = GET_ACHIEVEMENT_AND_UNLOCK_TIME.load(Ordering::Acquire);
    if address == 0 {
        return None;
    }
    let key = CString::new(key).ok()?;
    let mut achieved = false;
    let mut unlock_time = 0_u32;
    // SAFETY: the address is the matching export from the same live steam_api64 module.
    let get: GetAchievementAndUnlockTimeFn = unsafe { std::mem::transmute(address) };
    // SAFETY: all pointers reference live stack/CString storage for the duration of the call.
    let success = unsafe { get(instance, key.as_ptr(), &mut achieved, &mut unlock_time) };
    (success && achieved && unlock_time > 0).then_some(i64::from(unlock_time))
}

fn achievement_state() -> &'static Mutex<vapor_forge_game_bridge::AchievementCommitBuffer> {
    ACHIEVEMENT_STATE.get_or_init(|| Mutex::new(Default::default()))
}

unsafe fn bounded_name(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut bytes = Vec::new();
    for index in 0..vapor_forge_game_bridge::MAX_ACHIEVEMENT_KEY_LEN {
        // SAFETY: Steam accepted pointer as a C string for the original call.
        let byte = unsafe { *pointer.add(index) } as u8;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}
