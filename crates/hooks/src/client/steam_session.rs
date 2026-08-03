use core::ffi::{c_char, c_void};
use std::sync::Arc;

use tracing::debug;

use super::callback_dispatch::USER_STATS_RECEIVED;
use super::callback_notify;
use super::steam_context::CapturedInterfaces;
use super::user_stats::{
    AchievementSnapshot, AchievementState, SnapshotLayout, SnapshotStatKind, StatState,
    WorkerShared,
};
use vapor_forge_features::playtime::{PlaytimeGame, PlaytimeSnapshot};

const TIER0_SONAME: &[u8] = b"libtier0_s.so\0";
const CREATE_SIMPLE_THREAD: &[u8] = b"_ZN16SteamThreadTools18CreateSimpleThreadEPFjPvES0_Pjj\0";
const RELEASE_THREAD_HANDLE: &[u8] = b"ReleaseThreadHandle\0";
const THREAD_SET_DEBUG_NAME: &[u8] = b"ThreadSetDebugName\0";
const THREAD_NAME: &[u8] = b"vapor-user-stats\0";
const MAX_ACHIEVEMENTS: u32 = 10_000;
const MAX_STATS: u32 = 10_000;
const MAX_ACHIEVEMENT_KEY_LEN: usize = 255;
/// `k_EResultOK`.
pub(super) const ERESULT_OK: i32 = 1;
/// Bounds one callback batch without dropping the remaining events.
pub(super) const MAX_DRAIN_PER_TICK: usize = 256;

type SteamThreadEntry = unsafe extern "C" fn(*mut c_void) -> u32;
type CreateSimpleThreadFn =
    unsafe extern "C" fn(SteamThreadEntry, *mut c_void, *mut u32, u32) -> usize;
type ReleaseThreadHandleFn = unsafe extern "C" fn(usize) -> bool;
type ThreadSetDebugNameFn = unsafe extern "C" fn(*const c_char);

// Read-only playtime accessors, never detoured: playtime is corrected at the
// ingest side. See docs/developer/steam-playtime-source-analysis.md.
type BGetAppMinutesPlayedFn = unsafe extern "C" fn(*mut c_void, u32, *mut i32, *mut i32) -> bool;
type GetAppLastPlayedTimeFn = unsafe extern "C" fn(*mut c_void, u32) -> u32;
type GetNumStatsFn = unsafe extern "C" fn(*mut c_void, *const u64) -> u32;
type GetStatNameFn = unsafe extern "C" fn(*mut c_void, *const u64, u32) -> *const c_char;
type GetStatTypeFn = unsafe extern "C" fn(*mut c_void, *const u64, *const c_char) -> i32;
type GetStatIntFn = unsafe extern "C" fn(*mut c_void, *const u64, *const c_char, *mut i32) -> bool;
type GetStatFloatFn =
    unsafe extern "C" fn(*mut c_void, *const u64, *const c_char, *mut f32) -> bool;
type GetNumAchievementsFn = unsafe extern "C" fn(*mut c_void, *const u64) -> u32;
type GetAchievementNameFn = unsafe extern "C" fn(*mut c_void, *const u64, u32) -> *const c_char;
/// Slot 22. It names the user and returns the completion handle.
type RequestUserStatsFn = unsafe extern "C" fn(*mut c_void, u64, *const u64) -> u64;
type GetAchievementFn =
    unsafe extern "C" fn(*mut c_void, *const u64, *const c_char, *mut bool, *mut u32) -> bool;

/// What one `RequestUserStats` probe observed.
#[cfg(any(debug_assertions, test))]
pub(crate) struct UserStatsProbe {
    pub(crate) api_call: u64,
    pub(crate) stat_count: u32,
    pub(crate) achievement_count: u32,
    pub(crate) samples: Vec<String>,
}

/// Slot layout of Steam's `IClientUserStats` interface vtable.
///
/// Slot 6 is `DeprecatedPublic_RequestCurrentStats`, which sits between
/// `RequestCurrentStats` and `GetStat(int32)`. Omitting it shifted every later
/// accessor down by one: `get_stat_int` reached
/// `DeprecatedPublic_RequestCurrentStats`, which ignores the trailing arguments
/// and leaves the output untouched, so every integer stat read back as zero, and
/// `get_stat_float` reached `GetStat(int32)`, which writes an `i32` bit pattern
/// into an `f32`. The padding run happened to keep `get_achievement` correct.
///
/// Slots below were read off the live interface vtable, whose entries name
/// themselves: 0 GetNumStats, 1 GetStatName, 2 GetStatType,
/// 3 GetNumAchievements, 4 GetAchievementName, 5 RequestCurrentStats,
/// 6 DeprecatedPublic_RequestCurrentStats, 7 GetStat(int32), 8 GetStat(float),
/// 9 SetStat(int32), 10 SetStat(float), 11 UpdateAvgRateStat, 12 GetAchievement,
/// 13 SetAchievement, 14 ClearAchievement, 15 GetAchievementProgress,
/// 16 StoreStats, 17 GetAchievementIcon, 18 BGetAchievementIconURL,
/// 19 GetAchievementDisplayAttribute, 20 IndicateAchievementProgress,
/// 21 SetMaxStatsLoaded, 22 RequestUserStats.
///
/// The same order was independently recovered from the 64-bit build, where the
/// interface vtable sits at 0x2b0a2b8 and its 55 method-name strings form a closed
/// block, so no slot in this range is unaccounted for.
#[repr(C)]
struct ClientUserStatsVTable {
    get_num_stats: GetNumStatsFn,
    get_stat_name: GetStatNameFn,
    get_stat_type: GetStatTypeFn,
    get_num_achievements: GetNumAchievementsFn,
    get_achievement_name: GetAchievementNameFn,
    /// `RequestCurrentStats`. Slot 22 is used because it returns a handle.
    _request_current_stats: usize,
    _deprecated_request_current_stats: usize,
    get_stat_int: GetStatIntFn,
    get_stat_float: GetStatFloatFn,
    /// `SetStat(int32)`, `SetStat(float)`, `UpdateAvgRateStat`. Average-rate
    /// stats have their own setter here, so a float setter alone cannot cover
    /// them.
    _setters_9_11: [usize; 3],
    get_achievement: GetAchievementFn,
    /// 13 SetAchievement, 14 ClearAchievement, 15 GetAchievementProgress,
    /// 16 StoreStats, 17 GetAchievementIcon, 18 BGetAchievementIconURL,
    /// 19 GetAchievementDisplayAttribute, 20 IndicateAchievementProgress,
    /// 21 SetMaxStatsLoaded.
    _slots_13_21: [usize; 9],
    request_user_stats: RequestUserStatsFn,
}

struct SteamThreadContext {
    name: &'static [u8],
    entry: Box<dyn FnOnce() + Send>,
    set_debug_name: Option<ThreadSetDebugNameFn>,
}

/// Run `entry` on a SteamThreadTools thread. `name` must be NUL-terminated.
fn spawn_steam_thread(name: &'static [u8], entry: impl FnOnce() + Send + 'static) -> bool {
    let Some(module) = LoadedModule::open(TIER0_SONAME) else {
        return false;
    };
    // SAFETY: these are exported SteamThreadTools functions with the declared ABI.
    let create = unsafe { create_simple_thread_fn(module.symbol(CREATE_SIMPLE_THREAD)) };
    // SAFETY: same SteamThreadTools ABI as above.
    let release = unsafe { release_thread_handle_fn(module.symbol(RELEASE_THREAD_HANDLE)) };
    // SAFETY: optional C-linkage helper exported by tier0.
    let set_debug_name = unsafe { thread_set_debug_name_fn(module.symbol(THREAD_SET_DEBUG_NAME)) };
    let (Some(create), Some(release)) = (create, release) else {
        return false;
    };

    let context = Box::new(SteamThreadContext {
        name,
        entry: Box::new(entry),
        set_debug_name,
    });
    let raw_context = Box::into_raw(context);
    // SAFETY: raw_context owns one context and the entrypoint takes ownership on success.
    let handle = unsafe {
        create(
            steam_thread_entry,
            raw_context.cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if handle == 0 {
        // SAFETY: thread creation failed, so ownership was not transferred.
        drop(unsafe { Box::from_raw(raw_context) });
        return false;
    }
    // SAFETY: handle is the valid join handle returned by CreateSimpleThread.
    let _ = unsafe { release(handle) };
    true
}

pub(super) fn spawn_user_stats_worker(shared: Arc<WorkerShared>) -> bool {
    spawn_steam_thread(THREAD_NAME, move || super::user_stats::run_worker(&shared))
}

unsafe extern "C" fn steam_thread_entry(context: *mut c_void) -> u32 {
    if context.is_null() {
        return 1;
    }
    // SAFETY: spawn_steam_thread transferred one Box<SteamThreadContext> here.
    let context = unsafe { Box::from_raw(context.cast::<SteamThreadContext>()) };
    if let Some(set_debug_name) = context.set_debug_name {
        // SAFETY: the name is a process-lifetime NUL-terminated string.
        unsafe { set_debug_name(context.name.as_ptr().cast()) };
    }
    (context.entry)();
    0
}

/// A generation-bound view of Steam's owner-managed global-user wrappers.
pub(super) struct SteamUserStatsSession {
    captured: CapturedInterfaces,
    client_user: *mut c_void,
    stats: *mut c_void,
    stats_vtable: *const ClientUserStatsVTable,
}

impl SteamUserStatsSession {
    pub(super) fn connect() -> Result<Self, &'static str> {
        if !callback_notify::hooks_ready() {
            return Err("callback hooks are unavailable");
        }
        let captured =
            super::steam_context::capture().ok_or("Steam interface context unavailable")?;
        if captured.stats.is_null() {
            return Err("IClientUserStats context unavailable");
        }
        let stats_vtable = super::steam_context::checked_call(captured, || {
            // SAFETY: owner discovery captured this live IClientUserStats wrapper.
            unsafe { object_vtable::<ClientUserStatsVTable>(captured.stats) }
        })?
        .ok_or("IClientUserStats vtable is unavailable")?;
        let session = Self {
            captured,
            client_user: captured.user,
            stats: captured.stats,
            stats_vtable,
        };
        callback_notify::activate_session(captured.revision);
        Ok(session)
    }

    fn refresh_identity(&self) -> Result<u64, &'static str> {
        self.ensure_current()?;
        Ok(self.captured.steam_id64)
    }

    pub(super) fn user(&self) -> i32 {
        self.captured.steam_user
    }

    pub(super) fn is_current(&self) -> bool {
        super::steam_context::is_current(self.captured)
    }

    fn ensure_current(&self) -> Result<(), &'static str> {
        self.is_current()
            .then_some(())
            .ok_or("Steam interface context changed")
    }

    fn checked_call<T>(&self, call: impl FnOnce() -> T) -> Result<T, &'static str> {
        super::steam_context::checked_call(self.captured, call)
    }

    pub(super) fn playtime_snapshot(&self, app_id: u32) -> Result<PlaytimeSnapshot, &'static str> {
        if app_id == 0 {
            return Err("AppID is invalid");
        }
        // The notification arrives after Steam updates its playtime data.
        let steam_id64 = self.refresh_identity()?;
        let get_minutes = self
            .bget_app_minutes_played()?
            .ok_or("IClientUser::BGetAppMinutesPlayed is unavailable")?;
        let mut total = 0i32;
        let mut two_weeks = 0i32;
        // SAFETY: the function pointer was read from the live IClientUser vtable
        // slot named by Steam RTTI, and both out-pointers are live locals.
        let got_minutes = self.checked_call(|| {
            // SAFETY: the function pointer belongs to this captured wrapper and
            // both output pointers reference live locals.
            unsafe { get_minutes(self.client_user, app_id, &mut total, &mut two_weeks) }
        })?;
        if !got_minutes {
            return Err("BGetAppMinutesPlayed returned false");
        }
        let playtime_minutes =
            u32::try_from(total).map_err(|_| "BGetAppMinutesPlayed returned negative total")?;
        let playtime_2weeks_minutes = u32::try_from(two_weeks)
            .map_err(|_| "BGetAppMinutesPlayed returned negative two-week total")?;
        let last_played_at = match self.get_app_last_played_time()? {
            Some(get_last_played) => Some(self.checked_call(|| {
                // SAFETY: the function pointer belongs to this captured
                // wrapper and takes only value arguments.
                unsafe { get_last_played(self.client_user, app_id) }
            })?),
            None => None,
        }
        .filter(|value| *value != 0)
        .map(i64::from);
        debug!(
            app_id,
            playtime_minutes,
            playtime_2weeks_minutes,
            "user-stats native playtime snapshot complete"
        );
        Ok(PlaytimeSnapshot {
            steam_id64,
            games: vec![PlaytimeGame {
                app_id,
                playtime_minutes,
                playtime_2weeks_minutes,
                last_played_at,
            }],
        })
    }

    /// Issue one stats request and return its completion handle.
    ///
    /// A matching `SetAPICallResult` event carries the copied result payload.
    ///
    /// Passing our own SteamID asks for our own stats: the argument names a user, it
    /// does not restrict this to other users.
    pub(super) fn request_stats(&self, app_id: u32, steam_id64: u64) -> Result<u64, &'static str> {
        if app_id == 0 {
            return Err("AppID is invalid");
        }
        if steam_id64 == 0 {
            return Err("SteamID is unavailable");
        }
        if !callback_notify::begin_api_call(self.captured.revision, USER_STATS_RECEIVED) {
            return Err("RequestUserStats issue window could not be registered");
        }
        let game_id = u64::from(app_id);
        let call = match self.checked_call(|| {
            // SAFETY: session construction validated the typed stats vtable.
            unsafe { ((*self.stats_vtable).request_user_stats)(self.stats, steam_id64, &game_id) }
        }) {
            Ok(call) => call,
            Err(error) => {
                callback_notify::cancel_api_call(self.captured.revision, USER_STATS_RECEIVED);
                return Err(error);
            }
        };
        if call == 0 {
            callback_notify::cancel_api_call(self.captured.revision, USER_STATS_RECEIVED);
            return Err("RequestUserStats returned no call handle");
        }
        if !callback_notify::finish_api_call(self.captured.revision, call, USER_STATS_RECEIVED) {
            return Err("RequestUserStats handle could not be registered");
        }
        debug!(app_id, call, "user-stats request issued");
        Ok(call)
    }

    /// How many stats and achievements Steam currently holds for an app.
    ///
    /// A single immediate read. Zero counts are not a completion signal.
    pub(super) fn stats_counts(&self, app_id: u32) -> Result<(u32, u32), &'static str> {
        let game_id = u64::from(app_id);
        let stat_count = self.checked_call(|| {
            // SAFETY: session construction validated the typed stats vtable.
            unsafe { ((*self.stats_vtable).get_num_stats)(self.stats, &game_id) }
        })?;
        let achievement_count = self.checked_call(|| {
            // SAFETY: session construction validated the typed stats vtable.
            unsafe { ((*self.stats_vtable).get_num_achievements)(self.stats, &game_id) }
        })?;
        if stat_count > MAX_STATS || achievement_count > MAX_ACHIEVEMENTS {
            return Err("stats map count is invalid");
        }
        Ok((stat_count, achievement_count))
    }

    /// Read Steam's stats map for one app, exactly as it stands.
    ///
    /// Reads and nothing else: the caller establishes that the map is ready from a
    /// Steam event or a completed refresh request. Pulling from the backend before
    /// this point would overwrite an unsent local change with older backend state.
    pub(super) fn read_snapshot(
        &self,
        app_id: u32,
        layout: Option<&SnapshotLayout>,
    ) -> Result<AchievementSnapshot, &'static str> {
        if app_id == 0 {
            return Err("AppID is invalid");
        }
        match layout {
            Some(layout) => self.read_snapshot_from_layout(app_id, layout),
            None => self.read_snapshot_by_enumeration(app_id),
        }
    }

    /// Read values with names and types already decoded from the packet schema.
    ///
    /// The interface context guard spans the complete snapshot, and each item needs
    /// only its value getter. A stat with no recognized schema type falls back to
    /// `GetStatType` for that item.
    fn read_snapshot_from_layout(
        &self,
        app_id: u32,
        layout: &SnapshotLayout,
    ) -> Result<AchievementSnapshot, &'static str> {
        if layout.achievements.len() > MAX_ACHIEVEMENTS as usize {
            return Err("achievement count is invalid");
        }
        let game_id = u64::from(app_id);
        let snapshot = self.checked_call(|| {
            let mut achievements = Vec::with_capacity(layout.achievements.len());
            for achievement in &layout.achievements {
                let mut unlocked = false;
                let mut unlock_time = 0;
                // SAFETY: the layout owns a NUL-terminated key for the duration
                // of this call and both output pointers reference live locals.
                let got_achievement = unsafe {
                    ((*self.stats_vtable).get_achievement)(
                        self.stats,
                        &game_id,
                        achievement.c_key.as_ptr(),
                        &mut unlocked,
                        &mut unlock_time,
                    )
                };
                if !got_achievement {
                    return Err("GetAchievement failed");
                }
                achievements.push(AchievementState {
                    key: achievement.key.clone(),
                    unlocked,
                    unlock_time,
                });
            }

            let mut stats = Vec::with_capacity(layout.stats.len());
            for stat in &layout.stats {
                let key_ptr = stat.key.c_key.as_ptr();
                let kind = match stat.kind {
                    SnapshotStatKind::Dynamic => {
                        // SAFETY: the layout-owned key and game id remain live.
                        match unsafe {
                            ((*self.stats_vtable).get_stat_type)(self.stats, &game_id, key_ptr)
                        } {
                            1 => SnapshotStatKind::Int,
                            2 => SnapshotStatKind::Float,
                            3 => SnapshotStatKind::AverageRate,
                            _ => continue,
                        }
                    }
                    kind => kind,
                };
                let (value_type, value) = match kind {
                    SnapshotStatKind::Int => {
                        let mut value = 0i32;
                        // SAFETY: output points to a live i32 and the layout owns
                        // the key for the complete guarded snapshot.
                        let got_stat = unsafe {
                            ((*self.stats_vtable).get_stat_int)(
                                self.stats, &game_id, key_ptr, &mut value,
                            )
                        };
                        if !got_stat {
                            return Err("GetStat(int32) failed");
                        }
                        ("int", value.to_string())
                    }
                    SnapshotStatKind::Float | SnapshotStatKind::AverageRate => {
                        let mut value = 0f32;
                        // SAFETY: output points to a live f32 and the layout owns
                        // the key for the complete guarded snapshot.
                        let got_stat = unsafe {
                            ((*self.stats_vtable).get_stat_float)(
                                self.stats, &game_id, key_ptr, &mut value,
                            )
                        };
                        if !got_stat {
                            return Err("GetStat(float) failed");
                        }
                        let value_type = if kind == SnapshotStatKind::AverageRate {
                            "average_rate"
                        } else {
                            "float"
                        };
                        (value_type, value.to_string())
                    }
                    SnapshotStatKind::Dynamic => unreachable!("dynamic stat type was resolved"),
                };
                stats.push(StatState {
                    key: stat.key.key.clone(),
                    value_type: value_type.to_owned(),
                    value,
                });
            }
            Ok(AchievementSnapshot {
                app_id,
                achievements,
                stats,
            })
        })??;
        debug!(
            app_id,
            achievement_count = snapshot.achievements.len(),
            stat_count = snapshot.stats.len(),
            "user-stats schema-guided snapshot complete"
        );
        Ok(snapshot)
    }

    /// Enumerate Steam's public interface when this process has not observed the
    /// packet schema, such as a launch that reuses Steam's existing cache.
    fn read_snapshot_by_enumeration(
        &self,
        app_id: u32,
    ) -> Result<AchievementSnapshot, &'static str> {
        let game_id = u64::from(app_id);
        let (stat_count, achievement_count) = self.stats_counts(app_id)?;
        if achievement_count > MAX_ACHIEVEMENTS {
            return Err("achievement count is invalid");
        }

        let mut achievements = Vec::with_capacity(achievement_count as usize);
        for index in 0..achievement_count {
            let (key_ptr, key) = self
                .checked_call(|| {
                    // SAFETY: index is below the count reported by this stats map.
                    let key_ptr = unsafe {
                        ((*self.stats_vtable).get_achievement_name)(self.stats, &game_id, index)
                    };
                    bounded_key(key_ptr).map(|key| (key_ptr, key))
                })?
                .ok_or("achievement name is invalid")?;
            let mut unlocked = false;
            let mut unlock_time = 0;
            let got_achievement = self.checked_call(|| {
                // SAFETY: all pointers reference live local values for this call.
                unsafe {
                    ((*self.stats_vtable).get_achievement)(
                        self.stats,
                        &game_id,
                        key_ptr,
                        &mut unlocked,
                        &mut unlock_time,
                    )
                }
            })?;
            if !got_achievement {
                return Err("GetAchievement failed");
            }
            achievements.push(AchievementState {
                key,
                unlocked,
                unlock_time,
            });
        }
        let mut stats = Vec::with_capacity(stat_count as usize);
        for index in 0..stat_count {
            let (key_ptr, key) = self
                .checked_call(|| {
                    // SAFETY: index is below Steam's reported stat count.
                    let key_ptr = unsafe {
                        ((*self.stats_vtable).get_stat_name)(self.stats, &game_id, index)
                    };
                    bounded_key(key_ptr).map(|key| (key_ptr, key))
                })?
                .ok_or("stat name is invalid")?;
            let stat_type = self.checked_call(|| {
                // SAFETY: key is owned by Steam and valid for this call.
                unsafe { ((*self.stats_vtable).get_stat_type)(self.stats, &game_id, key_ptr) }
            })?;
            let (value_type, value) = match stat_type {
                1 => {
                    let mut value = 0i32;
                    let got_stat = self.checked_call(|| {
                        // SAFETY: output points to a live i32 and the key/game are valid.
                        unsafe {
                            ((*self.stats_vtable).get_stat_int)(
                                self.stats, &game_id, key_ptr, &mut value,
                            )
                        }
                    })?;
                    if !got_stat {
                        return Err("GetStat(int32) failed");
                    }
                    ("int".to_owned(), value.to_string())
                }
                2 | 3 => {
                    let mut value = 0f32;
                    let got_stat = self.checked_call(|| {
                        // SAFETY: output points to a live f32 and the key/game are valid.
                        unsafe {
                            ((*self.stats_vtable).get_stat_float)(
                                self.stats, &game_id, key_ptr, &mut value,
                            )
                        }
                    })?;
                    if !got_stat {
                        return Err("GetStat(float) failed");
                    }
                    let value_type = if stat_type == 3 {
                        "average_rate"
                    } else {
                        "float"
                    };
                    (value_type.to_owned(), value.to_string())
                }
                _ => continue,
            };
            stats.push(StatState {
                key,
                value_type,
                value,
            });
        }
        debug!(
            app_id,
            achievement_count, stat_count, "user-stats snapshot complete"
        );
        Ok(AchievementSnapshot {
            app_id,
            achievements,
            stats,
        })
    }

    /// Build debug output after the dispatcher consumes the completion event.
    #[cfg(any(debug_assertions, test))]
    pub(super) fn read_stats_probe(
        &self,
        app_id: u32,
        call: u64,
        result: i32,
    ) -> Result<UserStatsProbe, &'static str> {
        let game_id = u64::from(app_id);
        let (stat_count, achievement_count) = self.stats_counts(app_id)?;
        let mut samples = vec![format!(
            "api_call result {result} via SetAPICallResult event"
        )];
        if achievement_count > 0 || stat_count > 0 {
            samples.extend(self.sample_achievements(&game_id, achievement_count)?);
            samples.extend(self.sample_stats(&game_id, stat_count)?);
        }
        Ok(UserStatsProbe {
            api_call: call,
            stat_count,
            achievement_count,
            samples,
        })
    }

    /// Achievement state read straight out of Steam's map.
    ///
    /// The unlocked flag and the time are what the client itself holds, so this is
    /// also the instrument for observing whether an injected response changed the
    /// map or left it alone.
    ///
    #[cfg(any(debug_assertions, test))]
    fn sample_achievements(&self, game_id: &u64, count: u32) -> Result<Vec<String>, &'static str> {
        const MAX: usize = 8;
        let mut out = Vec::new();
        let mut unlocked_total = 0;
        for index in 0..count {
            let key_and_ptr = self.checked_call(|| {
                // SAFETY: index is below the count this map reported.
                let key_ptr = unsafe {
                    ((*self.stats_vtable).get_achievement_name)(self.stats, game_id, index)
                };
                bounded_key(key_ptr).map(|key| (key_ptr, key))
            })?;
            let Some((key_ptr, key)) = key_and_ptr else {
                continue;
            };
            let mut unlocked = false;
            let mut unlock_time = 0u32;
            let ok = self.checked_call(|| {
                // SAFETY: both outputs point to live locals and the key is valid.
                unsafe {
                    ((*self.stats_vtable).get_achievement)(
                        self.stats,
                        game_id,
                        key_ptr,
                        &mut unlocked,
                        &mut unlock_time,
                    )
                }
            })?;
            if unlocked {
                unlocked_total += 1;
            }
            if out.len() < MAX || unlocked {
                out.push(format!(
                    "ach[{index}] {key} ok={ok} unlocked={unlocked} at={unlock_time}"
                ));
            }
        }
        out.insert(0, format!("unlocked {unlocked_total}/{count}"));
        Ok(out)
    }

    /// A few stats read back through both typed getters.
    ///
    /// The int and float getters occupy adjacent slots whose stubs are
    /// indistinguishable in the binary, so which is which rests on ordering rather
    /// than on decoded evidence. Reading a declared int and a declared float and
    /// seeing whether the values are plausible is the only way to settle it.
    ///
    #[cfg(any(debug_assertions, test))]
    fn sample_stats(&self, game_id: &u64, stat_count: u32) -> Result<Vec<String>, &'static str> {
        const PER_BUCKET: usize = 3;
        let mut by_type = std::collections::BTreeMap::<i32, u32>::new();
        let mut nonzero_int = Vec::new();
        let mut zero_int = Vec::new();
        let mut floats = Vec::new();
        for index in 0..stat_count {
            let key_and_ptr = self.checked_call(|| {
                // SAFETY: index is below the count this map reported.
                let key_ptr =
                    unsafe { ((*self.stats_vtable).get_stat_name)(self.stats, game_id, index) };
                bounded_key(key_ptr).map(|key| (key_ptr, key))
            })?;
            let Some((key_ptr, key)) = key_and_ptr else {
                continue;
            };
            let stat_type = self.checked_call(|| {
                // SAFETY: key_ptr is owned by Steam and valid for this call.
                unsafe { ((*self.stats_vtable).get_stat_type)(self.stats, game_id, key_ptr) }
            })?;
            *by_type.entry(stat_type).or_default() += 1;
            match stat_type {
                1 => {
                    let mut value = 0i32;
                    let ok = self.checked_call(|| {
                        // SAFETY: output points to a live i32 and the key is valid.
                        unsafe {
                            ((*self.stats_vtable).get_stat_int)(
                                self.stats, game_id, key_ptr, &mut value,
                            )
                        }
                    })?;
                    let line = format!("int[{index}] {key} ok={ok} value={value}");
                    if value != 0 {
                        if nonzero_int.len() < PER_BUCKET {
                            nonzero_int.push(line);
                        }
                    } else if zero_int.len() < PER_BUCKET {
                        zero_int.push(line);
                    }
                }
                2 | 3 if floats.len() < PER_BUCKET * 2 => {
                    let mut value = 0f32;
                    let ok = self.checked_call(|| {
                        // SAFETY: output points to a live f32 and the key is valid.
                        unsafe {
                            ((*self.stats_vtable).get_stat_float)(
                                self.stats, game_id, key_ptr, &mut value,
                            )
                        }
                    })?;
                    floats.push(format!(
                        "float{stat_type}[{index}] {key} ok={ok} value={value}"
                    ));
                }
                _ => {}
            }
        }
        let mut samples = vec![format!(
            "types {}",
            by_type
                .iter()
                .map(|(kind, count)| format!("{kind}={count}"))
                .collect::<Vec<_>>()
                .join(" ")
        )];
        samples.extend(nonzero_int);
        samples.extend(zero_int);
        samples.extend(floats);
        Ok(samples)
    }

    fn client_user_method<T>(&self, name: &str) -> Result<Option<T>, &'static str> {
        let Some(slot) = crate::vtable_scan::slot_of("IClientUser", name) else {
            return Ok(None);
        };
        let Some(address) = self.checked_call(|| {
            // SAFETY: the slot comes from Steam's scanned interface RTTI and
            // the context guard keeps the captured wrapper current.
            unsafe { super::install::read_vtable_slot(self.client_user, slot) }
        })?
        else {
            return Ok(None);
        };
        if address == 0 {
            return Ok(None);
        }
        // SAFETY: the caller instantiates T with the Steam ABI for the named
        // method just read from the live IClientUser vtable.
        Ok(Some(unsafe {
            std::mem::transmute_copy::<usize, T>(&address)
        }))
    }

    fn bget_app_minutes_played(&self) -> Result<Option<BGetAppMinutesPlayedFn>, &'static str> {
        self.client_user_method::<BGetAppMinutesPlayedFn>("BGetAppMinutesPlayed")
    }

    fn get_app_last_played_time(&self) -> Result<Option<GetAppLastPlayedTimeFn>, &'static str> {
        self.client_user_method::<GetAppLastPlayedTimeFn>("GetAppLastPlayedTime")
    }
}

impl Drop for SteamUserStatsSession {
    fn drop(&mut self) {
        callback_notify::clear_session(self.captured.revision);
    }
}

struct LoadedModule(*mut c_void);

impl LoadedModule {
    fn open(name: &'static [u8]) -> Option<Self> {
        // SAFETY: LM_ID_BASE selects Steam's namespace and RTLD_NOLOAD only
        // obtains a reference to an already-loaded module.
        let module = unsafe {
            libc::dlmopen(
                libc::LM_ID_BASE,
                name.as_ptr().cast(),
                libc::RTLD_NOW | libc::RTLD_NOLOAD,
            )
        };
        (!module.is_null()).then_some(Self(module))
    }

    fn symbol(&self, name: &'static [u8]) -> *mut c_void {
        // SAFETY: self owns a live module reference and name is NUL-terminated.
        unsafe { libc::dlsym(self.0, name.as_ptr().cast()) }
    }
}

impl Drop for LoadedModule {
    fn drop(&mut self) {
        // SAFETY: self.0 is the handle acquired by dlmopen.
        unsafe { libc::dlclose(self.0) };
    }
}

unsafe fn object_vtable<T>(object: *mut c_void) -> Option<*const T> {
    if object.is_null() {
        return None;
    }
    // SAFETY: caller guarantees object is a live C++ interface object.
    let vtable = unsafe { object.cast::<*const T>().read() };
    (!vtable.is_null()).then_some(vtable)
}

fn bounded_key(key: *const c_char) -> Option<String> {
    if key.is_null() {
        return None;
    }
    let mut bytes = Vec::new();
    for index in 0..MAX_ACHIEVEMENT_KEY_LEN {
        // SAFETY: Steam returned key as a live NUL-terminated string.
        let byte = unsafe { key.add(index).read() } as u8;
        if byte == 0 {
            return (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte);
    }
    None
}

unsafe fn create_simple_thread_fn(address: *mut c_void) -> Option<CreateSimpleThreadFn> {
    (!address.is_null()).then(|| {
        // SAFETY: caller resolved SteamThreadTools::CreateSimpleThread.
        unsafe { std::mem::transmute::<*mut c_void, CreateSimpleThreadFn>(address) }
    })
}

unsafe fn release_thread_handle_fn(address: *mut c_void) -> Option<ReleaseThreadHandleFn> {
    (!address.is_null()).then(|| {
        // SAFETY: caller resolved ReleaseThreadHandle.
        unsafe { std::mem::transmute::<*mut c_void, ReleaseThreadHandleFn>(address) }
    })
}

unsafe fn thread_set_debug_name_fn(address: *mut c_void) -> Option<ThreadSetDebugNameFn> {
    (!address.is_null()).then(|| {
        // SAFETY: caller resolved ThreadSetDebugName.
        unsafe { std::mem::transmute::<*mut c_void, ThreadSetDebugNameFn>(address) }
    })
}

#[cfg(test)]
mod client_user_stats_vtable_layout {
    use super::ClientUserStatsVTable;

    // Slot numbers were read off the live IClientUserStats vtable. A field added
    // or removed above one of these shifts every later accessor onto a different
    // Steam method, and the failure is silent: the wrong method commonly returns
    // success while leaving the output buffer untouched.
    #[test]
    fn matches_the_live_interface_slots() {
        let slot = |offset: usize| offset / std::mem::size_of::<usize>();
        assert_eq!(
            slot(std::mem::offset_of!(ClientUserStatsVTable, get_num_stats)),
            0
        );
        assert_eq!(
            slot(std::mem::offset_of!(ClientUserStatsVTable, get_stat_name)),
            1
        );
        assert_eq!(
            slot(std::mem::offset_of!(ClientUserStatsVTable, get_stat_type)),
            2
        );
        assert_eq!(
            slot(std::mem::offset_of!(
                ClientUserStatsVTable,
                get_num_achievements
            )),
            3
        );
        assert_eq!(
            slot(std::mem::offset_of!(
                ClientUserStatsVTable,
                get_achievement_name
            )),
            4
        );
        // Slot 5 is RequestCurrentStats and slot 6 is
        // DeprecatedPublic_RequestCurrentStats. Neither is callable from here, but
        // both still have to occupy their slot or every accessor below shifts.
        assert_eq!(
            slot(std::mem::offset_of!(
                ClientUserStatsVTable,
                _request_current_stats
            )),
            5
        );
        assert_eq!(
            slot(std::mem::offset_of!(ClientUserStatsVTable, get_stat_int)),
            7
        );
        assert_eq!(
            slot(std::mem::offset_of!(ClientUserStatsVTable, get_stat_float)),
            8
        );
        // Slots 9 to 11 are SetStat(int32), SetStat(float), UpdateAvgRateStat.
        assert_eq!(
            slot(std::mem::offset_of!(ClientUserStatsVTable, get_achievement)),
            12
        );
        // Slots 13 to 21 are the achievement setters, StoreStats, the icon and
        // display accessors, and SetMaxStatsLoaded.
        assert_eq!(
            slot(std::mem::offset_of!(
                ClientUserStatsVTable,
                request_user_stats
            )),
            22
        );
    }
}
