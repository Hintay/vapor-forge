use core::ffi::{c_char, c_void};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use super::user_stats::{AchievementSnapshot, AchievementState, WorkerShared};

const ENGINE_VERSION: &[u8] = b"CLIENTENGINE_INTERFACE_VERSION005\0";
const CREATE_INTERFACE: &[u8] = b"CreateInterface\0";
const STEAMCLIENT_SONAME: &[u8] = b"steamclient.so\0";
const TIER0_SONAME: &[u8] = b"libtier0_s.so\0";
const CREATE_SIMPLE_THREAD: &[u8] = b"_ZN16SteamThreadTools18CreateSimpleThreadEPFjPvES0_Pjj\0";
const RELEASE_THREAD_HANDLE: &[u8] = b"ReleaseThreadHandle\0";
const THREAD_SET_DEBUG_NAME: &[u8] = b"ThreadSetDebugName\0";
const THREAD_NAME: &[u8] = b"vapor-user-stats\0";
const MAX_ACHIEVEMENTS: u32 = 10_000;
const MAX_ACHIEVEMENT_KEY_LEN: usize = 255;
const ENUMERATION_ATTEMPTS: usize = 60;
const ENUMERATION_INTERVAL: Duration = Duration::from_millis(50);

type SteamThreadEntry = unsafe extern "C" fn(*mut c_void) -> u32;
type CreateSimpleThreadFn =
    unsafe extern "C" fn(SteamThreadEntry, *mut c_void, *mut u32, u32) -> usize;
type ReleaseThreadHandleFn = unsafe extern "C" fn(usize) -> bool;
type ThreadSetDebugNameFn = unsafe extern "C" fn(*const c_char);

type CreateInterfaceFn = unsafe extern "C" fn(*const c_char, *mut i32) -> *mut c_void;
type CreatePipeFn = unsafe extern "C" fn(*mut c_void) -> i32;
type ReleasePipeFn = unsafe extern "C" fn(*mut c_void, i32) -> bool;
type ConnectUserFn = unsafe extern "C" fn(*mut c_void, i32) -> i32;
type ReleaseUserFn = unsafe extern "C" fn(*mut c_void, i32, i32);
type RunFrameFn = unsafe extern "C" fn(*mut c_void);
type GetClientUserFn = unsafe extern "C" fn(*mut c_void, i32, i32) -> *mut c_void;
type GetUserStatsFn = unsafe extern "C" fn(*mut c_void, i32, i32, *const c_char) -> *mut c_void;
type GetNumStatsFn = unsafe extern "C" fn(*mut c_void, *const u64) -> u32;
type GetNumAchievementsFn = unsafe extern "C" fn(*mut c_void, *const u64) -> u32;
type GetAchievementNameFn = unsafe extern "C" fn(*mut c_void, *const u64, u32) -> *const c_char;
type RequestCurrentStatsFn = unsafe extern "C" fn(*mut c_void, *const u64) -> bool;
type GetAchievementFn =
    unsafe extern "C" fn(*mut c_void, *const u64, *const c_char, *mut bool, *mut u32) -> bool;

#[repr(C)]
struct ClientEngine005VTable {
    create_steam_pipe: CreatePipeFn,
    release_steam_pipe: ReleasePipeFn,
    _slot_2: usize,
    connect_to_global_user: ConnectUserFn,
    _slots_4_5: [usize; 2],
    release_user: ReleaseUserFn,
    _slot_7: usize,
    get_client_user: GetClientUserFn,
    _slots_9_18: [usize; 10],
    run_frame: RunFrameFn,
    _slot_20: usize,
    get_client_user_stats: GetUserStatsFn,
}

#[repr(C)]
struct ClientUserStatsVTable {
    get_num_stats: GetNumStatsFn,
    _slots_1_2: [usize; 2],
    get_num_achievements: GetNumAchievementsFn,
    get_achievement_name: GetAchievementNameFn,
    request_current_stats: RequestCurrentStatsFn,
    _slots_6_11: [usize; 6],
    get_achievement: GetAchievementFn,
}

struct WorkerContext {
    shared: Arc<WorkerShared>,
    set_debug_name: Option<ThreadSetDebugNameFn>,
}

pub(super) fn spawn_user_stats_worker(shared: Arc<WorkerShared>) -> bool {
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

    let context = Box::new(WorkerContext {
        shared,
        set_debug_name,
    });
    let raw_context = Box::into_raw(context);
    // SAFETY: raw_context owns one WorkerContext and the entrypoint takes ownership on success.
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

unsafe extern "C" fn steam_thread_entry(context: *mut c_void) -> u32 {
    if context.is_null() {
        return 1;
    }
    // SAFETY: spawn_user_stats_worker transferred one Box<WorkerContext> here.
    let context = unsafe { Box::from_raw(context.cast::<WorkerContext>()) };
    if let Some(set_debug_name) = context.set_debug_name {
        // SAFETY: THREAD_NAME is a process-lifetime NUL-terminated string.
        unsafe { set_debug_name(THREAD_NAME.as_ptr().cast()) };
    }
    super::user_stats::run_worker(&context.shared);
    0
}

pub(super) struct SteamUserStatsSession {
    _module: LoadedModule,
    engine: *mut c_void,
    engine_vtable: *const ClientEngine005VTable,
    client_user: *mut c_void,
    stats: *mut c_void,
    stats_vtable: *const ClientUserStatsVTable,
    pipe: i32,
    user: i32,
}

impl SteamUserStatsSession {
    pub(super) fn connect() -> Result<Self, &'static str> {
        let module = LoadedModule::open(STEAMCLIENT_SONAME)
            .ok_or("steamclient base-namespace handle is unavailable")?;
        // SAFETY: CreateInterface is exported by the loaded steamclient module.
        let create = unsafe { create_interface_fn(module.symbol(CREATE_INTERFACE)) }
            .ok_or("CreateInterface export is unavailable")?;

        let mut return_code = -1;
        // SAFETY: ENGINE_VERSION and return_code satisfy CreateInterface's contract.
        let engine = unsafe { create(ENGINE_VERSION.as_ptr().cast(), &mut return_code) };
        if return_code != 0 || engine.is_null() {
            return Err("CLIENTENGINE_INTERFACE_VERSION005 is unavailable");
        }
        // SAFETY: the requested interface version fixes this vtable layout.
        let engine_vtable = unsafe { object_vtable::<ClientEngine005VTable>(engine) }
            .ok_or("IClientEngine vtable is unavailable")?;

        // SAFETY: engine and its typed vtable came from CreateInterface above.
        let pipe = unsafe { ((*engine_vtable).create_steam_pipe)(engine) };
        if pipe == 0 {
            return Err("CreateSteamPipe failed");
        }
        // SAFETY: pipe belongs to this engine.
        let user = unsafe { ((*engine_vtable).connect_to_global_user)(engine, pipe) };
        if user == 0 {
            // SAFETY: pipe was created above and remains live.
            let _ = unsafe { ((*engine_vtable).release_steam_pipe)(engine, pipe) };
            return Err("ConnectToGlobalUser failed");
        }
        // SAFETY: user and pipe are paired live handles from this engine.
        let client_user = unsafe { ((*engine_vtable).get_client_user)(engine, user, pipe) };
        if client_user.is_null() {
            // SAFETY: handles are live and owned by this function.
            unsafe { release_session(engine, engine_vtable, pipe, user) };
            return Err("GetIClientUser failed");
        }
        // SAFETY: the null version requests the engine's IClientUserStats map wrapper.
        let stats = unsafe {
            ((*engine_vtable).get_client_user_stats)(engine, user, pipe, std::ptr::null())
        };
        if stats.is_null() {
            // SAFETY: handles are live and owned by this function.
            unsafe { release_session(engine, engine_vtable, pipe, user) };
            return Err("GetIClientUserStats failed");
        }
        // SAFETY: GetIClientUserStats returned the version paired with Engine005.
        let stats_vtable = match unsafe { object_vtable::<ClientUserStatsVTable>(stats) } {
            Some(vtable) => vtable,
            None => {
                // SAFETY: handles are live and owned by this function.
                unsafe { release_session(engine, engine_vtable, pipe, user) };
                return Err("IClientUserStats vtable is unavailable");
            }
        };

        super::user::install_get_steam_id_hook(client_user);
        let session = Self {
            _module: module,
            engine,
            engine_vtable,
            client_user,
            stats,
            stats_vtable,
            pipe,
            user,
        };
        session.refresh_identity()?;
        Ok(session)
    }

    fn refresh_identity(&self) -> Result<u64, &'static str> {
        super::user::refresh_real_steam_id(self.client_user)
    }

    pub(super) fn snapshot(&self, app_id: u32) -> Result<AchievementSnapshot, &'static str> {
        let game_id = u64::from(app_id);
        // SAFETY: session construction validated the typed stats vtable.
        if !unsafe { ((*self.stats_vtable).request_current_stats)(self.stats, &game_id) } {
            return Err("RequestCurrentStats was rejected");
        }
        debug!(app_id, "user-stats snapshot requested");
        let count = self.wait_for_schema(app_id, &game_id)?;
        if count > MAX_ACHIEVEMENTS {
            return Err("achievement count is invalid");
        }

        let mut achievements = Vec::with_capacity(count as usize);
        for index in 0..count {
            // SAFETY: index is below the count reported by this stats map.
            let key_ptr =
                unsafe { ((*self.stats_vtable).get_achievement_name)(self.stats, &game_id, index) };
            let key = bounded_key(key_ptr).ok_or("achievement name is invalid")?;
            let mut unlocked = false;
            let mut unlock_time = 0;
            // SAFETY: all pointers reference live local values for this call.
            if !unsafe {
                ((*self.stats_vtable).get_achievement)(
                    self.stats,
                    &game_id,
                    key_ptr,
                    &mut unlocked,
                    &mut unlock_time,
                )
            } {
                return Err("GetAchievement failed");
            }
            achievements.push(AchievementState {
                key,
                unlocked,
                unlock_time,
            });
        }
        debug!(app_id, count, "user-stats snapshot complete");
        Ok(AchievementSnapshot {
            app_id,
            achievements,
        })
    }

    fn wait_for_schema(&self, app_id: u32, game_id: &u64) -> Result<u32, &'static str> {
        for _ in 0..ENUMERATION_ATTEMPTS {
            // SAFETY: session construction validated both typed vtables.
            unsafe { ((*self.engine_vtable).run_frame)(self.engine) };
            // IClientUserStats map requests do not deliver UserStatsReceived on
            // this engine pipe. Steam's cache counts are the completion signal.
            // SAFETY: session construction validated the typed stats vtable.
            let stat_count = unsafe { ((*self.stats_vtable).get_num_stats)(self.stats, game_id) };
            // SAFETY: session construction validated the typed stats vtable.
            let achievement_count =
                unsafe { ((*self.stats_vtable).get_num_achievements)(self.stats, game_id) };
            if stat_count > 0 || achievement_count > 0 {
                debug!(
                    app_id,
                    stat_count, achievement_count, "user-stats schema loaded"
                );
                return Ok(achievement_count);
            }
            std::thread::sleep(ENUMERATION_INTERVAL);
        }
        warn!(app_id, "user-stats schema did not become observable");
        Err("IClientUserStats schema load timed out")
    }
}

impl Drop for SteamUserStatsSession {
    fn drop(&mut self) {
        // SAFETY: this session owns the live handles until Drop.
        unsafe { release_session(self.engine, self.engine_vtable, self.pipe, self.user) };
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

unsafe fn release_session(
    engine: *mut c_void,
    vtable: *const ClientEngine005VTable,
    pipe: i32,
    user: i32,
) {
    // SAFETY: caller owns these paired handles and the typed vtable.
    unsafe {
        ((*vtable).release_user)(engine, pipe, user);
        let _ = ((*vtable).release_steam_pipe)(engine, pipe);
    }
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

unsafe fn create_interface_fn(address: *mut c_void) -> Option<CreateInterfaceFn> {
    (!address.is_null()).then(|| {
        // SAFETY: caller resolved the CreateInterface export.
        unsafe { std::mem::transmute::<*mut c_void, CreateInterfaceFn>(address) }
    })
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
