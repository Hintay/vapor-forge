// SteamUI library management: refresh the Steam library UI after
// pkg0 injection (add/remove apps, stamp purchase time).
//
// Two functions in steamui.so are hooked to capture their `this` pointers:
// - CSteamUIAppController::GetAppByID(controller, appId, bCreate) -> CSteamApp*
// - CUpdateManager::MarkAppChange(source, appId, flags)
//
// After capture, we can call them directly via trampoline to manipulate
// the library UI without restarting Steam.

use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_pointer_width = "64")]
use tracing::error;
use tracing::{info, warn};
use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;
use vapor_forge_steam_native_abi::steamui::CSteamApp;

use crate::hook_report::{log_drift_summary, log_hook_details, store_results, HookResult};
use crate::pattern_resolver::{resolve_pattern_entry, CodeRegion};
use vapor_forge_hook_engine::original::detour_or_return;
use vapor_forge_hook_engine::plan::{validate_hook_target, AddressRange, HookTargetInput};

pub use super::library::queue_removal;
use super::state::{
    GetAppByIdFn, MarkAppChangeFn, RepeatedFieldAddFn, APP_CHANGE_SOURCE, CONTROLLER,
    GET_APP_BY_ID_DETOUR, INSTALLED, MARK_APP_CHANGE_DETOUR,
};

type RunFrameFn = unsafe extern "C" fn(*mut c_void);
type FillInAppOverviewFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
type BuildCompleteChangeFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);

static mut REPEATED_FIELD_ADD: Option<RepeatedFieldAddFn> = None;
static mut RUN_FRAME_DETOUR: Option<Detour<RunFrameFn>> = None;
static mut FILL_IN_OVERVIEW_DETOUR: Option<Detour<FillInAppOverviewFn>> = None;
static mut BUILD_COMPLETE_DETOUR: Option<Detour<BuildCompleteChangeFn>> = None;
static INIT_TOAST_QUEUED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn hk_run_frame(controller: *mut c_void) {
    if CONTROLLER.load(Ordering::Relaxed) == 0 {
        CONTROLLER.store(controller as usize, Ordering::Release);
    }
    if super::library::HAS_PENDING.load(Ordering::Acquire) {
        super::library::drain_pending_removals(controller);
    }
    crate::ui::toast_bridge::bootstrap();
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!("CSteamUIAppController::RunFrame", RUN_FRAME_DETOUR);
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(controller) };
    maybe_show_init_toast();
    crate::ui::toast_bridge::pump();
}

unsafe extern "C" fn hk_fill_in_app_overview(
    this: *mut c_void,
    app_overview: *mut c_void,
    app: *mut c_void,
) -> *mut c_void {
    if !app.is_null() {
        // SAFETY: app is a CSteamApp* passed by SteamUI.
        let steam_app = app.cast::<CSteamApp>();
        // SAFETY: steam_app points to the CSteamApp passed by SteamUI; this is a by-value read.
        let app_id_raw = unsafe { (*steam_app).app_id };
        let cfg = crate::client::install::config();
        if vapor_forge_features::apps::classify_app(&cfg, AppId(app_id_raw))
            .requires_injected_ownership()
        {
            // Precedence: explicit config → max mtime across the .lua files
            // that contribute this app's depots (mirrors OpenSteamTool's
            // `LuaConfig::GetPurchaseTime`). If neither is available, leave
            // the field untouched so the original `FillInAppOverview` still
            // writes whatever Steam had.
            let mut t = cfg.purchase_time(AppId(app_id_raw));
            if t == 0 {
                let script_state = crate::client::install::script_state();
                t = script_state
                    .app_purchase_times
                    .get(&AppId(app_id_raw))
                    .copied()
                    .unwrap_or(0);
            }
            if t != 0 {
                // Stamp BEFORE the original copies the field into the overview.
                // SAFETY: steam_app points to the CSteamApp passed by SteamUI.
                unsafe { (*steam_app).purchased_time = t };
            }
        }
    }
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!(
        "CSteamUIAppController::FillInAppOverview",
        FILL_IN_OVERVIEW_DETOUR,
        std::ptr::null_mut()
    );
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(this, app_overview, app) }
}

unsafe extern "C" fn hk_build_complete_change(
    controller: *mut c_void,
    change: *mut c_void,
    callback_slot: *mut c_void,
) {
    // Call original first so the full snapshot is built.
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!(
        "CSteamUIAppController::BuildCompleteAppOverviewChange",
        BUILD_COMPLETE_DETOUR
    );
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(controller, change, callback_slot) };

    // SAFETY: REPEATED_FIELD_ADD resolved once at install time.
    let add_fn = unsafe { *std::ptr::addr_of!(REPEATED_FIELD_ADD) };
    super::library::append_removed_appids(change, add_fn);
}

unsafe extern "C" fn hk_get_app_by_id(
    controller: *mut c_void,
    app_id: u32,
    b_create: bool,
) -> *mut c_void {
    if CONTROLLER.load(Ordering::Relaxed) == 0 {
        CONTROLLER.store(controller as usize, Ordering::Release);
    }
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!(
        "CSteamUIAppController::GetAppByID",
        GET_APP_BY_ID_DETOUR,
        std::ptr::null_mut()
    );
    let app = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(controller, app_id, b_create) };
    crate::ui::toast_bridge::pump();
    app
}

unsafe extern "C" fn hk_mark_app_change(source: *mut c_void, app_id: u32, flags: u32) {
    if APP_CHANGE_SOURCE.load(Ordering::Relaxed) == 0 {
        APP_CHANGE_SOURCE.store(source as usize, Ordering::Release);
    }
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR);
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(source, app_id, flags) };
    crate::ui::toast_bridge::pump();
}

/// Install the steamui.so hooks after the loader reaches a consistent state.
pub fn install(
    steamui_code: &CodeRegion,
    registry: &vapor_forge_patterns::registry::PatternRegistry,
) -> bool {
    use vapor_forge_hook_engine::detour;

    let names = [
        "CSteamUIAppController::RunFrame",
        "CSteamUIAppController::FillInAppOverview",
        "CSteamUIAppController::BuildCompleteAppOverviewChange",
        "CSteamUIAppController::GetAppByID",
        "CUpdateManager::MarkAppChange",
        "google::protobuf::RepeatedField<uint32>::Add",
    ];
    let mut addrs = [0usize; 6];
    let mut all_found = true;
    for (i, name) in names[..5].iter().enumerate() {
        let entry = match registry.get(name) {
            Some(e) => e,
            None => {
                warn!(name, "steamui: pattern not in registry");
                all_found = false;
                continue;
            }
        };
        let short = name.rsplit("::").next().unwrap_or(name);
        match resolve_pattern_entry(steamui_code, short, &entry) {
            Some(a) => addrs[i] = a,
            None => {
                warn!(name, "steamui: pattern not found in steamui.so");
                all_found = false;
            }
        };
    }

    macro_rules! try_detour {
        ($name:expr, $addr:expr, $fn:expr, $ty:ty, $slot:ident) => {{
            let mut installed = false;
            if $addr != 0 {
                let replacement_address = $fn as *const () as usize;
                let plan = validate_hook_target(HookTargetInput {
                    target_address: $addr,
                    replacement_address,
                    executable_range: AddressRange {
                        start: steamui_code.base,
                        end: steamui_code.base + steamui_code.bytes.len(),
                    },
                })
                .inspect_err(|error| {
                    warn!(hook = $name, %error, "steamui hook validation failed");
                })
                .ok();
                // SAFETY: the pattern-resolved target and typed replacement share $ty.
                let pending = plan.and_then(|plan| unsafe {
                    detour::create_detour::<$ty>($name, plan)
                });
                // SAFETY: single-threaded init writes each detour slot once.
                installed = unsafe {
                    detour::store_and_finalize($name, std::ptr::addr_of_mut!($slot), pending)
                };
            }
            installed
        }};
    }

    let mut hook_results = vec![
        HookResult {
            name: names[0],
            installed: false,
            addr: addrs[0],
        },
        HookResult {
            name: names[1],
            installed: false,
            addr: addrs[1],
        },
        HookResult {
            name: names[2],
            installed: false,
            addr: addrs[2],
        },
        HookResult {
            name: names[3],
            installed: false,
            addr: addrs[3],
        },
        HookResult {
            name: names[4],
            installed: false,
            addr: addrs[4],
        },
        HookResult {
            name: names[5],
            installed: false,
            addr: addrs[5],
        },
    ];

    // GetAppByID and MarkAppChange are required capture hooks.
    if addrs[3] == 0 || addrs[4] == 0 {
        warn!("steamui: required capture hooks not found, aborting");
        log_drift_summary("steamui.so", &hook_results);
        store_results("steamui.so", &hook_results);
        if crate::client::install::config().runtime.diagnostics {
            log_hook_details("steamui.so", &hook_results);
        }
        return false;
    }

    hook_results[0].installed = try_detour!(
        "RunFrame",
        addrs[0],
        hk_run_frame as RunFrameFn,
        RunFrameFn,
        RUN_FRAME_DETOUR
    );
    hook_results[1].installed = try_detour!(
        "FillInAppOverview",
        addrs[1],
        hk_fill_in_app_overview as FillInAppOverviewFn,
        FillInAppOverviewFn,
        FILL_IN_OVERVIEW_DETOUR
    );
    hook_results[2].installed = try_detour!(
        "BuildComplete",
        addrs[2],
        hk_build_complete_change as BuildCompleteChangeFn,
        BuildCompleteChangeFn,
        BUILD_COMPLETE_DETOUR
    );
    hook_results[3].installed = try_detour!(
        "GetAppByID",
        addrs[3],
        hk_get_app_by_id as GetAppByIdFn,
        GetAppByIdFn,
        GET_APP_BY_ID_DETOUR
    );
    hook_results[4].installed = try_detour!(
        "MarkAppChange",
        addrs[4],
        hk_mark_app_change as MarkAppChangeFn,
        MarkAppChangeFn,
        MARK_APP_CHANGE_DETOUR
    );

    // Resolve RepeatedField<uint32>::Add for BuildComplete protobuf mutation.
    if let Some(addr) = resolve_repeated_field_add(steamui_code, registry) {
        addrs[5] = addr;
        hook_results[5].addr = addr;
        hook_results[5].installed = true;
    }

    #[cfg(target_pointer_width = "32")]
    hook_results.push(super::reverse_bridge::install(steamui_code));

    INSTALLED.store(true, Ordering::Release);

    if !all_found {
        warn!("steamui: some optional hooks missing, partial UI management");
    }
    log_drift_summary("steamui.so", &hook_results);
    store_results("steamui.so", &hook_results);
    if crate::client::install::config().runtime.diagnostics {
        log_hook_details("steamui.so", &hook_results);
    }

    // SAFETY: single-threaded init reads the resolver slot after install attempt.
    let rfa = unsafe { (*std::ptr::addr_of!(REPEATED_FIELD_ADD)).is_some() };
    info!(
        run_frame = format_args!("{:#x}", addrs[0]),
        fill_in = format_args!("{:#x}", addrs[1]),
        build_complete = format_args!("{:#x}", addrs[2]),
        get_app = format_args!("{:#x}", addrs[3]),
        mark = format_args!("{:#x}", addrs[4]),
        repeated_field_add = rfa,
        "steamui: hooks installed"
    );
    true
}

fn maybe_show_init_toast() {
    if INIT_TOAST_QUEUED.load(Ordering::Acquire) {
        return;
    }

    if INIT_TOAST_QUEUED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    let cfg = crate::client::install::config();
    vapor_forge_features::toast::show_init_toast(&cfg);
}

/// Resolve RepeatedField<uint32>::Add from steamui.so.
fn resolve_repeated_field_add(
    steamui_code: &CodeRegion,
    registry: &vapor_forge_patterns::registry::PatternRegistry,
) -> Option<usize> {
    let entry = registry.get("google::protobuf::RepeatedField<uint32>::Add")?;
    let addr = resolve_pattern_entry(
        steamui_code,
        "google::protobuf::RepeatedField<uint32>::Add",
        &entry,
    )?;

    #[cfg(target_pointer_width = "64")]
    if !is_repeated_field_u32_add_abi(steamui_code, addr) {
        error!(
            addr = format_args!("{:#x}", addr),
            "steamui: rejected RepeatedField<uint32>::Add candidate"
        );
        return None;
    }

    // SAFETY: addr is a validated function address in steamui.so .text.
    let f: RepeatedFieldAddFn = unsafe { std::mem::transmute(addr) };
    // SAFETY: single-threaded init writes the resolver slot once.
    unsafe { std::ptr::addr_of_mut!(REPEATED_FIELD_ADD).write(Some(f)) };
    info!(
        addr = format_args!("{:#x}", addr),
        "steamui: RepeatedField<uint32>::Add resolved"
    );
    Some(addr)
}

#[cfg(target_pointer_width = "64")]
fn is_repeated_field_u32_add_abi(code: &CodeRegion, addr: usize) -> bool {
    let Some(offset) = addr.checked_sub(code.base) else {
        return false;
    };
    let Some(bytes) = code.bytes.get(offset..offset.saturating_add(0x90)) else {
        return false;
    };

    bytes.windows(4).any(|w| w == [0x8b, 0x13, 0x41, 0x89])
        && bytes.windows(4).any(|w| w == [0x41, 0x89, 0x14, 0x80])
}

/// Resolve steamui.so code region from /proc/self/maps.
pub fn get_steamui_code() -> Option<CodeRegion> {
    use vapor_forge_memory::find_proc_self_maps_targets;

    let entries = find_proc_self_maps_targets(64).ok()?;
    let exec_entry = entries
        .iter()
        .find(|e| e.permissions.starts_with("r-xp") && e.path.ends_with("/steamui.so"))?;

    let base = exec_entry.range.base.0;
    let size = exec_entry.range.size;
    // SAFETY: reading the executable mapping of steamui.so.
    let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    Some(CodeRegion { base, bytes })
}
