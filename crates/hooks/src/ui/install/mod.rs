// SteamUI library management: refresh the Steam library UI after
// pkg0 injection (add/remove apps, stamp purchase time).
//
// RunFrame supplies the live app controller when UI work is drained.
// GetAppByID provides a trampoline for app lookup, while MarkAppChange captures
// the update manager used to publish the completed library change.

use core::ffi::c_void;
use std::sync::atomic::Ordering;

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
#[cfg(target_pointer_width = "64")]
use vapor_forge_patterns::Pattern;

pub(crate) use super::library::queue_metadata_refreshes;
pub use super::library::queue_removal;
use super::state::{
    GetAppByIdFn, MarkAppChangeFn, RepeatedFieldAddFn, APP_CHANGE_SOURCE, GET_APP_BY_ID_DETOUR,
    MARK_APP_CHANGE_DETOUR,
};

type RunFrameFn = unsafe extern "C" fn(*mut c_void);
type FillInAppOverviewFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
type IsVisibleInGamesListFn = unsafe extern "C" fn(*mut c_void) -> bool;
type BuildCompleteChangeFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
#[cfg(target_pointer_width = "64")]
const MAX_REPEATED_FIELD_CANDIDATES: usize = 256;

static mut REPEATED_FIELD_ADD: Option<RepeatedFieldAddFn> = None;
static mut RUN_FRAME_DETOUR: Option<Detour<RunFrameFn>> = None;
static mut FILL_IN_OVERVIEW_DETOUR: Option<Detour<FillInAppOverviewFn>> = None;
static mut IS_VISIBLE_IN_GAMES_LIST_DETOUR: Option<Detour<IsVisibleInGamesListFn>> = None;
static mut BUILD_COMPLETE_DETOUR: Option<Detour<BuildCompleteChangeFn>> = None;

unsafe extern "C" fn hk_run_frame(controller: *mut c_void) {
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!("CSteamUIAppController::RunFrame", RUN_FRAME_DETOUR);
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(controller) };
    let ui_work_ready = crate::capability::is_ready(crate::capability::Capability::LibraryUi)
        || crate::capability::is_ready(crate::capability::Capability::ConflictUiBridge);
    if ui_work_ready && vapor_forge_features::toast::take_ui_work() {
        drain_ui_work(controller);
    }
}

fn drain_ui_work(controller: *mut c_void) {
    super::library::drain_pending_metadata_refreshes(controller);
    super::library::drain_pending_removals(controller);
    crate::ui::toast_bridge::drain();
}

unsafe extern "C" fn hk_fill_in_app_overview(
    this: *mut c_void,
    app_overview: *mut c_void,
    app: *mut c_void,
) {
    let original = detour_or_return!(
        "CSteamUIAppController::FillInAppOverview",
        FILL_IN_OVERVIEW_DETOUR
    );
    if !crate::capability::is_ready(crate::capability::Capability::OverviewMetadata) {
        // SAFETY: forwards Steam's untouched overview arguments.
        unsafe { original(this, app_overview, app) };
        return;
    }
    // SAFETY: app is the direct CSteamApp pointer for this ABI.
    unsafe { stamp_purchase_time(app) };
    // SAFETY: forwards Steam's overview arguments after applying configured metadata.
    unsafe { original(this, app_overview, app) };
}

pub(super) unsafe fn stamp_purchase_time(app: *mut c_void) {
    if app.is_null() {
        return;
    }
    let steam_app = app.cast::<CSteamApp>();
    // SAFETY: steam_app is the live CSteamApp supplied by SteamUI.
    let app_id = AppId(unsafe { (*steam_app).app_id });
    let runtime = crate::client::install::runtime_snapshot();
    if !vapor_forge_features::apps::classify_app(&runtime.config, app_id)
        .requires_injected_ownership()
    {
        return;
    }
    let purchase_time = runtime.purchase_time(app_id);
    if purchase_time != 0 {
        // SAFETY: steam_app remains valid for the synchronous overview call.
        unsafe { (*steam_app).purchased_time = purchase_time };
    }
}

unsafe extern "C" fn hk_is_visible_in_games_list(app: *mut c_void) -> bool {
    let original = detour_or_return!(
        "CSteamApp::IsVisibleInGamesList",
        IS_VISIBLE_IN_GAMES_LIST_DETOUR,
        false
    );
    if app.is_null() {
        // SAFETY: forwards Steam's original argument unchanged.
        return unsafe { original(app) };
    }

    let steam_app = app.cast::<CSteamApp>();
    // SAFETY: Steam supplied a live CSteamApp for this synchronous predicate.
    let app_id = AppId(unsafe { (*steam_app).app_id });
    let should_override = {
        let runtime = crate::client::install::runtime_snapshot();
        vapor_forge_features::apps::classify_app(&runtime.config, app_id)
            .requires_injected_library_visibility()
            && crate::client::install::package_state().is_injected_into_pkg0(app_id)
    };
    if !should_override {
        // SAFETY: forwards Steam's original argument unchanged.
        return unsafe { original(app) };
    }

    // SAFETY: ownership_flags belongs to the live CSteamApp and is restored
    // before returning from this synchronous call.
    let flags = unsafe { std::ptr::addr_of_mut!((*steam_app).ownership_flags) };
    // SAFETY: CSteamApp is packed, so the field may be unaligned.
    let original_flags = unsafe { flags.read_unaligned() };
    if original_flags & super::state::EAPP_OWNERSHIP_FLAG_LEGACY_FREE_SUB == 0 {
        // SAFETY: forwards Steam's original argument unchanged.
        return unsafe { original(app) };
    }

    // SAFETY: the temporary value only affects the original visibility predicate.
    unsafe {
        flags.write_unaligned(original_flags & !super::state::EAPP_OWNERSHIP_FLAG_LEGACY_FREE_SUB)
    };
    // SAFETY: the trampoline preserves the one-argument CSteamApp ABI.
    let visible = unsafe { original(app) };
    // SAFETY: restore the exact ownership flags observed before the call.
    unsafe { flags.write_unaligned(original_flags) };
    visible
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

    if crate::capability::is_ready(crate::capability::Capability::LibrarySnapshot) {
        // SAFETY: REPEATED_FIELD_ADD resolved once at install time.
        let add_fn = unsafe { *std::ptr::addr_of!(REPEATED_FIELD_ADD) };
        super::library::append_removed_appids(change, add_fn);
    }
}

unsafe extern "C" fn hk_get_app_by_id(
    controller: *mut c_void,
    app_id: u32,
    b_create: bool,
) -> *mut c_void {
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!(
        "CSteamUIAppController::GetAppByID",
        GET_APP_BY_ID_DETOUR,
        std::ptr::null_mut()
    );
    // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
    unsafe { original(controller, app_id, b_create) }
}

unsafe extern "C" fn hk_mark_app_change(source: *mut c_void, app_id: u32, flags: u32) {
    if crate::capability::is_ready(crate::capability::Capability::LibraryUi)
        && APP_CHANGE_SOURCE
            .compare_exchange(0, source as usize, Ordering::Release, Ordering::Relaxed)
            .is_ok()
    {
        vapor_forge_features::toast::request_ui_work();
    }
    // SAFETY: detour set before hook enabled.
    let original = detour_or_return!("CUpdateManager::MarkAppChange", MARK_APP_CHANGE_DETOUR);
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(source, app_id, flags) };
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
        "CSteamApp::IsVisibleInGamesList",
        "google::protobuf::RepeatedField<uint32>::Add",
    ];
    let mut addrs = [0usize; 7];
    let mut all_found = true;
    for (i, name) in names[..6].iter().enumerate() {
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
            Some(a)
                if crate::pattern_resolver::validate_resolved_pattern(
                    "steamui",
                    steamui_code,
                    name,
                    a,
                ) =>
            {
                addrs[i] = a;
            }
            None => {
                warn!(name, "steamui: pattern not found in steamui.so");
                all_found = false;
            }
            Some(_) => {
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
        HookResult {
            name: names[6],
            installed: false,
            addr: addrs[6],
        },
    ];

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
    hook_results[5].installed = try_detour!(
        "IsVisibleInGamesList",
        addrs[5],
        hk_is_visible_in_games_list as IsVisibleInGamesListFn,
        IsVisibleInGamesListFn,
        IS_VISIBLE_IN_GAMES_LIST_DETOUR
    );

    // Resolve RepeatedField<uint32>::Add for BuildComplete protobuf mutation.
    if let Some(addr) = resolve_repeated_field_add(steamui_code, registry) {
        addrs[6] = addr;
        hook_results[6].addr = addr;
        hook_results[6].installed = true;
    }

    let reverse_bridge = super::reverse_bridge::install(steamui_code);
    let window_lifecycle_installed = reverse_bridge.iter().all(|result| result.installed);
    let conflict_bridge_installed = hook_results[0].installed && window_lifecycle_installed;
    hook_results.extend(reverse_bridge);

    let library_ready = crate::capability::set_from_requirements(
        crate::capability::Capability::LibraryUi,
        &[
            (hook_results[0].name, hook_results[0].installed),
            (hook_results[2].name, hook_results[2].installed),
            (hook_results[3].name, hook_results[3].installed),
            (hook_results[4].name, hook_results[4].installed),
            (hook_results[5].name, hook_results[5].installed),
            (hook_results[6].name, hook_results[6].installed),
        ],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::OverviewMetadata,
        &[(hook_results[1].name, hook_results[1].installed)],
    );
    crate::capability::set_from_requirements(
        crate::capability::Capability::LibrarySnapshot,
        &[
            (hook_results[2].name, hook_results[2].installed),
            (hook_results[6].name, hook_results[6].installed),
        ],
    );
    if library_ready {
        let runtime = crate::client::install::runtime_snapshot();
        queue_metadata_refreshes(runtime.purchase_time_app_ids());
    }
    super::reverse_bridge::set_runtime_ready(conflict_bridge_installed);
    let conflict_ui_ready = crate::ui::conflict_ui_ready();
    if conflict_bridge_installed {
        let config = crate::client::install::config();
        vapor_forge_features::toast::show_init_toast(&config);
    }

    if !all_found {
        warn!("steamui: hook capabilities are incomplete");
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
        is_visible = format_args!("{:#x}", addrs[5]),
        repeated_field_add = rfa,
        library_ready,
        conflict_bridge_installed,
        conflict_ui_ready,
        "steamui: hooks installed"
    );
    library_ready || conflict_bridge_installed
}

/// Resolve RepeatedField<uint32>::Add from steamui.so.
fn resolve_repeated_field_add(
    steamui_code: &CodeRegion,
    registry: &vapor_forge_patterns::registry::PatternRegistry,
) -> Option<usize> {
    let addr = resolve_repeated_field_add_address(steamui_code, registry)?;

    // SAFETY: addr passed the live semantic validator for this concrete ABI.
    let f: RepeatedFieldAddFn = unsafe { std::mem::transmute(addr) };
    // SAFETY: single-threaded init writes the resolver slot once.
    unsafe { std::ptr::addr_of_mut!(REPEATED_FIELD_ADD).write(Some(f)) };
    info!(
        addr = format_args!("{:#x}", addr),
        "steamui: RepeatedField<uint32>::Add resolved"
    );
    Some(addr)
}

pub(crate) fn resolve_repeated_field_add_address(
    steamui_code: &CodeRegion,
    registry: &vapor_forge_patterns::registry::PatternRegistry,
) -> Option<usize> {
    let entry = registry.get("google::protobuf::RepeatedField<uint32>::Add")?;
    #[cfg(target_pointer_width = "64")]
    let addr = {
        let mut match_count = 0usize;
        let mut resolved = None;
        for variant in entry.variants() {
            let pattern = match Pattern::parse(variant.pattern()) {
                Ok(pattern) => pattern,
                Err(error) => {
                    error!(%error, "steamui: invalid RepeatedField<uint32>::Add pattern");
                    return None;
                }
            };
            let matches =
                match pattern.find_all_bounded(steamui_code.bytes, MAX_REPEATED_FIELD_CANDIDATES) {
                    Ok(matches) => matches,
                    Err(error) => {
                        error!(%error, "steamui: RepeatedField<uint32>::Add pattern is too broad");
                        return None;
                    }
                };
            match_count += matches.len();
            if let Some(offset) = matches.into_iter().find(|&offset| {
                is_repeated_field_u32_add_abi(steamui_code, steamui_code.base + offset)
            }) {
                resolved = Some(steamui_code.base + offset);
                break;
            }
        }
        let addr = resolved.or_else(|| {
            error!(
                match_count,
                "steamui: no ABI-compatible RepeatedField<uint32>::Add candidate"
            );
            None
        })?;
        info!(
            match_count,
            addr = format_args!("{:#x}", addr),
            "steamui: selected ABI-compatible RepeatedField<uint32>::Add"
        );
        addr
    };

    #[cfg(target_pointer_width = "32")]
    let addr = resolve_pattern_entry(
        steamui_code,
        "google::protobuf::RepeatedField<uint32>::Add",
        &entry,
    )?;

    if !crate::pattern_resolver::validate_resolved_pattern(
        "steamui",
        steamui_code,
        "google::protobuf::RepeatedField<uint32>::Add",
        addr,
    ) {
        return None;
    }

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
