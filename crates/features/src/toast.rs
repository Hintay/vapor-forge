use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use tracing::warn;
use vapor_forge_config::RuntimeConfig;

static PENDING_TOASTS: Mutex<Vec<ToastRequest>> = Mutex::new(Vec::new());
static UI_WORK_PENDING: AtomicBool = AtomicBool::new(false);
static NEXT_TOAST_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_TITLE: &str = "Vapor Forge";
const INIT_BODY: &str = "Loaded successfully";
const DEFAULT_DURATION_MS: u32 = 5000;
const STEAMUI_BRIDGE_JS: &str = include_str!("ui/steamui_bridge.js");
const TOAST_JS: &str = include_str!("ui/toast.js");
const TOAST_I18N: &str = include_str!("ui/toast_i18n.json");
const CLOUD_CONFLICT_JS: &str = include_str!("ui/cloud_conflict.js");
const CLOUD_CONFLICT_I18N: &str = include_str!("ui/cloud_conflict_i18n.json");

#[derive(Clone, Debug)]
pub struct ToastRequest {
    id: u64,
    kind: ToastKind,
    style: ToastStyle,
    action: ToastAction,
    message_key: String,
    title: String,
    body: String,
    logo: ToastLogo,
    duration_ms: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToastKind {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToastStyle {
    Accent,
    Banner,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToastAction {
    Dismiss,
    OpenSteamUrl(String),
    OpenDeckyRoute(String),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ToastLogo {
    #[default]
    Default,
    Hidden,
    Custom(String),
}

impl ToastRequest {
    fn new(
        kind: ToastKind,
        style: ToastStyle,
        title: &str,
        body: &str,
        logo: ToastLogo,
        duration_ms: u32,
        action: ToastAction,
    ) -> Self {
        Self {
            id: NEXT_TOAST_ID.fetch_add(1, Ordering::Relaxed),
            kind,
            style,
            action,
            message_key: String::new(),
            title: if title.is_empty() {
                DEFAULT_TITLE.to_owned()
            } else {
                title.to_owned()
            },
            body: body.to_owned(),
            logo,
            duration_ms,
        }
    }

    fn with_message_key(mut self, message_key: &str) -> Self {
        self.message_key = message_key.to_owned();
        self
    }
}

impl ToastKind {
    fn as_js_str(self) -> &'static str {
        match self {
            ToastKind::Info => "info",
            ToastKind::Warning => "warning",
            ToastKind::Error => "error",
        }
    }

    fn sound(self) -> u32 {
        6
    }

    fn e_type(self) -> u32 {
        31
    }

    fn critical(self) -> bool {
        matches!(self, ToastKind::Error)
    }

    fn default_style(self) -> ToastStyle {
        match self {
            ToastKind::Info => ToastStyle::Accent,
            ToastKind::Warning | ToastKind::Error => ToastStyle::Banner,
        }
    }
}

impl ToastStyle {
    fn as_js_str(self) -> &'static str {
        match self {
            ToastStyle::Accent => "accent",
            ToastStyle::Banner => "banner",
        }
    }
}

impl ToastAction {
    fn as_js_kind(&self) -> &'static str {
        match self {
            Self::Dismiss => "dismiss",
            Self::OpenSteamUrl(_) => "steam-url",
            Self::OpenDeckyRoute(_) => "decky-route",
        }
    }

    fn target(&self) -> &str {
        match self {
            Self::Dismiss => "",
            Self::OpenSteamUrl(target) | Self::OpenDeckyRoute(target) => target,
        }
    }
}

impl ToastLogo {
    fn as_js_mode(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Hidden => "hidden",
            Self::Custom(_) => "custom",
        }
    }

    fn icon(&self) -> &str {
        match self {
            Self::Custom(icon) => icon,
            Self::Default | Self::Hidden => "",
        }
    }
}

pub fn show_toast(title: &str, body: &str, logo: ToastLogo, duration_ms: u32) {
    show_toast_with_kind(ToastKind::Info, title, body, logo, duration_ms);
}

pub fn show_toast_with_kind(
    kind: ToastKind,
    title: &str,
    body: &str,
    logo: ToastLogo,
    duration_ms: u32,
) {
    show_toast_with_style(kind, kind.default_style(), title, body, logo, duration_ms);
}

pub fn show_toast_with_style(
    kind: ToastKind,
    style: ToastStyle,
    title: &str,
    body: &str,
    logo: ToastLogo,
    duration_ms: u32,
) {
    show_toast_with_style_and_action(
        kind,
        style,
        title,
        body,
        logo,
        duration_ms,
        ToastAction::Dismiss,
    );
}

pub fn show_toast_with_style_and_action(
    kind: ToastKind,
    style: ToastStyle,
    title: &str,
    body: &str,
    logo: ToastLogo,
    duration_ms: u32,
    action: ToastAction,
) {
    enqueue_toast(ToastRequest::new(
        kind,
        style,
        title,
        body,
        logo,
        duration_ms,
        action,
    ));
}

fn enqueue_toast(toast: ToastRequest) {
    let mut pending = match PENDING_TOASTS.lock() {
        Ok(p) => p,
        Err(_) => {
            warn!("toast: pending queue lock poisoned");
            return;
        }
    };
    pending.push(toast);
    drop(pending);
    request_ui_work();
}

pub fn show_init_toast(config: &RuntimeConfig) {
    if config.toast.enabled && config.toast.init {
        enqueue_toast(
            ToastRequest::new(
                ToastKind::Info,
                ToastStyle::Accent,
                DEFAULT_TITLE,
                INIT_BODY,
                ToastLogo::Default,
                DEFAULT_DURATION_MS,
                ToastAction::Dismiss,
            )
            .with_message_key("loaded"),
        );
    }
}

pub fn has_pending_work() -> bool {
    pending_count() != 0
}

pub fn request_ui_work() {
    UI_WORK_PENDING.store(true, Ordering::Release);
}

pub fn take_ui_work() -> bool {
    UI_WORK_PENDING.swap(false, Ordering::AcqRel)
}

pub fn pending_count() -> usize {
    PENDING_TOASTS
        .lock()
        .map(|pending| pending.len())
        .unwrap_or(0)
}

pub fn take_pending() -> Vec<ToastRequest> {
    match PENDING_TOASTS.lock() {
        Ok(mut pending) => std::mem::take(&mut *pending),
        Err(_) => {
            warn!("toast: pending queue lock poisoned");
            Vec::new()
        }
    }
}

pub fn restore_pending(toasts: &[ToastRequest]) {
    if toasts.is_empty() {
        return;
    }
    match PENDING_TOASTS.lock() {
        Ok(mut pending) => {
            let mut restored = toasts.to_vec();
            restored.extend(pending.drain(..));
            *pending = restored;
        }
        Err(_) => warn!("toast: pending queue lock poisoned"),
    }
}

pub fn toast_script(toast: &ToastRequest) -> String {
    let duration = if toast.duration_ms == 0 {
        DEFAULT_DURATION_MS
    } else {
        toast.duration_ms
    };
    format!(
        "(function(){{try{{if(!window.VaporForgeToastBridge||!window.VaporForgeToastBridge.showToast){{return false;}}window.VaporForgeToastBridge.showToast({{id:{},kind:\"{}\",style:\"{}\",messageKey:\"{}\",title:\"{}\",body:\"{}\",logoMode:\"{}\",icon:\"{}\",duration:{},playSound:true,sound:{},eType:{},critical:{},action:{{kind:\"{}\",target:\"{}\"}}}});return true;}}catch(e){{try{{console.log('[VaporForgeToast] show error: '+e);}}catch(_){{}}}}}})();",
        toast.id,
        toast.kind.as_js_str(),
        toast.style.as_js_str(),
        js_escape(&toast.message_key),
        js_escape(&toast.title),
        js_escape(&toast.body),
        toast.logo.as_js_mode(),
        js_escape(toast.logo.icon()),
        duration,
        toast.kind.sound(),
        toast.kind.e_type(),
        toast.kind.critical(),
        toast.action.as_js_kind(),
        js_escape(toast.action.target())
    )
}

fn js_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < ' ' => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out
}

pub fn bridge_script() -> &'static str {
    static SCRIPT: OnceLock<String> = OnceLock::new();
    SCRIPT.get_or_init(|| {
        let capacity = STEAMUI_BRIDGE_JS.len()
            + TOAST_JS.len()
            + TOAST_I18N.len()
            + CLOUD_CONFLICT_JS.len()
            + CLOUD_CONFLICT_I18N.len()
            + 256;
        let mut script = String::with_capacity(capacity);
        script.push_str(STEAMUI_BRIDGE_JS);
        script.push_str("\n(function(){try{var bridge=window.VaporForgeUIBridge;");
        script.push_str("if(bridge){bridge.resources.toastLocales=");
        script.push_str(TOAST_I18N);
        script.push_str(";bridge.resources.cloudConflictLocales=");
        script.push_str(CLOUD_CONFLICT_I18N);
        script.push_str(
            ";}}catch(error){try{console.log('[VaporForgeUI] locale install error: '+error);}",
        );
        script.push_str("catch(_){}}})();\n");
        script.push_str(TOAST_JS);
        script.push('\n');
        script.push_str(CLOUD_CONFLICT_JS);
        script
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn js_escape_handles_control_chars() {
        assert_eq!(js_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
        assert_eq!(js_escape("\u{01}"), "\\u0001");
    }

    #[test]
    fn toast_script_uses_project_bridge() {
        let _guard = TEST_LOCK.lock().unwrap();
        let toast = ToastRequest {
            id: 42,
            kind: ToastKind::Info,
            style: ToastStyle::Accent,
            action: ToastAction::Dismiss,
            message_key: String::new(),
            title: "t".to_owned(),
            body: "b".to_owned(),
            logo: ToastLogo::Default,
            duration_ms: 5000,
        };
        let script = toast_script(&toast);
        assert!(script.contains("VaporForgeToastBridge"));
        assert!(script.contains("kind:\"info\""));
        assert!(script.contains("style:\"accent\""));
        assert!(script.contains("logoMode:\"default\""));
        assert!(script.contains("critical:false"));
        assert!(script.contains("action:{kind:\"dismiss\",target:\"\"}"));
        assert!(!script.contains("SLS"));
    }

    #[test]
    fn toast_script_marks_error_toasts_critical() {
        let _guard = TEST_LOCK.lock().unwrap();
        let toast = ToastRequest {
            id: 43,
            kind: ToastKind::Error,
            style: ToastStyle::Banner,
            action: ToastAction::Dismiss,
            message_key: String::new(),
            title: "t".to_owned(),
            body: "b".to_owned(),
            logo: ToastLogo::Hidden,
            duration_ms: 5000,
        };
        let script = toast_script(&toast);
        assert!(script.contains("kind:\"error\""));
        assert!(script.contains("logoMode:\"hidden\""));
        assert!(script.contains("critical:true"));
    }

    #[test]
    fn toast_script_serializes_steam_url_action() {
        let toast = ToastRequest {
            id: 44,
            kind: ToastKind::Info,
            style: ToastStyle::Accent,
            action: ToastAction::OpenSteamUrl("steam://open/downloads".to_owned()),
            message_key: String::new(),
            title: "t".to_owned(),
            body: "b".to_owned(),
            logo: ToastLogo::Custom("https://example.invalid/icon.png".to_owned()),
            duration_ms: 5000,
        };
        let script = toast_script(&toast);
        assert!(script.contains("logoMode:\"custom\""));
        assert!(script.contains("icon:\"https://example.invalid/icon.png\""));
        assert!(script.contains("action:{kind:\"steam-url\",target:\"steam://open/downloads\"}"));
    }

    #[test]
    fn toast_script_serializes_decky_route_action() {
        let toast = ToastRequest {
            id: 45,
            kind: ToastKind::Info,
            style: ToastStyle::Accent,
            action: ToastAction::OpenDeckyRoute("/decky/settings/plugins".to_owned()),
            message_key: String::new(),
            title: "t".to_owned(),
            body: "b".to_owned(),
            logo: ToastLogo::Default,
            duration_ms: 5000,
        };
        let script = toast_script(&toast);
        assert!(script.contains("action:{kind:\"decky-route\",target:\"/decky/settings/plugins\"}"));
    }

    #[test]
    fn bridge_renderer_handles_grouped_notifications() {
        let script = bridge_script();
        assert!(script.contains("notifications.filter(isVaporForgeNotification).map"));
        assert!(script.contains("notifications.some(isVaporForgeNotification)"));
        assert!(script.contains("location === 1 || !isGamepadUiReady()"));
    }

    #[test]
    fn bridge_patches_the_valve_renderer_without_a_trampoline() {
        let script = bridge_script();
        assert!(script.contains("function patchJsxRuntime(jsx)"));
        assert!(script.contains("jsx.jsx = wrap(originalJsx)"));
        assert!(script.contains("jsx.jsxs = wrap(originalJsxs)"));
        assert!(script.contains("JSX notification bridge ready"));
        assert!(script.contains("function patchClassRenderer(renderer)"));
        assert!(script.contains("prototype.render = wrapped"));
        assert!(script.contains("var renderer = state.renderer || findValveToastRenderer()"));
        assert!(script.contains("state.renderPatched = jsxPatched || renderPatched"));
        assert!(script.contains("Valve toast renderer render patch ready"));
        assert!(!script.contains("injectRendererTrampoline"));
        assert!(!script.contains("isReactComponent = true"));
        assert!(!script.contains("Object.create(component.prototype)"));
        assert!(!script.contains("trampoline ready"));
        assert!(!script.contains("Valve toast renderer export bridge ready"));
    }

    #[test]
    fn bridge_publishes_after_before_login_initialization() {
        let script = bridge_script();
        assert!(script.contains("function isSteamAppBeforeLoginReady()"));
        assert!(script.contains("app.BFinishedInitBeforeLogin()"));
        assert!(script.contains("app.BFinishedInitStageOne()"));
        assert!(script.contains("function findMobxObservable(target, property)"));
        assert!(script.contains("Object.getOwnPropertySymbols(target)"));
        assert!(script.contains("administration.values_"));
        assert!(script.contains("values.get(property)"));
        assert!(script.contains("typeof observable.observe_ === 'function'"));
        assert!(script.contains("function observeSteamBeforeLoginReady()"));
        assert!(script.contains("observable.observe_(function(change)"));
        assert!(script.contains("change.newValue === true"));
        assert!(script.contains("clearSteamStageOneSubscription()"));
        assert!(script.contains("queueSteamReadiness()"));
        assert!(script.contains("if (!isSteamAppBeforeLoginReady()) return false"));
        assert!(script.contains("isSteamAppBeforeLoginReady() && state.store"));
        assert!(script.contains("function isSteamServicesReady()"));
        assert!(script.contains("function ensureSteamServicesReady()"));
        assert!(script.contains("app.GetServicesInitialized()"));
        assert!(script.contains("function markSteamServicesReady()"));
        assert!(script.contains("function waitForSteamServices(app)"));
        assert!(script.contains("app.WaitForServicesInitialized()"));
        assert!(script.contains("Promise.resolve(app.WaitForServicesInitialized()).then"));
        assert!(script.contains("state.steamServicesWaitStarted"));
        assert!(!script.contains("var originalInitStage2 = app.InitStage2"));
        assert!(script.contains("window.requestAnimationFrame(run)"));
        assert!(script.contains("Steam before-login initialization ready"));
        assert!(!script.contains("function waitForToastChannel(store)"));
        assert!(!script.contains("store.GetCurrentToastNotification()"));
        assert!(!script.contains("store.m_valueCurrentToast"));
        assert!(script.contains("function ensurePreLoginSurface()"));
        assert!(script.contains("function activeSteamDocument()"));
        assert!(script.contains("function activeSteamWindow()"));
        assert!(script.contains("navigation.ActiveWindowInstance"));
        assert!(script.contains("store.MainWindowInstance || store.GamepadUIMainWindowInstance"));
        assert!(script.contains("instance.BrowserWindow || instance.m_BrowserWindow"));
        assert!(script.contains("function observeSteamWindowReady()"));
        assert!(script.contains("findMobxObservable(store, 'MainWindowInstance')"));
        assert!(script.contains("findMobxObservable(instance, 'm_BrowserWindow')"));
        assert!(script.contains("clearSteamWindowSubscriptions()"));
        assert!(script.contains("document.addEventListener('DOMContentLoaded', listener"));
        assert!(script.contains("function findNativePopupSupport()"));
        assert!(script.contains("hasOwnProperty.call(prototype, 'Show')"));
        assert!(script.contains("hasOwnProperty.call(prototype, 'RegisterChildBrowserView')"));
        assert!(script.contains("exp.EBrowserType_DirectHWND_Borderless === 4"));
        assert!(script.contains("function renderGamepadPreLoginToast("));
        assert!(script.contains("SteamClient.BrowserView.CreatePopup({"));
        assert!(script.contains("parentPopupBrowserID: parentPopupBrowserID"));
        assert!(script.contains("SteamClient.BrowserView.Destroy(created.browserView)"));
        assert!(script.contains("entry.browserView.SetBounds(left, top, 320, 80)"));
        assert!(script.contains("Number(owner.innerWidth) - 320"));
        assert!(script.contains("Number(owner.innerHeight) - 80 - stackIndex * 88"));
        assert!(script.contains("function renderDesktopPreLoginToast("));
        assert!(script.contains("state.browserTypes.EBrowserType_DirectHWND_Borderless"));
        assert!(script.contains("popup.OnLoad = function() {}"));
        assert!(script.contains("Number(owner.screenY || 0) + top,\n                false"));
        assert!(script.contains("if (!popup.BIsValid())"));
        assert!(script.contains("function renderPreLoginNativeToast(data, notification)"));
        assert!(script.contains("function renderNativeToastDom("));
        assert!(script.contains("function nativeToastSurfaceClass(document)"));
        assert!(script.contains("style.bottom === '0px' && style.left === '20px'"));
        assert!(script.contains("life.style.setProperty('--toast-duration', duration + 'ms')"));
        assert!(script.contains("life.addEventListener('animationend'"));
        assert!(script.contains("event.target !== toast || ++completedAnimations < 2"));
        assert!(script.contains("showToast: !beforeServices"));
        assert!(
            script.contains("if (beforeServices && !renderPreLoginNativeToast(toast, toastData))")
        );
        assert!(script.contains("state.pending.unshift(toast)"));
        assert!(script.contains("clearPreLoginNativeToasts()"));
        assert!(!script.contains("VaporForgePreLoginStack"));
        assert!(script.contains("var store = findStore() || state.store"));
        assert!(!script.contains("setInterval"));
        assert!(!script.contains("setTimeout"));
    }

    #[test]
    fn bridge_reveals_native_toasts_after_styles_load() {
        let script = bridge_script();
        assert!(script.contains("function copySteamStyles(source, target, onReady)"));
        assert!(script.contains("copy.addEventListener('load', finish)"));
        assert!(script.contains("copy.addEventListener('error', finish)"));
        assert!(script.contains("if (notified || pending > 0) return"));
        assert!(
            script.contains("copySteamStyles(ownerWindow.document, popup.document, function() {")
        );
        assert!(script.contains("if (entry.removed || entry.closing) return"));
        assert!(script.contains("entry.stylesReady = true"));
        assert!(script.contains("if (entry.stylesReady) entry.browserView.SetVisible(true)"));
        assert!(!script.contains(
            "SetBounds(left, top, 320, 80);\n              entry.browserView.SetVisible(true);"
        ));
    }

    #[test]
    fn bridge_waits_for_the_owner_popup_before_native_toasts() {
        let script = bridge_script();
        assert!(script.contains("function findPopupTracker(exports)"));
        assert!(script.contains("typeof value.GetPopupForWindow === 'function'"));
        assert!(script.contains("if (parent) state.popupTracker = findPopupTracker(parent)"));
        assert!(script.contains("function isOwnerPopupCreated(ownerWindow)"));
        assert!(script.contains("owner = tracker.GetPopupForWindow(ownerWindow)"));
        assert!(script.contains("if (!owner || owner.m_bCreated) return true"));
        assert!(script.contains("owner.OnCreate = function()"));
        assert!(script.contains("if (!isOwnerPopupCreated(ownerWindow)) return false"));
        assert!(script.contains("function isOwnerDocumentComplete(ownerWindow)"));
        assert!(script.contains("document.readyState === 'complete'"));
        assert!(script.contains("ownerWindow.addEventListener('load', function() { queueSteamReadiness(); }, { once: true })"));
        assert!(script.contains("if (!isOwnerDocumentComplete(ownerWindow)) return false"));
        assert!(script.contains("native notification waits for owner load state="));
        assert!(script.contains("native notification popup shown valid="));
    }

    #[test]
    fn bridge_uses_the_renderer_jsx_runtime() {
        let script = bridge_script();
        let renderer_runtime = script.find("findJsxFromRendererFactory();").unwrap();
        let export_scan = script[renderer_runtime..]
            .find("eachExport(function(exp)")
            .map(|offset| renderer_runtime + offset)
            .unwrap();
        assert!(renderer_runtime < export_scan);
        assert!(script.contains("var jsx = state.jsx || bridge.findJsx()"));
        assert!(!script.contains("jsx.jsx = function()"));
        assert!(!script.contains("jsx.jsxs = function()"));
    }

    #[test]
    fn bridge_requires_the_gamepad_focus_component() {
        let script = bridge_script();
        assert!(script.contains("registerFeatureOnce('toast'"));
        assert!(script.contains("typeof exp === 'function'"));
        assert!(script.contains("typeof exp.render === 'function'"));
        assert!(script.contains("'focusClassName'"));
        assert!(script.contains("'focusWithinClassName'"));
        assert!(script.contains("'onOKButton'"));
        assert!(script.contains("isGamepadUiReady() && !state.focusable"));
        assert!(script.contains("indexOf('/routes/')"));
        assert!(script.contains("findFocusable(gamepadUiReady)"));
    }

    #[test]
    fn bridge_registers_features_once_without_feature_versions() {
        let script = bridge_script();
        assert!(script.contains("bridge.registerFeatureOnce = function(name, install)"));
        assert!(script.contains("if (current)"));
        assert!(script.contains("bridge.features[name] = { api: api }"));
        assert!(!script.contains("current.version"));
        assert!(!script.contains("version: version"));
        assert!(!script.contains("current.api.dispose"));
    }

    #[test]
    fn bridge_uses_a_focusable_notification_root() {
        let script = bridge_script();
        assert!(script.contains("onActivate: function() { activateQamToast(data, notification); }"));
        assert!(script.contains("navigation.CloseSideMenus()"));
        assert!(script.contains("className: (css.StandardTemplateContainer || '')"));
    }

    #[test]
    fn bridge_dismisses_or_opens_clicked_notifications() {
        let script = bridge_script();
        assert!(script.contains("function dismissTrayNotification(notification)"));
        assert!(script.contains("store.GetNotificationsInTray()"));
        assert!(script.contains("store.RemoveGroupFromTray(group)"));
        assert!(script.contains("function runToastAction(data, notification)"));
        assert!(script.contains("target.indexOf('steam://') !== 0"));
        assert!(script.contains("client.URL.ExecuteSteamURL(target)"));
        assert!(script.contains("action.kind === 'decky-route'"));
        assert!(script.contains("function isDeckyRouteRegistered(target)"));
        assert!(script.contains("function runPendingDeckyRoute()"));
        assert!(script.contains("bus.addEventListener('update', listener)"));
        assert!(script.contains("navigation.Navigate(target)"));
        assert!(script
            .contains("state.pendingDeckyRoute = { target: target, notification: notification }"));
        assert!(script.contains("dismissTrayNotification(pending.notification)"));
        assert!(script.contains("if (activateQamToast(data, notification))"));
        assert!(script.contains("closePreLoginNativeToast(notification.notificationID)"));
        let run_action = script
            .find("var result = runToastAction(data, notification)")
            .unwrap();
        let dismiss = script[run_action..]
            .find("dismissTrayNotification(notification)")
            .map(|offset| run_action + offset)
            .unwrap();
        assert!(run_action < dismiss);
        assert!(!script.contains("setInterval"));
    }

    #[test]
    fn bridge_keeps_steam_toast_manager_selection() {
        let script = bridge_script();
        assert!(!script.contains("findToastStackManager"));
        assert!(!script.contains("isSingleToastManager"));
        assert!(!script.contains("toastStackManager"));
        assert!(!script.contains("GamepadUI uses ToastManagerGamepadUI"));
    }

    #[test]
    fn bridge_uses_general_notification_type_by_default() {
        let script = bridge_script();
        assert!(script.contains("eType: toast.eType || 31"));
        assert!(script.contains("function allocateNotificationId(toast)"));
        assert!(script.contains("notificationID: id"));
        assert!(script.contains("nNotificationID: id"));
    }

    #[test]
    fn bridge_installs_once_without_a_bridge_version() {
        let script = bridge_script();
        assert!(script.contains("if (existing)"));
        assert!(script.contains("array.__vaporForgeBridgeWrapped"));
        assert!(!script.contains("BRIDGE_VERSION"));
        assert!(!script.contains("__vaporForgeBridgeVersion"));
    }

    #[test]
    fn cloud_conflict_bridge_resumes_the_public_game_action() {
        let script = bridge_script();
        assert!(script.contains("SteamClient.Apps.GetGameActionForApp"));
        assert!(script.contains("SteamClient.Apps.VaporForgeResolveCloudConflict"));
        assert!(script.contains("registerFeatureOnce('cloud-conflict'"));
        assert!(script.contains("VaporForgeConfirmUIBridge('cloud-conflict-ready')"));
        assert!(!script.contains("cloud-conflict:3"));
        assert!(script.contains("state.acknowledging[ack.token]"));
        assert!(script.contains("const receipt = function()"));
        assert!(script.contains("VaporForgeConfirmCloudConflict(ack.token)"));
        assert!(script.contains("VaporForgeRetryCloudConflict(ack.token)"));
        assert!(script.contains("'aria-disabled': 'true'"));
        assert!(script.contains("IgnorePendingCloudSessions"));
        assert!(script.contains("SteamClient.Apps.CancelGameAction"));
        assert!(script.contains("new Observer"));
        assert!(script.contains("ActiveWindowInstance.BrowserWindow"));
        assert!(script.contains("targetDocument.querySelectorAll"));
        assert!(script.contains("customOverlay.classList.contains('inactive')"));
        assert!(script.contains("activeDialog.close()"));
        assert!(script.contains("activeDialog.remove()"));
        assert!(script.contains("restoreNativeCloudDialog(appId)"));
        assert!(script.contains("customDialog.showModal()"));
        assert!(script.contains("state.observer.disconnect()"));
        assert!(script.contains("state.epoch[key] !== epoch"));
        assert!(script.contains("popupHeight: 560"));
        assert!(script.contains("popupWidth: 740"));
        assert!(script.contains("settings.GetCurrentLanguage()"));
        assert!(script.contains("if (state.languageReady || state.languagePromise) return"));
        assert!(script.contains("if (!bridge.isTargetSteamUiContext()) return false"));
        assert!(script.contains("if (!confirmReady()) return false"));
        assert!(script.contains("cloudConflictLocales"));
        assert!(!script.contains("setInterval"));
        assert!(!script.contains("setTimeout"));
        assert!(!script.contains("synthetic"));
    }

    #[test]
    fn cloud_conflict_locales_match_english_keys() {
        let locales: serde_json::Value = serde_json::from_str(CLOUD_CONFLICT_I18N).unwrap();
        let locales = locales.as_object().unwrap();
        assert_eq!(
            locales.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["english", "japanese", "schinese", "tchinese"])
        );
        let english = locales["english"].as_object().unwrap();
        for locale in locales.values() {
            let messages = locale.as_object().unwrap();
            assert_eq!(messages.len(), english.len());
            for key in english.keys() {
                assert!(messages
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .is_some());
            }
        }
    }

    #[test]
    fn toast_locales_match_english_keys() {
        let locales: serde_json::Value = serde_json::from_str(TOAST_I18N).unwrap();
        let locales = locales.as_object().unwrap();
        assert_eq!(
            locales.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["english", "japanese", "schinese", "tchinese"])
        );
        let english = locales["english"].as_object().unwrap();
        for locale in locales.values() {
            let messages = locale.as_object().unwrap();
            assert_eq!(messages.len(), english.len());
            for key in english.keys() {
                let message = messages.get(key).and_then(serde_json::Value::as_object);
                assert!(message
                    .and_then(|value| value.get("title"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty()));
                assert!(message
                    .and_then(|value| value.get("body"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty()));
            }
        }
    }

    #[test]
    fn toast_bridge_localizes_stable_message_keys() {
        let script = bridge_script();
        assert!(script.contains("settings.GetCurrentLanguage()"));
        assert!(script.contains("toastLocales"));
        assert!(script.contains("function pendingNeedsLanguage()"));
        assert!(script.contains("function localizeToast(toast)"));
        assert!(script.contains("var toast = localizeToast(state.pending.shift())"));
        assert!(!script.contains("setInterval"));
        assert!(!script.contains("setTimeout"));
    }

    #[test]
    fn bridge_styles_warning_and_error_toasts() {
        let script = bridge_script();
        assert!(script.contains("function toastKind(data)"));
        assert!(script.contains("function toastStyle(data, kind)"));
        assert!(script.contains("function toastLogoMode(data)"));
        assert!(script.contains("if (mode === 'hidden') return 'hidden'"));
        assert!(script.contains("VaporForgeToast-' + kind"));
        assert!(script.contains("function toastBannerBackground(kind)"));
        assert!(script.contains("if (kind === 'error') return '#de3618'"));
        assert!(script.contains("if (kind === 'warning') return '#ffc82c'"));
        assert!(script.contains("VaporForgeToastStyle-' + style"));
        assert!(script.contains("function popupLogoClass(css)"));
        assert!(script.contains("css.ShortLogoDimensions || css.StandardLogoDimensions"));
        assert!(script.contains("function popupLogoStyle()"));
        assert!(script.contains("if (!isGamepadUiReady()) root.width = '100%'"));
        assert!(script.contains("root.paddingLeft = '10px'"));
        assert!(!script.contains("flex: '0 0 13px'"));
        assert!(script.contains("if (logo) toast.appendChild(logo)"));
        assert!(script.contains("function defaultLogoStyle(kind, style)"));
        assert!(script.contains("function renderDefaultLogo("));
        assert!(script.contains("logo.textContent = 'SR'"));
        assert!(script.contains("children: 'SR'"));
    }

    #[test]
    fn init_toast_respects_config() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = take_pending();
        let _ = take_ui_work();

        let mut config = RuntimeConfig::default();
        config.toast.enabled = false;
        show_init_toast(&config);
        assert!(take_pending().is_empty());

        config.toast.enabled = true;
        config.toast.init = true;
        show_init_toast(&config);
        let pending = take_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].title, DEFAULT_TITLE);
        assert_eq!(pending[0].body, INIT_BODY);
        assert_eq!(pending[0].action, ToastAction::Dismiss);
        assert_eq!(pending[0].message_key, "loaded");

        let _ = take_ui_work();
    }

    #[test]
    fn restore_pending_preserves_retry_order() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = take_pending();
        let _ = take_ui_work();

        show_toast("a", "b", ToastLogo::Default, 1000);
        let retry = take_pending();
        assert_eq!(retry.len(), 1);

        show_toast("new", "toast", ToastLogo::Default, 1000);
        restore_pending(&retry);

        let pending = take_pending();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].title, "a");
        assert_eq!(pending[1].title, "new");

        let _ = take_ui_work();
    }

    #[test]
    fn toast_production_publishes_ui_work() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = take_pending();
        let _ = take_ui_work();

        show_toast("title", "body", ToastLogo::Default, 1000);
        assert!(take_ui_work());
        assert!(!take_ui_work());

        let pending = take_pending();
        restore_pending(&pending);
        assert!(!take_ui_work());
        let _ = take_pending();
    }
}
