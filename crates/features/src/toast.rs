use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use tracing::warn;
use vapor_forge_config::RuntimeConfig;

static PENDING_TOASTS: Mutex<Vec<ToastRequest>> = Mutex::new(Vec::new());
static HAS_WORK: AtomicBool = AtomicBool::new(false);
static NEXT_TOAST_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_TITLE: &str = "Vapor Forge";
const INIT_BODY: &str = "Loaded successfully";
const DEFAULT_DURATION_MS: u32 = 5000;
const STEAMUI_BRIDGE_JS: &str = include_str!("ui/steamui_bridge.js");
const TOAST_JS: &str = include_str!("ui/toast.js");
const CLOUD_CONFLICT_JS: &str = include_str!("ui/cloud_conflict.js");
const CLOUD_CONFLICT_I18N: &str = include_str!("ui/cloud_conflict_i18n.json");

#[derive(Clone, Debug)]
pub struct ToastRequest {
    id: u64,
    kind: ToastKind,
    style: ToastStyle,
    title: String,
    body: String,
    icon: String,
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

pub fn show_toast(title: &str, body: &str, icon: Option<&str>, duration_ms: u32) {
    show_toast_with_kind(ToastKind::Info, title, body, icon, duration_ms);
}

pub fn show_toast_with_kind(
    kind: ToastKind,
    title: &str,
    body: &str,
    icon: Option<&str>,
    duration_ms: u32,
) {
    show_toast_with_style(kind, kind.default_style(), title, body, icon, duration_ms);
}

pub fn show_toast_with_style(
    kind: ToastKind,
    style: ToastStyle,
    title: &str,
    body: &str,
    icon: Option<&str>,
    duration_ms: u32,
) {
    let mut pending = match PENDING_TOASTS.lock() {
        Ok(p) => p,
        Err(_) => {
            warn!("toast: pending queue lock poisoned");
            return;
        }
    };
    pending.push(ToastRequest {
        id: NEXT_TOAST_ID.fetch_add(1, Ordering::Relaxed),
        kind,
        style,
        title: if title.is_empty() {
            DEFAULT_TITLE.to_owned()
        } else {
            title.to_owned()
        },
        body: body.to_owned(),
        icon: icon.unwrap_or("").to_owned(),
        duration_ms,
    });
    HAS_WORK.store(true, Ordering::Release);
}

pub fn show_init_toast(config: &RuntimeConfig) {
    if config.toast.enabled && config.toast.init {
        show_toast(DEFAULT_TITLE, INIT_BODY, None, DEFAULT_DURATION_MS);
    }
}

pub fn has_pending_work() -> bool {
    HAS_WORK.load(Ordering::Acquire)
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
            HAS_WORK.store(true, Ordering::Release);
        }
        Err(_) => warn!("toast: pending queue lock poisoned"),
    }
}

pub fn mark_idle_if_empty() {
    let empty = PENDING_TOASTS
        .lock()
        .map(|pending| pending.is_empty())
        .unwrap_or(false);
    if empty {
        HAS_WORK.store(false, Ordering::Release);
    }
}

pub fn toast_script(toast: &ToastRequest) -> String {
    let duration = if toast.duration_ms == 0 {
        DEFAULT_DURATION_MS
    } else {
        toast.duration_ms
    };
    format!(
        "(function(){{try{{if(!window.VaporForgeToastBridge||!window.VaporForgeToastBridge.showToast){{return false;}}window.VaporForgeToastBridge.showToast({{id:{},kind:\"{}\",style:\"{}\",title:\"{}\",body:\"{}\",icon:\"{}\",duration:{},playSound:true,sound:{},eType:{},critical:{}}});return true;}}catch(e){{try{{console.log('[VaporForgeToast] show error: '+e);}}catch(_){{}}}}}})();",
        toast.id,
        toast.kind.as_js_str(),
        toast.style.as_js_str(),
        js_escape(&toast.title),
        js_escape(&toast.body),
        js_escape(&toast.icon),
        duration,
        toast.kind.sound(),
        toast.kind.e_type(),
        toast.kind.critical()
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
            + CLOUD_CONFLICT_JS.len()
            + CLOUD_CONFLICT_I18N.len()
            + 256;
        let mut script = String::with_capacity(capacity);
        script.push_str(STEAMUI_BRIDGE_JS);
        script.push_str("\n(function(){try{var bridge=window.VaporForgeUIBridge;");
        script.push_str("if(bridge){bridge.resources.cloudConflictLocales=");
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
            title: "t".to_owned(),
            body: "b".to_owned(),
            icon: String::new(),
            duration_ms: 5000,
        };
        let script = toast_script(&toast);
        assert!(script.contains("VaporForgeToastBridge"));
        assert!(script.contains("kind:\"info\""));
        assert!(script.contains("style:\"accent\""));
        assert!(script.contains("critical:false"));
        assert!(!script.contains("SLS"));
    }

    #[test]
    fn toast_script_marks_error_toasts_critical() {
        let _guard = TEST_LOCK.lock().unwrap();
        let toast = ToastRequest {
            id: 43,
            kind: ToastKind::Error,
            style: ToastStyle::Banner,
            title: "t".to_owned(),
            body: "b".to_owned(),
            icon: String::new(),
            duration_ms: 5000,
        };
        let script = toast_script(&toast);
        assert!(script.contains("kind:\"error\""));
        assert!(script.contains("critical:true"));
    }

    #[test]
    fn bridge_renderer_handles_grouped_notifications() {
        let script = bridge_script();
        assert!(script.contains("notifications.filter(isVaporForgeNotification).map"));
        assert!(script.contains("notifications.some(isVaporForgeNotification)"));
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
        assert!(script.contains("version === BRIDGE_VERSION"));
        assert!(script.contains("version: BRIDGE_VERSION"));
        assert!(script.contains("const BRIDGE_VERSION = 12"));
        assert!(script.contains("eType: toast.eType || 31"));
        assert!(script.contains("function allocateNotificationId(toast)"));
        assert!(script.contains("notificationID: id"));
        assert!(script.contains("nNotificationID: id"));
    }

    #[test]
    fn cloud_conflict_bridge_resumes_the_public_game_action() {
        let script = bridge_script();
        assert!(script.contains("SteamClient.Apps.GetGameActionForApp"));
        assert!(script.contains("SteamClient.Apps.VaporForgeResolveCloudConflict"));
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
        assert!(script.contains("if (!Object.keys(state.dialogs).length) return true"));
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
    fn bridge_styles_warning_and_error_toasts() {
        let script = bridge_script();
        assert!(script.contains("function toastKind(data)"));
        assert!(script.contains("function toastStyle(data, kind)"));
        assert!(script.contains("VaporForgeToast-' + kind"));
        assert!(script.contains("function toastBannerBackground(kind)"));
        assert!(script.contains("if (kind === 'error') return '#de3618'"));
        assert!(script.contains("if (kind === 'warning') return '#ffc82c'"));
        assert!(script.contains("VaporForgeToastStyle-' + style"));
    }

    #[test]
    fn init_toast_respects_config() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = take_pending();
        mark_idle_if_empty();

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

        mark_idle_if_empty();
    }

    #[test]
    fn restore_pending_preserves_retry_order() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = take_pending();
        mark_idle_if_empty();

        show_toast("a", "b", None, 1000);
        let retry = take_pending();
        assert_eq!(retry.len(), 1);

        show_toast("new", "toast", None, 1000);
        restore_pending(&retry);

        let pending = take_pending();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].title, "a");
        assert_eq!(pending[1].title, "new");

        mark_idle_if_empty();
    }
}
