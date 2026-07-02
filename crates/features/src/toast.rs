use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use tracing::warn;
use vapor_forge_config::RuntimeConfig;

static PENDING_TOASTS: Mutex<Vec<ToastRequest>> = Mutex::new(Vec::new());
static HAS_WORK: AtomicBool = AtomicBool::new(false);
static NEXT_TOAST_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_TITLE: &str = "Vapor Forge";
const INIT_BODY: &str = "Loaded successfully";
const DEFAULT_DURATION_MS: u32 = 5000;

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
    r#"(function(){
try {
  if (window.VaporForgeToastBridge && window.VaporForgeToastBridge.version === 1) {
    window.VaporForgeToastBridge.tryReady && window.VaporForgeToastBridge.tryReady();
    return;
  }
  const bridge = window.VaporForgeToastBridge = {
    version: 1, req: null, store: null, css: null, jsx: null, focusable: null,
    nextId: 10000, pending: [], seen: {}, renderPatched: false, exportPatched: false, jsxPatched: false, targetSkipLogged: false,
    log: function(msg) { try { console.log('[VaporForgeToast] ' + msg); } catch (_) {} }
  };
  function isTargetSteamUiContext() {
    try {
      const href = String(window.location && window.location.href || '');
      const title = String(document && document.title || '');
      const sharedNames = {
        SharedJSContext: true,
        'Steam Shared Context presented by Valve™': true,
        Steam: true,
        SP: true
      };
      const isSteamUiUrl = href.indexOf('https://steamloopback.host/routes/') !== -1 ||
        href.indexOf('https://steamloopback.host/index.html') !== -1;
      const isSharedContext = href.indexOf('IN_STEAMUI_SHARED_CONTEXT=true') !== -1;
      return isSteamUiUrl && (isSharedContext || !!sharedNames[title]);
    } catch (_) {
      return false;
    }
  }
  function hasAll(text, parts) {
    for (const part of parts) {
      if (text.indexOf(part) === -1) return false;
    }
    return true;
  }
  function isStoreFactory(text) {
    return hasAll(text, ['ProcessNotification', 'm_nNextTestNotificationID']);
  }
  function isCssFactory(text) {
    return hasAll(text, ['StandardTemplateContainer', 'StandardTemplate', 'Title', 'Content']);
  }
  function isRendererFactory(text) {
    return text.indexOf('controller:"notification",method:') !== -1;
  }
  function visitExport(exp, id, mod, cb) {
    if (!exp) return false;
    if (cb(exp, id, mod)) return true;
    if (exp.default && cb(exp.default, id, mod, exp, 'default')) return true;
    if (typeof exp === 'object' || typeof exp === 'function') {
      for (const key of Object.keys(exp)) {
        try { if (cb(exp[key], id, mod, exp, key)) return true; } catch (_) {}
      }
    }
    return false;
  }
  function eachExport(cb, shouldLoadFactory) {
    const req = bridge.req;
    const cache = req && (req.c || req.cache);
    const seen = {};
    if (cache) {
      for (const id in cache) {
        seen[id] = true;
        const mod = cache[id];
        const exp = mod && mod.exports;
        if (visitExport(exp, id, mod, cb)) return true;
      }
    }
    const factories = req && req.m;
    if (!factories || !shouldLoadFactory) return false;
    for (const id of Object.keys(factories)) {
      if (seen[id]) continue;
      var text = '';
      try { text = String(factories[id]); } catch (_) {}
      if (!shouldLoadFactory(text, id)) continue;
      try {
        const exp = req(id);
        const mod = cache && cache[id];
        if (visitExport(exp, id, mod, cb)) return true;
        if (mod && mod.exports !== exp && visitExport(mod.exports, id, mod, cb)) return true;
      } catch (e) {
        bridge.log('module load skipped id=' + id + ' error=' + e);
      }
    }
    return false;
  }
  function isJsxRuntime(exp) {
    return exp && typeof exp.jsx === 'function' && typeof exp.jsxs === 'function';
  }
  function pickJsxRuntime(exp) {
    if (isJsxRuntime(exp)) return exp;
    if (exp && isJsxRuntime(exp.default)) return exp.default;
    return null;
  }
  function findJsxFromRendererFactory() {
    const req = bridge.req;
    const factories = req && req.m;
    if (!factories) return null;
    for (const id of Object.keys(factories)) {
      var text = '';
      try { text = String(factories[id]); } catch (_) {}
      if (!isRendererFactory(text)) continue;
      const importRe = /([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\((\d+)\)/g;
      var match;
      while ((match = importRe.exec(text))) {
        const local = match[1];
        const moduleId = match[2];
        if (text.indexOf(local + '.jsx') === -1 && text.indexOf(local + '.jsxs') === -1) continue;
        try {
          const jsx = pickJsxRuntime(req(moduleId));
          if (jsx) return jsx;
        } catch (_) {}
      }
    }
    return null;
  }
  function findStore() {
    var found = null;
    eachExport(function(exp) {
      if (exp && typeof exp.ProcessNotification === 'function') { found = exp; return true; }
      return false;
    }, isStoreFactory);
    return found;
  }
  function findCss() {
    var found = null;
    eachExport(function(exp) {
      if (exp && exp.StandardTemplateContainer && exp.StandardTemplate && exp.Title && exp.Content) {
        found = exp;
        return true;
      }
      return false;
    }, isCssFactory);
    return found;
  }
  function findJsx() {
    var found = null;
    eachExport(function(exp) {
      found = pickJsxRuntime(exp);
      if (found) return true;
      return false;
    });
    return found || findJsxFromRendererFactory();
  }
  function findFocusable() {
    var found = null;
    eachExport(function(exp) {
      try {
        if (exp && exp.render && typeof exp.render === 'function' && String(exp.render).indexOf('flow-children') !== -1) {
          found = exp;
          return true;
        }
      } catch (_) {}
      return false;
    });
    return found;
  }
  function allocateNotificationId(toast) {
    var id = bridge.nextId++;
    var toastId = Number(toast && toast.id);
    if (Number.isFinite(toastId) && toastId > 0) {
      id = 9999 + Math.floor(toastId);
    }
    var storeNext = Number(bridge.store && bridge.store.m_nNextTestNotificationID);
    if (Number.isFinite(storeNext)) {
      id = Math.max(id, storeNext);
      bridge.store.m_nNextTestNotificationID = id + 1;
    }
    bridge.nextId = Math.max(bridge.nextId, id + 1);
    return id;
  }
  function isValveToastRenderer(type) {
    try { return typeof type === 'function' && String(type).indexOf('controller:"notification",method:') !== -1; }
    catch (_) { return false; }
  }
  function renderFallback(jsx, title, body) {
    return jsx.jsx('div', { className: 'VaporForgeToastFallback', children: (title || 'Vapor Forge') + ': ' + (body || '') });
  }
  function toastKind(data) {
    var kind = String(data && data.kind || 'info').toLowerCase();
    if (kind === 'warn') return 'warning';
    if (kind === 'warning' || kind === 'error') return kind;
    return 'info';
  }
  function toastStyle(data, kind) {
    var style = String(data && data.style || '').toLowerCase();
    if (style === 'banner' || style === 'accent') return style;
    return kind === 'info' ? 'accent' : 'banner';
  }
  function toastAccent(kind) {
    if (kind === 'error') return '#ff5f57';
    if (kind === 'warning') return '#ffb454';
    return '#66c0f4';
  }
  function toastBannerBackground(kind) {
    if (kind === 'error') return '#de3618';
    if (kind === 'warning') return '#ffc82c';
    return '#66c0f4';
  }
  function toastBannerForeground(kind) {
    return kind === 'warning' ? '#000' : '#fff';
  }
  function toastBadgeText(kind) {
    if (kind === 'error') return 'X';
    if (kind === 'warning') return '!';
    return 'SR';
  }
  function toastRootStyle(kind, style) {
    if (style === 'banner') {
      return {
        backgroundColor: toastBannerBackground(kind),
        color: toastBannerForeground(kind),
        borderLeft: '0',
        boxSizing: 'border-box',
        fontFamily: '"Motiva Sans", Helvetica, sans-serif',
        fontWeight: 700,
        letterSpacing: '.5px',
        textTransform: 'uppercase'
      };
    }
    return {
      borderLeft: '3px solid ' + toastAccent(kind),
      boxSizing: 'border-box'
    };
  }
  function popupRootStyle(kind, style) {
    var root = toastRootStyle(kind, style);
    if (style === 'banner') {
      root.minHeight = '70px';
      root.padding = '0 8px';
      root.gap = '10px';
    }
    return root;
  }
  function qamRootStyle(kind, style) {
    var root = toastRootStyle(kind, style);
    if (style === 'banner') {
      root.minHeight = '36px';
      root.padding = '0 8px';
    }
    return root;
  }
  function toastTextStyle(kind, style, isBody) {
    if (style !== 'banner') return null;
    return {
      color: toastBannerForeground(kind),
      fontSize: isBody ? '11px' : '10px',
      fontWeight: 700,
      letterSpacing: '.5px',
      textTransform: 'uppercase',
      textShadow: 'none'
    };
  }
  function renderDefaultLogo(jsx, className, kind, style) {
    var banner = style === 'banner';
    return jsx.jsx('div', {
      className: className || '',
      style: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        borderRadius: '6px',
        border: banner ? '1px solid currentColor' : '0',
        background: banner ? 'transparent' : 'linear-gradient(135deg,' + toastAccent(kind) + ',#2a475e)',
        color: banner ? 'inherit' : '#fff',
        fontSize: '13px',
        fontWeight: 700,
        lineHeight: 1
      },
      children: toastBadgeText(kind)
    });
  }
  function renderPopupToast(css, jsx, data) {
    try {
      var title = data.title || 'Vapor Forge';
      var body = data.body || '';
      var icon = data.icon || '';
      var kind = toastKind(data);
      var style = toastStyle(data, kind);
      var logo = icon
        ? jsx.jsx('img', { className: css.Icon || css.AppLogo || '', src: icon, draggable: false })
        : renderDefaultLogo(jsx, css.Icon || css.AppLogo || '', kind, style);
      return jsx.jsxs('div', { className: (css.ShortTemplate || css.StandardTemplate || '') + ' VaporForgePopupToast VaporForgeToast-' + kind + ' VaporForgeToastStyle-' + style, style: popupRootStyle(kind, style), children: [
        logo,
        jsx.jsxs('div', { className: css.Content || '', children: [
          jsx.jsx('div', { className: css.Title || '', style: toastTextStyle(kind, style, false), children: title }),
          body ? jsx.jsx('div', { className: css.Body || css.StandardNotificationDescription || '', style: toastTextStyle(kind, style, true), children: body }) : null
        ]})
      ]});
    } catch (e) {
      bridge.log('popup render error: ' + e);
      return renderFallback(jsx, data.title, data.body);
    }
  }
  function renderQamToast(css, jsx, data, notification) {
    try {
      var title = data.title || 'Vapor Forge';
      var body = data.body || '';
      var icon = data.icon || '';
      var kind = toastKind(data);
      var style = toastStyle(data, kind);
      var logo = icon
        ? jsx.jsx('img', { className: css.StandardLogoDimensions || css.Icon || '', src: icon, draggable: false })
        : renderDefaultLogo(jsx, css.StandardLogoDimensions || css.Icon || '', kind, style);
      var timestamp = notification && notification.rtCreated
        ? jsx.jsx('div', { className: css.Timestamp || '', style: toastTextStyle(kind, style, true), children: new Date(notification.rtCreated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) })
        : null;
      var content = jsx.jsx('div', { className: (css.StandardTemplateContainer || '') + ' VaporForgeQAMToast VaporForgeToast-' + kind + ' VaporForgeToastStyle-' + style, style: qamRootStyle(kind, style), children:
        jsx.jsxs('div', { className: css.StandardTemplate || '', children: [
          logo,
          jsx.jsxs('div', { className: css.Content || '', children: [
            jsx.jsxs('div', { className: css.Header || '', children: [
              jsx.jsx('div', { className: css.Title || '', style: toastTextStyle(kind, style, false), children: title }),
              timestamp
            ]}),
            body ? jsx.jsx('div', { className: css.StandardNotificationDescription || '', style: toastTextStyle(kind, style, true), children: body }) : null
          ]})
        ]})
      });
      var Focusable = bridge.focusable;
      if (Focusable) return jsx.jsx(Focusable, { onActivate: function() {}, children: content });
      return content;
    } catch (e) {
      bridge.log('qam render error: ' + e);
      return renderFallback(jsx, data.title, data.body);
    }
  }
  function renderVaporForgeToast(props) {
    var css = bridge.css || {};
    var jsx = bridge.jsx;
    var notifications = props && props.group && props.group.notifications || [];
    var location = props && props.location;
    return notifications.filter(isVaporForgeNotification).map(function(notification) {
      var data = notification && notification.data || {};
      if (location === 1) return renderPopupToast(css, jsx, data);
      return renderQamToast(css, jsx, data, notification);
    });
  }
  function isVaporForgeNotification(notification) {
    return !!(notification && (notification.vaporForge || (notification.data && notification.data.vaporForge)));
  }
  function isVaporForgeProps(props) {
    try {
      const group = props && props.group;
      const notifications = group && group.notifications || [];
      if (group && group.vaporForge) return true;
      return notifications.some(isVaporForgeNotification);
    } catch (_) {
      return false;
    }
  }
  function patchJsxRuntime(jsx) {
    if (!jsx || bridge.jsxPatched) return !!jsx;
    const originalJsx = jsx.jsx;
    const originalJsxs = jsx.jsxs;
    if (typeof originalJsx !== 'function' || typeof originalJsxs !== 'function') return false;
    function wrap(create) {
      return function(type, props, key) {
        if (type !== renderVaporForgeToast && typeof type === 'function' && isVaporForgeProps(props)) {
          return create.call(this, renderVaporForgeToast, props, key);
        }
        return create.apply(this, arguments);
      };
    }
    try {
      jsx.jsx = wrap(originalJsx);
      jsx.jsxs = wrap(originalJsxs);
      bridge.jsxPatched = true;
      bridge.renderPatched = true;
      bridge.log('JSX notification bridge ready');
      return true;
    } catch (e) {
      bridge.log('JSX patch error: ' + e);
      return false;
    }
  }
  function patchJsxRenderer() {
    if (bridge.renderPatched) return true;
    const jsx = bridge.jsx || findJsx();
    const css = bridge.css || findCss();
    if (!jsx || !css) return false;
    bridge.jsx = jsx;
    bridge.css = css;
    const jsxPatched = patchJsxRuntime(jsx);
    bridge.focusable = bridge.focusable || findFocusable();
    if (jsxPatched) return true;
    var patched = false;
    eachExport(function(exp, id, mod, parent, key) {
      if (!isValveToastRenderer(exp) || exp.__vaporForgePatched) return false;
      const original = exp;
      const wrapped = function(props) {
        try {
          const n = props && props.group && props.group.notifications && props.group.notifications[0];
          if (n && n.vaporForge) return renderVaporForgeToast(props);
        } catch (e) { bridge.log('renderer patch error: ' + e); }
        return original.apply(this, arguments);
      };
      wrapped.__vaporForgePatched = true;
      try { wrapped.toString = function() { return original.toString(); }; } catch (_) {}
      if (parent && key) {
        try { parent[key] = wrapped; patched = true; return true; } catch (_) {}
      }
      if (mod && mod.exports === exp) {
        try { mod.exports = wrapped; patched = true; return true; } catch (_) {}
      }
      return false;
    }, isRendererFactory);
    if (patched) {
      bridge.exportPatched = true;
      bridge.renderPatched = true;
      bridge.log('Valve toast renderer export bridge ready');
      return true;
    }
    return false;
  }
  function captureReq(req) {
    if (!req || bridge.req === req) return;
    bridge.req = req;
    try { bridge.log('webpack require captured keys=' + Object.keys(req).join(',')); }
    catch (_) { bridge.log('webpack require captured'); }
    bridge.tryReady();
  }
  function wrapChunkArray(arr) {
    if (!arr || arr.__vaporForgeWrapped) return;
    const oldPush = arr.push;
    arr.push = function(chunk) {
      try {
        if (Array.isArray(chunk) && typeof chunk[2] === 'function') {
          const runtime = chunk[2];
          chunk[2] = function(req) { captureReq(req); return runtime.apply(this, arguments); };
        }
      } catch (_) {}
      const ret = oldPush.apply(this, arguments);
      bridge.tryReady();
      return ret;
    };
    arr.__vaporForgeWrapped = true;
  }
  let chunkArray = window.webpackChunksteamui || [];
  try {
    Object.defineProperty(window, 'webpackChunksteamui', {
      configurable: true,
      get: function() { return chunkArray; },
      set: function(v) { chunkArray = v; wrapChunkArray(chunkArray); }
    });
  } catch (_) {}
  window.webpackChunksteamui = chunkArray;
  wrapChunkArray(chunkArray);
  bridge.tryReady = function() {
    if (!isTargetSteamUiContext()) {
      if (!bridge.targetSkipLogged) {
        bridge.targetSkipLogged = true;
        bridge.log('skipping non-main SteamUI context');
      }
      return false;
    }
    if (!bridge.req && window.__webpack_require__) captureReq(window.__webpack_require__);
    if (bridge.req) {
      bridge.store = bridge.store || findStore();
      patchJsxRenderer();
    }
    if (bridge.store && bridge.renderPatched) bridge.flush();
  };
  bridge.flush = function() {
    if (!isTargetSteamUiContext()) return false;
    if (!bridge.store || !bridge.renderPatched) return false;
    while (bridge.pending.length) {
      var toast = bridge.pending.shift();
      if (toast.id != null && bridge.seen['flushed:' + toast.id]) continue;
      if (toast.id != null) bridge.seen['flushed:' + toast.id] = true;
      var id = allocateNotificationId(toast);
      var toastData = {
        notificationID: id,
        nNotificationID: id,
        bNewIndicator: true,
        rtCreated: Date.now(),
        eType: toast.eType || 31,
        eSource: 1,
        nToastDurationMS: toast.duration || 5000,
        data: toast,
        vaporForge: true
      };
      toastData.data.vaporForge = true;
      function fnTray(notification, tray) {
        var group = {
          eType: notification.eType,
          notifications: [notification]
        };
        tray.unshift(group);
      }
      bridge.store.ProcessNotification({
        showToast: true,
        sound: toast.sound == null ? 6 : toast.sound,
        playSound: toast.playSound !== false,
        eFeature: 0,
        toastDurationMS: toastData.nToastDurationMS,
        bCritical: !!toast.critical,
        fnTray: fnTray,
      }, toastData, 0);
    }
    return true;
  };
  bridge.showToast = function(toast) {
    toast = toast || {};
    if (toast.id != null) {
      var key = 'queued:' + toast.id;
      if (bridge.seen[key]) return true;
      bridge.seen[key] = true;
    }
    bridge.pending.push(toast);
    bridge.tryReady();
    return bridge.pending.length === 0;
  };
  try { chunkArray.push([[Date.now() & 0xfffffff], {}, function(req) { captureReq(req); }]); } catch (_) {}
  bridge.tryReady();
} catch (e) {
  try { console.log('[VaporForgeToast] bootstrap error: ' + e); } catch (_) {}
}
})();"#
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(script.contains("version === 1"));
        assert!(script.contains("version: 1"));
        assert!(script.contains("eType: toast.eType || 31"));
        assert!(script.contains("function allocateNotificationId(toast)"));
        assert!(script.contains("notificationID: id"));
        assert!(script.contains("nNotificationID: id"));
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
