(function(){
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
})();
