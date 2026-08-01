(function(){
try {
  if (window.VaporForgeUIBridge && window.VaporForgeUIBridge.version === 11) {
    window.VaporForgeUIBridge.tryReady && window.VaporForgeUIBridge.tryReady();
    return;
  }
  const bridge = window.VaporForgeUIBridge = {
    version: 11, req: null, store: null, css: null, jsx: null, focusable: null,
    modal: null, windowStore: null,
    nextId: 10000, pending: [], seen: {}, renderPatched: false, exportPatched: false, jsxPatched: false, targetSkipLogged: false,
    cloudDialogs: {}, cloudWaiting: {}, cloudHandles: {}, cloudClose: {}, cloudOpening: {}, cloudEpoch: {},
    cloudPromoted: {}, cloudNativeDialogs: {}, cloudObserver: null, cloudObserverDocument: null,
    log: function(msg) { try { console.log('[VaporForgeToast] ' + msg); } catch (_) {} }
  };
  window.VaporForgeToastBridge = bridge;
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
  function isModalFactory(text) {
    return hasAll(text, ['RequestModalMeasure', 'ShowLegacyPopupModal', 'bHideMainWindowForPopouts']);
  }
  function isWindowStoreFactory(text) {
    return hasAll(text, ['ActiveWindowInstance', 'SteamUIWindows', 'SetRunningApp']);
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
  function findModal() {
    var found = null;
    eachExport(function(exp) {
      if (typeof exp !== 'function') return false;
      var text = '';
      try { text = String(exp); } catch (_) {}
      if (hasAll(text, ['RequestModalMeasure', 'bNeverPopOut', 'bForcePopOut'])) {
        found = exp;
        return true;
      }
      return false;
    }, isModalFactory);
    return found;
  }
  function findWindowStore() {
    var found = null;
    eachExport(function(exp) {
      try {
        if (exp && typeof exp === 'object' && 'ActiveWindowInstance' in exp && exp.WindowStore) {
          found = exp;
          return true;
        }
      } catch (_) {}
      return false;
    }, isWindowStoreFactory);
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
  function formatCloudBytes(value) {
    var bytes = Number(value || 0);
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    var index = 0;
    while (bytes >= 1024 && index < units.length - 1) { bytes /= 1024; index++; }
    return (index ? bytes.toFixed(bytes >= 10 ? 0 : 1) : Math.floor(bytes)) + ' ' + units[index];
  }
  function setCloudBusy(root, busy, message) {
    if (!root) return;
    const selected = root.getAttribute('data-selected-token') || '';
    root.querySelectorAll('button').forEach(function(button) {
      button.disabled = !!busy;
      if (button.getAttribute('data-action') === 'continue') {
        const ready = !!selected && !busy;
        button.setAttribute('aria-disabled', ready ? 'false' : 'true');
        button.style.opacity = ready ? '1' : '0.45';
        button.style.cursor = ready ? 'pointer' : 'default';
      }
    });
    const status = root.querySelector('[data-cloud-status]');
    if (status) status.textContent = message || '';
  }
  function finishGameAction(appId, cancel, onComplete, onError) {
    try {
      SteamClient.Apps.GetGameActionForApp(String(appId), function(handle) {
        handle = Number(handle);
        if (!Number.isFinite(handle) || handle <= 0) {
          onError('Steam no longer has a pending launch action.');
          return;
        }
        try {
          restoreNativeCloudDialog(appId);
          if (cancel) SteamClient.Apps.CancelGameAction(handle);
          else SteamClient.Apps.ContinueGameAction(handle, 'IgnorePendingCloudSessions');
          delete bridge.cloudNativeDialogs[String(appId)];
          onComplete();
        } catch (error) {
          detachNativeCloudDialog(appId);
          bridge.log('cloud game action error: ' + error);
          onError(cancel
            ? 'The launch could not be cancelled.'
            : 'The launch could not be continued.');
        }
      });
    } catch (error) {
      bridge.log('cloud game action error: ' + error);
      onError(cancel
        ? 'The launch could not be cancelled.'
        : 'The launch could not be continued.');
    }
  }
  function submitCloudChoice(dialog, token, cancel, root, closeModal) {
    if (!token || bridge.cloudWaiting[token]) return;
    setCloudBusy(root, true, cancel ? 'Cancelling...' : 'Saving selection...');
    bridge.cloudWaiting[token] = {
      appId: dialog.app_id,
      root: root,
      closeModal: closeModal
    };
    try {
      SteamClient.Apps.VaporForgeResolveCloudConflict(token);
    } catch (error) {
      delete bridge.cloudWaiting[token];
      setCloudBusy(root, false, cancel
        ? 'The operation could not be cancelled.'
        : 'The selection could not be submitted.');
    }
  }
  function CloudConflictModal(props) {
    const jsx = bridge.jsx;
    const dialog = props.dialog;
    const appId = Number(dialog.app_id);
    bridge.cloudClose[String(appId)] = props.closeModal;
    const rows = dialog.candidates.map(function(candidate) {
      const title = (candidate.machine_name || 'Unknown device') +
        (candidate.is_local ? ' (this device)' : '');
      const time = Number(candidate.created_at_ms) > 0
        ? new Date(Number(candidate.created_at_ms)).toLocaleString()
        : 'Unknown time';
      const names = Array.isArray(candidate.file_names) && candidate.file_names.length
        ? candidate.file_names.join(', ')
        : 'No files';
      return jsx.jsxs('button', {
        type: 'button',
        'data-cloud-token': candidate.token,
        onClick: function(event) {
          const root = event.currentTarget.closest('[data-vapor-cloud-conflict]');
          if (!root) return;
          root.setAttribute('data-selected-token', candidate.token);
          root.querySelectorAll('[data-cloud-token]').forEach(function(button) {
            const selected = button.getAttribute('data-cloud-token') === candidate.token;
            button.style.borderColor = selected ? '#66c0f4' : '#4a515a';
            button.style.backgroundColor = selected ? '#303b45' : '#292d33';
          });
          setCloudBusy(root, false, '');
        },
        style: {
          width: '100%', minHeight: '76px', padding: '12px 14px', textAlign: 'left',
          color: '#f2f2f2', backgroundColor: '#292d33', border: '1px solid #4a515a',
          borderRadius: '3px', cursor: 'pointer', display: 'grid',
          gridTemplateColumns: '1fr auto', gap: '6px 14px', boxSizing: 'border-box'
        },
        children: [
          jsx.jsx('div', { style: { fontSize: '15px', fontWeight: '600' }, children: title }),
          jsx.jsx('div', { style: { color: '#b8bdc3', fontSize: '12px', textAlign: 'right' }, children: 'Revision ' + candidate.revision }),
          jsx.jsx('div', { style: { color: '#c7cbd0', fontSize: '12px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }, children: names }),
          jsx.jsx('div', { style: { color: '#b8bdc3', fontSize: '12px', textAlign: 'right' }, children: time + ' / ' + candidate.file_count + ' files / ' + formatCloudBytes(candidate.total_bytes) })
        ]
      }, candidate.token);
    });
    return jsx.jsxs('div', {
      'data-vapor-cloud-conflict': String(appId),
      style: {
        width: 'min(760px, calc(100vw - 48px))', maxHeight: 'calc(100vh - 48px)',
        overflow: 'auto', backgroundColor: '#202328', color: '#f2f2f2',
        boxSizing: 'border-box', padding: '24px', fontFamily: 'Motiva Sans, Arial, sans-serif'
      },
      children: [
        jsx.jsx('div', { style: { fontSize: '22px', fontWeight: '600', marginBottom: '8px' }, children: 'Cloud save conflict' }),
        jsx.jsx('div', { style: { color: '#b8bdc3', fontSize: '14px', lineHeight: '20px', marginBottom: '18px' }, children: 'Choose the save version to keep.' }),
        jsx.jsx('div', { style: { display: 'grid', gap: '8px' }, children: rows }),
        jsx.jsx('div', { 'data-cloud-status': '1', style: { minHeight: '20px', marginTop: '12px', color: '#ffb454', fontSize: '13px' }, children: '' }),
        jsx.jsxs('div', {
          style: { display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '12px' },
          children: [
            jsx.jsx('button', {
              type: 'button',
              onClick: function(event) {
                const root = event.currentTarget.closest('[data-vapor-cloud-conflict]');
                submitCloudChoice(dialog, dialog.cancel_token, true, root, props.closeModal);
              },
              style: {
                minWidth: '96px', height: '38px', border: '1px solid #69727d',
                borderRadius: '3px', backgroundColor: '#343941', color: '#fff',
                cursor: 'pointer', fontSize: '14px'
              },
              children: 'Cancel'
            }),
            jsx.jsx('button', {
              type: 'button',
              'aria-disabled': 'true',
              'data-action': 'continue',
              onClick: function(event) {
                const root = event.currentTarget.closest('[data-vapor-cloud-conflict]');
                const token = root && root.getAttribute('data-selected-token');
                submitCloudChoice(dialog, token, false, root, props.closeModal);
              },
              style: {
                minWidth: '112px', height: '38px', border: '0', borderRadius: '3px',
                backgroundColor: '#1a9fff', color: '#fff', cursor: 'default', opacity: '0.45',
                fontSize: '14px', fontWeight: '600'
              },
              children: 'Continue'
            })
          ]
        })
      ]
    });
  }
  function closeCloudConflict(appId) {
    const key = String(appId);
    const close = bridge.cloudClose[key];
    const handle = bridge.cloudHandles[key];
    bridge.cloudEpoch[key] = Number(bridge.cloudEpoch[key] || 0) + 1;
    delete bridge.cloudClose[key];
    delete bridge.cloudHandles[key];
    delete bridge.cloudOpening[key];
    try {
      if (typeof close === 'function') close();
      else if (handle && typeof handle.Close === 'function') handle.Close();
    } catch (_) {}
  }
  function renderCloudConflict(appId) {
    const key = String(appId);
    const dialog = bridge.cloudDialogs[key];
    if (!dialog || !Array.isArray(dialog.candidates) || dialog.candidates.length < 2) return false;
    if (bridge.cloudHandles[key] || bridge.cloudOpening[key]) return true;
    if (!bridge.jsx || !bridge.modal || !bridge.windowStore) return false;
    const owner = bridge.windowStore.ActiveWindowInstance &&
      bridge.windowStore.ActiveWindowInstance.BrowserWindow;
    if (!owner) return false;
    const epoch = Number(bridge.cloudEpoch[key] || 0) + 1;
    bridge.cloudEpoch[key] = epoch;
    bridge.cloudOpening[key] = true;
    const element = bridge.jsx.jsx(CloudConflictModal, { dialog: dialog });
    Promise.resolve(bridge.modal(element, owner, { bNeverPopOut: true })).then(function(handle) {
      if (bridge.cloudEpoch[key] !== epoch) {
        if (handle && typeof handle.Close === 'function') handle.Close();
        return;
      }
      bridge.cloudOpening[key] = false;
      if (bridge.cloudDialogs[key] === dialog) {
        bridge.cloudHandles[key] = handle;
        ensureCloudObserver();
      }
      else if (handle && typeof handle.Close === 'function') handle.Close();
    }).catch(function(error) {
      bridge.cloudOpening[key] = false;
      bridge.log('cloud modal error: ' + error);
    });
    return true;
  }
  function ensureCloudObserver() {
    const owner = bridge.windowStore && bridge.windowStore.ActiveWindowInstance &&
      bridge.windowStore.ActiveWindowInstance.BrowserWindow;
    const targetDocument = owner && owner.document;
    const Observer = owner && owner.MutationObserver;
    if (!targetDocument || typeof Observer !== 'function') return;
    if (bridge.cloudObserver && bridge.cloudObserverDocument === targetDocument) return;
    if (bridge.cloudObserver) bridge.cloudObserver.disconnect();
    bridge.cloudObserverDocument = targetDocument;
    bridge.cloudObserver = new Observer(function() {
      Object.keys(bridge.cloudDialogs).forEach(function(key) {
        promoteCloudDialog(key, targetDocument);
      });
    });
    bridge.cloudObserver.observe(targetDocument.documentElement, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ['class']
    });
  }
  function stopCloudObserverIfIdle() {
    if (!bridge.cloudObserver || Object.keys(bridge.cloudDialogs).length) return;
    bridge.cloudObserver.disconnect();
    bridge.cloudObserver = null;
    bridge.cloudObserverDocument = null;
  }
  function promoteCloudDialog(key, targetDocument) {
    if (bridge.cloudPromoted[key]) return;
    const roots = targetDocument.querySelectorAll('[data-vapor-cloud-conflict="' + key + '"]');
    const root = roots.length && roots[roots.length - 1];
    const customOverlay = root && root.closest('.ModalOverlayContent');
    if (!customOverlay || !customOverlay.classList.contains('inactive')) return;
    const activeOverlay = Array.from(targetDocument.querySelectorAll('.ModalOverlayContent.active'))
      .find(function(overlay) { return !overlay.contains(root); });
    const customDialog = customOverlay.closest('dialog');
    const activeDialog = activeOverlay && activeOverlay.closest('dialog');
    const parent = activeDialog && activeDialog.parentNode;
    if (!activeDialog || !customDialog || !parent) return;
    bridge.cloudPromoted[key] = true;
    try {
      bridge.cloudNativeDialogs[key] = {
        dialog: activeDialog,
        parent: parent,
        nextSibling: activeDialog.nextSibling,
        display: activeDialog.style.display,
        visibility: activeDialog.style.visibility,
        pointerEvents: activeDialog.style.pointerEvents,
        inert: activeDialog.inert,
        activeOverlay: activeOverlay,
        customOverlay: customOverlay,
        customDialog: customDialog
      };
      activeDialog.close();
      activeDialog.remove();
      activeOverlay.classList.remove('active');
      activeOverlay.classList.add('inactive');
      customOverlay.classList.remove('inactive');
      customOverlay.classList.add('active');
      customDialog.showModal();
    } catch (error) {
      delete bridge.cloudPromoted[key];
      restoreNativeCloudDialog(Number(key));
      delete bridge.cloudNativeDialogs[key];
      activeOverlay.classList.remove('inactive');
      activeOverlay.classList.add('active');
      customOverlay.classList.remove('active');
      customOverlay.classList.add('inactive');
      try { if (customDialog.open) customDialog.close(); } catch (_) {}
      bridge.log('cloud modal promotion error: ' + error);
    }
  }
  function restoreNativeCloudDialog(appId) {
    const record = bridge.cloudNativeDialogs[String(appId)];
    if (!record) return;
    if (!record.dialog.isConnected) {
      const before = record.nextSibling && record.nextSibling.parentNode === record.parent
        ? record.nextSibling
        : null;
      record.parent.insertBefore(record.dialog, before);
    }
    record.dialog.style.display = record.display;
    record.dialog.style.visibility = record.visibility;
    record.dialog.style.pointerEvents = record.pointerEvents;
    record.dialog.inert = record.inert;
  }
  function detachNativeCloudDialog(appId) {
    const record = bridge.cloudNativeDialogs[String(appId)];
    if (!record || !record.dialog.isConnected) return;
    try { if (record.dialog.open) record.dialog.close(); } catch (_) {}
    record.dialog.remove();
  }
  bridge.showCloudConflict = function(dialog) {
    if (!dialog || !Number.isFinite(Number(dialog.app_id))) return false;
    const appId = Number(dialog.app_id);
    const current = bridge.cloudDialogs[String(appId)];
    if (current && current.cancel_token !== dialog.cancel_token) {
      restoreNativeCloudDialog(appId);
      delete bridge.cloudNativeDialogs[String(appId)];
      closeCloudConflict(appId);
      delete bridge.cloudPromoted[String(appId)];
    }
    bridge.cloudDialogs[String(appId)] = dialog;
    ensureCloudObserver();
    bridge.tryReady();
    return renderCloudConflict(appId);
  };
  bridge.ackCloudConflict = function(ack) {
    if (!ack || !ack.token) return false;
    const waiting = bridge.cloudWaiting[ack.token];
    if (!waiting) return false;
    delete bridge.cloudWaiting[ack.token];
    if (!ack.accepted) {
      setCloudBusy(waiting.root, false, ack.message || 'The selected version could not be saved.');
      return false;
    }
    const finish = function() {
      closeCloudConflict(waiting.appId);
      delete bridge.cloudDialogs[String(waiting.appId)];
      delete bridge.cloudPromoted[String(waiting.appId)];
      stopCloudObserverIfIdle();
    };
    const fail = function(message) {
      setCloudBusy(waiting.root, false, message);
    };
    if (ack.cancel_launch) finishGameAction(ack.app_id, true, finish, fail);
    else if (ack.resume_launch) finishGameAction(ack.app_id, false, finish, fail);
    else finish();
    return true;
  };
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
      bridge.modal = bridge.modal || findModal();
      bridge.windowStore = bridge.windowStore || findWindowStore();
      if (bridge.jsx && bridge.modal && bridge.windowStore) {
        Object.keys(bridge.cloudDialogs).forEach(function(appId) {
          if (!bridge.cloudHandles[appId] && !bridge.cloudOpening[appId]) {
            renderCloudConflict(Number(appId));
          }
        });
      }
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
