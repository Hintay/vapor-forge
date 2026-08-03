// @ts-check
(function() {
  try {
    const bridge = window.VaporForgeUIBridge;
    if (!bridge || typeof bridge.registerFeature !== 'function') return;

    bridge.registerFeature('toast', 1, function(bridge) {
      const state = {
        store: null,
        css: null,
        jsx: null,
        focusable: null,
        nextId: 10000,
        pending: [],
        seen: {},
        renderPatched: false,
        exportPatched: false,
        jsxPatched: false
      };

      function findStore() {
        var found = null;
        bridge.eachExport(function(exp) {
          if (exp && typeof exp.ProcessNotification === 'function') {
            found = exp;
            return true;
          }
          return false;
        }, function(text) {
          return bridge.hasAll(text, ['ProcessNotification', 'm_nNextTestNotificationID']);
        });
        return found;
      }

      function findCss() {
        var found = null;
        bridge.eachExport(function(exp) {
          if (exp && exp.StandardTemplateContainer && exp.StandardTemplate && exp.Title && exp.Content) {
            found = exp;
            return true;
          }
          return false;
        }, function(text) {
          return bridge.hasAll(text, ['StandardTemplateContainer', 'StandardTemplate', 'Title', 'Content']);
        });
        return found;
      }

      function findFocusable() {
        var found = null;
        bridge.eachExport(function(exp) {
          try {
            if (exp && exp.render && typeof exp.render === 'function' &&
                String(exp.render).indexOf('flow-children') !== -1) {
              found = exp;
              return true;
            }
          } catch (_) {}
          return false;
        });
        return found;
      }

      function allocateNotificationId(toast) {
        var id = state.nextId++;
        var toastId = Number(toast && toast.id);
        if (Number.isFinite(toastId) && toastId > 0) id = 9999 + Math.floor(toastId);
        var storeNext = Number(state.store && state.store.m_nNextTestNotificationID);
        if (Number.isFinite(storeNext)) {
          id = Math.max(id, storeNext);
          state.store.m_nNextTestNotificationID = id + 1;
        }
        state.nextId = Math.max(state.nextId, id + 1);
        return id;
      }

      function isValveToastRenderer(type) {
        try {
          return typeof type === 'function' &&
            String(type).indexOf('controller:"notification",method:') !== -1;
        } catch (_) {
          return false;
        }
      }

      function renderFallback(jsx, title, body) {
        return jsx.jsx('div', {
          className: 'VaporForgeToastFallback',
          children: (title || 'Vapor Forge') + ': ' + (body || '')
        });
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
        return { borderLeft: '3px solid ' + toastAccent(kind), boxSizing: 'border-box' };
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
            background: banner ? 'transparent' :
              'linear-gradient(135deg,' + toastAccent(kind) + ',#2a475e)',
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
          return jsx.jsxs('div', {
            className: (css.ShortTemplate || css.StandardTemplate || '') +
              ' VaporForgePopupToast VaporForgeToast-' + kind + ' VaporForgeToastStyle-' + style,
            style: popupRootStyle(kind, style),
            children: [
              logo,
              jsx.jsxs('div', { className: css.Content || '', children: [
                jsx.jsx('div', {
                  className: css.Title || '',
                  style: toastTextStyle(kind, style, false),
                  children: title
                }),
                body ? jsx.jsx('div', {
                  className: css.Body || css.StandardNotificationDescription || '',
                  style: toastTextStyle(kind, style, true),
                  children: body
                }) : null
              ]})
            ]
          });
        } catch (error) {
          bridge.log('popup render error: ' + error);
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
            ? jsx.jsx('img', {
              className: css.StandardLogoDimensions || css.Icon || '',
              src: icon,
              draggable: false
            })
            : renderDefaultLogo(jsx, css.StandardLogoDimensions || css.Icon || '', kind, style);
          var timestamp = notification && notification.rtCreated
            ? jsx.jsx('div', {
              className: css.Timestamp || '',
              style: toastTextStyle(kind, style, true),
              children: new Date(notification.rtCreated).toLocaleTimeString([], {
                hour: '2-digit', minute: '2-digit'
              })
            })
            : null;
          var content = jsx.jsx('div', {
            className: (css.StandardTemplateContainer || '') +
              ' VaporForgeQAMToast VaporForgeToast-' + kind + ' VaporForgeToastStyle-' + style,
            style: qamRootStyle(kind, style),
            children: jsx.jsxs('div', { className: css.StandardTemplate || '', children: [
              logo,
              jsx.jsxs('div', { className: css.Content || '', children: [
                jsx.jsxs('div', { className: css.Header || '', children: [
                  jsx.jsx('div', {
                    className: css.Title || '',
                    style: toastTextStyle(kind, style, false),
                    children: title
                  }),
                  timestamp
                ]}),
                body ? jsx.jsx('div', {
                  className: css.StandardNotificationDescription || '',
                  style: toastTextStyle(kind, style, true),
                  children: body
                }) : null
              ]})
            ]})
          });
          var Focusable = state.focusable;
          if (Focusable) return jsx.jsx(Focusable, { onActivate: function() {}, children: content });
          return content;
        } catch (error) {
          bridge.log('qam render error: ' + error);
          return renderFallback(jsx, data.title, data.body);
        }
      }

      function renderVaporForgeToast(props) {
        var css = state.css || {};
        var jsx = state.jsx;
        var notifications = props && props.group && props.group.notifications || [];
        var location = props && props.location;
        return notifications.filter(isVaporForgeNotification).map(function(notification) {
          var data = notification && notification.data || {};
          if (location === 1) return renderPopupToast(css, jsx, data);
          return renderQamToast(css, jsx, data, notification);
        });
      }

      function isVaporForgeNotification(notification) {
        return !!(notification &&
          (notification.vaporForge || (notification.data && notification.data.vaporForge)));
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
        if (!jsx || state.jsxPatched) return !!jsx;
        const originalJsx = jsx.jsx;
        const originalJsxs = jsx.jsxs;
        if (typeof originalJsx !== 'function' || typeof originalJsxs !== 'function') return false;
        function wrap(create) {
          return function(type, props, key) {
            if (type !== renderVaporForgeToast && typeof type === 'function' &&
                isVaporForgeProps(props)) {
              return create.call(this, renderVaporForgeToast, props, key);
            }
            return create.apply(this, arguments);
          };
        }
        try {
          jsx.jsx = wrap(originalJsx);
          jsx.jsxs = wrap(originalJsxs);
          state.jsxPatched = true;
          state.renderPatched = true;
          bridge.log('JSX notification bridge ready');
          return true;
        } catch (error) {
          bridge.log('JSX patch error: ' + error);
          return false;
        }
      }

      function patchJsxRenderer() {
        if (state.renderPatched) return true;
        const jsx = state.jsx || bridge.findJsx();
        const css = state.css || findCss();
        if (!jsx || !css) return false;
        state.jsx = jsx;
        state.css = css;
        const jsxPatched = patchJsxRuntime(jsx);
        state.focusable = state.focusable || findFocusable();
        if (jsxPatched) return true;
        var patched = false;
        bridge.eachExport(function(exp, id, mod, parent, key) {
          if (!isValveToastRenderer(exp) || exp.__vaporForgePatched) return false;
          const original = exp;
          const wrapped = function(props) {
            try {
              const first = props && props.group && props.group.notifications &&
                props.group.notifications[0];
              if (first && first.vaporForge) return renderVaporForgeToast(props);
            } catch (error) {
              bridge.log('renderer patch error: ' + error);
            }
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
        }, bridge.isRendererFactory);
        if (patched) {
          state.exportPatched = true;
          state.renderPatched = true;
          bridge.log('Valve toast renderer export bridge ready');
          return true;
        }
        return false;
      }

      function flush() {
        if (!bridge.isTargetSteamUiContext()) return false;
        if (!state.store || !state.renderPatched) return false;
        while (state.pending.length) {
          var toast = state.pending.shift();
          if (toast.id != null && state.seen['flushed:' + toast.id]) continue;
          if (toast.id != null) state.seen['flushed:' + toast.id] = true;
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
            tray.unshift({ eType: notification.eType, notifications: [notification] });
          }
          state.store.ProcessNotification({
            showToast: true,
            sound: toast.sound == null ? 6 : toast.sound,
            playSound: toast.playSound !== false,
            eFeature: 0,
            toastDurationMS: toastData.nToastDurationMS,
            bCritical: !!toast.critical,
            fnTray: fnTray
          }, toastData, 0);
        }
        return true;
      }

      function showToast(toast) {
        toast = toast || {};
        if (toast.id != null) {
          var key = 'queued:' + toast.id;
          if (state.seen[key]) return true;
          state.seen[key] = true;
        }
        state.pending.push(toast);
        tryReady();
        return state.pending.length === 0;
      }

      function tryReady() {
        if (!bridge.req) return false;
        state.store = state.store || findStore();
        patchJsxRenderer();
        if (state.store && state.renderPatched) flush();
        return !!(state.store && state.renderPatched);
      }

      bridge.showToast = showToast;
      bridge.flush = flush;
      return { tryReady: tryReady, flush: flush, showToast: showToast };
    });
  } catch (error) {
    try { console.log('[VaporForgeUI] toast install error: ' + error); } catch (_) {}
  }
})();
