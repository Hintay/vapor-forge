// @ts-check
(function() {
  try {
    const existing = window.VaporForgeUIBridge;
    if (existing) {
      window.VaporForgeToastBridge = existing;
      existing.tryReady && existing.tryReady();
      return;
    }

    const bridge = window.VaporForgeUIBridge = {
      req: null,
      features: {},
      resources: {},
      targetSkipLogged: false,
      log: function(message) {
        try { console.log('[VaporForgeUI] ' + message); } catch (_) {}
      }
    };
    window.VaporForgeToastBridge = bridge;

    function isTargetSteamUiContext() {
      try {
        const href = String(window.location && window.location.href || '');
        const title = String(document && document.title || '');
        const sharedNames = {
          SharedJSContext: true,
          'Steam Shared Context presented by Valve\u2122': true,
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

    function visitExport(exp, id, mod, callback) {
      if (!exp) return false;
      if (callback(exp, id, mod)) return true;
      if (exp.default && callback(exp.default, id, mod, exp, 'default')) return true;
      if (typeof exp === 'object' || typeof exp === 'function') {
        for (const key of Object.keys(exp)) {
          try {
            if (callback(exp[key], id, mod, exp, key)) return true;
          } catch (_) {}
        }
      }
      return false;
    }

    function eachExport(callback, shouldLoadFactory) {
      const req = bridge.req;
      const cache = req && (req.c || req.cache);
      const seen = {};
      if (cache) {
        for (const id in cache) {
          seen[id] = true;
          const mod = cache[id];
          const exp = mod && mod.exports;
          if (visitExport(exp, id, mod, callback)) return true;
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
          if (visitExport(exp, id, mod, callback)) return true;
          if (mod && mod.exports !== exp && visitExport(mod.exports, id, mod, callback)) {
            return true;
          }
        } catch (error) {
          bridge.log('module load skipped id=' + id + ' error=' + error);
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

    function isRendererFactory(text) {
      return text.indexOf('controller:"notification",method:') !== -1;
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
          if (text.indexOf(local + '.jsx') === -1 && text.indexOf(local + '.jsxs') === -1) {
            continue;
          }
          try {
            const jsx = pickJsxRuntime(req(moduleId));
            if (jsx) return jsx;
          } catch (_) {}
        }
      }
      return null;
    }

    function findJsx() {
      var found = null;
      eachExport(function(exp) {
        found = pickJsxRuntime(exp);
        return !!found;
      });
      return found || findJsxFromRendererFactory();
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
      }, function(text) {
        return hasAll(text, ['RequestModalMeasure', 'ShowLegacyPopupModal', 'bHideMainWindowForPopouts']);
      });
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
      }, function(text) {
        return hasAll(text, ['ActiveWindowInstance', 'SteamUIWindows', 'SetRunningApp']);
      });
      return found;
    }

    bridge.isTargetSteamUiContext = isTargetSteamUiContext;
    bridge.hasAll = hasAll;
    bridge.eachExport = eachExport;
    bridge.isRendererFactory = isRendererFactory;
    bridge.findJsx = findJsx;
    bridge.findModal = findModal;
    bridge.findWindowStore = findWindowStore;

    bridge.registerFeatureOnce = function(name, install) {
      const current = bridge.features[name];
      if (current) {
        current.api.tryReady && current.api.tryReady();
        return current.api;
      }
      const api = install(bridge) || {};
      bridge.features[name] = { api: api };
      api.tryReady && api.tryReady();
      return api;
    };

    bridge.tryReady = function() {
      if (!isTargetSteamUiContext()) {
        if (!bridge.targetSkipLogged) {
          bridge.targetSkipLogged = true;
          bridge.log('skipping non-main SteamUI context');
        }
        return false;
      }
      if (!bridge.req && window.__webpack_require__) bridge.req = window.__webpack_require__;
      for (const name of Object.keys(bridge.features)) {
        const feature = bridge.features[name].api;
        try { feature.tryReady && feature.tryReady(); }
        catch (error) { bridge.log(name + ' readiness error: ' + error); }
      }
      return true;
    };

    function captureReq(req) {
      if (!req || bridge.req === req) return;
      bridge.req = req;
      try { bridge.log('webpack require captured keys=' + Object.keys(req).join(',')); }
      catch (_) { bridge.log('webpack require captured'); }
      bridge.tryReady();
    }

    function wrapChunkArray(array) {
      if (!array || array.__vaporForgeBridgeWrapped) return;
      const oldPush = array.push;
      array.push = function(chunk) {
        try {
          if (Array.isArray(chunk) && typeof chunk[2] === 'function') {
            const runtime = chunk[2];
            chunk[2] = function(req) {
              captureReq(req);
              return runtime.apply(this, arguments);
            };
          }
        } catch (_) {}
        const result = oldPush.apply(this, arguments);
        bridge.tryReady();
        return result;
      };
      array.__vaporForgeBridgeWrapped = true;
    }

    let chunkArray = window.webpackChunksteamui || [];
    try {
      Object.defineProperty(window, 'webpackChunksteamui', {
        configurable: true,
        get: function() { return chunkArray; },
        set: function(value) { chunkArray = value; wrapChunkArray(chunkArray); }
      });
    } catch (_) {}
    window.webpackChunksteamui = chunkArray;
    wrapChunkArray(chunkArray);
    try {
      chunkArray.push([[Date.now() & 0xfffffff], {}, function(req) { captureReq(req); }]);
    } catch (_) {}
    bridge.tryReady();
  } catch (error) {
    try { console.log('[VaporForgeUI] bootstrap error: ' + error); } catch (_) {}
  }
})();
