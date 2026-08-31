// @ts-check
(function() {
  try {
    const bridge = window.VaporForgeUIBridge;
    if (!bridge || typeof bridge.registerFeatureOnce !== 'function') return;

    bridge.registerFeatureOnce('toast', function(bridge) {
      const state = {
        store: null,
        css: null,
        jsx: null,
        focusable: null,
        navigation: null,
        language: 'english',
        languageReady: false,
        languagePromise: null,
        nextId: 10000,
        pending: [],
        seen: {},
        renderPatched: false,
        renderer: null,
        rendererHook: null,
        react: null,
        reactDom: null,
        reactHooks: null,
        steamApp: null,
        steamServicesReady: false,
        steamServicesWaitStarted: false,
        steamReadinessQueued: false,
        steamStageOneObservable: null,
        steamStageOneDisposer: null,
        steamMainWindowObservable: null,
        steamMainWindowDisposer: null,
        steamBrowserWindowObservable: null,
        steamBrowserWindowDisposer: null,
        steamObservedWindowInstance: null,
        preLoginDocument: null,
        preLoginDomListener: null,
        preLoginNativeEntries: [],
        nativeToastSurfaceClass: null,
        popupBase: null,
        browserTypes: null,
        windowCreationFlags: null,
        deckyLoaderHooked: false,
        deckyLoader: null,
        deckyRouteEventBus: null,
        deckyRouteEventListener: null,
        pendingDeckyRoute: null
      };

      const supportedLanguages = {
        english: true,
        schinese: true,
        tchinese: true,
        japanese: true
      };

      function finishLanguage(language) {
        if (language === 'sc_schinese') language = 'schinese';
        if (!supportedLanguages[language]) language = 'english';
        state.language = language;
        state.languageReady = true;
        bridge.tryReady();
      }

      function ensureLanguage() {
        if (state.languageReady || state.languagePromise) return;
        try {
          var settings = window.SteamClient && window.SteamClient.Settings;
          if (!settings || typeof settings.GetCurrentLanguage !== 'function') {
            finishLanguage('english');
            return;
          }
          state.languagePromise = Promise.resolve(settings.GetCurrentLanguage()).then(function(language) {
            finishLanguage(String(language || 'english').toLowerCase());
          }).catch(function(error) {
            bridge.log('toast language error: ' + error);
            finishLanguage('english');
          });
        } catch (error) {
          bridge.log('toast language error: ' + error);
          finishLanguage('english');
        }
      }

      function pendingNeedsLanguage() {
        return state.pending.some(function(toast) { return !!toast.messageKey; });
      }

      function isSteamAppBeforeLoginReady() {
        try {
          var app = window.App;
          if (!app || state.steamApp !== app) return false;
          if (typeof app.BFinishedInitBeforeLogin === 'function') {
            return !!app.BFinishedInitBeforeLogin();
          } else if (typeof app.BFinishedInitStageOne === 'function') {
            return !!app.BFinishedInitStageOne();
          }
          return app.m_bFinishedStage1 === true;
        } catch (_) {
          return false;
        }
      }

      function isSteamServicesReady() {
        try {
          var app = window.App;
          if (!app || state.steamApp !== app) return false;
          if (typeof app.GetServicesInitialized === 'function') {
            return !!app.GetServicesInitialized();
          }
          return state.steamServicesReady;
        } catch (_) {
          return false;
        }
      }

      function queueSteamReadiness() {
        if (state.steamReadinessQueued) return;
        state.steamReadinessQueued = true;
        var run = function() {
          state.steamReadinessQueued = false;
          tryReady();
          runPendingDeckyRoute();
        };
        if (typeof window.requestAnimationFrame === 'function') {
          window.requestAnimationFrame(run);
        } else {
          Promise.resolve().then(run);
        }
      }

      function clearSteamStageOneSubscription() {
        var dispose = state.steamStageOneDisposer;
        state.steamStageOneObservable = null;
        state.steamStageOneDisposer = null;
        try {
          if (typeof dispose === 'function') dispose();
        } catch (_) {}
      }

      function clearSteamBrowserWindowSubscription() {
        var dispose = state.steamBrowserWindowDisposer;
        state.steamBrowserWindowObservable = null;
        state.steamBrowserWindowDisposer = null;
        state.steamObservedWindowInstance = null;
        try {
          if (typeof dispose === 'function') dispose();
        } catch (_) {}
      }

      function clearSteamWindowSubscriptions() {
        var dispose = state.steamMainWindowDisposer;
        state.steamMainWindowObservable = null;
        state.steamMainWindowDisposer = null;
        clearSteamBrowserWindowSubscription();
        try {
          if (typeof dispose === 'function') dispose();
        } catch (_) {}
      }

      function findMobxObservable(target, property) {
        if (!target) return null;
        try {
          for (const symbol of Object.getOwnPropertySymbols(target)) {
            var administration = target[symbol];
            var values = administration && administration.values_;
            if (!values || typeof values.get !== 'function') continue;
            var observable = values.get(property);
            if (observable && typeof observable.observe_ === 'function') return observable;
          }
        } catch (_) {}
        return null;
      }

      function observeSteamBeforeLoginReady() {
        var app = window.App;
        if (!app || state.steamApp !== app) return false;
        if (isSteamAppBeforeLoginReady()) {
          clearSteamStageOneSubscription();
          return true;
        }
        var observable = findMobxObservable(app, 'm_bFinishedStage1');
        if (!observable) return false;
        if (state.steamStageOneObservable === observable &&
            state.steamStageOneDisposer) return true;
        clearSteamStageOneSubscription();
        try {
          var dispose = observable.observe_(function(change) {
            if (!(change && change.newValue === true) && !isSteamAppBeforeLoginReady()) return;
            clearSteamStageOneSubscription();
            bridge.log('Steam before-login initialization ready');
            queueSteamReadiness();
          }, false);
          if (typeof dispose !== 'function') return false;
          state.steamStageOneObservable = observable;
          state.steamStageOneDisposer = dispose;
          return true;
        } catch (error) {
          bridge.log('Steam App initialization subscription error: ' + error);
          return false;
        }
      }

      function markSteamServicesReady() {
        state.steamServicesReady = true;
        state.steamServicesWaitStarted = false;
        clearPreLoginNativeToasts();
        queueSteamReadiness();
      }

      function waitForSteamServices(app) {
        if (state.steamServicesWaitStarted ||
            typeof app.WaitForServicesInitialized !== 'function') return false;
        state.steamServicesWaitStarted = true;
        try {
          Promise.resolve(app.WaitForServicesInitialized()).then(function() {
            markSteamServicesReady();
          }, function(error) {
            state.steamServicesWaitStarted = false;
            bridge.log('Steam App readiness error: ' + error);
          });
          return true;
        } catch (error) {
          state.steamServicesWaitStarted = false;
          bridge.log('Steam App readiness error: ' + error);
          return false;
        }
      }

      function ensureSteamServicesReady() {
        var app = window.App;
        if (!app || state.steamApp !== app) return false;
        try {
          if (typeof app.GetServicesInitialized === 'function' &&
              app.GetServicesInitialized()) {
            state.steamServicesReady = true;
            return true;
          }
        } catch (_) {}
        waitForSteamServices(app);
        return false;
      }

      function trackSteamApp() {
        var app = window.App;
        if (!app || state.steamApp === app) return;
        clearSteamStageOneSubscription();
        clearSteamWindowSubscriptions();
        clearPreLoginNativeToasts();
        state.steamApp = app;
        state.steamServicesReady = false;
        state.steamServicesWaitStarted = false;
      }

      function localizeToast(toast) {
        var key = String(toast && toast.messageKey || '');
        if (!key) return toast;
        var locales = bridge.resources.toastLocales || {};
        var english = locales.english || {};
        var messages = locales[state.language] || english;
        var translated = messages[key] || english[key];
        if (!translated) return toast;
        return Object.assign({}, toast, {
          title: translated.title || toast.title,
          body: translated.body || toast.body
        });
      }

      function findStore() {
        var found = null;
        bridge.eachExport(function(exp) {
          if (exp && typeof exp.ProcessNotification === 'function' &&
              typeof exp.GetNotificationsInTray === 'function' &&
              typeof exp.RemoveGroupFromTray === 'function') {
            found = exp;
            return true;
          }
          return false;
        }, function(text) {
          return bridge.hasAll(text, [
            'ProcessNotification',
            'm_nNextTestNotificationID',
            'GetNotificationsInTray',
            'RemoveGroupFromTray'
          ]);
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

      function isGamepadUiReady() {
        try {
          return String(window.location && window.location.href || '').indexOf('/routes/') !== -1;
        } catch (_) {
          return false;
        }
      }

      function findFocusable(allowFactoryLoad) {
        var found = null;
        bridge.eachExport(function(exp) {
          try {
            var render = typeof exp === 'function'
              ? exp
              : exp && typeof exp.render === 'function' ? exp.render : null;
            if (render && bridge.hasAll(String(render), [
              'flow-children',
              'focusClassName',
              'focusWithinClassName',
              'onOKButton'
            ])) {
              found = exp;
              return true;
            }
          } catch (_) {}
          return false;
        }, allowFactoryLoad ? function(text) {
          return bridge.hasAll(text, [
            'flow-children',
            'focusClassName',
            'focusWithinClassName',
            'onOKButton'
          ]);
        } : null);
        return found;
      }

      function dismissTrayNotification(notification) {
        var store = state.store;
        if (!store || !notification ||
            typeof store.GetNotificationsInTray !== 'function' ||
            typeof store.RemoveGroupFromTray !== 'function') return false;
        try {
          var result = store.GetNotificationsInTray();
          var tray = Array.isArray(result) ? result[0] : null;
          if (!Array.isArray(tray)) return false;
          var id = notification.notificationID;
          var group = tray.find(function(entry) {
            var notifications = entry && entry.notifications || [];
            return notifications.some(function(item) {
              return item && item.notificationID === id;
            });
          });
          if (!group) return false;
          store.RemoveGroupFromTray(group);
          return true;
        } catch (error) {
          bridge.log('notification dismiss error: ' + error);
          return false;
        }
      }

      function clearDeckyRouteEvents() {
        var bus = state.deckyRouteEventBus;
        var listener = state.deckyRouteEventListener;
        state.deckyRouteEventBus = null;
        state.deckyRouteEventListener = null;
        try {
          if (bus && listener && typeof bus.removeEventListener === 'function') {
            bus.removeEventListener('update', listener);
          }
        } catch (_) {}
      }

      function deckyRouterState(loader) {
        try {
          var hook = loader && loader.routerHook;
          var routerState = hook && hook.routerState;
          return routerState && typeof routerState.publicState === 'function'
            ? routerState
            : null;
        } catch (_) {
          return null;
        }
      }

      function attachDeckyLoader(loader) {
        if (state.deckyLoader === loader) return;
        clearDeckyRouteEvents();
        state.deckyLoader = loader || null;
        var routerState = deckyRouterState(loader);
        var bus = routerState && routerState.eventBus;
        if (bus && typeof bus.addEventListener === 'function') {
          var listener = function() { runPendingDeckyRoute(); };
          try {
            bus.addEventListener('update', listener);
            state.deckyRouteEventBus = bus;
            state.deckyRouteEventListener = listener;
          } catch (_) {}
        }
        runPendingDeckyRoute();
      }

      function hookDeckyLoader() {
        if (state.deckyLoaderHooked) {
          attachDeckyLoader(window.DeckyPluginLoader);
          return;
        }
        var descriptor;
        try { descriptor = Object.getOwnPropertyDescriptor(window, 'DeckyPluginLoader'); }
        catch (_) {}
        if (descriptor && descriptor.configurable === false) {
          state.deckyLoaderHooked = true;
          attachDeckyLoader(window.DeckyPluginLoader);
          return;
        }
        var stored = descriptor && !descriptor.get ? descriptor.value : window.DeckyPluginLoader;
        try {
          Object.defineProperty(window, 'DeckyPluginLoader', {
            configurable: true,
            enumerable: !descriptor || descriptor.enumerable !== false,
            get: function() {
              return descriptor && descriptor.get ? descriptor.get.call(window) : stored;
            },
            set: function(value) {
              if (descriptor && descriptor.set) descriptor.set.call(window, value);
              else stored = value;
              attachDeckyLoader(
                descriptor && descriptor.get ? descriptor.get.call(window) : stored
              );
            }
          });
          state.deckyLoaderHooked = true;
        } catch (error) {
          bridge.log('Decky loader hook error: ' + error);
        }
        attachDeckyLoader(window.DeckyPluginLoader);
      }

      function isDeckyRouteRegistered(target) {
        var routerState = deckyRouterState(state.deckyLoader || window.DeckyPluginLoader);
        if (!routerState) return false;
        try {
          var publicState = routerState.publicState();
          var routes = publicState && publicState.routes;
          if (!routes || typeof routes.keys !== 'function') return false;
          var path = target.split(/[?#]/, 1)[0];
          for (const route of routes.keys()) {
            if (path === route || path.indexOf(String(route) + '/') === 0) return true;
          }
        } catch (_) {}
        return false;
      }

      function executeDeckyRoute(target) {
        if ((!isSteamServicesReady() && !ensureSteamServicesReady()) ||
            !isDeckyRouteRegistered(target)) return false;
        var navigation = state.navigation || bridge.findWindowStore();
        if (!navigation || typeof navigation.Navigate !== 'function') return false;
        try {
          navigation.Navigate(target);
          if (typeof navigation.CloseSideMenus === 'function') {
            navigation.CloseSideMenus();
          }
          state.navigation = navigation;
          return true;
        } catch (error) {
          bridge.log('Decky route action error: ' + error);
          return false;
        }
      }

      function runPendingDeckyRoute() {
        var pending = state.pendingDeckyRoute;
        if (!pending || !executeDeckyRoute(pending.target)) return false;
        state.pendingDeckyRoute = null;
        dismissTrayNotification(pending.notification);
        return true;
      }

      function runToastAction(data, notification) {
        var action = data && data.action;
        if (!action || action.kind === 'dismiss') return 'complete';
        var target = String(action.target || '');
        if (action.kind === 'decky-route') {
          if (target.indexOf('/decky/') !== 0) return 'rejected';
          hookDeckyLoader();
          if (executeDeckyRoute(target)) return 'complete';
          state.pendingDeckyRoute = { target: target, notification: notification };
          return 'pending';
        }
        if (action.kind !== 'steam-url') return 'rejected';
        if (target.indexOf('steam://') !== 0) return 'rejected';
        try {
          var client = window.SteamClient;
          if (!client || !client.URL || typeof client.URL.ExecuteSteamURL !== 'function') {
            return 'rejected';
          }
          client.URL.ExecuteSteamURL(target);
          return 'complete';
        } catch (error) {
          bridge.log('notification action error: ' + error);
          return 'rejected';
        }
      }

      function activateQamToast(data, notification) {
        var result = runToastAction(data, notification);
        if (result === 'rejected') {
          bridge.log('notification action rejected');
          return false;
        }
        if (result === 'pending') return false;
        dismissTrayNotification(notification);
        var navigation = state.navigation;
        if (navigation && typeof navigation.CloseSideMenus === 'function') {
          navigation.CloseSideMenus();
        }
        return true;
      }

      function clearPreLoginDomListener() {
        var listener = state.preLoginDomListener;
        var document = state.preLoginDocument;
        state.preLoginDomListener = null;
        try {
          if (listener) document.removeEventListener('DOMContentLoaded', listener);
        } catch (_) {}
      }

      function steamWindowStore(navigation) {
        try {
          return navigation && (navigation.WindowStore || navigation.m_WindowStore) || null;
        } catch (_) {
          return null;
        }
      }

      function steamMainWindowInstance(navigation) {
        try {
          var active = navigation && navigation.ActiveWindowInstance;
          if (active) return active;
          var store = steamWindowStore(navigation);
          return store && (store.MainWindowInstance || store.GamepadUIMainWindowInstance) || null;
        } catch (_) {
          return null;
        }
      }

      function steamWindowDocument(instance) {
        try {
          var browserWindow = instance && (instance.BrowserWindow || instance.m_BrowserWindow);
          return browserWindow && browserWindow.document || null;
        } catch (_) {
          return null;
        }
      }

      function steamBrowserWindow(instance) {
        try {
          return instance && (instance.BrowserWindow || instance.m_BrowserWindow) || null;
        } catch (_) {
          return null;
        }
      }

      function activeSteamWindow() {
        var navigation = state.navigation || bridge.findWindowStore();
        var instance = steamMainWindowInstance(navigation);
        var browserWindow = steamBrowserWindow(instance);
        if (!browserWindow) return null;
        state.navigation = navigation;
        return { instance: instance, browserWindow: browserWindow };
      }

      function activeSteamDocument() {
        try {
          var active = activeSteamWindow();
          var document = active && active.browserWindow.document;
          if (!document) return null;
          return document;
        } catch (_) {
          return null;
        }
      }

      function observeSteamBrowserWindow(instance) {
        if (!instance) return false;
        if (steamWindowDocument(instance)) {
          clearSteamWindowSubscriptions();
          queueSteamReadiness();
          return true;
        }
        var observable = findMobxObservable(instance, 'm_BrowserWindow');
        if (!observable) return false;
        if (state.steamObservedWindowInstance === instance &&
            state.steamBrowserWindowObservable === observable &&
            state.steamBrowserWindowDisposer) return true;
        clearSteamBrowserWindowSubscription();
        try {
          var dispose = observable.observe_(function(change) {
            if (!(change && change.newValue) && !steamWindowDocument(instance)) return;
            clearSteamWindowSubscriptions();
            bridge.log('Steam main browser window ready');
            queueSteamReadiness();
          }, false);
          if (typeof dispose !== 'function') return false;
          state.steamObservedWindowInstance = instance;
          state.steamBrowserWindowObservable = observable;
          state.steamBrowserWindowDisposer = dispose;
          return true;
        } catch (error) {
          bridge.log('Steam browser window subscription error: ' + error);
          return false;
        }
      }

      function observeSteamWindowReady() {
        if (activeSteamDocument()) {
          clearSteamWindowSubscriptions();
          return true;
        }
        var navigation = state.navigation || bridge.findWindowStore();
        var store = steamWindowStore(navigation);
        if (!navigation || !store) return false;
        state.navigation = navigation;
        var instance = steamMainWindowInstance(navigation);
        observeSteamBrowserWindow(instance);

        var observable = findMobxObservable(store, 'MainWindowInstance');
        if (!observable) return !!state.steamBrowserWindowDisposer;
        if (state.steamMainWindowObservable === observable &&
            state.steamMainWindowDisposer) return true;
        var previousDispose = state.steamMainWindowDisposer;
        state.steamMainWindowObservable = null;
        state.steamMainWindowDisposer = null;
        try {
          if (typeof previousDispose === 'function') previousDispose();
        } catch (_) {}
        try {
          var dispose = observable.observe_(function(change) {
            var next = change && change.newValue || steamMainWindowInstance(navigation);
            if (!next) return;
            if (steamWindowDocument(next)) {
              clearSteamWindowSubscriptions();
              bridge.log('Steam main window ready');
              queueSteamReadiness();
              return;
            }
            observeSteamBrowserWindow(next);
          }, false);
          if (typeof dispose !== 'function') return !!state.steamBrowserWindowDisposer;
          state.steamMainWindowObservable = observable;
          state.steamMainWindowDisposer = dispose;
          return true;
        } catch (error) {
          bridge.log('Steam main window subscription error: ' + error);
          return !!state.steamBrowserWindowDisposer;
        }
      }

      function ensurePreLoginSurface() {
        var document = activeSteamDocument();
        if (!document) {
          observeSteamWindowReady();
          return false;
        }
        if (state.preLoginDocument !== document) {
          clearPreLoginDomListener();
          clearPreLoginNativeToasts();
          state.preLoginDocument = document;
        }
        if (document.body) {
          clearPreLoginDomListener();
          return true;
        }
        if (!state.preLoginDomListener) {
          var listener = function() {
            clearPreLoginDomListener();
            queueSteamReadiness();
          };
          state.preLoginDomListener = listener;
          try {
            document.addEventListener('DOMContentLoaded', listener, { once: true });
          } catch (_) {
            state.preLoginDomListener = null;
          }
        }
        return false;
      }

      function findNativePopupSupport() {
        bridge.eachExport(function(exp) {
          var prototype = exp && exp.prototype;
          if (!state.popupBase && typeof exp === 'function' && prototype &&
              Object.prototype.hasOwnProperty.call(prototype, 'Show') &&
              Object.prototype.hasOwnProperty.call(prototype, 'Close') &&
              Object.prototype.hasOwnProperty.call(prototype, 'RegisterChildBrowserView') &&
              typeof prototype.Show === 'function' &&
              typeof prototype.Close === 'function' &&
              typeof prototype.RegisterChildBrowserView === 'function') {
            state.popupBase = exp;
          }
          if (!state.browserTypes && exp && typeof exp === 'object' &&
              exp.EBrowserType_DirectHWND_Borderless === 4) {
            state.browserTypes = exp;
          }
          if (!state.windowCreationFlags && exp && typeof exp === 'object' &&
              exp.NotFocusable === 512 && exp.Composited === 256 &&
              exp.ApplyBrowserScaleToDimensions === 4096) {
            state.windowCreationFlags = exp;
          }
          return !!(state.popupBase && state.browserTypes && state.windowCreationFlags);
        }, function(text) {
          return bridge.hasAll(text, ['replace_existing_popup', 'RegisterChildBrowserView']) ||
            text.indexOf('EBrowserType_DirectHWND_Borderless') !== -1;
        });
        return !!(state.popupBase && state.browserTypes && state.windowCreationFlags);
      }

      function nativeNotificationFlags() {
        var flags = state.windowCreationFlags;
        return flags.Composited | flags.NotFocusable | flags.ApplyBrowserScaleToDimensions |
          flags.AlwaysOnTop | flags.NoTaskbarIcon | flags.TransparentParentWindow |
          flags.NoWindowShadow | flags.NoRoundedCorners | flags.OverrideRedirect |
          flags.ForceBrowserVisible;
      }

      function installNativeToastSurface(document) {
        if (!document || document.__vaporForgeNativeToastSurface) return;
        try {
          var style = document.createElement('style');
          style.textContent =
            'html,body,#popup_target,#browserview_target{margin:0;width:100%;height:100%;' +
              'overflow:hidden;background:transparent}';
          document.head.appendChild(style);
          document.__vaporForgeNativeToastSurface = true;
        } catch (_) {}
      }

      function nativeToastSurfaceClass(document) {
        if (state.nativeToastSurfaceClass) return state.nativeToastSurfaceClass;
        try {
          for (const sheet of document.styleSheets) {
            var rules;
            try { rules = sheet.cssRules; } catch (_) { continue; }
            if (!rules) continue;
            var stack = Array.from(rules);
            while (stack.length) {
              var rule = stack.pop();
              if (rule.cssRules) stack.push.apply(stack, Array.from(rule.cssRules));
              var style = rule.style;
              var selector = String(rule.selectorText || '');
              if (!style || !/^\.[A-Za-z0-9_-]+$/.test(selector)) continue;
              if (style.position === 'absolute' && style.display === 'flex' &&
                  style.alignItems === 'center' && style.top === '0px' &&
                  style.right === '0px' && style.bottom === '0px' && style.left === '20px') {
                state.nativeToastSurfaceClass = selector.slice(1);
                return state.nativeToastSurfaceClass;
              }
            }
          }
        } catch (_) {}
        return null;
      }

      function copySteamStyles(source, target) {
        try {
          source.head.querySelectorAll('link[rel="stylesheet"],style').forEach(function(node) {
            var copy = node.cloneNode(true);
            if (node.tagName === 'LINK' && node.href) copy.href = node.href;
            target.head.appendChild(copy);
          });
        } catch (error) {
          bridge.log('native notification style error: ' + error);
        }
      }

      function removePreLoginNativeEntry(entry) {
        if (!entry || entry.removed) return;
        entry.removed = true;
        var index = state.preLoginNativeEntries.indexOf(entry);
        if (index >= 0) state.preLoginNativeEntries.splice(index, 1);
        try {
          if (entry.mount) entry.mount.remove();
        } catch (_) {}
        entry.mount = null;
        entry.browserView = null;
        relayoutPreLoginNativeToasts();
      }

      function closePreLoginNativeEntry(entry) {
        if (!entry || entry.closing) return;
        entry.closing = true;
        Promise.resolve().then(function() {
          var popup = entry.popup;
          var browserView = entry.browserView;
          removePreLoginNativeEntry(entry);
          try {
            if (popup) popup.Close();
            if (browserView) SteamClient.BrowserView.Destroy(browserView);
          } catch (_) {}
        });
      }

      function closePreLoginNativeToast(notificationID) {
        var entry = state.preLoginNativeEntries.find(function(candidate) {
          return candidate.notificationID === notificationID;
        });
        closePreLoginNativeEntry(entry);
      }

      function clearPreLoginNativeToasts() {
        var entries = state.preLoginNativeEntries.slice();
        state.preLoginNativeEntries.length = 0;
        entries.forEach(function(entry) {
          if (entry.closing) return;
          entry.closing = true;
          var popup = entry.popup;
          var browserView = entry.browserView;
          removePreLoginNativeEntry(entry);
          try {
            if (popup) popup.Close();
            if (browserView) SteamClient.BrowserView.Destroy(browserView);
          } catch (_) {}
        });
      }

      function applyElementStyle(element, style) {
        if (!style) return;
        Object.keys(style).forEach(function(name) {
          element.style[name] = style[name];
        });
      }

      function popupLogoClass(css) {
        return css.ShortLogoDimensions || css.StandardLogoDimensions ||
          css.AppLogo || css.Icon || '';
      }

      function renderNativeToastDom(target, data, notification, entry) {
        var duration = Math.max(1000, Number(data.duration) || 5000);
        var document = target.ownerDocument;
        var kind = toastKind(data);
        var style = toastStyle(data, kind);
        var surfaceClass = nativeToastSurfaceClass(document);
        if (!surfaceClass) throw new Error('native notification surface style unavailable');
        var life = document.createElement('div');
        life.className = surfaceClass + ' VaporForgeNativeToastLife';
        life.style.setProperty('--toast-duration', duration + 'ms');
        var completedAnimations = 0;
        life.addEventListener('animationend', function(event) {
          if (event.target !== toast || ++completedAnimations < 2) return;
          closePreLoginNativeEntry(entry);
        });

        var toast = document.createElement('div');
        toast.className = (state.css.ShortTemplate || state.css.StandardTemplate || '') +
          ' VaporForgePopupToast VaporForgeToast-' + kind + ' VaporForgeToastStyle-' + style;
        applyElementStyle(toast, popupRootStyle(kind, style));
        toast.addEventListener('click', function() {
          if (activateQamToast(data, notification)) {
            closePreLoginNativeEntry(entry);
          }
        });

        var logoMode = toastLogoMode(data);
        var logo = null;
        if (logoMode === 'custom') {
          logo = document.createElement('img');
          logo.className = popupLogoClass(state.css);
          logo.src = data.icon;
          logo.draggable = false;
          applyElementStyle(logo, popupLogoStyle());
        } else if (logoMode === 'default') {
          logo = document.createElement('div');
          logo.className = popupLogoClass(state.css);
          logo.textContent = 'SR';
          applyElementStyle(logo, defaultLogoStyle(kind, style));
        }
        var content = document.createElement('div');
        content.className = state.css.Content || '';
        var title = document.createElement('div');
        title.className = state.css.Title || '';
        title.textContent = data.title || 'Vapor Forge';
        applyElementStyle(title, toastTextStyle(kind, style, false));
        content.appendChild(title);
        if (data.body) {
          var body = document.createElement('div');
          body.className = state.css.Body || state.css.StandardNotificationDescription || '';
          body.textContent = data.body;
          applyElementStyle(body, toastTextStyle(kind, style, true));
          content.appendChild(body);
        }
        if (logo) toast.appendChild(logo);
        toast.appendChild(content);
        life.appendChild(toast);
        target.appendChild(life);
        entry.mount = life;
        return life;
      }

      function relayoutPreLoginNativeToasts() {
        var count = state.preLoginNativeEntries.length;
        state.preLoginNativeEntries.forEach(function(entry, index) {
          var stackIndex = count - index - 1;
          var owner = entry.ownerWindow;
          if (!owner) return;
          var left = Math.max(0, Number(owner.innerWidth) - 320);
          var top = Math.max(0, Number(owner.innerHeight) - 80 - stackIndex * 88);
          try {
            if (entry.browserView) {
              entry.browserView.SetBounds(left, top, 320, 80);
              entry.browserView.SetVisible(true);
            } else if (entry.popup && entry.popup.window &&
                entry.popup.window.SteamClient.Window.MoveTo) {
              entry.popup.window.SteamClient.Window.MoveTo(
                Number(owner.screenX || 0) + left,
                Number(owner.screenY || 0) + top,
                false
              );
            }
          } catch (error) {
            bridge.log('native notification layout error: ' + error);
          }
        });
      }

      function renderGamepadPreLoginToast(data, notification, ownerWindow) {
        var name = 'vaporforge_notification_' + notification.notificationID;
        var parentPopupBrowserID = ownerWindow.SteamClient.Browser.GetBrowserID();
        var created = SteamClient.BrowserView.CreatePopup({
          parentPopupBrowserID: parentPopupBrowserID,
          strName: name
        });
        var popup = window.open(
          created.strCreateURL + '&createflags=' + state.windowCreationFlags.NotFocusable,
          name,
          'top=0,left=0,width=320,height=80,resizable=no,status=0,toolbar=0,' +
            'menubar=0,location=0'
        );
        if (!popup) {
          SteamClient.BrowserView.Destroy(created.browserView);
          return false;
        }
        popup.document.write(
          '<!DOCTYPE html><html><head><title></title></head><body style="overflow:hidden">' +
            '<div id="browserview_target"></div></body></html>'
        );
        popup.document.title = name;
        popup.document.close();
        copySteamStyles(ownerWindow.document, popup.document);
        installNativeToastSurface(popup.document);
        var mount = popup.document.getElementById('browserview_target');
        var entry = {
          notificationID: notification.notificationID,
          ownerWindow: ownerWindow,
          mount: null,
          browserView: created.browserView,
          popup: null,
          closing: false,
          removed: false
        };
        state.preLoginNativeEntries.push(entry);
        try {
          popup.addEventListener('unload', function() { removePreLoginNativeEntry(entry); }, {
            once: true
          });
          renderNativeToastDom(mount, data, notification, entry);
          relayoutPreLoginNativeToasts();
        } catch (error) {
          try { SteamClient.BrowserView.Destroy(created.browserView); } catch (_) {}
          removePreLoginNativeEntry(entry);
          throw error;
        }
        return true;
      }

      function renderDesktopPreLoginToast(data, notification, ownerWindow) {
        var entry = {
          notificationID: notification.notificationID,
          ownerWindow: ownerWindow,
          mount: null,
          browserView: null,
          popup: null,
          closing: false,
          removed: false
        };
        var popup = new state.popupBase(
          'vaporforge_notification_' + notification.notificationID,
          {
            title: 'Vapor Forge',
            dimensions: { width: 320, height: 80 },
            browserType: state.browserTypes.EBrowserType_DirectHWND_Borderless,
            eCreationFlags: nativeNotificationFlags()
          }
        );
        popup.Render = function(_, element) {
          installNativeToastSurface(element.ownerDocument);
          renderNativeToastDom(element, data, notification, entry);
          relayoutPreLoginNativeToasts();
        };
        popup.OnLoad = function() {};
        popup.OnClose = function() {
          removePreLoginNativeEntry(entry);
        };
        entry.popup = popup;
        state.preLoginNativeEntries.push(entry);
        popup.Show(false);
        if (!popup.BIsValid()) {
          removePreLoginNativeEntry(entry);
          return false;
        }
        relayoutPreLoginNativeToasts();
        return true;
      }

      function renderPreLoginNativeToast(data, notification) {
        if (!ensurePreLoginSurface() || !findNativePopupSupport()) return false;
        var active = activeSteamWindow();
        var ownerWindow = active && active.browserWindow;
        if (!ownerWindow || !ownerWindow.document || !ownerWindow.document.body) return false;
        if (!nativeToastSurfaceClass(ownerWindow.document)) return false;
        try {
          if (isGamepadUiReady()) {
            return renderGamepadPreLoginToast(data, notification, ownerWindow);
          }
          return renderDesktopPreLoginToast(data, notification, ownerWindow);
        } catch (error) {
          bridge.log('native notification error: ' + error);
          return false;
        }
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

      function findValveToastRenderer() {
        var found = null;
        bridge.eachExport(function(exp) {
          if (!isValveToastRenderer(exp)) return false;
          found = exp;
          return true;
        }, bridge.isRendererFactory);
        return found;
      }

      function findReact() {
        var found = null;
        bridge.eachExport(function(exp) {
          if (exp && typeof exp.createElement === 'function' &&
              typeof exp.Component === 'function' &&
              typeof exp.PureComponent === 'function' &&
              typeof exp.useLayoutEffect === 'function') {
            found = exp;
            return true;
          }
          return false;
        }, function(text) {
          return bridge.hasAll(text, ['createElement', 'PureComponent', 'useLayoutEffect']);
        });
        return found;
      }

      function findReactDom() {
        var found = null;
        bridge.eachExport(function(exp) {
          if (exp && typeof exp.createPortal === 'function' &&
              (typeof exp.createRoot === 'function' ||
               exp.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE)) {
            found = exp;
            return true;
          }
          return false;
        }, function(text) {
          return bridge.hasAll(text, ['createPortal', 'flushSync', 'version']);
        });
        return found;
      }

      function findReactHooks(react) {
        try {
          var legacy = react &&
            react.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
          var dispatcher = legacy && legacy.ReactCurrentDispatcher;
          if (dispatcher && dispatcher.current) return dispatcher.current;
          var client = react &&
            react.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;
          if (!client) return null;
          return Object.values(client).find(function(value) {
            return value && typeof value.useEffect === 'function';
          }) || null;
        } catch (_) {
          return null;
        }
      }

      function reactMajorVersion(reactDom) {
        var version = String(reactDom && reactDom.version || '');
        if (version.indexOf('18.') === 0) return 18;
        if (version.indexOf('19.') === 0) return 19;
        return 0;
      }

      function injectRendererTrampoline(component, react, reactDom, jsx, hooks) {
        if (!component || !component.prototype) return false;
        if (component.prototype.isReactComponent &&
            typeof component.prototype.render === 'function') return true;

        var major = reactMajorVersion(reactDom);
        if (major !== 18 && major !== 19) return false;

        var forwarded = function() {
          return component.apply(this, arguments);
        };
        var activeComponent = { component: forwarded };
        component.prototype.render = function() {
          return react.createElement(
            activeComponent.component,
            this.props,
            this.props && this.props.children
          );
        };
        component.prototype.isReactComponent = true;

        var stubsApplied = false;
        var oldHooks = null;
        var oldCreateElement = react.createElement;
        var oldJsx = jsx && jsx.jsx;
        var oldJsxs = jsx && jsx.jsxs;

        function applyStubs() {
          if (stubsApplied) return;
          stubsApplied = true;
          oldHooks = {
            useContext: hooks.useContext,
            useCallback: hooks.useCallback,
            useLayoutEffect: hooks.useLayoutEffect,
            useEffect: hooks.useEffect,
            useMemo: hooks.useMemo,
            useRef: hooks.useRef,
            useState: hooks.useState
          };
          hooks.useCallback = function(callback) { return callback; };
          hooks.useContext = function(context) { return context && context._currentValue; };
          hooks.useLayoutEffect = function() {};
          hooks.useEffect = function() {};
          hooks.useMemo = function(callback) { return callback(); };
          hooks.useRef = function(value) { return { current: value || {} }; };
          hooks.useState = function(value) {
            var current = value;
            return [current, function(next) { current = next; }];
          };
          react.createElement = function() {
            return Object.create(component.prototype);
          };
          if (major === 19) {
            jsx.jsx = function() { return Object.create(component.prototype); };
            jsx.jsxs = function() { return Object.create(component.prototype); };
          }
        }

        function removeStubs() {
          if (!stubsApplied) return;
          stubsApplied = false;
          if (oldHooks) Object.assign(hooks, oldHooks);
          oldHooks = null;
          react.createElement = oldCreateElement;
          if (major === 19) {
            jsx.jsx = oldJsx;
            jsx.jsxs = oldJsxs;
          }
        }

        var renderStep = 0;
        if (major === 19) {
          Object.defineProperty(component, 'contextType', {
            configurable: true,
            get: function() {
              if (renderStep === 0) renderStep = 1;
              if (this._contextType == null) this._contextType = {};
              if (!this._contextType.__vaporForgeCurrentValueHook) {
                this._contextType.__vaporForgeCurrentValueHook = true;
                Object.defineProperty(this._contextType, '_currentValue', {
                  configurable: true,
                  get: function() {
                    if (renderStep === 1) {
                      renderStep = 2;
                      applyStubs();
                    }
                    return this.__vaporForgeCurrentValue;
                  },
                  set: function(value) { this.__vaporForgeCurrentValue = value; }
                });
              }
              return this._contextType;
            },
            set: function(value) { this._contextType = value; }
          });
          Object.defineProperty(component.prototype, 'updater', {
            configurable: true,
            get: function() { return this._updater; },
            set: function(value) {
              if (renderStep === 1 || renderStep === 2) {
                renderStep = 0;
                removeStubs();
              }
              this._updater = value;
            }
          });
          Object.defineProperty(component, 'getDerivedStateFromProps', {
            configurable: true,
            get: function() {
              if (renderStep === 1 || renderStep === 2) {
                renderStep = 0;
                removeStubs();
              }
              return this._getDerivedStateFromProps;
            },
            set: function(value) { this._getDerivedStateFromProps = value; }
          });
        } else {
          Object.defineProperty(component, 'contextType', {
            configurable: true,
            get: function() {
              if (renderStep === 0) renderStep = 1;
              else if (renderStep === 3) renderStep = 4;
              return this._contextType;
            },
            set: function(value) { this._contextType = value; }
          });
          Object.defineProperty(component, 'contextTypes', {
            configurable: true,
            get: function() {
              if (renderStep === 1) {
                renderStep = 2;
                applyStubs();
              }
              return this._contextTypes;
            },
            set: function(value) { this._contextTypes = value; }
          });
          Object.defineProperty(component.prototype, 'updater', {
            configurable: true,
            get: function() { return this._updater; },
            set: function(value) {
              if (renderStep === 2) {
                renderStep = 0;
                removeStubs();
              }
              this._updater = value;
            }
          });
          Object.defineProperty(component, 'getDerivedStateFromProps', {
            configurable: true,
            get: function() {
              if (renderStep === 2) {
                renderStep = 0;
                removeStubs();
              }
              return this._getDerivedStateFromProps;
            },
            set: function(value) { this._getDerivedStateFromProps = value; }
          });
        }
        return true;
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

      function toastLogoMode(data) {
        var mode = String(data && data.logoMode || '').toLowerCase();
        if (mode === 'hidden') return 'hidden';
        if (mode === 'custom') return data && data.icon ? 'custom' : 'default';
        if (mode === 'default') return 'default';
        return data && data.icon ? 'custom' : 'default';
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
        if (!isGamepadUiReady()) root.width = '100%';
        if (style === 'banner') {
          root.minHeight = '70px';
          root.padding = '0 8px';
          root.gap = '10px';
        } else {
          root.paddingLeft = '10px';
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

      function popupLogoStyle() {
        return {
          objectFit: 'contain',
          overflow: 'hidden',
          boxSizing: 'border-box'
        };
      }

      function defaultLogoStyle(kind, style) {
        var banner = style === 'banner';
        return {
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          overflow: 'hidden',
          boxSizing: 'border-box',
          borderRadius: '6px',
          border: banner ? '1px solid currentColor' : '0',
          background: banner ? 'transparent' :
            'linear-gradient(135deg,' + toastAccent(kind) + ',#2a475e)',
          color: banner ? 'inherit' : '#fff',
          fontSize: '13px',
          fontWeight: 700,
          lineHeight: 1
        };
      }

      function renderDefaultLogo(jsx, className, kind, style) {
        return jsx.jsx('div', {
          className: className || '',
          style: defaultLogoStyle(kind, style),
          children: 'SR'
        });
      }

      function renderPopupToast(css, jsx, data, notification) {
        try {
          var title = data.title || 'Vapor Forge';
          var body = data.body || '';
          var icon = data.icon || '';
          var kind = toastKind(data);
          var style = toastStyle(data, kind);
          var logoMode = toastLogoMode(data);
          var logo = logoMode === 'custom'
            ? jsx.jsx('img', {
              className: popupLogoClass(css),
              src: icon,
              draggable: false,
              style: popupLogoStyle()
            })
            : logoMode === 'default'
              ? renderDefaultLogo(jsx, popupLogoClass(css), kind, style)
              : null;
          return jsx.jsxs('div', {
            className: (css.ShortTemplate || css.StandardTemplate || '') +
              ' VaporForgePopupToast VaporForgeToast-' + kind + ' VaporForgeToastStyle-' + style,
            style: popupRootStyle(kind, style),
            onClick: function() {
              if (activateQamToast(data, notification)) {
                closePreLoginNativeToast(notification.notificationID);
              }
            },
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
          var logoMode = toastLogoMode(data);
          var logo = logoMode === 'custom'
            ? jsx.jsx('img', {
              className: css.StandardLogoDimensions || css.Icon || '',
              src: icon,
              draggable: false
            })
            : logoMode === 'default'
              ? renderDefaultLogo(
                jsx,
                css.StandardLogoDimensions || css.Icon || '',
                kind,
                style
              )
              : null;
          var timestamp = notification && notification.rtCreated
            ? jsx.jsx('div', {
              className: css.Timestamp || '',
              style: toastTextStyle(kind, style, true),
              children: new Date(notification.rtCreated).toLocaleTimeString([], {
                hour: '2-digit', minute: '2-digit'
              })
            })
            : null;
          var content = jsx.jsxs('div', {
            className: css.StandardTemplate || '',
            children: [
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
            ]
          });
          var Focusable = state.focusable;
          if (!Focusable) return renderFallback(jsx, title, body);
          return jsx.jsx(Focusable, {
            onActivate: function() { activateQamToast(data, notification); },
            className: (css.StandardTemplateContainer || '') +
              ' VaporForgeQAMToast VaporForgeToast-' + kind + ' VaporForgeToastStyle-' + style,
            style: qamRootStyle(kind, style),
            children: content
          });
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
          if (location === 1 || !isGamepadUiReady()) {
            return renderPopupToast(css, jsx, data, notification);
          }
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

      function patchClassRenderer(renderer) {
        var prototype = renderer && renderer.prototype;
        var current = prototype && prototype.render;
        if (typeof current !== 'function') return false;
        if (current === state.rendererHook) return true;
        var wrapped = function() {
          try {
            if (isVaporForgeProps(this && this.props)) {
              return renderVaporForgeToast(this.props);
            }
          } catch (error) {
            bridge.log('renderer patch error: ' + error);
          }
          return current.apply(this, arguments);
        };
        try {
          wrapped.toString = function() { return current.toString(); };
          prototype.render = wrapped;
          state.rendererHook = wrapped;
          return true;
        } catch (error) {
          bridge.log('renderer hook error: ' + error);
          return false;
        }
      }

      function patchToastRenderer() {
        var gamepadUiReady = isGamepadUiReady();
        state.focusable = state.focusable || findFocusable(gamepadUiReady);
        if (gamepadUiReady) {
          state.navigation = state.navigation || bridge.findWindowStore();
        }
        const currentRenderer = findValveToastRenderer();
        if (currentRenderer && currentRenderer !== state.renderer) {
          state.renderPatched = false;
        }
        const renderer = currentRenderer || state.renderer;
        const jsx = bridge.findJsx() || state.jsx;
        const css = findCss() || state.css;
        const react = findReact() || state.react;
        const reactDom = findReactDom() || state.reactDom;
        const hooks = findReactHooks(react) || state.reactHooks;
        if (!renderer || !jsx || !css || !react || !reactDom || !hooks) return false;
        if (typeof jsx.jsx !== 'function' || typeof jsx.jsxs !== 'function') return false;
        if (!injectRendererTrampoline(renderer, react, reactDom, jsx, hooks)) return false;
        state.renderer = renderer;
        state.jsx = jsx;
        state.css = css;
        state.react = react;
        state.reactDom = reactDom;
        state.reactHooks = hooks;
        var previousHook = state.rendererHook;
        if (patchClassRenderer(renderer)) {
          state.renderPatched = true;
          if (state.rendererHook !== previousHook) {
            bridge.log('Valve toast renderer trampoline ready');
          }
          return true;
        }
        state.renderPatched = false;
        return false;
      }

      function flush() {
        if (!bridge.isTargetSteamUiContext()) return false;
        if (!isSteamAppBeforeLoginReady()) return false;
        if (!state.store || !state.renderPatched) return false;
        if (isGamepadUiReady() && !state.focusable) return false;
        if (pendingNeedsLanguage() && !state.languageReady) return false;
        var beforeServices = !isSteamServicesReady();
        if (!beforeServices && state.preLoginNativeEntries.length) {
          clearPreLoginNativeToasts();
        }
        if (beforeServices &&
            (!ensurePreLoginSurface() || !findNativePopupSupport())) return false;
        while (state.pending.length) {
          var toast = localizeToast(state.pending.shift());
          var flushedKey = toast.id != null ? 'flushed:' + toast.id : '';
          if (flushedKey && state.seen[flushedKey]) continue;
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
          if (beforeServices && !renderPreLoginNativeToast(toast, toastData)) {
            state.pending.unshift(toast);
            return false;
          }
          if (flushedKey) state.seen[flushedKey] = true;
          state.store.ProcessNotification({
            showToast: !beforeServices,
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
        ensureLanguage();
        trackSteamApp();
        observeSteamBeforeLoginReady();
        var store = findStore() || state.store;
        state.store = store;
        patchToastRenderer();
        var ready = !!(isSteamAppBeforeLoginReady() && state.store && state.renderPatched &&
          (!isGamepadUiReady() || state.focusable) &&
          (!pendingNeedsLanguage() || state.languageReady));
        if (ready) flush();
        return ready;
      }

      bridge.showToast = showToast;
      bridge.flush = flush;
      return { tryReady: tryReady, flush: flush, showToast: showToast };
    });
  } catch (error) {
    try { console.log('[VaporForgeUI] toast install error: ' + error); } catch (_) {}
  }
})();
