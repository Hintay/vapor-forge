// @ts-check
(function() {
  try {
    const bridge = window.VaporForgeUIBridge;
    if (!bridge || typeof bridge.registerFeature !== 'function') return;

    /**
     * @typedef {Object} ConflictCandidate
     * @property {string} token
     * @property {number} revision
     * @property {string} machine_name
     * @property {number} created_at_ms
     * @property {number} file_count
     * @property {number} total_bytes
     * @property {string[]} file_names
     * @property {boolean} is_local
     */

    /**
     * @typedef {Object} ConflictDialog
     * @property {number} app_id
     * @property {string} cancel_token
     * @property {ConflictCandidate[]} candidates
     */

    bridge.registerFeature('cloud-conflict', 1, function(bridge) {
      const state = {
        jsx: null,
        modal: null,
        windowStore: null,
        dialogs: {},
        waiting: {},
        handles: {},
        close: {},
        opening: {},
        epoch: {},
        promoted: {},
        nativeDialogs: {},
        observer: null,
        observerDocument: null,
        language: 'english',
        locale: 'en-US',
        languageReady: false,
        languagePromise: null
      };

      const localeByLanguage = {
        english: 'en-US',
        schinese: 'zh-CN',
        tchinese: 'zh-TW',
        japanese: 'ja-JP'
      };

      function finishLanguage(language) {
        if (language === 'sc_schinese') language = 'schinese';
        if (!localeByLanguage[language]) language = 'english';
        state.language = language;
        state.locale = localeByLanguage[language];
        state.languageReady = true;
        bridge.tryReady();
      }

      function ensureLanguage() {
        if (state.languageReady || state.languagePromise) return;
        try {
          const settings = window.SteamClient && window.SteamClient.Settings;
          if (!settings || typeof settings.GetCurrentLanguage !== 'function') {
            finishLanguage('english');
            return;
          }
          state.languagePromise = Promise.resolve(settings.GetCurrentLanguage()).then(function(language) {
            finishLanguage(String(language || 'english').toLowerCase());
          }).catch(function(error) {
            bridge.log('cloud conflict language error: ' + error);
            finishLanguage('english');
          });
        } catch (error) {
          bridge.log('cloud conflict language error: ' + error);
          finishLanguage('english');
        }
      }

      function translate(key, values) {
        const locales = bridge.resources.cloudConflictLocales || {};
        const english = locales.english || {};
        const messages = locales[state.language] || english;
        var message = messages[key] || english[key] || key;
        if (!values) return message;
        return message.replace(/\{([a-z_]+)\}/g, function(match, name) {
          return Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : match;
        });
      }

      function formatNumber(value, options) {
        try { return new Intl.NumberFormat(state.locale, options).format(value); }
        catch (_) { return String(value); }
      }

      function formatCloudBytes(value) {
        var bytes = Number(value || 0);
        if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        var index = 0;
        while (bytes >= 1024 && index < units.length - 1) {
          bytes /= 1024;
          index++;
        }
        const digits = index && bytes < 10 ? 1 : 0;
        return formatNumber(bytes, {
          minimumFractionDigits: digits,
          maximumFractionDigits: digits
        }) + ' ' + units[index];
      }

      function formatFileCount(value) {
        const count = Math.max(0, Math.floor(Number(value) || 0));
        return translate(count === 1 ? 'file_count_one' : 'file_count_other', {
          count: formatNumber(count)
        });
      }

      function formatTime(value) {
        if (!(Number(value) > 0)) return translate('unknown_time');
        try { return new Date(Number(value)).toLocaleString(state.locale); }
        catch (_) { return translate('unknown_time'); }
      }

      function setCloudBusy(root, busy, message) {
        if (!root) return;
        const selected = root.getAttribute('data-selected-token') || '';
        root.querySelectorAll('button').forEach(function(button) {
          const isContinue = button.getAttribute('data-action') === 'continue';
          const enabled = !busy && (!isContinue || !!selected);
          button.disabled = !enabled;
          if (isContinue) {
            button.setAttribute('aria-disabled', enabled ? 'false' : 'true');
            button.style.opacity = enabled ? '1' : '0.45';
            button.style.cursor = enabled ? 'pointer' : 'default';
          }
        });
        const status = root.querySelector('[data-cloud-status]');
        if (status) status.textContent = message || '';
      }

      function finishGameAction(appId, cancel, onComplete, onError) {
        try {
          window.SteamClient.Apps.GetGameActionForApp(String(appId), function(handle) {
            handle = Number(handle);
            if (!Number.isFinite(handle) || handle <= 0) {
              onError(translate('pending_launch_missing'));
              return;
            }
            try {
              restoreNativeCloudDialog(appId);
              if (cancel) window.SteamClient.Apps.CancelGameAction(handle);
              else window.SteamClient.Apps.ContinueGameAction(handle, 'IgnorePendingCloudSessions');
              delete state.nativeDialogs[String(appId)];
              onComplete();
            } catch (error) {
              detachNativeCloudDialog(appId);
              bridge.log('cloud game action error: ' + error);
              onError(translate(cancel ? 'launch_cancel_failed' : 'launch_continue_failed'));
            }
          });
        } catch (error) {
          bridge.log('cloud game action error: ' + error);
          onError(translate(cancel ? 'launch_cancel_failed' : 'launch_continue_failed'));
        }
      }

      function submitCloudChoice(dialog, token, cancel, root, closeModal) {
        if (!token || state.waiting[token]) return;
        setCloudBusy(root, true, translate(cancel ? 'cancelling' : 'saving_selection'));
        state.waiting[token] = { appId: dialog.app_id, root: root, closeModal: closeModal };
        try {
          window.SteamClient.Apps.VaporForgeResolveCloudConflict(token);
        } catch (_) {
          delete state.waiting[token];
          setCloudBusy(root, false, translate(cancel ? 'cancel_failed' : 'submit_failed'));
        }
      }

      function CloudConflictModal(props) {
        const jsx = state.jsx;
        /** @type {ConflictDialog} */
        const dialog = props.dialog;
        const appId = Number(dialog.app_id);
        state.close[String(appId)] = props.closeModal;
        const rows = dialog.candidates.map(function(candidate) {
          const title = (candidate.machine_name || translate('unknown_device')) +
            (candidate.is_local ? translate('this_device_suffix') : '');
          const names = Array.isArray(candidate.file_names) && candidate.file_names.length
            ? candidate.file_names.join(state.language === 'english' ? ', ' : '\u3001')
            : translate('no_files');
          const metadata = translate('metadata', {
            time: formatTime(candidate.created_at_ms),
            files: formatFileCount(candidate.file_count),
            size: formatCloudBytes(candidate.total_bytes)
          });
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
              jsx.jsx('div', {
                style: { fontSize: '15px', fontWeight: '600' },
                children: title
              }),
              jsx.jsx('div', {
                style: { color: '#b8bdc3', fontSize: '12px', textAlign: 'right' },
                children: translate('revision', { revision: formatNumber(candidate.revision) })
              }),
              jsx.jsx('div', {
                style: {
                  color: '#c7cbd0', fontSize: '12px', overflow: 'hidden',
                  textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                },
                children: names
              }),
              jsx.jsx('div', {
                style: { color: '#b8bdc3', fontSize: '12px', textAlign: 'right' },
                children: metadata
              })
            ]
          }, candidate.token);
        });
        return jsx.jsxs('div', {
          'data-vapor-cloud-conflict': String(appId),
          style: {
            width: 'min(760px, calc(100vw - 48px))', maxHeight: 'calc(100vh - 48px)',
            overflow: 'auto', backgroundColor: '#202328', color: '#f2f2f2',
            boxSizing: 'border-box', padding: '24px',
            fontFamily: 'Motiva Sans, Arial, sans-serif'
          },
          children: [
            jsx.jsx('div', {
              style: { fontSize: '22px', fontWeight: '600', marginBottom: '8px' },
              children: translate('title')
            }),
            jsx.jsx('div', {
              style: {
                color: '#b8bdc3', fontSize: '14px', lineHeight: '20px',
                marginBottom: '18px'
              },
              children: translate('description')
            }),
            jsx.jsx('div', { style: { display: 'grid', gap: '8px' }, children: rows }),
            jsx.jsx('div', {
              'data-cloud-status': '1',
              style: {
                minHeight: '20px', marginTop: '12px', color: '#ffb454', fontSize: '13px'
              },
              children: ''
            }),
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
                  children: translate('cancel')
                }),
                jsx.jsx('button', {
                  type: 'button',
                  disabled: true,
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
                  children: translate('continue')
                })
              ]
            })
          ]
        });
      }

      function closeCloudConflict(appId) {
        const key = String(appId);
        const close = state.close[key];
        const handle = state.handles[key];
        state.epoch[key] = Number(state.epoch[key] || 0) + 1;
        delete state.close[key];
        delete state.handles[key];
        delete state.opening[key];
        try {
          if (typeof close === 'function') close();
          else if (handle && typeof handle.Close === 'function') handle.Close();
        } catch (_) {}
      }

      function renderCloudConflict(appId) {
        const key = String(appId);
        const dialog = state.dialogs[key];
        if (!dialog || !Array.isArray(dialog.candidates) || dialog.candidates.length < 2) {
          return false;
        }
        if (state.handles[key] || state.opening[key]) return true;
        if (!state.languageReady || !state.jsx || !state.modal || !state.windowStore) return false;
        const owner = state.windowStore.ActiveWindowInstance &&
          state.windowStore.ActiveWindowInstance.BrowserWindow;
        if (!owner) return false;
        const epoch = Number(state.epoch[key] || 0) + 1;
        state.epoch[key] = epoch;
        state.opening[key] = true;
        const element = state.jsx.jsx(CloudConflictModal, { dialog: dialog });
        Promise.resolve(state.modal(element, owner, {
          popupHeight: 560,
          popupWidth: 740
        })).then(function(handle) {
          if (state.epoch[key] !== epoch) {
            if (handle && typeof handle.Close === 'function') handle.Close();
            return;
          }
          state.opening[key] = false;
          if (state.dialogs[key] === dialog) {
            state.handles[key] = handle;
            ensureCloudObserver();
          } else if (handle && typeof handle.Close === 'function') {
            handle.Close();
          }
        }).catch(function(error) {
          state.opening[key] = false;
          bridge.log('cloud modal error: ' + error);
        });
        return true;
      }

      function ensureCloudObserver() {
        const owner = state.windowStore && state.windowStore.ActiveWindowInstance &&
          state.windowStore.ActiveWindowInstance.BrowserWindow;
        const targetDocument = owner && owner.document;
        const Observer = owner && owner.MutationObserver;
        if (!targetDocument || typeof Observer !== 'function') return;
        if (state.observer && state.observerDocument === targetDocument) return;
        if (state.observer) state.observer.disconnect();
        state.observerDocument = targetDocument;
        state.observer = new Observer(function() {
          Object.keys(state.dialogs).forEach(function(key) {
            promoteCloudDialog(key, targetDocument);
          });
        });
        state.observer.observe(targetDocument.documentElement, {
          subtree: true,
          childList: true,
          attributes: true,
          attributeFilter: ['class']
        });
      }

      function stopCloudObserverIfIdle() {
        if (!state.observer || Object.keys(state.dialogs).length) return;
        state.observer.disconnect();
        state.observer = null;
        state.observerDocument = null;
      }

      function promoteCloudDialog(key, targetDocument) {
        if (state.promoted[key]) return;
        const roots = targetDocument.querySelectorAll(
          '[data-vapor-cloud-conflict="' + key + '"]'
        );
        const root = roots.length && roots[roots.length - 1];
        const customOverlay = root && root.closest('.ModalOverlayContent');
        if (!customOverlay || !customOverlay.classList.contains('inactive')) return;
        const activeOverlay = Array.from(
          targetDocument.querySelectorAll('.ModalOverlayContent.active')
        ).find(function(overlay) { return !overlay.contains(root); });
        const customDialog = customOverlay.closest('dialog');
        const activeDialog = activeOverlay && activeOverlay.closest('dialog');
        const parent = activeDialog && activeDialog.parentNode;
        if (!activeDialog || !customDialog || !parent) return;
        state.promoted[key] = true;
        try {
          state.nativeDialogs[key] = {
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
          delete state.promoted[key];
          restoreNativeCloudDialog(Number(key));
          delete state.nativeDialogs[key];
          activeOverlay.classList.remove('inactive');
          activeOverlay.classList.add('active');
          customOverlay.classList.remove('active');
          customOverlay.classList.add('inactive');
          try { if (customDialog.open) customDialog.close(); } catch (_) {}
          bridge.log('cloud modal promotion error: ' + error);
        }
      }

      function restoreNativeCloudDialog(appId) {
        const record = state.nativeDialogs[String(appId)];
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
        const record = state.nativeDialogs[String(appId)];
        if (!record || !record.dialog.isConnected) return;
        try { if (record.dialog.open) record.dialog.close(); } catch (_) {}
        record.dialog.remove();
      }

      function showCloudConflict(dialog) {
        if (!dialog || !Number.isFinite(Number(dialog.app_id))) return false;
        const appId = Number(dialog.app_id);
        const current = state.dialogs[String(appId)];
        if (current && current.cancel_token !== dialog.cancel_token) {
          restoreNativeCloudDialog(appId);
          delete state.nativeDialogs[String(appId)];
          closeCloudConflict(appId);
          delete state.promoted[String(appId)];
        }
        state.dialogs[String(appId)] = dialog;
        ensureCloudObserver();
        tryReady();
        return renderCloudConflict(appId);
      }

      function ackCloudConflict(ack) {
        if (!ack || !ack.token) return false;
        const waiting = state.waiting[ack.token];
        if (!waiting) return false;
        delete state.waiting[ack.token];
        if (!ack.accepted) {
          const key = ack.error === 'stale_choice' ? 'choice_stale' : 'selection_save_failed';
          setCloudBusy(waiting.root, false, translate(key));
          return false;
        }
        const finish = function() {
          closeCloudConflict(waiting.appId);
          delete state.dialogs[String(waiting.appId)];
          delete state.promoted[String(waiting.appId)];
          stopCloudObserverIfIdle();
        };
        const fail = function(message) { setCloudBusy(waiting.root, false, message); };
        if (ack.cancel_launch) finishGameAction(ack.app_id, true, finish, fail);
        else if (ack.resume_launch) finishGameAction(ack.app_id, false, finish, fail);
        else finish();
        return true;
      }

      function tryReady() {
        if (!Object.keys(state.dialogs).length) return true;
        ensureLanguage();
        if (!bridge.req || !state.languageReady) return false;
        state.jsx = state.jsx || bridge.findJsx();
        state.modal = state.modal || bridge.findModal();
        state.windowStore = state.windowStore || bridge.findWindowStore();
        if (state.jsx && state.modal && state.windowStore) {
          Object.keys(state.dialogs).forEach(function(appId) {
            if (!state.handles[appId] && !state.opening[appId]) {
              renderCloudConflict(Number(appId));
            }
          });
          return true;
        }
        return false;
      }

      function dispose() {
        if (state.observer) state.observer.disconnect();
        Object.keys(state.dialogs).forEach(function(appId) {
          restoreNativeCloudDialog(Number(appId));
          closeCloudConflict(Number(appId));
        });
      }

      bridge.showCloudConflict = showCloudConflict;
      bridge.ackCloudConflict = ackCloudConflict;
      return {
        tryReady: tryReady,
        dispose: dispose,
        showCloudConflict: showCloudConflict,
        ackCloudConflict: ackCloudConflict
      };
    });
  } catch (error) {
    try { console.log('[VaporForgeUI] cloud conflict install error: ' + error); } catch (_) {}
  }
})();
