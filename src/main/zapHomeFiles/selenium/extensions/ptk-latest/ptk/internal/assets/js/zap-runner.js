/* Author: Denis Podgurskii */
'use strict';

(function () {
  const runtime = (typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null);

  const RETRY_DELAYS_MS = [0, 100, 300, 700, 1200, 2000, 3500, 5000, 7500, 10000];
  const requestPrefix = `zap-runner-${Date.now().toString(36)}`;
  let completed = false;

  function sendRuntimeMessage(payload) {
    if (!runtime?.sendMessage) {
      return Promise.resolve({ ok: false, observed: false, reason: 'runtime_unavailable' });
    }
    try {
      const result = runtime.sendMessage(payload);
      if (result && typeof result.then === 'function') {
        return result;
      }
      return new Promise((resolve) => {
        try {
          runtime.sendMessage(payload, (response) => resolve(response));
        } catch (_) {
          resolve({ ok: false, observed: false, reason: 'runtime_send_failed' });
        }
      });
    } catch (_) {
      return Promise.resolve({ ok: false, observed: false, reason: 'runtime_send_failed' });
    }
  }

  async function scan(reason, index) {
    if (completed) return;
    const response = await sendRuntimeMessage({
      channel: 'ptk_extension_zap_runner',
      type: 'scan_callback_tabs',
      reason,
      requestId: `${requestPrefix}-${index}`
    });
    if (response?.ok === true && response?.observed === true) {
      completed = true;
      setTimeout(() => {
        try {
          window.close();
        } catch (_) { }
      }, 250);
    }
  }

  RETRY_DELAYS_MS.forEach((delayMs, index) => {
    setTimeout(() => {
      void scan(index === 0 ? 'runner_loaded' : `runner_retry_${delayMs}`, index);
    }, delayMs);
  });
}());
