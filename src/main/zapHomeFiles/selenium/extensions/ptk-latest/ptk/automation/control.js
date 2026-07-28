/* Author: Denis Podgurskii */
'use strict';

(function () {
    const runtime = typeof browser !== 'undefined'
        ? browser.runtime
        : (typeof chrome !== 'undefined' ? chrome.runtime : null);

    async function armIastForNavigation(options = {}) {
        if (!runtime?.sendMessage) {
            return { ok: false, error: 'ptk_runtime_unavailable' };
        }
        try {
            return await runtime.sendMessage({
                channel: 'ptk_extension_automation_control',
                type: 'arm_iast_for_navigation',
                targetUrl: options.targetUrl,
                scanOptions: options.scanOptions || {},
                iastOptions: options.iastOptions || {},
                scanStrategy: options.scanStrategy || null,
                ttlMs: options.ttlMs || null
            });
        } catch (error) {
            return {
                ok: false,
                error: error?.message || String(error)
            };
        }
    }

    globalThis.PTK_AUTOMATION_CONTROL = Object.freeze({
        version: '1',
        armIastForNavigation
    });
    document.documentElement.dataset.ptkAutomationControl = 'ready';
}());
