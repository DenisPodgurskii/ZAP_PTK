/* Author: Denis Podgurskii */

if (!window.__PTK_CONTENT_BOOTSTRAP_LOADED__) {
window.__PTK_CONTENT_BOOTSTRAP_LOADED__ = true;

const DIALOG_SUPPRESSOR_SCRIPT_ID = 'ptk-dialog-suppressor';
const runtime = (typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null);

const PTK_SPA_ATTACK_TAB_MARKER = 'ptk_spa_attack_tab';
const PTK_SPA_DIALOG_PARAM = 'ptk_dast=1';
const ZAP_CALLBACK_PATH_REGEX = /^\/zapCallBackUrl\/[^/?#]+/i;

function runtimeGetURL(path) {
    if (!runtime?.getURL) return null;
    try {
        return runtime.getURL(path);
    } catch (_) {
        return null;
    }
}

function shouldSuppressSpaDialogs() {
    if (typeof window === 'undefined') return false;
    if (typeof window.name === 'string' && window.name.includes(PTK_SPA_ATTACK_TAB_MARKER)) return true;
    try {
        return String(window.location.href || '').includes(PTK_SPA_DIALOG_PARAM);
    } catch (_) {
        return false;
    }
}

function injectDialogSuppressor() {
    try {
        const existing = document.getElementById(DIALOG_SUPPRESSOR_SCRIPT_ID);
        if (existing) return;
        const src = runtimeGetURL('ptk/content/dialog_suppressor.js');
        if (!src) return;
        const script = document.createElement('script');
        script.id = DIALOG_SUPPRESSOR_SCRIPT_ID;
        script.src = src;
        script.async = false;
        script.onload = () => script.remove();
        script.onerror = () => script.remove();
        const parent = document.head || document.documentElement;
        if (parent) {
            parent.appendChild(script);
        }
    } catch (_) { }
}

if (shouldSuppressSpaDialogs()) {
    injectDialogSuppressor();
}

const bootstrapState = {
    requestInFlight: null,
    mode: null,
    script: null
};

function sendRuntimeMessage(payload) {
    if (!runtime?.sendMessage) return Promise.resolve();
    try {
        return runtime.sendMessage(payload);
    } catch (_) {
        return Promise.resolve();
    }
}

function getCurrentHref() {
    try {
        return window.location?.href || '';
    } catch (_) {
        return '';
    }
}

function isTopFrame() {
    try {
        return window.top === window;
    } catch (_) {
        return false;
    }
}

function isZapCallbackPageUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl) return false;
    try {
        const parsed = new URL(rawUrl);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
        return ZAP_CALLBACK_PATH_REGEX.test(parsed.pathname);
    } catch (_) {
        return false;
    }
}

function notifyZapCallbackPageIfPresent(reason = 'document_start') {
    if (!isTopFrame()) return;
    const href = getCurrentHref();
    if (!isZapCallbackPageUrl(href)) return;
    sendRuntimeMessage({
        channel: 'ptk_content2background_zap',
        type: 'zap_callback_url',
        url: href,
        reason
    }).catch(() => { });
}

function installSharedIastBridge() {
    if (window.__PTK_SHARED_IAST_CONTENT_BRIDGE__ === true) {
        return;
    }
    window.__PTK_SHARED_IAST_CONTENT_BRIDGE__ = true;

    if (runtime?.onMessage) {
        runtime.onMessage.addListener((message) => {
            if (message?.channel === 'ptk_background_iast2content') {
                if (message.type === 'clean iast result') {
                    localStorage.removeItem('ptk_iast_buffer');
                }
                if (message.type === 'ping') {
                    return Promise.resolve({ ok: true });
                }
            }

            if (message?.channel === 'ptk_background_iast2content_modules' && message.iastModules) {
                try {
                    window.postMessage({
                        channel: 'ptk_background_iast2content_modules',
                        iastModules: message.iastModules
                    }, '*');
                } catch (_) { }
                return Promise.resolve({ ok: true });
            }

            if (message?.channel === 'ptk_background_iast2content_token_origin') {
                try {
                    window.postMessage({
                        channel: 'ptk_background_iast2content_token_origin',
                        tokens: Array.isArray(message.tokens) ? message.tokens : []
                    }, '*');
                } catch (_) { }
                return Promise.resolve({ ok: true });
            }

            return undefined;
        });
    }

    window.addEventListener('message', (event) => {
        const data = event.data || {};

        if (data?.ptk_iast) {
            const type = data?.ptk_iast === 'runtime_signal' ? 'runtime_signal' : 'finding_report';
            sendRuntimeMessage({
                channel: 'ptk_content_iast2background_iast',
                type,
                finding: type === 'finding_report' ? data.finding : undefined,
                signal: type === 'runtime_signal' ? data.signal : undefined
            }).catch(() => { });
            return;
        }

        if (data?.channel === 'ptk_iast_agent_ready') {
            sendRuntimeMessage({
                channel: 'ptk_content_iast2background_iast',
                type: 'agent_ready'
            }).catch(() => { });
            return;
        }

        if (data?.channel === 'ptk_iast_agent_failed') {
            sendRuntimeMessage({
                channel: 'ptk_content_iast2background_iast',
                type: 'agent_failed',
                error: data?.error || null
            }).catch(() => { });
            return;
        }

        if (data?.channel === 'ptk_iast_runtime_health') {
            sendRuntimeMessage({
                channel: 'ptk_content_iast2background_iast',
                type: 'runtime_health',
                health: data?.health && typeof data.health === 'object' ? data.health : null
            }).catch(() => { });
            return;
        }

        if (data?.channel === 'ptk_content_iast_request_modules') {
            sendRuntimeMessage({
                channel: 'ptk_content_iast2background_request_modules'
            }).then((resp) => {
                try {
                    window.postMessage({
                        channel: 'ptk_background_iast2content_modules',
                        iastModules: resp?.iastModules || null,
                        iastModulesSignature: resp?.iastModulesSignature || null,
                        scanStrategy: resp?.scanStrategy || null
                    }, '*');
                } catch (_) { }
            }).catch(() => {
                try {
                    window.postMessage({
                        channel: 'ptk_background_iast2content_modules',
                        iastModules: null
                    }, '*');
                } catch (_) { }
            });
        }
    }, false);
}

function readStoredZapHintUrl() {
    try {
        const value = window.localStorage?.getItem?.('localzapurl');
        return typeof value === 'string' && value.trim() ? value.trim() : '';
    } catch (_) {
        return '';
    }
}

function requestRuntimeProfile(reason = 'document_start') {
    if (bootstrapState.requestInFlight || !runtime?.sendMessage) {
        return bootstrapState.requestInFlight || Promise.resolve(null);
    }

    const href = getCurrentHref();
    const zapHintUrl = readStoredZapHintUrl();

    bootstrapState.requestInFlight = runtime.sendMessage({
        channel: 'ptk_content2background_runtime',
        type: 'content_bootstrap_hello',
        url: href,
        zapHintUrl,
        reason,
        mode: bootstrapState.mode,
        script: bootstrapState.script
    }).then((response) => {
        if (response && typeof response === 'object') {
            bootstrapState.mode = typeof response.mode === 'string' ? response.mode : bootstrapState.mode;
            bootstrapState.script = typeof response.script === 'string' ? response.script : bootstrapState.script;
        }
        return response;
    }).catch(() => null).finally(() => {
        bootstrapState.requestInFlight = null;
    });

    return bootstrapState.requestInFlight;
}

if (runtime?.onMessage) {
    runtime.onMessage.addListener((message) => {
        if (message?.channel === 'ptk_background2content_runtime' && message?.type === 'refresh_profile') {
            void requestRuntimeProfile('background_refresh');
        }
    });
}

installSharedIastBridge();

notifyZapCallbackPageIfPresent();
void requestRuntimeProfile();

}
