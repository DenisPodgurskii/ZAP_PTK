/* Author: Denis Podgurskii */

if (!window.__PTK_CONTENT_BOOTSTRAP_LOADED__) {
window.__PTK_CONTENT_BOOTSTRAP_LOADED__ = true;

const shared = window.PTK_CONTENT_SHARED || {};
const runtime = shared.runtime || ((typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null));

const DIALOG_SUPPRESSOR_SCRIPT_ID = 'ptk-dialog-suppressor';
const PTK_SPA_ATTACK_TAB_MARKER = 'ptk_spa_attack_tab';
const PTK_SPA_DIALOG_PARAM = 'ptk_dast=1';
const ZAP_CALLBACK_NOTIFY_RETRY_DELAYS_MS = [0, 100, 500, 1000, 2500, 5000, 9000, 10500, 11500, 11900];

const bootstrapState = {
    requestInFlight: null,
    mode: null,
    script: null
};

function runtimeGetURL(path) {
    if (typeof shared.runtimeGetURL === 'function') return shared.runtimeGetURL(path);
    if (!runtime?.getURL) return null;
    try {
        return runtime.getURL(path);
    } catch (_) {
        return null;
    }
}

function sendRuntimeMessage(payload) {
    if (typeof shared.sendRuntimeMessage === 'function') return shared.sendRuntimeMessage(payload);
    if (!runtime?.sendMessage) return Promise.resolve();
    try {
        return runtime.sendMessage(payload);
    } catch (_) {
        return Promise.resolve();
    }
}

function getCurrentHref() {
    if (typeof shared.getCurrentHref === 'function') return shared.getCurrentHref();
    try {
        return window.location?.href || '';
    } catch (_) {
        return '';
    }
}

function isTopFrame() {
    if (typeof shared.isTopFrame === 'function') return shared.isTopFrame();
    try {
        return window.top === window;
    } catch (_) {
        return false;
    }
}

function isZapCallbackPageUrl(url) {
    return typeof shared.isZapCallbackPageUrl === 'function'
        ? shared.isZapCallbackPageUrl(url)
        : false;
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
        if (parent) parent.appendChild(script);
    } catch (_) { }
}

const zapCallbackNotifyState = {
    acknowledged: false,
    url: '',
    timers: []
};

function clearZapCallbackNotifyTimers() {
    for (const timer of zapCallbackNotifyState.timers.splice(0)) {
        try {
            clearTimeout(timer);
        } catch (_) { }
    }
}

function notifyZapCallbackPageIfPresent(reason = 'document_start') {
    if (!isTopFrame()) return;
    const href = getCurrentHref();
    if (!isZapCallbackPageUrl(href)) return;
    if (zapCallbackNotifyState.acknowledged && zapCallbackNotifyState.url === href) return;
    zapCallbackNotifyState.url = href;
    sendRuntimeMessage({
        channel: 'ptk_content2background_zap',
        type: 'zap_callback_url',
        url: href,
        reason
    }).then((response) => {
        if (response?.ok === true) {
            zapCallbackNotifyState.acknowledged = true;
            clearZapCallbackNotifyTimers();
        }
    }).catch(() => { });
}

function scheduleZapCallbackNotifications() {
    if (!isTopFrame() || !isZapCallbackPageUrl(getCurrentHref())) return;
    clearZapCallbackNotifyTimers();
    notifyZapCallbackPageIfPresent('document_start');
    for (const delayMs of ZAP_CALLBACK_NOTIFY_RETRY_DELAYS_MS) {
        const timer = setTimeout(() => {
            notifyZapCallbackPageIfPresent(`retry_${delayMs}`);
        }, delayMs);
        zapCallbackNotifyState.timers.push(timer);
    }
    const eventRetry = (event) => {
        notifyZapCallbackPageIfPresent(event?.type || 'event');
    };
    window.addEventListener('DOMContentLoaded', eventRetry, { once: true });
    window.addEventListener('load', eventRetry, { once: true });
    window.addEventListener('pageshow', eventRetry, { once: true });
}

function requestRuntimeProfile(reason = 'document_start') {
    if (bootstrapState.requestInFlight || !runtime?.sendMessage) {
        return bootstrapState.requestInFlight || Promise.resolve(null);
    }

    bootstrapState.requestInFlight = runtime.sendMessage({
        channel: 'ptk_content2background_runtime',
        type: 'content_bootstrap_hello',
        url: getCurrentHref(),
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
        return undefined;
    });
}

if (shouldSuppressSpaDialogs()) {
    injectDialogSuppressor();
}

shared.installEarlySastScriptCapture?.();
shared.installIastBridge?.();
shared.installSastContentMessageListener?.();
shared.installSpaUrlNotifier?.('content.js');

scheduleZapCallbackNotifications();
void requestRuntimeProfile();

}
