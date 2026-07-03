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
const ZAP_CALLBACK_NOTIFY_RETRY_DELAYS_MS = [0, 100, 500, 1000, 2500, 5000, 9000, 10500, 11500, 11900];

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

const SAST_INLINE_HANDLER_ATTRIBUTES = Object.freeze([
    'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover', 'onmouseout',
    'onmousemove', 'onmouseenter', 'onmouseleave', 'onkeydown', 'onkeyup', 'onkeypress',
    'oninput', 'onchange', 'onfocus', 'onblur', 'onsubmit', 'onreset', 'onselect',
    'oncontextmenu', 'onwheel', 'ondrag', 'ondrop', 'onload', 'onunload', 'onabort',
    'onerror', 'onresize', 'onscroll'
]);
const SAST_INLINE_HANDLER_ATTRIBUTE_SET = new Set(SAST_INLINE_HANDLER_ATTRIBUTES);
const SAST_INLINE_HANDLER_SELECTOR = SAST_INLINE_HANDLER_ATTRIBUTES.map((attr) => `[${attr}]`).join(',');
const SAST_EARLY_SCRIPT_REGISTRY_KEY = '__PTK_SAST_EARLY_SCRIPT_REGISTRY__';
const SAST_EARLY_SCRIPT_KEYS_KEY = '__PTK_SAST_EARLY_SCRIPT_KEYS__';
const SAST_EARLY_SCRIPT_CAPTURE_INSTALLED_KEY = '__PTK_SAST_EARLY_SCRIPT_CAPTURE_INSTALLED__';
const SAST_EARLY_SCRIPT_MAX_ENTRIES = 250;
const SAST_EARLY_SCRIPT_MAX_CODE_CHARS = 512 * 1024;
const PTK_SPA_URL_NOTIFIER_KEY = '__PTK_SPA_URL_NOTIFIER_INSTALLED__';

function getPtkEarlySastScriptRegistry() {
    try {
        if (!Array.isArray(window[SAST_EARLY_SCRIPT_REGISTRY_KEY])) {
            window[SAST_EARLY_SCRIPT_REGISTRY_KEY] = [];
        }
        return window[SAST_EARLY_SCRIPT_REGISTRY_KEY];
    } catch (_) {
        return [];
    }
}

function getPtkEarlySastScriptKeySet() {
    try {
        if (!(window[SAST_EARLY_SCRIPT_KEYS_KEY] instanceof Set)) {
            window[SAST_EARLY_SCRIPT_KEYS_KEY] = new Set();
        }
        return window[SAST_EARLY_SCRIPT_KEYS_KEY];
    } catch (_) {
        return new Set();
    }
}

function normalizeSastScriptCode(value) {
    if (typeof value !== 'string') return '';
    return value.length > SAST_EARLY_SCRIPT_MAX_CODE_CHARS
        ? value.slice(0, SAST_EARLY_SCRIPT_MAX_CODE_CHARS)
        : value;
}

function normalizeSastScriptSrc(src) {
    if (!src) return null;
    try {
        return new URL(src, document.URL).href;
    } catch (_) {
        return String(src || '') || null;
    }
}

function makeSastScriptKey(script) {
    const src = normalizeSastScriptSrc(script?.src || null);
    if (src) return `src:${src}`;
    const code = normalizeSastScriptCode(script?.code || '');
    return code ? `inline:${code}` : '';
}

function rememberEarlySastScriptElement(scriptEl, reason = 'observer') {
    if (!isExecutableSastScriptElement(scriptEl)) return;
    const src = normalizeSastScriptSrc(scriptEl?.src || null);
    const code = src ? null : normalizeSastScriptCode(scriptEl?.textContent || scriptEl?.innerText || '');
    if (!src && !String(code || '').trim()) return;

    const key = src ? `src:${src}` : `inline:${code}`;
    if (!key) return;

    const seen = getPtkEarlySastScriptKeySet();
    if (seen.has(key)) return;

    const registry = getPtkEarlySastScriptRegistry();
    if (registry.length >= SAST_EARLY_SCRIPT_MAX_ENTRIES) return;

    seen.add(key);
    registry.push({
        src,
        code,
        capturedAt: Date.now(),
        captureUrl: getCurrentHref() || document.URL || '',
        reason
    });
}

function scanCurrentDocumentScriptsForSast(reason = 'scan') {
    try {
        Array.from(document.scripts || []).forEach((script) => rememberEarlySastScriptElement(script, reason));
    } catch (_) { }
}

function installEarlySastScriptCapture() {
    try {
        if (window[SAST_EARLY_SCRIPT_CAPTURE_INSTALLED_KEY] === true) return;
        window[SAST_EARLY_SCRIPT_CAPTURE_INSTALLED_KEY] = true;
    } catch (_) {
        return;
    }

    scanCurrentDocumentScriptsForSast('document_start');

    if (typeof MutationObserver === 'function') {
        try {
            const observer = new MutationObserver((mutations) => {
                for (const mutation of mutations || []) {
                    for (const node of Array.from(mutation?.addedNodes || [])) {
                        if (!node) continue;
                        if (String(node.nodeName || '').toLowerCase() === 'script') {
                            rememberEarlySastScriptElement(node, 'mutation');
                        }
                        if (typeof node.querySelectorAll === 'function') {
                            try {
                                Array.from(node.querySelectorAll('script')).forEach((script) => {
                                    rememberEarlySastScriptElement(script, 'mutation_descendant');
                                });
                            } catch (_) { }
                        }
                    }
                }
            });
            observer.observe(document, { childList: true, subtree: true });
        } catch (_) { }
    }

    [0, 25, 100, 250, 500, 1000, 2000].forEach((delay) => {
        try {
            setTimeout(() => scanCurrentDocumentScriptsForSast(`timer_${delay}`), delay);
        } catch (_) { }
    });
}

function normalizeSastInlineHandlerKey(value) {
    return String(value || '').trim().replace(/\s+/g, ' ').replace(/;+\s*$/g, '');
}

const SAST_JAVASCRIPT_URL_ATTRIBUTES = Object.freeze(['href', 'xlink:href', 'action', 'formaction', 'src', 'data']);
const SAST_JAVASCRIPT_URL_ATTRIBUTE_SET = new Set(SAST_JAVASCRIPT_URL_ATTRIBUTES);
const SAST_EXTERNAL_SCRIPT_MAX_COUNT = 24;
const SAST_EXTERNAL_SCRIPT_MAX_BYTES = 1024 * 1024;

function collectSastInlineHandlers() {
    if (typeof document?.querySelectorAll !== 'function') return [];

    let elements = [];
    try {
        const urlSelectors = ['[href]', '[xlink\\:href]', '[action]', '[formaction]', '[src]', '[data]'];
        elements = Array.from(document.querySelectorAll([SAST_INLINE_HANDLER_SELECTOR, ...urlSelectors].filter(Boolean).join(',')));
    } catch (_) {
        return [];
    }

    const snippets = [];
    const seen = new Set();
    for (const element of elements) {
        const attrNames = typeof element?.getAttributeNames === 'function'
            ? element.getAttributeNames()
            : Array.from(element?.attributes || [], (attr) => attr?.name).filter(Boolean);
        for (const rawName of attrNames) {
            const attrName = String(rawName || '').trim().toLowerCase();
            if (!SAST_INLINE_HANDLER_ATTRIBUTE_SET.has(attrName)) continue;
            const value = typeof element?.getAttribute === 'function'
                ? element.getAttribute(attrName)
                : null;
            if (typeof value !== 'string') continue;
            const key = normalizeSastInlineHandlerKey(value);
            if (!key || seen.has(key)) continue;
            seen.add(key);
            snippets.push(value);
        }
        for (const rawName of attrNames) {
            const attrName = String(rawName || '').trim().toLowerCase();
            if (!SAST_JAVASCRIPT_URL_ATTRIBUTE_SET.has(attrName)) continue;
            const value = typeof element?.getAttribute === 'function'
                ? element.getAttribute(attrName)
                : null;
            if (typeof value !== 'string' || !/^\s*javascript\s*:/i.test(value)) continue;
            const snippet = value.replace(/^\s*javascript\s*:/i, '').trim();
            const key = normalizeSastInlineHandlerKey(snippet);
            if (!key || seen.has(key)) continue;
            seen.add(key);
            snippets.push(snippet);
        }
    }
    return snippets;
}

function isExecutableSastScriptElement(scriptEl) {
    if (!scriptEl) return false;
    const rawType = String(scriptEl.type || '').trim().toLowerCase();
    if (!rawType || rawType === 'module') return true;
    return /^(?:text|application)\/(?:javascript|ecmascript|x-javascript|x-ecmascript)$/i.test(rawType);
}

function isSameOriginSastScriptUrl(src) {
    if (!src) return true;
    try {
        const scriptUrl = new URL(src, document.URL);
        const pageUrl = new URL(document.URL);
        return scriptUrl.protocol === 'http:' || scriptUrl.protocol === 'https:'
            ? scriptUrl.origin === pageUrl.origin
            : false;
    } catch (_) {
        return false;
    }
}

async function hydrateSameOriginSastScripts(scripts) {
    if (!Array.isArray(scripts) || typeof fetch !== 'function') return scripts;
    let fetched = 0;
    const hydrated = [];
    for (const script of scripts) {
        if (
            script?.src &&
            !String(script.code || '').trim() &&
            fetched < SAST_EXTERNAL_SCRIPT_MAX_COUNT &&
            isSameOriginSastScriptUrl(script.src)
        ) {
            fetched += 1;
            try {
                const response = await fetch(script.src, { credentials: 'include', cache: 'force-cache' });
                if (response?.ok) {
                    let text = await response.text();
                    if (text.length > SAST_EXTERNAL_SCRIPT_MAX_BYTES) {
                        text = text.slice(0, SAST_EXTERNAL_SCRIPT_MAX_BYTES);
                    }
                    hydrated.push({ ...script, code: normalizeSastScriptCode(text) });
                    continue;
                }
            } catch (_) { }
        }
        hydrated.push(script);
    }
    return hydrated;
}

async function collectSastPayload() {
    scanCurrentDocumentScriptsForSast('collect');

    const currentScripts = Array.from(document.scripts || [])
        .filter(isExecutableSastScriptElement)
        .map((script) => ({
            src: normalizeSastScriptSrc(script.src || null),
            code: script.src ? null : normalizeSastScriptCode(script.innerText || script.textContent || '')
        }))
        .filter((script) => !script.src || isSameOriginSastScriptUrl(script.src));

    const scripts = [];
    const seen = new Set();
    const addScript = (script) => {
        if (!script || (script.src && !isSameOriginSastScriptUrl(script.src))) return;
        const src = normalizeSastScriptSrc(script.src || null);
        const code = src && typeof script.code === 'string'
            ? normalizeSastScriptCode(script.code)
            : (src ? null : normalizeSastScriptCode(script.code || ''));
        const normalized = {
            src,
            code
        };
        if (!normalized.src && !String(normalized.code || '').trim()) return;
        const key = makeSastScriptKey(normalized);
        if (!key || seen.has(key)) return;
        seen.add(key);
        scripts.push(normalized);
    };

    currentScripts.forEach(addScript);
    getPtkEarlySastScriptRegistry().forEach(addScript);

    return {
        scripts: await hydrateSameOriginSastScripts(scripts),
        html: collectSastInlineHandlers(),
        file: document.URL
    };
}

function isHttpTopFrameUrl(href) {
    if (!isTopFrame() || typeof href !== 'string' || !href) return false;
    try {
        const parsed = new URL(href);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

function installPtkSpaUrlNotifier(sourceScript = 'content.js') {
    if (!isTopFrame()) return false;
    if (window[PTK_SPA_URL_NOTIFIER_KEY]) return false;
    window[PTK_SPA_URL_NOTIFIER_KEY] = sourceScript;

    let lastHref = null;
    const notify = (reason = 'unknown') => {
        const href = getCurrentHref();
        if (!isHttpTopFrameUrl(href) || isZapCallbackPageUrl(href)) return;
        if (href === lastHref) return;
        const previousHref = lastHref;
        lastHref = href;
        const diagnostic = {
            phase: 'content.notify',
            sourceScript,
            reason,
            url: href,
            previousUrl: previousHref || null,
            readyState: document.readyState || null,
            visibilityState: document.visibilityState || null,
            hasHash: href.includes('#'),
            hasHashQuery: /#.*\?/.test(href),
            sentAt: Date.now()
        };
        sendRuntimeMessage({
            channel: 'ptk_content2rattacker',
            type: 'spa_url_changed',
            url: href,
            diagnostic
        }).catch(() => { });
        collectSastPayload().then((sastPayload) => {
            sendRuntimeMessage({
                channel: 'ptk_content_sast2background_sast',
                type: 'spa_url_changed',
                url: href,
                diagnostic,
                sastPayload
            }).catch(() => { });
        }).catch(() => { });
    };

    const wrapHistory = (fn) => {
        // Use Proxy so history.pushState.toString() still returns "[native code]".
        // Sites with anti-bot/integrity checks (e.g. Akamai) verify the native
        // signature and abort login flows when they see a plain wrapper function.
        if (typeof Proxy === 'function' && typeof Reflect !== 'undefined') {
            return new Proxy(fn, {
                apply(target, thisArg, args) {
                    const ret = Reflect.apply(target, thisArg, args);
                    notify(`history.${target?.name || 'state'}`);
                    return ret;
                }
            });
        }
        // Fallback for environments without Proxy: preserve toString manually.
        const wrapper = function () {
            const ret = fn.apply(this, arguments);
            notify(`history.${fn?.name || 'state'}`);
            return ret;
        };
        try {
            Object.defineProperty(wrapper, 'toString', {
                value: fn.toString.bind(fn),
                writable: true,
                configurable: true
            });
        } catch (_) {}
        return wrapper;
    };

    try {
        history.pushState = wrapHistory(history.pushState);
        history.replaceState = wrapHistory(history.replaceState);
    } catch (_) { }

    window.addEventListener('hashchange', () => notify('hashchange'), false);
    window.addEventListener('popstate', () => notify('popstate'), false);
    setInterval(() => notify('poll'), 500);
    setTimeout(() => notify('initial'), 0);
    return true;
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

function installSharedIastBridge() {
    if (window.__PTK_SHARED_IAST_CONTENT_BRIDGE__ === true) {
        return;
    }
    window.__PTK_SHARED_IAST_CONTENT_BRIDGE__ = true;
    const PTK_IAST_PAGE_TO_CONTENT_EVENT = 'ptk:iast:page-to-content:v1';
    const PTK_IAST_CONTENT_TO_PAGE_EVENT = 'ptk:iast:content-to-page:v1';

    function parseIastBridgeEventDetail(detail) {
        if (!detail) return null;
        if (typeof detail === 'object') return detail;
        if (typeof detail !== 'string') return null;
        try {
            const parsed = JSON.parse(detail);
            return parsed && typeof parsed === 'object' ? parsed : null;
        } catch (_) {
            return null;
        }
    }

    function dispatchIastBridgeToPage(payload) {
        if (!payload || typeof payload !== 'object') return;
        try {
            window.dispatchEvent(new CustomEvent(PTK_IAST_CONTENT_TO_PAGE_EVENT, {
                detail: JSON.stringify(payload)
            }));
        } catch (_) { }
    }

    function handleIastPageBridgePayload(data) {
        data = data || {};

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
                dispatchIastBridgeToPage({
                    channel: 'ptk_background_iast2content_modules',
                    active: resp?.active !== false,
                    reason: resp?.reason || null,
                    iastModules: resp?.iastModules || null,
                    iastModulesSignature: resp?.iastModulesSignature || null,
                    scanStrategy: resp?.scanStrategy || null
                });
            }).catch(() => {
                dispatchIastBridgeToPage({
                    channel: 'ptk_background_iast2content_modules',
                    active: true,
                    iastModules: null
                });
            });
        }
    }

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
                dispatchIastBridgeToPage({
                    channel: 'ptk_background_iast2content_modules',
                    active: message.active !== false,
                    reason: message.reason || null,
                    iastModules: message.iastModules,
                    iastModulesSignature: message.iastModulesSignature || null,
                    scanStrategy: message.scanStrategy || null
                });
                return Promise.resolve({ ok: true });
            }

            if (message?.channel === 'ptk_background_iast2content_token_origin') {
                dispatchIastBridgeToPage({
                    channel: 'ptk_background_iast2content_token_origin',
                    tokens: Array.isArray(message.tokens) ? message.tokens : []
                });
                return Promise.resolve({ ok: true });
            }

            return undefined;
        });
    }

    window.addEventListener(PTK_IAST_PAGE_TO_CONTENT_EVENT, (event) => {
        handleIastPageBridgePayload(parseIastBridgeEventDetail(event?.detail));
    }, false);

    window.addEventListener('message', (event) => {
        handleIastPageBridgePayload(event.data || {});
    }, false);
}

function requestRuntimeProfile(reason = 'document_start') {
    if (bootstrapState.requestInFlight || !runtime?.sendMessage) {
        return bootstrapState.requestInFlight || Promise.resolve(null);
    }

    const href = getCurrentHref();

    bootstrapState.requestInFlight = runtime.sendMessage({
        channel: 'ptk_content2background_runtime',
        type: 'content_bootstrap_hello',
        url: href,
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
        if (message?.channel === 'ptk_background2content_sast') {
            if (message.type === 'collect_scripts') {
                collectSastPayload().then((payload) => {
                    sendRuntimeMessage({
                        channel: 'ptk_content_sast2background_sast',
                        type: 'scripts_collected',
                        requestId: message.requestId || null,
                        ...payload
                    }).catch(() => { });
                }).catch(() => { });
                return Promise.resolve({ ok: true });
            }

            if (message.type === 'sast_set_hash') {
                const targetHash = typeof message.hash === 'string' ? message.hash : '';
                if (window.location.hash !== targetHash) {
                    window.location.hash = targetHash;
                }
                return Promise.resolve({ ok: true, url: document.URL });
            }

            if (message.type === 'sast_wait_ready') {
                const delayMs = Number(message.delayMs || 300);
                const waitReady = () => new Promise((resolve) => {
                    if (document.readyState === 'complete') return resolve();
                    const onReady = () => {
                        window.removeEventListener('load', onReady);
                        resolve();
                    };
                    window.addEventListener('load', onReady);
                });
                return waitReady()
                    .then(() => new Promise((resolve) => setTimeout(resolve, delayMs)))
                    .then(() => ({ ok: true, url: document.URL }));
            }
        }

        if (message?.channel === 'ptk_background2content_runtime' && message?.type === 'refresh_profile') {
            void requestRuntimeProfile('background_refresh');
        }
    });
}

installEarlySastScriptCapture();
installSharedIastBridge();
installPtkSpaUrlNotifier('content.js');

scheduleZapCallbackNotifications();
void requestRuntimeProfile();

}
