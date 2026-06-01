/* Author: Denis Podgurskii */

if (!window.__PTK_CONTENT_AUTOMATION_LOADED__) {
window.__PTK_CONTENT_AUTOMATION_LOADED__ = true;

const runtime = (typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null);
const sharedIastBridgeActive = window.__PTK_SHARED_IAST_CONTENT_BRIDGE__ === true;
const PTK_IAST_PAGE_TO_CONTENT_EVENT = 'ptk:iast:page-to-content:v1';
const PTK_IAST_CONTENT_TO_PAGE_EVENT = 'ptk:iast:content-to-page:v1';
const PTK_AGENT_AUTOMATION_SCRIPT_ID = 'ptk-agent-automation-layer';
const ptkAutomationVersion = (() => {
    try {
        const manifest = runtime?.getManifest ? runtime.getManifest() : null;
        return manifest?.version || 'unknown';
    } catch (_) {
        return 'unknown';
    }
})();
let automationNonce = null;
let automationMessageHandlerInstalled = false;
let zapAutomationKeepaliveTimer = null;

function sendRuntimeMessage(payload) {
    if (!runtime?.sendMessage) return Promise.resolve();
    try {
        return runtime.sendMessage(payload);
    } catch (_) {
        return Promise.resolve();
    }
}

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
        return true;
    }

    if (data?.channel === 'ptk_iast_agent_ready') {
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'agent_ready'
        }).catch(() => { });
        return true;
    }

    if (data?.channel === 'ptk_iast_agent_failed') {
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'agent_failed',
            error: data?.error || null
        }).catch(() => { });
        return true;
    }

    if (data?.channel === 'ptk_iast_runtime_health') {
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'runtime_health',
            health: data?.health && typeof data.health === 'object' ? data.health : null
        }).catch(() => { });
        return true;
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
        return true;
    }

    return false;
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

function installSastRoutePayloadNotifier() {
    if (window.__PTK_SAST_ROUTE_PAYLOAD_NOTIFIER__ === true) return;
    window.__PTK_SAST_ROUTE_PAYLOAD_NOTIFIER__ = true;
    if (!isTopFrame()) return;

    let lastHref = null;
    const notify = (reason = 'route_change') => {
        const href = getCurrentHref();
        if (!href || href === lastHref) return;
        lastHref = href;
        collectSastPayload().then((sastPayload) => {
            sendRuntimeMessage({
                channel: 'ptk_content_sast2background_sast',
                type: 'spa_url_changed',
                url: href,
                reason,
                sastPayload
            }).catch(() => { });
        }).catch(() => { });
    };

    const wrapHistory = (fn) => function () {
        const result = fn.apply(this, arguments);
        notify('history');
        return result;
    };

    try {
        history.pushState = wrapHistory(history.pushState);
        history.replaceState = wrapHistory(history.replaceState);
    } catch (_) { }

    window.addEventListener('hashchange', () => notify('hashchange'), false);
    window.addEventListener('popstate', () => notify('popstate'), false);
    setInterval(() => notify('poll'), 500);
    notify('initial');
}

function runtimeGetURL(path) {
    if (!runtime?.getURL) return null;
    try {
        return runtime.getURL(path);
    } catch (_) {
        return null;
    }
}

function normalizeAutomationBridgeResponse(type, response) {
    const isSuccessfulResponse = response && response.ok !== false && response.success !== false;
    if (type === 'export-scan-chunk' && isSuccessfulResponse) {
        if (response.chunk instanceof Uint8Array) {
            return response;
        }

        const serializedChunk = response.chunk;
        if (Array.isArray(serializedChunk)) {
            return {
                ...response,
                chunk: Uint8Array.from(serializedChunk)
            };
        }

        if (serializedChunk && typeof serializedChunk === 'object') {
            const byteKeys = Object.keys(serializedChunk)
                .filter((key) => /^\d+$/.test(key))
                .sort((left, right) => Number(left) - Number(right));

            if (byteKeys.length) {
                return {
                    ...response,
                    chunk: Uint8Array.from(byteKeys.map((key) => serializedChunk[key]))
                };
            }
        }
    }

    return response;
}

function installPtkAutomationBridge(version, nonce, automationEnabledState) {
    try {
        const existingBridge = window.PTK_AUTOMATION?.bridgeId === 'ptk-automation-bridge'
            ? window.PTK_AUTOMATION
            : null;
        if (existingBridge && !(automationEnabledState === true && existingBridge._automationEnabled === false)) return;
        const src = runtimeGetURL('ptk/automationBridge.js');
        if (!src) return;
        const script = document.createElement('script');
        script.async = false;
        script.src = src;
        script.dataset.ptkVersion = version || 'unknown';
        script.dataset.ptkNonce = nonce || '';
        script.dataset.ptkAutomationEnabled = automationEnabledState ? '1' : '0';
        try {
            script.dataset.ptkExtensionOrigin = new URL(src).origin;
        } catch (_) { }
        if (automationEnabledState === true) {
            script.onload = () => injectPtkAgentAutomationLayer();
        }
        const parent = document.documentElement || document.head || document.body;
        if (parent) {
            parent.appendChild(script);
        }
    } catch (_) { }
}

function injectPtkAgentAutomationLayer() {
    try {
        if (window.PTK_AGENT) return;
        if (document.getElementById(PTK_AGENT_AUTOMATION_SCRIPT_ID)) return;
        const src = runtimeGetURL('ptk/ptkAgentAutomation.js');
        if (!src) return;
        const script = document.createElement('script');
        script.id = PTK_AGENT_AUTOMATION_SCRIPT_ID;
        script.async = false;
        script.src = src;
        script.onload = () => script.remove();
        script.onerror = () => script.remove();
        const parent = document.documentElement || document.head || document.body;
        if (parent) {
            parent.appendChild(script);
        }
    } catch (_) { }
}

function notifyAutomationStatus(enabled, nonce) {
    try {
        window.postMessage({
            source: 'ptk-extension',
            type: 'automation-status',
            enabled: enabled === true,
            nonce: nonce || ''
        }, '*');
    } catch (_) { }
}

function handleAutomationBridgeMessage(data) {
    const validTypes = [
        'session-start',
        'session-end',
        'get-stats',
        'get-findings',
        'get-analysis-snapshot',
        'export-scan',
        'get-session-progress',
        'export-scan-chunk',
        'release-export-scan'
    ];
    if (!validTypes.includes(data.type)) return;

    const payload = {
        channel: 'ptk_content2background_automation',
        type: data.type,
        sessionId: data.sessionId,
        options: data.options || {},
        includeFindings: data.includeFindings === true,
        limit: data.limit,
        wait: data.wait,
        pageUrl: window.location.href,
        requestId: data.requestId
    };

    sendRuntimeMessage(payload).then((response) => {
        const normalizedResponse = normalizeAutomationBridgeResponse(data.type, response);
        window.postMessage({
            source: 'ptk-extension',
            nonce: automationNonce,
            requestId: data.requestId,
            ...normalizedResponse
        }, '*');
    }).catch((error) => {
        window.postMessage({
            source: 'ptk-extension',
            nonce: automationNonce,
            requestId: data.requestId,
            error: error?.message || 'PTK automation error'
        }, '*');
    });
}

function enableZapAutomationBridge() {
    if (automationMessageHandlerInstalled) return;
    automationMessageHandlerInstalled = true;
    window.__PTK_CONTENT_AUTOMATION_ACTIVE__ = true;
    automationNonce = `ptk-zap-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

    // The nonce is exposed to the WebDriver-controlled page as a correlation
    // guard, not a secret. Browser-close safety is trusted only when it flows
    // through ZAP's callback/zapid handling and the background confirms session
    // progress for this tab.
    let nonceEl = document.getElementById('__ptk_automation_nonce__');
    if (!nonceEl) {
        nonceEl = document.createElement('div');
        nonceEl.id = '__ptk_automation_nonce__';
        nonceEl.style.display = 'none';
        const parent = document.documentElement || document.body;
        if (parent) parent.appendChild(nonceEl);
    }
    if (nonceEl) {
        nonceEl.dataset.nonce = automationNonce;
        nonceEl.dataset.automationEnabled = '1';
        nonceEl.dataset.automationRuntime = 'zap';
    }

    installPtkAutomationBridge(ptkAutomationVersion, automationNonce, true);
    notifyAutomationStatus(true, automationNonce);
    [50, 250, 1000].forEach((delayMs) => {
        try {
            setTimeout(() => notifyAutomationStatus(true, automationNonce), delayMs);
        } catch (_) { }
    });

    window.addEventListener('message', (event) => {
        if (event.source !== window) return;
        const data = event.data;
        if (data?.source !== 'ptk-automation') return;
        if (data.nonce !== automationNonce) return;
        handleAutomationBridgeMessage(data);
    });

    if (!zapAutomationKeepaliveTimer) {
        const notifyBackgroundAlive = () => {
            sendRuntimeMessage({
                channel: 'ptk_content2background_automation',
                type: 'zap-keepalive',
                options: {
                    source: 'zap_keepalive'
                },
                pageUrl: getCurrentHref()
            }).catch(() => { });
        };
        try {
            zapAutomationKeepaliveTimer = setInterval(notifyBackgroundAlive, 15000);
            setTimeout(notifyBackgroundAlive, 5000);
        } catch (_) { }
    }
}

enableZapAutomationBridge();

const SAST_INLINE_HANDLER_ATTRIBUTES = Object.freeze([
    'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover', 'onmouseout',
    'onmousemove', 'onmouseenter', 'onmouseleave', 'onkeydown', 'onkeyup', 'onkeypress',
    'oninput', 'onchange', 'onfocus', 'onblur', 'onsubmit', 'onreset', 'onselect',
    'oncontextmenu', 'onwheel', 'ondrag', 'ondrop', 'onload', 'onunload', 'onabort',
    'onerror', 'onresize', 'onscroll'
]);

const SAST_INLINE_HANDLER_ATTRIBUTE_SET = new Set(SAST_INLINE_HANDLER_ATTRIBUTES);
const SAST_INLINE_HANDLER_SELECTOR = SAST_INLINE_HANDLER_ATTRIBUTES.map((attr) => `[${attr}]`).join(',');

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
    if (!rawType) return true;
    if (rawType === 'module') return true;
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

function normalizeSastScriptCode(value) {
    if (typeof value !== 'string') return '';
    const maxCodeChars = 512 * 1024;
    return value.length > maxCodeChars ? value.slice(0, maxCodeChars) : value;
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

const SAST_EARLY_SCRIPT_REGISTRY_KEY = '__PTK_SAST_EARLY_SCRIPT_REGISTRY__';
const SAST_EARLY_SCRIPT_KEYS_KEY = '__PTK_SAST_EARLY_SCRIPT_KEYS__';
const SAST_EARLY_SCRIPT_CAPTURE_INSTALLED_KEY = '__PTK_SAST_EARLY_SCRIPT_CAPTURE_INSTALLED__';
const SAST_EARLY_SCRIPT_MAX_ENTRIES = 250;

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

function getPtkEarlySastScriptKeys() {
    try {
        if (!(window[SAST_EARLY_SCRIPT_KEYS_KEY] instanceof Set)) {
            window[SAST_EARLY_SCRIPT_KEYS_KEY] = new Set();
        }
        return window[SAST_EARLY_SCRIPT_KEYS_KEY];
    } catch (_) {
        return new Set();
    }
}

function rememberEarlySastScriptElement(scriptEl, reason = 'observer') {
    if (!isExecutableSastScriptElement(scriptEl)) return;
    const src = normalizeSastScriptSrc(scriptEl?.src || null);
    const code = src ? null : normalizeSastScriptCode(scriptEl?.textContent || scriptEl?.innerText || '');
    const entry = { src, code, reason, capturedAt: Date.now() };
    const key = makeSastScriptKey(entry);
    if (!key) return;

    const keys = getPtkEarlySastScriptKeys();
    if (keys.has(key)) return;
    const registry = getPtkEarlySastScriptRegistry();
    if (registry.length >= SAST_EARLY_SCRIPT_MAX_ENTRIES) return;
    keys.add(key);
    registry.push(entry);
}

function rememberExistingSastScripts(reason = 'initial') {
    try {
        Array.from(document.scripts || []).forEach((script) => rememberEarlySastScriptElement(script, reason));
    } catch (_) { }
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
                    const text = await response.text();
                    const code = normalizeSastScriptCode(text);
                    if (text.length > SAST_EXTERNAL_SCRIPT_MAX_BYTES || code.length < text.length) {
                        hydrated.push({
                            ...script,
                            code: null,
                            truncated: true,
                            originalLength: text.length,
                            truncationLimit: Math.min(SAST_EXTERNAL_SCRIPT_MAX_BYTES, code.length || SAST_EXTERNAL_SCRIPT_MAX_BYTES)
                        });
                        continue;
                    }
                    hydrated.push({ ...script, code });
                    continue;
                }
            } catch (_) { }
        }
        hydrated.push(script);
    }
    return hydrated;
}

function installEarlySastScriptCapture() {
    try {
        if (window[SAST_EARLY_SCRIPT_CAPTURE_INSTALLED_KEY] === true) return;
        window[SAST_EARLY_SCRIPT_CAPTURE_INSTALLED_KEY] = true;
    } catch (_) {
        return;
    }

    rememberExistingSastScripts('initial');

    if (typeof MutationObserver === 'function') {
        try {
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    Array.from(mutation.addedNodes || []).forEach((node) => {
                        if (!node || node.nodeType !== 1) return;
                        if (String(node.nodeName || '').toLowerCase() === 'script') {
                            rememberEarlySastScriptElement(node, 'mutation');
                            return;
                        }
                        if (typeof node.querySelectorAll === 'function') {
                            Array.from(node.querySelectorAll('script')).forEach((script) => {
                                rememberEarlySastScriptElement(script, 'mutation_descendant');
                            });
                        }
                    });
                });
            });
            observer.observe(document.documentElement || document, { childList: true, subtree: true });
        } catch (_) { }
    }

    document.addEventListener('DOMContentLoaded', () => rememberExistingSastScripts('domcontentloaded'), { once: true });
    window.addEventListener('load', () => rememberExistingSastScripts('load'), { once: true });
}

async function collectSastPayload() {
    const currentScripts = Array.from(document.scripts)
        .filter(isExecutableSastScriptElement)
        .map((script) => ({
            src: normalizeSastScriptSrc(script.src || null),
            code: script.src ? null : normalizeSastScriptCode(script.innerText || script.textContent || '')
        }))
        .filter((script) => {
            if (!script.src) return true;
            return isSameOriginSastScriptUrl(script.src);
        });

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

if (runtime?.onMessage) runtime.onMessage.addListener(function (message) {
    if (message?.channel === 'ptk_background2content_automation' && message?.payload) {
        try {
            window.postMessage(message.payload, '*');
        } catch (_) { }
        return Promise.resolve({ ok: true });
    }

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

    if (!sharedIastBridgeActive && message?.channel === 'ptk_background_iast2content') {
        if (message.type === 'clean iast result') {
            localStorage.removeItem('ptk_iast_buffer');
        }
        if (message.type === 'ping') {
            return Promise.resolve({ ok: true });
        }
    }

    if (!sharedIastBridgeActive && message?.channel === 'ptk_background_iast2content_modules' && message.iastModules) {
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

    if (!sharedIastBridgeActive && message?.channel === 'ptk_background_iast2content_token_origin') {
        dispatchIastBridgeToPage({
            channel: 'ptk_background_iast2content_token_origin',
            tokens: Array.isArray(message.tokens) ? message.tokens : []
        });
        return Promise.resolve({ ok: true });
    }

    return undefined;
});

window.addEventListener(PTK_IAST_PAGE_TO_CONTENT_EVENT, (event) => {
    if (sharedIastBridgeActive) return;
    handleIastPageBridgePayload(parseIastBridgeEventDetail(event?.detail));
}, false);

window.addEventListener('message', (event) => {
    const data = event.data || {};

    if (data?.ptk_ws) {
        sendRuntimeMessage({
            channel: 'ptk_contentws2rattacker',
            type: data.kind,
            payload: data.payload
        }).catch(() => { });
        return;
    }

    if (data?.ptk) {
        sendRuntimeMessage({
            channel: 'ptk_content2rattacker',
            type: 'xss_confirmed',
            data: {
                attackValue: data,
                origin: event.origin,
                location: window.location?.toString?.() || ''
            }
        }).catch(() => { });
        return;
    }

    if (!sharedIastBridgeActive && handleIastPageBridgePayload(data)) {
        return;
    }
}, false);

installEarlySastScriptCapture();
installSastRoutePayloadNotifier();

}
