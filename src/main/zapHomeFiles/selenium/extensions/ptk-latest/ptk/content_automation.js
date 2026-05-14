/* Author: Denis Podgurskii */

if (!window.__PTK_CONTENT_AUTOMATION_LOADED__) {
window.__PTK_CONTENT_AUTOMATION_LOADED__ = true;

const runtime = (typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null);
const sharedIastBridgeActive = window.__PTK_SHARED_IAST_CONTENT_BRIDGE__ === true;
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

function sendRuntimeMessage(payload) {
    if (!runtime?.sendMessage) return Promise.resolve();
    try {
        return runtime.sendMessage(payload);
    } catch (_) {
        return Promise.resolve();
    }
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
        if (window.PTK_AUTOMATION) return;
        const src = runtimeGetURL('ptk/automationBridge.js');
        if (!src) return;
        const script = document.createElement('script');
        script.src = src;
        script.dataset.ptkVersion = version || 'unknown';
        script.dataset.ptkNonce = nonce || '';
        script.dataset.ptkAutomationEnabled = automationEnabledState ? '1' : '0';
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
    automationNonce = `ptk-zap-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

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

function collectSastInlineHandlers() {
    if (typeof document?.querySelectorAll !== 'function') return [];

    let elements = [];
    try {
        elements = Array.from(document.querySelectorAll(SAST_INLINE_HANDLER_SELECTOR));
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

function collectSastPayload() {
    const scripts = Array.from(document.scripts)
        .filter(isExecutableSastScriptElement)
        .map((script) => ({
            src: script.src || null,
            code: script.src ? null : script.innerText
        }))
        .filter((script) => {
            if (!script.src) return true;
            return isSameOriginSastScriptUrl(script.src);
        });

    return {
        scripts,
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
            const payload = collectSastPayload();
            sendRuntimeMessage({
                channel: 'ptk_content_sast2background_sast',
                type: 'scripts_collected',
                requestId: message.requestId || null,
                ...payload
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
        try {
            window.postMessage({
                channel: 'ptk_background_iast2content_modules',
                iastModules: message.iastModules
            }, '*');
        } catch (_) { }
        return Promise.resolve({ ok: true });
    }

    if (!sharedIastBridgeActive && message?.channel === 'ptk_background_iast2content_token_origin') {
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

    if (!sharedIastBridgeActive && data?.ptk_iast) {
        const type = data?.ptk_iast === 'runtime_signal' ? 'runtime_signal' : 'finding_report';
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type,
            finding: type === 'finding_report' ? data.finding : undefined,
            signal: type === 'runtime_signal' ? data.signal : undefined
        }).catch(() => { });
        return;
    }

    if (!sharedIastBridgeActive && data?.channel === 'ptk_iast_agent_ready') {
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'agent_ready'
        }).catch(() => { });
        return;
    }

    if (!sharedIastBridgeActive && data?.channel === 'ptk_iast_agent_failed') {
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'agent_failed',
            error: data?.error || null
        }).catch(() => { });
        return;
    }

    if (!sharedIastBridgeActive && data?.channel === 'ptk_iast_runtime_health') {
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'runtime_health',
            health: data?.health && typeof data.health === 'object' ? data.health : null
        }).catch(() => { });
        return;
    }

    if (!sharedIastBridgeActive && data?.channel === 'ptk_content_iast_request_modules') {
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
