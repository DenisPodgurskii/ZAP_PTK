/* Author: Denis Podgurskii */

if (!window.__PTK_CONTENT_AUTOMATION_LOADED__) {
window.__PTK_CONTENT_AUTOMATION_LOADED__ = true;

const runtime = (typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null);
const sharedIastBridgeActive = window.__PTK_SHARED_IAST_CONTENT_BRIDGE__ === true;

function sendRuntimeMessage(payload) {
    if (!runtime?.sendMessage) return Promise.resolve();
    try {
        return runtime.sendMessage(payload);
    } catch (_) {
        return Promise.resolve();
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

function collectSastPayload() {
    const scripts = Array.from(document.scripts)
        .filter(isExecutableSastScriptElement)
        .map((script) => ({
            src: script.src || null,
            code: script.src ? null : script.innerText
        }))
        .filter((script) => {
            if (!script.src) return true;
            return /^https?:\/\//i.test(script.src);
        });

    return {
        scripts,
        html: collectSastInlineHandlers(),
        file: document.URL
    };
}

if (runtime?.onMessage) runtime.onMessage.addListener(function (message) {
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
