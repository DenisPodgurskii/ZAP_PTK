/* Author: Denis Podgurskii */

if (window.__PTK_CONTENT_SHARED_LOADED__) {
    window.PTK_CONTENT_SHARED?.rebindIastBridge?.();
} else {
window.__PTK_CONTENT_SHARED_LOADED__ = true;

const runtime = (typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null);

const ZAP_CALLBACK_PATH_REGEX = /^\/zapCallBackUrl\/[^/?#]+/i;
const SAST_INLINE_HANDLER_ATTRIBUTES = Object.freeze([
    'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover', 'onmouseout',
    'onmousemove', 'onmouseenter', 'onmouseleave', 'onkeydown', 'onkeyup', 'onkeypress',
    'oninput', 'onchange', 'onfocus', 'onblur', 'onsubmit', 'onreset', 'onselect',
    'oncontextmenu', 'onwheel', 'ondrag', 'ondrop', 'onload', 'onunload', 'onabort',
    'onerror', 'onresize', 'onscroll'
]);
const SAST_INLINE_HANDLER_ATTRIBUTE_SET = new Set(SAST_INLINE_HANDLER_ATTRIBUTES);
const SAST_INLINE_HANDLER_SELECTOR = SAST_INLINE_HANDLER_ATTRIBUTES.map((attr) => `[${attr}]`).join(',');
const SAST_JAVASCRIPT_URL_ATTRIBUTES = Object.freeze(['href', 'xlink:href', 'action', 'formaction', 'src', 'data']);
const SAST_JAVASCRIPT_URL_ATTRIBUTE_SET = new Set(SAST_JAVASCRIPT_URL_ATTRIBUTES);
const SAST_EXTERNAL_SCRIPT_MAX_COUNT = 24;
const SAST_EXTERNAL_SCRIPT_MAX_BYTES = 1024 * 1024;
const SAST_EARLY_SCRIPT_REGISTRY_KEY = '__PTK_SAST_EARLY_SCRIPT_REGISTRY__';
const SAST_EARLY_SCRIPT_KEYS_KEY = '__PTK_SAST_EARLY_SCRIPT_KEYS__';
const SAST_EARLY_SCRIPT_CAPTURE_INSTALLED_KEY = '__PTK_SAST_EARLY_SCRIPT_CAPTURE_INSTALLED__';
const SAST_EARLY_SCRIPT_MAX_ENTRIES = 250;
const SAST_EARLY_SCRIPT_MAX_CODE_CHARS = 512 * 1024;
const PTK_SPA_URL_NOTIFIER_KEY = '__PTK_SPA_URL_NOTIFIER_INSTALLED__';
const PTK_SAST_MESSAGE_LISTENER_KEY = '__PTK_SAST_CONTENT_MESSAGE_LISTENER_INSTALLED__';
let sastContentProducer = null;
let sastDiscoveryRevisionFloor = -1;
const PTK_SCA_MESSAGE_LISTENER_KEY = '__PTK_SCA_CONTENT_MESSAGE_LISTENER_INSTALLED__';
const PTK_DAST_USER_INTERACTION_HOOKED_KEY = '__PTK_DAST_USER_INTERACTION_HOOKED__';
const PTK_DAST_USER_INTERACTION_SENT_KEY = '__PTK_DAST_USER_INTERACTION_SENT__';
const PTK_IAST_PAGE_TO_CONTENT_EVENT = 'ptk:iast:page-to-content:v1';
const PTK_IAST_CONTENT_TO_PAGE_EVENT = 'ptk:iast:content-to-page:v1';
// Correlation belongs to this isolated document. It is never a page grant or
// authorization token; the receiver still validates the runtime sender owner.
const iastDocumentGeneration = typeof globalThis.crypto?.randomUUID === 'function'
    ? globalThis.crypto.randomUUID()
    : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
let iastObservationState = null;
let iastBridgeDeliveryState = { pending: 0, failed: false, stopped: false, settlement: null, resolve: null };

function sendIastRuntimeMessage(payload, afterDelivery = null) {
    // A counter/one waiter, not another finding queue or unbounded history.
    const collection = iastBridgeDeliveryState;
    const tracked = collection.pending < 1000000;
    if (tracked) collection.pending += 1;
    else collection.failed = true;
    let delivery;
    try {
        if (!runtime?.sendMessage) throw new Error('iast_runtime_unavailable');
        delivery = runtime.sendMessage(payload);
    } catch (error) { delivery = Promise.reject(error); }
    return Promise.resolve(delivery).then(async response => {
        if (response?.ok === false) collection.failed = true;
        if (afterDelivery) {
            if (collection !== iastBridgeDeliveryState) collection.failed = true;
            else await afterDelivery(response);
        }
        return response;
    }).catch(error => {
        collection.failed = true;
        throw error;
    }).finally(() => {
        if (tracked) collection.pending -= 1;
        if (collection.pending === 0 && collection.resolve) {
            const resolve = collection.resolve;
            collection.resolve = null;
            collection.settlement = null;
            resolve();
        }
    });
}

function settleIastBridgeDeliveries(collection) {
    if (!collection.pending) return Promise.resolve();
    if (!collection.settlement) collection.settlement = new Promise(resolve => { collection.resolve = resolve; });
    return collection.settlement;
}

function runtimeGetURL(path) {
    if (!runtime?.getURL) return null;
    try {
        return runtime.getURL(path);
    } catch (_) {
        return null;
    }
}

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

function buildIastBridgeContext() {
    return {
        url: getCurrentHref(),
        topFrame: isTopFrame(),
        documentGeneration: iastDocumentGeneration
    };
}

function collectScaResources() {
    const urls = new Set();
    const pushUrl = (value) => {
        const next = String(value || '').trim();
        if (!/^https?:\/\//i.test(next)) return;
        urls.add(next);
    };

    try {
        Array.from(document.scripts || []).forEach((script) => pushUrl(script?.src));
    } catch (_) { }

    try {
        Array.from(document.querySelectorAll('link[href]')).forEach((link) => pushUrl(link?.href));
    } catch (_) { }

    try {
        const entries = performance?.getEntriesByType ? performance.getEntriesByType('resource') : [];
        Array.from(entries || []).forEach((entry) => pushUrl(entry?.name));
    } catch (_) { }

    try {
        pushUrl(document.URL);
    } catch (_) { }

    return { resources: Array.from(urls) };
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

function isHttpTopFrameUrl(href) {
    if (!isTopFrame() || typeof href !== 'string' || !href) return false;
    try {
        const parsed = new URL(href);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

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
    const kind = script?.scriptKind || 'classic';
    const src = normalizeSastScriptSrc(script?.src || null);
    if (src) return `${kind}:src:${src}`;
    const code = normalizeSastScriptCode(script?.code || '');
    return code ? `${kind}:inline:${code}` : '';
}

function isExecutableSastScriptElement(scriptEl) {
    if (!scriptEl) return false;
    const rawType = String(scriptEl.type || '').trim().toLowerCase();
    if (!rawType || rawType === 'module') return true;
    return /^(?:text|application)\/(?:javascript|ecmascript|x-javascript|x-ecmascript)$/i.test(rawType);
}

function rememberEarlySastScriptElement(scriptEl, reason = 'observer') {
    if (!isExecutableSastScriptElement(scriptEl)) return;
    const src = normalizeSastScriptSrc(scriptEl?.src || null);
    const code = src ? null : normalizeSastScriptCode(scriptEl?.textContent || scriptEl?.innerText || '');
    if (!src && !String(code || '').trim()) return;

    const scriptKind = String(scriptEl.type || '').trim().toLowerCase() === 'module' ? 'module' : 'classic';
    const key = makeSastScriptKey({ src, code, scriptKind });
    if (!key) return;

    const seen = getPtkEarlySastScriptKeySet();
    if (seen.has(key)) return;

    const registry = getPtkEarlySastScriptRegistry();
    if (registry.length >= SAST_EARLY_SCRIPT_MAX_ENTRIES) return;

    seen.add(key);
    registry.push({
        src,
        code,
        scriptKind,
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
    // Observation is scan-authorized, not a provisional buffer on every page.
    // The shared entry points may call this before a SAST state exists.
    return sastContentProducer?.active === true;
}

function normalizeSastInlineHandlerKey(value) {
    return String(value || '').trim().replace(/\s+/g, ' ').replace(/;+\s*$/g, '');
}

function collectSastInlineHandlers(extraNodes = [], onlyExtra = false) {
    if (typeof document?.querySelectorAll !== 'function') return [];

    let elements = [];
    try {
        const urlSelectors = ['[href]', '[xlink\\:href]', '[action]', '[formaction]', '[src]', '[data]'];
        if (!onlyExtra) elements = Array.from(document.querySelectorAll([SAST_INLINE_HANDLER_SELECTOR, ...urlSelectors].filter(Boolean).join(',')));
        for (const node of extraNodes) {
            if (!node) continue;
            elements.push(node);
            if (typeof node.querySelectorAll === 'function') elements.push(...node.querySelectorAll('*'));
        }
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

function hydrateSameOriginSastScripts(scripts) {
    // Kept as an inert compatibility helper; only the background native capture
    // lease may supply external source bodies, never this authenticated page.
    return scripts;
}

function collectSastPayload(extraHtml = []) {
    scanCurrentDocumentScriptsForSast('collect');

    const currentScripts = Array.from(document.scripts || [])
        .filter(isExecutableSastScriptElement)
        .map((script) => ({
            src: normalizeSastScriptSrc(script.src || null),
            scriptKind: String(script.type || '').trim().toLowerCase() === 'module' ? 'module' : 'classic',
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
        const normalized = { src, code, scriptKind: script.scriptKind === 'module' ? 'module' : 'classic' };
        if (!normalized.src && !String(normalized.code || '').trim()) return;
        const key = makeSastScriptKey(normalized);
        if (!key || seen.has(key)) return;
        seen.add(key);
        scripts.push(normalized);
    };

    currentScripts.forEach(addScript);
    getPtkEarlySastScriptRegistry().forEach(addScript);

    return {
        scripts: hydrateSameOriginSastScripts(scripts),
        html: [...new Set([...collectSastInlineHandlers(), ...extraHtml])],
        file: document.URL
    };
}

function createSastContentProducer({ collect, send, document: doc, window: win, MutationObserver: Observe, remember = () => [] }) {
    const resourceBytes = 8 * 1024 * 1024, pendingLimit = 32 * 1024 * 1024;
    let state = null, observer = null, pendingBytes = 0, lastSignature = null, disposed = false, collecting = false, dirty = false, transientBytes = 0;
    let streamEpoch = 0, replayAfterInFlight = false;
    const transient = new Set();
    let sending = new Set();
    let sendingEpoch = new Map();
    const failures = new Set();
    const listeners = [];
    const active = () => !disposed && state?.active === true;
    const sendFailure = (revision, reason) => {
        if (!active() || state.revision !== revision) return;
        if (failures.has(reason)) return;
        failures.add(reason);
        try { Promise.resolve(send({ type: 'producer_error', revision, reason }, state)).catch(() => {}); } catch (_) { }
    };
    const changed = (records = []) => {
        if (!active()) return;
        const admitted = state, admittedSending = sending;
        const admittedEpoch = streamEpoch;
        // Preserve observed transient snippets before coalescing, while the
        // full DOM collector itself has only one in-flight invocation.
        for (const snippet of remember(records) || []) {
            if (typeof snippet !== 'string' || transient.has(snippet)) continue;
            const bytes = snippet.length * 2 + 64;
            if (transientBytes + bytes > resourceBytes) { sendFailure(admitted.revision, 'payload_budget_exceeded'); break; }
            transient.add(snippet); transientBytes += bytes;
        }
        dirty = true;
        if (collecting) return;
        collecting = true; dirty = false;
        const extraHtml = [...transient]; transient.clear(); transientBytes = 0;
        const publish = payload => {
            if (!active() || state !== admitted || streamEpoch !== admittedEpoch) return;
            const packet = { type: 'dom_snapshot', revision: admitted.revision, payload };
            let signature;
            try { signature = JSON.stringify(payload); } catch (_) { sendFailure(admitted.revision, 'collection_failed'); return; }
            const bytes = signature.length * 2;
            if (bytes > resourceBytes || pendingBytes + bytes > pendingLimit) { sendFailure(admitted.revision, 'payload_budget_exceeded'); return; }
            if (lastSignature === signature) return;
            if (admittedSending.has(signature)) {
                if (sendingEpoch.get(signature) !== admittedEpoch) replayAfterInFlight = true;
                return;
            }
            pendingBytes += bytes;
            admittedSending.add(signature);
            sendingEpoch.set(signature, admittedEpoch);
            let sent;
            try { sent = send(packet, admitted); } catch (_) { pendingBytes -= bytes; admittedSending.delete(signature); sendFailure(admitted.revision, 'delivery_failed'); return; }
            // No ACK is needed to initiate another snapshot. Commit only after
            // the existing transport accepted the send, never before a throw.
            Promise.resolve(sent).then(reply => {
                // Runtime transport success is not DOM admission. A native
                // document can still be binding when this message arrives.
                if (active() && state === admitted && streamEpoch === admittedEpoch
                    && (admitted.transport !== 'runtime' || reply?.accepted === true)) lastSignature = signature;
            }, () => sendFailure(admitted.revision, 'delivery_failed'))
                .finally(() => {
                    pendingBytes -= bytes; admittedSending.delete(signature); sendingEpoch.delete(signature);
                    if (replayAfterInFlight && !sending.size && active()) {
                        replayAfterInFlight = false;
                        changed();
                    }
                });
        };
        const settle = () => {
            collecting = false;
            if (active() && dirty) changed();
        };
        let result;
        try { result = collect(extraHtml); } catch (_) { collecting = false; sendFailure(admitted.revision, 'collection_failed'); return; }
        if (result && typeof result.then === 'function') {
            Promise.resolve(result).then(publish, () => sendFailure(admitted.revision, 'collection_failed')).finally(settle);
        } else {
            // The normal collector is synchronous. Initiate the first owned
            // snapshot before a short-lived document can fire pagehide; only
            // burst coalescing waits for the next microtask.
            publish(result);
            Promise.resolve().then(settle);
        }
    };
    const disconnect = () => {
        observer?.disconnect(); observer = null;
        transient.clear(); transientBytes = 0; dirty = false;
        for (const [target, event, fn] of listeners.splice(0)) target.removeEventListener(event, fn);
    };
    const setState = value => {
        if (!value || typeof value.active !== 'boolean' || !Number.isSafeInteger(value.revision) || value.revision < 0) return false;
        if (state && value.revision < state.revision) return false;
        if (state?.revision === value.revision && state.active === false && value.active) return false;
        if (state?.revision === value.revision && state.active === value.active) return true;
        disconnect(); state = Object.freeze({ ...value }); lastSignature = null; failures.clear();
        sending = new Set(); sendingEpoch = new Map(); replayAfterInFlight = false; streamEpoch = 0;
        if (!active()) return true;
        if (typeof Observe === 'function') {
            observer = new Observe(records => changed(records));
            observer.observe(doc, { childList: true, subtree: true, attributes: true, characterData: true,
                attributeFilter: [...SAST_INLINE_HANDLER_ATTRIBUTES, ...SAST_JAVASCRIPT_URL_ATTRIBUTES, 'type'], attributeOldValue: true });
        }
        for (const [target, event] of [[doc, 'DOMContentLoaded'], [win, 'load'], [win, 'pageshow']]) {
            const fn = () => changed(); target.addEventListener(event, fn); listeners.push([target, event, fn]);
        }
        const pagehide = () => { disconnect(); state = Object.freeze({ ...state, active: false }); lastSignature = null; };
        win.addEventListener('pagehide', pagehide); listeners.push([win, 'pagehide', pagehide]);
        changed();
        return true;
    };
    const reopened = () => {
        if (!active() || !Number.isSafeInteger(streamEpoch) || streamEpoch >= 1000000) {
            if (active()) sendFailure(state.revision, 'stream_revision_limit');
            return false;
        }
        streamEpoch += 1;
        lastSignature = null;
        // document.open() erases listeners on the same Window/Document. The
        // observer object remains owned; reattach its lifecycle listeners and
        // force a fresh DOM snapshot even when bytes match an earlier stream.
        for (const [target, event, fn] of listeners) {
            target.removeEventListener(event, fn);
            target.addEventListener(event, fn);
        }
        changed();
        return true;
    };
    return { setState, changed, reopened, get active() { return active(); }, dispose() { disposed = true; disconnect(); state = null; lastSignature = null; } };
}

function setSastContentState(state) {
    if (state?.active && state.revision < sastDiscoveryRevisionFloor) return false;
    initializeSastContentPush();
    const previous = window.__PTK_SAST_CONTENT_STATE__;
    const previousRevision = previous?.revision;
    // A late one-time runtime discovery must not switch an already active
    // native producer back from CDP to the browser-message lane.
    if (state?.active && state.transport === 'runtime' && previous?.active
        && previous.transport === 'cdp' && state.revision === previousRevision) return true;
    if (Number.isSafeInteger(previousRevision) && state?.revision < previousRevision) return false;
    if (state?.active && state.revision !== previousRevision) {
        window[SAST_EARLY_SCRIPT_REGISTRY_KEY] = [];
        window[SAST_EARLY_SCRIPT_KEYS_KEY] = new Set();
    }
    const accepted = sastContentProducer.setState(state);
    if (accepted) window.__PTK_SAST_CONTENT_STATE__ = state;
    return accepted;
}

function applyInitialSastDiscovery(state) {
    if (state?.transport !== 'runtime' || typeof state.active !== 'boolean'
        || !Number.isSafeInteger(state.revision) || state.revision < 0) return false;
    if (state.active) return setSastContentState(state);
    // An initial denial is not a terminal revocation: native identity may
    // still be binding. Retain its floor without poisoning equal admission.
    sastDiscoveryRevisionFloor = Math.max(sastDiscoveryRevisionFloor, state.revision);
    const previous = window.__PTK_SAST_CONTENT_STATE__;
    if (sastContentProducer?.active && state.revision > previous?.revision) return setSastContentState(state);
    return false;
}

function initializeSastContentPush() {
    if (sastContentProducer) return;
    const send = (packet, state) => {
        if (state?.transport === 'cdp') {
            if (typeof window.__ptkSastDomPush !== 'function') throw new Error('sast_push_transport_unavailable');
            return window.__ptkSastDomPush(JSON.stringify(packet));
        }
        return sendRuntimeMessage({ channel: 'ptk_content_sast2background_sast', ...packet });
    };
    sastContentProducer = createSastContentProducer({ collect: collectSastPayload, send, document, window,
        MutationObserver: typeof MutationObserver === 'function' ? MutationObserver : null,
        remember: records => {
            const nodes = [], oldHandlers = [];
            for (const record of records || []) {
                nodes.push(...Array.from(record.addedNodes || []), ...Array.from(record.removedNodes || []));
                if (record.type === 'attributes' && record.target) {
                    nodes.push(record.target);
                    if (SAST_INLINE_HANDLER_ATTRIBUTE_SET.has(record.attributeName) && typeof record.oldValue === 'string') oldHandlers.push(record.oldValue);
                    if (SAST_JAVASCRIPT_URL_ATTRIBUTE_SET.has(record.attributeName) && /^\s*javascript\s*:/i.test(record.oldValue || '')) oldHandlers.push(record.oldValue.replace(/^\s*javascript\s*:/i, ''));
                }
            }
            for (const node of nodes) {
                if (String(node?.nodeName || '').toLowerCase() === 'script') rememberEarlySastScriptElement(node, 'authorized_mutation');
                for (const script of Array.from(node?.querySelectorAll?.('script') || [])) rememberEarlySastScriptElement(script, 'authorized_mutation_descendant');
            }
            return [...collectSastInlineHandlers(nodes, true), ...oldHandlers];
        } });
    if (window.__PTK_SAST_CONTENT_STATE__) sastContentProducer.setState(window.__PTK_SAST_CONTENT_STATE__);
    if (typeof window.__ptkSastDomPush === 'function') window.__ptkSastDomPush(JSON.stringify({ type: 'producer_ready' }));
    // One active-state discovery per isolated document, never per snapshot.
    // The background admits Chromium only against browser-owned document ID;
    // Firefox retains its existing exact native-document admission.
    sendRuntimeMessage({ channel: 'ptk_content_sast2background_sast', type: 'get_collection_context' })
        .then(applyInitialSastDiscovery).catch(() => {});
}

function collectSastPayloadSignature() {
    const scriptKeys = [];
    const pushScriptKey = (script) => {
        const key = makeSastScriptKey(script);
        if (key) scriptKeys.push(key);
    };

    try {
        Array.from(document.scripts || [])
            .filter(isExecutableSastScriptElement)
            .map((script) => ({
                src: normalizeSastScriptSrc(script.src || null),
                scriptKind: String(script.type || '').trim().toLowerCase() === 'module' ? 'module' : 'classic',
                code: script.src ? null : normalizeSastScriptCode(script.innerText || script.textContent || '')
            }))
            .filter((script) => !script.src || isSameOriginSastScriptUrl(script.src))
            .forEach(pushScriptKey);
    } catch (_) { }

    try {
        getPtkEarlySastScriptRegistry().forEach(pushScriptKey);
    } catch (_) { }

    const htmlKeys = [];
    try {
        collectSastInlineHandlers()
            .map(normalizeSastInlineHandlerKey)
            .filter(Boolean)
            .forEach((key) => htmlKeys.push(key));
    } catch (_) { }

    return JSON.stringify({
        scripts: Array.from(new Set(scriptKeys)).sort(),
        html: Array.from(new Set(htmlKeys)).sort()
    });
}

function installSpaUrlNotifier(sourceScript = 'content.js') {
    const topFrame = isTopFrame();
    if (window[PTK_SPA_URL_NOTIFIER_KEY]) return false;
    window[PTK_SPA_URL_NOTIFIER_KEY] = sourceScript;

    let lastHref = null;
    let lastSastPayloadSignature = null;
    const sendSastDomCandidate = () => {
        // Discovery can outlive a short-lived page. Send its inline DOM now;
        // only the background can decide whether this document has an active
        // SAST owner. External script bodies still come from native capture.
        const href = getCurrentHref();
        if (!topFrame || sastContentProducer?.active || window.__PTK_SAST_CONTENT_STATE__?.active === false
            || !isHttpTopFrameUrl(href) || isZapCallbackPageUrl(href)) return;
        let payload, signature;
        try {
            payload = collectSastPayload();
            signature = JSON.stringify(payload);
        } catch (_) { return; }
        if (signature.length * 2 > 8 * 1024 * 1024 || signature === lastSastPayloadSignature) return;
        lastSastPayloadSignature = signature;
        sendRuntimeMessage({ channel: 'ptk_content_sast2background_sast', type: 'dom_candidate', payload })
            .then(reply => {
                if (reply?.accepted !== true && lastSastPayloadSignature === signature) lastSastPayloadSignature = null;
            }, () => {
                if (lastSastPayloadSignature === signature) lastSastPayloadSignature = null;
            });
    };
    const notify = (reason = 'unknown') => {
        const href = getCurrentHref();
        if (!(topFrame ? isHttpTopFrameUrl(href) : /^https?:\/\//i.test(href)) || isZapCallbackPageUrl(href)) return;
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
        // Child documents report DAST routes only. SAST collection and the
        // privileged automation controller retain their top-frame ownership.
        if (sastContentProducer?.active) sastContentProducer.changed();
        else sendSastDomCandidate();
    };

    const wrapHistory = (fn) => function () {
        const ret = fn.apply(this, arguments);
        notify(`history.${fn?.name || 'state'}`);
        return ret;
    };

    try {
        history.pushState = wrapHistory(history.pushState);
        history.replaceState = wrapHistory(history.replaceState);
    } catch (_) { }

    window.addEventListener('hashchange', () => notify('hashchange'), false);
    window.addEventListener('popstate', () => notify('popstate'), false);
    // The first document-start snapshot may precede parser-created scripts.
    // This sends only a changed snapshot, without waiting for state discovery.
    window.addEventListener('DOMContentLoaded', sendSastDomCandidate, false);
    setInterval(() => notify('poll'), 500);
    setTimeout(() => notify('initial'), 0);
    return true;
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

function handleIastPageBridgePayload(data, admittedReplay = false) {
    data = data || {};
    if (iastBridgeDeliveryState.stopped && !admittedReplay
        && (data?.ptk_iast || ['ptk_iast_buffer_append', 'ptk_iast_buffer_flush_request',
            'ptk_iast_buffer_clear', 'ptk_iast_navigation_candidate'].includes(data?.channel))) return false;

    if (data?.channel === 'ptk_iast_observation_state') {
        const input = data.state && typeof data.state === 'object' ? data.state : data;
        const count = (key) => Number.isSafeInteger(input[key]) && input[key] >= 0
            ? Math.min(input[key], 1000000) : 0;
        iastObservationState = {
            installationState: ['installing', 'ready', 'failed'].includes(input.installationState)
                ? input.installationState : 'failed',
            operationHighWater: count('operationHighWater'),
            emittedRelationships: count('emittedRelationships'),
            pendingObservations: count('pendingObservations'),
            lossCount: count('lossCount'),
            revision: count('revision'),
            reasons: Array.isArray(input.reasons)
                ? input.reasons.filter(reason => typeof reason === 'string' && /^[a-z0-9_]{1,80}$/.test(reason)).slice(0, 16)
                : [],
            terminal: input.terminal === true
        };
        // Separate metadata delivery is not charged to the full finding FIFO.
        sendIastRuntimeMessage({ channel: 'ptk_content_iast2background_iast', type: 'observation_state',
            state: iastObservationState, context: buildIastBridgeContext() }).catch(() => { });
        return true;
    }

    if (data?.channel === 'ptk_iast_buffer_append') {
        sendIastRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'iast_buffer_append',
            message: data?.message || null,
            context: buildIastBridgeContext()
        }).catch(() => { });
        return true;
    }

    if (data?.channel === 'ptk_iast_buffer_flush_request') {
        sendIastRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'iast_buffer_flush',
            context: buildIastBridgeContext()
        }, (resp) => {
            const messages = Array.isArray(resp?.messages) ? resp.messages : [];
            messages.forEach((msg) => {
                try {
                    handleIastPageBridgePayload(msg, true);
                } catch (_) { }
            });
        }).catch(() => { });
        return true;
    }

    if (data?.channel === 'ptk_iast_buffer_clear') {
        sendIastRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'iast_buffer_clear',
            context: buildIastBridgeContext()
        }).catch(() => { });
        return true;
    }

    if (data?.channel === 'ptk_iast_navigation_candidate') {
        sendIastRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'navigation_candidate',
            candidate: data?.candidate && typeof data.candidate === 'object' ? data.candidate : null,
            finding: data?.finding && typeof data.finding === 'object' ? data.finding : null,
            context: buildIastBridgeContext()
        }).catch(() => { });
        return true;
    }

    if (data?.ptk_iast) {
        const type = data?.ptk_iast === 'runtime_signal' ? 'runtime_signal' : 'finding_report';
        const bufferId = data?.__ptkIastBufferId || data?.bufferId || null;
        sendIastRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type,
            bufferId,
            finding: type === 'finding_report' ? data.finding : undefined,
            signal: type === 'runtime_signal' ? data.signal : undefined,
            context: buildIastBridgeContext()
        }).then(response => {
            if (type === 'finding_report' && response?.ok === true && response?.accepted === true
                && typeof bufferId === 'string') {
                dispatchIastBridgeToPage({ channel: 'ptk_iast_finding_accepted', bufferId });
            }
        }).catch(() => { });
        return true;
    }

    if (data?.channel === 'ptk_iast_agent_ready') {
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'agent_ready',
            installationState: data.installationState || null,
            context: buildIastBridgeContext()
        }).catch(() => { });
        return true;
    }

    if (data?.channel === 'ptk_iast_agent_failed') {
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'agent_failed',
            error: data?.error || null,
            context: buildIastBridgeContext()
        }).catch(() => { });
        return true;
    }

    if (data?.channel === 'ptk_iast_runtime_health') {
        sendRuntimeMessage({
            channel: 'ptk_content_iast2background_iast',
            type: 'runtime_health',
            health: data?.health && typeof data.health === 'object' ? data.health : null,
            context: buildIastBridgeContext()
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

function onIastPageHide() {
    sendRuntimeMessage({ channel: 'ptk_content_iast2background_iast', type: 'observation_state',
        state: Object.assign({}, iastObservationState || { installationState: 'failed',
            lossCount: 0, reasons: ['document_receipt_missing'], revision: 0 }, {
            terminal: true, revision: Math.min(1000000, (iastObservationState?.revision || 0) + 1) }),
        context: buildIastBridgeContext() }).catch(() => { });
}

function onIastPageToContent(event) {
    handleIastPageBridgePayload(parseIastBridgeEventDetail(event?.detail));
}

function onIastWindowMessage(event) {
    handleIastPageBridgePayload(event.data || {});
}

function rebindIastBridge({ reopened = false } = {}) {
    try {
        window.removeEventListener?.('pagehide', onIastPageHide, false);
        window.removeEventListener?.(PTK_IAST_PAGE_TO_CONTENT_EVENT, onIastPageToContent, false);
        window.removeEventListener?.('message', onIastWindowMessage, false);
        window.addEventListener('pagehide', onIastPageHide, false);
        window.addEventListener(PTK_IAST_PAGE_TO_CONTENT_EVENT, onIastPageToContent, false);
        window.addEventListener('message', onIastWindowMessage, false);
        if (reopened && sastContentProducer?.active && sastContentProducer.reopened() !== true) return false;
        dispatchIastBridgeToPage({ channel: 'ptk_content_iast_bridge_ready' });
        return true;
    } catch (_) { return false; }
}

function installIastBridge() {
    if (window.__PTK_SHARED_IAST_CONTENT_BRIDGE__ === true) return false;
    window.__PTK_SHARED_IAST_CONTENT_BRIDGE__ = true;

    if (runtime?.onMessage) {
        runtime.onMessage.addListener((message) => {
            if (message?.channel === 'ptk_background_iast2content') {
                if (message.type === 'rebind_iast_bridge') {
                    return Promise.resolve({ ok: rebindIastBridge({ reopened: true }),
                        documentGeneration: iastDocumentGeneration });
                }
                if (message.type === 'document_identity') {
                    return Promise.resolve({ documentGeneration: iastDocumentGeneration })
                }
                if (message.type === 'clean iast result') {
                    iastBridgeDeliveryState = { pending: 0, failed: false, stopped: false, settlement: null, resolve: null };
                    iastObservationState = null;
                    dispatchIastBridgeToPage({ channel: 'ptk_iast_observation_reset' });
                    return sendIastRuntimeMessage({ channel: 'ptk_content_iast2background_iast',
                        type: 'iast_buffer_clear', context: buildIastBridgeContext() });
                }
                if (message.type === 'stop iast result') {
                    const collection = iastBridgeDeliveryState;
                    dispatchIastBridgeToPage({ channel: 'ptk_iast_observation_stop' });
                    collection.stopped = true;
                    const receipt = {
                        state: iastObservationState || { installationState: 'failed',
                            operationHighWater: 0, emittedRelationships: 0, pendingObservations: 0,
                            lossCount: 0, revision: 0, reasons: ['document_receipt_missing'], terminal: false },
                        context: buildIastBridgeContext()
                    };
                    return settleIastBridgeDeliveries(collection).then(() => ({ ...receipt, deliveryFailed: collection.failed }));
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

            return undefined;
        });
    }

    // The page-world agent may initialize at document_start before this
    // isolated content bridge is installed at document_idle. Ask an existing
    // authorized agent to repeat its genuine readiness and module request so
    // neither signal is lost to script-order timing.
    rebindIastBridge();

    return true;
}

function waitForSastDocumentReady(delayMs) {
    // Keep Chromium's existing load/delay timing. Only Firefox's native-bound
    // collection participates in the approved page-lifetime cancellation.
    if (typeof runtime?.getBrowserInfo !== 'function') {
        return new Promise((resolve) => {
            if (document.readyState === 'complete') return resolve();
            const onReady = () => {
                window.removeEventListener('load', onReady);
                resolve();
            };
            window.addEventListener('load', onReady);
        }).then(() => new Promise((resolve) => setTimeout(resolve, delayMs)))
            .then(() => ({ ok: true, url: document.URL }));
    }
    return new Promise((resolve) => {
        let timer = null, settled = false;
        const finish = (active) => {
            if (settled) return;
            settled = true;
            window.removeEventListener('load', onReady);
            window.removeEventListener('pagehide', onPageHide);
            if (timer !== null) clearTimeout(timer);
            resolve(active ? { ok: true, url: document.URL } : { ok: false, reason: 'sast_document_inactive' });
        };
        const onPageHide = () => finish(false);
        const onReady = () => {
            window.removeEventListener('load', onReady);
            if (!settled) timer = setTimeout(() => finish(true), delayMs);
        };
        window.addEventListener('pagehide', onPageHide);
        if (document.readyState === 'complete') onReady();
        else window.addEventListener('load', onReady);
    });
}

function installSastContentMessageListener() {
    if (window[PTK_SAST_MESSAGE_LISTENER_KEY] === true) return false;
    window[PTK_SAST_MESSAGE_LISTENER_KEY] = true;
    if (!runtime?.onMessage) return false;

    runtime.onMessage.addListener((message) => {
        if (message?.channel !== 'ptk_background2content_sast') return undefined;
        if (message.type === 'sast_state') return Promise.resolve({ accepted: setSastContentState(message.state) });

        if (message.type === 'sast_set_hash') {
            const targetHash = typeof message.hash === 'string' ? message.hash : '';
            if (window.location.hash !== targetHash) {
                window.location.hash = targetHash;
            }
            return Promise.resolve({ ok: true, url: document.URL });
        }


        return undefined;
    });

    return true;
}

function installScaContentMessageListener() {
    if (window[PTK_SCA_MESSAGE_LISTENER_KEY] === true) return false;
    window[PTK_SCA_MESSAGE_LISTENER_KEY] = true;
    if (!runtime?.onMessage) return false;

    runtime.onMessage.addListener((message) => {
        if (message?.channel === 'ptk_background2content_sca' && message.type === 'collect_resources') {
            return Promise.resolve(collectScaResources());
        }
        return undefined;
    });

    return true;
}

function installDastUserInteractionHook({ topFrameOnly = false } = {}) {
    if (window[PTK_DAST_USER_INTERACTION_HOOKED_KEY] === true) return false;
    if (topFrameOnly && !isTopFrame()) return false;
    window[PTK_DAST_USER_INTERACTION_HOOKED_KEY] = true;
    const events = ['click', 'keydown', 'submit', 'touchstart', 'pointerdown'];
    const handler = (event) => {
        if (!event?.isTrusted) return;
        if (window[PTK_DAST_USER_INTERACTION_SENT_KEY] === true) return;
        window[PTK_DAST_USER_INTERACTION_SENT_KEY] = true;
        sendRuntimeMessage({
            channel: 'ptk_content2rattacker',
            type: 'user_interaction',
            reason: event.type || 'interaction',
            location: getCurrentHref(),
            ts: Date.now()
        }).catch(() => { });
    };
    events.forEach((eventName) => {
        try {
            window.addEventListener(eventName, handler, { capture: true, passive: true });
        } catch (_) { }
    });
    return true;
}

const sharedApi = Object.freeze({
    runtime,
    runtimeGetURL,
    sendRuntimeMessage,
    getCurrentHref,
    isTopFrame,
    isHttpTopFrameUrl,
    isZapCallbackPageUrl,
    collectScaResources,
    collectSastPayload,
    collectSastPayloadSignature,
    setSastContentState,
    initializeSastContentPush,
    installEarlySastScriptCapture,
    installSpaUrlNotifier,
    installIastBridge,
    rebindIastBridge,
    installSastContentMessageListener,
    installScaContentMessageListener,
    installDastUserInteractionHook
});

window.PTK_CONTENT_SHARED = sharedApi;

sharedApi.installEarlySastScriptCapture();
sharedApi.installIastBridge();
sharedApi.installSastContentMessageListener();
sharedApi.initializeSastContentPush();
sharedApi.installScaContentMessageListener();
sharedApi.installSpaUrlNotifier('content_shared.js');

}
