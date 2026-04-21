/* Author: Denis Podgurskii */

const isFirefox = typeof InstallTrigger !== 'undefined';
const isChrome = !!window.chrome && !!window.chrome.runtime;
//console.log({ isChrome, isFirefox });

const INJECT_SCRIPT_ID = 'ptk-inject-bridge';
const DIALOG_SUPPRESSOR_SCRIPT_ID = 'ptk-dialog-suppressor';
const runtime = (typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null);

const PTK_SPA_ATTACK_TAB_MARKER = 'ptk_spa_attack_tab';
const PTK_SPA_DIALOG_PARAM = 'ptk_dast=1';

function shouldSuppressSpaDialogs() {
    if (typeof window === 'undefined') return false
    if (typeof window.name === 'string' && window.name.includes(PTK_SPA_ATTACK_TAB_MARKER)) return true
    try {
        return String(window.location.href || '').includes(PTK_SPA_DIALOG_PARAM)
    } catch (_) {
        return false
    }
}

function injectDialogSuppressor() {
    try {
        const existing = document.getElementById(DIALOG_SUPPRESSOR_SCRIPT_ID)
        if (existing) return
        const src = runtimeGetURL('ptk/content/dialog_suppressor.js')
        if (!src) return
        const script = document.createElement('script')
        script.id = DIALOG_SUPPRESSOR_SCRIPT_ID
        script.src = src
        script.async = false
        script.onload = () => script.remove()
        script.onerror = () => script.remove()
        const parent = document.head || document.documentElement
        parent && parent.appendChild(script)
    } catch (_) { }
}

if (shouldSuppressSpaDialogs()) {
    injectDialogSuppressor()
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

function normalizeAutomationBridgeResponse(type, response) {
    // Some replies use ok, some use success; only explicit false means failure here
    const isSuccessfulResponse = response && response.ok !== false && response.success !== false
    if (type === 'export-scan-chunk' && isSuccessfulResponse) {
        if (response.chunk instanceof Uint8Array) {
            return response
        }

        const serializedChunk = response.chunk
        if (Array.isArray(serializedChunk)) {
            return {
                ...response,
                chunk: Uint8Array.from(serializedChunk)
            }
        }

        if (serializedChunk && typeof serializedChunk === 'object') {
            // Chrome runtime messaging uses JSON serialization, so Uint8Array
            // chunk payloads can arrive as numeric-keyed plain objects here
            const byteKeys = Object.keys(serializedChunk)
                .filter((key) => /^\d+$/.test(key))
                .sort((left, right) => Number(left) - Number(right))

            if (byteKeys.length) {
                return {
                    ...response,
                    chunk: Uint8Array.from(byteKeys.map((key) => serializedChunk[key]))
                }
            }
        }
    }

    return response
}

let ptkUserInteractionSent = false;
let ptkUserInteractionHooked = false;

function notifyDastUserInteraction(reason = 'interaction') {
    if (ptkUserInteractionSent) return;
    ptkUserInteractionSent = true;
    sendRuntimeMessage({
        channel: "ptk_content2rattacker",
        type: "user_interaction",
        reason,
        location: window.location?.href || "",
        ts: Date.now()
    }).catch(() => { });
}

function setupDastUserInteractionHook() {
    if (ptkUserInteractionHooked) return;
    ptkUserInteractionHooked = true;
    const events = ["click", "keydown", "submit", "touchstart", "pointerdown"];
    const handler = (event) => {
        if (!event?.isTrusted) return;
        notifyDastUserInteraction(event.type || "interaction");
    };
    events.forEach((eventName) => {
        try {
            window.addEventListener(eventName, handler, { capture: true, passive: true });
        } catch (_) { }
    });
}

setupDastUserInteractionHook();

function dumpStorageFiltered(storage) {
    const out = {}
    try {
        for (let i = 0; i < storage.length; i++) {
            const key = storage.key(i)
            if (!key || /^ptk_/i.test(key)) continue
            out[key] = storage.getItem(key)
        }
    } catch (_) { }
    return JSON.stringify(out)
}
const pendingWappalyzerRequests = new Map();
let injectBridgeReady = false;
let injectBridgePromise = null;

const emptyCssResult = { matched: [], truncated: false };
const createEmptyHtmlResults = () => ({
    technologies: { matched: [], truncated: false },
    waf: { matched: [], truncated: false },
    cve: { matched: [], truncated: false }
});

function ensureInjectBridge() {
    if (injectBridgeReady) {
        return Promise.resolve();
    }

    if (injectBridgePromise) {
        return injectBridgePromise;
    }

    injectBridgePromise = new Promise((resolve, reject) => {
        const onLoad = () => {
            injectBridgeReady = true;
            resolve();
        };
        const onError = (error) => {
            injectBridgePromise = null;
            reject(error);
        };

        const existing = document.getElementById(INJECT_SCRIPT_ID);
        if (existing) {
            if (existing.dataset?.ptkInjectLoaded === 'true') {
                injectBridgeReady = true;
                resolve();
                return;
            }

            existing.addEventListener('load', onLoad, { once: true });
            existing.addEventListener('error', onError, { once: true });
            return;
        }

        const script = document.createElement('script');
        script.id = INJECT_SCRIPT_ID;
        script.dataset.ptkInjectLoaded = 'false';
        script.onload = () => {
            script.dataset.ptkInjectLoaded = 'true';
            onLoad();
        };
        script.onerror = onError;
        const injectUrl = runtimeGetURL('ptk/inject.js');
        if (!injectUrl) {
            reject(new Error('Runtime unavailable for inject script'));
            return;
        }
        script.src = injectUrl;
        (document.documentElement || document.head || document.body).appendChild(script);
    });

    return injectBridgePromise;
}

// keep service worker alive
setInterval(function () {
    sendRuntimeMessage({
        channel: "ptk_popup2background_app",
        type: "ping"
    }).catch(e => e)
}, 20000);

// Notify background about SPA URL changes (hash/history) so ui_url stays in sync
;(() => {
    // only top frame to avoid duplicate events
    try {
        if (window.top !== window.self) return
    } catch (_) { }

    let lastHref = null
    const notify = () => {
        const href = location.href
        if (href === lastHref) return
        lastHref = href
        // try {
        //     console.log('[PTK][SPA][content] hash/history change detected', href)
        // } catch (_) { }
        sendRuntimeMessage({
            channel: "ptk_content2rattacker",
            type: "spa_url_changed",
            url: href
        }).catch(e => {
            //try { console.warn('[PTK][SPA][content] failed to send spa_url_changed', e) } catch (_) { }
        })
        sendRuntimeMessage({
            channel: "ptk_content_sast2background_sast",
            type: "spa_url_changed",
            url: href
        }).catch(e => {
            // try { console.warn('[PTK][SPA][content] failed to send spa_url_changed to SAST', e) } catch (_) { }
        })
    }

    const wrapHistory = (fn) => function () {
        const ret = fn.apply(this, arguments)
        notify()
        return ret
    }

    try {
        history.pushState = wrapHistory(history.pushState)
        history.replaceState = wrapHistory(history.replaceState)
    } catch (e) { }

    window.addEventListener('hashchange', notify, false)
    window.addEventListener('popstate', notify, false)

    // poll as a safety net in case events are missed
    setInterval(notify, 500)

    notify()
})();


function collectSastPayload() {
    const scripts = Array.from(document.scripts)
        .filter(isExecutableSastScriptElement)
        .map(s => ({
            src: s.src || null,
            code: s.src ? null : s.innerText
        }))
        .filter(script => {
            if (!script.src) return true;
            return /^https?:\/\//i.test(script.src);
        });
    return {
        scripts: scripts,
        html: collectSastInlineHandlers(),
        file: document.URL
    };
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

function collectScaResources() {
    const urls = new Set()
    const pushUrl = (value) => {
        const next = String(value || '').trim()
        if (!/^https?:\/\//i.test(next)) return
        urls.add(next)
    }

    try {
        Array.from(document.scripts || []).forEach((script) => pushUrl(script?.src))
    } catch (_) { }

    try {
        Array.from(document.querySelectorAll('link[href]')).forEach((link) => pushUrl(link?.href))
    } catch (_) { }

    try {
        const entries = performance?.getEntriesByType ? performance.getEntriesByType('resource') : []
        Array.from(entries || []).forEach((entry) => pushUrl(entry?.name))
    } catch (_) { }

    try {
        pushUrl(document.URL)
    } catch (_) { }

    return { resources: Array.from(urls) }
}

(() => {
    // SAST payload collection is triggered explicitly by background requests.
})();


if (runtime?.onMessage) runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message && message.channel == "ptk_popup2content" && message.type == "ping") {
        return Promise.resolve({ ok: true, url: document.URL });
    }

    if (message?.channel === 'ptk_background2content_zap' && message?.type === 'fetch_config') {
        const configUrl = typeof message.url === 'string' ? message.url : ''
        if (!configUrl) {
            return Promise.resolve({ ok: false, error: 'missing_config_url' })
        }

        return fetch(configUrl, {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            },
            cache: 'no-store',
            credentials: 'include'
        }).then(async (response) => {
            const status = Number(response?.status || 0)
            const statusText = String(response?.statusText || '')
            const responseType = String(response?.type || '')
            const responseUrl = String(response?.url || configUrl)
            if (!response?.ok) {
                return {
                    ok: false,
                    status,
                    statusText,
                    responseType,
                    responseUrl,
                    error: `http_${status}`
                }
            }

            const body = await response.text()
            if (!body || !body.trim()) {
                return { ok: true, status, data: {} }
            }

            let parsed = null
            try {
                parsed = JSON.parse(body)
            } catch (_) {
                return {
                    ok: false,
                    status,
                    statusText,
                    responseType,
                    responseUrl,
                    error: 'parse_error'
                }
            }

            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
                return { ok: true, status, data: {} }
            }

            return { ok: true, status, data: parsed }
        }).catch((err) => {
            return {
                ok: false,
                error: err?.message || 'fetch_failed',
                errorName: err?.name || null,
                errorMessage: err?.message || 'fetch_failed'
            }
        })
    }

    if (message.channel == "ptk_background2content_sast") {
        if (message.type == "collect_scripts") {
            const payload = collectSastPayload();
            sendRuntimeMessage({
                channel: "ptk_content_sast2background_sast",
                type: "scripts_collected",
                requestId: message.requestId || null,
                ...payload
            }).catch(e => e)
            return Promise.resolve({ ok: true })
        }
        if (message.type == "sast_set_hash") {
            const targetHash = typeof message.hash === "string" ? message.hash : "";
            if (window.location.hash !== targetHash) {
                window.location.hash = targetHash;
            }
            return Promise.resolve({ ok: true, url: document.URL });
        }
        if (message.type == "sast_wait_ready") {
            const delayMs = Number(message.delayMs || 300);
            const waitReady = () => new Promise((resolve) => {
                if (document.readyState === "complete") return resolve();
                const onReady = () => {
                    window.removeEventListener("load", onReady);
                    resolve();
                };
                window.addEventListener("load", onReady);
            });
            return waitReady().then(() => new Promise((resolve) => setTimeout(resolve, delayMs)))
                .then(() => ({ ok: true, url: document.URL }));
        }
    }

    if (message.channel == "ptk_background2content_sca" && message.type == "collect_resources") {
        return Promise.resolve(collectScaResources())
    }

    if (message.channel == "ptk_background2content" && message.type == "init") {
        const requestId = message.requestId || `ptk-wappalyzer-${Date.now()}-${Math.random().toString(36).slice(2)}`
        const payload = {
            dom: message.dom || [],
            js: message.js || [],
            css: message.css || [],
            html: message.html || {},
            requestId: requestId
        }

        pendingWappalyzerRequests.set(requestId, payload)

        ensureInjectBridge().then(() => {
            window.postMessage({
                channel: "ptk_content2inject",
                requestId: requestId,
                dom: payload.dom,
                js: payload.js,
                css: payload.css,
                html: payload.html
            }, '*')
        }).catch(() => {
            pendingWappalyzerRequests.delete(requestId)
        })

        return Promise.resolve()
    }

    if (message.channel == "ptk_background_iast2content") {
        if (message.type == "clean iast result") {
            localStorage.removeItem('ptk_iast_buffer');
        }
        if (message.type == "ping") {
            return Promise.resolve({ ok: true })
        }
    }

    if (message.channel == "ptk_background_iast2content_modules" && message.iastModules) {
        try {
            window.postMessage({
                channel: 'ptk_background_iast2content_modules',
                iastModules: message.iastModules
            }, '*')
        } catch (_) { }
        return Promise.resolve({ ok: true })
    }

    if (message.channel == "ptk_background_iast2content_token_origin") {
        try {
            window.postMessage({
                channel: 'ptk_background_iast2content_token_origin',
                tokens: Array.isArray(message.tokens) ? message.tokens : []
            }, '*')
        } catch (_) { }
        return Promise.resolve({ ok: true })
    }

    if (message.channel == "ptk_popup2content") {
        if (message.type == "get_storage") {
            browser.runtime.sendMessage({
                channel: "ptk_content2popup",
                type: "return_storage",
                data: { localStorage: dumpStorageFiltered(window.localStorage), sessionStorage: dumpStorageFiltered(window.sessionStorage) }
            }).catch(e => e)
            return Promise.resolve()
        }

        else if (message.type == "update_storage") {
            if (message.storage == 'localStorage') {
                let item = window.localStorage.getItem(message.name)
                if (item) {
                    window.localStorage.setItem(message.name, message.value)
                }
            }
            if (message.storage == 'sessionStorage') {
                let item = window.sessionStorage.getItem(message.name)
                if (item) {
                    window.sessionStorage.setItem(message.name, message.value)
                }
            }
            // if (message.storage == 'cookie') {
            //     let item = window.sessionStorage.getItem(message.name)
            //     if (item) {
            //         window.sessionStorage.setItem(message.name, message.value)
            //     }
            // }
        }
    }
})


const ptkAutomationVersion = (() => {
    try {
        const manifest = browser.runtime.getManifest ? browser.runtime.getManifest() : null
        return manifest?.version || 'unknown'
    } catch (err) {
        return 'unknown'
    }
})();

// Storage key for settings (must match automation.js and settings.js)
const SETTINGS_KEY = 'pentestkit8_settings'

// Automation state
let automationEnabled = false
let automationNonce = null
let automationMessageHandler = null

function isCypressRunnerFrame() {
    try {
        const path = location.pathname || ''
        return path.startsWith('/__/') || path.includes('/__/#/')
    } catch (_) {
        return false
    }
}

// Dynamic enable/disable via storage.onChanged
;(async function initAutomation() {
    // Check if browser API is available (content script context)
    if (typeof browser === 'undefined' || !browser?.storage?.local) {
        return
    }

    let enabled = false

    // Initial check - use settings key with automation.enable
    // When automation is enabled, we inject in ALL frames (including Cypress AUT iframe)
    try {
        const result = await browser.storage.local.get(SETTINGS_KEY)
        enabled = result?.[SETTINGS_KEY]?.automation?.enable === true
        if (enabled) {
            enableAutomation()
        }
    } catch (e) {
        // Silently fail - automation stays disabled
    }

    // Automation OFF: keep existing behavior (top frame only)
    if (!enabled) {
        try {
            if (window.top !== window) return
        } catch (_) { return }
        installPtkAutomationBridge(ptkAutomationVersion, automationNonce, false)
    } else if (isCypressRunnerFrame()) {
        // Automation ON: skip Cypress runner frames
        return
    }

    // Listen for settings changes (no page reload needed)
    browser.storage.onChanged.addListener((changes, areaName) => {
        if (areaName !== 'local') return
        if (!changes[SETTINGS_KEY]) return

        const newEnabled = changes[SETTINGS_KEY]?.newValue?.automation?.enable === true
        const oldEnabled = changes[SETTINGS_KEY]?.oldValue?.automation?.enable === true

        if (newEnabled && !oldEnabled) {
            if (!isCypressRunnerFrame()) {
                enableAutomation()
            }
        } else if (!newEnabled && oldEnabled) {
            disableAutomation()
        }
    })
})();

function enableAutomation() {
    if (isCypressRunnerFrame()) return
    if (automationEnabled) return
    automationEnabled = true

    // Generate nonce for this session
    automationNonce = `ptk-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`

    // Expose nonce via DOM element for test frameworks (Cypress runs AUT in iframe)
    // This allows tests to read the nonce and include it in their messages
    let nonceEl = document.getElementById('__ptk_automation_nonce__')
    if (!nonceEl) {
        nonceEl = document.createElement('div')
        nonceEl.id = '__ptk_automation_nonce__'
        nonceEl.style.display = 'none'
        document.documentElement.appendChild(nonceEl)
    }
    nonceEl.dataset.nonce = automationNonce

    installPtkAutomationBridge(ptkAutomationVersion, automationNonce, true)
    notifyAutomationStatus(true, automationNonce)
    initPtkAutomationMessaging()

    // Listen for messages only when enabled
    automationMessageHandler = function(event) {
        if (event.source !== window) return
        const data = event.data
        if (data?.source !== 'ptk-automation') return
        // Validate nonce (require always)
        if (data.nonce !== automationNonce) return
        handleAutomationBridgeMessage(data)
    }
    window.addEventListener("message", automationMessageHandler)
}

function disableAutomation() {
    if (!automationEnabled) return
    automationEnabled = false

    // Remove message listener (can't uninject bridge JS, but stop responding)
    if (automationMessageHandler) {
        window.removeEventListener("message", automationMessageHandler)
        automationMessageHandler = null
    }
    notifyAutomationStatus(false, automationNonce)
    automationNonce = null

    // Remove nonce element
    const nonceEl = document.getElementById('__ptk_automation_nonce__')
    if (nonceEl) {
        nonceEl.remove()
    }
}

window.addEventListener("message", (event) => {
    const data = event.data || {}

    if (data?.channel === 'ptk_inject2content' && data?.requestId) {
        const pending = pendingWappalyzerRequests.get(data.requestId)
        if (pending) {
            pendingWappalyzerRequests.delete(data.requestId)
            runAnalysis(
                pending,
                data.js || [],
                data.dom || [],
                data.css || emptyCssResult,
                data.html || createEmptyHtmlResults()
            ).catch(() => { })
        }
        return
    }

    // Note: ptk-automation messages are handled conditionally via automationMessageHandler
    // when automation is enabled in settings

    if (data?.ptk_iast) {
        const type = data?.ptk_iast === 'runtime_signal' ? 'runtime_signal' : 'finding_report'
        browser.runtime.sendMessage({
            channel: "ptk_content_iast2background_iast",
            type,
            finding: type === 'finding_report' ? data.finding : undefined,
            signal: type === 'runtime_signal' ? data.signal : undefined
        }).catch(e => e)
        return
    }

    if (data?.channel === 'ptk_iast_agent_ready') {
        browser.runtime.sendMessage({
            channel: "ptk_content_iast2background_iast",
            type: "agent_ready"
        }).catch(e => e)
        return
    }

    if (data?.channel === 'ptk_iast_agent_failed') {
        browser.runtime.sendMessage({
            channel: "ptk_content_iast2background_iast",
            type: "agent_failed",
            error: data?.error || null
        }).catch(e => e)
        return
    }

    if (data?.channel === 'ptk_iast_runtime_health') {
        browser.runtime.sendMessage({
            channel: "ptk_content_iast2background_iast",
            type: "runtime_health",
            health: data?.health && typeof data.health === 'object' ? data.health : null
        }).catch(e => e)
        return
    }

    if (data?.channel === 'ptk_content_iast_request_modules') {
        browser.runtime.sendMessage({
            channel: 'ptk_content_iast2background_request_modules'
        }).then(resp => {
            try {
                window.postMessage({
                    channel: 'ptk_background_iast2content_modules',
                    iastModules: resp?.iastModules || null,
                    iastModulesSignature: resp?.iastModulesSignature || null,
                    scanStrategy: resp?.scanStrategy || null
                }, '*')
            } catch (_) { }
        }).catch(err => {
            try {
                console.warn('[PTK IAST] content failed to fetch modules', err)
            } catch (_) { }
            try {
                window.postMessage({
                    channel: 'ptk_background_iast2content_modules',
                    iastModules: null
                }, '*')
            } catch (_) { }
        })
        return
    }

    if (data?.ptk_ws) {
        browser.runtime.sendMessage({
            channel: "ptk_contentws2rattacker",
            type: data.kind,
            payload: data.payload
        }).catch(e => e)
    }


    if (data?.ptk) {
        browser.runtime.sendMessage({
            channel: "ptk_content2rattacker",
            type: "xss_confirmed",
            data: { attackValue: data, origin: event.origin, location: window.location.toString() }
        }).catch(e => e)
    }
}, false)

function handleAutomationBridgeMessage(data) {
    const validTypes = [
        'session-start',
        'session-end',
        'get-stats',
        'get-findings',
        'export-scan',
        'get-session-progress',
        'export-scan-chunk',
        'release-export-scan'
    ]
    if (!validTypes.includes(data.type)) return

    const payload = {
        channel: 'ptk_content2background_automation',
        type: data.type,
        sessionId: data.sessionId,
        options: data.options || {},
        includeFindings: data.includeFindings === true,
        limit: data.limit,
        wait: data.wait,  // For non-blocking stop
        pageUrl: window.location.href,
        requestId: data.requestId
    }

    browser.runtime.sendMessage(payload).then((response) => {
        const normalizedResponse = normalizeAutomationBridgeResponse(data.type, response)
        window.postMessage({
            source: 'ptk-extension',
            nonce: automationNonce,  // Include nonce in response
            requestId: data.requestId,
            ...normalizedResponse
        }, '*')
    }).catch((error) => {
        console.error('[PTK Content] Message error:', error)
        window.postMessage({
            source: 'ptk-extension',
            nonce: automationNonce,
            requestId: data.requestId,
            error: error?.message || 'PTK automation error'
        }, '*')
    })
}

function initPtkAutomationMessaging() {
    browser.runtime.onMessage.addListener((message, sender) => {
        if (message?.channel === 'ptk_background2content_automation' && message?.payload) {
            try {
                window.postMessage(message.payload, '*')
            } catch (_) { }
        }
    })
}

function installPtkAutomationBridge(version, nonce, automationEnabledState) {
    if (window.PTK_AUTOMATION) {
        return
    }
    const script = document.createElement('script')
    script.src = browser.runtime.getURL('ptk/automationBridge.js')
    script.dataset.ptkVersion = version || 'unknown'
    script.dataset.ptkNonce = nonce || ''  // Pass nonce to bridge
    script.dataset.ptkAutomationEnabled = automationEnabledState ? '1' : '0'
    const parent = document.documentElement || document.head || document.body
    parent.appendChild(script)
}

function notifyAutomationStatus(enabled, nonce) {
    try {
        window.postMessage({
            source: 'ptk-extension',
            type: 'automation-status',
            enabled: enabled === true,
            nonce: nonce || ''
        }, '*')
    } catch (_) { }
}

async function runAnalysis(message, js, dom, cssResults = emptyCssResult, htmlResults = createEmptyHtmlResults()) {

    // HTML
    let html = new XMLSerializer().serializeToString(document)

    // Discard the middle portion of HTML to avoid performance degradation on large pages
    const chunks = []
    const maxCols = 2000
    const maxRows = 3000
    const rows = html.length / maxCols

    for (let i = 0; i < rows; i += 1) {
        if (i < maxRows / 2 || i > rows - maxRows / 2) {
            chunks.push(html.slice(i * maxCols, (i + 1) * maxCols))
        }
    }
    html = chunks.join('')

    // Script tags
    const scriptNodes = Array.from(document.scripts)

    const scriptSrc = scriptNodes
        .filter(({ src }) => src && !src.startsWith('data:text/javascript;'))
        .map(({ src }) => src)

    const scripts = scriptNodes
        .map((node) => node.textContent)
        .filter((script) => script)



    // Meta tags
    const meta = Array.from(document.querySelectorAll('meta')).reduce(
        (metas, meta) => {
            const key = meta.getAttribute('name') || meta.getAttribute('property')

            if (key) {
                metas[key.toLowerCase()] = [meta.getAttribute('content')]
            }
            return metas
        },
        {}
    )



    dom = Array.prototype.concat.apply(message.dom
        .reduce((technologies, { name, dom }) => {
            const toScalar = (value) =>
                typeof value === 'string' || typeof value === 'number'
                    ? value
                    : !!value

            Object.keys(dom).forEach((selector) => {
                let nodes = []//document.querySelectorAll(selector)
                try {
                    nodes = document.querySelectorAll(selector)
                } catch (error) {
                    // Continue
                }

                if (!nodes.length) {
                    return
                }

                dom[selector].forEach(({ text, properties, attributes }) => {
                    nodes.forEach((node) => {
                        if (text) {
                            const value = node.textContent.trim()

                            if (value && !technologies.find(item => item.name == name)) {
                                technologies.push({
                                    name,
                                    selector,
                                    text: value,
                                })
                            }
                        }

                        if (properties) {
                            Object.keys(properties).forEach((property) => {
                                if (Object.prototype.hasOwnProperty.call(node, property)) {
                                    const value = node[property]

                                    if (typeof value !== 'undefined' && !technologies.find(item => item.name == name)) {
                                        technologies.push({
                                            name,
                                            selector,
                                            property,
                                            value: toScalar(value),
                                        })
                                    }
                                }
                            })
                        }

                        if (attributes) {
                            Object.keys(attributes).forEach((attribute) => {
                                if (node.hasAttribute(attribute) && !technologies.find(item => item.name == name)) {
                                    const value = node.getAttribute(attribute)

                                    technologies.push({
                                        name,
                                        selector,
                                        attribute,
                                        value: toScalar(value),
                                    })
                                }
                            })
                        }
                    })
                })
            })

            return technologies
        }, [])
        , dom)


    let auth = {
        localStorage: dumpStorageFiltered(window.localStorage),
        sessionStorage: dumpStorageFiltered(window.sessionStorage)
    }

    browser.runtime.sendMessage({
        channel: "ptk_content2popup",
        type: "init_complete",
        data: {
            html: html,
            htmlMatches: htmlResults,
            meta: meta,
            scriptSrc: scriptSrc,
            scripts: scripts,
            css: cssResults,
            auth: auth,
            dom: dom,
            js: js
        }
    }).catch(e => e)

    return Promise.resolve(true)
}
