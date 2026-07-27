/* Author: Denis Podgurskii */

if (!window.__PTK_CONTENT_MANUAL_LOADED__) {
window.__PTK_CONTENT_MANUAL_LOADED__ = true;

const isFirefox = typeof InstallTrigger !== 'undefined';
const isChrome = !!window.chrome && !!window.chrome.runtime;
//console.log({ isChrome, isFirefox });

const shared = window.PTK_CONTENT_SHARED || {};
const INJECT_SCRIPT_ID = 'ptk-inject-bridge';
const runtime = (typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null);

const PTK_AGENT_AUTOMATION_SCRIPT_ID = 'ptk-agent-automation-layer';

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

shared.installDastUserInteractionHook?.({ topFrameOnly: false });

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

// Automation state
let automationEnabled = false
let automationNonce = null
let automationMessageHandler = null
let zapCloseAutomationMessageHandlerInstalled = false

function isCypressRunnerFrame() {
    try {
        const path = location.pathname || ''
        return path.startsWith('/__/') || path.includes('/__/#/')
    } catch (_) {
        return false
    }
}

async function requestManualAutomationAuthorization(reason = 'settings') {
    if (typeof browser === 'undefined' || !browser?.runtime?.sendMessage) {
        return { ok: false, allowed: false, reason: 'runtime_unavailable' }
    }
    try {
        return await browser.runtime.sendMessage({
            channel: 'ptk_content2background_runtime',
            type: 'manual_automation_authorization',
            url: window.location.href,
            reason
        }) || { ok: true, allowed: false, reason: 'authorization_empty_response' }
    } catch (_) {
        return { ok: false, allowed: false, reason: 'authorization_failed' }
    }
}

function shouldInstallDisabledAutomationBridgeForDenial(response = null) {
    const reason = String(response?.reason || '')
    return ![
        'other_scan_active',
        'other_scan_active_out_of_scope',
        'active_session_out_of_scope',
        'terminal_session_out_of_scope',
        'ptk_child_tab_out_of_scope',
        'zap_detected_tab_out_of_scope',
        'inactive_tab',
        'not_top_frame'
    ].includes(reason)
}

function installDisabledAutomationBridgeForTopFrame() {
    try {
        if (window.top !== window) return
    } catch (_) {
        return
    }
    installPtkAutomationBridge(ptkAutomationVersion, automationNonce, false)
    initZapCloseAutomationMessaging()
}

function injectPtkAgentAutomationLayer() {
    try {
        if (window.PTK_AGENT) return
        if (document.getElementById(PTK_AGENT_AUTOMATION_SCRIPT_ID)) return
        const src = runtimeGetURL('ptk/ptkAgentAutomation.js')
        if (!src) return
        const script = document.createElement('script')
        script.id = PTK_AGENT_AUTOMATION_SCRIPT_ID
        script.async = false
        script.src = src
        script.onload = () => script.remove()
        script.onerror = () => script.remove()
        const parent = document.documentElement || document.head || document.body
        parent && parent.appendChild(script)
    } catch (_) { }
}

async function enableAutomationIfAllowed(reason = 'settings') {
    if (isCypressRunnerFrame()) return false
    const authorization = await requestManualAutomationAuthorization(reason)
    if (authorization?.allowed !== true) return false
    enableAutomation()
    return automationEnabled
}

async function reconcileAutomationState(reason = 'runtime_refresh') {
    if (isCypressRunnerFrame()) return false
    const authorization = await requestManualAutomationAuthorization(reason)
    if (authorization?.allowed === true) {
        enableAutomation()
        return true
    }
    disableAutomation()
    if (shouldInstallDisabledAutomationBridgeForDenial(authorization)) {
        installDisabledAutomationBridgeForTopFrame()
    }
    return false
}

// Settings and secrets stay in trusted extension contexts. The content script
// asks the background only for the current automation authorization decision.
;(async function initAutomation() {
    if (typeof browser === 'undefined' || !browser?.runtime?.sendMessage) return
    try {
        await reconcileAutomationState('initial')
    } catch (_) {
        installDisabledAutomationBridgeForTopFrame()
    }
})();

runtime?.onMessage?.addListener?.((message) => {
    if (message?.channel === 'ptk_background2content_runtime' && message?.type === 'refresh_profile') {
        return reconcileAutomationState('settings_changed').catch(() => false)
    }
    return undefined
})

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
    nonceEl.dataset.automationEnabled = '1'
    nonceEl.dataset.automationRuntime = 'manual'

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

function isZapAutomationRuntimeActive() {
    if (window.__PTK_CONTENT_AUTOMATION_LOADED__ === true) return true
    if (window.__PTK_CONTENT_AUTOMATION_ACTIVE__ === true) return true
    return false
}

function isZapBrowserCloseBridgeMessage(data) {
    // Manual-mode pages must not be able to bypass automation_disabled by
    // crafting broad automation messages with the DOM-readable nonce. The only
    // manual-mode exception is the browser-close contract for an explicit ZAP
    // session; the background still verifies source, same-tab ownership, and
    // session state before allowing progress/stop.
    if (data?.source !== 'ptk-automation') return false
    if (data?.options?.source !== 'zap_browser_close') return false
    const sessionId = data?.sessionId || data?.options?.sessionId
    if (typeof sessionId !== 'string' || !sessionId.trim()) return false
    return data.type === 'session-end' || data.type === 'get-session-progress'
}

function initZapCloseAutomationMessaging() {
    if (zapCloseAutomationMessageHandlerInstalled) return
    zapCloseAutomationMessageHandlerInstalled = true
    window.addEventListener("message", (event) => {
        if (automationEnabled) return
        if (event.source !== window) return
        const data = event.data
        if (!isZapBrowserCloseBridgeMessage(data)) return
        handleAutomationBridgeMessage(data, { responseNonce: data.nonce || '' })
    })
}

async function handleManualAutomationActivationRequest(data = {}) {
    const responseNonce = data.nonce || ''
    const requestId = data.requestId || null
    try {
        if (automationEnabled) {
            window.postMessage({
                source: 'ptk-extension',
                nonce: responseNonce,
                requestId,
                ok: true,
                allowed: true,
                reason: 'already_enabled'
            }, '*')
            return
        }

        const response = await browser.runtime.sendMessage({
            channel: 'ptk_content2background_runtime',
            type: 'manual_automation_activation_request',
            url: window.location.href,
            reason: data.reason || 'bridge_request'
        })

        window.postMessage({
            source: 'ptk-extension',
            nonce: responseNonce,
            requestId,
            ok: response?.ok !== false,
            allowed: response?.allowed === true,
            reason: response?.reason || 'manual_activation_denied',
            error: response?.allowed === true ? undefined : (response?.reason || 'manual_activation_denied')
        }, '*')
        if (response?.allowed === true) {
            setTimeout(() => enableAutomation(), 0)
        }
    } catch (error) {
        window.postMessage({
            source: 'ptk-extension',
            nonce: responseNonce,
            requestId,
            ok: false,
            allowed: false,
            error: error?.message || 'manual_activation_failed'
        }, '*')
    }
}

window.addEventListener("message", (event) => {
    const data = event.data || {}

    if (data?.source === 'ptk-automation' && data?.type === 'automation-activate') {
        handleManualAutomationActivationRequest(data).catch(() => { })
        return
    }

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

function handleAutomationBridgeMessage(data, options = {}) {
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
            nonce: options.responseNonce || automationNonce,  // Include nonce in response
            requestId: data.requestId,
            ...normalizedResponse
        }, '*')
    }).catch((error) => {
        console.error('[PTK Content] Message error:', error)
        window.postMessage({
            source: 'ptk-extension',
            nonce: options.responseNonce || automationNonce,
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
    const existingBridge = window.PTK_AUTOMATION?.bridgeId === 'ptk-automation-bridge'
        ? window.PTK_AUTOMATION
        : null
    if (existingBridge && !(automationEnabledState === true && existingBridge._automationEnabled === false)) return
    const script = document.createElement('script')
    const bridgeUrl = browser.runtime.getURL('ptk/automationBridge.js')
    script.async = false
    script.src = bridgeUrl
    script.dataset.ptkVersion = version || 'unknown'
    script.dataset.ptkNonce = nonce || ''  // Pass nonce to bridge
    script.dataset.ptkAutomationEnabled = automationEnabledState ? '1' : '0'
    try {
        script.dataset.ptkExtensionOrigin = new URL(bridgeUrl).origin
    } catch (_) { }
    if (automationEnabledState === true) {
        script.onload = () => injectPtkAgentAutomationLayer()
    }
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

}
