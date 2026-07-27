/* Author: Denis Podgurskii */

if (!window.__PTK_CONTENT_AUTOMATION_LOADED__) {
window.__PTK_CONTENT_AUTOMATION_LOADED__ = true;

const shared = window.PTK_CONTENT_SHARED || {};
const runtime = shared.runtime || ((typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null));
const PTK_AGENT_AUTOMATION_SCRIPT_ID = 'ptk-agent-automation-layer';
const ptkAutomationManifest = (() => {
    try {
        return runtime?.getManifest ? runtime.getManifest() : null;
    } catch (_) {
        return null;
    }
})();
const ptkAutomationVersion = ptkAutomationManifest?.version || 'unknown';
const isPtkAutomationAgentManifest = (() => {
    const background = ptkAutomationManifest?.background || {};
    return ptkAutomationManifest?.name === 'PTK Automation Agent'
        || background?.service_worker === 'app_automation.js'
        || background?.page === 'ptk/background_automation.html';
})();
let automationNonce = null;
let automationMessageHandlerInstalled = false;
let zapAutomationKeepaliveTimer = null;

function sendRuntimeMessage(payload) {
    if (typeof shared.sendRuntimeMessage === 'function') return shared.sendRuntimeMessage(payload);
    if (!runtime?.sendMessage) return Promise.resolve();
    try {
        return runtime.sendMessage(payload);
    } catch (_) {
        return Promise.resolve();
    }
}

function runtimeGetURL(path) {
    if (typeof shared.runtimeGetURL === 'function') return shared.runtimeGetURL(path);
    if (!runtime?.getURL) return null;
    try {
        return runtime.getURL(path);
    } catch (_) {
        return null;
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
        if (parent) parent.appendChild(script);
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
        if (parent) parent.appendChild(script);
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
        pageUrl: getCurrentHref(),
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

function enableAutomationBridge() {
    if (automationMessageHandlerInstalled) return;
    automationMessageHandlerInstalled = true;
    window.__PTK_CONTENT_AUTOMATION_ACTIVE__ = true;
    const automationRuntime = isPtkAutomationAgentManifest ? 'agent' : 'zap';
    automationNonce = `ptk-${automationRuntime}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

    // The nonce is exposed to the WebDriver-controlled page as a correlation
    // guard, not a secret. Browser-close safety is trusted only after the
    // background verifies tab ownership and session state.
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
        nonceEl.dataset.automationRuntime = automationRuntime;
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

    if (!isPtkAutomationAgentManifest && !zapAutomationKeepaliveTimer) {
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

shared.installIastBridge?.();
const automationTopFrame = isTopFrame();
if (automationTopFrame) {
    enableAutomationBridge();

    if (runtime?.onMessage) runtime.onMessage.addListener(function (message) {
        if (message && message.channel === 'ptk_popup2content' && message.type === 'ping') {
            return Promise.resolve({ ok: true, url: document.URL, runtime: 'automation' });
        }

        if (message?.channel === 'ptk_background2content_automation' && message?.payload) {
            try {
                window.postMessage(message.payload, '*');
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
        }
    }, false);

    shared.installDastUserInteractionHook?.({ topFrameOnly: true });
}

shared.installEarlySastScriptCapture?.();
shared.installSastContentMessageListener?.();
shared.installSpaUrlNotifier?.('content_automation.js');

}
