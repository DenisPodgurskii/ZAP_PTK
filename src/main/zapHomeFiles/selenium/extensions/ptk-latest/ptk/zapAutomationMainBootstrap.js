// Generated from the two authoritative PTK automation entries. Do not edit.
// automationBridge.js SHA-256: cfd8be71e7cde9ebde542dc5b7289752bff9b01e9f47d7b533b2cdd54ac333a3
// ptkAgentAutomation.js SHA-256: b1df553115c931bfae805ae7c64fe1eb6d39e72ae0071c5edf802bab1af9743b
export function installPtkZapMainBootstrap(config) {
    if (!config || config.schema !== 'ptk-zap-main-bootstrap-v1' || config.enabled !== true
        || typeof config.version !== 'string' || !config.version || config.version.length > 64
        || typeof config.extensionOrigin !== 'string'
        || !/^chrome-extension:\/\/[a-z]{32}$/u.test(config.extensionOrigin)
        || typeof config.nonce !== 'string' || !/^ptk-[A-Za-z0-9._-]{1,124}$/u.test(config.nonce)) {
        return { ok: false, reason: 'invalid_bootstrap_config' };
    }
    const __PTK_ZAP_MAIN_BOOTSTRAP_CONFIG__ = config;
/* Author: Denis Podgurskii */
;(function() {
    'use strict'

    // The generated, extension-owned ZAP MAIN entry passes this lexical value
    // as an executeScript argument. Ordinary script/declarative entry points do
    // not define it and keep their existing currentScript behavior.
    const ownedBootstrap = typeof __PTK_ZAP_MAIN_BOOTSTRAP_CONFIG__ === 'undefined'
        ? null
        : __PTK_ZAP_MAIN_BOOTSTRAP_CONFIG__
    const bridgeScript = ownedBootstrap ? null : document.currentScript
    const declarativeAutomationBootstrap = !bridgeScript
    const automationEnabledAttr = bridgeScript?.dataset?.ptkAutomationEnabled
    const initialAutomationEnabled = ownedBootstrap
        ? ownedBootstrap.enabled === true
        : (declarativeAutomationBootstrap || automationEnabledAttr === '1' || automationEnabledAttr === 'true')
    const AUTOMATION_REQUEST_EVENT = 'ptk-automation-request'
    const AUTOMATION_RESPONSE_EVENT = 'ptk-automation-response'
    let isTopFrame = true
    try {
        isTopFrame = window.top === window
    } catch (_) {
        isTopFrame = true
    }

    const VERSION = ownedBootstrap?.version || bridgeScript?.dataset?.ptkVersion || 'unknown'
    const EXTENSION_ORIGIN = ownedBootstrap?.extensionOrigin || bridgeScript?.dataset?.ptkExtensionOrigin || ''
    const BRIDGE_ID = 'ptk-automation-bridge'
    const bridgeGeneration = Number(window.__PTK_AUTOMATION_BRIDGE_GENERATION__ || 0) + 1
    window.__PTK_AUTOMATION_BRIDGE_GENERATION__ = bridgeGeneration
    if (typeof window.__PTK_AUTOMATION_BRIDGE_MESSAGE_HANDLER__ === 'function') {
        try {
            document.removeEventListener(AUTOMATION_RESPONSE_EVENT, window.__PTK_AUTOMATION_BRIDGE_MESSAGE_HANDLER__)
        } catch (_) { }
    }

    // The declarative pre-IAST Auto bridge is top-frame only, matching the
    // content_automation controller. Preserve explicit enabled iframe support
    // for Cypress and other existing injected-bridge callers.
    if (!isTopFrame && (declarativeAutomationBootstrap || !initialAutomationEnabled)) return
    const PTK_AUTOMATION_CAPABILITIES = Object.freeze([
        'startSession',
        'endSession',
        'getStats',
        'getFindings',
        'getAnalysisSnapshot',
        'exportScan',
        'getSessionProgress',
        'exportScanChunk',
        'releaseExportScan'
    ])
    // Marker value shared with ptkAgentAutomation.js (PTK_AGENT_SESSION_SCOPE);
    // callers passing this opt into strict lookup in getFindings().
    const PTK_AGENT_SESSION_SCOPE = 'current-tab'
    let currentNonce = ownedBootstrap?.nonce || bridgeScript?.dataset?.ptkNonce || ''
    if (!currentNonce) {
        currentNonce = `ptk-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
    }
    if (isTopFrame || initialAutomationEnabled) {
        let nonceEl = document.getElementById('__ptk_automation_nonce__')
        if (!nonceEl) {
            nonceEl = document.createElement('div')
            nonceEl.id = '__ptk_automation_nonce__'
            nonceEl.style.display = 'none'
            ;(document.documentElement || document.head)?.appendChild(nonceEl)
        }
        if (nonceEl) {
            nonceEl.dataset.nonce = currentNonce
            nonceEl.dataset.automationEnabled = initialAutomationEnabled ? '1' : '0'
            nonceEl.dataset.bridgeOwned = '1'
        }
    }

    function parseAutomationEvent(event) {
        try {
            return JSON.parse(String(event?.detail || ''), (_, value) => value?.__ptkType === 'Uint8Array'
                ? Uint8Array.from(value.data || [])
                : value)
        } catch (_) {
            return null
        }
    }

    function dispatchAutomationRequest(payload) {
        document.dispatchEvent(new CustomEvent(AUTOMATION_REQUEST_EVENT, {
            detail: JSON.stringify(payload)
        }))
    }

    const pendingRequests = new Map()
    let requestCounter = 0
    // Local cache of sessionId (background is source of truth, looks up by tabId)
    let currentSessionId = null

    function usesStrictCurrentTabScope(options = {}) {
        return options?.sessionScope === PTK_AGENT_SESSION_SCOPE
    }

    function sessionIdForBridgeLookup(options = {}) {
        return options?.sessionId || (usesStrictCurrentTabScope(options) ? null : currentSessionId)
    }

    function isZapBrowserCloseOptions(options = {}) {
        return options?.source === 'zap_browser_close'
            && typeof options?.sessionId === 'string'
            && options.sessionId.trim() !== ''
            && typeof options?.zapid === 'string'
            && options.zapid.trim() !== ''
    }

    function bridgeError(message, response = {}) {
        const error = new Error(message || 'ptk_automation_request_failed')
        error.response = response
        return error
    }

    function diagnosticExtras(value) {
        const response = value?.response || value
        if (!response || typeof response !== 'object') return {}

        return {
            ...(response.sessionLookup ? { sessionLookup: response.sessionLookup } : {}),
            ...(Array.isArray(response.warnings) ? { warnings: response.warnings } : {})
        }
    }

    // Low-level bridge transport helpers
    function sendMessage(type, payload) {
        return new Promise((resolve, reject) => {
            const requestId = `ptk-req-${++requestCounter}-${Date.now()}`
            pendingRequests.set(requestId, { resolve, reject, timestamp: Date.now() })

            // Timeout after 5 minutes
            setTimeout(() => {
                if (pendingRequests.has(requestId)) {
                    pendingRequests.delete(requestId)
                    reject(new Error('PTK automation request timed out'))
                }
            }, 300000)

            dispatchAutomationRequest({
                source: 'ptk-automation',
                nonce: currentNonce,  // Include nonce in every message
                requestId,
                type,
                ...payload
            })
        })
    }

    /**
     * Prefer the native encoder when available, but keep a fallback
     * because PTK still supports older browser/extension
     */
    function bytesToBase64(value) {
        if (!(value instanceof Uint8Array)) {
            throw new TypeError('unsupported_chunk_payload_type')
        }
        if (!value.length) return ''

        if (typeof value.toBase64 === 'function') {
            return value.toBase64()
        }

        const chunkSize = 0x8000
        const parts = []
        // Build a binary string in safe chunks for btoa() on older runtimes
        for (let i = 0; i < value.length; i += chunkSize) {
            const slice = value.subarray(i, i + chunkSize)
            parts.push(String.fromCharCode.apply(null, slice))
        }

        return btoa(parts.join(''))
    }

    /**
     * Normalize low-level findings input so callers can use either numeric
     * shorthand or lookup options while keeping strict lookup opt-in.
     * @param {number|Object} input
     * @returns {{limit: number, sessionId: string|undefined, lookupOptions: {sessionId: string|undefined, sessionScope: string|undefined}, strict: boolean}}
     */
    function getFindingsOptions(input = 100) {
        const maxFindingsLimit = 500
        const options = input && typeof input === 'object'
            ? input
            : { limit: input }
        const limitValue = Number(options?.limit)
        const limit = Math.min(Number.isFinite(limitValue) ? limitValue : 100, maxFindingsLimit)
        return {
            limit,
            sessionId: options?.sessionId,
            lookupOptions: {
                sessionId: options?.sessionId,
                sessionScope: options?.sessionScope
            },
            strict: options?.sessionScope === PTK_AGENT_SESSION_SCOPE
        }
    }

    const bridgeMessageHandler = (event) => {
        if (window.__PTK_AUTOMATION_BRIDGE_GENERATION__ !== bridgeGeneration) return
        const data = parseAutomationEvent(event)
        if (data?.source !== 'ptk-extension') return

        if (data.type === 'automation-status') {
            if (data.nonce !== currentNonce || !window.PTK_AUTOMATION) return
            // Page bridge state is compatibility/UI state, never scan authority.
            // Only the isolated content listener and background authorize and
            // execute requests, so a forged page-visible status cannot start a
            // scan or create that privileged listener.
            if (typeof data.version === 'string' && data.version) window.PTK_AUTOMATION.version = data.version
            if (typeof data.extensionOrigin === 'string' && data.extensionOrigin) {
                window.PTK_AUTOMATION.extensionOrigin = data.extensionOrigin
            }
            if (typeof data.enabled === 'boolean') window.PTK_AUTOMATION._automationEnabled = data.enabled
            return
        }

        // Validate nonce matches (require always)
        if (data.nonce !== currentNonce) return

            if (data.requestId && pendingRequests.has(data.requestId)) {
                const { resolve, reject } = pendingRequests.get(data.requestId)
                pendingRequests.delete(data.requestId)

                if (data.error) {
                    reject(bridgeError(data.error, data))
                } else {
                    resolve(data)
                }
        }
    }
    window.__PTK_AUTOMATION_BRIDGE_MESSAGE_HANDLER__ = bridgeMessageHandler
    document.addEventListener(AUTOMATION_RESPONSE_EVENT, bridgeMessageHandler)

    // PTK_AUTOMATION low-level compatibility bridge. The extension deliberately
    // overwrites page-owned objects with the same name; ZAP close decisions must
    // flow through this bridge and then through background session lookup.
    window.PTK_AUTOMATION = {
        version: VERSION,
        extensionOrigin: EXTENSION_ORIGIN || undefined,
        bridgeId: BRIDGE_ID,

        /**
         * Ping the bridge to check status.
         * Always available, returns automationEnabled status.
         */
        ping() {
            const enabled = this._automationEnabled !== false

            return {
                ok: enabled,
                version: this.version,
                bridgeId: this.bridgeId,
                capabilities: enabled
                    ? Array.from(PTK_AUTOMATION_CAPABILITIES)
                    : [],
                automationEnabled: enabled,
                extensionOrigin: this.extensionOrigin,
                error: enabled ? undefined : 'automation_disabled'
            }
        },

        async requestActivation(options = {}) {
            if (this._automationEnabled !== false) {
                return { ok: true, allowed: true, reason: 'already_enabled' }
            }

            const response = await sendMessage('automation-activate', {
                reason: options.reason || 'bridge_request'
            })
            if (response.error && response.allowed !== true) {
                return { ok: false, allowed: false, error: response.error, reason: response.reason || response.error }
            }
            return {
                ok: response.ok !== false,
                allowed: response.allowed === true,
                reason: response.reason || (response.allowed === true ? 'manual_activation_granted' : 'manual_activation_denied')
            }
        },

        /**
         * Start a session while keeping low-level start control in PTK_AUTOMATION.
         * This keeps the default low-level start path unchanged while allowing
         * additive engine-specific options when the caller needs them.
         * @param {Object} options
         * @param {string} options.project - Project identifier
         * @param {string[]} options.engines - Engines: ['DAST', 'IAST', 'SAST', 'SCA']
         * @param {string} options.policyCode - Scan policy
         * @param {string} options.testRunId - Test run ID for correlation
         * @param {boolean} options.runCve - Include CVE-focused scanning
         * @param {string} options.dastScanPolicy - Optional DAST scan policy passthrough
         * @param {string} options.rulepack - Optional SAST rulepack passthrough
         * @param {string} options.cveRulepack - Optional SCA rulepack passthrough
         * @param {Object} options.engineConfigs - Optional per-engine scan configuration
         * @param {string} options.sessionScope - Optional session lookup mode forwarded to the background start request
         * @returns {Promise<{sessionId: string, status: string}>}
         */
        async startSession(options = {}) {
            if (this._automationEnabled === false) {
                throw new Error('automation_disabled')
            }
            if (currentSessionId) {
                console.warn('[PTK] Session already active:', currentSessionId)
            }

            try {
                const response = await sendMessage('session-start', {
                    options: {
                        project: options.project,
                        engines: options.engines || ['DAST'],
                        policyCode: options.policyCode,
                        testRunId: options.testRunId,
                        runCve: options.runCve === true,
                        // Optional advanced passthrough for engine-scoped runs.
                        // Kept additive to preserve existing automation callers.
                        dastScanPolicy: options.dastScanPolicy,
                        rulepack: options.rulepack,
                        cveRulepack: options.cveRulepack,
                        engineConfigs: options.engineConfigs,
                        sessionScope: options.sessionScope
                    }
                })

                if (response.error) {
                    throw new Error(response.error)
                }

                currentSessionId = response.sessionId
                return { sessionId: response.sessionId, status: response.status || 'started' }
            } catch (err) {
                console.error('[PTK] Session start failed:', err)
                throw err
            }
        },

        /**
         * End a session while keeping low-level stop control in PTK_AUTOMATION.
         * This keeps the default low-level behavior unchanged while allowing
         * stricter lookup when the caller asks for it.
         * @param {Object} options
         * @param {string} options.sessionId - Optional explicit session lookup
         * @param {string} options.sessionScope - Optional session lookup mode
         * @param {boolean} options.wait - If false, return immediately and stop in background (default true)
         * @param {boolean} options.includeFindings - Include findings in response (only if wait=true)
         * @param {number} options.limit - Max findings to include
         * @returns {Promise<{ok: true, status?: string, stats?: Object, findings?: Array, truncated?: boolean} | {ok: false, error: string, stats: Object}>}
         */
        async endSession(options = {}) {
            const zapBrowserClose = isZapBrowserCloseOptions(options)
            if (this._automationEnabled === false && !zapBrowserClose) {
                return { ok: false, error: 'automation_disabled' }
            }
            // Background looks up session by tabId - no need to check locally
            try {
                const response = await sendMessage('session-end', {
                    sessionId: sessionIdForBridgeLookup(options),
                    options: {
                        sessionId: options?.sessionId,
                        sessionScope: options?.sessionScope,
                        stopTimeoutMs: options?.stopTimeoutMs,
                        drainTimeoutMs: options?.drainTimeoutMs,
                        source: options?.source,
                        zapid: options?.zapid,
                        currentUrl: options?.currentUrl,
                        closeRequestId: options?.closeRequestId,
                        closeRequestMode: options?.closeRequestMode,
                        closeRequestReason: options?.closeRequestReason,
                        immediateAnalysis: options?.immediateAnalysis
                    },
                    wait: options?.wait !== false,  // default true
                    includeFindings: options?.includeFindings === true,
                    limit: options?.limit
                })

                // Only clear currentSessionId if blocking stop (wait=true) completed
                if (options?.wait !== false) {
                    currentSessionId = null
                }

                if (response.error) {
                    return { ok: false, error: response.error, stats: { vulnsCount: 0, bySeverity: {} } }
                }

                const summary = response.summary || { status: 'completed', stats: { vulnsCount: 0, bySeverity: {} } }
                if (Array.isArray(response.findings)) {
                    summary.findings = response.findings
                }
                if (typeof response.truncated !== 'undefined') {
                    summary.truncated = response.truncated
                }
                return { ok: true, ...summary }
            } catch (err) {
                if (options?.wait !== false) {
                    currentSessionId = null
                }
                return { ok: false, error: err.message, stats: { vulnsCount: 0, bySeverity: {} } }
            }
        },

        /**
         * Read session progress while keeping low-level lookup control in PTK_AUTOMATION.
         * This keeps the default low-level lookup path unchanged while allowing
         * stricter lookup when the caller asks for it.
         * @param {Object} options
         * @param {string} options.sessionId - Optional explicit session lookup
         * @param {string} options.sessionScope - Optional session lookup mode
         * @returns {Promise<{ok: true, sessionId: string, status: string, engines: Object, summary: Object, warnings?: Array, finalSummary?: Object} | {ok: false, error: string}>}
         */
        async getSessionProgress(options = {}) {
            const zapBrowserClose = isZapBrowserCloseOptions(options)
            if (this._automationEnabled === false && !zapBrowserClose) {
                return { ok: false, error: 'automation_disabled' }
            }

            try {
                return await sendMessage('get-session-progress', { options })
            } catch (err) {
                return { ok: false, error: err.message, ...diagnosticExtras(err) }
            }
        },

        /**
         * Get current session statistics
         * @returns {Promise<{findingsCount: number, bySeverity: Object}>}
         */
        async getStats(options = {}) {
            if (this._automationEnabled === false) {
                return { findingsCount: 0, bySeverity: {} }
            }
            const lookupOptions = options && typeof options === 'object'
                ? {
                    sessionId: options.sessionId,
                    sessionScope: options.sessionScope
                }
                : {}
            const strict = lookupOptions.sessionScope === PTK_AGENT_SESSION_SCOPE
            try {
                const response = await sendMessage('get-stats', {
                    sessionId: sessionIdForBridgeLookup(lookupOptions),
                    options: lookupOptions
                })
                if (response.error) throw new Error(response.error)
                return {
                    ...(strict ? { ok: true } : {}),
                    findingsCount: response.findingsCount || 0,
                    bySeverity: response.bySeverity || {},
                    ...(response.sessionLookup ? { sessionLookup: response.sessionLookup } : {})
                }
            } catch (err) {
                return strict
                    ? { ok: false, error: err.message, ...diagnosticExtras(err) }
                    : { findingsCount: 0, bySeverity: {} }
            }
        },

        /**
         * Get findings with compatibility behavior by default and strict lookup
         * only when the caller asks for it. This keeps the default low-level
         * behavior unchanged while allowing stricter workflow-style lookup.
         * @param {number|Object} input - Numeric limit or lookup options object
         * @param {number} input.limit - Max findings to return when input is an object
         * @param {string} input.sessionId - Optional explicit session lookup
         * @param {string} input.sessionScope - Optional session lookup mode
         * @returns {Promise<{findings: Array, truncated: boolean} | {ok: true, findings: Array, truncated: boolean} | {ok: false, error: string}>}
         */
        async getFindings(input = 100) {
            const options = getFindingsOptions(input)
            if (this._automationEnabled === false) {
                return options.strict
                    ? { ok: false, error: 'automation_disabled' }
                    : { findings: [], truncated: false }
            }
            // Background looks up session by tabId
            try {
                const response = await sendMessage('get-findings', {
                    sessionId: sessionIdForBridgeLookup(options.lookupOptions),
                    limit: options.limit,
                    options: options.lookupOptions
                })
                if (response.error) throw new Error(response.error)
                return {
                    ...(options.strict ? { ok: true } : {}),
                    findings: response.findings || [],
                    truncated: response.truncated || false
                }
            } catch (err) {
                return options.strict
                    ? { ok: false, error: err.message, ...diagnosticExtras(err) }
                    : { findings: [], truncated: false }
            }
        },

        /**
         * Get a compact live analysis snapshot for crawler/agent evidence.
         * This is additive and may return unavailable on older or still-running scans.
         * @param {Object} options
         * @param {string} options.sessionId - Optional explicit session lookup
         * @param {string} options.sessionScope - Optional session lookup mode
         * @returns {Promise<{ok: true, engines: Array} | {ok: false, error: string}>}
         */
        async getAnalysisSnapshot(options = {}) {
            if (this._automationEnabled === false) {
                return { ok: false, error: 'automation_disabled' }
            }
            try {
                const response = await sendMessage('get-analysis-snapshot', {
                    sessionId: sessionIdForBridgeLookup(options),
                    options
                })
                if (response.error) throw new Error(response.error)
                return response
            } catch (err) {
                return { ok: false, error: err.message, ...diagnosticExtras(err) }
            }
        },

        /**
         * Export scan payload while keeping low-level export control in PTK_AUTOMATION.
         * This keeps the default low-level export path unchanged while allowing
         * stricter lookup when the caller asks for it.
         * @param {Object} options
         * @param {string} options.engine - Engine to export, or 'ALL'
         * @param {string} options.sessionId - Optional explicit completed session lookup
         * @param {string} options.sessionScope - Optional session lookup mode
         * @param {string} options.target - Export target hint passed to the exporter
         * @param {string} options.fileName - Suggested export file name
         * @param {boolean} options.allowChunked - Allow chunked fallback for large exports
         * @param {number} options.maxExportBytes - Inline export size limit before chunked fallback
         * @returns {Promise<{ok: true, scans: Array, truncatedAny: boolean, warnings: Array} | {ok: false, error: string, warnings?: Array}>}
         */
        async exportScan(options = {}) {
            if (this._automationEnabled === false) {
                return { ok: false, error: 'automation_disabled' }
            }
            if (options?.includeSecrets === true || String(options?.exportMode || '').toLowerCase() === 'replayable') {
                return { ok: false, error: 'replayable_export_requires_privileged_extension_export' }
            }

            try {
                const response = await sendMessage('export-scan', {
                    options: {
                        ...options,
                        sessionId: options?.sessionId || currentSessionId || undefined,
                        sessionScope: PTK_AGENT_SESSION_SCOPE,
                        exportMode: 'evidence',
                        includeSecrets: false
                    }
                })
                if (response.error) {
                    return {
                        ok: false,
                        error: response.error,
                        warnings: response.warnings || [],
                        ...diagnosticExtras(response)
                    }
                }
                return response
            } catch (err) {
                return {
                    ok: false,
                    error: err.message,
                    warnings: diagnosticExtras(err).warnings || [],
                    ...diagnosticExtras(err)
                }
            }
        },

        /**
         * Return export chunk data as base64 so external callers get a JSON-safe response shape
         * @param {Object} options
         * @param {string} options.engine - Engine that owns the export
         * @param {string} options.exportId - Retained export handle from exportScan()
         * @param {number} options.index - Zero-based chunk index to read
         * @returns {Promise<{ok, exportId, index, chunkCount, encoding, byteLength, chunkBase64, error}>}
         */
        async exportScanChunk(options = {}) {
            if (this._automationEnabled === false) {
                return { ok: false, error: 'automation_disabled' }
            }
            if (options?.includeSecrets === true || String(options?.exportMode || '').toLowerCase() === 'replayable') {
                return { ok: false, error: 'replayable_export_requires_privileged_extension_export' }
            }

            try {
                const response = await sendMessage('export-scan-chunk', {
                    options: {
                        ...options,
                        sessionScope: PTK_AGENT_SESSION_SCOPE,
                        exportMode: 'evidence',
                        includeSecrets: false
                    }
                })
                // Normalise low-level failure variants from the extension side into one bridge-level check
                if (response.ok === false || response.success === false) {
                    return { ok: false, error: response.error || 'export_not_found_or_expired' }
                }

                if (!(response.chunk instanceof Uint8Array)) {
                    return { ok: false, error: 'unsupported_chunk_payload_type' }
                }

                const chunkBytes = response.chunk
                return {
                    ok: true,
                    exportId: response.exportId,
                    index: response.index,
                    chunkCount: response.chunkCount,
                    encoding: 'base64',
                    byteLength: chunkBytes.byteLength,
                    chunkBase64: bytesToBase64(chunkBytes)
                }
            } catch (err) {
                return { ok: false, error: err.message }
            }
        },

        /**
         * Release retained chunked export state once the caller has finished fetching the report
         * @param {Object} options
         * @param {string} options.engine - Engine that owns the export
         * @param {string} options.exportId - Retained export handle from exportScan()
         * @returns {Promise<{ok, error}>}
         */
        async releaseExportScan(options = {}) {
            if (this._automationEnabled === false) {
                return { ok: false, error: 'automation_disabled' }
            }
            if (options?.includeSecrets === true || String(options?.exportMode || '').toLowerCase() === 'replayable') {
                return { ok: false, error: 'replayable_export_requires_privileged_extension_export' }
            }

            try {
                const response = await sendMessage('release-export-scan', {
                    options: {
                        ...options,
                        sessionScope: PTK_AGENT_SESSION_SCOPE,
                        exportMode: 'evidence',
                        includeSecrets: false
                    }
                })
                if (response.ok === false || response.success === false) {
                    return { ok: false, error: response.error || 'export_not_found_or_expired' }
                }
                return { ok: true }
            } catch (err) {
                return { ok: false, error: err.message }
            }
        },

        isAvailable() { return true },
        getSessionId() { return currentSessionId },
        _automationEnabled: initialAutomationEnabled
    }

    // The workflow PTK_AGENT layer is injected by the extension content runtime
    // only after the background authorizes this tab. Do not self-inject a
    // sibling script from page world: strict Trusted Types pages such as Gmail
    // block string assignment to HTMLScriptElement.src there.
})()
/* Author: Denis Podgurskii */
;(function() {
    'use strict'

    // Skip when the low-level bridge is absent (frame check or automation
    // disabled in an iframe will have short-circuited automationBridge.js).
    if (!window.PTK_AUTOMATION) return
    if (window.PTK_AGENT) return

    const VERSION = window.PTK_AUTOMATION.version
    const BRIDGE_ID = window.PTK_AUTOMATION.bridgeId

    const PTK_AGENT_API_VERSION = 1
    const PTK_AGENT_CAPABILITIES = Object.freeze([
        'describe',
        'preflight',
        'startScan',
        'scanStatus',
        'stopScan',
        'getFindings',
        'getAnalysisSnapshot',
        'exportFullReport'
    ])
    const PTK_AGENT_ENGINES = Object.freeze(['DAST', 'IAST', 'SAST', 'SCA'])
    // Methods PTK_AGENT calls directly; preflight reports stale low-level bridges early.
    const PTK_AGENT_REQUIRED_LOW_LEVEL_METHODS = Object.freeze([
        'startSession',
        'endSession',
        'getSessionProgress',
        'getFindings',
        'exportScan',
        'exportScanChunk',
        'releaseExportScan'
    ])
    const PTK_AGENT_STATUS_ALIASES = Object.freeze({
        started: 'running'
    })
    // Fallback status when PTK_AGENT cannot map a low-level status.
    const PTK_AGENT_UNKNOWN_STATUS = 'unknown'
    const PTK_AGENT_CANONICAL_STATUSES = new Set([
        'none',
        'starting',
        'running',
        'stopping',
        'completed',
        'error'
    ])
    const PTK_AGENT_ERROR_CODE_ALIASES = Object.freeze({
        session_belongs_to_another_tab: 'session_not_found'
    })
    const PTK_AGENT_ERROR_MESSAGE_OVERRIDES = Object.freeze({
        automation_disabled: 'PTK Automation Mode is disabled for this tab',
        automation_bridge_unavailable: 'PTK automation bridge is unavailable in this page context',
        unsupported_transfer_mode: 'exportFullReport() only supports retrieval-plan mode',
        session_not_found: 'No PTK session is available for this tab',
        no_tab_context: 'PTK automation request requires a browser tab context',
        session_already_running_in_tab: 'A PTK scan is already active for this tab',
        session_start_failed: 'PTK scan could not be started',
        session_status_failed: 'PTK scan status could not be read',
        session_stop_failed: 'PTK scan could not be stopped',
        get_findings_failed: 'PTK findings could not be read',
        export_failed: 'PTK report export could not be prepared',
        session_not_completed: 'PTK scan must be completed before export',
        no_exportable_results: 'PTK could not prepare an export for this request'
    })
    const PTK_AGENT_SESSION_SCOPE = 'current-tab'

    // PTK_AGENT workflow helpers
    function toAgentFailure(errorCode, fallback = 'unexpected_error', extras = {}) {
        errorCode = errorCode || fallback
        errorCode = PTK_AGENT_ERROR_CODE_ALIASES[errorCode] || errorCode
        return {
            ok: false,
            code: errorCode,
            message: PTK_AGENT_ERROR_MESSAGE_OVERRIDES[errorCode] || errorCode,
            ...extras
        }
    }

    // Normalize so workflow callers see only PTK_AGENT_CANONICAL_STATUSES or
    // the diagnostic fallback 'unknown' with the original value in rawStatus.
    function withNormalizedWorkflowStatus(payload, status) {
        const rawStatus = typeof status === 'string' ? status.trim() : ''
        if (!rawStatus) {
            // Keep workflow success responses on a string status instead of null.
            return {
                ...payload,
                status: PTK_AGENT_UNKNOWN_STATUS
            }
        }

        const loweredStatus = rawStatus.toLowerCase()
        const canonicalStatus = PTK_AGENT_STATUS_ALIASES[loweredStatus] || loweredStatus
        if (PTK_AGENT_CANONICAL_STATUSES.has(canonicalStatus)) {
            return {
                ...payload,
                status: canonicalStatus
            }
        }

        return {
            ...payload,
            status: PTK_AGENT_UNKNOWN_STATUS,
            rawStatus
        }
    }

    /**
     * Apply the shared PTK_AGENT current-tab lookup rule so workflow methods
     * stay aligned without changing low-level PTK_AUTOMATION defaults.
     * @param {Object} [options]
     * @returns {Object}
     */
    function withAgentSessionScope(options = {}) {
        return {
            ...options,
            sessionScope: PTK_AGENT_SESSION_SCOPE
        }
    }

    // PTK_AGENT thin workflow wrapper over the low-level bridge
    window.PTK_AGENT = {
        version: VERSION,
        bridgeId: BRIDGE_ID,

        /**
         * Describe the workflow contract so agents can discover the stable surface without checking readiness.
         * @returns {{ok, api, version, bridgeId, automationEnabled, capabilities, export, lowLevel}}
         */
        describe() {
            const automation = window.PTK_AUTOMATION
            const ping = automation?.ping?.() || {
                ok: false,
                automationEnabled: false,
                capabilities: []
            }

            return {
                ok: true,
                api: 'PTK_AGENT',
                agentApiVersion: PTK_AGENT_API_VERSION,
                ptkVersion: this.version,
                bridgeId: this.bridgeId,
                automationEnabled: ping.automationEnabled === true,
                capabilities: Array.from(PTK_AGENT_CAPABILITIES),
                engines: Array.from(PTK_AGENT_ENGINES),
                export: {
                    mode: 'retrieval-plan'
                },
                lowLevel: {
                    bridgeId: ping.bridgeId || BRIDGE_ID,
                    capabilities: Array.isArray(ping.capabilities)
                        ? Array.from(ping.capabilities)
                        : []
                }
            }
        },

        /**
         * Check whether the current page can use PTK now, separate from contract discovery.
         * @returns {{ok, ready, automationEnabled, blockers}}
         */
        preflight() {
            const automation = window.PTK_AUTOMATION
            if (!automation?.ping) {
                return {
                    ok: true,
                    ready: false,
                    automationEnabled: false,
                    blockers: ['automation_bridge_unavailable']
                }
            }

            const ping = automation.ping()
            const automationEnabled = ping.automationEnabled === true
            const blockers = automationEnabled ? [] : ['automation_disabled']

            for (const methodName of PTK_AGENT_REQUIRED_LOW_LEVEL_METHODS) {
                if (typeof automation[methodName] !== 'function') {
                    blockers.push(`missing_low_level_method:${methodName}`)
                }
            }

            return {
                ok: true,
                ready: blockers.length === 0,
                automationEnabled,
                blockers
            }
        },

        /**
         * Start a scan through the PTK_AGENT workflow method.
         * This keeps start on the workflow layer while using the same
         * current-tab lookup as the rest of that layer, and only reports
         * success once the new session can be read back immediately.
         * @param {Object} options
         * @param {string} options.project - Project identifier
         * @param {string[]} options.engines - Engines: ['DAST', 'IAST', 'SAST', 'SCA']
         * @param {string} options.policyCode - Scan policy
         * @param {string} options.testRunId - Test run ID for correlation
         * @param {boolean} options.runCve - Include CVE-focused scanning
         * @param {Object} options.engineConfigs - Optional per-engine scan configuration
         * @returns {Promise<{ok: true, sessionId: string|null, status: string, rawStatus?: string} | {ok: false, code: string, message: string}>}
         */
        async startScan(options = {}) {
            const automation = window.PTK_AUTOMATION
            if (!automation) {
                return toAgentFailure('automation_bridge_unavailable')
            }
            if (automation._automationEnabled === false) {
                return toAgentFailure('automation_disabled')
            }

            try {
                const startOptions = withAgentSessionScope(options)
                const result = await automation.startSession(startOptions)
                // Verify the new current-tab session before reporting workflow success.
                const progress = await automation.getSessionProgress(withAgentSessionScope({
                    sessionId: result?.sessionId ?? null
                }))
                if (progress?.ok === false) {
                    return toAgentFailure(progress?.error || 'session_start_failed', 'session_start_failed')
                }
                return withNormalizedWorkflowStatus({
                    ok: true,
                    sessionId: result?.sessionId ?? progress?.sessionId ?? null
                }, progress?.status ?? result?.status ?? null)
            } catch (err) {
                return toAgentFailure(err?.message || 'session_start_failed', 'session_start_failed')
            }
        },

        /**
         * Read scan progress through the PTK_AGENT workflow method.
         * This keeps workflow polling on the same current-tab lookup as the
         * rest of the workflow layer.
         * @param {Object} options
         * @param {string} options.sessionId - Optional explicit current-tab session lookup
         * @returns {Promise<{ok: true, sessionId: string|null, status: string, rawStatus?: string, startedAt?: string|null, finishedAt?: string|null, stopRequestedAt?: string|null, elapsedMs?: number|null, lastUpdatedAt?: string|null, engines: Object, summary: Object|null, warnings: Array, finalSummary?: Object} | {ok: false, code: string, message: string}>}
         */
        async scanStatus(options = {}) {
            const automation = window.PTK_AUTOMATION
            if (!automation) {
                return toAgentFailure('automation_bridge_unavailable')
            }
            if (automation._automationEnabled === false) {
                return toAgentFailure('automation_disabled')
            }

            try {
                const result = await automation.getSessionProgress(withAgentSessionScope(options))
                if (result?.ok === false) {
                    if (result.error === 'session_not_found' && !options?.sessionId) {
                        return {
                            ok: true,
                            sessionId: null,
                            status: 'none',
                            engines: {},
                            summary: null,
                            warnings: [],
                            ...(result?.sessionLookup ? { sessionLookup: result.sessionLookup } : {})
                        }
                    }
                    return toAgentFailure(result?.error || 'session_status_failed', 'session_status_failed', result?.sessionLookup ? { sessionLookup: result.sessionLookup } : {})
                }

                return withNormalizedWorkflowStatus({
                    ok: true,
                    sessionId: result?.sessionId ?? null,
                    startedAt: result?.startedAt ?? null,
                    finishedAt: result?.finishedAt ?? null,
                    stopRequestedAt: result?.stopRequestedAt ?? null,
                    elapsedMs: typeof result?.elapsedMs === 'number' ? result.elapsedMs : null,
                    lastUpdatedAt: result?.lastUpdatedAt ?? null,
                    engines: result?.engines ?? {},
                    summary: result?.summary ?? null,
                    warnings: Array.isArray(result?.warnings) ? result.warnings : [],
                    ...(result?.sessionLookup ? { sessionLookup: result.sessionLookup } : {}),
                    ...(result?.finalSummary ? { finalSummary: result.finalSummary } : {})
                }, result?.status ?? null)
            } catch (err) {
                return toAgentFailure(err?.message || 'session_status_failed', 'session_status_failed')
            }
        },

        /**
         * Stop a scan through the PTK_AGENT workflow method.
         * This keeps the safer stop/wait flow on the workflow layer while using
         * the same current-tab lookup as the rest of that layer.
         * @param {Object} options
         * @param {string} options.sessionId - Optional explicit current-tab session lookup
         * @param {boolean} options.wait - If false, return immediately and stop in background (default true)
         * @param {boolean} options.includeFindings - Include findings in response (only if wait=true)
         * @param {number} options.limit - Max findings to include
         * @returns {Promise<{ok: true, status: string, rawStatus?: string, stats?: Object, findings?: Array, truncated?: boolean} | {ok: false, code: string, message: string}>}
         */
        async stopScan(options = {}) {
            const automation = window.PTK_AUTOMATION
            if (!automation) {
                return toAgentFailure('automation_bridge_unavailable')
            }
            if (automation._automationEnabled === false) {
                return toAgentFailure('automation_disabled')
            }

            try {
                const result = await automation.endSession(withAgentSessionScope(options))
                if (result?.ok === false) {
                    return toAgentFailure(result?.error || 'session_stop_failed', 'session_stop_failed')
                }

                return withNormalizedWorkflowStatus({
                    ok: true,
                    ...(result?.stats ? { stats: result.stats } : {}),
                    ...(Array.isArray(result?.findings) ? { findings: result.findings } : {}),
                    ...(typeof result?.truncated !== 'undefined' ? { truncated: result.truncated } : {})
                }, result?.status ?? result?.summary?.status ?? null)
            } catch (err) {
                return toAgentFailure(err?.message || 'session_stop_failed', 'session_stop_failed')
            }
        },

        /**
         * Fetch findings through the PTK_AGENT workflow method.
         * This keeps the agent-facing call object-shaped while using the same
         * current-tab lookup as the rest of the workflow layer.
         * @param {Object|number} options - Options object or numeric limit shorthand
         * @param {number} options.limit - Max findings to return when options is an object
         * @param {string} options.sessionId - Optional explicit current-tab session lookup
         * @returns {Promise<{ok: true, findings: Array, truncated: boolean} | {ok: false, code: string, message: string}>}
         */
        async getFindings(options = {}) {
            const automation = window.PTK_AUTOMATION
            if (!automation) {
                return toAgentFailure('automation_bridge_unavailable')
            }
            if (automation._automationEnabled === false) {
                return toAgentFailure('automation_disabled')
            }

            const lookupOptions = typeof options === 'number'
                ? withAgentSessionScope({ limit: options })
                : withAgentSessionScope(options)
            try {
                const result = await automation.getFindings(lookupOptions)
                if (result?.ok === false) {
                    return toAgentFailure(result?.error || 'get_findings_failed', 'get_findings_failed', result?.sessionLookup ? { sessionLookup: result.sessionLookup } : {})
                }
                return {
                    ok: true,
                    findings: Array.isArray(result?.findings) ? result.findings : [],
                    truncated: result?.truncated === true,
                    ...(result?.sessionLookup ? { sessionLookup: result.sessionLookup } : {})
                }
            } catch (err) {
                return toAgentFailure(err?.message || 'get_findings_failed', 'get_findings_failed')
            }
        },

        /**
         * Fetch compact PTK analysis/explorer evidence through the workflow layer.
         * The method is optional from a product perspective, so callers should
         * handle unavailable snapshots without failing a scan.
         * @param {Object} options
         * @returns {Promise<{ok: true, engines: Array, summary?: Object} | {ok: false, code: string, message: string}>}
         */
        async getAnalysisSnapshot(options = {}) {
            const automation = window.PTK_AUTOMATION
            if (!automation) {
                return toAgentFailure('automation_bridge_unavailable')
            }
            if (automation._automationEnabled === false) {
                return toAgentFailure('automation_disabled')
            }
            if (typeof automation.getAnalysisSnapshot !== 'function') {
                return toAgentFailure('missing_low_level_method:getAnalysisSnapshot', 'analysis_snapshot_unavailable')
            }

            try {
                const result = await automation.getAnalysisSnapshot(withAgentSessionScope(options))
                if (result?.ok === false) {
                    return toAgentFailure(result?.error || 'analysis_snapshot_unavailable', 'analysis_snapshot_unavailable', result?.sessionLookup ? { sessionLookup: result.sessionLookup } : {})
                }
                return {
                    ok: true,
                    sessionId: result?.sessionId ?? null,
                    engines: Array.isArray(result?.engines) ? result.engines : [],
                    summary: result?.summary || null,
                    warnings: Array.isArray(result?.warnings) ? result.warnings : [],
                    ...(result?.sessionLookup ? { sessionLookup: result.sessionLookup } : {})
                }
            } catch (err) {
                return toAgentFailure(err?.message || 'analysis_snapshot_unavailable', 'analysis_snapshot_unavailable')
            }
        },

        /**
         * Return a retrieval plan for PTK_AGENT so agents can fetch report chunks.
         * This workflow method uses current-tab lookup; low-level export methods do not change.
         * @param {Object} options
         * @param {string} options.engine - Engine to export, or 'ALL'
         * @param {string} options.sessionId - Optional explicit current-tab completed session lookup
         * @param {string} options.target - Export target hint passed to the low-level exporter
         * @param {string} options.fileName - Suggested export file name
         * @param {string} options.transfer - Omit or use 'retrieval-plan'
         * @returns {Promise<{ok: true, mode: string, scans: Array, truncatedAny: boolean, warnings: Array} | {ok: false, code: string, message: string, warnings?: Array}>}
         */
        async exportFullReport(options = {}) {
            const automation = window.PTK_AUTOMATION
            if (!automation) {
                return toAgentFailure('automation_bridge_unavailable')
            }
            if (automation._automationEnabled === false) {
                return toAgentFailure('automation_disabled')
            }
            if (options?.includeSecrets === true || String(options?.exportMode || '').toLowerCase() === 'replayable') {
                return toAgentFailure('replayable_export_requires_privileged_extension_export', 'replayable_export_requires_privileged_extension_export')
            }

            const transfer = String(options?.transfer || '').trim()
            if (transfer && transfer !== 'retrieval-plan') {
                return toAgentFailure('unsupported_transfer_mode')
            }

            const exportOptions = {
                ...options,
                sessionScope: PTK_AGENT_SESSION_SCOPE,
                includeSecrets: false,
                exportMode: 'evidence',
                allowChunked: true,
                // Tell the background exporter this workflow requires a retrieval
                // descriptor; avoid preparing an inline payload only to reject it.
                forceChunked: true,
                // Retain the one-byte ceiling as a compatibility fallback for
                // backgrounds that do not yet understand forceChunked.
                maxExportBytes: 1
            }
            delete exportOptions.transfer

            try {
                const result = await automation.exportScan(exportOptions)
                if (result?.ok === false) {
                    return {
                        ...toAgentFailure(result?.error || 'export_failed', 'export_failed', result?.sessionLookup ? { sessionLookup: result.sessionLookup } : {}),
                        warnings: Array.isArray(result?.warnings) ? result.warnings : []
                    }
                }

                return {
                    ok: true,
                    mode: 'retrieval-plan',
                    scans: Array.isArray(result?.scans) ? result.scans : [],
                    truncatedAny: result?.truncatedAny === true,
                    warnings: Array.isArray(result?.warnings) ? result.warnings : [],
                    ...(result?.sessionLookup ? { sessionLookup: result.sessionLookup } : {})
                }
            } catch (err) {
                return toAgentFailure(err?.message || 'export_failed', 'export_failed')
            }
        }
    }

    // Signals both PTK_AUTOMATION and PTK_AGENT are ready; fires once per
    // bridge install because automationBridge.js has already populated
    // window.PTK_AUTOMATION by the time this file runs.
    window.dispatchEvent(new CustomEvent('ptk-automation-ready', { detail: { version: VERSION } }))
})()
    const bridge = window.PTK_AUTOMATION;
    const agent = window.PTK_AGENT;
    const nonceElement = document.getElementById('__ptk_automation_nonce__');
    return { ok: bridge?.bridgeId === 'ptk-automation-bridge' && !!agent
        && nonceElement?.dataset?.nonce === config.nonce,
        bridgeId: bridge?.bridgeId || null, nonce: nonceElement?.dataset?.nonce || null };
}
