/* Author: Denis Podgurskii */
;(function() {
    'use strict'

    const automationEnabledAttr = document.currentScript?.dataset?.ptkAutomationEnabled
    const initialAutomationEnabled = automationEnabledAttr === '1' || automationEnabledAttr === 'true'
    let isTopFrame = true
    try {
        isTopFrame = window.top === window
    } catch (_) {
        isTopFrame = true
    }

    const VERSION = document.currentScript?.dataset?.ptkVersion || 'unknown'
    const EXTENSION_ORIGIN = document.currentScript?.dataset?.ptkExtensionOrigin || ''
    const BRIDGE_ID = 'ptk-automation-bridge'
    const bridgeGeneration = Number(window.__PTK_AUTOMATION_BRIDGE_GENERATION__ || 0) + 1
    window.__PTK_AUTOMATION_BRIDGE_GENERATION__ = bridgeGeneration
    if (typeof window.__PTK_AUTOMATION_BRIDGE_MESSAGE_HANDLER__ === 'function') {
        try {
            window.removeEventListener('message', window.__PTK_AUTOMATION_BRIDGE_MESSAGE_HANDLER__)
        } catch (_) { }
    }

    // In Cypress, AUT runs in an iframe. Allow bridge there only when automation is enabled.
    if (!isTopFrame && !initialAutomationEnabled) return
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
    let currentNonce = document.currentScript?.dataset?.ptkNonce || ''
    if (!currentNonce) {
        currentNonce = `ptk-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
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

            window.postMessage({
                source: 'ptk-automation',
                nonce: currentNonce,  // Include nonce in every message
                requestId,
                type,
                ...payload
            }, '*')
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
        // Only accept messages from same window
        if (event.source !== window) return

        const data = event.data
        if (data?.source !== 'ptk-extension') return

        if (data.type === 'automation-status') {
            // The page can forge postMessage payloads, so this status message is
            // intentionally non-authoritative for enabling automation. The bridge
            // starts enabled only from the injected script dataset. Disabling is
            // allowed as a defensive state transition; re-enabling requires a new
            // injected bridge instance from the extension content script.
            if (data.enabled === false && window.PTK_AUTOMATION) {
                window.PTK_AUTOMATION._automationEnabled = false
            }
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
    window.addEventListener('message', bridgeMessageHandler)

    // PTK_AUTOMATION low-level compatibility bridge. The extension deliberately
    // overwrites page-owned objects with the same name; ZAP close decisions must
    // flow through this bridge and then through background session lookup.
    window.PTK_AUTOMATION = {
        version: VERSION,
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
                extensionOrigin: EXTENSION_ORIGIN || undefined,
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
