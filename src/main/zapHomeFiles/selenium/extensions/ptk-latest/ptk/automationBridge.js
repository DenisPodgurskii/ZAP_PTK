/* Author: Denis Podgurskii */
;(function() {
    'use strict'

    // Only inject in top frame
    if (window.top !== window) return
    if (window.PTK_AUTOMATION) return

    const VERSION = document.currentScript?.dataset?.ptkVersion || 'unknown'
    const BRIDGE_ID = 'ptk-automation-bridge'
    const automationEnabledAttr = document.currentScript?.dataset?.ptkAutomationEnabled
    const initialAutomationEnabled = automationEnabledAttr === '1' || automationEnabledAttr === 'true'
    let currentNonce = document.currentScript?.dataset?.ptkNonce || ''
    if (!currentNonce) {
        currentNonce = `ptk-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
    }

    const pendingRequests = new Map()
    let requestCounter = 0
    // Local cache of sessionId (background is source of truth, looks up by tabId)
    let currentSessionId = null

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

    window.addEventListener('message', (event) => {
        // Only accept messages from same window
        if (event.source !== window) return

        const data = event.data
        if (data?.source !== 'ptk-extension') return

        if (data.type === 'automation-status') {
            if (data.nonce) {
                currentNonce = data.nonce
            }
            if (window.PTK_AUTOMATION) {
                window.PTK_AUTOMATION._automationEnabled = data.enabled === true
            }
            return
        }

        // Validate nonce matches (require always)
        if (data.nonce !== currentNonce) return

        if (data.requestId && pendingRequests.has(data.requestId)) {
            const { resolve, reject } = pendingRequests.get(data.requestId)
            pendingRequests.delete(data.requestId)

            if (data.error) {
                reject(new Error(data.error))
            } else {
                resolve(data)
            }
        }
    })

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
                    ? ['startSession', 'endSession', 'getStats', 'getFindings', 'exportScan', 'getSessionProgress']
                    : [],
                automationEnabled: enabled,
                error: enabled ? undefined : 'automation_disabled'
            }
        },

        /**
         * Start a security scanning session (ASYNC - returns Promise)
         * @param {Object} options
         * @param {string} options.project - Project identifier
         * @param {string[]} options.engines - Engines: ['DAST', 'IAST', 'SAST', 'SCA']
         * @param {string} options.policyCode - Scan policy
         * @param {string} options.testRunId - Test run ID for correlation
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
                        runCve: options.runCve === true
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
         * End session and get results
         * @param {Object} options
         * @param {boolean} options.wait - If false, return immediately and stop in background (default true)
         * @param {boolean} options.includeFindings - Include findings in response (only if wait=true)
         * @param {number} options.limit - Max findings to include
         * @returns {Promise<{ok, summary}>}
         */
        async endSession(options = {}) {
            if (this._automationEnabled === false) {
                return { ok: false, error: 'automation_disabled' }
            }
            // Background looks up session by tabId - no need to check locally
            try {
                const response = await sendMessage('session-end', {
                    sessionId: currentSessionId,
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
         * Get session progress (fast, non-blocking)
         * Use for polling during stop+wait pattern
         *
         * @param {Object} options
         * @param {string} options.sessionId - Optional, defaults to current/last session
         * @returns {Promise<{ok, sessionId, status, engines, summary, ...}>}
         */
        async getSessionProgress(options = {}) {
            if (this._automationEnabled === false) {
                return { ok: false, error: 'automation_disabled' }
            }

            try {
                return await sendMessage('get-session-progress', { options })
            } catch (err) {
                return { ok: false, error: err.message }
            }
        },

        /**
         * Get current session statistics
         * @returns {Promise<{findingsCount: number, bySeverity: Object}>}
         */
        async getStats() {
            if (this._automationEnabled === false) {
                return { findingsCount: 0, bySeverity: {} }
            }
            // Background looks up session by tabId
            try {
                const response = await sendMessage('get-stats', { sessionId: currentSessionId })
                if (response.error) throw new Error(response.error)
                return { findingsCount: response.findingsCount || 0, bySeverity: response.bySeverity || {} }
            } catch {
                return { findingsCount: 0, bySeverity: {} }
            }
        },

        /**
         * Get findings (capped for performance)
         * Returns { findings, truncated }
         * @param {number} limit - Max findings to return (default 100, max 500)
         * @returns {Promise<{findings: Array, truncated: boolean}>}
         */
        async getFindings(limit = 100) {
            if (this._automationEnabled === false) {
                return { findings: [], truncated: false }
            }
            // Background looks up session by tabId
            try {
                const response = await sendMessage('get-findings', {
                    sessionId: currentSessionId,
                    limit: Math.min(limit, 500)
                })
                if (response.error) throw new Error(response.error)
                return {
                    findings: response.findings || [],
                    truncated: response.truncated || false
                }
            } catch {
                return { findings: [], truncated: false }
            }
        },

        /**
         * Export scan payload (independent from endSession, requires completion)
         * Always returns { scans: [...] } for consistency
         * @param {Object} options
         * @returns {Promise<{ok, scans, truncatedAny, warnings}>}
         */
        async exportScan(options = {}) {
            if (this._automationEnabled === false) {
                return { ok: false, error: 'automation_disabled' }
            }

            try {
                const response = await sendMessage('export-scan', { options })
                if (response.error) {
                    return {
                        ok: false,
                        error: response.error,
                        warnings: response.warnings || []
                    }
                }
                return response
            } catch (err) {
                return { ok: false, error: err.message }
            }
        },

        isAvailable() { return true },
        getSessionId() { return currentSessionId },
        _automationEnabled: initialAutomationEnabled
    }

    window.dispatchEvent(new CustomEvent('ptk-automation-ready', { detail: { version: VERSION } }))
})()
