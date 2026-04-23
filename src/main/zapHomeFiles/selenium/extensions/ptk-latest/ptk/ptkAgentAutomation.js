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
    function toAgentFailure(errorCode, fallback = 'unexpected_error') {
        errorCode = errorCode || fallback
        errorCode = PTK_AGENT_ERROR_CODE_ALIASES[errorCode] || errorCode
        return {
            ok: false,
            code: errorCode,
            message: PTK_AGENT_ERROR_MESSAGE_OVERRIDES[errorCode] || errorCode
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
                            warnings: []
                        }
                    }
                    return toAgentFailure(result?.error || 'session_status_failed', 'session_status_failed')
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
                }, result?.status ?? null)
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
                    return toAgentFailure(result?.error || 'get_findings_failed', 'get_findings_failed')
                }
                return {
                    ok: true,
                    findings: Array.isArray(result?.findings) ? result.findings : [],
                    truncated: result?.truncated === true
                }
            } catch (err) {
                return toAgentFailure(err?.message || 'get_findings_failed', 'get_findings_failed')
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

            const transfer = String(options?.transfer || '').trim()
            if (transfer && transfer !== 'retrieval-plan') {
                return toAgentFailure('unsupported_transfer_mode')
            }

            const exportOptions = {
                ...options,
                sessionScope: PTK_AGENT_SESSION_SCOPE,
                allowChunked: true,
                // Force the low-level exporter into chunked mode so exportFullReport
                // always returns a retrieval-plan descriptor instead of inline data.
                maxExportBytes: 1
            }
            delete exportOptions.transfer

            try {
                const result = await automation.exportScan(exportOptions)
                if (result?.ok === false) {
                    return {
                        ...toAgentFailure(result?.error || 'export_failed', 'export_failed'),
                        warnings: Array.isArray(result?.warnings) ? result.warnings : []
                    }
                }

                return {
                    ok: true,
                    mode: 'retrieval-plan',
                    scans: Array.isArray(result?.scans) ? result.scans : [],
                    truncatedAny: result?.truncatedAny === true,
                    warnings: Array.isArray(result?.warnings) ? result.warnings : []
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
