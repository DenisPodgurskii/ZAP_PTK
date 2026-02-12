/* Author: Denis Podgurskii */
'use strict'

import { zapBridge } from './integration/zap/index.js'
import buildExportScanResult from './export/buildExportScanResult.js'
import { resultsRegistry } from './resultsRegistry.js'


/**
 * Helper: wait until condition is true or timeout
 */
async function waitUntil(conditionFn, timeoutMs = 30000, pollMs = 100) {
    const start = Date.now()
    while (Date.now() - start < timeoutMs) {
        if (conditionFn()) return true
        await new Promise(r => setTimeout(r, pollMs))
    }
    return false
}

/**
 * Engine adapter interface - abstracts engine-specific methods
 * DAST uses startAutomationSession/stopAutomationSession end-to-end
 * stop() waits until isRunning() becomes false
 */
class EngineAdapter {
    constructor(app, automationModule) {
        this.app = app
        this.automationModule = automationModule  // Reference to ptk_automation for session tracking
    }

    // DAST adapter - uses automation session API for consistency
    dast = {
        isRunning: () => {
            const val = this.app?.rattacker?.engine?.isRunning
            return typeof val === 'function' ? val() : !!val
        },
        start: async (sessionId, tabId, host, options) => {
            const rattacker = this.app?.rattacker
            if (!rattacker) throw new Error('dast_not_available')
            // Use startAutomationSession for proper session tracking
            await rattacker.startAutomationSession({
                sessionId,
                tabId,
                host,
                domains: host,
                settings: {
                    scanStrategy: options?.policyCode || 'SMART',
                    runCve: options?.runCve === true
                },
                policyCode: options?.policyCode,
                hooks: {
                    onTaskStarted: () => {},
                    onTaskFinished: () => {}
                }
            })
        },
        stop: async (sessionId, timeoutMs = 180000) => {
            const rattacker = this.app?.rattacker
            if (!rattacker?.automationSession) return this._createEmptyStats()
            // Use stopAutomationSession which waits for idle and returns stats
            return rattacker.stopAutomationSession(sessionId, timeoutMs)
        },
        getStats: () => this._extractStats(this.app?.rattacker?.scanResult),
        getFindings: (limit = 100) => this._extractFindings(this.app?.rattacker?.scanResult, limit, 'DAST'),
        getScanId: () => this.app?.rattacker?.scanResult?.scanId || null
    }

    // IAST adapter
    iast = {
        isRunning: () => this.app?.iast?.isScanRunning || false,
        start: async (sessionId, tabId, host, options) => {
            const iast = this.app?.iast
            if (!iast) throw new Error('iast_not_available')
            // Just call runBackgroundScan - it handles "already running" internally by returning false
            await iast.runBackgroundScan(tabId, host, options?.policyCode || 'SMART')
            const ready = await this.automationModule?._waitForIastAgentReady?.(tabId, 5000)
            if (!ready) {
                throw new Error('iast_agent_not_ready')
            }
            return { ok: true }
        },
        stop: async (sessionId, timeoutMs = 60000) => {
            const iast = this.app?.iast
            if (!iast?.isScanRunning) return this._createEmptyStats()
            iast.stopBackgroundScan()
            // Wait until scan actually stops
            await waitUntil(() => !iast.isScanRunning, timeoutMs)
            return this._extractStats(iast.scanResult)
        },
        getStats: () => this._extractStats(this.app?.iast?.scanResult),
        getFindings: (limit = 100) => this._extractFindings(this.app?.iast?.scanResult, limit, 'IAST'),
        getScanId: () => this.app?.iast?.scanResult?.scanId || this.app?.iast?.currentScanId || null
    }

    // SAST adapter
    sast = {
        isRunning: () => this.app?.sast?.isScanRunning || false,
        start: async (sessionId, tabId, host, options) => {
            const sast = this.app?.sast
            if (!sast) throw new Error('sast_not_available')
            await sast.runBackgroundScan(tabId, host, { policyCode: options?.policyCode || 'SMART' })
        },
        stop: async (sessionId, timeoutMs = 60000) => {
            const sast = this.app?.sast
            if (!sast?.isScanRunning) return this._createEmptyStats()
            sast.stopBackgroundScan()
            await waitUntil(() => !sast.isScanRunning, timeoutMs)
            return this._extractStats(sast.scanResult)
        },
        getStats: () => this._extractStats(this.app?.sast?.scanResult),
        getFindings: (limit = 100) => this._extractFindings(this.app?.sast?.scanResult, limit, 'SAST'),
        getScanId: () => this.app?.sast?.scanResult?.scanId || null
    }

    // SCA adapter
    sca = {
        isRunning: () => this.app?.sca?.isScanRunning || false,
        start: async (sessionId, tabId, host, options) => {
            const sca = this.app?.sca
            if (!sca) throw new Error('sca_not_available')
            // Just call runBackgroundScan - it handles "already running" internally
            await sca.runBackgroundScan(tabId, host)
        },
        stop: async (sessionId, timeoutMs = 60000) => {
            const sca = this.app?.sca
            if (!sca?.isScanRunning) return this._createEmptyStats()
            sca.stopBackgroundScan()
            await waitUntil(() => !sca.isScanRunning, timeoutMs)
            return this._extractStats(sca.scanResult)
        },
        getStats: () => this._extractStats(this.app?.sca?.scanResult),
        getFindings: (limit = 100) => this._extractFindings(this.app?.sca?.scanResult, limit, 'SCA'),
        getScanId: () => this.app?.sca?.scanResult?.scanId || null
    }

    _createEmptyStats() {
        return { findingsCount: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }
    }

    // Compute stats from actual findings array
    _extractStats(scanResult) {
        const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        const stats = this._createEmptyStats()

        for (const finding of findings) {
            stats.findingsCount++
            const sev = (finding.severity || finding.effectiveSeverity || 'info').toLowerCase()
            if (stats.bySeverity.hasOwnProperty(sev)) {
                stats.bySeverity[sev]++
            } else {
                stats.bySeverity.info++
            }
        }
        return stats
    }

    // Extract findings with limit
    _extractFindings(scanResult, limit = 100, engine = 'unknown') {
        const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        return findings.slice(0, limit).map(f => ({
            id: f.id || f.findingId,
            title: f.title || f.name,
            severity: f.severity || f.effectiveSeverity || 'info',
            category: f.category || f.ruleId,
            url: f.url || f.location?.url,
            engine: f.engine || scanResult?.engine || engine
        }))
    }

    getAdapter(engine) {
        const adapters = { DAST: this.dast, IAST: this.iast, SAST: this.sast, SCA: this.sca }
        return adapters[engine.toUpperCase()]
    }
}


export class ptk_automation {
    constructor() {
        this.sessions = new Map()             // sessionId -> session
        this.activeSessionByTabId = new Map() // tabId -> sessionId (enforce single session per tab)
        this.lastCompletedSessionByTabId = new Map() // tabId -> sessionId
        this.lastCompletedSessionGlobal = null       // fallback for any-tab export
        this.MAX_COMPLETED_SESSIONS = 20
        this.SESSION_TTL_MS = 24 * 60 * 60 * 1000
        this.app = null
        this.engines = null
        this.zap = zapBridge                  // ZAP integration module
        this.addMessageListeners()
    }

    init(app) {
        this.app = app
        this.engines = new EngineAdapter(app, this)
        resultsRegistry.init(app)
        this.zap.init(app, resultsRegistry)
    }

    /**
     * Check if ZAP mode is active
     * @returns {boolean}
     */
    isZapActive() {
        return this.zap.isActive()
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    /**
     * Check if automation is enabled in settings
     * Uses in-memory settings from app.settings (no storage read needed)
     * @returns {boolean}
     */
    isAutomationEnabled() {
        const enabled = this.app?.settings?.automation?.enable === true
        console.log('[PTK Automation] isAutomationEnabled check:', {
            hasApp: !!this.app,
            hasSettings: !!this.app?.settings,
            automation: this.app?.settings?.automation,
            enabled
        })
        return enabled
    }

    onMessage(message, sender, sendResponse) {
        if (message.channel !== 'ptk_content2background_automation') {
            return false  // Explicitly indicate we don't handle this message
        }

        // Security check: verify automation is enabled in settings
        if (!this.isAutomationEnabled()) {
            console.warn('[PTK Automation] Automation is disabled in settings, rejecting request')
            sendResponse({ error: 'automation_disabled', requestId: message.requestId })
            return true
        }

        // Use sendResponse pattern for Chrome MV3 compatibility
        // This is more reliable than returning a Promise when multiple listeners exist
        ;(async () => {
            console.log('[PTK Automation] Received message:', message.type, message)

            const type = (message.type || '').replace(/-/g, '_')
            const handler = this['msg_' + type]
            if (handler) {
                const result = await handler.call(this, message, sender)
                console.log('[PTK Automation] Response:', result)
                return result
            }
            console.warn('[PTK Automation] Unknown message type:', type)
            return { error: 'unknown_message_type', requestId: message.requestId }
        })().then(result => {
            sendResponse(result)
        }).catch(e => {
            console.error('[PTK Automation] Error:', e)
            sendResponse({ error: e.message, requestId: message.requestId })
        })

        return true  // Indicate async response via sendResponse
    }

    // === Session Lifecycle ===

    async msg_session_start(message, sender) {
        console.log('[PTK Automation] msg_session_start called', { message, sender: sender?.tab?.id })
        const { options, pageUrl, requestId } = message
        const tabId = sender?.tab?.id

        if (!tabId) {
            console.error('[PTK Automation] No tab context')
            return { error: 'no_tab_context', requestId }
        }

        // Enforce single session per tab
        const existingSessionId = this.activeSessionByTabId.get(tabId)
        if (existingSessionId) {
            const existingSession = this.sessions.get(existingSessionId)
            if (existingSession && existingSession.status === 'running') {
                return { error: 'session_already_running_in_tab', existingSessionId, requestId }
            }
            // Clean up stale session
            this.sessions.delete(existingSessionId)
            this.activeSessionByTabId.delete(tabId)
        }

        // Background generates the sessionId (single source of truth)
        const sessionId = this._generateSessionId()
        const host = this._extractHost(pageUrl)
        const engines = this._normalizeEngines(options?.engines)

        const session = {
            id: sessionId,
            tabId,
            host,
            project: options?.project || null,
            testRunId: options?.testRunId || null,
            engines,
            policyCode: options?.policyCode || null,
            runCve: options?.runCve === true,
            startedAt: new Date().toISOString(),
            finishedAt: null,
            status: 'starting',
            scanIds: {},
            engineStates: {}
        }

        // Store session BEFORE starting engines (so we can track partial failures)
        this.sessions.set(sessionId, session)
        this.activeSessionByTabId.set(tabId, sessionId)

        try {
            await this._startEngines(session)
            session.status = 'running'
            return { sessionId, status: 'started', requestId }
        } catch (err) {
            session.status = 'error'
            session.error = err.message
            return { sessionId, status: 'error', error: err.message, requestId }
        }
    }

    async msg_session_end(message, sender) {
        const { requestId, wait = true } = message  // NEW: wait parameter
        const tabId = sender?.tab?.id

        // Look up session by tabId (background is source of truth)
        let sessionId = message.sessionId
        if (!sessionId && tabId) {
            sessionId = this.activeSessionByTabId.get(tabId)
        }

        const session = this.sessions.get(sessionId)
        if (!session) {
            return { error: 'session_not_found', requestId }
        }

        // === Non-blocking stop (wait=false) ===
        if (wait === false) {
            // Mark stop requested
            session.stopRequestedAt = new Date().toISOString()
            session.status = 'stopping'

            // Fire-and-forget stop with completion handler
            this._stopEnginesAsync(session)
                .then(stats => {
                    this._finalizeSession(session, stats)
                })
                .catch(err => {
                    console.error('[PTK Automation] Async stop failed', err)
                    session.status = 'error'
                    session.error = err.message
                })

            // Return immediately
            // NOTE: Do NOT clear activeSessionByTabId yet - wait until completed
            return {
                ok: true,
                requestId,
                summary: { status: 'stopping' }
            }
        }

        // === Blocking stop (wait=true, existing behavior) ===
        try {
            const stats = await this._stopEngines(session)
            this._finalizeSession(session, stats)

            let findingsPayload = null
            if (message.includeFindings === true) {
                const limit = Math.min(Number(message.limit) || 100, 500)
                const { findings, truncated } = this._collectFindings(session, limit)
                findingsPayload = { findings, truncated }
            }

            return {
                ok: true,
                requestId,
                summary: session.summary,
                ...(findingsPayload || {})
            }
        } catch (err) {
            session.status = 'error'
            session.error = err.message
            return { ok: false, error: err.message, requestId }
        }
    }

    async msg_get_stats(message, sender) {
        const { requestId } = message
        const tabId = sender?.tab?.id

        // Look up session by tabId (background is source of truth)
        let sessionId = message.sessionId
        if (!sessionId && tabId) {
            sessionId = this.activeSessionByTabId.get(tabId)
        }

        const session = this.sessions.get(sessionId)
        if (!session) {
            return { error: 'session_not_found', requestId }
        }

        const stats = this._collectCurrentStats(session)
        return {
            findingsCount: stats.findingsCount,
            bySeverity: stats.bySeverity,
            requestId
        }
    }

    // Return { findings, truncated }
    async msg_get_findings(message, sender) {
        const { requestId, limit = 100 } = message
        const tabId = sender?.tab?.id

        // Look up session by tabId (background is source of truth)
        let sessionId = message.sessionId
        if (!sessionId && tabId) {
            sessionId = this.activeSessionByTabId.get(tabId)
        }

        const session = this.sessions.get(sessionId)
        if (!session) {
            return { error: 'session_not_found', requestId }
        }

        const cappedLimit = Math.min(limit, 500)
        const { findings, truncated } = this._collectFindings(session, cappedLimit)
        return { findings, truncated, requestId }
    }

    /**
     * Get session progress (fast, non-blocking)
     * Used for polling during stop+wait pattern
     */
    async msg_get_session_progress(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id

        // === Session Resolution ===
        let sessionId = options.sessionId
        if (!sessionId && tabId) {
            // Priority: active > last completed for tab > global
            sessionId = this.activeSessionByTabId.get(tabId)
                || this.lastCompletedSessionByTabId.get(tabId)
        }
        if (!sessionId) {
            sessionId = this.lastCompletedSessionGlobal
        }

        const session = this.sessions.get(sessionId)
        if (!session) {
            return { ok: false, error: 'session_not_found', requestId }
        }

        // === Build Progress Response ===
        const now = Date.now()
        const startedAtMs = session.startedAt ? Date.parse(session.startedAt) : now
        const elapsedMs = now - startedAtMs

        // Derive session-level status
        const sessionStatus = this._deriveSessionStatus(session)

        // Build per-engine progress
        const enginesProgress = {}
        let totalFindingsCount = 0
        const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        let latestActivityAt = null

        for (const engineName of session.engines) {
            const engineState = session.engineStates[engineName] || {}
            const progress = this._getEngineProgress(engineName, engineState)
            enginesProgress[engineName] = progress

            totalFindingsCount += progress.findingsCount || 0

            // Aggregate severity counts
            if (progress.bySeverity) {
                for (const sev of Object.keys(bySeverity)) {
                    bySeverity[sev] += progress.bySeverity[sev] || 0
                }
            }

            // Track latest activity (for stuck detection)
            if (progress.lastActivityAt) {
                const activityMs = Date.parse(progress.lastActivityAt)
                if (!latestActivityAt || activityMs > Date.parse(latestActivityAt)) {
                    latestActivityAt = progress.lastActivityAt
                }
            }
        }

        return {
            ok: true,
            requestId,
            sessionId: session.id,
            status: sessionStatus,
            startedAt: session.startedAt,
            finishedAt: session.finishedAt,
            stopRequestedAt: session.stopRequestedAt || null,
            elapsedMs,
            lastUpdatedAt: latestActivityAt,  // null if no real activity timestamps
            engines: enginesProgress,
            summary: {
                findingsCount: totalFindingsCount,
                bySeverity
            },
            // Include final summary if completed
            ...(sessionStatus === 'completed' && session.summary ? { finalSummary: session.summary } : {}),
            warnings: session.warnings || []
        }
    }

    async msg_export_scan(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id

        // Resolve session: explicit sessionId > last completed for tab > global last completed
        let sessionId = options.sessionId
        if (!sessionId && tabId) {
            sessionId = this.lastCompletedSessionByTabId.get(tabId)
        }
        if (!sessionId) {
            sessionId = this.lastCompletedSessionGlobal
        }

        const session = this.sessions.get(sessionId)
        if (!session) {
            return { ok: false, error: 'session_not_found', requestId }
        }
        if (session.status !== 'completed') {
            return {
                ok: false,
                error: 'session_not_completed',
                hint: 'Call end_session() before export_scan_payload()',
                requestId
            }
        }

        const requestedEngine = (options.engine || 'ALL').toUpperCase().trim()
        const validEngines = ['DAST', 'IAST', 'SAST', 'SCA', 'ALL']
        if (!validEngines.includes(requestedEngine)) {
            return { ok: false, error: 'invalid_engine', requestId }
        }

        const enginesToExport = requestedEngine === 'ALL'
            ? session.engines
            : [requestedEngine]

        const warnings = []
        const exports = []

        for (const engine of enginesToExport) {
            let scanId = session.scanIds[engine]
            if (!scanId) {
                scanId = resultsRegistry.findScanIdForEngine(engine, {
                    tabId: session.tabId,
                    host: session.host
                })
                if (scanId) {
                    session.scanIds[engine] = scanId
                }
            }

            if (!scanId) {
                warnings.push(`engine_result_missing:${engine}`)
                continue
            }

            try {
                const scanExport = await this._buildEngineExport(engine, scanId, session, options)
                exports.push(scanExport)
            } catch (err) {
                warnings.push(`export_failed:${engine}:${err.message}`)
            }
        }

        if (!exports.length) {
            return { ok: false, error: 'no_exportable_results', warnings, requestId }
        }

        return {
            ok: true,
            scans: exports,
            truncatedAny: exports.some(e => e.truncated),
            warnings,
            requestId
        }
    }

    // === Engine Coordination ===

    // Pass sessionId to adapters for DAST automation session
    async _startEngines(session) {
        const { id: sessionId, tabId, host, engines, policyCode, runCve } = session
        console.log('[PTK Automation] _startEngines', { sessionId, tabId, host, engines })

        if (!this.engines) {
            console.error('[PTK Automation] Engine adapters not initialized (this.engines is null)')
            throw new Error('engine_adapters_not_initialized')
        }

        for (const engineName of engines) {
            const adapter = this.engines.getAdapter(engineName)
            console.log('[PTK Automation] Getting adapter for', engineName, !!adapter)
            if (!adapter) {
                session.engineStates[engineName] = { status: 'error', error: 'adapter_not_found' }
                continue
            }

            try {
                console.log('[PTK Automation] Starting engine', engineName)
                const startResult = await adapter.start(sessionId, tabId, host, { policyCode, runCve })
                session.engineStates[engineName] = { status: 'running', startedAt: Date.now() }
                if (startResult?.warning) {
                    session.engineStates[engineName].warning = startResult.warning
                    console.warn('[PTK Automation] Engine started with warning', engineName, startResult.warning)
                }
                console.log('[PTK Automation] Engine started', engineName)
            } catch (err) {
                console.error('[PTK Automation] Engine start failed', engineName, err)
                session.engineStates[engineName] = { status: 'error', error: err.message }
            }
        }
    }

    // Use adapter.stop() which waits for idle
    async _stopEngines(session) {
        const stats = { findingsCount: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }

        for (const engineName of session.engines) {
            const adapter = this.engines.getAdapter(engineName)
            if (!adapter) continue

            try {
                // Adapter.stop() now waits for idle and returns stats
                const engineStats = await adapter.stop(session.id, 180000)
                this._mergeStats(stats, engineStats)
                session.engineStates[engineName] = { status: 'stopped' }
            } catch (err) {
                session.engineStates[engineName] = { status: 'error', error: err.message }
            }
        }

        return stats
    }

    /**
     * Stop engines asynchronously (fire-and-forget with completion tracking)
     * Updates engineStates as each engine stops
     */
    async _stopEnginesAsync(session) {
        const stats = this._createEmptyStats()

        // Mark all engines as stopping
        for (const engineName of session.engines) {
            session.engineStates[engineName] = session.engineStates[engineName] || {}
            session.engineStates[engineName].status = 'stopping'
        }

        // Stop each engine with individual error handling
        const stopPromises = session.engines.map(async (engineName) => {
            const adapter = this.engines?.getAdapter(engineName)
            if (!adapter) {
                session.engineStates[engineName].status = 'error'
                session.engineStates[engineName].error = 'adapter_not_found'
                return
            }

            try {
                const engineStats = await adapter.stop(session.id)
                session.engineStates[engineName].status = 'stopped'

                // Aggregate stats
                stats.findingsCount += engineStats?.findingsCount || 0
                for (const sev of Object.keys(stats.bySeverity)) {
                    stats.bySeverity[sev] += engineStats?.bySeverity?.[sev] || 0
                }
            } catch (err) {
                console.error('[PTK Automation] Engine stop failed', engineName, err)
                session.engineStates[engineName].status = 'error'
                session.engineStates[engineName].error = err.message
            }
        })

        await Promise.all(stopPromises)
        return stats
    }

    _createEmptyStats() {
        return {
            findingsCount: 0,
            bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        }
    }

    /**
     * Finalize session after engines stopped
     * Called from both sync and async stop paths
     */
    _finalizeSession(session, stats) {
        // Final scanId capture
        this._finalScanIdCapture(session)

        session.finishedAt = new Date().toISOString()
        session.status = 'completed'

        // Store summary for get-session-progress to return
        session.summary = {
            status: 'completed',
            stats: {
                findingsCount: stats.findingsCount,
                bySeverity: stats.bySeverity
            }
        }

        // Update tracking for export
        this.lastCompletedSessionByTabId.set(session.tabId, session.id)
        this.lastCompletedSessionGlobal = session.id

        // NOW clear active mapping (session is truly done)
        if (this.activeSessionByTabId.get(session.tabId) === session.id) {
            this.activeSessionByTabId.delete(session.tabId)
        }

        // Enforce retention
        this._enforceSessionRetention()

        console.log('[PTK Automation] Session finalized', session.id)
    }

    _finalScanIdCapture(session) {
        for (const engineName of session.engines) {
            if (session.scanIds[engineName]) continue

            const adapter = this.engines?.getAdapter(engineName)
            const scanId = adapter?.getScanId?.() || null

            if (scanId) {
                session.scanIds[engineName] = scanId
                console.log('[PTK Automation] Final capture scanId for', engineName, scanId)
                continue
            }

            const fallbackId = resultsRegistry.findScanIdForEngine(engineName, {
                tabId: session.tabId,
                host: session.host
            })

            if (fallbackId) {
                session.scanIds[engineName] = fallbackId
                console.log('[PTK Automation] Registry fallback scanId for', engineName, fallbackId)
            } else {
                session.engineStates[engineName] = session.engineStates[engineName] || {}
                session.engineStates[engineName].warning = 'scan_id_not_available'
            }
        }
    }

    async _buildEngineExport(engine, scanId, session, options = {}) {
        const {
            includeBodies = true,
            includeEvidence = true,
            maxExportBytes = 25 * 1024 * 1024
        } = options

        const scanResult = resultsRegistry.get(engine, scanId)
        if (!scanResult) {
            throw new Error(`scan_result_not_found:${engine}`)
        }

        let exported = buildExportScanResult(scanId, { scanResult })
        if (!exported) {
            throw new Error(`export_build_failed:${engine}`)
        }

        exported.meta = exported.meta || {}
        exported.meta.automation = {
            sessionId: session.id,
            testRunId: session.testRunId,
            project: session.project,
            policyCode: session.policyCode,
            startedAt: session.startedAt,
            finishedAt: session.finishedAt,
            durationMs: session.finishedAt && session.startedAt
                ? Date.parse(session.finishedAt) - Date.parse(session.startedAt)
                : null,
            ptkVersion: this.app?.version || 'unknown',
            schemaVersion: 1
        }

        let bodiesStrippedByPolicy = false
        let evidenceStrippedByPolicy = false

        if (includeBodies === false) {
            this._stripBodiesInPlace(exported)
            bodiesStrippedByPolicy = true
        }

        if (includeEvidence === false) {
            this._stripEvidenceInPlace(exported)
            evidenceStrippedByPolicy = true
        }

        if (bodiesStrippedByPolicy || evidenceStrippedByPolicy) {
            exported.meta.privacy = {
                bodiesIncluded: !bodiesStrippedByPolicy,
                evidenceIncluded: !evidenceStrippedByPolicy
            }
        }

        let estimatedBytes = this._estimateBytes(exported)
        let truncated = false
        const truncationMeta = { applied: false }

        if (estimatedBytes > maxExportBytes) {
            if (includeBodies === true) {
                this._stripBodiesInPlace(exported)
                truncationMeta.applied = true
                truncationMeta.bodiesStrippedForSize = true

                exported.meta.privacy = exported.meta.privacy || {}
                exported.meta.privacy.bodiesIncluded = false

                truncated = true
                estimatedBytes = this._estimateBytes(exported)
            }

            if (estimatedBytes > maxExportBytes) {
                const originalCount = exported.findings?.length || 0
                const { keptCount, droppedCount, reason } = this._truncateFindings(
                    exported,
                    maxExportBytes
                )

                truncationMeta.applied = true
                truncationMeta.findingsTruncated = true
                truncationMeta.findingsOriginal = originalCount
                truncationMeta.findingsReturned = keptCount
                truncationMeta.findingsDropped = droppedCount

                if (reason === 'base_payload_exceeds_limit') {
                    truncationMeta.reason = reason
                }

                truncated = true
                estimatedBytes = this._estimateBytes(exported)
            }

            if (estimatedBytes > maxExportBytes) {
                throw new Error('export_too_large')
            }
        }

        if (truncationMeta.applied) {
            exported.meta.truncation = truncationMeta
        }

        return {
            engine,
            scan: exported,
            estimatedBytes,
            truncated
        }
    }

    _estimateBytes(obj) {
        const str = JSON.stringify(obj)
        if (typeof TextEncoder !== 'undefined') {
            return new TextEncoder().encode(str).length
        }
        return unescape(encodeURIComponent(str)).length
    }

    _stripBodiesInPlace(exported) {
        const strip = (httpMsg) => {
            if (!httpMsg) return
            if (httpMsg.body !== undefined) httpMsg.body = '[STRIPPED]'
            if (httpMsg.raw !== undefined) httpMsg.raw = '[STRIPPED]'
        }

        if (Array.isArray(exported.findings)) {
            for (const finding of exported.findings) {
                const dast = finding?.evidence?.dast
                if (!dast) continue
                strip(dast.request)
                strip(dast.response)
                strip(dast.original?.request)
                strip(dast.original?.response)
                strip(dast.attack?.request)
                strip(dast.attack?.response)
            }
        }

        if (Array.isArray(exported.requests)) {
            for (const req of exported.requests) {
                strip(req?.original?.request)
                strip(req?.original?.response)
            }
        }
    }

    _stripEvidenceInPlace(exported) {
        if (!Array.isArray(exported.findings)) return

        const stripValue = (val) => {
            if (val == null) return val
            if (Array.isArray(val)) return []
            if (typeof val === 'object') return {}
            return '[STRIPPED]'
        }

        for (const finding of exported.findings) {
            finding.evidenceStripped = true
            if (!finding.evidence) continue

            if (finding.evidence.dast) {
                const dast = finding.evidence.dast
                if (dast.proof != null) dast.proof = stripValue(dast.proof)
                if (dast.payload != null) dast.payload = stripValue(dast.payload)

                const stripHttp = (msg) => {
                    if (!msg) return
                    if (msg.body !== undefined) msg.body = '[STRIPPED]'
                    if (msg.raw !== undefined) msg.raw = '[STRIPPED]'
                }
                stripHttp(dast.request)
                stripHttp(dast.response)
                stripHttp(dast.original?.request)
                stripHttp(dast.original?.response)
                stripHttp(dast.attack?.request)
                stripHttp(dast.attack?.response)
            }

            if (finding.evidence.iast) {
                const iast = finding.evidence.iast
                if (iast.trace != null) iast.trace = stripValue(iast.trace)
                if (iast.stack != null) iast.stack = stripValue(iast.stack)
                if (iast.frames != null) iast.frames = stripValue(iast.frames)
                if (iast.matched != null) iast.matched = stripValue(iast.matched)
                if (iast.context) {
                    if (iast.context.html != null) iast.context.html = '[STRIPPED]'
                    if (iast.context.outerHTML != null) iast.context.outerHTML = '[STRIPPED]'
                    if (iast.context.elementOuterHTML != null) iast.context.elementOuterHTML = '[STRIPPED]'
                }
            }

            if (finding.evidence.sast) {
                const sast = finding.evidence.sast
                if (sast.codeSnippet != null) sast.codeSnippet = stripValue(sast.codeSnippet)
                if (sast.flow != null) sast.flow = stripValue(sast.flow)
                if (sast.trace != null) sast.trace = stripValue(sast.trace)
            }

            if (finding.evidence.sca) {
                const sca = finding.evidence.sca
                if (sca.summary != null) sca.summary = stripValue(sca.summary)
            }
        }
    }

    _truncateFindings(exported, maxBytes) {
        const findings = Array.isArray(exported.findings) ? [...exported.findings] : []
        if (!findings.length) return { keptCount: 0, droppedCount: 0 }

        const minViableExport = { ...exported, findings: [] }
        if (this._estimateBytes(minViableExport) > maxBytes) {
            exported.findings = []
            return { keptCount: 0, droppedCount: findings.length, reason: 'base_payload_exceeds_limit' }
        }

        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

        findings.sort((a, b) => {
            const sevA = severityOrder[(a.severity || a.effectiveSeverity || 'info').toLowerCase()] ?? 5
            const sevB = severityOrder[(b.severity || b.effectiveSeverity || 'info').toLowerCase()] ?? 5
            if (sevA !== sevB) return sevA - sevB

            const confA = a.confidence ?? a.effectiveConfidence ?? 0
            const confB = b.confidence ?? b.effectiveConfidence ?? 0
            if (confA !== confB) return confB - confA

            return (a.id || '').localeCompare(b.id || '')
        })

        const originalCount = findings.length

        let lo = 0
        let hi = findings.length
        while (lo < hi) {
            const mid = Math.ceil((lo + hi) / 2)
            exported.findings = findings.slice(0, mid)
            const bytes = this._estimateBytes(exported)
            if (bytes <= maxBytes) {
                lo = mid
            } else {
                hi = mid - 1
            }
        }

        exported.findings = findings.slice(0, lo)

        return {
            keptCount: lo,
            droppedCount: originalCount - lo
        }
    }

    _enforceSessionRetention() {
        const now = Date.now()
        const completedSessions = []

        for (const [id, session] of this.sessions) {
            if (session.status === 'completed' && session.finishedAt) {
                completedSessions.push({
                    id,
                    finishedAt: new Date(session.finishedAt).getTime()
                })
            }
        }

        completedSessions.sort((a, b) => a.finishedAt - b.finishedAt)

        for (const { id, finishedAt } of completedSessions) {
            if (now - finishedAt > this.SESSION_TTL_MS) {
                this._evictSession(id)
            }
        }

        const remaining = completedSessions.filter(s => this.sessions.has(s.id))
        while (remaining.length > this.MAX_COMPLETED_SESSIONS) {
            const oldest = remaining.shift()
            this._evictSession(oldest.id)
        }
    }

    _evictSession(sessionId) {
        const session = this.sessions.get(sessionId)
        if (!session) return

        console.log('[PTK Automation] Evicting session', sessionId)
        this.sessions.delete(sessionId)

        if (this.lastCompletedSessionGlobal === sessionId) {
            this.lastCompletedSessionGlobal = null
        }
        for (const [tabId, sid] of this.lastCompletedSessionByTabId) {
            if (sid === sessionId) {
                this.lastCompletedSessionByTabId.delete(tabId)
            }
        }
    }

    cleanupCompletedSessions({ maxAge = null, keepCount = null } = {}) {
        const now = Date.now()
        const completedSessions = []

        for (const [id, session] of this.sessions) {
            if (session.status === 'completed' && session.finishedAt) {
                const age = now - new Date(session.finishedAt).getTime()
                if (maxAge && age > maxAge) {
                    this._evictSession(id)
                } else {
                    completedSessions.push({ id, finishedAt: new Date(session.finishedAt).getTime() })
                }
            }
        }

        if (keepCount !== null) {
            completedSessions.sort((a, b) => a.finishedAt - b.finishedAt)
            while (completedSessions.length > keepCount) {
                const oldest = completedSessions.shift()
                this._evictSession(oldest.id)
            }
        }
    }

    // === Utility Methods ===

    _generateSessionId() {
        return `ptk-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    }

    _extractHost(url) {
        try { return new URL(url).host } catch { return url }
    }

    _normalizeEngines(engines) {
        const valid = ['DAST', 'IAST', 'SAST', 'SCA']
        if (!Array.isArray(engines) || engines.length === 0) return ['DAST']
        return engines.map(e => String(e).toUpperCase().trim()).filter(e => valid.includes(e))
    }

    async _checkIastContentReady(tabId) {
        if (!tabId) return false
        if (this.app?.iast?.isAgentReady && this.app.iast.isAgentReady(tabId)) {
            return true
        }
        if (!browser?.tabs?.sendMessage) return false
        try {
            await browser.tabs.sendMessage(tabId, {
                channel: 'ptk_background_iast2content',
                type: 'ping'
            })
            return true
        } catch (e) {
            return false
        }
    }

    async _waitForIastAgentReady(tabId, timeoutMs = 5000, pollMs = 100) {
        const start = Date.now()
        const hasAgentProbe = !!this.app?.iast?.isAgentReady
        while (Date.now() - start < timeoutMs) {
            if (hasAgentProbe && this.app.iast.isAgentReady(tabId)) {
                return true
            }
            // Fallback only when agent probe is unavailable.
            if (!hasAgentProbe && await this._checkIastContentReady(tabId)) {
                return true
            }
            await new Promise(r => setTimeout(r, pollMs))
        }
        return false
    }

    _mergeStats(target, source) {
        target.findingsCount += source?.findingsCount || 0
        const sev = source?.bySeverity || {}
        target.bySeverity.critical += sev.critical || 0
        target.bySeverity.high += sev.high || 0
        target.bySeverity.medium += sev.medium || 0
        target.bySeverity.low += sev.low || 0
        target.bySeverity.info += sev.info || 0
    }

    _collectCurrentStats(session) {
        const stats = { findingsCount: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }
        for (const engineName of session.engines) {
            const adapter = this.engines.getAdapter(engineName)
            if (adapter) {
                this._mergeStats(stats, adapter.getStats())
            }
        }
        return stats
    }

    // Returns { findings, truncated }
    _collectFindings(session, limit = 100) {
        const allFindings = []
        for (const engineName of session.engines) {
            const adapter = this.engines.getAdapter(engineName)
            if (adapter) {
                allFindings.push(...adapter.getFindings(limit + 1))  // Get more to check truncation
            }
        }
        const truncated = allFindings.length > limit
        return {
            findings: allFindings.slice(0, limit),
            truncated
        }
    }

    // === Session Progress Helpers ===

    /**
     * Derive session-level status from session and engine states
     */
    _deriveSessionStatus(session) {
        // Explicit status takes precedence
        if (session.status === 'completed') return 'completed'
        if (session.status === 'error') return 'error'
        if (session.status === 'stopping') return 'stopping'

        // Check if any engine has error
        const engineStates = session.engineStates || {}
        const hasError = Object.values(engineStates).some(s => s.status === 'error')
        if (hasError) return 'error'

        // Check if any engine is stopping
        const hasStopping = Object.values(engineStates).some(s => s.status === 'stopping')
        if (hasStopping) return 'stopping'

        // Check if all engines are stopped/completed
        const allStopped = session.engines.every(e => {
            const state = engineStates[e]
            return state?.status === 'stopped' || state?.status === 'completed'
        })
        if (allStopped && session.stopRequestedAt) return 'completed'

        // Default based on session.status
        return session.status || 'running'
    }

    /**
     * Get progress for a single engine (fast, no blocking)
     * Uses existing stats from scanResult, avoids scanning findings array
     */
    _getEngineProgress(engineName, engineState) {
        const engineUpper = engineName.toUpperCase()

        const result = {
            status: engineState.status || 'unknown',
            progress: { done: null, total: null },
            findingsCount: 0,
            bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            lastActivityAt: null,
            warnings: engineState.warnings ? [engineState.warnings] : []
        }

        if (engineState.error) {
            result.error = engineState.error
        }

        // Get scanResult reference (fast lookup, no deep copy)
        const scanResult = this._getEngineScanResult(engineUpper)
        if (!scanResult) return result

        // Use pre-computed stats if available (fast path)
        if (scanResult.stats) {
            result.findingsCount = scanResult.stats.findingsCount || 0
            result.bySeverity = scanResult.stats.bySeverity || result.bySeverity
        } else if (Array.isArray(scanResult.findings)) {
            // Fallback: count findings (avoid if possible)
            result.findingsCount = scanResult.findings.length
        }

        // Last activity timestamp
        result.lastActivityAt = scanResult.lastUpdatedAt
            || scanResult.updatedAt
            || engineState.lastActivityAt
            || null

        // Engine-specific progress
        if (engineUpper === 'DAST') {
            result.phase = this._getDastPhase()
            const scanStats = scanResult.scanStats || {}

            // Try various counter fields
            const total = scanStats.totalJobsPlanned
                ?? scanStats.total
                ?? scanStats.queued
                ?? null
            const done = scanStats.totalJobsExecuted
                ?? scanStats.processed
                ?? scanStats.executed
                ?? scanResult.requestCount
                ?? null

            result.progress = { done, total }
        } else {
            // IAST/SAST/SCA: limited progress info
            result.progress = {
                done: result.findingsCount,
                total: null
            }
        }

        return result
    }

    /**
     * Get scanResult reference for engine (fast, no copy)
     */
    _getEngineScanResult(engineUpper) {
        const sources = {
            DAST: () => this.app?.rattacker?.scanResult,
            IAST: () => this.app?.iast?.scanResult,
            SAST: () => this.app?.sast?.scanResult,
            SCA: () => this.app?.sca?.scanResult
        }
        return sources[engineUpper]?.() || null
    }

    /**
     * Get DAST phase if available
     */
    _getDastPhase() {
        const rattacker = this.app?.rattacker
        if (!rattacker) return null

        // Helper to safely check running state (could be function or boolean)
        const isRunning = (val) => typeof val === 'function' ? val() : !!val

        // Check various state indicators
        if (isRunning(rattacker.isSpiderRunning) || rattacker.spiderRunning) return 'spider'
        if (isRunning(rattacker.isActiveRunning) || rattacker.activeRunning) return 'active'
        if (isRunning(rattacker.engine?.isRunning) || rattacker.isRunning) return 'scanning'

        return 'idle'
    }
}
