/* Author: Denis Podgurskii */
'use strict'

import { zapBridge } from './integration/zap/index.js'
import buildExportScanResult from './export/buildExportScanResult.js'
import { resultsRegistry } from './resultsRegistry.js'
import { collapseDastAggregatedFindings } from './dast/services/dastFindingAggregation.js'
import { sastCollectionLooksComplete } from './sast/sast_progress.js'


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

function toNonEmptyString(value) {
    if (typeof value !== 'string') return null
    const trimmed = value.trim()
    return trimmed || null
}

function toFiniteNumber(value, fallback = null) {
    const num = Number(value)
    return Number.isFinite(num) ? num : fallback
}

function cloneJsonSafe(value, { warnings = null, label = 'value' } = {}) {
    if (value === undefined || value === null) return null
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (err) {
        const message = `snapshot_clone_failed:${label}:${err?.message || String(err)}`
        if (Array.isArray(warnings) && warnings.length < 12) {
            warnings.push(message)
        }
        try {
            console.warn('[PTK Automation] Failed to clone analysis snapshot field', {
                label,
                error: err?.message || String(err)
            })
        } catch (_) { }
        return null
    }
}

const STRICT_CURRENT_TAB_SESSION_SCOPE = 'current-tab'
const ACTIVE_SESSION_STATUSES = new Set(['starting', 'running', 'stopping'])
// Keep findings responses bounded to the long-standing bridge/background cap.
const MAX_FINDINGS_LIMIT = 500
const ENGINE_STATUS_STARTING = 'starting'
const ENGINE_STATUS_RUNNING = 'running'
const ENGINE_STATUS_DEFERRED_START = 'deferred_start'
const ENGINE_STATUS_STOPPING = 'stopping'
const ENGINE_STATUS_STOPPED = 'stopped'
const ENGINE_STATUS_COMPLETED = 'completed'
const ENGINE_STATUS_ERROR = 'error'
const ZAP_DEFERRED_ENGINE_START_BASE_DELAY_MS = 1500
const ZAP_DEFERRED_ENGINE_START_SPREAD_MS = 500
const ZAP_DEFERRED_ENGINE_START_BUCKETS = 4
const ZAP_DEFERRED_ENGINE_PER_ENGINE_DELAY_MS = 1000
const CONTENT_RUNTIME_MODE_PENDING = 'pending'
const CONTENT_RUNTIME_MODE_MANUAL = 'manual'
const CONTENT_RUNTIME_MODE_AUTOMATION = 'automation'
const CONTENT_RUNTIME_SCRIPT_NONE = 'none'
const CONTENT_RUNTIME_SCRIPT_MANUAL = 'manual'
const CONTENT_RUNTIME_SCRIPT_AUTOMATION = 'automation'
const CONTENT_RUNTIME_FILES = Object.freeze({
    [CONTENT_RUNTIME_SCRIPT_MANUAL]: ['ptk/content_manual.js', 'ptk/content/spa_hash_harness.js'],
    [CONTENT_RUNTIME_SCRIPT_AUTOMATION]: ['ptk/content_automation.js']
})

function sleep(ms) {
    if (!(Number.isFinite(Number(ms)) && Number(ms) > 0)) {
        return Promise.resolve()
    }
    return new Promise((resolve) => setTimeout(resolve, Number(ms)))
}

function isAutomationDebugLoggingEnabled() {
    return globalThis.__PTK_AUTOMATION_DEBUG__ === true
}

function debugAutomationLog(...args) {
    if (!isAutomationDebugLoggingEnabled()) {
        return
    }
    console.log(...args)
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
            const val = (this.app?.dast || this.app?.rattacker)?.engine?.isRunning
            return typeof val === 'function' ? val() : !!val
        },
        start: async (sessionId, tabId, host, options) => {
            const dast = this.app?.dast || this.app?.rattacker
            if (!dast) throw new Error('dast_not_available')
            const dastSettings = {
                scanStrategy: options?.scanStrategy || options?.policyCode || 'SMART',
                runCve: options?.runCve === true
            }
            if (options?.dastScanPolicy) {
                dastSettings.dastScanPolicy = options.dastScanPolicy
            }
            if (options?.safetyProfile) {
                dastSettings.safetyProfile = options.safetyProfile
            }
            if (options?.scanControls && typeof options.scanControls === 'object') {
                dastSettings.scanControls = options.scanControls
            }
            const passthroughSettings = [
                'allowCaptureWithoutInteraction',
                'enableHtmlLinkDiscovery',
                'htmlLinkDiscoveryBudget',
                'enableSyntheticRedirectRequests',
                'zapManaged',
                'targetUrl',
                'pageUrl',
                'zapCallbackDetectedAt',
                'zapHistorySeedUrls',
                'zapHistorySeedCount',
                'zapHistorySeedTotalAvailable',
                'zapHistorySeedDroppedByCap',
                'zapSeedMaxRequests',
                'maxRequestsPerSecond',
                'concurrency',
                'planningConcurrency'
            ]
            for (const key of passthroughSettings) {
                if (Object.prototype.hasOwnProperty.call(options || {}, key)) {
                    dastSettings[key] = options[key]
                }
            }
            if (options?.policyId !== undefined && options?.policyId !== null && options?.policyId !== '') {
                dastSettings.policyId = options.policyId
            }
            if (options?.policyName) {
                dastSettings.policyName = options.policyName
            }
            if (options?.rulepack && typeof options.rulepack === 'object') {
                dastSettings.rulepack = options.rulepack
            }
            if (options?.cveRulepack && typeof options.cveRulepack === 'object') {
                dastSettings.cveRulepack = options.cveRulepack
            }
            // Use startAutomationSession for proper session tracking
            await dast.startAutomationSession({
                sessionId,
                tabId,
                host,
                domains: host,
                settings: dastSettings,
                policyCode: options?.policyCode,
                hooks: {
                    onTaskStarted: () => {},
                    onTaskFinished: () => {}
                }
            })
        },
        stop: async (sessionId, timeoutMs = 180000) => {
            const dast = this.app?.dast || this.app?.rattacker
            const automationState = this.automationModule?._getDastAutomationCoordinatorState?.(sessionId)
            if (!automationState?.automationSession) return this._createEmptyStats()
            // Use stopAutomationSession which waits for idle and returns stats
            return dast.stopAutomationSession(sessionId, timeoutMs)
        },
        getStats: () => this._extractStats((this.app?.dast || this.app?.rattacker)?.scanResult),
        getFindings: (limit = 100) => this._extractFindings((this.app?.dast || this.app?.rattacker)?.scanResult, limit, 'DAST'),
        getScanId: () => (this.app?.dast || this.app?.rattacker)?.scanResult?.scanId || null
    }

    // IAST adapter
    iast = {
        isRunning: () => this.app?.iast?.isScanRunning || false,
        start: async (sessionId, tabId, host, options) => {
            const iast = this.app?.iast
            if (!iast) throw new Error('iast_not_available')
            const iastOpts = {}
            if (options?.rulepack && typeof options.rulepack === 'object') {
                iastOpts.rulepack = options.rulepack
            }
            if (options?.preferPortal) {
                iastOpts.preferPortal = true
            }
            if (options?.policyId !== undefined && options?.policyId !== null && options?.policyId !== '') {
                iastOpts.policyId = options.policyId
            }
            if (options?.policyName) {
                iastOpts.policyName = options.policyName
            }
            if (options?.zapManaged === true) {
                iastOpts.zapManaged = true
            }
            if (options?.zapTiming && typeof options.zapTiming === 'object') {
                iastOpts.zapTiming = options.zapTiming
            }
            // Just call runBackgroundScan - it handles "already running" internally by returning false
            await iast.runBackgroundScan(tabId, host, options?.policyCode || 'SMART', iastOpts)
            if (options?.waitForReady === false) {
                return { ok: true }
            }
            const readyTimeoutMs = Number.isFinite(Number(options?.agentReadyTimeoutMs))
                ? Math.max(1000, Number(options.agentReadyTimeoutMs))
                : 15000
            const ready = await this.automationModule?._waitForIastAgentReady?.(tabId, readyTimeoutMs)
            if (!ready) {
                const failureReason = this.app?.iast?.agentFailedTabs?.get?.(tabId)
                if (failureReason) {
                    throw new Error(`iast_agent_failed:${failureReason}`)
                }
                console.warn('[PTK Automation] IAST agent readiness not confirmed; continuing in best-effort mode', {
                    tabId,
                    readyTimeoutMs
                })
                return { ok: true, warning: 'iast_agent_ready_not_confirmed' }
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
            const sastOpts = {}
            if (options?.rulepack && typeof options.rulepack === 'object') {
                sastOpts.rulepack = options.rulepack
            }
            if (options?.catalog && typeof options.catalog === 'object') {
                sastOpts.catalog = options.catalog
            }
            if (options?.preferPortal) {
                sastOpts.preferPortal = true
            }
            if (options?.policyId !== undefined && options?.policyId !== null && options?.policyId !== '') {
                sastOpts.policyId = options.policyId
            }
            if (options?.policyName) {
                sastOpts.policyName = options.policyName
            }
            if (options?.zapManaged === true) {
                sastOpts.zapManaged = true
            }
            if (options?.zapTiming && typeof options.zapTiming === 'object') {
                sastOpts.zapTiming = options.zapTiming
            }
            await sast.runBackgroundScan(tabId, host, { policyCode: options?.policyCode || 'SMART' }, sastOpts)
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
        const rawFindings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        const findings = collapseDastAggregatedFindings(rawFindings)
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
        const rawFindings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        const findings = collapseDastAggregatedFindings(rawFindings)
        return findings.slice(0, limit).map(f => ({
            id: f.id || f.findingId,
            title: f.title || f.name || f.ruleName || f.moduleName || f.ruleId || f.moduleId,
            severity: f.severity || f.effectiveSeverity || 'info',
            category: f.category || f.vulnId || f.ruleId || f.moduleId,
            url: f.url || f.location?.url,
            engine: f.engine || scanResult?.engine || engine,
            moduleId: f.moduleId || null,
            moduleName: f.moduleName || null,
            ruleId: f.ruleId || null,
            ruleName: f.ruleName || null,
            vulnId: f.vulnId || null,
            confidence: Number.isFinite(Number(f.confidence)) ? Number(f.confidence) : null,
            presentationAggregate: f.presentationAggregate || null,
            occurrenceCount: Number.isFinite(Number(f.evidence?.dast?.occurrenceCount))
                ? Number(f.evidence.dast.occurrenceCount)
                : null,
            aggregate: f.evidence?.dast?.aggregate || null,
            samples: Array.isArray(f.evidence?.dast?.samples) ? f.evidence.dast.samples : null
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
        this.evictedSessions = new Map()             // bounded diagnostics for missing-session failures
        this.MAX_COMPLETED_SESSIONS = 20
        this.SESSION_TTL_MS = 24 * 60 * 60 * 1000
        this.app = null
        this.engines = null
        this.zap = zapBridge                  // ZAP integration module
        this._unsubscribeZapContentRuntimeRefresh = null
        this.addMessageListeners()
    }

    init(app) {
        this.app = app
        this.engines = new EngineAdapter(app, this)
        resultsRegistry.init(app)
        this.zap.attach(app, resultsRegistry)
        if (!this._unsubscribeZapContentRuntimeRefresh && this.zap?.transport?.onZapDetected) {
            this._unsubscribeZapContentRuntimeRefresh = this.zap.transport.onZapDetected((payload) => {
                const tabId = Number.isInteger(payload?.tabId) ? payload.tabId : null
                if (tabId == null) return
                this._notifyContentRuntimeRefresh(tabId).catch(() => { })
            })
        }
    }

    _getSessionForTab(tabId) {
        if (!Number.isInteger(tabId)) return null
        const sessionId = this.activeSessionByTabId.get(tabId)
        if (!sessionId) return null
        return this.sessions.get(sessionId) || null
    }

    _isZapManagedActiveSessionForTab(tabId) {
        const session = this._getSessionForTab(tabId)
        if (!session || session.source !== 'zap') return false
        return this._isActiveSessionStatus(session.status)
    }

    _getContentRuntimeProfile({ tabId = null, frameId = 0, url = '' } = {}) {
        const safeUrl = typeof url === 'string' ? url : ''
        const isTopFrame = frameId === 0
        const transport = this.zap?.transport || null
        const startup = transport?.getStartupSnapshot?.() || { pending: false }
        const detectedPayload = transport?.getLastDetectedPayload?.() || null
        const detectedTabId = Number.isInteger(detectedPayload?.tabId) ? detectedPayload.tabId : null
        const isBootstrapUrl = transport?.isBootstrapUrl?.(safeUrl) === true
        const hasZapSession = this._isZapManagedActiveSessionForTab(tabId)
        const isDetectedAutomationTab = Number.isInteger(tabId) && Number.isInteger(detectedTabId) && tabId === detectedTabId
        const isZapAutomationTab = hasZapSession || isDetectedAutomationTab
        const isZapActive = transport?.isActive?.() === true

        if (!isTopFrame) {
            if (isZapAutomationTab || isBootstrapUrl) {
                return {
                    mode: isZapActive || isZapAutomationTab ? CONTENT_RUNTIME_MODE_AUTOMATION : CONTENT_RUNTIME_MODE_PENDING,
                    script: CONTENT_RUNTIME_SCRIPT_NONE,
                    reason: 'subframe_suppressed'
                }
            }
            return {
                mode: CONTENT_RUNTIME_MODE_MANUAL,
                script: CONTENT_RUNTIME_SCRIPT_MANUAL,
                reason: 'manual_subframe'
            }
        }

        if (isZapActive && (isZapAutomationTab || isBootstrapUrl)) {
            return {
                mode: CONTENT_RUNTIME_MODE_AUTOMATION,
                script: CONTENT_RUNTIME_SCRIPT_AUTOMATION,
                reason: 'zap_active'
            }
        }

        if (!isZapActive && startup.pending && isBootstrapUrl) {
            return {
                mode: CONTENT_RUNTIME_MODE_PENDING,
                script: CONTENT_RUNTIME_SCRIPT_NONE,
                reason: 'zap_bootstrap_pending'
            }
        }

        if (isZapAutomationTab) {
            return {
                mode: CONTENT_RUNTIME_MODE_AUTOMATION,
                script: CONTENT_RUNTIME_SCRIPT_AUTOMATION,
                reason: 'zap_tab_claimed'
            }
        }

        return {
            mode: CONTENT_RUNTIME_MODE_MANUAL,
            script: CONTENT_RUNTIME_SCRIPT_MANUAL,
            reason: 'manual_default'
        }
    }

    _isFirefoxRuntime() {
        return !!browser?.runtime?.getBrowserInfo
    }

    async _executeContentRuntimeFiles({ tabId = null, frameId = 0, files = [] } = {}) {
        if (!Number.isInteger(tabId) || tabId < 0) return false
        const normalizedFiles = Array.isArray(files)
            ? files.filter((value) => typeof value === 'string' && value.trim())
            : []
        if (!normalizedFiles.length) return false

        const isFirefox = this._isFirefoxRuntime()
        const manifestVersion = Number(browser?.runtime?.getManifest?.()?.manifest_version || 2)

        if (!isFirefox && manifestVersion >= 3 && browser?.scripting?.executeScript) {
            await browser.scripting.executeScript({
                target: Number.isInteger(frameId)
                    ? { tabId, frameIds: [frameId] }
                    : { tabId, allFrames: false },
                files: normalizedFiles
            })
            return true
        }

        if (browser?.tabs?.executeScript) {
            for (const file of normalizedFiles) {
                const details = {
                    file,
                    frameId: Number.isInteger(frameId) ? frameId : 0,
                    runAt: 'document_idle'
                }
                await browser.tabs.executeScript(tabId, details)
            }
            return true
        }

        return false
    }

    async _notifyContentRuntimeRefresh(tabId, frameId = 0) {
        if (!Number.isInteger(tabId) || tabId < 0 || !browser?.tabs?.sendMessage) return false
        try {
            await browser.tabs.sendMessage(tabId, {
                channel: 'ptk_background2content_runtime',
                type: 'refresh_profile'
            }, Number.isInteger(frameId) ? { frameId } : undefined)
            return true
        } catch (_) {
            return false
        }
    }

    async handleContentBootstrapHello(message = {}, sender = {}) {
        const tabId = Number.isInteger(sender?.tab?.id) ? sender.tab.id : null
        const frameId = Number.isInteger(sender?.frameId) ? sender.frameId : 0
        const url = typeof message?.url === 'string'
            ? message.url
            : (typeof sender?.url === 'string' ? sender.url : '')
        const zapHintUrl = typeof message?.zapHintUrl === 'string' ? message.zapHintUrl : ''
        const observedUrls = Array.from(new Set([url, zapHintUrl].filter((value) => typeof value === 'string' && value)))
        for (const observedUrl of observedUrls) {
            try {
                this.zap?.transport?.processContentObservedZapUrl?.({
                    tabId,
                    frameId,
                    url: observedUrl
                })
            } catch (error) {
                console.warn('[PTK Automation] Failed to process bootstrap URL for ZAP detection', {
                    tabId,
                    frameId,
                    url: observedUrl,
                    error: error?.message || String(error)
                })
            }
        }
        const profile = this._getContentRuntimeProfile({ tabId, frameId, url })
        const files = CONTENT_RUNTIME_FILES[profile.script] || []
        const useStaticFirefoxManualRuntime = profile.script === CONTENT_RUNTIME_SCRIPT_MANUAL && this._isFirefoxRuntime()

        if (files.length && !useStaticFirefoxManualRuntime) {
            try {
                await this._executeContentRuntimeFiles({ tabId, frameId, files })
            } catch (error) {
                console.warn('[PTK Automation] Failed to inject content runtime', {
                    tabId,
                    frameId,
                    script: profile.script,
                    error: error?.message || String(error)
                })
                return {
                    ...profile,
                    script: CONTENT_RUNTIME_SCRIPT_NONE,
                    error: error?.message || String(error)
                }
            }
        }

        return profile
    }

    _getZapTimingForSession(session = null) {
        if (!session || session.source !== 'zap') return null
        return {
            zapid: this.zap?.transport?.getZapId?.() || null,
            zapSessionKey: session.zapSessionKey || null,
            automationSessionId: session.id || null,
            tabId: Number.isInteger(session.tabId) ? session.tabId : null,
            targetUrl: session.targetUrl || null
        }
    }

    _recordZapTiming(session = null, phase = null, extra = null) {
        const timing = this._getZapTimingForSession(session)
        if (!timing || !phase || typeof this.zap?.recordTiming !== 'function') {
            return false
        }
        return this.zap.recordTiming(Object.assign({}, timing, { phase, extra }))
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
        debugAutomationLog('[PTK Automation] isAutomationEnabled check:', {
            hasApp: !!this.app,
            hasSettings: !!this.app?.settings,
            automation: this.app?.settings?.automation,
            enabled
        })
        return enabled
    }

    _isZapAutomationBridgeRequestAllowed(message = {}, sender = {}) {
        const tabId = Number.isInteger(sender?.tab?.id) ? sender.tab.id : null
        if (this._isZapManagedActiveSessionForTab(tabId)) {
            return true
        }

        const requestedSessionId = toNonEmptyString(message?.sessionId)
            || toNonEmptyString(message?.options?.sessionId)
        if (!requestedSessionId) {
            return false
        }

        const session = this.sessions.get(requestedSessionId)
        if (session?.source === 'zap') {
            return true
        }

        const requestedByZapCloseContract = message?.options?.source === 'zap_browser_close'
        if (!requestedByZapCloseContract) {
            return false
        }

        return Number.isInteger(tabId)
    }

    onMessage(message, sender, sendResponse) {
        if (message.channel !== 'ptk_content2background_automation') {
            return false  // Explicitly indicate we don't handle this message
        }

        // Use sendResponse pattern for Chrome MV3 compatibility
        // This is more reliable than returning a Promise when multiple listeners exist
        ;(async () => {
            if (this.app?.ready && typeof this.app.ready.then === 'function') {
                await this.app.ready
            }

            // Verify automation only after app/settings bootstrap has finished.
            if (!this.isAutomationEnabled() && !this._isZapAutomationBridgeRequestAllowed(message, sender)) {
                console.warn('[PTK Automation] Automation is disabled in settings, rejecting request')
                return { error: 'automation_disabled', requestId: message.requestId }
            }

            debugAutomationLog('[PTK Automation] Received message:', message.type, message)

            const type = (message.type || '').replace(/-/g, '_')
            const handler = this['msg_' + type]
            if (handler) {
                const result = await handler.call(this, message, sender)
                debugAutomationLog('[PTK Automation] Response:', result)
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
        debugAutomationLog('[PTK Automation] msg_session_start called', { message, sender: sender?.tab?.id })
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
            if (existingSession && this._isActiveSessionStatus(existingSession.status)) {
                return {
                    error: 'session_already_running_in_tab',
                    existingSessionId,
                    existingSessionStatus: existingSession.status,
                    requestId
                }
            }
            // Clean up stale session
            this.sessions.delete(existingSessionId)
            this.activeSessionByTabId.delete(tabId)
        }

        // Background generates the sessionId (single source of truth)
        const sessionId = this._generateSessionId()
        const host = this._extractHost(pageUrl)
        const engines = this._normalizeEngines(options?.engines)
        const engineConfigs = this._normalizeEngineConfigs(options?.engineConfigs, engines)

        const session = {
            id: sessionId,
            tabId,
            host,
            project: options?.project || null,
            testRunId: options?.testRunId || null,
            engines,
            policyCode: options?.policyCode || null,
            runCve: options?.runCve === true,
            engineConfigs,
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

    async startZapConfiguredSession(payload = {}) {
        const tabId = Number.isInteger(payload?.tabId) ? payload.tabId : null
        debugAutomationLog('[PTK Automation] startZapConfiguredSession requested', {
            tabId,
            targetUrl: payload?.targetUrl || payload?.pageUrl || null,
            engines: Array.isArray(payload?.engines) ? payload.engines : null,
            zapSessionKey: payload?.zapSessionKey || null
        })
        if (!tabId) {
            console.warn('[PTK Automation] startZapConfiguredSession rejected: missing tabId', {
                tabId,
                zapSessionKey: payload?.zapSessionKey || null
            })
            throw new Error('zap_missing_tab')
        }

        const targetUrl = typeof payload?.targetUrl === 'string' && payload.targetUrl
            ? payload.targetUrl
            : (typeof payload?.pageUrl === 'string' ? payload.pageUrl : null)
        const host = this._extractHost(targetUrl || '')
        if (!host || host === 'zap') {
            console.warn('[PTK Automation] startZapConfiguredSession rejected: invalid target URL', {
                tabId,
                targetUrl,
                host,
                zapSessionKey: payload?.zapSessionKey || null
            })
            throw new Error('zap_invalid_target_url')
        }

        const requestedEngines = Array.isArray(payload?.engines) && payload.engines.length
            ? payload.engines
            : ['DAST', 'IAST', 'SAST', 'SCA']
        const engines = this._normalizeEngines(requestedEngines)
        if (!engines.length) {
            console.warn('[PTK Automation] startZapConfiguredSession rejected: no normalized engines', {
                tabId,
                targetUrl,
                requestedEngines,
                zapSessionKey: payload?.zapSessionKey || null
            })
            throw new Error('zap_no_engines')
        }

        const engineConfigs = this._normalizeEngineConfigs(payload?.engineConfigs, engines)
        const policyCode = payload?.policyCode || null
        const runCve = payload?.runCve === true
        const zapSessionKey = payload?.zapSessionKey || null
        const existingSessionId = this.activeSessionByTabId.get(tabId)
        if (existingSessionId) {
            const existingSession = this.sessions.get(existingSessionId)
            if (existingSession && this._isActiveSessionStatus(existingSession.status)) {
                if (zapSessionKey && existingSession.zapSessionKey === zapSessionKey) {
                    debugAutomationLog('[PTK Automation] startZapConfiguredSession already running for ZAP session', {
                        tabId,
                        sessionId: existingSessionId,
                        status: existingSession.status,
                        zapSessionKey,
                        engines: existingSession.engines
                    })
                    return {
                        sessionId: existingSessionId,
                        status: 'already_running',
                        requiredEngines: Array.isArray(existingSession.engines) ? existingSession.engines.slice() : engines
                    }
                }
                console.warn('[PTK Automation] startZapConfiguredSession busy with different session', {
                    tabId,
                    existingSessionId,
                    existingZapSessionKey: existingSession.zapSessionKey || null,
                    requestedZapSessionKey: zapSessionKey,
                    status: existingSession.status
                })
                return {
                    sessionId: existingSessionId,
                    status: 'busy',
                    requiredEngines: Array.isArray(existingSession?.engines) ? existingSession.engines.slice() : engines
                }
            }
            this.sessions.delete(existingSessionId)
            this.activeSessionByTabId.delete(tabId)
        }

        const sessionId = this._generateSessionId()
        const session = {
            id: sessionId,
            tabId,
            host,
            project: 'zap',
            testRunId: null,
            engines,
            policyCode,
            runCve,
            engineConfigs,
            startedAt: new Date().toISOString(),
            finishedAt: null,
            status: 'starting',
            scanIds: {},
            engineStates: {},
            source: 'zap',
            zapSessionKey,
            targetUrl
        }

        this._initializeEngineStates(session, engines)
        this.sessions.set(sessionId, session)
        this.activeSessionByTabId.set(tabId, sessionId)
        debugAutomationLog('[PTK Automation] startZapConfiguredSession created session', {
            sessionId,
            tabId,
            host,
            targetUrl,
            engines,
            zapSessionKey
        })
        this._recordZapTiming(session, 'session.created')

        try {
            const immediateEngines = this._selectImmediateZapStartupEngines(engines)
            const deferredEngines = engines.filter(engineName => !immediateEngines.includes(engineName))
            for (const engineName of deferredEngines) {
                session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                    status: ENGINE_STATUS_DEFERRED_START,
                    deferredAt: Date.now()
                })
            }

            await this._startEngines(session, immediateEngines)
            const startupSummary = this._summarizeEngineStartup(session, immediateEngines)
            if (startupSummary.failedEngines.length > 0 && startupSummary.startedEngines.length === 0) {
                const message = this._buildZapStartupFailureMessage(startupSummary.failedEngines)
                session.status = 'error'
                session.error = message
                session.finishedAt = new Date().toISOString()
                void this._cleanupFailedZapStartup(session)
                console.warn('[PTK Automation] startZapConfiguredSession engine startup failed', {
                    sessionId,
                    tabId,
                    host,
                    targetUrl,
                    startedEngines: startupSummary.startedEngines,
                    failedEngines: startupSummary.failedEngines,
                    message
                })
                return {
                    sessionId,
                    status: 'error',
                    error: message,
                    message,
                    startedEngines: startupSummary.startedEngines,
                    failedEngines: startupSummary.failedEngines,
                    requiredEngines: engines
                }
            }
            session.status = 'running'
            if (deferredEngines.length) {
                this._recordZapTiming(session, 'session.deferred_start.begin', {
                    engines: deferredEngines.join(',')
                })
                this._startDeferredZapEngines(
                    session,
                    deferredEngines,
                    this._computeDeferredZapEngineStartDelay(session)
                )
            }
            this._recordZapTiming(session, 'session.running', {
                startedEngines: startupSummary.startedEngines.join(','),
                deferredEngines: deferredEngines.join(',')
            })
            debugAutomationLog('[PTK Automation] startZapConfiguredSession running', {
                sessionId,
                tabId,
                host,
                targetUrl,
                startedEngines: startupSummary.startedEngines,
                deferredEngines,
                requiredEngines: engines
            })
            return {
                sessionId,
                status: deferredEngines.length ? 'starting' : 'started',
                startedEngines: startupSummary.startedEngines,
                failedEngines: startupSummary.failedEngines,
                deferredEngines,
                requiredEngines: engines
            }
        } catch (err) {
            session.status = 'error'
            session.error = err.message
            console.error('[PTK Automation] startZapConfiguredSession failed', {
                sessionId,
                tabId,
                host,
                targetUrl,
                error: err?.message || String(err)
            })
            return {
                sessionId,
                status: 'error',
                error: err.message,
                requiredEngines: engines
            }
        }
    }

    getZapManagedScanIds({ engine = null, zapSessionKey = null, host = null } = {}) {
        const engineName = String(engine || '').trim().toUpperCase()
        if (!engineName) return []

        const expectedSessionKey = toNonEmptyString(zapSessionKey)
        const expectedHost = toNonEmptyString(host)?.toLowerCase()
        const entries = []

        for (const session of this.sessions.values()) {
            if (!session || session.source !== 'zap') continue
            if (!Array.isArray(session.engines) || !session.engines.includes(engineName)) continue
            if (expectedSessionKey && session.zapSessionKey !== expectedSessionKey) continue
            if (expectedHost && String(session.host || '').toLowerCase() !== expectedHost) continue

            const scanId = toNonEmptyString(session.scanIds?.[engineName])
            if (!scanId) continue

            const startedAt = Date.parse(session.startedAt || '')
            entries.push({
                scanId,
                startedAt: Number.isFinite(startedAt) ? startedAt : 0
            })
        }

        const seen = new Set()
        return entries
            .sort((a, b) => a.startedAt - b.startedAt)
            .map(entry => entry.scanId)
            .filter(scanId => {
                if (seen.has(scanId)) return false
                seen.add(scanId)
                return true
            })
    }

    async requestZapSessionStop(sessionId, options = {}) {
        const safeSessionId = toNonEmptyString(sessionId)
        if (!safeSessionId) {
            return { ok: false, error: 'missing_session_id' }
        }
        const session = this.sessions.get(safeSessionId)
        if (!session || session.source !== 'zap') {
            return { ok: false, error: 'session_not_found', sessionId: safeSessionId }
        }
        if (session.status === 'completed' || session.status === 'error') {
            return {
                ok: true,
                sessionId: safeSessionId,
                status: session.status,
                alreadyTerminal: true,
                source: options?.source || null
            }
        }

        const timeoutMs = this._normalizeStopTimeoutMs(options?.timeoutMs)
        if (session.stopRequestedAt) {
            return {
                ok: true,
                sessionId: safeSessionId,
                status: session.status || 'stopping',
                stopRequestedAt: session.stopRequestedAt,
                alreadyRequested: true,
                source: options?.source || null
            }
        }

        session.stopRequestedAt = new Date().toISOString()
        session.status = 'stopping'

        this._stopEnginesAsync(session, timeoutMs)
            .then(stats => {
                this._finalizeSession(session, stats)
            })
            .catch(err => {
                console.error('[PTK Automation] Async ZAP stop failed', {
                    sessionId: safeSessionId,
                    source: options?.source || null,
                    error: err?.message || String(err)
                })
                session.status = 'error'
                session.error = err?.message || String(err)
            })

        return {
            ok: true,
            sessionId: safeSessionId,
            status: 'stopping',
            stopRequestedAt: session.stopRequestedAt,
            source: options?.source || null
        }
    }

    async msg_session_end(message, sender) {
        const { requestId, wait = true, options = {} } = message
        const tabId = sender?.tab?.id
        const strictCurrentTab = this._isStrictCurrentTabScope(options)
        const stopTimeoutMs = this._normalizeStopTimeoutMs(options?.stopTimeoutMs)

        const resolution = this._resolveSessionForRequest({
            sessionId: options?.sessionId || message.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: true,
            allowCompleted: false,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId }
        }
        const session = resolution.session

        // === Non-blocking stop (wait=false) ===
        if (wait === false) {
            // Mark stop requested
            session.stopRequestedAt = new Date().toISOString()
            session.status = 'stopping'

            // Fire-and-forget stop with completion handler
            this._stopEnginesAsync(session, stopTimeoutMs)
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
            const stats = await this._stopEngines(session, stopTimeoutMs)
            this._finalizeSession(session, stats)

            let findingsPayload = null
            if (message.includeFindings === true) {
                const limit = Math.min(Number(message.limit) || 100, MAX_FINDINGS_LIMIT)
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

        const resolution = this._resolveSessionForRequest({
            sessionId: message.sessionId,
            tabId,
            strictCurrentTab: false,
            allowActive: true,
            allowCompleted: false,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }
        const session = resolution.session

        const stats = this._collectCurrentStats(session)
        return {
            findingsCount: stats.findingsCount,
            bySeverity: stats.bySeverity,
            requestId,
            sessionLookup: resolution.sessionLookup
        }
    }

    // Return { findings, truncated }
    async msg_get_findings(message, sender) {
        const { requestId, limit = 100, options = {} } = message
        const tabId = sender?.tab?.id

        const strictCurrentTab = this._isStrictCurrentTabScope(options)
        const resolution = this._resolveSessionForRequest({
            sessionId: options?.sessionId || message.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: true,
            allowCompleted: strictCurrentTab,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }
        const session = resolution.session

        const cappedLimit = Math.min(limit, MAX_FINDINGS_LIMIT)
        const { findings, truncated } = this._collectFindings(session, cappedLimit)
        return { findings, truncated, requestId, sessionLookup: resolution.sessionLookup }
    }

    async msg_get_analysis_snapshot(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id
        const strictCurrentTab = this._isStrictCurrentTabScope(options)
        const resolution = this._resolveSessionForRequest({
            sessionId: options?.sessionId || message.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: true,
            allowCompleted: true,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }

        const snapshot = this._collectAnalysisSnapshot(resolution.session)
        return {
            ok: true,
            requestId,
            sessionId: resolution.sessionId,
            sessionLookup: resolution.sessionLookup,
            ...snapshot
        }
    }

    /**
     * Get session progress (fast, non-blocking)
     * Used for polling during stop+wait pattern
     */
    async msg_get_session_progress(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id
        const strictCurrentTab = this._isStrictCurrentTabScope(options)

        const resolution = this._resolveSessionForRequest({
            sessionId: options.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: true,
            allowCompleted: true,
            allowGlobalCompleted: true
        })

        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }

        const snapshot = this.getSessionProgressSnapshot(resolution.sessionId)
        if (!snapshot?.ok) {
            return { ok: false, error: snapshot?.error || 'session_not_found', requestId, sessionLookup: resolution.sessionLookup }
        }

        return {
            ...snapshot,
            requestId,
            sessionLookup: resolution.sessionLookup
        }
    }

    async msg_export_scan(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id

        const strictCurrentTab = this._isStrictCurrentTabScope(options)
        const resolution = this._resolveSessionForRequest({
            sessionId: options.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: strictCurrentTab,
            allowCompleted: true,
            allowGlobalCompleted: true
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }
        const session = resolution.session
        this._finalizeActiveSessionIfExportReady(session, 'export_scan')
        this._finalizeStoppedSessionIfExportReady(session, 'export_scan')
        if (session.status !== 'completed') {
            return {
                ok: false,
                error: 'session_not_completed',
                hint: 'Call end_session() before export_scan_payload()',
                requestId,
                sessionLookup: resolution.sessionLookup
            }
        }

        const requestedEngine = (options.engine || 'ALL').toUpperCase().trim()
        const validEngines = ['DAST', 'IAST', 'SAST', 'SCA', 'ALL']
        if (!validEngines.includes(requestedEngine)) {
            return { ok: false, error: 'invalid_engine', requestId, sessionLookup: resolution.sessionLookup }
        }

        const enginesToExport = requestedEngine === 'ALL'
            ? session.engines
            : [requestedEngine]

        const warnings = []
        const exports = []
        const allowChunked = options.allowChunked !== false

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
                let scanExport = null
                try {
                    scanExport = await this._buildEngineExport(engine, scanId, session, options)
                } catch (err) {
                    if (!allowChunked || String(err?.message || '') !== 'export_too_large') {
                        throw err
                    }
                    scanExport = await this._buildEngineChunkedExport(engine, session, options)
                }
                exports.push(scanExport)
            } catch (err) {
                warnings.push(`export_failed:${engine}:${err.message}`)
            }
        }

        if (!exports.length) {
            return { ok: false, error: 'no_exportable_results', warnings, requestId, sessionLookup: resolution.sessionLookup }
        }

        return {
            ok: true,
            scans: exports,
            truncatedAny: exports.some(e => e.truncated),
            warnings,
            requestId,
            sessionLookup: resolution.sessionLookup
        }
    }

    async msg_export_scan_chunk(message) {
        const { requestId, options = {} } = message
        const engine = String(options.engine || '').trim().toUpperCase()
        if (!engine) {
            return { ok: false, error: 'engine_required', requestId }
        }
        const exportModule = this._getEngineExportModule(engine)
        if (!exportModule?.msg_export_scan_chunk) {
            return { ok: false, error: 'chunked_export_not_supported', requestId, engine }
        }
        try {
            const result = await exportModule.msg_export_scan_chunk({
                exportId: options.exportId,
                index: options.index
            })
            return {
                ...(result || {}),
                ok: result?.success !== false,
                requestId
            }
        } catch (err) {
            return { ok: false, error: err?.message || 'chunk_read_failed', requestId, engine }
        }
    }

    async msg_release_export_scan(message) {
        const { requestId, options = {} } = message
        const engine = String(options.engine || '').trim().toUpperCase()
        if (!engine) {
            return { ok: false, error: 'engine_required', requestId }
        }
        const exportModule = this._getEngineExportModule(engine)
        if (!exportModule?.msg_release_export_scan) {
            return { ok: false, error: 'chunked_export_not_supported', requestId, engine }
        }
        try {
            const result = await exportModule.msg_release_export_scan({
                exportId: options.exportId
            })
            return {
                ...(result || {}),
                ok: result?.success !== false,
                requestId
            }
        } catch (err) {
            return { ok: false, error: err?.message || 'chunk_release_failed', requestId, engine }
        }
    }

    async msg_get_engine_snapshot(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id

        const resolution = this._resolveSessionForRequest({
            sessionId: options.sessionId,
            tabId,
            strictCurrentTab: false,
            allowActive: false,
            allowCompleted: true,
            allowGlobalCompleted: true
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId }
        }
        const session = resolution.session

        const engine = String(options.engine || '').trim().toUpperCase()
        if (!engine) {
            return { ok: false, error: 'engine_required', requestId }
        }

        let scanId = session.scanIds?.[engine] || null
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
            return { ok: false, error: 'scan_id_not_found', requestId, engine }
        }

        let scanResult = this._getEngineScanResult(engine)
        if (scanResult?.scanId !== scanId) {
            scanResult = resultsRegistry.get(engine, scanId)
        }
        if (!scanResult || typeof scanResult !== 'object') {
            return { ok: false, error: 'scan_result_not_found', requestId, engine, scanId }
        }

        const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
        const groups = Array.isArray(scanResult.groups) ? scanResult.groups : []
        const requests = Array.isArray(scanResult.requests) ? scanResult.requests : []
        const runtimeEvents = Array.isArray(scanResult.runtimeEvents) ? scanResult.runtimeEvents : []
        const stats = scanResult.stats && typeof scanResult.stats === 'object'
            ? {
                findingsCount: Number(scanResult.stats.findingsCount || findings.length || 0),
                bySeverity: Object.assign({ critical: 0, high: 0, medium: 0, low: 0, info: 0 }, scanResult.stats.bySeverity || {})
            }
            : this._extractStats(scanResult)
        const perfKey = engine.toLowerCase()

        return {
            ok: true,
            requestId,
            engine,
            scanId,
            sessionId: session.id,
            status: session.status,
            startedAt: scanResult.startedAt || session.startedAt || null,
            finishedAt: scanResult.finishedAt || scanResult.finished || session.finishedAt || null,
            stats,
            groupsCount: groups.length,
            requestsCount: requests.length,
            runtimeEventsCount: runtimeEvents.length,
            performance: scanResult.performance?.[perfKey] || null
        }
    }

    // === Engine Coordination ===

    // Pass sessionId to adapters for DAST automation session
    async _startEngines(session, engineNames = null) {
        const effectiveEngines = Array.isArray(engineNames) && engineNames.length
            ? engineNames
            : session?.engines
        const { id: sessionId, tabId, host } = session
        debugAutomationLog('[PTK Automation] _startEngines', { sessionId, tabId, host, engines: effectiveEngines })

        if (!this.engines) {
            console.error('[PTK Automation] Engine adapters not initialized (this.engines is null)')
            throw new Error('engine_adapters_not_initialized')
        }

        for (const engineName of Array.isArray(effectiveEngines) ? effectiveEngines : []) {
            await this._startEngine(session, engineName)
        }
    }

    // Use adapter.stop() which waits for idle
    async _stopEngines(session, timeoutMs = 180000) {
        const stats = { findingsCount: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }

        for (const engineName of session.engines) {
            const adapter = this.engines.getAdapter(engineName)
            if (!adapter) continue

            try {
                // Adapter.stop() now waits for idle and returns stats
                const engineStats = await adapter.stop(session.id, timeoutMs)
                const resolvedStats = this._resolveStoppedEngineStats(engineName, session, engineStats)
                this._mergeStats(stats, resolvedStats)
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
    async _stopEnginesAsync(session, timeoutMs = 180000) {
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
                const engineStats = await adapter.stop(session.id, timeoutMs)
                const resolvedStats = this._resolveStoppedEngineStats(engineName, session, engineStats)
                session.engineStates[engineName].status = 'stopped'

                // Aggregate stats
                stats.findingsCount += resolvedStats?.findingsCount || 0
                for (const sev of Object.keys(stats.bySeverity)) {
                    stats.bySeverity[sev] += resolvedStats?.bySeverity?.[sev] || 0
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

    _normalizeStopTimeoutMs(value) {
        const num = Number(value)
        if (!Number.isFinite(num) || num <= 0) return 180000
        return Math.max(250, Math.min(180000, Math.floor(num)))
    }

    _extractStatsFromScanResult(scanResult) {
        const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        const stats = this._createEmptyStats()
        for (const finding of findings) {
            stats.findingsCount += 1
            const sev = String(finding?.severity || finding?.effectiveSeverity || 'info').toLowerCase()
            if (Object.prototype.hasOwnProperty.call(stats.bySeverity, sev)) {
                stats.bySeverity[sev] += 1
            } else {
                stats.bySeverity.info += 1
            }
        }
        return stats
    }

    _resolveStoppedEngineStats(engineName, session, initialStats = null) {
        const best = {
            findingsCount: Number(initialStats?.findingsCount || 0),
            bySeverity: Object.assign(
                { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                initialStats?.bySeverity || {}
            )
        }

        const maybeAdopt = (scanResult) => {
            if (!scanResult || typeof scanResult !== 'object') return
            const derived = this._extractStatsFromScanResult(scanResult)
            if (Number(derived?.findingsCount || 0) > Number(best.findingsCount || 0)) {
                best.findingsCount = Number(derived.findingsCount || 0)
                best.bySeverity = Object.assign(
                    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                    derived.bySeverity || {}
                )
            }
        }

        maybeAdopt(this._getEngineScanResult(engineName))

        const adapter = this.engines?.getAdapter(engineName) || null
        let scanId = session?.scanIds?.[engineName] || adapter?.getScanId?.() || null
        if (!scanId && session) {
            scanId = resultsRegistry.findScanIdForEngine(engineName, {
                tabId: session.tabId,
                host: session.host
            })
        }
        if (scanId) {
            if (session?.scanIds) {
                session.scanIds[engineName] = scanId
            }
            maybeAdopt(resultsRegistry.get(engineName, scanId))
        }

        return best
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

        debugAutomationLog('[PTK Automation] Session finalized', session.id)
    }

    _finalScanIdCapture(session) {
        for (const engineName of session.engines) {
            if (session.scanIds[engineName]) continue

            const adapter = this.engines?.getAdapter(engineName)
            const scanId = adapter?.getScanId?.() || null

            if (scanId) {
                session.scanIds[engineName] = scanId
                debugAutomationLog('[PTK Automation] Final capture scanId for', engineName, scanId)
                continue
            }

            const fallbackId = resultsRegistry.findScanIdForEngine(engineName, {
                tabId: session.tabId,
                host: session.host
            })

            if (fallbackId) {
                session.scanIds[engineName] = fallbackId
                debugAutomationLog('[PTK Automation] Registry fallback scanId for', engineName, fallbackId)
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
            includeSecrets = false,
            maxExportBytes = 25 * 1024 * 1024
        } = options

        const scanResult = resultsRegistry.get(engine, scanId)
        if (!scanResult) {
            throw new Error(`scan_result_not_found:${engine}`)
        }

        let exported = buildExportScanResult(scanId, { scanResult, includeSecrets: includeSecrets === true })
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
        exported.meta.privacy = exported.meta.privacy || {}
        exported.meta.privacy.secretsIncluded = includeSecrets === true
        if (includeSecrets === true) {
            exported.meta.privacy.replayableRequests = true
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
                ...(exported.meta.privacy || {}),
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

    async _buildEngineChunkedExport(engine, session, options = {}) {
        const exportModule = this._getEngineExportModule(engine)
        if (!exportModule?.msg_export_scan_result) {
            throw new Error('chunked_export_not_supported')
        }
        const result = await exportModule.msg_export_scan_result({
            target: options?.target || 'download',
            fileName: options?.fileName || `PTK_${String(engine || 'scan').toUpperCase()}_scan.json`,
            includeSecrets: options?.includeSecrets === true
        })
        if (!result || result.success === false) {
            throw new Error(result?.error || 'chunked_export_failed')
        }
        if (result.exportMode !== 'chunked') {
            throw new Error('chunked_export_not_available')
        }
        return {
            engine,
            exportMode: 'chunked',
            exportId: result.exportId,
            fileName: result.fileName,
            size: result.size,
            chunkSize: result.chunkSize,
            chunkCount: result.chunkCount,
            contentType: result.contentType,
            compression: result.compression,
            expiresAt: result.expiresAt,
            truncated: false,
            chunked: true,
            meta: {
                automation: {
                    sessionId: session?.id || null,
                    testRunId: session?.testRunId || null,
                    project: session?.project || null,
                    policyCode: session?.policyCode || null,
                    startedAt: session?.startedAt || null,
                    finishedAt: session?.finishedAt || null,
                    schemaVersion: 1
                }
            }
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
                this._evictSession(id, 'ttl')
            }
        }

        const remaining = completedSessions.filter(s => this.sessions.has(s.id))
        while (remaining.length > this.MAX_COMPLETED_SESSIONS) {
            const oldest = remaining.shift()
            this._evictSession(oldest.id, 'max_completed_sessions')
        }
    }

    _evictSession(sessionId, reason = 'retention') {
        const session = this.sessions.get(sessionId)
        if (!session) return

        debugAutomationLog('[PTK Automation] Evicting session', sessionId)
        this._recordEvictedSession(session, reason)
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
                    this._evictSession(id, 'cleanup_max_age')
                } else {
                    completedSessions.push({ id, finishedAt: new Date(session.finishedAt).getTime() })
                }
            }
        }

        if (keepCount !== null) {
            completedSessions.sort((a, b) => a.finishedAt - b.finishedAt)
            while (completedSessions.length > keepCount) {
                const oldest = completedSessions.shift()
                this._evictSession(oldest.id, 'cleanup_keep_count')
            }
        }
    }

    _recordEvictedSession(session, reason = 'retention') {
        if (!session || !session.id) return
        this.evictedSessions.set(session.id, {
            sessionId: session.id,
            tabId: session.tabId ?? null,
            sessionStatus: session.status || null,
            sessionFinishedAt: session.finishedAt || null,
            stopRequestedAt: session.stopRequestedAt || null,
            reason,
            evictedAt: new Date().toISOString()
        })
        while (this.evictedSessions.size > Math.max(20, this.MAX_COMPLETED_SESSIONS * 2)) {
            const oldest = this.evictedSessions.keys().next().value
            this.evictedSessions.delete(oldest)
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

    _normalizeEngineConfigs(rawConfigs, allowedEngines = []) {
        const configs = {}
        const allowed = new Set((Array.isArray(allowedEngines) ? allowedEngines : []).map(e => String(e || '').toUpperCase()))
        if (!rawConfigs || typeof rawConfigs !== 'object') {
            return configs
        }

        for (const [engineNameRaw, value] of Object.entries(rawConfigs)) {
            const engineName = String(engineNameRaw || '').toUpperCase()
            if (!engineName || !allowed.has(engineName)) continue
            if (!value || typeof value !== 'object') continue
            configs[engineName] = Object.assign({}, value)
        }

        return configs
    }

    /**
     * Check whether a session status should still block a new start in the tab.
     *
     * This keeps per-tab busy detection aligned with the shared
     * ACTIVE_SESSION_STATUSES set. Any other value is ignored, so the status is
     * treated as non-active.
     *
     * @param {string} [status] - Session status to classify.
     * @returns {boolean}
     */
    _isActiveSessionStatus(status) {
        return ACTIVE_SESSION_STATUSES.has(String(status || '').toLowerCase())
    }

    /**
     * Check whether request options enable strict current-tab session lookup.
     *
     * This keeps the strict lookup switch tied to the shared
     * STRICT_CURRENT_TAB_SESSION_SCOPE value. Any other value, including a
     * missing `sessionScope`, is ignored so lookup stays non-strict.
     *
     * @param {Object} [options]
     * @param {string} [options.sessionScope] - Optional session lookup mode.
     * @returns {boolean}
     */
    _isStrictCurrentTabScope(options = {}) {
        return options?.sessionScope === STRICT_CURRENT_TAB_SESSION_SCOPE
    }

    _baseSessionLookupDiagnostics({
        sessionId = null,
        tabId = null,
        strictCurrentTab = false,
        allowActive = true,
        allowCompleted = false,
        allowGlobalCompleted = false
    } = {}) {
        const requestedSessionId = toNonEmptyString(sessionId)
        const activeSessionIdForTab = tabId ? this.activeSessionByTabId.get(tabId) || null : null
        const completedSessionIdForTab = tabId ? this.lastCompletedSessionByTabId.get(tabId) || null : null
        const candidateIds = [
            requestedSessionId,
            activeSessionIdForTab,
            completedSessionIdForTab,
            this.lastCompletedSessionGlobal
        ].filter(Boolean)
        const evicted = candidateIds.some(id => this.evictedSessions.has(id))
        return {
            requestedSessionId: requestedSessionId || null,
            tabId: tabId ?? null,
            strictCurrentTab: strictCurrentTab === true,
            allowActive: allowActive === true,
            allowCompleted: allowCompleted === true,
            allowGlobalCompleted: allowGlobalCompleted === true,
            lookupSource: 'none',
            activeSessionIdForTab,
            completedSessionIdForTab,
            globalCompletedSessionId: this.lastCompletedSessionGlobal || null,
            sessionExists: false,
            sessionStatus: null,
            sessionFinishedAt: null,
            stopRequestedAt: null,
            retention: {
                ttlMs: this.SESSION_TTL_MS,
                maxCompletedSessions: this.MAX_COMPLETED_SESSIONS,
                evicted
            }
        }
    }

    _sessionLookupDiagnostics(request, session = null, lookupSource = 'none') {
        const diagnostics = this._baseSessionLookupDiagnostics(request)
        diagnostics.lookupSource = lookupSource || 'none'
        diagnostics.sessionExists = Boolean(session)
        if (session) {
            diagnostics.sessionStatus = session.status || null
            diagnostics.sessionFinishedAt = session.finishedAt || null
            diagnostics.stopRequestedAt = session.stopRequestedAt || null
            diagnostics.retention.evicted = this.evictedSessions.has(session.id)
        }
        return diagnostics
    }

    /**
     * Resolve a session for a background request.
     *
     * This keeps session lookup rules in one place so request handlers do not
     * each implement their own tab/global fallback behaviour. The main benefit
     * is consistency: strict current-tab workflow handlers and compatibility
     * handlers can use the same lookup path while choosing whether to look at
     * the active tab session, the tab's last completed session, or the global
     * completed session.
     *
     * Lookup order is:
     * 1. explicit sessionId
     * 2. active session for the sender tab, when allowed
     * 3. retained completed session for the sender tab, when allowed
     * 4. retained completed session across tabs, when allowed and not strict
     *
     * Strict current-tab mode requires tab context and rejects explicit
     * sessionIds that belong to another tab. Stale map entries are cleaned up
     * while walking the candidate list.
     *
     * @param {Object} request
     * @param {string|null} [request.sessionId] - Explicit session to resolve first.
     * @param {number|null} [request.tabId] - Sender tab used for tab-scoped lookup.
     * @param {boolean} [request.strictCurrentTab=false] - Reject cross-tab explicit
     * session IDs and suppress global completed fallback.
     * @param {boolean} [request.allowActive=true] - Allow resolving the active
     * session for the sender tab.
     * @param {boolean} [request.allowCompleted=false] - Allow resolving the last
     * completed session for the sender tab.
     * @param {boolean} [request.allowGlobalCompleted=false] - Allow resolving the
     * last completed session across tabs when strict mode is disabled.
     * @returns {{ok: true, sessionId: string, session: Object} | {ok: false, error: string}}
     */
    _resolveSessionForRequest({
        sessionId = null,
        tabId = null,
        strictCurrentTab = false,
        allowActive = true,
        allowCompleted = false,
        allowGlobalCompleted = false
    } = {}) {
        const request = { sessionId, tabId, strictCurrentTab, allowActive, allowCompleted, allowGlobalCompleted }
        if (strictCurrentTab && !tabId) {
            return { ok: false, error: 'no_tab_context', sessionLookup: this._sessionLookupDiagnostics(request) }
        }

        const explicitSessionId = toNonEmptyString(sessionId)
        if (explicitSessionId) {
            const explicitSession = this.sessions.get(explicitSessionId)
            if (!explicitSession) {
                return { ok: false, error: 'session_not_found', sessionLookup: this._sessionLookupDiagnostics(request) }
            }
            if (strictCurrentTab && explicitSession.tabId !== tabId) {
                return { ok: false, error: 'session_belongs_to_another_tab', sessionLookup: this._sessionLookupDiagnostics(request, explicitSession, 'explicit-session') }
            }
            return {
                ok: true,
                sessionId: explicitSessionId,
                session: explicitSession,
                sessionLookup: this._sessionLookupDiagnostics(request, explicitSession, 'explicit-session')
            }
        }

        const candidates = []
        if (tabId && allowActive) {
            candidates.push({
                kind: 'active',
                lookupSource: 'active-tab',
                tabId,
                sessionId: this.activeSessionByTabId.get(tabId)
            })
        }
        if (tabId && allowCompleted) {
            candidates.push({
                kind: 'completed-tab',
                lookupSource: 'completed-tab',
                tabId,
                sessionId: this.lastCompletedSessionByTabId.get(tabId)
            })
        }
        if (!strictCurrentTab && allowGlobalCompleted) {
            candidates.push({
                kind: 'completed-global',
                lookupSource: 'completed-global',
                sessionId: this.lastCompletedSessionGlobal
            })
        }

        for (const candidate of candidates) {
            if (!candidate.sessionId) continue
            const session = this.sessions.get(candidate.sessionId)
            if (session) {
                return {
                    ok: true,
                    sessionId: candidate.sessionId,
                    session,
                    sessionLookup: this._sessionLookupDiagnostics(request, session, candidate.lookupSource)
                }
            }

            if (candidate.kind === 'active' && this.activeSessionByTabId.get(candidate.tabId) === candidate.sessionId) {
                this.activeSessionByTabId.delete(candidate.tabId)
            } else if (candidate.kind === 'completed-tab' && this.lastCompletedSessionByTabId.get(candidate.tabId) === candidate.sessionId) {
                this.lastCompletedSessionByTabId.delete(candidate.tabId)
            } else if (candidate.kind === 'completed-global' && this.lastCompletedSessionGlobal === candidate.sessionId) {
                this.lastCompletedSessionGlobal = null
            }
        }

        return { ok: false, error: 'session_not_found', sessionLookup: this._sessionLookupDiagnostics(request) }
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

    async _waitForIastAgentReady(tabId, timeoutMs = 15000, pollMs = 100) {
        const start = Date.now()
        const hasAgentProbe = !!this.app?.iast?.isAgentReady
        while (Date.now() - start < timeoutMs) {
            const failureReason = this.app?.iast?.agentFailedTabs?.get?.(tabId)
            if (failureReason) {
                return false
            }
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

    _collectAnalysisSnapshot(session) {
        const engines = []
        const warnings = []
        const summary = {
            routes: 0,
            endpoints: 0,
            graphql: 0,
            hiddenParams: 0,
            surfaces: 0,
            gadgets: 0,
            findings: 0,
            requests: 0,
            runtimeEvents: 0
        }

        for (const engineName of session?.engines || []) {
            let scanId = session.scanIds?.[engineName] || null
            if (!scanId) {
                scanId = resultsRegistry.findScanIdForEngine(engineName, {
                    tabId: session.tabId,
                    host: session.host
                })
            }

            let scanResult = this._getEngineScanResult(engineName)
            if (scanId && scanResult?.scanId !== scanId) {
                scanResult = resultsRegistry.get(engineName, scanId)
            }
            if (!scanResult || typeof scanResult !== 'object') {
                engines.push({
                    engine: engineName,
                    scanId,
                    available: false,
                    reason: 'scan_result_unavailable'
                })
                continue
            }

            const analysis = cloneJsonSafe(scanResult.analysis, { warnings, label: `${engineName}.analysis` })
            const codeArtifacts = cloneJsonSafe(scanResult.codeArtifacts, { warnings, label: `${engineName}.codeArtifacts` })
            const explorer = analysis?.explorer || null
            const counts = {
                findings: Array.isArray(scanResult.findings) ? scanResult.findings.length : 0,
                requests: Array.isArray(scanResult.requests) ? scanResult.requests.length : 0,
                runtimeEvents: Array.isArray(scanResult.runtimeEvents) ? scanResult.runtimeEvents.length : 0,
                routes: Array.isArray(explorer?.routes) ? explorer.routes.length : 0,
                endpoints: Array.isArray(explorer?.endpoints) ? explorer.endpoints.length : 0,
                graphql: Array.isArray(explorer?.graphql) ? explorer.graphql.length : 0,
                hiddenParams: Array.isArray(explorer?.hiddenParams) ? explorer.hiddenParams.length : 0,
                surfaces: Array.isArray(explorer?.surfaces) ? explorer.surfaces.length : 0,
                gadgets: Array.isArray(explorer?.gadgets) ? explorer.gadgets.length : 0
            }
            for (const [key, value] of Object.entries(counts)) {
                summary[key] = (summary[key] || 0) + (Number(value) || 0)
            }
            engines.push({
                engine: engineName,
                scanId: scanResult.scanId || scanId || null,
                available: true,
                analysisVersion: scanResult.analysisVersion || analysis?.version || null,
                analysis,
                explorer,
                codeArtifacts,
                findingsCount: counts.findings,
                requestsCount: counts.requests,
                runtimeEventsCount: counts.runtimeEvents,
                startedAt: scanResult.startedAt || session.startedAt || null,
                finishedAt: scanResult.finishedAt || scanResult.finished || session.finishedAt || null
            })
        }

        return {
            status: session?.status || 'unknown',
            engines,
            summary,
            warnings
        }
    }

    _summarizeEngineStartup(session, engineNames = null) {
        const startedEngines = []
        const failedEngines = []

        const effectiveEngineNames = Array.isArray(engineNames) && engineNames.length
            ? engineNames
            : (session?.engines || [])
        for (const engineName of effectiveEngineNames) {
            const state = session?.engineStates?.[engineName] || {}
            if (state.status === ENGINE_STATUS_RUNNING || state.status === ENGINE_STATUS_STARTING) {
                startedEngines.push(engineName)
                continue
            }

            failedEngines.push({
                engine: engineName,
                error: state.error || `engine_not_running:${state.status || 'unknown'}`
            })
        }

        return { startedEngines, failedEngines }
    }

    _initializeEngineStates(session, engineNames = []) {
        if (!session || typeof session !== 'object') return
        session.engineStates = session.engineStates && typeof session.engineStates === 'object'
            ? session.engineStates
            : {}
        for (const engineName of Array.isArray(engineNames) ? engineNames : []) {
            const previous = session.engineStates[engineName] || {}
            session.engineStates[engineName] = Object.assign({}, previous, {
                status: ENGINE_STATUS_STARTING
            })
        }
    }

    _selectImmediateZapStartupEngines(engineNames = []) {
        const normalized = Array.isArray(engineNames) ? engineNames.filter(Boolean) : []
        if (!normalized.length) return []
        if (normalized.includes('DAST')) {
            return ['DAST']
        }
        return [normalized[0]]
    }

    _startDeferredZapEngines(session, engineNames = [], initialDelayMs = 0) {
        const deferredEngines = Array.isArray(engineNames) ? engineNames.filter(Boolean) : []
        if (!session || !deferredEngines.length) {
            return null
        }

        const startupTask = (async () => {
            await sleep(initialDelayMs)
            const startedEngines = []
            const failedEngines = []
            for (const engineName of deferredEngines) {
                if (!this.sessions.has(session.id)) {
                    break
                }
                if (session.status === ENGINE_STATUS_ERROR
                    || session.status === ENGINE_STATUS_STOPPING
                    || session.status === ENGINE_STATUS_COMPLETED) {
                    break
                }
                const result = await this._startEngine(session, engineName)
                if (result?.ok) {
                    startedEngines.push(engineName)
                } else {
                    failedEngines.push({
                        engine: engineName,
                        error: result?.error || `engine_not_running:${result?.status || 'unknown'}`
                    })
                }
                if (engineName !== deferredEngines[deferredEngines.length - 1]) {
                    await sleep(ZAP_DEFERRED_ENGINE_PER_ENGINE_DELAY_MS)
                }
            }

            if (failedEngines.length > 0) {
                console.warn('[PTK Automation] Deferred ZAP engine startup had failures', {
                    sessionId: session.id,
                    tabId: session.tabId,
                    host: session.host,
                    targetUrl: session.targetUrl,
                    startedEngines,
                    failedEngines
                })
            } else {
                debugAutomationLog('[PTK Automation] Deferred ZAP engine startup completed', {
                    sessionId: session.id,
                    startedEngines
                })
            }
            this._recordZapTiming(session, 'session.deferred_start.end', {
                initialDelayMs,
                startedEngines: startedEngines.join(','),
                failedEngines: failedEngines.map(({ engine, error }) => `${engine}:${error}`).join('|')
            })
        })().catch((err) => {
            console.error('[PTK Automation] Deferred ZAP engine startup failed', {
                sessionId: session.id,
                tabId: session.tabId,
                host: session.host,
                targetUrl: session.targetUrl,
                error: err?.message || String(err)
            })
            this._recordZapTiming(session, 'session.deferred_start.end', {
                result: 'error',
                error: err?.message || String(err)
            })
        })

        session.deferredStartupPromise = startupTask
        return startupTask
    }

    async _startEngine(session, engineName) {
        const { id: sessionId, tabId, host, policyCode, runCve, engineConfigs } = session
        const adapter = this.engines?.getAdapter(engineName)
        const enginePhasePrefix = `engine.${String(engineName || '').toLowerCase()}.start`
        const engineStartedAt = Date.now()
        debugAutomationLog('[PTK Automation] Getting adapter for', engineName, !!adapter)
        if (!adapter) {
            session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                status: ENGINE_STATUS_ERROR,
                error: 'adapter_not_found'
            })
            return { ok: false, engine: engineName, status: ENGINE_STATUS_ERROR, error: 'adapter_not_found' }
        }

        session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
            status: ENGINE_STATUS_STARTING,
            requestedAt: Date.now()
        })

        try {
            debugAutomationLog('[PTK Automation] Starting engine', engineName)
            const perEngineOptions = (engineConfigs && typeof engineConfigs === 'object')
                ? (engineConfigs[engineName] || {})
                : {}
            const mergedOptions = Object.assign({}, perEngineOptions)
            if (mergedOptions.policyCode == null && policyCode != null) {
                mergedOptions.policyCode = policyCode
            }
            if (mergedOptions.runCve == null && runCve != null) {
                mergedOptions.runCve = runCve
            }
            if (engineName === 'DAST' && mergedOptions.targetUrl == null && session.targetUrl) {
                mergedOptions.targetUrl = session.targetUrl
            }
            if (session.source === 'zap') {
                mergedOptions.zapManaged = true
                mergedOptions.zapTiming = {
                    zapid: this.zap?.transport?.getZapId?.() || null,
                    zapSessionKey: session.zapSessionKey || null,
                    automationSessionId: session.id || null,
                    tabId,
                    targetUrl: session.targetUrl || null
                }
            }
            if (engineName === 'DAST' && session.source === 'zap') {
                if (!(Number.isFinite(Number(mergedOptions.maxRequestsPerSecond)) && Number(mergedOptions.maxRequestsPerSecond) > 0)) {
                    mergedOptions.maxRequestsPerSecond = 12
                }
                if (!(Number.isFinite(Number(mergedOptions.concurrency)) && Number(mergedOptions.concurrency) > 0)) {
                    mergedOptions.concurrency = 6
                }
                if (!(Number.isFinite(Number(mergedOptions.planningConcurrency)) && Number(mergedOptions.planningConcurrency) > 0)) {
                    mergedOptions.planningConcurrency = 4
                }
            }
            if (engineName === 'IAST' && session.source === 'zap') {
                mergedOptions.waitForReady = false
            }

            this._recordZapTiming(session, `${enginePhasePrefix}.begin`)
            const startResult = await adapter.start(sessionId, tabId, host, mergedOptions)
            const engineStatus = this._resolveEngineStartStatus(startResult)
            session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                status: engineStatus,
                startedAt: Date.now()
            })
            const scanId = adapter.getScanId?.() || null
            if (scanId) {
                session.scanIds[engineName] = scanId
            }
            if (startResult?.warning) {
                session.engineStates[engineName].warning = startResult.warning
                console.warn('[PTK Automation] Engine started with warning', engineName, startResult.warning)
            }
            this._recordZapTiming(session, `${enginePhasePrefix}.end`, {
                durationMs: Date.now() - engineStartedAt,
                result: startResult?.ok === false ? 'error' : 'ok',
                status: engineStatus,
                scanId: scanId || null,
                warning: startResult?.warning || null
            })
            debugAutomationLog('[PTK Automation] Engine started', engineName, engineStatus)
            return {
                ok: startResult?.ok !== false && engineStatus !== ENGINE_STATUS_ERROR,
                engine: engineName,
                status: engineStatus,
                scanId,
                warning: startResult?.warning || null,
                error: startResult?.ok === false ? (startResult?.error || startResult?.message || 'engine_start_failed') : null
            }
        } catch (err) {
            console.error('[PTK Automation] Engine start failed', engineName, err)
            session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                status: ENGINE_STATUS_ERROR,
                error: err.message
            })
            this._recordZapTiming(session, `engine.${String(engineName || '').toLowerCase()}.start.end`, {
                durationMs: Date.now() - engineStartedAt,
                result: 'error',
                error: err?.message || String(err)
            })
            return {
                ok: false,
                engine: engineName,
                status: ENGINE_STATUS_ERROR,
                error: err?.message || String(err)
            }
        }
    }

    _resolveEngineStartStatus(startResult = null) {
        const requestedStatus = String(startResult?.status || '').trim().toLowerCase()
        if (requestedStatus === ENGINE_STATUS_STARTING || requestedStatus === ENGINE_STATUS_RUNNING || requestedStatus === ENGINE_STATUS_DEFERRED_START) {
            return requestedStatus
        }
        if (startResult?.ok === false) {
            return ENGINE_STATUS_ERROR
        }
        return ENGINE_STATUS_RUNNING
    }

    _computeDeferredZapEngineStartDelay(session = null) {
        const sessionId = String(session?.id || '')
        if (!sessionId) {
            return ZAP_DEFERRED_ENGINE_START_BASE_DELAY_MS
        }
        let hash = 0
        for (let index = 0; index < sessionId.length; index += 1) {
            hash = (hash + sessionId.charCodeAt(index)) % 997
        }
        const bucket = hash % ZAP_DEFERRED_ENGINE_START_BUCKETS
        return ZAP_DEFERRED_ENGINE_START_BASE_DELAY_MS + (bucket * ZAP_DEFERRED_ENGINE_START_SPREAD_MS)
    }

    _buildZapStartupFailureMessage(failedEngines = []) {
        if (!Array.isArray(failedEngines) || failedEngines.length === 0) {
            return 'Required ZAP auto-mode engine failed to start'
        }

        return failedEngines
            .map(({ engine, error }) => `${String(engine || 'UNKNOWN').toUpperCase()} engine failed to start: ${error || 'unknown_error'}`)
            .join('; ')
    }

    async _cleanupFailedZapStartup(session) {
        if (!session || !Array.isArray(session.engines)) return

        for (const engineName of session.engines) {
            const state = session.engineStates?.[engineName] || null
            if (state?.status !== 'running') continue

            const adapter = this.engines?.getAdapter(engineName)
            if (!adapter) continue

            try {
                await adapter.stop(session.id, 30000)
                session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                    status: 'stopped'
                })
            } catch (err) {
                session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                    status: 'error',
                    error: err?.message || String(err)
                })
            }
        }
    }

    // === Session Progress Helpers ===

    getSessionProgressSnapshot(sessionId) {
        const session = this.sessions.get(sessionId)
        if (!session) {
            return { ok: false, error: 'session_not_found' }
        }

        const now = Date.now()
        const startedAtMs = session.startedAt ? Date.parse(session.startedAt) : now
        const elapsedMs = now - startedAtMs
        this._finalizeStoppedSessionIfExportReady(session, 'progress_snapshot')
        const sessionStatus = this._deriveSessionStatus(session)

        const enginesProgress = {}
        let totalFindingsCount = 0
        const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        let latestActivityAt = null
        let firstEngineError = null

        for (const engineName of session.engines) {
            const engineState = session.engineStates[engineName] || {}
            const progress = this._getEngineProgress(engineName, engineState)
            enginesProgress[engineName] = progress
            if (!firstEngineError && typeof engineState?.error === 'string' && engineState.error.trim()) {
                firstEngineError = `${engineName}:${engineState.error.trim()}`
            }

            totalFindingsCount += progress.findingsCount || 0

            if (progress.bySeverity) {
                for (const sev of Object.keys(bySeverity)) {
                    bySeverity[sev] += progress.bySeverity[sev] || 0
                }
            }

            if (progress.lastActivityAt) {
                const activityMs = Date.parse(progress.lastActivityAt)
                if (!latestActivityAt || activityMs > Date.parse(latestActivityAt)) {
                    latestActivityAt = progress.lastActivityAt
                }
            }
        }

        return {
            ok: true,
            sessionId: session.id,
            status: sessionStatus,
            error: session.error || firstEngineError || null,
            startedAt: session.startedAt,
            finishedAt: session.finishedAt,
            stopRequestedAt: session.stopRequestedAt || null,
            elapsedMs,
            lastUpdatedAt: latestActivityAt,
            engines: enginesProgress,
            summary: {
                findingsCount: totalFindingsCount,
                bySeverity
            },
            ...(sessionStatus === 'completed' && session.summary ? { finalSummary: session.summary } : {}),
            warnings: session.warnings || []
        }
    }

    getZapSessionProgressState(sessionId) {
        const snapshot = this.getSessionProgressSnapshot(sessionId)
        if (!snapshot?.ok) {
            return {
                ok: false,
                sessionId,
                error: 'session_not_found',
                message: 'PTK automation session was not found'
            }
        }

        const session = this.sessions.get(sessionId)
        if (!session) {
            return {
                ok: false,
                sessionId,
                error: 'session_not_found',
                message: 'PTK automation session was not found'
            }
        }

        const runtimeSnapshot = this._buildZapRuntimeSnapshot(session, snapshot)
        return {
            ok: true,
            sessionId,
            tabId: session.tabId ?? null,
            targetUrl: session.targetUrl || session.pageUrl || null,
            sessionStatus: snapshot.status,
            stopRequestedAt: session.stopRequestedAt || null,
            requiredEngines: runtimeSnapshot.requiredEngines,
            engines: runtimeSnapshot.engines,
            startedAt: session.startedAt || null,
            finishedAt: session.finishedAt || null,
            message: runtimeSnapshot.message || null
        }
    }

    _buildZapRuntimeSnapshot(session, snapshot) {
        const requiredEngines = Array.isArray(session?.engines)
            ? session.engines.map(engineName => String(engineName || '').toUpperCase()).filter(Boolean)
            : []
        const engines = {}
        let message = toNonEmptyString(session?.error) || null

        for (const engineName of requiredEngines) {
            const engineState = session?.engineStates?.[engineName] || {}
            const engineProgress = snapshot?.engines?.[engineName] || this._getEngineProgress(engineName, engineState)
            let telemetry = null

            if (engineName === 'DAST') {
                telemetry = this._buildZapDastRuntime(engineState, engineProgress, session)
            } else if (engineName === 'IAST') {
                telemetry = this._buildZapIastRuntime(engineState, engineProgress, session)
            } else if (engineName === 'SAST') {
                telemetry = this._buildZapSastRuntime(engineState, engineProgress, session)
            } else {
                telemetry = {
                    isRunning: engineProgress?.isRunning === true,
                    idle: engineProgress?.idle === true,
                    lastActivityAt: engineProgress?.lastActivityAt || null,
                    findingsCount: toFiniteNumber(engineProgress?.findingsCount, 0),
                    error: toNonEmptyString(engineProgress?.error) || toNonEmptyString(engineState?.error) || null
                }
            }

            engines[engineName] = {
                state: engineState.status || 'unknown',
                telemetry
            }

            if (!message) {
                message = toNonEmptyString(telemetry?.error)
            }
        }

        return {
            requiredEngines,
            engines,
            message
        }
    }

    _buildZapDastRuntime(engineState, engineProgress, session) {
        const coordinatorState = this._getDastAutomationCoordinatorState(session?.id)
        const hasCoordinatorState = coordinatorState && typeof coordinatorState === 'object'
        const planned = toFiniteNumber(engineProgress?.progress?.total)
        const executed = toFiniteNumber(engineProgress?.progress?.done)
        const remaining = toFiniteNumber(engineProgress?.progress?.remaining ?? engineProgress?.remaining)
        const activeTasks = toFiniteNumber(engineProgress?.activeTasks, 0)
        const taskQueue = toFiniteNumber(engineProgress?.taskQueue, 0)
        const requestQueue = toFiniteNumber(engineProgress?.requestQueue, 0)
        const pendingPlans = toFiniteNumber(engineProgress?.pendingPlans, 0)
        const planning = toFiniteNumber(engineProgress?.planning, 0)
        const pendingAutomationSeeds = hasCoordinatorState
            ? toFiniteNumber(coordinatorState?.pendingAutomationSeeds, 0)
            : 0
        const lastActivityAt = engineProgress?.lastActivityAt || null
        const hasObservedWork = [
            planned,
            executed,
            remaining,
            activeTasks,
            taskQueue,
            requestQueue,
            pendingPlans,
            planning,
            pendingAutomationSeeds,
            toFiniteNumber(engineProgress?.findingsCount, 0)
        ].some(value => Number.isFinite(value) && value > 0) || Boolean(toNonEmptyString(lastActivityAt))
        return {
            status: engineState?.status || 'unknown',
            isRunning: engineProgress?.isRunning === true,
            idle: engineProgress?.idle === true,
            phase: engineProgress?.phase || null,
            planned,
            executed,
            remaining,
            activeTasks,
            taskQueue,
            requestQueue,
            pendingPlans,
            planning,
            pendingAutomationSeeds,
            seededRequests: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.seeded, 0),
            proxySeededRequests: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.proxySeeded, 0),
            historySeededRequests: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeeded, 0),
            historySeedInputCount: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedInputCount, 0),
            historySeedTotalAvailable: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedTotalAvailable, 0),
            historySeedDroppedByCap: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedDroppedByCap, 0),
            historySeedDuplicatesSkipped: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedDuplicatesSkipped, 0),
            lastActivityAt,
            interactionRequired: hasCoordinatorState
                ? coordinatorState.requireUserInteractionBeforeCapture !== false
                : false,
            userInteractionUnlocked: hasCoordinatorState
                ? coordinatorState.userInteractionUnlocked === true
                : false,
            hasObservedWork,
            findingsCount: toFiniteNumber(engineProgress?.findingsCount, 0),
            error: toNonEmptyString(engineProgress?.error)
                || toNonEmptyString(engineState?.error)
                || null
        }
    }

    _buildZapIastRuntime(engineState, engineProgress, session) {
        const iast = this.app?.iast || null
        const scanResult = iast?.scanResult || null
        const tabId = Number.isInteger(session?.tabId) ? session.tabId : null
        const lastActivityAt = scanResult?.lastUpdatedAt
            || scanResult?.updatedAt
            || engineProgress?.lastActivityAt
            || null
        const requestsCount = Array.isArray(scanResult?.requests) ? scanResult.requests.length : 0
        const runtimeEventsCount = Array.isArray(scanResult?.runtimeEvents) ? scanResult.runtimeEvents.length : 0
        const findingsCount = Array.isArray(scanResult?.findings) ? scanResult.findings.length : toFiniteNumber(engineProgress?.findingsCount, 0)
        const hasAgentProbe = typeof iast?.isAgentReady === 'function'
        const agentReady = Number.isInteger(tabId)
            ? (hasAgentProbe ? iast.isAgentReady(tabId) : !!iast?.agentReadyTabs?.has?.(tabId))
            : false
        const activityError = Number.isInteger(tabId)
            ? toNonEmptyString(iast?.agentFailedTabs?.get?.(tabId))
            : null

        return {
            status: engineState?.status || 'unknown',
            isScanRunning: iast?.isScanRunning === true,
            agentReady,
            requestsCount,
            runtimeEventsCount,
            findingsCount,
            lastActivityAt,
            hasObservedActivity: requestsCount > 0 || runtimeEventsCount > 0 || findingsCount > 0 || Boolean(toNonEmptyString(lastActivityAt)),
            error: toNonEmptyString(engineProgress?.error) || toNonEmptyString(engineState?.error) || activityError || null
        }
    }

    _buildZapSastRuntime(engineState, engineProgress, session) {
        const liveProgress = this._getLiveSastAutomationProgress() || {}
        const automationState = this.app?.sast?.sessionCoordinator?.getAutomationState?.() || {}
        const scanResult = this.app?.sast?.scanResult || null
        const normalized = this._normalizeSastRuntimeFields({
            phase: liveProgress.phase || engineProgress?.phase || null,
            totalFiles: liveProgress.totalFiles ?? engineProgress?.totalFiles,
            completedFiles: liveProgress.completedFiles ?? engineProgress?.completedFiles,
            totalModules: liveProgress.totalModules ?? engineProgress?.totalModules,
            completedModules: liveProgress.completedModules ?? engineProgress?.completedModules,
            currentFile: liveProgress.currentFile || engineProgress?.currentFile || null,
            currentModule: liveProgress.currentModule || engineProgress?.currentModule || null,
            collectionState: automationState.collectionState || liveProgress.collectionState || engineProgress?.collectionState || null,
            analysisState: automationState.analysisState || liveProgress.analysisState || engineProgress?.analysisState || null,
            isSessionRunning: automationState.isSessionRunning === true || liveProgress.isRunning === true || engineProgress?.isRunning === true,
            isAnalysisRunning: automationState.isAnalysisRunning === true || liveProgress.isAnalysisRunning === true || engineProgress?.isAnalysisRunning === true,
            activeCollectionCount: automationState.activeCollectionCount,
            currentGeneration: automationState.currentGeneration,
            lastCompletedGeneration: automationState.lastCompletedGeneration || liveProgress.completedGeneration || engineProgress?.lastCompletedGeneration,
            sessionState: automationState.sessionState || liveProgress.sessionState || engineProgress?.sessionState || null
        })
        const phase = normalized.phase || null
        const totalFiles = toFiniteNumber(liveProgress.totalFiles ?? engineProgress?.totalFiles, 0)
        const completedFiles = toFiniteNumber(liveProgress.completedFiles ?? engineProgress?.completedFiles, 0)
        const totalModules = toFiniteNumber(liveProgress.totalModules ?? engineProgress?.totalModules, 0)
        const completedModules = toFiniteNumber(liveProgress.completedModules ?? engineProgress?.completedModules, 0)
        const currentFile = normalized.currentFile || null
        const currentModule = normalized.currentModule || null
        const lastStatus = toNonEmptyString(liveProgress.lastStatus || engineProgress?.lastStatus) || null
        const findings = toFiniteNumber(liveProgress.findings ?? engineProgress?.findings, 0)
        const hints = toFiniteNumber(liveProgress.hints ?? engineProgress?.hints, 0)
        const lastActivityAt = scanResult?.lastUpdatedAt
            || scanResult?.updatedAt
            || engineProgress?.lastActivityAt
            || null
        const hasObservedWork = totalFiles > 0
            || completedFiles > 0
            || totalModules > 0
            || completedModules > 0
            || Boolean(currentFile || currentModule || lastStatus)
            || (typeof phase === 'string' && phase.trim().toLowerCase() !== 'idle')
            || findings > 0
            || hints > 0

        return {
            status: engineState?.status || 'unknown',
            isRunning: normalized.isSessionRunning === true,
            isSessionRunning: normalized.isSessionRunning === true,
            isAnalysisRunning: normalized.isAnalysisRunning === true,
            phase,
            totalFiles,
            completedFiles,
            totalModules,
            completedModules,
            currentFile,
            currentModule,
            lastStatus,
            findings,
            hints,
            firstCollectionStarted: automationState.firstCollectionStarted === true,
            firstCollectionSettled: automationState.firstCollectionSettled === true,
            firstCollectionError: toNonEmptyString(automationState.firstCollectionError) || null,
            activeCollectionCount: normalized.activeCollectionCount,
            collectionState: normalized.collectionState || null,
            sessionState: normalized.sessionState || null,
            analysisState: normalized.analysisState || null,
            currentGeneration: normalized.currentGeneration,
            lastCompletedGeneration: normalized.lastCompletedGeneration,
            lastCompletedFile: toNonEmptyString(automationState.lastCompletedFile) || null,
            lastCompletedModule: toNonEmptyString(automationState.lastCompletedModule) || null,
            lastCompletedAt: toNonEmptyString(automationState.lastCompletedAt) || null,
            lastActivityAt,
            hasObservedWork,
            error: toNonEmptyString(engineProgress?.error) || toNonEmptyString(engineState?.error) || null
        }
    }

    _normalizeSastRuntimeFields(input = {}) {
        const totalFiles = toFiniteNumber(input.totalFiles, 0)
        const completedFiles = toFiniteNumber(input.completedFiles, 0)
        const totalModules = toFiniteNumber(input.totalModules, 0)
        const completedModules = toFiniteNumber(input.completedModules, 0)
        const currentFile = toNonEmptyString(input.currentFile) || null
        const currentModule = toNonEmptyString(input.currentModule) || null
        const activeCollectionCount = toFiniteNumber(input.activeCollectionCount, 0)
        const currentGeneration = toFiniteNumber(input.currentGeneration, 0)
        const lastCompletedGeneration = toFiniteNumber(input.lastCompletedGeneration, 0)
        const isSessionRunning = input.isSessionRunning === true
        const collectionLooksComplete = sastCollectionLooksComplete({
            totalFiles,
            completedFiles,
            totalModules,
            completedModules,
            currentFile,
            currentModule,
            analysisState: input.analysisState,
            collectionState: input.collectionState
        }, { activeCollectionCount })
        if (!collectionLooksComplete) {
            return {
                phase: toNonEmptyString(input.phase) || null,
                currentFile,
                currentModule,
                collectionState: toNonEmptyString(input.collectionState) || null,
                sessionState: toNonEmptyString(input.sessionState) || null,
                analysisState: toNonEmptyString(input.analysisState) || null,
                isSessionRunning,
                isAnalysisRunning: input.isAnalysisRunning === true,
                activeCollectionCount,
                currentGeneration,
                lastCompletedGeneration
            }
        }
        return {
            phase: 'waiting',
            currentFile: null,
            currentModule: null,
            collectionState: isSessionRunning ? 'waiting_for_page_activity' : 'completed',
            sessionState: toNonEmptyString(input.sessionState) || (isSessionRunning ? 'running' : 'completed'),
            analysisState: 'complete',
            isSessionRunning,
            isAnalysisRunning: false,
            activeCollectionCount: 0,
            currentGeneration,
            lastCompletedGeneration: Math.max(lastCompletedGeneration, currentGeneration)
        }
    }

    _finalizeActiveSessionIfExportReady(session, reason = 'unknown') {
        if (!session || session.status === 'completed' || session.status === 'error') {
            return false
        }

        if (!session.stopRequestedAt) {
            return false
        }

        return this._finalizeStoppedSessionIfExportReady(session, reason)
    }

    _finalizeStoppedSessionIfExportReady(session, reason = 'unknown') {
        if (!session || session.status === 'completed' || session.status === 'error' || !session.stopRequestedAt) {
            return false
        }

        const engines = Array.isArray(session.engines) ? session.engines : []
        if (!engines.length) return false

        if (!engines.every(engineName => this._isEngineExportReady(session, engineName, { requireStop: true }))) return false

        for (const engineName of engines) {
            const engineUpper = String(engineName || '').toUpperCase()
            session.engineStates[engineUpper] = session.engineStates[engineUpper] || {}
            if (session.engineStates[engineUpper].status === 'stopping') {
                session.engineStates[engineUpper].status = 'stopped'
            }
        }

        session.warnings = Array.isArray(session.warnings) ? session.warnings : []
        session.warnings.push({
            code: 'session_finalized_after_idle_stop',
            reason,
            at: new Date().toISOString()
        })
        this._finalizeSession(session, this._collectCurrentStats(session))
        return true
    }

    _isEngineExportReady(session, engineName, { requireStop = true } = {}) {
        const engineUpper = String(engineName || '').toUpperCase()
        const engineState = session.engineStates?.[engineUpper] || {}
        const progress = this._getEngineProgress(engineUpper, engineState) || {}
        const state = String(engineState.status || '').toLowerCase()
        const status = String(progress.status || state || '').toLowerCase()
        const phase = String(progress.phase || '').toLowerCase()
        if (state === 'error' || status === 'error') return true
        if (state === 'stopped' || state === 'completed' || status === 'stopped' || status === 'completed') return true

        const remaining = toFiniteNumber(progress.remaining ?? progress.progress?.remaining, 0)
        const activeTasks = toFiniteNumber(progress.activeTasks, 0)
        const taskQueue = toFiniteNumber(progress.taskQueue, 0)
        const requestQueue = toFiniteNumber(progress.requestQueue, 0)
        const pendingPlans = toFiniteNumber(progress.pendingPlans, 0)
        const planning = toFiniteNumber(progress.planning, 0)
        const done = toFiniteNumber(progress.progress?.done, null)
        const total = toFiniteNumber(progress.progress?.total, null)
        const finiteComplete = total !== null && done !== null && done >= total
        const queueEmpty = remaining <= 0 && activeTasks <= 0 && taskQueue <= 0 && requestQueue <= 0 && pendingPlans <= 0 && planning <= 0
        const hasExplicitWorkCounters = [
            progress.remaining,
            progress.progress?.remaining,
            progress.activeTasks,
            progress.taskQueue,
            progress.requestQueue,
            progress.pendingPlans,
            progress.planning
        ].some(value => typeof value !== 'undefined' && value !== null)
        const sastComplete = engineUpper === 'SAST'
            && queueEmpty
            && (finiteComplete || progress.totalFiles > 0 && progress.completedFiles >= progress.totalFiles)
            && !progress.currentFile
            && !progress.currentModule
            && !/collection_pending|payload_received|analyzing|running/i.test(`${progress.collectionState || ''} ${progress.analysisState || ''}`)
        const passiveComplete = ['IAST', 'SCA'].includes(engineUpper) && queueEmpty && !hasExplicitWorkCounters
        const idleComplete = (state === 'stopping' || status === 'stopping' || status === 'idle' || phase === 'idle')
            && (hasExplicitWorkCounters || progress.idle === true || status === 'idle' || phase === 'idle')
            && queueEmpty
        if (requireStop && !session.stopRequestedAt) return false
        return idleComplete || finiteComplete && queueEmpty || sastComplete || passiveComplete
    }

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

    _getDastAutomationCoordinatorState(sessionId) {
        const state = this.app?.dast?.sessionCoordinator?.getState?.()
            || this.app?.rattacker?.sessionCoordinator?.getState?.()
            || null
        if (!state || typeof state !== 'object') return null
        const automationSessionId = toNonEmptyString(state.automationSession?.id)
        if (automationSessionId && sessionId && automationSessionId !== sessionId) {
            return null
        }
        return state
    }

    /**
     * Get progress for a single engine (fast, no blocking)
     * Uses existing stats from scanResult, avoids scanning findings array
     */
    _getEngineProgress(engineName, engineState) {
        const engineUpper = engineName.toUpperCase()
        const adapter = this.engines?.getAdapter(engineUpper) || null
        let liveIsRunning = false
        try {
            liveIsRunning = !!adapter?.isRunning?.()
        } catch (_) {
            liveIsRunning = false
        }

        const result = {
            status: engineState.status || 'unknown',
            isRunning: liveIsRunning,
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
            const liveProgress = this._getDastAutomationProgress()
            result.phase = liveProgress?.phase || this._getDastPhase()
            if (liveProgress) {
                result.progress = {
                    done: liveProgress.executed ?? null,
                    total: liveProgress.planned ?? null,
                    remaining: liveProgress.remaining ?? null
                }
                result.isRunning = liveProgress.isRunning === true
                result.idle = liveProgress.isIdle === true
                result.remaining = liveProgress.remaining ?? null
                result.activeTasks = liveProgress.activeTasks ?? 0
                result.taskQueue = liveProgress.taskQueue ?? 0
                result.requestQueue = liveProgress.requestQueue ?? 0
                result.pendingPlans = liveProgress.pendingPlans ?? 0
                result.planning = liveProgress.planning ?? 0
                result.lastActivityAt = liveProgress.lastActivityAt || result.lastActivityAt
                if (engineState.status === 'running' && result.idle) {
                    result.status = 'idle'
                }
            } else {
                const scanStats = scanResult.scanStats || {}

                const total = scanStats.totalJobsPlanned
                    ?? scanStats.total
                    ?? scanStats.queued
                    ?? null
                const done = scanStats.totalJobsExecuted
                    ?? scanStats.processed
                    ?? scanStats.executed
                    ?? scanResult.requestCount
                    ?? null

                result.progress = { done, total, remaining: null }
                result.idle = !result.isRunning
                result.remaining = null
            }
        } else if (engineUpper === 'SAST') {
            const liveProgress = this._getLiveSastAutomationProgress()
            if (liveProgress) {
                const normalized = this._normalizeSastRuntimeFields({
                    phase: liveProgress.phase || null,
                    totalFiles: liveProgress.totalFiles,
                    completedFiles: liveProgress.completedFiles,
                    totalModules: liveProgress.totalModules,
                    completedModules: liveProgress.completedModules,
                    currentFile: liveProgress.currentFile || null,
                    currentModule: liveProgress.currentModule || null,
                    collectionState: liveProgress.collectionState || null,
                    analysisState: liveProgress.analysisState || null,
                    isSessionRunning: liveProgress.isRunning === true || liveProgress.isSessionRunning === true,
                    isAnalysisRunning: liveProgress.isAnalysisRunning === true,
                    activeCollectionCount: liveProgress.activeCollectionCount,
                    currentGeneration: liveProgress.currentGeneration,
                    lastCompletedGeneration: liveProgress.lastCompletedGeneration || liveProgress.completedGeneration
                })
                result.phase = normalized.phase || null
                result.totalFiles = toFiniteNumber(liveProgress.totalFiles, 0)
                result.completedFiles = toFiniteNumber(liveProgress.completedFiles, 0)
                result.totalModules = toFiniteNumber(liveProgress.totalModules, 0)
                result.completedModules = toFiniteNumber(liveProgress.completedModules, 0)
                result.currentFile = normalized.currentFile || null
                result.currentModule = normalized.currentModule || null
                result.lastStatus = toNonEmptyString(liveProgress.lastStatus) || null
                result.findings = toFiniteNumber(liveProgress.findings, 0)
                result.hints = toFiniteNumber(liveProgress.hints, 0)
                result.isRunning = normalized.isSessionRunning === true
                result.isSessionRunning = normalized.isSessionRunning === true
                result.isAnalysisRunning = normalized.isAnalysisRunning === true
                result.collectionState = normalized.collectionState || null
                result.sessionState = normalized.sessionState || null
                result.analysisState = normalized.analysisState || null
                result.activeCollectionCount = normalized.activeCollectionCount
                result.currentGeneration = normalized.currentGeneration
                result.lastCompletedGeneration = normalized.lastCompletedGeneration
                result.lastCompletedFile = toNonEmptyString(liveProgress.lastCompletedFile) || null
                result.lastCompletedModule = toNonEmptyString(liveProgress.lastCompletedModule) || null
                result.lastCompletedAt = toNonEmptyString(liveProgress.lastCompletedAt) || null
                if (result.totalFiles > 0) {
                    result.progress = {
                        done: result.completedFiles,
                        total: result.totalFiles,
                        remaining: Math.max(result.totalFiles - result.completedFiles, 0)
                    }
                } else if (result.totalModules > 0) {
                    result.progress = {
                        done: result.completedModules,
                        total: result.totalModules,
                        remaining: Math.max(result.totalModules - result.completedModules, 0)
                    }
                } else {
                    result.progress = {
                        done: result.findingsCount,
                        total: null
                    }
                }
                const phase = String(result.phase || '').toLowerCase()
                result.idle = result.isAnalysisRunning !== true && (phase === 'waiting' || phase === 'idle')
            } else {
                result.progress = {
                    done: result.findingsCount,
                    total: null
                }
                result.idle = !result.isRunning
            }
        } else {
            // IAST/SCA: limited progress info
            result.progress = {
                done: result.findingsCount,
                total: null
            }
            result.idle = !result.isRunning
        }

        return result
    }

    /**
     * Get scanResult reference for engine (fast, no copy)
     */
    _getEngineScanResult(engineUpper) {
        const sources = {
            DAST: () => this.app?.dast?.engine?.scanResult
                || this.app?.rattacker?.engine?.scanResult
                || this.app?.dast?.scanResult
                || this.app?.rattacker?.scanResult,
            IAST: () => this.app?.iast?.scanResult,
            SAST: () => this.app?.sast?.scanResult,
            SCA: () => this.app?.sca?.scanResult
        }
        return sources[engineUpper]?.() || null
    }

    _getEngineExportModule(engineUpper) {
        const sources = {
            DAST: () => this.app?.dast || this.app?.rattacker || null,
            IAST: () => this.app?.iast || null,
            SAST: () => this.app?.sast || null,
            SCA: () => this.app?.sca || null
        }
        return sources[engineUpper]?.() || null
    }

    /**
     * Get DAST phase if available
     */
    _getDastPhase() {
        const dast = this.app?.dast || this.app?.rattacker
        if (!dast) return null

        // Helper to safely check running state (could be function or boolean)
        const isRunning = (val) => typeof val === 'function' ? val() : !!val

        // Check various state indicators
        if (isRunning(dast.isSpiderRunning) || dast.spiderRunning) return 'spider'
        if (isRunning(dast.isActiveRunning) || dast.activeRunning) return 'active'
        if (isRunning(dast.engine?.isRunning) || dast.isRunning) return 'scanning'

        return 'idle'
    }

    _getDastAutomationProgress() {
        const dast = this.app?.dast || this.app?.rattacker
        const snapshot = dast?.engine?.getProgressSnapshot?.()
        return snapshot && typeof snapshot === 'object' ? snapshot : null
    }

    _getLiveSastAutomationProgress() {
        const snapshot = this.app?.sast?._buildSastProgressSnapshot?.()
        return snapshot && typeof snapshot === 'object' ? snapshot : null
    }
}
