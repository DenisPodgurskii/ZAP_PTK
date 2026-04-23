'use strict'

import zapTransport from './zapTransport.js'
import ZapPublisher from './zapPublisher.js'

const SOURCE = 'ptk'
const TYPE_ALERTS_BATCH = 'alerts_batch'
const TYPE_DAST_FINDINGS_BATCH = 'dast_findings_batch'
const TYPE_IAST_FINDINGS_BATCH = 'iast_findings_batch'
const TYPE_SAST_FINDINGS_BATCH = 'sast_findings_batch'
const DAST_SCHEMA = 'ptk-zap-dast-finding-v1'
const IAST_SCHEMA = 'ptk-zap-iast-finding-v1'
const SAST_SCHEMA = 'ptk-zap-sast-finding-v1'
const DEFAULT_ZAP_ENGINES = ['DAST', 'IAST', 'SAST']
const ZAP_MODE_AUTO = 'auto'
const ZAP_MODE_MANUAL = 'manual'
const ZAP_PROGRESS_HEARTBEAT_MS = 2000
const ZAP_PROGRESS_IDLE_GRACE_MS = 6000
const ZAP_PASSIVE_ENGINE_IDLE_GRACE_MS = 8000
const ZAP_PROGRESS_FLUSH_TIMEOUT_MS = 3000
const ZAP_PROGRESS_FLUSH_GRACE_MS = 4000
const ZAP_PROGRESS_STATUS_READY = 'ready'
const ZAP_PROGRESS_STATUS_CALLBACK = 'callback'
const ZAP_PROGRESS_STATUS_RUNNING = 'running'
const ZAP_PROGRESS_STATUS_COMPLETED = 'completed'
const ZAP_PROGRESS_STATUS_ERROR = 'error'
const ZAP_PROGRESS_STATUS_CANCELLED = 'cancelled'
const ZAP_CALLBACK_PREFIX = /^https?:\/\/zap\/zapCallBackUrl\//i
const RULEPACK_KEYS = {
    dast: 'DAST',
    iast: 'IAST',
    sast: 'SAST'
}
const AUTO_START_NAV_SOURCES = new Set([
    'webNavigation.onCommitted',
    'webNavigation.onBeforeNavigate',
    'tabs.onUpdated',
    'tabs.onReplaced',
    'bootstrap.tabs.query',
    'history.bootstrap',
    'history.onVisited'
])
const AUTO_START_OBSERVED_MAX_AGE_MS = 120000
const ZAP_ALLOWED_DEBUG_PREFIXES = [
    '[PTK ZAP] Bootstrapping zapBridge',
    '[PTK ZAP] zapBridge bootstrapped',
    '[PTK ZAP] Fetching ZAP config...',
    '[PTK ZAP] ZAP config resolved:',
    '[PTK ZAP] Handling ZAP detection:',
    '[PTK ZAP] ZAP detection context:',
    '[PTK ZAP] Callback handshake progress',
    '[PTK ZAP] ZAP is active, starting publisher',
    '[PTK ZAP] New base URL detected',
    '[PTK ZAP] Automation module not attached',
    '[PTK ZAP] mode is manual',
    '[PTK ZAP] Parsed ZAP auto config:',
    '[PTK ZAP] Auto-start engine selection:',
    '[PTK ZAP] Resolved target URL:',
    '[PTK ZAP] Resolved target tab:',
    '[PTK ZAP] Target URL not available',
    '[PTK ZAP] Target URL resolved but tabId',
    '[PTK ZAP] Pending auto-start',
    '[PTK ZAP] Replaying cached target navigation',
    '[PTK ZAP] Starting ZAP-driven automation:',
    '[PTK ZAP] Duplicate ZAP-driven automation start suppressed:',
    '[PTK ZAP] ZAP-driven automation result:',
    '[PTK ZAP] Starting progress monitor:',
    '[PTK ZAP] Progress monitor unavailable:',
    '[PTK ZAP] Progress monitor switched zapid:',
    '[PTK ZAP] Progress monitor completed:',
    '[PTK ZAP] No enabled PTK engines'
]

function createBatchId() {
    if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
        return globalThis.crypto.randomUUID()
    }
    return `ptk-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms))
}

function toObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null
    return value
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

function isFiniteNumber(value) {
    return Number.isFinite(Number(value))
}

function clampProgress(value, max = 100) {
    const num = toFiniteNumber(value, 0)
    return Math.max(0, Math.min(max, Math.round(num)))
}

function normalizeEngineList(engines = []) {
    if (!Array.isArray(engines)) return []
    return Array.from(new Set(
        engines
            .map(engineName => String(engineName || '').toUpperCase().trim())
            .filter(Boolean)
    ))
}

function hasEnabledRulepack(engineConfig) {
    const modules = engineConfig?.rulepack?.modules
    return Array.isArray(modules) && modules.length > 0
}

function toHttpUrl(value) {
    if (typeof value !== 'string' || !value.trim()) return null
    try {
        const url = new URL(value)
        const host = String(url.hostname || '').toLowerCase()
        if ((url.protocol === 'http:' || url.protocol === 'https:')
            && host !== 'zap'
            && !ZAP_CALLBACK_PREFIX.test(url.toString())) {
            return url.toString()
        }
    } catch (_) {
        return null
    }
    return null
}

function toHostKeyFromUrl(value) {
    const url = toHttpUrl(value)
    if (!url) return null
    try {
        return new URL(url).host.toLowerCase() || null
    } catch (_) {
        return null
    }
}

class ZapBridge {
    constructor() {
        this.transport = zapTransport
        this.publisher = null
        this.app = null
        this.resultsRegistry = null
        this.bootstrapped = false
        this.currentBaseUrl = null
        this.currentSessionKey = null
        this._unsubscribeDetected = null
        this._unsubscribeUrlObserved = null
        this._startInFlight = null
        this._lastStartKey = null
        this._lastStartSessionId = null
        this._pendingStart = null
        this._progressMonitor = null
        this._callbackProgressSent = new Set()
        this._lastTopLevelTargetObservation = null
        this._timingStateByKey = new Map()
        this._resolvedConfig = {
            mode: ZAP_MODE_MANUAL,
            engineConfigs: {},
            fetchedAt: null,
            baseUrl: null
        }
    }

    bootstrap() {
        if (this.bootstrapped) return

        this._syncDebugFlagFromApp()
        this._debugLog('[PTK ZAP] Bootstrapping zapBridge')
        this._unsubscribeDetected = this.transport.onZapDetected((payload) => {
            this._handleZapDetected(payload)
        })
        this._unsubscribeUrlObserved = this.transport.onUrlObserved((payload) => {
            this._handleUrlObserved(payload)
        })
        this.transport.init()
        this.bootstrapped = true

        this._debugLog('[PTK ZAP] zapBridge bootstrapped, waiting for ZAP detection')
    }

    attach(app, resultsRegistry) {
        this.bootstrap()

        this.app = app || this.app
        this.resultsRegistry = resultsRegistry || this.resultsRegistry
        this._syncDebugFlagFromApp()

        if (this.app && this.resultsRegistry && !this.publisher) {
            this.publisher = new ZapPublisher(this.app, this, this.resultsRegistry)
        } else if (this.publisher) {
            this.publisher.app = this.app
            this.publisher.resultsRegistry = this.resultsRegistry
        }

        this._replayActiveDetection()
    }

    // Backward-compat alias: init() with no args => bootstrap, with args => attach.
    init(app, resultsRegistry) {
        if (app || resultsRegistry) {
            this.attach(app, resultsRegistry)
            return
        }
        this.bootstrap()
    }

    _replayActiveDetection() {
        if (!this.app || !this.transport.isActive()) {
            return
        }

        const payload = this.transport.getLastDetectedPayload?.()
            || {
                baseUrl: this.transport.getBaseUrl(),
                configUrl: this.transport.getConfigUrl(),
                alertsUrl: this.transport.getAlertsUrl?.(),
                progressUrl: this.transport.getProgressUrl?.(),
                zapid: this.transport.getZapId?.()
            }

        void this._handleZapDetectedAsync(payload)
    }

    start() {
        if (!this.publisher) return
        this.publisher.start()
    }

    isActive() {
        return this.transport.isActive()
    }

    _resolveDebugEnabled() {
        const zapEnabled = this.app?.settings?.zap?.enable_logging
        if (typeof zapEnabled === 'boolean') {
            return zapEnabled === true
        }
        return this.app?.settings?.main?.enable_logging === true
    }

    _syncDebugFlagFromApp() {
        const enabled = this._resolveDebugEnabled()
        if (typeof this.transport?.setDebugEnabled === 'function') {
            this.transport.setDebugEnabled(enabled)
        }
    }

    _debugLog(...args) {
        const enabled = this._resolveDebugEnabled()
        if (this.transport?.isDebugEnabled?.() !== enabled) {
            this.transport?.setDebugEnabled?.(enabled)
        }
        if (!enabled) return
        const prefix = typeof args[0] === 'string' ? args[0] : ''
        if (!ZAP_ALLOWED_DEBUG_PREFIXES.some(allowed => prefix.startsWith(allowed))) {
            return
        }
        console.log(...args)
    }

    _buildZapSessionKey(baseUrl, zapid) {
        if (!baseUrl) return null
        return `${baseUrl}|${zapid || ''}`
    }

    _buildTimingKey({ zapSessionKey = null, zapid = null, automationSessionId = null, tabId = null, targetUrl = null } = {}) {
        return toNonEmptyString(zapSessionKey)
            || toNonEmptyString(zapid)
            || toNonEmptyString(automationSessionId)
            || (Number.isInteger(tabId) ? `tab:${tabId}` : null)
            || toNonEmptyString(targetUrl)
            || null
    }

    _ensureTimingState({ zapSessionKey = null, zapid = null, browserid = null, automationSessionId = null, tabId = null, targetUrl = null, anchorMs = null } = {}) {
        const effectiveZapId = toNonEmptyString(zapid) || this.transport.getZapId?.() || null
        const key = this._buildTimingKey({
            zapSessionKey,
            zapid: effectiveZapId,
            automationSessionId,
            tabId,
            targetUrl
        })
        if (!key) return null

        const now = Date.now()
        const state = this._timingStateByKey.get(key) || {
            key,
            anchorMs: null,
            markers: new Set()
        }

        state.zapid = toNonEmptyString(effectiveZapId) || state.zapid || null
        state.browserid = toNonEmptyString(browserid) || this.transport.getBrowserId?.() || state.browserid || null
        state.zapSessionKey = toNonEmptyString(zapSessionKey) || state.zapSessionKey || null
        state.automationSessionId = toNonEmptyString(automationSessionId) || state.automationSessionId || null
        state.tabId = Number.isInteger(tabId) ? tabId : (state.tabId ?? null)
        state.targetUrl = toNonEmptyString(targetUrl) || state.targetUrl || null

        if (isFiniteNumber(anchorMs)) {
            state.anchorMs = Number(anchorMs)
        } else if (!isFiniteNumber(state.anchorMs)) {
            state.anchorMs = now
        }

        this._timingStateByKey.set(key, state)
        return state
    }

    _formatTimingField(name, value) {
        if (value == null || value === '') return null
        if (typeof value === 'number' || typeof value === 'boolean') {
            return `${name}=${value}`
        }
        return `${name}=${JSON.stringify(String(value))}`
    }

    recordTiming({
        phase,
        zapid = null,
        browserid = null,
        zapSessionKey = null,
        automationSessionId = null,
        tabId = null,
        targetUrl = null,
        elapsedMs = null,
        anchorMs = null,
        startedAtMs = null,
        onceKey = null,
        extra = null
    } = {}) {
        const phaseName = toNonEmptyString(phase)
        if (!phaseName) return false

        const state = this._ensureTimingState({
            zapSessionKey,
            zapid,
            browserid,
            automationSessionId,
            tabId,
            targetUrl,
            anchorMs
        })
        if (!state) return false

        const markerKey = toNonEmptyString(onceKey)
        if (markerKey && state.markers.has(markerKey)) {
            return false
        }

        const now = Date.now()
        let effectiveElapsedMs = null
        if (isFiniteNumber(elapsedMs)) {
            effectiveElapsedMs = Math.max(0, Math.round(Number(elapsedMs)))
        } else if (isFiniteNumber(startedAtMs)) {
            effectiveElapsedMs = Math.max(0, now - Number(startedAtMs))
        } else if (isFiniteNumber(state.anchorMs)) {
            effectiveElapsedMs = Math.max(0, now - Number(state.anchorMs))
        } else {
            effectiveElapsedMs = 0
        }

        if (markerKey) {
            state.markers.add(markerKey)
        }

        const fields = [
            '[PTK_ZAP_TIMING]',
            this._formatTimingField('zapid', state.zapid),
            this._formatTimingField('browserid', state.browserid),
            this._formatTimingField('zapSessionKey', state.zapSessionKey),
            this._formatTimingField('automationSessionId', state.automationSessionId),
            this._formatTimingField('tabId', state.tabId),
            this._formatTimingField('targetUrl', state.targetUrl),
            this._formatTimingField('phase', phaseName),
            this._formatTimingField('elapsedMs', effectiveElapsedMs)
        ]

        if (extra && typeof extra === 'object' && !Array.isArray(extra)) {
            for (const [name, value] of Object.entries(extra)) {
                if (value == null || typeof value === 'object') continue
                fields.push(this._formatTimingField(name, value))
            }
        }

        console.log(fields.filter(Boolean).join(' '))
        return true
    }

    _clearProgressMonitor() {
        if (this._progressMonitor?.intervalId) {
            clearInterval(this._progressMonitor.intervalId)
        }
        this._progressMonitor = null
    }

    _clearProgressMonitorIfCurrent(monitor) {
        if (this._progressMonitor !== monitor) return
        this._clearProgressMonitor()
    }

    _buildProgressMonitorPayload({ progress, status, message = null, engines = null }) {
        const payload = {
            progress,
            status
        }
        const text = toNonEmptyString(message)
        if (text) {
            payload.message = text
        }
        if (engines && typeof engines === 'object' && !Array.isArray(engines)) {
            payload.engines = engines
        }
        return payload
    }

    _getRequiredZapEngines(monitor = null, runtimeSnapshot = null) {
        return normalizeEngineList(
            monitor?.requiredEngines?.length
                ? monitor.requiredEngines
                : runtimeSnapshot?.requiredEngines
        )
    }

    _buildReadyEngineStates(requiredEngines = []) {
        const engines = {}
        for (const engineName of normalizeEngineList(requiredEngines)) {
            engines[engineName] = {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0
            }
        }
        return engines
    }

    _buildStartupFailureEngineStates(startResult = {}, requiredEngines = []) {
        const engineNames = normalizeEngineList([
            ...normalizeEngineList(requiredEngines),
            ...normalizeEngineList(startResult?.startedEngines),
            ...normalizeEngineList(Array.isArray(startResult?.failedEngines)
                ? startResult.failedEngines.map(entry => entry?.engine)
                : [])
        ])
        if (!engineNames.length) return null

        const engines = {}
        for (const engineName of engineNames) {
            engines[engineName] = {
                status: ZAP_PROGRESS_STATUS_CANCELLED,
                progress: 100,
                message: 'PTK scan was aborted during startup'
            }
        }

        for (const failed of Array.isArray(startResult?.failedEngines) ? startResult.failedEngines : []) {
            const engineName = String(failed?.engine || '').toUpperCase().trim()
            if (!engineName) continue
            engines[engineName] = {
                status: ZAP_PROGRESS_STATUS_ERROR,
                progress: 100,
                message: toNonEmptyString(failed?.error) || 'engine_start_failed'
            }
        }

        return engines
    }

    _startProgressMonitor({ sessionKey, sessionId = null, zapid = null, requiredEngines = null, terminalPayload = null } = {}) {
        const effectiveSessionKey = sessionKey || this._buildZapSessionKey(this.transport.getBaseUrl?.(), zapid || this.transport.getZapId?.())
        const effectiveZapId = zapid || this.transport.getZapId?.() || null
        if (!effectiveSessionKey || !effectiveZapId) {
            this._debugLog('[PTK ZAP] Progress monitor unavailable:', {
                sessionKey: effectiveSessionKey || null,
                sessionId,
                zapid: effectiveZapId || null,
                requiredEngines: normalizeEngineList(requiredEngines)
            })
            return
        }

        this.transport.clearSessionTerminal?.()

        const existing = this._progressMonitor
        if (existing && existing.sessionKey === effectiveSessionKey && existing.sessionId === (sessionId || null)) {
            if (Array.isArray(requiredEngines) && requiredEngines.length) {
                existing.requiredEngines = normalizeEngineList(requiredEngines)
            }
            if (terminalPayload) {
                existing.terminalPayload = terminalPayload
            }
            return
        }

        this._clearProgressMonitor()

        const monitor = {
            sessionKey: effectiveSessionKey,
            sessionId: sessionId || null,
            zapid: effectiveZapId,
            requiredEngines: normalizeEngineList(requiredEngines),
            readySent: terminalPayload ? true : false,
            quietSince: null,
            lastRuntimeSnapshot: null,
            lastDerivedEngineStates: null,
            terminalPayload: terminalPayload || null,
            pendingFlushSince: null,
            enginePassiveSince: Object.create(null),
            intervalId: null
        }

        this._progressMonitor = monitor
        this._debugLog('[PTK ZAP] Starting progress monitor:', {
            sessionKey: effectiveSessionKey,
            sessionId: sessionId || null,
            zapid: effectiveZapId,
            requiredEngines: monitor.requiredEngines,
            terminal: !!terminalPayload
        })

        const tick = () => {
            void this._tickProgressMonitor(monitor)
        }

        tick()
        monitor.intervalId = setInterval(tick, ZAP_PROGRESS_HEARTBEAT_MS)
    }

    _scheduleTerminalProgress({ sessionKey, sessionId = null, zapid = null, requiredEngines = null, status = ZAP_PROGRESS_STATUS_ERROR, message = null, engines = null } = {}) {
        const payload = this._buildProgressMonitorPayload({
            progress: 100,
            status,
            message,
            engines
        })
        this._startProgressMonitor({
            sessionKey,
            sessionId,
            zapid,
            requiredEngines,
            terminalPayload: payload
        })
    }

    async _tickProgressMonitor(monitor) {
        if (this._progressMonitor !== monitor) {
            return
        }
        if (this.transport.getZapId?.() !== monitor.zapid) {
            this._debugLog('[PTK ZAP] Progress monitor switched zapid:', {
                monitorZapId: monitor.zapid,
                activeZapId: this.transport.getZapId?.() || null,
                sessionId: monitor.sessionId
            })
            this._clearProgressMonitorIfCurrent(monitor)
            return
        }

        let payload = monitor.terminalPayload
        if (!payload) {
            if (!monitor.readySent) {
                payload = this._buildProgressMonitorPayload({
                    progress: 0,
                    status: ZAP_PROGRESS_STATUS_READY,
                    engines: this._buildReadyEngineStates(monitor.requiredEngines)
                })
            } else {
                const automation = this.app?.automation
                const runtimeSnapshot = automation?.getZapSessionProgressState?.(monitor.sessionId)
                    || {
                        ok: false,
                        error: 'session_progress_unavailable',
                        message: 'PTK automation session progress is unavailable'
                    }

                if (!runtimeSnapshot?.ok) {
                    payload = this._buildProgressMonitorPayload({
                        progress: 100,
                        status: ZAP_PROGRESS_STATUS_ERROR,
                        message: runtimeSnapshot?.message || 'PTK automation session progress is unavailable'
                    })
                    monitor.terminalPayload = payload
                } else {
                    const derivedState = this._deriveZapProgressState(monitor, runtimeSnapshot)
                    const runtimeRequiredEngines = this._getRequiredZapEngines(monitor, runtimeSnapshot)
                    monitor.lastRuntimeSnapshot = runtimeSnapshot
                    monitor.lastDerivedEngineStates = derivedState.engines
                    if (derivedState.terminal) {
                        const flushed = await this._flushPublisherWithTimeout()
                        if (flushed) {
                            payload = this._buildZapProgressPayloadFromDerivedState(derivedState)
                            monitor.terminalPayload = payload
                            monitor.pendingFlushSince = null
                        } else {
                            const now = Date.now()
                            if (!monitor.pendingFlushSince) {
                                monitor.pendingFlushSince = now
                            }
                            const flushGraceElapsed = (now - monitor.pendingFlushSince) >= ZAP_PROGRESS_FLUSH_GRACE_MS
                            if (flushGraceElapsed) {
                                payload = this._buildZapProgressPayloadFromDerivedState(derivedState)
                                monitor.terminalPayload = payload
                            } else {
                                payload = this._buildProgressMonitorPayload({
                                    progress: this._computeZapAggregateProgress(derivedState.engines, runtimeRequiredEngines),
                                    status: ZAP_PROGRESS_STATUS_RUNNING,
                                    engines: derivedState.engines
                                })
                            }
                        }
                    } else {
                        monitor.pendingFlushSince = null
                        payload = this._buildZapProgressPayloadFromDerivedState(derivedState)
                    }
                }
            }
        }

        try {
            await this.transport.postProgressJson(payload)
            this.recordTiming({
                phase: 'progress.post.first',
                zapid: monitor.zapid,
                browserid: this.transport.getBrowserId?.() || null,
                zapSessionKey: monitor.sessionKey,
                automationSessionId: monitor.sessionId,
                tabId: monitor.lastRuntimeSnapshot?.tabId || null,
                targetUrl: monitor.lastRuntimeSnapshot?.targetUrl || null,
                onceKey: 'progress.post.first',
                extra: {
                    progress: payload.progress,
                    status: payload.status
                }
            })
            this._debugLog('[PTK ZAP] Progress monitor posted:', {
                zapid: monitor.zapid,
                sessionId: monitor.sessionId,
                progress: payload.progress,
                status: payload.status,
                engines: payload.engines || null,
                terminal: !!monitor.terminalPayload
            })
            if (!monitor.readySent && payload.status === ZAP_PROGRESS_STATUS_READY) {
                monitor.readySent = true
                return
            }
            if (monitor.terminalPayload || payload.progress === 100) {
                this.recordTiming({
                    phase: 'progress.post.terminal',
                    zapid: monitor.zapid,
                    browserid: this.transport.getBrowserId?.() || null,
                    zapSessionKey: monitor.sessionKey,
                    automationSessionId: monitor.sessionId,
                    tabId: monitor.lastRuntimeSnapshot?.tabId || null,
                    targetUrl: monitor.lastRuntimeSnapshot?.targetUrl || null,
                    onceKey: 'progress.post.terminal',
                    extra: {
                        progress: payload.progress,
                        status: payload.status
                    }
                })
                this._debugLog('[PTK ZAP] Progress monitor completed:', {
                    zapid: monitor.zapid,
                    sessionId: monitor.sessionId,
                    progress: payload.progress,
                    status: payload.status
                })
                this.transport.markSessionTerminal?.({
                    zapid: monitor.zapid,
                    sessionId: monitor.sessionId,
                    progress: payload.progress,
                    status: payload.status
                })
                this._clearProgressMonitorIfCurrent(monitor)
            }
        } catch (err) {
            console.warn('[PTK ZAP] Failed to POST ZAP progress update:', err?.message || String(err))
        }
    }

    _deriveZapProgressState(monitor, runtimeSnapshot) {
        const requiredEngines = this._getRequiredZapEngines(monitor, runtimeSnapshot)
        const engineStates = this._deriveZapEngineStates(monitor, runtimeSnapshot, requiredEngines)
        const sessionMessage = toNonEmptyString(runtimeSnapshot?.message)
        const errorMessage = sessionMessage || this._findFirstEngineMessage(engineStates, requiredEngines)
        if (errorMessage) {
            return {
                status: ZAP_PROGRESS_STATUS_ERROR,
                progress: 100,
                engines: engineStates,
                terminal: true,
                message: errorMessage
            }
        }

        const stopRequested = Boolean(runtimeSnapshot?.stopRequestedAt)
        if (stopRequested) {
            const cancelled = this._areRequiredEnginesSettled(engineStates, requiredEngines)
            return {
                status: cancelled ? ZAP_PROGRESS_STATUS_CANCELLED : ZAP_PROGRESS_STATUS_RUNNING,
                progress: cancelled ? 100 : this._computeZapAggregateProgress(engineStates, requiredEngines),
                engines: engineStates,
                terminal: cancelled,
                message: cancelled ? 'PTK scan was stopped by user' : null
            }
        }

        const completed = this._updateZapIdleGraceWindow(monitor, engineStates, runtimeSnapshot, requiredEngines)
        if (completed) {
            return {
                status: ZAP_PROGRESS_STATUS_COMPLETED,
                progress: 100,
                engines: engineStates,
                terminal: true,
                message: null
            }
        }

        const status = this._deriveZapTopLevelStatus(engineStates, {
            requiredEngines,
            startupReadySent: monitor.readySent,
            stopRequested: false,
            hasError: false
        })
        return {
            status,
            progress: status === ZAP_PROGRESS_STATUS_READY
                ? 0
                : this._computeZapAggregateProgress(engineStates, requiredEngines),
            engines: engineStates,
            terminal: false,
            message: null
        }
    }

    _deriveZapEngineStates(monitor, runtimeSnapshot, requiredEngines = null) {
        const engines = {}
        const engineNames = normalizeEngineList(requiredEngines?.length ? requiredEngines : runtimeSnapshot?.requiredEngines)
        for (const engineName of engineNames) {
            const runtimeEntry = runtimeSnapshot?.engines?.[engineName] || null
            const previousRuntimeEntry = monitor?.lastRuntimeSnapshot?.engines?.[engineName] || null

            if (engineName === 'DAST') {
                engines[engineName] = this._deriveZapDastEngineState(runtimeEntry, previousRuntimeEntry)
                continue
            }
            if (engineName === 'IAST') {
                engines[engineName] = this._deriveZapIastEngineState(runtimeEntry, previousRuntimeEntry)
                continue
            }
            if (engineName === 'SAST') {
                engines[engineName] = this._deriveZapSastEngineState(runtimeEntry, previousRuntimeEntry)
                continue
            }

            engines[engineName] = {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0
            }
        }
        return engines
    }

    _deriveZapDastEngineState(runtimeEntry, previousRuntimeEntry = null) {
        if (!runtimeEntry || typeof runtimeEntry !== 'object') {
            return { status: 'starting', progress: 0 }
        }

        const runtime = runtimeEntry.telemetry || {}
        const error = toNonEmptyString(runtime?.error)
        if (error) {
            return {
                status: ZAP_PROGRESS_STATUS_ERROR,
                progress: 100,
                message: error
            }
        }

        const interactionRequired = runtime?.interactionRequired === true
        const userInteractionUnlocked = runtime?.userInteractionUnlocked === true
        const hasObservedWork = runtime?.hasObservedWork === true
        const activeTasks = toFiniteNumber(runtime?.activeTasks, 0)
        const taskQueue = toFiniteNumber(runtime?.taskQueue, 0)
        const requestQueue = toFiniteNumber(runtime?.requestQueue, 0)
        const pendingPlans = toFiniteNumber(runtime?.pendingPlans, 0)
        const planning = toFiniteNumber(runtime?.planning, 0)
        const hasActiveWork = activeTasks > 0 || taskQueue > 0 || requestQueue > 0 || pendingPlans > 0 || planning > 0
        const progress = this._computeZapDastProgress(runtime)

        if (runtimeEntry.state === 'starting') {
            return { status: 'starting', progress: 0 }
        }
        if (hasActiveWork) {
            return {
                status: ZAP_PROGRESS_STATUS_RUNNING,
                progress: clampProgress(progress, 99)
            }
        }
        if (interactionRequired && !userInteractionUnlocked) {
            return {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0
            }
        }
        if (!hasObservedWork) {
            return {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0
            }
        }

        return {
            status: 'idle',
            progress: 100
        }
    }

    _deriveZapIastEngineState(runtimeEntry, previousRuntimeEntry = null) {
        if (!runtimeEntry || typeof runtimeEntry !== 'object') {
            return { status: 'starting', progress: 0 }
        }

        const runtime = runtimeEntry.telemetry || {}
        const previousRuntime = previousRuntimeEntry?.telemetry || null
        const error = toNonEmptyString(runtime?.error)
        if (error) {
            return {
                status: ZAP_PROGRESS_STATUS_ERROR,
                progress: 100,
                message: error
            }
        }

        const isScanRunning = runtime?.isScanRunning === true
        const agentReady = runtime?.agentReady === true
        const hasObservedActivity = runtime?.hasObservedActivity === true

        if (runtimeEntry.state === 'starting' || (isScanRunning && !agentReady)) {
            return { status: 'starting', progress: 0 }
        }
        if (!hasObservedActivity) {
            return {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0
            }
        }
        if (isScanRunning !== true) {
            return {
                status: 'idle',
                progress: 100
            }
        }
        if (this._didZapIastRuntimeAdvance(runtime, previousRuntime)) {
            return {
                status: ZAP_PROGRESS_STATUS_RUNNING,
                progress: 0
            }
        }

        return {
            status: 'idle',
            progress: 100
        }
    }

    _deriveZapSastEngineState(runtimeEntry, previousRuntimeEntry = null) {
        if (!runtimeEntry || typeof runtimeEntry !== 'object') {
            return { status: 'starting', progress: 0 }
        }

        const runtime = runtimeEntry.telemetry || {}
        const error = toNonEmptyString(runtime?.error)
        if (error) {
            return {
                status: ZAP_PROGRESS_STATUS_ERROR,
                progress: 100,
                message: error
            }
        }

        const phase = String(runtime?.phase || '').toLowerCase()
        const activePhases = new Set(['scan_start', 'file', 'module', 'file_complete', 'module_complete'])
        const hasObservedWork = runtime?.hasObservedWork === true
        const progress = this._computeZapSastProgress(runtime)

        if (runtimeEntry.state === 'starting') {
            return { status: 'starting', progress: 0 }
        }
        if (activePhases.has(phase)) {
            return {
                status: ZAP_PROGRESS_STATUS_RUNNING,
                progress: clampProgress(progress, 99)
            }
        }
        if (!hasObservedWork) {
            return {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0
            }
        }

        return {
            status: 'idle',
            progress: 100
        }
    }

    _deriveZapTopLevelStatus(engineStates, { requiredEngines = [], stopRequested = false, hasError = false } = {}) {
        if (hasError) return ZAP_PROGRESS_STATUS_ERROR
        if (stopRequested) return ZAP_PROGRESS_STATUS_CANCELLED

        const engineNames = normalizeEngineList(requiredEngines)
        if (!engineNames.length) return ZAP_PROGRESS_STATUS_READY

        if (engineNames.some(engineName => engineStates?.[engineName]?.status === ZAP_PROGRESS_STATUS_RUNNING)) {
            return ZAP_PROGRESS_STATUS_RUNNING
        }

        const allReadyOrStarting = engineNames.every((engineName) => {
            const status = engineStates?.[engineName]?.status
            return status === ZAP_PROGRESS_STATUS_READY || status === 'starting'
        })
        if (allReadyOrStarting) {
            return ZAP_PROGRESS_STATUS_READY
        }

        return ZAP_PROGRESS_STATUS_RUNNING
    }

    _computeZapAggregateProgress(engineStates, requiredEngines = []) {
        const engineNames = normalizeEngineList(requiredEngines).filter(engineName => engineStates?.[engineName])
        if (!engineNames.length) return 0

        const total = engineNames.reduce((sum, engineName) => (
            sum + toFiniteNumber(engineStates?.[engineName]?.progress, 0)
        ), 0)
        return clampProgress(total / engineNames.length, 99)
    }

    _updateZapIdleGraceWindow(monitor, engineStates, runtimeSnapshot, requiredEngines = []) {
        const engineNames = normalizeEngineList(requiredEngines)
        const previousRuntimeSnapshot = monitor?.lastRuntimeSnapshot || null
        const allQuiet = engineNames.length > 0
            && engineNames.every((engineName) => this._isZapEngineQuiet({
                monitor,
                engineName,
                engineState: engineStates?.[engineName] || null,
                runtimeEntry: runtimeSnapshot?.engines?.[engineName] || null,
                previousRuntimeEntry: previousRuntimeSnapshot?.engines?.[engineName] || null,
                engineStates,
                requiredEngines: engineNames
            }))

        if (!allQuiet) {
            monitor.quietSince = null
            return false
        }

        const now = Date.now()
        if (!monitor.quietSince) {
            monitor.quietSince = now
            return false
        }

        return (now - monitor.quietSince) >= ZAP_PROGRESS_IDLE_GRACE_MS
    }

    _isZapEngineQuiet({
        monitor,
        engineName,
        engineState = null,
        runtimeEntry = null,
        previousRuntimeEntry = null,
        engineStates = {},
        requiredEngines = []
    } = {}) {
        const normalizedEngineName = String(engineName || '').toUpperCase().trim()
        const status = String(engineState?.status || '').trim().toLowerCase()
        const runtime = runtimeEntry?.telemetry || null
        const previousRuntime = previousRuntimeEntry?.telemetry || null
        const passiveSince = monitor?.enginePassiveSince || (monitor.enginePassiveSince = Object.create(null))
        const clearPassive = () => {
            delete passiveSince[normalizedEngineName]
        }

        if (normalizedEngineName === 'DAST' && runtime?.isRunning === true) {
            const quietCandidate = runtime?.idle === true
                || status === 'idle'
                || !this._didZapDastRuntimeAdvance(runtime, previousRuntime)
            if (!quietCandidate) {
                clearPassive()
                return false
            }
            return this._isZapPassiveRuntimeQuiet({
                normalizedEngineName,
                runtime,
                passiveSince,
                clearPassive
            })
        }
        if (normalizedEngineName === 'IAST' && runtime?.isScanRunning === true) {
            const quietCandidate = !this._didZapIastRuntimeAdvance(runtime, previousRuntime)
            if (!quietCandidate) {
                clearPassive()
                return false
            }
            return this._isZapPassiveRuntimeQuiet({
                normalizedEngineName,
                runtime,
                passiveSince,
                clearPassive
            })
        }
        if (normalizedEngineName === 'SAST' && runtime?.isRunning === true) {
            const quietCandidate = !this._didZapSastRuntimeAdvance(runtime, previousRuntime)
            if (!quietCandidate) {
                clearPassive()
                return false
            }
            return this._isZapPassiveRuntimeQuiet({
                normalizedEngineName,
                runtime,
                passiveSince,
                clearPassive
            })
        }

        if (status === 'idle') {
            clearPassive()
            return true
        }

        if (!normalizedEngineName || status === ZAP_PROGRESS_STATUS_ERROR || status === ZAP_PROGRESS_STATUS_CANCELLED) {
            clearPassive()
            return false
        }

        const requiresDast = normalizeEngineList(requiredEngines).includes('DAST')
        const dastSettled = !requiresDast || engineStates?.DAST?.status === 'idle'
        if (!dastSettled || normalizedEngineName === 'DAST') {
            clearPassive()
            return false
        }

        if ((normalizedEngineName === 'IAST' || normalizedEngineName === 'SAST')
            && status === ZAP_PROGRESS_STATUS_READY) {
            clearPassive()
            return true
        }

        if (status !== ZAP_PROGRESS_STATUS_RUNNING) {
            clearPassive()
            return false
        }

        const quietCandidate = normalizedEngineName === 'SAST'
            ? !this._didZapSastRuntimeAdvance(runtime, previousRuntime)
            : normalizedEngineName === 'IAST'
                ? !this._didZapIastRuntimeAdvance(runtime, previousRuntime)
                : false

        if (!quietCandidate) {
            clearPassive()
            return false
        }

        return this._isZapPassiveRuntimeQuiet({
            normalizedEngineName,
            runtime,
            passiveSince,
            clearPassive
        })
    }

    _buildZapProgressPayloadFromDerivedState(derivedState = {}) {
        return this._buildProgressMonitorPayload({
            progress: derivedState?.progress,
            status: derivedState?.status,
            message: derivedState?.message || null,
            engines: derivedState?.engines || null
        })
    }

    _computeZapDastProgress(runtime = {}) {
        const executed = toFiniteNumber(runtime?.executed)
        const planned = toFiniteNumber(runtime?.planned)
        if (Number.isFinite(executed) && Number.isFinite(planned) && planned > 0) {
            return (executed / planned) * 100
        }

        const remaining = toFiniteNumber(runtime?.remaining)
        if (Number.isFinite(executed) && Number.isFinite(remaining) && (executed + remaining) > 0) {
            return (executed / (executed + remaining)) * 100
        }

        return 0
    }

    _computeZapSastProgress(runtime = {}) {
        const totalFiles = toFiniteNumber(runtime?.totalFiles, 0)
        const completedFiles = toFiniteNumber(runtime?.completedFiles, 0)
        if (totalFiles > 0) {
            return (completedFiles / totalFiles) * 100
        }

        const totalModules = toFiniteNumber(runtime?.totalModules, 0)
        const completedModules = toFiniteNumber(runtime?.completedModules, 0)
        if (totalModules > 0) {
            return (completedModules / totalModules) * 100
        }

        return 0
    }

    _didZapIastRuntimeAdvance(runtime = {}, previousRuntime = null) {
        if (!previousRuntime || typeof previousRuntime !== 'object') {
            return runtime?.hasObservedActivity === true
        }

        const currentCounts = [
            toFiniteNumber(runtime?.requestsCount, 0),
            toFiniteNumber(runtime?.runtimeEventsCount, 0),
            toFiniteNumber(runtime?.findingsCount, 0)
        ]
        const previousCounts = [
            toFiniteNumber(previousRuntime?.requestsCount, 0),
            toFiniteNumber(previousRuntime?.runtimeEventsCount, 0),
            toFiniteNumber(previousRuntime?.findingsCount, 0)
        ]
        if (currentCounts.some((value, index) => value > previousCounts[index])) {
            return true
        }

        const currentActivityAt = Date.parse(runtime?.lastActivityAt || '')
        const previousActivityAt = Date.parse(previousRuntime?.lastActivityAt || '')
        if (Number.isFinite(currentActivityAt) && (!Number.isFinite(previousActivityAt) || currentActivityAt > previousActivityAt)) {
            return true
        }

        return false
    }

    _didZapDastRuntimeAdvance(runtime = {}, previousRuntime = null) {
        if (!previousRuntime || typeof previousRuntime !== 'object') {
            return runtime?.idle !== true && runtime?.hasObservedWork === true
        }

        const currentCounters = [
            toFiniteNumber(runtime?.planned, 0),
            toFiniteNumber(runtime?.executed, 0),
            toFiniteNumber(runtime?.remaining, 0),
            toFiniteNumber(runtime?.activeTasks, 0),
            toFiniteNumber(runtime?.taskQueue, 0),
            toFiniteNumber(runtime?.requestQueue, 0),
            toFiniteNumber(runtime?.pendingPlans, 0),
            toFiniteNumber(runtime?.planning, 0),
            toFiniteNumber(runtime?.findingsCount, 0)
        ]
        const previousCounters = [
            toFiniteNumber(previousRuntime?.planned, 0),
            toFiniteNumber(previousRuntime?.executed, 0),
            toFiniteNumber(previousRuntime?.remaining, 0),
            toFiniteNumber(previousRuntime?.activeTasks, 0),
            toFiniteNumber(previousRuntime?.taskQueue, 0),
            toFiniteNumber(previousRuntime?.requestQueue, 0),
            toFiniteNumber(previousRuntime?.pendingPlans, 0),
            toFiniteNumber(previousRuntime?.planning, 0),
            toFiniteNumber(previousRuntime?.findingsCount, 0)
        ]
        if (currentCounters.some((value, index) => value !== previousCounters[index])) {
            return true
        }

        const currentMarkers = [
            String(runtime?.phase || ''),
            String(runtime?.status || ''),
            runtime?.idle === true ? 'idle' : 'active'
        ]
        const previousMarkers = [
            String(previousRuntime?.phase || ''),
            String(previousRuntime?.status || ''),
            previousRuntime?.idle === true ? 'idle' : 'active'
        ]
        if (currentMarkers.some((value, index) => value !== previousMarkers[index])) {
            return true
        }

        const currentActivityAt = Date.parse(runtime?.lastActivityAt || '')
        const previousActivityAt = Date.parse(previousRuntime?.lastActivityAt || '')
        if (Number.isFinite(currentActivityAt) && (!Number.isFinite(previousActivityAt) || currentActivityAt > previousActivityAt)) {
            return true
        }

        return false
    }

    _isZapPassiveRuntimeQuiet({
        normalizedEngineName,
        runtime = null,
        passiveSince = null,
        clearPassive = null
    } = {}) {
        const activityAt = Date.parse(runtime?.lastActivityAt || '')
        const now = Date.now()
        if (Number.isFinite(activityAt) && (now - activityAt) < ZAP_PASSIVE_ENGINE_IDLE_GRACE_MS) {
            clearPassive?.()
            return false
        }

        if (!passiveSince?.[normalizedEngineName]) {
            passiveSince[normalizedEngineName] = now
            return false
        }

        return (now - passiveSince[normalizedEngineName]) >= ZAP_PASSIVE_ENGINE_IDLE_GRACE_MS
    }

    _didZapSastRuntimeAdvance(runtime = {}, previousRuntime = null) {
        if (!previousRuntime || typeof previousRuntime !== 'object') {
            return runtime?.hasObservedWork === true
        }

        const currentCounters = [
            toFiniteNumber(runtime?.completedFiles, 0),
            toFiniteNumber(runtime?.completedModules, 0),
            toFiniteNumber(runtime?.findings, 0),
            toFiniteNumber(runtime?.hints, 0)
        ]
        const previousCounters = [
            toFiniteNumber(previousRuntime?.completedFiles, 0),
            toFiniteNumber(previousRuntime?.completedModules, 0),
            toFiniteNumber(previousRuntime?.findings, 0),
            toFiniteNumber(previousRuntime?.hints, 0)
        ]
        if (currentCounters.some((value, index) => value > previousCounters[index])) {
            return true
        }

        const currentMarkers = [
            String(runtime?.phase || ''),
            String(runtime?.currentFile || ''),
            String(runtime?.currentModule || ''),
            String(runtime?.lastStatus || '')
        ]
        const previousMarkers = [
            String(previousRuntime?.phase || ''),
            String(previousRuntime?.currentFile || ''),
            String(previousRuntime?.currentModule || ''),
            String(previousRuntime?.lastStatus || '')
        ]
        if (currentMarkers.some((value, index) => value !== previousMarkers[index] && value)) {
            return true
        }

        const currentActivityAt = Date.parse(runtime?.lastActivityAt || '')
        const previousActivityAt = Date.parse(previousRuntime?.lastActivityAt || '')
        if (Number.isFinite(currentActivityAt) && (!Number.isFinite(previousActivityAt) || currentActivityAt > previousActivityAt)) {
            return true
        }

        return false
    }

    async _flushPublisherWithTimeout(timeoutMs = ZAP_PROGRESS_FLUSH_TIMEOUT_MS) {
        const flushOnce = this.publisher?.flushOnce
        if (typeof flushOnce !== 'function') {
            return true
        }

        try {
            const result = await Promise.race([
                Promise.resolve(flushOnce.call(this.publisher)),
                new Promise((resolve) => setTimeout(() => resolve(false), timeoutMs))
            ])
            return result !== false
        } catch (err) {
            console.warn('[PTK ZAP] Failed to flush publisher before terminal progress:', err?.message || String(err))
            return false
        }
    }

    _findFirstEngineMessage(engineStates = {}, requiredEngines = []) {
        for (const engineName of normalizeEngineList(requiredEngines)) {
            const text = toNonEmptyString(engineStates?.[engineName]?.message)
            if (text) return text
        }
        return null
    }

    _areRequiredEnginesSettled(engineStates = {}, requiredEngines = []) {
        const engineNames = normalizeEngineList(requiredEngines)
        if (!engineNames.length) return false
        return engineNames.every((engineName) => {
            const status = engineStates?.[engineName]?.status
            return status !== ZAP_PROGRESS_STATUS_RUNNING && status !== 'starting'
        })
    }

    _buildStartFailureMessage(startResult = {}) {
        if (startResult?.status === 'busy') {
            return 'PTK automation is already busy on the target tab'
        }
        return startResult?.message || startResult?.error || 'PTK failed to start the required scans'
    }

    _getAutoStartEngines(parsedConfig = {}) {
        const engineConfigs = parsedConfig?.engineConfigs || {}
        return DEFAULT_ZAP_ENGINES.filter(engineName => hasEnabledRulepack(engineConfigs[engineName]))
    }

    _buildAutoStartEngineConfigs(parsedConfig = {}, engines = []) {
        const sourceConfigs = parsedConfig?.engineConfigs || {}
        const configs = {}
        for (const engineName of normalizeEngineList(engines)) {
            configs[engineName] = Object.assign({}, sourceConfigs[engineName] || {})
        }

        if (configs.DAST) {
            configs.DAST = Object.assign({}, configs.DAST, {
                allowCaptureWithoutInteraction: true
            })
        }

        return configs
    }

    async sendAlertsBatch({ engine, scanId, alerts, truncated }) {
        if (!this.isActive()) {
            this._debugLog('[PTK ZAP] Cannot send alerts - ZAP not active')
            return
        }
        if (!Array.isArray(alerts) || alerts.length === 0) {
            this._debugLog('[PTK ZAP] No alerts to send')
            return
        }

        this._debugLog('[PTK ZAP] Sending alerts batch:', { engine, scanId, count: alerts.length, truncated })

        const envelope = {
            source: SOURCE,
            type: TYPE_ALERTS_BATCH,
            ts: Date.now(),
            batchId: createBatchId(),
            payload: {
                sessionId: null,
                engine: engine || null,
                scanId: scanId || null,
                alerts,
                truncated: truncated === true
            }
        }

        await this.transport.postAlertsJson(envelope)
        this._debugLog('[PTK ZAP] Alerts batch sent successfully')
    }

    async sendDastFindingsBatch({ scanId, findings, truncated }) {
        if (!this.isActive()) {
            this._debugLog('[PTK ZAP] Cannot send DAST findings - ZAP not active')
            return
        }
        if (!Array.isArray(findings) || findings.length === 0) {
            this._debugLog('[PTK ZAP] No DAST findings to send')
            return
        }

        this._debugLog('[PTK ZAP] Sending DAST findings batch:', { scanId, count: findings.length, truncated })

        const envelope = {
            source: SOURCE,
            type: TYPE_DAST_FINDINGS_BATCH,
            schema: DAST_SCHEMA,
            ts: Date.now(),
            batchId: createBatchId(),
            payload: {
                engine: 'DAST',
                scanId: scanId || null,
                findings,
                truncated: truncated === true
            }
        }

        await this.transport.postAlertsJson(envelope)
        this._debugLog('[PTK ZAP] DAST findings batch sent successfully')
    }

    async sendIastFindingsBatch({ scanId, findings, truncated }) {
        if (!this.isActive()) return
        if (!Array.isArray(findings) || findings.length === 0) return

        this._debugLog('[PTK ZAP] Sending IAST findings batch:', { scanId, count: findings.length, truncated })

        const envelope = {
            source: SOURCE,
            type: TYPE_IAST_FINDINGS_BATCH,
            schema: IAST_SCHEMA,
            ts: Date.now(),
            batchId: createBatchId(),
            payload: {
                engine: 'IAST',
                scanId: scanId || null,
                findings,
                truncated: truncated === true
            }
        }

        await this.transport.postAlertsJson(envelope)
    }

    async sendSastFindingsBatch({ scanId, findings, truncated }) {
        if (!this.isActive()) return
        if (!Array.isArray(findings) || findings.length === 0) return

        this._debugLog('[PTK ZAP] Sending SAST findings batch:', { scanId, count: findings.length, truncated })

        const envelope = {
            source: SOURCE,
            type: TYPE_SAST_FINDINGS_BATCH,
            schema: SAST_SCHEMA,
            ts: Date.now(),
            batchId: createBatchId(),
            payload: {
                engine: 'SAST',
                scanId: scanId || null,
                findings,
                truncated: truncated === true
            }
        }

        await this.transport.postAlertsJson(envelope)
    }

    async confirmAndGetConfig(options = {}) {
        this._debugLog('[PTK ZAP] Fetching ZAP config...')
        const config = await this.transport.fetchConfig(options)
        this._debugLog('[PTK ZAP] ZAP config resolved:', config)
        return config
    }

    _handleZapDetected(payload = {}) {
        void this._handleZapDetectedAsync(payload)
    }

    async _handleZapDetectedAsync(payload = {}) {
        this._syncDebugFlagFromApp()
        this._debugLog('[PTK ZAP] Handling ZAP detection:', payload)

        const baseUrl = payload.baseUrl || this.transport.getBaseUrl()
        const zapid = payload.zapid || this.transport.getZapId?.() || null
        const browserid = payload.browserid || this.transport.getBrowserId?.() || null
        const sessionKey = this._buildZapSessionKey(baseUrl, zapid)
        const isNewSession = !!sessionKey && sessionKey !== this.currentSessionKey
        this._debugLog('[PTK ZAP] ZAP detection context:', {
            baseUrl,
            zapid,
            tabId: Number.isInteger(payload?.tabId) ? payload.tabId : null,
            targetUrl: payload?.targetUrl || null,
            source: payload?.source || null,
            sessionKey,
            isNewSession
        })
        this.recordTiming({
            phase: 'callback.detected',
            zapid,
            browserid,
            zapSessionKey: sessionKey,
            tabId: Number.isInteger(payload?.tabId) ? payload.tabId : null,
            targetUrl: payload?.targetUrl || null,
            elapsedMs: 0
        })
        this.currentBaseUrl = baseUrl || this.currentBaseUrl
        this.currentSessionKey = sessionKey || this.currentSessionKey

        if (isNewSession) {
            this._clearProgressMonitor()
            this._pendingStart = null
            this._lastStartKey = null
            this._lastStartSessionId = null
            this._resolvedConfig = {
                mode: ZAP_MODE_MANUAL,
                engineConfigs: {},
                fetchedAt: null,
                baseUrl: baseUrl || null
            }
        }

        void this._postCallbackHandshakeProgress({
            sessionKey,
            zapid,
            source: payload?.source || null,
            tabId: Number.isInteger(payload?.tabId) ? payload.tabId : null,
            targetUrl: payload?.targetUrl || null
        })

        this._debugLog('[PTK ZAP] ZAP is active, starting publisher')
        this.start()

        if (this.publisher && isNewSession) {
            this._debugLog('[PTK ZAP] New base URL detected, resetting publisher state')
            this.publisher.resetState()
        }

        const automation = this.app?.automation
        if (!automation || typeof automation.startZapConfiguredSession !== 'function') {
            this._debugLog('[PTK ZAP] Automation module not attached yet; delaying ZAP-managed session start')
            return
        }

        const startKeyBase = `${sessionKey || baseUrl || ''}|${payload.tabId || ''}`
        if (this._startInFlight?.key === startKeyBase) {
            return
        }

        const run = async () => {
            const configFetchStartedAt = Date.now()
            this.recordTiming({
                phase: 'config.fetch.start',
                zapid,
                browserid,
                zapSessionKey: sessionKey,
                tabId: Number.isInteger(payload?.tabId) ? payload.tabId : null,
                targetUrl: payload?.targetUrl || null
            })
            const rawConfig = await this.confirmAndGetConfig()
            this.recordTiming({
                phase: 'config.fetch.end',
                zapid,
                browserid,
                zapSessionKey: sessionKey,
                tabId: Number.isInteger(payload?.tabId) ? payload.tabId : null,
                targetUrl: payload?.targetUrl || null,
                extra: {
                    durationMs: Date.now() - configFetchStartedAt
                }
            })
            const parsedConfig = this._parseConfig(rawConfig)
            this._resolvedConfig = {
                mode: parsedConfig.mode,
                engineConfigs: parsedConfig.engineConfigs || {},
                fetchedAt: Date.now(),
                baseUrl: baseUrl || null
            }
            this._debugLog('[PTK ZAP] Parsed ZAP auto config:', {
                zapid,
                mode: parsedConfig.mode,
                configuredEngines: Object.keys(parsedConfig.engineConfigs || {}),
                moduleCounts: Object.fromEntries(Object.entries(parsedConfig.engineConfigs || {}).map(([engineName, config]) => [
                    engineName,
                    Array.isArray(config?.rulepack?.modules) ? config.rulepack.modules.length : 0
                ]))
            })

            if (parsedConfig.mode !== ZAP_MODE_AUTO) {
                this._pendingStart = null
                this._debugLog('[PTK ZAP] mode is manual; automatic scan start is disabled')
                return
            }

            const finalEngines = this._getAutoStartEngines(parsedConfig)
            const finalEngineConfigs = this._buildAutoStartEngineConfigs(parsedConfig, finalEngines)
            this._debugLog('[PTK ZAP] Auto-start engine selection:', {
                zapid,
                sessionKey,
                engines: finalEngines
            })
            if (!finalEngines.length) {
                this._pendingStart = null
                this._debugLog('[PTK ZAP] No enabled PTK engines in ZAP auto config; skipping automatic scan start')
                this._scheduleTerminalProgress({
                    sessionKey,
                    zapid,
                    requiredEngines: [],
                    status: ZAP_PROGRESS_STATUS_COMPLETED,
                    message: 'No PTK engines are enabled for this ZAP automation session'
                })
                return
            }

            const targetUrlResolveStartedAt = Date.now()
            const targetUrl = await this._resolveTargetUrl(payload, 120000)
            this._debugLog('[PTK ZAP] Resolved target URL:', {
                zapid,
                sessionKey,
                targetUrl,
                source: payload?.source || null
            })
            this.recordTiming({
                phase: 'target_url.resolved',
                zapid,
                browserid,
                zapSessionKey: sessionKey,
                tabId: Number.isInteger(payload?.tabId) ? payload.tabId : null,
                targetUrl,
                extra: {
                    durationMs: Date.now() - targetUrlResolveStartedAt,
                    source: payload?.source || null,
                    result: targetUrl ? 'ok' : 'missing'
                }
            })
            if (!targetUrl) {
                this._pendingStart = {
                    tabId: null,
                    baseUrl: baseUrl || null,
                    sessionKey,
                    zapid,
                    engines: finalEngines,
                    engineConfigs: finalEngineConfigs
                }
                this._debugLog('[PTK ZAP] Target URL not available yet; waiting for next non-ZAP navigation')
                await this._tryStartFromObservedTarget(this._pendingStart)
                return
            }

            const targetTabResolveStartedAt = Date.now()
            const targetTabId = await this._resolveTargetTabId(payload, targetUrl, 5000)
            this._debugLog('[PTK ZAP] Resolved target tab:', {
                zapid,
                sessionKey,
                targetUrl,
                targetTabId
            })
            this.recordTiming({
                phase: 'target_tab.resolved',
                zapid,
                browserid,
                zapSessionKey: sessionKey,
                tabId: targetTabId,
                targetUrl,
                extra: {
                    durationMs: Date.now() - targetTabResolveStartedAt,
                    result: Number.isInteger(targetTabId) ? 'ok' : 'missing'
                }
            })
            if (!targetTabId) {
                this._pendingStart = {
                    tabId: null,
                    baseUrl: baseUrl || null,
                    sessionKey,
                    zapid,
                    engines: finalEngines,
                    engineConfigs: finalEngineConfigs
                }
                this._debugLog('[PTK ZAP] Target URL resolved but tabId is unavailable; waiting for next non-ZAP navigation')
                await this._tryStartFromObservedTarget(this._pendingStart)
                return
            }

            await this._startZapSession({
                tabId: targetTabId,
                targetUrl,
                engines: finalEngines,
                engineConfigs: finalEngineConfigs,
                baseUrl,
                sessionKey,
                zapid
            })
        }

        this._startInFlight = { key: startKeyBase, promise: null }
        this._startInFlight.promise = run().finally(() => {
            if (this._startInFlight?.key === startKeyBase) {
                this._startInFlight = null
            }
        })

        await this._startInFlight.promise
    }

    async _postCallbackHandshakeProgress({ sessionKey = null, zapid = null, source = null, tabId = null, targetUrl = null } = {}) {
        const effectiveZapId = zapid || this.transport.getZapId?.() || null
        const progressUrl = this.transport.getProgressUrl?.() || null
        const progressKey = sessionKey || this._buildZapSessionKey(this.transport.getBaseUrl?.(), effectiveZapId)

        if (!effectiveZapId || !progressUrl || !progressKey) {
            this._debugLog('[PTK ZAP] Callback handshake progress unavailable:', {
                zapid: effectiveZapId,
                progressUrl,
                sessionKey: progressKey
            })
            return
        }

        if (this._callbackProgressSent.has(progressKey)) {
            this._debugLog('[PTK ZAP] Callback handshake progress already sent:', {
                zapid: effectiveZapId,
                sessionKey: progressKey,
                source
            })
            return
        }

        this._callbackProgressSent.add(progressKey)
        this._debugLog('[PTK ZAP] Callback handshake progress posting:', {
            zapid: effectiveZapId,
            sessionKey: progressKey,
            progressUrl,
            source,
            tabId,
            targetUrl
        })

        try {
            await this.transport.postProgressJson({
                progress: 0,
                status: ZAP_PROGRESS_STATUS_CALLBACK,
                message: 'ZAP callback detected; waiting for target navigation',
                engines: {}
            })
            this.recordTiming({
                phase: 'progress.post.first',
                zapid: effectiveZapId,
                browserid: this.transport.getBrowserId?.() || null,
                zapSessionKey: progressKey,
                tabId,
                targetUrl,
                onceKey: 'progress.post.first',
                extra: {
                    progress: 0,
                    status: ZAP_PROGRESS_STATUS_CALLBACK
                }
            })
            this._debugLog('[PTK ZAP] Callback handshake progress posted:', {
                zapid: effectiveZapId,
                sessionKey: progressKey
            })
        } catch (err) {
            this._callbackProgressSent.delete(progressKey)
            console.warn('[PTK ZAP] Failed to POST callback handshake progress:', err?.message || String(err))
        }
    }

    _handleUrlObserved(payload = {}) {
        this._rememberTopLevelTargetObservation(payload)

        const pending = this._pendingStart
        if (!pending) return

        const observedTabId = Number.isInteger(payload?.tabId) ? payload.tabId : null
        if (Number.isInteger(pending.tabId) && observedTabId !== pending.tabId) {
            return
        }

        const targetUrl = toHttpUrl(payload?.url)
        if (!targetUrl) return
        if (!this._isTopLevelTargetObservation(payload)) return

        const resolvedTabId = Number.isInteger(pending.tabId) ? pending.tabId : observedTabId
        if (!Number.isInteger(resolvedTabId) || resolvedTabId < 0) {
            this._debugLog('[PTK ZAP] Pending auto-start observed a target URL without a usable tabId; waiting for next navigation')
            return
        }

        const run = async () => {
            await this._startZapSession({
                tabId: resolvedTabId,
                targetUrl,
                engines: pending.engines,
                engineConfigs: pending.engineConfigs,
                baseUrl: pending.baseUrl,
                sessionKey: pending.sessionKey,
                zapid: pending.zapid
            })
        }

        const inFlightKey = `pending|${pending.sessionKey || pending.baseUrl || ''}|${resolvedTabId}`
        if (this._startInFlight?.key === inFlightKey) {
            return
        }

        this._startInFlight = { key: inFlightKey, promise: null }
        this._startInFlight.promise = run().finally(() => {
            if (this._startInFlight?.key === inFlightKey) {
                this._startInFlight = null
            }
        })
    }

    async _startZapSession({ tabId, targetUrl, engines, engineConfigs, baseUrl, sessionKey = null, zapid = null }) {
        const automation = this.app?.automation
        if (!automation || typeof automation.startZapConfiguredSession !== 'function') {
            console.warn('[PTK ZAP] Automation module unavailable for ZAP-managed session start')
            return
        }

        const safeTabId = Number.isInteger(tabId) ? tabId : null
        if (!safeTabId || !targetUrl) {
            this._debugLog('[PTK ZAP] Starting ZAP-driven automation:', {
                zapid,
                sessionKey,
                tabId,
                targetUrl,
                skipped: 'missing_tab_or_target'
            })
            return
        }

        const safeEngines = Array.isArray(engines) && engines.length
            ? normalizeEngineList(engines)
            : DEFAULT_ZAP_ENGINES
        const effectiveSessionKey = sessionKey || this._buildZapSessionKey(baseUrl, zapid || this.transport.getZapId?.())
        const effectiveZapId = zapid || this.transport.getZapId?.() || null
        const startKeyBase = `${effectiveSessionKey || baseUrl || ''}|${safeTabId}`
        const startKey = `${startKeyBase}|${targetUrl}|${safeEngines.join(',')}`
        if (startKey === this._lastStartKey) {
            this._pendingStart = null
            this._debugLog('[PTK ZAP] Duplicate ZAP-driven automation start suppressed:', {
                zapid: effectiveZapId,
                sessionKey: effectiveSessionKey,
                tabId: safeTabId,
                targetUrl,
                engines: safeEngines,
                sessionId: this._lastStartSessionId || null
            })
            if (this._lastStartSessionId) {
                this._startProgressMonitor({
                    sessionKey: effectiveSessionKey,
                    sessionId: this._lastStartSessionId,
                    zapid: effectiveZapId,
                    requiredEngines: safeEngines
                })
            }
            return
        }

        this._debugLog('[PTK ZAP] Starting ZAP-driven automation:', {
            zapid: effectiveZapId,
            sessionKey: effectiveSessionKey,
            tabId: safeTabId,
            targetUrl,
            engines: safeEngines
        })
        this.recordTiming({
            phase: 'automation.start.requested',
            zapid: effectiveZapId,
            browserid: this.transport.getBrowserId?.() || null,
            zapSessionKey: effectiveSessionKey,
            tabId: safeTabId,
            targetUrl,
            extra: {
                engines: safeEngines.join(',')
            }
        })
        const startResult = await automation.startZapConfiguredSession({
            tabId: safeTabId,
            targetUrl,
            pageUrl: targetUrl,
            engines: safeEngines,
            engineConfigs,
            zapSessionKey: effectiveSessionKey || baseUrl || null
        }).catch((err) => {
            console.warn('[PTK ZAP] Failed to start ZAP-driven automation session:', err?.message || String(err))
            return { status: 'error', error: err?.message || String(err), message: err?.message || String(err) }
        })

        this._debugLog('[PTK ZAP] ZAP-driven automation result:', startResult)

        const status = startResult?.status
        if (status === 'started' || status === 'already_running') {
            this._lastStartKey = startKey
            this._lastStartSessionId = startResult?.sessionId || this._lastStartSessionId
            this._pendingStart = null
            this._startProgressMonitor({
                sessionKey: effectiveSessionKey,
                sessionId: startResult?.sessionId || this._lastStartSessionId || null,
                zapid: effectiveZapId,
                requiredEngines: startResult?.requiredEngines || safeEngines
            })
            return
        }

        this._pendingStart = null
        this._scheduleTerminalProgress({
            sessionKey: effectiveSessionKey,
            sessionId: startResult?.sessionId || null,
            zapid: effectiveZapId,
            requiredEngines: startResult?.requiredEngines || safeEngines,
            status: ZAP_PROGRESS_STATUS_ERROR,
            message: this._buildStartFailureMessage(startResult),
            engines: this._buildStartupFailureEngineStates(startResult, startResult?.requiredEngines || safeEngines)
        })
    }

    _parseConfig(rawConfig) {
        const result = {
            mode: ZAP_MODE_MANUAL,
            engineConfigs: {}
        }

        const config = toObject(rawConfig)
        if (!config) return result

        const modeRaw = String(config.mode || '').trim().toLowerCase()
        if (modeRaw === ZAP_MODE_AUTO || modeRaw === ZAP_MODE_MANUAL) {
            result.mode = modeRaw
        }

        for (const [key, engine] of Object.entries(RULEPACK_KEYS)) {
            if (!Object.prototype.hasOwnProperty.call(config, key)) continue
            const pack = toObject(config[key])
            if (!pack) continue
            if (!Array.isArray(pack.modules)) continue

            result.engineConfigs[engine] = {
                rulepack: {
                    schema: pack.schema || 'ptk-modules-v1',
                    engine,
                    version: Number.isFinite(Number(pack.version)) ? Number(pack.version) : 1,
                    modules: pack.modules
                }
            }
        }

        return result
    }

    getManualEngineConfig(engineName) {
        const normalizedEngine = String(engineName || '').toUpperCase().trim()
        if (!normalizedEngine) return null
        const resolved = this._resolvedConfig || null
        if (!resolved || resolved.mode !== ZAP_MODE_MANUAL) {
            return null
        }
        const config = resolved.engineConfigs?.[normalizedEngine]
        if (!config || typeof config !== 'object') {
            return null
        }
        try {
            return JSON.parse(JSON.stringify(config))
        } catch (_) {
            return Object.assign({}, config)
        }
    }

    getActiveTargetUrl() {
        const observed = this._lastTopLevelTargetObservation?.targetUrl || null
        if (observed) return observed
        return this.transport.getLastDetectedPayload?.()?.targetUrl || null
    }

    getActiveTargetHost() {
        return toHostKeyFromUrl(this.getActiveTargetUrl())
    }

    getManagedScanIdsForEngine(engine) {
        const automation = this.app?.automation
        if (!automation || typeof automation.getZapManagedScanIds !== 'function') {
            return []
        }
        return automation.getZapManagedScanIds({
            engine,
            host: this.getActiveTargetHost()
        })
    }

    async _resolveTargetUrl(payload = {}, maxWaitMs = 120000) {
        const fromPayload = toHttpUrl(payload.targetUrl) || toHttpUrl(payload.pageUrl) || toHttpUrl(payload.url)
        if (fromPayload) return fromPayload

        const tabId = Number.isInteger(payload.tabId) ? payload.tabId : null
        if (tabId == null || !browser?.tabs?.get) return null

        const waitMs = Number.isFinite(Number(maxWaitMs)) ? Math.max(0, Number(maxWaitMs)) : 120000
        const resolveFromTab = async () => {
            try {
                const tab = await browser.tabs.get(tabId)
                const resolved = toHttpUrl(tab?.url) || toHttpUrl(tab?.pendingUrl)
                if (resolved) return resolved
            } catch (_) {
                return null
            }
            return null
        }

        const immediate = await resolveFromTab()
        if (immediate) return immediate
        if (waitMs <= 0) return null

        const deadline = Date.now() + waitMs
        while (Date.now() < deadline) {
            await sleep(500)
            const resolved = await resolveFromTab()
            if (resolved) return resolved
        }

        return null
    }

    _isTopLevelTargetObservation(payload = {}) {
        const source = String(payload?.source || '')
        if (!AUTO_START_NAV_SOURCES.has(source)) {
            return false
        }

        const frameId = Number.isInteger(payload?.frameId) ? payload.frameId : 0
        if (source.startsWith('webNavigation.') && frameId !== 0) {
            return false
        }

        return true
    }

    _rememberTopLevelTargetObservation(payload = {}) {
        if (!this._isTopLevelTargetObservation(payload)) {
            return null
        }

        const targetUrl = toHttpUrl(payload?.url)
        if (!targetUrl) {
            return null
        }

        const tabId = Number.isInteger(payload?.tabId) ? payload.tabId : null
        if (!Number.isInteger(tabId) || tabId < 0) {
            return null
        }

        this._lastTopLevelTargetObservation = {
            tabId,
            targetUrl,
            source: String(payload?.source || ''),
            ts: Date.now()
        }
        return this._lastTopLevelTargetObservation
    }

    _getFreshObservedTargetForPending(pending = {}) {
        const observed = this._lastTopLevelTargetObservation
        if (!observed) return null

        const ageMs = Date.now() - Number(observed.ts || 0)
        if (!Number.isFinite(ageMs) || ageMs < 0 || ageMs > AUTO_START_OBSERVED_MAX_AGE_MS) {
            return null
        }

        const pendingTabId = Number.isInteger(pending?.tabId) ? pending.tabId : null
        if (Number.isInteger(pendingTabId) && pendingTabId !== observed.tabId) {
            return null
        }

        return observed
    }

    async _tryStartFromObservedTarget(pending = {}) {
        const observed = this._getFreshObservedTargetForPending(pending)
        if (!observed) {
            return false
        }

        this._debugLog('[PTK ZAP] Replaying cached target navigation for auto mode', {
            tabId: observed.tabId,
            targetUrl: observed.targetUrl,
            source: observed.source
        })

        await this._startZapSession({
            tabId: observed.tabId,
            targetUrl: observed.targetUrl,
            engines: pending.engines,
            engineConfigs: pending.engineConfigs,
            baseUrl: pending.baseUrl,
            sessionKey: pending.sessionKey,
            zapid: pending.zapid
        })

        return true
    }

    async _resolveTargetTabId(payload = {}, targetUrl = '', maxWaitMs = 5000) {
        const tabId = Number.isInteger(payload?.tabId) ? payload.tabId : null
        if (Number.isInteger(tabId) && tabId > 0 && browser?.tabs?.get) {
            try {
                const tab = await browser.tabs.get(tabId)
                const tabUrl = toHttpUrl(tab?.url) || toHttpUrl(tab?.pendingUrl)
                if (tabUrl === targetUrl) {
                    return tabId
                }
            } catch (_) {
                // Fall through to observed/exact tab lookup.
            }
        }

        const observed = this._lastTopLevelTargetObservation
        if (
            observed
            && Number.isInteger(observed.tabId)
            && observed.tabId > 0
            && observed.targetUrl === targetUrl
        ) {
            return observed.tabId
        }

        if (!browser?.tabs?.query || !targetUrl) {
            return null
        }

        const waitMs = Number.isFinite(Number(maxWaitMs)) ? Math.max(0, Number(maxWaitMs)) : 5000
        const resolveFromTabs = async () => {
            try {
                const tabs = await browser.tabs.query({})
                const exactMatch = tabs.find(tab => {
                    if (!Number.isInteger(tab?.id) || tab.id <= 0) return false
                    return toHttpUrl(tab?.url) === targetUrl
                })
                if (Number.isInteger(exactMatch?.id) && exactMatch.id > 0) {
                    return exactMatch.id
                }
            } catch (_) {
                return null
            }
            return null
        }

        const immediate = await resolveFromTabs()
        if (immediate) return immediate
        if (waitMs <= 0) return null

        const deadline = Date.now() + waitMs
        while (Date.now() < deadline) {
            await sleep(300)
            const resolved = await resolveFromTabs()
            if (resolved) return resolved
        }

        return null
    }
}

const zapBridge = new ZapBridge()

export default zapBridge
