'use strict'

import zapTransport, {
    DAST_HISTORY_SEED_MAX_RESULTS,
    isSameOriginAndPathScoped,
    redactZapLogValue
} from './zapTransport.js'
import ZapPublisher from './zapPublisher.js'
import ZapAutomationController from './zapAutomationController.js'

const SOURCE = 'ptk'
const TYPE_ALERTS_BATCH = 'alerts_batch'
const TYPE_DAST_FINDINGS_BATCH = 'dast_findings_batch'
const TYPE_IAST_FINDINGS_BATCH = 'iast_findings_batch'
const TYPE_SAST_FINDINGS_BATCH = 'sast_findings_batch'
const DAST_SCHEMA = 'ptk-zap-dast-finding-v1'
const IAST_SCHEMA = 'ptk-zap-iast-finding-v1'
const SAST_SCHEMA = 'ptk-zap-sast-finding-v1'
const ZAP_PROGRESS_CONTRACT_VERSION = 2
const DEFAULT_ZAP_ENGINES = ['DAST', 'IAST', 'SAST']
const ZAP_MODE_AUTO = 'auto'
const ZAP_MODE_MANUAL = 'manual'
const ZAP_PROGRESS_HEARTBEAT_MS = 2000
const ZAP_CONTROL_BACKGROUND_POLL_MS = 2000
const ZAP_CONTROL_ALARM_NAME = 'ptk-zap-control-poll'
const ZAP_CONTROL_ALARM_PERIOD_MINUTES = 0.5
const ZAP_CONTROL_POLL_MIN_INTERVAL_MS = 1000
const ZAP_PROGRESS_TICK_STALE_MS = 15000
const ZAP_PROGRESS_IDLE_GRACE_MS = 6000
const ZAP_PASSIVE_ENGINE_IDLE_GRACE_MS = 8000
const ZAP_TARGET_ACTIVITY_QUIET_GRACE_MS = 2500
const ZAP_PROGRESS_FLUSH_TIMEOUT_MS = 3000
const ZAP_PROGRESS_DRAIN_MAX_PASSES = 4
const ZAP_CLOSE_TERMINAL_RETRY_MS = 2000
const ZAP_CLOSE_TERMINAL_RETRY_TIMEOUT_MS = 30000
const ZAP_PENDING_TARGET_RECOVERY_INTERVAL_MS = 1000
const ZAP_PENDING_TARGET_RECOVERY_MAX_MS = 120000
// Mirrors the ZAP add-on close-contract PTK stop budget for legacy
// closeRequested progress controls. Normal ZAP browser-close handling now uses
// the WebDriver close-decision script instead of progress callbacks to avoid
// stopping an active scan while ZAP is merely trying to close a browser tab.
const ZAP_CLOSE_CONTRACT_PTK_STOP_TIMEOUT_MS = 25000
const ZAP_PROGRESS_STATUS_READY = 'ready'
const ZAP_PROGRESS_STATUS_CALLBACK = 'callback'
const ZAP_PROGRESS_STATUS_RUNNING = 'running'
const ZAP_PROGRESS_STATUS_COMPLETED = 'completed'
const ZAP_PROGRESS_STATUS_ERROR = 'error'
const ZAP_PROGRESS_STATUS_CANCELLED = 'cancelled'
const ZAP_CALLBACK_PREFIX = /^https?:\/\/zap\/zapCallBackUrl\//i
const ZAP_DEFAULT_TIMING_PHASES = new Set([
    'progress.post.terminal'
])
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
    'content.zapTarget'
])
const TERMINAL_BLOCKING_TARGET_SOURCES = new Set([
    'webNavigation.onCommitted',
    'webNavigation.onBeforeNavigate',
    'tabs.onUpdated',
    'tabs.onReplaced',
    'bootstrap.tabs.query'
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
    '[PTK ZAP] Controller state:',
    '[PTK ZAP] Using cached target navigation',
    '[PTK ZAP] Starting ZAP-driven automation:',
    '[PTK ZAP] Duplicate ZAP-driven automation start suppressed:',
    '[PTK ZAP] ZAP-driven automation result:',
    '[PTK ZAP] Starting progress monitor:',
    '[PTK ZAP] Progress monitor unavailable:',
    '[PTK ZAP] Progress monitor switched zapid:',
    '[PTK ZAP] Progress monitor completed:',
    '[PTK ZAP] No enabled PTK engines',
    '[PTK ZAP] ZAP config fetch failed'
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

function isValidTabId(value) {
    return Number.isInteger(value) && value >= 0
}

function clampProgress(value, max = 100) {
    const num = toFiniteNumber(value, 0)
    return Math.max(0, Math.min(max, Math.round(num)))
}

function stableStringify(value) {
    if (value === null || value === undefined) return 'null'
    if (typeof value === 'string') return JSON.stringify(value)
    if (typeof value === 'number' || typeof value === 'boolean') return String(value)
    if (Array.isArray(value)) {
        return `[${value.map((entry) => stableStringify(entry)).join(',')}]`
    }
    if (typeof value === 'object') {
        return `{${Object.keys(value).sort((a, b) => a.localeCompare(b)).map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`
    }
    return JSON.stringify(String(value))
}

function isZapTerminalStatus(status) {
    const normalized = String(status || '').toLowerCase().trim()
    return normalized === ZAP_PROGRESS_STATUS_COMPLETED
        || normalized === ZAP_PROGRESS_STATUS_ERROR
        || normalized === ZAP_PROGRESS_STATUS_CANCELLED
        || normalized === 'timeout'
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

function normalizeHttpUrlList(values = []) {
    if (!Array.isArray(values)) return []
    const urls = []
    const seen = new Set()
    for (const value of values) {
        const url = toHttpUrl(value)
        if (!url || seen.has(url)) continue
        urls.push(url)
        seen.add(url)
    }
    return urls
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
        this._progressMonitorsByKey = new Map()
        this._controlAlarmActive = false
        this._controlAlarmRegistered = false
        this._controlAlarmHandler = null
        this._closeTerminalRetryTimers = new Map()
        this._callbackProgressSent = new Set()
        this._lastTopLevelTargetObservation = null
        this._pendingStartsByKey = new Map()
        this._startInFlightByKey = new Map()
        this._lastStartsByKey = new Map()
        this._timingStateByKey = new Map()
        this._pendingTargetRecoveryTimer = null
        this._pendingTargetRecoveryUntil = 0
        this.zapAutomationRewriteEnabled = true
        this._automationController = new ZapAutomationController({
            bridge: this,
            transport: this.transport
        })
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
        this._registerControlAlarmListener()
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

        this._resumeActiveDetection()
    }

    // Backward-compat alias: init() with no args => bootstrap, with args => attach.
    init(app, resultsRegistry) {
        if (app || resultsRegistry) {
            this.attach(app, resultsRegistry)
            return
        }
        this.bootstrap()
    }

    _resumeActiveDetection() {
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

    _shouldLogTimingPhase(phaseName) {
        if (!phaseName) return false
        if (this._resolveDebugEnabled()) {
            return true
        }
        return ZAP_DEFAULT_TIMING_PHASES.has(phaseName)
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
        console.log(...args.map((arg) => redactZapLogValue(arg)))
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

    _pendingStartKey(pending = {}) {
        return toNonEmptyString(pending?.sessionKey)
            || toNonEmptyString(pending?.zapid)
            || [toNonEmptyString(pending?.baseUrl), pending?.tabId].filter(value => value !== null && value !== undefined && value !== '').join('|')
            || null
    }

    _setPendingStart(pending = null) {
        if (!pending || typeof pending !== 'object') {
            return null
        }
        const key = this._pendingStartKey(pending)
        if (key) {
            this._pendingStartsByKey.set(key, pending)
        }
        this._pendingStart = pending
        this._ensurePendingTargetRecovery()
        return key
    }

    _clearPendingStart(pendingOrKey = null) {
        const key = typeof pendingOrKey === 'string'
            ? pendingOrKey
            : this._pendingStartKey(pendingOrKey)
        if (key) {
            this._pendingStartsByKey.delete(key)
        }
        if (!pendingOrKey || this._pendingStart === pendingOrKey || this._pendingStartKey(this._pendingStart) === key) {
            this._pendingStart = Array.from(this._pendingStartsByKey.values()).at(-1) || null
        }
        this._clearPendingTargetRecoveryIfIdle()
    }

    _hasPendingTargetRecoveryWork() {
        return this._pendingStartsByKey.size > 0 || Boolean(this._pendingStart)
    }

    _clearPendingTargetRecoveryIfIdle() {
        if (this._hasPendingTargetRecoveryWork()) return
        if (this._pendingTargetRecoveryTimer) {
            clearInterval(this._pendingTargetRecoveryTimer)
            this._pendingTargetRecoveryTimer = null
        }
        this._pendingTargetRecoveryUntil = 0
    }

    _ensurePendingTargetRecovery() {
        this._pendingTargetRecoveryUntil = Math.max(
            this._pendingTargetRecoveryUntil || 0,
            Date.now() + ZAP_PENDING_TARGET_RECOVERY_MAX_MS
        )
        if (this._pendingTargetRecoveryTimer) return

        const tick = () => {
            if (!this._hasPendingTargetRecoveryWork() || Date.now() > this._pendingTargetRecoveryUntil) {
                this._clearPendingTargetRecoveryIfIdle()
                if (this._pendingTargetRecoveryTimer) {
                    clearInterval(this._pendingTargetRecoveryTimer)
                    this._pendingTargetRecoveryTimer = null
                }
                return
            }
            void this._recoverPendingTargetStarts()
        }

        this._pendingTargetRecoveryTimer = setInterval(tick, ZAP_PENDING_TARGET_RECOVERY_INTERVAL_MS)
        tick()
    }

    async _recoverPendingTargetStarts() {
        const pendingStarts = this._pendingStartsByKey.size
            ? Array.from(this._pendingStartsByKey.entries())
            : (this._pendingStart ? [[this._pendingStartKey(this._pendingStart) || 'legacy', this._pendingStart]] : [])

        for (const [pendingKey, pending] of pendingStarts) {
            const targetUrl = await this._resolvePendingStartTargetUrl(pending)
            if (!targetUrl) continue

            const targetTabId = await this._resolveTargetTabId({
                tabId: Number.isInteger(pending?.tabId) ? pending.tabId : null
            }, targetUrl, 0)
            if (!isValidTabId(targetTabId)) continue

            const inFlightKey = `pending-recover|${pending.sessionKey || pending.baseUrl || pendingKey || ''}|${targetTabId}|${targetUrl}`
            if (this._startInFlightByKey.has(inFlightKey)) continue

            const run = async () => {
                await this._startZapSession({
                    tabId: targetTabId,
                    targetUrl,
                    engines: pending.engines,
                    engineConfigs: pending.engineConfigs,
                    baseUrl: pending.baseUrl,
                    sessionKey: pending.sessionKey,
                    zapid: pending.zapid
                })
            }

            const inFlight = run().finally(() => {
                this._startInFlightByKey.delete(inFlightKey)
                if (this._startInFlight?.key === inFlightKey) {
                    this._startInFlight = null
                }
            })
            this._startInFlightByKey.set(inFlightKey, inFlight)
            this._startInFlight = { key: inFlightKey, promise: inFlight }
        }
    }

    async _resolvePendingStartTargetUrl(pending = {}) {
        const scopedTargetUrl = this._resolvePendingStartScopeTargetUrl(pending)
        if (scopedTargetUrl) return scopedTargetUrl

        const observed = this._getFreshObservedTargetForPending(pending)
        if (observed?.targetUrl) return observed.targetUrl

        const pendingTabId = Number.isInteger(pending?.tabId) ? pending.tabId : null
        if (isValidTabId(pendingTabId) && browser?.tabs?.get) {
            try {
                const tab = await browser.tabs.get(pendingTabId)
                const tabUrl = toHttpUrl(tab?.url) || toHttpUrl(tab?.pendingUrl)
                if (tabUrl) return tabUrl
            } catch (_) {
                // Keep trying open-tab fallbacks below.
            }
        }

        return null
    }

    _resolvePendingStartScopeTargetUrl(pending = {}) {
        const configuredTargetUrl = toHttpUrl(pending?.targetUrl)
        if (configuredTargetUrl) return configuredTargetUrl

        const seedTargetUrl = this._selectPostCallbackTargetUrl(this._collectConfigSeedUrls(pending?.engineConfigs))
        if (seedTargetUrl) return seedTargetUrl

        return null
    }

    _isPendingStartTargetUrlAllowed(pending = {}, targetUrl = '') {
        const normalizedTargetUrl = toHttpUrl(targetUrl)
        if (!normalizedTargetUrl) return false

        const scopedTargetUrl = this._resolvePendingStartScopeTargetUrl(pending)
        if (!scopedTargetUrl) return true

        return normalizedTargetUrl === scopedTargetUrl
            || isSameOriginAndPathScoped(scopedTargetUrl, normalizedTargetUrl)
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
        return `${name}=${JSON.stringify(String(redactZapLogValue(value, name)))}`
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
        if (!this._shouldLogTimingPhase(phaseName)) return false

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

    _progressMonitorKey({ sessionKey = null, zapid = null, sessionId = null } = {}) {
        return toNonEmptyString(sessionKey)
            || [toNonEmptyString(zapid), toNonEmptyString(sessionId)].filter(Boolean).join('|')
            || null
    }

    _clearProgressMonitor(monitor = null) {
        if (monitor) {
            if (monitor.intervalId) {
                clearInterval(monitor.intervalId)
            }
            if (monitor.controlIntervalId) {
                clearInterval(monitor.controlIntervalId)
            }
            const key = this._progressMonitorKey(monitor)
            if (key) {
                this._progressMonitorsByKey.delete(key)
            }
            if (this._progressMonitor === monitor) {
                this._progressMonitor = Array.from(this._progressMonitorsByKey.values()).at(-1) || null
            }
            void this._clearControlAlarmIfIdle()
            return
        }

        for (const activeMonitor of this._progressMonitorsByKey.values()) {
            if (activeMonitor?.intervalId) {
                clearInterval(activeMonitor.intervalId)
            }
            if (activeMonitor?.controlIntervalId) {
                clearInterval(activeMonitor.controlIntervalId)
            }
        }
        this._progressMonitorsByKey.clear()
        this._progressMonitor = null
        void this._clearControlAlarmIfIdle()
    }

    _clearProgressMonitorIfCurrent(monitor) {
        if (!monitor) return
        this._clearProgressMonitor(monitor)
    }

    _registerControlAlarmListener() {
        const alarms = globalThis.browser?.alarms
        if (this._controlAlarmRegistered === true || !alarms?.onAlarm?.addListener) {
            return this._controlAlarmRegistered === true
        }
        this._controlAlarmHandler = (alarm = {}) => {
            if (alarm?.name && alarm.name !== ZAP_CONTROL_ALARM_NAME) {
                return
            }
            void this._handleControlAlarmTick()
        }
        try {
            alarms.onAlarm.addListener(this._controlAlarmHandler)
            this._controlAlarmRegistered = true
            return true
        } catch (err) {
            console.warn('[PTK ZAP] Failed to register control alarm listener:', err?.message || String(err))
            this._controlAlarmHandler = null
            return false
        }
    }

    async _ensureControlAlarmActive() {
        const alarms = globalThis.browser?.alarms
        if (!this._progressMonitorsByKey.size || !alarms?.create) {
            return false
        }
        this._registerControlAlarmListener()
        if (this._controlAlarmRegistered !== true) {
            return false
        }
        if (this._controlAlarmActive === true) {
            return true
        }
        try {
            await alarms.create(ZAP_CONTROL_ALARM_NAME, {
                delayInMinutes: ZAP_CONTROL_ALARM_PERIOD_MINUTES,
                periodInMinutes: ZAP_CONTROL_ALARM_PERIOD_MINUTES
            })
            this._controlAlarmActive = true
            this._debugLog('[PTK ZAP] Control alarm armed:', {
                name: ZAP_CONTROL_ALARM_NAME,
                periodInMinutes: ZAP_CONTROL_ALARM_PERIOD_MINUTES
            })
            return true
        } catch (err) {
            console.warn('[PTK ZAP] Failed to arm control alarm:', err?.message || String(err))
            return false
        }
    }

    async _clearControlAlarmIfIdle() {
        if (this._progressMonitorsByKey.size) {
            return false
        }
        const alarms = globalThis.browser?.alarms
        if (!alarms?.clear) {
            this._controlAlarmActive = false
            return false
        }
        if (this._controlAlarmActive !== true) {
            return false
        }
        try {
            await alarms.clear(ZAP_CONTROL_ALARM_NAME)
        } catch (err) {
            console.warn('[PTK ZAP] Failed to clear control alarm:', err?.message || String(err))
        } finally {
            this._controlAlarmActive = false
        }
        return true
    }

    async _handleControlAlarmTick() {
        const monitors = this._progressMonitorsByKey.size
        if (!monitors) {
            await this._clearControlAlarmIfIdle()
            return { ok: true, monitors: 0 }
        }
        this._debugLog('[PTK ZAP] Control alarm tick:', { monitors })
        this.tickProgressMonitors({ source: 'control_alarm' })
        this.pollControlMonitors({ source: 'control_alarm' })
        return { ok: true, monitors }
    }

    _buildProgressMonitorPayload({ progress, status, message = null, engines = null, safeToClose = null, phase = null, completionStatus = null, releaseStatus = null }) {
        const payload = {
            progress,
            status
        }
        const explicitPhase = toNonEmptyString(phase)
        if (explicitPhase) {
            payload.phase = explicitPhase
        }
        if (typeof safeToClose === 'boolean') {
            payload.safeToClose = safeToClose
        } else {
            payload.safeToClose = isZapTerminalStatus(status)
        }
        const text = toNonEmptyString(message)
        if (text) {
            payload.message = text
        }
        const completion = toNonEmptyString(completionStatus)
        if (completion) {
            payload.completionStatus = completion
        }
        const release = toNonEmptyString(releaseStatus)
        if (release) {
            payload.releaseStatus = release
        }
        if (engines && typeof engines === 'object' && !Array.isArray(engines)) {
            payload.engines = engines
        }
        return payload
    }

    _attachProgressSessionContext(payload, monitor) {
        if (!payload || typeof payload !== 'object' || !monitor) {
            return payload
        }
        if (monitor.sessionId && !payload.sessionId) {
            payload.sessionId = monitor.sessionId
        }
        if (monitor.zapid && !payload.zapid) {
            payload.zapid = monitor.zapid
        }
        if (monitor.baseUrl && !payload.baseUrl) {
            payload.baseUrl = monitor.baseUrl
        }
        const targetUrl = toHttpUrl(monitor.lastRuntimeSnapshot?.targetUrl)
        if (targetUrl && !payload.targetUrl) {
            payload.targetUrl = targetUrl
        }
        return payload
    }

    _normalizePublisherState(rawState = null) {
        const pendingFindings = toFiniteNumber(rawState?.pendingFindings, 0)
        const inFlightBatches = toFiniteNumber(rawState?.inFlightBatches, 0)
        const lastAckedBatchSeq = toFiniteNumber(rawState?.lastAckedBatchSeq, 0)
        const pendingByEngine = rawState?.pendingByEngine && typeof rawState.pendingByEngine === 'object' && !Array.isArray(rawState.pendingByEngine)
            ? rawState.pendingByEngine
            : {}
        const inFlightByEngine = rawState?.inFlightByEngine && typeof rawState.inFlightByEngine === 'object' && !Array.isArray(rawState.inFlightByEngine)
            ? rawState.inFlightByEngine
            : {}
        return {
            pendingFindings,
            inFlightBatches,
            drained: rawState?.drained === true && pendingFindings === 0 && inFlightBatches === 0,
            lastAckedBatchSeq,
            pendingByEngine,
            inFlightByEngine
        }
    }

    async _getPublisherStateForProgress() {
        try {
            if (!this.publisher || typeof this.publisher.getDrainState !== 'function') {
                return this._normalizePublisherState({ drained: true })
            }
            return this._normalizePublisherState(await this.publisher.getDrainState())
        } catch (err) {
            return this._normalizePublisherState({
                drained: false,
                pendingFindings: 0,
                inFlightBatches: 1,
                error: err?.message || String(err)
            })
        }
    }

    _sanitizeProgressEnginesForFingerprint(engines = null) {
        if (!engines || typeof engines !== 'object' || Array.isArray(engines)) return null
        const sanitized = {}
        for (const [engineName, engineValue] of Object.entries(engines)) {
            if (!engineValue || typeof engineValue !== 'object' || Array.isArray(engineValue)) continue
            const details = engineValue.details && typeof engineValue.details === 'object' && !Array.isArray(engineValue.details)
                ? engineValue.details
                : {}
            const safeDetails = {}
            const detailKeys = [
                'planned',
                'executed',
                'remaining',
                'activeTasks',
                'taskQueue',
                'requestQueue',
                'pendingPlans',
                'planning',
                'pendingCaptures',
                'pendingAutomationSeeds',
                'findingsCount',
                'seededRequests',
                'proxySeededRequests',
                'historySeededRequests',
                'agentReady',
                'requestsCount',
                'runtimeEventsCount',
                'findingReportsAccepted',
                'findingReportsDroppedInactive',
                'findingReportsDroppedTabMismatch',
                'runtimeSignalsAccepted',
                'modulesSentOk',
                'modulesSentSkipped',
                'modulesSentError',
                'collectionState',
                'runtimeHealthState',
                'completionStatus',
                'error',
                'message'
            ]
            for (const key of detailKeys) {
                if (details[key] !== undefined && details[key] !== null) {
                    safeDetails[key] = details[key]
                }
            }
            sanitized[engineName] = {
                status: engineValue.status || null,
                progress: toFiniteNumber(engineValue.progress, 0),
                completionStatus: engineValue.completionStatus || safeDetails.completionStatus || null,
                details: safeDetails
            }
        }
        return sanitized
    }

    _buildCloseReadiness(payload = {}, publisherState = {}, monitor = null) {
        const terminal = isZapTerminalStatus(payload?.status) || payload?.safeToClose === true
        const publisherDrained = publisherState?.drained === true
        const completionStatus = String(payload?.completionStatus || '').toLowerCase()
        const releaseStatus = String(payload?.releaseStatus || '').toLowerCase()
        const physicalIncompleteClose = payload?.safeToClose === true
            && (releaseStatus === 'incomplete'
                || completionStatus === 'engine_incomplete'
                || completionStatus === 'publisher_incomplete')
        const safeToClose = terminal && (publisherDrained || physicalIncompleteClose)
        let reason = 'running'
        if (!terminal) {
            reason = 'not_terminal'
        } else if (!publisherDrained) {
            reason = physicalIncompleteClose ? 'publisher_not_drained_incomplete_close' : 'publisher_not_drained'
        } else if (monitor?.closeRequest?.id) {
            reason = 'terminal_publisher_drained_after_close_request'
        } else {
            reason = 'terminal_publisher_drained'
        }
        return {
            safeToClose,
            reason,
            terminal,
            publisherDrained
        }
    }

    _attachV2ProgressContract(payload, monitor, publisherState = {}) {
        if (!payload || typeof payload !== 'object') return payload
        const completionStatus = toNonEmptyString(payload.completionStatus)
        let releaseStatus = toNonEmptyString(payload.releaseStatus)
        const terminalCandidate = isZapTerminalStatus(payload?.status) || payload?.safeToClose === true
        if (!releaseStatus && terminalCandidate) {
            const status = String(payload?.status || '').toLowerCase()
            releaseStatus = status === ZAP_PROGRESS_STATUS_ERROR || status === ZAP_PROGRESS_STATUS_CANCELLED
                ? 'incomplete'
                : completionStatus && completionStatus !== 'completed'
                ? 'incomplete'
                : (publisherState?.drained === true ? 'clean' : 'incomplete')
        }
        const progressPayload = releaseStatus
            ? Object.assign({}, payload, { releaseStatus })
            : payload
        const closeReadiness = this._buildCloseReadiness(progressPayload, publisherState, monitor)
        const closeRequest = monitor?.closeRequest || null
        const fingerprintSource = {
            sessionId: progressPayload.sessionId || monitor?.sessionId || null,
            status: progressPayload.status || null,
            progress: toFiniteNumber(progressPayload.progress, 0),
            phase: progressPayload.phase || null,
            completionStatus: progressPayload.completionStatus || null,
            releaseStatus: progressPayload.releaseStatus || null,
            safeToClose: closeReadiness.safeToClose,
            closeRequestId: closeRequest?.id || null,
            closeRequestAck: closeRequest?.acked === true,
            publisher: {
                pendingFindings: toFiniteNumber(publisherState?.pendingFindings, 0),
                inFlightBatches: toFiniteNumber(publisherState?.inFlightBatches, 0),
                drained: publisherState?.drained === true,
                lastAckedBatchSeq: toFiniteNumber(publisherState?.lastAckedBatchSeq, 0)
            },
            engines: this._sanitizeProgressEnginesForFingerprint(payload.engines)
        }
        const fingerprint = stableStringify(fingerprintSource)
        if (monitor) {
            if (!monitor.activityFingerprint || monitor.activityFingerprint !== fingerprint) {
                monitor.activitySeq = toFiniteNumber(monitor.activitySeq, 0) + 1
                monitor.activityFingerprint = fingerprint
            }
        }
        const v2Payload = Object.assign({}, progressPayload, {
            contractVersion: ZAP_PROGRESS_CONTRACT_VERSION,
            activitySeq: monitor?.activitySeq || 1,
            activityFingerprint: fingerprint,
            closeReadiness,
            publisher: publisherState,
            terminalSeen: closeReadiness.terminal,
            safeToClose: closeReadiness.safeToClose
        })
        if (closeRequest?.id) {
            v2Payload.closeRequestId = closeRequest.id
            v2Payload.closeRequestAck = closeRequest.acked === true
            v2Payload.closeRequestMode = closeRequest.mode || 'graceful_stop_and_drain'
        }
        return v2Payload
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

        const monitorKey = this._progressMonitorKey({ sessionKey: effectiveSessionKey, zapid: effectiveZapId, sessionId })
        const existing = monitorKey ? this._progressMonitorsByKey.get(monitorKey) : null
        if (existing && existing.sessionKey === effectiveSessionKey && existing.sessionId === (sessionId || null)) {
            if (Array.isArray(requiredEngines) && requiredEngines.length) {
                existing.requiredEngines = normalizeEngineList(requiredEngines)
            }
            if (terminalPayload) {
                existing.terminalPayload = terminalPayload
            }
            this._progressMonitor = existing
            void this._ensureControlAlarmActive()
            return
        }

        if (existing) {
            this._clearProgressMonitor(existing)
        }

        const monitor = {
            sessionKey: effectiveSessionKey,
            sessionId: sessionId || null,
            zapid: effectiveZapId,
            baseUrl: this.transport.getBaseUrl?.({ zapid: effectiveZapId }) || null,
            requiredEngines: normalizeEngineList(requiredEngines),
            readySent: terminalPayload ? true : false,
            quietSince: null,
            lastRuntimeSnapshot: null,
            lastDerivedEngineStates: null,
            terminalPayload: terminalPayload || null,
            pendingFlushSince: null,
            enginePassiveSince: Object.create(null),
            activitySeq: 0,
            activityFingerprint: null,
            closeRequest: null,
            closeRequestedSent: false,
            closeRequestAckPending: false,
            closeStopRequested: false,
            controlPollInFlight: false,
            lastControlPollAt: 0,
            controlIntervalId: null,
            intervalId: null
        }

        if (monitorKey) {
            this._progressMonitorsByKey.set(monitorKey, monitor)
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
        const controlTick = () => {
            void this._pollZapControl(monitor, { source: 'background_control_timer' })
        }

        tick()
        monitor.intervalId = setInterval(tick, ZAP_PROGRESS_HEARTBEAT_MS)
        monitor.controlIntervalId = setInterval(controlTick, ZAP_CONTROL_BACKGROUND_POLL_MS)
        void this._ensureControlAlarmActive()
    }

    async _postCloseRequestAck(monitor, { force = false } = {}) {
        if (!monitor?.closeRequest?.id || !this.transport?.postProgressJson) {
            return false
        }
        if (monitor.closeRequest.progressAckPosted === true && force !== true) {
            return true
        }
        monitor.closeRequest.acked = true
        const publisherState = await this._getPublisherStateForProgress()
        const progress = clampProgress(
            toFiniteNumber(monitor.lastDerivedEngineStates
                ? this._computeZapAggregateProgress(monitor.lastDerivedEngineStates, monitor.requiredEngines)
                : null, 99),
            99
        )
        let payload = this._buildProgressMonitorPayload({
            progress,
            status: ZAP_PROGRESS_STATUS_RUNNING,
            phase: 'draining',
            message: 'ZAP close request acknowledged; stopping PTK session',
            engines: monitor.lastDerivedEngineStates || this._buildReadyEngineStates(monitor.requiredEngines)
        })
        payload = this._attachProgressSessionContext(payload, monitor)
        payload = this._attachV2ProgressContract(payload, monitor, Object.assign({}, publisherState, {
            drained: false
        }))
        payload.safeToClose = false
        payload.closeReadiness = Object.assign({}, payload.closeReadiness || {}, {
            safeToClose: false,
            reason: 'close_request_acknowledged',
            terminal: false
        })
        try {
            await this.transport.postProgressJson(payload)
            monitor.closeRequest.progressAckPosted = true
            monitor.closeRequestAckPending = false
            return true
        } catch (err) {
            monitor.closeRequestAckPending = true
            console.warn('[PTK ZAP] Failed to acknowledge ZAP close request:', err?.message || String(err))
            return false
        }
    }

    async _pollZapControl(monitor, { source = null, force = false } = {}) {
        if (!monitor || typeof monitor !== 'object' || !this.transport?.postControlJson) {
            return null
        }
        const key = this._progressMonitorKey(monitor)
        if (key && this._progressMonitorsByKey.has(key) && this._progressMonitorsByKey.get(key) !== monitor) {
            return null
        }
        if (monitor.controlPollInFlight === true) {
            return null
        }
        const now = Date.now()
        if (force !== true && monitor.lastControlPollAt && now - monitor.lastControlPollAt < ZAP_CONTROL_POLL_MIN_INTERVAL_MS) {
            return null
        }
        monitor.controlPollInFlight = true
        monitor.lastControlPollAt = now
        try {
            const publisherState = await this._getPublisherStateForProgress()
            const response = await this.transport.postControlJson({
                contractVersion: ZAP_PROGRESS_CONTRACT_VERSION,
                zapid: monitor.zapid,
                sessionId: monitor.sessionId,
                activitySeq: monitor.activitySeq || 0,
                activityFingerprint: monitor.activityFingerprint || null,
                closeRequestId: monitor.closeRequest?.id || null,
                closeRequestAck: monitor.closeRequest?.acked === true,
                closeRequestMode: monitor.closeRequest?.mode || null,
                publisher: publisherState,
                source
            })
            await this._handleZapProgressControlResponse(monitor, response?.data, {
                source: source || 'control_poll'
            })
            return response
        } catch (err) {
            console.warn('[PTK ZAP] Failed to poll ZAP control endpoint:', err?.message || String(err))
            return null
        } finally {
            monitor.controlPollInFlight = false
        }
    }

    pollControlMonitors({ source = 'external' } = {}) {
        let monitors = 0
        for (const monitor of this._progressMonitorsByKey.values()) {
            if (!monitor || typeof monitor !== 'object') continue
            monitors += 1
            void this._pollZapControl(monitor, { source, force: true })
        }
        return { ok: true, monitors }
    }

    async _handleZapProgressControlResponse(monitor, control = {}, { source = 'progress_response' } = {}) {
        const key = this._progressMonitorKey(monitor)
        if (key && this._progressMonitorsByKey.has(key) && this._progressMonitorsByKey.get(key) !== monitor) {
            return
        }
        if (!control || typeof control !== 'object' || control.closeRequested !== true) {
            return
        }
        const closeRequestId = toNonEmptyString(control.closeRequestId)
            || `${monitor.zapid || 'zap'}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
        if (monitor.closeRequest?.id && monitor.closeRequest.id !== closeRequestId && monitor.closeRequest.acked === true) {
            this._debugLog('[PTK ZAP] Ignoring superseded close request after acknowledgement:', {
                zapid: monitor.zapid,
                sessionId: monitor.sessionId,
                existingCloseRequestId: monitor.closeRequest.id,
                closeRequestId
            })
            return
        }
        const automation = this.app?.automation
        if (!automation || typeof automation.requestZapSessionStop !== 'function') {
            console.warn('[PTK ZAP] ZAP close request received but automation stop API is unavailable')
            return
        }
        if (!monitor.closeRequest || monitor.closeRequest.id !== closeRequestId) {
            monitor.closeRequest = {
                id: closeRequestId,
                mode: toNonEmptyString(control.mode) || 'graceful_stop_and_drain',
                reason: toNonEmptyString(control.reason) || 'zap_requested_close',
                requestedAt: Date.now(),
                acked: false,
                progressAckPosted: false
            }
        } else {
            monitor.closeRequest.mode = toNonEmptyString(control.mode) || monitor.closeRequest.mode || 'graceful_stop_and_drain'
            monitor.closeRequest.reason = toNonEmptyString(control.reason) || monitor.closeRequest.reason || 'zap_requested_close'
        }
        monitor.closeRequestedSent = true
        await this._postCloseRequestAck(monitor, {
            force: source === 'control_poll' || control.closeRequested === true
        })
        const stopTimeoutMs = Number.isFinite(Number(control.stopTimeoutMs))
            ? Math.max(1000, Math.min(Number(control.stopTimeoutMs), ZAP_CLOSE_CONTRACT_PTK_STOP_TIMEOUT_MS))
            : ZAP_CLOSE_CONTRACT_PTK_STOP_TIMEOUT_MS
        const drainTimeoutMs = Number.isFinite(Number(control.drainTimeoutMs))
            ? Math.max(0, Math.min(Number(control.drainTimeoutMs), ZAP_CLOSE_CONTRACT_PTK_STOP_TIMEOUT_MS))
            : stopTimeoutMs
        this._startZapCloseStop(monitor, automation, {
            closeRequestId,
            stopTimeoutMs,
            drainTimeoutMs
        })
    }

    _startZapCloseStop(monitor, automation, { closeRequestId, stopTimeoutMs, drainTimeoutMs } = {}) {
        if (!monitor?.closeRequest?.id || !automation || typeof automation.requestZapSessionStop !== 'function') {
            return null
        }
        if (monitor.closeStopRequested === true) {
            return monitor.closeStopPromise || null
        }
        monitor.closeStopRequested = true
        monitor.closeStopPromise = Promise.resolve().then(async () => {
            const result = await automation.requestZapSessionStop(monitor.sessionId, {
                timeoutMs: stopTimeoutMs,
                drainTimeoutMs,
                source: 'zap_browser_close',
                closeRequestId,
                closeRequestMode: monitor.closeRequest.mode,
                closeRequestReason: monitor.closeRequest.reason,
                zapid: monitor.zapid
            })
            this._debugLog('[PTK ZAP] ZAP close request stop issued:', {
                zapid: monitor.zapid,
                sessionId: monitor.sessionId,
                closeRequestId,
                result
            })
            return result
        }).catch((err) => {
            monitor.closeStopError = err?.message || String(err)
            console.warn('[PTK ZAP] Failed to request PTK stop from ZAP close signal:', err?.message || String(err))
            return { ok: false, error: monitor.closeStopError }
        })
        return monitor.closeStopPromise
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

    tickProgressMonitors({ source = null } = {}) {
        let monitors = 0
        for (const monitor of this._progressMonitorsByKey.values()) {
            if (!monitor || typeof monitor !== 'object') continue
            monitors += 1
            void this._tickProgressMonitor(monitor, { source })
        }
        return { ok: true, monitors }
    }

    async _tickProgressMonitor(monitor, { source = null } = {}) {
        if (!monitor || typeof monitor !== 'object') return
        const now = Date.now()
        if (monitor.tickInFlight === true) {
            const startedAt = Number(monitor.tickStartedAt || 0)
            const ageMs = startedAt > 0 ? now - startedAt : 0
            if (ageMs >= 0 && ageMs < ZAP_PROGRESS_TICK_STALE_MS) return
            monitor.tickStaleRecoveries = toFiniteNumber(monitor.tickStaleRecoveries, 0) + 1
            console.warn('[PTK ZAP] Recovering stale progress monitor tick:', {
                zapid: monitor.zapid,
                sessionId: monitor.sessionId,
                source,
                ageMs,
                recoveries: monitor.tickStaleRecoveries
            })
        }
        const tickToken = toFiniteNumber(monitor.tickToken, 0) + 1
        monitor.tickToken = tickToken
        monitor.tickStartedAt = now
        if (monitor && typeof monitor === 'object') {
            monitor.tickInFlight = true
        }
        try {
            return await this._tickProgressMonitorOnce(monitor)
        } finally {
            if (monitor && typeof monitor === 'object' && monitor.tickToken === tickToken) {
                monitor.tickInFlight = false
                monitor.tickStartedAt = null
            }
        }
    }

    async _tickProgressMonitorOnce(monitor) {
        const monitorKey = this._progressMonitorKey(monitor)
        if (monitorKey && this._progressMonitorsByKey.has(monitorKey) && this._progressMonitorsByKey.get(monitorKey) !== monitor) {
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
                            monitor.pendingFlushSince = monitor.pendingFlushSince || Date.now()
                            payload = this._buildProgressMonitorPayload({
                                progress: this._computeZapAggregateProgress(derivedState.engines, runtimeRequiredEngines),
                                status: ZAP_PROGRESS_STATUS_RUNNING,
                                message: 'Waiting for final PTK findings drain',
                                engines: derivedState.engines
                            })
                        }
                    } else {
                        monitor.pendingFlushSince = null
                        payload = this._buildZapProgressPayloadFromDerivedState(derivedState)
                    }
                }
            }
        }

        try {
            payload = this._attachProgressSessionContext(payload, monitor)
            payload = this._attachV2ProgressContract(payload, monitor, await this._getPublisherStateForProgress())
            const progressResponse = await this.transport.postProgressJson(payload)
            await this._handleZapProgressControlResponse(monitor, progressResponse?.data)
            await this._pollZapControl(monitor, { source: 'progress_tick' })
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
            if (monitor.terminalPayload || payload.safeToClose === true) {
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
            await this._pollZapControl(monitor, { source: 'progress_post_failed', force: true })
        }
    }

    async postTerminalProgressForClose({ sessionId = null, zapid = null, allowRetry = true } = {}) {
        const effectiveZapId = zapid || this.transport.getZapId?.() || null
        if (!sessionId || !effectiveZapId || !this.transport.isReady?.({ zapid: effectiveZapId })) {
            return { ok: false, posted: false, reason: 'zap_progress_not_ready' }
        }

        const automation = this.app?.automation
        const runtimeSnapshot = automation?.getZapSessionProgressState?.(sessionId)
        if (!runtimeSnapshot?.ok) {
            return {
                ok: false,
                posted: false,
                reason: runtimeSnapshot?.error || 'session_progress_unavailable'
            }
        }

        const existingMonitor = Array.from(this._progressMonitorsByKey.values())
            .find(candidate => candidate?.sessionId === sessionId && (!effectiveZapId || candidate?.zapid === effectiveZapId))
        const monitor = existingMonitor
            ? existingMonitor
            : {
                sessionKey: this._buildZapSessionKey(this.transport.getBaseUrl?.(), effectiveZapId),
                sessionId,
                zapid: effectiveZapId,
                baseUrl: this.transport.getBaseUrl?.({ zapid: effectiveZapId }) || null,
                requiredEngines: this._getRequiredZapEngines(null, runtimeSnapshot),
                readySent: true,
                lastRuntimeSnapshot: runtimeSnapshot,
                lastDerivedEngineStates: null,
                terminalPayload: null,
                pendingFlushSince: null,
                enginePassiveSince: Object.create(null),
                activitySeq: 0,
                activityFingerprint: null,
                closeRequest: null,
                closeRequestedSent: false,
                closeStopRequested: false,
                controlPollInFlight: false,
                lastControlPollAt: 0
            }

        const derivedState = this._deriveZapProgressState(monitor, runtimeSnapshot)
        if (!derivedState?.terminal) {
            if (allowRetry) {
                this._scheduleCloseTerminalProgressRetry({
                    sessionId,
                    zapid: effectiveZapId,
                    reason: 'not_terminal'
                })
            }
            return {
                ok: true,
                posted: false,
                reason: 'not_terminal',
                status: derivedState?.status || null,
                progress: derivedState?.progress ?? null
            }
        }

        const flushed = await this._flushPublisherWithTimeout()
        if (!flushed) {
            if (allowRetry) {
                this._scheduleCloseTerminalProgressRetry({
                    sessionId,
                    zapid: effectiveZapId,
                    reason: 'publisher_not_drained'
                })
            }
            if (allowRetry) {
                return { ok: false, posted: false, reason: 'publisher_not_drained' }
            }
        }

        let payload = this._buildZapProgressPayloadFromDerivedState(derivedState)
        if (!flushed) {
            payload = Object.assign({}, payload, {
                progress: 100,
                status: payload.status === ZAP_PROGRESS_STATUS_COMPLETED
                    ? ZAP_PROGRESS_STATUS_COMPLETED
                    : ZAP_PROGRESS_STATUS_CANCELLED,
                completionStatus: 'publisher_incomplete',
                releaseStatus: 'incomplete',
                safeToClose: true,
                message: payload.message || 'PTK scan terminal state reached but final finding publisher drain was incomplete'
            })
        }
        monitor.lastRuntimeSnapshot = runtimeSnapshot
        monitor.lastDerivedEngineStates = derivedState.engines
        payload = this._attachProgressSessionContext(payload, monitor)
        payload = this._attachV2ProgressContract(payload, monitor, await this._getPublisherStateForProgress())
        await this.transport.postProgressJson(payload)
        this.transport.markSessionTerminal?.({
            zapid: effectiveZapId,
            sessionId,
            progress: payload.progress,
            status: payload.status
        })
        this._clearCloseTerminalProgressRetry({ sessionId, zapid: effectiveZapId })
        this._clearProgressMonitorIfCurrent(monitor)
        return {
            ok: true,
            posted: true,
            status: payload.status,
            progress: payload.progress
        }
    }

    _closeTerminalProgressRetryKey({ sessionId = null, zapid = null } = {}) {
        const safeSessionId = toNonEmptyString(sessionId)
        const safeZapId = toNonEmptyString(zapid)
        if (!safeSessionId || !safeZapId) return null
        return `${safeZapId}::${safeSessionId}`
    }

    _clearCloseTerminalProgressRetry({ sessionId = null, zapid = null } = {}) {
        const key = this._closeTerminalProgressRetryKey({ sessionId, zapid })
        if (!key) return
        const retry = this._closeTerminalRetryTimers.get(key)
        if (!retry) return
        clearInterval(retry.intervalId)
        this._closeTerminalRetryTimers.delete(key)
    }

    _scheduleCloseTerminalProgressRetry({ sessionId = null, zapid = null, reason = null } = {}) {
        const key = this._closeTerminalProgressRetryKey({ sessionId, zapid })
        if (!key || this._closeTerminalRetryTimers.has(key)) return

        const startedAt = Date.now()
        const retry = {
            startedAt,
            intervalId: null,
            running: false,
            lastReason: reason || null
        }
        const runRetry = async () => {
            if (retry.running) return
            if (Date.now() - startedAt > ZAP_CLOSE_TERMINAL_RETRY_TIMEOUT_MS) {
                this._clearCloseTerminalProgressRetry({ sessionId, zapid })
                console.warn('[PTK ZAP] Gave up retrying close terminal progress:', {
                    zapid,
                    sessionId,
                    reason: retry.lastReason
                })
                return
            }
            retry.running = true
            try {
                const result = await this.postTerminalProgressForClose({
                    sessionId,
                    zapid,
                    allowRetry: false
                })
                retry.lastReason = result?.reason || null
                if (result?.posted === true || this.transport.isSessionTerminal?.({ zapid, sessionId }) === true) {
                    this._clearCloseTerminalProgressRetry({ sessionId, zapid })
                }
            } catch (err) {
                retry.lastReason = err?.message || String(err)
            } finally {
                retry.running = false
            }
        }
        retry.intervalId = setInterval(runRetry, ZAP_CLOSE_TERMINAL_RETRY_MS)
        this._closeTerminalRetryTimers.set(key, retry)
    }

    _deriveZapProgressState(monitor, runtimeSnapshot) {
        const requiredEngines = this._getRequiredZapEngines(monitor, runtimeSnapshot)
        const engineStates = this._deriveZapEngineStates(monitor, runtimeSnapshot, requiredEngines)
        const sessionMessage = toNonEmptyString(runtimeSnapshot?.message)
        const errorMessage = sessionMessage || this._findFirstEngineMessage(engineStates, requiredEngines)
        if (errorMessage) {
            const settled = this._areRequiredEnginesSettled(engineStates, requiredEngines)
            const terminal = settled
            return {
                status: terminal ? ZAP_PROGRESS_STATUS_ERROR : ZAP_PROGRESS_STATUS_RUNNING,
                progress: terminal ? 100 : this._computeZapAggregateProgress(engineStates, requiredEngines),
                engines: engineStates,
                terminal,
                message: errorMessage,
                completionStatus: terminal ? 'engine_incomplete' : null,
                releaseStatus: terminal ? 'incomplete' : null
            }
        }

        const stopRequested = Boolean(runtimeSnapshot?.stopRequestedAt)
        if (stopRequested) {
            const cancelled = this._areRequiredEnginesSettled(engineStates, requiredEngines)
            const incomplete = cancelled && this._hasIncompleteEngine(engineStates, requiredEngines)
            return {
                status: cancelled
                    ? (incomplete ? ZAP_PROGRESS_STATUS_CANCELLED : ZAP_PROGRESS_STATUS_COMPLETED)
                    : ZAP_PROGRESS_STATUS_RUNNING,
                progress: cancelled ? 100 : this._computeZapAggregateProgress(engineStates, requiredEngines),
                engines: engineStates,
                terminal: cancelled,
                message: cancelled
                    ? (incomplete ? 'PTK scan stopped after flushing findings; some engine work was incomplete' : 'PTK scan stopped after flushing findings')
                    : null,
                completionStatus: incomplete ? 'engine_incomplete' : (cancelled ? 'completed' : null),
                releaseStatus: cancelled ? (incomplete ? 'incomplete' : 'clean') : null
            }
        }

        const completed = this._updateZapIdleGraceWindow(monitor, engineStates, runtimeSnapshot, requiredEngines)
        if (completed) {
            return {
                status: ZAP_PROGRESS_STATUS_COMPLETED,
                progress: 100,
                engines: engineStates,
                terminal: true,
                message: null,
                completionStatus: 'completed',
                releaseStatus: 'clean'
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
        const errorDetails = {
            error: error || null,
            message: error || null
        }
        if (error) {
            return {
                status: ZAP_PROGRESS_STATUS_ERROR,
                progress: 100,
                message: error,
                completionStatus: 'engine_incomplete',
                details: errorDetails
            }
        }

        const interactionRequired = runtime?.interactionRequired === true
        const userInteractionUnlocked = runtime?.userInteractionUnlocked === true
        const hasObservedWork = runtime?.hasObservedWork === true
        const activeTasks = toFiniteNumber(runtime?.activeTasks, 0)
        const taskQueue = toFiniteNumber(runtime?.taskQueue, 0)
        const requestQueue = toFiniteNumber(runtime?.requestQueue, 0)
        const pendingPlans = toFiniteNumber(runtime?.pendingPlans, 0)
        const rawPlanning = toFiniteNumber(runtime?.planning, 0)
        const pendingCaptures = toFiniteNumber(runtime?.pendingCaptures, 0)
        const pendingAutomationSeeds = toFiniteNumber(runtime?.pendingAutomationSeeds, 0)
        const concreteWork = activeTasks
            + taskQueue
            + requestQueue
            + pendingPlans
            + pendingCaptures
            + pendingAutomationSeeds
        const planning = rawPlanning > 0 && concreteWork > 0 ? rawPlanning : 0
        const rawRemaining = toFiniteNumber(runtime?.remaining, 0)
        const remaining = concreteWork > 0 || planning > 0 ? rawRemaining : 0
        const details = {
            planned: toFiniteNumber(runtime?.planned, 0),
            executed: toFiniteNumber(runtime?.executed, 0),
            remaining,
            activeTasks,
            taskQueue,
            requestQueue,
            pendingPlans,
            planning,
            pendingCaptures,
            pendingAutomationSeeds,
            captureStats: runtime?.captureStats || null,
            skippedDueToStrategy: toFiniteNumber(runtime?.skippedDueToStrategy, 0),
            scanStrategy: runtime?.scanStrategy || null,
            findingsCount: toFiniteNumber(runtime?.findingsCount, 0),
            seededRequests: toFiniteNumber(runtime?.seededRequests, 0),
            proxySeededRequests: toFiniteNumber(runtime?.proxySeededRequests, 0),
            historySeededRequests: toFiniteNumber(runtime?.historySeededRequests, 0)
        }
        const hasActiveWork = concreteWork > 0 || planning > 0
        const progress = this._computeZapDastProgress(runtime)

        if (runtimeEntry.state === 'starting' || runtimeEntry.state === 'deferred_start') {
            return { status: 'starting', progress: 0, details }
        }
        const state = String(runtimeEntry.state || '').toLowerCase()
        const completionStatus = String(runtime?.completionStatus || '').toLowerCase()
        if (state === 'cancelled' || state === 'engine_incomplete' || completionStatus === 'engine_incomplete') {
            return {
                status: ZAP_PROGRESS_STATUS_CANCELLED,
                progress: 100,
                details,
                completionStatus: 'engine_incomplete'
            }
        }
        if (state === 'stopped' || state === 'completed') {
            return {
                status: 'idle',
                progress: 100,
                details,
                completionStatus: completionStatus || 'completed'
            }
        }
        if (hasActiveWork) {
            return {
                status: ZAP_PROGRESS_STATUS_RUNNING,
                progress: clampProgress(progress, 99),
                details
            }
        }
        if (interactionRequired && !userInteractionUnlocked) {
            return {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0,
                details
            }
        }
        if (!hasObservedWork) {
            return {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0,
                details
            }
        }

        return {
            status: 'idle',
            progress: 100,
            details
        }
    }

    _deriveZapIastEngineState(runtimeEntry, previousRuntimeEntry = null) {
        if (!runtimeEntry || typeof runtimeEntry !== 'object') {
            return { status: 'starting', progress: 0 }
        }

        const runtime = runtimeEntry.telemetry || {}
        const previousRuntime = previousRuntimeEntry?.telemetry || null
        const error = toNonEmptyString(runtime?.error)
        const errorDetails = {
            error: error || null,
            message: error || null
        }
        if (error) {
            return {
                status: ZAP_PROGRESS_STATUS_ERROR,
                progress: 100,
                message: error,
                completionStatus: 'engine_incomplete',
                details: errorDetails
            }
        }

        const isScanRunning = runtime?.isScanRunning === true
        const agentReady = runtime?.agentReady === true
        const hasObservedActivity = runtime?.hasObservedActivity === true
        const telemetry = runtime?.automationTelemetry && typeof runtime.automationTelemetry === 'object'
            ? runtime.automationTelemetry
            : {}
        const details = {
            agentReady: agentReady ? 1 : 0,
            requestsCount: toFiniteNumber(runtime?.requestsCount, 0),
            runtimeEventsCount: toFiniteNumber(runtime?.runtimeEventsCount, 0),
            findingsCount: toFiniteNumber(runtime?.findingsCount, 0),
            findingReportsAccepted: toFiniteNumber(telemetry?.findingReportsAccepted, 0),
            findingReportsDroppedInactive: toFiniteNumber(telemetry?.findingReportsDroppedInactive, 0),
            findingReportsDroppedTabMismatch: toFiniteNumber(telemetry?.findingReportsDroppedTabMismatch, 0),
            runtimeSignalsAccepted: toFiniteNumber(telemetry?.runtimeSignalsAccepted, 0),
            modulesSentOk: toFiniteNumber(telemetry?.modulesSentOk, 0),
            modulesSentSkipped: toFiniteNumber(telemetry?.modulesSentSkipped, 0),
            modulesSentError: toFiniteNumber(telemetry?.modulesSentError, 0),
            scanStrategy: runtime?.scanStrategy || telemetry?.scanStrategy || null,
            lastDroppedReason: telemetry?.lastDroppedReason || null,
            lastModuleSendResult: telemetry?.lastModuleSendResult || null,
            runtimeHealthState: runtime?.runtimeHealth?.state || null
        }

        if (runtimeEntry.state === 'starting' || runtimeEntry.state === 'deferred_start' || (isScanRunning && !agentReady)) {
            return { status: 'starting', progress: 0, details }
        }
        const state = String(runtimeEntry.state || '').toLowerCase()
        if (state === 'cancelled' || state === 'engine_incomplete') {
            return {
                status: ZAP_PROGRESS_STATUS_CANCELLED,
                progress: 100,
                details,
                completionStatus: 'engine_incomplete'
            }
        }
        if (state === 'stopped' || state === 'completed') {
            return {
                status: 'idle',
                progress: 100,
                details,
                completionStatus: 'completed'
            }
        }
        if (!hasObservedActivity) {
            return {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0,
                details
            }
        }
        if (isScanRunning !== true) {
            return {
                status: 'idle',
                progress: 100,
                details
            }
        }
        if (this._didZapIastRuntimeAdvance(runtime, previousRuntime)) {
            return {
                status: ZAP_PROGRESS_STATUS_RUNNING,
                progress: 0,
                details
            }
        }

        return {
            status: 'idle',
            progress: 100,
            details
        }
    }

    _deriveZapSastEngineState(runtimeEntry, previousRuntimeEntry = null) {
        if (!runtimeEntry || typeof runtimeEntry !== 'object') {
            return { status: 'starting', progress: 0 }
        }

        const runtime = runtimeEntry.telemetry || {}
        const error = toNonEmptyString(runtime?.error)
        const errorDetails = {
            error: error || null,
            message: error || null
        }
        if (error) {
            return {
                status: ZAP_PROGRESS_STATUS_ERROR,
                progress: 100,
                message: error,
                completionStatus: 'engine_incomplete',
                details: errorDetails
            }
        }

        const phase = String(runtime?.phase || '').toLowerCase()
        const activePhases = new Set(['scan_start', 'file', 'module', 'file_complete', 'module_complete'])
        const hasObservedWork = runtime?.hasObservedWork === true
        const collectionState = String(runtime?.collectionState || '').toLowerCase()
        const firstCollectionStarted = runtime?.firstCollectionStarted === true
        const firstCollectionSettled = runtime?.firstCollectionSettled === true
        const activeCollectionCount = toFiniteNumber(runtime?.activeCollectionCount, 0)
        const pendingCollectionCount = toFiniteNumber(runtime?.pendingCollectionCount, 0)
        const progress = this._computeZapSastProgress(runtime)
        const waitingForFuturePageActivity = collectionState === 'waiting_for_page_activity'
            && activeCollectionCount === 0
            && pendingCollectionCount === 0

        if (runtimeEntry.state === 'starting' || runtimeEntry.state === 'deferred_start') {
            return { status: 'starting', progress: 0 }
        }
        const state = String(runtimeEntry.state || '').toLowerCase()
        if (state === 'cancelled' || state === 'engine_incomplete') {
            return {
                status: ZAP_PROGRESS_STATUS_CANCELLED,
                progress: 100,
                completionStatus: 'engine_incomplete'
            }
        }
        if (state === 'stopped' || state === 'completed') {
            return {
                status: 'idle',
                progress: 100,
                completionStatus: 'completed'
            }
        }
        if (!hasObservedWork && waitingForFuturePageActivity) {
            return {
                status: ZAP_PROGRESS_STATUS_READY,
                progress: 0
            }
        }
        if (!firstCollectionStarted
            || !firstCollectionSettled
            || activeCollectionCount > 0
            || pendingCollectionCount > 0
            || collectionState === 'collection_pending'
            || collectionState === 'payload_received'
            || collectionState === 'scan_in_flight') {
            return {
                status: ZAP_PROGRESS_STATUS_RUNNING,
                progress: clampProgress(progress, 99)
            }
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
            return status === ZAP_PROGRESS_STATUS_READY || status === 'starting' || status === 'deferred_start'
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

        if (!this._isZapTargetActivityQuiet(monitor, runtimeSnapshot, engineNames)) {
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

    _isZapTargetActivityQuiet(monitor, runtimeSnapshot, requiredEngines = []) {
        const engineNames = normalizeEngineList(requiredEngines)
        if (!engineNames.includes('DAST')) {
            return true
        }

        const observed = this._lastTopLevelTargetObservation
        if (!observed) {
            return true
        }

        const observedAt = Number(observed.ts || 0)
        if (!Number.isFinite(observedAt) || observedAt <= 0) {
            return true
        }

        const source = String(observed.source || '')
        if (!TERMINAL_BLOCKING_TARGET_SOURCES.has(source)) {
            return true
        }

        const ageMs = Date.now() - observedAt
        if (!Number.isFinite(ageMs) || ageMs < 0 || ageMs >= ZAP_TARGET_ACTIVITY_QUIET_GRACE_MS) {
            return true
        }

        const runtimeTabId = Number.isInteger(runtimeSnapshot?.tabId)
            ? runtimeSnapshot.tabId
            : (Number.isInteger(monitor?.lastRuntimeSnapshot?.tabId) ? monitor.lastRuntimeSnapshot.tabId : null)
        if (Number.isInteger(runtimeTabId) && observed.tabId !== runtimeTabId) {
            return true
        }

        const runtimeTargetUrl = toHttpUrl(runtimeSnapshot?.targetUrl)
            || toHttpUrl(monitor?.lastRuntimeSnapshot?.targetUrl)
            || null
        const runtimeHost = toHostKeyFromUrl(runtimeTargetUrl)
        const observedHost = toHostKeyFromUrl(observed?.targetUrl)
        if (runtimeHost && observedHost && runtimeHost !== observedHost) {
            return true
        }

        return false
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

        if (status === 'idle') {
            clearPassive()
            return true
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
            const waitingForFuturePageActivity = runtime?.hasObservedWork !== true
                && String(runtime?.collectionState || '').toLowerCase() === 'waiting_for_page_activity'
                && toFiniteNumber(runtime?.activeCollectionCount, 0) === 0
                && toFiniteNumber(runtime?.pendingCollectionCount, 0) === 0
            if (!waitingForFuturePageActivity
                && (runtime?.firstCollectionStarted !== true
                || runtime?.firstCollectionSettled !== true
                || toFiniteNumber(runtime?.activeCollectionCount, 0) > 0
                || toFiniteNumber(runtime?.pendingCollectionCount, 0) > 0)) {
                clearPassive()
                return false
            }
            if (waitingForFuturePageActivity) {
                clearPassive()
                return true
            }
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
            engines: derivedState?.engines || null,
            completionStatus: derivedState?.completionStatus || null,
            releaseStatus: derivedState?.releaseStatus || null
        })
    }

    _hasIncompleteEngine(engineStates = {}, requiredEngines = []) {
        return normalizeEngineList(requiredEngines).some((engineName) => {
            const state = engineStates?.[engineName] || null
            return state?.status === ZAP_PROGRESS_STATUS_CANCELLED
                || String(state?.completionStatus || '').toLowerCase() === 'engine_incomplete'
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

        return false
    }

    _didZapDastRuntimeAdvance(runtime = {}, previousRuntime = null) {
        const normalizeDastCounters = (entry = {}) => {
            const activeTasks = toFiniteNumber(entry?.activeTasks, 0)
            const taskQueue = toFiniteNumber(entry?.taskQueue, 0)
            const requestQueue = toFiniteNumber(entry?.requestQueue, 0)
            const pendingPlans = toFiniteNumber(entry?.pendingPlans, 0)
            const pendingCaptures = toFiniteNumber(entry?.pendingCaptures, 0)
            const pendingAutomationSeeds = toFiniteNumber(entry?.pendingAutomationSeeds, 0)
            const concreteWork = activeTasks
                + taskQueue
                + requestQueue
                + pendingPlans
                + pendingCaptures
                + pendingAutomationSeeds
            const planning = toFiniteNumber(entry?.planning, 0) > 0 && concreteWork > 0
                ? toFiniteNumber(entry?.planning, 0)
                : 0
            const remaining = concreteWork > 0 || planning > 0
                ? toFiniteNumber(entry?.remaining, 0)
                : 0
            return {
                planned: toFiniteNumber(entry?.planned, 0),
                executed: toFiniteNumber(entry?.executed, 0),
                remaining,
                activeTasks,
                taskQueue,
                requestQueue,
                pendingPlans,
                planning,
                pendingCaptures,
                pendingAutomationSeeds,
                seededRequests: toFiniteNumber(entry?.seededRequests, 0),
                findingsCount: toFiniteNumber(entry?.findingsCount, 0),
                active: concreteWork > 0 || planning > 0
            }
        }

        if (!previousRuntime || typeof previousRuntime !== 'object') {
            const current = normalizeDastCounters(runtime)
            return current.active === true || current.executed > 0 || current.seededRequests > 0 || current.findingsCount > 0
        }

        const current = normalizeDastCounters(runtime)
        const previous = normalizeDastCounters(previousRuntime)
        const currentCounters = [
            current.planned,
            current.executed,
            current.remaining,
            current.activeTasks,
            current.taskQueue,
            current.requestQueue,
            current.pendingPlans,
            current.planning,
            current.pendingCaptures,
            current.pendingAutomationSeeds,
            current.seededRequests,
            current.findingsCount
        ]
        const previousCounters = [
            previous.planned,
            previous.executed,
            previous.remaining,
            previous.activeTasks,
            previous.taskQueue,
            previous.requestQueue,
            previous.pendingPlans,
            previous.planning,
            previous.pendingCaptures,
            previous.pendingAutomationSeeds,
            previous.seededRequests,
            previous.findingsCount
        ]
        if (currentCounters.some((value, index) => value !== previousCounters[index])) {
            return true
        }

        const currentMarkers = [
            String(runtime?.phase || ''),
            String(runtime?.status || ''),
            current.active ? 'active' : 'idle'
        ]
        const previousMarkers = [
            String(previousRuntime?.phase || ''),
            String(previousRuntime?.status || ''),
            previous.active ? 'active' : 'idle'
        ]
        if (currentMarkers.some((value, index) => value !== previousMarkers[index])) {
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
        const now = Date.now()
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
            toFiniteNumber(runtime?.hints, 0),
            toFiniteNumber(runtime?.activeCollectionCount, 0)
        ]
        const previousCounters = [
            toFiniteNumber(previousRuntime?.completedFiles, 0),
            toFiniteNumber(previousRuntime?.completedModules, 0),
            toFiniteNumber(previousRuntime?.findings, 0),
            toFiniteNumber(previousRuntime?.hints, 0),
            toFiniteNumber(previousRuntime?.activeCollectionCount, 0)
        ]
        if (currentCounters.some((value, index) => value > previousCounters[index])) {
            return true
        }

        const currentMarkers = [
            String(runtime?.phase || ''),
            String(runtime?.currentFile || ''),
            String(runtime?.currentModule || ''),
            String(runtime?.lastStatus || ''),
            String(runtime?.collectionState || ''),
            runtime?.firstCollectionSettled === true ? 'settled' : 'pending'
        ]
        const previousMarkers = [
            String(previousRuntime?.phase || ''),
            String(previousRuntime?.currentFile || ''),
            String(previousRuntime?.currentModule || ''),
            String(previousRuntime?.lastStatus || ''),
            String(previousRuntime?.collectionState || ''),
            previousRuntime?.firstCollectionSettled === true ? 'settled' : 'pending'
        ]
        if (currentMarkers.some((value, index) => value !== previousMarkers[index] && value)) {
            return true
        }

        return false
    }

    async _flushPublisherWithTimeout(timeoutMs = ZAP_PROGRESS_FLUSH_TIMEOUT_MS) {
        const drainForTerminal = this.publisher?.flushPendingForTerminal
        const flushOnce = this.publisher?.flushOnce
        const getDrainState = this.publisher?.getDrainState
        const isDrained = (state) => this._normalizePublisherState(state).drained === true
        if (typeof drainForTerminal !== 'function' && typeof flushOnce !== 'function') {
            return true
        }

        try {
            if (typeof getDrainState === 'function' && isDrained(await getDrainState.call(this.publisher))) {
                return true
            }
            const result = await Promise.race([
                typeof drainForTerminal === 'function'
                    ? Promise.resolve(drainForTerminal.call(this.publisher, {
                        maxPasses: ZAP_PROGRESS_DRAIN_MAX_PASSES
                    }))
                    : Promise.resolve(flushOnce.call(this.publisher)),
                new Promise((resolve) => setTimeout(() => resolve(false), timeoutMs))
            ])
            if (typeof drainForTerminal === 'function') {
                if (result !== false && isDrained(result)) {
                    return true
                }
                if (typeof getDrainState === 'function' && isDrained(await getDrainState.call(this.publisher))) {
                    return true
                }
                return false
            }
            if (result !== false) {
                return true
            }
            return typeof getDrainState === 'function' && isDrained(await getDrainState.call(this.publisher))
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
            return status !== ZAP_PROGRESS_STATUS_RUNNING && status !== 'starting' && status !== 'deferred_start'
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

    async sendAlertsBatch({ engine, scanId, alerts, truncated, batchId = null, batchSeq = null }) {
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
            batchId: batchId || createBatchId(),
            batchSeq: Number.isFinite(Number(batchSeq)) ? Number(batchSeq) : undefined,
            payload: {
                sessionId: this._progressMonitor?.sessionId || this._lastStartSessionId || null,
                engine: engine || null,
                scanId: scanId || null,
                alerts,
                truncated: truncated === true
            }
        }

        const result = await this.transport.postAlertsJson(this._attachZapEnvelopeContext(envelope, { engine, scanId }))
        this._debugLog('[PTK ZAP] Alerts batch sent successfully')
        return result?.data || null
    }

    async sendDastFindingsBatch({ scanId, findings, truncated, batchId = null, batchSeq = null }) {
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
            batchId: batchId || createBatchId(),
            batchSeq: Number.isFinite(Number(batchSeq)) ? Number(batchSeq) : undefined,
            payload: {
                sessionId: this._progressMonitor?.sessionId || this._lastStartSessionId || null,
                engine: 'DAST',
                scanId: scanId || null,
                findings,
                truncated: truncated === true
            }
        }

        const result = await this.transport.postAlertsJson(this._attachZapEnvelopeContext(envelope, { engine: 'DAST', scanId }))
        this._debugLog('[PTK ZAP] DAST findings batch sent successfully')
        return result?.data || null
    }

    async sendIastFindingsBatch({ scanId, findings, truncated, batchId = null, batchSeq = null }) {
        if (!this.isActive()) return
        if (!Array.isArray(findings) || findings.length === 0) return

        this._debugLog('[PTK ZAP] Sending IAST findings batch:', { scanId, count: findings.length, truncated })

        const envelope = {
            source: SOURCE,
            type: TYPE_IAST_FINDINGS_BATCH,
            schema: IAST_SCHEMA,
            ts: Date.now(),
            batchId: batchId || createBatchId(),
            batchSeq: Number.isFinite(Number(batchSeq)) ? Number(batchSeq) : undefined,
            payload: {
                sessionId: this._progressMonitor?.sessionId || this._lastStartSessionId || null,
                engine: 'IAST',
                scanId: scanId || null,
                findings,
                truncated: truncated === true
            }
        }

        const result = await this.transport.postAlertsJson(this._attachZapEnvelopeContext(envelope, { engine: 'IAST', scanId }))
        return result?.data || null
    }

    async sendSastFindingsBatch({ scanId, findings, truncated, batchId = null, batchSeq = null }) {
        if (!this.isActive()) return
        if (!Array.isArray(findings) || findings.length === 0) return

        this._debugLog('[PTK ZAP] Sending SAST findings batch:', { scanId, count: findings.length, truncated })

        const envelope = {
            source: SOURCE,
            type: TYPE_SAST_FINDINGS_BATCH,
            schema: SAST_SCHEMA,
            ts: Date.now(),
            batchId: batchId || createBatchId(),
            batchSeq: Number.isFinite(Number(batchSeq)) ? Number(batchSeq) : undefined,
            payload: {
                sessionId: this._progressMonitor?.sessionId || this._lastStartSessionId || null,
                engine: 'SAST',
                scanId: scanId || null,
                findings,
                truncated: truncated === true
            }
        }

        const result = await this.transport.postAlertsJson(this._attachZapEnvelopeContext(envelope, { engine: 'SAST', scanId }))
        return result?.data || null
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
        if (this.zapAutomationRewriteEnabled !== false) {
            this._automationController?.setDependencies?.({
                bridge: this,
                transport: this.transport
            })
            return this._automationController.handleZapDetected(payload)
        }
        return this._handleZapDetectedLegacyAsync(payload)
    }

    async _handleZapDetectedLegacyAsync(payload = {}) {
        this._syncDebugFlagFromApp()
        this._debugLog('[PTK ZAP] Handling ZAP detection:', payload)

        const baseUrl = payload.baseUrl || this.transport.getBaseUrl()
        const zapid = payload.zapid || this.transport.getZapId?.() || null
        const browserid = payload.browserid || this.transport.getBrowserId?.() || null
        const sessionKey = this._buildZapSessionKey(baseUrl, zapid)
        const previousBaseUrl = this.currentBaseUrl
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

        if (this.publisher && isNewSession && previousBaseUrl && baseUrl && previousBaseUrl !== baseUrl) {
            this._debugLog('[PTK ZAP] New base URL detected, resetting publisher state')
            this.publisher.resetState()
        }

        const automation = this.app?.automation
        if (!automation || typeof automation.startZapConfiguredSession !== 'function') {
            this._debugLog('[PTK ZAP] Automation module not attached yet; delaying ZAP-managed session start')
            return
        }

        const startKeyBase = `${sessionKey || baseUrl || ''}|${payload.tabId || ''}`
        if (this._startInFlightByKey.has(startKeyBase)) {
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
            const rawConfig = await this.confirmAndGetConfig({
                zapid,
                baseUrl,
                targetUrl: payload?.targetUrl || null
            })
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
            if (rawConfig?.ptkConfigFetchFailed === true) {
                this._clearPendingStart(sessionKey)
                this._debugLog('[PTK ZAP] ZAP config fetch failed; automatic scan start aborted:', {
                    zapid,
                    sessionKey,
                    error: rawConfig?.error || 'zap_config_unavailable'
                })
                this._scheduleTerminalProgress({
                    sessionKey,
                    zapid,
                    requiredEngines: [],
                    status: ZAP_PROGRESS_STATUS_ERROR,
                    message: 'ZAP automation config fetch failed'
                })
                return
            }
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
                this._clearPendingStart(sessionKey)
                this._debugLog('[PTK ZAP] mode is manual; automatic scan start is disabled')
                return
            }

            const finalEngines = this._getAutoStartEngines(parsedConfig)
            const finalEngineConfigs = this._buildAutoStartEngineConfigs(parsedConfig, finalEngines)
            const configSeedUrls = this._collectConfigSeedUrls(finalEngineConfigs)
            const configSeedTargetUrl = this._selectPostCallbackTargetUrl(configSeedUrls)
            this._debugLog('[PTK ZAP] Auto-start engine selection:', {
                zapid,
                sessionKey,
                engines: finalEngines
            })
            if (!finalEngines.length) {
                this._clearPendingStart(sessionKey)
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

            const pendingStart = {
                tabId: Number.isInteger(payload?.tabId) && payload.tabId >= 0 ? payload.tabId : null,
                baseUrl: baseUrl || null,
                sessionKey,
                zapid,
                targetUrl: configSeedTargetUrl || toHttpUrl(payload?.targetUrl) || null,
                engines: finalEngines,
                engineConfigs: finalEngineConfigs
            }
            this._setPendingStart(pendingStart)
            const targetUrlResolveStartedAt = Date.now()
            const targetUrl = await this._resolveTargetUrl(Object.assign({}, payload, {
                zapHistorySeedUrls: configSeedUrls
            }), 120000)
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
                this._setPendingStart(pendingStart)
                this._debugLog('[PTK ZAP] Target URL not available yet; waiting for next non-ZAP navigation')
                await this._tryStartFromObservedTarget(pendingStart)
                return
            }

            const seededCallbackTabId = Number.isInteger(payload?.tabId) && payload.tabId >= 0
                && targetUrl
                && typeof payload?.url === 'string'
                && payload.url.includes('/zapCallBackUrl/')
                ? payload.tabId
                : null
            const targetTabResolveStartedAt = Date.now()
            const targetTabId = seededCallbackTabId != null
                ? seededCallbackTabId
                : await this._resolveTargetTabId(payload, targetUrl, 5000)
            this._debugLog('[PTK ZAP] Resolved target tab:', {
                zapid,
                sessionKey,
                targetUrl,
                targetTabId,
                source: seededCallbackTabId != null ? 'seeded_callback_tab' : 'target_navigation'
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
                    result: Number.isInteger(targetTabId) ? 'ok' : 'missing',
                    source: seededCallbackTabId != null ? 'seeded_callback_tab' : 'target_navigation'
                }
            })
            if (!isValidTabId(targetTabId)) {
                this._setPendingStart(Object.assign({}, pendingStart, { targetUrl }))
                this._debugLog('[PTK ZAP] Target URL resolved but tabId is unavailable; waiting for next non-ZAP navigation')
                await this._tryStartFromObservedTarget(Object.assign({}, pendingStart, { targetUrl }))
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

        const inFlight = run().finally(() => {
            this._startInFlightByKey.delete(startKeyBase)
            if (this._startInFlight?.key === startKeyBase) {
                this._startInFlight = null
            }
        })
        this._startInFlightByKey.set(startKeyBase, inFlight)
        this._startInFlight = { key: startKeyBase, promise: inFlight }

        await inFlight
    }

    async _postCallbackHandshakeProgress({ sessionKey = null, zapid = null, source = null, tabId = null, targetUrl = null } = {}) {
        const effectiveZapId = zapid || this.transport.getZapId?.() || null
        const progressUrl = this.transport.getProgressUrl?.({ zapid: effectiveZapId }) || null
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
                zapid: effectiveZapId,
                baseUrl: this.transport.getBaseUrl?.({ zapid: effectiveZapId }) || null,
                progress: 0,
                status: ZAP_PROGRESS_STATUS_CALLBACK,
                message: 'ZAP callback detected; waiting for target navigation',
                engines: {}
            })
            this.recordTiming({
                phase: 'callback.acquired',
                zapid: effectiveZapId,
                browserid: this.transport.getBrowserId?.() || null,
                zapSessionKey: progressKey,
                tabId,
                targetUrl,
                onceKey: 'callback.acquired',
                extra: {
                    source: source || ''
                }
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

        const observedTabId = Number.isInteger(payload?.tabId) ? payload.tabId : null
        const targetUrl = toHttpUrl(payload?.url)
        if (!targetUrl) return
        if (!this._isTopLevelTargetObservation(payload)) return

        const pendingStarts = this._pendingStartsByKey.size
            ? Array.from(this._pendingStartsByKey.entries())
            : (this._pendingStart ? [[this._pendingStartKey(this._pendingStart) || 'legacy', this._pendingStart]] : [])
        if (!pendingStarts.length) return

        for (const [pendingKey, pending] of pendingStarts) {
            if (!pending) continue
            if (Number.isInteger(pending.tabId) && observedTabId !== pending.tabId) {
                continue
            }

            const resolvedTabId = Number.isInteger(pending.tabId) ? pending.tabId : observedTabId
            if (!Number.isInteger(resolvedTabId) || resolvedTabId < 0) {
                this._debugLog('[PTK ZAP] Pending auto-start observed a target URL without a usable tabId; waiting for next navigation')
                continue
            }
            if (!this._isPendingStartTargetUrlAllowed(pending, targetUrl)) {
                this._debugLog('[PTK ZAP] Pending auto-start rejected out-of-scope target URL:', {
                    zapid: pending.zapid || null,
                    sessionKey: pending.sessionKey || null,
                    tabId: resolvedTabId,
                    targetUrl,
                    scopeTargetUrl: this._resolvePendingStartScopeTargetUrl(pending)
                })
                continue
            }
            const startTargetUrl = this._resolvePendingStartScopeTargetUrl(pending) || targetUrl

            const run = async () => {
                await this._startZapSession({
                    tabId: resolvedTabId,
                    targetUrl: startTargetUrl,
                    engines: pending.engines,
                    engineConfigs: pending.engineConfigs,
                    baseUrl: pending.baseUrl,
                    sessionKey: pending.sessionKey,
                    zapid: pending.zapid
                })
            }

            const inFlightKey = `pending|${pending.sessionKey || pending.baseUrl || pendingKey || ''}|${resolvedTabId}|${startTargetUrl}`
            if (this._startInFlightByKey.has(inFlightKey)) {
                continue
            }

            const inFlight = run().finally(() => {
                this._startInFlightByKey.delete(inFlightKey)
                if (this._startInFlight?.key === inFlightKey) {
                    this._startInFlight = null
                }
            })
            this._startInFlightByKey.set(inFlightKey, inFlight)
            this._startInFlight = { key: inFlightKey, promise: inFlight }
        }
    }

    async _startZapSession({ tabId, targetUrl, engines, engineConfigs, baseUrl, sessionKey = null, zapid = null }) {
        const automation = this.app?.automation
        if (!automation || typeof automation.startZapConfiguredSession !== 'function') {
            console.warn('[PTK ZAP] Automation module unavailable for ZAP-managed session start')
            return
        }

        const safeTabId = Number.isInteger(tabId) ? tabId : null
        if (safeTabId === null || safeTabId < 0 || !targetUrl) {
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
        const detectedPayload = this.transport.getLastDetectedPayload?.() || {}
        const callbackDetectedAt = Number.isFinite(Number(detectedPayload?.detectedAt))
            ? Number(detectedPayload.detectedAt)
            : null
        let effectiveEngineConfigs = engineConfigs
        let seedSourceEngineConfigs = engineConfigs || {}
        if ((safeEngines.includes('DAST') || safeEngines.includes('SAST')) && targetUrl) {
            const targetScopedSeedConfigs = await this._fetchTargetScopedSeedConfigs({
                targetUrl,
                zapid: effectiveZapId,
                sessionKey: effectiveSessionKey,
                baseUrl
            })
            if (targetScopedSeedConfigs) {
                seedSourceEngineConfigs = this._mergeEngineConfigs(seedSourceEngineConfigs, targetScopedSeedConfigs)
                effectiveEngineConfigs = seedSourceEngineConfigs
            }
        }
        if (safeEngines.includes('DAST') || safeEngines.includes('SAST')) {
            const configuredSeedUrls = normalizeHttpUrlList([
                ...(Array.isArray(seedSourceEngineConfigs?.DAST?.zapHistorySeedUrls) ? seedSourceEngineConfigs.DAST.zapHistorySeedUrls : []),
                ...(Array.isArray(seedSourceEngineConfigs?.SAST?.zapHistorySeedUrls) ? seedSourceEngineConfigs.SAST.zapHistorySeedUrls : []),
                ...(Array.isArray(seedSourceEngineConfigs?.SAST?.zapPageSourceUrls) ? seedSourceEngineConfigs.SAST.zapPageSourceUrls : [])
            ])
            const seedUrls = []
            const seenSeedUrls = new Set()
            const appendSeedUrl = (rawSeedUrl) => {
                const seedUrl = toHttpUrl(rawSeedUrl)
                if (!seedUrl || seenSeedUrls.has(seedUrl)) return
                if (seedUrls.length >= DAST_HISTORY_SEED_MAX_RESULTS) return
                seedUrls.push(seedUrl)
                seenSeedUrls.add(seedUrl)
            }
            const currentTargetSeedUrl = toHttpUrl(targetUrl)
            appendSeedUrl(currentTargetSeedUrl)
            for (const rawSeedUrl of configuredSeedUrls) {
                appendSeedUrl(rawSeedUrl)
                if (seedUrls.length >= DAST_HISTORY_SEED_MAX_RESULTS) break
            }
            const targetSeedAdded = currentTargetSeedUrl && !configuredSeedUrls.includes(currentTargetSeedUrl)
            const configuredSeedDroppedByCap = Math.max(0, configuredSeedUrls.length - configuredSeedUrls.filter(seedUrl => seenSeedUrls.has(seedUrl)).length)
            effectiveEngineConfigs = Object.assign({}, seedSourceEngineConfigs || {})
            const seedConfig = {
                zapCallbackDetectedAt: callbackDetectedAt,
                zapHistorySeedUrls: seedUrls,
                zapHistorySeedCount: seedUrls.length,
                zapHistorySeedTotalAvailable: configuredSeedUrls.length + (targetSeedAdded ? 1 : 0),
                zapHistorySeedDroppedByCap: configuredSeedDroppedByCap,
                zapCurrentTargetSeeded: Boolean(currentTargetSeedUrl)
            }
            if (safeEngines.includes('DAST')) {
                effectiveEngineConfigs.DAST = Object.assign({}, effectiveEngineConfigs.DAST || {}, seedConfig)
            }
            if (safeEngines.includes('SAST')) {
                effectiveEngineConfigs.SAST = Object.assign({}, effectiveEngineConfigs.SAST || {}, seedConfig, {
                    zapPageSourceUrls: seedUrls,
                    sastPageSourceMaxPages: seedUrls.length
                })
            }
        }
        const startKeyBase = `${effectiveSessionKey || baseUrl || ''}|${safeTabId}`
        const startKey = `${startKeyBase}|${targetUrl}|${safeEngines.join(',')}`
        const previousStart = this._lastStartsByKey.get(startKey)
        if (previousStart || startKey === this._lastStartKey) {
            this._clearPendingStart(effectiveSessionKey)
            this._debugLog('[PTK ZAP] Duplicate ZAP-driven automation start suppressed:', {
                zapid: effectiveZapId,
                sessionKey: effectiveSessionKey,
                tabId: safeTabId,
                targetUrl,
                engines: safeEngines,
                sessionId: previousStart?.sessionId || this._lastStartSessionId || null
            })
            const previousSessionId = previousStart?.sessionId || this._lastStartSessionId
            if (previousSessionId) {
                this._startProgressMonitor({
                    sessionKey: effectiveSessionKey,
                    sessionId: previousSessionId,
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
            engineConfigs: effectiveEngineConfigs,
            zapSessionKey: effectiveSessionKey || baseUrl || null
        }).catch((err) => {
            console.warn('[PTK ZAP] Failed to start ZAP-driven automation session:', err?.message || String(err))
            return { status: 'error', error: err?.message || String(err), message: err?.message || String(err) }
        })

        this._debugLog('[PTK ZAP] ZAP-driven automation result:', startResult)

        const status = startResult?.status
        if (status === 'starting' || status === 'started' || status === 'already_running') {
            this._lastStartKey = startKey
            this._lastStartSessionId = startResult?.sessionId || this._lastStartSessionId
            this._lastStartsByKey.set(startKey, {
                sessionId: startResult?.sessionId || this._lastStartSessionId || null,
                startedAt: Date.now()
            })
            this._clearPendingStart(effectiveSessionKey)
            this._startProgressMonitor({
                sessionKey: effectiveSessionKey,
                sessionId: startResult?.sessionId || this._lastStartSessionId || null,
                zapid: effectiveZapId,
                requiredEngines: startResult?.requiredEngines || safeEngines
            })
            return
        }

        this._clearPendingStart(effectiveSessionKey)
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

    _mergeEngineConfigs(baseConfigs = {}, overlayConfigs = {}) {
        const merged = Object.assign({}, baseConfigs || {})
        for (const [engineName, overlay] of Object.entries(overlayConfigs || {})) {
            if (!overlay || typeof overlay !== 'object' || Array.isArray(overlay)) continue
            merged[engineName] = Object.assign({}, merged[engineName] || {}, overlay)
        }
        return merged
    }

    _extractTargetScopedSeedConfigs(rawConfig) {
        const parsed = this._parseConfig(rawConfig)
        const result = {}
        for (const engine of ['DAST', 'SAST']) {
            const config = parsed.engineConfigs?.[engine]
            if (!Array.isArray(config?.zapHistorySeedUrls) || !config.zapHistorySeedUrls.length) {
                continue
            }
            result[engine] = {
                zapHistorySeedUrls: config.zapHistorySeedUrls,
                zapHistorySeedCount: config.zapHistorySeedCount,
                zapHistorySeedScope: config.zapHistorySeedScope || null
            }
            if (engine === 'SAST') {
                result[engine].zapPageSourceUrls = Array.isArray(config.zapPageSourceUrls)
                    ? config.zapPageSourceUrls
                    : config.zapHistorySeedUrls
                if (Number.isFinite(Number(config.sastPageSourceMaxPages))) {
                    result[engine].sastPageSourceMaxPages = Number(config.sastPageSourceMaxPages)
                }
            }
        }
        return Object.keys(result).length ? result : null
    }

    _collectConfigSeedUrls(engineConfigs = {}) {
        const seeds = []
        const seen = new Set()
        for (const config of Object.values(engineConfigs || {})) {
            for (const url of normalizeHttpUrlList(config?.zapHistorySeedUrls)) {
                if (seen.has(url)) continue
                seen.add(url)
                seeds.push(url)
            }
        }
        return seeds
    }

    async _fetchTargetScopedSeedConfigs({ targetUrl, zapid = null, sessionKey = null, baseUrl = null } = {}) {
        if (!targetUrl || !this.transport || typeof this.transport.fetchConfig !== 'function') {
            return null
        }
        const startedAt = Date.now()
        try {
            this.recordTiming({
                phase: 'config.fetch.target_scoped.start',
                zapid,
                browserid: this.transport.getBrowserId?.() || null,
                zapSessionKey: sessionKey,
                targetUrl
            })
            const rawConfig = await this.transport.fetchConfig({
                zapid,
                baseUrl,
                targetUrl
            })
            const seedConfigs = this._extractTargetScopedSeedConfigs(rawConfig)
            this.recordTiming({
                phase: 'config.fetch.target_scoped.end',
                zapid,
                browserid: this.transport.getBrowserId?.() || null,
                zapSessionKey: sessionKey,
                targetUrl,
                extra: {
                    durationMs: Date.now() - startedAt,
                    seedCount: Array.isArray(seedConfigs?.DAST?.zapHistorySeedUrls)
                        ? seedConfigs.DAST.zapHistorySeedUrls.length
                        : 0
                }
            })
            return seedConfigs
        } catch (err) {
            console.warn('[PTK ZAP] Target-scoped config seed refresh failed:', {
                zapid,
                sessionKey,
                targetUrl,
                error: err?.message || String(err)
            })
            this.recordTiming({
                phase: 'config.fetch.target_scoped.error',
                zapid,
                browserid: this.transport.getBrowserId?.() || null,
                zapSessionKey: sessionKey,
                targetUrl,
                extra: {
                    durationMs: Date.now() - startedAt,
                    error: err?.message || String(err)
                }
            })
            return null
        }
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

        const zapHistorySeedUrls = normalizeHttpUrlList(config.zapHistorySeedUrls)
        if (zapHistorySeedUrls.length) {
            const seedConfig = {
                zapHistorySeedUrls,
                zapHistorySeedCount: Number.isFinite(Number(config.zapHistorySeedCount))
                    ? Number(config.zapHistorySeedCount)
                    : zapHistorySeedUrls.length,
                zapHistorySeedScope: typeof config.zapHistorySeedScope === 'string'
                    ? config.zapHistorySeedScope
                    : null
            }
            for (const engine of ['DAST', 'SAST']) {
                result.engineConfigs[engine] = Object.assign({}, result.engineConfigs[engine] || {}, seedConfig)
            }
            result.engineConfigs.SAST.zapPageSourceUrls = zapHistorySeedUrls
            result.engineConfigs.SAST.sastPageSourceMaxPages = zapHistorySeedUrls.length
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

    _getManagedScanContext(engine, scanId) {
        const automation = this.app?.automation
        if (!automation || typeof automation.getZapManagedScanContexts !== 'function') {
            return null
        }
        const scanIdText = toNonEmptyString(scanId)
        if (!scanIdText) return null
        const contexts = automation.getZapManagedScanContexts({
            engine,
            host: this.getActiveTargetHost()
        })
        return contexts.find(entry => String(entry?.scanId || '') === scanIdText) || null
    }

    _zapIdFromSessionKey(sessionKey = null) {
        const text = toNonEmptyString(sessionKey)
        if (!text) return null
        const index = text.lastIndexOf('|')
        if (index < 0) return null
        return toNonEmptyString(text.slice(index + 1))
    }

    _attachZapEnvelopeContext(envelope, { engine = null, scanId = null } = {}) {
        if (!envelope || typeof envelope !== 'object') return envelope
        const context = this._getManagedScanContext(engine, scanId)
        const sessionId = context?.sessionId || this._progressMonitor?.sessionId || this._lastStartSessionId || null
        const zapSessionKey = context?.zapSessionKey || null
        const zapid = this._zapIdFromSessionKey(zapSessionKey) || this.transport.getZapId?.() || null
        if (zapid && !envelope.zapid) {
            envelope.zapid = zapid
        }
        if (zapSessionKey && !envelope.zapSessionKey) {
            envelope.zapSessionKey = zapSessionKey
        }
        envelope.payload = Object.assign({}, envelope.payload || {}, {
            sessionId: envelope.payload?.sessionId || sessionId,
            zapSessionKey: envelope.payload?.zapSessionKey || zapSessionKey || undefined
        })
        return envelope
    }

    async _resolveTargetUrl(payload = {}, maxWaitMs = 120000) {
        const seedResolved = this._resolveTargetUrlFromConfigSeeds(payload)
        const isAllowedBySeed = (candidateUrl) => {
            const normalized = toHttpUrl(candidateUrl)
            if (!normalized) return false
            if (!seedResolved) return true
            return normalized === seedResolved || isSameOriginAndPathScoped(seedResolved, normalized)
        }
        const fromPayload = toHttpUrl(payload.targetUrl) || toHttpUrl(payload.pageUrl) || toHttpUrl(payload.url)
        if (fromPayload && isAllowedBySeed(fromPayload)) return fromPayload
        if (seedResolved) return seedResolved
        const resolveFromLatestDetection = () => {
            const latest = this.transport.getLastDetectedPayload?.()
            if (!latest) return null
            const expectedBaseUrl = toNonEmptyString(payload.baseUrl || this.transport.getBaseUrl?.())
            const latestBaseUrl = toNonEmptyString(latest.baseUrl)
            if (expectedBaseUrl && latestBaseUrl && expectedBaseUrl !== latestBaseUrl) {
                return null
            }
            const expectedZapId = toNonEmptyString(payload.zapid || this.transport.getZapId?.())
            const latestZapId = toNonEmptyString(latest.zapid)
            if (expectedZapId && latestZapId && expectedZapId !== latestZapId) {
                return null
            }
            const candidate = toHttpUrl(latest.targetUrl) || toHttpUrl(latest.pageUrl)
            return isAllowedBySeed(candidate) ? candidate : null
        }
        const fromLatestDetection = resolveFromLatestDetection()
        if (fromLatestDetection) return fromLatestDetection

        const tabId = Number.isInteger(payload.tabId) ? payload.tabId : null
        if (tabId == null || !browser?.tabs?.get) {
            return null
        }

        const waitMs = Number.isFinite(Number(maxWaitMs)) ? Math.max(0, Number(maxWaitMs)) : 120000
        const resolveFromTab = async () => {
            try {
                const tab = await browser.tabs.get(tabId)
                const resolved = toHttpUrl(tab?.url) || toHttpUrl(tab?.pendingUrl)
                if (resolved && isAllowedBySeed(resolved)) return resolved
            } catch (_) {
                return null
            }
            return null
        }

        const observed = this._getFreshObservedTargetForPending({ tabId })
        if (observed?.targetUrl) return observed.targetUrl

        const immediate = await resolveFromTab()
        if (immediate) return immediate

        if (waitMs <= 0) return null

        const deadline = Date.now() + waitMs
        while (Date.now() < deadline) {
            await sleep(500)
            const nextFromLatestDetection = resolveFromLatestDetection()
            if (nextFromLatestDetection) return nextFromLatestDetection
            const nextObserved = this._getFreshObservedTargetForPending({ tabId })
            if (nextObserved?.targetUrl) return nextObserved.targetUrl
            const resolved = await resolveFromTab()
            if (resolved) return resolved
        }

        return null
    }

    _resolveTargetUrlFromConfigSeeds(payload = {}) {
        const candidates = normalizeHttpUrlList(payload?.zapHistorySeedUrls)
        if (!candidates.length) return null
        const targetUrl = this._selectPostCallbackTargetUrl(candidates)
        if (targetUrl) {
            this._debugLog('[PTK ZAP] Resolved target URL from ZAP config seed URLs:', {
                targetUrl,
                candidates: candidates.length
            })
        }
        return targetUrl
    }

    _selectPostCallbackTargetUrl(candidates = []) {
        if (!Array.isArray(candidates) || !candidates.length) return null
        const parsed = []
        for (let index = 0; index < candidates.length; index += 1) {
            const url = toHttpUrl(candidates[index])
            if (!url) continue
            try {
                const parsedUrl = new URL(url)
                parsed.push({
                    url,
                    index,
                    origin: parsedUrl.origin,
                    pathname: parsedUrl.pathname || '/',
                    search: parsedUrl.search || ''
                })
            } catch (_) {
                // Ignore malformed seed records.
            }
        }
        if (!parsed.length) return null

        const originCounts = new Map()
        for (const entry of parsed) {
            originCounts.set(entry.origin, (originCounts.get(entry.origin) || 0) + 1)
        }

        let dominantOrigin = parsed[0].origin
        let dominantCount = 0
        for (const [origin, count] of originCounts.entries()) {
            if (count > dominantCount) {
                dominantOrigin = origin
                dominantCount = count
            }
        }

        const sameOrigin = parsed.filter((entry) => entry.origin === dominantOrigin)
        if (sameOrigin.length <= 1) {
            return parsed[0].url
        }

        const score = (entry) => {
            const path = entry.pathname || '/'
            const segmentCount = path.split('/').filter(Boolean).length
            const hasQuery = entry.search ? 1 : 0
            const indexLike = /(?:^|\/)(?:index\.[a-z0-9]+)?$/i.test(path) ? 0 : 1
            return [
                indexLike,
                segmentCount,
                hasQuery,
                path.length + entry.search.length,
                entry.index
            ]
        }
        return sameOrigin
            .slice()
            .sort((left, right) => {
                const leftScore = score(left)
                const rightScore = score(right)
                for (let i = 0; i < leftScore.length; i += 1) {
                    if (leftScore[i] !== rightScore[i]) return leftScore[i] - rightScore[i]
                }
                return 0
            })[0]?.url || parsed[0].url
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
        if (!this._isPendingStartTargetUrlAllowed(pending, observed.targetUrl)) {
            return null
        }

        return observed
    }

    async _tryStartFromObservedTarget(pending = {}) {
        const observed = this._getFreshObservedTargetForPending(pending)
        if (!observed) {
            return false
        }

        this._debugLog('[PTK ZAP] Using cached target navigation for auto mode', {
            tabId: observed.tabId,
            targetUrl: observed.targetUrl,
            source: observed.source
        })
        const targetUrl = this._resolvePendingStartScopeTargetUrl(pending) || observed.targetUrl

        await this._startZapSession({
            tabId: observed.tabId,
            targetUrl,
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
        if (isValidTabId(tabId) && browser?.tabs?.get) {
            try {
                const tab = await browser.tabs.get(tabId)
                const tabUrl = toHttpUrl(tab?.url) || toHttpUrl(tab?.pendingUrl)
                if (tabUrl === targetUrl || isSameOriginAndPathScoped(targetUrl, tabUrl)) {
                    return tabId
                }
            } catch (_) {
                // Fall through to observed/exact tab lookup.
            }
        }

        const observed = this._lastTopLevelTargetObservation
        if (
            observed
            && isValidTabId(observed.tabId)
            && (observed.targetUrl === targetUrl || isSameOriginAndPathScoped(targetUrl, observed.targetUrl))
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
                    if (!isValidTabId(tab?.id)) return false
                    return toHttpUrl(tab?.url) === targetUrl
                })
                if (isValidTabId(exactMatch?.id)) {
                    return exactMatch.id
                }
                const scopedMatch = tabs.find(tab => {
                    if (!isValidTabId(tab?.id)) return false
                    const tabUrl = toHttpUrl(tab?.url) || toHttpUrl(tab?.pendingUrl)
                    return isSameOriginAndPathScoped(targetUrl, tabUrl)
                })
                if (isValidTabId(scopedMatch?.id)) {
                    return scopedMatch.id
                }
                let targetOrigin = null
                try {
                    targetOrigin = new URL(targetUrl).origin
                } catch (_) {
                    targetOrigin = null
                }
                if (targetOrigin) {
                    const sameOriginMatches = tabs
                        .filter(tab => isValidTabId(tab?.id))
                        .map(tab => {
                            const tabUrl = toHttpUrl(tab?.url) || toHttpUrl(tab?.pendingUrl)
                            if (!tabUrl) return null
                            try {
                                if (new URL(tabUrl).origin !== targetOrigin) return null
                            } catch (_) {
                                return null
                            }
                            return {
                                id: tab.id,
                                active: tab.active === true,
                                lastAccessed: Number(tab.lastAccessed || 0)
                            }
                        })
                        .filter(Boolean)
                        .sort((left, right) => {
                            if (left.active !== right.active) return left.active ? -1 : 1
                            return right.lastAccessed - left.lastAccessed
                        })
                    if (isValidTabId(sameOriginMatches[0]?.id)) {
                        return sameOriginMatches[0].id
                    }
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
