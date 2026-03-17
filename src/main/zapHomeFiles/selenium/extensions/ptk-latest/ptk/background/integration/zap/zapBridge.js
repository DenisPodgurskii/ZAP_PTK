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
    '[PTK ZAP] Fetching ZAP config...',
    '[PTK ZAP] ZAP config resolved:',
    '[PTK ZAP] Sending alerts batch:',
    '[PTK ZAP] Sending DAST findings batch:',
    '[PTK ZAP] Sending IAST findings batch:',
    '[PTK ZAP] Sending SAST findings batch:'
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

class ZapBridge {
    constructor() {
        this.transport = zapTransport
        this.publisher = null
        this.app = null
        this.resultsRegistry = null
        this.bootstrapped = false
        this.currentBaseUrl = null
        this._unsubscribeDetected = null
        this._unsubscribeUrlObserved = null
        this._startInFlight = null
        this._lastStartKey = null
        this._pendingStart = null
        this._lastTopLevelTargetObservation = null
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
                alertsUrl: this.transport.getAlertsUrl?.()
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
        const isNewBaseUrl = !!baseUrl && baseUrl !== this.currentBaseUrl
        this.currentBaseUrl = baseUrl || this.currentBaseUrl

        const shouldPrimeCallback = isNewBaseUrl || !this._resolvedConfig?.fetchedAt
        if (shouldPrimeCallback && typeof this.transport?.pingCallback === 'function') {
            await this.transport.pingCallback({ reason: 'zap_detected' })
        }

        this._debugLog('[PTK ZAP] ZAP is active, starting publisher')
        this.start()

        if (this.publisher && isNewBaseUrl) {
            this._debugLog('[PTK ZAP] New base URL detected, resetting publisher state')
            this.publisher.resetState()
            this._pendingStart = null
            this._resolvedConfig = {
                mode: ZAP_MODE_MANUAL,
                engineConfigs: {},
                fetchedAt: null,
                baseUrl: baseUrl || null
            }
        }

        const automation = this.app?.automation
        if (!automation || typeof automation.startZapConfiguredSession !== 'function') {
            this._debugLog('[PTK ZAP] Automation module not attached yet; delaying ZAP-managed session start')
            return
        }

        const startKeyBase = `${baseUrl || ''}|${payload.tabId || ''}`
        if (this._startInFlight?.key === startKeyBase) {
            return
        }

        const run = async () => {
            const rawConfig = await this.confirmAndGetConfig({ skipPing: true })
            const parsedConfig = this._parseConfig(rawConfig)
            this._resolvedConfig = {
                mode: parsedConfig.mode,
                engineConfigs: parsedConfig.engineConfigs || {},
                fetchedAt: Date.now(),
                baseUrl: baseUrl || null
            }

            if (parsedConfig.mode !== ZAP_MODE_AUTO) {
                this._pendingStart = null
                this._debugLog('[PTK ZAP] mode is manual; automatic scan start is disabled')
                return
            }
            const finalEngines = DEFAULT_ZAP_ENGINES

            const targetUrl = await this._resolveTargetUrl(payload, 120000)
            if (!targetUrl) {
                this._pendingStart = {
                    tabId: Number.isInteger(payload.tabId) ? payload.tabId : null,
                    baseUrl: baseUrl || null,
                    engines: finalEngines,
                    engineConfigs: parsedConfig.engineConfigs || {}
                }
                this._debugLog('[PTK ZAP] Target URL not available yet; waiting for next non-ZAP navigation')
                await this._tryStartFromObservedTarget(this._pendingStart)
                return
            }

            const targetTabId = await this._resolveTargetTabId(payload, targetUrl, 5000)
            if (!targetTabId) {
                this._pendingStart = {
                    tabId: null,
                    baseUrl: baseUrl || null,
                    engines: finalEngines,
                    engineConfigs: parsedConfig.engineConfigs || {}
                }
                this._debugLog('[PTK ZAP] Target URL resolved but tabId is unavailable; waiting for next non-ZAP navigation')
                await this._tryStartFromObservedTarget(this._pendingStart)
                return
            }

            await this._startZapSession({
                tabId: targetTabId,
                targetUrl,
                engines: finalEngines,
                engineConfigs: parsedConfig.engineConfigs,
                baseUrl
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
                baseUrl: pending.baseUrl
            })
        }

        const inFlightKey = `pending|${pending.baseUrl || ''}|${resolvedTabId}`
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

    async _startZapSession({ tabId, targetUrl, engines, engineConfigs, baseUrl }) {
        const automation = this.app?.automation
        if (!automation || typeof automation.startZapConfiguredSession !== 'function') {
            console.warn('[PTK ZAP] Automation module unavailable for ZAP-managed session start')
            return
        }

        const safeTabId = Number.isInteger(tabId) ? tabId : null
        if (!safeTabId || !targetUrl) return

        const safeEngines = Array.isArray(engines) && engines.length ? engines : DEFAULT_ZAP_ENGINES
        const startKeyBase = `${baseUrl || ''}|${safeTabId}`
        const startKey = `${startKeyBase}|${targetUrl}|${safeEngines.join(',')}`
        if (startKey === this._lastStartKey) {
            this._pendingStart = null
            return
        }

        const startResult = await automation.startZapConfiguredSession({
            tabId: safeTabId,
            targetUrl,
            pageUrl: targetUrl,
            engines: safeEngines,
            engineConfigs,
            zapSessionKey: baseUrl || null
        }).catch((err) => {
            console.warn('[PTK ZAP] Failed to start ZAP-driven automation session:', err?.message || String(err))
            return { status: 'error', error: err?.message || String(err) }
        })

        this._debugLog('[PTK ZAP] ZAP-driven automation result:', startResult)

        const status = startResult?.status
        if (status === 'started' || status === 'already_running') {
            this._lastStartKey = startKey
            this._pendingStart = null
            return
        }

        if (status === 'busy') {
            this._pendingStart = null
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

    async _resolveTargetUrl(payload = {}, maxWaitMs = 120000) {
        const fromPayload = toHttpUrl(payload.targetUrl) || toHttpUrl(payload.pageUrl) || toHttpUrl(payload.url)
        if (fromPayload) return fromPayload

        const tabId = Number.isInteger(payload.tabId) ? payload.tabId : null
        if (tabId == null || !browser?.tabs?.get) return null

        const waitMs = Number.isFinite(Number(maxWaitMs)) ? Math.max(0, Number(maxWaitMs)) : 120000
        const deadline = Date.now() + waitMs
        while (Date.now() < deadline) {
            try {
                const tab = await browser.tabs.get(tabId)
                const resolved = toHttpUrl(tab?.url)
                if (resolved) return resolved
            } catch (_) {
                // Ignore and retry until timeout.
            }
            await sleep(500)
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
            baseUrl: pending.baseUrl
        })

        return true
    }

    async _resolveTargetTabId(payload = {}, targetUrl = '', maxWaitMs = 5000) {
        const tabId = Number.isInteger(payload?.tabId) ? payload.tabId : null
        if (Number.isInteger(tabId) && tabId > 0) return tabId

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
        const deadline = Date.now() + waitMs
        while (Date.now() < deadline) {
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
                // Ignore and retry until timeout.
            }
            await sleep(300)
        }

        return null
    }
}

const zapBridge = new ZapBridge()

export default zapBridge
