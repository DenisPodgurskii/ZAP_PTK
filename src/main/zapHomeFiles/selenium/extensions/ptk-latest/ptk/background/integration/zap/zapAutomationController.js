'use strict'

const ZAP_MODE_AUTO = 'auto'
const ZAP_MODE_MANUAL = 'manual'
const ZAP_PROGRESS_STATUS_CALLBACK = 'callback'
const ZAP_PROGRESS_STATUS_COMPLETED = 'completed'
const ZAP_PROGRESS_STATUS_ERROR = 'error'

export const ZAP_AUTOMATION_STATES = Object.freeze({
    IDLE: 'idle',
    CALLBACK_OBSERVED: 'callback_observed',
    CONFIG_FETCHING: 'config_fetching',
    CONFIG_READY: 'config_ready',
    TARGET_WAITING: 'target_waiting',
    TARGET_READY: 'target_ready',
    SESSION_STARTING: 'session_starting',
    SESSION_RUNNING: 'session_running',
    TERMINAL_PROGRESS: 'terminal_progress',
    FAILED: 'failed'
})

function toNonEmptyString(value) {
    if (typeof value !== 'string') return null
    const trimmed = value.trim()
    return trimmed || null
}

function toHttpUrl(value) {
    if (typeof value !== 'string' || !value.trim()) return null
    try {
        const url = new URL(value)
        const host = String(url.hostname || '').toLowerCase()
        if ((url.protocol === 'http:' || url.protocol === 'https:') && host !== 'zap') {
            return url.toString()
        }
    } catch (_) {
        return null
    }
    return null
}

function isValidTabId(value) {
    return Number.isInteger(value) && value >= 0
}

function createRunId() {
    if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
        return globalThis.crypto.randomUUID()
    }
    return `zap-run-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`
}

export class ZapAutomationController {
    constructor({ bridge = null, transport = null, targetUrlWaitMs = 120000, targetTabWaitMs = 5000 } = {}) {
        this.bridge = bridge
        this.transport = transport
        this.targetUrlWaitMs = targetUrlWaitMs
        this.targetTabWaitMs = targetTabWaitMs
        this.runsByKey = new Map()
        this.inFlightByKey = new Map()
    }

    setDependencies({ bridge = this.bridge, transport = this.transport } = {}) {
        this.bridge = bridge
        this.transport = transport
    }

    getRun(key) {
        return this.runsByKey.get(key) || null
    }

    getRuns() {
        return Array.from(this.runsByKey.values())
    }

    _buildSessionKey(baseUrl, zapid) {
        if (typeof this.bridge?._buildZapSessionKey === 'function') {
            return this.bridge._buildZapSessionKey(baseUrl, zapid)
        }
        if (!baseUrl) return null
        return `${baseUrl}|${zapid || ''}`
    }

    _buildRunContext(payload = {}) {
        const baseUrl = toNonEmptyString(payload.baseUrl) || this.transport?.getBaseUrl?.() || null
        const zapid = toNonEmptyString(payload.zapid) || this.transport?.getZapId?.() || null
        const browserid = toNonEmptyString(payload.browserid) || this.transport?.getBrowserId?.() || null
        const sessionKey = this._buildSessionKey(baseUrl, zapid)
        const tabId = isValidTabId(payload.tabId) ? payload.tabId : null
        const runKey = sessionKey || zapid || baseUrl || (tabId != null ? `tab:${tabId}` : createRunId())
        return { baseUrl, zapid, browserid, sessionKey, tabId, runKey }
    }

    _getOrCreateRun(context) {
        let run = this.runsByKey.get(context.runKey)
        if (!run) {
            run = {
                runId: createRunId(),
                runKey: context.runKey,
                state: ZAP_AUTOMATION_STATES.IDLE,
                zapid: context.zapid || null,
                baseUrl: context.baseUrl || null,
                sessionKey: context.sessionKey || null,
                browserid: context.browserid || null,
                callbackTabId: context.tabId,
                targetTabId: null,
                targetUrl: null,
                engines: [],
                engineConfigs: {},
                startAttempts: 0,
                lastError: null,
                terminalReason: null,
                transitions: []
            }
            this.runsByKey.set(context.runKey, run)
        }

        run.zapid = context.zapid || run.zapid || null
        run.baseUrl = context.baseUrl || run.baseUrl || null
        run.sessionKey = context.sessionKey || run.sessionKey || null
        run.browserid = context.browserid || run.browserid || null
        run.callbackTabId = context.tabId ?? run.callbackTabId ?? null
        return run
    }

    _transition(run, state, extra = {}) {
        run.state = state
        if (extra?.targetUrl) run.targetUrl = extra.targetUrl
        if (isValidTabId(extra?.targetTabId)) run.targetTabId = extra.targetTabId
        if (extra?.engines) run.engines = Array.isArray(extra.engines) ? extra.engines.slice() : []
        if (extra?.engineConfigs) run.engineConfigs = extra.engineConfigs
        if (extra?.error) run.lastError = String(extra.error)
        if (extra?.reason) run.terminalReason = String(extra.reason)
        run.transitions.push({
            state,
            ts: Date.now(),
            reason: extra?.reason || null
        })
        this.bridge?._debugLog?.('[PTK ZAP] Controller state:', {
            runId: run.runId,
            state,
            zapid: run.zapid,
            sessionKey: run.sessionKey,
            tabId: isValidTabId(extra?.targetTabId) ? extra.targetTabId : run.callbackTabId,
            targetUrl: extra?.targetUrl || run.targetUrl || null,
            reason: extra?.reason || null
        })
    }

    async handleZapDetected(payload = {}) {
        const context = this._buildRunContext(payload)
        const run = this._getOrCreateRun(context)
        this._transition(run, ZAP_AUTOMATION_STATES.CALLBACK_OBSERVED, {
            targetUrl: toHttpUrl(payload.targetUrl) || null,
            reason: payload.source || 'zap_detected'
        })

        this._applyBridgeSessionContext(payload, context, run)

        const inFlight = this.inFlightByKey.get(context.runKey)
        if (inFlight) {
            return inFlight
        }

        const automation = this.bridge?.app?.automation
        if (!automation || typeof automation.startZapConfiguredSession !== 'function') {
            this._transition(run, ZAP_AUTOMATION_STATES.TARGET_WAITING, {
                reason: 'automation_module_unavailable'
            })
            return run
        }

        const promise = this._driveRun(payload, context, run)
            .finally(() => {
                this.inFlightByKey.delete(context.runKey)
            })
        this.inFlightByKey.set(context.runKey, promise)
        return promise
    }

    _applyBridgeSessionContext(payload, context, run) {
        const bridge = this.bridge
        if (!bridge) return

        const previousBaseUrl = bridge.currentBaseUrl
        const isNewSession = !!context.sessionKey && context.sessionKey !== bridge.currentSessionKey

        bridge.currentBaseUrl = context.baseUrl || bridge.currentBaseUrl
        bridge.currentSessionKey = context.sessionKey || bridge.currentSessionKey

        if (isNewSession) {
            bridge._resolvedConfig = {
                mode: ZAP_MODE_MANUAL,
                engineConfigs: {},
                fetchedAt: null,
                baseUrl: context.baseUrl || null
            }
        }

        bridge.recordTiming?.({
            phase: 'callback.detected',
            zapid: context.zapid,
            browserid: context.browserid,
            zapSessionKey: context.sessionKey,
            tabId: context.tabId,
            targetUrl: payload?.targetUrl || null,
            elapsedMs: 0
        })

        void bridge._postCallbackHandshakeProgress?.({
            sessionKey: context.sessionKey,
            zapid: context.zapid,
            source: payload?.source || null,
            tabId: context.tabId,
            targetUrl: payload?.targetUrl || null
        })

        bridge.start?.()
        if (bridge.publisher && isNewSession && previousBaseUrl && context.baseUrl && previousBaseUrl !== context.baseUrl && !run.publisherReset) {
            bridge.publisher.resetState?.()
            run.publisherReset = true
        }
    }

    async _driveRun(payload, context, run) {
        const bridge = this.bridge
        const configFetchStartedAt = Date.now()
        bridge?.recordTiming?.({
            phase: 'config.fetch.start',
            zapid: context.zapid,
            browserid: context.browserid,
            zapSessionKey: context.sessionKey,
            tabId: context.tabId,
            targetUrl: payload?.targetUrl || null
        })
        this._transition(run, ZAP_AUTOMATION_STATES.CONFIG_FETCHING)

        const rawConfig = await bridge.confirmAndGetConfig({
            zapid: context.zapid,
            baseUrl: context.baseUrl,
            targetUrl: payload?.targetUrl || null
        })

        bridge?.recordTiming?.({
            phase: 'config.fetch.end',
            zapid: context.zapid,
            browserid: context.browserid,
            zapSessionKey: context.sessionKey,
            tabId: context.tabId,
            targetUrl: payload?.targetUrl || null,
            extra: {
                durationMs: Date.now() - configFetchStartedAt
            }
        })

        if (rawConfig?.ptkConfigFetchFailed === true) {
            bridge._clearPendingStart?.(context.sessionKey)
            this._transition(run, ZAP_AUTOMATION_STATES.FAILED, {
                error: rawConfig?.error || 'zap_config_unavailable',
                reason: 'config_fetch_failed'
            })
            bridge._scheduleTerminalProgress?.({
                sessionKey: context.sessionKey,
                zapid: context.zapid,
                requiredEngines: [],
                status: ZAP_PROGRESS_STATUS_ERROR,
                message: 'ZAP automation config fetch failed'
            })
            return run
        }

        const parsedConfig = bridge._parseConfig(rawConfig)
        bridge._resolvedConfig = {
            mode: parsedConfig.mode,
            engineConfigs: parsedConfig.engineConfigs || {},
            fetchedAt: Date.now(),
            baseUrl: context.baseUrl || null
        }
        this._transition(run, ZAP_AUTOMATION_STATES.CONFIG_READY, {
            engineConfigs: parsedConfig.engineConfigs || {}
        })

        if (parsedConfig.mode !== ZAP_MODE_AUTO) {
            bridge._clearPendingStart?.(context.sessionKey)
            this._transition(run, ZAP_AUTOMATION_STATES.FAILED, {
                reason: 'manual_mode'
            })
            return run
        }

        const finalEngines = bridge._getAutoStartEngines(parsedConfig)
        const finalEngineConfigs = bridge._buildAutoStartEngineConfigs(parsedConfig, finalEngines)
        const configSeedUrls = bridge._collectConfigSeedUrls(finalEngineConfigs)
        const configSeedTargetUrl = bridge._selectPostCallbackTargetUrl(configSeedUrls)
        this._transition(run, ZAP_AUTOMATION_STATES.CONFIG_READY, {
            engines: finalEngines,
            engineConfigs: finalEngineConfigs,
            targetUrl: configSeedTargetUrl || null
        })

        if (!finalEngines.length) {
            bridge._clearPendingStart?.(context.sessionKey)
            this._transition(run, ZAP_AUTOMATION_STATES.TERMINAL_PROGRESS, {
                reason: 'no_enabled_engines'
            })
            bridge._scheduleTerminalProgress?.({
                sessionKey: context.sessionKey,
                zapid: context.zapid,
                requiredEngines: [],
                status: ZAP_PROGRESS_STATUS_COMPLETED,
                message: 'No PTK engines are enabled for this ZAP automation session'
            })
            return run
        }

        const pendingStart = {
            tabId: context.tabId,
            baseUrl: context.baseUrl || null,
            sessionKey: context.sessionKey,
            zapid: context.zapid,
            targetUrl: configSeedTargetUrl || toHttpUrl(payload?.targetUrl) || null,
            engines: finalEngines,
            engineConfigs: finalEngineConfigs
        }
        bridge._setPendingStart?.(pendingStart)

        const targetUrlStartedAt = Date.now()
        const targetUrl = await bridge._resolveTargetUrl(Object.assign({}, payload, {
            zapHistorySeedUrls: configSeedUrls
        }), this.targetUrlWaitMs)
        bridge?.recordTiming?.({
            phase: 'target_url.resolved',
            zapid: context.zapid,
            browserid: context.browserid,
            zapSessionKey: context.sessionKey,
            tabId: context.tabId,
            targetUrl,
            extra: {
                durationMs: Date.now() - targetUrlStartedAt,
                source: payload?.source || null,
                result: targetUrl ? 'ok' : 'missing'
            }
        })

        if (!targetUrl) {
            bridge._setPendingStart?.(pendingStart)
            this._transition(run, ZAP_AUTOMATION_STATES.TARGET_WAITING, {
                reason: 'target_url_missing'
            })
            await bridge._tryStartFromObservedTarget?.(pendingStart)
            return run
        }

        const pendingWithTarget = Object.assign({}, pendingStart, { targetUrl })
        this._transition(run, ZAP_AUTOMATION_STATES.TARGET_READY, { targetUrl })

        const targetTabStartedAt = Date.now()
        const targetTabId = await bridge._resolveTargetTabId(payload, targetUrl, this.targetTabWaitMs)
        bridge?.recordTiming?.({
            phase: 'target_tab.resolved',
            zapid: context.zapid,
            browserid: context.browserid,
            zapSessionKey: context.sessionKey,
            tabId: targetTabId,
            targetUrl,
            extra: {
                durationMs: Date.now() - targetTabStartedAt,
                result: isValidTabId(targetTabId) ? 'ok' : 'missing',
                source: 'target_navigation'
            }
        })

        if (!isValidTabId(targetTabId)) {
            bridge._setPendingStart?.(pendingWithTarget)
            this._transition(run, ZAP_AUTOMATION_STATES.TARGET_WAITING, {
                targetUrl,
                reason: 'target_tab_missing'
            })
            await bridge._tryStartFromObservedTarget?.(pendingWithTarget)
            return run
        }

        this._transition(run, ZAP_AUTOMATION_STATES.SESSION_STARTING, {
            targetUrl,
            targetTabId
        })
        run.startAttempts += 1
        await bridge._startZapSession({
            tabId: targetTabId,
            targetUrl,
            engines: finalEngines,
            engineConfigs: finalEngineConfigs,
            baseUrl: context.baseUrl,
            sessionKey: context.sessionKey,
            zapid: context.zapid
        })
        this._transition(run, ZAP_AUTOMATION_STATES.SESSION_RUNNING, {
            targetUrl,
            targetTabId
        })
        return run
    }
}

export default ZapAutomationController
