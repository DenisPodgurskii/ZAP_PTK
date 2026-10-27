'use strict'

const ZAP_MODE_AUTO = 'auto'
const ZAP_MODE_MANUAL = 'manual'
const ZAP_PROGRESS_STATUS_CALLBACK = 'callback'
const ZAP_PROGRESS_STATUS_COMPLETED = 'completed'
const ZAP_PROGRESS_STATUS_ERROR = 'error'
const ZAP_BOOTSTRAP_RECOVERY_STORAGE_KEY = 'ptk.zap.bootstrapRecovery.v1'
const ZAP_BOOTSTRAP_RECOVERY_ALARM_PREFIX = 'ptk-zap-bootstrap-retry:'
const ZAP_BOOTSTRAP_RECOVERY_VERSION = 1
const ZAP_BOOTSTRAP_RECOVERY_MAX_AGE_MS = 2 * 60 * 1000
const ZAP_BOOTSTRAP_RECOVERY_DELAYS_MS = [1000, 2500, 5000, 10000, 15000, 30000]
const ZAP_TRANSIENT_CONFIG_ERRORS = new Set(['zap_config_unavailable'])

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

function sanitizeIdentifier(value, maxLength = 256) {
    const text = toNonEmptyString(value)
    if (!text || text.length > maxLength || !/^[A-Za-z0-9_.:-]+$/.test(text)) return null
    return text
}

function sanitizeConfigDiagnostics(diagnostics = []) {
    if (!Array.isArray(diagnostics)) return []
    return diagnostics.slice(-12).map((entry) => {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
        const sanitized = {}
        for (const key of ['attempt', 'status']) {
            if (Number.isFinite(Number(entry[key]))) sanitized[key] = Number(entry[key])
        }
        for (const key of ['kind', 'errorName']) {
            const value = sanitizeIdentifier(entry[key], 96)
            if (value) sanitized[key] = value
        }
        return Object.keys(sanitized).length ? sanitized : null
    }).filter(Boolean)
}

function recoveryAlarmName(zapid) {
    return `${ZAP_BOOTSTRAP_RECOVERY_ALARM_PREFIX}${encodeURIComponent(zapid)}`
}

function zapidFromRecoveryAlarm(name) {
    if (typeof name !== 'string' || !name.startsWith(ZAP_BOOTSTRAP_RECOVERY_ALARM_PREFIX)) return null
    try {
        return sanitizeIdentifier(decodeURIComponent(name.slice(ZAP_BOOTSTRAP_RECOVERY_ALARM_PREFIX.length)))
    } catch (_) {
        return null
    }
}

export class ZapAutomationController {
    constructor({
        bridge = null,
        transport = null,
        targetUrlWaitMs = 120000,
        targetTabWaitMs = 5000,
        recoveryStorage = globalThis.browser?.storage?.session || null,
        recoveryAlarms = globalThis.browser?.alarms || null,
        recoveryMaxAgeMs = ZAP_BOOTSTRAP_RECOVERY_MAX_AGE_MS,
        recoveryDelaysMs = ZAP_BOOTSTRAP_RECOVERY_DELAYS_MS,
        now = () => Date.now()
    } = {}) {
        this.bridge = bridge
        this.transport = transport
        this.targetUrlWaitMs = targetUrlWaitMs
        this.targetTabWaitMs = targetTabWaitMs
        this.runsByKey = new Map()
        this.inFlightByKey = new Map()
        this.recoveryStorage = recoveryStorage
        this.recoveryAlarms = recoveryAlarms
        this.recoveryMaxAgeMs = Math.max(1000, Number(recoveryMaxAgeMs) || ZAP_BOOTSTRAP_RECOVERY_MAX_AGE_MS)
        this.recoveryDelaysMs = Array.isArray(recoveryDelaysMs) && recoveryDelaysMs.length
            ? recoveryDelaysMs.map(value => Math.max(0, Number(value) || 0))
            : ZAP_BOOTSTRAP_RECOVERY_DELAYS_MS.slice()
        this.now = typeof now === 'function' ? now : () => Date.now()
        this._recoveryAlarmRegistered = false
        this._recoveryAlarmHandler = null
        this._recoveryStorageMutation = Promise.resolve()
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

    start() {
        this._registerRecoveryAlarmListener()
        return this._rearmPersistedRecoveries()
    }

    dispose() {
        if (this._recoveryAlarmRegistered && this._recoveryAlarmHandler && this.recoveryAlarms?.onAlarm?.removeListener) {
            try {
                this.recoveryAlarms.onAlarm.removeListener(this._recoveryAlarmHandler)
            } catch (_) {
                // The MV3 worker may already be tearing down.
            }
        }
        this._recoveryAlarmRegistered = false
        this._recoveryAlarmHandler = null
    }

    _registerRecoveryAlarmListener() {
        if (this._recoveryAlarmRegistered || !this.recoveryAlarms?.onAlarm?.addListener) return this._recoveryAlarmRegistered
        this._recoveryAlarmHandler = (alarm = {}) => {
            if (!zapidFromRecoveryAlarm(alarm?.name)) return
            void this.handleRecoveryAlarm(alarm)
        }
        try {
            this.recoveryAlarms.onAlarm.addListener(this._recoveryAlarmHandler)
            this._recoveryAlarmRegistered = true
        } catch (_) {
            this._recoveryAlarmHandler = null
        }
        return this._recoveryAlarmRegistered
    }

    async _readRecoveryRecords() {
        if (!this.recoveryStorage?.get) return {}
        try {
            const stored = await this.recoveryStorage.get(ZAP_BOOTSTRAP_RECOVERY_STORAGE_KEY)
            const records = stored?.[ZAP_BOOTSTRAP_RECOVERY_STORAGE_KEY]
            return records && typeof records === 'object' && !Array.isArray(records)
                ? records
                : {}
        } catch (_) {
            return {}
        }
    }

    async _mutateRecoveryRecords(mutator) {
        if (!this.recoveryStorage?.get || !this.recoveryStorage?.set) return null
        const operation = this._recoveryStorageMutation.then(async () => {
            const records = await this._readRecoveryRecords()
            const result = await mutator(records)
            if (Object.keys(records).length) {
                await this.recoveryStorage.set({ [ZAP_BOOTSTRAP_RECOVERY_STORAGE_KEY]: records })
            } else if (this.recoveryStorage.remove) {
                await this.recoveryStorage.remove(ZAP_BOOTSTRAP_RECOVERY_STORAGE_KEY)
            } else {
                await this.recoveryStorage.set({ [ZAP_BOOTSTRAP_RECOVERY_STORAGE_KEY]: {} })
            }
            return result
        })
        this._recoveryStorageMutation = operation.catch(() => null)
        return operation
    }

    _sanitizeRecoveryRecord(record = {}) {
        if (Number(record.version) !== ZAP_BOOTSTRAP_RECOVERY_VERSION) return null
        const zapid = sanitizeIdentifier(record.zapid)
        if (!zapid) return null
        const startedAt = Number(record.startedAt)
        const expiresAt = Number(record.expiresAt)
        if (!Number.isFinite(startedAt) || !Number.isFinite(expiresAt) || expiresAt <= startedAt) return null
        return {
            version: ZAP_BOOTSTRAP_RECOVERY_VERSION,
            zapid,
            browserid: sanitizeIdentifier(record.browserid) || null,
            callbackTabId: isValidTabId(record.callbackTabId) ? record.callbackTabId : null,
            targetUrl: toHttpUrl(record.targetUrl),
            startedAt,
            expiresAt,
            retryCount: Math.max(0, Number(record.retryCount) || 0),
            nextRetryAt: Number.isFinite(Number(record.nextRetryAt)) ? Number(record.nextRetryAt) : null,
            lastError: ZAP_TRANSIENT_CONFIG_ERRORS.has(record.lastError) ? record.lastError : 'zap_config_unavailable',
            diagnostics: sanitizeConfigDiagnostics(record.diagnostics)
        }
    }

    _recoveryDelayMs(retryCount) {
        const index = Math.max(0, Math.min(Number(retryCount) || 0, this.recoveryDelaysMs.length - 1))
        return this.recoveryDelaysMs[index]
    }

    async _armRecoveryAlarm(record, delayMs = null) {
        if (!record?.zapid || !this.recoveryAlarms?.create) return false
        this._registerRecoveryAlarmListener()
        const now = this.now()
        const requestedDelay = delayMs == null ? this._recoveryDelayMs(record.retryCount) : Math.max(0, Number(delayMs) || 0)
        const when = Math.min(record.expiresAt, now + requestedDelay)
        try {
            await this.recoveryAlarms.create(recoveryAlarmName(record.zapid), { when })
            return true
        } catch (_) {
            return false
        }
    }

    async _persistBootstrapRecovery(payload, context, rawConfig) {
        const zapid = sanitizeIdentifier(context?.zapid)
        if (!zapid || !this.recoveryStorage?.get || !this.recoveryStorage?.set || !this.recoveryAlarms?.create) {
            return null
        }
        const now = this.now()
        const record = await this._mutateRecoveryRecords((records) => {
            const previous = this._sanitizeRecoveryRecord(records[zapid])
            const detectedAt = Number(payload?.detectedAt)
            const startedAt = previous?.startedAt
                || (Number.isFinite(detectedAt) && detectedAt > 0 && detectedAt <= now ? detectedAt : now)
            const retryCount = (previous?.retryCount || 0) + 1
            const next = this._sanitizeRecoveryRecord({
                version: ZAP_BOOTSTRAP_RECOVERY_VERSION,
                zapid,
                browserid: context?.browserid,
                callbackTabId: context?.tabId,
                targetUrl: payload?.targetUrl,
                startedAt,
                expiresAt: startedAt + this.recoveryMaxAgeMs,
                retryCount,
                nextRetryAt: Math.min(startedAt + this.recoveryMaxAgeMs, now + this._recoveryDelayMs(retryCount - 1)),
                lastError: rawConfig?.error,
                diagnostics: rawConfig?.diagnostics
            })
            records[zapid] = next
            return next
        }).catch(() => null)
        if (!record) return null
        if (record.expiresAt <= now) return record
        const armed = await this._armRecoveryAlarm(record, Math.max(0, record.nextRetryAt - now))
        return armed ? record : null
    }

    async cancelBootstrapRecovery(zapid, { reason = 'cancelled' } = {}) {
        const safeZapId = sanitizeIdentifier(zapid)
        if (!safeZapId) return false
        await this._mutateRecoveryRecords((records) => {
            delete records[safeZapId]
            return true
        }).catch(() => null)
        try {
            await this.recoveryAlarms?.clear?.(recoveryAlarmName(safeZapId))
        } catch (_) {
            // Cleanup remains best-effort during worker teardown.
        }
        this.bridge?._debugLog?.('[PTK ZAP] Bootstrap recovery cancelled:', {
            zapid: safeZapId,
            reason: sanitizeIdentifier(reason, 96) || 'cancelled'
        })
        return true
    }

    async _rearmPersistedRecoveries() {
        this._registerRecoveryAlarmListener()
        const records = await this._readRecoveryRecords()
        const now = this.now()
        for (const [key, rawRecord] of Object.entries(records)) {
            const record = this._sanitizeRecoveryRecord(rawRecord)
            if (!record || record.zapid !== key || record.expiresAt <= now) {
                await this.cancelBootstrapRecovery(key, { reason: 'invalid_or_expired' })
                continue
            }
            await this._armRecoveryAlarm(record, Math.max(0, (record.nextRetryAt || now) - now))
        }
        return true
    }

    async _terminalizeConfigFailure(run, context, rawConfig, reason = 'config_fetch_failed') {
        await this.cancelBootstrapRecovery(context?.zapid, { reason })
        this.bridge?._clearPendingStart?.(context?.sessionKey)
        this._transition(run, ZAP_AUTOMATION_STATES.FAILED, {
            error: rawConfig?.error || 'zap_config_unavailable',
            reason
        })
        this.bridge?._scheduleTerminalProgress?.({
            sessionKey: context?.sessionKey,
            zapid: context?.zapid,
            requiredEngines: [],
            status: ZAP_PROGRESS_STATUS_ERROR,
            message: reason === 'config_retry_budget_exhausted'
                ? 'ZAP automation config fetch timed out'
                : 'ZAP automation config fetch failed'
        })
        return run
    }

    async _resolveRecoveryPayload(record) {
        let route = this.transport?._getCallbackRoute?.({ zapid: record.zapid }) || null
        if (!route && this.transport?.scanOpenTabsForDirectCallbackUrls) {
            const observed = await this.transport.scanOpenTabsForDirectCallbackUrls('zap.bootstrap.recovery.alarm')
            if (observed) return { rediscovered: true, payload: null }
            route = this.transport?._getCallbackRoute?.({ zapid: record.zapid }) || null
        }
        if (!route?.baseUrl) return { rediscovered: false, payload: null }
        return {
            rediscovered: false,
            payload: {
                baseUrl: route.baseUrl,
                zapid: record.zapid,
                browserid: record.browserid || this.transport?.getBrowserId?.() || null,
                tabId: isValidTabId(record.callbackTabId) ? record.callbackTabId : route.tabId,
                targetUrl: record.targetUrl,
                source: 'bootstrap_recovery_alarm'
            }
        }
    }

    async handleRecoveryAlarm(alarm = {}) {
        const zapid = zapidFromRecoveryAlarm(alarm?.name)
        if (!zapid) return { ok: false, reason: 'unrelated_alarm' }
        const records = await this._readRecoveryRecords()
        const record = this._sanitizeRecoveryRecord(records[zapid])
        if (!record) {
            await this.cancelBootstrapRecovery(zapid, { reason: 'record_missing' })
            return { ok: false, reason: 'record_missing' }
        }
        if (record.expiresAt <= this.now()) {
            const context = this._buildRunContext({ zapid, browserid: record.browserid, tabId: record.callbackTabId })
            const run = this._getOrCreateRun(context)
            await this._terminalizeConfigFailure(run, context, { error: record.lastError }, 'config_retry_budget_exhausted')
            return { ok: false, reason: 'config_retry_budget_exhausted' }
        }
        if (this.transport?.isSessionTerminal?.({ zapid }) === true) {
            await this.cancelBootstrapRecovery(zapid, { reason: 'zap_session_terminal' })
            return { ok: false, reason: 'zap_session_terminal' }
        }
        const automation = this.bridge?.app?.automation
        if (!automation || typeof automation.startZapConfiguredSession !== 'function') {
            await this._armRecoveryAlarm(record)
            return { ok: false, reason: 'automation_module_unavailable' }
        }
        const resolved = await this._resolveRecoveryPayload(record)
        if (resolved.rediscovered) return { ok: true, reason: 'callback_rediscovered' }
        if (!resolved.payload) {
            const nextRecord = await this._mutateRecoveryRecords((allRecords) => {
                const current = this._sanitizeRecoveryRecord(allRecords[zapid]) || record
                current.retryCount += 1
                current.nextRetryAt = Math.min(current.expiresAt, this.now() + this._recoveryDelayMs(current.retryCount))
                allRecords[zapid] = current
                return current
            }).catch(() => null)
            if (nextRecord) await this._armRecoveryAlarm(nextRecord, Math.max(0, nextRecord.nextRetryAt - this.now()))
            return { ok: false, reason: 'callback_route_unavailable' }
        }
        try {
            const control = await this.transport?.postControlJson?.({ zapid })
            if (control?.data?.closeRequested === true) {
                await this.cancelBootstrapRecovery(zapid, { reason: 'zap_close_requested' })
                return { ok: false, reason: 'zap_close_requested' }
            }
        } catch (_) {
            // Config retry remains authoritative when the optional control route is unavailable.
        }
        const run = await this.handleZapDetected(resolved.payload)
        return { ok: true, reason: 'retry_finished', run }
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
            const error = rawConfig?.error || 'zap_config_unavailable'
            if (ZAP_TRANSIENT_CONFIG_ERRORS.has(error)) {
                const recovery = await this._persistBootstrapRecovery(payload, context, rawConfig)
                if (recovery && recovery.expiresAt > this.now()) {
                    this._transition(run, ZAP_AUTOMATION_STATES.CONFIG_FETCHING, {
                        error,
                        reason: 'config_fetch_retry_scheduled'
                    })
                    return run
                }
            }
            return this._terminalizeConfigFailure(run, context, rawConfig)
        }

        await this.cancelBootstrapRecovery(context.zapid, { reason: 'config_ready' })

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
        const callbackStillBound = () => {
            const route = this.transport?._getCallbackRoute?.({ zapid: context.zapid })
            return isValidTabId(context.tabId) && route?.tabId === context.tabId
                && route.zapid === context.zapid && route.baseUrl === context.baseUrl
                && this.transport?.getBrowserId?.() === context.browserid
        }
        // Only the already configured target can authorize startup while the
        // exact native callback tab is still held behind the host's ready gate.
        // Unseeded discovery retains the existing post-navigation path below.
        if (finalEngines.includes('SAST') && (configSeedTargetUrl || toHttpUrl(payload?.targetUrl)) && callbackStillBound()) {
            const targetUrl = await bridge._resolveTargetUrl(Object.assign({}, payload, {
                zapHistorySeedUrls: configSeedUrls
            }), 0)
            if (targetUrl) {
                const capture = bridge.browserCapture
                if (!capture) throw new Error('browser_capture_unsupported')
                this._transition(run, ZAP_AUTOMATION_STATES.CONFIG_READY, {
                    engines: finalEngines, engineConfigs: finalEngineConfigs, targetUrl
                })
                await capture.prepare({ tabId: context.tabId, zapid: context.zapid,
                    version: rawConfig?.browserCaptureVersion, engines: finalEngines,
                    startupKey: JSON.stringify([context.sessionKey, targetUrl, finalEngines]),
                    beforeReady: async () => {
                        if (!callbackStillBound()) throw new Error('browser_capture_owner_changed')
                        this._transition(run, ZAP_AUTOMATION_STATES.SESSION_STARTING, {
                            targetUrl, targetTabId: context.tabId
                        })
                        run.startAttempts += 1
                        const result = await bridge._startZapSession({
                            tabId: context.tabId, targetUrl, engines: finalEngines,
                            engineConfigs: finalEngineConfigs, baseUrl: context.baseUrl,
                            sessionKey: context.sessionKey, zapid: context.zapid
                        })
                        if (!callbackStillBound()) throw new Error('browser_capture_owner_changed')
                        return result
                    }
                })
                this._transition(run, ZAP_AUTOMATION_STATES.SESSION_RUNNING, {
                    targetUrl, targetTabId: context.tabId
                })
                return run
            }
        }
        // Arm natural-response capture before waiting for the first target URL.
        // The host's separate Selenium hook waits for the installed-listener ACK.
        if (finalEngines.length) {
            const capture = bridge.browserCapture
            if (!capture) throw new Error('browser_capture_unsupported')
            await capture.prepare({ tabId: context.tabId, zapid: context.zapid, version: rawConfig?.browserCaptureVersion, engines: finalEngines })
        }
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
