function createDefaultSessionState() {
    return {
        sentAllAttacksCompleted: false,
        acceptIncomingRequests: false,
        requireUserInteractionBeforeCapture: true,
        userInteractionUnlocked: false,
        deferredSeedState: null,
        enableSyntheticRedirectRequests: false,
        automationSession: null,
        zapManaged: false,
        pendingAutomationSeeds: 0,
        lastAutomationSeedResult: null
    }
}

function formatSeedLogField(name, value) {
    if (value == null || value === '') return null
    if (typeof value === 'number' || typeof value === 'boolean') {
        return `${name}=${value}`
    }
    return `${name}=${JSON.stringify(String(value))}`
}

function shouldLogAutomationSeedSummary() {
    return globalThis.__PTK_AUTOMATION_DEBUG__ === true
}

function toPositiveNumber(value, fallback) {
    const num = Number(value)
    return Number.isFinite(num) && num > 0 ? num : fallback
}

function shouldSkipPostStopAnalysis(options = {}) {
    const zapCloseRequest = options?.zapCloseRequest === true || options?.source === 'zap_browser_close'
    if (options?.skipPostStopAnalysis === true) return true
    if (options?.skipPostStopAnalysis === false) return false
    if (options?.immediateAnalysis === true) return false
    if (options?.immediateAnalysis === false) return true
    return zapCloseRequest
}

function withTimeout(promise, timeoutMs) {
    const boundedMs = Math.max(0, Number(timeoutMs) || 0)
    if (!boundedMs) {
        return Promise.resolve({ timedOut: true })
    }

    let timer = null
    return Promise.race([
        Promise.resolve(promise)
            .then(value => ({ timedOut: false, value }))
            .catch(error => ({ timedOut: false, error })),
        new Promise(resolve => {
            timer = setTimeout(() => resolve({ timedOut: true }), boundedMs)
        })
    ]).finally(() => {
        if (timer) clearTimeout(timer)
    })
}

export class DastSessionCoordinator {
    constructor({
        engine = null,
        captureAdapter = null,
        state = null,
        baseSettings = {},
        getZapManualEngineSettings = () => null,
        reset = () => {},
        parseDomains = () => [],
        registerScript = () => {},
        unregisterScript = async () => {},
        applyAnalysis = () => {},
        flushPersistScanResult = () => {},
        setScanResult = () => {},
        getScanResult = () => null,
        notifyScanCompleted = () => {},
        collectSeverityStats = () => ({ counts: {}, findingsCount: 0 })
    } = {}) {
        this.engine = engine
        this.captureAdapter = captureAdapter
        this.state = state && typeof state === "object" ? state : createDefaultSessionState()
        this.baseSettings = baseSettings && typeof baseSettings === "object" ? baseSettings : {}
        this.getZapManualEngineSettings = getZapManualEngineSettings
        this.reset = reset
        this.parseDomains = parseDomains
        this.registerScript = registerScript
        this.unregisterScript = unregisterScript
        this.applyAnalysis = applyAnalysis
        this.flushPersistScanResult = flushPersistScanResult
        this.setScanResult = setScanResult
        this.getScanResult = getScanResult
        this.notifyScanCompleted = notifyScanCompleted
        this.collectSeverityStats = collectSeverityStats
        this.relatedTabs = new Map()
    }

    _collectDrainSnapshot() {
        const progress = typeof this.engine?.getProgressSnapshot === 'function'
            ? this.engine.getProgressSnapshot()
            : null
        const requestQueue = toPositiveNumber(progress?.requestQueue, 0)
        const taskQueue = toPositiveNumber(progress?.taskQueue, 0)
        const pendingPlans = toPositiveNumber(progress?.pendingPlans, 0)
        const activeTasks = toPositiveNumber(progress?.activeTasks, 0)
        const planning = toPositiveNumber(progress?.planning, 0)
        const pendingCaptures = toPositiveNumber(progress?.pendingCaptures, 0)
        const remaining = toPositiveNumber(progress?.remaining, 0)
        const pendingAutomationSeeds = toPositiveNumber(this.state.pendingAutomationSeeds, 0)
        const pendingWork = requestQueue + taskQueue + pendingPlans + activeTasks + planning + pendingAutomationSeeds + pendingCaptures
        return {
            isRunning: this.engine?.isRunning === true,
            idle: progress?.isIdle === true,
            planned: toPositiveNumber(progress?.planned, 0),
            executed: toPositiveNumber(progress?.executed, 0),
            remaining,
            requestQueue,
            taskQueue,
            pendingPlans,
            activeTasks,
            planning,
            pendingCaptures,
            pendingAutomationSeeds,
            pendingWork
        }
    }

    _isDrainSnapshotIdle(snapshot = null) {
        if (!snapshot || typeof snapshot !== 'object') return false
        // Zero/defaulted counters do not prove executor or publication idle.
        return snapshot.idle === true
            && toPositiveNumber(snapshot.pendingWork, 0) <= 0
            && toPositiveNumber(snapshot.remaining, 0) <= 0
    }

    _resolveZapCloseDrainTimeout(timeoutMs, options = {}) {
        const explicit = Number(options?.drainTimeoutMs)
        if (Number.isFinite(explicit) && explicit >= 0) {
            return Math.max(0, Math.floor(explicit))
        }
        const budget = toPositiveNumber(timeoutMs, 25000)
        // Keep enough time for stopBackgroundScan(), finding persistence, and the
        // ZAP terminal progress callback. The drain is best-effort; unstarted tail
        // work is marked engine_incomplete instead of letting ZAP force-close.
        return Math.max(500, Math.min(20000, Math.floor(budget * 0.72)))
    }

    async _drainBeforeZapClose(timeoutMs, options = {}, stopOwner = null) {
        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        const before = this._collectDrainSnapshot()
        if (this._isDrainSnapshotIdle(before)) {
            return {
                mode: 'zap_close',
                drainTimeoutMs: 0,
                drained: true,
                timedOut: false,
                before,
                after: before
            }
        }

        const drainTimeoutMs = this._resolveZapCloseDrainTimeout(timeoutMs, options)
        // Zero must not dispatch an untimed engine idle waiter.
        if (drainTimeoutMs <= 0) {
            const after = this._collectDrainSnapshot()
            const drained = this._isDrainSnapshotIdle(after)
            return { mode: 'zap_close', drainTimeoutMs: 0, drained, timedOut: !drained, error: null, before, after }
        }
        const waitResult = await withTimeout(
            this.engine?.waitForIdle?.(drainTimeoutMs),
            drainTimeoutMs
        )
        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        const after = this._collectDrainSnapshot()
        return {
            mode: 'zap_close',
            drainTimeoutMs,
            drained: !('error' in waitResult) && !waitResult.timedOut && this._isDrainSnapshotIdle(after),
            timedOut: waitResult.timedOut === true,
            error: waitResult.error?.message || waitResult.error || null,
            before,
            after
        }
    }

    getState() {
        return this.state
    }

    isRunningForTab(tabId) {
        const normalized = Number(tabId)
        return !!(
            this.engine?.isRunning
            && Number.isInteger(normalized)
            && (this.engine.tabId === normalized || this.relatedTabs.has(normalized))
        )
    }

    registerRelatedTab(tabId, meta = {}) {
        const normalized = Number(tabId)
        if (!this.engine?.isRunning || !Number.isInteger(normalized) || normalized < 0 || normalized === this.engine.tabId) {
            return false
        }
        this.relatedTabs.set(normalized, Object.assign({}, this.relatedTabs.get(normalized) || {}, meta, {
            tabId: normalized
        }))
        return true
    }

    releaseRelatedTab(tabId) {
        const normalized = Number(tabId)
        if (!Number.isInteger(normalized) || normalized < 0) return false
        return this.relatedTabs.delete(normalized)
    }

    isCaptureBlockedByInteraction() {
        return this.state.requireUserInteractionBeforeCapture && !this.state.userInteractionUnlocked
    }

    unlockUserInteraction() {
        this.state.userInteractionUnlocked = true
        this.engine?.setControllerState?.({ userInteractionUnlocked: true })
        return true
    }

    async runBackgroundScan(tabId, host, domains, settings) {
        if (this.engine?.isRunning) {
            return false
        }
        const zapManualSettings = this.getZapManualEngineSettings?.()
        const resolvedSettings = Object.assign({}, this.baseSettings || {}, zapManualSettings || {}, settings || {})
        const runtimeSettings = settings && typeof settings === "object" ? settings : {}
        const normalizedDomains = Array.isArray(domains) ? domains.join(",") : domains
        const targetDomains = normalizedDomains && normalizedDomains.length ? normalizedDomains : host

        await this.reset?.()
        this.relatedTabs.clear()
        this.state.sentAllAttacksCompleted = false
        this.captureAdapter?.addListeners?.()
        this.state.acceptIncomingRequests = true

        const unsafeCaptureWithoutInteraction = runtimeSettings.allowCaptureWithoutInteraction === true
        this.state.requireUserInteractionBeforeCapture = !unsafeCaptureWithoutInteraction
        this.state.userInteractionUnlocked = !this.state.requireUserInteractionBeforeCapture
        this.state.enableSyntheticRedirectRequests = runtimeSettings.enableSyntheticRedirectRequests === true
        this.state.zapManaged = runtimeSettings.zapManaged === true
        this.state.pendingAutomationSeeds = 0
        this.state.lastAutomationSeedResult = null
        this.engine?.setControllerState?.({
            acceptIncomingRequests: true,
            requireUserInteractionBeforeCapture: this.state.requireUserInteractionBeforeCapture,
            userInteractionUnlocked: this.state.userInteractionUnlocked,
            enableSyntheticRedirectRequests: this.state.enableSyntheticRedirectRequests,
            zapManaged: this.state.zapManaged
        })

        try {
            if (resolvedSettings.ws) {
                await this.registerScript?.()
            }
            const started = await this.engine?.start?.(tabId, host, this.parseDomains?.(targetDomains), resolvedSettings)
            if (started === false || this.engine?.isRunning !== true) throw new Error("scan_start_failed")
            return true
        } catch (error) {
            this.state.acceptIncomingRequests = false
            this.state.userInteractionUnlocked = false
            this.state.enableSyntheticRedirectRequests = false
            this.state.zapManaged = false
            this.captureAdapter?.removeListeners?.()
            await this.unregisterScript?.().catch?.(() => {})
            return false
        }
    }

    // Optional internal owner guard; interactive callers retain their existing behavior.
    async stopBackgroundScan(options = {}, stopOwner = null) {
        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        const waitForIdleBeforeStop = options?.waitForIdleBeforeStop !== false
        const idleTimeoutMs = Number.isFinite(options?.idleTimeoutMs) ? Number(options.idleTimeoutMs) : 120000

        this.state.acceptIncomingRequests = false
        this.state.userInteractionUnlocked = false
        this.state.enableSyntheticRedirectRequests = false
        this.state.zapManaged = false
        this.state.pendingAutomationSeeds = 0
        this.relatedTabs.clear()
        this.engine?.setControllerState?.({
            acceptIncomingRequests: false,
            userInteractionUnlocked: false,
            enableSyntheticRedirectRequests: false,
            zapManaged: false
        })

        if (waitForIdleBeforeStop) {
            try {
                await this.engine?.waitForIdle?.(idleTimeoutMs)
            } catch (_) { }
        }

        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        await this.engine?.stop?.()
        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        this.setScanResult?.(this.engine?.scanResult)
        const scanResult = this.getScanResult?.() || this.engine?.scanResult || null
        if (scanResult) {
            scanResult.finished = new Date().toISOString()
        }

        if (!this.state.sentAllAttacksCompleted) {
            this.state.sentAllAttacksCompleted = true
            try {
                await this.notifyScanCompleted?.()
            } catch (_) { }
        }

        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        await this.flushPersistScanResult?.()
        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        await this.unregisterScript?.()
        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        this.captureAdapter?.removeListeners?.()
        return scanResult
    }

    async startAutomationSession({ sessionId, tabId, host, domains, settings, policyCode, hooks }) {
        if (!sessionId || !tabId || !host) {
            throw new Error("missing_session_parameters")
        }
        if (this.state.automationSession?.stopFlight || this.state.automationSession?.stopQualification) {
            throw new Error("automation_session_already_running")
        }
        if (this.state.automationSession && this.state.automationSession.id !== sessionId) {
            // If the engine is no longer running, treat the retained session id
            // as stale background state and let the new automation session claim it.
            if (this.engine?.isRunning === true) {
                throw new Error("automation_session_already_running")
            }
            this.state.automationSession = null
        }
        this.state.automationSession = { id: sessionId }

        const resolvedSettings = Object.assign({}, settings || {})
        if (policyCode) {
            resolvedSettings.policyCode = policyCode
        }
        const started = await this.runBackgroundScan(tabId, host, domains || host, resolvedSettings)
        if (!started) {
            if (this.state.automationSession?.id === sessionId) this.state.automationSession = null
            throw new Error("scan_start_failed")
        }
        if (this.engine?.setAutomationHooks) {
            this.engine.setAutomationHooks({
                sessionId,
                onTaskStarted: hooks?.onTaskStarted,
                onTaskFinished: hooks?.onTaskFinished,
                onPtkTabOpened: hooks?.onPtkTabOpened,
                onPtkTabClosing: hooks?.onPtkTabClosing
            })
        }
        this._seedZapAutomationRequests(tabId, resolvedSettings)
        return {
            success: true,
            seed: null
        }
    }

    _seedZapAutomationRequests(tabId, settings = {}) {
        if (settings?.zapManaged !== true || typeof this.captureAdapter?.seedZapAutomationRequestsFromProxy !== "function") {
            return null
        }
        this.state.pendingAutomationSeeds = Number(this.state.pendingAutomationSeeds || 0) + 1
        const seedPromise = Promise.resolve()
            .then(() => this.captureAdapter.seedZapAutomationRequestsFromProxy(tabId, {
                targetUrl: settings?.targetUrl || null,
                pageUrl: settings?.pageUrl || null,
                sinceMs: settings?.zapCallbackDetectedAt || 0,
                historySeedUrls: Array.isArray(settings?.zapHistorySeedUrls) ? settings.zapHistorySeedUrls : [],
                maxRequests: settings?.zapSeedMaxRequests || 200
            }))
            .then((result) => {
                const mergedResult = Object.assign({}, result || {}, {
                    historySeedTotalAvailable: Number(settings?.zapHistorySeedTotalAvailable || 0),
                    historySeedDroppedByCap: Number(settings?.zapHistorySeedDroppedByCap || 0)
                })
                this.state.lastAutomationSeedResult = mergedResult
                const fields = [
                    '[PTK_DAST_AUTOMATION_SEED]',
                    formatSeedLogField('tabId', tabId),
                    formatSeedLogField('targetUrl', settings?.targetUrl || settings?.pageUrl || null),
                    formatSeedLogField('proxySeeded', mergedResult?.proxySeeded ?? 0),
                    formatSeedLogField('historySeeded', mergedResult?.historySeeded ?? 0),
                    formatSeedLogField('historySeedInputCount', mergedResult?.historySeedInputCount ?? 0),
                    formatSeedLogField('historySeedTotalAvailable', mergedResult?.historySeedTotalAvailable ?? 0),
                    formatSeedLogField('historySeedDroppedByCap', mergedResult?.historySeedDroppedByCap ?? 0),
                    formatSeedLogField('historySeedDuplicatesSkipped', mergedResult?.historySeedDuplicatesSkipped ?? 0)
                ]
                if (shouldLogAutomationSeedSummary()) {
                    console.log(fields.filter(Boolean).join(' '))
                }
                return mergedResult
            })
            .catch((error) => {
                this.state.lastAutomationSeedResult = {
                    proxySeeded: 0,
                    historySeeded: 0,
                    historySeedInputCount: Array.isArray(settings?.zapHistorySeedUrls) ? settings.zapHistorySeedUrls.length : 0,
                    historySeedTotalAvailable: Number(settings?.zapHistorySeedTotalAvailable || 0),
                    historySeedDroppedByCap: Number(settings?.zapHistorySeedDroppedByCap || 0),
                    error: error?.message || String(error)
                }
                const fields = [
                    '[PTK_DAST_AUTOMATION_SEED]',
                    formatSeedLogField('tabId', tabId),
                    formatSeedLogField('targetUrl', settings?.targetUrl || settings?.pageUrl || null),
                    formatSeedLogField('proxySeeded', 0),
                    formatSeedLogField('historySeeded', 0),
                    formatSeedLogField('historySeedInputCount', this.state.lastAutomationSeedResult.historySeedInputCount),
                    formatSeedLogField('historySeedTotalAvailable', this.state.lastAutomationSeedResult.historySeedTotalAvailable),
                    formatSeedLogField('historySeedDroppedByCap', this.state.lastAutomationSeedResult.historySeedDroppedByCap),
                    formatSeedLogField('error', this.state.lastAutomationSeedResult.error)
                ]
                console.warn(fields.filter(Boolean).join(' '))
                return this.state.lastAutomationSeedResult
            })
            .finally(() => {
                this.state.pendingAutomationSeeds = Math.max(0, Number(this.state.pendingAutomationSeeds || 0) - 1)
            })
        this.state.lastAutomationSeedPromise = seedPromise
        return seedPromise
    }

    _assertAutomationStopOwner(stopOwner) {
        if (!stopOwner?.owner || this.state.automationSession !== stopOwner.owner
            || stopOwner.owner.id !== stopOwner.sessionId) {
            throw new Error("automation_session_mismatch")
        }
    }

    _resolveAutomationStopPolicy(timeoutMs = 180000, options = {}) {
        const normalizedTimeoutMs = toPositiveNumber(timeoutMs, 180000)
        const zapCloseRequest = options?.zapCloseRequest === true || options?.source === 'zap_browser_close'
        return Object.freeze({
            timeoutMs: normalizedTimeoutMs,
            zapCloseRequest,
            skipPostStopAnalysis: shouldSkipPostStopAnalysis(options),
            seedWaitMs: Math.max(0, Math.min(this._resolveAutomationSeedStopWaitMs(normalizedTimeoutMs, { zapCloseRequest }), 10000)),
            drainTimeoutMs: zapCloseRequest ? this._resolveZapCloseDrainTimeout(normalizedTimeoutMs, options) : null
        })
    }

    _sameAutomationStopPolicy(left, right) {
        return !!left && !!right && ['timeoutMs', 'zapCloseRequest', 'skipPostStopAnalysis', 'seedWaitMs', 'drainTimeoutMs']
            .every(key => left[key] === right[key])
    }

    async stopAutomationSession(sessionId, timeoutMs = 180000, options = {}) {
        const stopOwner = { owner: this.state.automationSession, sessionId }
        this._assertAutomationStopOwner(stopOwner)
        const automationSession = stopOwner.owner
        const policy = this._resolveAutomationStopPolicy(timeoutMs, options)
        this._assertAutomationStopOwner(stopOwner)
        if (automationSession.stopQualification
            && !this._sameAutomationStopPolicy(automationSession.stopQualification.policy, policy)) {
            throw new Error("automation_stop_policy_conflict")
        }
        const { zapCloseRequest, skipPostStopAnalysis } = policy
        let drainResult = automationSession.stopQualification?.drain
        if (!drainResult) {
            drainResult = {
                mode: zapCloseRequest ? 'zap_close' : 'normal',
                drained: true,
                timedOut: false,
                before: this._collectDrainSnapshot(),
                after: null
            }
            const preCleanupStartedAt = zapCloseRequest ? Date.now() : null
            await this._waitForAutomationSeedBeforeStop(policy.seedWaitMs, {
                clearPendingOnTimeout: !zapCloseRequest
            }, stopOwner)
            this._assertAutomationStopOwner(stopOwner)
            this.state.acceptIncomingRequests = false
            if (zapCloseRequest) {
                drainResult = await this._drainBeforeZapClose(policy.timeoutMs, {
                    // Constrain seed + drainage to the existing pre-cleanup
                    // allocation, even when the caller explicitly requests the
                    // whole outer deadline. Keep requested policy identity intact.
                    drainTimeoutMs: Math.min(policy.drainTimeoutMs, Math.max(0,
                        this._resolveZapCloseDrainTimeout(policy.timeoutMs, {})
                        - Math.max(0, Date.now() - preCleanupStartedAt)))
                }, stopOwner)
            } else {
                await this.engine?.waitForIdle?.(policy.timeoutMs)
                this._assertAutomationStopOwner(stopOwner)
                drainResult.after = this._collectDrainSnapshot()
                drainResult.drained = this._isDrainSnapshotIdle(drainResult.after)
            }
            this._assertAutomationStopOwner(stopOwner)
            automationSession.stopQualification = { policy, drain: drainResult }
        }
        this._assertAutomationStopOwner(stopOwner)
        if (this.engine?.setAutomationHooks) {
            this.engine.setAutomationHooks(null)
        }
        const scanResult = await this.stopBackgroundScan({
            waitForIdleBeforeStop: false,
            skipPostStopAnalysis
        }, stopOwner)
        this._assertAutomationStopOwner(stopOwner)
        const stats = this.collectSeverityStats?.(scanResult) || { counts: {}, findingsCount: 0 }
        const completionStatus = drainResult.drained ? 'completed' : 'engine_incomplete'
        this.state.lastAutomationStopResult = {
            completionStatus,
            zapCloseRequest,
            drain: drainResult,
            finishedAt: new Date().toISOString()
        }
        // The owning Rattacker flow clears this exact owner only after capture cleanup.
        return {
            findingsCount: stats.findingsCount,
            bySeverity: Object.assign({
                info: 0,
                low: 0,
                medium: 0,
                high: 0,
                critical: 0
            }, stats.counts || {}),
            completionStatus,
            zapCloseRequest,
            drained: drainResult.drained,
            drain: drainResult
        }
    }

    getAutomationStats() {
        const severity = this.collectSeverityStats?.()
        return {
            findingsCount: severity.findingsCount,
            bySeverity: Object.assign({}, severity.counts)
        }
    }

    _resolveAutomationSeedStopWaitMs(timeoutMs = 180000, options = {}) {
        const budget = toPositiveNumber(timeoutMs, 180000)
        if (options?.zapCloseRequest === true) {
            return Math.max(500, Math.min(budget, 8000, Math.floor(budget * 0.35)))
        }
        return budget
    }

    async _waitForAutomationSeedBeforeStop(timeoutMs = 180000, options = {}, stopOwner = null) {
        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        const seedPromise = this.state.lastAutomationSeedPromise
        if (!seedPromise || typeof seedPromise.then !== "function") {
            return
        }

        const waitMs = Math.max(0, Math.min(Number(timeoutMs) || 0, 10000))
        if (!waitMs) {
            return
        }

        let timedOut = false
        await Promise.race([
            seedPromise.catch(() => null),
            new Promise((resolve) => {
                setTimeout(() => {
                    timedOut = true
                    resolve(null)
                }, waitMs)
            })
        ])

        if (stopOwner) this._assertAutomationStopOwner(stopOwner)
        if (timedOut) {
            if (options?.clearPendingOnTimeout !== false) {
                this.state.pendingAutomationSeeds = 0
            }
            this.state.lastAutomationSeedResult = Object.assign({}, this.state.lastAutomationSeedResult || {}, {
                timedOutBeforeStop: true
            })
            console.warn("[PTK DAST] automation seed wait timed out during stop", {
                sessionId: this.state.automationSession?.id || null,
                timeoutMs: waitMs
            })
        }
    }
}

export default DastSessionCoordinator
