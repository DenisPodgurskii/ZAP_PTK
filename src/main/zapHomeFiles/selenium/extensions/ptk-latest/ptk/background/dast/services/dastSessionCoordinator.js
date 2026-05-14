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
    }

    getState() {
        return this.state
    }

    isRunningForTab(tabId) {
        return !!(this.engine?.isRunning && this.engine.tabId === tabId)
    }

    isCaptureBlockedByInteraction() {
        return this.state.requireUserInteractionBeforeCapture && !this.state.userInteractionUnlocked
    }

    unlockUserInteraction() {
        this.state.userInteractionUnlocked = true
        return true
    }

    runBackgroundScan(tabId, host, domains, settings) {
        if (this.engine?.isRunning) {
            return false
        }
        const zapManualSettings = this.getZapManualEngineSettings?.()
        const resolvedSettings = Object.assign({}, this.baseSettings || {}, zapManualSettings || {}, settings || {})
        const runtimeSettings = settings && typeof settings === "object" ? settings : {}
        const normalizedDomains = Array.isArray(domains) ? domains.join(",") : domains
        const targetDomains = normalizedDomains && normalizedDomains.length ? normalizedDomains : host

        this.reset?.()
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

        if (resolvedSettings.ws) {
            this.registerScript?.()
        }

        this.engine?.start?.(tabId, host, this.parseDomains?.(targetDomains), resolvedSettings)

        return true
    }

    async stopBackgroundScan(options = {}) {
        const waitForIdleBeforeStop = options?.waitForIdleBeforeStop !== false
        const idleTimeoutMs = Number.isFinite(options?.idleTimeoutMs) ? Number(options.idleTimeoutMs) : 120000

        this.state.acceptIncomingRequests = false
        this.state.userInteractionUnlocked = false
        this.state.enableSyntheticRedirectRequests = false
        this.state.zapManaged = false
        this.state.pendingAutomationSeeds = 0

        if (waitForIdleBeforeStop) {
            try {
                await this.engine?.waitForIdle?.(idleTimeoutMs)
            } catch (_) { }
        }

        this.engine?.stop?.()
        this.setScanResult?.(this.engine?.scanResult)
        const scanResult = this.getScanResult?.() || this.engine?.scanResult || null
        if (scanResult) {
            scanResult.finished = new Date().toISOString()
            try {
                this.applyAnalysis?.(scanResult, true)
            } catch (_) { }
        }

        if (!this.state.sentAllAttacksCompleted) {
            this.state.sentAllAttacksCompleted = true
            try {
                await this.notifyScanCompleted?.()
            } catch (_) { }
        }

        await this.flushPersistScanResult?.()
        await this.unregisterScript?.()
        this.captureAdapter?.removeListeners?.()
        return scanResult
    }

    async startAutomationSession({ sessionId, tabId, host, domains, settings, policyCode, hooks }) {
        if (!sessionId || !tabId || !host) {
            throw new Error("missing_session_parameters")
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
        this.runBackgroundScan(tabId, host, domains || host, resolvedSettings)
        this._seedZapAutomationRequests(tabId, resolvedSettings)
        if (this.engine?.setAutomationHooks) {
            this.engine.setAutomationHooks({
                sessionId,
                onTaskStarted: hooks?.onTaskStarted,
                onTaskFinished: hooks?.onTaskFinished
            })
        }
        return { success: true }
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

    async stopAutomationSession(sessionId, timeoutMs = 180000) {
        if (!this.state.automationSession || this.state.automationSession.id !== sessionId) {
            throw new Error("automation_session_mismatch")
        }
        this.state.acceptIncomingRequests = false
        await this._waitForAutomationSeedBeforeStop(timeoutMs)
        await this.engine?.waitForIdle?.(timeoutMs)
        if (this.engine?.setAutomationHooks) {
            this.engine.setAutomationHooks(null)
        }
        const scanResult = await this.stopBackgroundScan({ waitForIdleBeforeStop: false })
        const stats = this.collectSeverityStats?.(scanResult) || { counts: {}, findingsCount: 0 }
        this.state.automationSession = null
        return {
            findingsCount: stats.findingsCount,
            bySeverity: Object.assign({
                info: 0,
                low: 0,
                medium: 0,
                high: 0,
                critical: 0
            }, stats.counts || {})
        }
    }

    getAutomationStats() {
        const severity = this.collectSeverityStats?.()
        return {
            findingsCount: severity.findingsCount,
            bySeverity: Object.assign({}, severity.counts)
        }
    }

    async _waitForAutomationSeedBeforeStop(timeoutMs = 180000) {
        const seedPromise = this.state.lastAutomationSeedPromise
        if (!seedPromise || typeof seedPromise.then !== "function") {
            return
        }

        const waitMs = Math.max(0, Math.min(Number(timeoutMs) || 0, 5000))
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

        if (timedOut) {
            this.state.pendingAutomationSeeds = 0
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
