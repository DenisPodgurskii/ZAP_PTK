function createDefaultSessionState() {
    return {
        sentAllAttacksCompleted: false,
        acceptIncomingRequests: false,
        requireUserInteractionBeforeCapture: true,
        userInteractionUnlocked: false,
        deferredSeedState: null,
        enableSyntheticRedirectRequests: false,
        automationSession: null,
        zapManaged: false
    }
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
        if (this.engine?.setAutomationHooks) {
            this.engine.setAutomationHooks({
                sessionId,
                onTaskStarted: hooks?.onTaskStarted,
                onTaskFinished: hooks?.onTaskFinished
            })
        }
        return { success: true }
    }

    async stopAutomationSession(sessionId, timeoutMs = 180000) {
        if (!this.state.automationSession || this.state.automationSession.id !== sessionId) {
            throw new Error("automation_session_mismatch")
        }
        await this.engine?.waitForIdle?.(timeoutMs)
        this.state.acceptIncomingRequests = false
        await this.engine?.waitForIdle?.(timeoutMs)
        if (this.engine?.setAutomationHooks) {
            this.engine.setAutomationHooks(null)
        }
        const scanResult = await this.stopBackgroundScan()
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
}

export default DastSessionCoordinator
