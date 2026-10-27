import { DAST_RUNTIME_MESSAGE } from "./protocol.js"
import { isDastResponseAllowed } from "../services/dastAdmission.js"
import { dastSimpleFingerprint } from "../services/dastDedupe.js"
import { applyDastResultDelta } from "./resultDelta.js"
import { toRequestBuilderProgressMessage } from "./oneTimeDisplay.js"

const DAST_DISPLAY_CHANNELS = new Set([
    "ptk_background2popup_rattacker",
    "ptk_background2popup_dast"
])
const DAST_DISPLAY_TYPES = new Set([
    "dast_progress",
    "dast_idle",
    "dast_attack_delta",
    "dast_plan_completed",
    "attack completed",
    "all attacks completed",
    "attack failed",
    "dast_scan_completed"
])

function isDastDisplayMessage(message = {}) {
    return DAST_DISPLAY_CHANNELS.has(message?.channel)
        && DAST_DISPLAY_TYPES.has(message?.type)
}

export class RemoteDastEngineFacade {
    constructor({ client, controller = null, settings = {}, sessionIdFactory = () => crypto.randomUUID() } = {}) {
        this.client = client || controller?.client
        this.sessionIdFactory = sessionIdFactory
        this.sessionId = null
        this.executorGeneration = null
        this.isRunning = false
        this.tabId = null
        this.host = null
        this.domains = []
        this.settings = this._clone(settings || {})
        this.modules = []
        this.scanResult = {}
        this.progress = { isIdle: true }
        this.progressDrains = 0
        this._performanceTelemetry = null
        this.automationHooks = null
        this.resultMutationListener = null
        this.displayMessageListener = null
        this._moduleLoadPromise = Promise.resolve()
        this.captureSequence = 0
        this.strongRecordedKeys = new Set()
        this.publicationCursor = 0
        this.appliedEventCursor = 0
        this.controllerState = null
        this.automationSessionId = null
        this.eventApplyChain = Promise.resolve()
        this.resultDeltaRevision = 0
        this.terminalState = null
        this._remoteCleanup = null
        this._cleanupAttempt = null
        this._cleanupSessionBinding = null
        controller?.onEngineMessage?.((message, cursor) => this._queueEngineMessage(message, cursor))
    }

    _clone(value) {
        if (value == null) return value
        return typeof structuredClone === "function"
            ? structuredClone(value)
            : JSON.parse(JSON.stringify(value))
    }

    _applyRuntimeState(response = {}) {
        const state = response.executorState || {}
        if ((response.sessionId && response.sessionId !== this.sessionId)
            || (response.executorGeneration && response.executorGeneration !== this.executorGeneration)
            || (state.automationSessionId && state.automationSessionId !== this.automationSessionId)
            || (state.scanResult?.scanId && state.scanResult.scanId !== this.scanResult?.scanId)) {
            this._invalidateRemoteCleanup()
        }
        this.sessionId = response.sessionId || this.sessionId
        this.executorGeneration = response.executorGeneration || this.executorGeneration
        this.tabId = state.tabId ?? this.tabId
        this.host = state.host ?? this.host
        this.domains = Array.isArray(state.domains) ? state.domains : this.domains
        this.settings = state.settings || this.settings
        this.modules = state.modules || this.modules
        this.scanResult = state.scanResult ? this._clone(state.scanResult) : this.scanResult
        this.progress = state.progress || this.progress
        this._performanceTelemetry = state.performanceTelemetry
            ? this._clone(state.performanceTelemetry)
            : (state.scanResult?.performance?.dast
                ? this._clone(state.scanResult.performance.dast)
                : this._performanceTelemetry)
        this.controllerState = state.controllerState ? this._clone(state.controllerState) : this.controllerState
        this.automationSessionId = state.automationSessionId || this.automationSessionId
        this.resultDeltaRevision = Math.max(this.resultDeltaRevision, Number(state.resultDeltaRevision) || 0)
        this.isRunning = response.status === "running" || response.status === "stopping" || state.isRunning === true
        this.publicationCursor = Math.max(this.publicationCursor, Number(response.acknowledgedEventCursor) || 0)
        this.appliedEventCursor = Math.max(this.appliedEventCursor, this.publicationCursor)
        return this
    }

    async adopt(response = {}) {
        this._invalidateRemoteCleanup()
        this._cleanupSessionBinding = null
        if (!response?.ok) throw new Error(response?.error || "dast_runtime_adopt_failed")
        if (!response.sessionId || !response.executorGeneration || response.status === "idle") return false
        this._applyRuntimeState(response)
        // The previous controller may have applied and acknowledged the latest
        // worker event immediately before it was replaced, but died before an
        // external consumer (notably the ZAP publisher) completed its flush.
        // Re-presenting the authoritative snapshot is idempotent for consumers
        // and closes that publication gap without creating a second executor.
        try {
            await this._notifyResultMutation({ type: "runtime_adopted_snapshot" })
            await this.drainEvents()
        } catch (error) {
            this.progress = { ...this.progress, isIdle: false }
            throw error
        }
        return true
    }

    async start(tabId, host, domains, settings = {}) {
        this._invalidateRemoteCleanup()
        this._cleanupSessionBinding = null
        const sessionId = this.sessionIdFactory()
        const controllerState = {
            acceptIncomingRequests: true,
            requireUserInteractionBeforeCapture: settings?.allowCaptureWithoutInteraction !== true,
            userInteractionUnlocked: settings?.allowCaptureWithoutInteraction === true,
            enableSyntheticRedirectRequests: settings?.enableSyntheticRedirectRequests === true,
            zapManaged: settings?.zapManaged === true
        }
        const response = await this.client.request(DAST_RUNTIME_MESSAGE.START, {
            sessionId, tabId, host, domains, settings, controllerState
        })
        if (!response?.ok) throw new Error(response?.error || "scan_start_failed")
        this.sessionId = sessionId
        this.executorGeneration = response.executorGeneration
        this.tabId = tabId
        this.host = host
        this.domains = domains
        this.settings = response.executorState?.settings || settings
        this.modules = response.executorState?.modules || []
        this.scanResult = response.executorState?.scanResult || this.scanResult
        this.isRunning = true
        this.captureSequence = 0
        this.progress = response.executorState?.progress || { isIdle: false }
        this._performanceTelemetry = response.executorState?.performanceTelemetry
            ? this._clone(response.executorState.performanceTelemetry)
            : this._performanceTelemetry
        this.controllerState = response.executorState?.controllerState || controllerState
        this.publicationCursor = Math.max(0, Number(response.acknowledgedEventCursor) || 0)
        this.appliedEventCursor = this.publicationCursor
        this.resultDeltaRevision = Number(response.executorState?.resultDeltaRevision) || 0
        this.terminalState = null
        await this.drainEvents()
        return true
    }

    async enqueue(rawRequest, response) {
        const result = await this.client.request(DAST_RUNTIME_MESSAGE.CAPTURE, {
            sessionId: this.sessionId,
            executorGeneration: this.executorGeneration,
            tabId: response?.tabId ?? this.tabId,
            requestId: response?.requestId,
            captureSequence: Number.isFinite(Number(response?.captureSequence))
                ? Number(response.captureSequence)
                : ++this.captureSequence,
            fingerprint: rawRequest?.fingerprint,
            rawRequest,
            response
        })
        if (!result?.ok) {
            if (this._isIgnorableTerminalResponse(result)) return { ok: true, ignored: true, terminal: this.terminalState }
            throw new Error(result?.error || "dast_runtime_capture_failed")
        }
        return result
    }

    async _callResponse(method, args = []) {
        const response = await this.client.request(DAST_RUNTIME_MESSAGE.ENGINE_CALL, {
            sessionId: this.sessionId, executorGeneration: this.executorGeneration, method, args
        })
        if (!response?.ok) {
            if (this._isIgnorableTerminalResponse(response)) return null
            throw new Error(response?.error || "engine_call_failed")
        }
        return response
    }

    async _call(method, args = []) {
        const response = await this._callResponse(method, args)
        return response == null ? null : response.result
    }

    async onetimeScanRequest(raw, _legacy = true, display = {}) {
        const operationId = display.operationId || crypto.randomUUID()
        let displayChain = Promise.resolve()
        const unregister = this.client.onOneTimeDisplay?.(operationId, message => {
            const progress = toRequestBuilderProgressMessage(operationId, message, display)
            const listener = display.onProgress || this.displayMessageListener
            if (!progress || typeof listener !== "function") return
            displayChain = displayChain
                .then(() => listener(this._clone(progress)))
                .catch(() => false)
        }) || (() => {})
        try {
            const response = await this.client.request(DAST_RUNTIME_MESSAGE.ONE_TIME_SCAN, {
                operationId,
                raw: this._clone(raw),
                settings: this._clone(this.settings || {})
            })
            await displayChain
            if (!response?.ok) throw new Error(response?.error || "one_time_scan_failed")
            return this._clone(response.result)
        } finally {
            unregister()
        }
    }

    async waitForIdle(timeoutMs) {
        // The local wait resolves without a value both on idle and expiration.
        // Only the executor's subsequent counters establish settlement.
        await this._call("waitForIdle", [timeoutMs])
        return this.refreshProgress()
    }
    getProgressSnapshot() {
        return { ...this.progress, ...(this.progressDrains > 0 ? { isIdle: false } : {}) }
    }
    async refreshProgress() {
        if (this.sessionId && this.executorGeneration) {
            const response = await this._callResponse("getProgressSnapshot")
            const progress = response?.result
            if (!progress || typeof progress !== "object") {
                throw new Error("dast_runtime_progress_unavailable")
            }
            if (progress.isIdle === true || Number.isFinite(response?.eventCursor)) {
                this.progress = { ...this._clone(progress), isIdle: false }
                // The executor and controller advance independently. An idle
                // executor can already have published its final result delta
                // while the controller is still applying earlier display
                // events. Do not expose idle until this facade has consumed
                // the exact event watermark returned with the progress call.
                this.progressDrains++
                try {
                    await this.drainEvents({ throughCursor: response?.eventCursor })
                } catch (error) {
                    // Snapshot/live progress replay can contain executor idle,
                    // but a failed publication is not controller settlement.
                    this.progress = { ...this._clone(progress), isIdle: false }
                    throw error
                } finally {
                    this.progressDrains--
                }
            }
            // Older queued progress events must not overwrite this newer
            // authoritative observation while its watermark is being drained.
            this.progress = this._clone(progress)
        }
        return this.getProgressSnapshot()
    }
    async getPerformanceTelemetry({ refresh = true } = {}) {
        if (refresh && this.sessionId && this.executorGeneration) {
            this._performanceTelemetry = this._clone(await this._call("__getPerformanceTelemetry"))
        }
        return this._clone(this._performanceTelemetry)
    }
    async getRequestSnapshot(requestId, attackId = null) {
        return this._clone(await this._call("__getRequestSnapshot", [requestId, attackId]))
    }
    async stop() {
        const overlapping = this.terminalState === "stopping" || this.terminalState === "stopped"
        this._invalidateRemoteCleanup()
        const owner = { client: this.client, port: this.client?.port,
            nonce: this.client?.controllerNonce, sessionId: this.sessionId,
            generation: this.executorGeneration, hooksSessionId: this.automationSessionId,
            automationSessionId: this.automationSessionId || this._cleanupSessionBinding?.automationSessionId,
            binding: this._cleanupSessionBinding,
            scanId: this.scanResult?.scanId }
        const attempt = {}
        this._cleanupAttempt = attempt
        const current = () => this._cleanupAttempt === attempt && this.client === owner.client
            && this.client?.port === owner.port && this.client?.controllerNonce === owner.nonce
            && this.sessionId === owner.sessionId && this.executorGeneration === owner.generation
            && this.automationSessionId === owner.hooksSessionId
            && this._cleanupSessionBinding === owner.binding
            && (!owner.binding || (owner.binding.client === owner.client && owner.binding.port === owner.port
                && owner.binding.nonce === owner.nonce && owner.binding.sessionId === owner.sessionId
                && owner.binding.generation === owner.generation && owner.binding.scanId === owner.scanId))
            && this.scanResult?.scanId === owner.scanId
        let stoppedClean = false
        try {
        this.terminalState = "stopping"
        const response = await this.client.request(DAST_RUNTIME_MESSAGE.STOP, {
            sessionId: owner.sessionId, executorGeneration: owner.generation
        })
        if (!response?.ok) {
            this.terminalState = null
            throw new Error(response?.error || "scan_stop_failed")
        }
        stoppedClean = !overlapping && current() && !!owner.sessionId && !!owner.generation
            && !!owner.automationSessionId && !!owner.scanId
            && response.sessionId === owner.sessionId && response.executorGeneration === owner.generation
            && response.status === "stopped" && response.duplicate !== true
        await this.drainEvents()
        stoppedClean = stoppedClean && current()
        this.scanResult = response?.result?.scanResult ? this._clone(response.result.scanResult) : this.scanResult
        if (this.scanResult?.performance?.dast) {
            this._performanceTelemetry = this._clone(this.scanResult.performance.dast)
        }
        this.isRunning = false
        this.terminalState = "stopped"
        this.progress = { ...this.progress, isIdle: true }
        const released = await owner.client.request(DAST_RUNTIME_MESSAGE.RELEASE, {
            sessionId: owner.sessionId, executorGeneration: owner.generation
        })
        if (!released?.ok) throw new Error(released?.error || "scan_release_failed")
        const clean = stoppedClean && current() && released.released === true
            && released.status === "idle" && released.sessionId === null && released.executorGeneration === null
            && this.client?.pending?.size === 0
        this.sessionId = null
        this.executorGeneration = null
        this.terminalState = "released"
        if (clean) this._remoteCleanup = owner
        return this.scanResult
        } catch (error) {
            this._invalidateRemoteCleanup()
            throw error
        }
    }
    _invalidateRemoteCleanup() {
        this._remoteCleanup = null
        this._cleanupAttempt = null
    }
    getRemoteCleanupReceipt({ sessionId, scanId } = {}) {
        const receipt = this._remoteCleanup
        if (!receipt || receipt.automationSessionId !== sessionId || receipt.scanId !== scanId
            || this.client !== receipt.client || this.client?.port !== receipt.port
            || this.client?.controllerNonce !== receipt.nonce || this.client?.pending?.size !== 0
            || this.automationSessionId !== receipt.hooksSessionId || this._cleanupSessionBinding !== receipt.binding
            || this.scanResult?.scanId !== scanId
            || this.sessionId !== null || this.executorGeneration !== null || this.terminalState !== "released") {
            this._remoteCleanup = null
            return null
        }
        return receipt
    }
    async reset() {
        this._invalidateRemoteCleanup()
        this._cleanupSessionBinding = null
        if (this.sessionId && this.isRunning) await this._call("reset")
        this.scanResult = {}
        this.strongRecordedKeys.clear()
        this.publicationCursor = 0
        this.appliedEventCursor = 0
        this.controllerState = null
        this.automationSessionId = null
        this.resultDeltaRevision = 0
        this.terminalState = null
        return true
    }
    _isIgnorableTerminalResponse(response = {}) {
        return response?.error === "session_not_found"
            && ["stopping", "stopped", "released"].includes(this.terminalState)
    }
    async updateScanResult(result, data) { return this._call("updateScanResult", [result, data]) }
    setAutomationHooks(hooks) {
        if (this.automationSessionId !== (hooks?.sessionId || null)) this._invalidateRemoteCleanup()
        // The coordinator deliberately removes callbacks before native Stop.
        // Retain only that exact native-owner binding, not callbacks or results.
        if (hooks?.sessionId) this._cleanupSessionBinding = {
            automationSessionId: hooks.sessionId, client: this.client, port: this.client?.port,
            nonce: this.client?.controllerNonce, sessionId: this.sessionId,
            generation: this.executorGeneration, scanId: this.scanResult?.scanId
        }
        this.automationHooks = hooks || null
        this.automationSessionId = hooks?.sessionId || null
        if (this.sessionId && this.executorGeneration) {
            void this._call("__setAutomationSession", [this.automationSessionId])
                .catch(error => this._reportLateCallFailure("set_automation_session", error))
        }
    }
    setControllerState(patch = {}) {
        this.controllerState = { ...(this.controllerState || {}), ...(patch || {}) }
        if (this.sessionId && this.executorGeneration) {
            void this._call("__setControllerState", [this.controllerState])
                .catch(error => this._reportLateCallFailure("set_controller_state", error))
        }
        return true
    }
    _reportLateCallFailure(operation, error) {
        if (["stopping", "stopped", "released"].includes(this.terminalState)
            && String(error?.message || error) === "session_not_found") return
        console.error("[PTK DAST] Remote runtime call failed", {
            operation,
            active: this.isRunning === true,
            terminalState: this.terminalState,
            error: error?.message || String(error)
        })
    }
    setResultMutationListener(listener) { this.resultMutationListener = listener || null }
    setDisplayMessageListener(listener) { this.displayMessageListener = listener || null }
    setSessionProfileStore() {}
    notifyCaptureProgressChanged() {}
    _appendRuntimeEvent(event) {
        if (!this.sessionId || !this.executorGeneration) return null
        if (["stopping", "stopped", "released"].includes(this.terminalState)) return null
        return this._call("_appendRuntimeEvent", [event])
    }
    _isHtmlLinkDiscoveryEnabled() { return this.settings?.enableHtmlLinkDiscovery === true }
    isRecordedStrongTopFrameResponseDuplicate(response = {}) {
        const method = String(response.method || "GET").toUpperCase()
        if (!['GET', 'HEAD'].includes(method) || String(response.type || '').toLowerCase() !== 'main_frame' || Number(response.frameId) !== 0 || !this.isAllowed(response)) return false
        const url = String(response.url || response.ui_url || '').trim()
        const key = dastSimpleFingerprint({ raw: `${method} ${url} HTTP/1.1\r\n\r\n`, url, method, ui_url: response.ui_url || url }, response)
        return !!key && this.strongRecordedKeys.has(key)
    }
    isAllowed(response = {}) { return isDastResponseAllowed(response, this) }
    _queueEngineMessage(message = {}, cursor = null) {
        const normalizedCursor = Number(cursor)
        this.eventApplyChain = this.eventApplyChain.then(async () => {
            if (Number.isFinite(normalizedCursor) && normalizedCursor > 0 && normalizedCursor <= this.publicationCursor) return
            if (Number.isFinite(normalizedCursor) && normalizedCursor > this.publicationCursor + 1) {
                throw new Error("dast_runtime_event_cursor_gap")
            }
            if (!(Number.isFinite(normalizedCursor) && normalizedCursor > 0 && normalizedCursor <= this.appliedEventCursor)) {
                await this.applyEngineMessage(message)
                if (Number.isFinite(normalizedCursor) && normalizedCursor > 0) this.appliedEventCursor = normalizedCursor
            }
            if (Number.isFinite(normalizedCursor) && normalizedCursor > 0 && this.sessionId && this.executorGeneration) {
                const ack = await this.client.request(DAST_RUNTIME_MESSAGE.ACK_EVENTS, {
                    sessionId: this.sessionId,
                    executorGeneration: this.executorGeneration,
                    cursor: normalizedCursor
                })
                if (!ack?.ok) throw new Error(ack?.error || "dast_runtime_event_ack_failed")
                this.publicationCursor = normalizedCursor
            }
        })
        // Live-port callers do not await this promise. Observe the rejection
        // without converting the ordered chain back to success: later events
        // must not cumulatively acknowledge an unapplied/failed receipt.
        void this.eventApplyChain.catch(error => {
            this.progress = { ...this.progress, isIdle: false }
            this._reportLateCallFailure("apply_engine_event", error)
        })
        return this.eventApplyChain
    }
    async drainEvents(options = {}) {
        try {
            return await this._drainEvents(options)
        } catch (error) {
            this.progress = { ...this.progress, isIdle: false }
            throw error
        }
    }
    async _drainEvents({ throughCursor = null } = {}) {
        if (!this.sessionId || !this.executorGeneration) return
        const requiredCursor = throughCursor !== null
            && throughCursor !== undefined
            && Number.isFinite(Number(throughCursor))
            ? Math.max(0, Math.trunc(Number(throughCursor)))
            : null
        // Live port events may already cover the requested watermark. Let the
        // existing ordered chain finish before requesting replay pages, which
        // avoids queueing duplicate copies of the same durable events.
        try {
            await this.eventApplyChain
        } catch (_) {
            // The worker retains unacknowledged events. Reuse its existing
            // replay path from the last successful receipt; a repeated failure
            // below rejects drainage rather than silently skipping the event.
            this.eventApplyChain = Promise.resolve()
        }
        if (requiredCursor !== null && this.publicationCursor >= requiredCursor) return
        while (true) {
            const response = await this.client.request(DAST_RUNTIME_MESSAGE.EVENTS_PAGE, {
                sessionId: this.sessionId,
                executorGeneration: this.executorGeneration,
                afterCursor: this.publicationCursor,
                limit: 200
            })
            if (!response?.ok) throw new Error(response?.error || "dast_runtime_event_replay_failed")
            // An ACK can commit at the worker even if its response is lost.
            // Reconcile only receipts this controller actually applied; never
            // use a worker cursor to skip an unapplied event.
            this.publicationCursor = Math.max(this.publicationCursor, Math.min(
                this.appliedEventCursor, Number(response.acknowledgedEventCursor) || 0
            ))
            if (response.page?.resetRequired === true) {
                this._applyRuntimeState(response)
                await this._notifyResultMutation({ type: "runtime_replay_snapshot" })
                const resetCursor = Number(response.page?.resetCursor) || 0
                if (resetCursor > this.publicationCursor) {
                    this.appliedEventCursor = Math.max(this.appliedEventCursor, resetCursor)
                    const resetAck = await this.client.request(DAST_RUNTIME_MESSAGE.ACK_EVENTS, {
                        sessionId: this.sessionId,
                        executorGeneration: this.executorGeneration,
                        cursor: resetCursor
                    })
                    if (!resetAck?.ok) throw new Error(resetAck?.error || "dast_runtime_snapshot_ack_failed")
                    this.publicationCursor = resetCursor
                }
            }
            const items = Array.isArray(response.page?.items) ? response.page.items : []
            for (const item of items) await this._queueEngineMessage(item.event, item.cursor)
            await this.eventApplyChain
            if (requiredCursor !== null && this.publicationCursor >= requiredCursor) break
            if (!response.page?.hasMore || !items.length) break
        }
        await this.eventApplyChain
        if (requiredCursor !== null && this.publicationCursor < requiredCursor) {
            throw new Error("dast_runtime_event_watermark_unavailable")
        }
    }
    async _notifyResultMutation(payload) {
        if (typeof this.resultMutationListener !== "function") return
        await this.resultMutationListener(payload)
    }
    async applyEngineMessage(message = {}) {
        if (message.type === "dast_dedupe_delta") {
            message.strong ? this.strongRecordedKeys.add(message.key) : this.strongRecordedKeys.delete(message.key)
        }
        const hookMap = {
            automation_task_started: "onTaskStarted",
            automation_task_finished: "onTaskFinished",
            automation_tab_opened: "onPtkTabOpened",
            automation_tab_closing: "onPtkTabClosing"
        }
        if (hookMap[message.type]) await this.automationHooks?.[hookMap[message.type]]?.(message.payload)
        if (message.type === "result_mutation") await this._notifyResultMutation(message.payload)
        if (message.type === "dast_result_delta") {
            const delta = message.delta || {}
            const revision = Number(delta.revision) || 0
            if (revision >= this.resultDeltaRevision) {
                applyDastResultDelta(this.scanResult, delta)
                this.resultDeltaRevision = Math.max(this.resultDeltaRevision, revision)
                if (delta.finalChunk !== false) await this._notifyResultMutation(delta.mutation)
            }
        }
        if (message.type === "dast_progress") {
            // dastEngine emits the same runtime message consumed by the local
            // extension path: display metadata lives in `info`, while the
            // canonical engine counters live in `info.progress`. Keeping the
            // wrapper here made synchronous consumers (notably the ZAP
            // progress monitor) see no planned/executed work and report DAST
            // as permanently ready even though the offscreen executor ran.
            const progress = message.info?.progress
            this.progress = this._clone(
                progress && typeof progress === "object"
                    ? progress
                    : (message.info || {})
            )
        }
        if (message.type === "dast_attack_delta" || message.type === "dast_plan_completed") {
            const delta = message.delta || {}
            this.scanResult.requests ||= []
            let record = this.scanResult.requests.find(item => item?.id === delta.requestId)
            if (!record) {
                record = { id: delta.requestId, original: delta.original || null, attacks: [] }
                this.scanResult.requests.push(record)
            }
            const seen = new Set(record.attacks.map(item => item?.id).filter(Boolean))
            for (const attack of delta.attacks || []) if (!attack?.id || !seen.has(attack.id)) record.attacks.push(attack)
            await this._notifyResultMutation({ type: message.type, requestId: delta.requestId })
        }
        if (isDastDisplayMessage(message) && typeof this.displayMessageListener === "function") {
            // Apply the authoritative engine event before notifying the UI, and
            // await relay dispatch before acknowledging the durable worker
            // cursor, not the optional dashboard receiver's response.
            await this.displayMessageListener(this._clone(message))
        }
    }
}

export default RemoteDastEngineFacade
