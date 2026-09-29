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
        this._performanceTelemetry = null
        this.automationHooks = null
        this.resultMutationListener = null
        this.displayMessageListener = null
        this._moduleLoadPromise = Promise.resolve()
        this.captureSequence = 0
        this.strongRecordedKeys = new Set()
        this.publicationCursor = 0
        this.controllerState = null
        this.automationSessionId = null
        this.eventApplyChain = Promise.resolve()
        this.resultDeltaRevision = 0
        this.terminalState = null
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
        return this
    }

    async adopt(response = {}) {
        if (!response?.ok) throw new Error(response?.error || "dast_runtime_adopt_failed")
        if (!response.sessionId || !response.executorGeneration || response.status === "idle") return false
        this._applyRuntimeState(response)
        // The previous controller may have applied and acknowledged the latest
        // worker event immediately before it was replaced, but died before an
        // external consumer (notably the ZAP publisher) completed its flush.
        // Re-presenting the authoritative snapshot is idempotent for consumers
        // and closes that publication gap without creating a second executor.
        await this._notifyResultMutation({ type: "runtime_adopted_snapshot" })
        await this.drainEvents()
        return true
    }

    async start(tabId, host, domains, settings = {}) {
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

    async onetimeScanRequest(raw) {
        const operationId = crypto.randomUUID()
        let displayChain = Promise.resolve()
        const unregister = this.client.onOneTimeDisplay?.(operationId, message => {
            const progress = toRequestBuilderProgressMessage(operationId, message)
            if (!progress || typeof this.displayMessageListener !== "function") return
            displayChain = displayChain
                .then(() => this.displayMessageListener(this._clone(progress)))
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
        const result = await this._call("waitForIdle", [timeoutMs])
        this.progress = { ...(result || {}), isIdle: true }
        return result
    }
    getProgressSnapshot() { return { ...this.progress } }
    async refreshProgress() {
        if (this.sessionId && this.executorGeneration) {
            const response = await this._callResponse("getProgressSnapshot")
            const progress = response?.result
            if (progress && typeof progress === "object") this.progress = this._clone(progress)
            if (progress?.isIdle === true) {
                // The executor and controller advance independently. An idle
                // executor can already have published its final result delta
                // while the controller is still applying earlier display
                // events. Do not expose idle until this facade has consumed
                // the exact event watermark returned with the progress call.
                await this.drainEvents({ throughCursor: response?.eventCursor })
            }
        }
        return this.getProgressSnapshot()
    }
    async getPerformanceTelemetry({ refresh = true } = {}) {
        if (refresh && this.sessionId && this.executorGeneration) {
            this._performanceTelemetry = this._clone(await this._call("__getPerformanceTelemetry"))
        }
        return this._clone(this._performanceTelemetry)
    }
    async stop() {
        this.terminalState = "stopping"
        const response = await this.client.request(DAST_RUNTIME_MESSAGE.STOP, {
            sessionId: this.sessionId, executorGeneration: this.executorGeneration
        })
        if (!response?.ok) {
            this.terminalState = null
            throw new Error(response?.error || "scan_stop_failed")
        }
        await this.drainEvents()
        this.scanResult = response?.result?.scanResult ? this._clone(response.result.scanResult) : this.scanResult
        if (this.scanResult?.performance?.dast) {
            this._performanceTelemetry = this._clone(this.scanResult.performance.dast)
        }
        this.isRunning = false
        this.terminalState = "stopped"
        this.progress = { ...this.progress, isIdle: true }
        const released = await this.client.request(DAST_RUNTIME_MESSAGE.RELEASE, {
            sessionId: this.sessionId, executorGeneration: this.executorGeneration
        })
        if (!released?.ok) throw new Error(released?.error || "scan_release_failed")
        this.sessionId = null
        this.executorGeneration = null
        this.terminalState = "released"
        return this.scanResult
    }
    async reset() {
        if (this.sessionId && this.isRunning) await this._call("reset")
        this.scanResult = {}
        this.strongRecordedKeys.clear()
        this.publicationCursor = 0
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
            await this.applyEngineMessage(message)
            if (Number.isFinite(normalizedCursor) && normalizedCursor > 0 && this.sessionId && this.executorGeneration) {
                const ack = await this.client.request(DAST_RUNTIME_MESSAGE.ACK_EVENTS, {
                    sessionId: this.sessionId,
                    executorGeneration: this.executorGeneration,
                    cursor: normalizedCursor
                })
                if (ack?.ok) this.publicationCursor = Math.max(this.publicationCursor, normalizedCursor)
            }
        }).catch(() => {})
        return this.eventApplyChain
    }
    async drainEvents({ throughCursor = null } = {}) {
        if (!this.sessionId || !this.executorGeneration) return
        const requiredCursor = throughCursor !== null
            && throughCursor !== undefined
            && Number.isFinite(Number(throughCursor))
            ? Math.max(0, Math.trunc(Number(throughCursor)))
            : null
        // Live port events may already cover the requested watermark. Let the
        // existing ordered chain finish before requesting replay pages, which
        // avoids queueing duplicate copies of the same durable events.
        await this.eventApplyChain
        if (requiredCursor !== null && this.publicationCursor >= requiredCursor) return
        while (true) {
            const response = await this.client.request(DAST_RUNTIME_MESSAGE.EVENTS_PAGE, {
                sessionId: this.sessionId,
                executorGeneration: this.executorGeneration,
                afterCursor: this.publicationCursor,
                limit: 200
            })
            if (!response?.ok) throw new Error(response?.error || "dast_runtime_event_replay_failed")
            if (response.page?.resetRequired === true) {
                this._applyRuntimeState(response)
                await this._notifyResultMutation({ type: "runtime_replay_snapshot" })
                const resetCursor = Number(response.page?.resetCursor) || 0
                if (resetCursor > this.publicationCursor) {
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
            // await the relay so the durable worker cursor is not acknowledged
            // until the service-worker-owned browser message has been sent.
            await this.displayMessageListener(this._clone(message))
        }
    }
}

export default RemoteDastEngineFacade
