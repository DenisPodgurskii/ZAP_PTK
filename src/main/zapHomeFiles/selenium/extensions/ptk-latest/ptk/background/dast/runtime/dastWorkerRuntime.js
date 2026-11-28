import { DAST_RUNTIME_MESSAGE, validateDastRuntimeMessage } from "./protocol.js"

export class DastWorkerRuntime {
    constructor({ executorFactory, generationFactory = () => crypto.randomUUID(), eventLimit = 10000 } = {}) {
        this.executorFactory = executorFactory
        this.generationFactory = generationFactory
        this.session = null
        this.startInFlight = null
        this.startingSessionId = null
        this.captureLedger = new Map()
        this.operationLedger = new Map()
        this.oneTimeScanLedger = new Map()
        this.oneTimeScanInFlight = null
        this.stopInFlight = null
        this.releaseInFlight = null
        this.ownerStates = new WeakMap()
        this.eventLimit = Math.max(100, Number(eventLimit) || 10000)
        this.eventCursor = 0
        this.acknowledgedEventCursor = 0
        this.eventReplayFloor = 0
        this.eventJournal = []
    }

    _registerOwner(context) {
        this.ownerStates.set(context, { phase: "starting", calls: new Set(),
            ownerId: JSON.stringify([context.sessionId, context.executorGeneration, context.oneTime === true ? context.operationId : null]) })
        return context
    }

    _ownedState(owner) {
        const state = owner && this.ownerStates.get(owner)
        if (!state || state.phase === "released") throw new Error("stale_executor_owner")
        return state
    }

    _isCleanupOperation(operation) {
        return operation?.type === "browser_unsubscribe" || operation?.type === "browser_cleanup"
            || (operation?.type === "browser_call" && ["tabs.remove", "windows.remove",
                "scripting.unregisterContentScripts", "dast.tabs.navigationWatchCancel", "dast.dialog.detach"].includes(operation.method))
    }

    async _settleOwnerOperations(owner) {
        while (true) {
            const pending = [...this.operationLedger.values()].filter(entry => entry.owner === owner && entry.promise).map(entry => entry.promise)
            if (!pending.length) return
            await Promise.allSettled(pending)
        }
    }

    _pendingOperations() {
        return [...this.captureLedger.values(), ...this.operationLedger.values()].some(entry => entry.promise)
    }

    _retireOwnerOperations(owner) {
        for (const [key, entry] of this.operationLedger) if (entry.owner === owner && !entry.promise) this.operationLedger.delete(key)
    }

    describe() {
        return this.session
            ? {
                sessionId: this.session.sessionId,
                executorGeneration: this.session.executorGeneration,
                status: this.session.status,
                captureCount: Array.from(this.captureLedger.values()).filter(entry => entry.status === "completed").length,
                eventCursor: this.eventCursor,
                acknowledgedEventCursor: this.acknowledgedEventCursor,
                eventReplayFloor: this.eventReplayFloor
            }
            : {
                sessionId: null, executorGeneration: null, status: "idle", captureCount: 0,
                eventCursor: this.eventCursor, acknowledgedEventCursor: this.acknowledgedEventCursor,
                eventReplayFloor: this.eventReplayFloor
            }
    }

    async describeWithExecutor(options = {}) {
        const description = this.describe()
        if (!this.session) return description
        const executorState = await this.session.executor?.describe?.(options)
        return { ...description, executorState: executorState || null }
    }

    async handle(message) {
        const valid = validateDastRuntimeMessage(message)
        if (!valid.ok) return valid
        const payload = { ...(message.payload || {}) }
        if (payload.executorGeneration == null && message.executorGeneration != null) {
            payload.executorGeneration = message.executorGeneration
        }
        if (message.type === DAST_RUNTIME_MESSAGE.START) return this.start(payload)
        if (message.type === DAST_RUNTIME_MESSAGE.CAPTURE) return this.capture(payload)
        if (message.type === DAST_RUNTIME_MESSAGE.STATUS) {
            return { ok: true, ...await this.describeWithExecutor({ includeSnapshot: false }) }
        }
        if (message.type === DAST_RUNTIME_MESSAGE.CONTROLLER_REPLACED) {
            if (payload.sessionId && this.session && payload.sessionId !== this.session.sessionId) {
                return { ok: false, error: "session_not_found", ...this.describe() }
            }
            if (payload.executorGeneration && this.session && payload.executorGeneration !== this.session.executorGeneration) {
                return { ok: false, error: "stale_executor_generation", ...this.describe() }
            }
            if (this.session && this._ownedState(this.session.owner).phase === "running") {
                const state = this._ownedState(this.session.owner)
                const call = Promise.resolve().then(() => this.session.executor?.controllerReplaced?.())
                state.calls.add(call)
                try { await call } finally { state.calls.delete(call) }
            }
            return { ok: true, ...await this.describeWithExecutor({ includeSnapshot: true }) }
        }
        if (message.type === DAST_RUNTIME_MESSAGE.EVENTS_PAGE) return this.eventsPage(payload)
        if (message.type === DAST_RUNTIME_MESSAGE.ACK_EVENTS) return this.ackEvents(payload)
        if (message.type === DAST_RUNTIME_MESSAGE.RESULTS_PAGE) return this.resultsPage(payload)
        if (message.type === DAST_RUNTIME_MESSAGE.ENGINE_CALL) return this.engineCall(payload)
        if (message.type === DAST_RUNTIME_MESSAGE.ONE_TIME_SCAN) return this.oneTimeScan(payload)
        if (message.type === DAST_RUNTIME_MESSAGE.STOP) return this.stop(payload)
        if (message.type === DAST_RUNTIME_MESSAGE.RELEASE) return this.release(payload)
        if (message.type === DAST_RUNTIME_MESSAGE.INIT) return { ok: true, ...this.describe() }
        return { ok: false, error: "unsupported_message_type" }
    }

    async start(payload = {}) {
        const sessionId = String(payload.sessionId || "")
        if (!sessionId) return { ok: false, error: "missing_session_id" }
        if (this.releaseInFlight) return { ok: false, error: "executor_busy" }
        if (this.session) {
            if (this.session.sessionId !== sessionId) return { ok: false, error: "executor_busy" }
            return { ok: true, duplicate: true, ...this.describe() }
        }
        if (this.startInFlight) {
            if (this.startingSessionId !== sessionId) return { ok: false, error: "executor_busy" }
            return this.startInFlight.then(result => ({ ...result, duplicate: true }))
        }
        this.startingSessionId = sessionId
        this.startInFlight = (async () => {
            const executorGeneration = this.generationFactory()
            const owner = this._registerOwner({ sessionId, executorGeneration, payload })
            let executor
            try {
                executor = await this.executorFactory?.(owner)
                await executor?.start?.(payload)
            } catch (error) {
                this._ownedState(owner).phase = "stopping"
                try {
                    const cleanup = await executor?.release?.({ sessionId, executorGeneration, reason: "start_failed" })
                    if (cleanup === false) throw new Error("executor_cleanup_unproved")
                    await this._settleOwnerOperations(owner)
                    this._retireOwnerOperations(owner)
                    this._ownedState(owner).phase = "released"
                } catch (cleanupError) {
                    this.session = { sessionId, executorGeneration, executor, owner, status: "failed" }
                }
                throw error
            }
            this._ownedState(owner).phase = "running"
            this.session = { sessionId, executorGeneration, executor, owner, status: "running" }
            const executorState = await executor?.describe?.({ includeSnapshot: true })
            return { ok: true, duplicate: false, ...this.describe(), executorState: executorState || null }
        })().finally(() => {
            this.startInFlight = null
            this.startingSessionId = null
        })
        return this.startInFlight
    }

    _captureKey(payload = {}) {
        return [payload.sessionId, payload.tabId, payload.requestId, payload.captureSequence, payload.fingerprint].join("|")
    }

    async capture(payload = {}) {
        if (!this.session || payload.sessionId !== this.session.sessionId) return { ok: false, error: "session_not_found" }
        if (payload.executorGeneration !== this.session.executorGeneration) return { ok: false, error: "stale_executor_generation" }
        if (this.session.status !== "running") {
            return { ok: false, error: this.session.status === "stopping" ? "executor_stopping" : "executor_terminal" }
        }
        const key = this._captureKey(payload)
        const existing = this.captureLedger.get(key)
        if (existing?.status === "completed") return { ok: true, duplicate: true, ...this.describe() }
        if (existing?.promise) return existing.promise.then(() => ({ ok: true, duplicate: true, ...this.describe() }))
        const entry = { status: "pending", promise: null }
        entry.promise = Promise.resolve(this.session.executor?.capture?.(payload))
            .then(() => {
                entry.status = "completed"
                entry.promise = null
            })
            .catch((error) => {
                this.captureLedger.delete(key)
                throw error
            })
        this.captureLedger.set(key, entry)
        await entry.promise
        return { ok: true, duplicate: false, ...this.describe() }
    }

    async resultsPage(payload = {}) {
        if (!this.session || payload.sessionId !== this.session.sessionId) return { ok: false, error: "session_not_found" }
        const requestedLimit = Number(payload.limit)
        const limit = Math.max(1, Math.min(200, Number.isFinite(requestedLimit) ? Math.trunc(requestedLimit) : 100))
        const page = await this.session.executor?.resultsPage?.({ ...payload, limit })
        return { ok: true, ...this.describe(), page: page || { items: [], nextCursor: null } }
    }

    publishEvent(event = {}) {
        const cursor = ++this.eventCursor
        const entry = { cursor, event: structuredClone(event) }
        this.eventJournal.push(entry)
        if (this.eventJournal.length > this.eventLimit) {
            const removed = this.eventJournal.splice(0, this.eventJournal.length - this.eventLimit)
            this.eventReplayFloor = Math.max(this.eventReplayFloor, removed.at(-1)?.cursor || 0)
        }
        return entry
    }

    async eventsPage(payload = {}) {
        if (!this.session || (payload.sessionId && payload.sessionId !== this.session.sessionId)) {
            return { ok: false, error: "session_not_found", ...this.describe() }
        }
        if (payload.executorGeneration && payload.executorGeneration !== this.session.executorGeneration) {
            return { ok: false, error: "stale_executor_generation", ...this.describe() }
        }
        const requested = Number(payload.afterCursor)
        const afterCursor = Number.isFinite(requested)
            ? Math.max(0, Math.trunc(requested))
            : this.acknowledgedEventCursor
        const resetRequired = afterCursor < this.eventReplayFloor
        const effectiveCursor = resetRequired ? this.eventReplayFloor : afterCursor
        const requestedLimit = Number(payload.limit)
        const limit = Math.max(1, Math.min(500, Number.isFinite(requestedLimit) ? Math.trunc(requestedLimit) : 200))
        const items = this.eventJournal.filter(item => item.cursor > effectiveCursor).slice(0, limit)
        const nextCursor = items.length ? items[items.length - 1].cursor : effectiveCursor
        return {
            ok: true,
            ...this.describe(),
            executorState: resetRequired
                ? (await this.session.executor?.describe?.({ includeSnapshot: true }) || null)
                : undefined,
            page: {
                items: structuredClone(items), nextCursor, hasMore: nextCursor < this.eventCursor,
                resetRequired, resetCursor: resetRequired ? this.eventReplayFloor : null
            }
        }
    }

    ackEvents(payload = {}) {
        if (!this.session || payload.sessionId !== this.session.sessionId) {
            return { ok: false, error: "session_not_found", ...this.describe() }
        }
        if (payload.executorGeneration !== this.session.executorGeneration) {
            return { ok: false, error: "stale_executor_generation", ...this.describe() }
        }
        const cursor = Math.min(this.eventCursor, Math.max(0, Math.trunc(Number(payload.cursor) || 0)))
        this.acknowledgedEventCursor = Math.max(this.acknowledgedEventCursor, cursor)
        while (this.eventJournal[0]?.cursor <= this.acknowledgedEventCursor) this.eventJournal.shift()
        return { ok: true, ...this.describe() }
    }

    async engineCall(payload = {}) {
        if (!this.session || payload.sessionId !== this.session.sessionId) return { ok: false, error: "session_not_found" }
        if (payload.executorGeneration !== this.session.executorGeneration) return { ok: false, error: "stale_executor_generation" }
        const session = this.session
        const state = this._ownedState(session.owner)
        const readOnly = ["getProgressSnapshot", "waitForIdle", "__getPerformanceTelemetry", "__getRequestSnapshot", "isRecordedStrongTopFrameResponseDuplicate"].includes(payload.method)
        if (state.phase !== "running" && !readOnly) return { ok: false, error: "executor_terminal", ...this.describe() }
        const call = Promise.resolve().then(() => session.executor?.call?.(payload.method, Array.isArray(payload.args) ? payload.args : []))
        if (!readOnly) state.calls.add(call)
        try {
            const result = await call
            return { ok: true, ...this.describe(), result }
        } finally { state.calls.delete(call) }
    }

    async oneTimeScan(payload = {}) {
        const operationId = String(payload.operationId || "")
        if (!operationId) return { ok: false, error: "missing_operation_id" }
        if (!payload.raw || !["string", "object"].includes(typeof payload.raw)) return { ok: false, error: "scan_request_raw_missing" }
        let entry = this.oneTimeScanLedger.get(operationId)
        if (entry?.status === "completed") return { ok: true, duplicate: true, result: structuredClone(entry.result) }
        if (entry?.promise) return entry.promise.then(result => ({ ok: true, duplicate: true, result: structuredClone(result) }))
        if (this.oneTimeScanInFlight && this.oneTimeScanInFlight !== operationId) return { ok: false, error: "one_time_scan_busy" }
        if (this.releaseInFlight) return { ok: false, error: "executor_busy" }
        const duplicate = !!entry
        if (!entry) {
            const ownerId = "one-time:" + operationId
            const owner = this._registerOwner({ sessionId: ownerId, executorGeneration: ownerId, operationId,
                payload: { sessionId: ownerId, settings: payload.settings || {}, extensionVersion: payload.extensionVersion }, oneTime: true })
            entry = { status: "pending", promise: null, result: null, owner, executor: null, scanError: null }
            this.oneTimeScanLedger.set(operationId, entry)
        }
        this.oneTimeScanInFlight = operationId
        const current = entry
        current.promise = Promise.resolve().then(async () => {
            if (!duplicate) {
                try {
                    current.executor = await this.executorFactory?.(current.owner)
                    this._ownedState(current.owner).phase = "running"
                    const result = await current.executor?.oneTimeScan?.(payload.raw)
                    if (!result || typeof result !== "object") throw new Error("one_time_scan_result_missing")
                    current.result = structuredClone(result)
                } catch (error) { current.scanError = error }
            }
            this._ownedState(current.owner).phase = "stopping"
            try {
                const cleanup = await current.executor?.release?.({ reason: "one_time_scan_complete", operationId })
                if (cleanup === false) throw new Error("executor_cleanup_unproved")
                await this._settleOwnerOperations(current.owner)
            } catch (error) {
                current.status = "cleanup_failed"
                throw error
            }
            this._ownedState(current.owner).phase = "released"
            this._retireOwnerOperations(current.owner)
            this.oneTimeScanInFlight = null
            if (current.scanError) {
                this.oneTimeScanLedger.delete(operationId)
                throw current.scanError
            }
            current.status = "completed"
            while (this.oneTimeScanLedger.size > 25) {
                const oldest = this.oneTimeScanLedger.keys().next().value
                if (oldest === operationId) break
                this.oneTimeScanLedger.delete(oldest)
            }
            return current.result
        }).finally(() => { current.promise = null })
        return current.promise.then(result => ({ ok: true, duplicate, result: structuredClone(result) }))
    }

    async stop(payload = {}) {
        if (!this.session || payload.sessionId !== this.session.sessionId) return { ok: false, error: "session_not_found" }
        if (payload.executorGeneration !== this.session.executorGeneration) return { ok: false, error: "stale_executor_generation" }
        if (this.session.status === "stopped") return { ok: true, duplicate: true, ...this.describe(), result: this.session.stopResult || null }
        if (this.stopInFlight) return this.stopInFlight.then(result => ({ ...result, duplicate: true }))
        if (this.session.status !== "running" && this.session.status !== "stop_failed") {
            return { ok: false, error: "executor_terminal", ...this.describe() }
        }
        const session = this.session
        const state = this._ownedState(session.owner)
        state.phase = "stopping"
        session.status = "stopping"
        this.stopInFlight = (async () => {
            const admittedCaptures = Array.from(this.captureLedger.values())
                .map(entry => entry.promise)
                .filter(Boolean)
            const captureResults = await Promise.allSettled(admittedCaptures)
            try {
                await Promise.allSettled([...state.calls])
                const result = await session.executor?.stop?.(payload)
                if (result === false) throw new Error("executor_cleanup_unproved")
                await this._settleOwnerOperations(session.owner)
                const captureFailure = captureResults.find(result => result.status === "rejected")
                if (captureFailure) throw captureFailure.reason
                this.session.stopResult = result || null
                this.session.status = "stopped"
                return { ok: true, duplicate: false, ...this.describe(), result: this.session.stopResult }
            } catch (error) {
                this.session.status = "stop_failed"
                this.session.stopError = error?.message || String(error)
                return { ok: false, error: "executor_stop_failed", detail: this.session.stopError, ...this.describe() }
            }
        })().finally(() => { this.stopInFlight = null })
        return this.stopInFlight
    }

    async release(payload = {}) {
        if (this.startInFlight && payload.sessionId === this.startingSessionId) return { ok: false, error: "executor_operations_pending" }
        if (!this.session || payload.sessionId !== this.session.sessionId) return { ok: false, error: "session_not_found" }
        if (payload.executorGeneration !== this.session.executorGeneration) return { ok: false, error: "stale_executor_generation" }
        if (this.releaseInFlight) return this.releaseInFlight
        if (this.startInFlight || this.stopInFlight || this.session.status === "running" || this.session.status === "stopping") return { ok: false, error: "executor_running" }
        if (this._pendingOperations() || this.oneTimeScanInFlight) return { ok: false, error: "executor_operations_pending" }
        if (this.session.status !== "stopped" && this.session.status !== "failed") return { ok: false, error: "executor_not_releasable" }
        const session = this.session
        const state = this._ownedState(session.owner)
        state.phase = "releasing"
        const release = Promise.resolve().then(async () => {
            const cleanup = await session.executor?.release?.(payload)
            if (cleanup === false) throw new Error("executor_cleanup_unproved")
            await this._settleOwnerOperations(session.owner)
            if (this.session !== session || this.session.executorGeneration !== payload.executorGeneration) return { ok: false, error: "stale_executor_generation" }
            if (this._pendingOperations() || this.oneTimeScanInFlight) return { ok: false, error: "executor_operations_pending" }
            state.phase = "released"
            this.session = null
            this.captureLedger.clear()
            this._retireOwnerOperations(session.owner)
            this.eventJournal = []
            this.eventCursor = 0
            this.acknowledgedEventCursor = 0
            this.eventReplayFloor = 0
            return { ok: true, released: true, ...this.describe() }
        })
        this.releaseInFlight = release
        try { return await release }
        finally { if (this.releaseInFlight === release) this.releaseInFlight = null }
    }

    async runPrivilegedOperation(operation, adapter, { maxAttempts = 2, owner } = {}) {
        const operationId = String(operation?.operationId || "")
        if (!operationId) throw new Error("missing_operation_id")
        const state = this._ownedState(owner)
        if (operation.ownerId != null && operation.ownerId !== state.ownerId) throw new Error("foreign_executor_owner")
        if (["browser_call", "browser_subscribe", "browser_unsubscribe", "browser_cleanup"].includes(operation.type)
            && operation.ownerId !== state.ownerId) throw new Error("foreign_executor_owner")
        const existing = this.operationLedger.get(operationId)
        if (existing && existing.owner !== owner) throw new Error("foreign_operation_id")
        if (!["starting", "running"].includes(state.phase) && !this._isCleanupOperation(existing?.operation || operation)
            && (!existing || (!existing.promise && existing.status !== "completed"))) throw new Error("executor_stopping")
        if (existing?.status === "completed") return existing.result
        if (existing?.promise) return existing.promise
        const entry = existing || { status: "pending", attempts: 0, operation: structuredClone(operation), owner }
        this.operationLedger.set(operationId, entry)
        entry.promise = (async () => {
            const observed = await adapter.reconcile(entry.operation)
            if (observed?.completed === true) {
                entry.status = "completed"
                entry.result = observed.result
                return entry.result
            }
            while (entry.attempts < maxAttempts) {
                entry.attempts += 1
                try {
                    entry.result = await adapter.execute({ ...entry.operation, operationId })
                    entry.status = "completed"
                    return entry.result
                } catch (error) {
                    entry.error = error?.message || String(error)
                    const reconciled = await adapter.reconcile(entry.operation)
                    if (reconciled?.completed === true) {
                        entry.status = "completed"
                        entry.result = reconciled.result
                        return entry.result
                    }
                }
            }
            entry.status = "failed"
            throw new Error(entry.error || "privileged_operation_failed")
        })().finally(() => { entry.promise = null })
        return entry.promise
    }

    acknowledgePrivilegedOperation(operationId, owner) {
        const key = String(operationId || "")
        const entry = this.operationLedger.get(key)
        if (!entry || entry.owner !== owner || entry.promise || entry.status !== "completed") return false
        this.operationLedger.delete(key)
        return true
    }
}

export default DastWorkerRuntime
