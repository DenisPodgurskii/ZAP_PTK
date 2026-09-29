import { DastWorkerRuntime } from "../background/dast/runtime/dastWorkerRuntime.js"
import { buildDastResultDeltas, createDastResultProjection } from "../background/dast/runtime/resultDelta.js"
import { sanitizeOneTimeDastProgressMessage } from "../background/dast/runtime/oneTimeDisplay.js"

const privilegedPending = new Map()
let controllerAvailable = false
const controllerWaiters = new Set()
const browserEventListeners = new Map()

function cloneForTransport(value) {
    if (value == null) return value
    return JSON.parse(JSON.stringify(value))
}

function privilegedRequest(operation, timeoutMs = 15000) {
    const requestId = crypto.randomUUID()
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            privilegedPending.delete(requestId)
            reject(new Error("privileged_operation_timeout"))
        }, timeoutMs)
        privilegedPending.set(requestId, {
            resolve: value => { clearTimeout(timer); resolve(value) },
            reject: error => { clearTimeout(timer); reject(error) }
        })
        self.postMessage({ type: "privileged_request", requestId, operation })
    })
}

function waitForController(timeoutMs = 10000) {
    if (controllerAvailable) return Promise.resolve()
    return new Promise((resolve, reject) => {
        const waiter = () => { clearTimeout(timer); controllerWaiters.delete(waiter); resolve() }
        const timer = setTimeout(() => { controllerWaiters.delete(waiter); reject(new Error("controller_unavailable")) }, timeoutMs)
        controllerWaiters.add(waiter)
    })
}

class RemoteRequestTransport {
    constructor() {
        this.useListeners = false
        this.trackWithListeners = false
        this.isolatedRedirectSession = false
        this.isolatedPreserveRawHeaders = false
        this.runPrivileged = null
    }
    sendRequest(schema) {
        const operationId = String(schema?.opts?.operationId || schema?.opts?.taskId || crypto.randomUUID())
        return this.runPrivileged({
            type: "request_send", operationId, schema,
            transport: {
                useListeners: this.useListeners,
                trackWithListeners: this.trackWithListeners,
                isolatedRedirectSession: this.isolatedRedirectSession,
                isolatedPreserveRawHeaders: this.isolatedPreserveRawHeaders
            }
        })
    }
}

export class RemoteBrowserOperations {
    constructor(runPrivileged, ownerId) {
        this.runPrivileged = runPrivileged
        this.ownerId = ownerId
        this.desiredSubscriptions = new Map()
    }
    call(method, args = [], operationId = crypto.randomUUID()) {
        return this.runPrivileged({ type: "browser_call", operationId, ownerId: this.ownerId, method, args })
    }
    async subscribe(event, listener, options = {}) {
        const subscriptionId = options.subscriptionId || crypto.randomUUID()
        browserEventListeners.set(subscriptionId, listener)
        const descriptor = {
            type: "browser_subscribe", operationId: `subscribe:${subscriptionId}`,
            subscriptionId, ownerId: this.ownerId, event,
            filter: options.filter, extraInfoSpec: options.extraInfoSpec,
            options: options.options
        }
        this.desiredSubscriptions.set(subscriptionId, descriptor)
        try {
            await this.runPrivileged(descriptor)
        } catch (error) {
            browserEventListeners.delete(subscriptionId)
            this.desiredSubscriptions.delete(subscriptionId)
            throw error
        }
        return async () => {
            browserEventListeners.delete(subscriptionId)
            this.desiredSubscriptions.delete(subscriptionId)
            await this.runPrivileged({ type: "browser_unsubscribe", operationId: `unsubscribe:${subscriptionId}`, subscriptionId })
        }
    }
    async restoreSubscriptions() {
        for (const descriptor of this.desiredSubscriptions.values()) {
            await this.runPrivileged(descriptor)
        }
    }
    async cleanup() {
        for (const subscriptionId of this.desiredSubscriptions.keys()) {
            browserEventListeners.delete(subscriptionId)
        }
        this.desiredSubscriptions.clear()
        return this.runPrivileged({ type: "browser_cleanup", operationId: `cleanup:${this.ownerId}`, ownerId: this.ownerId })
    }
}

export function selectExecutorEventEmitter(context, canonicalEmitter) {
    return context?.oneTime === true ? () => {} : canonicalEmitter
}

class RealDastExecutor {
    constructor({ payload }, runPrivileged, emitEvent, emitDisplayMessage = emitEvent) {
        this.payload = payload
        this.engine = null
        this.runPrivileged = runPrivileged
        this.emitEvent = emitEvent
        this.emitDisplayMessage = emitDisplayMessage
        this.controllerState = { ...(payload?.controllerState || {}) }
        this.automationSessionId = null
        this.resultProjection = createDastResultProjection()
        this.resultDeltaRevision = 0
    }
    _installAutomationHooks(sessionId = this.automationSessionId) {
        if (!this.engine) return
        this.automationSessionId = sessionId || null
        this.engine.setAutomationHooks({
            sessionId: this.automationSessionId,
            onTaskStarted: payload => this.emitEvent({ type: "automation_task_started", payload }),
            onTaskFinished: payload => this.emitEvent({ type: "automation_task_finished", payload }),
            onPtkTabOpened: payload => this.emitEvent({ type: "automation_tab_opened", payload }),
            onPtkTabClosing: payload => this.emitEvent({ type: "automation_tab_closing", payload })
        })
    }
    async _ensureEngine() {
        if (this.engine) return this.engine
        globalThis.isFirefox = false
        globalThis.browser ||= {
            runtime: {
                getURL: path => new URL(`../../${path}`, self.location.href).href,
                getManifest: () => ({ version: this.payload?.extensionVersion || "9.9.9" })
            }
        }
        const { dastEngine } = await import("../background/dast/dastEngine.js")
        this.browserOperations = new RemoteBrowserOperations(this.runPrivileged, this.payload?.sessionId)
        this.engine = new dastEngine(this.payload?.settings || {}, {
            requestFactory: () => Object.assign(new RemoteRequestTransport(), { runPrivileged: this.runPrivileged }),
            browserOperations: {
                remote: true,
                sendRuntimeMessage: message => {
                    this.emitDisplayMessage(message)
                    return Promise.resolve(true)
                },
                call: (...args) => this.browserOperations.call(...args),
                subscribe: (...args) => this.browserOperations.subscribe(...args)
            }
        })
        this.engine.setSessionProfileStore({
            listProfiles: options => this.runPrivileged({
                type: "session_profiles_list",
                operationId: `session-profiles:${this.payload?.sessionId}:${JSON.stringify(options || {})}`,
                options
            })
        })
        this.resultProjection = createDastResultProjection(this.engine.scanResult)
        this.engine.setResultMutationListener(payload => {
            const built = buildDastResultDeltas(this.resultProjection, this.engine.scanResult, {
                revision: ++this.resultDeltaRevision,
                mutation: payload
            })
            this.resultProjection = built.projection
            for (const delta of built.deltas) this.emitEvent({ type: "dast_result_delta", delta })
        })
        this._installAutomationHooks(this.automationSessionId)
        return this.engine
    }
    async start(payload) { return (await this._ensureEngine()).start(payload.tabId, payload.host, payload.domains, payload.settings || {}) }
    async describe({ includeSnapshot = false } = {}) {
        const engine = await this._ensureEngine()
        return {
            tabId: engine.tabId,
            host: engine.host,
            domains: engine.domains,
            isRunning: engine.isRunning === true,
            settings: cloneForTransport(engine.settings),
            modules: includeSnapshot ? cloneForTransport(engine.modules) : undefined,
            scanResult: includeSnapshot ? cloneForTransport(engine.scanResult) : undefined,
            performanceTelemetry: cloneForTransport(engine._performanceTelemetry),
            progress: cloneForTransport(engine.getProgressSnapshot()),
            controllerState: cloneForTransport(this.controllerState),
            automationSessionId: this.automationSessionId,
            resultDeltaRevision: this.resultDeltaRevision
        }
    }
    async capture(payload) { return (await this._ensureEngine()).enqueue(payload.rawRequest, payload.response) }
    async oneTimeScan(raw) { return cloneForTransport(await (await this._ensureEngine()).onetimeScanRequest(raw)) }
    async stop() {
        const engine = await this._ensureEngine()
        engine.stop()
        await engine.waitForPrivilegedCleanup?.()
        await this.browserOperations?.cleanup()
        return { scanResult: cloneForTransport(engine.scanResult) }
    }
    async release() { await this.browserOperations?.cleanup(); this.engine = null; this.browserOperations = null }
    async resultsPage({ cursor = 0, limit = 100 } = {}) {
        const result = (await this._ensureEngine()).scanResult || {}
        const start = Math.max(0, Number(cursor) || 0)
        const items = Array.isArray(result.attacks) ? result.attacks.slice(start, start + limit) : []
        return { items: cloneForTransport(items), nextCursor: start + items.length < (result.attacks?.length || 0) ? start + items.length : null }
    }
    async call(method, args) {
        const engine = await this._ensureEngine()
        if (method === "__setControllerState") {
            this.controllerState = { ...this.controllerState, ...(args?.[0] || {}) }
            return { ...this.controllerState }
        }
        if (method === "__setAutomationSession") {
            this._installAutomationHooks(args?.[0] || null)
            return this.automationSessionId
        }
        if (method === "__getPerformanceTelemetry") {
            return cloneForTransport(engine._performanceTelemetry)
        }
        const allowed = new Set(["getProgressSnapshot", "waitForIdle", "updateScanResult", "reset", "_appendRuntimeEvent", "isRecordedStrongTopFrameResponseDuplicate"])
        if (!allowed.has(method) || typeof engine[method] !== "function") throw new Error("unsupported_engine_call")
        return engine[method](...args)
    }
    async controllerReplaced() {
        await this.browserOperations?.restoreSubscriptions?.()
        await this.engine?.restorePrivilegedRuntime?.()
    }
}

let runtime
const emitEngineEvent = event => {
  const published = runtime.publishEvent(event)
  self.postMessage({ type: "engine_event", event: published.event, cursor: published.cursor })
}
const emitOneTimeDisplayEvent = (operationId, message) => {
  const sanitized = sanitizeOneTimeDastProgressMessage(message)
  if (!sanitized || !operationId) return false
  self.postMessage({
    type: "one_time_display_event",
    operationId: String(operationId),
    message: sanitized
  })
  return true
}
const runPrivileged = async operation => {
  const operationTimeoutMs = operation?.type === "request_send" || operation?.method === "dast.h2.fetch"
    ? 15 * 60 * 1000
    : operation?.method === "dast.tabs.waitReady" || operation?.method === "dast.tabs.navigateAndWait"
      || operation?.method === "dast.tabs.reloadAndWait" || operation?.method === "dast.tabs.navigationWatchWait"
      ? 30000
      : 15000
  const result = await runtime.runPrivilegedOperation(operation, {
    reconcile: async current => {
        if (!controllerAvailable) return { completed: false }
        return privilegedRequest({ type: "request_reconcile", operationId: current.operationId }, operationTimeoutMs)
    },
    execute: async current => {
        await waitForController()
        return privilegedRequest(current, operationTimeoutMs)
    }
  }, { maxAttempts: 2 })
  runtime.acknowledgePrivilegedOperation(operation.operationId)
  return result
}
runtime = new DastWorkerRuntime({
  executorFactory: async context => new RealDastExecutor(
    context,
    runPrivileged,
    selectExecutorEventEmitter(context, emitEngineEvent),
    context?.oneTime === true
      ? message => emitOneTimeDisplayEvent(context.operationId, message)
      : emitEngineEvent
  )
})

self.onmessage = async event => {
    const data = event.data || {}
    if (data.type === "controller_available") {
        controllerAvailable = true
        for (const waiter of Array.from(controllerWaiters)) waiter()
        return
    }
    if (data.type === "privileged_response") {
        const pending = privilegedPending.get(data.requestId)
        if (!pending) return
        privilegedPending.delete(data.requestId)
        if (data.error === "controller_replaced") controllerAvailable = false
        data.error ? pending.reject(new Error(data.error)) : pending.resolve(data.result)
        return
    }
    if (data.type === "privileged_event") {
        const listener = browserEventListeners.get(data.event?.subscriptionId)
        if (listener) listener(...(data.event?.args || []))
        return
    }
    const { requestId, message } = data
    try {
        self.postMessage({ requestId, response: await runtime.handle(message) })
    } catch (error) {
        self.postMessage({ requestId, transportError: error?.message || String(error) })
    }
}
