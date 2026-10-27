import { DAST_RUNTIME_MESSAGE, createDastRuntimeMessage } from "./protocol.js"

export const DAST_RUNTIME_PORT = "ptk_dast_runtime_v1"

export function cloneDastPrivilegedResult(value) {
    if (value === undefined) return null
    try {
        return structuredClone(value)
    } catch (_) {
        return JSON.parse(JSON.stringify(value, (_key, current) => {
            if (current instanceof WeakMap || current instanceof WeakSet || typeof current === "function") return undefined
            return current
        }))
    }
}

export class OffscreenDastClient {
    constructor({ browserApi = globalThis.browser, offscreenManager, nonceFactory = () => crypto.randomUUID(), requestTimeoutMs = 10000, operationHandler = null, eventHandler = null } = {}) {
        this.browserApi = browserApi
        this.offscreenManager = offscreenManager
        this.nonceFactory = nonceFactory
        this.requestTimeoutMs = requestTimeoutMs
        this.operationHandler = operationHandler
        this.eventHandler = eventHandler
        this.port = null
        this.controllerNonce = null
        this.pending = new Map()
        this.oneTimeDisplayListeners = new Map()
        this.connectPromise = null
    }

    async connect() {
        if (this.port) return true
        if (this.connectPromise) return this.connectPromise
        this.connectPromise = (async () => {
            await this.offscreenManager.ensureDocument()
            const port = this.browserApi.runtime.connect({ name: DAST_RUNTIME_PORT })
            const nonce = this.nonceFactory()
            this.port = port
            this.controllerNonce = nonce
            port.onMessage.addListener(message => this._onMessage(message))
            port.onDisconnect.addListener(() => this._onDisconnect(port))
            const hello = await this._requestRaw({ type: "controller_hello", controllerNonce: nonce })
            if (!hello?.ok || hello.controllerNonce !== nonce) throw new Error("dast_runtime_auth_failed")
            return true
        })().catch(error => {
            this.port?.disconnect?.()
            this.port = null
            throw error
        }).finally(() => { this.connectPromise = null })
        return this.connectPromise
    }

    _onMessage(message) {
        if (message?.type === "engine_event" && message?.controllerNonce === this.controllerNonce) {
            this.eventHandler?.(message.event, message.cursor)
            return
        }
        if (message?.type === "one_time_display_event" && message?.controllerNonce === this.controllerNonce) {
            const listener = this.oneTimeDisplayListeners.get(String(message.operationId || ""))
            listener?.(message.message)
            return
        }
        if (message?.type === "privileged_request" && message?.controllerNonce === this.controllerNonce) {
            Promise.resolve(this.operationHandler?.(message.operation))
                .then(result => this.port?.postMessage({
                    type: "privileged_response", requestId: message.requestId,
                    controllerNonce: this.controllerNonce, result: cloneDastPrivilegedResult(result)
                }))
                .catch(error => this.port?.postMessage({
                    type: "privileged_response", requestId: message.requestId,
                    controllerNonce: this.controllerNonce, error: error?.message || String(error)
                }))
            return
        }
        const pending = this.pending.get(message?.requestId)
        if (!pending || message?.controllerNonce !== this.controllerNonce) return
        this.pending.delete(message.requestId)
        clearTimeout(pending.timer)
        if (message.ok === false && message.transportError) pending.reject(new Error(message.transportError))
        else pending.resolve(message.response)
    }

    _onDisconnect(port) {
        if (this.port !== port) return
        this.port = null
        Promise.resolve(this.operationHandler?.({ type: "controller_disconnect" })).catch(() => {})
        for (const pending of this.pending.values()) {
            clearTimeout(pending.timer)
            pending.reject(new Error("dast_runtime_disconnected"))
        }
        this.pending.clear()
        this.oneTimeDisplayListeners.clear()
    }

    _requestRaw(message, timeoutMs = this.requestTimeoutMs) {
        const requestId = crypto.randomUUID()
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(requestId)
                reject(new Error("dast_runtime_request_timeout"))
            }, timeoutMs)
            this.pending.set(requestId, { resolve, reject, timer })
            this.port.postMessage({ ...message, requestId })
        })
    }

    async request(type, payload = {}, metadata = {}) {
        await this.connect()
        const longRunning = new Set([
            DAST_RUNTIME_MESSAGE.START,
            DAST_RUNTIME_MESSAGE.CAPTURE,
            DAST_RUNTIME_MESSAGE.ENGINE_CALL,
            DAST_RUNTIME_MESSAGE.ONE_TIME_SCAN
        ])
        const timeoutMs = longRunning.has(type) ? Math.max(this.requestTimeoutMs, 15 * 60 * 1000) : this.requestTimeoutMs
        return this._requestRaw({
            type: "runtime_request",
            controllerNonce: this.controllerNonce,
            message: createDastRuntimeMessage(type, payload, metadata)
        }, timeoutMs)
    }

    onOneTimeDisplay(operationId, listener) {
        const key = String(operationId || "")
        if (!key || typeof listener !== "function") return () => {}
        this.oneTimeDisplayListeners.set(key, listener)
        return () => {
            if (this.oneTimeDisplayListeners.get(key) === listener) {
                this.oneTimeDisplayListeners.delete(key)
            }
        }
    }

    async reconnect(sessionId = null) {
        await this.connect()
        return this.request(DAST_RUNTIME_MESSAGE.CONTROLLER_REPLACED, { sessionId })
    }
}

export default OffscreenDastClient
