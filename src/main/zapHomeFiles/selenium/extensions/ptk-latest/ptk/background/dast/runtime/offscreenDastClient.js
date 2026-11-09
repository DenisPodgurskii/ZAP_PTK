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
        this.cleanupDisconnectListeners = new Set()
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
            port.onMessage.addListener(message => this._onMessage(message, port))
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

    _onMessage(message, port = this.port) {
        if (port !== this.port) return
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
        if (pending.finish) {
            if (pending.port !== port || pending.nonce !== this.controllerNonce) return
            if (pending.observation && !pending.observation.isCurrent()) {
                pending.finish(new Error("dast_runtime_cleanup_owner_changed"))
            } else if (message.ok === false && message.transportError) {
                pending.finish(new Error(message.transportError))
            } else pending.finish(null, message.response)
            return
        }
        this.pending.delete(message.requestId)
        clearTimeout(pending.timer)
        if (message.ok === false && message.transportError) pending.reject(new Error(message.transportError))
        else pending.resolve(message.response)
    }

    _onDisconnect(port) {
        if (this.port !== port) return
        this.port = null
        for (const listener of [...this.cleanupDisconnectListeners]) listener()
        Promise.resolve(this.operationHandler?.({ type: "controller_disconnect" })).catch(() => {})
        for (const pending of this.pending.values()) {
            if (pending.finish) {
                pending.finish(new Error("dast_runtime_disconnected"))
                continue
            }
            clearTimeout(pending.timer)
            pending.reject(new Error("dast_runtime_disconnected"))
        }
        this.pending.clear()
        this.oneTimeDisplayListeners.clear()
    }

    onCleanupDisconnect(listener) {
        this.cleanupDisconnectListeners.add(listener)
        return () => this.cleanupDisconnectListeners.delete(listener)
    }

    _requestRaw(message, timeoutMs = this.requestTimeoutMs, observation = null) {
        const requestId = crypto.randomUUID()
        return new Promise((resolve, reject) => {
            const entry = { port: this.port, nonce: this.controllerNonce, observation, timer: null, deadlineTimer: null }
            entry.finish = (error, response) => {
                if (this.pending.get(requestId) !== entry) return
                this.pending.delete(requestId)
                clearTimeout(entry.timer)
                clearTimeout(entry.deadlineTimer)
                if (error) { reject(error); observation?.reject(error) }
                else { resolve(response); observation?.resolve(response) }
            }
            entry.timer = setTimeout(() => {
                // A ZAP cleanup observer retains only this original response.
                // The ordinary RPC promise still rejects at its unchanged limit.
                if (!observation) this.pending.delete(requestId)
                reject(new Error("dast_runtime_request_timeout"))
            }, timeoutMs)
            this.pending.set(requestId, entry)
            if (observation) {
                observation.cancel = () => entry.finish(new Error("dast_runtime_cleanup_observation_cancelled"))
                entry.deadlineTimer = setTimeout(() => entry.finish(new Error("dast_runtime_cleanup_observation_expired")),
                    Math.max(0, observation.deadlineAt - Date.now()))
            }
            try { entry.port.postMessage({ ...message, requestId }) }
            catch (error) { entry.finish(error) }
        })
    }

    observeCleanupRequest(type, payload, { deadlineAt, isCurrent } = {}) {
        // Internal, opt-in, one-flight observation. The existing general Stop
        // ceiling bounds retention; it does not extend the 10s RPC deadline.
        if (![DAST_RUNTIME_MESSAGE.STOP, DAST_RUNTIME_MESSAGE.RELEASE].includes(type)
            || !this.port || typeof isCurrent !== "function" || !isCurrent()
            || !Number.isFinite(deadlineAt) || deadlineAt <= Date.now()
            || deadlineAt > Date.now() + 180000) throw new Error("dast_runtime_cleanup_observation_invalid")
        let resolve, reject
        const completion = new Promise((yes, no) => { resolve = yes; reject = no })
        const observation = { deadlineAt, isCurrent, resolve, reject, cancelled: false,
            port: this.port, nonce: this.controllerNonce,
            cancel() {
                this.cancelled = true
                reject(new Error("dast_runtime_cleanup_observation_cancelled"))
            } }
        // Keep the same connect/dispatch ordering as ordinary requests, notably
        // the coordinator's already-issued hook/controller quiescence calls.
        const response = this.request(type, payload, {}, observation)
        // Expiry of the public observation is historical, not native failure.
        // Real transport errors still reject the original completion above.
        void response.catch(error => {
            if (error?.message !== "dast_runtime_request_timeout") observation.reject(error)
        })
        void completion.catch(() => {})
        return { response, completion, cancel: () => observation.cancel?.() }
    }

    async request(type, payload = {}, metadata = {}, observation = null) {
        await this.connect()
        if (observation && (observation.cancelled || !observation.isCurrent()
            || observation.port !== this.port || observation.nonce !== this.controllerNonce
            || Date.now() >= observation.deadlineAt)) throw new Error("dast_runtime_cleanup_owner_changed")
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
        }, timeoutMs, observation)
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
