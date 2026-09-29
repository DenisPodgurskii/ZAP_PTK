import { OffscreenDastClient } from "./offscreenDastClient.js"

export class DastRuntimeController {
    constructor({ browserApi = globalThis.browser, offscreenManager, forceLocal = false, clientFactory, operationHandler = null } = {}) {
        // The application entrypoints set this explicitly before constructing
        // engines. Treat an unknown runtime as local so unit/embedded consumers
        // never opt into the Chromium offscreen architecture accidentally.
        this.remote = globalThis.isFirefox === false && forceLocal !== true
        this.engineListeners = new Set()
        const handleOperation = async operation => {
            if (operation?.type === "runtime_message") this.emitEngineMessage(operation.message)
            return operationHandler?.(operation)
        }
        this.client = this.remote
            ? (clientFactory?.() || new OffscreenDastClient({
                browserApi, offscreenManager, operationHandler: handleOperation,
                eventHandler: (event, cursor) => this.emitEngineMessage(event, cursor)
            }))
            : null
    }

    async ensureConnected() {
        if (!this.remote) return { ok: true, mode: "local" }
        await this.client.connect()
        return { ok: true, mode: "offscreen" }
    }

    async reconnect(sessionId) {
        if (!this.remote) return { ok: true, mode: "local", sessionId }
        return this.client.reconnect(sessionId)
    }
    onEngineMessage(listener) { this.engineListeners.add(listener); return () => this.engineListeners.delete(listener) }
    emitEngineMessage(message, cursor = null) { for (const listener of this.engineListeners) listener(message, cursor) }
}

export default DastRuntimeController
