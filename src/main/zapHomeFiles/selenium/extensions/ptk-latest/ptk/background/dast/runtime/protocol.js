export const DAST_RUNTIME_PROTOCOL_VERSION = 1

export const DAST_RUNTIME_MESSAGE = Object.freeze({
    INIT: "init",
    START: "start",
    CAPTURE: "capture",
    STATUS: "status",
    EVENTS_PAGE: "events_page",
    ACK_EVENTS: "ack_events",
    RESULTS_PAGE: "results_page",
    ENGINE_CALL: "engine_call",
    ONE_TIME_SCAN: "one_time_scan",
    STOP: "stop",
    RELEASE: "release",
    CONTROLLER_REPLACED: "controller_replaced"
})

export function createDastRuntimeMessage(type, payload = {}, metadata = {}) {
    return {
        protocolVersion: DAST_RUNTIME_PROTOCOL_VERSION,
        requestId: metadata.requestId || null,
        sessionId: metadata.sessionId || payload?.sessionId || null,
        executorGeneration: metadata.executorGeneration || null,
        type,
        payload
    }
}

export function validateDastRuntimeMessage(message) {
    if (!message || typeof message !== "object") return { ok: false, error: "invalid_message" }
    if (message.protocolVersion !== DAST_RUNTIME_PROTOCOL_VERSION) {
        return { ok: false, error: "unsupported_protocol_version" }
    }
    if (!Object.values(DAST_RUNTIME_MESSAGE).includes(message.type)) {
        return { ok: false, error: "unsupported_message_type" }
    }
    return { ok: true }
}
