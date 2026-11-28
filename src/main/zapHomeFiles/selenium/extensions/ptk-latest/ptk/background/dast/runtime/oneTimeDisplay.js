const ONE_TIME_PROGRESS_NUMBERS = Object.freeze([
    "planned",
    "executed",
    "skippedDueToStrategy",
    "remaining",
    "nonExecuted",
    "activeTasks",
    "taskQueue",
    "requestQueue",
    "pendingPlans",
    "planning",
    "pendingCaptures",
    "pendingHtmlDiscovery"
])

const ONE_TIME_PROGRESS_BOOLEANS = Object.freeze([
    "targetWindowRequired",
    "isRunning",
    "isIdle"
])

const ONE_TIME_PROGRESS_STRINGS = Object.freeze([
    "phase",
    "scanStrategy",
    "lastActivityAt"
])

function boundedString(value, maxLength) {
    return typeof value === "string" ? value.slice(0, maxLength) : null
}

export function sanitizeOneTimeDastProgressMessage(message = {}) {
    if (message?.channel !== "ptk_background2popup_rattacker" || message?.type !== "attack completed") {
        return null
    }
    const name = boundedString(message?.info?.name, 512)
    if (!name) return null
    const source = message?.info?.progress
    const progress = {}
    if (source && typeof source === "object" && !Array.isArray(source)) {
        for (const key of ONE_TIME_PROGRESS_NUMBERS) {
            const value = source[key]
            if (typeof value === "number" && Number.isFinite(value)) progress[key] = value
        }
        for (const key of ONE_TIME_PROGRESS_BOOLEANS) {
            if (typeof source[key] === "boolean") progress[key] = source[key]
        }
        for (const key of ONE_TIME_PROGRESS_STRINGS) {
            const value = boundedString(source[key], 128)
            if (value !== null) progress[key] = value
        }
    }
    return {
        channel: "ptk_background2popup_rattacker",
        type: "attack completed",
        info: { name, progress }
    }
}

export function toRequestBuilderProgressMessage(operationId, message = {}, identity = {}) {
    const sanitized = sanitizeOneTimeDastProgressMessage(message)
    const id = String(operationId || "")
    if (!sanitized || !id) return null
    return {
        channel: "ptk_background2popup_rbuilder",
        type: "scan progress",
        operationId: id,
        ...(identity.formId != null ? { formId: identity.formId } : {}),
        ...(identity.uiGeneration != null ? { uiGeneration: identity.uiGeneration } : {}),
        ...(identity.storageEpoch != null ? { storageEpoch: identity.storageEpoch } : {}),
        info: sanitized.info
    }
}
