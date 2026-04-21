'use strict'

const STARTUP_STATE_KEY = '__PTK_ZAP_STARTUP_STATE__'
const DEFAULT_STARTUP_PENDING_TTL_MS = 60000

function pad2(value) {
    return String(value).padStart(2, '0')
}

function createStartupId() {
    if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
        return globalThis.crypto.randomUUID()
    }
    return `ptk-zap-startup-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`
}

function cloneState(state) {
    return {
        pending: state.pending === true,
        armedAt: Number.isFinite(state.armedAt) ? state.armedAt : null,
        expiresAt: Number.isFinite(state.expiresAt) ? state.expiresAt : null,
        startupId: typeof state.startupId === 'string' ? state.startupId : null,
        reason: typeof state.reason === 'string' ? state.reason : null,
        clearedAt: Number.isFinite(state.clearedAt) ? state.clearedAt : null,
        clearReason: typeof state.clearReason === 'string' ? state.clearReason : null,
        expiredAt: Number.isFinite(state.expiredAt) ? state.expiredAt : null
    }
}

export function formatZapLifecycleTime(date = new Date()) {
    const candidate = date instanceof Date ? date : new Date(date)
    return `${pad2(candidate.getHours())}:${pad2(candidate.getMinutes())}:${pad2(candidate.getSeconds())}`
}

function isLifecycleLoggingEnabled() {
    return globalThis.__PTK_ZAP_LIFECYCLE_LOGGING__ === true
}

export function logZapLifecycle(event, details = null) {
    if (!isLifecycleLoggingEnabled()) {
        return
    }
    const prefix = `[PTK ZAP LIFECYCLE ${formatZapLifecycleTime()}] ${event}`
    if (details && typeof details === 'object' && !Array.isArray(details) && Object.keys(details).length) {
        console.log(prefix, details)
        return
    }
    console.log(prefix)
}

export function ensureZapStartupState(scope = globalThis) {
    if (!scope[STARTUP_STATE_KEY] || typeof scope[STARTUP_STATE_KEY] !== 'object') {
        scope[STARTUP_STATE_KEY] = {
            pending: false,
            armedAt: null,
            expiresAt: null,
            startupId: null,
            reason: null,
            clearedAt: null,
            clearReason: null,
            expiredAt: null
        }
    }
    return scope[STARTUP_STATE_KEY]
}

export function armZapStartupPending(scope = globalThis, options = {}) {
    const ttlMs = Number.isFinite(Number(options?.ttlMs))
        ? Math.max(1000, Number(options.ttlMs))
        : DEFAULT_STARTUP_PENDING_TTL_MS
    const reason = typeof options?.reason === 'string' && options.reason
        ? options.reason
        : 'runtime.onStartup'

    const state = ensureZapStartupState(scope)
    const now = Date.now()
    state.pending = true
    state.armedAt = now
    state.expiresAt = now + ttlMs
    state.startupId = createStartupId()
    state.reason = reason
    state.clearedAt = null
    state.clearReason = null
    state.expiredAt = null
    return cloneState(state)
}

export function clearZapStartupPending(scope = globalThis, options = {}) {
    const reason = typeof options?.reason === 'string' && options.reason
        ? options.reason
        : 'manual'

    const state = ensureZapStartupState(scope)
    state.pending = false
    state.clearedAt = Date.now()
    state.clearReason = reason
    return cloneState(state)
}

export function getZapStartupSnapshot(scope = globalThis) {
    const state = ensureZapStartupState(scope)
    let expiredNow = false
    if (state.pending === true && Number.isFinite(state.expiresAt) && Date.now() > state.expiresAt) {
        state.pending = false
        state.expiredAt = Date.now()
        state.clearReason = state.clearReason || 'expired'
        expiredNow = true
    }
    return {
        ...cloneState(state),
        expiredNow
    }
}

export function isZapStartupPending(scope = globalThis) {
    return getZapStartupSnapshot(scope).pending === true
}
