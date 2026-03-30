const STORAGE_KEY = "__ptk_active_scan_sessions_v1"
const ENGINES = ["dast", "iast", "sast", "sca"]

export const ACTIVE_SCAN_SESSIONS_STORAGE_KEY = STORAGE_KEY
export const ACTIVE_SCAN_SESSION_STALE_MS = 15 * 60 * 1000
export const ACTIVE_SCAN_SESSION_MIN_WRITE_MS = 10 * 1000

let cache = null
let cacheLoaded = false

function clone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function emptyState() {
    return {
        version: 1,
        updatedAt: null,
        sessions: {
            dast: null,
            iast: null,
            sast: null,
            sca: null
        }
    }
}

function normalizeEngine(engine) {
    const key = String(engine || "").trim().toLowerCase()
    return ENGINES.includes(key) ? key : null
}

function normalizeSession(engine, session = {}) {
    const key = normalizeEngine(engine)
    if (!key || !session || typeof session !== "object") return null
    const startedAt = String(session.startedAt || session.updatedAt || new Date().toISOString())
    const updatedAt = String(session.updatedAt || session.heartbeatAt || startedAt)
    const heartbeatAt = String(session.heartbeatAt || updatedAt)
    const status = String(session.status || "running").trim().toLowerCase()
    return {
        engine: key,
        status: status || "running",
        scanId: session.scanId ? String(session.scanId) : null,
        tabId: Number.isFinite(Number(session.tabId)) ? Number(session.tabId) : null,
        host: session.host ? String(session.host).trim().toLowerCase() : null,
        startedAt,
        heartbeatAt,
        updatedAt,
        settings: session.settings && typeof session.settings === "object"
            ? clone(session.settings)
            : null
    }
}

function normalizeState(raw) {
    const base = emptyState()
    const source = raw && typeof raw === "object" ? raw : {}
    const sessions = source.sessions && typeof source.sessions === "object" ? source.sessions : {}
    ENGINES.forEach((engine) => {
        base.sessions[engine] = normalizeSession(engine, sessions[engine])
    })
    base.updatedAt = source.updatedAt ? String(source.updatedAt) : null
    return base
}

async function writeState(state, browserApi = browser) {
    const normalized = normalizeState(state)
    cache = normalized
    cacheLoaded = true
    await browserApi.storage.local.set({
        [STORAGE_KEY]: normalized
    })
    return clone(normalized)
}

export async function loadActiveScanSessions(browserApi = browser) {
    if (cacheLoaded && cache) {
        return clone(cache)
    }
    const result = await browserApi.storage.local.get(STORAGE_KEY).catch(() => ({}))
    cache = normalizeState(result?.[STORAGE_KEY])
    cacheLoaded = true
    return clone(cache)
}

export async function upsertActiveScanSession(engine, patch = {}, browserApi = browser) {
    const key = normalizeEngine(engine)
    if (!key) return null
    const state = await loadActiveScanSessions(browserApi)
    const nowIso = new Date().toISOString()
    const next = normalizeSession(key, Object.assign({}, state.sessions[key] || {}, patch || {}, {
        status: "running",
        updatedAt: nowIso,
        heartbeatAt: patch?.heartbeatAt || nowIso
    }))
    if (!next) return null
    state.sessions[key] = next
    state.updatedAt = nowIso
    return writeState(state, browserApi)
}

export async function heartbeatActiveScanSession(engine, patch = {}, browserApi = browser, options = {}) {
    const key = normalizeEngine(engine)
    if (!key) return null
    const minWriteMs = Number.isFinite(Number(options?.minWriteMs))
        ? Math.max(0, Number(options.minWriteMs))
        : ACTIVE_SCAN_SESSION_MIN_WRITE_MS
    const state = await loadActiveScanSessions(browserApi)
    const current = state.sessions[key]
    if (!current) return null
    const nowMs = Date.now()
    const lastMs = Date.parse(current.heartbeatAt || current.updatedAt || current.startedAt || 0) || 0
    if (!options?.force && lastMs && (nowMs - lastMs) < minWriteMs) {
        return clone(current)
    }
    const nowIso = new Date(nowMs).toISOString()
    const next = normalizeSession(key, Object.assign({}, current, patch || {}, {
        status: "running",
        updatedAt: nowIso,
        heartbeatAt: nowIso
    }))
    if (!next) return null
    state.sessions[key] = next
    state.updatedAt = nowIso
    return writeState(state, browserApi)
}

export async function clearActiveScanSession(engine, browserApi = browser) {
    const key = normalizeEngine(engine)
    if (!key) return null
    const state = await loadActiveScanSessions(browserApi)
    state.sessions[key] = null
    state.updatedAt = new Date().toISOString()
    return writeState(state, browserApi)
}

export async function clearStaleActiveScanSessions(browserApi = browser, { staleMs = ACTIVE_SCAN_SESSION_STALE_MS * 20 } = {}) {
    const state = await loadActiveScanSessions(browserApi)
    const now = Date.now()
    let changed = false
    ENGINES.forEach((engine) => {
        const session = state.sessions[engine]
        if (!session) return
        const lastMs = Date.parse(session.heartbeatAt || session.updatedAt || session.startedAt || 0) || 0
        if (!lastMs || (now - lastMs) > staleMs) {
            state.sessions[engine] = null
            changed = true
        }
    })
    if (!changed) return clone(state)
    state.updatedAt = new Date().toISOString()
    return writeState(state, browserApi)
}

export function isActiveScanSessionFresh(session, { now = Date.now(), staleMs = ACTIVE_SCAN_SESSION_STALE_MS } = {}) {
    if (!session || typeof session !== "object") return false
    if (String(session.status || "").trim().toLowerCase() !== "running") return false
    const lastMs = Date.parse(session.heartbeatAt || session.updatedAt || session.startedAt || 0) || 0
    if (!lastMs) return false
    return (now - lastMs) <= staleMs
}

export function getActiveScanSessionFlags(state, options = {}) {
    const normalized = normalizeState(state)
    return {
        dast: isActiveScanSessionFresh(normalized.sessions.dast, options),
        iast: isActiveScanSessionFresh(normalized.sessions.iast, options),
        sast: isActiveScanSessionFresh(normalized.sessions.sast, options),
        sca: isActiveScanSessionFresh(normalized.sessions.sca, options)
    }
}

export function getFreshActiveScanSession(state, engine, options = {}) {
    const normalized = normalizeState(state)
    const key = normalizeEngine(engine)
    if (!key) return null
    const session = normalized.sessions[key]
    if (!isActiveScanSessionFresh(session, options)) {
        return null
    }
    return clone(session)
}

export async function loadFreshActiveScanSession(engine, browserApi = browser, options = {}) {
    const state = await loadActiveScanSessions(browserApi)
    return getFreshActiveScanSession(state, engine, options)
}
