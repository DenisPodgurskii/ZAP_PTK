function clone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function normalizeStatus(status) {
    return String(status || "queued").toLowerCase()
}

function isTerminalStatus(status) {
    return ["completed", "failed", "canceled", "timed_out"].includes(normalizeStatus(status))
}

function mergeSide(existing = null, payload = null) {
    const nextPayload = payload && typeof payload === "object" ? payload : {}
    const next = {
        jobId: nextPayload?.jobId || existing?.jobId || null,
        status: normalizeStatus(nextPayload?.status || existing?.status || "queued"),
        acceptedAt: nextPayload?.acceptedAt || existing?.acceptedAt || null,
        startedAt: nextPayload?.startedAt || existing?.startedAt || null,
        finishedAt: nextPayload?.finishedAt || existing?.finishedAt || null,
        requestedAt: nextPayload?.requestedAt || existing?.requestedAt || new Date().toISOString(),
        progress: nextPayload?.progress || existing?.progress || null,
        summary: nextPayload?.summary || existing?.summary || null,
        observations: Array.isArray(nextPayload?.observations) ? nextPayload.observations : (existing?.observations || []),
        artifacts: nextPayload?.artifacts || existing?.artifacts || null,
        sessionProfile: nextPayload?.sessionProfile || existing?.sessionProfile || null,
        comparableResponse: nextPayload?.comparableResponse || existing?.comparableResponse || null,
        error: nextPayload?.error || existing?.error || null
    }
    if (isTerminalStatus(next.status) && !next.finishedAt) {
        next.finishedAt = new Date().toISOString()
    }
    return next
}

export class AuthzDiffRunStore {
    constructor() {
        this.byRunId = new Map()
    }

    list() {
        return Array.from(this.byRunId.values())
            .sort((a, b) => String(b?.requestedAt || "").localeCompare(String(a?.requestedAt || "")))
            .map((entry) => clone(entry))
    }

    get(runId) {
        const key = String(runId || "").trim()
        if (!key) return null
        const run = this.byRunId.get(key)
        return run ? clone(run) : null
    }

    upsert(runId, payload = {}) {
        const key = String(runId || "").trim()
        if (!key) return null
        const existing = this.byRunId.get(key) || null
        const next = {
            runId: key,
            candidateId: payload?.candidateId || existing?.candidateId || null,
            status: normalizeStatus(payload?.status || existing?.status || "queued"),
            stage: String(payload?.stage || existing?.stage || "queued"),
            requestedAt: payload?.requestedAt || existing?.requestedAt || new Date().toISOString(),
            startedAt: payload?.startedAt || existing?.startedAt || null,
            finishedAt: payload?.finishedAt || existing?.finishedAt || null,
            updatedAt: new Date().toISOString(),
            baselineSession: payload?.baselineSession || existing?.baselineSession || null,
            comparisonSession: payload?.comparisonSession || existing?.comparisonSession || null,
            baselineRun: mergeSide(existing?.baselineRun || null, payload?.baselineRun || null),
            comparisonRun: mergeSide(existing?.comparisonRun || null, payload?.comparisonRun || null),
            baselineResponse: payload?.baselineResponse || existing?.baselineResponse || null,
            comparisonResponse: payload?.comparisonResponse || existing?.comparisonResponse || null,
            objectSwap: payload?.objectSwap || existing?.objectSwap || null,
            diff: payload?.diff || existing?.diff || null,
            error: payload?.error || existing?.error || null
        }
        if ((next.startedAt === null) && (next.status === "running" || next.stage === "polling_jobs" || next.stage === "diffing")) {
            next.startedAt = new Date().toISOString()
        }
        if (isTerminalStatus(next.status) && !next.finishedAt) {
            next.finishedAt = new Date().toISOString()
        }
        this.byRunId.set(key, next)
        return clone(next)
    }
}

export default AuthzDiffRunStore
