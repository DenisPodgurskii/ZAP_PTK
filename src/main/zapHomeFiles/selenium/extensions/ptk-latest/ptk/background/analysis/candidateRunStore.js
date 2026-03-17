function clone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function isTerminalStatus(status) {
    const normalized = String(status || "").toLowerCase()
    return ["completed", "failed", "canceled", "timed_out"].includes(normalized)
}

export class CandidateRunStore {
    constructor() {
        this.byCandidateId = new Map()
        this.byJobId = new Map()
    }

    get(candidateId) {
        const key = String(candidateId || "").trim()
        if (!key) return null
        const run = this.byCandidateId.get(key)
        return run ? clone(run) : null
    }

    getByJobId(jobId) {
        const key = String(jobId || "").trim()
        if (!key) return null
        const run = this.byJobId.get(key)
        return run ? clone(run) : null
    }

    upsert(candidateId, payload = {}) {
        const candidateKey = String(candidateId || "").trim()
        if (!candidateKey) return null
        const existing = this.byCandidateId.get(candidateKey) || null
        const next = {
            candidateId: candidateKey,
            jobId: payload?.jobId || existing?.jobId || null,
            status: String(payload?.status || existing?.status || "queued").toLowerCase(),
            acceptedAt: payload?.acceptedAt || existing?.acceptedAt || null,
            startedAt: payload?.startedAt || existing?.startedAt || null,
            finishedAt: payload?.finishedAt || existing?.finishedAt || null,
            requestedAt: payload?.requestedAt || existing?.requestedAt || new Date().toISOString(),
            progress: payload?.progress || existing?.progress || null,
            summary: payload?.summary || existing?.summary || null,
            observations: Array.isArray(payload?.observations) ? payload.observations : (existing?.observations || []),
            artifacts: payload?.artifacts || existing?.artifacts || null,
            error: payload?.error || existing?.error || null,
            updatedAt: new Date().toISOString()
        }
        if (isTerminalStatus(next.status) && !next.finishedAt) {
            next.finishedAt = new Date().toISOString()
        }
        this.byCandidateId.set(candidateKey, next)
        if (next.jobId) {
            this.byJobId.set(String(next.jobId), next)
        }
        return clone(next)
    }

    applyJobState(job = {}, fallbackCandidateId = null) {
        const jobId = String(job?.jobId || "").trim()
        if (!jobId) return null
        const existing = this.byJobId.get(jobId) || null
        const candidateId = String(existing?.candidateId || fallbackCandidateId || "").trim()
        if (!candidateId) return null
        return this.upsert(candidateId, {
            jobId,
            status: String(job?.status || existing?.status || "queued").toLowerCase(),
            acceptedAt: job?.acceptedAt || existing?.acceptedAt || null,
            startedAt: job?.startedAt || existing?.startedAt || null,
            finishedAt: job?.finishedAt || existing?.finishedAt || null,
            progress: job?.progress || existing?.progress || null,
            summary: job?.summary || existing?.summary || null,
            observations: Array.isArray(job?.observations) ? job.observations : (existing?.observations || []),
            artifacts: job?.artifacts || existing?.artifacts || null,
            error: job?.error || existing?.error || null
        })
    }
}

export default CandidateRunStore
