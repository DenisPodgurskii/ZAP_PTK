function clone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function buildEvidenceId() {
    return `evidence_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`
}

export class EvidencePackageStore {
    constructor() {
        this.byId = new Map()
    }

    save(evidencePackage = {}) {
        const id = String(evidencePackage?.id || buildEvidenceId()).trim()
        if (!id) return null
        const next = {
            id,
            createdAt: evidencePackage?.createdAt || new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            candidateId: evidencePackage?.candidateId || null,
            title: String(evidencePackage?.title || "").trim(),
            summary: String(evidencePackage?.summary || "").trim(),
            routeKey: evidencePackage?.routeKey || null,
            sessions: evidencePackage?.sessions || null,
            objectSwap: evidencePackage?.objectSwap || null,
            diff: evidencePackage?.diff || null,
            request: evidencePackage?.request || null,
            baselineResponse: evidencePackage?.baselineResponse || null,
            comparisonResponse: evidencePackage?.comparisonResponse || null,
            workflowSummary: evidencePackage?.workflowSummary || null,
            reproductionSteps: Array.isArray(evidencePackage?.reproductionSteps) ? evidencePackage.reproductionSteps : [],
            tags: Array.isArray(evidencePackage?.tags) ? evidencePackage.tags : []
        }
        this.byId.set(id, next)
        return clone(next)
    }

    get(id = null) {
        const key = String(id || "").trim()
        if (!key) return null
        const stored = this.byId.get(key) || null
        return stored ? clone(stored) : null
    }

    list({ candidateId = null } = {}) {
        const normalizedCandidateId = String(candidateId || "").trim()
        return Array.from(this.byId.values())
            .filter((entry) => !normalizedCandidateId || String(entry?.candidateId || "").trim() === normalizedCandidateId)
            .sort((a, b) => String(b?.createdAt || "").localeCompare(String(a?.createdAt || "")))
            .map((entry) => clone(entry))
    }
}

export default EvidencePackageStore
