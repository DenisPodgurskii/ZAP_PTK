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

function normalizeHostValue(host) {
    if (host === null || host === undefined) return ""
    const raw = String(host).trim()
    if (!raw) return ""
    try {
        if (/^https?:\/\//i.test(raw)) {
            return new URL(raw).host.toLowerCase()
        }
    } catch (_) {
        // fall through to string normalization
    }
    return raw
        .replace(/^https?:\/\//i, "")
        .replace(/\/+.*$/, "")
        .toLowerCase()
}

function resolveHostFromRouteKey(routeKey = null) {
    const raw = String(routeKey || "").trim()
    if (!raw) return ""
    const host = raw.split("|")[0] || ""
    return normalizeHostValue(host)
}

function resolveHostFromEvidencePackage(evidencePackage = {}) {
    const direct = normalizeHostValue(evidencePackage?.host || null)
    if (direct) return direct
    const requestUrl = String(evidencePackage?.request?.url || "").trim()
    if (requestUrl) {
        const host = normalizeHostValue(requestUrl)
        if (host) return host
    }
    const sessionHost = normalizeHostValue(
        evidencePackage?.sessions?.baseline?.host
        || evidencePackage?.sessions?.comparison?.host
        || null
    )
    if (sessionHost) return sessionHost
    return resolveHostFromRouteKey(evidencePackage?.routeKey || null)
}

function compareIsoDesc(left = null, right = null) {
    return String(right || "").localeCompare(String(left || ""))
}

export class EvidencePackageStore {
    constructor({
        storage = null,
        storageKey = "ptk_bugbounty_evidence_packages_v1",
        now = () => new Date().toISOString()
    } = {}) {
        this.storage = storage
        this.storageKey = storageKey
        this.now = now
        this._loaded = false
        this._packages = []
    }

    normalizeHost(host) {
        return normalizeHostValue(host)
    }

    async load() {
        if (this._loaded) return this._packages
        const stored = await this.storage?.getItem?.(this.storageKey)
        if (Array.isArray(stored?.packages)) {
            this._packages = stored.packages.map((entry) => clone(entry))
        } else if (Array.isArray(stored)) {
            this._packages = stored.map((entry) => clone(entry))
        } else {
            this._packages = []
        }
        this._loaded = true
        return this._packages
    }

    async _persist() {
        await this.storage?.setItem?.(this.storageKey, {
            packages: this._packages
        })
    }

    _filterPackages({ candidateId = null, host = null, scanId = null } = {}) {
        const normalizedCandidateId = String(candidateId || "").trim()
        const normalizedHost = this.normalizeHost(host)
        const normalizedScanId = String(scanId || "").trim()
        return this._packages.filter((entry) => {
            if (normalizedScanId && String(entry?.scanId || "").trim() !== normalizedScanId) {
                return false
            }
            if (!normalizedScanId && normalizedHost && this.normalizeHost(entry?.host || "") !== normalizedHost) {
                return false
            }
            if (normalizedCandidateId && String(entry?.candidateId || "").trim() !== normalizedCandidateId) {
                return false
            }
            return true
        })
    }

    async save(evidencePackage = {}) {
        await this.load()
        const id = String(evidencePackage?.id || buildEvidenceId()).trim()
        if (!id) return null
        const existing = this._packages.find((entry) => String(entry?.id || "") === id) || null
        const next = {
            id,
            createdAt: existing?.createdAt || evidencePackage?.createdAt || this.now(),
            updatedAt: this.now(),
            scanId: evidencePackage?.scanId || existing?.scanId || null,
            host: resolveHostFromEvidencePackage(evidencePackage) || existing?.host || null,
            candidateId: evidencePackage?.candidateId || existing?.candidateId || null,
            title: String(evidencePackage?.title || existing?.title || "").trim(),
            summary: String(evidencePackage?.summary || existing?.summary || "").trim(),
            routeKey: evidencePackage?.routeKey || existing?.routeKey || null,
            sessions: evidencePackage?.sessions || existing?.sessions || null,
            objectSwap: evidencePackage?.objectSwap || existing?.objectSwap || null,
            diff: evidencePackage?.diff || existing?.diff || null,
            request: evidencePackage?.request || existing?.request || null,
            baselineResponse: evidencePackage?.baselineResponse || existing?.baselineResponse || null,
            comparisonResponse: evidencePackage?.comparisonResponse || existing?.comparisonResponse || null,
            workflowSummary: evidencePackage?.workflowSummary || existing?.workflowSummary || null,
            reproductionSteps: Array.isArray(evidencePackage?.reproductionSteps)
                ? evidencePackage.reproductionSteps
                : (Array.isArray(existing?.reproductionSteps) ? existing.reproductionSteps : []),
            tags: Array.isArray(evidencePackage?.tags)
                ? evidencePackage.tags
                : (Array.isArray(existing?.tags) ? existing.tags : [])
        }
        this._packages = this._packages.filter((entry) => String(entry?.id || "") !== id)
        this._packages.push(next)
        await this._persist()
        return clone(next)
    }

    async importMany(evidencePackages = [], defaults = {}) {
        await this.load()
        const items = Array.isArray(evidencePackages) ? evidencePackages : []
        const imported = []
        for (const entry of items) {
            if (!entry || typeof entry !== "object") continue
            const saved = await this.save({
                ...entry,
                scanId: entry?.scanId || defaults?.scanId || null,
                host: entry?.host || defaults?.host || null
            })
            if (saved) imported.push(saved)
        }
        return imported
    }

    async get(id = null) {
        await this.load()
        const key = String(id || "").trim()
        if (!key) return null
        const stored = this._packages.find((entry) => String(entry?.id || "") === key) || null
        return stored ? clone(stored) : null
    }

    async list({ candidateId = null, host = null, scanId = null } = {}) {
        await this.load()
        return this._filterPackages({ candidateId, host, scanId })
            .sort((a, b) => compareIsoDesc(a?.updatedAt || a?.createdAt, b?.updatedAt || b?.createdAt))
            .map((entry) => clone(entry))
    }

    async clearHost(host = null) {
        await this.load()
        const normalizedHost = this.normalizeHost(host)
        if (!normalizedHost) return 0
        const before = this._packages.length
        this._packages = this._packages.filter((entry) => this.normalizeHost(entry?.host || "") !== normalizedHost)
        const deleted = before - this._packages.length
        if (deleted > 0) {
            await this._persist()
        }
        return deleted
    }
}

export default EvidencePackageStore
