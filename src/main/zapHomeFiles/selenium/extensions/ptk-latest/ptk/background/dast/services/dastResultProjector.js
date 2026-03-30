const DEFAULT_UI_SCAN_RESULT_BYTE_LIMIT = 8 * 1024 * 1024
const DEFAULT_UI_SCAN_RESULT_LIMITS = Object.freeze({
    maxFindings: 5000,
    maxGroups: 1000,
    maxRequests: 1500,
    maxAttacksPerRequest: 200,
    maxRuntimeEvents: 200,
    maxStringLength: 2048,
    maxArrayItems: 100,
    maxObjectKeys: 64,
    maxDepth: 4
})
const DEFAULT_UI_ANALYSIS_LIMITS = Object.freeze({
    ...DEFAULT_UI_SCAN_RESULT_LIMITS,
    maxDepth: 5
})

export class DastResultProjector {
    constructor({
        analysisService = null,
        byteLimit = DEFAULT_UI_SCAN_RESULT_BYTE_LIMIT,
        limits = DEFAULT_UI_SCAN_RESULT_LIMITS,
        analysisLimits = DEFAULT_UI_ANALYSIS_LIMITS
    } = {}) {
        this.analysisService = analysisService
        this.byteLimit = byteLimit
        this.limits = limits
        this.analysisLimits = analysisLimits
    }

    estimatePayloadSize(value) {
        try {
            const json = JSON.stringify(value || {})
            return (new TextEncoder()).encode(json).length
        } catch (_) {
            return Number.MAX_SAFE_INTEGER
        }
    }

    truncateString(value, maxLen = this.limits.maxStringLength) {
        if (typeof value !== "string") return value
        if (value.length <= maxLen) return value
        return value.slice(0, Math.max(0, maxLen - 1)) + "…"
    }

    sanitizeUiValue(value, depth = 0, limits = this.limits) {
        if (value === null || value === undefined) return value
        if (typeof value === "string") {
            return this.truncateString(value, limits.maxStringLength)
        }
        if (typeof value === "number" || typeof value === "boolean") {
            return value
        }
        if (depth >= limits.maxDepth) {
            return undefined
        }
        if (Array.isArray(value)) {
            return value
                .slice(0, limits.maxArrayItems)
                .map((item) => this.sanitizeUiValue(item, depth + 1, limits))
                .filter((item) => item !== undefined)
        }
        if (typeof value === "object") {
            const out = {}
            const keys = Object.keys(value).slice(0, limits.maxObjectKeys)
            keys.forEach((key) => {
                const sanitized = this.sanitizeUiValue(value[key], depth + 1, limits)
                if (sanitized !== undefined) {
                    out[key] = sanitized
                }
            })
            return out
        }
        return undefined
    }

    buildUiRequestSummary(source) {
        if (!source || typeof source !== "object") return null
        const request = source.request && typeof source.request === "object" ? source.request : source
        const summary = {}
        if (request.url) summary.url = this.truncateString(String(request.url), 4096)
        if (request.ui_url) summary.ui_url = this.truncateString(String(request.ui_url), 4096)
        if (request.method) summary.method = String(request.method)
        if (request.target) summary.target = this.truncateString(String(request.target), 1024)
        if (request.discoverySource) summary.discoverySource = this.truncateString(String(request.discoverySource), 128)
        if (request.discoveryLabel) summary.discoveryLabel = this.truncateString(String(request.discoveryLabel), 256)
        if (request.discoveryParentUrl) summary.discoveryParentUrl = this.truncateString(String(request.discoveryParentUrl), 4096)
        if (typeof request.raw === "string" && request.raw) {
            summary.raw = this.truncateString(request.raw, 8192)
        }
        if (request.headers) {
            summary.headers = this.sanitizeUiValue(request.headers, 0, this.limits)
        }
        if (typeof request.body === "string" && request.body) {
            summary.body = this.truncateString(request.body, 8192)
        } else if (request.body && typeof request.body === "object") {
            const preview = typeof request.body.text === "string"
                ? request.body.text
                : (typeof request.body.preview === "string" ? request.body.preview : null)
            if (preview) {
                summary.body = this.truncateString(preview, 8192)
            }
        }
        return Object.keys(summary).length ? summary : null
    }

    buildUiResponseSummary(source) {
        if (!source || typeof source !== "object") return null
        const response = source.response && typeof source.response === "object" ? source.response : source
        const summary = {}
        const statusCode = response.statusCode ?? response.status
        if (statusCode !== undefined && statusCode !== null) summary.statusCode = statusCode
        if (response.status !== undefined && response.status !== null) summary.status = response.status
        if (response.statusMessage) summary.statusMessage = this.truncateString(String(response.statusMessage), 256)
        if (response.statusText) summary.statusText = this.truncateString(String(response.statusText), 256)
        if (response.errorName) summary.errorName = this.truncateString(String(response.errorName), 128)
        if (response.errorMessage) summary.errorMessage = this.truncateString(String(response.errorMessage), 512)
        if (response.errorCause) summary.errorCause = this.truncateString(String(response.errorCause), 512)
        if (typeof response.timeMs === "number") summary.timeMs = response.timeMs
        if (typeof response.length === "number") summary.length = response.length
        if (typeof response.raw === "string" && response.raw) {
            summary.raw = this.truncateString(response.raw, 8192)
        }
        if (typeof response.statusLine === "string" && response.statusLine) {
            summary.statusLine = this.truncateString(response.statusLine, 512)
        }
        if (response.headers) {
            summary.headers = this.sanitizeUiValue(response.headers, 0, this.limits)
        }
        if (typeof response.body === "string" && response.body) {
            summary.body = this.truncateString(response.body, 8192)
        } else if (response.body && typeof response.body === "object") {
            const preview = typeof response.body.preview === "string"
                ? response.body.preview
                : (typeof response.body.text === "string" ? response.body.text : null)
            if (preview) {
                summary.body = this.truncateString(preview, 8192)
            }
        }
        return Object.keys(summary).length ? summary : null
    }

    buildUiAttackSummary(attack) {
        if (!attack || typeof attack !== "object") return null
        const summary = {
            id: attack.id || null,
            findingId: attack.findingId || null,
            success: !!attack.success
        }
        const scalarKeys = [
            "proof",
            "param",
            "name",
            "moduleId",
            "moduleName",
            "ruleId",
            "ruleName",
            "category",
            "severity",
            "vulnId",
            "outputKind",
            "reconKind",
            "presentationAggregate",
            "uiSurface",
            "payload"
        ]
        scalarKeys.forEach((key) => {
            if (attack[key] !== undefined && attack[key] !== null) {
                summary[key] = this.sanitizeUiValue(attack[key], 0, this.limits)
            }
        })
        const request = this.buildUiRequestSummary(attack.request)
        if (request) summary.request = request
        const response = this.buildUiResponseSummary(attack.response || attack)
        if (response) summary.response = response
        if (attack.metadata && typeof attack.metadata === "object") {
            summary.metadata = this.sanitizeUiValue(attack.metadata, 0, this.limits)
        }
        Object.keys(summary).forEach((key) => {
            if (summary[key] === null || summary[key] === undefined) {
                delete summary[key]
            }
        })
        return summary
    }

    buildUiRequestRecord(record, limits = this.limits, fallbackId = null) {
        if (!record || typeof record !== "object") return null
        const requestId = record.id || null
        const summary = {
            id: requestId || fallbackId || null,
            original: null,
            attacks: []
        }
        const originalRequest = this.buildUiRequestSummary(record.original || null)
        const originalResponse = this.buildUiResponseSummary(record.original?.response || null)
        if (originalRequest || originalResponse) {
            summary.original = {}
            if (originalRequest) summary.original.request = originalRequest
            if (originalResponse) summary.original.response = originalResponse
        }
        const attacks = Array.isArray(record.attacks) ? record.attacks : []
        const prioritizedAttacks = this.prioritizeAttacksForUi(attacks, limits.maxAttacksPerRequest)
        summary.attacks = prioritizedAttacks
            .map((attack) => this.buildUiAttackSummary(attack))
            .filter(Boolean)
        if (!summary.id) return null
        return summary
    }

    getAttackStatusCode(attack) {
        const value = attack?.response?.statusCode ?? attack?.statusCode ?? attack?.response?.status ?? null
        return Number.isFinite(Number(value)) ? Number(value) : null
    }

    isSuspiciousResponseAttack(attack) {
        const statusCode = this.getAttackStatusCode(attack)
        return Number.isFinite(statusCode) && statusCode >= 400 && statusCode <= 599
    }

    isPriorityAttackForUi(attack) {
        return Boolean(
            attack?.findingId
            || attack?.success === true
            || this.isSuspiciousResponseAttack(attack)
        )
    }

    prioritizeAttacksForUi(attacks, maxAttacks = this.limits.maxAttacksPerRequest) {
        const list = Array.isArray(attacks) ? attacks : []
        if (!Number.isFinite(maxAttacks) || maxAttacks <= 0) return []
        if (list.length <= maxAttacks) return list.slice()

        const prioritized = []
        const fallback = []
        list.forEach((attack) => {
            if (this.isPriorityAttackForUi(attack)) {
                prioritized.push(attack)
            } else {
                fallback.push(attack)
            }
        })

        if (prioritized.length >= maxAttacks) {
            return prioritized.slice(0, maxAttacks)
        }

        return prioritized.concat(fallback.slice(0, Math.max(0, maxAttacks - prioritized.length)))
    }

    buildUiFindingSummary(finding) {
        if (!finding || typeof finding !== "object") return null
        const summary = {}
        const allowedKeys = [
            "id",
            "engine",
            "scanId",
            "moduleId",
            "moduleName",
            "ruleId",
            "ruleName",
            "vulnId",
            "category",
            "severity",
            "name",
            "title",
            "description",
            "recommendation",
            "links",
            "owasp",
            "cwe",
            "tags",
            "confidence",
            "outputKind",
            "reconKind",
            "presentationAggregate",
            "uiSurface",
            "findingKind",
            "location"
        ]
        allowedKeys.forEach((key) => {
            if (finding[key] !== undefined && finding[key] !== null) {
                summary[key] = this.sanitizeUiValue(finding[key], 0, this.limits)
            }
        })
        const dastEvidence = finding?.evidence?.dast
        if (dastEvidence && typeof dastEvidence === "object") {
            summary.evidence = {
                dast: this.sanitizeUiValue({
                    attackId: dastEvidence.attackId || null,
                    requestId: dastEvidence.requestId || null,
                    resolverKey: dastEvidence.resolverKey || null,
                    param: dastEvidence.param || null,
                    payload: dastEvidence.payload || null,
                    proof: dastEvidence.proof || null
                }, 0, this.limits)
            }
        }
        return summary
    }

    buildUiReconSummary(observation) {
        if (!observation || typeof observation !== "object") return null
        const summary = {}
        const allowedKeys = [
            "id",
            "engine",
            "scanId",
            "moduleId",
            "moduleName",
            "ruleId",
            "ruleName",
            "category",
            "severity",
            "outputKind",
            "reconKind",
            "presentationAggregate",
            "uiSurface",
            "description",
            "recommendation",
            "links",
            "tags",
            "location",
            "createdAt"
        ]
        allowedKeys.forEach((key) => {
            if (observation[key] !== undefined && observation[key] !== null) {
                summary[key] = this.sanitizeUiValue(observation[key], 0, this.limits)
            }
        })
        const dastEvidence = observation?.evidence?.dast
        if (dastEvidence && typeof dastEvidence === "object") {
            summary.evidence = {
                dast: this.sanitizeUiValue({
                    attackId: dastEvidence.attackId || null,
                    requestId: dastEvidence.requestId || null,
                    resolverKey: dastEvidence.resolverKey || null,
                    param: dastEvidence.param || null,
                    payload: dastEvidence.payload || null,
                    proof: dastEvidence.proof || null
                }, 0, this.limits)
            }
        }
        return summary
    }

    buildScanResultUiSnapshot(scanResult) {
        const source = scanResult && typeof scanResult === "object" ? scanResult : {}
        const snapshot = {}
        const passKeys = [
            "engine",
            "type",
            "scanId",
            "host",
            "date",
            "startedAt",
            "finishedAt",
            "finished"
        ]
        passKeys.forEach((key) => {
            if (source[key] !== undefined) {
                snapshot[key] = source[key]
            }
        })
        snapshot.stats = this.sanitizeUiValue(source.stats || {}, 0, this.limits) || {}
        if (source.scanStats) {
            snapshot.scanStats = this.sanitizeUiValue(source.scanStats, 0, this.limits)
        }
        if (source.settings) {
            snapshot.settings = this.sanitizeUiValue(source.settings, 0, this.limits)
        }
        if (source.analysis && typeof source.analysis === "object") {
            snapshot.analysis = this.sanitizeUiValue(source.analysis, 0, this.analysisLimits)
        }
        if (source.analysisVersion) {
            snapshot.analysisVersion = source.analysisVersion
        }
        const findings = Array.isArray(source.findings) ? source.findings : []
        const recon = Array.isArray(source.recon) ? source.recon : []
        snapshot.findings = findings
            .concat(recon)
            .slice(0, this.limits.maxFindings)
            .map((finding) => this.buildUiFindingSummary(finding))
            .filter(Boolean)
        const groups = Array.isArray(source.groups) ? source.groups : []
        snapshot.groups = groups
            .slice(0, this.limits.maxGroups)
            .map((group) => this.sanitizeUiValue(group, 0, this.limits))
            .filter(Boolean)
        const requests = Array.isArray(source.requests) ? source.requests : []
        snapshot.requests = requests
            .slice(0, this.limits.maxRequests)
            .map((record, index) => this.buildUiRequestRecord(record, this.limits, `req-${index + 1}`))
            .filter(Boolean)
        if (Array.isArray(source.runtimeEvents) && source.runtimeEvents.length) {
            snapshot.runtimeEvents = source.runtimeEvents
                .slice(-this.limits.maxRuntimeEvents)
                .map((event) => this.sanitizeUiValue(event, 0, this.limits))
                .filter(Boolean)
        }
        return snapshot
    }

    enforceUiSnapshotSize(snapshot, byteLimit = this.byteLimit) {
        const out = snapshot && typeof snapshot === "object"
            ? JSON.parse(JSON.stringify(snapshot))
            : {}
        const resultMeta = {
            truncated: false,
            initialBytes: this.estimatePayloadSize(out),
            finalBytes: 0
        }
        let size = resultMeta.initialBytes
        if (size > byteLimit) {
            resultMeta.truncated = true
            out.findings = []
            size = this.estimatePayloadSize(out)
        }
        if (size > byteLimit) {
            const requests = Array.isArray(out.requests) ? out.requests : []
            requests.forEach((request) => {
                if (!Array.isArray(request?.attacks)) return
                request.attacks = request.attacks.filter((attack) => this.isPriorityAttackForUi(attack))
                if (request.attacks.length === 0) {
                    request.attacks = []
                }
            })
            size = this.estimatePayloadSize(out)
        }
        if (size > byteLimit) {
            const requests = Array.isArray(out.requests) ? out.requests : []
            requests.forEach((request) => {
                if (!Array.isArray(request?.attacks)) return
                request.attacks = request.attacks.slice(0, 50)
            })
            size = this.estimatePayloadSize(out)
        }
        if (size > byteLimit) {
            const requests = Array.isArray(out.requests) ? out.requests : []
            out.requests = requests.slice(0, 500)
            size = this.estimatePayloadSize(out)
        }
        while (size > byteLimit && Array.isArray(out.requests) && out.requests.length > 20) {
            out.requests = out.requests.slice(0, Math.max(20, Math.floor(out.requests.length / 2)))
            size = this.estimatePayloadSize(out)
        }
        resultMeta.finalBytes = size
        if (resultMeta.truncated) {
            out.__uiSnapshot = resultMeta
        }
        return out
    }

    cloneScanResultForUi(scanResult, { engineIsRunning = false } = {}) {
        const source = scanResult && typeof scanResult === "object" ? scanResult : {}
        const snapshot = this.buildScanResultUiSnapshot(source)
        const bounded = this.enforceUiSnapshotSize(snapshot, this.byteLimit)
        if (bounded && typeof bounded === "object") {
            bounded.__normalized = true
        }
        return bounded
    }
}

export default DastResultProjector
