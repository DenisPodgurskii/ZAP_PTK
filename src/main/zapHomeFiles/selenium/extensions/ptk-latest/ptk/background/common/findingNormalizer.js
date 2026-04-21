import CryptoES from "../../packages/crypto-es/index.js"

const VALID_ENGINES = new Set(["DAST", "SAST", "IAST", "SCA"])
const ENGINE_LOCATION_KIND = {
    DAST: "http",
    SAST: "code",
    IAST: "runtime",
    SCA: "package"
}
const VALID_SEVERITIES = new Set(["info", "low", "medium", "high", "critical"])

function ensureString(value) {
    if (value === undefined || value === null) return null
    try {
        const str = String(value).trim()
        return str.length ? str : null
    } catch (_) {
        return null
    }
}

function normalizeSeverity(value) {
    const normalized = ensureString(value)?.toLowerCase()
    if (!normalized) return "info"
    if (VALID_SEVERITIES.has(normalized)) return normalized
    if (!Number.isNaN(Number(normalized))) {
        const numeric = Number(normalized)
        if (numeric >= 9) return "critical"
        if (numeric >= 7) return "high"
        if (numeric >= 4) return "medium"
        if (numeric > 0) return "low"
    }
    return "info"
}

function ensureMeaningfulTaxonomyValue(value) {
    const str = ensureString(value)
    if (!str) return null
    if (str.toLowerCase() === "other") return null
    return str
}

function stableStringify(value) {
    if (value === null || value === undefined) return ""
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value)
    if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`
    if (typeof value === "object") {
        return `{${Object.keys(value).sort((a, b) => a.localeCompare(b)).map((key) => `${key}:${stableStringify(value[key])}`).join(",")}}`
    }
    return String(value)
}

function hashHex(payload) {
    return CryptoES.SHA256(String(payload || "")).toString(CryptoES.enc.Hex)
}

function truncateString(value, maxLength = 250) {
    const str = ensureString(value)
    if (!str) return null
    if (!Number.isFinite(maxLength) || maxLength <= 0) return str
    if (str.length <= maxLength) return str
    return `${str.slice(0, Math.max(0, maxLength - 3))}...`
}

function toUniqueStringArray(...sources) {
    const result = []
    const seen = new Set()
    const process = (value) => {
        if (value === undefined || value === null) return
        if (Array.isArray(value)) {
            value.forEach(process)
            return
        }
        const str = ensureString(value)
        if (str && !seen.has(str)) {
            seen.add(str)
            result.push(str)
        }
    }
    sources.forEach(process)
    return result
}

function normalizeOwaspEntry(entry) {
    if (entry === undefined || entry === null) return null
    if (typeof entry === "string" || typeof entry === "number") {
        return ensureString(entry)
    }
    if (typeof entry !== "object") return null
    const id = ensureString(entry.id || entry.key || entry.category)
    const version = ensureString(entry.version || entry.year || entry.top10 || entry.owasp_version)
    const name = ensureString(entry.name || entry.title || entry.description)
    const fallback = ensureString(entry.value || entry.label)
    if (id && version && name) return `${id}:${version} - ${name}`
    if (id && version) return `${id}:${version}`
    if (id) return id
    if (version && name) return `${version} - ${name}`
    if (version) return version
    return fallback || null
}

function normalizeOwaspArray(...sources) {
    const result = []
    const seen = new Set()
    const addEntry = (value) => {
        if (value === undefined || value === null) return
        if (Array.isArray(value)) {
            value.forEach(addEntry)
            return
        }
        const normalized = normalizeOwaspEntry(value)
        if (!normalized) return
        if (seen.has(normalized)) return
        seen.add(normalized)
        result.push(normalized)
    }
    sources.forEach(addEntry)
    return result
}

function pickObject(...candidates) {
    for (const candidate of candidates) {
        if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue
        if (!Object.keys(candidate).length) continue
        return { ...candidate }
    }
    return {}
}

function normalizeTags(...sources) {
    const seen = new Set()
    const tags = []
    sources.forEach(entry => {
        if (!Array.isArray(entry)) return
        entry.forEach(tag => {
            const value = ensureString(tag)
            if (!value || seen.has(value)) return
            seen.add(value)
            tags.push(value)
        })
    })
    return tags
}

function extractMetaField(source = {}, field) {
    if (!source || typeof source !== "object") return null
    const direct = ensureMeaningfulTaxonomyValue(source[field])
    if (direct) return direct
    if (source.metadata && typeof source.metadata === "object") {
        const nested = ensureMeaningfulTaxonomyValue(source.metadata[field])
        if (nested) return nested
    }
    return null
}

function resolveTaxonomyField(field, finding, ruleMeta, moduleMeta, fallback) {
    const fromFinding = ensureMeaningfulTaxonomyValue(finding?.[field])
    if (fromFinding) return fromFinding
    const fromRule = extractMetaField(ruleMeta, field)
    if (fromRule) return fromRule
    const fromModule = extractMetaField(moduleMeta, field)
    if (fromModule) return fromModule
    return fallback
}

function normalizeLocation(location, engine) {
    const loc = (location && typeof location === "object" && !Array.isArray(location))
        ? { ...location }
        : {}
    const kind = ENGINE_LOCATION_KIND[engine] || loc.kind || "general"
    loc.kind = kind

    if (engine === "DAST") {
        loc.url = loc.url || loc.pageUrl || loc.href || null
        loc.method = loc.method || loc.httpMethod || null
    } else if (engine === "SAST") {
        loc.file = loc.file || loc.path || null
        loc.line = loc.line ?? loc.startLine ?? loc.row ?? null
        loc.column = loc.column ?? loc.startColumn ?? null
        loc.url = loc.url || loc.pageUrl || null
    } else if (engine === "IAST") {
        loc.url = loc.url || loc.pageUrl || null
        loc.method = loc.method || null
    }
    return loc
}

function compactEvidenceObject(obj, allowedKeys) {
    if (!obj || typeof obj !== "object") return {}
    const result = {}
    allowedKeys.forEach(key => {
        if (obj[key] !== undefined && obj[key] !== null) {
            result[key] = obj[key]
        }
    })
    return result
}

function normalizeDastEvidence(evidence = {}, finding = {}) {
    let payload = {}
    if (evidence && typeof evidence === "object" && !Array.isArray(evidence)) {
        if (evidence.dast) {
            payload = evidence.dast
        } else {
            payload = evidence
        }
    }
    if (Array.isArray(evidence)) {
        payload = evidence[0] || {}
    }
    const legacyAttack = (payload.attack && typeof payload.attack === "object") ? payload.attack : {}
    const attackId = payload.attackId || legacyAttack.id || finding.attackId || null
    const requestId = payload.requestId || legacyAttack.requestId || finding.requestId || null
    const proof = payload.proof || finding.proof || null
    const resolverKey = payload.resolverKey || ((requestId && attackId) ? `${requestId}::${attackId}` : null)
    const confidenceSignals = Array.isArray(payload.confidenceSignals)
        ? payload.confidenceSignals
        : null
    const aggregate = (payload.aggregate && typeof payload.aggregate === "object")
        ? payload.aggregate
        : null
    const occurrenceCount = Number.isFinite(Number(payload.occurrenceCount))
        ? Number(payload.occurrenceCount)
        : null
    const sampleLimit = Number.isFinite(Number(payload.sampleLimit))
        ? Number(payload.sampleLimit)
        : null
    const truncated = payload.truncated === true
        ? true
        : (payload.truncated === false ? false : null)
    const samples = Array.isArray(payload.samples)
        ? payload.samples
            .filter((entry) => entry && typeof entry === "object")
            .map((entry) => compactEvidenceObject(entry, [
                "url",
                "method",
                "statusCode",
                "requestId",
                "attackId",
                "proof",
                "seenAt"
            ]))
            .filter((entry) => Object.keys(entry).length)
        : null
    const sanitized = compactEvidenceObject(
        {
            attackId,
            requestId,
            resolverKey,
            proof,
            param: payload.param ?? legacyAttack.param,
            payload: payload.payload ?? legacyAttack.payload,
            confidenceSignals,
            meta: payload.meta || legacyAttack.meta || null,
            aggregate,
            occurrenceCount,
            sampleLimit,
            truncated,
            samples
        },
        [
            "attackId",
            "requestId",
            "resolverKey",
            "proof",
            "param",
            "payload",
            "confidenceSignals",
            "meta",
            "aggregate",
            "occurrenceCount",
            "sampleLimit",
            "truncated",
            "samples"
        ]
    )
    return { dast: sanitized }
}

function normalizeSastEvidence(evidence = {}, finding = {}) {
    let payload = {}
    if (evidence && typeof evidence === "object" && !Array.isArray(evidence)) {
        payload = evidence.sast || evidence.sastEvidence || evidence
    }
    if (Array.isArray(evidence)) {
        payload = evidence[0] || {}
    }
    if (!payload || typeof payload !== "object") payload = {}
    const sanitized = compactEvidenceObject({
        codeSnippet: payload.codeSnippet || finding.codeSnippet || null,
        source: payload.source || null,
        sink: payload.sink || null,
        nodeType: payload.nodeType || null,
        trace: Array.isArray(payload.trace) ? payload.trace : payload.trace || null,
        sinkId: payload.sinkId || null,
        mode: payload.mode || finding.mode || null,
        findingKind: payload.findingKind || finding.findingKind || null,
        sinkContext: payload.sinkContext || null,
        sourceTier: payload.sourceTier || null,
        confidenceSignals: Array.isArray(payload.confidenceSignals) ? payload.confidenceSignals : null
    }, ["codeSnippet", "source", "sink", "nodeType", "trace", "sinkId", "mode", "findingKind", "sinkContext", "sourceTier", "confidenceSignals"])
    return { sast: sanitized }
}

function sanitizeIastTrace(traceValue) {
    if (!traceValue) return null
    if (Array.isArray(traceValue)) {
        const trimmed = traceValue
            .slice(0, 5)
            .map(entry => truncateString(entry, 200))
            .filter(Boolean)
        return trimmed.length ? trimmed : null
    }
    return truncateString(traceValue, 500)
}

function sanitizeIastContext(context) {
    if (!context || typeof context !== "object") return null
    const sanitized = {}
    const copyField = (srcKey, destKey = srcKey) => {
        const value = ensureString(context[srcKey])
        if (value) sanitized[destKey] = value
    }
    copyField("url")
    copyField("location")
    copyField("domPath")
    copyField("elementId")
    copyField("tagName")
    copyField("method")
    const valuePreview = truncateString(context.value ?? context.text ?? context.innerHTML ?? context.matched, 200)
    if (valuePreview) sanitized.valuePreview = valuePreview
    return Object.keys(sanitized).length ? sanitized : null
}

function normalizeIastEvidence(evidence = {}, finding = {}) {
    let payload = {}
    if (evidence && typeof evidence === "object" && !Array.isArray(evidence)) {
        payload = evidence.iast || evidence
    } else if (Array.isArray(evidence)) {
        payload = evidence.find(entry => entry && typeof entry === "object") || {}
    }
    if (!payload || typeof payload !== "object") payload = {}
    const context = (payload.context && typeof payload.context === "object")
        ? payload.context
        : (payload.raw && typeof payload.raw.context === "object" ? payload.raw.context : null)
    const sanitizedContext = sanitizeIastContext(context)
    const sanitizedTrace = sanitizeIastTrace(payload.trace || finding.trace || null)
    const sanitized = compactEvidenceObject({
        requestId: payload.requestId || payload.requestKey || null,
        sinkId: payload.sinkId || payload.sink || finding.sinkId || null,
        sourceId: payload.sourceId || payload.taintSource || finding.taintSource || null,
        taintSource: payload.taintSource || finding.taintSource || null,
        source: payload.source || finding.source || null,
        sources: Array.isArray(payload.sources) ? payload.sources : undefined,
        sink: payload.sink || null,
        matched: truncateString(payload.matched || finding.matched || null, 160),
        trace: sanitizedTrace,
        context: sanitizedContext,
        sinkSummary: payload.sinkSummary || null,
        taintSummary: payload.taintSummary || null,
        allowedSources: Array.isArray(payload.allowedSources) ? payload.allowedSources : null,
        schemaVersion: payload.schemaVersion || null,
        primaryClass: payload.primaryClass || null,
        sourceRole: payload.sourceRole || null,
        origin: payload.origin || null,
        observedAt: payload.observedAt || null,
        operation: payload.operation || null,
        detection: payload.detection || null,
        trust: payload.trust || null,
        suppression: payload.suppression || null,
        networkTarget: payload.networkTarget || null,
        routing: payload.routing || null,
        message: truncateString(payload.message || finding.message || null, 400)
    }, ["requestId", "sinkId", "sourceId", "taintSource", "source", "sources", "sink", "matched", "trace", "context", "sinkSummary", "taintSummary", "allowedSources", "schemaVersion", "primaryClass", "sourceRole", "origin", "observedAt", "operation", "detection", "trust", "suppression", "networkTarget", "routing", "message"])
    const extras = {}
    if (Array.isArray(finding.affectedUrls)) {
        const filtered = finding.affectedUrls.map(ensureString).filter(Boolean)
        if (filtered.length) extras.affectedUrls = filtered
    }
    if (finding.sinkSummary && typeof finding.sinkSummary === "object") {
        extras.sinkSummary = finding.sinkSummary
    }
    if (finding.taintSummary && typeof finding.taintSummary === "object") {
        extras.taintSummary = finding.taintSummary
    }
    const source = ensureString(finding.source)
    if (source) extras.source = source
    const taintSummarySource = ensureString(finding.taintSource)
    if (taintSummarySource) extras.taintSource = taintSummarySource
    if (Object.keys(extras).length) {
        Object.assign(sanitized, extras)
    }
    return { iast: sanitized }
}

function normalizeScaEvidence(evidence = {}, finding = {}) {
    let payload = {}
    if (evidence && typeof evidence === "object" && !Array.isArray(evidence)) {
        payload = evidence.sca || evidence
    } else if (Array.isArray(evidence)) {
        payload = evidence.find(entry => entry && typeof entry === "object") || {}
    }
    if (!payload || typeof payload !== "object") payload = {}
    const component = (payload.component && typeof payload.component === "object" && !Array.isArray(payload.component))
        ? { ...payload.component }
        : {}
    const identifiers = (payload.identifiers && typeof payload.identifiers === "object" && !Array.isArray(payload.identifiers))
        ? { ...payload.identifiers }
        : {}
    const versionRange = (payload.versionRange && typeof payload.versionRange === "object" && !Array.isArray(payload.versionRange))
        ? { ...payload.versionRange }
        : {
            atOrAbove: payload.atOrAbove || null,
            above: payload.above || null,
            atOrBelow: payload.atOrBelow || null,
            below: payload.below || null
        }
    const info = Array.isArray(payload.info) ? payload.info.slice().filter(Boolean) : []
    const sanitized = compactEvidenceObject({
        component: Object.keys(component).length ? component : null,
        identifiers: Object.keys(identifiers).length ? identifiers : undefined,
        versionRange: Object.keys(versionRange).some(key => versionRange[key]) ? versionRange : undefined,
        info: info.length ? info : undefined,
        summary: payload.summary || finding.description || null,
        sourceFile: payload.sourceFile || finding?.location?.file || null
    }, ["component", "identifiers", "versionRange", "info", "summary", "sourceFile"])
    return { sca: sanitized }
}

function normalizeEvidence(evidence, engine, finding) {
    if (engine === "DAST") {
        return normalizeDastEvidence(evidence, finding)
    }
    if (engine === "SAST") {
        return normalizeSastEvidence(evidence, finding)
    }
    if (engine === "IAST") {
        return normalizeIastEvidence(evidence, finding)
    }
    if (engine === "SCA") {
        return normalizeScaEvidence(evidence, finding)
    }
    return evidence && typeof evidence === "object" ? evidence : {}
}

function buildDeterministicFindingId({ normalized = {}, moduleId = "module", ruleId = "rule" } = {}) {
    const explicitFingerprint = ensureString(normalized?.fingerprint)
    if (explicitFingerprint) {
        return `${normalized?.scanId || "scan"}::${normalized?.engine || "ENGINE"}::${explicitFingerprint}`
    }
    const payload = [
        normalized?.scanId || "scan",
        normalized?.engine || "ENGINE",
        moduleId,
        ruleId,
        normalized?.vulnId || "",
        normalized?.category || "",
        normalized?.severity || "",
        normalized?.title || normalized?.name || normalized?.ruleName || "",
        stableStringify(normalized?.location || {}),
        stableStringify(normalized?.evidence || {}),
        normalized?.correlationKey || ""
    ].join("|")
    return `${normalized?.scanId || "scan"}::${normalized?.engine || "ENGINE"}::${moduleId}::${ruleId}::${hashHex(payload).slice(0, 24)}`
}

export function normalizeFinding({ engine, scanId, finding = {}, moduleMeta = {}, ruleMeta = {} } = {}) {
    if (!finding || typeof finding !== "object") return finding
    const normalizedEngine = (engine || finding.engine || "").toUpperCase()
    const resolvedEngine = VALID_ENGINES.has(normalizedEngine) ? normalizedEngine : (finding.engine || normalizedEngine || "DAST")
    const normalized = { ...finding }
    normalized.engine = resolvedEngine
    normalized.scanId = normalized.scanId || scanId || null

    const moduleId = ensureString(normalized.moduleId) || ensureString(moduleMeta.id) || ensureString(moduleMeta.moduleId) || "module"
    normalized.moduleId = moduleId
    normalized.moduleName = ensureString(normalized.moduleName) || ensureString(moduleMeta.name) || moduleId

    const ruleId = ensureString(normalized.ruleId) || ensureString(ruleMeta.id) || ensureString(ruleMeta.ruleId) || "rule"
    normalized.ruleId = ruleId
    normalized.ruleName = ensureString(normalized.ruleName) || ensureString(ruleMeta.name) || ruleId

    normalized.id = ensureString(normalized.id) || buildDeterministicFindingId({ normalized, moduleId, ruleId })
    normalized.severity = normalizeSeverity(normalized.severity)

    normalized.category = resolveTaxonomyField("category", normalized, ruleMeta, moduleMeta, "other")
    normalized.vulnId = resolveTaxonomyField("vulnId", normalized, ruleMeta, moduleMeta, "other")

    normalized.description = normalized.description || ruleMeta.description || moduleMeta.description || ""
    normalized.recommendation = normalized.recommendation || ruleMeta.recommendation || moduleMeta.recommendation || ""
    normalized.links = pickObject(normalized.links, ruleMeta.links, moduleMeta.links)
    normalized.tags = normalizeTags(normalized.tags, ruleMeta.tags, moduleMeta.tags)

    normalized.owasp = normalizeOwaspArray(normalized.owasp, ruleMeta.owasp, moduleMeta.owasp)
    normalized.cwe = toUniqueStringArray(normalized.cwe, ruleMeta.cwe, moduleMeta.cwe)

    normalized.location = normalizeLocation(normalized.location, normalized.engine)
    const createdAt = ensureString(normalized.createdAt) || new Date().toISOString()
    normalized.createdAt = createdAt
    normalized.updatedAt = ensureString(normalized.updatedAt) || createdAt

    if (Number.isFinite(normalized.confidence)) {
        normalized.confidence = Math.min(100, Math.max(0, Math.round(normalized.confidence)))
    }

    normalized.evidence = normalizeEvidence(normalized.evidence, normalized.engine, normalized)

    if (normalized.engine === "IAST") {
        delete normalized.message
        delete normalized.attackId
        delete normalized.engines
        delete normalized.policyId
        delete normalized.affectedUrls
        delete normalized.sinkId
        delete normalized.sinkSummary
        delete normalized.source
        delete normalized.taintSource
        delete normalized.taintSummary
    }

    return normalized
}

export default normalizeFinding
