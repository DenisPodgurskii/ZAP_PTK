const VALID_ENGINES = new Set(["DAST", "SAST", "IAST"])
const ENGINE_LOCATION_KIND = {
    DAST: "http",
    SAST: "code",
    IAST: "runtime"
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
    const normalized = {}
    const id = ensureString(entry.id || entry.key || entry.category)
    if (id) normalized.id = id
    const version = ensureString(entry.version || entry.year || entry.top10 || entry.owasp_version)
    if (version) normalized.version = version
    const name = ensureString(entry.name || entry.title || entry.description)
    if (name) normalized.name = name
    if (!Object.keys(normalized).length) return null
    return normalized
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
        const key = typeof normalized === "string"
            ? `str::${normalized}`
            : `obj::${JSON.stringify(normalized, Object.keys(normalized).sort())}`
        if (seen.has(key)) return
        seen.add(key)
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
    const attackId = payload.attackId || finding.attackId || null
    const requestId = payload.requestId || finding.requestId || null
    const proof = payload.proof || finding.proof || null
    const sanitized = compactEvidenceObject(
        { attackId, requestId, proof, param: payload.param, payload: payload.payload },
        ["attackId", "requestId", "proof", "param", "payload"]
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
    const sanitizedSources = Array.isArray(payload.sources)
        ? payload.sources.slice(0, 5).map(entry => ({
            key: entry?.key || null,
            display: truncateString(entry?.display || entry?.label || entry?.key || null, 160),
            sourceKind: entry?.sourceKind || entry?.kind || null,
            sourceValuePreview: truncateString(entry?.sourceValuePreview || entry?.raw || entry?.value || null, 160),
            score: entry?.score || null
        })).filter(entry => entry.display || entry.key)
        : null
    const sanitizedPrimarySource = payload.primarySource
        ? {
            key: payload.primarySource?.key || null,
            display: truncateString(payload.primarySource?.display || payload.primarySource?.label || payload.primarySource?.key || null, 160),
            sourceKind: payload.primarySource?.sourceKind || payload.primarySource?.kind || null,
            sourceValuePreview: truncateString(payload.primarySource?.sourceValuePreview || payload.primarySource?.raw || payload.primarySource?.value || null, 160),
            score: payload.primarySource?.score || null
        }
        : null
    const sanitizedSecondarySources = Array.isArray(payload.secondarySources)
        ? payload.secondarySources.slice(0, 5).map(entry => ({
            key: entry?.key || null,
            display: truncateString(entry?.display || entry?.label || entry?.key || null, 160),
            sourceKind: entry?.sourceKind || entry?.kind || null,
            sourceValuePreview: truncateString(entry?.sourceValuePreview || entry?.raw || entry?.value || null, 160),
            score: entry?.score || null
        })).filter(entry => entry.display || entry.key)
        : null
    const sinkContext = payload.sinkContext && typeof payload.sinkContext === "object"
        ? {
            requestUrl: truncateString(payload.sinkContext.requestUrl || null, 200),
            method: payload.sinkContext.method || null,
            headerName: payload.sinkContext.headerName || null,
            destUrl: truncateString(payload.sinkContext.destUrl || null, 200),
            destHost: payload.sinkContext.destHost || null,
            destOrigin: payload.sinkContext.destOrigin || null,
            isCrossOrigin: payload.sinkContext.isCrossOrigin ?? null,
            tagName: payload.sinkContext.tagName || null,
            domPath: truncateString(payload.sinkContext.domPath || null, 200),
            attribute: payload.sinkContext.attribute || null,
            elementId: payload.sinkContext.elementId || null,
            cookieName: payload.sinkContext.cookieName || null,
            cookieAttributes: payload.sinkContext.cookieAttributes || null,
            storageKey: payload.sinkContext.storageKey || null,
            storageArea: payload.sinkContext.storageArea || null
        }
        : null
    const sanitized = compactEvidenceObject({
        requestId: payload.requestId || payload.requestKey || null,
        sinkId: payload.sinkId || payload.sink || finding.sinkId || null,
        sourceId: payload.sourceId || payload.taintSource || finding.taintSource || null,
        taintSource: payload.taintSource || finding.taintSource || null,
        sourceKind: payload.sourceKind || null,
        sourceKey: payload.sourceKey || null,
        sourceValuePreview: truncateString(payload.sourceValuePreview || null, 160),
        primarySource: sanitizedPrimarySource,
        secondarySources: sanitizedSecondarySources,
        sources: sanitizedSources,
        matched: truncateString(payload.matched || finding.matched || null, 160),
        trace: sanitizedTrace,
        traceSummary: truncateString(payload.traceSummary || null, 200),
        context: sanitizedContext,
        sinkContext,
        sinkSummary: payload.sinkSummary || null,
        taintSummary: payload.taintSummary || null,
        allowedSources: Array.isArray(payload.allowedSources) ? payload.allowedSources.slice() : null,
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
        flowSummary: truncateString(payload.flowSummary || null, 200),
        message: truncateString(payload.message || finding.message || null, 400)
    }, [
        "requestId",
        "sinkId",
        "sourceId",
        "taintSource",
        "sourceKind",
        "sourceKey",
        "sourceValuePreview",
        "primarySource",
        "secondarySources",
        "sources",
        "matched",
        "trace",
        "traceSummary",
        "context",
        "sinkContext",
        "sinkSummary",
        "taintSummary",
        "allowedSources",
        "schemaVersion",
        "primaryClass",
        "sourceRole",
        "origin",
        "observedAt",
        "operation",
        "detection",
        "trust",
        "suppression",
        "networkTarget",
        "routing",
        "flowSummary",
        "message"
    ])
    return { iast: sanitized }
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
    return evidence && typeof evidence === "object" ? evidence : {}
}

export function normalizeFinding(finding = {}, { engine, moduleMeta = {}, ruleMeta = {}, scanId } = {}) {
    if (!finding || typeof finding !== "object") return finding
    const normalizedEngine = (engine || finding.engine || "").toUpperCase()
    const resolvedEngine = VALID_ENGINES.has(normalizedEngine) ? normalizedEngine : (finding.engine || normalizedEngine || "DAST")
    finding.engine = resolvedEngine
    if (scanId) finding.scanId = finding.scanId || scanId
    finding.scanId = finding.scanId || null

    const moduleId = ensureString(finding.moduleId) || ensureString(moduleMeta.id) || ensureString(moduleMeta.moduleId) || "module"
    finding.moduleId = moduleId
    finding.moduleName = ensureString(finding.moduleName) || ensureString(moduleMeta.name) || moduleId

    const ruleId = ensureString(finding.ruleId) || ensureString(ruleMeta.id) || ensureString(ruleMeta.ruleId) || "rule"
    finding.ruleId = ruleId
    finding.ruleName = ensureString(finding.ruleName) || ensureString(ruleMeta.name) || ruleId

    finding.id = ensureString(finding.id) || `${finding.scanId || "scan"}::${finding.engine}::${moduleId}::${ruleId}::${Date.now()}`
    finding.severity = normalizeSeverity(finding.severity)

    const resolvedCategory = ensureString(finding.category) || ensureString(ruleMeta.category) || ensureString(moduleMeta.category) || "other"
    finding.category = resolvedCategory

    const resolvedVulnId = ensureString(finding.vulnId) || ensureString(ruleMeta.vulnId) || ensureString(moduleMeta.vulnId) || "other"
    finding.vulnId = resolvedVulnId

    finding.description = finding.description || ruleMeta.description || moduleMeta.description || ""
    finding.recommendation = finding.recommendation || ruleMeta.recommendation || moduleMeta.recommendation || ""
    finding.links = pickObject(finding.links, ruleMeta.links, moduleMeta.links)
    finding.tags = normalizeTags(finding.tags, ruleMeta.tags, moduleMeta.tags)

    finding.owasp = normalizeOwaspArray(finding.owasp, ruleMeta.owasp, moduleMeta.owasp)
    finding.cwe = toUniqueStringArray(finding.cwe, ruleMeta.cwe, moduleMeta.cwe)

    finding.location = normalizeLocation(finding.location, finding.engine)
    finding.createdAt = finding.createdAt || new Date().toISOString()

    finding.evidence = normalizeEvidence(finding.evidence, finding.engine, finding)

    return finding
}

export default normalizeFinding
