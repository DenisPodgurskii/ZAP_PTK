import CryptoES from "../../../packages/crypto-es/index.js"
import { normalizeCwe, normalizeOwasp } from "../../common/normalizeMappings.js"
import { resolveFindingTaxonomy } from "../../common/resolveFindingTaxonomy.js"

const ENGINE_IAST = "IAST"
const DEFAULT_CATEGORY = "runtime_issue"
const IAST_FINDING_AGGREGATE_SAMPLE_LIMIT = 10
const IAST_FINDING_AGGREGATION_MODES = new Set([
    "route-source-sink",
    "route-source-sink-callsite",
    "source-sink",
    "source-sink-callsite"
])
const SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]
const SEVERITY_RANK = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
}

export function createFindingFromIAST(details = {}, meta = {}) {
    const now = new Date().toISOString()
    const severity = normalizeSeverity(details?.severity)
    const category = inferCategoryFromIAST(details)
    const location = buildLocation(details)
    const sinkId = details?.sinkId || details?.sink || null
    const taintSource = details?.taintSource || details?.source || details?.matched || null
    const cwe = normalizeCwe(details?.cwe || details?.meta?.cwe)
    const owasp = normalizeOwasp(details?.owasp || details?.meta?.owasp)
    const ruleId = details?.ruleId || null
    const moduleId = details?.moduleId || null
    const moduleName = details?.moduleName || details?.meta?.moduleName || null
    const ruleName = details?.ruleName || details?.meta?.ruleName || null
    const message = details?.message || null
    const description = details?.description || details?.meta?.description || null
    const recommendation = details?.recommendation || details?.meta?.recommendation || null
    const links = details?.links || details?.meta?.links || null
    const contextKey = extractContextKey(details?.context)
    const fingerprint = buildFingerprint({
        url: location.url,
        sink: sinkId,
        category,
        source: taintSource,
        contextKey
    })
    const evidence = buildIASTEvidence(details)
    const confidenceDetails = resolveIastConfidence(details, evidence)
    if (confidenceDetails.signals.length) {
        evidence.confidenceSignals = confidenceDetails.signals
    }

    const finding = {
        id: `${fingerprint}:${details?.timestamp || Date.now()}`,
        fingerprint,
        category,
        severity,
        confidence: confidenceDetails.confidence,
        cwe,
        owasp,
        location,
        ruleId,
        ruleName,
        moduleId,
        moduleName,
        message,
        description,
        recommendation,
        links,
        sinkId,
        source: taintSource,
        taintSource,
        engines: [ENGINE_IAST],
        evidence: { iast: evidence },
        scanId: meta?.scanId || null,
        attackId: null,
        policyId: null,
        createdAt: now,
        updatedAt: now
    }
    resolveFindingTaxonomy({
        finding,
        ruleMeta: details?.meta?.ruleMeta || details?.meta || {},
        moduleMeta: details?.meta?.moduleMeta || details?.meta || {}
    })
    return finding
}

export function getIastEvidencePayload(finding = {}) {
    if (!finding) return null
    const evidence = finding.evidence
    if (!evidence) return null
    if (Array.isArray(evidence)) {
        return evidence.find(entry => entry && typeof entry === "object") || null
    }
    if (evidence.iast && typeof evidence.iast === "object") {
        return evidence.iast
    }
    if (typeof evidence === "object") {
        return evidence
    }
    return null
}

export function getFindingFingerprint(finding = {}) {
    if (finding?.fingerprint) return finding.fingerprint
    const evidence = getIastEvidencePayload(finding) || {}
    const fallbackSource = finding?.taintSummary?.primarySource || finding?.source || null
    const contextKey =
        extractContextKey(evidence?.context) ||
        extractContextKey(finding?.location) ||
        null
    return buildFingerprint({
        url: extractLocationUrl(finding?.location),
        sink: evidence?.sinkId || finding?.sinkId || null,
        category: finding?.category || null,
        source: evidence?.taintSource || fallbackSource,
        contextKey
    })
}

export function normalizeIastFindingAggregationMode(value) {
    const mode = String(value || "").trim().toLowerCase()
    return IAST_FINDING_AGGREGATION_MODES.has(mode) ? mode : null
}

export function resolveIastFindingPresentationAggregate(...sources) {
    for (const source of sources) {
        const mode = normalizeIastFindingAggregationMode(
            source?.presentation?.aggregate
            || source?.metadata?.presentation?.aggregate
        )
        if (mode) return mode
    }
    return null
}

export function buildIastFindingAggregateKey({ finding = {}, ruleMeta = {}, moduleMeta = {}, scanId = null, host = null } = {}) {
    const mode = resolveIastFindingPresentationAggregate(ruleMeta, moduleMeta)
    if (!mode) return null
    const evidence = getIastEvidencePayload(finding) || {}
    const sourceKey = resolveIastAggregateSourceKey(finding, evidence)
    const sinkKey = normalizeIastAggregatePart(evidence?.sinkId || finding?.sinkId || evidence?.sink || "")
    if (!sourceKey || !sinkKey) return null
    const parts = [
        "IAST",
        mode,
        String(scanId || finding?.scanId || ""),
        normalizeIastAggregateHost(host || finding?.location?.url || evidence?.routing?.runtimeUrl || evidence?.routing?.url || ""),
        normalizeIastAggregatePart(finding?.moduleId || moduleMeta?.id || moduleMeta?.moduleId || ""),
        normalizeIastAggregatePart(finding?.ruleId || ruleMeta?.id || ruleMeta?.ruleId || "")
    ]

    if (mode.startsWith("route-")) {
        const route = normalizeIastAggregateRoute(
            evidence?.routing?.urlPattern
            || evidence?.routing?.runtimeUrl
            || evidence?.routing?.url
            || finding?.location?.runtimeUrl
            || finding?.location?.url
            || ""
        )
        if (!route) return null
        parts.push(route)
    }

    parts.push(sourceKey, sinkKey)

    if (mode.endsWith("-callsite")) {
        const callsite = resolveIastAggregateCallsite(finding, evidence)
        if (!callsite) return null
        parts.push(callsite)
    }

    return parts.join("|")
}

export function buildIastFindingAggregateSample(finding = {}) {
    const evidence = getIastEvidencePayload(finding) || {}
    const route = normalizeIastAggregateRoute(
        evidence?.routing?.urlPattern
        || evidence?.routing?.runtimeUrl
        || evidence?.routing?.url
        || finding?.location?.runtimeUrl
        || finding?.location?.url
        || ""
    )
    return compactObject({
        url: finding?.location?.runtimeUrl || evidence?.routing?.runtimeUrl || finding?.location?.url || null,
        route,
        sourceKey: resolveIastAggregateSourceKey(finding, evidence),
        sourceKind: evidence?.sourceKind || evidence?.primarySource?.sourceKind || evidence?.sources?.[0]?.sourceKind || evidence?.sources?.[0]?.kind || null,
        source: evidence?.source || evidence?.taintSource || finding?.source || null,
        sinkId: evidence?.sinkId || finding?.sinkId || null,
        callsite: resolveIastAggregateCallsite(finding, evidence),
        matched: truncateSampleValue(evidence?.matched || finding?.matched || null, 160),
        seenAt: new Date().toISOString()
    })
}

export function applyIastFindingAggregateState(finding, { aggregateKey = null, mode = null, sample = null } = {}) {
    if (!finding || !aggregateKey) return finding
    const normalizedMode = normalizeIastFindingAggregationMode(mode)
    if (!normalizedMode) return finding
    finding.evidence = finding.evidence && typeof finding.evidence === "object" ? finding.evidence : {}
    finding.evidence.iast = finding.evidence.iast && typeof finding.evidence.iast === "object" ? finding.evidence.iast : {}
    const evidence = finding.evidence.iast
    const aggregateFingerprint = CryptoES.SHA1(aggregateKey).toString(CryptoES.enc.Hex)
    finding.fingerprint = aggregateFingerprint
    finding.id = `${finding?.scanId || "scan"}::IAST::${aggregateFingerprint}`
    finding.presentationAggregate = normalizedMode
    evidence.aggregate = Object.assign({}, evidence.aggregate || {}, {
        mode: normalizedMode,
        key: aggregateKey
    })
    evidence.occurrenceCount = Math.max(1, Number(evidence.occurrenceCount || 0) || 0)
    evidence.sampleLimit = IAST_FINDING_AGGREGATE_SAMPLE_LIMIT
    evidence.truncated = evidence.truncated === true
    evidence.samples = Array.isArray(evidence.samples) ? evidence.samples : []
    appendIastAggregateSample(evidence, sample)
    return finding
}

export function mergeIastFindingAggregateOccurrence(existingFinding, incomingFinding, { sample = null } = {}) {
    if (!existingFinding || !incomingFinding) return existingFinding || incomingFinding
    const existingEvidence = getIastEvidencePayload(existingFinding) || {}
    const incomingEvidence = getIastEvidencePayload(incomingFinding) || {}
    existingFinding.severity = pickHigherSeverity(existingFinding.severity, incomingFinding.severity)
    if (
        Number.isFinite(Number(incomingFinding.confidence))
        && (
            !Number.isFinite(Number(existingFinding.confidence))
            || Number(incomingFinding.confidence) > Number(existingFinding.confidence)
        )
    ) {
        existingFinding.confidence = Number(incomingFinding.confidence)
    }
    existingFinding.updatedAt = incomingFinding.updatedAt || new Date().toISOString()
    existingFinding.lastSeenAt = new Date().toISOString()
    existingFinding.evidence = existingFinding.evidence && typeof existingFinding.evidence === "object" ? existingFinding.evidence : {}
    existingFinding.evidence.iast = existingEvidence
    existingEvidence.occurrenceCount = Math.max(1, Number(existingEvidence.occurrenceCount || 0) || 0) + 1
    existingEvidence.sampleLimit = IAST_FINDING_AGGREGATE_SAMPLE_LIMIT
    existingEvidence.truncated = existingEvidence.truncated === true
    existingEvidence.samples = Array.isArray(existingEvidence.samples) ? existingEvidence.samples : []
    appendIastAggregateSample(existingEvidence, sample || buildIastFindingAggregateSample(incomingFinding))
    mergeIastAggregateSourceSamples(existingEvidence, incomingEvidence)
    return existingFinding
}

export function mergeFinding(existingFinding, newFinding) {
    if (!existingFinding) return newFinding
    if (!newFinding) return existingFinding

    existingFinding.severity = pickHigherSeverity(existingFinding.severity, newFinding.severity)
    existingFinding.category = existingFinding.category || newFinding.category
    existingFinding.location = existingFinding.location || newFinding.location
    existingFinding.cwe = mergeCweSets(existingFinding.cwe, newFinding.cwe)
    existingFinding.owasp = mergeOwaspSets(existingFinding.owasp, newFinding.owasp)
    existingFinding.ruleId = existingFinding.ruleId || newFinding.ruleId
    existingFinding.moduleId = existingFinding.moduleId || newFinding.moduleId
    existingFinding.moduleName = existingFinding.moduleName || newFinding.moduleName
    existingFinding.message = existingFinding.message || newFinding.message
    existingFinding.description = existingFinding.description || newFinding.description
    existingFinding.recommendation = existingFinding.recommendation || newFinding.recommendation
    existingFinding.links = existingFinding.links || newFinding.links || null
    existingFinding.sinkId = existingFinding.sinkId || newFinding.sinkId
    existingFinding.source = existingFinding.source || newFinding.source
    existingFinding.taintSource = existingFinding.taintSource || newFinding.taintSource
    existingFinding.scanId = existingFinding.scanId || newFinding.scanId
    existingFinding.updatedAt = newFinding.updatedAt || new Date().toISOString()
    existingFinding.engines = mergeEngines(existingFinding.engines, newFinding.engines)
    existingFinding.evidence = mergeEvidence(existingFinding.evidence, newFinding.evidence)

    return existingFinding
}

function compactObject(value = {}) {
    return Object.fromEntries(
        Object.entries(value).filter(([, entry]) => entry !== null && entry !== undefined && entry !== "")
    )
}

function truncateSampleValue(value, limit = 160) {
    if (value === null || value === undefined) return null
    const text = String(value)
    return text.length > limit ? `${text.slice(0, limit)}...` : text
}

function normalizeIastAggregatePart(value = null) {
    const text = String(value || "").trim().toLowerCase()
    return text || null
}

function normalizeIastAggregateHost(value = null) {
    const raw = String(value || "").trim()
    if (!raw) return ""
    try {
        const hostOnly = /^[^/\s?#]+(?::\d+)?$/.test(raw)
        const hasScheme = !hostOnly && /^[a-z][a-z0-9+.-]*:/i.test(raw)
        const urlValue = hasScheme
            ? raw
            : (hostOnly ? `http://${raw}` : raw)
        const parsed = new URL(urlValue, hasScheme || hostOnly ? undefined : "http://placeholder")
        if (parsed.hostname === "placeholder" && !/placeholder/i.test(raw)) return ""
        return parsed.host.toLowerCase()
    } catch (_) {
        return raw.toLowerCase()
    }
}

function normalizeIastAggregateRoute(value = null) {
    const raw = String(value || "").trim()
    if (!raw) return null
    const normalizePath = (pathValue) => {
        const path = String(pathValue || "/").trim() || "/"
        if (path === "/") return path
        return path.replace(/\/+$/, "") || "/"
    }
    try {
        const parsed = new URL(raw, raw.startsWith("http") ? undefined : "http://placeholder")
        let route = `${parsed.origin.toLowerCase()}${normalizePath(parsed.pathname)}`
        if (parsed.hash) {
            const hashRoute = String(parsed.hash.slice(1) || "").split("?")[0]
            if (hashRoute) route += `#${normalizePath(hashRoute)}`
        }
        return route
    } catch (_) {
        const [withoutQuery] = raw.split("?")
        const [pathOnly, hashPart] = withoutQuery.split("#")
        const hashRoute = hashPart ? hashPart.split("?")[0] : ""
        return `${normalizePath(pathOnly)}${hashRoute ? `#${normalizePath(hashRoute)}` : ""}`
    }
}

function resolveIastAggregateSourceKey(finding = {}, evidence = {}) {
    const primary = getPrimaryIastSource(evidence)
    const candidates = [
        evidence?.sourceKey,
        evidence?.primarySource?.key,
        evidence?.primarySource?.source,
        primary?.key,
        primary?.source,
        primary?.sourceId,
        evidence?.sourceId,
        finding?.sourceKey,
        finding?.taintSource
    ]
    for (const candidate of candidates) {
        const normalized = normalizeIastAggregatePart(candidate)
        if (normalized) return normalized
    }
    return null
}

function getPrimaryIastSource(evidence = {}) {
    const sources = Array.isArray(evidence?.sources) ? evidence.sources : []
    for (const source of sources) {
        if (!source || typeof source !== "object") continue
        const sourceKind = source?.sourceKind || source?.kind || null
        const sourceKey = source?.key || source?.source || source?.sourceId || null
        if (sourceKind || sourceKey) return source
    }
    return null
}

function resolveIastAggregateCallsite(finding = {}, evidence = {}) {
    const context = evidence?.context && typeof evidence.context === "object" ? evidence.context : {}
    const contextScriptLocation = formatIastScriptLocation(context?.scriptUrl, context?.line, context?.column)
    const findingScriptLocation = formatIastScriptLocation(finding?.location?.scriptUrl, finding?.location?.line, finding?.location?.column)
    const candidates = [
        context.domPath,
        finding?.location?.domPath,
        contextScriptLocation,
        findingScriptLocation,
        context.elementId ? `id:${context.elementId}` : null,
        context.attribute ? `attr:${context.attribute}` : null,
        evidence?.traceSummary,
        firstTraceFrame(evidence?.trace),
        context.method ? `method:${context.method}` : null
    ]
    for (const candidate of candidates) {
        const normalized = normalizeIastAggregatePart(candidate)
        if (normalized) return normalized
    }
    return null
}

function formatIastScriptLocation(scriptUrl = null, line = null, column = null) {
    const script = String(scriptUrl || "").trim()
    if (!script) return null
    const lineNumber = Number(line)
    const columnNumber = Number(column)
    if (Number.isFinite(lineNumber) && lineNumber > 0) {
        return `${script}:${Math.trunc(lineNumber)}:${Number.isFinite(columnNumber) && columnNumber >= 0 ? Math.trunc(columnNumber) : 0}`
    }
    return script
}

function firstTraceFrame(trace = null) {
    if (Array.isArray(trace)) {
        for (const frame of trace) {
            if (!frame || typeof frame !== "object") continue
            const location = formatIastScriptLocation(frame.url || frame.scriptUrl || frame.file, frame.line || frame.lineNumber, frame.column || frame.columnNumber)
            if (location) return location
            const label = String(frame.label || frame.name || frame.functionName || frame.kind || "").trim()
            if (label) return label
        }
        return null
    }
    const text = String(trace || "")
    if (!text) return null
    return text.split("\n").map(line => line.trim()).find(line => line && !/^error:/i.test(line)) || null
}

function appendIastAggregateSample(evidence = {}, sample = null) {
    if (!sample || typeof sample !== "object") return
    evidence.samples = Array.isArray(evidence.samples) ? evidence.samples : []
    const sampleKey = [
        sample.route || "",
        sample.url || "",
        sample.sourceKey || "",
        sample.sinkId || "",
        sample.callsite || ""
    ].join("|")
    const existingKeys = new Set(evidence.samples.map((entry) => [
        entry?.route || "",
        entry?.url || "",
        entry?.sourceKey || "",
        entry?.sinkId || "",
        entry?.callsite || ""
    ].join("|")))
    if (existingKeys.has(sampleKey)) return
    if (evidence.samples.length < IAST_FINDING_AGGREGATE_SAMPLE_LIMIT) {
        evidence.samples.push(sample)
    } else {
        evidence.truncated = true
    }
}

function mergeIastAggregateSourceSamples(existingEvidence = {}, incomingEvidence = {}) {
    if (!Array.isArray(incomingEvidence?.sources) || !incomingEvidence.sources.length) return
    if (!Array.isArray(existingEvidence.sources)) {
        existingEvidence.sources = incomingEvidence.sources.slice(0, IAST_FINDING_AGGREGATE_SAMPLE_LIMIT)
        return
    }
    const seen = new Set(existingEvidence.sources.map(entry => String(entry?.key || entry?.source || entry?.sourceId || "")))
    for (const source of incomingEvidence.sources) {
        const key = String(source?.key || source?.source || source?.sourceId || "")
        if (!key || seen.has(key)) continue
        if (existingEvidence.sources.length >= IAST_FINDING_AGGREGATE_SAMPLE_LIMIT) break
        existingEvidence.sources.push(source)
        seen.add(key)
    }
}

function mergeOwaspSets(base, incoming) {
    const combined = []
    if (Array.isArray(base)) combined.push(...base)
    if (Array.isArray(incoming)) combined.push(...incoming)
    if (!combined.length) return []
    return normalizeOwasp(combined)
}

function mergeCweSets(base, incoming) {
    const combined = []
    if (Array.isArray(base)) combined.push(...base)
    if (Array.isArray(incoming)) combined.push(...incoming)
    if (!combined.length) return []
    return normalizeCwe(combined)
}

function buildIASTEvidence(details = {}) {
    const sinkId = details?.sinkId || details?.sink || null
    const taintSource = details?.taintSource || details?.source || null
    const context = (details?.context && typeof details.context === "object" && !Array.isArray(details.context))
        ? details.context
        : {}
    return {
        requestId: details?.requestId || details?.meta?.requestId || null,
        sinkId,
        sourceId: details?.sourceId || details?.sourceKey || null,
        matched: details?.matched || null,
        taintSource,
        source: details?.source || null,
        sourceKind: details?.sourceKind || null,
        sourceKey: details?.sourceKey || null,
        sourceValuePreview: details?.sourceValuePreview || null,
        primarySource: details?.primarySource || null,
        secondarySources: details?.secondarySources || null,
        sources: Array.isArray(details?.sources) ? details.sources : (Array.isArray(details?.taintedSources) ? details.taintedSources : null),
        sink: details?.sink || null,
        sinkContext: details?.sinkContext || null,
        context,
        schemaVersion: details?.schemaVersion || null,
        primaryClass: details?.primaryClass || context?.primaryClass || null,
        sourceRole: details?.sourceRole || context?.sourceRole || null,
        origin: details?.origin || context?.origin || null,
        observedAt: details?.observedAt || null,
        operation: details?.operation || context?.operation || null,
        navigationCorrelation: details?.navigationCorrelation || context?.navigationCorrelation || null,
        urlValidation: details?.urlValidation || context?.urlValidation || null,
        detection: details?.detection || context?.detection || null,
        trust: details?.trust || context?.trust || null,
        suppression: details?.suppression || context?.suppression || null,
        networkTarget: details?.networkTarget || context?.networkTarget || null,
        routing: details?.routing || null,
        trace: details?.trace || details?.flow || null,
        traceSummary: details?.traceSummary || null,
        flowSummary: details?.flowSummary || null,
        ruleId: details?.ruleId || null,
        moduleId: details?.moduleId || null,
        moduleName: details?.moduleName || null,
        message: details?.message || null
    }
}

function clampConfidence(value) {
    if (!Number.isFinite(value)) return null
    return Math.min(100, Math.max(0, Math.round(value)))
}

function toFiniteNumber(value) {
    if (typeof value === "number" && Number.isFinite(value)) return value
    if (typeof value === "string" && value.trim() !== "") {
        const parsed = Number(value)
        if (Number.isFinite(parsed)) return parsed
    }
    return null
}

function pickFiniteNumber(...values) {
    for (const value of values) {
        const numeric = toFiniteNumber(value)
        if (numeric !== null) return numeric
    }
    return null
}

function normalizeIastLabel(value) {
    if (value === null || value === undefined) return null
    const normalized = String(value).trim().toLowerCase()
    return normalized || null
}

function formatConfidenceDelta(value) {
    return value > 0 ? `+${value}` : String(value)
}

function confidenceScoreDelta(value, { pivot = 70, step = 5, min = -12, max = 10 } = {}) {
    if (!Number.isFinite(value)) return 0
    const delta = Math.round((value - pivot) / step)
    return Math.min(max, Math.max(min, delta))
}

function resolveIastContext(details = {}, evidence = {}) {
    const context = details?.context || evidence?.context || null
    return context && typeof context === "object" && !Array.isArray(context) ? context : {}
}

function resolvePrimaryClass(details = {}, evidence = {}, context = {}) {
    return normalizeIastLabel(details?.primaryClass || evidence?.primaryClass || context?.primaryClass)
}

function baseConfidenceForPrimaryClass(primaryClass) {
    switch (primaryClass) {
    case "taint_flow":
        return 82
    case "hybrid":
        return 74
    case "policy_violation":
        return 72
    case "observation":
        return 58
    default:
        return 76
    }
}

function matchTypeConfidenceDelta(matchType) {
    switch (matchType) {
    case "id":
    case "exact":
    case "direct":
        return 8
    case "prefix":
    case "suffix":
        return 3
    case "substring":
        return -12
    case "heuristic":
        return -8
    default:
        return 0
    }
}

function sourceRoleConfidenceDelta(sourceRole) {
    switch (sourceRole) {
    case "origin":
        return 4
    case "derived":
        return -2
    case "observed":
        return -8
    case "unknown":
        return -4
    default:
        return 0
    }
}

function traceLengthConfidenceDelta(traceLen) {
    if (!Number.isFinite(traceLen) || traceLen < 0) return 0
    if (traceLen === 0) return -10
    if (traceLen <= 3) return 8
    if (traceLen <= 6) return 4
    if (traceLen >= 10) return -6
    if (traceLen >= 7) return -2
    return 0
}

function trustLevelConfidenceDelta(level) {
    switch (level) {
    case "third_party":
        return 8
    case "same_origin":
        return -8
    case "first_party":
        return -4
    default:
        return 0
    }
}

function trustDecisionConfidenceDelta(decision) {
    switch (decision) {
    case "block":
        return 8
    case "warn":
        return -4
    case "allow":
        return -14
    default:
        return 0
    }
}

function resolveIastConfidence(details = {}, evidence = {}) {
    const signals = []
    const ruleMetaRaw = details?.meta?.ruleMeta?.metadata || details?.meta?.ruleMeta || {}
    const moduleMetaRaw = details?.meta?.moduleMeta?.metadata || details?.meta?.moduleMeta || {}
    const explicitOverride = pickFiniteNumber(
        details?.confidence,
        details?.meta?.confidence,
        ruleMetaRaw.confidence
    )
    if (explicitOverride !== null) {
        const value = clampConfidence(explicitOverride)
        return { confidence: value, signals: [`override:explicit:${value}`] }
    }

    const ruleDefault = pickFiniteNumber(ruleMetaRaw.confidenceDefault)
    if (ruleDefault !== null) {
        const value = clampConfidence(ruleDefault)
        return { confidence: value, signals: [`override:rule_default:${value}`] }
    }

    const moduleDefault = pickFiniteNumber(moduleMetaRaw.confidence, moduleMetaRaw.confidenceDefault)
    if (moduleDefault !== null) {
        const value = clampConfidence(moduleDefault)
        return { confidence: value, signals: [`override:module_default:${value}`] }
    }

    const context = resolveIastContext(details, evidence)
    const primaryClass = resolvePrimaryClass(details, evidence, context)
    let confidence = baseConfidenceForPrimaryClass(primaryClass)
    signals.push(`base:${primaryClass || "default"}:${confidence}`)

    const taintSource = evidence?.taintSource || details?.taintSource || details?.source || null
    const sinkId = evidence?.sinkId || details?.sinkId || details?.sink || null
    const trace = details?.trace || details?.flow || evidence?.trace || null
    const traceLen = Array.isArray(trace) ? trace.length : 0
    const match = context?.match && typeof context.match === "object" ? context.match : null
    const matchType = normalizeIastLabel(match?.matchType)
    const matchTypeDelta = matchTypeConfidenceDelta(matchType)
    if (matchTypeDelta) {
        confidence += matchTypeDelta
        signals.push(`match_type:${matchType}:${formatConfidenceDelta(matchTypeDelta)}`)
    }

    const matchConfidence = pickFiniteNumber(match?.confidence)
    if (matchConfidence !== null) {
        const delta = confidenceScoreDelta(matchConfidence, { pivot: 75, step: 5, min: -8, max: 6 })
        if (delta) {
            confidence += delta
            signals.push(`match_conf:${Math.round(matchConfidence)}:${formatConfidenceDelta(delta)}`)
        }
    }

    const detection = details?.detection || evidence?.detection || context?.detection || null
    const detectionConfidence = pickFiniteNumber(detection?.confidence)
    if (detectionConfidence !== null) {
        const delta = confidenceScoreDelta(detectionConfidence, { pivot: 70, step: 5, min: -12, max: 8 })
        if (delta) {
            confidence += delta
            signals.push(`detection_conf:${Math.round(detectionConfidence)}:${formatConfidenceDelta(delta)}`)
        }
    }

    const sourceRole = normalizeIastLabel(details?.sourceRole || evidence?.sourceRole || context?.sourceRole)
    const sourceRoleDelta = sourceRoleConfidenceDelta(sourceRole)
    if (sourceRoleDelta) {
        confidence += sourceRoleDelta
        signals.push(`source_role:${sourceRole}:${formatConfidenceDelta(sourceRoleDelta)}`)
    }

    if (!taintSource) {
        confidence -= 15
        signals.push("missing:source:-15")
    }
    if (!sinkId) {
        confidence -= 10
        signals.push("missing:sink:-10")
    }
    const traceDelta = traceLengthConfidenceDelta(traceLen)
    if (traceDelta) {
        confidence += traceDelta
        signals.push(`trace_len:${traceLen}:${formatConfidenceDelta(traceDelta)}`)
    }

    const sanitizerObserved = Array.isArray(context?.sanitizerObserved) ? context.sanitizerObserved : []
    const sanitizerPenalty = pickFiniteNumber(
        context?.confidencePenalty,
        details?.confidencePenalty,
        evidence?.context?.confidencePenalty
    )
    if (sanitizerObserved.length || sanitizerPenalty !== null) {
        const penaltyValue = Math.min(40, Math.max(10, Math.round(sanitizerPenalty ?? 20)))
        confidence -= penaltyValue
        signals.push(`sanitizer:${sanitizerObserved.length || 1}:-${penaltyValue}`)
    }

    const trust = details?.trust || evidence?.trust || context?.trust || null
    const trustLevel = normalizeIastLabel(trust?.level)
    const trustLevelDelta = trustLevelConfidenceDelta(trustLevel)
    if (trustLevelDelta) {
        confidence += trustLevelDelta
        signals.push(`trust_level:${trustLevel}:${formatConfidenceDelta(trustLevelDelta)}`)
    }

    const trustDecision = normalizeIastLabel(trust?.decision)
    const trustDecisionDelta = trustDecisionConfidenceDelta(trustDecision)
    if (trustDecisionDelta) {
        confidence += trustDecisionDelta
        signals.push(`trust_decision:${trustDecision}:${formatConfidenceDelta(trustDecisionDelta)}`)
    }

    const isCrossOrigin = [context?.isCrossOrigin, details?.isCrossOrigin, evidence?.networkTarget?.isCrossOrigin]
        .find(value => typeof value === "boolean")
    if (isCrossOrigin === true) {
        confidence += 6
        signals.push("cross_origin:true:+6")
    } else if (isCrossOrigin === false) {
        confidence -= 4
        signals.push("cross_origin:false:-4")
    }

    const suppression = details?.suppression || evidence?.suppression || context?.suppression || null
    if (suppression?.suppressed === true) {
        confidence -= 35
        signals.push("suppressed:true:-35")
    }

    return { confidence: clampConfidence(confidence), signals }
}

function normalizeSeverity(severity) {
    if (!severity && severity !== 0) return "info"
    const normalized = String(severity).toLowerCase()
    if (SEVERITY_LEVELS.includes(normalized)) return normalized
    if (!Number.isNaN(Number(normalized))) {
        const numeric = Number(normalized)
        if (numeric >= 8) return "high"
        if (numeric >= 5) return "medium"
        if (numeric > 0) return "low"
    }
    return "info"
}

function inferCategoryFromIAST(details = {}) {
    const sink = String(details?.sink || "").toLowerCase()
    const type = String(details?.type || "").toLowerCase()
    if (sink.includes("innerhtml") || sink.includes("document.write") || type.includes("xss")) {
        return "xss"
    }
    if (sink.includes("location") || sink.includes("href") || type.includes("redirect")) {
        return "open_redirect"
    }
    if (type) return type
    return DEFAULT_CATEGORY
}

function buildLocation(details = {}) {
    const location = details?.location
    if (location && typeof location === "object" && !Array.isArray(location)) {
        return {
            url: extractLocationUrl(location.url || location.href || null),
            scriptUrl: location.scriptUrl || null,
            line: sanitizeNumber(location.line),
            column: sanitizeNumber(location.column),
            domPath: location.domPath || null
        }
    }

    const context = details?.context || {}
    return {
        url: extractLocationUrl(location),
        scriptUrl: context.scriptUrl || null,
        line: sanitizeNumber(context.line),
        column: sanitizeNumber(context.column),
        domPath: context.domPath || context.element || null
    }
}

function buildFingerprint({ url = "", sink = "", category = "", source = "", contextKey = "" }) {
    const normalizedUrl = normalizeUrl(url)
    const payload = [normalizedUrl, sink || "", category || "", source || "", contextKey || ""].join("|")
    return CryptoES.SHA1(payload).toString(CryptoES.enc.Hex)
}

function normalizeUrl(url) {
    if (!url) return ""
    try {
        const u = new URL(url)
        u.hash = ""
        return u.toString()
    } catch (e) {
        return String(url)
    }
}

function extractContextKey(context = {}) {
    if (!context) return null
    if (typeof context !== "object") {
        try {
            return String(context)
        } catch (_) {
            return null
        }
    }
    return context.domPath || context.elementId || context.attribute || context.property || context.method || null
}

function sanitizeNumber(value) {
    if (Number.isFinite(value)) return value
    const parsed = Number(value)
    return Number.isFinite(parsed) ? parsed : null
}

function extractLocationUrl(location) {
    if (!location) return null
    if (typeof location === "string") return location
    if (typeof location === "object") {
        return location.url || location.href || null
    }
    return null
}

function mergeEngines(existing = [], incoming = []) {
    const merged = new Set()
    if (Array.isArray(existing)) existing.forEach(engine => merged.add(engine))
    if (Array.isArray(incoming)) incoming.forEach(engine => merged.add(engine))
    return Array.from(merged)
}

function mergeEvidence(existing, incoming) {
    const base = getIastEvidencePayload({ evidence: existing }) || {}
    const next = getIastEvidencePayload({ evidence: incoming }) || {}
    const pick = (field, fallback = null) => next?.[field] ?? base?.[field] ?? fallback
    const pickArray = (field) => {
        if (Array.isArray(next?.[field]) && next[field].length) return next[field]
        if (Array.isArray(base?.[field]) && base[field].length) return base[field]
        return null
    }
    const mergeStringArrays = (field) => {
        const merged = new Set()
        if (Array.isArray(base?.[field])) base[field].forEach(value => merged.add(String(value)))
        if (Array.isArray(next?.[field])) next[field].forEach(value => merged.add(String(value)))
        return merged.size ? Array.from(merged) : null
    }
    const merged = {
        requestId: pick("requestId"),
        sinkId: pick("sinkId"),
        sourceId: pick("sourceId"),
        taintSource: pick("taintSource"),
        source: pick("source"),
        sourceKind: pick("sourceKind"),
        sourceKey: pick("sourceKey"),
        sourceValuePreview: pick("sourceValuePreview"),
        primarySource: pick("primarySource"),
        secondarySources: pick("secondarySources"),
        sources: pickArray("sources"),
        sink: pick("sink"),
        sinkContext: pick("sinkContext"),
        matched: pick("matched"),
        trace: pick("trace"),
        traceSummary: pick("traceSummary"),
        flowSummary: pick("flowSummary"),
        context: pick("context"),
        schemaVersion: pick("schemaVersion"),
        primaryClass: pick("primaryClass"),
        sourceRole: pick("sourceRole"),
        origin: pick("origin"),
        observedAt: pick("observedAt"),
        operation: pick("operation"),
        navigationCorrelation: pick("navigationCorrelation"),
        urlValidation: pick("urlValidation"),
        detection: pick("detection"),
        trust: pick("trust"),
        suppression: pick("suppression"),
        networkTarget: pick("networkTarget"),
        routing: pick("routing"),
        confidenceSignals: mergeStringArrays("confidenceSignals"),
        message: pick("message")
    }
    return { iast: merged }
}

function pickHigherSeverity(existing, incoming) {
    const existingKey = normalizeSeverity(existing)
    const incomingKey = normalizeSeverity(incoming)
    return SEVERITY_RANK[incomingKey] > SEVERITY_RANK[existingKey] ? incomingKey : existingKey
}
