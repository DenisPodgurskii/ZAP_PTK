const DEFAULT_DAST_AGGREGATE_SAMPLE_LIMIT = 10

const SEVERITY_RANK = Object.freeze({
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
})

function clonePlain(value) {
    if (value === null || value === undefined) return value
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        if (Array.isArray(value)) return value.slice()
        if (typeof value === "object") return Object.assign({}, value)
        return value
    }
}

function toPositiveInteger(value, fallback) {
    const number = Number(value)
    if (!Number.isFinite(number) || number <= 0) return fallback
    return Math.max(1, Math.floor(number))
}

function toFiniteNumber(value, fallback = null) {
    const number = Number(value)
    return Number.isFinite(number) ? number : fallback
}

function getDastEvidence(finding) {
    return finding?.evidence?.dast && typeof finding.evidence.dast === "object"
        ? finding.evidence.dast
        : null
}

function getAggregateKey(finding) {
    const key = getDastEvidence(finding)?.aggregate?.key
    return typeof key === "string" && key.trim() ? key.trim() : null
}

function getOccurrenceCount(finding) {
    return toPositiveInteger(getDastEvidence(finding)?.occurrenceCount, 1)
}

function getSampleLimit(finding, fallback) {
    return toPositiveInteger(getDastEvidence(finding)?.sampleLimit, fallback)
}

function normalizeSeverity(value) {
    return typeof value === "string" ? value.trim().toLowerCase() : ""
}

function chooseHigherSeverity(current, incoming) {
    const currentRank = SEVERITY_RANK[normalizeSeverity(current)] ?? -1
    const incomingRank = SEVERITY_RANK[normalizeSeverity(incoming)] ?? -1
    return incomingRank > currentRank ? incoming : current
}

function compactObject(fields) {
    return Object.fromEntries(
        Object.entries(fields).filter(([, value]) => value !== null && value !== undefined && value !== "")
    )
}

function buildFindingSample(finding) {
    const evidence = getDastEvidence(finding) || {}
    const location = finding?.location && typeof finding.location === "object"
        ? finding.location
        : {}
    return compactObject({
        url: location.url || finding?.url || null,
        runtimeUrl: location.runtimeUrl || null,
        method: location.method || finding?.method || null,
        param: location.param || evidence.param || null,
        requestId: evidence.requestId || null,
        attackId: evidence.attackId || null,
        proof: evidence.proof || null,
        seenAt: finding?.lastSeenAt || finding?.createdAt || null
    })
}

function sampleIdentity(sample) {
    const method = String(sample?.method || "").toUpperCase()
    const url = String(sample?.url || "")
    const runtimeUrl = String(sample?.runtimeUrl || "")
    if (sample?.requestId) {
        return [method, url, runtimeUrl, "request", String(sample.requestId)].join("|")
    }
    if (sample?.attackId) {
        return [method, url, runtimeUrl, "attack", String(sample.attackId)].join("|")
    }
    return [
        method,
        url,
        runtimeUrl,
        String(sample?.param || ""),
        String(sample?.proof || "")
    ].join("|")
}

function collectSamples(finding) {
    const evidence = getDastEvidence(finding)
    const samples = Array.isArray(evidence?.samples)
        ? evidence.samples.map((sample) => clonePlain(sample)).filter((sample) => sample && typeof sample === "object")
        : []
    const findingSample = buildFindingSample(finding)
    if (Object.keys(findingSample).length) {
        samples.push(findingSample)
    }
    return samples
}

function ensureDastEvidence(finding) {
    if (!finding.evidence || typeof finding.evidence !== "object") {
        finding.evidence = {}
    }
    if (!finding.evidence.dast || typeof finding.evidence.dast !== "object") {
        finding.evidence.dast = {}
    }
    return finding.evidence.dast
}

function mergeSamples(targetEvidence, incomingSamples, sampleLimit) {
    if (!Array.isArray(targetEvidence.samples)) {
        targetEvidence.samples = []
    }
    const seen = new Set(targetEvidence.samples.map((sample) => sampleIdentity(sample)))
    for (const sample of incomingSamples) {
        const key = sampleIdentity(sample)
        if (seen.has(key)) continue
        seen.add(key)
        if (targetEvidence.samples.length < sampleLimit) {
            targetEvidence.samples.push(sample)
        } else {
            targetEvidence.truncated = true
        }
    }
}

function normalizeAggregatedFinding(finding, aggregateKey, sampleLimit) {
    const occurrenceCount = getOccurrenceCount(finding)
    const samples = collectSamples(finding)
    const evidence = ensureDastEvidence(finding)
    const existingAggregate = evidence.aggregate && typeof evidence.aggregate === "object"
        ? evidence.aggregate
        : {}
    evidence.aggregate = Object.assign({}, existingAggregate, { key: aggregateKey })
    evidence.occurrenceCount = occurrenceCount
    evidence.sampleLimit = sampleLimit
    evidence.truncated = evidence.truncated === true
    evidence.samples = []
    mergeSamples(evidence, samples, sampleLimit)
    if (!finding.presentationAggregate && evidence.aggregate.mode) {
        finding.presentationAggregate = evidence.aggregate.mode
    }
    return finding
}

function mergeAggregatedFinding(target, incoming, sampleLimit) {
    const targetEvidence = ensureDastEvidence(target)
    const incomingEvidence = getDastEvidence(incoming) || {}
    targetEvidence.occurrenceCount = getOccurrenceCount(target) + getOccurrenceCount(incoming)
    targetEvidence.sampleLimit = sampleLimit
    targetEvidence.truncated = targetEvidence.truncated === true || incomingEvidence.truncated === true
    mergeSamples(targetEvidence, collectSamples(incoming), sampleLimit)

    const incomingConfidence = toFiniteNumber(incoming?.confidence)
    const targetConfidence = toFiniteNumber(target?.confidence)
    if (incomingConfidence !== null && (targetConfidence === null || incomingConfidence > targetConfidence)) {
        target.confidence = incomingConfidence
    }

    target.severity = chooseHigherSeverity(target.severity, incoming?.severity)
    target.effectiveSeverity = chooseHigherSeverity(target.effectiveSeverity, incoming?.effectiveSeverity)
    if (!target.lastSeenAt || incoming?.lastSeenAt) {
        target.lastSeenAt = incoming?.lastSeenAt || target.lastSeenAt || incoming?.createdAt || target.createdAt || null
    }
    return target
}

export function collapseDastAggregatedFindings(findings, { sampleLimit = DEFAULT_DAST_AGGREGATE_SAMPLE_LIMIT } = {}) {
    if (!Array.isArray(findings) || findings.length === 0) return []
    const defaultSampleLimit = toPositiveInteger(sampleLimit, DEFAULT_DAST_AGGREGATE_SAMPLE_LIMIT)
    const collapsed = []
    const byAggregateKey = new Map()

    for (const finding of findings) {
        const aggregateKey = getAggregateKey(finding)
        if (!aggregateKey) {
            collapsed.push(finding)
            continue
        }

        const findingSampleLimit = getSampleLimit(finding, defaultSampleLimit)
        const existing = byAggregateKey.get(aggregateKey)
        if (!existing) {
            const normalized = normalizeAggregatedFinding(clonePlain(finding), aggregateKey, findingSampleLimit)
            byAggregateKey.set(aggregateKey, normalized)
            collapsed.push(normalized)
            continue
        }

        const mergedSampleLimit = Math.max(getSampleLimit(existing, defaultSampleLimit), findingSampleLimit)
        existing.evidence.dast.sampleLimit = mergedSampleLimit
        mergeAggregatedFinding(existing, finding, mergedSampleLimit)
    }

    return collapsed
}

export { DEFAULT_DAST_AGGREGATE_SAMPLE_LIMIT }
