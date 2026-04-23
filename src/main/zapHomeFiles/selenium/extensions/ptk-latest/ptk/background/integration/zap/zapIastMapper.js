'use strict'

import { stableHash } from './zapMapper.js'

const MAX_TEXT_LEN = 4096
function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const text = String(value).trim()
    return text.length ? text : null
}

function clamp(value, min, max) {
    const num = Number(value)
    if (!Number.isFinite(num)) return min
    return Math.max(min, Math.min(max, Math.round(num)))
}

function truncate(value, maxLen = MAX_TEXT_LEN) {
    if (value === undefined || value === null) return null
    const text = String(value)
    return text.length > maxLen ? text.slice(0, maxLen) : text
}

function toSeverity(value) {
    const text = String(value || 'low').toLowerCase()
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(text)) return 'low'
    if (text === 'critical') return 'high'
    if (text === 'info') return 'low'
    return text
}

function toObject(value) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null
}

function resolveCanonicalUrl(...values) {
    for (const value of values) {
        const text = toNonEmptyString(value)
        if (text) return text
    }
    return null
}

function findRequestEntry(scanResult = {}, finding = {}) {
    const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []
    if (!requests.length) return null
    const evidence = toObject(finding?.evidence?.iast) || {}
    const requestId = toNonEmptyString(evidence.requestId) || toNonEmptyString(finding.requestId)
    const requestKey = toNonEmptyString(evidence.requestKey) || toNonEmptyString(finding.requestKey)
    const location = toObject(finding.location) || {}
    const candidateUrl = resolveCanonicalUrl(
        location.runtimeUrl,
        location.url,
        location.pageUrl,
        evidence?.routing?.runtimeUrl,
        evidence?.routing?.url
    )

    if (requestId) {
        const byId = requests.find((entry) => toNonEmptyString(entry?.id) === requestId)
        if (byId) return byId
    }
    if (requestKey) {
        const byKey = requests.find((entry) => toNonEmptyString(entry?.key) === requestKey)
        if (byKey) return byKey
    }
    if (candidateUrl) {
        const byUrl = requests.find((entry) => {
            const entryUrl = resolveCanonicalUrl(entry?.url, entry?.displayUrl)
            return entryUrl === candidateUrl
        })
        if (byUrl) return byUrl
    }
    return null
}

function buildLocation(finding = {}, { scanResult = null } = {}) {
    const location = toObject(finding.location) || {}
    const routing = toObject(finding?.evidence?.iast?.routing) || {}
    const requestEntry = findRequestEntry(scanResult, finding)
    const url = resolveCanonicalUrl(
        location.runtimeUrl,
        routing.runtimeUrl,
        location.url,
        routing.url,
        location.pageUrl,
        requestEntry?.url,
        requestEntry?.displayUrl
    )
    if (!url) return null

    return {
        url,
        route: toNonEmptyString(location.route) || null,
        method: toNonEmptyString(location.method) || toNonEmptyString(requestEntry?.method) || null,
        param: toNonEmptyString(location.param) || null
    }
}

function buildContext(finding = {}) {
    const evidence = toObject(finding?.evidence?.iast) || {}
    const context = toObject(evidence.context) || {}
    return {
        domPath: toNonEmptyString(context.domPath) || null,
        elementId: toNonEmptyString(context.elementId) || null,
        tagName: toNonEmptyString(context.tagName) || null
    }
}

function buildSource(finding = {}) {
    const evidence = toObject(finding?.evidence?.iast) || {}
    const sourceObj = Array.isArray(evidence.sources) && evidence.sources.length
        ? (toObject(evidence.sources[0]) || {})
        : {}
    const label = toNonEmptyString(evidence.source)
        || toNonEmptyString(evidence.taintSource)
        || toNonEmptyString(sourceObj.display)
        || toNonEmptyString(sourceObj.label)
        || toNonEmptyString(sourceObj.raw)
        || null

    return {
        id: toNonEmptyString(evidence.sourceId) || toNonEmptyString(sourceObj.key) || null,
        label,
        kind: toNonEmptyString(sourceObj.sourceKind) || toNonEmptyString(sourceObj.kind) || toNonEmptyString(evidence.sourceKind) || null
    }
}

function buildSink(finding = {}) {
    const evidence = toObject(finding?.evidence?.iast) || {}
    const label = toNonEmptyString(evidence.sink) || toNonEmptyString(evidence.sinkId) || null
    return {
        id: toNonEmptyString(evidence.sinkId) || toNonEmptyString(finding.sinkId) || null,
        label
    }
}

function buildProof(finding = {}) {
    const proof = toObject(finding.proof) || {}
    const evidence = toObject(finding?.evidence?.iast) || {}
    const primaryClass = toNonEmptyString(evidence.primaryClass)
    let mode = 'signal'
    if (primaryClass === 'taint_flow' || primaryClass === 'hybrid') {
        mode = 'taint'
    }
    return {
        mode,
        payload: truncate(evidence.matched, 1024),
        proof: null,
        summary: truncate(
            proof.summary
            || finding.message
            || evidence.message
            || finding.ruleName
            || finding.category
            || 'Runtime signal detected',
            1024
        )
    }
}

function buildRootSummary({ finding = {}, proof, source, sink }) {
    const base = truncate(
        proof?.summary
        || finding.ruleName
        || finding.category
        || 'Runtime signal detected',
        512
    )
    const sourceLabel = truncate(source?.label || source?.id, 256)
    const sinkLabel = truncate(sink?.label || sink?.id, 256)
    if (!base) return null
    if (!sourceLabel && !sinkLabel) return base
    if (sourceLabel && sinkLabel) {
        return truncate(`${base} from source ${sourceLabel} to sink ${sinkLabel}`, 1024)
    }
    if (sourceLabel) {
        return truncate(`${base} from source ${sourceLabel}`, 1024)
    }
    return truncate(`${base} to sink ${sinkLabel}`, 1024)
}

export function toIastFinding(finding, { scanId, scanResult } = {}) {
    if (!finding || typeof finding !== 'object') return null
    const moduleId = toNonEmptyString(finding.moduleId)
    const ruleId = toNonEmptyString(finding.ruleId)
    const location = buildLocation(finding, { scanResult })
    if (!moduleId || !ruleId || !location) return null

    const source = buildSource(finding)
    const sink = buildSink(finding)
    const context = buildContext(finding)
    const fingerprint = toNonEmptyString(finding.fingerprint)
        || stableHash(`${location.url}|${moduleId}|${ruleId}|${sink.id || ''}|${source.id || ''}`)
    const evidence = toObject(finding?.evidence?.iast) || {}
    const proof = buildProof(finding)
    const summary = buildRootSummary({ finding, proof, source, sink })

    return {
        id: toNonEmptyString(finding.id) || fingerprint,
        fingerprint,
        moduleId,
        ruleId,
        severity: toSeverity(finding.severity),
        confidence: clamp(finding.confidence, 0, 100),
        summary,
        location,
        proof,
        source,
        sink,
        trace: truncate(evidence.trace, 2048),
        context
    }
}
