'use strict'

import { stableHash } from './zapMapper.js'
import { IAST_WIRE_V2, IAST_WIRE_V3, iastContractError, sanitizeIastObservation } from './iastWireContract.js'
import { projectIastFlow } from './iastFlowProjection.js'

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

function toSeverity(value, v2 = false) {
    const text = String(value || 'low').toLowerCase()
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(text)) return 'low'
    if (text === 'critical') return 'high'
    if (text === 'info') return v2 ? 'info' : 'low'
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

function toStatusCode(value) {
    const num = Number(value)
    if (!Number.isFinite(num)) return 200
    return Math.max(100, Math.min(599, Math.round(num)))
}

function defaultReasonPhrase(statusCode) {
    switch (statusCode) {
    case 201:
        return 'Created'
    case 202:
        return 'Accepted'
    case 204:
        return 'No Content'
    case 301:
        return 'Moved Permanently'
    case 302:
        return 'Found'
    case 304:
        return 'Not Modified'
    case 400:
        return 'Bad Request'
    case 401:
        return 'Unauthorized'
    case 403:
        return 'Forbidden'
    case 404:
        return 'Not Found'
    case 500:
        return 'Internal Server Error'
    default:
        return statusCode >= 400 ? 'Error' : 'OK'
    }
}

function buildRawRequest({ method, url }) {
    const requestMethod = toNonEmptyString(method) || 'GET'
    const requestUrl = toNonEmptyString(url) || '/'
    let host = ''
    try {
        host = new URL(requestUrl).host
    } catch (_) {
        host = ''
    }
    const headers = host ? `\r\nHost: ${host}` : ''
    return `${requestMethod} ${requestUrl} HTTP/1.1${headers}\r\n\r\n`
}

function buildRawResponse({ statusCode }) {
    const code = toStatusCode(statusCode)
    return `HTTP/1.1 ${code} ${defaultReasonPhrase(code)}\r\n\r\n`
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

function buildProof(finding = {}, observation = null) {
    const proof = toObject(finding.proof) || {}
    const evidence = toObject(finding?.evidence?.iast) || {}
    const primaryClass = toNonEmptyString(evidence.primaryClass)
    let mode = 'signal'
    if (observation?.kind !== 'policy_signal' && observation?.acquisition !== 'sink_storage_snapshot' && (primaryClass === 'taint_flow' || primaryClass === 'hybrid')) {
        mode = 'taint'
    }
    return {
        mode,
        payload: truncate(evidence.matched, 1024),
        proof: null,
        summary: truncate(
            (observation?.acquisition === 'sink_storage_snapshot' ? 'Inferred equality between current storage and sink input; application storage read was not observed.' : null)
            || proof.summary
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

export function toIastFinding(finding, { scanId, scanResult, wireSchema = null } = {}) {
    if (!finding || typeof finding !== 'object') return null
    const evidence = toObject(finding?.evidence?.iast) || {}
    const v3 = wireSchema === IAST_WIRE_V3
    const v2 = v3 || wireSchema === IAST_WIRE_V2 || evidence?.observation?.schemaVersion === 2
    const moduleId = toNonEmptyString(finding.moduleId)
    const ruleId = toNonEmptyString(finding.ruleId)
    // v2 canonical findings are immutable. A later request-store enrichment
    // must not change an already admitted/published proof or its destination.
    const location = buildLocation(finding, { scanResult: v2 ? null : scanResult })
    if (!moduleId || !ruleId || !location) {
        if (v2) throw iastContractError('invalid_payload', 'IAST v2 missing native rule/location')
        return null
    }

    const requestEntry = v2 ? null : findRequestEntry(scanResult, finding)
    const source = buildSource(finding)
    const sink = buildSink(finding)
    const context = buildContext(finding)
    const fingerprint = toNonEmptyString(finding.fingerprint)
        || stableHash(`${location.url}|${moduleId}|${ruleId}|${sink.id || ''}|${source.id || ''}`)
    const observation = v2 ? sanitizeIastObservation(evidence.observation) : null
    if (v2) {
        for (const value of [finding.id, finding.fingerprint, moduleId, ruleId]) {
            if (typeof value !== 'string' || !value.length || value.length > 128) throw iastContractError('invalid_payload', 'IAST v2 requires a bounded opaque native identity')
        }
        source.label = truncate(source.label, 256)
        sink.label = truncate(sink.label, 256)
        context.domPath = truncate(context.domPath, 1024)
        context.elementId = truncate(context.elementId, 1024)
        context.tagName = truncate(context.tagName, 80)
    }
    const selectedKey = evidence.sourceKey || evidence.primarySource?.key || evidence.sources?.[0]?.key || null
    if (observation?.kind === 'source_relationship' && (source.kind !== observation.sourceBinding.kind || selectedKey !== observation.sourceBinding.key)) {
        throw iastContractError('invalid_payload', 'IAST selected source disagrees with its observation binding')
    }
    if (observation?.acquisition === 'sink_storage_snapshot' && !['info', 'low'].includes(String(finding.severity).toLowerCase())) {
        throw iastContractError('invalid_payload', 'Inferred storage observation exceeds Low severity')
    }
    const proof = buildProof(finding, observation)
    const summary = buildRootSummary({ finding, proof, source, sink })

    const method = location.method || toNonEmptyString(requestEntry?.method) || 'GET'
    const statusCode = toStatusCode(requestEntry?.status || requestEntry?.statusCode)

    return {
        id: toNonEmptyString(finding.id) || fingerprint,
        fingerprint,
        moduleId,
        ruleId,
        severity: toSeverity(finding.severity, v2),
        confidence: clamp(finding.confidence, 0, 100),
        summary,
        location,
        proof,
        request: {
            method,
            url: location.url,
            raw: buildRawRequest({ method, url: location.url })
        },
        response: {
            statusCode,
            raw: buildRawResponse({ statusCode })
        },
        source,
        sink,
        trace: truncate(evidence.trace, 2048),
        context,
        ...(v2 ? { observation } : {}),
        ...(v3 ? { flow: projectIastFlow(evidence.context?.flow, observation, sink, evidence.sources || []) } : {})
    }
}
