'use strict'

import { stableHash } from './zapMapper.js'

const MAX_CODE_SNIPPET_LEN = 1536
const MAX_TRACE_ITEMS = 32

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const text = String(value).trim()
    return text.length ? text : null
}

function truncate(value, maxLen = MAX_CODE_SNIPPET_LEN) {
    if (value === undefined || value === null) return null
    const text = String(value)
    return text.length > maxLen ? text.slice(0, maxLen) : text
}

function clamp(value, min, max) {
    const num = Number(value)
    if (!Number.isFinite(num)) return min
    return Math.max(min, Math.min(max, Math.round(num)))
}

function toSeverity(value) {
    const text = String(value || 'low').toLowerCase()
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(text)) return 'low'
    if (text === 'critical') return 'high'
    if (text === 'info') return 'low'
    return text
}

function toStringArray(value) {
    if (!Array.isArray(value)) return []
    return value.map(item => String(item)).filter(Boolean)
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

function collectObservedPageUrls(finding = {}) {
    const location = toObject(finding.location) || {}
    const values = [
        location.pageUrls,
        location.runtimeUrls,
        location.urls,
        location.observedUrls,
        location.runtimeUrl,
        location.url,
        location.pageUrl
    ]
    const seen = new Set()
    const urls = []
    for (const value of values) {
        const entries = Array.isArray(value) ? value : [value]
        for (const entry of entries) {
            const url = toNonEmptyString(entry)
            if (!url || seen.has(url)) continue
            seen.add(url)
            urls.push(url)
        }
    }
    return urls
}

function buildLocation(finding = {}, { pageUrlOverride = null } = {}) {
    const location = toObject(finding.location) || {}
    const url = resolveCanonicalUrl(pageUrlOverride, location.runtimeUrl, location.url, location.pageUrl)
    return {
        url,
        route: toNonEmptyString(location.route) || null,
        method: toNonEmptyString(location.method) || null,
        param: toNonEmptyString(location.param) || null
    }
}

function buildSourceOrSink(entry) {
    const obj = toObject(entry) || {}
    return {
        label: toNonEmptyString(obj.label) || null,
        file: toNonEmptyString(obj.sourceFile || obj.sinkFile || obj.file) || null,
        line: Number.isFinite(obj.sourceLoc?.start?.line) ? obj.sourceLoc.start.line
            : (Number.isFinite(obj.sinkLoc?.start?.line) ? obj.sinkLoc.start.line : (Number.isFinite(obj.line) ? obj.line : null)),
        column: Number.isFinite(obj.sourceLoc?.start?.column) ? obj.sourceLoc.start.column
            : (Number.isFinite(obj.sinkLoc?.start?.column) ? obj.sinkLoc.start.column : (Number.isFinite(obj.column) ? obj.column : null))
    }
}

function sanitizeTrace(trace) {
    if (!Array.isArray(trace)) return []
    return trace.slice(0, MAX_TRACE_ITEMS).map((step) => {
        if (!step || typeof step !== 'object') return null
        return {
            kind: toNonEmptyString(step.kind) || null,
            label: truncate(step.label, 256),
            file: toNonEmptyString(step.file) || null,
            line: Number.isFinite(step?.loc?.start?.line) ? step.loc.start.line : (Number.isFinite(step.line) ? step.line : null),
            column: Number.isFinite(step?.loc?.start?.column) ? step.loc.start.column : (Number.isFinite(step.column) ? step.column : null)
        }
    }).filter(Boolean)
}

function buildProof(finding = {}) {
    const proof = toObject(finding.proof) || {}
    const mode = toNonEmptyString(finding?.evidence?.sast?.mode) || toNonEmptyString(finding.mode) || 'unknown'
    return {
        mode,
        payload: null,
        proof: null,
        summary: truncate(
            proof.summary
            || finding.ruleName
            || finding.description
            || 'Code finding matched',
            1024
        )
    }
}

function buildRootSummary({ finding = {}, proof, source, sink }) {
    const base = truncate(
        proof?.summary
        || finding.ruleName
        || finding.description
        || 'Code finding matched',
        512
    )
    const sourceLabel = truncate(source?.label, 256)
    const sinkLabel = truncate(sink?.label, 256)
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

export function toSastFinding(finding, { scanId, pageUrlOverride = null } = {}) {
    if (!finding || typeof finding !== 'object') return null
    const moduleId = toNonEmptyString(finding.moduleId)
    const ruleId = toNonEmptyString(finding.ruleId)
    const findingLocation = toObject(finding.location) || {}
    const location = buildLocation(finding, { pageUrlOverride })
    if (!moduleId || !ruleId || !toNonEmptyString(findingLocation.file)) return null

    const evidence = toObject(finding?.evidence?.sast) || {}
    const source = buildSourceOrSink(evidence.source)
    const sink = buildSourceOrSink(evidence.sink)
    const baseFingerprint = toNonEmptyString(finding.fingerprint)
        || stableHash(`${findingLocation.file || ''}|${findingLocation.line || ''}|${moduleId}|${ruleId}|${sink.label || ''}`)
    const urlSalt = toNonEmptyString(location.url)
    const fingerprint = urlSalt ? `${baseFingerprint}::url:${stableHash(urlSalt)}` : baseFingerprint
    const proof = buildProof(finding)
    const summary = buildRootSummary({ finding, proof, source, sink })
    const baseId = toNonEmptyString(finding.id) || baseFingerprint

    return {
        id: urlSalt ? `${baseId}::url:${stableHash(urlSalt)}` : baseId,
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
        trace: sanitizeTrace(evidence.trace || finding.trace),
        codeSnippet: truncate(evidence.codeSnippet || finding.codeSnippet || null, MAX_CODE_SNIPPET_LEN)
    }
}

export function toSastFindings(finding, options = {}) {
    const urls = collectObservedPageUrls(finding)
    if (!urls.length) {
        const mapped = toSastFinding(finding, options)
        return mapped ? [mapped] : []
    }
    return urls
        .map((url) => toSastFinding(finding, Object.assign({}, options, { pageUrlOverride: url })))
        .filter(Boolean)
}
