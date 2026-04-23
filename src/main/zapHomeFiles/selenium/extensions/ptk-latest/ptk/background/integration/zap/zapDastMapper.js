'use strict'

import { stableHash } from './zapMapper.js'

const VALID_PTK_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info'])

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const text = String(value).trim()
    return text.length ? text : null
}

function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value))
}

function toSeverity(value) {
    const normalized = toNonEmptyString(value)?.toLowerCase()
    if (!normalized || !VALID_PTK_SEVERITIES.has(normalized)) return 'low'
    if (normalized === 'critical') return 'high'
    if (normalized === 'info') return 'low'
    return normalized
}

function toConfidence(value) {
    const num = Number(value)
    if (Number.isFinite(num)) return clamp(Math.round(num), 0, 100)
    return 60
}

function toStatusCode(value) {
    const num = Number(value)
    if (Number.isFinite(num)) return clamp(Math.round(num), 0, 999)
    return 0
}

function toHttpStatusCode(value) {
    const statusCode = toStatusCode(value)
    return statusCode >= 100 && statusCode <= 599 ? statusCode : 200
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
    case 409:
        return 'Conflict'
    case 422:
        return 'Unprocessable Entity'
    case 429:
        return 'Too Many Requests'
    case 500:
        return 'Internal Server Error'
    case 502:
        return 'Bad Gateway'
    case 503:
        return 'Service Unavailable'
    case 504:
        return 'Gateway Timeout'
    default:
        return statusCode >= 400 ? 'Error' : 'OK'
    }
}

function buildStatusLine(response = {}) {
    const rawStatusLine = toNonEmptyString(response.statusLine)
    if (rawStatusLine && /^HTTP\/\d(?:\.\d)?\s+\d{3}(?:\s+.*)?$/i.test(rawStatusLine)) {
        return rawStatusLine
    }

    const protocolVersion = /^HTTP\/\d(?:\.\d)?/i.test(rawStatusLine || '')
        ? rawStatusLine.trim().split(/\s+/, 1)[0].toUpperCase()
        : 'HTTP/1.1'
    const statusCode = toHttpStatusCode(response.statusCode)
    const statusMessage = toNonEmptyString(response.statusMessage)
        || toNonEmptyString(response.statusText)
        || (() => {
            if (!rawStatusLine || !/^HTTP\/\d(?:\.\d)?\s+/i.test(rawStatusLine)) return null
            const remainder = rawStatusLine.trim().replace(/^HTTP\/\d(?:\.\d)?\s+/i, '')
            if (!remainder || /^\d{3}(?:\s+.*)?$/.test(remainder)) return null
            return remainder
        })()
        || defaultReasonPhrase(statusCode)

    return `${protocolVersion} ${statusCode} ${statusMessage}`
}

function toTimestampMs(value) {
    const numeric = Number(value)
    if (Number.isFinite(numeric) && numeric >= 0) return Math.round(numeric)
    const parsed = Date.parse(value)
    if (Number.isFinite(parsed) && parsed >= 0) return parsed
    return null
}

function buildRawResponse(response = {}) {
    const statusLine = buildStatusLine(response)
    const headersBlock = Array.isArray(response.headers)
        ? response.headers
            .map((h) => {
                const name = toNonEmptyString(h?.name)
                if (!name) return null
                const value = h?.value === undefined || h?.value === null ? '' : String(h.value)
                return `${name}: ${value}`
            })
            .filter(Boolean)
            .join('\r\n')
        : ''
    const body = typeof response.body === 'string' ? response.body : ''
    return [statusLine, headersBlock, '', body].join('\r\n')
}

function buildRawRequest(request = {}, fallbackLocation = {}) {
    const method = toNonEmptyString(request.method) || toNonEmptyString(fallbackLocation.method) || 'GET'
    const url = toNonEmptyString(request.url)
        || toNonEmptyString(request.ui_url)
        || toNonEmptyString(fallbackLocation.url)
        || '/'
    const firstLine = `${method} ${url} HTTP/1.1`
    const headersBlock = Array.isArray(request.headers)
        ? request.headers
            .map((h) => {
                const name = toNonEmptyString(h?.name)
                if (!name) return null
                const value = h?.value === undefined || h?.value === null ? '' : String(h.value)
                return `${name}: ${value}`
            })
            .filter(Boolean)
            .join('\r\n')
        : ''
    let body = ''
    if (request.body && typeof request.body === 'object') {
        if (typeof request.body.text === 'string') {
            body = request.body.text
        } else if (Array.isArray(request.body.params)) {
            body = request.body.params
                .map((p) => `${p?.name || ''}=${p?.value || ''}`)
                .join('&')
        }
    }
    return [firstLine, headersBlock, '', body].join('\r\n')
}

function resolveRequestRecord(scanResult, requestId) {
    if (!requestId) return null
    const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []
    return requests.find((item) => String(item?.id) === String(requestId)) || null
}

function resolveAttackRecord(requestRecord, attackId, ruleId) {
    const attacks = Array.isArray(requestRecord?.attacks) ? requestRecord.attacks : []
    if (!attacks.length) return null
    if (attackId) {
        const byId = attacks.find((item) => String(item?.id) === String(attackId))
        if (byId) return byId
    }
    if (ruleId) {
        const byRule = attacks.find((item) => String(item?.ruleId) === String(ruleId))
        if (byRule) return byRule
    }
    return attacks[0] || null
}

function resolvePayloadValue(value) {
    if (value === undefined || value === null) return null
    if (typeof value === 'string') return value
    try {
        return JSON.stringify(value)
    } catch (_) {
        return String(value)
    }
}

function toUriLike(value) {
    const text = toNonEmptyString(value)
    if (!text) return null
    try {
        const url = new URL(text)
        return url.toString()
    } catch (_) {
        return null
    }
}

function resolveProofSummary({ finding, sourceAttack, ruleId, proofValue }) {
    return toNonEmptyString(finding?.ruleName)
        || toNonEmptyString(sourceAttack?.ruleName)
        || toNonEmptyString(sourceAttack?.name)
        || toNonEmptyString(finding?.name)
        || toNonEmptyString(finding?.title)
        || toNonEmptyString(finding?.description)
        || toNonEmptyString(proofValue)
        || `Rule ${ruleId} matched`
}

export function toDastFinding(finding, { scanId, scanResult } = {}) {
    if (!finding || typeof finding !== 'object') return null

    const moduleId = toNonEmptyString(finding.moduleId)
    const ruleId = toNonEmptyString(finding.ruleId)
    if (!moduleId || !ruleId) return null

    const dastEvidence = (finding.evidence && typeof finding.evidence === 'object')
        ? (finding.evidence.dast || {})
        : {}

    const requestId = toNonEmptyString(dastEvidence.requestId)
        || toNonEmptyString(dastEvidence.attack?.requestId)
        || toNonEmptyString(finding.requestId)
    const attackId = toNonEmptyString(dastEvidence.attackId)
        || toNonEmptyString(dastEvidence.attack?.id)
        || toNonEmptyString(finding.attackId)
    const requestRecord = resolveRequestRecord(scanResult, requestId)
    const attackRecord = resolveAttackRecord(requestRecord, attackId, ruleId)
    const attackEvidence = (dastEvidence.attack && typeof dastEvidence.attack === 'object')
        ? dastEvidence.attack
        : {}
    const evidenceMeta = (dastEvidence.meta && typeof dastEvidence.meta === 'object')
        ? dastEvidence.meta
        : {}
    const sourceAttack = attackRecord || attackEvidence

    const locationUrl = toUriLike(finding.location?.url)
        || toUriLike(sourceAttack?.request?.url)
        || toUriLike(requestRecord?.original?.request?.url)
    if (!locationUrl) return null

    const locationMethod = toNonEmptyString(finding.location?.method)
        || toNonEmptyString(sourceAttack?.request?.method)
        || toNonEmptyString(requestRecord?.original?.request?.method)
        || 'GET'
    const locationParam = toNonEmptyString(finding.location?.param)
        || toNonEmptyString(sourceAttack?.param)
        || toNonEmptyString(dastEvidence.param)

    const proofValue = toNonEmptyString(dastEvidence.proof)
        || toNonEmptyString(sourceAttack?.proof)
        || toNonEmptyString(finding.proof)
    const proofSummary = resolveProofSummary({ finding, sourceAttack, ruleId, proofValue })

    const requestObj = sourceAttack?.request || requestRecord?.original?.request || {}
    const responseObj = sourceAttack?.response || requestRecord?.original?.response || {}
    const statusCode = toStatusCode(responseObj?.statusCode || sourceAttack?.statusCode)
    const responseTimeMs = Number(responseObj?.timeMs ?? sourceAttack?.timeMs)
    const requestUrl = toUriLike(requestObj?.url)
        || toUriLike(requestObj?.ui_url)
        || locationUrl
    const requestMethod = toNonEmptyString(requestObj?.method) || locationMethod
    const requestRaw = toNonEmptyString(requestObj?.raw) || buildRawRequest(requestObj, {
        url: requestUrl,
        method: requestMethod
    })
    const requestTimestamp = toTimestampMs(
        requestObj?.timestamp
        ?? requestObj?.timeStamp
        ?? requestObj?.ts
        ?? sourceAttack?.requestTimestamp
        ?? requestRecord?.original?.request?.timestamp
        ?? requestRecord?.original?.request?.timeStamp
        ?? requestRecord?.original?.request?.ts
    )
    const responseRaw = toNonEmptyString(responseObj?.raw) || buildRawResponse({
        statusCode,
        statusLine: responseObj?.statusLine,
        headers: responseObj?.headers,
        body: responseObj?.body
    })

    const fingerprint = toNonEmptyString(finding.fingerprint)
        || toNonEmptyString(finding.id)
        || stableHash(`${scanId || ''}|${moduleId}|${ruleId}|${locationUrl}|${locationParam || ''}|${statusCode}`)

    const mapped = {
        id: toNonEmptyString(finding.id) || fingerprint,
        fingerprint,
        moduleId,
        ruleId,
        attackId: ruleId,
        severity: toSeverity(finding.severity || finding.effectiveSeverity),
        confidence: toConfidence(finding.confidence ?? sourceAttack?.meta?.confidence ?? evidenceMeta?.confidence),
        summary: proofSummary,
        location: {
            url: locationUrl,
            route: toNonEmptyString(finding.location?.route) || null,
            method: locationMethod,
            param: locationParam || null
        },
        proof: {
            payload: resolvePayloadValue(sourceAttack?.payload ?? dastEvidence?.payload),
            proof: proofValue || null,
            summary: proofSummary
        },
        request: {
            timestamp: requestTimestamp,
            method: requestMethod,
            url: requestUrl,
            raw: requestRaw
        },
        response: {
            statusCode
        }
    }

    if (Number.isFinite(responseTimeMs) && responseTimeMs >= 0) {
        mapped.response.timeMs = Math.round(responseTimeMs)
    }
    mapped.response.raw = responseRaw

    return mapped
}
