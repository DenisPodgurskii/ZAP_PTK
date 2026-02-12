'use strict'

const MAX_EVIDENCE_LEN = 1024
const MAX_TEXT_LEN = 4096

function toNonEmptyString(value) {
    if (typeof value !== 'string') return null
    const trimmed = value.trim()
    return trimmed ? trimmed : null
}

function clamp(value, min, max) {
    const num = Number(value)
    if (!Number.isFinite(num)) return min
    const intVal = Math.trunc(num)
    return Math.max(min, Math.min(max, intVal))
}

function truncate(value, maxLen) {
    if (value === null || value === undefined) return null
    const text = String(value)
    if (!text) return null
    return text.length > maxLen ? text.slice(0, maxLen) : text
}

function stableHash(input) {
    const str = String(input || '')
    let hash = 0x811c9dc5
    for (let i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i)
        hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24)
    }
    const normalized = hash >>> 0
    return `fnv1a-${normalized.toString(16).padStart(8, '0')}`
}

function safeSerialize(value, maxLen = MAX_EVIDENCE_LEN) {
    if (value === null || value === undefined) return null
    if (typeof value === 'string') return truncate(value, maxLen)
    if (typeof value === 'number' || typeof value === 'boolean') return truncate(String(value), maxLen)

    const seen = new WeakSet()
    try {
        const serialized = JSON.stringify(value, (key, currentValue) => {
            if (typeof currentValue === 'object' && currentValue !== null) {
                if (seen.has(currentValue)) return '[Circular]'
                seen.add(currentValue)
            }
            return currentValue
        })
        return truncate(serialized, maxLen)
    } catch (_) {
        return truncate(String(value), maxLen)
    }
}

function resolveUrl(finding) {
    const directCandidates = [
        finding?.url,
        finding?.location?.url,
        finding?.location?.runtimeUrl,
        finding?.location?.pageUrl,
        finding?.pageUrl
    ]

    for (const candidate of directCandidates) {
        const value = toNonEmptyString(candidate)
        if (value) return value
    }

    const file = finding?.location?.file
    const fileValue = toNonEmptyString(file)
    if (!fileValue) return null
    if (/^https?:\/\//i.test(fileValue)) return fileValue
    if (/^\/\//.test(fileValue)) return `https:${fileValue}`
    return null
}

function normalizeSeverity(value) {
    const severity = String(value || 'info').toLowerCase()
    if (severity === 'critical') return 'critical'
    if (severity === 'high') return 'high'
    if (severity === 'medium') return 'medium'
    if (severity === 'low') return 'low'
    return 'info'
}

function mapRiskIdFromSeverity(severity) {
    if (severity === 'critical' || severity === 'high') return 3
    if (severity === 'medium') return 2
    if (severity === 'low') return 1
    return 0
}

function resolveConfidenceId(finding) {
    const raw = Number(finding?.confidenceId)
    return Number.isFinite(raw) ? clamp(raw, 1, 3) : 2
}

function looksLikeUrl(value) {
    return typeof value === 'string' && /^https?:\/\//i.test(value.trim())
}

function objectReferenceLines(obj) {
    const lines = []
    for (const [key, value] of Object.entries(obj || {})) {
        if (value === null || value === undefined) continue

        if (typeof value === 'string') {
            lines.push(looksLikeUrl(value) ? value : `${key}: ${value}`)
            continue
        }

        if (Array.isArray(value)) {
            for (const item of value) {
                if (typeof item === 'string') {
                    lines.push(looksLikeUrl(item) ? item : `${key}: ${item}`)
                } else if (item && typeof item === 'object') {
                    const nestedUrl = toNonEmptyString(item.url) || toNonEmptyString(item.href)
                    lines.push(nestedUrl && looksLikeUrl(nestedUrl) ? nestedUrl : `${key}: ${safeSerialize(item, 1024)}`)
                } else {
                    lines.push(`${key}: ${String(item)}`)
                }
            }
            continue
        }

        if (value && typeof value === 'object') {
            const nestedUrl = toNonEmptyString(value.url) || toNonEmptyString(value.href)
            lines.push(nestedUrl && looksLikeUrl(nestedUrl) ? nestedUrl : `${key}: ${safeSerialize(value, 1024)}`)
            continue
        }

        lines.push(`${key}: ${String(value)}`)
    }
    return lines
}

function serializeReferences(linksOrRefs) {
    if (linksOrRefs === null || linksOrRefs === undefined) return null

    if (typeof linksOrRefs === 'string') {
        return truncate(linksOrRefs, MAX_TEXT_LEN)
    }

    if (Array.isArray(linksOrRefs)) {
        const lines = linksOrRefs.map(value => {
            if (typeof value === 'string') return value
            if (value && typeof value === 'object') {
                const objectUrl = toNonEmptyString(value.url) || toNonEmptyString(value.href)
                return objectUrl || safeSerialize(value, 1024)
            }
            return String(value)
        }).filter(Boolean)

        return truncate(lines.join('\n'), MAX_TEXT_LEN)
    }

    if (typeof linksOrRefs === 'object') {
        const lines = objectReferenceLines(linksOrRefs)
        return truncate(lines.join('\n'), MAX_TEXT_LEN)
    }

    return truncate(String(linksOrRefs), MAX_TEXT_LEN)
}

function resolveAttack(finding, engine) {
    if (engine === 'DAST') {
        return safeSerialize(finding?.evidence?.dast?.attack || finding?.evidence?.dast?.payload || null)
    }
    if (engine === 'IAST') {
        return safeSerialize(finding?.evidence?.iast?.matched || null)
    }
    return null
}

function resolveEvidence(finding, engine) {
    if (typeof finding?.evidence === 'string') {
        return truncate(finding.evidence, MAX_EVIDENCE_LEN)
    }

    if (engine === 'DAST') {
        return safeSerialize(
            finding?.evidence?.dast?.proof
            || finding?.evidence?.dast?.attack?.proof
            || finding?.evidence?.dast?.attack
            || finding?.evidence?.dast?.payload
            || finding?.evidence?.dast
            || null
        )
    }

    if (engine === 'IAST') {
        return safeSerialize(
            finding?.evidence?.iast?.matched
            || finding?.evidence?.iast?.message
            || finding?.evidence?.iast?.trace
            || finding?.evidence?.iast
            || null
        )
    }

    if (engine === 'SAST') {
        return safeSerialize(
            finding?.evidence?.sast?.codeSnippet
            || finding?.evidence?.sast?.sink
            || finding?.evidence?.sast?.trace
            || finding?.evidence?.sast
            || null
        )
    }

    if (engine === 'SCA') {
        return safeSerialize(
            finding?.evidence?.sca?.identifiers?.summary
            || finding?.evidence?.sca?.component
            || finding?.evidence?.sca
            || null
        )
    }

    return safeSerialize(finding?.evidence || null)
}

function extractCweId(cwe) {
    const values = Array.isArray(cwe) ? cwe : [cwe]
    for (const value of values) {
        if (Number.isFinite(value)) return Math.trunc(value)
        if (typeof value === 'string') {
            const match = value.match(/(\d{1,6})/)
            if (match) return Number(match[1])
        } else if (value && typeof value === 'object') {
            const candidate = value.id ?? value.cwe ?? value.value
            if (Number.isFinite(candidate)) return Math.trunc(candidate)
            if (typeof candidate === 'string') {
                const match = candidate.match(/(\d{1,6})/)
                if (match) return Number(match[1])
            }
        }
    }
    return null
}

function buildTags(finding, engine, severity) {
    const tags = new Set()
    const normalizedEngine = String(engine || finding?.engine || '').toUpperCase() || 'UNKNOWN'
    tags.add(`ptk:engine=${normalizedEngine}`)

    if (severity === 'critical') {
        tags.add('ptk:severity=critical')
    }

    if (Array.isArray(finding?.tags)) {
        for (const tag of finding.tags) {
            const text = toNonEmptyString(tag)
            if (text) tags.add(text)
        }
    }

    return Array.from(tags)
}

function buildOtherInfo({ engine, finding, scanId }) {
    const entries = [
        `engine=${String(engine || finding?.engine || 'UNKNOWN').toUpperCase()}`,
        `moduleId=${finding?.moduleId || 'n/a'}`,
        `ruleId=${finding?.ruleId || 'n/a'}`,
        `scanId=${scanId || finding?.scanId || 'n/a'}`
    ]
    return entries.join('; ')
}

export function toAlert(finding, { engine, scanId } = {}) {
    if (!finding || typeof finding !== 'object') return null

    const normalizedEngine = String(engine || finding.engine || '').toUpperCase() || 'UNKNOWN'
    const normalizedScanId = scanId || finding.scanId || null

    const name = finding.title || finding.ruleName || finding.category || 'PTK Finding'
    const url = resolveUrl(finding)
    if (!url) return null

    const severity = normalizeSeverity(finding.severity || finding.effectiveSeverity)
    const riskId = clamp(mapRiskIdFromSeverity(severity), 0, 3)
    const confidenceId = resolveConfidenceId(finding)
    const param = toNonEmptyString(finding.param) || toNonEmptyString(finding?.location?.param) || null
    const attack = resolveAttack(finding, normalizedEngine)
    const evidence = resolveEvidence(finding, normalizedEngine)
    const description = truncate(finding.description, MAX_TEXT_LEN)
    const solution = truncate(finding.recommendation, MAX_TEXT_LEN)
    const references = serializeReferences(finding.links ?? finding.references)
    const cweId = extractCweId(finding.cwe)
    const tags = buildTags(finding, normalizedEngine, severity)
    const otherInfo = truncate(buildOtherInfo({ engine: normalizedEngine, finding, scanId: normalizedScanId }), MAX_TEXT_LEN)
    const fingerprint = toNonEmptyString(finding.fingerprint)
        || toNonEmptyString(finding.id)
        || stableHash(`${url}${name}${normalizedEngine}${finding.category || ''}${param || ''}`)

    return {
        name: String(name),
        url,
        riskId,
        confidenceId,
        param,
        attack,
        evidence,
        description,
        solution,
        references,
        cweId,
        wascId: null,
        tags,
        otherInfo,
        fingerprint
    }
}

export { stableHash }
