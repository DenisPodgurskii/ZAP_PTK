'use strict'

function normalizeEngine(value) {
    return String(value || '').trim().toUpperCase()
}

function isObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function normalizeSastFindingKind(finding = {}) {
    const raw = finding?.findingKind
        || finding?.evidence?.sast?.findingKind
        || finding?.metadata?.findingKind
        || 'finding'
    const normalized = String(raw || 'finding').trim().toLowerCase()
    return normalized || 'finding'
}

export function isZapExportableFinding(engine, finding) {
    if (!isObject(finding)) return false

    const normalizedEngine = normalizeEngine(engine || finding.engine)
    if (normalizedEngine === 'SAST') {
        return normalizeSastFindingKind(finding) === 'finding'
    }

    if (normalizedEngine === 'IAST') {
        return !!finding?.moduleId && !!finding?.ruleId && isObject(finding?.evidence?.iast)
    }

    if (normalizedEngine === 'DAST') {
        return !!finding?.moduleId && !!finding?.ruleId && isObject(finding?.evidence?.dast)
    }

    return false
}

