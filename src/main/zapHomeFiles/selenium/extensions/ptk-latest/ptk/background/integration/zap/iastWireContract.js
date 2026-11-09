'use strict'

export const IAST_WIRE_V1 = 'ptk-zap-iast-finding-v1'
export const IAST_WIRE_V2 = 'ptk-zap-iast-finding-v2'
export const IAST_WIRE_V3 = 'ptk-zap-iast-finding-v3'
const GRADES = new Set(['substring', 'lexical_word_boundary', 'canonical_url_equality', 'primitive_fingerprint_equality', 'complete_value_equality', 'instrumented_propagation', 'object_identity'])
const ACQUISITIONS = new Set(['instrumented_read', 'instrumented_write', 'initial_snapshot', 'sink_storage_snapshot', 'existing_other'])
const CONTROL = new Set(['observed', 'inferred', 'unknown', 'not_applicable'])

export function iastContractError(code, message = code) {
    return Object.assign(new Error(message), { permanent: true, code })
}

function check(condition) {
    if (!condition) throw iastContractError('invalid_payload', 'Invalid IAST v2 observation/completeness contract')
}

function object(value, keys, required = []) {
    check(value && typeof value === 'object' && !Array.isArray(value))
    check(Object.keys(value).every(key => keys.includes(key)))
    check(required.every(key => Object.prototype.hasOwnProperty.call(value, key)))
}

function text(value, limit, nullable = false) {
    if (nullable && value === null) return null
    check(typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value))
    return value
}

function reasons(value) {
    check(Array.isArray(value) && value.length <= 16)
    check(value.every(reason => typeof reason === 'string' && /^[a-z][a-z0-9_.:-]{0,63}$/.test(reason)))
    check(new Set(value).size === value.length)
    return value.slice().sort()
}

export function sanitizeIastObservation(value) {
    object(value, ['schemaVersion', 'identityVersion', 'kind', 'operationId', 'acquisition', 'evidenceGrade', 'inheritedGrade', 'valueRelation', 'propagation', 'gradeAuthority', 'attackerControl', 'controlReason', 'site', 'completeness', 'sourceBinding'], ['schemaVersion', 'identityVersion', 'kind', 'operationId', 'acquisition', 'evidenceGrade', 'inheritedGrade', 'valueRelation', 'propagation', 'gradeAuthority', 'attackerControl', 'controlReason', 'site', 'completeness', 'sourceBinding'])
    check(value.schemaVersion === 2 && value.identityVersion === 2)
    check(['source_relationship', 'policy_signal'].includes(value.kind))
    text(value.operationId, 128)
    check(ACQUISITIONS.has(value.acquisition) && CONTROL.has(value.attackerControl))
    check(value.gradeAuthority === 'page_observed_untrusted')
    text(value.controlReason, 160)
    const policy = value.kind === 'policy_signal'
    check(policy ? value.evidenceGrade === null && value.inheritedGrade === null && value.sourceBinding === null && value.attackerControl === 'not_applicable' && value.valueRelation === 'unavailable' : GRADES.has(value.evidenceGrade) && (value.inheritedGrade === null || GRADES.has(value.inheritedGrade)) && GRADES.has(value.valueRelation) && value.valueRelation !== 'instrumented_propagation')
    if (!policy) {
        object(value.sourceBinding, ['sourceId', 'key', 'kind'], ['sourceId', 'key', 'kind'])
        text(value.sourceBinding.sourceId, 128, true)
        text(value.sourceBinding.key, 512)
        text(value.sourceBinding.kind, 80)
    }
    if (value.acquisition === 'sink_storage_snapshot') {
        check(!policy && ['localStorage', 'sessionStorage'].includes(value.sourceBinding.kind)
            && value.evidenceGrade === 'complete_value_equality' && value.valueRelation === 'complete_value_equality'
            && ['unknown', 'inferred'].includes(value.attackerControl))
    }
    if (value.propagation !== null) {
        object(value.propagation, ['operation', 'inheritedGrade'], ['operation', 'inheritedGrade'])
        text(value.propagation.operation, 128)
        check(GRADES.has(value.propagation.inheritedGrade) && !policy)
    }
    object(value.site, ['kind', 'scriptUrl', 'line', 'column', 'domPath', 'attribute', 'operation', 'observationId'], ['kind'])
    check(['code', 'dom', 'unresolved'].includes(value.site.kind))
    for (const [key, limit] of [['scriptUrl', 2048], ['domPath', 1024], ['attribute', 80], ['operation', 128], ['observationId', 128]]) {
        if (value.site[key] !== undefined && value.site[key] !== null) text(value.site[key], limit)
    }
    for (const key of ['line', 'column']) if (value.site[key] !== undefined && value.site[key] !== null) check(Number.isSafeInteger(value.site[key]) && value.site[key] <= 2147483647 && value.site[key] >= (key === 'line' ? 1 : 0))
    if (value.site.kind === 'code') check(typeof value.site.scriptUrl === 'string' && Number.isSafeInteger(value.site.line) && Number.isSafeInteger(value.site.column))
    if (value.site.kind === 'unresolved') text(value.site.observationId || value.operationId, 128)
    object(value.completeness, ['status', 'reasons'], ['status', 'reasons'])
    check(['complete', 'limited'].includes(value.completeness.status))
    const result = structuredClone(value)
    result.completeness.reasons = reasons(value.completeness.reasons)
    check(JSON.stringify(result).length <= 8192)
    return result
}

export function sanitizeIastScanCompleteness(value) {
    object(value, ['schemaVersion', 'revision', 'status', 'reasons', 'counters', 'terminal'], ['schemaVersion', 'revision', 'status', 'reasons', 'counters', 'terminal'])
    check(value.schemaVersion === 2 && Number.isSafeInteger(value.revision) && value.revision >= 0)
    check(['unknown', 'partial', 'complete'].includes(value.status) && typeof value.terminal === 'boolean')
    object(value.counters, ['lossCount', 'recordsRejected'], ['lossCount', 'recordsRejected'])
    check(Object.values(value.counters).every(count => Number.isSafeInteger(count) && count >= 0))
    check(value.status !== 'complete' || (value.terminal && value.counters.lossCount === 0 && value.counters.recordsRejected === 0 && value.reasons.length === 0))
    return { schemaVersion: 2, revision: value.revision, status: value.status, reasons: reasons(value.reasons), counters: { ...value.counters }, terminal: value.terminal }
}
