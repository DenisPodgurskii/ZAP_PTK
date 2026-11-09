import CryptoES from '../../packages/crypto-es/index.js'

export const IAST_OBSERVATION_LIMITS = Object.freeze({ records: 4096, recordBytes: 64 * 1024, scanBytes: 32 * 1024 * 1024 })
const GRADES = new Set(['substring', 'lexical_word_boundary', 'canonical_url_equality', 'primitive_fingerprint_equality', 'complete_value_equality', 'instrumented_propagation', 'object_identity'])
const RELATIONS = new Set([...GRADES, 'unavailable'])
const ACQUISITIONS = new Set(['instrumented_read', 'instrumented_write', 'initial_snapshot', 'sink_storage_snapshot', 'existing_other'])
const CONTROLS = new Set(['observed', 'inferred', 'unknown', 'not_applicable'])
const identityStates = new WeakMap()
const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : null
const string = (value, max) => typeof value === 'string' && value.length <= max && !/[\u0000-\u001f]/.test(value) ? value : null
const optionalString = (value, max, reason) => value == null || value === '' ? null : (string(value, max) || fail(reason))
const fail = reason => { const error = new Error(reason); error.code = reason; throw error }
const enumValue = (value, values, reason) => values.has(value) ? value : fail(reason)
const integer = (value, min = 0) => Number.isSafeInteger(value) && value >= min && value <= 2147483647 ? value : null

export function sanitizeIastObservation(value) {
    if (value == null) return null
    if (!object(value) || value.schemaVersion !== 2 || value.identityVersion !== 2) fail('unsupported_iast_observation_version')
    const kind = enumValue(value.kind, new Set(['source_relationship', 'policy_signal']), 'invalid_iast_observation_kind')
    const operationId = string(value.operationId, 128)
    if (!operationId) fail('invalid_iast_observation_operation')
    const acquisition = enumValue(value.acquisition, ACQUISITIONS, 'invalid_iast_acquisition')
    const evidenceGrade = value.evidenceGrade == null && kind === 'policy_signal' ? null : enumValue(value.evidenceGrade, GRADES, 'invalid_iast_evidence_grade')
    const inheritedGrade = value.inheritedGrade == null ? null : enumValue(value.inheritedGrade, GRADES, 'invalid_iast_inherited_grade')
    const valueRelation = enumValue(value.valueRelation, RELATIONS, 'invalid_iast_value_relation')
    const attackerControl = enumValue(value.attackerControl, CONTROLS, 'invalid_iast_control')
    if (value.gradeAuthority !== 'page_observed_untrusted') fail('invalid_iast_grade_authority')
    const controlReason = string(value.controlReason, 160)
    if (!controlReason) fail('invalid_iast_control_reason')
    const source = object(value.sourceBinding)
    let sourceBinding = null
    if (kind === 'source_relationship') {
        if (!source || !string(source.key, 512) || !string(source.kind, 80)) fail('invalid_iast_source_binding')
        sourceBinding = { sourceId: optionalString(source.sourceId, 128, 'invalid_iast_source_binding'), key: source.key, kind: source.kind }
    } else if (source || evidenceGrade !== null || attackerControl !== 'not_applicable') fail('invalid_iast_policy_observation')
    const rawSite = object(value.site)
    const siteKind = enumValue(rawSite?.kind, new Set(['code', 'dom', 'unresolved']), 'invalid_iast_site')
    let site
    if (siteKind === 'code') {
        const scriptUrl = string(rawSite.scriptUrl, 2048)
        const line = integer(rawSite.line, 1), column = integer(rawSite.column)
        if (!scriptUrl || !/^https?:\/\//i.test(scriptUrl) || line === null || column === null) fail('invalid_iast_code_site')
        try { if (new URL(scriptUrl).username || new URL(scriptUrl).password) fail('invalid_iast_code_site') } catch (_) { fail('invalid_iast_code_site') }
        site = { kind: siteKind, scriptUrl, line, column }
        const operation = optionalString(rawSite.operation, 128, 'invalid_iast_site_operation')
        if (operation) site.operation = operation
    } else if (siteKind === 'dom') {
        const domPath = optionalString(rawSite.domPath, 1024, 'invalid_iast_dom_site')
        const operation = optionalString(rawSite.operation, 128, 'invalid_iast_site_operation')
        if (!domPath && !operation) fail('invalid_iast_dom_site')
        site = { kind: siteKind, domPath, attribute: optionalString(rawSite.attribute, 80, 'invalid_iast_site_attribute'), operation }
        const observationId = optionalString(rawSite.observationId, 128, 'invalid_iast_observation_operation')
        if (observationId) site.observationId = observationId
    } else {
        const observationId = optionalString(rawSite.observationId, 128, 'invalid_iast_observation_operation') || operationId
        site = { kind: siteKind, observationId }
        const operation = optionalString(rawSite.operation, 128, 'invalid_iast_site_operation')
        if (operation) site.operation = operation
    }
    const completeness = object(value.completeness)
    if (!completeness || !['complete', 'limited'].includes(completeness.status) || !Array.isArray(completeness.reasons) || completeness.reasons.length > 16) fail('invalid_iast_observation_completeness')
    const reasons = [...new Set(completeness.reasons.map(reason => string(reason, 64) || fail('invalid_iast_completeness_reason')))]
    const propagation = value.propagation == null ? null : object(value.propagation)
    if (value.propagation != null && (!propagation || !string(propagation.operation, 128) || !GRADES.has(propagation.inheritedGrade))) fail('invalid_iast_propagation')
    if (acquisition === 'sink_storage_snapshot' && (attackerControl === 'observed' || evidenceGrade === 'object_identity' || evidenceGrade === 'instrumented_propagation' || propagation)) fail('invalid_iast_inferred_provenance')
    return {
        schemaVersion: 2, identityVersion: 2, kind, operationId, acquisition, evidenceGrade, inheritedGrade, valueRelation,
        gradeAuthority: 'page_observed_untrusted', attackerControl, controlReason,
        propagation: propagation ? { operation: propagation.operation, inheritedGrade: propagation.inheritedGrade } : null,
        site, completeness: { status: completeness.status, reasons }, sourceBinding
    }
}

export function validateIastEvidenceVersion(evidence = {}) {
    const rawVersion = evidence.schemaVersion
    const version = rawVersion == null || rawVersion === 'iast-evidence@1' ? 1
        : rawVersion === 'iast-evidence@2' ? 2 : rawVersion
    if (version !== 1 && version !== 2) fail('unsupported_iast_evidence_version')
    if (version === 2 && !evidence.observation) fail('missing_iast_observation')
    if (evidence.observation && version !== 2) fail('iast_evidence_version_mismatch')
    return version
}

export function iastSerializedBytes(value) { return new TextEncoder().encode(JSON.stringify(value)).byteLength }

function secureId() {
    const crypto = globalThis.crypto
    if (!crypto?.getRandomValues) fail('iast_identity_crypto_unavailable')
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('')
}

export function createIastPublicId() { return `iast-v2-${secureId().slice(0, 32)}` }

export function resetIastIdentityState(owner) {
    identityStates.set(owner, { key: secureId(), entries: new Map(), bytes: 0 })
}

export function forgetIastIdentityState(owner) { identityStates.delete(owner) }

export function buildIastObservationTuple(finding, documentIdentity = null) {
    const evidence = finding?.evidence?.iast || {}
    const observation = sanitizeIastObservation(evidence.observation)
    if (!observation) fail('missing_iast_observation')
    const ownerUrl = finding?.location?.url
    if (!string(ownerUrl, 16384) || !/^https?:\/\//i.test(ownerUrl)) fail('invalid_iast_owner_url')
    const source = observation.sourceBinding
    if (String(evidence.sinkId || finding.sinkId || '').startsWith('code.') && observation.site.kind === 'dom') fail('invalid_iast_code_site')
    const carrier = evidence.context?.transportCarrierKey || null
    const site = observation.site.kind === 'code'
        ? ['code', observation.site.scriptUrl, observation.site.line, observation.site.column]
        : observation.site.kind === 'dom'
            ? ['dom', observation.site.domPath, observation.site.attribute, observation.site.operation, observation.site.observationId || null]
            : ['unresolved', documentIdentity, observation.site.observationId]
    return [2, finding.scanId, ownerUrl, finding.moduleId, finding.ruleId,
        source ? [source.kind, source.key] : null, evidence.sinkId || finding.sinkId, site, carrier,
        [evidence.primaryClass, observation.acquisition, observation.valueRelation, observation.evidenceGrade,
            observation.inheritedGrade, observation.propagation, observation.attackerControl, evidence.detection?.reason || null,
            finding.severity, Math.min(100, Math.max(0, Math.round(Number(finding.confidence) || 0)))]]
}

// Exact tuples and the scan HMAC key never become properties of a scan/finding.
// The public UUID is stable once admitted and survives a redacted round trip.
export function admitIastObservationIdentity(owner, finding, { documentIdentity = null, limits = IAST_OBSERVATION_LIMITS } = {}) {
    const state = identityStates.get(owner)
    if (!state) fail('iast_identity_state_unavailable')
    const tuple = buildIastObservationTuple(finding, documentIdentity)
    const digest = CryptoES.HmacSHA256(JSON.stringify(tuple), state.key).toString(CryptoES.enc.Hex)
    const existing = state.entries.get(digest)
    if (existing) return { ...existing, existing: true }
    const publicId = createIastPublicId()
    const aggregate = { identityVersion: 2, mode: 'url-site-stratum', key: publicId }
    const byteEvidence = { ...finding.evidence, iast: { ...finding.evidence.iast, aggregate,
        occurrenceCount: Number.MAX_SAFE_INTEGER, sampleLimit: 0, truncated: false, samples: [] } }
    const bytes = iastSerializedBytes(byteEvidence)
    if (bytes > limits.recordBytes) fail('iast_record_bytes_exceeded')
    if (state.entries.size >= limits.records) fail('iast_record_limit_exceeded')
    if (state.bytes + bytes > limits.scanBytes) fail('iast_scan_bytes_exceeded')
    const entry = { publicId, bytes }
    state.entries.set(digest, entry)
    state.bytes += bytes
    return { ...entry, existing: false }
}

export function createIastScanCompleteness() {
    return { schemaVersion: 2, revision: 1, status: 'unknown', reasons: ['document_receipts_pending'], counters: { lossCount: 0, recordsRejected: 0 }, terminal: false }
}

export function validateIastImportedFindings(findings, { limits = IAST_OBSERVATION_LIMITS } = {}) {
    if (!Array.isArray(findings)) return
    let records = 0, bytes = 0
    for (const finding of findings) {
        const evidence = finding?.evidence?.iast || finding?.evidence || {}
        const version = validateIastEvidenceVersion(evidence)
        if (version !== 2) continue
        sanitizeIastObservation(evidence.observation)
        const size = iastSerializedBytes(finding.evidence)
        if (++records > limits.records) fail('iast_record_limit_exceeded')
        if (size > limits.recordBytes) fail('iast_record_bytes_exceeded')
        if ((bytes += size) > limits.scanBytes) fail('iast_scan_bytes_exceeded')
        if (!/^iast-v2-[a-f0-9]{32}$/.test(finding.fingerprint || '')) fail('invalid_iast_public_identity')
    }
}

export function sanitizeIastScanCompleteness(value) {
    if (!object(value) || value.schemaVersion !== 2 || !['complete', 'partial', 'unknown'].includes(value.status)
        || !Number.isSafeInteger(value.revision) || value.revision < 0 || typeof value.terminal !== 'boolean'
        || !Array.isArray(value.reasons) || value.reasons.length > 16 || !object(value.counters)) fail('invalid_iast_scan_completeness')
    const reasons = [...new Set(value.reasons.map(reason => typeof reason === 'string' && /^[a-z0-9_]{1,64}$/.test(reason) ? reason : fail('invalid_iast_completeness_reason')))]
    const counters = {}
    for (const key of ['lossCount', 'recordsRejected']) {
        const count = value.counters[key]
        if (!Number.isSafeInteger(count) || count < 0) fail('invalid_iast_completeness_counter')
        counters[key] = count
    }
    if (value.status === 'complete' && (!value.terminal || reasons.length || counters.lossCount || counters.recordsRejected)) fail('invalid_iast_complete_status')
    return { schemaVersion: 2, revision: value.revision, status: value.status, reasons, counters, terminal: value.terminal }
}
