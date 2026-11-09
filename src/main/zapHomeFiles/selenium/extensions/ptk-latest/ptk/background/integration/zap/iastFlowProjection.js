'use strict'

import { redactSensitiveStrings } from '../../export/buildExportScanResult.js'
import { iastContractError } from './iastWireContract.js'

// Read data descriptors only: projection must never execute page-provided getters
// or coerce objects, including when collecting the local masking candidates.
function own(value, key) {
    if (!value || typeof value !== 'object') return undefined
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (descriptor && !Object.prototype.hasOwnProperty.call(descriptor, 'value')) throw iastContractError('invalid_payload')
    return descriptor?.value
}
function requireFlow(condition) {
    if (!condition) throw iastContractError('invalid_payload', 'Invalid ordered IAST flow binding or shape')
}

export function projectIastFlow(nativeFlow, observation, sink, sources = []) {
    const unavailable = reason => ({ schemaVersion: 1, status: 'unavailable', reasons: [reason], steps: [] })
    if (observation.kind === 'policy_signal') return unavailable('flow_policy_signal')
    if (nativeFlow === null || nativeFlow === undefined || (Array.isArray(nativeFlow) && nativeFlow.length === 0)) return unavailable('flow_absent')
    requireFlow(Array.isArray(nativeFlow) && nativeFlow.length <= 4096)
    const reasons = []
    const limited = reason => { if (!reasons.includes(reason)) reasons.push(reason) }
    const candidates = []
    let candidateBytes = 0
    const candidate = value => {
        if (typeof value !== 'string' || !value.length || candidates.includes(value)) return
        // Longer values or excess candidates cannot be masked with bounded work.
        // Suppress metadata text rather than retaining a partial secret candidate.
        if (value.length > 4096 || candidates.length >= 64 || candidateBytes + value.length > 65536) { maskUnavailable = true; return }
        candidates.push(value); candidateBytes += value.length
    }
    let maskUnavailable = false
    for (let index = 0; index < nativeFlow.length; index++) {
        const step = own(nativeFlow, String(index))
        requireFlow(step && typeof step === 'object' && !Array.isArray(step))
        const stage = own(step, 'stage')
        requireFlow(['source', 'propagation', 'sink'].includes(stage))
        candidate(own(step, 'value'))
    }
    requireFlow(Array.isArray(sources) && sources.length <= 64)
    for (let index = 0; index < sources.length; index++) {
        const source = own(sources, String(index))
        candidate(own(source, 'raw')); candidate(own(source, 'value'))
    }
    candidates.sort((a, b) => b.length - a.length)
    const clean = (value, limit) => {
        if (value === null || value === undefined) return null
        requireFlow(typeof value === 'string')
        if (maskUnavailable || value.length > 65536) { limited('flow_field_limit'); return null }
        let result = redactSensitiveStrings(value)
        for (const secret of candidates) result = result.split(secret).join('[REDACTED]')
        if (result.length > limit) { limited('flow_field_limit'); result = result.slice(0, limit) }
        return result
    }
    const location = value => {
        if (value === null || value === undefined) return null
        requireFlow(typeof value === 'string')
        if (value.length > 65536) { limited('flow_field_limit'); return null }
        try {
            const url = new URL(value)
            if (!['http:', 'https:'].includes(url.protocol)) return null
            url.username = ''; url.password = ''; url.search = ''; url.hash = ''
            const result = clean(url.href, 65536)
            if (result === null) return null
            const redacted = new URL(result)
            if (!['http:', 'https:'].includes(redacted.protocol) || redacted.username || redacted.password || redacted.search || redacted.hash) return null
            // WHATWG URL retains literal brackets in paths, while Java URI
            // correctly rejects them. Encode the redaction marker after masking
            // and retain one canonical URL without cutting a percent escape.
            redacted.pathname = redacted.pathname
                .replace(/[^A-Za-z0-9\-._~!$&'()*+,;=:@/%]/g, character => encodeURIComponent(character))
                .replace(/%(?![0-9A-Fa-f]{2})/g, '%25')
            const canonical = redacted.href
            if (canonical.length > 2048) { limited('flow_field_limit'); return null }
            return canonical
        } catch (_) { return null }
    }
    const binding = observation.sourceBinding
    const isSelected = step => ['source', 'propagation'].includes(own(step, 'stage')) &&
        (own(step, 'key') === binding.key || (binding.sourceId !== null && binding.sourceId !== undefined &&
        (own(step, 'key') === binding.sourceId || own(step, 'sourceId') === binding.sourceId)))
    let selectedPresent = false
    for (let index = 0; index < nativeFlow.length; index++) if (isSelected(own(nativeFlow, String(index)))) selectedPresent = true
    requireFlow(selectedPresent)
    const final = own(nativeFlow, String(nativeFlow.length - 1))
    requireFlow(own(final, 'stage') === 'sink' && own(final, 'key') === sink.id)
    if (nativeFlow.length >= 22) limited('flow_upstream_at_limit')
    if (nativeFlow.length > 22) limited('flow_step_limit')
    const indices = nativeFlow.length > 22 ? [...Array.from({ length: 21 }, (_, i) => i), nativeFlow.length - 1] : Array.from({ length: nativeFlow.length }, (_, i) => i)
    if (!indices.some(index => isSelected(own(nativeFlow, String(index))))) {
        limited('flow_source_not_retained')
        return { schemaVersion: 1, status: 'limited', reasons, steps: [] }
    }
    const steps = indices.map(index => {
        const step = own(nativeFlow, String(index))
        const operation = clean(own(step, 'op'), 128)
        if (!operation) limited('flow_operation_unavailable')
        const descriptor = Object.getOwnPropertyDescriptor(step, 'value')
        const value = own(step, 'value')
        const valueType = value === null ? 'null' : typeof value
        return { index, stage: own(step, 'stage'), operation, sourceRef: isSelected(step) ? 0 : null,
            sinkRef: index === nativeFlow.length - 1 ? 0 : null, label: clean(own(step, 'label'), 256),
            location: location(own(step, 'location')),
            value: descriptor ? { state: 'withheld', type: valueType, length: typeof value === 'string' ? Math.min(4096, value.length) : null, atLimit: typeof value === 'string' && value.length >= 4096 }
                : { state: 'unavailable', type: null, length: null, atLimit: false } }
    })
    const result = { schemaVersion: 1, status: reasons.length ? 'limited' : 'observed', reasons, steps }
    if (new TextEncoder().encode(JSON.stringify(result)).length > 8192) {
        limited('flow_byte_limit'); result.status = 'limited'; result.steps = []
    }
    return result
}

const STATUSES = ['accepted_raised', 'accepted_duplicate', 'rejected_missing_mapping', 'rejected_raise_failed', 'rejected_invalid_url', 'rejected_missing_site_tree_match', 'rejected_immutable_identity_conflict', 'rejected_receipt_capacity', 'rejected_retired_session']
function ackCheck(condition) { if (!condition) throw iastContractError('invalid_ack', 'Invalid IAST v3 acknowledgement') }
function closed(value, allowed, required = allowed) {
    ackCheck(value && typeof value === 'object' && !Array.isArray(value))
    ackCheck(Object.keys(value).every(key => allowed.includes(key)) && required.every(key => Object.prototype.hasOwnProperty.call(value, key)))
}
function bounded(value, max, nullable = false) { return (nullable && value === null) || (typeof value === 'string' && value.length <= max) }
export function validateIastV3Ack(ack, batch, revision) {
    const required = ['result', 'contractVersion', 'schema', 'structuredAck', 'legacyAck', 'received', 'accepted', 'alertsRaised', 'findingResults', 'reasonCounts', 'permanentFailure', 'scanCompletenessAccepted']
    closed(ack, [...required, 'batchId', 'batchSeq', 'errorCode', 'scanCompletenessRevision'], required)
    ackCheck(['OK', 'ERROR'].includes(ack.result) && ack.contractVersion === 3 && ack.schema === 'ptk-zap-iast-finding-v3' && ack.structuredAck === true && ack.legacyAck === false)
    ackCheck(bounded(ack.batchId, 128) && ack.batchId === batch.batchId && Number.isInteger(ack.batchSeq) && ack.batchSeq >= 0 && ack.batchSeq <= 2147483647 && ack.batchSeq === batch.batchSeq)
    for (const key of ['received', 'accepted', 'alertsRaised']) ackCheck(Number.isInteger(ack[key]) && ack[key] >= 0 && ack[key] <= 200)
    ackCheck(typeof ack.permanentFailure === 'boolean' && typeof ack.scanCompletenessAccepted === 'boolean')
    if (ack.errorCode !== undefined) ackCheck(bounded(ack.errorCode, 80, true))
    if (ack.scanCompletenessRevision !== undefined) ackCheck(ack.scanCompletenessRevision === null || (Number.isSafeInteger(ack.scanCompletenessRevision) && ack.scanCompletenessRevision >= 0))
    const entries = batch.entries || []
    ackCheck(ack.received === entries.length && Array.isArray(ack.findingResults) && ack.findingResults.length === entries.length && entries.length <= 200)
    const expected = new Map(entries.map(entry => [entry.mapped.id, entry.mapped.fingerprint]))
    ackCheck(expected.size === entries.length)
    const seen = new Set(); const histogram = {}; let accepted = 0; let raised = 0
    for (const receipt of ack.findingResults) {
        closed(receipt, ['id', 'findingId', 'fingerprint', 'status', 'reason', 'alertRef'], ['id', 'findingId', 'fingerprint', 'status', 'reason'])
        for (const key of ['id', 'findingId', 'fingerprint']) ackCheck(bounded(receipt[key], 128) && receipt[key].length > 0)
        ackCheck(expected.has(receipt.id) && !seen.has(receipt.id) && receipt.findingId === receipt.id && expected.get(receipt.id) === receipt.fingerprint)
        seen.add(receipt.id)
        ackCheck(STATUSES.includes(receipt.status) && receipt.reason === receipt.status)
        if (receipt.alertRef !== undefined) ackCheck(bounded(receipt.alertRef, 64, true))
        if (receipt.status.startsWith('accepted_')) { accepted++; ackCheck(typeof receipt.alertRef === 'string' && receipt.alertRef.length > 0) }
        if (receipt.status === 'accepted_raised') raised++
        histogram[receipt.status] = (histogram[receipt.status] || 0) + 1
    }
    closed(ack.reasonCounts, Object.keys(histogram))
    ackCheck(Object.keys(histogram).every(key => ack.reasonCounts[key] === histogram[key]))
    ackCheck(ack.accepted === accepted && ack.alertsRaised === raised)
    ackCheck(ack.scanCompletenessRevision === undefined || ack.scanCompletenessRevision === null || ack.scanCompletenessRevision === revision)
    ackCheck(ack.scanCompletenessAccepted !== true || ack.scanCompletenessRevision === revision)
    return true
}
