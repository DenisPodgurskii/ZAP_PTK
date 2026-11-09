const ID = /^[A-Za-z0-9_-]{1,128}$/u

// Capability negotiation proves only that this extension build supports the
// trusted-runner protocol. It never certifies a scan, document, or visit.
export function handleZapRunnerVisitCapability(message = {}) {
    const requestId = ID.test(message?.requestId || '') ? message.requestId : null
    if (!requestId) return { ok: false, reason: 'visit_request_invalid',
        trustedRunner: 'ptk-zap-visit-v1', requestId }
    return { ok: true, kind: 'visit_capability', trustedRunner: 'ptk-zap-visit-v1',
        requestId, phases: ['prestart', 'advance', 'departure', 'clear', 'rebind', 'observe'],
        maxObservationMs: 300000, ownerBound: true }
}

// The trusted Client runner supplies its assigned target before navigation.
// The bridge independently binds that target to the pending callback owner.
export async function handleZapRunnerVisitPrestart(bridge, message = {}) {
    const requestId = ID.test(message?.requestId || '') ? message.requestId : null
    const failure = reason => ({ ok: false, reason, trustedRunner: 'ptk-zap-visit-v1',
        requestId })
    if (!requestId || !ID.test(message.zapid || '') || !ID.test(message.browserid || '')
        || typeof message.targetUrl !== 'string' || message.targetUrl.length > 2048) {
        return failure('visit_request_invalid')
    }
    let url
    try { url = new URL(message.targetUrl) } catch (_) { return failure('visit_request_invalid') }
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname
        || url.username || url.password || url.hostname.toLowerCase() === 'zap'
        || url.toString() !== message.targetUrl) return failure('visit_request_invalid')
    if (typeof bridge?.prestartOwnedVisit !== 'function') return failure('visit_prestart_unavailable')
    try {
        const result = await bridge.prestartOwnedVisit({
            zapid: message.zapid, browserid: message.browserid, targetUrl: message.targetUrl
        })
        if (!result || typeof result.ok !== 'boolean') return failure('visit_response_invalid')
        return { ...result, trustedRunner: 'ptk-zap-visit-v1', requestId }
    } catch (_) { return failure('visit_prestart_failed') }
}

// Only app.js may call this after its extension-runner sender check. The
// requested tab is deliberately absent: automation derives it from its live
// exact-session ownership table.
export async function handleZapRunnerVisitRequest(automation, message = {}) {
    const requestId = ID.test(message?.requestId || '') ? message.requestId : null
    const failure = reason => ({ ok: false, reason, trustedRunner: 'ptk-zap-visit-v1',
        requestId })
    if (!requestId || !ID.test(message.sessionId || '') || !ID.test(message.zapid || '')
        || !ID.test(message.browserid || '')
        || !['advance', 'departure', 'clear', 'rebind'].includes(message.phase)
        || (message.phase === 'advance' && (!Number.isSafeInteger(message.observationMs)
            || message.observationMs < 1 || message.observationMs > 300000))) {
        return failure('visit_request_invalid')
    }
    if (typeof automation?.getZapOwnedVisitCheckpoint !== 'function') {
        return failure('visit_coordinator_unavailable')
    }
    try {
        const result = await automation.getZapOwnedVisitCheckpoint({
            sessionId: message.sessionId, zapid: message.zapid,
            browserid: message.browserid, phase: message.phase,
            observationMs: message.phase === 'advance' ? message.observationMs : undefined
        })
        if (!result || typeof result.ok !== 'boolean') return failure('visit_response_invalid')
        return { ...result, trustedRunner: 'ptk-zap-visit-v1', requestId }
    } catch (_) {
        return failure('visit_checkpoint_failed')
    }
}

// One extension-background observation loop avoids repeatedly opening and
// closing WebDriver runner tabs. Timeout and unavailable evidence are never
// converted into a successful visit or STOP decision.
export async function handleZapRunnerVisitObservation(automation, message = {}, {
    now = () => performance.now(),
    sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
} = {}) {
    const requestId = ID.test(message?.requestId || '') ? message.requestId : null
    const failure = reason => ({ ok: false, reason, trustedRunner: 'ptk-zap-visit-v1', requestId })
    if (!requestId || !ID.test(message.sessionId || '') || !ID.test(message.zapid || '')
        || !ID.test(message.browserid || '')
        || !Number.isSafeInteger(message.observationMs) || message.observationMs < 1
        || message.observationMs > 300000
        || (message.depart !== undefined && typeof message.depart !== 'boolean')
        || !Number.isSafeInteger(message.maxWaitMs)
        || message.maxWaitMs < message.observationMs || message.maxWaitMs > 300000) {
        return failure('visit_request_invalid')
    }
    const startedAt = now()
    if (!Number.isFinite(startedAt)) return failure('visit_clock_unavailable')
    let rebinds = 0
    const retryable = new Set(['visit_observation_started', 'visit_observation_pending',
        'visit_sast_incomplete', 'visit_iast_incomplete', 'visit_publication_pending',
        'visit_root_unavailable', 'visit_document_unbound', 'visit_cut_changed',
        'visit_owner_unavailable', 'visit_scan_unavailable'])
    while (true) {
        const elapsed = now() - startedAt
        if (!Number.isFinite(elapsed) || elapsed < 0) return failure('visit_clock_unavailable')
        if (elapsed >= message.maxWaitMs) return failure('visit_observation_timeout')
        const result = await handleZapRunnerVisitRequest(automation, {
            ...message, phase: 'advance'
        })
        if (now() - startedAt >= message.maxWaitMs) return failure('visit_observation_timeout')
        if (result.ok === true) {
            if (result.kind !== 'observed_interval' || !result.cut) {
                return failure('visit_response_invalid')
            }
            if (message.depart !== true) return result
            // Keep the final departure proof in the same extension-owned
            // request as the stable observation. A second WebDriver runner
            // tab round trip can itself let page observations advance.
            const departure = await handleZapRunnerVisitRequest(automation, {
                ...message, phase: 'departure'
            })
            if (now() - startedAt >= message.maxWaitMs) return failure('visit_observation_timeout')
            if (departure.ok === true) {
                if (departure.kind !== 'departure_cut' || !departure.cut) {
                    return failure('visit_response_invalid')
                }
                if (now() - startedAt > message.maxWaitMs) {
                    return failure('visit_observation_timeout')
                }
                return { ...departure, kind: 'observed_departure_cut',
                    elapsedMs: result.elapsedMs }
            }
            if (departure.reason !== 'visit_cut_changed') {
                return failure(departure.reason || 'visit_departure_unverified')
            }
            // The cut moved before departure. Reobserve it within the same
            // original deadline; never treat the prior interval as complete.
        }
        else if (result.reason === 'visit_stream_rebind_unverified' && rebinds < 4) {
            rebinds += 1
            const rebound = await handleZapRunnerVisitRequest(automation, {
                ...message, phase: 'rebind'
            })
            if (now() - startedAt >= message.maxWaitMs) return failure('visit_observation_timeout')
            if (rebound.ok !== true || rebound.kind !== 'stream_rebound') {
                return failure(rebound.reason || 'visit_rebind_unavailable')
            }
        } else if (!retryable.has(result.reason)) {
            return failure(result.reason || 'visit_cut_unavailable')
        }
        const remaining = message.maxWaitMs - (now() - startedAt)
        if (!Number.isFinite(remaining) || remaining <= 0) {
            return failure('visit_observation_timeout')
        }
        await sleep(Math.min(100, remaining))
    }
}
