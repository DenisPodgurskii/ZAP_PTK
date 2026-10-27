// Volatile capture staging only. This is not an engine evidence/history store.
export const CAPTURE_LIMITS = Object.freeze({ resourceBytes: 8 * 1024 * 1024, tabBytes: 32 * 1024 * 1024, totalBytes: 64 * 1024 * 1024 })

export function captureIdentity(record) {
    return JSON.stringify([record.epoch, record.tabId, record.sessionId || '', record.scriptId ? 'script' : 'network', record.scriptId || record.requestId, record.hop || 0])
}

export function freezeCapture(value) {
    if (!value || typeof value !== 'object') return value
    const copy = Array.isArray(value) ? value.map(freezeCapture) : Object.fromEntries(Object.entries(value).map(([key, item]) => [key, freezeCapture(item)]))
    return Object.freeze(copy)
}

// Charge UTF-16 representation (including base64), keys and identity/ref metadata.
// No unbounded queue or strings may be hidden outside this account.
function bytes(value) {
    if (typeof value === 'string') return value.length * 2
    if (value === null || value === undefined) return 8
    if (typeof value !== 'object') return 8
    return 32 + Object.entries(value).reduce((sum, [key, item]) => sum + key.length * 2 + bytes(item), 0)
}

export class CaptureStore {
    constructor(limits = {}) {
        this.limits = { ...CAPTURE_LIMITS, ...limits }
        this.records = new Map()
        this.staging = new Map()
        this.tabBytes = new Map()
        this.totalBytes = 0
    }

    reserve(record, consumers) {
        const key = captureIdentity(record)
        const existing = this.records.get(key)
        if (existing) return this._replace(key, existing.record, [...new Set([...existing.refs, ...consumers])], existing.complete)
        return this._replace(key, record, consumers, false)
    }

    complete(record, consumers) {
        const key = captureIdentity(record)
        const existing = this.records.get(key)
        if (existing?.complete) return { ok: true, key, record: existing.record }
        const refs = existing ? [...existing.refs].filter(id => consumers.includes(id)) : consumers
        const result = this._replace(key, record, refs, true)
        // A refused completion must not strand the old pending reservation.
        if (!result.ok) this.remove(key)
        return result
    }

    // Admission-only projection. In particular this never reserves a new ref,
    // freezes a record, or removes a pending reservation on refusal.
    canComplete(record, consumers) {
        const key = captureIdentity(record), existing = this.records.get(key)
        if (existing?.complete) return { ok: true, key }
        const refs = existing ? [...existing.refs].filter(id => consumers.includes(id)) : consumers
        const result = this._project(key, record, refs)
        return result.ok ? { ok: true, key } : { ok: false, reason: result.reason }
    }

    _project(key, record, consumers) {
        const refs = new Set(consumers)
        if (!refs.size) return { ok: false, reason: 'owner_unavailable' }
        const previous = this.records.get(key)
        const size = bytes(record) + key.length * 2 + [...refs].reduce((n, id) => n + id.length * 2 + 32, 64)
        const oldSize = previous?.size || 0
        const tabSize = (this.tabBytes.get(record.tabId) || 0) - oldSize + size
        let reason
        if (size > this.limits.resourceBytes) reason = 'resource_budget'
        else if (tabSize > this.limits.tabBytes) reason = 'tab_budget'
        else if (this.totalBytes - oldSize + size > this.limits.totalBytes) reason = 'global_budget'
        if (reason) return { ok: false, reason }
        return { ok: true, refs, size, oldSize, tabSize }
    }

    _replace(key, record, consumers, complete) {
        const projected = this._project(key, record, consumers)
        if (!projected.ok) return projected
        const { refs, size, oldSize, tabSize } = projected
        const previous = this.records.get(key)
        const immutable = previous?.record === record ? record : freezeCapture(record)
        this.records.set(key, { record: immutable, refs, complete, size })
        this.totalBytes += size - oldSize
        this.tabBytes.set(record.tabId, tabSize)
        return { ok: true, key, record: immutable }
    }

    get(key, consumer) {
        const entry = this.records.get(key)
        return entry?.complete && entry.refs.has(consumer) ? entry.record : undefined
    }

    find(consumer, query) {
        // Deliberately refuse URL-only lookup, including an unknown document.
        if (!query.documentId && !query.loaderId) return []
        return [...this.records.values()].filter(entry => entry.complete && entry.refs.has(consumer)
            && Object.entries(query).every(([key, value]) => value === undefined || entry.record[key] === value)).map(entry => entry.record)
    }

    consume(key, consumer) {
        const entry = this.records.get(key)
        if (!entry) return
        entry.refs.delete(consumer)
        if (!entry.refs.size) this.remove(key)
    }

    release(consumer, predicate = () => true) {
        for (const [key, entry] of this.records) if (predicate(entry.record)) this.consume(key, consumer)
    }

    remove(key) {
        const entry = this.records.get(key)
        if (!entry) return
        this.records.delete(key)
        this.totalBytes -= entry.size
        const remaining = (this.tabBytes.get(entry.record.tabId) || 0) - entry.size
        if (remaining) this.tabBytes.set(entry.record.tabId, remaining)
        else this.tabBytes.delete(entry.record.tabId)
    }

    // Adapter-held chunks/identity metadata use the same tab/global account as
    // immutable records. There is no separately unbounded pre-completion pool.
    stage(record, kind, additionalBytes) {
        if (!['chunks', 'metadata'].includes(kind)) return { ok: false, reason: 'invalid_budget_kind' }
        if (!Number.isSafeInteger(additionalBytes) || additionalBytes < 0) return { ok: false, reason: 'invalid_budget_charge' }
        const key = `${captureIdentity(record)}:${kind}`
        const previous = this.staging.get(key)
        const metadata = previous ? 0 : bytes({ epoch: record.epoch, tabId: record.tabId, sessionId: record.sessionId, requestId: record.requestId, hop: record.hop, frameId: record.frameId, documentId: record.documentId, loaderId: record.loaderId }) + key.length * 2
        const delta = additionalBytes + metadata
        const size = (previous?.size || 0) + delta
        if (size > this.limits.resourceBytes) return { ok: false, reason: 'resource_budget' }
        if ((this.tabBytes.get(record.tabId) || 0) + delta > this.limits.tabBytes) return { ok: false, reason: 'tab_budget' }
        if (this.totalBytes + delta > this.limits.totalBytes) return { ok: false, reason: 'global_budget' }
        this.staging.set(key, { record: previous?.record || freezeCapture({ epoch: record.epoch, tabId: record.tabId, sessionId: record.sessionId, requestId: record.requestId, hop: record.hop, frameId: record.frameId, documentId: record.documentId, loaderId: record.loaderId }), size })
        this.totalBytes += delta
        this.tabBytes.set(record.tabId, (this.tabBytes.get(record.tabId) || 0) + delta)
        return { ok: true }
    }

    unstage(record, kind) {
        const key = `${captureIdentity(record)}:${kind}`
        const entry = this.staging.get(key)
        if (!entry) return
        this.staging.delete(key)
        this.totalBytes -= entry.size
        const remaining = (this.tabBytes.get(entry.record.tabId) || 0) - entry.size
        if (remaining) this.tabBytes.set(entry.record.tabId, remaining)
        else this.tabBytes.delete(entry.record.tabId)
    }

    clearStaging(predicate) {
        for (const [key, entry] of this.staging) {
            const kind = key.slice(key.lastIndexOf(':') + 1)
            if (predicate(entry.record, kind)) this.unstage(entry.record, kind)
        }
    }

    rebindDocument(predicate, documentId) {
        const reasons = new Set()
        for (const [key, entry] of this.records) if (predicate(entry.record)) {
            const result = this._replace(key, { ...entry.record, documentId }, [...entry.refs], entry.complete)
            if (!result.ok) { reasons.add(result.reason); this.remove(key) }
        }
        for (const [key, entry] of this.staging) if (predicate(entry.record)) {
            const record = { ...entry.record, documentId }, delta = bytes(record) - bytes(entry.record)
            let reason
            if (entry.size + delta > this.limits.resourceBytes) reason = 'resource_budget'
            else if ((this.tabBytes.get(record.tabId) || 0) + delta > this.limits.tabBytes) reason = 'tab_budget'
            else if (this.totalBytes + delta > this.limits.totalBytes) reason = 'global_budget'
            // Failed aliasing does not free adapter-held buffers. Preserve their
            // existing charge until the adapter actually drops them/releasehooks.
            if (reason) { reasons.add(reason); continue }
            entry.record = freezeCapture(record)
            entry.size += delta
            this.totalBytes += delta
            this.tabBytes.set(record.tabId, (this.tabBytes.get(record.tabId) || 0) + delta)
        }
        return { ok: !reasons.size, reasons: [...reasons] }
    }

    snapshot() {
        return { records: this.records.size, pending: [...this.records.values()].filter(entry => !entry.complete).length, staging: this.staging.size, totalBytes: this.totalBytes, tabBytes: Object.fromEntries(this.tabBytes) }
    }
}

export default CaptureStore
