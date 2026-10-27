const RESOURCE_BYTES = 8 * 1024 * 1024
const TAB_BYTES = 32 * 1024 * 1024
const TOTAL_BYTES = 64 * 1024 * 1024
const METADATA_BYTES = 64 * 1024
function metadataSize(value, limit = METADATA_BYTES) {
    if (typeof value === 'string') return value.length * 2
    if (!value || typeof value !== 'object') return 8
    if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return value.byteLength
    let bytes = 32
    for (const key in value) { bytes += key.length * 2 + metadataSize(value[key], limit - bytes); if (bytes > limit) break }
    return bytes
}
function base64(chunks) {
    let binary = ''
    for (const bytes of chunks) for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192))
    return btoa(binary)
}
function isDocument(type) { return type === 'main_frame' || type === 'sub_frame' }

// Private transport representation only: immutable byte arrays survive shared
// JSON-like capture freezing. Recorder restores its own native ArrayBuffers.
function rawRequestExtraBytes(body) {
    let extra = 0, found = false
    for (const part of Array.isArray(body?.raw) ? body.raw : []) {
        const value = part?.bytes
        if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) continue
        found = true
        const length = value.byteLength
        // Account numeric values and the longest possible decimal array key
        // before allocating; this conservatively bounds metadataSize's result.
        extra += 32 + length * (8 + 2 * String(Math.max(0, length - 1)).length) - length
    }
    return found ? extra : null
}
function immutableRawRequestBody(body) {
    return Object.freeze({ ...body, raw: Object.freeze(body.raw.map(part => {
        const value = part?.bytes
        if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) return Object.freeze({ ...part })
        const bytes = value instanceof ArrayBuffer ? new Uint8Array(value)
            : new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
        return Object.freeze({ ...part, bytes: Object.freeze(Array.from(bytes)) })
    })) })
}

export class FirefoxCaptureAdapter {
    constructor({ browser = globalThis.browser, maxResourceBytes = RESOURCE_BYTES, maxTabBytes = TAB_BYTES, maxTotalBytes = TOTAL_BYTES } = {}) {
        this.browser = browser
        this.maxResourceBytes = maxResourceBytes
        this.maxTabBytes = maxTabBytes
        this.maxTotalBytes = maxTotalBytes
        this.totalBytes = 0
        this.supportsRetiredSources = true
        this.tabs = new Map()
        this.requests = new Map()
        this.sink = () => {}
        this.admit = () => false
        this.budget = { retain: () => ({ ok: true }), release: () => {} }
        const urls = { urls: ['<all_urls>'] }
        browser.webRequest.onBeforeRequest.addListener(details => this._before(details), urls, ['blocking', 'requestBody'])
        browser.webRequest.onSendHeaders?.addListener(details => this._requestHeaders(details), urls, ['requestHeaders'])
        browser.webRequest.onHeadersReceived.addListener(details => this._headers(details), urls, ['responseHeaders'])
        browser.webRequest.onBeforeRedirect.addListener(details => this._redirect(details), urls)
        browser.webRequest.onCompleted.addListener(details => this._completed(details), urls)
        browser.webRequest.onErrorOccurred.addListener(details => this._error(details), urls)
        browser.webNavigation?.onCommitted.addListener(details => this._committed(details))
        browser.webNavigation?.onErrorOccurred.addListener(details => this._navigationError(details))
    }
    setEventSink(fn) { this.sink = fn }
    setAdmission(fn) { this.admit = fn }
    setBudgetHooks(hooks) { this.budget = hooks }
    _emit(type, record, extra = {}) { this.sink({ type, record: { ...record }, ...extra }) }
    async configure(tabId, capabilities) {
        if (!this.browser.webNavigation?.onCommitted) throw new Error('capture_navigation_identity_unavailable')
        const existing = this.tabs.get(tabId)
        const state = existing || { tabId, bytes: 0, frames: new Map(), candidates: new Map(), serial: 0, capabilities: new Set() }
        state.capabilities = new Set(capabilities)
        this.tabs.set(tabId, state)
        if (existing || !this.browser.webNavigation.getAllFrames) return
        // Native snapshot permits live DOM collection on an already loaded
        // document. It never recovers pre-epoch bodies or binds by URL. A
        // concurrent navigation wins over this asynchronous initial snapshot.
        const serial = state.serial
        const frames = await this.browser.webNavigation.getAllFrames({ tabId })
        if (this.tabs.get(tabId) !== state || state.serial !== serial) return
        for (const frame of frames || []) {
            if (frame.errorOccurred || frame.frameLifecycle && frame.frameLifecycle !== 'active'
                || typeof frame.documentId !== 'string' || !frame.documentId || !Number.isInteger(frame.frameId)
                || metadataSize(frame) > METADATA_BYTES || state.frames.has(frame.frameId)) continue
            const record = { tabId, frameId: frame.frameId, parentFrameId: frame.parentFrameId,
                parentDocumentId: frame.parentDocumentId, documentId: frame.documentId,
                nativeDocument: true, preexisting: true, documentUrl: frame.url, url: frame.url,
                navigationGeneration: ++state.serial }
            if (this._frame(state, record)) this._emit('protocol', record, { method: 'Page.frameNavigated' })
        }
    }
    send() { return Promise.reject(new Error('capture_command_unsupported')) }
    setSastState(tabId, config) {
        const state = this.tabs.get(tabId)
        if (!state) return Promise.resolve(false)
        if (state.sastPush?.active && config.active && state.sastPush.ownerId !== config.ownerId) throw new Error('capture_sast_owner_conflict')
        state.sastPush = config
        // A deferred document-navigation error must not make Stop wait for a
        // native request terminal that may never arrive. Existing deactivation
        // is the cancellation boundary; ordinary active drainage still waits.
        if (!config.active) for (const entry of this.requests.values()) {
            if (entry.state === state && (entry.navigationErrorDeferred || entry.replacementDeferred)) this._settle(entry, 'navigation_failed', true)
        }
        return this.refreshSastState(tabId)
    }
    async refreshSastState(tabId) {
        const state = this.tabs.get(tabId), config = state?.sastPush
        if (!config) return false
        for (const frame of state.frames.values()) {
            if (this.tabs.get(tabId) !== state || state.sastPush !== config) return false
            const identity = config.getIdentity(frame.record)
            const active = config.active && config.isActive() && !!identity
            try {
                // State lifecycle only: the content producer decides when to
                // collect. No snapshot request/permission or analysis ACK.
                const notification = this.browser.tabs.sendMessage(tabId, { channel: 'ptk_background2content_sast', type: 'sast_state',
                    state: { active, revision: config.revision, transport: 'runtime' } },
                { frameId: frame.record.frameId, documentId: frame.record.documentId })
                notification?.catch?.(() => {})
            } catch (_) { /* A newly admitted document discovers state after its listener installs. */ }
        }
        return true
    }
    acceptSastPayload(identity, sender, payload) {
        const state = this.tabs.get(identity.tabId), frame = state?.frames.get(identity.frameId)?.record
        // sender is supplied only by runtime.onMessage, never by payload fields.
        if (!state?.capabilities.has('sources') || !this.browser.runtime?.id || sender?.id !== this.browser.runtime.id || sender?.tab?.id !== identity.tabId || sender?.frameId !== identity.frameId || typeof sender?.documentId !== 'string' || sender.documentId !== identity.documentId || frame?.documentId !== identity.documentId || frame?.navigationGeneration !== identity.navigationGeneration || !this.admit({ ...frame, tabId: identity.tabId }, 'domSources') || !payload || metadataSize(payload, this.maxResourceBytes) > this.maxResourceBytes) throw new Error('capture_collection_unavailable')
        return payload
    }
    getSnapshot(tabId) {
        const state = this.tabs.get(tabId)
        return { frames: state ? [...state.frames.values()].map(frame => ({ ...frame.record })) : [], contexts: [], capabilities: [...(state?.capabilities || [])] }
    }
    _retain(entry, kind, additionalBytes) {
        if (entry.state.bytes + additionalBytes > this.maxTabBytes || this.totalBytes + additionalBytes > this.maxTotalBytes) return false
        const result = this.budget.retain(entry.record, kind, additionalBytes)
        if (!result.ok) return false
        entry.state.bytes += additionalBytes
        this.totalBytes += additionalBytes
        entry[kind === 'chunks' ? 'bytes' : 'metadataBytes'] += additionalBytes
        return true
    }
    _releaseCharge(entry, kind) {
        const key = kind === 'chunks' ? 'bytes' : 'metadataBytes'
        if (!entry[key]) return
        entry.state.bytes -= entry[key]
        this.totalBytes -= entry[key]
        entry[key] = 0
        this.budget.release(entry.record, kind)
    }
    _selected(state, record) {
        let accepted = false
        for (const cap of ['sources', 'authBodies', 'recording']) if (state.capabilities.has(cap) && this.admit(record, cap)) accepted = true
        return accepted
    }
    canRetainSource(record) {
        const entry = this.requests.get(record.requestId)
        return !!(entry && ['tabId', 'requestId', 'hop', 'frameId', 'parentFrameId', 'parentDocumentId', 'documentId', 'sessionId', 'sessionGeneration', 'navigationGeneration', 'url', 'documentUrl', 'method', 'resourceType']
            .every(key => entry.record[key] === record[key]) && !entry.settled && entry.document && entry.bound
            // A bound original may still be streaming when its successor
            // starts. The exact retired-source grant keeps its reservation;
            // _settle still requires a closed filter, headers and native success.
            && entry.filter && entry.done && (!entry.stopped || entry.filterClosed)
            && this.tabs.get(record.tabId) === entry.state
            && entry.state.frames.get(record.frameId)?.record.documentId === record.documentId
            && this.admit(record, 'sources'))
    }
    _frame(state, record) {
        const prior = state.frames.get(record.frameId)
        if (prior) this._releaseCharge(prior, 'metadata')
        const frame = { state, record: { tabId: state.tabId, frameId: record.frameId, parentFrameId: record.parentFrameId, parentDocumentId: record.parentDocumentId, documentId: record.documentId, documentUrl: record.documentUrl, url: record.url, nativeDocument: record.nativeDocument === true, preexisting: record.preexisting === true, previousNativeId: record.previousNativeId, committedTimeStamp: record.committedTimeStamp, navigationGeneration: record.navigationGeneration, requestId: `frame:${record.frameId}`, hop: 0 }, metadataBytes: 0 }
        // Includes bounded candidate-set/scalar bookkeeping for this frame.
        if (!this._retain(frame, 'metadata', metadataSize(frame.record) + 256)) {
            state.frames.delete(record.frameId)
            this._emit('gap', { tabId: state.tabId, reason: 'identity_budget_exceeded', complete: false })
            return false
        }
        state.frames.set(record.frameId, frame)
        return true
    }
    _removeDescendants(state, frameId) {
        for (const [id, frame] of state.frames) if (frame.record.parentFrameId === frameId) {
            this._removeDescendants(state, id)
            for (const entry of this.requests.values()) if (entry.state === state && entry.record.frameId === id) { this._settle(entry, 'document_replaced', true); this._remove(entry.record.requestId, entry, true) }
            this._releaseCharge(frame, 'metadata')
            state.frames.delete(id); state.candidates.delete(id)
            this._emit('protocol', { tabId: state.tabId, frameId: id }, { method: 'Page.frameDetached', params: { frameId: id } })
        }
    }
    _continuation(entry, details, state) {
        const record = entry?.record, redirect = entry?.redirect
        return !!(entry?.tombstone && entry.state === state && redirect
            && record.tabId === details.tabId && record.frameId === details.frameId
            && record.resourceType === details.type && record.parentFrameId === details.parentFrameId
            && (record.parentDocumentId || null) === (details.parentDocumentId || null)
            && state.frames.get(record.frameId)?.record.navigationGeneration === record.navigationGeneration
            && redirect.url === details.url && Number.isFinite(details.timeStamp)
            && details.timeStamp >= redirect.timeStamp)
    }
    _poison(entry) {
        const candidates = entry.state.candidates.get(entry.record.frameId)
        if (!candidates?.has(entry)) return
        candidates.delete(entry)
        if (![...candidates].some(candidate => !candidate.record)) candidates.add({ settled: true })
        this._remove(entry.record.requestId, entry, true)
    }
    _tombstone(entry) {
        const { tabId, requestId, hop, frameId, parentFrameId, parentDocumentId, documentId, url, resourceType, navigationGeneration, timeStamp } = entry.record
        const tombstone = { state: entry.state, record: { tabId, requestId, hop, frameId, parentFrameId, parentDocumentId, documentId, url, resourceType, navigationGeneration, timeStamp }, document: true, bound: false, settled: true, tombstone: true, bytes: 0, metadataBytes: 0 }
        const candidates = entry.state.candidates.get(frameId)
        candidates.delete(entry)
        this._remove(requestId, entry, true)
        if (this._retain(tombstone, 'metadata', metadataSize(tombstone.record))) {
            candidates.add(tombstone)
            this.requests.set(requestId, tombstone)
        } else {
            if (![...candidates].some(candidate => !candidate.record)) candidates.add({ settled: true })
            this._emit('gap', { ...tombstone.record, reason: 'identity_budget_exceeded', complete: false })
        }
    }
    _before(details) {
        const state = this.tabs.get(details.tabId)
        if (!state) return
        if (metadataSize(details) > METADATA_BYTES) { this._emit('gap', { tabId: details.tabId, requestId: String(details.requestId || '').slice(0, 2048), complete: false, reason: 'metadata_budget_exceeded' }); return }
        const rawExtra = rawRequestExtraBytes(details.requestBody)
        if (rawExtra !== null && metadataSize(details) + rawExtra > Math.min(METADATA_BYTES, this.maxResourceBytes,
            this.maxTabBytes - state.bytes, this.maxTotalBytes - this.totalBytes)) {
            this._emit('gap', { tabId: details.tabId, requestId: String(details.requestId || '').slice(0, 2048), complete: false, reason: 'metadata_budget_exceeded' })
            return
        }
        let prior = this.requests.get(details.requestId)
        if (prior && prior.state !== state) { this._emit('gap', { tabId: details.tabId, requestId: details.requestId, reason: 'document_identity_unavailable', complete: false }); return }
        const frame = state.frames.get(details.frameId)?.record
        const document = isDocument(details.type)
        const hop = prior ? prior.record.hop + 1 : 0
        let conflictingPredecessor = false
        if (document && prior && !this._continuation(prior, details, state)) {
            conflictingPredecessor = true
            if (prior.tombstone) this._poison(prior)
            else { this._settle(prior, 'document_replaced', true); this._remove(details.requestId, prior, true) }
            prior = undefined
        }
        const record = { tabId: details.tabId, requestId: details.requestId, hop, frameId: details.frameId, parentFrameId: details.parentFrameId, parentDocumentId: details.parentDocumentId, documentId: document ? `firefox:${details.requestId}:${hop}` : details.documentId, nativeDocument: !document, documentUrl: document ? details.url : details.documentUrl || frame?.url, url: details.url, method: details.method, resourceType: details.type, timeStamp: details.timeStamp, request: { requestBody: rawExtra === null ? details.requestBody : immutableRawRequestBody(details.requestBody) } }
        // Native navigation requests intentionally have no documentId. Their
        // request namespace is provisional, never a substitute native UUID.
        if (document) {
            const parent = state.frames.get(details.parentFrameId)?.record
            if (details.type === 'sub_frame' && parent && details.parentDocumentId && parent.documentId !== details.parentDocumentId) { this._emit('gap', { ...record, reason: 'parent_document_replaced', complete: false }); return }
            record.navigationGeneration = ++state.serial
            this._removeDescendants(state, record.frameId)
            for (const existing of this.requests.values()) if (existing.record.frameId === record.frameId && existing.record.tabId === record.tabId) {
                if (existing !== prior && (this.canRetainSource(existing.record)
                    || existing.replacementDeferred && this.admit(existing.record, 'retiredSources'))) {
                    existing.replacementDeferred = true
                    continue
                }
                if (existing === prior) state.candidates.get(record.frameId)?.delete(existing)
                else if (existing.tombstone) this._poison(existing)
                this._settle(existing, existing === prior ? 'redirect_body_unavailable' : 'document_replaced', true)
                this._remove(existing.record.requestId, existing, true)
            }
            this._emit('request', record)
            // Retirement synchronously pins the exact source grant before the
            // manager replaces its frame. Never retain without that witness.
            for (const existing of this.requests.values()) if (existing.state === state && existing.replacementDeferred
                && !this.admit(existing.record, 'retiredSources')) {
                this._settle(existing, 'document_replaced', true); this._remove(existing.record.requestId, existing, true)
            }
            if (!this.admit(record, 'metadata')) return
            if (!this._frame(state, { ...record, url: details.url, previousNativeId: frame?.previousNativeId || (frame?.documentId?.startsWith('firefox:') ? undefined : frame?.documentId) })) return
        } else if (!record.documentId || !frame || record.documentId !== frame.documentId || (details.parentDocumentId && state.frames.get(details.parentFrameId)?.record.documentId !== details.parentDocumentId)) {
            this._emit('gap', { ...record, reason: 'document_identity_unavailable', complete: false })
            return
        }
        if (!document) {
            // Preserve the already-validated native frame's admission identity;
            // never borrow a newer navigation generation at body completion.
            record.navigationGeneration = frame.navigationGeneration
            this._emit('request', record); if (!this.admit(record, 'metadata')) return
        }
        if (prior) { this._settle(prior, 'redirect_body_unavailable', true); this._remove(details.requestId, prior, true) }
        const entry = { state, record, chunks: [], bytes: 0, metadataBytes: 0, settled: false, document, bound: !document, continuation: !!prior?.tombstone, filterClosed: false, navigationErrorDeferred: false }
        if (!this._retain(entry, 'metadata', metadataSize(record) + metadataSize({ filterClosed: false, navigationErrorDeferred: false, replacementDeferred: false }))) { this._emit('gap', { ...record, complete: false, reason: 'metadata_budget_exceeded' }); return }
        this.requests.set(details.requestId, entry)
        if (document) {
            const candidates = state.candidates.get(record.frameId) || new Set()
            if (prior) candidates.delete(prior)
            if (conflictingPredecessor && ![...candidates].some(candidate => !candidate.record)) candidates.add({ settled: true })
            candidates.add(entry)
            state.candidates.set(record.frameId, candidates)
        }
        if (!this._selected(state, record)) return
        try {
            entry.filter = this.browser.webRequest.filterResponseData(details.requestId)
            entry.done = new Promise(resolve => { entry.resolve = resolve })
            entry.filter.ondata = event => {
                // Application delivery comes first, always with the original bytes.
                try { entry.filter.write(event.data) } catch { this._settle(entry, 'stream_write_error', true); return }
                if (entry.settled) return
                const bytes = new Uint8Array(event.data)
                // Chunks + eventual UTF16/base64 representation + chunk identity.
                const charge = bytes.byteLength * 4 + 32
                if (entry.bytes + charge > this.maxResourceBytes || !this._retain(entry, 'chunks', charge)) { this._settle(entry, 'resource_budget_exceeded', true); return }
                entry.chunks.push(bytes.slice())
            }
            entry.filter.onstop = () => {
                entry.stopped = true
                try { entry.filter.close() } catch { this._settle(entry, 'stream_close_error'); return }
                entry.filterClosed = true
                if (entry.completed && !entry.headersReady) this._settle(entry, 'response_headers_unavailable')
                else this._settle(entry)
            }
            entry.filter.onerror = () => this._settle(entry, 'stream_error', true)
        } catch { this._settle(entry, 'response_filter_unavailable', true) }
    }
    _committed(details) {
        const state = this.tabs.get(details.tabId)
        if (!state) return
        if (!details.documentId || metadataSize(details) > METADATA_BYTES) { this._emit('gap', { tabId: details.tabId, reason: 'document_identity_unavailable', complete: false }); return }
        const current = state.frames.get(details.frameId)?.record
        if (Number.isFinite(current?.committedTimeStamp) && Number.isFinite(details.timeStamp) && details.timeStamp < current.committedTimeStamp) return
        const candidates = [...(state.candidates.get(details.frameId) || [])]
        const entry = candidates.length === 1 ? candidates[0] : null
        // Correlation requires unique native request/frame lineage. URL is only
        // an additional consistency check, never the source of identity.
        const bound = entry && !entry.settled && entry.record.url === details.url
            && state.frames.get(details.frameId)?.record.previousNativeId !== details.documentId
            && (!entry.record.parentDocumentId || entry.record.parentDocumentId === details.parentDocumentId)
            && (!Number.isFinite(entry.record.timeStamp) || !Number.isFinite(details.timeStamp) || details.timeStamp >= entry.record.timeStamp)
        const previousDocumentId = bound ? entry.record.documentId : undefined
        const generation = ++state.serial
        const record = { tabId: details.tabId, frameId: details.frameId, parentFrameId: details.parentFrameId, parentDocumentId: details.parentDocumentId, documentId: details.documentId, nativeDocument: true, documentUrl: details.url, url: details.url, previousDocumentId, committedTimeStamp: details.timeStamp, navigationGeneration: bound ? entry.record.navigationGeneration : generation, resourceType: details.frameId === 0 ? 'main_frame' : 'sub_frame' }
        // Manager rekeys only exact previous identity. A conflicting/overlapping
        // navigation is invalidated rather than guessed onto the current UUID.
        if (!this._frame(state, record)) return
        this._emit('protocol', record, { method: 'Page.frameNavigated' })
        state.candidates.delete(details.frameId)
        if (bound) {
            const nextRecord = { ...entry.record, documentId: details.documentId, documentUrl: details.url }
            const delta = metadataSize(nextRecord) - metadataSize(entry.record)
            entry.record = nextRecord
            if (delta > 0 && !this._retain(entry, 'metadata', delta)) { this._settle(entry, 'metadata_budget_exceeded', true); return }
            entry.bound = true
            if (entry.stopped) this._settle(entry)
        } else {
            if (candidates.length) this._emit('gap', { ...record, reason: 'navigation_identity_ambiguous', complete: false })
            for (const candidate of candidates) if (candidate.record) this._settle(candidate, 'navigation_identity_ambiguous', true)
        }
        for (const candidate of candidates) if (candidate.record && candidate.settled) this._remove(candidate.record.requestId, candidate, true)
    }
    _navigationError(details) {
        const state = this.tabs.get(details.tabId)
        if (!state) return
        const current = state.frames.get(details.frameId)?.record
        // webNavigation errors name a native document, not a webRequest ID.
        // A replaced document's error may arrive after the next provisional
        // request, even with the same URL. Only webRequest.onErrorOccurred can
        // cancel that unbound request; never adopt an error UUID onto it.
        if (!details.documentId || current?.documentId !== details.documentId
            || (Number.isFinite(current.committedTimeStamp) && Number.isFinite(details.timeStamp) && details.timeStamp < current.committedTimeStamp)) return
        for (const entry of this.requests.values()) if (entry.state === state && entry.document && entry.bound
            && entry.record.frameId === details.frameId && entry.record.documentId === details.documentId) {
            // Navigation can fail after the original stream closed but before
            // its native headers/completion callbacks. Preserve only this
            // already-delivered, exact active SAST original; never a prefix.
            const sast = state.sastPush
            if (!entry.settled && entry.stopped && entry.filterClosed && !entry.completed
                && entry.record.navigationGeneration === current.navigationGeneration
                && state.capabilities.has('sources') && sast?.active && sast.isActive()
                && sast.getIdentity(entry.record) && this.admit(entry.record, 'sources')) {
                entry.navigationErrorDeferred = true
                continue
            }
            this._settle(entry, 'navigation_failed', true)
        }
    }
    _nativeEntry(details) {
        const entry = this.requests.get(details.requestId)
        if (entry && (['tabId', 'frameId', 'parentFrameId'].some(key => details[key] !== undefined && details[key] !== entry.record[key])
            || (details.url !== undefined && details.url !== entry.record.url)
            || (details.type !== undefined && details.type !== entry.record.resourceType))) return
        if (!entry?.continuation) return entry
        const record = entry.record
        // Native callbacks have no hop field. Reject contradictory lineage and
        // older events; indistinguishable terminal/metadata events fail closed.
        if (['tabId', 'frameId', 'parentFrameId'].some(key => details[key] !== undefined && details[key] !== record[key])
            || (details.type !== undefined && details.type !== record.resourceType)
            || (details.url !== undefined && details.url !== record.url)
            || (details.parentDocumentId !== undefined && (details.parentDocumentId || null) !== (record.parentDocumentId || null))
            || (Number.isFinite(details.timeStamp) && details.timeStamp < record.timeStamp)) return
        if (!Number.isFinite(details.timeStamp) || details.timeStamp === record.timeStamp) {
            this._settle(entry, 'navigation_identity_ambiguous', true)
            return
        }
        return entry
    }
    _requestHeaders(details) {
        const entry = this._nativeEntry(details)
        if (!entry || entry.settled || entry.tombstone) return
        if (metadataSize(details) > METADATA_BYTES || !this._retain(entry, 'metadata', metadataSize(details.requestHeaders))) {
            this._settle(entry, 'metadata_budget_exceeded', true); this._remove(details.requestId, entry); return
        }
        entry.record.requestHeaders = details.requestHeaders
        this._emit('requestHeaders', entry.record)
    }
    _headers(details) {
        const entry = this._nativeEntry(details)
        if (!entry || entry.settled) return
        if (metadataSize(details) > METADATA_BYTES) { this._settle(entry, 'metadata_budget_exceeded', true); this._remove(details.requestId, entry); return }
        const response = { status: details.statusCode, statusLine: details.statusLine, headers: details.responseHeaders, ip: details.ip }
        if (!this._retain(entry, 'metadata', metadataSize(response) + 32)) { this._settle(entry, 'metadata_budget_exceeded', true); this._remove(details.requestId, entry); return }
        entry.record.response = response
        entry.contentType = details.responseHeaders?.find(header => header.name.toLowerCase() === 'content-type')?.value || ''
        entry.headersReady = true
        this._emit('response', entry.record)
        if (entry.stopped) this._settle(entry)
    }
    _settle(entry, reason, disconnect = false) {
        if (entry.settled) return
        // StreamFilter callbacks may precede webRequest response headers. Close
        // delivery immediately, but publish only after native request success,
        // response metadata and authoritative document binding all agree.
        if (!reason && (!entry.completed || !entry.stopped || !entry.headersReady || (entry.document && !entry.bound))) return
        entry.settled = true
        try { if (disconnect) entry.filter?.disconnect(); else if (!entry.stopped) entry.filter?.close() } catch { reason ||= 'stream_close_error' }
        if (!reason && this.tabs.get(entry.record.tabId) !== entry.state) reason = 'capture_cancelled'
        const current = entry.state.frames.get(entry.record.frameId)?.record
        if (!reason && current?.documentId !== entry.record.documentId
            && !(entry.replacementDeferred && this.admit(entry.record, 'retiredSources'))) reason = 'document_replaced'
        if (!reason && entry.document && !entry.bound) reason = 'document_identity_unavailable'
        let body, text, textual = false
        if (!reason) {
            textual = /^(text\/|application\/(?:javascript|x-javascript|json|xml|xhtml\+xml))/i.test(entry.contentType)
            try {
                if (textual) {
                    const charset = /charset\s*=\s*["']?([^;\s"']+)/i.exec(entry.contentType)?.[1] || 'utf-8'
                    const decoder = new TextDecoder(charset)
                    text = entry.chunks.map(chunk => decoder.decode(chunk, { stream: true })).join('') + decoder.decode()
                    body = text
                } else body = base64(entry.chunks)
            } catch { reason = 'unsupported_charset' }
        }
        entry.chunks = []
        this._releaseCharge(entry, 'chunks')
        if (reason) this._emit('gap', { ...entry.record, complete: false, reason })
        else this._emit('body', { ...entry.record, body, text, base64Encoded: !textual, complete: true })
        entry.resolve?.()
        if (reason && entry.document && !entry.bound && entry.state.candidates.get(entry.record.frameId)?.has(entry)) {
            if (['stream_error', 'response_filter_unavailable', 'redirect_body_unavailable'].includes(reason)) {
                this._tombstone(entry)
                return
            }
            // Retain only one bounded ambiguity marker, not failed POST/header
            // data. The existing frame metadata charge covers this scalar state.
            const candidates = entry.state.candidates.get(entry.record.frameId)
            candidates.delete(entry)
            if (![...candidates].some(candidate => !candidate.record)) candidates.add({ settled: true })
            this._remove(entry.record.requestId, entry, true)
        }
        if (entry.completed) this._remove(entry.record.requestId, entry)
    }
    _redirect(details) {
        let entry = this.requests.get(details.requestId)
        if (entry && !entry.settled && metadataSize(details) <= METADATA_BYTES
            && entry.record.tabId === details.tabId && entry.record.frameId === details.frameId
            && entry.record.url === details.url && typeof details.redirectUrl === 'string') {
            this._emit('redirect', { ...entry.record, redirectUrl: details.redirectUrl })
        }
        if (entry?.filter) this._settle(entry, 'redirect_body_unavailable', true)
        entry = this.requests.get(details.requestId)
        if (!entry?.tombstone) return
        const record = entry.record
        if (metadataSize(details) > METADATA_BYTES || entry.state !== this.tabs.get(details.tabId)
            || record.frameId !== details.frameId || record.resourceType !== details.type
            || record.parentFrameId !== details.parentFrameId
            || (record.parentDocumentId || null) !== (details.parentDocumentId || null)
            || record.url !== details.url || typeof details.redirectUrl !== 'string'
            || !Number.isFinite(record.timeStamp) || !Number.isFinite(details.timeStamp)
            || details.timeStamp < record.timeStamp
            || entry.state.frames.get(record.frameId)?.record.navigationGeneration !== record.navigationGeneration
            || entry.redirect) { this._poison(entry); return }
        const redirect = { url: details.redirectUrl, timeStamp: details.timeStamp }
        if (!this._retain(entry, 'metadata', metadataSize(redirect))) {
            this._emit('gap', { ...record, reason: 'identity_budget_exceeded', complete: false })
            this._poison(entry)
            return
        }
        entry.redirect = redirect
    }
    _completed(details) {
        const entry = this._nativeEntry(details)
        if (!entry) return
        if (entry.tombstone) { this._poison(entry); return }
        if (metadataSize(details) > METADATA_BYTES) { this._settle(entry, 'metadata_budget_exceeded', true); this._remove(details.requestId, entry); return }
        this._emit('complete', { ...entry.record, ip: details.ip })
        entry.completed = true
        if (entry.stopped && !entry.headersReady) this._settle(entry, 'response_headers_unavailable')
        else this._settle(entry)
        if (!entry.filter || entry.settled) this._remove(details.requestId, entry)
    }
    _error(details) {
        const entry = this._nativeEntry(details)
        if (entry?.tombstone) { this._poison(entry); return }
        if (entry) { this._settle(entry, 'request_cancelled', true); this._remove(details.requestId, entry) }
    }
    _remove(id, entry, force = false) {
        if (!force && entry.document && !entry.bound && entry.state.candidates.get(entry.record.frameId)?.has(entry)) return
        this._releaseCharge(entry, 'metadata')
        if (this.requests.get(id) === entry) this.requests.delete(id)
        // Keep unbound candidate evidence until the authoritative commit, even
        // if its request finishes first; otherwise a later same-URL overlap
        // could masquerade as the only pending navigation.
    }
    async drain(tabId, { skipDeferred } = {}) {
        const entries = [...this.requests.values()].filter(entry => entry.record.tabId === tabId && entry.done
            // Only the manager's stopping-owner cutoff may skip this newly
            // deferred class. It never settles the shared native request.
            && !((entry.navigationErrorDeferred || entry.replacementDeferred) && !entry.settled
                && typeof skipDeferred === 'function' && skipDeferred(entry.record) === true))
        for (const entry of entries) if (entry.completed && entry.stopped && entry.document && !entry.bound) this._settle(entry, 'document_identity_unavailable')
        else if (entry.completed && entry.stopped && !entry.headersReady) this._settle(entry, 'response_headers_unavailable')
        await Promise.all(entries.map(entry => entry.done))
    }
    release(tabId) {
        const state = this.tabs.get(tabId)
        if (!state) return Promise.resolve()
        this.tabs.delete(tabId)
        for (const [id, entry] of this.requests) if (entry.record.tabId === tabId) { this._settle(entry, 'capture_cancelled', true); this._remove(id, entry, true) }
        for (const frame of state.frames.values()) this._releaseCharge(frame, 'metadata')
        state.frames.clear(); state.candidates.clear()
        return Promise.resolve()
    }
}

export default FirefoxCaptureAdapter
