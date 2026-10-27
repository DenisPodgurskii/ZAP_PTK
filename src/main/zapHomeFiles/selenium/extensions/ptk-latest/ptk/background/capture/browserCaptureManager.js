import { CaptureStore, captureIdentity, freezeCapture } from './captureStore.js'

export const CAPTURE_CAPABILITIES = Object.freeze(['network', 'sources', 'authBodies', 'recording', 'input', 'dialogs'])
const COMMANDS = Object.freeze({ 'Input.dispatchMouseEvent': 'input', 'Page.handleJavaScriptDialog': 'dialogs', 'Network.getRequestPostData': 'recording' })
const BODY_CAPABILITIES = ['sources', 'authBodies', 'recording']
const NON_SOURCE_RESOURCE_TYPES = Object.freeze(['Stylesheet', 'Image', 'Media', 'Font', 'TextTrack', 'XHR', 'Fetch', 'Ping', 'CSPViolationReport', 'Preflight',
    'stylesheet', 'image', 'imageset', 'media', 'font', 'xmlhttprequest', 'ping', 'beacon', 'csp_report'])
const PREPARED_TTL_MS = 60000
const SAST_EARLY_DOM_DOCUMENT_HISTORY_LIMIT = 4096
function httpUrl(value) { try { const url = new URL(value); return /^https?:$/.test(url.protocol) ? url : null } catch (_) { return null } }
function documentIdentity(record) { return record.documentId || record.loaderId || null }
function headerBytes(value, limit = 65536) {
    if (typeof value === 'string') return value.length * 2
    if (!value || typeof value !== 'object') return 8
    let size = 32
    for (const key of Object.keys(value)) { size += key.length * 2 + headerBytes(value[key], limit - size); if (size > limit) break }
    return size
}
function frameKey(record) { return JSON.stringify([record.sessionId || '', record.frameId ?? 'root']) }
function sastDocumentKey(record) { return JSON.stringify([record.epoch, record.captureId, record.tabId, record.sessionId || '',
    record.frameId, record.documentId, record.sessionGeneration, record.navigationGeneration]) }
function sastPayload(payload, maxBytes) {
    if (!payload || typeof payload.file !== 'string' || payload.file.length > 32768 || !Array.isArray(payload.scripts) || payload.scripts.length > 4096 || !Array.isArray(payload.html) || payload.html.length > 4096) throw new Error('capture_collection_unavailable')
    let bytes = payload.file.length * 2
    const scripts = payload.scripts.map(script => {
        if (!script || (script.src != null && typeof script.src !== 'string') || (script.code != null && typeof script.code !== 'string')) throw new Error('capture_collection_unavailable')
        const scriptKind = ['classic', 'module', 'unknown'].includes(script.scriptKind) ? script.scriptKind : undefined
        bytes += ((script.src?.length || 0) + (script.code?.length || 0) + (scriptKind?.length || 0)) * 2 + 96
        if (bytes > maxBytes) throw new Error('capture_collection_unavailable')
        return { src: script.src || null, code: script.code ?? null, ...(scriptKind ? { scriptKind } : {}) }
    })
    const html = payload.html.map(value => {
        if (typeof value !== 'string') throw new Error('capture_collection_unavailable')
        bytes += value.length * 2 + 32
        if (bytes > maxBytes) throw new Error('capture_collection_unavailable')
        return value
    })
    return freezeCapture({ file: payload.file, scripts, html })
}
function isDocument(record) { return ['Document', 'main_frame', 'sub_frame'].includes(record.resourceType) }
function isRootFrame(record) {
    if (record.sessionId || record.resourceType === 'sub_frame') return false
    if (record.parentFrameId !== undefined && record.parentFrameId !== null && record.parentFrameId !== -1) return false
    if (record.resourceType === 'main_frame') return record.frameId === 0
    return record.resourceType === 'Document' || record.resourceType === undefined
}
function scopeValue(scope = {}) {
    if (scope.prepared) return { prepared: true, targetUrl: scope.targetUrl || null, mode: scope.mode || 'origin' }
    const url = httpUrl(scope.targetUrl)
    if (!url || !['origin', 'path'].includes(scope.mode || 'origin')) throw new Error('capture_scope_invalid')
    return { prepared: false, targetUrl: url.href, mode: scope.mode || 'origin' }
}
function permitted(scope, value) {
    const url = httpUrl(value), target = httpUrl(scope.targetUrl)
    if (!url || !target || url.origin !== target.origin) return false
    return scope.mode !== 'path' || url.pathname === target.pathname || url.pathname.startsWith(target.pathname.replace(/\/$/, '') + '/')
}

export class BrowserCaptureManager {
    constructor({ adapter, store = new CaptureStore(), isOwnerActive = () => true, now = () => Date.now(), epoch = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}` } = {}) {
        if (!adapter) throw new Error('capture_adapter_required')
        this.adapter = adapter
        this.store = store
        this.epoch = epoch
        this.isOwnerActive = isOwnerActive
        this.now = now
        this.targets = new Map()
        this.owners = new Map()
        this.serial = 0
        this.headers = new Map()
        adapter.setEventSink(event => this._event(event))
        adapter.setAdmission((record, capability) => this._admit(record, capability))
        adapter.setBudgetHooks?.({
            retain: (record, kind, additionalBytes) => {
                const normalized = { ...record, epoch: this.epoch }
                const target = this.targets.get(record.tabId)
                const pending = this.store.records.get(captureIdentity(normalized))
                // Native frame/context metadata establishes identity and must be
                // budgeted before it can establish a document's scope. Its exact
                // live target owner is necessary, but is NOT body admission.
                const allowed = target && !target.lost && ([...target.owners].some(owner => kind === 'metadata' ? this._valid(owner) : this._allowed(owner, normalized, true) && pending?.refs.has(owner.id))
                    || kind === 'chunks' && this._retiredSources(normalized).length > 0)
                return allowed ? this._captureBudget(() => this.store.stage(normalized, kind, additionalBytes), normalized.tabId) : { ok: false, reason: 'owner_unavailable' }
            },
            release: (record, kind) => this.store.unstage({ ...record, epoch: this.epoch }, kind)
        })
    }

    _target(tabId) {
        if (!this.targets.has(tabId)) this.targets.set(tabId, { tabId, owners: new Set(), tail: Promise.resolve(), pendingOperations: 0, frames: new Map(), lost: false })
        return this.targets.get(tabId)
    }

    _queue(target, fn) {
        target.pendingOperations++
        const result = target.tail.then(fn).finally(() => {
            target.pendingOperations--
            if (target.retirementRequested) this._retireTarget(target)
        })
        target.tail = result.catch(() => {})
        return result
    }

    _valid(owner) {
        if (!owner.active || this.owners.get(owner.key) !== owner) return false
        if (owner.h2Helper) {
            let active = false
            try { active = owner.h2Helper.isOperationActive({ ownerId: owner.ownerId, tabId: owner.tabId, requestUrl: owner.h2Helper.requestUrl }) === true } catch (_) { /* fail closed */ }
            if (!active) { this._release(owner, 'operation_inactive').catch(() => {}); return false }
        }
        if (owner.scope.prepared && this.now() >= owner.preparedDeadline) {
            this._release(owner, 'prepared_expired').catch(() => {})
            return false
        }
        try { return this.isOwnerActive({ ownerId: owner.ownerId, tabId: owner.tabId, epoch: this.epoch }) === true } catch (_) { return false }
    }

    _capabilities(target) {
        return new Set([...target.owners].filter(owner => this._valid(owner)).flatMap(owner => [...owner.capabilities]))
    }

    async acquire({ ownerId, tabId, scope, capabilities = ['network'], signal, selectResource } = {}) {
        if (typeof ownerId !== 'string' || !ownerId || !Number.isInteger(tabId) || tabId < 0) throw new Error('capture_owner_invalid')
        if (!Array.isArray(capabilities) || !capabilities.length || capabilities.some(cap => !CAPTURE_CAPABILITIES.includes(cap))) throw new Error('capture_capability_invalid')
        const key = JSON.stringify([ownerId, tabId])
        if (this.owners.has(key)) throw new Error('capture_owner_duplicate')
        if (selectResource !== undefined && typeof selectResource !== 'function') throw new Error('capture_selector_invalid')
        const normalizedScope = scopeValue(scope)
        const target = this._target(tabId)
        if (target.closed) throw new Error('capture_owner_unavailable')
        if (target.h2HelperUsed) throw new Error('capture_helper_exclusive')
        if (target.lost && target.owners.size) throw new Error('capture_lost')
        if (!target.owners.size) target.lost = false
        const owner = { key, id: `${this.epoch}:${++this.serial}`, ownerId, tabId, scope: normalizedScope, capabilities: new Set(capabilities), target, active: true, ready: false, frozen: false, listeners: new Set(), deliveries: new Set(), collections: new Set(), revision: 0, preparedDocument: null, selectResource, gapCount: 0 }
        this.owners.set(key, owner)
        target.owners.add(owner)
        if (owner.scope.prepared) this._armPrepared(owner)
        const abort = () => { this._release(owner, 'cancelled').catch(() => {}) }
        signal?.addEventListener('abort', abort, { once: true })
        owner.abortCleanup = () => signal?.removeEventListener('abort', abort)
        if (signal?.aborted) abort()
        try {
            await this._queue(target, async () => {
                if (!this._valid(owner)) throw new Error('capture_owner_unavailable')
                await this.adapter.configure(tabId, this._capabilities(target))
                if (!this._valid(owner)) throw new Error('capture_owner_unavailable')
                for (const frame of this.adapter.getSnapshot?.(tabId)?.frames || []) this._document(target, { ...frame, tabId })
                owner.ready = true
            })
        } catch (_) {
            await this._release(owner, 'acquisition_failed').catch(() => {})
            throw new Error('capture_acquisition_failed')
        }
        return this._lease(owner)
    }

    // Internal DAST operation seam, not a scope option for ordinary/prepared
    // owners. The trusted caller owns creation and tab closure; only this
    // exclusive lease can execute the adapter's fixed DAST fetch operation.
    async acquireH2Helper({ ownerId, tabId, requestUrl, isOperationActive, signal } = {}) {
        if (typeof ownerId !== 'string' || !ownerId || !Number.isInteger(tabId) || tabId < 0 || typeof requestUrl !== 'string' || requestUrl.length > 32768 || !httpUrl(requestUrl) || typeof isOperationActive !== 'function') throw new Error('capture_helper_invalid')
        if (this.adapter.supportsH2HelperMetadata !== true) throw new Error('capture_helper_unavailable')
        if (this.targets.has(tabId)) throw new Error('capture_helper_exclusive')
        const target = this._target(tabId)
        if (target.owners.size || target.h2HelperUsed || target.frames.size || target.lost) throw new Error('capture_helper_exclusive')
        target.h2HelperUsed = true
        const key = JSON.stringify([ownerId, tabId])
        const owner = { key, id: `${this.epoch}:${++this.serial}`, ownerId, tabId, scope: scopeValue({ targetUrl: requestUrl }), capabilities: new Set(['network']), target, active: true, ready: false, frozen: false, listeners: new Set(), deliveries: new Set(), collections: new Set(), revision: 0, gapCount: 0, h2Helper: { requestUrl, isOperationActive, binding: null, initialRoot: null } }
        this.owners.set(key, owner)
        target.owners.add(owner)
        const abort = () => { this._release(owner, 'cancelled').catch(() => {}) }
        signal?.addEventListener('abort', abort, { once: true })
        owner.abortCleanup = () => signal?.removeEventListener('abort', abort)
        if (signal?.aborted) abort()
        try {
            await this._queue(target, async () => {
                if (!this._valid(owner)) throw new Error('capture_helper_unavailable')
                await this.adapter.configure(tabId, new Set(['network']))
                if (!this._valid(owner) || target.lost) throw new Error('capture_helper_unavailable')
                const roots = (this.adapter.getSnapshot?.(tabId)?.frames || []).filter(frame => isRootFrame(frame))
                const frame = roots.length === 1 ? roots[0] : null
                if (!frame || frame.nativeDocument === false || frame.url !== 'about:blank' || typeof frame.frameId !== 'string' || !frame.frameId || typeof frame.loaderId !== 'string' || !frame.loaderId || frame.documentId !== frame.loaderId || !Number.isInteger(frame.sessionGeneration) || frame.sessionGeneration <= 0) throw new Error('capture_helper_unavailable')
                this._document(target, { ...frame, tabId })
                if (!this._valid(owner)) throw new Error('capture_helper_unavailable')
                owner.h2Helper.binding = Object.freeze({ frameId: frame.frameId, documentId: frame.documentId, loaderId: frame.loaderId, sessionGeneration: frame.sessionGeneration })
                owner.ready = true
            })
        } catch (_) {
            await this._release(owner, 'acquisition_failed').catch(() => {})
            throw new Error('capture_helper_unavailable')
        }
        const lease = this._lease(owner)
        return Object.freeze({ ...Object.fromEntries(['ownerId', 'tabId', 'epoch', 'captureId', 'subscribe', 'freeze', 'drain', 'release', 'getSnapshot'].map(key => [key, lease[key]])),
            fetch: request => this._h2Fetch(owner, request) })
    }

    _h2Fetch(owner, request) {
        const helper = owner.h2Helper
        const binding = helper?.binding
        const identity = { ...binding, epoch: this.epoch, captureId: owner.id, tabId: owner.tabId,
            url: helper?.requestUrl, documentUrl: 'about:blank' }
        if (!this._admit(identity, 'h2Fetch') || helper.started || !this.adapter.executeH2Fetch) return Promise.reject(new Error('capture_helper_unavailable'))
        if (!request || typeof request !== 'object' || Array.isArray(request)
            || Object.keys(request).some(key => !['url', 'method', 'headers', 'body', 'credentials', 'followRedirect'].includes(key))
            || request.url !== helper.requestUrl || httpUrl(request.url)?.protocol !== 'https:'
            || typeof request.method !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/.test(request.method)
            || !request.headers || typeof request.headers !== 'object' || Array.isArray(request.headers)
            || Object.values(request.headers).some(value => typeof value !== 'string')
            || (request.body != null && typeof request.body !== 'string')
            || !['include', 'omit', 'same-origin'].includes(request.credentials)
            || typeof request.followRedirect !== 'boolean') return Promise.reject(new Error('capture_helper_request_invalid'))
        // Copy only structured data before any await; callers cannot mutate the
        // URL/body or pass executable Runtime parameters through this seam.
        const limit = this.store.limits.resourceBytes
        if (headerBytes(request, limit) > limit) return Promise.reject(new Error('capture_helper_budget_exceeded'))
        request = { url: request.url, method: request.method, headers: { ...request.headers },
            body: request.body, credentials: request.credentials, followRedirect: request.followRedirect }
        helper.started = true
        const task = Promise.resolve().then(async () => {
            if (!this._admit(identity, 'h2Fetch')) throw new Error('capture_helper_unavailable')
            const result = await this.adapter.executeH2Fetch(identity, request)
            if (!this._admit(identity, 'h2Fetch')) throw new Error('capture_helper_unavailable')
            return result
        }).finally(() => owner.collections.delete(task))
        owner.collections.add(task)
        return task
    }

    _lease(owner) {
        return Object.freeze({
            ownerId: owner.ownerId, tabId: owner.tabId, epoch: this.epoch, captureId: owner.id,
            subscribe: fn => {
                if (!this._valid(owner) || typeof fn !== 'function') throw new Error('capture_owner_unavailable')
                owner.listeners.add(fn)
                return () => owner.listeners.delete(fn)
            },
            subscribeSastPayload: fn => {
                if (!this._valid(owner) || !owner.capabilities.has('sources') || owner.sastPayloadListener || typeof fn !== 'function') throw new Error('capture_owner_unavailable')
                owner.sastPayloadListener = fn
                owner.sastBatches ||= new Set()
                return () => { owner.sastPayloadListener = null; for (const batch of [...owner.sastBatches]) batch.release() }
            },
            setSastState: state => this._setSastState(owner, state),
            getSastState: sender => this._getSastState(owner, sender),
            getSastAcquisitionStatus: () => this._sastAcquisitionStatus(owner),
            reconcileSastSourceReferences: (identity, refs) => this._reconcileSastSourceReferences(owner, identity, refs),
            getSastAnalysisFailure: () => {
                if (!this._valid(owner)) return null
                for (const obligation of owner.sastDomDocuments?.values() || []) {
                    const receipt = obligation.analysisFailure?.value
                    if (receipt?.failedLiveCode) return receipt.failedLiveCode
                    if (receipt?.failurePhase === 'final') return receipt.failedOriginalCode
                }
                return null
            },
            acquireSastAnalysisReceipt: identity => {
                const obligation = this._analysisObligation(owner, identity)
                return this._borrowAnalysisReceipt(obligation?.analysisReceipt || obligation?.analysisFailure)
            },
            setSastAnalysisReceipt: (identity, value, bytes) => this._setAnalysisReceipt(owner, identity, value, bytes),
            acceptSastPush: (sender, packet) => this._acceptSastPush(owner, sender, packet),
            // Private SAST seam. Handoffs are synchronous queue admission only;
            // a listener must not return/await analysis or lease drainage.
            subscribeSourceBatches: fn => {
                if (!this._valid(owner) || !owner.capabilities.has('sources') || owner.sourceBatchListener || typeof fn !== 'function') throw new Error('capture_owner_unavailable')
                owner.sourceBatchListener = fn
                owner.sourceBatches = new Set()
                return () => {
                    owner.sourceBatchListener = null
                    this._revokeSourceBatches(owner)
                    this._revokeRetiredSources(owner)
                }
            },
            getResources: (query = {}) => {
                if (!this._valid(owner) || owner.scope.prepared) return []
                return this.store.find(owner.id, { ...query, epoch: this.epoch, tabId: owner.tabId }).filter(record => this._allowed(owner, record, true))
            },
            getResource: key => {
                const record = this.store.get(key, owner.id)
                return record && this._valid(owner) && !owner.scope.prepared && this._allowed(owner, record, true) ? record : undefined
            },
            consume: key => this.store.consume(key, owner.id),
            updateScope: scope => this._updateScope(owner, scope),
            freeze: () => {
                if (owner.frozen) return
                owner.frozen = true
                if (owner.sastState?.active) this._setSastState(owner, { active: false }).catch(() => {})
                if (owner.h2Helper) this.adapter.cancelH2Fetch?.(owner.tabId, owner.id)
            },
            drain: () => this._drain(owner),
            release: reason => this._release(owner, reason),
            sendCommand: (method, params = {}, sessionId) => this._command(owner, method, params, sessionId),
            getDocuments: () => this._documents(owner),
            isSastDocumentPending: (identity, requiredScripts) => this._sastDocumentPending(owner, identity, requiredScripts),
            hasPendingSastSources: identity => this._sastDocumentPending(owner, identity, null),
            hasRetiredSastSources: identity => this._hasRetiredSastSources(owner, identity),
            collectSastPayload: identity => this._collectSastPayload(owner, identity),
            acceptSastPayload: (identity, trustedSender, payload) => this._acceptSastPayload(owner, identity, trustedSender, payload),
            getSnapshot: () => ({ epoch: this.epoch, ready: owner.ready && this._valid(owner), active: this._valid(owner), prepared: owner.scope.prepared, reason: owner.releaseReason, capabilities: [...owner.capabilities], gaps: owner.gapCount, resources: this.store.snapshot() })
        })
    }

    _document(target, record) {
        const identity = documentIdentity(record)
        if (!identity) return
        const key = frameKey(record), previous = target.frames.get(key)
        if (record.previousDocumentId && previous && previous.identity !== record.previousDocumentId) return
        // Only a native adapter's authoritative binding can replace an exact
        // provisional frame identity. URL coincidence never rebinds a record.
        const rebind = record.previousDocumentId && previous?.identity === record.previousDocumentId && identity !== previous.identity
        if (rebind) {
            const match = resource => resource.tabId === target.tabId && frameKey(resource) === key && documentIdentity(resource) === previous.identity
            const rebound = this.store.rebindDocument(match, identity)
            for (const reason of rebound.reasons) this._gap([...target.owners].filter(owner => this._valid(owner)), reason)
            for (const owner of target.owners) if (owner.preparedDocument === previous.identity) owner.preparedDocument = identity
        }
        const changed = previous?.identity !== identity || previous?.sessionGeneration !== record.sessionGeneration
        if (changed && previous && !rebind) this._sealRetiringDocument(target, key, previous)
        if (changed) target.frames.set(key, { identity, url: record.url || record.documentUrl, parentFrameId: record.parentFrameId ?? previous?.parentFrameId, sessionGeneration: record.sessionGeneration, navigationGeneration: record.navigationGeneration, nativeDocument: record.nativeDocument !== false })
        if (record.nativeDocument !== false && typeof record.documentId === 'string' && record.documentId) {
            // Reject delayed messages from any document already bound in this
            // tab. On saturation, fail closed for the unbound fast path.
            target.sastSeenDocumentIds ||= new Set()
            if (!target.sastSeenDocumentIds.has(record.documentId)) {
                if (target.sastSeenDocumentIds.size < SAST_EARLY_DOM_DOCUMENT_HISTORY_LIMIT) target.sastSeenDocumentIds.add(record.documentId)
                else target.sastEarlyDomHistorySaturated = true
            }
        }
        const nativeRole = { ...record, parentFrameId: target.frames.get(key)?.parentFrameId }
        if (!target.primaryFrame && isRootFrame(nativeRole)) target.primaryFrame = key
        for (const owner of target.owners) {
            if (owner.h2Helper && isRootFrame(nativeRole)) {
                const initial = owner.h2Helper.initialRoot
                if (initial && (initial.key !== key || initial.identity !== identity || initial.sessionGeneration !== record.sessionGeneration || record.url !== 'about:blank')) {
                    this._release(owner, 'helper_navigated').catch(() => {})
                    continue
                }
                owner.h2Helper.initialRoot ||= { key, identity, sessionGeneration: record.sessionGeneration }
            }
            if (changed) this.store.release(owner.id, resource => frameKey(resource) === key && documentIdentity(resource) !== identity)
            if (owner.scope.prepared && !owner.preparedDocument && !record.preexisting && httpUrl(record.url || record.documentUrl)) {
                // Prepared capture is only the owned primary document, not an arbitrary iframe.
                if (key !== target.primaryFrame || !isRootFrame(nativeRole) || !['Document', 'main_frame'].includes(record.resourceType)) continue
                owner.preparedDocument = identity
                owner.scope.targetUrl = record.url || record.documentUrl
            }
            if (changed) this.store.release(owner.id, resource => frameKey(resource) === key && !this._allowed(owner, resource, true))
            if (changed && owner.sastState?.active) {
                this._syncSastObligations(owner)
                this.adapter.refreshSastState?.(owner.tabId)
            }
            if (record.nativeDocument === true) this._flushPendingSastDom(owner, record)
        }
    }

    _sealRetiringDocument(target, key, frame) {
        const [sessionId, frameId] = JSON.parse(key)
        for (const owner of target.owners) {
            const identity = {
            epoch: this.epoch, captureId: owner.id, tabId: owner.tabId, sessionId: sessionId || undefined,
            frameId, documentId: frame.identity, sessionGeneration: frame.sessionGeneration,
            navigationGeneration: frame.navigationGeneration, url: frame.url, documentUrl: frame.url
            }
            // Retained SAST originals no longer emit the adapter's global
            // replacement gap. Preserve that existing observation only for
            // non-source consumers which actually held this pending body ref.
            if (!owner.capabilities.has('sources') && (owner.capabilities.has('recording') || owner.capabilities.has('authBodies'))
                && this.adapter.canRetainSource) {
                for (const entry of this.store.records.values()) if (!entry.complete && entry.refs.has(owner.id)
                    && frameKey(entry.record) === key && documentIdentity(entry.record) === frame.identity
                    && entry.record.sessionGeneration === frame.sessionGeneration && entry.record.navigationGeneration === frame.navigationGeneration
                    && this._allowed(owner, entry.record, true) && this.adapter.canRetainSource(entry.record)) {
                    this._gap([owner], 'document_replaced', entry.record)
                }
            }
            if (!this._retainRetiringSources(owner, identity)) this._sealSourceBatch(owner, identity, 'retired')
        }
    }

    _sourceEntries(owner, identity) {
        return [...this.store.records.entries()].filter(([, entry]) => entry.refs.has(owner.id)
            && frameKey(entry.record) === frameKey(identity) && documentIdentity(entry.record) === identity.documentId
            && entry.record.sessionGeneration === identity.sessionGeneration && entry.record.navigationGeneration === identity.navigationGeneration
            && this._allowed(owner, entry.record, true) && this._selected(owner, entry.record, 'sources'))
    }

    _retainRetiringSources(owner, identity) {
        if (this.adapter.supportsRetiredSources !== true || !owner.sourceBatchListener || !this._collectionAllowed(owner, identity, true)) return false
        const matching = this._sourceEntries(owner, identity)
        if (!matching.some(([, entry]) => !entry.complete)) return false
        // Firefox may retain only its fully stopped, natively bound original;
        // other adapters preserve their existing admitted-source contract.
        if (this.adapter.canRetainSource && matching.some(([, entry]) => !entry.complete
            && !this.adapter.canRetainSource(entry.record))) return false
        const refId = `${owner.id}:retired-source:${++this.serial}`
        const reserved = this._completeCapture({ ...identity, requestId: refId, keys: matching.map(([key]) => key) }, [refId])
        if (!reserved.ok) { this._gap([owner], reserved.reason); return false }
        const pinned = []
        for (const [key, entry] of matching) {
            const result = this._captureBudget(() => this.store.reserve(entry.record, [refId]), owner.tabId)
            if (!result.ok) {
                for (const key of pinned) this.store.consume(key, refId)
                this.store.consume(reserved.key, refId)
                this._gap([owner], result.reason)
                return false
            }
            pinned.push(key)
        }
        owner.retiredSources ||= new Set()
        const health = owner.sastDomDocuments?.get(sastDocumentKey(identity))?.analysisFailure
        const analysisFailurePin = this._pinAnalysisReceipt(health, identity)
        if (health?.value && !analysisFailurePin) {
            for (const key of pinned) this.store.consume(key, refId)
            this.store.consume(reserved.key, refId)
            this._gap([owner], 'source_batch_delivery_failed'); return false
        }
        const receipt = owner.sastDomDocuments?.get(sastDocumentKey(identity))?.analysisReceipt
        const source = owner.sastDomDocuments?.get(sastDocumentKey(identity))?.sourceAcquisition
        const sourceAcquisitionPin = this._pinAnalysisReceipt(source, identity)
        if (source?.value?.refs.length && !sourceAcquisitionPin) {
            this._releaseAnalysisPin(analysisFailurePin)
            for (const key of pinned) this.store.consume(key, refId)
            this.store.consume(reserved.key, refId)
            this._gap([owner], 'source_batch_delivery_failed'); return false
        }
        owner.retiredSources.add({ key: reserved.key, refId, revision: owner.revision,
            analysisPin: this._pinAnalysisReceipt(receipt, identity),
            analysisFailurePin, sourceAcquisitionPin })
        return true
    }

    _retiredData(owner, grant) {
        if (!this._valid(owner) || !owner.ready || owner.target.lost || owner.scope.prepared
            || !owner.sourceBatchListener || !owner.capabilities.has('sources') || owner.revision !== grant.revision) return
        return this.store.get(grant.key, grant.refId)
    }

    _retiredSources(record) {
        if (this.adapter.supportsRetiredSources !== true) return []
        const key = captureIdentity(record), result = []
        const fields = ['tabId', 'frameId', 'documentId', 'loaderId', 'sessionGeneration', 'navigationGeneration', 'url', 'documentUrl', 'method', 'resourceType']
        for (const owner of this.targets.get(record.tabId)?.owners || []) for (const grant of owner.retiredSources || []) {
            const data = this._retiredData(owner, grant), entry = this.store.records.get(key)
            if (data?.keys.includes(key) && entry?.refs.has(grant.refId)
                && (record.sessionId || '') === (entry.record.sessionId || '')
                && fields.every(field => record[field] === entry.record[field])
                && permitted(owner.scope, record.url) && (!record.documentUrl || permitted({ ...owner.scope, mode: 'origin' }, record.documentUrl))
                && this._selected(owner, record, 'sources')) result.push({ owner, grant })
        }
        return result
    }

    _revokeRetiredSources(owner, predicate = () => true) {
        for (const grant of [...owner.retiredSources || []]) {
            const data = this.store.get(grant.key, grant.refId)
            if (data && !predicate(data)) continue
            for (const key of data?.keys || []) this.store.consume(key, grant.refId)
            this.store.consume(grant.key, grant.refId)
            this._releaseAnalysisPin(grant.analysisPin)
            this._releaseAnalysisPin(grant.analysisFailurePin)
            this._releaseAnalysisPin(grant.sourceAcquisitionPin)
            owner.retiredSources.delete(grant)
        }
    }

    _flushRetiredSources(owner, final = false) {
        for (const grant of [...owner.retiredSources || []]) {
            const data = this._retiredData(owner, grant)
            if (!data) { this._revokeRetiredSources(owner, identity => identity.requestId === grant.refId); continue }
            const entries = data.keys.map(key => [key, this.store.records.get(key)]).filter(([, entry]) => entry?.refs.has(grant.refId))
            if (!final && entries.some(([, entry]) => !entry.complete)) continue
            const incompleteCount = data.keys.length - entries.filter(([, entry]) => entry.complete && entry.record.complete === true).length
            this._publishSourceBatch(owner, data, entries, 'retired', incompleteCount, grant.analysisPin?.receipt, grant.analysisFailurePin?.receipt, grant.sourceAcquisitionPin?.receipt)
            this._revokeRetiredSources(owner, identity => identity.requestId === grant.refId)
        }
    }

    _sealSourceBatch(owner, identity, reason) {
        if (!owner.sourceBatchListener || !this._collectionAllowed(owner, identity, true)) return
        this._publishSourceBatch(owner, identity, this._sourceEntries(owner, identity), reason)
    }

    _publishSourceBatch(owner, identity, matching, reason, incompleteCount = matching.filter(([, entry]) => !entry.complete || entry.record.complete !== true).length, retainedReceipt = null, retainedFailure = null, retainedAcquisition = null) {
        const complete = matching.filter(([, entry]) => entry.complete && entry.record.complete === true)
        const source = retainedAcquisition || owner.sastDomDocuments?.get(sastDocumentKey(identity))?.sourceAcquisition
        this._resolveSastSourceReferences(source, matching)
        if (!complete.length) {
            if (incompleteCount || source?.value?.refs.length) this._gap([owner], 'source_batch_incomplete')
            return
        }
        const refId = `${owner.id}:source-batch:${++this.serial}`
        const descriptor = { ...identity, requestId: refId, ownerId: owner.ownerId, revision: owner.revision,
            keys: complete.map(([key]) => key), reason, incompleteCount }
        // The descriptor/key list and every extra record reference are charged
        // before a handle can escape. Never copy bodies into a second cache.
        const reserved = this._completeCapture(descriptor, [refId])
        if (!reserved.ok) { this._gap([owner], reserved.reason); return }
        const pinned = []
        for (const [key, entry] of complete) {
            const result = this._captureBudget(() => this.store.reserve(entry.record, [refId]), owner.tabId)
            if (!result.ok) {
                for (const pinnedKey of pinned) this.store.consume(pinnedKey, refId)
                this.store.consume(reserved.key, refId)
                this._gap([owner], result.reason)
                return
            }
            pinned.push(key)
        }
        const health = retainedFailure || owner.sastDomDocuments?.get(sastDocumentKey(identity))?.analysisFailure
        const analysisFailurePin = this._pinAnalysisReceipt(health, identity)
        if (health?.value && !analysisFailurePin) {
            for (const key of pinned) this.store.consume(key, refId)
            this.store.consume(reserved.key, refId)
            this._gap([owner], 'source_batch_delivery_failed'); return
        }
        const receipt = retainedReceipt || owner.sastDomDocuments?.get(sastDocumentKey(identity))?.analysisReceipt
        const sourceAcquisitionPin = source?.value?.refs.length ? this._pinAnalysisReceipt(source, identity) : null
        if (source?.value?.refs.length && !sourceAcquisitionPin) {
            this._releaseAnalysisPin(analysisFailurePin)
            for (const key of pinned) this.store.consume(key, refId)
            this.store.consume(reserved.key, refId)
            this._gap([owner], 'source_batch_delivery_failed'); return
        }
        const batch = { key: reserved.key, refId, revision: owner.revision,
            analysisPin: this._pinAnalysisReceipt(receipt, identity),
            analysisFailurePin, sourceAcquisitionPin }
        owner.sourceBatches.add(batch)
        const isActive = () => this._valid(owner) && !owner.target.lost && owner.ready
            && owner.revision === batch.revision && owner.sourceBatches.has(batch)
        const handle = Object.freeze({
            isActive,
            acquireAnalysisReceipt: () => isActive() ? this._borrowAnalysisReceipt(batch.analysisPin?.receipt || batch.analysisFailurePin?.receipt) : { value: null, release() {} },
            setAnalysisReceipt: (value, bytes) => isActive() && this._setAnalysisReceipt(owner, identity, value, bytes, batch),
            read: () => {
                if (!isActive()) throw new Error('capture_source_batch_unavailable')
                const data = this.store.get(batch.key, batch.refId)
                if (!data) throw new Error('capture_source_batch_unavailable')
                const records = data.keys.map(key => this.store.get(key, batch.refId))
                if (records.some(record => !record)) throw new Error('capture_source_batch_unavailable')
                return Object.freeze({ identity: data, records: Object.freeze(records), incompleteCount: data.incompleteCount, reason: data.reason,
                    unresolvedSourceReferences: batch.sourceAcquisitionPin?.receipt?.value?.refs || Object.freeze([]) })
            },
            release: () => this._releaseSourceBatch(owner, batch)
        })
        try {
            // Deliberately do not use _deliver: its current-document check is
            // correct for live events, and its awaited task would cycle drainage.
            owner.sourceBatchListener(handle)
        } catch (_) {
            handle.release()
            this._gap([owner], 'source_batch_delivery_failed')
        }
    }

    _releaseSourceBatch(owner, batch) {
        if (!owner.sourceBatches?.delete(batch)) return
        const data = this.store.get(batch.key, batch.refId)
        for (const key of data?.keys || []) this.store.consume(key, batch.refId)
        this.store.consume(batch.key, batch.refId)
        this._releaseAnalysisPin(batch.analysisPin)
        this._releaseAnalysisPin(batch.analysisFailurePin)
        this._releaseAnalysisPin(batch.sourceAcquisitionPin)
    }

    _revokeSourceBatches(owner, predicate = () => true) {
        for (const batch of [...owner.sourceBatches || []]) {
            const identity = this.store.get(batch.key, batch.refId)
            if (!identity || predicate(identity)) this._releaseSourceBatch(owner, batch)
        }
    }

    _allowed(owner, record, currentDocument = false) {
        if (!this._valid(owner) || owner.target.lost || record.tabId !== owner.tabId) return false
        if (owner.h2Helper) {
            const binding = owner.h2Helper.binding
            const current = binding && owner.target.frames.get(frameKey(binding))
            return !!(owner.ready && binding && current && current.url === 'about:blank' && current.identity === binding.documentId && current.sessionGeneration === binding.sessionGeneration && !record.sessionId && record.frameId === binding.frameId && record.documentId === binding.documentId && record.loaderId === binding.loaderId && record.sessionGeneration === binding.sessionGeneration && record.documentUrl === 'about:blank' && record.url === owner.h2Helper.requestUrl && (!record.response?.url || record.response.url === owner.h2Helper.requestUrl) && !isDocument(record))
        }
        const identity = documentIdentity(record)
        const current = owner.target.frames.get(frameKey(record))
        if (currentDocument && (!identity || !current || current.identity !== identity)) return false
        if (identity && current && identity !== current.identity) return false
        if (record.sessionId && current && current.sessionGeneration !== record.sessionGeneration) return false
        if (owner.scope.prepared && (!owner.preparedDocument || identity !== owner.preparedDocument)) return false
        if (current?.url && !permitted({ ...owner.scope, mode: 'origin' }, current.url)) return false
        // Both source URL and owning document are checked; a sourceURL cannot grant scope.
        return permitted(owner.scope, record.url || record.documentUrl) && (!record.documentUrl || permitted({ ...owner.scope, mode: 'origin' }, record.documentUrl))
    }

    _eligible(record, capability, pending = false) {
        const target = this.targets.get(record.tabId)
        if (!target || target.lost) return []
        return [...target.owners].filter(owner => (!pending || !owner.frozen) && !(capability === 'recording' && owner.recordingInvalidated) && owner.capabilities.has(capability) && this._allowed(owner, record, BODY_CAPABILITIES.includes(capability)) && this._selected(owner, record, capability))
    }

    _selected(owner, record, capability) {
        if (!BODY_CAPABILITIES.includes(capability)) return true
        if (capability === 'sources' && !record.scriptId && !['Document', 'main_frame', 'sub_frame', 'Script', 'script'].includes(record.resourceType)) return false
        // Auth endpoint/body selection remains the existing consumer's policy,
        // never a manager-wide capture of all authenticated traffic.
        if (capability === 'authBodies' && !owner.selectResource) return false
        try { return !owner.selectResource || owner.selectResource(record, capability) === true } catch (_) { return false }
    }

    _admit(record, capability) {
        const normalized = { ...record, epoch: this.epoch }
        const target = this.targets.get(record.tabId)
        if (!target) return false
        if (capability === 'h2Fetch') return [...target.owners].some(owner => owner.h2Helper
            && owner.id === record.captureId && !owner.frozen && this._allowed(owner, normalized, true))
        if (capability === 'retiredSources') return this._retiredSources(normalized).length > 0
        if (capability === 'domSources') return [...target.owners].some(owner => owner.capabilities.has('sources') && this._allowed(owner, normalized, true))
        if (isDocument(record) && !target.frames.has(frameKey(record))) this._document(target, record)
        if (capability === 'metadata') return ['network', ...BODY_CAPABILITIES].some(cap => this._eligible(normalized, cap, true).length)
        const owners = this._eligible(normalized, capability, true)
        if (!owners.length) return false
        const result = this._captureBudget(() => this.store.reserve(normalized, owners.map(owner => owner.id)), normalized.tabId)
        if (!result.ok) this._gap(owners, result.reason)
        return result.ok
    }

    _event(event) {
        const target = this.targets.get(event.record?.tabId ?? event.source?.tabId)
        if (!target) return
        if (event.type === 'sastPushError') {
            const owner = [...target.owners].find(item => item.id === event.ownerId)
            if (owner?.sastState?.isActive() && owner.sastState.revision === event.revision) this._gap([owner], event.record.reason, event.record)
            return
        }
        if (event.type === 'sastPayload') {
            const owner = [...target.owners].find(item => item.id === event.ownerId)
            if (!owner || owner.sastState?.revision !== event.revision || !owner.sastState.active || event.current?.() !== true) return
            const identity = this._documents(owner).find(item => ['frameId', 'documentId', 'sessionGeneration', 'navigationGeneration'].every(key => item[key] === event.record[key]) && (item.sessionId || '') === (event.record.sessionId || ''))
            if (identity) this._publishSastPayload(owner, identity, event.payload, event.nativeCurrent)
            return
        }
        if (event.type === 'tabClosed') {
            target.closed = true
            target.lost = true
            target.retirementRequested = true
            this._clearHeaders(chain => chain.tabId === target.tabId)
            for (const owner of [...target.owners]) this._release(owner, 'tab_closed').catch(() => {})
            this._queue(target, () => this._retireTarget(target)).catch(() => {})
            return
        }
        // Once armed, any primary navigation/detach permanently ends this
        // operation's exception, including a later return to about:blank.
        for (const owner of target.owners) if (owner.h2Helper?.binding) {
            const binding = owner.h2Helper.binding
            const rootNavigation = event.type === 'protocol' && event.method === 'Page.frameNavigated' && !event.record?.sessionId && event.record?.frameId === binding.frameId
            const rootReplacement = event.type === 'invalidate' && event.record?.reason === 'document_replaced' && !event.record.sessionId && event.record.frameId === binding.frameId && event.record.documentId === binding.documentId && event.record.sessionGeneration === binding.sessionGeneration
            const rootDetach = event.type === 'protocol' && event.method === 'Page.frameDetached' && !event.record?.sessionId && (event.params?.frameId ?? event.record?.frameId) === binding.frameId
            if (event.type === 'detach' || rootNavigation || rootReplacement || rootDetach || event.type === 'request' && isDocument(event.record) && !event.record.sessionId && event.record.frameId === binding.frameId) this._release(owner, 'helper_navigated').catch(() => {})
        }
        if (event.type === 'invalidate' && event.record?.reason === 'document_replaced') {
            const record = event.record, key = frameKey(record), current = target.frames.get(key)
            if (!current || current.identity !== documentIdentity(record) || current.sessionGeneration !== record.sessionGeneration) return
            this._sealRetiringDocument(target, key, current)
            target.frames.delete(key)
            for (const owner of target.owners) if (owner.sastDomDocuments) this._syncSastObligations(owner)
            const match = resource => resource.tabId === target.tabId && frameKey(resource) === key && documentIdentity(resource) === current.identity && resource.sessionGeneration === current.sessionGeneration
            this._clearHeaders(chain => chain.tabId === target.tabId && chain.hops.some(hop => match(hop.record)))
            for (const owner of target.owners) this.store.release(owner.id, match)
            return
        }
        if (event.type === 'invalidate' && event.record?.reason === 'child_domains_failed') {
            const { sessionId, sessionGeneration } = event.record
            if (!sessionId) return
            for (const owner of target.owners) this._revokeSourceBatches(owner, identity => identity.sessionId === sessionId && identity.sessionGeneration === sessionGeneration)
            for (const owner of target.owners) this._revokeRetiredSources(owner, identity => identity.sessionId === sessionId && identity.sessionGeneration === sessionGeneration)
            const keys = new Set([...target.frames].filter(([key, frame]) => JSON.parse(key)[0] === sessionId && frame.sessionGeneration === sessionGeneration).map(([key]) => key))
            for (const key of keys) target.frames.delete(key)
            for (const owner of target.owners) if (owner.sastDomDocuments) this._syncSastObligations(owner)
            this._clearHeaders(chain => chain.tabId === target.tabId && chain.sessionId === sessionId && chain.generation === sessionGeneration)
            for (const owner of target.owners) this.store.release(owner.id, record => record.tabId === target.tabId && record.sessionId === sessionId && record.sessionGeneration === sessionGeneration)
            this._gap([...target.owners].filter(owner => this._valid(owner)), 'child_domains_failed')
            return
        }
        if (event.type === 'detach') this._clearHeaders(chain => chain.tabId === target.tabId)
        if (event.type === 'protocol' && ['Page.frameDetached', 'Target.detachedFromTarget'].includes(event.method)) {
            const detachedFrame = event.params?.frameId ?? event.record?.frameId
            const detachedSession = event.params?.sessionId
            const generation = event.record?.sessionGeneration
            const keys = new Set([...target.frames].filter(([key, frame]) => (generation === undefined || frame.sessionGeneration === generation)
                && (detachedSession ? JSON.parse(key)[0] === detachedSession : JSON.parse(key)[1] === detachedFrame && JSON.parse(key)[0] === (event.record?.sessionId || ''))).map(([key]) => key))
            // Remove same-process descendants as well as the named native frame.
            let added
            do {
                added = false
                for (const [key, frame] of target.frames) if (!keys.has(key) && [...keys].some(parent => JSON.parse(parent)[0] === JSON.parse(key)[0] && JSON.parse(parent)[1] === frame.parentFrameId)) { keys.add(key); added = true }
            } while (added)
            for (const owner of target.owners) this._revokeSourceBatches(owner, identity => detachedSession
                ? identity.sessionId === detachedSession && (generation === undefined || identity.sessionGeneration === generation)
                : keys.has(frameKey(identity)) && (generation === undefined || identity.sessionGeneration === generation))
            for (const owner of target.owners) this._revokeRetiredSources(owner, identity => detachedSession
                ? identity.sessionId === detachedSession && (generation === undefined || identity.sessionGeneration === generation)
                : (keys.has(frameKey(identity)) || identity.frameId === detachedFrame && (identity.sessionId || '') === (event.record?.sessionId || '')) && (generation === undefined || identity.sessionGeneration === generation))
            for (const key of keys) target.frames.delete(key)
            for (const owner of target.owners) if (owner.sastDomDocuments) this._syncSastObligations(owner)
            this._clearHeaders(chain => chain.tabId === target.tabId && (detachedSession ? chain.sessionId === detachedSession : chain.hops.some(hop => keys.has(frameKey(hop.record)))))
            const match = resource => resource.tabId === target.tabId && keys.has(frameKey(resource))
            for (const owner of target.owners) this.store.release(owner.id, match)
            if (keys.size) this._gap([...target.owners].filter(owner => this._valid(owner)), 'frame_detached')
            return
        }
        if (event.type === 'detach') {
            target.lost = true
            target.frames.clear()
            for (const owner of target.owners) if (owner.sastDomDocuments) this._syncSastObligations(owner)
            for (const owner of target.owners) {
                this._clearPendingSastDom(owner)
                this._revokeSourceBatches(owner)
                this._revokeRetiredSources(owner)
                owner.ready = false
                this.store.release(owner.id)
                this._deliver(owner, freezeCapture({ type: 'gap', record: { tabId: owner.tabId, epoch: this.epoch, reason: 'capture_detached', complete: false } }))
            }
            return
        }
        let record = { ...event.record, epoch: this.epoch }
        if (event.type === 'protocol' && event.method === 'Page.frameNavigated') this._document(target, record)
        if (event.type === 'request' && isDocument(record)) this._document(target, record)
        // Header identity has its own lifetime: body completion/consume cannot
        // retire redirect slots or native ExtraInfo sequences.
        if (event.type === 'protocol' && /^Network\.(requestWillBeSent|responseReceived)ExtraInfo$/.test(event.method)) { this._headerEvent(target, event, record); return }
        if (event.type === 'request' || event.type === 'response' || event.type === 'terminal') this._headerEvent(target, event, record)
        if (event.type === 'terminal') return
        if (event.type === 'protocol' && event.method === 'Page.frameNavigated') this._clearHeaders(chain => chain.tabId === target.tabId && chain.hops.some(hop => frameKey(hop.record) === frameKey(record) && (documentIdentity(hop.record) !== documentIdentity(record) || hop.record.sessionGeneration !== record.sessionGeneration)))
        if (event.type === 'request') {
            // A redirect leaves the previous hop's captured body intact, but it
            // cannot lend its identity to later extra-info on a foreign hop.
            for (const [key, entry] of this.store.records) if (!entry.complete && entry.record.tabId === record.tabId && entry.record.requestId === record.requestId && (entry.record.sessionId || '') === (record.sessionId || '') && entry.record.hop !== record.hop) this.store.remove(key)
        }
        if (event.type === 'gap') {
            const retired = this._retiredSources(record)
            if (retired.length) {
                this.store.remove(captureIdentity(record))
                for (const { owner } of retired) { this._gap([owner], /^[a-z_]+$/.test(record.reason || '') ? record.reason : 'capture_unavailable'); this._flushRetiredSources(owner) }
                return
            }
            const eligible = record.url || record.documentUrl ? [...new Set(['network', ...BODY_CAPABILITIES].flatMap(cap => this._eligible(record, cap)))] : [...target.owners].filter(owner => this._valid(owner))
            const key = captureIdentity(record), stored = this.store.records.get(key)
            // A late terminal observation cannot erase immutable source bytes
            // already sealed before retirement. It still cannot admit new bytes.
            if (!stored?.complete || ![...stored.refs].some(ref => ref.includes(':source-batch:'))) this.store.remove(key)
            this._gap(eligible, /^[a-z_]+$/.test(record.reason || '') ? record.reason : 'capture_unavailable', record)
            return
        }
        if (event.type === 'protocol' && event.method?.startsWith('Page.javascriptDialog')) {
            const frame = [...target.frames.entries()].find(([key, value]) => JSON.parse(key)[0] === (record.sessionId || '') && (value.parentFrameId === undefined || value.parentFrameId === null || value.parentFrameId === -1))
            if (!frame) return
            record = { ...record, frameId: JSON.parse(frame[0])[1], documentId: frame[1].identity, url: frame[1].url, documentUrl: frame[1].url }
        }
        const body = event.type === 'body' || event.type === 'script'
        const retired = body && record.complete === true ? this._retiredSources(record) : []
        if (retired.length) {
            const result = this._completeCapture(record, retired.map(({ grant }) => grant.refId))
            for (const owner of new Set(retired.map(item => item.owner))) {
                if (!result.ok) this._gap([owner], result.reason)
                this._flushRetiredSources(owner)
            }
            return
        }
        const capabilities = event.type === 'script' ? ['sources'] : body ? BODY_CAPABILITIES : event.type === 'protocol' && event.method?.startsWith('Page.javascriptDialog') ? ['dialogs'] : event.type === 'protocol' && event.method?.endsWith('ExtraInfo') ? ['recording'] : ['network', 'recording', 'sources', 'authBodies']
        let owners = [...new Set(capabilities.flatMap(cap => this._eligible(record, cap)))]
        if (event.type === 'request') owners = owners.filter(owner => !owner.h2Helper || !owner.frozen)
        if (!owners.length) {
            if (body && !this.store.records.get(captureIdentity(record))?.complete) this.store.remove(captureIdentity(record))
            return
        }
        if (body) {
            if (!this.store.records.has(captureIdentity(record))) return
            const result = this._completeCapture(record, owners.map(owner => owner.id))
            if (!result.ok) { this._gap(owners, result.reason); return }
            record = result.record
            owners = owners.filter(owner => this.store.get(result.key, owner.id))
        } else if (event.type === 'request') {
            // Recorder needs bounded request identity until body/post-data/extra-info
            // completion. Other metadata is charged while delivery is outstanding,
            // not retained as an unnecessary scan-wide request history.
            const recordingOwners = owners.filter(owner => owner.capabilities.has('recording')
                || this.adapter.supportsRetiredSources === true && !owner.frozen && owner.sourceBatchListener
                    && owner.capabilities.has('sources') && this._allowed(owner, record, true) && this._selected(owner, record, 'sources'))
            if (recordingOwners.length) {
                const result = this._captureBudget(() => this.store.reserve(record, recordingOwners.map(owner => owner.id)), record.tabId)
                if (!result.ok) this._gap(recordingOwners, result.reason)
            }
        }
        const immutable = Object.freeze({ ...freezeCapture(event), record: body ? record : freezeCapture(record) })
        for (const owner of owners) if (owner.ready && !owner.scope.prepared) this._deliver(owner, immutable)
    }

    _clearHeaders(predicate) {
        for (const [key, chain] of this.headers) if (predicate(chain)) {
            for (const charge of chain.charges) this.store.unstage(charge, 'metadata')
            this.headers.delete(key)
        }
    }

    _forgetHeaderOwner(owner) {
        for (const chain of this.headers.values()) chain.owners = chain.owners.filter(item => item.owner !== owner)
        this._clearHeaders(chain => !chain.owners.length)
    }

    _headerOwners(chain, record) {
        return chain.owners.filter(({ owner, revision }) => this._valid(owner) && !owner.recordingInvalidated && owner.revision === revision && (!record || this._allowed(owner, record, true) && owner.target.frames.get(frameKey(record))?.sessionGeneration === record.sessionGeneration)).map(item => item.owner)
    }

    _headerCharge(chain, value) {
        const record = { epoch: this.epoch, tabId: chain.tabId, sessionId: chain.sessionId, requestId: `capture-header:${++this.serial}` }
        const size = headerBytes(value)
        const result = size <= 65536 ? this.store.stage(record, 'metadata', size) : { ok: false }
        if (!result.ok) { this._headerSuppress(chain); return null }
        record.headerCharge = this.store.staging.get(`${captureIdentity(record)}:metadata`).size
        if ((chain.bytes || 0) + record.headerCharge > this.store.limits.resourceBytes) { this.store.unstage(record, 'metadata'); this._headerSuppress(chain); return null }
        chain.bytes = (chain.bytes || 0) + record.headerCharge
        chain.charges.add(record)
        return record
    }

    _headerSuppress(chain) {
        if (chain.suppressed) return
        chain.suppressed = true
        for (const queue of chain.queues) queue.length = 0
        // Preserve only the already charged chain tombstone, never restart its
        // sequence after overflow and accidentally lend another hop's scope.
        for (const charge of [...chain.charges]) if (charge !== chain.charge) { this.store.unstage(charge, 'metadata'); chain.bytes -= charge.headerCharge; chain.charges.delete(charge) }
        chain.hops.length = 0
        this._gap(this._headerOwners(chain), 'header_correlation_incomplete')
    }

    _headerEvent(target, event, record) {
        if (this.adapter.supportsExtraInfo !== true) return
        if (record.sessionId && ![...target.frames.keys()].some(key => JSON.parse(key)[0] === record.sessionId)) return
        const generationFrames = [...target.frames.entries()].filter(([key]) => JSON.parse(key)[0] === (record.sessionId || ''))
        if (generationFrames.length && !generationFrames.some(([, frame]) => frame.sessionGeneration === record.sessionGeneration)) return
        const key = JSON.stringify([this.epoch, record.tabId, record.sessionId || '', record.sessionGeneration || 0, record.requestId])
        let chain = this.headers.get(key)
        if (!chain) {
            const owners = [...target.owners].filter(owner => owner.ready && !owner.frozen && !owner.recordingInvalidated && owner.capabilities.has('recording') && this._valid(owner))
            if (!owners.length || record.requestId === undefined) return
            chain = { tabId: record.tabId, sessionId: record.sessionId || '', generation: record.sessionGeneration, owners: owners.map(owner => ({ owner, revision: owner.revision })), hops: [], queues: [[], []], cursors: [0, 0], charges: new Set(), terminal: false }
            chain.charge = this._headerCharge(chain, { key, owners: owners.map(owner => owner.id) })
            if (!chain.charge) {
                // No space even for suppression identity: invalidate only the
                // affected recording capture, not other body consumers.
                for (const owner of owners) { owner.headerFailed = true; owner.recordingInvalidated = true; this._forgetHeaderOwner(owner) }
                return
            }
            this.headers.set(key, chain)
            if (event.type === 'request' && record.redirect) { this._headerSuppress(chain); return }
        }
        if (chain.suppressed) return
        if (event.type === 'request') {
            if (chain.hops.length) {
                const previous = chain.hops.at(-1)
                previous.flag = record.redirectHasExtraInfo
                if (typeof previous.flag !== 'boolean') { this._headerSuppress(chain); return }
            }
            const identity = { epoch: this.epoch, tabId: record.tabId, sessionId: record.sessionId, sessionGeneration: record.sessionGeneration, requestId: record.requestId, hop: chain.hops.length, frameId: record.frameId, documentId: record.documentId, loaderId: record.loaderId, url: record.url, documentUrl: record.documentUrl }
            if (!this._headerCharge(chain, identity)) return
            chain.hops.push({ record: identity, flag: undefined, seen: [false, false] })
        } else if (event.type === 'response') {
            const hop = chain.hops.at(-1)
            if (!hop || typeof record.hasExtraInfo !== 'boolean') { this._headerSuppress(chain); return }
            hop.flag = record.hasExtraInfo
        } else if (event.type === 'terminal') chain.terminal = true
        else {
            const current = chain.hops.at(-1)?.record
            if (current && ['documentId', 'loaderId', 'frameId', 'url', 'documentUrl'].some(field => record[field] !== undefined && record[field] !== current[field])) return
            const index = event.method === 'Network.requestWillBeSentExtraInfo' ? 0 : 1
            const charge = this._headerCharge(chain, event)
            if (!charge) return
            chain.queues[index].push({ event: freezeCapture(event), charge })
        }
        for (let index = 0; index < 2; index++) {
            while (chain.cursors[index] < chain.hops.length) {
                const hop = chain.hops[chain.cursors[index]]
                if (hop.flag === undefined) break
                if (hop.flag === false) { chain.cursors[index]++; continue }
                const queued = chain.queues[index].shift()
                if (!queued) break
                const supplied = queued.event.record || {}
                const identity = hop.record
                // Native ExtraInfo has no scope fields. If a producer supplies
                // them, disagreement cannot override the admitted hop.
                const conflicts = ['documentId', 'loaderId', 'frameId', 'url', 'documentUrl'].some(field => supplied[field] !== undefined && supplied[field] !== identity[field])
                if (!conflicts) for (const owner of this._headerOwners(chain, identity)) this._deliver(owner, Object.freeze({ ...queued.event, record: freezeCapture(identity) }))
                this.store.unstage(queued.charge, 'metadata'); chain.bytes -= queued.charge.headerCharge; chain.charges.delete(queued.charge)
                hop.seen[index] = true
                chain.cursors[index]++
            }
        }
        // Native completion plus both fully resolved sequences retires header
        // identity independently of body references. A later orphan cannot be
        // dispatched without a new exact base event; stop reports it incomplete.
        if (chain.terminal && chain.hops.length && chain.cursors.every(cursor => cursor === chain.hops.length) && chain.queues.every(queue => !queue.length)) this._clearHeaders(candidate => candidate === chain)
    }

    _deliver(owner, event) {
        const revision = owner.revision
        for (const listener of owner.listeners) {
            const deliveryId = `${owner.id}:delivery:${++this.serial}`
            const body = event.type === 'body' || event.type === 'script'
            const reservation = this._captureBudget(() => body ? this.store.reserve(event.record, [deliveryId]) : this.store.reserve({ epoch: this.epoch, tabId: owner.tabId, requestId: deliveryId, event }, [deliveryId]), owner.tabId)
            if (!reservation.ok) { owner.gapCount++; owner.deliveryFailed = true; continue }
            // Do not await analysis, publication or user callbacks on browser event handlers.
            const task = Promise.resolve().then(() => {
                if (event.type === 'gap' && event.record?.requestId !== undefined) {
                    if (this._valid(owner) && owner.revision === revision && this._nativeGapCurrent(owner, event.record)) return listener(event)
                    return
                }
                const headers = event.method?.endsWith('ExtraInfo')
                const childScoped = event.record?.sessionId && event.record?.frameId !== undefined
                if (this._valid(owner) && owner.revision === revision && (!(body || headers || childScoped || owner.h2Helper) || this._allowed(owner, event.record, true)) && (!(headers || childScoped) || owner.target.frames.get(frameKey(event.record))?.sessionGeneration === event.record.sessionGeneration)) return listener(event)
            }).catch(() => { owner.deliveryFailed = true }).finally(() => { this.store.consume(reservation.key, deliveryId); owner.deliveries.delete(task) })
            owner.deliveries.add(task)
        }
    }

    _nativeGapCurrent(owner, record) {
        const current = owner.target.frames.get(frameKey(record))
        return !!(current && current.nativeDocument !== false && documentIdentity(record) === current.identity
            && (record.loaderId === undefined || record.loaderId === current.identity)
            && record.sessionGeneration === current.sessionGeneration
            && record.navigationGeneration === current.navigationGeneration
            && this._allowed(owner, { ...record, url: current.url, documentUrl: current.url }, true))
    }

    _gap(owners, reason, nativeRecord) {
        for (const owner of owners) {
            owner.gapCount++
            const identity = {}
            const fields = ['sessionId', 'requestId', 'hop', 'frameId', 'documentId', 'loaderId', 'sessionGeneration', 'navigationGeneration']
            const intermediateRedirect = reason === 'redirect_body_unavailable'
                && Number.isInteger(nativeRecord?.response?.status)
                && [301, 302, 303, 307, 308].includes(nativeRecord.response.status)
            // Only adapter-supplied, exactly admitted native failures carry an
            // identity. Synthetic gaps remain anonymous; never forward payloads.
            if ((['request_cancelled', 'response_body_unavailable'].includes(reason) || intermediateRedirect)
                && nativeRecord && typeof nativeRecord.requestId === 'string' && nativeRecord.requestId
                && nativeRecord.nativeDocument !== false && owner.target.frames.get(frameKey(nativeRecord))?.nativeDocument !== false
                && nativeRecord.frameId !== undefined && documentIdentity(nativeRecord)
                && fields.every(field => nativeRecord[field] === undefined || ['string', 'number'].includes(typeof nativeRecord[field]))
                && this._allowed(owner, nativeRecord, true) && this._nativeGapCurrent(owner, nativeRecord)) {
                for (const field of fields) if (nativeRecord[field] !== undefined) identity[field] = nativeRecord[field]
                // Preserve the network loss while excluding only proven
                // non-source requests from SAST's missing-source accounting.
                if (intermediateRedirect || nativeRecord.scriptId === undefined && NON_SOURCE_RESOURCE_TYPES.includes(nativeRecord.resourceType)) identity.affectsSources = false
            }
            if (owner.ready && !owner.scope.prepared) this._deliver(owner, freezeCapture({ type: 'gap', record: { ...identity, tabId: owner.tabId, epoch: this.epoch, complete: false, reason } }))
        }
    }

    _updateScope(owner, scope) {
        if (owner.h2Helper) throw new Error('capture_helper_scope_denied')
        if (!this._valid(owner)) throw new Error('capture_owner_unavailable')
        const next = scopeValue(scope)
        this._clearPendingSastDom(owner)
        this._revokeSourceBatches(owner)
        this._revokeRetiredSources(owner)
        const wasPrepared = owner.scope.prepared
        if (wasPrepared && next.prepared && !next.targetUrl) next.targetUrl = owner.scope.targetUrl
        // Adoption keeps this same lease's admitted natural reads only when
        // the newly validated scope and current native document still allow
        // them. Other revisions invalidate pending work as before.
        if (!wasPrepared || next.prepared) this.store.release(owner.id, record => !this.store.records.get(captureIdentity(record))?.complete)
        owner.scope = next
        if (!next.prepared) { clearTimeout(owner.preparedTimer); owner.preparedDeadline = undefined }
        else if (!wasPrepared) this._armPrepared(owner)
        owner.revision++
        this._forgetHeaderOwner(owner)
        this.store.release(owner.id, record => !this._allowed(owner, record, true))
        if (owner.sastDomDocuments) this._syncSastObligations(owner)
        if (owner.sastState?.active) this.adapter.refreshSastState?.(owner.tabId)
        return { active: true, prepared: next.prepared }
    }

    async _command(owner, method, params, sessionId) {
        if (!this._valid(owner) || !owner.ready || owner.target.lost || !owner.capabilities.has(COMMANDS[method])) throw new Error('capture_command_denied')
        let request
        if (method === 'Network.getRequestPostData') {
            request = [...this.store.records.values()].find(entry => entry.refs.has(owner.id) && entry.record.requestId === params.requestId && (entry.record.sessionId || '') === (sessionId || '') && this._allowed(owner, entry.record, true))?.record
            if (!request) throw new Error('capture_request_unavailable')
        }
        const frame = sessionId ? [...owner.target.frames].find(([key]) => JSON.parse(key)[0] === sessionId) : undefined
        if (sessionId && !frame) throw new Error('capture_session_unavailable')
        const revision = owner.revision
        const result = await this.adapter.send(owner.tabId, method, params, sessionId)
        if (!this._valid(owner) || owner.revision !== revision || owner.target.lost) throw new Error('capture_owner_unavailable')
        if (frame && (!owner.target.frames.has(frame[0]) || owner.target.frames.get(frame[0]).sessionGeneration !== frame[1].sessionGeneration)) throw new Error('capture_session_unavailable')
        if (request) {
            const entry = this.store.records.get(captureIdentity(request))
            if (!entry?.refs.has(owner.id) || entry.record.sessionGeneration !== request.sessionGeneration || documentIdentity(entry.record) !== documentIdentity(request) || frameKey(entry.record) !== frameKey(request) || !this._allowed(owner, entry.record, true)) throw new Error('capture_request_unavailable')
        }
        return result
    }

    _documents(owner) {
        if (!this._valid(owner) || !owner.ready || owner.scope.prepared || !owner.capabilities.has('sources')) return []
        return [...owner.target.frames].filter(([, frame]) => frame.nativeDocument).map(([key, frame]) => {
            const [sessionId, frameId] = JSON.parse(key)
            return freezeCapture({ epoch: this.epoch, captureId: owner.id, tabId: owner.tabId, sessionId: sessionId || undefined, frameId, parentFrameId: frame.parentFrameId, documentId: frame.identity, sessionGeneration: frame.sessionGeneration, navigationGeneration: frame.navigationGeneration, url: frame.url, documentUrl: frame.url })
        }).filter(identity => this._allowed(owner, identity, true))
    }
    _collectionAllowed(owner, identity, accepted = false) {
        if (!identity || !owner.target.frames.get(frameKey(identity))?.nativeDocument) return false
        return identity && identity.epoch === this.epoch && identity.captureId === owner.id && owner.ready && (accepted || !owner.frozen) && !owner.scope.prepared && owner.capabilities.has('sources') && this._allowed(owner, identity, true) && owner.target.frames.get(frameKey(identity))?.sessionGeneration === identity.sessionGeneration && owner.target.frames.get(frameKey(identity))?.navigationGeneration === identity.navigationGeneration
    }
    _hasRetiredSastSources(owner, identity) {
        if (!identity || !this._valid(owner) || !owner.ready || owner.target.lost || owner.scope.prepared
            || !owner.sourceBatchListener || !owner.capabilities.has('sources')) return false
        const matches = data => data && ['epoch', 'captureId', 'tabId', 'frameId', 'documentId', 'sessionGeneration', 'navigationGeneration']
            .every(key => data[key] === identity[key]) && (data.sessionId || '') === (identity.sessionId || '')
            && data.epoch === this.epoch && data.captureId === owner.id
            && permitted(owner.scope, data.url) && permitted({ ...owner.scope, mode: 'origin' }, data.documentUrl || data.url)
        const retained = (item, data) => matches(data) && item.revision === owner.revision && data.keys?.length > 0
            && data.keys.every(key => this.store.records.get(key)?.refs.has(item.refId))
        return [...owner.retiredSources || []].some(grant => retained(grant, this._retiredData(owner, grant)))
            || [...owner.sourceBatches || []].some(batch => {
                const data = this.store.get(batch.key, batch.refId)
                return data?.reason === 'retired' && data.ownerId === owner.ownerId && retained(batch, data)
            })
    }
    _sastDocumentPending(owner, identity, requiredScripts = []) {
        if (!this._valid(owner) || !this._collectionAllowed(owner, identity, true)
            || !this._documents(owner).some(current => ['epoch', 'captureId', 'tabId', 'frameId', 'documentId', 'sessionGeneration', 'navigationGeneration']
                .every(key => current[key] === identity[key]) && (current.sessionId || '') === (identity.sessionId || ''))) return false
        // Existing native request reservations live until body completion or
        // terminal failure. Never infer pending acquisition from a URL or age.
        const entries = this._sourceEntries(owner, identity)
        // Stop observes all already-admitted SAST sources, including imports
        // not represented by a live DOM reference. It never waits for them.
        if (requiredScripts === null) return entries.some(([, entry]) => !entry.complete
            && (isDocument(entry.record) || ['Script', 'script'].includes(entry.record.resourceType)))
        if (entries.some(([, entry]) => !entry.complete && isDocument(entry.record))) return true
        if (!Array.isArray(requiredScripts) || !requiredScripts.length) return false
        return requiredScripts.every(src => {
            if (typeof src !== 'string' || !src) return false
            const matching = entries.filter(([, entry]) => ['Script', 'script'].includes(entry.record.resourceType) && entry.record.url === src)
            return matching.length === 1 && !matching[0][1].complete
                && typeof matching[0][1].record.requestId === 'string' && !!matching[0][1].record.requestId
        })
    }
    _collectSastPayload(owner, identity) {
        if (!this._collectionAllowed(owner, identity) || !this.adapter.collectSastPayload || owner.collections.size >= 2) return Promise.reject(new Error('capture_collection_unavailable'))
        // Copy only the native identity held by this owner; an awaiting caller
        // cannot mutate a supplied object into another frame/document.
        identity = this._documents(owner).find(document => ['epoch', 'captureId', 'tabId', 'frameId', 'documentId', 'sessionGeneration', 'navigationGeneration'].every(key => document[key] === identity[key]) && (document.sessionId || '') === (identity.sessionId || ''))
        if (!identity) return Promise.reject(new Error('capture_collection_unavailable'))
        const charge = { ...identity, requestId: `capture-collection:${++this.serial}` }
        if (!this.store.stage(charge, 'metadata', 1024).ok) return Promise.reject(new Error('capture_collection_unavailable'))
        const revision = owner.revision
        const task = Promise.resolve().then(async () => {
            if (!this._collectionAllowed(owner, identity, true) || owner.revision !== revision) throw new Error('capture_collection_unavailable')
            const payload = await this.adapter.collectSastPayload(identity)
            if (!this._collectionAllowed(owner, identity, true) || owner.revision !== revision) throw new Error('capture_collection_unavailable')
            try { return this._sastPayload(identity, payload) }
            catch (error) { try { error.sastCollectionStage = 'manager_validation' } catch (_) {} throw error }
        }).finally(() => { this.store.unstage(charge, 'metadata'); owner.collections.delete(task) })
        owner.collections.add(task)
        return task
    }
    _acceptSastPayload(owner, identity, sender, payload) {
        // This is an acceptance seam for the existing trusted content-message
        // handler, not a transport. Native Firefox document IDs must match exactly.
        if (!this._collectionAllowed(owner, identity) || !this.adapter.acceptSastPayload) throw new Error('capture_collection_unavailable')
        return this._sastPayload(identity, this.adapter.acceptSastPayload(identity, sender, payload))
    }
    _sastPayload(identity, payload) {
        const result = sastPayload(payload, this.store.limits.resourceBytes)
        const charge = { ...identity, requestId: `capture-collection-result:${++this.serial}` }
        if (!this.store.stage(charge, 'chunks', headerBytes(result, this.store.limits.resourceBytes)).ok) throw new Error('capture_collection_unavailable')
        // Synchronous ownership transfer, no retained second collector cache.
        this.store.unstage(charge, 'chunks')
        return result
    }

    _setSastState(owner, value) {
        if (value?.active && (!this._valid(owner) || !owner.ready || owner.frozen || !owner.sastPayloadListener || typeof value.scanId !== 'string' || !value.scanId)) throw new Error('capture_owner_unavailable')
        this._clearPendingSastDom(owner)
        const config = { active: value?.active === true, scanId: value?.scanId || owner.sastState?.scanId || null,
            ownerId: owner.id, revision: ++this.serial,
            isActive: () => owner.sastState === config && config.active && !owner.frozen && this._valid(owner),
            nextRevision: () => ++this.serial,
            getIdentity: record => this._documents(owner).find(identity => this._collectionAllowed(owner, identity)
                && ['frameId', 'documentId', 'sessionGeneration', 'navigationGeneration'].every(key => identity[key] === record[key])
                && (identity.sessionId || '') === (record.sessionId || '')) }
        owner.sastState = config
        if (config.active) this._syncSastObligations(owner)
        const result = Promise.resolve(this.adapter.setSastState?.(owner.tabId, config))
        owner.sastStateFlight = result
        return result
    }

    _disposeAnalysisReceipt(receipt) {
        if (!receipt || receipt.current || receipt.pins) return
        this.store.unstage(receipt.charge, receipt.kind || 'chunks')
        receipt.value = null
    }

    _borrowAnalysisReceipt(receipt) {
        if (!receipt?.value) return { value: null, release() {} }
        receipt.pins++
        let released = false
        return { value: receipt.value, release: () => {
            if (released) return
            released = true; receipt.pins--; this._disposeAnalysisReceipt(receipt)
        } }
    }

    _pinAnalysisReceipt(receipt, identity) {
        if (!receipt?.value) return null
        receipt.pins++
        const charge = { ...identity, requestId: `sast-analysis-pin:${++this.serial}` }
        const admitted = receipt.kind === 'metadata'
            ? this._captureBudget(() => this.store.stage(charge, 'metadata', 128), identity.tabId)
            : this.store.stage(charge, 'metadata', 128)
        if (!admitted.ok) { receipt.pins--; this._disposeAnalysisReceipt(receipt); return null }
        return { receipt, charge }
    }

    _releaseAnalysisPin(pin) {
        if (!pin || pin.released) return
        pin.released = true
        this.store.unstage(pin.charge, 'metadata')
        pin.receipt.pins--; this._disposeAnalysisReceipt(pin.receipt)
    }

    _evictAnalysisReceipt(tabId, global) {
        for (const owner of this.owners.values()) for (const obligation of owner.sastDomDocuments?.values() || []) {
            const receipt = obligation.analysisReceipt
            if (!receipt?.value || receipt.pins || !global && owner.tabId !== tabId) continue
            obligation.analysisReceipt = null; receipt.current = false
            this._disposeAnalysisReceipt(receipt)
            return true
        }
        return false
    }

    _captureBudget(operation, tabId) {
        let result = operation()
        while (!result.ok && ['tab_budget', 'global_budget'].includes(result.reason)
            && this._evictAnalysisReceipt(tabId, result.reason === 'global_budget')) result = operation()
        return result
    }

    _completeCapture(record, consumers) {
        // Projection has exactly complete's ref intersection/short circuit,
        // but cannot remove a pending native reservation on quota refusal.
        this._captureBudget(() => this.store.canComplete(record, consumers), record.tabId)
        return this.store.complete(record, consumers)
    }

    _analysisObligation(owner, identity, create = false) {
        if (!this._valid(owner) || !this._collectionAllowed(owner, identity, true)) return null
        const key = sastDocumentKey(identity)
        if (!this._documents(owner).some(document => sastDocumentKey(document) === key)) return null
        owner.sastDomDocuments ||= new Map()
        if (create && !owner.sastDomDocuments.has(key)) {
            const charge = { ...identity, requestId: `sast-dom-obligation:${++this.serial}` }
            if (!this._captureBudget(() => this.store.stage(charge, 'metadata', headerBytes(identity) + 192), owner.tabId).ok) return null
            // Fixed health capacity is mandatory acquisition metadata, not an
            // evictable successful-result optimization. No raw source is kept.
            const healthCharge = { ...identity, requestId: `sast-analysis-health:${++this.serial}` }
            if (!this._captureBudget(() => this.store.stage(healthCharge, 'metadata', 1024), owner.tabId).ok) {
                this.store.unstage(charge, 'metadata'); return null
            }
            owner.sastDomDocuments.set(key, { charge, received: false, analysisReceipt: null, sourceAcquisition: null,
                analysisFailure: { value: null, charge: healthCharge, kind: 'metadata', pins: 0, current: true } })
        }
        return owner.sastDomDocuments.get(key) || null
    }

    _resolveSastSourceReferences(cell, entries) {
        if (!cell?.value) return
        const captured = new Set(entries.filter(([, entry]) => entry.complete && entry.record.complete === true
            && ['Script', 'script'].includes(entry.record.resourceType) && !entry.record.base64Encoded
            && typeof entry.record.body === 'string').map(([, entry]) => entry.record.url))
        cell.value.refs = Object.freeze(cell.value.refs.filter(ref => !captured.has(ref)))
    }

    _reconcileSastSourceReferences(owner, identity, refs) {
        const obligation = this._analysisObligation(owner, identity, owner.sastState?.isActive() === true)
        if (!obligation) return { unresolved: 0, refused: true, references: [] }
        if (!Array.isArray(refs) || refs.length > 4096
            || refs.some(ref => typeof ref !== 'string' || !ref || ref.length > 8192)) {
            this._gap([owner], 'source_batch_delivery_failed', identity)
            return { unresolved: 0, refused: true, references: [] }
        }
        const previous = obligation.sourceAcquisition
        const expected = new Set([...(previous?.value?.refs || []), ...(owner.sastState?.isActive() ? refs : [])])
        if (expected.size > 4096) {
            this._gap([owner], 'source_batch_delivery_failed', identity)
            return { unresolved: expected.size, refused: true, references: previous?.value?.refs || [] }
        }
        const value = { refs: Object.freeze([...expected]) }, candidate = { value }
        this._resolveSastSourceReferences(candidate, this._sourceEntries(owner, identity))
        if (!value.refs.length) {
            if (previous) { previous.current = false; this._disposeAnalysisReceipt(previous); obligation.sourceAcquisition = null }
            return { unresolved: 0, refused: false, references: value.refs }
        }
        const bytes = value.refs.reduce((sum, ref) => sum + ref.length * 2 + 32, 128)
        const charge = previous?.charge || { ...identity, requestId: `sast-source-references:${++this.serial}` }
        const additional = Math.max(0, bytes - (previous?.bytes || 0))
        if (additional && !this._captureBudget(() => this.store.stage(charge, 'metadata', additional), owner.tabId).ok) {
            this._gap([owner], 'source_batch_delivery_failed', identity)
            return { unresolved: value.refs.length, refused: true, references: previous?.value?.refs || [] }
        }
        const cell = previous || { charge, kind: 'metadata', pins: 0, current: true, bytes: 0 }
        cell.value = value; cell.bytes = Math.max(bytes, cell.bytes)
        obligation.sourceAcquisition = cell
        return { unresolved: value.refs.length, refused: false, references: value.refs }
    }

    _setAnalysisReceipt(owner, identity, value, bytes, batch = null) {
        if (!this._valid(owner) || !owner.ready || owner.target.lost || !owner.capabilities.has('sources')
            || !value || !Number.isSafeInteger(bytes) || bytes < 0 || bytes > this.store.limits.resourceBytes) return false
        const obligation = this._analysisObligation(owner, identity, !batch)
        if (!obligation && (!batch || !owner.sourceBatches.has(batch) || owner.revision !== batch.revision)) return false
        const health = obligation?.analysisFailure || batch?.analysisFailurePin?.receipt
        if (health) {
            if (value.failedOriginalCode || value.failedLiveCode) health.value = {
                failedOriginalKey: value.failedOriginalKey, failedOriginalCode: value.failedOriginalCode,
                failedLiveCode: value.failedLiveCode, failurePhase: value.failurePhase,
                run: value.run, engine: value.engine, token: value.token
            }
            else if (value.key || !health.value?.failedLiveCode) health.value = null
        }
        const charge = { ...identity, requestId: `sast-analysis-receipt:${++this.serial}` }
        // Result records are optional: never evict source bytes to retain one.
        if (!this._captureBudget(() => this.store.stage(charge, 'chunks', bytes), owner.tabId).ok) return false
        const receipt = { value, charge, pins: 0, current: !!obligation }
        if (obligation) {
            const previous = obligation.analysisReceipt
            obligation.analysisReceipt = receipt
            if (previous) { previous.current = false; this._disposeAnalysisReceipt(previous) }
        }
        if (batch) {
            const pin = this._pinAnalysisReceipt(receipt, identity)
            if (pin) {
                this._releaseAnalysisPin(batch.analysisPin)
                batch.analysisPin = pin
            } else if (!obligation) this._disposeAnalysisReceipt(receipt)
        }
        return true
    }

    _syncSastObligations(owner) {
        owner.sastDomDocuments ||= new Map()
        const documents = this._documents(owner), current = new Set(documents.map(sastDocumentKey))
        for (const [key, obligation] of owner.sastDomDocuments) if (!current.has(key)) {
            if (obligation.analysisReceipt) { obligation.analysisReceipt.current = false; this._disposeAnalysisReceipt(obligation.analysisReceipt) }
            if (obligation.analysisFailure) { obligation.analysisFailure.current = false; this._disposeAnalysisReceipt(obligation.analysisFailure) }
            if (obligation.sourceAcquisition) { obligation.sourceAcquisition.current = false; this._disposeAnalysisReceipt(obligation.sourceAcquisition) }
            this.store.unstage(obligation.charge, 'metadata'); owner.sastDomDocuments.delete(key)
        }
        if (!owner.sastState?.isActive()) return
        for (const identity of documents) {
            const key = sastDocumentKey(identity)
            if (owner.sastDomDocuments.has(key)) continue
            if (!this._analysisObligation(owner, identity, true)) this._gap([owner], 'sast_dom_push_failed', identity)
        }
    }

    _sastAcquisitionStatus(owner) {
        const current = new Set(this._documents(owner).map(sastDocumentKey))
        let expected = 0, unresolved = 0, unresolvedSources = 0
        const cells = new Set()
        for (const [key, obligation] of owner.sastDomDocuments || []) if (current.has(key)) {
            expected++; if (!obligation.received) unresolved++
            if (obligation.sourceAcquisition?.value) cells.add(obligation.sourceAcquisition)
        }
        for (const grant of owner.retiredSources || []) if (this._retiredData(owner, grant) && grant.sourceAcquisitionPin?.receipt?.value) cells.add(grant.sourceAcquisitionPin.receipt)
        for (const batch of owner.sourceBatches || []) if (this._valid(owner) && batch.revision === owner.revision && batch.sourceAcquisitionPin?.receipt?.value) cells.add(batch.sourceAcquisitionPin.receipt)
        for (const cell of cells) unresolvedSources += cell.value.refs.length
        return { expected, unresolved, unresolvedSources }
    }

    _getSastState(owner, sender) {
        const config = owner.sastState
        if (!config?.isActive()) return { active: false, revision: config?.revision || 0, transport: 'runtime' }
        if (this.adapter.supportsBrowserSastDocument) return this._getBrowserSastState(owner, sender, config)
        const identity = this._documents(owner).find(item => item.frameId === sender?.frameId && item.documentId === sender?.documentId && item.tabId === sender?.tab?.id)
        if (!identity || typeof sender?.documentId !== 'string') return { active: false, revision: config.revision, transport: 'runtime' }
        // Existing adapter validator proves the browser-owned sender and exact
        // native incarnation; an empty inert payload establishes no DOM data.
        try { this._acceptSastPayload(owner, identity, sender, { file: identity.url, scripts: [], html: [] }) }
        catch (_) { return { active: false, revision: config.revision, transport: 'runtime' } }
        return { active: true, revision: config.revision, transport: 'runtime' }
    }

    async _getBrowserSastState(owner, sender, config) {
        const document = await this.adapter.getBrowserSastDocument(sender)
        return { active: !!(document && config.isActive() && owner.ready && owner.capabilities.has('sources')
            && document.tabId === owner.tabId && permitted(owner.scope, document.url)),
        revision: config.revision, transport: 'runtime' }
    }

    _acceptSastPush(owner, sender, packet) {
        const candidate = packet?.type === 'dom_candidate'
        if (candidate && sender?.frameId !== 0) return false
        const config = owner.sastState, state = this._getSastState(owner, sender)
        // An early candidate carries no content-side grant. Stamp the current
        // owner revision only after the exact native document is validated;
        // the normal admission path rechecks activity after async lookup.
        const admittedPacket = candidate ? { type: 'dom_snapshot', revision: config?.revision, payload: packet.payload } : packet
        if (this.adapter.supportsBrowserSastDocument) return Promise.resolve(state).then(result =>
            this._acceptBrowserSastPush(owner, sender, admittedPacket, config, result))
        if (!state.active || owner.sastState !== config || !config?.isActive() || admittedPacket?.revision !== config.revision) {
            // Firefox can deliver a trusted root snapshot before its native
            // onCommitted identity. Retain at most one charged DOM candidate;
            // it is not an analysis grant until that exact document binds.
            return candidate && !state.active ? this._retainPendingSastDom(owner, sender, packet, config) : false
        }
        const identity = this._documents(owner).find(item => item.frameId === sender.frameId && item.documentId === sender.documentId)
        if (admittedPacket.type === 'producer_error') { this._gap([owner], 'sast_dom_push_failed', identity); return false }
        if (admittedPacket.type !== 'dom_snapshot') return false
        let payload
        try { payload = this._acceptSastPayload(owner, identity, sender, admittedPacket.payload) } catch (_) { this._gap([owner], 'sast_dom_push_failed', identity); return false }
        return this._publishSastPayload(owner, identity, payload, () => true, candidate)
    }

    _clearPendingSastDom(owner) {
        const pending = owner.pendingSastDom
        if (!pending) return
        owner.pendingSastDom = null
        this.store.unstage(pending.charge, 'chunks')
    }

    _retainPendingSastDom(owner, sender, packet, config) {
        if (!config?.isActive() || !owner.ready || !owner.capabilities.has('sources') || !owner.sastPayloadListener
            || owner.scope.prepared || owner.target.lost || sender?.tab?.id !== owner.tabId || sender?.frameId !== 0
            || typeof sender?.documentId !== 'string' || !sender.documentId
            || typeof this.adapter.browser?.runtime?.id !== 'string'
            || sender.id !== this.adapter.browser.runtime.id) return false
        const current = owner.target.frames.get(frameKey({ frameId: 0 }))
        // A new document's trusted content message can overtake the queued
        // provisional request while the prior native document is still shown
        // as current. Only an exact match to that current document is denied;
        // the different candidate remains unanalysed until native binding.
        if (owner.target.sastEarlyDomHistorySaturated || owner.target.sastSeenDocumentIds?.has(sender.documentId)
            || current?.nativeDocument && current.identity === sender.documentId
            || owner.pendingSastDom && owner.pendingSastDom.sender.documentId !== sender.documentId) return false
        let payload
        try {
            payload = sastPayload(packet.payload, this.store.limits.resourceBytes)
            if (!permitted(owner.scope, payload.file) || sender.url && httpUrl(sender.url)?.origin !== httpUrl(payload.file)?.origin) return false
            // Source URLs are DOM references; only inline code is retained.
            payload = freezeCapture({ ...payload, scripts: payload.scripts.map(script => script.src ? { ...script, code: null } : script) })
        } catch (_) { return false }
        const charge = { epoch: this.epoch, captureId: owner.id, tabId: owner.tabId, requestId: `sast-dom-candidate:${++this.serial}` }
        if (!this.store.stage(charge, 'chunks', headerBytes(payload, this.store.limits.resourceBytes)).ok) return false
        this._clearPendingSastDom(owner)
        owner.pendingSastDom = { charge, sender: { id: sender.id, tab: { id: sender.tab.id }, frameId: 0,
            documentId: sender.documentId, url: sender.url }, payload, config, revision: owner.revision }
        return true
    }

    _flushPendingSastDom(owner, record) {
        const pending = owner.pendingSastDom
        if (!pending || record?.nativeDocument !== true || record.frameId !== 0) return
        this._clearPendingSastDom(owner)
        if (record.documentId !== pending.sender.documentId || owner.revision !== pending.revision
            || owner.sastState !== pending.config || !pending.config.isActive()) return
        const identity = this._documents(owner).find(item => item.frameId === 0 && item.documentId === pending.sender.documentId)
        if (!identity) return
        try {
            const payload = this._acceptSastPayload(owner, identity, pending.sender, pending.payload)
            this._publishSastPayload(owner, identity, payload, () => true, true)
        } catch (_) { this._gap([owner], 'sast_dom_push_failed', identity) }
    }

    _acceptBrowserSastPush(owner, sender, packet, config, state) {
        if (!state?.active || !config?.isActive() || owner.sastState !== config
            || packet?.revision !== config.revision || packet?.type !== 'dom_snapshot') return false
        const url = sender.url
        if (packet.payload?.file !== url || !permitted(owner.scope, url)) return false
        const identity = freezeCapture({ epoch: this.epoch, captureId: owner.id, tabId: owner.tabId,
            frameId: 0, documentId: sender.documentId, url, documentUrl: url, browserDocument: true })
        let payload
        try { payload = freezeCapture(sastPayload(packet.payload, this.store.limits.resourceBytes)) }
        catch (_) { this._gap([owner], 'sast_dom_push_failed', identity); return false }
        // Browser DOM is live/inline evidence only. Original and external JS
        // bodies remain under the independent native Network source contract.
        payload = freezeCapture({ ...payload, scripts: payload.scripts.filter(script => !script.src) })
        const charge = { ...identity, requestId: `sast-browser-dom:${++this.serial}` }
        if (!this.store.stage(charge, 'chunks', headerBytes(payload, this.store.limits.resourceBytes)).ok) {
            this._gap([owner], 'sast_dom_push_failed', identity); return false
        }
        const revision = owner.revision
        let released = false
        const batch = Object.freeze({ identity, payload, browserDocument: true,
            isActive: () => !released && owner.revision === revision && config.isActive()
                && owner.sastPayloadListener && !owner.target.lost,
            get active() { return batch.isActive() },
            release: () => { if (released) return; released = true; owner.sastBatches.delete(batch); this.store.unstage(charge, 'chunks') } })
        owner.sastBatches ||= new Set(); owner.sastBatches.add(batch)
        try { owner.sastPayloadListener(batch) }
        catch (_) { batch.release(); this._gap([owner], 'sast_dom_push_failed', identity); return false }
        return true
    }

    _publishSastPayload(owner, identity, value, nativeCurrent = () => true, acceptedCandidate = false) {
        if (!owner.sastState?.isActive() || !this._collectionAllowed(owner, identity) || !owner.sastPayloadListener) return false
        let payload
        try { payload = freezeCapture(sastPayload(value, this.store.limits.resourceBytes)) }
        catch (_) { this._gap([owner], 'sast_dom_push_failed', identity); return false }
        // The native URL owns original responses; the current live route must
        // independently remain in scope. Payload URLs never rebind identity.
        if (!permitted(owner.scope, payload.file) || httpUrl(payload.file)?.origin !== httpUrl(identity.url)?.origin) return false
        const charge = { ...identity, requestId: `sast-dom-pending:${++this.serial}` }, bytes = headerBytes(payload, this.store.limits.resourceBytes)
        if (!this.store.stage(charge, 'chunks', bytes).ok) { this._gap([owner], 'sast_dom_push_failed', identity); return false }
        const revision = owner.revision, config = owner.sastState
        // Once the browser has authenticated an early candidate, navigation
        // must not erase its already-copied DOM before the queued analysis runs.
        // Ordinary live snapshots retain their stricter current-document gate.
        const current = acceptedCandidate
            ? () => this._valid(owner) && !owner.target.lost && owner.sastState === config && config.isActive()
            : () => this._valid(owner) && !owner.target.lost && this._collectionAllowed(owner, identity, true)
                && this._documents(owner).some(item => ['frameId', 'documentId', 'sessionGeneration', 'navigationGeneration'].every(key => item[key] === identity[key]) && (item.sessionId || '') === (identity.sessionId || ''))
        let released = false
        const batch = Object.freeze({ identity, payload, browserDocument: acceptedCandidate,
            get active() { return !released && owner.revision === revision && current() && nativeCurrent() },
            release: () => { if (released) return; released = true; owner.sastBatches.delete(batch); this.store.unstage(charge, 'chunks') } })
        owner.sastBatches ||= new Set(); owner.sastBatches.add(batch)
        try { owner.sastPayloadListener(batch) } catch (_) { batch.release(); this._gap([owner], 'sast_dom_push_failed', identity); return false }
        const obligation = owner.sastDomDocuments?.get(sastDocumentKey(identity))
        if (obligation) obligation.received = true
        return true
    }

    async _drain(owner) {
        if (!this._valid(owner)) return { complete: false, reason: 'owner_unavailable' }
        await owner.target.tail
        const skipDeferred = owner.frozen && !owner.capabilities.has('sources')
            && (owner.capabilities.has('recording') || owner.capabilities.has('authBodies'))
            ? record => {
                if (!this._valid(owner) || !owner.frozen || record.tabId !== owner.tabId) return false
                const normalized = { ...record, epoch: this.epoch }, key = captureIdentity(normalized)
                const entry = this.store.records.get(key)
                // A pending body ref is the admission witness. Network-only
                // observations deliberately establish no body-loss obligation.
                if (entry?.refs.has(owner.id)) {
                    // A conflicting or already-complete witness is not an
                    // unselected owner: retain its ordinary drainage contract.
                    if (entry.complete || !['tabId', 'sessionId', 'requestId', 'hop', 'frameId', 'documentId', 'loaderId', 'sessionGeneration', 'navigationGeneration', 'url', 'documentUrl', 'method', 'resourceType']
                        .every(field => entry.record[field] === normalized[field])
                        || !this._allowed(owner, normalized, true)) return false
                    this.store.consume(key, owner.id)
                    owner.deferredBodyIncomplete = true
                    this._gap([owner], 'response_body_unavailable', normalized)
                }
                return true
            } : undefined
        await this.adapter.drain(owner.tabId, skipDeferred ? { skipDeferred } : undefined)
        for (const grant of [...owner.retiredSources || []]) if (owner.frozen || !this._retiredData(owner, grant)) this._flushRetiredSources(owner, owner.frozen)
        while (owner.collections.size) await Promise.allSettled([...owner.collections])
        // Freeze rejects new admission, not completion of already accepted
        // native reads. Seal final sources only after those reads have drained.
        if (owner.frozen && !owner.sourceFinalSealed) {
            owner.sourceFinalSealed = true
            for (const identity of this._documents(owner)) this._sealSourceBatch(owner, identity, 'final')
        }
        while (owner.deliveries.size) await Promise.all([...owner.deliveries])
        const unresolved = owner.capabilities.has('recording') && [...this.headers.values()].some(chain => chain.owners.some(item => item.owner === owner) && (chain.suppressed || chain.queues.some(queue => queue.length) || chain.hops.some(hop => hop.flag === undefined || hop.flag && hop.seen.some(seen => !seen))))
        if (owner.capabilities.has('recording') && owner.frozen) {
            if (unresolved || owner.headerFailed) { owner.headerFailed = true; this._gap([owner], 'header_correlation_incomplete'); while (owner.deliveries.size) await Promise.all([...owner.deliveries]) }
        }
        return { complete: this._valid(owner) && !owner.target.lost && !owner.deliveryFailed && !owner.headerFailed && !owner.deferredBodyIncomplete, ...(owner.capabilities.has('recording') ? { headersComplete: !unresolved && !owner.headerFailed } : {}), gaps: owner.gapCount, reason: owner.target.lost ? 'capture_detached' : owner.deliveryFailed ? 'consumer_delivery_failed' : owner.headerFailed ? 'header_correlation_incomplete' : owner.deferredBodyIncomplete ? 'response_body_unavailable' : undefined }
    }

    _armPrepared(owner) {
        owner.preparedDeadline = this.now() + PREPARED_TTL_MS
        owner.preparedTimer = setTimeout(() => { this._release(owner, 'prepared_expired').catch(() => {}) }, PREPARED_TTL_MS)
        owner.preparedTimer.unref?.()
    }

    _release(owner, reason) {
        if (!owner.active) return owner.releasePromise || Promise.resolve()
        const stateStop = owner.sastState ? this._setSastState(owner, { active: false }) : Promise.resolve()
        this._clearPendingSastDom(owner)
        owner.active = false
        for (const batch of [...owner.sastBatches || []]) batch.release()
        for (const obligation of owner.sastDomDocuments?.values() || []) {
            if (obligation.analysisReceipt) { obligation.analysisReceipt.current = false; this._disposeAnalysisReceipt(obligation.analysisReceipt) }
            if (obligation.analysisFailure) { obligation.analysisFailure.current = false; this._disposeAnalysisReceipt(obligation.analysisFailure) }
            if (obligation.sourceAcquisition) { obligation.sourceAcquisition.current = false; this._disposeAnalysisReceipt(obligation.sourceAcquisition) }
            this.store.unstage(obligation.charge, 'metadata')
        }
        owner.sastDomDocuments?.clear()
        owner.sastPayloadListener = null
        this._revokeSourceBatches(owner)
        this._revokeRetiredSources(owner)
        owner.sourceBatchListener = null
        owner.abortCleanup?.()
        owner.releaseReason = reason
        clearTimeout(owner.preparedTimer)
        owner.ready = false
        owner.revision++
        owner.listeners.clear()
        this.owners.delete(owner.key)
        owner.target.owners.delete(owner)
        this.store.release(owner.id)
        this._forgetHeaderOwner(owner)
        owner.releasePromise = this._queue(owner.target, async () => {
            let stateError
            try { await stateStop } catch (error) { stateError = error }
            if (owner.target.owners.size) {
                if (!owner.target.lost) await this.adapter.configure(owner.tabId, this._capabilities(owner.target))
            } else {
                await this.adapter.release(owner.tabId)
                if (this.targets.get(owner.tabId) === owner.target && !owner.target.owners.size) {
                    owner.target.frames.clear()
                    owner.target.primaryFrame = undefined
                    owner.target.retirementRequested = true
                    this._retireTarget(owner.target)
                }
                // Detached targets can still have deferred CDP reads holding
                // job metadata. Only physical adapter releasehooks may debit
                // staging; target release does not imply those jobs are freed.
            }
            if (stateError) throw stateError
        })
        return owner.releasePromise
    }

    _retireTarget(target) {
        // H2 operation identity is single-use for the lifetime of its native
        // helper tab. Keep only the empty exclusivity marker until native close.
        if (this.targets.get(target.tabId) === target && !target.owners.size && !target.pendingOperations
            && (!target.h2HelperUsed || target.closed)) this.targets.delete(target.tabId)
    }

    releaseOwner(ownerId, tabId, reason) {
        const owner = this.owners.get(JSON.stringify([ownerId, tabId]))
        return owner ? this._release(owner, reason) : Promise.resolve()
    }
}

export default BrowserCaptureManager
