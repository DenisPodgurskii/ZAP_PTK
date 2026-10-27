const RESOURCE_BYTES = 8 * 1024 * 1024
const TAB_BYTES = 32 * 1024 * 1024
const METADATA_BYTES = 64 * 1024
const SAST_PUSH_BINDING = '__ptkSastDomPush'
// Native ownership bookkeeping only: never calls the content producer.
const SAST_PUSH_OWN = `function(id, origin) {
    if (chrome.runtime.id !== id || chrome.runtime.getURL('') !== origin || typeof globalThis.__ptkSastDomPush !== 'function') return false;
    const owned = globalThis.__PTK_SAST_PUSH_OWNED_BINDING__;
    if (owned && owned !== globalThis.__ptkSastDomPush) return false;
    globalThis.__PTK_SAST_PUSH_OWNED_BINDING__ = globalThis.__ptkSastDomPush;
    return true;
}`
const SAST_PUSH_REMOVE = `function(id, origin, revision) {
    if (chrome.runtime.id !== id || chrome.runtime.getURL('') !== origin) return false;
    if (globalThis.__PTK_SAST_CONTENT_STATE__?.revision > revision) return false;
    globalThis.__PTK_SAST_CONTENT_STATE__ = { active: false, revision, transport: 'cdp' };
    if (!Object.hasOwn(globalThis,'__ptkSastDomPush')) return true;
    if (globalThis.__PTK_SAST_PUSH_OWNED_BINDING__ !== globalThis.__ptkSastDomPush) return false;
    const deleted = delete globalThis.__ptkSastDomPush;
    delete globalThis.__PTK_SAST_PUSH_OWNED_BINDING__;
    delete globalThis.__PTK_SAST_PUSH_READY_REVISION__;
    return deleted && !Object.hasOwn(globalThis,'__ptkSastDomPush');
}`
const SAST_PUSH_BOOTSTRAP = `function(id, origin, revision) {
    if (chrome.runtime.id !== id || chrome.runtime.getURL('') !== origin) return false;
    if (typeof globalThis.__ptkSastDomPush !== 'function') return false;
    const owned = globalThis.__PTK_SAST_PUSH_OWNED_BINDING__;
    if (owned && owned !== globalThis.__ptkSastDomPush) return false;
    globalThis.__PTK_SAST_PUSH_OWNED_BINDING__ = globalThis.__ptkSastDomPush;
    globalThis.PTK_CONTENT_SHARED?.initializeSastContentPush?.();
    if (globalThis.__PTK_SAST_PUSH_READY_REVISION__ !== revision && typeof globalThis.PTK_CONTENT_SHARED?.setSastContentState === 'function') {
        globalThis.__PTK_SAST_PUSH_READY_REVISION__ = revision;
        globalThis.__ptkSastDomPush(JSON.stringify({type:'producer_ready'}));
    }
    return true;
}`
const SAST_PUSH_STATE = `function(id, origin, state) {
    if (chrome.runtime.id !== id || chrome.runtime.getURL('') !== origin) return false;
    const prior = globalThis.__PTK_SAST_CONTENT_STATE__;
    if (prior && prior.revision > state.revision) return false;
    const hasReceiver = typeof globalThis.PTK_CONTENT_SHARED?.setSastContentState === 'function';
    const accepted = hasReceiver ? globalThis.PTK_CONTENT_SHARED.setSastContentState(state) : !state.active;
    if (!hasReceiver) globalThis.__PTK_SAST_CONTENT_STATE__ = state;
    return accepted;
}`
// Inert capability check in an already native-admitted extension world only.
const PROBE_SAST_COLLECTOR = `function(id, origin) {
    try { return { runtimeIdentity: globalThis.chrome?.runtime?.id === id && chrome.runtime.getURL('') === origin,
        collector: typeof globalThis.PTK_CONTENT_SHARED?.collectSastPayload === 'function' }; }
    catch (_) { return { runtimeIdentity: false, collector: false }; }
}`
// Fixed isolated-world operation: callers cannot supply executable code.
const COLLECT_SAST = `async function(id, origin) {
    if (chrome.runtime.id !== id || chrome.runtime.getURL('') !== origin ||
        typeof globalThis.PTK_CONTENT_SHARED?.collectSastPayload !== 'function') throw new Error('capture_context_unavailable');
    const payload = await globalThis.PTK_CONTENT_SHARED.collectSastPayload();
    if (chrome.runtime.id !== id || chrome.runtime.getURL('') !== origin) throw new Error('capture_context_unavailable');
    return payload;
}`

// DAST-only operation, never caller-supplied code or an application-world
// bridge. An openerless blank is NOT cookie isolation: normal Fetch policy,
// credentials, CORS and redirects remain in force. A private remote controller
// lets release cancel this one fetch without page globals or caller code.
const H2_CONTROLLER = `function() {
    if (location.href !== 'about:blank' || globalThis.origin !== 'null' || window.opener !== null)
        throw new Error('capture_helper_unavailable');
    return new AbortController();
}`
const H2_ABORT = `function() { this.abort(); }`
const H2_OPERATION_TIMEOUT_MS = 15000 // existing privileged-operation budget
const H2_FETCH = `async function(request, limit, timeoutMs) {
    const assertBlank = () => {
        if (location.href !== 'about:blank' || globalThis.origin !== 'null' || window.opener !== null)
            throw new Error('capture_helper_unavailable');
    };
    let failure = 'capture_h2_fetch_failed', reader, timer;
    const fail = code => { failure = code; throw new Error(code); };
    try {
    assertBlank();
    timer = setTimeout(() => { failure = 'capture_helper_timeout'; this.abort(); }, timeoutMs);
    const response = await fetch(request.url, {
        method: request.method, headers: request.headers, body: request.body,
        credentials: request.credentials, redirect: request.followRedirect ? 'follow' : 'manual', cache: 'no-cache', signal: this.signal
    });
    let retained = 256 + (response.statusText || '').length * 2, wireBytes = 0, body = '';
    const headers = [];
    for (const [name, value] of response.headers.entries()) {
        retained += 64 + (name.length + value.length) * 2;
        if (retained > limit) fail('capture_helper_budget_exceeded');
        headers.push({ name, value });
    }
    if (retained > limit) fail('capture_helper_budget_exceeded');
    if (response.body) {
        reader = response.body.getReader();
        const decoder = new TextDecoder();
        while (true) {
            const chunk = await reader.read();
            if (this.signal.aborted) throw new Error('capture_cancelled');
            if (chunk.done) break;
            wireBytes += chunk.value.byteLength;
            if (wireBytes > limit) fail('capture_helper_budget_exceeded');
            const text = decoder.decode(chunk.value, { stream: true });
            retained += text.length * 2;
            if (retained > limit) fail('capture_helper_budget_exceeded');
            body += text;
        }
        const tail = decoder.decode();
        retained += tail.length * 2;
        if (retained > limit) fail('capture_helper_budget_exceeded');
        body += tail;
    }
    assertBlank();
    return { status: response.status, statusText: response.statusText || '',
        headers, body };
    } catch (_) {
        this.abort();
        if (reader) { try { await reader.cancel(); } catch (_) {} }
        return { captureError: failure };
    } finally {
        clearTimeout(timer);
        if (reader) reader.releaseLock();
    }
}`

// Stop sizing as soon as the bound is crossed; never stringify an unbounded
// protocol payload merely to decide whether it can be retained.
function metadataSize(value, limit = METADATA_BYTES, seen = new Set()) {
    if (typeof value === 'string') return value.length * 2
    if (!value || typeof value !== 'object') return 8
    if (seen.has(value)) return 0
    seen.add(value)
    if (ArrayBuffer.isView(value)) return value.byteLength
    if (value instanceof ArrayBuffer) return value.byteLength
    let bytes = 32
    for (const key in value) {
        bytes += key.length * 2 + metadataSize(value[key], limit - bytes, seen)
        if (bytes > limit) break
    }
    return bytes
}

// The manager owns admission and retention; this adapter owns only the browser
// connection, bounded pending reads and protocol identities.
export class ChromiumCaptureAdapter {
    constructor({ chrome = globalThis.chrome, maxResourceBytes = RESOURCE_BYTES, maxTabBytes = TAB_BYTES, h2OperationTimeoutMs = H2_OPERATION_TIMEOUT_MS } = {}) {
        this.chrome = chrome
        this.supportsExtraInfo = true
        this.supportsH2HelperMetadata = true
        this.supportsRetiredSources = true
        this.supportsBrowserSastDocument = true
        this.maxResourceBytes = maxResourceBytes
        this.maxTabBytes = maxTabBytes
        this.h2OperationTimeoutMs = h2OperationTimeoutMs
        this.tabs = new Map()
        this.sink = () => {}
        this.admit = () => false
        this.jobs = []
        this.running = 0
        this.waiters = []
        this.budget = { retain: () => ({ ok: true }), release: () => {} }
        this.budgetSerial = 0
        this.generation = 0
        this.extensionOrigin = chrome.runtime?.getURL?.('')
        // Detached H2 helpers retain only their one-use marker until the owned
        // native tab closes. Ordinary released targets need no tombstones.
        chrome.tabs?.onRemoved?.addListener(tabId => this._emit('tabClosed', { tabId }))
        chrome.debugger.onEvent.addListener((source, method, params) => this._event(source, method, params))
        chrome.debugger.onDetach.addListener((source, reason) => {
            const state = this.tabs.get(source.tabId)
            if (!state) return
            state.alive = false
            this._freeMetadata(state)
            this.tabs.delete(source.tabId)
            this._emit('detach', { tabId: source.tabId, reason, complete: false })
        })
    }

    setEventSink(fn) { this.sink = fn }
    setAdmission(fn) { this.admit = fn }
    setBudgetHooks(hooks) { this.budget = hooks }
    async getBrowserSastDocument(sender) {
        const tabId = sender?.tab?.id, documentId = sender?.documentId
        if (!Number.isInteger(tabId) || tabId < 0 || sender?.frameId !== 0
            || typeof documentId !== 'string' || !documentId
            || sender?.documentLifecycle !== 'active' || typeof sender?.url !== 'string'
            || !/^https?:\/\//i.test(sender.url) || !this.chrome?.webNavigation?.getFrame) return null
        let frame
        try { frame = await this.chrome.webNavigation.getFrame({ tabId, frameId: 0, documentId }) }
        catch (_) { return null }
        // getFrame validates the supplied tab/frame against documentId; its
        // result deliberately has no frameId field. Do not join to CDP by URL.
        if (!frame || frame.documentId !== documentId || frame.documentLifecycle !== 'active'
            || frame.parentFrameId !== -1 || frame.url !== sender.url) return null
        return { tabId, frameId: 0, documentId, url: frame.url }
    }
    _reserveBudget(record, kind, bytes, unavailableRecord = record) {
        const result = this.budget.retain(record, kind, bytes)
        if (!result.ok) this._emit('gap', { ...unavailableRecord, reason: result.reason, complete: false })
        return result.ok
    }
    _freeMetadata(state) {
        this._clearH2Operation(state)
        for (const child of state.childStates.values()) this._revokeChild(state, child, false)
        state.childStates.clear()
        for (const record of state.identityBudget.values()) this.budget.release(record, 'metadata')
        state.identityBudget.clear()
        for (const key of [...state.requests.keys()]) this._dropRequest(state, key)
        state.frames.clear(); state.children.clear()
        state.contexts.clear()
        state.sastPush = null
        state.sastGrants?.clear(); state.sastBindings?.clear()
    }
    _emit(type, record, extra = {}) {
        const state = this.tabs.get(record.tabId)
        this.sink({ type, record: { ...record, sessionGeneration: record.sessionGeneration ?? state?.sessionGenerations.get(record.sessionId || '') }, ...extra })
    }
    _call(source, method, params = {}) {
        return new Promise((resolve, reject) => this.chrome.debugger.sendCommand(source, method, params, result => {
            const error = this.chrome.runtime?.lastError
            if (error) reject(new Error('capture_protocol_command_failed'))
            else resolve(result || {})
        }))
    }
    async send(tabId, method, params = {}, sessionId) {
        const state = this.tabs.get(tabId)
        if (!state?.alive) throw new Error('capture_not_attached')
        const child = sessionId ? state.childStates.get(sessionId) : undefined
        const valid = () => this.tabs.get(tabId) === state && state.alive && (!sessionId || child?.ready && this._childCurrent(state, child) && state.children.has(sessionId))
        if (!valid()) throw new Error('capture_session_unavailable')
        const result = await this._call({ tabId, ...(sessionId ? { sessionId } : {}) }, method, params)
        if (!valid()) throw new Error('capture_session_unavailable')
        return result
    }
    async configure(tabId, capabilities) {
        let state = this.tabs.get(tabId)
        if (!state) {
            state = { tabId, alive: true, attached: false, capabilities: new Set(), requests: new Map(), frames: new Map(), contexts: new Map(), runtimeEnabled: false, children: new Set(), childStates: new Map(), sessionGenerations: new Map([['', ++this.generation]]), identityBudget: new Map(), pendingBytes: 0, requestBytes: 0, identityBytes: 0, pendingJobs: 0 }
            this.tabs.set(tabId, state)
            state.attach = new Promise((resolve, reject) => this.chrome.debugger.attach({ tabId }, '1.3', () => {
                if (this.chrome.runtime?.lastError) reject(new Error('capture_attach_failed'))
                else { state.attached = true; resolve() }
            }))
        }
        try { await state.attach } catch (error) { if (this.tabs.get(tabId) === state) this.tabs.delete(tabId); throw error }
        if (!state.alive) throw new Error('capture_detached')
        const previous = state.capabilities
        state.capabilities = new Set(capabilities)
        try {
            await this._configureSession(state, undefined, capabilities, previous)
            for (const child of [...state.childStates.values()]) {
                await child.setup
                if (this._childCurrent(state, child)) await this._configureChild(state, child, capabilities)
            }
            state.capabilities = new Set(capabilities)
        } catch (error) {
            state.capabilities = previous
            if (previous.size) {
                // Best-effort rollback only of domains changed by this upgrade.
                // Never resume a pause or detach an established consumer.
                try { await this._configureSession(state, undefined, previous, capabilities) } catch { /* original failure remains authoritative */ }
                for (const child of [...state.childStates.values()]) {
                    try { await child.setup; if (this._childCurrent(state, child)) await this._configureChild(state, child, previous) } catch { /* child may have exited */ }
                }
            }
            state.capabilities = previous
            // A failed first acquisition owns its successful attach, but a failed
            // upgrade must not detach the consumers already using it.
            if (!previous.size && state.attached && this.tabs.get(tabId) === state) await this.release(tabId)
            else if (!state.attached) this.tabs.delete(tabId)
            throw error
        }
    }
    async _configureSession(state, sessionId, next, previous, child) {
        const source = { tabId: state.tabId, ...(sessionId ? { sessionId } : {}) }
        const call = async (method, params) => {
            if (!state.alive || this.tabs.get(state.tabId) !== state) throw new Error('capture_session_unavailable')
            if (child && !this._childCurrent(state, child)) throw new Error('capture_session_unavailable')
            const result = await this._call(source, method, params)
            if (!child && (!state.alive || this.tabs.get(state.tabId) !== state)) throw new Error('capture_session_unavailable')
            if (child) {
                child.acknowledged.add(method)
                if (method === 'Network.setCacheDisabled') child.cacheDisabled = params.cacheDisabled
                if (!this._childCurrent(state, child)) throw new Error('capture_session_unavailable')
            }
            return result
        }
        if (next.size && !previous.size) {
            await call('Network.enable', { maxResourceBufferSize: this.maxResourceBytes, maxTotalBufferSize: this.maxTabBytes })
        }
        if (next.has('sources') && !previous.has('sources')) {
            // Browser-owned bounded response storage survives renderer replacement.
            // Readiness fails closed if this reviewed native command is unavailable.
            await call('Network.configureDurableMessages', { maxResourceBufferSize: this.maxResourceBytes, maxTotalBufferSize: this.maxTabBytes })
        }
        if (next.size && !previous.size) {
            await call('Page.enable')
            const tree = await call('Page.getFrameTree')
            const walk = node => { if (!node || child && !this._childCurrent(state, child)) return; if (child) this._queueChildEvent(state, child, source, 'Page.frameNavigated', { frame: node.frame }); else this._frame(state, node.frame, sessionId); (node.childFrames || []).forEach(walk) }
            walk(tree.frameTree)
            await call('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true, filter: [{ type: 'iframe', exclude: false }, { exclude: true }] })
        }
        if (next.has('recording') !== previous.has('recording')) {
            await call('Network.setCacheDisabled', { cacheDisabled: next.has('recording') })
            if (!sessionId) state.cacheDisabled = next.has('recording')
        }
        const runtime = child || state
        if (next.has('sources') && !runtime.runtimeEnabled) {
            // Accept replayed identities during enable, but never collect before ACK.
            runtime.runtimeObserving = true
            try {
                await call('Runtime.enable'); runtime.runtimeEnabled = true
                if (!state.alive || this.tabs.get(state.tabId) !== state) throw new Error('capture_session_unavailable')
            }
            catch (error) { runtime.runtimeObserving = false; this._clearContexts(state, sessionId); throw error }
        } else if (!next.has('sources') && runtime.runtimeEnabled) {
            runtime.runtimeObserving = false
            this._clearContexts(state, sessionId)
            await call('Runtime.disable'); runtime.runtimeEnabled = false
        }
        if (next.has('sources') && runtime.runtimeEnabled) runtime.runtimeObserving = true
    }

    _childCurrent(state, child) {
        if (!state.alive || state.childStates.get(child.sessionId) !== child || child.revoked) return false
        if (!child.parentSessionId) return state.sessionGenerations.get('') === child.parentGeneration
        const parent = state.childStates.get(child.parentSessionId)
        return parent?.generation === child.parentGeneration && this._childCurrent(state, parent)
    }
    _freeChildQueue(state, child) {
        for (const event of child.queue.splice(0)) {
            state.pendingBytes -= event.bytes; child.queueBytes -= event.bytes
            this.budget.release(event.budgetRecord, 'metadata')
        }
    }
    _revokeChild(state, child, report = true) {
        if (child.revoked) return
        child.revoked = true; child.ready = false
        this._clearContexts(state, child.sessionId)
        for (const [key, binding] of state.sastBindings || []) if (binding.sessionId === child.sessionId) this._identityDelete(state, state.sastBindings, key)
        state.children.delete(child.sessionId)
        for (const descendant of [...state.childStates.values()]) if (descendant.parentSessionId === child.sessionId && descendant.parentGeneration === child.generation && !descendant.revoked) {
            if (!descendant.configuring) {
                descendant.cleaning = true; state.pendingJobs++
                this._revokeChild(state, descendant, report || state.alive)
                this._rollbackChild(state, descendant).finally(() => {
                    if (state.childStates.get(descendant.sessionId) === descendant) { state.childStates.delete(descendant.sessionId); state.sessionGenerations.delete(descendant.sessionId) }
                    descendant.cleaning = false; this._releaseChildCharge(state, descendant)
                    state.pendingJobs--; this._notifyWaiters()
                })
            } else this._revokeChild(state, descendant, report || state.alive)
        }
        this._freeChildQueue(state, child)
        for (const [key, record] of state.requests) if (record.sessionId === child.sessionId && record.sessionGeneration === child.generation) this._dropRequest(state, key)
        for (const [frameId, frame] of [...state.frames]) if (frame.sessionId === child.sessionId && frame.sessionGeneration === child.generation) this._identityDelete(state, state.frames, frameId)
        if (report) this._emit('invalidate', { tabId: state.tabId, sessionId: child.sessionId, sessionGeneration: child.generation, reason: 'child_domains_failed', complete: false })
        if (!child.configuring && !child.cleaning) this._releaseChildCharge(state, child)
    }
    _releaseChildCharge(state, child) {
        if (!child.bytes) return
        state.pendingBytes -= child.bytes; child.bytes = 0
        this.budget.release(child.budgetRecord, 'metadata')
    }
    async _rollbackChild(state, child) {
        // An ACK belonging to an exited/replaced incarnation is not authority
        // to send commands to the replacement using the same raw session ID.
        if (!state.alive || state.childStates.get(child.sessionId) !== child || child.detached) return
        const source = { tabId: state.tabId, sessionId: child.sessionId }
        const commands = []
        if (child.acknowledged.has('Runtime.enable')) commands.push(['Runtime.disable', {}])
        if (child.cacheDisabled) commands.push(['Network.setCacheDisabled', { cacheDisabled: false }])
        if (child.acknowledged.has('Target.setAutoAttach')) commands.push(['Target.setAutoAttach', { autoAttach: false, waitForDebuggerOnStart: false, flatten: true }])
        if (child.acknowledged.has('Page.enable')) commands.push(['Page.disable', {}])
        if (child.acknowledged.has('Network.enable')) commands.push(['Network.disable', {}])
        for (const [method, params] of commands) {
            if (!state.alive || state.childStates.get(child.sessionId) !== child || child.detached) break
            try { await this._call(source, method, params) } catch { /* original setup failure remains authoritative */ }
        }
    }
    _queueChildEvent(state, child, source, method, params) {
        if (!this._childCurrent(state, child)) return false
        const payloadBytes = metadataSize(params)
        const bytes = payloadBytes + metadataSize(source) + method.length * 2 + 512 + child.sessionId.length * 4
        const budgetRecord = { tabId: state.tabId, sessionId: child.sessionId, sessionGeneration: child.generation, requestId: `capture-child-event:${++this.budgetSerial}` }
        if (payloadBytes > METADATA_BYTES || child.queueBytes + child.bytes + bytes > this.maxResourceBytes || state.identityBytes + state.requestBytes + state.pendingBytes + bytes > this.maxTabBytes || !this.budget.retain(budgetRecord, 'metadata', bytes).ok) {
            this._revokeChild(state, child)
            return false
        }
        state.pendingBytes += bytes; child.queueBytes += bytes
        child.queue.push({ source: { ...source }, method, params, bytes, budgetRecord })
        return true
    }
    async _configureChild(state, child, capabilities) {
        if (!this._childCurrent(state, child)) return
        child.configuring = true
        child.ready = false; state.children.delete(child.sessionId)
        try {
            let next = new Set(capabilities)
            do {
                await this._configureSession(state, child.sessionId, next, child.capabilities, child)
                child.capabilities = next
                // A root capability transaction can advance while an initial
                // child ACK is pending. Catch up before flushing any first input.
                next = new Set(state.capabilities)
            } while ([...next].some(capability => !child.capabilities.has(capability)) || [...child.capabilities].some(capability => !next.has(capability)))
            if (!this._childCurrent(state, child)) throw new Error('capture_session_unavailable')
            child.ready = true; state.children.add(child.sessionId)
            // Transfer each queue entry synchronously only after every domain,
            // recursive-target and Recorder cache-policy ACK has succeeded.
            while (child.queue.length && this._childCurrent(state, child)) {
                const event = child.queue.shift()
                this._event(event.source, event.method, event.params)
                state.pendingBytes -= event.bytes; child.queueBytes -= event.bytes
                this.budget.release(event.budgetRecord, 'metadata')
            }
        } catch (error) {
            this._revokeChild(state, child)
            await this._rollbackChild(state, child)
            if (state.childStates.get(child.sessionId) === child) { state.childStates.delete(child.sessionId); state.sessionGenerations.delete(child.sessionId) }
            throw error
        } finally { child.configuring = false; if (child.revoked) this._releaseChildCharge(state, child) }
    }
    _startChild(state, sessionId, parentSessionId = '') {
        const parent = parentSessionId ? state.childStates.get(parentSessionId) : undefined
        if (parentSessionId && (!parent?.ready || !this._childCurrent(state, parent)) || sessionId === parentSessionId) return
        for (let ancestor = parent; ancestor; ancestor = ancestor.parentSessionId ? state.childStates.get(ancestor.parentSessionId) : undefined) if (ancestor.sessionId === sessionId) return
        const previous = state.childStates.get(sessionId)
        if (previous) { previous.detached = true; this._revokeChild(state, previous); state.childStates.delete(sessionId); state.sessionGenerations.delete(sessionId) }
        if (parentSessionId && (!parent?.ready || !this._childCurrent(state, parent))) return
        const generation = ++this.generation
        const parentGeneration = parent?.generation ?? state.sessionGenerations.get('')
        const child = { sessionId, generation, parentSessionId, parentGeneration, ready: false, revoked: false, queue: [], queueBytes: 0, capabilities: new Set(), acknowledged: new Set(), budgetRecord: { tabId: state.tabId, sessionId, sessionGeneration: generation, requestId: `capture-child:${generation}` } }
        const bytes = 576 + sessionId.length * 2 + parentSessionId.length * 2
        if (state.identityBytes + state.requestBytes + state.pendingBytes + bytes > this.maxTabBytes || !this.budget.retain(child.budgetRecord, 'metadata', bytes).ok) { this._emit('invalidate', { tabId: state.tabId, sessionId, sessionGeneration: generation, reason: 'child_domains_failed', complete: false }); return }
        child.bytes = bytes; state.pendingBytes += bytes; state.pendingJobs++
        state.childStates.set(sessionId, child); state.sessionGenerations.set(sessionId, generation)
        child.setup = this._configureChild(state, child, new Set(state.capabilities)).catch(() => {}).finally(() => {
            state.pendingJobs--
            this._notifyWaiters()
        })
    }
    async release(tabId) {
        const state = this.tabs.get(tabId)
        if (!state) return
        state.alive = false
        state.runtimeObserving = false
        this._freeMetadata(state)
        this.tabs.delete(tabId)
        if (!state.attached) return
        if (state.runtimeEnabled) {
            try { await this._call({ tabId }, 'Runtime.disable') } catch { /* detached */ }
            state.runtimeEnabled = false
        }
        if (state.cacheDisabled) {
            try { await this._call({ tabId }, 'Network.setCacheDisabled', { cacheDisabled: false }) } catch { /* detached */ }
        }
        await new Promise(resolve => this.chrome.debugger.detach({ tabId }, () => { void this.chrome.runtime?.lastError; resolve() }))
    }
    getSnapshot(tabId) {
        const state = this.tabs.get(tabId)
        return { frames: state ? [...state.frames.values()].map(frame => ({ ...frame })) : [], contexts: [], capabilities: [...(state?.capabilities || [])] }
    }
    _clearContexts(state, sessionId, frameId) {
        for (const [key, context] of state.contexts) if ((context.sessionId || '') === (sessionId || '') && (frameId === undefined || context.frameId === frameId)) this._identityDelete(state, state.contexts, key)
    }
    _contextEvent(state, sessionId, method, params) {
        this._h2ContextEvent(state, sessionId, method, params)
        const runtime = sessionId ? state.childStates.get(sessionId) : state
        if (!runtime?.runtimeObserving) return
        if (method === 'Runtime.executionContextsCleared') { this._clearContexts(state, sessionId); runtime.sastContextInventoryIncomplete = false; return }
        if (method === 'Runtime.executionContextDestroyed') {
            for (const [key, context] of state.contexts) if ((context.sessionId || '') === (sessionId || '') && (params.executionContextUniqueId ? context.uniqueId === params.executionContextUniqueId : context.contextId === params.executionContextId)) this._identityDelete(state, state.contexts, key)
            return
        }
        if (method === 'Runtime.bindingCalled') { this._sastBindingCalled(state, sessionId, params); return }
        if (method !== 'Runtime.executionContextCreated') return
        if (metadataSize(params) > METADATA_BYTES) { runtime.sastContextInventoryIncomplete = true; return }
        const context = params.context, frame = state.frames.get(context?.auxData?.frameId)
        if (Number.isInteger(context?.id)) this._identityDelete(state, state.contexts, JSON.stringify([sessionId || '', context.id]))
        if (!context || !Number.isInteger(context.id) || typeof context.uniqueId !== 'string' || !context.uniqueId || context.uniqueId.length > 2048 || !this.extensionOrigin || context.origin !== this.extensionOrigin.replace(/\/$/, '') || context.auxData?.isDefault !== false || context.auxData?.type !== 'isolated' || !frame?.documentId || (frame.sessionId || '') !== (sessionId || '')) return
        const key = JSON.stringify([sessionId || '', context.id])
        // Reuse cannot lend the earlier incarnation's unique identity.
        this._identityDelete(state, state.contexts, key)
        if (state.contexts.size >= 1024) { runtime.sastContextInventoryIncomplete = true; return }
        const name = typeof context.name === 'string' && context.name.length > 0 && context.name.length <= 256 ? context.name : null
        // Namespace ownership is name-wide, unlike DOM authority. Retain exact
        // extension realms outside source scope for inert collision/cleanup
        // bookkeeping only; grants still require config.getIdentity below.
        const subscription = name && state.sastBindings?.get(JSON.stringify([sessionId || '', name]))
        if (!name || !this._identitySet(state, state.contexts, key, { ...frame, contextId: context.id, uniqueId: context.uniqueId, name,
            ...(subscription ? { sastBindingId: subscription.bindingId } : {}) })) runtime.sastContextInventoryIncomplete = true
        if (state.sastPush?.active) this._scheduleSastPush(state)
    }

    setSastState(tabId, config) {
        const state = this.tabs.get(tabId)
        if (!state?.alive) return Promise.resolve(false)
        if (state.sastPush?.active && config.active && state.sastPush.ownerId !== config.ownerId) throw new Error('capture_sast_owner_conflict')
        // Revocation is synchronous; queued binding events cannot borrow a new run.
        state.sastPush = config
        state.sastGrants ||= new Map()
        if (!config.active) for (const key of [...state.sastGrants.keys()]) this._identityDelete(state, state.sastGrants, key)
        // A suspended renderer must not hold revocation behind an earlier
        // activation call. Native binding cleanup is independent of the
        // notification receiver, whose monotonic revision rejects late state.
        return config.active ? this._scheduleSastPush(state) : this._syncSastPush(state, config)
    }

    refreshSastState(tabId) { const state = this.tabs.get(tabId); if (state?.sastPush?.active) return this._scheduleSastPush(state) }

    _scheduleSastPush(state) {
        state.sastPushDirty = true
        if (state.sastPushWork) return state.sastPushWork
        const task = Promise.resolve().then(async () => {
            do { state.sastPushDirty = false; await this._syncSastPush(state, state.sastPush) } while (state.sastPushDirty)
        })
        state.sastPushWork = task
        const config = state.sastPush
        task.catch(() => { if (state.sastPush === config && config?.active) this._emit('sastPushError', { tabId: state.tabId, reason: 'sast_push_unavailable', complete: false }, { ownerId: config.ownerId, revision: config.revision }) })
            .finally(() => { if (state.sastPushWork === task) state.sastPushWork = null; if (state.sastPushDirty) this._scheduleSastPush(state) })
        return task
    }

    async _syncSastPush(state, config) {
        if (!config || this.tabs.get(state.tabId) !== state || !state.alive || state.sastPush !== config) return false
        state.sastBindings ||= new Map()
        state.sastGrants ||= new Map()
        const contexts = [...state.contexts.values()]
        const nativeCurrent = context => this.tabs.get(state.tabId) === state && state.alive
            && state.contexts.get(JSON.stringify([context.sessionId || '', context.contextId])) === context
        const current = context => nativeCurrent(context) && state.sastPush === config
        const runtime = context => context.sessionId ? state.childStates.get(context.sessionId) : state
        const unavailable = context => {
            const target = runtime(context)
            if (target && target.sastUnavailableRevision !== config.revision) {
                target.sastUnavailableRevision = config.revision
                this._emit('sastPushError', { tabId: state.tabId, reason: 'sast_push_unavailable', complete: false }, { ownerId: config.ownerId, revision: config.revision })
            }
        }
        if (!config.active) {
            const owned = [...state.sastBindings.values()].flatMap(binding => binding.members || [])
            for (const member of owned) if (member.activated && current(member.context)) {
                const context = member.context
                this.send(state.tabId, 'Runtime.callFunctionOn', { functionDeclaration: SAST_PUSH_STATE,
                    uniqueContextId: context.uniqueId, arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin },
                        { value: { active: false, revision: config.revision, transport: 'cdp' } }], returnByValue: true }, context.sessionId).catch(() => {})
            }
            // Native installation/ownership is a physical lease operation,
            // unlike a content state receiver. Do not detach between addBinding
            // and capture of the exact function we are entitled to delete.
            const setups = await Promise.allSettled([...state.sastNativeSetups || []])
            let failed = setups.some(result => result.status === 'rejected')
            for (const binding of state.sastBindings.values()) {
                if (runtime(binding)?.sastContextInventoryIncomplete || binding.unownedInstallation) failed = true
                for (const member of binding.members || []) if (member.owned && current(member.context)) {
                const context = member.context
                const result = await this.send(state.tabId, 'Runtime.callFunctionOn', { functionDeclaration: SAST_PUSH_REMOVE,
                    uniqueContextId: context.uniqueId, arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin },
                        { value: config.revision }], returnByValue: true }, context.sessionId)
                if (result.exceptionDetails || result.result?.value !== true) failed = true
                }
            }
            for (const [key, binding] of state.sastBindings) {
                if (state.sastPush !== config) return false
                await this.send(state.tabId, 'Runtime.removeBinding', { name: SAST_PUSH_BINDING }, binding.sessionId)
                this._identityDelete(state, state.sastBindings, key)
            }
            if (failed) throw new Error('capture_sast_binding_cleanup_failed')
            return true
        }
        if (!config.isActive()) return false
        for (const [key, grant] of state.sastGrants) if (!current(grant.context) || !config.getIdentity(grant.context)) {
            this._identityDelete(state, state.sastGrants, key)
            if (current(grant.context)) this.send(state.tabId, 'Runtime.callFunctionOn', { functionDeclaration: SAST_PUSH_STATE,
                uniqueContextId: grant.context.uniqueId, arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin },
                    { value: { active: false, revision: config.nextRevision(), transport: 'cdp' } }], returnByValue: true }, grant.context.sessionId).catch(() => {})
        }
        const capabilities = new Map(), selected = new Set()
        const inventoryCurrent = () => state.contexts.size === contexts.length && contexts.every(nativeCurrent)
        // Decide the producer before setting up its namespace. A single valid
        // runtime with no shared receiver may be bootstrapped dormantly; an
        // ambiguous document never receives bootstrap or active state.
        for (const context of contexts) if (current(context) && config.getIdentity(context)) {
            const result = await this.send(state.tabId, 'Runtime.callFunctionOn', { functionDeclaration: PROBE_SAST_COLLECTOR,
                uniqueContextId: context.uniqueId, arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin }], returnByValue: true }, context.sessionId)
            if (!current(context) || !config.isActive()) return false
            if (!inventoryCurrent()) { state.sastPushDirty = true; return false }
            if (!result.exceptionDetails) capabilities.set(context, result.result?.value)
        }
        for (const context of capabilities.keys()) {
            const candidates = contexts.filter(item => item.frameId === context.frameId && item.documentId === context.documentId
                && item.sessionGeneration === context.sessionGeneration && (item.sessionId || '') === (context.sessionId || ''))
            const valid = candidates.filter(item => capabilities.get(item)?.runtimeIdentity === true)
            const collectors = valid.filter(item => capabilities.get(item)?.collector === true)
            if (collectors.length === 1) selected.add(collectors[0])
            else if (collectors.length === 0 && valid.length === 1) selected.add(valid[0])
            else unavailable(context)
        }
        const groups = new Map()
        for (const context of contexts) if (current(context) && context.name) {
            const bindingKey = JSON.stringify([context.sessionId || '', context.name])
            if (!groups.has(bindingKey)) groups.set(bindingKey, [])
            groups.get(bindingKey).push(context)
        }
        for (const [bindingKey, group] of groups) {
            const context = group.find(item => selected.has(item))
            if (!context) continue
            if (runtime(context)?.sastContextInventoryIncomplete) { unavailable(context); continue }
            let binding = state.sastBindings.get(bindingKey)
            let safe = true
            // V8 assigns by session+name, not by the context we probe. Every
            // current same-name realm must be safe before any new assignment.
            for (const item of group) {
                const probe = await this.send(state.tabId, 'Runtime.callFunctionOn', {
                    uniqueContextId: item.uniqueId,
                    functionDeclaration: `function(id, origin, name) { try { return { own: chrome.runtime.id === id && chrome.runtime.getURL('') === origin, collision: Object.hasOwn(globalThis,name), callable: typeof globalThis[name] === 'function', owned: typeof globalThis[name] === 'function' && globalThis.__PTK_SAST_PUSH_OWNED_BINDING__ === globalThis[name] }; } catch (_) { return null; } }`,
                    arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin }, { value: SAST_PUSH_BINDING }], returnByValue: true }, item.sessionId)
                if (!current(context) || !current(item) || !config.isActive()) return false
                if (!inventoryCurrent()) { state.sastPushDirty = true; return false }
                if (runtime(context)?.sastContextInventoryIncomplete) { safe = false; break }
                const prior = binding?.members?.find(member => member.context === item && member.owned)
                // A native creation event while this exact name subscription
                // exists proves automatic installation in the fresh realm.
                // It cannot authorize adopting an older pre-existing realm.
                const assignedOnCreation = binding?.installed && item.sastBindingId === binding.bindingId
                if (probe.exceptionDetails || probe.result?.value?.own !== true
                    || (binding ? prior ? probe.result.value.owned !== true
                        : !assignedOnCreation || probe.result.value.collision !== true || probe.result.value.callable !== true
                        : probe.result.value.collision !== false)) { safe = false; break }
            }
            if (!safe) {
                if (binding && group.some(item => item.sastBindingId === binding.bindingId && !binding.members.some(member => member.context === item && member.owned))) binding.unownedInstallation = true
                unavailable(context); continue
            }
            if (!binding) {
                binding = { ...context, sessionId: context.sessionId || '', bindingId: ++this.budgetSerial, installed: false,
                    members: group.map(item => ({ context: item, owned: false, activated: false })) }
                if (!this._identitySet(state, state.sastBindings, bindingKey, binding)) { unavailable(context); continue }
                // Reserve before dispatch so synchronous Stop can unsubscribe
                // an addBinding already in flight without waiting for it.
                state.sastNativeSetups ||= new Set()
                const setup = (async () => {
                    await this.send(state.tabId, 'Runtime.addBinding', { name: SAST_PUSH_BINDING, executionContextName: context.name }, context.sessionId)
                    binding.installed = true
                    if (this.tabs.get(state.tabId) !== state || !state.alive
                        || state.contexts.get(JSON.stringify([context.sessionId || '', context.contextId])) !== context) throw new Error('capture_context_unavailable')
                    for (const member of binding.members) {
                    const item = member.context
                    if (!nativeCurrent(item)) continue
                    const result = await this.send(state.tabId, 'Runtime.callFunctionOn', { functionDeclaration: SAST_PUSH_OWN,
                        uniqueContextId: item.uniqueId, arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin }], returnByValue: true }, item.sessionId)
                    if (result.exceptionDetails || result.result?.value !== true) throw new Error('capture_sast_binding_unavailable')
                    member.owned = true
                    }
                })()
                state.sastNativeSetups.add(setup)
                try { await setup } finally { state.sastNativeSetups.delete(setup) }
            }
            const missing = group.filter(item => !binding.members.some(member => member.context === item))
            if (missing.length) {
                const expanded = { ...binding, members: [...binding.members.filter(member => current(member.context)),
                    ...missing.map(item => ({ context: item, owned: false, activated: false }))] }
                if (!this._identitySet(state, state.sastBindings, bindingKey, expanded)) { runtime(context).sastContextInventoryIncomplete = true; unavailable(context); continue }
                binding = expanded
            }
            const capture = (async () => {
            for (const member of binding.members) if (!member.owned && nativeCurrent(member.context)) {
                const result = await this.send(state.tabId, 'Runtime.callFunctionOn', { functionDeclaration: SAST_PUSH_OWN,
                    uniqueContextId: member.context.uniqueId, arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin }], returnByValue: true }, member.context.sessionId)
                if (!nativeCurrent(member.context)) continue
                if (result.exceptionDetails || result.result?.value !== true) { safe = false; break }
                member.owned = true
            }
            })()
            state.sastNativeSetups ||= new Set()
            state.sastNativeSetups.add(capture)
            try { await capture } finally { state.sastNativeSetups.delete(capture) }
            if (!safe) { unavailable(context); continue }
            for (const context of group) {
            if (!selected.has(context) || !config.getIdentity(context)) continue
            if (!current(context) || !config.isActive()) return false
            // Shared may load before or after addBinding. This state-only call
            // announces the transport; producer_ready never grants authority.
            const bootstrap = await this.send(state.tabId, 'Runtime.callFunctionOn', { functionDeclaration: SAST_PUSH_BOOTSTRAP,
                uniqueContextId: context.uniqueId, arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin }, { value: config.revision }], returnByValue: true }, context.sessionId)
            if (!current(context) || !config.isActive()) return false
            if (bootstrap.exceptionDetails || bootstrap.result?.value !== true) throw new Error('capture_sast_binding_unavailable')
            if (!inventoryCurrent()) { state.sastPushDirty = true; return false }
            if (capabilities.get(context)?.collector !== true) continue
            const key = JSON.stringify([context.sessionId || '', context.contextId])
            const prior = state.sastGrants.get(key)
            if (prior?.context === context && prior.config === config) continue
            const revision = config.nextRevision()
            if (!this._identitySet(state, state.sastGrants, key, { ...context, context, config, revision })) throw new Error('capture_sast_binding_unavailable')
            const result = await this.send(state.tabId, 'Runtime.callFunctionOn', { functionDeclaration: SAST_PUSH_STATE,
                uniqueContextId: context.uniqueId, arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin },
                    { value: { active: true, revision, transport: 'cdp' } }], returnByValue: true }, context.sessionId)
            if (!current(context) || !config.isActive()) return false
            if (result.exceptionDetails || result.result?.value !== true) this._identityDelete(state, state.sastGrants, key)
            else {
                const member = binding.members.find(item => item.context === context)
                if (member) member.activated = true
            }
            }
        }
        return true
    }

    _sastBindingCalled(state, sessionId, params) {
        if (params.name !== SAST_PUSH_BINDING || typeof params.payload !== 'string' || params.payload.length * 2 > this.maxResourceBytes) return
        const key = JSON.stringify([sessionId || '', params.executionContextId]), context = state.contexts.get(key), config = state.sastPush
        if (!context || !config?.active || !config.isActive() || !config.getIdentity(context)) return
        let packet
        try { packet = JSON.parse(params.payload) } catch (_) { return }
        if (packet?.type === 'producer_ready') {
            const existing = state.sastGrants.get(key)
            if (existing?.context !== context || existing.config !== config) this._scheduleSastPush(state)
            return
        }
        const grant = state.sastGrants.get(key)
        if (!grant || grant.context !== context || grant.config !== config || packet?.revision !== grant.revision) return
        // Context/config are captured NOW, before any manager delivery queue.
        if (packet.type === 'dom_snapshot') this._emit('sastPayload', { ...context, tabId: state.tabId }, {
            payload: packet.payload, ownerId: config.ownerId, revision: config.revision,
            current: () => state.contexts.get(key) === context && state.sastPush === config && config.isActive(),
            nativeCurrent: () => this.tabs.get(state.tabId) === state && state.alive && state.contexts.get(key) === context })
        else if (packet.type === 'producer_error') this._emit('sastPushError', { ...context, tabId: state.tabId, reason: 'sast_dom_push_failed', complete: false }, { ownerId: config.ownerId, revision: config.revision })
    }

    _clearH2Operation(state) {
        const operation = state.h2Operation
        if (!operation) return
        operation.active = false
        operation.cancel()
        for (const key of [...operation.contexts.keys()]) this._identityDelete(state, operation.contexts, key)
        if (operation.charged) {
            this.budget.release(operation.charge, 'metadata')
            state.pendingBytes -= operation.bytes
            operation.charged = false
        }
        state.h2Operation = null
    }

    cancelH2Fetch(tabId, captureId) {
        const operation = this.tabs.get(tabId)?.h2Operation
        if (operation?.identity.captureId === captureId) operation.cancel()
    }

    _h2ContextEvent(state, sessionId, method, params) {
        const operation = state.h2Operation
        if (!operation?.active || sessionId) return
        if (method === 'Runtime.executionContextsCleared') {
            for (const key of [...operation.contexts.keys()]) this._identityDelete(state, operation.contexts, key)
            if (operation.dispatched) operation.cancel()
            return
        }
        if (method === 'Runtime.executionContextDestroyed') {
            for (const [key, context] of operation.contexts) if (params.executionContextUniqueId
                ? context.uniqueId === params.executionContextUniqueId : context.contextId === params.executionContextId) {
                this._identityDelete(state, operation.contexts, key)
                if (operation.dispatched) operation.cancel()
            }
            return
        }
        if (method !== 'Runtime.executionContextCreated') return
        if (metadataSize(params) > METADATA_BYTES) { operation.contextInvalid = true; return }
        const context = params.context
        if (Number.isInteger(context?.id)) {
            if (operation.dispatched && operation.contexts.has(context.id)) operation.cancel()
            this._identityDelete(state, operation.contexts, context.id)
        }
        // Native default root only; existing SAST extension-isolated admission
        // above remains separate and cannot borrow this execution identity.
        if (!context || !Number.isInteger(context.id) || context.auxData?.isDefault !== true
            || context.auxData?.frameId !== operation.identity.frameId
            || typeof context.uniqueId !== 'string' || !context.uniqueId || context.uniqueId.length > 2048
            || !this.admit(operation.identity, 'h2Fetch')) return
        if (operation.contexts.size >= 2) { operation.contextInvalid = true; return }
        this._identitySet(state, operation.contexts, context.id, { ...operation.identity, contextId: context.id, uniqueId: context.uniqueId })
    }

    async executeH2Fetch(identity, request) {
        const state = this.tabs.get(identity.tabId)
        const matches = () => state && this.tabs.get(identity.tabId) === state && state.alive
            && state.capabilities.size === 1 && state.capabilities.has('network')
            && state.frames.size === 1 && state.childStates.size === 0
            && state.frames.get(identity.frameId)?.url === 'about:blank'
            && state.frames.get(identity.frameId)?.documentId === identity.documentId
            && state.frames.get(identity.frameId)?.loaderId === identity.loaderId
            && state.sessionGenerations.get('') === identity.sessionGeneration
            && this.admit(identity, 'h2Fetch')
        if (!matches() || state.h2Operation || request.url !== identity.url) throw new Error('capture_helper_unavailable')
        const bytes = metadataSize(request, this.maxResourceBytes) + metadataSize(identity) + 1024
        const charge = { ...identity, requestId: `capture-h2-operation:${++this.budgetSerial}` }
        if (bytes > this.maxResourceBytes || state.identityBytes + state.requestBytes + state.pendingBytes + bytes > this.maxTabBytes
            || !this._reserveBudget(charge, 'metadata', bytes)) throw new Error('capture_helper_budget_exceeded')
        const cancelled = Symbol('cancelled')
        let cancel
        const cancellation = new Promise(resolve => { cancel = reason => {
            operation.cancelReason ||= reason || 'capture_helper_unavailable'
            operation.abort?.()
            resolve(cancelled)
        } })
        const operation = { identity: { ...identity }, contexts: new Map(), active: true, cancel, charge, bytes, charged: true }
        state.h2Operation = operation
        state.pendingBytes += bytes
        const deadline = Date.now() + this.h2OperationTimeoutMs
        const timer = setTimeout(() => cancel('capture_helper_timeout'), this.h2OperationTimeoutMs)
        const disposeController = objectId => {
            // These fixed operations use only the handle returned by our own
            // exact native context. Cleanup must not wait for a stalled fetch.
            void this._call({ tabId: identity.tabId }, 'Runtime.callFunctionOn', { objectId, functionDeclaration: H2_ABORT, returnByValue: true })
                .catch(() => {})
                .then(() => this._call({ tabId: identity.tabId }, 'Runtime.releaseObject', { objectId }))
                .catch(() => {})
        }
        const valid = () => matches() && operation.active && !operation.contextInvalid && state.h2Operation === operation
        const call = async (method, params) => {
            if (!valid()) throw new Error('capture_helper_unavailable')
            const result = await Promise.race([this.send(identity.tabId, method, params), cancellation])
            if (result === cancelled || !valid()) throw new Error(operation.cancelReason || 'capture_helper_unavailable')
            return result
        }
        const frameMatches = tree => !tree?.childFrames?.length && tree?.frame?.id === identity.frameId
            && tree.frame.loaderId === identity.loaderId && tree.frame.url === 'about:blank'
        try {
            if (!frameMatches((await call('Page.getFrameTree')).frameTree)) throw new Error('capture_helper_unavailable')
            await call('Runtime.enable')
            state.runtimeEnabled = true
            if (operation.contexts.size !== 1) throw new Error('capture_helper_context_unavailable')
            const context = [...operation.contexts.values()][0]
            if (!frameMatches((await call('Page.getFrameTree')).frameTree)
                || operation.contexts.size !== 1 || [...operation.contexts.values()][0] !== context) throw new Error('capture_helper_context_unavailable')
            operation.dispatched = true
            const controllerTask = this.send(identity.tabId, 'Runtime.callFunctionOn', { functionDeclaration: H2_CONTROLLER,
                uniqueContextId: context.uniqueId, returnByValue: false })
            // A callback after revocation may own a handle, but cannot start a
            // fetch; dispose it rather than leaking it or lending its identity.
            void controllerTask.then(result => {
                if ((!valid() || operation.cancelReason) && result?.result?.objectId) disposeController(result.result.objectId)
            }, () => {})
            const controller = await Promise.race([controllerTask, cancellation])
            if (controller === cancelled || !valid()) throw new Error(operation.cancelReason || 'capture_helper_unavailable')
            if (controller.exceptionDetails) throw new Error('capture_h2_fetch_failed')
            const objectId = controller.result?.objectId
            if (typeof objectId !== 'string' || !objectId || objectId.length > 2048) throw new Error('capture_helper_context_unavailable')
            operation.abort = () => { if (!operation.controllerDisposed) { operation.controllerDisposed = true; disposeController(objectId) } }
            const result = await call('Runtime.callFunctionOn', { functionDeclaration: H2_FETCH, objectId,
                arguments: [{ value: request }, { value: this.maxResourceBytes }, { value: Math.max(1, deadline - Date.now()) }],
                awaitPromise: true, returnByValue: true })
            if (!frameMatches((await call('Page.getFrameTree')).frameTree)
                || operation.contexts.size !== 1 || [...operation.contexts.values()][0] !== context) throw new Error('capture_helper_context_unavailable')
            if (result.exceptionDetails) throw new Error('capture_h2_fetch_failed')
            const value = result.result?.value
            if (['capture_helper_budget_exceeded', 'capture_helper_timeout', 'capture_h2_fetch_failed'].includes(value?.captureError)) throw new Error(value.captureError)
            if (!value || !Number.isInteger(value.status) || value.status < 0 || value.status > 599 || typeof value.statusText !== 'string'
                || !Array.isArray(value.headers) || value.headers.some(header => typeof header?.name !== 'string' || typeof header?.value !== 'string')
                || typeof value.body !== 'string') throw new Error('capture_h2_response_unavailable')
            const resultBytes = metadataSize(value, this.maxResourceBytes)
            const resultCharge = { ...charge, requestId: `${charge.requestId}:result` }
            if (resultBytes > this.maxResourceBytes || state.identityBytes + state.requestBytes + state.pendingBytes + resultBytes > this.maxTabBytes
                || !this._reserveBudget(resultCharge, 'metadata', resultBytes)) throw new Error('capture_helper_budget_exceeded')
            // Immediate transfer to the DAST result, never shared body storage.
            this.budget.release(resultCharge, 'metadata')
            return { status: value.status, statusText: value.statusText, headers: value.headers.map(({ name, value }) => ({ name, value })), body: value.body }
        } finally {
            clearTimeout(timer)
            operation.abort?.()
            if (state.h2Operation === operation) this._clearH2Operation(state)
            if (this.tabs.get(identity.tabId) === state && state.alive && state.runtimeEnabled && !state.capabilities.has('sources')) {
                // Optional domain cleanup cannot turn cancellation/deadline
                // into an unbounded wait for a native callback. The owner still
                // releases and closes this exclusive operation-owned helper.
                const disable = this.send(identity.tabId, 'Runtime.disable').catch(() => {})
                const remaining = deadline - Date.now()
                if (!operation.cancelReason && remaining > 0) {
                    let cleanupTimer
                    try { await Promise.race([disable, new Promise(resolve => { cleanupTimer = setTimeout(resolve, remaining) })]) }
                    finally { clearTimeout(cleanupTimer) }
                }
                state.runtimeEnabled = false
            }
        }
    }
    async collectSastPayload(identity) {
        const unavailable = stage => Object.assign(new Error('capture_context_unavailable'), { sastCollectionStage: stage })
        const state = this.tabs.get(identity.tabId)
        const sessionId = identity.sessionId || ''
        const matches = () => state && this.tabs.get(identity.tabId) === state && state.alive && state.capabilities.has('sources') && (sessionId ? state.childStates.get(sessionId)?.ready && this._childCurrent(state, state.childStates.get(sessionId)) && state.childStates.get(sessionId).runtimeEnabled : state.runtimeEnabled) && state.frames.get(identity.frameId)?.documentId === identity.documentId && state.frames.get(identity.frameId)?.sessionGeneration === identity.sessionGeneration && (state.frames.get(identity.frameId)?.sessionId || '') === sessionId && this.admit({ ...state.frames.get(identity.frameId), tabId: identity.tabId }, 'domSources')
        const contexts = () => [...state.contexts.values()].filter(context => context.frameId === identity.frameId && context.documentId === identity.documentId && context.sessionGeneration === identity.sessionGeneration && (context.sessionId || '') === sessionId)
        if (!matches()) throw unavailable('precheck')
        const candidates = contexts()
        if (!candidates.length) throw unavailable('candidate_zero')
        const unchanged = () => {
            const current = contexts()
            return matches() && current.length === candidates.length && candidates.every(context => current.includes(context))
        }
        let context = candidates[0]
        if (candidates.length > 1) {
            if (new Set(candidates.map(candidate => candidate.uniqueId)).size !== candidates.length) throw unavailable('candidate_duplicate_identity')
            const valid = []
            for (const candidate of candidates) {
                let probe
                try { probe = await this.send(identity.tabId, 'Runtime.callFunctionOn', {
                    functionDeclaration: PROBE_SAST_COLLECTOR, uniqueContextId: candidate.uniqueId,
                    arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin }], returnByValue: true
                }, identity.sessionId) } catch (_) { throw unavailable('candidate_probe_failed') }
                if (!unchanged()) throw unavailable('context_changed')
                if (probe.exceptionDetails || !probe.result?.value
                    || typeof probe.result.value.runtimeIdentity !== 'boolean' || typeof probe.result.value.collector !== 'boolean') throw unavailable('candidate_probe_failed')
                if (probe.result.value.runtimeIdentity === true && probe.result.value.collector === true) valid.push(candidate)
            }
            if (valid.length !== 1) throw unavailable(valid.length ? 'candidate_many_valid' : 'candidate_zero_valid')
            context = valid[0]
        }
        let result
        try { result = await this.send(identity.tabId, 'Runtime.callFunctionOn', { functionDeclaration: COLLECT_SAST, uniqueContextId: context.uniqueId, arguments: [{ value: this.chrome.runtime.id }, { value: this.extensionOrigin }], awaitPromise: true, returnByValue: true }, identity.sessionId) }
        catch (error) { try { error.sastCollectionStage = 'dispatch' } catch (_) {} throw error }
        if (!unchanged()) throw unavailable('context_changed')
        if (result.exceptionDetails) throw unavailable('collector_exception')
        if (!result.result?.value) throw unavailable('missing_value')
        if (metadataSize(result.result.value, this.maxResourceBytes) > this.maxResourceBytes) throw unavailable('oversize')
        return result.result.value
    }
    _frame(state, frame, sessionId) {
        if (!frame?.id) return
        const old = state.frames.get(frame.id)
        if (old?.documentId && old.documentId !== frame.loaderId) {
            // Replacement is a native fact even if retaining the new frame is
            // refused. Never lend the old loader to a later new-world context.
            this._clearFrame(state, frame.id, true)
            this._identityDelete(state, state.frames, frame.id)
        }
        if (!this._identitySet(state, state.frames, frame.id, { frameId: frame.id, parentFrameId: frame.parentId, loaderId: frame.loaderId, documentId: frame.loaderId, url: frame.url, sessionId, sessionGeneration: state.sessionGenerations.get(sessionId || '') })) return
        this._emit('protocol', { tabId: state.tabId, ...state.frames.get(frame.id) }, { method: 'Page.frameNavigated', source: { tabId: state.tabId, sessionId }, params: { frame } })
    }
    _identitySet(state, map, key, value, unavailableRecord) {
        const prior = map.has(key) ? metadataSize(map.get(key)) + String(key).length * 2 : 0
        const charge = metadataSize(value) + String(key).length * 2
        if (state.identityBytes - prior + charge + state.pendingBytes + state.requestBytes > this.maxTabBytes) { this._emit('gap', { ...(unavailableRecord || { tabId: state.tabId }), reason: 'identity_budget_exceeded', complete: false }); return false }
        const budgetKey = `${map === state.contexts ? 'context' : map === state.frames ? 'frame' : map === state.sastBindings ? 'sast-binding' : map === state.sastGrants ? 'sast-grant' : 'h2-context'}:${key}`
        const frame = state.frames.get(value.frameId)
        const budgetRecord = { ...value, tabId: state.tabId, documentId: value.documentId || frame?.documentId, requestId: `capture-identity:${++this.budgetSerial}` }
        if (!this._reserveBudget(budgetRecord, 'metadata', charge, unavailableRecord || budgetRecord)) return false
        const oldBudget = state.identityBudget.get(budgetKey)
        if (oldBudget) this.budget.release(oldBudget, 'metadata')
        state.identityBudget.set(budgetKey, budgetRecord)
        state.identityBytes += charge - prior
        map.set(key, value)
        return true
    }
    _identityDelete(state, map, key) {
        const grant = state.sastGrants?.get(key)
        if (map === state.contexts && grant && grant.context === map.get(key)) this._identityDelete(state, state.sastGrants, key)
        if (map === state.contexts && map.has(key)) {
            const context = map.get(key)
            for (const [bindingKey, binding] of state.sastBindings || []) {
                if (!binding.members?.some(member => member.context === context)) continue
                const smaller = { ...binding, members: binding.members.filter(member => member.context !== context) }
                if (!this._identitySet(state, state.sastBindings, bindingKey, smaller)) {
                    const runtime = context.sessionId ? state.childStates.get(context.sessionId) : state
                    if (runtime) runtime.sastContextInventoryIncomplete = true
                }
            }
        }
        const budgetKey = `${map === state.contexts ? 'context' : map === state.frames ? 'frame' : map === state.sastBindings ? 'sast-binding' : map === state.sastGrants ? 'sast-grant' : 'h2-context'}:${key}`
        const budgetRecord = state.identityBudget.get(budgetKey)
        if (budgetRecord) this.budget.release(budgetRecord, 'metadata')
        state.identityBudget.delete(budgetKey)
        if (map.has(key)) state.identityBytes -= metadataSize(map.get(key)) + String(key).length * 2
        map.delete(key)
    }
    _dropRequest(state, key) {
        const record = state.requests.get(key)
        if (record) { state.requestBytes -= metadataSize(record, this.maxTabBytes); this.budget.release(record, 'metadata') }
        state.requests.delete(key)
    }
    _clearFrame(state, frameId, invalidate = false) {
        const frame = state.frames.get(frameId)
        if (invalidate && frame) this._emit('invalidate', { tabId: state.tabId, ...frame, reason: 'document_replaced', complete: false })
        for (const [key, context] of state.contexts) if (context.frameId === frameId) this._identityDelete(state, state.contexts, key)
        for (const [id, frame] of state.frames) if (frame.parentFrameId === frameId) { this._clearFrame(state, id, invalidate); this._identityDelete(state, state.frames, id) }
        for (const [key, record] of state.requests) if (record.frameId === frameId
            && !(invalidate && this.admit(record, 'retiredSources'))) this._dropRequest(state, key)
    }
    _selected(state, record) {
        let accepted = false
        for (const capability of ['sources', 'authBodies', 'recording']) if (state.capabilities.has(capability) && this.admit(record, capability)) accepted = true
        return accepted || this.admit(record, 'retiredSources')
    }
    _event(source, method, params = {}) {
        const state = this.tabs.get(source.tabId)
        if (!state?.alive) return
        // Retained-source recovery is not part of Network + DOM capture.
        // Ignore even oversized unsolicited payloads before sizing or dispatch.
        if (method.startsWith('Debugger.')) return
        if (source.sessionId) {
            const child = state.childStates.get(source.sessionId)
            if (!child || child.revoked) return
            if (!child.ready) { this._queueChildEvent(state, child, source, method, params); return }
        }
        const sessionId = source.sessionId || ''
        if (method.startsWith('Runtime.')) { this._contextEvent(state, source.sessionId, method, params); return }
        const key = `${sessionId}:${params.requestId}`
        if (metadataSize(params) > METADATA_BYTES) {
            this._emit('gap', { tabId: source.tabId, sessionId: source.sessionId, requestId: String(params.requestId || '').slice(0, 2048), reason: 'metadata_budget_exceeded', complete: false })
            this._dropRequest(state, key)
            return
        }
        if (method === 'Page.frameNavigated') this._frame(state, params.frame, source.sessionId)
        if (method === 'Page.frameDetached') { this._clearFrame(state, params.frameId); this._identityDelete(state, state.frames, params.frameId) }
        if (method === 'Target.attachedToTarget') {
            if (params.targetInfo?.type !== 'iframe') { this._emit('gap', { tabId: source.tabId, reason: 'unsupported_child_target', complete: false }); return }
            if (state.childStates.size >= 1024 || typeof params.sessionId !== 'string' || !params.sessionId || params.sessionId.length > 2048) { this._emit('gap', { tabId: source.tabId, reason: 'identity_budget_exceeded', complete: false }); return }
            this._startChild(state, params.sessionId, source.sessionId || '')
        }
        if (method === 'Target.detachedFromTarget') {
            const child = state.childStates.get(params.sessionId)
            if (child) { child.detached = true; this._revokeChild(state, child, false); state.childStates.delete(params.sessionId) }
            state.children.delete(params.sessionId)
            state.sessionGenerations.delete(params.sessionId)
            for (const [frameId, frame] of state.frames) if (frame.sessionId === params.sessionId) { this._clearFrame(state, frameId); this._identityDelete(state, state.frames, frameId) }
            // Preserve the detached incarnation for manager-side grant revocation;
            // the raw session may already have been removed or subsequently reused.
            this._emit('protocol', { tabId: source.tabId, sessionId: source.sessionId, sessionGeneration: child?.generation }, { method, source, params })
            return
        }
        if (method === 'Network.requestWillBeSent') {
            const old = state.requests.get(key)
            if (old && params.redirectResponse) this._emit('gap', { ...old, response: params.redirectResponse, complete: false, reason: 'redirect_body_unavailable' })
            const frame = state.frames.get(params.frameId)
            const record = { tabId: source.tabId, sessionId: source.sessionId, sessionGeneration: state.sessionGenerations.get(sessionId), requestId: params.requestId, hop: old ? old.hop + 1 : 0, frameId: params.frameId, loaderId: params.loaderId || frame?.loaderId, documentId: params.loaderId || frame?.documentId, url: params.request?.url, documentUrl: params.documentURL, method: params.request?.method, resourceType: params.type, timeStamp: params.timestamp, request: params.request, redirectHasExtraInfo: params.redirectHasExtraInfo }
            if (state.requests.size >= Math.floor(this.maxTabBytes / 2048) && !old) {
                this._emit('gap', { ...record, reason: 'identity_budget_exceeded', complete: false })
                return
            }
            if (params.type === 'Document') this._frame(state, { id: params.frameId, loaderId: params.loaderId, url: record.url }, source.sessionId)
            this._emit('request', { ...record, redirect: !!params.redirectResponse, redirectResponse: params.redirectResponse })
            if (!this.admit(record, 'metadata')) return
            this._dropRequest(state, key)
            const charge = metadataSize(record, this.maxTabBytes)
            if (state.identityBytes + state.requestBytes + state.pendingBytes + charge > this.maxTabBytes) { this._emit('gap', { tabId: source.tabId, requestId: params.requestId, reason: 'identity_budget_exceeded', complete: false }); return }
            if (!this._reserveBudget(record, 'metadata', charge)) return
            state.requestBytes += charge
            state.requests.set(key, record)
        } else if (method === 'Network.responseReceived') {
            const record = state.requests.get(key)
            // A denied redirect hop still occupies a native ExtraInfo slot.
            // Forward only its presence flag, never foreign response headers.
            if (!record) this._emit('response', { tabId: source.tabId, sessionId: source.sessionId, requestId: params.requestId, hasExtraInfo: params.hasExtraInfo })
            if (record) {
                const oldCharge = metadataSize(record, this.maxTabBytes)
                const charge = metadataSize(params.response) + 32
                if (state.identityBytes + state.requestBytes + state.pendingBytes + charge > this.maxTabBytes) { this._emit('gap', { tabId: source.tabId, requestId: params.requestId, reason: 'metadata_budget_exceeded', complete: false }); this._dropRequest(state, key); return }
                if (!this._reserveBudget(record, 'metadata', charge)) { this._dropRequest(state, key); return }
                record.response = params.response; record.resourceType = params.type; record.hasExtraInfo = params.hasExtraInfo; this._emit('response', record)
                state.requestBytes += metadataSize(record, this.maxTabBytes) - oldCharge
            }
        } else if (method === 'Network.requestWillBeSentExtraInfo' || method === 'Network.responseReceivedExtraInfo') {
            // Extra-info has its own redirect sequence and is deliberately not
            // guessed onto a hop. Recorder receives the ordered protocol event.
            this._emit('protocol', { tabId: source.tabId, sessionId: source.sessionId, requestId: params.requestId }, { method, source, params })
        } else if (method === 'Network.loadingFinished') {
            const record = state.requests.get(key)
            this._emit('terminal', { tabId: source.tabId, sessionId: source.sessionId, requestId: params.requestId, failed: false })
            if (record && this._selected(state, record)) this._queue(state, record)
            this._dropRequest(state, key)
        } else if (method === 'Network.loadingFailed') {
            const record = state.requests.get(key)
            this._emit('terminal', { tabId: source.tabId, sessionId: source.sessionId, requestId: params.requestId, failed: true })
            if (record) this._emit('gap', { ...record, complete: false, reason: params.canceled ? 'request_cancelled' : 'request_failed' })
            this._dropRequest(state, key)
        } else this._emit('protocol', { tabId: source.tabId, sessionId: source.sessionId }, { method, source, params })
        // Browser listeners never await consumer work.
    }
    _queue(state, record) {
        const charge = 1024 + metadataSize(record, this.maxTabBytes)
        if (state.identityBytes + state.requestBytes + state.pendingBytes + charge > this.maxTabBytes) { this._emit('gap', { ...record, complete: false, reason: 'pending_budget_exceeded' }); return }
        const budgetRecord = { ...record, requestId: `capture-job:${++this.budgetSerial}` }
        if (!this._reserveBudget(budgetRecord, 'metadata', charge, record)) return
        state.pendingBytes += charge
        state.pendingJobs++
        this.jobs.push({ state, record: { ...record }, charge, budgetRecord })
        this._pump()
    }
    _pump() {
        while (this.running < 2 && this.jobs.length) {
            const job = this.jobs.shift()
            this.running++
            const { state, record } = job
            Promise.resolve().then(async () => {
                if (!state.alive) return
                const currentChild = () => !record.sessionId || state.children.has(record.sessionId) && state.childStates.get(record.sessionId)?.generation === record.sessionGeneration
                const admitted = () => state.frames.get(record.frameId)?.documentId === record.documentId
                    ? true : this.admit(record, 'retiredSources')
                if (!currentChild() || !admitted()) return
                try {
                    const result = await this.send(state.tabId, 'Network.getResponseBody', { requestId: record.requestId }, record.sessionId)
                    if (!state.alive) return
                    if (!currentChild()) return
                    if (!admitted()) return
                    const body = result.body
                    if (typeof body !== 'string') throw new Error('unavailable')
                    if (body.length * 2 > this.maxResourceBytes) this._emit('gap', { ...record, complete: false, reason: 'resource_budget_exceeded' })
                    else if (this._reserveBudget(record, 'chunks', body.length * 2)) {
                        // Synchronous ownership transfer, not a second retained
                        // body copy. The manager rechecks/charges immutable data.
                        this.budget.release(record, 'chunks')
                        this._emit('body', { ...record, body, text: result.base64Encoded ? undefined : body, base64Encoded: !!result.base64Encoded, complete: true })
                    }
                } catch { if (state.alive && currentChild()) this._emit('gap', { ...record, complete: false, reason: 'body_read_unavailable' }) }
            }).finally(() => {
                state.pendingBytes -= job.charge
                state.pendingJobs--
                this.budget.release(job.budgetRecord, 'metadata')
                this.running--
                this._pump()
                this._notifyWaiters()
            })
        }
    }
    _notifyWaiters() {
        this.waiters = this.waiters.filter(waiter => {
            if (waiter.state ? !waiter.state.pendingJobs : !this.running && !this.jobs.length && ![...this.tabs.values()].some(state => state.pendingJobs)) { waiter.resolve(); return false }
            return true
        })
    }
    drain(tabId) {
        const state = this.tabs.get(tabId)
        if (tabId !== undefined && !state?.pendingJobs) return Promise.resolve()
        if (tabId === undefined && !this.running && !this.jobs.length && ![...this.tabs.values()].some(target => target.pendingJobs)) return Promise.resolve()
        return new Promise(resolve => this.waiters.push({ state, resolve }))
    }
}

export default ChromiumCaptureAdapter
