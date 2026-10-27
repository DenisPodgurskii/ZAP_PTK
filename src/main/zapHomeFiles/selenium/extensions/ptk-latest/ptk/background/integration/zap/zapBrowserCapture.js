import { removeLegacySastCaptureRules } from './zapSastSources.js'

const VERSION = 1
const ID = /^[A-Za-z0-9_-]{1,128}$/

// Metadata-only handshake. Bodies remain in the shared, background-owned store.
export class ZapBrowserCapture {
    constructor({ transport, manager, sast, browserApi = globalThis.browser, randomId = () => crypto.randomUUID() } = {}) {
        this.transport = transport
        this.manager = manager
        this.sast = sast
        this.randomId = randomId
        this.state = null
        this.generation = 0
        this.pendingPrepare = null
        this.ready = removeLegacySastCaptureRules(browserApi).then(() => true, () => false)
    }

    isBrowserCaptureOwnerActive({ ownerId, tabId }) {
        return this.state?.ownerId === ownerId && this.state.tabId === tabId && !this.state.stopping
    }

    _identity(state) {
        return { version: VERSION, captureId: state.captureId, zapid: state.zapid, browserid: state.browserid }
    }

    prepare(context) {
        const { tabId, zapid, version, engines = [], startupKey = null, beforeReady = null } = context
        const browserid = this.transport.getBrowserId()
        if (version !== VERSION) return Promise.reject(new Error('browser_capture_unsupported'))
        if (!Number.isInteger(tabId) || tabId < 0 || !ID.test(zapid || '') || !ID.test(browserid || '')
            || !Array.isArray(engines) || !engines.length
            || ((startupKey !== null || beforeReady !== null)
                && (typeof startupKey !== 'string' || !startupKey || startupKey.length > 8192
                    || typeof beforeReady !== 'function' || !engines.includes('SAST')))) return Promise.reject(new Error('browser_capture_context_invalid'))
        const capabilities = ['network', ...(Array.isArray(engines) && engines.includes('SAST') ? ['sources'] : [])]
        const key = JSON.stringify([tabId, zapid, version, browserid, capabilities, startupKey])
        if (this.pendingPrepare?.key === key && this.pendingPrepare.generation === this.generation) return this.pendingPrepare.promise
        const generation = ++this.generation
        const operation = this._prepare({ tabId, zapid, version, engines, browserid, capabilities, startupKey, beforeReady }, generation)
        const promise = operation.finally(() => {
            if (this.pendingPrepare?.promise === promise) this.pendingPrepare = null
        })
        this.pendingPrepare = { key, generation, promise }
        return promise
    }

    async _prepare({ tabId, zapid, version, engines, browserid, capabilities, startupKey, beforeReady }, generation) {
        const assertCurrent = () => {
            if (generation !== this.generation) throw new Error('browser_capture_initialization_failed')
        }
        if (await this.ready !== true) throw new Error('browser_capture_rule_cleanup_failed')
        assertCurrent()
        if (version !== VERSION) throw new Error('browser_capture_unsupported')
        if (!Number.isInteger(tabId) || tabId < 0 || !ID.test(zapid || '') || !ID.test(browserid || '')
            || !Array.isArray(engines) || !engines.length) throw new Error('browser_capture_context_invalid')
        if (this.state?.tabId === tabId && this.state.zapid === zapid && this.state.browserid === browserid
            && this.state.capabilities.join(',') === capabilities.join(',') && this.state.startupKey === startupKey && !this.state.stopping
            && ['prepared', 'active'].includes(this.state.phase) && this.state.lease?.getSnapshot().ready) return this.state.startResult
        if (this.state?.phase === 'active' && !this.state.stopping) throw new Error('browser_capture_active_owner')
        await this._stopState(this.state)
        assertCurrent()
        const captureId = this.randomId()
        if (!ID.test(captureId || '')) throw new Error('browser_capture_context_invalid')
        const state = { tabId, zapid, browserid, captureId, ownerId: `ZAP_CAPTURE:${captureId}`,
            phase: 'prepared', capabilities, startupKey, preparePending: true }
        this.state = state
        try {
            let result
            try { result = await this.transport.browserCaptureRequest({ ...this._identity(state), action: 'prepare' }) }
            finally { state.preparePending = false }
            assertCurrent()
            if (this.state !== state || result?.ok !== true || result.version !== VERSION) throw new Error('browser_capture_registration_refused')
            state.expiry = setTimeout(() => {
                if (this.state === state && state.phase === 'prepared') void this.stop().catch(() => {})
            }, 60000)
            state.expiry.unref?.()
            const lease = await this.manager.acquire({ ownerId: state.ownerId, tabId,
                scope: { prepared: true }, capabilities })
            state.lease = lease
            if (generation !== this.generation || this.state !== state || !lease.getSnapshot().ready) {
                await lease.release('prepared_owner_changed')
                throw new Error('browser_capture_owner_changed')
            }
            if (engines.includes('SAST')) {
                state.revokeAdoption = this.sast.adoptBrowserCaptureLease({ tabId, zapid, lease,
                    onClaim: () => {
                        if (this.state !== state || state.stopping || state.phase !== 'prepared') return false
                        clearTimeout(state.expiry)
                        state.phase = 'active'
                        return true
                    },
                    onRelease: () => this.state === state ? this.stop() : undefined
                })
            }
            if (beforeReady) {
                // The bound callback tab need not navigate before normal SAST
                // startup claims its validated, path-scoped source lease.
                // Await the whole start: onClaim alone precedes subscription.
                const result = await beforeReady()
                assertCurrent()
                const snapshot = lease.getSnapshot()
                if (this.state !== state || state.stopping || state.phase !== 'active'
                    || !snapshot.active || !snapshot.ready || snapshot.prepared
                    || !['starting', 'started', 'already_running'].includes(result?.status)
                    || !result?.requiredEngines?.includes('SAST')
                    || result?.failedEngines?.some(item => item?.engine === 'SAST')) {
                    throw new Error('browser_capture_initialization_failed')
                }
                state.startResult = result
            }
            const ack = await this.transport.browserCaptureRequest({ ...this._identity(state), action: 'ready', capabilities: lease.getSnapshot().capabilities })
            assertCurrent()
            if (this.state !== state || !lease.getSnapshot().ready || ack?.ok !== true || ack.version !== VERSION) throw new Error('browser_capture_initialization_failed')
            return state.startResult
        } catch {
            await this._stopState(state)
            // A pending registration can finish after an earlier stop's release
            // request. Revoke that exact old identity again, never the new owner.
            if (state.releaseBeforePrepareAck) await this._releaseMetadata(state)
            throw new Error('browser_capture_initialization_failed')
        }
    }

    _releaseMetadata(state) {
        return this.transport.browserCaptureRequest({ ...this._identity(state), action: 'release' }).catch(() => {})
    }

    stop() {
        // Invalidate even a preparation still waiting for initial rule cleanup.
        this.generation++
        return this._stopState(this.state)
    }

    _stopState(state) {
        if (!state) return Promise.resolve()
        if (state.stopPromise) return state.stopPromise
        state.stopping = true
        state.revokeAdoption?.()
        clearTimeout(state.expiry)
        state.stopPromise = (async () => {
            try {
                state.lease?.freeze()
                // Successful SAST already drained before onRelease. Failed or
                // expired prepare cancels outstanding native reads immediately.
                await state.lease?.release('zap_capture_released')
            } finally {
                if (this.state === state) this.state = null
                state.releaseBeforePrepareAck = state.preparePending
                await this._releaseMetadata(state)
            }
        })()
        return state.stopPromise
    }
}
