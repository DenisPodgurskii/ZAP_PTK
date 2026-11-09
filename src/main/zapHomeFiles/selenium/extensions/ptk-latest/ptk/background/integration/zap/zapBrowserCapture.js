import { removeLegacySastCaptureRules } from './zapSastSources.js'
import { sameDocumentUrl } from '../../capture/sameDocumentUrl.js'

const VERSION = 1
const ID = /^[A-Za-z0-9_-]{1,128}$/

// Metadata-only handshake. Bodies remain in the shared, background-owned store.
export class ZapBrowserCapture {
    constructor({ transport, manager, sast, iast, browserApi = globalThis.browser, randomId = () => crypto.randomUUID() } = {}) {
        this.transport = transport
        this.manager = manager
        this.sast = sast
        this.iast = iast
        this.randomId = randomId
        this.state = null
        this.generation = 0
        this.pendingPrepare = null
        this.ready = removeLegacySastCaptureRules(browserApi).then(() => true, () => false)
    }

    isBrowserCaptureOwnerActive({ ownerId, tabId }) {
        return this.state?.ownerId === ownerId && this.state.tabId === tabId && !this.state.stopping
    }

    // A DAST-only visit has no IAST registration. Its pre-navigation receipt
    // instead requires the exact metadata-only native capture lease to be
    // ready for the callback tab; document identity is checked after navigation.
    hasPreparedMetadataOwner({ zapid, browserid, tabId } = {}) {
        const state = this.state
        const snapshot = state?.lease?.getSnapshot?.()
        return state?.phase === 'prepared' && !state.stopping
            && state.zapid === zapid && state.browserid === browserid
            && state.tabId === tabId && state.capabilities.length === 1
            && state.capabilities[0] === 'network'
            && state.lease?.ownerId === state.ownerId
            && snapshot?.ready === true && snapshot.active === true
    }

    getCurrentRootDocument({ zapid, browserid, nativeFrameId = null } = {}) {
        const state = this.state
        const metadataOnlyPrepared = state?.phase === 'prepared' && !state.capabilities.includes('sources')
        if (!state || state.stopping || (state.phase !== 'active' && !metadataOnlyPrepared)
            || state.zapid !== zapid || state.browserid !== browserid
            || state.lease?.getSnapshot?.().active !== true
            || state.lease?.getSnapshot?.().ready !== true) return null
        const roots = (state.lease.getVisitDocuments?.() || []).filter(document =>
            document.tabId === state.tabId && !document.sessionId
            && (nativeFrameId === null ? (document.parentFrameId === undefined
                || document.parentFrameId === null || document.parentFrameId === -1)
                : document.frameId === nativeFrameId))
        if (roots.length !== 1) return null
        const document = roots[0]
        if (typeof document.documentId !== 'string' || !document.documentId
            || typeof document.url !== 'string' || !document.url
            || !Number.isSafeInteger(document.streamGeneration) || document.streamGeneration < 0) return null
        return Object.freeze({ captureId: state.captureId, zapid, browserid, tabId: state.tabId,
            frameId: document.frameId, documentId: document.documentId,
            sessionGeneration: document.sessionGeneration,
            streamGeneration: document.streamGeneration, url: document.url })
    }

    async getVerifiedCurrentRootDocument({ zapid, browserid } = {}) {
        const state = this.state
        if (!state || state.stopping || state.zapid !== zapid || state.browserid !== browserid
            || typeof state.lease?.getVerifiedVisitRoot !== 'function') return null
        const beforeDocuments = state.lease.getVisitDocuments?.() || []
        let nativeRoot
        try { nativeRoot = await state.lease.getVerifiedVisitRoot() }
        catch (_) { return null }
        if (this.state !== state || state.stopping || !nativeRoot) return null
        const before = beforeDocuments.filter(document => !document.sessionId
            && document.tabId === state.tabId && document.frameId === nativeRoot.frameId)
        const after = this.getCurrentRootDocument({ zapid, browserid,
            nativeFrameId: nativeRoot.frameId })
        // The transport UUID, lease owner name and manager capture ID are
        // distinct identities. Bind the native root to the exact acquired
        // lease, without exposing its internal capture ID on the wire.
        if (!after || before.length !== 1
            || before[0].captureId !== state.lease.captureId
            || after.captureId !== state.captureId
            || state.lease.ownerId !== state.ownerId
            || nativeRoot.captureId !== state.lease.captureId
            || ['tabId', 'frameId', 'documentId',
            'sessionGeneration', 'streamGeneration'].some(key =>
            after[key] !== nativeRoot[key])) return null
        // A new document may commit during native verification. Its exact
        // post-query lease and native identity may be returned as the current
        // root; the prior document's evidence remains a separate obligation.
        if (before[0].documentId === after.documentId
            && (['tabId', 'frameId', 'sessionGeneration', 'streamGeneration'].some(key =>
                before[0][key] !== after[key])
                || !sameDocumentUrl(before[0].url, after.url))) return null
        if (!sameDocumentUrl(after.url, nativeRoot.url)) return null
        return after
    }

    async armNextPreparedMetadataDocument({ zapid, browserid, tabId, root } = {}) {
        const state = this.state
        if (!state || state.phase !== 'prepared' || state.stopping
            || state.zapid !== zapid || state.browserid !== browserid
            || state.tabId !== tabId || state.capabilities.length !== 1
            || state.capabilities[0] !== 'network'
            || typeof state.lease?.armNextPreparedDocument !== 'function'
            || !root || root.captureId !== state.captureId) return false
        const verified = await this.getVerifiedCurrentRootDocument({ zapid, browserid })
        if (!verified || ['captureId', 'tabId', 'frameId', 'documentId',
            'sessionGeneration', 'streamGeneration', 'url'].some(key =>
            verified[key] !== root[key])) return false
        return state.lease.armNextPreparedDocument({
            ...verified, captureId: state.lease.captureId
        }) === true
    }

    async getVerifiedCurrentRootAcquisition({ zapid, browserid } = {}) {
        const root = await this.getVerifiedCurrentRootDocument({ zapid, browserid })
        const state = this.state
        if (!root || !state || state.stopping || state.captureId !== root.captureId
            || state.zapid !== zapid || state.browserid !== browserid) return null
        if (!state.capabilities.includes('sources')) {
            return Object.freeze({ root, sast: Object.freeze({ required: false }) })
        }
        const documents = state.lease?.getDocuments?.() || []
        const matching = documents.filter(document => document.captureId === state.lease.captureId
            && document.tabId === root.tabId && document.frameId === root.frameId
            && document.documentId === root.documentId
            && document.sessionGeneration === root.sessionGeneration
            && document.streamGeneration === root.streamGeneration && !document.sessionId)
        if (matching.length !== 1) return null
        const status = state.lease?.getSastDocumentAcquisitionStatus?.(matching[0])
        if (!status || typeof status.domPayloadAdmitted !== 'boolean'
            || typeof status.pendingNativeSources !== 'boolean'
            || !Number.isSafeInteger(status.unresolvedSourceReferences)
            || status.unresolvedSourceReferences < 0
            || typeof status.analysisFailure !== 'boolean') return null
        const after = this.getCurrentRootDocument({ zapid, browserid,
            nativeFrameId: root.frameId })
        if (this.state !== state || state.stopping || !after
            || ['captureId', 'tabId', 'frameId', 'documentId', 'sessionGeneration',
                'streamGeneration'].some(key => root[key] !== after[key])
            || !sameDocumentUrl(root.url, after.url)) return null
        return Object.freeze({ root, sast: Object.freeze({ required: true,
            domPayloadAdmitted: status.domPayloadAdmitted,
            pendingNativeSources: status.pendingNativeSources,
            unresolvedSourceReferences: status.unresolvedSourceReferences,
            analysisFailure: status.analysisFailure }) })
    }

    async getVerifiedCurrentRootAnalysis({ zapid, browserid } = {}) {
        const acquired = await this.getVerifiedCurrentRootAcquisition({ zapid, browserid })
        if (!acquired) return null
        if (acquired.sast.required !== true) return Object.freeze({ ...acquired,
            analysis: Object.freeze({ required: false }) })
        const { root } = acquired
        const state = this.state
        if (!state || state.stopping || state.captureId !== root.captureId
            || typeof this.sast?.getCurrentSastAnalysisSnapshot !== 'function') return null
        const matching = (state.lease?.getDocuments?.() || []).filter(document =>
            document.captureId === state.lease.captureId
            && document.tabId === root.tabId && document.frameId === root.frameId
            && document.documentId === root.documentId
            && document.sessionGeneration === root.sessionGeneration
            && document.streamGeneration === root.streamGeneration && !document.sessionId)
        if (matching.length !== 1) return null
        const analysis = this.sast.getCurrentSastAnalysisSnapshot({ tabId: root.tabId,
            identity: matching[0] })
        if (!analysis || analysis.tabId !== root.tabId || analysis.documentId !== root.documentId
            || analysis.streamGeneration !== root.streamGeneration
            || typeof analysis.scanId !== 'string' || !analysis.scanId
            || !Number.isSafeInteger(analysis.revision) || analysis.revision < 0
            || typeof analysis.complete !== 'boolean') return null
        const after = this.getCurrentRootDocument({ zapid, browserid,
            nativeFrameId: root.frameId })
        if (this.state !== state || state.stopping || !after
            || ['captureId', 'tabId', 'frameId', 'documentId', 'sessionGeneration',
                'streamGeneration'].some(key => root[key] !== after[key])
            || !sameDocumentUrl(root.url, after.url)) return null
        return Object.freeze({ ...acquired, analysis: Object.freeze({ required: true,
            scanId: analysis.scanId, revision: analysis.revision, complete: analysis.complete }) })
    }

    _identity(state) {
        return { version: VERSION, captureId: state.captureId, zapid: state.zapid, browserid: state.browserid }
    }

    prepare(context) {
        const { tabId, zapid, version, engines = [], startupKey = null,
            beforeReady = null, preparedTargetUrl = null,
            preparedTargetMatch = 'origin', skipExistingDocument = false } = context
        const browserid = this.transport.getBrowserId()
        if (version !== VERSION) return Promise.reject(new Error('browser_capture_unsupported'))
        if (!Number.isInteger(tabId) || tabId < 0 || !ID.test(zapid || '') || !ID.test(browserid || '')
            || !Array.isArray(engines) || !engines.length
            || ((startupKey !== null || beforeReady !== null)
                && (typeof startupKey !== 'string' || !startupKey || startupKey.length > 8192
                    || typeof beforeReady !== 'function' || !engines.includes('SAST')))) return Promise.reject(new Error('browser_capture_context_invalid'))
        const capabilities = ['network', ...(Array.isArray(engines) && engines.includes('SAST') ? ['sources'] : [])]
        const key = JSON.stringify([tabId, zapid, version, browserid, capabilities,
            startupKey, preparedTargetUrl, preparedTargetMatch, skipExistingDocument])
        if (this.pendingPrepare?.key === key && this.pendingPrepare.generation === this.generation) return this.pendingPrepare.promise
        const generation = ++this.generation
        const operation = this._prepare({ tabId, zapid, version, engines, browserid,
            capabilities, startupKey, beforeReady, preparedTargetUrl,
            preparedTargetMatch, skipExistingDocument }, generation)
        const promise = operation.finally(() => {
            if (this.pendingPrepare?.promise === promise) this.pendingPrepare = null
        })
        this.pendingPrepare = { key, generation, promise }
        return promise
    }

    // The DAST-only callback lease may have observed another same-origin page
    // before Client Spider assigns this visit. Replace metadata ownership
    // before navigation; the new lease skips the current document and may
    // bind one new document on the assigned target's origin.
    async rearmPreparedMetadataVisit({ zapid, browserid, tabId, targetUrl,
        isCurrent = () => true, isVisitCurrent = isCurrent } = {}) {
        const state = this.state
        let url
        try { url = new URL(targetUrl) } catch (_) { return false }
        if (!['http:', 'https:'].includes(url.protocol) || url.href !== targetUrl
            || !state || state.phase !== 'prepared' || state.stopping
            || state.zapid !== zapid || state.browserid !== browserid
            || state.tabId !== tabId || state.capabilities.length !== 1
            || state.capabilities[0] !== 'network'
            || this.transport.getBrowserId() !== browserid || !isCurrent()) return false
        await this.stop()
        if (!isCurrent() || this.state) return false
        try {
            await this.prepare({ tabId, zapid, version: VERSION, engines: ['DAST'],
                preparedTargetUrl: targetUrl, preparedTargetMatch: 'origin',
                skipExistingDocument: true })
        } catch (_) { return false }
        if (!isCurrent() || !this.hasPreparedMetadataOwner({ zapid, browserid, tabId })
            || this.state?.preparedTargetUrl !== targetUrl
            || this.state?.preparedTargetMatch !== 'origin'
            || this.state?.skipExistingDocument !== true) {
            await this.stop()
            return false
        }
        // A DAST-only Client crawl can outlive the ordinary 60-second
        // unclaimed-preparation timeout. Keep this exact prepared lease only
        // while its named running session remains current; the periodic check
        // still releases an abandoned or stopped visit within one interval.
        this.state.visitCurrent = isVisitCurrent
        this._armPreparedExpiry(this.state, 30000)
        return true
    }

    _armPreparedExpiry(state, intervalMs = 60000) {
        clearTimeout(state.expiry)
        state.expiry = setTimeout(() => {
            void this._expirePreparedState(state)
        }, intervalMs)
        state.expiry.unref?.()
    }

    _expirePreparedState(state) {
        if (this.state !== state || state.phase !== 'prepared') return Promise.resolve()
        let current = false
        try { current = state.visitCurrent?.() === true } catch (_) { /* expired owner */ }
        const renewed = current && state.lease?.renewPreparedMetadataVisit?.() === true
        if (renewed) {
            this._armPreparedExpiry(state, 30000)
            return Promise.resolve()
        }
        return this.stop().catch(() => {})
    }

    async _prepare({ tabId, zapid, version, engines, browserid, capabilities,
        startupKey, beforeReady, preparedTargetUrl, preparedTargetMatch,
        skipExistingDocument }, generation) {
        const assertCurrent = () => {
            if (generation !== this.generation) throw new Error('browser_capture_initialization_failed')
        }
        if (await this.ready !== true) throw new Error('browser_capture_rule_cleanup_failed')
        assertCurrent()
        if (version !== VERSION) throw new Error('browser_capture_unsupported')
        if (!Number.isInteger(tabId) || tabId < 0 || !ID.test(zapid || '') || !ID.test(browserid || '')
            || !Array.isArray(engines) || !engines.length) throw new Error('browser_capture_context_invalid')
        if (this.state?.tabId === tabId && this.state.zapid === zapid && this.state.browserid === browserid
            && this.state.capabilities.join(',') === capabilities.join(',')
            && this.state.startupKey === startupKey
            && this.state.preparedTargetUrl === preparedTargetUrl
            && this.state.preparedTargetMatch === preparedTargetMatch
            && this.state.skipExistingDocument === skipExistingDocument && !this.state.stopping
            && ['prepared', 'active'].includes(this.state.phase) && this.state.lease?.getSnapshot().ready) return this.state.startResult
        if (this.state?.phase === 'active' && !this.state.stopping) throw new Error('browser_capture_active_owner')
        await this._stopState(this.state)
        assertCurrent()
        const captureId = this.randomId()
        if (!ID.test(captureId || '')) throw new Error('browser_capture_context_invalid')
        const state = { tabId, zapid, browserid, captureId, ownerId: `ZAP_CAPTURE:${captureId}`,
            phase: 'prepared', capabilities, startupKey, preparedTargetUrl,
            preparedTargetMatch, skipExistingDocument, preparePending: true }
        this.state = state
        try {
            let result
            try { result = await this.transport.browserCaptureRequest({ ...this._identity(state), action: 'prepare' }) }
            finally { state.preparePending = false }
            assertCurrent()
            if (this.state !== state || result?.ok !== true || result.version !== VERSION) throw new Error('browser_capture_registration_refused')
            this._armPreparedExpiry(state)
            const lease = await this.manager.acquire({ ownerId: state.ownerId, tabId,
                scope: { prepared: true, mode: preparedTargetMatch,
                    ...(skipExistingDocument ? { skipExistingDocument: true } : {}),
                    ...(preparedTargetUrl ? { targetUrl: preparedTargetUrl } : {}) },
                capabilities })
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
                if (engines.includes('IAST')) {
                    const receipt = this.iast?.getRegistrationReceipt?.(tabId)
                    if (receipt?.ready !== true || receipt?.documentStart !== true
                        || receipt?.tabId !== tabId || !receipt?.scanId
                        || result?.failedEngines?.some(item => item?.engine === 'IAST')) {
                        throw new Error('browser_capture_iast_registration_failed')
                    }
                    state.iastRegistration = { scanId: receipt.scanId, branch: receipt.branch }
                }
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
