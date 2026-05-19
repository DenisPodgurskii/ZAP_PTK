/* Author: Denis Podgurskii */
import { dastEngine } from "./dast/dastEngine.js"
import { ptk_utils, ptk_storage } from "../background/utils.js"
import { loadCanonicalRulepack } from "./common/moduleRegistry.js"
import { parseUploadedScanFile } from "./export/parseUploadedScanFile.js"
import { DastAnalysisService } from "./dast/services/dastAnalysisService.js"
import { DastResultProjector } from "./dast/services/dastResultProjector.js"
import { DastCaptureAdapter } from "./dast/services/dastCaptureAdapter.js"
import { DastSessionCoordinator } from "./dast/services/dastSessionCoordinator.js"
import { DastScanResultLifecycleService } from "./dast/services/dastScanResultLifecycleService.js"
import { DastExportService } from "./dast/services/dastExportService.js"
import { DastPortalClient } from "./dast/services/dastPortalClient.js"
import { DastCandidateRunService } from "./dast/services/dastCandidateRunService.js"
import { DastFindingPresentationService } from "./dast/services/dastFindingPresentationService.js"
import { collapseDastAggregatedFindings } from "./dast/services/dastFindingAggregation.js"
import { SessionProfileStore } from "./bugbounty/sessionProfileStore.js"
import { EvidencePackageStore } from "./bugbounty/evidencePackageStore.js"
import { scanResultStore } from "./scanResultStore.js"
import { portalPolicyRuntimeStore } from "./common/portalPolicyRuntimeStore.js"


const worker = self

function getPortalApiKey() {
    return String(worker?.ptk_app?.settings?.profile?.api_key || '').trim()
}

function getDastPolicyState() {
    return portalPolicyRuntimeStore.getState('DAST')
}

function getSelectedDastPolicy() {
    return portalPolicyRuntimeStore.getSelectedPolicy('DAST')
}

function getDastRulepackSelection() {
    return portalPolicyRuntimeStore.getRulepackSelection('DAST')
}

function getDastPackStatusForSelection(selection = null, policyState = null) {
    if (selection?.source === 'portal') {
        return String(policyState?.packStatus || 'active').trim() || 'active'
    }
    return 'active'
}

const UI_SCAN_RESULT_BYTE_LIMIT = 8 * 1024 * 1024
const UI_SCAN_RESULT_LIMITS = Object.freeze({
    maxFindings: 5000,
    maxGroups: 1000,
    maxRequests: 1500,
    maxAttacksPerRequest: 200,
    maxRuntimeEvents: 200,
    maxStringLength: 2048,
    maxArrayItems: 100,
    maxObjectKeys: 64,
    maxDepth: 4
})
const UI_ANALYSIS_LIMITS = Object.freeze({
    ...UI_SCAN_RESULT_LIMITS,
    // Analysis candidates include nested evidence/why objects that need one extra level for UI.
    maxDepth: 5
})
const UI_FINDING_DETAILS_LIMITS = Object.freeze({
    ...UI_ANALYSIS_LIMITS,
    // Native SAST/IAST detail dialogs need nested location points like
    // evidence.sast.source.sourceLoc.start.line to survive sanitization.
    maxDepth: 7
})
const ANALYSIS_DIFF_BASE_STORAGE_KEY = "ptk_dast_analysis_diff_base_v1"
const ANALYSIS_SUPPRESSIONS_STORAGE_KEY = "ptk_dast_analysis_suppressions_v1"
const POPUP_TO_BACKGROUND_CHANNELS = new Set(["ptk_popup2background_dast", "ptk_popup2background_rattacker"])
const CONTENT_TO_BACKGROUND_CHANNELS = new Set(["ptk_content2dast", "ptk_content2rattacker"])
const CONTENT_WS_TO_BACKGROUND_CHANNELS = new Set(["ptk_contentws2dast", "ptk_contentws2rattacker"])
const IMPORT_TRANSFER_TTL_MS = 10 * 60 * 1000
const IMPORT_TRANSFER_MAX_ENTRIES = 2

function cloneForTransport(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value || null
    }
}

export class ptk_rattacker {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_rattacker"

        this.engine = new dastEngine(this.settings)
        this._persistTimer = null
        this._persistDebounceMs = 1000
        this.scanResultLifecycle = new DastScanResultLifecycleService({
            storage: ptk_storage,
            storageKey: this.storageKey
        })
        this.exportService = new DastExportService({
            lifecycleService: this.scanResultLifecycle
        })
        this.portalClient = new DastPortalClient({
            lifecycleService: this.scanResultLifecycle
        })
        this.analysisService = new DastAnalysisService({
            storage: ptk_storage,
            scanResultStore,
            diffBaseStorageKey: ANALYSIS_DIFF_BASE_STORAGE_KEY,
            suppressionsStorageKey: ANALYSIS_SUPPRESSIONS_STORAGE_KEY,
            getAppState: () => worker?.ptk_app,
            getCurrentScanResult: () => this.scanResult,
            getEngineIsRunning: () => this.engine?.isRunning === true
        })
        this.resultProjector = new DastResultProjector({
            analysisService: this.analysisService,
            byteLimit: UI_SCAN_RESULT_BYTE_LIMIT,
            limits: UI_SCAN_RESULT_LIMITS,
            analysisLimits: UI_ANALYSIS_LIMITS
        })
        this.captureAdapter = new DastCaptureAdapter({
            engine: this.engine,
            worker,
            browserApi: browser,
            requestFilters: ptk_utils.requestFilters,
            extraInfoSpec: ptk_utils.extraInfoSpec,
            getState: () => this.sessionCoordinator?.getState?.() || {}
        })
        this.engine?.setCaptureProgressProvider?.(this.captureAdapter)
        this.sessionCoordinator = new DastSessionCoordinator({
            engine: this.engine,
            captureAdapter: this.captureAdapter,
            baseSettings: this.settings,
            getZapManualEngineSettings: () => this._getZapManualEngineSettings(),
            reset: () => this.reset(),
            parseDomains: (domains) => this.parseDomains(domains),
            registerScript: () => this.registerScript(),
            unregisterScript: () => this.unregisterScript(),
            applyAnalysis: (scanResult, force) => this._applyAnalysis(scanResult, force),
            flushPersistScanResult: () => this._flushPersistScanResult(),
            setScanResult: (scanResult) => this._setAuthoritativeScanResult(scanResult, {
                markFinished: !!(scanResult?.finishedAt || scanResult?.finished)
            }),
            getScanResult: () => this.scanResult,
            notifyScanCompleted: () => this._notifyScanCompleted(),
            collectSeverityStats: () => this._collectSeverityStats()
        })
        this.findingPresentationService = new DastFindingPresentationService({
            getModules: () => this._getActiveCatalogModules(),
            sanitizeUiValue: (value, depth = 0, limits = UI_SCAN_RESULT_LIMITS) => this._sanitizeUiValue(value, depth, limits),
            uiLimits: UI_SCAN_RESULT_LIMITS
        })
        this.sessionProfileStore = new SessionProfileStore({
            storage: ptk_storage,
            browserApi: browser
        })
        if (this.engine?.setSessionProfileStore) {
            this.engine.setSessionProfileStore(this.sessionProfileStore)
        }
        this.evidencePackageStore = new EvidencePackageStore({
            storage: ptk_storage
        })
        this.candidateRunService = new DastCandidateRunService({
            settings: this.settings,
            getScanResult: () => this.scanResult,
            getCandidate: (candidateId) => this._findAnalysisCandidate(candidateId),
            getRequestRecordById: (requestId) => this.findingPresentationService.findRequestRecordById(this.scanResult, requestId),
            sessionProfileStore: this.sessionProfileStore,
            evidencePackageStore: this.evidencePackageStore,
            workflowOverlayService: undefined,
            startWorkflowReplay: (payload = {}) => browser.runtime.sendMessage({
                channel: "ptk_popup2background_recorder",
                type: "replay",
                ...payload
            }),
            onBugBountyStateChanged: (bugbounty) => this._setBugBountySnapshot(bugbounty)
        })
        this.importTransfers = new Map()
        if (this.engine?.setResultMutationListener) {
            this.engine.setResultMutationListener((payload = null) => {
                this._setAuthoritativeScanResult(this.engine.scanResult, {
                    markFinished: !!(this.engine?.scanResult?.finishedAt || this.engine?.scanResult?.finished)
                })
                this._schedulePersistScanResult()
                if (payload?.type === "attack_finding") {
                    worker?.ptk_app?.automation?.zap?.publisher?.requestFlush?.()
                }
            })
        }
        this.addMessageListeners()
        this.regularModulesCache = null
        this.cveModulesCache = null
        this._initPromise = null
        this._persistedScanHydrated = false
        this._analysisStateLoaded = false
        this._candidateRunStateScopeKey = null
        this._uiSnapshotRevision = 0
        this._uiSnapshotCache = null
    }

    _cleanupImportTransfers(now = Date.now()) {
        for (const [id, entry] of this.importTransfers.entries()) {
            if (!entry || Number(entry.expiresAt || 0) <= now) {
                this.importTransfers.delete(id)
            }
        }
    }

    _enforceImportTransferLimit() {
        if (this.importTransfers.size <= IMPORT_TRANSFER_MAX_ENTRIES) return
        const sorted = Array.from(this.importTransfers.entries()).sort((a, b) => {
            const left = Number(a?.[1]?.createdAt || 0)
            const right = Number(b?.[1]?.createdAt || 0)
            return left - right
        })
        while (sorted.length && this.importTransfers.size > IMPORT_TRANSFER_MAX_ENTRIES) {
            const oldest = sorted.shift()
            if (oldest?.[0]) this.importTransfers.delete(oldest[0])
        }
    }

    _normalizeImportChunk(chunk) {
        if (chunk instanceof Uint8Array) return chunk
        if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk)
        if (ArrayBuffer.isView(chunk)) {
            return new Uint8Array(chunk.buffer.slice(chunk.byteOffset, chunk.byteOffset + chunk.byteLength))
        }
        if (Array.isArray(chunk)) return Uint8Array.from(chunk)
        if (chunk && typeof chunk === "object") return Uint8Array.from(Object.values(chunk))
        return new Uint8Array(0)
    }

    _createImportTransfer(fileMeta = {}) {
        const now = Date.now()
        const size = Number(fileMeta?.size || 0)
        const chunkCount = Number(fileMeta?.chunkCount || 0)
        const importId = `dast-import-${now}-${Math.random().toString(36).slice(2, 10)}`
        const entry = {
            id: importId,
            name: String(fileMeta?.name || ""),
            type: String(fileMeta?.type || ""),
            size,
            chunkCount,
            createdAt: now,
            expiresAt: now + IMPORT_TRANSFER_TTL_MS,
            chunks: new Array(chunkCount).fill(null),
            receivedChunks: 0,
            receivedBytes: 0
        }
        this.importTransfers.set(importId, entry)
        this._enforceImportTransferLimit()
        return entry
    }

    _getImportTransfer(importId) {
        this._cleanupImportTransfers()
        const key = String(importId || "")
        if (!key) return null
        return this.importTransfers.get(key) || null
    }

    _deleteImportTransfer(importId) {
        const key = String(importId || "")
        if (key) this.importTransfers.delete(key)
    }

    _invalidateUiSnapshot() {
        this._uiSnapshotRevision += 1
        this._uiSnapshotCache = null
    }

    _getCandidateRunStateScopeKey(scanResult = this.scanResult) {
        const scanId = String(scanResult?.scanId || '').trim()
        const host = String(scanResult?.host || '').trim().toLowerCase()
        if (!scanId && !host) return '__empty__'
        return `${scanId || '__scanless__'}|${host || '__hostless__'}`
    }

    _setLoadedScanResult(scanResult) {
        const previousScopeKey = this._getCandidateRunStateScopeKey(this.scanResult)
        this.scanResult = scanResult || {}
        const nextScopeKey = this._getCandidateRunStateScopeKey(this.scanResult)
        if (previousScopeKey !== nextScopeKey) {
            this._candidateRunStateScopeKey = null
        }
        this._invalidateUiSnapshot()
        return this.scanResult
    }

    async _ensureCandidateRunStateLoaded({ force = false } = {}) {
        const scopeKey = this._getCandidateRunStateScopeKey(this.scanResult)
        if (!force && scopeKey === this._candidateRunStateScopeKey) {
            return
        }
        await this.candidateRunService.loadPersistedState()
        this._candidateRunStateScopeKey = scopeKey
    }

    async init({ force = false } = {}) {
        if (this._initPromise && !force) {
            return this._initPromise
        }
        const initPromise = (async () => {
            await portalPolicyRuntimeStore.ensureLoaded()
            if (force || !this._analysisStateLoaded) {
                await this.analysisService.loadState()
                this._analysisStateLoaded = true
            }
            if (this.engine.isRunning) {
                if (this.scanResult !== this.engine.scanResult) {
                    this._setAuthoritativeScanResult(this.engine.scanResult)
                }
            } else {
                if (force || !this._persistedScanHydrated) {
                    this.storage = await this.scanResultLifecycle.loadPersistedScan() || {}
                    this._persistedScanHydrated = true
                }
                if (Object.keys(this.storage || {}).length > 0) {
                    if (this.scanResult !== this.storage) {
                        this._setLoadedScanResult(this.storage)
                    }
                } else if (!this.scanResult || Object.keys(this.scanResult).length === 0) {
                    this._setLoadedScanResult(this.engine.scanResult || {})
                }
            }
            await this._ensureCandidateRunStateLoaded({ force })
        })()
        if (!force) {
            this._initPromise = initPromise
        }
        try {
            return await initPromise
        } finally {
            if (!force) {
                this._initPromise = null
            }
        }
    }

    async _ensureDefaultModulesReady() {
        if (this.engine?._moduleLoadPromise) {
            try {
                await this.engine._moduleLoadPromise
            } catch (err) {
                console.warn('[PTK DAST] Failed to load base modules', err)
            }
        }
    }

    _normalizeAnalysisHostKey(host) {
        return this.analysisService.normalizeAnalysisHostKey(host)
    }

    _getSuppressionsForHost(host) {
        return this.analysisService.getSuppressionsForHost(host)
    }

    _setSuppression(host, suppressKey, suppressed = true) {
        return this.analysisService.setSuppression(host, suppressKey, suppressed)
    }

    _clearSuppressions(host) {
        return this.analysisService.clearSuppressions(host)
    }

    _applyAnalysis(scanResult, force = false) {
        return this.analysisService.applyAnalysis(scanResult, {
            force,
            engineIsRunning: this.engine?.isRunning === true
        })
    }

    _resolveSessionProfileHost(host = null) {
        const direct = String(host || "").trim()
        if (direct) return direct
        const scanHost = String(this.scanResult?.host || "").trim()
        if (scanHost) return scanHost
        const dashboardTabUrl = String(worker?.ptk_app?.proxy?.getDashboardTab?.()?.url || "").trim()
        if (dashboardTabUrl) return dashboardTabUrl
        return ""
    }

    _cloneScanResultForUi() {
        const engineIsRunning = this.engine?.isRunning === true
        const cached = this._uiSnapshotCache
        if (cached
            && cached.revision === this._uiSnapshotRevision
            && cached.engineIsRunning === engineIsRunning) {
            return cached.snapshot
        }
        const snapshot = this.resultProjector.cloneScanResultForUi(this.scanResult || {}, {
            engineIsRunning
        })
        this._uiSnapshotCache = {
            revision: this._uiSnapshotRevision,
            engineIsRunning,
            snapshot
        }
        return snapshot
    }

    _hasRenderableScanData(scanResult = this.scanResult) {
        if (!scanResult || typeof scanResult !== "object") return false
        if (Array.isArray(scanResult.requests) && scanResult.requests.length) return true
        if (Array.isArray(scanResult.findings) && scanResult.findings.length) return true
        if (Array.isArray(scanResult.recon) && scanResult.recon.length) return true
        return false
    }

    _sanitizeUiValue(value, depth = 0, limits = UI_SCAN_RESULT_LIMITS) {
        return this.resultProjector.sanitizeUiValue(value, depth, limits)
    }

    _setAuthoritativeScanResult(scanResult, { markFinished = false } = {}) {
        const previousScopeKey = this._getCandidateRunStateScopeKey(this.scanResult)
        const synced = this.scanResultLifecycle.syncScanResult(scanResult, { markFinished })
        this.scanResult = synced || scanResult || this.engine?.scanResult || {}
        const nextScopeKey = this._getCandidateRunStateScopeKey(this.scanResult)
        if (previousScopeKey !== nextScopeKey) {
            this._candidateRunStateScopeKey = null
        }
        this._invalidateUiSnapshot()
        return this.scanResult
    }

    _setBugBountySnapshot(bugbounty = null) {
        if (!this.scanResult || typeof this.scanResult !== "object") {
            this.scanResult = this._setAuthoritativeScanResult(this.engine?.scanResult || {})
        }
        if (!bugbounty || typeof bugbounty !== "object") {
            delete this.scanResult?.bugbounty
            delete this.scanResult?.bugBounty
        } else {
            const clone = JSON.parse(JSON.stringify(bugbounty))
            this.scanResult.bugbounty = clone
            this.scanResult.bugBounty = clone
        }
        this._invalidateUiSnapshot()
        this._schedulePersistScanResult()
        return this.scanResult?.bugbounty || null
    }

    _schedulePersistScanResult() {
        if (this._persistTimer) return
        this._persistTimer = setTimeout(() => {
            this._persistTimer = null
            void this.scanResultLifecycle.persistScanResult(this.scanResult)
        }, this._persistDebounceMs)
    }

    _flushPersistScanResult() {
        if (this._persistTimer) {
            clearTimeout(this._persistTimer)
            this._persistTimer = null
        }
        return this.scanResultLifecycle.persistScanResult(this.scanResult)
    }

    _notifyScanCompleted() {
        return Promise.all([
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_rattacker",
                type: "all attacks completed",
                info: { completed: true }
            }).catch(e => e),
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_rattacker",
                type: "dast_scan_completed",
                info: { completed: true }
            }).catch(e => e)
        ])
    }

    async reset() {
        const previousScanId = this.scanResult?.scanId || this.engine?.scanResult?.scanId || null
        const previousHost = this.scanResult?.host || this.engine?.scanResult?.host || null
        if (this._persistTimer) {
            clearTimeout(this._persistTimer)
            this._persistTimer = null
        }
        this.scanResultLifecycle.deleteScan(previousScanId)
        this.analysisService.clearDiffBaseIfOwnedByScan({
            host: previousHost,
            scanId: previousScanId
        })
        this.engine.reset()
        this.storage = {}
        this._persistedScanHydrated = true
        this._candidateRunStateScopeKey = null
        this._setLoadedScanResult(this.engine.scanResult)
        await this.candidateRunService.clearHostState(previousHost)
        void ptk_storage.setItem(this.storageKey, {})
    }

    async loadRegularModules() {
        if (Array.isArray(this.regularModulesCache)) {
            return this.regularModulesCache
        }
        try {
            const rulepack = await loadCanonicalRulepack('DAST')
            this.regularModulesCache = Array.isArray(rulepack?.modules) ? rulepack.modules : []
        } catch (err) {
            console.warn('[PTK DAST] Failed to load base rulepack', err)
            this.regularModulesCache = []
        }
        return this.regularModulesCache
    }

    async loadCveModules() {
        if (Array.isArray(this.cveModulesCache)) {
            return this.cveModulesCache
        }
        try {
            const cveRulepack = await loadCanonicalRulepack('DAST', { variant: 'cve' })
            this.cveModulesCache = Array.isArray(cveRulepack.modules) ? cveRulepack.modules : []
        } catch (err) {
            console.warn('[PTK DAST] Failed to load CVE rulepack', err)
            this.cveModulesCache = []
        }
        return this.cveModulesCache
    }

    async getDefaultModules() {
        return this.getRegularModules()
    }

    async getPolicyPreviewModules(rulepack = null) {
        const selectedRulepack = rulepack && Array.isArray(rulepack.modules)
            ? rulepack
            : portalPolicyRuntimeStore.getSelectedRulepack('DAST')
        if (selectedRulepack && Array.isArray(selectedRulepack.modules)) {
            try {
                return JSON.parse(JSON.stringify(selectedRulepack.modules))
            } catch (_) {
                return Array.isArray(selectedRulepack.modules) ? selectedRulepack.modules : []
            }
        }
        return this.getRegularModules()
    }

    _getActiveCatalogModules() {
        const selectedRulepack = portalPolicyRuntimeStore.getSelectedRulepack('DAST')
        if (selectedRulepack && Array.isArray(selectedRulepack.modules)) {
            return selectedRulepack.modules
        }
        if (Array.isArray(this.engine?.modules) && this.engine.modules.length) {
            return this.engine.modules
        }
        if (Array.isArray(this.regularModulesCache) && this.regularModulesCache.length) {
            return this.regularModulesCache
        }
        return []
    }

    async getRegularModules() {
        const regularModules = await this.loadRegularModules()
        try {
            return JSON.parse(JSON.stringify(Array.isArray(regularModules) ? regularModules : []))
        } catch {
            return Array.isArray(regularModules) ? regularModules : []
        }
    }

    async getCveModules() {
        const cveModules = await this.loadCveModules()
        try {
            return JSON.parse(JSON.stringify(Array.isArray(cveModules) ? cveModules : []))
        } catch {
            return Array.isArray(cveModules) ? cveModules : []
        }
    }

    async _ensureSelectedPortalRulepackSnapshot() {
        await portalPolicyRuntimeStore.ensureLoaded()
        const selectedPolicy = getSelectedDastPolicy()
        const existingRulepack = portalPolicyRuntimeStore.getSelectedRulepack('DAST')
        if (existingRulepack && Array.isArray(existingRulepack.modules) && existingRulepack.modules.length) {
            return existingRulepack
        }
        const policyId = String(selectedPolicy?.id || '').trim()
        if (!policyId) return null
        const apiKey = getPortalApiKey()
        if (!apiKey) return null
        try {
            const resolved = await portalPolicyRuntimeStore.resolveRulepackForRun({
                apiKey,
                engine: 'DAST',
                policyId,
                policyName: selectedPolicy?.name || null
            })
            return resolved?.rulepack || null
        } catch (_) {
            return null
        }
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    addListeners() {
        return this.captureAdapter.addListeners()
    }

    removeListeners() {
        return this.captureAdapter.removeListeners()
    }

    onRemoved(tabId, info) {
        return this.captureAdapter.onRemoved(tabId, info)
    }

    _sleep(ms = 0) {
        return this.captureAdapter.sleep(ms)
    }

    _extractUiUrlFromRaw(rawRequest, fallbackUrl) {
        return this.captureAdapter._extractUiUrlFromRaw(rawRequest, fallbackUrl)
    }

    _buildResponseEnvelopeFromTabRequest(tabId, frameId, requestId, requestDetails) {
        return this.captureAdapter._buildResponseEnvelopeFromTabRequest(tabId, frameId, requestId, requestDetails)
    }

    _isStateChangingRequest(response) {
        return this.captureAdapter._isStateChangingRequest(response)
    }

    _isAttackableRequestType(response) {
        return this.captureAdapter._isAttackableRequestType(response)
    }

    _rawRequestHeaderRichness(rawRequest) {
        return this.captureAdapter._rawRequestHeaderRichness(rawRequest)
    }

    _normalizeRawRequestLine(rawRequest, response = null) {
        return this.captureAdapter._normalizeRawRequestLine(rawRequest, response)
    }

    _seedRequestsFromTab(tabId, maxRequests = 200) {
        return this.captureAdapter.seedRequestsFromTab(tabId, maxRequests)
    }

    _scheduleDeferredSeedAtEnd(seedGeneration) {
        return this.captureAdapter.scheduleDeferredSeedAtEnd(seedGeneration)
    }

    async _runDeferredSeedNowIfPending(timeoutMs = 120000) {
        return this.captureAdapter.runDeferredSeedNowIfPending(timeoutMs)
    }

    async _enqueueObservedRequest(response, maxAttempts = 6) {
        return this.captureAdapter.enqueueObservedRequest(response, maxAttempts)
    }

    onResponseStarted(response) {
        return this.captureAdapter.onResponseStarted(response)
    }

    _enqueueRedirect(response) {
        return this.captureAdapter._enqueueRedirect(response)
    }

    onHeadersReceived(response) {
        return this.captureAdapter.onHeadersReceived(response)
    }


    parseDomains(domains) {
        if (!domains || typeof domains !== 'string') {
            return []
        }
        let d = []
        domains.split(",").forEach(function (item) {
            const value = item?.trim()
            if (!value) {
                return
            }
            if (value.startsWith('*')) {
                d.push(value.replace('*.', ''))
            }
            else {
                d.push(value)
            }
        })
        return d
    }

    _getZapManualEngineSettings() {
        const bridge = worker?.ptk_app?.automation?.zap
        if (!bridge || typeof bridge.getManualEngineConfig !== 'function') {
            return null
        }
        const config = bridge.getManualEngineConfig('DAST')
        return (config && typeof config === 'object') ? config : null
    }

    onCompleted(response) {
        return this.captureAdapter.onCompleted(response)
    }

    registerScript() {
        let file = !worker.isFirefox ? 'ptk/content/ws.js' : 'content/ws.js'
        try {
            browser.scripting.registerContentScripts([{
                id: 'websocket-agent',
                js: [file],
                matches: ['<all_urls>'],
                runAt: 'document_start',
                world: 'MAIN'
            }]).then(() => { });
        } catch (e) {
            console.warn('Failed to register WebSocket script:', e);
        }
    }


    async unregisterScript() {
        try {
            await browser.scripting.unregisterContentScripts({
                ids: ["websocket-agent"],
            });
        } catch (err) {
            //console.log(`failed to unregister content scripts: ${err}`);
        }

    }

    onMessage(message, sender, sendResponse) {
        if (CONTENT_WS_TO_BACKGROUND_CHANNELS.has(message.channel)) {

            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (POPUP_TO_BACKGROUND_CHANNELS.has(message.channel)) {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (CONTENT_TO_BACKGROUND_CHANNELS.has(message.channel)) {
            if (message.type == 'user_interaction' && sender?.tab?.id && this.sessionCoordinator.isRunningForTab(sender.tab.id)) {
                this.sessionCoordinator.unlockUserInteraction()
                return Promise.resolve({ ok: true, unlocked: true })
            }

            if (message.type == 'xss_confirmed' && this.scanResult.host == (new URL(message.data.origin)).host) {
                this.checkConfirmedAttack(message.data)
            }

            if (message.type == 'spa_url_changed' && sender?.tab?.id) {
                if (worker?.ptk_app?.proxy?.tabUrlMap) {
                    worker.ptk_app.proxy.tabUrlMap.set(sender.tab.id, message.url)
                }
                if (this.sessionCoordinator.isRunningForTab(sender.tab.id)) {
                    if (this.sessionCoordinator.isCaptureBlockedByInteraction()) {
                        return Promise.resolve({ ok: true, gated: true })
                    }
                    try {
                        const uiUrl = message.url
                        if (!uiUrl.includes('#')) {
                            return Promise.resolve({ ok: true })
                        }
                        const parsed = new URL(uiUrl)
                        const cleanedUrl = uiUrl.split('#')[0] || (parsed.origin + parsed.pathname + (parsed.search || ''))
                        const host = parsed.host
                        const rawRequest = `GET ${cleanedUrl} HTTP/1.1\nHost: ${host}`
                        const response = {
                            url: cleanedUrl,
                            ui_url: uiUrl,
                            type: 'main_frame',
                            tabId: sender.tab.id
                        }
                        this.engine.enqueue({ raw: rawRequest, ui_url: uiUrl, responseType: 'main_frame', fingerprint: `spa:${uiUrl}` }, response)
                    } catch (e) { }
                }
                return Promise.resolve({ ok: true })
            }

            if (message.type == 'start') {
                this.runBackgroundScan(sender.tab.id, new URL(sender.origin).host)
                return Promise.resolve({ success: true, scanResult: this._cloneScanResultForUi() })
            }

            if (message.type == 'stop') {
                return this.stopBackgroundScan().then(() => {
                    let result = { attacks: this.scanResult.attacks, stats: this.scanResult.stats }
                    return { scanResult: JSON.parse(JSON.stringify(result)) }
                })
            }
        }
    }

    async msg_init(message) {
        await this.init()
        const scanResult = this._cloneScanResultForUi()
        const hasRenderableData = this._hasRenderableScanData(scanResult)
        const shouldWarmRulepackPreview = !this.engine.isRunning && !hasRenderableData
        if (shouldWarmRulepackPreview) {
            await this._ensureSelectedPortalRulepackSnapshot()
        }
        return Promise.resolve({
            scanResult,
            isScanRunning: this.engine.isRunning,
            viewState: this.engine.isRunning ? 'running' : (hasRenderableData ? 'idle_with_data' : 'idle_empty'),
            activeTab: worker.ptk_app.proxy.activeTab,
            settings: this.settings,
            policyState: getDastPolicyState(),
            rulepackSelection: getDastRulepackSelection()
        })
    }

    async msg_get_default_modules(message) {
        await portalPolicyRuntimeStore.ensureLoaded()
        await this._ensureSelectedPortalRulepackSnapshot()
        const [defaultModules, cveModules] = await Promise.all([
            this.getPolicyPreviewModules(),
            this.getCveModules()
        ])
        return Promise.resolve({
            success: true,
            default_modules: defaultModules,
            cve_modules: cveModules,
            policyState: getDastPolicyState(),
            rulepackSelection: getDastRulepackSelection()
        })
    }

    async msg_get_policy_state(message) {
        await portalPolicyRuntimeStore.ensureLoaded()
        return Promise.resolve({
            success: true,
            policyState: getDastPolicyState(),
            rulepackSelection: getDastRulepackSelection()
        })
    }

    async msg_load_policy_metadata(message) {
        await portalPolicyRuntimeStore.ensureLoaded()
        const apiKey = getPortalApiKey()
        if (!apiKey) {
            return Promise.resolve({
                success: false,
                error: "missing_api_key",
                policyState: getDastPolicyState()
            })
        }
        try {
            const policyState = await portalPolicyRuntimeStore.loadMetadata({ apiKey, engine: 'DAST' })
            return {
                success: true,
                policyState
            }
        } catch (err) {
            return {
                success: false,
                error: err?.message || String(err),
                policyState: getDastPolicyState()
            }
        }
    }

    async msg_select_policy(message) {
        try {
            const apiKey = getPortalApiKey()
            const policyState = await portalPolicyRuntimeStore.selectPolicy({
                engine: 'DAST',
                policyId: message?.policyId,
                policyName: message?.policyName || null,
                apiKey: apiKey || null
            })
            return {
                success: true,
                policyState,
                rulepackSelection: getDastRulepackSelection(),
                default_modules: await this.getPolicyPreviewModules(),
                cve_modules: await this.getCveModules()
            }
        } catch (err) {
            return {
                success: false,
                error: err?.message || String(err),
                policyState: getDastPolicyState()
            }
        }
    }

    async msg_clear_policy(message) {
        await portalPolicyRuntimeStore.ensureLoaded()
        const policyState = portalPolicyRuntimeStore.clearPolicy('DAST')
        return Promise.resolve({
            success: true,
            policyState,
            rulepackSelection: getDastRulepackSelection(),
            default_modules: await this.getPolicyPreviewModules(),
            cve_modules: await this.getCveModules()
        })
    }

    async msg_get_request_snapshot(message) {
        let targetScan = this.scanResult
        const requestedScanId = String(message?.scanId || '').trim()
        if (requestedScanId && String(targetScan?.scanId || '') !== requestedScanId) {
            await this.analysisService?.hydratePersistedRelatedScans?.(this.scanResult)
            targetScan = scanResultStore.getScan(requestedScanId) || targetScan
        }
        return Promise.resolve(
            this.findingPresentationService.getRequestSnapshot(targetScan, {
                requestId: message?.requestId || null,
                attackId: message?.attackId || null
            })
        )
    }

    async msg_get_analysis_suppressions(message) {
        const host = message?.host || this.scanResult?.host || null
        const suppressions = this._getSuppressionsForHost(host)
        return Promise.resolve({
            success: true,
            host: this._normalizeAnalysisHostKey(host),
            suppressions
        })
    }

    async msg_toggle_analysis_suppression(message) {
        const host = message?.host || this.scanResult?.host || null
        const suppressKey = message?.suppressKey || null
        const suppressed = message?.suppressed !== false
        const suppressions = this._setSuppression(host, suppressKey, suppressed)
        return Promise.resolve({
            success: true,
            host: this._normalizeAnalysisHostKey(host),
            suppressions
        })
    }

    async msg_clear_analysis_suppressions(message) {
        const host = message?.host || this.scanResult?.host || null
        const suppressions = this._clearSuppressions(host)
        return Promise.resolve({
            success: true,
            host: this._normalizeAnalysisHostKey(host),
            suppressions
        })
    }

    async msg_list_session_profiles(message) {
        const host = this._resolveSessionProfileHost(message?.host || null)
        const profiles = await this.sessionProfileStore.listProfiles({ host })
        return Promise.resolve({
            success: true,
            host: this.sessionProfileStore.normalizeHost(host),
            profiles
        })
    }

    async msg_create_session_profile(message) {
        const host = this._resolveSessionProfileHost(message?.host || null)
        try {
            const profile = await this.sessionProfileStore.createProfile({
                label: message?.label || "",
                host,
                notes: message?.notes || ""
            })
            const profiles = await this.sessionProfileStore.listProfiles({ host })
            return Promise.resolve({
                success: true,
                host: this.sessionProfileStore.normalizeHost(host),
                profile,
                profiles
            })
        } catch (err) {
            return Promise.resolve({
                success: false,
                error: err?.message || String(err),
                host: this.sessionProfileStore.normalizeHost(host),
                profiles: await this.sessionProfileStore.listProfiles({ host })
            })
        }
    }

    async msg_delete_session_profile(message) {
        const host = this._resolveSessionProfileHost(message?.host || null)
        const deleted = await this.sessionProfileStore.deleteProfile(message?.id || null)
        const profiles = await this.sessionProfileStore.listProfiles({ host })
        return Promise.resolve({
            success: true,
            host: this.sessionProfileStore.normalizeHost(host),
            deleted,
            profiles
        })
    }

    _findAnalysisCandidate(candidateId) {
        const id = String(candidateId || "").trim()
        if (!id) return null
        const analysis = this.scanResult?.analysis
        const candidates = Array.isArray(analysis?.candidates) ? analysis.candidates : []
        return candidates.find((candidate) => String(candidate?.id || "") === id) || null
    }

    async msg_get_candidate_playwright_readiness(message) {
        return this.candidateRunService.getCandidatePlaywrightReadiness({
            candidateId: message?.candidateId || null,
            skipNetwork: message?.skipNetwork === true
        })
    }

    async msg_run_candidate_in_playwright(message) {
        return this.candidateRunService.runCandidateInPlaywright({
            candidateId: message?.candidateId || null,
            profile: message?.profile || "smoke",
            authMode: message?.authMode || "reuse_storage_state",
            constraints: message?.constraints || {},
            sessionProfileId: message?.sessionProfileId || null
        })
    }

    async msg_get_candidate_playwright_run(message) {
        return this.candidateRunService.getCandidatePlaywrightRun({
            candidateId: message?.candidateId || null
        })
    }

    async msg_compare_candidate_authz_diff(message) {
        return this.candidateRunService.compareCandidateAuthzDiff({
            candidateId: message?.candidateId || null,
            baselineSessionProfileId: message?.baselineSessionProfileId || null,
            comparisonSessionProfileId: message?.comparisonSessionProfileId || null,
            baselineResponse: message?.baselineResponse || null,
            comparisonResponse: message?.comparisonResponse || null,
            objectSwap: message?.objectSwap || null
        })
    }

    async msg_suggest_candidate_object_swap(message) {
        return this.candidateRunService.suggestCandidateObjectSwap({
            candidateId: message?.candidateId || null,
            objectSwap: message?.objectSwap || null
        })
    }

    async msg_run_candidate_authz_diff(message) {
        return this.candidateRunService.runCandidateAuthzDiff({
            candidateId: message?.candidateId || null,
            baselineSessionProfileId: message?.baselineSessionProfileId || null,
            comparisonSessionProfileId: message?.comparisonSessionProfileId || null,
            profile: message?.profile || "smoke",
            constraints: message?.constraints || {},
            objectSwap: message?.objectSwap || null
        })
    }

    async msg_get_candidate_authz_diff_run(message) {
        return this.candidateRunService.getCandidateAuthzDiffRun({
            runId: message?.runId || null
        })
    }

    async msg_create_evidence_package_from_authz_diff(message) {
        return this.candidateRunService.createEvidencePackageFromAuthzDiff({
            candidateId: message?.candidateId || null,
            runId: message?.runId || null,
            baselineSessionProfileId: message?.baselineSessionProfileId || null,
            comparisonSessionProfileId: message?.comparisonSessionProfileId || null,
            baselineResponse: message?.baselineResponse || null,
            comparisonResponse: message?.comparisonResponse || null,
            objectSwap: message?.objectSwap || null,
            title: message?.title || "",
            notes: message?.notes || ""
        })
    }

    async msg_list_evidence_packages(message) {
        return this.candidateRunService.listEvidencePackages({
            candidateId: message?.candidateId || null
        })
    }

    async msg_get_evidence_package(message) {
        return this.candidateRunService.getEvidencePackage({
            evidencePackageId: message?.evidencePackageId || null
        })
    }

    async msg_export_evidence_package(message) {
        return this.candidateRunService.exportEvidencePackage({
            evidencePackageId: message?.evidencePackageId || null,
            format: message?.format || "json"
        })
    }

    async msg_build_candidate_report_draft(message) {
        return this.candidateRunService.buildCandidateReportDraft({
            candidateId: message?.candidateId || null,
            runId: message?.runId || null,
            baselineSessionProfileId: message?.baselineSessionProfileId || null,
            comparisonSessionProfileId: message?.comparisonSessionProfileId || null,
            baselineResponse: message?.baselineResponse || null,
            comparisonResponse: message?.comparisonResponse || null,
            objectSwap: message?.objectSwap || null,
            title: message?.title || "",
            notes: message?.notes || ""
        })
    }

    async msg_get_workflow_overlay_summary(message) {
        return this.candidateRunService.getWorkflowOverlaySummary({
            candidateId: message?.candidateId || null,
            objectSwap: message?.objectSwap || null,
            baselineSessionProfileId: message?.baselineSessionProfileId || null,
            comparisonSessionProfileId: message?.comparisonSessionProfileId || null
        })
    }

    async msg_start_workflow_overlay_replay(message) {
        return this.candidateRunService.startWorkflowOverlayReplay({
            candidateId: message?.candidateId || null,
            objectSwap: message?.objectSwap || null,
            baselineSessionProfileId: message?.baselineSessionProfileId || null,
            comparisonSessionProfileId: message?.comparisonSessionProfileId || null,
            replaySessionRelation: message?.replaySessionRelation || "comparison",
            cleanCookie: message?.cleanCookie !== false,
            includeDestructive: message?.includeDestructive === true,
            validateRegex: message?.validateRegex || null
        })
    }

    async msg_get_finding_details(message) {
        await this._ensureSelectedPortalRulepackSnapshot()
        const findingId = message?.findingId || null
        const requestId = message?.requestId || null
        const attackId = message?.attackId || null
        const moduleId = message?.moduleId || null

        const decorate = (scan, details = {}, resolvedFinding = null) => {
            const response = Object.assign({}, details || {})
            const fullFinding = resolvedFinding || details?.finding || null
            response.finding = this._sanitizeUiValue(details?.finding || null, 0, UI_ANALYSIS_LIMITS)
            response.attack = this._sanitizeUiValue(details?.attack || null, 0, UI_SCAN_RESULT_LIMITS)
            response.findingDetail = this._sanitizeUiValue(fullFinding, 0, UI_FINDING_DETAILS_LIMITS)
            response.sourceScanId = scan?.scanId || null
            response.engine = response.findingDetail?.engine || response.finding?.engine || scan?.engine || null

            const effectiveRequestId = response.requestId
                || requestId
                || fullFinding?.evidence?.dast?.requestId
                || fullFinding?.evidence?.dast?.request_id
                || null
            const effectiveAttackId = attackId
                || fullFinding?.evidence?.dast?.attackId
                || fullFinding?.evidence?.dast?.attack_id
                || null

            if (scan?.engine === "DAST" || String(response.engine || "").toUpperCase() === "DAST") {
                const snapshot = effectiveRequestId
                    ? this.findingPresentationService.getRequestSnapshot(scan, {
                        requestId: effectiveRequestId,
                        attackId: effectiveAttackId
                    })
                    : { original: null, attack: null }
                response.original = cloneForTransport(snapshot?.original || null)
                if (snapshot?.attack && typeof snapshot.attack === "object") {
                    const mergedAttack = Object.assign(
                        {},
                        response.attack && typeof response.attack === "object" ? response.attack : {}
                    )
                    if (Object.prototype.hasOwnProperty.call(snapshot.attack, "request")) {
                        mergedAttack.request = cloneForTransport(snapshot.attack.request)
                    }
                    if (Object.prototype.hasOwnProperty.call(snapshot.attack, "response")) {
                        mergedAttack.response = cloneForTransport(snapshot.attack.response)
                    }
                    if (!mergedAttack.id && snapshot.attack.id) {
                        mergedAttack.id = snapshot.attack.id
                    }
                    response.attack = mergedAttack
                } else if (!response.attack && snapshot?.attack) {
                    response.attack = this._sanitizeUiValue(snapshot.attack, 0, UI_SCAN_RESULT_LIMITS)
                }
                response.requestId = effectiveRequestId || response.requestId || null
            }
            return response
        }

        const currentDetails = this.findingPresentationService.getFindingDetails(this.scanResult, {
            findingId,
            requestId,
            attackId,
            moduleId
        })
        if (!findingId || String(currentDetails?.finding?.id || "") === String(findingId || "")) {
            return Promise.resolve(decorate(this.scanResult, currentDetails, currentDetails?.finding || null))
        }

        await this.analysisService?.hydratePersistedRelatedScans?.(this.scanResult)

        const resolved = scanResultStore.findFindingById({
            findingId,
            host: this.scanResult?.host || null,
            tabId: this.scanResult?.tabId || null,
            preferredScanId: this.scanResult?.scanId || null
        })
        if (!resolved?.scan || !resolved?.finding) {
            return Promise.resolve(decorate(this.scanResult, currentDetails, currentDetails?.finding || null))
        }

        const relatedRequestId = requestId
            || resolved.finding?.evidence?.dast?.requestId
            || resolved.finding?.evidence?.dast?.request_id
            || null
        const relatedAttackId = attackId
            || resolved.finding?.evidence?.dast?.attackId
            || resolved.finding?.evidence?.dast?.attack_id
            || null
        const relatedDetails = this.findingPresentationService.getFindingDetails(resolved.scan, {
            findingId,
            requestId: relatedRequestId,
            attackId: relatedAttackId,
            moduleId: moduleId || resolved.finding?.moduleId || null
        })
        return Promise.resolve(decorate(resolved.scan, relatedDetails, resolved.finding))
    }

    async msg_get_related_finding_summaries(message) {
        await this.analysisService?.hydratePersistedRelatedScans?.(this.scanResult)
        const relatedScans = this.analysisService?.getRelatedScansForCoverage?.(this.scanResult) || []
        const summaries = []
        relatedScans.forEach((scan) => {
            const engine = String(scan?.engine || '').trim().toUpperCase()
            if (!engine || engine === 'DAST') return
            const findings = Array.isArray(scan?.findings) ? scan.findings : []
            findings.forEach((finding) => {
                const id = String(finding?.id || '').trim()
                if (!id) return
                const location = finding?.location && typeof finding.location === 'object' ? finding.location : {}
                summaries.push({
                    id,
                    engine,
                    title: finding?.ruleName || finding?.title || finding?.name || finding?.moduleName || finding?.moduleId || finding?.category || null,
                    ruleName: finding?.ruleName || null,
                    ruleId: finding?.ruleId || null,
                    moduleId: finding?.moduleId || null,
                    severity: finding?.severity || null,
                    location: {
                        url: location?.url || null,
                        route: location?.route || null,
                        method: location?.method || null,
                        param: location?.param || null
                    }
                })
            })
        })
        return Promise.resolve({
            success: true,
            findings: summaries
        })
    }

    async msg_recompute_analysis(message) {
        await this._ensureSelectedPortalRulepackSnapshot()
        if (!this.scanResult || typeof this.scanResult !== "object") {
            return Promise.resolve({
                success: false,
                error: "no_scan_result",
                message: "No DAST scan result is loaded."
            })
        }
        try {
            await this.analysisService.hydratePersistedRelatedScans(this.scanResult)
            this._applyAnalysis(this.scanResult, true)
            await this._flushPersistScanResult()
            return Promise.resolve({
                success: true,
                scanResult: this._cloneScanResultForUi(),
                isScanRunning: this.engine.isRunning
            })
        } catch (err) {
            return Promise.resolve({
                success: false,
                error: err?.code || err?.message || "analysis_recompute_failed",
                message: err?.message || String(err),
                scanResult: this._cloneScanResultForUi(),
                isScanRunning: this.engine.isRunning
            })
        }
    }

    async msg_check_apikey(message) {
        let self = this
        let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.attacks_endpoint
        let response = await fetch(url, { headers: { 'Authorization': message.key }, cache: "no-cache" })
            .then(response => response.text())
            .then(text => {
                try {
                    return JSON.parse(text)
                } catch (err) {
                    return { "success": false, "json": { "message": text } }
                }
            }).catch(e => {
                return { "success": false, "json": { "message": e.message } }
            })
        return response
    }

    async msg_save_scan(message) {
        if (!this._hasRenderableScanData(this.scanResult)) {
            this.storage = await this.scanResultLifecycle.loadPersistedScan() || {}
            this._persistedScanHydrated = true
            this._setLoadedScanResult(this.storage)
        }
        return this.portalClient.saveScan(worker.ptk_app.settings.profile || {}, this.scanResult, {
            projectId: message?.projectId || null
        })
    }

    async msg_export_scan_result(message) {
        if (!this.scanResult || Object.keys(this.scanResult).length === 0) {
            this.storage = await this.scanResultLifecycle.loadPersistedScan() || {}
            this._persistedScanHydrated = true
            this._setLoadedScanResult(this.storage)
        }
        if (!this.scanResult) return null
        try {
            return await this.exportService.createChunkedExport(this.scanResult, {
                target: message?.target || "download",
                fileName: message?.fileName || "PTK_DAST_scan.json",
                includeSecrets: message?.includeSecrets === true,
                owner: message?.owner || null
            })
        } catch (err) {
            console.error("[PTK DAST] Failed to export scan result", err)
            throw err
        }
    }

    async msg_export_scan_chunk(message) {
        return this.exportService.getChunk(message?.exportId, message?.index, message?.owner || null)
    }

    async msg_release_export_scan(message) {
        return this.exportService.release(message?.exportId, message?.owner || null)
    }

    async msg_get_projects(message) {
        return this.portalClient.getProjects(worker.ptk_app.settings.profile || {})
    }

    async msg_download_scans(message) {
        return this.portalClient.downloadScans(worker.ptk_app.settings.profile || {}, {
            projectId: message?.projectId || null,
            engine: message?.engine || "dast"
        })
    }

    async msg_download_scan_by_id(message) {
        await portalPolicyRuntimeStore.ensureLoaded()
        await this._ensureSelectedPortalRulepackSnapshot()
        const response = await this.portalClient.downloadScanById(worker.ptk_app.settings.profile || {}, message?.scanId)
        if (!response?.success || !response?.scanResult) {
            return response
        }
        this.storage = response.scanResult
        this._persistedScanHydrated = true
        this._setLoadedScanResult(response.scanResult)
        await this._ensureCandidateRunStateLoaded({ force: true })
        if (this.scanResult && (this.scanResult.finishedAt || this.scanResult.finished)) {
            try {
                if (!this.analysisService.hasCurrentAnalysis(this.scanResult)) {
                    await this.analysisService.hydratePersistedRelatedScans(this.scanResult)
                }
                this._applyAnalysis(this.scanResult, false)
            } catch (_) { }
        }
        await this._flushPersistScanResult()
        return this._cloneScanResultForUi()
    }

    async msg_reset(message) {
        await portalPolicyRuntimeStore.ensureLoaded()
        await this._ensureSelectedPortalRulepackSnapshot()
        this.reset()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi(),
            activeTab: worker.ptk_app.proxy.activeTab,
            policyState: getDastPolicyState(),
            rulepackSelection: getDastRulepackSelection()
        })
    }

    async msg_loadfile(message) {
        this.reset()
        const parsed = await parseUploadedScanFile(message?.file)
        if (!parsed?.ok || !parsed?.json) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        return this.msg_save({ json: JSON.stringify(parsed.json) })
    }

    async msg_loadfile_init(message) {
        const fileMeta = message?.fileMeta || {}
        const size = Number(fileMeta?.size || 0)
        const chunkCount = Number(fileMeta?.chunkCount || 0)
        if (!size || size <= 0 || !chunkCount || chunkCount <= 0) {
            throw new Error("Invalid file payload.")
        }
        this._cleanupImportTransfers()
        const entry = this._createImportTransfer(fileMeta)
        return {
            success: true,
            importId: entry.id,
            chunkCount: entry.chunkCount,
            size: entry.size
        }
    }

    async msg_loadfile_chunk(message) {
        const entry = this._getImportTransfer(message?.importId)
        if (!entry) {
            throw new Error("Import transfer expired.")
        }
        const index = Number(message?.index)
        if (!Number.isInteger(index) || index < 0 || index >= entry.chunkCount) {
            throw new Error("Invalid file payload.")
        }
        const normalized = this._normalizeImportChunk(message?.chunk)
        if (!normalized?.byteLength) {
            throw new Error("Invalid file payload.")
        }
        const previous = entry.chunks[index]
        if (previous?.byteLength) {
            entry.receivedBytes -= previous.byteLength
        } else {
            entry.receivedChunks += 1
        }
        entry.chunks[index] = normalized
        entry.receivedBytes += normalized.byteLength
        entry.expiresAt = Date.now() + IMPORT_TRANSFER_TTL_MS
        return {
            success: true,
            importId: entry.id,
            index,
            receivedChunks: entry.receivedChunks,
            receivedBytes: entry.receivedBytes
        }
    }

    async msg_loadfile_finish(message) {
        const entry = this._getImportTransfer(message?.importId)
        if (!entry) {
            throw new Error("Import transfer expired.")
        }
        try {
            if (entry.receivedChunks !== entry.chunkCount || entry.chunks.some(chunk => !chunk?.byteLength)) {
                throw new Error("Incomplete file payload.")
            }
            const totalBytes = entry.chunks.reduce((sum, chunk) => sum + Number(chunk?.byteLength || 0), 0)
            const combined = new Uint8Array(totalBytes)
            let offset = 0
            for (const chunk of entry.chunks) {
                combined.set(chunk, offset)
                offset += chunk.byteLength
            }
            const parsed = await parseUploadedScanFile({
                name: entry.name,
                type: entry.type,
                size: entry.size || combined.byteLength,
                buffer: combined.buffer
            })
            if (!parsed?.ok || !parsed?.json) {
                throw new Error("Wrong format or empty scan result")
            }
            this.reset()
            return this.msg_save({ json: JSON.stringify(parsed.json) })
        } finally {
            this._deleteImportTransfer(entry.id)
        }
    }

    async msg_release_import(message) {
        this._deleteImportTransfer(message?.importId)
        return { success: true }
    }

    async msg_save(message) {
        await portalPolicyRuntimeStore.ensureLoaded()
        await this._ensureSelectedPortalRulepackSnapshot()
        const raw = JSON.parse(message.json || "{}")
        const normalized = this.scanResultLifecycle.hydrateImportedScan(raw)
        if (!normalized) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        this.reset()
        this.storage = normalized
        this._persistedScanHydrated = true
        this._setLoadedScanResult(normalized)
        await this._ensureCandidateRunStateLoaded({ force: true })
        if (this.scanResult && (this.scanResult.finishedAt || this.scanResult.finished)) {
            try {
                if (!this.analysisService.hasCurrentAnalysis(this.scanResult)) {
                    await this.analysisService.hydratePersistedRelatedScans(this.scanResult)
                }
                this._applyAnalysis(this.scanResult, false)
            } catch (_) { }
        }
        await this._flushPersistScanResult()
        const defaultModules = await this.getPolicyPreviewModules()
        const cveModules = await this.getCveModules()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi(),
            isScanRunning: this.engine.isRunning,
            default_modules: defaultModules,
            cve_modules: cveModules,
            activeTab: worker.ptk_app.proxy.activeTab,
            policyState: getDastPolicyState(),
            rulepackSelection: getDastRulepackSelection()
        })
    }

    async msg_run_bg_scan(message) {
        try {
            const effectiveSettings = await this._resolveDastRunSettings(message?.settings || {})
            const started = this.runBackgroundScan(message.tabId, message.host, message.domains, effectiveSettings)
            if (!started || !this.engine.isRunning) {
                return Promise.resolve({
                    success: false,
                    error: started === false ? 'scan_already_running' : 'scan_start_failed',
                    message: started === false ? 'DAST scan is already running.' : 'Failed to start DAST scan.',
                    isScanRunning: this.engine.isRunning,
                    scanResult: this._cloneScanResultForUi(),
                    policyState: getDastPolicyState(),
                    rulepackSelection: getDastRulepackSelection()
                })
            }
            const defaultModules = await this.getPolicyPreviewModules(effectiveSettings.rulepack || null)
            return Promise.resolve({
                success: true,
                isScanRunning: this.engine.isRunning,
                scanResult: this._cloneScanResultForUi(),
                default_modules: defaultModules,
                policyState: getDastPolicyState(),
                rulepackSelection: getDastRulepackSelection()
            })
        } catch (err) {
            return Promise.resolve({
                success: false,
                error: err?.code || err?.message || 'portal_rulepack_fetch_failed',
                message: err?.portalMessage || err?.message || String(err),
                policyState: getDastPolicyState(),
                rulepackSelection: getDastRulepackSelection()
            })
        }
    }

    async msg_stop_bg_scan(message) {
        await this.stopBackgroundScan({
            runDeferredSeed: message?.runDeferredSeed,
            waitForIdleBeforeStop: message?.waitForIdleBeforeStop,
            seedTimeoutMs: message?.seedTimeoutMs,
            idleTimeoutMs: message?.idleTimeoutMs
        })
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi(),
            isScanRunning: this.engine.isRunning
        })
    }

    runBackgroundScan(tabId, host, domains, settings) {
        const effectiveSettings = Object.assign({}, settings || {})
        // Always send an explicit rulepack value for each run so the engine
        // cannot inherit a portal policy snapshot from a previous scan.
        effectiveSettings.rulepack = effectiveSettings.rulepack || null
        const started = this.sessionCoordinator.runBackgroundScan(tabId, host, domains, effectiveSettings)
        if (started) {
            this._setAuthoritativeScanResult(this.engine.scanResult)
        }
        return started
    }

    async stopBackgroundScan(options = {}) {
        const scanResult = await this.sessionCoordinator.stopBackgroundScan(options)
        if (scanResult) {
            this._setAuthoritativeScanResult(scanResult, {
                markFinished: !!(scanResult?.finishedAt || scanResult?.finished)
            })
            if (!options?.skipPostStopAnalysis && this.scanResult && (this.scanResult.finishedAt || this.scanResult.finished)) {
                try {
                    await this.analysisService.hydratePersistedRelatedScans(this.scanResult)
                    this._applyAnalysis(this.scanResult, true)
                    await this._flushPersistScanResult()
                } catch (_) { }
            }
        }
        return scanResult
    }


    checkConfirmedAttack(data) {
        this.engine.updateScanResult(null, data)
    }

    async startAutomationSession({ sessionId, tabId, host, domains, settings, policyCode, hooks }) {
        const effectiveSettings = await this._resolveDastRunSettings(settings || {})
        return this.sessionCoordinator.startAutomationSession({
            sessionId,
            tabId,
            host,
            domains,
            settings: effectiveSettings,
            policyCode,
            hooks
        })
    }

    async _resolveDastRunSettings(settings = {}) {
        const effectiveSettings = Object.assign({}, settings || {})
        if (effectiveSettings.rulepack && typeof effectiveSettings.rulepack === 'object') {
            effectiveSettings.dastPackStatus = String(effectiveSettings.dastPackStatus || 'active')
            return effectiveSettings
        }
        const explicitPolicyId = String(effectiveSettings.policyId || '').trim()
        const selectedPolicy = getSelectedDastPolicy()
        const selectedPolicyId = String(selectedPolicy?.id || '').trim()
        const explicitPolicyMode = String(effectiveSettings.dastScanPolicy || '').trim().toUpperCase()
        const explicitBuiltInPolicy = !!explicitPolicyMode && explicitPolicyMode !== 'PORTAL'
        const shouldUsePortal =
            explicitPolicyMode === 'PORTAL'
            || !!explicitPolicyId
            || (!explicitBuiltInPolicy && !!selectedPolicyId)
        if (!shouldUsePortal) {
            effectiveSettings.rulepack = null
            effectiveSettings.dastPackStatus = 'active'
            effectiveSettings.dastPackError = null
            return effectiveSettings
        }

        const apiKey = getPortalApiKey()
        if (!apiKey) {
            const err = new Error('missing_api_key')
            err.code = 'missing_api_key'
            throw err
        }

        const resolved = await portalPolicyRuntimeStore.resolveRulepackForRun({
            apiKey,
            engine: 'DAST',
            policyId: explicitPolicyId || selectedPolicyId,
            policyName: effectiveSettings.policyName || selectedPolicy?.name || null
        })
        if (!resolved?.rulepack) {
            const err = new Error('portal_policy_rulepack_unavailable')
            err.code = 'portal_policy_rulepack_unavailable'
            throw err
        }

        effectiveSettings.rulepack = resolved.rulepack
        if (resolved.selection?.policyId) effectiveSettings.policyId = resolved.selection.policyId
        if (resolved.selection?.policyName) effectiveSettings.policyName = resolved.selection.policyName
        effectiveSettings.dastScanPolicy = 'PORTAL'
        const policyState = getDastPolicyState()
        effectiveSettings.dastPackStatus = getDastPackStatusForSelection(resolved.selection || getDastRulepackSelection(), policyState)
        effectiveSettings.dastPackError = cloneForTransport(policyState?.lastError || null)
        return effectiveSettings
    }

    async stopAutomationSession(sessionId, timeoutMs = 180000) {
        return this.sessionCoordinator.stopAutomationSession(sessionId, timeoutMs)
    }

    _collectSeverityStats(scanResult = this.scanResult) {
        const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 }
        const normalize = (value) => {
            const sev = typeof value === 'string' ? value.toLowerCase() : ''
            if (sev.includes('critical')) return 'critical'
            if (sev.includes('high')) return 'high'
            if (sev.includes('medium')) return 'medium'
            if (sev.includes('low')) return 'low'
            if (sev.includes('info')) return 'info'
            return 'info'
        }
        const accumulate = (severity) => {
            const sev = normalize(severity)
            counts[sev] = (counts[sev] || 0) + 1
        }
        const sourceScan = scanResult && typeof scanResult === 'object' ? scanResult : this.scanResult
        const rawFindings = Array.isArray(sourceScan?.findings) ? sourceScan.findings : []
        const findings = collapseDastAggregatedFindings(rawFindings)
        if (rawFindings.length) {
            findings.forEach(finding => accumulate(finding?.severity))
        } else {
            const requests = Array.isArray(sourceScan?.requests) ? sourceScan.requests : []
            if (requests.length) {
                requests.forEach(record => {
                    const attacks = Array.isArray(record?.attacks) ? record.attacks : []
                    attacks.forEach(attack => {
                        if (attack?.success) {
                            accumulate(attack?.severity || attack?.metadata?.severity)
                        }
                    })
                })
            } else {
                const items = Array.isArray(sourceScan?.items) ? sourceScan.items : []
                for (const item of items) {
                    const attacks = Array.isArray(item?.attacks) ? item.attacks : []
                    attacks.forEach(attack => {
                        if (attack?.success) {
                            accumulate(attack?.severity || attack?.metadata?.severity)
                        }
                    })
                }
            }
        }
        const stats = sourceScan?.stats || {}
        const findingsFromCounts = counts.info + counts.low + counts.medium + counts.high + counts.critical
        const findingsCount = rawFindings.length
            ? findingsFromCounts
            : (stats?.findingsCount && stats.findingsCount > findingsFromCounts
            ? stats.findingsCount
            : findingsFromCounts)
        return { counts, findingsCount }
    }

    getAutomationStats() {
        return this.sessionCoordinator.getAutomationStats()
    }
}
