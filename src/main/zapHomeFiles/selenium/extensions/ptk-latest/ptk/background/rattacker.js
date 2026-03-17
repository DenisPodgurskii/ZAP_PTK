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
import { scanResultStore } from "./scanResultStore.js"


const worker = self

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
const ANALYSIS_DIFF_BASE_STORAGE_KEY = "ptk_dast_analysis_diff_base_v1"
const ANALYSIS_SUPPRESSIONS_STORAGE_KEY = "ptk_dast_analysis_suppressions_v1"
const POPUP_TO_BACKGROUND_CHANNELS = new Set(["ptk_popup2background_dast", "ptk_popup2background_rattacker"])
const CONTENT_TO_BACKGROUND_CHANNELS = new Set(["ptk_content2dast", "ptk_content2rattacker"])
const CONTENT_WS_TO_BACKGROUND_CHANNELS = new Set(["ptk_contentws2dast", "ptk_contentws2rattacker"])

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
            getModules: () => this.engine?.modules || [],
            sanitizeUiValue: (value, depth = 0, limits = UI_SCAN_RESULT_LIMITS) => this._sanitizeUiValue(value, depth, limits),
            uiLimits: UI_SCAN_RESULT_LIMITS
        })
        this.candidateRunService = new DastCandidateRunService({
            settings: this.settings,
            getScanResult: () => this.scanResult,
            getCandidate: (candidateId) => this._findAnalysisCandidate(candidateId),
            getRequestRecordById: (requestId) => this.findingPresentationService.findRequestRecordById(this.scanResult, requestId)
        })
        if (this.engine?.setResultMutationListener) {
            this.engine.setResultMutationListener(() => {
                this._setAuthoritativeScanResult(this.engine.scanResult, {
                    markFinished: !!(this.engine?.scanResult?.finishedAt || this.engine?.scanResult?.finished)
                })
                this._schedulePersistScanResult()
            })
        }
        this.addMessageListeners()
        this.regularModulesCache = null
        this.cveModulesCache = null
    }


    async init() {
        await this._ensureDefaultModulesReady()
        this.storage = await this.scanResultLifecycle.loadPersistedScan() || {}
        await this.analysisService.loadState()
        if (!this.engine.isRunning && Object.keys(this.storage).length > 0) {
            this.scanResult = this.storage
        } else {
            this.scanResult = this._setAuthoritativeScanResult(this.engine.scanResult)
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

    _cloneScanResultForUi() {
        return this.resultProjector.cloneScanResultForUi(this.scanResult || {}, {
            engineIsRunning: this.engine?.isRunning === true
        })
    }

    _sanitizeUiValue(value, depth = 0, limits = UI_SCAN_RESULT_LIMITS) {
        return this.resultProjector.sanitizeUiValue(value, depth, limits)
    }

    _setAuthoritativeScanResult(scanResult, { markFinished = false } = {}) {
        const synced = this.scanResultLifecycle.syncScanResult(scanResult, { markFinished })
        this.scanResult = synced || scanResult || this.engine?.scanResult || {}
        return this.scanResult
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
        if (this._persistTimer) {
            clearTimeout(this._persistTimer)
            this._persistTimer = null
        }
        this.scanResultLifecycle.deleteScan(previousScanId)
        this.engine.reset()
        this.scanResult = this.engine.scanResult
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
        await this.analysisService.hydratePersistedRelatedScans(this.scanResult)
        if (this.scanResult && typeof this.scanResult === "object") {
            this._applyAnalysis(this.scanResult, false)
        }
        const defaultModules = await this.getRegularModules()
        const cveModules = await this.getCveModules()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi(),
            isScanRunning: this.engine.isRunning,
            default_modules: defaultModules,
            cve_modules: cveModules,
            activeTab: worker.ptk_app.proxy.activeTab,
            settings: this.settings
        })
    }

    async msg_get_request_snapshot(message) {
        return Promise.resolve(
            this.findingPresentationService.getRequestSnapshot(this.scanResult, {
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
            constraints: message?.constraints || {}
        })
    }

    async msg_get_candidate_playwright_run(message) {
        return this.candidateRunService.getCandidatePlaywrightRun({
            candidateId: message?.candidateId || null
        })
    }

    async msg_get_finding_details(message) {
        return Promise.resolve(
            this.findingPresentationService.getFindingDetails(this.scanResult, {
                findingId: message?.findingId || null,
                requestId: message?.requestId || null,
                attackId: message?.attackId || null,
                moduleId: message?.moduleId || null
            })
        )
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
        return this.portalClient.saveScan(worker.ptk_app.settings.profile || {}, this.scanResult, {
            projectId: message?.projectId || null
        })
    }

    async msg_export_scan_result(message) {
        if (!this.scanResult || Object.keys(this.scanResult).length === 0) {
            this.scanResult = await this.scanResultLifecycle.loadPersistedScan()
        }
        if (!this.scanResult) return null
        try {
            return await this.exportService.createChunkedExport(this.scanResult, {
                target: message?.target || "download",
                fileName: message?.fileName || "PTK_DAST_scan.json"
            })
        } catch (err) {
            console.error("[PTK DAST] Failed to export scan result", err)
            throw err
        }
    }

    async msg_export_scan_chunk(message) {
        return this.exportService.getChunk(message?.exportId, message?.index)
    }

    async msg_release_export_scan(message) {
        return this.exportService.release(message?.exportId)
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
        const response = await this.portalClient.downloadScanById(worker.ptk_app.settings.profile || {}, message?.scanId)
        if (!response?.success || !response?.scanResult) {
            return response
        }
        this.scanResult = response.scanResult
        if (this.scanResult && (this.scanResult.finishedAt || this.scanResult.finished)) {
            try {
                this._applyAnalysis(this.scanResult, false)
            } catch (_) { }
        }
        await this._flushPersistScanResult()
        return this._cloneScanResultForUi()
    }

    async msg_delete_scan_by_id(message) {
        let apiKey = worker.ptk_app.settings.profile?.api_key
        if (apiKey) {
            const baseUrl = this.portalClient.buildPortalUrl(worker.ptk_app.settings.profile?.storage_endpoint, worker.ptk_app.settings.profile || {})
            if (!baseUrl) {
                return { success: false, json: { message: "Portal endpoint is not configured." } }
            }
            let url = baseUrl + "/" + message.scanId
            let response = await fetch(url, {
                method: "DELETE",
                headers: {
                    'Authorization': apiKey,
                },
                cache: "no-cache"
            })
                .then(response => response.json())
                .then(json => {
                    this.scanResult = json
                    return json
                }).catch(e => e)
            return response
        }
    }

    async msg_reset(message) {
        this.reset()
        const defaultModules = await this.getRegularModules()
        const cveModules = await this.getCveModules()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi(),
            default_modules: defaultModules,
            cve_modules: cveModules,
            activeTab: worker.ptk_app.proxy.activeTab
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

    async msg_save(message) {
        const raw = JSON.parse(message.json || "{}")
        const normalized = this.scanResultLifecycle.hydrateImportedScan(raw)
        if (!normalized) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        this.reset()
        this.scanResult = normalized
        if (this.scanResult && (this.scanResult.finishedAt || this.scanResult.finished)) {
            try {
                this._applyAnalysis(this.scanResult, false)
            } catch (_) { }
        }
        await this._flushPersistScanResult()
        const defaultModules = await this.getRegularModules()
        const cveModules = await this.getCveModules()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi(),
            isScanRunning: this.engine.isRunning,
            default_modules: defaultModules,
            cve_modules: cveModules,
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }

    msg_run_bg_scan(message) {
        this.runBackgroundScan(message.tabId, message.host, message.domains, message.settings)
        return Promise.resolve({ isScanRunning: this.engine.isRunning, scanResult: this._cloneScanResultForUi() })
    }

    async msg_stop_bg_scan(message) {
        await this.stopBackgroundScan()
        return Promise.resolve({ scanResult: this._cloneScanResultForUi() })
    }

    runBackgroundScan(tabId, host, domains, settings) {
        const started = this.sessionCoordinator.runBackgroundScan(tabId, host, domains, settings)
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
        }
        return scanResult
    }


    checkConfirmedAttack(data) {
        this.engine.updateScanResult(null, data)
    }

    async startAutomationSession({ sessionId, tabId, host, domains, settings, policyCode, hooks }) {
        return this.sessionCoordinator.startAutomationSession({ sessionId, tabId, host, domains, settings, policyCode, hooks })
    }

    async stopAutomationSession(sessionId, timeoutMs = 180000) {
        return this.sessionCoordinator.stopAutomationSession(sessionId, timeoutMs)
    }

    _collectSeverityStats() {
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
        const findings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings : []
        if (findings.length) {
            findings.forEach(finding => accumulate(finding?.severity))
        } else {
            const requests = Array.isArray(this.scanResult?.requests) ? this.scanResult.requests : []
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
                const items = Array.isArray(this.scanResult?.items) ? this.scanResult.items : []
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
        const stats = this.scanResult?.stats || {}
        const findingsFromCounts = counts.info + counts.low + counts.medium + counts.high + counts.critical
        const findingsCount = stats?.findingsCount && stats.findingsCount > findingsFromCounts
            ? stats.findingsCount
            : findingsFromCounts
        return { counts, findingsCount }
    }

    getAutomationStats() {
        return this.sessionCoordinator.getAutomationStats()
    }
}
