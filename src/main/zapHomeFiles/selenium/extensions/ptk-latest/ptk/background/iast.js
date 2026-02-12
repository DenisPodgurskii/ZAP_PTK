/* Author: Denis Podgurskii */
import { ptk_utils, ptk_logger, ptk_queue, ptk_storage, ptk_ruleManager } from "../background/utils.js"
import { createFindingFromIAST, getIastEvidencePayload } from "./iast/modules/reporting.js"
import { loadRulepack } from "./common/moduleRegistry.js"
import { scanResultStore } from "./scanResultStore.js"
import {
    normalizeRulepack,
    normalizeSeverityValue,
    resolveEffectiveSeverity
} from "./common/severity_utils.js"
import buildExportScanResult from "./export/buildExportScanResult.js"

const activeIastTabs = new Set()
let iastModulesCache = null
let iastScanStrategy = 'SMART'
function mergeLinks(baseLinks, overrideLinks) {
    const result = Object.assign({}, baseLinks || {})
    if (overrideLinks && typeof overrideLinks === "object") {
        Object.entries(overrideLinks).forEach(([key, value]) => {
            if (key) result[key] = value
        })
    }
    return Object.keys(result).length ? result : null
}

function buildIastRuleIndex(rulepack) {
    iastRuleMetaIndex = new Map()
    iastModuleMetaIndex = new Map()
    const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
    modules.forEach((mod) => {
        const moduleMeta = mod?.metadata || {}
        const base = {
            moduleId: mod?.id || null,
            moduleName: mod?.name || mod?.id || null,
            vulnId: mod?.vulnId || moduleMeta.vulnId || mod?.id || null,
            category: moduleMeta.category || null,
            severity: moduleMeta.severity || null,
            owasp: moduleMeta.owasp || null,
            cwe: moduleMeta.cwe || null,
            tags: moduleMeta.tags || [],
            description: moduleMeta.description || null,
            recommendation: moduleMeta.recommendation || null,
            links: moduleMeta.links || null
        }
        iastModuleMetaIndex.set(base.moduleId, {
            id: base.moduleId,
            name: base.moduleName,
            metadata: moduleMeta,
            vulnId: base.vulnId,
            category: base.category,
            severity: base.severity,
            links: base.links,
            tags: base.tags,
            description: base.description,
            recommendation: base.recommendation
        })
        const rules = Array.isArray(mod?.rules) ? mod.rules : []
        rules.forEach(rule => {
            const ruleMeta = rule?.metadata || {}
            if (!rule?.id) return
            const mergedLinks = mergeLinks(base.links, ruleMeta.links)
            iastRuleMetaIndex.set(rule.id, {
                moduleId: base.moduleId,
                moduleName: base.moduleName,
                ruleName: rule?.name || rule?.id || null,
                vulnId: base.vulnId,
                category: ruleMeta.category || base.category,
                severity: resolveEffectiveSeverity({
                    moduleMeta,
                    ruleMeta
                }),
                owasp: ruleMeta.owasp || base.owasp,
                cwe: ruleMeta.cwe || base.cwe,
                tags: ruleMeta.tags || base.tags,
                description: ruleMeta.description || base.description || null,
                recommendation: ruleMeta.recommendation || base.recommendation || null,
                links: mergedLinks,
                moduleMeta: iastModuleMetaIndex.get(base.moduleId),
                ruleMeta: {
                    id: rule?.id || null,
                    name: rule?.name || rule?.id || null,
                    metadata: ruleMeta
                }
            })
        })
    })
}

function getIastRuleMeta(ruleId) {
    if (!ruleId) return null
    return iastRuleMetaIndex.get(ruleId) || null
}
let iastRuleMetaIndex = new Map()
let iastModuleMetaIndex = new Map()

function getIastModuleMeta(moduleId) {
    if (!moduleId) return null
    return iastModuleMetaIndex.get(moduleId) || null
}

function getRuntime() {
    if (typeof chrome !== 'undefined' && chrome.runtime) return chrome
    if (typeof browser !== 'undefined' && browser.runtime) return browser
    return null
}

async function loadIastModules() {
    if (iastModulesCache) return iastModulesCache
    try {
        const rulepack = await loadRulepack('IAST')
        normalizeRulepack(rulepack, { engine: 'IAST', childKey: 'rules' })
        iastModulesCache = rulepack
        buildIastRuleIndex(rulepack)
        //console.log('[PTK IAST BG] Loaded IAST rulepack')
        return iastModulesCache
    } catch (e) {
        console.error('[PTK IAST BG] Error loading IAST rulepack:', e)
        iastModulesCache = null
        return null
    }
}

async function sendIastModulesToContent(tabId, attempt = 1) {
    const modules = await loadIastModules()
    if (!modules) {
        console.warn('[PTK IAST BG] No IAST modules to send to tab', tabId)
        return
    }
    const rt = getRuntime()
    if (!rt || !rt.tabs?.sendMessage) {
        console.warn('[PTK IAST BG] tabs.sendMessage unavailable')
        return
    }
    try {
        rt.tabs.sendMessage(
            tabId,
            {
                channel: 'ptk_background_iast2content_modules',
                iastModules: modules,
                scanStrategy: iastScanStrategy
            },
            () => {
                const err = rt.runtime.lastError
                if (err) {
                    console.warn('[PTK IAST BG] Error sending IAST modules to tab', tabId, err.message)
                    if (attempt < 5) {
                        setTimeout(() => {
                            sendIastModulesToContent(tabId, attempt + 1)
                        }, 700)
                    }
                } else {
                    //console.log('[PTK IAST BG] Sent IAST modules to tab', tabId)
                }
            }
        )
    } catch (e) {
        console.error('[PTK IAST BG] Exception sending IAST modules to tab', tabId, e)
    }
}


const worker = self
const MAX_HTTP_EVENTS = 1000
const MAX_TRACKED_REQUESTS = 500
const SEVERITY_ORDER = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
}

function isHttpUrl(url) {
    if (!url) return false
    return /^https?:\/\//i.test(String(url))
}

export class ptk_iast {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_iast"
        this.devtoolsAttached = false
        this.devtoolsTarget = null
        this.onDevtoolsEvent = null
        this.agentReadyTabs = new Set()
        this.agentFailedTabs = new Map()
        this.maxHttpEvents = MAX_HTTP_EVENTS
        this.maxTrackedRequests = MAX_TRACKED_REQUESTS
        this.requestLookup = new Map()
        this._requestLookupByUrl = new Map()
        this._pagesByKey = new Map()
        this._pagesByUrl = new Map()
        this._pageFindingIds = new Map()
        this._missingPageCounter = 0
        this._persistTimer = null
        this._persistDebounceMs = 1000
        this.resetScanResult()
        this.modulesCatalog = null

        this.addMessageListeners()
    }

    async init() {
        if (!this.isScanRunning) {
            await loadIastModules()
            const stored = await ptk_storage.getItem(this.storageKey) || {}
            if (stored && ((stored.scanResult) || Object.keys(stored).length > 0)) {
                await this.normalizeScanResult(stored)
            }
        }
    }

    resetScanResult() {
        this.unregisterScript()
        this.detachDevtoolsDebugger()
        this.isScanRunning = false
        if (this.currentScanId) {
            scanResultStore.deleteScan(this.currentScanId)
        }
        this.scanResult = this.getScanResultSchema()
        this.currentScanId = this.scanResult?.scanId || null
        this.requestLookup = new Map()
        this._requestLookupByUrl = new Map()
        this._resetPageIndexes()
        if (this._persistTimer) {
            clearTimeout(this._persistTimer)
            this._persistTimer = null
        }
    }

    async getDefaultModules(rulepack = null) {
        try {
            const loaded = rulepack || await loadIastModules()
            const modules = Array.isArray(loaded?.modules) ? loaded.modules : []
            return JSON.parse(JSON.stringify(modules))
        } catch (err) {
            console.warn('[PTK IAST] Failed to load default modules', err)
            return []
        }
    }

    getScanResultSchema({ scanId = null, host = null, startedAt = null } = {}) {
        return scanResultStore.createScan({
            engine: "IAST",
            scanId: scanId || ptk_utils.UUID(),
            host,
            startedAt: startedAt || new Date().toISOString(),
            settings: {},
            extraFields: {
                httpEvents: [],
                runtimeEvents: [],
                requests: [],
                pages: [],
                files: []
            }
        })
    }

    persistScanResult() {
        const scanId = this.scanResult?.scanId || this.currentScanId
        const source = scanId ? scanResultStore.exportScanResult(scanId) : this.scanResult
        const cloned = this._cloneForStorage(source, { dropTabId: true }) || {}
        if (Array.isArray(cloned.rawFindings)) {
            delete cloned.rawFindings
        }
        ptk_storage.setItem(this.storageKey, cloned)
    }

    _schedulePersistScanResult() {
        if (this._persistTimer) return
        this._persistTimer = setTimeout(() => {
            this._persistTimer = null
            // Debounce storage writes to reduce MV2 overhead.
            this.persistScanResult()
        }, this._persistDebounceMs)
    }

    _flushPersistScanResult() {
        if (this._persistTimer) {
            clearTimeout(this._persistTimer)
            this._persistTimer = null
        }
        this.persistScanResult()
    }

    _cloneForStorage(value, { dropTabId = false } = {}) {
        try {
            const cloned = JSON.parse(JSON.stringify(value ?? (Array.isArray(value) ? [] : {})))
            if (dropTabId && cloned && typeof cloned === "object") {
                delete cloned.tabId
            }
            return cloned
        } catch (_) {
            return value
        }
    }

    _getPublicScanResult() {
        const scanId = this.scanResult?.scanId || this.currentScanId
        const exported = scanId ? scanResultStore.exportScanResult(scanId) : this.scanResult
        const clone = this._cloneForStorage(exported, { dropTabId: true })
        if (clone && typeof clone === "object") {
            clone.__normalized = true
        }
        return clone
    }

    _extractPersistedData(raw) {
        const fallback = { scanResult: this.getScanResultSchema(), rawFindings: [] }
        if (!raw || typeof raw !== "object") {
            return fallback
        }
        let scanPayload = null
        let legacyRaw = []
        if (raw.scanResult && typeof raw.scanResult === "object") {
            scanPayload = raw.scanResult
            legacyRaw = Array.isArray(raw.rawFindings) ? raw.rawFindings : []
        } else if (raw.engine || raw.version || Array.isArray(raw.findings)) {
            scanPayload = raw
        } else {
            scanPayload = raw
            legacyRaw = Array.isArray(raw.rawFindings) ? raw.rawFindings : Array.isArray(raw.items) ? raw.items : []
        }
        const scanClone = this._cloneForStorage(scanPayload)
        const embeddedRaw = Array.isArray(scanClone?.rawFindings) ? scanClone.rawFindings : []
        return {
            scanResult: scanClone,
            rawFindings: this._cloneForStorage(embeddedRaw.length ? embeddedRaw : legacyRaw)
        }
    }

    async reset() {
        this.resetScanResult()
        await ptk_storage.setItem(this.storageKey, {})
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    addListeners() {
        this.onRemoved = this.onRemoved.bind(this)
        browser.tabs.onRemoved.addListener(this.onRemoved)

        this.onUpdated = this.onUpdated.bind(this)
        browser.tabs.onUpdated.addListener(this.onUpdated)

        this.onCompleted = this.onCompleted.bind(this)
        browser.webRequest.onCompleted.addListener(
            this.onCompleted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )
    }

    async onUpdated(tabId, info, tab) {

    }

    removeListeners() {
        browser.tabs.onRemoved.removeListener(this.onRemoved)
        browser.tabs.onUpdated.removeListener(this.onUpdated)
        browser.webRequest.onCompleted.removeListener(this.onCompleted)
    }

    onRemoved(tabId, info) {
        if (this.scanResult?.tabId == tabId) {
            this.scanResult.tabId = null
            this.isScanRunning = false
            this.detachDevtoolsDebugger()
        }
    }

    onCompleted(response) {
        if (!this.isScanRunning) return
        if (!this.scanResult?.tabId || response.tabId !== this.scanResult.tabId) return

        if (this.scanResult.host) {
            try {
                const url = new URL(response.url)
                if (url.host !== this.scanResult.host) return
            } catch (e) {
                // ignore malformed URLs
            }
        }
        if (!isHttpUrl(response.url)) return

        const evt = {
            type: "http",
            time: Date.now(),
            requestId: response.requestId,
            url: response.url,
            method: response.method || null,
            status: response.statusCode,
            ip: response.ip || null,
            fromCache: !!response.fromCache,
            tabId: response.tabId,
            host: this.scanResult.host
        }

        this.recordHttpEvent(evt)
    }

    onMessage(message, sender, sendResponse) {

        if (message.channel == "ptk_popup2background_iast") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (message.channel == "ptk_content2iast") {

            if (message.type == 'check') {
                //console.log('check iast')
                if (this.isScanRunning && this.scanResult.tabId == sender.tab.id)
                    return Promise.resolve({ loadAgent: true })
                else
                    return Promise.resolve({ loadAgent: false })
            }
        }

        if (message.channel == "ptk_content_iast2background_iast") {

            if (message.type == 'finding_report') {
                if (this.isScanRunning && this.scanResult.tabId == sender.tab.id) {
                    try {
                        const finding = createFindingFromIAST(message.finding, {
                            scanId: this.scanResult.scanId,
                            host: this.scanResult.host,
                            tabId: this.scanResult.tabId
                        })
                        this.addOrUpdateFinding(finding)
                    } catch (e) {
                        console.warn('[PTK IAST][background] createFindingFromIAST failed', e)
                    }
                } else {
                    // Ignore findings when scan is not active or tab mismatches.
                }
                return
            }

            if (message.type === 'agent_ready') {
                const tabId = sender?.tab?.id
                if (tabId != null) {
                    this.agentReadyTabs.add(tabId)
                    this.agentFailedTabs.delete(tabId)
                    sendIastModulesToContent(tabId)
                }
                return
            }

            if (message.type === 'agent_failed') {
                const tabId = sender?.tab?.id
                if (tabId != null) {
                    this.agentReadyTabs.delete(tabId)
                    this.agentFailedTabs.set(tabId, message?.error || 'agent_load_failed')
                    try { console.warn('[PTK IAST] Agent load failed for tab', tabId, message?.error || 'agent_load_failed') } catch (_) { }
                }
                return
            }
        }

        if (message.channel === "ptk_content_iast2background_request_modules") {
            ;(async () => {
                try {
                    const modules = await loadIastModules()
                    if (!modules) {
                        console.warn('[PTK IAST BG] No IAST modules available for request')
                        sendResponse && sendResponse({ iastModules: null, scanStrategy: iastScanStrategy })
                        return
                    }
                    const tabId = sender?.tab?.id
                    //console.log('[PTK IAST BG] Content requested IAST modules for tab', tabId)
                    sendResponse && sendResponse({ iastModules: modules, scanStrategy: iastScanStrategy })
                } catch (err) {
                    console.warn('[PTK IAST BG] Failed to load IAST modules', err)
                    sendResponse && sendResponse({ iastModules: null, scanStrategy: iastScanStrategy, error: err?.message || String(err) })
                }
            })()
            return true
        }
    }

    updateScanResult({ persist = true, immediate = false } = {}) {
        if (!this.scanResult) {
            this.scanResult = this.getScanResultSchema()
            this.currentScanId = this.scanResult?.scanId || null
        }
        if (!this.scanResult.stats || typeof this.scanResult.stats !== "object") {
            this.scanResult.stats = { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        }
        this.scanResult.stats.requestsCount = Array.isArray(this.scanResult.requests)
            ? this.scanResult.requests.length
            : 0
        if (persist) {
            if (immediate) {
                this._flushPersistScanResult()
            } else {
                this._schedulePersistScanResult()
            }
        }
    }

    async msg_init(message) {
        await this.init()
        const defaultModules = await this.getDefaultModules()
        return Promise.resolve({
            scanResult: this._getPublicScanResult(),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab,
            default_modules: defaultModules
        })
    }


    async msg_reset(message) {
        this.reset()
        const defaultModules = await this.getDefaultModules()
        return Promise.resolve({
            scanResult: this._getPublicScanResult(),
            activeTab: worker.ptk_app.proxy.activeTab,
            default_modules: defaultModules
        })
    }

    async msg_loadfile(message) {
        this.reset()
        //await this.init()

        return new Promise((resolve, reject) => {
            var fr = new FileReader()
            fr.onload = () => {

                resolve(this.msg_save(fr.result))
            }
            fr.onerror = reject
            fr.readAsText(message.file)
        })

    }

    async msg_save(message) {
        let res = JSON.parse(message.json)
        const isIast = (typeof res.engine === "string" && res.engine.toUpperCase() === "IAST") ||
            (typeof res.type === "string" && res.type.toLowerCase() === "iast")
        const hasFindings = Array.isArray(res.findings) && res.findings.length > 0
        const hasLegacyItems = Array.isArray(res.items) && res.items.length > 0
        if (!isIast || (!hasFindings && !hasLegacyItems)) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        this.reset()
        await loadIastModules()
        await this.normalizeScanResult(res)
        this.updateScanResult({ persist: true, immediate: true })
        const defaultModules = await this.getDefaultModules()
        return {
            scanResult: this._getPublicScanResult(),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab,
            default_modules: defaultModules
        }
    }

    async msg_export_scan_result(message) {
        const scanId = this.scanResult?.scanId || this.currentScanId || null
        if (!scanId) return null
        try {
            return buildExportScanResult(scanId, {
                target: message?.target || "download",
                scanResult: this.scanResult
            })
        } catch (err) {
            console.error("[PTK IAST] Failed to export scan result", err)
            throw err
        }
    }

    msg_run_bg_scan(message) {
        return this.runBackgroundScan(message.tabId, message.host, message.scanStrategy).then(async () => {
            const defaultModules = await this.getDefaultModules()
            return { isScanRunning: this.isScanRunning, scanResult: this._getPublicScanResult(), default_modules: defaultModules }
        })
    }

    msg_stop_bg_scan(message) {
        this.stopBackgroundScan()
        return Promise.resolve({ scanResult: this._getPublicScanResult() })
    }

    async runBackgroundScan(tabId, host, scanStrategy) {
        if (this.isScanRunning) {
            return false
        }
        this.reset()
        this.agentReadyTabs.delete(tabId)
        this.agentFailedTabs.delete(tabId)
        this.isScanRunning = true
        this.scanningRequest = false
        browser.tabs.sendMessage(tabId, {
            channel: "ptk_background_iast2content",
            type: "clean iast result"
        }).catch(() => { })
        const scanId = ptk_utils.UUID()
        const started = new Date().toISOString()
        this.scanResult = this.getScanResultSchema({ scanId, host, startedAt: started })
        this.scanResult.tabId = tabId
        this.scanResult.host = host
        this.scanResult.startedAt = started
        this.scanResult.finishedAt = null
        this.scanResult.settings = Object.assign({}, this.scanResult.settings || {}, {
            iastScanStrategy: scanStrategy || 'SMART'
        })
        iastScanStrategy = this.scanResult.settings.iastScanStrategy
        this.currentScanId = scanId
        activeIastTabs.add(tabId)
        this.registerScript()
        // Inject agent into current page (MV2 path uses tabs.executeScript for Firefox)
        await this.injectIastAgent(tabId)
        this.addListeners()
        this.attachDevtoolsDebugger(tabId)
        await loadIastModules()
        await sendIastModulesToContent(tabId)
        this.broadcastScanUpdate()
    }

    stopBackgroundScan() {
        browser.tabs.sendMessage(this.scanResult.tabId, {
            channel: "ptk_background_iast2content",
            type: "clean iast result"
        }).catch(() => { })
        this.isScanRunning = false
        activeIastTabs.delete(this.scanResult.tabId)
        if (this.scanResult?.tabId != null) {
            this.agentReadyTabs.delete(this.scanResult.tabId)
            this.agentFailedTabs.delete(this.scanResult.tabId)
        }
        this.scanResult.tabId = null
        this.unregisterScript()
        this.removeListeners()
        this.detachDevtoolsDebugger()
        if (this.scanResult?.scanId) {
            const finished = new Date().toISOString()
            scanResultStore.setFinished(this.scanResult.scanId, finished)
            this.scanResult.finishedAt = finished
        }
        this._flushPersistScanResult()
        this.broadcastScanUpdate()
    }

    recordHttpEvent(evt) {
        if (!evt || !isHttpUrl(evt.url)) return
        if (!this.scanResult.httpEvents) {
            this.scanResult.httpEvents = []
        }
        this.scanResult.httpEvents.push(evt)
        this.upsertRequestFromEvent(evt)
        if (this.scanResult.httpEvents.length > this.maxHttpEvents) {
            this.scanResult.httpEvents.shift()
        }
        if (!this.scanResult.stats || typeof this.scanResult.stats !== "object") {
            this.scanResult.stats = { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        }
        this.scanResult.stats.requestsCount = Array.isArray(this.scanResult.requests)
            ? this.scanResult.requests.length
            : 0
        this._schedulePersistScanResult()
    }

    addOrUpdateFinding(finding) {
        if (!finding || !this.scanResult?.scanId) return
        let prepared
        try {
            prepared = this.prepareFindingMetadata(finding)
        } catch (e) {
            try { console.warn('[PTK IAST][background] prepareFindingMetadata failed', e) } catch (_) { }
            return
        }
        if (!prepared) return
        scanResultStore.upsertFinding({
            scanId: this.scanResult.scanId,
            engine: "IAST",
            finding: prepared.finding,
            moduleMeta: prepared.moduleMeta,
            ruleMeta: prepared.ruleMeta
        })
        this._upsertPageFromFinding(prepared.finding)
        this.updateScanResult()
        this.broadcastScanDelta(prepared.finding)
    }

    async normalizeScanResult(raw) {
        await loadIastModules()
        const payload = this._extractPersistedData(raw || {})
        const source = payload.scanResult || {}
        const scanId = source.scanId || ptk_utils.UUID()
        this.scanResult = this.getScanResultSchema({
            scanId,
            host: source.host || null,
            startedAt: source.startedAt || source.date || new Date().toISOString()
        })
        this.scanResult.tabId = source.tabId || null
        this.scanResult.policyId = source.policyId || null
        this.scanResult.settings = source.settings || {}
        this.scanResult.httpEvents = Array.isArray(source.httpEvents) ? source.httpEvents : []
        this.scanResult.runtimeEvents = Array.isArray(source.runtimeEvents) ? source.runtimeEvents : []
        this.scanResult.requests = Array.isArray(source.requests) ? source.requests : []
        this.scanResult.pages = Array.isArray(source.pages) ? source.pages : []
        this.scanResult.files = Array.isArray(source.files) ? source.files : []
        this.scanResult.finishedAt = source.finishedAt || source.finished || null
        this.currentScanId = scanId

        const hydratedFindings = Array.isArray(source.findings) ? source.findings : []
        hydratedFindings.forEach(item => {
            try {
                const prepared = this.prepareFindingMetadata(item)
                if (!prepared) return
                scanResultStore.upsertFinding({
                    scanId,
                    engine: "IAST",
                    finding: prepared.finding,
                    moduleMeta: prepared.moduleMeta,
                    ruleMeta: prepared.ruleMeta
                })
            } catch (err) {
                try { console.warn("[PTK IAST] Failed to hydrate finding", err) } catch (_) { }
            }
        })

        this._ingestLegacyRawFindings(Array.isArray(payload.rawFindings) ? payload.rawFindings : [])
        if (Array.isArray(source.rawFindings) && source.rawFindings.length) {
            this._ingestLegacyRawFindings(source.rawFindings)
        }
        if (Array.isArray(this.scanResult.rawFindings)) {
            delete this.scanResult.rawFindings
        }
        this.requestLookup = new Map()
        if (Array.isArray(this.scanResult.requests)) {
            this.scanResult.requests.forEach(entry => {
                if (entry?.key) {
                    this.requestLookup.set(entry.key, entry)
                }
                if (entry?.url) {
                    this._requestLookupByUrl.set(entry.url, entry)
                }
            })
        }
        this._rebuildPagesFromFindings()
        this.updateScanResult({ persist: false })
        return this.scanResult
    }

    normalizeRequestUrl(url) {
        if (!url) return ""
        try {
            const u = new URL(url)
            u.hash = ""
            return u.toString()
        } catch (e) {
            try {
                return String(url).split('#')[0]
            } catch (_) {
                return ""
            }
        }
    }

    buildRequestKey(method, url) {
        const normalizedUrl = this.normalizeRequestUrl(url)
        if (!normalizedUrl) return null
        const normalizedMethod = (method || 'GET').toUpperCase()
        return normalizedMethod + ' ' + normalizedUrl
    }

    trimTrackedRequests() {
        if (!Array.isArray(this.scanResult.requests)) return
        if (this.scanResult.requests.length <= this.maxTrackedRequests) return
        const overflow = this.scanResult.requests.length - this.maxTrackedRequests
        if (overflow <= 0) return
        const removed = this.scanResult.requests.splice(0, overflow)
        removed.forEach(entry => {
            if (entry?.key) {
                this.requestLookup.delete(entry.key)
            }
            if (entry?.url) {
                this._requestLookupByUrl.delete(entry.url)
            }
        })
    }

    _ingestLegacyRawFindings(rawList) {
        if (!Array.isArray(rawList) || !rawList.length || !this.scanResult?.scanId) return
        rawList.forEach(item => {
            if (!item) return
            try {
                const prepared = this.prepareFindingMetadata(item)
                if (!prepared) return
                scanResultStore.upsertFinding({
                    scanId: this.scanResult.scanId,
                    engine: "IAST",
                    finding: prepared.finding,
                    moduleMeta: prepared.moduleMeta,
                    ruleMeta: prepared.ruleMeta
                })
            } catch (e) {
                try { console.warn('[PTK IAST][background] failed to ingest legacy finding', e) } catch (_) { }
            }
        })
    }

    upsertRequestFromEvent(evt) {
        if (!evt) return
        if (!Array.isArray(this.scanResult.requests)) {
            this.scanResult.requests = []
        }
        const url = evt?.url
        if (!url || !isHttpUrl(url)) return
        const method = evt?.method || 'GET'
        const key = this.buildRequestKey(method, url)
        if (!key) return
        let entry = this.requestLookup.get(key)
        const status = evt?.status || evt?.statusCode || null
        const lastSeen = evt?.time || Date.now()
        if (entry) {
            if (status) entry.status = status
            entry.lastSeen = lastSeen
            entry.type = evt?.type || entry.type
        } else {
            entry = {
                key,
                method: (method || 'GET').toUpperCase(),
                url: this.normalizeRequestUrl(url),
                displayUrl: url,
                status,
                host: evt?.host || this.scanResult.host || null,
                type: evt?.type || 'http',
                mimeType: evt?.mimeType || null,
                lastSeen
            }
            this.scanResult.requests.push(entry)
            this.requestLookup.set(key, entry)
            this.trimTrackedRequests()
        }
        if (entry?.url) {
            this._requestLookupByUrl.set(entry.url, entry)
        }
        this._updatePageRequestMetaForEntry(entry)
    }

    _resetPageIndexes() {
        this._pagesByKey = new Map()
        this._pagesByUrl = new Map()
        this._pageFindingIds = new Map()
        this._missingPageCounter = 0
        if (this.scanResult) {
            this.scanResult.pages = []
        }
    }

    _rebuildPagesFromFindings() {
        this._resetPageIndexes()
        const items = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings : []
        items.forEach((finding) => this._upsertPageFromFinding(finding))
    }

    _resolveRequestEntryForFinding(finding) {
        if (!finding) return null
        const directKey = finding?.requestKey
        if (directKey && this.requestLookup.has(directKey)) {
            return this.requestLookup.get(directKey)
        }
        const urls = this.collectFindingUrls(finding)
        const primaryUrl = (urls && urls.length) ? urls[0] : (finding?.location?.url || null)
        if (!primaryUrl) return null
        const normalized = this.normalizeRequestUrl(primaryUrl)
        if (!normalized) return null
        return this._requestLookupByUrl.get(normalized) || this.findRequestMetaForUrl(primaryUrl)
    }

    _resolveRequestKeyForFinding(finding) {
        const entry = this._resolveRequestEntryForFinding(finding)
        return entry?.key || null
    }

    _updatePageRequestMetaForEntry(entry) {
        if (!entry || !entry.url) return
        const key = this._pagesByUrl.get(entry.url)
        if (!key) return
        const page = this._pagesByKey.get(key)
        if (!page) return
        page.requestKey = entry.key || null
        page.requestMeta = {
            method: entry.method || null,
            status: entry.status || null,
            mimeType: entry.mimeType || null
        }
    }

    _upsertPageFromFinding(finding) {
        if (!finding) return
        if (!Array.isArray(this.scanResult.pages)) {
            this.scanResult.pages = []
        }
        const candidateUrls = this.collectFindingUrls(finding)
        const normalizedPrimary = candidateUrls.length ? candidateUrls[0] : null
        const pageUrl = finding?.location?.url || normalizedPrimary || null
        let key = normalizedPrimary || pageUrl || null
        if (!key) {
            const fallbackId = finding?.id || finding?.fingerprint || this._missingPageCounter++
            key = `__missing_url__${fallbackId}`
        }
        let page = this._pagesByKey.get(key)
        if (!page) {
            page = {
                url: pageUrl || normalizedPrimary || null,
                stats: {
                    totalFindings: 0,
                    byCategory: {},
                    bySeverity: {}
                },
                findingIds: [],
                requestKey: null,
                requestMeta: {}
            }
            this._pagesByKey.set(key, page)
            if (normalizedPrimary) {
                const normalizedKey = this.normalizeRequestUrl(normalizedPrimary)
                if (normalizedKey) {
                    this._pagesByUrl.set(normalizedKey, key)
                }
            }
            this.scanResult.pages.push(page)
        }

        const findingId = finding?.id || finding?.fingerprint || null
        let idSet = this._pageFindingIds.get(key)
        if (!idSet) {
            idSet = new Set()
            this._pageFindingIds.set(key, idSet)
        }
        if (findingId && idSet.has(findingId)) {
            return
        }
        if (findingId) {
            idSet.add(findingId)
            page.findingIds.push(findingId)
        }

        const category = finding?.category || "runtime_issue"
        const severity = String(finding?.severity || "info").toLowerCase()
        page.stats.totalFindings += 1
        page.stats.byCategory[category] = (page.stats.byCategory[category] || 0) + 1
        page.stats.bySeverity[severity] = (page.stats.bySeverity[severity] || 0) + 1

        if (!page.requestKey) {
            const match = this._resolveRequestEntryForFinding(finding)
            if (match) {
                page.requestKey = match.key || null
                page.requestMeta = {
                    method: match.method || null,
                    status: match.status || null,
                    mimeType: match.mimeType || null
                }
            }
        }
    }


    prepareFindingMetadata(finding) {
        if (!finding) return null
        if (!finding.location || typeof finding.location !== "object" || Array.isArray(finding.location)) {
            const rawValue = typeof finding.location === "string" ? finding.location : null
            finding.location = { url: rawValue }
        }
        const ruleInfo = finding.ruleId ? getIastRuleMeta(finding.ruleId) : null
        if (!ruleInfo && finding.ruleId) {
            try {
                console.warn(`[PTK][IAST] missing rule metadata for ruleId=${finding.ruleId}`)
            } catch (_) { }
        }
        let moduleInfo = ruleInfo?.moduleMeta || (finding.moduleId ? getIastModuleMeta(finding.moduleId) : null)
        if (!moduleInfo && finding.moduleId) {
            try {
                console.warn(`[PTK][IAST] missing module metadata for moduleId=${finding.moduleId}`)
            } catch (_) { }
        }
        if (!moduleInfo && ruleInfo?.moduleId) {
            moduleInfo = getIastModuleMeta(ruleInfo.moduleId) || moduleInfo
        }
        if (!finding.moduleId && moduleInfo?.id) {
            finding.moduleId = moduleInfo.id
        }
        if (!finding.moduleName && moduleInfo?.name) {
            finding.moduleName = moduleInfo.name
        }
        if (!finding.ruleName && ruleInfo?.ruleName) {
            finding.ruleName = ruleInfo.ruleName
        }
        const urls = this.collectFindingUrls(finding)
        if (urls.length > 0) {
            finding.location.url = urls[0]
        }
        finding.affectedUrls = urls
        if (!finding.requestKey) {
            finding.requestKey = this._resolveRequestKeyForFinding(finding)
        }
        const summary = this.buildTaintAndSinkSummaries(finding)
        finding.taintSummary = summary.taintSummary
        finding.sinkSummary = summary.sinkSummary
        const allowedSources = ruleInfo?.ruleMeta?.metadata?.sources || ruleInfo?.ruleMeta?.sources || null
        if (Array.isArray(allowedSources) && allowedSources.length) {
            finding.allowedSources = allowedSources.slice()
        }
        if (finding?.evidence?.iast && typeof finding.evidence.iast === "object") {
            finding.evidence.iast.taintSummary = summary.taintSummary
            finding.evidence.iast.sinkSummary = summary.sinkSummary
            if (Array.isArray(allowedSources) && allowedSources.length) {
                finding.evidence.iast.allowedSources = allowedSources.slice()
            }
        }
        const moduleMetaPayload = moduleInfo?.metadata || moduleInfo || {}
        const ruleMetaPayload = (ruleInfo?.ruleMeta && (ruleInfo.ruleMeta.metadata || ruleInfo.ruleMeta)) || {}
        return {
            finding,
            moduleMeta: moduleMetaPayload,
            ruleMeta: ruleMetaPayload
        }
    }

    collectFindingUrls(finding) {
        const urls = new Set()
        const add = (value) => {
            if (!value) return
            const normalized = this.normalizeFindingUrl(value)
            if (normalized) urls.add(normalized)
        }
        const baseLocation = finding?.location
        const ev = getIastEvidencePayload(finding)
        const routingUrl = ev?.routing?.runtimeUrl || ev?.routing?.url || null
        if (routingUrl) add(routingUrl)
        if (typeof baseLocation === "string") add(baseLocation)
        if (baseLocation && typeof baseLocation === "object") {
            add(baseLocation.url || baseLocation.href)
        }
        if (Array.isArray(finding?.affectedUrls)) {
            finding.affectedUrls.forEach(add)
        }
        if (ev) {
            if (Array.isArray(ev.affectedUrls)) {
                ev.affectedUrls.forEach(add)
            }
            add(ev?.context?.url)
            add(ev?.context?.location)
        }
        if (urls.size === 0 && baseLocation?.url) {
            add(baseLocation.url)
        }
        return Array.from(urls).sort((a, b) => {
            if (a.length !== b.length) return b.length - a.length
            return a.localeCompare(b)
        })
    }

    normalizeFindingUrl(rawUrl) {
        if (!rawUrl) return ""
        const value = String(rawUrl).trim()
        const candidates = [value]
        if (this.scanResult?.host && !/^https?:\/\//i.test(value)) {
            const base = this.scanResult.host.match(/^https?:\/\//i) ? this.scanResult.host : `http://${this.scanResult.host}`
            try {
                candidates.push(new URL(value, base).toString())
            } catch (_) { }
        }
        for (const candidate of candidates) {
            try {
                const u = new URL(candidate)
                if (!/^https?:$/i.test(u.protocol)) {
                    continue
                }
                let pathname = u.pathname || "/"
                pathname = pathname.replace(/\/{2,}/g, "/")
                if (pathname.length > 1 && pathname.endsWith("/")) pathname = pathname.slice(0, -1)
                u.pathname = pathname
                return `${u.origin}${u.pathname}${u.search || ""}${u.hash || ""}`
            } catch (_) { }
        }
        return value
    }

    buildTaintAndSinkSummaries(finding) {
        const sources = new Set()
        const sinks = new Set()
        const directSources = [finding?.source, finding?.taintSource]
        directSources.forEach(src => { if (src) sources.add(String(src)) })
        const directSinks = [finding?.sink, finding?.sinkId]
        directSinks.forEach(sink => { if (sink) sinks.add(String(sink)) })
        const evidence = getIastEvidencePayload(finding)
        if (evidence) {
            ;[evidence.taintSource, evidence.sourceId].forEach(src => {
                if (src) sources.add(String(src))
            })
            ;[evidence.sinkId].forEach(sink => {
                if (sink) sinks.add(String(sink))
            })
        }
        const sourcesArr = Array.from(sources)
        const sinksArr = Array.from(sinks)
        return {
            taintSummary: {
                sources: sourcesArr,
                primarySource: sourcesArr.length ? sourcesArr[0] : null
            },
            sinkSummary: {
                sinks: sinksArr,
                primarySink: sinksArr.length ? sinksArr[0] : null
            }
        }
    }

    updatePagesFromFindings() {
        const items = Array.isArray(this.scanResult.findings) ? this.scanResult.findings : []
        const map = new Map()
        items.forEach((finding, index) => {
            if (!finding) return
            const candidateUrls = this.collectFindingUrls(finding)
            const normalizedPrimary = candidateUrls.length ? candidateUrls[0] : null
            const pageUrl = finding?.location?.url || normalizedPrimary
            const key = normalizedPrimary || pageUrl || `__missing_url__${index}`
            if (!map.has(key)) {
                map.set(key, {
                    url: pageUrl || normalizedPrimary || null,
                    stats: {
                        totalFindings: 0,
                        byCategory: {},
                        bySeverity: {}
                    },
                    findingIds: [],
                    requestKey: null,
                    requestMeta: {}
                })
            }
            const page = map.get(key)
            const category = finding?.category || "runtime_issue"
            const severity = String(finding?.severity || "info").toLowerCase()
            const findingId = finding?.id || `${index}`
            page.stats.totalFindings += 1
            page.stats.byCategory[category] = (page.stats.byCategory[category] || 0) + 1
            page.stats.bySeverity[severity] = (page.stats.bySeverity[severity] || 0) + 1
            page.findingIds.push(findingId)
        })
        const pages = Array.from(map.values()).map(page => {
            const match = this.findRequestMetaForUrl(page.url)
            if (match) {
                page.requestKey = match.key || null
                page.requestMeta = {
                    method: match.method || null,
                    status: match.status || null,
                    mimeType: match.mimeType || null
                }
            }
            return page
        })
        this.scanResult.pages = pages
    }

    findRequestMetaForUrl(url) {
        if (!url || !Array.isArray(this.scanResult.requests)) return null
        const normalized = this.normalizeRequestUrl(url)
        if (!normalized) return null
        let best = null
        for (const req of this.scanResult.requests) {
            if (!req?.url) continue
            if (req.url === normalized) {
                best = req
                break
            }
        }
        if (!best) {
            best = this.scanResult.requests.find(req => req?.displayUrl === url) || null
        }
        return best
    }

    broadcastScanUpdate() {
        try {
            browser.runtime.sendMessage({
                channel: "ptk_background_iast2popup",
                type: "scan_update",
                scanResult: this._getPublicScanResult(),
                isScanRunning: this.isScanRunning
            }).catch(() => { })
        } catch (_) { }
    }

    broadcastScanDelta(finding) {
        if (!finding) return
        try {
            browser.runtime.sendMessage({
                channel: "ptk_background_iast2popup",
                type: "scan_delta",
                finding,
                stats: this.scanResult?.stats || {},
                isScanRunning: this.isScanRunning
            }).catch(() => { })
        } catch (_) { }
    }

    attachDevtoolsDebugger(tabId) {
        if (worker.isFirefox) return
        if (typeof chrome === "undefined" || !chrome.debugger) return
        if (this.devtoolsAttached && this.devtoolsTarget && this.devtoolsTarget.tabId === tabId) return

        const target = { tabId }
        chrome.debugger.attach(target, "1.3", () => {
            if (chrome.runtime.lastError) {
                console.warn("[PTK IAST] DevTools attach failed:", chrome.runtime.lastError.message)
                return
            }

            this.devtoolsAttached = true
            this.devtoolsTarget = target

            chrome.debugger.sendCommand(target, "Network.enable", {}, () => {
                if (chrome.runtime.lastError) {
                    console.warn("[PTK IAST] Network.enable failed:", chrome.runtime.lastError.message)
                }
            })

            if (!this.onDevtoolsEvent) {
                this.onDevtoolsEvent = this.handleDevtoolsEvent.bind(this)
            }
            chrome.debugger.onEvent.addListener(this.onDevtoolsEvent)
        })
    }

    async loadModules() {
        return loadIastModules()
    }

    async sendModulesToContent(tabId) {
        return sendIastModulesToContent(tabId)
    }

    detachDevtoolsDebugger() {
        if (!this.devtoolsAttached || !this.devtoolsTarget) return
        if (typeof chrome === "undefined" || !chrome.debugger) return

        try {
            if (this.onDevtoolsEvent) {
                chrome.debugger.onEvent.removeListener(this.onDevtoolsEvent)
            }
        } catch (e) {
            // ignore listener removal errors
        }

        chrome.debugger.detach(this.devtoolsTarget, () => {
            if (chrome.runtime.lastError) {
                console.warn("[PTK IAST] DevTools detach error:", chrome.runtime.lastError.message)
            }
            this.devtoolsAttached = false
            this.devtoolsTarget = null
            this.onDevtoolsEvent = null
        })
    }

    handleDevtoolsEvent(source, method, params) {
        if (!this.devtoolsTarget || source.tabId !== this.devtoolsTarget.tabId) return
        if (!this.isScanRunning || !this.scanResult?.tabId || source.tabId !== this.scanResult.tabId) return

        if (method === "Network.requestWillBeSent") {
            const request = params && params.request ? params.request : {}
            if (!isHttpUrl(request.url)) return
            const evt = {
                type: "devtools-http-request",
                time: Date.now(),
                requestId: params && params.requestId ? params.requestId : undefined,
                url: request.url,
                method: request.method,
                tabId: source.tabId
            }
            this.recordHttpEvent(evt)
        }

        if (method === "Network.responseReceived") {
            const response = params && params.response ? params.response : {}
            if (!isHttpUrl(response.url)) return
            const evt = {
                type: "devtools-http-response",
                time: Date.now(),
                requestId: params && params.requestId ? params.requestId : undefined,
                url: response.url,
                status: response.status,
                mimeType: response.mimeType,
                tabId: source.tabId
            }
            this.recordHttpEvent(evt)
            this.captureAuthResponseTokens({
                tabId: source.tabId,
                requestId: params && params.requestId ? params.requestId : null,
                url: response.url,
                mimeType: response.mimeType
            })
        }
    }

    isLikelyAuthEndpoint(url) {
        if (!url) return false
        const lower = String(url).toLowerCase()
        return /(login|auth|token|session)/.test(lower)
    }

    async captureAuthResponseTokens({ tabId, requestId, url, mimeType }) {
        if (!tabId || !requestId || !url) return
        if (!mimeType || !String(mimeType).toLowerCase().includes("json")) return
        if (!this.isLikelyAuthEndpoint(url)) return
        if (typeof chrome === "undefined" || !chrome.debugger) return
        const target = { tabId }
        chrome.debugger.sendCommand(target, "Network.getResponseBody", { requestId }, (resp) => {
            if (chrome.runtime.lastError || !resp || !resp.body) return
            const bodyText = resp.base64Encoded ? atob(resp.body) : resp.body
            if (!bodyText || bodyText.length > 200000) return
            let parsed
            try {
                parsed = JSON.parse(bodyText)
            } catch (_) {
                return
            }
            const tokens = this.extractTokenCandidates(parsed).map(entry => ({
                value: entry.value,
                origin: {
                    kind: "http_response",
                    url,
                    requestId,
                    detail: entry.path
                }
            }))
            if (!tokens.length) return
            try {
                browser.tabs.sendMessage(tabId, {
                    channel: "ptk_background_iast2content_token_origin",
                    tokens
                }).catch((err) => {
                    console.warn("[PTK IAST] token origin send failed", err)
                })
            } catch (err) {
                console.warn("[PTK IAST] token origin send exception", err)
            }
        })
    }

    extractTokenCandidates(payload, path = "$") {
        const results = []
        const tokenKeys = ["token", "access_token", "refresh_token", "jwt", "auth", "session"]
        if (payload && typeof payload === "object") {
            Object.entries(payload).forEach(([key, value]) => {
                const lower = String(key).toLowerCase()
                const nextPath = `${path}.${key}`
                if (typeof value === "string") {
                    if (tokenKeys.some(k => lower.includes(k)) || this.isTokenLike(value)) {
                        results.push({ path: nextPath, value })
                    }
                } else if (value && typeof value === "object") {
                    if (Object.keys(value).length <= 12) {
                        results.push(...this.extractTokenCandidates(value, nextPath))
                    }
                }
            })
        }
        return results
    }

    isTokenLike(value) {
        if (!value) return false
        const str = String(value).trim()
        if (str.length < 12) return false
        if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(str) && str.length >= 30) {
            return true
        }
        if (/^[A-Fa-f0-9]+$/.test(str) && str.length >= 32) return true
        if (/^[A-Za-z0-9+/_=-]+$/.test(str) && str.length >= 24) return true
        return false
    }

    registerScript() {
        // Firefox MV2 uses different path structure than Chrome MV3
        const file = !worker.isFirefox ? 'ptk/content/iast.js' : 'content/iast.js'
        try {
            browser.scripting.registerContentScripts([{
                id: 'iast-agent',
                js: [file],
                matches: ['<all_urls>'],
                runAt: 'document_start',
                world: 'MAIN'
            }]).then(() => { });
        } catch (e) {
            console.warn('[PTK IAST] Failed to register IAST script:', e);
        }
    }

    async injectIastAgent(tabId) {
        const file = 'ptk/content/iast.js'

        // MV3 path (Chromium). Avoid in Firefox MV2 where scripting exists but behaves differently.
        if (!worker?.isFirefox && browser?.scripting?.executeScript) {
            try {
                await browser.scripting.executeScript({
                    target: { tabId },
                    files: [file],
                    world: 'MAIN'
                })
                return true
            } catch (e) {
                try { console.warn('[PTK IAST] executeScript failed:', e?.message || e) } catch (_) { }
            }
        }

        // MV2-safe injection: use tabs.executeScript + script tag with absolute URL
        if (browser?.tabs?.executeScript && browser?.runtime?.getURL) {
            try {
                const url = browser.runtime.getURL(file)
                const code = `
                    (function() {
                        try {
                            if (document.getElementById('__ptk_iast_agent__')) return;
                            var s = document.createElement('script');
                            s.id = '__ptk_iast_agent__';
                            s.src = ${JSON.stringify(url)};
                            s.type = 'text/javascript';
                            s.onload = function() {
                                try { window.postMessage({ channel: 'ptk_iast_agent_ready' }, '*'); } catch (e) {}
                                try { s.remove(); } catch (e) {}
                            };
                            s.onerror = function() {
                                try { window.postMessage({ channel: 'ptk_iast_agent_failed', error: 'script_load_failed' }, '*'); } catch (e) {}
                                try { s.remove(); } catch (e) {}
                            };
                            (document.head || document.documentElement).appendChild(s);
                        } catch (e) {}
                    })();
                `
                // Use document_idle for already-loaded pages (document_start is for initial load)
                await browser.tabs.executeScript(tabId, { code, runAt: 'document_idle' })
                return true
            } catch (e) {
                try { console.warn('[PTK IAST] tabs.executeScript failed:', e?.message || e) } catch (_) { }
            }
        }

        console.warn('[PTK IAST] No injection method available')
        return false
    }

    isAgentReady(tabId) {
        return this.agentReadyTabs.has(tabId)
    }

    async unregisterScript() {
        try {
            await browser.scripting.unregisterContentScripts({
                ids: ["iast-agent"],
            });
        } catch (err) {
            //console.log(`failed to unregister content scripts: ${err}`);
        }

    }

}
