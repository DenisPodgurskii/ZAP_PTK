/* Author: Denis Podgurskii */
import { Wappalyzer } from "../packages/wappalyzer/wappalyzer.js"
import { buildCssPlan } from "../packages/wappalyzer/cssRules.js"
import { buildHtmlPlan } from "../packages/wappalyzer/htmlRules.js"
import { analyzeHeadersForTab } from "./headerAnalysis/headerAnalyzer.js"
import { setWappalyzerTechnologiesForHeaders } from "./headerAnalysis/wappalyzerHeadersEvaluator.js"
import { setCveTechnologiesForHeaders } from "./headerAnalysis/cveHeadersEvaluator.js"
import { ptk_utils, ptk_storage } from "./utils.js"
import { portalPolicyRuntimeStore, normalizePortalPolicyEngine } from "./common/portalPolicyRuntimeStore.js"
import {
    buildPortalUrl as buildSharedPortalUrl,
    initializePortalRuntimeConfig
} from "../common/portalConfig.js"


const worker = self

function getPortalApiKey() {
    return String(worker?.ptk_app?.settings?.profile?.api_key || '').trim()
}

function buildDashboardPortalUrl(endpoint, profile = {}) {
    return buildSharedPortalUrl(endpoint, {
        baseUrl: profile?.base_url || profile?.api_url || profile?.baseUrl || null,
        apiBase: profile?.api_base || profile?.apiBase || undefined
    })
}

export class ptk_dashboard {
    constructor() {
        this.headerAnalysisCache = new Map()
        this.contentInitCache = new Map()
        // Per-tab cache for analysis data (technologies, cves, waf)
        this.tabAnalysisCache = new Map()
        this.ready = this._loadWappalyzerAssets()
        this._rulesReadyPromise = null

        this.addMessageListiners()
    }

    async _loadWappalyzerAssets() {
        const [technologyData, wafData, cveData] = await Promise.all([
            fetch(browser.runtime.getURL('ptk/packages/wappalyzer/technologies.json')).then(response => response.json()),
            fetch(browser.runtime.getURL('ptk/packages/wappalyzer/waf.json')).then(response => response.json()),
            fetch(browser.runtime.getURL('ptk/packages/wappalyzer/cves.json')).then(response => response.json())
        ])

        this.technologies = technologyData?.technologies || {}
        this.categories = technologyData?.categories || []
        this.wappalyzerCssRules = []
        const technologyHtmlData = buildHtmlPlan(this.technologies, 'technologies')
        this.wappalyzerHtmlPlan = technologyHtmlData.plan
        this.wappalyzerHtmlPatterns = technologyHtmlData.patternIndex
        setWappalyzerTechnologiesForHeaders(this.technologies)

        this.wafTechnologies = wafData?.technologies || {}
        this.wafCategories = wafData?.categories || []
        const wafHtmlData = buildHtmlPlan(this.wafTechnologies, 'waf')
        this.wappalyzerWafHtmlPlan = wafHtmlData.plan
        this.wappalyzerWafHtmlPatterns = wafHtmlData.patternIndex

        this.cveRaw = cveData || {}
        this.cveTechnologies = cveData?.technologies || {}
        this.cveCategories = cveData?.categories || []
        const cveHtmlData = buildHtmlPlan(this.cveTechnologies, 'cve')
        this.cveHtmlPlan = cveHtmlData.plan
        this.cveHtmlPatterns = cveHtmlData.patternIndex
        setCveTechnologiesForHeaders(this.cveTechnologies)
    }

    async ensureAnalysisRulesReady() {
        await this.ready
        if (this._wappalyzerRulesBuilt) {
            return true
        }
        if (this._rulesReadyPromise) {
            return this._rulesReadyPromise
        }
        this._rulesReadyPromise = (async () => {
            this.setWappalyzer(this.technologies, this.categories)

            const activeTechnologies = new Set(Wappalyzer.technologies.map(({ name }) => name))

            if (!this.wappalyzerHtmlPlan?.length) {
                const htmlData = buildHtmlPlan(this.technologies, 'technologies')
                this.wappalyzerHtmlPlan = htmlData.plan
                this.wappalyzerHtmlPatterns = htmlData.patternIndex
            }

            if (!this.wappalyzerWafHtmlPlan?.length && this.wafTechnologies) {
                const htmlData = buildHtmlPlan(this.wafTechnologies, 'waf')
                this.wappalyzerWafHtmlPlan = htmlData.plan
                this.wappalyzerWafHtmlPatterns = htmlData.patternIndex
            }

            if (!this.cveHtmlPlan?.length && this.cveTechnologies) {
                const htmlData = buildHtmlPlan(this.cveTechnologies, 'cve')
                this.cveHtmlPlan = htmlData.plan
                this.cveHtmlPatterns = htmlData.patternIndex
            }

            this.wappalyzerDomRules = Wappalyzer.technologies
                .filter(({ dom }) => dom)
                .map(({ name, dom }) => ({ name, dom }))
                .filter(item => item.dom != "")

            this.wappalyzerJsRules = Wappalyzer.technologies
                .filter(({ js }) => js)
                .map(({ name, js }) => ({ name, js }))
                .filter(item => item.js != "")

            this.cveJsRules = Object.entries(this.cveTechnologies || {})
                .filter(([_, definition]) => definition && definition.js)
                .map(([name, definition]) => ({ name, js: definition.js }))

            this.wappalyzerCssRules = buildCssPlan(this.technologies, activeTechnologies)
            this._wappalyzerRulesBuilt = true
            return true
        })()
        try {
            return await this._rulesReadyPromise
        } finally {
            this._rulesReadyPromise = null
        }
    }

    _hasExportableScanResult(scanResult) {
        if (!scanResult || typeof scanResult !== "object") return false
        if (scanResult.scanId || scanResult.startedAt || scanResult.finishedAt) return true
        const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
        const items = Array.isArray(scanResult.items) ? scanResult.items : []
        const requests = Array.isArray(scanResult.requests) ? scanResult.requests : []
        const hasStats = !!scanResult.stats && Object.keys(scanResult.stats).length > 0
        return findings.length > 0 || items.length > 0 || requests.length > 0 || hasStats
    }

    // Get cached analysis data for a specific tab
    _getTabAnalysisCache(tabId) {
        if (!tabId) return null
        return this.tabAnalysisCache.get(tabId) || null
    }

    // Save analysis data for a specific tab
    _setTabAnalysisCache(tabId, data) {
        if (!tabId) return
        const existing = this.tabAnalysisCache.get(tabId) || {}
        this.tabAnalysisCache.set(tabId, {
            ...existing,
            ...data,
            updatedAt: Date.now()
        })
        // Limit cache size to 10 tabs
        if (this.tabAnalysisCache.size > 10) {
            const oldest = [...this.tabAnalysisCache.entries()]
                .sort((a, b) => (a[1].updatedAt || 0) - (b[1].updatedAt || 0))[0]
            if (oldest) this.tabAnalysisCache.delete(oldest[0])
        }
    }

    _buildExportableFlags(overrides = {}) {
        const flags = {
            dast: this._hasExportableScanResult(overrides.dast || worker.ptk_app?.dast?.scanResult || worker.ptk_app?.rattacker?.scanResult),
            iast: this._hasExportableScanResult(overrides.iast || worker.ptk_app?.iast?.scanResult),
            sast: this._hasExportableScanResult(overrides.sast || worker.ptk_app?.sast?.scanResult),
            sca: this._hasExportableScanResult(overrides.sca || worker.ptk_app?.sca?.scanResult)
        }
        flags.any = Object.values(flags).some(Boolean)
        return flags
    }

    async _loadStoredScanResults() {
        try {
            const [dast, iast, sast, sca] = await Promise.all([
                ptk_storage.getItem("ptk_rattacker"),
                ptk_storage.getItem("ptk_iast"),
                ptk_storage.getItem("ptk_sast"),
                ptk_storage.getItem("ptk_sca")
            ])
            return { dast, iast, sast, sca }
        } catch (_) {
            return {}
        }
    }

    _getScanEngines() {
        const dast = worker.ptk_app?.dast || worker.ptk_app?.rattacker || null
        return {
            dast,
            rattacker: dast,
            iast: worker.ptk_app?.iast || null,
            sast: worker.ptk_app?.sast || null,
            sca: worker.ptk_app?.sca || null
        }
    }

    _scanResultMatchesHost(scanResult, host) {
        if (!host || !scanResult || typeof scanResult !== 'object') return false
        return scanResult.host === host
    }

    _hasAnyScanForHost(host, scanResults = {}) {
        if (!host) return false
        const engines = this._getScanEngines()
        return !!(
            this._scanResultMatchesHost(engines.dast?.scanResult || scanResults.dast, host) ||
            this._scanResultMatchesHost(engines.iast?.scanResult || scanResults.iast, host) ||
            this._scanResultMatchesHost(engines.sast?.scanResult || scanResults.sast, host) ||
            this._scanResultMatchesHost(engines.sca?.scanResult || scanResults.sca, host)
        )
    }

    _buildLiveScansState() {
        const engines = this._getScanEngines()
        return {
            dast: !!engines.dast?.engine?.isRunning,
            iast: !!engines.iast?.isScanRunning,
            sast: !!engines.sast?.isScanRunning,
            sca: !!engines.sca?.isScanRunning,
            dastSettings: engines.dast?.settings || worker.ptk_app?.settings?.rattacker || {},
            exportable: this._buildExportableFlags()
        }
    }

    async _buildDashboardScansState({ includeStored = false } = {}) {
        const scans = this._buildLiveScansState()
        let stored = null

        try {
            const activeUrl = worker.ptk_app?.proxy?.activeTab?.url || null
            const host = activeUrl ? new URL(activeUrl).host : null
            if (includeStored) {
                stored = await this._loadStoredScanResults()
            }
            scans.hasAnyScanForHost = this._hasAnyScanForHost(host, stored || {})
            if (stored) {
                const storedExportable = this._buildExportableFlags(stored)
                scans.exportable = {
                    dast: !!(scans.exportable?.dast || storedExportable.dast),
                    iast: !!(scans.exportable?.iast || storedExportable.iast),
                    sast: !!(scans.exportable?.sast || storedExportable.sast),
                    sca: !!(scans.exportable?.sca || storedExportable.sca)
                }
                scans.exportable.any = Object.values(scans.exportable).some(Boolean)
            }
        } catch (_) {
            scans.hasAnyScanForHost = false
        }

        return scans
    }

    async initCookies(urls) {
        let merged = []
        let promises = []
        for (let i = 0; i < urls.length; i++) {
            promises.push(browser.cookies.getAll({ 'url': urls[i] }))
        }
        let self = this
        return Promise.all(promises).then(function (cookie) {
            let merged = [].concat.apply([], cookie)
            let cookies = merged.filter((v, i, a) => a.findIndex(v2 => (JSON.stringify(v) === JSON.stringify(v2))) === i).sort((a, b) => a.name.localeCompare(b.name));
            self.tab.cookies = cookies
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_dashboard",
                type: "cookies_loaded",
                data: Object.assign({}, { cookies: cookies })
            }).catch(e => e)
        })
    }

    async analyzeTab(message) {
        await this.ensureAnalysisRulesReady()
        this.setWappalyzer(this.technologies, this.categories)

        if (!this.tab) {
            this.tab = {}
        }

        const proxyTab = worker.ptk_app.proxy.getTab(this.activeTab?.tabId || this.tab?.tabId)
        const headerAnalysis = await this.runHeaderAnalysis(proxyTab)
        const techHeaderMatches = headerAnalysis.techHeaderMatches || []
        const cveHeaderMatches = headerAnalysis.cveHeaderMatches || []
        this.tab.findings = headerAnalysis.securityFindings || []
        this.tab.techHeaderMatches = techHeaderMatches
        this.tab.cveHeaderMatches = cveHeaderMatches
        this.tab.headerAnalysisEvidence = headerAnalysis.evidence
        if (!message.info) {
            message.info = {}
        }
        message.info.headers = techHeaderMatches

        let cookies = {}
        if (this.tab.cookies)
            Object.values(this.tab.cookies).forEach(function (c) {
                cookies[c.name.toLowerCase()] = [c.value]
            })


        let detections = Wappalyzer.analyze({
            headers: this.tab.responseHeaders,
            meta: message.info.meta,
            scriptSrc: message.info.scriptSrc,
            scripts: message.info.scripts,
            html: message.info.html,
            js: message.info.js,
            dom: message.info.dom,
            cookies: cookies,
            url: this.activeTab?.url || this.tab?.url || ''
        })
        detections = Wappalyzer.resolve(detections)

        const htmlMatches = message.info?.htmlMatches?.technologies?.matched || []
        const htmlDetections = this.buildHtmlDetections(htmlMatches, this.wappalyzerHtmlPatterns)
        detections = detections.concat(htmlDetections)


        let technologies = Array.prototype.concat.apply(
            [],
            message.info.dom.map(({ name, selector, exists, text, property, attribute, value }) => {

                const technology = Wappalyzer.technologies.find(({ name: _name }) => name === _name)
                if (!technology) return []
                if (typeof exists !== 'undefined') {
                    return Wappalyzer.analyzeManyToMany(technology, 'dom.exists', { [selector]: [''], })
                }

                if (text) {
                    return Wappalyzer.analyzeManyToMany(technology, 'dom.text', { [selector]: [text], })
                }

                if (property) {
                    return Wappalyzer.analyzeManyToMany(technology, `dom.properties.${property}`, { [selector]: [value], })
                }

                if (attribute) {
                    return Wappalyzer.analyzeManyToMany(technology, `dom.attributes.${attribute}`, { [selector]: [value], })
                }

                return []
            })
        )

        technologies = Array.prototype.concat.apply(
            technologies,
            message.info.js
                .map(({ name, chain, value }) => {
                    const technology = Wappalyzer.technologies.find(({ name: _name }) => name === _name)
                    if (!technology) return []
                    if (name) {
                        return Wappalyzer.analyzeManyToMany(technology, 'js', { [chain]: [value], })
                    }

                    return []
                })
        )

        const cssMatches = Array.isArray(message.info?.css?.matched) ? message.info.css.matched : []

        technologies = Array.prototype.concat.apply(
            technologies,
            cssMatches
                .map(({ tech, name, selector, prop, value, pattern }) => {
                    const techName = tech || name

                    const technology = Wappalyzer.technologies.find(({ name: _name }) => techName === _name)
                    if (!technology) return []

                    return [{
                        technology,
                        pattern: {
                            type: 'css',
                            selector,
                            prop,
                            value: value || '',
                            pattern: pattern || '',
                        },
                        version: ''
                    }]
                })
        )

        const headerMatches = Array.isArray(message.info?.headers)
            ? message.info.headers
            : []

        technologies = Array.prototype.concat.apply(
            technologies,
            headerMatches.map(({ techId, techName, matches }) => {
                if (!Array.isArray(matches) || !matches.length) {
                    return []
                }

                const resolvedName = techId || techName
                if (!resolvedName) {
                    return []
                }

                const technology =
                    Wappalyzer.technologies.find(({ name: _name }) => _name === resolvedName) ||
                    this.createTechnologyStub(resolvedName)

                return matches.map(({ header, value, pattern }) => ({
                    technology,
                    pattern: {
                        type: 'header',
                        header,
                        value: value || '',
                        pattern: pattern || '',
                    },
                    version: ''
                }))
            })
        )

        let technologyEntries = technologies
            .map((item) => ({
                name: item.technology?.name || "",
                version: item.version ? item.version : "",
                category: this.resolveTechnologyCategory(item.technology),
            }))
            .filter((item) => item.name)

        const resolvedEntries = Object.keys(detections).map((key) => {
            const detection = detections[key]
            return {
                name: detection.name,
                version: detection.version || "",
                category: this.resolveTechnologyCategory(detection),
            }
        })

        technologyEntries = technologyEntries.concat(resolvedEntries)


        //WAF
        let wafDetections = {}
        this.setWappalyzer(this.wafTechnologies, this.wafCategories)

        wafDetections = Wappalyzer.analyze({
            headers: this.tab.responseHeaders,
            meta: message.info.meta,
            scriptSrc: message.info.scriptSrc,
            scripts: message.info.scripts,
            html: message.info.html,
            js: message.info.js,
            dom: message.info.dom,
            cookies: cookies,
            url: this.activeTab?.url || this.tab?.url || ''
        })

        const wafHtmlMatches = message.info?.htmlMatches?.waf?.matched || []
        const wafHtmlDetections = this.buildHtmlDetections(wafHtmlMatches, this.wappalyzerWafHtmlPatterns)
        wafDetections = wafDetections.concat(wafHtmlDetections)


        this.tab.waf = Wappalyzer.resolve(wafDetections)

        const wafEntries = (Array.isArray(this.tab.waf) ? this.tab.waf : Object.values(this.tab.waf || {}))
            .map((item) => ({
                name: item?.name || "",
                version: item?.version || "",
                category: "WAF",
            }))
            .filter((item) => item.name)

        technologyEntries = technologyEntries.concat(wafEntries)
        this.tab.technologies = this.mergeTechnologyEntries(technologyEntries)

        const hasCveSignatures = this.cveTechnologies && Object.keys(this.cveTechnologies).length > 0
        if (hasCveSignatures) {
            this.setWappalyzer(this.cveTechnologies, this.cveCategories || [])
            const cveEvidence = {
                js: new Map(),
                html: new Map(),
                headers: new Map(),
                url: new Map()
            }

            const incrementEvidence = (bucket, techName) => {
                if (!techName) {
                    return
                }
                bucket.set(techName, (bucket.get(techName) || 0) + 1)
            }

            const jsInputs = Array.isArray(message.info.js) ? message.info.js : []
            const jsDetections = Array.prototype.concat.apply([],
                jsInputs.map(({ name, chain, value }) => {
                    const technology = Wappalyzer.technologies.find(({ name: _name }) => name === _name)
                    if (!technology) {
                        return []
                    }
                    const detectionsForTech = Wappalyzer.analyzeManyToMany(technology, 'js', { [chain]: [value] }) || []
                    detectionsForTech.forEach((detection) => {
                        incrementEvidence(cveEvidence.js, detection?.technology?.name)
                    })
                    return detectionsForTech
                })
            )

            const cveHtmlMatches = message.info?.htmlMatches?.cve?.matched || []
            const cveHtmlDetections = this.buildHtmlDetections(cveHtmlMatches, this.cveHtmlPatterns)
            cveHtmlDetections.forEach((detection) => {
                incrementEvidence(cveEvidence.html, detection?.technology?.name)
            })

            const cveHeaderDetections = Array.prototype.concat.apply([],
                cveHeaderMatches.map(({ techId, techName, matches }) => {
                    if (!Array.isArray(matches) || !matches.length) {
                        return []
                    }
                    const resolvedName = techId || techName
                    if (!resolvedName) {
                        return []
                    }
                    const technology =
                        Wappalyzer.technologies.find(({ name: _name }) => _name === resolvedName) ||
                        this.createTechnologyStub(resolvedName)

                    return matches.map(({ header, value, pattern }) => ({
                        technology,
                        pattern: {
                            type: 'header',
                            header,
                            value: value || '',
                            pattern: pattern || '',
                        },
                        version: ''
                    }))
                })
            )
            cveHeaderDetections.forEach((detection) => {
                incrementEvidence(cveEvidence.headers, detection?.technology?.name)
            })

            const cveUrlInput = this.activeTab?.url || this.tab?.url || ''
            const cveUrlDetections = cveUrlInput
                ? (Wappalyzer.analyze({ url: cveUrlInput }) || [])
                : []
            cveUrlDetections.forEach((detection) => {
                incrementEvidence(cveEvidence.url, detection?.technology?.name)
            })

            let cveDetections = []
            cveDetections = cveDetections
                .concat(jsDetections)
                .concat(cveHtmlDetections)
                .concat(cveHeaderDetections)
                .concat(cveUrlDetections)

            const resolvedCves = Wappalyzer.resolve(cveDetections) || []
            const cveDefinitions = this.cveTechnologies || {}

            const passiveCves = (Array.isArray(resolvedCves) ? resolvedCves : []).map((item) => {
                const id = item.name
                const raw = cveDefinitions[id] || {}
                const meta = raw.ptk || {}
                const evidence = {
                    js: cveEvidence.js.get(id) || 0,
                    html: cveEvidence.html.get(id) || 0,
                    headers: cveEvidence.headers.get(id) || 0,
                    url: cveEvidence.url.get(id) || 0
                }

                return {
                    id,
                    title: raw.name || item.description || id,
                    severity: meta.severity || '',
                    category: meta.category || '',
                    confidence: item.confidence || 0,
                    evidence,
                    references: meta.references || {},
                    verify: meta.verify || null
                }
            })
            this.tab.cves = passiveCves
        } else {
            this.tab.cves = []
        }

        this.setWappalyzer(this.technologies, this.categories)

        this.tab.storage = message.info.auth
        this.tab.wappalyzerMatches = {
            dom: message.info.dom,
            js: message.info.js,
            css: message.info.css,
            headers: techHeaderMatches
        }

        // Cache analysis data per-tab so it persists across popup opens
        const currentTabId = this.activeTab?.tabId || this.tab?.tabId
        if (currentTabId) {
            this._setTabAnalysisCache(currentTabId, {
                technologies: this.tab.technologies,
                cves: this.tab.cves,
                waf: this.tab.waf,
                storage: this.tab.storage
            })
        }

        let self = this
        try {
            self = JSON.parse(JSON.stringify(this))//FF fix
        } catch (e) {
            self = {}
        }
        browser.runtime.sendMessage({
            channel: "ptk_background2popup_dashboard",
            type: "analyze_complete",
            data: Object.assign({}, self)
        }).catch(e => e)

        return Promise.resolve()
    }

    setWappalyzer(technologies, categories) {
        Wappalyzer.technologies = []
        Wappalyzer.categories = []
        Wappalyzer.requires = []
        Wappalyzer.categoryRequires = []
        Wappalyzer.setTechnologies(technologies)
        Wappalyzer.setCategories(categories)
    }

    resolveTechnologyCategory(technology, fallback = "") {
        if (!technology) {
            return fallback || ""
        }

        const categories = Array.isArray(technology.categories) ? technology.categories : []
        if (!categories.length) {
            return fallback || ""
        }

        if (typeof categories[0] === "object") {
            const names = categories.map((category) => category?.name).filter(Boolean)
            return names.length ? names.join(", ") : fallback || ""
        }

        const names = categories
            .map((categoryId) => Wappalyzer.getCategory(categoryId))
            .filter((category) => !!category)
            .map((category) => category.name)
            .filter(Boolean)

        return names.length ? names.join(", ") : fallback || ""
    }

    createTechnologyStub(name) {
        return {
            name: name || "unknown",
            categories: [],
            icon: 'default.svg',
            excludes: [],
            implies: [],
            requires: [],
            requiresCategory: []
        }
    }

    mergeTechnologyEntries(entries = []) {
        const dedupe = new Map()

        entries.forEach((entry) => {
            if (!entry || !entry.name) {
                return
            }

            const normalized = {
                name: entry.name,
                version: entry.version || "",
                category: entry.category || "",
            }

            const existing = dedupe.get(normalized.name)
            if (!existing) {
                dedupe.set(normalized.name, normalized)
                return
            }

            if (!existing.version && normalized.version) {
                existing.version = normalized.version
            }

            if (!existing.category && normalized.category) {
                existing.category = normalized.category
            }
        })

        return Array.from(dedupe.values())
    }

    collectTabRequestsForHeaders(tabInstance) {
        const entries = []
        if (!tabInstance?.frames) {
            return entries
        }

        tabInstance.frames.forEach((requestMap, frameId) => {
            requestMap.forEach((events) => {
                if (!Array.isArray(events)) {
                    return
                }

                events.forEach((event) => {
                    if (!event || !Array.isArray(event.responseHeaders) || !event.responseHeaders.length) {
                        return
                    }

                    entries.push({
                        url: event.url,
                        method: event.method,
                        statusCode: event.statusCode,
                        requestHeaders: event.requestHeaders || [],
                        responseHeaders: event.responseHeaders || [],
                        type: event.type,
                        frameId: frameId,
                        tabId: tabInstance.tabId,
                        timeStamp: event.timeStamp || Date.now()
                    })
                })
            })
        })

        return entries
    }

    _countTabRequests(tabInstance) {
        if (!tabInstance?.frames) return 0
        let count = 0
        tabInstance.frames.forEach((requestMap) => {
            requestMap.forEach((events) => {
                if (!Array.isArray(events)) return
                events.forEach((event) => {
                    if (!event || !Array.isArray(event.responseHeaders) || !event.responseHeaders.length) {
                        return
                    }
                    count++
                })
            })
        })
        return count
    }

    async runHeaderAnalysis(tabInstance) {
        if (!tabInstance) {
            return { securityFindings: [], techHeaderMatches: [], cveHeaderMatches: [], evidence: { evaluatedResponses: 0 } }
        }

        const requestCount = this._countTabRequests(tabInstance)
        if (!requestCount) {
            return { securityFindings: [], techHeaderMatches: [], cveHeaderMatches: [], evidence: { evaluatedResponses: 0 } }
        }

        const cacheKey = String(tabInstance.tabId || this.activeTab?.tabId || 'unknown')
        const cached = this.headerAnalysisCache.get(cacheKey)
        // Extended cache to 60 seconds (from 10s) for better performance during active scans
        // Cache is still invalidated if request count changes significantly (>10% growth)
        if (cached && (Date.now() - cached.timestamp) < 60000) {
            const growthRatio = requestCount / (cached.requestCount || 1)
            if (growthRatio <= 1.1) {  // Less than 10% growth
                return cached.result
            }
        }

        const requests = this.collectTabRequestsForHeaders(tabInstance)
        if (!requests.length) {
            return { securityFindings: [], techHeaderMatches: [], cveHeaderMatches: [], evidence: { evaluatedResponses: 0 } }
        }

        try {
            const result = await analyzeHeadersForTab({
                tabId: tabInstance.tabId || this.activeTab?.tabId,
                url: this.activeTab?.url || worker.ptk_app.proxy.activeTab?.url || "",
                requests
            })
            this.headerAnalysisCache.set(cacheKey, {
                requestCount,
                timestamp: Date.now(),
                result
            })
            return result
        } catch (err) {
            // Swallow header analysis errors to keep init flow resilient.
            return { securityFindings: [], techHeaderMatches: [], cveHeaderMatches: [], evidence: { error: err?.message } }
        }
    }

    buildHtmlDetections(matches = [], patternIndex) {
        if (!Array.isArray(matches) || !patternIndex) {
            return []
        }

        return matches.reduce((detections, { id, match }) => {
            if (!id) {
                return detections
            }

            const meta = patternIndex.get(id)

            if (!meta || !meta.pattern) {
                return detections
            }

            const technology =
                Wappalyzer.technologies.find(({ name }) => name === meta.tech) ||
                this.createTechnologyStub(meta.tech)

            const snippet = (match || '').toString()
            const resolvedMatch = snippet || meta.pattern.value || ''
            const version = Wappalyzer.resolveVersion(meta.pattern, resolvedMatch) || ''

            detections.push({
                technology,
                pattern: {
                    ...meta.pattern,
                    type: 'html',
                    value: meta.pattern.value,
                    match: resolvedMatch
                },
                version
            })

            return detections
        }, [])
    }



    /* Listeners */

    addMessageListiners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    onMessage(message, sender, sendResponse) {

        if (!ptk_utils.isTrustedOrigin(sender))
            return Promise.reject({ success: false, error: 'Error origin value' })

        if (message.channel == "ptk_popup2background_dashboard") {
            //console.log(message)
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve()
        }
    }

    async _refreshSelectedPortalPolicies(scans = {}, portalSelections = {}) {
        const apiKey = getPortalApiKey()
        const enginesToRefresh = []
        if (scans?.dast) enginesToRefresh.push('DAST')
        if (scans?.iast) enginesToRefresh.push('IAST')
        if (scans?.sast) enginesToRefresh.push('SAST')
        const selectedPolicies = []
        enginesToRefresh.forEach((engine) => {
            const selectionKey = String(engine || '').toLowerCase()
            if (Object.prototype.hasOwnProperty.call(portalSelections || {}, selectionKey)) {
                const explicitSelection = portalSelections?.[selectionKey]
                if (explicitSelection?.policyId) {
                    selectedPolicies.push({
                        engine,
                        policyId: explicitSelection.policyId,
                        policyName: explicitSelection.policyName || null
                    })
                } else {
                    portalPolicyRuntimeStore.clearPolicy(engine)
                }
                return
            }
            portalPolicyRuntimeStore.clearPolicy(engine)
        })
        await Promise.all(selectedPolicies.map(({ engine, policyId, policyName }) => (
            portalPolicyRuntimeStore.selectPolicy({
                engine,
                policyId,
                policyName,
                apiKey: apiKey || null
            })
        )))

        return true
    }

    async msg_run_bg_scan(message) {
        const requested = []
        if (message.scans.dast) requested.push('dast')
        if (message.scans.iast) requested.push('iast')
        if (message.scans.sast) requested.push('sast')
        if (message.scans.sca) requested.push('sca')
        if (requested.length && typeof worker.ptk_app?.ensureEngines === 'function') {
            await worker.ptk_app.ensureEngines(requested)
        }

        try {
            await this._refreshSelectedPortalPolicies(
                message.scans || {},
                message?.settings?.portalSelections || {}
            )
        } catch (err) {
            return Promise.resolve({
                success: false,
                error: err?.message || String(err),
                scans: this._buildLiveScansState(),
                skipped: { dast: false, iast: false, sast: false, sca: false },
                policyState: portalPolicyRuntimeStore.getState()
            })
        }

        const engines = this._getScanEngines()
        const running = {
            dast: !!engines.dast?.engine?.isRunning,
            iast: !!engines.iast?.isScanRunning,
            sast: !!engines.sast?.isScanRunning,
            sca: !!engines.sca?.isScanRunning
        }
        const skipped = { dast: false, iast: false, sast: false, sca: false }
        const dastPortalSelection = portalPolicyRuntimeStore.getRulepackSelection('DAST')
        const iastPortalSelection = portalPolicyRuntimeStore.getRulepackSelection('IAST')
        const sastPortalSelection = portalPolicyRuntimeStore.getRulepackSelection('SAST')

        if (message.scans.dast) {
            if (running.dast) skipped.dast = true
            else {
                const dastSettings = Object.assign({}, message.settings || {})
                if (dastPortalSelection?.policyId && !dastSettings.policyId) {
                    dastSettings.policyId = dastPortalSelection.policyId
                }
                if (dastPortalSelection?.policyName && !dastSettings.policyName) {
                    dastSettings.policyName = dastPortalSelection.policyName
                }
                const response = await engines.dast?.msg_run_bg_scan({
                    tabId: message.tabId,
                    host: message.host,
                    domains: message.domains,
                    settings: dastSettings
                })
                const dastStarted = !!(response && response.success !== false && (response.isScanRunning === true || engines.dast?.engine?.isRunning))
                if (!dastStarted) {
                    return Promise.resolve({
                        success: false,
                        error: response?.error || 'scan_start_failed',
                        message: response?.message || response?.error || 'scan_start_failed',
                        scans: this._buildLiveScansState(),
                        skipped: { dast: false, iast: false, sast: false, sca: false },
                        policyState: portalPolicyRuntimeStore.getState()
                    })
                }
            }
        }
        if (message.scans.iast) {
            if (running.iast) skipped.iast = true
            else {
                const iastOpts = {}
                if (iastPortalSelection?.policyId) {
                    iastOpts.policyId = iastPortalSelection.policyId
                }
                if (iastPortalSelection?.policyName) {
                    iastOpts.policyName = iastPortalSelection.policyName
                }
                const response = await engines.iast?.msg_run_bg_scan({
                    tabId: message.tabId,
                    host: message.host,
                    scanStrategy: message.settings?.scanStrategy,
                    opts: iastOpts
                })
                if (response?.success === false) {
                    return Promise.resolve({
                        success: false,
                        error: response?.error || 'scan_start_failed',
                        message: response?.message || response?.error || 'scan_start_failed',
                        scans: this._buildLiveScansState(),
                        skipped: { dast: false, iast: false, sast: false, sca: false },
                        policyState: portalPolicyRuntimeStore.getState()
                    })
                }
            }
        }
        if (message.scans.sast) {
            if (running.sast) {
                skipped.sast = true
            } else {
                const sastOpts = {}
                if (sastPortalSelection?.policyId) {
                    sastOpts.policyId = sastPortalSelection.policyId
                }
                if (sastPortalSelection?.policyName) {
                    sastOpts.policyName = sastPortalSelection.policyName
                }
                const response = await engines.sast?.msg_run_bg_scan({
                    tabId: message.tabId,
                    host: message.host,
                    scanStrategy: message.settings.sastScanStrategy ?? message.settings.policy,
                    opts: sastOpts
                })
                if (response?.success === false) {
                    return Promise.resolve({
                        success: false,
                        error: response?.error || 'scan_start_failed',
                        message: response?.message || response?.error || 'scan_start_failed',
                        scans: this._buildLiveScansState(),
                        skipped: { dast: false, iast: false, sast: false, sca: false },
                        policyState: portalPolicyRuntimeStore.getState()
                    })
                }
            }
        }
        if (message.scans.sca) {
            if (running.sca) skipped.sca = true
            else engines.sca?.runBackgroundScan(message.tabId, message.host)
        }

        let scans = this._buildLiveScansState()

        let payload = {}
        try {
            payload = JSON.parse(JSON.stringify({
                success: true,
                activeTab: worker.ptk_app?.proxy?.activeTab || null,
                scans,
                skipped,
                policyState: portalPolicyRuntimeStore.getState()
            }))
        } catch (e) {
            payload = { success: true, activeTab: null, scans, skipped, policyState: portalPolicyRuntimeStore.getState() }
        }

        return Promise.resolve(payload)
    }

    async msg_stop_bg_scan(message) {
        const engines = this._getScanEngines()
        const dastEngine = engines.dast || engines.rattacker || null
        const siblingStops = []

        if (message.scans.iast && typeof engines.iast?.stopBackgroundScan === 'function') {
            siblingStops.push(Promise.resolve().then(() => engines.iast.stopBackgroundScan()).catch(() => { }))
        }
        if (message.scans.sast && typeof engines.sast?.stopBackgroundScan === 'function') {
            siblingStops.push(Promise.resolve().then(() => engines.sast.stopBackgroundScan()).catch(() => { }))
        }
        if (message.scans.sca && typeof engines.sca?.stopBackgroundScan === 'function') {
            siblingStops.push(Promise.resolve().then(() => engines.sca.stopBackgroundScan()).catch(() => { }))
        }

        if (siblingStops.length) {
            await Promise.allSettled(siblingStops)
        }

        if (message.scans.dast && typeof dastEngine?.stopBackgroundScan === 'function') {
            try {
                await dastEngine.stopBackgroundScan({
                    runDeferredSeed: false,
                    waitForIdleBeforeStop: false
                })
            } catch (_) { }
        }

        let scans = this._buildLiveScansState()

        return Promise.resolve(Object.assign({}, { scans: JSON.parse(JSON.stringify(scans)) }))
    }

    async msg_get(message) {
        return Promise.resolve(Object.assign({},
            this,
            worker.ptk_app.proxy.activeTab,
            { policyState: portalPolicyRuntimeStore.getState() }))
    }

    async msg_get_scans(message) {
        if (message?.tabId) {
            worker.ptk_app.proxy.setDashboardTab(message.tabId, message.url || '')
        }
        const scans = await this._buildDashboardScansState({ includeStored: true })
        return Promise.resolve({
            success: true,
            activeTab: worker.ptk_app.proxy.activeTab,
            scans,
            policyState: portalPolicyRuntimeStore.getState()
        })
    }

    async msg_save(message) {
        if (message.items)
            this.items = message.items
        return Promise.resolve(Object.assign({},
            this,
            worker.ptk_app.proxy.activeTab))
    }

    async msg_init(message) {
        if (message?.tabId) {
            worker.ptk_app.proxy.setDashboardTab(message.tabId, message.url || '')
        }
        if (worker.ptk_app?.settings?.history?.route != 'index') {
            let link = ""
            const historyRoute = worker.ptk_app.settings.history.route === 'rattacker'
                ? 'dast'
                : worker.ptk_app.settings.history.route
            if (['session', 'sca', 'iast', 'sast', 'proxy', 'rbuilder', 'dast', 'rattacker', 'macro', 'traffic', 'swagger', 'decoder', 'portscanner', 'jwt', 'xss', 'sql'].includes(historyRoute)) {
                link = historyRoute + ".html"
                if (worker.ptk_app.settings.history.hash) {
                    link += "#" + worker.ptk_app.settings.history.hash
                }
            }
            if (link != "")
                return Promise.resolve({ redirect: link, items: this.items })
        }

        const scans = await this._buildDashboardScansState({ includeStored: true })

        if (true) {
            this.activeTab = worker.ptk_app.proxy.activeTab
            this.privacy = worker.ptk_app.settings.privacy

            // Get per-tab cached analysis data for the CURRENT active tab
            const currentTabId = this.activeTab?.tabId
            const perTabCache = this._getTabAnalysisCache(currentTabId)

            // Build tab object with per-tab cached analysis data
            let tabData = null
            if (perTabCache) {
                tabData = {
                    tabId: currentTabId,
                    technologies: perTabCache.technologies || [],
                    cves: perTabCache.cves || [],
                    waf: perTabCache.waf || null,
                    storage: perTabCache.storage || null
                }
            }

            const hasAnalysisData = tabData && (
                (Array.isArray(tabData.technologies) && tabData.technologies.length) ||
                (Array.isArray(tabData.cves) && tabData.cves.length) ||
                (Array.isArray(tabData.waf) && tabData.waf.length) ||
                (!!tabData.waf && !Array.isArray(tabData.waf))
            )

            return Object.assign(
                {},
                { lite: true },
                worker.ptk_app.proxy.activeTab,
                { privacy: this.privacy },
                { scans: scans },
                { policyState: portalPolicyRuntimeStore.getState() },
                tabData ? { tab: tabData } : {},
                { hasAnalysisData: !!hasAnalysisData },
                perTabCache ? { tabCacheUpdatedAt: perTabCache.updatedAt || null } : {}
            )
        }
    }

    async msg_get_policy_state(message) {
        return Promise.resolve({
            success: true,
            policyState: portalPolicyRuntimeStore.getState()
        })
    }

    async msg_get_projects(message) {
        await initializePortalRuntimeConfig()
        const profile = worker.ptk_app?.settings?.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return Promise.resolve({
                success: false,
                error: "missing_api_key",
                json: { message: "No API key found" }
            })
        }
        const url = buildDashboardPortalUrl("/projects", profile)
        if (!url) {
            return Promise.resolve({
                success: false,
                error: "portal_not_configured",
                json: { message: "Portal endpoint is not configured." }
            })
        }
        return fetch(url, {
            headers: {
                Authorization: "Bearer " + apiKey,
                Accept: "application/json"
            },
            credentials: "omit",
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) {
                    return { success: true, json }
                }
                return { success: false, json: json || { message: "Unable to load projects" } }
            })
            .catch((e) => ({ success: false, json: { message: "Error while loading projects: " + e.message } }))
    }

    async msg_load_policy_metadata(message) {
        const apiKey = getPortalApiKey()
        if (!apiKey) {
            return Promise.resolve({
                success: false,
                error: "missing_api_key",
                policyState: portalPolicyRuntimeStore.getState()
            })
        }
        try {
            const engine = normalizePortalPolicyEngine(message?.engine)
            await portalPolicyRuntimeStore.loadMetadata({
                apiKey,
                engine: engine || undefined
            })
            return {
                success: true,
                policyState: portalPolicyRuntimeStore.getState()
            }
        } catch (err) {
            return {
                success: false,
                error: err?.code || err?.message || String(err),
                message: err?.portalMessage || err?.message || String(err),
                policyState: portalPolicyRuntimeStore.getState()
            }
        }
    }

    async msg_select_policy(message) {
        const engine = normalizePortalPolicyEngine(message?.engine)
        if (!engine) {
            return Promise.resolve({
                success: false,
                error: "invalid_policy_engine",
                policyState: portalPolicyRuntimeStore.getState()
            })
        }
        try {
            const apiKey = getPortalApiKey()
            await portalPolicyRuntimeStore.selectPolicy({
                engine,
                policyId: message?.policyId,
                policyName: message?.policyName || null,
                apiKey: apiKey || null
            })
            return {
                success: true,
                policyState: portalPolicyRuntimeStore.getState()
            }
        } catch (err) {
            return {
                success: false,
                error: err?.code || err?.message || String(err),
                message: err?.portalMessage || err?.message || String(err),
                policyState: portalPolicyRuntimeStore.getState()
            }
        }
    }

    async msg_clear_policy(message) {
        const engine = normalizePortalPolicyEngine(message?.engine)
        if (!engine) {
            return Promise.resolve({
                success: false,
                error: "invalid_policy_engine",
                policyState: portalPolicyRuntimeStore.getState()
            })
        }
        portalPolicyRuntimeStore.clearPolicy(engine)
        return Promise.resolve({
            success: true,
            policyState: portalPolicyRuntimeStore.getState()
        })
    }

    async msg_get_full_dashboard(message) {
        const scans = await this._buildDashboardScansState({ includeStored: true })
        return await this._buildFullDashboardPayload(scans)
    }

    _buildOwaspCounts(findings = []) {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        if (!Array.isArray(findings)) return counts
        findings.forEach((finding) => {
            const sev = (finding?.severity || finding?.effectiveSeverity || finding?.risk || 'info').toString().toLowerCase()
            if (sev in counts) {
                counts[sev] += 1
            }
        })
        return counts
    }

    _buildOwaspSig(findings = [], countsBySeverity = {}, updatedAt = 0) {
        if (!Array.isArray(findings)) return `owasp:0:${updatedAt}`
        const normalized = findings.map((row) => {
            if (Array.isArray(row)) {
                const title = row[0] || ''
                const desc = row[1] || ''
                return `${title}:${String(desc).length}`
            }
            const title = row?.title || row?.name || ''
            const sev = (row?.severity || row?.effectiveSeverity || row?.risk || 'info').toString().toLowerCase()
            return `${title}:${sev}`
        })
        normalized.sort()
        const head = normalized.slice(0, 10).join('|')
        const counts = ['critical', 'high', 'medium', 'low', 'info']
            .map((k) => `${k}:${countsBySeverity?.[k] || 0}`)
            .join('|')
        return `owasp:${findings.length}:${counts}:${head}:${updatedAt}`
    }

    _buildHeadersSig(requestHeaders = {}, updatedAt = 0) {
        const names = Object.keys(requestHeaders || {}).map((k) => k.toLowerCase()).sort()
        let totalLen = 0
        names.forEach((name) => {
            const values = requestHeaders[name] || []
            if (Array.isArray(values)) {
                values.forEach((v) => {
                    totalLen += String(v || '').length
                })
            }
        })
        return `headers:${names.join(',')}:${totalLen}:${updatedAt}`
    }

    async msg_headers_refresh(message) {
        const tabId = message?.tabId || worker.ptk_app.proxy.activeTab?.tabId
        const requestId = message?.requestId || null
        if (!tabId) {
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_dashboard",
                type: "headers_update",
                tabId: null,
                requestId,
                status: "error",
                updatedAt: Date.now(),
                sig: `error:${Date.now()}`,
                errorMessage: "Active tab not set"
            }).catch(e => e)
            return Promise.resolve()
        }

        const tab = worker.ptk_app.proxy.getTab(tabId)
        if (!tab) {
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_dashboard",
                type: "headers_update",
                tabId,
                requestId,
                status: "error",
                updatedAt: Date.now(),
                sig: `error:${Date.now()}`,
                errorMessage: "Tab not tracked"
            }).catch(e => e)
            return Promise.resolve()
        }

        const cacheKey = String(tabId)
        const cached = this.headerAnalysisCache.get(cacheKey)
        const lastActivityAt = worker.ptk_app.proxy.getTabActivity(tabId)
        let requestHeaders = {}
        if (!cached || !cached.timestamp || (lastActivityAt && lastActivityAt > cached.timestamp)) {
            const tabInfo = await tab.analyze()
            requestHeaders = tabInfo?.requestHeaders || {}
        }
        const ttlMs = 60000
        if (cached?.result) {
            const owasp = { findings: cached.result.securityFindings || [], countsBySeverity: this._buildOwaspCounts(cached.result.securityFindings || []) }
            const updatedAt = cached.timestamp || Date.now()
            const sig = `${this._buildOwaspSig(owasp.findings, owasp.countsBySeverity, updatedAt)}|${this._buildHeadersSig(requestHeaders, updatedAt)}`
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_dashboard",
                type: "headers_update",
                tabId,
                requestId,
                status: "cache",
                owasp,
                requestHeaders,
                updatedAt,
                sig
            }).catch(e => e)
        }

        const isStale = !cached ||
            (Date.now() - (cached.timestamp || 0)) > ttlMs ||
            (lastActivityAt && lastActivityAt > (cached.timestamp || 0))
        if (!isStale) {
            return Promise.resolve()
        }

        try {
            const result = await this.runHeaderAnalysis(tab)
            const latest = this.headerAnalysisCache.get(cacheKey)
            const updatedAt = latest?.timestamp || Date.now()
            const owasp = { findings: result.securityFindings || [], countsBySeverity: this._buildOwaspCounts(result.securityFindings || []) }
            const sig = `${this._buildOwaspSig(owasp.findings, owasp.countsBySeverity, updatedAt)}|${this._buildHeadersSig(requestHeaders, updatedAt)}`
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_dashboard",
                type: "headers_update",
                tabId,
                requestId,
                status: "fresh",
                owasp,
                requestHeaders,
                updatedAt,
                sig
            }).catch(e => e)
        } catch (err) {
            const updatedAt = Date.now()
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_dashboard",
                type: "headers_update",
                tabId,
                requestId,
                status: "error",
                updatedAt,
                sig: `error:${updatedAt}`,
                errorMessage: err?.message || "Header analysis failed"
            }).catch(e => e)
        }

        return Promise.resolve()
    }

    async _buildFullDashboardPayload(scans) {
        //this.Wappalyzer = Wappalyzer
        this.activeTab = worker.ptk_app.proxy.activeTab
        this.privacy = worker.ptk_app.settings.privacy
        await this.ensureAnalysisRulesReady()
        this.setWappalyzer(this.technologies, this.categories)

        if (this.activeTab?.tabId) {
            const tabKey = `${this.activeTab.tabId}:${this.activeTab.url || ''}`
            // Always re-init content on popup open (MV3 may reload content scripts); clear cache entry.
            this.contentInitCache.delete(tabKey)
            const contentAlreadyInitialized = false
            // Always send init message to content script for now (no cache)
            if (!contentAlreadyInitialized && this._wappalyzerRulesBuilt) {
                const requestId = `ptk-wappalyzer-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
                browser.tabs.sendMessage(this.activeTab.tabId, {
                    channel: "ptk_background2content",
                    type: "init",
                    tabId: this.activeTab.tabId,
                    url: this.activeTab.url || '',
                    dom: this.wappalyzerDomRules,
                    js: [
                        ...(this.wappalyzerJsRules || []),
                        ...(this.cveJsRules || [])
                    ],
                    css: this.wappalyzerCssRules,
                    html: {
                        technologies: this.wappalyzerHtmlPlan || [],
                        waf: this.wappalyzerWafHtmlPlan || [],
                        cve: this.cveHtmlPlan || []
                    },
                    requestId: requestId
                }).catch(() => {})
                this.contentInitCache.set(tabKey, Date.now())
            }

            const tab = worker.ptk_app.proxy.getTab(this.activeTab.tabId)
            if (tab) {
                const result = await tab.analyze()
                // Get per-tab cached analysis data for THIS specific tab
                const perTabCache = this._getTabAnalysisCache(this.activeTab.tabId)
                this['tab'] = result
                this.tab.tabId = this.activeTab.tabId
                // Restore cached analysis data for this tab
                if (perTabCache?.technologies?.length) this.tab.technologies = perTabCache.technologies
                if (perTabCache?.cves?.length) this.tab.cves = perTabCache.cves
                if (perTabCache?.waf) this.tab.waf = perTabCache.waf
                if (perTabCache?.storage) this.tab.storage = perTabCache.storage
                const headerAnalysis = await this.runHeaderAnalysis(tab)
                this.tab.findings = headerAnalysis.securityFindings
                this.tab.techHeaderMatches = headerAnalysis.techHeaderMatches
                this.tab.headerAnalysisEvidence = headerAnalysis.evidence
                this.initCookies(result.urls)

                return Object.assign(
                    {},
                    this,
                    worker.ptk_app.proxy.activeTab,
                    { findings: this.tab.findings },
                    { scans: scans },
                    { policyState: portalPolicyRuntimeStore.getState() }
                )
            }
        }

        return Object.assign(
            {},
            worker.ptk_app.proxy.activeTab,
            { privacy: this.privacy },
            { scans: scans },
            { policyState: portalPolicyRuntimeStore.getState() }
        )
    }

    msg_analyze(message, tab) {
        if (!this.tab) {
            this.tab = {}
        }
        return this.analyzeTab(message).then(() => Object.assign({}, this))
    }

    // Handle request for fresh tab analysis when popup has no cached data
    async msg_request_tab_analysis(message) {
        const tabId = message?.tabId || this.activeTab?.tabId || worker.ptk_app.proxy.activeTab?.tabId
        if (!tabId) {
            return { success: false, reason: 'no_active_tab' }
        }
        const proxyTab = worker.ptk_app.proxy.getTab(tabId)
        const tabUrl = proxyTab?.url || message?.url || this.activeTab?.url || worker.ptk_app.proxy.activeTab?.url || ''

        // Send init message to content script to trigger fresh wappalyzer analysis
        const requestId = `ptk-wappalyzer-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
        await this.ensureAnalysisRulesReady()

        // Clear content init cache for this tab to force re-init
        const tabKey = `${tabId}:${tabUrl}`
        this.contentInitCache.delete(tabKey)

        try {
            await browser.tabs.sendMessage(tabId, {
                channel: "ptk_background2content",
                type: "init",
                dom: this.wappalyzerDomRules || [],
                js: [
                    ...(this.wappalyzerJsRules || []),
                    ...(this.cveJsRules || [])
                ],
                css: this.wappalyzerCssRules || [],
                html: {
                    technologies: this.wappalyzerHtmlPlan || [],
                    waf: this.wappalyzerWafHtmlPlan || [],
                    cve: this.cveHtmlPlan || []
                },
                requestId: requestId
            })
            this.contentInitCache.set(tabKey, Date.now())
            return { success: true, tabId: tabId }
        } catch (e) {
            return { success: false, reason: 'content_script_error', error: e.message }
        }
    }

    /* End Listeners */
}
