/* Author: Denis Podgurskii */
import { Wappalyzer } from "../packages/wappalyzer/wappalyzer.js"
import { buildCssPlan } from "../packages/wappalyzer/cssRules.js"
import { buildHtmlPlan } from "../packages/wappalyzer/htmlRules.js"
import { analyzeHeadersForTab } from "./headerAnalysis/headerAnalyzer.js"
import { setWappalyzerTechnologiesForHeaders } from "./headerAnalysis/wappalyzerHeadersEvaluator.js"
import { setCveTechnologiesForHeaders } from "./headerAnalysis/cveHeadersEvaluator.js"
import { ptk_utils, ptk_storage } from "./utils.js"


const worker = self

export class ptk_dashboard {
    constructor() {
        this.headerAnalysisCache = new Map()
        this.contentInitCache = new Map()
        // Per-tab cache for analysis data (technologies, cves, waf)
        this.tabAnalysisCache = new Map()

        fetch(browser.runtime.getURL('ptk/packages/wappalyzer/technologies.json'))
            .then(response => response.json())
            .then(data => {
                this.technologies = data.technologies
                this.categories = data.categories
                this.wappalyzerCssRules = []
                const htmlData = buildHtmlPlan(this.technologies, 'technologies')
                this.wappalyzerHtmlPlan = htmlData.plan
                this.wappalyzerHtmlPatterns = htmlData.patternIndex
                setWappalyzerTechnologiesForHeaders(this.technologies)
            })

        fetch(browser.runtime.getURL('ptk/packages/wappalyzer/waf.json'))
            .then(response => response.json())
            .then(data => {
                this.wafTechnologies = data.technologies
                this.wafCategories = data.categories
                const htmlData = buildHtmlPlan(this.wafTechnologies, 'waf')
                this.wappalyzerWafHtmlPlan = htmlData.plan
                this.wappalyzerWafHtmlPatterns = htmlData.patternIndex
            })

        fetch(browser.runtime.getURL('ptk/packages/wappalyzer/cves.json'))
            .then(response => response.json())
            .then(data => {
                this.cveRaw = data
                this.cveTechnologies = data.technologies || {}
                this.cveCategories = data.categories || []
                const htmlData = buildHtmlPlan(this.cveTechnologies, 'cve')
                this.cveHtmlPlan = htmlData.plan
                this.cveHtmlPatterns = htmlData.patternIndex
                setCveTechnologiesForHeaders(this.cveTechnologies)
            })

        this.addMessageListiners()
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
            dast: this._hasExportableScanResult(overrides.dast || worker.ptk_app?.rattacker?.scanResult),
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
            cookies: cookies
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
            cookies: cookies
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
                headers: new Map()
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

            let cveDetections = []
            cveDetections = cveDetections.concat(jsDetections).concat(cveHtmlDetections).concat(cveHeaderDetections)

            const resolvedCves = Wappalyzer.resolve(cveDetections) || []
            const cveDefinitions = this.cveTechnologies || {}

            this.tab.cves = (Array.isArray(resolvedCves) ? resolvedCves : []).map((item) => {
                const id = item.name
                const raw = cveDefinitions[id] || {}
                const meta = raw.ptk || {}
                const evidence = {
                    js: cveEvidence.js.get(id) || 0,
                    html: cveEvidence.html.get(id) || 0,
                    headers: cveEvidence.headers.get(id) || 0
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

    async msg_run_bg_scan(message) {
        const running = {
            dast: worker.ptk_app.rattacker.engine.isRunning,
            iast: worker.ptk_app.iast.isScanRunning,
            sast: worker.ptk_app.sast.isScanRunning,
            sca: worker.ptk_app.sca.isScanRunning
        }
        const skipped = { dast: false, iast: false, sast: false, sca: false }

        if (message.scans.dast) {
            if (running.dast) skipped.dast = true
            else worker.ptk_app.rattacker.runBackgroundScan(message.tabId, message.host, message.domains, message.settings)
        }
        if (message.scans.iast) {
            if (running.iast) skipped.iast = true
            else worker.ptk_app.iast.runBackgroundScan(message.tabId, message.host)
        }
        if (message.scans.sast) {
            if (running.sast) {
                skipped.sast = true
            } else {
            worker.ptk_app.sast.msg_run_bg_scan({
                tabId: message.tabId,
                host: message.host,
                scanStrategy: message.settings.sastScanStrategy ?? message.settings.policy
            })
            }
        }
        if (message.scans.sca) {
            if (running.sca) skipped.sca = true
            else worker.ptk_app.sca.runBackgroundScan(message.tabId, message.host)
        }

        let scans = {
            dast: worker.ptk_app.rattacker.engine.isRunning,
            iast: worker.ptk_app.iast.isScanRunning,
            sast: worker.ptk_app.sast.isScanRunning,
            sca: worker.ptk_app.sca.isScanRunning,
            exportable: this._buildExportableFlags()
        }

        let payload = {}
        try {
            payload = JSON.parse(JSON.stringify({
                activeTab: worker.ptk_app.proxy.activeTab || null,
                scans,
                skipped
            }))
        } catch (e) {
            payload = { activeTab: null, scans, skipped }
        }

        return Promise.resolve(payload)
    }

    async msg_stop_bg_scan(message) {

        if (message.scans.dast) worker.ptk_app.rattacker.stopBackgroundScan()
        if (message.scans.iast) worker.ptk_app.iast.stopBackgroundScan()
        if (message.scans.sast) worker.ptk_app.sast.stopBackgroundScan()
        if (message.scans.sca) worker.ptk_app.sca.stopBackgroundScan()

        let scans = {
            dast: worker.ptk_app.rattacker.engine.isRunning,
            iast: worker.ptk_app.iast.isScanRunning,
            sast: worker.ptk_app.sast.isScanRunning,
            sca: worker.ptk_app.sca.isScanRunning,
            exportable: this._buildExportableFlags()
        }

        return Promise.resolve(Object.assign({}, { scans: JSON.parse(JSON.stringify(scans)) }))
    }

    async msg_get(message) {
        return Promise.resolve(Object.assign({},
            this,
            worker.ptk_app.proxy.activeTab))
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
            if (['session', 'sca', 'iast', 'sast', 'proxy', 'rbuilder', 'rattacker', 'macro', 'traffic', 'swagger', 'decoder', 'portscanner', 'jwt', 'xss', 'sql'].includes(worker.ptk_app.settings.history.route)) {
                link = worker.ptk_app.settings.history.route + ".html"
                if (worker.ptk_app.settings.history.hash) {
                    link += "#" + worker.ptk_app.settings.history.hash
                }
            }
            if (link != "")
                return Promise.resolve({ redirect: link, items: this.items })
        }

        const scans = {
            dast: worker.ptk_app.rattacker.engine.isRunning,
            iast: worker.ptk_app.iast.isScanRunning,
            sast: worker.ptk_app.sast.isScanRunning,
            sca: worker.ptk_app.sca.isScanRunning,
            dastSettings: worker.ptk_app.rattacker.settings,
            exportable: this._buildExportableFlags()
        }
        try {
            const activeUrl = worker.ptk_app.proxy.activeTab?.url || null
            const host = activeUrl ? new URL(activeUrl).host : null
            if (host) {
                scans.hasAnyScanForHost = !!(
                    worker.ptk_app.rattacker.scanResult?.host === host ||
                    worker.ptk_app.iast.scanResult?.host === host ||
                    worker.ptk_app.sast.scanResult?.host === host ||
                    worker.ptk_app.sca.scanResult?.host === host
                )
            } else {
                scans.hasAnyScanForHost = false
            }
        } catch (_) {
            scans.hasAnyScanForHost = false
        }

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
                tabData ? { tab: tabData } : {},
                { hasAnalysisData: !!hasAnalysisData },
                perTabCache ? { tabCacheUpdatedAt: perTabCache.updatedAt || null } : {}
            )
        }
    }

    async msg_get_full_dashboard(message) {
        // Only load from storage if in-memory results are empty
        const inMemoryFlags = this._buildExportableFlags()
        const scans = {
            dast: worker.ptk_app.rattacker.engine.isRunning,
            iast: worker.ptk_app.iast.isScanRunning,
            sast: worker.ptk_app.sast.isScanRunning,
            sca: worker.ptk_app.sca.isScanRunning,
            dastSettings: worker.ptk_app.rattacker.settings,
            exportable: inMemoryFlags
        }
        try {
            const activeUrl = worker.ptk_app.proxy.activeTab?.url || null
            const host = activeUrl ? new URL(activeUrl).host : null
            if (host) {
                scans.hasAnyScanForHost = !!(
                    worker.ptk_app.rattacker.scanResult?.host === host ||
                    worker.ptk_app.iast.scanResult?.host === host ||
                    worker.ptk_app.sast.scanResult?.host === host ||
                    worker.ptk_app.sca.scanResult?.host === host
                )
            } else {
                scans.hasAnyScanForHost = false
            }
        } catch (_) {
            scans.hasAnyScanForHost = false
        }
        if (!inMemoryFlags.any) {
            const stored = await this._loadStoredScanResults()
            scans.exportable = this._buildExportableFlags(stored)
        }
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

        this.setWappalyzer(this.technologies, this.categories)

        // Build Wappalyzer rules only once, cache them for subsequent calls
        // HTML plans are already guarded, add guards for DOM/JS/CSS rules
        if (!this._wappalyzerRulesBuilt && this.technologies) {
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

            // Cache DOM/JS/CSS rules - these don't change during session
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
        }

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

                return Object.assign({}, this, worker.ptk_app.proxy.activeTab, { findings: this.tab.findings }, { scans: scans })
            }
        }

        return Object.assign({}, worker.ptk_app.proxy.activeTab, { privacy: this.privacy }, { scans: scans })
    }

    msg_analyze(message, tab) {
        if (!this.tab) {
            this.tab = {}
        }
        this.analyzeTab(message)
        return Promise.resolve(Object.assign({}, this))
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

        // Ensure wappalyzer rules are built
        if (!this._wappalyzerRulesBuilt && this.technologies) {
            this.setWappalyzer(this.technologies, this.categories)

            const activeTechnologies = new Set(Wappalyzer.technologies.map(({ name }) => name))

            if (!this.wappalyzerHtmlPlan?.length) {
                const htmlData = buildHtmlPlan(this.technologies, 'technologies')
                this.wappalyzerHtmlPlan = htmlData.plan
                this.wappalyzerHtmlPatterns = htmlData.patternIndex
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
        }

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
