/* Author: Denis Podgurskii */
import { dastEngine } from "./dast/dastEngine.js"
import { ptk_utils, ptk_logger, ptk_storage } from "../background/utils.js"
import { loadRulepack } from "./common/moduleRegistry.js"
import { normalizeRulepack } from "./common/severity_utils.js"
import buildExportScanResult from "./export/buildExportScanResult.js"


const worker = self

export class ptk_rattacker {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_rattacker"

        this.engine = new dastEngine(this.settings)
        this._sentAllAttacksCompleted = false
        this.addMessageListeners()
        this._acceptIncomingRequests = false
        this.automationSession = null
        this.cveModulesCache = null
    }


    async init() {
        this.storage = await ptk_storage.getItem(this.storageKey)
        if (!this.engine.isRunning && Object.keys(this.storage).length > 0) {
            this.scanResult = this.storage
        } else {
            this.scanResult = this.engine.scanResult
        }
    }

    _cloneScanResultForUi() {
        const clone = JSON.parse(JSON.stringify(this.scanResult || {}))
        if (clone && typeof clone === "object") {
            clone.__normalized = true
        }
        return clone
    }

    async reset() {
        this.engine.reset()
        this.scanResult = this.engine.scanResult
        ptk_storage.setItem(this.storageKey, {})
    }

    async loadCveModules() {
        if (Array.isArray(this.cveModulesCache)) {
            return this.cveModulesCache
        }
        try {
            const cveRulepack = await loadRulepack('DAST', { variant: 'cve' })
            normalizeRulepack(cveRulepack, { engine: 'DAST', childKey: 'attacks' })
            this.cveModulesCache = Array.isArray(cveRulepack.modules) ? cveRulepack.modules : []
        } catch (err) {
            console.warn('[PTK DAST] Failed to load CVE rulepack', err)
            this.cveModulesCache = []
        }
        return this.cveModulesCache
    }

    async getDefaultModules() {
        const dedup = new Map()
        const cloneModule = (mod) => {
            try {
                return JSON.parse(JSON.stringify(mod))
            } catch {
                return mod
            }
        }
        const pushModules = (modules) => {
            if (!Array.isArray(modules)) return
            modules.forEach(mod => {
                if (!mod) return
                const keyCandidates = [
                    mod.id,
                    mod.moduleId,
                    mod.metadata?.module_id,
                    mod.metadata?.id,
                    mod.name,
                    mod.metadata?.module_name
                ]
                const key = String(keyCandidates.find(val => val && String(val).trim()) || JSON.stringify(mod)).toLowerCase()
                if (!dedup.has(key)) {
                    dedup.set(key, cloneModule(mod))
                }
            })
        }

        pushModules(this.engine?.modules)
        const cveModules = await this.loadCveModules()
        pushModules(cveModules)
        return Array.from(dedup.values())
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    addListeners() {
        this.onRemoved = this.onRemoved.bind(this)
        browser.tabs.onRemoved.addListener(this.onRemoved)

        this.onCompleted = this.onCompleted.bind(this)
        browser.webRequest.onCompleted.addListener(
            this.onCompleted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )

        this.onResponseStarted = this.onResponseStarted.bind(this)
        browser.webRequest.onResponseStarted.addListener(
            this.onResponseStarted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )

        this.onHeadersReceived = this.onHeadersReceived.bind(this)
        browser.webRequest.onHeadersReceived.addListener(
            this.onHeadersReceived,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )


    }

    removeListeners() {
        browser.tabs.onRemoved.removeListener(this.onRemoved)
        browser.webRequest.onCompleted.removeListener(this.onCompleted)
        browser.webRequest.onResponseStarted.removeListener(this.onResponseStarted)
        browser.webRequest.onHeadersReceived.removeListener(this.onHeadersReceived)
    }

    onRemoved(tabId, info) {
        if (this.engine.isRunning && this.engine.tabId == tabId) {
            this.engine.stop()
        }
    }


    onResponseStarted(response) {
        if (this.engine.isRunning && this._acceptIncomingRequests && this.engine.tabId == response.tabId) {
            try {
                let rawRequest = worker.ptk_app.proxy.getRawRequest(worker.ptk_app.proxy.getTab(response.tabId), response.frameId, response.requestId)
                let uiUrl = response.ui_url || response.url
                if (typeof rawRequest === 'string') {
                    const line = rawRequest.split(/\r?\n/)[0] || ''
                    const parts = line.trim().split(/\s+/)
                    const rawUrl = parts[1] || null
                    if (rawUrl) {
                        try {
                            uiUrl = rawUrl.startsWith('http')
                                ? rawUrl
                                : new URL(rawUrl, response.url).toString()
                        } catch (_) { }
                    }
                }
                this.engine.enqueue({
                    raw: rawRequest,
                    ui_url: uiUrl,
                    responseType: response.type
                }, response)
            } catch (e) { }
        }
    }

    _enqueueRedirect(response) {
        const status = response?.statusCode
        if (status < 300 || status >= 400) return
        const headers = response?.responseHeaders || []
        const locationHeader = headers.find(
            (h) => (h?.name || '').toLowerCase() === 'location'
        )
        const locationValue = locationHeader?.value || null
        if (!locationValue) return
        try {
            const redirectUrl = new URL(locationValue, response.url).toString()
            const urlObj = new URL(redirectUrl)
            const syntheticRaw = `GET ${redirectUrl} HTTP/1.1\r\nHost: ${urlObj.host}\r\n\r\n`
            const redirectResponse = Object.assign({}, response, {
                url: redirectUrl,
                ui_url: redirectUrl
            })
            this.engine.enqueue({
                raw: syntheticRaw,
                ui_url: redirectUrl,
                responseType: response.type
            }, redirectResponse)
        } catch (_) { }
    }

    onHeadersReceived(response) {
        if (this.engine.isRunning && this._acceptIncomingRequests && this.engine.tabId == response.tabId) {
            try {
                this._enqueueRedirect(response)
            } catch (e) { }
        }
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

    onCompleted(response) {
        // if (this.engine.isRunning && this.engine.tabId == response.tabId) {
        //     try {
        //         let rawRequest = worker.ptk_app.proxy.getRawRequest(worker.ptk_app.proxy.getTab(response.tabId), response.frameId, response.requestId)
        //         this.engine.enqueue(rawRequest, response)
        //     } catch (e) { }
        // }
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
        if (message.channel == "ptk_contentws2rattacker") {

            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (message.channel == "ptk_popup2background_rattacker") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (message.channel == "ptk_content2rattacker") {

            if (message.type == 'xss_confirmed' && this.scanResult.host == (new URL(message.data.origin)).host) {
                this.checkConfirmedAttack(message.data)
            }

            if (message.type == 'spa_url_changed' && sender?.tab?.id) {
                if (worker?.ptk_app?.proxy?.tabUrlMap) {
                    worker.ptk_app.proxy.tabUrlMap.set(sender.tab.id, message.url)
                }
                if (this.engine?.isRunning && this.engine.tabId === sender.tab.id) {
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
                this.stopBackgroundScan()
                let result = { attacks: this.scanResult.attacks, stats: this.scanResult.stats }
                return Promise.resolve({ scanResult: JSON.parse(JSON.stringify(result)) })
            }
        }
    }

    async msg_init(message) {
        await this.init()
        const defaultModules = await this.getDefaultModules()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi(),
            isScanRunning: this.engine.isRunning,
            default_modules: defaultModules,
            activeTab: worker.ptk_app.proxy.activeTab,
            settings: this.settings
        })
    }

    async msg_get_request_snapshot(message) {
        const requestId = message?.requestId
        if (!requestId) {
            return Promise.resolve({ requestId: null, original: null, attack: null })
        }
        const requests = Array.isArray(this.scanResult?.requests) ? this.scanResult.requests : []
        const record = requests.find(item => String(item?.id) === String(requestId)) || null
        if (!record) {
            return Promise.resolve({ requestId, original: null, attack: null })
        }
        const attackId = message?.attackId
        let attack = null
        if (attackId && Array.isArray(record.attacks)) {
            attack = record.attacks.find(item => String(item?.id) === String(attackId)) || null
        }
        const clone = (val) => {
            try {
                return JSON.parse(JSON.stringify(val))
            } catch (_) {
                return val || null
            }
        }
        return Promise.resolve({
            requestId,
            original: clone(record.original || null),
            attack: clone(attack)
        })
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
        let profile = worker.ptk_app.settings.profile || {}
        let apiKey = profile?.api_key
        if (apiKey && Object.keys(this.scanResult?.items || {}).length > 0) {
            let url = this.buildPortalUrl(profile.scans_endpoint, profile)
            if (!url) {
                return { "success": false, "json": { "message": "Portal endpoint is not configured." } }
            }
            const payload = buildExportScanResult(this.scanResult?.scanId, {
                target: "portal",
                scanResult: this.scanResult
            })
            if (!payload) {
                return { "success": false, "json": { "message": "Scan result is empty" } }
            }
            if (message?.projectId) {
                payload.projectId = message.projectId
            }
            let response = await fetch(url, {
                method: "POST",
                headers: {
                    'Authorization': 'Bearer ' + apiKey,
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                cache: "no-cache",
                body: JSON.stringify(payload)
            })
                .then(response => {
                    if (response.status == 201)
                        return { "success": true }
                    else {
                        return response.json().then(json => {
                            return { "success": false, json }
                        })
                    }
                })
                .catch(e => { return { "success": false, "json": { "message": "Error while saving report: " + e.message } } })
            return response
        } else {
            return { "success": false, "json": { "message": "No API key found" } }
        }
    }

    async msg_export_scan_result(message) {
        if (!this.scanResult || Object.keys(this.scanResult).length === 0) {
            const stored = await ptk_storage.getItem(this.storageKey)
            if (stored && stored.scanResult && Object.keys(stored.scanResult).length) {
                this.scanResult = stored.scanResult
            } else if (stored && Object.keys(stored).length) {
                this.scanResult = stored
            }
        }
        if (!this.scanResult) return null
        try {
            return buildExportScanResult(this.scanResult?.scanId, {
                target: message?.target || "download",
                scanResult: this.scanResult
            })
        } catch (err) {
            console.error("[PTK DAST] Failed to export scan result", err)
            throw err
        }
    }

    async msg_get_projects(message) {
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { "success": false, "json": { "message": "No API key found" } }
        }
        const url = this.buildPortalUrl(profile.projects_endpoint, profile)
        if (!url) {
            return { "success": false, "json": { "message": "Portal endpoint is not configured." } }
        }
        const response = await fetch(url, {
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json'
            },
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) {
                    return { "success": true, json }
                }
                return { "success": false, json: json || { "message": "Unable to load projects" } }
            })
            .catch(e => ({ "success": false, "json": { "message": "Error while loading projects: " + e.message } }))
        return response
    }

    buildPortalUrl(endpoint, profile) {
        profile = profile || worker.ptk_app.settings.profile || {}
        const baseUrl = (profile.base_url || profile.api_url || "").trim()
        const apiBase = (profile.api_base || "").trim()
        const resolvedEndpoint = (endpoint || "").trim()
        if (!baseUrl || !apiBase || !resolvedEndpoint) return null
        const normalizedBase = baseUrl.replace(/\/+$/, "")
        let normalizedApiBase = apiBase.replace(/\/+$/, "")
        if (!normalizedApiBase.startsWith('/')) normalizedApiBase = '/' + normalizedApiBase
        let normalizedEndpoint = resolvedEndpoint
        if (!normalizedEndpoint.startsWith('/')) normalizedEndpoint = '/' + normalizedEndpoint
        return normalizedBase + normalizedApiBase + normalizedEndpoint
    }

    async msg_download_scans(message) {
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { "success": false, "json": { "message": "No API key found" } }
        }
        const baseUrl = this.buildPortalUrl(profile.scans_endpoint, profile)
        if (!baseUrl) {
            return { "success": false, "json": { "message": "Portal endpoint is not configured." } }
        }
        let requestUrl = baseUrl
        try {
            const url = new URL(baseUrl)
            if (message?.projectId) {
                url.searchParams.set('projectId', message.projectId)
            }
            const engine = message?.engine || 'dast'
            if (engine) {
                url.searchParams.set('engine', engine)
            }
            requestUrl = url.toString()
        } catch (err) {
            return { "success": false, "json": { "message": "Invalid scans endpoint." } }
        }
        const response = await fetch(requestUrl, {
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json'
            },
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) {
                    return { "success": true, json }
                }
                return { "success": false, json: json || { "message": "Unable to load scans" } }
            })
            .catch(e => ({ "success": false, "json": { "message": "Error while loading scans: " + e.message } }))
        return response
    }

    async msg_download_scan_by_id(message) {
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { "success": false, "json": { "message": "No API key found" } }
        }
        if (!message?.scanId) {
            return { "success": false, "json": { "message": "Scan identifier is required." } }
        }
        const baseUrl = this.buildPortalUrl(profile.scans_endpoint, profile)
        if (!baseUrl) {
            return { "success": false, "json": { "message": "Portal endpoint is not configured." } }
        }
        const normalizedBase = baseUrl.replace(/\/+$/, "")
        const downloadUrl = `${normalizedBase}/${encodeURIComponent(message.scanId)}/download`
        const response = await fetch(downloadUrl, {
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json'
            },
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (!httpResponse.ok) {
                    return { "success": false, "json": json || { "message": "Unable to download scan" } }
                }
                if (json) {
                    this.scanResult = json
                    ptk_storage.setItem(this.storageKey, json)
                }
                return json
            })
            .catch(e => ({ "success": false, "json": { "message": "Error while downloading scan: " + e.message } }))
        return response
    }

    async msg_delete_scan_by_id(message) {
        let apiKey = worker.ptk_app.settings.profile?.api_key
        if (apiKey) {
            let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.storage_endpoint + "/" + message.scanId
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
        const defaultModules = await this.getDefaultModules()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi(),
            default_modules: defaultModules,
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }

    async msg_loadfile(message) {
        this.reset()

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
        const raw = JSON.parse(message.json || "{}")
        const normalized = this.normalizeImportedScan(raw)
        if (!normalized) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        this.reset()
        this.scanResult = normalized
        ptk_storage.setItem(this.storageKey, JSON.parse(JSON.stringify(normalized)))
        const defaultModules = await this.getDefaultModules()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi(),
            isScanRunning: this.engine.isRunning,
            default_modules: defaultModules,
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }

    msg_run_bg_scan(message) {
        this.runBackgroundScan(message.tabId, message.host, message.domains, message.settings)
        return Promise.resolve({ isScanRunning: this.engine.isRunning, scanResult: this._cloneScanResultForUi() })
    }

    msg_stop_bg_scan(message) {
        this.stopBackgroundScan()
        return Promise.resolve({ scanResult: this._cloneScanResultForUi() })
    }

    runBackgroundScan(tabId, host, domains, settings) {
        if (this.engine?.isRunning) {
            return false
        }
        const resolvedSettings = Object.assign({}, this.settings || {}, settings || {})
        const normalizedDomains = Array.isArray(domains) ? domains.join(',') : domains
        const targetDomains = normalizedDomains && normalizedDomains.length ? normalizedDomains : host
        this.reset()
        this._sentAllAttacksCompleted = false
        this.addListeners()
        this._acceptIncomingRequests = true
        if(resolvedSettings.ws)
            this.registerScript()
        this.engine.start(tabId, host, this.parseDomains(targetDomains), resolvedSettings)
    }

    stopBackgroundScan() {
        this._acceptIncomingRequests = false
        this.engine.stop()
        this.scanResult = this.engine.scanResult
        if (this.scanResult) {
            this.scanResult.finished = new Date().toISOString()
        }
        if (!this._sentAllAttacksCompleted) {
            this._sentAllAttacksCompleted = true
            // Send completion once to avoid per-result message spam.
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_rattacker",
                type: "all attacks completed",
                info: { completed: true }
            }).catch(e => e)
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_rattacker",
                type: "dast_scan_completed",
                info: { completed: true }
            }).catch(e => e)
        }
        ptk_storage.setItem(this.storageKey, this.scanResult)
        this.unregisterScript()
        this.removeListeners()
    }


    checkConfirmedAttack(data) {
        this.engine.updateScanResult(null, data)
    }

    async startAutomationSession({ sessionId, tabId, host, domains, settings, policyCode, hooks }) {
        if (!sessionId || !tabId || !host) {
            throw new Error('missing_session_parameters')
        }
        if (this.automationSession && this.automationSession.id !== sessionId) {
            throw new Error('automation_session_already_running')
        }
        this.automationSession = { id: sessionId }
        const resolvedSettings = Object.assign({}, settings || {})
        if (policyCode) {
            resolvedSettings.policyCode = policyCode
        }
        this.runBackgroundScan(tabId, host, domains || host, resolvedSettings)
        if (this.engine?.setAutomationHooks) {
            this.engine.setAutomationHooks({
                sessionId,
                onTaskStarted: hooks?.onTaskStarted,
                onTaskFinished: hooks?.onTaskFinished
            })
        }
        return { success: true }
    }

    async stopAutomationSession(sessionId, timeoutMs = 180000) {
        if (!this.automationSession || this.automationSession.id !== sessionId) {
            throw new Error('automation_session_mismatch')
        }
        this._acceptIncomingRequests = false
        await this.engine.waitForIdle(timeoutMs)
        if (this.engine?.setAutomationHooks) {
            this.engine.setAutomationHooks(null)
        }
        this.stopBackgroundScan()
        const stats = this._collectSeverityStats()
        this.automationSession = null
        return {
            findingsCount: stats.findingsCount,
            bySeverity: Object.assign({
                info: 0,
                low: 0,
                medium: 0,
                high: 0,
                critical: 0
            }, stats.counts || {})
        }
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
                            accumulate(attack.metadata?.severity)
                        }
                    })
                })
            } else {
                const items = Array.isArray(this.scanResult?.items) ? this.scanResult.items : []
                for (const item of items) {
                    const attacks = Array.isArray(item?.attacks) ? item.attacks : []
                    attacks.forEach(attack => {
                        if (attack?.success) {
                            accumulate(attack.metadata?.severity)
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
        const severity = this._collectSeverityStats()
        return {
            findingsCount: severity.findingsCount,
            bySeverity: Object.assign({}, severity.counts)
        }
    }

    normalizeImportedScan(raw) {
        if (!raw || typeof raw !== "object") return null
        const clone = JSON.parse(JSON.stringify(raw))
        if (clone.scanResult) {
            return clone.scanResult
        }
        if (clone.engine && Array.isArray(clone.requests)) {
            return clone
        }
        if (!clone.type || String(clone.type).toLowerCase() === 'dast') {
            const items = Array.isArray(clone.items) ? clone.items : []
            if (items.length) {
                return clone
            }
        }
        return null
    }
}
