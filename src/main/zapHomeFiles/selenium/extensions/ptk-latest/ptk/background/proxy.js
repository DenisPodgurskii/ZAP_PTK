/* Author: Denis Podgurskii */
import { ptk_logger, ptk_utils } from "./utils.js"

/*
{frames: new Map[ frameId: new Map [requestId: [item: {request: object, response: object} ] ] ] }
*/

const worker = self

export class ptk_proxy {

    constructor(settings) {
        this.maxTabsCount = settings.max_tabs
        this.maxRequestsPerTab = settings.max_requests_per_tab

        this.tabs = {}
        this._createdTab = null
        this._activeTab = null
        this._previousTab = null
        this._dashboardTab = null
        this.tabUrlMap = new Map()
        this._tabActivity = new Map()

        this.addMessageListiners()
        this.addListiners()
        this.restoreActiveTabFromBrowser()
    }

    /* Listeners */

    addListiners() {

        this.onActivated = this.onActivated.bind(this)
        browser.tabs.onActivated.addListener(this.onActivated)
        this.onUpdated = this.onUpdated.bind(this)
        browser.tabs.onUpdated.addListener(this.onUpdated)
        this.onRemoved = this.onRemoved.bind(this)
        browser.tabs.onRemoved.addListener(this.onRemoved)

        this.onBeforeRequest = this.onBeforeRequest.bind(this)
        browser.webRequest.onBeforeRequest.addListener(
            this.onBeforeRequest,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["requestBody"].concat(ptk_utils.extraInfoSpec)
        )
        this.onSendHeaders = this.onSendHeaders.bind(this)
        browser.webRequest.onSendHeaders.addListener(
            this.onSendHeaders,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["requestHeaders"].concat(ptk_utils.extraInfoSpec)
        )

        this.onBeforeRedirect = this.onBeforeRedirect.bind(this)
        browser.webRequest.onBeforeRedirect.addListener(
            this.onBeforeRedirect,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )

        this.onCompleted = this.onCompleted.bind(this)
        browser.webRequest.onCompleted.addListener(
            this.onCompleted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )
    }

    removeListeners() {
        browser.tabs.onActivated.removeListener(this.onActivated)
        browser.tabs.onUpdated.removeListener(this.onUpdated)
        browser.tabs.onRemoved.removeListener(this.onRemoved)

        browser.webRequest.onBeforeRequest.removeListener(this.onBeforeRequest)
        browser.webRequest.onSendHeaders.removeListener(this.onSendHeaders)
        browser.webRequest.onBeforeRedirect.removeListener(this.onBeforeRedirect)
        browser.webRequest.onCompleted.removeListener(this.onCompleted)
    }

    restoreActiveTabFromBrowser() {
        try {
            this.ensureActiveTabContext().catch(e => {
                ptk_logger.log(e, "Could not restore active tab", "info")
            })
        } catch (e) {
            ptk_logger.log(e, "Could not query tabs for restore", "info")
        }
    }

    _rememberResolvedBrowserTab(tab) {
        if (!tab || typeof tab.id !== 'number' || !ptk_utils.isURL(tab.url)) return null
        this.tabUrlMap.set(tab.id, tab.url)
        this._createdTab = { tabId: tab.id, window: tab.windowId }
        this.activeTab = { tabId: tab.id, url: tab.url, window: tab.windowId }
        return this.activeTab
    }

    async ensureActiveTabContext({ tabId = null, url = '' } = {}) {
        if (typeof tabId === 'number') {
            let resolvedTab = null
            if (ptk_utils.isURL(url)) {
                resolvedTab = { id: tabId, url, windowId: this.activeTab?.window || this._dashboardTab?.window }
            } else {
                resolvedTab = await browser.tabs.get(tabId).catch(() => null)
            }
            if (resolvedTab && ptk_utils.isURL(resolvedTab.url)) {
                return this._rememberResolvedBrowserTab(resolvedTab)
            }
        }

        if (ptk_utils.isURL(this.activeTab?.url) && typeof this.activeTab?.tabId === 'number') {
            return this.activeTab
        }

        const queries = [
            { active: true, currentWindow: true },
            { active: true, lastFocusedWindow: true },
            { currentWindow: true },
            {}
        ]

        for (const query of queries) {
            const tabs = await browser.tabs.query(query).catch(() => [])
            if (!Array.isArray(tabs) || !tabs.length) continue
            const candidate = tabs.find((tab) => ptk_utils.isURL(tab?.url) && tab.active)
                || tabs.find((tab) => ptk_utils.isURL(tab?.url))
            if (candidate) {
                return this._rememberResolvedBrowserTab(candidate)
            }
        }

        if (this._dashboardTab?.tabId != null && ptk_utils.isURL(this._dashboardTab?.url)) {
            this.activeTab = {
                tabId: this._dashboardTab.tabId,
                url: this._dashboardTab.url,
                window: this._dashboardTab.window || this.activeTab?.window
            }
            return this.activeTab
        }

        return this.activeTab || null
    }

    onActivated(info) {
        this._createdTab = { tabId: info.tabId, window: info.windowId }
        setTimeout(function () {
            browser.tabs.get(info.tabId).then(function (tab) {
                if (tab?.url && ptk_utils.isURL(tab?.url)) {
                    worker.ptk_app.proxy.tabUrlMap.set(info.tabId, tab.url)
                    worker.ptk_app.proxy.activeTab = { tabId: tab.id, url: tab.url, window: tab.windowId }
                }
            }).catch(e => e)
        }, 150)
    }

    onUpdated(tabId, info, tab) {
        if (tab?.url && ptk_utils.isURL(tab?.url)) {
            this.tabUrlMap.set(tabId, tab.url)
            this.activeTab = { tabId: tabId, url: tab.url, window: tab.windowId }
        }
        if (info?.url && ptk_utils.isURL(info.url)) {
            this.tabUrlMap.set(tabId, info.url)
        }
        if (this._dashboardTab?.tabId === tabId) {
            const url = tab?.url || info?.url || this._dashboardTab.url
            this._dashboardTab = { tabId, url: url || this._dashboardTab.url, window: tab?.windowId || this._dashboardTab.window }
        }
    }

    onRemoved(tabId, info) {
        if (this._previousTab && this._activeTab?.tabId == tabId) this._activeTab = this._previousTab
        if (this.tabUrlMap.has(tabId)) this.tabUrlMap.delete(tabId)
        if (this._dashboardTab?.tabId === tabId) this._dashboardTab = null
    }

    onBeforeRequest(request) {
        ptk_logger.log("ptk_tabs onBeforeRequest", { tabId: request.tabId, request: request.requestId, request: request })
        request.ui_url = this.getUiUrl(request.tabId, request.url)
        this.setTab(request.tabId, request, 'start')
    }

    onSendHeaders(request) {
        ptk_logger.log("ptk_tabs onSendHeaders", { tabId: request.tabId, request: request.requestId, request: request })
        request.ui_url = this.getUiUrl(request.tabId, request.url)
        this.setTab(request.tabId, request, 'request')
    }

    onBeforeRedirect(response) {
        ptk_logger.log("onBeforeRedirect", { tabId: response.tabId, request: response.requestId, response: response })
        response.ui_url = this.getUiUrl(response.tabId, response.url)
        this.setTab(response.tabId, response, 'redirect')
    }

    onCompleted(response) {
        ptk_logger.log("onCompleted", { tabId: response.tabId, request: response.requestId, response: response })
        response.ui_url = this.getUiUrl(response.tabId, response.url)
        this.setTab(response.tabId, response, 'response')
    }

    addMessageListiners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    onMessage(message, sender, sendResponse) {

        if (!ptk_utils.isTrustedOrigin(sender))
            return Promise.reject({ success: false, error: 'Error origin value' })

        if (message.channel == "ptk_popup2background_tabs") {
            const activeTabId = this.activeTab?.tabId
            let tab = activeTabId ? this.getTab(activeTabId) : null

            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message, tab)
            }
        }
    }

    async msg_init(message, tab) {
        await this.ensureActiveTabContext({ tabId: message?.tabId, url: message?.url || '' })
        const base = Object.assign({}, this.activeTab || {})
        if (!base.tabId) {
            const resolved = this.resolveTabContext(tab)
            if (resolved.tabId != null) {
                base.tabId = resolved.tabId
                base.url = this.getUiUrl(resolved.tabId, base.url || '')
            }
        }
        return Promise.resolve(base)
    }


    async msg_get_active_tab(message, tab) {
        await this.ensureActiveTabContext({ tabId: message?.tabId, url: message?.url || '' })
        const resolved = this.resolveTabContext(tab)
        let base = Object.assign({}, this.activeTab || {})
        if (!base.tabId && resolved.tabId != null) {
            base.tabId = resolved.tabId
        }
        if ((!base.url || !ptk_utils.isURL(base.url)) && resolved.tabId != null) {
            base.url = this.getUiUrl(resolved.tabId, base.url || '')
        }
        if (!resolved.tab) {
            return Promise.resolve(Object.assign(base, {
                frames: [],
                requests: [],
                domains: [],
                urls: [],
                responseHeaders: {},
                requestHeaders: {},
                fqdnIP: []
            }))
        }
        if (!resolved.tab.tabInfo) {
            resolved.tab.tabInfo = await resolved.tab.analyze()
        }
        return Promise.resolve(Object.assign(base, resolved.tab.tabInfo))
    }


    async msg_get_all_frames(message, tab) {
        const resolved = this.resolveTabContext(tab)
        let tabInfo = { requestHeaders: {}, responseHeaders: {}, frames: [], requests: [], domains: [], urls: [], fqdnIP: [] }
        if (resolved.tab) tabInfo = await resolved.tab.analyze()
        return Promise.resolve(tabInfo)
    }

    msg_get_frame(message, tab) {
        const resolved = this.resolveTabContext(tab)
        if (!resolved.tab || !resolved.tab.frames?.has(message.frameIndex)) {
            return Promise.resolve([])
        }
        return Promise.resolve(Array.from(resolved.tab.frames.get(message.frameIndex)))
    }

    msg_get_request_details(message, tab) {
        const resolved = this.resolveTabContext(tab)
        if (!resolved.tab) return Promise.resolve({})
        const frame = resolved.tab.frames?.get(message.frameId)
        if (!frame || !frame.has(message.requestId)) return Promise.resolve({})
        let r = this.getRequestDetails(resolved.tab, message.frameId, message.requestId)
        return Promise.resolve(r)
    }

    msg_clear(message, tab) {
        const resolved = this.resolveTabContext(tab)
        if (resolved.tabId != null) delete this.tabs[resolved.tabId]
        return Promise.resolve({ result: true })
    }

    /* End Listeners */

    _decodeRawRequestBody(rawParts) {
        if (!Array.isArray(rawParts) || rawParts.length === 0) return ''
        const decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null
        let out = ''
        rawParts.forEach((part) => {
            try {
                if (!part || !part.bytes) return
                let bytes = null
                if (part.bytes instanceof ArrayBuffer) {
                    bytes = new Uint8Array(part.bytes)
                } else if (ArrayBuffer.isView(part.bytes)) {
                    bytes = new Uint8Array(part.bytes.buffer, part.bytes.byteOffset, part.bytes.byteLength)
                }
                if (!bytes || bytes.length === 0) return
                if (decoder) out += decoder.decode(bytes)
                else out += String.fromCharCode.apply(String, bytes)
            } catch (_) { }
        })
        return out
    }

    _requestEntryScore(entry) {
        if (!entry || typeof entry !== 'object') return -1
        let score = 0
        const headers = Array.isArray(entry.requestHeaders) ? entry.requestHeaders : []
        if (headers.length) {
            score += Math.min(headers.length, 40) * 10
            headers.forEach((header) => {
                const lname = String(header?.name || '').toLowerCase()
                if (lname === 'cookie') score += 60
                else if (lname === 'user-agent') score += 40
                else if (lname.startsWith('sec-ch-')) score += 15
                else if (lname === 'accept' || lname === 'origin' || lname === 'referer' || lname === 'content-type') score += 12
                else if (lname === 'host') score += 4
                else score += 6
            })
        }
        if (entry.url) score += 8
        if (entry.method) score += 8
        const requestBody = entry.requestBody || null
        if (requestBody?.formData && Object.keys(requestBody.formData).length) score += 20
        if (Array.isArray(requestBody?.raw) && requestBody.raw.length) score += 20
        if (typeof requestBody?.raw === 'string' && requestBody.raw.length) score += 20
        if (Array.isArray(entry.responseHeaders) && entry.responseHeaders.length) score += 8
        if (entry.statusCode) score += 6
        return score
    }

    _normalizeComparableUrl(rawUrl) {
        if (!rawUrl) return ''
        try {
            const parsed = new URL(String(rawUrl))
            return `${parsed.origin}${parsed.pathname}${parsed.search || ''}`
        } catch (_) {
            return String(rawUrl || '')
        }
    }

    _normalizeComparableMethod(rawMethod) {
        return String(rawMethod || '').trim().toUpperCase()
    }

    _pickBestRequestEntry(entries, options = {}) {
        if (!Array.isArray(entries) || !entries.length) return null
        const expectedUrl = this._normalizeComparableUrl(options?.expectedUrl || '')
        const expectedMethod = this._normalizeComparableMethod(options?.expectedMethod || '')
        const methodMatched = expectedMethod
            ? entries.filter((entry) => this._normalizeComparableMethod(entry?.method) === expectedMethod)
            : []
        const urlMatched = expectedUrl
            ? entries.filter((entry) => this._normalizeComparableUrl(entry?.url) === expectedUrl)
            : []
        const urlAndMethodMatched = (expectedUrl && expectedMethod)
            ? entries.filter((entry) => this._normalizeComparableUrl(entry?.url) === expectedUrl && this._normalizeComparableMethod(entry?.method) === expectedMethod)
            : []
        const pool = urlAndMethodMatched.length
            ? urlAndMethodMatched
            : (urlMatched.length ? urlMatched : (methodMatched.length ? methodMatched : entries))
        let best = pool[0]
        let bestScore = this._requestEntryScore(best)
        for (let i = 1; i < pool.length; i++) {
            const candidate = pool[i]
            const score = this._requestEntryScore(candidate)
            if (score > bestScore) {
                best = candidate
                bestScore = score
                continue
            }
            if (score === bestScore) {
                const bestHeaders = Array.isArray(best?.requestHeaders) ? best.requestHeaders.length : 0
                const candHeaders = Array.isArray(candidate?.requestHeaders) ? candidate.requestHeaders.length : 0
                if (candHeaders > bestHeaders) {
                    best = candidate
                    bestScore = score
                }
            }
        }
        return best
    }

    getRequestDetails(tab, frameId, requestId, options = {}) {
        if (!tab?.frames?.has(frameId) || !tab.frames.get(frameId)?.has(requestId)) {
            throw new Error('request_not_found')
        }
        const requestEntries = tab.frames.get(frameId).get(requestId)
        let request = this._pickBestRequestEntry(requestEntries, options)
        if (!request) {
            throw new Error('request_not_found')
        }
        let r = JSON.parse(JSON.stringify(request))
        if (request.requestBody?.raw) {
            const decodedBody = this._decodeRawRequestBody(request.requestBody.raw)
            if (decodedBody) {
                r.requestBody.raw = decodedBody
            }
        }
        const hasPerRequestHeaders = Array.isArray(request.requestHeaders) && request.requestHeaders.length > 0
        if (!hasPerRequestHeaders && tab?.tabInfo?.requestHeaders) {
            let rH = tab.tabInfo.requestHeaders
            r.requestHeaders = Object.keys(rH).map(key => {
                // let h = rH[key].split(':')
                // if (h.length > 2) return { name: key, value: rH[key] }
                //console.log( { key: rH[key]})
                return { name: key, value: rH[key] }
            })
        }
        r.__hasPerRequestHeaders = hasPerRequestHeaders
        r.__requestHeadersCount = Array.isArray(r.requestHeaders) ? r.requestHeaders.length : 0
        return r
    }

    getRawRequestWithMeta(tab, frameId, requestId, options = {}) {
        if (!tab) throw new Error('tab_not_found')
        let request = this.getRequestDetails(tab, frameId, requestId, options)
        let path = request.method + ' ' + request.url + ' HTTP/1.1'
        let headers = Array.isArray(request.requestHeaders)
            ? request.requestHeaders.map(x => x.name + ": " + x.value)
            : []
        let rawRequest = path + '\r\n' + headers.join('\r\n')

        if (request?.requestBody?.formData) {
            let params = Object.keys(request.requestBody.formData).map(function (k) {
                return encodeURIComponent(k) + '=' + encodeURIComponent(request.requestBody.formData[k])
            }).join('&')
            rawRequest += "\r\n\r\n" + params
        } else if (request?.requestBody?.raw) {
            rawRequest += "\r\n\r\n" + request.requestBody.raw
        } else {
            rawRequest += "\r\n\r\n"
        }
        return {
            raw: rawRequest,
            meta: {
                hasPerRequestHeaders: !!request.__hasPerRequestHeaders,
                requestHeadersCount: Number(request.__requestHeadersCount || 0)
            }
        }
    }

    getRawRequest(tab, frameId, requestId, options = {}) {
        return this.getRawRequestWithMeta(tab, frameId, requestId, options).raw
    }

    setTab(tabId, params, t) {
        if (!ptk_utils.isURL(params?.url) ) return
        if (!Number.isInteger(tabId) || tabId < 0) return

        const scanTabId = (worker?.ptk_app?.dast || worker?.ptk_app?.rattacker)?.engine?.tabId
        const shouldTrackForScan = scanTabId != null && tabId === scanTabId
        const alreadyTracked = Object.prototype.hasOwnProperty.call(this.tabs, tabId)
        const shouldAdoptRequestContext = !alreadyTracked && !shouldTrackForScan && (
            this._dashboardTab?.tabId === tabId
            || this.activeTab?.tabId == null
            || !ptk_utils.isURL(this.activeTab?.url)
        )

        if (shouldAdoptRequestContext) {
            this.tabUrlMap.set(tabId, params.url)
            this.activeTab = {
                tabId,
                url: this.getUiUrl(tabId, params.url),
                window: this.activeTab?.window || this._dashboardTab?.window
            }
        }

        if (tabId == this._createdTab?.tabId || tabId == this.activeTab?.tabId || shouldTrackForScan || alreadyTracked) 
            this.updateTab(tabId, params, t)
    }

    getTab(tabId) {
        if (tabId in this.tabs && this.tabs[tabId] instanceof ptk_tab) return this.tabs[tabId]
        return null
    }

    updateTab(tabId, params, t) {
        if (!ptk_utils.isURL(params.url)) return

        try {
            if (tabId in this.tabs && this.tabs[tabId] instanceof ptk_tab) {
                this.tabs[tabId].setParams(params, t)
                ptk_logger.log("Tab updated ", { tabId: tabId })
            } else {
                this.tabs[tabId] = new ptk_tab(tabId, params, t)
                this.reduceTabs(this.maxTabsCount, tabId)
                ptk_logger.log("Tab added ", { tabId: tabId })
            }
            this.trackTabActivity(tabId)
            this.tabs[tabId].reduceTabSize(this.maxRequestsPerTab)
        } catch (e) {
            ptk_logger.log(e, "Could not update a tab", "error")
        }
    }

    clearTab(tabId) {
        delete this.tabs[tabId]
        this.forgetTab(tabId)
    }

    reduceTabs(maxTabs, newTabId) {
        let tabsCount = Object.keys(this.tabs).length
        if (tabsCount <= maxTabs) return
        let removeKey = [], count = 0
        Object.keys(this.tabs).forEach(key => {
            if ((tabsCount - count) > maxTabs && key != newTabId) {
                removeKey.push(key)
                count++
            }
        })
        if (removeKey.length > 0) {
            removeKey.forEach((tabId) => {
                delete this.tabs[tabId]
                this.forgetTab(tabId)
            })
        }
    }

    set activeTab(s) {
        if (ptk_utils.isURL(this._activeTab?.url))
            this._previousTab = this._activeTab

        this._activeTab = s
        // browser.runtime.sendMessage({
        //     channel: "ptk_background2popup_tabs",
        //     type: "active tab changed"
        // }).catch(e => ptk_logger.log(e, "Could not set active tab", "warning"))
    }

    get activeTab() {
        return this._activeTab
    }

    setDashboardTab(tabId, url = '') {
        if (tabId == null) return
        const resolvedUrl = url || this.tabUrlMap.get(tabId) || ''
        this._dashboardTab = { tabId, url: resolvedUrl }
        if ((!this.activeTab?.tabId || !ptk_utils.isURL(this.activeTab?.url)) && ptk_utils.isURL(resolvedUrl)) {
            this.activeTab = { tabId, url: resolvedUrl, window: this.activeTab?.window || this._dashboardTab.window }
        }
    }

    getDashboardTab() {
        if (this._dashboardTab?.tabId != null) {
            const url = this._dashboardTab.url || this.tabUrlMap.get(this._dashboardTab.tabId) || ''
            return { tabId: this._dashboardTab.tabId, url }
        }
        return this.activeTab
    }

    getUiUrl(tabId, fallback = '') {
        return this.tabUrlMap.get(tabId) || fallback
    }

    resolveTabContext(tab) {
        if (tab instanceof ptk_tab) {
            return { tab: tab, tabId: tab.tabId }
        }
        const fallbackId = this.getLastTrackedTabId()
        if (fallbackId == null) return { tab: null, tabId: null }
        return { tab: this.tabs[fallbackId], tabId: fallbackId }
    }

    trackTabActivity(tabId) {
        if (tabId == null) return
        this._tabActivity.set(String(tabId), Date.now())
    }

    getTabActivity(tabId) {
        if (tabId == null) return 0
        return this._tabActivity.get(String(tabId)) || 0
    }

    forgetTab(tabId) {
        if (tabId == null) return
        this._tabActivity.delete(String(tabId))
    }

    getLastTrackedTabId() {
        let latestId = null
        let latestTs = -1
        this._tabActivity.forEach((ts, tabId) => {
            if (ts >= latestTs && this.tabs[tabId] instanceof ptk_tab) {
                latestTs = ts
                latestId = isNaN(Number(tabId)) ? tabId : Number(tabId)
            }
        })
        return latestId
    }
}


//---------------------------------------------------//

export class ptk_tab {
    constructor(tabId, params, type) {
        this.tabId = tabId
        this.frames = new Map()
        this.setParams(params, type)
        this.tabInfo = null
        this.tabInfoDirty = true
        this.lastAnalyzedAt = 0
    }

    setParams(params, type) {
        this.tabInfoDirty = true
        if (Number.isInteger(params.frameId)) {
            //Init frame map if doesn't exist
            if (!this.frames.has(params.frameId)) {
                this.frames.set(params.frameId, new Map())
                ptk_logger.log("Init frames", { frameId: params.frameId, requestId: params.requestId })
            }
            //Init request map if doesn't exist
            if (!this.frames.get(params.frameId).has(params.requestId)) {
                this.frames.get(params.frameId).set(params.requestId, new Array())
            }
            let index = this.frames.get(params.frameId).get(params.requestId).length
            if (type == 'start' || index == 0) {
                this.frames.get(params.frameId).get(params.requestId).push(params)
                ptk_logger.log("Add new item for ", { frameId: params.frameId, requestId: params.requestId })
            } else {
                for (let p in params) {
                    let requestKey = index == 0 ? 0 : index - 1
                    if (this.frames.get(params.frameId).get(params.requestId)[requestKey][p] != params[p]) {
                        this.frames.get(params.frameId).get(params.requestId)[requestKey][p] = params[p]
                    }
                }
                ptk_logger.log("Updated params ", { params: params, frameId: params.frameId, requestId: params.requestId })
            }
        } else {
            for (let p in params) {
                this[p] = params[p]
                ptk_logger.log("Add or update param ", { p: params[p] })
            }
        }
    }

    reduceTabSize(maxRequest) {
        let updated = false
        this.frames.forEach((frame, fkey) => {
            frame.forEach((request, rkey) => {
                if (frame.size >= maxRequest) {
                    updated = true
                    frame.delete(rkey)
                }
            })
        })
        if (updated) {
            this.tabInfoDirty = true
        }
        if (updated) browser.runtime.sendMessage({
            channel: "ptk_background2popup_tabs",
            type: "requests source resized"
        }).catch(e => ptk_logger.log(e, "Could not send a message", "info"))
    }

    async analyze() {
        const cacheAgeMs = Date.now() - (this.lastAnalyzedAt || 0)
        if (!this.tabInfoDirty && this.tabInfo && cacheAgeMs < 5000) {
            return this.tabInfo
        }

        // Use Sets for O(1) lookups instead of O(n) array.includes()
        const urlSet = new Set()
        const domainSet = new Set()
        const ipSet = new Set()

        let requestHeaders = {},
            responseHeaders = {},
            fqdnIP = [],
            frames = [],
            requests = []

        this.frames.forEach((fV, fK) => {
            let i = 0, data = {}, ipList = []
            fV.forEach((rV, rK) => {
                rV.forEach((request, key) => {
                    try {
                        // O(1) Set lookup instead of O(n) array.includes()
                        if (request.url && !urlSet.has(request.url)) {
                            urlSet.add(request.url)
                        }

                        const hostname = (new URL(request.url)).hostname
                        if (!domainSet.has(hostname)) {
                            domainSet.add(hostname)
                            fqdnIP.push([hostname, request.ip])
                        }

                        if (request.requestHeaders) {
                            request.requestHeaders.forEach((hV) => {
                                const headerName = hV.name.toLowerCase()
                                if (!(headerName in requestHeaders)) {
                                    requestHeaders[headerName] = [hV.value]
                                }
                            })
                        }

                        if (request.responseHeaders) {
                            request.responseHeaders.forEach((hV) => {
                                const headerName = hV.name.toLowerCase()
                                if (!(headerName in responseHeaders)) {
                                    responseHeaders[headerName] = [hV.value]
                                }
                            })
                        }

                        if (i == 0) {
                            data.frame = request.parentFrameId == -1 ? "main" : "iframe"
                            data.url = hostname
                        }
                        if (request.ip && !ipSet.has(request.ip)) {
                            ipSet.add(request.ip)
                            ipList.push(request.ip)
                        }
                        i++
                    } catch (e) { }
                })
            })
            frames.push(['', fK, data.frame, data.url, ipList.join(', ')])
        })

        // Convert Sets to Arrays for the result
        this.tabInfo = {
            responseHeaders,
            requestHeaders,
            frames,
            requests,
            domains: Array.from(domainSet),
            urls: Array.from(urlSet),
            fqdnIP
        }
        this.tabInfoDirty = false
        this.lastAnalyzedAt = Date.now()
        return this.tabInfo
    }

}
