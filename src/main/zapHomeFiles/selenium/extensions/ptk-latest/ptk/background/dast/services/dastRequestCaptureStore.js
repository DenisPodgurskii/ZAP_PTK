import { ptk_logger, ptk_utils } from "../../utils.js"
import {
    encodeMultipartHeaderParameter,
    normalizeMultipartBoundary
} from "../../requestBuilder/multipartEncoding.js"

function scoreZapAutomationSeedUrl(url, { method = "GET", stateChanging = false, hasBody = false } = {}) {
    let score = 0
    const upperMethod = String(method || "GET").toUpperCase()
    if (stateChanging) score += 90
    if (hasBody) score += 70
    try {
        const parsed = new URL(url)
        const pathAndQuery = `${parsed.pathname || ""}?${parsed.searchParams?.toString?.() || ""}`.toLowerCase()
        if (parsed.search && parsed.search !== "?") score += 120
        if (/(?:xss|script|javascript|js[_/-]|eval|attr|attribute|tagname|tag|html|textarea|href|svg|onerror|onload|search|query|(?:^|[?&])q=)/i.test(pathAndQuery)) {
            score += 160
        }
        if (/(?:^|\/)\.(?:git|svn|hg)(?:\/|$)/i.test(parsed.pathname || "")) {
            score -= 300
        }
        if (!parsed.search && upperMethod === "GET") {
            score -= 40
        }
    } catch (_) {
        score -= 20
    }
    return score
}

export class DastRequestCaptureStore {
    constructor({
        maxTabsCount = 20,
        maxRequestsPerTab = 500,
        logger = ptk_logger,
        runtimeApi = globalThis.browser
    } = {}) {
        this.maxTabsCount = maxTabsCount
        this.maxRequestsPerTab = maxRequestsPerTab
        this.logger = logger
        this.runtimeApi = runtimeApi
        this.tabs = {}
        this.tabUrlMap = new Map()
        this._tabActivity = new Map()
    }

    rememberTabUrl(tabId, url = "") {
        if (!Number.isInteger(tabId) || !ptk_utils.isURL(url)) return false
        this.tabUrlMap.set(tabId, url)
        return true
    }

    getUiUrl(tabId, fallback = "") {
        return this.tabUrlMap.get(tabId) || fallback
    }

    getTab(tabId) {
        if (tabId in this.tabs && this.tabs[tabId] instanceof DastCapturedTab) return this.tabs[tabId]
        return null
    }

    clearTab(tabId) {
        delete this.tabs[tabId]
        this.forgetTab(tabId)
    }

    resolveTabContext(tab) {
        if (tab instanceof DastCapturedTab) {
            return { tab, tabId: tab.tabId }
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
            if (ts >= latestTs && this.tabs[tabId] instanceof DastCapturedTab) {
                latestTs = ts
                latestId = isNaN(Number(tabId)) ? tabId : Number(tabId)
            }
        })
        return latestId
    }

    updateTab(tabId, params, t) {
        if (!ptk_utils.isURL(params?.url)) return
        try {
            if (tabId in this.tabs && this.tabs[tabId] instanceof DastCapturedTab) {
                this.tabs[tabId].setParams(params, t)
                this.logger.log("Tab updated ", { tabId })
            } else {
                this.tabs[tabId] = new DastCapturedTab(tabId, params, t, {
                    logger: this.logger,
                    runtimeApi: this.runtimeApi
                })
                this.reduceTabs(this.maxTabsCount, tabId)
                this.logger.log("Tab added ", { tabId })
            }
            this.trackTabActivity(tabId)
            this.tabs[tabId].reduceTabSize(this.maxRequestsPerTab)
        } catch (e) {
            this.logger.log(e, "Could not update a tab", "error")
        }
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
            removeKey.forEach((tabId) => this.clearTab(tabId))
        }
    }

    _decodeRawRequestBody(rawParts) {
        if (!Array.isArray(rawParts) || rawParts.length === 0) return ""
        const decoder = typeof TextDecoder !== "undefined" ? new TextDecoder() : null
        let out = ""
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

    _getRequestHeaderValue(headers = [], name = "") {
        if (!Array.isArray(headers) || !name) return ""
        const target = String(name || "").trim().toLowerCase()
        const header = headers.find((entry) => String(entry?.name || "").trim().toLowerCase() === target)
        return String(header?.value || "")
    }

    _isMultipartRequest(headers = [], requestBody = null) {
        const requestContentType = this._getRequestHeaderValue(headers, "content-type")
        const bodyContentType = String(requestBody?.contentType || requestBody?.mimeType || "")
        return /multipart\/form-data/i.test(requestContentType) || /multipart\/form-data/i.test(bodyContentType)
    }

    _serializeRequestFormData(formData = null) {
        if (!formData || typeof formData !== "object") return ""
        const params = new URLSearchParams()
        Object.entries(formData).forEach(([name, value]) => {
            if (Array.isArray(value)) {
                value.forEach((entry) => params.append(name, String(entry ?? "")))
                return
            }
            params.append(name, String(value ?? ""))
        })
        return params.toString()
    }

    _serializeSyntheticMultipartFormData(formData = null, boundary = "") {
        const safeBoundary = normalizeMultipartBoundary(boundary)
        if (!formData || typeof formData !== "object" || !safeBoundary) return ""
        const parts = []
        Object.entries(formData).forEach(([name, value]) => {
            const values = Array.isArray(value) ? value : [value]
            values.forEach((entry) => {
                parts.push(
                    `--${safeBoundary}\r\n`
                    + `Content-Disposition: form-data; name="${encodeMultipartHeaderParameter(name)}"\r\n`
                    + `\r\n`
                    + `${String(entry ?? "")}\r\n`
                )
            })
        })
        return parts.join("") + `--${safeBoundary}--`
    }

    _extractRequestBodyText(request = null) {
        const requestBody = request?.requestBody
        if (!requestBody || typeof requestBody !== "object") return ""
        if (typeof requestBody.raw === "string") return requestBody.raw
        if (Array.isArray(requestBody.raw) && requestBody.raw.length) {
            return this._decodeRawRequestBody(requestBody.raw)
        }
        if (typeof requestBody.postData === "string") return requestBody.postData
        if (requestBody.formData) {
            if (this._isMultipartRequest(request?.requestHeaders, requestBody)) {
                const contentType = this._getRequestHeaderValue(request?.requestHeaders, "content-type")
                const match = String(contentType || "").match(/boundary=([^;]+)/i)
                const boundary = match?.[1] ? String(match[1]).trim().replace(/^"|"$/g, "") : ""
                return this._serializeSyntheticMultipartFormData(requestBody.formData, boundary)
            }
            return this._serializeRequestFormData(requestBody.formData)
        }
        return ""
    }

    _normalizeRawRequestHeaders(requestHeaders = [], bodyText = "") {
        const headers = Array.isArray(requestHeaders)
            ? requestHeaders.map((header) => ({ name: header?.name, value: header?.value }))
            : []
        if (!headers.length || typeof bodyText !== "string" || !bodyText.length) return headers
        let contentLength = String(bodyText.length)
        try {
            if (typeof TextEncoder !== "undefined") {
                contentLength = String(new TextEncoder().encode(bodyText).length)
            }
        } catch (_) { }
        const contentLengthIndex = headers.findIndex((header) => String(header?.name || "").trim().toLowerCase() === "content-length")
        if (contentLengthIndex >= 0) {
            headers[contentLengthIndex].value = contentLength
        } else {
            headers.push({ name: "Content-Length", value: contentLength })
        }
        return headers
    }

    _requestEntryScore(entry) {
        if (!entry || typeof entry !== "object") return -1
        let score = 0
        const headers = Array.isArray(entry.requestHeaders) ? entry.requestHeaders : []
        if (headers.length) {
            score += Math.min(headers.length, 40) * 10
            headers.forEach((header) => {
                const lname = String(header?.name || "").toLowerCase()
                if (lname === "cookie") score += 60
                else if (lname === "user-agent") score += 40
                else if (lname.startsWith("sec-ch-")) score += 15
                else if (lname === "accept" || lname === "origin" || lname === "referer" || lname === "content-type") score += 12
                else if (lname === "host") score += 4
                else score += 6
            })
        }
        if (entry.url) score += 8
        if (entry.method) score += 8
        const requestBody = entry.requestBody || null
        if (requestBody?.formData && Object.keys(requestBody.formData).length) score += 20
        if (Array.isArray(requestBody?.raw) && requestBody.raw.length) score += 20
        if (typeof requestBody?.raw === "string" && requestBody.raw.length) score += 20
        if (Array.isArray(entry.responseHeaders) && entry.responseHeaders.length) score += 8
        if (entry.statusCode) score += 6
        return score
    }

    _requestBodyHasContent(requestBody = null) {
        if (!requestBody || typeof requestBody !== "object") return false
        if (typeof requestBody.raw === "string" && requestBody.raw.length > 0) return true
        if (Array.isArray(requestBody.raw) && requestBody.raw.length > 0) return true
        if (typeof requestBody.postData === "string" && requestBody.postData.length > 0) return true
        if (requestBody.formData && typeof requestBody.formData === "object" && Object.keys(requestBody.formData).length > 0) return true
        return false
    }

    _mergeRequestEntryDetails(best = null, pool = []) {
        if (!best || typeof best !== "object") return best
        const merged = Object.assign({}, best)
        if (!this._requestBodyHasContent(merged.requestBody)) {
            const bodyCandidate = pool.find((entry) => this._requestBodyHasContent(entry?.requestBody))
            if (bodyCandidate?.requestBody) {
                merged.requestBody = bodyCandidate.requestBody
            }
        }
        if (!Array.isArray(merged.requestHeaders) || merged.requestHeaders.length === 0) {
            const headerCandidate = pool.find((entry) => Array.isArray(entry?.requestHeaders) && entry.requestHeaders.length > 0)
            if (headerCandidate?.requestHeaders) {
                merged.requestHeaders = headerCandidate.requestHeaders
            }
        } else {
            const headerCandidates = pool
                .filter((entry) => Array.isArray(entry?.requestHeaders) && entry.requestHeaders.length > merged.requestHeaders.length)
                .sort((left, right) => right.requestHeaders.length - left.requestHeaders.length)
            for (const candidate of headerCandidates) {
                const seen = new Set(merged.requestHeaders
                    .map((header) => String(header?.name || "").trim().toLowerCase())
                    .filter(Boolean))
                for (const header of candidate.requestHeaders) {
                    const name = String(header?.name || "").trim()
                    if (!name) continue
                    const lname = name.toLowerCase()
                    if (seen.has(lname)) continue
                    merged.requestHeaders.push({ name: header.name, value: header.value })
                    seen.add(lname)
                }
            }
        }
        return merged
    }

    _normalizeComparableUrl(rawUrl) {
        if (!rawUrl) return ""
        try {
            const parsed = new URL(String(rawUrl))
            return `${parsed.origin}${parsed.pathname}${parsed.search || ""}`
        } catch (_) {
            return String(rawUrl || "")
        }
    }

    _normalizeComparableMethod(rawMethod) {
        return String(rawMethod || "").trim().toUpperCase()
    }

    _pickBestRequestEntry(entries, options = {}) {
        if (!Array.isArray(entries) || !entries.length) return null
        const expectedUrl = this._normalizeComparableUrl(options?.expectedUrl || "")
        const expectedMethod = this._normalizeComparableMethod(options?.expectedMethod || "")
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
        return this._mergeRequestEntryDetails(best, pool)
    }

    getRequestDetails(tab, frameId, requestId, options = {}) {
        if (!tab?.frames?.has(frameId) || !tab.frames.get(frameId)?.has(requestId)) {
            throw new Error("request_not_found")
        }
        const requestEntries = tab.frames.get(frameId).get(requestId)
        let request = this._pickBestRequestEntry(requestEntries, options)
        if (!request) {
            throw new Error("request_not_found")
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
            r.requestHeaders = Object.keys(rH).map(key => ({ name: key, value: rH[key] }))
        }
        r.__hasPerRequestHeaders = hasPerRequestHeaders
        r.__requestHeadersCount = Array.isArray(r.requestHeaders) ? r.requestHeaders.length : 0
        return r
    }

    getRawRequestWithMeta(tab, frameId, requestId, options = {}) {
        if (!tab) throw new Error("tab_not_found")
        let request = this.getRequestDetails(tab, frameId, requestId, options)
        let path = request.method + " " + request.url + " HTTP/1.1"
        const bodyText = this._extractRequestBodyText(request)
        const normalizedHeaders = this._normalizeRawRequestHeaders(request.requestHeaders, bodyText)
        let headers = Array.isArray(normalizedHeaders)
            ? normalizedHeaders.map(x => x.name + ": " + x.value)
            : []
        let rawRequest = path + "\r\n" + headers.join("\r\n")

        rawRequest += "\r\n\r\n" + bodyText
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

    collectZapAutomationSeedRequests(tabId, options = {}) {
        const tab = this.getTab(tabId)
        if (!tab?.frames || typeof tab.frames.forEach !== "function") return []

        const sinceMs = Number.isFinite(Number(options?.sinceMs)) ? Number(options.sinceMs) : 0
        const maxRequests = Number.isFinite(Number(options?.maxRequests))
            ? Math.max(0, Number(options.maxRequests))
            : 200
        const targetOrigin = (() => {
            try {
                const raw = options?.targetUrl || options?.pageUrl || ""
                return raw ? new URL(raw).origin : null
            } catch (_) {
                return null
            }
        })()

        const isStateChanging = (method) => ["POST", "PUT", "PATCH", "DELETE"].includes(String(method || "").toUpperCase())
        const sameOrigin = (url) => {
            if (!targetOrigin) return true
            try {
                return new URL(url).origin === targetOrigin
            } catch (_) {
                return false
            }
        }

        const entries = []
        tab.frames.forEach((frameMap, frameId) => {
            if (!frameMap || typeof frameMap.forEach !== "function") return
            frameMap.forEach((events, requestId) => {
                if (!Array.isArray(events) || !events.length) return
                let details = null
                let rawBundle = null
                try {
                    details = this.getRequestDetails(tab, frameId, requestId)
                    if (!details?.url || !sameOrigin(details.url)) return
                    const seenAt = Math.max(
                        ...events.map((event) => Number(event?.__ptkSeenAtMs || event?.timeStamp || 0)).filter(Number.isFinite),
                        0
                    )
                    if (sinceMs > 0 && seenAt > 0 && seenAt < sinceMs) return
                    rawBundle = this.getRawRequestWithMeta(tab, frameId, requestId, {
                        expectedUrl: details.url,
                        expectedMethod: details.method
                    })
                } catch (_) {
                    return
                }

                const method = String(details?.method || "").toUpperCase()
                const bodyText = (() => {
                    if (typeof details?.requestBody?.raw === "string") return details.requestBody.raw
                    if (details?.requestBody?.formData) return JSON.stringify(details.requestBody.formData)
                    return ""
                })()
                entries.push({
                    tabId,
                    frameId,
                    requestId,
                    url: details.url,
                    ui_url: details.ui_url || details.url,
                    method,
                    type: details.type || "xmlhttprequest",
                    statusCode: details.statusCode || 200,
                    requestHeaders: details.requestHeaders || [],
                    requestBody: details.requestBody || null,
                    raw: rawBundle?.raw || "",
                    seenAt: Math.max(
                        ...events.map((event) => Number(event?.__ptkSeenAtMs || event?.timeStamp || 0)).filter(Number.isFinite),
                        0
                    ),
                    stateChanging: isStateChanging(method),
                    hasBody: !!bodyText
                })
            })
        })

        const deduped = []
        const seen = new Set()
        entries
            .sort((left, right) => {
                const leftScore = scoreZapAutomationSeedUrl(left.url, left)
                const rightScore = scoreZapAutomationSeedUrl(right.url, right)
                if (leftScore !== rightScore) return rightScore - leftScore
                if (left.stateChanging !== right.stateChanging) return left.stateChanging ? -1 : 1
                if (left.hasBody !== right.hasBody) return left.hasBody ? -1 : 1
                return Number(left.seenAt || 0) - Number(right.seenAt || 0)
            })
            .forEach((entry) => {
                const key = `${entry.method}|${entry.url}|${String(entry.raw || "").slice(-512)}`
                if (seen.has(key)) return
                seen.add(key)
                deduped.push(entry)
            })

        return maxRequests > 0 ? deduped.slice(0, maxRequests) : deduped
    }
}

export class DastCapturedTab {
    constructor(tabId, params, type, { logger = ptk_logger, runtimeApi = globalThis.browser } = {}) {
        this.tabId = tabId
        this.logger = logger
        this.runtimeApi = runtimeApi
        this.frames = new Map()
        this.setParams(params, type)
        this.tabInfo = null
        this.tabInfoDirty = true
        this.lastAnalyzedAt = 0
    }

    setParams(params, type) {
        this.tabInfoDirty = true
        if (Number.isInteger(params.frameId)) {
            if (!this.frames.has(params.frameId)) {
                this.frames.set(params.frameId, new Map())
                this.logger.log("Init frames", { frameId: params.frameId, requestId: params.requestId })
            }
            if (!this.frames.get(params.frameId).has(params.requestId)) {
                this.frames.get(params.frameId).set(params.requestId, new Array())
            }
            let index = this.frames.get(params.frameId).get(params.requestId).length
            if (type == "start" || index == 0) {
                this.frames.get(params.frameId).get(params.requestId).push(params)
                this.logger.log("Add new item for ", { frameId: params.frameId, requestId: params.requestId })
            } else {
                for (let p in params) {
                    let requestKey = index == 0 ? 0 : index - 1
                    if (this.frames.get(params.frameId).get(params.requestId)[requestKey][p] != params[p]) {
                        this.frames.get(params.frameId).get(params.requestId)[requestKey][p] = params[p]
                    }
                }
                this.logger.log("Updated params ", { params, frameId: params.frameId, requestId: params.requestId })
            }
        } else {
            for (let p in params) {
                this[p] = params[p]
                this.logger.log("Add or update param ", { p: params[p] })
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
        if (updated) this.runtimeApi?.runtime?.sendMessage?.({
            channel: "ptk_background2popup_tabs",
            type: "requests source resized"
        }).catch(e => this.logger.log(e, "Could not send a message", "info"))
    }

    async analyze() {
        const cacheAgeMs = Date.now() - (this.lastAnalyzedAt || 0)
        if (!this.tabInfoDirty && this.tabInfo && cacheAgeMs < 5000) {
            return this.tabInfo
        }

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
            frames.push(["", fK, data.frame, data.url, ipList.join(", ")])
        })

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

export default DastRequestCaptureStore
