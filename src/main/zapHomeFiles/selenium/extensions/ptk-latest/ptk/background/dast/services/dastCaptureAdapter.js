function defaultSleep(ms = 0) {
    return new Promise((resolve) => setTimeout(resolve, ms))
}

function cloneCapturedRequest(value = null) {
    if (!value || typeof value !== "object") return null
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return null
    }
}

export class DastCaptureAdapter {
    constructor({
        engine = null,
        worker = globalThis,
        browserApi = globalThis.browser,
        requestFilters = [],
        extraInfoSpec = [],
        getState = () => ({})
    } = {}) {
        this.engine = engine
        this.worker = worker
        this.browserApi = browserApi
        this.requestFilters = Array.isArray(requestFilters) ? requestFilters : []
        this.extraInfoSpec = Array.isArray(extraInfoSpec) ? extraInfoSpec : []
        this.getState = getState

        this.onRemoved = this.onRemoved.bind(this)
        this.onCompleted = this.onCompleted.bind(this)
        this.onResponseStarted = this.onResponseStarted.bind(this)
        this.onHeadersReceived = this.onHeadersReceived.bind(this)

        this._captureGeneration = 0
        this.resetCaptureStats()
    }

    get state() {
        return this.getState?.() || {}
    }

    sleep(ms = 0) {
        return defaultSleep(ms)
    }

    resetCaptureStats() {
        this._captureGeneration += 1
        this.pendingObservedRequests = 0
        this.pendingObservedRequestsMax = 0
        this.observedRequestsStarted = 0
        this.observedRequestsQueued = 0
        this.observedRequestsDropped = 0
        this.observedRequestsErrored = 0
        this.lastObservedRequestStartedAt = null
        this.lastObservedRequestFinishedAt = null
        this.lastObservedRequestQueuedAt = null
        this.lastObservedRequestDroppedAt = null
        this.lastObservedRequestErrorAt = null
    }

    getPendingObservedRequestCount() {
        return Math.max(0, Number(this.pendingObservedRequests || 0))
    }

    getCaptureStats() {
        return {
            pendingObservedRequests: this.getPendingObservedRequestCount(),
            pendingObservedRequestsMax: Math.max(0, Number(this.pendingObservedRequestsMax || 0)),
            observedRequestsStarted: Math.max(0, Number(this.observedRequestsStarted || 0)),
            observedRequestsQueued: Math.max(0, Number(this.observedRequestsQueued || 0)),
            observedRequestsDropped: Math.max(0, Number(this.observedRequestsDropped || 0)),
            observedRequestsErrored: Math.max(0, Number(this.observedRequestsErrored || 0)),
            lastObservedRequestStartedAt: this.lastObservedRequestStartedAt || null,
            lastObservedRequestFinishedAt: this.lastObservedRequestFinishedAt || null,
            lastObservedRequestQueuedAt: this.lastObservedRequestQueuedAt || null,
            lastObservedRequestDroppedAt: this.lastObservedRequestDroppedAt || null,
            lastObservedRequestErrorAt: this.lastObservedRequestErrorAt || null
        }
    }

    _markCaptureProgressChanged() {
        try {
            this.engine?.notifyCaptureProgressChanged?.()
        } catch (_) { }
    }

    _trackObservedRequest(promise) {
        const generation = this._captureGeneration
        this.pendingObservedRequests += 1
        this.pendingObservedRequestsMax = Math.max(
            this.pendingObservedRequestsMax,
            this.pendingObservedRequests
        )
        this.observedRequestsStarted += 1
        this.lastObservedRequestStartedAt = new Date().toISOString()
        this._markCaptureProgressChanged()
        return Promise.resolve(promise)
            .then((queued) => {
                if (generation === this._captureGeneration) {
                    if (queued === true) {
                        this.observedRequestsQueued += 1
                        this.lastObservedRequestQueuedAt = new Date().toISOString()
                    } else {
                        this.observedRequestsDropped += 1
                        this.lastObservedRequestDroppedAt = new Date().toISOString()
                    }
                }
                return queued
            })
            .catch((error) => {
                if (generation === this._captureGeneration) {
                    this.observedRequestsErrored += 1
                    this.lastObservedRequestErrorAt = new Date().toISOString()
                }
                return false
            })
            .finally(() => {
                if (generation === this._captureGeneration) {
                    this.pendingObservedRequests = Math.max(0, this.pendingObservedRequests - 1)
                    this.lastObservedRequestFinishedAt = new Date().toISOString()
                    this._markCaptureProgressChanged()
                }
            })
    }

    addListeners() {
        if (!this.browserApi) return
        this.resetCaptureStats()
        this.browserApi.tabs?.onRemoved?.addListener?.(this.onRemoved)
        this.browserApi.webRequest?.onCompleted?.addListener?.(
            this.onCompleted,
            { urls: ["<all_urls>"], types: this.requestFilters },
            ["responseHeaders"].concat(this.extraInfoSpec)
        )
        this.browserApi.webRequest?.onResponseStarted?.addListener?.(
            this.onResponseStarted,
            { urls: ["<all_urls>"], types: this.requestFilters },
            ["responseHeaders"].concat(this.extraInfoSpec)
        )
        this.browserApi.webRequest?.onHeadersReceived?.addListener?.(
            this.onHeadersReceived,
            { urls: ["<all_urls>"], types: this.requestFilters },
            ["responseHeaders"].concat(this.extraInfoSpec)
        )
    }

    removeListeners() {
        if (!this.browserApi) return
        this.browserApi.tabs?.onRemoved?.removeListener?.(this.onRemoved)
        this.browserApi.webRequest?.onCompleted?.removeListener?.(this.onCompleted)
        this.browserApi.webRequest?.onResponseStarted?.removeListener?.(this.onResponseStarted)
        this.browserApi.webRequest?.onHeadersReceived?.removeListener?.(this.onHeadersReceived)
    }

    onRemoved(tabId) {
        if (this.engine?.isRunning && this.engine.tabId === tabId) {
            this.engine.stop()
        }
    }

    _extractUiUrlFromRaw(rawRequest, fallbackUrl) {
        let uiUrl = fallbackUrl || null
        if (typeof rawRequest !== "string") return uiUrl
        const line = rawRequest.split(/\r?\n/)[0] || ""
        const parts = line.trim().split(/\s+/)
        const rawUrl = parts[1] || null
        if (!rawUrl) return uiUrl
        try {
            uiUrl = rawUrl.startsWith("http")
                ? rawUrl
                : new URL(rawUrl, fallbackUrl || "http://localhost").toString()
        } catch (_) { }
        return uiUrl
    }

    _buildResponseEnvelopeFromTabRequest(tabId, frameId, requestId, requestDetails) {
        const url = requestDetails?.url || null
        if (!url) return null
        const uiUrl = requestDetails?.ui_url || this.worker?.ptk_app?.proxy?.getUiUrl?.(tabId, url) || url
        return {
            tabId,
            frameId,
            requestId,
            url,
            ui_url: uiUrl,
            type: requestDetails?.type || "xmlhttprequest",
            statusCode: requestDetails?.statusCode || 200
        }
    }

    _isStateChangingRequest(response) {
        const method = String(response?.method || "").toUpperCase()
        return ["POST", "PUT", "PATCH", "DELETE"].includes(method)
    }

    _isAttackableRequestType(response) {
        const type = String(response?.type || "").toLowerCase()
        if (!type) return true
        return (
            type === "main_frame"
            || type === "sub_frame"
            || type === "xmlhttprequest"
            || type === "other"
            || type === "ping"
        )
    }

    _isHtmlLinkDiscoveryEnabled() {
        if (typeof this.engine?._isHtmlLinkDiscoveryEnabled === "function") {
            try {
                return this.engine._isHtmlLinkDiscoveryEnabled() === true
            } catch (_) { }
        }
        return this.engine?.settings?.enableHtmlLinkDiscovery === true
    }

    _getResponseContentType(response) {
        if (typeof response?.mimeType === "string" && response.mimeType.trim()) {
            return response.mimeType.trim().toLowerCase()
        }
        const headers = Array.isArray(response?.responseHeaders) ? response.responseHeaders : []
        const header = headers.find((item) => String(item?.name || "").toLowerCase() === "content-type")
        return String(header?.value || "").trim().toLowerCase()
    }

    _isSameOriginHtmlDocumentResponse(response) {
        if (!this._isHtmlLinkDiscoveryEnabled()) return false
        const method = String(response?.method || "").toUpperCase()
        if (method !== "GET") return false
        const type = String(response?.type || "").toLowerCase()
        if (type !== "main_frame" && type !== "sub_frame") return false
        const contentType = this._getResponseContentType(response)
        if (!contentType.includes("text/html") && !contentType.includes("application/xhtml+xml")) {
            return false
        }
        const responseUrl = String(response?.url || response?.ui_url || "").trim()
        const scanHost = String(this.engine?.host || "").trim().toLowerCase()
        if (!responseUrl || !scanHost) return false
        try {
            const parsed = new URL(responseUrl)
            return String(parsed.host || "").trim().toLowerCase() === scanHost
        } catch (_) {
            return false
        }
    }

    _rawRequestHeaderRichness(rawRequest) {
        const raw = String(rawRequest || "")
        if (!raw.trim()) return 0
        const lines = raw.split(/\r?\n/)
        if (!lines.length) return 0
        let score = 0
        let headersCount = 0
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i]
            if (!line || !line.trim()) break
            const sep = line.indexOf(":")
            if (sep <= 0) continue
            headersCount += 1
            const lname = line.slice(0, sep).trim().toLowerCase()
            if (lname === "cookie") score += 30
            else if (lname === "user-agent") score += 20
            else if (lname.startsWith("sec-ch-")) score += 10
            else if (lname === "accept" || lname === "origin" || lname === "referer" || lname === "content-type") score += 8
            else if (lname === "host") score += 2
            else score += 4
        }
        score += Math.min(headersCount, 20) * 6
        return score
    }

    _isPtkGeneratedRequest(rawRequest = "", url = "") {
        const raw = String(rawRequest || "")
        if (/^x-ptk-source\s*:/im.test(raw)) return true
        const markerSource = `${raw}\n${String(url || "")}`
        return /(?:ptk_xss_|PTK_SPA_DOM_XSS_|source%3A%27ptk-xss%27|source:'ptk-xss')/i.test(markerSource)
    }

    _isPtkGeneratedCapturedRequest(capturedRequest = {}) {
        const headers = Array.isArray(capturedRequest?.requestHeaders) ? capturedRequest.requestHeaders : []
        return headers.some((header) => {
            const name = String(header?.name || "").trim().toLowerCase()
            const value = String(header?.value || "").trim().toLowerCase()
            return name === "x-ptk-source" || (name === "x-requested-by" && value === "ptk")
        })
    }

    _hasHeader(headers = [], name = "") {
        const target = String(name || "").trim().toLowerCase()
        if (!target || !Array.isArray(headers)) return false
        return headers.some((header) => String(header?.name || "").trim().toLowerCase() === target)
    }

    _rawHasHeader(rawRequest = "", name = "") {
        const target = String(name || "").trim().toLowerCase()
        if (!target) return false
        const lines = String(rawRequest || "").split(/\r?\n/)
        for (let i = 1; i < lines.length; i += 1) {
            const line = lines[i]
            if (!line || !line.trim()) break
            const sep = line.indexOf(":")
            if (sep <= 0) continue
            if (line.slice(0, sep).trim().toLowerCase() === target) return true
        }
        return false
    }

    _rawRequestHeaderValue(rawRequest = "", name = "") {
        const target = String(name || "").trim().toLowerCase()
        if (!target) return ""
        const lines = String(rawRequest || "").split(/\r?\n/)
        for (let i = 1; i < lines.length; i += 1) {
            const line = lines[i]
            if (!line || !line.trim()) break
            const sep = line.indexOf(":")
            if (sep <= 0) continue
            if (line.slice(0, sep).trim().toLowerCase() === target) {
                return line.slice(sep + 1).trim()
            }
        }
        return ""
    }

    _capturedRequestHeaderValue(capturedRequest = {}, name = "") {
        const target = String(name || "").trim().toLowerCase()
        if (!target) return ""
        const headers = Array.isArray(capturedRequest?.requestHeaders) ? capturedRequest.requestHeaders : []
        const match = headers.find((header) => String(header?.name || "").trim().toLowerCase() === target)
        return String(match?.value || "").trim()
    }

    _rawRequestBodyText(rawRequest = "") {
        const raw = String(rawRequest || "")
        const separator = raw.includes("\r\n\r\n") ? "\r\n\r\n" : (raw.includes("\n\n") ? "\n\n" : null)
        if (!separator) return ""
        return raw.slice(raw.indexOf(separator) + separator.length)
    }

    _capturedRequestBodyText(capturedRequest = {}) {
        const body = capturedRequest?.requestBody
        if (!body) return ""
        if (typeof body === "string") return body
        if (typeof body?.text === "string") return body.text
        if (typeof body?.raw === "string") return body.raw
        if (typeof body?.bytes === "string") return body.bytes
        if (Array.isArray(body?.formData)) return body.formData.map((entry) => `${entry?.name || ""}=${entry?.value || ""}`).join("&")
        if (body?.formData && typeof body.formData === "object") {
            return Object.entries(body.formData)
                .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(",") : String(value ?? "")}`)
                .join("&")
        }
        return ""
    }

    _hasMeaningfulRequestBody(rawRequest = "", capturedRequest = {}) {
        const rawBody = this._rawRequestBodyText(rawRequest)
        const capturedBody = this._capturedRequestBodyText(capturedRequest)
        return Boolean(String(rawBody || "").trim() || String(capturedBody || "").trim())
    }

    _stateChangingBodyReadiness(rawRequest = "", capturedRequest = {}, response = {}) {
        if (!this._isStateChangingRequest(response)) return { ready: true, reason: "not_state_changing", dropIfFinal: false }
        if (this._hasMeaningfulRequestBody(rawRequest, capturedRequest)) {
            return { ready: true, reason: "body_present", dropIfFinal: false }
        }
        const rawLength = this._rawRequestHeaderValue(rawRequest, "content-length")
        const capturedLength = this._capturedRequestHeaderValue(capturedRequest, "content-length")
        const length = Number(rawLength || capturedLength || 0)
        const contentType = [
            this._rawRequestHeaderValue(rawRequest, "content-type"),
            this._capturedRequestHeaderValue(capturedRequest, "content-type")
        ].join(" ").toLowerCase()
        const hasStructuredBodyType = /application\/json|application\/x-www-form-urlencoded|multipart\/form-data|text\/plain/.test(contentType)
        const requestBodyObjectPresent = capturedRequest?.requestBody && typeof capturedRequest.requestBody === "object"
        const expectsBody = (Number.isFinite(length) && length > 0) || hasStructuredBodyType || requestBodyObjectPresent
        if (!expectsBody) return { ready: true, reason: "body_not_expected", dropIfFinal: false }
        const status = Number(response?.statusCode || response?.status || 0)
        return {
            ready: false,
            reason: status >= 500 ? "state_changing_error_without_body" : "state_changing_body_pending",
            dropIfFinal: status >= 500
        }
    }

    _recordCaptureDiagnostic(event) {
        try {
            if (typeof this.engine?._appendRuntimeEvent === "function") {
                this.engine._appendRuntimeEvent(Object.assign({ ts: new Date().toISOString(), source: "dast_capture" }, event || {}))
            }
        } catch (_) { }
    }

    _isSameHostAsScan(url = "") {
        const scanHost = String(this.engine?.host || "").trim()
        if (!scanHost) return false
        try {
            const parsed = new URL(url)
            const scanUrl = new URL(/^https?:\/\//i.test(scanHost) ? scanHost : `http://${scanHost}`)
            return String(parsed.host || "").toLowerCase() === String(scanUrl.host || "").toLowerCase()
        } catch (_) {
            return false
        }
    }

    _isJwtLikeCookie(cookie = {}) {
        const name = String(cookie?.name || "").trim()
        const value = String(cookie?.value || "")
        return /^(?:token|id_token|access_token|refresh_token|jwt)$/i.test(name)
            || /(?:^|[=\s])(ey[A-Za-z0-9_=-]+)\.([A-Za-z0-9_=-]+)\.([A-Za-z0-9_-]{2,})(?:$|[;\s])/i.test(value)
    }

    _sanitizeCookiePair(cookie = {}) {
        const name = String(cookie?.name || "").trim()
        const value = String(cookie?.value || "")
        if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) return null
        if (!value || /[\x00-\x20\x7f;]/.test(value)) return null
        return `${name}=${value}`
    }

    _appendRawHeader(rawRequest = "", name = "", value = "") {
        const raw = String(rawRequest || "")
        if (!raw.trim() || !name) return raw
        const headerLine = `${name}: ${value}`
        const separator = raw.includes("\r\n\r\n") ? "\r\n\r\n" : (raw.includes("\n\n") ? "\n\n" : null)
        if (!separator) return `${raw.replace(/\s+$/, "")}\r\n${headerLine}\r\n\r\n`
        const index = raw.indexOf(separator)
        const lineEnding = separator.startsWith("\r\n") ? "\r\n" : "\n"
        return `${raw.slice(0, index)}${lineEnding}${headerLine}${raw.slice(index)}`
    }

    async _backfillJwtCookieHeader(rawRequest = "", capturedRequest = {}) {
        const requestHeaders = Array.isArray(capturedRequest?.requestHeaders)
            ? capturedRequest.requestHeaders.map((header) => ({ name: header?.name, value: header?.value }))
            : []
        if (this._rawHasHeader(rawRequest, "cookie") || this._hasHeader(requestHeaders, "cookie")) {
            return { rawRequest, capturedRequest: Object.assign({}, capturedRequest, { requestHeaders }) }
        }
        const url = String(capturedRequest?.url || "").trim()
        if (!/^https?:\/\//i.test(url) || !this._isSameHostAsScan(url)) {
            return { rawRequest, capturedRequest: Object.assign({}, capturedRequest, { requestHeaders }) }
        }
        let cookies = []
        try {
            const result = this.browserApi?.cookies?.getAll?.({ url })
            cookies = typeof result?.then === "function" ? await result : (Array.isArray(result) ? result : [])
        } catch (_) {
            cookies = []
        }
        const jwtCookies = (Array.isArray(cookies) ? cookies : [])
            .filter((cookie) => cookie?.name && this._isJwtLikeCookie(cookie))
        const cookiePairs = jwtCookies
            .map((cookie) => this._sanitizeCookiePair(cookie))
            .filter(Boolean)
        if (!cookiePairs.length) {
            return { rawRequest, capturedRequest: Object.assign({}, capturedRequest, { requestHeaders }) }
        }
        const cookieHeader = cookiePairs.join("; ")
        const nextHeaders = requestHeaders.concat([{ name: "Cookie", value: cookieHeader }])
        return {
            rawRequest: this._appendRawHeader(rawRequest, "Cookie", cookieHeader),
            capturedRequest: Object.assign({}, capturedRequest, { requestHeaders: nextHeaders })
        }
    }

    _normalizeRawRequestLine(rawRequest, response = null) {
        const raw = String(rawRequest || "")
        if (!raw.trim()) return ""
        const lines = raw.split(/\r?\n/)
        if (!lines.length) return ""
        const firstLine = String(lines[0] || "").trim()
        const lineMatch = firstLine.match(/^([A-Za-z]+)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/)
        const responseUrl = String(response?.url || response?.ui_url || "").trim()
        const responseMethodRaw = String(response?.method || "").trim().toUpperCase()
        const responseMethod = /^[A-Z]+$/.test(responseMethodRaw) ? responseMethodRaw : ""
        if (!lineMatch) {
            if (!responseUrl) return raw
            const method = responseMethod || "GET"
            lines[0] = `${method} ${responseUrl} HTTP/1.1`
            return lines.join("\r\n")
        }
        let method = String(lineMatch[1] || "GET").toUpperCase()
        let target = String(lineMatch[2] || "").trim()
        if (!target) {
            if (!responseUrl) return raw
            target = responseUrl
        } else if (!/^https?:\/\//i.test(target)) {
            if (target.startsWith("/")) {
                try {
                    const base = responseUrl || this.engine?.host || ""
                    if (base) {
                        target = new URL(target, base).toString()
                    }
                } catch (_) { }
            } else if (responseUrl) {
                try {
                    target = new URL(target, responseUrl).toString()
                } catch (_) { }
            }
        }
        if (!/^https?:\/\//i.test(target)) {
            return raw
        }
        if (responseUrl) {
            target = responseUrl
        }
        if (responseMethod) {
            method = responseMethod
        }
        lines[0] = `${method} ${target} HTTP/1.1`
        return lines.join("\r\n")
    }

    seedRequestsFromTab(tabId, maxRequests = 200) {
        if (this.state?.zapManaged === true) return
        if (!this.engine?.isRunning || !this.state.acceptIncomingRequests) return
        const tab = this.worker?.ptk_app?.proxy?.getTab?.(tabId)
        if (!tab?.frames || typeof tab.frames.forEach !== "function") return

        const entries = []
        tab.frames.forEach((frameMap, frameId) => {
            if (!frameMap || typeof frameMap.forEach !== "function") return
            frameMap.forEach((_, requestId) => entries.push({ frameId, requestId }))
        })
        if (!entries.length) return

        const cap = Number.isFinite(maxRequests) ? Math.max(0, Number(maxRequests)) : 200
        const selectedKeys = new Set()
        const selected = cap > 0 ? entries.slice(-cap) : entries
        selected.forEach(({ frameId, requestId }) => selectedKeys.add(`${frameId}:${requestId}`))
        if (cap > 0 && entries.length > selected.length) {
            for (let i = 0; i < entries.length; i++) {
                const item = entries[i]
                const key = `${item.frameId}:${item.requestId}`
                if (selectedKeys.has(key)) continue
                try {
                    const details = this.worker?.ptk_app?.proxy?.getRequestDetails?.(tab, item.frameId, item.requestId)
                    const method = String(details?.method || "").toUpperCase()
                    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
                        selected.push(item)
                        selectedKeys.add(key)
                    }
                } catch (_) { }
            }
        }

        selected.forEach(({ frameId, requestId }) => {
            try {
                const details = this.worker?.ptk_app?.proxy?.getRequestDetails?.(tab, frameId, requestId)
                const envelope = this._buildResponseEnvelopeFromTabRequest(tabId, frameId, requestId, details)
                if (!envelope) return
                const rawBundle = this.worker?.ptk_app?.proxy?.getRawRequestWithMeta
                    ? this.worker.ptk_app.proxy.getRawRequestWithMeta(tab, frameId, requestId)
                    : { raw: this.worker?.ptk_app?.proxy?.getRawRequest?.(tab, frameId, requestId), meta: {} }
                let rawRequest = rawBundle?.raw || ""
                const hasPerRequestHeaders = !!rawBundle?.meta?.hasPerRequestHeaders
                const hasBody = /\r?\n\r?\n[\s\S]+/.test(String(rawRequest || ""))
                const richness = this._rawRequestHeaderRichness(rawRequest)
                const method = String(details?.method || "").toUpperCase()
                const isStateChanging = ["POST", "PUT", "PATCH", "DELETE"].includes(method)
                if (!isStateChanging && !hasPerRequestHeaders && !hasBody && richness < 20) return
                rawRequest = this._normalizeRawRequestLine(rawRequest, envelope)
                if (!rawRequest) return
                if (this._isPtkGeneratedRequest(rawRequest, details?.url || envelope.url)) return
                const capturedRequest = cloneCapturedRequest({
                    url: details?.url || envelope.url,
                    ui_url: details?.ui_url || envelope.ui_url || envelope.url,
                    method: details?.method || method,
                    requestHeaders: details?.requestHeaders || [],
                    requestBody: details?.requestBody || null
                })
                if (this._isPtkGeneratedCapturedRequest(capturedRequest)) return
                const uiUrl = this._extractUiUrlFromRaw(rawRequest, envelope.ui_url || envelope.url)
                this.engine?.enqueue?.({
                    raw: rawRequest,
                    url: envelope.url,
                    method,
                    ui_url: uiUrl || envelope.ui_url || envelope.url,
                    responseType: envelope.type,
                    capturedRequest
                }, Object.assign({}, envelope, {
                    ui_url: uiUrl || envelope.ui_url || envelope.url
                }))
            } catch (_) { }
        })
    }

    async seedZapAutomationRequestsFromProxy(tabId, options = {}) {
        if (!this.engine?.isRunning || !this.state.acceptIncomingRequests) {
            return {
                seeded: 0,
                proxySeeded: 0,
                historySeeded: 0,
                historySeedInputCount: 0,
                historySeedDuplicatesSkipped: 0
            }
        }

        const proxy = this.worker?.ptk_app?.proxy
        const maxRequests = Number.isFinite(Number(options?.maxRequests))
            ? Math.max(0, Number(options.maxRequests))
            : 200
        const proxyEntries = typeof proxy?.collectZapAutomationSeedRequests === "function"
            ? proxy.collectZapAutomationSeedRequests(tabId, {
                targetUrl: options?.targetUrl || options?.pageUrl || null,
                sinceMs: options?.sinceMs || 0,
                maxRequests
            })
            : []

        let proxySeeded = 0
        for (const entry of Array.isArray(proxyEntries) ? proxyEntries : []) {
            const rawRequest = String(entry?.raw || "")
            const firstLine = rawRequest.split(/\r?\n/)[0] || ""
            if (!/^[A-Z]+\s+https?:\/\//.test(firstLine)) continue
            if (this._isPtkGeneratedRequest(rawRequest, entry?.url || "")) continue
            const response = {
                tabId,
                frameId: Number.isInteger(entry?.frameId) ? entry.frameId : 0,
                requestId: entry?.requestId || `zap-seed-${proxySeeded}`,
                url: entry?.url,
                ui_url: entry?.ui_url || entry?.url,
                method: entry?.method || "GET",
                type: entry?.type || "xmlhttprequest",
                statusCode: entry?.statusCode || 200
            }
            this.engine?.enqueue?.({
                raw: rawRequest,
                url: entry?.url,
                method: entry?.method || "GET",
                ui_url: entry?.ui_url || entry?.url,
                responseType: response.type,
                capturedRequest: cloneCapturedRequest({
                    url: entry?.url,
                    ui_url: entry?.ui_url || entry?.url,
                    method: entry?.method || "GET",
                    requestHeaders: entry?.requestHeaders || [],
                    requestBody: entry?.requestBody || null
                })
            }, response)
            proxySeeded += 1
        }

        const historySeedUrls = Array.isArray(options?.historySeedUrls) ? options.historySeedUrls : []
        let historySeeded = 0
        let historySeedDuplicatesSkipped = 0
        const seenHistory = new Set(proxyEntries.map((entry) => String(entry?.url || "")))
        for (const url of historySeedUrls) {
            if (typeof url !== "string" || !/^https?:\/\//i.test(url)) continue
            if (this._isPtkGeneratedRequest("", url)) continue
            if (seenHistory.has(url)) {
                historySeedDuplicatesSkipped += 1
                continue
            }
            try {
                const parsed = new URL(url)
                const raw = `GET ${url} HTTP/1.1\r\nHost: ${parsed.host}\r\n\r\n`
                this.engine?.enqueue?.({
                    raw,
                    url,
                    method: "GET",
                    ui_url: url,
                    responseType: "main_frame"
                }, {
                    tabId,
                    frameId: 0,
                    requestId: `zap-history-seed-${historySeeded}`,
                    url,
                    ui_url: url,
                    method: "GET",
                    type: "main_frame",
                    statusCode: 200
                })
                historySeeded += 1
                seenHistory.add(url)
            } catch (_) { }
        }

        return {
            seeded: proxySeeded + historySeeded,
            proxySeeded,
            historySeeded,
            historySeedInputCount: historySeedUrls.length,
            historySeedDuplicatesSkipped
        }
    }

    scheduleDeferredSeedAtEnd(seedGeneration) {
        this.sleep(0).then(async () => {
            const state = this.state
            const deferredState = state?.deferredSeedState
            if (!deferredState || deferredState.seeded || deferredState.generation !== seedGeneration) return
            if (state?.zapManaged === true) return
            if (!this.engine?.isRunning || !state.acceptIncomingRequests) return
            if (state.requireUserInteractionBeforeCapture && !state.userInteractionUnlocked) return
            try {
                await this.engine?.waitForIdle?.(deferredState.idleTimeoutMs)
            } catch (_) { }
            const current = this.state?.deferredSeedState
            if (!current || current.seeded || current.generation !== seedGeneration) return
            if (!this.engine?.isRunning || !this.state.acceptIncomingRequests) return
            current.seeded = true
            this.seedRequestsFromTab(current.tabId, current.maxSeedRequests)
            try {
                await this.engine?.waitForIdle?.(current.postSeedIdleTimeoutMs)
            } catch (_) { }
        }).catch(() => false)
    }

    async runDeferredSeedNowIfPending(timeoutMs = 120000) {
        const state = this.state
        const deferredState = state?.deferredSeedState
        if (!deferredState || deferredState.seeded) return false
        if (state?.zapManaged === true) return false
        if (!this.engine?.isRunning || !state.acceptIncomingRequests) return false
        if (state.requireUserInteractionBeforeCapture && !state.userInteractionUnlocked) return false
        deferredState.seeded = true
        this.seedRequestsFromTab(deferredState.tabId, deferredState.maxSeedRequests)
        try {
            await this.engine?.waitForIdle?.(timeoutMs)
        } catch (_) { }
        return true
    }

    async enqueueObservedRequest(response, maxAttempts = 6) {
        const requestedAttempts = Math.max(1, Number(maxAttempts) || 1)
        const attempts = this._isStateChangingRequest(response) ? Math.max(requestedAttempts, 6) : requestedAttempts
        for (let attempt = 0; attempt < attempts; attempt++) {
            try {
                const tab = this.worker?.ptk_app?.proxy?.getTab?.(response.tabId)
                if (!tab) throw new Error("tab_not_ready")
                const details = this.worker?.ptk_app?.proxy?.getRequestDetails?.(tab, response.frameId, response.requestId, {
                    expectedUrl: response.url,
                    expectedMethod: response.method
                }) || null
                const rawBundle = this.worker?.ptk_app?.proxy?.getRawRequestWithMeta
                    ? this.worker.ptk_app.proxy.getRawRequestWithMeta(tab, response.frameId, response.requestId, {
                        expectedUrl: response.url,
                        expectedMethod: response.method
                    })
                    : { raw: this.worker?.ptk_app?.proxy?.getRawRequest?.(tab, response.frameId, response.requestId), meta: {} }
                let rawRequest = rawBundle?.raw || ""
                if (!String(rawRequest || "").trim() && response?.url) {
                    try {
                        const parsed = new URL(response.url)
                        const method = String(response?.method || "GET").toUpperCase()
                        rawRequest = `${method} ${response.url} HTTP/1.1\r\nHost: ${parsed.host}\r\n\r\n`
                    } catch (_) { }
                }
                if (this._isPtkGeneratedRequest(rawRequest, response?.url || response?.ui_url || "")) {
                    return false
                }
                const capturedRequest = {
                    url: details?.url || response.url,
                    ui_url: details?.ui_url || response.ui_url || response.url,
                    method: details?.method || response.method,
                    requestHeaders: details?.requestHeaders || [],
                    requestBody: details?.requestBody || null
                }
                if (this._isPtkGeneratedCapturedRequest(capturedRequest)) {
                    return false
                }
                const withCookieBackfill = await this._backfillJwtCookieHeader(rawRequest, capturedRequest)
                rawRequest = withCookieBackfill.rawRequest
                const effectiveCapturedRequest = withCookieBackfill.capturedRequest
                const hasPerRequestHeaders = !!rawBundle?.meta?.hasPerRequestHeaders
                const richness = this._rawRequestHeaderRichness(rawRequest)
                const bodyReadiness = this._stateChangingBodyReadiness(rawRequest, effectiveCapturedRequest, response)
                if (!bodyReadiness.ready) {
                    if (attempt < attempts - 1) {
                        await this.sleep(75 * (attempt + 1))
                        continue
                    }
                    this._recordCaptureDiagnostic({
                        type: "state_changing_request_body_unavailable",
                        reason: bodyReadiness.reason,
                        url: response?.url || null,
                        method: response?.method || null,
                        statusCode: response?.statusCode || null
                    })
                    if (bodyReadiness.dropIfFinal) return false
                }
                if ((!hasPerRequestHeaders || richness < 60) && attempt < attempts - 1) {
                    await this.sleep(75 * (attempt + 1))
                    continue
                }
                rawRequest = this._normalizeRawRequestLine(rawRequest, response)
                const firstLine = String(rawRequest || "").split(/\r?\n/)[0] || ""
                if (!/^[A-Z]+\s+https?:\/\//.test(firstLine)) return false
                const uiUrl = this._extractUiUrlFromRaw(rawRequest, response.ui_url || response.url)
                this.engine?.enqueue?.({
                    raw: rawRequest,
                    url: response.url,
                    method: response.method,
                    ui_url: uiUrl || response.ui_url || response.url,
                    responseType: response.type,
                    capturedRequest: cloneCapturedRequest(effectiveCapturedRequest)
                }, Object.assign({}, response, {
                    ui_url: uiUrl || response.ui_url || response.url
                }))
                return true
            } catch (_) {
                if (attempt < attempts - 1) {
                    await this.sleep(30 * (attempt + 1))
                }
            }
        }
        return false
    }

    _enqueueRedirect(response) {
        const status = response?.statusCode
        if (status < 300 || status >= 400) return
        const headers = response?.responseHeaders || []
        const locationHeader = headers.find((h) => (h?.name || "").toLowerCase() === "location")
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
            this.engine?.enqueue?.({
                raw: syntheticRaw,
                ui_url: redirectUrl,
                responseType: response.type
            }, redirectResponse)
        } catch (_) { }
    }

    _shouldCaptureResponse(response, { allowHtmlDiscoveryBypass = false } = {}) {
        if (!(this.engine?.isRunning && this.state.acceptIncomingRequests && this.engine.tabId === response?.tabId)) {
            return false
        }
        if (!this._isAttackableRequestType(response)) return false
        if (this.state.requireUserInteractionBeforeCapture && !this.state.userInteractionUnlocked) {
            if (allowHtmlDiscoveryBypass && this._isSameOriginHtmlDocumentResponse(response)) {
                return true
            }
            if (this._isStateChangingRequest(response)) {
                this.state.userInteractionUnlocked = true
            } else {
                return false
            }
        }
        return true
    }

    onResponseStarted(response) {
        if (!this._shouldCaptureResponse(response)) return
        this._trackObservedRequest(this.enqueueObservedRequest(response))
    }

    onHeadersReceived(response) {
        if (!this._shouldCaptureResponse(response, { allowHtmlDiscoveryBypass: true })) return
        try {
            this._trackObservedRequest(this.enqueueObservedRequest(response, 2))
            if (this.state.enableSyntheticRedirectRequests) {
                this._enqueueRedirect(response)
            }
        } catch (_) { }
    }

    onCompleted(response) {
        if (!this._shouldCaptureResponse(response, { allowHtmlDiscoveryBypass: true })) return
        this._trackObservedRequest(this.enqueueObservedRequest(response, 2))
    }
}

export default DastCaptureAdapter
