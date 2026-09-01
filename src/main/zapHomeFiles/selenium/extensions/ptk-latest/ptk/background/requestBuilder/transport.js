/* Author: Denis Podgurskii */
import { ptk_utils, ptk_ruleManager } from "../utils.js"
import { RequestBuilderModel } from "./model.js"
import {
    IsolatedRedirectCookieJar,
    isRedirectStatus,
    redirectRequestTransition
} from "./isolatedRedirectSession.js"

const worker = globalThis.self || globalThis

export class RequestBuilderTransport {
    static _dnrLock = Promise.resolve()
    static _storedHeaderMap = new Map()
    static _storedHeaderTtlMs = 120000

    static clearStoredHeaders() {
        this._storedHeaderMap.clear()
    }

    static _purgeStoredHeaders(now = Date.now()) {
        for (const [key, value] of this._storedHeaderMap.entries()) {
            const ts = value?.ts || 0
            if (now - ts > this._storedHeaderTtlMs) {
                this._storedHeaderMap.delete(key)
            }
        }
    }

    static _cloneHeader(header = {}) {
        return {
            name: typeof header?.name === 'string' ? header.name : String(header?.name || ''),
            value: typeof header?.value === 'string' ? header.value : String(header?.value ?? '')
        }
    }

    static _parseCookieHeader(value) {
        const map = new Map()
        const order = []
        String(value ?? '').split(';').forEach((part) => {
            const trimmed = part.trim()
            if (!trimmed) return
            const eqIndex = trimmed.indexOf('=')
            const name = (eqIndex >= 0 ? trimmed.slice(0, eqIndex) : trimmed).trim()
            if (!name) return
            const cookieValue = eqIndex >= 0 ? trimmed.slice(eqIndex + 1).trim() : ''
            if (!map.has(name)) order.push(name)
            map.set(name, cookieValue)
        })
        return { map, order }
    }

    static _mergeCookieHeaderValues(liveValue, storedValue) {
        const normalizedStoredValue = typeof storedValue === 'string'
            ? storedValue
            : String(storedValue ?? '')
        if (!normalizedStoredValue.trim()) {
            return normalizedStoredValue
        }

        const liveCookies = this._parseCookieHeader(liveValue)
        const storedCookies = this._parseCookieHeader(normalizedStoredValue)
        const mergedMap = new Map(liveCookies.map)
        const mergedOrder = liveCookies.order.slice()

        storedCookies.order.forEach((name) => {
            if (!mergedMap.has(name)) {
                mergedOrder.push(name)
            }
            mergedMap.set(name, storedCookies.map.get(name))
        })

        return mergedOrder.map((name) => `${name}=${mergedMap.get(name)}`).join('; ')
    }

    static _mergeFirefoxListenerHeaders(liveHeaders, storedHeaders, opts = {}) {
        const strictCookieOverride = opts?.strictCookieOverride === true
        const baseHeaders = Array.isArray(liveHeaders)
            ? liveHeaders.filter((header) => header?.name).map((header) => this._cloneHeader(header))
            : []
        const overrideHeaders = Array.isArray(storedHeaders)
            ? storedHeaders.filter((header) => header?.name).map((header) => this._cloneHeader(header))
            : []

        if (!worker.isFirefox || !overrideHeaders.length) {
            return overrideHeaders.length ? overrideHeaders : baseHeaders
        }

        const mergedHeaders = baseHeaders.slice()
        const indexByName = new Map()
        mergedHeaders.forEach((header, index) => {
            const key = String(header?.name || '').toLowerCase()
            if (key && !indexByName.has(key)) {
                indexByName.set(key, index)
            }
        })
        const hasStoredCookieHeader = overrideHeaders.some(
            (header) => String(header?.name || '').toLowerCase() === 'cookie'
        )

        overrideHeaders.forEach((header) => {
            const key = String(header?.name || '').toLowerCase()
            if (!key) return

            const existingIndex = indexByName.get(key)
            const existingHeader = Number.isInteger(existingIndex)
                ? mergedHeaders[existingIndex]
                : null
            let nextValue = header.value

            if (key === 'cookie') {
                nextValue = strictCookieOverride
                    ? header.value
                    : this._mergeCookieHeaderValues(existingHeader?.value, header.value)
            }

            const nextHeader = {
                name: existingHeader?.name || header.name,
                value: nextValue
            }

            if (Number.isInteger(existingIndex)) {
                mergedHeaders[existingIndex] = nextHeader
                return
            }

            indexByName.set(key, mergedHeaders.length)
            mergedHeaders.push(nextHeader)
        })

        if (!strictCookieOverride || hasStoredCookieHeader) {
            return mergedHeaders
        }

        return mergedHeaders.filter(
            (header) => String(header?.name || '').toLowerCase() !== 'cookie'
        )
    }

    static async _withDnrLock(fn) {
        const prev = this._dnrLock
        let release
        const next = new Promise((resolve) => { release = resolve })
        this._dnrLock = prev.then(() => next)
        await prev
        try {
            return await fn()
        } finally {
            release()
        }
    }

    constructor() {
        this.init()
    }

    async init() {
        this.useListeners = false
        this.trackWithListeners = false
        this.trackingRequest = null
        this.isolatedRedirectSession = false
        this.isolatedPreserveRawHeaders = false
    }

    addListeners() {
        let blocking = []
        if (worker.isFirefox)
            blocking.push("blocking")

        this.onBeforeRequest = this.onBeforeRequest.bind(this)
        browser.webRequest.onBeforeRequest.addListener(
            this.onBeforeRequest,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["requestBody"].concat(ptk_utils.extraInfoSpec).concat(blocking)
        )

        this.onBeforeSendHeaders = this.onBeforeSendHeaders.bind(this)
        browser.webRequest.onBeforeSendHeaders.addListener(
            this.onBeforeSendHeaders,
            { urls: ["<all_urls>"], types: ptk_utils.filterType },
            ["requestHeaders"].concat(ptk_utils.extraInfoSpec).concat(blocking)
        )

        this.onHeadersReceived = this.onHeadersReceived.bind(this);
        browser.webRequest.onHeadersReceived.addListener(
            this.onHeadersReceived,
            { urls: ["<all_urls>"], types: ptk_utils.filterType },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec).concat(blocking)
        )
    }

    removeListeners() {
        browser.webRequest.onBeforeSendHeaders.removeListener(this.onBeforeSendHeaders)
        browser.webRequest.onBeforeRequest.removeListener(this.onBeforeRequest)
        browser.webRequest.onHeadersReceived.removeListener(this.onHeadersReceived)
    }

    onBeforeRequest(request) {
        if (this.trackingRequest) {
            let item = {
                requestId: request.requestId,
                type: "main_frame",
                request: request,
                response: {}
            }
            this.trackingRequest.set(request.requestId, item)
        }
    }

    onBeforeSendHeaders(request) {
        const reqIdHeader = (request.requestHeaders || []).find(
            (h) => (h?.name || '').toLowerCase() === 'x-ptk-reqid'
        )?.value
        const sourceHeader = (request.requestHeaders || []).find(
            (h) => (h?.name || '').toLowerCase() === 'x-ptk-source'
        )?.value

        let modifiedHeaders = request.requestHeaders
        RequestBuilderTransport._purgeStoredHeaders()
        if (reqIdHeader && sourceHeader && RequestBuilderTransport._storedHeaderMap.has(reqIdHeader)) {
            const stored = RequestBuilderTransport._storedHeaderMap.get(reqIdHeader)
            if (stored?.source !== sourceHeader) {
                RequestBuilderTransport._storedHeaderMap.delete(reqIdHeader)
            } else {
                const storedHeaders = stored?.headers || []
                modifiedHeaders = RequestBuilderTransport._mergeFirefoxListenerHeaders(
                    request.requestHeaders,
                    storedHeaders,
                    { strictCookieOverride: stored?.strictCookieOverride === true }
                )
            }
        }

        if (this.trackingRequest?.has(request.requestId)) {
            const entry = this.trackingRequest.get(request.requestId)
            entry.request.requestHeaders = modifiedHeaders
            if (reqIdHeader) {
                entry.ptkReqId = reqIdHeader
                this.trackingRequest.set(`ptk:${reqIdHeader}`, entry)
            }
        }

        return { requestHeaders: modifiedHeaders }
    }

    onHeadersReceived(response) {
        if (this.trackingRequest?.has(response.requestId)) {
            this.trackingRequest.get(response.requestId).response = response
        }
        return { responseHeaders: response.responseHeaders }
    }

    static _exactUrlRegex(value) {
        const parsed = new URL(value)
        parsed.hash = ''
        return `^${parsed.toString().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`
    }

    static _nextRuleId() {
        const values = new Uint32Array(1)
        globalThis.crypto.getRandomValues(values)
        return 1000 + (values[0] % 2147482000)
    }

    static async _addExactSessionRule(url, headers, ruleId) {
        if (worker.isFirefox) return
        const parsed = new URL(url)
        const requestHeaders = (Array.isArray(headers) ? headers : [])
            .filter((header) => header?.name)
            .map((header) => ({
                header: String(header.name),
                operation: 'set',
                value: String(header.value ?? '')
            }))
        if (!requestHeaders.length) return
        const condition = {
            regexFilter: RequestBuilderTransport._exactUrlRegex(parsed.toString()),
            requestDomains: [parsed.hostname],
            resourceTypes: ['xmlhttprequest', 'other']
        }
        if (chrome?.runtime?.id) condition.initiatorDomains = [chrome.runtime.id]
        await chrome.declarativeNetRequest.updateSessionRules({
            addRules: [{
                id: Number(ruleId),
                priority: 1,
                action: {
                    type: 'modifyHeaders',
                    requestHeaders
                },
                condition
            }]
        })
    }

    _isolatedRedirectHeaders(baseHeaders, {
        currentUrl,
        previousUrl = null,
        method,
        body,
        cookieHeader,
        ptkReqId,
        ptkSource,
        schema
    }) {
        const current = new URL(currentUrl)
        const previous = previousUrl ? new URL(previousUrl) : null
        const crossOrigin = previous && previous.origin !== current.origin
        const bodyless = body === null || method === 'GET' || method === 'HEAD'
        const removeNames = new Set(['cookie', 'x-ptk-reqid', 'x-ptk-source'])
        if (bodyless) {
            removeNames.add('content-length')
            removeNames.add('content-type')
            removeNames.add('transfer-encoding')
        }
        if (previous && previous.host !== current.host) {
            removeNames.add('host')
        }
        if (crossOrigin) {
            ;[
                'authorization',
                'proxy-authorization',
                'origin',
                'referer'
            ].forEach((name) => removeNames.add(name))
        }

        const map = new Map()
        ;(Array.isArray(baseHeaders) ? baseHeaders : []).forEach((header) => {
            const name = String(header?.name || '')
            const key = name.toLowerCase()
            if (!name || removeNames.has(key)) return
            map.set(key, { name, value: String(header?.value ?? '') })
        })
        if (cookieHeader) map.set('cookie', { name: 'Cookie', value: cookieHeader })
        map.set('x-ptk-reqid', { name: 'X-PTK-ReqId', value: ptkReqId })
        map.set('x-ptk-source', { name: 'X-PTK-Source', value: ptkSource })

        const fetchHeaders = Object.fromEntries(
            Array.from(map.values()).map((header) => [header.name, header.value])
        )
        this._ensureContentLength(schema, fetchHeaders, body)
        const allRuleHeaders = Object.entries(fetchHeaders).map(([name, value]) => ({ name, value }))
        const ruleHeaders = schema?.opts?.override_headers !== false
            ? allRuleHeaders
            : allRuleHeaders.filter((header) => [
                'cookie',
                'x-ptk-reqid',
                'x-ptk-source'
            ].includes(String(header?.name || '').toLowerCase()))
        return {
            fetchHeaders,
            ruleHeaders,
            needsDnr: this._isolatedRedirectNeedsDnr(currentUrl, ruleHeaders, schema)
        }
    }

    _isolatedRedirectNeedsDnr(currentUrl, headers, schema) {
        if (worker.isFirefox || schema?.opts?.use_dnr === false) return false
        if (schema?.opts?.force_dnr === true) return true

        const headerList = Array.isArray(headers) ? headers : []
        const names = new Set(headerList.map((header) => String(header?.name || '').toLowerCase()))
        if (names.has('cookie')) return true

        const hostHeader = headerList.find(
            (header) => String(header?.name || '').toLowerCase() === 'host'
        )?.value
        if (hostHeader) {
            try {
                if (String(hostHeader) !== new URL(currentUrl).host) return true
            } catch (_) {
                return true
            }
        }

        return ['origin', 'referer', 'user-agent'].some((name) => names.has(name))
    }

    async _sendIsolatedRedirectRequest(schema) {
        schema.opts = schema.opts || {}
        schema.request = schema.request || {}
        const rbSchema = schema
        rbSchema.response = rbSchema.response || {}

        const initialUrl = new URL(schema.request.url).toString()
        const rawInitialHeaders = Array.isArray(schema.request.headers)
            ? schema.request.headers.map((header) => ({ ...header }))
            : []
        const explicitCookie = rawInitialHeaders.find(
            (header) => String(header?.name || '').toLowerCase() === 'cookie'
        )?.value || (
            Array.isArray(schema.request.cookies)
                ? schema.request.cookies
                    .filter((cookie) => cookie?.name)
                    .map((cookie) => `${cookie.name}=${cookie.value || ''}`)
                    .join('; ')
                : ''
        )
        const preserveBrowserHeaders = this.isolatedPreserveRawHeaders === true
            || schema?.opts?.preserve_browser_headers === true
        const cacheValidatorNames = new Set([
            'if-none-match',
            'if-modified-since',
            'if-match',
            'if-unmodified-since'
        ])
        const browserManagedHeaderNames = new Set([
            'accept-encoding',
            'connection',
            'content-length',
            'host',
            'origin',
            'referer',
            'upgrade-insecure-requests',
            'user-agent'
        ])
        const initialHeaders = rawInitialHeaders.filter((header) => {
            const name = String(header?.name || '').toLowerCase()
            if (!name || cacheValidatorNames.has(name)) return false
            if (preserveBrowserHeaders) return true
            return !browserManagedHeaderNames.has(name)
                && !name.startsWith('sec-fetch-')
                && !name.startsWith('sec-ch-ua')
        })
        const jar = new IsolatedRedirectCookieJar()
        if (explicitCookie) jar.seedRequestCookieHeader(initialUrl, explicitCookie)

        let preparedBody = null
        const initialMethod = String(schema.request.method || 'GET').toUpperCase()
        if (schema.request.body && !initialMethod.match(/(^GET|^HEAD)/)) {
            if (typeof schema.request.body.text === 'string') {
                preparedBody = schema.request.body.text
            } else if (Array.isArray(schema.request.body.params)) {
                preparedBody = RequestBuilderModel._isMultipartBody(schema.request.body)
                    ? RequestBuilderModel.serializeMultipartParams(schema.request.body.params, schema.request.body.boundary)
                    : (
                        RequestBuilderModel._hasRawUrlencodedParams(schema.request.body.params)
                            ? RequestBuilderModel.serializeUrlencodedParams(schema.request.body.params)
                            : new URLSearchParams(schema.request.body.params.map((item) => `${item.name}=${item.value}`).join('&')).toString()
                    )
                schema.request.body.text = preparedBody
            }
        }

        const parsedMaxRedirects = Number(schema.opts.max_redirects)
        const maxRedirects = Number.isFinite(parsedMaxRedirects)
            ? Math.max(0, Math.min(20, Math.trunc(parsedMaxRedirects)))
            : 10
        const timeoutMs = Number(schema.opts.requestTimeoutMs)
        const controller = timeoutMs > 0 ? new AbortController() : null
        const timeoutId = controller
            ? setTimeout(() => controller.abort(), timeoutMs)
            : null
        const startTime = (typeof performance !== 'undefined' && performance.now)
            ? performance.now()
            : Date.now()
        const requestTimestamp = Number(
            rbSchema.request.timestamp
            ?? rbSchema.request.timeStamp
            ?? rbSchema.request.ts
        )
        rbSchema.request.timestamp = Number.isFinite(requestTimestamp) && requestTimestamp >= 0
            ? Math.round(requestTimestamp)
            : Date.now()
        const ptkSource = String(schema.opts.ptk_source || 'rbuilder')
        const retryOnTransportFailure = schema?.opts?.retry_on_transport_failure === true
        const parsedRetryCount = Number(schema?.opts?.transport_retry_count)
        const maxTransportRetries = Number.isFinite(parsedRetryCount)
            ? Math.max(0, Math.trunc(parsedRetryCount))
            : (retryOnTransportFailure ? 1 : 0)
        const parsedRetryDelay = Number(schema?.opts?.transport_retry_delay_ms)
        const transportRetryDelayMs = Number.isFinite(parsedRetryDelay)
            ? Math.max(0, parsedRetryDelay)
            : 75
        const sleep = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms))
        const isRetriableTransportFailure = (error) => {
            if (!error || controller?.signal?.aborted) return false
            const name = String(error?.name || '')
            const message = String(error?.message || '')
            if (name === 'AbortError') return false
            return name === 'TypeError'
                || /failed to fetch/i.test(message)
                || /networkerror/i.test(message)
        }
        const visited = new Set()
        let currentUrl = initialUrl
        let previousUrl = null
        let currentMethod = initialMethod
        let currentBody = preparedBody
        let redirectCount = 0
        let transportAttempts = 0
        let transportRetryCount = 0
        let listenersAdded = false

        const responseHeadersFromFetch = (response) => {
            const headers = []
            for (const pair of response.headers.entries()) {
                headers.push({ name: pair[0], value: pair[1] })
            }
            return headers
        }
        const headerValue = (headers, name) => {
            const wanted = String(name).toLowerCase()
            return (Array.isArray(headers) ? headers : []).find(
                (header) => String(header?.name || '').toLowerCase() === wanted
            )?.value || ''
        }
        const setFailure = (error) => {
            rbSchema.response = rbSchema.response || {}
            rbSchema.response.statusLine = error?.message || 'Request failed'
            rbSchema.response.transportAttempts = transportAttempts
            rbSchema.response.transportRetried = transportRetryCount > 0
            rbSchema.response.transportRetryCount = transportRetryCount
            rbSchema.response.redirectCount = redirectCount
            if (error?.name) rbSchema.response.errorName = String(error.name)
            if (error?.message) rbSchema.response.errorMessage = String(error.message)
            return rbSchema
        }

        const execute = async () => {
            try {
                this.trackingRequest = new Map()
                this.addListeners()
                listenersAdded = true
                while (true) {
                    const visitKey = `${currentMethod} ${currentUrl}`
                    if (visited.has(visitKey)) throw new Error('redirect_loop_detected')
                    visited.add(visitKey)

                    let response
                    let ptkReqId = null
                    let hopRetryCount = 0
                    while (true) {
                        ptkReqId = ptk_utils.attackParamId()
                        const cookieHeader = jar.cookieHeaderFor(currentUrl)
                        const { fetchHeaders, ruleHeaders, needsDnr } = this._isolatedRedirectHeaders(initialHeaders, {
                            currentUrl,
                            previousUrl,
                            method: currentMethod,
                            body: currentBody,
                            cookieHeader,
                            ptkReqId,
                            ptkSource,
                            schema
                        })
                        if (worker.isFirefox) {
                            RequestBuilderTransport._storedHeaderMap.set(ptkReqId, {
                                headers: ruleHeaders,
                                ts: Date.now(),
                                source: ptkSource,
                                strictCookieOverride: true
                            })
                        }
                        const params = {
                            method: currentMethod,
                            credentials: 'omit',
                            redirect: 'manual',
                            cache: 'no-cache',
                            keepalive: schema.opts.keepalive === true,
                            headers: fetchHeaders
                        }
                        if (currentBody !== null && currentMethod !== 'GET' && currentMethod !== 'HEAD') {
                            params.body = currentBody
                        }
                        if (controller) params.signal = controller.signal

                        const fetchAttempt = async () => {
                            let ruleId = null
                            try {
                                transportAttempts += 1
                                if (needsDnr) {
                                    ruleId = RequestBuilderTransport._nextRuleId()
                                    await RequestBuilderTransport._addExactSessionRule(currentUrl, ruleHeaders, ruleId)
                                }
                                return await fetch(currentUrl, params)
                            } finally {
                                if (ruleId) await ptk_ruleManager.removeSessionRule(ruleId)
                            }
                        }

                        try {
                            response = needsDnr
                                ? await RequestBuilderTransport._withDnrLock(fetchAttempt)
                                : await fetchAttempt()
                            break
                        } catch (error) {
                            const shouldRetry = retryOnTransportFailure
                                && hopRetryCount < maxTransportRetries
                                && isRetriableTransportFailure(error)
                            if (!shouldRetry) throw error
                            hopRetryCount += 1
                            transportRetryCount += 1
                            await sleep(transportRetryDelayMs * hopRetryCount)
                        } finally {
                            RequestBuilderTransport._storedHeaderMap.delete(ptkReqId)
                        }
                    }

                    const trackingRequest = this.trackingRequest.get(`ptk:${ptkReqId}`) || null
                    const trackedResponse = trackingRequest?.response || null
                    const headers = trackedResponse?.responseHeaders || responseHeadersFromFetch(response)
                    const statusCode = Number(trackedResponse?.statusCode ?? response.status)
                    const statusLine = trackedResponse?.statusLine || (
                        response.statusText
                            ? `${schema.request.protocolVersion || 'HTTP/1.1'} ${statusCode} ${response.statusText}`
                            : `${schema.request.protocolVersion || 'HTTP/1.1'} ${statusCode}`
                    )
                    jar.absorbResponseHeaders(currentUrl, headers)

                    if (isRedirectStatus(statusCode)) {
                        const location = headerValue(headers, 'location')
                        if (!location) {
                            rbSchema.response.body = await response.text()
                            rbSchema.response.headers = headers
                            rbSchema.response.statusCode = statusCode
                            rbSchema.response.statusLine = statusLine
                            break
                        }
                        if (redirectCount >= maxRedirects) throw new Error('redirect_limit_exceeded')
                        const nextUrl = new URL(location, currentUrl)
                        if (!['http:', 'https:'].includes(nextUrl.protocol)) {
                            throw new Error(`unsupported_redirect_protocol:${nextUrl.protocol}`)
                        }
                        const transition = redirectRequestTransition(statusCode, currentMethod, currentBody)
                        previousUrl = currentUrl
                        currentUrl = nextUrl.toString()
                        currentMethod = transition.method
                        currentBody = transition.body
                        redirectCount += 1
                        continue
                    }

                    rbSchema.response.body = await response.text()
                    rbSchema.response.headers = headers
                    rbSchema.response.statusCode = statusCode
                    rbSchema.response.statusLine = statusLine
                    break
                }

                rbSchema.response.length = typeof rbSchema.response.body === 'string'
                    ? rbSchema.response.body.length
                    : null
                const endTime = (typeof performance !== 'undefined' && performance.now)
                    ? performance.now()
                    : Date.now()
                rbSchema.response.timeMs = Math.round(endTime - startTime)
                rbSchema.response.transportAttempts = transportAttempts
                rbSchema.response.transportRetried = transportRetryCount > 0
                rbSchema.response.transportRetryCount = transportRetryCount
                rbSchema.response.redirectCount = redirectCount
                rbSchema.response.redirected = redirectCount > 0
                rbSchema.response.url = currentUrl
                return rbSchema
            } catch (error) {
                return setFailure(error)
            } finally {
                clearTimeout(timeoutId)
                this.trackingRequest = null
                if (listenersAdded) this.removeListeners()
            }
        }

        return execute()
    }

    async sendRequest(schema) {
        if (this.isolatedRedirectSession === true && schema?.opts?.follow_redirect !== false) {
            return this._sendIsolatedRedirectRequest(schema)
        }
        const shouldUseTrackingListeners = this.useListeners || this.trackWithListeners
        if (shouldUseTrackingListeners) this.addListeners()
        let ruleId = null
        this.trackingRequest = new Map()

        const headerList = schema.request.headers || []
        const transportMode = String(schema?.opts?.transport_mode || '').toLowerCase()
        const isSmugglingH1 = transportMode === 'smuggling_h1'
        const overrideHeaders = schema.opts.override_headers != false
        const preserveBrowserHeaders =
            this.useListeners || schema?.opts?.preserve_browser_headers === true || isSmugglingH1
        let effectiveCredentials = schema?.opts?.credentials || 'include'
        const hasCookieHeader = headerList.some(
            (h) => (h.name || '').toLowerCase() === 'cookie'
        )
        const hasOriginHeader = headerList.some(
            (h) => (h.name || '').toLowerCase() === 'origin'
        )
        const hasRefererHeader = headerList.some(
            (h) => (h.name || '').toLowerCase() === 'referer'
        )
        const hasUserAgentHeader = headerList.some(
            (h) => (h.name || '').toLowerCase() === 'user-agent'
        )
        let hostMismatch = false
        const hostHeader = headerList.find(
            (h) => (h.name || '').toLowerCase() === 'host'
        )?.value
        if (hostHeader) {
            try {
                const urlHost = new URL(schema.request.url).host
                hostMismatch = hostHeader !== urlHost
            } catch (_) {
                hostMismatch = true
            }
        }
        const needsDnr =
            isSmugglingH1 ||
            hasCookieHeader ||
            hostMismatch ||
            (
                preserveBrowserHeaders &&
                (
                    hasOriginHeader ||
                    hasRefererHeader ||
                    hasUserAgentHeader
                )
            )
        const useDnr =
            (schema?.opts?.use_dnr !== false) &&
            overrideHeaders &&
            (needsDnr || schema?.opts?.force_dnr === true)

        if (overrideHeaders && !hasCookieHeader && effectiveCredentials === 'include') {
            effectiveCredentials = 'omit'
        }

        const cacheValidatorNames = new Set([
            'if-none-match',
            'if-modified-since',
            'if-match',
            'if-unmodified-since'
        ])
        const browserManagedHeaderNames = new Set([
            'accept-encoding',
            'connection',
            'content-length',
            'host',
            'origin',
            'referer',
            'upgrade-insecure-requests',
            'user-agent'
        ])
        let effectiveHeaders = headerList.filter(
            (h) => !cacheValidatorNames.has((h?.name || '').toLowerCase())
        )
        if (!preserveBrowserHeaders && !isSmugglingH1) {
            effectiveHeaders = effectiveHeaders.filter((h) => {
                const name = String(h?.name || '').toLowerCase()
                return !browserManagedHeaderNames.has(name) && !name.startsWith('sec-fetch-') && !name.startsWith('sec-ch-ua')
            })
        }

        const hasCookiesArray = Array.isArray(schema?.request?.cookies) && schema.request.cookies.length > 0
        const hasCookieHeaderAfter = effectiveHeaders.some(
            (h) => (h.name || '').toLowerCase() === 'cookie'
        )
        if (hasCookiesArray && !hasCookieHeaderAfter) {
            const cookieValue = schema.request.cookies
                .map((c) => `${c.name}=${c.value}`)
                .join('; ')
            effectiveHeaders.push({ name: 'Cookie', value: cookieValue })
        }

        const ptkReqId = schema?.opts?.ptk_req_id || ptk_utils.attackParamId()
        schema.opts.ptk_req_id = ptkReqId
        if (!effectiveHeaders.some((h) => (h.name || '').toLowerCase() === 'x-ptk-reqid')) {
            effectiveHeaders.push({ name: 'X-PTK-ReqId', value: ptkReqId })
        }
        let ptkSource = schema?.opts?.ptk_source
        if (!ptkSource && this.useListeners) {
            ptkSource = 'rbuilder'
        }
        if (ptkSource && !effectiveHeaders.some((h) => (h.name || '').toLowerCase() === 'x-ptk-source')) {
            effectiveHeaders.push({ name: 'X-PTK-Source', value: String(ptkSource) })
        }

        if (effectiveCredentials === 'omit') {
            effectiveHeaders = effectiveHeaders.filter(
                (h) => (h.name || '').toLowerCase() !== 'cookie'
            )
        }
        schema.request.headers = effectiveHeaders

        const syncStoredHeadersForAttempt = () => {
            if (!shouldUseTrackingListeners || !ptkReqId) return
            const webRequestHeaders = Object.entries(h).map(([name, value]) => ({ name, value }))
            RequestBuilderTransport._storedHeaderMap.set(ptkReqId, {
                headers: webRequestHeaders,
                ts: Date.now(),
                source: ptkSource || null,
                strictCookieOverride: schema?.opts?.strict_cookie_override === true
            })
        }

        const timeoutMs = Number(schema?.opts?.requestTimeoutMs)
        let controller = null
        let timeoutId = null
        if (timeoutMs && timeoutMs > 0) {
            controller = new AbortController()
            timeoutId = setTimeout(() => controller.abort(), timeoutMs)
        }
        let h = {}
        for (let i = 0; i < effectiveHeaders.length; i++) {
            let item = effectiveHeaders[i]
            h[item.name] = item.value
        }
        let params = {
            method: schema.request.method,
            credentials: effectiveCredentials,
            redirect: schema.opts.follow_redirect ? "follow" : "manual",
            cache: 'no-cache',
            keepalive: schema?.opts?.keepalive === true,
            headers: h,
        }
        if (controller) {
            params.signal = controller.signal
        }
        let preparedBody = null
        if (schema.request.body && !schema.request.method.toUpperCase().match(/(^GET|^HEAD)/)) {
            if (typeof schema.request.body.text === 'string') {
                preparedBody = schema.request.body.text
            } else if (Array.isArray(schema.request.body.params)) {
                preparedBody = RequestBuilderModel._isMultipartBody(schema.request.body)
                    ? RequestBuilderModel.serializeMultipartParams(schema.request.body.params, schema.request.body.boundary)
                    : (
                        RequestBuilderModel._hasRawUrlencodedParams(schema.request.body.params)
                            ? RequestBuilderModel.serializeUrlencodedParams(schema.request.body.params)
                            : new URLSearchParams(schema.request.body.params.map(x => `${x.name}=${x.value}`).join('&')).toString()
                    )
                schema.request.body.text = preparedBody
            }
            if (preparedBody !== null) {
                params.body = preparedBody
            }
        }
        this._ensureContentLength(schema, h, preparedBody)
        let rbSchema = schema
        rbSchema.response = rbSchema.response || {}
        rbSchema.request = rbSchema.request || {}
        const requestTimestamp = Number(
            rbSchema.request.timestamp
            ?? rbSchema.request.timeStamp
            ?? rbSchema.request.ts
        )
        if (Number.isFinite(requestTimestamp) && requestTimestamp >= 0) {
            rbSchema.request.timestamp = Math.round(requestTimestamp)
        } else {
            rbSchema.request.timestamp = Date.now()
        }
        const startTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()
        let self = this
        const retryOnTransportFailure = !isSmugglingH1 && schema?.opts?.retry_on_transport_failure === true
        const parsedRetryCount = Number(schema?.opts?.transport_retry_count)
        const maxTransportRetries = Number.isFinite(parsedRetryCount)
            ? Math.max(0, parsedRetryCount)
            : (retryOnTransportFailure ? 1 : 0)
        const parsedRetryDelay = Number(schema?.opts?.transport_retry_delay_ms)
        const transportRetryDelayMs = Number.isFinite(parsedRetryDelay)
            ? Math.max(0, parsedRetryDelay)
            : 75
        const sleep = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms))
        const isRetriableTransportFailure = (error) => {
            if (!error) return false
            if (controller?.signal?.aborted) return false
            const name = String(error?.name || '')
            const message = String(error?.message || '')
            if (name === 'AbortError') return false
            return (
                name === 'TypeError'
                || /failed to fetch/i.test(message)
                || /networkerror/i.test(message)
            )
        }

        const runRequest = async () => {
            if (useDnr && effectiveHeaders.length > 0) {
                ruleId = parseInt((Math.floor(Math.random() * 6) + 1) + Math.floor((Date.now() * Math.random() * 1000)).toString().substr(-8, 8))
                await ptk_ruleManager.addSessionRule(schema, ruleId)
            }
            try {
                let attempt = 0
                while (true) {
                    try {
                        attempt += 1
                        syncStoredHeadersForAttempt()
                        const response = await fetch(schema.request.url, params)
                        let rh = []
                        for (var pair of response.headers.entries()) {
                            rh.push({ name: pair[0], value: pair[1] })
                        }
                        let trackingRequest = null
                        if (self.trackingRequest && rbSchema?.opts?.ptk_req_id) {
                            trackingRequest = self.trackingRequest.get(`ptk:${rbSchema.opts.ptk_req_id}`) || null
                        }

                        rbSchema.response.body = await response.text()
                        rbSchema.response.length = typeof rbSchema.response.body === 'string' ? rbSchema.response.body.length : null
                        if (trackingRequest) {
                            rbSchema.response.headers = trackingRequest.response.responseHeaders || rh
                            rbSchema.response.statusLine = trackingRequest.response.statusLine
                            rbSchema.response.statusCode = trackingRequest.response.statusCode ?? response.status
                            if (!rbSchema.response.statusLine) {
                                const protocolVersion = (rbSchema.request.protocolVersion || 'HTTP/1.1').trim()
                                const statusText = typeof response.statusText === 'string' ? response.statusText.trim() : ''
                                rbSchema.response.statusLine = statusText
                                    ? `${protocolVersion} ${response.status} ${statusText}`
                                    : `${protocolVersion} ${response.status}`
                            }
                        } else {
                            rbSchema.response.headers = rh
                            rbSchema.response.statusCode = response.status
                            const protocolVersion = (rbSchema.request.protocolVersion || 'HTTP/1.1').trim()
                            const statusText = typeof response.statusText === 'string' ? response.statusText.trim() : ''
                            rbSchema.response.statusLine = statusText
                                ? `${protocolVersion} ${response.status} ${statusText}`
                                : `${protocolVersion} ${response.status}`
                        }
                        const endTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()
                        rbSchema.response.timeMs = Math.round(endTime - startTime)
                        rbSchema.response.transportAttempts = attempt
                        rbSchema.response.transportRetried = attempt > 1
                        rbSchema.response.transportRetryCount = Math.max(0, attempt - 1)
                        return rbSchema
                    } catch (e) {
                        const shouldRetry = attempt <= maxTransportRetries && isRetriableTransportFailure(e)
                        if (shouldRetry) {
                            await sleep(transportRetryDelayMs * attempt)
                            continue
                        }
                        console.warn('ptk_request.sendRequest failed', {
                            url: schema?.request?.url,
                            method: schema?.request?.method,
                            hasBody: preparedBody !== null,
                            bodyLength: preparedBody ? preparedBody.length : 0,
                            name: e?.name,
                            message: e?.message,
                            cause: e?.cause?.message || e?.cause || null,
                            attempt
                        }, e)
                        rbSchema.response = rbSchema.response || {}
                        rbSchema.response.statusLine = e?.message || 'Request failed'
                        rbSchema.response.transportAttempts = attempt
                        rbSchema.response.transportRetried = attempt > 1
                        rbSchema.response.transportRetryCount = Math.max(0, attempt - 1)
                        if (e?.name) rbSchema.response.errorName = String(e.name)
                        if (e?.message) rbSchema.response.errorMessage = String(e.message)
                        if (e?.cause) {
                            rbSchema.response.errorCause = typeof e.cause === 'string'
                                ? e.cause
                                : (e.cause?.message || String(e.cause))
                        }
                        return rbSchema
                    }
                }
            } catch (e) {
                rbSchema.response = rbSchema.response || {}
                rbSchema.response.statusLine = e?.message || 'Request failed'
                if (e?.name) rbSchema.response.errorName = String(e.name)
                if (e?.message) rbSchema.response.errorMessage = String(e.message)
                if (e?.cause) {
                    rbSchema.response.errorCause = typeof e.cause === 'string'
                        ? e.cause
                        : (e.cause?.message || String(e.cause))
                }
                return rbSchema
            } finally {
                clearTimeout(timeoutId)
                if (ptkReqId) RequestBuilderTransport._storedHeaderMap.delete(ptkReqId)
                self.trackingRequest = null
                if (shouldUseTrackingListeners) self.removeListeners()
                if (ruleId) {
                    await ptk_ruleManager.removeSessionRule(ruleId)
                }
            }
        }

        if (useDnr) {
            return RequestBuilderTransport._withDnrLock(runRequest)
        }
        return runRequest()
    }

    _ensureContentLength(schema, headersMap, body) {
        const transportMode = String(schema?.opts?.transport_mode || '').toLowerCase()
        const shouldUpdate = transportMode !== 'smuggling_h1' && schema?.opts?.update_content_length !== false
        const findHeaderName = () => {
            if (!headersMap) return null
            return Object.keys(headersMap).find(key => key?.toLowerCase() === 'content-length') || null
        }
        if (!shouldUpdate) {
            return
        }
        if (!body && body !== '') {
            const headerName = findHeaderName()
            if (headerName) delete headersMap[headerName]
            return
        }
        try {
            const byteLength = Buffer.byteLength(body, 'utf8')
            const headerName = findHeaderName() || 'Content-Length'
            headersMap[headerName] = String(byteLength)
        } catch (_) {
            const headerName = findHeaderName()
            if (headerName) delete headersMap[headerName]
        }
    }
}
