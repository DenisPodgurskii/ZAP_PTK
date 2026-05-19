/* Author: Denis Podgurskii */
import { ptk_utils, ptk_storage, ptk_ruleManager, ptk_logger } from "./utils.js"
import { httpZ } from "./lib/httpZ.esm.js"
import { getSearchParamsFromUrlOrHash } from "./dast/urlUtils.js"

const worker = self

export class ptk_request_manager {

    constructor(settings) {
        this.storageKey = 'ptk_rbuilder'
        this.storage = []
        this.settings = settings
        this.init()
        this.addMessageListeners()
    }

    async init() {
        this.storage = await ptk_storage.getItem(this.storageKey)
    }

    async clear(index) {
        this.init()
        if (index) delete this.storage[index]
        else this.storage = []
        await ptk_storage.setItem(this.storageKey, this.storage)
    }

    findLastIndex(obj, requestId) {
        let l = obj.length
        while (l--) {
            if (obj[l].requestId == requestId) return l
        }
        return -1
    }

    /* Listeners */

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    onMessage(message, sender, sendResponse) {

        if (!ptk_utils.isTrustedOrigin(sender))
            return Promise.reject({ success: false, error: 'Error origin value' })

        if (message.channel == "ptk_popup2background_request") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }
    }

    resort(storage) {
        let i = 0
        Object.keys(storage).sort(function (a, b) { return storage[a].sort - storage[b].sort }).forEach(function (key) {
            storage[key].sort = i
            i++
        })
        return storage
    }

    async msg_init(message) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        this.storage = this.storage ? this.resort(this.storage) : []
        return Promise.resolve(JSON.parse(JSON.stringify(this.storage)))
    }

    msg_clear(message) {
        this.clear(message.index)
        return Promise.resolve()
    }

    msg_reset_all(message) {
        this.clear()
        return Promise.resolve()
    }

    async msg_parse_request(message) {
        let rbObj = ptk_request.parseRawRequest(message.raw, message.opts)
        if (message.formId) {

            if (!this.storage[message.formId]) {
                this.storage[message.formId] = rbObj
                this.storage[message.formId].sort = Object.keys(this.storage).length
            } else {
                this.storage[message.formId].opts = message.opts
                this.storage[message.formId].request = rbObj.request
            }
            await ptk_storage.setItem(this.storageKey, this.storage)
        }
        return Promise.resolve(rbObj)
    }

    async msg_update_request(message) {
        let rbObj = ptk_request.updateRawRequest(message.schema, message.params, message.opts)
        if (message.formId) {
            if (!this.storage[message.formId]) {
                this.storage[message.formId] = rbObj
                this.storage[message.formId].sort = Object.keys(this.storage).length
            } else {
                this.storage[message.formId].opts = message.opts
                this.storage[message.formId].request = rbObj.request
            }
            await ptk_storage.setItem(this.storageKey, this.storage)
        }
        return Promise.resolve(rbObj)
    }

    async msg_delete_request(message) {
        if (this.storage[message.formId]) {
            delete this.storage[message.formId]
            await ptk_storage.setItem(this.storageKey, this.resort(this.storage))
        }
        return Promise.resolve(JSON.parse(JSON.stringify(this.storage)))
    }

    async msg_send_request(message) {
        let self = this
        let request = new ptk_request()
        if (message.useListeners) request.useListeners = true
        return request.sendRequest(message.schema).then(function (response) {
            if (message.formId) {
                if (!self.storage[message.formId]) {
                    self.storage[message.formId] = { sort: Object.keys(self.storage).length }
                }
                const sort = typeof self.storage[message.formId].sort === "number"
                    ? self.storage[message.formId].sort
                    : Object.keys(self.storage).length
                self.storage[message.formId] = response
                self.storage[message.formId].sort = sort
                delete self.storage[message.formId].scanResult
                ptk_storage.setItem(self.storageKey, self.storage)
            }
            return Promise.resolve(response)
        })
    }

    async msg_scan_request(message) {
        const rawRequest = message?.schema?.request?.raw || message?.raw || null
        const dastApp = worker.ptk_app?.rattacker || worker.ptk_app?.dast || null
        const scanFn = dastApp?.engine?.onetimeScanRequest
        if (typeof scanFn !== 'function') {
            throw new Error('dast_engine_not_available')
        }
        if (!rawRequest) {
            throw new Error('scan_request_raw_missing')
        }
        try {
            const scanResult = await scanFn.call(dastApp.engine, rawRequest, true)
            const cloned = JSON.parse(JSON.stringify(scanResult))
            const requestManager = worker.ptk_app?.request_manager || null
            if (requestManager?.storage?.[message.formId]) {
                requestManager.storage[message.formId].scanResult = cloned
                await ptk_storage.setItem(requestManager.storageKey, requestManager.storage)
            }
            await browser.runtime.sendMessage({
                channel: "ptk_background2popup_rbuilder",
                type: "scan completed",
                scanResult: cloned
            }).catch(e => ptk_logger.log(e, "Could not send a message", "info"))
            return Promise.resolve({ success: true, scanResult: cloned })
        } catch (error) {
            const detail = error?.message || String(error)
            await browser.runtime.sendMessage({
                channel: "ptk_background2popup_rbuilder",
                type: "scan_failed",
                error: detail
            }).catch(e => ptk_logger.log(e, "Could not send a failure message", "info"))
            throw error
        }
    }

    async msg_sync_storage(message) {
        if (message.storage) {
            this.storage = this.resort(message.storage)
            await ptk_storage.setItem(this.storageKey, this.storage)
        }
        return Promise.resolve(JSON.parse(JSON.stringify(this.storage)))
    }


    /* End Listeners */

}


export class ptk_request {
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

    static _hasRawUrlencodedParams(params) {
        return Array.isArray(params) && params.some(
            (param) => param?.__ptkRawMode === 'append_suffix'
        )
    }

    static _serializeUrlencodedParam(param) {
        const name = String(param?.name ?? '')
        if (param?.__ptkRawMode === 'append_suffix') {
            const base = typeof param.__ptkRawBase === 'undefined'
                ? String(param?.value ?? '')
                : String(param.__ptkRawBase)
            const pair = new URLSearchParams([[name, base]]).toString()
            return `${pair}${String(param.__ptkRawSuffix ?? '')}`
        }
        return new URLSearchParams([[name, String(param?.value ?? '')]]).toString()
    }

    static serializeUrlencodedParams(params) {
        if (!Array.isArray(params)) return ''
        return params.map((param) => ptk_request._serializeUrlencodedParam(param)).join('&')
    }

    static _isMultipartBody(body = null) {
        const contentType = String(body?.contentType || body?.mimeType || '').toLowerCase()
        return contentType.includes('multipart/form-data')
            || (
                Array.isArray(body?.params)
                && typeof body?.boundary === 'string'
                && body.boundary.length > 0
            )
    }

    static serializeMultipartParams(params, boundary) {
        if (!Array.isArray(params) || !params.length || !boundary) return ''
        return params.map((param) => {
            let part = `--${boundary}\r\n`
            part += `Content-Disposition: ${param?.type || 'form-data'}`
            if (param?.name) {
                part += `; name="${String(param.name).replace(/"/g, '\\"')}"`
            }
            if (param?.fileName) {
                part += `; filename="${String(param.fileName).replace(/"/g, '\\"')}"`
            }
            part += `\r\n`
            if (param?.contentType) {
                part += `Content-Type: ${String(param.contentType)}\r\n`
            }
            part += `\r\n`
            part += String(param?.value ?? '')
            part += `\r\n`
            return part
        }).join('') + `--${boundary}--`
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

    constructor() {
        this.init()
    }

    async init() {
        this.useListeners = false
        this.trackWithListeners = false
        this.trackingRequest = null
    }

    /* Listeners */

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

        // Check if we have stored headers to apply for this request
        let modifiedHeaders = request.requestHeaders
        ptk_request._purgeStoredHeaders()
        if (reqIdHeader && sourceHeader && ptk_request._storedHeaderMap.has(reqIdHeader)) {
            const stored = ptk_request._storedHeaderMap.get(reqIdHeader)
            if (stored?.source !== sourceHeader) {
                ptk_request._storedHeaderMap.delete(reqIdHeader)
            } else {
                const storedHeaders = stored?.headers || []
                modifiedHeaders = ptk_request._mergeFirefoxListenerHeaders(
                    request.requestHeaders,
                    storedHeaders,
                    { strictCookieOverride: stored?.strictCookieOverride === true }
                )
                ptk_request._storedHeaderMap.delete(reqIdHeader)
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

    /* End Listeners */

    static rbuilderScheme() {
        return {
            sort: 0,
            opts: {
                "title": "",
                "override_headers": true,
                "follow_redirect": true,
                "update_content_length": true,
                "use_content_type": true
            },
            request: {

            },
            response: {
                headers: [],
                statusLine: '',
                statusCode: '',
                body: ''
            }
        }
    }

    static getParsedRaw(request) {
        let raw = ""
        if (request.split(/\r?\n\r?\n/).length > 1)
            raw = request.split(/\r?\n/).join('\r\n')
        else
            raw = request.split(/\r?\n/).concat(['\r\n']).join('\r\n')

        return raw
    }

    static updateRawRequest(schema, params, opts) {
        if (!opts) opts = schema.opts
        else schema.opts = opts

        if (params) {
            let url = params.request_protocol + '://' + params.request_url.replace(/^https?:\/\//, '')
            schema.request.scheme = params.request_protocol
            schema.request.method = params.request_method
            schema.request.url = url
        }

        ptk_request.normalizeHeaders(schema, opts)
        let requestForRaw = schema.request
        if (ptk_request._hasRawUrlencodedParams(schema?.request?.body?.params)) {
            const rawBody = schema.request.body?.text || ptk_request.serializeUrlencodedParams(schema.request.body.params)
            requestForRaw = Object.assign({}, schema.request, {
                body: Object.assign({}, schema.request.body, {
                    text: rawBody,
                    contentType: 'text/plain'
                })
            })
        }
        schema.request.raw = httpZ.build(requestForRaw, opts)
        return schema
    }

    static fingerprintRawRequest(raw) {
        if (!raw) return ''
        try {
            const schema = ptk_request.parseRawRequest(raw)
            const req = schema.request || {}
            const method = (req.method || 'GET').toUpperCase()
            const scheme = req.scheme || (req.request?.scheme) || 'http'
            const baseHost = req.host || req.headers?.find(h => (h.name || '').toLowerCase() === 'host')?.value || 'localhost'
            const needsBase = !(req.url || '').startsWith('http')
            const base = `${scheme}://${baseHost}`
            const urlObj = new URL(req.url || '/', needsBase ? base : undefined)
            const protocol = (urlObj.protocol || 'http:').replace(':', '').toLowerCase()
            const host = (urlObj.host || '').toLowerCase()
            let pathname = urlObj.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            pathname = pathname.replace(/\/+/g, '/')

            const queryNames = new Set()
            if (Array.isArray(req.queryParams)) {
                req.queryParams.forEach(param => {
                    const name = param?.name
                    if (name) queryNames.add(name.toLowerCase())
                })
            } else {
                urlObj.searchParams.forEach((_, key) => queryNames.add(key.toLowerCase()))
            }
            const querySig = Array.from(queryNames).sort().join('&')
            const bodySig = ptk_request._bodyFingerprint(req.body)

            const parts = [
                protocol,
                host,
                pathname,
                method
            ]
            if (querySig) parts.push(`q:${querySig}`)
            if (bodySig) parts.push(`b:${bodySig}`)
            return parts.join('|')
        } catch (err) {
            return ptk_request._fallbackFingerprint(raw)
        }
    }

    static _fallbackFingerprint(raw) {
        try {
            const firstLine = raw.split(/\r?\n/)[0] || ''
            const parts = firstLine.trim().split(/\s+/)
            const method = (parts[0] || 'GET').toUpperCase()
            const urlStr = parts[1] || '/'
            const urlObj = new URL(urlStr, urlStr.startsWith('http') ? undefined : 'http://localhost')
            const host = (urlObj.host || '').toLowerCase()
            let pathname = urlObj.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            pathname = pathname.replace(/\/+/g, '/')
            const queryNames = new Set()
            urlObj.searchParams.forEach((_, key) => queryNames.add(key.toLowerCase()))
            const querySig = Array.from(queryNames).sort().join('&')
            const partsOut = ['http', host, pathname, method]
            if (querySig) partsOut.push(`q:${querySig}`)
            return partsOut.join('|')
        } catch (_) {
            try {
                return raw.split(/\r?\n/)[0]?.trim() || raw
            } catch {
                return raw || ''
            }
        }
    }

    static _bodyFingerprint(body) {
        if (!body) return ''

        if (Array.isArray(body.params) && body.params.length) {
            return body.params
                .map(p => (p?.name || '').toLowerCase())
                .filter(Boolean)
                .sort()
                .join('&')
        }

        if (body.json && typeof body.json === 'object') {
            const jsonPaths = []
            ptk_request._collectJsonPaths(body.json, '', jsonPaths)
            if (jsonPaths.length) {
                return jsonPaths.sort().join('&')
            }
        }

        if (typeof body.text === 'string' && body.text.length) {
            const mime = (body.mimeType || '').toLowerCase()
            const looksForm = mime.includes('application/x-www-form-urlencoded') || /[=&]/.test(body.text)
            if (looksForm) {
                try {
                    const usp = new URLSearchParams(body.text)
                    const keys = Array.from(usp.keys()).map(key => key.toLowerCase())
                    if (keys.length) return keys.sort().join('&')
                } catch { /* ignore malformed urlencoded bodies */ }
            }

            try {
                const json = JSON.parse(body.text)
                const jsonPaths = []
                ptk_request._collectJsonPaths(json, '', jsonPaths)
                if (jsonPaths.length) {
                    return jsonPaths.sort().join('&')
                }
            } catch { /* not json */ }
        }

        return ''
    }

    static _collectJsonPaths(value, prefix, acc) {
        if (value === null || value === undefined) {
            if (prefix) acc.push(prefix)
            return
        }
        if (Array.isArray(value)) {
            value.forEach((item, index) => {
                const next = prefix ? `${prefix}[${index}]` : `[${index}]`
                if (item !== null && typeof item === 'object') {
                    ptk_request._collectJsonPaths(item, next, acc)
                } else {
                    acc.push(next)
                }
            })
            return
        }
        if (typeof value === 'object') {
            const keys = Object.keys(value)
            if (!keys.length) {
                if (prefix) acc.push(prefix)
                return
            }
            keys.forEach(key => {
                const next = prefix ? `${prefix}.${key}` : key
                const item = value[key]
                if (item !== null && typeof item === 'object') {
                    ptk_request._collectJsonPaths(item, next, acc)
                } else {
                    acc.push(next)
                }
            })
            return
        }
        if (prefix) acc.push(prefix)
    }

    static parseRawRequest(raw, opts) {
        let schema = ptk_request.rbuilderScheme()
        if (!opts) opts = schema.opts
        else schema.opts = opts

        schema.request = Object.assign(httpZ.parse(ptk_request.getParsedRaw(raw), opts))
        schema.request.scheme = schema.request.url.startsWith('https://') ? 'https' : 'http'

        // Backfill legacy request shape fields expected by many module conditions.
        // Some parser paths populate url/method but omit target/path; derive them
        // deterministically from URL to preserve compatibility.
        try {
            const parsedUrl = new URL(schema.request.url)
            const pathname = parsedUrl.pathname || '/'
            const target = `${pathname}${parsedUrl.search || ''}`
            if (!schema.request.path) {
                schema.request.path = pathname
            }
            if (!schema.request.target) {
                schema.request.target = target
            }
        } catch (_) {
            if (!schema.request.path && typeof schema.request.target === 'string') {
                schema.request.path = schema.request.target.split('?')[0] || '/'
            }
            if (!schema.request.target && typeof schema.request.path === 'string') {
                schema.request.target = schema.request.path
            }
        }

        ptk_request.normalizeHeaders(schema, opts)
        schema.request.raw = httpZ.build(schema.request, opts)
        const urlForParams = opts?.ui_url || schema.request.url
        const params = getSearchParamsFromUrlOrHash(urlForParams)
        schema.request.queryParams = []
        params.forEach((value, name) => {
            schema.request.queryParams.push({ name, value })
        })
        schema.request.ui_url = urlForParams
        return schema
    }


    static normalizeHeaders(schema, opts) {
        //Cache - no-cache
        let cacheControl = schema.request.headers.findIndex(obj => { return obj.name.toLowerCase() == "cache-control" });
        if (cacheControl == -1) {
            schema.request.headers.push({
                "name": "Cache-Control",
                "value": "no-cache"
            })
        } else {
            schema.request.headers[cacheControl].value = "no-cache"
        }

        let pragmaControl = schema.request.headers.findIndex(obj => { return obj.name.toLowerCase() == "pragma" });
        if (pragmaControl == -1) {
            schema.request.headers.push({
                "name": "Pragma",
                "value": "no-cache"
            })
        } else {
            schema.request.headers[pragmaControl].value = "no-cache"
        }

        //Host header
        if (schema.request.host == 'unspecified-host') {
            try {
                let url = new URL(schema.request.url)
                schema.request.host = url.host
            } catch (e) {
                throw new Error('Host header not defined. Use an absolute URL or add "Host" header.')
            }
        }
        if (schema.request.headers.findIndex(x => x.name.toLowerCase() == 'host') < 0) {
            schema.request.headers.push({ name: 'Host', value: schema.request.host })
        }



        //Content-Length - FF fix
        const transportMode = String(opts?.transport_mode || '').toLowerCase()
        if (transportMode !== 'smuggling_h1' && opts?.update_content_length != false) {
            if (["POST", "PUT", "DELETE", "PATCH"].includes(schema.request.method)) {
                let contentLengthIndex = schema.request.headers.findIndex(obj => { return obj.name.toLowerCase() == "content-length" })
                let contentLengthVal = 0
                if (schema.request.body?.params) {
                    const encodedBody = ptk_request._isMultipartBody(schema.request.body)
                        ? ptk_request.serializeMultipartParams(schema.request.body.params, schema.request.body.boundary)
                        : (
                            ptk_request._hasRawUrlencodedParams(schema.request.body.params)
                                ? ptk_request.serializeUrlencodedParams(schema.request.body.params)
                                : (new URLSearchParams(schema.request.body.params.map(x => `${x.name}=${x.value}`).join('&'))).toString()
                        )
                    schema.request.bodySize = encodedBody.length
                    contentLengthVal = encodedBody.length
                } else if (schema.request.body?.text) {
                    contentLengthVal = schema.request.body.text.toString().length
                }
                schema.request.bodySize = contentLengthVal
                if (contentLengthIndex < 0) {
                    schema.request.headers.push({
                        "name": "Content-Length",
                        "value": contentLengthVal.toString()
                    })
                } else {
                    schema.request.headers[contentLengthIndex].value = contentLengthVal.toString()
                }
            }
        }

    }

    async sendRequest(schema) {
        const shouldUseTrackingListeners = this.useListeners || this.trackWithListeners
        if (shouldUseTrackingListeners) this.addListeners()
        // ptk_ruleManager.getDynamicRules()
        // ptk_ruleManager.getSessionRules()
        let ruleId = null
        this.trackingRequest = new Map()

        const headerList = schema.request.headers || []
        const transportMode = String(schema?.opts?.transport_mode || '').toLowerCase()
        const isSmugglingH1 = transportMode === 'smuggling_h1'
        const overrideHeaders = schema.opts.override_headers != false
        // Listener-based header override replaces the full header list in Firefox.
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
            // Prevent browser cookies from leaking when request doesn't specify Cookie.
            effectiveCredentials = 'omit'
        }

        // Strip cache validators for active requests.
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

        // Ensure Cookie header is explicit when cookies are present.
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

        // Attach request id header for tracking correlation.
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
            ptk_request._storedHeaderMap.set(ptkReqId, {
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
        const getHeaderValue = (headers, name) => {
            const target = name.toLowerCase()
            return (headers || []).find((h) => (h?.name || '').toLowerCase() === target)?.value || ''
        }
        const logFingerprint = schema?.opts?.log_fingerprint === true
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
                preparedBody = ptk_request._isMultipartBody(schema.request.body)
                    ? ptk_request.serializeMultipartParams(schema.request.body.params, schema.request.body.boundary)
                    : (
                        ptk_request._hasRawUrlencodedParams(schema.request.body.params)
                            ? ptk_request.serializeUrlencodedParams(schema.request.body.params)
                            : new URLSearchParams(schema.request.body.params.map(x => `${x.name}=${x.value}`).join('&')).toString()
                    )
                // keep schema in sync so future mutations operate on text
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
            const isJwt1 = schema?.metadata?.id === 'jwt_1'
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
                            rbSchema.response.headers = trackingRequest.response.responseHeaders
                            rbSchema.response.statusLine = trackingRequest.response.statusLine
                            rbSchema.response.statusCode = trackingRequest.response.statusCode
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
                self.trackingRequest = null
                if (shouldUseTrackingListeners) self.removeListeners()
                if (ruleId) {
                    await ptk_ruleManager.removeSessionRule(ruleId)
                }
            }
        }

        if (useDnr) {
            return ptk_request._withDnrLock(runRequest)
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
