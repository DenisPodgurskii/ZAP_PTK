(() => {
    if (window.__ptkSpaJsHookInstalled) return
    window.__ptkSpaJsHookInstalled = true

    const leakMarkerKey = '__ptkLeakMarker__'
    const setLeakMarker = (val) => { try { window[leakMarkerKey] = val } catch (_) { } }
    const notifyNetwork = (event) => {
        try {
            window.postMessage({ source: 'ptk-spa-net', event }, '*')
        } catch (_) { }
    }
    const normalizeHeadersObject = (headersLike) => {
        const out = {}
        try {
            if (headersLike && typeof headersLike.forEach === 'function') {
                headersLike.forEach((value, key) => {
                    out[String(key).toLowerCase()] = String(value)
                })
                return out
            }
            if (Array.isArray(headersLike)) {
                headersLike.forEach((entry) => {
                    const key = entry?.name || entry?.key
                    if (!key) return
                    out[String(key).toLowerCase()] = String(entry?.value ?? '')
                })
                return out
            }
            if (headersLike && typeof headersLike === 'object') {
                Object.entries(headersLike).forEach(([key, value]) => {
                    out[String(key).toLowerCase()] = String(value ?? '')
                })
            }
        } catch (_) { }
        return out
    }
    const previewBody = (body) => {
        if (body == null) return null
        try {
            if (typeof body === 'string') return body.slice(0, 1024)
            if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
                return body.toString().slice(0, 1024)
            }
            if (typeof FormData !== 'undefined' && body instanceof FormData) {
                const entries = []
                for (const [key, value] of body.entries()) {
                    entries.push(`${key}=${typeof value === 'string' ? value : '[file]'}`)
                    if (entries.length >= 20) break
                }
                return entries.join('&').slice(0, 1024)
            }
            return JSON.stringify(body).slice(0, 1024)
        } catch (_) {
            return null
        }
    }
    const buildFetchMeta = (resource, init = {}) => {
        let url = ''
        let method = 'GET'
        let credentials = init?.credentials || null
        let headers = normalizeHeadersObject(init?.headers || null)
        let bodyPreview = previewBody(init?.body)
        try {
            if (typeof Request !== 'undefined' && resource instanceof Request) {
                url = resource.url || url
                method = resource.method || method
                credentials = credentials || resource.credentials || null
                headers = Object.assign({}, normalizeHeadersObject(resource.headers), headers)
            } else if (typeof resource === 'string' || resource instanceof URL) {
                url = String(resource)
            } else if (resource && typeof resource === 'object' && resource.url) {
                url = String(resource.url)
                method = resource.method || method
                credentials = credentials || resource.credentials || null
                headers = Object.assign({}, normalizeHeadersObject(resource.headers), headers)
            }
        } catch (_) { }
        method = String(init?.method || method || 'GET').toUpperCase()
        return {
            kind: 'fetch',
            url,
            method,
            credentials: credentials || null,
            requestHeaders: headers,
            bodyPreview
        }
    }

    try {
        const originalEval = window.eval
        window.eval = function (str) {
            try {
                window.postMessage({ source: 'ptk-spa', sink: 'eval', code: String(str) }, '*')
            } catch (_) { }
            return originalEval.apply(this, arguments)
        }

        const OriginalFunction = window.Function
        window.Function = function (...args) {
            try {
                const body = args[args.length - 1]
                window.postMessage({ source: 'ptk-spa', sink: 'Function', code: String(body) }, '*')
            } catch (_) { }
            return OriginalFunction.apply(this, args)
        }

        const originalSetTimeout = window.setTimeout
        window.setTimeout = function (handler, timeout, ...rest) {
            if (typeof handler === 'string') {
                try {
                    window.postMessage({ source: 'ptk-spa', sink: 'setTimeout', code: String(handler) }, '*')
                } catch (_) { }
            }
            return originalSetTimeout(handler, timeout, ...rest)
        }

        const originalSetInterval = window.setInterval
        window.setInterval = function (handler, timeout, ...rest) {
            if (typeof handler === 'string') {
                try {
                    window.postMessage({ source: 'ptk-spa', sink: 'setInterval', code: String(handler) }, '*')
                } catch (_) { }
            }
            return originalSetInterval(handler, timeout, ...rest)
        }
    } catch (_) { }

    // Leak detection for fetch / XHR
    const notifyLeak = (marker, location, requestUrl, method) => {
        try {
            const host = new URL(requestUrl, window.location.href).host || ''
            window.postMessage({ source: 'ptk-leak', marker, location, requestUrl, method, host }, '*')
        } catch (_) {
            window.postMessage({ source: 'ptk-leak', marker, location, requestUrl, method }, '*')
        }
    }

    const hasMarker = (marker, str) => {
        if (!marker || !str) return false
        return String(str).includes(marker)
    }

    const origFetch = window.fetch
    window.fetch = function () {
        const marker = window[leakMarkerKey]
        const url = arguments[0]
        const init = arguments[1] || {}
        const meta = buildFetchMeta(url, init)
        if (marker && hasMarker(marker, url)) {
            notifyLeak(marker, 'url', url, 'FETCH')
        }
        return origFetch.apply(this, arguments).then((response) => {
            notifyNetwork(Object.assign({}, meta, {
                responseUrl: response?.url || meta.url,
                responseStatus: response?.status ?? null,
                responseHeaders: normalizeHeadersObject(response?.headers || null)
            }))
            return response
        }).catch((error) => {
            notifyNetwork(Object.assign({}, meta, {
                error: error?.message || String(error || 'fetch_failed')
            }))
            throw error
        })
    }

    const OrigXHR = window.XMLHttpRequest
    function PatchedXHR() {
        const xhr = new OrigXHR()
        let _url = ''
        let _method = ''
        let _headers = {}
        let _bodyPreview = null
        const origOpen = xhr.open
        xhr.open = function (method, url) {
            _method = method || ''
            _url = url || ''
            const marker = window[leakMarkerKey]
            if (marker && hasMarker(marker, url)) {
                notifyLeak(marker, 'url', url, method)
            }
            return origOpen.apply(xhr, arguments)
        }
        const origSetRequestHeader = xhr.setRequestHeader
        xhr.setRequestHeader = function (name, value) {
            try {
                _headers[String(name || '').toLowerCase()] = String(value ?? '')
            } catch (_) { }
            return origSetRequestHeader.apply(xhr, arguments)
        }
        const origSend = xhr.send
        xhr.send = function (body) {
            const markerVal = window[leakMarkerKey]
            _bodyPreview = previewBody(body)
            if (markerVal && hasMarker(markerVal, body)) {
                notifyLeak(markerVal, 'body', _url, _method)
            }
            xhr.addEventListener('loadend', () => {
                const responseHeaders = {}
                try {
                    const rawHeaders = String(xhr.getAllResponseHeaders?.() || '')
                    rawHeaders.split(/\r?\n/).forEach((line) => {
                        const idx = line.indexOf(':')
                        if (idx <= 0) return
                        const key = line.slice(0, idx).trim().toLowerCase()
                        const value = line.slice(idx + 1).trim()
                        if (!key) return
                        responseHeaders[key] = value
                    })
                } catch (_) { }
                notifyNetwork({
                    kind: 'xhr',
                    url: _url,
                    method: String(_method || 'GET').toUpperCase(),
                    credentials: xhr.withCredentials === true ? 'include' : 'same-origin',
                    requestHeaders: Object.assign({}, _headers),
                    bodyPreview: _bodyPreview,
                    responseUrl: xhr.responseURL || _url,
                    responseStatus: xhr.status || null,
                    responseHeaders
                })
            }, { once: true })
            return origSend.apply(xhr, arguments)
        }
        return xhr
    }
    window.XMLHttpRequest = PatchedXHR

    window.addEventListener('message', (ev) => {
        const data = ev.data || {}
        if (data && data.source === 'ptk-leak-set' && typeof data.marker === 'string') {
            setLeakMarker(data.marker)
        }
    })
})()
