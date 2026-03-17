(() => {
    if (window.__ptkSpaJsHookInstalled) return
    window.__ptkSpaJsHookInstalled = true

    const leakMarkerKey = '__ptkLeakMarker__'
    const setLeakMarker = (val) => { try { window[leakMarkerKey] = val } catch (_) { } }

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
        if (marker && hasMarker(marker, url)) {
            notifyLeak(marker, 'url', url, 'FETCH')
        }
        return origFetch.apply(this, arguments)
    }

    const OrigXHR = window.XMLHttpRequest
    function PatchedXHR() {
        const xhr = new OrigXHR()
        let _url = ''
        let _method = ''
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
        const origSend = xhr.send
        xhr.send = function (body) {
            const markerVal = window[leakMarkerKey]
            if (markerVal && hasMarker(markerVal, body)) {
                notifyLeak(markerVal, 'body', _url, _method)
            }
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
