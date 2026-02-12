/* Author: PTK */

if (!window.__ptkSpaHarnessLoaded) {
    window.__ptkSpaHarnessLoaded = true

const spaJsEvents = []
const xssExecutionEvents = []
const leakEvents = []
let hookInjected = false

function injectSpaJsHook() {
    if (hookInjected) return
    hookInjected = true
    try {
        const s = document.createElement('script')
        s.src = browser.runtime.getURL('ptk/content/spa_hash_hook.js')
        s.async = false
        ; (document.documentElement || document.head || document.body).appendChild(s)
        s.onload = () => { try { s.remove() } catch (_) { } }
    } catch (_) { hookInjected = false }
}

function detectDomXss(marker) {
    if (!marker) return null
    const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
        null
    )
    let node
    while ((node = walker.nextNode())) {
        if (node.nodeType === Node.TEXT_NODE) {
            if (node.nodeValue && node.nodeValue.includes(marker)) {
                return {
                    type: 'text',
                    snippet: node.nodeValue.slice(0, 200)
                }
            }
        } else if (node.nodeType === Node.ELEMENT_NODE) {
            for (const attr of node.attributes) {
                if (attr.value && attr.value.includes(marker)) {
                    return {
                        type: 'attribute',
                        tag: node.tagName.toLowerCase(),
                        attr: attr.name,
                        snippet: attr.value.slice(0, 200)
                    }
                }
            }
        }
    }
    return null
}

async function setHashParam(param, payload) {
    const url = new URL(window.location.href)

    let hash = url.hash || '#/'
    if (!hash.startsWith('#')) hash = '#' + hash

    const hashWithoutHash = hash.substring(1)
    const qIdx = hashWithoutHash.indexOf('?')
    let basePath = hashWithoutHash
    let query = ''

    if (qIdx !== -1) {
        basePath = hashWithoutHash.substring(0, qIdx)
        query = hashWithoutHash.substring(qIdx + 1)
    }

    const params = new URLSearchParams(query)
    params.set(param, payload)

    const newHash = basePath + '?' + params.toString()

    window.location.hash = newHash

    await new Promise(r => setTimeout(r, 500))
}

window.addEventListener('message', (event) => {
    if (event.source !== window) return
    const data = event.data || {}
    if (data.source === 'ptk-spa' && data.sink) {
        spaJsEvents.push({
            sink: data.sink,
            code: data.code,
            ts: Date.now()
        })
        if (spaJsEvents.length > 50) spaJsEvents.shift()
    }
    if (data && data.source === 'ptk-xss' && typeof data.id === 'string') {
        xssExecutionEvents.push({ id: data.id, ts: Date.now() })
        if (xssExecutionEvents.length > 50) xssExecutionEvents.shift()
    }
    if (data && data.source === 'ptk-leak' && data.marker && data.location) {
        leakEvents.push({
            marker: data.marker,
            location: data.location,
            requestUrl: data.requestUrl || '',
            method: data.method || '',
            host: data.host || '',
            ts: Date.now()
        })
        if (leakEvents.length > 50) leakEvents.shift()
    }
})

function detectContextType(el, attrName) {
    if (!attrName) return 'attribute'
    const lower = attrName.toLowerCase()
    if (lower.startsWith('on')) return 'attribute_event_handler'
    if (['href', 'src', 'action', 'formaction'].includes(lower)) return 'attribute_url'
    return 'attribute'
}

function computeCssPath(el) {
    if (!el || el.nodeType !== Node.ELEMENT_NODE) return ''
    const path = []
    let current = el
    while (current && current.nodeType === Node.ELEMENT_NODE && path.length < 8) {
        let selector = current.nodeName.toLowerCase()
        if (current.id) {
            selector += `#${current.id}`
            path.unshift(selector)
            break
        } else {
            const siblingIndex = Array.prototype.indexOf.call(current.parentNode ? current.parentNode.children : [], current) + 1
            selector += `:nth-child(${siblingIndex || 1})`
        }
        path.unshift(selector)
        current = current.parentElement
    }
    return path.join(' > ')
}

function simpleHash(str) {
    if (!str) return ''
    let hash = 0
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i)
        hash |= 0
    }
    return String(hash)
}

function detectDomReflection(marker) {
    if (!marker) return null

    const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
        null
    )

    let node
    while ((node = walker.nextNode())) {
        if (node.nodeType === Node.TEXT_NODE) {
            if (node.nodeValue && node.nodeValue.includes(marker)) {
                return {
                    type: 'text',
                    tag: null,
                    attr: null,
                    outerHTML: null,
                    cssPath: computeCssPath(node.parentElement),
                    snippet: node.nodeValue.slice(0, 200)
                }
            }
        } else if (node.nodeType === Node.ELEMENT_NODE) {
            for (const attr of node.attributes) {
                if (attr.value && attr.value.includes(marker)) {
                    const el = node
                    return {
                        type: detectContextType(el, attr.name),
                        tag: el.tagName.toLowerCase(),
                        attr: attr.name,
                        outerHTML: el.outerHTML ? el.outerHTML.slice(0, 512) : null,
                        cssPath: computeCssPath(el),
                        snippet: attr.value.slice(0, 200)
                    }
                }
            }
        }
    }
    return null
}

function buildSinkKey(context) {
    if (!context) return null
    const parts = [
        context.type || '',
        context.tag || '',
        context.attr || '',
        context.cssPath || '',
        context.outerHTML ? simpleHash(context.outerHTML) : ''
    ]
    return parts.join('|')
}

async function runSpaParamTest({ param, payload, checks = [], markerDomain, markerToken }) {
    try {
        injectSpaJsHook()

        const originalHref = window.location.href
        const originalHostname = window.location.hostname
        const originalHash = window.location.hash

        spaJsEvents.length = 0
        xssExecutionEvents.length = 0
        leakEvents.length = 0

        const effectiveMarker = markerToken || payload

        const snapshotStorage = () => {
            const snap = { local: {}, session: {} }
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i)
                    if (!k || /^ptk_/i.test(k)) continue
                    snap.local[k] = localStorage.getItem(k)
                }
            } catch (_) { }
            try {
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i)
                    if (!k || /^ptk_/i.test(k)) continue
                    snap.session[k] = sessionStorage.getItem(k)
                }
            } catch (_) { }
            return snap
        }

        let storageBefore = null
        if (checks.includes('client_storage_leak')) {
            storageBefore = snapshotStorage()
        }

        if (checks.includes('token_leak_third_party') && effectiveMarker) {
            try {
                window.postMessage({ source: 'ptk-leak-set', marker: effectiveMarker }, '*')
            } catch (_) { }
        }

        await setHashParam(param, payload)
        const expectedHref = window.location.href

        await new Promise(r => setTimeout(r, 800))

        const result = {}

        if (checks.includes('dom_xss')) {
            const context = detectDomReflection(effectiveMarker)
            const sinkKey = buildSinkKey(context)
            const executed = xssExecutionEvents.some(ev => ev.id === effectiveMarker)
            result.dom_xss = {
                vulnerable: !!context,
                reflected: !!context,
                executed: !!executed,
                sinkKey: sinkKey || null,
                context: context || undefined
            }
        }

        if (checks.includes('dom_redirect')) {
            const currentHref = window.location.href
            const currentHostname = window.location.hostname
            const changedHost = currentHostname !== originalHostname
            const matchesMarkerDomain = markerDomain && currentHref.includes(markerDomain)
            const redirected = changedHost || (matchesMarkerDomain && currentHref !== expectedHref)

            result.dom_redirect = redirected
                ? { vulnerable: true, evidence: { originalHref, expectedHref, currentHref } }
                : { vulnerable: false }
        }

        if (checks.includes('js_injection')) {
            const event = spaJsEvents.find(ev => ev.code && ev.code.includes(effectiveMarker))
            result.js_injection = event
                ? { vulnerable: true, evidence: { sink: event.sink, codeSnippet: event.code.slice(0, 200) } }
                : { vulnerable: false }
        }

        if (checks.includes('token_in_fragment')) {
            const fragParams = new URLSearchParams((window.location.hash || '').replace(/^#/, '').split('?')[1] || '')
            const tokens = []
            const tokenNames = ['access_token', 'id_token', 'token', 'auth', 'jwt']
            const looksJwt = (v) => /^ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$/.test(v)
            const looksLong = (v) => v && v.length >= 24
            for (const [k, v] of fragParams.entries()) {
                const preview = v.slice(0, 80)
                if (tokenNames.includes(k.toLowerCase()) || looksJwt(v) || looksLong(v)) {
                    tokens.push({ name: k, preview })
                }
            }
            result.token_in_fragment = {
                vulnerable: tokens.length > 0,
                tokens: tokens.slice(0, 10)
            }
        }

        if (checks.includes('token_leak_third_party')) {
            const leak = leakEvents.find(ev => ev.marker === effectiveMarker)
            result.token_leak_third_party = leak ? {
                vulnerable: true,
                evidence: {
                    requestUrl: leak.requestUrl,
                    location: leak.location,
                    host: leak.host,
                    method: leak.method
                }
            } : { vulnerable: false }
        }

        if (checks.includes('postmessage')) {
            try {
                window.postMessage({ source: 'ptk-pmtest', marker: effectiveMarker }, '*')
            } catch (_) { }
        }

        if (checks.includes('client_storage_leak')) {
            const storageAfter = snapshotStorage()
            const leaks = []
            const recordDiff = (storage, name) => {
                Object.keys(storage || {}).forEach(k => {
                    const before = storageBefore?.[name]?.[k]
                    const after = storageAfter?.[name]?.[k]
                    if (before !== after && after) {
                        if ((markerToken && after.includes(markerToken)) || /eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*/.test(after) || after.length >= 24) {
                            leaks.push({ storage: name, key: k, preview: after.slice(0, 80) })
                        }
                    }
                })
            }
            recordDiff(storageAfter?.local, 'local')
            recordDiff(storageAfter?.session, 'session')
            result.client_storage_leak = {
                vulnerable: leaks.length > 0,
                entries: leaks.slice(0, 5)
            }
        }

        if (checks.includes('spa_sensitive_data')) {
            const matches = []
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null)
            const seen = new Set()
            const addMatch = (type, val) => {
                if (seen.has(val)) return
                seen.add(val)
                matches.push({ type, preview: val.slice(0, 100) })
            }
            const emailRe = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/
            const jwtRe = /eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*/
            const tokenRe = /[A-Za-z0-9_\-]{24,}/
            let node
            while ((node = walker.nextNode()) && matches.length < 10) {
                const text = node.nodeValue || ''
                const email = text.match(emailRe)
                if (email) addMatch('email', email[0])
                const jwtm = text.match(jwtRe)
                if (jwtm) addMatch('jwt', jwtm[0])
                const tok = text.match(tokenRe)
                if (tok) addMatch('token', tok[0])
            }
            result.spa_sensitive_data = {
                vulnerable: matches.length > 0,
                matches
            }
        }

        try {
            window.location.hash = originalHash
        } catch (_) { }

        return result
    } catch (e) {
        return { error: e && e.message }
    }
}

const spaRuntime = (typeof browser !== 'undefined' && browser.runtime)
    ? browser.runtime
    : ((typeof chrome !== 'undefined' && chrome.runtime) ? chrome.runtime : null)

if (spaRuntime?.onMessage?.addListener) {
    spaRuntime.onMessage.addListener((msg, sender, sendResponse) => {
        if (msg?.type === 'spaPing') {
            if (sendResponse) sendResponse({ ok: true })
            return false
        }
        if (msg?.type === 'spaParamTest') {
            Promise.resolve()
                .then(() => runSpaParamTest(msg))
                .then(result => {
                    if (sendResponse) sendResponse(result)
                })
                .catch(err => {
                    const message = err && err.message ? err.message : String(err || 'unknown error')
                    if (sendResponse) sendResponse({ error: message })
                })
            return true
        }
    })
}
}
