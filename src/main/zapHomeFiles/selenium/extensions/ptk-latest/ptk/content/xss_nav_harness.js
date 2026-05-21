/* Author: PTK */

if (!window.__ptkBrowserNavHarnessLoaded) {
    window.__ptkBrowserNavHarnessLoaded = true

    const ATTACK_TAB_MARKER = 'ptk_browser_nav_attack_tab'
    const xssExecutionEvents = []

    function isAttackTab() {
        try {
            return String(window.name || '').includes(ATTACK_TAB_MARKER)
        } catch (_) {
            return false
        }
    }

    function sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms))
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
            }
            const siblingIndex = Array.prototype.indexOf.call(current.parentNode ? current.parentNode.children : [], current) + 1
            selector += `:nth-child(${siblingIndex || 1})`
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

    function buildSinkKey(context) {
        if (!context) return null
        const parts = [
            context.type || '',
            context.sourceDriver || '',
            context.sourceKey || '',
            context.tag || '',
            context.attr || '',
            context.cssPath || '',
            context.outerHTML ? simpleHash(context.outerHTML) : ''
        ]
        return parts.join('|')
    }

    function attributeContextType(attrName) {
        const lower = String(attrName || '').toLowerCase()
        if (lower.startsWith('on')) return 'attribute_event_handler'
        if (lower === 'srcdoc') return 'attribute_srcdoc'
        if (['href', 'src', 'action', 'formaction'].includes(lower)) return 'attribute_url'
        if (lower === 'style') return 'attribute_style'
        return null
    }

    function publicContext(context) {
        if (!context) return undefined
        const { node, ...safeContext } = context
        return safeContext
    }

    function detectDomReflection(marker) {
        const root = document.documentElement || document.body
        if (!marker || !root) return null

        const walker = document.createTreeWalker(
            root,
            NodeFilter.SHOW_ELEMENT,
            null
        )

        let node
        while ((node = walker.nextNode())) {
            if (node.nodeType !== Node.ELEMENT_NODE) continue

            for (const attr of Array.from(node.attributes || [])) {
                if (!attr?.value || !String(attr.value).includes(marker)) continue
                const type = attributeContextType(attr.name)
                if (!type) continue
                return {
                    node,
                    type,
                    tag: node.tagName.toLowerCase(),
                    attr: attr.name,
                    outerHTML: node.outerHTML ? node.outerHTML.slice(0, 512) : null,
                    cssPath: computeCssPath(node),
                    snippet: String(attr.value).slice(0, 200)
                }
            }

            if (node.tagName && node.tagName.toLowerCase() === 'script') {
                const text = String(node.textContent || '')
                if (text.includes(marker)) {
                    return {
                        node,
                        type: 'script_text',
                        tag: 'script',
                        attr: null,
                        outerHTML: node.outerHTML ? node.outerHTML.slice(0, 512) : null,
                        cssPath: computeCssPath(node),
                        snippet: text.slice(0, 200)
                    }
                }
            }
        }

        return null
    }

    async function exerciseExecutableContext(context) {
        const node = context?.node
        if (!node || node.nodeType !== Node.ELEMENT_NODE) return
        const type = context.type || ''
        const attr = String(context.attr || '').toLowerCase()
        try {
            if (type === 'attribute_event_handler') {
                const authoredEvent = attr.startsWith('on') ? attr.slice(2) : ''
                const events = Array.from(new Set([
                    authoredEvent,
                    'mouseover',
                    'mouseenter',
                    'mousemove',
                    'pointerover',
                    'load',
                    'error'
                ].filter(Boolean)))
                for (const eventName of events) {
                    if (/^(?:mouse|pointer|click)/i.test(eventName)) {
                        node.dispatchEvent(new MouseEvent(eventName, {
                            bubbles: true,
                            cancelable: true,
                            view: window
                        }))
                    } else {
                        node.dispatchEvent(new Event(eventName, {
                            bubbles: true,
                            cancelable: true
                        }))
                    }
                }
                await sleep(50)
                return
            }
            if (type === 'attribute_url' && attr === 'href') {
                const href = String(node.getAttribute('href') || '')
                if (/^\s*javascript:/i.test(href) && typeof node.click === 'function') {
                    node.click()
                    await sleep(75)
                }
            }
        } catch (_) { }
    }

    function recordExecutionMarker(id) {
        const markerId = String(id || '').trim()
        if (!markerId) return
        xssExecutionEvents.push({ id: markerId, ts: Date.now() })
        if (xssExecutionEvents.length > 50) xssExecutionEvents.shift()
    }

    function recordWindowNameExecutionMarker(markerToken) {
        const markerId = String(markerToken || '').trim()
        if (!markerId) return
        try {
            const nameValue = String(window.name || '')
            if (nameValue.includes(`ptk-xss:${markerId}`)) {
                recordExecutionMarker(markerId)
            }
        } catch (_) { }
    }

    function injectMainWorldWindowNameProbe(markerToken) {
        const markerId = String(markerToken || '').trim()
        if (!markerId) return false
        try {
            const doc = document
            const root = doc?.documentElement || doc?.head || doc?.body
            if (!doc?.createElement || !root?.appendChild) return false
            const script = doc.createElement('script')
            const markerJson = JSON.stringify(markerId)
            const tokenJson = JSON.stringify(`ptk-xss:${markerId}`)
            script.textContent = [
                'try{',
                `var t=${tokenJson};`,
                `if(String(window.name||'').indexOf(t)!==-1){window.postMessage({source:'ptk-xss',id:${markerJson}},'*');}`,
                '}catch(_){}'
            ].join('')
            root.appendChild(script)
            if (typeof script.remove === 'function') script.remove()
            else if (script.parentNode && typeof script.parentNode.removeChild === 'function') script.parentNode.removeChild(script)
            return true
        } catch (_) {
            return false
        }
    }

    async function probeWindowNameExecutionMarker(markerToken) {
        const markerId = String(markerToken || '').trim()
        if (!markerId) return
        recordWindowNameExecutionMarker(markerId)
        if (xssExecutionEvents.some((event) => event.id === markerId)) return
        if (injectMainWorldWindowNameProbe(markerId)) {
            await sleep(25)
            recordWindowNameExecutionMarker(markerId)
        }
    }

    window.addEventListener('message', (event) => {
        if (event.source !== window) return
        const data = event.data || {}
        if (data && data.source === 'ptk-xss' && typeof data.id === 'string') {
            recordExecutionMarker(data.id)
            return
        }
        if (typeof data === 'string' && data.startsWith('ptk-xss:')) {
            recordExecutionMarker(data.slice('ptk-xss:'.length))
        }
    })

    async function waitForPageSettled(waitMs) {
        const bounded = Math.max(0, Math.min(5000, Number(waitMs) || 0))
        if (document.readyState === 'complete') {
            if (bounded > 0) await sleep(bounded)
            return
        }
        await new Promise((resolve) => {
            let done = false
            const finish = async () => {
                if (done) return
                done = true
                if (bounded > 0) await sleep(bounded)
                resolve()
            }
            window.addEventListener('load', () => { finish() }, { once: true })
            setTimeout(() => { finish() }, Math.max(1500, bounded + 250))
        })
    }

    async function runBrowserNavTest({ markerToken, checks = [], settleMs = 0 } = {}) {
        if (!isAttackTab()) {
            return { error: 'not_attack_tab' }
        }

        await waitForPageSettled(settleMs)
        const normalizedChecks = Array.isArray(checks) && checks.length ? checks : ['dom_xss']
        const result = {}

        if (normalizedChecks.includes('dom_xss')) {
            const context = detectDomReflection(markerToken)
            if (context) {
                await exerciseExecutableContext(context)
            }
            await probeWindowNameExecutionMarker(markerToken)
            const executed = xssExecutionEvents.some((event) => event.id === markerToken)
            const reflected = !!context
            result.dom_xss = {
                vulnerable: !!executed,
                executed: !!executed,
                reflected,
                sinkKey: buildSinkKey(context),
                context: publicContext(context)
            }
        }

        return result
    }

    function normalizedSourceDrivers(values = []) {
        const allowed = new Set(['cookie', 'localStorage', 'sessionStorage', 'form'])
        return Array.from(new Set(
            (Array.isArray(values) ? values : [values])
                .map((value) => String(value || '').trim())
                .filter((value) => allowed.has(value))
        ))
    }

    function parseCookies() {
        const out = {}
        const raw = String(document.cookie || '')
        if (!raw) return out
        for (const part of raw.split(';')) {
            const idx = part.indexOf('=')
            const name = (idx >= 0 ? part.slice(0, idx) : part).trim()
            if (!name) continue
            const value = idx >= 0 ? part.slice(idx + 1).trim() : ''
            try {
                out[decodeURIComponent(name)] = value
            } catch (_) {
                out[name] = value
            }
        }
        return out
    }

    function rawCookieValueSafe(value) {
        return !/[;\r\n\u0000]/.test(String(value == null ? '' : value))
    }

    function setCookie(name, value, options = {}) {
        const normalizedName = encodeURIComponent(name)
        const normalizedValue = value == null ? '' : String(value)
        if (options?.encoding === 'raw-first' && rawCookieValueSafe(normalizedValue)) {
            try {
                document.cookie = `${normalizedName}=${normalizedValue}; SameSite=Lax`
                if (parseCookies()[name] === normalizedValue) {
                    return
                }
            } catch (_) { }
        }
        document.cookie = `${normalizedName}=${encodeURIComponent(normalizedValue)}; SameSite=Lax`
    }

    function deleteCookie(name) {
        document.cookie = `${encodeURIComponent(name)}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax`
        document.cookie = `${encodeURIComponent(name)}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax`
    }

    function snapshotStorage(storage) {
        const values = {}
        try {
            for (let i = 0; i < storage.length; i += 1) {
                const key = storage.key(i)
                if (key == null) continue
                values[String(key)] = storage.getItem(key)
            }
        } catch (_) { }
        return values
    }

    function sourceSnapshot(drivers = []) {
        if (!isAttackTab()) {
            return { error: 'not_attack_tab' }
        }
        const sources = {}
        for (const driver of normalizedSourceDrivers(drivers)) {
            if (driver === 'cookie') {
                const values = parseCookies()
                sources.cookie = {
                    keys: Object.keys(values),
                    values
                }
            } else if (driver === 'localStorage') {
                const values = snapshotStorage(window.localStorage)
                sources.localStorage = {
                    keys: Object.keys(values),
                    values
                }
            } else if (driver === 'sessionStorage') {
                const values = snapshotStorage(window.sessionStorage)
                sources.sessionStorage = {
                    keys: Object.keys(values),
                    values
                }
            }
        }
        return { ok: true, sources }
    }

    function applySourceValue({ driver, key, value, cookieEncoding } = {}) {
        if (!isAttackTab()) {
            return { error: 'not_attack_tab' }
        }
        const sourceDriver = String(driver || '').trim()
        const sourceKey = String(key || '').trim()
        if (!sourceDriver || !sourceKey) return { error: 'missing_source' }
        try {
            if (sourceDriver === 'cookie') {
                setCookie(sourceKey, value, { encoding: cookieEncoding })
                return { ok: true }
            }
            if (sourceDriver === 'localStorage') {
                window.localStorage.setItem(sourceKey, value == null ? '' : String(value))
                return { ok: true }
            }
            if (sourceDriver === 'sessionStorage') {
                window.sessionStorage.setItem(sourceKey, value == null ? '' : String(value))
                return { ok: true }
            }
        } catch (err) {
            return { error: err?.message || String(err) }
        }
        return { error: 'unsupported_source_driver' }
    }

    function restoreSourceValue({ driver, key, hadOriginal, originalValue } = {}) {
        if (!isAttackTab()) {
            return { error: 'not_attack_tab' }
        }
        const sourceDriver = String(driver || '').trim()
        const sourceKey = String(key || '').trim()
        if (!sourceDriver || !sourceKey) return { error: 'missing_source' }
        try {
            if (sourceDriver === 'cookie') {
                if (hadOriginal) setCookie(sourceKey, originalValue, { encoding: 'raw-first' })
                else deleteCookie(sourceKey)
                return { ok: true }
            }
            if (sourceDriver === 'localStorage') {
                if (hadOriginal) window.localStorage.setItem(sourceKey, originalValue == null ? '' : String(originalValue))
                else window.localStorage.removeItem(sourceKey)
                return { ok: true }
            }
            if (sourceDriver === 'sessionStorage') {
                if (hadOriginal) window.sessionStorage.setItem(sourceKey, originalValue == null ? '' : String(originalValue))
                else window.sessionStorage.removeItem(sourceKey)
                return { ok: true }
            }
        } catch (err) {
            return { error: err?.message || String(err) }
        }
        return { error: 'unsupported_source_driver' }
    }

    async function buildExecutedSourceResult(markerToken, sourceContext) {
        await probeWindowNameExecutionMarker(markerToken)
        const executed = xssExecutionEvents.some((event) => event.id === markerToken)
        const context = executed
            ? {
                type: 'browser_source',
                sourceDriver: sourceContext?.driver || null,
                sourceKey: sourceContext?.key || null,
                tag: null,
                attr: sourceContext?.driver || null,
                cssPath: null,
                outerHTML: null,
                snippet: `${sourceContext?.driver || 'source'}:${sourceContext?.key || ''}`
            }
            : null
        return {
            vulnerable: !!executed,
            executed: !!executed,
            reflected: false,
            sinkKey: buildSinkKey(context),
            context
        }
    }

    async function runPostMessageSourceProbe({ markerToken, checks = [], settleMs = 0, payload } = {}) {
        if (!isAttackTab()) {
            return { error: 'not_attack_tab' }
        }
        await waitForPageSettled(settleMs)
        const normalizedChecks = Array.isArray(checks) && checks.length ? checks : ['dom_xss']
        const result = {}
        try {
            const origin = window.location && window.location.origin && window.location.origin !== 'null'
                ? window.location.origin
                : '*'
            const rawPayload = String(payload == null ? '' : payload)
            const messageVariants = [
                rawPayload,
                { payload: rawPayload },
                { value: rawPayload },
                { data: rawPayload },
                { message: rawPayload },
                { q: rawPayload },
                { query: rawPayload }
            ]
            const targets = origin === '*' ? ['*'] : [origin, '*']
            for (const targetOrigin of targets) {
                for (const message of messageVariants) {
                    try {
                        window.postMessage(message, targetOrigin)
                    } catch (_) { }
                }
            }
        } catch (_) { }
        await sleep(Math.max(50, Math.min(5000, Number(settleMs) || 0)))
        if (normalizedChecks.includes('dom_xss')) {
            result.dom_xss = await buildExecutedSourceResult(markerToken, {
                driver: 'postMessage',
                key: 'window'
            })
        }
        return result
    }

    function fillControl(control, payload) {
        if (!control) return false
        const tag = String(control.tagName || '').toLowerCase()
        const type = String(control.getAttribute?.('type') || '').toLowerCase()
        if (tag === 'input' && ['submit', 'button', 'reset', 'image', 'file', 'hidden', 'checkbox', 'radio'].includes(type)) {
            return false
        }
        const value = String(payload == null ? '' : payload)
        try {
            if (tag === 'select') {
                const option = Array.from(control.options || []).find((candidate) => !candidate.disabled)
                if (option) control.value = option.value
            } else if (control.isContentEditable) {
                control.textContent = value
            } else {
                control.value = value
            }
            control.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }))
            control.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }))
            return true
        } catch (_) {
            return false
        }
    }

    function usableForms(limit = 4) {
        const forms = Array.from(document.forms || [])
        return forms.filter((form) => {
            if (!form || form.disabled) return false
            const controls = form.querySelectorAll('input, textarea, select, [contenteditable=""], [contenteditable="true"]')
            return Array.from(controls).some((control) => {
                const tag = String(control.tagName || '').toLowerCase()
                const type = String(control.getAttribute?.('type') || '').toLowerCase()
                return tag !== 'input' || !['submit', 'button', 'reset', 'image', 'file', 'hidden'].includes(type)
            })
        }).slice(0, Math.max(1, Math.min(8, Number(limit) || 4)))
    }

    function formContext(form) {
        return {
            driver: 'form',
            key: String(form?.getAttribute?.('name') || form?.getAttribute?.('id') || computeCssPath(form) || 'form')
        }
    }

    async function runFormSourceProbe({ markerToken, checks = [], settleMs = 0, payload } = {}) {
        if (!isAttackTab()) {
            return { error: 'not_attack_tab' }
        }
        await waitForPageSettled(settleMs)
        const forms = usableForms()
        if (!forms.length) {
            return { skipped: true, reason: 'no_source_candidates' }
        }
        const normalizedChecks = Array.isArray(checks) && checks.length ? checks : ['dom_xss']
        let anyFilled = false

        for (const form of forms) {
            const controls = Array.from(form.querySelectorAll('input, textarea, select, [contenteditable=""], [contenteditable="true"]'))
            const filled = controls.filter((control) => fillControl(control, payload)).length
            if (!filled) continue
            anyFilled = true

            const sourceContext = formContext(form)
            let defaultPrevented = false
            try {
                const submitEvent = new Event('submit', { bubbles: true, cancelable: true })
                defaultPrevented = !form.dispatchEvent(submitEvent)
            } catch (_) { }

            if (!defaultPrevented) {
                const submitter = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])')
                setTimeout(() => {
                    try {
                        if (typeof form.requestSubmit === 'function') {
                            form.requestSubmit(submitter || undefined)
                        } else if (submitter && typeof submitter.click === 'function') {
                            submitter.click()
                        } else if (typeof form.submit === 'function') {
                            form.submit()
                        }
                    } catch (_) { }
                }, 0)
                return {
                    ok: true,
                    mayNavigate: true,
                    sourceContext
                }
            }

            await sleep(Math.max(50, Math.min(5000, Number(settleMs) || 0)))
            const result = {
                ok: true,
                mayNavigate: false,
                sourceContext
            }
            if (normalizedChecks.includes('dom_xss')) {
                result.dom_xss = await buildExecutedSourceResult(markerToken, sourceContext)
            }
            if (result.dom_xss?.vulnerable) return result
        }

        if (!anyFilled) {
            return { skipped: true, reason: 'no_source_candidates' }
        }
        return { skipped: true, reason: 'browser_source_no_vulnerability_match' }
    }

    const browserNavRuntime = (typeof browser !== 'undefined' && browser.runtime)
        ? browser.runtime
        : ((typeof chrome !== 'undefined' && chrome.runtime) ? chrome.runtime : null)

    if (browserNavRuntime?.onMessage?.addListener) {
        browserNavRuntime.onMessage.addListener((msg, sender, sendResponse) => {
            if (msg?.type === 'browserNavPing') {
                if (sendResponse) sendResponse({ ok: true, active: isAttackTab() })
                return false
            }
            if (msg?.type === 'browserNavRun') {
                Promise.resolve()
                    .then(() => runBrowserNavTest(msg))
                    .then((result) => {
                        if (sendResponse) sendResponse(result)
                    })
                    .catch((err) => {
                        const message = err && err.message ? err.message : String(err || 'unknown error')
                        if (sendResponse) sendResponse({ error: message })
                    })
                return true
            }
            if (msg?.type === 'browserNavSourceSnapshot') {
                if (sendResponse) sendResponse(sourceSnapshot(msg?.drivers || []))
                return false
            }
            if (msg?.type === 'browserNavSourceApply') {
                if (sendResponse) sendResponse(applySourceValue(msg))
                return false
            }
            if (msg?.type === 'browserNavSourceRestore') {
                if (sendResponse) sendResponse(restoreSourceValue(msg))
                return false
            }
            if (msg?.type === 'browserNavSourcePostMessage') {
                Promise.resolve()
                    .then(() => runPostMessageSourceProbe(msg))
                    .then((result) => {
                        if (sendResponse) sendResponse(result)
                    })
                    .catch((err) => {
                        const message = err && err.message ? err.message : String(err || 'unknown error')
                        if (sendResponse) sendResponse({ error: message })
                })
                return true
            }
            if (msg?.type === 'browserNavSourceForm') {
                Promise.resolve()
                    .then(() => runFormSourceProbe(msg))
                    .then((result) => {
                        if (sendResponse) sendResponse(result)
                    })
                    .catch((err) => {
                        const message = err && err.message ? err.message : String(err || 'unknown error')
                        if (sendResponse) sendResponse({ error: message })
                    })
                return true
            }
        })
    }
}
