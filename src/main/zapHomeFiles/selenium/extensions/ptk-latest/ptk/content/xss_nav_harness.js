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

    window.addEventListener('message', (event) => {
        if (event.source !== window) return
        const data = event.data || {}
        if (data && data.source === 'ptk-xss' && typeof data.id === 'string') {
            xssExecutionEvents.push({ id: data.id, ts: Date.now() })
            if (xssExecutionEvents.length > 50) xssExecutionEvents.shift()
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
        })
    }
}
