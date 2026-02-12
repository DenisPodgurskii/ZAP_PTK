/* Author: Denis Podgurskii */

(function () {
    if (window.ptk_replayer || typeof browser === typeof undefined) return

    let isIframe = false
    try {
        isIframe = window.self !== window.top
    } catch (e) {
        isIframe = true
    }

    let windowIndex = window.opener ? 1 : 0

    if (isIframe)
        windowIndex = window.top.opener ? 1 : 0


    class ptk_replayer {
        constructor() {
            browser.storage.local.get([
                'ptk_replay',
                'ptk_replay_items',
                'ptk_replay_step',
                'ptk_replay_regex',
                'ptk_recording_log',
                'ptk_replay_debug_enabled']).then(function (result) {
                    if (result.ptk_replay_step == -1) return
                    this.items = result.ptk_replay_items
                    this.step = result.ptk_replay_step
                    this.regex = result.ptk_replay_regex
                    this.paused = false
                    this.forward = false
                    this.log = result.ptk_recording_log
                    this._networkPending = 0
                    this._lastNetworkActivity = 0
                    this._networkWrapped = false
                    this.tabId = null
                    this.activeReplayTabId = null
                    this.hasInitialNavigate = false
                    this.debugEnabled = typeof result.ptk_replay_debug_enabled === 'boolean'
                        ? result.ptk_replay_debug_enabled
                        : true


                    if (!isIframe && !windowIndex) {
                        this._initNetworkTracking()
                        this.bootstrapControl()
                    } else if (!isIframe && windowIndex) {
                        window.opener.postMessage({ channel: "child2opener", message: 'init' }, '*')
                    }
                }.bind(this))
        }

        logEvent(item, msg) {
            if (item) {
                let eventName = (item.EventType == 'Javascript') ? item.EventType + '(' + item.EventTypeName + ')' : item.EventType
                this.log += 'Step #' + (this.step + 1) + ': ' + eventName + '<br/>'
            }
            if (msg) {
                this.log += msg + '<br/>'
            }
            browser.storage.local.set({
                'ptk_recording_log': this.log
            })
        }

        wait(ms, opts = {}) {
            return new Promise((resolve, reject) => {
                let timerId = setTimeout(resolve, ms)
                if (opts.signal) {
                    opts.signal.addEventListener('abort', event => {
                        clearTimeout(timerId)
                        reject(event)
                    })
                }
            })
        }

        validate() {
            if (this.regex && this.step > 0) {
                var regex = new RegExp(this.regex, 'i')
                if (regex.test(document.body.innerHTML)) {
                    var str = regex.exec(document.body.innerHTML)
                    this.logEvent(null, 'Regex successfully match: ' + str[0])
                    alert('Successfully match: ' + str[0])
                } else {
                    this.logEvent(null, 'Regex match not found')
                    alert('Match not found')
                }
            }
        }

        async execute(item) {
            let frames = document.getElementsByTagName('iframe')
            if (!isIframe && item.WindowIndex == windowIndex) {
                if (item.ElementPath.includes('//IFRAME')) {
                    this.executeFrame(item)
                } else {
                    await this.doStep(this.step, item)
                }
            } else if (!isIframe && this.childWindow) {
                this.childWindow.postMessage({ channel: "2child", message: 'doStep', step: this.step, item: item }, '*')
            }
        }

        executeFrame(item){
            const rawParts = String(item.ElementPath || '').split('|||>').filter(Boolean)
            const parts = rawParts.filter(part => part !== 'xpath=' && part !== 'css=')
            const isIframeLocator = (part) => /IFRAME/i.test(part)
            let elementPathIndex = -1
            for (let i = parts.length - 1; i >= 0; i--) {
                if (/^(css|xpath)=/.test(parts[i]) && !isIframeLocator(parts[i])) {
                    elementPathIndex = i
                    break
                }
            }
            if (elementPathIndex === -1) elementPathIndex = parts.length - 1
            const frameLocators = parts.slice(0, elementPathIndex).filter(isIframeLocator)
            const elementPath = parts[elementPathIndex] || ''

            let currentWindow = window
            let frameWindow = null
            for (const locator of frameLocators) {
                const frameElement = this.getFrameElement(locator, currentWindow.document)
                if (!frameElement || !frameElement.contentWindow) {
                    if (item.Optional == 0) {
                        alert('Could not locate frame for ' + locator)
                    }
                    return
                }
                frameWindow = frameElement.contentWindow
                currentWindow = frameWindow
            }

            if (!frameWindow) return
            item.ElementPath = elementPath
            frameWindow.postMessage({ channel: "2frame", message: 'doStep', step: this.step, item: item }, '*')
        }

        getFrameElement(locator, doc) {
            if (!locator || !doc) return null
            const value = locator.startsWith('xpath=') ? locator.slice(6) : locator
            if (locator.startsWith('css=')) {
                return doc.querySelector(locator.slice(4))
            }
            if (value.includes('IFRAME')) {
                const xpath = value.startsWith('//') ? value : ('//' + value)
                return doc.evaluate(xpath, doc, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue
            }
            return null
        }

        async start() {
            if (this.step > -1) {
                while (true) {
                    await this.waitForActiveTab()
                    if (this.paused) break

                    const storedStep = await this.getCurrentStep()
                    if (storedStep === -1) break
                    if (storedStep >= this.items.length) {
                        this.step = storedStep
                        this.validate()
                        break
                    }
                    this.step = storedStep
                    let item = this.items[this.step]
                    this.debugLog('step_start', {
                        step: this.step,
                        eventType: item.EventType || item.EventTypeName,
                        target: item.target,
                        elementPath: item.ElementPath
                    })

                    this.logEvent(item)
                    browser.storage.local.set({ 'ptk_replay_step': (this.step + 1) })

                    this.abortController = new AbortController()
                    this.awaitTimeout = this.wait(item.Duration, { signal: this.abortController.signal }).catch(() => { })
                    await this.awaitTimeout

                    if (this.paused) break

                    this.step++

                    if (this.forward) {
                        this.forward = false
                        continue
                    }

                    await this.execute(item)
                    this.debugLog('step_done', { step: this.step })
                }
            }
            if (!this.paused) this.stop()
        }

        stop() {
            this.step = -1
            browser.storage.local.set({ "ptk_replay_step": this.step })
        }

        pause() {
            this.paused = true
            this.logEvent(null, 'Paused...')
        }

        run() {
            this.paused = false
            this.logEvent(null, 'Resumed...')
            this.start()
        }

        stepForward() {
            if (this.step > -1) {
                this.forward = true
                this.logEvent(null, 'Skip step #' + (this.step + 1))
                this.abortController.abort()
            }
        }

        async doStep(step, item) {
            if (!item || this.paused) return

            this.step = step
            const rawType = item.EventType || item.EventTypeName || item.eventTypeName || ''
            let eventType = String(rawType).toLowerCase()
            this.handler = this[eventType]
            if (this.handler) {
                await this.handler(item)
            } else {
                this.debugLog('missing_handler', { step: this.step, eventType })
            }
        }

        async bootstrapControl() {
            try {
                const resp = await browser.runtime.sendMessage({
                    channel: "ptk_content2background_recorder",
                    type: "get_tab_id"
                })
                this.tabId = resp?.tabId ?? null
                this.activeReplayTabId = resp?.activeReplayTabId ?? null
            } catch (e) {
                this.tabId = null
            }
            this.start()
        }

        async waitForActiveTab(timeoutMs = 60000, intervalMs = 250) {
            if (!this.tabId) return
            const endAt = Date.now() + timeoutMs
            while (Date.now() < endAt) {
                if (this.paused) return
                try {
                    const resp = await browser.runtime.sendMessage({
                        channel: "ptk_content2background_recorder",
                        type: "get_active_replay_tab"
                    })
                    this.activeReplayTabId = resp?.activeReplayTabId ?? this.activeReplayTabId
                    if (!this.activeReplayTabId || this.activeReplayTabId === this.tabId) {
                        return
                    }
                } catch (e) {
                    return
                }
                await this.wait(intervalMs)
            }
        }

        async getCurrentStep() {
            try {
                const result = await browser.storage.local.get(['ptk_replay_step', 'ptk_replay'])
                if (!result.ptk_replay) {
                    return -1
                }
                if (typeof result.ptk_replay_step === 'number') {
                    return result.ptk_replay_step
                }
            } catch (e) {
                // ignore
            }
            return this.step
        }

        async navigate(item) {
            if (item?.Data) {
                this.debugLog('navigate', { url: item.Data })
                const isInitial = item?.isInitial || item?.hardNavigate || item?.HardNavigate
                if (!this.hasInitialNavigate) {
                    this.hasInitialNavigate = true
                    window.location.href = item.Data
                } else {
                    await this.waitForUrl(item.Data, this.getStepTimeout(item))
                    await this.waitForAppIdle({ timeoutMs: this.getStepTimeout(item) })
                }
            }
        }

        async waitforurl(item) {
            if (!item?.Data) return
            this.debugLog('wait_for_url', { url: item.Data })
            await this.waitForUrl(item.Data, this.getStepTimeout(item))
            await this.waitForAppIdle({ timeoutMs: this.getStepTimeout(item) })
        }

        delay(item) { }

        driverclick(item) { this.click(item) }
        onclick(item) { this.click(item) }
        async click(item) {
            this.debugLog('click', { step: this.step })
            let element = await this.waitForElement(item, this.getStepTimeout(item))
            if (element) {
                const beforeUrl = window.location.href
                await this.performClick(element)
                element.dispatchEvent(new Event('resize', {bubbles: true}))
                await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
            } else if (item.Optional == 0) {
                const ref = item?._cssPath ? 'CSS: ' + item._cssPath : 'Path: ' + item.ElementPath
                this.debugLog('click_failed', { ref })
                alert('Could not execute click on ( ' + ref + ')')
            }
        }

        driversetcontrolvalue(item) { this.type(item) }
        setcontroldata(item) { this.type(item) }
        setvalue(item) { this.type(item) }
        async type(item) {
            this.debugLog('type', { step: this.step })
            let element = await this.waitForElement(item, this.getStepTimeout(item))
            if (element) {
                const beforeUrl = window.location.href
                let lastValue = element.value
                let event = new Event('input', {bubbles: true})
                event.simulated = true
                element.value = item.Data
                element.defaultValue = item.Data
                let tracker = element._valueTracker
                if (tracker) { tracker.setValue(lastValue) }
                element.dispatchEvent(event)
                element.dispatchEvent(new Event('change', {bubbles: true}))
                element.dispatchEvent(new Event('blur', {bubbles: true}))
                element.dispatchEvent(new Event('resize', {bubbles: true}))
                await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
            } else if (item.Optional == 0) {
                const ref = item?._cssPath ? 'CSS: ' + item._cssPath : 'Path: ' + item.ElementPath
                this.debugLog('type_failed', { ref })
                alert('Could not execute click on ( ' + ref + ')')
            }
        }

        async sendkeys(item) {
            this.debugLog('sendkeys', { step: this.step, data: item.Data || item.data })
            let element = await this.waitForElement(item, this.getStepTimeout(item))
            if (!element) {
                if (item.Optional == 0) {
                    const ref = item?._cssPath ? 'CSS: ' + item._cssPath : 'Path: ' + item.ElementPath
                    this.debugLog('sendkeys_failed', { ref, url: window.location.href })
                    alert('Could not execute sendKeys on ( ' + ref + ')')
                }
                return
            }

            const beforeUrl = window.location.href
            const raw = item.Data || item.data || ''
            const tokens = this.parseKeyTokens(String(raw))
            const hasEnter = tokens.some(token => token.type === 'key' && String(token.key).toUpperCase() === 'KEY_ENTER')
            for (const token of tokens) {
                if (token.type === 'text') {
                    this.insertText(element, token.value)
                } else {
                    this.dispatchKey(element, token.key)
                }
            }
            if (hasEnter) {
                await this.waitForUrlChange(this.getStepTimeout(item))
            }
            element.dispatchEvent(new Event('change', { bubbles: true }))
            element.dispatchEvent(new Event('blur', { bubbles: true }))
            await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
        }

        async selectwindow(item) {
            const target = item?.data || item?.Data || item?.target || (Array.isArray(item?.targetOptions) ? item.targetOptions[0] : null)
            const targetOptions = item?.targetOptions || item?.targets || []
            this.debugLog('select_window', { target })
            try {
                await browser.runtime.sendMessage({
                    channel: "ptk_content2background_recorder",
                    type: "select_window",
                    target: target,
                    targetOptions: targetOptions
                })
                await this.forceViewportRefresh()
            } catch (e) {
                if (item.Optional == 0) {
                    alert('Could not switch window')
                }
            }
        }

        async hover(item) {
            this.debugLog('hover', { step: this.step, target: item?.target, elementPath: item?.ElementPath })
            const element = await this.waitForElement(item, this.getStepTimeout(item))
            if (!element) {
                if (item.Optional == 0) {
                    const ref = item?._cssPath ? 'CSS: ' + item._cssPath : 'Path: ' + item.ElementPath
                    this.debugLog('hover_failed', { ref })
                }
                return
            }
            try {
                const rect = element.getBoundingClientRect()
                const init = {
                    bubbles: true,
                    cancelable: true,
                    view: window,
                    clientX: rect.left + rect.width / 2,
                    clientY: rect.top + rect.height / 2
                }
                element.dispatchEvent(new MouseEvent('mouseover', init))
                element.dispatchEvent(new MouseEvent('mouseenter', init))
                element.dispatchEvent(new MouseEvent('mousemove', init))
            } catch (e) {
                // ignore
            }
            await this.wait(150)
        }

        async setwindowsize(item) {
            const parsed = this.parseWindowSize(item?.Data || item?.data)
            if (!parsed) {
                this.debugLog('set_window_size_failed', { data: item?.Data || item?.data })
                return
            }
            this.debugLog('set_window_size', parsed)
            try {
                await browser.runtime.sendMessage({
                    channel: "ptk_content2background_recorder",
                    type: "set_window_size",
                    width: parsed.width,
                    height: parsed.height
                })
                await this.wait(250)
                await this.forceViewportRefresh()
            } catch (e) {
                this.debugLog('set_window_size_error', { error: e?.message })
            }
        }

        async javascript(item) {
            if (!item || !item.Data) return
            try {
                const beforeUrl = window.location.href
                const data = item.Data
                const match = data.match(/\}\)\('([^']*)'(?:,\s*`([\s\S]*?)`)?\)/)
                if (!match) {
                    if (item.Optional == 0) alert('Could not parse javascript macro step')
                    return
                }

                const path = match[1]
                const rawValue = match[2]
                const value = typeof rawValue === 'string'
                    ? rawValue.replace(/\\`/g, '`').replace(/\\\\/g, '\\')
                    : null

                if (value !== null) {
                    await this.type({ ElementPath: 'xpath=', Data: value, Optional: item.Optional, _cssPath: path })
                    return
                }

                const element = await this.waitForElement({ ElementPath: 'xpath=', Optional: item.Optional, _cssPath: path }, this.getStepTimeout(item))
                if (element) {
                    await this.performClick(element)
                    const clickCount = (data.match(/item\.click\(\)/g) || []).length
                    if (clickCount > 1) {
                        await this.performClick(element)
                    }
                    element.dispatchEvent(new Event('resize', { bubbles: true }))
                    await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
                } else if (item.Optional == 0) {
                    alert('Could not execute click on ( CSS: ' + path + ')')
                }
            } catch (e) {
                if (item.Optional == 0) alert('Could not execute javascript: ' + e.message)
            }
        }

        getStepTimeout(item) {
            const base = Math.max(30000, (item?.Duration || 0) * 5)
            return base
        }

        parseWindowSize(raw) {
            if (!raw) return null
            if (typeof raw === 'string') {
                const parts = raw.split(',').map(p => Number(p.trim()))
                if (parts.length >= 2 && parts[0] && parts[1]) {
                    return { width: parts[0], height: parts[1] }
                }
            }
            if (typeof raw === 'object') {
                const width = Number(raw.width)
                const height = Number(raw.height)
                if (width && height) {
                    return { width, height }
                }
            }
            return null
        }

        parseKeyTokens(raw) {
            const tokens = []
            const regex = /\$\{([^}]+)\}/g
            let lastIndex = 0
            let match
            while ((match = regex.exec(raw))) {
                if (match.index > lastIndex) {
                    tokens.push({ type: 'text', value: raw.slice(lastIndex, match.index) })
                }
                tokens.push({ type: 'key', key: match[1] })
                lastIndex = regex.lastIndex
            }
            if (lastIndex < raw.length) {
                tokens.push({ type: 'text', value: raw.slice(lastIndex) })
            }
            return tokens
        }

        insertText(element, text) {
            if (!text) return
            const lastValue = element.value
            const event = new Event('input', { bubbles: true })
            event.simulated = true
            element.value = (element.value || '') + text
            element.defaultValue = element.value
            const tracker = element._valueTracker
            if (tracker) { tracker.setValue(lastValue) }
            element.dispatchEvent(event)
        }

        dispatchKey(element, keyToken) {
            const keyMap = {
                KEY_ENTER: { key: 'Enter', code: 'Enter', keyCode: 13, which: 13 },
                KEY_TAB: { key: 'Tab', code: 'Tab', keyCode: 9, which: 9 },
                KEY_BACKSPACE: { key: 'Backspace', code: 'Backspace', keyCode: 8, which: 8 },
                KEY_DELETE: { key: 'Delete', code: 'Delete', keyCode: 46, which: 46 },
                KEY_ESCAPE: { key: 'Escape', code: 'Escape', keyCode: 27, which: 27 },
                KEY_ESC: { key: 'Escape', code: 'Escape', keyCode: 27, which: 27 },
                KEY_ARROW_LEFT: { key: 'ArrowLeft', code: 'ArrowLeft', keyCode: 37, which: 37 },
                KEY_ARROW_RIGHT: { key: 'ArrowRight', code: 'ArrowRight', keyCode: 39, which: 39 },
                KEY_ARROW_UP: { key: 'ArrowUp', code: 'ArrowUp', keyCode: 38, which: 38 },
                KEY_ARROW_DOWN: { key: 'ArrowDown', code: 'ArrowDown', keyCode: 40, which: 40 }
            }
            const normalized = String(keyToken || '').toUpperCase()
            const def = keyMap[keyToken] || keyMap[normalized] || null
            if (!def) {
                this.insertText(element, `\${${keyToken}}`)
                return
            }
            const payload = { bubbles: true, cancelable: true, ...def }
            element.dispatchEvent(new KeyboardEvent('keydown', payload))
            element.dispatchEvent(new KeyboardEvent('keypress', payload))
            element.dispatchEvent(new KeyboardEvent('keyup', payload))
        }

        _initNetworkTracking() {
            if (this._networkWrapped) return
            this._networkWrapped = true
            this._lastNetworkActivity = Date.now()
            const self = this
            const origFetch = window.fetch
            if (origFetch) {
                window.fetch = function (...args) {
                    self._networkPending++
                    self._lastNetworkActivity = Date.now()
                    return origFetch.apply(this, args)
                        .catch((err) => {
                            throw err
                        })
                        .finally(() => {
                            self._networkPending = Math.max(0, self._networkPending - 1)
                            self._lastNetworkActivity = Date.now()
                        })
                }
            }
            const origOpen = XMLHttpRequest.prototype.open
            const origSend = XMLHttpRequest.prototype.send
            XMLHttpRequest.prototype.open = function (...args) {
                this.__ptk_tracking = true
                return origOpen.apply(this, args)
            }
            XMLHttpRequest.prototype.send = function (...args) {
                if (this.__ptk_tracking) {
                    self._networkPending++
                    self._lastNetworkActivity = Date.now()
                    this.addEventListener('loadend', () => {
                        self._networkPending = Math.max(0, self._networkPending - 1)
                        self._lastNetworkActivity = Date.now()
                    }, { once: true })
                }
                return origSend.apply(this, args)
            }
        }

        async waitForUrl(expected, timeoutMs = 10000) {
            if (!expected) return
            const endAt = Date.now() + timeoutMs
            const normalizedExpected = String(expected)
            while (Date.now() < endAt) {
                if (window.location.href === normalizedExpected) return
                await this.wait(150)
            }
        }

        async waitForNetworkIdle(idleMs = 400, timeoutMs = 10000) {
            const endAt = Date.now() + timeoutMs
            while (Date.now() < endAt) {
                const pending = this._networkPending || 0
                const since = Date.now() - (this._lastNetworkActivity || 0)
                if (pending === 0 && since >= idleMs) return
                await this.wait(100)
            }
        }

        async waitForDomIdle(idleMs = 400, timeoutMs = 10000) {
            const endAt = Date.now() + timeoutMs
            let lastChange = Date.now()
            return new Promise((resolve) => {
                const observer = new MutationObserver(() => {
                    lastChange = Date.now()
                })
                observer.observe(document, { subtree: true, childList: true, attributes: true })
                const timer = setInterval(() => {
                    if (Date.now() - lastChange >= idleMs || Date.now() > endAt) {
                        clearInterval(timer)
                        observer.disconnect()
                        resolve()
                    }
                }, 100)
            })
        }

        async waitForAppIdle({ beforeUrl = null, timeoutMs = 10000 } = {}) {
            const startUrl = beforeUrl || window.location.href
            let urlChanged = false
            const urlEndAt = Date.now() + Math.min(1500, timeoutMs)
            while (Date.now() < urlEndAt) {
                if (window.location.href !== startUrl) {
                    urlChanged = true
                    break
                }
                await this.wait(100)
            }
            if (urlChanged) {
                await this.waitForUrl(window.location.href, timeoutMs)
            }
            await Promise.all([
                this.waitForNetworkIdle(400, timeoutMs),
                this.waitForDomIdle(400, timeoutMs)
            ])
        }

        getElementByXpath(item) {
            let xpath = item.ElementPath
            xpath = xpath.replace('xpath=', '').replace(/\[(\d+)\]/g, function (fullMatch, n) { return "[" + (Number(n) + 1) + "]"; })
            if (!xpath.startsWith('//')) xpath = '/' + xpath
            return document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue
        }

        getElementByCss(item) {
            let selector = item.ElementPath.replace('css=', '')
            return this.findElementByCss(selector)
        }

        async waitForElement(item, timeoutMs = 15000, intervalMs = 250) {
            const endAt = Date.now() + timeoutMs
            let lastError = null
            let lastSeen = null
            while (Date.now() < endAt) {
                try {
                    const locators = this.getLocatorCandidates(item)
                    for (const locator of locators) {
                        item._lastLocator = locator
                        const el = this.normalizeElement(this.getElementByLocator(locator))
                        if (el && this.isInteractable(el)) return el
                        if (el) lastSeen = el
                    }
                } catch (e) {
                    lastError = e
                }
                await this.wait(intervalMs)
            }
            if (item && item._lastLocator) {
                this.debugLog('wait_for_element_failed', {
                    locator: item._lastLocator,
                    elementPath: item.ElementPath,
                    url: window.location.href
                })
            }
            if (lastSeen && this.isInteractable(lastSeen)) return lastSeen
            return null
        }

        async waitForUrlChange(timeoutMs = 10000) {
            const startUrl = window.location.href
            const endAt = Date.now() + timeoutMs
            while (Date.now() < endAt) {
                if (window.location.href !== startUrl) {
                    this.debugLog('url_changed', { from: startUrl, to: window.location.href })
                    return true
                }
                await this.wait(150)
            }
            return false
        }

        getLocatorCandidates(item) {
            const candidates = []
            const pushUnique = (value) => {
                if (value && !candidates.includes(value)) {
                    candidates.push(value)
                }
            }
            const normalizeLocator = (value) => {
                if (!value) return null
                const trimmed = String(value).trim()
                if (!trimmed) return null
                if (/^(css|xpath|id|name|linkText)=/i.test(trimmed)) return trimmed
                if (/^\/|^\.\//.test(trimmed)) return `xpath=${trimmed}`
                return `css=${trimmed}`
            }
            const addFromTargets = (targets) => {
                if (!Array.isArray(targets)) return
                targets.forEach((entry) => {
                    if (Array.isArray(entry)) {
                        pushUnique(normalizeLocator(entry[0]))
                    } else {
                        pushUnique(normalizeLocator(entry))
                    }
                })
            }

            addFromTargets(item?.targetOptions)
            addFromTargets(item?.targets)
            pushUnique(normalizeLocator(item?.target))
            pushUnique(normalizeLocator(item?.ElementPath))
            if (item?._cssPath) {
                pushUnique(normalizeLocator(`css=${item._cssPath}`))
            }
            if (item?.csspath) {
                pushUnique(normalizeLocator(`css=${item.csspath}`))
            }
            if (item?.xpath) {
                pushUnique(normalizeLocator(`xpath=${item.xpath}`))
            }
            if (item?.fullxpath) {
                pushUnique(normalizeLocator(`xpath=${item.fullxpath}`))
            }

            return candidates.filter(Boolean)
        }

        getElementByLocator(locator) {
            if (!locator) return null
            const value = String(locator)
            const escapeCss = (input) => {
                if (window.CSS && typeof window.CSS.escape === 'function') {
                    return window.CSS.escape(input)
                }
                return String(input).replace(/"/g, '\\"')
            }
            if (value.startsWith('id=')) {
                return document.getElementById(value.slice(3))
            }
            if (value.startsWith('name=')) {
                return document.querySelector(`[name="${escapeCss(value.slice(5))}"]`)
            }
            if (value.startsWith('linkText=')) {
                const raw = value.slice(9)
                const [text, posPart] = raw.split('@POS=')
                const links = Array.from(document.querySelectorAll('a')).filter(a => (a.innerText || a.textContent || '').trim() === text)
                if (posPart) {
                    const index = Number(posPart) - 1
                    return links[index] || null
                }
                return links[0] || null
            }
            if (value.startsWith('css=')) {
                return this.findElementByCss(value.slice(4))
            }
            if (value.startsWith('xpath=')) {
                const item = { ElementPath: value }
                return this.getElementByXpath(item)
            }
            return this.findElementByCss(value)
        }

        async forceViewportRefresh() {
            try {
                window.dispatchEvent(new Event('resize'))
                window.dispatchEvent(new Event('orientationchange'))
                await new Promise(resolve => requestAnimationFrame(resolve))
                await new Promise(resolve => requestAnimationFrame(resolve))
            } catch (e) {
                // ignore
            }
        }

        debugLog(label, data = {}) {
            if (!this.debugEnabled) return
            const entry = {
                ts: new Date().toISOString(),
                label: label,
                data: data
            }
            try {
                console.debug('[PTK Replay]', entry)
                browser.storage.local.get(['ptk_replay_debug']).then((result) => {
                    const prev = result.ptk_replay_debug || ''
                    const line = JSON.stringify(entry)
                    const next = (prev + line + '\n').slice(-20000)
                    browser.storage.local.set({ ptk_replay_debug: next })
                }).catch(() => {})
            } catch (e) {
                // ignore
            }
        }

        normalizeElement(node) {
            if (!node) return null
            if (node.nodeType === Node.ELEMENT_NODE) return node
            if (node.nodeType === Node.TEXT_NODE) return node.parentElement
            if (node.nodeType === Node.ATTRIBUTE_NODE) return node.ownerElement
            return null
        }

        async performClick(element) {
            const target = element.closest?.('button,a,input,textarea,select,[role="button"]') || element
            try {
                if (target.scrollIntoView) {
                    target.scrollIntoView({ block: "center", inline: "center", behavior: "instant" })
                }
                target.focus?.({ preventScroll: true })
            } catch (e) {
                // ignore
            }
            const point = this.getClickPoint(target)
            if (point) {
                try {
                    const res = await browser.runtime.sendMessage({
                        channel: "ptk_content2background_recorder",
                        type: "debugger_click",
                        x: point.x,
                        y: point.y,
                        clickCount: 1
                    })
                    if (res?.success) {
                        return
                    }
                } catch (e) {
                    // fall back to DOM click
                }
            }
            if (typeof target.click === 'function') {
                target.click()
                return
            }
            if (target.dispatchEvent) {
                target.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, cancelable: true, view: window, pointerType: 'mouse' }))
                target.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true, view: window }))
                target.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, cancelable: true, view: window, pointerType: 'mouse' }))
                target.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true, view: window }))
                target.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }))
            }
        }

        isInteractable(element) {
            if (!element || !element.getBoundingClientRect) return false
            const rect = element.getBoundingClientRect()
            if (rect.width <= 0 || rect.height <= 0) return false
            const style = element.ownerDocument?.defaultView?.getComputedStyle?.(element)
            if (style) {
                if (style.visibility === "hidden" || style.display === "none") return false
                if (style.pointerEvents === "none") return false
            }
            return true
        }

        getClickPoint(element) {
            if (!element?.getBoundingClientRect) return null
            const rect = element.getBoundingClientRect()
            let x = rect.left + rect.width / 2
            let y = rect.top + rect.height / 2
            try {
                let win = element.ownerDocument?.defaultView
                while (win && win.frameElement) {
                    const frameRect = win.frameElement.getBoundingClientRect()
                    x += frameRect.left
                    y += frameRect.top
                    win = win.parent
                }
            } catch (e) {
                return null
            }
            if (x < 0 || y < 0 || x > window.innerWidth || y > window.innerHeight) {
                return null
            }
            if (!Number.isFinite(x) || !Number.isFinite(y)) return null
            return { x, y }
        }

        findElementByCss(selector) {
            let el = this.querySelectorDeep(selector, document)
            if (el) return el
            const frames = document.querySelectorAll('iframe')
            for (const frame of frames) {
                try {
                    const doc = frame.contentDocument
                    if (!doc) continue
                    el = this.querySelectorDeep(selector, doc)
                    if (el) return el
                } catch (e) {
                    // ignore cross-origin frames
                }
            }
            return null
        }

        querySelectorDeep(selector, root) {
            if (!root || !root.querySelector) return null
            let el = this.findBySelectorFallback(selector, root)
            if (el) return el
            const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT)
            let node = walker.currentNode
            while (node) {
                if (node.shadowRoot) {
                    el = this.findBySelectorFallback(selector, node.shadowRoot)
                    if (el) return el
                }
                node = walker.nextNode()
            }
            return null
        }

        findBySelectorFallback(selector, root) {
            let el = root.querySelector(selector)
            if (el) return el
            const normalized = this.normalizeCssSelector(selector)
            if (normalized !== selector) {
                el = root.querySelector(normalized)
                if (el) return el
            }
            const stripped = this.stripNthOfType(selector)
            if (stripped !== selector) {
                el = root.querySelector(stripped)
                if (el) return el
            }
            const normalizedStripped = this.stripNthOfType(normalized)
            if (normalizedStripped !== normalized) {
                el = root.querySelector(normalizedStripped)
                if (el) return el
            }
            const noIds = this.stripIdSelectors(selector)
            if (noIds !== selector) {
                el = root.querySelector(noIds)
                if (el) return el
            }
            const normalizedNoIds = this.stripIdSelectors(normalized)
            if (normalizedNoIds !== normalized) {
                el = root.querySelector(normalizedNoIds)
                if (el) return el
            }

            const parts = selector.split('>').map(part => part.trim()).filter(Boolean)
            if (parts.length < 2) return null

            for (let i = 1; i < parts.length; i++) {
                const candidate = parts.slice(i).join(' > ')
                el = root.querySelector(candidate)
                if (el) return el
                const normalizedCandidate = this.normalizeCssSelector(candidate)
                if (normalizedCandidate !== candidate) {
                    el = root.querySelector(normalizedCandidate)
                    if (el) return el
                }
                const strippedCandidate = this.stripNthOfType(candidate)
                if (strippedCandidate !== candidate) {
                    el = root.querySelector(strippedCandidate)
                    if (el) return el
                }
                const normalizedStrippedCandidate = this.stripNthOfType(normalizedCandidate)
                if (normalizedStrippedCandidate !== normalizedCandidate) {
                    el = root.querySelector(normalizedStrippedCandidate)
                    if (el) return el
                }
                const noIdsCandidate = this.stripIdSelectors(candidate)
                if (noIdsCandidate !== candidate) {
                    el = root.querySelector(noIdsCandidate)
                    if (el) return el
                }
                const normalizedNoIdsCandidate = this.stripIdSelectors(normalizedCandidate)
                if (normalizedNoIdsCandidate !== normalizedCandidate) {
                    el = root.querySelector(normalizedNoIdsCandidate)
                    if (el) return el
                }
            }

            return null
        }

        normalizeCssSelector(selector) {
            return selector.replace(/(^|[\s>+~])([A-Z][A-Z0-9-]*)/g, (match, prefix, tag) => {
                return prefix + tag.toLowerCase()
            })
        }

        stripNthOfType(selector) {
            return selector.replace(/:nth-of-type\(\d+\)/g, '')
        }

        stripIdSelectors(selector) {
            return selector
                .replace(/\[id="[^"]*"\]/g, '')
                .replace(/#[A-Za-z0-9_-]+/g, '')
        }

    }

    window.ptk_replayer = new ptk_replayer()


    window.addEventListener("message", (event) => {
        if (!isIframe && event.data.channel == 'child2opener' && event.data.message == 'init') {
            window.ptk_replayer.childWindow = event.source
        }
        if (isIframe && event.data.channel == '2frame' && event.data.message == 'doStep') {
            window.ptk_replayer.doStep(event.data.step, event.data.item)
        }
        if (!isIframe && event.data.channel == '2child' && event.data.message == 'doStep') {
            if (event.data.item.ElementPath.includes('//IFRAME')) {
                window.ptk_replayer.executeFrame(event.data.item)
            } else {
                window.ptk_replayer.doStep(event.data.step, event.data.item)
            }
        }
    })

})()
