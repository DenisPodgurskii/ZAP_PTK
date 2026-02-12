/* Author: Denis Podgurskii */

(function () {
    if (window.ptk_recorder || typeof browser === typeof undefined) return

    const gstartTime = (new Date()).getTime()
    const LeftButton = 0
    const MiddleButton = 1
    const RightButton = 2
    const UnknownButton = 3

    const EventTypes = {
        Navigate: 0,
        Click: 1,
        KeyPress: 2,
        Tab: 3,
        Change: 4,
        MouseDown: 5,
        MouseUp: 6,
        Paste: 7,
        SetWindowSize: 8,
        DblClick: 9,
        WaitForUrl: 10,
        SendKeys: 11,
        Hover: 12,
        Delay: 25
    }

    let isIframe = false
    try {
        isIframe = window.self !== window.top
    } catch (e) {
        isIframe = true
    }

    var frameInfo = {}
    var windowIndex = window.opener ? 1 : 0

    class ptk_event {
        constructor(e) {
            this.event = (e) ? e : window.event 
            let t = this.target()
            let path = e.path ? e.path : e.composedPath()

            if (e && (e.type === "click" || e.type === "dblclick" || e.type === "mousedown" || e.type === "mouseup")) {
                const clickable = this.getClickableTarget(t)
                if (clickable && clickable !== t && Array.isArray(path)) {
                    const idx = path.indexOf(clickable)
                    if (idx > -1) {
                        t = clickable
                        path = path.slice(idx)
                    }
                }
            }
            this.props = {
                elementType: t.type, id: t.id, name: e.name,
                action: t.action, method: t.method, href: t.href, tagName: t.tagName,
                value: t.value != undefined ? t.value : t.innerText, checked: t.checked,
                form: t.form ? { id: t.form.id, name: t.form.name } : undefined,
                src: t.src, title: t.title
            }

            this.eventStart = (new Date()).getTime()

            this.xpath = this.getElementXPath(e, path)
            this.fullxpath = this.getElementFullXPath(e, path)
            this.csspath = this.getElementCssPath(e, path)
            this.fullcsspath = this.getElementFullCssPath(e, path)
            this.targetOptions = this.getLocatorCandidates(t)
            this.target = this.targetOptions.length ? this.targetOptions[0] : null
            this.frameStack = Array.isArray(frameInfo?.stack) ? frameInfo.stack.slice() : []
        }

        isStableId(id) {
            if (!id) return false
            if (/\d+$/.test(id) && /[-_]/.test(id)) return false
            if (/^(mat|cdk|mdc)-/i.test(id)) return false
            if (/^mat-mdc-/.test(id)) return false
            return true
        }

        getPreferredAttr(element) {
            if (!element || !element.getAttribute) return null
            const candidates = [
                "data-testid",
                "data-test",
                "data-qa",
                "aria-label",
                "name",
                "id"
            ]
            for (const attr of candidates) {
                const value = element.getAttribute(attr)
                if (!value) continue
                if (attr === "id" && !this.isStableId(value)) continue
                if (value.includes('"')) continue
                return { attr, value }
            }
            return null
        }

        getClickableTarget(element) {
            if (!element || !element.closest) return element
            return element.closest('button,a,input,textarea,select,[role="button"]') || element
        }

        getLocatorCandidates(element) {
            const candidates = []
            const pushUnique = (value) => {
                if (value && !candidates.includes(value)) {
                    candidates.push(value)
                }
            }
            if (!element || !element.getAttribute) return candidates

            const text = (element.innerText || element.textContent || '').trim()
            const tag = (element.tagName || '').toLowerCase()

            if (tag === 'a' && text) {
                pushUnique(`linkText=${text}`)
            }

            const preferredAttrs = [
                'data-testid',
                'data-test',
                'data-qa',
                'aria-label',
                'placeholder',
                'name',
                'id'
            ]
            preferredAttrs.forEach((attr) => {
                const value = element.getAttribute(attr)
                if (!value || value.includes('"')) return
                if (attr === 'id' && !this.isStableId(value)) return
                if (attr === 'id') {
                    pushUnique(`id=${value}`)
                    return
                }
                if (attr === 'name') {
                    pushUnique(`name=${value}`)
                    return
                }
                pushUnique(`css=[${attr}="${value}"]`)
            })

            if (this.csspath) {
                pushUnique(`css=${this.csspath}`)
            } else if (this.fullcsspath) {
                pushUnique(`css=${this.fullcsspath}`)
            }

            if (this.xpath) {
                pushUnique(`xpath=${this.xpath}`)
            }
            if (this.fullxpath) {
                pushUnique(`xpath=${this.fullxpath}`)
            }

            return candidates
        }

        stopPropagation() {
            if (this.event.stopPropagation)
                this.event.stopPropagation()
        }

        preventDefault() {
            if (this.event.preventDefault)
                this.event.preventDefault()
        }

        button() {
            if (this.event.button) {
                if (this.event.button == 2) {
                    return RightButton
                }
                return LeftButton
            } else if (this.event.which) {
                if (this.event.which > 1) {
                    return RightButton
                }
                return LeftButton
            }
            return UnknownButton
        }

        target() {
            let t = (this.event.target) ? this.event.target : this.event.srcElement
            if (t && t.nodeType == 3)
                return t.parentNode
            return t
        }

        keycode() {
            return (this.event.keyCode) ? this.event.keyCode : this.event.which
        }

        keychar() {
            return String.fromCharCode(this.keycode())
        }

        shiftkey() {
            if (this.event.shiftKey)
                return true
            return false
        }

        getPathIndex(pathPos, path) {
            let index = 0
            try {
                let element = path[pathPos]
                if (!element) return index
                let parentElement = element.parentElement ? element.parentElement : (path.length > (pathPos + 1) ? path[pathPos + 1] : null)
                if (parentElement && parentElement.querySelectorAll(':scope > ' + element.nodeName).length > 1) {
                    let list = parentElement.querySelectorAll(':scope > ' + element.nodeName)
                    for (let i = 0; i < list.length; i++) {
                        if (list[i].isSameNode(element)) {
                            index = i
                            if (element.getAttribute('PTK_originalIndex') && parseInt(element.getAttribute('PTK_originalIndex')) > 0) {
                                index = parseInt(element.getAttribute('PTK_originalIndex'))
                            }
                            break
                        }
                    }
                }
            } catch (e) {
            }
            return index
        }

        getElementXPath(element, path) {
            let paths = []
            for (let pathPos = 0; pathPos < path.length; pathPos++) {
                element = path[pathPos]
                if (element.nodeName == 'HTML')
                    break
                if (element.tagName.toUpperCase() == 'SVG' || (element.parentElement && element.parentElement.tagName.toUpperCase() == 'SVG'))
                    continue

                let xPath = element.localName ? element.localName.toLowerCase() : element.nodeName.toLowerCase()
                const preferred = this.getPreferredAttr(element)
                if (preferred) {
                    paths.splice(0, 0, "/" + xPath + '[@' + preferred.attr + '="' + preferred.value + '"]')
                    break
                }

                let index = this.getPathIndex(pathPos, path)
                let pathIndex = (index ? "[" + (index) + "]" : "")
                paths.splice(0, 0, xPath + pathIndex)
            }
            return "/" + paths.join("/")
        }

        getElementCssPath(element, path) {
            let paths = []
            for (let pathPos = 0; pathPos < path.length; pathPos++) {
                element = path[pathPos]
                if (element.nodeName == 'HTML')
                    break
                if (element.tagName.toUpperCase() == 'SVG' || (element.parentElement && element.parentElement.tagName.toUpperCase() == 'SVG'))
                    continue

                let cssPath = element.localName ? element.localName.toLowerCase() : element.nodeName.toLowerCase()
                const preferred = this.getPreferredAttr(element)
                if (preferred) {
                    paths.splice(0, 0, cssPath + '[' + preferred.attr + '="' + preferred.value + '"]')
                    break
                }

                let index = this.getPathIndex(pathPos, path)
                let pathIndex = (index ? ":nth-of-type(" + (index + 1) + ")" : "")
                paths.splice(0, 0, cssPath + pathIndex)

            }
            return paths.join(" > ")
        }

        getElementFullXPath(element, path) {
            let paths = []
            for (let pathPos = 0; pathPos < path.length; pathPos++) {
                element = path[pathPos]
                if (element.nodeName == 'HTML')
                    break
                if (element.tagName.toUpperCase() == 'SVG' || (element.parentElement && element.parentElement.tagName.toUpperCase() == 'SVG'))
                    continue

                let xPath = element.localName ? element.localName.toLowerCase() : element.nodeName.toLowerCase()
                let index = this.getPathIndex(pathPos, path)
                let pathIndex = (index ? "[" + (index) + "]" : "")
                paths.splice(0, 0, xPath + pathIndex)
            }
            return "/" + paths.join("/")
        }

        getElementFullCssPath(element, path) {
            let paths = []
            for (let pathPos = 0; pathPos < path.length; pathPos++) {
                element = path[pathPos]
                if (element.nodeName == 'HTML')
                    break
                if (element.tagName.toUpperCase() == 'SVG' || (element.parentElement && element.parentElement.tagName.toUpperCase() == 'SVG'))
                    continue

                let cssPath = element.localName ? element.localName.toLowerCase() : element.nodeName.toLowerCase()
                let index = this.getPathIndex(pathPos, path)
                let pathIndex = (index ? ":nth-of-type(" + (index + 1) + ")" : "")
                paths.splice(0, 0, cssPath + pathIndex)
            }
            return paths.join(" > ")
        }
    }

    class ptk_event_click extends ptk_event {
        constructor(e) {
            super(e)
            this.eventType = EventTypes.Click
            this.eventTypeName = "Click"
        }
    }

    class ptk_event_dblclick extends ptk_event {
        constructor(e) {
            super(e)
            this.eventType = EventTypes.DblClick
            this.eventTypeName = "DblClick"
        }
    }

    class ptk_event_keypress extends ptk_event {
        constructor(e) {
            super(e)
            this.eventType = EventTypes.KeyPress
            this.eventTypeName = "SetValue"
            this.data = this.keychar()
        }
    }

    class ptk_event_sendkeys extends ptk_event {
        constructor(e, data) {
            super(e)
            this.eventType = EventTypes.SendKeys
            this.eventTypeName = "SendKeys"
            this.data = data
        }
    }

    class ptk_event_navigate {
        constructor(startUrl) {
            this.eventStart = (new Date()).getTime()
            this.eventType = EventTypes.Navigate
            this.eventTypeName = "Navigate"
            this.data = startUrl
            this.hardNavigate = true
            this.isInitial = true
        }
    }

    class ptk_event_waitforurl {
        constructor(url, urlBefore = null) {
            this.eventStart = (new Date()).getTime()
            this.eventType = EventTypes.WaitForUrl
            this.eventTypeName = "WaitForUrl"
            this.data = url
            this.urlBefore = urlBefore
            this.hardNavigate = false
        }
    }

    class ptk_event_delay {
        constructor(e) {
            this.eventStart = (new Date()).getTime()
            this.eventType = EventTypes.Delay
            this.eventTypeName = "Delay"
        }
    }

    class ptk_event_setwindowsize {
        constructor(e) {
            this.eventStart = (new Date()).getTime()
            this.eventType = EventTypes.SetWindowSize
            this.eventTypeName = "SetWindowSize"
        }
    }

    class ptk_event_change extends ptk_event {
        constructor(e) {
            super(e)
            this.eventType = EventTypes.Change
            this.eventTypeName = "Change"
        }
    }

    class ptk_event_hover extends ptk_event {
        constructor(e) {
            super(e)
            this.eventType = EventTypes.Hover
            this.eventTypeName = "Hover"
        }
    }

    class ptk_testcase {
        constructor(items, log) {
            this.items = items ? items : []
            this.log = log ? log : ""
        }

        append(item) {
            if (item?.props?.id?.startsWith('ptk_recording_')) return
            if (!this.items) this.items = []
            let prev = {}
            if (this.items.length > 0) {
                prev = this.items[this.items.length - 1]
                prev.eventDuration = item.eventStart - prev.eventStart
            }
            if (!(item.eventType == EventTypes.Delay && prev.eventType == EventTypes.Delay)) {

                let clonedItem = {
                    windowIndex: windowIndex,
                    frameInfo: frameInfo,
                    frameStack: item.frameStack || (frameInfo?.stack || []),
                    eventType: item.eventType,
                    eventTypeName: item.eventTypeName,
                    data: item.data,
                    hardNavigate: item.hardNavigate || false,
                    isInitial: item.isInitial || false,
                    urlBefore: item.urlBefore || null,
                    props: item.props,
                    eventStart: item.eventStart,
                    xpath: item.xpath,
                    fullxpath: item.fullxpath,
                    csspath: item.csspath,
                    fullcsspath: item.fullcsspath,
                    target: item.target,
                    targetOptions: item.targetOptions || []
                }

                try {
                    clonedItem = cloneInto(clonedItem, window) //FF fix
                } catch (e) { }

                this.items.push(clonedItem)

                this.log += 'Step #' + this.items.length + ': ' + item.eventTypeName + '<br/>'
            }
            this.sync()
        }

        sync(items, log) {
            if (items) this.items = items
            if (log) this.log = log
            return browser.storage.local.set({ "ptk_recording_items": this.items, "ptk_recording_log": this.log })
        }

        peek() {
            if (!this.items || this.items.length === 0) return undefined
            return this.items[this.items.length - 1]
        }

        poke(o) {
            if (!this.items || this.items.length === 0) return
            this.items[this.items.length - 1] = o
        }

        pop(o) {
            if (!this.items || this.items.length === 0) return
            this.items.pop()
        }
    }

    class ptk_recorder {
        constructor() {
            this.timer = null
            this.clickDelay = 180
            this.waitClick = false
            this.testcase = new ptk_testcase()
            this._routeDebounceMs = 150
            this._routeTimer = null
            this._lastRecordedUrl = null
            this._historyWrapped = false
            this._originalHistory = {}

            browser.storage.local.get(['ptk_recording', 'ptk_recording_items', 'ptk_recording_timing', 'ptk_recording_log', 'ptk_double_click']).then(function (result) {

                this.doubleClick = result.ptk_double_click
                if (!isIframe) {
                    this.testcase = new ptk_testcase(result.ptk_recording_items, result.ptk_recording_log)
                    if (this.testcase.items.length == 0) {
                        let evtNavigate = new ptk_event_navigate(result.ptk_recording?.startUrl)
                        evtNavigate.eventDuration = evtNavigate.eventStart - gstartTime
                        this.testcase.append(evtNavigate)
                        this._lastRecordedUrl = evtNavigate.data
                    }

                    setTimeout(function () {
                        if (this.testcase.peek().eventType != EventTypes.Delay) {
                            let evtDelay = new ptk_event_delay()
                            this.testcase.append(evtDelay)
                        }
                    }.bind(this), windowIndex ? 1000 : 0)
                }
            this.init()
            this.start()
        }.bind(this))
        }

        init() {

            if (isIframe) {
                windowIndex = window.top.opener ? 1 : 0
            } else {
                this.broadcastFrameInfo([])
            }
        }

        broadcastFrameInfo(parentStack = []) {
            let frames = document.getElementsByTagName('iframe')
            if (!frames || !frames.length) return
            for (let i = 0; i < frames.length; i++) {
                let item = {
                    index: i, name: frames[i].name ? frames[i].name : "",
                    id: frames[i].id ? frames[i].id : "",
                    title: frames[i].title ? frames[i].title : "",
                    src: frames[i].src ? frames[i].src : ""
                }
                item.stack = parentStack.concat([item])
                frames[item.index].contentWindow.postMessage({ channel: "frameInfo", item: item, testcase: this.testcase }, '*')
            }
        }

        start() {
            this.window = window
            this.captureEvents()
            // let script = document.createElement('script')
            // script.textContent = '(' + function () {
            //     let overloadStopPropagation = Event.prototype.stopPropagation;
            //     Event.prototype.stopPropagation = function () {
            //         overloadStopPropagation.apply(this, arguments);
            //         this.target.dispatchEvent(new MouseEvent('customRecorderEvent', this))
            //     };
            // } + ')();';
            // (document.head || document.documentElement).appendChild(script)
            // script.parentNode.removeChild(script)
        }

        stop() {
            this.releaseEvents()
            return
        }

        captureEvents() {
            this.onclick = this.onclick.bind(this)
            document.addEventListener("click", this.onclick)

            this.onmouseover = this.onmouseover.bind(this)
            document.addEventListener("mouseover", this.onmouseover, true)

            if (this.doubleClick) {
                this.ondblclick = this.ondblclick.bind(this)
                document.addEventListener("dblclick", this.ondblclick)
            }

            this.onkeypress = this.onkeypress.bind(this)
            document.addEventListener("keypress", this.onkeypress)

            this.onkeydown = this.onkeydown.bind(this)
            document.addEventListener("keydown", this.onkeydown)

            this.oninput = this.oninput.bind(this)
            document.addEventListener("input", this.oninput)

            this.onpaste = this.onpaste.bind(this)
            document.addEventListener("paste", this.onpaste)

            this.onchange = this.onchange.bind(this)
            document.addEventListener("change", this.onchange)

            this.onselect = this.onselect.bind(this)
            document.addEventListener("select", this.onselect)

            this.oncustomevent = this.oncustomevent.bind(this)
            document.addEventListener("customRecorderEvent", this.oncustomevent)
            this._initRouteTracking()

            this.mutationObserver = new MutationObserver(function (mutations) {
                mutations.forEach(function (mutation) {
                    if (mutation.target.tagName == 'HEAD' || mutation.target.tagName == 'SCRIPT' || mutation.target.tagName == 'STYLE' ||
                        (mutation.target.id && mutation.target.id.toLowerCase().startsWith('ptk_')) ||
                        (mutation.target.parentElement && mutation.target.parentElement.tagName == 'BODY')) {
                        return
                    }

                    if (mutation.type == 'childList' && mutation.addedNodes.length > 0) {
                        let addedNode = mutation.addedNodes[0]
                        let count = 0
                        for (let i = 0; i < mutation.target.children.length; i++) {
                            if (mutation.target.children[i].tagName == addedNode.tagName) {
                                if (!mutation.target.children[i].getAttribute("PTK_originalIndex"))
                                    mutation.target.children[i].setAttribute("PTK_originalIndex", count)
                                count++
                            }
                        }
                    }
                    if (mutation.type == 'childList' && mutation.removedNodes.length > 0) {
                        let removedNode = mutation.removedNodes[0]
                        let count = 0
                        for (let i = 0; i < mutation.target.children.length; i++) {
                            if (mutation.target.children[i].tagName == removedNode.tagName && mutation.target.children[i].getAttribute("PTK_originalIndex")) {
                                count = parseInt(mutation.target.children[i].getAttribute("PTK_originalIndex"))
                                if (count > -1) mutation.target.children[i].setAttribute("PTK_originalIndex", (count - 1))
                            }
                        }
                    }
                })
            })

            this.mutationObserver.observe(document, {
                attributes: true,
                subtree: true,
                attributeOldValue: true,
                attributeFilter: ["class"],
                childList: true
            })
        }

        releaseEvents() {
            document.removeEventListener("click", this.onclick)
            document.removeEventListener("mouseover", this.onmouseover, true)
            if (this.doubleClick) document.removeEventListener("dblclick", this.ondblclick)
            document.removeEventListener("keypress", this.onkeypress)
            document.removeEventListener("keydown", this.onkeydown)
            document.removeEventListener("input", this.oninput)
            document.removeEventListener("paste", this.onpaste)
            document.removeEventListener("change", this.onchange)
            document.removeEventListener("select", this.onselect)
            document.removeEventListener("customRecorderEvent", this.oncustomevent)
            this.mutationObserver.disconnect()
            this._teardownRouteTracking()
        }

        _initRouteTracking() {
            if (isIframe) return
            this._routeHandler = this._routeHandler || this._handleRouteChange.bind(this)
            window.addEventListener('popstate', this._routeHandler, true)
            window.addEventListener('hashchange', this._routeHandler, true)
            this._wrapHistory()
        }

        _teardownRouteTracking() {
            if (this._routeHandler) {
                window.removeEventListener('popstate', this._routeHandler, true)
                window.removeEventListener('hashchange', this._routeHandler, true)
            }
            if (this._routeTimer) {
                clearTimeout(this._routeTimer)
                this._routeTimer = null
            }
            this._unwrapHistory()
        }

        _wrapHistory() {
            if (this._historyWrapped) return
            if (!window.history || !window.history.pushState) return
            this._historyWrapped = true
            this._originalHistory.pushState = window.history.pushState
            this._originalHistory.replaceState = window.history.replaceState
            const self = this
            window.history.pushState = function (...args) {
                const res = self._originalHistory.pushState.apply(this, args)
                self._handleRouteChange()
                return res
            }
            window.history.replaceState = function (...args) {
                const res = self._originalHistory.replaceState.apply(this, args)
                self._handleRouteChange()
                return res
            }
        }

        _unwrapHistory() {
            if (!this._historyWrapped) return
            if (this._originalHistory.pushState) {
                window.history.pushState = this._originalHistory.pushState
            }
            if (this._originalHistory.replaceState) {
                window.history.replaceState = this._originalHistory.replaceState
            }
            this._historyWrapped = false
        }

        _handleRouteChange() {
            if (isIframe) return
            const url = window.location.href
            if (!url) return
            if (this._routeTimer) {
                clearTimeout(this._routeTimer)
            }
            this._routeTimer = setTimeout(() => {
                this._routeTimer = null
                if (this._lastRecordedUrl === url) return
                const before = this._lastRecordedUrl
                this._lastRecordedUrl = url
                const evt = new ptk_event_waitforurl(url, before)
                this.testcase.append(evt)
            }, this._routeDebounceMs)
        }

        clickaction(evt) {
            let elData = null

            if (evt.elementType == "checkbox" || evt.elementType == "radio") {
                elData = new ptk_event_keypress(evt.event)
            }
            let addNewEvent = true
            let last = this.testcase.peek()
            if (last != undefined && last.eventType == evt.eventType && (evt.eventStart - last.eventStart) < 1000) {
                addNewEvent = false
            }

            if (addNewEvent) this.testcase.append(evt)
            if (elData != null) this.testcase.append(elData)

        }

        onclick(e) {

            let evt = new ptk_event_click(e)
            if (e?.srcElement?.id?.startsWith('ptk_recording') || evt.xpath == "/") return false

            if (evt.button() == LeftButton) {
                if (this.doubleClick && !this.waitClick) {
                    this.waitClick = true
                    this.timer = setTimeout(function () {
                        this.clickaction(evt)
                        this.waitClick = false
                    }.bind(this), this.clickDelay)
                }
                else {
                    this.clickaction(evt)
                }
            }
            return true
        }

        ondblclick(e) {

            let evt = new ptk_event_dblclick(e)
            if (e?.srcElement?.id?.startsWith('ptk_recording') || evt.xpath == "/") return false

            clearTimeout(this.timer)
            this.waitClick = false
            if (evt.button() == LeftButton) {
                this.clickaction(evt)
            }
            return true
        }

        oncustomevent(e) {
            if (e?.srcElement?.id?.startsWith('ptk_recording'))
                return false
            let evt = new ptk_event_click(e)
            if (evt.button() == LeftButton && (e.x != 0 && e.y != 0)) {
                this.clickaction(evt)
            }
            return true
        }

        onmouseover(e) {
            const target = e.target
            if (!target) return false
            if (target?.id?.startsWith('ptk_recording')) return false
            const ariaHasPopup = target.getAttribute && target.getAttribute('aria-haspopup')
            const role = target.getAttribute && target.getAttribute('role')
            const dataMenu = target.getAttribute && target.getAttribute('data-menu')
            const hasMenuRole = role === 'menu' || role === 'menuitem'
            if (!ariaHasPopup && !hasMenuRole && !dataMenu) return false

            let evt = new ptk_event_hover(e)
            if (evt.xpath == "/") return false
            this.testcase.append(evt)
            return true
        }

        onkeypress(e) {
            e.stopImmediatePropagation()
            let evt = new ptk_event_keypress(e)
            if (evt.keycode() == 9 || evt.keycode() == 13) return false
            let last = this.testcase.peek()

            if (last && last.eventType == EventTypes.KeyPress && last.xpath == evt.xpath) {
                last.data = last.data + evt.keychar()
                last.eventStart = (new Date()).getTime()
                this.testcase.poke(last)
                this.testcase.sync()
            } else {
                this.testcase.append(evt)
            }
            return false
        }

        onkeydown(e) {
            e.stopImmediatePropagation()
            let evt = new ptk_event(e)
            if (evt.keycode() == 9 || evt.keycode() == 13) {
                const token = evt.keycode() == 9 ? '${KEY_TAB}' : '${KEY_ENTER}'
                const sendEvt = new ptk_event_sendkeys(e, token)
                this.testcase.append(sendEvt)
                return false
            }
            //backspace or delete
            if (evt.keycode() == 8 || evt.keycode() == 46) {
                let selectedTxt = document.getSelection().toString(),
                    posStart = evt.event.target.selectionStart,
                    posEnd = evt.event.target.selectionEnd,
                    last = this.testcase.peek()
                if (last.eventType == EventTypes.Click) {
                    this.testcase.pop()
                    last = this.testcase.peek()
                }
                if (evt.keycode() == 46) posStart++

                if (selectedTxt == "") {
                    if (last.eventType == EventTypes.KeyPress) {
                        let text = last.data
                        if (last.data.length == 0) {
                            return false
                        } else if (last.data.length == posStart) { //deleted at the end
                            text = last.data.substring(0, posStart - 1)
                        } else {
                            text = last.data.substring(0, posStart - 1)
                            text += last.data.substring(posStart, last.data.length)
                        }
                        last.data = text
                        last.eventStart = (new Date()).getTime()
                    }
                } else {
                    last.data = last.data.replace(selectedTxt, "")
                }
                this.testcase.poke(last)
            }
            this.testcase.sync()
            return false
        }

        oninput(e) {
            let t = e.target
            if (!t || !('value' in t)) return
            if (t.type == 'password' && t.value == '') return

            let evt = new ptk_event_keypress(e)
            evt.data = t.value

            let last = this.testcase.peek()
            if (last && last.eventType == EventTypes.KeyPress && last.xpath == evt.xpath) {
                if ((evt.eventStart - last.eventStart) < 300) {
                    return
                }
            }
            this.testcase.append(evt)
        }

        onpaste(e) {
            let evt = new ptk_event_keypress(e)
            evt.data = e.clipboardData.getData('Text')
            this.testcase.append(evt)
        }

        onchange(e) {
            if (e.srcElement.type != 'select-one') return
            let evt = new ptk_event_keypress(e)
            evt.data = evt.props.value
            this.testcase.append(evt)
        }

        onselect(e) {

        }
    }


    if (!window.ptk_recorder) window.ptk_recorder = new ptk_recorder()

    window.addEventListener("message", (event) => {
        if (!isIframe && event.data.channel == 'sync') {
            if (window.ptk_recorder?.testcase) window.ptk_recorder.testcase.sync(event.data.items, event.data.log)
        }
        else if (isIframe && event.data.channel == 'frameInfo') {
            frameInfo = event.data.item
            if (!Array.isArray(frameInfo?.stack)) {
                frameInfo.stack = [frameInfo]
            }
            window.ptk_recorder.testcase = new ptk_testcase(event.data.testcase.items, event.data.testcase.log)
            window.ptk_recorder?.broadcastFrameInfo(frameInfo.stack)
        }
    })

    browser.storage.onChanged.addListener(function (changes, namespace) {
        if (changes['ptk_recording_items']) {
            if (!window.ptk_recorder)
                window.ptk_recorder = new ptk_recorder()

            window.ptk_recorder.testcase.items = changes['ptk_recording_items'].newValue
        }

        if (changes['ptk_recording_log']) {
            window.ptk_recorder.testcase.log = changes['ptk_recording_log'].newValue
        }
    })

    setTimeout(function () {
        browser.storage.local.get("ptk_recording_timing").then(function (result) {
            let entries = performance.getEntries().filter(v => ['navigation', 'resource'].includes(v.entryType))
            let storage = result.ptk_recording_timing
            let s = new Set([...storage, ...entries])

            browser.storage.local.set({
                "ptk_recording_timing": JSON.parse(JSON.stringify(Array.from(s)))
            })
        })
    }, isIframe ? 20 : 0)

})()
