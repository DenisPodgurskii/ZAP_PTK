const CALLS = Object.freeze({
    "tabs.sendMessage": (api, args) => api.tabs.sendMessage(...args),
    "tabs.get": (api, args) => api.tabs.get(...args),
    "tabs.create": (api, args) => api.tabs.create(...args),
    "tabs.update": (api, args) => api.tabs.update(...args),
    "tabs.reload": (api, args) => api.tabs.reload(...args),
    "tabs.remove": (api, args) => api.tabs.remove(...args),
    "windows.get": (api, args) => api.windows.get(...args),
    "windows.create": (api, args) => api.windows.create(...args),
    "windows.remove": (api, args) => api.windows.remove(...args),
    "scripting.registerContentScripts": (api, args) => api.scripting.registerContentScripts(...args),
    "scripting.unregisterContentScripts": (api, args) => api.scripting.unregisterContentScripts(...args),
    "scripting.injectFile": (api, [tabId, file, allFrames = false]) => api.scripting.executeScript({ target: { tabId, allFrames }, files: [file] }),
    "scripting.probeWindowName": (api, [tabId, marker]) => api.scripting.executeScript({
        target: { tabId }, world: "MAIN",
        func: value => String(window.name || "").includes(`ptk-xss:${String(value || "").trim()}`), args: [marker]
    }),
    "scripting.probeDomMarker": (api, [tabId, marker, attributeName]) => api.scripting.executeScript({
        target: { tabId }, world: "MAIN",
        func: (value, name) => {
            const root = document.documentElement || document.body
            const current = String(root?.getAttribute?.(name) || "")
            return current === value || current.split(/\s+/).includes(value)
        }, args: [marker, attributeName]
    }),
    "scripting.markAttackTab": (api, [tabId, marker, domOnly]) => api.scripting.executeScript({
        target: { tabId, allFrames: true },
        func: (name, markDomOnly) => {
            const attrName = name === "ptk_browser_nav_attack_tab" ? "data-ptk-browser-nav-attack-tab" : "data-ptk-spa-attack-tab"
            const root = document.documentElement || document.body
            root?.setAttribute?.(attrName, "1")
            if (!markDomOnly && (!window.name || !window.name.includes(name))) window.name = `${window.name ? `${window.name} ` : ""}${name}`
        }, args: [marker, domOnly]
    }),
})

function waitForTabState(api, tabId, timeoutMs = 8000, { requireNavigation = false } = {}) {
    const normalizedTabId = Number(tabId)
    if (!Number.isInteger(normalizedTabId) || normalizedTabId < 0) {
        return Promise.resolve({ ready: false, reason: "invalid_tab", status: null })
    }
    return new Promise(resolve => {
        let settled = false
        let started = false
        let timer = null
        const finish = (ready, reason, tab = null) => {
            if (settled) return
            settled = true
            if (timer) clearTimeout(timer)
            try { api.tabs.onUpdated.removeListener(listener) } catch (_) { }
            resolve({
                ready, reason, status: tab?.status || null,
                url: tab?.url || tab?.pendingUrl || null
            })
        }
        const listener = (updatedTabId, info, tab) => {
            if (Number(updatedTabId) !== normalizedTabId) return
            if (info?.status === "loading" || typeof info?.url === "string") started = true
            if ((!requireNavigation || started) && (info?.status === "complete" || tab?.status === "complete")) {
                finish(true, requireNavigation ? "navigation_complete" : "updated_complete", tab)
            }
        }
        api.tabs.onUpdated.addListener(listener)
        timer = setTimeout(() => finish(false, requireNavigation
            ? (started ? "navigation_incomplete" : "navigation_not_observed")
            : "timeout"), Math.max(250, Number(timeoutMs) || 8000))
        Promise.resolve(api.tabs.get(normalizedTabId)).then(tab => {
            if (!requireNavigation && tab?.status === "complete") finish(true, "already_complete", tab)
        }).catch(error => finish(false, error?.message || "tab_lookup_failed"))
    })
}

function serializeWebSocketData(value) {
    try {
        if (typeof value === "string") return value.slice(0, 2048)
        if (value instanceof ArrayBuffer) return `[arraybuffer:${value.byteLength}]`
        if (ArrayBuffer.isView(value)) return `[typedarray:${value.byteLength}]`
        if (typeof Blob !== "undefined" && value instanceof Blob) return `[blob:${value.size}]`
        return String(value ?? "").slice(0, 2048)
    } catch (_) {
        return "[unserializable_websocket_data]"
    }
}

async function executeWebSocketExchange(adapter, operation) {
    const api = adapter.browserApi
    const options = operation.args?.[0] || {}
    const targetUrl = String(options.url || "").split("#")[0]
    if (!targetUrl || typeof globalThis.WebSocket !== "function") return null
    const desiredHeaders = Array.isArray(options.desiredHeaders) ? options.desiredHeaders : []
    const touchedNames = new Set((options.touchedHeaderNames || []).map(value => String(value || "").toLowerCase()))
    return new Promise(resolve => {
        let done = false
        let socket = null
        let timeoutId = null
        let idleCloseId = null
        const state = {
            url: targetUrl, opened: false, closed: false, closeCode: null, closeReason: null,
            cleanClose: null, error: null, requestHeaders: [], responseHeaders: [],
            statusCode: null, statusLine: null, messages: [],
            sentPayload: options.sendPayload == null ? null : serializeWebSocketData(options.sendPayload)
        }
        const beforeHeaders = request => {
            if (request?.type !== "websocket" || String(request?.url || "").split("#")[0] !== targetUrl) return undefined
            const merged = (request.requestHeaders || []).filter(header => !touchedNames.has(String(header?.name || "").toLowerCase()))
            for (const header of desiredHeaders) {
                const name = String(header?.name || "").trim()
                if (name && touchedNames.has(name.toLowerCase())) merged.push({ name, value: String(header?.value ?? "") })
            }
            state.requestHeaders = cloneSafe(merged)
            return { requestHeaders: merged }
        }
        const receivedHeaders = response => {
            if (response?.type !== "websocket" || String(response?.url || "").split("#")[0] !== targetUrl) return undefined
            state.responseHeaders = cloneSafe(response.responseHeaders || [])
            state.statusLine = response.statusLine || null
            if (Number.isFinite(Number(response.statusCode))) state.statusCode = Number(response.statusCode)
            return undefined
        }
        const cleanup = () => {
            try { api.webRequest.onBeforeSendHeaders.removeListener(beforeHeaders) } catch (_) { }
            try { api.webRequest.onHeadersReceived.removeListener(receivedHeaders) } catch (_) { }
            clearTimeout(timeoutId); clearTimeout(idleCloseId)
            try { if (socket?.readyState === globalThis.WebSocket.OPEN) socket.close(1000, "ptk-dast-websocket-complete") } catch (_) { }
        }
        const finish = () => { if (done) return; done = true; cleanup(); resolve(state) }
        const scheduleClose = delay => {
            clearTimeout(idleCloseId)
            idleCloseId = setTimeout(() => {
                try { if (socket?.readyState === globalThis.WebSocket.OPEN) socket.close(1000, "ptk-dast-websocket-idle") } catch (_) { }
                setTimeout(finish, 25)
            }, delay)
        }
        const blocking = options.blocking === true ? ["blocking"] : []
        api.webRequest.onBeforeSendHeaders.addListener(beforeHeaders, { urls: ["<all_urls>"], types: ["websocket"] }, ["requestHeaders", ...(options.extraInfoSpec || []), ...blocking])
        api.webRequest.onHeadersReceived.addListener(receivedHeaders, { urls: ["<all_urls>"], types: ["websocket"] }, ["responseHeaders", ...(options.extraInfoSpec || []), ...blocking])
        timeoutId = setTimeout(finish, Math.max(250, Number(options.timeoutMs) || 2500))
        try {
            socket = Array.isArray(options.protocols) && options.protocols.length
                ? new globalThis.WebSocket(targetUrl, options.protocols)
                : new globalThis.WebSocket(targetUrl)
        } catch (error) { state.error = error?.message || String(error); finish(); return }
        socket.addEventListener("open", () => {
            state.opened = true
            if (state.statusCode == null) { state.statusCode = 101; state.statusLine ||= "HTTP/1.1 101 Switching Protocols" }
            if (options.sendPayload != null) {
                try { socket.send(options.sendPayload) } catch (error) { state.error = error?.message || String(error) }
            }
            scheduleClose(options.sendPayload == null ? 125 : 250)
        })
        socket.addEventListener("message", event => { state.messages.push(serializeWebSocketData(event?.data)); scheduleClose(125) })
        socket.addEventListener("error", event => { state.error ||= event?.message || "websocket_error" })
        socket.addEventListener("close", event => {
            state.closed = true; state.closeCode = Number(event?.code) || null
            state.closeReason = event?.reason || null; state.cleanClose = event?.wasClean === true
            setTimeout(finish, 25)
        })
    })
}

async function executeH2Fetch(adapter, operation) {
    const api = adapter.browserApi
    const payload = operation.args?.[0] || {}
    const requestUrl = String(payload.url || "").trim()
    if (!requestUrl) return null
    let tabId = null
    let lease = null
    const entry = { ownerId: operation.ownerId, active: true, tabId: null, lease: null }
    adapter.captureOperations.add(entry)
    let protocol = null
    let statusCode = null
    let responseHeaders = []
    let statusLine = null
    const onEvent = event => {
        const record = event.record || {}
        const params = { response: record.response }
        if (event.type !== 'response' || record.tabId !== tabId || String(params.response?.url || record.url || '') !== requestUrl) return
        protocol = String(params?.response?.protocol || "").toLowerCase() || null
        statusCode = Number(params?.response?.status) || null
        responseHeaders = Object.entries(params?.response?.headers || {}).map(([name, value]) => ({ name, value: String(value ?? "") }))
        statusLine = params?.response?.statusText
            ? `${String(protocol || "HTTP/2").toUpperCase()} ${statusCode} ${params.response.statusText}`
            : `${String(protocol || "HTTP/2").toUpperCase()} ${statusCode || ""}`.trim()
    }
    try {
        const tab = await api.tabs.create({ url: "about:blank", active: false })
        tabId = tab?.id
        if (!tabId) return null
        entry.tabId = tabId
        if (!entry.active || !adapter.browserCaptureManager) throw new Error('capture_helper_unavailable')
        lease = entry.lease = await adapter.browserCaptureManager.acquireH2Helper({
            ownerId: operation.ownerId, tabId, requestUrl,
            isOperationActive: () => entry.active && adapter.captureOperations.has(entry)
        })
        lease.subscribe(onEvent)
        const result = await lease.fetch({ url: requestUrl, method: payload.method || "GET", headers: payload.headers || {},
            body: payload.body, credentials: payload.credentials || "include", followRedirect: payload.followRedirect !== false })
        if (!entry.active) throw new Error('capture_owner_unavailable')
        return {
            protocol,
            success: /(^|\/)h2$/i.test(String(protocol || "")) || /^http\/2/i.test(String(protocol || "")),
            request: { url: requestUrl, method: payload.method || "GET", headers: cloneSafe(payload.originalHeaders || []) },
            response: {
                statusCode: Number(result?.status) || statusCode || null,
                statusLine, headers: responseHeaders.length ? responseHeaders : cloneSafe(result?.headers || []),
                body: String(result?.body || "")
            }
        }
    } catch (error) {
        return {
            protocol, success: false,
            request: { url: requestUrl, method: payload.method || "GET", headers: cloneSafe(payload.originalHeaders || []) },
            response: { statusCode, statusLine: error?.message || "h2_transport_failed", headers: responseHeaders, body: "" },
            error: error?.message || String(error)
        }
    } finally {
        entry.active = false
        await adapter.cleanupCaptureOperation(entry, 'operation_complete')
    }
}

const NAMED_OPERATIONS = Object.freeze({
    "dast.tabs.waitReady": (adapter, operation) => waitForTabState(adapter.browserApi, operation.args?.[0], operation.args?.[1]),
    "dast.tabs.navigateAndWait": async (adapter, operation) => {
        const [tabId, url, timeoutMs] = operation.args || []
        const ready = waitForTabState(adapter.browserApi, tabId, timeoutMs, { requireNavigation: true })
        await adapter.browserApi.tabs.update(tabId, { url })
        return ready
    },
    "dast.tabs.reloadAndWait": async (adapter, operation) => {
        const [tabId, timeoutMs] = operation.args || []
        const ready = waitForTabState(adapter.browserApi, tabId, timeoutMs)
        await adapter.browserApi.tabs.reload(tabId)
        return ready
    },
    "dast.tabs.navigationWatchStart": (adapter, operation) => adapter.startNavigationWatch(operation),
    "dast.tabs.navigationWatchWait": (adapter, operation) => adapter.waitNavigationWatch(operation.args?.[0]),
    "dast.tabs.navigationWatchCancel": (adapter, operation) => adapter.cancelNavigationWatch(operation.args?.[0], operation.args?.[1]),
    "dast.dialog.attach": (adapter, operation) => adapter.attachDialogAutoDismiss(operation.args?.[0], operation.ownerId),
    "dast.dialog.detach": (adapter, operation) => adapter.detachDialogAutoDismiss(operation.args?.[0]),
    "dast.websocket.exchange": executeWebSocketExchange,
    "dast.h2.fetch": executeH2Fetch
})

const EVENTS = Object.freeze({
    "tabs.onUpdated": api => api.tabs.onUpdated,
    "tabs.onRemoved": api => api.tabs.onRemoved,
    "windows.onRemoved": api => api.windows.onRemoved,
    "webRequest.onBeforeRequest": api => api.webRequest.onBeforeRequest,
    "webRequest.onBeforeSendHeaders": api => api.webRequest.onBeforeSendHeaders,
    "webRequest.onHeadersReceived": api => api.webRequest.onHeadersReceived,
    "webRequest.onCompleted": api => api.webRequest.onCompleted,
    "webRequest.onErrorOccurred": api => api.webRequest.onErrorOccurred
})

function cloneSafe(value) {
    if (value === undefined) return null
    if (typeof structuredClone === "function") return structuredClone(value)
    return JSON.parse(JSON.stringify(value))
}

export class DastPrivilegedBrowserAdapter {
    constructor({ browserApi = globalThis.browser, onEvent = null } = {}) {
        this.browserApi = browserApi
        this.onEvent = onEvent
        this.subscriptions = new Map()
        this.navigationWatches = new Map()
        this.dialogTabs = new Map()
        this.dialogListener = null
        this.captureOperations = new Set()
    }
    setBrowserCaptureManager(manager) { this.browserCaptureManager = manager; return this }
    isBrowserCaptureOwnerActive({ ownerId, tabId }) {
        return [...this.captureOperations].some(entry => entry.active && entry.ownerId === ownerId && entry.tabId === tabId)
            || [...this.dialogTabs.values()].some(entry => entry.active && entry.ownerId === ownerId && entry.tabId === tabId)
    }
    async execute(operation = {}) {
        if (operation.type === "browser_subscribe") return this.subscribe(operation)
        if (operation.type === "browser_unsubscribe") return this.unsubscribe(operation.subscriptionId, operation.ownerId)
        if (operation.type === "browser_cleanup") return this.cleanup(operation.ownerId)
        const resource = operation.method === "dast.tabs.navigationWatchCancel" || operation.method === "dast.tabs.navigationWatchWait"
            ? this.navigationWatches.get(String(operation.args?.[0] || ""))
            : operation.method === "dast.dialog.detach" ? this.dialogTabs.get(Number(operation.args?.[0])) : null
        if (resource && resource.ownerId !== operation.ownerId) throw new Error("foreign_browser_owner")
        if (Object.hasOwn(NAMED_OPERATIONS, operation.method)) {
            return cloneSafe(await NAMED_OPERATIONS[operation.method](this, operation))
        }
        if (!Object.hasOwn(CALLS, operation.method)) throw new Error("unsupported_dast_browser_operation")
        const call = CALLS[operation.method]
        const args = Array.isArray(operation.args) ? cloneSafe(operation.args) : []
        const result = await call(this.browserApi, args)
        if (result === false && ["tabs.remove", "windows.remove", "scripting.unregisterContentScripts"].includes(operation.method)) throw new Error("browser_cleanup_unproved")
        return cloneSafe(result)
    }
    subscribe(operation = {}) {
        const { subscriptionId, event, ownerId } = operation
        if (!subscriptionId || !ownerId) throw new Error("unsupported_dast_browser_subscription")
        if (this.subscriptions.has(subscriptionId)) {
            if (this.subscriptions.get(subscriptionId).ownerId !== ownerId) throw new Error("foreign_browser_owner")
            return { subscribed: true, duplicate: true }
        }
        if (event === "dast.oast") return this.subscribeOast(operation)
        if (!Object.hasOwn(EVENTS, event)) throw new Error("unsupported_dast_browser_subscription")
        const target = EVENTS[event](this.browserApi)
        if (!target?.addListener || !target?.removeListener) throw new Error("dast_browser_event_unavailable")
        const listener = (...args) => this.onEvent?.({ type: "browser_event", subscriptionId, ownerId, event, args: cloneSafe(args) })
        const filter = operation.filter == null ? null : cloneSafe(operation.filter)
        const extraInfoSpec = operation.extraInfoSpec == null ? null : cloneSafe(operation.extraInfoSpec)
        if (filter && extraInfoSpec) target.addListener(listener, filter, extraInfoSpec)
        else if (filter) target.addListener(listener, filter)
        else target.addListener(listener)
        this.subscriptions.set(subscriptionId, { ownerId, target, listener })
        return { subscribed: true }
    }
    subscribeOast(operation = {}) {
        const { subscriptionId, ownerId } = operation
        const domains = new Set((operation.options?.domains || []).map(value => String(value || "").trim().toLowerCase()).filter(Boolean))
        const target = this.browserApi?.webRequest?.onBeforeRequest
        if (!target?.addListener || !target?.removeListener || !domains.size) throw new Error("dast_oast_probe_unavailable")
        const listener = request => {
            const url = String(request?.url || "")
            const lower = url.toLowerCase()
            const domain = [...domains].find(value => lower.includes(value))
            if (!domain) return
            this.onEvent?.({
                type: "browser_event", subscriptionId, ownerId, event: "dast.oast",
                args: [{
                    domain, url, method: request?.method || null,
                    tabId: Number.isFinite(request?.tabId) ? request.tabId : null,
                    frameId: Number.isFinite(request?.frameId) ? request.frameId : null,
                    requestId: request?.requestId || null
                }]
            })
        }
        target.addListener(listener, {
            urls: ["<all_urls>"],
            types: operation.options?.requestFilters || ["xmlhttprequest", "main_frame", "sub_frame", "other"]
        })
        this.subscriptions.set(subscriptionId, { ownerId, target, listener })
        return { subscribed: true }
    }

    startNavigationWatch(operation = {}) {
        const [tabId, timeoutMs, watchIdArg] = operation.args || []
        const watchId = String(watchIdArg || operation.operationId || "")
        if (!watchId) throw new Error("missing_navigation_watch_id")
        if (this.navigationWatches.has(watchId)) {
            if (this.navigationWatches.get(watchId).ownerId !== operation.ownerId) throw new Error("foreign_browser_owner")
            return { watchId, duplicate: true }
        }
        let finish
        const promise = new Promise(resolve => { finish = resolve })
        const normalizedTabId = Number(tabId)
        let started = false
        let settled = false
        const complete = (ready, reason, tab = null) => {
            if (settled) return
            this.browserApi.tabs.onUpdated.removeListener(entry.listener)
            settled = true
            clearTimeout(entry.timer)
            entry.result = { ready, reason, status: tab?.status || null, url: tab?.url || tab?.pendingUrl || null }
            finish(entry.result)
        }
        const entry = {
            ownerId: operation.ownerId,
            promise,
            result: null,
            listener: (updatedTabId, info, tab) => {
                if (Number(updatedTabId) !== normalizedTabId) return
                if (info?.status === "loading" || typeof info?.url === "string") started = true
                if (started && (info?.status === "complete" || tab?.status === "complete")) complete(true, "navigation_complete", tab)
            },
            timer: null,
            complete
        }
        this.browserApi.tabs.onUpdated.addListener(entry.listener)
        entry.timer = setTimeout(() => complete(false, started ? "navigation_incomplete" : "navigation_not_observed"), Math.max(250, Number(timeoutMs) || 8000))
        this.navigationWatches.set(watchId, entry)
        return { watchId, duplicate: false }
    }
    async waitNavigationWatch(watchId) {
        const key = String(watchId || "")
        const entry = this.navigationWatches.get(key)
        if (!entry) return { ready: false, reason: "navigation_watch_lost", status: null }
        const result = entry.result || await entry.promise
        this.navigationWatches.delete(key)
        return result
    }
    cancelNavigationWatch(watchId, reason = "cancelled") {
        const key = String(watchId || "")
        const entry = this.navigationWatches.get(key)
        if (!entry) return { cancelled: false }
        entry.complete(false, reason)
        this.navigationWatches.delete(key)
        return { cancelled: true }
    }

    async attachDialogAutoDismiss(tabId, ownerId = null) {
        const normalized = Number(tabId)
        if (!Number.isInteger(normalized) || normalized < 0 || !ownerId || !this.browserCaptureManager) return false
        const previous = this.dialogTabs.get(normalized)
        if (previous) return previous.ownerId === ownerId ? previous.promise : false
        const entry = { ownerId, tabId: normalized, active: true, lease: null }
        this.dialogTabs.set(normalized, entry)
        entry.promise = (async () => {
            try {
                const tab = await this.browserApi.tabs.get(normalized)
                if (!entry.active) return false
                entry.lease = await this.browserCaptureManager.acquire({
                    ownerId, tabId: normalized, scope: { targetUrl: tab.url }, capabilities: ['dialogs']
                })
                if (!entry.active || this.dialogTabs.get(normalized) !== entry) return false
                entry.lease.subscribe(event => {
                    if (event.type === 'protocol' && event.method === 'Page.javascriptDialogOpening') {
                        return entry.lease.sendCommand('Page.handleJavaScriptDialog', { accept: true }, event.record?.sessionId)
                    }
                })
                return true
            } catch (error) {
                if (!entry.lease && this.dialogTabs.get(normalized) === entry) this.dialogTabs.delete(normalized)
                if (entry.lease) throw error
                return false
            }
        })()
        return entry.promise
    }
    async detachDialogAutoDismiss(tabId) {
        const normalized = Number(tabId)
        const entry = this.dialogTabs.get(normalized)
        if (!entry) return true
        entry.active = false
        // Join the already admitted attachment before testing its lease handle.
        await Promise.allSettled([entry.promise])
        if (entry.lease) {
            const result = await entry.lease.release('dialog_complete')
            if (result === false) throw new Error("dialog_cleanup_unproved")
            entry.lease = null
        }
        if (this.dialogTabs.get(normalized) === entry) this.dialogTabs.delete(normalized)
        return true
    }

    unsubscribe(subscriptionId, ownerId) {
        const entry = this.subscriptions.get(subscriptionId)
        if (!entry) return { unsubscribed: false }
        if (entry.ownerId !== ownerId) throw new Error("foreign_browser_owner")
        const result = entry.target.removeListener(entry.listener)
        if (result === false) throw new Error("subscription_cleanup_unproved")
        this.subscriptions.delete(subscriptionId)
        return { unsubscribed: true }
    }
    async cleanupCaptureOperation(entry, reason) {
        entry.active = false
        const failures = []
        if (entry.lease) {
            try {
                const result = await entry.lease.release(reason)
                if (result === false) throw new Error("capture_cleanup_unproved")
                entry.lease = null
            } catch (error) { failures.push(error) }
        }
        if (entry.tabId != null) {
            try {
                const result = await this.browserApi.tabs.remove(entry.tabId)
                if (result === false) throw new Error("capture_tab_cleanup_unproved")
                entry.tabId = null
            } catch (error) { failures.push(error) }
        }
        if (!failures.length) this.captureOperations.delete(entry)
        else throw new AggregateError(failures, "dast_browser_cleanup_failed")
    }

    async cleanup(ownerId = null) {
        let count = 0
        const failures = []
        const attempt = async action => {
            try { await action(); count++ } catch (error) { failures.push(error) }
        }
        for (const entry of [...this.captureOperations]) {
            if (ownerId != null && entry.ownerId !== ownerId) continue
            await attempt(() => this.cleanupCaptureOperation(entry, 'owner_cleanup'))
        }
        for (const [subscriptionId, entry] of [...this.subscriptions]) {
            if (ownerId != null && entry.ownerId !== ownerId) continue
            await attempt(() => this.unsubscribe(subscriptionId, entry.ownerId))
        }
        for (const [watchId, entry] of [...this.navigationWatches]) {
            if (ownerId != null && entry.ownerId !== ownerId) continue
            await attempt(() => this.cancelNavigationWatch(watchId, "owner_cleanup"))
        }
        for (const [tabId, entry] of [...this.dialogTabs]) {
            if (ownerId != null && entry.ownerId !== ownerId) continue
            await attempt(() => this.detachDialogAutoDismiss(tabId))
        }
        if (failures.length) throw new AggregateError(failures, "dast_browser_cleanup_failed")
        return { cleaned: count }
    }

    static allowedMethods() { return [...Object.keys(CALLS), ...Object.keys(NAMED_OPERATIONS)] }
    static allowedEvents() { return [...Object.keys(EVENTS), "dast.oast"] }
}

export default DastPrivilegedBrowserAdapter
