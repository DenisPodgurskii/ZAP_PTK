'use strict'

const CALLBACK_PATH_REGEX = /^\/zapCallBackUrl\/([^/?#]+)/i
const CALLBACK_URL_REGEX = /^https?:\/\/[^/?#]+\/zapCallBackUrl\/([^/?#]+)/i
const RETRY_DELAYS_MS = [250, 1000, 4000]
const TARGET_PARAM_KEYS = ['url', 'target', 'targetUrl', 'scanUrl', 'startUrl', 'site']
const DETECTION_DEDUPE_WINDOW_MS = 3000
const CONFIG_INITIAL_FETCH_DELAY_MS = 1200
const CONFIG_DIRECT_FETCH_RETRY_DELAYS_MS = [0, 400, 1200, 2400]
const QUICKSTART_URL_REGEX = /^https?:\/\/zap\/OTHER\/quickstartlaunch\/other\/startPage\//i
const QUICKSTART_PROBE_COOLDOWN_MS = 5000
const QUICKSTART_SCRIPT_FETCH_LIMIT = 8
const QUICKSTART_SCRIPT_BODY_MAX = 250000
const HISTORY_BOOTSTRAP_LOOKBACK_MS = 15 * 60 * 1000
const HISTORY_BOOTSTRAP_MAX_RESULTS = 200
let ZAP_DEBUG_LOG_ENABLED = false
const ZAP_ALLOWED_DEBUG_PREFIXES = [
    '[PTK ZAP] ZAP detected!'
]

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms))
}

function debugLog(...args) {
    if (!ZAP_DEBUG_LOG_ENABLED) return
    const prefix = typeof args[0] === 'string' ? args[0] : ''
    if (!ZAP_ALLOWED_DEBUG_PREFIXES.some(allowed => prefix.startsWith(allowed))) {
        return
    }
    console.log(...args)
}

function summarizeFetchError(err) {
    const stack = typeof err?.stack === 'string' ? err.stack.split('\n')[0] : null
    return {
        name: err?.name || null,
        message: err?.message || String(err || ''),
        stack
    }
}

function logStructured(prefix, payload) {
    try {
        debugLog(prefix, JSON.stringify(payload))
    } catch (_) {
        debugLog(prefix, payload)
    }
}

function isObjectPayload(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function safeParseUrl(value) {
    if (!value || typeof value !== 'string') return null
    try {
        const url = new URL(value)
        if (url.protocol === 'http:' || url.protocol === 'https:') {
            return url.toString()
        }
    } catch (_) {
        return null
    }
    return null
}

function parseCallbackUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl) return null

    try {
        const parsed = new URL(rawUrl)
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return null
        }
        const match = parsed.pathname.match(CALLBACK_PATH_REGEX)
        if (!match || !match[1]) {
            return null
        }
        return {
            origin: parsed.origin,
            secret: match[1]
        }
    } catch (_) {
        return null
    }
}

function extractTargetUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return null

    try {
        const parsed = new URL(rawUrl)
        for (const key of TARGET_PARAM_KEYS) {
            const candidate = safeParseUrl(parsed.searchParams.get(key))
            if (candidate) return candidate
        }

        const hash = parsed.hash || ''
        if (hash.includes('?')) {
            const hashQuery = hash.slice(hash.indexOf('?') + 1)
            const params = new URLSearchParams(hashQuery)
            for (const key of TARGET_PARAM_KEYS) {
                const candidate = safeParseUrl(params.get(key))
                if (candidate) return candidate
            }
        }
    } catch (_) {
        return null
    }

    return null
}

function extractCallbackCandidate(text) {
    const body = String(text || '')
    const fullMatch = body.match(/https?:\/\/[^"'\\s<>]+\/zapCallBackUrl\/[^"'\\s<>]+/i)
    if (fullMatch && fullMatch[0]) {
        return fullMatch[0]
    }

    const pathMatch = body.match(/\/zapCallBackUrl\/([^"'\\s<>/?#]+)/i)
    if (pathMatch && pathMatch[1]) {
        return `https://zap/zapCallBackUrl/${pathMatch[1]}?zapenable=true`
    }

    return null
}

function extractQuickstartScriptUrls(html, pageUrl) {
    const urls = []
    const seen = new Set()
    const regex = /<script[^>]+src=["']([^"']+)["']/ig
    let match = null

    while ((match = regex.exec(String(html || ''))) !== null) {
        const src = match[1]
        if (!src) continue
        try {
            const absolute = new URL(src, pageUrl).toString()
            if (!/^https?:\/\/zap\//i.test(absolute)) continue
            if (seen.has(absolute)) continue
            seen.add(absolute)
            urls.push(absolute)
        } catch (_) {
            // Ignore invalid script URLs.
        }
    }

    return urls
}

function deriveCallbackFromQuickstartUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl) return null

    try {
        const parsed = new URL(rawUrl)
        if (!QUICKSTART_URL_REGEX.test(parsed.toString())) {
            return null
        }

        const paramKeys = [
            'ptkcallbackurl',
            'ptkcallback',
            'callbackurl',
            'callback',
            'ptksecret',
            'secret'
        ]

        for (const key of paramKeys) {
            const rawValue = parsed.searchParams.get(key)
            if (!rawValue) continue
            const value = rawValue.trim()
            if (!value) continue

            // Accept full callback URL.
            if (CALLBACK_URL_REGEX.test(value)) {
                return value.includes('zapenable=') ? value : `${value}?zapenable=true`
            }

            // Accept callback path.
            const pathMatch = value.match(/^\/?zapCallBackUrl\/([^/?#]+)/i)
            if (pathMatch && pathMatch[1]) {
                return `${parsed.origin}/zapCallBackUrl/${pathMatch[1]}?zapenable=true`
            }

            // Accept secret-only values.
            if (/^[A-Za-z0-9_-]{6,}$/.test(value)) {
                return `${parsed.origin}/zapCallBackUrl/${value}?zapenable=true`
            }
        }
    } catch (_) {
        return null
    }

    return null
}

class ZapTransport {
    constructor() {
        this.secret = null
        this.baseUrl = null
        this.pingUrl = null
        this.configUrl = null
        this.alertsUrl = null
        this.active = false
        this._lastDetectedPayload = null
        this._detectedCallbacks = new Set()
        this._urlObservedCallbacks = new Set()
        this._listenerAttached = false
        this._onCommitted = null
        this._onBeforeNavigate = null
        this._onTabUpdated = null
        this._onTabCreated = null
        this._onTabReplaced = null
        this._onCreatedNavigationTarget = null
        this._onHistoryVisited = null
        this._lastDetectionByTab = new Map()
        this._lastQuickstartProbeByTab = new Map()
    }

    setDebugEnabled(enabled) {
        ZAP_DEBUG_LOG_ENABLED = enabled === true
    }

    isDebugEnabled() {
        return ZAP_DEBUG_LOG_ENABLED === true
    }

    init() {
        if (this._listenerAttached) return

        const hasCommitted = !!browser?.webNavigation?.onCommitted
        const hasBeforeNavigate = !!browser?.webNavigation?.onBeforeNavigate
        const hasCreatedNavigationTarget = !!browser?.webNavigation?.onCreatedNavigationTarget
        const hasTabUpdated = !!browser?.tabs?.onUpdated
        const hasTabCreated = !!browser?.tabs?.onCreated
        const hasTabReplaced = !!browser?.tabs?.onReplaced
        const hasHistoryVisited = !!browser?.history?.onVisited
        const hasHistorySearch = !!browser?.history?.search

        if (
            !hasCommitted
            && !hasBeforeNavigate
            && !hasCreatedNavigationTarget
            && !hasTabUpdated
            && !hasTabCreated
            && !hasTabReplaced
            && !hasHistoryVisited
            && !hasHistorySearch
        ) {
            console.warn('[PTK ZAP] No navigation APIs available for ZAP detection')
            return
        }

        if (hasCommitted) {
            this._onCommitted = this._onCommitted || this._handleNavigationCommitted.bind(this)
            browser.webNavigation.onCommitted.addListener(this._onCommitted)
        }

        if (hasBeforeNavigate) {
            this._onBeforeNavigate = this._onBeforeNavigate || this._handleNavigationBefore.bind(this)
            browser.webNavigation.onBeforeNavigate.addListener(this._onBeforeNavigate)
        }

        if (hasCreatedNavigationTarget) {
            this._onCreatedNavigationTarget = this._onCreatedNavigationTarget || this._handleCreatedNavigationTarget.bind(this)
            browser.webNavigation.onCreatedNavigationTarget.addListener(this._onCreatedNavigationTarget)
        }

        if (hasTabUpdated) {
            this._onTabUpdated = this._onTabUpdated || this._handleTabUpdated.bind(this)
            browser.tabs.onUpdated.addListener(this._onTabUpdated)
        }

        if (hasTabCreated) {
            this._onTabCreated = this._onTabCreated || this._handleTabCreated.bind(this)
            browser.tabs.onCreated.addListener(this._onTabCreated)
        }

        if (hasTabReplaced) {
            this._onTabReplaced = this._onTabReplaced || this._handleTabReplaced.bind(this)
            browser.tabs.onReplaced.addListener(this._onTabReplaced)
        }

        if (hasHistoryVisited) {
            this._onHistoryVisited = this._onHistoryVisited || this._handleHistoryVisited.bind(this)
            browser.history.onVisited.addListener(this._onHistoryVisited)
        }

        this._listenerAttached = true
        void this._bootstrapFromHistory()
        void this._bootstrapFromOpenTabs()
    }

    isActive() {
        return this.active && !!this.baseUrl && !!this.configUrl && !!this.alertsUrl
    }

    getBaseUrl() {
        return this.baseUrl
    }

    getPingUrl() {
        return this.pingUrl
    }

    getConfigUrl() {
        return this.configUrl
    }

    getAlertsUrl() {
        return this.alertsUrl
    }

    onZapDetected(cb) {
        if (typeof cb !== 'function') {
            return () => {}
        }

        this._detectedCallbacks.add(cb)

        if (this.active && this._lastDetectedPayload) {
            // Defer callback so registration remains synchronous and non-blocking.
            Promise.resolve().then(() => {
                try {
                    cb({ ...this._lastDetectedPayload })
                } catch (err) {
                    console.warn('[PTK ZAP] onZapDetected immediate callback failed:', err)
                }
            })
        }

        return () => this._detectedCallbacks.delete(cb)
    }

    onUrlObserved(cb) {
        if (typeof cb !== 'function') {
            return () => {}
        }

        this._urlObservedCallbacks.add(cb)
        return () => this._urlObservedCallbacks.delete(cb)
    }

    getLastDetectedPayload() {
        return this._lastDetectedPayload ? { ...this._lastDetectedPayload } : null
    }

    async postAlertsJson(obj) {
        if (!this.alertsUrl) {
            throw new Error('zap_alerts_not_ready')
        }

        debugLog('[PTK ZAP] Sending alerts POST to:', this.alertsUrl)

        let lastError = null
        for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
            try {
                const response = await fetch(this.alertsUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(obj)
                })

                const acceptedStatusZero = response.status === 0 && response.type !== 'opaque'
                if (!response.ok && !acceptedStatusZero) {
                    throw new Error(`zap_alerts_http_${response.status}`)
                }

                if (acceptedStatusZero) {
                    debugLog('[PTK ZAP] Alerts POST accepted from non-OK HTTP status because transport returned status 0')
                }
                debugLog('[PTK ZAP] Alerts POST response:', response.status)
                return response
            } catch (err) {
                lastError = err
                if (attempt >= RETRY_DELAYS_MS.length) {
                    break
                }
                await sleep(RETRY_DELAYS_MS[attempt])
            }
        }

        throw lastError || new Error('zap_alerts_failed')
    }

    // Backward-compatible alias.
    async postJson(obj) {
        return this.postAlertsJson(obj)
    }

    async fetchConfig(options = {}) {
        if (!this.configUrl) {
            debugLog('[PTK ZAP] No callback URL stored, cannot fetch config')
            return {}
        }

        const skipPing = options?.skipPing === true
        const startedAt = Date.now()
        const diagnostics = []
        const pingUrl = this._resolvePingUrl()

        debugLog('[PTK ZAP] Fetching config from:', this.configUrl)
        if (pingUrl && !skipPing) {
            await this._pingBeforeConfigFetch({
                pingUrl,
                startedAt,
                diagnostics
            })
        } else if (skipPing) {
            debugLog('[PTK ZAP] Skipping config preflight ping (already sent after ZAP detection)')
        }
        debugLog('[PTK ZAP] Config fetch startup delay (ms):', CONFIG_INITIAL_FETCH_DELAY_MS)
        if (CONFIG_INITIAL_FETCH_DELAY_MS > 0) {
            await sleep(CONFIG_INITIAL_FETCH_DELAY_MS)
        }

        const totalAttempts = CONFIG_DIRECT_FETCH_RETRY_DELAYS_MS.length
        for (let attempt = 0; attempt < totalAttempts; attempt++) {
            const attemptNo = attempt + 1
            const delayMs = CONFIG_DIRECT_FETCH_RETRY_DELAYS_MS[attempt]
            if (delayMs > 0) {
                await sleep(delayMs)
            }

            try {
                const response = await fetch(this.configUrl, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json'
                    },
                    cache: 'no-store',
                    credentials: 'include'
                })

                const responseMeta = {
                    status: response.status,
                    statusText: response.statusText,
                    ok: response.ok,
                    type: response.type,
                    url: response.url,
                    redirected: response.redirected
                }

                logStructured('[PTK ZAP] Config request attempt response:', {
                    attempt: attemptNo,
                    totalAttempts,
                    delayMs,
                    elapsedMs: Date.now() - startedAt,
                    ...responseMeta
                })

                if (response.type === 'opaque') {
                    diagnostics.push({ attempt: attemptNo, kind: 'opaque_response', status: response.status, type: response.type })
                    continue
                }

                let body = ''
                try {
                    body = await response.text()
                } catch (err) {
                    diagnostics.push({
                        attempt: attemptNo,
                        kind: 'body_read_error',
                        errorMessage: err?.message || String(err)
                    })
                    continue
                }

                if (!body || !body.trim()) {
                    diagnostics.push({
                        attempt: attemptNo,
                        kind: response.ok ? 'empty_body' : 'non_ok_empty_body',
                        status: response.status,
                        statusText: response.statusText
                    })
                } else {
                    let data = null
                    try {
                        data = JSON.parse(body)
                    } catch (err) {
                        diagnostics.push({
                            attempt: attemptNo,
                            kind: response.ok ? 'parse_error' : 'non_ok_parse_error',
                            status: response.status,
                            statusText: response.statusText
                        })
                    }

                    if (isObjectPayload(data)) {
                        if (!response.ok) {
                            debugLog('[PTK ZAP] Config accepted from non-OK HTTP status because JSON body is valid')
                        }
                        debugLog('[PTK ZAP] Config response data:', data)
                        return data
                    }
                }

                diagnostics.push({
                    attempt: attemptNo,
                    kind: 'no_usable_json_config',
                    status: response.status,
                    statusText: response.statusText
                })
                continue
            } catch (err) {
                const summary = summarizeFetchError(err)
                diagnostics.push({
                    attempt: attemptNo,
                    kind: 'exception',
                    errorName: summary.name,
                    errorMessage: summary.message
                })
                logStructured('[PTK ZAP] Config request attempt threw:', {
                    attempt: attemptNo,
                    totalAttempts,
                    delayMs,
                    elapsedMs: Date.now() - startedAt,
                    error: summary
                })
            }
        }

        logStructured('[PTK ZAP] Config fetch diagnostics summary:', {
            configUrl: this.configUrl,
            elapsedMs: Date.now() - startedAt,
            strategy: 'background_fetch_only',
            recentDiagnostics: diagnostics.slice(-12)
        })
        debugLog('[PTK ZAP] Config unavailable, using default PTK engines')
        return {}
    }

    async confirmZap(options = {}) {
        return this.fetchConfig(options)
    }

    async pingCallback(options = {}) {
        const pingUrl = this._resolvePingUrl()
        const startedAt = Date.now()
        const diagnostics = []
        const reason = String(options?.reason || '').trim()

        if (reason) {
            debugLog(`[PTK ZAP] Sending callback preflight ping (${reason})`)
        }

        if (!pingUrl) {
            return {
                pingUrl: null,
                elapsedMs: Date.now() - startedAt,
                diagnostics,
                ok: false
            }
        }

        await this._pingBeforeConfigFetch({
            pingUrl,
            startedAt,
            diagnostics
        })

        const pingDiagnostic = diagnostics.find((item) => item?.kind === 'ping') || null
        return {
            pingUrl,
            elapsedMs: Date.now() - startedAt,
            diagnostics,
            ok: pingDiagnostic?.ok === true || pingDiagnostic?.status === 200
        }
    }

    _resolvePingUrl() {
        if (typeof this.pingUrl === 'string' && this.pingUrl) {
            return this.pingUrl
        }
        if (typeof this.configUrl !== 'string' || !this.configUrl) {
            return null
        }

        return this.configUrl.replace(/\/config(?:[?#].*)?$/i, '/ping')
    }

    async _pingBeforeConfigFetch({ pingUrl, startedAt, diagnostics } = {}) {
        if (typeof pingUrl !== 'string' || !pingUrl) {
            return
        }

        debugLog('[PTK ZAP] Pinging callback endpoint before config fetch:', pingUrl)

        try {
            const response = await fetch(pingUrl, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json, text/plain, */*'
                },
                cache: 'no-store',
                credentials: 'include'
            })

            logStructured('[PTK ZAP] Ping request response:', {
                elapsedMs: Date.now() - startedAt,
                status: response.status,
                statusText: response.statusText,
                ok: response.ok,
                type: response.type,
                url: response.url,
                redirected: response.redirected
            })

            diagnostics.push({
                kind: 'ping',
                status: response.status,
                statusText: response.statusText,
                ok: response.ok,
                type: response.type
            })
        } catch (err) {
            const summary = summarizeFetchError(err)
            diagnostics.push({
                kind: 'ping_exception',
                errorName: summary.name,
                errorMessage: summary.message
            })
            logStructured('[PTK ZAP] Ping request threw:', {
                elapsedMs: Date.now() - startedAt,
                error: summary
            })
        }
    }

    _handleNavigationCommitted(details) {
        if (!details) return

        this._logCaughtUrl('webNavigation.onCommitted', {
            tabId: details.tabId,
            frameId: details.frameId,
            url: details.url || ''
        })

        this._processPotentialZapUrl({
            tabId: details.tabId,
            url: details.url || '',
            source: 'webNavigation.onCommitted'
        })
    }

    _handleNavigationBefore(details) {
        if (!details) return

        this._logCaughtUrl('webNavigation.onBeforeNavigate', {
            tabId: details.tabId,
            frameId: details.frameId,
            url: details.url || ''
        })

        this._processPotentialZapUrl({
            tabId: details.tabId,
            url: details.url || '',
            source: 'webNavigation.onBeforeNavigate'
        })
    }

    _handleCreatedNavigationTarget(details) {
        if (!details) return
        const url = details.url || ''
        if (!url) return

        this._logCaughtUrl('webNavigation.onCreatedNavigationTarget', {
            tabId: details.tabId,
            frameId: details.frameId,
            url
        })

        this._processPotentialZapUrl({
            tabId: details.tabId,
            url,
            source: 'webNavigation.onCreatedNavigationTarget'
        })
    }

    _handleTabUpdated(tabId, changeInfo, tab) {
        const urls = [
            changeInfo?.url || '',
            changeInfo?.pendingUrl || '',
            tab?.pendingUrl || '',
            tab?.url || ''
        ].filter(Boolean)

        for (const url of urls) {
            this._logCaughtUrl('tabs.onUpdated', {
                tabId,
                frameId: 0,
                url
            })

            this._processPotentialZapUrl({
                tabId,
                url,
                source: 'tabs.onUpdated'
            })
        }
    }

    _handleTabCreated(tab) {
        const tabId = Number.isInteger(tab?.id) ? tab.id : null
        const urls = [
            tab?.pendingUrl || '',
            tab?.url || ''
        ].filter(Boolean)

        for (const url of urls) {
            this._logCaughtUrl('tabs.onCreated', {
                tabId,
                frameId: 0,
                url
            })

            this._processPotentialZapUrl({
                tabId,
                url,
                source: 'tabs.onCreated'
            })
        }
    }

    async _handleTabReplaced(addedTabId) {
        if (!Number.isInteger(addedTabId) || !browser?.tabs?.get) return

        try {
            const tab = await browser.tabs.get(addedTabId)
            const urls = [
                tab?.pendingUrl || '',
                tab?.url || ''
            ].filter(Boolean)

            for (const url of urls) {
                this._logCaughtUrl('tabs.onReplaced', {
                    tabId: addedTabId,
                    frameId: 0,
                    url
                })

                this._processPotentialZapUrl({
                    tabId: addedTabId,
                    url,
                    source: 'tabs.onReplaced'
                })
            }
        } catch (_) {
            // Ignore lookup failures.
        }
    }

    _handleHistoryVisited(historyItem) {
        const url = typeof historyItem?.url === 'string' ? historyItem.url : ''
        if (!url) return

        this._logCaughtUrl('history.onVisited', {
            tabId: null,
            frameId: 0,
            url
        })

        this._processPotentialZapUrl({
            tabId: null,
            url,
            source: 'history.onVisited'
        })
    }

    async _bootstrapFromHistory() {
        if (!browser?.history?.search) return

        const startTime = Date.now() - HISTORY_BOOTSTRAP_LOOKBACK_MS
        const seen = new Set()

        const collect = async (text) => {
            try {
                const items = await browser.history.search({
                    text,
                    startTime,
                    maxResults: HISTORY_BOOTSTRAP_MAX_RESULTS
                })
                if (!Array.isArray(items)) return
                for (const item of items) {
                    const url = typeof item?.url === 'string' ? item.url : ''
                    if (!url || seen.has(url)) continue
                    seen.add(url)
                    this._logCaughtUrl('history.bootstrap', {
                        tabId: null,
                        frameId: 0,
                        url
                    })
                    this._processPotentialZapUrl({
                        tabId: null,
                        url,
                        source: 'history.bootstrap'
                    })
                }
            } catch (err) {
                console.warn('[PTK ZAP] Failed to bootstrap ZAP detection from browser history:', err?.message || String(err))
            }
        }

        await collect('zapCallBackUrl')
        await collect('quickstartlaunch')
    }

    async _bootstrapFromOpenTabs() {
        if (!browser?.tabs?.query) return

        try {
            await this._scanOpenTabsForPotentialZapUrls('bootstrap.tabs.query')
        } catch (err) {
            console.warn('[PTK ZAP] Failed to bootstrap ZAP detection from existing tabs:', err?.message || String(err))
        }
    }

    async _scanOpenTabsForPotentialZapUrls(source = 'bootstrap.tabs.query') {
        if (!browser?.tabs?.query) return

        const tabs = await browser.tabs.query({})
        for (const tab of tabs) {
            const urls = [
                tab?.pendingUrl || '',
                tab?.url || ''
            ].filter(Boolean)

            for (const url of urls) {
                this._logCaughtUrl(source, {
                    tabId: tab.id,
                    frameId: 0,
                    url
                })
                this._processPotentialZapUrl({
                    tabId: tab.id,
                    url,
                    source
                })
            }
        }
    }

    _processPotentialZapUrl({ tabId, url, source = 'unknown' } = {}) {
        if (typeof url !== 'string') {
            return false
        }

        const callbackInfo = parseCallbackUrl(url)
        const hasCallbackPattern = !!callbackInfo
        const hasEnableFlag = url.includes('zapenable=true')
        if (!hasCallbackPattern && !hasEnableFlag) {
            const derived = deriveCallbackFromQuickstartUrl(url)
            if (derived && derived !== url) {
                debugLog('[PTK ZAP] Derived callback URL from quickstart params')
                return this._processPotentialZapUrl({
                    tabId,
                    url: derived,
                    source: `${source}.quickstart.params`
                })
            }
            return false
        }

        const secret = callbackInfo?.secret || ''
        if (!secret) {
            debugLog('[PTK ZAP] URL hint observed but no valid callback pattern')
            return false
        }

        const baseUrl = this._buildBaseUrl(url, secret)
        const pingUrl = `${baseUrl}/ptk/ping`
        const configUrl = `${baseUrl}/ptk/config`
        const alertsUrl = `${baseUrl}/ptk/alerts`
        const changed = this.baseUrl !== baseUrl
        const targetUrl = extractTargetUrl(url)
        const now = Date.now()
        const hasLiveTabId = Number.isInteger(tabId) && tabId >= 0
        const currentTabId = this._lastDetectedPayload?.tabId
        const needsTabRebind = hasLiveTabId && (!Number.isInteger(currentTabId) || currentTabId < 0)

        // If we already have the same active ZAP callback, ignore repeated re-checks.
        if (this.active && !changed) {
            if (needsTabRebind) {
                debugLog('[PTK ZAP] Rebinding active ZAP session to live tab', {
                    tabId,
                    source
                })
                const payload = Object.assign({}, this._lastDetectedPayload || {}, {
                    tabId,
                    url,
                    source,
                    changed: false,
                    pingUrl: this.pingUrl || this._lastDetectedPayload?.pingUrl || null,
                    targetUrl: targetUrl || this._lastDetectedPayload?.targetUrl || null
                })
                this._lastDetectedPayload = payload
                this._emitDetected(payload)
                return true
            }
            return false
        }

        debugLog('[PTK ZAP] Checking ZAP URL:', url)

        const dedupeKey = `${tabId || 'na'}|${baseUrl}`
        const previousDetection = this._lastDetectionByTab.get(dedupeKey)
        if (
            previousDetection
            && previousDetection.url === url
            && now - previousDetection.ts < DETECTION_DEDUPE_WINDOW_MS
        ) {
            debugLog('[PTK ZAP] Duplicate detection suppressed', {
                tabId,
                baseUrl,
                source,
                ageMs: now - previousDetection.ts
            })
            return false
        }
        this._lastDetectionByTab.set(dedupeKey, { url, ts: now })

        if (this.active && this.baseUrl && changed) {
            debugLog('[PTK ZAP] New ZAP session detected, updating...')
        }

        debugLog('[PTK ZAP] ZAP detected!', {
            secret,
            baseUrl,
            pingUrl,
            configUrl,
            alertsUrl,
            changed,
            tabId,
            targetUrl,
            source
        })

        this.secret = secret
        this.baseUrl = baseUrl
        this.pingUrl = pingUrl
        this.configUrl = configUrl
        this.alertsUrl = alertsUrl
        this.active = true
        const payload = {
            secret,
            baseUrl,
            pingUrl,
            configUrl,
            alertsUrl,
            tabId,
            url,
            targetUrl,
            changed,
            source
        }

        this._lastDetectedPayload = payload
        this._emitDetected(payload)
        return true
    }

    _buildBaseUrl(url, secret) {
        let origin = 'https://zap'
        try {
            const parsed = new URL(url)
            if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.host) {
                origin = parsed.origin
            }
        } catch (_) {
            // Keep default origin.
        }
        return `${origin}/zapCallBackUrl/${secret}`
    }

    _logCaughtUrl(source, payload = {}) {
        const url = typeof payload.url === 'string' ? payload.url : ''
        if (!url) return

        const now = Date.now()

        const observedPayload = {
            source,
            tabId: payload.tabId,
            frameId: payload.frameId,
            url,
            ts: now
        }

        this._emitUrlObserved(observedPayload)

        const tabStr = Number.isInteger(payload.tabId) ? payload.tabId : 'na'
        const frameStr = Number.isInteger(payload.frameId) ? payload.frameId : 'na'
        const tsIso = new Date(now).toISOString()
        debugLog(`[PTK ZAP] URL observed [${source}] ts=${tsIso} tab=${tabStr} frame=${frameStr} url=${url}`)

        if (!this.active && QUICKSTART_URL_REGEX.test(url)) {
            debugLog('[PTK ZAP] Quickstart page observed before callback detection')
            void this._probeQuickstartForCallback(url, payload.tabId)
        }
    }

    async _probeQuickstartForCallback(url, tabId) {
        if (!url || !QUICKSTART_URL_REGEX.test(url)) return

        const tabKey = Number.isInteger(tabId) ? tabId : 'na'
        const lastProbeTs = this._lastQuickstartProbeByTab.get(tabKey) || 0
        if (Date.now() - lastProbeTs < QUICKSTART_PROBE_COOLDOWN_MS) {
            return
        }
        this._lastQuickstartProbeByTab.set(tabKey, Date.now())

        try {
            debugLog('[PTK ZAP] Probing quickstart content for callback URL...')
            const response = await fetch(url, { method: 'GET', cache: 'no-store' })
            const text = await response.text()
            const body = String(text || '').slice(0, 400000)

            let candidate = extractCallbackCandidate(body)

            if (!candidate) {
                const scripts = extractQuickstartScriptUrls(body, url).slice(0, QUICKSTART_SCRIPT_FETCH_LIMIT)
                for (const scriptUrl of scripts) {
                    try {
                        const scriptResponse = await fetch(scriptUrl, { method: 'GET', cache: 'no-store' })
                        if (!scriptResponse.ok) continue
                        const scriptBody = (await scriptResponse.text()).slice(0, QUICKSTART_SCRIPT_BODY_MAX)
                        candidate = extractCallbackCandidate(scriptBody)
                        if (candidate) {
                            debugLog('[PTK ZAP] Inferred callback URL from quickstart script')
                            break
                        }
                    } catch (_) {
                        // Ignore script probe failures.
                    }
                }
            }

            if (!candidate) {
                debugLog('[PTK ZAP] Quickstart probe did not expose callback URL')
                return
            }

            debugLog('[PTK ZAP] Inferred callback URL from quickstart content')
            this._processPotentialZapUrl({
                tabId,
                url: candidate,
                source: 'quickstart.probe.html'
            })
        } catch (_) {
            debugLog('[PTK ZAP] Quickstart probe request failed')
        }
    }

    _emitUrlObserved(payload) {
        for (const cb of this._urlObservedCallbacks) {
            try {
                cb(payload)
            } catch (err) {
                console.warn('[PTK ZAP] onUrlObserved callback failed:', err)
            }
        }
    }

    _emitDetected(payload) {
        for (const cb of this._detectedCallbacks) {
            try {
                cb(payload)
            } catch (err) {
                console.warn('[PTK ZAP] onZapDetected callback failed:', err)
            }
        }
    }

}

const zapTransport = new ZapTransport()
// Register low-level listeners as soon as the module is evaluated.
// This reduces the chance of missing short-lived ZAP callback URLs during startup redirects.
zapTransport.init()

export default zapTransport
