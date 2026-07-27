'use strict'

import {
    clearZapStartupPending,
    getZapStartupSnapshot,
    isZapStartupPending,
    logZapLifecycle
} from '../../../common/zapLifecycle.js'

const TRUSTED_ZAP_ORIGIN = 'https://zap'
const CALLBACK_PATH_REGEX = /^\/zapCallBackUrl\/([A-Za-z0-9_-]+)(?:\/|$)/i
const CALLBACK_URL_REGEX = /^https:\/\/zap\/zapCallBackUrl\/([A-Za-z0-9_-]+)(?:[/?#]|$)/i
const RETRY_DELAYS_MS = [250, 1000, 4000]
const TARGET_PARAM_KEYS = ['url', 'target', 'targetUrl', 'scanUrl', 'startUrl', 'site']
const DETECTION_DEDUPE_WINDOW_MS = 3000
const CONFIG_INITIAL_FETCH_DELAY_MS = 0
// ZAP Client Spider can launch many browser sessions at once. During that burst the
// callback page may be visible and progress POSTs may work before the config
// endpoint responds quickly enough, so keep config fetch retrying for a bounded
// startup window instead of silently falling back to manual mode.
const CONFIG_DIRECT_FETCH_RETRY_DELAYS_MS = [0, 250, 1000, 2500, 5000]
const CONFIG_DIRECT_FETCH_TIMEOUT_MS = 2500
const CALLBACK_PROGRESS_POST_TIMEOUT_MS = 2500
const CALLBACK_PROGRESS_RETRY_DELAYS_MS = [250]
const CALLBACK_ALERT_POST_TIMEOUT_MS = 10000
const CALLBACK_CONTROL_POST_TIMEOUT_MS = 2500
const CALLBACK_CONTROL_RETRY_DELAYS_MS = []
const QUICKSTART_URL_REGEX = /^https:\/\/zap\/OTHER\/quickstartlaunch\/other\/startPage\//i
const QUICKSTART_PROBE_COOLDOWN_MS = 5000
const QUICKSTART_SCRIPT_FETCH_LIMIT = 8
const QUICKSTART_SCRIPT_BODY_MAX = 250000
const STARTUP_BOOTSTRAP_RETRY_DELAYS_MS = [0, 500, 2000, 5000]
const ACTIVE_CALLBACK_RECOVERY_INTERVAL_MS = 1000
const ACTIVE_CALLBACK_RECOVERY_WINDOW_MS = 10 * 60 * 1000
const DAST_HISTORY_SEED_MAX_RESULTS = 256
let ZAP_DEBUG_LOG_ENABLED = false
const ZAP_ALLOWED_DEBUG_PREFIXES = [
    '[PTK ZAP] ZAP detected!',
    '[PTK ZAP] Quickstart page observed',
    '[PTK ZAP] Probing quickstart content',
    '[PTK ZAP] Quickstart probe',
    '[PTK ZAP] Inferred callback URL',
    '[PTK ZAP] Derived callback URL',
    '[PTK ZAP] URL hint observed',
    '[PTK ZAP] Rebinding active ZAP session',
    '[PTK ZAP] Checking ZAP URL:',
    '[PTK ZAP] Duplicate detection suppressed',
    '[PTK ZAP] New ZAP session detected',
    '[PTK ZAP] No callback URL stored',
    '[PTK ZAP] No zapid stored',
    '[PTK ZAP] Fetching config from:',
    '[PTK ZAP] Config request attempt threw:',
    '[PTK ZAP] Config accepted from non-OK',
    '[PTK ZAP] Config response data:',
    '[PTK ZAP] Config fetch diagnostics summary:',
    '[PTK ZAP] Config unavailable'
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
    console.log(...args.map((arg) => redactZapLogValue(arg)))
}

function summarizeFetchError(err) {
    const stack = typeof err?.stack === 'string' ? err.stack.split('\n')[0] : null
    return {
        name: err?.name || null,
        message: err?.message || String(err || ''),
        stack
    }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = CONFIG_DIRECT_FETCH_TIMEOUT_MS) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || typeof AbortController === 'undefined') {
        return fetch(url, options)
    }
    const controller = new AbortController()
    const timeout = setTimeout(() => {
        try { controller.abort() } catch (_) { }
    }, Math.max(1, timeoutMs))
    try {
        return await fetch(url, Object.assign({}, options || {}, { signal: controller.signal }))
    } finally {
        clearTimeout(timeout)
    }
}

function logStructured(prefix, payload) {
    try {
        debugLog(prefix, JSON.stringify(redactZapLogValue(payload)))
    } catch (_) {
        debugLog(prefix, payload)
    }
}

function isObjectPayload(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function toNonEmptyString(value) {
    if (typeof value !== 'string') return null
    const trimmed = value.trim()
    return trimmed || null
}

function redactZapCallbackUrlForLog(value) {
    if (typeof value !== 'string' || !value) return value
    const redacted = value
        .replace(/(https?:\/\/[^/?#\s"'<>]+\/zapCallBackUrl\/)[^/?#\s"'<>]+/gi, '$1<redacted>')
        .replace(/(\/zapCallBackUrl\/)[^/?#\s"'<>]+/gi, '$1<redacted>')
    if (!redacted.includes('/zapCallBackUrl/')) return redacted
    return redacted
        .replace(/([?&]zapid=)[^&#\s"'<>]+/gi, '$1<redacted>')
        .replace(/(\|)[^\s"'<>]+/g, '$1<redacted>')
}

function redactZapLogValue(value, key = '') {
    if (typeof key === 'string' && /(^|_|\b)(secret|callbackSecret)(_|$|\b)/i.test(key)) {
        return '<redacted>'
    }
    if (typeof key === 'string' && /^(zapid|zapSessionKey)$/i.test(key)) {
        return '<redacted>'
    }
    if (typeof value === 'string') {
        return redactZapCallbackUrlForLog(value)
    }
    if (Array.isArray(value)) {
        return value.map((item) => redactZapLogValue(item))
    }
    if (value && typeof value === 'object') {
        const redacted = {}
        for (const [entryKey, entryValue] of Object.entries(value)) {
            redacted[entryKey] = redactZapLogValue(entryValue, entryKey)
        }
        return redacted
    }
    return value
}

function createBrowserId() {
    if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
        return globalThis.crypto.randomUUID()
    }
    return `ptk-browser-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`
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

function effectiveHttpPort(parsed) {
    if (!parsed || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')) return -1
    if (parsed.port) return Number(parsed.port)
    return parsed.protocol === 'https:' ? 443 : 80
}

function targetScopePathPrefix(pathname = '') {
    const path = typeof pathname === 'string' && pathname.startsWith('/') ? pathname : '/'
    if (!path || path === '/') return '/'
    if (path.endsWith('/')) return path
    const index = path.lastIndexOf('/')
    return index >= 0 ? path.slice(0, index + 1) : '/'
}

export function isSameOriginAndPathScoped(targetValue, candidateValue) {
    const targetString = safeParseUrl(targetValue)
    const candidateString = safeParseUrl(candidateValue)
    if (!targetString || !candidateString) return false

    try {
        const target = new URL(targetString)
        const candidate = new URL(candidateString)
        if (target.protocol !== candidate.protocol) return false
        if (!target.hostname || !candidate.hostname) return false
        if (target.hostname.toLowerCase() !== candidate.hostname.toLowerCase()) return false
        if (effectiveHttpPort(target) !== effectiveHttpPort(candidate)) return false
        return candidate.pathname.startsWith(targetScopePathPrefix(target.pathname))
    } catch (_) {
        return false
    }
}

function parseCallbackUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl) return null

    try {
        const parsed = new URL(rawUrl)
        if (parsed.origin !== TRUSTED_ZAP_ORIGIN) {
            return null
        }
        const match = parsed.pathname.match(CALLBACK_PATH_REGEX)
        if (!match || !match[1]) {
            return null
        }
        return {
            origin: parsed.origin,
            secret: match[1],
            zapid: toNonEmptyString(parsed.searchParams.get('zapid'))
        }
    } catch (_) {
        return null
    }
}

function isTrustedCallbackEndpoint(rawUrl, endpoint = null) {
    if (typeof rawUrl !== 'string' || !rawUrl) return false
    try {
        const parsed = new URL(rawUrl)
        if (parsed.origin !== TRUSTED_ZAP_ORIGIN || parsed.search || parsed.hash) return false
        const match = parsed.pathname.match(/^\/zapCallBackUrl\/[A-Za-z0-9_-]+\/ptk\/(config|alert|progress|control)$/i)
        if (!match) return false
        return !endpoint || match[1].toLowerCase() === endpoint
    } catch (_) {
        return false
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
    const fullMatch = body.match(/https:\/\/zap\/zapCallBackUrl\/[A-Za-z0-9_-]+(?:\?[^"'\\s<>]*)?/i)
    if (fullMatch && fullMatch[0]) {
        return fullMatch[0]
    }

    const pathMatch = body.match(/\/zapCallBackUrl\/([^"'\\s<>/?#]+)/i)
    if (pathMatch && pathMatch[1]) {
        return `https://zap/zapCallBackUrl/${pathMatch[1]}?zapenable=true`
    }

    return null
}

function buildCallbackCandidateUrl(secret, zapid = null) {
    if (!secret) return null

    try {
        const url = new URL(`${TRUSTED_ZAP_ORIGIN}/zapCallBackUrl/${secret}`)
        url.searchParams.set('zapenable', 'true')
        if (toNonEmptyString(zapid)) {
            url.searchParams.set('zapid', zapid)
        }
        return url.toString()
    } catch (_) {
        return null
    }
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
            if (!/^https:\/\/zap\//i.test(absolute)) continue
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
                const callbackUrl = new URL(value)
                if (!callbackUrl.searchParams.has('zapenable')) {
                    callbackUrl.searchParams.set('zapenable', 'true')
                }
                const quickstartZapId = toNonEmptyString(parsed.searchParams.get('zapid'))
                if (quickstartZapId && !callbackUrl.searchParams.has('zapid')) {
                    callbackUrl.searchParams.set('zapid', quickstartZapId)
                }
                return callbackUrl.toString()
            }

            // Accept callback path.
            const pathMatch = value.match(/^\/?zapCallBackUrl\/([^/?#]+)/i)
            if (pathMatch && pathMatch[1]) {
                return buildCallbackCandidateUrl(pathMatch[1], parsed.searchParams.get('zapid'))
            }

            // Accept secret-only values.
            if (/^[A-Za-z0-9_-]{6,}$/.test(value)) {
                return buildCallbackCandidateUrl(value, parsed.searchParams.get('zapid'))
            }
        }
    } catch (_) {
        return null
    }

    return null
}

function isZapBootstrapUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl) return false
    return CALLBACK_URL_REGEX.test(rawUrl)
        || QUICKSTART_URL_REGEX.test(rawUrl)
        || /(?:[?&])zapenable=true(?:[=&]|$)/i.test(rawUrl)
}

function isDirectZapCallbackUrl(rawUrl) {
    return !!parseCallbackUrl(rawUrl)
}

class ZapTransport {
    constructor() {
        this._isFirefox = !!browser?.runtime?.getBrowserInfo
        this.secret = null
        this.zapid = null
        this.browserid = createBrowserId()
        this.baseUrl = null
        this.configUrl = null
        this.alertsUrl = null
        this.progressUrl = null
        this.controlUrl = null
        this.active = false
        this._activeSessionTerminal = false
        this._lastDetectedPayload = null
        this._detectedCallbacks = new Set()
        this._urlObservedCallbacks = new Set()
        this._listenerAttached = false
        this._onCommitted = null
        this._onBeforeNavigate = null
        this._onBeforeRequest = null
        this._onTabUpdated = null
        this._onTabCreated = null
        this._onTabReplaced = null
        this._onCreatedNavigationTarget = null
        this._lastDetectionByTab = new Map()
        this._lastQuickstartProbeByTab = new Map()
        this._callbackRoutesByZapId = new Map()
        this._callbackRoutesByBaseUrl = new Map()
        this._callbackRoutesByTabId = new Map()
        this._controlSupportByRouteKey = new Map()
        this._startupBootstrapRunId = 0
        this._activeCallbackRecoveryTimer = null
        this._activeCallbackRecoveryUntil = 0
        this._activeCallbackRecoveryRunning = false
    }

    _lifecycleLog(event, details = {}) {
        const startup = getZapStartupSnapshot(globalThis)
        if (startup.expiredNow) {
            logZapLifecycle('zapTransport.gateExpired', {
                pending: startup.pending,
                startupId: startup.startupId,
                armedAt: startup.armedAt,
                expiresAt: startup.expiresAt,
                expiredAt: startup.expiredAt,
                clearReason: startup.clearReason
            })
        }
        logZapLifecycle(event, redactZapLogValue({
            pending: startup.pending,
            startupId: startup.startupId,
            armedAt: startup.armedAt,
            expiresAt: startup.expiresAt,
            ...details
        }))
    }

    _isStartupGateOpen() {
        return isZapStartupPending(globalThis)
    }

    _canProcessLiveSignals(url = '', source = 'unknown') {
        if (this.active) return true
        if (isDirectZapCallbackUrl(url)) {
            return true
        }
        if (this._isFirefox) {
            return isZapBootstrapUrl(url)
        }
        if (!this._isStartupGateOpen()) {
            return false
        }
        return true
    }

    _shouldObserveUrl(source, url = '') {
        if (!url) return false
        if (this.active) {
            if (this._activeSessionTerminal) {
                return isZapBootstrapUrl(url)
            }
            return isZapBootstrapUrl(url) || !!safeParseUrl(url)
        }
        return this._canProcessLiveSignals(url, source)
    }

    clearSessionTerminal() {
        this._activeSessionTerminal = false
        this._activeSessionTerminalDetails = null
    }

    markSessionTerminal(details = {}) {
        if (!this.active || this._activeSessionTerminal) {
            return
        }
        this._activeSessionTerminal = true
        this._activeSessionTerminalDetails = {
            status: toNonEmptyString(details.status) || null,
            progress: Number.isFinite(Number(details.progress)) ? Number(details.progress) : null,
            zapid: toNonEmptyString(details.zapid) || this.zapid || null,
            sessionId: toNonEmptyString(details.sessionId) || null,
            markedAt: new Date().toISOString()
        }
        this._lifecycleLog('zapTransport.sessionTerminal', {
            status: this._activeSessionTerminalDetails.status,
            progress: this._activeSessionTerminalDetails.progress,
            zapid: this._activeSessionTerminalDetails.zapid,
            sessionId: this._activeSessionTerminalDetails.sessionId
        })
    }

    isSessionTerminal(details = {}) {
        if (!this._activeSessionTerminal) {
            return false
        }
        const expectedZapId = toNonEmptyString(details.zapid)
        const expectedSessionId = toNonEmptyString(details.sessionId)
        if (expectedZapId && this._activeSessionTerminalDetails?.zapid && expectedZapId !== this._activeSessionTerminalDetails.zapid) {
            return false
        }
        if (expectedSessionId && this._activeSessionTerminalDetails?.sessionId && expectedSessionId !== this._activeSessionTerminalDetails.sessionId) {
            return false
        }
        return true
    }

    getSessionTerminalDetails() {
        return this._activeSessionTerminalDetails
            ? Object.assign({}, this._activeSessionTerminalDetails)
            : null
    }

    handleStartupGateOpened(source = 'unknown') {
        this._lifecycleLog('zapTransport.gateOpened', {
            source,
            active: this.active
        })
        if (!this._listenerAttached) {
            return
        }
        if (this.active) {
            this._extendActiveCallbackRecoveryWindow(source)
            return
        }
        this._scheduleStartupBootstraps(source)
    }

    _scheduleStartupBootstraps(source = 'unknown') {
        const runId = ++this._startupBootstrapRunId
        this._lifecycleLog('zapTransport.bootstrap.schedule', {
            source,
            runId,
            delaysMs: STARTUP_BOOTSTRAP_RETRY_DELAYS_MS
        })

        for (const delayMs of STARTUP_BOOTSTRAP_RETRY_DELAYS_MS) {
            const run = async () => {
                if (runId !== this._startupBootstrapRunId || this.active || !this._isStartupGateOpen()) {
                    return
                }
                this._lifecycleLog('zapTransport.bootstrap.run', {
                    source,
                    runId,
                    delayMs
                })
                await this._bootstrapFromOpenTabs()
            }

            if (delayMs <= 0) {
                void run()
            } else {
                setTimeout(() => {
                    void run()
                }, delayMs)
            }
        }
    }

    _closeStartupGate(reason = 'callback_detected') {
        this._startupBootstrapRunId++
        const snapshot = clearZapStartupPending(globalThis, { reason })
        this._lifecycleLog('zapTransport.gateClosed', {
            reason,
            ...snapshot
        })
        return snapshot
    }

    _logCallbackSignalSuppressed(reason = 'unknown', details = {}) {
        this._lifecycleLog('callback_signal_suppressed', {
            reason,
            ...details
        })
    }

    _extendActiveCallbackRecoveryWindow(source = 'unknown') {
        if (!browser?.tabs?.query) return
        const until = Date.now() + ACTIVE_CALLBACK_RECOVERY_WINDOW_MS
        if (until > this._activeCallbackRecoveryUntil) {
            this._activeCallbackRecoveryUntil = until
        }
        this._ensureActiveCallbackRecoveryScanner(source)
    }

    _ensureActiveCallbackRecoveryScanner(source = 'unknown') {
        if (this._activeCallbackRecoveryTimer || !browser?.tabs?.query) return

        const run = async () => {
            this._activeCallbackRecoveryTimer = null
            const shouldContinue = (this.active || this._isStartupGateOpen())
                && Date.now() <= this._activeCallbackRecoveryUntil
            if (!shouldContinue) return

            if (!this._activeCallbackRecoveryRunning) {
                this._activeCallbackRecoveryRunning = true
                try {
                    await this._scanOpenTabsForDirectCallbackUrls(`active.callback.recovery:${source}`)
                } finally {
                    this._activeCallbackRecoveryRunning = false
                }
            }

            if ((this.active || this._isStartupGateOpen()) && Date.now() <= this._activeCallbackRecoveryUntil) {
                this._activeCallbackRecoveryTimer = setTimeout(run, ACTIVE_CALLBACK_RECOVERY_INTERVAL_MS)
            }
        }

        this._activeCallbackRecoveryTimer = setTimeout(run, ACTIVE_CALLBACK_RECOVERY_INTERVAL_MS)
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
        const hasBeforeRequest = !!browser?.webRequest?.onBeforeRequest?.addListener
        const hasTabUpdated = !!browser?.tabs?.onUpdated
        const hasTabCreated = !!browser?.tabs?.onCreated
        const hasTabReplaced = !!browser?.tabs?.onReplaced

        if (
            !hasCommitted
            && !hasBeforeNavigate
            && !hasCreatedNavigationTarget
            && !hasBeforeRequest
            && !hasTabUpdated
            && !hasTabCreated
            && !hasTabReplaced
        ) {
            console.warn('[PTK ZAP] No navigation APIs available for ZAP detection')
            return
        }

        this._lifecycleLog('zapTransport.init', {
            isFirefox: this._isFirefox,
            hasCommitted,
            hasBeforeNavigate,
            hasCreatedNavigationTarget,
            hasBeforeRequest,
            hasTabUpdated,
            hasTabCreated,
            hasTabReplaced
        })

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

        if (hasBeforeRequest) {
            this._onBeforeRequest = this._onBeforeRequest || this._handleWebRequestBefore.bind(this)
            try {
                browser.webRequest.onBeforeRequest.addListener(this._onBeforeRequest, {
                    urls: ['https://zap/zapCallBackUrl/*'],
                    types: ['main_frame']
                })
            } catch (err) {
                this._logCallbackSignalSuppressed('webrequest_listener_unavailable', {
                    source: 'webRequest.onBeforeRequest',
                    error: err?.message || String(err)
                })
            }
        } else {
            this._logCallbackSignalSuppressed('webrequest_listener_unavailable', {
                source: 'zapTransport.init'
            })
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

        this._listenerAttached = true
        if (this._isStartupGateOpen()) {
            this._scheduleStartupBootstraps('init')
        } else if (this.active) {
            this._extendActiveCallbackRecoveryWindow('init.active')
        } else {
            this._lifecycleLog('zapTransport.init.gateClosed', {
                active: this.active,
                startupPending: this._isStartupGateOpen()
            })
        }
    }

    isActive() {
        return this.active && !!this.baseUrl && !!this.configUrl && !!this.alertsUrl && !!this.progressUrl
    }

    isReady(options = {}) {
        if (!options || (!options.zapid && !options.baseUrl)) {
            return this.isActive()
        }
        const route = this._getCallbackRoute(options)
        return !!(route?.baseUrl && route?.configUrl && route?.alertsUrl && route?.progressUrl)
    }

    getBaseUrl(options = {}) {
        return this._getCallbackRoute(options)?.baseUrl || this.baseUrl
    }

    getZapId() {
        return this.zapid
    }

    getBrowserId() {
        return this.browserid
    }

    getConfigUrl(options = {}) {
        return this._getCallbackRoute(options)?.configUrl || this.configUrl
    }

    getAlertsUrl(options = {}) {
        return this._getCallbackRoute(options)?.alertsUrl || this.alertsUrl
    }

    getProgressUrl(options = {}) {
        return this._getCallbackRoute(options)?.progressUrl || this.progressUrl
    }

    getControlUrl(options = {}) {
        return this._getCallbackRoute(options)?.controlUrl || this.controlUrl
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

    getStartupSnapshot() {
        return getZapStartupSnapshot(globalThis)
    }

    isBootstrapUrl(url = '') {
        return isZapBootstrapUrl(url)
    }

    processContentObservedZapUrl({ tabId = null, frameId = 0, url = '', targetUrl = null } = {}) {
        if (!isZapBootstrapUrl(url)) {
            this._logCallbackSignalSuppressed('parse_failed', {
                source: 'content.zapCallback',
                tabId,
                frameId,
                url
            })
            return false
        }

        this._lifecycleLog('background_callback_received', {
            source: 'content.zapCallback',
            tabId,
            frameId,
            url
        })

        this._logCaughtUrl('content.zapCallback', {
            tabId,
            frameId,
            url
        })

        return this._processPotentialZapUrl({
            tabId,
            url,
            source: 'content.zapCallback',
            targetUrl
        })
    }

    processContentObservedTargetUrl({ tabId = null, frameId = 0, url = '' } = {}) {
        if (!this.isActive()) {
            return false
        }
        if (frameId !== 0) {
            return false
        }
        const targetUrl = safeParseUrl(url)
        if (!targetUrl || isZapBootstrapUrl(targetUrl)) {
            return false
        }

        const detectedPayload = this._lastDetectedPayload || null
        const detectedTabId = Number.isInteger(detectedPayload?.tabId) ? detectedPayload.tabId : null
        const scopedTargetUrl = safeParseUrl(detectedPayload?.targetUrl)
        const routeForTab = this._getCallbackRouteByTabId(tabId)

        if (routeForTab) {
            const scopedRouteTargetUrl = safeParseUrl(routeForTab.targetUrl)
            if (scopedRouteTargetUrl && !isSameOriginAndPathScoped(scopedRouteTargetUrl, targetUrl)) {
                debugLog('[PTK ZAP] Rejected out-of-scope target URL for callback tab', {
                    tabId,
                    frameId,
                    url: targetUrl,
                    targetUrl: scopedRouteTargetUrl
                })
                return false
            }
            if (!scopedRouteTargetUrl) {
                this._rememberCallbackRoute(Object.assign({}, routeForTab, {
                    tabId,
                    targetUrl
                }))
                const routeMatchesCurrentPayload = (routeForTab.zapid && routeForTab.zapid === detectedPayload?.zapid)
                    || (routeForTab.baseUrl && routeForTab.baseUrl === detectedPayload?.baseUrl)
                    || (Number.isInteger(detectedTabId) && detectedTabId === tabId)
                if (routeMatchesCurrentPayload) {
                    this._lastDetectedPayload = Object.assign({}, detectedPayload || {}, {
                        targetUrl
                    })
                }
            }
        } else if (scopedTargetUrl) {
            if (!isSameOriginAndPathScoped(scopedTargetUrl, targetUrl)) {
                debugLog('[PTK ZAP] Rejected out-of-scope target URL', {
                    tabId,
                    frameId,
                    url: targetUrl,
                    targetUrl: scopedTargetUrl
                })
                return false
            }
        } else if (Number.isInteger(detectedTabId) && detectedTabId === tabId) {
            this._lastDetectedPayload = Object.assign({}, detectedPayload || {}, {
                targetUrl
            })
        } else {
            debugLog('[PTK ZAP] Rejected unclaimed target URL', {
                tabId,
                frameId,
                url: targetUrl,
                detectedTabId
            })
            return false
        }

        this._logCaughtUrl('content.zapTarget', {
            tabId,
            frameId,
            url: targetUrl
        })
        return true
    }

    async _postJsonWithRetry(url, obj, errorCode, options = {}) {
        if (!url) {
            throw new Error(errorCode)
        }
        if (!isTrustedCallbackEndpoint(url)) {
            throw new Error(`${errorCode}_untrusted_endpoint`)
        }
        const timeoutMs = Number.isFinite(Number(options?.timeoutMs))
            ? Math.max(250, Number(options.timeoutMs))
            : CONFIG_DIRECT_FETCH_TIMEOUT_MS
        const retryDelaysMs = Array.isArray(options?.retryDelaysMs)
            ? options.retryDelaysMs
            : RETRY_DELAYS_MS
        let lastError = null
        for (let attempt = 0; attempt <= retryDelaysMs.length; attempt++) {
            try {
                const response = await fetchWithTimeout(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(obj),
                    credentials: 'omit',
                    redirect: 'error',
                    cache: 'no-store'
                }, timeoutMs)

                const acceptedStatusZero = response.status === 0 && response.type !== 'opaque'
                if (!response.ok && !acceptedStatusZero) {
                    throw new Error(`${errorCode}_http_${response.status}`)
                }

                return response
            } catch (err) {
                lastError = err
                if (attempt >= retryDelaysMs.length) {
                    break
                }
                await sleep(retryDelaysMs[attempt])
            }
        }

        throw lastError || new Error(errorCode)
    }

    _rememberCallbackRoute(payload = {}) {
        const route = {
            zapid: toNonEmptyString(payload.zapid) || null,
            baseUrl: toNonEmptyString(payload.baseUrl) || null,
            configUrl: toNonEmptyString(payload.configUrl) || null,
            alertsUrl: toNonEmptyString(payload.alertsUrl) || null,
            progressUrl: toNonEmptyString(payload.progressUrl) || null,
            controlUrl: toNonEmptyString(payload.controlUrl) || null,
            secret: toNonEmptyString(payload.secret) || null,
            tabId: Number.isInteger(payload.tabId) ? payload.tabId : null,
            targetUrl: toNonEmptyString(payload.targetUrl) || null,
            detectedAt: Number.isFinite(Number(payload.detectedAt)) ? Number(payload.detectedAt) : Date.now()
        }
        if (!route.configUrl || !route.alertsUrl || !route.progressUrl) {
            return null
        }
        if (
            !isTrustedCallbackEndpoint(route.configUrl, 'config')
            || !isTrustedCallbackEndpoint(route.alertsUrl, 'alert')
            || !isTrustedCallbackEndpoint(route.progressUrl, 'progress')
            || (route.controlUrl && !isTrustedCallbackEndpoint(route.controlUrl, 'control'))
        ) {
            return null
        }
        if (route.zapid) {
            this._callbackRoutesByZapId.set(route.zapid, route)
        }
        if (route.baseUrl) {
            this._callbackRoutesByBaseUrl.set(route.baseUrl, route)
        }
        if (Number.isInteger(route.tabId) && route.tabId >= 0) {
            this._callbackRoutesByTabId.set(route.tabId, route)
        }
        return route
    }

    _getCallbackRoute(options = {}) {
        const zapid = toNonEmptyString(options?.zapid)
            || toNonEmptyString(options?.payload?.zapid)
            || toNonEmptyString(options?.body?.zapid)
        if (zapid && this._callbackRoutesByZapId.has(zapid)) {
            return this._callbackRoutesByZapId.get(zapid)
        }

        const baseUrl = toNonEmptyString(options?.baseUrl)
            || toNonEmptyString(options?.payload?.baseUrl)
            || toNonEmptyString(options?.body?.baseUrl)
        if (baseUrl && this._callbackRoutesByBaseUrl.has(baseUrl)) {
            return this._callbackRoutesByBaseUrl.get(baseUrl)
        }

        if (this.configUrl || this.alertsUrl || this.progressUrl) {
            return {
                zapid: this.zapid || null,
                baseUrl: this.baseUrl || null,
                configUrl: this.configUrl || null,
                alertsUrl: this.alertsUrl || null,
                progressUrl: this.progressUrl || null,
                controlUrl: this.controlUrl || null,
                secret: this.secret || null
            }
        }
        return null
    }

    _getCallbackRouteByTabId(tabId) {
        if (!Number.isInteger(tabId) || tabId < 0) {
            return null
        }
        return this._callbackRoutesByTabId.get(tabId) || null
    }

    _controlRouteKey(route = null) {
        const zapid = toNonEmptyString(route?.zapid) || this.zapid || null
        if (zapid) return `zapid:${zapid}`
        const baseUrl = toNonEmptyString(route?.baseUrl) || this.baseUrl || null
        if (baseUrl) return `base:${baseUrl}`
        return null
    }

    _markControlSupport(route = null, supported = true) {
        const key = this._controlRouteKey(route)
        if (!key) return
        this._controlSupportByRouteKey.set(key, supported === true)
    }

    _isControlUnsupported(route = null) {
        const key = this._controlRouteKey(route)
        return key ? this._controlSupportByRouteKey.get(key) === false : false
    }

    async postAlertsJson(obj) {
        const body = isObjectPayload(obj) ? { ...obj } : obj
        const route = this._getCallbackRoute(body)
        const alertsUrl = route?.alertsUrl || this.alertsUrl
        if (!alertsUrl) {
            throw new Error('zap_alerts_not_ready')
        }

        if (isObjectPayload(body)) {
            if (!toNonEmptyString(body.zapid) && route?.zapid) {
                body.zapid = route.zapid
            }
            if (!toNonEmptyString(body.browserid) && this.browserid) {
                body.browserid = this.browserid
            }
        }

        debugLog('[PTK ZAP] Sending alerts POST to:', alertsUrl)
        const response = await this._postJsonWithRetry(alertsUrl, body, 'zap_alerts_failed', {
            timeoutMs: CALLBACK_ALERT_POST_TIMEOUT_MS
        })
        if (response.status === 0 && response.type !== 'opaque') {
            debugLog('[PTK ZAP] Alerts POST accepted from non-OK HTTP status because transport returned status 0')
        }
        debugLog('[PTK ZAP] Alerts POST response:', response.status)
        let data = null
        try {
            const text = await response.clone().text()
            data = text ? JSON.parse(text) : null
        } catch (err) {
            debugLog('[PTK ZAP] Alerts response parse skipped:', err?.message || String(err))
        }
        return { response, data }
    }

    async postProgressJson(payload = {}) {
        const route = this._getCallbackRoute(payload)
        const progressUrl = route?.progressUrl || this.progressUrl
        const zapid = toNonEmptyString(payload?.zapid) || route?.zapid || this.zapid
        if (!progressUrl) {
            throw new Error('zap_progress_not_ready')
        }
        if (!zapid) {
            throw new Error('zap_progress_missing_zapid')
        }
        const body = {
            zapid,
            browserid: this.browserid,
            progress: payload.progress,
            status: payload.status
        }
        if (Number.isFinite(Number(payload.contractVersion))) {
            body.contractVersion = Number(payload.contractVersion)
        }
        if (toNonEmptyString(payload.phase)) {
            body.phase = payload.phase.trim()
        }
        if (toNonEmptyString(payload.sessionId)) {
            body.sessionId = payload.sessionId.trim()
        }
        if (toNonEmptyString(payload.targetUrl)) {
            body.targetUrl = payload.targetUrl.trim()
        }
        if (typeof payload.safeToClose === 'boolean') {
            body.safeToClose = payload.safeToClose
        }
        if (toNonEmptyString(payload.message)) {
            body.message = payload.message.trim()
        }
        if (toNonEmptyString(payload.completionStatus)) {
            body.completionStatus = payload.completionStatus.trim()
        }
        if (toNonEmptyString(payload.releaseStatus)) {
            body.releaseStatus = payload.releaseStatus.trim()
        }
        if (payload.engines && typeof payload.engines === 'object' && !Array.isArray(payload.engines)) {
            body.engines = payload.engines
        }
        if (Number.isFinite(Number(payload.activitySeq))) {
            body.activitySeq = Number(payload.activitySeq)
        }
        if (toNonEmptyString(payload.activityFingerprint)) {
            body.activityFingerprint = payload.activityFingerprint.trim()
        }
        if (payload.closeReadiness && typeof payload.closeReadiness === 'object' && !Array.isArray(payload.closeReadiness)) {
            body.closeReadiness = payload.closeReadiness
        }
        if (payload.publisher && typeof payload.publisher === 'object' && !Array.isArray(payload.publisher)) {
            body.publisher = payload.publisher
        }
        if (typeof payload.terminalSeen === 'boolean') {
            body.terminalSeen = payload.terminalSeen
        }
        if (toNonEmptyString(payload.closeRequestId)) {
            body.closeRequestId = payload.closeRequestId.trim()
        }
        if (typeof payload.closeRequestAck === 'boolean') {
            body.closeRequestAck = payload.closeRequestAck
        }
        if (toNonEmptyString(payload.closeRequestMode)) {
            body.closeRequestMode = payload.closeRequestMode.trim()
        }

        debugLog('[PTK ZAP] Sending progress POST:', {
            url: progressUrl,
            body
        })
        const response = await this._postJsonWithRetry(progressUrl, body, 'zap_progress_failed', {
            timeoutMs: CALLBACK_PROGRESS_POST_TIMEOUT_MS,
            retryDelaysMs: CALLBACK_PROGRESS_RETRY_DELAYS_MS
        })
        let data = null
        try {
            const text = await response.clone().text()
            data = text ? JSON.parse(text) : null
        } catch (err) {
            debugLog('[PTK ZAP] Progress response parse skipped:', err?.message || String(err))
        }
        return { response, data }
    }

    async postControlJson(payload = {}) {
        const route = this._getCallbackRoute(payload)
        const controlUrl = route?.controlUrl || this.controlUrl
        const zapid = toNonEmptyString(payload?.zapid) || route?.zapid || this.zapid
        if (!controlUrl || this._isControlUnsupported(route)) {
            return {
                response: null,
                data: { result: 'UNSUPPORTED', closeRequested: false, controlUnsupported: true },
                unsupported: true
            }
        }
        if (!zapid) {
            throw new Error('zap_control_missing_zapid')
        }

        const body = {
            contractVersion: Number.isFinite(Number(payload.contractVersion))
                ? Number(payload.contractVersion)
                : 2,
            zapid,
            browserid: this.browserid
        }
        for (const key of [
            'sessionId',
            'activityFingerprint',
            'closeRequestId',
            'closeRequestMode'
        ]) {
            if (toNonEmptyString(payload[key])) {
                body[key] = payload[key].trim()
            }
        }
        if (Number.isFinite(Number(payload.activitySeq))) {
            body.activitySeq = Number(payload.activitySeq)
        }
        if (payload.publisher && typeof payload.publisher === 'object' && !Array.isArray(payload.publisher)) {
            body.publisher = payload.publisher
        }
        if (typeof payload.closeRequestAck === 'boolean') {
            body.closeRequestAck = payload.closeRequestAck
        }

        try {
            const response = await this._postJsonWithRetry(controlUrl, body, 'zap_control_failed', {
                timeoutMs: CALLBACK_CONTROL_POST_TIMEOUT_MS,
                retryDelaysMs: CALLBACK_CONTROL_RETRY_DELAYS_MS
            })
            let data = null
            try {
                const text = await response.clone().text()
                data = text ? JSON.parse(text) : null
            } catch (_) {
                this._markControlSupport(route, false)
                return {
                    response,
                    data: { result: 'UNSUPPORTED', closeRequested: false, controlUnsupported: true },
                    unsupported: true
                }
            }
            if (!data || typeof data !== 'object' || Array.isArray(data)) {
                this._markControlSupport(route, false)
                return {
                    response,
                    data: { result: 'UNSUPPORTED', closeRequested: false, controlUnsupported: true },
                    unsupported: true
                }
            }
            this._markControlSupport(route, true)
            return { response, data }
        } catch (err) {
            const message = err?.message || String(err)
            if (/zap_control_failed_http_(?:400|404|405|410|501)/.test(message)) {
                this._markControlSupport(route, false)
                return {
                    response: null,
                    data: { result: 'UNSUPPORTED', closeRequested: false, controlUnsupported: true },
                    unsupported: true,
                    error: message
                }
            }
            throw err
        }
    }

    // Backward-compatible alias.
    async postJson(obj) {
        return this.postAlertsJson(obj)
    }

    async fetchConfig(options = {}) {
        const route = this._getCallbackRoute(options)
        const configUrl = route?.configUrl || this.configUrl
        const zapid = toNonEmptyString(options?.zapid) || route?.zapid || this.zapid
        if (!configUrl) {
            debugLog('[PTK ZAP] No callback URL stored, cannot fetch config')
            return {
                ptkConfigFetchFailed: true,
                error: 'zap_config_url_unavailable',
                elapsedMs: 0,
                diagnostics: [{ kind: 'missing_config_url' }]
            }
        }
        if (!zapid) {
            debugLog('[PTK ZAP] No zapid stored, cannot fetch config yet')
            return {
                ptkConfigFetchFailed: true,
                error: 'zapid_unavailable',
                elapsedMs: 0,
                diagnostics: [{ kind: 'missing_zapid' }]
            }
        }
        if (!isTrustedCallbackEndpoint(configUrl, 'config')) {
            return {
                ptkConfigFetchFailed: true,
                error: 'zap_config_url_untrusted',
                elapsedMs: 0,
                diagnostics: [{ kind: 'untrusted_config_url' }]
            }
        }

        const startedAt = Date.now()
        const diagnostics = []

        debugLog('[PTK ZAP] Fetching config from:', configUrl)
        this._lifecycleLog('config_fetch_started', {
            zapid,
            configUrl,
            baseUrl: route?.baseUrl || this.baseUrl || null,
            targetUrl: toNonEmptyString(options?.targetUrl) || null
        })
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
                const requestBody = {
                    zapid,
                    browserid: this.browserid
                }
                const targetUrl = toNonEmptyString(options?.targetUrl)
                if (targetUrl) {
                    requestBody.targetUrl = targetUrl
                }

                const response = await fetchWithTimeout(configUrl, {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(requestBody),
                    cache: 'no-store',
                    credentials: 'omit',
                    redirect: 'error'
                }, CONFIG_DIRECT_FETCH_TIMEOUT_MS)

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
                        const route = this._getCallbackRoute({ zapid, baseUrl: this.baseUrl })
                        if (data.ptkControlSupported === true || data.controlSupported === true) {
                            this._markControlSupport(route, true)
                        } else if (data.ptkControlSupported === false || data.controlSupported === false) {
                            this._markControlSupport(route, false)
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
            configUrl,
            zapid,
            elapsedMs: Date.now() - startedAt,
            strategy: 'background_fetch_only',
            recentDiagnostics: diagnostics.slice(-12)
        })
        debugLog('[PTK ZAP] Config unavailable; ZAP automation config fetch failed')
        return {
            ptkConfigFetchFailed: true,
            error: 'zap_config_unavailable',
            elapsedMs: Date.now() - startedAt,
            diagnostics: diagnostics.slice(-12)
        }
    }

    async confirmZap(options = {}) {
        return this.fetchConfig(options)
    }

    _handleNavigationCommitted(details) {
        if (!details) return
        const url = details.url || ''
        if (!this._canProcessLiveSignals(url, 'webNavigation.onCommitted')) {
            return
        }

        this._logCaughtUrl('webNavigation.onCommitted', {
            tabId: details.tabId,
            frameId: details.frameId,
            url
        })

        this._processPotentialZapUrl({
            tabId: details.tabId,
            url,
            source: 'webNavigation.onCommitted'
        })
    }

    _handleNavigationBefore(details) {
        if (!details) return
        const url = details.url || ''
        if (!this._canProcessLiveSignals(url, 'webNavigation.onBeforeNavigate')) {
            return
        }

        this._logCaughtUrl('webNavigation.onBeforeNavigate', {
            tabId: details.tabId,
            frameId: details.frameId,
            url
        })

        this._processPotentialZapUrl({
            tabId: details.tabId,
            url,
            source: 'webNavigation.onBeforeNavigate'
        })
    }

    _handleWebRequestBefore(details = {}) {
        const url = details?.url || ''
        if (!isDirectZapCallbackUrl(url)) {
            return
        }
        if (!this._canProcessLiveSignals(url, 'webRequest.onBeforeRequest')) {
            this._logCallbackSignalSuppressed('startup_gate_closed', {
                source: 'webRequest.onBeforeRequest',
                tabId: details.tabId,
                frameId: details.frameId,
                url
            })
            return
        }

        this._logCaughtUrl('webRequest.onBeforeRequest', {
            tabId: details.tabId,
            frameId: Number.isInteger(details.frameId) ? details.frameId : 0,
            url
        })

        this._processPotentialZapUrl({
            tabId: details.tabId,
            url,
            source: 'webRequest.onBeforeRequest'
        })
    }

    _handleCreatedNavigationTarget(details) {
        if (!details) return
        const url = details.url || ''
        if (!url) return
        if (!this._canProcessLiveSignals(url, 'webNavigation.onCreatedNavigationTarget')) {
            return
        }

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
            if (!this._canProcessLiveSignals(url, 'tabs.onUpdated')) {
                continue
            }
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
            if (!this._canProcessLiveSignals(url, 'tabs.onCreated')) {
                continue
            }
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
                if (!this._canProcessLiveSignals(url, 'tabs.onReplaced')) {
                    continue
                }
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

    async _bootstrapFromOpenTabs() {
        if (!browser?.tabs?.query || !this._isStartupGateOpen() || this.active) return

        try {
            await this._scanOpenTabsForPotentialZapUrls('bootstrap.tabs.query')
        } catch (err) {
            console.warn('[PTK ZAP] Failed to bootstrap ZAP detection from existing tabs:', err?.message || String(err))
        }
    }

    async _scanOpenTabsForPotentialZapUrls(source = 'bootstrap.tabs.query') {
        if (!browser?.tabs?.query || !this._isStartupGateOpen() || this.active) return

        const tabs = await browser.tabs.query({})
        for (const tab of tabs) {
            if (this.active || !this._isStartupGateOpen()) {
                return
            }
            const urls = [
                tab?.pendingUrl || '',
                tab?.url || ''
            ].filter(Boolean)

            for (const url of urls) {
                if (this.active || !this._isStartupGateOpen()) {
                    return
                }
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
                if (this.active || !this._isStartupGateOpen()) {
                    return
                }
            }
        }
    }

    async scanOpenTabsForDirectCallbackUrls(source = 'zap.runner') {
        return this._scanOpenTabsForDirectCallbackUrls(source)
    }

    async _scanOpenTabsForDirectCallbackUrls(source = 'active.callback.recovery') {
        if (!browser?.tabs?.query) return false

        let observed = false
        const tabs = await browser.tabs.query({})
        for (const tab of tabs) {
            const urls = [
                tab?.pendingUrl || '',
                tab?.url || ''
            ].filter(Boolean)

            for (const url of urls) {
                if (!isDirectZapCallbackUrl(url)) {
                    continue
                }
                this._logCaughtUrl(source, {
                    tabId: tab.id,
                    frameId: 0,
                    url
                })
                observed = this._processPotentialZapUrl({
                    tabId: tab.id,
                    url,
                    source
                }) || observed
            }
        }
        return observed
    }

    _processPotentialZapUrl({ tabId, url, source = 'unknown', targetUrl: observedTargetUrl = null } = {}) {
        if (!this._canProcessLiveSignals(url, source)) {
            this._logCallbackSignalSuppressed('startup_gate_closed', {
                source,
                tabId,
                url
            })
            return false
        }
        if (typeof url !== 'string') {
            this._logCallbackSignalSuppressed('parse_failed', {
                source,
                tabId
            })
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
            this._logCallbackSignalSuppressed('parse_failed', {
                source,
                tabId,
                url
            })
            return false
        }

        const secret = callbackInfo?.secret || ''
        const detectedZapId = callbackInfo?.zapid || null
        if (!secret) {
            debugLog('[PTK ZAP] URL hint observed but no valid callback pattern')
            this._logCallbackSignalSuppressed('parse_failed', {
                source,
                tabId,
                url
            })
            return false
        }
        if (!detectedZapId) {
            this._logCallbackSignalSuppressed('missing_zapid', {
                source,
                tabId,
                url
            })
        }

        const baseUrl = this._buildBaseUrl(url, secret)
        const configUrl = `${baseUrl}/ptk/config`
        const alertsUrl = `${baseUrl}/ptk/alert`
        const progressUrl = `${baseUrl}/ptk/progress`
        const controlUrl = `${baseUrl}/ptk/control`
        const existingZapId = this.zapid || this._lastDetectedPayload?.zapid || null
        const changed = this.baseUrl !== baseUrl || (!!existingZapId && !!detectedZapId && existingZapId !== detectedZapId)
        const needsZapIdEnrichment = !changed && !!detectedZapId && detectedZapId !== existingZapId
        const targetUrl = extractTargetUrl(url) || safeParseUrl(observedTargetUrl)
        const now = Date.now()
        const hasLiveTabId = Number.isInteger(tabId) && tabId >= 0
        const currentTabId = this._lastDetectedPayload?.tabId
        const needsTabRebind = hasLiveTabId && (!Number.isInteger(currentTabId) || currentTabId < 0)
        const needsTargetUrlEnrichment = !!targetUrl && targetUrl !== this._lastDetectedPayload?.targetUrl

        this._lifecycleLog('callback_observed', {
            source,
            tabId,
            baseUrl,
            zapid: detectedZapId || null,
            url
        })

        // If we already have the same active ZAP callback, ignore repeated re-checks.
        if (this.active && !changed) {
            if (needsTabRebind || needsZapIdEnrichment || needsTargetUrlEnrichment) {
                debugLog('[PTK ZAP] Rebinding active ZAP session to live tab', {
                    tabId,
                    source
                })
                const payload = Object.assign({}, this._lastDetectedPayload || {}, {
                    tabId,
                    url,
                    source,
                    changed: false,
                    zapid: detectedZapId || existingZapId || null,
                    progressUrl: this.progressUrl || this._lastDetectedPayload?.progressUrl || null,
                    controlUrl: this.controlUrl || this._lastDetectedPayload?.controlUrl || null,
                    targetUrl: targetUrl || this._lastDetectedPayload?.targetUrl || null,
                    detectedAt: this._lastDetectedPayload?.detectedAt || now
                })
                this.zapid = payload.zapid || null
                this._lastDetectedPayload = payload
                this._rememberCallbackRoute(payload)
                this._emitDetected(payload)
                this._extendActiveCallbackRecoveryWindow(source)
                return true
            }
            this._logCallbackSignalSuppressed('duplicate_same_zapid', {
                source,
                tabId,
                baseUrl,
                zapid: detectedZapId || existingZapId || null,
                url
            })
            return false
        }

        debugLog('[PTK ZAP] Checking ZAP URL:', url)

        const dedupeKey = `${Number.isInteger(tabId) ? tabId : 'na'}|${baseUrl}|${detectedZapId || ''}|${source || ''}`
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
            this._logCallbackSignalSuppressed('duplicate_same_zapid', {
                source,
                tabId,
                baseUrl,
                zapid: detectedZapId || null,
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
            configUrl,
            alertsUrl,
            progressUrl,
            controlUrl,
            zapid: detectedZapId || null,
            browserid: this.browserid,
            changed,
            tabId,
            targetUrl,
            source
        })

        if (this._isStartupGateOpen()) {
            this._closeStartupGate('callback_detected')
        }

        this.secret = secret
        this.zapid = detectedZapId || null
        this.baseUrl = baseUrl
        this.configUrl = configUrl
        this.alertsUrl = alertsUrl
        this.progressUrl = progressUrl
        this.controlUrl = controlUrl
        this.active = true
        this._activeSessionTerminal = false
        const payload = {
            secret,
            zapid: this.zapid,
            browserid: this.browserid,
            baseUrl,
            configUrl,
            alertsUrl,
            progressUrl,
            controlUrl,
            tabId,
            url,
            targetUrl,
            detectedAt: now,
            changed,
            source
        }

        this._lastDetectedPayload = payload
        this._rememberCallbackRoute(payload)
        this._lifecycleLog('transport_processed_callback', {
            source,
            tabId,
            baseUrl,
            zapid: this.zapid,
            changed
        })
        this._emitDetected(payload)
        this._extendActiveCallbackRecoveryWindow(source)
        return true
    }

    _buildBaseUrl(url, secret) {
        return `${TRUSTED_ZAP_ORIGIN}/zapCallBackUrl/${secret}`
    }

    _logCaughtUrl(source, payload = {}) {
        const url = typeof payload.url === 'string' ? payload.url : ''
        if (!url) return
        if (!this._shouldObserveUrl(source, url)) {
            return
        }

        const now = Date.now()

        const observedPayload = {
            source,
            tabId: payload.tabId,
            frameId: payload.frameId,
            url,
            ts: now
        }

        this._emitUrlObserved(observedPayload)

        this._lifecycleLog(source, {
            tabId: Number.isInteger(payload.tabId) ? payload.tabId : null,
            frameId: Number.isInteger(payload.frameId) ? payload.frameId : null,
            url
        })

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
            const response = await fetch(url, {
                method: 'GET',
                cache: 'no-store',
                credentials: 'omit',
                redirect: 'error'
            })
            const text = await response.text()
            const body = String(text || '').slice(0, 400000)

            let candidate = extractCallbackCandidate(body)

            if (!candidate) {
                const scripts = extractQuickstartScriptUrls(body, url).slice(0, QUICKSTART_SCRIPT_FETCH_LIMIT)
                for (const scriptUrl of scripts) {
                    try {
                        const scriptResponse = await fetch(scriptUrl, {
                            method: 'GET',
                            cache: 'no-store',
                            credentials: 'omit',
                            redirect: 'error'
                        })
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
export {
    DAST_HISTORY_SEED_MAX_RESULTS,
    redactZapCallbackUrlForLog,
    redactZapLogValue
}
