/* Author: Denis Podgurskii */
'use strict'

import { zapBridge } from './integration/zap/index.js'
import buildExportScanResult from './export/buildExportScanResult.js'
import { resultsRegistry } from './resultsRegistry.js'
import { collapseDastAggregatedFindings } from './dast/services/dastFindingAggregation.js'
import { sastCollectionLooksComplete } from './sast/sast_progress.js'

// Mirrors the add-on close-contract PTK stop budget. This is a drain budget
// for current engine work, not permission to start new work during close.
const ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS = 25000
const ZAP_CLOSE_TERMINAL_FALLBACK_POLL_MS = 100
const PTK_CHILD_TAB_ENGINE_WAIT_MS = 750
const PTK_CHILD_TAB_IAST_DRAIN_MS = 250
const PTK_CHILD_TAB_SAST_COLLECTION_TIMEOUT_MS = 2500
const STRICT_CURRENT_TAB_SESSION_SCOPE = 'current-tab'
const PAGE_EXPORT_OWNER = 'page-automation-export'
const PAGE_EXPORT_MODE = 'evidence'
const REPLAYABLE_EXPORT_OWNER = 'sdk-replayable-export'
const REPLAYABLE_EXPORT_MODE = 'replayable'
const REPLAYABLE_EXPORT_TTL_MS = 5 * 60 * 1000
const REPLAYABLE_EXPORT_MAX_CHUNKS = 512
const PRIVILEGED_SERVICE_WORKER_URL = 'extension-service-worker'
const REPLAYABLE_EXPORT_REQUIRED_ERROR = 'replayable_export_requires_privileged_extension_export'

/**
 * Helper: wait until condition is true or timeout
 */
async function waitUntil(conditionFn, timeoutMs = 30000, pollMs = 100) {
    const start = Date.now()
    while (Date.now() - start < timeoutMs) {
        if (conditionFn()) return true
        await new Promise(r => setTimeout(r, pollMs))
    }
    return false
}

function toNonEmptyString(value) {
    if (typeof value !== 'string') return null
    const trimmed = value.trim()
    return trimmed || null
}

function toFiniteNumber(value, fallback = null) {
    const num = Number(value)
    return Number.isFinite(num) ? num : fallback
}

function makeRandomToken(prefix = 'ptk') {
    try {
        if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
            return `${prefix}_${globalThis.crypto.randomUUID()}`
        }
        const bytes = new Uint8Array(16)
        globalThis.crypto.getRandomValues(bytes)
        return `${prefix}_${Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')}`
    } catch (_) {
        return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2)}`
    }
}

async function sha256Hex(value) {
    const input = String(value || '')
    if (!input) return null
    try {
        if (globalThis.crypto?.subtle && typeof TextEncoder !== 'undefined') {
            const bytes = new TextEncoder().encode(input)
            const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes)
            return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('')
        }
    } catch (_) { }
    return `plain:${input}`
}

function bytesToBase64(value) {
    const bytes = value instanceof Uint8Array
        ? value
        : value instanceof ArrayBuffer
            ? new Uint8Array(value)
            : Array.isArray(value)
                ? Uint8Array.from(value)
                : new Uint8Array(0)
    let binary = ''
    const chunkSize = 0x8000
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize))
    }
    if (typeof btoa === 'function') return btoa(binary)
    if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64')
    throw new Error('base64_unavailable')
}

function normalizeExportMode(value, fallback = PAGE_EXPORT_MODE) {
    return String(value || fallback).trim().toLowerCase()
}

function isZapBrowserCloseOptions(options = {}) {
    return options && typeof options === 'object' && options.source === 'zap_browser_close'
}

function senderFrameId(sender = {}) {
    return Number.isInteger(sender?.frameId) ? sender.frameId : 0
}

function sameDocumentUrl(left, right, baseUrl = '') {
    try {
        const a = new URL(String(left || ''), baseUrl || undefined)
        const b = new URL(String(right || ''), baseUrl || undefined)
        return a.origin === b.origin
            && a.pathname === b.pathname
            && a.search === b.search
            && a.hash === b.hash
    } catch (_) {
        return String(left || '') === String(right || '')
    }
}

function isHttpPageUrl(value) {
    try {
        const parsed = new URL(String(value || ''))
        return parsed.protocol === 'http:' || parsed.protocol === 'https:'
    } catch (_) {
        return false
    }
}

function parseHttpPageUrl(value) {
    try {
        const parsed = new URL(String(value || ''))
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
        return parsed
    } catch (_) {
        return null
    }
}

function effectiveHttpPort(parsed) {
    if (!parsed || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')) return -1
    if (parsed.port) return Number(parsed.port)
    return parsed.protocol === 'https:' ? 443 : 80
}

function sameHttpOrigin(leftValue, rightValue) {
    const left = parseHttpPageUrl(leftValue)
    const right = parseHttpPageUrl(rightValue)
    if (!left || !right) return false
    return left.protocol === right.protocol
        && String(left.hostname || '').toLowerCase() === String(right.hostname || '').toLowerCase()
        && effectiveHttpPort(left) === effectiveHttpPort(right)
}

function targetScopePathPrefix(pathname = '') {
    const path = typeof pathname === 'string' && pathname.startsWith('/') ? pathname : '/'
    if (!path || path === '/') return '/'
    if (path.endsWith('/')) return path
    const index = path.lastIndexOf('/')
    return index >= 0 ? path.slice(0, index + 1) : '/'
}

function sameOriginAndPathScoped(targetValue, candidateValue) {
    const target = parseHttpPageUrl(targetValue)
    const candidate = parseHttpPageUrl(candidateValue)
    if (!target || !candidate) return false
    return sameHttpOrigin(target.href, candidate.href)
        && candidate.pathname.startsWith(targetScopePathPrefix(target.pathname))
}

function cloneJsonSafe(value, { warnings = null, label = 'value' } = {}) {
    if (value === undefined || value === null) return null
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (err) {
        const message = `snapshot_clone_failed:${label}:${err?.message || String(err)}`
        if (Array.isArray(warnings) && warnings.length < 12) {
            warnings.push(message)
        }
        try {
            console.warn('[PTK Automation] Failed to clone analysis snapshot field', {
                label,
                error: err?.message || String(err)
            })
        } catch (_) { }
        return null
    }
}

const ACTIVE_SESSION_STATUSES = new Set(['starting', 'running', 'stopping'])
// Keep findings responses bounded to the long-standing bridge/background cap.
const MAX_FINDINGS_LIMIT = 500
const ENGINE_STATUS_STARTING = 'starting'
const ENGINE_STATUS_RUNNING = 'running'
const ENGINE_STATUS_DEFERRED_START = 'deferred_start'
const ENGINE_STATUS_STOPPING = 'stopping'
const ENGINE_STATUS_STOPPED = 'stopped'
const ENGINE_STATUS_COMPLETED = 'completed'
const ENGINE_STATUS_ERROR = 'error'
const ZAP_DEFERRED_ENGINE_START_BASE_DELAY_MS = 1500
const ZAP_DEFERRED_ENGINE_START_SPREAD_MS = 500
const ZAP_DEFERRED_ENGINE_START_BUCKETS = 4
const ZAP_DEFERRED_ENGINE_PER_ENGINE_DELAY_MS = 1000
const ZAP_RELATED_SAST_WORK_EVIDENCE_MS = 10000
const MANUAL_AUTOMATION_BOOTSTRAP_GRANT_TTL_MS = 60 * 1000
const CONTENT_RUNTIME_MODE_PENDING = 'pending'
const CONTENT_RUNTIME_MODE_MANUAL = 'manual'
const CONTENT_RUNTIME_MODE_AUTOMATION = 'automation'
const CONTENT_RUNTIME_SCRIPT_NONE = 'none'
const CONTENT_RUNTIME_SCRIPT_MANUAL = 'manual'
const CONTENT_RUNTIME_SCRIPT_AUTOMATION = 'automation'
const CONTENT_RUNTIME_FILES = Object.freeze({
    [CONTENT_RUNTIME_SCRIPT_MANUAL]: ['ptk/content_manual.js', 'ptk/content/spa_hash_harness.js'],
    [CONTENT_RUNTIME_SCRIPT_AUTOMATION]: ['ptk/content_automation.js']
})

function isHttpZapTargetUrl(value) {
    if (typeof value !== 'string' || !value.trim()) return false
    try {
        const parsed = new URL(value)
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
        if (String(parsed.hostname || '').toLowerCase() === 'zap') return false
        return true
    } catch (_) {
        return false
    }
}

function sleep(ms) {
    if (!(Number.isFinite(Number(ms)) && Number(ms) > 0)) {
        return Promise.resolve()
    }
    return new Promise((resolve) => setTimeout(resolve, Number(ms)))
}

function isAutomationDebugLoggingEnabled() {
    return globalThis.__PTK_AUTOMATION_DEBUG__ === true
}

function debugAutomationLog(...args) {
    if (!isAutomationDebugLoggingEnabled()) {
        return
    }
    console.log(...args)
}

/**
 * Engine adapter interface - abstracts engine-specific methods
 * DAST uses startAutomationSession/stopAutomationSession end-to-end
 * stop() waits until isRunning() becomes false
 */
class EngineAdapter {
    constructor(app, automationModule) {
        this.app = app
        this.automationModule = automationModule  // Reference to ptk_automation for session tracking
    }

    // DAST adapter - uses automation session API for consistency
    dast = {
        isRunning: () => {
            const val = (this.app?.dast || this.app?.rattacker)?.engine?.isRunning
            return typeof val === 'function' ? val() : !!val
        },
        start: async (sessionId, tabId, host, options) => {
            const dast = this.app?.dast || this.app?.rattacker
            if (!dast) throw new Error('dast_not_available')
            const dastSettings = {
                scanStrategy: options?.scanStrategy || options?.policyCode || 'SMART',
                runCve: options?.runCve === true
            }
            if (options?.dastScanPolicy) {
                dastSettings.dastScanPolicy = options.dastScanPolicy
            }
            if (options?.safetyProfile) {
                dastSettings.safetyProfile = options.safetyProfile
            }
            if (options?.scanControls && typeof options.scanControls === 'object') {
                dastSettings.scanControls = options.scanControls
            }
            const passthroughSettings = [
                'allowCaptureWithoutInteraction',
                'enableHtmlLinkDiscovery',
                'htmlLinkDiscoveryBudget',
                'enableSyntheticRedirectRequests',
                'zapManaged',
                'targetUrl',
                'pageUrl',
                'zapCallbackDetectedAt',
                'zapHistorySeedUrls',
                'zapHistorySeedCount',
                'zapHistorySeedTotalAvailable',
                'zapHistorySeedDroppedByCap',
                'zapSeedMaxRequests',
                'maxRequestsPerSecond',
                'concurrency',
                'planningConcurrency'
            ]
            for (const key of passthroughSettings) {
                if (Object.prototype.hasOwnProperty.call(options || {}, key)) {
                    dastSettings[key] = options[key]
                }
            }
            if (options?.policyId !== undefined && options?.policyId !== null && options?.policyId !== '') {
                dastSettings.policyId = options.policyId
            }
            if (options?.policyName) {
                dastSettings.policyName = options.policyName
            }
            if (options?.rulepack && typeof options.rulepack === 'object') {
                dastSettings.rulepack = options.rulepack
            }
            if (options?.cveRulepack && typeof options.cveRulepack === 'object') {
                dastSettings.cveRulepack = options.cveRulepack
            }
            // Use startAutomationSession for proper session tracking
            return await dast.startAutomationSession({
                sessionId,
                tabId,
                host,
                domains: host,
                settings: dastSettings,
                policyCode: options?.policyCode,
                hooks: {
                    onTaskStarted: () => {},
                    onTaskFinished: () => {},
                    onPtkTabOpened: (details) => this.automationModule?._handleDastPtkTabOpened?.(sessionId, details),
                    onPtkTabClosing: (details) => this.automationModule?._handleDastPtkTabClosing?.(sessionId, details)
                }
            })
        },
        stop: async (sessionId, timeoutMs = 180000, options = {}) => {
            const dast = this.app?.dast || this.app?.rattacker
            const automationState = this.automationModule?._getDastAutomationCoordinatorState?.(sessionId)
            if (!automationState?.automationSession) return this._createEmptyStats()
            // Use stopAutomationSession which quiesces/drains and returns stats.
            return dast.stopAutomationSession(sessionId, timeoutMs, options)
        },
        getStats: () => this._extractStats((this.app?.dast || this.app?.rattacker)?.scanResult),
        getFindings: (limit = 100) => this._extractFindings((this.app?.dast || this.app?.rattacker)?.scanResult, limit, 'DAST'),
        getScanId: () => (this.app?.dast || this.app?.rattacker)?.scanResult?.scanId || null
    }

    // IAST adapter
    iast = {
        isRunning: () => this.app?.iast?.isScanRunning || false,
        start: async (sessionId, tabId, host, options) => {
            const iast = this.app?.iast
            if (!iast) throw new Error('iast_not_available')
            const iastOpts = {}
            if (options?.rulepack && typeof options.rulepack === 'object') {
                iastOpts.rulepack = options.rulepack
            }
            if (options?.preferPortal) {
                iastOpts.preferPortal = true
            }
            if (options?.policyId !== undefined && options?.policyId !== null && options?.policyId !== '') {
                iastOpts.policyId = options.policyId
            }
            if (options?.policyName) {
                iastOpts.policyName = options.policyName
            }
            if (options?.zapManaged === true) {
                iastOpts.zapManaged = true
            }
            if (options?.zapTiming && typeof options.zapTiming === 'object') {
                iastOpts.zapTiming = options.zapTiming
            }
            const started = await iast.runBackgroundScan(tabId, host, options?.policyCode || 'SMART', iastOpts)
            if (started === false) {
                const activeTabId = Number(iast?.scanResult?.tabId)
                const activeHost = String(iast?.scanResult?.host || '').toLowerCase()
                const requestedHost = String(host || '').toLowerCase()
                const canEnrollRelated = iast?.isScanRunning === true
                    && Number.isInteger(activeTabId)
                    && activeTabId >= 0
                    && activeTabId !== tabId
                    && activeHost
                    && requestedHost
                    && activeHost === requestedHost
                    && typeof iast.enrollRelatedScanTab === 'function'
                if (canEnrollRelated) {
                    const enrolled = await iast.enrollRelatedScanTab(tabId, {
                        role: 'zap_parallel_worker',
                        sourceEngine: 'IAST',
                        sessionId,
                        url: options?.zapTiming?.targetUrl || null
                    })
                    if (enrolled) {
                        if (options?.waitForReady !== false) {
                            const readyTimeoutMs = Number.isFinite(Number(options?.agentReadyTimeoutMs))
                                ? Math.max(1000, Number(options.agentReadyTimeoutMs))
                                : 15000
                            const ready = await this.automationModule?._waitForIastAgentReady?.(tabId, readyTimeoutMs)
                            if (!ready) {
                                const failureReason = this.app?.iast?.agentFailedTabs?.get?.(tabId)
                                if (failureReason) {
                                    throw new Error(`iast_agent_failed:${failureReason}`)
                                }
                                console.warn('[PTK Automation] IAST related tab readiness not confirmed; continuing in best-effort mode', {
                                    tabId,
                                    ownerTabId: activeTabId,
                                    readyTimeoutMs
                                })
                            }
                        }
                        return {
                            ok: true,
                            status: ENGINE_STATUS_RUNNING,
                            warning: 'iast_enrolled_related_zap_worker',
                            relatedTab: true,
                            ownerTabId: activeTabId,
                            scanId: iast?.scanResult?.scanId || iast?.currentScanId || null
                        }
                    }
                }
                return {
                    ok: false,
                    status: ENGINE_STATUS_ERROR,
                    error: iast?.isScanRunning === true
                        ? 'iast_already_running_for_different_tab'
                        : 'iast_start_returned_false'
                }
            }
            if (options?.waitForReady === false) {
                return { ok: true }
            }
            const readyTimeoutMs = Number.isFinite(Number(options?.agentReadyTimeoutMs))
                ? Math.max(1000, Number(options.agentReadyTimeoutMs))
                : 15000
            const ready = await this.automationModule?._waitForIastAgentReady?.(tabId, readyTimeoutMs)
            if (!ready) {
                const failureReason = this.app?.iast?.agentFailedTabs?.get?.(tabId)
                if (failureReason) {
                    throw new Error(`iast_agent_failed:${failureReason}`)
                }
                console.warn('[PTK Automation] IAST agent readiness not confirmed; continuing in best-effort mode', {
                    tabId,
                    readyTimeoutMs
                })
                return { ok: true, warning: 'iast_agent_ready_not_confirmed' }
            }
            return { ok: true }
        },
        stop: async (sessionId, timeoutMs = 60000, options = {}) => {
            const iast = this.app?.iast
            const session = this.automationModule?.sessions?.get?.(sessionId) || null
            const state = session?.engineStates?.IAST || null
            if (state?.relatedTab === true) {
                if (Number.isInteger(session?.tabId) && typeof iast?.releaseRelatedScanTab === 'function') {
                    try {
                        iast.releaseRelatedScanTab(session.tabId)
                    } catch (_) { }
                }
                return this._createEmptyStats()
            }
            if (!iast?.isScanRunning) return this._createEmptyStats()
            const zapCloseRequest = options?.zapCloseRequest === true || options?.source === 'zap_browser_close'
            const effectiveTimeoutMs = zapCloseRequest
                ? Math.min(timeoutMs, ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS)
                : timeoutMs
            const stopPromise = iast.stopBackgroundScan({
                skipPostStopAnalysis: zapCloseRequest
            })
            // stopBackgroundScan clears isScanRunning early, but still flushes
            // normalized findings asynchronously. Await it so ZAP export/final
            // progress does not race ahead of IAST persistence.
            const stopped = await Promise.race([
                Promise.resolve(stopPromise).then(() => true),
                sleep(effectiveTimeoutMs).then(() => false)
            ])
            return Object.assign(this._extractStats(iast.scanResult), {
                completionStatus: stopped ? 'completed' : 'engine_incomplete',
                drained: stopped
            })
        },
        getStats: () => this._extractStats(this.app?.iast?.scanResult),
        getFindings: (limit = 100) => this._extractFindings(this.app?.iast?.scanResult, limit, 'IAST'),
        getScanId: () => this.app?.iast?.scanResult?.scanId || this.app?.iast?.currentScanId || null
    }

    // SAST adapter
    sast = {
        isRunning: () => this.app?.sast?.isScanRunning || false,
        start: async (sessionId, tabId, host, options) => {
            const sast = this.app?.sast
            if (!sast) throw new Error('sast_not_available')
            const sastOpts = {}
            if (options?.rulepack && typeof options.rulepack === 'object') {
                sastOpts.rulepack = options.rulepack
            }
            if (options?.catalog && typeof options.catalog === 'object') {
                sastOpts.catalog = options.catalog
            }
            if (options?.preferPortal) {
                sastOpts.preferPortal = true
            }
            if (options?.policyId !== undefined && options?.policyId !== null && options?.policyId !== '') {
                sastOpts.policyId = options.policyId
            }
            if (options?.policyName) {
                sastOpts.policyName = options.policyName
            }
            if (options?.zapManaged === true) {
                sastOpts.zapManaged = true
            }
            if (options?.zapTiming && typeof options.zapTiming === 'object') {
                sastOpts.zapTiming = options.zapTiming
            }
            const passthroughSastOptions = [
                'zapHistorySeedUrls',
                'zapPageSourceUrls',
                'zapHistorySeedCount',
                'zapHistorySeedTotalAvailable',
                'zapHistorySeedDroppedByCap',
                'sastPageSourceCrawl',
                'sastPageSourceMaxPages',
                'sastPageSourceMaxBytes',
                'enableSastPageSourceLinkDiscovery'
            ]
            for (const key of passthroughSastOptions) {
                if (Object.prototype.hasOwnProperty.call(options || {}, key)) {
                    sastOpts[key] = options[key]
                }
            }
            const started = await sast.runBackgroundScan(tabId, host, { policyCode: options?.policyCode || 'SMART' }, sastOpts)
            if (started !== false) {
                return { ok: true }
            }

            const activeTabId = Number(sast?.scanResult?.tabId ?? sast?.activeTabId)
            const activeHost = String(sast?.scanResult?.host || '').toLowerCase()
            const requestedHost = String(host || '').toLowerCase()
            const canQueueRelatedWork = options?.zapManaged === true
                && sast?.isScanRunning === true
                && Number.isInteger(activeTabId)
                && activeTabId >= 0
                && activeTabId !== tabId
                && activeHost
                && requestedHost
                && activeHost === requestedHost

            if (!canQueueRelatedWork) {
                return {
                    ok: false,
                    status: ENGINE_STATUS_ERROR,
                    error: sast?.isScanRunning === true
                        ? 'sast_already_running_for_different_tab'
                        : 'sast_start_returned_false'
                }
            }

            const session = this.automationModule?.sessions?.get?.(sessionId) || null
            const relatedTasks = []
            const markRelatedWork = (patch = {}) => {
                if (!session?.engineStates?.SAST) return
                session.engineStates.SAST = Object.assign({}, session.engineStates.SAST, patch)
            }

            if (typeof sast.collectAndScanTab === 'function') {
                relatedTasks.push(Promise.resolve().then(() => sast.collectAndScanTab(tabId, {
                    delayMs: options?.spaDelayMs || 500,
                    attempts: 4,
                    timeoutMs: 12000,
                    retryDelayMs: 600
                })))
            }

            const seedUrls = Array.isArray(sastOpts.zapPageSourceUrls)
                ? sastOpts.zapPageSourceUrls
                : (Array.isArray(sastOpts.zapHistorySeedUrls) ? sastOpts.zapHistorySeedUrls : [])
            if (seedUrls.length && typeof sast.scanZapManagedPageSources === 'function') {
                relatedTasks.push(Promise.resolve().then(() => sast.scanZapManagedPageSources(seedUrls, {
                    startUrl: options?.zapTiming?.targetUrl || host,
                    zapTiming: options?.zapTiming || null,
                    source: 'zap_parallel_worker_seed',
                    sastPageSourceMaxPages: sastOpts.sastPageSourceMaxPages,
                    sastPageSourceMaxBytes: sastOpts.sastPageSourceMaxBytes,
                    enableSastPageSourceLinkDiscovery: sastOpts.enableSastPageSourceLinkDiscovery === true
                })))
            }

            if (!relatedTasks.length) {
                return {
                    ok: false,
                    status: ENGINE_STATUS_ERROR,
                    error: 'sast_related_worker_no_collection_path'
                }
            }

            markRelatedWork({
                relatedTab: true,
                ownerTabId: activeTabId,
                relatedWorkPending: true,
                relatedWorkQueuedAt: Date.now(),
                relatedWorkCompletedAt: null,
                relatedWorkError: null
            })

            Promise.allSettled(relatedTasks)
                .then((results) => {
                    const rejected = results.find((result) => result?.status === 'rejected')
                    markRelatedWork({
                        relatedWorkPending: false,
                        relatedWorkCompletedAt: Date.now(),
                        relatedWorkError: rejected?.reason?.message || (rejected ? String(rejected.reason) : null)
                    })
                    if (rejected) {
                        console.warn('[PTK Automation] Related ZAP SAST worker collection failed', {
                            sessionId,
                            tabId,
                            ownerTabId: activeTabId,
                            error: rejected.reason?.message || String(rejected.reason)
                        })
                    }
                })
                .catch((err) => {
                    markRelatedWork({
                        relatedWorkPending: false,
                        relatedWorkCompletedAt: Date.now(),
                        relatedWorkError: err?.message || String(err)
                    })
                })

            return {
                ok: true,
                status: ENGINE_STATUS_RUNNING,
                warning: 'sast_enrolled_related_zap_worker',
                relatedTab: true,
                ownerTabId: activeTabId,
                scanId: sast?.scanResult?.scanId || null
            }
        },
        stop: async (sessionId, timeoutMs = 60000, options = {}) => {
            const sast = this.app?.sast
            const session = this.automationModule?.sessions?.get?.(sessionId) || null
            const state = session?.engineStates?.SAST || null
            if (state?.relatedTab === true) {
                return this._createEmptyStats()
            }
            if (!sast?.isScanRunning) return this._createEmptyStats()
            const zapCloseRequest = options?.zapCloseRequest === true || options?.source === 'zap_browser_close'
            const effectiveTimeoutMs = zapCloseRequest
                ? Math.min(timeoutMs, ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS)
                : timeoutMs
            let collectionDrained = true
            if (zapCloseRequest && typeof sast.waitForCollectionIdle === 'function') {
                collectionDrained = await sast.waitForCollectionIdle({
                    timeoutMs: Math.max(250, Math.floor(effectiveTimeoutMs * 0.8))
                })
            }
            const stopPromise = sast.stopBackgroundScan({
                skipPostStopAnalysis: zapCloseRequest
            })
            const stopped = await Promise.race([
                Promise.resolve(stopPromise).then(() => true),
                sleep(effectiveTimeoutMs).then(() => false)
            ])
            const drained = stopped && collectionDrained !== false
            return Object.assign(this._extractStats(sast.scanResult), {
                completionStatus: drained ? 'completed' : 'engine_incomplete',
                drained
            })
        },
        getStats: () => this._extractStats(this.app?.sast?.scanResult),
        getFindings: (limit = 100) => this._extractFindings(this.app?.sast?.scanResult, limit, 'SAST'),
        getScanId: () => this.app?.sast?.scanResult?.scanId || null
    }

    // SCA adapter
    sca = {
        isRunning: () => this.app?.sca?.isScanRunning || false,
        start: async (sessionId, tabId, host, options) => {
            const sca = this.app?.sca
            if (!sca) throw new Error('sca_not_available')
            // Just call runBackgroundScan - it handles "already running" internally
            await sca.runBackgroundScan(tabId, host)
        },
        stop: async (sessionId, timeoutMs = 60000, options = {}) => {
            const sca = this.app?.sca
            if (!sca?.isScanRunning) return this._createEmptyStats()
            const zapCloseRequest = options?.zapCloseRequest === true || options?.source === 'zap_browser_close'
            const effectiveTimeoutMs = zapCloseRequest
                ? Math.min(timeoutMs, ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS)
                : timeoutMs
            sca.stopBackgroundScan()
            const stopped = await waitUntil(() => !sca.isScanRunning, effectiveTimeoutMs)
            return Object.assign(this._extractStats(sca.scanResult), {
                completionStatus: stopped ? 'completed' : 'engine_incomplete',
                drained: stopped
            })
        },
        getStats: () => this._extractStats(this.app?.sca?.scanResult),
        getFindings: (limit = 100) => this._extractFindings(this.app?.sca?.scanResult, limit, 'SCA'),
        getScanId: () => this.app?.sca?.scanResult?.scanId || null
    }

    _createEmptyStats() {
        return { findingsCount: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }
    }

    // Compute stats from actual findings array
    _extractStats(scanResult) {
        const rawFindings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        const findings = collapseDastAggregatedFindings(rawFindings)
        const stats = this._createEmptyStats()

        for (const finding of findings) {
            stats.findingsCount++
            const sev = (finding.severity || finding.effectiveSeverity || 'info').toLowerCase()
            if (stats.bySeverity.hasOwnProperty(sev)) {
                stats.bySeverity[sev]++
            } else {
                stats.bySeverity.info++
            }
        }
        return stats
    }

    // Extract findings with limit
    _extractFindings(scanResult, limit = 100, engine = 'unknown') {
        const rawFindings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        const findings = collapseDastAggregatedFindings(rawFindings)
        return findings.slice(0, limit).map(f => ({
            id: f.id || f.findingId,
            title: f.title || f.name || f.ruleName || f.moduleName || f.ruleId || f.moduleId,
            severity: f.severity || f.effectiveSeverity || 'info',
            category: f.category || f.vulnId || f.ruleId || f.moduleId,
            url: f.url || f.location?.url,
            engine: f.engine || scanResult?.engine || engine,
            moduleId: f.moduleId || null,
            moduleName: f.moduleName || null,
            ruleId: f.ruleId || null,
            ruleName: f.ruleName || null,
            vulnId: f.vulnId || null,
            confidence: Number.isFinite(Number(f.confidence)) ? Number(f.confidence) : null,
            presentationAggregate: f.presentationAggregate || null,
            occurrenceCount: Number.isFinite(Number(f.evidence?.dast?.occurrenceCount))
                ? Number(f.evidence.dast.occurrenceCount)
                : null,
            aggregate: f.evidence?.dast?.aggregate || null,
            samples: Array.isArray(f.evidence?.dast?.samples) ? f.evidence.dast.samples : null
        }))
    }

    getAdapter(engine) {
        const adapters = { DAST: this.dast, IAST: this.iast, SAST: this.sast, SCA: this.sca }
        return adapters[engine.toUpperCase()]
    }
}


export class ptk_automation {
    constructor() {
        this.sessions = new Map()             // sessionId -> session
        this.activeSessionByTabId = new Map() // tabId -> sessionId (enforce single session per tab)
        this.lastCompletedSessionByTabId = new Map() // tabId -> sessionId
        this.lastCompletedSessionGlobal = null       // fallback for any-tab export
        this.evictedSessions = new Map()             // bounded diagnostics for missing-session failures
        this.replayableExportLeases = new Map()      // leaseId -> privileged replayable export metadata
        this.ptkChildTabRecords = new Map()          // sessionId:tabId -> PTK-created child tab engine work
        this.manualAutomationBootstrapGrants = new Map() // tabId -> short-lived explicit manual automation grant
        this.MAX_COMPLETED_SESSIONS = 20
        this.SESSION_TTL_MS = 24 * 60 * 60 * 1000
        this.app = null
        this.engines = null
        this.zap = zapBridge                  // ZAP integration module
        this._unsubscribeZapContentRuntimeRefresh = null
        this._installPrivilegedReplayableExportApi()
        this.addMessageListeners()
    }

    init(app) {
        this.app = app
        this.engines = new EngineAdapter(app, this)
        resultsRegistry.init(app)
        this.zap.attach(app, resultsRegistry)
        if (!this._unsubscribeZapContentRuntimeRefresh && this.zap?.transport?.onZapDetected) {
            this._unsubscribeZapContentRuntimeRefresh = this.zap.transport.onZapDetected((payload) => {
                const tabId = Number.isInteger(payload?.tabId) ? payload.tabId : null
                if (tabId == null) return
                this._notifyContentRuntimeRefresh(tabId).catch(() => { })
            })
        }
    }

    _ptkChildTabKey(sessionId, tabId) {
        return `${String(sessionId || '')}:${Number(tabId)}`
    }

    _sessionHasEngine(session, engineName) {
        const needle = String(engineName || '').trim().toUpperCase()
        return !!needle && Array.isArray(session?.engines)
            && session.engines.some(engine => String(engine || '').trim().toUpperCase() === needle)
    }

    async _waitForEngineReady(checkFn, timeoutMs = PTK_CHILD_TAB_ENGINE_WAIT_MS) {
        const started = Date.now()
        while (Date.now() - started <= timeoutMs) {
            try {
                if (checkFn()) return true
            } catch (_) { }
            await sleep(75)
        }
        return false
    }

    async _handleDastPtkTabOpened(sessionId, details = {}) {
        const session = this.sessions.get(sessionId)
        const tabId = Number(details?.tabId)
        const parentTabId = Number(details?.parentTabId)
        if (!session || !Number.isInteger(tabId) || !Number.isInteger(parentTabId)) return { ok: false, reason: 'invalid_ptk_child_tab' }
        if (Number(session.tabId) !== parentTabId) return { ok: false, reason: 'parent_tab_mismatch' }
        const record = {
            sessionId,
            tabId,
            parentTabId,
            role: String(details?.role || 'ptk_child_tab'),
            url: typeof details?.url === 'string' ? details.url : null,
            sourceEngine: String(details?.sourceEngine || 'DAST'),
            createdAt: Date.now(),
            sastPromise: null
        }
        this.ptkChildTabRecords.set(this._ptkChildTabKey(sessionId, tabId), record)

        if (this._sessionHasEngine(session, 'IAST')) {
            const iast = this.app?.iast || null
            const iastReady = await this._waitForEngineReady(() => iast?.isScanRunning === true && typeof iast.enrollRelatedScanTab === 'function')
            if (iastReady) {
                await iast.enrollRelatedScanTab(tabId, {
                    parentTabId,
                    role: record.role,
                    url: record.url,
                    sourceEngine: record.sourceEngine,
                    sessionId
                }).catch((err) => {
                    console.warn('[PTK Automation] Failed to enroll PTK child tab for IAST', {
                        sessionId,
                        tabId,
                        role: record.role,
                        error: err?.message || String(err)
                    })
                    return false
                })
            }
        }

        if (this._sessionHasEngine(session, 'SAST')) {
            const sast = this.app?.sast || null
            record.sastPromise = Promise.resolve()
                .then(async () => {
                    const sastReady = await this._waitForEngineReady(() => sast?.isScanRunning === true && typeof sast.collectAndScanTab === 'function')
                    if (!sastReady) return null
                    return sast.collectAndScanTab(tabId, {
                        delayMs: 100,
                        attempts: 1,
                        timeoutMs: PTK_CHILD_TAB_SAST_COLLECTION_TIMEOUT_MS,
                        retryDelayMs: 100,
                        expectedUrl: record.url || undefined,
                        source: 'ptk_child_tab',
                        childTabRole: record.role
                    })
                })
                .catch((err) => {
                    console.warn('[PTK Automation] Failed to collect SAST for PTK child tab', {
                        sessionId,
                        tabId,
                        role: record.role,
                        error: err?.message || String(err)
                    })
                    return null
                })
        }

        return { ok: true }
    }

    async _handleDastPtkTabClosing(sessionId, details = {}) {
        const tabId = Number(details?.tabId)
        if (!Number.isInteger(tabId)) return { ok: false, reason: 'invalid_ptk_child_tab' }
        const key = this._ptkChildTabKey(sessionId, tabId)
        const record = this.ptkChildTabRecords.get(key) || null
        if (record?.sastPromise) {
            await Promise.race([
                record.sastPromise,
                sleep(PTK_CHILD_TAB_SAST_COLLECTION_TIMEOUT_MS).then(() => null)
            ]).catch(() => null)
        }
        if (this.app?.iast?.releaseRelatedScanTab) {
            await sleep(PTK_CHILD_TAB_IAST_DRAIN_MS)
            this.app.iast.releaseRelatedScanTab(tabId)
        }
        this.ptkChildTabRecords.delete(key)
        return { ok: true }
    }

    _getSessionForTab(tabId) {
        if (!Number.isInteger(tabId)) return null
        const sessionId = this.activeSessionByTabId.get(tabId)
        if (!sessionId) return null
        return this.sessions.get(sessionId) || null
    }

    _getCompletedSessionForTab(tabId) {
        if (!Number.isInteger(tabId)) return null
        const sessionId = this.lastCompletedSessionByTabId.get(tabId)
        if (!sessionId) return null
        const session = this.sessions.get(sessionId) || null
        if (session && this._isTerminalSessionStatus(session.status)) return session
        this.lastCompletedSessionByTabId.delete(tabId)
        return null
    }

    _getSessionScopeUrl(session = null) {
        if (!session || typeof session !== 'object') return null
        return toNonEmptyString(session.targetUrl)
            || toNonEmptyString(session.pageUrl)
            || toNonEmptyString(session.lastInScopeUrl)
            || null
    }

    _sessionUrlInScope(session = null, candidateUrl = '', options = {}) {
        if (!session) return false
        if (options?.requireActive !== false && !this._isActiveSessionStatus(session.status)) return false
        const parsedCandidate = parseHttpPageUrl(candidateUrl)
        if (!parsedCandidate) return false

        const scopeUrl = this._getSessionScopeUrl(session)
        if (scopeUrl) {
            return session.source === 'zap'
                ? sameOriginAndPathScoped(scopeUrl, parsedCandidate.href)
                : sameHttpOrigin(scopeUrl, parsedCandidate.href)
        }

        if (session.host) {
            return String(parsedCandidate.hostname || '').toLowerCase() === String(session.host || '').toLowerCase()
        }

        // Legacy test/session objects can predate explicit scope metadata. Keep
        // those working, but all real sessions created by this module set a scope.
        return true
    }

    _recordInScopeSessionUrl(session = null, candidateUrl = '') {
        if (!session || !this._sessionUrlInScope(session, candidateUrl)) return false
        const parsedCandidate = parseHttpPageUrl(candidateUrl)
        if (!parsedCandidate) return false
        session.lastInScopeUrl = parsedCandidate.href
        return true
    }

    _getPtkChildTabRecord(tabId) {
        if (!Number.isInteger(tabId)) return null
        for (const record of this.ptkChildTabRecords.values()) {
            if (Number(record?.tabId) === tabId) return record
        }
        return null
    }

    _ptkChildTabUrlInScope(tabId, candidateUrl = '') {
        const record = this._getPtkChildTabRecord(tabId)
        if (!record) return false
        const session = this.sessions.get(record.sessionId) || null
        if (session) return this._sessionUrlInScope(session, candidateUrl)
        return record.url ? sameHttpOrigin(record.url, candidateUrl) : false
    }

    _detectedZapTabUrlInScope(detectedPayload = null, candidateUrl = '') {
        const targetUrl = toNonEmptyString(detectedPayload?.targetUrl)
        if (!targetUrl) return true
        return sameOriginAndPathScoped(targetUrl, candidateUrl)
    }

    _pruneManualAutomationBootstrapGrants(now = Date.now()) {
        for (const [tabId, grant] of this.manualAutomationBootstrapGrants.entries()) {
            if (!grant || Number(grant.expiresAt || 0) <= now) {
                this.manualAutomationBootstrapGrants.delete(tabId)
            }
        }
    }

    _getManualAutomationBootstrapGrant(tabId, now = Date.now()) {
        if (!Number.isInteger(tabId)) return null
        this._pruneManualAutomationBootstrapGrants(now)
        const grant = this.manualAutomationBootstrapGrants.get(tabId) || null
        if (!grant || Number(grant.expiresAt || 0) <= now) {
            this.manualAutomationBootstrapGrants.delete(tabId)
            return null
        }
        return grant
    }

    _createManualAutomationBootstrapGrant(tabId, details = {}) {
        if (!Number.isInteger(tabId)) return null
        const now = Date.now()
        const ttlMs = Number.isFinite(Number(details.ttlMs)) && Number(details.ttlMs) > 0
            ? Math.min(Number(details.ttlMs), MANUAL_AUTOMATION_BOOTSTRAP_GRANT_TTL_MS)
            : MANUAL_AUTOMATION_BOOTSTRAP_GRANT_TTL_MS
        const grant = {
            tabId,
            reason: String(details.reason || 'manual_activation_request'),
            url: typeof details.url === 'string' ? details.url : null,
            createdAt: now,
            expiresAt: now + ttlMs
        }
        this.manualAutomationBootstrapGrants.set(tabId, grant)
        return grant
    }

    _consumeManualAutomationBootstrapGrant(tabId, now = Date.now()) {
        const grant = this._getManualAutomationBootstrapGrant(tabId, now)
        if (grant) {
            this.manualAutomationBootstrapGrants.delete(tabId)
        }
        return grant
    }

    _hasActiveSessionInAnyTab() {
        for (const session of this.sessions.values()) {
            if (this._isActiveSessionStatus(session?.status)) return true
        }
        return false
    }

    _isPtkChildTab(tabId) {
        return !!this._getPtkChildTabRecord(tabId)
    }

    _getDastController() {
        return this.app?.dast || this.app?.rattacker || null
    }

    _isBrowserEngineScanRunningForTab(tabId) {
        if (!Number.isInteger(tabId)) return false

        const dast = this._getDastController()
        if (dast?.sessionCoordinator?.isRunningForTab?.(tabId) === true) return true
        if (dast?.engine?.isRunning === true && Number(dast.engine.tabId) === tabId) return true

        const iast = this.app?.iast || null
        if (iast?.isTrackedScanTab?.(tabId) === true) return true
        if (iast?.isScanRunning === true && Number(iast?.scanResult?.tabId) === tabId) return true

        const sast = this.app?.sast || null
        if (sast?.isScanRunning === true && Number(sast?.activeTabId) === tabId) return true
        if (sast?.sessionCoordinator?.isScanRunning === true && Number(sast.sessionCoordinator.activeTabId) === tabId) return true

        const sca = this.app?.sca || null
        if (sca?.isScanRunning === true && Number(sca?.activeTabId) === tabId) return true

        return false
    }

    _hasBrowserEngineScanRunningInAnyTab() {
        const dast = this._getDastController()
        if (dast?.engine?.isRunning === true) return true

        const iast = this.app?.iast || null
        if (iast?.isScanRunning === true) return true

        const sast = this.app?.sast || null
        if (sast?.isScanRunning === true || sast?.sessionCoordinator?.isScanRunning === true) return true

        const sca = this.app?.sca || null
        if (sca?.isScanRunning === true) return true

        return false
    }

    _isZapManagedActiveSessionForTab(tabId) {
        const session = this._getSessionForTab(tabId) || this._getCompletedSessionForTab(tabId)
        if (!session || session.source !== 'zap') return false
        return this._isActiveSessionStatus(session.status)
    }

    _getContentRuntimeProfile({ tabId = null, frameId = 0, url = '', zapTargetObserved = false } = {}) {
        const safeUrl = typeof url === 'string' ? url : ''
        const isTopFrame = frameId === 0
        const transport = this.zap?.transport || null
        const startup = transport?.getStartupSnapshot?.() || { pending: false }
        const detectedPayload = transport?.getLastDetectedPayload?.() || null
        const detectedTabId = Number.isInteger(detectedPayload?.tabId) ? detectedPayload.tabId : null
        const isBootstrapUrl = transport?.isBootstrapUrl?.(safeUrl) === true
        const activeSession = this._getSessionForTab(tabId)
        const hasActiveSession = !!activeSession && this._isActiveSessionStatus(activeSession.status)
        const activeSessionInScope = !hasActiveSession || isBootstrapUrl || this._sessionUrlInScope(activeSession, safeUrl)
        const hasZapSession = hasActiveSession && activeSession.source === 'zap' && activeSessionInScope
        const isDetectedAutomationTab = Number.isInteger(tabId) && Number.isInteger(detectedTabId) && tabId === detectedTabId
        const detectedAutomationTabInScope = isDetectedAutomationTab
            && (isBootstrapUrl || this._detectedZapTabUrlInScope(detectedPayload, safeUrl))
        const isZapAutomationTab = hasZapSession || detectedAutomationTabInScope
        const isPtkChildTab = this._isPtkChildTab(tabId)
        const ptkChildTabInScope = !isPtkChildTab || isBootstrapUrl || this._ptkChildTabUrlInScope(tabId, safeUrl)
        const isZapActive = transport?.isActive?.() === true

        if (isTopFrame && hasActiveSession && !activeSessionInScope) {
            return {
                mode: CONTENT_RUNTIME_MODE_PENDING,
                script: CONTENT_RUNTIME_SCRIPT_NONE,
                reason: 'active_session_out_of_scope'
            }
        }

        if (
            isTopFrame
            && hasActiveSession
            && activeSessionInScope
            && activeSession.source !== 'zap'
        ) {
            return {
                mode: CONTENT_RUNTIME_MODE_MANUAL,
                script: CONTENT_RUNTIME_SCRIPT_MANUAL,
                reason: 'active_session_tab'
            }
        }

        if (isTopFrame && isPtkChildTab && !ptkChildTabInScope) {
            return {
                mode: CONTENT_RUNTIME_MODE_PENDING,
                script: CONTENT_RUNTIME_SCRIPT_NONE,
                reason: 'ptk_child_tab_out_of_scope'
            }
        }

        if (!isTopFrame) {
            if (isZapAutomationTab || isBootstrapUrl) {
                return {
                    mode: isZapActive || isZapAutomationTab ? CONTENT_RUNTIME_MODE_AUTOMATION : CONTENT_RUNTIME_MODE_PENDING,
                    script: CONTENT_RUNTIME_SCRIPT_NONE,
                    reason: 'subframe_suppressed'
                }
            }
            return {
                mode: CONTENT_RUNTIME_MODE_MANUAL,
                script: CONTENT_RUNTIME_SCRIPT_MANUAL,
                reason: 'manual_subframe'
            }
        }

        if (isZapActive && (isZapAutomationTab || isBootstrapUrl)) {
            return {
                mode: CONTENT_RUNTIME_MODE_AUTOMATION,
                script: CONTENT_RUNTIME_SCRIPT_AUTOMATION,
                reason: 'zap_active'
            }
        }

        if (isZapActive && isTopFrame && zapTargetObserved) {
            return {
                mode: CONTENT_RUNTIME_MODE_AUTOMATION,
                script: CONTENT_RUNTIME_SCRIPT_AUTOMATION,
                reason: 'zap_active_target'
            }
        }

        if (!isZapActive && startup.pending && isBootstrapUrl) {
            return {
                mode: CONTENT_RUNTIME_MODE_PENDING,
                script: CONTENT_RUNTIME_SCRIPT_NONE,
                reason: 'zap_bootstrap_pending'
            }
        }

        if (isZapAutomationTab) {
            return {
                mode: CONTENT_RUNTIME_MODE_AUTOMATION,
                script: CONTENT_RUNTIME_SCRIPT_AUTOMATION,
                reason: 'zap_tab_claimed'
            }
        }

        if (
            isTopFrame
            && (
                isZapActive
                || this._hasActiveSessionInAnyTab()
                || this._hasBrowserEngineScanRunningInAnyTab()
            )
        ) {
            return {
                mode: CONTENT_RUNTIME_MODE_PENDING,
                script: CONTENT_RUNTIME_SCRIPT_NONE,
                reason: 'other_scan_active_out_of_scope'
            }
        }

        return {
            mode: CONTENT_RUNTIME_MODE_MANUAL,
            script: CONTENT_RUNTIME_SCRIPT_MANUAL,
            reason: 'manual_default'
        }
    }

    _isFirefoxRuntime() {
        return !!browser?.runtime?.getBrowserInfo
    }

    async _executeContentRuntimeFiles({ tabId = null, frameId = 0, files = [] } = {}) {
        if (!Number.isInteger(tabId) || tabId < 0) return false
        const normalizedFiles = Array.isArray(files)
            ? files.filter((value) => typeof value === 'string' && value.trim())
            : []
        if (!normalizedFiles.length) return false

        const isFirefox = this._isFirefoxRuntime()
        const manifestVersion = Number(browser?.runtime?.getManifest?.()?.manifest_version || 2)

        if (!isFirefox && manifestVersion >= 3 && browser?.scripting?.executeScript) {
            await browser.scripting.executeScript({
                target: Number.isInteger(frameId)
                    ? { tabId, frameIds: [frameId] }
                    : { tabId, allFrames: false },
                files: normalizedFiles
            })
            return true
        }

        if (browser?.tabs?.executeScript) {
            for (const file of normalizedFiles) {
                const details = {
                    file,
                    frameId: Number.isInteger(frameId) ? frameId : 0,
                    runAt: 'document_idle'
                }
                await browser.tabs.executeScript(tabId, details)
            }
            return true
        }

        return false
    }

    async _notifyContentRuntimeRefresh(tabId, frameId = 0) {
        if (!Number.isInteger(tabId) || tabId < 0 || !browser?.tabs?.sendMessage) return false
        try {
            await browser.tabs.sendMessage(tabId, {
                channel: 'ptk_background2content_runtime',
                type: 'refresh_profile'
            }, Number.isInteger(frameId) ? { frameId } : undefined)
            return true
        } catch (_) {
            return false
        }
    }

    async handleContentBootstrapHello(message = {}, sender = {}) {
        const tabId = Number.isInteger(sender?.tab?.id) ? sender.tab.id : null
        const frameId = Number.isInteger(sender?.frameId) ? sender.frameId : 0
        const url = typeof message?.url === 'string'
            ? message.url
            : (typeof sender?.url === 'string' ? sender.url : '')
        const zapHintUrl = typeof message?.zapHintUrl === 'string' ? message.zapHintUrl : ''
        const currentPageIsZapBootstrap = this.zap?.transport?.isBootstrapUrl?.(url) === true
        const observedUrls = Array.from(new Set([
            url,
            currentPageIsZapBootstrap ? zapHintUrl : ''
        ].filter((value) => typeof value === 'string' && value)))
        const currentTargetUrl = frameId === 0 && isHttpZapTargetUrl(url) ? url : null
        for (const observedUrl of observedUrls) {
            try {
                this.zap?.transport?.processContentObservedZapUrl?.({
                    tabId,
                    frameId,
                    url: observedUrl,
                    targetUrl: currentTargetUrl
                })
            } catch (error) {
                console.warn('[PTK Automation] Failed to process bootstrap URL for ZAP detection', {
                    tabId,
                    frameId,
                    url: observedUrl,
                    error: error?.message || String(error)
                })
            }
        }
        let zapTargetObserved = false
        if (currentTargetUrl) {
            try {
                await this.zap?.transport?.recoverCallbackFromTargetBootstrap?.({
                    tabId,
                    frameId,
                    url: currentTargetUrl
                })
            } catch (error) {
                console.warn('[PTK Automation] Failed to recover ZAP callback from target bootstrap', {
                    tabId,
                    frameId,
                    url,
                    error: error?.message || String(error)
                })
            }
            try {
                zapTargetObserved = this.zap?.transport?.processContentObservedTargetUrl?.({
                    tabId,
                    frameId,
                    url: currentTargetUrl
                }) === true
            } catch (error) {
                console.warn('[PTK Automation] Failed to process target URL for ZAP detection', {
                    tabId,
                    frameId,
                    url,
                    error: error?.message || String(error)
                })
            }
        }
        // Target observations grant automation only after zapTransport accepts
        // the URL as scoped to the active ZAP target.
        const profile = this._getContentRuntimeProfile({ tabId, frameId, url, zapTargetObserved })
        if (frameId === 0) {
            this._recordInScopeSessionUrl(this._getSessionForTab(tabId), url)
        }
        const files = CONTENT_RUNTIME_FILES[profile.script] || []
        const useStaticFirefoxManualRuntime = profile.script === CONTENT_RUNTIME_SCRIPT_MANUAL && this._isFirefoxRuntime()

        if (files.length && !useStaticFirefoxManualRuntime) {
            try {
                await this._executeContentRuntimeFiles({ tabId, frameId, files })
            } catch (error) {
                console.warn('[PTK Automation] Failed to inject content runtime', {
                    tabId,
                    frameId,
                    script: profile.script,
                    error: error?.message || String(error)
                })
                return {
                    ...profile,
                    script: CONTENT_RUNTIME_SCRIPT_NONE,
                    error: error?.message || String(error)
                }
            }
        }

        return profile
    }

    handleManualAutomationAuthorization(message = {}, sender = {}) {
        const tabId = Number.isInteger(sender?.tab?.id) ? sender.tab.id : null
        const frameId = Number.isInteger(sender?.frameId) ? sender.frameId : 0
        const url = typeof message?.url === 'string'
            ? message.url
            : (typeof sender?.url === 'string' ? sender.url : '')

        if (!this.isAutomationEnabled()) {
            return { ok: true, allowed: false, reason: 'automation_disabled' }
        }

        if (!Number.isInteger(tabId)) {
            return { ok: true, allowed: false, reason: 'no_tab_context' }
        }

        const session = this._getSessionForTab(tabId) || this._getCompletedSessionForTab(tabId)
        if (session && this._isActiveSessionStatus(session.status)) {
            if (!this._sessionUrlInScope(session, url)) {
                return { ok: true, allowed: false, reason: 'active_session_out_of_scope', tabId, frameId, sessionId: session.id }
            }
            return { ok: true, allowed: true, reason: 'active_session_tab', tabId, frameId, sessionId: session.id }
        }
        if (session && this._isTerminalSessionStatus(session.status)) {
            if (!this._sessionUrlInScope(session, url, { requireActive: false })) {
                return { ok: true, allowed: false, reason: 'terminal_session_out_of_scope', tabId, frameId, sessionId: session.id }
            }
            return { ok: true, allowed: true, reason: 'terminal_session_tab', tabId, frameId, sessionId: session.id }
        }

        if (this._isPtkChildTab(tabId)) {
            if (!this._ptkChildTabUrlInScope(tabId, url)) {
                return { ok: true, allowed: false, reason: 'ptk_child_tab_out_of_scope', tabId, frameId }
            }
            return { ok: true, allowed: true, reason: 'ptk_child_tab', tabId, frameId }
        }

        if (this._isBrowserEngineScanRunningForTab(tabId)) {
            return { ok: true, allowed: true, reason: 'browser_scan_tab', tabId, frameId }
        }

        const transport = this.zap?.transport || null
        const detectedPayload = transport?.getLastDetectedPayload?.() || null
        const detectedTabId = Number.isInteger(detectedPayload?.tabId) ? detectedPayload.tabId : null
        if (Number.isInteger(detectedTabId) && detectedTabId === tabId) {
            if (!this._detectedZapTabUrlInScope(detectedPayload, url)) {
                return { ok: true, allowed: false, reason: 'zap_detected_tab_out_of_scope', tabId, frameId }
            }
            return { ok: true, allowed: true, reason: 'zap_detected_tab', tabId, frameId }
        }
        if (transport?.isBootstrapUrl?.(url) === true) {
            return { ok: true, allowed: true, reason: 'zap_bootstrap_url', tabId, frameId }
        }

        const grant = this._getManualAutomationBootstrapGrant(tabId)
        if (grant) {
            return {
                ok: true,
                allowed: true,
                reason: 'manual_bootstrap_grant',
                grantReason: grant.reason,
                tabId,
                frameId
            }
        }

        if (this._hasActiveSessionInAnyTab() || this._hasBrowserEngineScanRunningInAnyTab()) {
            return { ok: true, allowed: false, reason: 'other_scan_active', tabId, frameId }
        }

        return { ok: true, allowed: false, reason: 'manual_bootstrap_not_armed', tabId, frameId }
    }

    handleManualAutomationActivationRequest(message = {}, sender = {}) {
        const tabId = Number.isInteger(sender?.tab?.id) ? sender.tab.id : null
        const frameId = Number.isInteger(sender?.frameId) ? sender.frameId : 0
        const url = typeof message?.url === 'string'
            ? message.url
            : (typeof sender?.url === 'string' ? sender.url : '')

        if (!this.isAutomationEnabled()) {
            return { ok: true, allowed: false, reason: 'automation_disabled' }
        }

        if (!Number.isInteger(tabId)) {
            return { ok: true, allowed: false, reason: 'no_tab_context' }
        }

        if (frameId !== 0) {
            return { ok: true, allowed: false, reason: 'not_top_frame', tabId, frameId }
        }

        if (sender?.tab && sender.tab.active === false) {
            return { ok: true, allowed: false, reason: 'inactive_tab', tabId, frameId }
        }

        const existingAuthorization = this.handleManualAutomationAuthorization(message, sender)
        if (existingAuthorization?.allowed === true) {
            return existingAuthorization
        }

        if (existingAuthorization?.reason === 'other_scan_active') {
            return existingAuthorization
        }

        const grant = this._createManualAutomationBootstrapGrant(tabId, {
            reason: message?.reason || 'manual_activation_request',
            url
        })

        return {
            ok: true,
            allowed: true,
            reason: 'manual_activation_granted',
            grantReason: grant?.reason || 'manual_activation_request',
            expiresAt: grant?.expiresAt || null,
            tabId,
            frameId
        }
    }

    _getZapTimingForSession(session = null) {
        if (!session || session.source !== 'zap') return null
        return {
            zapid: this.zap?.transport?.getZapId?.() || null,
            zapSessionKey: session.zapSessionKey || null,
            automationSessionId: session.id || null,
            tabId: Number.isInteger(session.tabId) ? session.tabId : null,
            targetUrl: session.targetUrl || null
        }
    }

    _recordZapTiming(session = null, phase = null, extra = null) {
        const timing = this._getZapTimingForSession(session)
        if (!timing || !phase || typeof this.zap?.recordTiming !== 'function') {
            return false
        }
        return this.zap.recordTiming(Object.assign({}, timing, { phase, extra }))
    }

    /**
     * Check if ZAP mode is active
     * @returns {boolean}
     */
    isZapActive() {
        return this.zap.isActive()
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    /**
     * Check if automation is enabled in settings
     * Uses in-memory settings from app.settings (no storage read needed)
     * @returns {boolean}
     */
    isAutomationEnabled() {
        const enabled = this.app?.settings?.automation?.enable === true
        debugAutomationLog('[PTK Automation] isAutomationEnabled check:', {
            hasApp: !!this.app,
            hasSettings: !!this.app?.settings,
            automation: this.app?.settings?.automation,
            enabled
        })
        return enabled
    }

    _isZapAutomationBridgeRequestAllowed(message = {}, sender = {}) {
        const tabId = Number.isInteger(sender?.tab?.id) ? sender.tab.id : null
        if (!Number.isInteger(tabId)) return false

        // This method is reached only when global PTK automation is disabled.
        // The exception is intentionally narrow: ZAP-managed browser-close
        // scripts may read progress and request stop for the explicit ZAP
        // session attached to the same tab. All other automation commands remain
        // blocked, and the background session lookup still owns the decision.
        const type = String(message?.type || '').replace(/_/g, '-')
        if (type !== 'get-session-progress' && type !== 'session-end' && type !== 'zap-keepalive') return false
        if (type === 'zap-keepalive') {
            if (message?.options?.source !== 'zap_keepalive') return false
            return this._isZapManagedActiveSessionForTab(tabId)
        }
        if (message?.options?.source !== 'zap_browser_close') return false

        const requestedSessionId = toNonEmptyString(message?.sessionId)
            || toNonEmptyString(message?.options?.sessionId)
        if (!requestedSessionId) {
            return this._isZapManagedActiveSessionForTab(tabId)
        }

        const session = this.sessions.get(requestedSessionId)
        if (session?.source !== 'zap') return false
        // In ZAP client-spider runs, Firefox can close a WebDriver browser tab
        // that differs from the tab which originally started the ZAP PTK
        // session. The close contract is intentionally narrower than general
        // automation: it requires an explicit ZAP-owned PTK session id and only
        // permits progress reads or non-blocking stop requests.
        const sameTab = Number.isInteger(session?.tabId) && session.tabId === tabId
        const requestedZapId = toNonEmptyString(message?.options?.zapid)
        const sessionZapKey = toNonEmptyString(session?.zapSessionKey)
        const sameZapSession = Boolean(
            requestedZapId
            && sessionZapKey
            && sessionZapKey.endsWith(`|${requestedZapId}`)
        )
        if (!sameTab && !sameZapSession) return false
        if (type === 'session-end' && (session.status === 'completed' || session.status === 'error')) {
            return false
        }

        return true
    }

    async msg_zap_keepalive(message, sender) {
        const tabId = Number.isInteger(sender?.tab?.id) ? sender.tab.id : null
        if (!Number.isInteger(tabId)) {
            return { ok: false, error: 'no_tab_context', requestId: message.requestId }
        }

        const requestedSessionId = toNonEmptyString(message?.sessionId)
            || toNonEmptyString(message?.options?.sessionId)
            || this.activeSessionByTabId.get(tabId)
            || null
        const session = requestedSessionId ? this.sessions.get(requestedSessionId) : null
        if (!session || session.source !== 'zap' || !this._isActiveSessionStatus(session.status)) {
            return {
                ok: false,
                reason: 'no_active_zap_session',
                requestId: message.requestId
            }
        }

        const result = typeof this.zap?.tickProgressMonitors === 'function'
            ? this.zap.tickProgressMonitors({ source: 'content_keepalive' })
            : { ok: false, monitors: 0, reason: 'zap_bridge_unavailable' }
        this.zap?.pollControlMonitors?.({ source: 'content_keepalive' })
        return {
            ok: result?.ok === true,
            monitors: Number(result?.monitors || 0),
            sessionId: session.id,
            requestId: message.requestId
        }
    }

    onMessage(message, sender, sendResponse) {
        if (message.channel === 'ptk_privileged_replayable_export') {
            ;(async () => {
                if (this.app?.ready && typeof this.app.ready.then === 'function') {
                    await this.app.ready
                }
                const caller = this._privilegedCallerFromSender(sender, message?.transport || message?.request?.transport)
                const type = String(message.type || '').replace(/-/g, '_')
                if (type === 'ptk_privileged_replayable_export') {
                    return await this.ptk_privileged_replayable_export(message.request || message.options || message, caller)
                }
                if (type === 'ptk_privileged_replayable_export_chunk') {
                    return await this.ptk_privileged_replayable_export_chunk(message.request || message.options || message, caller)
                }
                if (type === 'ptk_privileged_replayable_export_release') {
                    return await this.ptk_privileged_replayable_export_release(message.request || message.options || message, caller)
                }
                return { ok: false, error: 'unknown_privileged_export_message', requestId: message.requestId }
            })().then(result => {
                sendResponse(result)
            }).catch(e => {
                console.error('[PTK Automation] Privileged replayable export error:', e)
                sendResponse({ ok: false, error: e?.message || String(e), requestId: message.requestId })
            })
            return true
        }

        if (message.channel !== 'ptk_content2background_automation') {
            return false  // Explicitly indicate we don't handle this message
        }

        // Use sendResponse pattern for Chrome MV3 compatibility
        // This is more reliable than returning a Promise when multiple listeners exist
        ;(async () => {
            if (this.app?.ready && typeof this.app.ready.then === 'function') {
                await this.app.ready
            }

            // Verify automation only after app/settings bootstrap has finished.
            if (!this.isAutomationEnabled() && !this._isZapAutomationBridgeRequestAllowed(message, sender)) {
                console.warn('[PTK Automation] Automation is disabled in settings, rejecting request')
                return { error: 'automation_disabled', requestId: message.requestId }
            }

            debugAutomationLog('[PTK Automation] Received message:', message.type, message)

            const type = (message.type || '').replace(/-/g, '_')
            const handler = this['msg_' + type]
            if (handler) {
                const result = await handler.call(this, message, sender)
                debugAutomationLog('[PTK Automation] Response:', result)
                return result
            }
            console.warn('[PTK Automation] Unknown message type:', type)
            return { error: 'unknown_message_type', requestId: message.requestId }
        })().then(result => {
            sendResponse(result)
        }).catch(e => {
            console.error('[PTK Automation] Error:', e)
            sendResponse({ error: e.message, requestId: message.requestId })
        })

        return true  // Indicate async response via sendResponse
    }

    // === Session Lifecycle ===

    async msg_session_start(message, sender) {
        debugAutomationLog('[PTK Automation] msg_session_start called', { message, sender: sender?.tab?.id })
        const { options, pageUrl, requestId } = message
        const tabId = sender?.tab?.id
        const frameId = senderFrameId(sender)

        if (!tabId) {
            console.error('[PTK Automation] No tab context')
            return { error: 'no_tab_context', requestId }
        }

        // Enforce single session per tab
        const existingSessionId = this.activeSessionByTabId.get(tabId)
        if (existingSessionId) {
            const existingSession = this.sessions.get(existingSessionId)
            if (existingSession && this._isActiveSessionStatus(existingSession.status)) {
                return {
                    error: 'session_already_running_in_tab',
                    existingSessionId,
                    existingSessionStatus: existingSession.status,
                    requestId
                }
            }
            // Clean up stale session
            this.sessions.delete(existingSessionId)
            this.activeSessionByTabId.delete(tabId)
        }

        const manualGrant = this._consumeManualAutomationBootstrapGrant(tabId)
        if (!manualGrant && !this._isBrowserEngineScanRunningForTab(tabId) && !this._isPtkChildTab(tabId)) {
            return {
                ok: false,
                error: 'manual_automation_not_authorized',
                requestId
            }
        }

        // Background generates the sessionId (single source of truth)
        const sessionId = this._generateSessionId()
        const host = this._extractHost(pageUrl)
        const engines = this._normalizeEngines(options?.engines)
        const engineConfigs = this._normalizeEngineConfigs(options?.engineConfigs, engines)

        const session = {
            id: sessionId,
            tabId,
            frameId,
            host,
            pageUrl,
            targetUrl: pageUrl,
            lastInScopeUrl: pageUrl,
            project: options?.project || null,
            testRunId: options?.testRunId || null,
            engines,
            policyCode: options?.policyCode || null,
            runCve: options?.runCve === true,
            engineConfigs,
            startedAt: new Date().toISOString(),
            finishedAt: null,
            status: 'starting',
            scanIds: {},
            engineStates: {}
        }

        // Store session BEFORE starting engines (so we can track partial failures)
        this.sessions.set(sessionId, session)
        this.activeSessionByTabId.set(tabId, sessionId)

        try {
            await this._startEngines(session)
            session.status = 'running'
            return { sessionId, tabId, frameId, status: 'started', requestId }
        } catch (err) {
            session.status = 'error'
            session.error = err.message
            return { sessionId, tabId, frameId, status: 'error', error: err.message, requestId }
        }
    }

    async startZapConfiguredSession(payload = {}) {
        const tabId = Number.isInteger(payload?.tabId) ? payload.tabId : null
        debugAutomationLog('[PTK Automation] startZapConfiguredSession requested', {
            tabId,
            targetUrl: payload?.targetUrl || payload?.pageUrl || null,
            engines: Array.isArray(payload?.engines) ? payload.engines : null,
            zapSessionKey: payload?.zapSessionKey || null
        })
        if (tabId === null || tabId < 0) {
            console.warn('[PTK Automation] startZapConfiguredSession rejected: missing tabId', {
                tabId,
                zapSessionKey: payload?.zapSessionKey || null
            })
            throw new Error('zap_missing_tab')
        }

        const targetUrl = typeof payload?.targetUrl === 'string' && payload.targetUrl
            ? payload.targetUrl
            : (typeof payload?.pageUrl === 'string' ? payload.pageUrl : null)
        const host = this._extractHost(targetUrl || '')
        if (!host || host === 'zap') {
            console.warn('[PTK Automation] startZapConfiguredSession rejected: invalid target URL', {
                tabId,
                targetUrl,
                host,
                zapSessionKey: payload?.zapSessionKey || null
            })
            throw new Error('zap_invalid_target_url')
        }

        const requestedEngines = Array.isArray(payload?.engines) && payload.engines.length
            ? payload.engines
            : ['DAST', 'IAST', 'SAST', 'SCA']
        const engines = this._normalizeEngines(requestedEngines)
        if (!engines.length) {
            console.warn('[PTK Automation] startZapConfiguredSession rejected: no normalized engines', {
                tabId,
                targetUrl,
                requestedEngines,
                zapSessionKey: payload?.zapSessionKey || null
            })
            throw new Error('zap_no_engines')
        }

        const engineConfigs = this._normalizeEngineConfigs(payload?.engineConfigs, engines)
        const policyCode = payload?.policyCode || null
        const runCve = payload?.runCve === true
        const zapSessionKey = payload?.zapSessionKey || null
        const existingSessionId = this.activeSessionByTabId.get(tabId)
        if (existingSessionId) {
            const existingSession = this.sessions.get(existingSessionId)
            if (existingSession && this._isActiveSessionStatus(existingSession.status)) {
                if (zapSessionKey && existingSession.zapSessionKey === zapSessionKey) {
                    debugAutomationLog('[PTK Automation] startZapConfiguredSession already running for ZAP session', {
                        tabId,
                        sessionId: existingSessionId,
                        status: existingSession.status,
                        zapSessionKey,
                        engines: existingSession.engines
                    })
                    return {
                        sessionId: existingSessionId,
                        status: 'already_running',
                        requiredEngines: Array.isArray(existingSession.engines) ? existingSession.engines.slice() : engines
                    }
                }
                console.warn('[PTK Automation] startZapConfiguredSession busy with different session', {
                    tabId,
                    existingSessionId,
                    existingZapSessionKey: existingSession.zapSessionKey || null,
                    requestedZapSessionKey: zapSessionKey,
                    status: existingSession.status
                })
                return {
                    sessionId: existingSessionId,
                    status: 'busy',
                    requiredEngines: Array.isArray(existingSession?.engines) ? existingSession.engines.slice() : engines
                }
            }
            this.sessions.delete(existingSessionId)
            this.activeSessionByTabId.delete(tabId)
        }

        const sessionId = this._generateSessionId()
        const session = {
            id: sessionId,
            tabId,
            frameId: 0,
            host,
            project: 'zap',
            testRunId: null,
            engines,
            policyCode,
            runCve,
            engineConfigs,
            startedAt: new Date().toISOString(),
            finishedAt: null,
            status: 'starting',
            scanIds: {},
            engineStates: {},
            source: 'zap',
            zapSessionKey,
            targetUrl,
            pageUrl: targetUrl,
            lastInScopeUrl: targetUrl
        }

        this._initializeEngineStates(session, engines)
        this.sessions.set(sessionId, session)
        this.activeSessionByTabId.set(tabId, sessionId)
        debugAutomationLog('[PTK Automation] startZapConfiguredSession created session', {
            sessionId,
            tabId,
            host,
            targetUrl,
            engines,
            zapSessionKey
        })
        this._recordZapTiming(session, 'session.created')

        try {
            const immediateEngines = this._selectImmediateZapStartupEngines(engines)
            const deferredEngines = engines.filter(engineName => !immediateEngines.includes(engineName))
            for (const engineName of deferredEngines) {
                session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                    status: ENGINE_STATUS_DEFERRED_START,
                    deferredAt: Date.now()
                })
            }

            await this._startEngines(session, immediateEngines)
            const startupSummary = this._summarizeEngineStartup(session, immediateEngines)
            if (startupSummary.failedEngines.length > 0 && startupSummary.startedEngines.length === 0) {
                const message = this._buildZapStartupFailureMessage(startupSummary.failedEngines)
                session.status = 'error'
                session.error = message
                session.finishedAt = new Date().toISOString()
                void this._cleanupFailedZapStartup(session)
                console.warn('[PTK Automation] startZapConfiguredSession engine startup failed', {
                    sessionId,
                    tabId,
                    host,
                    targetUrl,
                    startedEngines: startupSummary.startedEngines,
                    failedEngines: startupSummary.failedEngines,
                    message
                })
                return {
                    sessionId,
                    status: 'error',
                    error: message,
                    message,
                    startedEngines: startupSummary.startedEngines,
                    failedEngines: startupSummary.failedEngines,
                    requiredEngines: engines
                }
            }
            session.status = 'running'
            if (deferredEngines.length) {
                this._recordZapTiming(session, 'session.deferred_start.begin', {
                    engines: deferredEngines.join(',')
                })
                this._startDeferredZapEngines(
                    session,
                    deferredEngines,
                    this._computeDeferredZapEngineStartDelay(session)
                )
            }
            this._recordZapTiming(session, 'session.running', {
                startedEngines: startupSummary.startedEngines.join(','),
                deferredEngines: deferredEngines.join(',')
            })
            debugAutomationLog('[PTK Automation] startZapConfiguredSession running', {
                sessionId,
                tabId,
                host,
                targetUrl,
                startedEngines: startupSummary.startedEngines,
                deferredEngines,
                requiredEngines: engines
            })
            return {
                sessionId,
                status: deferredEngines.length ? 'starting' : 'started',
                startedEngines: startupSummary.startedEngines,
                failedEngines: startupSummary.failedEngines,
                deferredEngines,
                requiredEngines: engines
            }
        } catch (err) {
            session.status = 'error'
            session.error = err.message
            console.error('[PTK Automation] startZapConfiguredSession failed', {
                sessionId,
                tabId,
                host,
                targetUrl,
                error: err?.message || String(err)
            })
            return {
                sessionId,
                status: 'error',
                error: err.message,
                requiredEngines: engines
            }
        }
    }

    getZapManagedScanContexts({ engine = null, zapSessionKey = null, host = null } = {}) {
        const engineName = String(engine || '').trim().toUpperCase()
        if (!engineName) return []

        const expectedSessionKey = toNonEmptyString(zapSessionKey)
        const expectedHost = toNonEmptyString(host)?.toLowerCase()
        const entries = []

        for (const session of this.sessions.values()) {
            if (!session || session.source !== 'zap') continue
            if (!Array.isArray(session.engines) || !session.engines.includes(engineName)) continue
            if (expectedSessionKey && session.zapSessionKey !== expectedSessionKey) continue
            if (expectedHost && String(session.host || '').toLowerCase() !== expectedHost) continue

            const scanId = toNonEmptyString(session.scanIds?.[engineName])
            if (!scanId) continue

            const startedAt = Date.parse(session.startedAt || '')
            entries.push({
                scanId,
                startedAt: Number.isFinite(startedAt) ? startedAt : 0,
                sessionId: session.id || null,
                zapSessionKey: session.zapSessionKey || null,
                host: session.host || null
            })
        }

        const seen = new Set()
        return entries
            .sort((a, b) => a.startedAt - b.startedAt)
            .filter(entry => {
                const scanId = entry.scanId
                if (seen.has(scanId)) return false
                seen.add(scanId)
                return true
            })
    }

    getZapManagedScanIds(options = {}) {
        return this.getZapManagedScanContexts(options).map(entry => entry.scanId)
    }

    async requestZapSessionStop(sessionId, options = {}) {
        const safeSessionId = toNonEmptyString(sessionId)
        if (!safeSessionId) {
            return { ok: false, error: 'missing_session_id' }
        }
        const session = this.sessions.get(safeSessionId)
        if (!session || session.source !== 'zap') {
            return { ok: false, error: 'session_not_found', sessionId: safeSessionId }
        }
        if (session.status === 'completed' || session.status === 'error') {
            return {
                ok: true,
                sessionId: safeSessionId,
                status: session.status,
                alreadyTerminal: true,
                source: options?.source || null
            }
        }

        const timeoutMs = this._normalizeStopTimeoutMs(options?.timeoutMs)
        const zapCloseRequest = options?.source === 'zap_browser_close'
        const closeRequestId = toNonEmptyString(options?.closeRequestId)
        if (closeRequestId) {
            session.closeRequestId = closeRequestId
            session.closeRequestAck = true
            session.closeRequestMode = toNonEmptyString(options?.closeRequestMode) || 'graceful_stop_and_drain'
            session.closeRequestReason = toNonEmptyString(options?.closeRequestReason) || null
        }
        if (session.stopRequestedAt) {
            if (zapCloseRequest) {
                await this._finalizeZapCloseSessionForTerminal(session, {
                    zapid: options?.zapid,
                    timeoutMs,
                    reason: 'zap_close_stop_already_requested'
                })
                const responseStatus = session.status || 'stopping'
                return {
                    ok: true,
                    sessionId: safeSessionId,
                    status: responseStatus,
                    completionStatus: session.completionStatus || session.summary?.status || null,
                    summary: session.summary || null,
                    stopRequestedAt: session.stopRequestedAt,
                    alreadyRequested: true,
                    closeRequestId: session.closeRequestId || null,
                    closeRequestAck: session.closeRequestAck === true,
                    source: options?.source || null
                }
            }
            return {
                ok: true,
                sessionId: safeSessionId,
                status: session.status || 'stopping',
                completionStatus: session.completionStatus || session.summary?.status || null,
                summary: session.summary || null,
                stopRequestedAt: session.stopRequestedAt,
                alreadyRequested: true,
                closeRequestId: session.closeRequestId || null,
                closeRequestAck: session.closeRequestAck === true,
                source: options?.source || null
            }
        }

        session.stopRequestedAt = new Date().toISOString()
        session.status = 'stopping'
        session.stopInProgress = true

        if (zapCloseRequest) {
            await this._finalizeZapCloseSessionForTerminal(session, {
                zapid: options?.zapid,
                timeoutMs,
                reason: toNonEmptyString(options?.closeRequestReason) || 'zap_browser_close_terminalized'
            })
            const responseStatus = session.status || 'stopping'
            return {
                ok: true,
                sessionId: safeSessionId,
                status: responseStatus,
                completionStatus: session.completionStatus || session.summary?.status || null,
                summary: session.summary || null,
                stopRequestedAt: session.stopRequestedAt,
                closeRequestId: session.closeRequestId || null,
                closeRequestAck: session.closeRequestAck === true,
                source: options?.source || null
            }
        }

        this._stopEnginesAsync(session, timeoutMs, {
            source: options?.source || null,
            zapCloseRequest: false
        })
            .then(stats => {
                session.stopInProgress = false
                if (session.status === 'completed' || session.status === 'error') {
                    return
                }
                this._finalizeSession(session, stats)
            })
            .catch(err => {
                console.error('[PTK Automation] Async ZAP stop failed', {
                    sessionId: safeSessionId,
                    source: options?.source || null,
                    error: err?.message || String(err)
                })
                session.stopInProgress = false
                session.status = 'error'
                session.error = err?.message || String(err)
            })

        return {
            ok: true,
            sessionId: safeSessionId,
            status: session.status || 'stopping',
            completionStatus: session.completionStatus || session.summary?.status || null,
            summary: session.summary || null,
            stopRequestedAt: session.stopRequestedAt,
            closeRequestId: session.closeRequestId || null,
            closeRequestAck: session.closeRequestAck === true,
            source: options?.source || null
        }
    }

    async msg_session_end(message, sender) {
        const { requestId, wait = true, options = {} } = message
        const tabId = sender?.tab?.id
        const strictCurrentTab = this._isStrictCurrentTabScope(options)
        const stopTimeoutMs = this._normalizeStopTimeoutMs(options?.stopTimeoutMs)

        const resolution = this._resolveSessionForRequest({
            sessionId: options?.sessionId || message.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: true,
            allowCompleted: false,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId }
        }
        const session = resolution.session
        const closeRequestId = toNonEmptyString(options?.closeRequestId)
        if (options?.source === 'zap_browser_close' && closeRequestId) {
            session.closeRequestId = closeRequestId
            session.closeRequestAck = true
            session.closeRequestMode = toNonEmptyString(options?.closeRequestMode) || 'graceful_stop_and_drain'
            session.closeRequestReason = toNonEmptyString(options?.closeRequestReason) || null
        }

        // === Non-blocking stop (wait=false) ===
        if (wait === false) {
            // Mark stop requested
            session.stopRequestedAt = new Date().toISOString()
            session.status = 'stopping'
            session.stopInProgress = true

            if (options?.source === 'zap_browser_close') {
                await this._finalizeZapCloseSessionForTerminal(session, {
                    zapid: options?.zapid,
                    timeoutMs: stopTimeoutMs,
                    reason: toNonEmptyString(options?.closeRequestReason) || 'zap_browser_close_terminalized'
                })
                const responseStatus = session.status || 'stopping'
                return {
                    ok: true,
                    requestId,
                    status: responseStatus,
                    completionStatus: session.completionStatus || session.summary?.status || null,
                    summary: session.summary || { status: session.status || 'stopping' },
                    closeRequestId: session.closeRequestId || null,
                    closeRequestAck: session.closeRequestAck === true
                }
            }

            // Fire-and-forget stop with completion handler
            this._stopEnginesAsync(session, stopTimeoutMs, {
                source: options?.source || null,
                zapCloseRequest: false
            })
                .then(stats => {
                    session.stopInProgress = false
                    if (session.status === 'completed' || session.status === 'error') {
                        return
                    }
                    this._finalizeSession(session, stats)
                })
                .catch(err => {
                    console.error('[PTK Automation] Async stop failed', err)
                    session.stopInProgress = false
                    session.status = 'error'
                    session.error = err.message
                })

            // Return immediately
            // NOTE: Do NOT clear activeSessionByTabId yet - wait until completed
            return {
                ok: true,
                requestId,
                summary: { status: 'stopping' }
            }
        }

        // === Blocking stop (wait=true, existing behavior) ===
        try {
            const stats = await this._stopEngines(session, stopTimeoutMs)
            this._finalizeSession(session, stats)

            let findingsPayload = null
            if (message.includeFindings === true) {
                const limit = Math.min(Number(message.limit) || 100, MAX_FINDINGS_LIMIT)
                const { findings, truncated } = this._collectFindings(session, limit)
                findingsPayload = { findings, truncated }
            }

            return {
                ok: true,
                requestId,
                summary: session.summary,
                ...(findingsPayload || {})
            }
        } catch (err) {
            session.status = 'error'
            session.error = err.message
            return { ok: false, error: err.message, requestId }
        }
    }

    async msg_get_stats(message, sender) {
        const { requestId } = message
        const tabId = sender?.tab?.id

        const resolution = this._resolveSessionForRequest({
            sessionId: message.sessionId,
            tabId,
            strictCurrentTab: false,
            allowActive: true,
            allowCompleted: false,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }
        const session = resolution.session

        const stats = this._collectCurrentStats(session)
        return {
            findingsCount: stats.findingsCount,
            bySeverity: stats.bySeverity,
            requestId,
            sessionLookup: resolution.sessionLookup
        }
    }

    // Return { findings, truncated }
    async msg_get_findings(message, sender) {
        const { requestId, limit = 100, options = {} } = message
        const tabId = sender?.tab?.id

        const strictCurrentTab = this._isStrictCurrentTabScope(options)
        const resolution = this._resolveSessionForRequest({
            sessionId: options?.sessionId || message.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: true,
            allowCompleted: strictCurrentTab,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }
        const session = resolution.session

        const cappedLimit = Math.min(limit, MAX_FINDINGS_LIMIT)
        const { findings, truncated } = this._collectFindings(session, cappedLimit)
        return { findings, truncated, requestId, sessionLookup: resolution.sessionLookup }
    }

    async msg_get_analysis_snapshot(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id
        const strictCurrentTab = this._isStrictCurrentTabScope(options)
        const resolution = this._resolveSessionForRequest({
            sessionId: options?.sessionId || message.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: true,
            allowCompleted: true,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }

        const snapshot = this._collectAnalysisSnapshot(resolution.session)
        return {
            ok: true,
            requestId,
            sessionId: resolution.sessionId,
            sessionLookup: resolution.sessionLookup,
            ...snapshot
        }
    }

    /**
     * Get session progress (fast, non-blocking)
     * Used for polling during stop+wait pattern
     */
    async msg_get_session_progress(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id
        const strictCurrentTab = this._isStrictCurrentTabScope(options)

        const resolution = this._resolveSessionForRequest({
            sessionId: options.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: true,
            allowCompleted: true,
            allowGlobalCompleted: true
        })

        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }

        if (isZapBrowserCloseOptions(options)) {
            this._ensureZapSastCurrentPageCollection(resolution.session, tabId, options)
                .catch((err) => {
                    console.warn('[PTK Automation] Failed to ensure ZAP SAST current-page collection', {
                        sessionId: resolution.sessionId,
                        tabId,
                        error: err?.message || String(err)
                    })
                })
        }

        const snapshot = this.getSessionProgressSnapshot(resolution.sessionId)
        if (!snapshot?.ok) {
            return { ok: false, error: snapshot?.error || 'session_not_found', requestId, sessionLookup: resolution.sessionLookup }
        }

        let zapCloseProgress = {}
        let zapCloseContext = null
        if (isZapBrowserCloseOptions(options)) {
            const requestTabId = Number.isInteger(tabId) ? tabId : null
            const sessionTabId = Number.isInteger(resolution.session?.tabId) ? resolution.session.tabId : null
            const senderUrl = toNonEmptyString(sender?.tab?.url)
                || toNonEmptyString(options?.currentUrl)
                || null
            const targetUrl = toNonEmptyString(resolution.session?.targetUrl)
                || toNonEmptyString(resolution.session?.pageUrl)
                || null
            const sameTab = requestTabId !== null && sessionTabId !== null && requestTabId === sessionTabId
            const matchesTargetUrl = Boolean(
                senderUrl
                && targetUrl
                && isHttpPageUrl(senderUrl)
                && isHttpPageUrl(targetUrl)
                && sameDocumentUrl(senderUrl, targetUrl, targetUrl)
            )
            zapCloseContext = {
                requestTabId,
                sessionTabId,
                sameTab,
                currentUrl: senderUrl,
                targetUrl,
                matchesTargetUrl,
                shouldStopSession: sameTab || matchesTargetUrl
            }
            const terminalStatus = ['none', 'completed', 'error', 'timeout', 'cancelled']
            let zapProgressTerminalPosted = this.zap?.transport?.isSessionTerminal?.({
                zapid: options?.zapid,
                sessionId: resolution.sessionId
            }) === true
            let zapTerminalPost = null
            if (!zapProgressTerminalPosted && terminalStatus.includes(String(snapshot.status || '').toLowerCase())) {
                const terminalPostPayload = {
                    zapid: options?.zapid,
                    sessionId: resolution.sessionId
                }
                zapTerminalPost = {
                    ok: true,
                    posted: false,
                    reason: 'terminal_progress_post_queued'
                }
                Promise.resolve()
                    .then(() => this.zap?.postTerminalProgressForClose?.(terminalPostPayload))
                    .catch((err) => {
                        debugAutomationLog('[PTK Automation] Failed to post ZAP terminal progress from status read', {
                            sessionId: resolution.sessionId,
                            error: err?.message || String(err)
                        })
                    })
                zapProgressTerminalPosted = this.zap?.transport?.isSessionTerminal?.({
                    zapid: options?.zapid,
                    sessionId: resolution.sessionId
                }) === true
            }
            zapCloseProgress = {
                zapProgressTerminalPosted,
                zapProgressTerminalDetails: this.zap?.transport?.getSessionTerminalDetails?.() || null,
                zapTerminalPost,
                zapPublisherDrain: await this._getZapPublisherDrainState(),
                zapCloseContext
            }
        }

        return {
            ...snapshot,
            ...zapCloseProgress,
            requestId,
            sessionLookup: resolution.sessionLookup
        }
    }

    async _ensureZapSastCurrentPageCollection(session, tabId, options = {}) {
        if (!session || !Array.isArray(session.engines) || !session.engines.includes('SAST')) {
            return false
        }
        if (session.status !== ENGINE_STATUS_RUNNING || session.stopRequestedAt) {
            return false
        }
        if (!Number.isInteger(Number(tabId))) {
            return false
        }
        const sast = this.app?.sast || null
        if (!sast || typeof sast.collectAndScanTab !== 'function') {
            return false
        }
        const coordinator = sast.sessionCoordinator || null
        const state = coordinator?.getAutomationState?.() || {}
        if (state.isSessionRunning === false || sast.isScanRunning === false) {
            return false
        }

        let currentUrl = toNonEmptyString(options?.currentUrl) || null
        if (!currentUrl) {
            try {
                const tab = await browser.tabs.get(Number(tabId))
                currentUrl = toNonEmptyString(tab?.url) || null
            } catch (_) { }
        }
        if (!isHttpPageUrl(currentUrl)) {
            return false
        }
        if (/\/zapCallBackUrl\//i.test(currentUrl)) {
            return false
        }

        const hasCompletedEvidence = [
            state.lastCompletedScriptsCount,
            state.lastCompletedHtmlChars,
            state.lastCompletedFindingsCount,
            state.lastCompletedArtifactsCount
        ].some((value) => typeof value !== 'undefined' && value !== null)
        if (sameDocumentUrl(state.lastCompletedFile, currentUrl, currentUrl)
            && hasCompletedEvidence
            && (state.lastCompletedAt || state.lastCompletedCollectionId)) {
            return false
        }

        const activeOrPending = toFiniteNumber(state.activeCollectionCount, 0) > 0
            || toFiniteNumber(state.pendingCollectionCount, 0) > 0
            || state.collectionState === 'collection_pending'
            || state.collectionState === 'payload_received'
            || state.collectionState === 'analysis_running'
            || state.analysisState === 'collecting'
            || state.analysisState === 'analyzing'
        if (activeOrPending && sameDocumentUrl(state.currentCollectionFile, currentUrl, currentUrl)) {
            return false
        }

        const now = Date.now()
        if (!(session.zapSastCurrentPageCollectionRequests instanceof Map)) {
            session.zapSastCurrentPageCollectionRequests = new Map()
        }
        const previousRequestedAt = session.zapSastCurrentPageCollectionRequests.get(currentUrl)
        if (Number.isFinite(previousRequestedAt) && now - previousRequestedAt < 8000) {
            return false
        }
        session.zapSastCurrentPageCollectionRequests.set(currentUrl, now)

        if (session.zapSastCurrentPageCollectionRequests.size > 20) {
            const oldest = session.zapSastCurrentPageCollectionRequests.keys().next().value
            if (oldest) session.zapSastCurrentPageCollectionRequests.delete(oldest)
        }

        this._recordZapTiming(session, 'sast.collection.ensure_current_page', {
            tabId: Number(tabId),
            currentUrl
        })
        sast.collectAndScanTab(Number(tabId), {
            delayMs: 50,
            attempts: 4,
            timeoutMs: 12000,
            retryDelayMs: 600,
            expectedUrl: currentUrl,
            source: 'zap_progress_current_page'
        }).catch((err) => {
            console.warn('[PTK Automation] ZAP SAST current-page collection failed', {
                sessionId: session.id,
                tabId: Number(tabId),
                currentUrl,
                error: err?.message || String(err)
            })
        })
        return true
    }

    _installPrivilegedReplayableExportApi() {
        const serviceWorkerCaller = () => ({
            callerType: 'privileged-sdk-export',
            extensionOwned: true,
            transport: 'service-worker',
            senderId: this._getRuntimeId(),
            senderUrl: PRIVILEGED_SERVICE_WORKER_URL
        })
        try {
            globalThis.PTK_PRIVILEGED_REPLAYABLE_EXPORT = (request = {}) => {
                return this.ptk_privileged_replayable_export(request, serviceWorkerCaller())
            }
            globalThis.PTK_PRIVILEGED_REPLAYABLE_EXPORT_CHUNK = (request = {}) => {
                return this.ptk_privileged_replayable_export_chunk(request, serviceWorkerCaller())
            }
            globalThis.PTK_PRIVILEGED_REPLAYABLE_EXPORT_RELEASE = (request = {}) => {
                return this.ptk_privileged_replayable_export_release(request, serviceWorkerCaller())
            }
        } catch (_) { }
    }

    _getRuntimeId() {
        const browserRuntimeId = typeof browser !== 'undefined' ? browser?.runtime?.id : null
        const chromeRuntimeId = typeof chrome !== 'undefined' ? chrome?.runtime?.id : null
        return browserRuntimeId || chromeRuntimeId || null
    }

    _privilegedCallerFromSender(sender = {}, transport = null) {
        const normalizedTransport = String(transport || '').trim().toLowerCase()
        const runtimeId = this._getRuntimeId()
        return {
            callerType: 'privileged-sdk-export',
            extensionOwned: sender?.id && runtimeId ? sender.id === runtimeId : false,
            transport: normalizedTransport || 'extension-page',
            senderId: sender?.id || null,
            senderUrl: sender?.url || null,
            exportTabId: Number.isInteger(sender?.tab?.id) ? sender.tab.id : null,
            frameId: senderFrameId(sender)
        }
    }

    _cleanupReplayableExportLeases(now = Date.now()) {
        for (const [leaseId, lease] of this.replayableExportLeases.entries()) {
            if (!lease || lease.expiresAt <= now || lease.released === true) {
                this.replayableExportLeases.delete(leaseId)
            }
        }
    }

    _isPrivilegedReplayableCallerAllowed(caller = {}, request = {}) {
        const transport = String(caller?.transport || request?.transport || '').trim().toLowerCase()
        const runtimeId = this._getRuntimeId()
        if (transport === 'service-worker') {
            return caller?.extensionOwned === true
                && caller?.senderUrl === PRIVILEGED_SERVICE_WORKER_URL
                && (!runtimeId || !caller?.senderId || caller.senderId === runtimeId)
        }
        if (transport === 'extension-page') {
            if (caller?.extensionOwned !== true) return false
            if (runtimeId && caller?.senderId !== runtimeId) return false
            const senderUrl = toNonEmptyString(caller?.senderUrl)
            if (!senderUrl) return false
            try {
                const parsed = new URL(senderUrl)
                if (parsed.protocol !== 'chrome-extension:' && parsed.protocol !== 'moz-extension:') return false
                if (runtimeId && parsed.hostname !== runtimeId) return false
                return parsed.pathname === '/ptk/automation/export.html'
                    && parsed.search === ''
                    && parsed.hash === ''
            } catch (_) {
                return false
            }
        }
        return false
    }

    async _validatePrivilegedReplayableRequest(request = {}, caller = {}, { requireLease = false } = {}) {
        const requestId = request?.requestId || null
        const transport = String(request?.transport || caller?.transport || '').trim().toLowerCase()
        if (!this._isPrivilegedReplayableCallerAllowed({ ...caller, transport }, request)) {
            return { ok: false, error: REPLAYABLE_EXPORT_REQUIRED_ERROR, requestId }
        }

        if (normalizeExportMode(request?.exportMode, '') !== REPLAYABLE_EXPORT_MODE
            || request?.includeSecrets !== true
            || request?.sensitive !== true) {
            return { ok: false, error: 'invalid_replayable_export_request', requestId }
        }

        if (!toNonEmptyString(request?.sessionId)) {
            return { ok: false, error: 'session_id_required', requestId }
        }
        if (!Number.isInteger(Number(request?.originalScanTabId))) {
            return { ok: false, error: 'original_scan_tab_required', requestId }
        }

        const resolution = this._resolveSessionForRequest({
            sessionId: request.sessionId,
            tabId: Number(request.originalScanTabId),
            strictCurrentTab: true,
            allowActive: false,
            allowCompleted: true,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }

        const session = resolution.session
        this._finalizeStoppedSessionIfExportReady(session, 'privileged_replayable_export')
        if (session.status !== 'completed') {
            return {
                ok: false,
                error: 'session_not_completed',
                hint: 'Call end_session() before replayable export.',
                requestId,
                sessionLookup: resolution.sessionLookup
            }
        }
        if (Number(session.tabId) !== Number(request.originalScanTabId)) {
            return { ok: false, error: 'session_belongs_to_another_tab', requestId, sessionLookup: resolution.sessionLookup }
        }

        let lease = null
        if (requireLease) {
            this._cleanupReplayableExportLeases()
            lease = this.replayableExportLeases.get(String(request?.leaseId || '')) || null
            if (!lease) {
                return { ok: false, error: 'replayable_export_lease_not_found', requestId, sessionLookup: resolution.sessionLookup }
            }
            if (lease.sessionId !== session.id
                || Number(lease.originalScanTabId) !== Number(session.tabId)
                || lease.transport !== transport
                || (request?.sdkRunId && lease.sdkRunId !== request.sdkRunId)) {
                return { ok: false, error: 'replayable_export_lease_mismatch', requestId, sessionLookup: resolution.sessionLookup }
            }
        }

        return {
            ok: true,
            requestId,
            transport,
            session,
            sessionLookup: resolution.sessionLookup,
            lease
        }
    }

    _validateReplayableNonce({ nonce = null, nonceHash = null, sdkRunId = null } = {}) {
        const normalizedNonce = toNonEmptyString(nonce)
        const normalizedNonceHash = toNonEmptyString(nonceHash)
        if (!normalizedNonce && !normalizedNonceHash) return false
        for (const lease of this.replayableExportLeases.values()) {
            if (!lease || lease.released === true || lease.expiresAt <= Date.now()) continue
            if (sdkRunId && lease.sdkRunId && lease.sdkRunId !== sdkRunId) continue
            if (normalizedNonceHash && lease.nonceHash === normalizedNonceHash) return false
        }
        return true
    }

    _replayableExportOwner(session, lease, engine) {
        return {
            sessionId: session?.id || null,
            tabId: Number.isInteger(session?.tabId) ? session.tabId : Number(session?.tabId),
            originalScanTabId: Number.isInteger(session?.tabId) ? session.tabId : Number(session?.tabId),
            frameId: Number.isInteger(session?.frameId) ? session.frameId : 0,
            topFrameId: 0,
            engine: String(engine || '').trim().toUpperCase(),
            exportMode: REPLAYABLE_EXPORT_MODE,
            owner: REPLAYABLE_EXPORT_OWNER,
            transport: lease?.transport || null,
            sdkRunId: lease?.sdkRunId || null,
            leaseId: lease?.leaseId || null,
            nonceHash: lease?.nonceHash || null
        }
    }

    async _buildPrivilegedReplayableChunkedExport(engine, session, lease, options = {}) {
        const exportModule = this._getEngineExportModule(engine)
        if (!exportModule?.msg_export_scan_result) {
            throw new Error('chunked_export_not_supported')
        }
        const owner = this._replayableExportOwner(session, lease, engine)
        const result = await exportModule.msg_export_scan_result({
            target: options?.target || 'sdk-replayable-export',
            fileName: options?.fileName || `PTK_${String(engine || 'scan').toUpperCase()}_replayable_scan.json`,
            includeSecrets: true,
            owner
        })
        if (!result || result.success === false) {
            throw new Error(result?.error || 'chunked_export_failed')
        }
        if (result.exportMode !== 'chunked') {
            throw new Error('chunked_export_not_available')
        }
        return {
            engine,
            exportMode: REPLAYABLE_EXPORT_MODE,
            sensitive: true,
            secretsIncluded: true,
            replayableRequests: true,
            sessionId: session?.id || null,
            originalScanTabId: Number(session?.tabId),
            leaseId: lease.leaseId,
            exportId: result.exportId,
            fileName: result.fileName,
            size: result.size,
            chunkSize: result.chunkSize,
            chunkCount: result.chunkCount,
            contentType: result.contentType,
            compression: result.compression,
            expiresAt: result.expiresAt,
            owner: REPLAYABLE_EXPORT_OWNER,
            transport: lease.transport,
            sdkRunId: lease.sdkRunId || null,
            privacy: {
                exportMode: REPLAYABLE_EXPORT_MODE,
                secretsIncluded: true,
                replayableRequests: true,
                sensitiveArtifact: true
            }
        }
    }

    async ptk_privileged_replayable_export(request = {}, caller = {}) {
        const requestId = request?.requestId || null
        if (this.app?.ready && typeof this.app.ready.then === 'function') {
            await this.app.ready
        }
        this._cleanupReplayableExportLeases()
        const nonceHash = toNonEmptyString(request?.nonceHash) || await sha256Hex(request?.nonce)
        if (!this._validateReplayableNonce({
            nonce: request?.nonce,
            nonceHash,
            sdkRunId: request?.sdkRunId || null
        })) {
            return { ok: false, error: 'replayable_export_nonce_reused_or_missing', requestId }
        }
        const validation = await this._validatePrivilegedReplayableRequest({
            ...request,
            nonceHash
        }, caller)
        if (!validation.ok) return validation

        const session = validation.session
        const requestedEngine = String(request?.engine || 'ALL').trim().toUpperCase()
        const validEngines = ['DAST', 'IAST', 'SAST', 'SCA', 'ALL']
        if (!validEngines.includes(requestedEngine)) {
            return { ok: false, error: 'invalid_engine', requestId, sessionLookup: validation.sessionLookup }
        }
        const enginesToExport = requestedEngine === 'ALL' ? session.engines : [requestedEngine]
        session.scanIds = session.scanIds && typeof session.scanIds === 'object' ? session.scanIds : {}
        const lease = {
            leaseId: makeRandomToken('replayable_lease'),
            sessionId: session.id,
            originalScanTabId: Number(session.tabId),
            engine: requestedEngine,
            transport: validation.transport,
            sdk: toNonEmptyString(request?.sdk) || null,
            sdkRunId: toNonEmptyString(request?.sdkRunId) || makeRandomToken('sdk_run'),
            nonceHash,
            createdAt: Date.now(),
            expiresAt: Date.now() + REPLAYABLE_EXPORT_TTL_MS,
            released: false,
            exports: new Map()
        }

        const warnings = []
        const scans = []
        for (const engine of enginesToExport) {
            let scanId = session.scanIds?.[engine] || null
            if (!scanId) {
                scanId = resultsRegistry.findScanIdForEngine(engine, {
                    tabId: session.tabId,
                    host: session.host
                })
                if (scanId) session.scanIds[engine] = scanId
            }
            if (!scanId) {
                warnings.push(`engine_result_missing:${engine}`)
                continue
            }
            try {
                const exported = await this._buildPrivilegedReplayableChunkedExport(engine, session, lease, request)
                if (Number(exported.chunkCount) > REPLAYABLE_EXPORT_MAX_CHUNKS) {
                    warnings.push(`export_too_many_chunks:${engine}`)
                    continue
                }
                lease.exports.set(engine, {
                    exportId: exported.exportId,
                    chunkCount: exported.chunkCount
                })
                scans.push(exported)
            } catch (err) {
                warnings.push(`export_failed:${engine}:${err?.message || String(err)}`)
            }
        }

        if (!scans.length) {
            return { ok: false, error: 'no_exportable_results', warnings, requestId, sessionLookup: validation.sessionLookup }
        }
        this.replayableExportLeases.set(lease.leaseId, lease)
        return {
            ok: true,
            requestId,
            exportMode: REPLAYABLE_EXPORT_MODE,
            sensitive: true,
            secretsIncluded: true,
            replayableRequests: true,
            sensitiveArtifact: true,
            leaseId: lease.leaseId,
            sessionId: session.id,
            originalScanTabId: Number(session.tabId),
            transport: lease.transport,
            sdkRunId: lease.sdkRunId,
            expiresAt: lease.expiresAt,
            scans,
            warnings,
            sessionLookup: validation.sessionLookup,
            privacy: {
                exportMode: REPLAYABLE_EXPORT_MODE,
                secretsIncluded: true,
                replayableRequests: true,
                sensitiveArtifact: true
            }
        }
    }

    async ptk_privileged_replayable_export_chunk(request = {}, caller = {}) {
        const requestId = request?.requestId || null
        const validation = await this._validatePrivilegedReplayableRequest(request, caller, { requireLease: true })
        if (!validation.ok) return validation

        const engine = String(request?.engine || '').trim().toUpperCase()
        if (!engine) return { ok: false, error: 'engine_required', requestId }
        const leaseEntry = validation.lease.exports.get(engine)
        if (!leaseEntry || leaseEntry.exportId !== request?.exportId) {
            return { ok: false, error: 'replayable_export_lease_mismatch', requestId }
        }
        const exportModule = this._getEngineExportModule(engine)
        if (!exportModule?.msg_export_scan_chunk) {
            return { ok: false, error: 'chunked_export_not_supported', requestId, engine }
        }
        const owner = this._replayableExportOwner(validation.session, validation.lease, engine)
        try {
            const result = await exportModule.msg_export_scan_chunk({
                exportId: request.exportId,
                index: request.index,
                owner
            })
            if (!result || result.success === false) {
                return { ok: false, error: result?.error || 'chunk_read_failed', requestId, engine }
            }
            return {
                ok: true,
                requestId,
                engine,
                exportMode: REPLAYABLE_EXPORT_MODE,
                sensitive: true,
                exportId: result.exportId,
                index: result.index,
                chunkCount: result.chunkCount,
                chunkBase64: bytesToBase64(result.chunk)
            }
        } catch (err) {
            return { ok: false, error: err?.message || 'chunk_read_failed', requestId, engine }
        }
    }

    async ptk_privileged_replayable_export_release(request = {}, caller = {}) {
        const requestId = request?.requestId || null
        const validation = await this._validatePrivilegedReplayableRequest(request, caller, { requireLease: true })
        if (!validation.ok) return validation

        const requestedEngine = String(request?.engine || 'ALL').trim().toUpperCase()
        const engines = requestedEngine === 'ALL'
            ? Array.from(validation.lease.exports.keys())
            : [requestedEngine]
        const released = {}
        for (const engine of engines) {
            const leaseEntry = validation.lease.exports.get(engine)
            if (!leaseEntry) {
                released[engine] = false
                continue
            }
            const exportModule = this._getEngineExportModule(engine)
            const owner = this._replayableExportOwner(validation.session, validation.lease, engine)
            try {
                const result = await exportModule?.msg_release_export_scan?.({
                    exportId: leaseEntry.exportId,
                    owner
                })
                released[engine] = result?.success === true
            } catch (_) {
                released[engine] = false
            }
            validation.lease.exports.delete(engine)
        }
        if (validation.lease.exports.size === 0) {
            validation.lease.released = true
            this.replayableExportLeases.delete(validation.lease.leaseId)
        }
        return {
            ok: Object.values(released).some(Boolean),
            requestId,
            leaseId: validation.lease.leaseId,
            released
        }
    }

    async msg_export_scan(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id
        const requestedMode = String(options?.exportMode || PAGE_EXPORT_MODE).trim().toLowerCase()

        if (options?.includeSecrets === true || requestedMode === 'replayable') {
            return this._rejectReplayablePageExport(requestId)
        }

        const exportOptions = {
            ...options,
            includeSecrets: false,
            exportMode: PAGE_EXPORT_MODE,
            sessionScope: STRICT_CURRENT_TAB_SESSION_SCOPE
        }
        const strictCurrentTab = true
        const resolution = this._resolveSessionForRequest({
            sessionId: exportOptions.sessionId,
            tabId,
            strictCurrentTab,
            allowActive: true,
            allowCompleted: true,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }
        const session = resolution.session
        if (!this._isAuthorizedSessionFrame(session, sender)) {
            return {
                ok: false,
                error: 'session_belongs_to_another_frame',
                requestId,
                sessionLookup: resolution.sessionLookup
            }
        }
        this._finalizeActiveSessionIfExportReady(session, 'export_scan')
        this._finalizeStoppedSessionIfExportReady(session, 'export_scan')
        if (session.status !== 'completed') {
            return {
                ok: false,
                error: 'session_not_completed',
                hint: 'Call end_session() before export_scan_payload()',
                requestId,
                sessionLookup: resolution.sessionLookup
            }
        }

        const requestedEngine = (exportOptions.engine || 'ALL').toUpperCase().trim()
        const validEngines = ['DAST', 'IAST', 'SAST', 'SCA', 'ALL']
        if (!validEngines.includes(requestedEngine)) {
            return { ok: false, error: 'invalid_engine', requestId, sessionLookup: resolution.sessionLookup }
        }

        const enginesToExport = requestedEngine === 'ALL'
            ? session.engines
            : [requestedEngine]

        const warnings = []
        const exports = []
        const allowChunked = options.allowChunked !== false

        for (const engine of enginesToExport) {
            let scanId = session.scanIds[engine]
            if (!scanId) {
                scanId = resultsRegistry.findScanIdForEngine(engine, {
                    tabId: session.tabId,
                    host: session.host
                })
                if (scanId) {
                    session.scanIds[engine] = scanId
                }
            }

            if (!scanId) {
                warnings.push(`engine_result_missing:${engine}`)
                continue
            }

            try {
                let scanExport = null
                try {
                    scanExport = await this._buildEngineExport(engine, scanId, session, exportOptions)
                } catch (err) {
                    if (!allowChunked || String(err?.message || '') !== 'export_too_large') {
                        throw err
                    }
                    scanExport = await this._buildEngineChunkedExport(engine, session, {
                        ...exportOptions,
                        owner: this._pageExportOwner(session, sender, engine, PAGE_EXPORT_MODE)
                    })
                }
                exports.push(scanExport)
            } catch (err) {
                warnings.push(`export_failed:${engine}:${err.message}`)
            }
        }

        if (!exports.length) {
            return { ok: false, error: 'no_exportable_results', warnings, requestId, sessionLookup: resolution.sessionLookup }
        }

        return {
            ok: true,
            scans: exports,
            truncatedAny: exports.some(e => e.truncated),
            warnings,
            requestId,
            sessionLookup: resolution.sessionLookup
        }
    }

    async msg_export_scan_chunk(message, sender) {
        const { requestId, options = {} } = message
        const engine = String(options.engine || '').trim().toUpperCase()
        if (!engine) {
            return { ok: false, error: 'engine_required', requestId }
        }
        if (String(options?.exportMode || '').toLowerCase() === 'replayable' || options?.includeSecrets === true) {
            return this._rejectReplayablePageExport(requestId)
        }
        const resolution = this._resolveSessionForRequest({
            sessionId: options.sessionId,
            tabId: sender?.tab?.id,
            strictCurrentTab: true,
            allowActive: false,
            allowCompleted: true,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }
        if (!this._isAuthorizedSessionFrame(resolution.session, sender)) {
            return {
                ok: false,
                error: 'session_belongs_to_another_frame',
                requestId,
                sessionLookup: resolution.sessionLookup
            }
        }
        const owner = this._pageExportOwner(resolution.session, sender, engine, PAGE_EXPORT_MODE)
        const exportModule = this._getEngineExportModule(engine)
        if (!exportModule?.msg_export_scan_chunk) {
            return { ok: false, error: 'chunked_export_not_supported', requestId, engine }
        }
        try {
            const result = await exportModule.msg_export_scan_chunk({
                exportId: options.exportId,
                index: options.index,
                owner
            })
            return {
                ...(result || {}),
                ok: result?.success !== false,
                requestId
            }
        } catch (err) {
            return { ok: false, error: err?.message || 'chunk_read_failed', requestId, engine }
        }
    }

    async msg_release_export_scan(message, sender) {
        const { requestId, options = {} } = message
        const engine = String(options.engine || '').trim().toUpperCase()
        if (!engine) {
            return { ok: false, error: 'engine_required', requestId }
        }
        if (String(options?.exportMode || '').toLowerCase() === 'replayable' || options?.includeSecrets === true) {
            return this._rejectReplayablePageExport(requestId)
        }
        const resolution = this._resolveSessionForRequest({
            sessionId: options.sessionId,
            tabId: sender?.tab?.id,
            strictCurrentTab: true,
            allowActive: false,
            allowCompleted: true,
            allowGlobalCompleted: false
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId, sessionLookup: resolution.sessionLookup }
        }
        if (!this._isAuthorizedSessionFrame(resolution.session, sender)) {
            return {
                ok: false,
                error: 'session_belongs_to_another_frame',
                requestId,
                sessionLookup: resolution.sessionLookup
            }
        }
        const owner = this._pageExportOwner(resolution.session, sender, engine, PAGE_EXPORT_MODE)
        const exportModule = this._getEngineExportModule(engine)
        if (!exportModule?.msg_release_export_scan) {
            return { ok: false, error: 'chunked_export_not_supported', requestId, engine }
        }
        try {
            const result = await exportModule.msg_release_export_scan({
                exportId: options.exportId,
                owner
            })
            return {
                ...(result || {}),
                ok: result?.success !== false,
                requestId
            }
        } catch (err) {
            return { ok: false, error: err?.message || 'chunk_release_failed', requestId, engine }
        }
    }

    async msg_get_engine_snapshot(message, sender) {
        const { requestId, options = {} } = message
        const tabId = sender?.tab?.id

        const resolution = this._resolveSessionForRequest({
            sessionId: options.sessionId,
            tabId,
            strictCurrentTab: false,
            allowActive: false,
            allowCompleted: true,
            allowGlobalCompleted: true
        })
        if (!resolution.ok) {
            return { ok: false, error: resolution.error, requestId }
        }
        const session = resolution.session

        const engine = String(options.engine || '').trim().toUpperCase()
        if (!engine) {
            return { ok: false, error: 'engine_required', requestId }
        }

        let scanId = session.scanIds?.[engine] || null
        if (!scanId) {
            scanId = resultsRegistry.findScanIdForEngine(engine, {
                tabId: session.tabId,
                host: session.host
            })
            if (scanId) {
                session.scanIds[engine] = scanId
            }
        }

        if (!scanId) {
            return { ok: false, error: 'scan_id_not_found', requestId, engine }
        }

        let scanResult = this._getEngineScanResult(engine)
        if (scanResult?.scanId !== scanId) {
            scanResult = resultsRegistry.get(engine, scanId)
        }
        if (!scanResult || typeof scanResult !== 'object') {
            return { ok: false, error: 'scan_result_not_found', requestId, engine, scanId }
        }

        const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
        const groups = Array.isArray(scanResult.groups) ? scanResult.groups : []
        const requests = Array.isArray(scanResult.requests) ? scanResult.requests : []
        const runtimeEvents = Array.isArray(scanResult.runtimeEvents) ? scanResult.runtimeEvents : []
        const stats = scanResult.stats && typeof scanResult.stats === 'object'
            ? {
                findingsCount: Number(scanResult.stats.findingsCount || findings.length || 0),
                bySeverity: Object.assign({ critical: 0, high: 0, medium: 0, low: 0, info: 0 }, scanResult.stats.bySeverity || {})
            }
            : this._extractStats(scanResult)
        const perfKey = engine.toLowerCase()

        return {
            ok: true,
            requestId,
            engine,
            scanId,
            sessionId: session.id,
            status: session.status,
            startedAt: scanResult.startedAt || session.startedAt || null,
            finishedAt: scanResult.finishedAt || scanResult.finished || session.finishedAt || null,
            stats,
            groupsCount: groups.length,
            requestsCount: requests.length,
            runtimeEventsCount: runtimeEvents.length,
            performance: scanResult.performance?.[perfKey] || null
        }
    }

    // === Engine Coordination ===

    // Pass sessionId to adapters for DAST automation session
    async _startEngines(session, engineNames = null) {
        const effectiveEngines = Array.isArray(engineNames) && engineNames.length
            ? engineNames
            : session?.engines
        const { id: sessionId, tabId, host } = session
        debugAutomationLog('[PTK Automation] _startEngines', { sessionId, tabId, host, engines: effectiveEngines })

        if (!this.engines) {
            console.error('[PTK Automation] Engine adapters not initialized (this.engines is null)')
            throw new Error('engine_adapters_not_initialized')
        }

        for (const engineName of Array.isArray(effectiveEngines) ? effectiveEngines : []) {
            await this._startEngine(session, engineName)
        }
    }

    // Use adapter.stop() which waits for idle
    async _stopEngines(session, timeoutMs = 180000, options = {}) {
        const stats = { findingsCount: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }

        for (const engineName of session.engines) {
            const adapter = this.engines.getAdapter(engineName)
            if (!adapter) {
                session.engineStates[engineName] = {
                    status: 'error',
                    error: 'adapter_not_found',
                    completionStatus: 'engine_incomplete',
                    drained: false
                }
                stats.completionStatus = 'engine_incomplete'
                stats.incompleteEngines = Array.isArray(stats.incompleteEngines) ? stats.incompleteEngines : []
                stats.incompleteEngines.push(engineName)
                continue
            }

            try {
                const engineStats = await adapter.stop(session.id, timeoutMs, options)
                const resolvedStats = this._resolveStoppedEngineStats(engineName, session, engineStats)
                this._mergeStats(stats, resolvedStats)
                const incomplete = engineStats?.completionStatus === 'engine_incomplete'
                session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                    status: incomplete ? 'cancelled' : 'stopped',
                    completionStatus: engineStats?.completionStatus || (incomplete ? 'engine_incomplete' : 'completed'),
                    drained: engineStats?.drained !== false
                })
                if (incomplete) stats.completionStatus = 'engine_incomplete'
            } catch (err) {
                session.engineStates[engineName] = {
                    status: 'error',
                    error: err.message,
                    completionStatus: 'engine_incomplete',
                    drained: false
                }
                stats.completionStatus = 'engine_incomplete'
                stats.incompleteEngines = Array.isArray(stats.incompleteEngines) ? stats.incompleteEngines : []
                stats.incompleteEngines.push(engineName)
            }
        }

        return stats
    }

    async _stopEngineWithHardTimeout(adapter, session, engineName, timeoutMs, options = {}) {
        const zapCloseRequest = options?.zapCloseRequest === true || options?.source === 'zap_browser_close'
        const boundedTimeoutMs = zapCloseRequest
            ? Math.min(this._normalizeStopTimeoutMs(timeoutMs), ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS)
            : this._normalizeStopTimeoutMs(timeoutMs)
        let timer = null
        const timeoutResult = new Promise(resolve => {
            timer = setTimeout(() => {
                resolve({
                    __ptkStopTimedOut: true,
                    findingsCount: 0,
                    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                    completionStatus: 'engine_incomplete',
                    drained: false
                })
            }, boundedTimeoutMs)
        })
        try {
            const result = await Promise.race([
                Promise.resolve(adapter.stop(session.id, boundedTimeoutMs, options)),
                timeoutResult
            ])
            return result
        } finally {
            if (timer) clearTimeout(timer)
        }
    }

    /**
     * Stop engines asynchronously (fire-and-forget with completion tracking)
     * Updates engineStates as each engine stops
     */
    async _stopEnginesAsync(session, timeoutMs = 180000, options = {}) {
        const stats = this._createEmptyStats()
        stats.completionStatus = 'completed'
        stats.incompleteEngines = []

        // Mark all engines as stopping
        for (const engineName of session.engines) {
            session.engineStates[engineName] = session.engineStates[engineName] || {}
            session.engineStates[engineName].status = 'stopping'
        }

        // Stop each engine with individual error handling
        const stopPromises = session.engines.map(async (engineName) => {
            const adapter = this.engines?.getAdapter(engineName)
            if (!adapter) {
                session.engineStates[engineName].status = 'error'
                session.engineStates[engineName].error = 'adapter_not_found'
                session.engineStates[engineName].completionStatus = 'engine_incomplete'
                session.engineStates[engineName].drained = false
                stats.completionStatus = 'engine_incomplete'
                stats.incompleteEngines.push(engineName)
                return
            }

            try {
                const engineStats = await this._stopEngineWithHardTimeout(adapter, session, engineName, timeoutMs, options)
                const resolvedStats = this._resolveStoppedEngineStats(engineName, session, engineStats)
                const timedOut = engineStats?.__ptkStopTimedOut === true
                const incomplete = timedOut || engineStats?.completionStatus === 'engine_incomplete'
                session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                    status: incomplete ? 'cancelled' : 'stopped',
                    completionStatus: incomplete ? 'engine_incomplete' : (engineStats?.completionStatus || 'completed'),
                    drained: engineStats?.drained !== false && !timedOut,
                    stopTimedOut: timedOut || undefined
                })
                if (incomplete) {
                    stats.completionStatus = 'engine_incomplete'
                    stats.incompleteEngines.push(engineName)
                }

                // Aggregate stats
                stats.findingsCount += resolvedStats?.findingsCount || 0
                for (const sev of Object.keys(stats.bySeverity)) {
                    stats.bySeverity[sev] += resolvedStats?.bySeverity?.[sev] || 0
                }
            } catch (err) {
                console.error('[PTK Automation] Engine stop failed', engineName, err)
                session.engineStates[engineName].status = 'error'
                session.engineStates[engineName].error = err.message
                session.engineStates[engineName].completionStatus = 'engine_incomplete'
                session.engineStates[engineName].drained = false
                stats.completionStatus = 'engine_incomplete'
                stats.incompleteEngines.push(engineName)
            }
        })

        await Promise.all(stopPromises)
        return stats
    }

    _createEmptyStats() {
        return {
            findingsCount: 0,
            bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        }
    }

    _normalizeStopTimeoutMs(value) {
        const num = Number(value)
        if (!Number.isFinite(num) || num <= 0) return 180000
        return Math.max(250, Math.min(180000, Math.floor(num)))
    }

    _extractStatsFromScanResult(scanResult) {
        const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        const stats = this._createEmptyStats()
        for (const finding of findings) {
            stats.findingsCount += 1
            const sev = String(finding?.severity || finding?.effectiveSeverity || 'info').toLowerCase()
            if (Object.prototype.hasOwnProperty.call(stats.bySeverity, sev)) {
                stats.bySeverity[sev] += 1
            } else {
                stats.bySeverity.info += 1
            }
        }
        return stats
    }

    _resolveStoppedEngineStats(engineName, session, initialStats = null) {
        const best = {
            findingsCount: Number(initialStats?.findingsCount || 0),
            bySeverity: Object.assign(
                { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                initialStats?.bySeverity || {}
            )
        }

        const maybeAdopt = (scanResult) => {
            if (!scanResult || typeof scanResult !== 'object') return
            const derived = this._extractStatsFromScanResult(scanResult)
            if (Number(derived?.findingsCount || 0) > Number(best.findingsCount || 0)) {
                best.findingsCount = Number(derived.findingsCount || 0)
                best.bySeverity = Object.assign(
                    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                    derived.bySeverity || {}
                )
            }
        }

        maybeAdopt(this._getEngineScanResult(engineName))

        const adapter = this.engines?.getAdapter(engineName) || null
        try {
            const adapterStats = adapter?.getStats?.()
            if (Number(adapterStats?.findingsCount || 0) > Number(best.findingsCount || 0)) {
                best.findingsCount = Number(adapterStats.findingsCount || 0)
                best.bySeverity = Object.assign(
                    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                    adapterStats.bySeverity || {}
                )
            }
        } catch (err) {
            debugAutomationLog('[PTK Automation] Failed to collect stopped engine stats from adapter', {
                engineName,
                error: err?.message || String(err)
            })
        }
        let scanId = session?.scanIds?.[engineName] || adapter?.getScanId?.() || null
        if (!scanId && session) {
            scanId = resultsRegistry.findScanIdForEngine(engineName, {
                tabId: session.tabId,
                host: session.host
            })
        }
        if (scanId) {
            if (session?.scanIds) {
                session.scanIds[engineName] = scanId
            }
            maybeAdopt(resultsRegistry.get(engineName, scanId))
        }

        return best
    }

    /**
     * Finalize session after engines stopped
     * Called from both sync and async stop paths
     */
    _finalizeSession(session, stats) {
        if (session?.zapCloseTerminalFallbackTimer) {
            clearTimeout(session.zapCloseTerminalFallbackTimer)
            delete session.zapCloseTerminalFallbackTimer
        }
        // Final scanId capture
        this._finalScanIdCapture(session)

        const completionStatus = stats?.completionStatus === 'engine_incomplete'
            || stats?.completionStatus === 'publisher_incomplete'
            || (Array.isArray(stats?.incompleteEngines) && stats.incompleteEngines.length > 0)
            ? (stats?.completionStatus === 'publisher_incomplete' ? 'publisher_incomplete' : 'engine_incomplete')
            : 'completed'
        session.finishedAt = new Date().toISOString()
        session.status = completionStatus === 'completed' ? 'completed' : 'cancelled'
        session.completionStatus = completionStatus
        session.releaseStatus = completionStatus === 'completed' ? 'clean' : 'incomplete'

        // Store summary for get-session-progress to return
        session.summary = {
            status: completionStatus,
            releaseStatus: session.releaseStatus,
            stats: {
                findingsCount: stats.findingsCount,
                bySeverity: stats.bySeverity
            }
        }
        if (Array.isArray(stats?.incompleteEngines) && stats.incompleteEngines.length > 0) {
            session.summary.incompleteEngines = stats.incompleteEngines
        }

        // Update tracking for export
        this.lastCompletedSessionByTabId.set(session.tabId, session.id)
        this.lastCompletedSessionGlobal = session.id

        // NOW clear active mapping (session is truly done)
        if (this.activeSessionByTabId.get(session.tabId) === session.id) {
            this.activeSessionByTabId.delete(session.tabId)
        }

        // Enforce retention
        this._enforceSessionRetention()

        debugAutomationLog('[PTK Automation] Session finalized', session.id)
    }

    _scheduleZapCloseTerminalFallback(session, { zapid = null, timeoutMs = ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS } = {}) {
        if (!session || session.status === 'completed' || session.status === 'error') return
        if (session.zapCloseTerminalFallbackTimer) {
            clearTimeout(session.zapCloseTerminalFallbackTimer)
        }

        const fallbackMs = Math.max(250, Math.min(
            ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS,
            this._normalizeStopTimeoutMs(timeoutMs)
        ))

        session.zapCloseTerminalFallbackTimer = setTimeout(() => {
            this._finalizeZapCloseSessionIncomplete(session, {
                reason: 'zap_close_stop_timeout',
                zapid
            })
        }, fallbackMs)
    }

    _postZapCloseTerminalProgress(session, { zapid = null } = {}) {
        if (!session?.id) return
        Promise.resolve()
            .then(() => this.zap?.postTerminalProgressForClose?.({
                sessionId: session.id,
                zapid
            }))
            .catch((err) => {
                debugAutomationLog('[PTK Automation] Failed to post ZAP close terminal progress', {
                    sessionId: session.id,
                    error: err?.message || String(err)
                })
            })
    }

    async _finalizeZapCloseSessionForTerminal(session, { zapid = null, reason = 'zap_browser_close_terminalized', timeoutMs = ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS } = {}) {
        if (!session || session.status === 'completed' || session.status === 'error') {
            if (session?.id) {
                await this.zap?.postTerminalProgressForClose?.({
                    sessionId: session.id,
                    zapid
                })
            }
            return false
        }
        if (!session.stopRequestedAt) {
            session.stopRequestedAt = new Date().toISOString()
        }

        if (session.zapCloseTerminalFallbackTimer) {
            clearTimeout(session.zapCloseTerminalFallbackTimer)
            delete session.zapCloseTerminalFallbackTimer
        }

        session.stopInProgress = false
        session.warnings = Array.isArray(session.warnings) ? session.warnings : []
        session.warnings.push({
            code: reason,
            at: new Date().toISOString()
        })

        const stats = await this._stopEnginesAsync(session, timeoutMs, {
            source: 'zap_browser_close',
            zapCloseRequest: true
        })
        this._finalizeSession(session, stats)

        await this.zap?.postTerminalProgressForClose?.({
            sessionId: session.id,
            zapid
        })
        return true
    }

    _stopZapEnginesBestEffortAfterTerminal(session, { timeoutMs = ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS } = {}) {
        if (!session || !Array.isArray(session.engines) || !session.engines.length) return
        const sessionId = session.id
        const engineNames = Array.from(session.engines)
        const boundedTimeoutMs = Math.max(250, Math.min(5000, this._normalizeStopTimeoutMs(timeoutMs)))
        setTimeout(() => {
            for (const engineName of engineNames) {
                const adapter = this.engines?.getAdapter?.(engineName)
                if (!adapter || typeof adapter.stop !== 'function') continue
                Promise.resolve()
                    .then(() => adapter.stop(sessionId, boundedTimeoutMs, {
                        source: 'zap_browser_close',
                        zapCloseRequest: true,
                        terminalAlreadyPosted: true
                    }))
                    .catch((err) => {
                        debugAutomationLog('[PTK Automation] Best-effort ZAP engine stop after terminal failed', {
                            sessionId,
                            engineName,
                            error: err?.message || String(err)
                        })
                    })
            }
        }, 0)
    }

    async _completeZapCloseFallbackAfterGrace(session, { zapid = null, timeoutMs = ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS } = {}) {
        if (!session || session.status === 'completed' || session.status === 'error') return false
        const deadlineMs = Date.now() + Math.max(250, Math.min(
            ZAP_CLOSE_ENGINE_STOP_TIMEOUT_MS,
            this._normalizeStopTimeoutMs(timeoutMs)
        ))
        while (Date.now() < deadlineMs) {
            if (!session || session.status === 'completed' || session.status === 'error') return false
            await sleep(ZAP_CLOSE_TERMINAL_FALLBACK_POLL_MS)
        }
        if (!session || session.status === 'completed' || session.status === 'error') return false
        return this._finalizeZapCloseSessionIncomplete(session, {
            reason: 'zap_close_stop_bounded',
            zapid
        })
    }

    async _finalizeZapCloseSessionIncomplete(session, { reason = 'zap_close_stop_timeout', zapid = null } = {}) {
        if (!session || session.status === 'completed' || session.status === 'error') return false
        if (!session.stopRequestedAt) return false

        if (session.zapCloseTerminalFallbackTimer) {
            clearTimeout(session.zapCloseTerminalFallbackTimer)
            delete session.zapCloseTerminalFallbackTimer
        }

        const stats = this._collectCurrentStats(session)
        stats.completionStatus = 'engine_incomplete'
        stats.incompleteEngines = []

        const engines = Array.isArray(session.engines) ? session.engines : []
        for (const engineName of engines) {
            const engineUpper = String(engineName || '').toUpperCase()
            session.engineStates[engineUpper] = session.engineStates[engineUpper] || {}
            const state = String(session.engineStates[engineUpper].status || '').toLowerCase()
            if (state !== 'stopped' && state !== 'completed' && state !== 'error') {
                session.engineStates[engineUpper] = Object.assign({}, session.engineStates[engineUpper], {
                    status: 'cancelled',
                    completionStatus: 'engine_incomplete',
                    drained: false,
                    stopTimedOut: true
                })
                stats.incompleteEngines.push(engineUpper)
            }
        }

        session.stopInProgress = false
        session.warnings = Array.isArray(session.warnings) ? session.warnings : []
        session.warnings.push({
            code: reason,
            at: new Date().toISOString()
        })
        this._finalizeSession(session, stats)

        try {
            await this.zap?.postTerminalProgressForClose?.({
                sessionId: session.id,
                zapid
            })
        } catch (err) {
            debugAutomationLog('[PTK Automation] Failed to post ZAP-close fallback terminal progress', {
                sessionId: session.id,
                error: err?.message || String(err)
            })
        }

        return true
    }

    _finalScanIdCapture(session) {
        for (const engineName of session.engines) {
            if (session.scanIds[engineName]) continue

            const adapter = this.engines?.getAdapter(engineName)
            const scanId = adapter?.getScanId?.() || null

            if (scanId) {
                session.scanIds[engineName] = scanId
                debugAutomationLog('[PTK Automation] Final capture scanId for', engineName, scanId)
                continue
            }

            const fallbackId = resultsRegistry.findScanIdForEngine(engineName, {
                tabId: session.tabId,
                host: session.host
            })

            if (fallbackId) {
                session.scanIds[engineName] = fallbackId
                debugAutomationLog('[PTK Automation] Registry fallback scanId for', engineName, fallbackId)
            } else {
                session.engineStates[engineName] = session.engineStates[engineName] || {}
                session.engineStates[engineName].warning = 'scan_id_not_available'
            }
        }
    }

    async _buildEngineExport(engine, scanId, session, options = {}) {
        const {
            includeBodies = true,
            includeEvidence = true,
            includeSecrets = false,
            maxExportBytes = 25 * 1024 * 1024
        } = options
        if (includeSecrets === true || String(options?.exportMode || '').toLowerCase() === 'replayable') {
            throw new Error(REPLAYABLE_EXPORT_REQUIRED_ERROR)
        }

        const scanResult = resultsRegistry.get(engine, scanId)
        if (!scanResult) {
            throw new Error(`scan_result_not_found:${engine}`)
        }

        let exported = buildExportScanResult(scanId, { scanResult, includeSecrets: includeSecrets === true })
        if (!exported) {
            throw new Error(`export_build_failed:${engine}`)
        }

        exported.meta = exported.meta || {}
        exported.meta.automation = {
            sessionId: session.id,
            testRunId: session.testRunId,
            project: session.project,
            policyCode: session.policyCode,
            startedAt: session.startedAt,
            finishedAt: session.finishedAt,
            durationMs: session.finishedAt && session.startedAt
                ? Date.parse(session.finishedAt) - Date.parse(session.startedAt)
                : null,
            ptkVersion: this.app?.version || 'unknown',
            schemaVersion: 1
        }
        exported.meta.privacy = exported.meta.privacy || {}
        exported.meta.privacy.secretsIncluded = includeSecrets === true
        exported.meta.privacy.exportMode = PAGE_EXPORT_MODE
        exported.meta.privacy.redactionEnforced = true
        if (includeSecrets === true) {
            exported.meta.privacy.replayableRequests = true
        }

        let bodiesStrippedByPolicy = false
        let evidenceStrippedByPolicy = false

        if (includeBodies === false) {
            this._stripBodiesInPlace(exported)
            bodiesStrippedByPolicy = true
        }

        if (includeEvidence === false) {
            this._stripEvidenceInPlace(exported)
            evidenceStrippedByPolicy = true
        }

        if (bodiesStrippedByPolicy || evidenceStrippedByPolicy) {
            exported.meta.privacy = {
                ...(exported.meta.privacy || {}),
                bodiesIncluded: !bodiesStrippedByPolicy,
                evidenceIncluded: !evidenceStrippedByPolicy
            }
        }

        let estimatedBytes = this._estimateBytes(exported)
        let truncated = false
        const truncationMeta = { applied: false }

        if (estimatedBytes > maxExportBytes) {
            if (includeBodies === true) {
                this._stripBodiesInPlace(exported)
                truncationMeta.applied = true
                truncationMeta.bodiesStrippedForSize = true

                exported.meta.privacy = exported.meta.privacy || {}
                exported.meta.privacy.bodiesIncluded = false

                truncated = true
                estimatedBytes = this._estimateBytes(exported)
            }

            if (estimatedBytes > maxExportBytes) {
                const originalCount = exported.findings?.length || 0
                const { keptCount, droppedCount, reason } = this._truncateFindings(
                    exported,
                    maxExportBytes
                )

                truncationMeta.applied = true
                truncationMeta.findingsTruncated = true
                truncationMeta.findingsOriginal = originalCount
                truncationMeta.findingsReturned = keptCount
                truncationMeta.findingsDropped = droppedCount

                if (reason === 'base_payload_exceeds_limit') {
                    truncationMeta.reason = reason
                }

                truncated = true
                estimatedBytes = this._estimateBytes(exported)
            }

            if (estimatedBytes > maxExportBytes) {
                throw new Error('export_too_large')
            }
        }

        if (truncationMeta.applied) {
            exported.meta.truncation = truncationMeta
        }

        return {
            engine,
            scan: exported,
            estimatedBytes,
            truncated
        }
    }

    async _buildEngineChunkedExport(engine, session, options = {}) {
        if (options?.includeSecrets === true || String(options?.exportMode || '').toLowerCase() === 'replayable') {
            throw new Error(REPLAYABLE_EXPORT_REQUIRED_ERROR)
        }
        const exportModule = this._getEngineExportModule(engine)
        if (!exportModule?.msg_export_scan_result) {
            throw new Error('chunked_export_not_supported')
        }
        const result = await exportModule.msg_export_scan_result({
            target: options?.target || 'download',
            fileName: options?.fileName || `PTK_${String(engine || 'scan').toUpperCase()}_scan.json`,
            includeSecrets: options?.includeSecrets === true,
            owner: options?.owner || null
        })
        if (!result || result.success === false) {
            throw new Error(result?.error || 'chunked_export_failed')
        }
        if (result.exportMode !== 'chunked') {
            throw new Error('chunked_export_not_available')
        }
        return {
            engine,
            exportMode: 'chunked',
            sessionId: session?.id || null,
            tabId: session?.tabId ?? null,
            frameId: Number.isInteger(session?.frameId) ? session.frameId : 0,
            exportId: result.exportId,
            fileName: result.fileName,
            size: result.size,
            chunkSize: result.chunkSize,
            chunkCount: result.chunkCount,
            contentType: result.contentType,
            compression: result.compression,
            expiresAt: result.expiresAt,
            truncated: false,
            chunked: true,
            meta: {
                automation: {
                    sessionId: session?.id || null,
                    testRunId: session?.testRunId || null,
                    project: session?.project || null,
                    policyCode: session?.policyCode || null,
                    startedAt: session?.startedAt || null,
                    finishedAt: session?.finishedAt || null,
                    schemaVersion: 1
                }
            }
        }
    }

    _estimateBytes(obj) {
        const str = JSON.stringify(obj)
        if (typeof TextEncoder !== 'undefined') {
            return new TextEncoder().encode(str).length
        }
        return unescape(encodeURIComponent(str)).length
    }

    _stripBodiesInPlace(exported) {
        const strip = (httpMsg) => {
            if (!httpMsg) return
            if (httpMsg.body !== undefined) httpMsg.body = '[STRIPPED]'
            if (httpMsg.raw !== undefined) httpMsg.raw = '[STRIPPED]'
        }

        if (Array.isArray(exported.findings)) {
            for (const finding of exported.findings) {
                const dast = finding?.evidence?.dast
                if (!dast) continue
                strip(dast.request)
                strip(dast.response)
                strip(dast.original?.request)
                strip(dast.original?.response)
                strip(dast.attack?.request)
                strip(dast.attack?.response)
            }
        }

        if (Array.isArray(exported.requests)) {
            for (const req of exported.requests) {
                strip(req?.original?.request)
                strip(req?.original?.response)
            }
        }
    }

    _stripEvidenceInPlace(exported) {
        if (!Array.isArray(exported.findings)) return

        const stripValue = (val) => {
            if (val == null) return val
            if (Array.isArray(val)) return []
            if (typeof val === 'object') return {}
            return '[STRIPPED]'
        }

        for (const finding of exported.findings) {
            finding.evidenceStripped = true
            if (!finding.evidence) continue

            if (finding.evidence.dast) {
                const dast = finding.evidence.dast
                if (dast.proof != null) dast.proof = stripValue(dast.proof)
                if (dast.payload != null) dast.payload = stripValue(dast.payload)

                const stripHttp = (msg) => {
                    if (!msg) return
                    if (msg.body !== undefined) msg.body = '[STRIPPED]'
                    if (msg.raw !== undefined) msg.raw = '[STRIPPED]'
                }
                stripHttp(dast.request)
                stripHttp(dast.response)
                stripHttp(dast.original?.request)
                stripHttp(dast.original?.response)
                stripHttp(dast.attack?.request)
                stripHttp(dast.attack?.response)
            }

            if (finding.evidence.iast) {
                const iast = finding.evidence.iast
                if (iast.trace != null) iast.trace = stripValue(iast.trace)
                if (iast.stack != null) iast.stack = stripValue(iast.stack)
                if (iast.frames != null) iast.frames = stripValue(iast.frames)
                if (iast.matched != null) iast.matched = stripValue(iast.matched)
                if (iast.context) {
                    if (iast.context.html != null) iast.context.html = '[STRIPPED]'
                    if (iast.context.outerHTML != null) iast.context.outerHTML = '[STRIPPED]'
                    if (iast.context.elementOuterHTML != null) iast.context.elementOuterHTML = '[STRIPPED]'
                }
            }

            if (finding.evidence.sast) {
                const sast = finding.evidence.sast
                if (sast.codeSnippet != null) sast.codeSnippet = stripValue(sast.codeSnippet)
                if (sast.flow != null) sast.flow = stripValue(sast.flow)
                if (sast.trace != null) sast.trace = stripValue(sast.trace)
            }

            if (finding.evidence.sca) {
                const sca = finding.evidence.sca
                if (sca.summary != null) sca.summary = stripValue(sca.summary)
            }
        }
    }

    _truncateFindings(exported, maxBytes) {
        const findings = Array.isArray(exported.findings) ? [...exported.findings] : []
        if (!findings.length) return { keptCount: 0, droppedCount: 0 }

        const minViableExport = { ...exported, findings: [] }
        if (this._estimateBytes(minViableExport) > maxBytes) {
            exported.findings = []
            return { keptCount: 0, droppedCount: findings.length, reason: 'base_payload_exceeds_limit' }
        }

        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

        findings.sort((a, b) => {
            const sevA = severityOrder[(a.severity || a.effectiveSeverity || 'info').toLowerCase()] ?? 5
            const sevB = severityOrder[(b.severity || b.effectiveSeverity || 'info').toLowerCase()] ?? 5
            if (sevA !== sevB) return sevA - sevB

            const confA = a.confidence ?? a.effectiveConfidence ?? 0
            const confB = b.confidence ?? b.effectiveConfidence ?? 0
            if (confA !== confB) return confB - confA

            return (a.id || '').localeCompare(b.id || '')
        })

        const originalCount = findings.length

        let lo = 0
        let hi = findings.length
        while (lo < hi) {
            const mid = Math.ceil((lo + hi) / 2)
            exported.findings = findings.slice(0, mid)
            const bytes = this._estimateBytes(exported)
            if (bytes <= maxBytes) {
                lo = mid
            } else {
                hi = mid - 1
            }
        }

        exported.findings = findings.slice(0, lo)

        return {
            keptCount: lo,
            droppedCount: originalCount - lo
        }
    }

    _enforceSessionRetention() {
        const now = Date.now()
        const completedSessions = []

        for (const [id, session] of this.sessions) {
            if (session.status === 'completed' && session.finishedAt) {
                completedSessions.push({
                    id,
                    finishedAt: new Date(session.finishedAt).getTime()
                })
            }
        }

        completedSessions.sort((a, b) => a.finishedAt - b.finishedAt)

        for (const { id, finishedAt } of completedSessions) {
            if (now - finishedAt > this.SESSION_TTL_MS) {
                this._evictSession(id, 'ttl')
            }
        }

        const remaining = completedSessions.filter(s => this.sessions.has(s.id))
        while (remaining.length > this.MAX_COMPLETED_SESSIONS) {
            const oldest = remaining.shift()
            this._evictSession(oldest.id, 'max_completed_sessions')
        }
    }

    _evictSession(sessionId, reason = 'retention') {
        const session = this.sessions.get(sessionId)
        if (!session) return

        debugAutomationLog('[PTK Automation] Evicting session', sessionId)
        this._recordEvictedSession(session, reason)
        this.sessions.delete(sessionId)

        if (this.lastCompletedSessionGlobal === sessionId) {
            this.lastCompletedSessionGlobal = null
        }
        for (const [tabId, sid] of this.lastCompletedSessionByTabId) {
            if (sid === sessionId) {
                this.lastCompletedSessionByTabId.delete(tabId)
            }
        }
    }

    cleanupCompletedSessions({ maxAge = null, keepCount = null } = {}) {
        const now = Date.now()
        const completedSessions = []

        for (const [id, session] of this.sessions) {
            if (session.status === 'completed' && session.finishedAt) {
                const age = now - new Date(session.finishedAt).getTime()
                if (maxAge && age > maxAge) {
                    this._evictSession(id, 'cleanup_max_age')
                } else {
                    completedSessions.push({ id, finishedAt: new Date(session.finishedAt).getTime() })
                }
            }
        }

        if (keepCount !== null) {
            completedSessions.sort((a, b) => a.finishedAt - b.finishedAt)
            while (completedSessions.length > keepCount) {
                const oldest = completedSessions.shift()
                this._evictSession(oldest.id, 'cleanup_keep_count')
            }
        }
    }

    _recordEvictedSession(session, reason = 'retention') {
        if (!session || !session.id) return
        this.evictedSessions.set(session.id, {
            sessionId: session.id,
            tabId: session.tabId ?? null,
            sessionStatus: session.status || null,
            sessionFinishedAt: session.finishedAt || null,
            stopRequestedAt: session.stopRequestedAt || null,
            reason,
            evictedAt: new Date().toISOString()
        })
        while (this.evictedSessions.size > Math.max(20, this.MAX_COMPLETED_SESSIONS * 2)) {
            const oldest = this.evictedSessions.keys().next().value
            this.evictedSessions.delete(oldest)
        }
    }

    // === Utility Methods ===

    _generateSessionId() {
        return `ptk-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    }

    _extractHost(url) {
        try { return new URL(url).host } catch { return url }
    }

    _normalizeEngines(engines) {
        const valid = ['DAST', 'IAST', 'SAST', 'SCA']
        if (!Array.isArray(engines) || engines.length === 0) return ['DAST']
        return engines.map(e => String(e).toUpperCase().trim()).filter(e => valid.includes(e))
    }

    _normalizeEngineConfigs(rawConfigs, allowedEngines = []) {
        const configs = {}
        const allowed = new Set((Array.isArray(allowedEngines) ? allowedEngines : []).map(e => String(e || '').toUpperCase()))
        if (!rawConfigs || typeof rawConfigs !== 'object') {
            return configs
        }

        for (const [engineNameRaw, value] of Object.entries(rawConfigs)) {
            const engineName = String(engineNameRaw || '').toUpperCase()
            if (!engineName || !allowed.has(engineName)) continue
            if (!value || typeof value !== 'object') continue
            configs[engineName] = Object.assign({}, value)
        }

        return configs
    }

    /**
     * Check whether a session status should still block a new start in the tab.
     *
     * This keeps per-tab busy detection aligned with the shared
     * ACTIVE_SESSION_STATUSES set. Any other value is ignored, so the status is
     * treated as non-active.
     *
     * @param {string} [status] - Session status to classify.
     * @returns {boolean}
     */
    _isActiveSessionStatus(status) {
        return ACTIVE_SESSION_STATUSES.has(String(status || '').toLowerCase())
    }

    _isTerminalSessionStatus(status) {
        const normalized = String(status || '').toLowerCase()
        return normalized === 'completed' || normalized === 'cancelled' || normalized === 'error'
    }

    /**
     * Check whether request options enable strict current-tab session lookup.
     *
     * This keeps the strict lookup switch tied to the shared
     * STRICT_CURRENT_TAB_SESSION_SCOPE value. Any other value, including a
     * missing `sessionScope`, is ignored so lookup stays non-strict.
     *
     * @param {Object} [options]
     * @param {string} [options.sessionScope] - Optional session lookup mode.
     * @returns {boolean}
     */
    _isStrictCurrentTabScope(options = {}) {
        return options?.sessionScope === STRICT_CURRENT_TAB_SESSION_SCOPE
    }

    _isAuthorizedSessionFrame(session = null, sender = {}) {
        if (!session) return false
        const expectedFrameId = Number.isInteger(session.frameId) ? session.frameId : 0
        return senderFrameId(sender) === expectedFrameId
    }

    _pageExportOwner(session = null, sender = {}, engine = 'ALL', exportMode = PAGE_EXPORT_MODE) {
        if (!session) return null
        return {
            sessionId: session.id,
            tabId: session.tabId,
            frameId: Number.isInteger(session.frameId) ? session.frameId : 0,
            topFrameId: 0,
            engine: String(engine || 'ALL').toUpperCase(),
            exportMode,
            owner: PAGE_EXPORT_OWNER
        }
    }

    _rejectReplayablePageExport(requestId, extra = {}) {
        return {
            ok: false,
            error: REPLAYABLE_EXPORT_REQUIRED_ERROR,
            requestId,
            ...extra
        }
    }

    _baseSessionLookupDiagnostics({
        sessionId = null,
        tabId = null,
        strictCurrentTab = false,
        allowActive = true,
        allowCompleted = false,
        allowGlobalCompleted = false
    } = {}) {
        const requestedSessionId = toNonEmptyString(sessionId)
        const activeSessionIdForTab = tabId ? this.activeSessionByTabId.get(tabId) || null : null
        const completedSessionIdForTab = tabId ? this.lastCompletedSessionByTabId.get(tabId) || null : null
        const candidateIds = [
            requestedSessionId,
            activeSessionIdForTab,
            completedSessionIdForTab,
            this.lastCompletedSessionGlobal
        ].filter(Boolean)
        const evicted = candidateIds.some(id => this.evictedSessions.has(id))
        return {
            requestedSessionId: requestedSessionId || null,
            tabId: tabId ?? null,
            strictCurrentTab: strictCurrentTab === true,
            allowActive: allowActive === true,
            allowCompleted: allowCompleted === true,
            allowGlobalCompleted: allowGlobalCompleted === true,
            lookupSource: 'none',
            activeSessionIdForTab,
            completedSessionIdForTab,
            globalCompletedSessionId: this.lastCompletedSessionGlobal || null,
            sessionExists: false,
            sessionStatus: null,
            sessionFinishedAt: null,
            stopRequestedAt: null,
            retention: {
                ttlMs: this.SESSION_TTL_MS,
                maxCompletedSessions: this.MAX_COMPLETED_SESSIONS,
                evicted
            }
        }
    }

    _sessionLookupDiagnostics(request, session = null, lookupSource = 'none') {
        const diagnostics = this._baseSessionLookupDiagnostics(request)
        diagnostics.lookupSource = lookupSource || 'none'
        diagnostics.sessionExists = Boolean(session)
        if (session) {
            diagnostics.sessionStatus = session.status || null
            diagnostics.sessionFinishedAt = session.finishedAt || null
            diagnostics.stopRequestedAt = session.stopRequestedAt || null
            diagnostics.retention.evicted = this.evictedSessions.has(session.id)
        }
        return diagnostics
    }

    /**
     * Resolve a session for a background request.
     *
     * This keeps session lookup rules in one place so request handlers do not
     * each implement their own tab/global fallback behaviour. The main benefit
     * is consistency: strict current-tab workflow handlers and compatibility
     * handlers can use the same lookup path while choosing whether to look at
     * the active tab session, the tab's last completed session, or the global
     * completed session.
     *
     * Lookup order is:
     * 1. explicit sessionId
     * 2. active session for the sender tab, when allowed
     * 3. retained completed session for the sender tab, when allowed
     * 4. retained completed session across tabs, when allowed and not strict
     *
     * Strict current-tab mode requires tab context and rejects explicit
     * sessionIds that belong to another tab. Stale map entries are cleaned up
     * while walking the candidate list.
     *
     * @param {Object} request
     * @param {string|null} [request.sessionId] - Explicit session to resolve first.
     * @param {number|null} [request.tabId] - Sender tab used for tab-scoped lookup.
     * @param {boolean} [request.strictCurrentTab=false] - Reject cross-tab explicit
     * session IDs and suppress global completed fallback.
     * @param {boolean} [request.allowActive=true] - Allow resolving the active
     * session for the sender tab.
     * @param {boolean} [request.allowCompleted=false] - Allow resolving the last
     * completed session for the sender tab.
     * @param {boolean} [request.allowGlobalCompleted=false] - Allow resolving the
     * last completed session across tabs when strict mode is disabled.
     * @returns {{ok: true, sessionId: string, session: Object} | {ok: false, error: string}}
     */
    _resolveSessionForRequest({
        sessionId = null,
        tabId = null,
        strictCurrentTab = false,
        allowActive = true,
        allowCompleted = false,
        allowGlobalCompleted = false
    } = {}) {
        const request = { sessionId, tabId, strictCurrentTab, allowActive, allowCompleted, allowGlobalCompleted }
        if (strictCurrentTab && !tabId) {
            return { ok: false, error: 'no_tab_context', sessionLookup: this._sessionLookupDiagnostics(request) }
        }

        const explicitSessionId = toNonEmptyString(sessionId)
        if (explicitSessionId) {
            const explicitSession = this.sessions.get(explicitSessionId)
            if (!explicitSession) {
                return { ok: false, error: 'session_not_found', sessionLookup: this._sessionLookupDiagnostics(request) }
            }
            if (strictCurrentTab && explicitSession.tabId !== tabId) {
                return { ok: false, error: 'session_belongs_to_another_tab', sessionLookup: this._sessionLookupDiagnostics(request, explicitSession, 'explicit-session') }
            }
            return {
                ok: true,
                sessionId: explicitSessionId,
                session: explicitSession,
                sessionLookup: this._sessionLookupDiagnostics(request, explicitSession, 'explicit-session')
            }
        }

        const candidates = []
        if (tabId && allowActive) {
            candidates.push({
                kind: 'active',
                lookupSource: 'active-tab',
                tabId,
                sessionId: this.activeSessionByTabId.get(tabId)
            })
        }
        if (tabId && allowCompleted) {
            candidates.push({
                kind: 'completed-tab',
                lookupSource: 'completed-tab',
                tabId,
                sessionId: this.lastCompletedSessionByTabId.get(tabId)
            })
        }
        if (!strictCurrentTab && allowGlobalCompleted) {
            candidates.push({
                kind: 'completed-global',
                lookupSource: 'completed-global',
                sessionId: this.lastCompletedSessionGlobal
            })
        }

        for (const candidate of candidates) {
            if (!candidate.sessionId) continue
            const session = this.sessions.get(candidate.sessionId)
            if (session) {
                return {
                    ok: true,
                    sessionId: candidate.sessionId,
                    session,
                    sessionLookup: this._sessionLookupDiagnostics(request, session, candidate.lookupSource)
                }
            }

            if (candidate.kind === 'active' && this.activeSessionByTabId.get(candidate.tabId) === candidate.sessionId) {
                this.activeSessionByTabId.delete(candidate.tabId)
            } else if (candidate.kind === 'completed-tab' && this.lastCompletedSessionByTabId.get(candidate.tabId) === candidate.sessionId) {
                this.lastCompletedSessionByTabId.delete(candidate.tabId)
            } else if (candidate.kind === 'completed-global' && this.lastCompletedSessionGlobal === candidate.sessionId) {
                this.lastCompletedSessionGlobal = null
            }
        }

        return { ok: false, error: 'session_not_found', sessionLookup: this._sessionLookupDiagnostics(request) }
    }

    async _checkIastContentReady(tabId) {
        if (!tabId) return false
        if (this.app?.iast?.isAgentReady && this.app.iast.isAgentReady(tabId)) {
            return true
        }
        if (!browser?.tabs?.sendMessage) return false
        try {
            await browser.tabs.sendMessage(tabId, {
                channel: 'ptk_background_iast2content',
                type: 'ping'
            })
            return true
        } catch (e) {
            return false
        }
    }

    async _waitForIastAgentReady(tabId, timeoutMs = 15000, pollMs = 100) {
        const start = Date.now()
        const hasAgentProbe = !!this.app?.iast?.isAgentReady
        while (Date.now() - start < timeoutMs) {
            const failureReason = this.app?.iast?.agentFailedTabs?.get?.(tabId)
            if (failureReason) {
                return false
            }
            if (hasAgentProbe && this.app.iast.isAgentReady(tabId)) {
                return true
            }
            // Fallback only when agent probe is unavailable.
            if (!hasAgentProbe && await this._checkIastContentReady(tabId)) {
                return true
            }
            await new Promise(r => setTimeout(r, pollMs))
        }
        return false
    }

    _mergeStats(target, source) {
        target.findingsCount += source?.findingsCount || 0
        const sev = source?.bySeverity || {}
        target.bySeverity.critical += sev.critical || 0
        target.bySeverity.high += sev.high || 0
        target.bySeverity.medium += sev.medium || 0
        target.bySeverity.low += sev.low || 0
        target.bySeverity.info += sev.info || 0
    }

    _collectCurrentStats(session) {
        const stats = { findingsCount: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }
        for (const engineName of session.engines) {
            const adapter = this.engines.getAdapter(engineName)
            if (adapter) {
                this._mergeStats(stats, adapter.getStats())
            }
        }
        return stats
    }

    // Returns { findings, truncated }
    _collectFindings(session, limit = 100) {
        const allFindings = []
        for (const engineName of session.engines) {
            const adapter = this.engines.getAdapter(engineName)
            if (adapter) {
                allFindings.push(...adapter.getFindings(limit + 1))  // Get more to check truncation
            }
        }
        const truncated = allFindings.length > limit
        return {
            findings: allFindings.slice(0, limit),
            truncated
        }
    }

    _collectAnalysisSnapshot(session) {
        const engines = []
        const warnings = []
        const summary = {
            routes: 0,
            endpoints: 0,
            graphql: 0,
            hiddenParams: 0,
            surfaces: 0,
            gadgets: 0,
            findings: 0,
            requests: 0,
            runtimeEvents: 0
        }

        for (const engineName of session?.engines || []) {
            let scanId = session.scanIds?.[engineName] || null
            if (!scanId) {
                scanId = resultsRegistry.findScanIdForEngine(engineName, {
                    tabId: session.tabId,
                    host: session.host
                })
            }

            let scanResult = this._getEngineScanResult(engineName)
            if (scanId && scanResult?.scanId !== scanId) {
                scanResult = resultsRegistry.get(engineName, scanId)
            }
            if (!scanResult || typeof scanResult !== 'object') {
                engines.push({
                    engine: engineName,
                    scanId,
                    available: false,
                    reason: 'scan_result_unavailable'
                })
                continue
            }

            const analysis = cloneJsonSafe(scanResult.analysis, { warnings, label: `${engineName}.analysis` })
            const codeArtifacts = cloneJsonSafe(scanResult.codeArtifacts, { warnings, label: `${engineName}.codeArtifacts` })
            const explorer = analysis?.explorer || null
            const counts = {
                findings: Array.isArray(scanResult.findings) ? scanResult.findings.length : 0,
                requests: Array.isArray(scanResult.requests) ? scanResult.requests.length : 0,
                runtimeEvents: Array.isArray(scanResult.runtimeEvents) ? scanResult.runtimeEvents.length : 0,
                routes: Array.isArray(explorer?.routes) ? explorer.routes.length : 0,
                endpoints: Array.isArray(explorer?.endpoints) ? explorer.endpoints.length : 0,
                graphql: Array.isArray(explorer?.graphql) ? explorer.graphql.length : 0,
                hiddenParams: Array.isArray(explorer?.hiddenParams) ? explorer.hiddenParams.length : 0,
                surfaces: Array.isArray(explorer?.surfaces) ? explorer.surfaces.length : 0,
                gadgets: Array.isArray(explorer?.gadgets) ? explorer.gadgets.length : 0
            }
            for (const [key, value] of Object.entries(counts)) {
                summary[key] = (summary[key] || 0) + (Number(value) || 0)
            }
            engines.push({
                engine: engineName,
                scanId: scanResult.scanId || scanId || null,
                available: true,
                analysisVersion: scanResult.analysisVersion || analysis?.version || null,
                analysis,
                explorer,
                codeArtifacts,
                findingsCount: counts.findings,
                requestsCount: counts.requests,
                runtimeEventsCount: counts.runtimeEvents,
                startedAt: scanResult.startedAt || session.startedAt || null,
                finishedAt: scanResult.finishedAt || scanResult.finished || session.finishedAt || null
            })
        }

        return {
            status: session?.status || 'unknown',
            engines,
            summary,
            warnings
        }
    }

    _summarizeEngineStartup(session, engineNames = null) {
        const startedEngines = []
        const failedEngines = []

        const effectiveEngineNames = Array.isArray(engineNames) && engineNames.length
            ? engineNames
            : (session?.engines || [])
        for (const engineName of effectiveEngineNames) {
            const state = session?.engineStates?.[engineName] || {}
            if (state.status === ENGINE_STATUS_RUNNING || state.status === ENGINE_STATUS_STARTING) {
                startedEngines.push(engineName)
                continue
            }

            failedEngines.push({
                engine: engineName,
                error: state.error || `engine_not_running:${state.status || 'unknown'}`
            })
        }

        return { startedEngines, failedEngines }
    }

    _initializeEngineStates(session, engineNames = []) {
        if (!session || typeof session !== 'object') return
        session.engineStates = session.engineStates && typeof session.engineStates === 'object'
            ? session.engineStates
            : {}
        for (const engineName of Array.isArray(engineNames) ? engineNames : []) {
            const previous = session.engineStates[engineName] || {}
            session.engineStates[engineName] = Object.assign({}, previous, {
                status: ENGINE_STATUS_STARTING
            })
        }
    }

    _selectImmediateZapStartupEngines(engineNames = []) {
        const normalized = Array.isArray(engineNames) ? engineNames.filter(Boolean) : []
        if (!normalized.length) return []
        const immediate = []
        if (normalized.includes('IAST')) {
            // IAST must be registered before DAST/client navigation executes
            // page-load DOM sinks. Deferring it misses load-time DOM mutation XSS.
            immediate.push('IAST')
        }
        if (normalized.includes('DAST')) {
            immediate.push('DAST')
        }
        if (normalized.includes('SAST')) {
            // ZAP browser coverage closes short-lived pages quickly. Starting
            // SAST in the initial engine group makes current-page script
            // collection deterministic instead of racing a deferred timer.
            immediate.push('SAST')
        }
        if (immediate.length) return immediate
        return [normalized[0]]
    }

    _startDeferredZapEngines(session, engineNames = [], initialDelayMs = 0) {
        const deferredEngines = Array.isArray(engineNames) ? engineNames.filter(Boolean) : []
        if (!session || !deferredEngines.length) {
            return null
        }

        const startupTask = (async () => {
            await sleep(initialDelayMs)
            const startedEngines = []
            const failedEngines = []
            for (const engineName of deferredEngines) {
                if (!this.sessions.has(session.id)) {
                    break
                }
                if (session.status === ENGINE_STATUS_ERROR
                    || session.status === ENGINE_STATUS_STOPPING
                    || session.status === ENGINE_STATUS_COMPLETED) {
                    break
                }
                const result = await this._startEngine(session, engineName)
                if (result?.ok) {
                    startedEngines.push(engineName)
                } else {
                    failedEngines.push({
                        engine: engineName,
                        error: result?.error || `engine_not_running:${result?.status || 'unknown'}`
                    })
                }
                if (engineName !== deferredEngines[deferredEngines.length - 1]) {
                    await sleep(ZAP_DEFERRED_ENGINE_PER_ENGINE_DELAY_MS)
                }
            }

            if (failedEngines.length > 0) {
                console.warn('[PTK Automation] Deferred ZAP engine startup had failures', {
                    sessionId: session.id,
                    tabId: session.tabId,
                    host: session.host,
                    targetUrl: session.targetUrl,
                    startedEngines,
                    failedEngines
                })
            } else {
                debugAutomationLog('[PTK Automation] Deferred ZAP engine startup completed', {
                    sessionId: session.id,
                    startedEngines
                })
            }
            this._recordZapTiming(session, 'session.deferred_start.end', {
                initialDelayMs,
                startedEngines: startedEngines.join(','),
                failedEngines: failedEngines.map(({ engine, error }) => `${engine}:${error}`).join('|')
            })
        })().catch((err) => {
            console.error('[PTK Automation] Deferred ZAP engine startup failed', {
                sessionId: session.id,
                tabId: session.tabId,
                host: session.host,
                targetUrl: session.targetUrl,
                error: err?.message || String(err)
            })
            this._recordZapTiming(session, 'session.deferred_start.end', {
                result: 'error',
                error: err?.message || String(err)
            })
        })

        session.deferredStartupPromise = startupTask
        return startupTask
    }

    async _startEngine(session, engineName) {
        const { id: sessionId, tabId, host, policyCode, runCve, engineConfigs } = session
        const adapter = this.engines?.getAdapter(engineName)
        const enginePhasePrefix = `engine.${String(engineName || '').toLowerCase()}.start`
        const engineStartedAt = Date.now()
        debugAutomationLog('[PTK Automation] Getting adapter for', engineName, !!adapter)
        if (!adapter) {
            session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                status: ENGINE_STATUS_ERROR,
                error: 'adapter_not_found'
            })
            return { ok: false, engine: engineName, status: ENGINE_STATUS_ERROR, error: 'adapter_not_found' }
        }

        session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
            status: ENGINE_STATUS_STARTING,
            requestedAt: Date.now()
        })

        try {
            debugAutomationLog('[PTK Automation] Starting engine', engineName)
            const perEngineOptions = (engineConfigs && typeof engineConfigs === 'object')
                ? (engineConfigs[engineName] || {})
                : {}
            const mergedOptions = Object.assign({}, perEngineOptions)
            if (mergedOptions.policyCode == null && policyCode != null) {
                mergedOptions.policyCode = policyCode
            }
            if (mergedOptions.runCve == null && runCve != null) {
                mergedOptions.runCve = runCve
            }
            if (engineName === 'DAST' && mergedOptions.targetUrl == null && session.targetUrl) {
                mergedOptions.targetUrl = session.targetUrl
            }
            if (session.source === 'zap') {
                mergedOptions.zapManaged = true
                mergedOptions.zapTiming = {
                    zapid: this.zap?.transport?.getZapId?.() || null,
                    zapSessionKey: session.zapSessionKey || null,
                    automationSessionId: session.id || null,
                    tabId,
                    targetUrl: session.targetUrl || null
                }
            }
            if (engineName === 'DAST' && session.source === 'zap') {
                if (!(Number.isFinite(Number(mergedOptions.maxRequestsPerSecond)) && Number(mergedOptions.maxRequestsPerSecond) > 0)) {
                    mergedOptions.maxRequestsPerSecond = 12
                }
                if (!(Number.isFinite(Number(mergedOptions.concurrency)) && Number(mergedOptions.concurrency) > 0)) {
                    mergedOptions.concurrency = 6
                }
                if (!(Number.isFinite(Number(mergedOptions.planningConcurrency)) && Number(mergedOptions.planningConcurrency) > 0)) {
                    mergedOptions.planningConcurrency = 4
                }
            }
            if (engineName === 'IAST' && session.source === 'zap') {
                if (mergedOptions.policyCode == null && mergedOptions.scanStrategy != null) {
                    mergedOptions.policyCode = mergedOptions.scanStrategy
                }
                if (mergedOptions.waitForReady == null) {
                    mergedOptions.waitForReady = true
                }
                if (!(Number.isFinite(Number(mergedOptions.agentReadyTimeoutMs)) && Number(mergedOptions.agentReadyTimeoutMs) > 0)) {
                    mergedOptions.agentReadyTimeoutMs = 5000
                }
            }

            this._recordZapTiming(session, `${enginePhasePrefix}.begin`)
            const startResult = await adapter.start(sessionId, tabId, host, mergedOptions)
            const engineStatus = this._resolveEngineStartStatus(startResult)
            session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                status: engineStatus,
                startedAt: Date.now()
            })
            if (startResult?.ok === false) {
                session.engineStates[engineName].error = startResult?.error || startResult?.message || 'engine_start_failed'
            }
            const scanId = startResult?.scanId || adapter.getScanId?.() || null
            if (scanId) {
                session.scanIds[engineName] = scanId
            }
            if (startResult?.relatedTab === true) {
                session.engineStates[engineName].relatedTab = true
            }
            if (Number.isInteger(startResult?.ownerTabId)) {
                session.engineStates[engineName].ownerTabId = startResult.ownerTabId
            }
            if (startResult?.warning) {
                session.engineStates[engineName].warning = startResult.warning
                console.warn('[PTK Automation] Engine started with warning', engineName, startResult.warning)
            }
            this._recordZapTiming(session, `${enginePhasePrefix}.end`, {
                durationMs: Date.now() - engineStartedAt,
                result: startResult?.ok === false ? 'error' : 'ok',
                status: engineStatus,
                scanId: scanId || null,
                warning: startResult?.warning || null
            })
            debugAutomationLog('[PTK Automation] Engine started', engineName, engineStatus)
            return {
                ok: startResult?.ok !== false && engineStatus !== ENGINE_STATUS_ERROR,
                engine: engineName,
                status: engineStatus,
                scanId,
                warning: startResult?.warning || null,
                error: startResult?.ok === false ? (startResult?.error || startResult?.message || 'engine_start_failed') : null
            }
        } catch (err) {
            console.error('[PTK Automation] Engine start failed', engineName, err)
            session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                status: ENGINE_STATUS_ERROR,
                error: err.message
            })
            this._recordZapTiming(session, `engine.${String(engineName || '').toLowerCase()}.start.end`, {
                durationMs: Date.now() - engineStartedAt,
                result: 'error',
                error: err?.message || String(err)
            })
            return {
                ok: false,
                engine: engineName,
                status: ENGINE_STATUS_ERROR,
                error: err?.message || String(err)
            }
        }
    }

    _resolveEngineStartStatus(startResult = null) {
        const requestedStatus = String(startResult?.status || '').trim().toLowerCase()
        if (requestedStatus === ENGINE_STATUS_STARTING || requestedStatus === ENGINE_STATUS_RUNNING || requestedStatus === ENGINE_STATUS_DEFERRED_START) {
            return requestedStatus
        }
        if (startResult?.ok === false) {
            return ENGINE_STATUS_ERROR
        }
        return ENGINE_STATUS_RUNNING
    }

    _computeDeferredZapEngineStartDelay(session = null) {
        const sessionId = String(session?.id || '')
        if (!sessionId) {
            return ZAP_DEFERRED_ENGINE_START_BASE_DELAY_MS
        }
        let hash = 0
        for (let index = 0; index < sessionId.length; index += 1) {
            hash = (hash + sessionId.charCodeAt(index)) % 997
        }
        const bucket = hash % ZAP_DEFERRED_ENGINE_START_BUCKETS
        return ZAP_DEFERRED_ENGINE_START_BASE_DELAY_MS + (bucket * ZAP_DEFERRED_ENGINE_START_SPREAD_MS)
    }

    _buildZapStartupFailureMessage(failedEngines = []) {
        if (!Array.isArray(failedEngines) || failedEngines.length === 0) {
            return 'Required ZAP auto-mode engine failed to start'
        }

        return failedEngines
            .map(({ engine, error }) => `${String(engine || 'UNKNOWN').toUpperCase()} engine failed to start: ${error || 'unknown_error'}`)
            .join('; ')
    }

    async _cleanupFailedZapStartup(session) {
        if (!session || !Array.isArray(session.engines)) return

        for (const engineName of session.engines) {
            const state = session.engineStates?.[engineName] || null
            if (state?.status !== 'running') continue

            const adapter = this.engines?.getAdapter(engineName)
            if (!adapter) continue

            try {
                await adapter.stop(session.id, 30000)
                session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                    status: 'stopped'
                })
            } catch (err) {
                session.engineStates[engineName] = Object.assign({}, session.engineStates[engineName], {
                    status: 'error',
                    error: err?.message || String(err)
                })
            }
        }
    }

    // === Session Progress Helpers ===

    getSessionProgressSnapshot(sessionId) {
        const session = this.sessions.get(sessionId)
        if (!session) {
            return { ok: false, error: 'session_not_found' }
        }

        const now = Date.now()
        const startedAtMs = session.startedAt ? Date.parse(session.startedAt) : now
        const elapsedMs = now - startedAtMs
        this._finalizeStoppedSessionIfExportReady(session, 'progress_snapshot')
        const sessionStatus = this._deriveSessionStatus(session)

        const enginesProgress = {}
        let totalFindingsCount = 0
        const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        let latestActivityAt = null
        let firstEngineError = null

        for (const engineName of session.engines) {
            const engineState = session.engineStates[engineName] || {}
            const progress = this._getEngineProgress(engineName, engineState, session)
            enginesProgress[engineName] = progress
            if (!firstEngineError && typeof engineState?.error === 'string' && engineState.error.trim()) {
                firstEngineError = `${engineName}:${engineState.error.trim()}`
            }

            totalFindingsCount += progress.findingsCount || 0

            if (progress.bySeverity) {
                for (const sev of Object.keys(bySeverity)) {
                    bySeverity[sev] += progress.bySeverity[sev] || 0
                }
            }

            if (progress.lastActivityAt) {
                const activityMs = Date.parse(progress.lastActivityAt)
                if (!latestActivityAt || activityMs > Date.parse(latestActivityAt)) {
                    latestActivityAt = progress.lastActivityAt
                }
            }
        }

        return {
            ok: true,
            sessionId: session.id,
            status: sessionStatus,
            completionStatus: session.completionStatus || session.summary?.status || sessionStatus,
            releaseStatus: session.releaseStatus || session.summary?.releaseStatus || null,
            error: session.error || firstEngineError || null,
            startedAt: session.startedAt,
            finishedAt: session.finishedAt,
            stopRequestedAt: session.stopRequestedAt || null,
            closeRequestId: session.closeRequestId || null,
            closeRequestAck: session.closeRequestAck === true,
            closeRequestMode: session.closeRequestMode || null,
            elapsedMs,
            lastUpdatedAt: latestActivityAt,
            engines: enginesProgress,
            summary: {
                findingsCount: totalFindingsCount,
                bySeverity
            },
            ...(sessionStatus === 'completed' && session.summary ? { finalSummary: session.summary } : {}),
            warnings: session.warnings || []
        }
    }

    getZapSessionProgressState(sessionId) {
        const snapshot = this.getSessionProgressSnapshot(sessionId)
        if (!snapshot?.ok) {
            return {
                ok: false,
                sessionId,
                error: 'session_not_found',
                message: 'PTK automation session was not found'
            }
        }

        const session = this.sessions.get(sessionId)
        if (!session) {
            return {
                ok: false,
                sessionId,
                error: 'session_not_found',
                message: 'PTK automation session was not found'
            }
        }

        const runtimeSnapshot = this._buildZapRuntimeSnapshot(session, snapshot)
        return {
            ok: true,
            sessionId,
            tabId: session.tabId ?? null,
            targetUrl: session.targetUrl || session.pageUrl || null,
            sessionStatus: snapshot.status,
            completionStatus: snapshot.completionStatus || session.completionStatus || null,
            releaseStatus: session.releaseStatus || session.summary?.releaseStatus || null,
            stopRequestedAt: session.stopRequestedAt || null,
            closeRequestId: session.closeRequestId || null,
            closeRequestAck: session.closeRequestAck === true,
            closeRequestMode: session.closeRequestMode || null,
            requiredEngines: runtimeSnapshot.requiredEngines,
            engines: runtimeSnapshot.engines,
            startedAt: session.startedAt || null,
            finishedAt: session.finishedAt || null,
            message: runtimeSnapshot.message || null
        }
    }

    _buildZapRuntimeSnapshot(session, snapshot) {
        const requiredEngines = Array.isArray(session?.engines)
            ? session.engines.map(engineName => String(engineName || '').toUpperCase()).filter(Boolean)
            : []
        const engines = {}
        let message = toNonEmptyString(session?.error) || null

        for (const engineName of requiredEngines) {
            const engineState = session?.engineStates?.[engineName] || {}
            const engineProgress = snapshot?.engines?.[engineName] || this._getEngineProgress(engineName, engineState, session)
            let telemetry = null

            if (engineName === 'DAST') {
                telemetry = this._buildZapDastRuntime(engineState, engineProgress, session)
            } else if (engineName === 'IAST') {
                telemetry = this._buildZapIastRuntime(engineState, engineProgress, session)
            } else if (engineName === 'SAST') {
                telemetry = this._buildZapSastRuntime(engineState, engineProgress, session)
            } else {
                telemetry = {
                    isRunning: engineProgress?.isRunning === true,
                    idle: engineProgress?.idle === true,
                    lastActivityAt: engineProgress?.lastActivityAt || null,
                    findingsCount: toFiniteNumber(engineProgress?.findingsCount, 0),
                    error: toNonEmptyString(engineProgress?.error) || toNonEmptyString(engineState?.error) || null
                }
            }

            engines[engineName] = {
                state: engineProgress?.status || engineState.status || 'unknown',
                telemetry
            }

            if (!message) {
                message = toNonEmptyString(telemetry?.error)
            }
        }

        return {
            requiredEngines,
            engines,
            message
        }
    }

    _buildZapDastRuntime(engineState, engineProgress, session) {
        const coordinatorState = this._getDastAutomationCoordinatorState(session?.id)
        const hasCoordinatorState = coordinatorState && typeof coordinatorState === 'object'
        const planned = toFiniteNumber(engineProgress?.progress?.total)
        const executed = toFiniteNumber(engineProgress?.progress?.done)
        const remaining = toFiniteNumber(engineProgress?.progress?.remaining ?? engineProgress?.remaining)
        const activeTasks = toFiniteNumber(engineProgress?.activeTasks, 0)
        const taskQueue = toFiniteNumber(engineProgress?.taskQueue, 0)
        const requestQueue = toFiniteNumber(engineProgress?.requestQueue, 0)
        const pendingPlans = toFiniteNumber(engineProgress?.pendingPlans, 0)
        const planning = toFiniteNumber(engineProgress?.planning, 0)
        const pendingCaptures = toFiniteNumber(engineProgress?.pendingCaptures, 0)
        const pendingAutomationSeeds = hasCoordinatorState
            ? toFiniteNumber(coordinatorState?.pendingAutomationSeeds, 0)
            : 0
        const stopResult = hasCoordinatorState && coordinatorState?.lastAutomationStopResult
            ? coordinatorState.lastAutomationStopResult
            : null
        const lastActivityAt = engineProgress?.lastActivityAt || null
        const hasObservedWork = [
            planned,
            executed,
            remaining,
            activeTasks,
            taskQueue,
            requestQueue,
            pendingPlans,
            planning,
            pendingCaptures,
            pendingAutomationSeeds,
            toFiniteNumber(engineProgress?.findingsCount, 0)
        ].some(value => Number.isFinite(value) && value > 0) || Boolean(toNonEmptyString(lastActivityAt))
        return {
            status: engineProgress?.status || engineState?.status || 'unknown',
            isRunning: engineProgress?.isRunning === true,
            idle: engineProgress?.idle === true,
            phase: engineProgress?.phase || null,
            planned,
            executed,
            remaining,
            activeTasks,
            taskQueue,
            requestQueue,
            pendingPlans,
            planning,
            pendingCaptures,
            captureStats: engineProgress?.captureStats || null,
            pendingAutomationSeeds,
            skippedDueToStrategy: toFiniteNumber(engineProgress?.skippedDueToStrategy, 0),
            scanStrategy: toNonEmptyString(engineProgress?.scanStrategy) || null,
            seededRequests: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.seeded, 0),
            proxySeededRequests: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.proxySeeded, 0),
            historySeededRequests: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeeded, 0),
            historySeedInputCount: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedInputCount, 0),
            historySeedTotalAvailable: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedTotalAvailable, 0),
            historySeedDroppedByCap: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedDroppedByCap, 0),
            historySeedDuplicatesSkipped: toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedDuplicatesSkipped, 0),
            completionStatus: toNonEmptyString(stopResult?.completionStatus) || null,
            stopDrain: stopResult?.drain || null,
            lastActivityAt,
            interactionRequired: hasCoordinatorState
                ? coordinatorState.requireUserInteractionBeforeCapture !== false
                : false,
            userInteractionUnlocked: hasCoordinatorState
                ? coordinatorState.userInteractionUnlocked === true
                : false,
            hasObservedWork,
            findingsCount: toFiniteNumber(engineProgress?.findingsCount, 0),
            error: toNonEmptyString(engineProgress?.error)
                || toNonEmptyString(engineState?.error)
                || null
        }
    }

    _buildZapIastRuntime(engineState, engineProgress, session) {
        const iast = this.app?.iast || null
        const scanResult = iast?.scanResult || null
        const tabId = Number.isInteger(session?.tabId) ? session.tabId : null
        const lastActivityAt = scanResult?.lastUpdatedAt
            || scanResult?.updatedAt
            || engineProgress?.lastActivityAt
            || null
        const requestsCount = Array.isArray(scanResult?.requests) ? scanResult.requests.length : 0
        const runtimeEventsCount = Array.isArray(scanResult?.runtimeEvents) ? scanResult.runtimeEvents.length : 0
        const findingsCount = Array.isArray(scanResult?.findings) ? scanResult.findings.length : toFiniteNumber(engineProgress?.findingsCount, 0)
        const iastTelemetry = scanResult?.iastTelemetry && typeof scanResult.iastTelemetry === 'object'
            ? scanResult.iastTelemetry
            : {}
        const automationTelemetry = iastTelemetry.automation && typeof iastTelemetry.automation === 'object'
            ? iastTelemetry.automation
            : {}
        const runtimeHealth = iastTelemetry.activation?.runtimeHealth && typeof iastTelemetry.activation.runtimeHealth === 'object'
            ? iastTelemetry.activation.runtimeHealth
            : null
        const hasAgentProbe = typeof iast?.isAgentReady === 'function'
        const agentReady = Number.isInteger(tabId)
            ? (hasAgentProbe ? iast.isAgentReady(tabId) : !!iast?.agentReadyTabs?.has?.(tabId))
            : false
        const activityError = Number.isInteger(tabId)
            ? toNonEmptyString(iast?.agentFailedTabs?.get?.(tabId))
            : null
        const modulesSentOk = toFiniteNumber(automationTelemetry?.modulesSentOk, 0)
        const modulesSentError = toFiniteNumber(automationTelemetry?.modulesSentError, 0)
        const runtimeHealthCount = toFiniteNumber(automationTelemetry?.runtimeHealthCount, 0)
        const findingReportsAccepted = toFiniteNumber(automationTelemetry?.findingReportsAccepted, 0)
        const runtimeSignalsAccepted = toFiniteNumber(automationTelemetry?.runtimeSignalsAccepted, 0)
        const lastSenderTabId = Number.isInteger(Number(automationTelemetry?.lastSenderTabId))
            ? Number(automationTelemetry.lastSenderTabId)
            : null
        const moduleDeliveryObserved = runtimeHealth?.modulesLoaded === true
            || (modulesSentOk > 0 && (!Number.isInteger(tabId) || lastSenderTabId === null || lastSenderTabId === tabId))
        const agentObservedActivity = findingReportsAccepted > 0
            || runtimeSignalsAccepted > 0
            || runtimeHealthCount > 0
            || runtimeEventsCount > 0
            || findingsCount > 0

        return {
            status: engineState?.status || 'unknown',
            isScanRunning: iast?.isScanRunning === true,
            agentReady,
            modulesLoaded: runtimeHealth?.modulesLoaded === true,
            modulesSignature: toNonEmptyString(runtimeHealth?.modulesSignature) || null,
            pendingFindingReports: toFiniteNumber(runtimeHealth?.pendingFindingReports, 0),
            flushedPendingFindingReports: toFiniteNumber(runtimeHealth?.flushedPendingFindingReports, 0),
            runtimeUrl: runtimeHealth?.url || null,
            agentBootUrl: runtimeHealth?.agentBootUrl || null,
            documentReadyState: runtimeHealth?.documentReadyState || null,
            agentBootReadyState: runtimeHealth?.agentBootReadyState || null,
            agentBootAfterLoad: runtimeHealth?.agentBootAfterLoad === true,
            agentBootDelayMs: Number.isFinite(Number(runtimeHealth?.agentBootDelayMs))
                ? Number(runtimeHealth.agentBootDelayMs)
                : null,
            modulesSentOk,
            modulesSentSkipped: toFiniteNumber(automationTelemetry?.modulesSentSkipped, 0),
            modulesSentError,
            runtimeHealthCount,
            findingReportsAccepted,
            runtimeSignalsAccepted,
            lastModuleSendResult: automationTelemetry?.lastModuleSendResult || null,
            lastSenderTabId: automationTelemetry?.lastSenderTabId ?? null,
            moduleDeliveryObserved,
            requestsCount,
            runtimeEventsCount,
            findingsCount,
            scanStrategy: scanResult?.settings?.iastScanStrategy || automationTelemetry.scanStrategy || null,
            automationTelemetry,
            runtimeHealth,
            lastActivityAt,
            agentObservedActivity,
            hasObservedActivity: agentObservedActivity || requestsCount > 0 || Boolean(toNonEmptyString(lastActivityAt)),
            error: toNonEmptyString(engineProgress?.error) || toNonEmptyString(engineState?.error) || activityError || null
        }
    }

    _buildZapSastRuntime(engineState, engineProgress, session) {
        const liveProgress = this._getLiveSastAutomationProgress() || {}
        const automationState = this.app?.sast?.sessionCoordinator?.getAutomationState?.() || {}
        const scanResult = this.app?.sast?.scanResult || null
        const relatedWorkPending = engineState?.relatedTab === true && engineState?.relatedWorkPending === true
        const relatedWorkCompletedAtMs = Number(engineState?.relatedWorkCompletedAt || 0)
        const relatedWorkRecentlyCompleted = engineState?.relatedTab === true
            && relatedWorkCompletedAtMs > 0
            && Date.now() - relatedWorkCompletedAtMs <= ZAP_RELATED_SAST_WORK_EVIDENCE_MS
        const normalized = this._normalizeSastRuntimeFields({
            phase: relatedWorkPending
                ? 'file'
                : (relatedWorkRecentlyCompleted ? 'file_complete' : (liveProgress.phase || engineProgress?.phase || null)),
            totalFiles: liveProgress.totalFiles ?? engineProgress?.totalFiles,
            completedFiles: liveProgress.completedFiles ?? engineProgress?.completedFiles,
            totalModules: liveProgress.totalModules ?? engineProgress?.totalModules,
            completedModules: liveProgress.completedModules ?? engineProgress?.completedModules,
            currentFile: liveProgress.currentFile || engineProgress?.currentFile || null,
            currentModule: liveProgress.currentModule || engineProgress?.currentModule || null,
            collectionState: automationState.collectionState || liveProgress.collectionState || engineProgress?.collectionState || null,
            analysisState: automationState.analysisState || liveProgress.analysisState || engineProgress?.analysisState || null,
            isSessionRunning: automationState.isSessionRunning === true || liveProgress.isRunning === true || engineProgress?.isRunning === true,
            isAnalysisRunning: relatedWorkPending || automationState.isAnalysisRunning === true || liveProgress.isAnalysisRunning === true || engineProgress?.isAnalysisRunning === true,
            activeCollectionCount: toFiniteNumber(automationState.activeCollectionCount, 0) + (relatedWorkPending ? 1 : 0),
            pendingCollectionCount: automationState.pendingCollectionCount ?? liveProgress.pendingCollectionCount ?? engineProgress?.pendingCollectionCount,
            currentGeneration: automationState.currentGeneration,
            lastCompletedGeneration: automationState.lastCompletedGeneration || liveProgress.completedGeneration || engineProgress?.lastCompletedGeneration,
            sessionState: automationState.sessionState || liveProgress.sessionState || engineProgress?.sessionState || null
        })
        const phase = normalized.phase || null
        const totalFiles = toFiniteNumber(liveProgress.totalFiles ?? engineProgress?.totalFiles, 0)
        const completedFiles = toFiniteNumber(liveProgress.completedFiles ?? engineProgress?.completedFiles, 0)
        const totalModules = toFiniteNumber(liveProgress.totalModules ?? engineProgress?.totalModules, 0)
        const completedModules = toFiniteNumber(liveProgress.completedModules ?? engineProgress?.completedModules, 0)
        const currentFile = normalized.currentFile || null
        const currentModule = normalized.currentModule || null
        const lastStatus = toNonEmptyString(liveProgress.lastStatus || engineProgress?.lastStatus) || null
        const findings = toFiniteNumber(liveProgress.findings ?? engineProgress?.findings, 0)
        const hints = toFiniteNumber(liveProgress.hints ?? engineProgress?.hints, 0)
        const firstCollectionStarted = automationState.firstCollectionStarted === true
        const firstCollectionSettled = automationState.firstCollectionSettled === true
        const activeCollectionCount = normalized.activeCollectionCount
        const pendingCollectionCount = toFiniteNumber(automationState.pendingCollectionCount ?? liveProgress.pendingCollectionCount ?? engineProgress?.pendingCollectionCount, 0)
        const currentCollectionId = toNonEmptyString(automationState.currentCollectionId) || null
        const lastCompletedCollectionId = toNonEmptyString(automationState.lastCompletedCollectionId) || null
        const currentCollectionFile = toNonEmptyString(automationState.currentCollectionFile) || null
        const lastCompletedFile = toNonEmptyString(automationState.lastCompletedFile) || null
        const phaseName = typeof phase === 'string' ? phase.trim().toLowerCase() : ''
        const collectionStateName = typeof normalized.collectionState === 'string'
            ? normalized.collectionState.trim().toLowerCase()
            : ''
        const lastActivityAt = scanResult?.lastUpdatedAt
            || scanResult?.updatedAt
            || engineProgress?.lastActivityAt
            || null
        const hasObservedWork = totalFiles > 0
            || completedFiles > 0
            || totalModules > 0
            || completedModules > 0
            || Boolean(currentFile || currentModule || lastStatus)
            || (phaseName !== '' && phaseName !== 'idle' && phaseName !== 'waiting')
            || (collectionStateName !== ''
                && collectionStateName !== 'completed'
                && collectionStateName !== 'waiting_for_page_activity')
            || firstCollectionStarted
            || firstCollectionSettled
            || activeCollectionCount > 0
            || pendingCollectionCount > 0
            || Boolean(currentCollectionId || lastCompletedCollectionId || currentCollectionFile || lastCompletedFile)
            || relatedWorkPending
            || relatedWorkRecentlyCompleted
            || findings > 0
            || hints > 0

        return {
            status: engineState?.status || 'unknown',
            isRunning: normalized.isSessionRunning === true,
            isSessionRunning: normalized.isSessionRunning === true,
            isAnalysisRunning: normalized.isAnalysisRunning === true,
            phase,
            totalFiles,
            completedFiles,
            totalModules,
            completedModules,
            currentFile,
            currentModule,
            lastStatus,
            findings,
            hints,
            firstCollectionStarted,
            firstCollectionSettled,
            firstCollectionError: toNonEmptyString(automationState.firstCollectionError) || null,
            activeCollectionCount,
            pendingCollectionCount,
            collectionState: normalized.collectionState || null,
            sessionState: normalized.sessionState || null,
            analysisState: normalized.analysisState || null,
            currentGeneration: normalized.currentGeneration,
            lastCompletedGeneration: normalized.lastCompletedGeneration,
            currentCollectionId,
            currentCollectionFile,
            currentCollectionScriptsCount: toFiniteNumber(automationState.currentCollectionScriptsCount),
            currentCollectionHtmlChars: toFiniteNumber(automationState.currentCollectionHtmlChars),
            currentCollectionFindingsCount: toFiniteNumber(automationState.currentCollectionFindingsCount),
            currentCollectionStartedAt: toNonEmptyString(automationState.currentCollectionStartedAt) || null,
            currentCollectionPayloadAt: toNonEmptyString(automationState.currentCollectionPayloadAt) || null,
            lastCompletedCollectionId,
            lastCompletedFile,
            lastCompletedModule: toNonEmptyString(automationState.lastCompletedModule) || null,
            lastCompletedScriptsCount: toFiniteNumber(automationState.lastCompletedScriptsCount),
            lastCompletedHtmlChars: toFiniteNumber(automationState.lastCompletedHtmlChars),
            lastCompletedFindingsCount: toFiniteNumber(automationState.lastCompletedFindingsCount),
            lastCompletedArtifactsCount: toFiniteNumber(automationState.lastCompletedArtifactsCount),
            lastCompletedAt: toNonEmptyString(automationState.lastCompletedAt) || null,
            lastActivityAt,
            hasObservedWork,
            error: toNonEmptyString(engineProgress?.error) || toNonEmptyString(engineState?.error) || null
        }
    }

    _normalizeSastRuntimeFields(input = {}) {
        const totalFiles = toFiniteNumber(input.totalFiles, 0)
        const completedFiles = toFiniteNumber(input.completedFiles, 0)
        const totalModules = toFiniteNumber(input.totalModules, 0)
        const completedModules = toFiniteNumber(input.completedModules, 0)
        const currentFile = toNonEmptyString(input.currentFile) || null
        const currentModule = toNonEmptyString(input.currentModule) || null
        const activeCollectionCount = toFiniteNumber(input.activeCollectionCount, 0)
        const currentGeneration = toFiniteNumber(input.currentGeneration, 0)
        const lastCompletedGeneration = toFiniteNumber(input.lastCompletedGeneration, 0)
        const isSessionRunning = input.isSessionRunning === true
        const collectionLooksComplete = sastCollectionLooksComplete({
            totalFiles,
            completedFiles,
            totalModules,
            completedModules,
            currentFile,
            currentModule,
            analysisState: input.analysisState,
            collectionState: input.collectionState
        }, { activeCollectionCount })
        if (!collectionLooksComplete) {
            return {
                phase: toNonEmptyString(input.phase) || null,
                currentFile,
                currentModule,
                collectionState: toNonEmptyString(input.collectionState) || null,
                sessionState: toNonEmptyString(input.sessionState) || null,
                analysisState: toNonEmptyString(input.analysisState) || null,
                isSessionRunning,
                isAnalysisRunning: input.isAnalysisRunning === true,
                activeCollectionCount,
                currentGeneration,
                lastCompletedGeneration
            }
        }
        return {
            phase: 'waiting',
            currentFile: null,
            currentModule: null,
            collectionState: isSessionRunning ? 'waiting_for_page_activity' : 'completed',
            sessionState: toNonEmptyString(input.sessionState) || (isSessionRunning ? 'running' : 'completed'),
            analysisState: 'complete',
            isSessionRunning,
            isAnalysisRunning: false,
            activeCollectionCount: 0,
            currentGeneration,
            lastCompletedGeneration: Math.max(lastCompletedGeneration, currentGeneration)
        }
    }

    _finalizeActiveSessionIfExportReady(session, reason = 'unknown') {
        if (!session || session.status === 'completed' || session.status === 'error') {
            return false
        }

        if (!session.stopRequestedAt) {
            return false
        }

        return this._finalizeStoppedSessionIfExportReady(session, reason)
    }

    _finalizeStoppedSessionIfExportReady(session, reason = 'unknown') {
        if (!session || session.status === 'completed' || session.status === 'error' || !session.stopRequestedAt) {
            return false
        }
        if (session.stopInProgress === true) {
            return false
        }

        const engines = Array.isArray(session.engines) ? session.engines : []
        if (!engines.length) return false

        if (!engines.every(engineName => this._isEngineExportReady(session, engineName, { requireStop: true }))) return false

        for (const engineName of engines) {
            const engineUpper = String(engineName || '').toUpperCase()
            session.engineStates[engineUpper] = session.engineStates[engineUpper] || {}
            if (session.engineStates[engineUpper].status === 'stopping') {
                session.engineStates[engineUpper].status = 'stopped'
            }
        }

        session.warnings = Array.isArray(session.warnings) ? session.warnings : []
        session.warnings.push({
            code: 'session_finalized_after_idle_stop',
            reason,
            at: new Date().toISOString()
        })
        this._finalizeSession(session, this._collectCurrentStats(session))
        return true
    }

    _isEngineExportReady(session, engineName, { requireStop = true } = {}) {
        const engineUpper = String(engineName || '').toUpperCase()
        const engineState = session.engineStates?.[engineUpper] || {}
        const progress = this._getEngineProgress(engineUpper, engineState, session) || {}
        const state = String(engineState.status || '').toLowerCase()
        const status = String(progress.status || state || '').toLowerCase()
        const phase = String(progress.phase || '').toLowerCase()
        if (state === 'error' || status === 'error') return true
        if (state === 'stopped' || state === 'completed' || status === 'stopped' || status === 'completed') return true

        const remaining = toFiniteNumber(progress.remaining ?? progress.progress?.remaining, 0)
        const activeTasks = toFiniteNumber(progress.activeTasks, 0)
        const taskQueue = toFiniteNumber(progress.taskQueue, 0)
        const requestQueue = toFiniteNumber(progress.requestQueue, 0)
        const pendingPlans = toFiniteNumber(progress.pendingPlans, 0)
        const planning = toFiniteNumber(progress.planning, 0)
        const pendingCaptures = toFiniteNumber(progress.pendingCaptures, 0)
        const done = toFiniteNumber(progress.progress?.done, null)
        const total = toFiniteNumber(progress.progress?.total, null)
        const finiteComplete = total !== null && done !== null && done >= total
        const queueEmpty = remaining <= 0 && activeTasks <= 0 && taskQueue <= 0 && requestQueue <= 0 && pendingPlans <= 0 && planning <= 0 && pendingCaptures <= 0
        const hasExplicitWorkCounters = [
            progress.remaining,
            progress.progress?.remaining,
            progress.activeTasks,
            progress.taskQueue,
            progress.requestQueue,
            progress.pendingPlans,
            progress.planning,
            progress.pendingCaptures
        ].some(value => typeof value !== 'undefined' && value !== null)
        const sastComplete = engineUpper === 'SAST'
            && queueEmpty
            && (finiteComplete || progress.totalFiles > 0 && progress.completedFiles >= progress.totalFiles)
            && !progress.currentFile
            && !progress.currentModule
            && !/collection_pending|payload_received|analyzing|running/i.test(`${progress.collectionState || ''} ${progress.analysisState || ''}`)
        const passiveComplete = ['IAST', 'SCA'].includes(engineUpper) && queueEmpty && !hasExplicitWorkCounters
        const stoppedNoRemaining = (state === 'stopped'
            || state === 'cancelled'
            || status === 'stopped'
            || status === 'cancelled'
            || phase === 'stopped'
            || phase === 'cancelled')
            && queueEmpty
        const idleComplete = (state === 'stopping' || status === 'stopping' || status === 'idle' || phase === 'idle')
            && (hasExplicitWorkCounters || progress.idle === true || status === 'idle' || phase === 'idle')
            && queueEmpty
        if (requireStop && !session.stopRequestedAt) return false
        return idleComplete || stoppedNoRemaining || finiteComplete && queueEmpty || sastComplete || passiveComplete
    }

    /**
     * Derive session-level status from session and engine states
     */
    _deriveSessionStatus(session) {
        // Explicit status takes precedence
        if (session.status === 'completed') return 'completed'
        if (session.status === 'error') return 'error'
        if (session.status === 'stopping') return 'stopping'

        // Check if any engine has error
        const engineStates = session.engineStates || {}
        const hasError = Object.values(engineStates).some(s => s.status === 'error')
        if (hasError) return 'error'

        // Check if any engine is stopping
        const hasStopping = Object.values(engineStates).some(s => s.status === 'stopping')
        if (hasStopping) return 'stopping'

        // Check if all engines are stopped/completed
        const allStopped = session.engines.every(e => {
            const state = engineStates[e]
            return state?.status === 'stopped' || state?.status === 'completed'
        })
        if (allStopped && session.stopRequestedAt) return 'completed'

        // Default based on session.status
        return session.status || 'running'
    }

    _getDastAutomationCoordinatorState(sessionId) {
        const state = this.app?.dast?.sessionCoordinator?.getState?.()
            || this.app?.rattacker?.sessionCoordinator?.getState?.()
            || null
        if (!state || typeof state !== 'object') return null
        const automationSessionId = toNonEmptyString(state.automationSession?.id)
        if (automationSessionId && sessionId && automationSessionId !== sessionId) {
            return null
        }
        return state
    }

    /**
     * Get progress for a single engine (fast, no blocking)
     * Uses existing stats from scanResult, avoids scanning findings array
     */
    _getEngineProgress(engineName, engineState, session = null) {
        const engineUpper = engineName.toUpperCase()
        const adapter = this.engines?.getAdapter(engineUpper) || null
        let liveIsRunning = false
        try {
            liveIsRunning = !!adapter?.isRunning?.()
        } catch (_) {
            liveIsRunning = false
        }

        const result = {
            status: engineState.status || 'unknown',
            isRunning: liveIsRunning,
            progress: { done: null, total: null },
            findingsCount: 0,
            bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            lastActivityAt: null,
            warnings: engineState.warnings ? [engineState.warnings] : []
        }

        if (engineState.error) {
            result.error = engineState.error
        }
        if (session?.source === 'zap') {
            result.targetWindowRequired = false
        }

        // Get scanResult reference (fast lookup, no deep copy)
        const scanResult = this._getEngineScanResult(engineUpper)
        if (!scanResult) return result

        // Use pre-computed stats if available (fast path)
        if (scanResult.stats) {
            result.findingsCount = scanResult.stats.findingsCount || 0
            result.bySeverity = scanResult.stats.bySeverity || result.bySeverity
        } else if (Array.isArray(scanResult.findings)) {
            // Fallback: count findings (avoid if possible)
            result.findingsCount = scanResult.findings.length
        }

        // Last activity timestamp
        result.lastActivityAt = scanResult.lastUpdatedAt
            || scanResult.updatedAt
            || engineState.lastActivityAt
            || null

        // Engine-specific progress
        if (engineUpper === 'DAST') {
            const liveProgress = this._getDastAutomationProgress()
            const coordinatorState = session?.id
                ? this._getDastAutomationCoordinatorState(session.id)
                : null
            result.phase = liveProgress?.phase || this._getDastPhase()
            if (liveProgress) {
                result.progress = {
                    done: liveProgress.executed ?? null,
                    total: liveProgress.planned ?? null,
                    remaining: liveProgress.remaining ?? null
                }
                result.isRunning = liveProgress.isRunning === true
                result.idle = liveProgress.isIdle === true
                result.remaining = liveProgress.remaining ?? null
                result.activeTasks = liveProgress.activeTasks ?? 0
                result.taskQueue = liveProgress.taskQueue ?? 0
                result.requestQueue = liveProgress.requestQueue ?? 0
                result.pendingPlans = liveProgress.pendingPlans ?? 0
                result.planning = liveProgress.planning ?? 0
                result.pendingCaptures = liveProgress.pendingCaptures ?? 0
                result.captureStats = liveProgress.captureStats || null
                result.skippedDueToStrategy = liveProgress.skippedDueToStrategy ?? 0
                result.scanStrategy = liveProgress.scanStrategy || null
                result.pendingAutomationSeeds = toFiniteNumber(coordinatorState?.pendingAutomationSeeds, 0)
                result.seededRequests = toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.seeded, 0)
                result.proxySeededRequests = toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.proxySeeded, 0)
                result.historySeededRequests = toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeeded, 0)
                result.historySeedInputCount = toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedInputCount, 0)
                result.historySeedTotalAvailable = toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedTotalAvailable, 0)
                result.historySeedDroppedByCap = toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedDroppedByCap, 0)
                result.historySeedDuplicatesSkipped = toFiniteNumber(coordinatorState?.lastAutomationSeedResult?.historySeedDuplicatesSkipped, 0)
                result.targetWindowRequired = liveProgress.targetWindowRequired !== false
                result.zapAttackWindow = liveProgress.zapAttackWindow || null
                result.lastActivityAt = liveProgress.lastActivityAt || result.lastActivityAt
                if (engineState.status === 'running' && result.idle) {
                    result.status = 'idle'
                }
            } else {
                const scanStats = scanResult.scanStats || {}

                const total = scanStats.totalJobsPlanned
                    ?? scanStats.total
                    ?? scanStats.queued
                    ?? null
                const done = scanStats.totalJobsExecuted
                    ?? scanStats.processed
                    ?? scanStats.executed
                    ?? scanResult.requestCount
                    ?? null

                result.progress = { done, total, remaining: null }
                result.idle = !result.isRunning
                result.remaining = null
            }
        } else if (engineUpper === 'SAST') {
            const liveProgress = this._getLiveSastAutomationProgress()
            const automationState = this.app?.sast?.sessionCoordinator?.getAutomationState?.() || {}
            if (liveProgress) {
                const normalized = this._normalizeSastRuntimeFields({
                    phase: liveProgress.phase || null,
                    totalFiles: liveProgress.totalFiles,
                    completedFiles: liveProgress.completedFiles,
                    totalModules: liveProgress.totalModules,
                    completedModules: liveProgress.completedModules,
                    currentFile: liveProgress.currentFile || null,
                    currentModule: liveProgress.currentModule || null,
                    collectionState: automationState.collectionState || liveProgress.collectionState || null,
                    analysisState: automationState.analysisState || liveProgress.analysisState || null,
                    sessionState: automationState.sessionState || liveProgress.sessionState || null,
                    isSessionRunning: automationState.isSessionRunning === true || liveProgress.isRunning === true || liveProgress.isSessionRunning === true,
                    isAnalysisRunning: automationState.isAnalysisRunning === true || liveProgress.isAnalysisRunning === true,
                    activeCollectionCount: automationState.activeCollectionCount ?? liveProgress.activeCollectionCount,
                    pendingCollectionCount: automationState.pendingCollectionCount ?? liveProgress.pendingCollectionCount,
                    currentGeneration: automationState.currentGeneration ?? liveProgress.currentGeneration,
                    lastCompletedGeneration: automationState.lastCompletedGeneration || liveProgress.lastCompletedGeneration || liveProgress.completedGeneration
                })
                result.phase = normalized.phase || null
                result.totalFiles = toFiniteNumber(liveProgress.totalFiles, 0)
                result.completedFiles = toFiniteNumber(liveProgress.completedFiles, 0)
                result.totalModules = toFiniteNumber(liveProgress.totalModules, 0)
                result.completedModules = toFiniteNumber(liveProgress.completedModules, 0)
                result.currentFile = normalized.currentFile || null
                result.currentModule = normalized.currentModule || null
                result.lastStatus = toNonEmptyString(liveProgress.lastStatus) || null
                result.findings = toFiniteNumber(liveProgress.findings, 0)
                result.hints = toFiniteNumber(liveProgress.hints, 0)
                result.isRunning = normalized.isSessionRunning === true
                result.isSessionRunning = normalized.isSessionRunning === true
                result.isAnalysisRunning = normalized.isAnalysisRunning === true
                result.collectionState = normalized.collectionState || null
                result.sessionState = normalized.sessionState || null
                result.analysisState = normalized.analysisState || null
                result.firstCollectionStarted = automationState.firstCollectionStarted === true
                result.firstCollectionSettled = automationState.firstCollectionSettled === true
                result.firstCollectionError = toNonEmptyString(automationState.firstCollectionError) || null
                result.initialCollectionDeferred = automationState.initialCollectionDeferred || null
                result.activeCollectionCount = normalized.activeCollectionCount
                result.pendingCollectionCount = toFiniteNumber(automationState.pendingCollectionCount ?? liveProgress.pendingCollectionCount, 0)
                result.currentGeneration = normalized.currentGeneration
                result.lastCompletedGeneration = normalized.lastCompletedGeneration
                result.currentCollectionId = toNonEmptyString(automationState.currentCollectionId || liveProgress.currentCollectionId) || null
                result.currentCollectionFile = toNonEmptyString(automationState.currentCollectionFile || liveProgress.currentCollectionFile) || null
                result.currentCollectionScriptsCount = toFiniteNumber(automationState.currentCollectionScriptsCount ?? liveProgress.currentCollectionScriptsCount)
                result.currentCollectionHtmlChars = toFiniteNumber(automationState.currentCollectionHtmlChars ?? liveProgress.currentCollectionHtmlChars)
                result.currentCollectionFindingsCount = toFiniteNumber(automationState.currentCollectionFindingsCount ?? liveProgress.currentCollectionFindingsCount)
                result.currentCollectionStartedAt = toNonEmptyString(automationState.currentCollectionStartedAt || liveProgress.currentCollectionStartedAt) || null
                result.currentCollectionPayloadAt = toNonEmptyString(automationState.currentCollectionPayloadAt || liveProgress.currentCollectionPayloadAt) || null
                result.lastCompletedCollectionId = toNonEmptyString(automationState.lastCompletedCollectionId || liveProgress.lastCompletedCollectionId) || null
                result.lastCompletedFile = toNonEmptyString(automationState.lastCompletedFile || liveProgress.lastCompletedFile) || null
                result.lastCompletedModule = toNonEmptyString(automationState.lastCompletedModule || liveProgress.lastCompletedModule) || null
                result.lastCompletedScriptsCount = toFiniteNumber(automationState.lastCompletedScriptsCount ?? liveProgress.lastCompletedScriptsCount)
                result.lastCompletedHtmlChars = toFiniteNumber(automationState.lastCompletedHtmlChars ?? liveProgress.lastCompletedHtmlChars)
                result.lastCompletedFindingsCount = toFiniteNumber(automationState.lastCompletedFindingsCount ?? liveProgress.lastCompletedFindingsCount)
                result.lastCompletedArtifactsCount = toFiniteNumber(automationState.lastCompletedArtifactsCount ?? liveProgress.lastCompletedArtifactsCount)
                result.lastCompletedAt = toNonEmptyString(automationState.lastCompletedAt || liveProgress.lastCompletedAt) || null
                result.hasObservedCollection = result.firstCollectionStarted
                    || result.firstCollectionSettled
                    || toFiniteNumber(result.currentGeneration, 0) > 0
                    || toFiniteNumber(result.lastCompletedGeneration, 0) > 0
                    || Boolean(result.currentCollectionFile || result.lastCompletedFile)
                if (result.totalFiles > 0) {
                    result.progress = {
                        done: result.completedFiles,
                        total: result.totalFiles,
                        remaining: Math.max(result.totalFiles - result.completedFiles, 0)
                    }
                } else if (result.totalModules > 0) {
                    result.progress = {
                        done: result.completedModules,
                        total: result.totalModules,
                        remaining: Math.max(result.totalModules - result.completedModules, 0)
                    }
                } else {
                    result.progress = {
                        done: result.findingsCount,
                        total: null
                    }
                }
                const phase = String(result.phase || '').toLowerCase()
                result.idle = result.isAnalysisRunning !== true && (phase === 'waiting' || phase === 'idle')
            } else {
                result.progress = {
                    done: result.findingsCount,
                    total: null
                }
                result.idle = !result.isRunning
            }
        } else {
            if (engineUpper === 'IAST') {
                const iast = this.app?.iast || null
                const scanResult = iast?.scanResult || null
                const automationTelemetry = scanResult?.iastTelemetry?.automation || {}
                const runtimeHealth = scanResult?.iastTelemetry?.activation?.runtimeHealth || null
                const sessionTabId = Number.isInteger(Number(session?.tabId)) ? Number(session.tabId) : null
                const scanResultTabId = Number.isInteger(Number(scanResult?.tabId)) ? Number(scanResult.tabId) : null
                const tabId = sessionTabId ?? scanResultTabId
                result.requestsCount = Array.isArray(scanResult?.requests) ? scanResult.requests.length : 0
                result.runtimeEventsCount = Array.isArray(scanResult?.runtimeEvents) ? scanResult.runtimeEvents.length : 0
                result.findingsCount = Array.isArray(scanResult?.findings)
                    ? scanResult.findings.length
                    : result.findingsCount
                result.agentReady = tabId !== null
                    ? (typeof iast?.isAgentReady === 'function'
                        ? iast.isAgentReady(tabId)
                        : iast?.agentReadyTabs?.has?.(tabId) === true)
                    : Array.from(iast?.agentReadyTabs || []).length > 0
                result.modulesSentOk = toFiniteNumber(automationTelemetry?.modulesSentOk, 0)
                result.modulesSentSkipped = toFiniteNumber(automationTelemetry?.modulesSentSkipped, 0)
                result.modulesSentError = toFiniteNumber(automationTelemetry?.modulesSentError, 0)
                result.runtimeHealthState = runtimeHealth?.state || null
                result.modulesLoaded = runtimeHealth?.modulesLoaded === true
                result.modulesSignature = toNonEmptyString(runtimeHealth?.modulesSignature) || null
                result.pendingFindingReports = toFiniteNumber(runtimeHealth?.pendingFindingReports, 0)
                result.flushedPendingFindingReports = toFiniteNumber(runtimeHealth?.flushedPendingFindingReports, 0)
                result.runtimeUrl = runtimeHealth?.url || null
                result.agentBootUrl = runtimeHealth?.agentBootUrl || null
                result.documentReadyState = runtimeHealth?.documentReadyState || null
                result.agentBootReadyState = runtimeHealth?.agentBootReadyState || null
                result.agentBootAfterLoad = runtimeHealth?.agentBootAfterLoad === true
                result.agentBootDelayMs = Number.isFinite(Number(runtimeHealth?.agentBootDelayMs))
                    ? Number(runtimeHealth.agentBootDelayMs)
                    : null
                result.runtimeHealthCount = toFiniteNumber(automationTelemetry?.runtimeHealthCount, 0)
                result.findingReportsAccepted = toFiniteNumber(automationTelemetry?.findingReportsAccepted, 0)
                result.runtimeSignalsAccepted = toFiniteNumber(automationTelemetry?.runtimeSignalsAccepted, 0)
                result.lastModuleSendResult = automationTelemetry?.lastModuleSendResult || null
                result.lastSenderTabId = automationTelemetry?.lastSenderTabId ?? null
                const lastSenderTabId = Number.isInteger(Number(result.lastSenderTabId))
                    ? Number(result.lastSenderTabId)
                    : null
                result.moduleDeliveryObserved = result.modulesLoaded === true
                    || (result.modulesSentOk > 0 && (tabId === null || lastSenderTabId === null || lastSenderTabId === tabId))
                result.agentObservedActivity = result.findingReportsAccepted > 0
                    || result.runtimeSignalsAccepted > 0
                    || result.runtimeHealthCount > 0
                    || result.runtimeEventsCount > 0
                    || result.findingsCount > 0
                result.readyEvidence = result.agentReady === true && result.modulesLoaded === true
                    ? 'agent_modules_ready'
                    : (result.findingReportsAccepted > 0 || result.findingsCount > 0
                        ? 'finding_activity'
                        : (result.runtimeSignalsAccepted > 0 || result.runtimeHealthCount > 0 || result.runtimeEventsCount > 0
                            ? 'runtime_activity'
                            : (result.moduleDeliveryObserved ? 'module_delivery' : null)))
                result.idle = result.pendingFindingReports === 0
                    && result.modulesSentError === 0
                    && Boolean(result.readyEvidence)
            } else {
                result.idle = !result.isRunning
            }
            // IAST/SCA: limited progress info
            result.progress = {
                done: result.findingsCount,
                total: null
            }
        }

        return result
    }

    /**
     * Get scanResult reference for engine (fast, no copy)
     */
    _getEngineScanResult(engineUpper) {
        const sources = {
            DAST: () => this.app?.dast?.engine?.scanResult
                || this.app?.rattacker?.engine?.scanResult
                || this.app?.dast?.scanResult
                || this.app?.rattacker?.scanResult,
            IAST: () => this.app?.iast?.scanResult,
            SAST: () => this.app?.sast?.scanResult,
            SCA: () => this.app?.sca?.scanResult
        }
        return sources[engineUpper]?.() || null
    }

    _getEngineExportModule(engineUpper) {
        const sources = {
            DAST: () => this.app?.dast || this.app?.rattacker || null,
            IAST: () => this.app?.iast || null,
            SAST: () => this.app?.sast || null,
            SCA: () => this.app?.sca || null
        }
        return sources[engineUpper]?.() || null
    }

    /**
     * Get DAST phase if available
     */
    _getDastPhase() {
        const dast = this.app?.dast || this.app?.rattacker
        if (!dast) return null

        // Helper to safely check running state (could be function or boolean)
        const isRunning = (val) => typeof val === 'function' ? val() : !!val

        // Check various state indicators
        if (isRunning(dast.isSpiderRunning) || dast.spiderRunning) return 'spider'
        if (isRunning(dast.isActiveRunning) || dast.activeRunning) return 'active'
        if (isRunning(dast.engine?.isRunning) || dast.isRunning) return 'scanning'

        return 'idle'
    }

    _getDastAutomationProgress() {
        const dast = this.app?.dast || this.app?.rattacker
        const snapshot = dast?.engine?.getProgressSnapshot?.()
        return snapshot && typeof snapshot === 'object' ? snapshot : null
    }

    _getLiveSastAutomationProgress() {
        const snapshot = this.app?.sast?._buildSastProgressSnapshot?.()
        if (!snapshot || typeof snapshot !== 'object') return null
        const automationState = this.app?.sast?.sessionCoordinator?.getAutomationState?.() || {}
        return Object.assign({}, snapshot, {
            sessionState: automationState.sessionState || snapshot.sessionState || null,
            collectionState: automationState.collectionState || snapshot.collectionState || null,
            analysisState: automationState.analysisState || snapshot.analysisState || null,
            isSessionRunning: automationState.isSessionRunning === true || snapshot.isRunning === true,
            isAnalysisRunning: automationState.isAnalysisRunning === true || snapshot.isAnalysisRunning === true,
            firstCollectionStarted: automationState.firstCollectionStarted === true,
            firstCollectionSettled: automationState.firstCollectionSettled === true,
            firstCollectionError: automationState.firstCollectionError || null,
            activeCollectionCount: automationState.activeCollectionCount,
            pendingCollectionCount: automationState.pendingCollectionCount,
            currentGeneration: automationState.currentGeneration ?? snapshot.currentGeneration,
            lastCompletedGeneration: automationState.lastCompletedGeneration ?? snapshot.completedGeneration,
            currentCollectionId: automationState.currentCollectionId || null,
            currentCollectionFile: automationState.currentCollectionFile || null,
            currentCollectionScriptsCount: automationState.currentCollectionScriptsCount,
            currentCollectionHtmlChars: automationState.currentCollectionHtmlChars,
            currentCollectionFindingsCount: automationState.currentCollectionFindingsCount,
            currentCollectionStartedAt: automationState.currentCollectionStartedAt || null,
            currentCollectionPayloadAt: automationState.currentCollectionPayloadAt || null,
            lastCompletedFile: automationState.lastCompletedFile || snapshot.lastCompletedFile || null,
            lastCompletedModule: automationState.lastCompletedModule || snapshot.lastCompletedModule || null,
            lastCompletedCollectionId: automationState.lastCompletedCollectionId || null,
            lastCompletedScriptsCount: automationState.lastCompletedScriptsCount,
            lastCompletedHtmlChars: automationState.lastCompletedHtmlChars,
            lastCompletedFindingsCount: automationState.lastCompletedFindingsCount,
            lastCompletedArtifactsCount: automationState.lastCompletedArtifactsCount,
            lastCompletedAt: automationState.lastCompletedAt || null
        })
    }

    async _getZapPublisherDrainState() {
        try {
            if (!this.zap?.publisher || typeof this.zap.publisher.getDrainState !== 'function') {
                return null
            }
            return await this.zap.publisher.getDrainState()
        } catch (err) {
            return {
                drained: false,
                error: err?.message || String(err)
            }
        }
    }
}
