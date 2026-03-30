// dastEngine.js
import {
    ptk_module,
    normalizeRequestContextPath,
    deriveRequestContextSurface,
    buildRequestContextKey
} from "./modules/module.js"
import { ptk_request } from "../rbuilder.js"
import { ptk_utils, ptk_queue, ptk_ruleManager } from "../utils.js"
import { getSearchParamsFromUrlOrHash } from "./urlUtils.js"
import { loadCanonicalRulepack } from "../common/moduleRegistry.js"
import {
    createScanResultEnvelope,
    addFinding,
    addFindingToGroup
} from "../common/scanResults.js"
import {
    resolveEffectiveSeverity
} from "../common/severity_utils.js"
import { resolveFindingTaxonomy } from "../common/resolveFindingTaxonomy.js"
import normalizeFinding from "../common/findingNormalizer.js"
import { loadCanonicalDastRulepack } from "./contract/index.js"
import { DastTaskPlanner } from "./services/dastTaskPlanner.js"
import { DastTaskScheduler } from "./services/dastTaskScheduler.js"
import { DastConfirmationService } from "./services/dastConfirmationService.js"

const DEFAULT_SCAN_STRATEGY = 'SMART'
const DEFAULT_DAST_REQUEST_TIMEOUT_MS = 15000
const DEFAULT_DAST_ORIGINAL_REQUEST_TIMEOUT_MS = 10000
const DEFAULT_SCAN_CONTROL_PROFILE = 'safe'
const DEFAULT_HTML_LINK_DISCOVERY_BUDGET = "safe"
const HTML_LINK_DISCOVERY_BUDGETS = Object.freeze({
    strict: 64,
    safe: 256,
    wide: 1024
})
const TASK_FAMILY_FAIRNESS_LOAD_SHED_THRESHOLD = 128
const HTML_DISCOVERY_SEED_BATCH_SIZE = 8
const HTML_LINK_DISCOVERY_SOURCE = "html_link"
const HTML_LINK_DISCOVERY_LABEL = "Auto-discovered"
const STATIC_ASSET_LINK_REGEX = /\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|pdf|zip|tar|gz|mp4|webm|mp3|wav|txt)(?:[?#].*)?$/i
const SCAN_STRATEGY_CONFIGS = {
    FAST: {
        strategy: 'FAST',
        requestGroupingDefault: 'bulk',
        findingScope: 'url-module'
    },
    SMART: {
        strategy: 'SMART',
        requestGroupingDefault: 'per_target',
        findingScope: 'url-param-module'
    },
    COMPREHENSIVE: {
        strategy: 'COMPREHENSIVE',
        requestGroupingDefault: 'per_target',
        findingScope: null
    }
}

const DEFAULT_HARD_DENY_COOKIE_REGEX = "^(session|sessionid|sess|sessid|phpsessid|jsessionid|connect\\.sid|sid|csrf|xsrf|awsalb|awselb|alb|__Host-|__Secure-)"
const DEFAULT_HARD_DENY_PARAM_REGEX = "^(csrf|xsrf|_csrf|session|sessionid)$"
const DEFAULT_HARD_DENY_HEADER_REGEX = "^(cookie|set-cookie)$"
const DEFAULT_SOFT_EXCLUDE_PARAM_REGEX = "^(utm_|gclid|fbclid|_ga|_gid|optanon|consent|locale|lang)$"
const DEFAULT_SOFT_EXCLUDE_COOKIE_REGEX = "^(ga|_ga|_gid|gid|fbp|consent|optanon|locale|lang|theme|route|sticky)$"
const DEFAULT_SOFT_EXCLUDE_HEADER_REGEX = "^(proxy-authorization|cookie|set-cookie|x-csrf-token|x-xsrf-token)$"

const SCAN_CONTROL_PROFILE_DEFAULTS = {
    strict: {
        profile: 'strict',
        allowedCapabilities: {
            boolean: true,
            error: false,
            union: false,
            time: false,
            oast: false,
            xmlEncoding: false
        },
        stopRules: {
            stopOnFirstFindingPerModule: true,
            stopOnFirstFindingPerRequest: false
        },
        confirm: {
            mode: 'module',
            confirmFindings: true,
            confirmOnlyWhenBorderline: true,
            minLenDelta: 20,
            borderlineWindow: 10,
            confirmMaxExtraRequests: 1
        },
        allowAuthLikeMutations: false,
        globalExcludes: {
            hardDenyCookieNameRegex: DEFAULT_HARD_DENY_COOKIE_REGEX,
            hardDenyParamNameRegex: DEFAULT_HARD_DENY_PARAM_REGEX,
            hardDenyHeaderNameRegex: DEFAULT_HARD_DENY_HEADER_REGEX,
            excludeParamNameRegex: DEFAULT_SOFT_EXCLUDE_PARAM_REGEX,
            excludeCookieNameRegex: DEFAULT_SOFT_EXCLUDE_COOKIE_REGEX,
            excludeHeaderNameRegex: DEFAULT_SOFT_EXCLUDE_HEADER_REGEX,
            allowDangerousInputs: false
        }
    },
    safe: {
        profile: 'safe',
        allowedCapabilities: {
            boolean: true,
            error: true,
            union: true,
            time: true,
            oast: false,
            xmlEncoding: true
        },
        stopRules: {
            stopOnFirstFindingPerModule: true,
            stopOnFirstFindingPerRequest: false
        },
        confirm: {
            mode: 'module',
            confirmFindings: true,
            confirmOnlyWhenBorderline: true,
            minLenDelta: 20,
            borderlineWindow: 10,
            confirmMaxExtraRequests: 1
        },
        allowAuthLikeMutations: true,
        globalExcludes: {
            hardDenyCookieNameRegex: DEFAULT_HARD_DENY_COOKIE_REGEX,
            hardDenyParamNameRegex: DEFAULT_HARD_DENY_PARAM_REGEX,
            hardDenyHeaderNameRegex: DEFAULT_HARD_DENY_HEADER_REGEX,
            excludeParamNameRegex: DEFAULT_SOFT_EXCLUDE_PARAM_REGEX,
            excludeCookieNameRegex: DEFAULT_SOFT_EXCLUDE_COOKIE_REGEX,
            excludeHeaderNameRegex: DEFAULT_SOFT_EXCLUDE_HEADER_REGEX,
            allowDangerousInputs: false
        }
    },
    wide: {
        profile: 'wide',
        allowedCapabilities: {
            boolean: true,
            error: true,
            union: true,
            time: true,
            oast: true,
            xmlEncoding: true
        },
        stopRules: {
            stopOnFirstFindingPerModule: false,
            stopOnFirstFindingPerRequest: false
        },
        confirm: {
            mode: 'generic',
            confirmFindings: true,
            confirmOnlyWhenBorderline: false,
            minLenDelta: 20,
            borderlineWindow: 10,
            confirmMaxExtraRequests: 1
        },
        allowAuthLikeMutations: true,
        globalExcludes: {
            hardDenyCookieNameRegex: DEFAULT_HARD_DENY_COOKIE_REGEX,
            hardDenyParamNameRegex: DEFAULT_HARD_DENY_PARAM_REGEX,
            hardDenyHeaderNameRegex: DEFAULT_HARD_DENY_HEADER_REGEX,
            excludeParamNameRegex: DEFAULT_SOFT_EXCLUDE_PARAM_REGEX,
            excludeCookieNameRegex: DEFAULT_SOFT_EXCLUDE_COOKIE_REGEX,
            excludeHeaderNameRegex: DEFAULT_SOFT_EXCLUDE_HEADER_REGEX,
            allowDangerousInputs: true
        }
    }
}

function mergeModuleDefinitions(base = [], extra = []) {
    const merged = Array.isArray(base) ? base.slice() : []
    const idIndex = new Map()
    merged.forEach((mod, idx) => {
        if (mod?.id) {
            idIndex.set(mod.id, idx)
        }
    })
    extra.forEach(mod => {
        if (!mod) return
        if (mod.id && idIndex.has(mod.id)) {
            merged[idIndex.get(mod.id)] = mod
        } else {
            if (mod?.id) {
                idIndex.set(mod.id, merged.length)
            }
            merged.push(mod)
        }
    })
    return merged
}

function extractModulesFromRulepack(rulepack, { engine = 'DAST', childKey = 'attacks', label = 'custom' } = {}) {
    if (!rulepack || typeof rulepack !== 'object') {
        return null
    }
    try {
        const canonical = loadCanonicalDastRulepack(rulepack, { label })
        if (!Array.isArray(canonical.modules)) {
            console.warn('[PTK DAST] Custom rulepack has no modules array', { label })
            return null
        }
        return canonical.modules
    } catch (err) {
        console.warn('[PTK DAST] Failed to normalize custom rulepack', { label, error: err?.message || String(err) })
        return null
    }
}

function cloneValue(value) {
    if (typeof globalThis.structuredClone === 'function') {
        try {
            return globalThis.structuredClone(value)
        } catch (_) {
            // fall through to JSON clone
        }
    }
    return JSON.parse(JSON.stringify(value))
}

export class dastEngine {
    /**
     * settings: { maxRequestsPerSecond, concurrency, modulesUrl, ... }
     */
    constructor(settings = {}) {
        this.settings = settings
        this.maxRequestsPerSecond = settings.maxRequestsPerSecond
        this.concurrency = settings.concurrency
        this.planningConcurrency = settings.planningConcurrency
        this.requestTimeoutMs = this._resolveTimeoutMs(
            settings.requestTimeoutMs,
            DEFAULT_DAST_REQUEST_TIMEOUT_MS
        )
        this.originalRequestTimeoutMs = this._resolveTimeoutMs(
            settings.originalRequestTimeoutMs,
            this.requestTimeoutMs || DEFAULT_DAST_ORIGINAL_REQUEST_TIMEOUT_MS
        )
        const requestedStrategy = settings.scanStrategy || settings.dastScanStrategy || DEFAULT_SCAN_STRATEGY
        this.strategyConfig = this._resolveStrategyConfig(requestedStrategy)
        this.scanStats = this._createStrategyStats(this.strategyConfig.strategy)
        this._strategyFindingKeys = new Set()
        const initialScanControls = this.settings?.scanControls || (
            this.settings?.safetyProfile
                ? { profile: this.settings.safetyProfile }
                : null
        )
        this.scanControls = this._normalizeScanControls(initialScanControls).controls
        this._baseRulepackPromise = null
        this._cveRulepackPromise = null
        this._rawBaseModules = null
        this._rawCveModules = null
        this.taskPlanner = new DastTaskPlanner({
            awaitModulesLoaded: async () => {
                if (this._moduleLoadPromise) {
                    await this._moduleLoadPromise
                }
            },
            refreshOastProbeDomains: () => this._refreshOastProbeDomains(),
            ensureOastCallbackProbe: () => this._ensureOastCallbackProbe(),
            resolveOriginal: async (schema, rawMeta, options) => this._resolveOriginalForPlan(schema, rawMeta, options),
            getModules: () => this.modules,
            shouldPlanModule: (module, schema, original) => this._shouldPlanModuleForRequest(module, schema, original),
            moduleRuntimeMode: (module) => this._moduleRuntimeMode(module),
            buildSpaTasks: (original, module, attack, rawMeta, planFingerprint) => this._buildSpaTasks(original, module, attack, rawMeta, planFingerprint),
            shouldUseBulkAttack: (module, options = {}) => this._shouldUseBulkAttack(module, options),
            enrichAttackPayload: (schema, module, attack) => this._enrichAttackPayload(schema, module, attack),
            createTask: (task) => this._createTask(task),
            attackMetadataView: (module, attack, metadata) => this._attackMetadataView(module, attack, metadata),
            appendSelectorDiagnostics: (module, attack, original) => this._appendSelectorDiagnostics(module, attack, original),
            registerPlannedTask: () => this._registerPlannedTask(),
            appendRuntimeEvent: (event) => this._appendRuntimeEvent(event),
            fingerprintFromSchema: (schema) => this._fingerprintFromSchema(schema),
            fingerprintFromPayload: (payload) => this._fingerprintFromPayload(payload)
        })
        this.taskScheduler = new DastTaskScheduler({
            sleep: (ms = 0) => this._sleep(ms),
            runTask: async (task, context) => this._runTask(task, context),
            normalizeResultOrder: (results) => this._normalizeResultOrder(results)
        })
        this.confirmationService = new DastConfirmationService({
            getConfirmConfig: () => this._confirmConfig(),
            activeAttack: async (payload) => this.activeAttack(payload),
            hasRealHttpResponse: (response) => this._hasRealHttpResponse(response),
            appendTaskRuntimeEvent: (task, context, event) => this._appendTaskRuntimeEvent(task, context, event),
            attackRuntimeConfirmation: (attack, kind) => this._attackRuntimeConfirmation(attack, kind),
            getOastCallbackEvents: () => this._oastCallbackEvents,
            setOastConfirmationMetadata: () => {}
        })
        this.reset()
        this.automationHooks = null
        this._resultMutationListener = typeof settings?.onResultMutation === 'function'
            ? settings.onResultMutation
            : null

        this._moduleLoadPromise = this.loadModules({
            runCve: !!settings?.runCve,
            policy: settings?.dastScanPolicy || settings?.scanPolicy,
            rulepack: settings?.rulepack,
            cveRulepack: settings?.cveRulepack
        })
        this._proModuleLoadPromise = this.loadProModules()
        this._debuggerDialogTabs = new Set()
        this._debuggerDialogListener = null
        this._oastCallbackListener = null
    }

    reset() {
        this._detachOastCallbackProbe()
        this.isRunning = false
        this.inProgress = false
        this.tokens = this.maxRequestsPerSecond
        this.lastRefill = Date.now()
        this.tokenRefillInterval = 1000
        this.activeCount = 0
        this._requestQueue = new ptk_queue()
        this.scanResult = this.getEmptyScanResult()
        this._resetTaskQueues()
        this._activePlans = new Map()
        this._taskWorkers = new Set()
        this._moduleLocks = new Set()
        this._planLocks = new Set()
        this._modulePlanningCache = new WeakMap()
        this._requestPlanningSummaryCache = new WeakMap()
        this._requestPlanningSummaryByFingerprint = new Map()
        this._planningDecisionCache = new Map()
        this._resolvedOriginalCache = new Map()
        this._uniqueAttackSuccess = new Set()
        this._passiveUniqueFindingKeys = new Set()
        this._activeUniqueFindingKeys = new Set()
        this._spaSeenSinks = new Set()
        this._fingerprintMeta = new Map()
        this._htmlDiscoverySeededUrls = new Set()
        this._pendingHtmlDiscoveryUrls = []
        this._pendingHtmlDiscoverySet = new Set()
        this._htmlDiscoveryBackpressure = {
            throttled: false,
            reason: null
        }
        this._familyActiveCounts = new Map()
        this._familyFairnessState = {
            lastDequeuedFamily: null,
            consecutiveDequeues: 0
        }
        this._idleResolvers = new Set()
        this._runtimeEventsDropped = 0
        this._runtimeEventsDropMarked = false
        this._oastDomains = new Set()
        this._oastCallbackEvents = []
        this._lastProgressAt = 0
        this._lastProgressKey = null
        if (this._deferredProgressTimer) {
            clearTimeout(this._deferredProgressTimer)
            this._deferredProgressTimer = null
        }
        this._deferredProgressPayload = null
        this._initializeStrategyState(this.strategyConfig)
        this._performanceTelemetry = this._createPerformanceTelemetry()
        this.scanResult.performance = { dast: this._performanceTelemetry }
        this._requestSeq = 0
        this._attackSeq = 0
        ptk_request.clearStoredHeaders()
    }

    _moduleMetadataRaw(module) {
        return module?.metadata && typeof module.metadata === 'object' ? module.metadata : {}
    }

    _moduleTaxonomy(module) {
        const meta = this._moduleMetadataRaw(module)
        return meta.taxonomy && typeof meta.taxonomy === 'object' ? meta.taxonomy : {}
    }

    _moduleDocs(module) {
        const meta = this._moduleMetadataRaw(module)
        return meta.docs && typeof meta.docs === 'object' ? meta.docs : {}
    }

    _moduleExecution(module) {
        const meta = this._moduleMetadataRaw(module)
        return meta.execution && typeof meta.execution === 'object' ? meta.execution : {}
    }

    _moduleRuntime(module) {
        return module?.runtime && typeof module.runtime === 'object' ? module.runtime : {}
    }

    _moduleCapabilities(module) {
        const execution = this._moduleExecution(module)
        if (Array.isArray(execution.capabilities)) return execution.capabilities
        return []
    }

    _moduleRuntimeHooks(module) {
        const runtime = this._moduleRuntime(module)
        return Array.isArray(runtime.hooks) ? runtime.hooks : []
    }

    _moduleRuntimeMode(module) {
        const runtime = this._moduleRuntime(module)
        return String(runtime.mode || '').toLowerCase()
    }

    _resetTaskQueues() {
        this._taskQueueGroups = new Map()
        this._taskQueueGroupPriority = new Map()
        this._taskReadyGroups = []
        this._taskReadyGroupSet = new Set()
        this._taskReadyGroupFamily = new Map()
        this._taskReadyFamilyCounts = new Map()
        this._taskQueueLength = 0
    }

    _taskQueueCount() {
        return Number(this._taskQueueLength || 0)
    }

    _normalizeHtmlLinkDiscoveryBudget(value) {
        const normalized = String(value || DEFAULT_HTML_LINK_DISCOVERY_BUDGET).trim().toLowerCase()
        return Object.prototype.hasOwnProperty.call(HTML_LINK_DISCOVERY_BUDGETS, normalized)
            ? normalized
            : DEFAULT_HTML_LINK_DISCOVERY_BUDGET
    }

    _isHtmlLinkDiscoveryEnabled() {
        return this.settings?.enableHtmlLinkDiscovery === true
    }

    _resolveHtmlLinkDiscoveryBudgetLimit() {
        const budget = this._normalizeHtmlLinkDiscoveryBudget(this.settings?.htmlLinkDiscoveryBudget)
        return Number(HTML_LINK_DISCOVERY_BUDGETS[budget] || HTML_LINK_DISCOVERY_BUDGETS[DEFAULT_HTML_LINK_DISCOVERY_BUDGET] || 0)
    }

    _remainingHtmlLinkDiscoveryBudget() {
        if (!this._isHtmlLinkDiscoveryEnabled()) return 0
        const limit = this._resolveHtmlLinkDiscoveryBudgetLimit()
        const used = this._htmlDiscoverySeededUrls instanceof Set ? this._htmlDiscoverySeededUrls.size : 0
        return Math.max(0, limit - used)
    }

    _pendingHtmlLinkDiscoveryCount() {
        return Array.isArray(this._pendingHtmlDiscoveryUrls) ? this._pendingHtmlDiscoveryUrls.length : 0
    }

    _remainingHtmlLinkDiscoveryAdmissionBudget() {
        if (!this._isHtmlLinkDiscoveryEnabled()) return 0
        const limit = this._resolveHtmlLinkDiscoveryBudgetLimit()
        const seeded = this._htmlDiscoverySeededUrls instanceof Set ? this._htmlDiscoverySeededUrls.size : 0
        const pending = this._pendingHtmlLinkDiscoveryCount()
        return Math.max(0, limit - seeded - pending)
    }

    _htmlDiscoveryPressureThresholds() {
        const concurrency = Math.max(1, Number(this.concurrency || 1))
        const planningConcurrency = Math.max(1, Number(this.planningConcurrency || concurrency || 1))
        return {
            readyGroupsPause: Math.max(72, concurrency * 24),
            readyGroupsResume: Math.max(24, concurrency * 8),
            taskQueuePause: Math.max(256, concurrency * 96),
            taskQueueResume: Math.max(96, concurrency * 32),
            activePlansPause: Math.max(48, planningConcurrency * 16),
            activePlansResume: Math.max(16, planningConcurrency * 6),
            requestQueuePause: Math.max(24, planningConcurrency * 8),
            requestQueueResume: Math.max(8, planningConcurrency * 3)
        }
    }

    _htmlDiscoveryPressureSnapshot() {
        return {
            readyGroups: Number(this._taskReadyGroups?.length || 0),
            taskQueue: Number(this._taskQueueCount() || 0),
            activePlans: Number(this._activePlans?.size || 0),
            requestQueue: Number(this._requestQueue?.size ? this._requestQueue.size() : 0),
            pendingDiscovered: this._pendingHtmlLinkDiscoveryCount()
        }
    }

    _evaluateHtmlDiscoveryBackpressure() {
        const thresholds = this._htmlDiscoveryPressureThresholds()
        const snapshot = this._htmlDiscoveryPressureSnapshot()
        const state = this._htmlDiscoveryBackpressure || { throttled: false, reason: null }
        const pauseReasons = []
        if (snapshot.readyGroups >= thresholds.readyGroupsPause) pauseReasons.push("ready_groups")
        if (snapshot.taskQueue >= thresholds.taskQueuePause) pauseReasons.push("task_queue")
        if (snapshot.activePlans >= thresholds.activePlansPause) pauseReasons.push("active_plans")
        if (snapshot.requestQueue >= thresholds.requestQueuePause) pauseReasons.push("request_queue")
        const shouldPause = pauseReasons.length > 0
        const canResume = (
            snapshot.readyGroups <= thresholds.readyGroupsResume
            && snapshot.taskQueue <= thresholds.taskQueueResume
            && snapshot.activePlans <= thresholds.activePlansResume
            && snapshot.requestQueue <= thresholds.requestQueueResume
        )
        let throttled = !!state.throttled
        let reason = state.reason || null
        if (throttled) {
            if (canResume) {
                throttled = false
                reason = null
            }
        } else if (shouldPause) {
            throttled = true
            reason = pauseReasons.join(",")
        }
        const changed = throttled !== !!state.throttled || reason !== (state.reason || null)
        this._htmlDiscoveryBackpressure = { throttled, reason }
        if (changed) {
            this._appendRuntimeEvent({
                type: "dast_html_discovery_backpressure",
                phase: "html_discovery",
                throttled,
                reason: reason || null,
                thresholds,
                snapshot,
                budget: this._normalizeHtmlLinkDiscoveryBudget(this.settings?.htmlLinkDiscoveryBudget),
                remainingBudget: this._remainingHtmlLinkDiscoveryBudget(),
                admissionBudget: this._remainingHtmlLinkDiscoveryAdmissionBudget()
            })
        }
        return {
            throttled,
            reason,
            thresholds,
            snapshot
        }
    }

    _queueHtmlDiscoveredUrl(url, parentUrl = null) {
        if (!url) return false
        if (!Array.isArray(this._pendingHtmlDiscoveryUrls)) this._pendingHtmlDiscoveryUrls = []
        if (!(this._pendingHtmlDiscoverySet instanceof Set)) this._pendingHtmlDiscoverySet = new Set()
        if (this._htmlDiscoverySeededUrls?.has(url) || this._pendingHtmlDiscoverySet.has(url)) return false
        this._pendingHtmlDiscoveryUrls.push({
            url,
            parentUrl: parentUrl || null
        })
        this._pendingHtmlDiscoverySet.add(url)
        return true
    }

    _resolveHtmlDiscoverySeedBatchSize() {
        return Math.max(2, Math.min(HTML_DISCOVERY_SEED_BATCH_SIZE, Math.max(1, Number(this.planningConcurrency || this.concurrency || 1)) * 2))
    }

    _drainPendingHtmlDiscoveryQueue() {
        if (!this.isRunning) return 0
        if (!this._isHtmlLinkDiscoveryEnabled()) return 0
        if (!Array.isArray(this._pendingHtmlDiscoveryUrls) || !this._pendingHtmlDiscoveryUrls.length) return 0
        const pressure = this._evaluateHtmlDiscoveryBackpressure()
        if (pressure.throttled) return 0

        const maxSeed = Math.min(
            this._remainingHtmlLinkDiscoveryBudget(),
            this._resolveHtmlDiscoverySeedBatchSize(),
            this._pendingHtmlDiscoveryUrls.length
        )
        if (maxSeed <= 0) return 0

        let seeded = 0
        const samples = []
        while (this._pendingHtmlDiscoveryUrls.length && seeded < maxSeed && this.isRunning) {
            const next = this._pendingHtmlDiscoveryUrls.shift()
            if (!next?.url) continue
            this._pendingHtmlDiscoverySet?.delete(next.url)
            if (this._htmlDiscoverySeededUrls?.has(next.url)) continue
            try {
                const parsed = new URL(next.url)
                const raw = `GET ${next.url} HTTP/1.1\r\nHost: ${parsed.host}\r\n\r\n`
                this.enqueue({
                    raw,
                    url: next.url,
                    method: 'GET',
                    ui_url: next.url,
                    responseType: 'main_frame',
                    discoverySource: HTML_LINK_DISCOVERY_SOURCE,
                    discoveryLabel: HTML_LINK_DISCOVERY_LABEL,
                    discoveryParentUrl: next.parentUrl || null
                }, {
                    url: next.url,
                    ui_url: next.url,
                    method: 'GET',
                    type: 'main_frame',
                    statusCode: 200
                })
                this._htmlDiscoverySeededUrls.add(next.url)
                seeded += 1
                if (samples.length < 4) samples.push(next.url)
            } catch (_) { }
        }

        if (seeded > 0) {
            this._appendRuntimeEvent({
                type: 'dast_html_links_seeded',
                phase: 'html_discovery',
                seededCount: seeded,
                samples,
                pendingDiscovered: this._pendingHtmlLinkDiscoveryCount(),
                budget: this._normalizeHtmlLinkDiscoveryBudget(this.settings?.htmlLinkDiscoveryBudget),
                remainingBudget: this._remainingHtmlLinkDiscoveryBudget()
            })
        }

        return seeded
    }

    _createPerformanceTelemetry() {
        return {
            planner: {
                plansBuilt: 0,
                totalMs: 0,
                maxMs: 0,
                tasksPlanned: 0,
                tasksPlannedMax: 0,
                baselineReplayCount: 0,
                baselineCapturedReuseCount: 0,
                moduleSkips: 0,
                moduleSkipReasons: Object.create(null)
            },
            queue: {
                tasksQueued: 0,
                tasksDequeued: 0,
                depthMax: 0,
                readyGroupsMax: 0,
                waitMsTotal: 0,
                waitMsMax: 0
            },
            scheduler: {
                fairnessChecks: 0,
                fairnessYields: 0,
                alternativeFamilyHits: 0,
                alternativeFamilyMisses: 0,
                fairnessLoadShedBypass: 0,
                readyFamiliesMax: 0
            },
            execution: {
                tasksCompleted: 0,
                totalMs: 0,
                maxMs: 0,
                byModule: Object.create(null),
                byFamily: Object.create(null)
            }
        }
    }

    _perfModuleBucket(moduleId = "module") {
        const store = this._performanceTelemetry?.execution?.byModule
        if (!store) return null
        if (!store[moduleId]) {
            store[moduleId] = {
                planned: 0,
                dequeued: 0,
                completed: 0,
                queueWaitMsTotal: 0,
                queueWaitMsMax: 0,
                executionMsTotal: 0,
                executionMsMax: 0
            }
        }
        return store[moduleId]
    }

    _perfFamilyBucket(family = "unknown") {
        const store = this._performanceTelemetry?.execution?.byFamily
        if (!store) return null
        if (!store[family]) {
            store[family] = {
                planned: 0,
                completed: 0,
                executionMsTotal: 0,
                executionMsMax: 0
            }
        }
        return store[family]
    }

    _taskFamilyKey(task = null) {
        if (task && typeof task === "object" && task._familyKey) {
            return task._familyKey
        }
        const module = task?.module || null
        const moduleId = String(task?.moduleId || module?.id || task?.moduleName || "").toLowerCase()
        const taxonomy = this._moduleTaxonomy(module)
        const vulnId = String(taxonomy?.vulnId || "").toLowerCase()
        const category = String(taxonomy?.category || "").toLowerCase()
        const tags = Array.isArray(taxonomy?.tags)
            ? taxonomy.tags.map((value) => String(value || "").toLowerCase())
            : []
        const runtimeMode = this._moduleRuntimeMode(module)
        let family = moduleId || "unknown"
        if (runtimeMode === "spa" || moduleId.startsWith("spa_") || tags.includes("spa")) family = "spa"
        else if (moduleId.includes("graphql") || vulnId.includes("graphql") || tags.includes("graphql")) family = "graphql"
        else if (moduleId.includes("jwt") || vulnId.includes("jwt") || tags.includes("jwt")) family = "jwt"
        else if (moduleId.includes("request_smuggling") || vulnId.includes("request_smuggling")) family = "smuggling"
        else if (moduleId.includes("host_header") || vulnId.includes("host_header")) family = "host"
        else if (moduleId.includes("cors") || vulnId.includes("cors") || tags.includes("cors")) family = "cors"
        else if (moduleId.includes("ssrf") || vulnId.includes("ssrf") || category === "ssrf" || tags.includes("ssrf")) family = "ssrf"
        else if (moduleId.includes("api_testing") || tags.includes("api")) family = "api"
        else if (moduleId.includes("dom_based") || moduleId.includes("dom_") || vulnId.includes("dom_") || tags.includes("dom")) family = "dom"
        else if (moduleId.includes("deserial") || vulnId.includes("deserial")) family = "deserialization"
        else if (moduleId.includes("xss") || vulnId.includes("xss") || category === "xss" || tags.includes("xss")) family = "xss"
        else if (moduleId.includes("sql") || moduleId.includes("sqli") || moduleId.includes("bsql") || vulnId.includes("sql") || vulnId.includes("injection")) family = "sqli"
        if (typeof task?.module?._selectorFamily === "function") {
            try {
                const selectorFamily = String(task.module._selectorFamily(task?.attack?.action || null) || "").trim().toLowerCase()
                if (selectorFamily && selectorFamily !== "unknown") {
                    family = selectorFamily
                }
            } catch (_) {
                // fall through
            }
        }
        if (task && typeof task === "object") {
            task._familyKey = family || "unknown"
        }
        return family || "unknown"
    }

    _boundedMapSet(map, key, value, limit = 256) {
        if (!(map instanceof Map) || key == null) return
        if (map.has(key)) {
            map.delete(key)
        }
        map.set(key, value)
        while (map.size > limit) {
            const firstKey = map.keys().next().value
            map.delete(firstKey)
        }
    }

    _clonePlanningDecision(decision) {
        if (!decision || typeof decision !== "object") return decision
        return {
            allowed: decision.allowed !== false,
            reason: decision.reason || null
        }
    }

    _familyConcurrencyQuota(family = "unknown") {
        const key = String(family || "unknown").toLowerCase()
        if (key === "sqli") return 1
        return 2
    }

    _familyBurstQuota(family = "unknown") {
        const key = String(family || "unknown").toLowerCase()
        if (key === "sqli") return 24
        return 48
    }

    _bumpReadyFamilyCount(family, delta = 0) {
        const key = String(family || "unknown")
        if (!key || !delta) return
        if (!this._taskReadyFamilyCounts) this._taskReadyFamilyCounts = new Map()
        const nextValue = Number(this._taskReadyFamilyCounts.get(key) || 0) + Number(delta || 0)
        if (nextValue <= 0) {
            this._taskReadyFamilyCounts.delete(key)
        } else {
            this._taskReadyFamilyCounts.set(key, nextValue)
        }
        const scheduler = this._performanceTelemetry?.scheduler
        if (scheduler) {
            scheduler.readyFamiliesMax = Math.max(scheduler.readyFamiliesMax || 0, this._taskReadyFamilyCounts.size)
        }
    }

    _resolveReadyGroupFamily(groupKey) {
        if (!groupKey) return null
        const queue = this._taskQueueGroups?.get(groupKey)
        if (!Array.isArray(queue) || !queue.length) return null
        const task = queue[0]
        if (!task) return null
        return this._taskFamilyKey(task)
    }

    _trackReadyGroupFamily(groupKey) {
        if (!groupKey) return
        if (!this._taskReadyGroupFamily) this._taskReadyGroupFamily = new Map()
        const nextFamily = this._resolveReadyGroupFamily(groupKey)
        const previousFamily = this._taskReadyGroupFamily.get(groupKey) || null
        if (previousFamily === nextFamily) return
        if (previousFamily) {
            this._bumpReadyFamilyCount(previousFamily, -1)
            this._taskReadyGroupFamily.delete(groupKey)
        }
        if (!nextFamily) return
        this._taskReadyGroupFamily.set(groupKey, nextFamily)
        this._bumpReadyFamilyCount(nextFamily, 1)
    }

    _untrackReadyGroupFamily(groupKey) {
        if (!groupKey || !this._taskReadyGroupFamily?.has(groupKey)) return
        const family = this._taskReadyGroupFamily.get(groupKey)
        this._taskReadyGroupFamily.delete(groupKey)
        this._bumpReadyFamilyCount(family, -1)
    }

    _hasRunnableAlternativeFamily(excludedFamily) {
        const targetFamily = String(excludedFamily || "unknown")
        const counts = this._taskReadyFamilyCounts instanceof Map ? this._taskReadyFamilyCounts : null
        if (!counts || !counts.size) return false
        for (const [family, count] of counts.entries()) {
            if (family !== targetFamily && Number(count || 0) > 0) return true
        }
        return false
    }

    _shouldYieldForFamilyFairness(task) {
        if (!task) return false
        const scheduler = this._performanceTelemetry?.scheduler
        if (scheduler) {
            scheduler.fairnessChecks += 1
        }
        if ((this._taskReadyGroups?.length || 0) >= TASK_FAMILY_FAIRNESS_LOAD_SHED_THRESHOLD) {
            if (scheduler) {
                scheduler.fairnessLoadShedBypass += 1
            }
            return false
        }
        const family = this._taskFamilyKey(task)
        const hasAlternativeFamily = this._hasRunnableAlternativeFamily(family)
        if (!hasAlternativeFamily) {
            if (scheduler) {
                scheduler.alternativeFamilyMisses += 1
            }
            return false
        }
        if (scheduler) {
            scheduler.alternativeFamilyHits += 1
        }

        const activeCount = Number(this._familyActiveCounts?.get(family) || 0)
        if (activeCount >= this._familyConcurrencyQuota(family)) {
            if (scheduler) {
                scheduler.fairnessYields += 1
            }
            return true
        }

        const state = this._familyFairnessState || {}
        if (state.lastDequeuedFamily === family && Number(state.consecutiveDequeues || 0) >= this._familyBurstQuota(family)) {
            if (scheduler) {
                scheduler.fairnessYields += 1
            }
            return true
        }

        return false
    }

    _markTaskFamilyDequeued(task) {
        if (!task) return
        const family = this._taskFamilyKey(task)
        const activeCount = Number(this._familyActiveCounts?.get(family) || 0)
        this._familyActiveCounts?.set(family, activeCount + 1)
        if (!this._familyFairnessState) {
            this._familyFairnessState = {
                lastDequeuedFamily: family,
                consecutiveDequeues: 1
            }
        } else if (this._familyFairnessState.lastDequeuedFamily === family) {
            this._familyFairnessState.consecutiveDequeues = Number(this._familyFairnessState.consecutiveDequeues || 0) + 1
        } else {
            this._familyFairnessState.lastDequeuedFamily = family
            this._familyFairnessState.consecutiveDequeues = 1
        }
        task._familyKey = family
    }

    _releaseTaskFamily(task) {
        if (!task) return
        const family = task._familyKey || this._taskFamilyKey(task)
        const activeCount = Number(this._familyActiveCounts?.get(family) || 0)
        if (activeCount <= 1) {
            this._familyActiveCounts?.delete(family)
            return
        }
        this._familyActiveCounts?.set(family, activeCount - 1)
    }

    _taskPriority(task = null) {
        const module = task?.module || null
        const moduleId = String(task?.moduleId || module?.id || '').toLowerCase()
        const runtimeMode = this._moduleRuntimeMode(module)
        const taxonomy = this._moduleTaxonomy(module)
        const vulnId = String(taxonomy?.vulnId || '').toLowerCase()
        const tags = Array.isArray(taxonomy?.tags)
            ? taxonomy.tags.map((value) => String(value || '').toLowerCase())
            : []

        let priority = 0
        const isSpa = runtimeMode === 'spa' || moduleId.startsWith('spa_') || tags.includes('spa')
        if (isSpa) priority += 1000

        const topTierModules = new Set([
            'graphql_introspection',
            'graphql_advanced',
            'api_testing_coverage',
            'ssrf_coverage',
            'dom_based_vuln_coverage',
            'jwt_attacks_coverage',
            'jwt_injection'
        ])
        if (topTierModules.has(moduleId)) priority += 800

        const midTierModules = new Set([
            'host_header_poisoning',
            'cors_misconfig',
            'cors_coverage',
            'request_smuggling'
        ])
        if (midTierModules.has(moduleId)) priority += 550

        if (/\b(dom_xss|open_redirect|token_exposure|ssrf)\b/.test(vulnId)) {
            priority += 150
        }

        const isSqlHeavy = /\b(sql|sqli|bsql|union)\b/.test(moduleId) || /\b(sql|sqli|bsql|union)\b/.test(vulnId)
        if (isSqlHeavy) priority -= 400

        if (task?.moduleAsync === false) {
            priority += 25
        }

        return priority
    }

    _insertReadyGroup(groupKey) {
        if (!groupKey) return
        const priority = Number(this._taskQueueGroupPriority?.get(groupKey) || 0)
        let insertAt = this._taskReadyGroups.length
        for (let index = 0; index < this._taskReadyGroups.length; index += 1) {
            const currentKey = this._taskReadyGroups[index]
            const currentPriority = Number(this._taskQueueGroupPriority?.get(currentKey) || 0)
            if (priority > currentPriority) {
                insertAt = index
                break
            }
        }
        this._taskReadyGroups.splice(insertAt, 0, groupKey)
    }

    _requeueReadyGroup(groupKey) {
        if (!groupKey || !this._taskReadyGroupSet?.has(groupKey)) return
        const currentIndex = this._taskReadyGroups.indexOf(groupKey)
        if (currentIndex >= 0) {
            this._taskReadyGroups.splice(currentIndex, 1)
        }
        this._insertReadyGroup(groupKey)
    }

    _recordPlanBuild(plan, durationMs = 0) {
        const planner = this._performanceTelemetry?.planner
        if (!planner) return
        const tasksPlanned = Array.isArray(plan?.tasks) ? plan.tasks.length : 0
        planner.plansBuilt += 1
        planner.totalMs += Math.max(0, Number(durationMs || 0))
        planner.maxMs = Math.max(planner.maxMs || 0, Math.max(0, Number(durationMs || 0)))
        planner.tasksPlanned += tasksPlanned
        planner.tasksPlannedMax = Math.max(planner.tasksPlannedMax || 0, tasksPlanned)
        if (plan && (durationMs >= 50 || tasksPlanned >= 10)) {
            this._appendRuntimeEvent({
                type: "dast_plan_metrics",
                phase: "plan_build",
                url: plan?.original?.request?.url || null,
                method: plan?.original?.request?.method || null,
                durationMs: Math.max(0, Number(durationMs || 0)),
                tasksPlanned
            })
        }
    }

    _recordModulePlanningSkip(module, reason = "prefilter") {
        const planner = this._performanceTelemetry?.planner
        if (!planner) return
        planner.moduleSkips += 1
        const key = String(reason || "prefilter")
        planner.moduleSkipReasons[key] = Number(planner.moduleSkipReasons[key] || 0) + 1
        const moduleId = module?.id || module?.name || "module"
        const bucket = this._perfModuleBucket(moduleId)
        if (bucket) {
            bucket.skipped = Number(bucket.skipped || 0) + 1
        }
    }

    _recordBaselineResolution(kind = "replay") {
        const planner = this._performanceTelemetry?.planner
        if (!planner) return
        if (kind === "captured") {
            planner.baselineCapturedReuseCount += 1
            return
        }
        planner.baselineReplayCount += 1
    }

    _recordTaskQueued(task) {
        if (!task) return
        task._queuedAt = Date.now()
        const queue = this._performanceTelemetry?.queue
        if (queue) {
            queue.tasksQueued += 1
            queue.depthMax = Math.max(queue.depthMax || 0, this._taskQueueCount())
            queue.readyGroupsMax = Math.max(queue.readyGroupsMax || 0, this._taskReadyGroups?.length || 0)
        }
        const moduleBucket = this._perfModuleBucket(task.moduleId || task.module?.id || task.moduleName || "module")
        if (moduleBucket) {
            moduleBucket.planned += 1
        }
        const familyBucket = this._perfFamilyBucket(task._familyKey || this._taskFamilyKey(task))
        if (familyBucket) {
            familyBucket.planned += 1
        }
    }

    _recordTaskDequeued(task, waitMs = 0) {
        const queue = this._performanceTelemetry?.queue
        if (queue) {
            queue.tasksDequeued += 1
            queue.waitMsTotal += Math.max(0, Number(waitMs || 0))
            queue.waitMsMax = Math.max(queue.waitMsMax || 0, Math.max(0, Number(waitMs || 0)))
        }
        const moduleBucket = this._perfModuleBucket(task?.moduleId || task?.module?.id || task?.moduleName || "module")
        if (moduleBucket) {
            moduleBucket.dequeued += 1
            moduleBucket.queueWaitMsTotal += Math.max(0, Number(waitMs || 0))
            moduleBucket.queueWaitMsMax = Math.max(moduleBucket.queueWaitMsMax || 0, Math.max(0, Number(waitMs || 0)))
        }
    }

    _recordTaskExecution(task, durationMs = 0) {
        const execution = this._performanceTelemetry?.execution
        if (execution) {
            execution.tasksCompleted += 1
            execution.totalMs += Math.max(0, Number(durationMs || 0))
            execution.maxMs = Math.max(execution.maxMs || 0, Math.max(0, Number(durationMs || 0)))
        }
        const moduleBucket = this._perfModuleBucket(task?.moduleId || task?.module?.id || task?.moduleName || "module")
        if (moduleBucket) {
            moduleBucket.completed += 1
            moduleBucket.executionMsTotal += Math.max(0, Number(durationMs || 0))
            moduleBucket.executionMsMax = Math.max(moduleBucket.executionMsMax || 0, Math.max(0, Number(durationMs || 0)))
        }
        const familyBucket = this._perfFamilyBucket(task?._familyKey || this._taskFamilyKey(task))
        if (familyBucket) {
            familyBucket.completed += 1
            familyBucket.executionMsTotal += Math.max(0, Number(durationMs || 0))
            familyBucket.executionMsMax = Math.max(familyBucket.executionMsMax || 0, Math.max(0, Number(durationMs || 0)))
        }
    }

    _normalizePlanningMethods(values) {
        return Array.isArray(values)
            ? values.map((value) => String(value || "").toUpperCase()).filter(Boolean)
            : []
    }

    _planningFingerprintFromSchema(schema) {
        if (!schema) return null
        const request = schema?.request || {}
        const base = this._fingerprintFromSchema(schema) || this._fingerprintFromRequest(request) || "request"
        const headers = Array.isArray(request?.headers) ? request.headers : []
        const queryNames = new Set()
        const bodyParamNames = new Set()
        const jsonKeys = new Set()
        const cookieNames = new Set()

        try {
            const targetUrl = request?.url || request?.path || "/"
            const baseUrl = this._guessRequestBase(request)
            const resolved = new URL(targetUrl, targetUrl && targetUrl.startsWith("http") ? undefined : baseUrl || "http://localhost")
            resolved.searchParams.forEach((_, key) => queryNames.add(String(key || "").toLowerCase()))
        } catch (_) {
            // Ignore malformed targets for cache-key purposes.
        }

        if (Array.isArray(request?.queryParams)) {
            for (const param of request.queryParams) {
                if (param?.name) queryNames.add(String(param.name).toLowerCase())
            }
        }
        if (Array.isArray(request?.body?.params)) {
            for (const param of request.body.params) {
                if (param?.name) bodyParamNames.add(String(param.name).toLowerCase())
            }
        }
        if (request?.body?.json && typeof request.body.json === "object" && !Array.isArray(request.body.json)) {
            Object.keys(request.body.json).forEach((key) => jsonKeys.add(String(key || "").toLowerCase()))
        }
        if (Array.isArray(request?.cookies)) {
            for (const cookie of request.cookies) {
                if (cookie?.name) cookieNames.add(String(cookie.name).toLowerCase())
            }
        } else {
            const cookieHeader = headers.find((header) => String(header?.name || "").toLowerCase() === "cookie")
            const cookieText = String(cookieHeader?.value || "")
            cookieText.split(";").forEach((entry) => {
                const name = String(entry || "").split("=")[0].trim().toLowerCase()
                if (name) cookieNames.add(name)
            })
        }

        const hasNonCookieHeaders = headers.some((header) => String(header?.name || "").toLowerCase() !== "cookie")
        const contentTypeHeader = headers.find((header) => String(header?.name || "").toLowerCase() === "content-type")
        const contentType = String(contentTypeHeader?.value || request?.body?.mimeType || "").toLowerCase()
        const bodyText = typeof request?.body?.text === "string" ? request.body.text : ""
        const hasJsonBody = !!(
            (request?.body?.json && typeof request.body.json === "object")
            || contentType.includes("application/json")
            || contentType.includes("text/json")
            || contentType.includes("+json")
        )
        const hasXmlBody = !!(
            bodyText
            && (contentType.includes("/xml") || contentType.includes("+xml") || /^\s*<[\w:.-]+[\s>]/.test(bodyText))
        )
        const parts = [
            base,
            `body:${bodyText || Array.isArray(request?.body?.params) ? 1 : 0}`,
            `json:${hasJsonBody ? 1 : 0}`,
            `xml:${hasXmlBody ? 1 : 0}`,
            `cookies:${cookieNames.size ? 1 : 0}`,
            `headers:${hasNonCookieHeaders ? 1 : 0}`
        ]
        const querySig = Array.from(queryNames).sort().join(",")
        const bodySig = Array.from(bodyParamNames).sort().join(",")
        const jsonSig = Array.from(jsonKeys).sort().join(",")
        const cookieSig = Array.from(cookieNames).sort().join(",")
        if (querySig) parts.push(`qp:${querySig}`)
        if (bodySig) parts.push(`bp:${bodySig}`)
        if (jsonSig) parts.push(`jk:${jsonSig}`)
        if (cookieSig) parts.push(`ck:${cookieSig}`)
        return parts.join("|")
    }

    _requestPlanningSummary(schema) {
        if (schema && typeof schema === "object") {
            const cached = this._requestPlanningSummaryCache?.get(schema)
            if (cached) return cached
        }
        const planningFingerprint = this._planningFingerprintFromSchema(schema)
        if (planningFingerprint && this._requestPlanningSummaryByFingerprint?.has(planningFingerprint)) {
            const reused = this._requestPlanningSummaryByFingerprint.get(planningFingerprint)
            if (schema && typeof schema === "object") {
                this._requestPlanningSummaryCache?.set(schema, reused)
            }
            return reused
        }
        const request = schema?.request || {}
        const method = String(request?.method || "GET").toUpperCase()
        const headers = Array.isArray(request?.headers) ? request.headers : []
        const hasNonCookieHeaders = headers.some((header) => String(header?.name || "").toLowerCase() !== "cookie")
        const hasCookies = Array.isArray(request?.cookies)
            ? request.cookies.length > 0
            : headers.some((header) => String(header?.name || "").toLowerCase() === "cookie" && String(header?.value || "").trim().length > 0)
        const queryParams = Array.isArray(request?.queryParams) ? request.queryParams : []
        const bodyParams = Array.isArray(request?.body?.params) ? request.body.params : []
        const contentTypeHeader = headers.find((header) => String(header?.name || "").toLowerCase() === "content-type")
        const contentType = String(contentTypeHeader?.value || request?.body?.mimeType || "").toLowerCase()
        const bodyText = typeof request?.body?.text === "string" ? request.body.text : ""
        const hasQueryParams = queryParams.length > 0
        const hasBodyParams = bodyParams.length > 0
        const hasJsonObject = request?.body?.json && typeof request.body.json === "object"
        let hasJsonBody = !!hasJsonObject
        if (!hasJsonBody && bodyText) {
            if (contentType.includes("application/json") || contentType.includes("text/json") || contentType.includes("+json")) {
                hasJsonBody = true
            } else {
                try {
                    const parsed = JSON.parse(bodyText)
                    hasJsonBody = !!(parsed && typeof parsed === "object")
                } catch (_) {
                    hasJsonBody = false
                }
            }
        }
        const hasXmlBody = !!(
            bodyText
            && (contentType.includes("/xml") || contentType.includes("+xml") || /^\s*<[\w:.-]+[\s>]/.test(bodyText))
        )
        const hasBody = hasBodyParams || hasJsonBody || hasXmlBody || bodyText.length > 0
        const summary = {
            method,
            hasBody,
            hasQueryParams,
            hasBodyParams,
            hasJsonBody,
            hasXmlBody,
            hasCookies,
            hasNonCookieHeaders,
            hasAnyParamSurface: hasQueryParams || hasBodyParams || hasJsonBody || hasXmlBody
        }
        if (schema && typeof schema === "object") {
            this._requestPlanningSummaryCache?.set(schema, summary)
        }
        if (planningFingerprint) {
            this._boundedMapSet(this._requestPlanningSummaryByFingerprint, planningFingerprint, summary, 512)
        }
        return summary
    }

    _modulePlanningHints(module) {
        if (!module || typeof module !== "object") {
            return {
                surfaces: new Set(),
                hasGenericAttack: false,
                prefilters: {}
            }
        }
        let cached = this._modulePlanningCache?.get(module)
        if (cached) return cached
        const surfaces = new Set()
        let hasGenericAttack = false
        const attacks = Array.isArray(module?.attacks) ? module.attacks : []
        for (const attack of attacks) {
            const action = attack?.action || {}
            const target = attack?.target || {}
            const hasParams = Array.isArray(action?.params) && action.params.length > 0
            const hasCookies = Array.isArray(action?.cookies) && action.cookies.length > 0
            const hasHeaders = Array.isArray(action?.headers) && action.headers.some((entry) => String(entry?.name || "").toLowerCase() !== "cookie")
            const hasCookieHeader = Array.isArray(action?.headers) && action.headers.some((entry) => String(entry?.name || "").toLowerCase() === "cookie")
            const hasTargetParams = target?.params && typeof target.params === "object" && Object.keys(target.params).length > 0
            const hasTargetCookies = target?.cookies && typeof target.cookies === "object" && Object.keys(target.cookies).length > 0
            const hasTargetHeaders = target?.headers && typeof target.headers === "object" && Object.keys(target.headers).length > 0
            const hasTargetJson = target?.json && typeof target.json === "object" && Object.keys(target.json).length > 0
            const hasTargetXml = target?.xml && typeof target.xml === "object" && Object.keys(target.xml).length > 0
            if (hasParams || hasTargetParams || hasTargetJson || hasTargetXml) surfaces.add("params")
            if (hasCookies || hasCookieHeader || hasTargetCookies) surfaces.add("cookies")
            if (hasHeaders || hasTargetHeaders) surfaces.add("headers")
            if (!hasParams && !hasCookies && !hasHeaders && !hasCookieHeader && !hasTargetParams && !hasTargetCookies && !hasTargetHeaders && !hasTargetJson && !hasTargetXml) {
                hasGenericAttack = true
            }
        }
        const execution = this._moduleExecution(module)
        const prefilters = execution?.prefilters && typeof execution.prefilters === "object"
            ? execution.prefilters
            : {}
        cached = { surfaces, hasGenericAttack, prefilters }
        this._modulePlanningCache?.set(module, cached)
        return cached
    }

    _shouldPlanModuleForRequest(module, schema, _original = null) {
        if (!module || typeof module !== "object") return { allowed: false, reason: "invalid_module" }
        const planningFingerprint = this._planningFingerprintFromSchema(schema) || this._fingerprintFromSchema(schema) || "request"
        const moduleId = String(module?.id || module?.name || "module")
        const cacheKey = `${planningFingerprint}|${moduleId}`
        const cachedDecision = this._planningDecisionCache?.get(cacheKey)
        if (cachedDecision) {
            if (cachedDecision.allowed === false) {
                this._recordModulePlanningSkip(module, cachedDecision.reason || "prefilter_cached")
            }
            return this._clonePlanningDecision(cachedDecision)
        }
        const summary = this._requestPlanningSummary(schema)
        const hints = this._modulePlanningHints(module)
        const methods = this._normalizePlanningMethods(hints.prefilters?.methods)
        if (methods.length && !methods.includes(summary.method)) {
            this._recordModulePlanningSkip(module, "prefilter_methods")
            const decision = { allowed: false, reason: "prefilter_methods" }
            this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
            return decision
        }
        if (hints.prefilters?.requiresBody && !summary.hasBody) {
            this._recordModulePlanningSkip(module, "prefilter_body")
            const decision = { allowed: false, reason: "prefilter_body" }
            this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
            return decision
        }
        if (hints.prefilters?.requiresJsonBody && !summary.hasJsonBody) {
            this._recordModulePlanningSkip(module, "prefilter_json_body")
            const decision = { allowed: false, reason: "prefilter_json_body" }
            this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
            return decision
        }
        if (hints.prefilters?.requiresXmlBody && !summary.hasXmlBody) {
            this._recordModulePlanningSkip(module, "prefilter_xml_body")
            const decision = { allowed: false, reason: "prefilter_xml_body" }
            this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
            return decision
        }
        if (hints.prefilters?.requiresQueryParams && !summary.hasQueryParams) {
            this._recordModulePlanningSkip(module, "prefilter_query_params")
            const decision = { allowed: false, reason: "prefilter_query_params" }
            this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
            return decision
        }
        if (hints.prefilters?.requiresQueryOrBodyParams && !(summary.hasQueryParams || summary.hasBodyParams || summary.hasJsonBody || summary.hasXmlBody)) {
            this._recordModulePlanningSkip(module, "prefilter_query_or_body_params")
            const decision = { allowed: false, reason: "prefilter_query_or_body_params" }
            this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
            return decision
        }
        if (hints.prefilters?.requiresCookies && !summary.hasCookies) {
            this._recordModulePlanningSkip(module, "prefilter_cookies")
            const decision = { allowed: false, reason: "prefilter_cookies" }
            this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
            return decision
        }
        if (hints.prefilters?.requiresHeaders && !summary.hasNonCookieHeaders) {
            this._recordModulePlanningSkip(module, "prefilter_headers")
            const decision = { allowed: false, reason: "prefilter_headers" }
            this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
            return decision
        }
        if (module?.type === "active" && !hints.hasGenericAttack && hints.surfaces.size > 0) {
            let hasRelevantSurface = false
            if (hints.surfaces.has("params") && summary.hasAnyParamSurface) hasRelevantSurface = true
            if (hints.surfaces.has("cookies") && summary.hasCookies) hasRelevantSurface = true
            if (hints.surfaces.has("headers") && summary.hasNonCookieHeaders) hasRelevantSurface = true
            if (!hasRelevantSurface) {
                this._recordModulePlanningSkip(module, "prefilter_inferred_surfaces")
                const decision = { allowed: false, reason: "prefilter_inferred_surfaces" }
                this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
                return decision
            }
        }
        const decision = { allowed: true, reason: null }
        this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
        return decision
    }

    _moduleMetadataView(module) {
        const meta = cloneValue(this._moduleMetadataRaw(module))
        const taxonomy = this._moduleTaxonomy(module)
        const docs = this._moduleDocs(module)
        const execution = this._moduleExecution(module)
        const constants = meta.constants && typeof meta.constants === 'object' ? cloneValue(meta.constants) : {}
        const view = Object.assign({}, meta)
        const legacy = meta.extensions?.legacy && typeof meta.extensions.legacy === 'object'
            ? meta.extensions.legacy
            : {}

        if (taxonomy.severity != null && view.severity == null) view.severity = taxonomy.severity
        if (taxonomy.category != null && view.category == null) view.category = taxonomy.category
        if (taxonomy.vulnId != null && view.vulnId == null) view.vulnId = taxonomy.vulnId
        if (taxonomy.owasp != null && view.owasp == null) view.owasp = cloneValue(taxonomy.owasp)
        if (taxonomy.cwe != null && view.cwe == null) view.cwe = cloneValue(taxonomy.cwe)
        if (taxonomy.tags != null && view.tags == null) view.tags = cloneValue(taxonomy.tags)

        if (docs.description != null && view.description == null) view.description = docs.description
        if (docs.recommendation != null && view.recommendation == null) view.recommendation = docs.recommendation
        if (docs.links != null && view.links == null) view.links = cloneValue(docs.links)

        if (execution.findingSemantics != null && view.findingSemantics == null) view.findingSemantics = execution.findingSemantics
        if (execution.allowStrategyBulk != null && view.allowStrategyBulk == null) view.allowStrategyBulk = execution.allowStrategyBulk
        if (execution.allowAuthLikeTargets != null && view.allowAuthLikeTargets == null) view.allowAuthLikeTargets = execution.allowAuthLikeTargets
        if (execution.allowHardDeniedTargets != null && view.allowHardDeniedTargets == null) view.allowHardDeniedTargets = cloneValue(execution.allowHardDeniedTargets)
        if (execution.ignoreGlobalExcludes != null && view.ignoreGlobalExcludes == null) view.ignoreGlobalExcludes = execution.ignoreGlobalExcludes
        if (execution.requiredEngineCapabilities != null && view.requiredEngineCapabilities == null) {
            view.requiredEngineCapabilities = cloneValue(execution.requiredEngineCapabilities)
        }
        if (execution.capabilities != null && view.capabilities == null) view.capabilities = cloneValue(execution.capabilities)
        if (legacy.uniqueBehavior != null && view.legacyUniqueBehavior == null) view.legacyUniqueBehavior = legacy.uniqueBehavior

        view.constants = constants
        Object.keys(constants).forEach((key) => {
            if (view[key] === undefined) {
                view[key] = cloneValue(constants[key])
            }
        })
        return view
    }

    _attackRuntimeConfig(attack, key) {
        const runtime = attack?.runtime
        if (runtime?.config && typeof runtime.config === 'object' && runtime.config[key] && typeof runtime.config[key] === 'object') {
            return runtime.config[key]
        }
        return null
    }

    _attackRuntimeConfirmation(attack, key) {
        const runtime = attack?.runtime
        if (runtime?.confirmation && typeof runtime.confirmation === 'object' && runtime.confirmation[key] && typeof runtime.confirmation[key] === 'object') {
            return runtime.confirmation[key]
        }
        return null
    }

    _attackMetadataView(module, attack, baseMetadata = {}) {
        const moduleView = this._moduleMetadataView(module)
        const attackMeta = attack?.metadata && typeof attack.metadata === 'object' ? cloneValue(attack.metadata) : {}
        const taxonomy = attackMeta.taxonomy && typeof attackMeta.taxonomy === 'object' ? attackMeta.taxonomy : {}
        const docs = attackMeta.docs && typeof attackMeta.docs === 'object' ? attackMeta.docs : {}
        const attackConstants = attackMeta.constants && typeof attackMeta.constants === 'object' ? cloneValue(attackMeta.constants) : {}
        const constants = Object.assign({}, moduleView.constants || {}, attackConstants)
        const view = Object.assign({}, moduleView, cloneValue(attack || {}), cloneValue(baseMetadata || {}))

        if (taxonomy.severity != null) view.severity = taxonomy.severity
        if (taxonomy.category != null) view.category = taxonomy.category
        if (taxonomy.vulnId != null) view.vulnId = taxonomy.vulnId
        if (taxonomy.owasp != null) view.owasp = cloneValue(taxonomy.owasp)
        if (taxonomy.cwe != null) view.cwe = cloneValue(taxonomy.cwe)
        if (taxonomy.tags != null) view.tags = cloneValue(taxonomy.tags)

        if (docs.description != null) view.description = docs.description
        if (docs.recommendation != null) view.recommendation = docs.recommendation
        if (docs.links != null) view.links = cloneValue(docs.links)

        view.constants = constants
        Object.keys(constants).forEach((key) => {
            if (view[key] === undefined) {
                view[key] = cloneValue(constants[key])
            }
        })

        const spaCfg = this._attackRuntimeConfig(attack, 'spa')
        if (spaCfg && view.spa === undefined) view.spa = cloneValue(spaCfg)
        const oastCfg = this._attackRuntimeConfirmation(attack, 'oast')
        if (oastCfg && view.oast === undefined) view.oast = cloneValue(oastCfg)
        const trackingCfg = this._attackRuntimeConfirmation(attack, 'tracking')
        if (trackingCfg && view.tracking === undefined) view.tracking = cloneValue(trackingCfg)
        const deserCfg = this._attackRuntimeConfig(attack, 'deserialization')
        if (deserCfg && view.deserProfile === undefined) view.deserProfile = cloneValue(deserCfg)

        return view
    }

    async loadModules(options = {}) {
        const runCve = !!options.runCve
        const policyRaw = options.policy || this.settings?.dastScanPolicy || this.settings?.scanPolicy || 'ACTIVE'
        const policy = String(policyRaw || 'ACTIVE').toUpperCase()
        const customBaseModules = extractModulesFromRulepack(options.rulepack, {
            engine: 'DAST',
            childKey: 'attacks',
            label: 'base'
        })
        const baseModules = Array.isArray(customBaseModules)
            ? customBaseModules
            : await this._ensureBaseModules()
        let moduleDefs = Array.isArray(baseModules) ? baseModules : []
        if (runCve) {
            const customCveModules = extractModulesFromRulepack(options.cveRulepack, {
                engine: 'DAST',
                childKey: 'attacks',
                label: 'cve'
            })
            const cveModules = Array.isArray(customCveModules)
                ? customCveModules
                : await this._ensureCveModules()
            if (cveModules && cveModules.length) {
                moduleDefs = mergeModuleDefinitions(baseModules, cveModules)
            }
        }
        if (policy === 'RECON' || policy === 'RECONNAISSANCE' || policy === 'PASSIVE') {
            moduleDefs = moduleDefs.filter(m => (m?.type || '').toLowerCase() === 'passive')
        }
        this.modules = moduleDefs.map(m => new ptk_module(m))
        this._syncScanControlsToModules()
        return this.modules
    }

    async _ensureBaseModules() {
        if (Array.isArray(this._rawBaseModules)) {
            return this._rawBaseModules
        }
        if (!this._baseRulepackPromise) {
            this._baseRulepackPromise = loadCanonicalRulepack('DAST')
        }
        const rulepack = await this._baseRulepackPromise
        const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
        this._rawBaseModules = modules
        return modules
    }

    async _ensureCveModules() {
        if (Array.isArray(this._rawCveModules)) {
            return this._rawCveModules
        }
        if (!this._cveRulepackPromise) {
            this._cveRulepackPromise = loadCanonicalRulepack('DAST', { variant: 'cve' })
                .then(rulepack => Array.isArray(rulepack?.modules) ? rulepack.modules : [])
                .catch(err => {
                    console.warn('[PTK DAST] Failed to load CVE modules', err)
                    return []
                })
        }
        const modules = await this._cveRulepackPromise
        this._rawCveModules = modules
        return modules
    }


    async loadProModules() {
        // let self = this
        // this.pro_modules = []
        // let apiKey = worker.ptk_app?.settings?.profile?.api_key
        // let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.attacks_endpoint
        // if (apiKey) {
        //     return await fetch(url, { headers: { 'Authorization': apiKey }, cache: "no-cache" })
        //         .then(response => response.json())
        //         .then(json => {
        //             let modules = JSON.parse(json.rules.modules.json).modules
        //             Object.values(modules).forEach(module => {
        //                 self.pro_modules.push(new ptk_module(module))
        //             })
        //         }).catch(e => {
        //             console.log(e)
        //             return { "success": false, "json": { "message": e.message } }
        //         })
        // }
    }

    getEmptyScanResult() {
        const strategyName = this.strategyConfig?.strategy || DEFAULT_SCAN_STRATEGY
        const envelope = createScanResultEnvelope({
            engine: "DAST",
            scanId: null,
            host: null,
            tabId: null,
            startedAt: new Date().toISOString(),
            settings: this._buildExportableScanSettings({
                scanStrategy: strategyName
            })
        })
        envelope.version = envelope.version || "1.0"
        delete envelope.items
        delete envelope.type
        delete envelope.tabId
        envelope.recon = []
        envelope.requests = []
        envelope.pages = []
        envelope.runtimeEvents = []
        envelope.stats = Object.assign({}, envelope.stats, {
            high: 0,
            medium: 0,
            low: 0,
            attacksCount: 0
        })
        envelope.scanStats = this._createStrategyStats(strategyName)
        return envelope
    }

    canSendRequest() {
        const now = Date.now()
        if (now - this.lastRefill > this.tokenRefillInterval) {
            this.tokens = this.maxRequestsPerSecond
            this.lastRefill = now
        }
        if (this.tokens > 0) {
            this.tokens--
            return true
        }
        return false
    }

    _requestHeaderRichnessScore(rawRequest) {
        const raw = typeof rawRequest === 'object' ? (rawRequest.raw || '') : (rawRequest || '')
        const text = String(raw || '')
        if (!text.trim()) return 0
        const lines = text.split(/\r?\n/)
        if (!lines.length) return 0
        let score = 0
        let headerCount = 0
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i]
            if (!line || !line.trim()) break
            const sep = line.indexOf(':')
            if (sep <= 0) continue
            headerCount += 1
            const name = line.slice(0, sep).trim().toLowerCase()
            const value = line.slice(sep + 1).trim()
            if (name === 'cookie' && value) score += 35
            else if (name === 'authorization' && value) score += 30
            else if (name === 'user-agent' && value) score += 18
            else if (name.startsWith('sec-ch-') && value) score += 10
            else if ((name === 'accept' || name === 'origin' || name === 'referer' || name === 'content-type') && value) score += 8
            else if (name === 'host' && value) score += 2
            else if (value) score += 4
        }
        score += Math.min(headerCount, 24) * 6
        score += Math.min(text.length, 4096) / 512
        return score
    }

    _normalizeCapturedResponse(response) {
        if (!response || typeof response !== 'object') return null
        const headers = this._normalizeHttpHeaders(response.headers || response.responseHeaders)
        const statusCode = response.statusCode ?? response.status ?? null
        const body = typeof response.body === 'string' ? response.body : null
        const length = typeof response.length === 'number'
            ? response.length
            : (typeof body === 'string' ? body.length : null)
        const normalized = {
            url: response.url || null,
            ui_url: response.ui_url || response.uiUrl || response.url || null,
            method: response.method || null,
            type: response.type || response.responseType || null,
            statusCode,
            status: response.status ?? statusCode,
            statusMessage: response.statusMessage || null,
            statusText: response.statusText || null,
            statusLine: response.statusLine || null,
            mimeType: response.mimeType || null,
            headers: headers || [],
            body,
            length,
            timeMs: typeof response.timeMs === 'number' ? response.timeMs : null
        }
        if (normalized.statusCode == null && !normalized.headers.length && !normalized.body) {
            return null
        }
        return normalized
    }

    _normalizeQueuedRequestPayload(rawRequest, dedupeKey, response = null) {
        const payload = (rawRequest && typeof rawRequest === 'object')
            ? Object.assign({}, rawRequest)
            : { raw: rawRequest }
        payload.__dedupeKey = dedupeKey
        const capturedResponse = this._normalizeCapturedResponse(response)
        if (capturedResponse) {
            payload.capturedResponse = capturedResponse
        }
        return payload
    }

    _capturedOriginalSatisfiesRequirements(capturedResponse, modules = []) {
        if (!capturedResponse || typeof capturedResponse !== 'object') return false
        const hasStatus = Number.isFinite(Number(capturedResponse.statusCode))
        const hasHeaders = Array.isArray(capturedResponse.headers) && capturedResponse.headers.length > 0
        const hasBody = typeof capturedResponse.body === 'string'
        for (const module of (Array.isArray(modules) ? modules : [])) {
            const attacks = Array.isArray(module?.attacks) ? module.attacks : []
            for (const attack of attacks) {
                if (typeof module?.getAttackOriginalRequirements !== 'function') {
                    return false
                }
                const requirements = module.getAttackOriginalRequirements(attack)
                if (requirements?.needsOtherResponseData) return false
                if (requirements?.needsStatus && !hasStatus) return false
                if (requirements?.needsHeaders && !hasHeaders) return false
                if (requirements?.needsBody && !hasBody) return false
            }
        }
        return true
    }

    _buildCapturedOriginalFromMeta(schema, rawMeta, modules = []) {
        const capturedResponse = this._normalizeCapturedResponse(rawMeta?.capturedResponse || null)
        if (!this._capturedOriginalSatisfiesRequirements(capturedResponse, modules)) {
            return null
        }
        const request = cloneValue(schema?.request || {})
        request.raw = request.raw || rawMeta?.raw || null
        if (!request.ui_url && (rawMeta?.ui_url || rawMeta?.uiUrl)) {
            request.ui_url = rawMeta?.ui_url || rawMeta?.uiUrl
        }
        if (!request.url && capturedResponse?.url) {
            request.url = capturedResponse.url
        }
        const response = {
            statusCode: capturedResponse.statusCode,
            status: capturedResponse.status ?? capturedResponse.statusCode,
            headers: cloneValue(capturedResponse.headers || [])
        }
        if (capturedResponse.statusMessage) {
            response.statusMessage = capturedResponse.statusMessage
        }
        if (capturedResponse.statusText) {
            response.statusText = capturedResponse.statusText
        }
        if (capturedResponse.statusLine) {
            response.statusLine = capturedResponse.statusLine
        }
        if (capturedResponse.mimeType) {
            response.mimeType = capturedResponse.mimeType
        }
        if (typeof capturedResponse.body === 'string') {
            response.body = capturedResponse.body
            response.length = capturedResponse.body.length
        } else if (typeof capturedResponse.length === 'number') {
            response.length = capturedResponse.length
        }
        if (typeof capturedResponse.timeMs === 'number') {
            response.timeMs = capturedResponse.timeMs
        }
        return {
            request,
            response
        }
    }

    async _resolveOriginalForPlan(schema, rawMeta = {}, options = {}) {
        const modules = Array.isArray(options?.modules) ? options.modules : []
        const originalCacheKey = ptk_request.fingerprintRawRequest(rawMeta?.raw || schema?.request?.raw || "")
            || rawMeta?.__dedupeKey
            || null
        const cachedOriginal = originalCacheKey ? this._resolvedOriginalCache?.get(originalCacheKey) : null
        if (cachedOriginal) {
            this._recordBaselineResolution("captured")
            const nextOriginal = cloneValue(cachedOriginal)
            this._applyRequestDiscoveryMetadata(nextOriginal, rawMeta)
            return nextOriginal
        }
        const capturedOriginal = this._buildCapturedOriginalFromMeta(schema, rawMeta, modules)
        if (capturedOriginal) {
            this._applyRequestDiscoveryMetadata(capturedOriginal, rawMeta)
            this._recordBaselineResolution("captured")
            if (originalCacheKey) {
                const cacheOriginal = cloneValue(capturedOriginal)
                this._stripRequestDiscoveryMetadata(cacheOriginal)
                this._boundedMapSet(this._resolvedOriginalCache, originalCacheKey, cacheOriginal, 256)
            }
            return capturedOriginal
        }
        this._recordBaselineResolution("replay")
        const original = await this.executeOriginal(schema)
        this._applyRequestDiscoveryMetadata(original, rawMeta)
        if (originalCacheKey && original) {
            const cacheOriginal = cloneValue(original)
            this._stripRequestDiscoveryMetadata(cacheOriginal)
            this._boundedMapSet(this._resolvedOriginalCache, originalCacheKey, cacheOriginal, 256)
        }
        return original
    }

    _replacePendingQueuedRequest(dedupeKey, payload) {
        if (!this._requestQueue?.size || this._requestQueue.size() <= 0) return false
        const buffer = this._requestQueue._buffer
        const head = this._requestQueue._head || 0
        if (!Array.isArray(buffer)) return false
        for (let i = buffer.length - 1; i >= head; i--) {
            const item = buffer[i]
            if (item && typeof item === 'object' && item.__dedupeKey === dedupeKey) {
                buffer[i] = payload
                return true
            }
        }
        return false
    }

    enqueue(rawRequest, response) {
        if (!this.isAllowed(response)) return

        const raw = typeof rawRequest === 'object' ? rawRequest.raw : rawRequest
        const fpHint = typeof rawRequest === 'object' ? rawRequest.fingerprint : null
        const canonicalFingerprint = this._simpleFingerprint(rawRequest, response)
        const secondaryFingerprint = canonicalFingerprint ? null : ptk_request.fingerprintRawRequest(raw)
        const prefersHint = fpHint && fpHint.startsWith('spa:')
        const dedupeKey = prefersHint ? fpHint : (canonicalFingerprint || secondaryFingerprint)

        if (!dedupeKey) return
        if (!this._fingerprintMeta) this._fingerprintMeta = new Map()
        const quality = this._requestHeaderRichnessScore(rawRequest)
        const existing = this._fingerprintMeta.get(dedupeKey)
        const qualityDelta = 8
        const payload = this._normalizeQueuedRequestPayload(rawRequest, dedupeKey, response)
        if (!existing) {
            this._fingerprintMeta.set(dedupeKey, {
                quality,
                count: 1,
                upgraded: 0
            })
            this._requestQueue.enqueue(payload)
            return
        }
        if (quality > (existing.quality + qualityDelta)) {
            existing.quality = quality
            existing.count = (existing.count || 0) + 1
            existing.upgraded = (existing.upgraded || 0) + 1
            if (this._replacePendingQueuedRequest(dedupeKey, payload)) {
                this._fingerprintMeta.set(dedupeKey, existing)
                return
            }
            this._fingerprintMeta.set(dedupeKey, existing)
            this._requestQueue.enqueue(payload)
            return
        }
        existing.count = (existing.count || 0) + 1
        this._fingerprintMeta.set(dedupeKey, existing)
    }



    isAllowed(response) {
        let allowed = true
        const rawUrl = response?.ui_url || response?.url || ''
        const sourceUrl = response?.url || rawUrl
        if (!sourceUrl) return false
        let url = null
        try {
            url = new URL(sourceUrl)
        } catch (_) {
            return false
        }
        const params = getSearchParamsFromUrlOrHash(rawUrl)
        const hasParams = [...params.keys()].length > 0
        const method = String(response?.method || 'GET').toUpperCase()
        const isStateChanging = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)
        const blacklist = Array.isArray(this.settings?.blacklist) ? this.settings.blacklist : []
        // Never drop state-changing requests because they frequently carry sink inputs
        // in body/json (for example auth/login or mutation APIs) without query params.
        if (blacklist.includes(response.type) && !hasParams && !isStateChanging) {
            allowed = false
        } else {
            const allowedHost = String(this.host || '')
            const allowedDomains = Array.isArray(this.domains) ? this.domains : []
            if (!url.host.includes(allowedHost) &&
                allowedDomains.findIndex(i => url.host.includes(i)) < 0) {
                allowed = false
            }
        }
        return allowed
    }

    updateScanResult(result, data) {
        if (!this.scanResult.stats) {
            this.scanResult.stats = {
                high: 0,
                medium: 0,
                low: 0,
                attacksCount: 0,
                findingsCount: 0
            }
        }
        const stats = this.scanResult.stats

        if (result) {
            const attacks = Array.isArray(result.attacks) ? result.attacks : []
            stats.attacksCount = (stats.attacksCount || 0) + attacks.length
            attacks.forEach((attack, index) => {
                if (attack?.success) {
                    if (this._isReconAttackResult(attack)) {
                        this._addReconObservation(result.requestRecord || { original: result.original }, attack, index)
                    } else {
                        this._addUnifiedFinding(result.requestRecord || { original: result.original }, attack, index)
                    }
                }
            })
            this._seedHtmlDiscoveredRequests(result.requestRecord?.original || result.original || null)
        }

        if (data) {
            this._confirmAttackFromContent(data)
        }

        stats.findingsCount = stats.findingsCount || 0
        this.scanResult.stats = stats
        this._syncScanStats()

        if (result) {
            const delta = this._buildPlanDelta(result)
            this._emitDeltaMessage("dast_plan_completed", delta)
        }
        if (result || data) {
            this._notifyResultMutation({
                type: result ? 'plan_completed' : 'runtime_update',
                requestId: result?.requestRecord?.id || null
            })
        }
    }

    _buildPlanDelta(result) {
        if (!result) return null
        const requestRecord = result.requestRecord || null
        const requestId = requestRecord?.id || null
        const original = this._buildDeltaOriginalSummary(requestRecord?.original || result.original || null)
        const attacksSource = Array.isArray(requestRecord?.attacks)
            ? requestRecord.attacks
            : (Array.isArray(result.attacks) ? result.attacks : [])
        const attacks = attacksSource
            .map(attack => this._buildDeltaAttackSummary(attack))
            .filter(Boolean)
        return {
            requestId,
            original,
            attacks
        }
    }

    _emitDeltaMessage(type, delta) {
        if (!delta) return
        browser.runtime.sendMessage({
            channel: "ptk_background2popup_rattacker",
            type,
            delta
        }).catch(e => e)
    }

    _notifyResultMutation(payload = null) {
        if (typeof this._resultMutationListener !== 'function') return
        try {
            this._resultMutationListener(payload || null)
        } catch (err) {
            console.warn('[PTK DAST] Result mutation listener failed', {
                type: payload?.type || null,
                requestId: payload?.requestId || null,
                error: err?.message || String(err)
            })
        }
    }

    _normalizeHttpHeaders(headers) {
        if (!Array.isArray(headers)) return null
        const normalized = headers
            .map((header) => {
                if (!header || typeof header !== 'object') return null
                const name = header.name || header.key || null
                if (!name) return null
                const value = header.value === undefined || header.value === null
                    ? ''
                    : String(header.value)
                return { name, value }
            })
            .filter(Boolean)
        return normalized.length ? normalized : null
    }

    _extractRequestShape(entry) {
        if (!entry || typeof entry !== 'object') return null
        if (entry.request && typeof entry.request === 'object') {
            return entry.request
        }
        return entry
    }

    _extractResponseShape(entry) {
        if (!entry || typeof entry !== 'object') return null
        if (entry.response && typeof entry.response === 'object') {
            return entry.response
        }
        return entry
    }

    _applyRequestDiscoveryMetadata(original, rawMeta = {}) {
        if (!original || typeof original !== 'object') return original
        const request = original.request && typeof original.request === 'object'
            ? original.request
            : null
        if (!request) return original
        const discoverySource = String(rawMeta?.discoverySource || '').trim().toLowerCase()
        if (!discoverySource) return original
        request.discoverySource = discoverySource
        const discoveryLabel = String(rawMeta?.discoveryLabel || '').trim()
        if (discoveryLabel) request.discoveryLabel = discoveryLabel
        const discoveryParentUrl = String(rawMeta?.discoveryParentUrl || '').trim()
        if (discoveryParentUrl) request.discoveryParentUrl = discoveryParentUrl
        return original
    }

    _stripRequestDiscoveryMetadata(original) {
        if (!original || typeof original !== 'object') return original
        const request = original.request && typeof original.request === 'object'
            ? original.request
            : null
        if (!request) return original
        delete request.discoverySource
        delete request.discoveryLabel
        delete request.discoveryParentUrl
        return original
    }

    _compactRequestForStorage(entry, { includeRaw = true, includeHeaders = true, includeBody = true } = {}) {
        const request = this._extractRequestShape(entry)
        if (!request || typeof request !== 'object') return null
        const compact = {}
        const requestTimestamp = Number(request.timestamp ?? request.timeStamp ?? request.ts)
        if (Number.isFinite(requestTimestamp) && requestTimestamp >= 0) {
            compact.timestamp = Math.round(requestTimestamp)
        }
        if (request.url) compact.url = request.url
        if (request.ui_url) compact.ui_url = request.ui_url
        if (request.method) compact.method = request.method
        if (request.discoverySource) compact.discoverySource = request.discoverySource
        if (request.discoveryLabel) compact.discoveryLabel = request.discoveryLabel
        if (request.discoveryParentUrl) compact.discoveryParentUrl = request.discoveryParentUrl
        if (includeRaw && typeof request.raw === 'string' && request.raw.length) {
            compact.raw = request.raw
        }
        if (includeHeaders) {
            const headers = this._normalizeHttpHeaders(request.headers)
            if (headers) compact.headers = headers
        }
        if (includeBody && request.body !== undefined) {
            compact.body = cloneValue(request.body)
        }
        return Object.keys(compact).length ? compact : null
    }

    _compactResponseForStorage(entry, {
        includeBody = true,
        includeHeaders = true,
        includeRaw = false,
        fallbackLength = null,
        fallbackTimeMs = null
    } = {}) {
        const response = this._extractResponseShape(entry)
        if (!response || typeof response !== 'object') return null
        const compact = {}
        const statusCode = response.statusCode ?? response.status
        if (statusCode !== undefined && statusCode !== null) compact.statusCode = statusCode
        if (response.status !== undefined && response.status !== null) compact.status = response.status
        if (response.statusMessage) compact.statusMessage = response.statusMessage
        if (response.statusText) compact.statusText = response.statusText
        if (response.statusLine) compact.statusLine = response.statusLine
        if (response.errorName) compact.errorName = response.errorName
        if (response.errorMessage) compact.errorMessage = response.errorMessage
        if (response.errorCause) compact.errorCause = response.errorCause
        if (response.mimeType) compact.mimeType = response.mimeType
        if (includeHeaders) {
            const headers = this._normalizeHttpHeaders(response.headers)
            if (headers) compact.headers = headers
        }
        if (includeBody && typeof response.body === 'string') {
            compact.body = response.body
        }
        if (includeRaw && typeof response.raw === 'string' && response.raw.length) {
            compact.raw = response.raw
        }
        const length = typeof response.length === 'number'
            ? response.length
            : (typeof fallbackLength === 'number' ? fallbackLength : null)
        if (typeof length === 'number') compact.length = length
        const timeMs = typeof response.timeMs === 'number'
            ? response.timeMs
            : (typeof fallbackTimeMs === 'number' ? fallbackTimeMs : null)
        if (typeof timeMs === 'number') compact.timeMs = timeMs
        return Object.keys(compact).length ? compact : null
    }

    _compactOriginalRecord(original) {
        if (!original || typeof original !== 'object') return null
        const sourceRequest = original.request && typeof original.request === 'object'
            ? original.request
            : original
        const sourceResponse = original.response && typeof original.response === 'object'
            ? original.response
            : null
        const request = this._compactRequestForStorage(sourceRequest, {
            includeRaw: true,
            includeHeaders: true,
            includeBody: true
        })
        const response = this._compactResponseForStorage(sourceResponse, {
            includeBody: true,
            includeHeaders: true,
            includeRaw: false
        })
        if (!request && !response) return null
        const compact = {}
        if (request) compact.request = request
        if (response) compact.response = response
        return compact
    }

    _buildDeltaOriginalSummary(original) {
        const request = this._compactRequestForStorage(original, {
            includeRaw: false,
            includeHeaders: false,
            includeBody: false
        })
        if (!request) return null
        if (request.ui_url && !request.url) {
            request.url = request.ui_url
        }
        return request
    }

    _buildDeltaAttackSummary(attack) {
        if (!attack || typeof attack !== 'object') return null
        const request = this._compactRequestForStorage(attack.request, {
            includeRaw: false,
            includeHeaders: false,
            includeBody: false
        })
        const response = this._compactResponseForStorage(attack.response, {
            includeBody: false,
            includeHeaders: false,
            includeRaw: false,
            fallbackLength: attack.length,
            fallbackTimeMs: attack.timeMs
        }) || {}
        const summary = {
            id: attack.id || null,
            findingId: attack.findingId || null,
            success: !!attack.success,
            proof: attack.proof || null,
            payload: attack.payload || null,
            param: attack.param || null,
            name: attack.name || null,
            moduleId: attack.moduleId || null,
            moduleName: attack.moduleName || null,
            ruleId: attack.ruleId || null,
            ruleName: attack.ruleName || null,
            category: attack.category || null,
            severity: attack.severity || null,
            vulnId: attack.vulnId || null,
            outputKind: attack.outputKind || null,
            reconKind: attack.reconKind || null,
            presentationAggregate: attack.presentationAggregate || null,
            uiSurface: attack.uiSurface || null,
            statusCode: response.statusCode ?? attack.statusCode ?? null,
            timeMs: response.timeMs ?? attack.timeMs ?? null,
            length: response.length ?? attack.length ?? null
        }
        Object.keys(summary).forEach((key) => {
            if (summary[key] === null || summary[key] === undefined) {
                delete summary[key]
            }
        })
        if (request) summary.request = request
        if (Object.keys(response).length) summary.response = response
        return summary
    }

    async start(tabId, host, domains, settings = {}) {
        const nextSettings = Object.assign({}, this.settings || {}, settings || {})
        // Rulepack overrides are per-run inputs. If a new run does not provide
        // them, clear any previous snapshot so scans fall back to the built-in pack.
        if (!Object.prototype.hasOwnProperty.call(settings || {}, 'rulepack')) {
            nextSettings.rulepack = null
        }
        if (!Object.prototype.hasOwnProperty.call(settings || {}, 'cveRulepack')) {
            nextSettings.cveRulepack = null
        }
        if (!Object.prototype.hasOwnProperty.call(settings || {}, 'enableHtmlLinkDiscovery')) {
            nextSettings.enableHtmlLinkDiscovery = false
        }
        if (!Object.prototype.hasOwnProperty.call(settings || {}, 'htmlLinkDiscoveryBudget')) {
            nextSettings.htmlLinkDiscoveryBudget = DEFAULT_HTML_LINK_DISCOVERY_BUDGET
        }
        this.settings = nextSettings
        this.requestTimeoutMs = this._resolveTimeoutMs(
            this.settings?.requestTimeoutMs,
            DEFAULT_DAST_REQUEST_TIMEOUT_MS
        )
        this.originalRequestTimeoutMs = this._resolveTimeoutMs(
            this.settings?.originalRequestTimeoutMs,
            this.requestTimeoutMs || DEFAULT_DAST_ORIGINAL_REQUEST_TIMEOUT_MS
        )
        this.reset()
        this.tabId = tabId
        this.scanResult.host = this.host = host
        const started = new Date().toISOString()
        this.scanResult.startedAt = started
        this.scanResult.finishedAt = null
        this.domains = domains
        this.isRunning = true
        this.scanResult.scanId = this.scanId = ptk_utils.UUID()
        const runCveEnabled = !!(this.settings && this.settings.runCve)
        const dastScanPolicy = this.settings?.dastScanPolicy || this.settings?.scanPolicy || 'ACTIVE'
        this._moduleLoadPromise = this.loadModules({
            runCve: runCveEnabled,
            policy: dastScanPolicy,
            rulepack: this.settings?.rulepack,
            cveRulepack: this.settings?.cveRulepack
        })

        this.maxRequestsPerSecond = this.settings.maxRequestsPerSecond || this.maxRequestsPerSecond || 5
        this.concurrency = this.settings.concurrency || this.concurrency || 1
        this.planningConcurrency = this.settings.planningConcurrency || this.planningConcurrency || Math.min(2, Math.max(1, this.concurrency || 1))
        const requestedStrategy = this.settings.scanStrategy || this.settings.dastScanStrategy
        this._applyScanStrategy(requestedStrategy)
        this._applyScanControls(
            this.settings?.scanControls || (
                this.settings?.safetyProfile
                    ? { profile: this.settings.safetyProfile }
                    : null
            ),
            { emitWarnings: true }
        )
        this._syncScanSettings({
            scanStrategy: this.strategyConfig.strategy,
            scanControls: this._scanControlsSummary(),
            runCve: runCveEnabled,
            dastScanPolicy,
            enableHtmlLinkDiscovery: this._isHtmlLinkDiscoveryEnabled(),
            htmlLinkDiscoveryBudget: this._normalizeHtmlLinkDiscoveryBudget(this.settings?.htmlLinkDiscoveryBudget),
            requestTimeoutMs: this.requestTimeoutMs,
            originalRequestTimeoutMs: this.originalRequestTimeoutMs,
            planningConcurrency: this.planningConcurrency
        })

        this.inProgress = false
        this._appendRuntimeEvent({
            type: 'dast_patch_marker_v1',
            phase: 'scan_start',
            strategy: this.strategyConfig?.strategy || null
        })
        this.run()
        this._emitProgress({ message: 'Scan started' }, { force: true })
    }

    stop() {
        this.isRunning = false
        this.inProgress = false
        this._detachOastCallbackProbe()
        const pendingPlans = this._activePlans ? Array.from(this._activePlans.values()) : []
        for (const plan of pendingPlans) {
            plan.pending = 0
            this._finalizePlan(plan)
        }
        if (this._activePlans) this._activePlans.clear()
        if (this._taskWorkers) this._taskWorkers.clear()
        this._resetTaskQueues()
        if (this._moduleLocks) this._moduleLocks.clear()
        this._resolveIdleResolvers()
        if (this.scanResult) {
            const finished = new Date().toISOString()
            this.scanResult.finishedAt = finished
        }
        this._emitProgress({ message: 'Scan stopped' }, { force: true })
        ptk_request.clearStoredHeaders()
    }

    async run() {
        if (!this.isRunning) return

        if (this.inProgress) return
        this.inProgress = true
        try {
            const planningConcurrency = Math.max(1, this.planningConcurrency || 1)
            if (planningConcurrency === 1 && this.concurrency === 1) {
                await this.runSequential()
            } else {
                await this.runParallel()
            }
            this._drainPendingHtmlDiscoveryQueue()
        } finally {
            this.inProgress = false
            this._notifyIdleResolvers()
        }

        if (this.isRunning) {
            setTimeout(() => this.run(), 200)
        }
    }

    async runSequential() {
        await this._drainRequestQueue()
        this._ensureTaskWorkers()
    }

    async runParallel() {
        const planningConcurrency = Math.max(1, this.planningConcurrency || this.concurrency || 1)
        const workers = []
        for (let i = 0; i < planningConcurrency; i++) {
            workers.push(this._drainRequestQueue())
        }
        await Promise.all(workers)
        this._ensureTaskWorkers()
    }

    async onetimeScanRequest(raw) {
        let result = await this.scanRequest(raw, true)
        let stats = { findingsCount: 0, high: 0, medium: 0, low: 0, attacksCount: 0 }
        for (let i in result.attacks) {
            stats.attacksCount++
            if (result.attacks[i].success && !this._isReconAttackResult(result.attacks[i])) {
                stats.findingsCount++
                if (result.attacks[i].metadata.severity == 'High') stats.high++
                if (result.attacks[i].metadata.severity == 'Medium') stats.medium++
                if (result.attacks[i].metadata.severity == 'Low') stats.low++
            }
        }
        return Object.assign({}, result, { stats: stats })
    }

    async buildAttackPlan(raw) {
        const startedAt = Date.now()
        const plan = await this.taskPlanner.buildAttackPlan(raw)
        this._recordPlanBuild(plan, Date.now() - startedAt)
        return plan
    }

    _enrichAttackPayload(schema, module, attack) {
        if (!schema) return schema
        const payload = cloneValue(schema)
        payload.metadata = this._attackMetadataView(module, attack, payload.metadata)
        return payload
    }

    _createTask({ module, attack, payload, type, fingerprint }) {
        const moduleId = module?.id || null
        const moduleName = module?.name || null
        return {
            id: ptk_utils.attackId(),
            type,
            module,
            moduleId,
            moduleName,
            moduleAsync: module?.async !== false,
            attack,
            attackKey: attack?.id || attack?.name || `${module?.id || 'module'}:${ptk_utils.attackId()}`,
            payload,
            target: payload?.metadata?.attacked || null,
            urlFingerprint: fingerprint || null,
            planLockGroup: moduleId || moduleName || attack?.id || attack?.name || null,
            deferCondition: module?.async === false && !!attack?.condition
        }
    }

    _createTaskContext(original, options = {}) {
        return this.taskPlanner.createTaskContext(original, options)
    }

    _createRequestRecord(original, persist = true) {
        const requests = Array.isArray(this.scanResult.requests) ? this.scanResult.requests : []
        if (!this.scanResult.requests) this.scanResult.requests = requests
        this._requestSeq = (this._requestSeq || 0) + 1
        const requestId = `req-${this._requestSeq}`
        const record = {
            id: requestId,
            original: this._compactOriginalRecord(original),
            attacks: []
        }
        if (persist) {
            requests.push(record)
        }
        return record
    }

    _attachAttackToRecord(record, attackResult) {
        if (!record || !attackResult) return null
        if (!Array.isArray(record.attacks)) {
            record.attacks = []
        }
        if (attackResult.__requestRecordEntry) {
            const existing = attackResult.__requestRecordEntry
            const existingId = existing?.id || null
            const alreadyAttached = record.attacks.includes(existing)
                || (existingId && record.attacks.some((item) => String(item?.id || "") === String(existingId)))
            if (alreadyAttached) {
                return existing
            }
        }
        this._attackSeq = (this._attackSeq || 0) + 1
        const attackId = `atk-${this._attackSeq}`
        const mutation = Array.isArray(attackResult?.metadata?.mutations) ? attackResult.metadata.mutations[0] : null
        const classification = this._buildAttackClassification(attackResult, attackId)
        const reconMeta = this._resolveAttackPtkMeta(attackResult)
        const payloadValue = attackResult?.metadata?.payload || attackResult?.payload || mutation?.after || null
        const attackedParam = attackResult?.param
            || attackResult?.metadata?.attacked?.name
            || (Array.isArray(attackResult?.metadata?.mutations) && attackResult.metadata.mutations[0]?.name)
            || null
        const actionToken = attackResult?.metadata?.action?.random || null
        const responseSource = this._extractResponseShape(attackResult?.response)
        const responseBody = responseSource?.body
        const responseLength = typeof responseBody === 'string'
            ? responseBody.length
            : (typeof attackResult?.length === 'number' ? attackResult.length : null)
        const responseTime = typeof responseSource?.timeMs === 'number'
            ? responseSource.timeMs
            : (typeof attackResult?.timeMs === 'number' ? attackResult.timeMs : null)
        const requestData = this._compactRequestForStorage(attackResult?.request, {
            includeRaw: true,
            includeHeaders: true,
            includeBody: true
        })
        const responseData = this._compactResponseForStorage(responseSource, {
            includeBody: true,
            includeHeaders: true,
            includeRaw: false,
            fallbackLength: responseLength,
            fallbackTimeMs: responseTime
        })
        const attackMeta = {
            id: attackId,
            findingId: attackResult?.findingId || null,
            success: !!attackResult?.success,
            payload: payloadValue,
            proof: attackResult?.proof || null,
            statusCode: responseData?.statusCode || attackResult?.statusCode || null,
            timeMs: responseTime,
            length: responseLength,
            name: attackResult?.metadata?.name || attackResult?.name || classification.ruleName || null,
            param: attackedParam,
            moduleId: classification.moduleId,
            moduleName: classification.moduleName,
            ruleId: classification.ruleId,
            ruleName: classification.ruleName,
            category: classification.category,
            severity: classification.severity || null,
            vulnId: classification.vulnId || null,
            outputKind: reconMeta.outputKind || classification.outputKind || null,
            reconKind: reconMeta.reconKind || classification.reconKind || null,
            presentationAggregate: reconMeta?.presentation?.aggregate || classification.presentationAggregate || null,
            uiSurface: reconMeta.uiSurface || classification.uiSurface || null
        }
        if (requestData) attackMeta.request = requestData
        if (responseData) attackMeta.response = responseData
        const followupRequestData = this._compactRequestForStorage(attackResult?.renderFollowup?.request, {
            includeRaw: true,
            includeHeaders: true,
            includeBody: true
        })
        const followupResponseData = this._compactResponseForStorage(attackResult?.renderFollowup?.response, {
            includeBody: true,
            includeHeaders: true,
            includeRaw: false
        })
        if (attackResult?.renderFollowup?.url || followupRequestData || followupResponseData) {
            attackMeta.renderFollowup = {}
            if (attackResult?.renderFollowup?.url) attackMeta.renderFollowup.url = attackResult.renderFollowup.url
            if (followupRequestData) attackMeta.renderFollowup.request = followupRequestData
            if (followupResponseData) attackMeta.renderFollowup.response = followupResponseData
        }
        if (Number.isFinite(attackResult?.confidence)) attackMeta.confidence = attackResult.confidence
        if (Number.isFinite(attackResult?.metadata?.confidence)) attackMeta.confidence = attackResult.metadata.confidence
        if (actionToken) {
            attackMeta.actionToken = actionToken
        }
        record.attacks.push(attackMeta)
        if (attackResult && typeof attackResult === 'object') {
            attackResult.__requestRecordEntry = attackMeta
        }
        return attackMeta
    }

    _attachAttacksToRequestRecord(attacks = [], record) {
        if (!record || !Array.isArray(attacks)) return
        attacks.forEach(attack => this._attachAttackToRecord(record, attack))
    }

    _emitLiveAttackDelta(plan, attackResult) {
        if (!plan?.requestRecord || !attackResult) return
        const entry = this._attachAttackToRecord(plan.requestRecord, attackResult)
        if (!entry) return
        const delta = {
            requestId: plan.requestRecord?.id || null,
            original: this._buildDeltaOriginalSummary(plan.requestRecord?.original || plan.original || null),
            attacks: [this._buildDeltaAttackSummary(entry)].filter(Boolean)
        }
        this._emitDeltaMessage("dast_attack_delta", delta)
        this._notifyResultMutation({
            type: "attack_delta",
            requestId: plan.requestRecord?.id || null,
            attackId: entry?.id || null
        })
    }

    async scanRequest(raw, ontime = false) {
        const plan = await this.buildAttackPlan(raw)
        if (!plan) return null
        const context = this._createTaskContext(plan.original, {
            rateLimited: !ontime,
            respectEngineState: true
        })
        const attacks = []
        for (const task of plan.tasks) {
            const result = await this._runTask(task, context)
            if (result) attacks.push(result)
        }
        this._normalizeResultOrder(attacks)
        const requestRecord = this._createRequestRecord(plan.original, false)
        this._attachAttacksToRequestRecord(attacks, requestRecord)
        return { original: plan.original, attacks, requestRecord }
    }

    async scanRequestWithTasks(raw, options = {}) {
        const plan = await this.buildAttackPlan(raw)
        if (!plan) return null
        const attacks = await this._executeTaskPlan(plan, options)
        return { original: plan.original, attacks }
    }

    async _executeTaskPlan(plan, options = {}) {
        const context = this._createTaskContext(plan.original, {
            rateLimited: options.rateLimited !== false,
            respectEngineState: options.respectEngineState ?? false
        })
        return this.taskScheduler.executeTaskPlan(plan, {
            concurrency: Math.max(1, options.concurrency || this.concurrency || 1),
            context
        })
    }

    _hasRealHttpResponse(response) {
        if (!response || typeof response !== 'object') return false
        const statusCode = Number(response.statusCode ?? response.status)
        return Number.isFinite(statusCode) && statusCode >= 100
    }

    _normalizePathForRequestContext(rawPath) {
        return normalizeRequestContextPath(rawPath)
    }

    _deriveTaskSurfaceTarget(task) {
        const attacked = task?.target || task?.payload?.metadata?.attacked || null
        return deriveRequestContextSurface(attacked)
    }

    _buildRequestContext(task, context, requestOverride = null) {
        const req = requestOverride || task?.payload?.request || context?.original?.request || {}
        const method = (req.method || context?.original?.request?.method || 'GET').toUpperCase()
        const rawTarget = req.url || req.path || context?.original?.request?.url || '/'
        let pathname = '/'
        try {
            const parsed = new URL(
                rawTarget,
                rawTarget && rawTarget.startsWith('http')
                    ? undefined
                    : this._guessRequestBase(req)
            )
            pathname = parsed.pathname || '/'
        } catch (_) {
            pathname = String(rawTarget || '/').split('?')[0] || '/'
        }
        const pathResult = this._normalizePathForRequestContext(pathname)
        const surface = this._deriveTaskSurfaceTarget(task)
        const requestContextKey = buildRequestContextKey({
            method,
            normalizedPath: pathResult.normalizedPath,
            sourceType: surface.sourceType,
            targetName: surface.targetName
        })
        return {
            method,
            normalizedPath: pathResult.normalizedPath,
            sourceType: surface.sourceType,
            targetName: surface.targetName,
            requestContextKey,
            uncertainPath: pathResult.uncertain
        }
    }

    _techniqueAllowed(technique) {
        const allowed = this.scanControls?.allowedCapabilities || {}
        const value = String(technique || '').trim().toLowerCase()
        if (!value) return true
        const aliasMap = {
            bool: 'boolean',
            boolean_oracle: 'boolean',
            error_based: 'error',
            union_based: 'union',
            time_based: 'time',
            out_of_band: 'oast',
            xml_encoded: 'xmlEncoding',
            xmlencoding: 'xmlEncoding'
        }
        const key = aliasMap[value] || value
        if (!Object.prototype.hasOwnProperty.call(allowed, key)) return true
        return allowed[key] !== false
    }

    _moduleAllowedByTechniques(task) {
        const techniques = this._moduleCapabilities(task?.module)
        if (!Array.isArray(techniques) || !techniques.length) return true
        return techniques.every((technique) => this._techniqueAllowed(technique))
    }

    _scanStopRules() {
        return this.scanControls?.stopRules || {}
    }

    _shouldSkipTaskDueToScanControls(task, context) {
        return this.taskScheduler.shouldSkipTaskDueToScanControls(task, context, this.scanControls)
    }

    _shouldCountSuccessAsFindingCandidate(task, result) {
        if (!result?.success) return false
        const ruleId = String(result?.ruleId || task?.attack?.id || '').toLowerCase()
        if (ruleId.includes('baseline')) return false
        if (this._isReconAttackResult(result) || this._isReconAttackResult(task?.attack)) return false
        return true
    }

    _recordScanControlFinding(task, context, result) {
        if (!this._shouldCountSuccessAsFindingCandidate(task, result)) {
            return
        }
        return this.taskScheduler.recordScanControlFinding(task, context, result)
    }

    _taskConditionRequiresModuleExecuted(task) {
        const condition = task?.attack?.condition || null
        if (!condition) return false
        try {
            return JSON.stringify(condition).includes("module.executed")
        } catch (_) {
            return false
        }
    }

    _confirmConfig() {
        return this.scanControls?.confirm || {}
    }

    _evaluateGenericConfirmBorderline(result, original) {
        return this.confirmationService.evaluateGenericConfirmBorderline(result, original)
    }

    async _runGenericConfirm(task, combined, context) {
        return this.confirmationService.runGenericConfirm(task, combined, context)
    }

    async _maybeApplyConfirmPolicy(task, combined, context) {
        return this.confirmationService.maybeApplyConfirmPolicy(task, combined, context)
    }

    async _runTask(task, context) {
        if (!task || !task.module) return null

        const automationToken = this._automationTaskStarted()
        let taskError = null
        try {
            if (this._isUniqueAttackAlreadySuccessful(task)) {
                this._appendTaskRuntimeEvent(task, context, {
                    type: 'dast_attack_skipped',
                    phase: 'preflight',
                    reason: 'unique_already_confirmed'
                })
                return null
            }

            if (this._shouldSkipTaskDueToStrategy(task)) {
                this._appendTaskRuntimeEvent(task, context, {
                    type: 'dast_attack_skipped',
                    phase: 'preflight',
                    reason: 'strategy_stop_on_first'
                })
                return null
            }

            if (!this._moduleAllowedByTechniques(task)) {
                this._appendTaskRuntimeEvent(task, context, {
                    type: 'dast_attack_skipped',
                    phase: 'preflight',
                    reason: 'technique_disallowed_by_profile'
                })
                return null
            }

            const scanStop = this._shouldSkipTaskDueToScanControls(task, context)
            if (scanStop) {
                this._appendTaskRuntimeEvent(task, context, {
                    type: 'dast_attack_skipped',
                    phase: 'preflight',
                    reason: scanStop.reason
                })
                return null
            }

            const moduleId = task.moduleId || task.module?.id || null
            const executedByModule = context?.executedByModule || null
            const contextDescriptor = this._buildRequestContext(task, context)
            const requestKey = `${moduleId || 'module'}|${contextDescriptor.requestContextKey}`
            const executedHistory = !task.moduleAsync && moduleId && executedByModule
                ? (executedByModule[requestKey] ||= [])
                : null
            const recordExecuted = (entry) => {
                if (!executedHistory || !entry) return
                const hasResponse = this._hasRealHttpResponse(entry?.response)
                const allowFailure = task?.module?.metadata?.recordFailuresInExecuted === true
                if (!hasResponse && !allowFailure) return
                executedHistory.unshift(entry)
                if (executedHistory.length > 5) executedHistory.pop()
            }
            if (executedHistory) {
                task.module.executed = executedHistory
            }
            if (task.deferCondition && task.attack?.condition) {
                const deferNeedsHistory = this._taskConditionRequiresModuleExecuted(task)
                const executedCount = Array.isArray(task.module?.executed) ? task.module.executed.length : 0
                const deferRetryCount = Number(task._deferRetryCount || 0)
                if (deferNeedsHistory && executedCount === 0 && deferRetryCount < 1) {
                    task._deferRetryCount = deferRetryCount + 1
                    this._appendTaskRuntimeEvent(task, context, {
                        type: 'dast_deferred_condition_waiting',
                        phase: 'condition_eval',
                        reason: 'awaiting_module_executed'
                    })
                    return { __ptkRequeueTask: true }
                }
                const conditionPayload = { metadata: this._attackMetadataView(task.module, task.attack) }
                const shouldRun = task.module.validateAttackConditions(conditionPayload, context.original)
                if (!shouldRun) {
                    const moduleId = task.moduleId || task.module?.id || null
                    if (moduleId === 'jwt_injection') {
                        const executed = Array.isArray(task.module?.executed) ? task.module.executed : []
                        const executedSummary = executed.slice(0, 5).map(entry => ({
                            attackId: entry?.metadata?.id || null,
                            statusCode: entry?.response?.statusCode ?? entry?.statusCode ?? null,
                            length: entry?.response?.length ?? entry?.length ?? null,
                            success: typeof entry?.success === 'boolean' ? entry.success : null
                        }))
                        this._appendRuntimeEvent(Object.assign(
                            this._buildTaskRuntimeContext(task, context),
                            {
                                type: 'dast_jwt_deferred_condition_skipped',
                                reason: 'condition_false',
                                executed: executedSummary
                            }
                        ))
                    } else {
                        const executed = Array.isArray(task.module?.executed) ? task.module.executed : []
                        const executedSummary = executed.slice(0, 5).map(entry => ({
                            attackId: entry?.metadata?.id || null,
                            statusCode: entry?.response?.statusCode ?? entry?.statusCode ?? null,
                            length: entry?.response?.length ?? entry?.length ?? null,
                            hasHeaders: Array.isArray(entry?.response?.headers),
                            success: typeof entry?.success === 'boolean' ? entry.success : null
                        }))
                        this._appendTaskRuntimeEvent(task, context, {
                            type: 'dast_deferred_condition_skipped',
                            phase: 'condition_eval',
                            reason: 'condition_false',
                            executed: executedSummary
                        })
                    }
                    this._notifyAttackCompleted(task, context)
                    return null
                }
            }

            const shouldThrottle = task.type !== 'passive' && context?.rateLimited !== false
            if (shouldThrottle) {
                while (true) {
                    if (this.canSendRequest()) break
                    if (context?.respectEngineState !== false && !this.isRunning) break
                    await this._sleep(20)
                }
            }
            this._incrementStrategyStat('totalJobsExecuted')

            if (task.type === 'spa') {
                const res = await this._runSpaAttack(task)
                this._notifyAttackCompleted(task, context)
                if (res) {
                    this._decorateAttackResult(res, task)
                }
                if (res?.success) {
                    this._recordStrategyFinding(task, res)
                    this._recordScanControlFinding(task, context, res)
                }
                if (res?.success && !this._shouldRecordSuccess(task)) {
                    return null
                }
                if (res) this._tagResultOrder(res, task)
                return res
            } else if (task.type === 'active') {
                const executed = await this.activeAttack(task.payload)
                if (executed) {
                    const trackingResult = await this._runTracking(task, executed, context)
                    if (trackingResult?.success) {
                        const combined = Object.assign(executed, trackingResult)
                        this._runOastCallbackCorrelation(task, executed, combined, context)
                        const confirmed = await this._maybeApplyConfirmPolicy(task, combined, context)
                        this._decorateAttackResult(combined, task)
                        if (confirmed?.success) {
                            this._recordStrategyFinding(task, confirmed)
                            this._recordScanControlFinding(task, context, confirmed)
                        }
                        if (confirmed?.success && !this._shouldRecordSuccess(task)) {
                            recordExecuted(combined)
                            this._notifyAttackCompleted(task, context)
                            return null
                        }
                        this._tagResultOrder(combined, task)
                        recordExecuted(combined)
                        this._notifyAttackCompleted(task, context)
                        return combined
                    }
                }
                if (executed && task.attack?.validation) {
                    const res = task.module.validateAttack(executed, context.original)
                    const renderFollowup = !res?.success
                        ? await this._runTemplateRenderFollowup(task, executed, context)
                        : null
                    const combined = Object.assign(executed, renderFollowup?.success ? renderFollowup : res)
                    if (task.attack?.id === 'jwt_1') {
                        combined.__jwt1 = true
                    }
                    this._runOastCallbackCorrelation(task, executed, combined, context)
                    const confirmed = await this._maybeApplyConfirmPolicy(task, combined, context)
                    this._decorateAttackResult(combined, task)
                    if (confirmed?.success) {
                        this._recordStrategyFinding(task, confirmed)
                        this._recordScanControlFinding(task, context, confirmed)
                    }
                    if (confirmed?.success && !this._shouldRecordSuccess(task)) {
                        recordExecuted(combined)
                        this._notifyAttackCompleted(task, context)
                        return null
                    }
                    this._tagResultOrder(combined, task)
                    recordExecuted(combined)
                    this._notifyAttackCompleted(task, context)
                    return combined
                }
                recordExecuted(executed)
                this._notifyAttackCompleted(task, context)
                return null
            } else if (task.type === 'passive') {
                const res = task.module.validateAttack(task.payload, context.original)
                this._notifyAttackCompleted(task, context)
                if (res.success) {
                    const combined = Object.assign({}, task.payload, res)
                    combined.request =
                        combined.request ||
                        context.original?.request ||
                        context.original ||
                        null
                    combined.response =
                        combined.response ||
                        context.original?.response ||
                        null
                    this._decorateAttackResult(combined, task)
                    if (!this._shouldRecordSuccess(task)) {
                        return null
                    }
                    if (!this._shouldRecordPassiveUnique(combined, task, context.original)) {
                        return null
                    }
                    if (!this._isReconAttackResult(combined)) {
                        this._recordStrategyFinding(task, combined)
                        this._recordScanControlFinding(task, context, combined)
                    }
                    this._tagResultOrder(combined, task)
                    return combined
                }
            }
            return null
        } catch (err) {
            taskError = err
            throw err
        } finally {
            this._automationTaskFinished(automationToken, taskError)
        }
    }

    _notifyAttackCompleted(task, context) {
        if (!task) return
        const key = task.attackKey || task.id
        if (context?.notified?.has(key)) return
        context?.notified?.add(key)
        const attack = task.attack
        const progress = this._buildProgressSnapshot()
        browser.runtime.sendMessage({
            channel: "ptk_background2popup_rattacker",
            type: "attack completed",
            // Avoid cloning full scanResult for progress updates.
            info: {
                name: attack?.name || task?.attack?.name || "Attack completed",
                progress
            }
        }).catch(e => e)
        this._emitProgress({ name: attack?.name || task?.attack?.name || "Attack completed" })
    }

    _buildProgressSnapshot() {
        const planned = Number(this.scanStats?.totalJobsPlanned || 0)
        const executed = Number(this.scanStats?.totalJobsExecuted || 0)
        const activeTasks = Math.max(0, Number(this.activeCount || 0))
        const taskQueue = this._taskQueueCount()
        const requestQueue = this._requestQueue?.size ? this._requestQueue.size() : 0
        const pendingPlans = this._activePlans?.size || 0
        const nonExecuted = Math.max(planned - executed, 0)
        const planning = this.inProgress ? 1 : 0
        const pipelineRemaining = Math.max(taskQueue + activeTasks + requestQueue + pendingPlans + planning, 0)
        const remaining = pipelineRemaining
        const isIdle = Boolean(this.isRunning && requestQueue === 0 && taskQueue === 0 && pendingPlans === 0 && activeTasks === 0 && planning === 0)
        return {
            planned,
            executed,
            remaining,
            nonExecuted,
            activeTasks,
            taskQueue,
            requestQueue,
            pendingPlans,
            planning,
            isRunning: !!this.isRunning,
            isIdle,
            phase: this.isRunning ? (isIdle ? 'idle' : 'scanning') : 'stopped',
            lastActivityAt: this._lastProgressAt ? new Date(this._lastProgressAt).toISOString() : null
        }
    }

    getProgressSnapshot() {
        return this._buildProgressSnapshot()
    }

    _emitProgress(update = {}, options = {}) {
        const force = options?.force === true
        if (force && this._deferredProgressTimer) {
            clearTimeout(this._deferredProgressTimer)
            this._deferredProgressTimer = null
            this._deferredProgressPayload = null
        }
        const progress = this._buildProgressSnapshot()
        const key = [
            progress.executed,
            progress.planned,
            progress.remaining,
            progress.activeTasks,
            progress.taskQueue,
            progress.requestQueue,
            progress.pendingPlans,
            progress.planning || 0,
            progress.isRunning ? 1 : 0,
            progress.isIdle ? 1 : 0
        ].join('|')
        const now = Date.now()
        const changed = key !== this._lastProgressKey
        const hasMessage = Boolean(update?.name || update?.message)
        if (!force) {
            if (!changed && !hasMessage) return
            const elapsed = now - (this._lastProgressAt || 0)
            if (elapsed < 300) {
                if (changed) {
                    this._deferredProgressPayload = update
                    if (this._deferredProgressTimer) {
                        clearTimeout(this._deferredProgressTimer)
                    }
                    this._deferredProgressTimer = setTimeout(() => {
                        this._deferredProgressTimer = null
                        const deferredUpdate = this._deferredProgressPayload || {}
                        this._deferredProgressPayload = null
                        this._emitProgress(deferredUpdate, { force: true })
                    }, 300 - elapsed)
                }
                return
            }
        }
        this._lastProgressAt = now
        this._lastProgressKey = key
        browser.runtime.sendMessage({
            channel: "ptk_background2popup_rattacker",
            type: "dast_progress",
            info: {
                name: update?.name || null,
                message: update?.message || null,
                progress
            }
        }).catch(e => e)
    }

    _tagResultOrder(result, task) {
        if (!result || !task) return
        result.__taskOrder = task.order ?? 0
    }

    _normalizeResultOrder(attacks = []) {
        attacks.sort((a, b) => {
            const ao = typeof a === 'object' && a !== null ? (a.__taskOrder ?? 0) : 0
            const bo = typeof b === 'object' && b !== null ? (b.__taskOrder ?? 0) : 0
            return ao - bo
        })
        for (const item of attacks) {
            if (item && typeof item === 'object' && Object.prototype.hasOwnProperty.call(item, '__taskOrder')) {
                delete item.__taskOrder
            }
        }
        return attacks
    }

    _shouldRecordSuccess(task) {
        if (!task || !task.module) return true
        const meta = this._moduleMetadataView(task.module)
        if (meta.legacyUniqueBehavior === 'skip_after_success') {
            if (!this._uniqueAttackSuccess) this._uniqueAttackSuccess = new Set()
            const key = `${task.moduleId || task.moduleName || 'module'}|${task.attackKey || task.id}`
            if (this._uniqueAttackSuccess.has(key)) {
                return false
            }
            this._uniqueAttackSuccess.add(key)
        }
        return true
    }

    _buildUniqueFindingKey(moduleId, ruleId, url, param) {
        return `${moduleId || 'module'}|${ruleId || 'rule'}|${url || ''}|${param || ''}`
    }

    _shouldRecordPassiveUnique(result, task, original) {
        if (!task || !result) return true
        const findingSemantics = String(this._moduleExecution(task.module).findingSemantics || '').toLowerCase()
        if (findingSemantics !== 'unique') return true
        if (task.type !== 'passive') return true
        if (!this._passiveUniqueFindingKeys) this._passiveUniqueFindingKeys = new Set()

        const moduleId = task.moduleId || task.module?.id || task.moduleName || 'module'
        const ruleId = result.ruleId || task.attack?.id || task.attack?.name || 'rule'
        const req = result.request || original?.request || original || {}
        const url = req?.url || req?.ui_url || req?.uiUrl || null
        const param =
            result.param ||
            result.metadata?.attacked?.name ||
            (Array.isArray(result.metadata?.mutations) && result.metadata.mutations[0]?.name) ||
            null
        const key = this._buildUniqueFindingKey(moduleId, ruleId, url, param)
        if (this._passiveUniqueFindingKeys.has(key)) {
            return false
        }
        this._passiveUniqueFindingKeys.add(key)
        return true
    }

    _findPersistedActiveUniqueFinding(moduleId, ruleId, url, param) {
        const findings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings : []
        if (!findings.length) return null
        const targetKey = this._buildUniqueFindingKey(moduleId, ruleId, url, param)
        for (const finding of findings) {
            if (!finding || String(finding.engine || "").toUpperCase() !== "DAST") continue
            const location = finding.location || {}
            const findingKey = this._buildUniqueFindingKey(
                finding.moduleId,
                finding.ruleId,
                location.url || location.runtimeUrl || null,
                location.param || null
            )
            if (findingKey === targetKey) {
                return finding
            }
        }
        return null
    }

    _shouldRecordActiveUniqueFinding(moduleMeta, moduleId, ruleId, url, param) {
        const findingSemantics = String(moduleMeta?.findingSemantics || '').toLowerCase()
        if (findingSemantics !== 'unique') {
            return {
                allowed: true,
                uniqueKey: null,
                existingFinding: null
            }
        }
        if (!this._activeUniqueFindingKeys) this._activeUniqueFindingKeys = new Set()

        const key = this._buildUniqueFindingKey(moduleId, ruleId, url, param)
        const existingFinding = this._findPersistedActiveUniqueFinding(moduleId, ruleId, url, param)
        if (existingFinding?.id) {
            this._activeUniqueFindingKeys.add(key)
            return {
                allowed: false,
                uniqueKey: key,
                existingFinding
            }
        }
        if (this._activeUniqueFindingKeys.has(key)) {
            // The in-memory key is stale if there is no persisted matching finding.
            this._activeUniqueFindingKeys.delete(key)
        }
        return {
            allowed: true,
            uniqueKey: key,
            existingFinding: null
        }
    }

    _isUniqueAttackAlreadySuccessful(task) {
        if (!task || !task.module) return false
        const meta = this._moduleMetadataView(task.module)
        if (meta.legacyUniqueBehavior === 'skip_after_success') {
            if (!this._uniqueAttackSuccess) this._uniqueAttackSuccess = new Set()
            const key = `${task.moduleId || task.moduleName || 'module'}|${task.attackKey || task.id}`
            return this._uniqueAttackSuccess.has(key)
        }
        return false
    }

    _markTaskGroupReady(groupKey) {
        if (!groupKey) return
        if (!this._taskQueueGroups?.has(groupKey)) return
        if (this._taskReadyGroupSet?.has(groupKey)) return
        this._insertReadyGroup(groupKey)
        this._taskReadyGroupSet.add(groupKey)
        this._trackReadyGroupFamily(groupKey)
        const queue = this._performanceTelemetry?.queue
        if (queue) {
            queue.readyGroupsMax = Math.max(queue.readyGroupsMax || 0, this._taskReadyGroups.length)
        }
    }

    _enqueueTask(task) {
        if (!task) return
        const groupKey = this._resolvePlanLockKey(task) || task.planId || task.id
        task._taskGroupKey = groupKey
        task._runtimePlanLockKey = groupKey
        task._familyKey = task._familyKey || this._taskFamilyKey(task)
        task.priority = this._taskPriority(task)
        const existing = this._taskQueueGroups.get(groupKey) || []
        existing.push(task)
        this._taskQueueGroups.set(groupKey, existing)
        const previousGroupPriority = Number(this._taskQueueGroupPriority?.get(groupKey) || Number.NEGATIVE_INFINITY)
        if (!this._taskQueueGroupPriority) this._taskQueueGroupPriority = new Map()
        if (task.priority > previousGroupPriority) {
            this._taskQueueGroupPriority.set(groupKey, task.priority)
            if (this._taskReadyGroupSet?.has(groupKey)) {
                this._requeueReadyGroup(groupKey)
            }
        }
        this._taskQueueLength += 1
        this._recordTaskQueued(task)
        if (existing.length === 1) {
            this._markTaskGroupReady(groupKey)
        }
    }

    _enqueuePlan(plan) {
        if (!plan) return
        if (!this.isRunning) {
            // Preserve real user requests even when stop is triggered mid-planning.
            // We intentionally persist the original request record with zero attacks
            // instead of dropping it from scan history/export.
            const requestRecord = this._createRequestRecord(plan.original)
            this._appendRuntimeEvent({
                type: 'dast_request_recorded',
                phase: 'plan_enqueue',
                requestId: requestRecord?.id || null,
                method: requestRecord?.original?.request?.method || plan?.original?.request?.method || null,
                url: requestRecord?.original?.request?.url || plan?.original?.request?.url || null,
                pendingTasks: 0
            })
            this.updateScanResult({
                original: plan.original,
                attacks: [],
                requestRecord
            })
            this._notifyIdleResolvers()
            this._emitProgress()
            return
        }
        plan.pending = plan.tasks?.length || 0
        plan.attacks = []
        plan.requestRecord = this._createRequestRecord(plan.original)
        this._appendRuntimeEvent({
            type: 'dast_request_recorded',
            phase: 'plan_enqueue',
            requestId: plan.requestRecord?.id || null,
            method: plan.requestRecord?.original?.request?.method || plan?.original?.request?.method || null,
            url: plan.requestRecord?.original?.request?.url || plan?.original?.request?.url || null,
            pendingTasks: plan.pending
        })
        plan.context = this._createTaskContext(plan.original, {
            rateLimited: true,
            respectEngineState: true
        })
        this._activePlans.set(plan.id, plan)

        if (plan.pending === 0) {
            this._finalizePlan(plan)
            return
        }

        plan.tasks.forEach((task, index) => {
            task.planId = plan.id
            if (typeof task.order !== 'number') {
                task.order = index
            }
            this._enqueueTask(task)
        })
        plan.tasks = []
        this._ensureTaskWorkers()
        this._emitProgress()
    }

    _finalizePlan(plan) {
        if (!plan || !this._activePlans?.has(plan.id)) return
        this._normalizeResultOrder(plan.attacks)
        if (plan.requestRecord) {
            this._attachAttacksToRequestRecord(plan.attacks, plan.requestRecord)
        }
        this._appendRuntimeEvent({
            type: 'dast_request_finalized',
            phase: 'plan_finalize',
            requestId: plan.requestRecord?.id || null,
            method: plan.requestRecord?.original?.request?.method || plan?.original?.request?.method || null,
            url: plan.requestRecord?.original?.request?.url || plan?.original?.request?.url || null,
            attacksCount: Array.isArray(plan.requestRecord?.attacks) ? plan.requestRecord.attacks.length : 0
        })
        const result = {
            original: plan.original,
            attacks: plan.attacks,
            requestRecord: plan.requestRecord
        }
        this.updateScanResult(result)
        this._activePlans.delete(plan.id)
        plan.context = null
        this._notifyIdleResolvers()
        this._emitProgress()
    }

    _ensureTaskWorkers() {
        if (!this.isRunning) return
        if (!this._taskWorkers) this._taskWorkers = new Set()
        const target = Math.max(1, this.concurrency || 1)
        while (this._taskWorkers.size < target) {
            const worker = this._taskWorkerLoop()
            this._taskWorkers.add(worker)
            worker.finally(() => {
                this._taskWorkers.delete(worker)
                if (this.isRunning) {
                    this._ensureTaskWorkers()
                }
            })
        }
    }

    _resolvePlanLockKey(task) {
        if (!task?.planId) return null
        const stopRules = typeof this._scanStopRules === 'function'
            ? this._scanStopRules()
            : (this.scanControls?.stopRules || {})
        if (stopRules?.stopOnFirstFindingPerRequest) {
            return task.planId
        }
        const group = task.planLockGroup || task.moduleId || task.moduleName || task.attackKey || task.id || "__plan__"
        return `${task.planId}:${group}`
    }

    async _taskWorkerLoop() {
        while (this.isRunning) {
            const task = this._dequeueRunnableTask()
            if (!task) {
                await this._sleep(50)
                continue
            }

            const plan = this._activePlans.get(task.planId)
            if (!plan) {
                this._releaseModuleLock(task)
                this._releasePlanLock(task)
                continue
            }

            const startedAt = Date.now()
            let requeued = false
            try {
                this.activeCount = Math.max(0, this.activeCount)
                this.activeCount++
                const res = await this._runTask(task, plan.context)
                if (res?.__ptkRequeueTask === true) {
                    requeued = true
                    this._enqueueTask(task)
                } else if (res) {
                    plan.attacks.push(res)
                    this._emitLiveAttackDelta(plan, res)
                }
            } catch (err) {
                console.error('DAST worker error', {
                    module: task?.moduleId || task?.moduleName,
                    attack: task?.attackKey || task?.attack?.id,
                    url: task?.payload?.request?.url,
                    name: err?.name,
                    message: err?.message,
                    cause: err?.cause?.message || err?.cause || null
                }, err)
            } finally {
                this._recordTaskExecution(task, Date.now() - startedAt)
                this.activeCount = Math.max(0, this.activeCount - 1)
                this._releaseTaskFamily(task)
                this._releaseModuleLock(task)
                this._releasePlanLock(task)
                if (!requeued) {
                    plan.pending = Math.max(0, (plan.pending || 0) - 1)
                }
                if (plan.pending === 0) {
                    this._finalizePlan(plan)
                }
                this._notifyIdleResolvers()
                this._emitProgress()
            }
        }
    }

    _dequeueRunnableTask(ignoreFairness = false) {
        const task = this._dequeueRunnableTaskInternal(ignoreFairness)
        if (task) return task
        if (!ignoreFairness) {
            return this._dequeueRunnableTaskInternal(true)
        }
        return null
    }

    _dequeueRunnableTaskInternal(ignoreFairness = false) {
        if (!this._taskQueueCount()) return null
        const attempts = this._taskReadyGroups?.length || 0
        for (let i = 0; i < attempts; i++) {
            const groupKey = this._taskReadyGroups.shift()
            this._taskReadyGroupSet.delete(groupKey)
            this._untrackReadyGroupFamily(groupKey)
            const queue = this._taskQueueGroups.get(groupKey)
            if (!Array.isArray(queue) || !queue.length) {
                this._taskQueueGroups.delete(groupKey)
                this._taskQueueGroupPriority?.delete(groupKey)
                continue
            }
            const task = queue[0]
            if (!task) {
                queue.shift()
                this._taskQueueLength = Math.max(0, this._taskQueueLength - 1)
                if (queue.length) this._markTaskGroupReady(groupKey)
                else {
                    this._taskQueueGroups.delete(groupKey)
                    this._taskQueueGroupPriority?.delete(groupKey)
                }
                continue
            }
            if (!task.moduleAsync && task.moduleId && this._moduleLocks.has(task.moduleId)) {
                this._markTaskGroupReady(groupKey)
                continue
            }
            const planLockKey = task._runtimePlanLockKey || this._resolvePlanLockKey(task)
            if (planLockKey && this._planLocks.has(planLockKey)) {
                this._markTaskGroupReady(groupKey)
                continue
            }
            if (!ignoreFairness && this._shouldYieldForFamilyFairness(task)) {
                this._markTaskGroupReady(groupKey)
                continue
            }
            const planExists = this._activePlans.has(task.planId)
            if (!planExists) {
                queue.shift()
                this._taskQueueLength = Math.max(0, this._taskQueueLength - 1)
                if (queue.length) this._markTaskGroupReady(groupKey)
                else {
                    this._taskQueueGroups.delete(groupKey)
                    this._taskQueueGroupPriority?.delete(groupKey)
                }
                continue
            }
            queue.shift()
            this._taskQueueLength = Math.max(0, this._taskQueueLength - 1)
            if (!queue.length) {
                this._taskQueueGroups.delete(groupKey)
                this._taskQueueGroupPriority?.delete(groupKey)
            }
            if (!task.moduleAsync && task.moduleId) {
                this._moduleLocks.add(task.moduleId)
                task._lockedModule = task.moduleId
            }
            if (planLockKey) {
                this._planLocks.add(planLockKey)
                task._planLocked = true
                task._planLockKey = planLockKey
            }
            this._markTaskFamilyDequeued(task)
            const waitMs = task._queuedAt ? Math.max(0, Date.now() - task._queuedAt) : 0
            this._recordTaskDequeued(task, waitMs)
            return task
        }
        return null
    }

    _releaseModuleLock(task) {
        if (task && !task.moduleAsync && task._lockedModule) {
            this._moduleLocks.delete(task._lockedModule)
            delete task._lockedModule
        }
    }

    _releasePlanLock(task) {
        if (task && task._planLocked && task._planLockKey) {
            this._planLocks.delete(task._planLockKey)
            const groupKey = task._taskGroupKey || task._runtimePlanLockKey || null
            delete task._planLocked
            delete task._planLockKey
            if (groupKey && this._taskQueueGroups?.has(groupKey)) {
                this._markTaskGroupReady(groupKey)
            }
        }
    }

    _simpleFingerprint(rawRequest, response) {
        const raw = typeof rawRequest === 'object' ? rawRequest.raw : rawRequest
        const line = raw ? raw.split(/\r?\n/)[0] : ''
        const parts = line.trim().split(/\s+/)
        const method = (parts[0] || 'GET').toUpperCase()
        // Prefer real request target for dedupe. ui_url can be page route in SPA contexts and
        // would otherwise collapse distinct API calls (for example login/graphql) into one key.
        const objectUrl = (typeof rawRequest === 'object'
            ? (rawRequest.url || rawRequest.requestUrl || null)
            : null)
        const urlPart = parts[1] || objectUrl || (typeof rawRequest === 'object' ? (rawRequest.ui_url || rawRequest.uiUrl) : null) || response?.url || response?.ui_url || '/'
        const base = response?.url || urlPart
        try {
            const urlObj = new URL(urlPart, urlPart && urlPart.startsWith('http') ? undefined : base || 'http://localhost')
            const host = (urlObj.host || '').toLowerCase()
            let pathname = urlObj.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            pathname = pathname.replace(/\/+/g, '/')
            const queryNames = new Set()
            urlObj.searchParams.forEach((_, key) => queryNames.add(key.toLowerCase()))
            const querySig = Array.from(queryNames).sort().join('&')
            const partsOut = ['http', host, pathname, method]
            if (querySig) partsOut.push(`q:${querySig}`)
            return partsOut.join('|')
        } catch (e) {
            return ''
        }
    }

    _buildSpaTasks(original, module, attack, rawMeta = {}, defaultFingerprint = null) {
        const tasks = []
        const uiUrl = rawMeta.ui_url || rawMeta.uiUrl || original?.request?.ui_url || original?.request?.url
        const baseEvent = {
            type: 'dast_spa_filtered',
            phase: 'task_build',
            moduleId: module?.id || null,
            moduleName: module?.name || null,
            attackId: attack?.id || null,
            attackName: attack?.name || null,
            url: original?.request?.url || null,
            uiUrl: uiUrl || null,
            method: original?.request?.method || null
        }
        if (!uiUrl) {
            this._appendRuntimeEvent(Object.assign({}, baseEvent, { reason: 'missing_ui_url' }))
            return tasks
        }
        try {
            const parsed = new URL(uiUrl)
            const hasHashQuery = parsed.hash && parsed.hash.includes('?')
            if (!hasHashQuery) {
                this._appendRuntimeEvent(Object.assign({}, baseEvent, { reason: 'no_hash_query' }))
                return tasks
            }
        } catch (_) {
            this._appendRuntimeEvent(Object.assign({}, baseEvent, { reason: 'invalid_ui_url' }))
            return tasks
        }

        const params = getSearchParamsFromUrlOrHash(uiUrl)
        const names = Array.from(new Set(Array.from(params.keys())))
        if (!names.length) {
            // still run once for checks that do not need params (token scans, sensitive data)
            names.push('')
        }

        const spaCfg = this._attackRuntimeConfig(attack, 'spa') || {}
        const payloads = Array.isArray(spaCfg.payloads) && spaCfg.payloads.length ? spaCfg.payloads : [spaCfg.markerToken || ptk_utils.attackParamId()]
        const checks = Array.isArray(spaCfg.checks) && spaCfg.checks.length ? spaCfg.checks : ['dom_xss']

        for (const name of names) {
            for (const payload of payloads) {
                const fingerprint = this._fingerprintFromUrl(uiUrl) || defaultFingerprint
                const task = this._createTask({
                    module,
                    attack,
                    payload: {
                        param: name,
                        payload,
                        checks,
                        markerDomain: spaCfg.markerDomain,
                        markerToken: spaCfg.markerToken || payload,
                        ui_url: uiUrl,
                        metadata: this._attackMetadataView(module, attack)
                    },
                    type: 'spa',
                    fingerprint
                })
                task.attackKey = `${task.attackKey}|${name}`
                tasks.push(task)
                this._registerPlannedTask()
            }
        }
        return tasks
    }

    _moduleAllowsStrategyBulk(module) {
        if (!module) return false
        const execution = this._moduleExecution(module)
        if (typeof execution.allowStrategyBulk === 'boolean') return execution.allowStrategyBulk
        return true
    }

    _shouldUseBulkAttack(moduleOrAllowsStrategyBulk, options = {}) {
        const moduleAllowsStrategyBulk = typeof options.moduleAllowsStrategyBulk === 'boolean'
            ? options.moduleAllowsStrategyBulk
            : typeof moduleOrAllowsStrategyBulk === 'boolean'
                ? moduleOrAllowsStrategyBulk
                : this._moduleAllowsStrategyBulk(moduleOrAllowsStrategyBulk)
        if (options.resolveOnly === true) {
            return moduleAllowsStrategyBulk
        }
        return this.strategyConfig?.requestGroupingDefault === 'bulk' && moduleAllowsStrategyBulk
    }

    _resolveStrategyConfig(value) {
        const key = typeof value === 'string'
            ? value.toUpperCase()
            : (value?.strategy ? String(value.strategy).toUpperCase() : DEFAULT_SCAN_STRATEGY)
        const base = SCAN_STRATEGY_CONFIGS[key] || SCAN_STRATEGY_CONFIGS[DEFAULT_SCAN_STRATEGY]
        return Object.assign({}, base)
    }

    _resolveTimeoutMs(value, fallback = null) {
        const candidate = Number(value)
        if (Number.isFinite(candidate) && candidate > 0) {
            return Math.max(1000, Math.floor(candidate))
        }
        const fb = Number(fallback)
        if (Number.isFinite(fb) && fb > 0) {
            return Math.max(1000, Math.floor(fb))
        }
        return null
    }

    _resolveRequestTimeoutMs(override, fallback = null) {
        return this._resolveTimeoutMs(
            override,
            fallback || this.requestTimeoutMs || this.settings?.requestTimeoutMs || DEFAULT_DAST_REQUEST_TIMEOUT_MS
        )
    }

    _createStrategyStats(strategy) {
        if (!this.taskScheduler || typeof this.taskScheduler.createStrategyStats !== 'function') {
            return {
                strategy: strategy || DEFAULT_SCAN_STRATEGY,
                totalJobsPlanned: 0,
                totalJobsExecuted: 0,
                skippedDueToStrategy: 0
            }
        }
        return this.taskScheduler.createStrategyStats(strategy || DEFAULT_SCAN_STRATEGY)
    }

    _initializeStrategyState(strategyConfig = this.strategyConfig) {
        const cfg = strategyConfig && strategyConfig.strategy ? Object.assign({}, strategyConfig) : this._resolveStrategyConfig(strategyConfig)
        this.strategyConfig = cfg
        this.scanStats = this._createStrategyStats(cfg.strategy)
        this._strategyFindingKeys = new Set()
        if (this.scanResult) {
            this._syncScanSettings({ scanStrategy: cfg.strategy })
            this._syncScanStats()
        }
    }

    _applyScanStrategy(strategyValue) {
        const cfg = this._resolveStrategyConfig(strategyValue || this.strategyConfig?.strategy)
        this._initializeStrategyState(cfg)
    }

    _scanControlProfileDefaults(profile) {
        const key = String(profile || DEFAULT_SCAN_CONTROL_PROFILE).toLowerCase()
        const selected = SCAN_CONTROL_PROFILE_DEFAULTS[key] || SCAN_CONTROL_PROFILE_DEFAULTS[DEFAULT_SCAN_CONTROL_PROFILE]
        return cloneValue(selected)
    }

    _normalizeBoolean(value, fallback) {
        if (typeof value === 'boolean') return value
        if (typeof value === 'string') {
            const normalized = value.trim().toLowerCase()
            if (normalized === 'true') return true
            if (normalized === 'false') return false
        }
        return fallback
    }

    _normalizeNonNegativeInt(value, fallback, warnings, field) {
        const parsed = Number.parseInt(value, 10)
        if (Number.isFinite(parsed) && parsed >= 0) {
            return parsed
        }
        if (typeof value !== 'undefined' && value !== null && value !== '') {
            warnings.push({
                field,
                message: `Invalid value for ${field}; fallback applied.`,
                fallback
            })
        }
        return fallback
    }

    _normalizeScanControls(rawControls = null) {
        const warnings = []
        const input = (rawControls && typeof rawControls === 'object') ? rawControls : {}
        const requestedProfile = String(input.profile || DEFAULT_SCAN_CONTROL_PROFILE).toLowerCase()
        const profile = SCAN_CONTROL_PROFILE_DEFAULTS[requestedProfile]
            ? requestedProfile
            : DEFAULT_SCAN_CONTROL_PROFILE

        if (requestedProfile !== profile) {
            warnings.push({
                field: 'scanControls.profile',
                message: `Unknown profile '${requestedProfile}'. Downgraded to '${profile}'.`,
                fallback: profile
            })
        }

        const controls = this._scanControlProfileDefaults(profile)
        controls.profile = profile

        const allowedInput = input.allowedCapabilities && typeof input.allowedCapabilities === 'object'
            ? input.allowedCapabilities
            : input.allowedTechniques && typeof input.allowedTechniques === 'object'
                ? input.allowedTechniques
            : {}
        for (const key of Object.keys(controls.allowedCapabilities || {})) {
            controls.allowedCapabilities[key] = this._normalizeBoolean(
                allowedInput[key],
                controls.allowedCapabilities[key]
            )
        }

        const stopInput = input.stopRules && typeof input.stopRules === 'object'
            ? input.stopRules
            : {}
        controls.stopRules.stopOnFirstFindingPerModule = this._normalizeBoolean(
            stopInput.stopOnFirstFindingPerModule,
            controls.stopRules.stopOnFirstFindingPerModule
        )
        controls.stopRules.stopOnFirstFindingPerRequest = this._normalizeBoolean(
            stopInput.stopOnFirstFindingPerRequest,
            controls.stopRules.stopOnFirstFindingPerRequest
        )

        const confirmInput = input.confirm && typeof input.confirm === 'object'
            ? input.confirm
            : {}
        const confirmMode = String(confirmInput.mode || controls.confirm.mode || 'module').toLowerCase()
        if (!['none', 'module', 'generic'].includes(confirmMode)) {
            warnings.push({
                field: 'scanControls.confirm.mode',
                message: `Unknown confirm mode '${confirmMode}'. Fallback applied.`,
                fallback: controls.confirm.mode
            })
        } else {
            controls.confirm.mode = confirmMode
        }
        controls.confirm.confirmFindings = this._normalizeBoolean(
            confirmInput.confirmFindings,
            controls.confirm.confirmFindings
        )
        controls.confirm.confirmOnlyWhenBorderline = this._normalizeBoolean(
            confirmInput.confirmOnlyWhenBorderline,
            controls.confirm.confirmOnlyWhenBorderline
        )
        controls.confirm.minLenDelta = this._normalizeNonNegativeInt(
            confirmInput.minLenDelta,
            controls.confirm.minLenDelta,
            warnings,
            'scanControls.confirm.minLenDelta'
        )
        controls.confirm.borderlineWindow = this._normalizeNonNegativeInt(
            confirmInput.borderlineWindow,
            controls.confirm.borderlineWindow,
            warnings,
            'scanControls.confirm.borderlineWindow'
        )
        controls.confirm.confirmMaxExtraRequests = this._normalizeNonNegativeInt(
            confirmInput.confirmMaxExtraRequests,
            controls.confirm.confirmMaxExtraRequests,
            warnings,
            'scanControls.confirm.confirmMaxExtraRequests'
        )
        controls.allowAuthLikeMutations = this._normalizeBoolean(
            input.allowAuthLikeMutations,
            controls.allowAuthLikeMutations === true
        )

        const excludesInput = input.globalExcludes && typeof input.globalExcludes === 'object'
            ? input.globalExcludes
            : {}
        for (const key of [
            'hardDenyCookieNameRegex',
            'hardDenyParamNameRegex',
            'hardDenyHeaderNameRegex',
            'excludeParamNameRegex',
            'excludeCookieNameRegex',
            'excludeHeaderNameRegex'
        ]) {
            const incoming = excludesInput[key]
            if (typeof incoming === 'string' && incoming.trim()) {
                controls.globalExcludes[key] = incoming
            }
        }
        controls.globalExcludes.allowDangerousInputs = this._normalizeBoolean(
            excludesInput.allowDangerousInputs,
            controls.globalExcludes.allowDangerousInputs
        )

        return { controls, warnings }
    }

    _scanControlsSummary() {
        const controls = this.scanControls || this._scanControlProfileDefaults(DEFAULT_SCAN_CONTROL_PROFILE)
        return {
            profile: controls.profile,
            stopRules: Object.assign({}, controls.stopRules),
            confirm: Object.assign({}, controls.confirm),
            allowAuthLikeMutations: controls?.allowAuthLikeMutations === true,
            allowedCapabilities: Object.assign({}, controls.allowedCapabilities),
            globalExcludes: {
                allowDangerousInputs: controls?.globalExcludes?.allowDangerousInputs === true
            }
        }
    }

    _buildExportableScanSettings(overrides = {}) {
        const source = (this.settings && typeof this.settings === 'object') ? this.settings : {}
        const base = {}
        for (const [key, value] of Object.entries(source)) {
            if (key === 'rulepack' || key === 'cveRulepack' || key === 'onResultMutation') continue
            if (typeof value === 'function' || typeof value === 'undefined') continue
            if (value && typeof value === 'object') {
                base[key] = cloneValue(value)
            } else {
                base[key] = value
            }
        }
        const normalizedPolicy = source?.dastScanPolicy || source?.scanPolicy || 'ACTIVE'
        return Object.assign({}, base, {
            scanStrategy: this.strategyConfig?.strategy || source?.scanStrategy || source?.dastScanStrategy || DEFAULT_SCAN_STRATEGY,
            dastScanStrategy: source?.dastScanStrategy || source?.scanStrategy || this.strategyConfig?.strategy || DEFAULT_SCAN_STRATEGY,
            safetyProfile: source?.safetyProfile || this.scanControls?.profile || DEFAULT_SCAN_CONTROL_PROFILE,
            scanControls: this._scanControlsSummary(),
            runCve: !!source?.runCve,
            dastScanPolicy: normalizedPolicy,
            scanPolicy: source?.scanPolicy || normalizedPolicy,
            policyId: source?.policyId || null,
            policyName: source?.policyName || null,
            maxRequestsPerSecond: Number(this.maxRequestsPerSecond || source?.maxRequestsPerSecond || 0) || null,
            concurrency: Number(this.concurrency || source?.concurrency || 0) || null,
            planningConcurrency: Number(this.planningConcurrency || source?.planningConcurrency || 0) || null,
            requestTimeoutMs: Number(this.requestTimeoutMs || source?.requestTimeoutMs || 0) || null,
            originalRequestTimeoutMs: Number(this.originalRequestTimeoutMs || source?.originalRequestTimeoutMs || 0) || null,
            hasRulepackSnapshot: !!source?.rulepack,
            hasCveRulepackSnapshot: !!source?.cveRulepack
        }, overrides || {})
    }

    _syncScanSettings(overrides = {}) {
        if (!this.scanResult || typeof this.scanResult !== 'object') return
        this.scanResult.settings = this._buildExportableScanSettings(overrides)
    }

    _syncScanControlsToModules() {
        if (!Array.isArray(this.modules)) return
        for (const module of this.modules) {
            if (module && typeof module.setScanControls === 'function') {
                module.setScanControls(this.scanControls)
            }
        }
    }

    _applyScanControls(rawControls = null, { emitWarnings = false } = {}) {
        const normalized = this._normalizeScanControls(rawControls)
        this.scanControls = normalized.controls
        this._syncScanControlsToModules()
        if (this.scanResult) {
            this._syncScanSettings({ scanControls: this._scanControlsSummary() })
        }
        if (emitWarnings && normalized.warnings.length) {
            for (const warning of normalized.warnings) {
                this._appendRuntimeEvent({
                    type: 'dast_scan_controls_warning',
                    field: warning.field,
                    message: warning.message,
                    fallback: warning.fallback
                })
            }
        }
    }

    _syncScanStats() {
        if (this.scanResult) {
            this.scanResult.scanStats = Object.assign({}, this.scanStats)
        }
    }

    _incrementStrategyStat(field, delta = 1) {
        if (!this.scanStats || typeof this.scanStats[field] === 'undefined') return
        this.scanStats[field] += delta
        if (this.scanStats[field] < 0) {
            this.scanStats[field] = 0
        }
        this._syncScanStats()
    }

    _registerPlannedTask() {
        this._incrementStrategyStat('totalJobsPlanned', 1)
    }

    _runtimeEventLimit() {
        const value = Number(this.settings?.runtimeEventsLimit)
        if (Number.isFinite(value) && value > 0) {
            return Math.max(100, Math.floor(value))
        }
        return 5000
    }

    _appendRuntimeEvent(event = {}) {
        if (!this.scanResult) return
        if (!Array.isArray(this.scanResult.runtimeEvents)) {
            this.scanResult.runtimeEvents = []
        }
        const list = this.scanResult.runtimeEvents
        const limit = this._runtimeEventLimit()
        if (list.length >= limit) {
            this._runtimeEventsDropped = (this._runtimeEventsDropped || 0) + 1
            const marker = {
                ts: new Date().toISOString(),
                engine: 'DAST',
                type: 'dast_runtime_events_truncated',
                dropped: this._runtimeEventsDropped
            }
            if (this._runtimeEventsDropMarked && list.length) {
                const last = list[list.length - 1]
                if (last?.type === 'dast_runtime_events_truncated') {
                    last.dropped = this._runtimeEventsDropped
                    last.ts = marker.ts
                    return
                }
            }
            if (list.length) {
                list[list.length - 1] = marker
            } else {
                list.push(marker)
            }
            this._runtimeEventsDropMarked = true
            return
        }
        list.push(Object.assign({
            ts: new Date().toISOString(),
            engine: 'DAST'
        }, event))
    }

    _buildTaskRuntimeContext(task, context) {
        const originalReq = context?.original?.request || {}
        const taskReq = task?.payload?.request || {}
        return {
            moduleId: task?.moduleId || task?.module?.id || null,
            moduleName: task?.moduleName || task?.module?.name || null,
            attackId: task?.attack?.id || null,
            attackName: task?.attack?.name || null,
            taskType: task?.type || null,
            method: originalReq.method || taskReq.method || null,
            url: originalReq.url || taskReq.url || null,
            uiUrl: originalReq.ui_url || originalReq.uiUrl || taskReq.ui_url || taskReq.uiUrl || task?.payload?.ui_url || task?.payload?.uiUrl || null,
            param: task?.payload?.param || this._extractParamName(task, null)
        }
    }

    _appendTaskRuntimeEvent(task, context, event = {}) {
        this._appendRuntimeEvent(Object.assign(
            this._buildTaskRuntimeContext(task, context),
            event
        ))
    }

    _refreshOastProbeDomains() {
        const next = new Set()
        const modules = Array.isArray(this.modules) ? this.modules : []
        modules.forEach((module) => {
            const attacks = Array.isArray(module?.attacks) ? module.attacks : []
            attacks.forEach((attack) => {
                const oastCfg = this._attackRuntimeConfirmation(attack, 'oast')
                if (!oastCfg || oastCfg.enabled !== true) return
                if (typeof oastCfg.domain === 'string' && oastCfg.domain.trim()) {
                    next.add(oastCfg.domain.trim().toLowerCase())
                }
                if (Array.isArray(oastCfg.domains)) {
                    oastCfg.domains.forEach((domain) => {
                        if (typeof domain === 'string' && domain.trim()) {
                            next.add(domain.trim().toLowerCase())
                        }
                    })
                }
            })
        })
        this._oastDomains = next
    }

    _ensureOastCallbackProbe() {
        if (!this.isRunning) return
        if (!this._oastDomains || this._oastDomains.size === 0) return
        this._attachOastCallbackProbe()
    }

    _attachOastCallbackProbe() {
        if (this._oastCallbackListener) return
        if (!browser?.webRequest?.onBeforeRequest?.addListener) return
        const listener = this._handleOastWebRequest.bind(this)
        try {
            browser.webRequest.onBeforeRequest.addListener(
                listener,
                { urls: ["<all_urls>"], types: ptk_utils.requestFilters || ["xmlhttprequest", "main_frame", "sub_frame", "other"] }
            )
            this._oastCallbackListener = listener
            this._appendRuntimeEvent({
                type: 'dast_oast_probe_attached',
                phase: 'scan_start',
                domains: Array.from(this._oastDomains || [])
            })
        } catch (err) {
            this._oastCallbackListener = null
            this._appendRuntimeEvent({
                type: 'dast_oast_probe_error',
                phase: 'scan_start',
                reason: 'attach_failed',
                error: err?.message || String(err)
            })
        }
    }

    _detachOastCallbackProbe() {
        const listener = this._oastCallbackListener
        if (!listener) return
        try {
            if (browser?.webRequest?.onBeforeRequest?.removeListener) {
                browser.webRequest.onBeforeRequest.removeListener(listener)
            }
            this._appendRuntimeEvent({
                type: 'dast_oast_probe_detached',
                phase: 'scan_stop'
            })
        } catch (_) {
            // best effort
        } finally {
            this._oastCallbackListener = null
        }
    }

    _handleOastWebRequest(request = {}) {
        const url = typeof request?.url === 'string' ? request.url : ''
        if (!url) return
        const lowerUrl = url.toLowerCase()
        const domains = this._oastDomains instanceof Set ? this._oastDomains : new Set()
        let matchedDomain = null
        for (const domain of domains) {
            if (lowerUrl.includes(domain)) {
                matchedDomain = domain
                break
            }
        }
        if (!matchedDomain) return
        const event = {
            type: 'dast_oast_callback_observed',
            phase: 'runtime_probe',
            source: 'webRequest.onBeforeRequest',
            domain: matchedDomain,
            url,
            method: request?.method || null,
            tabId: Number.isFinite(request?.tabId) ? request.tabId : null,
            frameId: Number.isFinite(request?.frameId) ? request.frameId : null,
            requestId: request?.requestId || null
        }
        this._appendRuntimeEvent(event)
        if (!Array.isArray(this._oastCallbackEvents)) {
            this._oastCallbackEvents = []
        }
        this._oastCallbackEvents.push(event)
        if (this._oastCallbackEvents.length > 300) {
            this._oastCallbackEvents.shift()
        }
    }

    _extractAttackOastMarkers(task, executed) {
        return this.confirmationService.extractAttackOastMarkers(task, executed)
    }

    _findOastCallbackMatch(markers) {
        return this.confirmationService.findOastCallbackMatch(markers)
    }

    _runOastCallbackCorrelation(task, executed, combined, context) {
        return this.confirmationService.runOastCallbackCorrelation(task, executed, combined, context)
    }

    _appendSelectorDiagnostics(module, attack, original) {
        if (!module || typeof module.consumeSelectorDiagnostics !== 'function') return
        const diagnostics = module.consumeSelectorDiagnostics()
        if (!Array.isArray(diagnostics) || !diagnostics.length) return
        const originalReq = original?.request || {}
        for (const item of diagnostics) {
            if (item?.kind === 'selection') {
                this._appendRuntimeEvent({
                    type: 'dast_selector_selection',
                    phase: 'target_resolution',
                    moduleId: module?.id || null,
                    moduleName: module?.name || null,
                    attackId: attack?.id || null,
                    attackName: attack?.name || null,
                    method: originalReq.method || null,
                    url: originalReq.url || null,
                    uiUrl: originalReq.ui_url || originalReq.uiUrl || null,
                    surface: item?.surface || null,
                    family: item?.family || null,
                    selected: item?.selected || null
                })
                continue
            }
            if (item?.kind === 'truncation') {
                this._appendRuntimeEvent({
                    type: 'dast_selector_diagnostics_truncated',
                    phase: 'target_resolution',
                    moduleId: module?.id || null,
                    moduleName: module?.name || null,
                    attackId: attack?.id || null,
                    attackName: attack?.name || null,
                    method: originalReq.method || null,
                    url: originalReq.url || null,
                    uiUrl: originalReq.ui_url || originalReq.uiUrl || null,
                    reason: item?.reason || null,
                    dropped: Number(item?.dropped || 0)
                })
                continue
            }
            this._appendRuntimeEvent({
                type: 'dast_selector_skip',
                phase: 'target_resolution',
                moduleId: module?.id || null,
                moduleName: module?.name || null,
                attackId: attack?.id || null,
                attackName: attack?.name || null,
                method: originalReq.method || null,
                url: originalReq.url || null,
                uiUrl: originalReq.ui_url || originalReq.uiUrl || null,
                surface: item?.surface || null,
                reason: item?.reason || null,
                count: item?.count || 0,
                samples: Array.isArray(item?.samples) ? item.samples : []
            })
        }
    }

    _fingerprintFromSchema(schema) {
        if (!schema) return null
        if (schema.request) {
            return this._fingerprintFromRequest(schema.request)
        }
        return null
    }

    _fingerprintFromPayload(payload) {
        if (!payload) return null
        if (payload.request) {
            return this._fingerprintFromRequest(payload.request)
        }
        const uiUrl = payload.ui_url || payload.uiUrl
        if (uiUrl) {
            return this._fingerprintFromUrl(uiUrl)
        }
        return null
    }

    _fingerprintFromRequest(req) {
        if (!req) return null
        const method = (req.method || 'GET').toUpperCase()
        const targetUrl = req.url || req.path || '/'
        const base = this._guessRequestBase(req)
        try {
            const resolved = new URL(targetUrl, targetUrl && targetUrl.startsWith('http') ? undefined : base || 'http://localhost')
            const host = (resolved.host || '').toLowerCase()
            let pathname = resolved.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            const names = new Set()
            resolved.searchParams.forEach((_, key) => names.add(key.toLowerCase()))
            if (Array.isArray(req.queryParams)) {
                for (const param of req.queryParams) {
                    if (param?.name) {
                        names.add(String(param.name).toLowerCase())
                    }
                }
            }
            const querySig = Array.from(names).sort().join('&')
            const parts = [method, host, pathname]
            if (querySig) parts.push(`q:${querySig}`)
            return parts.join('|')
        } catch (_) {
            return `${method}|${targetUrl || ''}`
        }
    }

    _guessRequestBase(req) {
        if (req?.baseUrl) return req.baseUrl
        const headers = Array.isArray(req?.headers) ? req.headers : []
        const hostHeader = headers.find(h => (h.name || '').toLowerCase() === 'host')
        if (hostHeader?.value) {
            const trimmed = hostHeader.value.trim()
            if (/^https?:\/\//i.test(trimmed)) {
                return trimmed
            }
            return `http://${trimmed}`
        }
        return 'http://localhost'
    }

    _fingerprintFromUrl(rawUrl) {
        if (!rawUrl) return null
        try {
            const resolved = new URL(rawUrl, rawUrl && rawUrl.startsWith('http') ? undefined : 'http://localhost')
            const host = (resolved.host || '').toLowerCase()
            let pathname = resolved.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            const names = new Set()
            resolved.searchParams.forEach((_, key) => names.add(key.toLowerCase()))
            const querySig = Array.from(names).sort().join('&')
            const parts = ['SPA', host, pathname]
            if (querySig) parts.push(`q:${querySig}`)
            return parts.join('|')
        } catch (_) {
            return rawUrl
        }
    }

    _extractParamName(task, result) {
        const meta = result?.metadata || task?.payload?.metadata || {}
        const attacked = meta.attacked || task?.target
        if (attacked) {
            if (typeof attacked === 'string') return attacked
            if (typeof attacked?.name === 'string') return attacked.name
        }
        if (typeof task?.target === 'string') return task.target
        return null
    }

    _taskFindingKey(task, result) {
        return this.taskScheduler._taskFindingKey(task, result, {
            strategyConfig: this.strategyConfig,
            fingerprintFromPayload: (payload) => this._fingerprintFromPayload(payload),
            extractParamName: (taskValue, resultValue) => this._extractParamName(taskValue, resultValue)
        })
    }

    _shouldSkipTaskDueToStrategy(task) {
        return this.taskScheduler.shouldSkipTaskDueToStrategy(task, {
            strategyConfig: this.strategyConfig,
            strategyFindingKeys: this._strategyFindingKeys,
            fingerprintFromPayload: (payload) => this._fingerprintFromPayload(payload),
            extractParamName: (taskValue, resultValue) => this._extractParamName(taskValue, resultValue),
            onSkip: () => this._incrementStrategyStat('skippedDueToStrategy', 1)
        })
    }

    _recordStrategyFinding(task, result) {
        if (!this._shouldCountSuccessAsFindingCandidate(task, result)) {
            return
        }
        if (!this._strategyFindingKeys) {
            this._strategyFindingKeys = new Set()
        }
        this.taskScheduler.recordStrategyFinding(task, result, {
            strategyConfig: this.strategyConfig,
            strategyFindingKeys: this._strategyFindingKeys,
            fingerprintFromPayload: (payload) => this._fingerprintFromPayload(payload),
            extractParamName: (taskValue, resultValue) => this._extractParamName(taskValue, resultValue)
        })
    }

    async _runSpaAttack(task) {
        const payload = task?.payload || {}
        const uiUrl = payload.ui_url
        const taskContext = { original: { request: { url: uiUrl || null, ui_url: uiUrl || null, method: 'GET' } } }
        if (!uiUrl) {
            this._appendRuntimeEvent(Object.assign(
                this._buildTaskRuntimeContext(task, taskContext),
                {
                    type: 'dast_spa_filtered',
                    phase: 'attack_eval',
                    reason: 'missing_ui_url'
                }
            ))
            return null
        }
        if (!payload.param) {
            this._appendRuntimeEvent(Object.assign(
                this._buildTaskRuntimeContext(task, taskContext),
                {
                    type: 'dast_spa_filtered',
                    phase: 'attack_eval',
                    reason: 'missing_param'
                }
            ))
            return null
        }

        const runChecks = async () => {
            return this._withSpaAttackTab(uiUrl, async (tabId) => {
                try {
                    return await browser.tabs.sendMessage(tabId, {
                        type: 'spaParamTest',
                        param: payload.param,
                        payload: payload.payload,
                        checks: payload.checks || [],
                        markerDomain: payload.markerDomain,
                        markerToken: payload.markerToken
                    })
                } catch (err) {
                    if (browser?.scripting?.executeScript) {
                        try {
                            await browser.scripting.executeScript({
                                target: { tabId },
                            files: ['ptk/content/spa_hash_harness.js']
                        })
                        } catch (injectErr) {
                            this._appendTaskRuntimeEvent(task, taskContext, {
                                type: 'dast_spa_filtered',
                                phase: 'harness_bootstrap',
                                reason: 'inject_failed',
                                error: injectErr?.message || String(injectErr)
                            })
                        }
                    }
                    return browser.tabs.sendMessage(tabId, {
                        type: 'spaParamTest',
                        param: payload.param,
                        payload: payload.payload,
                        checks: payload.checks || [],
                        markerDomain: payload.markerDomain,
                        markerToken: payload.markerToken
                    })
                }
            })
        }

        try {
            const res = await runChecks()
            const checks = payload.checks || []
            let filteredReason = null
            let filteredDetails = null

            const pickDomXss = () => {
                const dx = res?.dom_xss
                if (!dx || !dx.vulnerable) return null
                if (dx.sinkKey && this._spaSeenSinks?.has(dx.sinkKey)) {
                    filteredReason = 'duplicate_sink'
                    filteredDetails = { sinkKey: dx.sinkKey }
                    return null
                }
                if (dx.sinkKey && this._spaSeenSinks) {
                    this._spaSeenSinks.add(dx.sinkKey)
                }
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks,
                    sinkKey: dx.sinkKey || null,
                    executed: !!dx.executed,
                    reflected: !!dx.reflected,
                    context: dx.context || null
                })
                const proof = JSON.stringify({
                    executed: !!dx.executed,
                    reflected: !!dx.reflected,
                    sinkKey: dx.sinkKey || null,
                    context: dx.context || null
                })
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickDomRedirect = () => {
                const dr = res?.dom_redirect
                if (!dr || !dr.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(dr.evidence || dr)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickJsInjection = () => {
                const ji = res?.js_injection
                if (!ji || !ji.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(ji.evidence || ji)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickTokenInFragment = () => {
                const t = res?.token_in_fragment
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.tokens || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickTokenLeak = () => {
                const t = res?.token_leak_third_party
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.evidence || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickClientStorage = () => {
                const t = res?.client_storage_leak
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.entries || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickPostMessage = () => {
                const t = res?.postmessage
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.evidence || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickSensitiveData = () => {
                const t = res?.spa_sensitive_data
                if (!t || !t.vulnerable) return null
                const matches = Array.isArray(t.matches) ? t.matches : []
                const nonEmailMatches = matches.filter((m) => String(m?.type || '').toLowerCase() !== 'email')
                // Email-only matches are common in normal profile/account pages and too noisy as security findings.
                if (!nonEmailMatches.length) {
                    filteredReason = 'email_only_sensitive_data'
                    filteredDetails = { matchesCount: matches.length }
                    return null
                }
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.matches || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            for (const chk of checks) {
                if (chk === 'dom_xss') {
                    const r = pickDomXss()
                    if (r) return r
                } else if (chk === 'dom_redirect') {
                    const r = pickDomRedirect()
                    if (r) return r
                } else if (chk === 'js_injection') {
                    const r = pickJsInjection()
                    if (r) return r
                } else if (chk === 'token_in_fragment') {
                    const r = pickTokenInFragment()
                    if (r) return r
                } else if (chk === 'token_leak_third_party') {
                    const r = pickTokenLeak()
                    if (r) return r
                } else if (chk === 'client_storage_leak') {
                    const r = pickClientStorage()
                    if (r) return r
                } else if (chk === 'postmessage') {
                    const r = pickPostMessage()
                    if (r) return r
                } else if (chk === 'spa_sensitive_data') {
                    const r = pickSensitiveData()
                    if (r) return r
                }
            }

            const checksSummary = {}
            checks.forEach(chk => {
                const value = res?.[chk]
                if (value && typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, 'vulnerable')) {
                    checksSummary[chk] = !!value.vulnerable
                    return
                }
                checksSummary[chk] = null
            })
            this._appendRuntimeEvent(Object.assign(
                this._buildTaskRuntimeContext(task, taskContext),
                {
                    type: 'dast_spa_filtered',
                    phase: 'attack_eval',
                    reason: filteredReason || 'no_vulnerability_match',
                    checks: checksSummary,
                    details: filteredDetails
                }
            ))
            return null
        } catch (err) {
            console.error('SPA attack failed', {
                url: uiUrl,
                param: payload.param,
                message: err?.message
            }, err)
            this._appendRuntimeEvent(Object.assign(
                this._buildTaskRuntimeContext(task, taskContext),
                {
                    type: 'dast_spa_filtered',
                    phase: 'attack_eval',
                    reason: 'execution_error',
                    error: err?.message || String(err)
                }
            ))
            return null
        }
    }

    async _withSpaAttackTab(url, fn) {
        let tabId = null
        try {
            const isFirefox = typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
            if (isFirefox) {
                const markedUrl = this._addSpaDialogMarker(url)
                const tab = await browser.tabs.create({ url: markedUrl, active: false })
                tabId = tab.id
                await this._markSpaAttackTab(tabId, { runAt: "document_start" })
            } else {
                const tab = await browser.tabs.create({ url: "about:blank", active: false })
                tabId = tab.id
                await this._markSpaAttackTab(tabId)
                await browser.tabs.update(tabId, { url })
            }
            await this._waitForTabReady(tabId)
            const res = await fn(tabId, url)
            return res
        } finally {
            if (tabId !== null) {
                await this._detachDialogAutoDismiss(tabId)
                try { await browser.tabs.remove(tabId) } catch (_) { }
            }
        }
    }

    _addSpaDialogMarker(url) {
        const marker = "ptk_dast=1"
        if (!url || url.includes(marker)) return url
        const hashIndex = url.indexOf("#")
        if (hashIndex >= 0) {
            const base = url.slice(0, hashIndex)
            const hash = url.slice(hashIndex + 1)
            const joiner = hash.includes("?") ? "&" : "?"
            return `${base}#${hash}${joiner}${marker}`
        }
        const joiner = url.includes("?") ? "&" : "?"
        return `${url}${joiner}${marker}`
    }

    async _attachDialogAutoDismiss(tabId) {
        const isFirefox = typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
        if (isFirefox) return false
        if (!browser?.debugger || !tabId) return false
        const target = { tabId }
        try {
            await browser.debugger.attach(target, "1.3")
        } catch (_) {
            return false
        }
        try {
            await browser.debugger.sendCommand(target, "Page.enable")
            await browser.debugger.sendCommand(target, "Runtime.enable")
        } catch (_) { }
        this._ensureDebuggerDialogListener()
        this._debuggerDialogTabs.add(tabId)
        return true
    }

    async _detachDialogAutoDismiss(tabId) {
        if (!browser?.debugger || !tabId) return
        this._debuggerDialogTabs.delete(tabId)
        try {
            await browser.debugger.detach({ tabId })
        } catch (_) { }
    }

    _ensureDebuggerDialogListener() {
        if (this._debuggerDialogListener || !browser?.debugger?.onEvent) return
        this._debuggerDialogListener = (source, method, params) => {
            if (!source?.tabId || !this._debuggerDialogTabs.has(source.tabId)) return
            if (method !== "Page.javascriptDialogOpening" && method !== "Runtime.javascriptDialogOpening") return
            try {
                browser.debugger.sendCommand(source, "Page.handleJavaScriptDialog", { accept: true })
            } catch (_) { }
        }
        browser.debugger.onEvent.addListener(this._debuggerDialogListener)
    }

    async _markSpaAttackTab(tabId, opts = {}) {
        if (!tabId) return
        const marker = 'ptk_spa_attack_tab'
        const runAt = opts.runAt || "document_start"
        const code = (name) => {
            try {
                if (!window.name || !window.name.includes(name)) {
                    window.name = (window.name ? window.name + " " : "") + name
                }
            } catch (_) { }
        }
        if (browser?.scripting?.executeScript) {
            try {
                await browser.scripting.executeScript({
                    target: { tabId, allFrames: true },
                    func: code,
                    args: [marker]
                })
                return
            } catch (_) { }
        }
        if (browser?.tabs?.executeScript) {
            try {
                await browser.tabs.executeScript(tabId, {
                    code: `try{var n=${JSON.stringify(marker)};if(!window.name||window.name.indexOf(n)===-1){window.name=(window.name?window.name+' ':'')+n;}}catch(_){}`,
                    allFrames: true,
                    runAt
                })
            } catch (_) { }
        }
    }

    async _waitForTabReady(tabId, timeoutMs = 8000) {
        return new Promise((resolve) => {
            let done = false
            const finish = () => {
                if (done) return
                done = true
                try { browser.tabs.onUpdated.removeListener(listener) } catch (_) { }
                resolve()
            }
            const timer = setTimeout(() => {
                clearTimeout(timer)
                finish()
            }, timeoutMs)
            const listener = (updatedTabId, info) => {
                if (updatedTabId === tabId && info.status === 'complete') {
                    clearTimeout(timer)
                    finish()
                }
            }
            browser.tabs.onUpdated.addListener(listener)
        })
    }

    async _drainRequestQueue() {
        while (this.isRunning && this._requestQueue.size()) {
            const raw = this._requestQueue.dequeue()
            try {
                const plan = await this.buildAttackPlan(raw)
                if (plan) {
                    this._enqueuePlan(plan)
                }
                if (!this.isRunning) break
            } catch (err) {
                console.warn('Failed to build attack plan', err)
            }
        }
    }


    async activeAttack(schema) {
        try {
            let request = new ptk_request()
            if (!schema.opts) schema.opts = {}
            if (!schema.request || typeof schema.request !== 'object') {
                schema.request = {}
            }
            schema.request.timestamp = Date.now()
            schema.opts.ptk_source = 'dast'
            const isFirefox = typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
            if (isFirefox) {
                request.useListeners = true
                schema.opts.use_dnr = false
            }
            if (typeof schema.opts.override_headers === 'undefined') {
                schema.opts.override_headers = true
            }
            if (typeof schema.opts.preserve_browser_headers === 'undefined') {
                schema.opts.preserve_browser_headers = false
            }
            if (typeof schema.opts.keepalive === 'undefined') {
                schema.opts.keepalive = false
            }
            if (typeof schema.opts.retry_on_transport_failure === 'undefined') {
                schema.opts.retry_on_transport_failure = true
            }
            if (typeof schema.opts.transport_retry_count === 'undefined') {
                schema.opts.transport_retry_count = 1
            }
            if (typeof schema.opts.transport_retry_delay_ms === 'undefined') {
                schema.opts.transport_retry_delay_ms = 75
            }
            schema.opts.log_fingerprint = true
            const requestTimeoutMs = this._resolveRequestTimeoutMs(
                schema?.opts?.requestTimeoutMs,
                this.requestTimeoutMs
            )
            if (requestTimeoutMs) {
                schema.opts.requestTimeoutMs = requestTimeoutMs
            }
            return request.sendRequest(schema)
        } catch (e) {
            // optionally: log or handle
        }
    }

    async executeOriginal(schema) {
        let _schema = JSON.parse(JSON.stringify(schema))
        let request = new ptk_request()
        _schema.opts = _schema.opts || {}
        _schema.opts.ptk_source = 'dast'
        const isFirefox = typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
        if (isFirefox) {
            request.useListeners = true
            _schema.opts.use_dnr = false
        }
        _schema.opts.override_headers = true
        _schema.opts.follow_redirect = true
        const requestTimeoutMs = this._resolveRequestTimeoutMs(
            _schema?.opts?.requestTimeoutMs,
            this.originalRequestTimeoutMs || this.requestTimeoutMs
        )
        if (requestTimeoutMs) {
            _schema.opts.requestTimeoutMs = requestTimeoutMs
        }
        return Promise.resolve(request.sendRequest(_schema))
    }

    _isTemplateTechniqueTask(task) {
        const hooks = this._moduleRuntimeHooks(task?.module)
        if (hooks.some((hook) => String(hook || '').toLowerCase() === 'template_render_followup')) {
            return true
        }
        const techniques = this._moduleCapabilities(task?.module)
        if (techniques.some((technique) => String(technique || '').toLowerCase() === 'template_injection')) {
            return true
        }
        const moduleId = String(task?.module?.id || task?.moduleId || '').toLowerCase()
        return moduleId === 'ssti' || moduleId === 'el_injection'
    }

    _getHeaderValue(headers, name) {
        const wanted = String(name || '').toLowerCase()
        if (!wanted) return null
        const normalized = this._normalizeHttpHeaders(headers) || []
        const match = normalized.find((header) => String(header?.name || '').toLowerCase() === wanted)
        return match?.value || null
    }

    _isHtmlLikeResponse(entry) {
        const response = this._extractResponseShape(entry)
        if (!response || typeof response !== 'object') return false
        const mimeType = String(
            response?.mimeType || this._getHeaderValue(response?.headers, 'content-type') || ''
        ).toLowerCase()
        if (mimeType.includes('text/html') || mimeType.includes('application/xhtml+xml')) {
            return true
        }
        const body = typeof response?.body === 'string' ? response.body : ''
        return /^\s*<!doctype html/i.test(body) || /^\s*<html\b/i.test(body)
    }

    _resolveSameOriginUrl(candidate, baseUrl) {
        if (!candidate || !baseUrl) return null
        try {
            const resolved = new URL(candidate, baseUrl)
            const base = new URL(baseUrl)
            if (!['http:', 'https:'].includes(resolved.protocol)) return null
            if (resolved.origin !== base.origin) return null
            return resolved.toString()
        } catch (_) {
            return null
        }
    }

    _recentHtmlGetUrls(baseUrl, limit = 3) {
        if (!baseUrl || limit <= 0) return []
        const records = Array.isArray(this.scanResult?.requests) ? this.scanResult.requests : []
        const urls = []
        const seen = new Set()
        for (let i = records.length - 1; i >= 0 && urls.length < limit; i -= 1) {
            const request = records[i]?.original?.request
            const response = records[i]?.original?.response
            if (!request?.url) continue
            if (String(request.method || 'GET').toUpperCase() !== 'GET') continue
            if (!this._isHtmlLikeResponse(response)) continue
            const resolved = this._resolveSameOriginUrl(request.ui_url || request.url, baseUrl)
            if (!resolved || seen.has(resolved)) continue
            seen.add(resolved)
            urls.push(resolved)
        }
        return urls
    }

    _shouldRunTemplateRenderFollowup(task, executed, context = null) {
        if (!this._isTemplateTechniqueTask(task)) return false
        const request = executed?.request || context?.original?.request || null
        if (!request) return false
        const method = String(request.method || 'GET').toUpperCase()
        if (!['POST', 'PUT', 'PATCH'].includes(method)) return false
        const statusCode = Number(executed?.response?.statusCode ?? executed?.response?.status)
        if (Number.isFinite(statusCode) && statusCode >= 500) return false
        const contentType = String(this._getHeaderValue(request.headers, 'content-type') || '').toLowerCase()
        const body = request?.body
        const hasBody = typeof body === 'string'
            ? body.length > 0
            : !!(body && typeof body === 'object' && Object.keys(body).length)
        return (
            hasBody ||
            contentType.includes('application/x-www-form-urlencoded') ||
            contentType.includes('application/json') ||
            contentType.includes('multipart/form-data') ||
            contentType.includes('text/plain')
        )
    }

    _collectTemplateRenderFollowupUrls(task, executed, context = null) {
        const baseUrl = executed?.request?.url || context?.original?.request?.url || null
        if (!baseUrl) return []
        const originalRequest = context?.original?.request || {}
        const urls = []
        const seen = new Set()
        const add = (candidate) => {
            const resolved = this._resolveSameOriginUrl(candidate, baseUrl)
            if (!resolved || seen.has(resolved)) return
            seen.add(resolved)
            urls.push(resolved)
        }

        add(this._getHeaderValue(executed?.response?.headers, 'location'))
        add(this._getHeaderValue(originalRequest?.headers, 'referer'))
        add(this._getHeaderValue(executed?.request?.headers, 'referer'))
        add(executed?.request?.ui_url)
        add(originalRequest?.ui_url)
        add(baseUrl)
        this._recentHtmlGetUrls(baseUrl, 3).forEach(add)

        return urls.slice(0, 4)
    }

    _decodeHtmlDiscoveryValue(value) {
        return String(value || '')
            .replace(/&amp;/gi, '&')
            .replace(/&quot;/gi, '"')
            .replace(/&#0*39;/gi, "'")
            .replace(/&#x0*27;/gi, "'")
            .replace(/&lt;/gi, '<')
            .replace(/&gt;/gi, '>')
    }

    _isSeedableHtmlLinkUrl(candidate, baseUrl) {
        const raw = String(candidate || '').trim()
        if (!raw) return null
        if (/^(javascript|mailto|tel|data|blob):/i.test(raw)) return null
        if (raw === '#') return null
        const resolved = this._resolveSameOriginUrl(this._decodeHtmlDiscoveryValue(raw), baseUrl)
        if (!resolved) return null
        try {
            const parsed = new URL(resolved)
            if (STATIC_ASSET_LINK_REGEX.test(`${parsed.pathname}${parsed.search}`)) {
                return null
            }
            return parsed.toString()
        } catch (_) {
            return null
        }
    }

    _extractHtmlDiscoveredUrls(entry, max = Number.POSITIVE_INFINITY) {
        if (!this._isHtmlLikeResponse(entry) || max <= 0) return []
        const request = this._extractRequestShape(entry)
        const response = this._extractResponseShape(entry)
        const baseUrl = request?.ui_url || request?.url || null
        const body = typeof response?.body === 'string' ? response.body : ''
        if (!baseUrl || !body) return []

        const urls = []
        const seen = new Set()
        const add = (candidate) => {
            const resolved = this._isSeedableHtmlLinkUrl(candidate, baseUrl)
            if (!resolved || seen.has(resolved)) return
            seen.add(resolved)
            urls.push(resolved)
        }

        const attrRegex = /\b(?:href|src|action|data-href)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'<>`]+))/ig
        let match = null
        while ((match = attrRegex.exec(body)) && urls.length < max) {
            add(match[1] || match[2] || match[3] || '')
        }

        return urls
    }

    _seedHtmlDiscoveredRequests(entry) {
        if (!this.isRunning) return 0
        if (!this._isHtmlLinkDiscoveryEnabled()) return 0
        const request = this._extractRequestShape(entry)
        const baseUrl = request?.ui_url || request?.url || null
        if (!baseUrl) return 0
        const method = String(request?.method || 'GET').toUpperCase()
        if (method !== 'GET') return 0
        const admissionBudget = this._remainingHtmlLinkDiscoveryAdmissionBudget()
        if (admissionBudget <= 0) {
            this._drainPendingHtmlDiscoveryQueue()
            return 0
        }

        const discoveredUrls = this._extractHtmlDiscoveredUrls(entry, admissionBudget)
        if (!discoveredUrls.length) {
            this._drainPendingHtmlDiscoveryQueue()
            return 0
        }

        let queued = 0
        const samples = []
        discoveredUrls.forEach((url) => {
            if (!this._queueHtmlDiscoveredUrl(url, baseUrl)) return
            queued += 1
            if (samples.length < 4) samples.push(url)
        })

        const seeded = this._drainPendingHtmlDiscoveryQueue()
        if (queued > 0) {
            this._appendRuntimeEvent({
                type: 'dast_html_links_buffered',
                phase: 'html_discovery',
                url: baseUrl,
                queuedCount: queued,
                seededCount: seeded,
                samples,
                pendingDiscovered: this._pendingHtmlLinkDiscoveryCount(),
                budget: this._normalizeHtmlLinkDiscoveryBudget(this.settings?.htmlLinkDiscoveryBudget),
                remainingBudget: this._remainingHtmlLinkDiscoveryBudget()
            })
        }

        return seeded
    }

    async _runTemplateRenderFollowup(task, executed, context = null) {
        if (!this._shouldRunTemplateRenderFollowup(task, executed, context)) return null
        const candidates = this._collectTemplateRenderFollowupUrls(task, executed, context)
        if (!candidates.length) {
            this._appendTaskRuntimeEvent(task, context, {
                type: 'dast_render_followup_skipped',
                phase: 'render_followup',
                reason: 'no_followup_candidates'
            })
            return null
        }

        this._appendTaskRuntimeEvent(task, context, {
            type: 'dast_render_followup_started',
            phase: 'render_followup',
            candidateCount: candidates.length
        })

        for (const url of candidates) {
            const followup = this._buildFollowupRequest(executed, url)
            if (!followup) continue
            const followupExecuted = await this.activeAttack(followup)
            if (!followupExecuted) continue
            const res = task.module.validateAttack(followupExecuted, context.original)
            if (!res?.success) continue

            this._appendTaskRuntimeEvent(task, context, {
                type: 'dast_render_followup_confirmed',
                phase: 'render_followup',
                url
            })
            const proofPrefix = `Follow-up render confirmed at ${url}.`
            return {
                success: true,
                proof: res?.proof ? `${proofPrefix} ${res.proof}` : proofPrefix,
                detector: res?.detector || null,
                match: res?.match || url,
                confidence: res?.confidence,
                severity: res?.severity,
                renderFollowupConfirmed: true,
                renderFollowup: {
                    url,
                    request: followupExecuted?.request || null,
                    response: followupExecuted?.response || null
                }
            }
        }

        this._appendTaskRuntimeEvent(task, context, {
            type: 'dast_render_followup_inconclusive',
            phase: 'render_followup'
        })
        return null
    }

    async _runTracking(task, executed, context = null) {
        const tracking = this._attackRuntimeConfirmation(task?.attack, 'tracking')
        if (!tracking || tracking.enabled !== true) return null
        const mode = tracking.mode || 'followup_get'
        if (mode !== 'followup_get') {
            this._appendTaskRuntimeEvent(task, context, {
                type: 'dast_tracking_skipped',
                phase: 'tracking',
                reason: 'unsupported_tracking_mode',
                mode
            })
            return null
        }

        const marker = tracking.marker || 'PTK_UPLOAD_TEST'
        const trackingConfidence = typeof tracking.confidence === 'number' ? tracking.confidence : 95
        const responseBody = executed?.response?.body || ''
        if (marker && responseBody.includes(marker)) {
            return {
                success: true,
                proof: `Upload marker detected in response body.`,
                confidence: trackingConfidence,
                trackingConfirmed: true
            }
        }

        const candidates = this._extractTrackingUrls(task, executed)
        if (!candidates.length) return null

        for (const url of candidates) {
            const followup = this._buildFollowupRequest(executed, url)
            if (!followup) continue
            const res = await this.activeAttack(followup)
            const body = res?.response?.body || ''
            if (marker && body.includes(marker)) {
                return {
                    success: true,
                    proof: `Upload marker retrieved from ${url}.`,
                    tracking: { url },
                    confidence: trackingConfidence,
                    trackingConfirmed: true
                }
            }
        }

        return null
    }

    _extractTrackingUrls(task, executed) {
        const tracking = this._attackRuntimeConfirmation(task?.attack, 'tracking') || {}
        const filename =
            tracking.filename ||
            task?.attack?.action?.files?.[0]?.filename ||
            task?.attack?.metadata?.action?.files?.[0]?.filename ||
            null
        const urls = new Set()
        const headers = executed?.response?.headers || []
        const locationHeader = headers.find(
            (h) => (h?.name || '').toLowerCase() === 'location'
        )
        if (locationHeader?.value) {
            if (!filename || locationHeader.value.includes(filename)) {
                urls.add(locationHeader.value)
            }
        }

        const body = executed?.response?.body || ''
        if (filename && body.includes(filename)) {
            const escaped = filename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            const absRe = new RegExp(`https?:\\/\\/[^\"'\\s<>]*${escaped}[^\"'\\s<>]*`, 'ig')
            const relRe = new RegExp(`\\/[^\"'\\s<>]*${escaped}[^\"'\\s<>]*`, 'ig')
            let match
            while ((match = absRe.exec(body))) urls.add(match[0])
            while ((match = relRe.exec(body))) urls.add(match[0])
        }

        return Array.from(urls).slice(0, 3)
    }

    _buildFollowupRequest(executed, url) {
        if (!executed?.request?.url || !url) return null
        let resolved = url
        try {
            resolved = new URL(url, executed.request.url).toString()
        } catch {
            return null
        }

        const schema = JSON.parse(JSON.stringify(executed))
        schema.request = schema.request || {}
        schema.response = {}
        schema.request.method = 'GET'
        schema.request.url = resolved
        schema.request.body = null
        schema.request.raw = null
        schema.opts = schema.opts || {}
        schema.opts.override_headers = true
        schema.opts.follow_redirect = true
        return schema
    }

    _sleep(ms) {
        return new Promise(r => setTimeout(r, ms))
    }

    _confirmAttackFromContent(data) {
        if (!data?.attackValue?.ptk) return
        const token = data.attackValue.ptk
        const requests = Array.isArray(this.scanResult?.requests) ? this.scanResult.requests : []
        for (const request of requests) {
            const attacks = Array.isArray(request?.attacks) ? request.attacks : []
            for (let idx = 0; idx < attacks.length; idx++) {
                const attack = attacks[idx]
                if (!attack || attack.success) continue
                if (attack.actionToken && attack.actionToken === token) {
                    attack.success = true
                    attack.proof = 'Confirmed by code execution on ' + data.location + '. Attack parameter value is: ' + token
                    this._addUnifiedFinding(request, attack, idx)
                    return
                }
            }
        }
    }

    _addUnifiedFinding(requestRecord, attack, index = 0) {
        if (!requestRecord || !attack || !attack.success || attack.__findingRecorded) return
        const classification = this._buildAttackClassification(attack, `attack-${index}`)
        const ruleIdLower = String(classification.ruleId || '').toLowerCase()
        if (ruleIdLower.includes('baseline')) {
            return
        }
        const moduleId = classification.moduleId
        const moduleName = classification.moduleName
        const vulnId = classification.vulnId
        const ruleId = classification.ruleId
        const ruleName = classification.ruleName
        const severity = classification.severity
        const reqSchema = attack.request && attack.request.request ? attack.request.request : attack.request
        const originalReq = requestRecord?.original?.request || requestRecord?.original || {}
        const attackRecord = attack.__requestRecordEntry || attack
        const mutation = Array.isArray(attack?.metadata?.mutations) ? attack.metadata.mutations[0] : null
        const payloadValue = attack?.metadata?.payload || attack?.payload || mutation?.after || attackRecord?.payload || null
        const location = {
            url: reqSchema?.url || attack.request?.url || attack.request?.ui_url || originalReq?.url || null,
            method: reqSchema?.method || attack.request?.method || originalReq?.method || null,
            param: attack.param || attack.metadata?.attacked?.name || (Array.isArray(attack.metadata?.mutations) && attack.metadata.mutations[0]?.name) || null
        }
        const uniqueFindingState = this._shouldRecordActiveUniqueFinding(
            classification.moduleMeta,
            moduleId,
            ruleId,
            location.url,
            location.param
        )
        if (!uniqueFindingState.allowed) {
            const existingFindingId = uniqueFindingState?.existingFinding?.id || null
            if (existingFindingId) {
                attack.findingId = existingFindingId
            }
            attack.__findingRecorded = true
            if (attack.__requestRecordEntry && attack.__requestRecordEntry !== attack) {
                attack.__requestRecordEntry.__findingRecorded = true
                if (existingFindingId) {
                    attack.__requestRecordEntry.findingId = existingFindingId
                }
            }
            return
        }
        const logAttackId = attack.id || attack.__requestRecordEntry?.id || attack.__attackKey || null
        const attackedParam = attack.param
            || attack.metadata?.attacked?.name
            || (Array.isArray(attack.metadata?.mutations) && attack.metadata.mutations[0]?.name)
            || null
        const confidenceDetails = this._resolveAttackConfidenceDetails(attack, classification)
        const confidence = confidenceDetails.confidence
        const attackMeta = attack?.metadata || {}
        const attackMetaEvidence = {
            attacked: attackMeta.attacked || null,
            checks: attackMeta.checks || null,
            sinkKey: attackMeta.sinkKey || null,
            executed: typeof attackMeta.executed === 'boolean' ? attackMeta.executed : null,
            reflected: typeof attackMeta.reflected === 'boolean' ? attackMeta.reflected : null,
            context: attackMeta.context || null,
            detector: attack?.detector || attackMeta.validation?.type || null,
            match: attack?.match || null,
            confidence: Number.isFinite(confidence) ? confidence : null,
            codecChain: attackMeta.codecChain || attackMeta?.deserialization?.candidate?.codecChain || null,
            formatFamily: attackMeta.formatFamily || attackMeta.deserFamily || attackMeta?.deserialization?.candidate?.formatFamily || null,
            mutationsRun: attackMeta.mutationsRun || null,
            diffSignals: attackMeta.diffSignals || null,
            confirmation: attackMeta.confirmation || null
        }
        Object.keys(attackMetaEvidence).forEach((key) => {
            if (attackMetaEvidence[key] === null) delete attackMetaEvidence[key]
        })
        const resolverKey = (requestRecord?.id && logAttackId)
            ? `${requestRecord.id}::${logAttackId}`
            : null
        const dastEvidence = {
            attackId: logAttackId,
            requestId: requestRecord?.id || null,
            resolverKey,
            param: location.param || attackedParam || null,
            payload: payloadValue || null,
            proof: attackRecord?.proof || null,
            confidenceSignals: Array.isArray(confidenceDetails.signals) ? confidenceDetails.signals : [],
            codecChain: attackMeta.codecChain || attackMeta?.deserialization?.candidate?.codecChain || null,
            formatFamily: attackMeta.formatFamily || attackMeta.deserFamily || attackMeta?.deserialization?.candidate?.formatFamily || null,
            mutationsRun: attackMeta.mutationsRun || null,
            diffSignals: attackMeta.diffSignals || null,
            confirmation: attackMeta.confirmation || null
        }
        if (Object.keys(attackMetaEvidence).length) {
            dastEvidence.meta = attackMetaEvidence
        }
        const tags = Array.isArray(classification.tags) ? classification.tags : []
        const findingInstanceId = resolverKey || `${requestRecord?.id || 'req'}::${logAttackId || `attack-${index}`}`
        const unifiedFinding = {
            id: `${this.scanResult.scanId || 'scan'}::DAST::${moduleId}::${ruleId}::${findingInstanceId}`,
            engine: "DAST",
            scanId: this.scanResult.scanId || null,
            moduleId,
            moduleName,
            ruleId,
            ruleName,
            vulnId: vulnId || moduleId,
            category: classification.category || 'dast',
            severity,
            confidence: Number.isFinite(confidence) ? confidence : null,
            owasp: classification.owasp || null,
            cwe: classification.cwe || null,
            tags: classification.tags || [],
            description: classification.description || null,
            recommendation: classification.recommendation || null,
            links: classification.links || null,
            location,
            createdAt: new Date().toISOString(),
            evidence: {
                dast: dastEvidence
            }
        }
        resolveFindingTaxonomy({
            finding: unifiedFinding,
            ruleMeta: classification.ruleMeta,
            moduleMeta: classification.moduleMeta
        })
        const normalizedFinding = normalizeFinding({
            engine: "DAST",
            moduleMeta: classification.moduleMeta || {},
            ruleMeta: classification.ruleMeta || {},
            scanId: this.scanResult?.scanId || null,
            finding: unifiedFinding
        })
        addFinding(this.scanResult, normalizedFinding)
        const groupKey = [
            "DAST",
            normalizedFinding.vulnId,
            moduleId,
            ruleId,
            normalizedFinding?.location?.url || location.url || "",
            normalizedFinding?.location?.param || location.param || ""
        ].join('@@')
        addFindingToGroup(this.scanResult, normalizedFinding, groupKey, {
            url: normalizedFinding?.location?.url || location.url,
            param: normalizedFinding?.location?.param || location.param || null
        })
        if (attack && typeof attack === 'object') {
            attack.findingId = normalizedFinding.id
            attack.__findingRecorded = true
            if (attack.__requestRecordEntry && attack.__requestRecordEntry !== attack) {
                attack.__requestRecordEntry.findingId = normalizedFinding.id
            }
        }
        if (uniqueFindingState?.uniqueKey) {
            if (!this._activeUniqueFindingKeys) this._activeUniqueFindingKeys = new Set()
            this._activeUniqueFindingKeys.add(uniqueFindingState.uniqueKey)
        }
    }

    _decorateAttackResult(result, task) {
        if (!result || !task) return
        const moduleMeta = this._moduleMetadataView(task.module)
        const attackMeta = this._attackMetadataView(task.module, task.attack, result.metadata || {})
        result.metadata = attackMeta
        result.__moduleId = task.moduleId || task.module?.id || moduleMeta.id || attackMeta.moduleId || null
        result.__moduleName = task.moduleName || task.module?.name || moduleMeta.name || attackMeta.moduleName || result.__moduleId
        result.__moduleMetadata = moduleMeta
        result.__moduleVulnId = task.module?.vulnId || moduleMeta.vulnId || attackMeta.vulnId || null
        result.__attackKey = task.attackKey || attackMeta.id || null
    }

    _resolveAttackConfidenceDetails(attack, classification = {}) {
        const clamp = (value) => {
            if (!Number.isFinite(value)) return null
            return Math.min(100, Math.max(0, Math.round(value)))
        }
        const mergeSignals = (...signalSets) => {
            return Array.from(new Set(signalSets.flat().filter(Boolean)))
        }
        const resolveExplicitOverride = () => {
            if (Number.isFinite(attack?.confidence)) {
                const value = clamp(attack.confidence)
                return { confidence: value, signals: [`override:attack:${value}`] }
            }
            if (Number.isFinite(attack?.metadata?.confidence)) {
                const value = clamp(attack.metadata.confidence)
                return { confidence: value, signals: [`override:rule:${value}`] }
            }
            if (Number.isFinite(attack?.metadata?.confidenceDefault)) {
                const value = clamp(attack.metadata.confidenceDefault)
                return { confidence: value, signals: [`override:module:${value}`] }
            }
            return null
        }
        const explicitOverride = resolveExplicitOverride()
        if (
            attack?.oastConfirmed === true ||
            (
                attack?.metadata?.confirmation?.type === 'oast_callback' &&
                attack?.metadata?.confirmation?.confirmed === true
            )
        ) {
            if (explicitOverride) {
                return {
                    confidence: explicitOverride.confidence,
                    signals: mergeSignals(explicitOverride.signals, ["oast:callback_confirmed"])
                }
            }
            return { confidence: 98, signals: ["oast:callback_confirmed"] }
        }
        if (
            attack?.success &&
            (
                attack?.runtime?.confirmation?.oast?.enabled === true
                || attack?.metadata?.oast?.enabled === true
            ) &&
            attack?.metadata?.confirmation?.type === 'oast_callback' &&
            attack?.metadata?.confirmation?.confirmed === false
        ) {
            return { confidence: 65, signals: ["oast:callback_not_observed"] }
        }
        if (attack?.trackingConfirmed) {
            if (explicitOverride) {
                return {
                    confidence: explicitOverride.confidence,
                    signals: mergeSignals(explicitOverride.signals, ["tracking:confirmed"])
                }
            }
            return { confidence: 95, signals: ["tracking:confirmed"] }
        }
        if (attack?.renderFollowupConfirmed) {
            if (explicitOverride) {
                return {
                    confidence: explicitOverride.confidence,
                    signals: mergeSignals(explicitOverride.signals, ["render_followup:confirmed"])
                }
            }
            return { confidence: 90, signals: ["render_followup:confirmed"] }
        }
        if (explicitOverride) {
            return explicitOverride
        }
        const rule = classification?.ruleMeta?.validation?.rule || attack?.metadata?.validation?.rule || null
        const ruleStr = (() => {
            try {
                return JSON.stringify(rule || {})
            } catch (_) {
                return ""
            }
        })()
        const hasModuleBaseline = ruleStr.includes("module.executed")
        const hasOriginalBaseline = ruleStr.includes("original.response")
        const hasTimeSignal = ruleStr.includes("timeMs")
        const hasStatusSignal = ruleStr.includes("statusCode")
        const hasRegexSignal = ruleStr.includes("\"regex\"")
        const hasBodySignal = ruleStr.includes("response.body")
        const hasHeaderSignal = ruleStr.includes("headers")

        if (hasModuleBaseline) {
            return { confidence: 84, signals: ["validation:paired:module"] }
        }
        if (hasTimeSignal) {
            return { confidence: 58, signals: ["validation:time_single_sample"] }
        }
        if (hasOriginalBaseline) {
            return { confidence: 78, signals: ["validation:paired:original"] }
        }
        if (hasStatusSignal && !hasRegexSignal && !hasBodySignal && !hasHeaderSignal) {
            return { confidence: 52, signals: ["validation:status_single_sample"] }
        }
        if (hasRegexSignal && !hasStatusSignal && !hasTimeSignal) {
            return { confidence: 68, signals: ["validation:pattern_single_sample"] }
        }
        if (attack?.metadata?.executed === true || attack?.executed === true) {
            return { confidence: 60, signals: ["execution:observed"] }
        }
        if (rule) {
            return { confidence: 74, signals: ["validation:rule"] }
        }
        if (attack?.success) {
            return { confidence: 55, signals: ["success:observed"] }
        }
        return { confidence: 30, signals: ["validation:none"] }
    }

    setResultMutationListener(listener) {
        this._resultMutationListener = typeof listener === 'function' ? listener : null
    }

    setAutomationHooks(hooks) {
        if (hooks && typeof hooks === 'object') {
            this.automationHooks = {
                sessionId: hooks.sessionId,
                onTaskStarted: hooks.onTaskStarted,
                onTaskFinished: hooks.onTaskFinished
            }
        } else {
            this.automationHooks = null
        }
    }

    _automationTaskStarted() {
        const hooks = this.automationHooks
        if (!hooks || typeof hooks.onTaskStarted !== 'function') {
            return null
        }
        try {
            hooks.onTaskStarted()
        } catch (err) {
            console.warn('[PTK DAST] automation onTaskStarted hook failed', {
                sessionId: hooks.sessionId || null,
                error: err?.message || String(err)
            })
        }
        return hooks
    }

    _automationTaskFinished(token, error) {
        if (!token || typeof token.onTaskFinished !== 'function') {
            return
        }
        try {
            token.onTaskFinished(error)
        } catch (err) {
            console.warn('[PTK DAST] automation onTaskFinished hook failed', {
                sessionId: token.sessionId || null,
                taskError: error?.message || error || null,
                error: err?.message || String(err)
            })
        }
    }

    waitForIdle(timeoutMs) {
        if (!this.isRunning) {
            return Promise.resolve()
        }
        if (this._isIdle()) {
            return Promise.resolve()
        }
        return new Promise((resolve) => {
            const waiter = { resolve }
            if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
                waiter.timer = setTimeout(() => {
                    if (waiter.timer) {
                        clearTimeout(waiter.timer)
                        waiter.timer = null
                    }
                    this._idleResolvers.delete(waiter)
                    resolve()
                }, timeoutMs)
            }
            this._idleResolvers.add(waiter)
        })
    }

    _buildAttackClassification(attack, fallbackRuleId = null) {
        const moduleMeta = attack?.__moduleMetadata || attack?.metadata || {}
        const attackMeta = attack?.metadata || {}
        const ptkMeta = this._resolveAttackPtkMeta(attack)
        const moduleId = attack?.__moduleId
            || attack?.moduleId
            || moduleMeta.id
            || moduleMeta.moduleId
            || attackMeta.moduleId
            || 'module'
        const moduleName = attack?.__moduleName
            || attack?.moduleName
            || moduleMeta.name
            || moduleId
        const vulnId = attack?.__moduleVulnId
            || attack?.vulnId
            || moduleMeta.vulnId
            || moduleMeta.category
            || moduleId
        const ruleId = attack?.ruleId
            || attackMeta.id
            || attackMeta.ruleId
            || attackMeta.attackId
            || fallbackRuleId
            || attack?.__attackKey
            || 'attack'
        const ruleName = attack?.ruleName || attackMeta.name || ruleId
        const baseSeverity = attack?.severity || resolveEffectiveSeverity({
            moduleMeta,
            attackMeta
        })
        const severity = baseSeverity
        const category = attack?.category || attackMeta.category || moduleMeta.category || 'dast'
        const description = attack?.description || attackMeta.description || moduleMeta.description || null
        const recommendation = attack?.recommendation || attackMeta.recommendation || moduleMeta.recommendation || null
        const links = attack?.links || attackMeta.links || moduleMeta.links || null
        const tags = Array.isArray(attack?.tags)
            ? attack.tags
            : (Array.isArray(moduleMeta.tags) ? moduleMeta.tags : [])
        return {
            moduleId,
            moduleName,
            vulnId,
            ruleId,
            ruleName,
            severity,
            category,
            owasp: attack?.owasp || moduleMeta.owasp || null,
            cwe: attack?.cwe || moduleMeta.cwe || null,
            tags,
            description,
            recommendation,
            links,
            outputKind: ptkMeta.outputKind || null,
            reconKind: ptkMeta.reconKind || null,
            presentationAggregate: ptkMeta?.presentation?.aggregate || null,
            uiSurface: ptkMeta.uiSurface || null,
            moduleMeta,
            ruleMeta: attackMeta
        }
    }

    _resolveAttackPtkMeta(attack = null) {
        const normalize = (value) => (
            value && typeof value === 'object' && !Array.isArray(value)
                ? cloneValue(value)
                : {}
        )
        const attackMeta = attack?.metadata && typeof attack.metadata === 'object'
            ? attack.metadata
            : {}
        const moduleLevel = normalize(attackMeta?.extensions?.ptk)
        const attackLevel = normalize(attackMeta?.metadata?.extensions?.ptk)
        return Object.assign({}, moduleLevel, attackLevel)
    }

    _isReconAttackResult(attack = null) {
        const ptkMeta = this._resolveAttackPtkMeta(attack)
        return String(ptkMeta.outputKind || '').toLowerCase() === 'recon'
    }

    _ensureReconSink() {
        if (!Array.isArray(this.scanResult?.recon)) {
            this.scanResult.recon = []
        }
        return this.scanResult.recon
    }

    _normalizeReconObservationRoute(location = {}) {
        const method = String(location?.method || 'GET').trim().toUpperCase() || 'GET'
        const rawUrl = location?.url || location?.runtimeUrl || location?.route || null
        if (!rawUrl) {
            return `${method}|/`
        }
        try {
            const parsed = new URL(String(rawUrl), this.host ? `http://${String(this.host).trim()}` : undefined)
            const pathname = String(parsed.pathname || '/').trim().toLowerCase() || '/'
            return `${method}|${pathname}`
        } catch (_) {
            const normalized = String(rawUrl || '')
                .replace(/[?#].*$/, '')
                .trim()
                .toLowerCase() || '/'
            return `${method}|${normalized}`
        }
    }

    _buildReconObservationDedupeKey(classification = {}, location = {}, param = null) {
        const normalizedRoute = this._normalizeReconObservationRoute(location)
        const normalizedParam = String(param || '').trim().toLowerCase()
        return [
            String(classification.moduleId || ''),
            String(classification.ruleId || ''),
            normalizedRoute,
            normalizedParam
        ].join('|')
    }

    _addReconObservation(requestRecord, attack, index = 0) {
        if (!requestRecord || !attack || !attack.success || attack.__reconRecorded) return
        const classification = this._buildAttackClassification(attack, `attack-${index}`)
        if (String(classification.outputKind || '').toLowerCase() !== 'recon') {
            return
        }
        const ptkMeta = this._resolveAttackPtkMeta(attack)
        const reqSchema = attack.request && attack.request.request ? attack.request.request : attack.request
        const originalReq = requestRecord?.original?.request || requestRecord?.original || {}
        const mutation = Array.isArray(attack?.metadata?.mutations) ? attack.metadata.mutations[0] : null
        const payloadValue = attack?.metadata?.payload || attack?.payload || mutation?.after || null
        const location = {
            url: reqSchema?.url || attack?.request?.url || attack?.request?.ui_url || originalReq?.url || null,
            method: reqSchema?.method || attack?.request?.method || originalReq?.method || null,
            param: attack?.param || attack?.metadata?.attacked?.name || (Array.isArray(attack?.metadata?.mutations) && attack.metadata.mutations[0]?.name) || null
        }
        const sink = this._ensureReconSink()
        const dedupeKey = this._buildReconObservationDedupeKey(classification, location, location.param)
        const existing = sink.find((entry) => entry?.dedupeKey === dedupeKey)
        if (existing) {
            existing.count = Number(existing.count || 1) + 1
            existing.lastSeenAt = new Date().toISOString()
            const existingEvidence = existing?.evidence?.dast && typeof existing.evidence.dast === 'object'
                ? existing.evidence.dast
                : null
            if (existingEvidence && !existingEvidence.requestId && requestRecord?.id) {
                existingEvidence.requestId = requestRecord.id
            }
            if (existingEvidence && !existingEvidence.attackId) {
                existingEvidence.attackId = attack.id || attack.__requestRecordEntry?.id || attack.__attackKey || null
            }
            attack.__reconRecorded = true
            if (attack.__requestRecordEntry && attack.__requestRecordEntry !== attack) {
                attack.__requestRecordEntry.__reconRecorded = true
            }
            return
        }
        const logAttackId = attack.id || attack.__requestRecordEntry?.id || attack.__attackKey || null
        const resolverKey = (requestRecord?.id && logAttackId)
            ? `${requestRecord.id}::${logAttackId}`
            : null
        sink.push({
            id: `${this.scanResult.scanId || 'scan'}::DAST::RECON::${classification.moduleId}::${classification.ruleId}::${resolverKey || `attack-${index}`}`,
            engine: "DAST",
            scanId: this.scanResult.scanId || null,
            moduleId: classification.moduleId,
            moduleName: classification.moduleName,
            ruleId: classification.ruleId,
            ruleName: classification.ruleName,
            category: classification.category || 'recon',
            severity: classification.severity || null,
            outputKind: "recon",
            reconKind: ptkMeta.reconKind || classification.reconKind || null,
            presentationAggregate: ptkMeta?.presentation?.aggregate || classification.presentationAggregate || null,
            uiSurface: ptkMeta.uiSurface || classification.uiSurface || null,
            tags: classification.tags || [],
            description: classification.description || null,
            recommendation: classification.recommendation || null,
            links: classification.links || null,
            dedupeKey,
            count: 1,
            location,
            createdAt: new Date().toISOString(),
            lastSeenAt: new Date().toISOString(),
            evidence: {
                dast: {
                    attackId: logAttackId,
                    requestId: requestRecord?.id || null,
                    resolverKey,
                    param: location.param || null,
                    payload: payloadValue || null,
                    proof: attack?.proof || null
                }
            }
        })
        attack.__reconRecorded = true
        if (attack.__requestRecordEntry && attack.__requestRecordEntry !== attack) {
            attack.__requestRecordEntry.__reconRecorded = true
        }
    }

    _isIdle() {
        const queueEmpty = !this._requestQueue?.size || this._requestQueue.size() === 0
        const noTaskQueue = this._taskQueueCount() === 0
        const noPlans = !this._activePlans?.size
        const noActiveTasks = (this.activeCount || 0) === 0
        const notBuilding = this.inProgress === false
        return queueEmpty && noTaskQueue && noPlans && noActiveTasks && notBuilding && this.isRunning
    }

    _notifyIdleResolvers() {
        if (!this._idleResolvers?.size) {
            return
        }
        if (!this._isIdle()) {
            return
        }
        this._resolveIdleResolvers()
    }

    _resolveIdleResolvers() {
        if (!this._idleResolvers?.size) {
            return
        }
        for (const waiter of this._idleResolvers) {
            if (waiter?.timer) {
                clearTimeout(waiter.timer)
            }
            try {
                waiter.resolve()
            } catch (_) {
                // ignore individual resolver errors
            }
        }
        this._idleResolvers.clear()
    }
}
