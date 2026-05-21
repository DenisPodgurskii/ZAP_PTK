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
import { loadBundledDastWordlists } from "./bundledWordlists.js"
import { DastTaskPlanner } from "./services/dastTaskPlanner.js"
import { DastTaskScheduler } from "./services/dastTaskScheduler.js"
import { DastConfirmationService } from "./services/dastConfirmationService.js"
import { AuthzDiffService } from "../bugbounty/authzDiffService.js"

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
const DAST_BROWSER_NAV_HARNESS_SCRIPT_ID = "ptk-dast-browser-nav-harness"
const DAST_BROWSER_NAV_TAB_MARKER = "ptk_browser_nav_attack_tab"
const DAST_BROWSER_NAV_DEFAULT_SETTLE_MS = 900
const DAST_BROWSER_NAV_SUPPORTED_CHECKS = new Set([
    "dom_xss"
])
const DAST_BROWSER_NAV_SOURCE_DRIVERS = new Set([
    "cookie",
    "localStorage",
    "sessionStorage",
    "form",
    "postMessage"
])
const DAST_BROWSER_NAV_SOURCE_KEY_LIMIT = 12
const DAST_BROWSER_WORKFLOW_HARNESS_SCRIPT_ID = "ptk-dast-browser-workflow-harness"
const DAST_BROWSER_WORKFLOW_TAB_MARKER = "ptk_browser_workflow_attack_tab"
const DAST_BROWSER_WORKFLOW_DEFAULT_SETTLE_MS = 400
const DAST_BROWSER_WORKFLOW_DEFAULT_PROTECTED_PATHS = Object.freeze([
    "/my-account",
    "/account",
    "/profile",
    "/dashboard",
    "/settings",
    "/me",
    "/user"
])
const DAST_FINDING_SCAN_AGGREGATE_SAMPLE_LIMIT = 10
const DAST_FINDING_AGGREGATION_MODES = new Set([
    "scan",
    "route",
    "route-param",
    "route-sink",
    "route-param-sink"
])
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
const DAST_MODULE_STATUS_ACTIVE = "active"
const DAST_MODULE_STATUS_SKIPPED_CAPABILITY = "skipped_capability"
const DAST_MODULE_STATUS_SKIPPED_PROFILE = "skipped_profile"
const DAST_MODULE_STATUS_SKIPPED_TRANSPORT_UNSUPPORTED = "skipped_transport_unsupported"
const TRANSPORT_LIMITED_ENGINE_CAPABILITIES = new Set([
    "smuggling_h1",
    "smuggling_h2",
    "websocket_handshake",
    "websocket_frames"
])
const DAST_ENGINE_CAPABILITY_SUPPORT = Object.freeze({
    smuggling_h1: false,
    smuggling_h2: false,
    websocket_handshake: false,
    websocket_frames: false,
    oast_callbacks: true,
    race_burst: true,
    multipart_files: true,
    multi_identity: false
})
const DEFAULT_HARD_DENY_COOKIE_REGEX = "^(session|sessionid|sess|sessid|phpsessid|jsessionid|connect\\.sid|sid|csrf|xsrf|awsalb|awselb|alb|__Host-|__Secure-)"
const DEFAULT_HARD_DENY_PARAM_REGEX = "^(csrf|xsrf|_csrf|session|sessionid)$"
const DEFAULT_HARD_DENY_HEADER_REGEX = "^(cookie|set-cookie)$"
const DEFAULT_SOFT_EXCLUDE_PARAM_REGEX = "^(utm_|gclid|fbclid|_ga|_gid|optanon|consent)$"
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
        confirm: {
            mode: 'module',
            confirmFindings: true,
            confirmOnlyWhenBorderline: true,
            minLenDelta: 20,
            borderlineWindow: 10,
            confirmMaxExtraRequests: 1
        },
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
        confirm: {
            mode: 'module',
            confirmFindings: true,
            confirmOnlyWhenBorderline: true,
            minLenDelta: 20,
            borderlineWindow: 10,
            confirmMaxExtraRequests: 1
        },
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
        confirm: {
            mode: 'generic',
            confirmFindings: true,
            confirmOnlyWhenBorderline: false,
            minLenDelta: 20,
            borderlineWindow: 10,
            confirmMaxExtraRequests: 1
        },
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
        this._bundledWordlistsPromise = null
        this._rawBaseModules = null
        this._rawCveModules = null
        this._bundledWordlists = null
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
        this.authzDiffService = new AuthzDiffService()
        this.reset()
        this.automationHooks = null
        this.captureProgressProvider = null
        this.sessionProfileStore = settings?.sessionProfileStore || null
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

    setSessionProfileStore(store = null) {
        this.sessionProfileStore = store || null
        this._refreshModuleStatuses()
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
        this._zapQueueOrder = 0
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
        this._findingAggregateIndex = new Map()
        this._spaConfirmedAggregateKeys = new Set()
        this._browserNavSeenSinks = new Set()
        this._browserNavHarnessRegistered = false
        this._browserWorkflowHarnessRegistered = false
        this._fingerprintMeta = new Map()
        this._recordedRequestDedupeKeys = new Set()
        this._requestRecordByDedupeKey = new Map()
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
        this._moduleStatusMap = new Map()
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

    _moduleRequiredEngineCapabilities(module) {
        const execution = this._moduleExecution(module)
        if (!Array.isArray(execution.requiredEngineCapabilities)) return []
        return Array.from(new Set(
            execution.requiredEngineCapabilities
                .map((value) => this._normalizeEngineCapabilityId(value))
                .filter(Boolean)
        ))
    }

    _moduleRuntimeHooks(module) {
        const runtime = this._moduleRuntime(module)
        return Array.isArray(runtime.hooks) ? runtime.hooks : []
    }

    _moduleRuntimeMode(module) {
        const runtime = this._moduleRuntime(module)
        return String(runtime.mode || '').toLowerCase()
    }

    _normalizeEngineCapabilityId(value) {
        const normalized = String(value || "").trim().toLowerCase()
        if (!normalized) return null
        if (normalized === "raw_http1") return "smuggling_h1"
        if (normalized === "http2") return "smuggling_h2"
        return normalized
    }

    _isTransportLimitedCapability(value) {
        const capability = this._normalizeEngineCapabilityId(value)
        return !!capability && TRANSPORT_LIMITED_ENGINE_CAPABILITIES.has(capability)
    }

    _isEngineCapabilitySupported(value) {
        const capability = this._normalizeEngineCapabilityId(value)
        if (!capability) return true
        if (capability === "smuggling_h1") {
            // Firefox listener override is the only transport path we currently trust enough to expose.
            return this._isFirefoxRuntime()
        }
        if (capability === "smuggling_h2") {
            return this._supportsH2ObservationTransport()
        }
        if (capability === "websocket_handshake" || capability === "websocket_frames") {
            return this._supportsWebSocketTransport()
        }
        if (capability === "multi_identity") {
            return this._supportsMultiIdentityExecution()
        }
        return DAST_ENGINE_CAPABILITY_SUPPORT[capability] === true
    }

    _supportsWebSocketTransport() {
        return this._isFirefoxRuntime()
            && typeof globalThis.WebSocket === "function"
            && !!browser?.webRequest?.onBeforeSendHeaders
            && !!browser?.webRequest?.onHeadersReceived
    }

    _supportsH2ObservationTransport() {
        return !this._isFirefoxRuntime()
            && !!browser?.debugger
            && !!browser?.tabs?.create
            && !!browser?.tabs?.remove
            && !!browser?.scripting?.executeScript
    }

    _supportsMultiIdentityExecution() {
        return !!this.sessionProfileStore?.listProfiles
            || typeof this.settings?.listSessionProfilesForHost === "function"
    }

    _engineCapabilitySupportState(value) {
        const capability = this._normalizeEngineCapabilityId(value)
        if (!capability) {
            return {
                capability: null,
                supported: true,
                status: DAST_MODULE_STATUS_ACTIVE,
                reason: null
            }
        }
        const supported = this._isEngineCapabilitySupported(capability)
        if (supported) {
            return {
                capability,
                supported: true,
                status: DAST_MODULE_STATUS_ACTIVE,
                reason: null
            }
        }
        return {
            capability,
            supported: false,
            status: this._isTransportLimitedCapability(capability)
                ? DAST_MODULE_STATUS_SKIPPED_TRANSPORT_UNSUPPORTED
                : DAST_MODULE_STATUS_SKIPPED_CAPABILITY,
            reason: this._isTransportLimitedCapability(capability)
                ? "transport_unsupported"
                : "capability_unsupported"
        }
    }

    _moduleTechniquesAllowed(module) {
        const techniques = this._moduleCapabilities(module)
        if (!Array.isArray(techniques) || !techniques.length) return true
        return techniques.every((technique) => this._techniqueAllowed(technique))
    }

    _buildModuleStatusEntry(module, overrides = {}) {
        const requiredEngineCapabilities = this._moduleRequiredEngineCapabilities(module)
        return Object.assign({
            moduleId: module?.id || null,
            moduleName: module?.name || null,
            status: DAST_MODULE_STATUS_ACTIVE,
            requiredEngineCapabilities,
            unsupportedCapability: null,
            disallowedTechniques: []
        }, overrides || {})
    }

    _evaluateModuleRunStatus(module) {
        const base = this._buildModuleStatusEntry(module)
        for (const capability of base.requiredEngineCapabilities) {
            const support = this._engineCapabilitySupportState(capability)
            if (!support.supported) {
                return Object.assign(base, {
                    status: support.status,
                    unsupportedCapability: capability
                })
            }
        }
        const disallowedTechniques = this._moduleCapabilities(module)
            .filter((technique) => !this._techniqueAllowed(technique))
        if (disallowedTechniques.length) {
            return Object.assign(base, {
                status: DAST_MODULE_STATUS_SKIPPED_PROFILE,
                disallowedTechniques
            })
        }
        return base
    }

    _syncModuleStatusesToScanResult() {
        if (!this.scanResult || typeof this.scanResult !== "object") return
        const entries = Array.from(this._moduleStatusMap?.values?.() || [])
            .sort((left, right) => String(left?.moduleId || left?.moduleName || "").localeCompare(String(right?.moduleId || right?.moduleName || "")))
            .map((entry) => cloneValue(entry))
        this.scanResult.moduleStatuses = entries
    }

    _refreshModuleStatuses() {
        const next = new Map()
        const modules = Array.isArray(this.modules) ? this.modules : []
        modules.forEach((module) => {
            const key = module?.id || module?.name || null
            if (!key) return
            next.set(key, this._evaluateModuleRunStatus(module))
        })
        this._moduleStatusMap = next
        this._syncModuleStatusesToScanResult()
    }

    _getModuleRunStatus(moduleOrId) {
        const key = typeof moduleOrId === "string"
            ? moduleOrId
            : (moduleOrId?.id || moduleOrId?.name || null)
        if (!key) {
            return {
                status: DAST_MODULE_STATUS_ACTIVE
            }
        }
        return this._moduleStatusMap?.get(key) || this._buildModuleStatusEntry(
            typeof moduleOrId === "string" ? { id: moduleOrId, name: moduleOrId } : moduleOrId
        )
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
        const remainingBudget = this._remainingHtmlLinkDiscoveryBudget()
        if (remainingBudget <= 0) {
            const dropped = this._pendingHtmlDiscoveryUrls.length
            this._pendingHtmlDiscoveryUrls = []
            this._pendingHtmlDiscoverySet?.clear?.()
            if (dropped > 0) {
                this._appendRuntimeEvent({
                    type: 'dast_html_links_dropped',
                    phase: 'html_discovery',
                    reason: 'html_link_discovery_budget_exhausted',
                    droppedCount: dropped,
                    budget: this._normalizeHtmlLinkDiscoveryBudget(this.settings?.htmlLinkDiscoveryBudget)
                })
            }
            return 0
        }

        const maxSeed = Math.min(
            remainingBudget,
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
        else if (runtimeMode === "browser_nav") family = "browser_nav"
        else if (runtimeMode === "browser_workflow") family = "browser_workflow"
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
        if (runtimeMode === 'browser_nav') priority += 900
        if (runtimeMode === 'browser_workflow') priority += 875

        const topTierModules = new Set([
            'graphql_introspection',
            'graphql_advanced',
            'api_testing_coverage',
            'ssrf_coverage',
            'dom_based_vuln_coverage',
            'jwt_advanced',
            'jwt_injection'
        ])
        if (topTierModules.has(moduleId)) priority += 800
        if (moduleId === 'jwt_injection') {
            priority += 1400
        }

        const isXssTask = (
            moduleId === 'xss'
            || moduleId.includes('xss')
            || vulnId.includes('xss')
            || tags.includes('xss')
        )
        if (isXssTask) {
            priority += this.settings?.zapManaged === true ? 5000 : 700
        }
        if (
            this.settings?.zapManaged === true
            && moduleId === 'xss'
            && runtimeMode !== 'browser_nav'
            && runtimeMode !== 'browser_workflow'
        ) {
            // ZAP browser jobs have a fixed close budget. Run cheap reflected-XSS
            // request/response validation before slower browser-driven probes so
            // confirmed server-side findings are not starved by tab-based work.
            priority += 2200
        }

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

        const taskUrlText = [
            task?.payload?.request?.url,
            task?.payload?.request?.path,
            task?.payload?.request?.target,
            task?.target?.name,
            task?.target?.location
        ]
            .filter(value => value != null)
            .map(value => String(value).toLowerCase())
            .join(" ")
        const isSqlHeavy = /\b(sql|sqli|bsql|union)\b/.test(moduleId) || /\b(sql|sqli|bsql|union)\b/.test(vulnId)
        if (isSqlHeavy) priority -= 400
        if (isSqlHeavy && /\b(?:login|signin|sign-in|auth|authenticate|session|token)\b/.test(taskUrlText)) {
            priority += 1800
        }

        if (task?.moduleAsync === false) {
            priority += 25
        }

        const plannerPriority = Number(task?.plannerPriority)
        if (Number.isFinite(plannerPriority) && plannerPriority !== 0) {
            priority += Math.max(-1000, Math.min(1000, Math.trunc(plannerPriority)))
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

    _moduleSupportsBrowserSourceDrivers(module) {
        const attacks = Array.isArray(module?.attacks) ? module.attacks : []
        return attacks.some((attack) => {
            const cfg = attack?.runtime?.config?.browserNav
                || attack?.runtime?.browserNav
                || {}
            const values = cfg.sourceDrivers || cfg.sources || []
            return (Array.isArray(values) ? values : [values])
                .some((value) => DAST_BROWSER_NAV_SOURCE_DRIVERS.has(String(value || '').trim()))
        })
    }

    _shouldPlanModuleForRequest(module, schema, _original = null) {
        if (!module || typeof module !== "object") return { allowed: false, reason: "invalid_module" }
        const moduleRunStatus = this._getModuleRunStatus(module)
        if (moduleRunStatus?.status && moduleRunStatus.status !== DAST_MODULE_STATUS_ACTIVE) {
            this._recordModulePlanningSkip(module, `module_status_${moduleRunStatus.status}`)
            return {
                allowed: false,
                reason: `module_status_${moduleRunStatus.status}`,
                status: moduleRunStatus.status
            }
        }
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
        const supportsBrowserSources = this._moduleSupportsBrowserSourceDrivers(module)
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
            if (!supportsBrowserSources) {
                this._recordModulePlanningSkip(module, "prefilter_query_or_body_params")
                const decision = { allowed: false, reason: "prefilter_query_or_body_params" }
                this._boundedMapSet(this._planningDecisionCache, cacheKey, decision, 4096)
                return decision
            }
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
            if (!hasRelevantSurface && !supportsBrowserSources) {
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
        if (execution.requiredEngineCapabilities != null && view.requiredEngineCapabilities == null) {
            view.requiredEngineCapabilities = cloneValue(execution.requiredEngineCapabilities)
        }
        if (execution.capabilities != null && view.capabilities == null) view.capabilities = cloneValue(execution.capabilities)

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
        const baseConstants = baseMetadata?.constants && typeof baseMetadata.constants === 'object'
            ? cloneValue(baseMetadata.constants)
            : {}
        const constants = Object.assign({}, moduleView.constants || {}, attackConstants, baseConstants)
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
        const bundledWordlists = await this._ensureBundledWordlists()
        this.modules = moduleDefs.map(m => new ptk_module({
            ...m,
            bundledWordlists
        }))
        this._syncScanControlsToModules()
        this._refreshModuleStatuses()
        return this.modules
    }

    async _ensureBundledWordlists() {
        if (this._bundledWordlists) {
            return this._bundledWordlists
        }
        if (!this._bundledWordlistsPromise) {
            this._bundledWordlistsPromise = loadBundledDastWordlists()
                .catch((error) => {
                    this._bundledWordlistsPromise = null
                    throw error
                })
        }
        const wordlists = await this._bundledWordlistsPromise
        this._bundledWordlists = wordlists
        return wordlists
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
        envelope.moduleStatuses = []
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

    _requestRawBodyText(raw = '') {
        if (typeof raw !== 'string' || !raw.length) return ''
        const splitCrlf = raw.indexOf('\r\n\r\n')
        if (splitCrlf >= 0) return raw.slice(splitCrlf + 4)
        const splitLf = raw.indexOf('\n\n')
        if (splitLf >= 0) return raw.slice(splitLf + 2)
        return ''
    }

    _requestRawHeaderValue(raw = '', name = '') {
        if (typeof raw !== 'string' || !raw.length || !name) return ''
        const target = String(name || '').trim().toLowerCase()
        const lines = raw.split(/\r?\n/)
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i]
            if (!line || !line.trim()) break
            const sep = line.indexOf(':')
            if (sep <= 0) continue
            const headerName = line.slice(0, sep).trim().toLowerCase()
            if (headerName === target) return line.slice(sep + 1).trim()
        }
        return ''
    }

    _capturedRequestBodyText(rawRequest = null) {
        const raw = typeof rawRequest === 'object' ? String(rawRequest?.raw || '') : String(rawRequest || '')
        const rawBody = this._requestRawBodyText(raw)
        if (rawBody) return rawBody
        const requestBody = rawRequest && typeof rawRequest === 'object'
            ? rawRequest?.capturedRequest?.requestBody
            : null
        if (!requestBody || typeof requestBody !== 'object') return ''
        if (typeof requestBody.raw === 'string') return requestBody.raw
        if (requestBody.formData && typeof requestBody.formData === 'object') {
            try {
                return JSON.stringify(requestBody.formData)
            } catch (_) {
                return String(requestBody.formData || '')
            }
        }
        return ''
    }

    _requestBodyRichnessScore(rawRequest = null) {
        const raw = typeof rawRequest === 'object' ? String(rawRequest?.raw || '') : String(rawRequest || '')
        const bodyText = this._capturedRequestBodyText(rawRequest)
        const trimmed = String(bodyText || '').trim()
        const contentLength = Number(this._requestRawHeaderValue(raw, 'content-length'))
        const contentType = this._requestRawHeaderValue(raw, 'content-type').toLowerCase()
        let score = 0

        if (contentType.includes('json')) score += 24
        else if (contentType.includes('x-www-form-urlencoded') || contentType.includes('multipart/form-data')) score += 20
        else if (contentType) score += 8

        if (!trimmed) {
            if (Number.isFinite(contentLength) && contentLength > 0) score -= 120
            return score
        }

        score += Math.min(trimmed.length, 4096) / 32
        if (trimmed.length >= 3) score += 50
        if (/[=&]/.test(trimmed)) score += 25
        if (/[{[]/.test(trimmed) && /[:\]}]/.test(trimmed)) {
            try {
                const parsed = JSON.parse(trimmed)
                if (parsed && typeof parsed === 'object') score += 110
            } catch (_) {
                score += 20
            }
        }
        if (/(?:comment|message|text|name|title|query|search|url|rating|captcha|email|username|password)\s*[:=]/i.test(trimmed)) {
            score += 35
        }
        return score
    }

    _requestBaselineQualityScore(rawRequest, response = null) {
        const raw = typeof rawRequest === 'object' ? String(rawRequest?.raw || '') : String(rawRequest || '')
        const firstLine = raw.split(/\r?\n/)[0] || ''
        const method = String((typeof rawRequest === 'object' ? rawRequest?.method : '') || firstLine.split(/\s+/)[0] || 'GET').toUpperCase()
        const statusCode = Number(response?.statusCode ?? response?.status ?? rawRequest?.capturedResponse?.statusCode ?? 0)
        let score = this._requestHeaderRichnessScore(rawRequest) + this._requestBodyRichnessScore(rawRequest)

        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) score += 30
        if (Number.isFinite(statusCode) && statusCode > 0) {
            if (statusCode >= 200 && statusCode < 300) score += 130
            else if (statusCode >= 300 && statusCode < 400) score += 55
            else if (statusCode === 401 || statusCode === 403) score -= 90
            else if (statusCode >= 500) score -= 180
            else if (statusCode >= 400) score -= 60
        }
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

    _extractQueuedRequestUrl(payload = {}, response = null) {
        const direct = payload?.url || payload?.ui_url || response?.url || response?.ui_url || ''
        if (direct && /^https?:\/\//i.test(String(direct))) return String(direct)
        const raw = String(payload?.raw || '')
        const firstLine = raw.split(/\r?\n/)[0] || ''
        const match = firstLine.match(/^[A-Z]+\s+(https?:\/\/\S+)\s+HTTP\/\d(?:\.\d)?$/i)
        return match?.[1] || ''
    }

    _scoreZapManagedQueuedRequest(payload = {}, response = null) {
        const method = String(payload?.method || response?.method || '').toUpperCase()
        const raw = String(payload?.raw || '')
        const hasBody = this._requestRawHasBody(raw) || !!payload?.capturedRequest?.requestBody
        const responseType = String(payload?.responseType || response?.type || '').toLowerCase()
        const statusCode = Number(response?.statusCode ?? payload?.capturedResponse?.statusCode ?? 0)
        let score = 0

        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) score += 160
        if (hasBody) score += 110
        if (responseType === 'main_frame' || responseType === 'sub_frame') score += 60
        else if (responseType === 'xmlhttprequest' || responseType === 'fetch') score += 20
        if (statusCode >= 400) score -= 80

        const url = this._extractQueuedRequestUrl(payload, response)
        if (!url) return score - 20

        try {
            const parsed = new URL(url)
            const pathname = decodeURIComponent(parsed.pathname || '').toLowerCase()
            const search = decodeURIComponent(parsed.search || '').toLowerCase()
            const surface = `${pathname}?${search}`

            if ((parsed.pathname || '').match(/(?:^|\/)\.(?:git|svn|hg)(?:\/|$)/i)) score -= 1000
            if (parsed.search && parsed.search !== '?') score += 140
            if (!parsed.search && method === 'GET') score -= 60
            if (/(?:^|[?&])(?:q|query|search|s|term|keyword|text|message|comment|name|title|url|redirect)=/i.test(search)) score += 120
            if (/(?:script|javascript|js[_/-]|eval|template|expression|comment)/i.test(surface)) score += 260
            if (/(?:attr|attribute|event|tagname|svg|onerror|onload|onmouseover|href|srcdoc)/i.test(surface)) score += 240
            if (/(?:textarea|html|body|head|content|render|preview)/i.test(surface)) score += 60
            if (/(?:xss|dom)/i.test(surface)) score += 180
        } catch (_) {
            score -= 20
        }

        return score
    }

    _enqueueRequestPayload(payload, response = null) {
        if (this.settings?.zapManaged !== true) {
            this._requestQueue.enqueue(payload)
            return
        }

        const priority = this._scoreZapManagedQueuedRequest(payload, response)
        payload.__zapQueuePriority = priority
        payload.__zapQueueOrder = ++this._zapQueueOrder

        const buffer = this._requestQueue?._buffer
        if (!Array.isArray(buffer)) {
            this._requestQueue.enqueue(payload)
            return
        }

        const head = this._requestQueue._head || 0
        let insertAt = buffer.length
        for (let i = head; i < buffer.length; i++) {
            const candidate = buffer[i]
            if (!candidate || typeof candidate !== 'object') continue
            const candidatePriority = Number(candidate.__zapQueuePriority || 0)
            if (priority > candidatePriority) {
                insertAt = i
                break
            }
        }

        buffer.splice(insertAt, 0, payload)
        this._requestQueue._size += 1
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

    _getHeaderValue(headers = [], name = '') {
        if (!Array.isArray(headers) || !name) return ''
        const target = String(name || '').trim().toLowerCase()
        const header = headers.find((entry) => String(entry?.name || '').trim().toLowerCase() === target)
        return String(header?.value || '')
    }

    _decodeCapturedRawRequestBody(rawParts = null) {
        if (!Array.isArray(rawParts) || !rawParts.length) return ''
        const decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null
        let out = ''
        rawParts.forEach((part) => {
            try {
                if (!part?.bytes) return
                let bytes = null
                if (part.bytes instanceof ArrayBuffer) {
                    bytes = new Uint8Array(part.bytes)
                } else if (ArrayBuffer.isView(part.bytes)) {
                    bytes = new Uint8Array(part.bytes.buffer, part.bytes.byteOffset, part.bytes.byteLength)
                }
                if (!bytes || !bytes.length) return
                out += decoder ? decoder.decode(bytes) : String.fromCharCode.apply(String, bytes)
            } catch (_) { }
        })
        return out
    }

    _normalizeCapturedFormDataParams(formData = null) {
        if (!formData || typeof formData !== 'object') return []
        const params = []
        Object.entries(formData).forEach(([name, value]) => {
            if (Array.isArray(value)) {
                value.forEach((entry) => {
                    params.push({ name: String(name), value: String(entry ?? '') })
                })
                return
            }
            params.push({ name: String(name), value: String(value ?? '') })
        })
        return params.filter((param) => param.name)
    }

    _requestRawHasBody(raw = '') {
        if (typeof raw !== 'string' || !raw.length) return false
        return this._requestRawBodyText(raw).length > 0
    }

    _applyCapturedRequestBodyFallback(request = null, rawMeta = {}) {
        if (!request || typeof request !== 'object') return request
        const capturedRequest = rawMeta?.capturedRequest
        if (!capturedRequest || typeof capturedRequest !== 'object') return request

        if ((!request.headers || !request.headers.length) && Array.isArray(capturedRequest.requestHeaders)) {
            request.headers = cloneValue(capturedRequest.requestHeaders)
        }

        const requestHeaders = Array.isArray(request.headers) ? request.headers : []
        const contentType = this._getHeaderValue(requestHeaders, 'content-type')
        const isMultipart = /multipart\/form-data/i.test(contentType)
        if (!isMultipart) return request
        if (request.body && Array.isArray(request.body?.params) && request.body.params.length) return request

        const requestBody = capturedRequest.requestBody
        if (!requestBody || typeof requestBody !== 'object') return request

        let rawBody = ''
        if (typeof requestBody.raw === 'string' && requestBody.raw.length) {
            rawBody = requestBody.raw
        } else if (Array.isArray(requestBody.raw) && requestBody.raw.length) {
            rawBody = this._decodeCapturedRawRequestBody(requestBody.raw)
        }

        if (rawBody) {
            try {
                const rebuilt = ptk_request.parseRawRequest(`${String(request.method || 'POST').toUpperCase()} ${request.url} HTTP/1.1\r\n${requestHeaders.map((header) => `${header.name}: ${header.value}`).join('\r\n')}\r\n\r\n${rawBody}`)
                if (rebuilt?.request?.body) {
                    request.body = cloneValue(rebuilt.request.body)
                    request.raw = rebuilt.request.raw
                    return request
                }
            } catch (_) { }
        }

        const textParams = this._normalizeCapturedFormDataParams(requestBody.formData)
        if (!textParams.length) return request

        request.body = request.body && typeof request.body === 'object' ? request.body : {}
        request.body.contentType = 'multipart/form-data'
        request.body.mimeType = contentType
        const boundaryMatch = String(contentType || '').match(/boundary=([^;]+)/i)
        if (boundaryMatch?.[1]) {
            request.body.boundary = String(boundaryMatch[1]).trim().replace(/^"|"$/g, '')
        }
        request.body.params = textParams
        if (request.body.boundary) {
            request.body.text = ptk_request.serializeMultipartParams(textParams, request.body.boundary)
        }
        try {
            const seedRaw = request.raw
                || rawMeta?.raw
                || `${String(request.method || 'POST').toUpperCase()} ${request.url} HTTP/1.1\r\n${requestHeaders.map((header) => `${header.name}: ${header.value}`).join('\r\n')}\r\n\r\n`
            const rebuildSchema = ptk_request.parseRawRequest(seedRaw)
            rebuildSchema.request.method = request.method || rebuildSchema.request.method
            rebuildSchema.request.url = request.url || rebuildSchema.request.url
            rebuildSchema.request.ui_url = request.ui_url || rebuildSchema.request.ui_url
            rebuildSchema.request.headers = cloneValue(request.headers || rebuildSchema.request.headers || [])
            rebuildSchema.request.body = cloneValue(request.body)
            ptk_request.updateRawRequest(rebuildSchema, null, rebuildSchema.opts)
            request.headers = cloneValue(rebuildSchema.request.headers || request.headers)
            request.body = cloneValue(rebuildSchema.request.body || request.body)
            request.raw = rebuildSchema.request.raw
        } catch (_) { }
        return request
    }

    _buildCapturedOriginalFromMeta(schema, rawMeta, modules = []) {
        const capturedResponse = this._normalizeCapturedResponse(rawMeta?.capturedResponse || null)
        if (!this._capturedOriginalSatisfiesRequirements(capturedResponse, modules)) {
            return null
        }
        const request = cloneValue(schema?.request || {})
        this._applyCapturedRequestBodyFallback(request, rawMeta)
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

    _markRecordedRequestDedupeKey(dedupeKey, record = null) {
        const key = String(dedupeKey || '').trim()
        if (!key) return
        if (!(this._recordedRequestDedupeKeys instanceof Set)) {
            this._recordedRequestDedupeKeys = new Set()
        }
        if (!(this._requestRecordByDedupeKey instanceof Map)) {
            this._requestRecordByDedupeKey = new Map()
        }
        this._recordedRequestDedupeKeys.add(key)
        if (record) this._requestRecordByDedupeKey.set(key, record)
    }

    _requestDedupeKeyFromOriginal(original) {
        if (!original || typeof original !== 'object') return null
        const request = this._extractRequestShape(original)
        const response = this._extractResponseShape(original)
        return this._simpleFingerprint(request, response)
            || this._fingerprintFromRequest(request)
            || null
    }

    _isRecordedRequestDedupeKey(dedupeKey) {
        const key = String(dedupeKey || '').trim()
        return !!key && this._recordedRequestDedupeKeys instanceof Set && this._recordedRequestDedupeKeys.has(key)
    }

    _recordedRequestLooksWeak(record = null) {
        if (!record || typeof record !== 'object') return false
        const request = record?.original?.request || record?.request || {}
        const response = record?.original?.response || record?.response || {}
        const method = String(request?.method || '').toUpperCase()
        const statusCode = Number(response?.statusCode ?? response?.status)
        if (Number.isFinite(statusCode) && statusCode >= 500) return true
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
            const bodyText = typeof request?.body?.text === 'string'
                ? request.body.text
                : this._requestRawBodyText(String(request?.raw || ''))
            if (!String(bodyText || '').trim()) return true
        }
        return false
    }

    _shouldUpgradeRecordedRequest(dedupeKey, record = null, existing = null, quality = 0) {
        if (!dedupeKey || !record || !this._recordedRequestLooksWeak(record)) return false
        const previousQuality = Number(existing?.quality ?? 0)
        const upgradedAfterRecord = Number(existing?.upgradedAfterRecord || 0)
        if (upgradedAfterRecord >= 2) return false
        return quality > previousQuality + 80
    }

    _recordDroppedDuplicateRequest(dedupeKey, existing = null, quality = 0) {
        if (!dedupeKey) return
        const meta = existing || this._fingerprintMeta?.get(dedupeKey) || {
            quality,
            count: 0,
            upgraded: 0
        }
        meta.count = (meta.count || 0) + 1
        meta.droppedAfterRecord = (meta.droppedAfterRecord || 0) + 1
        if (quality > Number(meta.quality || 0)) {
            meta.quality = quality
        }
        this._fingerprintMeta?.set?.(dedupeKey, meta)
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
        const quality = this._requestBaselineQualityScore(rawRequest, response)
        const existing = this._fingerprintMeta.get(dedupeKey)
        const qualityDelta = 8
        const payload = this._normalizeQueuedRequestPayload(rawRequest, dedupeKey, response)
        if (this._isRecordedRequestDedupeKey(dedupeKey)) {
            const record = this._requestRecordByDedupeKey instanceof Map
                ? this._requestRecordByDedupeKey.get(dedupeKey)
                : null
            if (this._shouldUpgradeRecordedRequest(dedupeKey, record, existing, quality)) {
                payload.__upgradeRecordedRequest = true
                const nextExisting = existing || { count: 0, upgraded: 0 }
                nextExisting.quality = quality
                nextExisting.count = (nextExisting.count || 0) + 1
                nextExisting.upgradedAfterRecord = (nextExisting.upgradedAfterRecord || 0) + 1
                this._fingerprintMeta.set(dedupeKey, nextExisting)
                this._enqueueRequestPayload(payload, response)
                return
            }
            this._recordDroppedDuplicateRequest(dedupeKey, existing, quality)
            return
        }
        if (!existing) {
            this._fingerprintMeta.set(dedupeKey, {
                quality,
                count: 1,
                upgraded: 0
            })
            this._enqueueRequestPayload(payload, response)
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
            this._enqueueRequestPayload(payload, response)
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
            confidence: Number.isFinite(Number(attack.confidence)) ? Number(attack.confidence) : null,
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
        this._unregisterBrowserNavHarnessScript().catch(() => {})
        this._unregisterBrowserWorkflowHarnessScript().catch(() => {})
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

    _createRequestRecord(original, persist = true, options = {}) {
        const requests = Array.isArray(this.scanResult.requests) ? this.scanResult.requests : []
        if (!this.scanResult.requests) this.scanResult.requests = requests
        const dedupeKey = options?.dedupeKey || this._requestDedupeKeyFromOriginal(original)
        if (persist && dedupeKey && this._requestRecordByDedupeKey instanceof Map) {
            const existingRecord = this._requestRecordByDedupeKey.get(dedupeKey)
            if (existingRecord) {
                if (options?.allowRecordedUpgrade === true && this._recordedRequestLooksWeak(existingRecord)) {
                    existingRecord.original = this._compactOriginalRecord(original)
                    existingRecord.upgradedOriginal = true
                    this._appendRuntimeEvent({
                        type: 'dast_request_record_upgraded',
                        phase: 'plan_enqueue',
                        requestId: existingRecord.id || null,
                        method: existingRecord?.original?.request?.method || original?.request?.method || null,
                        url: existingRecord?.original?.request?.url || original?.request?.url || null
                    })
                }
                return existingRecord
            }
        }
        this._requestSeq = (this._requestSeq || 0) + 1
        const requestId = `req-${this._requestSeq}`
        const record = {
            id: requestId,
            original: this._compactOriginalRecord(original),
            attacks: []
        }
        if (persist) {
            requests.push(record)
            this._markRecordedRequestDedupeKey(dedupeKey, record)
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
            presentationAggregate: classification.presentationAggregate || null,
            uiSurface: reconMeta.uiSurface || classification.uiSurface || null
        }
        const persistedConfidenceDetails = attackResult?.success
            ? this._resolveAttackConfidenceDetails(attackResult, classification)
            : null
        if (requestData) attackMeta.request = requestData
        if (responseData) attackMeta.response = responseData
        if (typeof attackResult?.executed === 'boolean') attackMeta.executed = attackResult.executed
        if (attackResult?.metadata?.confirmation) {
            attackMeta.confirmation = cloneValue(attackResult.metadata.confirmation)
        }
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
        const trackingRequestData = this._compactRequestForStorage(attackResult?.tracking?.request, {
            includeRaw: true,
            includeHeaders: true,
            includeBody: true
        })
        const trackingResponseData = this._compactResponseForStorage(attackResult?.tracking?.response, {
            includeBody: true,
            includeHeaders: true,
            includeRaw: false
        })
        if (
            attackResult?.tracking?.url
            || attackResult?.tracking?.tier
            || trackingRequestData
            || trackingResponseData
        ) {
            attackMeta.tracking = {}
            if (attackResult?.tracking?.url) attackMeta.tracking.url = attackResult.tracking.url
            if (attackResult?.tracking?.tier) attackMeta.tracking.tier = attackResult.tracking.tier
            if (trackingRequestData) attackMeta.tracking.request = trackingRequestData
            if (trackingResponseData) attackMeta.tracking.response = trackingResponseData
        }
        if (Number.isFinite(attackResult?.confidence)) attackMeta.confidence = attackResult.confidence
        if (Number.isFinite(attackResult?.metadata?.confidence)) attackMeta.confidence = attackResult.metadata.confidence
        if (!Number.isFinite(attackMeta.confidence) && Number.isFinite(persistedConfidenceDetails?.confidence)) {
            attackMeta.confidence = persistedConfidenceDetails.confidence
        }
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

    _recordLiveAttackFinding(plan, attackResult, attackIndex = 0) {
        if (!plan?.requestRecord || !attackResult?.success) return
        const wasRecorded = Boolean(attackResult.__findingRecorded || attackResult.__reconRecorded)
        if (this._isReconAttackResult(attackResult)) {
            this._addReconObservation(plan.requestRecord, attackResult, attackIndex)
        } else {
            this._addUnifiedFinding(plan.requestRecord, attackResult, attackIndex)
        }
        const isRecorded = Boolean(attackResult.__findingRecorded || attackResult.__reconRecorded)
        if (wasRecorded || !isRecorded) {
            return
        }
        this._syncScanStats()
        this._notifyResultMutation({
            type: "attack_finding",
            requestId: plan.requestRecord?.id || null,
            attackId: attackResult.__requestRecordEntry?.id || attackResult.id || null
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
        const pathContextKey = buildRequestContextKey({
            method,
            normalizedPath: pathResult.normalizedPath,
            sourceType: '*',
            targetName: '*'
        })
        return {
            method,
            normalizedPath: pathResult.normalizedPath,
            sourceType: surface.sourceType,
            targetName: surface.targetName,
            requestContextKey,
            pathContextKey,
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
        return this._moduleTechniquesAllowed(task?.module)
    }

    _shouldCountSuccessAsFindingCandidate(task, result) {
        if (!result?.success) return false
        const ruleId = String(result?.ruleId || task?.attack?.id || '').toLowerCase()
        if (ruleId.includes('baseline')) return false
        if (this._isReconAttackResult(result) || this._isReconAttackResult(task?.attack)) return false
        return true
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

    _pickActiveAttackPrimaryResult(validationResult, renderFollowupResult, trackingResult) {
        const ordered = [validationResult, renderFollowupResult, trackingResult]
        for (const result of ordered) {
            if (result?.success && typeof result?.proof === 'string' && result.proof.trim()) {
                return result
            }
        }
        for (const result of ordered) {
            if (result?.success) return result
        }
        return validationResult || renderFollowupResult || trackingResult || null
    }

    _mergeActiveAttackResults(executed, {
        validationResult = null,
        renderFollowupResult = null,
        trackingResult = null
    } = {}) {
        const primary = this._pickActiveAttackPrimaryResult(validationResult, renderFollowupResult, trackingResult)
        if (!executed && !primary) return null

        const combined = Object.assign({}, executed || {}, primary || {})
        const mergeMetadata = (result) => {
            if (!result?.metadata || typeof result.metadata !== 'object') return
            const next = cloneValue(result.metadata)
            const existing = combined.metadata && typeof combined.metadata === 'object'
                ? cloneValue(combined.metadata)
                : {}
            const merged = Object.assign({}, existing, next)
            if (
                existing.confirmation && typeof existing.confirmation === 'object'
                || next.confirmation && typeof next.confirmation === 'object'
            ) {
                merged.confirmation = Object.assign(
                    {},
                    existing.confirmation && typeof existing.confirmation === 'object' ? existing.confirmation : {},
                    next.confirmation && typeof next.confirmation === 'object' ? next.confirmation : {}
                )
            }
            combined.metadata = merged
        }
        mergeMetadata(executed)
        mergeMetadata(primary)
        const supplement = (result) => {
            if (!result || !result.success) return
            if (!combined.proof && result.proof) combined.proof = result.proof
            if (!combined.detector && result.detector) combined.detector = result.detector
            if (!combined.match && result.match) combined.match = result.match
            if (!combined.severity && result.severity) combined.severity = result.severity
            if (!Number.isFinite(combined.confidence) && Number.isFinite(result.confidence)) {
                combined.confidence = result.confidence
            }
            mergeMetadata(result)
        }

        supplement(validationResult)
        supplement(renderFollowupResult)
        supplement(trackingResult)

        if (trackingResult?.success) {
            combined.trackingConfirmed = true
            if (trackingResult.tracking) combined.tracking = trackingResult.tracking
            if (trackingResult.trackingTier) combined.trackingTier = trackingResult.trackingTier
            if (trackingResult.executed === true) combined.executed = true
        }
        if (renderFollowupResult?.success) {
            combined.renderFollowupConfirmed = true
            if (renderFollowupResult.renderFollowup) {
                combined.renderFollowup = renderFollowupResult.renderFollowup
            }
        }

        const anySuccess = !!(validationResult?.success || renderFollowupResult?.success || trackingResult?.success)
        combined.success = anySuccess || primary?.success === true
        return combined
    }

    _htmlSnippetIsInsideComment(body, snippet) {
        const source = String(body || '')
        const proof = String(snippet || '')
        if (!source || !proof) return false
        if (/^<!--[\s\S]*-->$/.test(proof.trim())) return true
        let found = false
        let index = source.indexOf(proof)
        while (index >= 0) {
            found = true
            const lastOpen = source.lastIndexOf('<!--', index)
            const lastClose = source.lastIndexOf('-->', index)
            if (!(lastOpen >= 0 && lastOpen > lastClose)) return false
            index = source.indexOf(proof, index + Math.max(1, proof.length))
        }
        return found
    }

    _filterActiveValidationResult(task, validationResult, executed, context = null) {
        const moduleId = String(task?.moduleId || task?.module?.id || '').trim().toLowerCase()
        if (!validationResult?.success) {
            const jwtRecovered = this._recoverJwtValidationFromProbeContrast(task, validationResult, executed, context)
            return jwtRecovered || validationResult
        }
        if (moduleId !== 'xss') return validationResult
        const body = executed?.response?.body || ''
        const snippets = [
            validationResult.match,
            validationResult.proof
        ].filter((value) => typeof value === 'string' && value.trim())
        if (!snippets.some((snippet) => this._htmlSnippetIsInsideComment(body, snippet))) {
            return validationResult
        }
        this._appendTaskRuntimeEvent(task, context, {
            type: 'dast_validation_suppressed',
            phase: 'validation',
            reason: 'xss_match_inside_html_comment'
        })
        return null
    }

    _responseDiffersEnough(left = null, right = null) {
        const leftStatus = Number(left?.statusCode ?? left?.status)
        const rightStatus = Number(right?.statusCode ?? right?.status)
        if (Number.isFinite(leftStatus) && Number.isFinite(rightStatus) && leftStatus !== rightStatus) {
            return true
        }
        const leftLength = Number(left?.length ?? (typeof left?.body === 'string' ? left.body.length : NaN))
        const rightLength = Number(right?.length ?? (typeof right?.body === 'string' ? right.body.length : NaN))
        return Number.isFinite(leftLength) && Number.isFinite(rightLength) && Math.abs(leftLength - rightLength) > 30
    }

    _requestEvidenceContainsJwtNone(request = null, surface = 'any') {
        const text = JSON.stringify(request || '')
        if (!/eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0\./.test(text)) return false
        if (surface === 'cookie') return /cookie/i.test(text)
        if (surface === 'authorization') return /authorization/i.test(text)
        return true
    }

    _recoverJwtValidationFromProbeContrast(task, validationResult, executed, context = null) {
        const moduleId = String(task?.moduleId || task?.module?.id || '').trim().toLowerCase()
        if (moduleId !== 'jwt_injection') return null
        const attackId = String(task?.attack?.id || '').trim()
        const attackResponse = executed?.response || null
        const attackStatus = Number(attackResponse?.statusCode ?? attackResponse?.status)
        if (!Number.isFinite(attackStatus) || attackStatus >= 500) return null

        const expectedProbeIds = attackId === 'jwt_1'
            ? new Set(['jwt_probe_no_cookie', 'jwt_probe_no_both'])
            : attackId === 'jwt_3'
                ? new Set(['jwt_probe_no_authz', 'jwt_probe_no_both'])
                : null
        if (!expectedProbeIds) return null

        const surface = attackId === 'jwt_1' ? 'cookie' : 'authorization'
        if (!this._requestEvidenceContainsJwtNone(executed?.request, surface)) return null

        const history = Array.isArray(task?.module?.executed) ? task.module.executed : []
        const contrastingProbe = history.find((entry) => {
            const entryId = String(entry?.metadata?.id || '').trim()
            if (!expectedProbeIds.has(entryId)) return false
            return this._responseDiffersEnough(entry?.response, attackResponse)
        })
        if (!contrastingProbe) return null

        this._appendTaskRuntimeEvent(task, context, {
            type: 'dast_validation_recovered',
            phase: 'validation',
            reason: 'jwt_probe_contrast',
            probeId: contrastingProbe?.metadata?.id || null,
            attackStatus,
            probeStatus: contrastingProbe?.response?.statusCode ?? contrastingProbe?.response?.status ?? null
        })
        return Object.assign({}, validationResult || {}, {
            success: true,
            proof: validationResult?.proof || `JWT none accepted while ${contrastingProbe?.metadata?.id || 'JWT removal probe'} differed`
        })
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
            const moduleRunStatus = this._getModuleRunStatus(task.module)
            if (moduleRunStatus?.status && moduleRunStatus.status !== DAST_MODULE_STATUS_ACTIVE) {
                this._appendTaskRuntimeEvent(task, context, {
                    type: 'dast_attack_skipped',
                    phase: 'preflight',
                    reason: `module_status_${moduleRunStatus.status}`,
                    status: moduleRunStatus.status,
                    unsupportedCapability: moduleRunStatus.unsupportedCapability || null
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

            const moduleId = task.moduleId || task.module?.id || null
            const executedByModule = context?.executedByModule || null
            const contextDescriptor = this._buildRequestContext(task, context)
            const requestKey = `${moduleId || 'module'}|${contextDescriptor.requestContextKey}`
            const pathKey = `${moduleId || 'module'}|${contextDescriptor.pathContextKey || contextDescriptor.requestContextKey}`
            const executedHistory = !task.moduleAsync && moduleId && executedByModule
                ? (executedByModule[requestKey] ||= [])
                : null
            const executedPathHistory = !task.moduleAsync && moduleId && executedByModule
                ? (executedByModule[pathKey] ||= [])
                : null
            const mergedExecutedHistory = () => {
                const seen = new Set()
                const merged = []
                const append = (entries) => {
                    for (const entry of Array.isArray(entries) ? entries : []) {
                        if (!entry || typeof entry !== 'object') continue
                        const key = [
                            String(entry?.metadata?.id || ''),
                            String(entry?.response?.statusCode ?? entry?.statusCode ?? ''),
                            String(entry?.response?.body ?? '')
                        ].join('|')
                        if (seen.has(key)) continue
                        seen.add(key)
                        merged.push(entry)
                        if (merged.length >= 5) break
                    }
                }
                append(executedHistory)
                if (merged.length < 5) append(executedPathHistory)
                return merged
            }
            const recordExecuted = (entry) => {
                if ((!executedHistory && !executedPathHistory) || !entry) return
                const hasResponse = this._hasRealHttpResponse(entry?.response)
                const allowFailure = task?.module?.metadata?.recordFailuresInExecuted === true
                if (!hasResponse && !allowFailure) return
                const pushUnique = (bucket) => {
                    if (!Array.isArray(bucket)) return
                    const key = [
                        String(entry?.metadata?.id || ''),
                        String(entry?.response?.statusCode ?? entry?.statusCode ?? ''),
                        String(entry?.response?.body ?? '')
                    ].join('|')
                    const duplicateIndex = bucket.findIndex((candidate) => [
                        String(candidate?.metadata?.id || ''),
                        String(candidate?.response?.statusCode ?? candidate?.statusCode ?? ''),
                        String(candidate?.response?.body ?? '')
                    ].join('|') === key)
                    if (duplicateIndex >= 0) {
                        bucket.splice(duplicateIndex, 1)
                    }
                    bucket.unshift(entry)
                    if (bucket.length > 5) bucket.pop()
                }
                pushUnique(executedHistory)
                if (executedPathHistory !== executedHistory) {
                    pushUnique(executedPathHistory)
                }
            }
            if (executedHistory || executedPathHistory) {
                task.module.executed = mergedExecutedHistory()
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
                const conditionPayload = {
                    metadata: this._attackMetadataView(
                        task.module,
                        task.attack,
                        task?.payload?.metadata && typeof task.payload.metadata === 'object'
                            ? task.payload.metadata
                            : {}
                    )
                }
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
                }
                if (res) this._tagResultOrder(res, task)
                return res
            } else if (task.type === 'active') {
                const preparedPayload = this._prepareActiveTaskPayload(task, task.payload)
                const runtimeMode = this._moduleRuntimeMode(task.module)
                if (runtimeMode === 'browser_nav') {
                    const combined = await this._runBrowserNavAttack(task, context, preparedPayload)
                    if (combined) {
                        this._decorateAttackResult(combined, task)
                    }
                    if (combined?.success) {
                        this._recordStrategyFinding(task, combined)
                    }
                    if (combined) {
                        this._tagResultOrder(combined, task)
                        recordExecuted(combined)
                    }
                    this._notifyAttackCompleted(task, context)
                    return combined?.success ? combined : null
                }
                if (runtimeMode === 'browser_workflow') {
                    const combined = await this._runBrowserWorkflowAttack(task, context, preparedPayload)
                    if (combined) {
                        this._decorateAttackResult(combined, task)
                    }
                    if (combined?.success) {
                        this._recordStrategyFinding(task, combined)
                    }
                    if (combined) {
                        this._tagResultOrder(combined, task)
                        recordExecuted(combined)
                    }
                    this._notifyAttackCompleted(task, context)
                    return combined?.success ? combined : null
                }
                const raceCfg = this._taskAttackRuntimeConfig(task, 'race')
                if (raceCfg) {
                    const combined = await this._runRaceBurstAttack(task, context, preparedPayload)
                    if (combined) {
                        this._decorateAttackResult(combined, task)
                    }
                    if (combined?.success) {
                        this._recordStrategyFinding(task, combined)
                    }
                    if (combined) {
                        this._tagResultOrder(combined, task)
                        recordExecuted(combined)
                    }
                    this._notifyAttackCompleted(task, context)
                    return combined?.success ? combined : null
                }
                if (this._isWebSocketAttackTask(task)) {
                    const executed = await this._runWebSocketAttack(task, context, preparedPayload)
                    if (executed && task.attack?.validation) {
                        const combined = Object.assign(executed, task.module.validateAttack(executed, context.original))
                        this._decorateAttackResult(combined, task)
                        if (combined?.success) {
                            this._recordStrategyFinding(task, combined)
                        }
                        this._tagResultOrder(combined, task)
                        recordExecuted(combined)
                        this._notifyAttackCompleted(task, context)
                        return combined?.success ? combined : null
                    }
                    if (executed?.success) {
                        this._decorateAttackResult(executed, task)
                        this._recordStrategyFinding(task, executed)
                        this._tagResultOrder(executed, task)
                        recordExecuted(executed)
                        this._notifyAttackCompleted(task, context)
                        return executed
                    }
                    recordExecuted(executed)
                    this._notifyAttackCompleted(task, context)
                    return null
                }
                if (this._shouldUseSmugglingH2Transport(task, preparedPayload)) {
                    const executed = await this._runSmugglingH2Attack(task, context, preparedPayload)
                    if (executed && task.attack?.validation) {
                        const combined = Object.assign(executed, task.module.validateAttack(executed, context.original))
                        this._decorateAttackResult(combined, task)
                        if (combined?.success) {
                            this._recordStrategyFinding(task, combined)
                        }
                        this._tagResultOrder(combined, task)
                        recordExecuted(combined)
                        this._notifyAttackCompleted(task, context)
                        return combined?.success ? combined : null
                    }
                    if (executed?.success) {
                        this._decorateAttackResult(executed, task)
                        this._recordStrategyFinding(task, executed)
                        this._tagResultOrder(executed, task)
                        recordExecuted(executed)
                        this._notifyAttackCompleted(task, context)
                        return executed
                    }
                    recordExecuted(executed)
                    this._notifyAttackCompleted(task, context)
                    return null
                }
                if (this._isMultiIdentityAttackTask(task)) {
                    const combined = await this._runMultiIdentityAttack(task, context, preparedPayload)
                    if (combined) {
                        this._decorateAttackResult(combined, task)
                    }
                    if (combined?.success) {
                        this._recordStrategyFinding(task, combined)
                    }
                    if (combined) {
                        this._tagResultOrder(combined, task)
                        recordExecuted(combined)
                    }
                    this._notifyAttackCompleted(task, context)
                    return combined?.success ? combined : null
                }
                const executed = await this.activeAttack(preparedPayload)
                if (executed) {
                    const trackingResult = await this._runTracking(task, executed, context)
                    const validationResult = task.attack?.validation
                        ? this._filterActiveValidationResult(task, task.module.validateAttack(executed, context.original), executed, context)
                        : null
                    const renderFollowup = validationResult && !validationResult?.success
                        ? await this._runTemplateRenderFollowup(task, executed, context)
                        : null
                    const combined = this._mergeActiveAttackResults(executed, {
                        validationResult,
                        renderFollowupResult: renderFollowup,
                        trackingResult
                    })
                    if (combined && (task.attack?.validation || trackingResult?.success)) {
                        if (task.attack?.id === 'jwt_1') {
                            combined.__jwt1 = true
                        }
                        this._runOastCallbackCorrelation(task, executed, combined, context)
                        const confirmed = await this._maybeApplyConfirmPolicy(task, combined, context)
                        this._decorateAttackResult(combined, task)
                        if (confirmed?.success) {
                            this._recordStrategyFinding(task, confirmed)
                        }
                        this._tagResultOrder(combined, task)
                        recordExecuted(combined)
                        this._notifyAttackCompleted(task, context)
                        return combined
                    }
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
                    if (!this._shouldRecordPassiveUnique(combined, task, context.original)) {
                        return null
                    }
                    if (!this._isReconAttackResult(combined)) {
                        this._recordStrategyFinding(task, combined)
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
        const pendingHtmlDiscovery = this._pendingHtmlLinkDiscoveryCount()
        const captureStats = this._captureProgressSnapshot()
        const pendingCaptures = Math.max(0, Number(captureStats?.pendingObservedRequests || 0))
        const nonExecuted = Math.max(planned - executed, 0)
        const planning = this.inProgress ? 1 : 0
        const pipelineRemaining = Math.max(taskQueue + activeTasks + requestQueue + pendingPlans + planning + pendingCaptures + pendingHtmlDiscovery, 0)
        const remaining = pipelineRemaining
        const isIdle = Boolean(this.isRunning && requestQueue === 0 && taskQueue === 0 && pendingPlans === 0 && activeTasks === 0 && planning === 0 && pendingCaptures === 0 && pendingHtmlDiscovery === 0)
        return {
            planned,
            executed,
            skippedDueToStrategy: Number(this.scanStats?.skippedDueToStrategy || 0),
            remaining,
            nonExecuted,
            activeTasks,
            taskQueue,
            requestQueue,
            pendingPlans,
            planning,
            pendingCaptures,
            pendingHtmlDiscovery,
            captureStats,
            isRunning: !!this.isRunning,
            isIdle,
            phase: this.isRunning ? (isIdle ? 'idle' : 'scanning') : 'stopped',
            scanStrategy: this.strategyConfig?.strategy || DEFAULT_SCAN_STRATEGY,
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
            progress.pendingCaptures || 0,
            progress.pendingHtmlDiscovery || 0,
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

    _resolveFindingAggregateScopeHost(urlValue = null) {
        const fallbackHost = this._requestHostValue(this.scanResult?.host)
            || this._requestHostValue(this.host)
            || null
        const baseUrl = (() => {
            const rawBase = String(this.scanResult?.host || this.host || '').trim()
            if (!rawBase) return undefined
            if (/^https?:\/\//i.test(rawBase)) return rawBase
            return `http://${rawBase}`
        })()
        const raw = String(urlValue || '').trim()
        if (!raw) return fallbackHost
        try {
            const parsed = new URL(
                raw,
                raw.startsWith('http')
                    ? undefined
                    : baseUrl
            )
            return parsed.host || fallbackHost
        } catch (_) {
            return this._requestHostValue(raw) || fallbackHost
        }
    }

    _normalizeFindingAggregationMode(value) {
        const mode = String(value || '').trim().toLowerCase()
        return DAST_FINDING_AGGREGATION_MODES.has(mode) ? mode : null
    }

    _resolveFindingPresentationAggregate(...sources) {
        for (const source of sources) {
            const mode = this._normalizeFindingAggregationMode(source?.presentation?.aggregate)
            if (mode) return mode
        }
        return null
    }

    _normalizeFindingAggregateRoute(urlValue = null) {
        const raw = String(urlValue || '').trim()
        if (!raw) return ''
        const fallbackBase = this.host ? `http://${String(this.host).trim()}` : 'http://localhost'
        const normalizePath = (value) => {
            const text = String(value || '/').trim() || '/'
            if (text === '/') return text
            return text.replace(/\/+$/, '') || '/'
        }
        try {
            const parsed = new URL(raw, raw.startsWith('http') ? undefined : fallbackBase)
            const origin = String(parsed.origin || '').toLowerCase()
            let route = `${origin}${normalizePath(parsed.pathname)}`
            if (parsed.hash) {
                const hashRoute = String(parsed.hash.slice(1) || '').split('?')[0]
                if (hashRoute) {
                    route += `#${normalizePath(hashRoute)}`
                }
            }
            return route
        } catch (_) {
            const [withoutQuery] = raw.split('?')
            const [pathOnly, hashPart] = withoutQuery.split('#')
            const hashRoute = hashPart ? hashPart.split('?')[0] : ''
            return `${normalizePath(pathOnly)}${hashRoute ? `#${normalizePath(hashRoute)}` : ''}`
        }
    }

    _resolveFindingAggregateParam(location = {}, attackMeta = {}, attack = null) {
        const explicit = location?.param
            || attack?.param
            || attackMeta?.attacked?.name
            || (Array.isArray(attackMeta?.mutations) && attackMeta.mutations[0]?.name)
            || null
        if (explicit) return String(explicit).trim().toLowerCase()
        const params = getSearchParamsFromUrlOrHash(location?.runtimeUrl || location?.url || '')
        const names = Array.from(new Set(Array.from(params.keys()).map((name) => String(name || '').trim()).filter(Boolean)))
        return names.length === 1 ? names[0].toLowerCase() : null
    }

    _normalizeFindingAggregateSink(value = null) {
        if (value && typeof value === 'object') return null
        const text = String(value || '').trim()
        if (!text) return null
        const normalizeHarnessSink = (sinkText) => {
            const sinkParts = String(sinkText || '').split('|')
            const type = String(sinkParts[0] || '').trim().toLowerCase()
            const knownHarnessTypes = new Set([
                'attribute_event_handler',
                'attribute_srcdoc',
                'attribute_style',
                'attribute_url',
                'attribute',
                'script_text',
                'text'
            ])
            if (sinkParts.length >= 5 && knownHarnessTypes.has(type)) {
                // The final harness part is a hash of outerHTML, which can include
                // the attack marker/payload. It is too volatile for presentation
                // aggregation; route + param + structural sink is the stable identity.
                return sinkParts.slice(0, 4).join('|')
            }
            return sinkText
        }
        const parts = text.split('|')
        if (parts.length > 1) {
            try {
                new URL(parts[0])
                const rest = parts.slice(1).join('|').trim()
                if (rest) return normalizeHarnessSink(rest).toLowerCase()
            } catch (_) {
                // Keep non-URL composite sink keys intact.
            }
        }
        return normalizeHarnessSink(text).toLowerCase()
    }

    _resolveFindingAggregateSink(attackMeta = {}, attack = null) {
        const checks = Array.isArray(attackMeta?.checks)
            ? attackMeta.checks.join(',')
            : attackMeta?.checks
        const candidates = [
            attackMeta?.sinkKey,
            attackMeta?.sink,
            attackMeta?.context?.sink,
            attackMeta?.context,
            attack?.detector,
            attackMeta?.detector,
            attackMeta?.validation?.type,
            checks
        ]
        for (const candidate of candidates) {
            const sink = this._normalizeFindingAggregateSink(candidate)
            if (sink) return sink
        }
        return null
    }

    _buildFindingAggregateKey(classification = {}, location = {}, details = {}) {
        const mode = this._normalizeFindingAggregationMode(classification?.presentationAggregate)
        if (!mode) return null
        const scopeHost = this._resolveFindingAggregateScopeHost(
            location?.runtimeUrl || location?.url || null
        )
        const baseParts = [
            'DAST',
            mode,
            String(this.scanResult?.scanId || ''),
            String(scopeHost || ''),
            String(classification?.moduleId || ''),
            String(classification?.ruleId || '')
        ]
        if (mode === 'scan') {
            return baseParts.join('|')
        }

        const route = this._normalizeFindingAggregateRoute(location?.runtimeUrl || location?.url || null)
        if (!route) return null
        baseParts.push(route)

        const attackMeta = details?.attackMeta && typeof details.attackMeta === 'object'
            ? details.attackMeta
            : {}
        const attack = details?.attack || null
        if (mode === 'route-param' || mode === 'route-param-sink') {
            const param = this._resolveFindingAggregateParam(location, attackMeta, attack)
            if (!param) return null
            baseParts.push(param)
        }
        if (mode === 'route-sink' || mode === 'route-param-sink') {
            const sink = this._resolveFindingAggregateSink(attackMeta, attack)
            if (!sink) return null
            baseParts.push(sink)
        }
        return baseParts.join('|')
    }

    _buildSpaRuntimeAggregateContext(task, {
        uiUrl = null,
        param = null,
        sinkKey = null,
        resultMetadata = {}
    } = {}) {
        const targetUrl = uiUrl || task?.payload?.ui_url || task?.payload?.uiUrl || null
        const targetParam = param ?? task?.payload?.param ?? null
        const moduleMeta = this._moduleMetadataView(task?.module)
        const baseMetadata = task?.payload?.metadata && typeof task.payload.metadata === 'object'
            ? task.payload.metadata
            : this._attackMetadataView(task?.module, task?.attack)
        const metadata = Object.assign({}, baseMetadata, resultMetadata || {}, {
            attacked: { location: 'hash', name: targetParam },
            sinkKey: sinkKey || resultMetadata?.sinkKey || baseMetadata?.sinkKey || null
        })
        const attackForClassification = {
            success: true,
            metadata,
            request: { url: targetUrl, ui_url: targetUrl, method: 'GET' },
            __moduleId: task?.moduleId || task?.module?.id || moduleMeta.id || metadata.moduleId || null,
            __moduleName: task?.moduleName || task?.module?.name || moduleMeta.name || metadata.moduleName || null,
            __moduleMetadata: moduleMeta,
            __moduleVulnId: task?.module?.vulnId || moduleMeta.vulnId || metadata.vulnId || null,
            __attackKey: task?.attack?.id || task?.attackKey || metadata.id || null
        }
        const classification = this._buildAttackClassification(
            attackForClassification,
            task?.attack?.id || task?.attackKey || null
        )
        const location = {
            url: targetUrl,
            runtimeUrl: targetUrl,
            method: 'GET',
            param: targetParam
        }
        return {
            aggregateKey: this._buildFindingAggregateKey(classification, location, {
                attackMeta: metadata,
                attack: attackForClassification
            }),
            classification,
            location,
            metadata
        }
    }

    _isSpaAttackResult(attack = null, classification = {}) {
        const request = attack?.request?.request && typeof attack.request.request === 'object'
            ? attack.request.request
            : (attack?.request && typeof attack.request === 'object' ? attack.request : {})
        const metadata = attack?.metadata && typeof attack.metadata === 'object' ? attack.metadata : {}
        if (request?.ui_url || request?.uiUrl) return true
        if (metadata?.attacked?.location === 'hash' && Array.isArray(metadata?.checks)) return true
        return String(classification?.moduleId || '').toLowerCase().startsWith('spa_')
    }

    _isSpaAggregateKeyConfirmed(aggregateKey = null) {
        if (!aggregateKey) return false
        if (!(this._spaConfirmedAggregateKeys instanceof Set)) {
            this._spaConfirmedAggregateKeys = new Set()
        }
        if (this._spaConfirmedAggregateKeys.has(aggregateKey)) return true
        const existing = this._lookupAggregatedFinding(aggregateKey)
        if (existing?.id) {
            this._spaConfirmedAggregateKeys.add(aggregateKey)
            return true
        }
        return false
    }

    _markSpaAggregateKeyConfirmed(aggregateKey = null, attack = null, classification = {}) {
        if (!aggregateKey || !this._isSpaAttackResult(attack, classification)) return
        if (!(this._spaConfirmedAggregateKeys instanceof Set)) {
            this._spaConfirmedAggregateKeys = new Set()
        }
        this._spaConfirmedAggregateKeys.add(aggregateKey)
    }

    _lookupAggregatedFinding(aggregateKey = null) {
        if (!aggregateKey) return null
        if (!(this._findingAggregateIndex instanceof Map)) {
            this._findingAggregateIndex = new Map()
        }
        const indexed = this._findingAggregateIndex.get(aggregateKey)
        if (indexed) return indexed
        const findings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings : []
        const existing = findings.find((finding) => {
            const aggregate = finding?.evidence?.dast?.aggregate
            return aggregate?.key === aggregateKey
        }) || null
        if (existing) {
            this._findingAggregateIndex.set(aggregateKey, existing)
        }
        return existing
    }

    _buildFindingAggregateSample({ requestRecord = null, attack = null, attackRecord = null, location = {} } = {}) {
        const sourceAttack = attackRecord || attack || {}
        const response = sourceAttack?.response && typeof sourceAttack.response === 'object'
            ? sourceAttack.response
            : {}
        return Object.fromEntries(
            Object.entries({
                url: location?.url || location?.runtimeUrl || null,
                method: location?.method || null,
                statusCode: response?.statusCode ?? response?.status ?? null,
                requestId: requestRecord?.id || null,
                attackId: sourceAttack?.id || attack?.id || null,
                proof: sourceAttack?.proof || null,
                seenAt: new Date().toISOString()
            }).filter(([, value]) => value !== null && value !== undefined && value !== '')
        )
    }

    _applyFindingAggregateState(finding, {
        aggregateKey = null,
        classification = {},
        sample = null
    } = {}) {
        if (!finding || !aggregateKey) return finding
        if (!finding.evidence || typeof finding.evidence !== 'object') {
            finding.evidence = {}
        }
        if (!finding.evidence.dast || typeof finding.evidence.dast !== 'object') {
            finding.evidence.dast = {}
        }
        const dastEvidence = finding.evidence.dast
        const aggregate = dastEvidence.aggregate && typeof dastEvidence.aggregate === 'object'
            ? dastEvidence.aggregate
            : {}
        dastEvidence.aggregate = Object.assign({}, aggregate, {
            mode: this._normalizeFindingAggregationMode(classification?.presentationAggregate) || 'scan',
            key: aggregateKey,
            scopeHost: this._resolveFindingAggregateScopeHost(
                finding?.location?.runtimeUrl || finding?.location?.url || null
            ) || aggregate.scopeHost || null
        })
        dastEvidence.occurrenceCount = Math.max(1, Number(dastEvidence.occurrenceCount || 0) || 0)
        dastEvidence.sampleLimit = DAST_FINDING_SCAN_AGGREGATE_SAMPLE_LIMIT
        dastEvidence.truncated = dastEvidence.truncated === true
        dastEvidence.samples = Array.isArray(dastEvidence.samples)
            ? dastEvidence.samples
            : []
        if (sample && typeof sample === 'object') {
            const sampleKey = `${String(sample.method || '').toUpperCase()}|${String(sample.url || '')}`
            const existingKeys = new Set(
                dastEvidence.samples.map((entry) => `${String(entry?.method || '').toUpperCase()}|${String(entry?.url || '')}`)
            )
            if (!existingKeys.has(sampleKey)) {
                if (dastEvidence.samples.length < DAST_FINDING_SCAN_AGGREGATE_SAMPLE_LIMIT) {
                    dastEvidence.samples.push(sample)
                } else {
                    dastEvidence.truncated = true
                }
            }
        }
        finding.presentationAggregate = classification?.presentationAggregate || finding.presentationAggregate || null
        return finding
    }

    _mergeAggregatedFindingOccurrence(existingFinding, {
        aggregateKey = null,
        classification = {},
        sample = null,
        confidence = null
    } = {}) {
        if (!existingFinding || !aggregateKey) return existingFinding
        this._applyFindingAggregateState(existingFinding, {
            aggregateKey,
            classification,
            sample
        })
        if (
            Number.isFinite(confidence)
            && (
                !Number.isFinite(existingFinding.confidence)
                || Number(confidence) > Number(existingFinding.confidence)
            )
        ) {
            existingFinding.confidence = confidence
        }
        if (!existingFinding.lastSeenAt) {
            existingFinding.lastSeenAt = new Date().toISOString()
        } else {
            existingFinding.lastSeenAt = new Date().toISOString()
        }
        const dastEvidence = existingFinding?.evidence?.dast
        if (dastEvidence && typeof dastEvidence === 'object') {
            dastEvidence.occurrenceCount = Math.max(1, Number(dastEvidence.occurrenceCount || 0) || 0) + 1
            if (!dastEvidence.requestId && sample?.requestId) {
                dastEvidence.requestId = sample.requestId
            }
            if (!dastEvidence.attackId && sample?.attackId) {
                dastEvidence.attackId = sample.attackId
            }
            if (!dastEvidence.proof && sample?.proof) {
                dastEvidence.proof = sample.proof
            }
        }
        return existingFinding
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
        let insertAt = existing.length
        for (let index = 0; index < existing.length; index += 1) {
            const currentPriority = Number(existing[index]?.priority || 0)
            if (task.priority > currentPriority) {
                insertAt = index
                break
            }
        }
        existing.splice(insertAt, 0, task)
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
            const requestRecord = this._createRequestRecord(plan.original, true, {
                dedupeKey: plan?.raw?.__dedupeKey || plan?.fingerprint || null,
                allowRecordedUpgrade: plan?.raw?.__upgradeRecordedRequest === true
            })
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
        plan.requestRecord = this._createRequestRecord(plan.original, true, {
            dedupeKey: plan?.raw?.__dedupeKey || plan?.fingerprint || null,
            allowRecordedUpgrade: plan?.raw?.__upgradeRecordedRequest === true
        })
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
                    const attackIndex = plan.attacks.length
                    plan.attacks.push(res)
                    this._emitLiveAttackDelta(plan, res)
                    this._recordLiveAttackFinding(plan, res, attackIndex)
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
            confirm: Object.assign({}, controls.confirm),
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
            dastPackStatus: source?.dastPackStatus || 'active',
            dastPackError: source?.dastPackError || null,
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
        if (Array.isArray(this.modules) && this.modules.length) {
            this._refreshModuleStatuses()
        }
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

    _taskRequiresStrategyContinuation(task) {
        if (this._taskConditionRequiresModuleExecuted(task)) return true
        const fileUpload = task?.attack?.metadata?.extensions?.fileUpload
        if (!fileUpload || typeof fileUpload !== 'object') return false
        if (fileUpload.chain && typeof fileUpload.chain === 'object') return true
        return this._normalizeTrackingTier(fileUpload.confirmationTier, '') === 'executed'
    }

    _shouldSkipTaskDueToStrategy(task) {
        if (this._taskRequiresStrategyContinuation(task)) return false
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

    _isFirefoxRuntime() {
        return typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
    }

    _supportsActiveRequestTrackingListeners() {
        return !!(
            typeof browser !== 'undefined'
            && browser?.webRequest?.onBeforeRequest
            && browser?.webRequest?.onBeforeSendHeaders
            && browser?.webRequest?.onHeadersReceived
        )
    }

    _spaResponseMissingChecks(response, checks = []) {
        if (!Array.isArray(checks) || !checks.length) {
            return !response || typeof response !== 'object'
        }
        if (!response || typeof response !== 'object') return true
        return checks.some((checkName) => !Object.prototype.hasOwnProperty.call(response, checkName))
    }

    async _injectSpaHarness(tabId, task, taskContext, reason = 'send_failed') {
        let lastError = null

        if (browser?.scripting?.executeScript) {
            try {
                await browser.scripting.executeScript({
                    target: { tabId },
                    files: ['ptk/content/spa_hash_harness.js']
                })
                await new Promise((resolve) => setTimeout(resolve, 75))
                return true
            } catch (err) {
                lastError = err
            }
        }

        if (browser?.tabs?.executeScript) {
            try {
                await browser.tabs.executeScript(tabId, {
                    file: 'ptk/content/spa_hash_harness.js',
                    runAt: 'document_idle'
                })
                await new Promise((resolve) => setTimeout(resolve, 75))
                return true
            } catch (err) {
                lastError = err
            }
        }

        this._appendTaskRuntimeEvent(task, taskContext, {
            type: 'dast_spa_filtered',
            phase: 'harness_bootstrap',
            reason: 'inject_failed',
            bootstrapReason: reason,
            error: lastError?.message || String(lastError || 'inject_failed')
        })
        return false
    }

    async _ensureSpaHarnessReady(tabId, task, taskContext) {
        try {
            const ping = await browser.tabs.sendMessage(tabId, { type: 'spaPing' })
            if (ping?.ok === true) {
                return true
            }
        } catch (_) { }

        const injected = await this._injectSpaHarness(tabId, task, taskContext, 'preflight_ping')
        if (!injected) return false

        try {
            const ping = await browser.tabs.sendMessage(tabId, { type: 'spaPing' })
            if (ping?.ok === true) {
                return true
            }
        } catch (_) { }

        this._appendTaskRuntimeEvent(task, taskContext, {
            type: 'dast_spa_filtered',
            phase: 'harness_bootstrap',
            reason: 'ping_failed'
        })
        return false
    }

    _browserNavHarnessFile() {
        return !this._isFirefoxRuntime()
            ? 'ptk/content/xss_nav_harness.js'
            : 'content/xss_nav_harness.js'
    }

    async _ensureBrowserNavHarnessScript() {
        if (this._browserNavHarnessRegistered) return true
        if (!browser?.scripting?.registerContentScripts) {
            return false
        }
        try {
            if (browser?.scripting?.unregisterContentScripts) {
                await browser.scripting.unregisterContentScripts({
                    ids: [DAST_BROWSER_NAV_HARNESS_SCRIPT_ID]
                }).catch(() => {})
            }
            await browser.scripting.registerContentScripts([{
                id: DAST_BROWSER_NAV_HARNESS_SCRIPT_ID,
                js: [this._browserNavHarnessFile()],
                matches: ['<all_urls>'],
                // Keep the browser-nav harness in the extension content-script world
                // so browser.runtime messaging stays available on Chromium.
                runAt: 'document_start'
            }])
            this._browserNavHarnessRegistered = true
            return true
        } catch (err) {
            console.warn('[PTK DAST] Failed to register browser-nav harness', err)
            this._browserNavHarnessRegistered = false
            return false
        }
    }

    async _unregisterBrowserNavHarnessScript() {
        this._browserNavHarnessRegistered = false
        if (!browser?.scripting?.unregisterContentScripts) return
        try {
            await browser.scripting.unregisterContentScripts({
                ids: [DAST_BROWSER_NAV_HARNESS_SCRIPT_ID]
            })
        } catch (_) { }
    }

    async _injectBrowserNavHarness(tabId, task, taskContext, reason = 'send_failed') {
        let lastError = null

        if (browser?.scripting?.executeScript) {
            try {
                await browser.scripting.executeScript({
                    target: { tabId },
                    files: ['ptk/content/xss_nav_harness.js']
                })
                await new Promise((resolve) => setTimeout(resolve, 75))
                return true
            } catch (err) {
                lastError = err
            }
        }

        if (browser?.tabs?.executeScript) {
            try {
                await browser.tabs.executeScript(tabId, {
                    file: 'ptk/content/xss_nav_harness.js',
                    runAt: 'document_idle'
                })
                await new Promise((resolve) => setTimeout(resolve, 75))
                return true
            } catch (err) {
                lastError = err
            }
        }

        this._appendTaskRuntimeEvent(task, taskContext, {
            type: 'dast_browser_nav_filtered',
            phase: 'harness_bootstrap',
            reason: 'inject_failed',
            bootstrapReason: reason,
            error: lastError?.message || String(lastError || 'inject_failed')
        })
        return false
    }

    async _ensureBrowserNavHarnessReady(tabId, task, taskContext) {
        try {
            const ping = await browser.tabs.sendMessage(tabId, { type: 'browserNavPing' })
            if (ping?.ok === true && ping?.active === true) {
                return true
            }
        } catch (_) { }

        const injected = await this._injectBrowserNavHarness(tabId, task, taskContext, 'preflight_ping')
        if (!injected) return false

        try {
            const ping = await browser.tabs.sendMessage(tabId, { type: 'browserNavPing' })
            if (ping?.ok === true && ping?.active === true) {
                return true
            }
        } catch (_) { }

        this._appendTaskRuntimeEvent(task, taskContext, {
            type: 'dast_browser_nav_filtered',
            phase: 'harness_bootstrap',
            reason: 'ping_failed'
        })
        return false
    }

    _normalizeBrowserNavChecks(values = []) {
        const normalized = Array.from(new Set(
            (Array.isArray(values) ? values : [values])
                .map((value) => String(value || '').trim().toLowerCase())
                .filter(Boolean)
                .filter((value) => DAST_BROWSER_NAV_SUPPORTED_CHECKS.has(value))
        ))
        return normalized.length ? normalized : ['dom_xss']
    }

    _normalizeBrowserNavSourceDrivers(values = []) {
        return Array.from(new Set(
            (Array.isArray(values) ? values : [values])
                .map((value) => String(value || '').trim())
                .filter(Boolean)
                .filter((value) => DAST_BROWSER_NAV_SOURCE_DRIVERS.has(value))
        ))
    }

    _effectiveBrowserNavSourceDriversForTask(task, sourceDrivers = []) {
        const drivers = this._normalizeBrowserNavSourceDrivers(sourceDrivers)
        const attackId = String(task?.attack?.id || '')
        const context = String(task?.attack?.metadata?.constants?.context || '')
        if (attackId.startsWith('angularjs_csti_') && context === 'template_interpolation') {
            return drivers.filter((driver) => driver === 'form')
        }
        return drivers
    }

    _browserNavSourceKeyHintsForDriver(payload = null, driver = '') {
        const hints = payload?.metadata?.browserSource?.keyHints
        const values = hints && typeof hints === 'object' ? hints[driver] : null
        return Array.from(new Set(
            (Array.isArray(values) ? values : [])
                .map((value) => String(value || '').trim())
                .filter(Boolean)
        ))
    }

    _browserNavSourceKeyModeForDriver(payload = null, driver = '') {
        const keyMode = payload?.metadata?.browserSource?.keyMode
        if (typeof keyMode === 'string') return keyMode.trim()
        if (!keyMode || typeof keyMode !== 'object') return ''
        return String(keyMode[driver] || '').trim()
    }

    _browserNavSourceValueLooksSensitive(value = '') {
        const raw = String(value == null ? '' : value)
        if (!raw) return false
        if (/^Bearer\s+[A-Za-z0-9._~+/=-]{16,}$/i.test(raw)) return true
        if (/^[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/.test(raw)) return true
        if (/token|session|csrf|xsrf|password|passwd|secret|credential|api[_-]?key/i.test(raw) && raw.length >= 12) return true
        return false
    }

    _browserNavSourceKeyIsSensitive(driver, key, value = '') {
        const sourceDriver = String(driver || '').trim()
        const sourceKey = String(key || '').trim()
        if (!sourceKey) return true
        const normalized = sourceKey.toLowerCase()
        if (sourceDriver === 'cookie') {
            const hardDeny = new RegExp(DEFAULT_HARD_DENY_COOKIE_REGEX, 'i')
            if (hardDeny.test(sourceKey)) return true
        }
        if (/^(?:authorization|cookie|set-cookie)$/i.test(sourceKey)) return true
        if (/^(?:__host-|__secure-)/i.test(sourceKey)) return true
        if (/(session|sessionid|sess|sid|auth|authorization|bearer|token|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|csrf|xsrf|password|passwd|pwd|secret|credential|api[_-]?key|apikey)/i.test(normalized)) return true
        if (/(?:awsalb|awselb|connect\.sid|phpsessid|jsessionid)/i.test(normalized)) return true
        return this._browserNavSourceValueLooksSensitive(value)
    }

    _filterBrowserNavSourceKeys(driver, keys = [], values = {}, task = null, taskContext = null) {
        const safeKeys = []
        const skippedKeys = []
        const sourceValues = values && typeof values === 'object' ? values : {}
        for (const rawKey of Array.isArray(keys) ? keys : []) {
            const key = String(rawKey || '').trim()
            if (!key) continue
            const value = Object.prototype.hasOwnProperty.call(sourceValues, key)
                ? sourceValues[key]
                : ''
            if (this._browserNavSourceKeyIsSensitive(driver, key, value)) {
                skippedKeys.push(key)
                continue
            }
            safeKeys.push(key)
        }
        if (skippedKeys.length) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_nav_source_key_skipped',
                phase: 'attack_eval',
                reason: 'sensitive_source_key',
                sourceDriver: driver,
                skippedCount: skippedKeys.length,
                sampledKeys: skippedKeys.slice(0, 5)
            })
        }
        return safeKeys
    }

    _browserNavPayloadValue(task, payload) {
        const metadataPayload = payload?.metadata?.payload
        if (metadataPayload != null) return String(metadataPayload)
        const params = Array.isArray(task?.attack?.action?.params) ? task.attack.action.params : []
        const firstValue = params.find((param) => param && param.value != null)?.value
        if (firstValue != null) return String(firstValue)
        const constantsPayload = task?.attack?.metadata?.constants?.payload
        if (constantsPayload != null) return String(constantsPayload)
        return ''
    }

    _browserNavSourceBaseUrl(payload, context, fallbackUrl = null) {
        const candidates = [
            context?.original?.request?.ui_url,
            context?.original?.request?.uiUrl,
            context?.original?.request?.url,
            payload?.request?.ui_url,
            payload?.request?.uiUrl,
            payload?.request?.url,
            payload?.ui_url,
            payload?.uiUrl,
            payload?.url,
            fallbackUrl
        ]
        for (const candidate of candidates) {
            const value = String(candidate || '').trim()
            if (value) return value
        }
        return null
    }

    async _sendBrowserNavHarnessMessage(tabId, message, task, taskContext) {
        const ready = await this._ensureBrowserNavHarnessReady(tabId, task, taskContext)
        if (!ready) {
            return { error: 'harness_not_ready' }
        }
        try {
            return await browser.tabs.sendMessage(tabId, message)
        } catch (err) {
            const injected = await this._injectBrowserNavHarness(tabId, task, taskContext, 'send_failed')
            if (!injected) throw err
            return browser.tabs.sendMessage(tabId, message)
        }
    }

    async _probeBrowserNavMainWorldWindowName(tabId, markerToken) {
        const markerId = String(markerToken || '').trim()
        if (!tabId || !markerId || !browser?.scripting?.executeScript) return false
        try {
            const results = await browser.scripting.executeScript({
                target: { tabId },
                world: 'MAIN',
                func: (marker) => {
                    try {
                        const token = `ptk-xss:${String(marker || '').trim()}`
                        return !!token && String(window.name || '').includes(token)
                    } catch (_) {
                        return false
                    }
                },
                args: [markerId]
            })
            return Array.isArray(results) && results.some((entry) => entry?.result === true)
        } catch (_) {
            return false
        }
    }

    async _runBrowserNavChecksInTab(tabId, task, taskContext, markerToken, checks, settleMs) {
        const result = await this._sendBrowserNavHarnessMessage(tabId, {
            type: 'browserNavRun',
            markerToken,
            checks,
            settleMs
        }, task, taskContext)
        if (
            this._normalizeBrowserNavChecks(checks).includes('dom_xss')
            && !result?.dom_xss?.vulnerable
            && await this._probeBrowserNavMainWorldWindowName(tabId, markerToken)
        ) {
            return Object.assign({}, result, {
                dom_xss: {
                    vulnerable: true,
                    executed: true,
                    reflected: false,
                    sinkKey: null,
                    context: {
                        type: 'window_name_marker',
                        sourceDriver: null,
                        sourceKey: null,
                        tag: null,
                        attr: 'window.name',
                        cssPath: null,
                        outerHTML: null,
                        snippet: `ptk-xss:${String(markerToken || '').trim()}`
                    }
                }
            })
        }
        return result
    }

    async _reloadBrowserNavAttackTab(tabId, task, taskContext) {
        const ready = this._waitForTabReady(tabId)
        try {
            if (browser?.tabs?.reload) {
                await browser.tabs.reload(tabId)
            } else {
                const tab = browser?.tabs?.get ? await browser.tabs.get(tabId) : null
                const url = tab?.url || tab?.pendingUrl || null
                if (url && browser?.tabs?.update) {
                    await browser.tabs.update(tabId, { url })
                }
            }
        } catch (_) { }
        await ready
        await this._markSpaAttackTab(tabId, {
            marker: DAST_BROWSER_NAV_TAB_MARKER,
            domOnly: true
        })
        await this._ensureBrowserNavHarnessReady(tabId, task, taskContext)
    }

    async _waitForBrowserNavAttackTabNavigation(tabId, task, taskContext, timeoutMs = 4500) {
        await this._waitForTabReady(tabId, timeoutMs)
        await this._markSpaAttackTab(tabId, {
            marker: DAST_BROWSER_NAV_TAB_MARKER,
            domOnly: true
        })
        await this._ensureBrowserNavHarnessReady(tabId, task, taskContext)
    }

    _buildBrowserNavAttackResult(task, payload, uiUrl, attacked, checks, markerToken, domXss, runtimeMode, sourceInfo = null) {
        const sinkKey = domXss.sinkKey ? `${uiUrl}|${domXss.sinkKey}` : null
        if (sinkKey && this._browserNavSeenSinks?.has(sinkKey)) {
            return { duplicate: true, sinkKey }
        }
        if (sinkKey && this._browserNavSeenSinks) {
            this._browserNavSeenSinks.add(sinkKey)
        }

        const metadata = Object.assign(
            {},
            this._attackMetadataView(task?.module, task?.attack),
            payload?.metadata || {},
            {
                attacked,
                checks,
                markerToken,
                executed: !!domXss.executed,
                reflected: !!domXss.reflected,
                context: domXss.context || null,
                sinkKey: sinkKey || null,
                runtimeMode
            },
            sourceInfo ? { browserSource: sourceInfo } : {}
        )
        const proof = JSON.stringify({
            executed: !!domXss.executed,
            reflected: !!domXss.reflected,
            sinkKey: sinkKey || null,
            context: domXss.context || null,
            source: sourceInfo || null
        })

        return {
            success: true,
            metadata,
            request: {
                url: uiUrl,
                ui_url: uiUrl,
                method: 'GET'
            },
            response: {},
            proof
        }
    }

    async _runBrowserNavSourceDrivers(task, taskContext, payload, options = {}) {
        const drivers = this._normalizeBrowserNavSourceDrivers(options.sourceDrivers || [])
        if (!drivers.length) return null
        const payloadValue = this._browserNavPayloadValue(task, payload)
        if (!payloadValue) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_nav_filtered',
                phase: 'attack_eval',
                reason: 'missing_browser_source_payload'
            })
            return null
        }
        const uiUrl = this._browserNavSourceBaseUrl(payload, taskContext, options.uiUrl)
        if (!uiUrl) return null

        for (const driver of drivers) {
            const result = await this._withBrowserNavAttackTab(uiUrl, async (tabId) => {
                if (driver === 'postMessage') {
                    const res = await this._sendBrowserNavHarnessMessage(tabId, {
                        type: 'browserNavSourcePostMessage',
                        markerToken: options.markerToken,
                        checks: options.checks,
                        settleMs: options.settleMs,
                        payload: payloadValue
                    }, task, taskContext)
                    return {
                        res,
                        sourceInfo: {
                            driver,
                            key: 'window'
                        }
                    }
                }
                if (driver === 'form') {
                    const submitted = await this._sendBrowserNavHarnessMessage(tabId, {
                        type: 'browserNavSourceForm',
                        markerToken: options.markerToken,
                        checks: options.checks,
                        settleMs: options.settleMs,
                        payload: payloadValue
                    }, task, taskContext)
                    if (submitted?.dom_xss?.vulnerable) {
                        return {
                            res: submitted,
                            sourceInfo: submitted.sourceContext || {
                                driver,
                                key: 'form'
                            }
                        }
                    }
                    if (submitted?.mayNavigate) {
                        await this._waitForBrowserNavAttackTabNavigation(tabId, task, taskContext)
                        const res = await this._runBrowserNavChecksInTab(
                            tabId,
                            task,
                            taskContext,
                            options.markerToken,
                            options.checks,
                            options.settleMs
                        )
                        return {
                            res,
                            sourceInfo: submitted.sourceContext || {
                                driver,
                                key: 'form'
                            }
                        }
                    }
                    return {
                        res: submitted,
                        reason: submitted?.reason || submitted?.error || 'no_source_candidates',
                        sourceInfo: submitted?.sourceContext || { driver }
                    }
                }

                const snapshot = await this._sendBrowserNavHarnessMessage(tabId, {
                    type: 'browserNavSourceSnapshot',
                    drivers: [driver]
                }, task, taskContext)
                const sourceValues = snapshot?.sources?.[driver]?.values && typeof snapshot.sources[driver].values === 'object'
                    ? snapshot.sources[driver].values
                    : {}
                const rawKeys = Array.isArray(snapshot?.sources?.[driver]?.keys)
                    ? snapshot.sources[driver].keys
                        .map((key) => String(key || '').trim())
                        .filter(Boolean)
                    : []
                const hintedKeys = this._browserNavSourceKeyHintsForDriver(payload, driver)
                const keyMode = this._browserNavSourceKeyModeForDriver(payload, driver)
                const candidateKeys = keyMode === 'hint-only'
                    ? hintedKeys
                    : rawKeys.concat(hintedKeys)
                const keys = this._filterBrowserNavSourceKeys(
                    driver,
                    candidateKeys,
                    sourceValues,
                    task,
                    taskContext
                )
                    .slice(0, DAST_BROWSER_NAV_SOURCE_KEY_LIMIT)
                if (!keys.length) {
                    return {
                        skipped: true,
                        reason: 'no_source_candidates',
                        sourceInfo: { driver }
                    }
                }
                for (const key of keys) {
                    const applied = await this._sendBrowserNavHarnessMessage(tabId, {
                        type: 'browserNavSourceApply',
                        driver,
                        key,
                        value: payloadValue,
                        cookieEncoding: options.cookieEncoding || null
                    }, task, taskContext)
                    if (applied?.error) continue
                    let res = null
                    const hadOriginal = Object.prototype.hasOwnProperty.call(sourceValues, key)
                    const originalValue = hadOriginal ? sourceValues[key] : null
                    try {
                        await this._reloadBrowserNavAttackTab(tabId, task, taskContext)
                        res = await this._runBrowserNavChecksInTab(
                            tabId,
                            task,
                            taskContext,
                            options.markerToken,
                            options.checks,
                            options.settleMs
                        )
                    } finally {
                        await this._sendBrowserNavHarnessMessage(tabId, {
                            type: 'browserNavSourceRestore',
                            driver,
                            key,
                            hadOriginal,
                            originalValue
                        }, task, taskContext).catch(() => null)
                    }
                    if (res?.dom_xss?.vulnerable) {
                        return {
                            res,
                            sourceInfo: {
                                driver,
                                key
                            }
                        }
                    }
                }
                return {
                    res: null,
                    sourceInfo: { driver }
                }
            })

            const domXss = result?.res?.dom_xss
            if (domXss?.vulnerable) {
                return {
                    uiUrl,
                    domXss,
                    sourceInfo: result.sourceInfo || { driver }
                }
            }
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_nav_filtered',
                phase: 'attack_eval',
                reason: result?.reason || 'browser_source_no_vulnerability_match',
                sourceDriver: driver
            })
        }
        return null
    }

    async _runBrowserNavAttack(task, context, preparedPayload) {
        const payload = preparedPayload || task?.payload || {}
        const request = payload?.request || {}
        const requestUrl = request.url || payload.url || null
        const originalUiUrl = request.ui_url || request.uiUrl || payload.ui_url || payload.uiUrl || null
        const uiUrl = requestUrl || originalUiUrl || null
        const method = String(request.method || 'GET').toUpperCase()
        const attacked = payload?.metadata?.attacked || null
        const taskContext = context || { original: { request: { url: uiUrl || null, ui_url: uiUrl || null, method } } }

        if (!uiUrl) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_nav_filtered',
                phase: 'attack_eval',
                reason: 'missing_ui_url'
            })
            return null
        }
        if (method !== 'GET') {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_nav_filtered',
                phase: 'attack_eval',
                reason: 'unsupported_method',
                attackMethod: method
            })
            return null
        }
        const browserNavCfg = this._taskAttackRuntimeConfig(task, 'browserNav') || {}
        const payloadBrowserSourceDrivers = Array.isArray(payload?.metadata?.browserSource?.sourceDrivers)
            ? payload.metadata.browserSource.sourceDrivers
            : null
        const sourceDrivers = this._effectiveBrowserNavSourceDriversForTask(
            task,
            payloadBrowserSourceDrivers || browserNavCfg.sourceDrivers || browserNavCfg.sources || []
        )
        const attackedLocation = String(attacked?.location || '').toLowerCase()
        if (attackedLocation !== 'query' && !(attackedLocation === 'browser_source' && sourceDrivers.length)) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_nav_filtered',
                phase: 'attack_eval',
                reason: 'unsupported_target_surface',
                attacked
            })
            return null
        }

        const checks = this._normalizeBrowserNavChecks(browserNavCfg.checks || [])
        const markerToken = String(browserNavCfg.markerToken || '').trim()
        const settleMsRaw = Number(browserNavCfg.settleMs)
        const settleMs = Number.isFinite(settleMsRaw)
            ? Math.max(0, Math.min(5000, Math.floor(settleMsRaw)))
            : DAST_BROWSER_NAV_DEFAULT_SETTLE_MS

        if (!markerToken) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_nav_filtered',
                phase: 'attack_eval',
                reason: 'missing_marker_token'
            })
            return null
        }

        try {
            let domXss = null
            if (attackedLocation === 'query') {
                const res = await this._withBrowserNavAttackTab(uiUrl, (tabId) => (
                    this._runBrowserNavChecksInTab(tabId, task, taskContext, markerToken, checks, settleMs)
                ))
                if (this._spaResponseMissingChecks(res, checks)) {
                    this._appendTaskRuntimeEvent(task, taskContext, {
                        type: 'dast_browser_nav_filtered',
                        phase: 'attack_eval',
                        reason: 'harness_not_ready',
                        missingChecks: checks.filter((checkName) => !Object.prototype.hasOwnProperty.call(res || {}, checkName))
                    })
                    return null
                }
                domXss = res?.dom_xss || null
            }

            if (domXss?.vulnerable) {
                const built = this._buildBrowserNavAttackResult(
                    task,
                    payload,
                    uiUrl,
                    attacked,
                    checks,
                    markerToken,
                    domXss,
                    'browser_nav'
                )
                if (built?.duplicate) {
                    this._appendTaskRuntimeEvent(task, taskContext, {
                        type: 'dast_browser_nav_filtered',
                        phase: 'attack_eval',
                        reason: 'duplicate_sink',
                        sinkKey: built.sinkKey
                    })
                    return null
                }
                return built
            }

            const sourceResult = await this._runBrowserNavSourceDrivers(task, taskContext, payload, {
                uiUrl,
                sourceDrivers,
                markerToken,
                checks,
                settleMs,
                cookieEncoding: typeof payload?.metadata?.browserSource === 'object'
                    ? payload.metadata.browserSource.cookieEncoding
                    : browserNavCfg.cookieEncoding
            })
            if (sourceResult?.domXss?.vulnerable) {
                const sourceAttacked = Object.assign({}, attacked || {}, {
                    location: 'browser_source',
                    name: sourceResult.sourceInfo?.key || sourceResult.sourceInfo?.driver || 'browser_source',
                    sourceDriver: sourceResult.sourceInfo?.driver || null,
                    sourceKey: sourceResult.sourceInfo?.key || null
                })
                const built = this._buildBrowserNavAttackResult(
                    task,
                    payload,
                    sourceResult.uiUrl,
                    sourceAttacked,
                    checks,
                    markerToken,
                    sourceResult.domXss,
                    'browser_source',
                    sourceResult.sourceInfo
                )
                if (built?.duplicate) {
                    this._appendTaskRuntimeEvent(task, taskContext, {
                        type: 'dast_browser_nav_filtered',
                        phase: 'attack_eval',
                        reason: 'duplicate_sink',
                        sinkKey: built.sinkKey
                    })
                    return null
                }
                return built
            }

            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_nav_filtered',
                phase: 'attack_eval',
                reason: 'no_vulnerability_match',
                checks: { dom_xss: !!domXss?.vulnerable },
                sourceDrivers
            })
            return null
        } catch (err) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_nav_filtered',
                phase: 'attack_eval',
                reason: 'execution_error',
                error: err?.message || String(err)
            })
            return null
        }
    }

    _normalizeBrowserWorkflowProtectedPaths(values = []) {
        const normalized = Array.from(new Set(
            (Array.isArray(values) ? values : [values])
                .map((value) => String(value || '').trim())
                .filter(Boolean)
        ))
        return normalized.length ? normalized : DAST_BROWSER_WORKFLOW_DEFAULT_PROTECTED_PATHS.slice()
    }

    _sanitizeBrowserWorkflowHeaders(headers = []) {
        const out = {}
        const skip = /^(?:host|content-length|cookie|origin|referer|connection|accept-encoding|transfer-encoding|proxy-.*|sec-.*)$/i
        for (const header of Array.isArray(headers) ? headers : []) {
            const name = String(header?.name || '').trim()
            if (!name || skip.test(name)) continue
            const value = header?.value
            if (value === undefined || value === null) continue
            out[name] = String(value)
        }
        return out
    }

    _serializeBrowserWorkflowRequest(request = null) {
        const url = String(request?.url || '').trim()
        if (!url) return null
        const method = String(request?.method || 'GET').toUpperCase()
        let body = null
        if (!['GET', 'HEAD'].includes(method)) {
            if (typeof request?.body?.text === 'string') {
                body = request.body.text
            } else if (request?.body?.json && typeof request.body.json === 'object') {
                try {
                    body = JSON.stringify(request.body.json)
                } catch (_) { }
            } else if (Array.isArray(request?.body?.params)) {
                body = ptk_request._isMultipartBody(request.body)
                    ? ptk_request.serializeMultipartParams(request.body.params, request.body.boundary)
                    : (
                        ptk_request._hasRawUrlencodedParams(request.body.params)
                            ? ptk_request.serializeUrlencodedParams(request.body.params)
                            : new URLSearchParams(
                                request.body.params.map((param) => [String(param?.name || ''), String(param?.value ?? '')])
                            ).toString()
                    )
            }
        }
        return {
            url,
            method,
            headers: this._sanitizeBrowserWorkflowHeaders(request?.headers),
            body
        }
    }

    _resolveBrowserWorkflowPageUrl(requestUrl, originalUiUrl = null) {
        const requestText = String(requestUrl || '').trim()
        if (!requestText) return null
        let requestResolved = null
        try {
            requestResolved = new URL(requestText)
        } catch (_) {
            return null
        }
        if (!/^https?:$/i.test(requestResolved.protocol || '')) return null

        const uiText = String(originalUiUrl || '').trim()
        if (uiText) {
            try {
                const uiResolved = new URL(uiText)
                if (uiResolved.origin === requestResolved.origin && /^https?:$/i.test(uiResolved.protocol || '')) {
                    return uiResolved.toString()
                }
            } catch (_) { }
        }

        return `${requestResolved.origin}/`
    }

    async _runBrowserWorkflowAttack(task, context, preparedPayload) {
        const payload = preparedPayload || task?.payload || {}
        const request = payload?.request || {}
        const originalUiUrl = request.ui_url || request.uiUrl || context?.original?.request?.ui_url || context?.original?.request?.uiUrl || null
        const serializedRequest = this._serializeBrowserWorkflowRequest(request)
        const taskContext = context || { original: { request: { url: serializedRequest?.url || null, ui_url: originalUiUrl || null, method: serializedRequest?.method || 'POST' } } }

        if (!serializedRequest?.url) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_workflow_filtered',
                phase: 'attack_eval',
                reason: 'missing_attack_request'
            })
            return null
        }

        if (['GET', 'HEAD'].includes(serializedRequest.method)) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_workflow_filtered',
                phase: 'attack_eval',
                reason: 'unsupported_method',
                attackMethod: serializedRequest.method
            })
            return null
        }

        const browserWorkflowCfg = this._taskAttackRuntimeConfig(task, 'browserWorkflow') || {}
        const flow = String(browserWorkflowCfg.flow || 'auth_2fa_bypass').trim().toLowerCase()
        if (flow !== 'auth_2fa_bypass') {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_workflow_filtered',
                phase: 'attack_eval',
                reason: 'unsupported_flow',
                flow
            })
            return null
        }

        const pageUrl = this._resolveBrowserWorkflowPageUrl(serializedRequest.url, originalUiUrl)
        if (!pageUrl) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_workflow_filtered',
                phase: 'attack_eval',
                reason: 'missing_ui_url'
            })
            return null
        }

        const settleMsRaw = Number(browserWorkflowCfg.settleMs)
        const settleMs = Number.isFinite(settleMsRaw)
            ? Math.max(0, Math.min(5000, Math.floor(settleMsRaw)))
            : DAST_BROWSER_WORKFLOW_DEFAULT_SETTLE_MS
        const protectedPaths = this._normalizeBrowserWorkflowProtectedPaths(browserWorkflowCfg.protectedPaths)
        const attacked = payload?.metadata?.attacked || null

        const runWorkflow = async () => this._withBrowserWorkflowAttackTab(pageUrl, async (tabId) => {
            const message = {
                type: 'browserWorkflowRun',
                flow,
                settleMs,
                request: serializedRequest,
                protectedPaths,
                challengeRegex: browserWorkflowCfg.challengeRegex || null,
                loggedOutRegex: browserWorkflowCfg.loggedOutRegex || null,
                loggedInRegex: browserWorkflowCfg.loggedInRegex || null
            }
            const sendRun = () => browser.tabs.sendMessage(tabId, message)
            const ready = await this._ensureBrowserWorkflowHarnessReady(tabId, task, taskContext)
            if (!ready) {
                return { error: 'harness_not_ready' }
            }
            try {
                return await sendRun()
            } catch (err) {
                const injected = await this._injectBrowserWorkflowHarness(tabId, task, taskContext, 'send_failed')
                if (!injected) throw err
                return sendRun()
            }
        })

        try {
            const res = await runWorkflow()
            if (res?.error) {
                this._appendTaskRuntimeEvent(task, taskContext, {
                    type: 'dast_browser_workflow_filtered',
                    phase: 'attack_eval',
                    reason: res.error
                })
                return null
            }
            if (!res?.challengeDetected) {
                this._appendTaskRuntimeEvent(task, taskContext, {
                    type: 'dast_browser_workflow_filtered',
                    phase: 'attack_eval',
                    reason: res?.reason || 'no_challenge_signal'
                })
                return null
            }
            const finding = res?.finding
            if (!finding) {
                this._appendTaskRuntimeEvent(task, taskContext, {
                    type: 'dast_browser_workflow_filtered',
                    phase: 'attack_eval',
                    reason: res?.reason || 'no_bypass_evidence'
                })
                return null
            }

            const metadata = Object.assign(
                {},
                this._attackMetadataView(task?.module, task?.attack),
                payload?.metadata || {},
                {
                    attacked,
                    flow,
                    runtimeMode: 'browser_workflow',
                    challengeDetected: true,
                    protectedPath: finding.path || null,
                    protectedUrl: finding.url || null,
                    baselineStatus: finding?.baseline?.status ?? null,
                    postLoginStatus: finding?.status ?? null,
                    challengeUrl: res?.loginResponse?.url || null
                }
            )
            const proof = JSON.stringify({
                flow,
                protectedPath: finding.path || null,
                protectedUrl: finding.url || null,
                baselineStatus: finding?.baseline?.status ?? null,
                postLoginStatus: finding?.status ?? null,
                challengeUrl: res?.loginResponse?.url || null,
                loginStatus: res?.loginResponse?.status ?? null
            })

            return {
                success: true,
                metadata,
                request: {
                    url: serializedRequest.url,
                    ui_url: pageUrl,
                    method: serializedRequest.method
                },
                response: {
                    statusCode: Number(finding?.status || 0) || null,
                    length: null
                },
                proof
            }
        } catch (err) {
            this._appendTaskRuntimeEvent(task, taskContext, {
                type: 'dast_browser_workflow_filtered',
                phase: 'attack_eval',
                reason: 'execution_error',
                error: err?.message || String(err)
            })
            return null
        }
    }

    async _runSpaAttack(task) {
        const payload = task?.payload || {}
        const uiUrl = payload.ui_url
        const checks = payload.checks || []
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
                const message = {
                    type: 'spaParamTest',
                    param: payload.param,
                    payload: payload.payload,
                    checks,
                    markerDomain: payload.markerDomain,
                    markerToken: payload.markerToken
                }
                const sendChecks = () => browser.tabs.sendMessage(tabId, message)

                const ready = await this._ensureSpaHarnessReady(tabId, task, taskContext)
                if (!ready) {
                    return null
                }

                try {
                    let result = await sendChecks()
                    if (this._spaResponseMissingChecks(result, checks)) {
                        const reinjected = await this._injectSpaHarness(
                            tabId,
                            task,
                            taskContext,
                            'missing_check_result'
                        )
                        if (reinjected) {
                            result = await sendChecks()
                        }
                    }
                    return result
                } catch (err) {
                    const injected = await this._injectSpaHarness(
                        tabId,
                        task,
                        taskContext,
                        'send_failed'
                    )
                    if (!injected) {
                        throw err
                    }
                    return sendChecks()
                }
            })
        }

        try {
            const res = await runChecks()
            if (this._spaResponseMissingChecks(res, checks)) {
                const missingChecks = checks.filter((checkName) => !Object.prototype.hasOwnProperty.call(res || {}, checkName))
                this._appendTaskRuntimeEvent(task, taskContext, {
                    type: 'dast_spa_filtered',
                    phase: 'attack_eval',
                    reason: 'harness_not_ready',
                    missingChecks
                })
                return null
            }
            let filteredReason = null
            let filteredDetails = null

            const pickDomXss = () => {
                const dx = res?.dom_xss
                if (!dx || !dx.vulnerable) return null
                const aggregateState = this._buildSpaRuntimeAggregateContext(task, {
                    uiUrl,
                    param: payload.param,
                    sinkKey: dx.sinkKey || null,
                    resultMetadata: {
                        checks: payload.checks,
                        executed: !!dx.executed,
                        reflected: !!dx.reflected,
                        context: dx.context || null
                    }
                })
                if (aggregateState.aggregateKey && this._isSpaAggregateKeyConfirmed(aggregateState.aggregateKey)) {
                    filteredReason = 'duplicate_aggregate'
                    filteredDetails = {
                        aggregateKey: aggregateState.aggregateKey,
                        sinkKey: dx.sinkKey || null
                    }
                    return null
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

            const pickSpaCsrf = () => {
                const t = res?.spa_csrf
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.candidates || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickSpaCors = () => {
                const t = res?.spa_cors
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.candidates || t.observed || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickPrototypePollution = () => {
                const t = res?.prototype_pollution
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
                } else if (chk === 'spa_csrf') {
                    const r = pickSpaCsrf()
                    if (r) return r
                } else if (chk === 'spa_cors') {
                    const r = pickSpaCors()
                    if (r) return r
                } else if (chk === 'prototype_pollution') {
                    const r = pickPrototypePollution()
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
        let childTabMeta = null
        try {
            const isFirefox = typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
            const markedUrl = this._addSpaDialogMarker(url)
            if (isFirefox) {
                const tab = await browser.tabs.create({ url: markedUrl, active: false })
                tabId = tab.id
                await this._markSpaAttackTab(tabId, { runAt: "document_start" })
            } else {
                const tab = await browser.tabs.create({ url: markedUrl, active: false })
                tabId = tab.id
            }
            await this._waitForTabReady(tabId)
            // Re-apply the marker on the loaded page before messaging the SPA
            // harness so recovery logic also
            // keeps this internal DAST tab alive while the attack runs.
            await this._markSpaAttackTab(tabId)
            childTabMeta = {
                tabId,
                url,
                parentTabId: this.tabId,
                role: 'dast_spa_attack_tab',
                marker: 'ptk_spa_attack_tab',
                sourceEngine: 'DAST'
            }
            await this._automationPtkTabOpened(childTabMeta)
            const res = await fn(tabId, url)
            return res
        } finally {
            if (tabId !== null) {
                await this._automationPtkTabClosing(childTabMeta || {
                    tabId,
                    url,
                    parentTabId: this.tabId,
                    role: 'dast_spa_attack_tab',
                    marker: 'ptk_spa_attack_tab',
                    sourceEngine: 'DAST'
                })
                await this._detachDialogAutoDismiss(tabId)
                try { await browser.tabs.remove(tabId) } catch (_) { }
            }
        }
    }

    async _withBrowserNavAttackTab(url, fn) {
        let tabId = null
        let childTabMeta = null
        try {
            await this._ensureBrowserNavHarnessScript().catch(() => false)
            const tab = await browser.tabs.create({ url: 'about:blank', active: false })
            tabId = tab.id
            await this._markSpaAttackTab(tabId, {
                marker: DAST_BROWSER_NAV_TAB_MARKER,
                runAt: 'document_start'
            })
            await browser.tabs.update(tabId, { url })
            await this._waitForTabReady(tabId)
            // Chromium can lose the pre-navigation marker that was set on about:blank.
            // Re-apply it on the real target page before the harness ping so the content
            // script can identify the page as a browser-nav attack tab.
            await this._markSpaAttackTab(tabId, {
                marker: DAST_BROWSER_NAV_TAB_MARKER,
                domOnly: true
            })
            childTabMeta = {
                tabId,
                url,
                parentTabId: this.tabId,
                role: 'dast_browser_nav_attack_tab',
                marker: DAST_BROWSER_NAV_TAB_MARKER,
                sourceEngine: 'DAST'
            }
            await this._automationPtkTabOpened(childTabMeta)
            return await fn(tabId, url)
        } finally {
            if (tabId !== null) {
                await this._automationPtkTabClosing(childTabMeta || {
                    tabId,
                    url,
                    parentTabId: this.tabId,
                    role: 'dast_browser_nav_attack_tab',
                    marker: DAST_BROWSER_NAV_TAB_MARKER,
                    sourceEngine: 'DAST'
                })
                try { await browser.tabs.remove(tabId) } catch (_) { }
            }
        }
    }

    _browserWorkflowHarnessFile() {
        return !this._isFirefoxRuntime()
            ? 'ptk/content/auth_workflow_harness.js'
            : 'content/auth_workflow_harness.js'
    }

    async _ensureBrowserWorkflowHarnessScript() {
        if (this._browserWorkflowHarnessRegistered) return true
        if (!browser?.scripting?.registerContentScripts) {
            return false
        }
        try {
            if (browser?.scripting?.unregisterContentScripts) {
                await browser.scripting.unregisterContentScripts({
                    ids: [DAST_BROWSER_WORKFLOW_HARNESS_SCRIPT_ID]
                }).catch(() => {})
            }
            await browser.scripting.registerContentScripts([{
                id: DAST_BROWSER_WORKFLOW_HARNESS_SCRIPT_ID,
                js: [this._browserWorkflowHarnessFile()],
                matches: ['<all_urls>'],
                runAt: 'document_start'
            }])
            this._browserWorkflowHarnessRegistered = true
            return true
        } catch (err) {
            console.warn('[PTK DAST] Failed to register browser-workflow harness', err)
            this._browserWorkflowHarnessRegistered = false
            return false
        }
    }

    async _unregisterBrowserWorkflowHarnessScript() {
        this._browserWorkflowHarnessRegistered = false
        if (!browser?.scripting?.unregisterContentScripts) return
        try {
            await browser.scripting.unregisterContentScripts({
                ids: [DAST_BROWSER_WORKFLOW_HARNESS_SCRIPT_ID]
            })
        } catch (_) { }
    }

    async _injectBrowserWorkflowHarness(tabId, task, taskContext, reason = 'send_failed') {
        let lastError = null

        if (browser?.scripting?.executeScript) {
            try {
                await browser.scripting.executeScript({
                    target: { tabId },
                    files: ['ptk/content/auth_workflow_harness.js']
                })
                await new Promise((resolve) => setTimeout(resolve, 75))
                return true
            } catch (err) {
                lastError = err
            }
        }

        if (browser?.tabs?.executeScript) {
            try {
                await browser.tabs.executeScript(tabId, {
                    file: 'ptk/content/auth_workflow_harness.js',
                    runAt: 'document_idle'
                })
                await new Promise((resolve) => setTimeout(resolve, 75))
                return true
            } catch (err) {
                lastError = err
            }
        }

        this._appendTaskRuntimeEvent(task, taskContext, {
            type: 'dast_browser_workflow_filtered',
            phase: 'harness_bootstrap',
            reason: 'inject_failed',
            bootstrapReason: reason,
            error: lastError?.message || String(lastError || 'inject_failed')
        })
        return false
    }

    async _ensureBrowserWorkflowHarnessReady(tabId, task, taskContext) {
        try {
            const ping = await browser.tabs.sendMessage(tabId, { type: 'browserWorkflowPing' })
            if (ping?.ok === true && ping?.active === true) {
                return true
            }
        } catch (_) { }

        const injected = await this._injectBrowserWorkflowHarness(tabId, task, taskContext, 'preflight_ping')
        if (!injected) return false

        try {
            const ping = await browser.tabs.sendMessage(tabId, { type: 'browserWorkflowPing' })
            if (ping?.ok === true && ping?.active === true) {
                return true
            }
        } catch (_) { }

        this._appendTaskRuntimeEvent(task, taskContext, {
            type: 'dast_browser_workflow_filtered',
            phase: 'harness_bootstrap',
            reason: 'ping_failed'
        })
        return false
    }

    async _withBrowserWorkflowAttackTab(url, fn) {
        let tabId = null
        let childTabMeta = null
        try {
            await this._ensureBrowserWorkflowHarnessScript().catch(() => false)
            const tab = await browser.tabs.create({ url: 'about:blank', active: false })
            tabId = tab.id
            await this._markSpaAttackTab(tabId, {
                marker: DAST_BROWSER_WORKFLOW_TAB_MARKER,
                runAt: 'document_start'
            })
            await browser.tabs.update(tabId, { url })
            await this._waitForTabReady(tabId)
            await this._markSpaAttackTab(tabId, {
                marker: DAST_BROWSER_WORKFLOW_TAB_MARKER
            })
            childTabMeta = {
                tabId,
                url,
                parentTabId: this.tabId,
                role: 'dast_browser_workflow_attack_tab',
                marker: DAST_BROWSER_WORKFLOW_TAB_MARKER,
                sourceEngine: 'DAST'
            }
            await this._automationPtkTabOpened(childTabMeta)
            return await fn(tabId, url)
        } finally {
            if (tabId !== null) {
                await this._automationPtkTabClosing(childTabMeta || {
                    tabId,
                    url,
                    parentTabId: this.tabId,
                    role: 'dast_browser_workflow_attack_tab',
                    marker: DAST_BROWSER_WORKFLOW_TAB_MARKER,
                    sourceEngine: 'DAST'
                })
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
        const marker = opts.marker || 'ptk_spa_attack_tab'
        const runAt = opts.runAt || "document_start"
        const domOnly = opts.domOnly === true
        const code = (name, markDomOnly) => {
            try {
                const attrName = name === 'ptk_browser_nav_attack_tab'
                    ? 'data-ptk-browser-nav-attack-tab'
                    : 'data-ptk-spa-attack-tab'
                const root = document.documentElement || document.body
                if (root && typeof root.setAttribute === 'function') {
                    root.setAttribute(attrName, '1')
                }
                if (markDomOnly) return
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
                    args: [marker, domOnly]
                })
                return
            } catch (_) { }
        }
        if (browser?.tabs?.executeScript) {
            try {
                await browser.tabs.executeScript(tabId, {
                    code: `try{var n=${JSON.stringify(marker)};var d=${JSON.stringify(domOnly)};var a=n==='ptk_browser_nav_attack_tab'?'data-ptk-browser-nav-attack-tab':'data-ptk-spa-attack-tab';var r=document.documentElement||document.body;if(r&&r.setAttribute){r.setAttribute(a,'1')}if(!d){if(!window.name||window.name.indexOf(n)===-1){window.name=(window.name?window.name+' ':'')+n;}}}catch(_){}`,
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
        while (this.isRunning && (this._requestQueue.size() || this._pendingHtmlLinkDiscoveryCount())) {
            if (!this._requestQueue.size()) {
                if (!this._drainPendingHtmlDiscoveryQueue()) break
                continue
            }
            const raw = this._requestQueue.dequeue()
            try {
                const plan = await this.buildAttackPlan(raw)
                if (plan) {
                    this._enqueuePlan(plan)
                }
                if (!this._requestQueue.size()) {
                    this._drainPendingHtmlDiscoveryQueue()
                }
                if (!this.isRunning) break
            } catch (err) {
                console.warn('Failed to build attack plan', err)
            }
        }
    }

    _taskAttackRuntimeConfig(task, key) {
        const runtime = task?.attack?.runtime
        if (!runtime || typeof runtime !== 'object') return null
        const config = runtime.config
        if (!config || typeof config !== 'object') return null
        if (!key) return config
        const section = config[key]
        return section && typeof section === 'object' ? section : null
    }

    async _listSessionProfilesForHost(host) {
        const normalizedHost = String(host || "").trim()
        if (!normalizedHost) return []
        try {
            if (this.sessionProfileStore?.listProfiles) {
                const profiles = await this.sessionProfileStore.listProfiles({
                    host: normalizedHost,
                    includeSnapshot: true
                })
                return Array.isArray(profiles) ? profiles : []
            }
            if (typeof this.settings?.listSessionProfilesForHost === "function") {
                const profiles = await this.settings.listSessionProfilesForHost(normalizedHost)
                return Array.isArray(profiles) ? cloneValue(profiles) : []
            }
        } catch (err) {
            console.warn("[PTK DAST] Failed to list session profiles for host", {
                host: normalizedHost,
                error: err?.message || String(err)
            })
        }
        return []
    }

    _requestHostValue(value) {
        const raw = String(value || "").trim()
        if (!raw) return null
        try {
            return new URL(raw).host || null
        } catch (_) {
            return null
        }
    }

    _resolveTaskHost(task, context, payload = null) {
        return this._requestHostValue(payload?.request?.url)
            || this._requestHostValue(context?.original?.request?.url)
            || this._requestHostValue(payload?.request?.ui_url)
            || this._requestHostValue(context?.original?.request?.ui_url)
            || null
    }

    _cloneSessionCookiesFromProfile(profile = null) {
        const cookies = Array.isArray(profile?.snapshot?.cookies) ? profile.snapshot.cookies : []
        return cookies.map((cookie) => ({
            name: cookie?.name || "",
            value: cookie?.value || "",
            domain: cookie?.domain || "",
            path: cookie?.path || "/",
            secure: cookie?.secure === true,
            httpOnly: cookie?.httpOnly === true,
            sameSite: cookie?.sameSite || "no_restriction"
        }))
    }

    _applySessionProfileToPayload(payload = null, profile = null) {
        const next = cloneValue(payload || {})
        if (!next.request || typeof next.request !== "object") {
            next.request = {}
        }
        next.opts = next.opts || {}
        next.metadata = next.metadata || {}
        const cookies = this._cloneSessionCookiesFromProfile(profile)
        next.request.cookies = cookies
        const cookieHeaderValue = cookies
            .filter((cookie) => cookie?.name)
            .map((cookie) => `${cookie.name}=${cookie.value || ""}`)
            .join("; ")
        const headers = Array.isArray(next.request.headers) ? next.request.headers.slice() : []
        const filteredHeaders = headers.filter(
            (header) => String(header?.name || "").toLowerCase() !== "cookie"
        )
        if (cookieHeaderValue) {
            filteredHeaders.push({
                name: "Cookie",
                value: cookieHeaderValue
            })
        }
        next.request.headers = filteredHeaders
        next.opts.strict_cookie_override = true
        next.metadata.sessionProfile = {
            id: profile?.id || null,
            label: profile?.label || "session"
        }
        return next
    }

    _normalizeComparableResponseForDiff(result = null) {
        return {
            status: Number(result?.response?.statusCode) || 0,
            headers: Array.isArray(result?.response?.headers)
                ? result.response.headers.map((header) => ({
                    name: header?.name || "",
                    value: header?.value || ""
                }))
                : [],
            body: String(result?.response?.body || "")
        }
    }

    _deriveObjectSwapFromPayload(original = null, payload = null) {
        const mutation = Array.isArray(payload?.metadata?.mutations) ? payload.metadata.mutations[0] : null
        if (!mutation) return null
        return {
            applied: true,
            targetParam: mutation?.name || payload?.metadata?.attacked?.name || null,
            originalValue: mutation?.before ?? null,
            swappedValue: mutation?.after ?? null,
            location: mutation?.location || payload?.metadata?.attacked?.location || null,
            originalUrl: original?.request?.url || null
        }
    }

    _isMultiIdentityAttackTask(task) {
        const requiredCaps = this._moduleRequiredEngineCapabilities(task?.module)
        const moduleId = String(task?.moduleId || task?.module?.id || "").trim().toLowerCase()
        return requiredCaps.includes("multi_identity") || moduleId === "access_control_multi_identity"
    }

    _isWebSocketAttackTask(task) {
        const requiredCaps = this._moduleRequiredEngineCapabilities(task?.module)
        const moduleId = String(task?.moduleId || task?.module?.id || "").trim().toLowerCase()
        return requiredCaps.includes("websocket_handshake")
            || requiredCaps.includes("websocket_frames")
            || moduleId === "websocket_handshake_security"
            || moduleId === "websocket_frames_security"
            || moduleId === "graphql_realtime_upload"
    }

    _stripUrlFragment(url) {
        const raw = String(url || "").trim()
        if (!raw) return null
        try {
            const resolved = new URL(raw)
            resolved.hash = ""
            return resolved.toString()
        } catch (_) {
            return raw.split("#")[0] || raw
        }
    }

    _resolveWebSocketAttackUrl(task, context, payload = null) {
        const rawUrl = payload?.request?.url
            || context?.original?.request?.url
            || payload?.request?.ui_url
            || context?.original?.request?.ui_url
            || null
        if (!rawUrl) return null
        try {
            const resolved = new URL(rawUrl)
            if (resolved.protocol === "ws:" || resolved.protocol === "wss:") {
                resolved.hash = ""
                return resolved.toString()
            }
            if (!["http:", "https:"].includes(resolved.protocol)) return null
            resolved.protocol = resolved.protocol === "https:" ? "wss:" : "ws:"
            if (resolved.searchParams.get("transport") === "polling") {
                resolved.searchParams.set("transport", "websocket")
            }
            resolved.hash = ""
            return resolved.toString()
        } catch (_) {
            return null
        }
    }

    _extractWebSocketProtocols(payload = null) {
        const headerValue = Array.isArray(payload?.request?.headers)
            ? payload.request.headers.find(
                (header) => String(header?.name || "").toLowerCase() === "sec-websocket-protocol"
            )?.value
            : null
        if (!headerValue) return []
        return String(headerValue)
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean)
    }

    _resolveWebSocketFramePayload(task, context, payload = null) {
        const requiredCaps = this._moduleRequiredEngineCapabilities(task?.module)
        const frameMode = requiredCaps.includes("websocket_frames")
        if (!frameMode) return null
        const bodyText = payload?.request?.body?.text
        if (typeof bodyText === "string" && bodyText.length) {
            return bodyText
        }
        if (payload?.request?.body?.json && typeof payload.request.body.json === "object") {
            try {
                return JSON.stringify(payload.request.body.json)
            } catch (_) { }
        }
        const originalBody = context?.original?.request?.body?.text
        if (typeof originalBody === "string" && originalBody.length) {
            return originalBody
        }
        return null
    }

    _collectWebSocketTouchedHeaderNames(task, payload = null) {
        const touched = new Set()
        for (const header of (task?.attack?.action?.headers || [])) {
            const name = String(header?.name || "").trim().toLowerCase()
            if (name) touched.add(name)
        }
        if ((task?.attack?.action?.cookies || []).length) {
            touched.add("cookie")
        }
        if (Array.isArray(payload?.request?.headers)) {
            for (const header of payload.request.headers) {
                const name = String(header?.name || "").trim().toLowerCase()
                if (name === "cookie") touched.add(name)
            }
        }
        return touched
    }

    _mergeWebSocketHeaders(liveHeaders = [], desiredHeaders = [], task = null, payload = null) {
        const touchedNames = this._collectWebSocketTouchedHeaderNames(task, payload)
        const baseHeaders = Array.isArray(liveHeaders)
            ? liveHeaders.filter((header) => header?.name).map((header) => ({
                name: header.name,
                value: header.value
            }))
            : []
        const merged = baseHeaders.filter(
            (header) => !touchedNames.has(String(header?.name || "").toLowerCase())
        )
        const desired = Array.isArray(desiredHeaders) ? desiredHeaders : []
        for (const header of desired) {
            const name = String(header?.name || "").trim()
            if (!name) continue
            const lower = name.toLowerCase()
            if (touchedNames.has(lower)) {
                merged.push({ name, value: String(header?.value ?? "") })
            }
        }
        return merged
    }

    _serializeWebSocketData(value) {
        try {
            if (typeof value === "string") return value.slice(0, 2048)
            if (value instanceof ArrayBuffer) {
                return `[arraybuffer:${value.byteLength}]`
            }
            if (ArrayBuffer.isView(value)) {
                return `[typedarray:${value.byteLength}]`
            }
            if (typeof Blob !== "undefined" && value instanceof Blob) {
                return `[blob:${value.size}]`
            }
            return String(value ?? "").slice(0, 2048)
        } catch (_) {
            return "[unserializable_websocket_data]"
        }
    }

    async _executeWebSocketTransport({
        url = null,
        protocols = [],
        desiredHeaders = [],
        task = null,
        payload = null,
        sendPayload = null,
        timeoutMs = 2500
    } = {}) {
        const targetUrl = this._stripUrlFragment(url)
        if (!targetUrl || !this._supportsWebSocketTransport()) {
            return null
        }
        return await new Promise((resolve) => {
            let done = false
            let socket = null
            let timeoutId = null
            let idleCloseId = null
            const state = {
                url: targetUrl,
                opened: false,
                closed: false,
                closeCode: null,
                closeReason: null,
                cleanClose: null,
                error: null,
                requestHeaders: [],
                responseHeaders: [],
                statusCode: null,
                statusLine: null,
                messages: [],
                sentPayload: sendPayload == null ? null : this._serializeWebSocketData(sendPayload)
            }

            const cleanup = () => {
                try { browser.webRequest.onBeforeSendHeaders.removeListener(onBeforeSendHeaders) } catch (_) { }
                try { browser.webRequest.onHeadersReceived.removeListener(onHeadersReceived) } catch (_) { }
                clearTimeout(timeoutId)
                clearTimeout(idleCloseId)
                try {
                    if (socket && socket.readyState === globalThis.WebSocket.OPEN) {
                        socket.close(1000, "ptk-dast-websocket-complete")
                    }
                } catch (_) { }
            }

            const finish = () => {
                if (done) return
                done = true
                cleanup()
                resolve(state)
            }

            const scheduleIdleClose = (delayMs = 175) => {
                clearTimeout(idleCloseId)
                idleCloseId = setTimeout(() => {
                    try {
                        if (socket && socket.readyState === globalThis.WebSocket.OPEN) {
                            socket.close(1000, "ptk-dast-websocket-idle")
                        }
                    } catch (_) { }
                    setTimeout(finish, 25)
                }, delayMs)
            }

            const onBeforeSendHeaders = (request) => {
                if (request?.type !== "websocket") return undefined
                if (this._stripUrlFragment(request?.url) !== targetUrl) return undefined
                const nextHeaders = this._mergeWebSocketHeaders(
                    request?.requestHeaders || [],
                    desiredHeaders,
                    task,
                    payload
                )
                state.requestHeaders = cloneValue(nextHeaders)
                return { requestHeaders: nextHeaders }
            }

            const onHeadersReceived = (response) => {
                if (response?.type !== "websocket") return undefined
                if (this._stripUrlFragment(response?.url) !== targetUrl) return undefined
                state.responseHeaders = cloneValue(response?.responseHeaders || [])
                state.statusLine = response?.statusLine || null
                if (Number.isFinite(Number(response?.statusCode))) {
                    state.statusCode = Number(response.statusCode)
                }
                return undefined
            }

            const blocking = this._isFirefoxRuntime() ? ["blocking"] : []
            browser.webRequest.onBeforeSendHeaders.addListener(
                onBeforeSendHeaders,
                { urls: ["<all_urls>"], types: ["websocket"] },
                ["requestHeaders"].concat(ptk_utils.extraInfoSpec).concat(blocking)
            )
            browser.webRequest.onHeadersReceived.addListener(
                onHeadersReceived,
                { urls: ["<all_urls>"], types: ["websocket"] },
                ["responseHeaders"].concat(ptk_utils.extraInfoSpec).concat(blocking)
            )

            timeoutId = setTimeout(() => finish(), Math.max(250, Number(timeoutMs) || 2500))

            try {
                socket = Array.isArray(protocols) && protocols.length
                    ? new globalThis.WebSocket(targetUrl, protocols)
                    : new globalThis.WebSocket(targetUrl)
            } catch (err) {
                state.error = err?.message || String(err)
                finish()
                return
            }

            socket.addEventListener("open", () => {
                state.opened = true
                if (state.statusCode == null) {
                    state.statusCode = 101
                    state.statusLine = state.statusLine || "HTTP/1.1 101 Switching Protocols"
                }
                if (sendPayload != null) {
                    try {
                        socket.send(sendPayload)
                    } catch (err) {
                        state.error = err?.message || String(err)
                    }
                }
                scheduleIdleClose(sendPayload == null ? 125 : 250)
            })

            socket.addEventListener("message", (event) => {
                state.messages.push(this._serializeWebSocketData(event?.data))
                scheduleIdleClose(125)
            })

            socket.addEventListener("error", (event) => {
                if (!state.error) {
                    state.error = event?.message || "websocket_error"
                }
            })

            socket.addEventListener("close", (event) => {
                state.closed = true
                state.closeCode = Number(event?.code) || null
                state.closeReason = event?.reason || null
                state.cleanClose = event?.wasClean === true
                setTimeout(finish, 25)
            })
        })
    }

    _buildWebSocketAttackResult(task, context, payload = null, transport = null) {
        if (!transport) return null
        const requiredCaps = this._moduleRequiredEngineCapabilities(task?.module)
        const frameMode = requiredCaps.includes("websocket_frames")
        let statusCode = Number(transport?.statusCode)
        if (!Number.isFinite(statusCode)) statusCode = null
        if (frameMode) {
            if (transport?.messages?.length) {
                statusCode = 200
            } else if (transport?.opened && !transport?.error) {
                statusCode = 204
            }
        } else if (transport?.opened && statusCode == null) {
            statusCode = 101
        }
        const bodyParts = []
        if (Array.isArray(transport?.messages) && transport.messages.length) {
            bodyParts.push(transport.messages.join("\n"))
        }
        if (transport?.error) {
            bodyParts.push(String(transport.error))
        }
        if (transport?.closeReason) {
            bodyParts.push(String(transport.closeReason))
        }
        const responseBody = bodyParts.join("\n")
        const metadata = Object.assign({}, this._attackMetadataView(task?.module, task?.attack), payload?.metadata || {}, {
            attacked: payload?.metadata?.attacked || null,
            websocket: {
                url: transport?.url || null,
                opened: transport?.opened === true,
                closeCode: transport?.closeCode || null,
                cleanClose: transport?.cleanClose === true,
                messageCount: Array.isArray(transport?.messages) ? transport.messages.length : 0
            }
        })
        return {
            success: transport?.opened === true || (frameMode && Array.isArray(transport?.messages) && transport.messages.length > 0),
            metadata,
            request: {
                url: transport?.url || payload?.request?.url || context?.original?.request?.url || null,
                method: "GET",
                headers: cloneValue(transport?.requestHeaders || [])
            },
            response: {
                statusCode,
                statusLine: transport?.statusLine || (statusCode == null ? null : `WS ${statusCode}`),
                headers: cloneValue(transport?.responseHeaders || []),
                body: responseBody,
                websocket: {
                    opened: transport?.opened === true,
                    closeCode: transport?.closeCode || null,
                    closeReason: transport?.closeReason || null,
                    cleanClose: transport?.cleanClose === true,
                    messages: cloneValue(transport?.messages || [])
                }
            },
            proof: JSON.stringify({
                url: transport?.url || null,
                opened: transport?.opened === true,
                statusCode,
                closeCode: transport?.closeCode || null,
                error: transport?.error || null,
                messages: transport?.messages || []
            })
        }
    }

    async _runWebSocketAttack(task, context, preparedPayload) {
        const targetUrl = this._resolveWebSocketAttackUrl(task, context, preparedPayload)
        if (!targetUrl) {
            this._appendTaskRuntimeEvent(task, context, {
                type: "dast_attack_skipped",
                phase: "transport",
                reason: "websocket_target_unresolvable"
            })
            return null
        }
        const transport = await this._executeWebSocketTransport({
            url: targetUrl,
            protocols: this._extractWebSocketProtocols(preparedPayload),
            desiredHeaders: Array.isArray(preparedPayload?.request?.headers)
                ? preparedPayload.request.headers
                : [],
            task,
            payload: preparedPayload,
            sendPayload: this._resolveWebSocketFramePayload(task, context, preparedPayload),
            timeoutMs: preparedPayload?.opts?.requestTimeoutMs || 2500
        })
        return this._buildWebSocketAttackResult(task, context, preparedPayload, transport)
    }

    async _runMultiIdentityAttack(task, context, preparedPayload) {
        const host = this._resolveTaskHost(task, context, preparedPayload)
        const profiles = await this._listSessionProfilesForHost(host)
        const usableProfiles = profiles
            .filter((profile) => Array.isArray(profile?.snapshot?.cookies) && profile.snapshot.cookies.length > 0)
            .sort((left, right) => String(left?.label || "").localeCompare(String(right?.label || "")))
        if (usableProfiles.length < 2) {
            this._appendTaskRuntimeEvent(task, context, {
                type: "dast_attack_skipped",
                phase: "transport",
                reason: "multi_identity_profiles_unavailable",
                host: host || null
            })
            return null
        }

        const baselineProfile = usableProfiles[0]
        const comparisonProfile = usableProfiles[1]
        const baselinePayload = this._applySessionProfileToPayload(preparedPayload, baselineProfile)
        const comparisonPayload = this._applySessionProfileToPayload(preparedPayload, comparisonProfile)
        const [baselineResponse, comparisonResponse] = await Promise.all([
            this.activeAttack(baselinePayload),
            this.activeAttack(comparisonPayload)
        ])

        if (!this._hasRealHttpResponse(baselineResponse?.response) || !this._hasRealHttpResponse(comparisonResponse?.response)) {
            return {
                success: false,
                metadata: Object.assign({}, this._attackMetadataView(task?.module, task?.attack), preparedPayload?.metadata || {}),
                request: comparisonResponse?.request || comparisonPayload?.request || preparedPayload?.request || null,
                response: comparisonResponse?.response || null,
                proof: JSON.stringify({
                    baselineStatus: baselineResponse?.response?.statusCode || null,
                    comparisonStatus: comparisonResponse?.response?.statusCode || null
                })
            }
        }

        const objectSwap = this._deriveObjectSwapFromPayload(context?.original, preparedPayload)
        const diff = this.authzDiffService.evaluate({
            request: {
                method: preparedPayload?.request?.method || context?.original?.request?.method || "GET",
                url: preparedPayload?.request?.url || context?.original?.request?.url || null
            },
            baseline: {
                session: {
                    id: baselineProfile?.id || null,
                    label: baselineProfile?.label || "baseline",
                    relation: "baseline"
                },
                response: this._normalizeComparableResponseForDiff(baselineResponse)
            },
            comparison: {
                session: {
                    id: comparisonProfile?.id || null,
                    label: comparisonProfile?.label || "comparison",
                    relation: "comparison"
                },
                response: this._normalizeComparableResponseForDiff(comparisonResponse)
            },
            objectSwap
        })
        const category = String(diff?.result?.category || "NO_DIFFERENCE")
        const success = diff?.result?.meaningfulDifference === true && category !== "NO_DIFFERENCE" && category !== "RESPONSE_DRIFT"
        return {
            success,
            metadata: Object.assign({}, this._attackMetadataView(task?.module, task?.attack), comparisonResponse?.metadata || {}, {
                attacked: preparedPayload?.metadata?.attacked || null,
                diffSignals: diff?.responseDiff?.indicators || null,
                multiIdentity: {
                    baselineSession: baselineProfile?.label || "baseline",
                    comparisonSession: comparisonProfile?.label || "comparison",
                    category,
                    confidence: diff?.result?.confidence || null
                }
            }),
            request: comparisonResponse?.request || comparisonPayload?.request || preparedPayload?.request || null,
            response: Object.assign({}, comparisonResponse?.response || {}, {
                authzDiff: diff
            }),
            proof: JSON.stringify(diff)
        }
    }

    async _executeH2FetchTransport(schema = null) {
        if (!this._supportsH2ObservationTransport()) {
            return null
        }
        const requestUrl = String(schema?.request?.url || "").trim()
        if (!requestUrl) return null
        let resolved
        try {
            resolved = new URL(requestUrl)
        } catch (_) {
            return null
        }
        if (resolved.protocol !== "https:") {
            return null
        }

        const requestHeaders = Array.isArray(schema?.request?.headers)
            ? schema.request.headers
                .filter((header) => header?.name)
                .reduce((acc, header) => {
                    acc[String(header.name)] = String(header?.value ?? "")
                    return acc
                }, {})
            : {}
        const requestBody = (() => {
            if (typeof schema?.request?.body?.text === "string") {
                return schema.request.body.text
            }
            if (schema?.request?.body?.json && typeof schema.request.body.json === "object") {
                try {
                    return JSON.stringify(schema.request.body.json)
                } catch (_) {
                    return null
                }
            }
            return null
        })()

        let tabId = null
        let protocol = null
        let statusCode = null
        let responseHeaders = []
        let statusLine = null
        const onEvent = (source, method, params) => {
            if (!source?.tabId || source.tabId !== tabId) return
            if (method !== "Network.responseReceived") return
            if (String(params?.response?.url || "") !== requestUrl) return
            protocol = String(params?.response?.protocol || "").toLowerCase() || null
            statusCode = Number(params?.response?.status) || null
            responseHeaders = Object.entries(params?.response?.headers || {}).map(([name, value]) => ({
                name,
                value: String(value ?? "")
            }))
            statusLine = params?.response?.statusText
                ? `${String(protocol || "HTTP/2").toUpperCase()} ${statusCode} ${params.response.statusText}`
                : `${String(protocol || "HTTP/2").toUpperCase()} ${statusCode || ""}`.trim()
        }

        try {
            const tab = await browser.tabs.create({ url: "about:blank", active: false })
            tabId = tab?.id
            if (!tabId) return null
            await browser.debugger.attach({ tabId }, "1.3")
            await browser.debugger.sendCommand({ tabId }, "Network.enable")
            browser.debugger.onEvent.addListener(onEvent)

            const [execution] = await browser.scripting.executeScript({
                target: { tabId },
                func: async (payload) => {
                    const response = await fetch(payload.url, {
                        method: payload.method,
                        headers: payload.headers,
                        body: payload.body,
                        credentials: payload.credentials,
                        redirect: payload.followRedirect ? "follow" : "manual",
                        cache: "no-cache"
                    })
                    const bodyText = await response.text()
                    return {
                        status: response.status,
                        statusText: response.statusText || "",
                        headers: Array.from(response.headers.entries()).map(([name, value]) => ({ name, value })),
                        body: bodyText
                    }
                },
                args: [{
                    url: requestUrl,
                    method: schema?.request?.method || "GET",
                    headers: requestHeaders,
                    body: requestBody,
                    credentials: schema?.opts?.credentials || "include",
                    followRedirect: schema?.opts?.follow_redirect !== false
                }]
            })
            const fetchResult = execution?.result || null
            return {
                protocol,
                success: /(^|\/)h2$/i.test(String(protocol || "")) || /^http\/2/i.test(String(protocol || "")),
                request: {
                    url: requestUrl,
                    method: schema?.request?.method || "GET",
                    headers: cloneValue(schema?.request?.headers || [])
                },
                response: {
                    statusCode: Number(fetchResult?.status) || statusCode || null,
                    statusLine: statusLine || null,
                    headers: responseHeaders.length ? responseHeaders : cloneValue(fetchResult?.headers || []),
                    body: String(fetchResult?.body || "")
                }
            }
        } catch (err) {
            return {
                protocol,
                success: false,
                request: {
                    url: requestUrl,
                    method: schema?.request?.method || "GET",
                    headers: cloneValue(schema?.request?.headers || [])
                },
                response: {
                    statusCode,
                    statusLine: err?.message || "h2_transport_failed",
                    headers: responseHeaders,
                    body: ""
                },
                error: err?.message || String(err)
            }
        } finally {
            if (browser?.debugger?.onEvent?.hasListener?.(onEvent)) {
                browser.debugger.onEvent.removeListener(onEvent)
            } else {
                try { browser.debugger.onEvent.removeListener(onEvent) } catch (_) { }
            }
            if (tabId) {
                try { await browser.debugger.detach({ tabId }) } catch (_) { }
                try { await browser.tabs.remove(tabId) } catch (_) { }
            }
        }
    }

    async _runSmugglingH2Attack(task, context, preparedPayload) {
        const executed = await this._executeH2FetchTransport(preparedPayload)
        if (!executed) {
            this._appendTaskRuntimeEvent(task, context, {
                type: "dast_attack_skipped",
                phase: "transport",
                reason: "h2_transport_unavailable"
            })
            return null
        }
        return {
            success: executed.success === true,
            metadata: Object.assign({}, this._attackMetadataView(task?.module, task?.attack), preparedPayload?.metadata || {}, {
                h2: {
                    protocol: executed.protocol || null
                }
            }),
            request: executed.request,
            response: Object.assign({}, executed.response, {
                transportProtocol: executed.protocol || null
            }),
            proof: JSON.stringify({
                protocol: executed.protocol || null,
                statusCode: executed?.response?.statusCode || null,
                error: executed?.error || null
            })
        }
    }

    _shouldUseSmugglingH1Transport(task, payload = null) {
        const moduleId = String(task?.moduleId || task?.module?.id || payload?.metadata?.moduleId || '').toLowerCase()
        if (moduleId === 'request_smuggling_h1') return true
        const requiredCaps = this._moduleRequiredEngineCapabilities(task?.module)
        return requiredCaps.includes('smuggling_h1')
    }

    _shouldUseSmugglingH2Transport(task, payload = null) {
        const moduleId = String(task?.moduleId || task?.module?.id || payload?.metadata?.moduleId || '').toLowerCase()
        if (moduleId === 'request_smuggling_h2') return true
        const requiredCaps = this._moduleRequiredEngineCapabilities(task?.module)
        return requiredCaps.includes('smuggling_h2')
    }

    _prepareActiveTaskPayload(task, payload) {
        const next = cloneValue(payload || {})
        next.opts = next.opts || {}
        next.metadata = next.metadata || {}
        if (this._shouldUseSmugglingH1Transport(task, next)) {
            next.opts.transport_mode = 'smuggling_h1'
        } else if (this._shouldUseSmugglingH2Transport(task, next)) {
            next.opts.transport_mode = 'smuggling_h2'
        }
        const raceCfg = this._taskAttackRuntimeConfig(task, 'race')
        if (raceCfg) {
            next.metadata.race = cloneValue(raceCfg)
        }
        return next
    }

    _isLikelyRaceBurstAccepted(response, original) {
        if (!this._hasRealHttpResponse(response?.response)) return false
        const status = Number(response?.response?.statusCode)
        if (!Number.isFinite(status) || ![200, 201, 202, 204, 302].includes(status)) {
            return false
        }
        const body = String(response?.response?.body || '')
        if (/(duplicate|replay|nonce|already\\s*processed|idempotent|invalid\\s*sequence|rate\\s*limit|too\\s*many\\s*requests|forbidden|unauthorized|csrf)/i.test(body)) {
            return false
        }
        if (status === 204) return true
        if (/(\b(ok|ack|success|processed|updated|created|accepted|applied|order|basket|payment|balance|result)\b|"(ok|ack|success|processed|updated|created|accepted|result|status|order|basket|payment|balance)"\s*:)/i.test(body)) {
            return true
        }
        const originalStatus = Number(original?.response?.statusCode)
        const originalBody = String(original?.response?.body || '')
        return status !== originalStatus || (body.length > 0 && body !== originalBody)
    }

    async _runRaceBurstAttack(task, context, preparedPayload) {
        const raceCfg = this._taskAttackRuntimeConfig(task, 'race') || {}
        const burstCount = Math.max(2, Math.min(8, Number(raceCfg?.burstCount) || 4))
        const basePayload = cloneValue(preparedPayload || task?.payload || {})
        const burstGroup = `ptk-race-${Date.now()}-${ptk_utils.attackParamId()}`
        const requests = []
        for (let index = 0; index < burstCount; index += 1) {
            const schema = cloneValue(basePayload)
            schema.opts = schema.opts || {}
            schema.opts.race_burst = true
            schema.opts.retry_on_transport_failure = false
            schema.opts.transport_retry_count = 0
            schema.opts.transport_retry_delay_ms = 0
            schema.opts.ptk_race_group = burstGroup
            schema.opts.ptk_race_index = index
            schema.request = schema.request || {}
            schema.request.headers = Array.isArray(schema.request.headers) ? schema.request.headers.slice() : []
            if (!schema.request.headers.some((header) => String(header?.name || '').toLowerCase() === 'x-ptk-race-burst')) {
                schema.request.headers.push({
                    name: 'X-PTK-Race-Burst',
                    value: `${burstGroup}-${index}`
                })
            }
            requests.push(schema)
        }

        const responses = await Promise.all(requests.map((schema) => this.activeAttack(schema)))
        const accepted = responses.filter((entry) => this._isLikelyRaceBurstAccepted(entry, context?.original))
        const sampleBodies = responses.slice(0, 4).map((entry) => String(entry?.response?.body || '').slice(0, 120))
        const statuses = responses.map((entry) => Number(entry?.response?.statusCode) || null)
        const acceptedFingerprints = new Set(
            accepted.map((entry) => `${entry?.response?.statusCode || 'na'}|${entry?.response?.length || 0}|${String(entry?.response?.body || '').slice(0, 120)}`)
        )
        const summary = {
            burstCount,
            acceptedCount: accepted.length,
            statuses,
            distinctAcceptedResponses: acceptedFingerprints.size,
            burstGroup
        }
        const primary = accepted[0] || responses[0] || {}
        const success = accepted.length >= 2 && (
            acceptedFingerprints.size >= 2
            || accepted.length === burstCount
            || accepted.some((entry) => Number(entry?.response?.statusCode) !== Number(context?.original?.response?.statusCode))
        )
        const metadata = Object.assign({}, this._attackMetadataView(task?.module, task?.attack), primary?.metadata || {}, {
            attacked: primary?.metadata?.attacked || preparedPayload?.metadata?.attacked || null,
            raceBurst: summary
        })

        return Object.assign({}, primary, {
            success,
            metadata,
            proof: JSON.stringify({
                ...summary,
                sampleBodies
            }),
            response: Object.assign({}, primary?.response || {}, {
                burstSummary: summary,
                burstResponses: responses.map((entry) => ({
                    statusCode: Number(entry?.response?.statusCode) || null,
                    length: Number(entry?.response?.length) || 0
                }))
            })
        })
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
            const transportMode = String(schema?.opts?.transport_mode || '').toLowerCase()
            const isSmugglingH1 = transportMode === 'smuggling_h1'
            if (isFirefox) {
                request.useListeners = true
                schema.opts.use_dnr = false
            } else if (this._supportsActiveRequestTrackingListeners()) {
                request.trackWithListeners = true
            }
            if (isSmugglingH1) {
                schema.opts.override_headers = true
                schema.opts.preserve_browser_headers = true
                schema.opts.keepalive = true
                schema.opts.retry_on_transport_failure = false
                schema.opts.transport_retry_count = 0
                schema.opts.transport_retry_delay_ms = 0
            } else if (typeof schema.opts.override_headers === 'undefined') {
                schema.opts.override_headers = true
            }
            if (!isSmugglingH1 && typeof schema.opts.preserve_browser_headers === 'undefined') {
                schema.opts.preserve_browser_headers = false
            }
            if (!isSmugglingH1 && typeof schema.opts.keepalive === 'undefined') {
                schema.opts.keepalive = false
            }
            if (!isSmugglingH1 && typeof schema.opts.retry_on_transport_failure === 'undefined') {
                schema.opts.retry_on_transport_failure = true
            }
            if (!isSmugglingH1 && typeof schema.opts.transport_retry_count === 'undefined') {
                schema.opts.transport_retry_count = 1
            }
            if (!isSmugglingH1 && typeof schema.opts.transport_retry_delay_ms === 'undefined') {
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
        } else if (this._supportsActiveRequestTrackingListeners()) {
            request.trackWithListeners = true
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

        const tagRegex = /<([A-Za-z][\w:-]*)\b([^>]*)>/ig
        const attrValueRegex = (attrName) => new RegExp(`\\b${attrName}\\s*=\\s*(?:\"([^\"]+)\"|'([^']+)'|([^\\s\"'<>\\x60]+))`, 'i')
        let tagMatch = null
        while ((tagMatch = tagRegex.exec(body)) && urls.length < max) {
            const tagName = String(tagMatch[1] || '').toLowerCase()
            const attrs = String(tagMatch[2] || '')
            if (!tagName || !attrs) continue

            const addAttr = (attrName) => {
                const attrMatch = attrs.match(attrValueRegex(attrName))
                if (!attrMatch) return
                add(attrMatch[1] || attrMatch[2] || attrMatch[3] || '')
            }

            if (tagName === 'a' || tagName === 'area') {
                addAttr('href')
                addAttr('data-href')
            } else if (tagName === 'form') {
                addAttr('action')
                addAttr('data-href')
            } else if (tagName === 'iframe' || tagName === 'frame') {
                addAttr('src')
                addAttr('data-href')
            }
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

    _isReflectedXssTrackingTask(task) {
        const moduleId = String(task?.moduleId || task?.module?.id || '').trim().toLowerCase()
        if (moduleId !== 'xss') return false
        if (Array.isArray(task?.attack?.action?.files) && task.attack.action.files.length) return false
        return this._moduleRuntimeMode(task?.module) !== 'browser_nav'
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
        const responseTier = this._resolveTrackingConfirmationTier(task, tracking)
        if (this._isReflectedXssTrackingTask(task)) {
            this._appendTaskRuntimeEvent(task, context, {
                type: 'dast_tracking_skipped',
                phase: 'tracking',
                reason: 'reflected_xss_requires_validation_or_browser_execution',
                sameResponseMarker: !!(marker && responseBody.includes(marker))
            })
            return null
        }
        if (marker && responseBody.includes(marker)) {
            return this._buildTrackingSuccessResult(task, tracking, {
                tier: responseTier,
                confidence: trackingConfidence,
                source: 'response',
                response: executed?.response || null
            })
        }

        let trackingExecuted = executed
        const secondStage = this._trackingSecondStageFile(task)
        if (secondStage) {
            const stageTwoExecuted = await this._runTrackingSecondStageUpload(task, executed, context)
            if (stageTwoExecuted?.request?.url) {
                trackingExecuted = stageTwoExecuted
            }
        }

        const candidates = this._buildTrackingFollowupUrls(task, trackingExecuted, context)
        if (!candidates.length) return null

        for (const url of candidates) {
            const followup = this._buildFollowupRequest(trackingExecuted, url)
            if (!followup) continue
            const res = await this.activeAttack(followup)
            const body = res?.response?.body || ''
            if (marker && body.includes(marker)) {
                return this._buildTrackingSuccessResult(task, tracking, {
                    tier: this._resolveTrackingConfirmationTier(task, tracking),
                    url,
                    confidence: trackingConfidence,
                    source: 'followup',
                    request: res?.request || null,
                    response: res?.response || null
                })
            }
        }

        return null
    }

    _extractTrackingUrls(task, executed, context = null) {
        const tracking = this._attackRuntimeConfirmation(task?.attack, 'tracking') || {}
        const filename =
            tracking.filename ||
            task?.attack?.action?.files?.[0]?.filename ||
            task?.attack?.metadata?.action?.files?.[0]?.filename ||
            null
        const urls = new Set()
        const baseUrl = executed?.request?.url || context?.original?.request?.url || null
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
        const filenameVariants = filename ? this._trackingFilenameVariants(filename) : []
        if (filenameVariants.some((variant) => body.includes(variant))) {
            filenameVariants.forEach((candidateFilename) => {
                const escaped = candidateFilename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
                const absRe = new RegExp(`https?:\\/\\/[^\"'\\s<>]*${escaped}[^\"'\\s<>]*`, 'ig')
                const relRe = new RegExp(`\\/[^\"'\\s<>]*${escaped}[^\"'\\s<>]*`, 'ig')
                let match
                while ((match = absRe.exec(body))) urls.add(match[0])
                while ((match = relRe.exec(body))) urls.add(match[0])
                this._extractTrackingPathFragmentsFromBody(body, candidateFilename).forEach((fragment) => {
                    this._trackingCandidateUrlsFromPathFragment(fragment, baseUrl).forEach((url) => urls.add(url))
                })
            })
        }

        if (baseUrl && filename) {
            const originalFileNames = [
                ...this._extractMultipartFileNamesFromRequest(context?.original?.request),
                ...this._extractMultipartFileNamesFromRequest(executed?.request)
            ]
            this._observedUploadTrackingUrls(
                baseUrl,
                Array.from(new Set(originalFileNames)),
                this._trackingFilenameVariants(filename),
                3
            ).forEach((url) => urls.add(url))
        }

        const limit = this._taskRequiresStrategyContinuation(task) ? 8 : 4
        return Array.from(urls).slice(0, limit)
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
        schema.request.headers = Array.isArray(schema.request.headers)
            ? schema.request.headers.filter((header) => {
                const name = String(header?.name || '').trim().toLowerCase()
                return name !== 'content-type' && name !== 'content-length' && name !== 'origin'
            })
            : []
        schema.opts = schema.opts || {}
        schema.opts.override_headers = true
        schema.opts.follow_redirect = true
        return schema
    }

    _trackingFileUploadConfig(task) {
        const cfg = task?.attack?.metadata?.extensions?.fileUpload
        return cfg && typeof cfg === 'object' ? cfg : {}
    }

    _trackingSecondStageFile(task) {
        const secondStage = this._trackingFileUploadConfig(task)?.chain?.secondStage
        return secondStage && typeof secondStage === 'object' ? secondStage : null
    }

    _trackingSourceFileContents(task) {
        const contents = []
        const addFileContent = (file) => {
            if (!file || typeof file !== 'object') return
            if (file.content === undefined || file.content === null) return
            contents.push(String(file.content))
        }
        const baseFiles = Array.isArray(task?.attack?.action?.files) ? task.attack.action.files : []
        baseFiles.forEach(addFileContent)
        addFileContent(this._trackingSecondStageFile(task))
        return contents
    }

    _trackingMarkerAppearsInSource(task, marker) {
        if (!marker) return false
        return this._trackingSourceFileContents(task).some((content) => content.includes(marker))
    }

    _normalizeTrackingTier(value, fallback = 'retrieved') {
        const raw = String(value || '').trim().toLowerCase()
        if (raw === 'executed' || raw === 'execution') return 'executed'
        if (raw === 'retrieved' || raw === 'retrievable' || raw === 'retrieval') return 'retrieved'
        if (raw === 'uploaded' || raw === 'accepted') return 'uploaded'
        return fallback
    }

    _resolveTrackingConfirmationTier(task, tracking) {
        const explicitTier = this._trackingFileUploadConfig(task)?.confirmationTier
        if (explicitTier) {
            return this._normalizeTrackingTier(explicitTier, 'retrieved')
        }
        return this._trackingMarkerAppearsInSource(task, tracking?.marker || 'PTK_UPLOAD_TEST')
            ? 'retrieved'
            : 'executed'
    }

    _trackingProofForTier(tier, url = null, source = 'followup', marker = null) {
        const resolvedTier = this._normalizeTrackingTier(tier, 'retrieved')
        const markerText = marker ? ` marker ${marker}` : ''
        if (source === 'response') {
            if (resolvedTier === 'executed') {
                return `Upload execution${markerText} observed in upload response body.`
            }
            if (resolvedTier === 'uploaded') {
                return `Upload acceptance${markerText} observed in upload response body.`
            }
            return `Uploaded file${markerText} observed in upload response body.`
        }
        if (resolvedTier === 'executed') {
            return `Uploaded executable${markerText} executed on retrieval from ${url}.`
        }
        if (resolvedTier === 'uploaded') {
            return url
                ? `Uploaded file${markerText} was accepted and later referenced via ${url}.`
                : `Uploaded file${markerText} was accepted.`
        }
        return `Uploaded file${markerText} is retrievable from ${url}.`
    }

    _buildTrackingSuccessResult(task, tracking, {
        tier = 'retrieved',
        url = null,
        confidence = null,
        source = 'followup',
        request = null,
        response = null
    } = {}) {
        const resolvedTier = this._normalizeTrackingTier(tier, 'retrieved')
        const trackingMeta = {
            channel: 'tracking',
            tier: resolvedTier
        }
        const marker = tracking?.marker ? String(tracking.marker) : ''
        if (url) trackingMeta.url = url
        if (source) trackingMeta.source = source
        if (marker) trackingMeta.marker = marker
        return {
            success: true,
            proof: this._trackingProofForTier(resolvedTier, url, source, marker),
            confidence,
            trackingConfirmed: true,
            trackingTier: resolvedTier,
            tracking: {
                url: url || null,
                tier: resolvedTier,
                source,
                marker: marker || null,
                request: request || null,
                response: response || null
            },
            executed: resolvedTier === 'executed',
            metadata: {
                confirmation: trackingMeta,
                executed: resolvedTier === 'executed'
            }
        }
    }

    _extractMultipartFileNamesFromRequest(request = null) {
        const names = new Set()
        const add = (value) => {
            const text = String(value || '').trim()
            if (text) names.add(text)
        }
        const params = Array.isArray(request?.body?.params) ? request.body.params : []
        params.forEach((param) => {
            if (param?.fileName != null) add(param.fileName)
            if (param?.filename != null) add(param.filename)
        })
        const rawSources = [request?.raw, request?.body?.text]
        rawSources.forEach((raw) => {
            if (typeof raw !== 'string' || !raw) return
            const regex = /filename="([^"]+)"/ig
            let match
            while ((match = regex.exec(raw))) add(match[1])
        })
        return Array.from(names)
    }

    _trackingFilenameVariants(filename) {
        const variants = new Set()
        const add = (value) => {
            const text = String(value || '').trim()
            if (text) variants.add(text)
        }
        add(filename)
        try {
            add(decodeURIComponent(String(filename || '')))
        } catch (_) { }
        const raw = String(filename || '')
        add(raw.replace(/%00.*$/i, ''))
        add(raw.replace(/\u0000.*$/i, ''))
        add(raw.replace(/\.+$/g, ''))
        Array.from(variants).forEach((value) => {
            const leaf = String(value || '').split(/[\\/]/).filter(Boolean).pop()
            if (leaf && leaf !== value) add(leaf)
        })
        return Array.from(variants).filter(Boolean)
    }

    _extractTrackingPathFragmentsFromBody(body, filename) {
        const text = typeof body === 'string' ? body : ''
        if (!text || !filename) return []
        const fragments = new Set()
        const add = (value) => {
            const cleaned = String(value || '')
                .trim()
                .replace(/&(?:quot|apos|amp|lt|gt);.*$/i, '')
                .replace(/[)"'<>.,;]+$/g, '')
            if (cleaned && cleaned.includes('/')) fragments.add(cleaned)
        }
        this._trackingFilenameVariants(filename).forEach((variant) => {
            const escaped = variant.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            const fragmentRe = new RegExp(`(?:[A-Za-z0-9_.~%+-]+\\/){0,8}${escaped}`, 'ig')
            let match
            while ((match = fragmentRe.exec(text))) add(match[0])
        })
        return Array.from(fragments)
    }

    _trackingCandidateUrlsFromPathFragment(fragment, baseUrl) {
        if (!fragment || !baseUrl) return []
        const urls = []
        const seen = new Set()
        const add = (candidate) => {
            const resolved = this._resolveSameOriginUrl(candidate, baseUrl)
            if (!resolved || seen.has(resolved)) return
            seen.add(resolved)
            urls.push(resolved)
        }
        const raw = String(fragment || '').trim()
        if (!raw) return []
        if (/^https?:\/\//i.test(raw) || raw.startsWith('/')) {
            add(raw)
            return urls
        }

        const cleaned = raw.replace(/^\.\/+/, '').replace(/^\/+/, '')
        if (!cleaned) return []
        const firstSegment = cleaned.split('/')[0] || ''
        const hasStorageRoot = /^(?:files?|uploads?|assets?|static|media|attachments?|images?)$/i.test(firstSegment)
        const leafFromTraversal = (() => {
            try {
                const decoded = decodeURIComponent(cleaned)
                if (!decoded.includes('../') && !decoded.includes('..\\')) return null
                return decoded.split(/[\\/]/).filter((part) => part && part !== '.' && part !== '..').pop() || null
            } catch (_) {
                return null
            }
        })()

        if (!hasStorageRoot) {
            add(`/files/${cleaned}`)
            if (leafFromTraversal) add(`/files/${leafFromTraversal}`)
            add(`/uploads/${cleaned}`)
            if (leafFromTraversal) add(`/uploads/${leafFromTraversal}`)
        }
        add(`/${cleaned}`)
        add(cleaned)
        return urls
    }

    _replaceTrackedFilenameInUrl(url, originalName, targetName) {
        if (!url || !targetName) return []
        const variants = new Set()
        const add = (value) => {
            const resolved = this._resolveSameOriginUrl(value, url)
            if (resolved) variants.add(resolved)
        }
        const originalVariants = this._trackingFilenameVariants(originalName)
        const targetVariants = this._trackingFilenameVariants(targetName)
        if (!originalVariants.length) {
            try {
                const parsed = new URL(url)
                const segments = parsed.pathname.split('/')
                segments[segments.length - 1] = targetName
                parsed.pathname = segments.join('/')
                add(parsed.toString())
            } catch (_) { }
            return Array.from(variants)
        }
        originalVariants.forEach((originalVariant) => {
            targetVariants.forEach((targetVariant) => {
                if (!originalVariant || !targetVariant) return
                if (url.includes(originalVariant)) {
                    add(url.replace(originalVariant, targetVariant))
                }
                const encodedOriginal = encodeURIComponent(originalVariant)
                const encodedTarget = encodeURIComponent(targetVariant)
                if (url.includes(encodedOriginal)) {
                    add(url.replace(encodedOriginal, encodedTarget))
                }
            })
        })
        return Array.from(variants)
    }

    _recentUploadLikeGetUrls(baseUrl, limit = 4) {
        if (!baseUrl || limit <= 0) return []
        const records = Array.isArray(this.scanResult?.requests) ? this.scanResult.requests : []
        const urls = []
        const seen = new Set()
        for (let i = records.length - 1; i >= 0 && urls.length < limit; i -= 1) {
            const request = records[i]?.original?.request || records[i]?.request || null
            const response = records[i]?.original?.response || records[i]?.response || null
            const requestUrl = request?.ui_url || request?.url
            if (!requestUrl) continue
            if (String(request?.method || 'GET').toUpperCase() !== 'GET') continue
            const resolved = this._resolveSameOriginUrl(requestUrl, baseUrl)
            if (!resolved || seen.has(resolved)) continue
            const path = (() => {
                try {
                    return new URL(resolved).pathname || '/'
                } catch (_) {
                    return resolved
                }
            })()
            const contentType = String(this._getHeaderValue(response?.headers, 'content-type') || '').toLowerCase()
            const looksUploadLike =
                /\/(?:files?|uploads?|avatars?|images?|media|attachments?)\//i.test(path)
                || contentType.includes('image/')
                || contentType.includes('svg')
                || contentType.includes('text/html')
                || contentType.includes('application/octet-stream')
            if (!looksUploadLike) continue
            seen.add(resolved)
            urls.push(resolved)
        }
        return urls
    }

    _observedUploadTrackingUrls(baseUrl, originalFileNames = [], targetFileNames = [], limit = 4) {
        if (!baseUrl || !targetFileNames.length || limit <= 0) return []
        const urls = []
        const seen = new Set()
        const add = (candidate) => {
            const resolved = this._resolveSameOriginUrl(candidate, baseUrl)
            if (!resolved || seen.has(resolved)) return
            seen.add(resolved)
            urls.push(resolved)
        }
        this._recentUploadLikeGetUrls(baseUrl, 6).forEach((observedUrl) => {
            if (originalFileNames.length) {
                originalFileNames.forEach((originalFileName) => {
                    targetFileNames.forEach((targetFileName) => {
                        this._replaceTrackedFilenameInUrl(observedUrl, originalFileName, targetFileName).forEach(add)
                    })
                })
            }
            targetFileNames.forEach((targetFileName) => {
                this._replaceTrackedFilenameInUrl(observedUrl, null, targetFileName).forEach(add)
            })
        })
        return urls.slice(0, limit)
    }

    _buildTrackingFollowupUrls(task, executed, context = null) {
        const tracking = this._attackRuntimeConfirmation(task?.attack, 'tracking') || {}
        const explicitFilename = tracking.filename || task?.attack?.action?.files?.[0]?.filename || null
        const baseUrl = executed?.request?.url || context?.original?.request?.url || null
        const urls = new Set(this._extractTrackingUrls(task, executed, context))
        if (!baseUrl || !explicitFilename) {
            return Array.from(urls)
        }
        const originalFileNames = [
            ...this._extractMultipartFileNamesFromRequest(context?.original?.request),
            ...this._extractMultipartFileNamesFromRequest(executed?.request)
        ]
        this._observedUploadTrackingUrls(
            baseUrl,
            Array.from(new Set(originalFileNames)),
            this._trackingFilenameVariants(explicitFilename),
            4
        ).forEach((url) => urls.add(url))
        const limit = this._taskRequiresStrategyContinuation(task) ? 8 : 4
        return Array.from(urls).slice(0, limit)
    }

    async _runTrackingSecondStageUpload(task, executed, context = null) {
        const secondStage = this._trackingSecondStageFile(task)
        if (!secondStage) return executed
        if (!task?.module?.modifyMultipartFiles) return executed
        const baseRequest = cloneValue(executed || context?.original || null)
        if (!baseRequest?.request?.url) return executed
        baseRequest.response = {}
        baseRequest.request = cloneValue(baseRequest.request || {})
        baseRequest.request.headers = Array.isArray(baseRequest.request.headers) ? baseRequest.request.headers.slice() : []
        baseRequest.opts = cloneValue(baseRequest.opts || {})
        task.module.modifyMultipartFiles(baseRequest, {
            files: [cloneValue(secondStage)]
        }, [])
        try {
            ptk_request.updateRawRequest(baseRequest, null, baseRequest.opts)
        } catch (_) { }
        return await this.activeAttack(baseRequest)
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
        const aggregateKey = this._buildFindingAggregateKey(classification, location, {
            attackMeta,
            attack
        })
        const aggregateSample = aggregateKey
            ? this._buildFindingAggregateSample({
                requestRecord,
                attack,
                attackRecord,
                location
            })
            : null
        if (aggregateKey) {
            const existingFinding = this._lookupAggregatedFinding(aggregateKey)
            if (existingFinding) {
                this._mergeAggregatedFindingOccurrence(existingFinding, {
                    aggregateKey,
                    classification,
                    sample: aggregateSample,
                    confidence
                })
                addFindingToGroup(this.scanResult, existingFinding, aggregateKey, {
                    url: existingFinding?.location?.url || location.url,
                    param: null,
                    occurrenceId: resolverKey || findingInstanceId
                })
                if (attack && typeof attack === 'object') {
                    attack.findingId = existingFinding.id
                    attack.__findingRecorded = true
                    if (attack.__requestRecordEntry && attack.__requestRecordEntry !== attack) {
                        attack.__requestRecordEntry.findingId = existingFinding.id
                        attack.__requestRecordEntry.__findingRecorded = true
                    }
                }
                if (uniqueFindingState?.uniqueKey) {
                    if (!this._activeUniqueFindingKeys) this._activeUniqueFindingKeys = new Set()
                    this._activeUniqueFindingKeys.add(uniqueFindingState.uniqueKey)
                }
                this._markSpaAggregateKeyConfirmed(aggregateKey, attack, classification)
                return
            }
        }
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
            presentationAggregate: classification.presentationAggregate || null,
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
        if (aggregateKey) {
            this._applyFindingAggregateState(normalizedFinding, {
                aggregateKey,
                classification,
                sample: aggregateSample
            })
            const dastEvidence = normalizedFinding?.evidence?.dast
            if (dastEvidence && typeof dastEvidence === 'object') {
                dastEvidence.occurrenceCount = 1
            }
        }
        addFinding(this.scanResult, normalizedFinding)
        if (aggregateKey && this._findingAggregateIndex instanceof Map) {
            this._findingAggregateIndex.set(aggregateKey, normalizedFinding)
        }
        this._markSpaAggregateKeyConfirmed(aggregateKey, attack, classification)
        const groupKey = aggregateKey || [
            "DAST",
            normalizedFinding.vulnId,
            moduleId,
            ruleId,
            normalizedFinding?.location?.url || location.url || "",
            normalizedFinding?.location?.param || location.param || ""
        ].join('@@')
        addFindingToGroup(this.scanResult, normalizedFinding, groupKey, {
            url: normalizedFinding?.location?.url || location.url,
            param: aggregateKey ? null : (normalizedFinding?.location?.param || location.param || null),
            occurrenceId: resolverKey || findingInstanceId
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
        const trackingTier = this._normalizeTrackingTier(
            attack?.trackingTier
            || attack?.tracking?.tier
            || attack?.metadata?.confirmation?.tier
            || attack?.confirmation?.tier,
            ''
        )
        if (attack?.trackingConfirmed) {
            if (explicitOverride) {
                return {
                    confidence: explicitOverride.confidence,
                    signals: mergeSignals(
                        explicitOverride.signals,
                        [trackingTier === 'executed' ? "tracking:executed" : trackingTier === 'retrieved' ? "tracking:retrieved" : "tracking:confirmed"]
                    )
                }
            }
            if (trackingTier === 'executed') {
                return { confidence: 97, signals: ["tracking:executed"] }
            }
            if (trackingTier === 'retrieved') {
                return { confidence: 92, signals: ["tracking:retrieved"] }
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
            return { confidence: 92, signals: ["execution:observed"] }
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
                onTaskFinished: hooks.onTaskFinished,
                onPtkTabOpened: hooks.onPtkTabOpened,
                onPtkTabClosing: hooks.onPtkTabClosing
            }
        } else {
            this.automationHooks = null
        }
    }

    setCaptureProgressProvider(provider) {
        this.captureProgressProvider = provider && typeof provider === 'object'
            ? provider
            : null
    }

    _captureProgressSnapshot() {
        const provider = this.captureProgressProvider
        if (!provider || typeof provider !== 'object') {
            return {
                pendingObservedRequests: 0
            }
        }
        if (typeof provider.getCaptureStats === 'function') {
            try {
                const stats = provider.getCaptureStats()
                if (stats && typeof stats === 'object') return stats
            } catch (_) { }
        }
        if (typeof provider.getPendingObservedRequestCount === 'function') {
            try {
                return {
                    pendingObservedRequests: Math.max(0, Number(provider.getPendingObservedRequestCount() || 0))
                }
            } catch (_) { }
        }
        return {
            pendingObservedRequests: 0
        }
    }

    notifyCaptureProgressChanged() {
        try {
            this._emitProgress({ name: 'Observed request capture progress' })
        } catch (_) { }
        this._notifyIdleResolvers()
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

    async _automationPtkTabOpened(details = {}) {
        const hooks = this.automationHooks
        if (!hooks || typeof hooks.onPtkTabOpened !== 'function') return null
        try {
            return await hooks.onPtkTabOpened(Object.assign({
                sessionId: hooks.sessionId || null,
                parentTabId: this.tabId || null
            }, details || {}))
        } catch (err) {
            console.warn('[PTK DAST] automation onPtkTabOpened hook failed', {
                sessionId: hooks.sessionId || null,
                tabId: details?.tabId || null,
                role: details?.role || null,
                error: err?.message || String(err)
            })
            return null
        }
    }

    async _automationPtkTabClosing(details = {}) {
        const hooks = this.automationHooks
        if (!hooks || typeof hooks.onPtkTabClosing !== 'function') return null
        try {
            return await hooks.onPtkTabClosing(Object.assign({
                sessionId: hooks.sessionId || null,
                parentTabId: this.tabId || null
            }, details || {}))
        } catch (err) {
            console.warn('[PTK DAST] automation onPtkTabClosing hook failed', {
                sessionId: hooks.sessionId || null,
                tabId: details?.tabId || null,
                role: details?.role || null,
                error: err?.message || String(err)
            })
            return null
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
        const presentationAggregate = this._resolveFindingPresentationAggregate(
            ptkMeta,
            attackMeta?.metadata,
            attackMeta,
            moduleMeta?.metadata,
            moduleMeta
        )
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
            presentationAggregate,
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
        const confidenceDetails = this._resolveAttackConfidenceDetails(attack, classification)
        const confidence = Number.isFinite(confidenceDetails?.confidence) ? confidenceDetails.confidence : null
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
            confidence,
            outputKind: "recon",
            reconKind: ptkMeta.reconKind || classification.reconKind || null,
            presentationAggregate: classification.presentationAggregate || null,
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
                    proof: attack?.proof || null,
                    confidenceSignals: Array.isArray(confidenceDetails?.signals) ? confidenceDetails.signals : []
                }
            }
        })
        attack.__reconRecorded = true
        if (attack.__requestRecordEntry && attack.__requestRecordEntry !== attack) {
            attack.__requestRecordEntry.__reconRecorded = true
        }
    }

    _isIdle() {
        let queueEmpty = !this._requestQueue?.size || this._requestQueue.size() === 0
        const noTaskQueue = this._taskQueueCount() === 0
        const noPlans = !this._activePlans?.size
        const noActiveTasks = (this.activeCount || 0) === 0
        const notBuilding = this.inProgress === false
        const noPendingCaptures = Math.max(0, Number(this._captureProgressSnapshot()?.pendingObservedRequests || 0)) === 0
        if (this.isRunning && queueEmpty && noTaskQueue && noPlans && noActiveTasks && notBuilding && noPendingCaptures && this._pendingHtmlLinkDiscoveryCount() > 0) {
            this._drainPendingHtmlDiscoveryQueue()
            queueEmpty = !this._requestQueue?.size || this._requestQueue.size() === 0
        }
        const noPendingHtmlDiscovery = this._pendingHtmlLinkDiscoveryCount() === 0
        return queueEmpty && noTaskQueue && noPlans && noActiveTasks && notBuilding && noPendingCaptures && noPendingHtmlDiscovery && this.isRunning
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
