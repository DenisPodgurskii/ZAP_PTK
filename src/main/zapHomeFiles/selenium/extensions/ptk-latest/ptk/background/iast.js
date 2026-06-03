/* Author: Denis Podgurskii */
import { ptk_utils, ptk_logger, ptk_queue, ptk_storage, ptk_ruleManager } from "../background/utils.js"
import {
    applyIastFindingAggregateState,
    buildIastFindingAggregateKey,
    buildIastFindingAggregateSample,
    createFindingFromIAST,
    getIastEvidencePayload,
    mergeIastFindingAggregateOccurrence,
    normalizeIastFindingAggregationMode,
    resolveIastFindingPresentationAggregate
} from "./iast/modules/reporting.js"
import { loadCanonicalRulepack } from "./common/moduleRegistry.js"
import { scanResultStore } from "./scanResultStore.js"
import { normalizeEvidenceRefs } from "./analysis/evidenceRefs.js"
import {
    resolveEffectiveSeverity
} from "./common/severity_utils.js"
import { loadCanonicalIastRulepack } from "./iast/contract/index.js"
import buildExportScanResult from "./export/buildExportScanResult.js"
import { compressScanPayload } from "./export/compressScanPayload.js"
import { ExportChunkStore } from "./export/exportChunkStore.js"
import { parseDownloadedScanPayload } from "./export/parseDownloadedScanPayload.js"
import { parseUploadedScanFile } from "./export/parseUploadedScanFile.js"
import {
    buildPortalUrl as buildSharedPortalUrl,
    getPortalBaseUrl,
    initializePortalRuntimeConfig
} from "../common/portalConfig.js"
import { portalPolicyRuntimeStore } from "./common/portalPolicyRuntimeStore.js"
import { buildIastRuntimePlan } from "../content/iast_runtime_plan.js"

const activeIastTabs = new Set()
let iastModulesCache = null
let iastModulesCacheIsCustom = false
let iastModulesCacheKey = null
let iastScanStrategy = 'SMART'
const lastIastModuleDeliveryByTab = new Map()
const inFlightIastModuleSendByTab = new Map()

function normalizeIastBackgroundStrategy(value = 'SMART') {
    return String(value || '').trim().toUpperCase() === 'COMPREHENSIVE'
        ? 'COMPREHENSIVE'
        : 'SMART'
}

function buildIastAgentScriptFiles(scanStrategy = 'SMART', { isFirefox = false } = {}) {
    const prefix = isFirefox ? 'content/' : 'ptk/content/'
    const bootstrap = `${prefix}iast_agent_bootstrap.js`
    const strategy = normalizeIastBackgroundStrategy(scanStrategy)
    return strategy === 'COMPREHENSIVE'
        ? [bootstrap, `${prefix}iast_comprehensive_bootstrap.js`, `${prefix}iast.js`]
        : [bootstrap, `${prefix}iast.js`]
}

function normalizeIastRegistrationHost({ host = '', targetUrl = '' } = {}) {
    const candidates = [targetUrl, host]
        .map((value) => typeof value === 'string' ? value.trim() : '')
        .filter(Boolean)

    for (const candidate of candidates) {
        try {
            const normalizedCandidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)
                ? candidate
                : `https://${candidate.replace(/^\/+/, '')}`
            const parsed = new URL(normalizedCandidate)
            const protocol = String(parsed.protocol || '').toLowerCase()
            if (protocol !== 'http:' && protocol !== 'https:') continue
            const hostname = String(parsed.hostname || '').toLowerCase()
            const hostWithPort = String(parsed.host || '').toLowerCase()
            if (!hostname || hostname === '*' || hostname.includes('*')) continue
            return {
                hostname,
                hostWithPort: hostWithPort || hostname
            }
        } catch (_) { }
    }

    return null
}

function formatIastRegistrationMatchHost(hostname = '') {
    const normalized = String(hostname || '').trim().toLowerCase()
    if (!normalized) return ''
    if (normalized.includes(':') && !normalized.startsWith('[')) {
        return `[${normalized}]`
    }
    return normalized
}

function buildIastAgentScriptRegistrationScope({ host = '', targetUrl = '' } = {}) {
    const normalized = normalizeIastRegistrationHost({ host, targetUrl })
    if (!normalized) return null
    const matchHost = formatIastRegistrationMatchHost(normalized.hostname)
    if (!matchHost) return null

    const scope = {
        matches: [
            `http://${matchHost}/*`,
            `https://${matchHost}/*`
        ]
    }
    if (normalized.hostWithPort && normalized.hostWithPort !== normalized.hostname) {
        scope.includeGlobs = [
            `http://${normalized.hostWithPort}/*`,
            `https://${normalized.hostWithPort}/*`
        ]
    }
    return scope
}

function clearIastModuleSendTracking(tabId = null) {
    if (tabId == null) {
        lastIastModuleDeliveryByTab.clear()
        inFlightIastModuleSendByTab.clear()
        return
    }
    lastIastModuleDeliveryByTab.delete(tabId)
    inFlightIastModuleSendByTab.delete(tabId)
}

function getIastModuleDeliveryState(tabId) {
    return {
        delivered: lastIastModuleDeliveryByTab.get(tabId) || null,
        inFlight: inFlightIastModuleSendByTab.get(tabId) || null
    }
}
function mergeLinks(baseLinks, overrideLinks) {
    const result = Object.assign({}, baseLinks || {})
    if (overrideLinks && typeof overrideLinks === "object") {
        Object.entries(overrideLinks).forEach(([key, value]) => {
            if (key) result[key] = value
        })
    }
    return Object.keys(result).length ? result : null
}

function buildIastRuleIndex(rulepack) {
    iastRuleMetaIndex = new Map()
    iastModuleMetaIndex = new Map()
    const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
    modules.forEach((mod) => {
        const moduleMeta = mod?.metadata || {}
        const base = {
            moduleId: mod?.id || null,
            moduleName: mod?.name || mod?.id || null,
            vulnId: mod?.vulnId || moduleMeta.vulnId || mod?.id || null,
            category: moduleMeta.category || null,
            severity: moduleMeta.severity || null,
            owasp: moduleMeta.owasp || null,
            cwe: moduleMeta.cwe || null,
            tags: moduleMeta.tags || [],
            description: moduleMeta.description || null,
            recommendation: moduleMeta.recommendation || null,
            links: moduleMeta.links || null
        }
        iastModuleMetaIndex.set(base.moduleId, {
            id: base.moduleId,
            name: base.moduleName,
            metadata: moduleMeta,
            vulnId: base.vulnId,
            category: base.category,
            severity: base.severity,
            links: base.links,
            tags: base.tags,
            description: base.description,
            recommendation: base.recommendation
        })
        const rules = Array.isArray(mod?.rules) ? mod.rules : []
        rules.forEach(rule => {
            const ruleMeta = rule?.metadata || {}
            if (!rule?.id) return
            const mergedLinks = mergeLinks(base.links, ruleMeta.links)
            iastRuleMetaIndex.set(rule.id, {
                moduleId: base.moduleId,
                moduleName: base.moduleName,
                ruleName: rule?.name || rule?.id || null,
                vulnId: base.vulnId,
                category: ruleMeta.category || base.category,
                severity: resolveEffectiveSeverity({
                    moduleMeta,
                    ruleMeta
                }),
                owasp: ruleMeta.owasp || base.owasp,
                cwe: ruleMeta.cwe || base.cwe,
                tags: ruleMeta.tags || base.tags,
                description: ruleMeta.description || base.description || null,
                recommendation: ruleMeta.recommendation || base.recommendation || null,
                links: mergedLinks,
                moduleMeta: iastModuleMetaIndex.get(base.moduleId),
                ruleMeta: {
                    id: rule?.id || null,
                    name: rule?.name || rule?.id || null,
                    metadata: ruleMeta
                }
            })
        })
    })
}

function getIastRuleMeta(ruleId) {
    if (!ruleId) return null
    return iastRuleMetaIndex.get(ruleId) || null
}
let iastRuleMetaIndex = new Map()
let iastModuleMetaIndex = new Map()

function getIastModuleMeta(moduleId) {
    if (!moduleId) return null
    return iastModuleMetaIndex.get(moduleId) || null
}

function getPrimaryIastSource(evidence = {}) {
    const sources = Array.isArray(evidence?.sources) ? evidence.sources : []
    for (const source of sources) {
        if (!source || typeof source !== "object") continue
        const sourceKind = source?.sourceKind || source?.kind || null
        const sourceKey = source?.key || source?.source || source?.sourceId || null
        if (sourceKind || sourceKey) {
            return source
        }
    }
    return null
}

function getRuntime() {
    if (typeof chrome !== 'undefined' && chrome.runtime) return chrome
    if (typeof browser !== 'undefined' && browser.runtime) return browser
    return null
}

function normalizeIastRulepack(rulepack, label = 'IAST') {
    if (!rulepack || typeof rulepack !== 'object' || Array.isArray(rulepack)) {
        return null
    }
    try {
        return loadCanonicalIastRulepack(rulepack, { label })
    } catch (err) {
        console.warn('[PTK IAST BG] Failed to normalize rulepack', { label, error: err?.message || String(err) })
        return null
    }
}

function cloneIastValue(value, fallback = null) {
    if (value === undefined) return fallback
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function buildIastRulepackError(code, message, extras = {}) {
    const err = new Error(String(message || code || 'invalid_iast_rulepack'))
    err.code = String(code || 'invalid_iast_rulepack')
    Object.assign(err, extras)
    return err
}

function getIastPackStatusForSelection(selection = null, policyState = null) {
    if (selection?.source === 'portal') {
        return String(policyState?.packStatus || 'active').trim() || 'active'
    }
    return 'active'
}

export function validateIastActivationRulepack(rulepack, opts = {}) {
    const runtimePlan = buildIastRuntimePlan(rulepack)
    const issues = []
    const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
    modules.forEach((moduleDef, moduleIndex) => {
        const rules = Array.isArray(moduleDef?.rules) ? moduleDef.rules : []
        rules.forEach((ruleDef, ruleIndex) => {
            const sinkId = String(ruleDef?.sinkId || '').trim()
            if (!sinkId) return
            const sinkPlan = runtimePlan?.bySinkId?.[sinkId] || null
            if (!sinkPlan || !Array.isArray(sinkPlan.variants) || !sinkPlan.variants.some((entry) => entry?.ruleId === ruleDef?.id)) {
                issues.push(`missing_runtime_binding:${moduleDef?.id || moduleIndex}:${ruleDef?.id || ruleIndex}:${sinkId}`)
                return
            }
            if (!Array.isArray(sinkPlan.hookGroups) || sinkPlan.hookGroups.length === 0) {
                issues.push(`missing_hook_group:${moduleDef?.id || moduleIndex}:${ruleDef?.id || ruleIndex}:${sinkId}`)
            }
        })
    })
    if (issues.length) {
        throw buildIastRulepackError(
            'iast_runtime_plan_invalid',
            `[PTK IAST] Rulepack activation plan is incompatible${opts?.label ? ` for ${opts.label}` : ''}: ${issues.join(', ')}`,
            {
                issues,
                runtimePlan
            }
        )
    }
    return runtimePlan
}

export function buildIastActivationTelemetry(rulepack, runtimePlan, opts = {}) {
    const hookGroups = runtimePlan?.installPlan?.hookGroups && typeof runtimePlan.installPlan.hookGroups === 'object'
        ? runtimePlan.installPlan.hookGroups
        : {}
    const hookRuleCounts = Object.fromEntries(
        Object.entries(hookGroups)
            .sort(([left], [right]) => String(left).localeCompare(String(right)))
            .map(([groupId, hookPlan]) => [groupId, Number(hookPlan?.ruleCount || 0)])
    )
    return {
        packStatus: String(opts?.packStatus || 'active'),
        activeModuleCount: Array.isArray(runtimePlan?.activeModuleIds) ? runtimePlan.activeModuleIds.length : 0,
        activeRuleCount: Array.isArray(runtimePlan?.activeRuleIds) ? runtimePlan.activeRuleIds.length : 0,
        activeHookGroups: Array.isArray(runtimePlan?.activeHookGroups) ? runtimePlan.activeHookGroups.slice() : [],
        freeSafeHookGroups: Array.isArray(runtimePlan?.freeSafeHookGroups) ? runtimePlan.freeSafeHookGroups.slice() : [],
        policyOnlyHookGroups: Array.isArray(runtimePlan?.policyOnlyHookGroups) ? runtimePlan.policyOnlyHookGroups.slice() : [],
        supportHookGroups: Array.isArray(runtimePlan?.supportHookGroups) ? runtimePlan.supportHookGroups.slice() : [],
        hookRuleCounts,
        rulepackSource: String(opts?.selection?.source || 'local'),
        policyId: opts?.selection?.policyId || null,
        policyName: opts?.selection?.policyName || null,
        moduleIds: Array.isArray(runtimePlan?.activeModuleIds) ? runtimePlan.activeModuleIds.slice() : [],
        ruleIds: Array.isArray(runtimePlan?.activeRuleIds) ? runtimePlan.activeRuleIds.slice() : [],
        runtimeHealth: buildDefaultIastRuntimeHealthTelemetry({
            enabledHookGroups: Array.isArray(runtimePlan?.activeHookGroups) ? runtimePlan.activeHookGroups.slice() : []
        })
    }
}

export function buildDefaultIastRuntimeHealthTelemetry(overrides = {}) {
    const hookGroupFailures = overrides?.hookGroupFailures && typeof overrides.hookGroupFailures === 'object'
        ? Object.fromEntries(Object.entries(overrides.hookGroupFailures).map(([groupId, entry]) => [groupId, cloneIastValue(entry, null)]))
        : {}
    return {
        state: String(overrides?.state || 'initializing'),
        enabledHookGroups: Array.isArray(overrides?.enabledHookGroups) ? overrides.enabledHookGroups.slice() : [],
        degradedHookGroups: Array.isArray(overrides?.degradedHookGroups) ? overrides.degradedHookGroups.slice() : [],
        globallyDisabledHookGroups: Array.isArray(overrides?.globallyDisabledHookGroups) ? overrides.globallyDisabledHookGroups.slice() : [],
        hookGroupFailures,
        modulesLoaded: overrides?.modulesLoaded === true,
        modulesSignature: overrides?.modulesSignature || null,
        pendingFindingReports: Number.isFinite(Number(overrides?.pendingFindingReports))
            ? Number(overrides.pendingFindingReports)
            : null,
        flushedPendingFindingReports: Number.isFinite(Number(overrides?.flushedPendingFindingReports))
            ? Number(overrides.flushedPendingFindingReports)
            : null,
        url: overrides?.url || null,
        agentBootUrl: overrides?.agentBootUrl || null,
        documentReadyState: overrides?.documentReadyState || null,
        agentBootReadyState: overrides?.agentBootReadyState || null,
        agentBootAt: Number.isFinite(Number(overrides?.agentBootAt)) ? Number(overrides.agentBootAt) : null,
        navigationStart: Number.isFinite(Number(overrides?.navigationStart)) ? Number(overrides.navigationStart) : null,
        agentBootDelayMs: Number.isFinite(Number(overrides?.agentBootDelayMs)) ? Number(overrides.agentBootDelayMs) : null,
        agentBootAfterLoad: overrides?.agentBootAfterLoad === true,
        updatedAt: overrides?.updatedAt || null,
        error: overrides?.error || null
    }
}

function buildDefaultIastAutomationTelemetry(overrides = {}) {
    const expectedTabId = overrides?.expectedTabId
    const lastSenderTabId = overrides?.lastSenderTabId
    return {
        scanStrategy: normalizeIastBackgroundStrategy(overrides?.scanStrategy || iastScanStrategy),
        agentReadyCount: Number(overrides?.agentReadyCount || 0),
        agentFailedCount: Number(overrides?.agentFailedCount || 0),
        runtimeHealthCount: Number(overrides?.runtimeHealthCount || 0),
        findingReportsAccepted: Number(overrides?.findingReportsAccepted || 0),
        findingReportsDroppedInactive: Number(overrides?.findingReportsDroppedInactive || 0),
        findingReportsDroppedTabMismatch: Number(overrides?.findingReportsDroppedTabMismatch || 0),
        runtimeSignalsAccepted: Number(overrides?.runtimeSignalsAccepted || 0),
        runtimeSignalsDroppedInactive: Number(overrides?.runtimeSignalsDroppedInactive || 0),
        runtimeSignalsDroppedTabMismatch: Number(overrides?.runtimeSignalsDroppedTabMismatch || 0),
        modulesSentOk: Number(overrides?.modulesSentOk || 0),
        modulesSentSkipped: Number(overrides?.modulesSentSkipped || 0),
        modulesSentError: Number(overrides?.modulesSentError || 0),
        expectedTabId: expectedTabId !== null && expectedTabId !== undefined && Number.isInteger(Number(expectedTabId))
            ? Number(expectedTabId)
            : null,
        lastSenderTabId: lastSenderTabId !== null && lastSenderTabId !== undefined && Number.isInteger(Number(lastSenderTabId))
            ? Number(lastSenderTabId)
            : null,
        lastDroppedReason: overrides?.lastDroppedReason || null,
        lastModuleSendResult: overrides?.lastModuleSendResult || null,
        lastUpdatedAt: overrides?.lastUpdatedAt || null
    }
}

export function computeIastNoiseTelemetry(scanResult = {}) {
    const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
    const runtimeEvents = Array.isArray(scanResult?.runtimeEvents) ? scanResult.runtimeEvents : []
    const telemetry = {
        findingCount: findings.length,
        runtimeSignalCount: runtimeEvents.length,
        lowConfidenceFindingCount: 0,
        observationFindingCount: 0,
        suppressedFindingCount: 0,
        trustAllowedFindingCount: 0,
        observationRuntimeSignalCount: 0,
        suppressedRuntimeSignalCount: 0,
        trustAllowedRuntimeSignalCount: 0
    }

    findings.forEach((finding) => {
        const confidence = Number(finding?.confidence)
        if (Number.isFinite(confidence) && confidence < 40) {
            telemetry.lowConfidenceFindingCount += 1
        }
        const evidence = getIastEvidencePayload(finding) || {}
        const primaryClass = String(evidence?.primaryClass || '').trim().toLowerCase()
        if (primaryClass === 'observation') {
            telemetry.observationFindingCount += 1
        }
        if (evidence?.suppression?.suppressed === true) {
            telemetry.suppressedFindingCount += 1
        }
        if (String(evidence?.trust?.decision || '').trim().toLowerCase() === 'allow') {
            telemetry.trustAllowedFindingCount += 1
        }
    })

    runtimeEvents.forEach((event) => {
        const primaryClass = String(event?.primaryClass || '').trim().toLowerCase()
        if (primaryClass === 'observation') {
            telemetry.observationRuntimeSignalCount += 1
        }
        if (event?.suppression?.suppressed === true) {
            telemetry.suppressedRuntimeSignalCount += 1
        }
        if (String(event?.trust?.decision || '').trim().toLowerCase() === 'allow') {
            telemetry.trustAllowedRuntimeSignalCount += 1
        }
    })

    return telemetry
}

function buildPortalRulepackLoadOptions(options = {}) {
    const explicitPortal = (options?.portal && typeof options.portal === 'object') ? options.portal : {}
    const profile = worker?.ptk_app?.settings?.profile || {}
    const explicitPolicyId =
        (explicitPortal.policyId !== undefined && explicitPortal.policyId !== null && explicitPortal.policyId !== '')
            ? String(explicitPortal.policyId).trim()
            : ((options?.policyId !== undefined && options?.policyId !== null && options?.policyId !== '')
                ? String(options.policyId).trim()
                : null)
    const hasPolicySelection =
        !!explicitPolicyId
    const preferPortal = options?.preferPortal === true
        || explicitPortal?.preferPortal === true
        || hasPolicySelection
    if (!preferPortal) return null

    const baseUrl = String(explicitPortal.baseUrl || getPortalBaseUrl() || '').trim()
    const apiKey = String(explicitPortal.apiKey || explicitPortal.token || profile.api_key || '').trim()
    if (!baseUrl || !apiKey) return null

    return {
        preferPortal: true,
        baseUrl,
        apiBase: explicitPortal.apiBase || "/api/v1",
        policiesEndpoint: explicitPortal.policiesEndpoint || "/policies",
        apiKey,
        policyId: explicitPolicyId,
        policyName: explicitPortal.policyName || options?.policyName || null
    }
}

function buildConfiguredIastRulepackLoadOptions(options = {}) {
    const requestedVariant = options?.variant ? String(options.variant).trim() : ""
    const portalOptions = buildPortalRulepackLoadOptions(options)
    return Object.assign(
        {},
        requestedVariant ? { variant: requestedVariant } : {},
        portalOptions || {}
    )
}

function normalizeIastSelectionValue(value) {
    if (value === undefined || value === null) return null
    const text = String(value).trim()
    return text || null
}

function buildIastModulesSignature(modules = null, scanStrategy = null) {
    const normalizedStrategy = String(scanStrategy || '').trim().toUpperCase() || 'SMART'
    if (!modules || !Array.isArray(modules.modules)) {
        return `strategy:${normalizedStrategy}|modules:0`
    }

    const policyId = normalizeIastSelectionValue(modules?.policy?.id) || ''
    const policyName = normalizeIastSelectionValue(modules?.policy?.name) || ''
    const version = normalizeIastSelectionValue(modules?.version) || ''
    const moduleSignature = modules.modules.map((moduleDef, moduleIndex) => {
        const moduleId = normalizeIastSelectionValue(moduleDef?.id) || `module#${moduleIndex}`
        const ruleIds = Array.isArray(moduleDef?.rules)
            ? moduleDef.rules.map((ruleDef, ruleIndex) => normalizeIastSelectionValue(ruleDef?.id) || `rule#${ruleIndex}`).join(',')
            : ''
        return `${moduleId}:${ruleIds}`
    }).join('|')

    return `strategy:${normalizedStrategy}|version:${version}|policy:${policyId}|name:${policyName}|modules:${moduleSignature}`
}

function buildIastRulepackSelectionSummary(rulepack = null, options = {}) {
    const requestedVariant = normalizeIastSelectionValue(options?.variant)
    const policyMeta = rulepack?.policy && typeof rulepack.policy === 'object'
        ? rulepack.policy
        : null
    const policyId = normalizeIastSelectionValue(policyMeta?.id || options?.policyId)
    const policyName = normalizeIastSelectionValue(policyMeta?.name || options?.policyName)
    const hasPortalPolicy = !!(policyId || policyName || policyMeta)

    if (options?.rulepack && !hasPortalPolicy) {
        return {
            source: 'custom',
            preferPortal: false,
            policyId: null,
            policyName: null,
            variant: requestedVariant,
            label: 'Custom rulepack'
        }
    }

    if (hasPortalPolicy) {
        return {
            source: 'portal',
            preferPortal: true,
            policyId,
            policyName,
            variant: requestedVariant,
            label: policyName
                ? `Portal policy: ${policyName}`
                : (policyId ? `Portal policy #${policyId}` : 'Portal policy')
        }
    }

    return {
        source: 'local',
        preferPortal: false,
        policyId: null,
        policyName: null,
        variant: requestedVariant,
        label: requestedVariant
            ? `Built-in ${requestedVariant} rulepack`
            : 'Built-in rulepack'
    }
}

function buildIastRulepackSelectionFromScan(scanResult = {}) {
    const settings = scanResult?.settings && typeof scanResult.settings === 'object'
        ? scanResult.settings
        : {}
    const source = normalizeIastSelectionValue(settings.iastRulepackSource) || 'local'
    const policyId = normalizeIastSelectionValue(scanResult?.policyId)
    const policyName = normalizeIastSelectionValue(settings.iastPolicyName)
    const variant = normalizeIastSelectionValue(settings.iastRulepackVariant)
    if (source === 'custom') {
        return {
            source,
            preferPortal: false,
            policyId: null,
            policyName: null,
            variant,
            label: 'Custom rulepack'
        }
    }
    if (source === 'portal' && (policyId || policyName)) {
        return {
            source,
            preferPortal: true,
            policyId,
            policyName,
            variant,
            label: policyName
                ? `Portal policy: ${policyName}`
                : (policyId ? `Portal policy #${policyId}` : 'Portal policy')
        }
    }
    return {
        source: 'local',
        preferPortal: false,
        policyId: null,
        policyName: null,
        variant,
        label: variant
            ? `Built-in ${variant} rulepack`
            : 'Built-in rulepack'
    }
}

function getIastPortalPolicyState() {
    return portalPolicyRuntimeStore.getState('IAST')
}

function getIastPortalSelection() {
    return portalPolicyRuntimeStore.getRulepackSelection('IAST')
}

function getIastSelectedPortalPolicy() {
    return portalPolicyRuntimeStore.getSelectedPolicy('IAST')
}

function getPortalApiKey() {
    return String(worker?.ptk_app?.settings?.profile?.api_key || '').trim()
}

function buildIastRulepackCacheKey(options = {}) {
    const requestedVariant = options?.variant ? String(options.variant).trim() : ''
    const portalOptions = buildPortalRulepackLoadOptions(options)
    if (portalOptions?.policyId) {
        return `portal:${String(portalOptions.policyId).trim()}`
    }
    return `local:${requestedVariant || 'default'}`
}

async function loadIastModules(options = {}) {
    const requestedVariant = options?.variant ? String(options.variant).trim() : null
    if (options && Object.prototype.hasOwnProperty.call(options, 'rulepack')) {
        const forcedRulepack = normalizeIastRulepack(options?.rulepack, 'custom')
        if (!forcedRulepack) {
            iastModulesCache = null
            iastModulesCacheIsCustom = false
            iastModulesCacheKey = null
            throw buildIastRulepackError('invalid_iast_rulepack', '[PTK IAST] Custom rulepack failed validation')
        }
        iastModulesCache = forcedRulepack
        iastModulesCacheIsCustom = true
        iastModulesCacheKey = requestedVariant ? `custom:${requestedVariant}` : '__custom__'
        buildIastRuleIndex(forcedRulepack)
        return iastModulesCache
    }

    if (options?.resetCache === true) {
        iastModulesCache = null
        iastModulesCacheIsCustom = false
        iastModulesCacheKey = null
    }

    const cacheKey = buildIastRulepackCacheKey(options)
    if (iastModulesCache && !iastModulesCacheIsCustom && iastModulesCacheKey === cacheKey) return iastModulesCache
    if (iastModulesCache && iastModulesCacheIsCustom) {
        iastModulesCache = null
        iastModulesCacheKey = null
    }
    try {
        const portalOptions = buildPortalRulepackLoadOptions(options)
        const loadOptions = Object.assign(
            {},
            requestedVariant ? { variant: requestedVariant } : {},
            portalOptions || {}
        )
        const resolvedRulepack = await loadCanonicalRulepack('IAST', loadOptions)
        if (!resolvedRulepack) {
            throw new Error('invalid_iast_rulepack')
        }
        iastModulesCache = resolvedRulepack
        iastModulesCacheIsCustom = false
        iastModulesCacheKey = cacheKey
        buildIastRuleIndex(resolvedRulepack)
        //console.log('[PTK IAST BG] Loaded IAST rulepack')
        return iastModulesCache
    } catch (e) {
        console.error('[PTK IAST BG] Error loading IAST rulepack:', e)
        iastModulesCache = null
        iastModulesCacheIsCustom = false
        iastModulesCacheKey = null
        throw e
    }
}

async function sendIastModulesToContent(tabId, attempt = 1, options = {}) {
    let modules = null
    try {
        modules = await loadIastModules(options)
    } catch (err) {
        console.warn('[PTK IAST BG] Failed to load IAST modules for tab', tabId, err?.code || err?.message || String(err))
        return
    }
    if (!modules) {
        console.warn('[PTK IAST BG] No IAST modules to send to tab', tabId)
        return
    }
    const rt = getRuntime()
    if (!rt || !rt.tabs?.sendMessage) {
        console.warn('[PTK IAST BG] tabs.sendMessage unavailable')
        return
    }
    const modulesSignature = buildIastModulesSignature(modules, iastScanStrategy)
    const deliveredEntry = lastIastModuleDeliveryByTab.get(tabId)
    if (deliveredEntry?.signature === modulesSignature) {
        return {
            ok: true,
            skipped: true,
            reason: 'already_delivered',
            signature: modulesSignature
        }
    }
    const inFlightEntry = inFlightIastModuleSendByTab.get(tabId)
    if (inFlightEntry?.signature === modulesSignature && inFlightEntry?.promise) {
        return inFlightEntry.promise
    }

    const payload = {
        channel: 'ptk_background_iast2content_modules',
        active: true,
        iastModules: modules,
        iastModulesSignature: modulesSignature,
        scanStrategy: iastScanStrategy
    }

    let sendPromise = null
    const finalizeSend = (result) => {
        const trackedEntry = inFlightIastModuleSendByTab.get(tabId)
        if (trackedEntry?.signature === modulesSignature && trackedEntry?.promise === sendPromise) {
            inFlightIastModuleSendByTab.delete(tabId)
        }
        return result
    }

    sendPromise = new Promise((resolve) => {
        const performSend = (sendAttempt) => {
            try {
                rt.tabs.sendMessage(
                    tabId,
                    payload,
                    () => {
                        const err = rt.runtime.lastError
                        if (err) {
                            console.warn('[PTK IAST BG] Error sending IAST modules to tab', tabId, err.message)
                            if (sendAttempt < 5) {
                                setTimeout(() => {
                                    performSend(sendAttempt + 1)
                                }, 700)
                                return
                            }
                            resolve(finalizeSend({
                                ok: false,
                                error: err.message,
                                signature: modulesSignature
                            }))
                            return
                        }

                        lastIastModuleDeliveryByTab.set(tabId, {
                            signature: modulesSignature,
                            deliveredAt: Date.now()
                        })
                        resolve(finalizeSend({
                            ok: true,
                            signature: modulesSignature
                        }))
                    }
                )
            } catch (e) {
                console.error('[PTK IAST BG] Exception sending IAST modules to tab', tabId, e)
                resolve(finalizeSend({
                    ok: false,
                    error: e?.message || String(e),
                    signature: modulesSignature
                }))
            }
        }

        performSend(attempt)
    })

    inFlightIastModuleSendByTab.set(tabId, {
        signature: modulesSignature,
        promise: sendPromise
    })

    try {
        return await sendPromise
    } catch (e) {
        console.error('[PTK IAST BG] Exception sending IAST modules to tab', tabId, e)
        return {
            ok: false,
            error: e?.message || String(e),
            signature: modulesSignature
        }
    }
}


const worker = self

async function refreshFinishedDastAnalysisIfNeeded() {
    const dast = worker?.ptk_app?.dast || worker?.ptk_app?.rattacker
    if (!dast || typeof dast !== "object") return
    if (dast?.engine?.isRunning === true) return
    const scanResult = dast?.scanResult
    if (!(scanResult?.finishedAt || scanResult?.finished)) return
    try {
        await dast.analysisService?.hydratePersistedRelatedScans?.(scanResult)
        if (typeof dast._applyAnalysis === "function") {
            dast._applyAnalysis(scanResult, true)
        }
        await dast._flushPersistScanResult?.()
    } catch (_) { }
}
const MAX_HTTP_EVENTS = 1000
const MAX_TRACKED_REQUESTS = 500
const IMPORT_TRANSFER_TTL_MS = 10 * 60 * 1000
const IMPORT_TRANSFER_MAX_ENTRIES = 2
const IAST_AGENT_SCRIPT_TAG_MAX_ATTEMPTS = 4
const IAST_AGENT_SCRIPT_TAG_RETRY_DELAYS_MS = Object.freeze([100, 250, 500])
const SEVERITY_ORDER = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
}

function isHttpUrl(url) {
    if (!url) return false
    return /^https?:\/\//i.test(String(url))
}

function buildIastAgentScriptTagLoaderSource(src, scanStrategy = 'SMART', options = {}) {
    const retryDelays = Array.isArray(options?.retryDelaysMs)
        ? options.retryDelaysMs
            .map(value => Number(value))
            .filter(value => Number.isFinite(value) && value >= 0)
        : IAST_AGENT_SCRIPT_TAG_RETRY_DELAYS_MS
    const maxAttempts = Number.isFinite(Number(options?.maxAttempts))
        ? Math.max(1, Math.floor(Number(options.maxAttempts)))
        : IAST_AGENT_SCRIPT_TAG_MAX_ATTEMPTS
    const strategy = String(scanStrategy || 'SMART').trim().toUpperCase() === 'COMPREHENSIVE'
        ? 'COMPREHENSIVE'
        : 'SMART'

    return `
        (function(src, strategy, retryDelays, maxAttempts) {
            var attempts = 0;
            function postReady() {
                try { window.postMessage({ channel: 'ptk_iast_agent_ready' }, '*'); } catch (e) {}
            }
            function postFailed(error) {
                try { window.postMessage({ channel: 'ptk_iast_agent_failed', error: error || 'script_load_failed' }, '*'); } catch (e) {}
            }
            function removeLoader() {
                try {
                    var existing = document.getElementById('__ptk_iast_agent__');
                    if (existing) existing.remove();
                } catch (e) {}
            }
            function scheduleRetry() {
                var delay = retryDelays[Math.min(attempts - 1, retryDelays.length - 1)] || 0;
                try { setTimeout(loadAgent, delay); } catch (e) { loadAgent(); }
            }
            function loadAgent() {
                try {
                    window.__PTK_IAST_SCAN_STRATEGY__ = strategy || 'SMART';
                    window.__PTK_IAST_AGENT_AUTHORIZED__ = true;
                    window.__PTK_IAST_PROVISIONAL_HOOKS__ = true;
                    if (window.__PTK_IAST_AGENT_LOADED__ === true) {
                        postReady();
                        return;
                    }
                    removeLoader();
                    attempts += 1;
                    var script = document.createElement('script');
                    script.id = '__ptk_iast_agent__';
                    script.src = src;
                    script.type = 'text/javascript';
                    script.async = true;
                    script.onload = function() {
                        postReady();
                    };
                    script.onerror = function() {
                        removeLoader();
                        if (attempts < maxAttempts) {
                            scheduleRetry();
                            return;
                        }
                        postFailed('script_load_failed');
                    };
                    (document.head || document.documentElement).appendChild(script);
                } catch (e) {
                    if (attempts < maxAttempts) {
                        attempts += 1;
                        scheduleRetry();
                        return;
                    }
                    postFailed(e && e.message ? e.message : 'script_inject_failed');
                }
            }
            loadAgent();
        })(${JSON.stringify(src || '')}, ${JSON.stringify(strategy)}, ${JSON.stringify(retryDelays)}, ${maxAttempts});
    `
}

export class ptk_iast {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_iast"
        this.devtoolsAttached = false
        this.devtoolsTarget = null
        this.onDevtoolsEvent = null
        this.agentReadyTabs = new Set()
        this.agentFailedTabs = new Map()
        this.maxHttpEvents = MAX_HTTP_EVENTS
        this.maxTrackedRequests = MAX_TRACKED_REQUESTS
        this.requestLookup = new Map()
        this._requestLookupByUrl = new Map()
        this._pagesByKey = new Map()
        this._pagesByUrl = new Map()
        this._pageFindingIds = new Map()
        this._iastFindingAggregateIndex = new Map()
        this._runtimeEventIndex = new Map()
        this.relatedScanTabs = new Map()
        this._missingPageCounter = 0
        this._persistTimer = null
        this._persistDebounceMs = 1000
        this.exportChunkStore = new ExportChunkStore({ prefix: "iast" })
        this.importTransfers = new Map()
        this.resetScanResult()
        this.modulesCatalog = null
        this.currentRulepackOverride = null
        this.currentRulepackLoadOptions = null

        this.addMessageListeners()
    }

    _getZapTimingBridge() {
        return worker?.ptk_app?.automation?.zap || null
    }

    _getCurrentZapTiming(opts = null) {
        const direct = opts?.zapTiming
        if (direct && typeof direct === 'object') {
            return direct
        }
        const stored = this.scanResult?.settings?.zapTiming
        return (stored && typeof stored === 'object') ? stored : null
    }

    _recordZapTiming(phase, opts = null, extra = null, onceKey = null) {
        const timing = this._getCurrentZapTiming(opts)
        const bridge = this._getZapTimingBridge()
        if (!timing || typeof bridge?.recordTiming !== 'function') {
            return false
        }
        return bridge.recordTiming({
            phase,
            zapid: timing?.zapid || null,
            zapSessionKey: timing?.zapSessionKey || null,
            automationSessionId: timing?.automationSessionId || null,
            tabId: Number.isInteger(timing?.tabId) ? timing.tabId : (this.scanResult?.tabId ?? null),
            targetUrl: timing?.targetUrl || this.scanResult?.targetUrl || null,
            onceKey,
            extra
        })
    }

    _cleanupImportTransfers(now = Date.now()) {
        for (const [id, entry] of this.importTransfers.entries()) {
            if (!entry || Number(entry.expiresAt || 0) <= now) {
                this.importTransfers.delete(id)
            }
        }
    }

    _enforceImportTransferLimit() {
        if (this.importTransfers.size <= IMPORT_TRANSFER_MAX_ENTRIES) return
        const sorted = Array.from(this.importTransfers.entries()).sort((a, b) => {
            const left = Number(a?.[1]?.createdAt || 0)
            const right = Number(b?.[1]?.createdAt || 0)
            return left - right
        })
        while (sorted.length && this.importTransfers.size > IMPORT_TRANSFER_MAX_ENTRIES) {
            const oldest = sorted.shift()
            if (oldest?.[0]) this.importTransfers.delete(oldest[0])
        }
    }

    _normalizeImportChunk(chunk) {
        if (chunk instanceof Uint8Array) return chunk
        if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk)
        if (ArrayBuffer.isView(chunk)) {
            return new Uint8Array(chunk.buffer.slice(chunk.byteOffset, chunk.byteOffset + chunk.byteLength))
        }
        if (Array.isArray(chunk)) return Uint8Array.from(chunk)
        if (chunk && typeof chunk === "object") return Uint8Array.from(Object.values(chunk))
        return new Uint8Array(0)
    }

    _createImportTransfer(fileMeta = {}) {
        const now = Date.now()
        const size = Number(fileMeta?.size || 0)
        const chunkCount = Number(fileMeta?.chunkCount || 0)
        const importId = `iast-import-${now}-${Math.random().toString(36).slice(2, 10)}`
        const entry = {
            id: importId,
            name: String(fileMeta?.name || ""),
            type: String(fileMeta?.type || ""),
            size,
            chunkCount,
            createdAt: now,
            expiresAt: now + IMPORT_TRANSFER_TTL_MS,
            chunks: new Array(chunkCount).fill(null),
            receivedChunks: 0,
            receivedBytes: 0
        }
        this.importTransfers.set(importId, entry)
        this._enforceImportTransferLimit()
        return entry
    }

    _getImportTransfer(importId) {
        this._cleanupImportTransfers()
        const key = String(importId || "")
        if (!key) return null
        return this.importTransfers.get(key) || null
    }

    _deleteImportTransfer(importId) {
        const key = String(importId || "")
        if (key) this.importTransfers.delete(key)
    }

    async init() {
        if (!this.isScanRunning) {
            const stored = await ptk_storage.getItem(this.storageKey) || {}
            if (stored && ((stored.scanResult) || Object.keys(stored).length > 0)) {
                const payload = this._extractPersistedData(stored)
                const storedScan = payload?.scanResult && typeof payload.scanResult === "object"
                    ? payload.scanResult
                    : null
                const storedScanId = String(storedScan?.scanId || "")
                const currentScanId = String(this.scanResult?.scanId || this.currentScanId || "")
                const currentFindings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0
                const currentRequests = Array.isArray(this.scanResult?.requests) ? this.scanResult.requests.length : 0
                const currentRuntimeEvents = Array.isArray(this.scanResult?.runtimeEvents) ? this.scanResult.runtimeEvents.length : 0
                const currentHasRenderableData = currentFindings > 0 || currentRequests > 0 || currentRuntimeEvents > 0
                if (!currentHasRenderableData || !storedScanId || storedScanId !== currentScanId) {
                    await this.normalizeScanResult(stored)
                }
            }
        }
    }

    resetScanResult() {
        this.unregisterScript()
        this.detachDevtoolsDebugger()
        this.isScanRunning = false
        if (this.currentScanId) {
            scanResultStore.deleteScan(this.currentScanId)
        }
        this.scanResult = this.getScanResultSchema()
        this.currentScanId = this.scanResult?.scanId || null
        this.currentRulepackOverride = null
        this.requestLookup = new Map()
        this._requestLookupByUrl = new Map()
        this._iastFindingAggregateIndex = new Map()
        this.relatedScanTabs = new Map()
        this._resetRuntimeEventIndex()
        this._resetPageIndexes()
        if (this._persistTimer) {
            clearTimeout(this._persistTimer)
            this._persistTimer = null
        }
    }

    async getDefaultModules(rulepack = null) {
        try {
            const loaded = rulepack || await loadIastModules(this.currentRulepackLoadOptions || {})
            const modules = Array.isArray(loaded?.modules) ? loaded.modules : []
            return JSON.parse(JSON.stringify(modules))
        } catch (err) {
            console.warn('[PTK IAST] Failed to load default modules', err)
            return []
        }
    }

    getScanResultSchema({ scanId = null, host = null, startedAt = null } = {}) {
        return scanResultStore.createScan({
            engine: "IAST",
            scanId: scanId || ptk_utils.UUID(),
            host,
            startedAt: startedAt || new Date().toISOString(),
            settings: {},
            extraFields: {
                httpEvents: [],
                runtimeEvents: [],
                requests: [],
                pages: [],
                files: [],
                iastTelemetry: {
                    activation: null,
                    automation: buildDefaultIastAutomationTelemetry(),
                    noise: null
                }
            }
        })
    }

    _refreshIastTelemetry() {
        const existing = this.scanResult?.iastTelemetry && typeof this.scanResult.iastTelemetry === 'object'
            ? this.scanResult.iastTelemetry
            : {}
        const activation = existing.activation && typeof existing.activation === 'object'
            ? existing.activation
            : null
        const automation = existing.automation && typeof existing.automation === 'object'
            ? buildDefaultIastAutomationTelemetry(existing.automation)
            : buildDefaultIastAutomationTelemetry({
                scanStrategy: this.scanResult?.settings?.iastScanStrategy || iastScanStrategy,
                expectedTabId: this.scanResult?.tabId ?? null
            })
        const noise = computeIastNoiseTelemetry(this.scanResult || {})
        this.scanResult.iastTelemetry = {
            activation: cloneIastValue(activation, null),
            automation,
            noise
        }
    }

    _updateIastAutomationTelemetry(patch = {}, { persist = false, immediate = false } = {}) {
        if (!this.scanResult) return false
        const existingTelemetry = this.scanResult.iastTelemetry && typeof this.scanResult.iastTelemetry === 'object'
            ? this.scanResult.iastTelemetry
            : {}
        const previous = existingTelemetry.automation && typeof existingTelemetry.automation === 'object'
            ? existingTelemetry.automation
            : buildDefaultIastAutomationTelemetry({
                scanStrategy: this.scanResult?.settings?.iastScanStrategy || iastScanStrategy,
                expectedTabId: this.scanResult?.tabId ?? null
            })
        const next = buildDefaultIastAutomationTelemetry(Object.assign({}, previous, patch, {
            scanStrategy: patch.scanStrategy || previous.scanStrategy || this.scanResult?.settings?.iastScanStrategy || iastScanStrategy,
            expectedTabId: patch.expectedTabId ?? previous.expectedTabId ?? this.scanResult?.tabId ?? null,
            lastUpdatedAt: patch.lastUpdatedAt || Date.now()
        }))
        if (JSON.stringify(previous) === JSON.stringify(next)) return false
        this.scanResult.iastTelemetry = Object.assign({}, existingTelemetry, {
            automation: next,
            activation: existingTelemetry.activation || null,
            noise: existingTelemetry.noise || computeIastNoiseTelemetry(this.scanResult || {})
        })
        if (persist) {
            this.updateScanResult({ persist, immediate })
        }
        return true
    }

    _incrementIastAutomationTelemetry(counterName, patch = {}, opts = {}) {
        const existing = this.scanResult?.iastTelemetry?.automation || {}
        const nextValue = Number(existing?.[counterName] || 0) + 1
        return this._updateIastAutomationTelemetry(Object.assign({}, patch, {
            [counterName]: nextValue
        }), opts)
    }

    _recordIastModuleSendResult(result = null, opts = {}) {
        const normalized = result && typeof result === 'object'
            ? {
                ok: result.ok !== false,
                skipped: result.skipped === true,
                reason: result.reason || null,
                error: result.error || null,
                signature: result.signature || null
            }
            : {
                ok: false,
                skipped: false,
                reason: null,
                error: 'no_result',
                signature: null
            }
        const existing = this.scanResult?.iastTelemetry?.automation || {}
        const patch = {
            lastModuleSendResult: normalized,
            scanStrategy: opts.scanStrategy || existing.scanStrategy || this.scanResult?.settings?.iastScanStrategy || iastScanStrategy
        }
        if (normalized.ok && normalized.skipped) {
            patch.modulesSentSkipped = Number(existing.modulesSentSkipped || 0) + 1
        } else if (normalized.ok) {
            patch.modulesSentOk = Number(existing.modulesSentOk || 0) + 1
        } else {
            patch.modulesSentError = Number(existing.modulesSentError || 0) + 1
        }
        this._updateIastAutomationTelemetry(patch, {
            persist: opts.persist === true,
            immediate: opts.immediate === true
        })
    }

    _updateRuntimeHealthTelemetry(health, { persist = true, immediate = false } = {}) {
        if (!this.scanResult) return false
        const existingTelemetry = this.scanResult.iastTelemetry && typeof this.scanResult.iastTelemetry === 'object'
            ? this.scanResult.iastTelemetry
            : {}
        const activation = existingTelemetry.activation && typeof existingTelemetry.activation === 'object'
            ? cloneIastValue(existingTelemetry.activation, {})
            : {}
        const previous = activation.runtimeHealth && typeof activation.runtimeHealth === 'object'
            ? activation.runtimeHealth
            : buildDefaultIastRuntimeHealthTelemetry()
        const next = buildDefaultIastRuntimeHealthTelemetry(Object.assign({}, previous, cloneIastValue(health, {})))
        const previousSignature = JSON.stringify(previous)
        const nextSignature = JSON.stringify(next)
        if (previousSignature === nextSignature) {
            return false
        }
        activation.runtimeHealth = next
        this.scanResult.iastTelemetry = Object.assign({}, existingTelemetry, {
            activation,
            noise: existingTelemetry.noise || computeIastNoiseTelemetry(this.scanResult || {})
        })
        this.updateScanResult({ persist, immediate })
        return true
    }

    persistScanResult() {
        const scanId = this.scanResult?.scanId || this.currentScanId
        const source = scanId ? scanResultStore.exportScanResult(scanId) : this.scanResult
        const cloned = this._cloneForStorage(source, { dropTabId: true }) || {}
        if (Array.isArray(cloned.rawFindings)) {
            delete cloned.rawFindings
        }
        return ptk_storage.setItem(this.storageKey, cloned)
    }

    _schedulePersistScanResult() {
        if (this._persistTimer) return
        this._persistTimer = setTimeout(() => {
            this._persistTimer = null
            // Debounce storage writes to reduce MV2 overhead.
            this.persistScanResult()
        }, this._persistDebounceMs)
    }

    _flushPersistScanResult() {
        if (this._persistTimer) {
            clearTimeout(this._persistTimer)
            this._persistTimer = null
        }
        return this.persistScanResult()
    }

    _cloneForStorage(value, { dropTabId = false } = {}) {
        try {
            const cloned = JSON.parse(JSON.stringify(value ?? (Array.isArray(value) ? [] : {})))
            if (dropTabId && cloned && typeof cloned === "object") {
                delete cloned.tabId
            }
            return cloned
        } catch (_) {
            return value
        }
    }

    _getPublicScanResult() {
        const scanId = this.scanResult?.scanId || this.currentScanId
        const exported = scanId ? scanResultStore.exportScanResult(scanId) : this.scanResult
        const clone = this._cloneForStorage(exported, { dropTabId: true })
        if (clone && typeof clone === "object") {
            clone.__normalized = true
        }
        return clone
    }

    _extractPersistedData(raw) {
        const fallback = { scanResult: this.getScanResultSchema(), rawFindings: [] }
        if (!raw || typeof raw !== "object") {
            return fallback
        }
        let scanPayload = null
        let legacyRaw = []
        if (raw.scanResult && typeof raw.scanResult === "object") {
            scanPayload = raw.scanResult
            legacyRaw = Array.isArray(raw.rawFindings) ? raw.rawFindings : []
        } else if (raw.engine || raw.version || Array.isArray(raw.findings)) {
            scanPayload = raw
        } else {
            scanPayload = raw
            legacyRaw = Array.isArray(raw.rawFindings) ? raw.rawFindings : Array.isArray(raw.items) ? raw.items : []
        }
        const scanClone = this._cloneForStorage(scanPayload)
        const embeddedRaw = Array.isArray(scanClone?.rawFindings) ? scanClone.rawFindings : []
        return {
            scanResult: scanClone,
            rawFindings: this._cloneForStorage(embeddedRaw.length ? embeddedRaw : legacyRaw)
        }
    }

    async reset() {
        this.resetScanResult()
        await ptk_storage.setItem(this.storageKey, {})
    }

    _normalizeTabId(tabId) {
        const numeric = Number(tabId)
        return Number.isInteger(numeric) && numeric >= 0 ? numeric : null
    }

    _primaryScanTabId() {
        return this._normalizeTabId(this.scanResult?.tabId)
    }

    isTrackedScanTab(tabId) {
        const normalized = this._normalizeTabId(tabId)
        if (!this.isScanRunning || normalized === null) return false
        const primary = this._primaryScanTabId()
        return normalized === primary || this.relatedScanTabs?.has?.(normalized) === true
    }

    _trackedScanTabIds() {
        const ids = []
        const primary = this._primaryScanTabId()
        if (primary !== null) ids.push(primary)
        for (const tabId of this.relatedScanTabs?.keys?.() || []) {
            if (!ids.includes(tabId)) ids.push(tabId)
        }
        return ids
    }

    getRelatedScanTabMeta(tabId) {
        const normalized = this._normalizeTabId(tabId)
        if (normalized === null) return null
        return this.relatedScanTabs?.get?.(normalized) || null
    }

    registerRelatedScanTab(tabId, meta = {}) {
        const normalized = this._normalizeTabId(tabId)
        const primary = this._primaryScanTabId()
        if (!this.isScanRunning || normalized === null || primary === null || normalized === primary) {
            return false
        }
        const parentTabId = this._normalizeTabId(meta?.parentTabId)
        if (parentTabId !== null && parentTabId !== primary) {
            return false
        }
        const now = Date.now()
        const existing = this.relatedScanTabs.get(normalized) || {}
        this.relatedScanTabs.set(normalized, Object.assign({}, existing, {
            tabId: normalized,
            parentTabId: primary,
            role: String(meta?.role || existing.role || 'ptk_child_tab'),
            sourceEngine: String(meta?.sourceEngine || existing.sourceEngine || 'DAST'),
            url: typeof meta?.url === 'string' ? meta.url : (existing.url || null),
            sessionId: meta?.sessionId || existing.sessionId || null,
            createdAt: existing.createdAt || now,
            updatedAt: now
        }))
        activeIastTabs.add(normalized)
        return true
    }

    async enrollRelatedScanTab(tabId, meta = {}) {
        if (!this.registerRelatedScanTab(tabId, meta)) return false
        const normalized = this._normalizeTabId(tabId)
        clearIastModuleSendTracking(normalized)
        try {
            await browser.tabs.sendMessage(normalized, {
                channel: "ptk_background_iast2content",
                type: "clean iast result"
            }).catch(() => { })
        } catch (_) { }
        try {
            await this.injectIastAgent(normalized, this.scanResult?.settings?.iastScanStrategy || 'SMART')
        } catch (err) {
            this.agentFailedTabs.set(normalized, err?.message || String(err))
        }
        const moduleSendResult = await sendIastModulesToContent(normalized, 1, this.currentRulepackLoadOptions || {})
        this._recordIastModuleSendResult(moduleSendResult, {
            scanStrategy: this.scanResult?.settings?.iastScanStrategy || 'SMART'
        })
        return true
    }

    releaseRelatedScanTab(tabId) {
        const normalized = this._normalizeTabId(tabId)
        if (normalized === null) return false
        this.relatedScanTabs.delete(normalized)
        activeIastTabs.delete(normalized)
        this.agentReadyTabs.delete(normalized)
        this.agentFailedTabs.delete(normalized)
        clearIastModuleSendTracking(normalized)
        return true
    }

    _applyRelatedTabEvidence(finding, tabId) {
        const meta = this.getRelatedScanTabMeta(tabId)
        if (!meta || !finding || typeof finding !== 'object') return finding
        if (!finding.evidence || typeof finding.evidence !== 'object') finding.evidence = {}
        if (!finding.evidence.iast || typeof finding.evidence.iast !== 'object') finding.evidence.iast = {}
        finding.evidence.iast.automationTab = {
            tabId: meta.tabId,
            parentTabId: meta.parentTabId,
            role: meta.role,
            sourceEngine: meta.sourceEngine,
            url: meta.url || null
        }
        return finding
    }

    _applyRelatedTabRuntimeSignal(signal, tabId) {
        const meta = this.getRelatedScanTabMeta(tabId)
        if (!meta || !signal || typeof signal !== 'object') return signal
        return Object.assign({}, signal, {
            automationTab: {
                tabId: meta.tabId,
                parentTabId: meta.parentTabId,
                role: meta.role,
                sourceEngine: meta.sourceEngine,
                url: meta.url || null
            }
        })
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    addListeners() {
        this.onRemoved = this.onRemoved.bind(this)
        browser.tabs.onRemoved.addListener(this.onRemoved)

        this.onUpdated = this.onUpdated.bind(this)
        browser.tabs.onUpdated.addListener(this.onUpdated)

        this.onCompleted = this.onCompleted.bind(this)
        browser.webRequest.onCompleted.addListener(
            this.onCompleted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )
    }

    async onUpdated(tabId, info, tab) {
        if (info?.status === 'loading' || typeof info?.url === 'string') {
            clearIastModuleSendTracking(tabId)
        }
    }

    removeListeners() {
        browser.tabs.onRemoved.removeListener(this.onRemoved)
        browser.tabs.onUpdated.removeListener(this.onUpdated)
        browser.webRequest.onCompleted.removeListener(this.onCompleted)
    }

    onRemoved(tabId, info) {
        clearIastModuleSendTracking(tabId)
        if (this.relatedScanTabs?.has?.(Number(tabId))) {
            this.releaseRelatedScanTab(tabId)
            return
        }
        if (this.scanResult?.tabId == tabId) {
            this.scanResult.tabId = null
            this.isScanRunning = false
            this.detachDevtoolsDebugger()
        }
    }

    onCompleted(response) {
        if (!this.isScanRunning) return
        if (!this.isTrackedScanTab(response.tabId)) return

        if (this.scanResult.host) {
            try {
                const url = new URL(response.url)
                if (url.host !== this.scanResult.host) return
            } catch (e) {
                // ignore malformed URLs
            }
        }
        if (!isHttpUrl(response.url)) return

        const evt = {
            type: "http",
            time: Date.now(),
            requestId: response.requestId,
            url: response.url,
            method: response.method || null,
            status: response.statusCode,
            ip: response.ip || null,
            fromCache: !!response.fromCache,
            tabId: response.tabId,
            host: this.scanResult.host
        }

        this.recordHttpEvent(evt)
    }

    onMessage(message, sender, sendResponse) {

        if (message.channel == "ptk_popup2background_iast") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (message.channel == "ptk_content2iast") {

            if (message.type == 'check') {
                //console.log('check iast')
                if (this.isTrackedScanTab(sender?.tab?.id))
                    return Promise.resolve({ loadAgent: true })
                else
                    return Promise.resolve({ loadAgent: false })
            }
        }

        if (message.channel == "ptk_content_iast2background_iast") {

            if (message.type == 'finding_report') {
                const senderTabId = sender?.tab?.id
                if (this.isTrackedScanTab(senderTabId)) {
                    this._incrementIastAutomationTelemetry('findingReportsAccepted', {
                        lastSenderTabId: senderTabId
                    })
                    try {
                        const finding = createFindingFromIAST(message.finding, {
                            scanId: this.scanResult.scanId,
                            host: this.scanResult.host,
                            tabId: senderTabId
                        })
                        this._applyRelatedTabEvidence(finding, senderTabId)
                        this.addOrUpdateFinding(finding)
                    } catch (e) {
                        console.warn('[PTK IAST][background] createFindingFromIAST failed', e)
                    }
                } else {
                    const reason = this.isScanRunning ? 'tab_mismatch' : 'inactive_scan'
                    this._incrementIastAutomationTelemetry(
                        reason === 'tab_mismatch' ? 'findingReportsDroppedTabMismatch' : 'findingReportsDroppedInactive',
                        {
                            lastSenderTabId: senderTabId,
                            lastDroppedReason: reason
                        }
                    )
                }
                return
            }

            if (message.type === 'runtime_signal') {
                const senderTabId = sender?.tab?.id
                if (this.isTrackedScanTab(senderTabId)) {
                    this._incrementIastAutomationTelemetry('runtimeSignalsAccepted', {
                        lastSenderTabId: senderTabId
                    })
                    this.addOrUpdateRuntimeSignal(this._applyRelatedTabRuntimeSignal(message.signal, senderTabId))
                } else {
                    const reason = this.isScanRunning ? 'tab_mismatch' : 'inactive_scan'
                    this._incrementIastAutomationTelemetry(
                        reason === 'tab_mismatch' ? 'runtimeSignalsDroppedTabMismatch' : 'runtimeSignalsDroppedInactive',
                        {
                            lastSenderTabId: senderTabId,
                            lastDroppedReason: reason
                        }
                    )
                }
                return
            }

            if (message.type === 'runtime_health') {
                if (this.isScanRunning && this.scanResult?.tabId == sender?.tab?.id) {
                    this._incrementIastAutomationTelemetry('runtimeHealthCount', {
                        lastSenderTabId: sender?.tab?.id
                    })
                    this._recordZapTiming('iast.runtime.health.first', null, {
                        state: message?.health?.state || null
                    }, 'iast.runtime.health.first')
                    if (this._updateRuntimeHealthTelemetry(message.health, { persist: true, immediate: false })) {
                        this.broadcastScanUpdate()
                    }
                }
                return
            }

            if (message.type === 'agent_ready') {
                const tabId = sender?.tab?.id
                if (tabId != null) {
                    this.agentReadyTabs.add(tabId)
                    this.agentFailedTabs.delete(tabId)
                    this._incrementIastAutomationTelemetry('agentReadyCount', {
                        lastSenderTabId: tabId
                    })
                    if (this.isScanRunning && this.scanResult?.tabId == tabId) {
                        if (this._updateRuntimeHealthTelemetry({
                            state: 'normal',
                            error: null,
                            updatedAt: Date.now()
                        }, { persist: true, immediate: false })) {
                            this.broadcastScanUpdate()
                        }
                    }
                    sendIastModulesToContent(tabId, 1, this.currentRulepackLoadOptions || {})
                        .then(result => this._recordIastModuleSendResult(result))
                        .catch(err => this._recordIastModuleSendResult({ ok: false, error: err?.message || String(err) }))
                }
                return
            }

            if (message.type === 'agent_failed') {
                const tabId = sender?.tab?.id
                if (tabId != null) {
                    this.agentReadyTabs.delete(tabId)
                    this.agentFailedTabs.set(tabId, message?.error || 'agent_load_failed')
                    this._incrementIastAutomationTelemetry('agentFailedCount', {
                        lastSenderTabId: tabId,
                        lastDroppedReason: message?.error || 'agent_load_failed'
                    }, { persist: true, immediate: true })
                    if (this.isScanRunning && this.scanResult?.tabId == tabId) {
                        if (this._updateRuntimeHealthTelemetry({
                            state: 'agent_failed',
                            error: message?.error || 'agent_load_failed',
                            updatedAt: Date.now()
                        }, { persist: true, immediate: true })) {
                            this.broadcastScanUpdate()
                        }
                    }
                    try { console.warn('[PTK IAST] Agent load failed for tab', tabId, message?.error || 'agent_load_failed') } catch (_) { }
                }
                return
            }
        }

        if (message.channel === "ptk_content_iast2background_request_modules") {
            ;(async () => {
                try {
                    const tabId = sender?.tab?.id
                    if (!this.isTrackedScanTab(tabId)) {
                        const reason = this.isScanRunning ? 'tab_mismatch' : 'inactive_scan'
                        sendResponse && sendResponse({
                            active: false,
                            reason,
                            iastModules: null,
                            iastModulesSignature: null,
                            scanStrategy: iastScanStrategy
                        })
                        return
                    }
                    const modules = await loadIastModules(this.currentRulepackLoadOptions || {})
                    if (!modules) {
                        console.warn('[PTK IAST BG] No IAST modules available for request')
                        sendResponse && sendResponse({
                            active: true,
                            iastModules: null,
                            iastModulesSignature: null,
                            scanStrategy: iastScanStrategy
                        })
                        return
                    }
                    //console.log('[PTK IAST BG] Content requested IAST modules for tab', tabId)
                    sendResponse && sendResponse({
                        active: true,
                        iastModules: modules,
                        iastModulesSignature: buildIastModulesSignature(modules, iastScanStrategy),
                        scanStrategy: iastScanStrategy
                    })
                } catch (err) {
                    console.warn('[PTK IAST BG] Failed to load IAST modules', err)
                    sendResponse && sendResponse({
                        active: true,
                        iastModules: null,
                        iastModulesSignature: null,
                        scanStrategy: iastScanStrategy,
                        error: err?.message || String(err)
                    })
                }
            })()
            return true
        }
    }

    updateScanResult({ persist = true, immediate = false } = {}) {
        if (!this.scanResult) {
            this.scanResult = this.getScanResultSchema()
            this.currentScanId = this.scanResult?.scanId || null
        }
        if (!this.scanResult.stats || typeof this.scanResult.stats !== "object") {
            this.scanResult.stats = { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        }
        this.scanResult.stats.requestsCount = Array.isArray(this.scanResult.requests)
            ? this.scanResult.requests.length
            : 0
        this._refreshIastTelemetry()
        if (persist) {
            if (immediate) {
                this._flushPersistScanResult()
            } else {
                this._schedulePersistScanResult()
            }
        }
    }

    async msg_init(message) {
        await this.init()
        const response = {
            scanResult: this._getPublicScanResult(),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab
        }
        const scanResult = response.scanResult || {}
        const hasRenderableData = (Array.isArray(scanResult.findings) && scanResult.findings.length > 0)
            || (Array.isArray(scanResult.items) && scanResult.items.length > 0)
            || (Array.isArray(scanResult.vulns) && scanResult.vulns.length > 0)
        response.viewState = response.isScanRunning ? 'running' : (hasRenderableData ? 'idle_with_data' : 'idle_empty')
        response.policyState = getIastPortalPolicyState()
        response.rulepackSelection = !response.isScanRunning && !hasRenderableData
            ? getIastPortalSelection()
            : buildIastRulepackSelectionFromScan(scanResult)
        return Promise.resolve(response)
    }

    async msg_get_default_modules(message) {
        const configuredRulepackOptions = { variant: null }
        const configuredRulepack = await loadIastModules(configuredRulepackOptions)
        return Promise.resolve({
            success: true,
            default_modules: await this.getDefaultModules(configuredRulepack),
            rulepackSelection: buildIastRulepackSelectionSummary(
                configuredRulepack,
                configuredRulepackOptions
            ),
            policyState: getIastPortalPolicyState()
        })
    }


    async msg_reset(message) {
        await this.reset()
        return Promise.resolve({
            scanResult: this._getPublicScanResult(),
            activeTab: worker.ptk_app.proxy.activeTab,
            rulepackSelection: getIastPortalSelection(),
            policyState: getIastPortalPolicyState()
        })
    }

    async msg_get_policy_state() {
        return Promise.resolve({
            success: true,
            policyState: getIastPortalPolicyState(),
            rulepackSelection: getIastPortalSelection()
        })
    }

    async msg_load_policy_metadata() {
        const apiKey = getPortalApiKey()
        if (!apiKey) {
            return Promise.resolve({
                success: false,
                error: "missing_api_key",
                policyState: getIastPortalPolicyState()
            })
        }
        try {
            const policyState = await portalPolicyRuntimeStore.loadMetadata({ apiKey, engine: 'IAST' })
            return {
                success: true,
                policyState
            }
        } catch (err) {
            return {
                success: false,
                error: err?.message || String(err),
                policyState: getIastPortalPolicyState()
            }
        }
    }

    async msg_select_policy(message) {
        try {
            const apiKey = getPortalApiKey()
            const policyState = await portalPolicyRuntimeStore.selectPolicy({
                engine: 'IAST',
                policyId: message?.policyId,
                policyName: message?.policyName || null,
                apiKey: apiKey || null
            })
            return {
                success: true,
                policyState,
                rulepackSelection: getIastPortalSelection(),
                default_modules: await this.getDefaultModules(await loadIastModules({ variant: null }))
            }
        } catch (err) {
            return {
                success: false,
                error: err?.message || String(err),
                policyState: getIastPortalPolicyState()
            }
        }
    }

    async msg_clear_policy() {
        const policyState = portalPolicyRuntimeStore.clearPolicy('IAST')
        const configuredRulepack = await loadIastModules({ resetCache: true })
        return Promise.resolve({
            success: true,
            policyState,
            rulepackSelection: getIastPortalSelection(),
            default_modules: await this.getDefaultModules(configuredRulepack)
        })
    }

    async msg_loadfile(message) {
        this.reset()
        const parsed = await parseUploadedScanFile(message?.file)
        if (!parsed?.ok || !parsed?.json) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        return this.msg_save({ json: JSON.stringify(parsed.json) })
    }

    async msg_loadfile_init(message) {
        const fileMeta = message?.fileMeta || {}
        const size = Number(fileMeta?.size || 0)
        const chunkCount = Number(fileMeta?.chunkCount || 0)
        if (!size || size <= 0 || !chunkCount || chunkCount <= 0) {
            throw new Error("Invalid file payload.")
        }
        this._cleanupImportTransfers()
        const entry = this._createImportTransfer(fileMeta)
        return {
            success: true,
            importId: entry.id,
            chunkCount: entry.chunkCount,
            size: entry.size
        }
    }

    async msg_loadfile_chunk(message) {
        const entry = this._getImportTransfer(message?.importId)
        if (!entry) {
            throw new Error("Import transfer expired.")
        }
        const index = Number(message?.index)
        if (!Number.isInteger(index) || index < 0 || index >= entry.chunkCount) {
            throw new Error("Invalid file payload.")
        }
        const normalized = this._normalizeImportChunk(message?.chunk)
        if (!normalized?.byteLength) {
            throw new Error("Invalid file payload.")
        }
        const previous = entry.chunks[index]
        if (previous?.byteLength) {
            entry.receivedBytes -= previous.byteLength
        } else {
            entry.receivedChunks += 1
        }
        entry.chunks[index] = normalized
        entry.receivedBytes += normalized.byteLength
        entry.expiresAt = Date.now() + IMPORT_TRANSFER_TTL_MS
        return {
            success: true,
            importId: entry.id,
            index,
            receivedChunks: entry.receivedChunks,
            receivedBytes: entry.receivedBytes
        }
    }

    async msg_loadfile_finish(message) {
        const entry = this._getImportTransfer(message?.importId)
        if (!entry) {
            throw new Error("Import transfer expired.")
        }
        try {
            if (entry.receivedChunks !== entry.chunkCount || entry.chunks.some(chunk => !chunk?.byteLength)) {
                throw new Error("Incomplete file payload.")
            }
            const totalBytes = entry.chunks.reduce((sum, chunk) => sum + Number(chunk?.byteLength || 0), 0)
            const combined = new Uint8Array(totalBytes)
            let offset = 0
            for (const chunk of entry.chunks) {
                combined.set(chunk, offset)
                offset += chunk.byteLength
            }
            const parsed = await parseUploadedScanFile({
                name: entry.name,
                type: entry.type,
                size: entry.size || combined.byteLength,
                bytes: Array.from(combined)
            })
            if (!parsed?.ok || !parsed?.json) {
                throw new Error("Wrong format or empty scan result")
            }
            return this.msg_save({ json: JSON.stringify(parsed.json) })
        } finally {
            this._deleteImportTransfer(entry.id)
        }
    }

    async msg_release_import(message) {
        this._deleteImportTransfer(message?.importId)
        return { success: true }
    }

    async msg_save(message) {
        let res = JSON.parse(message.json)
        const isIast = (typeof res.engine === "string" && res.engine.toUpperCase() === "IAST") ||
            (typeof res.type === "string" && res.type.toLowerCase() === "iast")
        const hasFindings = Array.isArray(res.findings) && res.findings.length > 0
        const hasLegacyItems = Array.isArray(res.items) && res.items.length > 0
        if (!isIast || (!hasFindings && !hasLegacyItems)) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        this.reset()
        await loadIastModules()
        await this.normalizeScanResult(res)
        this.updateScanResult({ persist: true, immediate: true })
        const configuredRulepackOptions = buildConfiguredIastRulepackLoadOptions()
        const configuredRulepack = await loadIastModules(configuredRulepackOptions)
        const defaultModules = await this.getDefaultModules(configuredRulepack)
        return {
            scanResult: this._getPublicScanResult(),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab,
            default_modules: defaultModules,
            rulepackSelection: buildIastRulepackSelectionFromScan(this._getPublicScanResult())
        }
    }

    async msg_export_scan_result(message) {
        const scanId = this.scanResult?.scanId || this.currentScanId || null
        if (!scanId) return null
        try {
            const payload = buildExportScanResult(scanId, {
                target: message?.target || "download",
                includeSecrets: message?.includeSecrets === true,
                scanResult: this.scanResult
            })
            if (!payload) return null
            const compressed = await compressScanPayload(payload)
            const descriptor = this.exportChunkStore.createEntry({
                bytes: compressed.body,
                fileName: message?.fileName || "PTK_IAST_scan.json",
                contentType: compressed.contentType,
                compression: compressed.compression,
                owner: message?.owner || null
            })
            if (!descriptor) {
                return { success: false, error: "empty_export_payload" }
            }
            return {
                success: true,
                exportMode: "chunked",
                ...descriptor
            }
        } catch (err) {
            console.error("[PTK IAST] Failed to export scan result", err)
            throw err
        }
    }

    async msg_export_scan_chunk(message) {
        const chunk = this.exportChunkStore.getChunk(message?.exportId, message?.index, message?.owner || null)
        if (!chunk) {
            return { success: false, error: "export_not_found_or_expired" }
        }
        return {
            success: true,
            exportMode: "chunked",
            exportId: chunk.exportId,
            index: chunk.index,
            chunkCount: chunk.chunkCount,
            chunk: chunk.chunk
        }
    }

    async msg_release_export_scan(message) {
        const released = this.exportChunkStore.release(message?.exportId, message?.owner || null)
        return { success: released }
    }

    buildPortalUrl(endpoint, profile = {}) {
        return buildSharedPortalUrl(endpoint, {
            baseUrl: profile?.base_url || profile?.api_url || profile?.baseUrl || null,
            apiBase: profile?.api_base || profile?.apiBase || undefined
        })
    }

    async msg_get_projects(message) {
        await initializePortalRuntimeConfig()
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        const url = this.buildPortalUrl("/projects", profile)
        if (!url) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        return fetch(url, {
            headers: {
                Authorization: "Bearer " + apiKey,
                Accept: "application/json"
            },
            credentials: "omit",
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) return { success: true, json }
                return { success: false, json: json || { message: "Unable to load projects" } }
            })
            .catch((e) => ({ success: false, json: { message: "Error while loading projects: " + e.message } }))
    }

    async msg_save_scan(message) {
        await initializePortalRuntimeConfig()
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        let scanId = this.scanResult?.scanId || this.currentScanId || null
        let exportedScan = scanId ? scanResultStore.exportScanResult(scanId) : this.scanResult
        if (!Array.isArray(exportedScan?.findings) || !exportedScan.findings.length) {
            const stored = await ptk_storage.getItem(this.storageKey) || {}
            if (stored && ((stored.scanResult) || Object.keys(stored).length > 0)) {
                await this.normalizeScanResult(stored)
                scanId = this.scanResult?.scanId || this.currentScanId || null
                exportedScan = scanId ? scanResultStore.exportScanResult(scanId) : this.scanResult
            }
        }
        const findingCount = Array.isArray(exportedScan?.findings) ? exportedScan.findings.length : 0
        if (!findingCount) {
            return { success: false, json: { message: "Scan result is empty" } }
        }
        const url = this.buildPortalUrl("/scans", profile)
        if (!url) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const payload = buildExportScanResult(scanId, {
            target: "portal",
            scanResult: exportedScan || this.scanResult
        })
        if (!payload) {
            return { success: false, json: { message: "Scan result is empty" } }
        }
        if (message?.projectId) {
            payload.projectId = message.projectId
        }
        let compressed
        try {
            compressed = await compressScanPayload(payload)
        } catch (err) {
            return {
                success: false,
                json: { message: "Unable to compress scan payload: " + (err?.message || "compression_failed") }
            }
        }
        return fetch(url, {
            method: "POST",
            headers: {
                Authorization: "Bearer " + apiKey,
                Accept: "application/json",
                "Content-Type": compressed.contentType,
                "X-PTK-Compression": compressed.compression
            },
            credentials: "omit",
            cache: "no-cache",
            body: compressed.body
        })
            .then(async (httpResponse) => {
                if (httpResponse.status === 201) return { success: true }
                const json = await httpResponse.json().catch(() => ({ message: httpResponse.statusText }))
                return { success: false, json }
            })
            .catch((e) => ({ success: false, json: { message: "Error while saving report: " + e.message } }))
    }

    async msg_download_scans(message) {
        await initializePortalRuntimeConfig()
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        const baseUrl = this.buildPortalUrl("/scans", profile)
        if (!baseUrl) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        let requestUrl = baseUrl
        try {
            const url = new URL(baseUrl)
            if (message?.projectId) {
                url.searchParams.set("projectId", message.projectId)
            }
            const engine = message?.engine || "iast"
            if (engine) {
                url.searchParams.set("engine", engine)
            }
            requestUrl = url.toString()
        } catch (_) {
            return { success: false, json: { message: "Invalid scans endpoint." } }
        }
        return fetch(requestUrl, {
            headers: {
                Authorization: "Bearer " + apiKey,
                Accept: "application/json"
            },
            credentials: "omit",
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) return { success: true, json }
                return { success: false, json: json || { message: "Unable to load scans" } }
            })
            .catch((e) => ({ success: false, json: { message: "Error while loading scans: " + e.message } }))
    }

    async msg_download_scan_by_id(message) {
        await initializePortalRuntimeConfig()
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        if (!message?.scanId) {
            return { success: false, json: { message: "Scan identifier is required." } }
        }
        const baseUrl = this.buildPortalUrl("/scans", profile)
        if (!baseUrl) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const normalizedBase = baseUrl.replace(/\/+$/, "")
        const downloadUrl = `${normalizedBase}/${encodeURIComponent(message.scanId)}/download`
        const response = await fetch(downloadUrl, {
            headers: {
                Authorization: "Bearer " + apiKey,
                Accept: "application/gzip, application/x-gzip"
            },
            credentials: "omit",
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                if (!httpResponse.ok) {
                    const json = await httpResponse.json().catch(() => null)
                    return { success: false, json: json || { message: "Unable to download scan" } }
                }
                const parsed = await parseDownloadedScanPayload(httpResponse)
                if (!parsed?.ok || !parsed?.json) {
                    return { success: false, json: { message: "Downloaded scan payload is invalid JSON." } }
                }
                return { success: true, json: parsed.json }
            })
            .catch((e) => ({ success: false, json: { message: "Error while downloading scan: " + e.message } }))
        if (!response?.success || !response?.json) {
            return response
        }
        return this.msg_save({ json: JSON.stringify(response.json) })
    }

    msg_run_bg_scan(message) {
        return this.runBackgroundScan(message.tabId, message.host, message.scanStrategy, message?.opts || {}).then(async () => {
            const response = {
                success: true,
                isScanRunning: this.isScanRunning,
                scanResult: this._getPublicScanResult(),
                policyState: getIastPortalPolicyState(),
                rulepackSelection: this.isScanRunning
                    ? buildIastRulepackSelectionFromScan(this._getPublicScanResult())
                    : getIastPortalSelection()
            }
            if (!this.isScanRunning) {
                response.default_modules = await this.getDefaultModules()
            }
            return response
        }).catch((err) => ({
            success: false,
            error: err?.code || err?.message || 'portal_rulepack_fetch_failed',
            message: err?.portalMessage || err?.message || String(err),
            rulepackSelection: message?.opts?.rulepack
                ? buildIastRulepackSelectionSummary(null, {
                    rulepack: message?.opts?.rulepack,
                    variant: message?.opts?.variant || null
                })
                : getIastPortalSelection(),
            policyState: getIastPortalPolicyState(),
            packStatus: getIastPortalPolicyState()?.packStatus || null
        }))
    }

    async msg_stop_bg_scan(message) {
        await this.stopBackgroundScan()
        return Promise.resolve({
            scanResult: this._getPublicScanResult(),
            isScanRunning: this.isScanRunning
        })
    }

    _getZapManualEngineOptions() {
        const bridge = worker?.ptk_app?.automation?.zap
        if (!bridge || typeof bridge.getManualEngineConfig !== 'function') {
            return null
        }
        const config = bridge.getManualEngineConfig('IAST')
        return (config && typeof config === 'object') ? config : null
    }

    async runBackgroundScan(tabId, host, scanStrategy, opts = {}) {
        if (this.isScanRunning) {
            return false
        }
        const zapManualOpts = this._getZapManualEngineOptions()
        const effectiveOpts = Object.assign({}, zapManualOpts || {}, opts || {})
        const zapTiming = (effectiveOpts?.zapTiming && typeof effectiveOpts.zapTiming === 'object')
            ? Object.assign({}, effectiveOpts.zapTiming)
            : null
        const customRulepack = (effectiveOpts && typeof effectiveOpts === 'object' && effectiveOpts.rulepack && typeof effectiveOpts.rulepack === 'object')
            ? effectiveOpts.rulepack
            : null
        const selectedPortalPolicy = !customRulepack
            ? getIastSelectedPortalPolicy()
            : null
        const shouldUsePortal = !customRulepack && (
            effectiveOpts?.preferPortal === true
            || !!effectiveOpts?.policyId
            || !!selectedPortalPolicy?.id
        )
        if (shouldUsePortal && !getPortalApiKey()) {
            const err = new Error('missing_api_key')
            err.code = 'missing_api_key'
            throw err
        }
        const rulepackLoadOptions = customRulepack
            ? { rulepack: customRulepack }
            : selectedPortalPolicy
                ? {
                    preferPortal: true,
                    policyId: effectiveOpts?.policyId || selectedPortalPolicy?.id || null,
                    policyName: effectiveOpts?.policyName || selectedPortalPolicy?.name || null,
                    apiKey: getPortalApiKey()
                }
            : {
                variant: effectiveOpts?.variant || null,
                preferPortal: effectiveOpts?.preferPortal === true,
                policyId: effectiveOpts?.policyId ?? null,
                policyName: effectiveOpts?.policyName || null,
                portal: effectiveOpts?.portal && typeof effectiveOpts.portal === 'object'
                    ? effectiveOpts.portal
                    : undefined
            }
        const loadedRulepack = await loadIastModules(rulepackLoadOptions)
        const rulepackSelection = buildIastRulepackSelectionSummary(loadedRulepack, rulepackLoadOptions)
        const policyState = getIastPortalPolicyState()
        const packStatus = getIastPackStatusForSelection(rulepackSelection, policyState)
        const runtimePlan = validateIastActivationRulepack(loadedRulepack, {
            label: rulepackSelection?.label || 'IAST'
        })
        const activationTelemetry = buildIastActivationTelemetry(loadedRulepack, runtimePlan, {
            selection: rulepackSelection,
            packStatus
        })
        const policyMeta = loadedRulepack?.policy && typeof loadedRulepack.policy === 'object' ? loadedRulepack.policy : null
        this.reset()
        this.currentRulepackOverride = customRulepack
        this.currentRulepackLoadOptions = Object.assign({}, rulepackLoadOptions, zapTiming ? { zapTiming } : {})
        clearIastModuleSendTracking(tabId)
        this.agentReadyTabs.delete(tabId)
        this.agentFailedTabs.delete(tabId)
        this.isScanRunning = true
        this.scanningRequest = false
        browser.tabs.sendMessage(tabId, {
            channel: "ptk_background_iast2content",
            type: "clean iast result"
        }).catch(() => { })
        const scanId = ptk_utils.UUID()
        const started = new Date().toISOString()
        this.scanResult = this.getScanResultSchema({ scanId, host, startedAt: started })
        this.scanResult.tabId = tabId
        this.scanResult.host = host
        this.scanResult.startedAt = started
        this.scanResult.finishedAt = null
        this.scanResult.settings = Object.assign({}, this.scanResult.settings || {}, {
            iastScanStrategy: scanStrategy || 'SMART'
        })
        if (zapTiming) {
            this.scanResult.settings.zapTiming = zapTiming
            if (!this.scanResult.targetUrl && zapTiming.targetUrl) {
                this.scanResult.targetUrl = zapTiming.targetUrl
            }
            this._recordZapTiming('iast.scan.requested', zapTiming, {
                host,
                scanStrategy: scanStrategy || 'SMART'
            })
        }
        iastScanStrategy = this.scanResult.settings.iastScanStrategy
        this.currentScanId = scanId
        activeIastTabs.add(tabId)
        this.scanResult.policyId = policyMeta?.id || (rulepackLoadOptions?.policyId != null ? String(rulepackLoadOptions.policyId) : null)
        this.scanResult.settings = Object.assign({}, this.scanResult.settings || {}, {
            iastRulepackSource: customRulepack ? 'custom' : (policyMeta ? 'portal' : 'local'),
            iastPolicyName: policyMeta?.name || null,
            iastPackStatus: packStatus,
            iastPackError: cloneIastValue(policyState?.lastError, null)
        })
        if (rulepackLoadOptions?.variant) {
            this.scanResult.settings.iastRulepackVariant = String(rulepackLoadOptions.variant)
        }
        this.scanResult.iastTelemetry = {
            activation: activationTelemetry,
            automation: buildDefaultIastAutomationTelemetry({
                scanStrategy: scanStrategy || 'SMART',
                expectedTabId: tabId
            }),
            noise: computeIastNoiseTelemetry(this.scanResult)
        }
        this.broadcastScanUpdate()
        await this.registerScript(this.scanResult.settings.iastScanStrategy || 'SMART', {
            host: this.scanResult.host,
            targetUrl: this.scanResult.targetUrl || zapTiming?.targetUrl || null
        })
        this.addListeners()
        const devtoolsStartedAt = Date.now()
        await this.attachDevtoolsDebugger(tabId)
        this._recordZapTiming('iast.devtools.attach.end', zapTiming, {
            durationMs: Date.now() - devtoolsStartedAt
        })
        // Inject agent into current page using an async loader so scan start does not block on full agent evaluation.
        const injectStartedAt = Date.now()
        this._recordZapTiming('iast.agent.inject.start', zapTiming)
        try {
            await this.injectIastAgent(tabId, this.scanResult.settings.iastScanStrategy || 'SMART')
            this._recordZapTiming('iast.agent.inject.success', zapTiming, {
                durationMs: Date.now() - injectStartedAt
            })
        } catch (err) {
            this._recordZapTiming('iast.agent.inject.failure', zapTiming, {
                durationMs: Date.now() - injectStartedAt,
                error: err?.message || String(err)
            })
            throw err
        }
        const modulesSentAt = Date.now()
        const moduleSendResult = await sendIastModulesToContent(tabId, 1, this.currentRulepackLoadOptions || {})
        this._recordIastModuleSendResult(moduleSendResult, {
            persist: false,
            scanStrategy: this.scanResult.settings.iastScanStrategy || 'SMART'
        })
        this._recordZapTiming('iast.modules.sent', zapTiming, {
            durationMs: Date.now() - modulesSentAt,
            result: moduleSendResult?.ok === false ? 'error' : (moduleSendResult?.skipped ? 'skipped' : 'ok')
        })
        this.broadcastScanUpdate()
    }

    async stopBackgroundScan(options = {}) {
        const trackedTabIds = this._trackedScanTabIds()
        for (const tabId of trackedTabIds) {
            browser.tabs.sendMessage(tabId, {
                channel: "ptk_background_iast2content",
                type: "clean iast result"
            }).catch(() => { })
        }
        this.isScanRunning = false
        this.currentRulepackOverride = null
        this.currentRulepackLoadOptions = null
        for (const tabId of trackedTabIds) {
            activeIastTabs.delete(tabId)
            this.agentReadyTabs.delete(tabId)
            this.agentFailedTabs.delete(tabId)
            clearIastModuleSendTracking(tabId)
        }
        this.scanResult.tabId = null
        this.relatedScanTabs = new Map()
        this.unregisterScript()
        this.removeListeners()
        this.detachDevtoolsDebugger()
        if (this.scanResult?.scanId) {
            const finished = new Date().toISOString()
            scanResultStore.setFinished(this.scanResult.scanId, finished)
            this.scanResult.finishedAt = finished
        }
        scanResultStore._applyAnalysisSafe(this.scanResult, { force: true })
        await this._flushPersistScanResult()
        this.broadcastScanUpdate()
        if (options?.skipPostStopAnalysis !== true) {
            await refreshFinishedDastAnalysisIfNeeded()
        }
        return this.scanResult
    }

    recordHttpEvent(evt) {
        if (!evt || !isHttpUrl(evt.url)) return
        if (!this.scanResult.httpEvents) {
            this.scanResult.httpEvents = []
        }
        this.scanResult.httpEvents.push(evt)
        this.upsertRequestFromEvent(evt)
        if (this.scanResult.httpEvents.length > this.maxHttpEvents) {
            this.scanResult.httpEvents.shift()
        }
        if (!this.scanResult.stats || typeof this.scanResult.stats !== "object") {
            this.scanResult.stats = { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        }
        this.scanResult.stats.requestsCount = Array.isArray(this.scanResult.requests)
            ? this.scanResult.requests.length
            : 0
        this._schedulePersistScanResult()
    }

    _lookupAggregatedFinding(aggregateKey = null) {
        if (!aggregateKey) return null
        if (!(this._iastFindingAggregateIndex instanceof Map)) {
            this._iastFindingAggregateIndex = new Map()
        }
        const indexed = this._iastFindingAggregateIndex.get(aggregateKey)
        if (indexed) return indexed
        const findings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings : []
        const existing = findings.find((finding) => finding?.evidence?.iast?.aggregate?.key === aggregateKey) || null
        if (existing) {
            this._iastFindingAggregateIndex.set(aggregateKey, existing)
        }
        return existing
    }

    _prepareFindingAggregation(prepared = null) {
        if (!prepared?.finding) return null
        const mode = normalizeIastFindingAggregationMode(
            resolveIastFindingPresentationAggregate(prepared.ruleMeta, prepared.moduleMeta)
        )
        if (!mode) return null
        const aggregateKey = buildIastFindingAggregateKey({
            finding: prepared.finding,
            ruleMeta: prepared.ruleMeta,
            moduleMeta: prepared.moduleMeta,
            scanId: this.scanResult?.scanId || null,
            host: this.scanResult?.host || null
        })
        if (!aggregateKey) return null
        const sample = buildIastFindingAggregateSample(prepared.finding)
        applyIastFindingAggregateState(prepared.finding, {
            aggregateKey,
            mode,
            sample
        })
        return {
            mode,
            aggregateKey,
            sample
        }
    }

    addOrUpdateFinding(finding) {
        if (!finding || !this.scanResult?.scanId) return
        let prepared
        try {
            prepared = this.prepareFindingMetadata(finding)
        } catch (e) {
            try { console.warn('[PTK IAST][background] prepareFindingMetadata failed', e) } catch (_) { }
            return
        }
        if (!prepared) return
        const aggregation = this._prepareFindingAggregation(prepared)
        if (aggregation?.aggregateKey) {
            const existing = this._lookupAggregatedFinding(aggregation.aggregateKey)
            if (existing) {
                mergeIastFindingAggregateOccurrence(existing, prepared.finding, {
                    sample: aggregation.sample
                })
                const runtimeEventChanged = this._syncRuntimeEventForFinding(existing)
                if (runtimeEventChanged) {
                    scanResultStore._applyAnalysisSafe(this.scanResult, { force: true })
                }
                this._upsertPageFromFinding(existing)
                this.updateScanResult()
                this.broadcastScanDelta(existing)
                if (runtimeEventChanged) {
                    this.broadcastScanUpdate()
                }
                return
            }
        }
        const normalizedFinding = scanResultStore.upsertFinding({
            scanId: this.scanResult.scanId,
            engine: "IAST",
            finding: prepared.finding,
            moduleMeta: prepared.moduleMeta,
            ruleMeta: prepared.ruleMeta
        })
        if (normalizedFinding) {
            prepared.finding = normalizedFinding
        }
        if (aggregation?.aggregateKey && prepared.finding) {
            this._iastFindingAggregateIndex.set(aggregation.aggregateKey, prepared.finding)
        }
        const runtimeEventChanged = this._syncRuntimeEventForFinding(prepared.finding)
        if (runtimeEventChanged) {
            scanResultStore._applyAnalysisSafe(this.scanResult, { force: true })
        }
        this._upsertPageFromFinding(prepared.finding)
        this.updateScanResult()
        this.broadcastScanDelta(prepared.finding)
        if (runtimeEventChanged) {
            this.broadcastScanUpdate()
        }
    }

    addOrUpdateRuntimeSignal(signal) {
        if (!signal || typeof signal !== 'object' || !this.scanResult?.scanId) return
        const routing = signal?.routing && typeof signal.routing === 'object' ? signal.routing : null
        const url = signal?.url || signal?.location?.url || routing?.runtimeUrl || routing?.url || null
        const method = signal?.method || signal?.location?.method || 'GET'
        const sinkContext = signal?.sinkContext && typeof signal.sinkContext === 'object' ? signal.sinkContext : {}
        const event = Object.assign({}, signal, {
            engine: 'IAST',
            kind: 'iast_runtime_signal',
            id: signal?.id || `runtimeevent:${String(signal?.eventKey || '').trim()}`,
            eventKey: String(signal?.eventKey || signal?.id || '').trim(),
            severity: signal?.severity || 'info',
            confidence: Number.isFinite(Number(signal?.confidence)) ? Number(signal.confidence) : null,
            location: {
                url,
                method,
                route: signal?.route || signal?.location?.route || routing?.route || null
            },
            url,
            route: signal?.route || signal?.location?.route || routing?.route || null,
            method,
            signalFamily: signal?.signalFamily || null,
            signalCode: signal?.signalCode || null,
            sourceKind: signal?.sourceKind || null,
            sourceKey: signal?.sourceKey || null,
            sinkId: signal?.sinkId || null,
            primaryClass: signal?.primaryClass || null,
            sourceRole: signal?.sourceRole || null,
            detection: signal?.detection && typeof signal.detection === 'object' ? signal.detection : null,
            trust: signal?.trust && typeof signal.trust === 'object' ? signal.trust : null,
            sanitizers: Array.isArray(signal?.sanitizers) ? signal.sanitizers : [],
            confidenceSignals: Array.isArray(signal?.confidenceSignals) ? signal.confidenceSignals : [],
            headerName: signal?.headerName || sinkContext?.headerName || null,
            storageKey: signal?.storageKey || sinkContext?.storageKey || null,
            cookieName: signal?.cookieName || sinkContext?.cookieName || null,
            attribute: signal?.attribute || sinkContext?.attribute || null,
            isCrossOrigin: typeof signal?.isCrossOrigin === 'boolean' ? signal.isCrossOrigin : null,
            observedAt: signal?.observedAt || null,
            sinkContext: Object.keys(sinkContext).length ? sinkContext : null,
            time: Number(signal?.time || Date.now()),
            evidenceRefs: normalizeEvidenceRefs(signal?.evidenceRefs || [])
        })
        if (!event.eventKey) return
        const changed = this._upsertRuntimeEvent(event)
        if (!changed) return
        scanResultStore._applyAnalysisSafe(this.scanResult, { force: true })
        this.updateScanResult()
        this.broadcastScanUpdate()
    }

    async normalizeScanResult(raw) {
        await loadIastModules()
        const payload = this._extractPersistedData(raw || {})
        const source = payload.scanResult || {}
        const scanId = source.scanId || ptk_utils.UUID()
        this.scanResult = this.getScanResultSchema({
            scanId,
            host: source.host || null,
            startedAt: source.startedAt || source.date || new Date().toISOString()
        })
        this.scanResult.tabId = source.tabId || null
        this.scanResult.policyId = source.policyId || null
        this.scanResult.settings = source.settings || {}
        this.scanResult.httpEvents = Array.isArray(source.httpEvents) ? source.httpEvents : []
        this.scanResult.runtimeEvents = Array.isArray(source.runtimeEvents) ? source.runtimeEvents : []
        this.scanResult.iastTelemetry = source.iastTelemetry && typeof source.iastTelemetry === 'object'
            ? source.iastTelemetry
            : {
                activation: null,
                noise: null
            }
        this._rebuildRuntimeEventIndex()
        this.scanResult.requests = Array.isArray(source.requests) ? source.requests : []
        this.scanResult.pages = Array.isArray(source.pages) ? source.pages : []
        this.scanResult.files = Array.isArray(source.files) ? source.files : []
        this.scanResult.finishedAt = source.finishedAt || source.finished || null
        if (source.analysis && typeof source.analysis === "object") {
            try {
                this.scanResult.analysis = JSON.parse(JSON.stringify(source.analysis))
            } catch (_) {
                this.scanResult.analysis = source.analysis
            }
        }
        if (source.analysisVersion) {
            this.scanResult.analysisVersion = source.analysisVersion
            if (this.scanResult.analysis && !this.scanResult.analysis.version) {
                this.scanResult.analysis.version = source.analysisVersion
            }
        }
        this.currentScanId = scanId

        const hydratedFindings = Array.isArray(source.findings) ? source.findings : []
        hydratedFindings.forEach(item => {
            try {
                const prepared = this.prepareFindingMetadata(item)
                if (!prepared) return
                const normalizedFinding = scanResultStore.upsertFinding({
                    scanId,
                    engine: "IAST",
                    finding: prepared.finding,
                    moduleMeta: prepared.moduleMeta,
                    ruleMeta: prepared.ruleMeta
                })
                this._syncRuntimeEventForFinding(normalizedFinding || prepared.finding)
            } catch (err) {
                try { console.warn("[PTK IAST] Failed to hydrate finding", err) } catch (_) { }
            }
        })

        this._ingestLegacyRawFindings(Array.isArray(payload.rawFindings) ? payload.rawFindings : [])
        if (Array.isArray(source.rawFindings) && source.rawFindings.length) {
            this._ingestLegacyRawFindings(source.rawFindings)
        }
        if (Array.isArray(this.scanResult.rawFindings)) {
            delete this.scanResult.rawFindings
        }
        this.requestLookup = new Map()
        if (Array.isArray(this.scanResult.requests)) {
            this.scanResult.requests.forEach(entry => {
                if (entry?.key) {
                    this.requestLookup.set(entry.key, entry)
                }
                if (entry?.url) {
                    this._requestLookupByUrl.set(entry.url, entry)
                }
            })
        }
        this._rebuildPagesFromFindings()
        scanResultStore._applyAnalysisSafe(this.scanResult, { force: true })
        this.updateScanResult({ persist: false })
        return this.scanResult
    }

    normalizeRequestUrl(url) {
        if (!url) return ""
        try {
            const u = new URL(url)
            u.hash = ""
            return u.toString()
        } catch (e) {
            try {
                return String(url).split('#')[0]
            } catch (_) {
                return ""
            }
        }
    }

    buildRequestKey(method, url) {
        const normalizedUrl = this.normalizeRequestUrl(url)
        if (!normalizedUrl) return null
        const normalizedMethod = (method || 'GET').toUpperCase()
        return normalizedMethod + ' ' + normalizedUrl
    }

    trimTrackedRequests() {
        if (!Array.isArray(this.scanResult.requests)) return
        if (this.scanResult.requests.length <= this.maxTrackedRequests) return
        const overflow = this.scanResult.requests.length - this.maxTrackedRequests
        if (overflow <= 0) return
        const removed = this.scanResult.requests.splice(0, overflow)
        removed.forEach(entry => {
            if (entry?.key) {
                this.requestLookup.delete(entry.key)
            }
            if (entry?.url) {
                this._requestLookupByUrl.delete(entry.url)
            }
        })
    }

    _ingestLegacyRawFindings(rawList) {
        if (!Array.isArray(rawList) || !rawList.length || !this.scanResult?.scanId) return
        rawList.forEach(item => {
            if (!item) return
            try {
                const prepared = this.prepareFindingMetadata(item)
                if (!prepared) return
                const normalizedFinding = scanResultStore.upsertFinding({
                    scanId: this.scanResult.scanId,
                    engine: "IAST",
                    finding: prepared.finding,
                    moduleMeta: prepared.moduleMeta,
                    ruleMeta: prepared.ruleMeta
                })
                this._syncRuntimeEventForFinding(normalizedFinding || prepared.finding)
            } catch (e) {
                try { console.warn('[PTK IAST][background] failed to ingest legacy finding', e) } catch (_) { }
            }
        })
    }

    _resetRuntimeEventIndex() {
        this._runtimeEventIndex = new Map()
    }

    _rebuildRuntimeEventIndex() {
        this._resetRuntimeEventIndex()
        const events = Array.isArray(this.scanResult?.runtimeEvents) ? this.scanResult.runtimeEvents : []
        events.forEach((event, index) => {
            const key = String(event?.eventKey || event?.id || "").trim()
            if (!key) return
            this._runtimeEventIndex.set(key, index)
        })
    }

    _buildRuntimeEventKey(finding, evidence = {}) {
        const stable = finding?.fingerprint || finding?.id || null
        if (stable) return `iast:${stable}`
        const sinkId = evidence?.sinkId || finding?.sinkId || ""
        const primarySource = getPrimaryIastSource(evidence)
        const sourceKey = (
            evidence?.sourceKey
            || evidence?.primarySource?.key
            || evidence?.primarySource?.source
            || primarySource?.key
            || primarySource?.source
            || primarySource?.sourceId
            || evidence?.sourceId
            || evidence?.taintSource
            || finding?.taintSource
            || ""
        )
        const url = finding?.location?.url || evidence?.routing?.runtimeUrl || evidence?.routing?.url || ""
        return `iast:${sinkId}|${sourceKey}|${url}|${finding?.ruleId || ""}`
    }

    _deriveRuntimeSignalFamily({ finding, evidence, primaryClass, detectionReason }) {
        const sinkId = String(evidence?.sinkId || finding?.sinkId || "").toLowerCase()
        const category = String(finding?.category || "").toLowerCase()
        const reason = String(detectionReason || "").toLowerCase()
        const primarySource = getPrimaryIastSource(evidence)
        const sourceKind = String(evidence?.sourceKind || evidence?.primarySource?.sourceKind || primarySource?.sourceKind || primarySource?.kind || "").toLowerCase()
        if (sinkId.startsWith("storage.") || reason.includes("token") || reason.includes("jwt") || reason.includes("auth_header")) {
            return "auth_signal"
        }
        if (sinkId.startsWith("postmessage") || sinkId.startsWith("channel.") || sourceKind === "postmessage") {
            return "message_boundary"
        }
        if (sinkId.startsWith("nav.") || category === "open_redirect" || category === "link") {
            return "navigation_control"
        }
        if (sinkId.startsWith("code.") || sinkId === "document.write" || sinkId.startsWith("dom.") || category === "xss") {
            return "client_execution"
        }
        if (primaryClass === "policy_violation") {
            return "policy_violation"
        }
        return "client_runtime"
    }

    _buildRuntimeEventFromFinding(finding) {
        if (!finding || typeof finding !== "object") return null
        const evidence = getIastEvidencePayload(finding) || {}
        const primarySource = getPrimaryIastSource(evidence)
        const context = evidence?.context && typeof evidence.context === "object" ? evidence.context : {}
        const primaryClass = String(evidence?.primaryClass || "").trim().toLowerCase() || null
        const detection = evidence?.detection && typeof evidence.detection === "object" ? evidence.detection : null
        const trust = evidence?.trust && typeof evidence.trust === "object" ? evidence.trust : null
        const suppression = evidence?.suppression && typeof evidence.suppression === "object" ? evidence.suppression : null
        const sanitizerObserved = Array.isArray(context?.sanitizerObserved) ? context.sanitizerObserved : []
        const shouldEmit = (
            primaryClass === "observation"
            || primaryClass === "hybrid"
            || primaryClass === "policy_violation"
            || Boolean(detection?.reason)
            || Boolean(trust?.level || trust?.decision)
            || sanitizerObserved.length > 0
            || suppression?.suppressed === true
        )
        if (!shouldEmit) return null

        const routing = evidence?.routing && typeof evidence.routing === "object" ? evidence.routing : {}
        const url = finding?.location?.url || routing?.runtimeUrl || routing?.url || context?.url || context?.location || null
        const method = context?.method || evidence?.operation?.method || finding?.location?.method || "GET"
        const sourceKind = evidence?.sourceKind || evidence?.primarySource?.sourceKind || primarySource?.sourceKind || primarySource?.kind || null
        const sourceKey = (
            evidence?.sourceKey
            || evidence?.primarySource?.key
            || evidence?.primarySource?.source
            || primarySource?.key
            || primarySource?.source
            || primarySource?.sourceId
            || evidence?.sourceId
            || evidence?.taintSource
            || finding?.taintSource
            || null
        )
        const signalCode = detection?.reason || finding?.ruleId || primaryClass || "iast_runtime_signal"
        const signalFamily = this._deriveRuntimeSignalFamily({
            finding,
            evidence,
            primaryClass,
            detectionReason: signalCode
        })
        const eventKey = this._buildRuntimeEventKey(finding, evidence)
        const eventId = `runtimeevent:${eventKey}`
        const sinkContext = evidence?.sinkContext && typeof evidence.sinkContext === "object" ? evidence.sinkContext : {}
        const confidenceSignals = Array.isArray(evidence?.confidenceSignals) ? evidence.confidenceSignals.slice(0, 12) : []
        return {
            id: eventId,
            eventKey,
            engine: "IAST",
            kind: "iast_runtime_signal",
            signalFamily,
            signalCode,
            category: finding?.category || null,
            severity: finding?.severity || null,
            confidence: Number.isFinite(Number(finding?.confidence)) ? Number(finding.confidence) : null,
            findingId: finding?.id || null,
            findingFingerprint: finding?.fingerprint || null,
            requestId: evidence?.requestId || null,
            requestKey: finding?.requestKey || null,
            moduleId: finding?.moduleId || null,
            ruleId: finding?.ruleId || null,
            sinkId: evidence?.sinkId || finding?.sinkId || null,
            sourceKind: sourceKind || null,
            sourceKey: sourceKey || null,
            sourceRole: evidence?.sourceRole || null,
            primaryClass,
            detection,
            trust,
            suppression,
            sanitizers: sanitizerObserved,
            confidenceSignals,
            url,
            route: routing?.route || null,
            method,
            location: {
                url,
                method,
                route: routing?.route || null
            },
            routing: Object.keys(routing || {}).length ? routing : null,
            headerName: context?.headerName || sinkContext?.headerName || null,
            storageKey: context?.storageKey || sinkContext?.storageKey || context?.key || null,
            cookieName: context?.cookieName || sinkContext?.cookieName || null,
            attribute: context?.attribute || sinkContext?.attribute || null,
            isCrossOrigin: typeof context?.isCrossOrigin === "boolean"
                ? context.isCrossOrigin
                : (typeof evidence?.networkTarget?.isCrossOrigin === "boolean" ? evidence.networkTarget.isCrossOrigin : null),
            observedAt: evidence?.observedAt || null,
            sinkContext: Object.keys(sinkContext || {}).length ? sinkContext : null,
            time: Date.parse(String(finding?.updatedAt || finding?.createdAt || "")) || Date.now(),
            evidenceRefs: normalizeEvidenceRefs([
                finding?.id ? {
                    type: "finding",
                    id: finding.id,
                    loc: {
                        module: finding?.moduleId || null,
                        rule: finding?.ruleId || null,
                        severity: finding?.severity || null,
                        method
                    }
                } : null,
                evidence?.requestId ? {
                    type: "request",
                    id: evidence.requestId,
                    loc: {
                        method,
                        path: finding?.location?.url || url || null
                    }
                } : null
            ])
        }
    }

    _mergeRuntimeEvent(existing = {}, incoming = {}) {
        return Object.assign({}, existing, incoming, {
            time: Number(incoming?.time || existing?.time || Date.now()),
            evidenceRefs: normalizeEvidenceRefs([
                ...(Array.isArray(existing?.evidenceRefs) ? existing.evidenceRefs : []),
                ...(Array.isArray(incoming?.evidenceRefs) ? incoming.evidenceRefs : [])
            ]),
            confidenceSignals: Array.from(new Set([
                ...(Array.isArray(existing?.confidenceSignals) ? existing.confidenceSignals : []),
                ...(Array.isArray(incoming?.confidenceSignals) ? incoming.confidenceSignals : [])
            ])).slice(0, 12)
        })
    }

    _removeRuntimeEventByKey(eventKey) {
        const key = String(eventKey || "").trim()
        if (!key) return false
        const idx = this._runtimeEventIndex.get(key)
        if (!Number.isInteger(idx)) return false
        if (Array.isArray(this.scanResult?.runtimeEvents)) {
            this.scanResult.runtimeEvents.splice(idx, 1)
        }
        this._rebuildRuntimeEventIndex()
        return true
    }

    _upsertRuntimeEvent(event) {
        if (!event || typeof event !== "object") return false
        if (!Array.isArray(this.scanResult?.runtimeEvents)) {
            this.scanResult.runtimeEvents = []
        }
        const key = String(event?.eventKey || event?.id || "").trim()
        if (!key) return false
        const existingIdx = this._runtimeEventIndex.get(key)
        if (Number.isInteger(existingIdx) && existingIdx >= 0 && existingIdx < this.scanResult.runtimeEvents.length) {
            this.scanResult.runtimeEvents[existingIdx] = this._mergeRuntimeEvent(this.scanResult.runtimeEvents[existingIdx], event)
            return true
        }
        this.scanResult.runtimeEvents.push(event)
        this._runtimeEventIndex.set(key, this.scanResult.runtimeEvents.length - 1)
        return true
    }

    _syncRuntimeEventForFinding(finding) {
        const event = this._buildRuntimeEventFromFinding(finding)
        const eventKey = this._buildRuntimeEventKey(finding, getIastEvidencePayload(finding) || {})
        if (!event) {
            return this._removeRuntimeEventByKey(eventKey)
        }
        return this._upsertRuntimeEvent(event)
    }

    upsertRequestFromEvent(evt) {
        if (!evt) return
        if (!Array.isArray(this.scanResult.requests)) {
            this.scanResult.requests = []
        }
        const url = evt?.url
        if (!url || !isHttpUrl(url)) return
        const method = evt?.method || 'GET'
        const key = this.buildRequestKey(method, url)
        if (!key) return
        let entry = this.requestLookup.get(key)
        const status = evt?.status || evt?.statusCode || null
        const lastSeen = evt?.time || Date.now()
        if (entry) {
            if (status) entry.status = status
            entry.lastSeen = lastSeen
            entry.type = evt?.type || entry.type
        } else {
            entry = {
                key,
                method: (method || 'GET').toUpperCase(),
                url: this.normalizeRequestUrl(url),
                displayUrl: url,
                status,
                host: evt?.host || this.scanResult.host || null,
                type: evt?.type || 'http',
                mimeType: evt?.mimeType || null,
                lastSeen
            }
            this.scanResult.requests.push(entry)
            this.requestLookup.set(key, entry)
            this.trimTrackedRequests()
        }
        if (entry?.url) {
            this._requestLookupByUrl.set(entry.url, entry)
        }
        this._updatePageRequestMetaForEntry(entry)
    }

    _resetPageIndexes() {
        this._pagesByKey = new Map()
        this._pagesByUrl = new Map()
        this._pageFindingIds = new Map()
        this._missingPageCounter = 0
        if (this.scanResult) {
            this.scanResult.pages = []
        }
    }

    _rebuildPagesFromFindings() {
        this._resetPageIndexes()
        const items = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings : []
        items.forEach((finding) => this._upsertPageFromFinding(finding))
    }

    _resolveRequestEntryForFinding(finding) {
        if (!finding) return null
        const directKey = finding?.requestKey
        if (directKey && this.requestLookup.has(directKey)) {
            return this.requestLookup.get(directKey)
        }
        const urls = this.collectFindingUrls(finding)
        const primaryUrl = (urls && urls.length) ? urls[0] : (finding?.location?.url || null)
        if (!primaryUrl) return null
        const normalized = this.normalizeRequestUrl(primaryUrl)
        if (!normalized) return null
        return this._requestLookupByUrl.get(normalized) || this.findRequestMetaForUrl(primaryUrl)
    }

    _resolveRequestKeyForFinding(finding) {
        const entry = this._resolveRequestEntryForFinding(finding)
        return entry?.key || null
    }

    _updatePageRequestMetaForEntry(entry) {
        if (!entry || !entry.url) return
        const key = this._pagesByUrl.get(entry.url)
        if (!key) return
        const page = this._pagesByKey.get(key)
        if (!page) return
        page.requestKey = entry.key || null
        page.requestMeta = {
            method: entry.method || null,
            status: entry.status || null,
            mimeType: entry.mimeType || null
        }
    }

    _upsertPageFromFinding(finding) {
        if (!finding) return
        if (!Array.isArray(this.scanResult.pages)) {
            this.scanResult.pages = []
        }
        const candidateUrls = this.collectFindingUrls(finding)
        const normalizedPrimary = candidateUrls.length ? candidateUrls[0] : null
        const pageUrl = finding?.location?.url || normalizedPrimary || null
        let key = normalizedPrimary || pageUrl || null
        if (!key) {
            const fallbackId = finding?.id || finding?.fingerprint || this._missingPageCounter++
            key = `__missing_url__${fallbackId}`
        }
        let page = this._pagesByKey.get(key)
        if (!page) {
            page = {
                url: pageUrl || normalizedPrimary || null,
                stats: {
                    totalFindings: 0,
                    byCategory: {},
                    bySeverity: {}
                },
                findingIds: [],
                requestKey: null,
                requestMeta: {}
            }
            this._pagesByKey.set(key, page)
            if (normalizedPrimary) {
                const normalizedKey = this.normalizeRequestUrl(normalizedPrimary)
                if (normalizedKey) {
                    this._pagesByUrl.set(normalizedKey, key)
                }
            }
            this.scanResult.pages.push(page)
        }

        const findingId = finding?.id || finding?.fingerprint || null
        let idSet = this._pageFindingIds.get(key)
        if (!idSet) {
            idSet = new Set()
            this._pageFindingIds.set(key, idSet)
        }
        if (findingId && idSet.has(findingId)) {
            return
        }
        if (findingId) {
            idSet.add(findingId)
            page.findingIds.push(findingId)
        }

        const category = finding?.category || "runtime_issue"
        const severity = String(finding?.severity || "info").toLowerCase()
        page.stats.totalFindings += 1
        page.stats.byCategory[category] = (page.stats.byCategory[category] || 0) + 1
        page.stats.bySeverity[severity] = (page.stats.bySeverity[severity] || 0) + 1

        if (!page.requestKey) {
            const match = this._resolveRequestEntryForFinding(finding)
            if (match) {
                page.requestKey = match.key || null
                page.requestMeta = {
                    method: match.method || null,
                    status: match.status || null,
                    mimeType: match.mimeType || null
                }
            }
        }
    }


    prepareFindingMetadata(finding) {
        if (!finding) return null
        if (!finding.location || typeof finding.location !== "object" || Array.isArray(finding.location)) {
            const rawValue = typeof finding.location === "string" ? finding.location : null
            finding.location = { url: rawValue }
        }
        const ruleInfo = finding.ruleId ? getIastRuleMeta(finding.ruleId) : null
        if (!ruleInfo && finding.ruleId) {
            try {
                console.warn(`[PTK][IAST] missing rule metadata for ruleId=${finding.ruleId}`)
            } catch (_) { }
        }
        let moduleInfo = ruleInfo?.moduleMeta || (finding.moduleId ? getIastModuleMeta(finding.moduleId) : null)
        if (!moduleInfo && finding.moduleId) {
            try {
                console.warn(`[PTK][IAST] missing module metadata for moduleId=${finding.moduleId}`)
            } catch (_) { }
        }
        if (!moduleInfo && ruleInfo?.moduleId) {
            moduleInfo = getIastModuleMeta(ruleInfo.moduleId) || moduleInfo
        }
        if (!finding.moduleId && moduleInfo?.id) {
            finding.moduleId = moduleInfo.id
        }
        if (!finding.moduleName && moduleInfo?.name) {
            finding.moduleName = moduleInfo.name
        }
        if (!finding.ruleName && ruleInfo?.ruleName) {
            finding.ruleName = ruleInfo.ruleName
        }
        const urls = this.collectFindingUrls(finding)
        if (urls.length > 0) {
            finding.location.url = urls[0]
        }
        finding.affectedUrls = urls
        if (!finding.requestKey) {
            finding.requestKey = this._resolveRequestKeyForFinding(finding)
        }
        const summary = this.buildTaintAndSinkSummaries(finding)
        finding.taintSummary = summary.taintSummary
        finding.sinkSummary = summary.sinkSummary
        const allowedSources = ruleInfo?.ruleMeta?.metadata?.sources || ruleInfo?.ruleMeta?.sources || null
        if (Array.isArray(allowedSources) && allowedSources.length) {
            finding.allowedSources = allowedSources.slice()
        }
        if (finding?.evidence?.iast && typeof finding.evidence.iast === "object") {
            finding.evidence.iast.taintSummary = summary.taintSummary
            finding.evidence.iast.sinkSummary = summary.sinkSummary
            if (Array.isArray(allowedSources) && allowedSources.length) {
                finding.evidence.iast.allowedSources = allowedSources.slice()
            }
        }
        const moduleMetaPayload = moduleInfo?.metadata || moduleInfo || {}
        const ruleMetaPayload = (ruleInfo?.ruleMeta && (ruleInfo.ruleMeta.metadata || ruleInfo.ruleMeta)) || {}
        return {
            finding,
            moduleMeta: moduleMetaPayload,
            ruleMeta: ruleMetaPayload
        }
    }

    collectFindingUrls(finding) {
        const urls = new Set()
        const add = (value) => {
            if (!value) return
            const normalized = this.normalizeFindingUrl(value)
            if (normalized) urls.add(normalized)
        }
        const baseLocation = finding?.location
        const ev = getIastEvidencePayload(finding)
        const routingUrl = ev?.routing?.runtimeUrl || ev?.routing?.url || null
        if (routingUrl) add(routingUrl)
        if (typeof baseLocation === "string") add(baseLocation)
        if (baseLocation && typeof baseLocation === "object") {
            add(baseLocation.url || baseLocation.href)
        }
        if (Array.isArray(finding?.affectedUrls)) {
            finding.affectedUrls.forEach(add)
        }
        if (ev) {
            if (Array.isArray(ev.affectedUrls)) {
                ev.affectedUrls.forEach(add)
            }
            add(ev?.context?.url)
            add(ev?.context?.location)
        }
        if (urls.size === 0 && baseLocation?.url) {
            add(baseLocation.url)
        }
        return Array.from(urls).sort((a, b) => {
            if (a.length !== b.length) return b.length - a.length
            return a.localeCompare(b)
        })
    }

    normalizeFindingUrl(rawUrl) {
        if (!rawUrl) return ""
        const value = String(rawUrl).trim()
        const candidates = [value]
        if (this.scanResult?.host && !/^https?:\/\//i.test(value)) {
            const base = this.scanResult.host.match(/^https?:\/\//i) ? this.scanResult.host : `http://${this.scanResult.host}`
            try {
                candidates.push(new URL(value, base).toString())
            } catch (_) { }
        }
        for (const candidate of candidates) {
            try {
                const u = new URL(candidate)
                if (!/^https?:$/i.test(u.protocol)) {
                    continue
                }
                let pathname = u.pathname || "/"
                pathname = pathname.replace(/\/{2,}/g, "/")
                if (pathname.length > 1 && pathname.endsWith("/")) pathname = pathname.slice(0, -1)
                u.pathname = pathname
                return `${u.origin}${u.pathname}${u.search || ""}${u.hash || ""}`
            } catch (_) { }
        }
        return value
    }

    buildTaintAndSinkSummaries(finding) {
        const sources = new Set()
        const sinks = new Set()
        const directSources = [finding?.source, finding?.taintSource]
        directSources.forEach(src => { if (src) sources.add(String(src)) })
        const directSinks = [finding?.sink, finding?.sinkId]
        directSinks.forEach(sink => { if (sink) sinks.add(String(sink)) })
        const evidence = getIastEvidencePayload(finding)
        if (evidence) {
            ;[evidence.taintSource, evidence.sourceId].forEach(src => {
                if (src) sources.add(String(src))
            })
            ;[evidence.sinkId].forEach(sink => {
                if (sink) sinks.add(String(sink))
            })
        }
        const sourcesArr = Array.from(sources)
        const sinksArr = Array.from(sinks)
        return {
            taintSummary: {
                sources: sourcesArr,
                primarySource: sourcesArr.length ? sourcesArr[0] : null
            },
            sinkSummary: {
                sinks: sinksArr,
                primarySink: sinksArr.length ? sinksArr[0] : null
            }
        }
    }

    updatePagesFromFindings() {
        const items = Array.isArray(this.scanResult.findings) ? this.scanResult.findings : []
        const map = new Map()
        items.forEach((finding, index) => {
            if (!finding) return
            const candidateUrls = this.collectFindingUrls(finding)
            const normalizedPrimary = candidateUrls.length ? candidateUrls[0] : null
            const pageUrl = finding?.location?.url || normalizedPrimary
            const key = normalizedPrimary || pageUrl || `__missing_url__${index}`
            if (!map.has(key)) {
                map.set(key, {
                    url: pageUrl || normalizedPrimary || null,
                    stats: {
                        totalFindings: 0,
                        byCategory: {},
                        bySeverity: {}
                    },
                    findingIds: [],
                    requestKey: null,
                    requestMeta: {}
                })
            }
            const page = map.get(key)
            const category = finding?.category || "runtime_issue"
            const severity = String(finding?.severity || "info").toLowerCase()
            const findingId = finding?.id || `${index}`
            page.stats.totalFindings += 1
            page.stats.byCategory[category] = (page.stats.byCategory[category] || 0) + 1
            page.stats.bySeverity[severity] = (page.stats.bySeverity[severity] || 0) + 1
            page.findingIds.push(findingId)
        })
        const pages = Array.from(map.values()).map(page => {
            const match = this.findRequestMetaForUrl(page.url)
            if (match) {
                page.requestKey = match.key || null
                page.requestMeta = {
                    method: match.method || null,
                    status: match.status || null,
                    mimeType: match.mimeType || null
                }
            }
            return page
        })
        this.scanResult.pages = pages
    }

    findRequestMetaForUrl(url) {
        if (!url || !Array.isArray(this.scanResult.requests)) return null
        const normalized = this.normalizeRequestUrl(url)
        if (!normalized) return null
        let best = null
        for (const req of this.scanResult.requests) {
            if (!req?.url) continue
            if (req.url === normalized) {
                best = req
                break
            }
        }
        if (!best) {
            best = this.scanResult.requests.find(req => req?.displayUrl === url) || null
        }
        return best
    }

    broadcastScanUpdate() {
        try {
            browser.runtime.sendMessage({
                channel: "ptk_background_iast2popup",
                type: "scan_update",
                scanResult: this._getPublicScanResult(),
                isScanRunning: this.isScanRunning,
                rulepackSelection: this.isScanRunning
                    ? buildIastRulepackSelectionFromScan(this._getPublicScanResult())
                    : getIastPortalSelection(),
                policyState: getIastPortalPolicyState()
            }).catch(() => { })
        } catch (_) { }
    }

    broadcastScanDelta(finding) {
        if (!finding) return
        try {
            browser.runtime.sendMessage({
                channel: "ptk_background_iast2popup",
                type: "scan_delta",
                finding,
                stats: this.scanResult?.stats || {},
                isScanRunning: this.isScanRunning
            }).catch(() => { })
        } catch (_) { }
    }

    async attachDevtoolsDebugger(tabId) {
        if (worker.isFirefox) return
        if (typeof chrome === "undefined" || !chrome.debugger) return false
        if (this.devtoolsAttached && this.devtoolsTarget && this.devtoolsTarget.tabId === tabId) return true

        const target = { tabId }
        return await new Promise((resolve) => {
            chrome.debugger.attach(target, "1.3", () => {
                if (chrome.runtime.lastError) {
                    console.warn("[PTK IAST] DevTools attach failed:", chrome.runtime.lastError.message)
                    resolve(false)
                    return
                }

                this.devtoolsAttached = true
                this.devtoolsTarget = target

                if (!this.onDevtoolsEvent) {
                    this.onDevtoolsEvent = this.handleDevtoolsEvent.bind(this)
                }
                try {
                    if (!chrome.debugger.onEvent.hasListener(this.onDevtoolsEvent)) {
                        chrome.debugger.onEvent.addListener(this.onDevtoolsEvent)
                    }
                } catch (_) {
                    chrome.debugger.onEvent.addListener(this.onDevtoolsEvent)
                }

                chrome.debugger.sendCommand(target, "Network.enable", {}, () => {
                    if (chrome.runtime.lastError) {
                        console.warn("[PTK IAST] Network.enable failed:", chrome.runtime.lastError.message)
                        resolve(false)
                        return
                    }
                    resolve(true)
                })
            })
        })
    }

    async loadModules(options = {}) {
        return loadIastModules(options)
    }

    async sendModulesToContent(tabId, options = {}) {
        return sendIastModulesToContent(tabId, 1, options)
    }

    detachDevtoolsDebugger() {
        if (!this.devtoolsAttached || !this.devtoolsTarget) return
        if (typeof chrome === "undefined" || !chrome.debugger) return

        try {
            if (this.onDevtoolsEvent) {
                chrome.debugger.onEvent.removeListener(this.onDevtoolsEvent)
            }
        } catch (e) {
            // ignore listener removal errors
        }

        chrome.debugger.detach(this.devtoolsTarget, () => {
            if (chrome.runtime.lastError) {
                console.warn("[PTK IAST] DevTools detach error:", chrome.runtime.lastError.message)
            }
            this.devtoolsAttached = false
            this.devtoolsTarget = null
            this.onDevtoolsEvent = null
        })
    }

    handleDevtoolsEvent(source, method, params) {
        if (!this.devtoolsTarget || source.tabId !== this.devtoolsTarget.tabId) return
        if (!this.isScanRunning || !this.scanResult?.tabId || source.tabId !== this.scanResult.tabId) return

        if (method === "Network.requestWillBeSent") {
            const request = params && params.request ? params.request : {}
            if (!isHttpUrl(request.url)) return
            const evt = {
                type: "devtools-http-request",
                time: Date.now(),
                requestId: params && params.requestId ? params.requestId : undefined,
                url: request.url,
                method: request.method,
                tabId: source.tabId
            }
            this.recordHttpEvent(evt)
        }

        if (method === "Network.responseReceived") {
            const response = params && params.response ? params.response : {}
            if (!isHttpUrl(response.url)) return
            const evt = {
                type: "devtools-http-response",
                time: Date.now(),
                requestId: params && params.requestId ? params.requestId : undefined,
                url: response.url,
                status: response.status,
                mimeType: response.mimeType,
                tabId: source.tabId
            }
            this.recordHttpEvent(evt)
            this.captureAuthResponseTokens({
                tabId: source.tabId,
                requestId: params && params.requestId ? params.requestId : null,
                url: response.url,
                mimeType: response.mimeType
            })
        }
    }

    isLikelyAuthEndpoint(url) {
        if (!url) return false
        const lower = String(url).toLowerCase()
        return /(login|auth|token|session)/.test(lower)
    }

    async captureAuthResponseTokens({ tabId, requestId, url, mimeType }) {
        if (!tabId || !requestId || !url) return
        if (!mimeType || !String(mimeType).toLowerCase().includes("json")) return
        if (!this.isLikelyAuthEndpoint(url)) return
        if (typeof chrome === "undefined" || !chrome.debugger) return
        const target = { tabId }
        chrome.debugger.sendCommand(target, "Network.getResponseBody", { requestId }, (resp) => {
            if (chrome.runtime.lastError || !resp || !resp.body) return
            const bodyText = resp.base64Encoded ? atob(resp.body) : resp.body
            if (!bodyText || bodyText.length > 200000) return
            let parsed
            try {
                parsed = JSON.parse(bodyText)
            } catch (_) {
                return
            }
            const tokens = this.extractTokenCandidates(parsed).map(entry => ({
                value: entry.value,
                origin: {
                    kind: "http_response",
                    url,
                    requestId,
                    detail: entry.path
                }
            }))
            if (!tokens.length) return
            try {
                browser.tabs.sendMessage(tabId, {
                    channel: "ptk_background_iast2content_token_origin",
                    tokens
                }).catch((err) => {
                    console.warn("[PTK IAST] token origin send failed", err)
                })
            } catch (err) {
                console.warn("[PTK IAST] token origin send exception", err)
            }
        })
    }

    extractTokenCandidates(payload, path = "$") {
        const results = []
        const tokenKeys = ["token", "access_token", "refresh_token", "jwt", "auth", "session"]
        if (payload && typeof payload === "object") {
            Object.entries(payload).forEach(([key, value]) => {
                const lower = String(key).toLowerCase()
                const nextPath = `${path}.${key}`
                if (typeof value === "string") {
                    if (tokenKeys.some(k => lower.includes(k)) || this.isTokenLike(value)) {
                        results.push({ path: nextPath, value })
                    }
                } else if (value && typeof value === "object") {
                    if (Object.keys(value).length <= 12) {
                        results.push(...this.extractTokenCandidates(value, nextPath))
                    }
                }
            })
        }
        return results
    }

    isTokenLike(value) {
        if (!value) return false
        const str = String(value).trim()
        if (str.length < 12) return false
        if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(str) && str.length >= 30) {
            return true
        }
        if (/^[A-Fa-f0-9]+$/.test(str) && str.length >= 32) return true
        if (/^[A-Za-z0-9+/_=-]+$/.test(str) && str.length >= 24) return true
        return false
    }

    async registerScript(scanStrategy = 'SMART', scope = {}) {
        const files = buildIastAgentScriptFiles(scanStrategy, { isFirefox: worker.isFirefox === true })
        try {
            if (!browser?.scripting?.registerContentScripts) {
                return false
            }
            await this.unregisterScript()
            const registrationScope = buildIastAgentScriptRegistrationScope(scope)
            if (!registrationScope?.matches?.length) {
                console.warn('[PTK IAST] Skipping dynamic IAST script registration without scan host scope')
                return false
            }
            const contentScript = {
                id: 'iast-agent',
                js: files,
                matches: registrationScope.matches,
                runAt: 'document_start',
                world: 'MAIN',
                persistAcrossSessions: false
            }
            if (Array.isArray(registrationScope.includeGlobs) && registrationScope.includeGlobs.length) {
                contentScript.includeGlobs = registrationScope.includeGlobs
            }
            try {
                await browser.scripting.registerContentScripts([contentScript])
            } catch (e) {
                if (!contentScript.includeGlobs) throw e
                delete contentScript.includeGlobs
                await browser.scripting.registerContentScripts([contentScript])
            }
            return true
        } catch (e) {
            console.warn('[PTK IAST] Failed to register IAST script:', e);
            return false
        }
    }

    async injectIastAgent(tabId, scanStrategy = 'SMART') {
        const file = 'ptk/content/iast.js'
        const url = browser?.runtime?.getURL ? browser.runtime.getURL(file) : null
        const normalizedStrategy = String(scanStrategy || 'SMART').trim().toUpperCase() === 'COMPREHENSIVE'
            ? 'COMPREHENSIVE'
            : 'SMART'

        const injectByScriptTag = async (execution) => {
            if (!url) return false
            const results = await execution({
                target: { tabId },
                world: 'MAIN',
                func: (src, strategy, retryDelays, maxAttempts) => {
                    try {
                        let attempts = 0
                        const postReady = () => {
                            try { window.postMessage({ channel: 'ptk_iast_agent_ready' }, '*') } catch (_) { }
                        }
                        const postFailed = (error) => {
                            try { window.postMessage({ channel: 'ptk_iast_agent_failed', error: error || 'script_load_failed' }, '*') } catch (_) { }
                        }
                        const removeLoader = () => {
                            try {
                                const existing = document.getElementById('__ptk_iast_agent__')
                                if (existing) existing.remove()
                            } catch (_) { }
                        }
                        const scheduleRetry = () => {
                            const delay = retryDelays[Math.min(attempts - 1, retryDelays.length - 1)] || 0
                            try { setTimeout(loadAgent, delay) } catch (_) { loadAgent() }
                        }
                        const loadAgent = () => {
                            try {
                                window.__PTK_IAST_SCAN_STRATEGY__ = strategy || 'SMART'
                                window.__PTK_IAST_AGENT_AUTHORIZED__ = true
                                window.__PTK_IAST_PROVISIONAL_HOOKS__ = true
                                if (window.__PTK_IAST_AGENT_LOADED__ === true) {
                                    postReady()
                                    return
                                }
                                removeLoader()
                                attempts += 1
                                const script = document.createElement('script')
                                script.id = '__ptk_iast_agent__'
                                script.src = src
                                script.type = 'text/javascript'
                                script.async = true
                                script.onload = postReady
                                script.onerror = function () {
                                    removeLoader()
                                    if (attempts < maxAttempts) {
                                        scheduleRetry()
                                        return
                                    }
                                    postFailed('script_load_failed')
                                }
                                ;(document.head || document.documentElement).appendChild(script)
                            } catch (error) {
                                if (attempts < maxAttempts) {
                                    attempts += 1
                                    scheduleRetry()
                                    return
                                }
                                postFailed(error?.message || 'script_inject_failed')
                            }
                        }
                        loadAgent()
                        return true
                    } catch (error) {
                        try {
                            window.postMessage({ channel: 'ptk_iast_agent_failed', error: error?.message || 'script_inject_failed' }, '*')
                        } catch (_) { }
                        return false
                    }
                },
                args: [url, normalizedStrategy, IAST_AGENT_SCRIPT_TAG_RETRY_DELAYS_MS, IAST_AGENT_SCRIPT_TAG_MAX_ATTEMPTS]
            })
            return Array.isArray(results) ? results.some(entry => entry?.result === true) : true
        }

        // MV3 path (Chromium). Execute the agent file directly in the MAIN
        // world first; inserting a chrome-extension:// script tag can be
        // blocked by the page CSP and was unreliable in ZAP headless runs.
        if (!worker?.isFirefox && browser?.scripting?.executeScript) {
            try {
                await browser.scripting.executeScript({
                    target: { tabId },
                    world: 'MAIN',
                    func: (strategy) => {
                        try {
                            window.__PTK_IAST_SCAN_STRATEGY__ = strategy || 'SMART'
                            window.__PTK_IAST_AGENT_AUTHORIZED__ = true
                            window.__PTK_IAST_PROVISIONAL_HOOKS__ = true
                        } catch (_) { }
                    },
                    args: [normalizedStrategy]
                })
                const results = await browser.scripting.executeScript({
                    target: { tabId },
                    world: 'MAIN',
                    files: [file]
                })
                return Array.isArray(results) ? results.length > 0 : true
            } catch (e) {
                try { console.warn('[PTK IAST] executeScript file injection failed:', e?.message || e) } catch (_) { }
                try {
                    return await injectByScriptTag((options) => browser.scripting.executeScript(options))
                } catch (fallbackError) {
                    try { console.warn('[PTK IAST] executeScript script-tag fallback failed:', fallbackError?.message || fallbackError) } catch (_) { }
                }
            }
        }

        // MV2-safe injection: use tabs.executeScript + script tag with absolute URL
        if (browser?.tabs?.executeScript && url) {
            try {
                const code = buildIastAgentScriptTagLoaderSource(url, normalizedStrategy)
                // Use document_idle for already-loaded pages (document_start is for initial load)
                await browser.tabs.executeScript(tabId, { code, runAt: 'document_idle' })
                return true
            } catch (e) {
                try { console.warn('[PTK IAST] tabs.executeScript failed:', e?.message || e) } catch (_) { }
            }
        }

        console.warn('[PTK IAST] No injection method available')
        return false
    }

    isAgentReady(tabId) {
        return this.agentReadyTabs.has(tabId)
    }

    async unregisterScript() {
        try {
            await browser.scripting.unregisterContentScripts({
                ids: ["iast-agent"],
            });
        } catch (err) {
            //console.log(`failed to unregister content scripts: ${err}`);
        }

    }

}

export const __iastTestHooks = {
    buildIastAgentScriptTagLoaderSource,
    buildDefaultIastRuntimeHealthTelemetry,
    buildIastAgentScriptFiles,
    buildIastAgentScriptRegistrationScope,
    buildIastModulesSignature,
    clearIastModuleSendTracking,
    getIastModuleDeliveryState,
    sendIastModulesToContent
}
