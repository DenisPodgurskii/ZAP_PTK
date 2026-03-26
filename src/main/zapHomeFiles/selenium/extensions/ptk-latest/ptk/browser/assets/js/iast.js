/* Author: Denis Podgurskii */
import { ptk_controller_iast } from "../../../controller/iast.js"
import { ptk_controller_rbuilder } from "../../../controller/rbuilder.js"
import { ptk_utils } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import * as rutils from "../js/rutils.js"
import { normalizeScanResult } from "../js/scanResultViewModel.js"
import { normalizeCwe, normalizeOwasp, toLegacyOwaspString } from "../../../background/common/normalizeMappings.js"
import { downloadScanExportResult, readScanFileText } from "../js/scanCompression.js"
import { buildIastItemFromFinding as buildSharedIastItemFromFinding } from "./iastFindingItem.js"

const controller = new ptk_controller_iast()
const request_controller = new ptk_controller_rbuilder()
const decoder = new ptk_decoder()
const PORTAL_ACTIONS_VISIBLE = false
const iastFilterState = {
    scope: 'all',
    requestKey: null,
    view: 'findings'
}
const IAST_SEVERITY_ORDER = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
}
const IAST_DISCOVERY_GROUPS = [
    { key: "client_execution", title: "Execution", empty: "No client execution buckets yet." },
    { key: "navigation_and_route_control", title: "Navigation", empty: "No navigation or route-control buckets yet." },
    { key: "client_authz_and_state", title: "Authz/State", empty: "No client authz or state buckets yet." },
    { key: "data_exposure_and_storage", title: "Data/Storage", empty: "No data exposure or storage buckets yet." },
    { key: "cross_context_messaging", title: "Messaging", empty: "No cross-context messaging buckets yet." },
    { key: "runtime_integrity_and_third_party", title: "Runtime/3rd Party", empty: "No runtime integrity or third-party buckets yet." }
]
const IAST_RESULT_VIEWS = new Set(["findings", ...IAST_DISCOVERY_GROUPS.map((group) => group.key)])
const IAST_DISCOVERY_VISUALS = {
    critical: { color: "ptk-sev-critical", icon: "fire", order: 0, highlight: true },
    high: { color: "ptk-sev-high", icon: "exclamation triangle", order: 1, highlight: true },
    medium: { color: "ptk-sev-medium", icon: "exclamation triangle", order: 2, highlight: false },
    low: { color: "ptk-sev-low", icon: "exclamation triangle", order: 3, highlight: false },
    info: { color: "ptk-sev-info", icon: "info circle", order: 4, highlight: false }
}
const IAST_UNKNOWN_REQ = "__ptk_unknown__"
const IAST_COUNTERS = buildIastCounters()
const IAST_REQUEST_COUNTERS = new Map()
const IAST_DELTA_QUEUE = []
const IAST_FLUSH_INTERVAL_MS = 300
let iastFlushTimer = null
let iastRequestFilterDirty = false
let iastDefaultModulesRequest = null
const IAST_PROGRESS_RENDER = {
    timer: null,
    flushMs: 150,
    metrics: "",
    status: "",
    snapshot: null,
    scanning: false
}
let iastDiscoveryDirty = true

function escapeIastPolicyHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
}

function setIastPortalPolicyStatus(message, { error = false } = {}) {
    $('#iast-portal-policy-status')
        .text(message || 'Runtime only. Default (system) is used by default.')
        .toggleClass('red', !!error)
        .toggleClass('grey', !error)
}

function setIastPortalPolicyLoading(loading) {
    const isLoading = !!loading
    $('#load_pro_policies_button')
        .toggleClass('loading', isLoading)
        .toggleClass('disabled', isLoading)
    $('#iast-scan-policy').prop('disabled', isLoading)
}

function openExtensionSettingsWindow() {
    return browser.windows.create({
        type: 'popup',
        url: browser.runtime.getURL('/ptk/browser/settings.html'),
        width: 1100,
        height: 820
    }).catch(() => null)
}

function countEnginePolicies(policyState = {}) {
    return Array.isArray(policyState?.metadata) ? policyState.metadata.length : 0
}

function buildPolicyLoadSuccessMessage(engineLabel, policyState = {}) {
    const count = countEnginePolicies(policyState)
    return `Loaded ${count} ${engineLabel} scan polic${count === 1 ? 'y' : 'ies'}.`
}

function buildPolicyLoadErrorMessage(result, scopeLabel = 'scan policies') {
    if (result?.error === 'missing_api_key') {
        return `PTK Pro token is missing. Open Settings -> PTK Pro and add an activation token before loading ${scopeLabel}.`
    }
    const reason = String(result?.message || result?.error || 'unknown_error').trim()
    return `Could not load ${scopeLabel}. Portal returned: ${reason}.`
}

function syncIastPortalPolicyDropdown(value) {
    const $select = $('#iast-scan-policy')
    if (!$select.length) return
    const normalized = value ? String(value) : ''
    $select.val(normalized)
    if (typeof $select.dropdown === 'function') {
        $select.dropdown('refresh')
        $select.dropdown('set selected', normalized)
    }
}

function buildIastPortalPolicyEntries(policyState = {}, selection = null) {
    const metadata = Array.isArray(policyState?.metadata) ? policyState.metadata.slice() : []
    const selected = policyState?.selectedPolicy && typeof policyState.selectedPolicy === 'object'
        ? policyState.selectedPolicy
        : (selection?.source === 'portal' && selection?.policyId
            ? {
                id: selection.policyId,
                name: selection.policyName || null,
                label: selection.label || (selection.policyName || `Policy #${selection.policyId}`)
            }
            : null)
    if (selected?.id && !metadata.some((entry) => String(entry?.id || '') === String(selected.id))) {
        metadata.unshift(selected)
    }
    return metadata.filter((entry) => entry && (entry.id || entry.name))
}

function normalizeIastSelectionValue(value) {
    if (value === undefined || value === null) return null
    const text = String(value).trim()
    return text || null
}

function normalizeIastRulepackSelection(selection = {}) {
    const source = normalizeIastSelectionValue(selection?.source) || 'local'
    const policyId = normalizeIastSelectionValue(selection?.policyId)
    const policyName = normalizeIastSelectionValue(selection?.policyName)
    const variant = normalizeIastSelectionValue(selection?.variant)
    const preferPortal = selection?.preferPortal === true || source === 'portal'
    let label = normalizeIastSelectionValue(selection?.label)
    if (!label) {
        if (source === 'custom') {
            label = 'Custom rulepack'
        } else if (preferPortal && (policyId || policyName)) {
            label = policyName
                ? `Scan policy: ${policyName}`
                : `Scan policy #${policyId}`
        } else {
            label = variant
                ? `Default (system) ${variant}`
                : 'Default (system)'
        }
    }
    return {
        source,
        preferPortal,
        policyId,
        policyName,
        variant,
        label
    }
}

function getIastRulepackSelection(result = {}) {
    if (result?.rulepackSelection && typeof result.rulepackSelection === 'object') {
        return normalizeIastRulepackSelection(result.rulepackSelection)
    }
    const scanResult = result?.scanResult || {}
    const settings = scanResult?.settings && typeof scanResult.settings === 'object'
        ? scanResult.settings
        : {}
    return normalizeIastRulepackSelection({
        source: settings.iastRulepackSource || 'local',
        policyId: scanResult?.policyId || null,
        policyName: settings.iastPolicyName || null,
        variant: settings.iastRulepackVariant || null
    })
}

function buildIastRulepackRunOptions(selection = {}) {
    const normalized = normalizeIastRulepackSelection(selection)
    const opts = {}
    if (normalized.variant) {
        opts.variant = normalized.variant
    }
    if (normalized.preferPortal || normalized.source === 'portal') {
        opts.preferPortal = true
        if (normalized.policyId) opts.policyId = normalized.policyId
        if (normalized.policyName) opts.policyName = normalized.policyName
    }
    return Object.keys(opts).length ? opts : null
}

function updateIastRulepackUi(result = {}) {
    const selection = getIastRulepackSelection(result)
    const policyState = (result?.policyState && typeof result.policyState === 'object')
        ? result.policyState
        : (controller.policyState || {})
    controller.policyState = policyState
    const entries = buildIastPortalPolicyEntries(policyState, selection)
    const hasPortalEntries = entries.length > 0
    const hasSelectedPortalPolicy = !!policyState?.selectedPolicy?.id
    const options = []
    if (hasPortalEntries || hasSelectedPortalPolicy) {
        options.push('<option value="">Select policy</option>')
    }
    options.push('<option value="default:0">Default (system)</option>')
    entries.forEach((entry) => {
        if (!entry?.id) return
        const label = entry.label || entry.name || `Policy #${entry.id}`
        options.push(`<option value="policy:${escapeIastPolicyHtml(entry.id)}">${escapeIastPolicyHtml(label)}</option>`)
    })
    $('#iast-scan-policy').html(options.join(''))
    const selectedValue = policyState?.selectedPolicy?.id
        ? `policy:${policyState.selectedPolicy.id}`
        : (selection?.source === 'portal' && selection?.policyId
            ? `policy:${selection.policyId}`
            : ((hasPortalEntries || hasSelectedPortalPolicy) ? '' : 'default:0'))
    syncIastPortalPolicyDropdown(selectedValue)
    if (selection?.source === 'portal' && selection?.label) {
        setIastPortalPolicyStatus(`Selected: ${selection.label}`)
    } else if (Array.isArray(policyState?.metadata) && policyState.metadata.length) {
        setIastPortalPolicyStatus(`Loaded ${policyState.metadata.length} scan polic${policyState.metadata.length === 1 ? 'y' : 'ies'}. Default (system) is used unless a PTK Pro policy is selected.`)
    } else {
        setIastPortalPolicyStatus('Runtime only. Default (system) is used by default.')
    }
    return selection
}

function resolveIastHelpPopupPosition($icon) {
    const element = $icon && $icon[0]
    if (!element || typeof element.getBoundingClientRect !== 'function') {
        return 'bottom left'
    }
    const rect = element.getBoundingClientRect()
    const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 600
    const estimatedPopupWidth = Math.min(350, Math.max(220, viewportWidth - 48))
    const leftSpace = rect.left
    const rightSpace = viewportWidth - rect.right
    if (rightSpace < estimatedPopupWidth && leftSpace > rightSpace) {
        return 'bottom right'
    }
    return 'bottom left'
}

function bindIastHelpPopups() {
    $('#iast_scans_form .question.circle.icon').each(function () {
        const $icon = $(this)
        let $popup = $icon.closest('.ptk-help-label-row').nextAll('.ptk-help-popup').first()
        if (!$popup.length) {
            $popup = $icon.closest('.field').find('.ptk-help-popup').first()
        }
        if (!$popup.length) return
        if ($icon.data('module-popup')) {
            $icon.popup('destroy')
        }
        $icon.popup({
            popup: $popup,
            inline: true,
            hoverable: true,
            position: resolveIastHelpPopupPosition($icon),
            delay: {
                show: 300,
                hide: 800
            }
        })
    })
}

function maybeBindIastPortalPreview(result = {}) {
    const currentScan = result?.scanResult || controller?.scanResult?.scanResult || null
    if (result?.isScanRunning || hasRenderableIastData(currentScan)) return
    if (Array.isArray(result?.default_modules) && result.default_modules.length) {
        bindModules(result)
        showWelcomeForm()
    }
}

async function ensureIastDefaultModulesLoaded({ force = false } = {}) {
    if (!force && Array.isArray(controller?.default_modules) && controller.default_modules.length) {
        bindModules({ default_modules: controller.default_modules })
        return { default_modules: controller.default_modules }
    }
    if (iastDefaultModulesRequest && !force) {
        return iastDefaultModulesRequest
    }
    iastDefaultModulesRequest = controller.getDefaultModules()
        .then((result) => {
            updateIastRulepackUi(result || {})
            if (Array.isArray(result?.default_modules)) {
                controller.default_modules = result.default_modules
                bindModules(result)
            }
            return result
        })
        .finally(() => {
            iastDefaultModulesRequest = null
        })
    return iastDefaultModulesRequest
}

function buildIastCounters() {
    return {
        total: 0,
        info: 0,
        vuln: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    }
}

function resetIastCounters() {
    const fresh = buildIastCounters()
    IAST_COUNTERS.total = fresh.total
    IAST_COUNTERS.info = fresh.info
    IAST_COUNTERS.vuln = fresh.vuln
    IAST_COUNTERS.bySeverity = fresh.bySeverity
    IAST_REQUEST_COUNTERS.clear()
}

function resetIastProgressRender({ hide = true } = {}) {
    if (IAST_PROGRESS_RENDER.timer) {
        clearTimeout(IAST_PROGRESS_RENDER.timer)
        IAST_PROGRESS_RENDER.timer = null
    }
    IAST_PROGRESS_RENDER.metrics = ""
    IAST_PROGRESS_RENDER.status = ""
    IAST_PROGRESS_RENDER.snapshot = null
    IAST_PROGRESS_RENDER.scanning = false
    if (hide) {
        $("#progress_message").hide()
    }
}

function buildIastProgressSnapshot(source = null) {
    const scanResult = source?.scanResult || source || controller?.scanViewModel || controller?.scanResult?.scanResult || {}
    const stats = scanResult?.stats && typeof scanResult.stats === "object" ? scanResult.stats : {}
    const requests = Math.max(0, Number(stats.requestsCount || (Array.isArray(scanResult.requests) ? scanResult.requests.length : 0)))
    const findings = Math.max(0, Number(stats.findingsCount || (Array.isArray(scanResult.findings) ? scanResult.findings.length : 0)))
    const signals = Math.max(0, Number(Array.isArray(scanResult.runtimeEvents) ? scanResult.runtimeEvents.length : 0))
    const pages = Math.max(0, Number(Array.isArray(scanResult.pages) ? scanResult.pages.length : 0))
    const host = String(scanResult?.host || controller?.scanResult?.scanResult?.host || "").trim()
    return { requests, findings, signals, pages, host }
}

function formatIastProgressDetails(snapshot) {
    const details = snapshot || buildIastProgressSnapshot()
    return `Requests ${details.requests} | Findings ${details.findings} | Signals ${details.signals} | Pages ${details.pages}`
}

function composeIastProgressStatus(info = {}) {
    const snapshot = info.snapshot || IAST_PROGRESS_RENDER.snapshot || buildIastProgressSnapshot()
    const host = String(snapshot?.host || "").trim()
    const message = String(info.message || "").trim()
    if (message && host) {
        return `${message}: ${host}`
    }
    if (message) return message
    if (host) return `Runtime scan running on ${host}`
    return "Runtime scan running"
}

function scheduleIastProgressUpdate(payload = {}) {
    const info = (payload && typeof payload === "object") ? payload : { message: String(payload || "") }
    const snapshot = info.snapshot || buildIastProgressSnapshot(info.scanResult || null)
    IAST_PROGRESS_RENDER.snapshot = snapshot
    IAST_PROGRESS_RENDER.metrics = formatIastProgressDetails(snapshot)
    IAST_PROGRESS_RENDER.status = composeIastProgressStatus({ ...info, snapshot })
    IAST_PROGRESS_RENDER.scanning = true
    if (IAST_PROGRESS_RENDER.timer) return
    IAST_PROGRESS_RENDER.timer = setTimeout(() => {
        IAST_PROGRESS_RENDER.timer = null
        $("#progress_scan_metrics").text(IAST_PROGRESS_RENDER.metrics || "Requests 0 | Findings 0 | Signals 0 | Pages 0")
        $("#progress_attack_name").text(IAST_PROGRESS_RENDER.status || "Runtime scan running")
        $("#progress_message").show()
    }, IAST_PROGRESS_RENDER.flushMs)
}

function normalizeIastSeverityValue(finding) {
    const raw = finding?.effectiveSeverity || finding?.severity || "info"
    const normalized = String(raw).toLowerCase()
    if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low" || normalized === "info") {
        return normalized
    }
    return "info"
}

function ensureIastRequestCounters(requestKey) {
    const key = requestKey || IAST_UNKNOWN_REQ
    if (!IAST_REQUEST_COUNTERS.has(key)) {
        IAST_REQUEST_COUNTERS.set(key, buildIastCounters())
    }
    return IAST_REQUEST_COUNTERS.get(key)
}

function updateIastCountersForFinding(finding, requestKey) {
    const severity = normalizeIastSeverityValue(finding)
    const isInfo = severity === "info"
    const targets = [IAST_COUNTERS, ensureIastRequestCounters(requestKey)]
    targets.forEach((counter) => {
        counter.total += 1
        counter.bySeverity[severity] = (counter.bySeverity[severity] || 0) + 1
        if (isInfo) {
            counter.info += 1
        } else {
            counter.vuln += 1
        }
    })
}

function getIastBaseCounters() {
    const key = iastFilterState.requestKey || null
    if (!key) return IAST_COUNTERS
    return IAST_REQUEST_COUNTERS.get(key) || buildIastCounters()
}

function renderIastStatsFromCounters() {
    const scope = iastFilterState.scope
    const base = getIastBaseCounters()
    const stats = {
        findingsCount: base.total,
        critical: base.bySeverity.critical || 0,
        high: base.bySeverity.high || 0,
        medium: base.bySeverity.medium || 0,
        low: base.bySeverity.low || 0,
        info: base.bySeverity.info || 0
    }
    if (scope === "vuln") {
        stats.findingsCount = base.vuln
        stats.info = 0
    }
    rutils.bindStats(stats, "iast")
}

function collectIastStatsFromElements($collection) {
    const counts = { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    if (!$collection || typeof $collection.length === 'undefined') return counts
    $collection.each(function () {
        counts.findingsCount += 1
        const severity = ($(this).attr('data-severity') || '').toLowerCase()
        if (severity === 'critical') counts.critical += 1
        else if (severity === 'high') counts.high += 1
        else if (severity === 'medium') counts.medium += 1
        else if (severity === 'low') counts.low += 1
        else if (severity === 'info' || severity === 'informational') counts.info += 1
        else counts.low += 1
    })
    return counts
}

function hasRenderableIastData(scanResult) {
    if (!scanResult) return false
    if (Array.isArray(scanResult.findings) && scanResult.findings.length) return true
    const items = scanResult.items
    if (Array.isArray(items) && items.length) return true
    if (items && typeof items === 'object' && Object.keys(items).length) return true
    if (Array.isArray(scanResult.vulns) && scanResult.vulns.length) return true
    if (countIastDiscoveryItems(scanResult) > 0) return true
    return false
}

function formatIastSeverityLabel(value) {
    if (!value) return 'info'
    return String(value).toLowerCase()
}

function formatIastSeverityDisplay(value) {
    const normalized = formatIastSeverityLabel(value)
    return normalized.charAt(0).toUpperCase() + normalized.slice(1)
}

function isIastDiscoveryView(view) {
    return view !== "findings" && IAST_DISCOVERY_GROUPS.some((group) => group.key === view)
}

function normalizeIastViewKey(view, scanResult = null) {
    if (view === "discovery") {
        return firstPopulatedIastDiscoveryGroup(scanResult) || IAST_DISCOVERY_GROUPS[0].key
    }
    if (IAST_RESULT_VIEWS.has(view)) return view
    return "findings"
}

function normalizeIastDiscoveryBuckets(scanResult) {
    const rawBuckets = scanResult?.analysis?.discovery?.iastBuckets
    if (!Array.isArray(rawBuckets)) return []
    return rawBuckets
        .map((bucket) => {
            if (!bucket || typeof bucket !== "object" || !bucket.bucket) return null
            return {
                ...bucket,
                severity: formatIastSeverityLabel(bucket.severity),
                hits: Number.isFinite(bucket.hits) ? Number(bucket.hits) : 0,
                priority: Number.isFinite(bucket.priority) ? Number(bucket.priority) : 0,
                sanitizedCount: Number.isFinite(bucket.sanitizedCount) ? Number(bucket.sanitizedCount) : 0,
                subtypes: Array.isArray(bucket.subtypes) ? bucket.subtypes : [],
                sourceKinds: Array.isArray(bucket.sourceKinds) ? bucket.sourceKinds : [],
                dataKinds: Array.isArray(bucket.dataKinds) ? bucket.dataKinds : [],
                trustLevels: Array.isArray(bucket.trustLevels) ? bucket.trustLevels : [],
                trustDecisions: Array.isArray(bucket.trustDecisions) ? bucket.trustDecisions : [],
                sanitizerIds: Array.isArray(bucket.sanitizerIds) ? bucket.sanitizerIds : [],
                corroboratingEngines: Array.isArray(bucket.corroboratingEngines) ? bucket.corroboratingEngines : []
            }
        })
        .filter(Boolean)
}

function countIastDiscoveryItems(scanResult) {
    return normalizeIastDiscoveryBuckets(scanResult).length
}

function firstPopulatedIastDiscoveryGroup(scanResult) {
    const buckets = normalizeIastDiscoveryBuckets(scanResult)
    const match = IAST_DISCOVERY_GROUPS.find((group) => buckets.some((bucket) => bucket.bucket === group.key))
    return match ? match.key : null
}

function getIastDiscoveryGroupMeta(groupKey) {
    return IAST_DISCOVERY_GROUPS.find((group) => group.key === groupKey) || { key: groupKey, title: groupKey || "Discovery" }
}

function parseIastRouteKey(routeKey) {
    const raw = String(routeKey || "")
    const firstSep = raw.indexOf("|")
    const secondSep = firstSep === -1 ? -1 : raw.indexOf("|", firstSep + 1)
    if (firstSep === -1 || secondSep === -1) {
        return {
            host: "",
            method: "GET",
            path: raw || "/"
        }
    }
    return {
        host: raw.slice(0, firstSep) || "",
        method: raw.slice(firstSep + 1, secondSep) || "GET",
        path: raw.slice(secondSep + 1) || "/"
    }
}

function formatIastDiscoveryLabel(value) {
    return String(value || "")
        .split(/[_-]+/g)
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ")
}

function formatIastSubtypeLabel(value) {
    const normalized = String(value || "").trim().toLowerCase()
    if (!normalized) return ""
    const exact = {
        postmessage_flow: "PostMessage flow",
        broadcast_channel_flow: "BroadcastChannel flow",
        message_port_flow: "MessagePort flow",
        cross_origin_message_flow: "Cross-origin message flow",
        dom_execution: "DOM execution",
        dynamic_code_execution: "Dynamic code execution",
        html_parser_execution: "HTML parser execution",
        html_sink_execution: "HTML sink execution",
        runtime_integrity: "Runtime integrity",
        prototype_pollution_impact: "Prototype pollution impact",
        third_party_runtime: "Third-party runtime",
        worker_bootstrap: "Worker bootstrap",
        realtime_runtime: "Realtime runtime",
        client_state_assumption: "Client state assumption",
        session_material_use: "Session material use",
        session_state_signal: "Session state signal",
        data_exposure: "Data exposure",
        client_data_parsing: "Client data parsing",
        storage_state: "Storage state",
        credential_or_token_exposure: "Credential or token exposure",
        feature_flag_state: "Feature flag state",
        privileged_state_signal: "Privileged state signal",
        policy_violation: "Policy violation",
        navigation_control: "Navigation control",
        route_control: "Route control",
        dangerous_scheme_navigation: "Dangerous-scheme navigation",
        route_guard_signal: "Route guard signal",
        runtime_signal: "Runtime signal"
    }
    return exact[normalized] || formatIastDiscoveryLabel(normalized)
}

function parseIastParamKey(paramKey) {
    const raw = String(paramKey || "").trim()
    if (!raw) {
        return { raw: "", prefix: "", key: "", label: "Unknown source" }
    }
    const sep = raw.indexOf(":")
    const prefix = sep === -1 ? "" : raw.slice(0, sep)
    const key = sep === -1 ? raw : raw.slice(sep + 1)
    switch (prefix) {
    case "response":
        return { raw, prefix, key, label: `API response field "${key}"` }
    case "storage":
        return { raw, prefix, key, label: `Stored value "${key}"` }
    case "form":
        return { raw, prefix, key, label: `Form input "${key}"` }
    case "query":
        return { raw, prefix, key, label: `Query parameter "${key}"` }
    case "hash":
        return { raw, prefix, key, label: `Hash parameter "${key}"` }
    case "route":
        return { raw, prefix, key, label: `Client route "${key}"` }
    case "cookie":
        return { raw, prefix, key, label: `Cookie "${key}"` }
    default:
        return { raw, prefix, key, label: raw }
    }
}

function formatIastSinkLabel(sinkId) {
    const raw = String(sinkId || "").trim()
    if (!raw) return "runtime sink"
    const exact = {
        "dom.innerHTML": "DOM innerHTML",
        "dom.outerHTML": "DOM outerHTML",
        "document.write": "document.write",
        "code.eval": "eval",
        "http.xhr.setRequestHeader": "XHR request header",
        "storage.localStorage.setItem": "localStorage persistence",
        "storage.sessionStorage.setItem": "sessionStorage persistence",
        "client.json.parse": "JSON.parse",
        "realtime.websocket.send": "WebSocket send",
        "http.image.src": "image src request"
    }
    if (exact[raw]) return exact[raw]
    const normalized = raw
        .replace(/^dom\./, "DOM ")
        .replace(/^http\.xhr\./, "XHR ")
        .replace(/^http\.fetch\./, "fetch ")
        .replace(/^storage\./, "")
        .replace(/^client\./, "")
        .replace(/^realtime\./, "")
        .replace(/\./g, " ")
    return normalized
}

function buildIastDiscoveryHeadline(bucket = {}) {
    const source = parseIastParamKey(bucket.paramKey)
    const sink = formatIastSinkLabel(bucket.sinkId)
    switch (bucket.bucket) {
    case "client_execution":
        return `${source.label} reaches ${sink}`
    case "navigation_and_route_control":
        return `${source.label} influences navigation`
    case "client_authz_and_state":
        return `${source.label} influences client auth or state`
    case "data_exposure_and_storage":
        return `${source.label} flows into ${sink}`
    case "cross_context_messaging":
        return `${source.label} crosses a messaging boundary`
    case "runtime_integrity_and_third_party":
        return `${source.label} reaches ${sink}`
    default:
        return `${source.label} reaches ${sink}`
    }
}

function buildIastDiscoveryWhyInteresting(bucket = {}) {
    const source = parseIastParamKey(bucket.paramKey)
    const sink = formatIastSinkLabel(bucket.sinkId)
    const dataKind = formatIastDataKindLabel(getIastBucketPrimaryDataKind(bucket))
    const trust = formatIastTrustSummary(bucket)
    switch (bucket.bucket) {
    case "client_execution":
        return `${source.label} reaches an execution-capable sink (${sink})${trust ? ` across a ${trust} trust path` : ""}.`
    case "navigation_and_route_control":
        return `${source.label} influences client-side routing or navigation behavior${trust ? ` across a ${trust} trust boundary` : ""}.`
    case "client_authz_and_state":
        return `${source.label} appears to influence client-side auth, session, or privilege state${dataKind ? ` as ${dataKind} material` : ""}.`
    case "data_exposure_and_storage":
        return `${source.label} is stored, reused, or parsed in a client-side data flow via ${sink}${dataKind ? ` as ${dataKind} data` : ""}.`
    case "cross_context_messaging":
        return `${source.label} crosses a browser trust boundary through cross-context messaging${trust ? ` (${trust})` : ""}.`
    case "runtime_integrity_and_third_party":
        return `${source.label} reaches a runtime or third-party-sensitive sink (${sink})${trust ? ` with ${trust} trust context` : ""}.`
    default:
        return `${source.label} reaches ${sink}.`
    }
}

function buildIastDiscoveryNextCheck(bucket = {}) {
    const dataKind = formatIastDataKindLabel(getIastBucketPrimaryDataKind(bucket))
    const trust = formatIastTrustSummary(bucket)
    switch (bucket.bucket) {
    case "client_execution":
        return "Try to turn the source into executable HTML or JS and confirm whether it reaches script or HTML execution."
    case "navigation_and_route_control":
        return "Try redirect, route bypass, or dangerous scheme inputs using the same source."
    case "client_authz_and_state":
        return dataKind
            ? `Tamper with the ${dataKind} value and compare the client-side state change with a direct server request.`
            : "Tamper with the client state and compare the UI change with a direct server request."
    case "data_exposure_and_storage":
        return dataKind
            ? `Check whether the ${dataKind} value can be attacker-controlled and later reused by privileged requests or client decisions.`
            : "Check whether this value can be attacker-controlled and later reused by privileged requests or client decisions."
    case "cross_context_messaging":
        return trust.toLowerCase().includes("block")
            ? "Replay the same message from a different origin or context and verify whether the blocked boundary can be bypassed."
            : "Replay the same message from a different origin or context and verify whether it reaches the same sink."
    case "runtime_integrity_and_third_party":
        return "Check whether this runtime path leads to trusted third-party loading, exfiltration, or integrity impact."
    default:
        return "Reproduce the same source-to-sink path and confirm whether it leads to a meaningful bug bounty impact."
    }
}

function renderIastBucketLead(text) {
    const raw = String(text || "").trim()
    const splitIndex = raw.indexOf(":")
    if (splitIndex === -1) {
        return ptk_utils.escapeHtml(raw)
    }
    const prefix = raw.slice(0, splitIndex + 1).trim()
    const suffix = raw.slice(splitIndex + 1).trim()
    if (!suffix) return ptk_utils.escapeHtml(prefix)
    return `${ptk_utils.escapeHtml(prefix)} <b>${ptk_utils.escapeHtml(suffix)}</b>`
}

function renderIastBucketValue(value) {
    return `<b>${ptk_utils.escapeHtml(String(value || "").trim())}</b>`
}

function isMeaningfulIastParamKey(value) {
    const normalized = String(value || "").trim()
    return normalized.length > 0 && !normalized.includes("<none>")
}

function discoveryBucketSeverityModel(bucket) {
    const severity = formatIastSeverityLabel(bucket?.severity)
    return {
        severity,
        visual: IAST_DISCOVERY_VISUALS[severity] || IAST_DISCOVERY_VISUALS.info
    }
}

function discoveryBucketTitle(bucket, groupKey) {
    const route = parseIastRouteKey(bucket?.routeKey)
    const base = `${route.method || "GET"} ${route.path || "/"}`
    if (isMeaningfulIastParamKey(bucket?.paramKey)) {
        return `${base} · ${bucket.paramKey}`
    }
    if (base.trim()) return base
    return getIastDiscoveryGroupMeta(groupKey).title
}

function discoveryBucketSignals(bucket = {}) {
    const signals = []
    const push = (value) => {
        const normalized = String(value || "").trim()
        if (!normalized || signals.includes(normalized)) return
        signals.push(normalized)
    }
    if (bucket.subtype) push(formatIastDiscoveryLabel(bucket.subtype))
    if (bucket.crossOrigin) push("cross-origin")
    if (bucket.routeControlled) push("route-controlled")
    if (bucket.thirdParty) push("third-party")
    if (bucket.authLike) push("auth-like")
    if (bucket.candidateType) push(bucket.candidateType)
    return signals
}

function discoveryBucketDetails(bucket = {}) {
    const details = []
    const corroboratingEngines = Array.isArray(bucket.corroboratingEngines)
        ? bucket.corroboratingEngines.filter((engine) => String(engine || "").trim().toUpperCase() !== "IAST")
        : []
    const push = (label, value) => {
        const normalized = Array.isArray(value)
            ? value.map((entry) => String(entry || "").trim()).filter(Boolean).join(", ")
            : String(value || "").trim()
        if (!normalized) return
        details.push({ label, value: normalized })
    }
    push("Detected data", Array.isArray(bucket.dataKinds) ? bucket.dataKinds.map((entry) => formatIastDataKindLabel(entry).toLowerCase()) : [])
    push("Trust", formatIastTrustSummary(bucket))
    if (bucket.sanitizedCount > 0) push("Sanitized flows", bucket.sanitizedCount)
    push("Sanitizers", bucket.sanitizerIds)
    push("Also seen in", corroboratingEngines)
    return details
}

function truncateIastBucketText(value, maxLength = 120) {
    const normalized = String(value || "").trim()
    if (!normalized) return ""
    if (normalized.length <= maxLength) return normalized
    return `${normalized.slice(0, Math.max(0, maxLength - 3))}...`
}

function formatIastSourceKindsInline(sourceKinds = []) {
    if (!Array.isArray(sourceKinds) || !sourceKinds.length) return ""
    return sourceKinds
        .map((kind) => formatIastDiscoveryLabel(kind))
        .filter(Boolean)
        .join(", ")
}

function pickPriorityValue(values = [], preferred = []) {
    if (!Array.isArray(values) || !values.length) return ""
    for (const candidate of preferred) {
        const match = values.find((value) => String(value || "").toLowerCase() === String(candidate).toLowerCase())
        if (match) return String(match)
    }
    return String(values[0] || "")
}

function formatIastDataKindLabel(value) {
    const normalized = String(value || "").trim().toLowerCase()
    if (!normalized) return ""
    if (normalized === "pii") return "PII"
    if (normalized === "jwt") return "JWT"
    return normalized
        .split(/[_-]+/g)
        .filter(Boolean)
        .join(" ")
}

function getIastBucketPrimaryDataKind(bucket = {}) {
    return pickPriorityValue(bucket.dataKinds, ["token", "jwt", "credentials", "password", "session", "secret"])
}

function formatIastTrustSummary(bucket = {}) {
    const level = pickPriorityValue(bucket.trustLevels, ["cross_origin", "third_party", "same_origin"])
    const decision = pickPriorityValue(bucket.trustDecisions, ["block", "allow"])
    const levelLabel = formatIastDiscoveryLabel(level)
    const decisionLabel = formatIastDiscoveryLabel(decision)
    if (levelLabel && decisionLabel) return `${levelLabel} (${decisionLabel.toLowerCase()})`
    return levelLabel || decisionLabel || ""
}

function summarizeIastAdditionalSources(representativeFinding = null) {
    const evidenceEntry = extractPrimaryIastEvidence(representativeFinding) || {}
    const sources = Array.isArray(evidenceEntry?.sources) ? evidenceEntry.sources : []
    if (!sources.length) return ""
    const primaryKey = String(
        evidenceEntry?.primarySource?.key
        || evidenceEntry?.primarySource?.source
        || evidenceEntry?.sourceKey
        || ""
    ).trim()
    const labels = []
    const seen = new Set()
    sources.forEach((source) => {
        const key = String(source?.key || source?.source || "").trim()
        if (primaryKey && key && key === primaryKey) return
        const label = String(source?.label || source?.display || key || "").trim()
        if (!label) return
        const dedupeKey = label.toLowerCase()
        if (seen.has(dedupeKey)) return
        seen.add(dedupeKey)
        labels.push(label)
    })
    if (!labels.length) return ""
    return labels.slice(0, 3).join(", ")
}

function getIastSinkValuePreview(representativeFinding = null) {
    const evidenceEntry = extractPrimaryIastEvidence(representativeFinding) || {}
    return truncateIastBucketText(
        evidenceEntry?.context?.valuePreview
        || evidenceEntry?.context?.value
        || "",
        120
    )
}

function getIastDomTargetSummary(representativeFinding = null) {
    const evidenceEntry = extractPrimaryIastEvidence(representativeFinding) || {}
    const elementId = String(evidenceEntry?.context?.elementId || "").trim()
    const tagName = String(evidenceEntry?.context?.tagName || "").trim().toLowerCase()
    if (tagName && elementId) return `${tagName}#${elementId}`
    if (elementId) return `#${elementId}`
    if (tagName) return tagName
    return ""
}

function extractMeaningfulIastTraceFrame(representativeFinding = null) {
    const evidenceEntry = extractPrimaryIastEvidence(representativeFinding) || {}
    const traceSummary = String(evidenceEntry?.traceSummary || "").trim()
    if (traceSummary && traceSummary.toLowerCase() !== "err") return truncateIastBucketText(traceSummary, 140)
    const trace = evidenceEntry?.trace
    if (typeof trace === "string") {
        const lines = trace.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
        const candidate = lines.find((line) => /(?:\.js:\d+|\bat\b)/i.test(line) && !/^error\b/i.test(line))
        if (candidate) return truncateIastBucketText(candidate, 140)
    }
    if (Array.isArray(trace)) {
        const candidate = trace
            .map((entry) => {
                if (typeof entry === "string") return entry.trim()
                if (!entry || typeof entry !== "object") return ""
                return String(entry.frame || entry.location || entry.file || entry.function || "").trim()
            })
            .find((line) => /(?:\.js:\d+|\w+)/i.test(line))
        if (candidate) return truncateIastBucketText(candidate, 140)
    }
    return ""
}

function buildIastBucketSourceDetail(bucket = {}, representativeFinding = null) {
    const source = parseIastParamKey(bucket.paramKey)
    const evidenceEntry = extractPrimaryIastEvidence(representativeFinding) || {}
    const preview = truncateIastBucketText(
        evidenceEntry?.sourceValuePreview
        || evidenceEntry?.primarySource?.sourceValuePreview
        || evidenceEntry?.primarySource?.raw
        || evidenceEntry?.primarySource?.value
        || "",
        100
    )
    const parts = [source.label]
    const kindLabel = formatIastSourceKindsInline(bucket.sourceKinds)
    if (kindLabel) parts.push(`kind: ${kindLabel}`)
    if (isMeaningfulIastParamKey(bucket.paramKey)) parts.push(`key: ${bucket.paramKey}`)
    if (preview) parts.push(`sample: ${preview}`)
    return parts.join(" · ")
}

function buildIastDiscoveryItem(bucket, groupKey, index) {
    if (!bucket) return ""
    const risk = discoveryBucketSeverityModel(bucket)
    const severity = risk.severity
    const severityLabel = formatIastSeverityDisplay(severity)
    const attackClass = risk.visual.highlight
        ? `vuln success visible ${severityLabel} severity-${severity}`
        : "nonvuln visible"
    const details = discoveryBucketDetails(bucket)
    const route = parseIastRouteKey(bucket.routeKey)
    const sink = formatIastSinkLabel(bucket.sinkId)
    const whyInteresting = buildIastDiscoveryWhyInteresting(bucket)
    const nextCheck = buildIastDiscoveryNextCheck(bucket)
    const representativeFinding = resolveRepresentativeIastBucketFinding(bucket)
    const representativeRequest = representativeFinding
        ? resolveRepresentativeIastBucketRequestEntry(representativeFinding)
        : null
    const sourceDetail = buildIastBucketSourceDetail(bucket, representativeFinding)
    const sinkValuePreview = getIastSinkValuePreview(representativeFinding)
    const domTarget = getIastDomTargetSummary(representativeFinding)
    const traceFrame = extractMeaningfulIastTraceFrame(representativeFinding)
    const additionalSources = summarizeIastAdditionalSources(representativeFinding)
    const primarySubtype = formatIastSubtypeLabel(bucket.subtype || (Array.isArray(bucket.subtypes) ? bucket.subtypes[0] : ""))
    const actions = []
    if (representativeFinding) {
        actions.push(`<a href="#" class="iast-bucket-open-finding" data-bucket-id="${ptk_utils.escapeHtml(bucket.id || "")}">Open finding</a>`)
    }
    if (representativeFinding && representativeRequest) {
        actions.push(`<a href="#" class="iast-bucket-open-rbuilder" data-bucket-id="${ptk_utils.escapeHtml(bucket.id || "")}">Open request in R-Builder</a>`)
    }
    const actionLinks = [
        `<a href="#" class="iast-bucket-details-toggle" data-visible="false">Details</a>`,
        ...actions
    ]
    const actionsHtml = `<div style="margin-top:6px">${actionLinks.join(' &middot; ')}</div>`
    const detailsHtml = details.map((entry) => {
        return `<div>${ptk_utils.escapeHtml(entry.label)}: ${renderIastBucketValue(entry.value)}</div>`
    }).join("")
    return `
        <div class="ui message attack_info iast-discovery-item ${attackClass}"
            style="overflow:auto"
            data-index="${index}"
            data-bucket-id="${ptk_utils.escapeHtml(bucket.id || "")}"
            data-order="${risk.visual.order}"
            data-group="${ptk_utils.escapeHtml(groupKey)}"
            data-severity="${ptk_utils.escapeHtml(severity)}">
            <div class="description">
                ${primarySubtype ? `<div><b>${ptk_utils.escapeHtml(primarySubtype)}</b></div>` : ""}
                <div>${renderIastBucketLead(whyInteresting)}</div>
                <div style="margin-top:6px">${ptk_utils.escapeHtml(nextCheck)}</div>
                ${actionsHtml}
                <div class="iast-bucket-details-content" style="display:none; margin-top:6px">
                    <div>Source: ${renderIastBucketValue(sourceDetail)}</div>
                    ${additionalSources ? `<div>Also tainted from: ${renderIastBucketValue(additionalSources)}</div>` : ""}
                    <div>Sink: ${renderIastBucketValue(sink)}</div>
                    ${sinkValuePreview ? `<div>Sink value: ${renderIastBucketValue(sinkValuePreview)}</div>` : ""}
                    ${domTarget ? `<div>Target element: ${renderIastBucketValue(domTarget)}</div>` : ""}
                    <div>Route: ${renderIastBucketValue(`${route.method || "GET"} ${route.path || "/"}`)}</div>
                    <div>Instances: ${renderIastBucketValue(String(bucket.hits || 0))}</div>
                    ${traceFrame ? `<div>Trace: ${renderIastBucketValue(traceFrame)}</div>` : ""}
                    ${detailsHtml}
                </div>
            </div>
        </div>
    `
}

function renderIastDiscovery(scanResult) {
    const buckets = normalizeIastDiscoveryBuckets(scanResult)
    let renderIndex = 0
    const sections = IAST_DISCOVERY_GROUPS.map((group) => {
        const entries = buckets.filter((bucket) => bucket.bucket === group.key)
        const sorted = entries.slice().sort((left, right) => {
            const leftRisk = discoveryBucketSeverityModel(left)
            const rightRisk = discoveryBucketSeverityModel(right)
            const orderDiff = (leftRisk.visual.order || 99) - (rightRisk.visual.order || 99)
            if (orderDiff !== 0) return orderDiff
            const priorityDiff = (right.priority || 0) - (left.priority || 0)
            if (priorityDiff !== 0) return priorityDiff
            const hitsDiff = (right.hits || 0) - (left.hits || 0)
            if (hitsDiff !== 0) return hitsDiff
            return discoveryBucketTitle(left, group.key).localeCompare(discoveryBucketTitle(right, group.key))
        })
        const itemsHtml = sorted.map((bucket) => {
            const html = buildIastDiscoveryItem(bucket, group.key, renderIndex)
            renderIndex += 1
            return html
        }).join("")
        return `
            <div class="iast-discovery-panel" data-discovery-group="${ptk_utils.escapeHtml(group.key)}">
                <div class="iast-discovery-cards">${itemsHtml || `
                    <div class="ui small message">
                        <div class="header">${ptk_utils.escapeHtml(group.title)}</div>
                        <p>${ptk_utils.escapeHtml(group.empty)}</p>
                    </div>
                `}</div>
            </div>
        `
    })
    $("#discovery_info").html(sections.join(""))
}

function ensureIastDiscoveryRendered({ force = false } = {}) {
    if (!force && !iastDiscoveryDirty) return
    const raw = controller?.scanResult?.scanResult || controller?.scanViewModel || null
    const vm = controller?.scanViewModel || (raw ? normalizeScanResult(raw) : null)
    if (!vm) return
    renderIastDiscovery(vm)
    iastDiscoveryDirty = false
}

function showResultModal(header, message, options = {}) {
    $('#result_header').text(header)
    $('#result_message').text(message || '')
    $('#result_dialog').find('.result_open_settings_btn').toggle(!!options?.showSettings)
    $('#result_dialog').modal('show')
}

const $iastSaveScanModal = $('#save_scan_modal')
let $iastSaveScanProjectDropdown = $('#save_scan_project_select')
const $iastSaveScanModalError = $('#save_scan_modal_error')
const iastSaveScanProjectMap = new Map()
const $downloadScansModal = $('#download_scans')
let $iastDownloadProjectDropdown = $('#download_project_select')
const iastDownloadProjectMap = new Map()

function handleIastSaveScanResponse(result) {
    if (result instanceof Error) {
        showResultModal('Error', result.message || 'Unable to save scan')
        return
    }
    if (result?.success) {
        showResultModal('Success', 'Scan saved')
    } else {
        const message = result?.json?.message || result?.message || 'Unable to save scan'
        showResultModal('Error', message, { showSettings: result?.error === 'missing_api_key' })
    }
}

function extractProjectsFromPayload(payload) {
    if (!payload) return []
    if (Array.isArray(payload)) return payload
    if (typeof payload !== 'object') return []
    const containers = ['projects', 'data', 'items', 'results']
    for (const key of containers) {
        const value = payload[key]
        if (!value) continue
        if (Array.isArray(value)) {
            return value
        }
        const nested = extractProjectsFromPayload(value)
        if (nested.length) {
            return nested
        }
    }
    return []
}

function normalizeProjectOption(project) {
    if (project === null || project === undefined) return null
    if (typeof project === 'string' || typeof project === 'number' || typeof project === 'boolean') {
        const value = project
        return { value: String(value), text: String(value), raw: value }
    }
    if (typeof project !== 'object') return null
    const idFields = ['id', 'projectId', 'project_id', '_id', 'uuid', 'slug', 'key']
    let value = null
    for (const field of idFields) {
        if (project[field] !== undefined && project[field] !== null && project[field] !== '') {
            value = project[field]
            break
        }
    }
    if (!value && project?.name) {
        value = project.name
    }
    if (!value) return null
    const text = project.name || project.title || project.projectName || project.display_name || project.displayName || project.slug || project.key || String(value)
    return { value: String(value), text, raw: value }
}

function buildProjectOptions(payload) {
    const rawProjects = extractProjectsFromPayload(payload)
    const options = []
    rawProjects.forEach((project) => {
        const option = normalizeProjectOption(project)
        if (option) {
            options.push(option)
        }
    })
    return options
}

function resetSemanticDropdown($dropdown) {
    if (!$dropdown || !$dropdown.length) {
        return $dropdown
    }
    const id = $dropdown.attr('id') || ''
    const classes = $dropdown.attr('class') || 'ui dropdown'
    const $newDropdown = $(`<select id="${id}" class="${classes}"></select>`)
    const $existingWrapper = $dropdown.closest('.ui.dropdown.selection')
    if ($existingWrapper.length) {
        $existingWrapper.replaceWith($newDropdown)
    } else {
        $dropdown.replaceWith($newDropdown)
    }
    return $newDropdown
}

function rebuildProjectDropdown($dropdown, projectMap, projectOptions, placeholderText) {
    let $target = resetSemanticDropdown($dropdown)
    projectMap.clear()
    if (!$target) return $dropdown
    $target.empty()
    const placeholder = document.createElement('option')
    placeholder.value = ''
    placeholder.textContent = placeholderText || 'Select a project'
    $target.append(placeholder)
    projectOptions.forEach((opt) => {
        const option = document.createElement('option')
        option.value = opt.value
        option.textContent = opt.text
        projectMap.set(opt.value, opt.raw)
        $target.append(option)
    })
    $target.dropdown()
    $target.dropdown('clear')
    return $target
}

function rebuildIastProjectDropdown(projectOptions) {
    $iastSaveScanProjectDropdown = rebuildProjectDropdown($iastSaveScanProjectDropdown, iastSaveScanProjectMap, projectOptions, 'Select a project')
}

function rebuildIastDownloadProjectDropdown(projectOptions) {
    $iastDownloadProjectDropdown = rebuildProjectDropdown($iastDownloadProjectDropdown, iastDownloadProjectMap, projectOptions, 'Select a project')
    if (!$iastDownloadProjectDropdown) return
    $iastDownloadProjectDropdown.off('change').on('change', function () {
        const selected = $(this).val()
        if (!selected) {
            clearDownloadScansTable()
            setDownloadScansError('')
            return
        }
        const projectId = iastDownloadProjectMap.get(selected) ?? selected
        loadIastScansForProject(projectId)
    })
}

function hideIastSaveScanModalError() {
    $iastSaveScanModalError.hide().text('')
}

function showIastSaveScanModalError(message) {
    $iastSaveScanModalError.text(message || '').show()
}

function fetchIastPortalProjects() {
    return controller.getProjects().then((result) => {
        if (!result?.success) {
            const message = result?.json?.message || result?.message || 'Unable to load projects. Check your PTK Pro configuration.'
            throw new Error(message)
        }
        const projectOptions = buildProjectOptions(result.json)
        if (!projectOptions.length) {
            throw new Error('No projects available. Create a project in the portal and try again.')
        }
        return projectOptions
    })
}

function runIastSaveScan(projectId, $loader) {
    hideIastSaveScanModalError()
    if ($loader) {
        $loader.addClass('active')
    }
    $iastSaveScanModal.addClass('loading')
    controller.saveScan(projectId).then((result) => {
        handleIastSaveScanResponse(result)
        $iastSaveScanModal.modal('hide')
    }).catch((err) => {
        showResultModal('Error', err?.message || 'Unable to save scan')
    }).finally(() => {
        if ($loader) {
            $loader.removeClass('active')
        }
        $iastSaveScanModal.removeClass('loading')
    })
}

function showIastSaveScanModal($loader) {
    hideIastSaveScanModalError()
    $iastSaveScanModal
        .modal({
            allowMultiple: true,
            onApprove: function () {
                const projectId = $iastSaveScanProjectDropdown.val()
                if (!projectId) {
                    showIastSaveScanModalError('Select a project to continue.')
                    return false
                }
                const payloadProjectId = iastSaveScanProjectMap.get(projectId) ?? projectId
                runIastSaveScan(payloadProjectId, $loader)
                return false
            }
        })
        .modal('show')
}

function requestIastProjectsAndShowModal($loader) {
    if ($loader) {
        $loader.addClass('active')
    }
    fetchIastPortalProjects()
        .then((projectOptions) => {
            rebuildIastProjectDropdown(projectOptions)
            showIastSaveScanModal($loader)
        })
        .catch((err) => {
            showResultModal('Error', err?.message || 'Unable to load projects. Check your PTK Pro configuration.')
        })
        .finally(() => {
            if ($loader) {
                $loader.removeClass('active')
            }
        })
}

function setDownloadScansError(message) {
    if (message) {
        $('#download_error').text(message)
        $('#download_scans_error').show()
    } else {
        $('#download_error').text('')
        $('#download_scans_error').hide()
    }
}

function extractDownloadScans(payload, inheritedHost = '') {
    if (!payload) return []
    if (Array.isArray(payload)) {
        return payload.reduce((acc, item) => acc.concat(extractDownloadScans(item, inheritedHost)), [])
    }
    if (typeof payload !== 'object') return []
    const host = payload.hostname || payload.host || payload.domain || payload.project || payload.name || inheritedHost || ''
    if (Array.isArray(payload.scans)) {
        return payload.scans.reduce((acc, item) => acc.concat(extractDownloadScans(item, host)), [])
    }
    const scanId = payload.scanId || payload.id
    if (scanId) {
        const rawDate = payload.scanDate || payload.finished_at || payload.created_at || payload.started_at || payload.meta?.scanDate
        return [{ hostname: host, scanId, scanDate: rawDate, raw: payload }]
    }
    const containers = ['items', 'data', 'results', 'entries', 'projects', 'records']
    return containers.reduce((acc, key) => {
        if (!payload[key]) return acc
        return acc.concat(extractDownloadScans(payload[key], host))
    }, [])
}

function renderDownloadScansTable(items) {
    const entries = extractDownloadScans(items)
    const dt = []
    entries.forEach((entry) => {
        if (!entry) return
        const scanId = entry.scanId || ''
        const hostname = entry.hostname || entry.raw?.meta?.hostname || ''
        const rawDate = entry.scanDate || entry.raw?.finished_at || entry.raw?.created_at || entry.raw?.started_at
        const dateObj = rawDate ? new Date(rawDate) : null
        const scanDate = dateObj && !isNaN(dateObj.getTime()) ? dateObj.toLocaleString() : ''
        const downloadAvailable = !(entry.raw?.download_available === false || entry.raw?.download_available === 0)
        const link = downloadAvailable
            ? `<div class="ui mini icon button download_scan_by_id" style="position: relative" data-scan-id="${scanId}"><i class="download alternate large icon" title="Download"></i><div style="position:absolute; top:1px;right: 2px"><div class="ui centered inline inverted loader"></div></div></div>`
            : `<div class="ui mini icon button disabled" style="position: relative" title="Download unavailable for this scan"><i class="download alternate large icon"></i></div>`
        dt.push([hostname, scanId, scanDate, link])
    })

    dt.sort(function (a, b) {
        if (a[0] === b[0]) {
            return 0
        }
        return a[0] < b[0] ? -1 : 1
    })
    const groupColumn = 0
    const params = {
        forceRebuild: true,
        data: dt,
        columnDefs: [{
            visible: false, targets: groupColumn
        }],
        order: [[groupColumn, 'asc']],
        drawCallback: function () {
            const api = this.api()
            const rows = api.rows({ page: 'current' }).nodes()
            let last = null
            api.column(groupColumn, { page: 'current' }).data().each(function (group, i) {
                if (last !== group) {
                    $(rows).eq(i).before(
                        `<tr class="group"><td colspan="3"><div class="ui black ribbon label">${group}</div></td></tr>`
                    )
                    last = group
                }
            })
        }
    }
    bindTable('#tbl_scans', params)
}

function clearDownloadScansTable() {
    renderDownloadScansTable([])
}

function loadIastDownloadProjects() {
    setDownloadScansError('')
    clearDownloadScansTable()
    $downloadScansModal.addClass('loading')
    fetchIastPortalProjects()
        .then((options) => {
            rebuildIastDownloadProjectDropdown(options)
        })
        .catch((err) => {
            setDownloadScansError(err?.message || 'Unable to load projects. Check your PTK Pro configuration.')
        })
        .finally(() => {
            $downloadScansModal.removeClass('loading')
        })
}

function loadIastScansForProject(projectId) {
    if (!projectId) {
        setDownloadScansError('Select a project to load scans.')
        clearDownloadScansTable()
        return
    }
    setDownloadScansError('')
    $downloadScansModal.addClass('loading')
    controller.downloadScans(projectId, 'iast').then((result) => {
        if (!result?.success) {
            const message = result?.json?.message || result?.message || 'Unable to load scans.'
            setDownloadScansError(message)
            clearDownloadScansTable()
            return
        }
        setDownloadScansError('')
        renderDownloadScansTable(result.json)
    }).catch((err) => {
        setDownloadScansError(err?.message || 'Unable to load scans.')
        clearDownloadScansTable()
    }).finally(() => {
        $downloadScansModal.removeClass('loading')
    })
}

function convertLegacyVulnToFinding(vuln, index) {
    if (!vuln) return null
    const owasp = normalizeOwasp(vuln.owasp)
    const cwe = normalizeCwe(vuln.cwe)
    const owaspPrimary = owasp.length ? owasp[0] : null
    const owaspLegacy = toLegacyOwaspString(owasp)
    return {
        id: vuln.id || `vuln-${index}`,
        ruleId: vuln.ruleId || vuln.id || vuln.category || `vuln-${index}`,
        ruleName: vuln.ruleName || vuln.category || `Vulnerability ${index + 1}`,
        moduleId: vuln.moduleId || null,
        moduleName: vuln.moduleName || null,
        category: vuln.category || null,
        severity: vuln.severity || 'medium',
        owasp,
        owaspPrimary,
        owaspLegacy,
        cwe,
        tags: vuln.tags || [],
        location: { url: vuln.url || null, method: vuln.method || null },
        affectedUrls: vuln.url ? [vuln.url] : [],
        evidence: {
            iast: {
                taintSource: vuln.taintSource || null,
                sinkId: vuln.sink || null,
                context: {},
                matched: null,
                trace: []
            }
        }
    }
}

function mergeLinkMaps(...sources) {
    const out = {}
    sources.forEach(src => {
        if (!src || typeof src !== 'object') return
        Object.entries(src).forEach(([key, value]) => {
            if (!key || value === undefined || value === null) return
            out[key] = value
        })
    })
    return out
}

function extractPrimaryIastEvidence(finding) {
    if (!finding) return null
    const evidence = finding.evidence
    if (!evidence) return null
    if (typeof evidence === 'object' && !Array.isArray(evidence)) {
        if (evidence.iast && typeof evidence.iast === 'object') return evidence.iast
        if (evidence.IAST && typeof evidence.IAST === 'object') return evidence.IAST
        return evidence
    }
    if (Array.isArray(evidence) && evidence.length) {
        const entry = evidence.find(ev => {
            const src = String(ev?.source || ev?.type || '').toLowerCase()
            return src === 'iast'
        })
        return entry || evidence[0] || null
    }
    return null
}

function buildIastItemFromFinding(finding, index) {
    return buildSharedIastItemFromFinding(finding, index)
}

function getIastAttackItem(index) {
    if (Number.isNaN(Number(index))) return null
    const items = Array.isArray(controller?.iastAttackItems) ? controller.iastAttackItems : null
    if (items && items[index]) return items[index]
    const legacyItems = controller?.scanResult?.scanResult?.items
    if (Array.isArray(legacyItems)) return legacyItems[index] || null
    return null
}

function getIastDiscoveryBucket(bucketId) {
    const scanResult = controller?.scanViewModel || controller?.scanResult?.scanResult || null
    if (!bucketId || !scanResult) return null
    return normalizeIastDiscoveryBuckets(scanResult).find((bucket) => String(bucket?.id || "") === String(bucketId)) || null
}

function findIastAttackItemByFindingId(findingId) {
    const normalizedId = String(findingId || "").trim()
    if (!normalizedId) return null
    const items = Array.isArray(controller?.iastAttackItems) ? controller.iastAttackItems : []
    return items.find((item) => {
        const itemId = String(item?.id || "").trim()
        const sourceFindingId = String(item?.__sourceFinding?.id || "").trim()
        return itemId === normalizedId || sourceFindingId === normalizedId
    }) || null
}

function resolveRepresentativeIastBucketFinding(bucket) {
    if (!bucket || !Array.isArray(bucket.evidenceRefs)) return null
    for (const ref of bucket.evidenceRefs) {
        if (!ref || String(ref.type || "") !== "finding") continue
        const finding = findIastAttackItemByFindingId(ref.id)
        if (finding) return finding
    }
    return null
}

function resolveRepresentativeIastBucketRequestEntry(item) {
    if (!item) return null
    const requestKey = String(item?.requestKey || "").trim()
    if (!requestKey) return null
    return controller?._iastRequestIndex?.get(requestKey) || null
}

function buildIastBucketRawRequest(item, requestEntry) {
    const evidenceEntry = extractPrimaryIastEvidence(item) || {}
    const sinkContext = evidenceEntry?.sinkContext && typeof evidenceEntry.sinkContext === "object" ? evidenceEntry.sinkContext : {}
    const contextPayload = evidenceEntry?.context && typeof evidenceEntry.context === "object" ? evidenceEntry.context : {}
    const method = String(
        requestEntry?.method
        || sinkContext?.requestMethod
        || contextPayload?.method
        || item?.location?.method
        || "GET"
    ).toUpperCase()
    const requestUrl = String(
        sinkContext?.requestUrl
        || contextPayload?.requestUrl
        || contextPayload?.url
        || requestEntry?.displayUrl
        || requestEntry?.url
        || extractIastPrimaryUrl(item)
        || ""
    ).trim()
    if (!requestUrl) return null

    let requestTarget = requestUrl
    let hostHeader = ""
    try {
        const parsed = new URL(requestUrl, window.location.href)
        requestTarget = parsed.href || requestUrl
        hostHeader = parsed.host || ""
    } catch (_) {
        requestTarget = requestUrl
    }

    const parts = [`${method} ${requestTarget || "/"} HTTP/1.1`]
    if (hostHeader) parts.push(`Host: ${hostHeader}`)
    parts.push("User-Agent: PentestKit-IAST")
    parts.push("Accept: */*")
    return parts.join("\n")
}

function triggerIastStatsEvent(rawScanResult, viewModel) {
    const raw = rawScanResult || {}
    const vm = viewModel || normalizeScanResult(raw)
    const stats = vm.stats || raw.stats || {}
    $(document).trigger("bind_stats", Object.assign({}, raw, { stats }))
}


jQuery(function () {

    // initialize all modals
    $('.modal.coupled')
        .modal({
            allowMultiple: true
        })


    $(document).on("click", ".showHtml", function () {
        rutils.showHtml($(this))
    })
    $(document).on("click", ".showHtmlNew", function () {
        rutils.showHtml($(this), true)
    })

    $(document).on("click", ".generate_report", function () {
        browser.windows.create({
            type: 'popup',
            url: browser.runtime.getURL("/ptk/browser/report.html?iast_report")
        })
    })

    $(document).on("click", ".save_scan", function () {
        const $loader = $(this).find('.loader')
        requestIastProjectsAndShowModal($loader)
    })

    $(document).on('click', '#load_pro_policies_button', async function () {
        setIastPortalPolicyLoading(true)
        try {
            const result = await controller.loadPolicyMetadata()
            updateIastRulepackUi(result)
            if (result?.success) {
                showResultModal('Success', buildPolicyLoadSuccessMessage('IAST', result?.policyState || {}))
            } else {
                showResultModal(
                    'Error',
                    buildPolicyLoadErrorMessage(result, 'IAST scan policies'),
                    { showSettings: result?.error === 'missing_api_key' }
                )
            }
        } catch (err) {
            showResultModal('Error', buildPolicyLoadErrorMessage({ message: err?.message || 'unknown_error' }, 'IAST scan policies'))
        } finally {
            setIastPortalPolicyLoading(false)
        }
        return false
    })

    $(document).on('click', '#result_dialog .result_open_settings_btn', function () {
        openExtensionSettingsWindow()
        $('#result_dialog').modal('hide')
        return false
    })

    $(document).on('change', '#iast-scan-policy', async function () {
        const $select = $(this)
        const rawValue = String($select.val() || '').trim()
        const policyId = rawValue.startsWith('policy:') ? rawValue.slice('policy:'.length).trim() : ''
        const policyName = policyId ? String($select.find('option:selected').text() || '').trim() : null
        setIastPortalPolicyLoading(true)
        try {
            const result = policyId
                ? await controller.selectPolicy(policyId, policyName)
                : await controller.clearPolicy()
            updateIastRulepackUi(result)
            if (result?.success) {
                maybeBindIastPortalPreview(result)
            } else {
                showResultModal(
                    'Error',
                    result?.error === 'missing_api_key'
                        ? 'PAT required. Activate the portal token in Settings first.'
                        : `Failed to update scan policy: ${result?.error || 'unknown_error'}`
                )
            }
        } catch (err) {
            showResultModal('Error', `Failed to update scan policy: ${err?.message || 'unknown_error'}`)
        } finally {
            setIastPortalPolicyLoading(false)
        }
        return false
    })

    $(document).on("click", ".run_scan_runtime", function () {
        controller.init().then(async function (result) {
            if (!result?.activeTab?.url) {
                $('#result_header').text("Error")
                $('#result_message').text("Active tab not set. Reload required tab to activate tracking.")
                $('#result_dialog').modal('show')
                return false
            }

            let h = new URL(result.activeTab.url).host
            $('#scan_host').text(h)
            const rulepackSelection = updateIastRulepackUi(result)
            // $('#scan_domains').text(h)

            $('#iast-scan-strategy').val('SMART')
            window._ptkIastReloadWarningClosed = false
            let contentReady = true
            contentReady = await rutils.pingContentScript(result.activeTab.tabId, { timeoutMs: 700 })
            if (!window._ptkIastReloadWarningClosed) {
                $('#ptk_scan_reload_warning').toggle(!contentReady)
            }

            $('#run_scan_dlg')
                .modal({
                    allowMultiple: true,
                    onApprove: function () {
                        const scanStrategy = $('#iast-scan-strategy').val() || 'SMART'
                        const selectedPolicyValue = String($('#iast-scan-policy').val() || '').trim()
                        const hasPortalEntries = Array.isArray(controller?.policyState?.metadata) && controller.policyState.metadata.length > 0
                        if (hasPortalEntries && !selectedPolicyValue) {
                            showResultModal('Error', 'Select a scan policy.')
                            return false
                        }
                        if (!contentReady) {
                            $('#ptk_scan_reload_warning').show()
                            return false
                        }
                        changeView({
                            isScanRunning: true,
                            rulepackSelection,
                            scanResult: {
                                host: h,
                                findings: [],
                                items: [],
                                policyId: rulepackSelection?.policyId || null,
                                settings: {
                                    iastRulepackSource: rulepackSelection?.source || 'local',
                                    iastPolicyName: rulepackSelection?.policyName || null,
                                    iastRulepackVariant: rulepackSelection?.variant || null
                                },
                                stats: { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
                            }
                        })
                        controller.runBackgroundScan(
                            result.activeTab.tabId,
                            h,
                            scanStrategy,
                            buildIastRulepackRunOptions(rulepackSelection)
                        ).then(function (result) {
                            if (result?.success === false) {
                                showResultModal('Error', result?.message || result?.error || 'Failed to start scan.')
                                return
                            }
                            $("#request_info").html("")
                            $("#attacks_info").html("")
                            $("#discovery_info").html("")
                            triggerIastStatsEvent(result.scanResult)
                            changeView(result)
                        })
                    }
                })
                .modal('show')
            bindIastHelpPopups()
        })

        return false
    })

    $(document).on("click", "#ptk_scan_reload_warning_close_iast", function () {
        window._ptkIastReloadWarningClosed = true
        $('#ptk_scan_reload_warning').hide()
    })

    $(document).on("click", ".stop_scan_runtime", function () {
        controller.stopBackgroundScan().then(function (result) {
            changeView(result)
            bindScanResult(result)
        })
        return false
    })

    $('.settings.rattacker').on('click', function () {
        $('#settings').modal('show')

    })

    $('.cloud_download_scans').on('click', function () {
        $downloadScansModal.modal('show')
        loadIastDownloadProjects()
    })

    $(document).on("click", ".download_scan_by_id", function () {
        $(this).parent().find(".loader").addClass("active")
        let scanId = $(this).attr("data-scan-id")
        controller.downloadScanById(scanId).then(function (result) {
            if (result?.success === false) {
                const message = result?.json?.message || result?.message || 'Unable to download scan'
                showResultModal('Error', message, { showSettings: result?.error === 'missing_api_key' })
                return
            }
            const info = result?.scanResult ? result : { isScanRunning: false, scanResult: result }
            changeView(info)
            if (hasRenderableIastData(info.scanResult)) {
                bindScanResult(info)
            }
            $('#download_scans').modal('hide')
        }).catch((err) => {
            showResultModal('Error', err?.message || 'Unable to download scan')
        })
    })

    $('.import_export').on('click', function () {

        controller.init().then(function (result) {
            if (!hasRenderableIastData(result.scanResult)) {
                $('.export_scan_btn').addClass('disabled')
            } else {
                $('.export_scan_btn').removeClass('disabled')
            }
            hideExportProgress()
            $('#import_export_dlg').modal('show')
        })

    })

    const $exportScanBtn = $('.export_scan_btn')
    const $importScanFileBtn = $('.import_scan_file_btn')
    const $importScanTextBtn = $('.import_scan_text_btn')
    const $scanExportProgress = $('#scan_export_progress')
    const $scanExportProgressTitle = $('#scan_export_progress .ptk-export-progress-title')
    const $scanExportProgressBar = $('#scan_export_progress_bar')
    const $scanExportProgressText = $('#scan_export_progress_text')
    let exportInProgress = false
    let importInProgress = false

    function setTransferProgress(title, percent, text) {
        const safePercent = Math.max(0, Math.min(100, Number(percent) || 0))
        $scanExportProgress.show()
        $scanExportProgressTitle.text(title || 'Progress')
        $scanExportProgressBar.css('width', `${safePercent}%`)
        $scanExportProgressText.text(text || `${title || 'Working'}... ${safePercent}%`)
    }

    function setExportProgress(percent, text) {
        setTransferProgress('Export', percent, text)
    }

    function hideExportProgress() {
        $scanExportProgress.hide()
        $scanExportProgressTitle.text('Export')
        $scanExportProgressBar.css('width', '0%')
        $scanExportProgressText.text('Preparing export...')
    }

    function setImportProgress(percent, text) {
        setTransferProgress('Import', percent, text)
    }

    function updateImportProgressFromEvent(event) {
        const phase = String(event?.phase || '')
        const completed = Number(event?.completed || 0)
        const total = Number(event?.total || 0)
        if (phase === 'read_start') {
            setImportProgress(5, 'Reading scan file...')
            return
        }
        if (phase === 'read_complete') {
            setImportProgress(35, 'Preparing import payload...')
            return
        }
        if (phase === 'upload_start') {
            setImportProgress(65, total > 1 ? `Uploading import payload... 0/${total}` : 'Uploading import payload...')
            return
        }
        if (phase === 'upload_chunk') {
            const percent = total > 0 ? Math.floor((completed / total) * 25) : 0
            setImportProgress(65 + percent, `Uploading import payload... ${completed}/${total}`)
            return
        }
        if (phase === 'finalize_start') {
            setImportProgress(92, 'Finalizing import...')
            return
        }
        if (phase === 'done') {
            setImportProgress(100, 'Import complete.')
        }
    }

    function updateExportProgressFromChunk(event) {
        const phase = String(event?.phase || '')
        const completed = Number(event?.completed || 0)
        const total = Number(event?.total || 0)
        if (phase === 'chunk_start') {
            setExportProgress(15, total > 1 ? `Downloading export chunks... 0/${total}` : 'Preparing download...')
            return
        }
        if (phase === 'chunk_download') {
            const percent = total > 0 ? Math.floor((completed / total) * 100) : 0
            setExportProgress(percent, `Downloading export chunks... ${completed}/${total}`)
            return
        }
        if (phase === 'done') {
            setExportProgress(100, 'Export complete.')
        }
    }

    $('.export_scan_btn').on('click', function () {
        if (exportInProgress) return
        exportInProgress = true
        $exportScanBtn.addClass('disabled loading')
        setExportProgress(5, 'Preparing export payload...')

        controller.exportScanResult().then(async function (scanResult) {
            if (scanResult?.exportMode === "chunked") {
                setExportProgress(10, 'Preparing chunked download...')
                await downloadScanExportResult(controller, scanResult, "PTK_IAST_scan.json", {
                    onProgress: updateExportProgressFromChunk
                })
            } else if (scanResult && hasRenderableIastData(scanResult)) {
                setExportProgress(60, 'Compressing export payload...')
                await downloadScanExportResult(controller, scanResult, "PTK_IAST_scan.json", {
                    onProgress: updateExportProgressFromChunk
                })
            } else {
                hideExportProgress()
                showResultModal("Error", "Nothing to export yet.")
            }
        }).catch(err => {
            hideExportProgress()
            showResultModal("Error", err?.message || "Unable to export scan")
        }).finally(() => {
            exportInProgress = false
            $exportScanBtn.removeClass('disabled loading')
            setTimeout(() => {
                if (!exportInProgress) hideExportProgress()
            }, 800)
        })
    })

    $('.import_scan_file_btn').on('click', function (e) {
        $("#import_scan_file_input").trigger("click")
        e.stopPropagation()
        e.preventDefault()
    })

    $("#import_scan_file_input").on('change', function (e) {
        e.stopPropagation()
        e.preventDefault()
        let file = $('#import_scan_file_input').prop('files')[0]
        loadFile(file)
        $('#import_scan_file_input').val(null)
    })

    async function loadFile(file) {
        if (importInProgress) return
        importInProgress = true
        $exportScanBtn.addClass('disabled')
        $importScanFileBtn.addClass('disabled loading')
        $importScanTextBtn.addClass('disabled')
        try {
            setImportProgress(2, 'Preparing import...')
            const result = await controller.loadfile(file, {
                onProgress: updateImportProgressFromEvent
            })
            if (result instanceof Error || result?.success === false || !hasRenderableIastData(result?.scanResult)) {
                showResultModal("Error", result?.message || result?.error || "Could not import IAST scan")
                return
            }
            changeView(result)
            bindScanResult(result)
            $('#import_export_dlg').modal('hide')
        } catch (e) {
            showResultModal("Error", e?.message || "Could not import IAST scan")
        } finally {
            importInProgress = false
            $exportScanBtn.removeClass('disabled')
            $importScanFileBtn.removeClass('disabled loading')
            $importScanTextBtn.removeClass('disabled')
            setTimeout(() => {
                if (!importInProgress && !exportInProgress) hideExportProgress()
            }, 800)
        }
    }

    $('.import_scan_text_btn').on('click', function () {
        let scan = $("#import_scan_json").val()
        controller.save(scan).then(result => {
            changeView(result)
            if (hasRenderableIastData(result.scanResult)) {
                bindScanResult(result)
            }
            $('#import_export_dlg').modal('hide')
        }).catch(e => {
            $('#result_message').text('Could not import IAST scan')
            $('#result_dialog').modal('show')
        })
    })





    $(document).on("click", ".reset", function () {
        $("#request_info").html("")
        $("#attacks_info").html("")
        $("#discovery_info").html("")
        $('.generate_report').hide()
        $('.save_scan').hide()
        //$('.exchange').hide()

        hideRunningForm()
        showWelcomeForm()
        controller.reset().then(function (result) {
            updateIastRulepackUi(result)
            triggerIastStatsEvent(result.scanResult)
            ensureIastDefaultModulesLoaded({ force: true }).catch(() => { })
        })
    })

    $(document).on("click", ".request_filter_toggle", function (event) {
        event.preventDefault()
        event.stopPropagation()
        const key = $(this).attr("data-request-key") || ""
        toggleRequestFilter(key)
    })

    $('.send_rbuilder').on("click", function () {
        let request = $('#raw_request').val().trim()
        window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(request)))
        return false
    })


    $('#filter_all').on("click", function () {
        setIastScopeFilter('all')
    })

    $('#filter_vuln').on("click", function () {
        setIastScopeFilter('vuln')
    })

    $(document).on("click", "#iast_result_tabs .item", function (event) {
        event.preventDefault()
        const view = $(this).attr("data-view") || "findings"
        setIastView(view)
    })


    $(document).on("click", ".btn_stacktrace", function () {
        let el = $(this).parent().find(".content.stacktrace")
        if (this.textContent.trim() == 'Stack trace') {
            this.textContent = 'Hide stack trace'
            $(el).show()
        } else {
            $(this).parent().find(".content.stacktrace").hide()
            this.textContent = 'Stack trace'
        }

    })

    $(document).on("click", ".close.icon.stacktrace", function () {
        $(this).parent().hide()
        $(this).parent().parent().find(".btn_stacktrace").text('Stack trace')
    })

    $(document).on("click", ".iast-trace-toggle", function (event) {
        event.preventDefault()
        const $toggle = $(this)
        const $content = $toggle.next(".iast-trace-content")
        if (!$content.length) return
        const isVisible = $content.is(":visible")
        if (isVisible) {
            $content.slideUp(120)
            $toggle.attr("data-visible", "false").text("Show trace")
        } else {
            $content.slideDown(120)
            $toggle.attr("data-visible", "true").text("Hide trace")
        }
    })

    $(document).on("click", ".iast-bucket-details-toggle", function (event) {
        event.preventDefault()
        const $toggle = $(this)
        const $content = $toggle.closest(".iast-discovery-item").find(".iast-bucket-details-content").first()
        if (!$content.length) return
        const isVisible = $content.is(":visible")
        if (isVisible) {
            $content.slideUp(120)
            $toggle.attr("data-visible", "false").text("Details")
        } else {
            $content.slideDown(120)
            $toggle.attr("data-visible", "true").text("Hide details")
        }
    })

    $(document).on("click", ".iast-bucket-open-finding", function (event) {
        event.preventDefault()
        const bucketId = $(this).attr("data-bucket-id") || ""
        const bucket = getIastDiscoveryBucket(bucketId)
        const item = resolveRepresentativeIastBucketFinding(bucket)
        if (!item) return
        rutils.bindAttackDetails_IAST(item)
    })

    $(document).on("click", ".iast-bucket-open-rbuilder", function (event) {
        event.preventDefault()
        const bucketId = $(this).attr("data-bucket-id") || ""
        const bucket = getIastDiscoveryBucket(bucketId)
        const item = resolveRepresentativeIastBucketFinding(bucket)
        if (!item) return
        const requestEntry = resolveRepresentativeIastBucketRequestEntry(item)
        if (!requestEntry) return
        const rawRequest = buildIastBucketRawRequest(item, requestEntry)
        if (!rawRequest) return
        window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(rawRequest)))
    })


    $(document).on("bind_stats", function (e, scanResult) {
        if (scanResult?.stats) {
            rutils.bindStats(scanResult.stats, 'iast')
            if ((scanResult.stats.findingsCount || 0) > 0) {
                $('#filter_vuln').trigger("click")
            }
        }
        return false
    })

    $.fn.selectRange = function (start, end) {
        var e = document.getElementById($(this).attr('id')); // I don't know why... but $(this) don't want to work today :-/
        if (!e) return;
        else if (e.setSelectionRange) { e.focus(); e.setSelectionRange(start, end); } /* WebKit */
        else if (e.createTextRange) { var range = e.createTextRange(); range.collapse(true); range.moveEnd('character', end); range.moveStart('character', start); range.select(); } /* IE */
        else if (e.selectionStart) { e.selectionStart = start; e.selectionEnd = end; }
    }

    controller.init().then(function (result) {
        updateIastRulepackUi(result)
        changeView(result)
        if (hasRenderableIastData(result.scanResult)) {
            bindScanResult(result)
        } else if (!result.isScanRunning) {
            showWelcomeForm()
            ensureIastDefaultModulesLoaded().catch(() => { })
        }
    }).catch(() => { })

})

function filterByRequestId(requestId) {
    toggleRequestFilter(requestId)
}

function setIastPageLoader(show) {
    const $loader = $('#iast_page_loader')
    if (!$loader.length) return
    $loader.toggle(!!show)
}

function showWelcomeForm() {
    setIastPageLoader(false)
    $('#main').hide()
    $('#welcome_message').show()
    $('#run_scan_bg_control').show()
    resetIastProgressRender({ hide: true })
}

function hideWelcomeForm() {
    $('#welcome_message').hide()
    $('#main').show()
}

function showRunningForm(result) {
    setIastPageLoader(false)
    $('#main').show()
    $('#scanning_url').text(result.scanResult.host)
    updateIastRulepackUi(result)
    $('.scan_info').show()
    $('#stop_scan_bg_control').show()
}

function hideRunningForm() {
    $('#scanning_url').text("")
    $('.scan_info').hide()
    $('#stop_scan_bg_control').hide()
    resetIastProgressRender({ hide: true })
}

function showScanForm(result) {
    setIastPageLoader(false)
    $('#main').show()
    $('#run_scan_bg_control').show()
}

function hideScanForm() {
    $('#run_scan_bg_control').hide()
}


function changeView(result) {
    $('#init_loader').removeClass('active')
    if (result.isScanRunning) {
        hideWelcomeForm()
        hideScanForm()
        showRunningForm(result)
        scheduleIastProgressUpdate({ message: "Runtime scan running", scanResult: result.scanResult || {} })
    }
    else if (hasRenderableIastData(result.scanResult)) {
        hideWelcomeForm()
        hideRunningForm(result)
        showScanForm()
        resetIastProgressRender({ hide: true })
    }
    else {
        hideRunningForm()
        hideScanForm()
        showWelcomeForm()
    }
}

function cleanScanResult() {
    $("#attacks_info").html("")
    $("#discovery_info").html("")
    resetIastCounters()
    rutils.bindStats({
        attacksCount: 0,
        findingsCount: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    }, 'iast')
}

function bindScanResult(result) {
    if (!result.scanResult) return
    const raw = result.scanResult || {}
    const vm = raw.__normalized ? raw : normalizeScanResult(raw)
    controller.scanResult = result
    controller.scanViewModel = vm
    updateIastRulepackUi(result)
    if (!result.isScanRunning) {
        resetIastProgressRender({ hide: true })
    }
    $('.generate_report').show()
    if (PORTAL_ACTIONS_VISIBLE) {
        $('.save_scan').show()
    } else {
        $('.save_scan').hide()
    }
    $('#request_info').html("")
    $('#attacks_info').html("")
    $('#discovery_info').html("")
    iastDiscoveryDirty = true
    hideWelcomeForm()
    IAST_DELTA_QUEUE.length = 0
    if (iastFlushTimer) {
        clearTimeout(iastFlushTimer)
        iastFlushTimer = null
    }

    const requests = prepareIastRequests(vm)
    controller._iastRequests = requests
    controller._iastRequestIndex = new Map()
    requests.forEach((req) => {
        if (req?._uiKey) controller._iastRequestIndex.set(req._uiKey, req)
    })
    bindRequestList(requests)
    iastRequestFilterDirty = true
    const requestIndex = buildIastRequestIndex(requests)

    const findings = Array.isArray(vm.findings) ? vm.findings : []
    const legacyItems = Array.isArray(raw.items)
        ? raw.items
        : (raw.items && typeof raw.items === 'object'
            ? Object.keys(raw.items).sort().map(key => raw.items[key]).filter(Boolean)
            : [])
    const legacyVulns = Array.isArray(raw.vulns) ? raw.vulns : []

    let attackItems = []
    if (findings.length) {
        const showSuppressed = localStorage.getItem('ptk_iast_show_suppressed') === '1'
        attackItems = findings.map((finding, index) => {
            const item = buildIastItemFromFinding(finding, index)
            if (item) {
                item.__sourceFinding = finding
                item.requestKey = finding?.requestKey || null
            }
            return item
        })
            .filter(Boolean)
            .filter(item => {
                if (showSuppressed) return true
                const suppression = item?.evidence?.iast?.suppression
                return !(suppression && suppression.suppressed)
            })
    } else if (legacyItems.length) {
        attackItems = legacyItems.map((item, index) => {
            if (!item) return null
            item.__index = Number(index)
            item.requestId = index
            return item
        }).filter(Boolean)
    } else if (legacyVulns.length) {
        attackItems = legacyVulns.map((vuln, index) => {
            const normalized = convertLegacyVulnToFinding(vuln, index)
            return buildIastItemFromFinding(normalized, index)
        }).filter(Boolean)
    }
    controller.iastAttackItems = attackItems
    resetIastCounters()
    const $attacksInfo = $("#attacks_info")
    if (iastFilterState.requestKey) {
        $attacksInfo.attr("data-request-key", iastFilterState.requestKey)
    } else {
        $attacksInfo.removeAttr("data-request-key")
    }
    updateIastRequestFilterStyle(iastFilterState.requestKey)
    $attacksInfo.attr("data-scope", iastFilterState.scope)

    const bucketMarkup = {
        critical: [],
        high: [],
        medium: [],
        low: [],
        info: []
    }
    const bucketOrder = ['critical', 'high', 'medium', 'low', 'info']
    attackItems.forEach((item, index) => {
        if (!item) return
        item.__index = Number(index)
        item.requestId = index
        if (!item.requestKey) {
            item.requestKey = mapFindingToRequestKey(item, requestIndex)
        }
        const bucket = getIastBucket(item)
        bucketMarkup[bucket].push(rutils.bindIASTAttack(item, index))
        updateIastCountersForFinding(item, item.requestKey)
    })
    const bucketHtml = bucketOrder
        .map((bucket) => `<div class="iast_bucket${bucketMarkup[bucket].length ? ' has-items' : ''}" data-bucket="${bucket}">${bucketMarkup[bucket].join('')}</div>`)
        .join('')
    $("#attacks_info").html(bucketHtml)

    const deferWork = () => {
        const scanning = !!result.isScanRunning
        controller._iastIsScanning = scanning
        if (scanning) {
            scheduleIastProgressUpdate({ message: "Runtime scan running", scanResult: raw })
        }
        // Keep bucket ordering; avoid DOM re-sorts.
        triggerIastStatsEvent(raw, vm)
        if (iastRequestFilterDirty) {
            updateRequestFilterActiveState()
            iastRequestFilterDirty = false
        }
        const discoveryCount = countIastDiscoveryItems(vm)
        if (!attackItems.length && discoveryCount > 0) {
            setIastView(firstPopulatedIastDiscoveryGroup(vm) || IAST_DISCOVERY_GROUPS[0].key)
        } else if (discoveryCount === 0 && isIastDiscoveryView(iastFilterState.view)) {
            setIastView("findings")
        } else {
            setIastView(iastFilterState.view)
        }
    }
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(deferWork)
    } else {
        setTimeout(deferWork, 0)
    }
}

function applyIastScanDelta(message) {
    const finding = message?.finding || null
    if (!finding) return
    if (!controller.scanViewModel) {
        if (message?.scanResult) {
            bindScanResult({ scanResult: message.scanResult, isScanRunning: message.isScanRunning })
        }
        return
    }
    if (!Array.isArray(controller.scanViewModel.findings)) {
        controller.scanViewModel.findings = []
    }
    if (!Array.isArray(controller.iastAttackItems)) {
        controller.iastAttackItems = []
    }
    IAST_DELTA_QUEUE.push(finding)
    if (!iastFlushTimer) {
        iastFlushTimer = setTimeout(flushIastQueue, IAST_FLUSH_INTERVAL_MS)
    }
}

function upsertIastRequestFromFinding(finding) {
    const requestKey = finding?.requestKey || null
    if (!requestKey) return null
    if (!controller._iastRequestIndex) {
        controller._iastRequestIndex = new Map()
    }
    if (controller._iastRequestIndex.has(requestKey)) {
        return null
    }
    const displayUrl = extractIastPrimaryUrl(finding) || finding?.location?.url || ""
    const normalizedUrl = canonicalizeIastUrl(displayUrl)
    const method = extractIastMethod(finding)
    const entry = {
        key: requestKey,
        _uiKey: requestKey,
        method,
        displayUrl: displayUrl || normalizedUrl || requestKey,
        url: normalizedUrl || displayUrl || "",
        _normalizedUrl: normalizedUrl || "",
        host: "",
        status: null,
        type: "finding",
        lastSeen: Date.now()
    }
    controller._iastRequestIndex.set(requestKey, entry)
    return entry
}

function flushIastQueue() {
    iastFlushTimer = null
    if (!IAST_DELTA_QUEUE.length) return
    const $attacksInfo = $("#attacks_info")
    if (iastFilterState.requestKey) {
        $attacksInfo.attr("data-request-key", iastFilterState.requestKey)
    } else {
        $attacksInfo.removeAttr("data-request-key")
    }
    updateIastRequestFilterStyle(iastFilterState.requestKey)
    $attacksInfo.attr("data-scope", iastFilterState.scope)
    const batch = IAST_DELTA_QUEUE.splice(0, IAST_DELTA_QUEUE.length)
    ensureIastBuckets($attacksInfo)
    const attackMarkup = []
    const requestMarkup = []
    let requestAdded = false

    batch.forEach((finding) => {
        if (!finding) return
        const index = controller.scanViewModel.findings.length
        controller.scanViewModel.findings.push(finding)
        const item = buildIastItemFromFinding(finding, index)
        if (!item) return
        item.__index = index
        item.requestId = index
        item.requestKey = finding?.requestKey || null
        controller.iastAttackItems.push(item)
        const bucket = getIastBucket(item)
        attackMarkup.push({ html: rutils.bindIASTAttack(item, index), bucket })
        updateIastCountersForFinding(item, item.requestKey)

        const reqEntry = upsertIastRequestFromFinding(finding)
        if (reqEntry) {
            requestMarkup.push(bindRequest(reqEntry))
            requestAdded = true
        }
    })

    if (requestMarkup.length) {
        $("#request_info").append(requestMarkup.join(""))
    }
    if (attackMarkup.length) {
        attackMarkup.forEach(({ html, bucket }) => {
            appendIastToBucket(html, bucket)
        })
    }

    if (requestAdded || iastRequestFilterDirty) {
        updateRequestFilterActiveState()
        iastRequestFilterDirty = false
    }
    renderIastStatsFromCounters()
    if (controller._iastIsScanning) {
        const latest = batch[batch.length - 1]
        const latestName = latest?.ruleName || latest?.name || latest?.title || "Finding captured"
        scheduleIastProgressUpdate({ message: `Captured ${latestName}`, scanResult: controller.scanViewModel || controller?.scanResult?.scanResult || {} })
    }
}

function ensureIastBuckets($container) {
    if ($container.find('.iast_bucket').length) return
    const buckets = ['critical', 'high', 'medium', 'low', 'info']
    const markup = buckets.map((bucket) => `<div class="iast_bucket" data-bucket="${bucket}"></div>`)
    $container.html(markup.join(''))
}

function appendIastToBucket(attackHtml, bucketKey) {
    const selector = `.iast_bucket[data-bucket="${bucketKey}"]`
    const $bucket = $("#attacks_info").find(selector)
    if ($bucket.length) {
        $bucket.addClass('has-items')
        $bucket.append(attackHtml)
    } else {
        $("#attacks_info").append(attackHtml)
    }
}

function getIastBucket(item) {
    const severityRaw = item?.severity || item?.evidence?.raw?.severity || 'info'
    const severity = String(severityRaw || 'info').toLowerCase()
    if (severity === 'critical') return 'critical'
    if (severity === 'high') return 'high'
    if (severity === 'medium') return 'medium'
    if (severity === 'low') return 'low'
    return 'info'
}

function bindModules(result) {
    const modules = Array.isArray(result?.default_modules)
        ? result.default_modules
        : (Array.isArray(controller?.default_modules) ? controller.default_modules : (Array.isArray(result) ? result : []))
    const rows = []
    modules.forEach((mod) => {
        if (!mod) return
        const moduleName = mod.name || mod.metadata?.name || mod.metadata?.module_name || mod.id || 'Module'
        const moduleSeverity = formatIastSeverityLabel(mod.metadata?.severity || mod.severity)
        const rules = Array.isArray(mod.rules) ? mod.rules : []
        if (rules.length) {
            rules.forEach(rule => {
                if (!rule) return
                const ruleName = rule.name || rule.metadata?.name || rule.id || 'Rule'
                const severity = formatIastSeverityLabel(rule.severity || rule.metadata?.severity || moduleSeverity)
                rows.push([ruleName, moduleName, formatIastSeverityDisplay(severity)])
            })
        } else {
            rows.push([moduleName, moduleName, formatIastSeverityDisplay(moduleSeverity)])
        }
    })
    rows.sort((a, b) => {
        const leftSeverity = formatIastSeverityLabel(a[2])
        const rightSeverity = formatIastSeverityLabel(b[2])
        const severityDiff = (IAST_SEVERITY_ORDER[leftSeverity] ?? 99) - (IAST_SEVERITY_ORDER[rightSeverity] ?? 99)
        if (severityDiff !== 0) return severityDiff
        const leftName = String(a[0] || '').toLowerCase()
        const rightName = String(b[0] || '').toLowerCase()
        return leftName.localeCompare(rightName)
    })
    bindTable('#iast_rules_table', { data: rows })
}

function bindRequest(info) {
    if (!info || !info._uiKey) return ''
    const requestUrl = ptk_utils.escapeHtml(info.displayUrl || info.url || 'unknown request')
    return `
        <div>
        <div class="title short_message_text request_filter_toggle" data-request-key="${ptk_utils.escapeHtml(info._uiKey)}" style="overflow-y: hidden;height: 34px;background-color: #eeeeee;margin:1px 0 0 0;cursor:pointer; position: relative">
            ${requestUrl}<i class="filter icon" style="float:right; position: absolute; top: 3px; right: -3px;" title="Filter by request"></i>
            
        </div>
    `
}



function bindAttackProgress(message) {
    const name = message?.info?.name || message?.info?.message || "Runtime scan running"
    scheduleIastProgressUpdate({ message: name })
}

function extractIastDataset(source) {
    if (!source) return []
    if (Array.isArray(source.findings) && source.findings.length) return source.findings
    if (source.legacy) {
        const legacyData = extractIastDataset(source.legacy)
        if (legacyData.length) return legacyData
    }
    const items = Array.isArray(source.items)
        ? source.items
        : (source.items && typeof source.items === 'object'
            ? Object.keys(source.items).sort().map(key => source.items[key]).filter(Boolean)
            : [])
    if (items.length) return items
    const vulns = Array.isArray(source.vulns) ? source.vulns : []
    if (vulns.length) {
        return vulns.map((vuln, index) => convertLegacyVulnToFinding(vuln, index)).filter(Boolean)
    }
    return []
}

function extractIastPrimaryUrl(item) {
    if (item?.location?.url) return item.location.url
    const ev = extractPrimaryIastEvidence(item) || {}
    if (Array.isArray(ev?.affectedUrls) && ev.affectedUrls.length) return ev.affectedUrls[0]
    if (Array.isArray(item?.affectedUrls) && item.affectedUrls.length) return item.affectedUrls[0]
    if (ev?.context?.url) return ev.context.url
    if (ev?.context?.location) return ev.context.location
    return ''
}

function extractIastMethod(item) {
    if (item?.location?.method) return String(item.location.method).toUpperCase()
    if (item?.request?.method) return String(item.request.method).toUpperCase()
    return 'GET'
}

function prepareIastRequests(source) {
    const requestMap = new Map()
    const addRequestEntry = (entry) => {
        if (!entry || typeof entry !== "object") return
        const displayUrl = entry.displayUrl || entry.url || null
        const normalizedUrl = canonicalizeIastUrl(displayUrl || entry.url)
        if (!normalizedUrl) return
        const method = String(entry.method || "GET").toUpperCase()
        const key = `${method} ${normalizedUrl}`
        const lastSeenTs = Number(entry.lastSeen ?? Date.now())
        if (!requestMap.has(normalizedUrl)) {
            let host = entry.host || ''
            if (!host) {
                try {
                    host = new URL(displayUrl || normalizedUrl).host || ''
                } catch (_) { }
            }
            requestMap.set(normalizedUrl, {
                key,
                method,
                displayUrl: displayUrl || normalizedUrl,
                host,
                status: entry.status ?? null,
                type: entry.type || 'http',
                url: normalizedUrl,
                lastSeen: Number.isNaN(lastSeenTs) ? Date.now() : lastSeenTs,
                _normalizedUrl: normalizedUrl,
                _uiKey: entry.key || key
            })
        } else {
            const existing = requestMap.get(normalizedUrl)
            if (!Number.isNaN(lastSeenTs) && lastSeenTs > (existing.lastSeen || 0)) {
                existing.lastSeen = lastSeenTs
            }
            if (entry.status && !existing.status) {
                existing.status = entry.status
            }
        }
    }

    const scanRequests = Array.isArray(source?.requests) ? source.requests : []
    scanRequests.forEach(addRequestEntry)

    const dataset = extractIastDataset(source)
    dataset.forEach(item => {
        if (!item) return
        const primaryUrl = extractIastPrimaryUrl(item)
        const evidenceEntry = extractPrimaryIastEvidence(item) || {}
        const candidateUrls = []
        const addCandidate = (value) => {
            if (!value) return
            const str = String(value).trim()
            if (!str) return
            candidateUrls.push(str)
        }
        if (primaryUrl) addCandidate(primaryUrl)
        if (Array.isArray(evidenceEntry?.affectedUrls)) {
            evidenceEntry.affectedUrls.forEach(addCandidate)
        }
        if (Array.isArray(item?.affectedUrls)) {
            item.affectedUrls.filter(Boolean).forEach(addCandidate)
        }
        addCandidate(evidenceEntry?.context?.url)
        addCandidate(evidenceEntry?.context?.location)
        if (!candidateUrls.length) return
        const normalizedUrl = canonicalizeIastUrl(primaryUrl || candidateUrls[0])
        if (!normalizedUrl) return
        const method = extractIastMethod(item)
        const lastSeenTs = Date.parse(item?.updatedAt || item?.createdAt || Date.now())
        if (!requestMap.has(normalizedUrl)) {
            let host = ''
            try {
                const parsed = new URL(normalizedUrl)
                host = parsed.host || ''
            } catch (_) {
                try {
                    const parsedRaw = new URL(primaryUrl || candidateUrls[0])
                    host = parsedRaw.host || ''
                } catch (_) { }
            }
            requestMap.set(normalizedUrl, {
                key: `${method} ${normalizedUrl}`,
                method,
                displayUrl: primaryUrl || candidateUrls[0] || normalizedUrl,
                host,
                status: null,
                type: 'finding',
                url: normalizedUrl,
                lastSeen: Number.isNaN(lastSeenTs) ? Date.now() : lastSeenTs,
                _normalizedUrl: normalizedUrl,
                _uiKey: `${method} ${normalizedUrl}`
            })
        } else {
            const existing = requestMap.get(normalizedUrl)
            if (!Number.isNaN(lastSeenTs) && lastSeenTs > (existing.lastSeen || 0)) {
                existing.lastSeen = lastSeenTs
            }
        }
    })
    return Array.from(requestMap.values()).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
}

function bindRequestList(requests) {
    const $container = $('#request_info')
    $container.html("")
    if (!requests.length) {
        //$container.append(`<div class="item"><div class="content"><div class="description">No requests captured yet.</div></div></div>`)
        return
    }
    const html = requests.map(req => bindRequest(req)).join('')
    $container.html(html)
}

function buildIastRequestIndex(requests) {
    const index = new Map()
    requests.forEach(req => {
        if (!req?._normalizedUrl) return
        if (!index.has(req._normalizedUrl)) {
            index.set(req._normalizedUrl, [])
        }
        index.get(req._normalizedUrl).push(req)
    })
    return index
}

function mapFindingToRequestKey(finding, requestIndex) {
    if (!finding || !(requestIndex instanceof Map)) return null
    const evidenceEntry = extractPrimaryIastEvidence(finding) || {}
    const candidateUrls = []
    const addCandidate = (value) => {
        if (!value) return
        const str = String(value).trim()
        if (!str) return
        candidateUrls.push(str)
    }
    addCandidate(finding?.location?.url)
    if (Array.isArray(evidenceEntry?.affectedUrls)) {
        evidenceEntry.affectedUrls.forEach(addCandidate)
    }
    if (Array.isArray(finding?.affectedUrls)) {
        finding.affectedUrls.forEach(addCandidate)
    }
    addCandidate(evidenceEntry?.context?.url)
    addCandidate(evidenceEntry?.context?.location)
    const primaryUrl = candidateUrls.find(Boolean)
    const url = canonicalizeIastUrl(primaryUrl)
    if (!url) return null
    const matches = requestIndex.get(url)
    if (!matches || !matches.length) return null
    return matches[0]._uiKey || matches[0].key || null
}

function canonicalizeIastUrl(url) {
    if (!url) return ''
    try {
        const parsed = new URL(url)
        let pathname = parsed.pathname || '/'
        pathname = pathname.replace(/\/{2,}/g, '/')
        if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1)
        parsed.pathname = pathname
        return `${parsed.origin}${parsed.pathname}${parsed.search || ''}${parsed.hash || ''}`
    } catch (err) {
        try {
            const normalized = new URL(url, window.location.href)
            let pathname = normalized.pathname || '/'
            pathname = pathname.replace(/\/{2,}/g, '/')
            if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1)
            normalized.pathname = pathname
            return `${normalized.origin}${normalized.pathname}${normalized.search || ''}${normalized.hash || ''}`
        } catch (_) {
            return ''
        }
    }
}

function canonicalizeRequestKey(rawKey) {
    return rawKey ? String(rawKey) : ''
}

function escAttrValue(value) {
    if (value === null || value === undefined) return ""
    if (window.CSS && typeof CSS.escape === "function") return CSS.escape(String(value))
    return String(value)
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"')
        .replace(/[\n\r\t\f\v]/g, " ")
}

function getIastRequestFilterStyleTag() {
    let style = document.getElementById("ptkIastRequestFilterStyle")
    if (!style) {
        style = document.createElement("style")
        style.id = "ptkIastRequestFilterStyle"
        document.head.appendChild(style)
    }
    return style
}

function updateIastRequestFilterStyle(requestKey) {
    const style = getIastRequestFilterStyleTag()
    if (!requestKey) {
        style.textContent = ""
        return
    }
    const escaped = escAttrValue(requestKey)
    // Keep match rule non-important so scope filters can still hide.
    style.textContent = `#attacks_info[data-request-key="${escaped}"] .iast_attack_card[data-request-key="${escaped}"] { display:block; }`
}

function toggleRequestFilter(rawKey) {
    const key = canonicalizeRequestKey(rawKey)
    if (!key) {
        clearRequestFilter()
        return
    }
    if (iastFilterState.requestKey === key) {
        clearRequestFilter()
        return
    }
    iastFilterState.requestKey = key
    iastRequestFilterDirty = true
    updateRequestFilterActiveState()
    applyIastFilters()
}

function clearRequestFilter() {
    iastFilterState.requestKey = null
    iastRequestFilterDirty = true
    updateRequestFilterActiveState()
    applyIastFilters()
}

function updateRequestFilterActiveState() {
    const key = iastFilterState.requestKey
    const $toggles = $('.request_filter_toggle')
    if (!$toggles.length) {
        iastFilterState.requestKey = null
        return
    }
    let found = false
    $toggles.each(function () {
        const matches = key && $(this).attr('data-request-key') === key
        $(this).toggleClass('active', !!matches)
        $(this).find('.filter.icon').toggleClass('primary', !!matches)
        if (matches) found = true
    })
    if (key && !found) {
        iastFilterState.requestKey = null
        iastRequestFilterDirty = true
        applyIastFilters()
    }
}

function applyIastFilters() {
    const requestKey = iastFilterState.requestKey
    const scope = iastFilterState.scope
    const $container = $("#attacks_info")
    if (requestKey) {
        $container.attr("data-request-key", requestKey)
    } else {
        $container.removeAttr("data-request-key")
    }
    updateIastRequestFilterStyle(requestKey)
    $container.attr("data-scope", scope)
    renderIastStatsFromCounters()
}

function updateIastScopeUI() {
    const scope = iastFilterState.scope === 'vuln' ? 'vuln' : 'all'
    const showScopeActive = normalizeIastViewKey(iastFilterState.view, controller?.scanViewModel || controller?.scanResult?.scanResult || null) === "findings"
    $('#filter_all')
        .toggleClass('active', showScopeActive && scope === 'all')
        .toggleClass('primary', showScopeActive && scope === 'all')
    $('#filter_vuln')
        .toggleClass('active', showScopeActive && scope === 'vuln')
        .toggleClass('primary', showScopeActive && scope === 'vuln')
    $('#iast_scope_count_label').text(scope === 'vuln' ? 'Findings' : 'All items')
}

$(document).on('click', '.iast-attack-details', function (event) {
    event.preventDefault()
    const indexAttr = $(this).attr('data-index')
    const index = typeof indexAttr !== 'undefined' ? Number(indexAttr) : NaN
    if (Number.isNaN(index)) {
        return
    }
    const item = getIastAttackItem(index)
    if (!item) return
    rutils.bindAttackDetails_IAST(item)
})

function setIastScopeFilter(scope) {
    const normalized = scope === 'vuln' ? 'vuln' : 'all'
    const changed = iastFilterState.scope !== normalized
    iastFilterState.scope = normalized
    updateIastScopeUI()
    if (iastFilterState.view !== "findings") {
        setIastView("findings")
        return
    }
    if (changed) {
        applyIastFilters()
    }
}

function setIastView(view) {
    const scanResult = controller?.scanViewModel || controller?.scanResult?.scanResult || null
    const normalized = normalizeIastViewKey(view, scanResult)
    iastFilterState.view = normalized
    const showFindings = normalized === "findings"
    $("#iast_result_tabs .item").removeClass("active")
    if (!showFindings) {
        $(`#iast_result_tabs .item[data-view="${normalized}"]`).addClass("active")
    }
    updateIastScopeUI()
    $("#attacks_info").toggle(showFindings)
    $("#discovery_info").toggle(!showFindings)
    if (!showFindings) {
        ensureIastDiscoveryRendered()
        const $panels = $("#discovery_info .iast-discovery-panel")
        $panels.hide()
        $panels.filter(`[data-discovery-group="${normalized}"]`).show()
    }
    applyIastFilters()
}




////////////////////////////////////
/* Chrome runtime events handlers */
////////////////////////////////////
browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message?.channel === 'ptk_background_iast2popup') {
        if (message?.type === 'scan_update') {
            const info = {
                scanResult: message.scanResult || {},
                isScanRunning: !!message.isScanRunning,
                policyState: message.policyState || controller.policyState || {},
                rulepackSelection: message.rulepackSelection || null
            }
            changeView(info)
            if (hasRenderableIastData(info.scanResult)) {
                bindScanResult(info)
            } else {
                updateIastRulepackUi(info)
            }
        }
        if (message?.type === 'scan_delta') {
            applyIastScanDelta(message)
        }
    }
})
