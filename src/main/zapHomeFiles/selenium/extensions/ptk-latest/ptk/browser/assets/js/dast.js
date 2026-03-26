/* Author: Denis Podgurskii */
import { ptk_controller_dast } from "../../../controller/dast.js"
import { ptk_controller_macro } from "../../../controller/macro.js"
import { ptk_controller_rbuilder } from "../../../controller/rbuilder.js"
import { ptk_utils } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import { shouldShowScanAnalysisUI } from "../../../background/analysis/featureFlags.js"
import * as rutils from "../js/rutils.js"
import { normalizeScanResult } from "../js/scanResultViewModel.js"
import { downloadScanExportResult, readScanFileText } from "../js/scanCompression.js"
import {
    extractComparableResponseFromRun,
    renderSessionProfileListHtml,
    renderSessionProfileOptions,
    renderAuthzDiffResultHtml,
    renderAuthzDiffRunStatusHtml,
    renderObjectSwapSummaryHtml,
    renderEvidencePackageSummaryHtml,
    renderEvidencePackageListHtml,
    renderWorkflowOverlaySummaryHtml,
    renderWorkflowOverlayReplayStatusHtml,
    renderReportDraftPreview
} from "../js/dastBugBountyWorkspace.js"

const controller = new ptk_controller_dast()
const macro_controller = new ptk_controller_macro()
const request_controller = new ptk_controller_rbuilder()

const DAST_RENDER = {
    queue: [],
    timer: null,
    flushMs: 350,
    renderedRequestIds: new Set(),
    renderedAttackIds: new Set(),
    renderedReconKeys: new Set(),
    groupedReconObservations: new Map(),
    scanning: false,
    legacyBound: false,
    progressTimer: null,
    progressFlushMs: 20,
    progressName: '',
    progressDetails: null,
    progressStatus: '',
    progressMetrics: '',
    progressContext: '',
    lastActivityAt: 0,
    idleCheckTimer: null,
    idleSorted: false
}
const attackFilterState = {
    scope: 'all',
    requestId: null
}
let dastScopeTouchedByUser = false
const UNKNOWN_REQ = "__ptk_unknown__"
const DAST_COUNTERS = createEmptyCounters()
const DAST_REQUEST_COUNTERS = new Map()
let requestFilterDirty = false
const decoder = new ptk_decoder()
const DAST_SEVERITY_ORDER = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
}
const DAST_BUCKET_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'nonvuln']
const DAST_RESULT_VIEWS = new Set(['findings', 'analysis'])
const ANALYSIS_CANDIDATE_PAGE_SIZE = 10
let dastResultView = 'findings'
const ANALYSIS_CANDIDATE_INDEX = new Map()
const RELATED_FINDING_SUMMARY_INDEX = new Map()
const ANALYSIS_FILTER_STATE = {
    engine: 'all',
    type: 'all',
    confidence: 'all',
    route: '',
    paramLocation: 'all',
    diff: 'all',
    candidateLimit: ANALYSIS_CANDIDATE_PAGE_SIZE
}
const ANALYSIS_PLAYWRIGHT_RUNS = new Map()
const ANALYSIS_PLAYWRIGHT_POLLERS = new Map()
const ANALYSIS_ACTION_READINESS = new Map()
const ANALYSIS_ACTION_READINESS_PENDING = new Set()
const PLAYWRIGHT_RUN_TERMINAL = new Set(['completed', 'failed', 'canceled', 'timed_out'])
const PLAYWRIGHT_FEATURES_VISIBLE = false
const AUTHZ_DIFF_FEATURES_VISIBLE = false
const PORTAL_ACTIONS_VISIBLE = false
const PLAYWRIGHT_PAUSED_REASON = 'Playwright-backed automation is temporarily hidden while PTK stabilizes the next integration path.'
const ANALYSIS_PLAYWRIGHT_MODAL_STATE = {
    candidateId: '',
    readiness: null
}
const ANALYSIS_SESSION_PROFILES_STATE = {
    host: '',
    profiles: [],
    requestSeq: 0
}
const ANALYSIS_AUTHZ_DIFF_MODAL_STATE = {
    candidateId: '',
    host: '',
    snapshot: null,
    diff: null,
    runId: '',
    run: null,
    objectSwap: null,
    evidencePackage: null,
    evidencePackages: [],
    reportDraft: null,
    workflowSummary: null,
    workflowReplay: null,
    pollTimer: null
}
const ANALYSIS_SUPPRESSION_STATE = {
    host: null,
    keys: new Set(),
    requestSeq: 0
}
const DAST_SCAN_MACRO_STATE = {
    requested: false,
    started: false
}
let dastDefaultModulesRequest = null
let latestDastRawScan = null
let scanAnalysisUiEnabled = true
let analysisPanelsDirty = true

function escapeDastPolicyHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
}

const DAST_BUILTIN_POLICY_OPTIONS = [
    { value: 'RECON', label: 'Recon (system)' },
    { value: 'ACTIVE', label: 'Active (system)' }
]

function buildDastPortalOptionValue(entry = {}) {
    const id = String(entry?.id || '').trim()
    return id ? `policy:${id}` : ''
}

function parseDastPortalOptionValue(value) {
    const rawValue = String(value || '').trim()
    if (!rawValue.startsWith('policy:')) return null
    const policyId = rawValue.slice('policy:'.length).trim()
    return policyId || null
}

function getCurrentDastBuiltinPolicyValue(result = {}, fallbackValue = null) {
    const settingsValue = String(
        result?.settings?.dastScanPolicy
        || fallbackValue
        || controller?.settings?.dastScanPolicy
        || 'ACTIVE'
    ).trim().toUpperCase()
    return DAST_BUILTIN_POLICY_OPTIONS.some((entry) => entry.value === settingsValue)
        ? settingsValue
        : 'ACTIVE'
}

function setDastPortalPolicyLoading(loading) {
    const isLoading = !!loading
    $('#load_pro_policies_button')
        .toggleClass('loading', isLoading)
        .toggleClass('disabled', isLoading)
    $('#dast-scan-policy').prop('disabled', isLoading)
}

function openExtensionSettingsWindow() {
    return browser.windows.create({
        type: 'popup',
        url: browser.runtime.getURL('/ptk/browser/settings.html'),
        width: 1100,
        height: 820
    }).catch(() => null)
}

function getAnalysisSuppressionKeys() {
    return Array.from(ANALYSIS_SUPPRESSION_STATE.keys)
}

function resetAnalysisSuppressionState() {
    ANALYSIS_SUPPRESSION_STATE.host = null
    ANALYSIS_SUPPRESSION_STATE.keys = new Set()
    ANALYSIS_SUPPRESSION_STATE.requestSeq += 1
}

async function refreshAnalysisSuppressions(host = null) {
    const normalizedHost = String(host || '').trim()
    ANALYSIS_SUPPRESSION_STATE.host = normalizedHost || null
    if (!normalizedHost) {
        ANALYSIS_SUPPRESSION_STATE.keys = new Set()
        rerenderAnalysisPanels()
        return
    }
    const requestSeq = ANALYSIS_SUPPRESSION_STATE.requestSeq + 1
    ANALYSIS_SUPPRESSION_STATE.requestSeq = requestSeq
    try {
        const result = await controller.getAnalysisSuppressions(normalizedHost)
        if (ANALYSIS_SUPPRESSION_STATE.requestSeq !== requestSeq) return
        const suppressions = Array.isArray(result?.suppressions) ? result.suppressions : []
        ANALYSIS_SUPPRESSION_STATE.keys = new Set(suppressions.map((entry) => String(entry || '').trim()).filter(Boolean))
        rerenderAnalysisPanels()
    } catch (_) {
        if (ANALYSIS_SUPPRESSION_STATE.requestSeq !== requestSeq) return
        ANALYSIS_SUPPRESSION_STATE.keys = new Set()
    }
}

async function toggleReconRouteSuppression(routeKey = '', suppressed = false) {
    const host = String(ANALYSIS_SUPPRESSION_STATE.host || latestDastRawScan?.host || controller?.scanResult?.scanResult?.host || '').trim()
    const normalizedRouteKey = String(routeKey || '').trim()
    if (!host || !normalizedRouteKey) {
        showResultDialog('Recon', 'Route suppression is unavailable for this scan.')
        return
    }
    const suppressKey = `route:${normalizedRouteKey}`
    try {
        const result = await controller.toggleAnalysisSuppression({
            host,
            suppressKey,
            suppressed
        })
        const suppressions = Array.isArray(result?.suppressions) ? result.suppressions : []
        ANALYSIS_SUPPRESSION_STATE.host = host
        ANALYSIS_SUPPRESSION_STATE.keys = new Set(suppressions.map((entry) => String(entry || '').trim()).filter(Boolean))
        rerenderAnalysisPanels()
    } catch (err) {
        showResultDialog('Recon', err?.message || 'Route suppression could not be updated.')
    }
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

function syncDastPolicyDropdown(value) {
    const $select = $('#dast-scan-policy')
    if (!$select.length) return
    const normalized = value ? String(value) : ''
    $select.val(normalized)
    if (typeof $select.dropdown === 'function') {
        $select.dropdown('refresh')
        $select.dropdown('set selected', normalized)
    }
}

function buildDastPortalPolicyEntries(policyState = {}) {
    const metadata = Array.isArray(policyState?.metadata) ? policyState.metadata.slice() : []
    const selected = policyState?.selectedPolicy && typeof policyState.selectedPolicy === 'object'
        ? policyState.selectedPolicy
        : null
    if (selected?.id && !metadata.some((entry) => String(entry?.id || '') === String(selected.id))) {
        metadata.unshift(selected)
    }
    return metadata.filter((entry) => entry && (entry.id || entry.name))
}

function defaultDastPolicyLabel(policyState = {}) {
    const hasLoadedOptions = (Array.isArray(policyState?.metadata) && policyState.metadata.length > 0)
        || !!policyState?.selectedPolicy?.id
    if (hasLoadedOptions) return 'Select policy'
    return 'Active (system)'
}

function applyDastPortalPolicyState(result = {}) {
    const policyState = (result?.policyState && typeof result.policyState === 'object')
        ? result.policyState
        : (controller.policyState || {})
    controller.policyState = policyState
    const previousSelectedValue = String($('#dast-scan-policy').val() || '').trim()
    const entries = buildDastPortalPolicyEntries(policyState)
    const hasPortalEntries = entries.length > 0
    const hasSelectedPortalPolicy = !!policyState?.selectedPolicy?.id
    const options = []
    if (hasPortalEntries || hasSelectedPortalPolicy) {
        options.push(`<option value="">${escapeDastPolicyHtml(defaultDastPolicyLabel(policyState))}</option>`)
    }
    DAST_BUILTIN_POLICY_OPTIONS.forEach((entry) => {
        options.push(`<option value="${escapeDastPolicyHtml(entry.value)}">${escapeDastPolicyHtml(entry.label)}</option>`)
    })
    entries.forEach((entry) => {
        if (!entry?.id) return
        const label = entry.label || entry.name || `Policy #${entry.id}`
        options.push(`<option value="${escapeDastPolicyHtml(buildDastPortalOptionValue(entry))}">${escapeDastPolicyHtml(label)}</option>`)
    })
    $('#dast-scan-policy').html(options.join(''))
    const selectedValue = policyState?.selectedPolicy?.id
        ? buildDastPortalOptionValue(policyState.selectedPolicy)
        : ((hasPortalEntries || hasSelectedPortalPolicy)
            ? previousSelectedValue
            : getCurrentDastBuiltinPolicyValue(result, previousSelectedValue))
    syncDastPolicyDropdown(selectedValue)
}

function countDastModuleAttacks(modules = []) {
    return (Array.isArray(modules) ? modules : []).reduce((sum, mod) => {
        const attacks = mod?.attacks
        const attackCount = Array.isArray(attacks)
            ? attacks.length
            : (attacks && typeof attacks === 'object' ? Object.keys(attacks).length : 0)
        return sum + attackCount
    }, 0)
}

function countDastModuleTypes(modules = []) {
    return (Array.isArray(modules) ? modules : []).reduce((acc, mod) => {
        const type = String(mod?.type || '').trim().toLowerCase()
        if (type === 'passive') {
            acc.passive += 1
        } else if (type) {
            acc.active += 1
        }
        return acc
    }, { passive: 0, active: 0 })
}

function buildDastProgressContext(result = {}) {
    const selection = (result?.rulepackSelection && typeof result.rulepackSelection === 'object')
        ? result.rulepackSelection
        : (controller?.rulepackSelection && typeof controller.rulepackSelection === 'object' ? controller.rulepackSelection : null)
    const modules = Array.isArray(result?.default_modules)
        ? result.default_modules
        : (Array.isArray(controller?.default_modules) ? controller.default_modules : [])
    const sourceLabel = selection?.source === 'portal' ? 'Portal policy' : 'Built-in rulepack'
    let policyLabel = selection?.label || null
    if (selection?.source === 'portal') {
        if (selection?.policyName && selection?.policyId) {
            policyLabel = `${selection.policyName} (#${selection.policyId})`
        } else if (selection?.policyName) {
            policyLabel = selection.policyName
        } else if (selection?.policyId) {
            policyLabel = `#${selection.policyId}`
        }
    }
    const parts = [`Source: ${sourceLabel}`]
    if (policyLabel) {
        parts.push(`Policy: ${policyLabel}`)
    }
    if (Array.isArray(modules) && modules.length) {
        parts.push(`Modules: ${modules.length}`)
        parts.push(`Attacks: ${countDastModuleAttacks(modules)}`)
        const typeCounts = countDastModuleTypes(modules)
        parts.push(`Passive: ${typeCounts.passive}`)
        parts.push(`Active: ${typeCounts.active}`)
    }
    return parts.join(' • ')
}

function updateDastProgressContext(result = {}) {
    if (Array.isArray(result?.default_modules)) {
        controller.default_modules = result.default_modules
    }
    if (Array.isArray(result?.cve_modules)) {
        controller.cve_modules = result.cve_modules
    }
    if (result?.rulepackSelection && typeof result.rulepackSelection === 'object') {
        controller.rulepackSelection = result.rulepackSelection
    }
    DAST_RENDER.progressContext = buildDastProgressContext(result)
    $('#progress_rulepack_meta').text(DAST_RENDER.progressContext || '')
}

function resolveDastHelpPopupPosition($icon) {
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

function bindDastHelpPopups() {
    $('#dast_form .question.circle.icon').each(function () {
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
            position: resolveDastHelpPopupPosition($icon),
            delay: {
                show: 300,
                hide: 800
            }
        })
    })
}

function maybeBindDastPortalPreview(result = {}) {
    const currentScan = result?.scanResult || controller?.scanResult?.scanResult || null
    if (result?.isScanRunning || hasRenderableScanData(currentScan)) return
    if (Array.isArray(result?.default_modules) && result.default_modules.length) {
        bindModules(result)
        showWelcomeForm()
    }
}

async function ensureDastDefaultModulesLoaded({ force = false } = {}) {
    if (!force && Array.isArray(controller?.default_modules) && controller.default_modules.length) {
        bindModules({
            default_modules: controller.default_modules,
            cve_modules: Array.isArray(controller?.cve_modules) ? controller.cve_modules : []
        })
        return {
            default_modules: controller.default_modules,
            cve_modules: Array.isArray(controller?.cve_modules) ? controller.cve_modules : []
        }
    }
    if (dastDefaultModulesRequest && !force) {
        return dastDefaultModulesRequest
    }
    dastDefaultModulesRequest = controller.getDefaultModules()
        .then((result) => {
            if (result?.policyState) applyDastPortalPolicyState(result)
            updateDastProgressContext(result || {})
            bindModules(result || {})
            return result
        })
        .finally(() => {
            dastDefaultModulesRequest = null
        })
    return dastDefaultModulesRequest
}

function resetAnalysisUiState() {
    ANALYSIS_CANDIDATE_INDEX.clear()
    ANALYSIS_FILTER_STATE.engine = 'all'
    ANALYSIS_FILTER_STATE.type = 'all'
    ANALYSIS_FILTER_STATE.confidence = 'all'
    ANALYSIS_FILTER_STATE.route = ''
    ANALYSIS_FILTER_STATE.paramLocation = 'all'
    ANALYSIS_FILTER_STATE.candidateLimit = ANALYSIS_CANDIDATE_PAGE_SIZE
    ANALYSIS_PLAYWRIGHT_POLLERS.forEach((timer) => clearInterval(timer))
    ANALYSIS_PLAYWRIGHT_POLLERS.clear()
    ANALYSIS_PLAYWRIGHT_RUNS.clear()
    ANALYSIS_ACTION_READINESS.clear()
    ANALYSIS_ACTION_READINESS_PENDING.clear()
    ANALYSIS_PLAYWRIGHT_MODAL_STATE.candidateId = ''
    ANALYSIS_PLAYWRIGHT_MODAL_STATE.readiness = null
    ANALYSIS_SESSION_PROFILES_STATE.host = ''
    ANALYSIS_SESSION_PROFILES_STATE.profiles = []
    ANALYSIS_SESSION_PROFILES_STATE.requestSeq += 1
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId = ''
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.host = ''
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.snapshot = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.diff = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.runId = ''
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.run = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackage = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackages = []
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.reportDraft = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay = null
    if (ANALYSIS_AUTHZ_DIFF_MODAL_STATE.pollTimer) {
        clearInterval(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.pollTimer)
    }
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.pollTimer = null
    latestDastRawScan = null
}

function resolveCandidateAnalysisHost(candidate = null) {
    const routeKey = String(candidate?.routeKey || '').trim()
    if (routeKey) {
        const parts = routeKey.split('|')
        const host = String(parts[0] || '').trim()
        if (host) return host
    }
    return normalizeHostKey(latestDastRawScan?.host || '')
}

async function loadSessionProfilesForHost(host, { silent = false } = {}) {
    const normalizedHost = normalizeHostKey(host || '')
    ANALYSIS_SESSION_PROFILES_STATE.host = normalizedHost
    if (!normalizedHost) {
        ANALYSIS_SESSION_PROFILES_STATE.profiles = []
        return []
    }
    const requestSeq = ANALYSIS_SESSION_PROFILES_STATE.requestSeq + 1
    ANALYSIS_SESSION_PROFILES_STATE.requestSeq = requestSeq
    try {
        const response = await controller.listSessionProfiles(normalizedHost)
        if (ANALYSIS_SESSION_PROFILES_STATE.requestSeq !== requestSeq) {
            return ANALYSIS_SESSION_PROFILES_STATE.profiles
        }
        if (!response?.success) {
            throw new Error(response?.error || 'Session profiles could not be loaded')
        }
        ANALYSIS_SESSION_PROFILES_STATE.host = normalizeHostKey(response?.host || normalizedHost)
        ANALYSIS_SESSION_PROFILES_STATE.profiles = Array.isArray(response?.profiles) ? response.profiles : []
        return ANALYSIS_SESSION_PROFILES_STATE.profiles
    } catch (err) {
        if (!silent) {
            showResultDialog('Session Profiles', err?.message || 'Session profiles could not be loaded')
        }
        ANALYSIS_SESSION_PROFILES_STATE.profiles = []
        return []
    }
}

function getSessionProfilesForHost(host = null) {
    const normalizedHost = normalizeHostKey(host || '')
    if (normalizedHost && normalizedHost === normalizeHostKey(ANALYSIS_SESSION_PROFILES_STATE.host || '')) {
        return Array.isArray(ANALYSIS_SESSION_PROFILES_STATE.profiles)
            ? ANALYSIS_SESSION_PROFILES_STATE.profiles.slice()
            : []
    }
    return []
}

function renderPlaywrightSessionProfileOptions(selectedId = '') {
    const profiles = getSessionProfilesForHost(ANALYSIS_SESSION_PROFILES_STATE.host || '')
    const html = renderSessionProfileOptions(profiles, {
        selectedId,
        placeholder: 'Select session profile'
    })
    $('#analysis_playwright_session_profile').html(html)
    if (typeof $('#analysis_playwright_session_profile').dropdown === 'function') {
        $('#analysis_playwright_session_profile').dropdown('refresh')
    }
}

function renderAuthzDiffSessionSelectors({
    baselineSessionProfileId = '',
    comparisonSessionProfileId = ''
} = {}) {
    const profiles = getSessionProfilesForHost(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.host || '')
    $('#analysis_authz_diff_baseline_session').html(renderSessionProfileOptions(profiles, {
        selectedId: baselineSessionProfileId,
        placeholder: 'Select baseline session'
    }))
    $('#analysis_authz_diff_comparison_session').html(renderSessionProfileOptions(profiles, {
        selectedId: comparisonSessionProfileId,
        placeholder: 'Select comparison session'
    }))
    if (typeof $('#analysis_authz_diff_baseline_session').dropdown === 'function') {
        $('#analysis_authz_diff_baseline_session').dropdown('refresh')
    }
    if (typeof $('#analysis_authz_diff_comparison_session').dropdown === 'function') {
        $('#analysis_authz_diff_comparison_session').dropdown('refresh')
    }
}

function stopAuthzDiffRunPolling() {
    const timer = ANALYSIS_AUTHZ_DIFF_MODAL_STATE.pollTimer
    if (timer) {
        clearInterval(timer)
    }
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.pollTimer = null
}

function hasWorkflowRecording(summary = null) {
    return !!(summary && typeof summary === 'object' && summary.recordingPresent === true && Number(summary?.stepCount || 0) > 0)
}

function hasAuthzDiffOutput() {
    return !!(
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.diff
        || ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackage
        || ANALYSIS_AUTHZ_DIFF_MODAL_STATE.reportDraft
        || (ANALYSIS_AUTHZ_DIFF_MODAL_STATE.run && String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.run?.status || '').trim())
    )
}

function renderAuthzDiffRunUi() {
    $('#analysis_authz_diff_run_status').html(
        PLAYWRIGHT_FEATURES_VISIBLE
            ? renderAuthzDiffRunStatusHtml(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.run)
            : `
                <div class="ui tiny info message">
                    <div class="header">Automation hidden for now</div>
                    <p>${escapeHtml(PLAYWRIGHT_PAUSED_REASON)} Manual JSON comparison, object swap, evidence, and report draft flows remain available.</p>
                </div>
            `
    )
    $('#analysis_authz_diff_result').html(renderAuthzDiffResultHtml(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.diff))
    $('#analysis_authz_object_swap_summary').html(renderObjectSwapSummaryHtml(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap))
    $('#analysis_authz_evidence_summary').html(renderEvidencePackageSummaryHtml(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackage))
    $('#analysis_authz_evidence_list').html(renderEvidencePackageListHtml({
        evidencePackages: ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackages,
        activeEvidencePackageId: ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackage?.id || ''
    }))
    $('#analysis_authz_report_draft').html(renderReportDraftPreview(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.reportDraft))
    $('#analysis_authz_workflow_summary').html(
        PLAYWRIGHT_FEATURES_VISIBLE
            ? renderWorkflowOverlaySummaryHtml(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary, {
                showRecordAction: true
            })
            : ''
    )
    $('#analysis_authz_workflow_replay_status').html(
        PLAYWRIGHT_FEATURES_VISIBLE && ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay
            ? renderWorkflowOverlayReplayStatusHtml(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay)
            : ''
    )
    const workflowAvailable = hasWorkflowRecording(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary)
        || hasWorkflowRecording(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay?.workflowSummary || null)
        || hasWorkflowRecording(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackage?.workflowSummary || null)
    const hasEvidenceEntries = Array.isArray(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackages) && ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackages.length > 0
    $('#analysis_authz_workflow_controls').toggle(PLAYWRIGHT_FEATURES_VISIBLE && workflowAvailable)
    $('#analysis_authz_evidence_section').toggle(hasAuthzDiffOutput() || hasEvidenceEntries)
    $('#analysis_authz_evidence_actions').toggle(hasAuthzDiffOutput())
}

function triggerTextDownload(content, fileName, contentType = 'text/plain') {
    const blob = new Blob([String(content ?? '')], { type: contentType || 'text/plain' })
    const link = document.createElement('a')
    link.download = String(fileName || 'download.txt')
    link.href = window.URL.createObjectURL(blob)
    link.click()
}

async function refreshEvidencePackageListForCurrentCandidate({ silent = false } = {}) {
    const candidateId = String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId || '').trim()
    if (!candidateId) {
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackages = []
        renderAuthzDiffRunUi()
        return []
    }
    try {
        const response = await controller.listEvidencePackages({ candidateId })
        if (!response?.success) {
            throw new Error(response?.error || 'Evidence packages could not be loaded.')
        }
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackages = Array.isArray(response?.evidencePackages)
            ? response.evidencePackages
            : []
        renderAuthzDiffRunUi()
        return ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackages
    } catch (err) {
        if (!silent) {
            showResultDialog('Evidence Packages', err?.message || 'Evidence packages could not be loaded.')
        }
        return []
    }
}

function openEvidencePackageReportWindow(evidencePackageId) {
    const id = String(evidencePackageId || '').trim()
    if (!id) {
        showResultDialog('Evidence Package', 'Evidence package is not available anymore.')
        return
    }
    browser.windows.create({
        type: 'popup',
        url: browser.runtime.getURL(`/ptk/browser/report.html?bugbounty_report=1&evidence_package_id=${encodeURIComponent(id)}`)
    })
}

function openMacroRecorderWindow() {
    return browser.windows.create({
        type: 'popup',
        url: browser.runtime.getURL('/ptk/browser/macro.html'),
        width: 1100,
        height: 820
    }).catch(() => null)
}

async function exportEvidencePackageFromUi(evidencePackageId, format = 'json') {
    const id = String(evidencePackageId || '').trim()
    if (!id) {
        throw new Error('Evidence package is not available anymore.')
    }
    const response = await controller.exportEvidencePackage({
        evidencePackageId: id,
        format
    })
    if (!response?.success || !response?.content) {
        throw new Error(response?.error || 'Evidence package could not be exported.')
    }
    triggerTextDownload(
        response.content,
        response.fileName || `evidence-package.${String(format || 'json').toLowerCase() === 'markdown' ? 'md' : 'json'}`,
        response.contentType || (String(format || '').toLowerCase() === 'markdown' ? 'text/markdown' : 'application/json')
    )
}

function applyAuthzDiffRun(run = null) {
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.run = run && typeof run === 'object' ? run : null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.runId = String(run?.runId || '').trim()
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.diff = run?.diff || null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = run?.objectSwap || ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap || null
    if (ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap?.targetParam) {
        $('#analysis_authz_object_swap_enabled').prop('checked', true)
        $('#analysis_authz_object_swap_target').val(String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap.targetParam || ''))
        $('#analysis_authz_object_swap_location').val(String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap.location || 'param'))
        $('#analysis_authz_object_swap_value').val(String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap.swappedValue || ''))
    }
    renderAuthzDiffRunUi()
    if (run?.baselineResponse) {
        $('#analysis_authz_diff_baseline_response').val(JSON.stringify(run.baselineResponse, null, 2))
    }
    if (run?.comparisonResponse) {
        $('#analysis_authz_diff_comparison_response').val(JSON.stringify(run.comparisonResponse, null, 2))
    }
}

function renderSessionProfilesModalContent(feedback = null) {
    const host = ANALYSIS_SESSION_PROFILES_STATE.host || ''
    const profiles = getSessionProfilesForHost(host)
    $('#analysis_session_profiles_host').html(`<b>Host:</b> ${escapeHtml(host || 'n/a')}`)
    $('#analysis_session_profiles_feedback')
        .toggle(!!feedback)
        .removeClass('red green yellow info')
        .addClass(feedback?.color || 'info')
        .html(feedback?.message ? escapeHtml(feedback.message) : '')
    $('#analysis_session_profiles_list').html(renderSessionProfileListHtml({ host, profiles }))
}

function formatDastSeverityLabel(value) {
    if (!value) return 'info'
    return String(value).toLowerCase()
}

function formatDastSeverityDisplay(value) {
    const normalized = formatDastSeverityLabel(value)
    return normalized.charAt(0).toUpperCase() + normalized.slice(1)
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
}

function escapeAttr(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
}

function formatAnalysisComputedAt(value) {
    const text = String(value || '').trim()
    if (!text) return 'n/a'
    const date = new Date(text)
    if (Number.isNaN(date.getTime())) return text
    return date.toLocaleString()
}

function formatAnalysisStatusMode(value) {
    const normalized = String(value || '').trim().toLowerCase()
    if (normalized === 'finalized') return 'Finalized scan snapshot'
    if (normalized === 'live') return 'Live scan state'
    if (normalized === 'partial') return 'Partial scan state'
    return 'Unknown'
}

function buildAnalysisStatusHtml(analysis = {}) {
    const coverage = analysis?.coverage && typeof analysis.coverage === 'object' ? analysis.coverage : {}
    const engines = Array.isArray(coverage.enginesPresent) ? coverage.enginesPresent : []
    const coverageConfidence = String(coverage?.confidence || '').trim().toLowerCase()
    const coverageConfidenceScore = Number(coverage?.confidenceScore || 0)
    return `
        <div class="ui message">
            <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:12px;">
                <div style="min-width:260px;">
                    <div><b>Confidence:</b> ${escapeHtml(coverageConfidence || 'low')}${coverageConfidenceScore ? ` (${coverageConfidenceScore})` : ''}</div>
                    <div><b>Engines present in this session:</b> ${escapeHtml(engines.join(', ') || 'DAST')}</div>
                </div>
                <div style="margin-left:auto;position: absolute;top: 0;right: 0;">
                    <button type="button" id="analysis_recompute" class="ui mini button">
                        Recompute
                    </button>
                </div>
            </div>
        </div>
    `
}

function buildEmptyAnalysisStateHtml() {
    return `
        <div class="ui info message">
            <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <div class="header">No analysis yet</div>
                    <p>Analysis appears when the scan has enough finalized evidence.</p>
                </div>
                <div style="margin-left:auto;">
                    <button type="button" id="analysis_recompute" class="ui tiny button">
                        Recompute analysis
                    </button>
                </div>
            </div>
        </div>
    `
}

function formatAnalysisConfidence(value) {
    const normalized = String(value || 'low').toLowerCase()
    if (normalized === 'high') return 'green'
    if (normalized === 'medium') return 'yellow'
    return 'grey'
}

function formatAnalysisConfidenceVisual(value) {
    const normalized = String(value || 'low').toLowerCase()
    if (normalized === 'high') {
        return {
            icon: 'exclamation triangle',
            colorClass: 'ptk-sev-high',
            label: 'High'
        }
    }
    if (normalized === 'medium') {
        return {
            icon: 'exclamation triangle',
            colorClass: 'ptk-sev-medium',
            label: 'Medium'
        }
    }
    if (normalized === 'low') {
        return {
            icon: 'exclamation triangle',
            colorClass: 'ptk-sev-low',
            label: 'Low'
        }
    }
    return {
        icon: 'question circle outline',
        colorClass: '',
        label: normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : 'Unknown'
    }
}

function buildAnalysisConfidenceBadge(confidence) {
    const visual = formatAnalysisConfidenceVisual(confidence)
    const colorClass = visual.colorClass ? ` ${visual.colorClass}` : ''
    const title = escapeAttr(`Confidence: ${visual.label}`)
    return `<span class="ui tiny basic label" title="${title}" aria-label="${title}" style="white-space:nowrap;"><i class="${visual.icon}${colorClass} icon" style="margin-right:0;"></i></span>`
}

function humanizeAnalysisSignalCode(code) {
    return String(code || 'SIGNAL')
        .toLowerCase()
        .split('_')
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(' ')
}

function humanizeAnalysisRuleCode(code) {
    const normalized = String(code || '').trim().toUpperCase()
    const labels = {
        R1_5XX_CLUSTER: '5xx cluster',
        R2_ERROR_FINGERPRINT: 'Error fingerprint',
        R3_AUTH_SESSION_DRIFT: 'Auth/session drift',
        R4_PARAM_HOTSPOT: 'Parameter hotspot',
        R5_LATENCY_OUTLIERS: 'Latency outlier',
        R7_CRITICAL_GAPS: 'Critical gap',
        R8_INCONSISTENT_RESOURCE_BEHAVIOR: 'Resource drift',
        R9_PASSIVE_FINDING_SEEDS: 'Passive finding seed',
        R10_TEMPLATE_RENDER_WORKFLOWS: 'Template render workflow',
        R11_SAST_CODE_ARTIFACTS: 'Code artifact',
        R12_IAST_RUNTIME_SIGNALS: 'IAST runtime signal',
        R13_CROSS_ENGINE_CORRELATION: 'Cross-engine correlation'
    }
    return labels[normalized] || normalized || 'Rule'
}

function humanizeAnalysisToken(value) {
    return String(value || '')
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
        .replace(/[._-]+/g, ' ')
        .split(/\s+/)
        .filter(Boolean)
        .map((part) => {
            const lower = part.toLowerCase()
            if (lower === 'xss') return 'XSS'
            if (lower === 'idor') return 'IDOR'
            if (lower === 'dom') return 'DOM'
            if (lower === 'csp') return 'CSP'
            if (lower === 'sast') return 'SAST'
            if (lower === 'iast') return 'IAST'
            if (lower === 'dast') return 'DAST'
            if (lower === 'api') return 'API'
            if (lower === 'xhr') return 'XHR'
            if (lower === 'http') return 'HTTP'
            if (lower === 'https') return 'HTTPS'
            if (lower === 'json') return 'JSON'
            if (lower === 'jwt') return 'JWT'
            if (lower === 'url') return 'URL'
            if (lower === 'uri') return 'URI'
            if (lower === 'html') return 'HTML'
            if (lower === 'svg') return 'SVG'
            if (lower === 'csrf') return 'CSRF'
            if (lower === 'cve') return 'CVE'
            return lower.charAt(0).toUpperCase() + lower.slice(1)
        })
        .join(' ')
}

function sanitizeEvidenceLabel(value, options = {}) {
    const {
        humanize = false,
        stripKeyPrefix = false,
        ignored = []
    } = options
    let raw = String(value || '').trim()
    if (!raw) return ''
    if (stripKeyPrefix && raw.includes(':')) {
        const parts = raw.split(':').map((part) => String(part || '').trim()).filter(Boolean)
        raw = String(parts[parts.length - 1] || '').trim()
    }
    const lower = raw.toLowerCase()
    const ignoreSet = new Set([
        '_',
        '<none>',
        'none',
        'unknown',
        'n/a',
        'na',
        ...ignored.map((entry) => String(entry || '').trim().toLowerCase()).filter(Boolean)
    ])
    if (ignoreSet.has(lower)) return ''
    return humanize ? humanizeAnalysisToken(raw) : raw
}

function humanizeRuntimeSinkLabel(value) {
    const raw = String(value || '').trim()
    if (!raw) return ''
    const normalized = raw.toLowerCase()
    const labels = {
        'http.xhr.setrequestheader': 'Outgoing request header',
        'storage.document.cookie': 'Document cookie access',
        'storage.localstorage.setitem': 'localStorage write',
        'storage.localstorage.getitem': 'localStorage read',
        'storage.sessionstorage.setitem': 'sessionStorage write',
        'storage.sessionstorage.getitem': 'sessionStorage read',
        'client.json.parse': 'Parsed JSON response',
        'dom.innerhtml': 'innerHTML sink',
        'dom.outerhtml': 'outerHTML sink',
        'nav.location.assign': 'Location navigation',
        'nav.location.replace': 'Location replace navigation',
        'nav.window.open': 'Window open navigation'
    }
    return labels[normalized] || humanizeAnalysisToken(raw)
}

function humanizeEvidenceFindingTitle({ ruleId = '', moduleId = '', engine = '' } = {}) {
    const normalizedRule = String(ruleId || '').trim().toLowerCase()
    const normalizedModule = String(moduleId || '').trim().toLowerCase()
    const normalizedEngine = String(engine || '').trim().toUpperCase()
    if (normalizedEngine === 'IAST' || normalizedModule.startsWith('iast_')) {
        const iastRuleLabels = {
            dom_innerhtml_xss: 'DOM XSS via Element.innerHTML',
            dom_outerhtml_xss: 'DOM XSS via Element.outerHTML',
            dom_document_write_xss: 'DOM XSS via document.write',
            dom_srcdoc_xss: 'DOM XSS via iframe.srcdoc',
            dom_parser_xss: 'DOM XSS via DOMParser',
            javascript_url_execution: 'JavaScript URL execution',
            open_redirect: 'Open redirect',
            dom_open_redirect: 'DOM open redirect'
        }
        if (iastRuleLabels[normalizedRule]) {
            return iastRuleLabels[normalizedRule]
        }
        const domXssMatch = normalizedRule.match(/^dom_(.+)_xss$/)
        if (domXssMatch) {
            const sinkToken = String(domXssMatch[1] || '').trim()
            const sinkLabels = {
                innerhtml: 'Element.innerHTML',
                outerhtml: 'Element.outerHTML',
                document_write: 'document.write',
                srcdoc: 'iframe.srcdoc',
                parser: 'DOMParser'
            }
            const sinkLabel = sinkLabels[sinkToken] || humanizeAnalysisToken(sinkToken)
            return sinkLabel ? `DOM XSS via ${sinkLabel}` : 'DOM XSS'
        }
    }
    return humanizeAnalysisToken(ruleId || moduleId || '') || 'Finding'
}

function parseRuntimeEventEvidenceId(idValue) {
    const empty = {
        routeLabel: '',
        paramLabel: '',
        sinkLabel: '',
        reasonLabel: '',
        sourceLabel: ''
    }
    const rawId = String(idValue || '').trim()
    if (!rawId || !rawId.toLowerCase().startsWith('runtimeevent:')) {
        return empty
    }
    const parts = rawId.split(':').map((part) => String(part || '').trim()).filter(Boolean)
    if (parts.length < 2) return empty
    const sinkLabel = humanizeRuntimeSinkLabel(parts[1])
    const reasonLabel = sanitizeEvidenceLabel(parts[2], { humanize: true, ignored: ['observed'] })
    const sourceLabel = sanitizeEvidenceLabel(parts[3], { humanize: true })
    let routeLabel = ''
    const lastPart = String(parts[parts.length - 1] || '').trim()
    if (/^_[A-Za-z0-9_/-]*$/.test(lastPart)) {
        const normalizedTail = lastPart.replace(/^_+/, '').replace(/_/g, '/')
        routeLabel = normalizedTail ? `/${normalizedTail}` : '/'
    }
    const routeTailLength = routeLabel ? 1 : 0
    const candidateParts = parts.slice(4, parts.length - routeTailLength).filter(Boolean)
    const ignoredParamParts = new Set([
        'localstorage',
        'sessionstorage',
        'cookie',
        'response',
        'json',
        'query',
        'hashquery',
        'hash',
        'param',
        'body',
        'apiresponsefield',
        'graphqlresponsefield',
        'formdatafield',
        'jsonbodyfield',
        'graphqlvariable',
        'inline',
        'header',
        'pathname',
        'pathsegment',
        'clientroute',
        'historystate'
    ])
    const paramCandidate = [...candidateParts]
        .reverse()
        .find((part) => {
            const normalized = String(part || '').trim().toLowerCase()
            return normalized && !ignoredParamParts.has(normalized) && normalized !== '_'
        }) || ''
    const paramLabel = sanitizeEvidenceLabel(paramCandidate, { humanize: true, stripKeyPrefix: true })
    return {
        routeLabel,
        paramLabel,
        sinkLabel,
        reasonLabel,
        sourceLabel
    }
}

function humanizeCrossEngineTheme(value) {
    const normalized = String(value || '').trim().toLowerCase()
    const labels = {
        dom_xss: 'DOM XSS',
        auth_surface: 'Auth/session',
        template_render: 'Template/render',
        tenant_boundary: 'Tenant/object boundary',
        file_surface: 'Upload/export/file surface',
        graphql_api_surface: 'GraphQL/API surface',
        realtime_boundary: 'Realtime boundary',
        trust_boundary: 'Client trust boundary',
        secret_exposure: 'Secret exposure',
        redirect_flow: 'Redirect flow'
    }
    return labels[normalized] || humanizeAnalysisToken(normalized) || 'Cross-engine signal'
}

function humanizeEngineList(value) {
    const engines = String(value || '')
        .split('+')
        .map((entry) => String(entry || '').trim().toUpperCase())
        .filter(Boolean)
    if (!engines.length) return ''
    if (engines.length === 1) return engines[0]
    if (engines.length === 2) return `${engines[0]} and ${engines[1]}`
    return `${engines.slice(0, -1).join(', ')}, and ${engines[engines.length - 1]}`
}

function getCandidateSignalValue(candidate, signalCode) {
    const why = Array.isArray(candidate?.why) ? candidate.why : []
    const match = why.find((entry) => String(entry?.signal || '').trim().toUpperCase() === String(signalCode || '').trim().toUpperCase())
    return match?.value ?? ''
}

function formatAnalysisSignalMessage(signal, value) {
    const normalizedSignal = String(signal || 'SIGNAL').toUpperCase()
    const normalizedValue = value ?? ''
    switch (normalizedSignal) {
    case 'PARAM_HOTSPOT':
        return `Parameter hotspot: observed ${normalizedValue} time${Number(normalizedValue) === 1 ? '' : 's'}`
    case 'PARAM_FANOUT':
        return `Parameter fanout: across ${normalizedValue} route famil${Number(normalizedValue) === 1 ? 'y' : 'ies'}`
    case 'REPEATED_5XX':
        return `Repeated 5xx responses: ${normalizedValue}`
    case 'MISSING_RELEVANT_ENGINE':
        return `Missing corroboration: ${normalizedValue}`
    case 'LOW_COVERAGE':
        return `Low coverage score: ${normalizedValue}`
    case 'CROSS_ENGINE_CORROBORATION':
        return `Cross-engine corroboration: ${normalizedValue}`
    case 'STACK_TRACE_FINGERPRINT':
        return normalizedValue ? `Stack trace fingerprint: ${normalizedValue}` : 'Stack trace fingerprint detected'
    case 'DB_ERROR_SIGNATURE':
        return normalizedValue ? `Database error signature: ${normalizedValue}` : 'Database error signature detected'
    case 'TEMPLATE_ERROR_SIGNATURE':
        return normalizedValue ? `Template error signature: ${normalizedValue}` : 'Template error signature detected'
    case 'LATENCY_OUTLIER':
        return normalizedValue ? `Latency outlier: ${normalizedValue}` : 'Latency outlier detected'
    case 'AUTH_SESSION_SIGNAL':
        return normalizedValue ? `Auth or session signal: ${normalizedValue}` : 'Auth or session signal'
    case 'RESOURCE_BEHAVIOR_DRIFT':
        return normalizedValue ? `Resource behavior drift: ${normalizedValue}` : 'Resource behavior drift'
    case 'PASSIVE_FINDING_SEED':
        return normalizedValue ? `Passive finding seed: ${normalizedValue}` : 'Passive finding seed'
    case 'FINDING_CORROBORATION':
        return 'Corroborated by an underlying finding'
    case 'CROSS_ENGINE_THEME':
        return normalizedValue ? `Theme: ${humanizeCrossEngineTheme(normalizedValue)}` : 'Cross-engine theme'
    case 'CROSS_ENGINE_SUPPORT':
        return normalizedValue ? `Backed by ${humanizeEngineList(normalizedValue)}` : 'Cross-engine support'
    case 'APP_LEVEL_ENGINE_SUPPORT':
        return normalizedValue ? `Additional app-level support from ${humanizeEngineList(normalizedValue)}` : 'App-level support'
    case 'SUPPORTING_SIGNAL_COUNT':
        return normalizedValue ? `Based on ${normalizedValue} supporting signal${Number(normalizedValue) === 1 ? '' : 's'}` : 'Supporting signals available'
    case 'SUPPORTING_ANALYSIS':
        return normalizedValue ? `Related signals: ${normalizedValue}` : 'Related analysis available'
    default:
        return normalizedValue
            ? `${humanizeAnalysisSignalCode(normalizedSignal)}: ${normalizedValue}`
            : humanizeAnalysisSignalCode(normalizedSignal)
    }
}

function buildAnalysisWhyList(lines = [], emptyText = 'No explicit signals captured.') {
    const items = Array.isArray(lines)
        ? lines.map((line) => String(line || '').trim()).filter(Boolean)
        : []
    if (!items.length) {
        return `<div class="ui tiny grey text">${escapeHtml(emptyText)}</div>`
    }
    return `<ul style="margin:4px 0 0 18px;">${items.map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul>`
}

function buildCrossEngineWhyHtml(candidate) {
    const themeValue = getCandidateSignalValue(candidate, 'CROSS_ENGINE_THEME')
    const supportValue = getCandidateSignalValue(candidate, 'CROSS_ENGINE_SUPPORT')
    const appLevelSupportValue = getCandidateSignalValue(candidate, 'APP_LEVEL_ENGINE_SUPPORT')
    const supportCountValue = Number(getCandidateSignalValue(candidate, 'SUPPORTING_SIGNAL_COUNT') || 0)
    const relatedSignals = String(getCandidateSignalValue(candidate, 'SUPPORTING_ANALYSIS') || '')
        .split('|')
        .map((entry) => String(entry || '').trim())
        .filter(Boolean)
        .slice(0, 2)
    const themeLabel = humanizeCrossEngineTheme(themeValue)
    const supportLabel = humanizeEngineList(supportValue)
    const appLevelSupportLabel = humanizeEngineList(appLevelSupportValue)
    const lines = []

    if (themeValue && supportLabel) {
        lines.push(`${themeLabel} is supported by ${supportLabel} evidence.`)
    } else if (supportLabel) {
        lines.push(`This route is backed by ${supportLabel} evidence.`)
    } else if (themeValue) {
        lines.push(`${themeLabel} signals were clustered on this route.`)
    }
    if (supportCountValue > 0) {
        lines.push(`${supportCountValue} supporting signal${supportCountValue === 1 ? '' : 's'} were clustered here.`)
    }
    if (appLevelSupportLabel && appLevelSupportLabel !== supportLabel) {
        lines.push(`Additional app-level support came from ${appLevelSupportLabel}.`)
    }
    if (relatedSignals.length) {
        lines.push(`Related signals: ${relatedSignals.join('; ')}.`)
    }
    return buildAnalysisWhyList(lines, `${humanizeAnalysisRuleCode(candidate?.createdByRule)} triggered this candidate.`)
}

function buildCandidateWhyHtml(candidate) {
    const why = Array.isArray(candidate?.why) ? candidate.why.slice(0, 4) : []
    if (String(candidate?.createdByRule || '').trim().toUpperCase() === 'R13_CROSS_ENGINE_CORRELATION') {
        return buildCrossEngineWhyHtml(candidate)
    }
    const lines = why.map((entry) => formatAnalysisSignalMessage(entry?.signal, entry?.value)).filter(Boolean)
    if (!why.length) {
        return buildAnalysisWhyList([], `${humanizeAnalysisRuleCode(candidate?.createdByRule)} triggered this candidate.`)
    }
    return buildAnalysisWhyList(lines)
}

function buildManualStepsHtml(candidate) {
    const steps = Array.isArray(candidate?.manualSteps) ? candidate.manualSteps.slice(0, 5) : []
    if (!steps.length) return '<div class="ui tiny grey text">No manual guidance.</div>'
    return `<ol style="margin:4px 0 0 18px;">${steps.map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ol>`
}

function buildManualStepsToggleHtml(candidate) {
    const steps = Array.isArray(candidate?.manualSteps) ? candidate.manualSteps.filter(Boolean) : []
    if (!steps.length) {
        return '<div class="ui tiny grey text">No manual guidance.</div>'
    }
    const candidateId = String(candidate?.id || '')
    const drawerId = `analysis_steps_${toDomSafeId(candidateId || `${candidate?.title || 'candidate'}_${steps.length}`)}`
    return `
        <a href="#" class="toggle_candidate_manual_steps" data-steps-target="${escapeAttr(drawerId)}">Show next steps</a>
        <div id="${escapeAttr(drawerId)}" style="display:none; margin-top:6px;">
            <b>Manual steps:</b> ${buildManualStepsHtml(candidate)}
        </div>
    `
}

function buildEvidenceRefsHtml(candidate) {
    const refs = Array.isArray(candidate?.evidenceRefs) ? candidate.evidenceRefs.slice(0, 6) : []
    if (!refs.length) return '<span style="color:#333; font-size:15px; font-weight:500;">No evidence refs available.</span>'
    return refs.map((ref) => {
        const type = escapeHtml(ref?.type || 'evidence')
        const id = escapeHtml(ref?.id || 'n/a')
        return `<span class="ui small basic label" style="margin-bottom:4px;">${type}:${id}</span>`
    }).join(' ')
}

function toDomSafeId(value) {
    return String(value || '')
        .replace(/[^A-Za-z0-9_-]/g, '_')
        .slice(0, 120)
}

function getCandidateParamLocation(candidate) {
    const raw = String(candidate?.paramKey || '')
    const idx = raw.indexOf(':')
    if (idx <= 0) return 'param'
    return raw.slice(0, idx).toLowerCase()
}

function normalizeFilterToken(value) {
    return String(value || '').trim().toLowerCase()
}

function normalizeHostKey(host) {
    return String(host || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '')
}

function normalizeRunStatus(status) {
    const normalized = String(status || '').trim().toLowerCase()
    return normalized || 'queued'
}

function runStatusColor(status) {
    const normalized = normalizeRunStatus(status)
    if (normalized === 'completed') return 'green'
    if (normalized === 'running') return 'blue'
    if (normalized === 'failed' || normalized === 'timed_out') return 'red'
    if (normalized === 'canceled') return 'orange'
    return 'grey'
}

function runStatusDisplay(status) {
    const normalized = normalizeRunStatus(status)
    if (normalized === 'timed_out') return 'Timed Out'
    return normalized.charAt(0).toUpperCase() + normalized.slice(1)
}

function isRunTerminal(status) {
    return PLAYWRIGHT_RUN_TERMINAL.has(normalizeRunStatus(status))
}

function normalizeReadinessLevel(value) {
    const normalized = String(value || '').trim().toLowerCase()
    if (normalized === 'blocked') return 'blocked'
    if (normalized === 'limited') return 'limited'
    return 'ready'
}

function readinessColor(level) {
    const normalized = normalizeReadinessLevel(level)
    if (normalized === 'blocked') return 'red'
    if (normalized === 'limited') return 'yellow'
    return 'green'
}

function readinessDisplay(level) {
    const normalized = normalizeReadinessLevel(level)
    return normalized.charAt(0).toUpperCase() + normalized.slice(1)
}

function mapReadinessReasonMessage(code) {
    const normalized = String(code || '').trim().toUpperCase()
    if (normalized === 'ROUTE_UNRESOLVABLE') return 'Route cannot be resolved'
    if (normalized === 'METHOD_NOT_ALLOWED') return 'HTTP method is not allowed'
    if (normalized === 'NO_REQUEST_SEED') return 'No reliable request seed'
    if (normalized === 'BASELINE_UNREACHABLE') return 'Target is not reachable'
    if (normalized === 'LOW_SIGNAL_DENSITY') return 'Low signal density'
    return normalized || 'Unknown readiness reason'
}

function localCandidateReadinessFallback(candidate) {
    const routeKey = String(candidate?.routeKey || '')
    const parts = routeKey.split('|')
    const routeResolved = parts.length >= 3 && String(parts[0] || '').trim().length > 0
    const reasons = routeResolved ? [] : ['ROUTE_UNRESOLVABLE']
    return {
        runInPlaywright: routeResolved ? 'ready' : 'blocked',
        sendToRBuilder: routeResolved ? 'ready' : 'limited',
        reasons,
        details: {
            routeResolved,
            methodAllowed: true,
            seedQuality: true,
            baselineReachable: null,
            lowSignal: false
        }
    }
}

function getCandidateActionReadiness(candidate) {
    const candidateId = String(candidate?.id || '').trim()
    if (!candidateId) return localCandidateReadinessFallback(candidate)
    return ANALYSIS_ACTION_READINESS.get(candidateId) || localCandidateReadinessFallback(candidate)
}

async function refreshCandidateActionReadiness(candidateId, { skipNetwork = true } = {}) {
    const key = String(candidateId || '').trim()
    if (!key) return null
    if (ANALYSIS_ACTION_READINESS_PENDING.has(key)) return null
    ANALYSIS_ACTION_READINESS_PENDING.add(key)
    try {
        const response = await controller.getCandidatePlaywrightReadiness({
            candidateId: key,
            skipNetwork
        })
        if (response?.success && response?.readiness) {
            const previous = ANALYSIS_ACTION_READINESS.get(key)
            ANALYSIS_ACTION_READINESS.set(key, response.readiness)
            const prevStr = previous ? JSON.stringify(previous) : ''
            const nextStr = JSON.stringify(response.readiness)
            if (prevStr !== nextStr) {
                rerenderAnalysisPanels()
            }
            return response.readiness
        }
        return null
    } catch (_) {
        return null
    } finally {
        ANALYSIS_ACTION_READINESS_PENDING.delete(key)
    }
}

function prefetchReadinessForCandidates(candidates = []) {
    const list = Array.isArray(candidates) ? candidates : []
    list.forEach((candidate) => {
        const candidateId = String(candidate?.id || '').trim()
        if (!candidateId) return
        if (ANALYSIS_ACTION_READINESS.has(candidateId)) return
        refreshCandidateActionReadiness(candidateId, { skipNetwork: true })
    })
}

function upsertCandidatePlaywrightRun(run) {
    const candidateId = String(run?.candidateId || '').trim()
    if (!candidateId) return null
    ANALYSIS_PLAYWRIGHT_RUNS.set(candidateId, {
        candidateId,
        jobId: run?.jobId || null,
        status: normalizeRunStatus(run?.status || 'queued'),
        acceptedAt: run?.acceptedAt || null,
        startedAt: run?.startedAt || null,
        finishedAt: run?.finishedAt || null,
        requestedAt: run?.requestedAt || null,
        progress: run?.progress || null,
        summary: run?.summary || null,
        observations: Array.isArray(run?.observations) ? run.observations : [],
        artifacts: run?.artifacts || null,
        sessionProfile: run?.sessionProfile || null,
        error: run?.error || null
    })
    return ANALYSIS_PLAYWRIGHT_RUNS.get(candidateId)
}

function stopCandidateRunPolling(candidateId) {
    const key = String(candidateId || '').trim()
    if (!key) return
    const timer = ANALYSIS_PLAYWRIGHT_POLLERS.get(key)
    if (timer) {
        clearInterval(timer)
        ANALYSIS_PLAYWRIGHT_POLLERS.delete(key)
    }
}

function buildCandidatePlaywrightRunHtml(candidate) {
    if (!PLAYWRIGHT_FEATURES_VISIBLE) return ''
    const candidateId = String(candidate?.id || '').trim()
    if (!candidateId) return ''
    const run = ANALYSIS_PLAYWRIGHT_RUNS.get(candidateId)
    if (!run) return ''
    const status = normalizeRunStatus(run?.status || 'queued')
    const color = runStatusColor(status)
    const progress = run?.progress && typeof run.progress === 'object'
        ? ` (${Number(run.progress.current || 0)}/${Number(run.progress.total || 0)})`
        : ''
    const summary = run?.summary && typeof run.summary === 'object'
        ? `<div class="ui tiny grey text" style="margin-top:4px;">Requests: ${Number(run.summary.requestsExecuted || 0)} | Routes: ${Number(run.summary.uniqueRoutes || 0)}</div>`
        : ''
    const topObservation = Array.isArray(run?.observations) && run.observations.length
        ? `<div class="ui tiny grey text" style="margin-top:4px;">${escapeHtml(run.observations[0]?.detail || '')}</div>`
        : ''
    const error = run?.error
        ? `<div class="ui tiny red text" style="margin-top:4px;">${escapeHtml(run.error)}</div>`
        : ''
    const sessionProfile = run?.sessionProfile && typeof run.sessionProfile === 'object'
        ? `<div class="ui tiny grey text" style="margin-top:4px;">Session: ${escapeHtml(run.sessionProfile?.label || 'current')}</div>`
        : ''
    return `
        <div class="ui tiny message" style="margin-top:8px; padding:8px;">
            <div><b>Playwright Run:</b> <span class="ui tiny ${color} label">${escapeHtml(runStatusDisplay(status))}</span>${escapeHtml(progress)}</div>
            ${sessionProfile}
            ${summary}
            ${topObservation}
            ${error}
        </div>
    `
}

function ensureAnalysisPlaywrightRunModal() {
    if (!PLAYWRIGHT_FEATURES_VISIBLE) return
    if ($('#analysis_playwright_run_modal').length) return
    const html = `
        <div class="ui tiny modal" id="analysis_playwright_run_modal">
            <div class="header">Run in Playwright</div>
            <div class="content">
                <div id="analysis_playwright_run_candidate" class="ui tiny message" style="margin-bottom:10px;">
                    Select a candidate to run.
                </div>
                <div id="analysis_playwright_run_warning" class="ui tiny warning message" style="display:none;"></div>
                <form class="ui tiny form" id="analysis_playwright_run_form">
                    <div class="two fields">
                        <div class="field">
                            <label>Profile</label>
                            <select id="analysis_playwright_profile" class="ui tiny dropdown">
                                <option value="smoke">Smoke</option>
                                <option value="deep">Deep</option>
                                <option value="custom">Custom</option>
                            </select>
                        </div>
                        <div class="field">
                            <label>Auth</label>
                            <select id="analysis_playwright_auth" class="ui tiny dropdown">
                                <option value="reuse_storage_state">Reuse current</option>
                                <option value="saved_state">Saved state</option>
                                <option value="anonymous">Anonymous</option>
                                <option value="session_profile">Session profile</option>
                            </select>
                        </div>
                    </div>
                    <div id="analysis_playwright_session_profile_field" class="field" style="display:none;">
                        <label>Session Profile</label>
                        <div style="display:flex; gap:8px; align-items:center;">
                            <select id="analysis_playwright_session_profile" class="ui tiny dropdown" style="flex:1 1 auto;">
                                <option value="">Select session profile</option>
                            </select>
                            <button type="button" class="ui tiny basic button" id="analysis_manage_session_profiles">Manage Sessions</button>
                        </div>
                        <div class="ui tiny grey text" style="margin-top:4px;">Profiles stay local in the extension and only apply to explicit bug bounty runs.</div>
                    </div>
                    <div id="analysis_playwright_custom_limits" style="display:none;">
                        <div class="three fields">
                            <div class="field">
                                <label>Duration (ms)</label>
                                <input type="number" id="analysis_playwright_limit_duration" value="120000" min="10000" step="1000" />
                            </div>
                            <div class="field">
                                <label>Max Requests</label>
                                <input type="number" id="analysis_playwright_limit_requests" value="60" min="1" step="1" />
                            </div>
                            <div class="field">
                                <label>Max Mutations</label>
                                <input type="number" id="analysis_playwright_limit_mutations" value="20" min="1" step="1" />
                            </div>
                        </div>
                    </div>
                </form>
            </div>
            <div class="actions">
                <button type="button" class="ui tiny button cancel">Cancel</button>
                <button type="button" class="ui tiny primary button" id="analysis_playwright_run_confirm">Run</button>
            </div>
        </div>
    `
    $('body').append(html)
}

function togglePlaywrightAuthMode(authMode = 'reuse_storage_state') {
    const normalized = String(authMode || 'reuse_storage_state').trim().toLowerCase()
    $('#analysis_playwright_session_profile_field').toggle(normalized === 'session_profile')
}

function ensureAnalysisSessionProfilesModal() {
    if ($('#analysis_session_profiles_modal').length) return
    const html = `
        <div class="ui tiny modal" id="analysis_session_profiles_modal">
            <div class="header">Session Profiles</div>
            <div class="content">
                <div id="analysis_session_profiles_host" class="ui tiny message"></div>
                <div id="analysis_session_profiles_feedback" class="ui tiny message" style="display:none;"></div>
                <div id="analysis_session_profiles_list" style="max-height:240px; overflow:auto; margin-bottom:12px;"></div>
                <form class="ui tiny form" id="analysis_session_profile_form">
                    <div class="fields">
                        <div class="eight wide field">
                            <label>Label</label>
                            <input type="text" id="analysis_session_profile_label" placeholder="user-a / admin / tenant-b" />
                        </div>
                        <div class="eight wide field">
                            <label>Notes</label>
                            <input type="text" id="analysis_session_profile_notes" placeholder="Optional notes" />
                        </div>
                    </div>
                </form>
            </div>
            <div class="actions">
                <button type="button" class="ui tiny button cancel">Close</button>
                <button type="button" class="ui tiny primary button" id="analysis_session_profile_create">Capture Current Session</button>
            </div>
        </div>
    `
    $('body').append(html)
}

function ensureAnalysisAuthzDiffModal() {
    if ($('#analysis_authz_diff_modal').length) return
    const sessionsSegment = PLAYWRIGHT_FEATURES_VISIBLE
        ? `
                        <div class="ui segment">
                            <div class="ui small header" style="margin-bottom:10px;">1. Sessions</div>
                            <div class="fields">
                                <div class="seven wide field">
                                    <label>Baseline Session</label>
                                    <select id="analysis_authz_diff_baseline_session" class="ui tiny dropdown">
                                        <option value="">Select baseline session</option>
                                    </select>
                                </div>
                                <div class="seven wide field">
                                    <label>Comparison Session</label>
                                    <select id="analysis_authz_diff_comparison_session" class="ui tiny dropdown">
                                        <option value="">Select comparison session</option>
                                    </select>
                                </div>
                                <div class="two wide field">
                                    <label>&nbsp;</label>
                                    <button type="button" class="ui tiny basic button" id="analysis_authz_manage_sessions" style="width:100%;">Sessions</button>
                                </div>
                            </div>
                        </div>
                        <div class="ui segment">
                            <div class="ui small header" style="margin-bottom:10px;">2. Execute</div>
                            <div id="analysis_authz_diff_run_status" style="margin-bottom:10px;"></div>
                            <div id="analysis_authz_diff_result" style="margin-top:10px;"></div>
                            <div style="margin-top:12px;">
                                <button type="button" class="ui tiny primary button" id="analysis_authz_diff_run">Run Automated Diff</button>
                            </div>
                        </div>
        `
        : `
                        <div class="ui segment">
                            <div class="ui small header" style="margin-bottom:10px;">1. Manual Compare</div>
                            <div id="analysis_authz_diff_run_status" style="margin-bottom:10px;"></div>
                            <div id="analysis_authz_diff_result" style="margin-top:10px;"></div>
                        </div>
        `
    const baselinePrefillActions = `
                                                <button type="button" class="ui tiny basic button prefill_authz_response" data-authz-target="baseline" data-authz-source="captured">Use Captured</button>
                                                ${PLAYWRIGHT_FEATURES_VISIBLE ? '<button type="button" class="ui tiny basic button prefill_authz_response" data-authz-target="baseline" data-authz-source="run">Use Latest Run</button>' : ''}
    `
    const comparisonPrefillActions = PLAYWRIGHT_FEATURES_VISIBLE
        ? `
                                                <button type="button" class="ui tiny basic button prefill_authz_response" data-authz-target="comparison" data-authz-source="captured">Use Captured</button>
                                                <button type="button" class="ui tiny basic button prefill_authz_response" data-authz-target="comparison" data-authz-source="run">Use Latest Run</button>
        `
        : ''
    const workflowControls = PLAYWRIGHT_FEATURES_VISIBLE
        ? `
                                <div id="analysis_authz_workflow_summary" style="margin-top:10px;"></div>
                                <div id="analysis_authz_workflow_replay_status" style="margin-top:10px;"></div>
                                <div id="analysis_authz_workflow_controls" style="margin-top:10px;">
                                    <button type="button" class="ui tiny basic button" id="analysis_authz_preview_workflow">Preview Workflow</button>
                                    <button type="button" class="ui tiny basic button" id="analysis_authz_replay_workflow">Replay Workflow</button>
                                </div>
        `
        : `
                                <div id="analysis_authz_workflow_summary" style="display:none;"></div>
                                <div id="analysis_authz_workflow_replay_status" style="display:none;"></div>
                                <div id="analysis_authz_workflow_controls" style="display:none;"></div>
        `
    const html = `
        <div class="ui small modal" id="analysis_authz_diff_modal">
            <div class="header">Authz Diff</div>
            <div class="content">
                <div id="analysis_authz_diff_candidate" class="ui tiny message" style="margin-bottom:10px;">
                    Select a candidate to compare.
                </div>
                <div class="ui tiny info message">
                    ${PLAYWRIGHT_FEATURES_VISIBLE
            ? 'Run the same request across two local session profiles. Use Advanced only when you need object swap, manual JSON comparison, or workflow replay.'
            : `${escapeDastPolicyHtml(PLAYWRIGHT_PAUSED_REASON)} Use manual JSON comparison, object swap, evidence, and report draft flows for now.`}
                </div>
                <div class="ui tiny form">
                    <div class="ui tiny segments">
                        ${sessionsSegment}
                        <details class="ui segment" id="analysis_authz_advanced">
                            <summary style="cursor:pointer; font-weight:600;">Advanced</summary>
                            <div style="margin-top:12px;">
                                <div class="fields" style="margin-bottom:0;">
                                    <div class="three wide field">
                                        <label>Object Swap</label>
                                        <div class="ui checkbox" style="margin-top:8px;">
                                            <input type="checkbox" id="analysis_authz_object_swap_enabled" />
                                            <label>Enable</label>
                                        </div>
                                    </div>
                                    <div class="five wide field">
                                        <label>Target</label>
                                        <input type="text" id="analysis_authz_object_swap_target" placeholder="userId / orderId / path segment" />
                                    </div>
                                    <div class="four wide field">
                                        <label>Location</label>
                                        <select id="analysis_authz_object_swap_location" class="ui tiny dropdown">
                                            <option value="param">Param</option>
                                            <option value="query">Query</option>
                                            <option value="json">JSON</option>
                                            <option value="form">Form</option>
                                            <option value="header">Header</option>
                                            <option value="path">Path</option>
                                        </select>
                                    </div>
                                    <div class="four wide field">
                                        <label>Swapped Value</label>
                                        <input type="text" id="analysis_authz_object_swap_value" placeholder="2 / alt-id / uuid" />
                                    </div>
                                </div>
                                <div style="margin-top:8px;">
                                    <button type="button" class="ui tiny basic button" id="analysis_authz_suggest_swap">Suggest Swap</button>
                                </div>
                                <div id="analysis_authz_object_swap_summary" style="margin-top:10px;"></div>
                                <div class="two fields" style="margin-top:12px;">
                                    <div class="field">
                                        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:4px;">
                                            <label style="margin:0;">Baseline Response JSON</label>
                                            <span>
                                                ${baselinePrefillActions}
                                            </span>
                                        </div>
                                        <textarea id="analysis_authz_diff_baseline_response" rows="10" spellcheck="false" style="font-family:monospace;"></textarea>
                                    </div>
                                    <div class="field">
                                        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:4px;">
                                            <label style="margin:0;">Comparison Response JSON</label>
                                            <span>
                                                ${comparisonPrefillActions}
                                            </span>
                                        </div>
                                        <textarea id="analysis_authz_diff_comparison_response" rows="10" spellcheck="false" style="font-family:monospace;"></textarea>
                                    </div>
                                </div>
                                <div style="margin-top:10px;">
                                    <button type="button" class="ui tiny basic button" id="analysis_authz_diff_compare">Compare JSON</button>
                                </div>
                                ${workflowControls}
                            </div>
                        </details>
                        <div class="ui segment" id="analysis_authz_evidence_section">
                            <div class="ui small header" style="margin-bottom:10px;">${PLAYWRIGHT_FEATURES_VISIBLE ? '3. Evidence' : '2. Evidence'}</div>
                            <div id="analysis_authz_evidence_summary" style="margin-top:10px;"></div>
                            <div id="analysis_authz_evidence_list" style="margin-top:10px;"></div>
                            <div id="analysis_authz_report_draft" style="margin-top:10px;"></div>
                            <div id="analysis_authz_evidence_actions" style="margin-top:12px;">
                                <button type="button" class="ui tiny basic button" id="analysis_authz_save_evidence">Save Evidence</button>
                                <button type="button" class="ui tiny basic button" id="analysis_authz_preview_draft">Preview Draft</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="actions">
                <button type="button" class="ui tiny button cancel">Close</button>
            </div>
        </div>
    `
    $('body').append(html)
    if (typeof $('#analysis_authz_diff_modal').modal === 'function') {
        $('#analysis_authz_diff_modal').modal({
            autofocus: false,
            observeChanges: true,
            onHidden: function () {
                stopAuthzDiffRunPolling()
            }
        })
    }
}

function renderRunModalReadiness(readiness) {
    const normalized = readiness && typeof readiness === 'object'
        ? readiness
        : { runInPlaywright: 'limited', reasons: ['UNKNOWN'] }
    const level = normalizeReadinessLevel(normalized?.runInPlaywright || 'limited')
    const reasons = Array.isArray(normalized?.reasons) ? normalized.reasons : []
    const messages = reasons.map((code) => mapReadinessReasonMessage(code))
    const color = readinessColor(level)
    const stateLabel = readinessDisplay(level)
    const $warning = $('#analysis_playwright_run_warning')
    const $confirm = $('#analysis_playwright_run_confirm')
    if (messages.length) {
        $warning
            .removeClass('red yellow green')
            .addClass(color)
            .html(`<div><b>Readiness:</b> ${escapeHtml(stateLabel)}</div><div style="margin-top:4px;">${messages.map((msg) => escapeHtml(msg)).join(' | ')}</div>`)
            .show()
    } else {
        $warning.hide().html('')
    }
    $confirm.prop('disabled', level === 'blocked')
}

function setPlaywrightRunModalProfile(profile = 'smoke') {
    const normalized = String(profile || 'smoke').toLowerCase()
    const isCustom = normalized === 'custom'
    $('#analysis_playwright_profile').val(isCustom ? 'custom' : normalized)
    $('#analysis_playwright_custom_limits').toggle(isCustom)
}

function getPlaywrightRunModalConstraints() {
    const profile = String($('#analysis_playwright_profile').val() || 'smoke').toLowerCase()
    if (profile !== 'custom') return null
    const maxDurationMs = Number($('#analysis_playwright_limit_duration').val() || 120000)
    const maxRequests = Number($('#analysis_playwright_limit_requests').val() || 60)
    const maxMutations = Number($('#analysis_playwright_limit_mutations').val() || 20)
    return {
        maxDurationMs: Number.isFinite(maxDurationMs) ? Math.max(10000, maxDurationMs) : 120000,
        maxRequests: Number.isFinite(maxRequests) ? Math.max(1, maxRequests) : 60,
        maxMutations: Number.isFinite(maxMutations) ? Math.max(1, maxMutations) : 20
    }
}

async function openSessionProfilesModal({ host = null } = {}) {
    const normalizedHost = normalizeHostKey(host || ANALYSIS_SESSION_PROFILES_STATE.host || '')
    ensureAnalysisSessionProfilesModal()
    if (!normalizedHost) {
        showResultDialog('Session Profiles', 'Host is not available for session capture.')
        return
    }
    ANALYSIS_SESSION_PROFILES_STATE.host = normalizedHost
    $('#analysis_session_profile_label').val('')
    $('#analysis_session_profile_notes').val('')
    $('#analysis_session_profiles_modal').modal('show')
    renderSessionProfilesModalContent()
    await loadSessionProfilesForHost(normalizedHost, { silent: true })
    renderSessionProfilesModalContent()
    renderPlaywrightSessionProfileOptions($('#analysis_playwright_session_profile').val() || '')
    renderAuthzDiffSessionSelectors({
        baselineSessionProfileId: $('#analysis_authz_diff_baseline_session').val() || '',
        comparisonSessionProfileId: $('#analysis_authz_diff_comparison_session').val() || ''
    })
}

function serializeComparableResponse(response = null) {
    if (!response || typeof response !== 'object') return ''
    try {
        return JSON.stringify(response, null, 2)
    } catch (_) {
        return ''
    }
}

function parseComparableResponseInput(value, label = 'Response') {
    const raw = String(value || '').trim()
    if (!raw) {
        throw new Error(`${label} JSON is required.`)
    }
    try {
        const parsed = JSON.parse(raw)
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error(`${label} JSON must be an object.`)
        }
        return parsed
    } catch (err) {
        if (err?.message?.includes('must be an object')) throw err
        throw new Error(`${label} JSON is invalid.`)
    }
}

function getAuthzDiffObjectSwapInput() {
    const enabled = $('#analysis_authz_object_swap_enabled').is(':checked')
    if (!enabled) return null
    const targetParam = String($('#analysis_authz_object_swap_target').val() || '').trim()
    const location = String($('#analysis_authz_object_swap_location').val() || 'param').trim().toLowerCase()
    const swappedValue = String($('#analysis_authz_object_swap_value').val() || '').trim()
    if (!targetParam) {
        throw new Error('Object swap target is required when object swap is enabled.')
    }
    if (!swappedValue) {
        throw new Error('Object swap value is required when object swap is enabled.')
    }
    const existing = ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap && typeof ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap === 'object'
        ? ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap
        : {}
    return {
        applied: true,
        location,
        targetParam,
        originalValue: existing?.targetParam === targetParam ? existing?.originalValue ?? null : (existing?.originalValue ?? null),
        swappedValue,
        strategy: String(existing?.strategy || 'manual_override')
    }
}

function applyObjectSwapSuggestionToModal(objectSwap = null) {
    const suggestion = objectSwap && typeof objectSwap === 'object' ? objectSwap : null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = suggestion
    const enabled = !!suggestion?.targetParam
    $('#analysis_authz_object_swap_enabled').prop('checked', enabled)
    if (enabled) {
        $('#analysis_authz_object_swap_target').val(String(suggestion?.targetParam || ''))
        $('#analysis_authz_object_swap_location').val(String(suggestion?.location || 'param'))
        $('#analysis_authz_object_swap_value').val(String(suggestion?.swappedValue || ''))
    } else {
        $('#analysis_authz_object_swap_target').val('')
        $('#analysis_authz_object_swap_location').val('param')
        $('#analysis_authz_object_swap_value').val('')
    }
    renderAuthzDiffRunUi()
}

async function loadCandidateRequestSnapshot(candidate = null) {
    const refs = Array.isArray(candidate?.evidenceRefs) ? candidate.evidenceRefs : []
    const requestRef = refs.find((ref) => String(ref?.type || '').toLowerCase() === 'request' && ref?.id)
    const attackRef = refs.find((ref) => String(ref?.type || '').toLowerCase() === 'attack' && ref?.id)
    if (!requestRef?.id) return { requestId: null, original: null, attack: null }
    const snapshot = await controller.getRequestSnapshot(requestRef.id, attackRef?.id || null)
    return snapshot && typeof snapshot === 'object'
        ? snapshot
        : { requestId: requestRef.id, original: null, attack: null }
}

function fillAuthzDiffResponse(target = 'baseline', response = null) {
    const key = String(target || 'baseline').toLowerCase() === 'comparison'
        ? '#analysis_authz_diff_comparison_response'
        : '#analysis_authz_diff_baseline_response'
    $(key).val(serializeComparableResponse(response))
}

async function prefillAuthzDiffResponse(target = 'baseline', source = 'captured') {
    const normalizedTarget = String(target || 'baseline').toLowerCase() === 'comparison' ? 'comparison' : 'baseline'
    if (String(source || 'captured').toLowerCase() === 'run') {
        if (!PLAYWRIGHT_FEATURES_VISIBLE) {
            showResultDialog('Authz Diff', PLAYWRIGHT_PAUSED_REASON)
            return
        }
        const run = ANALYSIS_PLAYWRIGHT_RUNS.get(String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId || '').trim())
        const response = extractComparableResponseFromRun(run)
        if (!response) {
            showResultDialog('Authz Diff', 'No comparable response was found in the latest Playwright run for this candidate.')
            return
        }
        fillAuthzDiffResponse(normalizedTarget, response)
        if (normalizedTarget === 'comparison' && run?.sessionProfile?.id) {
            $('#analysis_authz_diff_comparison_session').val(String(run.sessionProfile.id))
            if (typeof $('#analysis_authz_diff_comparison_session').dropdown === 'function') {
                $('#analysis_authz_diff_comparison_session').dropdown('refresh')
                $('#analysis_authz_diff_comparison_session').dropdown('set selected', String(run.sessionProfile.id))
            }
        }
        return
    }
    const snapshot = ANALYSIS_AUTHZ_DIFF_MODAL_STATE.snapshot
    const response = snapshot?.original?.response || null
    if (!response) {
        showResultDialog('Authz Diff', 'Captured baseline response is not available for this candidate.')
        return
    }
    fillAuthzDiffResponse(normalizedTarget, response)
}

async function openCandidateAuthzDiffModal(candidateId) {
    const key = String(candidateId || '').trim()
    if (!key) return
    const candidate = ANALYSIS_CANDIDATE_INDEX.get(key)
    if (!candidate) {
        showResultDialog('Authz Diff', 'Candidate is not available anymore.')
        return
    }
    ensureAnalysisAuthzDiffModal()
    const host = resolveCandidateAnalysisHost(candidate)
    stopAuthzDiffRunPolling()
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId = key
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.host = host
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.diff = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.snapshot = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.runId = ''
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.run = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackage = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackages = []
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.reportDraft = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay = null
    $('#analysis_authz_diff_candidate').html(`
        <div><b>Candidate:</b> ${escapeHtml(candidate?.title || key)}</div>
        <div style="margin-top:4px;"><code>${escapeHtml(candidate?.routeKey || '-')}</code></div>
    `)
    renderAuthzDiffRunUi()
    $('#analysis_authz_diff_baseline_response').val('')
    $('#analysis_authz_diff_comparison_response').val('')
    $('#analysis_authz_object_swap_enabled').prop('checked', false)
    $('#analysis_authz_object_swap_target').val('')
    $('#analysis_authz_object_swap_location').val('param')
    $('#analysis_authz_object_swap_value').val('')
    await loadSessionProfilesForHost(host, { silent: true })
    const profiles = getSessionProfilesForHost(host)
    const latestRun = ANALYSIS_PLAYWRIGHT_RUNS.get(key)
    const comparisonSelected = latestRun?.sessionProfile?.id
        && profiles.some((profile) => String(profile?.id || '') === String(latestRun.sessionProfile.id))
        ? String(latestRun.sessionProfile.id)
        : (profiles[1]?.id || '')
    renderAuthzDiffSessionSelectors({
        baselineSessionProfileId: profiles[0]?.id || '',
        comparisonSessionProfileId: comparisonSelected
    })
    $('#analysis_authz_diff_modal').modal('show')
    await refreshEvidencePackageListForCurrentCandidate({ silent: true })
    try {
        const snapshot = await loadCandidateRequestSnapshot(candidate)
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.snapshot = snapshot
        if (snapshot?.original?.response) {
            fillAuthzDiffResponse('baseline', snapshot.original.response)
        }
        const latestRunResponse = extractComparableResponseFromRun(latestRun)
        if (latestRunResponse) {
            fillAuthzDiffResponse('comparison', latestRunResponse)
        }
    } catch (_) {
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.snapshot = null
    }
    try {
        const swapSuggestion = await controller.suggestCandidateObjectSwap({
            candidateId: key
        })
        if (swapSuggestion?.success) {
            applyObjectSwapSuggestionToModal(swapSuggestion.objectSwap || null)
        }
    } catch (_) { }
    await refreshAuthzWorkflowSummaryAvailability({ silent: true })
}

async function runCandidateAuthzDiffComparison() {
    const candidateId = String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId || '').trim()
    if (!candidateId) {
        throw new Error('Candidate is not selected.')
    }
    const baselineSessionProfileId = String($('#analysis_authz_diff_baseline_session').val() || '').trim()
    const comparisonSessionProfileId = String($('#analysis_authz_diff_comparison_session').val() || '').trim()
    if (!baselineSessionProfileId || !comparisonSessionProfileId) {
        throw new Error('Select baseline and comparison sessions.')
    }
    if (baselineSessionProfileId === comparisonSessionProfileId) {
        throw new Error('Baseline and comparison sessions must be different.')
    }
    const baselineResponse = parseComparableResponseInput($('#analysis_authz_diff_baseline_response').val(), 'Baseline response')
    const comparisonResponse = parseComparableResponseInput($('#analysis_authz_diff_comparison_response').val(), 'Comparison response')
    const objectSwap = getAuthzDiffObjectSwapInput()
    const response = await controller.compareCandidateAuthzDiff({
        candidateId,
        baselineSessionProfileId,
        comparisonSessionProfileId,
        baselineResponse,
        comparisonResponse,
        objectSwap
    })
    if (!response?.success || !response?.diff) {
        throw new Error(response?.error || 'Authz diff comparison failed.')
    }
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = objectSwap
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackage = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.reportDraft = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.diff = response.diff
    renderAuthzDiffRunUi()
}

async function pollCandidateAuthzDiffRun(runId) {
    const key = String(runId || '').trim()
    if (!key) return
    try {
        const response = await controller.getCandidateAuthzDiffRun({ runId: key })
        if (!response?.success || !response?.run) {
            throw new Error(response?.error || 'Authz diff run polling failed.')
        }
        applyAuthzDiffRun(response.run)
        const status = String(response.run?.status || '').toLowerCase()
        if (status === 'completed' || status === 'failed' || status === 'canceled' || status === 'timed_out') {
            stopAuthzDiffRunPolling()
        }
    } catch (err) {
        stopAuthzDiffRunPolling()
        applyAuthzDiffRun({
            runId: key,
            status: 'failed',
            stage: 'job_failed',
            error: err?.message || 'Authz diff run polling failed.'
        })
    }
}

function startAuthzDiffRunPolling(runId) {
    const key = String(runId || '').trim()
    if (!key) return
    stopAuthzDiffRunPolling()
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.runId = key
    pollCandidateAuthzDiffRun(key)
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.pollTimer = setInterval(() => {
        pollCandidateAuthzDiffRun(key)
    }, 1000)
}

async function runCandidateAuthzDiffAutomated() {
    if (!PLAYWRIGHT_FEATURES_VISIBLE) {
        throw new Error(PLAYWRIGHT_PAUSED_REASON)
    }
    const candidateId = String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId || '').trim()
    if (!candidateId) {
        throw new Error('Candidate is not selected.')
    }
    const baselineSessionProfileId = String($('#analysis_authz_diff_baseline_session').val() || '').trim()
    const comparisonSessionProfileId = String($('#analysis_authz_diff_comparison_session').val() || '').trim()
    if (!baselineSessionProfileId || !comparisonSessionProfileId) {
        throw new Error('Select baseline and comparison sessions.')
    }
    if (baselineSessionProfileId === comparisonSessionProfileId) {
        throw new Error('Baseline and comparison sessions must be different.')
    }
    const objectSwap = getAuthzDiffObjectSwapInput()
    const response = await controller.runCandidateAuthzDiff({
        candidateId,
        baselineSessionProfileId,
        comparisonSessionProfileId,
        profile: 'smoke',
        objectSwap
    })
    if (!response?.success || !response?.run) {
        const reasons = Array.isArray(response?.readiness?.reasons)
            ? response.readiness.reasons.map((code) => mapReadinessReasonMessage(code)).join(' | ')
            : ''
        const suffix = reasons ? ` (${reasons})` : ''
        throw new Error((response?.error || 'Automated authz diff could not be started.') + suffix)
    }
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = objectSwap
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackage = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.reportDraft = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay = null
    applyAuthzDiffRun(response.run)
    const status = String(response.run?.status || '').toLowerCase()
    if (status !== 'completed' && status !== 'failed' && status !== 'canceled' && status !== 'timed_out') {
        startAuthzDiffRunPolling(response.run.runId)
    }
}

async function suggestCandidateObjectSwapFromModal() {
    const candidateId = String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId || '').trim()
    if (!candidateId) {
        throw new Error('Candidate is not selected.')
    }
    const currentInput = $('#analysis_authz_object_swap_value').val()
        ? {
            targetParam: String($('#analysis_authz_object_swap_target').val() || '').trim(),
            location: String($('#analysis_authz_object_swap_location').val() || 'param').trim().toLowerCase(),
            swappedValue: String($('#analysis_authz_object_swap_value').val() || '').trim()
        }
        : null
    const response = await controller.suggestCandidateObjectSwap({
        candidateId,
        objectSwap: currentInput
    })
    if (!response?.success) {
        throw new Error(response?.error || 'Object swap could not be suggested.')
    }
    applyObjectSwapSuggestionToModal(response.objectSwap || null)
}

async function refreshAuthzWorkflowSummaryAvailability({ silent = true } = {}) {
    if (!PLAYWRIGHT_FEATURES_VISIBLE) {
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = null
        renderAuthzDiffRunUi()
        return null
    }
    const candidateId = String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId || '').trim()
    if (!candidateId) {
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = null
        renderAuthzDiffRunUi()
        return null
    }
    try {
        const response = await controller.getWorkflowOverlaySummary({
            candidateId,
            baselineSessionProfileId: String($('#analysis_authz_diff_baseline_session').val() || '').trim() || null,
            comparisonSessionProfileId: String($('#analysis_authz_diff_comparison_session').val() || '').trim() || null,
            objectSwap: getAuthzDiffObjectSwapInput()
        })
        if (!response?.success) {
            throw new Error(response?.error || 'Workflow overlay summary could not be built.')
        }
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = response?.workflowSummary || null
        renderAuthzDiffRunUi()
        return ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary
    } catch (err) {
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = null
        renderAuthzDiffRunUi()
        if (!silent) {
            throw err
        }
        return null
    }
}

async function previewAuthzWorkflowOverlay() {
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = getAuthzDiffObjectSwapInput()
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay = null
    await refreshAuthzWorkflowSummaryAvailability({ silent: false })
}

async function startAuthzWorkflowOverlayReplay() {
    const candidateId = String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId || '').trim()
    if (!candidateId) {
        throw new Error('Candidate is not selected.')
    }
    const baselineSessionProfileId = String($('#analysis_authz_diff_baseline_session').val() || '').trim()
    const comparisonSessionProfileId = String($('#analysis_authz_diff_comparison_session').val() || '').trim()
    if (!baselineSessionProfileId || !comparisonSessionProfileId) {
        throw new Error('Select baseline and comparison sessions.')
    }
    if (baselineSessionProfileId === comparisonSessionProfileId) {
        throw new Error('Baseline and comparison sessions must be different.')
    }
    const objectSwap = getAuthzDiffObjectSwapInput()
    const response = await controller.startWorkflowOverlayReplay({
        candidateId,
        baselineSessionProfileId,
        comparisonSessionProfileId,
        replaySessionRelation: 'comparison',
        objectSwap
    })
    if (!response?.success) {
        throw new Error(response?.error || 'Workflow replay could not be started.')
    }
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = objectSwap
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = response?.workflowSummary || null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay = response
    renderAuthzDiffRunUi()
}

async function saveAuthzEvidencePackage() {
    const candidateId = String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId || '').trim()
    if (!candidateId) {
        throw new Error('Candidate is not selected.')
    }
    const objectSwap = getAuthzDiffObjectSwapInput()
    const payload = {
        candidateId,
        runId: String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.runId || '').trim() || null,
        baselineSessionProfileId: String($('#analysis_authz_diff_baseline_session').val() || '').trim() || null,
        comparisonSessionProfileId: String($('#analysis_authz_diff_comparison_session').val() || '').trim() || null,
        objectSwap
    }
    if (!payload.runId) {
        payload.baselineResponse = parseComparableResponseInput($('#analysis_authz_diff_baseline_response').val(), 'Baseline response')
        payload.comparisonResponse = parseComparableResponseInput($('#analysis_authz_diff_comparison_response').val(), 'Comparison response')
    }
    const response = await controller.createEvidencePackageFromAuthzDiff(payload)
    if (!response?.success || !response?.evidencePackage) {
        throw new Error(response?.error || 'Evidence package could not be created.')
    }
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = objectSwap
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.evidencePackage = response.evidencePackage
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.reportDraft = response.reportDraft || null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = response.workflowSummary || null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay = null
    renderAuthzDiffRunUi()
    await refreshEvidencePackageListForCurrentCandidate({ silent: true })
}

async function previewCandidateReportDraft() {
    const candidateId = String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.candidateId || '').trim()
    if (!candidateId) {
        throw new Error('Candidate is not selected.')
    }
    const objectSwap = getAuthzDiffObjectSwapInput()
    const payload = {
        candidateId,
        runId: String(ANALYSIS_AUTHZ_DIFF_MODAL_STATE.runId || '').trim() || null,
        baselineSessionProfileId: String($('#analysis_authz_diff_baseline_session').val() || '').trim() || null,
        comparisonSessionProfileId: String($('#analysis_authz_diff_comparison_session').val() || '').trim() || null,
        objectSwap
    }
    if (!payload.runId) {
        payload.baselineResponse = parseComparableResponseInput($('#analysis_authz_diff_baseline_response').val(), 'Baseline response')
        payload.comparisonResponse = parseComparableResponseInput($('#analysis_authz_diff_comparison_response').val(), 'Comparison response')
    }
    const response = await controller.buildCandidateReportDraft(payload)
    if (!response?.success || !response?.reportDraft) {
        throw new Error(response?.error || 'Report draft could not be built.')
    }
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = objectSwap
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.reportDraft = response.reportDraft
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowSummary = response.workflowSummary || null
    ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay = null
    renderAuthzDiffRunUi()
}

async function openCandidatePlaywrightRunModal(candidateId) {
    if (!PLAYWRIGHT_FEATURES_VISIBLE) {
        showResultDialog('Playwright Run', PLAYWRIGHT_PAUSED_REASON)
        return
    }
    const key = String(candidateId || '').trim()
    if (!key) return
    const candidate = ANALYSIS_CANDIDATE_INDEX.get(key)
    if (!candidate) {
        showResultDialog('Playwright Run', 'Candidate is not available anymore.')
        return
    }
    ensureAnalysisPlaywrightRunModal()
    ANALYSIS_PLAYWRIGHT_MODAL_STATE.candidateId = key
    ANALYSIS_PLAYWRIGHT_MODAL_STATE.readiness = null
    const host = resolveCandidateAnalysisHost(candidate)
    $('#analysis_playwright_run_candidate').html(`
        <div><b>Candidate:</b> ${escapeHtml(candidate?.title || key)}</div>
        <div style="margin-top:4px;"><code>${escapeHtml(candidate?.routeKey || '-')}</code></div>
    `)
    $('#analysis_playwright_run_warning').hide().html('')
    const fallback = getCandidateActionReadiness(candidate)
    renderRunModalReadiness(fallback)
    setPlaywrightRunModalProfile('smoke')
    $('#analysis_playwright_auth').val('reuse_storage_state')
    togglePlaywrightAuthMode('reuse_storage_state')
    await loadSessionProfilesForHost(host, { silent: true })
    renderPlaywrightSessionProfileOptions('')
    $('#analysis_playwright_run_confirm').addClass('loading disabled')
    $('#analysis_playwright_run_modal').modal('show')
    try {
        const readiness = await refreshCandidateActionReadiness(key, { skipNetwork: false })
        ANALYSIS_PLAYWRIGHT_MODAL_STATE.readiness = readiness || fallback
        renderRunModalReadiness(ANALYSIS_PLAYWRIGHT_MODAL_STATE.readiness)
    } catch (_) {
        ANALYSIS_PLAYWRIGHT_MODAL_STATE.readiness = fallback
        renderRunModalReadiness(fallback)
    } finally {
        $('#analysis_playwright_run_confirm').removeClass('loading disabled')
    }
}

async function pollCandidatePlaywrightRun(candidateId) {
    const key = String(candidateId || '').trim()
    if (!key) return
    try {
        const response = await controller.getCandidatePlaywrightRun({ candidateId: key })
        if (response?.run) {
            const run = upsertCandidatePlaywrightRun(response.run)
            rerenderAnalysisPanels()
            if (isRunTerminal(run?.status)) {
                stopCandidateRunPolling(key)
            }
            return
        }
        if (response?.success === false && response?.error) {
            const current = ANALYSIS_PLAYWRIGHT_RUNS.get(key)
            if (current && !isRunTerminal(current.status)) {
                upsertCandidatePlaywrightRun({
                    ...current,
                    status: 'failed',
                    error: String(response.error || 'Playwright run polling failed')
                })
                rerenderAnalysisPanels()
            }
            stopCandidateRunPolling(key)
        }
    } catch (_) {
        const current = ANALYSIS_PLAYWRIGHT_RUNS.get(key)
        if (current && !isRunTerminal(current.status)) {
            upsertCandidatePlaywrightRun({
                ...current,
                status: 'failed',
                error: 'Playwright run polling failed'
            })
            rerenderAnalysisPanels()
        }
        stopCandidateRunPolling(key)
    }
}

function startCandidateRunPolling(candidateId) {
    const key = String(candidateId || '').trim()
    if (!key) return
    const run = ANALYSIS_PLAYWRIGHT_RUNS.get(key)
    if (!run || isRunTerminal(run.status)) return
    if (ANALYSIS_PLAYWRIGHT_POLLERS.has(key)) return
    pollCandidatePlaywrightRun(key)
    const timer = setInterval(() => {
        pollCandidatePlaywrightRun(key)
    }, 1000)
    ANALYSIS_PLAYWRIGHT_POLLERS.set(key, timer)
}

function candidateMatchesAnalysisFilters(candidate) {
    if (!candidate || typeof candidate !== 'object') return false
    const engineFilter = normalizeFilterToken(ANALYSIS_FILTER_STATE.engine)
    if (engineFilter && engineFilter !== 'all') {
        const engineSignals = Array.isArray(candidate.engineSignals) ? candidate.engineSignals : []
        const hasEngine = engineSignals.some((engine) => normalizeFilterToken(engine) === engineFilter)
        if (!hasEngine) return false
    }
    const typeFilter = normalizeFilterToken(ANALYSIS_FILTER_STATE.type)
    if (typeFilter && typeFilter !== 'all') {
        if (normalizeFilterToken(candidate?.type) !== typeFilter) return false
    }
    const confidenceFilter = normalizeFilterToken(ANALYSIS_FILTER_STATE.confidence)
    if (confidenceFilter && confidenceFilter !== 'all') {
        if (normalizeFilterToken(candidate?.confidence) !== confidenceFilter) return false
    }
    const routeFilter = normalizeFilterToken(ANALYSIS_FILTER_STATE.route)
    if (routeFilter) {
        const routeKey = normalizeFilterToken(candidate?.routeKey)
        if (!routeKey.includes(routeFilter)) return false
    }
    const paramLocationFilter = normalizeFilterToken(ANALYSIS_FILTER_STATE.paramLocation)
    if (paramLocationFilter && paramLocationFilter !== 'all') {
        if (getCandidateParamLocation(candidate) !== paramLocationFilter) return false
    }
    return true
}

function buildSelectOptions(values, selectedValue, allLabel = 'All') {
    const selected = String(selectedValue || 'all')
    const sorted = Array.from(new Set(values.map((value) => String(value)).filter(Boolean)))
        .sort((a, b) => a.localeCompare(b))
    const allSelected = selected === 'all' ? ' selected' : ''
    const options = [`<option value="all"${allSelected}>${escapeHtml(allLabel)}</option>`]
    sorted.forEach((value) => {
        const isSelected = value === selected ? ' selected' : ''
        options.push(`<option value="${escapeAttr(value)}"${isSelected}>${escapeHtml(value)}</option>`)
    })
    return options.join('')
}

function buildAnalysisFiltersHtml(candidates = []) {
    const engines = []
    const types = []
    const paramLocations = []
    candidates.forEach((candidate) => {
        const engineSignals = Array.isArray(candidate?.engineSignals) ? candidate.engineSignals : []
        engineSignals.forEach((engine) => engines.push(String(engine || '').toUpperCase()))
        if (candidate?.type) types.push(String(candidate.type))
        paramLocations.push(getCandidateParamLocation(candidate))
    })
    return `
        <div class="ui tiny form" id="analysis_filters" style="margin-bottom:8px;">
            <div class="fields">
                <div class="two wide field">
                    <label>Engine</label>
                    <select class="ui tiny dropdown" id="analysis_filter_engine">
                        ${buildSelectOptions(engines, ANALYSIS_FILTER_STATE.engine, 'All engines')}
                    </select>
                </div>
                <div class="two wide field">
                    <label>Type</label>
                    <select class="ui tiny dropdown" id="analysis_filter_type">
                        ${buildSelectOptions(types, ANALYSIS_FILTER_STATE.type, 'All types')}
                    </select>
                </div>
                <div class="three wide field">
                    <label>Confidence</label>
                    <select class="ui tiny dropdown" id="analysis_filter_confidence">
                        ${buildSelectOptions(['high', 'medium', 'low'], ANALYSIS_FILTER_STATE.confidence, 'All confidence')}
                    </select>
                </div>
                <div class="three wide field">
                    <label>Location</label>
                    <select class="ui tiny dropdown" id="analysis_filter_param_location">
                        ${buildSelectOptions(paramLocations, ANALYSIS_FILTER_STATE.paramLocation, 'All locations')}
                    </select>
                </div>
                <div class="four wide field">
                    <label>Route</label>
                    <input type="text" id="analysis_filter_route" placeholder="Contains route..." value="${escapeAttr(ANALYSIS_FILTER_STATE.route || '')}" />
                </div>
                <div class="field" style="padding-top:22px;">
                    <button type="button" class="ui tiny basic button" id="analysis_filter_reset">Reset</button>
                </div>
            </div>
        </div>
    `
}

function buildEvidenceDrawerHtml(candidate) {
    const refs = Array.isArray(candidate?.evidenceRefs) ? candidate.evidenceRefs : []
    if (!refs.length) {
        return '<div style="font-size:14px;color:#555;">No evidence refs available for this candidate yet.</div>'
    }
    const groups = new Map()
    refs.forEach((ref) => {
        const type = String(ref?.type || 'evidence').toLowerCase()
        if (!groups.has(type)) groups.set(type, new Map())
        const locator = ref?.loc && typeof ref.loc === 'object'
            ? Object.keys(ref.loc).sort((a, b) => a.localeCompare(b)).map((key) => `${key}=${ref.loc[key]}`).join('&')
            : ''
        const key = [type, String(ref?.id || '').trim(), locator].join('|')
        if (!groups.get(type).has(key)) {
            groups.get(type).set(key, ref)
        }
    })
    return Array.from(groups.entries()).map(([type, entries]) => buildEvidenceDrawerGroupHtml(type, Array.from(entries.values()), candidate)).join('')
}

function formatEvidenceLoc(loc) {
    if (!loc || typeof loc !== 'object') return ''
    return Object.keys(loc)
        .sort((a, b) => a.localeCompare(b))
        .map((key) => `${escapeHtml(key)}=${escapeHtml(loc[key])}`)
        .join(', ')
}

function summarizeRequestRef(ref) {
    const requestModel = findRequestModel(ref?.id)
    const originalRequest = requestModel?.original?.request || {}
    const method = String(originalRequest?.method || requestModel?.method || ref?.loc?.method || 'GET').toUpperCase()
    const url = originalRequest?.url || originalRequest?.ui_url || requestModel?.displayUrl || requestModel?.url || null
    const title = url ? `${method} ${url}` : `${method} request ${ref?.id || 'n/a'}`
    const details = []
    if (requestModel?.status != null) {
        details.push(`Status: <b>${escapeHtml(requestModel.status)}</b>`)
    }
    const locText = formatEvidenceLoc(ref?.loc)
    if (locText) {
        details.push(`Context: <b>${locText}</b>`)
    }
    return {
        title,
        details,
        engine: 'DAST'
    }
}

function findAttackRefModel(attackId) {
    const requests = getViewModelRequests()
    for (let idx = 0; idx < requests.length; idx += 1) {
        const requestModel = requests[idx]
        const attack = findAttackModel(requestModel, attackId)
        if (attack) {
            return { requestModel, attack }
        }
    }
    return { requestModel: null, attack: null }
}

function summarizeAttackRef(ref) {
    const { requestModel, attack } = findAttackRefModel(ref?.id)
    const originalRequest = requestModel?.original?.request || attack?.request || {}
    const method = String(originalRequest?.method || ref?.loc?.method || 'GET').toUpperCase()
    const url = originalRequest?.url || originalRequest?.ui_url || requestModel?.original?.ui_url || null
    const titleBase = attack?.ruleName || attack?.name || attack?.moduleName || attack?.moduleId || attack?.ruleId || ref?.id || 'Attack'
    const title = `${titleBase}${url ? ` · ${method} ${url}` : ''}`
    const details = []
    const param = attack?.param || attack?.metadata?.param || attack?.metadata?.attacked?.name || attack?.metadata?.attacked || null
    if (param) {
        details.push(`Parameter: <b>${escapeHtml(param)}</b>`)
    }
    const severity = String(attack?.severity || attack?.metadata?.severity || '').trim().toLowerCase()
    if (severity) {
        details.push(`Severity: <b>${escapeHtml(severity)}</b>`)
    }
    const locText = formatEvidenceLoc(ref?.loc)
    if (locText) {
        details.push(`Context: <b>${locText}</b>`)
    }
    return {
        title,
        details,
        engine: 'DAST'
    }
}

function inferEvidenceRefEngine(ref, candidate = null) {
    const type = String(ref?.type || '').trim().toLowerCase()
    if (type === 'request' || type === 'attack') {
        return 'DAST'
    }
    if (type === 'runtimeevent') {
        return 'IAST'
    }
    const findingId = String(ref?.id || '').trim()
    if (type === 'finding' && findingId) {
        const lookup = controller._dastFindingLookup || buildFindingLookup(controller?.scanViewModel?.findings || [])
        controller._dastFindingLookup = lookup
        const finding = lookup.get(findingId) || RELATED_FINDING_SUMMARY_INDEX.get(findingId) || null
        if (finding?.engine) {
            return String(finding.engine).trim().toUpperCase()
        }
        const engineMatch = findingId.match(/::(DAST|IAST|SAST|SCA)::/i)
        if (engineMatch) {
            return String(engineMatch[1] || '').toUpperCase()
        }
        if (/^[a-f0-9]{32,64}:\d{10,14}$/i.test(findingId)) {
            return 'IAST'
        }
    }
    const loc = ref?.loc && typeof ref.loc === 'object' ? ref.loc : {}
    const moduleText = `${String(loc.module || '').trim()} ${String(loc.rule || '').trim()} ${String(loc.kind || '').trim()}`.toLowerCase()
    const idText = findingId.toLowerCase()
    if (moduleText.includes('iast') || idText.startsWith('runtimeevent:') || idText.startsWith('iast-')) {
        return 'IAST'
    }
    if (moduleText.includes('sast') || idText.startsWith('sast-')) {
        return 'SAST'
    }
    if (moduleText.includes('sca') || idText.startsWith('sca-')) {
        return 'SCA'
    }
    if (moduleText.includes('dast') || idText.startsWith('dast-')) {
        return 'DAST'
    }
    if (candidate?.engine) {
        return String(candidate.engine).trim().toUpperCase()
    }
    return ''
}

function summarizeFindingRef(ref, candidate = null) {
    const lookup = controller._dastFindingLookup || buildFindingLookup(controller?.scanViewModel?.findings || [])
    controller._dastFindingLookup = lookup
    const findingId = String(ref?.id || '')
    const finding = lookup.get(findingId) || RELATED_FINDING_SUMMARY_INDEX.get(findingId) || null
    const engineMatch = findingId.match(/::(DAST|IAST|SAST|SCA)::/i)
    const opaqueIastId = /^[a-f0-9]{32,64}:\d{10,14}$/i.test(findingId)
    const engineHint = finding?.engine
        || (engineMatch ? String(engineMatch[1] || '').toUpperCase() : '')
        || (opaqueIastId ? 'IAST' : '')
    const titleBase = finding?.ruleName
        || finding?.title
        || finding?.category
        || finding?.moduleName
        || finding?.moduleId
        || sanitizeEvidenceLabel(ref?.loc?.title || '', { humanize: false })
        || (engineMatch
            ? (humanizeEvidenceFindingTitle({
                ruleId: findingId.split('::')[3] || findingId.split('::')[2] || '',
                moduleId: ref?.loc?.module || '',
                engine: engineHint
            }) || 'Finding')
            : (humanizeEvidenceFindingTitle({
                ruleId: ref?.loc?.rule || '',
                moduleId: ref?.loc?.module || '',
                engine: engineHint
            }) || 'Finding'))
    const method = String(finding?.location?.method || ref?.loc?.method || 'GET').toUpperCase()
    const candidateRoute = candidate?.routeKey ? splitRouteKeyParts(candidate.routeKey) : null
    const fallbackRoute = candidateRoute?.pathTemplate ? `${candidateRoute.method} ${candidateRoute.pathTemplate}` : null
    const locationLabel = finding?.location?.url
        || finding?.location?.route
        || fallbackRoute
        || null
    const title = locationLabel
        ? (String(locationLabel).startsWith('http') || String(locationLabel).startsWith('#/') || String(locationLabel).startsWith('/') || String(locationLabel).includes(' ')
            ? `${titleBase} · ${locationLabel}`
            : `${titleBase} · ${method} ${locationLabel}`)
        : titleBase
    const details = []
    const severity = String(finding?.severity || ref?.loc?.severity || '').trim().toLowerCase()
    if (severity) {
        details.push(`Severity: <b>${escapeHtml(severity)}</b>`)
    }
    const param = finding?.location?.param || null
    if (param) {
        details.push(`Parameter: <b>${escapeHtml(param)}</b>`)
    }
    const locText = formatEvidenceLoc(ref?.loc)
    if (locText) {
        details.push(`Context: <b>${locText}</b>`)
    }
    return {
        title,
        details,
        engine: engineHint || ''
    }
}

function summarizeGenericEvidenceRef(ref) {
    const type = String(ref?.type || 'evidence').trim()
    const normalizedType = type.toLowerCase()
    const idValue = String(ref?.id || '').trim()
    const loc = ref?.loc && typeof ref.loc === 'object' ? ref.loc : {}
    const routeParts = splitRouteKeyParts(loc.route || '')
    const routeMethod = String(loc.method || routeParts.method || '').trim().toUpperCase()
    const routePath = String(loc.path || routeParts.pathTemplate || '').trim()
    const routeLabel = routePath
        ? `${routeMethod && routeMethod !== '*' ? `${routeMethod} ` : ''}${routePath}`
        : ''
    const fallbackRouteLabel = (() => {
        const rawRoute = String(loc.route || '').trim()
        if (!rawRoute || routeLabel) return routeLabel
        if (rawRoute.startsWith('http') || rawRoute.startsWith('#/') || rawRoute.startsWith('/')) {
            return rawRoute
        }
        if (rawRoute.includes('|')) {
            const parts = splitRouteKeyParts(rawRoute)
            const method = String(parts.method || routeMethod || '').trim().toUpperCase()
            const path = String(parts.pathTemplate || '').trim()
            if (path) {
                return `${method && method !== '*' ? `${method} ` : ''}${path}`
            }
        }
        return routeMethod ? `${routeMethod} ${rawRoute}` : rawRoute
    })()
    const inferredKindFromId = (() => {
        const lower = idValue.toLowerCase()
        if (lower.startsWith('sast-hidden-param::')) return 'hidden_param'
        if (lower.startsWith('sast-surface::')) return 'surface'
        if (lower.startsWith('sast-gadget::')) return 'gadget'
        if (lower.startsWith('sast-route::')) return 'route'
        if (lower.startsWith('runtimeevent:')) return 'runtimeevent'
        return ''
    })()
    const kind = String(loc.kind || inferredKindFromId || '').trim().toLowerCase()
    const moduleLabel = humanizeAnalysisToken(String(loc.module || '').trim())
    const ruleLabel = humanizeAnalysisToken(String(loc.rule || '').trim())
    const idParts = idValue.split('::').filter(Boolean)
    const fallbackParamFromId = (() => {
        if (kind === 'hidden_param' || kind === 'surface' || kind === 'gadget') {
            return String(idParts[idParts.length - 1] || '').trim()
        }
        return ''
    })()
    const runtimeIdFallback = parseRuntimeEventEvidenceId(idValue)
    const paramLabel = normalizedType === 'runtimeevent'
        ? sanitizeEvidenceLabel(loc.param || runtimeIdFallback.paramLabel || '', { humanize: true, stripKeyPrefix: true })
            || sanitizeEvidenceLabel(fallbackParamFromId, { humanize: true, stripKeyPrefix: true })
        : String(loc.param || fallbackParamFromId || '').trim()
    const kindLabels = {
        hidden_param: 'Hidden parameter',
        surface: 'Surface artifact',
        gadget: 'Client-side gadget',
        route: 'Route artifact',
        iast_runtime: 'IAST runtime event',
        client_authz_and_state: 'Client auth/state event',
        runtimeevent: 'Runtime event'
    }
    const typeBase = normalizedType === 'artifact'
        ? 'Artifact'
        : normalizedType === 'runtimeevent'
            ? 'Runtime event'
            : humanizeAnalysisToken(type)
    const effectiveRouteLabel = (() => {
        const label = String(fallbackRouteLabel || runtimeIdFallback.routeLabel || '').trim()
        if (!label) return ''
        if (/^[A-Z*]+\s*$/.test(label)) return ''
        return label
    })()
    const pushTitlePart = (list, value) => {
        const text = String(value || '').trim()
        if (!text) return
        if (list.some((item) => String(item || '').trim().toLowerCase() === text.toLowerCase())) return
        list.push(text)
    }
    const titleParts = []
    if (normalizedType === 'runtimeevent') {
        pushTitlePart(titleParts, paramLabel)
        pushTitlePart(titleParts, ruleLabel)
        pushTitlePart(titleParts, runtimeIdFallback.reasonLabel)
        pushTitlePart(titleParts, moduleLabel)
        pushTitlePart(titleParts, runtimeIdFallback.sinkLabel)
        pushTitlePart(titleParts, effectiveRouteLabel)
    } else {
        pushTitlePart(titleParts, kindLabels[kind] || (kind ? humanizeAnalysisToken(kind) : typeBase))
        if (!kind) pushTitlePart(titleParts, moduleLabel)
        pushTitlePart(titleParts, paramLabel)
        pushTitlePart(titleParts, effectiveRouteLabel)
    }
    const title = titleParts.filter(Boolean).join(' · ') || typeBase
    const details = []
    if (moduleLabel) details.push(`Module: <b>${escapeHtml(moduleLabel)}</b>`)
    if (ruleLabel) details.push(`Rule: <b>${escapeHtml(ruleLabel)}</b>`)
    if (normalizedType === 'runtimeevent' && runtimeIdFallback.reasonLabel && !title.includes(runtimeIdFallback.reasonLabel)) {
        details.push(`Signal: <b>${escapeHtml(runtimeIdFallback.reasonLabel)}</b>`)
    }
    if (normalizedType === 'runtimeevent' && runtimeIdFallback.sourceLabel) {
        details.push(`Source: <b>${escapeHtml(runtimeIdFallback.sourceLabel)}</b>`)
    }
    if (runtimeIdFallback.sinkLabel && !title.includes(runtimeIdFallback.sinkLabel)) {
        details.push(`Sink: <b>${escapeHtml(runtimeIdFallback.sinkLabel)}</b>`)
    }
    if (effectiveRouteLabel && !title.includes(effectiveRouteLabel)) details.push(`Route: <b>${escapeHtml(effectiveRouteLabel)}</b>`)
    if (paramLabel && !title.includes(paramLabel)) details.push(`Parameter: <b>${escapeHtml(paramLabel)}</b>`)
    if (!details.length) {
        const locText = formatEvidenceLoc(ref?.loc)
        if (locText) {
            details.push(`Context: <b>${locText}</b>`)
        }
    }
    const engine = inferEvidenceRefEngine(ref)
    return {
        title,
        details,
        engine
    }
}

function buildEvidenceEngineBadge(engine) {
    const normalized = String(engine || '').trim().toUpperCase()
    if (!normalized) return ''
    let labelClass = 'ui mini grey label'
    if (normalized === 'DAST') labelClass = 'ui mini red label'
    else if (normalized === 'IAST') labelClass = 'ui mini blue label'
    else if (normalized === 'SAST') labelClass = 'ui mini teal label'
    return `<span class="${labelClass}" style="white-space:nowrap; margin-left:6px;">${escapeHtml(normalized)}</span>`
}

function canOpenGenericEvidenceInRBuilder(ref, candidate) {
    if (!candidate) return false
    return inferEvidenceRefEngine(ref, candidate) === 'DAST'
}

function buildEvidenceDrawerEntryHtml(ref, candidate) {
    const type = String(ref?.type || 'evidence').toLowerCase()
    let summary = null
    if (type === 'request') {
        summary = summarizeRequestRef(ref)
    } else if (type === 'attack') {
        summary = summarizeAttackRef(ref)
    } else if (type === 'finding') {
        summary = summarizeFindingRef(ref, candidate)
    } else {
        summary = summarizeGenericEvidenceRef(ref)
    }
    const title = escapeHtml(summary?.title || `${type}: ${ref?.id || 'n/a'}`)
    const details = Array.isArray(summary?.details) ? summary.details.filter(Boolean) : []
    const engineBadge = buildEvidenceEngineBadge(summary?.engine || inferEvidenceRefEngine(ref, candidate))
    let rightActionHtml = ''
    if (type === 'request' && ref?.id) {
        rightActionHtml = `
            <a href="#" class="open_evidence_request_rbuilder"
                data-request-id="${escapeAttr(ref.id)}"
                data-candidate-id="${escapeAttr(candidate?.id || '')}"
                style="display:inline-flex; align-items:center; justify-content:center; width:24px; height:24px; color:#000;"
                title="Send to R-Builder">
                <i class="wrench large icon" style="margin:0;"></i>
            </a>
        `
    } else if (type === 'attack' && ref?.id) {
        rightActionHtml = `
            <a href="#" class="open_evidence_attack_rbuilder"
                data-attack-id="${escapeAttr(ref.id)}"
                data-candidate-id="${escapeAttr(candidate?.id || '')}"
                style="display:inline-flex; align-items:center; justify-content:center; width:24px; height:24px; color:#000;"
                title="Send to R-Builder">
                <i class="wrench large icon" style="margin:0;"></i>
            </a>
        `
    } else if (type === 'finding' && ref?.id) {
        rightActionHtml = `
            <a href="#" class="open_evidence_finding_details"
                data-finding-id="${escapeAttr(ref.id)}"
                data-candidate-id="${escapeAttr(candidate?.id || '')}"
                title="Details">Details</a>
        `
    } else if (canOpenGenericEvidenceInRBuilder(ref, candidate)) {
        rightActionHtml = `
            <a href="#" class="open_evidence_generic_rbuilder"
                data-evidence-id="${escapeAttr(ref?.id || '')}"
                data-evidence-type="${escapeAttr(type)}"
                data-evidence-route="${escapeAttr(ref?.loc?.route || '')}"
                data-evidence-method="${escapeAttr(ref?.loc?.method || '')}"
                data-evidence-param="${escapeAttr(ref?.loc?.param || '')}"
                data-candidate-id="${escapeAttr(candidate?.id || '')}"
                style="display:inline-flex; align-items:center; justify-content:center; width:24px; height:24px; color:#000;"
                title="Send to R-Builder">
                <i class="wrench large icon" style="margin:0;"></i>
            </a>
        `
    }
    return `
        <div class="ui segment" style="position:relative; padding:8px; margin:6px 0; min-height:72px;">
            <div style="position:absolute; top:0px; right:0px; white-space:nowrap;">
                ${engineBadge}
            </div>
            <div style="padding-right:40px; min-width:0; overflow-wrap:anywhere; word-break:break-word; white-space:normal;">
                <b style="overflow-wrap:anywhere; word-break:break-word; white-space:normal;">${title}</b>
            </div>
            ${details.length ? `<div style="margin-top:4px; padding-right:40px; font-size:13px; color:#555; min-width:0; overflow-wrap:anywhere; word-break:break-word; white-space:normal;">${details.join('<br/>')}</div>` : ''}
            ${rightActionHtml ? `<div style="position:absolute; right:8px; bottom:8px; display:flex; align-items:center; justify-content:flex-end;">${rightActionHtml}</div>` : ''}
        </div>
    `
}

function humanizeEvidenceGroup(type) {
    const normalized = String(type || '').toLowerCase()
    if (normalized === 'request') return 'Requests'
    if (normalized === 'attack') return 'Attacks'
    if (normalized === 'finding') return 'Findings'
    if (normalized === 'artifact') return 'Artifacts'
    if (normalized === 'runtimeevent') return 'Runtime events'
    return normalized ? `${normalized.charAt(0).toUpperCase()}${normalized.slice(1)}` : 'Evidence'
}

function buildEvidenceDrawerGroupHtml(type, refs, candidate) {
    const label = escapeHtml(humanizeEvidenceGroup(type))
    return `
        <div style="margin:8px 0 12px 0;">
            <div style="font-size:13px; font-weight:600; color:#555; margin-bottom:4px;">${label}</div>
            ${refs.map((ref) => buildEvidenceDrawerEntryHtml(ref, candidate)).join('')}
        </div>
    `
}

function splitRouteKeyParts(routeKey, fallbackHost = null) {
    const [hostRaw = '', methodRaw = '', pathRaw = ''] = String(routeKey || '').split('|')
    return {
        host: hostRaw || String(fallbackHost || 'localhost:80'),
        method: (methodRaw || 'GET').toUpperCase(),
        pathTemplate: pathRaw || '/'
    }
}

function materializePathTemplate(pathTemplate) {
    const raw = String(pathTemplate || '/').trim() || '/'
    const replaced = raw.replace(/:[A-Za-z0-9_]+/g, '1')
    return replaced.startsWith('/') ? replaced : `/${replaced}`
}

function defaultRequestSchemeForHost(host) {
    const normalizedHost = String(host || '').trim().toLowerCase()
    if (!normalizedHost) return 'http'
    if (
        normalizedHost === 'localhost'
        || normalizedHost.startsWith('localhost:')
        || normalizedHost === '127.0.0.1'
        || normalizedHost.startsWith('127.0.0.1:')
        || normalizedHost === '0.0.0.0'
        || normalizedHost.startsWith('0.0.0.0:')
        || normalizedHost === '[::1]'
        || normalizedHost.startsWith('[::1]:')
    ) {
        return 'http'
    }
    return 'https'
}

function inferScanOrigin(rawScan = {}, host = '') {
    const normalizedHost = String(host || rawScan?.host || '').trim()
    const requests = Array.isArray(rawScan?.requests) ? rawScan.requests : []
    const absoluteUrlCandidates = []
    requests.forEach((record) => {
        const originalUrl = String(record?.original?.request?.url || '').trim()
        if (/^https?:\/\//i.test(originalUrl)) {
            absoluteUrlCandidates.push(originalUrl)
        }
        const attacks = Array.isArray(record?.attacks) ? record.attacks : []
        attacks.forEach((attack) => {
            const attackUrl = String(attack?.request?.url || attack?.request?.target || '').trim()
            if (/^https?:\/\//i.test(attackUrl)) {
                absoluteUrlCandidates.push(attackUrl)
            }
        })
    })
    for (const candidateUrl of absoluteUrlCandidates) {
        try {
            const parsed = new URL(candidateUrl)
            if (!normalizedHost || parsed.host === normalizedHost) {
                return parsed.origin
            }
        } catch (_) { }
    }
    if (/^https?:\/\//i.test(normalizedHost)) {
        try {
            return new URL(normalizedHost).origin
        } catch (_) { }
    }
    const scheme = defaultRequestSchemeForHost(normalizedHost)
    return `${scheme}://${normalizedHost || 'localhost'}`
}

function buildAbsoluteRequestUrl(target, rawScan = {}, host = '') {
    const normalizedTarget = String(target || '').trim()
    const origin = inferScanOrigin(rawScan, host)
    if (!normalizedTarget) {
        return new URL('/', origin).toString()
    }
    if (/^https?:\/\//i.test(normalizedTarget)) {
        try {
            return new URL(normalizedTarget).toString()
        } catch (_) {
            return normalizedTarget
        }
    }
    try {
        return new URL(normalizedTarget, origin).toString()
    } catch (_) {
        const path = normalizedTarget.startsWith('/') ? normalizedTarget : `/${normalizedTarget}`
        return `${origin}${path}`
    }
}

function structuredRequestToRaw(request, candidate, rawScan = {}) {
    const fallback = splitRouteKeyParts(candidate?.routeKey, rawScan?.host || null)
    const method = String(request?.method || fallback.method || 'GET').toUpperCase()
    let host = String(fallback.host || rawScan?.host || 'localhost:80')
    let requestTarget = buildAbsoluteRequestUrl(materializePathTemplate(fallback.pathTemplate || '/'), rawScan, host)
    const headers = []
    if (request?.url) {
        try {
            const parsed = new URL(String(request.url))
            host = parsed.host || host
            requestTarget = parsed.toString()
        } catch (_) {
            requestTarget = buildAbsoluteRequestUrl(request.url, rawScan, host)
        }
    } else if (request?.target) {
        requestTarget = buildAbsoluteRequestUrl(request.target, rawScan, host)
        try {
            host = new URL(requestTarget).host || host
        } catch (_) { }
    }
    if (Array.isArray(request?.headers)) {
        request.headers.forEach((header) => {
            const name = String(header?.name || '').trim()
            const value = String(header?.value || '').trim()
            if (!name || !value) return
            headers.push(`${name}: ${value}`)
        })
    } else if (request?.headers && typeof request.headers === 'object') {
        Object.keys(request.headers).forEach((name) => {
            const value = request.headers[name]
            if (value === undefined || value === null) return
            headers.push(`${name}: ${String(value)}`)
        })
    }
    if (!headers.some((line) => /^host\s*:/i.test(line))) {
        headers.unshift(`Host: ${host}`)
    }
    let body = ''
    if (typeof request?.body === 'string') {
        body = request.body
    } else if (typeof request?.postData === 'string') {
        body = request.postData
    } else if (request?.body && typeof request.body === 'object') {
        try {
            body = JSON.stringify(request.body)
        } catch (_) {
            body = String(request.body)
        }
    }
    if (!body && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        body = '{}'
    }
    if (body && !headers.some((line) => /^content-type\s*:/i.test(line))) {
        headers.push('Content-Type: application/json')
    }
    return `${method} ${requestTarget} HTTP/1.1\n${headers.join('\n')}\n\n${body}`
}

function buildFallbackCandidateRawRequest(candidate, rawScan = {}) {
    const fallback = splitRouteKeyParts(candidate?.routeKey, rawScan?.host || null)
    const method = fallback.method || 'GET'
    const path = materializePathTemplate(fallback.pathTemplate || '/')
    const host = fallback.host || String(rawScan?.host || 'localhost:80')
    const requestTarget = buildAbsoluteRequestUrl(path, rawScan, host)
    const headers = [
        `Host: ${host}`,
        'User-Agent: PentestKit-Analysis',
        'Accept: */*'
    ]
    let body = ''
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        headers.push('Content-Type: application/json')
        const param = String(candidate?.paramKey || '').replace(/^param:/, '').trim()
        if (param && !/^(host|origin|referer|referrer)$/i.test(param)) {
            body = JSON.stringify({ [param]: 'test' })
        } else {
            body = '{}'
        }
    }
    return `${method} ${requestTarget} HTTP/1.1\n${headers.join('\n')}\n\n${body}`
}

function pathTemplateToRegex(pathTemplate) {
    const raw = String(pathTemplate || '/')
    const escaped = raw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const withParams = escaped.replace(/:[A-Za-z0-9_]+/g, '[^/]+')
    return new RegExp(`^${withParams}/?$`, 'i')
}

function extractPathname(urlValue) {
    try {
        const parsed = new URL(String(urlValue || ''), 'http://localhost')
        return parsed.pathname || '/'
    } catch (_) {
        return '/'
    }
}

function findBestStructuredRequestForCandidate(candidate, rawScan = {}) {
    const requests = Array.isArray(rawScan?.requests) ? rawScan.requests : []
    if (!requests.length) return null
    const fallback = splitRouteKeyParts(candidate?.routeKey, rawScan?.host || null)
    const method = String(fallback.method || 'GET').toUpperCase()
    const template = String(fallback.pathTemplate || '/')
    const templateRe = pathTemplateToRegex(template)
    const paramName = String(candidate?.paramKey || '').replace(/^[^:]+:/, '').trim().toLowerCase()
    let best = null
    let bestScore = -1

    const scoreRequest = (request, sourceScore = 0) => {
        if (!request || typeof request !== 'object') return
        const reqMethod = String(request?.method || '').toUpperCase()
        const reqPath = extractPathname(request?.url || request?.target || '')
        let score = sourceScore
        if (reqMethod && reqMethod === method) score += 4
        if (templateRe.test(reqPath)) score += 6
        if (reqPath === materializePathTemplate(template)) score += 2
        if (paramName) {
            const bodyText = String(request?.body || request?.postData || '')
            const urlText = String(request?.url || '')
            const headerText = JSON.stringify(request?.headers || {})
            const haystack = `${bodyText}\n${urlText}\n${headerText}`.toLowerCase()
            if (haystack.includes(paramName)) score += 2
        }
        if (score > bestScore) {
            best = request
            bestScore = score
        }
    }

    requests.forEach((record) => {
        const original = record?.original?.request || null
        scoreRequest(original, 1)
        const attacks = Array.isArray(record?.attacks) ? record.attacks : []
        attacks.forEach((attack) => {
            scoreRequest(attack?.request || null, 2)
        })
    })

    return best
}

function showResultDialog(header, message, type = 'error', options = {}) {
    const $dialog = $('#result_dialog')
    $('#result_header').text(header || 'Info')
    $('#result_message').text(message || '')
    $dialog.find('.result_open_settings_btn').toggle(!!options?.showSettings)
    $dialog
        .removeClass('error success warning info')
        .addClass(type || 'error')
        .modal('show')
}

async function openCandidateInRBuilder(candidateId) {
    const key = String(candidateId || '')
    const candidate = ANALYSIS_CANDIDATE_INDEX.get(key)
    if (!candidate) {
        showResultDialog('Error', 'Candidate is not available anymore.')
        return
    }

    const refs = Array.isArray(candidate.evidenceRefs) ? candidate.evidenceRefs : []
    const requestRef = refs.find((ref) => String(ref?.type || '').toLowerCase() === 'request' && ref?.id)
    const attackRef = refs.find((ref) => String(ref?.type || '').toLowerCase() === 'attack' && ref?.id)
    let rawRequest = ''
    if (requestRef?.id) {
        try {
            const snapshot = await controller.getRequestSnapshot(requestRef.id, attackRef?.id || null)
            rawRequest = (typeof snapshot?.attack?.request?.raw === 'string' && snapshot.attack.request.raw.trim().length)
                ? snapshot.attack.request.raw
                : ''
            if (!rawRequest && typeof snapshot?.original?.request?.raw === 'string' && snapshot.original.request.raw.trim().length) {
                rawRequest = snapshot.original.request.raw
            }
            if (!rawRequest) {
                const structured = snapshot?.attack?.request || snapshot?.original?.request || null
                if (structured && typeof structured === 'object') {
                    rawRequest = structuredRequestToRaw(structured, candidate, latestDastRawScan || {})
                }
            }
        } catch (_) {
            // fallback request builder payload below
        }
    }
    if (!rawRequest) {
        const matchedStructured = findBestStructuredRequestForCandidate(candidate, latestDastRawScan || {})
        if (matchedStructured) {
            rawRequest = structuredRequestToRaw(matchedStructured, candidate, latestDastRawScan || {})
        } else {
            rawRequest = buildFallbackCandidateRawRequest(candidate, latestDastRawScan || {})
        }
    }
    window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(rawRequest)))
}

async function openEvidenceRequestInRBuilder(requestId, candidateId) {
    const requestKey = String(requestId || '')
    if (!requestKey) {
        showResultDialog('Error', 'Request is not available anymore.')
        return
    }
    const candidate = ANALYSIS_CANDIDATE_INDEX.get(String(candidateId || '')) || null
    const requestModel = findRequestModel(requestKey)
    let rawRequest = ''
    let structured = requestModel?.original?.request || null

    if (typeof requestModel?.original?.request?.raw === 'string' && requestModel.original.request.raw.trim().length) {
        rawRequest = requestModel.original.request.raw
    }

    if (!rawRequest) {
        try {
            const snapshot = await controller.getRequestSnapshot(requestKey)
            if (snapshot?.original) {
                if (requestModel) {
                    requestModel.original = snapshot.original
                }
                if (typeof snapshot.original?.request?.raw === 'string' && snapshot.original.request.raw.trim().length) {
                    rawRequest = snapshot.original.request.raw
                }
                if (!structured && snapshot.original?.request && typeof snapshot.original.request === 'object') {
                    structured = snapshot.original.request
                }
            }
        } catch (_) {
            // fall through to local structured or candidate fallback
        }
    }

    if (!rawRequest && structured && typeof structured === 'object' && candidate) {
        rawRequest = structuredRequestToRaw(structured, candidate, latestDastRawScan || {})
    }

    if (!rawRequest && candidate) {
        const matchedStructured = findBestStructuredRequestForCandidate(candidate, latestDastRawScan || {})
        if (matchedStructured) {
            rawRequest = structuredRequestToRaw(matchedStructured, candidate, latestDastRawScan || {})
        } else {
            rawRequest = buildFallbackCandidateRawRequest(candidate, latestDastRawScan || {})
        }
    }

    if (!rawRequest) {
        showResultDialog('Error', 'Could not prepare request for R-Builder.')
        return
    }

    window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(rawRequest)))
}

async function openEvidenceAttackInRBuilder(attackId, candidateId) {
    const attackKey = String(attackId || '')
    if (!attackKey) {
        showResultDialog('Error', 'Attack is not available anymore.')
        return
    }
    const candidate = ANALYSIS_CANDIDATE_INDEX.get(String(candidateId || '')) || null
    const { requestModel, attack } = findAttackRefModel(attackKey)
    const requestId = requestModel?.id != null ? String(requestModel.id) : ''
    let rawRequest = ''
    let structured = attack?.request || requestModel?.original?.request || null

    if (typeof attack?.request?.raw === 'string' && attack.request.raw.trim().length) {
        rawRequest = attack.request.raw
    } else if (typeof requestModel?.original?.request?.raw === 'string' && requestModel.original.request.raw.trim().length) {
        rawRequest = requestModel.original.request.raw
    }

    if (!rawRequest && requestId) {
        try {
            const snapshot = await controller.getRequestSnapshot(requestId, attackKey)
            if (snapshot?.original && requestModel) {
                requestModel.original = snapshot.original
            }
            if (typeof snapshot?.attack?.request?.raw === 'string' && snapshot.attack.request.raw.trim().length) {
                rawRequest = snapshot.attack.request.raw
            } else if (typeof snapshot?.original?.request?.raw === 'string' && snapshot.original.request.raw.trim().length) {
                rawRequest = snapshot.original.request.raw
            }
            if (!structured) {
                structured = snapshot?.attack?.request || snapshot?.original?.request || null
            }
        } catch (_) {
            // fall through to structured/local fallback
        }
    }

    if (!rawRequest && structured && typeof structured === 'object' && candidate) {
        rawRequest = structuredRequestToRaw(structured, candidate, latestDastRawScan || {})
    }

    if (!rawRequest && candidate) {
        const matchedStructured = findBestStructuredRequestForCandidate(candidate, latestDastRawScan || {})
        if (matchedStructured) {
            rawRequest = structuredRequestToRaw(matchedStructured, candidate, latestDastRawScan || {})
        } else {
            rawRequest = buildFallbackCandidateRawRequest(candidate, latestDastRawScan || {})
        }
    }

    if (!rawRequest) {
        showResultDialog('Error', 'Could not prepare attack request for R-Builder.')
        return
    }

    window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(rawRequest)))
}

async function openEvidenceGenericInRBuilder(ref, candidateId) {
    const candidate = ANALYSIS_CANDIDATE_INDEX.get(String(candidateId || '')) || null
    if (!candidate) {
        showResultDialog('Error', 'Evidence is not available anymore.')
        return
    }
    if (inferEvidenceRefEngine(ref, candidate) !== 'DAST') {
        showResultDialog('R-Builder', 'Only DAST-backed evidence can be sent to R-Builder.')
        return
    }
    const routeKey = String(ref?.loc?.route || candidate?.routeKey || '').trim()
    const method = String(ref?.loc?.method || '').trim().toUpperCase()
    const param = String(ref?.loc?.param || '').trim()
    const materializedCandidate = {
        ...candidate,
        ...(routeKey ? { routeKey } : {}),
        ...(method && !routeKey ? { routeKey: buildRouteKeyFromEvidence(candidate?.routeKey, method) } : {}),
        ...(param ? { paramKey: `param:${param}` } : {})
    }
    let rawRequest = ''
    const matchedStructured = findBestStructuredRequestForCandidate(materializedCandidate, latestDastRawScan || {})
    if (matchedStructured) {
        rawRequest = structuredRequestToRaw(matchedStructured, materializedCandidate, latestDastRawScan || {})
    } else {
        rawRequest = buildFallbackCandidateRawRequest(materializedCandidate, latestDastRawScan || {})
    }
    if (!rawRequest) {
        showResultDialog('Error', 'Could not prepare request for R-Builder.')
        return
    }
    window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(rawRequest)))
}

function buildRouteKeyFromEvidence(candidateRouteKey, method) {
    const parts = splitRouteKeyParts(candidateRouteKey, latestDastRawScan?.host || null)
    return `${parts.host}|${method || parts.method || 'GET'}|${parts.pathTemplate || '/'}`
}

function resolveDastFindingContext(findingId) {
    const key = String(findingId || '').trim()
    if (!key) return null
    const lookup = controller._dastFindingLookup || buildFindingLookup(controller?.scanViewModel?.findings || [])
    controller._dastFindingLookup = lookup
    const finding = lookup.get(key) || null
    const requests = getViewModelRequests()
    for (let idx = 0; idx < requests.length; idx += 1) {
        const requestModel = requests[idx]
        const attacks = Array.isArray(requestModel?.attacks) ? requestModel.attacks : []
        for (let attackIdx = 0; attackIdx < attacks.length; attackIdx += 1) {
            const attack = attacks[attackIdx]
            if (String(attack?.findingId || '') !== key) continue
            return {
                findingId: key,
                requestId: requestModel?.id || null,
                attackId: attack?.id || null,
                moduleId: attack?.moduleId || attack?.metadata?.moduleId || attack?.metadata?.id || finding?.moduleId || null
            }
        }
    }
    return {
        findingId: key,
        requestId: null,
        attackId: null,
        moduleId: finding?.moduleId || null
    }
}

async function openEvidenceFindingDetails(findingId) {
    const key = String(findingId || '').trim()
    if (!key) {
        showResultDialog('Error', 'Finding is not available anymore.')
        return
    }
    try {
        const context = resolveDastFindingContext(key)
        const details = await controller.getFindingDetails({
            findingId: key,
            requestId: context?.requestId || null,
            attackId: context?.attackId || null,
            moduleId: context?.moduleId || null
        })
        if (!details || (!details.finding && !details.findingDetail && !details.attack)) {
            showResultDialog('Error', 'Finding details are not available anymore.')
            return
        }
        rutils.showEvidenceFindingDetails(details)
    } catch (err) {
        showResultDialog('Error', err?.message || 'Finding details could not be loaded.')
    }
}

function renderAnalysisAndCoverage(vm, rawScan = {}) {
    const analysis = vm?.analysis || rawScan?.analysis || null
    const $analysis = $('#analysis_info')
    ANALYSIS_CANDIDATE_INDEX.clear()
    if (!analysis || typeof analysis !== 'object') {
        $analysis.html(buildEmptyAnalysisStateHtml())
        return
    }

    const compareCandidatesForDisplay = (a = {}, b = {}) => {
        const scoreDelta = Number(b?.score || 0) - Number(a?.score || 0)
        if (scoreDelta !== 0) return scoreDelta
        const confidenceDelta = Number(b?.confidenceRank || 0) - Number(a?.confidenceRank || 0)
        if (confidenceDelta !== 0) return confidenceDelta
        const titleCmp = String(a?.title || '').localeCompare(String(b?.title || ''))
        if (titleCmp !== 0) return titleCmp
        const routeCmp = String(a?.routeKey || '').localeCompare(String(b?.routeKey || ''))
        if (routeCmp !== 0) return routeCmp
        const paramCmp = String(a?.paramKey || '').localeCompare(String(b?.paramKey || ''))
        if (paramCmp !== 0) return paramCmp
        const ruleCmp = String(a?.createdByRule || '').localeCompare(String(b?.createdByRule || ''))
        if (ruleCmp !== 0) return ruleCmp
        return String(a?.id || '').localeCompare(String(b?.id || ''))
    }
    const candidates = (Array.isArray(analysis.candidates) ? analysis.candidates : []).slice().sort(compareCandidatesForDisplay)
    candidates.forEach((candidate) => {
        const id = String(candidate?.id || '').trim()
        if (!id) return
        ANALYSIS_CANDIDATE_INDEX.set(id, candidate)
    })
    const visibleCandidates = candidates.slice()
    const filteredCandidates = visibleCandidates.filter((candidate) => candidateMatchesAnalysisFilters(candidate))
    const candidateLimit = Math.max(ANALYSIS_CANDIDATE_PAGE_SIZE, Number(ANALYSIS_FILTER_STATE.candidateLimit || ANALYSIS_CANDIDATE_PAGE_SIZE))
    const topCandidates = filteredCandidates.slice(0, candidateLimit)
    const hiddenCandidateCount = Math.max(0, filteredCandidates.length - topCandidates.length)
    prefetchReadinessForCandidates(topCandidates)
    const candidateHtml = topCandidates.length
        ? topCandidates.map((candidate, index) => {
            const score = Number(candidate?.score || 0)
            const confidence = String(candidate?.confidence || 'low').toLowerCase()
            const confidenceColor = formatAnalysisConfidence(confidence)
            const confidenceBadge = buildAnalysisConfidenceBadge(confidence)
            const readiness = getCandidateActionReadiness(candidate)
            const sendReadiness = normalizeReadinessLevel(readiness?.sendToRBuilder || 'ready')
            const readinessReasons = Array.isArray(readiness?.reasons) ? readiness.reasons : []
            const readinessReasonText = readinessReasons.length
                ? readinessReasons.map((code) => mapReadinessReasonMessage(code)).join(' | ')
                : ''
            const sendDisabled = sendReadiness === 'blocked' ? 'disabled' : ''
            const sendTooltip = readinessReasonText ? `title="${escapeAttr(readinessReasonText)}"` : ''
            const runReadiness = normalizeReadinessLevel(readiness?.runInPlaywright || 'ready')
            const runDisabled = runReadiness === 'blocked' ? 'disabled' : ''
            const runTooltip = readinessReasonText ? `title="${escapeAttr(readinessReasonText)}"` : ''
            const routeKey = escapeHtml(candidate?.routeKey || '-')
            const paramKey = escapeHtml(candidate?.paramKey || '-')
            const candidateId = String(candidate?.id || '')
            const drawerId = `analysis_evidence_${toDomSafeId(candidateId)}`
            const runStatusHtml = buildCandidatePlaywrightRunHtml(candidate)
            const playwrightButtonHtml = PLAYWRIGHT_FEATURES_VISIBLE
                ? `
                            <button type="button" class="ui tiny button run_candidate_playwright" data-candidate-id="${escapeAttr(candidateId)}" ${runDisabled} ${runTooltip}>
                                Run In Playwright
                            </button>
                `
                : ''
            return `
                <div class="ui message attack_info nonvuln">
                    <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:8px; margin-bottom:6px;">
                        <div><b>${index + 1}. ${escapeHtml(candidate?.title || 'Manual candidate')}</b></div>
                        <span style="margin-left:auto; white-space:nowrap; display:inline-flex; align-items:center; gap:6px;">${confidenceBadge}<span class="ui tiny ${confidenceColor} label" style="white-space:nowrap;">Score ${score}</span></span>
                    </div>
                    <div class="description">
                        <div><b>Route:</b> <code>${routeKey}</code></div>
                        <div><b>Param:</b> <code>${paramKey}</code></div>
                        <div style="margin-top:6px;"><b>Why:</b> ${buildCandidateWhyHtml(candidate)}</div>
                        <div style="margin-top:6px;">${buildManualStepsToggleHtml(candidate)}</div>
                        <div style="margin-top:8px;">
                            <button type="button" class="ui tiny button toggle_candidate_evidence" data-evidence-target="${escapeAttr(drawerId)}">
                                Show Evidence
                            </button>
                            ${playwrightButtonHtml}
                            ${AUTHZ_DIFF_FEATURES_VISIBLE ? `
                            <button type="button" class="ui tiny button open_candidate_authz_diff" data-candidate-id="${escapeAttr(candidateId)}">
                                Authz Diff
                            </button>
                            ` : ''}
                            <button type="button" class="ui tiny button open_candidate_rbuilder" data-candidate-id="${escapeAttr(candidateId)}" ${sendDisabled} ${sendTooltip}>
                                Send To R-Builder
                            </button>
                        </div>
                        ${runStatusHtml}
                        <div id="${escapeAttr(drawerId)}" class="ui tiny message" style="display:none; margin-top:8px; padding:8px;">
                            ${buildEvidenceDrawerHtml(candidate)}
                        </div>
                    </div>
                </div>
            `
        }).join('')
        : `
            <div class="ui info message">
                <div class="header">No manual candidates</div>
                <p>No suspicious clusters were strong enough for candidate cards.</p>
            </div>
        `

    const showMoreHtml = hiddenCandidateCount > 0
        ? `
            <div style="margin-top:10px;">
                <button type="button" id="analysis_show_more_candidates" class="ui tiny primary button">
                    Show more (${Math.min(ANALYSIS_CANDIDATE_PAGE_SIZE, hiddenCandidateCount)} more)
                </button>
            </div>
        `
        : ''

    $analysis.html(`
        ${buildAnalysisStatusHtml(analysis)}
        <div class="ui message">
            <div><b>Candidates:</b> ${topCandidates.length} of ${visibleCandidates.length} visible (${candidates.length} total${hiddenCandidateCount > 0 ? `, showing first ${topCandidates.length}` : ', showing all'})</div>
            ${analysis?.diff && typeof analysis.diff === 'object'
                ? `<div><b>Diff:</b> +${Number(analysis.diff.addedCount || 0)} / ~${Number(analysis.diff.changedCount || 0)} / =${Number(analysis.diff.unchangedCount || 0)} / -${Number(analysis.diff.removedCount || 0)}</div>`
                : ''}
        </div>
        ${candidateHtml}
        ${showMoreHtml}
    `)
}

function ensureAnalysisPanelsRendered({ force = false } = {}) {
    if (!scanAnalysisUiEnabled) return
    if (!force && !analysisPanelsDirty) return
    const raw = latestDastRawScan || controller?.scanResult?.scanResult || null
    if (!raw) return
    const vm = controller.scanViewModel || normalizeScanResult(raw)
    renderAnalysisAndCoverage(vm, raw)
    analysisPanelsDirty = false
}

function setDastResultView(view) {
    const normalizedView = String(view || '').trim().toLowerCase() === 'coverage' ? 'analysis' : view
    const requestedView = DAST_RESULT_VIEWS.has(normalizedView) ? normalizedView : 'findings'
    const nextView = (!scanAnalysisUiEnabled && requestedView !== 'findings') ? 'findings' : requestedView
    dastResultView = nextView
    $('#dast_result_tabs .item').removeClass('active')
    $(`#dast_result_tabs .item[data-view="${nextView}"]`).addClass('active')
    $('#dast_findings_filters')
        .css('visibility', 'visible')
        .css('pointer-events', 'auto')
    $('#attacks_info').toggle(nextView === 'findings')
    $('#analysis_info').toggle(nextView === 'analysis')
    if (nextView === 'analysis') {
        ensureAnalysisPanelsRendered()
    }
    if (nextView === 'analysis' && !$('#analysis_info').children().length) {
        $('#analysis_info').html(buildEmptyAnalysisStateHtml())
    }
    if (nextView === 'findings') {
        renderStatsFromCounters()
    }
    updateDastScopeFilterButtons()
}

function updateDastScopeFilterButtons() {
    const $buttons = $('#filter_vuln, #filter_all, #filter_400, #filter_500')
    $buttons.removeClass('active primary')
    if (dastResultView !== 'findings') {
        return
    }
    $('#filter_' + attackFilterState.scope).addClass('active primary')
}

function rerenderAnalysisPanels() {
    if (!scanAnalysisUiEnabled) return
    analysisPanelsDirty = true
    if (dastResultView === 'findings') return
    ensureAnalysisPanelsRendered({ force: true })
    if (dastResultView !== 'findings') {
        setDastResultView(dastResultView)
    }
}

function createSeverityCounters() {
    return {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    }
}

function createEmptyCounters() {
    return {
        total: 0,
        vuln: 0,
        nonvuln: 0,
        s4xx: 0,
        s5xx: 0,
        vuln4xx: 0,
        vuln5xx: 0,
        severity: createSeverityCounters(),
        severity4xx: createSeverityCounters(),
        severity5xx: createSeverityCounters()
    }
}

function resetDastCounters() {
    const empty = createEmptyCounters()
    Object.keys(empty).forEach((key) => {
        if (typeof empty[key] === 'object') {
            Object.assign(DAST_COUNTERS[key], empty[key])
        } else {
            DAST_COUNTERS[key] = empty[key]
        }
    })
    DAST_REQUEST_COUNTERS.clear()
}

function normalizeSeverityKey(value) {
    if (!value) return 'info'
    let normalized = String(value || '').toLowerCase()
    if (normalized === 'informational') {
        normalized = 'info'
    }
    return Object.prototype.hasOwnProperty.call(DAST_COUNTERS.severity, normalized)
        ? normalized
        : 'info'
}

function normalizeObservationRoutePath(urlValue = '') {
    const fallback = String(urlValue || '')
        .replace(/[?#].*$/, '')
        .trim()
        .toLowerCase() || '/'
    try {
        const parsed = new URL(String(urlValue || ''), 'http://localhost')
        return String(parsed.pathname || '/').trim().toLowerCase() || '/'
    } catch (_) {
        return fallback
    }
}

const RECON_AGGREGATE_MODES = new Set(['scan', 'route'])

function getAttackPresentationAggregate(attack = null) {
    const outputKind = String(attack?.outputKind || attack?.finding?.outputKind || attack?.metadata?.outputKind || '').toLowerCase()
    if (outputKind !== 'recon') return 'none'
    const mode = String(
        attack?.presentationAggregate
        || attack?.finding?.presentationAggregate
        || attack?.metadata?.presentationAggregate
        || attack?.metadata?.extensions?.ptk?.presentation?.aggregate
        || attack?.finding?.metadata?.extensions?.ptk?.presentation?.aggregate
        || attack?.finding?.extensions?.ptk?.presentation?.aggregate
        || ''
    ).trim().toLowerCase()
    return RECON_AGGREGATE_MODES.has(mode) ? mode : 'none'
}

function buildReconRenderDedupeKey(attack = null, original = null) {
    const outputKind = String(attack?.outputKind || attack?.finding?.outputKind || attack?.metadata?.outputKind || '').toLowerCase()
    if (outputKind !== 'recon') return null
    const request = attack?.request || original?.request || original || {}
    const path = normalizeObservationRoutePath(request?.url || request?.ui_url || request?.target || '')
    const method = String(request?.method || '').trim().toUpperCase() || 'GET'
    const ruleId = String(attack?.ruleId || attack?.finding?.ruleId || '').trim().toLowerCase()
    const param = String(
        attack?.param
        || attack?.metadata?.param
        || attack?.metadata?.attacked?.name
        || attack?.finding?.location?.param
        || ''
    ).trim().toLowerCase()
    const aggregateMode = getAttackPresentationAggregate(attack)
    if (aggregateMode === 'scan') {
        return [
            String(attack?.moduleId || attack?.finding?.moduleId || ''),
            ruleId
        ].join('|')
    }
    if (aggregateMode === 'route') {
        return [
            String(attack?.moduleId || attack?.finding?.moduleId || ''),
            ruleId,
            method,
            path
        ].join('|')
    }
    return [
        String(attack?.moduleId || attack?.finding?.moduleId || ''),
        ruleId,
        method,
        path,
        param
    ].join('|')
}

function isAggregatedReconRule(attack = null) {
    return getAttackPresentationAggregate(attack) !== 'none'
}

function shouldRenderAttackCard(attack = null, original = null) {
    const dedupeKey = buildReconRenderDedupeKey(attack, original)
    if (!dedupeKey) {
        return true
    }
    if (DAST_RENDER.renderedReconKeys.has(dedupeKey)) {
        return false
    }
    DAST_RENDER.renderedReconKeys.add(dedupeKey)
    return true
}

function getAttackBucket(meta) {
    if (!meta?.isVuln) {
        return 'nonvuln'
    }
    return normalizeSeverityKey(meta.severity)
}

function buildBucketContainerHtml() {
    return DAST_BUCKET_ORDER
        .map((bucket) => `<div class="dast_bucket" data-bucket="${bucket}"></div>`)
        .join('')
}

function ensureAttackBuckets() {
    const $container = $("#attacks_info")
    if ($container.find('.dast_bucket').length) {
        return
    }
    $container.html(buildBucketContainerHtml())
}

function appendAttackToBucket(attackHtml, meta) {
    if (!attackHtml) return
    ensureAttackBuckets()
    const bucket = getAttackBucket(meta)
    const selector = `.dast_bucket[data-bucket="${bucket}"]`
    const $bucket = $("#attacks_info").find(selector)
    $bucket.addClass('has-items')
    $bucket.append(attackHtml)
}

function normalizeRequestId(value) {
    if (value === null || value === undefined || value === '') {
        return UNKNOWN_REQ
    }
    return String(value)
}

function getRequestCounters(requestId) {
    const key = normalizeRequestId(requestId)
    if (!DAST_REQUEST_COUNTERS.has(key)) {
        DAST_REQUEST_COUNTERS.set(key, createEmptyCounters())
    }
    return DAST_REQUEST_COUNTERS.get(key)
}

function applyCountersUpdate(target, meta) {
    if (!target || !meta) return
    target.total += 1
    if (meta.is4xx) {
        target.s4xx += 1
    }
    if (meta.is5xx) {
        target.s5xx += 1
    }
    if (meta.countsAsFinding ?? meta.isVuln) {
        target.vuln += 1
        const severityKey = normalizeSeverityKey(meta.severity)
        target.severity[severityKey] += 1
        if (meta.is4xx) {
            target.vuln4xx += 1
            target.severity4xx[severityKey] += 1
        } else if (meta.is5xx) {
            target.vuln5xx += 1
            target.severity5xx[severityKey] += 1
        }
    } else {
        target.nonvuln += 1
    }
}

function updateDastCountersFromMeta(meta, requestId) {
    // Counters are O(1) per insert to keep stats fast without DOM scans.
    applyCountersUpdate(DAST_COUNTERS, meta)
    applyCountersUpdate(getRequestCounters(requestId), meta)
}

function getBaseCounters() {
    if (attackFilterState.requestId) {
        return DAST_REQUEST_COUNTERS.get(normalizeRequestId(attackFilterState.requestId)) || createEmptyCounters()
    }
    return DAST_COUNTERS
}

function renderStatsFromCounters() {
    const base = getBaseCounters()
    let attacksCount = base.total
    let findingsCount = base.vuln
    let severity = base.severity
    const useTotalForRequest = !!attackFilterState.requestId
    if (attackFilterState.scope === 'vuln') {
        attacksCount = base.total
        findingsCount = base.vuln
        severity = base.severity
    } else if (attackFilterState.scope === '400') {
        attacksCount = base.s4xx
        findingsCount = base.vuln4xx
        severity = base.severity4xx
    } else if (attackFilterState.scope === '500') {
        attacksCount = base.s5xx
        findingsCount = base.vuln5xx
        severity = base.severity5xx
    }
    rutils.bindStats({
        attacksCount,
        findingsCount,
        critical: severity.critical,
        high: severity.high,
        medium: severity.medium,
        low: severity.low,
        info: severity.info
    }, 'dast')
}

function escAttrValue(value) {
    return String(value)
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"')
        .replace(/[\n\r\t\f\v]/g, " ")
}

function getRequestFilterStyleEl() {
    let styleEl = document.getElementById('ptkRequestFilterStyle')
    if (!styleEl) {
        styleEl = document.createElement('style')
        styleEl.id = 'ptkRequestFilterStyle'
        document.head.appendChild(styleEl)
    }
    return styleEl
}

function updateRequestFilterStyle(requestId) {
    const styleEl = getRequestFilterStyleEl()
    if (!requestId) {
        styleEl.textContent = ''
        return
    }
    // CSS-only request filtering avoids O(N) hide/show on large lists.
    const raw = String(requestId)
    const escaped = (window.CSS && typeof CSS.escape === 'function') ? CSS.escape(raw) : escAttrValue(raw)
    styleEl.textContent = `#attacks_info[data-request="${escaped}"] .attack_info[data-request-id="${escaped}"] { display:block; }`
}

function isAttackVisibleForCurrentFilters($attack) {
    if (!$attack || !$attack.length) return false
    const requestId = attackFilterState.requestId
    if (requestId && String($attack.attr('data-request-id') || '') !== String(requestId)) {
        return false
    }
    if (attackFilterState.scope === 'vuln') {
        return !$attack.hasClass('nonvuln')
    }
    if (attackFilterState.scope === '400') {
        return $attack.hasClass('4xx_status')
    }
    if (attackFilterState.scope === '500') {
        return $attack.hasClass('5xx_status')
    }
    return true
}

function updateDastBucketVisibility() {
    const $buckets = $("#attacks_info .dast_bucket")
    if (!$buckets.length) return
    $buckets.each(function () {
        const $bucket = $(this)
        const $attacks = $bucket.find('.attack_info')
        let visibleCount = 0
        $attacks.each(function () {
            const visible = isAttackVisibleForCurrentFilters($(this))
            $(this).toggleClass('dast-filter-visible', visible)
            if (visible) {
                visibleCount += 1
            }
        })
        const hasVisibleItems = visibleCount > 0
        $bucket.toggleClass('has-visible-items', hasVisibleItems)
        $bucket.toggle(hasVisibleItems)
    })
}

function getPreferredAttackScopeFromCounters() {
    return DAST_COUNTERS.vuln > 0 ? 'vuln' : 'all'
}

function applyDefaultAttackScope(options = {}) {
    const preserveManual = options.preserveManual !== false
    if (preserveManual && dastScopeTouchedByUser) {
        return
    }
    attackFilterState.scope = getPreferredAttackScopeFromCounters()
    $("#attacks_info").attr("data-scope", attackFilterState.scope)
    updateDastScopeFilterButtons()
}

function getGroupedReconObservationKey(attack = null, original = null) {
    const mode = getAttackPresentationAggregate(attack)
    const request = attack?.request || original?.request || original || {}
    const method = String(request?.method || '').trim().toUpperCase() || 'GET'
    const path = normalizeObservationRoutePath(request?.url || request?.ui_url || request?.target || '')
    const ruleId = String(attack?.ruleId || attack?.finding?.ruleId || '').trim().toLowerCase()
    if (mode === 'route') {
        return [ruleId, method, path].join('|')
    }
    return ruleId
}

function ensureGroupedReconObservation(map, attack, original, requestId) {
    const key = getGroupedReconObservationKey(attack, original)
    if (!key) return null
    if (!map.has(key)) {
        const request = attack?.request || original?.request || original || {}
        map.set(key, {
            key,
            aggregateMode: getAttackPresentationAggregate(attack),
            requestId: requestId || null,
            sampleAttack: attack,
            sampleRequest: request,
            routes: new Map(),
            rawCount: 0
        })
    }
    return map.get(key)
}

function collectGroupedReconObservation(map, attack, original, requestId) {
    const entry = ensureGroupedReconObservation(map, attack, original, requestId)
    if (!entry) return
    const request = attack?.request || original?.request || original || {}
    const method = String(request?.method || '').trim().toUpperCase() || 'GET'
    const path = normalizeObservationRoutePath(request?.url || request?.ui_url || request?.target || '')
    const routeKey = `${method} ${path}`
    if (!entry.routes.has(routeKey)) {
        entry.routes.set(routeKey, {
            method,
            path,
            url: String(request?.url || request?.ui_url || request?.target || '')
        })
    }
    entry.rawCount += 1
}

function renderGroupedReconRoutes(entry) {
    const routes = [...(entry?.routes?.values?.() || [])]
    if (!routes.length) return ''
    if (entry?.aggregateMode === 'route') {
        const route = routes[0]
        const label = `${route.method} ${route.path}`
        return `
            <div class="description">
                <p>Affected route: <b>${ptk_utils.escapeHtml(label)}</b></p>
                <p>Matched requests: <b>${entry.rawCount}</b></p>
            </div>
        `
    }
    const previewRoutes = routes.slice(0, 6)
    const remainingRoutes = routes.slice(6)
    const renderRouteItem = (route) => {
        const label = `${route.method} ${route.path}`
        if (route.url) {
            return `<li><a href="${ptk_utils.escapeHtml(route.url)}" target="_blank">${ptk_utils.escapeHtml(label)}</a></li>`
        }
        return `<li>${ptk_utils.escapeHtml(label)}</li>`
    }
    const preview = previewRoutes.map(renderRouteItem).join('')
    const remaining = remainingRoutes.length
    const allRoutes = remainingRoutes.map(renderRouteItem).join('')
    const toggleKey = ptk_utils.escapeHtml(String(entry?.key || ''))
    return `
        <div class="description">
            <p>Affected routes: <b>${routes.length}</b>${entry.rawCount > routes.length ? `</p><p>Matched requests: <b>${entry.rawCount}</b>` : ''}</p>
            <ul style="margin: 6px 0 0 16px;">${preview}</ul>
            ${remaining > 0 ? `
                <div class="grouped_recon_routes_all" data-grouped-routes-key="${toggleKey}" style="display:none;">
                    <ul style="margin: 6px 0 0 16px;">${allRoutes}</ul>
                </div>
                <p style="margin-top:6px;">
                    <a href="#" class="toggle_grouped_recon_routes" data-grouped-routes-key="${toggleKey}" data-expanded="0">Show all routes</a>
                </p>
            ` : ''}
        </div>
    `
}

function buildGroupedReconDetailsPayload(entry, resolvedAttack = null) {
    if (!entry?.sampleAttack && !resolvedAttack) return null
    const sampleAttack = enrichAttackFromCatalog(Object.assign({}, resolvedAttack || entry.sampleAttack))
    const sampleFinding = sampleAttack.finding && typeof sampleAttack.finding === 'object'
        ? Object.assign({}, sampleAttack.finding)
        : {}
    const baseDescription = sampleFinding.description
        || sampleAttack.description
        || sampleAttack.metadata?.description
        || sampleAttack.metadata?.docs?.description
        || ''
    const attack = Object.assign({}, sampleAttack, {
        description: baseDescription,
        recommendation: sampleFinding.recommendation || sampleAttack.recommendation || sampleAttack.metadata?.recommendation || sampleAttack.metadata?.docs?.recommendation || '',
        links: sampleFinding.links || sampleAttack.links || sampleAttack.metadata?.links || sampleAttack.metadata?.docs?.links || {},
        finding: Object.assign({}, sampleFinding, {
            description: baseDescription,
            recommendation: sampleFinding.recommendation || sampleAttack.recommendation || sampleAttack.metadata?.recommendation || sampleAttack.metadata?.docs?.recommendation || '',
            links: sampleFinding.links || sampleAttack.links || sampleAttack.metadata?.links || sampleAttack.metadata?.docs?.links || {}
        })
    })
    const original = {
        request: entry.sampleRequest || sampleAttack.request || null,
        response: sampleAttack.response || null
    }
    return { attack, original }
}

function buildGroupedReconCardHtml(entry) {
    if (!entry?.sampleAttack) return null
    const meta = rutils.getMiscMeta(entry.sampleAttack)
    const severityAttr = meta.severity || ''
    const safeRequestId = entry.requestId === null || entry.requestId === undefined || entry.requestId === ''
        ? '__ptk_grouped_recon__'
        : String(entry.requestId)
    const keyAttr = ptk_utils.escapeHtml(entry.key)
    const targetUrl = entry.sampleRequest?.url
        || entry.sampleRequest?.ui_url
        || entry.sampleRequest?.target
        || ''
    const safeTarget = ptk_utils.escapeHtml(targetUrl)
    const routesHtml = renderGroupedReconRoutes(entry)
    const groupedLabel = entry?.aggregateMode === 'route' ? 'grouped by route' : 'grouped by scan'
    const titleHtml = `${meta.icon} <span class="ui mini basic label">${ptk_utils.escapeHtml(groupedLabel)}</span>`
    const html = `
        <div class="ui message attack_info grouped_recon_card ${meta.attackClass} ${ptk_utils.escapeHtml(safeRequestId)}"
            data-order="${meta.order}"
            data-severity="${ptk_utils.escapeHtml(severityAttr)}"
            data-request-id="${ptk_utils.escapeHtml(safeRequestId)}"
            data-grouped-recon-key="${keyAttr}">
            <div class="ptk-finding-header">
                <div class="ptk-finding-header-main">${titleHtml}</div>
            </div>
            <div class="description">
                <p>Grouped posture observation to reduce repeated low-signal route cards.</p>
            </div>
            ${targetUrl ? `<div class="description"><p>Sample URL: <a href="${safeTarget}" target="_blank">${safeTarget}</a></p></div>` : ''}
            ${routesHtml}
            <div class="ui left floated">
                <a href="#" class="attack_details" data-grouped-recon-key="${keyAttr}">Details</a>
            </div>
        </div>
    `
    return { html, meta }
}

function renderGroupedReconObservationCards(map) {
    return [...(map?.values?.() || [])]
        .map(buildGroupedReconCardHtml)
        .filter(Boolean)
}



jQuery(function () {

    const $runCveInput = $('#ptk_dast_run_cve')
    const $runCveCheckboxWrapper = $runCveInput.closest('.ui.checkbox')
    let runCveState = false

    function setRunCveState(enabled, { updateUi = true } = {}) {
        runCveState = !!enabled
        if (!updateUi) {
            return
        }
        if ($runCveCheckboxWrapper.length && typeof $runCveCheckboxWrapper.checkbox === 'function') {
            const action = runCveState ? 'set checked' : 'set unchecked'
            $runCveCheckboxWrapper.checkbox(action)
        } else if ($runCveInput.length) {
            $runCveInput.prop('checked', runCveState)
        }
    }

    function isRunCveEnabled() {
        return !!runCveState
    }

    if ($runCveCheckboxWrapper.length && typeof $runCveCheckboxWrapper.checkbox === 'function') {
        $runCveCheckboxWrapper.checkbox({
            onChecked() {
                setRunCveState(true, { updateUi: false })
            },
            onUnchecked() {
                setRunCveState(false, { updateUi: false })
            }
        })
    } else if ($runCveInput.length) {
        $runCveInput.on('change', function () {
            setRunCveState($(this).is(':checked'), { updateUi: false })
        })
    }

    setRunCveState(false)
    setDastResultView('findings')

    // initialize all modals
    $('.modal.coupled')
        .modal({
            allowMultiple: true
        })

    const $saveScanModal = $('#save_scan_modal')
    let $saveScanProjectDropdown = $('#save_scan_project_select')
    const $saveScanModalError = $('#save_scan_modal_error')
    const saveScanProjectMap = new Map()
    const $downloadScansModal = $('#download_scans')
    let $downloadProjectDropdown = $('#download_project_select')
    const downloadProjectMap = new Map()

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

    function populateProjectDropdown($dropdown, projectMap, projectOptions, placeholderText) {
        let $target = resetSemanticDropdown($dropdown)
        projectMap.clear()
        if (!$target) return $dropdown
        $target.empty()
        const placeholder = document.createElement('option')
        placeholder.value = ''
        placeholder.textContent = placeholderText || 'Select a project'
        $target.append(placeholder)
        projectOptions.forEach(opt => {
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

    function showResultModal(header, message) {
        $('#result_header').text(header)
        $('#result_message').text(message || '')
        $('#result_dialog').modal('show')
    }

    function handleSaveScanResponse(result) {
        if (result instanceof Error) {
            showResultModal("Error", result.message || "Unable to save scan")
            return
        }
        if (result?.success) {
            showResultModal("Success", "Scan saved")
        } else {
            const message = result?.json?.message || result?.message || "Unable to save scan"
            showResultModal("Error", message)
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
        rawProjects.forEach(project => {
            const option = normalizeProjectOption(project)
            if (option) {
                options.push(option)
            }
        })
        return options
    }

    function fetchPortalProjects() {
        return controller.getProjects().then(result => {
            if (!result?.success) {
                const message = result?.json?.message || result?.message || 'Unable to load projects. Check your PTK+ configuration.'
                throw new Error(message)
            }
            const projectOptions = buildProjectOptions(result.json)
            if (!projectOptions.length) {
                throw new Error('No projects available. Create a project in the portal and try again.')
            }
            return projectOptions
        })
    }

    function populateSaveScanProjectDropdown(projectOptions) {
        $saveScanProjectDropdown = populateProjectDropdown($saveScanProjectDropdown, saveScanProjectMap, projectOptions, 'Select a project')
    }

    function populateDownloadProjectDropdown(projectOptions) {
        $downloadProjectDropdown = populateProjectDropdown($downloadProjectDropdown, downloadProjectMap, projectOptions, 'Select a project')
        if (!$downloadProjectDropdown) return
        $downloadProjectDropdown.off('change').on('change', function () {
            const selected = $(this).val()
            if (!selected) {
                clearDownloadScansTable()
                setDownloadScansError('')
                return
            }
            const projectId = downloadProjectMap.get(selected) ?? selected
            loadScansForProject(projectId)
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
        entries.forEach(entry => {
            if (!entry) return
            const scanId = entry.scanId || ''
            const hostname = entry.hostname || entry.raw?.meta?.hostname || ''
            const rawDate = entry.scanDate || entry.raw?.finished_at || entry.raw?.created_at || entry.raw?.started_at
            const dateObj = rawDate ? new Date(rawDate) : null
            const scanDate = dateObj && !isNaN(dateObj.getTime()) ? dateObj.toLocaleString() : ''
            const downloadAvailable = !(entry.raw?.download_available === false || entry.raw?.download_available === 0)
            const link = downloadAvailable
                ? `<div class="ui mini icon button download_scan_by_id" style="position: relative" data-scan-id="${scanId}"><i class="download alternate large icon"
                                        title="Download"></i>
                                        <div style="position:absolute; top:1px;right: 2px">
                                             <div class="ui  centered inline inverted loader"></div>
                                        </div>
                                </div>`
                : `<div class="ui mini icon button disabled" style="position: relative" title="Download unavailable for this scan"><i class="download alternate large icon"></i></div>`
            dt.push([hostname, scanId, scanDate, link])
        })

        dt.sort(function (a, b) {
            if (a[0] === b[0]) { return 0 } else { return (a[0] < b[0]) ? -1 : 1 }
        })
        const groupColumn = 0
        const params = {
            forceRebuild: true,
            data: dt,
            columnDefs: [{
                "visible": false, "targets": groupColumn
            }],
            "order": [[groupColumn, 'asc']],
            "drawCallback": function (settings) {
                var api = this.api()
                var rows = api.rows({ page: 'current' }).nodes()
                var last = null

                api.column(groupColumn, { page: 'current' }).data().each(function (group, i) {
                    if (last !== group) {
                        $(rows).eq(i).before(
                            '<tr class="group" ><td colspan="3"><div class="ui black ribbon label">' + group + '</div></td></tr>'
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

    function loadDownloadProjects() {
        setDownloadScansError('')
        clearDownloadScansTable()
        $downloadScansModal.addClass('loading')
        fetchPortalProjects()
            .then(options => {
                populateDownloadProjectDropdown(options)
            })
            .catch(err => {
                setDownloadScansError(err?.message || 'Unable to load projects. Check your PTK+ configuration.')
            })
            .finally(() => {
                $downloadScansModal.removeClass('loading')
            })
    }

    function loadScansForProject(projectId) {
        if (!projectId) {
            setDownloadScansError('Select a project to load scans.')
            clearDownloadScansTable()
            return
        }
        setDownloadScansError('')
        $downloadScansModal.addClass('loading')
        controller.downloadScans(projectId, 'dast').then(result => {
            if (!result?.success) {
                const message = result?.json?.message || result?.message || 'Unable to load scans.'
                setDownloadScansError(message)
                clearDownloadScansTable()
                return
            }
            setDownloadScansError('')
            renderDownloadScansTable(result.json)
        }).catch(err => {
            setDownloadScansError(err?.message || 'Unable to load scans.')
            clearDownloadScansTable()
        }).finally(() => {
            $downloadScansModal.removeClass('loading')
        })
    }

    function hideSaveScanModalError() {
        $saveScanModalError.hide().text('')
    }

    function showSaveScanModalError(message) {
        $saveScanModalError.text(message || '').show()
    }

    function runSaveScan(projectId, $loader) {
        hideSaveScanModalError()
        if ($loader) {
            $loader.addClass('active')
        }
        $saveScanModal.addClass('loading')
        controller.saveScan(projectId).then(result => {
            handleSaveScanResponse(result)
            $saveScanModal.modal('hide')
        }).catch(err => {
            showResultModal("Error", err?.message || "Unable to save scan")
        }).finally(() => {
            if ($loader) {
                $loader.removeClass('active')
            }
            $saveScanModal.removeClass('loading')
        })
    }

    function showSaveScanModal($loader) {
        hideSaveScanModalError()
        $saveScanModal
            .modal({
                allowMultiple: true,
                onApprove: function () {
                    const projectId = $saveScanProjectDropdown.val()
                    if (!projectId) {
                        showSaveScanModalError('Select a project to continue.')
                        return false
                    }
                    const payloadProjectId = saveScanProjectMap.get(projectId) ?? projectId
                    runSaveScan(payloadProjectId, $loader)
                    return false
                }
            })
            .modal('show')
    }

    function requestProjectsAndShowModal($loader) {
        if ($loader) {
            $loader.addClass('active')
        }
        fetchPortalProjects()
            .then(projectOptions => {
                populateSaveScanProjectDropdown(projectOptions)
                showSaveScanModal($loader)
            })
            .catch(err => {
                showResultModal('Error', err?.message || 'Unable to load projects. Check your PTK+ configuration.')
            })
            .finally(() => {
                if ($loader) {
                    $loader.removeClass('active')
                }
            })
    }


    //$('.question').popup()
    // $('.domains_example')
    //     .popup({
    //         position: 'right center',

    //         title: 'Example',
    //         content: `<i>Example: <br /> domain.com, api.domain.com, subdomain.domain.com, www.domain.com</i>
    //             <br />
    //             <b>OR</b>
    //             <br />
    //             <i>*.domain.com - to scan all subdomains</i>`
    //     })


    $(document).on("click", ".showHtml", function () {
        rutils.showHtml($(this))
    })
    $(document).on("click", ".showHtmlNew", function () {
        rutils.showHtml($(this), true)
    })

    $(document).on("click", ".generate_report", function () {
        browser.windows.create({
            type: 'popup',
            url: browser.runtime.getURL("/ptk/browser/report.html?dast_report")
        })
    })

    $(document).on("click", ".save_scan", function () {
        const $loader = $(this).find(".loader")
        requestProjectsAndShowModal($loader)
    })

    $(document).on('click', '#load_pro_policies_button', async function () {
        setDastPortalPolicyLoading(true)
        try {
            const result = await controller.loadPolicyMetadata()
            applyDastPortalPolicyState(result)
            if (result?.success) {
                showResultDialog('Success', buildPolicyLoadSuccessMessage('DAST', result?.policyState || {}), 'success')
            } else {
                showResultDialog(
                    'Error',
                    buildPolicyLoadErrorMessage(result, 'DAST scan policies'),
                    'error',
                    { showSettings: result?.error === 'missing_api_key' }
                )
            }
        } catch (err) {
            showResultDialog('Error', buildPolicyLoadErrorMessage({ message: err?.message || 'unknown_error' }, 'DAST scan policies'), 'error')
        } finally {
            setDastPortalPolicyLoading(false)
        }
        return false
    })

    $(document).on('click', '#result_dialog .result_open_settings_btn', function () {
        openExtensionSettingsWindow()
        $('#result_dialog').modal('hide')
        return false
    })

    $(document).on('change', '#dast-scan-policy', async function () {
        const $select = $(this)
        const rawValue = String($select.val() || '').trim()
        const policyId = parseDastPortalOptionValue(rawValue)
        const policyName = policyId ? String($select.find('option:selected').text() || '').trim() : null
        setDastPortalPolicyLoading(true)
        try {
            const result = policyId
                ? await controller.selectPolicy(policyId, policyName)
                : await controller.clearPolicy()
            applyDastPortalPolicyState(result)
            if (result?.success) {
                maybeBindDastPortalPreview(result)
            } else {
                showResultDialog(
                    'Error',
                    result?.error === 'missing_api_key'
                        ? 'PAT required. Activate the portal token in Settings first.'
                        : `Failed to update portal policy: ${result?.error || 'unknown_error'}`
                )
            }
        } catch (err) {
            showResultDialog('Error', `Failed to update portal policy: ${err?.message || 'unknown_error'}`)
        } finally {
            setDastPortalPolicyLoading(false)
        }
        return false
    })

    $(document).on("click", ".run_scan_runtime", function () {
        controller.init().then(function (result) {
            if (!result?.activeTab?.url) {
                $('#result_header').text("Error")
                $('#result_message').text("Active tab not set. Reload required tab to activate tracking.")
                $('#result_dialog').modal('show')
                return false
            }

            let h = new URL(result.activeTab.url).host
            $('#scan_host').text(h)
            $('#scan_domains').text(h)
            $('#maxRequestsPerSecond').val(result.settings.maxRequestsPerSecond)
            $('#concurrency').val(result.settings.concurrency)
            $('#dast-scan-strategy').val(result.settings.dastScanStrategy || 'SMART')
            $('#ptk_dast_record_macro').prop('checked', false)
            applyDastPortalPolicyState(result)
            const rattackerSafetyProfile = (
                result?.settings?.scanControls?.profile ||
                result?.settings?.safetyProfile ||
                'safe'
            )
            $('#dast-safety-profile').val(String(rattackerSafetyProfile).toLowerCase())
            setRunCveState(false)
            window._ptkDastReloadWarningClosed = false
            rutils.pingContentScript(result.activeTab.tabId, { timeoutMs: 700 }).then((ready) => {
                if (window._ptkDastReloadWarningClosed) return
                $('#ptk_scan_reload_warning').toggle(!ready)
            })

            $('#run_scan_dlg')
                .modal({
                    allowMultiple: true,
                    onApprove: function () {
                        const selectedPolicyValue = String($('#dast-scan-policy').val() || '').trim()
                        const selectedPortalPolicyId = parseDastPortalOptionValue(selectedPolicyValue)
                        const selectedPortalPolicyName = selectedPortalPolicyId
                            ? String($('#dast-scan-policy option:selected').text() || '').trim() || null
                            : null
                        const hasPortalEntries = Array.isArray(controller?.policyState?.metadata) && controller.policyState.metadata.length > 0
                        if (hasPortalEntries && !selectedPolicyValue) {
                            showResultDialog('Error', 'Select a scan policy.')
                            return false
                        }
                        const safetyProfile = ($('#dast-safety-profile').val() || 'safe').toLowerCase()
                        const settings = {
                            maxRequestsPerSecond: $('#maxRequestsPerSecond').val(),
                            concurrency: $('#concurrency').val(),
                            scanStrategy: $('#dast-scan-strategy').val() || 'SMART',
                            dastScanPolicy: selectedPortalPolicyId ? 'PORTAL' : (selectedPolicyValue || 'ACTIVE'),
                            safetyProfile,
                            scanControls: {
                                profile: safetyProfile
                            },
                            runCve: isRunCveEnabled()
                        }
                        if (selectedPortalPolicyId) {
                            settings.policyId = selectedPortalPolicyId
                            settings.policyName = selectedPortalPolicyName || null
                        }
                        const shouldRecordMacro = $('#ptk_dast_record_macro').is(':checked')
                        DAST_SCAN_MACRO_STATE.requested = shouldRecordMacro
                        DAST_SCAN_MACRO_STATE.started = false
                        const startScan = function () {
                            controller.runBackgroundScan(result.activeTab.tabId, h, $('#scan_domains').val(), settings).then(function (scanStartResult) {
                                if (scanStartResult?.success === false) {
                                    DAST_SCAN_MACRO_STATE.requested = false
                                    showResultDialog('Error', scanStartResult?.message || scanStartResult?.error || 'Failed to start scan.')
                                    return
                                }
                                const startMacroRecording = async () => {
                                    if (!shouldRecordMacro) return
                                    const recordingResult = await macro_controller.start(false, result.activeTab.url || window.location.href, {
                                        skipNavigation: true,
                                        source: 'dast_runtime_scan'
                                    })
                                    if (recordingResult?.success === false) {
                                        DAST_SCAN_MACRO_STATE.requested = false
                                        showResultDialog('Warning', recordingResult?.error || 'Runtime scan started, but macro recording could not be started.')
                                        return
                                    }
                                    DAST_SCAN_MACRO_STATE.started = true
                                }
                                resetDastRenderState()
                                updateDastProgressContext(scanStartResult)
                                DAST_RENDER.scanning = true
                                startIdleChecker()
                                updateLiveModeNotice()
                                $("#request_info").html("")
                                $("#attacks_info").html("")
                                triggerDastStatsEvent(scanStartResult.scanResult)
                                changeView(scanStartResult)
                                if (hasRenderableScanData(scanStartResult.scanResult)) {
                                    bindScanResult(scanStartResult)
                                }
                                startMacroRecording().catch((err) => {
                                    DAST_SCAN_MACRO_STATE.requested = false
                                    DAST_SCAN_MACRO_STATE.started = false
                                    showResultDialog('Warning', err?.message || 'Runtime scan started, but macro recording could not be started.')
                                })
                            })
                        }
                        startScan()
                        $('#run_scan_dlg').modal('hide')
                        return false
                    }
                })
                .modal('show')
            bindDastHelpPopups()
        })

        return false
    })

    $(document).on("click", "#ptk_scan_reload_warning_close_dast", function () {
        window._ptkDastReloadWarningClosed = true
        $('#ptk_scan_reload_warning').hide()
    })

    $(document).on("click", ".stop_scan_runtime", function () {
        const $stopButton = $('#stop_scan_bg_control')
        $stopButton.addClass('loading disabled')
        $('#progress_message').show()
        $('#progress_attack_name').text('Stopping runtime scan...')
        controller.stopBackgroundScan({
            runDeferredSeed: false,
            waitForIdleBeforeStop: false
        }).then(function (result) {
            const normalizedResult = Object.assign({ isScanRunning: false }, result || {})
            const stopMacroRecording = DAST_SCAN_MACRO_STATE.started
                ? macro_controller.stop({ reason: 'dast_runtime_scan_stopped' }).catch(() => null)
                : Promise.resolve(null)
            DAST_SCAN_MACRO_STATE.requested = false
            DAST_SCAN_MACRO_STATE.started = false
            DAST_RENDER.scanning = false
            if (DAST_RENDER.idleCheckTimer) {
                clearInterval(DAST_RENDER.idleCheckTimer)
                DAST_RENDER.idleCheckTimer = null
            }
            updateLiveModeNotice()
            changeView(normalizedResult)
            if (hasRenderableScanData(normalizedResult.scanResult)) {
                bindScanResult(normalizedResult)
            }
            stopMacroRecording.catch(() => null)
        }).catch(function (err) {
            showResultDialog('Error', err?.message || 'Runtime scan could not be stopped.')
        }).finally(function () {
            $stopButton.removeClass('loading disabled')
        })
        return false
    })

    $('.settings.rattacker').on('click', function () {
        $('#settings').modal('show')

    })

    $('.cloud_download_scans').on('click', function () {
        $downloadScansModal.modal('show')
        loadDownloadProjects()
    })

    $(document).on("click", ".download_scan_by_id", function () {
        $(this).parent().find(".loader").addClass("active")
        let scanId = $(this).attr("data-scan-id")
        controller.downloadScanById(scanId).then(function (result) {
            if (result?.success === false) {
                const message = result?.json?.message || result?.message || 'Unable to download scan'
                showResultModal("Error", message)
                return
            }
            let info = { isScanRunning: false, scanResult: result }
            changeView(info)
            if (hasRenderableScanData(info.scanResult)) {
                bindScanResult(info)
            }
            $('#download_scans').modal('hide')
        }).catch(err => {
            showResultModal("Error", err?.message || 'Unable to download scan')
        })
    })

    $('.import_export').on('click', function () {

        controller.init().then(function (result) {
            if (!hasRenderableScanData(result.scanResult)) {
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
            setImportProgress(15, 'Preparing import chunks...')
            return
        }
        if (phase === 'upload_start') {
            setImportProgress(20, total > 1 ? `Uploading import chunks... 0/${total}` : 'Uploading import payload...')
            return
        }
        if (phase === 'upload_chunk') {
            const chunkPercent = total > 0 ? Math.floor((completed / total) * 65) : 0
            setImportProgress(20 + chunkPercent, `Uploading import chunks... ${completed}/${total}`)
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
                await downloadScanExportResult(controller, scanResult, "PTK_DAST_scan.json", {
                    onProgress: updateExportProgressFromChunk
                })
            } else if (scanResult && hasRenderableScanData(scanResult)) {
                setExportProgress(60, 'Compressing export payload...')
                await downloadScanExportResult(controller, scanResult, "PTK_DAST_scan.json", {
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
            if (result instanceof Error || result?.success === false || !hasRenderableScanData(result?.scanResult)) {
                const message = result?.message || result?.error || 'Could not import DAST scan'
                $('#result_message').text(message)
                $('#result_dialog').modal('show')
                return
            }
            changeView(result)
            bindScanResult(result)
            $('#import_export_dlg').modal('hide')
        } catch (e) {
            $('#result_message').text(e?.message || 'Could not import DAST scan')
            $('#result_dialog').modal('show')
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
            if (hasRenderableScanData(result.scanResult)) {
                bindScanResult(result)
            }
            $('#import_export_dlg').modal('hide')
        }).catch(e => {
            $('#result_message').text('Could not import DAST scan: ')
            $('#result_dialog').modal('show')
        })
    })





    $(document).on("click", ".reset", function () {
        $("#request_info").html("")
        $("#attacks_info").html("")
        $("#analysis_info").html("")
        resetAnalysisSuppressionState()
        resetAnalysisUiState()
        $('.generate_report').hide()
        $('#dast_result_tabs').hide()
        $('.save_scan').hide()
        //$('.exchange').hide()
        setDastResultView('findings')

        hideRunningForm()
        showWelcomeForm()
        controller.reset().then(function (result) {
            triggerDastStatsEvent(result.scanResult)
            updateDastProgressContext(result)
            ensureDastDefaultModulesLoaded({ force: true }).catch(() => { })
        })
    })

    $('.send_rbuilder').on("click", function () {
        let request = $('#raw_request').val().trim()
        window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(request)))
        return false
    })

    $(document).on("click", ".open_candidate_rbuilder", async function () {
        const candidateId = $(this).attr('data-candidate-id') || ''
        await openCandidateInRBuilder(candidateId)
        return false
    })

    $(document).on("click", ".open_evidence_request_rbuilder", async function () {
        const requestId = $(this).attr('data-request-id') || ''
        const candidateId = $(this).attr('data-candidate-id') || ''
        await openEvidenceRequestInRBuilder(requestId, candidateId)
        return false
    })

    $(document).on("click", ".open_evidence_attack_rbuilder", async function () {
        const attackId = $(this).attr('data-attack-id') || ''
        const candidateId = $(this).attr('data-candidate-id') || ''
        await openEvidenceAttackInRBuilder(attackId, candidateId)
        return false
    })

    $(document).on("click", ".open_evidence_finding_details", async function () {
        const findingId = $(this).attr('data-finding-id') || ''
        await openEvidenceFindingDetails(findingId)
        return false
    })

    $(document).on("click", ".open_evidence_generic_rbuilder", async function () {
        const candidateId = $(this).attr('data-candidate-id') || ''
        const ref = {
            type: $(this).attr('data-evidence-type') || 'evidence',
            id: $(this).attr('data-evidence-id') || null,
            loc: {
                route: $(this).attr('data-evidence-route') || null,
                method: $(this).attr('data-evidence-method') || null,
                param: $(this).attr('data-evidence-param') || null
            }
        }
        await openEvidenceGenericInRBuilder(ref, candidateId)
        return false
    })

    $(document).on("click", ".run_candidate_playwright", async function () {
        const candidateId = String($(this).attr('data-candidate-id') || '').trim()
        if (!candidateId) return false
        await openCandidatePlaywrightRunModal(candidateId)
        return false
    })

    $(document).on("click", ".open_candidate_authz_diff", async function () {
        if (!AUTHZ_DIFF_FEATURES_VISIBLE) return false
        const candidateId = String($(this).attr('data-candidate-id') || '').trim()
        if (!candidateId) return false
        await openCandidateAuthzDiffModal(candidateId)
        return false
    })

    $(document).on("change", "#analysis_playwright_profile", function () {
        setPlaywrightRunModalProfile($(this).val() || 'smoke')
    })

    $(document).on("change", "#analysis_playwright_auth", function () {
        togglePlaywrightAuthMode($(this).val() || 'reuse_storage_state')
    })

    $(document).on("click", "#analysis_manage_session_profiles, #analysis_authz_manage_sessions", async function () {
        const host = ANALYSIS_AUTHZ_DIFF_MODAL_STATE.host
            || resolveCandidateAnalysisHost(ANALYSIS_CANDIDATE_INDEX.get(String(ANALYSIS_PLAYWRIGHT_MODAL_STATE.candidateId || '').trim()) || null)
            || ANALYSIS_SESSION_PROFILES_STATE.host
        await openSessionProfilesModal({ host })
        return false
    })

    $(document).on("click", "#analysis_session_profile_create", async function () {
        const host = normalizeHostKey(ANALYSIS_SESSION_PROFILES_STATE.host || '')
        if (!host) {
            renderSessionProfilesModalContent({ color: 'red', message: 'Host is required before capturing a session.' })
            return false
        }
        const label = String($('#analysis_session_profile_label').val() || '').trim()
        const notes = String($('#analysis_session_profile_notes').val() || '').trim()
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            const response = await controller.createSessionProfile({ label, host, notes })
            if (!response?.success) {
                throw new Error(response?.error || response?.message || 'Session profile could not be captured.')
            }
            ANALYSIS_SESSION_PROFILES_STATE.host = normalizeHostKey(response?.host || host)
            ANALYSIS_SESSION_PROFILES_STATE.profiles = Array.isArray(response?.profiles) ? response.profiles : []
            $('#analysis_session_profile_label').val('')
            $('#analysis_session_profile_notes').val('')
            renderSessionProfilesModalContent({ color: 'green', message: 'Session profile captured.' })
            renderPlaywrightSessionProfileOptions($('#analysis_playwright_session_profile').val() || '')
            renderAuthzDiffSessionSelectors({
                baselineSessionProfileId: $('#analysis_authz_diff_baseline_session').val() || '',
                comparisonSessionProfileId: $('#analysis_authz_diff_comparison_session').val() || ''
            })
        } catch (err) {
            renderSessionProfilesModalContent({ color: 'red', message: err?.message || 'Session profile could not be captured.' })
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", ".delete_session_profile", async function () {
        const id = String($(this).attr('data-session-profile-id') || '').trim()
        if (!id) return false
        const host = normalizeHostKey(ANALYSIS_SESSION_PROFILES_STATE.host || '')
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            const response = await controller.deleteSessionProfile(id, host || null)
            if (!response?.success) {
                throw new Error(response?.error || 'Session profile could not be deleted.')
            }
            ANALYSIS_SESSION_PROFILES_STATE.host = normalizeHostKey(response?.host || host)
            ANALYSIS_SESSION_PROFILES_STATE.profiles = Array.isArray(response?.profiles) ? response.profiles : []
            renderSessionProfilesModalContent({ color: 'green', message: 'Session profile deleted.' })
            renderPlaywrightSessionProfileOptions($('#analysis_playwright_session_profile').val() || '')
            renderAuthzDiffSessionSelectors({
                baselineSessionProfileId: $('#analysis_authz_diff_baseline_session').val() || '',
                comparisonSessionProfileId: $('#analysis_authz_diff_comparison_session').val() || ''
            })
        } catch (err) {
            renderSessionProfilesModalContent({ color: 'red', message: err?.message || 'Session profile could not be deleted.' })
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", "#analysis_playwright_run_confirm", async function () {
        const candidateId = String(ANALYSIS_PLAYWRIGHT_MODAL_STATE.candidateId || '').trim()
        if (!candidateId) return false
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            const profile = String($('#analysis_playwright_profile').val() || 'smoke').toLowerCase()
            const authMode = String($('#analysis_playwright_auth').val() || 'reuse_storage_state')
            const constraints = getPlaywrightRunModalConstraints()
            const sessionProfileId = authMode === 'session_profile'
                ? String($('#analysis_playwright_session_profile').val() || '').trim()
                : null
            if (authMode === 'session_profile' && !sessionProfileId) {
                throw new Error('Select a session profile before starting a session-based Playwright run.')
            }
            const response = await controller.runCandidateInPlaywright({
                candidateId,
                profile,
                authMode,
                constraints,
                sessionProfileId
            })
            if (!response?.success || !response?.run) {
                const reasons = Array.isArray(response?.readiness?.reasons)
                    ? response.readiness.reasons.map((code) => mapReadinessReasonMessage(code)).join(' | ')
                    : ''
                const suffix = reasons ? ` (${reasons})` : ''
                throw new Error((response?.error || 'Playwright run could not be started') + suffix)
            }
            const run = upsertCandidatePlaywrightRun(response.run)
            if (response?.readiness) {
                ANALYSIS_ACTION_READINESS.set(candidateId, response.readiness)
            }
            rerenderAnalysisPanels()
            if (run && !isRunTerminal(run.status)) {
                startCandidateRunPolling(candidateId)
            }
            $('#analysis_playwright_run_modal').modal('hide')
        } catch (err) {
            showResultDialog('Playwright Run', err?.message || 'Playwright run could not be started')
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", ".prefill_authz_response", async function () {
        const target = $(this).attr('data-authz-target') || 'baseline'
        const source = $(this).attr('data-authz-source') || 'captured'
        await prefillAuthzDiffResponse(target, source)
        return false
    })

    $(document).on("change input", "#analysis_authz_object_swap_enabled, #analysis_authz_object_swap_target, #analysis_authz_object_swap_location, #analysis_authz_object_swap_value", function () {
        if (!$('#analysis_authz_object_swap_enabled').is(':checked')) {
            ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = null
            renderAuthzDiffRunUi()
            return false
        }
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap = {
            applied: true,
            location: String($('#analysis_authz_object_swap_location').val() || 'param').trim().toLowerCase(),
            targetParam: String($('#analysis_authz_object_swap_target').val() || '').trim(),
            originalValue: ANALYSIS_AUTHZ_DIFF_MODAL_STATE.objectSwap?.originalValue ?? null,
            swappedValue: String($('#analysis_authz_object_swap_value').val() || '').trim()
        }
        renderAuthzDiffRunUi()
        return false
    })

    $(document).on("change", "#analysis_authz_diff_baseline_session, #analysis_authz_diff_comparison_session", function () {
        ANALYSIS_AUTHZ_DIFF_MODAL_STATE.workflowReplay = null
        refreshAuthzWorkflowSummaryAvailability({ silent: true }).catch(() => { })
        return false
    })

    $(document).on("click", "#analysis_authz_suggest_swap", async function () {
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            await suggestCandidateObjectSwapFromModal()
        } catch (err) {
            showResultDialog('Object Swap', err?.message || 'Object swap suggestion failed.')
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", "#analysis_authz_diff_compare", async function () {
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            await runCandidateAuthzDiffComparison()
        } catch (err) {
            showResultDialog('Authz Diff', err?.message || 'Authz diff comparison failed.')
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", "#analysis_authz_save_evidence", async function () {
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            await saveAuthzEvidencePackage()
        } catch (err) {
            showResultDialog('Evidence Package', err?.message || 'Evidence package could not be created.')
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", ".open_evidence_package_report", function () {
        const evidencePackageId = String($(this).attr('data-evidence-package-id') || '').trim()
        openEvidencePackageReportWindow(evidencePackageId)
        return false
    })

    $(document).on("click", ".export_evidence_package", async function () {
        const evidencePackageId = String($(this).attr('data-evidence-package-id') || '').trim()
        const format = String($(this).attr('data-export-format') || 'json').trim().toLowerCase()
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            await exportEvidencePackageFromUi(evidencePackageId, format)
        } catch (err) {
            showResultDialog('Evidence Package', err?.message || 'Evidence package could not be exported.')
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", "#analysis_authz_preview_draft", async function () {
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            await previewCandidateReportDraft()
        } catch (err) {
            showResultDialog('Report Draft', err?.message || 'Report draft preview failed.')
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", "#analysis_authz_preview_workflow", async function () {
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            await previewAuthzWorkflowOverlay()
        } catch (err) {
            showResultDialog('Workflow Overlay', err?.message || 'Workflow overlay preview failed.')
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", "#analysis_authz_replay_workflow", async function () {
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            await startAuthzWorkflowOverlayReplay()
        } catch (err) {
            showResultDialog('Workflow Replay', err?.message || 'Workflow replay could not be started.')
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", "#analysis_authz_record_workflow", function () {
        openMacroRecorderWindow()
        return false
    })

    $(document).on("click", "#analysis_authz_diff_run", async function () {
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            await runCandidateAuthzDiffAutomated()
        } catch (err) {
            showResultDialog('Authz Diff', err?.message || 'Automated authz diff could not be started.')
        } finally {
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", ".toggle_candidate_evidence", function () {
        const targetId = String($(this).attr("data-evidence-target") || "")
        if (!targetId) return false
        const $drawer = $(`#${targetId}`)
        if (!$drawer.length) return false
        const isVisible = $drawer.is(":visible")
        $drawer.toggle(!isVisible)
        $(this).text(isVisible ? "Show Evidence" : "Hide Evidence")
        return false
    })

    $(document).on("click", ".toggle_candidate_manual_steps", function () {
        const targetId = String($(this).attr("data-steps-target") || "")
        if (!targetId) return false
        const $drawer = $(`#${targetId}`)
        if (!$drawer.length) return false
        const isVisible = $drawer.is(":visible")
        $drawer.toggle(!isVisible)
        $(this).text(isVisible ? "Show next steps" : "Hide next steps")
        return false
    })

    $(document).on("click", ".toggle_grouped_recon_routes", function () {
        const key = String($(this).attr("data-grouped-routes-key") || "").trim()
        if (!key) return false
        const escaped = (window.CSS && typeof CSS.escape === 'function') ? CSS.escape(key) : escAttrValue(key)
        const $allRoutes = $(`.grouped_recon_routes_all[data-grouped-routes-key="${escaped}"]`)
        if (!$allRoutes.length) return false
        const expanded = String($(this).attr("data-expanded") || "0") === "1"
        $allRoutes.toggle(!expanded)
        $(this).attr("data-expanded", expanded ? "0" : "1")
        $(this).text(expanded ? "Show all routes" : "Hide routes")
        return false
    })

    $(document).on("click", ".toggle_recon_route_suppression", async function () {
        const routeKey = String($(this).attr("data-route-key") || "").trim()
        const currentlySuppressed = String($(this).attr("data-suppressed") || "") === "1"
        const $button = $(this)
        $button.addClass("loading disabled")
        await toggleReconRouteSuppression(routeKey, !currentlySuppressed)
        $button.removeClass("loading disabled")
        return false
    })

    $(document).on("change", "#analysis_filter_engine, #analysis_filter_type, #analysis_filter_confidence, #analysis_filter_param_location", function () {
        ANALYSIS_FILTER_STATE.engine = String($("#analysis_filter_engine").val() || "all")
        ANALYSIS_FILTER_STATE.type = String($("#analysis_filter_type").val() || "all")
        ANALYSIS_FILTER_STATE.confidence = String($("#analysis_filter_confidence").val() || "all")
        ANALYSIS_FILTER_STATE.paramLocation = String($("#analysis_filter_param_location").val() || "all")
        ANALYSIS_FILTER_STATE.candidateLimit = ANALYSIS_CANDIDATE_PAGE_SIZE
        rerenderAnalysisPanels()
    })

    $(document).on("input", "#analysis_filter_route", function () {
        ANALYSIS_FILTER_STATE.route = String($(this).val() || "")
        ANALYSIS_FILTER_STATE.candidateLimit = ANALYSIS_CANDIDATE_PAGE_SIZE
        rerenderAnalysisPanels()
    })

    $(document).on("click", "#analysis_filter_reset", function () {
        ANALYSIS_FILTER_STATE.engine = "all"
        ANALYSIS_FILTER_STATE.type = "all"
        ANALYSIS_FILTER_STATE.confidence = "all"
        ANALYSIS_FILTER_STATE.route = ""
        ANALYSIS_FILTER_STATE.paramLocation = "all"
        ANALYSIS_FILTER_STATE.candidateLimit = ANALYSIS_CANDIDATE_PAGE_SIZE
        rerenderAnalysisPanels()
        return false
    })

    $(document).on("click", "#analysis_show_more_candidates", function () {
        ANALYSIS_FILTER_STATE.candidateLimit += ANALYSIS_CANDIDATE_PAGE_SIZE
        rerenderAnalysisPanels()
        return false
    })

    $(document).on("click", "#analysis_recompute", async function () {
        const $button = $(this)
        $button.addClass('loading disabled')
        try {
            const result = await controller.recomputeAnalysis()
            if (!result || result instanceof Error || result?.success === false || !result?.scanResult) {
                throw new Error(result?.message || result?.error || 'Analysis could not be recomputed.')
            }
            changeView(result)
            bindScanResult(result)
            setDastResultView('analysis')
        } catch (err) {
            showResultDialog('Analysis', err?.message || 'Analysis could not be recomputed.')
            $button.removeClass('loading disabled')
        }
        return false
    })

    $(document).on("click", "#dast_result_tabs .item", function () {
        const nextView = $(this).attr('data-view') || 'findings'
        setDastResultView(nextView)
    })

    $(document).on("click", "#dast_modules_tabs .item", function () {
        if ($(this).hasClass('disabled')) return false
        const nextTab = $(this).attr('data-modules-tab') || 'regular'
        setDastModulesCatalogTab(nextTab)
        return false
    })


    function applyAttackFilters() {
        const requestId = attackFilterState.requestId
        if (requestId) {
            $("#attacks_info").attr("data-request", requestId)
        } else {
            $("#attacks_info").removeAttr("data-request")
        }
        $("#attacks_info").attr("data-scope", attackFilterState.scope)
        // CSS-only filtering avoids full DOM hide/show on large scans.
        updateRequestFilterStyle(requestId)
        updateDastBucketVisibility()
        renderStatsFromCounters()
    }


    function setScopeFilter(scope, options = {}) {
        const allowedScopes = new Set(['all', 'vuln', '400', '500'])
        attackFilterState.scope = allowedScopes.has(scope) ? scope : 'all'
        if (!options.auto) {
            dastScopeTouchedByUser = true
        }
        if (dastResultView !== 'findings') {
            setDastResultView('findings')
        }
        updateDastScopeFilterButtons()
        applyAttackFilters()
    }

    function setRequestFilter(requestId) {
        attackFilterState.requestId = requestId || null
        requestFilterDirty = true
        applyAttackFilters()
        if (window.ptkUpdateRequestFilterUI) {
            const applied = window.ptkUpdateRequestFilterUI()
            if (applied) {
                requestFilterDirty = false
            }
        }
    }

    function updateRequestFilterUI() {
        const current = attackFilterState.requestId
        const $headers = $('#request_info .title.short_message_text')
        if (!$headers.length) {
            attackFilterState.requestId = null
            updateRequestFilterStyle(null)
            $("#attacks_info").removeAttr("data-request")
            renderStatsFromCounters()
            updateRequestFilterUI.lastHighlightedId = null
            return true
        }
        const currentId = current != null ? String(current) : null
        const prevId = updateRequestFilterUI.lastHighlightedId || null
        if (prevId && prevId !== currentId) {
            const prevEscaped = (window.CSS && typeof CSS.escape === 'function') ? CSS.escape(prevId) : escAttrValue(prevId)
            const $prev = $headers.filter(`[data-request-id="${prevEscaped}"]`)
            $prev.toggleClass('active', false)
            $prev.find('.filter.icon').toggleClass('primary', false)
        }
        if (!currentId) {
            updateRequestFilterUI.lastHighlightedId = null
            return true
        }
        if (currentId) {
            const currEscaped = (window.CSS && typeof CSS.escape === 'function') ? CSS.escape(currentId) : escAttrValue(currentId)
            const $current = $headers.filter(`[data-request-id="${currEscaped}"]`)
            if ($current.length) {
                $current.toggleClass('active', true)
                $current.find('.filter.icon').toggleClass('primary', true)
                updateRequestFilterUI.lastHighlightedId = currentId
                return true
            }
        }
        updateRequestFilterUI.lastHighlightedId = null
        return false
    }

    $('[id^="filter_"]').on("click", function () {
        const scope = this.id.replace('filter_', '')
        setScopeFilter(scope)
    })

    //$('#filter_all').addClass('active')


    function hasRawPayload(original) {
        return !!(original?.request?.raw || original?.response?.body)
    }

    function hasAttackDetailsPayload(attack) {
        if (!attack || typeof attack !== 'object') return false
        if (attack?.request?.raw) return true
        if (typeof attack?.response?.body === 'string' && attack.response.body.length) return true
        if (Array.isArray(attack?.response?.headers) && attack.response.headers.length) return true
        return false
    }

    $(document).on("click", ".attack_details", async function () {
        $('.metadata .item').tab()
        const groupedReconKey = String($(this).attr("data-grouped-recon-key") || "").trim()
        if (groupedReconKey) {
            const entry = DAST_RENDER.groupedReconObservations.get(groupedReconKey) || null
            const resolvedAttack = await resolveGroupedReconDetailsAttack(entry)
            const groupedDetails = buildGroupedReconDetailsPayload(entry, resolvedAttack)
            if (!groupedDetails) return false
            rutils.bindAttackDetails_DAST($(this), groupedDetails.attack, groupedDetails.original)
            $('.metadata .item').tab('change tab', 'first');
            return false
        }
        const requestId = $(this).attr("data-requestId")
        const attackId = $(this).attr("data-index")
        const requestModel = findRequestModel(requestId)
        if (!requestModel) return
        let attack = findAttackModel(requestModel, attackId)
        if (!attack) return
        let original = requestModel.original || controller?.scanResult?.scanResult?.items?.[requestId]?.original
        if (!hasRawPayload(original) || !hasAttackDetailsPayload(attack)) {
            try {
                const snapshot = await controller.getRequestSnapshot(requestId, attackId)
                if (snapshot?.original) {
                    requestModel.original = snapshot.original
                    original = snapshot.original
                }
                if (snapshot?.attack && Array.isArray(requestModel.attacks)) {
                    const idx = requestModel.attacks.findIndex(item => String(item?.id) === String(attackId))
                    if (idx >= 0) {
                        requestModel.attacks[idx] = Object.assign({}, requestModel.attacks[idx], snapshot.attack)
                        attack = requestModel.attacks[idx]
                    }
                }
            } catch (_) {
                // fall back to existing data
            }
        }
        let lookup = controller._dastFindingLookup || buildFindingLookup(controller?.scanViewModel?.findings || [])
        controller._dastFindingLookup = lookup
        let enrichedAttack = attachFindingMetadataToAttack(attack, lookup)
        enrichedAttack = enrichAttackFromCatalog(enrichedAttack)
        if (!hasFindingPresentationData(enrichedAttack)) {
            lookup = await ensureAttackFindingDetails(attack, requestId, attackId) || lookup
            controller._dastFindingLookup = lookup
            enrichedAttack = attachFindingMetadataToAttack(attack, lookup)
            enrichedAttack = enrichAttackFromCatalog(enrichedAttack)
        }
        rutils.bindAttackDetails_DAST($(this), enrichedAttack, original)
        $('.metadata .item').tab('change tab', 'first');
    })


    $(document).on("bind_stats", function (e, scanResult) {
        if (scanResult.stats) {
            rutils.bindStats(scanResult.stats, 'dast')
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
        applyDastPortalPolicyState(result)
        updateDastProgressContext(result)
        changeView(result)
        DAST_RENDER.scanning = !!result.isScanRunning
        if (DAST_RENDER.scanning) {
            DAST_RENDER.legacyBound = false
            startIdleChecker()
        }
        updateLiveModeNotice()
        if (hasRenderableScanData(result.scanResult)) {
            bindScanResult(result)
        } else {
            showWelcomeForm()
            ensureDastDefaultModulesLoaded().catch(() => { })
        }
    })
    $('.ui.accordion').accordion({
        onOpen: function () {
            const $content = $(this)
            const index = $content.find('input[name="requestId"]').val()
            loadRequestRawForContent($content, index)
            setRequestFilter(index)
        },
        onClose: function () {
            setRequestFilter(null)
        }
    })

    window.ptkApplyAttackFilters = applyAttackFilters
    window.ptkSetRequestFilter = setRequestFilter
    window.ptkUpdateRequestFilterUI = updateRequestFilterUI
})

function filterByRequestId(requestId) {
    if (window.ptkSetRequestFilter) {
        window.ptkSetRequestFilter(requestId || null)
    }
}

function setDastPageLoader(show) {
    const $loader = $('#dast_page_loader')
    if (!$loader.length) return
    $loader.toggle(!!show)
}

function showWelcomeForm() {
    setDastPageLoader(false)
    $('#main').hide()
    $('#welcome_message').show()
    $('#run_scan_bg_control').show()
}

function hideWelcomeForm() {
    $('#welcome_message').hide()
    $('#main').show()
}

function showRunningForm(result) {
    setDastPageLoader(false)
    $('#main').show()
    $('#scanning_url').text(result.scanResult.host)
    $('.scan_info').show()
    $('#stop_scan_bg_control').show()
}

function hideRunningForm() {
    $('#scanning_url').text("")
    $('.scan_info').hide()
    $('#stop_scan_bg_control').hide()
}

function showScanForm(result) {
    setDastPageLoader(false)
    $('#main').show()
    $('#run_scan_bg_control').show()
}

function hideScanForm() {
    $('#run_scan_bg_control').hide()
}


function changeView(result) {
    $('#init_loader').removeClass('active')
    if (!result || typeof result !== 'object') {
        hideRunningForm()
        hideScanForm()
        showWelcomeForm()
        return
    }
    if (result.isScanRunning) {
        hideWelcomeForm()
        hideScanForm()
        showRunningForm(result)
    }
    else if (hasRenderableScanData(result.scanResult)) {
        hideWelcomeForm()
        hideRunningForm(result)
        showScanForm()
    }
    else {
        hideRunningForm()
        hideScanForm()
        showWelcomeForm()
    }
}

function cleanScanResult() {
    $("#attacks_info").html("")
    $("#analysis_info").html("")
    analysisPanelsDirty = true
    RELATED_FINDING_SUMMARY_INDEX.clear()
    DAST_RENDER.groupedReconObservations.clear()
    resetAnalysisSuppressionState()
    resetAnalysisUiState()
    $("#attacks_info").attr("data-scope", "all")
    resetDastCounters()
    dastScopeTouchedByUser = false
    ensureAttackBuckets()
    rutils.bindStats({
        attacksCount: 0,
        findingsCount: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    }, 'dast')
    setDastResultView('findings')
}

function hasRenderableScanData(scanResult) {
    if (!scanResult) return false
    if (Array.isArray(scanResult.requests) && scanResult.requests.length) return true
    if (Array.isArray(scanResult.findings) && scanResult.findings.length) return true
    if (Array.isArray(scanResult.recon) && scanResult.recon.length) return true
    return false
}

function getViewModelRequests() {
    if (!controller?.scanViewModel) return []
    return Array.isArray(controller.scanViewModel.requests) ? controller.scanViewModel.requests : []
}

function buildFindingLookup(findings) {
    const map = new Map()
    if (Array.isArray(findings)) {
        findings.forEach((finding) => {
            if (finding && finding.id) {
                map.set(String(finding.id), finding)
            }
        })
    }
    return map
}

function setRelatedFindingSummaryIndex(entries) {
    RELATED_FINDING_SUMMARY_INDEX.clear()
    ;(Array.isArray(entries) ? entries : []).forEach((entry) => {
        const id = String(entry?.id || '').trim()
        if (!id) return
        RELATED_FINDING_SUMMARY_INDEX.set(id, entry)
    })
}

async function ensureRelatedFindingSummariesLoaded() {
    if (!scanAnalysisUiEnabled) return
    try {
        const result = await controller.getRelatedFindingSummaries()
        if (result instanceof Error || result?.success === false) return
        setRelatedFindingSummaryIndex(result?.findings || [])
        if (dastResultView === 'analysis') {
            analysisPanelsDirty = true
            ensureAnalysisPanelsRendered({ force: true })
        }
    } catch (_) { }
}

function attachFindingMetadataToAttack(attack, lookup) {
    if (!attack) return attack
    if (attack && attack.findingId && lookup) {
        attack.finding = lookup.get(String(attack.findingId)) || null
    } else {
        attack.finding = null
    }
    const finding = attack.finding
    const severityFromFinding = finding?.severity
    const severityFromMeta = attack.metadata && typeof attack.metadata === 'object' ? attack.metadata.severity : undefined
    attack.severity = attack.severity || severityFromFinding || severityFromMeta || 'medium'
    return attack
}

function resolveCatalogMetaForAttack(attack) {
    const modules = Array.isArray(controller?.default_modules) ? controller.default_modules : []
    if (!attack || !modules.length) return null
    const moduleId = String(attack.moduleId || attack.metadata?.moduleId || attack.metadata?.id || '').trim()
    const ruleId = String(attack.ruleId || attack.metadata?.ruleId || attack.metadata?.id || attack.id || '').trim()
    const moduleDef = modules.find((item) => String(item?.id || '').trim() === moduleId)
        || modules.find((item) => String(item?.name || '').trim().toLowerCase() === String(attack.moduleName || '').trim().toLowerCase())
    if (!moduleDef) return null
    const attackDef = (Array.isArray(moduleDef.attacks) ? moduleDef.attacks : []).find((item) => String(item?.id || '').trim() === ruleId) || null
    return {
        moduleDef,
        attackDef,
        moduleMeta: moduleDef?.metadata && typeof moduleDef.metadata === 'object' ? moduleDef.metadata : {},
        attackMeta: attackDef?.metadata && typeof attackDef.metadata === 'object' ? attackDef.metadata : {}
    }
}

function enrichAttackFromCatalog(attack) {
    if (!attack || typeof attack !== 'object') return attack
    const catalog = resolveCatalogMetaForAttack(attack)
    if (!catalog) return attack
    const existing = attack.metadata && typeof attack.metadata === 'object' ? attack.metadata : {}
    const mergedMeta = Object.assign({}, catalog.moduleMeta, catalog.attackMeta, existing, {
        taxonomy: Object.assign({}, catalog.moduleMeta?.taxonomy || {}, catalog.attackMeta?.taxonomy || {}, existing.taxonomy || {}),
        docs: Object.assign({}, catalog.moduleMeta?.docs || {}, catalog.attackMeta?.docs || {}, existing.docs || {}),
        constants: Object.assign({}, catalog.moduleMeta?.constants || {}, catalog.attackMeta?.constants || {}, existing.constants || {}),
        extensions: Object.assign({}, catalog.moduleMeta?.extensions || {}, catalog.attackMeta?.extensions || {}, existing.extensions || {})
    })
    const docs = mergedMeta.docs && typeof mergedMeta.docs === 'object' ? mergedMeta.docs : {}
    const taxonomy = mergedMeta.taxonomy && typeof mergedMeta.taxonomy === 'object' ? mergedMeta.taxonomy : {}
    attack.metadata = mergedMeta
    attack.moduleName = attack.moduleName || catalog.moduleDef?.name || null
    attack.ruleName = attack.ruleName || catalog.attackDef?.name || null
    attack.category = attack.category || taxonomy.category || null
    attack.vulnId = attack.vulnId || taxonomy.vulnId || null
    attack.severity = attack.severity || taxonomy.severity || null
    attack.description = attack.description || docs.description || null
    attack.recommendation = attack.recommendation || docs.recommendation || null
    attack.links = attack.links || docs.links || null
    if (attack.finding && typeof attack.finding === 'object') {
        attack.finding = Object.assign({}, attack.finding, {
            description: attack.finding.description || attack.description || null,
            recommendation: attack.finding.recommendation || attack.recommendation || null,
            links: attack.finding.links || attack.links || null
        })
    }
    return attack
}

function hasFindingPresentationData(attack) {
    const finding = attack?.finding
    if (!finding || typeof finding !== 'object') return false
    if (typeof finding.description === 'string' && finding.description.trim().length) return true
    if (typeof finding.recommendation === 'string' && finding.recommendation.trim().length) return true
    if (finding.links && typeof finding.links === 'object' && Object.keys(finding.links).length) return true
    return false
}

async function resolveGroupedReconDetailsAttack(entry) {
    if (!entry?.sampleAttack) return null
    let attack = enrichAttackFromCatalog(Object.assign({}, entry.sampleAttack))
    let lookup = controller._dastFindingLookup
    if (!lookup) {
        lookup = buildFindingLookup(controller?.scanViewModel?.findings || [])
        controller._dastFindingLookup = lookup
    }
    attack = attachFindingMetadataToAttack(attack, lookup)
    if (!hasFindingPresentationData(attack)) {
        try {
            const details = await controller.getFindingDetails({
                findingId: attack?.findingId || null,
                requestId: entry?.requestId || null,
                attackId: attack?.id || null,
                moduleId: attack?.moduleId || attack?.metadata?.moduleId || attack?.metadata?.id || null
            })
            if (details?.finding?.id) {
                lookup.set(String(details.finding.id), details.finding)
            }
            if (details?.attack && typeof details.attack === 'object') {
                attack = Object.assign({}, attack, details.attack)
            }
        } catch (_) {
            // keep local catalog-enriched payload
        }
        controller._dastFindingLookup = lookup
        attack = attachFindingMetadataToAttack(attack, lookup)
        attack = enrichAttackFromCatalog(attack)
    }
    entry.sampleAttack = attack
    return attack
}

async function ensureAttackFindingDetails(attack, requestId, attackId) {
    if (!attack) return null
    let lookup = controller._dastFindingLookup
    if (!lookup) {
        lookup = buildFindingLookup(controller?.scanViewModel?.findings || [])
        controller._dastFindingLookup = lookup
    }
    if (hasFindingPresentationData(attack)) {
        return lookup
    }
    try {
        const details = await controller.getFindingDetails({
            findingId: attack?.findingId || null,
            requestId: requestId || null,
            attackId: attackId || attack?.id || null,
            moduleId: attack?.moduleId || attack?.metadata?.moduleId || attack?.metadata?.id || null
        })
        const finding = details?.finding
        if (finding && finding.id) {
            lookup.set(String(finding.id), finding)
        }
        if (details?.attack && typeof details.attack === 'object') {
            Object.assign(attack, details.attack)
        }
    } catch (_) {
        // keep existing sparse payload when lazy lookup fails
    }
    return lookup
}

function findRequestModel(requestId) {
    if (requestId == null) return null
    const key = String(requestId)
    const requests = getViewModelRequests()
    if (requests.length) {
        const direct = requests.find(record => String(record.id) === key)
        if (direct) return direct
        const idx = Number(key)
        if (!Number.isNaN(idx) && requests[idx]) {
            return requests[idx]
        }
    }
    return null
}

function findAttackModel(requestModel, attackId) {
    if (!requestModel || attackId == null) return null
    const key = String(attackId)
    const attacks = Array.isArray(requestModel.attacks) ? requestModel.attacks : []
    if (attacks.length) {
        const direct = attacks.find(attack => String(attack.id) === key)
        if (direct) return direct
        const idx = Number(key)
        if (!Number.isNaN(idx) && attacks[idx]) {
            return attacks[idx]
        }
    }
    return null
}

function triggerDastStatsEvent(rawScanResult, viewModel) {
    const raw = rawScanResult || {}
    const vm = viewModel || normalizeScanResult(raw)
    const stats = vm.stats || raw.stats || {}
    $(document).trigger("bind_stats", Object.assign({}, raw, { stats }))
}

function bindScanResult(result) {
    if (!result.scanResult) return
    updateDastProgressContext(result)
    const raw = result.scanResult || {}
    latestDastRawScan = raw
    const vm = raw.__normalized ? raw : normalizeScanResult(raw)
    controller.scanResult = result
    controller.scanViewModel = vm
    setRelatedFindingSummaryIndex([])
    void ensureRelatedFindingSummariesLoaded()
    const snapshotProgress = buildProgressFromScanResult(raw)
    if (snapshotProgress) {
        DAST_RENDER.progressDetails = snapshotProgress
        DAST_RENDER.progressMetrics = formatProgressDetails(snapshotProgress)
    }
    DAST_RENDER.queue = []
    if (DAST_RENDER.timer) {
        clearTimeout(DAST_RENDER.timer)
        DAST_RENDER.timer = null
    }
    seedRenderedFromViewModel(vm)
    $("#progress_message").hide()
    $('.generate_report').show()
    scanAnalysisUiEnabled = shouldShowScanAnalysisUI(raw)
    refreshAnalysisSuppressions(raw?.host || vm?.host || null)
    if (scanAnalysisUiEnabled) {
        $('#dast_result_tabs').show()
    } else {
        $('#dast_result_tabs').hide()
        dastResultView = 'findings'
    }
    if (PORTAL_ACTIONS_VISIBLE) {
        $('.save_scan').show()
    } else {
        $('.save_scan').hide()
    }
    $('#request_info').html("")
    $('#attacks_info').html("")
    $('#analysis_info').html("")
    analysisPanelsDirty = true
    hideWelcomeForm()
    if (scanAnalysisUiEnabled && dastResultView === 'analysis') {
        ensureAnalysisPanelsRendered({ force: true })
    }

    const findings = Array.isArray(vm.findings) ? vm.findings : []
    const findingLookup = buildFindingLookup(findings)
    controller._dastFindingLookup = findingLookup
    const requests = Array.isArray(vm.requests) ? vm.requests : []
    const requestMarkup = []
    const bucketMarkup = {
        critical: [],
        high: [],
        medium: [],
        low: [],
        info: [],
        nonvuln: []
    }
    const groupedReconObservations = new Map()
    resetDastCounters()
    requests.forEach((request, index) => {
        const requestKey = String(request.id ?? `req-${index}`)
        const original = request.original && request.original.request ? request.original : request.original
        if (original && original.request) {
            requestMarkup.push(bindRequest(original, requestKey))
        }
        const attacks = Array.isArray(request.attacks) ? request.attacks : []
        attacks.forEach((attack, attackIdx) => {
            const attackKey = String(attack.id ?? `${requestKey}-${attackIdx}`)
            let enrichedAttack = attachFindingMetadataToAttack(attack, findingLookup)
            enrichedAttack = enrichAttackFromCatalog(enrichedAttack)
            attacks[attackIdx] = enrichedAttack
            if (isAggregatedReconRule(enrichedAttack)) {
                collectGroupedReconObservation(groupedReconObservations, enrichedAttack, original, requestKey)
                return
            }
            if (!shouldRenderAttackCard(enrichedAttack, original)) {
                return
            }
            const meta = rutils.getMiscMeta(enrichedAttack)
            updateDastCountersFromMeta(meta, requestKey)
            const attackHtml = rutils.bindAttack(enrichedAttack, original, attackKey, requestKey)
            const bucket = getAttackBucket(meta)
            bucketMarkup[bucket].push(attackHtml)
        })
    })
    DAST_RENDER.groupedReconObservations = groupedReconObservations
    renderGroupedReconObservationCards(groupedReconObservations).forEach(({ html, meta }) => {
        updateDastCountersFromMeta(meta, '__ptk_grouped_recon__')
        const bucket = getAttackBucket(meta)
        bucketMarkup[bucket].push(html)
    })
    $("#request_info").html(requestMarkup.join(''))
    $("#attacks_info").html([
        `<div class="dast_bucket${bucketMarkup.critical.length ? ' has-items' : ''}" data-bucket="critical">${bucketMarkup.critical.join('')}</div>`,
        `<div class="dast_bucket${bucketMarkup.high.length ? ' has-items' : ''}" data-bucket="high">${bucketMarkup.high.join('')}</div>`,
        `<div class="dast_bucket${bucketMarkup.medium.length ? ' has-items' : ''}" data-bucket="medium">${bucketMarkup.medium.join('')}</div>`,
        `<div class="dast_bucket${bucketMarkup.low.length ? ' has-items' : ''}" data-bucket="low">${bucketMarkup.low.join('')}</div>`,
        `<div class="dast_bucket${bucketMarkup.info.length ? ' has-items' : ''}" data-bucket="info">${bucketMarkup.info.join('')}</div>`,
        `<div class="dast_bucket${bucketMarkup.nonvuln.length ? ' has-items' : ''}" data-bucket="nonvuln">${bucketMarkup.nonvuln.join('')}</div>`
    ].join(''))
    dastScopeTouchedByUser = false
    applyDefaultAttackScope({ preserveManual: false })
    $("#attacks_info").attr("data-scope", attackFilterState.scope)
    updateRequestFilterStyle(attackFilterState.requestId)
    setDastResultView(dastResultView)

    const deferWork = () => {
        if (window.ptkUpdateRequestFilterUI) {
            window.ptkUpdateRequestFilterUI()
        }
        renderStatsFromCounters()
        DAST_RENDER.idleSorted = true
        triggerDastStatsEvent(raw, vm)
        if (window.ptkApplyAttackFilters) {
            window.ptkApplyAttackFilters()
        }
    }
    if (typeof requestAnimationFrame === "function") {
        requestAnimationFrame(deferWork)
    } else {
        setTimeout(deferWork, 0)
    }
}

function buildModuleRows(modules) {
    const rows = []
    ;(Array.isArray(modules) ? modules : []).forEach((mod) => {
        if (!mod) return
        const moduleName = mod.name || mod.metadata?.name || mod.metadata?.module_name || mod.id || 'Module'
        const severity = formatDastSeverityLabel(mod.metadata?.taxonomy?.severity || mod.metadata?.severity || mod.severity)
        const attacks = mod.attacks
        const attackCount = Array.isArray(attacks)
            ? attacks.length
            : (attacks && typeof attacks === 'object' ? Object.keys(attacks).length : 0)
        rows.push([
            moduleName,
            attackCount,
            formatDastSeverityDisplay(severity)
        ])
    })

    rows.sort((a, b) => {
        const leftSeverity = formatDastSeverityLabel(a[2])
        const rightSeverity = formatDastSeverityLabel(b[2])
        const severityDiff = (DAST_SEVERITY_ORDER[leftSeverity] ?? 99) - (DAST_SEVERITY_ORDER[rightSeverity] ?? 99)
        if (severityDiff !== 0) return severityDiff
        const leftName = String(a[0] || '').toLowerCase()
        const rightName = String(b[0] || '').toLowerCase()
        return leftName.localeCompare(rightName)
    })
    return rows
}

function setDastModulesCatalogTab(tab = 'regular') {
    const normalized = String(tab || 'regular').toLowerCase() === 'cve' ? 'cve' : 'regular'
    $('#dast_modules_tabs .item').removeClass('active')
    $(`#dast_modules_tabs .item[data-modules-tab="${normalized}"]`).addClass('active')
    $('#dast_modules_regular_panel').toggle(normalized === 'regular')
    $('#dast_modules_cve_panel').toggle(normalized === 'cve')
}

function bindModules(result) {
    const regularModules = Array.isArray(result?.default_modules)
        ? result.default_modules
        : (Array.isArray(controller?.default_modules) ? controller.default_modules : (Array.isArray(result) ? result : []))
    const cveModules = Array.isArray(result?.cve_modules)
        ? result.cve_modules
        : (Array.isArray(controller?.cve_modules) ? controller.cve_modules : [])

    const regularRows = buildModuleRows(regularModules)
    const cveRows = buildModuleRows(cveModules)

    $('#dast_regular_modules_count').text(`(${regularRows.length})`)
    $('#dast_cve_modules_count').text(`(${cveRows.length})`)

    bindTable('#tbl_modules', { data: regularRows })
    bindTable('#tbl_cve_modules', { data: cveRows })

    const hasRegular = regularRows.length > 0
    const hasCve = cveRows.length > 0
    $('#dast_modules_tabs .item[data-modules-tab="regular"]').toggleClass('disabled', !hasRegular)
    $('#dast_modules_tabs .item[data-modules-tab="cve"]').toggleClass('disabled', !hasCve)
    setDastModulesCatalogTab(hasRegular ? 'regular' : 'cve')
}

function bindRequest(info, requestId) {
    let item = `
                <div>
                <div class="title short_message_text" data-request-id="${requestId}" style="overflow-y: hidden;height: 34px;background-color: #eeeeee;margin:1px 0 0 0;cursor:pointer; position: relative">
                    <i class="dropdown icon"></i>${info.request.ui_url || info.request.url}<i class="filter icon" style="float:right; position: absolute; top: 3px; right: -3px;" title="Filter by request"></i>
                    
                </div>
               
                <div class="content">
                <input type="hidden" name="requestId" value="${requestId}" />
                <textarea class="ui medium input" data-request-raw="1" data-loaded="0" data-placeholder="Open to load request" placeholder="Open to load request" style="width:100%; height:200px; border: solid 1px #cecece; padding: 12px;"></textarea></div>
                </div>
                `
    return item
}

function scoreRawRequestRichness(rawValue) {
    const raw = String(rawValue || '')
    if (!raw.trim()) return -1
    const lines = raw.split(/\r?\n/)
    if (!lines.length) return -1
    let score = 0
    let headerCount = 0
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i]
        if (!line || !line.trim()) break
        const sep = line.indexOf(':')
        if (sep <= 0) continue
        headerCount += 1
        const lname = line.slice(0, sep).trim().toLowerCase()
        if (lname === 'cookie') score += 30
        else if (lname === 'user-agent') score += 20
        else if (lname.startsWith('sec-ch-')) score += 10
        else if (lname === 'accept' || lname === 'origin' || lname === 'referer' || lname === 'content-type') score += 8
        else if (lname === 'host') score += 2
        else score += 4
    }
    score += Math.min(headerCount, 20) * 6
    score += Math.min(raw.length, 4096) / 512
    return score
}

function pickRichestRawRequest(candidates) {
    let best = ''
    let bestScore = -1
    candidates.forEach((candidate) => {
        const score = scoreRawRequestRichness(candidate)
        if (score > bestScore) {
            best = String(candidate || '')
            bestScore = score
            return
        }
        if (score === bestScore && String(candidate || '').length > String(best || '').length) {
            best = String(candidate || '')
            bestScore = score
        }
    })
    return best
}

function collectPeerRawCandidates(requestModel, requestId) {
    const peers = []
    const targetUrl = requestModel?.original?.request?.url || requestModel?.original?.request?.ui_url || ''
    const targetMethod = String(requestModel?.original?.request?.method || '').toUpperCase()
    if (!targetUrl) return peers
    const requests = getViewModelRequests()
    requests.forEach((record) => {
        if (!record) return
        if (String(record.id || '') === String(requestId || '')) return
        const req = record?.original?.request || {}
        const url = req.url || req.ui_url || ''
        if (!url || url !== targetUrl) return
        const method = String(req.method || '').toUpperCase()
        if (targetMethod && method && method !== targetMethod) return
        const raw = req.raw || ''
        if (raw) peers.push(raw)
    })
    return peers
}

async function loadRequestRawForContent($content, requestId) {
    if (!requestId) return
    const $textarea = $content.find('textarea[data-request-raw="1"]')
    if (!$textarea.length) return
    if ($textarea.attr('data-loaded') === '1' || $textarea.attr('data-loading') === '1') return
    // Lazy-load raw requests to avoid large upfront DOM payloads.
    $textarea.attr('data-loading', '1')
    const placeholder = $textarea.attr('data-placeholder') || 'Open to load request'
    $textarea.attr('placeholder', 'Loading request...')
    const rawCandidates = []
    const requestModel = findRequestModel(requestId)
    const localRaw = requestModel?.original?.request?.raw || ''
    if (localRaw) rawCandidates.push(localRaw)
    const localScore = scoreRawRequestRichness(localRaw)
    if (!localRaw || localScore < 36) {
        try {
            const snapshot = await controller.getRequestSnapshot(requestId)
            const snapshotRaw = snapshot?.original?.request?.raw || ''
            if (snapshotRaw) rawCandidates.push(snapshotRaw)
            if (snapshot?.original && requestModel) {
                requestModel.original = snapshot.original
            }
        } catch (_) {
            // keep local raw candidate if snapshot fetch fails
        }
    }
    if (localScore < 30) {
        rawCandidates.push(...collectPeerRawCandidates(requestModel, requestId))
    }
    const raw = pickRichestRawRequest(rawCandidates)
    if (raw) {
        $textarea.val(raw)
        $textarea.attr('data-loaded', '1')
    }
    $textarea.attr('placeholder', placeholder)
    $textarea.removeAttr('data-loading')
}

function buildRequestCardHtml(original, requestId) {
    if (!original || !original.request) return ''
    return bindRequest(original, requestId)
}

function buildAttackCardHtml(attack, original, attackId, requestId, lookup) {
    const enriched = attachFindingMetadataToAttack(attack, lookup)
    return rutils.bindAttack(enriched, original, attackId, requestId)
}

function seedRenderedFromViewModel(viewModel) {
    DAST_RENDER.renderedRequestIds.clear()
    DAST_RENDER.renderedAttackIds.clear()
    DAST_RENDER.renderedReconKeys.clear()
    const requests = Array.isArray(viewModel?.requests) ? viewModel.requests : []
    requests.forEach(request => {
        if (request?.id) {
            DAST_RENDER.renderedRequestIds.add(String(request.id))
        }
        const attacks = Array.isArray(request?.attacks) ? request.attacks : []
        attacks.forEach(attack => {
            if (attack?.id) {
                DAST_RENDER.renderedAttackIds.add(String(attack.id))
            }
        })
    })
}

function updateLiveModeNotice() {
    const existing = document.getElementById("dast_live_notice")
    if (existing) existing.remove()
}

function resetDastRenderState() {
    DAST_RENDER.queue = []
    if (DAST_RENDER.timer) {
        clearTimeout(DAST_RENDER.timer)
        DAST_RENDER.timer = null
    }
    if (DAST_RENDER.progressTimer) {
        clearTimeout(DAST_RENDER.progressTimer)
        DAST_RENDER.progressTimer = null
    }
    DAST_RENDER.renderedRequestIds.clear()
    DAST_RENDER.renderedAttackIds.clear()
    DAST_RENDER.renderedReconKeys.clear()
    DAST_RENDER.groupedReconObservations.clear()
    DAST_RENDER.legacyBound = false
    DAST_RENDER.progressName = ''
    DAST_RENDER.progressDetails = null
    DAST_RENDER.progressStatus = ''
    DAST_RENDER.progressMetrics = ''
    DAST_RENDER.progressContext = ''
    DAST_RENDER.lastActivityAt = 0
    DAST_RENDER.idleSorted = false
    $("#progress_rulepack_meta").text("")
    resetDastCounters()
    dastScopeTouchedByUser = false
    requestFilterDirty = false
    if (DAST_RENDER.idleCheckTimer) {
        clearInterval(DAST_RENDER.idleCheckTimer)
        DAST_RENDER.idleCheckTimer = null
    }
}

function normalizeProgressPayload(payload) {
    if (!payload) return {}
    if (typeof payload === 'string') {
        return { name: payload }
    }
    if (typeof payload === 'object') {
        return payload
    }
    return {}
}

function formatProgressDetails(progress) {
    if (!progress || typeof progress !== 'object') {
        return 'Executed 0/Remaining 0/Active 0/Queued 0'
    }
    const planned = Number(progress.planned || 0)
    const executed = Number(progress.executed || 0)
    const active = Math.max(0, Number(progress.activeTasks || 0))
    const captured = Math.max(0, Number(progress.requestQueue || 0))
    const taskQueue = Math.max(0, Number(progress.taskQueue || 0))
    const pendingPlans = Math.max(0, Number(progress.pendingPlans || 0))
    const planning = Math.max(0, Number(progress.planning || 0))
    const nonExecuted = Math.max(0, Number(progress.nonExecuted || 0))
    const rawRemaining = Number(progress.remaining)
    const pipelineRemaining = Math.max(0, taskQueue + active + captured + pendingPlans + planning)
    const hasPipelineCounters = [progress.activeTasks, progress.taskQueue, progress.requestQueue, progress.pendingPlans, progress.planning]
        .some(v => Number.isFinite(Number(v)))
    const derivedRemaining = hasPipelineCounters
        ? pipelineRemaining
        : Math.max(0, planned - executed, nonExecuted)
    const remaining = Number.isFinite(rawRemaining)
        ? (hasPipelineCounters ? Math.max(0, rawRemaining, pipelineRemaining) : Math.max(0, rawRemaining, derivedRemaining))
        : derivedRemaining
    return `Executed ${executed}/Remaining ${remaining}/Active ${active}/Queued ${captured}`
}

function buildProgressFromScanResult(scanResult) {
    if (!scanResult || typeof scanResult !== 'object') return null
    const scanStats = scanResult.scanStats || {}
    const stats = scanResult.stats || {}
    const plannedRaw = Number(scanStats.totalJobsPlanned)
    const executedRaw = Number(scanStats.totalJobsExecuted)
    const fallbackExecuted = Number(stats.attacksCount || countSnapshotAttacks(scanResult) || 0)
    const executed = Number.isFinite(executedRaw) && executedRaw >= 0 ? executedRaw : fallbackExecuted
    const planned = Number.isFinite(plannedRaw) && plannedRaw >= executed ? plannedRaw : executed
    const isFinished = Boolean(scanResult.finishedAt || scanResult.finished)
    const remaining = isFinished ? 0 : Math.max(planned - executed, 0)
    return {
        planned,
        executed,
        remaining,
        activeTasks: 0,
        requestQueue: 0
    }
}

function composeProgressStatus(name, message) {
    return name || message || 'Scan running'
}

function scheduleProgressUpdate(payload) {
    const info = normalizeProgressPayload(payload)
    if (info.name) DAST_RENDER.progressName = info.name
    if (info.progress && typeof info.progress === 'object') {
        DAST_RENDER.progressDetails = info.progress
    }
    DAST_RENDER.progressMetrics = formatProgressDetails(DAST_RENDER.progressDetails)
    DAST_RENDER.progressStatus = composeProgressStatus(DAST_RENDER.progressName, info.message)
    DAST_RENDER.lastActivityAt = Date.now()
    if (DAST_RENDER.progressTimer) return
        DAST_RENDER.progressTimer = setTimeout(() => {
        DAST_RENDER.progressTimer = null
        if (DAST_RENDER.progressStatus || DAST_RENDER.progressMetrics) {
            $("#progress_scan_metrics").text(DAST_RENDER.progressMetrics || 'Executed 0/Remaining 0/Active 0/Queued 0')
            $("#progress_rulepack_meta").text(DAST_RENDER.progressContext || '')
            $("#progress_attack_name").text(DAST_RENDER.progressStatus || 'Scan running')
            $("#progress_message").show()
        }
    }, DAST_RENDER.progressFlushMs)
}

function startIdleChecker() {
    if (DAST_RENDER.idleCheckTimer) return
    DAST_RENDER.idleCheckTimer = setInterval(() => {
        if (!DAST_RENDER.scanning) return
        const last = DAST_RENDER.lastActivityAt || 0
        if (Date.now() - last < 1500) return
        const baseline = DAST_RENDER.progressDetails || {}
        const executed = Math.max(0, Number(baseline.executed || 0))
        const planned = Math.max(executed, Number(baseline.planned || executed || 0))
        const activeTasks = Math.max(0, Number(baseline.activeTasks || 0))
        const taskQueue = Math.max(0, Number(baseline.taskQueue || 0))
        const requestQueue = Math.max(0, Number(baseline.requestQueue || 0))
        const pendingPlans = Math.max(0, Number(baseline.pendingPlans || 0))
        const planning = Math.max(0, Number(baseline.planning || 0))
        const nonExecuted = Math.max(0, Number(baseline.nonExecuted || (planned - executed)))
        const hasPipelineCounters = [baseline.activeTasks, baseline.taskQueue, baseline.requestQueue, baseline.pendingPlans, baseline.planning]
            .some(v => Number.isFinite(Number(v)))
        const remaining = hasPipelineCounters
            ? Math.max(0, taskQueue + activeTasks + requestQueue + pendingPlans + planning)
            : Math.max(0, nonExecuted, planned - executed)
        const message = (remaining === 0)
            ? 'Runtime scan active, waiting for captured requests'
            : (activeTasks === 0)
            ? 'Scan running, preparing next attack batch'
            : 'Scan running, waiting for next runnable attack'
        scheduleProgressUpdate({
            message,
            progress: {
                planned,
                executed,
                remaining,
                nonExecuted,
                activeTasks,
                taskQueue,
                requestQueue,
                pendingPlans,
                planning
            }
        })
    }, 1000)
}

function countSnapshotAttacks(scanResult) {
    const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []
    if (!requests.length) return 0
    return requests.reduce((sum, req) => sum + (Array.isArray(req?.attacks) ? req.attacks.length : 0), 0)
}

function ensureDastViewModel() {
    if (!controller.scanViewModel) {
        controller.scanViewModel = { requests: [], findings: [], stats: {} }
    }
    if (!Array.isArray(controller.scanViewModel.requests)) {
        controller.scanViewModel.requests = []
    }
}

function addDeltaToViewModel(delta) {
    if (!delta) return
    ensureDastViewModel()
    const requestId = delta.requestId
    if (!requestId) return
    const requests = controller.scanViewModel.requests
    let requestModel = requests.find(req => String(req?.id) === String(requestId))
    if (!requestModel) {
        requestModel = {
            id: requestId,
            original: delta.original ? { request: delta.original } : null,
            attacks: []
        }
        requests.push(requestModel)
    } else if (!requestModel.original && delta.original) {
        requestModel.original = { request: delta.original }
    }
    if (Array.isArray(delta.attacks) && delta.attacks.length) {
        delta.attacks.forEach(attack => {
            if (!attack || !attack.id) return
            const exists = requestModel.attacks.find(item => String(item.id) === String(attack.id))
            if (!exists) {
                requestModel.attacks.push(attack)
            }
        })
    }
}

function enqueueDastDelta(delta) {
    if (!delta) return
    DAST_RENDER.queue.push(delta)
    DAST_RENDER.scanning = true
    DAST_RENDER.lastActivityAt = Date.now()
    DAST_RENDER.idleSorted = false
    startIdleChecker()
    updateLiveModeNotice()
    if (!DAST_RENDER.timer) {
        DAST_RENDER.timer = setTimeout(flushDastQueue, DAST_RENDER.flushMs)
    }
}

function flushDastQueue() {
    if (DAST_RENDER.timer) {
        clearTimeout(DAST_RENDER.timer)
        DAST_RENDER.timer = null
    }
    if (!DAST_RENDER.queue.length) return

    const deltas = DAST_RENDER.queue.splice(0, DAST_RENDER.queue.length)
    const lookup = controller._dastFindingLookup || buildFindingLookup(controller?.scanViewModel?.findings || [])
    const requestMarkup = []
    const attackMarkup = []
    const groupedReconKeys = new Set()
    let appendedRequests = false

    deltas.forEach(delta => {
        addDeltaToViewModel(delta)
        const requestId = delta.requestId ? String(delta.requestId) : null
        const original = delta.original ? { request: delta.original } : null
        if (requestId && !DAST_RENDER.renderedRequestIds.has(requestId)) {
            DAST_RENDER.renderedRequestIds.add(requestId)
            const requestHtml = buildRequestCardHtml(original, requestId)
            if (requestHtml) {
                appendedRequests = true
                requestMarkup.push(requestHtml)
            }
        }
        const attacks = Array.isArray(delta.attacks) ? delta.attacks : []
        attacks.forEach((attack, attackIdx) => {
            const attackId = attack?.id ? String(attack.id) : null
            if (!attackId || DAST_RENDER.renderedAttackIds.has(attackId)) return
            DAST_RENDER.renderedAttackIds.add(attackId)
            let enrichedAttack = attachFindingMetadataToAttack(attack, lookup)
            enrichedAttack = enrichAttackFromCatalog(enrichedAttack)
            attacks[attackIdx] = enrichedAttack
            if (isAggregatedReconRule(enrichedAttack)) {
                collectGroupedReconObservation(DAST_RENDER.groupedReconObservations, enrichedAttack, original, requestId)
                groupedReconKeys.add(getGroupedReconObservationKey(enrichedAttack, original))
                return
            }
            if (!shouldRenderAttackCard(enrichedAttack, original)) {
                return
            }
            const meta = rutils.getMiscMeta(enrichedAttack)
            updateDastCountersFromMeta(meta, requestId)
            const attackHtml = rutils.bindAttack(enrichedAttack, original, attackId, requestId)
            if (attackHtml) {
                attackMarkup.push({ html: attackHtml, meta })
            }
        })
    })

    if (requestMarkup.length) {
        $("#request_info").append(requestMarkup.join(''))
    }
    if (attackMarkup.length) {
        ensureAttackBuckets()
        attackMarkup.forEach(({ html, meta }) => {
            appendAttackToBucket(html, meta)
        })
    }
    if (groupedReconKeys.size) {
        ensureAttackBuckets()
        groupedReconKeys.forEach((key) => {
            const entry = DAST_RENDER.groupedReconObservations.get(key)
            const rendered = buildGroupedReconCardHtml(entry)
            if (!rendered) return
            const attrValue = (window.CSS && typeof CSS.escape === 'function') ? CSS.escape(key) : escAttrValue(key)
            const $existing = $(`#attacks_info .grouped_recon_card[data-grouped-recon-key="${attrValue}"]`)
            if ($existing.length) {
                $existing.replaceWith(rendered.html)
            } else {
                updateDastCountersFromMeta(rendered.meta, '__ptk_grouped_recon__')
                appendAttackToBucket(rendered.html, rendered.meta)
            }
        })
    }

    if (window.ptkUpdateRequestFilterUI && (requestFilterDirty || appendedRequests)) {
        window.ptkUpdateRequestFilterUI()
        requestFilterDirty = false
    }
    applyDefaultAttackScope()
    updateDastBucketVisibility()
    // Avoid full DOM filtering/sorting on every flush to keep the popup responsive.
    renderStatsFromCounters()
}

function bindAttackProgress(message) {
    scheduleProgressUpdate(message?.info || null)
}




////////////////////////////////////
/* Chrome runtime events handlers */
////////////////////////////////////
browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.channel == "ptk_background2popup_rattacker" || message.channel == "ptk_background2popup_dast") {
        if (message.type == "dast_progress") {
            scheduleProgressUpdate(message?.info || { name: 'Attack completed' })
        }
        if (message.type == "dast_idle") {
            scheduleProgressUpdate(message?.info || { message: 'Scan running, waiting for next runnable attack' })
        }
        if (message.type == "dast_plan_completed" || message.type == "dast_attack_delta") {
            enqueueDastDelta(message.delta)
        }
        if (message.type == "dast_scan_completed") {
            DAST_RENDER.scanning = false
            if (DAST_RENDER.idleCheckTimer) {
                clearInterval(DAST_RENDER.idleCheckTimer)
                DAST_RENDER.idleCheckTimer = null
            }
            const completedFromScan = buildProgressFromScanResult(message?.scanResult || null)
            const completedFromLive = Object.assign({}, DAST_RENDER.progressDetails || {}, {
                remaining: 0,
                activeTasks: 0,
                requestQueue: 0
            })
            const completedProgress = completedFromScan || completedFromLive
            scheduleProgressUpdate({
                message: "Scan completed",
                progress: completedProgress
            })
            updateLiveModeNotice()
            flushDastQueue()
            if (requestFilterDirty && window.ptkUpdateRequestFilterUI) {
                window.ptkUpdateRequestFilterUI()
                requestFilterDirty = false
            }
            if (message.scanResult) {
                DAST_RENDER.legacyBound = true
                bindScanResult({ scanResult: message.scanResult })
            }
            if (!DAST_RENDER.idleSorted) {
                const runFinal = () => {
                    renderStatsFromCounters()
                    DAST_RENDER.idleSorted = true
                }
                // Defer expensive completion work to keep the popup responsive.
                if (typeof requestIdleCallback === "function") {
                    requestIdleCallback(runFinal, { timeout: 250 })
                } else {
                    setTimeout(runFinal, 0)
                }
            }
            return
        }
        if (message.type == "attack completed") {
            //$(document).trigger("bind_stats", message.scanResult)
            //$("#attacks_info").append(bindAttack(message.info))
            //bindScanResult(message)
            scheduleProgressUpdate(message?.info || { name: 'Attack completed' })
        }
        if (message.type == "all attacks completed") {
            // Rely on delta pipeline; avoid one-time full bind to reduce UI churn.
        }
        if (message.type == "attack failed") {
            $('#scan_error_message').text(message.info)
            $('.mini.modal').modal('show')
        }
    }
})
