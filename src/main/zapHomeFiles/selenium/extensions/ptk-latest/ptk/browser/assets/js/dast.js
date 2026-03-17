/* Author: Denis Podgurskii */
import { ptk_controller_dast } from "../../../controller/dast.js"
import { ptk_controller_rbuilder } from "../../../controller/rbuilder.js"
import { ptk_utils } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import { shouldShowScanAnalysisUI } from "../../../background/analysis/featureFlags.js"
import * as rutils from "../js/rutils.js"
import { normalizeScanResult } from "../js/scanResultViewModel.js"
import { downloadScanExportResult, readScanFileText } from "../js/scanCompression.js"

const controller = new ptk_controller_dast()
const request_controller = new ptk_controller_rbuilder()

const DAST_RENDER = {
    queue: [],
    timer: null,
    flushMs: 350,
    renderedRequestIds: new Set(),
    renderedAttackIds: new Set(),
    scanning: false,
    legacyBound: false,
    progressTimer: null,
    progressFlushMs: 20,
    progressName: '',
    progressDetails: null,
    progressStatus: '',
    progressMetrics: '',
    lastActivityAt: 0,
    idleCheckTimer: null,
    idleSorted: false
}
const attackFilterState = {
    scope: 'all',
    requestId: null
}
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
const DAST_RESULT_VIEWS = new Set(['findings', 'analysis', 'coverage'])
const ANALYSIS_CANDIDATE_PAGE_SIZE = 10
let dastResultView = 'findings'
const ANALYSIS_CANDIDATE_INDEX = new Map()
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
const ANALYSIS_PLAYWRIGHT_MODAL_STATE = {
    candidateId: '',
    readiness: null
}
let latestDastRawScan = null
let scanAnalysisUiEnabled = true

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
    latestDastRawScan = null
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
        R12_IAST_RUNTIME_SIGNALS: 'IAST runtime signal'
    }
    return labels[normalized] || normalized || 'Rule'
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
    default:
        return normalizedValue
            ? `${humanizeAnalysisSignalCode(normalizedSignal)}: ${normalizedValue}`
            : humanizeAnalysisSignalCode(normalizedSignal)
    }
}

function buildCandidateWhyHtml(candidate) {
    const why = Array.isArray(candidate?.why) ? candidate.why.slice(0, 4) : []
    const createdByRule = escapeHtml(humanizeAnalysisRuleCode(candidate?.createdByRule || 'RULE'))
    const parts = [`<div class="ui tiny primary label" style="margin-bottom:4px;">${createdByRule}</div>`]
    if (!why.length) {
        parts.push('<span class="ui grey text">No explicit signals captured.</span>')
        return parts.join('')
    }
    parts.push(...why.map((entry) => {
        const message = escapeHtml(formatAnalysisSignalMessage(entry?.signal, entry?.value))
        return `<div class="ui tiny basic label" style="margin-bottom:4px;">${message}</div>`
    }))
    return parts.join('')
}

function buildManualStepsHtml(candidate) {
    const steps = Array.isArray(candidate?.manualSteps) ? candidate.manualSteps.slice(0, 5) : []
    if (!steps.length) return '<div class="ui tiny grey text">No manual guidance.</div>'
    return `<ol style="margin:4px 0 0 18px;">${steps.map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ol>`
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
    return `
        <div class="ui tiny message" style="margin-top:8px; padding:8px;">
            <div><b>Playwright Run:</b> <span class="ui tiny ${color} label">${escapeHtml(runStatusDisplay(status))}</span>${escapeHtml(progress)}</div>
            ${summary}
            ${topObservation}
            ${error}
        </div>
    `
}

function ensureAnalysisPlaywrightRunModal() {
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
                            </select>
                        </div>
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

async function openCandidatePlaywrightRunModal(candidateId) {
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
    $('#analysis_playwright_run_candidate').html(`
        <div><b>Candidate:</b> ${escapeHtml(candidate?.title || key)}</div>
        <div style="margin-top:4px;"><code>${escapeHtml(candidate?.routeKey || '-')}</code></div>
    `)
    $('#analysis_playwright_run_warning').hide().html('')
    const fallback = getCandidateActionReadiness(candidate)
    renderRunModalReadiness(fallback)
    setPlaywrightRunModalProfile('smoke')
    $('#analysis_playwright_auth').val('reuse_storage_state')
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
        if (!groups.has(type)) groups.set(type, [])
        groups.get(type).push(ref)
    })
    if (groups.has('request')) {
        const seen = new Map()
        groups.get('request').forEach((ref) => {
            const key = String(ref?.id || '').trim() || JSON.stringify(ref?.loc || {})
            if (!seen.has(key)) {
                seen.set(key, ref)
            }
        })
        groups.set('request', Array.from(seen.values()))
    }
    return Array.from(groups.entries()).map(([type, entries]) => buildEvidenceDrawerGroupHtml(type, entries, candidate)).join('')
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
        details
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
        details
    }
}

function summarizeFindingRef(ref) {
    const lookup = controller._dastFindingLookup || buildFindingLookup(controller?.scanViewModel?.findings || [])
    controller._dastFindingLookup = lookup
    const finding = lookup.get(String(ref?.id || '')) || null
    const titleBase = finding?.ruleName || finding?.category || finding?.moduleName || finding?.moduleId || ref?.id || 'Finding'
    const method = String(finding?.location?.method || ref?.loc?.method || 'GET').toUpperCase()
    const url = finding?.location?.url || finding?.location?.route || null
    const title = url ? `${titleBase} · ${method} ${url}` : titleBase
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
        details
    }
}

function summarizeGenericEvidenceRef(ref) {
    const type = String(ref?.type || 'evidence')
    const id = ref?.id || 'n/a'
    const title = `${type}: ${id}`
    const details = []
    const locText = formatEvidenceLoc(ref?.loc)
    if (locText) {
        details.push(`Context: <b>${locText}</b>`)
    }
    return {
        title,
        details
    }
}

function buildEvidenceDrawerEntryHtml(ref, candidate) {
    const type = String(ref?.type || 'evidence').toLowerCase()
    let summary = null
    if (type === 'request') {
        summary = summarizeRequestRef(ref)
    } else if (type === 'attack') {
        summary = summarizeAttackRef(ref)
    } else if (type === 'finding') {
        summary = summarizeFindingRef(ref)
    } else {
        summary = summarizeGenericEvidenceRef(ref)
    }
    const title = escapeHtml(summary?.title || `${type}: ${ref?.id || 'n/a'}`)
    const details = Array.isArray(summary?.details) ? summary.details.filter(Boolean) : []
    let actionHtml = ''
    if (type === 'request' && ref?.id) {
        actionHtml = `
            <button type="button" class="ui icon button open_evidence_request_rbuilder"
                data-request-id="${escapeAttr(ref.id)}"
                data-candidate-id="${escapeAttr(candidate?.id || '')}"
                style="padding:4px; min-width:auto; margin:0 6px 0 0;"
                title="Send to R-Builder">
                <i class="wrench large icon" title="Send to R-Builder"></i>
            </button>
        `
    } else if (type === 'attack' && ref?.id) {
        actionHtml = `
            <button type="button" class="ui icon button open_evidence_attack_rbuilder"
                data-attack-id="${escapeAttr(ref.id)}"
                data-candidate-id="${escapeAttr(candidate?.id || '')}"
                style="padding:4px; min-width:auto; margin:0 6px 0 0;"
                title="Send to R-Builder">
                <i class="wrench large icon" title="Send to R-Builder"></i>
            </button>
        `
    }
    return `
        <div class="ui segment" style="padding:8px; margin:6px 0;">
            <div style="display:flex; align-items:flex-start; gap:6px;">
                <div style="flex:1 1 auto;"><b>${title}</b></div>
                ${actionHtml}
            </div>
            ${details.length ? `<div style="margin-top:4px; font-size:13px; color:#555;">${details.join('<br/>')}</div>` : ''}
        </div>
    `
}

function humanizeEvidenceGroup(type) {
    const normalized = String(type || '').toLowerCase()
    if (normalized === 'request') return 'Requests'
    if (normalized === 'attack') return 'Attacks'
    if (normalized === 'finding') return 'Findings'
    return normalized ? `${normalized.charAt(0).toUpperCase()}${normalized.slice(1)} refs` : 'Evidence refs'
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

function structuredRequestToRaw(request, candidate, rawScan = {}) {
    const fallback = splitRouteKeyParts(candidate?.routeKey, rawScan?.host || null)
    const method = String(request?.method || fallback.method || 'GET').toUpperCase()
    let host = String(fallback.host || rawScan?.host || 'localhost:80')
    let path = materializePathTemplate(fallback.pathTemplate || '/')
    const headers = []
    if (request?.url) {
        try {
            const parsed = new URL(String(request.url))
            host = parsed.host || host
            path = `${parsed.pathname || '/'}${parsed.search || ''}`
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
    return `${method} ${path} HTTP/1.1\n${headers.join('\n')}\n\n${body}`
}

function buildFallbackCandidateRawRequest(candidate, rawScan = {}) {
    const fallback = splitRouteKeyParts(candidate?.routeKey, rawScan?.host || null)
    const method = fallback.method || 'GET'
    const path = materializePathTemplate(fallback.pathTemplate || '/')
    const host = fallback.host || String(rawScan?.host || 'localhost:80')
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
    return `${method} ${path} HTTP/1.1\n${headers.join('\n')}\n\n${body}`
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

function showResultDialog(header, message) {
    $('#result_header').text(header || 'Info')
    $('#result_message').text(message || '')
    $('#result_dialog').modal('show')
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

function renderAnalysisAndCoverage(vm, rawScan = {}) {
    const analysis = vm?.analysis || rawScan?.analysis || null
    const $analysis = $('#analysis_info')
    const $coverage = $('#coverage_info')
    ANALYSIS_CANDIDATE_INDEX.clear()
    if (!analysis || typeof analysis !== 'object') {
        $analysis.html(`
            <div class="ui info message">
                <div class="header">No analysis yet</div>
                <p>Analysis appears when the scan has enough finalized evidence.</p>
            </div>
        `)
        $coverage.html(`
            <div class="ui info message">
                <div class="header">No coverage summary yet</div>
                <p>Complete or import a scan with analysis data to view coverage gaps.</p>
            </div>
        `)
        return
    }

    const candidates = Array.isArray(analysis.candidates) ? analysis.candidates : []
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
            const routeKey = escapeHtml(candidate?.routeKey || '-')
            const paramKey = escapeHtml(candidate?.paramKey || '-')
            const candidateId = String(candidate?.id || '')
            const drawerId = `analysis_evidence_${toDomSafeId(candidateId)}`
            const runStatusHtml = buildCandidatePlaywrightRunHtml(candidate)
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
                        <div style="margin-top:6px;"><b>Manual steps:</b> ${buildManualStepsHtml(candidate)}</div>
                        <div style="margin-top:8px;">
                            <button type="button" class="ui tiny button toggle_candidate_evidence" data-evidence-target="${escapeAttr(drawerId)}">
                                Show Evidence
                            </button>
                            <button type="button" class="ui tiny button open_candidate_rbuilder" data-candidate-id="${escapeAttr(candidateId)}" ${sendDisabled} ${sendTooltip}>
                                Send To R-Builder
                            </button>
                        </div>
                        ${runStatusHtml}
                        <div id="${escapeAttr(drawerId)}" class="ui tiny message" style="display:none; margin-top:8px; padding:8px;">
                            <div class="ui tiny header" style="margin:0 0 6px 0;">Evidence refs</div>
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
        <div class="ui message">
            <div><b>Analysis version:</b> ${escapeHtml(analysis?.version || 'n/a')}</div>
            <div><b>Candidates:</b> ${topCandidates.length} of ${visibleCandidates.length} visible (${candidates.length} total${hiddenCandidateCount > 0 ? `, showing first ${topCandidates.length}` : ', showing all'})</div>
            ${analysis?.diff && typeof analysis.diff === 'object'
                ? `<div><b>Diff:</b> +${Number(analysis.diff.addedCount || 0)} / ~${Number(analysis.diff.changedCount || 0)} / =${Number(analysis.diff.unchangedCount || 0)} / -${Number(analysis.diff.removedCount || 0)}</div>`
                : ''}
        </div>
        ${candidateHtml}
        ${showMoreHtml}
    `)

    const coverage = analysis?.coverage && typeof analysis.coverage === 'object' ? analysis.coverage : {}
    const enginesPresent = Array.isArray(coverage.enginesPresent) ? coverage.enginesPresent : []
    const enginesRouteOverlap = Array.isArray(coverage.enginesRouteOverlap) ? coverage.enginesRouteOverlap : []
    const enginesMissing = Array.isArray(coverage.enginesMissing) ? coverage.enginesMissing : []
    const enginesHostOnly = Array.isArray(coverage.enginesHostOnly) ? coverage.enginesHostOnly : []
    const gaps = Array.isArray(coverage.gaps) ? coverage.gaps : []
    const limitations = Array.isArray(coverage.limitations) ? coverage.limitations : []

    const coverageEntryHtml = (entries) => {
        if (!entries.length) {
            return '<div class="ui tiny grey text">None</div>'
        }
        return entries.map((entry) => `
            <div class="ui segment" style="margin-top:6px; padding:8px;">
                <div><b>${escapeHtml(entry?.code || 'CODE')}</b> <span class="ui tiny basic label">${escapeHtml(entry?.severity || 'low')}</span></div>
                <div style="margin-top:4px;">${escapeHtml(entry?.detail || '')}</div>
                <div style="margin-top:4px;" class="ui tiny grey text">${escapeHtml(entry?.recommendedActionKey || '')}</div>
            </div>
        `).join('')
    }

    $coverage.html(`
        <div class="ui message">
            <div><b>Confidence:</b> ${escapeHtml(coverage?.confidence || 'low')} (${Number(coverage?.confidenceScore || 0)})</div>
            <div><b>Engines present in this session:</b> ${escapeHtml(enginesPresent.join(', ') || 'none')}</div>
            <div><b>Engines with overlapping runtime routes:</b> ${escapeHtml(enginesRouteOverlap.join(', ') || 'none')}</div>
            ${enginesHostOnly.length ? `<div><b>Engines seen elsewhere on host:</b> ${escapeHtml(enginesHostOnly.join(', '))}</div>` : ''}
            <div><b>Engines missing from this session:</b> ${escapeHtml(enginesMissing.join(', ') || 'none')}</div>
        </div>
        <div class="ui small header">Gaps (Not Executed)</div>
        ${coverageEntryHtml(gaps)}
        <div class="ui small header" style="margin-top:12px;">Limitations (Low Confidence)</div>
        ${coverageEntryHtml(limitations)}
    `)
}

function setDastResultView(view) {
    const requestedView = DAST_RESULT_VIEWS.has(view) ? view : 'findings'
    const nextView = (!scanAnalysisUiEnabled && requestedView !== 'findings') ? 'findings' : requestedView
    dastResultView = nextView
    $('#dast_result_tabs .item').removeClass('active')
    $(`#dast_result_tabs .item[data-view="${nextView}"]`).addClass('active')
    $('#dast_findings_filters')
        .css('visibility', 'visible')
        .css('pointer-events', 'auto')
    $('#attacks_info').toggle(nextView === 'findings')
    $('#analysis_info').toggle(nextView === 'analysis')
    $('#coverage_info').toggle(nextView === 'coverage')
    if (nextView === 'analysis' && !$('#analysis_info').children().length) {
        $('#analysis_info').html(`
            <div class="ui info message">
                <div class="header">No analysis yet</div>
                <p>Run or import a completed scan to populate manual candidates.</p>
            </div>
        `)
    }
    if (nextView === 'coverage' && !$('#coverage_info').children().length) {
        $('#coverage_info').html(`
            <div class="ui info message">
                <div class="header">No coverage summary yet</div>
                <p>Coverage details appear when scan analysis data is available.</p>
            </div>
        `)
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
    const raw = latestDastRawScan || controller?.scanResult?.scanResult || null
    if (!raw) return
    const vm = controller.scanViewModel || normalizeScanResult(raw)
    renderAnalysisAndCoverage(vm, raw)
    if (dastResultView === 'analysis') {
        setDastResultView('analysis')
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
    if (meta.isVuln) {
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

    function extractScans(payload, inheritedHost = '') {
        if (!payload) return []
        if (Array.isArray(payload)) {
            return payload.reduce((acc, item) => acc.concat(extractScans(item, inheritedHost)), [])
        }
        if (typeof payload !== 'object') return []
        const host = payload.hostname || payload.host || payload.domain || payload.project || payload.name || inheritedHost || ''
        if (Array.isArray(payload.scans)) {
            return payload.scans.reduce((acc, item) => acc.concat(extractScans(item, host)), [])
        }
        const scanId = payload.scanId || payload.id
        if (scanId) {
            const scanDate = payload.scanDate || payload.finished_at || payload.created_at || payload.started_at || payload.meta?.scanDate
            return [{ hostname: host, scanId, scanDate, raw: payload }]
        }
        const containers = ['items', 'data', 'results', 'entries', 'projects', 'records']
        return containers.reduce((acc, key) => {
            if (!payload[key]) return acc
            return acc.concat(extractScans(payload[key], host))
        }, [])
    }

    function renderDownloadScansTable(items) {
        const entries = extractScans(items)
        const dt = []
        entries.forEach(entry => {
            if (!entry) return
            const scanId = entry.scanId || ''
            const hostname = entry.hostname || entry.raw?.meta?.hostname || ''
            const d = entry.scanDate ? new Date(entry.scanDate) : null
            const rawDate = entry.scanDate || entry.raw?.finished_at || entry.raw?.created_at || entry.raw?.started_at
            const dateObj = rawDate ? new Date(rawDate) : null
            const scanDate = dateObj && !isNaN(dateObj.getTime()) ? dateObj.toLocaleString() : ''
            const link = `<div class="ui mini icon button download_scan_by_id" style="position: relative" data-scan-id="${scanId}"><i class="download alternate large icon"
                                        title="Download"></i>
                                        <div style="position:absolute; top:1px;right: 2px">
                                             <div class="ui  centered inline inverted loader"></div>
                                        </div>
                                </div>`
            const del = ` <div class="ui mini icon button delete_scan_by_id" data-scan-id="${scanId}" data-scan-host="${hostname}"><i  class="trash alternate large icon "
                    title="Delete"></i></div>`
            dt.push([hostname, scanId, scanDate, link, del])
        })

        dt.sort(function (a, b) {
            if (a[0] === b[0]) { return 0 } else { return (a[0] < b[0]) ? -1 : 1 }
        })
        const groupColumn = 0
        const params = {
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
                            '<tr class="group" ><td colspan="4"><div class="ui black ribbon label">' + group + '</div></td></tr>'
                        )
                        last = group
                    }
                })
            },

            scrollY: '100%',   // or a px value like '360px'
            scrollCollapse: true,
            paging: false

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
            $('#dast-scan-policy').val(result.settings.dastScanPolicy || 'ACTIVE')
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
                        const safetyProfile = ($('#dast-safety-profile').val() || 'safe').toLowerCase()
                        const settings = {
                            maxRequestsPerSecond: $('#maxRequestsPerSecond').val(),
                            concurrency: $('#concurrency').val(),
                            scanStrategy: $('#dast-scan-strategy').val() || 'SMART',
                            dastScanPolicy: $('#dast-scan-policy').val() || 'ACTIVE',
                            safetyProfile,
                            scanControls: {
                                profile: safetyProfile
                            },
                            runCve: isRunCveEnabled()
                        }
                        controller.runBackgroundScan(result.activeTab.tabId, h, $('#scan_domains').val(), settings).then(function (result) {
                            resetDastRenderState()
                            DAST_RENDER.scanning = true
                            startIdleChecker()
                            updateLiveModeNotice()
                            $("#request_info").html("")
                            $("#attacks_info").html("")
                            triggerDastStatsEvent(result.scanResult)
                            changeView(result)
                            if (hasRenderableScanData(result.scanResult)) {
                                bindScanResult(result)
                            }
                        })
                    }
                })
                .modal('show')
            $('#dast_form .question')
                .popup({
                    inline: true,
                    hoverable: true,
                    delay: {
                        show: 300,
                        hide: 800
                    }
                })
        })

        return false
    })

    $(document).on("click", "#ptk_scan_reload_warning_close_dast", function () {
        window._ptkDastReloadWarningClosed = true
        $('#ptk_scan_reload_warning').hide()
    })

    $(document).on("click", ".stop_scan_runtime", function () {
        controller.stopBackgroundScan().then(function (result) {
            DAST_RENDER.scanning = false
            if (DAST_RENDER.idleCheckTimer) {
                clearInterval(DAST_RENDER.idleCheckTimer)
                DAST_RENDER.idleCheckTimer = null
            }
            updateLiveModeNotice()
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
    const $scanExportProgress = $('#scan_export_progress')
    const $scanExportProgressBar = $('#scan_export_progress_bar')
    const $scanExportProgressText = $('#scan_export_progress_text')
    let exportInProgress = false

    function setExportProgress(percent, text) {
        const safePercent = Math.max(0, Math.min(100, Number(percent) || 0))
        $scanExportProgress.show()
        $scanExportProgressBar.css('width', `${safePercent}%`)
        $scanExportProgressText.text(text || `Exporting... ${safePercent}%`)
    }

    function hideExportProgress() {
        $scanExportProgress.hide()
        $scanExportProgressBar.css('width', '0%')
        $scanExportProgressText.text('Preparing export...')
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
        try {
            const text = await readScanFileText(file)
            controller.save(text).then(result => {
                changeView(result)
                if (hasRenderableScanData(result.scanResult)) {
                    bindScanResult(result)
                }
                $('#import_export_dlg').modal('hide')
            }).catch(e => {
                $('#result_message').text('Could not import DAST scan')
                $('#result_dialog').modal('show')
            })
        } catch (e) {
            $('#result_message').text('Could not import DAST scan')
            $('#result_dialog').modal('show')
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





    $(document).on("click", ".delete_scan_by_id", function () {
        let scanId = $(this).attr("data-scan-id")
        let scanHost = $(this).attr("data-scan-host")
        $("#scan_hostname").val("")
        $("#scan_delete_message").text("")
        $('#delete_scan_dlg')
            .modal({
                allowMultiple: true,
                onApprove: function () {
                    if ($("#scan_hostname").val() == scanHost) {
                        return controller.deleteScanById(scanId).then(function (result) {
                            $('.cloud_download_scans').trigger("click")
                            //console.log(result)
                            return true
                        })

                    } else {
                        $("#scan_delete_message").text("Type scan hostname to confirm delete")
                        return false
                    }
                }
            })
            .modal('show')
    })


    $(document).on("click", ".reset", function () {
        $("#request_info").html("")
        $("#attacks_info").html("")
        $("#analysis_info").html("")
        $("#coverage_info").html("")
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
            bindModules(result)
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

    $(document).on("click", ".run_candidate_playwright", async function () {
        const candidateId = String($(this).attr('data-candidate-id') || '').trim()
        if (!candidateId) return false
        await openCandidatePlaywrightRunModal(candidateId)
        return false
    })

    $(document).on("change", "#analysis_playwright_profile", function () {
        setPlaywrightRunModalProfile($(this).val() || 'smoke')
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
            const response = await controller.runCandidateInPlaywright({
                candidateId,
                profile,
                authMode,
                constraints
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


    function setScopeFilter(scope) {
        const allowedScopes = new Set(['all', 'vuln', '400', '500'])
        attackFilterState.scope = allowedScopes.has(scope) ? scope : 'all'
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
        if (!hasFindingPresentationData(enrichedAttack)) {
            lookup = await ensureAttackFindingDetails(attack, requestId, attackId) || lookup
            controller._dastFindingLookup = lookup
            enrichedAttack = attachFindingMetadataToAttack(attack, lookup)
        }
        rutils.bindAttackDetails_DAST($(this), enrichedAttack, original)
        $('.metadata .item').tab('change tab', 'first');
    })


    $(document).on("bind_stats", function (e, scanResult) {
        if (scanResult.stats) {
            rutils.bindStats(scanResult.stats, 'dast')
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
        changeView(result)
        DAST_RENDER.scanning = !!result.isScanRunning
        if (DAST_RENDER.scanning) {
            DAST_RENDER.legacyBound = false
            startIdleChecker()
        }
        updateLiveModeNotice()
        if (hasRenderableScanData(result.scanResult)) {
            bindScanResult(result)
        } else if (Array.isArray(result?.default_modules) && result.default_modules.length) {
            bindModules(result)
        } else {
            showWelcomeForm()
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
    $("#coverage_info").html("")
    resetAnalysisUiState()
    $("#attacks_info").attr("data-scope", "all")
    resetDastCounters()
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

function hasFindingPresentationData(attack) {
    const finding = attack?.finding
    if (!finding || typeof finding !== 'object') return false
    if (typeof finding.description === 'string' && finding.description.trim().length) return true
    if (typeof finding.recommendation === 'string' && finding.recommendation.trim().length) return true
    if (finding.links && typeof finding.links === 'object' && Object.keys(finding.links).length) return true
    return false
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
    const raw = result.scanResult || {}
    latestDastRawScan = raw
    const vm = raw.__normalized ? raw : normalizeScanResult(raw)
    controller.scanResult = result
    controller.scanViewModel = vm
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
    if (scanAnalysisUiEnabled) {
        $('#dast_result_tabs').show()
    } else {
        $('#dast_result_tabs').hide()
        dastResultView = 'findings'
    }
    $('.save_scan').show()
    $('#request_info').html("")
    $('#attacks_info').html("")
    $('#analysis_info').html("")
    $('#coverage_info').html("")
    hideWelcomeForm()
    if (scanAnalysisUiEnabled) {
        renderAnalysisAndCoverage(vm, raw)
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
            const enrichedAttack = attachFindingMetadataToAttack(attack, findingLookup)
            const meta = rutils.getMiscMeta(enrichedAttack)
            updateDastCountersFromMeta(meta, requestKey)
            const attackHtml = rutils.bindAttack(enrichedAttack, original, attackKey, requestKey)
            const bucket = getAttackBucket(meta)
            bucketMarkup[bucket].push(attackHtml)
        })
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
        : (Array.isArray(result) ? result : [])
    const cveModules = Array.isArray(result?.cve_modules) ? result.cve_modules : []

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
    DAST_RENDER.legacyBound = false
    DAST_RENDER.progressName = ''
    DAST_RENDER.progressDetails = null
    DAST_RENDER.progressStatus = ''
    DAST_RENDER.progressMetrics = ''
    DAST_RENDER.lastActivityAt = 0
    DAST_RENDER.idleSorted = false
    resetDastCounters()
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
        return 'Executed 0/Remaining 0/Active 0/Captured 0'
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
    return `Executed ${executed}/Remaining ${remaining}/Active ${active}/Captured ${captured}`
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
            $("#progress_scan_metrics").text(DAST_RENDER.progressMetrics || 'Executed 0/Remaining 0/Active 0/Captured 0')
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
        attacks.forEach(attack => {
            const attackId = attack?.id ? String(attack.id) : null
            if (!attackId || DAST_RENDER.renderedAttackIds.has(attackId)) return
            DAST_RENDER.renderedAttackIds.add(attackId)
            const enrichedAttack = attachFindingMetadataToAttack(attack, lookup)
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

    if (window.ptkUpdateRequestFilterUI && (requestFilterDirty || appendedRequests)) {
        window.ptkUpdateRequestFilterUI()
        requestFilterDirty = false
    }
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
